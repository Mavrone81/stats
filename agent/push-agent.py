#!/usr/bin/env python3
"""
netmap push agent -- for devices the prober has no route to.

Run this by cron on a host that ALREADY has the access, and it POSTs results to
/api/probe-push. Targets marked {"m":"push"} on the board read the last value
this submitted. The alternative -- opening a firewall policy so the central
prober can reach those devices -- widens the blast radius of the monitoring
system itself to make a dashboard tidier. Don't.

  ./push-agent.py --dry-run                     # prints the payload, no creds
  ./push-agent.py --url https://status.bevorasg.com --token "$NETMAP_PUSH_TOKEN"

RUN --dry-run FROM THE CANDIDATE HOST BEFORE COMMITTING TO IT. Do not assume
that because one machine on a segment reaches a device, any machine on it does:
access is frequently per-address, and inheriting that assumption is how you
ship an agent that reports nothing from its permanent home.

Stdlib only, same as the server, and for the same reason: this runs on hosts we
do not control the package set of.
"""
import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

# What this agent probes. Edit for the host it lives on -- these are the
# devices the CENTRAL prober cannot see, not a copy of the main target list.
TARGETS = [
    # The VPC ingest port on bevora-ops. Only hosts inside the DigitalOcean VPC
    # can see this; 165 (10.104.0.2) can, the netmap prober cannot. This agent
    # therefore belongs on 165. Run --dry-run FROM 165 before adopting it.
    {"ip": "10.104.0.3", "port": 4100, "m": "tcp"},
    # {"ip": "10.x.x.x", "port": 443, "m": "tcp"},
]

DEFAULT_TIMEOUT = 3.0
_STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")


def probe(t, timeout=DEFAULT_TIMEOUT):
    """One target. Mirrors server.py's probe discipline deliberately.

    In particular `http` mode reads the STATUS LINE, it does not merely open a
    socket. An agent that reported bare TCP reachability would reproduce, on the
    pushed half of the board, exactly the weakness the central prober was built
    to avoid: a listening port is not a working service. These backends all
    answer /health with 200 while returning 404 on /, so the path matters too.
    """
    ip, port = t["ip"], int(t["port"])
    mode = t.get("m", "tcp")
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if mode == "tcp":
            return {"ip": ip, "port": port, "up": True,
                    "ms": int((time.monotonic() - t0) * 1000)}
        if mode == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=t.get("host", ip))
        host = t.get("host", ip)
        path = t.get("path", "/")
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      f"User-Agent: netmap-push-agent/1\r\n"
                      f"Connection: close\r\n\r\n").encode())
        sock.settimeout(timeout)
        buf = b""
        while b"\r\n" not in buf and len(buf) < 256:
            chunk = sock.recv(128)
            if not chunk:
                break
            buf += chunk
        ms = int((time.monotonic() - t0) * 1000)
        m = _STATUS.match(buf)
        if not m:
            return {"ip": ip, "port": port, "up": False, "ms": ms}
        code = int(m.group(1))
        exp = t.get("expect")
        up = (code in exp) if isinstance(exp, list) and exp else code < 500
        return {"ip": ip, "port": port, "up": up, "ms": ms, "code": code}
    except Exception:
        return {"ip": ip, "port": port, "up": False, "ms": None}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def load_targets(path):
    """Targets are DATA, same as on the server: one generic agent, a per-host
    JSON list beside it. Editing what a host reports must never mean editing
    (and redeploying) the agent."""
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return TARGETS


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="https://status.bevorasg.com",
                    help="netmap base URL")
    ap.add_argument("--token", help="shared push token (NETMAP_PUSH_TOKEN)")
    ap.add_argument("--token-file", help="read the token from a file instead of argv "
                                         "(argv is world-readable in /proc)")
    ap.add_argument("--targets", help="JSON file of targets; defaults to "
                                      "targets.json beside this script")
    ap.add_argument("--report-ip", help="identity to report results under, if it "
                                        "differs from the probe address. Loopback "
                                        "services are probed at 127.0.0.1 but must "
                                        "be reported under the HOST's address, or "
                                        "every agent's rows collide on 127.0.0.1")
    ap.add_argument("--agent", default=socket.gethostname(),
                    help="name recorded against these results")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--dry-run", action="store_true",
                    help="probe and print the payload; sends nothing, needs no token")
    a = ap.parse_args()

    tfile = a.targets or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "targets.json")
    try:
        targets = load_targets(tfile)
    except Exception as e:
        sys.stderr.write(f"push-agent: cannot read {tfile}: {e}\n")
        return 1

    if not targets:
        sys.stderr.write("push-agent: no targets -- nothing to do. Provide "
                         "--targets or edit TARGETS at the top of this file.\n")
        return 1

    results = [probe(t, a.timeout) for t in targets]
    if a.report_ip:
        for r in results:
            r["ip"] = a.report_ip
    payload = {"agent": a.agent, "results": results}

    if a.dry_run:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        up = sum(1 for r in payload["results"] if r["up"])
        sys.stderr.write(f"push-agent: DRY RUN -- {up}/{len(payload['results'])} "
                         f"reachable from {a.agent}. Nothing was sent.\n")
        # Non-zero if this host cannot see its own targets: that is the whole
        # point of running --dry-run here before adopting the host.
        return 0 if up else 2

    token = a.token
    if not token and a.token_file:
        try:
            token = open(a.token_file).read().strip()
        except Exception as e:
            sys.stderr.write(f"push-agent: cannot read token file: {e}\n")
            return 1
    if not token:
        token = os.environ.get("NETMAP_PUSH_TOKEN", "")
    if not token:
        sys.stderr.write("push-agent: need --token, --token-file or "
                         "NETMAP_PUSH_TOKEN (or use --dry-run)\n")
        return 1

    req = urllib.request.Request(
        a.url.rstrip("/") + "/api/probe-push",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Push-Token": token},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            sys.stderr.write(f"push-agent: {r.status} {r.read().decode()[:200]}\n")
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"push-agent: HTTP {e.code} {e.read().decode()[:200]}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"push-agent: {type(e).__name__}: {e}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
