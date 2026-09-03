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

DEFAULT_TIMEOUT = 2.0


def probe(t, timeout=DEFAULT_TIMEOUT):
    ip, port = t["ip"], int(t["port"])
    t0 = time.monotonic()
    try:
        if t.get("m") == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.create_connection((ip, port), timeout=timeout),
                                 server_hostname=t.get("host", ip)):
                pass
        else:
            with socket.create_connection((ip, port), timeout=timeout):
                pass
        return {"ip": ip, "port": port, "up": True,
                "ms": int((time.monotonic() - t0) * 1000)}
    except Exception:
        return {"ip": ip, "port": port, "up": False, "ms": None}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="https://status.bevorasg.com",
                    help="netmap base URL")
    ap.add_argument("--token", help="shared push token (NETMAP_PUSH_TOKEN)")
    ap.add_argument("--agent", default=socket.gethostname(),
                    help="name recorded against these results")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--dry-run", action="store_true",
                    help="probe and print the payload; sends nothing, needs no token")
    a = ap.parse_args()

    if not TARGETS:
        sys.stderr.write("push-agent: TARGETS is empty -- nothing to do. Edit the "
                         "list at the top of this file.\n")
        return 1

    payload = {"agent": a.agent,
               "results": [probe(t, a.timeout) for t in TARGETS]}

    if a.dry_run:
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
        up = sum(1 for r in payload["results"] if r["up"])
        sys.stderr.write(f"push-agent: DRY RUN -- {up}/{len(payload['results'])} "
                         f"reachable from {a.agent}. Nothing was sent.\n")
        # Non-zero if this host cannot see its own targets: that is the whole
        # point of running --dry-run here before adopting the host.
        return 0 if up else 2

    if not a.token:
        sys.stderr.write("push-agent: --token is required (or use --dry-run)\n")
        return 1

    req = urllib.request.Request(
        a.url.rstrip("/") + "/api/probe-push",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Push-Token": a.token},
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
