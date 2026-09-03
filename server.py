#!/usr/bin/env python3
"""
bevoraSG netmap — inventory, reachability and incident board for the non-RMA fleet.

Stdlib only, by design. This class of tool has to keep working on the day
everything else is broken, so it has no dependencies to rot and no supply chain
to compromise. See README.md §"Why no framework".

Scope: the non-RMA hosts ONLY. RMA hosts, credentials and target lists never
appear here and must never be added -- the two estates do not share a box, an
account or a credential.
"""
import concurrent.futures
import hmac
import http.server
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
PORT            = int(os.environ.get("NETMAP_PORT", "8080"))
DATA_DIR        = os.environ.get("NETMAP_DATA", "/data")
APP_DIR         = os.path.dirname(os.path.abspath(__file__))
REFRESH         = int(os.environ.get("NETMAP_REFRESH", "30"))      # seconds per cycle
WORKERS         = int(os.environ.get("NETMAP_WORKERS", "24"))
RETENTION_DAYS  = int(os.environ.get("NETMAP_RETENTION_DAYS", "7"))
MAX_TARGETS     = 500
MAX_POST        = 1024 * 1024                                       # 1 MiB
PUSH_TTL        = int(os.environ.get("NETMAP_PUSH_TTL", "300"))
CERT_WARN_DAYS  = 21
DOWN_CONFIRM_CYCLES = 2

TCP_TIMEOUT   = 1.2
HTTP_TIMEOUT  = 4.0
HTTPS_TIMEOUT = 6.0    # the TLS handshake costs a round trip; don't starve it

DB_PATH        = os.path.join(DATA_DIR, "netmap.db")
LIVE_TARGETS   = os.path.join(DATA_DIR, "targets.json")   # layer 3 -- WINS
SEED_TARGETS   = os.path.join(APP_DIR, "targets.json")    # layer 2 -- deployed seed
ACKS_PATH      = os.path.join(DATA_DIR, "acks.json")
PUSH_PATH      = os.path.join(DATA_DIR, "push.json")

USER = os.environ.get("NETMAP_USER")
PASS = os.environ.get("NETMAP_PASS")

# ---------------------------------------------------------------------------
# Layer 1: builtin seed. FALLBACK ONLY.
#
# Reading this list tells you NOTHING about what is actually being probed --
# the live store at /data/targets.json overrides it entirely and is edited from
# the UI. To find out what is really probed, query /api/targets. Never grep
# this file and conclude anything.
# ---------------------------------------------------------------------------
BUILTIN_TARGETS = [
    # -- segment: edge-165 -- public vhosts on the shared 165 address -------
    #
    # Probed BY HOSTNAME, not by the shared IP, and this is load-bearing.
    # Every one of these is a name-based vhost on one address, so a bare TCP
    # probe of that address would be ONE check reported 31 times -- all green
    # together, all red together, and still green when a single app dies
    # because the reverse proxy keeps answering. Sending SNI + a Host header
    # fixes that much.
    #
    # But probing the IP with a Host header ALSO hides a dead name: nginx
    # answers the catch-all and the row stays green even when the hostname no
    # longer resolves for anybody. Measured on med.awakenfs.store, which had no
    # DNS record at all while by-IP probing reported it up with a healthy 200
    # and a valid cert. That vhost has since been retired (see README), but it
    # is the reason every row below is probed by name rather than by address.
    # Resolving the name is part of what users depend on, so it is part of
    # the check.
    {"ip": "app.urbanfleetsg.com", "port": 443, "label": "urbanfleet app", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urban Fleet", "opts": {"m": "https", "host": "app.urbanfleetsg.com", "path": "/", "expect": [200, 307]}},
    {"ip": "app.vorkhive.com", "port": 443, "label": "vorkhive app", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Vorkhive", "opts": {"m": "https", "host": "app.vorkhive.com", "path": "/", "expect": [200, 307]}},
    {"ip": "awakenfs.store", "port": 443, "label": "awakenfs", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "AwakenFS", "opts": {"m": "https", "host": "awakenfs.store", "path": "/", "expect": [200, 307]}},
    # Same shape as crm.bevorasg.com: static root, backend only under /api/.
    # Currently healthy, but probing "/" would keep saying so after :4210 died,
    # so it is probed where the backend actually answers.
    {"ip": "back-end.store", "port": 443, "label": "back-end.store", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Back-End Store", "opts": {"m": "https", "host": "back-end.store", "path": "/api/health", "expect": [200]}},
    {"ip": "bill.bevorasg.com", "port": 443, "label": "bill (bevora)", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "bill.bevorasg.com", "path": "/", "expect": [200]}},
    {"ip": "chachisoftware.store", "port": 443, "label": "chachi website", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Chachi", "opts": {"m": "https", "host": "chachisoftware.store", "path": "/", "expect": [200]}},
    {"ip": "court.chachisoftware.store", "port": 443, "label": "chachi court", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Chachi", "opts": {"m": "https", "host": "court.chachisoftware.store", "path": "/", "expect": [200]}},
    # Probed at /login, NOT "/". This vhost serves a STATIC brochure page from
    # /var/www for "/" and only proxies ^/(admin|login|api|_next) to the app on
    # :3013. Probing "/" therefore returns 200 off the filesystem and reports
    # the site healthy while the application behind it is dead -- measured: "/"
    # gave 200 and /login gave 502 at the same instant. A reverse proxy that
    # can answer without the backend is the single most reliable way to build a
    # monitoring board that lies.
    {"ip": "crm.bevorasg.com", "port": 443, "label": "crm (bevora)", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "crm.bevorasg.com", "path": "/login", "expect": [200, 302, 307]}},
    {"ip": "crm.urbanwerkzsg.com", "port": 443, "label": "crm (urbanwerkz)", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urbanwerkz", "opts": {"m": "https", "host": "crm.urbanwerkzsg.com", "path": "/", "expect": [200, 307]}},
    {"ip": "dancestudio.chachisoftware.store", "port": 443, "label": "chachi dancestudio", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Chachi", "opts": {"m": "https", "host": "dancestudio.chachisoftware.store", "path": "/", "expect": [200]}},
    {"ip": "dine.chachisoftware.store", "port": 443, "label": "chachi dine", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Chachi", "opts": {"m": "https", "host": "dine.chachisoftware.store", "path": "/", "expect": [200]}},
    {"ip": "eform.bevorasg.com", "port": 443, "label": "eform (bevora)", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "eform.bevorasg.com", "path": "/", "expect": [200]}},
    {"ip": "enshrinepets.com.sg", "port": 443, "label": "enshrine pets", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Enshrine Pets", "opts": {"m": "https", "host": "enshrinepets.com.sg", "path": "/", "expect": [200]}},
    {"ip": "form.bevorasg.com", "port": 443, "label": "bamform", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "form.bevorasg.com", "path": "/", "expect": [200]}},
    {"ip": "hris.chachisoftware.store", "port": 443, "label": "chachi hris", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Chachi", "opts": {"m": "https", "host": "hris.chachisoftware.store", "path": "/", "expect": [200]}},
    {"ip": "huayutong.urbanwerkzsg.com", "port": 443, "label": "huayutong", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urbanwerkz", "opts": {"m": "https", "host": "huayutong.urbanwerkzsg.com", "path": "/", "expect": [200]}},
    {"ip": "ims.bevorasg.com", "port": 443, "label": "ims (bevora)", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "ims.bevorasg.com", "path": "/", "expect": [200]}},
    {"ip": "jobs.chachisoftware.store", "port": 443, "label": "jobstuff", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Chachi", "opts": {"m": "https", "host": "jobs.chachisoftware.store", "path": "/", "expect": [200]}},
    {"ip": "lng.bevorasg.com", "port": 443, "label": "lng (bevora)", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "lng.bevorasg.com", "path": "/", "expect": [200]}},
    {"ip": "loan.chachisoftware.store", "port": 443, "label": "chachi loan demo", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Chachi", "opts": {"m": "https", "host": "loan.chachisoftware.store", "path": "/", "expect": [200]}},
    {"ip": "mcts.urbanwerkzsg.com", "port": 443, "label": "housecharging / mcts", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urbanwerkz", "opts": {"m": "https", "host": "mcts.urbanwerkzsg.com", "path": "/", "expect": [200]}},
    {"ip": "sign.bevorasg.com", "port": 443, "label": "bevorasign", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "sign.bevorasg.com", "path": "/", "expect": [200, 302]}},
    {"ip": "singaporebuddhistfuneral.com.sg", "port": 443, "label": "sbf funeral", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Singapore Buddhist Funeral", "opts": {"m": "https", "host": "singaporebuddhistfuneral.com.sg", "path": "/", "expect": [200]}},
    # Probed at /track/<anything>, NOT at "/". This app (CDMS web-tracking) has
    # exactly one route -- app/track/[trackingId] -- and no root page, so "/"
    # returns a perfectly correct 404. Probing "/" reported a healthy app as
    # broken for as long as it was configured that way. The lesson generalises:
    # before filing a 404 as a fault, check whether the app was ever supposed
    # to serve that path.
    {"ip": "track.urbanfleetsg.com", "port": 443, "label": "urbanfleet track", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urban Fleet", "opts": {"m": "https", "host": "track.urbanfleetsg.com", "path": "/track/netmap-probe", "expect": [200]}},
    {"ip": "uat.bevorasg.com", "port": 443, "label": "uat (bevora)", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "uat.bevorasg.com", "path": "/", "expect": [200]}},
    {"ip": "urbanfleetsg.com", "port": 443, "label": "urbanfleet www", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urban Fleet", "opts": {"m": "https", "host": "urbanfleetsg.com", "path": "/", "expect": [200]}},
    {"ip": "urbanwerkzsg.com", "port": 443, "label": "urbanwerkz www", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urbanwerkz", "opts": {"m": "https", "host": "urbanwerkzsg.com", "path": "/", "expect": [200]}},
    {"ip": "vo.urbanwerkzsg.com", "port": 443, "label": "VirtualOffice", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Urbanwerkz", "opts": {"m": "https", "host": "vo.urbanwerkzsg.com", "path": "/", "expect": [200, 302]}},
    {"ip": "vorkhive.com", "port": 443, "label": "vorkhive www", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Vorkhive", "opts": {"m": "https", "host": "vorkhive.com", "path": "/", "expect": [200]}},
    {"ip": "www.bevorasg.com", "port": 443, "label": "bevorasg www", "seg": "edge-165", "srv": "app-165 (165.22.246.45)", "co": "Bevora", "opts": {"m": "https", "host": "www.bevorasg.com", "path": "/", "expect": [200]}},

    # -- segment: host-165 -- the box itself, not a vhost --------------------
    {"ip": "165.22.246.45", "port": 22, "label": "165 sshd", "seg": "host-165", "srv": "app-165 (165.22.246.45)", "co": "Infrastructure", "opts": {"m": "tcp"}},
    # MEASURED, not assumed: both of these bind 0.0.0.0 on the host, so `ss`
    # reports them world-listening -- but neither answers from off-box. What
    # actually closes them is the host's OWN ufw (default-deny INPUT, allowing
    # only OpenSSH / Nginx Full / wireguard) plus a DOCKER-USER rule dropping
    # new inbound connections arriving on eth0 -- the rule that stops Docker's
    # published ports from punching straight through ufw, which is otherwise
    # exactly what they do. There is NO cloud firewall on this droplet at all.
    # Probed INVERTED, so these rows go red if either protection is dropped.
    {"ip": "165.22.246.45", "port": 5432, "label": "165 postgres (must stay closed)", "seg": "host-165", "srv": "app-165 (165.22.246.45)", "co": "Infrastructure", "opts": {"m": "tcp", "invert": True}},
    {"ip": "165.22.246.45", "port": 6379, "label": "165 redis (must stay closed)", "seg": "host-165", "srv": "app-165 (165.22.246.45)", "co": "Infrastructure", "opts": {"m": "tcp", "invert": True}},

    # -- segment: gadonghr -- ONE hostname, PATH-based routing via Traefik ---
    #
    # Traefik routes every backend off the same host by path prefix, so here
    # the discriminator is `path`, not `host`. Probing "/" alone would only
    # ever test the web router and report all eight backends as healthy.
    # 401/404 count as UP: these are unauthenticated probes of authenticated
    # APIs, and a service that refuses us is a service that is running. Only
    # 5xx or no answer means the backend is gone.
    {"ip": "hr.bevorasg.com", "port": 443, "label": "gadonghr web", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/", "expect": [200]}},
    {"ip": "hr.bevorasg.com", "port": 443, "label": "keycloak auth", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/auth/", "expect": [200, 302, 303]}},
    {"ip": "hr.bevorasg.com", "port": 443, "label": "svc-config", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/api/config", "expect": [200, 401, 404]}},
    {"ip": "hr.bevorasg.com", "port": 443, "label": "svc-authz", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/api/authz", "expect": [200, 401, 404]}},
    {"ip": "hr.bevorasg.com", "port": 443, "label": "svc-audit", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/api/audit", "expect": [200, 401, 404]}},
    {"ip": "hr.bevorasg.com", "port": 443, "label": "svc-i18n", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/api/i18n", "expect": [200, 401, 404]}},
    {"ip": "hr.bevorasg.com", "port": 443, "label": "svc-notify", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/api/notify", "expect": [200, 401, 404]}},
    {"ip": "hr.bevorasg.com", "port": 443, "label": "svc-docs", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "https", "host": "hr.bevorasg.com", "path": "/api/docs", "expect": [200, 401, 404]}},
    {"ip": "157.230.38.96", "port": 22, "label": "gadonghr sshd", "seg": "gadonghr", "srv": "gadonghr-prod (157.230.38.96)", "co": "GaDong HR", "opts": {"m": "tcp"}},

    # -- segment: bevora-ops -------------------------------------------------
    # Publicly filtered on every port tried. NOT unrouted, though: all three
    # droplets share a DigitalOcean VPC (165=10.104.0.2, ops=10.104.0.3,
    # gadonghr=10.104.0.4) and from 165 over that VPC port 4100 answers while
    # 22/80/443/3000 are filtered. So the separation is a firewall POLICY on a
    # shared private network, not an absence of route -- a distinction this
    # file cared enough about to lecture on in the Simple View, and then got
    # wrong by only testing the public address. Both facts are probed below.
    {"ip": "157.245.152.227", "port": 22, "label": "bevora-ops sshd (public, filtered)", "seg": "bevora-ops", "srv": "bevora-ops (157.245.152.227)", "co": "Infrastructure", "opts": {"m": "tcp"}},
    # The VPC ingest port Bevora Ops' own agents push into -- the one port
    # permitted across the private network. PUSH mode, not tcp: a prober
    # outside the VPC structurally cannot see this, and probing it from outside
    # would produce a permanently-red row that says "we cannot look" while
    # appearing to say "it is down". Those are different facts and the board
    # must not conflate them.
    #
    # This needs an agent homed on 165 (which IS in the VPC) -- see
    # agent/push-agent.py. Until one is, this row reads STALE, which is the
    # honest state: nobody is currently measuring the private path. Do not
    # "fix" it by switching to tcp; fix it by homing the agent, or delete the
    # target and say so in the README.
    {"ip": "10.104.0.3", "port": 4100, "label": "bevora-ops ingest (VPC, needs on-VPC agent)", "seg": "bevora-ops", "srv": "bevora-ops (157.245.152.227)", "co": "Infrastructure", "opts": {"m": "push"}},
]


# ---------------------------------------------------------------------------
# JSON stores (targets / acks / push)
# ---------------------------------------------------------------------------
def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _write_json_atomic(path, obj, keep_bak=True):
    """Atomic replace + timestamped .bak. A half-written target list is worse
    than a stale one: the cycle would probe a truncated list and, per the
    stranded-event rule, start closing incidents for hosts that never left."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if keep_bak and os.path.exists(path):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            with open(path, "rb") as src, open(f"{path}.{stamp}.bak", "wb") as dst:
                dst.write(src.read())
        except Exception:
            pass
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


_HOSTRE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def validate_targets(raw):
    """Return (targets, errors). Rejects the whole payload on any error --
    a partially-applied target list is a silent coverage hole."""
    errs = []
    if not isinstance(raw, list):
        return None, ["payload must be a JSON array"]
    if len(raw) > MAX_TARGETS:
        return None, [f"too many targets ({len(raw)} > {MAX_TARGETS})"]
    out = []
    for i, t in enumerate(raw):
        if not isinstance(t, dict):
            errs.append(f"[{i}] not an object"); continue
        ip = str(t.get("ip", "")).strip()
        if not ip or not _HOSTRE.match(ip):
            errs.append(f"[{i}] bad ip/host {ip!r}"); continue
        try:
            port = int(t.get("port", 0))
        except (TypeError, ValueError):
            errs.append(f"[{i}] bad port"); continue
        if not 1 <= port <= 65535:
            errs.append(f"[{i}] port out of range"); continue
        opts = t.get("opts") or {}
        if not isinstance(opts, dict):
            errs.append(f"[{i}] opts must be an object"); continue
        mode = str(opts.get("m", "tcp"))
        if mode not in ("tcp", "http", "https", "push"):
            errs.append(f"[{i}] unknown mode {mode!r}"); continue
        exp = opts.get("expect")
        if exp is not None and (not isinstance(exp, list)
                                or not all(isinstance(c, int) for c in exp)):
            errs.append(f"[{i}] expect must be a list of ints"); continue
        rec = {
            "ip": ip, "port": port,
            "label": str(t.get("label", "") or f"{ip}:{port}")[:120],
            "seg": str(t.get("seg", "") or "unsegmented")[:60],
            "opts": opts,
        }
        # Optional grouping dimensions for the board. Both are OPTIONAL and
        # carried through verbatim rather than defaulted here: the UI derives
        # a sensible fallback (company from the registrable domain, server from
        # the segment), so a target added through the editor groups correctly
        # without anyone having to know these fields exist.
        for k in ("srv", "co"):
            v = t.get(k)
            if v:
                rec[k] = str(v)[:60]
        out.append(rec)
    if errs:
        return None, errs
    return out, []


def load_targets():
    """Three layers, most-specific wins: live store > deployed seed > builtin.

    NOTE FOR ANYONE DEBUGGING: the source you are reading is the LAST resort.
    If the live store exists, BUILTIN_TARGETS above is dead code. Ask the API."""
    for path in (LIVE_TARGETS, SEED_TARGETS):
        raw = _read_json(path)
        if raw is not None:
            ts, errs = validate_targets(raw)
            if ts is not None:
                return ts, path
            sys.stderr.write(f"[netmap] ignoring invalid {path}: {errs[:3]}\n")
    return list(BUILTIN_TARGETS), "builtin"


def load_acks():
    a = _read_json(ACKS_PATH)
    return a if isinstance(a, dict) else {}


def load_push():
    p = _read_json(PUSH_PATH)
    return p if isinstance(p, dict) else {}


# ---------------------------------------------------------------------------
# TLS certificate expiry
#
# We connect with verification OFF (see probe_https), which means the stdlib
# hands back the DER and no parsed dict at all -- so notAfter has to be pulled
# out of the DER by hand. Verified against `openssl x509 -noout -enddate` on
# six live hosts before this was trusted; see test_server.py.
# ---------------------------------------------------------------------------
_UTCTIME = re.compile(rb"^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$")
_GENTIME = re.compile(rb"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$")


def _der_times(der):
    """Yield every UTCTime/GeneralizedTime in the DER, in order.

    The certificate's Validity is the first SEQUENCE holding exactly two of
    them, so scanning tag-by-tag and taking the 2nd of the first adjacent pair
    is both simpler and more robust than a full ASN.1 walk."""
    i, n = 0, len(der)
    while i < n - 1:
        tag, ln = der[i], der[i + 1]
        if tag in (0x17, 0x18) and ln < 0x80 and i + 2 + ln <= n:
            body = der[i + 2:i + 2 + ln]
            m = _UTCTIME.match(body) if tag == 0x17 else _GENTIME.match(body)
            if m:
                g = [int(x) for x in m.groups()]
                if tag == 0x17:
                    g[0] += 2000 if g[0] < 50 else 1900
                try:
                    yield datetime(*g, tzinfo=timezone.utc), i
                except ValueError:
                    pass
            i += 2 + ln
            continue
        i += 1


def cert_not_after(der):
    """notAfter as a UTC datetime, or None. Takes the second of the first
    adjacent (notBefore, notAfter) pair -- later pairs belong to extensions."""
    times = list(_der_times(der))
    for a, b in zip(times, times[1:]):
        # adjacent in the encoding => same Validity SEQUENCE
        if b[1] - a[1] <= 20 and b[0] >= a[0]:
            return b[0]
    return times[1][0] if len(times) > 1 else None


def cert_days_left(der, now=None):
    na = cert_not_after(der)
    if na is None:
        return None
    now = now or datetime.now(timezone.utc)
    return int((na - now).total_seconds() // 86400)


# ---------------------------------------------------------------------------
# Probes -- one function per mode, dispatched off opts["m"]
# ---------------------------------------------------------------------------
_STATUS = re.compile(rb"^HTTP/1\.[01] (\d{3})")


def _judge(code, opts):
    exp = opts.get("expect")
    if isinstance(exp, list) and exp:
        return code in exp
    return code < 500


def judge_with_cert(code, opts, cert_days):
    """Final up/down for an HTTP(S) exchange. Returns (up, detail).

    Kept as a pure function so the expired-cert override is testable without a
    socket -- it is the one judgement here that contradicts the status code,
    so it is the one most worth pinning down.

    An expired cert is a total outage for every browser however cheerfully the
    server returns 200. Pure reachability monitoring misses this entirely: the
    board this was modelled on found a host serving a default self-signed cert
    that had been expired ~16 months, green the whole time.
    """
    up = _judge(code, opts)
    if cert_days is not None and cert_days < 0:
        return False, f"HTTP {code} but CERT EXPIRED {abs(cert_days)}d ago"
    return up, f"HTTP {code}"


def probe_tcp(ip, port, opts):
    """Plain TCP connect.

    `opts["invert"]` flips the verdict: UP means the port is REFUSED or
    filtered. That is not a curiosity -- several services on the 165 host bind
    0.0.0.0 (so `ss` reports them as world-listening) while a cloud firewall
    upstream is the only thing actually keeping them shut. An inverted target
    is the guard on that firewall: if someone opens it, this goes red. Without
    it, the difference between "closed" and "nobody checked" is invisible.
    """
    invert = bool(opts.get("invert"))
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            ms = int((time.monotonic() - t0) * 1000)
            if invert:
                return {"up": False, "ms": ms,
                        "detail": "REACHABLE but must be closed"}
            return {"up": True, "ms": ms, "detail": "tcp open"}
    except Exception as e:
        if invert:
            return {"up": True, "ms": None,
                    "detail": f"correctly closed ({type(e).__name__})"}
        return {"up": False, "ms": None, "detail": f"tcp: {type(e).__name__}"}


def _http_exchange(ip, port, opts, use_tls):
    """GET the path, read ONLY the status line, close.

    GET, never HEAD: an app was found answering HEAD with a redirect that is
    byte-identical to the reverse proxy's catch-all while answering GET
    correctly -- HEAD would have reported a healthy app as missing. Because we
    never read the body, GET costs the same as HEAD on the wire we care about.
    """
    host = opts.get("host") or ip
    path = opts.get("path") or "/"
    timeout = HTTPS_TIMEOUT if use_tls else HTTP_TIMEOUT
    t0 = time.monotonic()
    cert_days = None
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Reachability, not trust: a self-signed but in-date cert still
            # means the vhost is serving, and we want a status code either way.
            # Expiry is then reported SEPARATELY as cert_days below.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)  # SNI
            der = sock.getpeercert(binary_form=True)
            if der:
                cert_days = cert_days_left(der)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: bevora-netmap/1\r\nAccept: */*\r\n"
               f"Connection: close\r\n\r\n").encode()
        sock.sendall(req)
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
            return {"up": False, "ms": ms, "detail": "no status line", "cert_days": cert_days}
        code = int(m.group(1))
        up, detail = judge_with_cert(code, opts, cert_days)
        return {"up": up, "ms": ms, "code": code, "detail": detail, "cert_days": cert_days}
    except Exception as e:
        return {"up": False, "ms": None, "detail": f"{type(e).__name__}", "cert_days": cert_days}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def probe_http(ip, port, opts):
    return _http_exchange(ip, port, opts, use_tls=False)


def probe_https(ip, port, opts):
    return _http_exchange(ip, port, opts, use_tls=True)


def probe_push(ip, port, opts, push_store=None, now=None):
    """No probe at all -- read the last value a remote agent pushed.

    Past the TTL the row reads STALE (and DOWN), never green. A dead agent
    must not look like perfect uptime forever; that is the entire safety
    property of push mode."""
    now = now if now is not None else time.time()
    store = push_store if push_store is not None else load_push()
    rec = store.get(f"{ip}:{port}")
    if not rec:
        return {"up": False, "ms": None, "detail": "push: never reported", "stale": True}
    age = now - float(rec.get("ts", 0))
    ttl = int(opts.get("ttl", PUSH_TTL))
    if age > ttl:
        return {"up": False, "ms": rec.get("ms"), "stale": True,
                "detail": f"push: STALE {int(age)}s > {ttl}s TTL"}
    return {"up": bool(rec.get("up")), "ms": rec.get("ms"), "stale": False,
            "detail": f"push: {'up' if rec.get('up') else 'down'} {int(age)}s ago"}


PROBES = {"tcp": probe_tcp, "http": probe_http, "https": probe_https}


def probe_one(target, push_store=None, now=None):
    ip, port = target["ip"], target["port"]
    opts = target.get("opts") or {}
    mode = opts.get("m", "tcp")
    try:
        if mode == "push":
            r = probe_push(ip, port, opts, push_store=push_store, now=now)
        else:
            r = PROBES.get(mode, probe_tcp)(ip, port, opts)
    except Exception as e:                                   # never kill a cycle
        r = {"up": False, "ms": None, "detail": f"probe error: {type(e).__name__}"}
    r.setdefault("cert_days", None)
    r.setdefault("stale", False)
    return r


# ---------------------------------------------------------------------------
# The flap gate
#
# Without this the incident log is noise. The counter is PERSISTENT across
# cycles -- it is emphatically NOT a retry inside one probe. An immediate retry
# lands inside the same 4-6s graceful restart, fails twice, and confirms the
# wrong answer with more confidence. It has to be two probes a full REFRESH
# apart. Cost: <= one REFRESH of detection delay on a genuine outage.
# ---------------------------------------------------------------------------
def confirmed_up(key, raw_up, counts):
    if raw_up:
        counts.pop(key, None)
        return True
    # min() clamps: a permanently-down host fails every cycle forever
    # (~2,880/day at REFRESH=30) and an unclamped counter grows without bound.
    n = min(counts.get(key, 0) + 1, DOWN_CONFIRM_CYCLES)
    counts[key] = n
    return n < DOWN_CONFIRM_CYCLES


# ---------------------------------------------------------------------------
# History (SQLite) -- must FAIL SAFE
#
# Reachability is the product; history is a nice-to-have. If the DB cannot be
# opened (no writable volume, disk full) we set HISTORY_OK=False and keep
# serving the live map. Storage failure must never take the board down.
#
# Concurrency invariant: ONE long-lived write connection, owned by the probe
# thread. Read connections are short-lived and per-request. WAL allows
# concurrent readers, which is why there is no lock anywhere in this file.
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS sample(
  ts INTEGER, ip TEXT, port INTEGER, up INTEGER, ms INTEGER);
CREATE TABLE IF NOT EXISTS event(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT, port INTEGER, label TEXT, seg TEXT,
  down_ts INTEGER, up_ts INTEGER, duration INTEGER);
CREATE INDEX IF NOT EXISTS idx_sample_ts   ON sample(ts);
CREATE INDEX IF NOT EXISTS idx_sample_host ON sample(ip, port, ts);
CREATE INDEX IF NOT EXISTS idx_event_down  ON event(down_ts);
CREATE INDEX IF NOT EXISTS idx_event_open  ON event(up_ts);
"""

HISTORY_OK = False


def db_connect(path=DB_PATH):
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def db_open_safe(path=DB_PATH):
    global HISTORY_OK
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        conn = db_connect(path)
        HISTORY_OK = True
        return conn
    except Exception as e:
        HISTORY_OK = False
        sys.stderr.write(f"[netmap] HISTORY DISABLED ({type(e).__name__}: {e}) "
                         f"-- live board continues\n")
        return None


def load_open_events(conn):
    """key (ip,port) -> event id, for every event that has not closed."""
    if conn is None:
        return {}
    rows = conn.execute(
        "SELECT id, ip, port FROM event WHERE up_ts IS NULL").fetchall()
    return {(r[1], r[2]): r[0] for r in rows}


def open_event(conn, open_ev, t, now):
    key = (t["ip"], t["port"])
    if conn is None or key in open_ev:
        return
    cur = conn.execute(
        "INSERT INTO event(ip,port,label,seg,down_ts,up_ts,duration) "
        "VALUES(?,?,?,?,?,NULL,NULL)",
        (t["ip"], t["port"], t.get("label", ""), t.get("seg", ""), now))
    open_ev[key] = cur.lastrowid


def close_event(conn, open_ev, key, now):
    if conn is None or key not in open_ev:
        return
    eid = open_ev.pop(key)
    conn.execute(
        "UPDATE event SET up_ts=?, duration=?-down_ts WHERE id=?",
        (now, now, eid))


def reconcile_stranded(conn, open_ev, live_keys, now, fail_counts):
    """Close incidents for targets that no longer exist in the target list.

    THE BUG THIS FIXES: an event only closes when a later cycle sees that host
    UP. Remove a target and nothing probes it, no up sample ever arrives, and
    its open incident can NEVER close -- it reads as an ongoing outage for as
    long as the database lives, permanently skewing the open-incident count and
    every MTTR figure.

    This lives in the cycle, not in the target editor, on purpose: the probe
    thread already knows exactly which targets exist, so it needs no new API,
    no lock, and no second writer on the probe thread's connection.
    """
    if not live_keys:
        # Guard: a momentarily empty target list (bad edit, unreadable store)
        # must not close every open incident at once.
        return 0
    stranded = [k for k in open_ev if k not in live_keys]
    for key in stranded:
        close_event(conn, open_ev, key, now)
        # Drop the flap counter too, or state is retained for a host that is
        # never probed again.
        fail_counts.pop(key, None)
    return len(stranded)


def prune(conn, now):
    if conn is None:
        return
    conn.execute("DELETE FROM sample WHERE ts < ?", (now - RETENTION_DAYS * 86400,))


# ---------------------------------------------------------------------------
# The cycle
# ---------------------------------------------------------------------------
def run_cycle(targets, conn, state, now=None, executor=None, push_store=None):
    """Probe every target once, gate, record, reconcile. Returns the snapshot.

    The flap gate is applied HERE, inside the cycle, so the board, the sample
    history and the incident list all get the SAME answer. /api/probe routes
    through the same gate for its stored effect (its HTTP response stays raw --
    the caller asked what the host is doing right now)."""
    now = int(now if now is not None else time.time())
    fail_counts = state.setdefault("fail_counts", {})
    open_ev = state.setdefault("open_ev", {})
    push_store = push_store if push_store is not None else load_push()

    def _run(t):
        return probe_one(t, push_store=push_store, now=now)

    # ex.map, NOT submit+as_completed: map preserves input order, so the board
    # snapshot stays stable between cycles and rows do not jump around.
    if executor is not None:
        results = list(executor.map(_run, targets))
    else:
        results = [_run(t) for t in targets]

    snapshot, live_keys = [], set()
    for t, r in zip(targets, results):
        key = (t["ip"], t["port"])
        live_keys.add(key)
        up = confirmed_up(key, bool(r["up"]), fail_counts)
        row = dict(t)
        row.update({
            "up": up, "raw_up": bool(r["up"]), "ms": r.get("ms"),
            "detail": r.get("detail", ""), "cert_days": r.get("cert_days"),
            "stale": r.get("stale", False), "ts": now,
            "pending": (not r["up"]) and up,      # failing, not yet confirmed
        })
        snapshot.append(row)

        if conn is not None:
            try:
                conn.execute(
                    "INSERT INTO sample(ts,ip,port,up,ms) VALUES(?,?,?,?,?)",
                    (now, t["ip"], t["port"], 1 if up else 0, r.get("ms")))
                if up:
                    close_event(conn, open_ev, key, now)
                else:
                    open_event(conn, open_ev, t, now)
            except Exception as e:
                sys.stderr.write(f"[netmap] sample write failed: {e}\n")

    if conn is not None:
        try:
            reconcile_stranded(conn, open_ev, live_keys, now, fail_counts)
            state["cycles"] = state.get("cycles", 0) + 1
            if state["cycles"] % max(1, int(3600 / max(REFRESH, 1))) == 0:
                prune(conn, now)
            conn.commit()
        except Exception as e:
            sys.stderr.write(f"[netmap] cycle commit failed: {e}\n")

    return snapshot


# In-memory current state, replaced wholesale each cycle (never mutated in
# place, so a reader always sees one consistent generation).
STATE = {"snapshot": [], "ts": 0, "source": "builtin", "cycles": 0}
_CYCLE_STATE = {"fail_counts": {}, "open_ev": {}, "cycles": 0}
_DB = None


def prober_loop():
    global _DB
    _DB = db_open_safe()
    _CYCLE_STATE["open_ev"] = load_open_events(_DB)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS,
                                               thread_name_prefix="probe")
    while True:
        t0 = time.time()
        try:
            targets, source = load_targets()
            snap = run_cycle(targets, _DB, _CYCLE_STATE, executor=ex)
            STATE["snapshot"] = snap
            STATE["ts"] = int(t0)
            STATE["source"] = source
            STATE["cycles"] = _CYCLE_STATE.get("cycles", 0)
        except Exception as e:
            sys.stderr.write(f"[netmap] cycle failed: {type(e).__name__}: {e}\n")
        time.sleep(max(1.0, REFRESH - (time.time() - t0)))


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------
def ack_state(acks, key, now=None):
    """'' | 'perm' | 'window'. `until: null` means never expires = PERMANENT
    (down by design); a timestamp is a time-boxed maintenance window."""
    now = now if now is not None else time.time()
    a = acks.get(key)
    if not a:
        return ""
    until = a.get("until")
    if until is None:
        return "perm"
    try:
        return "window" if float(until) > now else ""
    except (TypeError, ValueError):
        return ""


def overview(snapshot, conn, acks, window=86400, now=None, buckets=48):
    now = int(now if now is not None else time.time())
    since = now - window
    up = sum(1 for r in snapshot if r["up"])
    down_rows = [r for r in snapshot if not r["up"]]
    segs = {}
    for r in snapshot:
        s = segs.setdefault(r.get("seg") or "unsegmented",
                            {"seg": r.get("seg") or "unsegmented", "up": 0, "down": 0})
        s["up" if r["up"] else "down"] += 1

    # Acked hosts are excluded from the open-incident KPI -- otherwise it never
    # reaches zero and people stop reading it.
    unacked_down = [r for r in down_rows
                    if not ack_state(acks, f'{r["ip"]}:{r["port"]}', now)]

    out = {
        "ts": now, "history_ok": HISTORY_OK, "window": window,
        "total": len(snapshot), "up": up, "down": len(down_rows),
        "down_unacked": len(unacked_down),
        "segments": sorted(segs.values(), key=lambda s: s["seg"]),
        "cert_warn": sorted(
            [{"label": r["label"], "host": (r.get("opts") or {}).get("host", r["ip"]),
              "days": r["cert_days"]}
             for r in snapshot
             if r.get("cert_days") is not None and r["cert_days"] <= CERT_WARN_DAYS],
            key=lambda c: c["days"]),
        "open_incidents": 0, "flappiest": [], "slowest": [], "availability": None,
        # THE DISCRIMINATING CHECK -- see README. These two are computed from
        # completely different sources (the event table vs the live snapshot)
        # and must agree. When they disagreed (10 vs 9) on the board this was
        # modelled on, that single mismatch is what exposed stranded incidents.
        "invariant_ok": True, "invariant_detail": "",
    }
    if conn is None:
        out["invariant_detail"] = "history disabled -- invariant not checked"
        return out

    try:
        open_rows = conn.execute(
            "SELECT ip,port,label,seg,down_ts FROM event WHERE up_ts IS NULL").fetchall()
        open_unacked = [r for r in open_rows
                        if not ack_state(acks, f"{r[0]}:{r[1]}", now)]
        out["open_incidents"] = len(open_unacked)
        out["open_list"] = [{"ip": r[0], "port": r[1], "label": r[2], "seg": r[3],
                             "down_ts": r[4], "mins": int((now - r[4]) / 60)}
                            for r in sorted(open_unacked, key=lambda r: r[4])]
        if len(open_unacked) != len(unacked_down):
            out["invariant_ok"] = False
            out["invariant_detail"] = (
                f"open incidents ({len(open_unacked)}) != down rows on board "
                f"({len(unacked_down)}) -- stranded or missing event")
        else:
            out["invariant_detail"] = (
                f"open incidents == down rows ({len(unacked_down)})")

        tot, upc = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(up),0) FROM sample WHERE ts>=?",
            (since,)).fetchone()
        out["availability"] = round(100.0 * upc / tot, 3) if tot else None

        out["flappiest"] = [
            {"label": r[0] or f"{r[1]}:{r[2]}", "ip": r[1], "port": r[2], "count": r[3]}
            for r in conn.execute(
                "SELECT label,ip,port,COUNT(*) c FROM event WHERE down_ts>=? "
                "GROUP BY ip,port ORDER BY c DESC LIMIT 5", (since,)).fetchall()]

        out["slowest"] = [
            {"ip": r[0], "port": r[1], "ms": int(r[2])}
            for r in conn.execute(
                "SELECT ip,port,AVG(ms) a FROM sample WHERE ts>=? AND ms IS NOT NULL "
                "AND up=1 GROUP BY ip,port ORDER BY a DESC LIMIT 5", (since,)).fetchall()]

        step = max(1, window // buckets)
        rows = conn.execute(
            "SELECT (ts/?)*? b, COUNT(*), COALESCE(SUM(up),0) FROM sample "
            "WHERE ts>=? GROUP BY b ORDER BY b", (step, step, since)).fetchall()
        out["timeline"] = [{"ts": r[0], "n": r[1],
                            "pct": round(100.0 * r[2] / r[1], 2) if r[1] else None}
                           for r in rows]
    except Exception as e:
        out["invariant_detail"] = f"aggregate query failed: {type(e).__name__}"
    return out




# ---------------------------------------------------------------------------
# §11 Auth -- fails CLOSED
#
# This page is an inventory of everything we own and where it is weak, so it is
# treated as sensitive: nothing is served without a valid session, and only an
# explicit path allow-list is routed -- never a directory, or the .bak files,
# the SQLite database and this source would all be downloadable.
#
# Credentials live in /data/auth.json as a PBKDF2 hash, never in plaintext and
# never in the image. The seeded pair is a BOOTSTRAP credential: `must_change`
# is set, and until it is cleared every authenticated route redirects to the
# change form. A shared default that is merely "documented as temporary" stays
# live for years; one the server refuses to work around does not.
# ---------------------------------------------------------------------------
import base64
import hashlib
import secrets

SEED_USER = os.environ.get("NETMAP_USER", "Mavrone")
SEED_PASS = os.environ.get("NETMAP_PASS", "P@55w0rd")
PUSH_TOKEN = os.environ.get("NETMAP_PUSH_TOKEN", "")
AUTH_PATH = os.path.join(DATA_DIR, "auth.json")

PBKDF2_ROUNDS = 200_000
SESSION_TTL = int(os.environ.get("NETMAP_SESSION_TTL", str(12 * 3600)))
COOKIE = "netmap_sid"
MIN_PASS_LEN = 12

_SESSIONS = {}          # token -> {"user":.., "ts":..}
_SESS_LOCK = threading.Lock()
_LOGIN_FAILS = {}       # client ip -> [count, first_ts]
_LOGIN_LOCK = threading.Lock()
LOGIN_MAX_FAILS = 8
LOGIN_WINDOW = 300


def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return salt, dk.hex()


def verify_pw(pw, salt, expect):
    try:
        _, got = hash_pw(pw, salt)
    except Exception:
        return False
    return hmac.compare_digest(got, expect)


def load_auth():
    """Read the credential record, seeding it on first run.

    If /data is not writable we still return a usable in-memory record rather
    than serving unauthenticated: storage failure must degrade the tool, never
    disarm the lock."""
    rec = _read_json(AUTH_PATH)
    if isinstance(rec, dict) and rec.get("hash") and rec.get("salt"):
        return rec
    salt, h = hash_pw(SEED_PASS)
    rec = {"user": SEED_USER, "salt": salt, "hash": h,
           "must_change": True, "updated": int(time.time())}
    try:
        _write_json_atomic(AUTH_PATH, rec, keep_bak=False)
        os.chmod(AUTH_PATH, 0o600)
    except Exception as e:
        sys.stderr.write(f"[netmap] WARNING: cannot persist {AUTH_PATH} "
                         f"({type(e).__name__}) -- the bootstrap credential will "
                         f"return on every restart\n")
    return rec


def save_auth(rec):
    _write_json_atomic(AUTH_PATH, rec, keep_bak=False)
    try:
        os.chmod(AUTH_PATH, 0o600)
    except Exception:
        pass


def check_login(user, pw):
    rec = load_auth()
    ok = (hmac.compare_digest(str(user), str(rec.get("user", "")))
          and verify_pw(pw, rec["salt"], rec["hash"]))
    return (rec if ok else None)


def password_problem(pw, user):
    """Return a reason string, or None if acceptable.

    Deliberately short: length is the property that actually matters, and a
    long composition ruleset mostly teaches people to write P@55w0rd1."""
    if len(pw or "") < MIN_PASS_LEN:
        return f"password must be at least {MIN_PASS_LEN} characters"
    if pw == SEED_PASS:
        return "cannot reuse the bootstrap password"
    if user and pw.lower() == str(user).lower():
        return "password cannot be the username"
    return None


def new_session(user):
    tok = secrets.token_urlsafe(32)
    with _SESS_LOCK:
        now = time.time()
        for t, s in [(t, s) for t, s in _SESSIONS.items() if now - s["ts"] > SESSION_TTL]:
            _SESSIONS.pop(t, None)
        _SESSIONS[tok] = {"user": user, "ts": now}
    return tok


def session_user(token):
    if not token:
        return None
    with _SESS_LOCK:
        s = _SESSIONS.get(token)
        if not s:
            return None
        if time.time() - s["ts"] > SESSION_TTL:
            _SESSIONS.pop(token, None)
            return None
        return s["user"]


def drop_session(token):
    with _SESS_LOCK:
        _SESSIONS.pop(token, None)


def drop_all_sessions():
    """Called on a credential change: every other session must re-authenticate
    with the new secret, or rotating the password would not evict anyone."""
    with _SESS_LOCK:
        _SESSIONS.clear()


def login_throttled(ip, now=None):
    now = now if now is not None else time.time()
    with _LOGIN_LOCK:
        rec = _LOGIN_FAILS.get(ip)
        if not rec:
            return False
        if now - rec[1] > LOGIN_WINDOW:
            _LOGIN_FAILS.pop(ip, None)
            return False
        return rec[0] >= LOGIN_MAX_FAILS


def note_login_fail(ip, now=None):
    now = now if now is not None else time.time()
    with _LOGIN_LOCK:
        rec = _LOGIN_FAILS.get(ip)
        if not rec or now - rec[1] > LOGIN_WINDOW:
            _LOGIN_FAILS[ip] = [1, now]
        else:
            rec[0] += 1


def clear_login_fails(ip):
    with _LOGIN_LOCK:
        _LOGIN_FAILS.pop(ip, None)


def parse_cookies(header):
    out = {}
    for part in (header or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
STATIC = {"/": "index.html", "/index.html": "index.html"}
API_GET = ("/api/status", "/api/history", "/api/events", "/api/overview",
           "/api/targets", "/api/probe", "/api/health", "/api/whoami")
API_POST = ("/api/targets", "/api/ack", "/api/probe-push", "/api/credentials")
OPEN_PATHS = ("/login", "/api/health")          # reachable without a session

_BADPATH = re.compile(r"[\s\r\n]")

_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(title)s &middot; bevoraSG netmap</title>
<link rel="icon" href="data:image/svg+xml,%%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%%3E%%3Crect width='32' height='32' rx='7' fill='%%230d1117'/%%3E%%3Cpath d='M9 22 L16 10 L23 19' fill='none' stroke='%%235b90ff' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/%%3E%%3Ccircle cx='16' cy='10' r='3.6' fill='%%233fb950'/%%3E%%3Ccircle cx='9' cy='22' r='3.1' fill='%%235b90ff'/%%3E%%3Ccircle cx='23' cy='19' r='3.1' fill='%%235b90ff'/%%3E%%3C/svg%%3E">
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#12161c;--mut:#5a6675;--line:#dfe3e8;--acc:#2563eb;--bad:#b42318}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--acc:#4b8bff;--bad:#f85149}}
.mark{display:block;margin:0 auto 14px}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;
background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;padding:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;width:100%%;max-width:400px}
h1{margin:0 0 4px;font-size:19px}p.sub{margin:0 0 20px;color:var(--mut);font-size:13px}
label{display:block;font-size:12px;font-weight:600;color:var(--mut);margin:14px 0 5px;text-transform:uppercase;letter-spacing:.04em}
input{width:100%%;padding:11px 12px;font-size:15px;border:1px solid var(--line);border-radius:8px;
background:var(--bg);color:var(--fg);min-height:44px}
input:focus{outline:2px solid var(--acc);outline-offset:1px}
button{width:100%%;margin-top:22px;padding:12px;font-size:15px;font-weight:600;min-height:44px;
border:0;border-radius:8px;background:var(--acc);color:#fff;cursor:pointer}
.err{margin-top:16px;padding:10px 12px;border-radius:8px;font-size:13px;
background:color-mix(in srgb,var(--bad) 12%%,transparent);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad) 35%%,transparent)}
.note{margin-top:18px;font-size:12px;color:var(--mut)}
</style></head><body><div class="card">
<svg class="mark" viewBox="0 0 32 32" width="34" height="34" aria-hidden="true">
<rect width="32" height="32" rx="7" fill="#0d1117"/>
<path d="M9 22 L16 10 L23 19" fill="none" stroke="#5b90ff" stroke-width="2.2"
      stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="16" cy="10" r="3.6" fill="#3fb950"/><circle cx="9" cy="22" r="3.1" fill="#5b90ff"/>
<circle cx="23" cy="19" r="3.1" fill="#5b90ff"/></svg>
<h1>%(title)s</h1><p class="sub">%(sub)s</p>%(body)s</div></body></html>"""


def login_page(err="", nexturl="/"):
    body = ('<form method="POST" action="/login">'
            f'<input type="hidden" name="next" value="{html_escape(nexturl)}">'
            '<label for="u">Username</label>'
            '<input id="u" name="user" autocomplete="username" autofocus required>'
            '<label for="p">Password</label>'
            '<input id="p" name="pass" type="password" autocomplete="current-password" required>'
            '<button type="submit">Sign in</button>'
            + (f'<div class="err">{html_escape(err)}</div>' if err else "") +
            '</form>')
    return (_PAGE % {"title": "Sign in", "sub": "bevoraSG network map",
                     "body": body}).encode()


def change_page(user, err="", forced=False):
    sub = ("This is the bootstrap credential. Set your own before continuing."
           if forced else "Change your sign-in details.")
    body = ('<form method="POST" action="/api/credentials" id="f">'
            f'<label for="u">Username</label><input id="u" name="user" value="{html_escape(user)}" required>'
            '<label for="c">Current password</label>'
            '<input id="c" name="current" type="password" autocomplete="current-password" required>'
            '<label for="n">New password</label>'
            '<input id="n" name="new" type="password" autocomplete="new-password" required>'
            '<label for="n2">Confirm new password</label>'
            '<input id="n2" name="confirm" type="password" autocomplete="new-password" required>'
            '<button type="submit">Save and continue</button>'
            + (f'<div class="err">{html_escape(err)}</div>' if err else "") +
            f'<div class="note">Minimum {MIN_PASS_LEN} characters. Saving signs '
            'out every other session, including this one.</div></form>')
    return (_PAGE % {"title": "Set your credentials", "sub": sub,
                     "body": body}).encode()


def html_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "netmap"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        if os.environ.get("NETMAP_ACCESS_LOG"):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))

    # -- plumbing -----------------------------------------------------------
    def client_ip(self):
        """Behind our own nginx only. X-Forwarded-For's FIRST entry is
        client-controlled, so the LAST hop nginx appended is the only one worth
        reading -- and even that is trusted only because nothing else can reach
        this port."""
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[-1].strip()[:45]
        return self.client_address[0]

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                         "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200, extra=None):
        self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def _html(self, body, code=200, extra=None):
        self._send(code, body, "text/html; charset=utf-8", extra)

    def _redirect(self, to, extra=None):
        e = {"Location": to}
        e.update(extra or {})
        self._send(303, b"", "text/plain", e)

    def _cookie(self, tok, clear=False):
        # Secure is set unconditionally: the only supported way to reach this
        # is https://status.bevorasg.com through nginx. If you are testing over
        # plain http, use a tunnel, do not drop the flag.
        if clear:
            return {"Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly; "
                                  f"SameSite=Strict; Secure"}
        return {"Set-Cookie": f"{COOKIE}={tok}; Path=/; Max-Age={SESSION_TTL}; "
                              f"HttpOnly; SameSite=Strict; Secure"}

    def _token(self):
        return parse_cookies(self.headers.get("Cookie")).get(COOKIE, "")

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None, "bad length"
        if n <= 0 or n > MAX_POST:
            # We are about to reject WITHOUT draining the body. Anything still
            # in the socket would be parsed as the next request line on a
            # keep-alive connection (observed as a spurious REQUEST_URI_TOO_LONG
            # against the client's own payload), so this connection ends here.
            self.close_connection = True
            return None, f"body must be 1..{MAX_POST} bytes"
        raw = self.rfile.read(n)
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype == "application/x-www-form-urlencoded":
            return {k: v[0] for k, v in
                    urllib.parse.parse_qs(raw.decode("utf-8", "replace")).items()}, None
        try:
            return json.loads(raw.decode("utf-8")), None
        except Exception:
            return None, "invalid JSON"

    def _wants_json(self):
        return "application/json" in (self.headers.get("Accept") or "")

    # -- the gate -----------------------------------------------------------
    def _gate(self, path):
        """Returns (user, auth_record) or None having already responded.

        Fails CLOSED: any path not explicitly opened requires a live session,
        and a session holding the bootstrap credential is routed to the change
        form and nowhere else."""
        user = session_user(self._token())
        if not user:
            if self._wants_json() or path.startswith("/api/"):
                self._json({"error": "auth required"}, 401)
            else:
                self._html(login_page(nexturl=path), 401)
            return None
        rec = load_auth()
        if rec.get("must_change") and path not in ("/change", "/api/credentials", "/logout"):
            if path.startswith("/api/"):
                self._json({"error": "credential change required",
                            "must_change": True}, 403)
            else:
                self._redirect("/change")
            return None
        return user, rec

    # -- GET ----------------------------------------------------------------
    def do_GET(self):
        if _BADPATH.search(self.path or ""):
            return self._send(400, b'{"error":"bad path"}')
        u = urllib.parse.urlsplit(self.path)
        path, q = u.path, urllib.parse.parse_qs(u.query)

        if path == "/login":
            if session_user(self._token()):
                return self._redirect("/")
            return self._html(login_page())
        if path == "/api/health":
            # Deliberately unauthenticated and deliberately contentless: it
            # reports that the process is alive, never what it monitors.
            return self._json({"ok": True, "history_ok": HISTORY_OK,
                               "cycles": STATE.get("cycles", 0)})

        g = self._gate(path)
        if g is None:
            return
        user, rec = g

        if path == "/change":
            return self._html(change_page(user, forced=bool(rec.get("must_change"))))
        if path == "/logout":
            drop_session(self._token())
            return self._redirect("/login", self._cookie("", clear=True))
        if path in STATIC:
            try:
                with open(os.path.join(APP_DIR, STATIC[path]), "rb") as fh:
                    body = fh.read()
            except Exception:
                return self._send(500, b"index.html missing", "text/plain")
            return self._html(body)
        if path not in API_GET:
            return self._send(404, b'{"error":"not found"}')
        return self._api_get(path, q, user)

    def do_HEAD(self):
        self.do_GET()

    def _api_get(self, path, q, user):
        acks = load_acks()
        now = time.time()
        if path == "/api/whoami":
            return self._json({"user": user, "refresh": REFRESH,
                               "history_ok": HISTORY_OK})
        if path == "/api/status":
            rows = []
            for r in STATE["snapshot"]:
                key = f'{r["ip"]}:{r["port"]}'
                rows.append(dict(r, ack=ack_state(acks, key, now),
                                 ack_note=(acks.get(key) or {}).get("note", "")))
            return self._json({"ts": STATE["ts"], "source": STATE["source"],
                               "history_ok": HISTORY_OK, "refresh": REFRESH,
                               "hosts": rows})
        if path == "/api/overview":
            win = int((q.get("window") or ["86400"])[0])
            conn = self._read_conn()
            try:
                return self._json(overview(STATE["snapshot"], conn, acks,
                                           window=max(300, min(win, 30 * 86400))))
            finally:
                if conn:
                    conn.close()
        if path == "/api/targets":
            targets, source = load_targets()
            return self._json({"source": source, "targets": targets,
                               "note": "This is the live list. BUILTIN_TARGETS in "
                                       "server.py is a fallback and may differ -- "
                                       "never conclude anything from the source."})
        if path == "/api/probe":
            ip = (q.get("ip") or [""])[0]
            try:
                port = int((q.get("port") or ["0"])[0])
            except ValueError:
                port = 0
            if not ip or not _HOSTRE.match(ip) or not 1 <= port <= 65535:
                return self._json({"error": "ip and port required"}, 400)
            targets, _ = load_targets()
            t = next((x for x in targets if x["ip"] == ip and x["port"] == port),
                     None)
            if t is None:
                # Only probe what is already on the list: an authenticated
                # arbitrary-connect endpoint is a port scanner with our source
                # address on it.
                return self._json({"error": "not a configured target"}, 404)
            r = probe_one(t)
            # Raw, ungated: the caller asked what the host is doing RIGHT NOW.
            # Stored board state is only ever moved by the cycle, so one click
            # during a blip cannot turn the board red behind the loop's back.
            return self._json({"ip": ip, "port": port, "raw": r,
                               "note": f"raw single probe; board state is gated "
                                       f"over {DOWN_CONFIRM_CYCLES} cycles"})
        conn = self._read_conn()
        if conn is None:
            return self._json({"error": "history disabled", "history_ok": False,
                               "events": [], "buckets": []})
        try:
            if path == "/api/events":
                lim = max(1, min(int((q.get("limit") or ["200"])[0]), 1000))
                rows = conn.execute(
                    "SELECT id,ip,port,label,seg,down_ts,up_ts,duration FROM event "
                    "ORDER BY down_ts DESC LIMIT ?", (lim,)).fetchall()
                cols = ("id", "ip", "port", "label", "seg", "down_ts", "up_ts", "duration")
                return self._json({"history_ok": True,
                                   "events": [dict(zip(cols, r)) for r in rows]})
            if path == "/api/history":
                win = max(300, min(int((q.get("window") or ["86400"])[0]), 30 * 86400))
                since = int(time.time()) - win
                step = max(60, win // 96)
                ip = (q.get("ip") or [""])[0]
                args, where = [step, step, since], ""
                if ip:
                    where = " AND ip=?"
                    args.append(ip)
                    if q.get("port"):
                        where += " AND port=?"
                        args.append(int(q["port"][0]))
                rows = conn.execute(
                    "SELECT (ts/?)*? b, COUNT(*), COALESCE(SUM(up),0), AVG(ms) "
                    "FROM sample WHERE ts>=?" + where +
                    " GROUP BY b ORDER BY b", args).fetchall()
                return self._json({"history_ok": True, "step": step, "buckets": [
                    {"ts": r[0], "n": r[1],
                     "pct": round(100.0 * r[2] / r[1], 2) if r[1] else None,
                     "ms": int(r[3]) if r[3] is not None else None} for r in rows]})
        except Exception as e:
            return self._json({"error": type(e).__name__}, 500)
        finally:
            conn.close()
        return self._send(404, b'{"error":"not found"}')

    def _read_conn(self):
        """Short-lived READ connection. WAL permits concurrent readers while the
        probe thread holds the single writer -- that is the whole reason there
        is no lock around the database anywhere in this file."""
        if not HISTORY_OK:
            return None
        try:
            c = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=3)
            c.execute("PRAGMA query_only=ON")
            return c
        except Exception:
            return None

    # -- POST ---------------------------------------------------------------
    def do_POST(self):
        if _BADPATH.search(self.path or ""):
            return self._send(400, b'{"error":"bad path"}')
        path = urllib.parse.urlsplit(self.path).path

        if path == "/login":
            return self._do_login()
        if path == "/logout":
            drop_session(self._token())
            return self._redirect("/login", self._cookie("", clear=True))
        if path == "/api/probe-push":
            return self._do_push()          # token-authenticated, not session

        g = self._gate(path)
        if g is None:
            return
        user, rec = g
        if path == "/api/credentials":
            return self._do_credentials(user, rec)
        if path not in API_POST:
            return self._send(404, b'{"error":"not found"}')

        body, err = self._body()
        if err:
            return self._json({"error": err}, 400)

        if path == "/api/targets":
            targets, errs = validate_targets(body)
            if errs:
                return self._json({"error": "rejected", "detail": errs[:20]}, 400)
            try:
                _write_json_atomic(LIVE_TARGETS, targets)
            except Exception as e:
                return self._json({"error": f"write failed: {type(e).__name__}"}, 500)
            return self._json({"ok": True, "count": len(targets),
                               "note": "live store updated; effective next cycle"})

        if path == "/api/ack":
            key = str(body.get("key", "")).strip()
            if not re.match(r"^[A-Za-z0-9._-]{1,253}:\d{1,5}$", key):
                return self._json({"error": "key must be ip:port"}, 400)
            acks = load_acks()
            if body.get("clear"):
                acks.pop(key, None)
            else:
                until = body.get("until")     # null == PERMANENT, by design
                if until is not None:
                    try:
                        until = float(until)
                    except (TypeError, ValueError):
                        return self._json({"error": "until must be epoch or null"}, 400)
                acks[key] = {"note": str(body.get("note", ""))[:300],
                             "since": int(time.time()), "until": until,
                             "by": user}
            try:
                _write_json_atomic(ACKS_PATH, acks)
            except Exception as e:
                return self._json({"error": f"write failed: {type(e).__name__}"}, 500)
            return self._json({"ok": True, "acks": len(acks)})

    def _do_login(self):
        ip = self.client_ip()
        if login_throttled(ip):
            return self._html(login_page("Too many attempts. Wait 5 minutes."), 429)
        body, err = self._body()
        if err:
            return self._html(login_page("Malformed request."), 400)
        user = str(body.get("user", ""))
        pw = str(body.get("pass", ""))
        rec = check_login(user, pw)
        if not rec:
            note_login_fail(ip)
            sys.stderr.write(f"[netmap] failed login for {user!r} from {ip}\n")
            return self._html(login_page("Incorrect username or password."), 401)
        clear_login_fails(ip)
        tok = new_session(rec["user"])
        nxt = str(body.get("next", "/")) or "/"
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = "/"                        # no open redirect
        if rec.get("must_change"):
            nxt = "/change"
        return self._redirect(nxt, self._cookie(tok))

    def _do_credentials(self, user, rec):
        body, err = self._body()
        if err:
            return self._json({"error": err}, 400)
        forced = bool(rec.get("must_change"))
        newuser = str(body.get("user", user)).strip() or user
        cur = str(body.get("current", ""))
        new = str(body.get("new", ""))
        conf = str(body.get("confirm", new))

        def fail(msg, code=400):
            if self._wants_json():
                return self._json({"error": msg}, code)
            return self._html(change_page(newuser, msg, forced), code)

        if not re.match(r"^[A-Za-z0-9._@-]{3,64}$", newuser):
            return fail("username must be 3-64 chars (letters, digits, . _ @ -)")
        if not check_login(rec.get("user"), cur):
            note_login_fail(self.client_ip())
            return fail("current password is incorrect", 401)
        if new != conf:
            return fail("new passwords do not match")
        problem = password_problem(new, newuser)
        if problem:
            return fail(problem)

        salt, h = hash_pw(new)
        updated = {"user": newuser, "salt": salt, "hash": h,
                   "must_change": False, "updated": int(time.time())}
        try:
            save_auth(updated)
        except Exception as e:
            return fail(f"could not save credentials: {type(e).__name__}", 500)
        # Rotating the secret must evict everyone, including this session --
        # otherwise a stolen cookie outlives the password change that was made
        # to revoke it.
        drop_all_sessions()
        sys.stderr.write(f"[netmap] credentials updated; user is now {newuser!r}\n")
        if self._wants_json():
            return self._json({"ok": True, "user": newuser,
                               "note": "all sessions signed out; sign in again"})
        return self._redirect("/login", self._cookie("", clear=True))

    def _do_push(self):
        """Remote agents authenticate with a shared token, never a session.

        Fails CLOSED the same way the UI does: with no token configured there
        is no way to submit, because an open ingest endpoint lets anyone paint
        the board green -- which is strictly worse than no monitoring."""
        if not PUSH_TOKEN:
            return self._json({"error": "push ingest disabled "
                                        "(NETMAP_PUSH_TOKEN unset)"}, 503)
        got = (self.headers.get("X-Push-Token")
               or (self.headers.get("Authorization") or "").removeprefix("Bearer "))
        if not hmac.compare_digest(str(got), PUSH_TOKEN):
            note_login_fail(self.client_ip())
            return self._json({"error": "bad push token"}, 401)
        body, err = self._body()
        if err:
            return self._json({"error": err}, 400)
        results = body.get("results") if isinstance(body, dict) else None
        if not isinstance(results, list):
            return self._json({"error": "expected {results:[...]}"}, 400)
        store, now, n_ok = load_push(), int(time.time()), 0
        for r in results[:MAX_TARGETS]:
            if not isinstance(r, dict):
                continue
            ip, port = str(r.get("ip", "")), r.get("port")
            if not _HOSTRE.match(ip) or not isinstance(port, int):
                continue
            store[f"{ip}:{port}"] = {"up": bool(r.get("up")), "ms": r.get("ms"),
                                     "ts": now,
                                     "agent": str(body.get("agent", ""))[:64]}
            n_ok += 1
        try:
            _write_json_atomic(PUSH_PATH, store, keep_bak=False)
        except Exception as e:
            return self._json({"error": f"write failed: {type(e).__name__}"}, 500)
        return self._json({"ok": True, "accepted": n_ok, "ttl": PUSH_TTL})


def main():
    rec = load_auth()
    if rec.get("must_change"):
        sys.stderr.write(
            "[netmap] NOTE: serving with the BOOTSTRAP credential. Every route "
            "redirects to /change until it is replaced.\n")
    if not PUSH_TOKEN:
        sys.stderr.write("[netmap] push ingest disabled (NETMAP_PUSH_TOKEN unset)\n")
    threading.Thread(target=prober_loop, daemon=True, name="prober").start()
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    sys.stderr.write(f"[netmap] listening on :{PORT}, refresh {REFRESH}s, "
                     f"user {rec.get('user')!r}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
