#!/usr/bin/env python3
"""
Assert this repo only ever targets the NON-RMA estate.

The standing rule is that RMA and non-RMA never share a box, an account or a
credential. A monitoring board is exactly the artefact that quietly merges two
estates, because adding "just one more host" is a two-line edit.

This is an ALLOWLIST, not a denylist, for two reasons:
  1. A denylist would require listing RMA hostnames and IPs *in this repo* --
     which is itself the leak it claims to prevent.
  2. A denylist silently passes anything nobody thought of. An allowlist fails
     closed: a host outside the approved estate is rejected until a human
     consciously adds it here, which is the moment the boundary question gets
     asked.

Run: python3 scripts/assert-non-rma-only.py
"""
import ipaddress
import re
import sys

# The non-RMA estate. Adding to this list is the deliberate act of saying
# "this belongs on the Bevora side" -- do not widen it to make CI pass.
ALLOWED_IPS = {"165.22.246.45", "157.230.38.96", "157.245.152.227"}
ALLOWED_NETS = [ipaddress.ip_network("10.104.0.0/20")]      # the shared VPC
ALLOWED_DOMAINS = {
    "bevorasg.com", "urbanwerkzsg.com", "urbanfleetsg.com", "vorkhive.com",
    "chachisoftware.store", "awakenfs.store", "back-end.store",
    "enshrinepets.com.sg", "singaporebuddhistfuneral.com.sg",
}

TARGET_RE = re.compile(r'\{"ip":\s*"([^"]+)"')
HOSTOPT_RE = re.compile(r'"host":\s*"([^"]+)"')


def allowed(value):
    try:
        ip = ipaddress.ip_address(value)
        return value in ALLOWED_IPS or any(ip in n for n in ALLOWED_NETS)
    except ValueError:
        pass
    v = value.lower().rstrip(".")
    return any(v == d or v.endswith("." + d) for d in ALLOWED_DOMAINS)


def main():
    src = open("server.py", encoding="utf-8").read()
    found = set(TARGET_RE.findall(src)) | set(HOSTOPT_RE.findall(src))
    if not found:
        # A guard that inspects nothing is the failure mode this repo cares
        # most about, so finding zero targets is an error, not a pass.
        print("FAIL: no targets found in server.py -- this guard is inspecting "
              "nothing, which is indistinguishable from passing.")
        return 1

    bad = sorted(v for v in found if not allowed(v))
    print(f"checked {len(found)} distinct target hosts in server.py's seed")
    if bad:
        print("\nFAIL: these are not in the approved non-RMA estate:")
        for v in bad:
            print(f"  - {v}")
        print("\nIf one of these genuinely belongs on the Bevora side, add it to "
              "ALLOWED_* in this file in the same commit, so the boundary "
              "decision is reviewable. If it is RMA, it must not be here at all.")
        return 1
    print("OK: every seeded target is inside the approved non-RMA estate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
