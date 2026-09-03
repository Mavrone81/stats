#!/usr/bin/env bash
# Assert that this repo's safety guards CAN FAIL.
#
# A test that passes against code where the feature is UNWIRED is not a test.
# The recurring defect in this estate is not a wrong check -- it is a check that
# was never in force: configured, healthy-looking, exit 0, testing nothing.
# Bevora Ops found four of its own verification scripts in exactly that state.
#
# So this script deliberately BREAKS each guard, runs the suite, and requires it
# to FAIL. If the suite still passes with the guard removed, that guard is
# unverified and this script exits non-zero.
#
# It restores every file afterwards, including on failure, via the trap below.
set -uo pipefail
cd "$(dirname "$0")/.."

BACKUP=$(mktemp -d)
cp server.py "$BACKUP/server.py"
restore() { cp "$BACKUP/server.py" server.py; rm -rf "$BACKUP"; }
trap restore EXIT INT TERM

fail=0

# Each case: a name, the exact line to break, and its replacement.
run_case () {
  local name="$1" old="$2" new="$3"
  cp "$BACKUP/server.py" server.py
  if ! grep -qF -- "$old" server.py; then
    echo "  !! $name: anchor line not found -- this script is stale and is"
    echo "     no longer breaking anything. That is the same silent-no-op"
    echo "     failure it exists to catch, so it counts as a failure."
    fail=1; return
  fi
  python3 - "$old" "$new" <<'PY'
import sys
old, new = sys.argv[1], sys.argv[2]
s = open("server.py").read()
open("server.py", "w").write(s.replace(old, new, 1))
PY
  # The suite MUST fail now. NETMAP_DATA is a scratch dir; no network needed.
  if NETMAP_DATA=$(mktemp -d) python3 -m unittest test_server >/dev/null 2>&1; then
    echo "  !! $name: suite still PASSED with the guard removed -- UNVERIFIED"
    fail=1
  else
    echo "  OK    $name: suite fails when the guard is removed"
  fi
}

echo "== asserting each guard can fail =="

run_case "flap gate" \
  'up = confirmed_up(key, bool(r["up"]), fail_counts)' \
  'up = bool(r["up"])'

run_case "stranded-incident reconciliation" \
  'reconcile_stranded(conn, open_ev, live_keys, now, fail_counts)' \
  'pass'

run_case "forced credential change" \
  'if rec.get("must_change") and path not in ("/change", "/api/credentials", "/logout"):' \
  'if False:'

run_case "expired cert forces DOWN" \
  'if cert_days is not None and cert_days < 0:' \
  'if False:'

run_case "inverted target (port must stay closed)" \
  'invert = bool(opts.get("invert"))' \
  'invert = False'

echo
if [ "$fail" = 0 ]; then
  echo "All guards verified: each one, when removed, breaks the suite."
else
  echo "FAILED: at least one guard is not actually being tested."
fi
exit $fail
