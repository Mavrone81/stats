#!/usr/bin/env bash
# Assert that this repo's safety guards CAN FAIL.
#
# A test that passes against code where the feature is UNWIRED is not a test.
# The recurring defect in this estate is not a wrong check -- it is a check that
# was never in force: configured, healthy-looking, exit 0, testing nothing.
# So this script deliberately BREAKS each guard, runs the suite against the
# broken code, and requires the suite to FAIL.
#
# IT NEVER TOUCHES THE WORKING TREE. Each case is run against a COPY in a temp
# directory; server.py in the repo is only ever read.
#
# That is not fastidiousness -- an earlier version sabotaged the real file and
# restored it from a trap, and an outer `timeout` killed it mid-run while bash
# was blocked on the test subprocess. The trap did not win the race, and the
# repo was left with `invert = False` in server.py. Only `git status` caught it.
# A script that leaves a silently-disarmed guard behind when interrupted is a
# strictly worse problem than the one it was written to detect, so the fix is
# structural: there is no window in which a sabotaged file exists under the
# repo, and therefore no trap to get right.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM     # only ever deletes a temp dir

fail=0

run_case () {
  local name="$1" old="$2" new="$3"
  local dir="$WORK/case"
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$REPO/server.py" "$REPO/test_server.py" "$dir/"

  if ! grep -qF -- "$old" "$dir/server.py"; then
    echo "  !! $name: anchor line not found -- this script is stale and is no"
    echo "     longer breaking anything. A guard-checker that silently matches"
    echo "     nothing is the same failure it exists to catch, so: FAIL."
    fail=1; return
  fi

  python3 - "$dir/server.py" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
open(path, "w").write(s.replace(old, new, 1))
PY

  # The suite MUST fail against the sabotaged copy.
  if (cd "$dir" && NETMAP_DATA="$dir/data" python3 -m unittest test_server) \
       >/dev/null 2>&1; then
    echo "  !! $name: suite still PASSED with the guard removed -- UNVERIFIED"
    fail=1
  else
    echo "  OK    $name: suite fails when the guard is removed"
  fi
}

echo "== asserting each guard can fail (in a temp copy; repo untouched) =="

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
