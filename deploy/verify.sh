#!/usr/bin/env bash
# Post-deploy verification. "I copied it" is not "it's there" -- this compares
# checksums on both sides and then proves the running service actually answers.
#
#   ./deploy/verify.sh <ssh-host> [url]
set -euo pipefail
HOST="${1:?usage: verify.sh <ssh-host> [url]}"
URL="${2:-https://status.bevorasg.com}"
DIR="/opt/netmap"
cd "$(dirname "$0")/.."

fail=0
echo "== file integrity =="
for f in server.py index.html test_server.py docker-compose.yml; do
  a=$(sha256sum "$f" | cut -d' ' -f1)
  b=$(ssh "$HOST" "sha256sum $DIR/$f 2>/dev/null | cut -d' ' -f1" || echo MISSING)
  if [ "$a" = "$b" ]; then printf "  OK    %s\n" "$f"
  else printf "  DIFF  %s (local %s / remote %s)\n" "$f" "${a:0:12}" "${b:0:12}"; fail=1; fi
done

echo "== tests, in the same image as prod =="
# The exit status is CHECKED, and the log is written remotely rather than piped.
#
# This step previously read:
#     ssh "$HOST" "... python3 -m unittest test_server 2>&1 | tail -3"
# which could not fail. `ssh host "cmd | tail"` returns the status of `tail`,
# not of `cmd`; the remote shell has no `pipefail`, so a suite failing every
# test still exited 0 and this script still printed a clean run. It was a
# verification step that verified nothing -- the exact defect it exists to
# catch. Do not reintroduce a pipe here.
if ssh "$HOST" "cd $DIR && docker run --rm -v $DIR:/app:ro -w /app \
      -e NETMAP_DATA=/tmp python:3.12-slim \
      python3 -m unittest test_server > /tmp/netmap-tests.log 2>&1"; then
  echo "  OK    test suite passed in the prod image"
  ssh "$HOST" "tail -2 /tmp/netmap-tests.log" | sed 's/^/        /'
else
  echo "  !! TEST SUITE FAILED in the prod image"
  ssh "$HOST" "tail -20 /tmp/netmap-tests.log" | sed 's/^/        /'
  fail=1
fi

echo "== service answers =="
code=$(ssh "$HOST" "curl -s -o /dev/null -w '%{http_code}' $URL/api/health" || echo 000)
echo "  GET $URL/api/health -> $code"
[ "$code" = "200" ] || fail=1
# The board itself must NOT be open. A 200 here is a serious finding.
code=$(ssh "$HOST" "curl -s -o /dev/null -w '%{http_code}' $URL/" || echo 000)
echo "  GET $URL/ -> $code (401 expected: the board must never be public)"
[ "$code" = "401" ] || { echo "  !! board is not requiring auth"; fail=1; }

echo "== git =="
# A fix that only exists on a laptop and the box is one lost laptop from gone.
git status --porcelain | grep . && { echo "  !! uncommitted local changes"; fail=1; } || echo "  OK    working tree clean"
git fetch -q origin 2>/dev/null || true
if [ -n "$(git log origin/main..HEAD --oneline 2>/dev/null)" ]; then
  echo "  !! commits not pushed to origin/main:"; git log origin/main..HEAD --oneline | sed 's/^/       /'; fail=1
else echo "  OK    origin/main is up to date"; fi

exit $fail
