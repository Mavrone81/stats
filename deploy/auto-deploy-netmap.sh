#!/usr/bin/env bash
# Server-side PULL deploy for netmap. Runs ON the netmap host by systemd timer.
#
# WHY PULL, NOT PUSH FROM CI
# The host's cloud firewall (`bevora-ops-fw`) permits inbound tcp/22 from ONE
# address. GitHub-hosted runners have no stable egress address, so a push
# deploy would mean either allowing a very large published IP range to SSH in,
# or holding a long-lived deploy key in CI. A pull needs neither: the box
# reaches OUT to a public git remote and nothing needs to reach in. It also
# fixes the drift problem this repo has documented from the start -- without a
# puller, a hand-edit on the box survives indefinitely and nothing resets it.
#
# SAFETY ORDER -- do not reorder these:
#   1. refuse to run if the box's working tree is dirty (never clobber a
#      hand-edit; a human must reconcile it -- see deploy/pull-drift.sh)
#   2. fetch; exit quietly if there is nothing new
#   3. run the FULL test suite in the prod image on the NEW code
#   4. only then restart
#   5. verify it actually came back, and roll back if it did not
set -uo pipefail

DIR="${NETMAP_DIR:-/opt/netmap}"
BRANCH="${NETMAP_BRANCH:-main}"
CONTAINER="${NETMAP_CONTAINER:-netmap}"
IMAGE="python:3.12-slim"
URL="${NETMAP_URL:-http://127.0.0.1:8080}"

log() { echo "[auto-deploy $(date -u +%FT%TZ)] $*"; }
cd "$DIR" || { log "FATAL: $DIR missing"; exit 1; }

# 1. Never destroy work that exists only here.
if [ -n "$(git status --porcelain)" ]; then
  log "REFUSING TO DEPLOY: working tree is dirty on the box."
  git status --porcelain | sed 's/^/    /'
  log "A hand-edit here exists nowhere else. Reconcile it with"
  log "deploy/pull-drift.sh and commit it before this can resume."
  exit 1
fi

# 2. Anything new?
git fetch --quiet origin "$BRANCH" || { log "fetch failed"; exit 1; }
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse "origin/$BRANCH")
if [ "$LOCAL" = "$REMOTE" ]; then
  log "up to date at ${LOCAL:0:8}"
  exit 0
fi
log "new commit: ${LOCAL:0:8} -> ${REMOTE:0:8}"
git --no-pager log --oneline "$LOCAL..$REMOTE" | sed 's/^/    /'

PREV="$LOCAL"
git reset --hard --quiet "$REMOTE" || { log "checkout failed"; exit 1; }

# 3. Test the code we are about to run, in the image we will run it in.
#    Exit status is checked directly -- no pipe, because `cmd | tail` returns
#    tail's status and would make this step incapable of failing.
log "running test suite in $IMAGE"
if ! docker run --rm -v "$DIR:/app:ro" -w /app -e NETMAP_DATA=/tmp "$IMAGE" \
     python3 -m unittest test_server > /tmp/netmap-deploy-tests.log 2>&1; then
  log "TESTS FAILED on ${REMOTE:0:8} -- rolling back to ${PREV:0:8}, not deploying"
  tail -20 /tmp/netmap-deploy-tests.log | sed 's/^/    /'
  git reset --hard --quiet "$PREV"
  exit 1
fi
# grep the SUMMARY line, not tail -1: unittest writes warnings after it, so
# tail printed a stray ResourceWarning where the result should be.
log "tests passed: $(grep -E "^(OK|Ran [0-9]+ test)" /tmp/netmap-deploy-tests.log | paste -sd" " || echo "see /tmp/netmap-deploy-tests.log")"

# 4. Restart. `docker restart`, NOT recreate: the container may have been
#    started with run-time flags a recreate would silently drop.
#    index.html needs no restart at all -- it is read per request.
if git diff --name-only "$PREV" "$REMOTE" | grep -qvE '^(index\.html|README\.md|\.github/|docs/)'; then
  log "restarting $CONTAINER"
  docker restart "$CONTAINER" >/dev/null || { log "restart failed"; exit 1; }
else
  log "only index.html/docs changed -- served fresh, no restart needed"
fi

# 5. Prove it came back. A deploy that is not verified is a deploy that is
#    assumed, and this repo does not do assumed.
for i in $(seq 1 20); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL/api/health" || echo 000)
  [ "$code" = "200" ] && { log "healthy at ${REMOTE:0:8} (health 200)"; break; }
  sleep 2
done
if [ "${code:-000}" != "200" ]; then
  log "UNHEALTHY after deploy (last health code ${code:-000}) -- rolling back"
  git reset --hard --quiet "$PREV"
  docker restart "$CONTAINER" >/dev/null || true
  exit 1
fi

# The board must never answer the public unauthenticated. Checked on every
# deploy, because this is the failure that would be worst to discover late.
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$URL/" || echo 000)
if [ "$code" != "401" ]; then
  log "WARNING: GET / returned $code, expected 401 -- the board may be public"
  exit 1
fi
log "deploy complete and verified (board requires auth)"
