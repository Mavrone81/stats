#!/usr/bin/env bash
# Run BEFORE every deploy. There is no auto-deploy puller on this box, so a
# server-side edit survives indefinitely and an scp would silently destroy it.
# This pulls the box's copy down and diffs it against the repo so drift is
# committed, not overwritten.
#
#   ./deploy/pull-drift.sh <ssh-host>
set -euo pipefail
HOST="${1:?usage: pull-drift.sh <ssh-host>}"
DIR="/opt/netmap"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
cd "$(dirname "$0")/.."

drift=0
for f in server.py index.html test_server.py docker-compose.yml agent/push-agent.py; do
  mkdir -p "$TMP/$(dirname "$f")"
  if scp -q "$HOST:$DIR/$f" "$TMP/$f" 2>/dev/null; then
    if ! diff -q "$f" "$TMP/$f" >/dev/null; then
      echo "=== DRIFT in $f (box differs from repo) ==="; diff -u "$f" "$TMP/$f" || true; drift=1
    fi
  else
    echo "--- $f not present on the box"
  fi
done

# The live target list is edited through the UI and exists ONLY on the box.
# It is state, not source, but losing it loses the entire inventory.
echo "=== live target list (box-only state, back this up) ==="
ssh "$HOST" "docker run --rm -v netmap_netmap_data:/d busybox cat /d/targets.json 2>/dev/null" \
  | tee "$TMP/targets.live.json" | head -5 || echo "  (none yet -- still on the builtin seed)"
cp "$TMP/targets.live.json" ./targets.live.json 2>/dev/null && \
  echo "  saved to ./targets.live.json (commit it as a seed if it looks right)"

[ "$drift" = 0 ] && echo "No source drift." || echo "DRIFT FOUND -- commit it before deploying."
exit $drift
