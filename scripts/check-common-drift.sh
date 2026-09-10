#!/usr/bin/env bash
# check-common-drift.sh — fail if the shared `common/` library drifts between
# the site and engine repos. Lives in both repos as the same file; the repo it
# is running in is detected from the tree.
#
# Compares the package contract only — `source/`, `dub.sdl`,
# `dub.selections.json` — so untracked build output (`libirc-fiber-common.a`,
# the `irc-fiber-common-test-unittest` binary) never registers as drift, and
# the deliberately-different canonical `common/README.md` stays out of it.
#
# Usage: ./scripts/check-common-drift.sh [--fetch]
#   default   compare against the peer repo's `main` through an existing peer
#             remote, falling back to a shallow clone
#   --fetch   always shallow-clone the peer repo's `main`
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SYNC_PATHS=(source dub.sdl dub.selections.json)

if [ -d "$ROOT/frontend" ]; then
  THIS="site"
  OTHER_NAME="engine"
  OTHER_URL="${PEER_REPO_URL:-https://github.com/kevinpostal/ircfiber-engine.git}"
else
  THIS="engine"
  OTHER_NAME="site"
  OTHER_URL="${PEER_REPO_URL:-https://github.com/kevinpostal/ircfiber-site.git}"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PEER="$TMP/peer"

clone_peer() {
  # URL is never echoed — PEER_REPO_URL may carry a token in CI.
  echo "Cloning $OTHER_NAME/main (sparse: common/)..."
  rm -rf "$PEER"
  git clone --quiet --depth 1 --no-tags --filter=blob:none --sparse "$OTHER_URL" "$PEER"
  git -C "$PEER" sparse-checkout set common
}

if [[ "${1:-}" == "--fetch" ]]; then
  clone_peer
elif git -C "$ROOT" remote | grep -qx "$OTHER_NAME"; then
  echo "Reading $OTHER_NAME/main from the local peer remote..."
  git -C "$ROOT" fetch --quiet "$OTHER_NAME" main
  mkdir -p "$PEER"
  git -C "$ROOT" archive "$OTHER_NAME/main" common | tar -x -C "$PEER" || clone_peer
else
  clone_peer
fi

echo "Diffing $THIS common vs $OTHER_NAME common..."
rc=0
for p in "${SYNC_PATHS[@]}"; do
  mine="$ROOT/common/$p"
  theirs="$PEER/common/$p"
  if [ ! -e "$mine" ] && [ ! -e "$theirs" ]; then
    continue
  fi
  if ! diff -rq "$mine" "$theirs" > "$TMP/diff.txt" 2>&1; then
    echo "✗ drift in common/$p:"
    sed "s#$PEER/##; s#$ROOT/#$THIS/#" "$TMP/diff.txt"
    rc=1
  fi
done

if [ "$rc" -ne 0 ]; then
  echo ""
  echo "Fix: edit site/common (source of truth), then run site/scripts/sync-common.sh"
  echo "     and commit common/ in every repo before bumping the superproject pins."
  exit 1
fi

echo "✓ common/ in sync with $OTHER_NAME — no drift"
