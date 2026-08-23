#!/usr/bin/env bash
# check-common-drift.sh — fail if common/ drifts between site and engine repos
# Usage: ./scripts/check-common-drift.sh [--fetch]
# Without --fetch, diffs local common/ against origin's other repo (requires `git fetch` of other remote).
# With --fetch, does a live fetch of the other repo's main.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Determine which repo we're in by presence of frontend/ vs engine/
if [ -d "$ROOT/frontend" ]; then
  THIS="site"
  OTHER_URL="https://github.com/kevinpostal/ircfiber-engine.git"
  OTHER_NAME="engine"
else
  THIS="engine"
  OTHER_URL="https://github.com/kevinpostal/ircfiber-site.git"
  OTHER_NAME="site"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [[ "${1:-}" == "--fetch" ]]; then
  echo "Fetching $OTHER_NAME common from $OTHER_URL..."
  git clone --depth 1 --filter=blob:none "$OTHER_URL" "$TMP/other" 2>&1 | tail -3
  OTHER_COMMON="$TMP/other/common"
else
  # Try to compare against already-fetched origin if present
  if git -C "$ROOT" remote | grep -q "$OTHER_NAME"; then
    git -C "$ROOT" fetch "$OTHER_NAME" main 2>&1 | tail -3
    OTHER_COMMON="$TMP/other-common"
    git -C "$ROOT" show "$OTHER_NAME/main:common/dub.sdl" > "$OTHER_COMMON/dub.sdl" 2>/dev/null || true
    # Fallback to clone if show fails
    if [ ! -s "$OTHER_COMMON/dub.sdl" ]; then
      git clone --depth 1 --filter=blob:none "$OTHER_URL" "$TMP/other" 2>&1 | tail -3
      OTHER_COMMON="$TMP/other/common"
    fi
  else
    git clone --depth 1 --filter=blob:none "$OTHER_URL" "$TMP/other" 2>&1 | tail -3
    OTHER_COMMON="$TMP/other/common"
  fi
fi

echo "Diffing $THIS common vs $OTHER_NAME common..."
if diff -rq --exclude=".git" "$ROOT/common" "$OTHER_COMMON" > "$TMP/diff.txt" 2>&1; then
  echo "✓ common/ in sync — no drift"
  exit 0
else
  echo "✗ common/ drift detected between $THIS and $OTHER_NAME:"
  cat "$TMP/diff.txt"
  echo ""
  echo "Fix: cherry-pick the common/ change to the other repo, or run:"
  echo "  rsync -a $ROOT/common/ $TMP/other/common/"
  exit 1
fi
