#!/usr/bin/env bash
# engine-fingerprint.sh — hash of all engine-relevant sources
# Mirrors what `make update` builds: D sources + Containerfile + dub configs
# Usage: ./scripts/engine-fingerprint.sh [--short]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
# Use git-tracked engine files if git available, else filesystem
if git rev-parse --git-dir >/dev/null 2>&1; then
  # Last commit that touched engine paths — stable fingerprint across branches
  HASH=$(git log -1 --format=%H -- engine common backend/source Containerfile dub.json dub.sdl 2>/dev/null || echo "no-engine-commit")
  # Also hash current working tree in case of uncommitted engine changes
  if ! git diff --quiet -- engine common backend/source Containerfile 2>/dev/null; then
    HASH="${HASH}-dirty"
  fi
else
  HASH=$(find engine common backend/source -type f -name '*.d' -o -name '*.json' -o -name 'Containerfile' 2>/dev/null | sort | xargs cat 2>/dev/null | sha256sum | cut -d' ' -f1)
fi
if [[ "${1:-}" == "--short" ]]; then
  echo "${HASH:0:12}"
else
  echo "$HASH"
fi
