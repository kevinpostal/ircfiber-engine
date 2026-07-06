#!/usr/bin/env bash
#
# run-loadtest.sh — Wrapper for ircfiber-loadtest
#
# Builds (if needed) and runs the loadtest binary against a target Redis.
# Publishes synthetic PRIVMSG events to irc:events:<userId> at a configurable rate.
#
# Usage:
#   ./scripts/run-loadtest.sh [options]
#
# Options:
#   --redis-url URL   Redis URL (default: redis://127.0.0.1:6379)
#   --user UUID       Target user ID (default: 1d61f5b3-5f4d-49b1-a59f-03d79f58ac3c)
#   --rps N           Events per second target (default: 10000)
#   --duration N      Run duration in seconds (default: 60)
#   --no-build        Skip dub build step
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/ircfiber-loadtest"
BUILD=1

# Parse known args, forward rest to binary
BUILD_ARGS=()
RUN_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=0 ;;
        *)
            if [ "$BUILD" -eq 1 ]; then
                BUILD_ARGS+=("$arg")
            fi
            RUN_ARGS+=("$arg")
            ;;
    esac
done

if [ "$BUILD" -eq 1 ]; then
    echo "==> Building ircfiber-loadtest ..."
    cd "$PROJECT_DIR"
    dub build --config=loadtest
    echo ""
fi

if [ ! -x "$BINARY" ]; then
    echo "ERROR: Binary not found at $BINARY" >&2
    echo "Run with --no-build or build first: dub build --config=loadtest" >&2
    exit 1
fi

echo "==> Starting loadtest ..."
exec "$BINARY" "${RUN_ARGS[@]}"
