#!/usr/bin/env bash
# test-clickhouse-config-regressions.sh — run ./test-clickhouse-config.sh
# against each known-bad fixture and verify it rejects. Exits 0 only if
# every bad fixture is caught.
#
# This is the "did we add a config that breaks boot" smoke test. It
# runs in well under a minute per fixture (most failures are detected
# in the 30s keeper wait + 60s clickhouse wait). Total runtime with
# 3 fixtures: ~5 min on a cold image pull, ~1.5 min on a warm cache.
#
# Usage:
#   ./test-clickhouse-config-regressions.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST="$SCRIPT_DIR/test-clickhouse-config.sh"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
GOOD_OVERRIDES="$PROJECT_ROOT/deploy/roles/signoz/files/clickhouse-server-overrides.xml"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

if [ ! -x "$TEST" ]; then
    echo "FAIL: $TEST is not executable"
    exit 1
fi

PASS=0
FAIL=0
FAILED_FIXTURES=()

# Save the current good overrides so we can restore at the end.
GOOD_BACKUP="$(mktemp)"
cp "$GOOD_OVERRIDES" "$GOOD_BACKUP"

cleanup() {
    cp "$GOOD_BACKUP" "$GOOD_OVERRIDES"
    rm -f "$GOOD_BACKUP"
}
trap cleanup EXIT

for FIXTURE_DIR in "$FIXTURES_DIR"/*/; do
    FIXTURE_NAME="$(basename "$FIXTURE_DIR")"
    BAD_XML="$FIXTURE_DIR/clickhouse-server-overrides.xml"
    if [ ! -f "$BAD_XML" ]; then
        echo "SKIP: $FIXTURE_NAME (no XML)"
        continue
    fi
    echo
    echo "=== Testing fixture: $FIXTURE_NAME ==="
    cp "$BAD_XML" "$GOOD_OVERRIDES"
    if "$TEST" >/dev/null 2>&1; then
        echo "    REGRESSION: $FIXTURE_NAME passed when it should have failed"
        FAIL=$((FAIL+1))
        FAILED_FIXTURES+=("$FIXTURE_NAME")
    else
        EXIT_CODE=$?
        echo "    OK: $FIXTURE_NAME rejected (exit $EXIT_CODE)"
        PASS=$((PASS+1))
    fi
done

# Sanity check: the real config should pass. Restore the good file
# first so the sanity check isn't contaminated by the last fixture
# left in place (the trap restores at script exit, not before the
# sanity check).
cp "$GOOD_BACKUP" "$GOOD_OVERRIDES"
echo
echo "=== Sanity check: real overrides.xml still pass ==="
if "$TEST" >/dev/null 2>&1; then
    echo "    OK: real config passes"
else
    echo "    FAIL: real config rejected — possible regression in test or config"
    FAIL=$((FAIL+1))
    FAILED_FIXTURES+=("real-config")
fi

echo
echo "=============================="
echo "Pass: $PASS  Fail: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "Failed: ${FAILED_FIXTURES[*]}"
    exit 1
fi
echo "All fixtures rejected as expected"
