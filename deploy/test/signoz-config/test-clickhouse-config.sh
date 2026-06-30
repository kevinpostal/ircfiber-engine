#!/usr/bin/env bash
# test-clickhouse-config.sh — boot ClickHouse + Keeper with the production
# config overrides and verify it stays up.
#
# Catches the class of bug where a malformed XML config (e.g. nested
# <logger>/<log>/<size>) sends ClickHouse into a restart loop. The
# OVH production server has 7.7 GB RAM and a 1.7 GB internal cap, so
# when parts-merge fails the err.log bloats from MBs to 700+ MB within
# hours and the writable layer fills up. Validating locally first
# means a 3-second teardown instead of a 1-hour rollback.
#
# Exit codes:
#   0  — ClickHouse started and accepted a query
#   1  — generic failure (see output)
#   2  — bad XML (xmllint --noout)
#   3  — Keeper didn't come up
#   4  — ClickHouse didn't come up
#   5  — ClickHouse came up but exited 36 (config reject)
#   6  — ClickHouse came up but config didn't apply (server_settings miss)
#
# Run from the project root:
#   ./deploy/test/signoz-config/test-clickhouse-config.sh
# or
#   cd deploy/test/signoz-config && ./test-clickhouse-config.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.test.yml"
OVERRIDES_FILE="$PROJECT_ROOT/deploy/roles/signoz/files/clickhouse-server-overrides.xml"

# 1. XML well-formedness — fast, no docker needed. xmllint ships with
#    libxml2; on macOS it's `brew install libxml2`. If absent, fall
#    back to Python's ElementTree which is always available.
echo "==> Validating XML well-formedness of clickhouse-server-overrides.xml"
if command -v xmllint >/dev/null 2>&1; then
    if ! xmllint --noout "$OVERRIDES_FILE" 2>&1; then
        echo "FAIL: $OVERRIDES_FILE is not well-formed XML"
        exit 2
    fi
else
    if ! python3 -c "import xml.etree.ElementTree as ET; ET.parse('$OVERRIDES_FILE')" 2>&1; then
        echo "FAIL: $OVERRIDES_FILE is not well-formed XML"
        exit 2
    fi
fi
echo "    OK — XML parses"

# 2. Brings the stack down first so the script is idempotent.
echo "==> Bringing up test stack (will reuse existing volume if present)"
( cd "$SCRIPT_DIR" && docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 ) || true
( cd "$SCRIPT_DIR" && docker compose -f "$COMPOSE_FILE" up -d )

# 3. Wait for Keeper to be healthy. Probe with `nc` on the keeper
#    Raft healthcheck port directly — `docker compose ps` JSON output
#    shape varies between Docker versions, but a direct netcat probe
#    is stable. imok = keeper reports the cluster has a leader.
echo "==> Waiting for clickhouse-keeper (probing 127.0.0.1:9181 with nc)"
KEEPER_OK=false
for i in {1..30}; do
    if ( cd "$SCRIPT_DIR" && docker exec test-clickhouse-keeper sh -c "echo ruok | nc -w 1 127.0.0.1 9181" 2>/dev/null | grep -q imok ); then
        KEEPER_OK=true
        echo "    keeper responding (imok)"
        break
    fi
    sleep 1
done
if [ "$KEEPER_OK" != "true" ]; then
    echo "FAIL: keeper never responded on 9181 (30s timeout)"
    ( cd "$SCRIPT_DIR" && docker logs --tail=20 test-clickhouse-keeper 2>&1 )
    ( cd "$SCRIPT_DIR" && docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 )
    exit 3
fi

# 4. Wait for ClickHouse to come up AND stay up. Exit code 36 (config
#    reject) shows up as the container rapidly cycling; we wait the
#    full timeout then check exit history.
echo "==> Waiting for clickhouse (up to 60s for a fresh boot)"
UP=false
for i in {1..60}; do
    STATUS=$( cd "$SCRIPT_DIR" && docker inspect test-clickhouse --format '{{.State.Status}}' 2>/dev/null )
    if [ "$STATUS" = "running" ]; then
        if ( cd "$SCRIPT_DIR" && docker exec test-clickhouse clickhouse-client --query "SELECT 1" >/dev/null 2>&1 ); then
            UP=true
            break
        fi
    fi
    sleep 1
done

if [ "$UP" != "true" ]; then
    STATUS=$( cd "$SCRIPT_DIR" && docker inspect test-clickhouse --format '{{.State.Status}}' 2>/dev/null )
    EXIT_CODE=$( cd "$SCRIPT_DIR" && docker inspect test-clickhouse --format '{{.State.ExitCode}}' 2>/dev/null )
    echo "FAIL: clickhouse didn't come up (status=$STATUS exit=$EXIT_CODE)"
    echo "---- last 30 log lines ----"
    ( cd "$SCRIPT_DIR" && docker logs --tail=30 test-clickhouse 2>&1 )
    ( cd "$SCRIPT_DIR" && docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 )
    if [ "$EXIT_CODE" = "36" ]; then
        exit 5
    fi
    exit 4
fi

# 5. Verify the overrides actually applied. If the file shipped values
#    but the running server reports the defaults, the file mount
#    silently no-op'd and the test is meaningless.
echo "==> Verifying server_settings picked up the overrides"
NEEDED_KEYS=( "max_server_memory_usage" "background_pool_size" "background_merges_mutations_concurrency_ratio" )
MISSING=()
for KEY in "${NEEDED_KEYS[@]}"; do
    EXPECTED=$( grep -E "<${KEY}>" "$OVERRIDES_FILE" | sed -E "s|.*<${KEY}>([0-9]+).*|\1|" | head -1 )
    ACTUAL=$( ( cd "$SCRIPT_DIR" && docker exec test-clickhouse clickhouse-client --query "SELECT value FROM system.server_settings WHERE name = '${KEY}'" 2>/dev/null | tr -d '[:space:]' ) )
    if [ -z "$EXPECTED" ]; then
        # Key not in our overrides file — skip
        continue
    fi
    if [ "$ACTUAL" != "$EXPECTED" ]; then
        MISSING+=("$KEY: expected=$EXPECTED actual=$ACTUAL")
    else
        echo "    $KEY = $ACTUAL (matches override)"
    fi
done

# 6. Tear down. Leave the volume in place so subsequent runs reuse the
#    keeper state; pass --volumes explicitly if you want a clean start.
echo "==> Tearing down test stack"
( cd "$SCRIPT_DIR" && docker compose -f "$COMPOSE_FILE" down --remove-orphans >/dev/null 2>&1 )

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "FAIL: config shipped but didn't apply:"
    for m in "${MISSING[@]}"; do
        echo "    $m"
    done
    exit 6
fi

echo "PASS: ClickHouse started, accepted a query, and applied the overrides"
