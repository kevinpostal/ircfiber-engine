#!/usr/bin/env bash
# test-signoz-config.sh — entrypoint that runs the clickhouse config
# validator and any other signoz-related smoke tests. Designed to be
# safe to wire into a pre-push git hook or a CI job. Always exits 0
# if the production-equivalent config validates.
#
# Usage:
#   ./deploy/test/signoz-config/test-signoz-config.sh
#
# Future hooks (delete the next line when adding a new test):
#   - docker-compose YAML parse check
#   - ansible syntax check (`ansible-playbook --syntax-check`)
#   - retention-defaults vs container env-var consistency

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== ircfiber/signoz config validator ==="

"$SCRIPT_DIR/test-clickhouse-config.sh"
RC=$?
if [ $RC -ne 0 ]; then
    echo
    echo "FAIL: clickhouse config validator exited $RC"
    exit $RC
fi

echo
echo "=== ircfiber/signoz config validator: PASS ==="
