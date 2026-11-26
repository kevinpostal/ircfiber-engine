#!/usr/bin/env bash
# Physical session qualification; no external Nord account or endpoint is used.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" nord_capacity "$@"
fi
[[ ${ROUTING_REGRESSION_NORD_CAPACITY:-0} == 1 &&
   ${COMPOSE_FILE:-} == "$SCRIPT_DIR/fixtures/docker-compose.routing-regression.yml" &&
   ${COMPOSE_PROJECT_NAME:-} == "${ROUTING_REGRESSION_RUN:-}" &&
   ${ROUTING_REGRESSION_RUN:-} =~ ^regression-[0-9]+-[0-9]+$ ]] || {
    printf 'FAIL: use the isolated Nord-capacity routing wrapper\n' >&2
    exit 1
}
python3 "$SCRIPT_DIR/fixtures/nord_capacity.py" "$@"
