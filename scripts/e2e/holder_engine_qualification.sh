#!/usr/bin/env bash
# Separate candidate-holder qualification; never weakens Rollout A's image gate.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" holder_engine_qualification "$@"
fi
: "${HOLDER_ENGINE_EVIDENCE_DIR:?launcher must supply a fresh evidence directory}"
: "${ROUTING_REGRESSION_RUN:?owned launcher required}"
: "${COMPOSE_PROJECT_NAME:?owned launcher required}"
: "${HOLDER_MAINTENANCE_HELPER:?guarded maintenance helper required}"
exec python3 "$SCRIPT_DIR/fixtures/holder_engine_qualification.py" qualify "$@"
