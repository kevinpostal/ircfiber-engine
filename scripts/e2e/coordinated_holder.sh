#!/usr/bin/env bash
# Physical coordinated path only; old-holder continuity remains a failed gate.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" coordinated_holder "$@"
fi
: "${HOLDER_ENGINE_EVIDENCE_DIR:?fresh owned evidence directory required}"
: "${ROUTING_REGRESSION_RUN:?owned launcher required}"
: "${COORDINATED_COMPOSE_FILE:?owned override required}"
: "${COORDINATED_ENGINE_IMAGE:?immutable A image required}"
: "${COORDINATED_HOLDER_IMAGE:?immutable corrected holder required}"
exec python3 "$SCRIPT_DIR/fixtures/coordinated_holder.py" "$@"
