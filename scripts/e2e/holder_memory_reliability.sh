#!/usr/bin/env bash
# Corrected-holder working set only; this cannot qualify old-holder Rollout A or B.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" holder_memory_reliability "$@"
fi
: "${MEMORY_EVIDENCE_DIR:?owned launcher must supply fresh evidence directory}"
[[ ${ROUTING_REGRESSION_MEMORY:-0} == 1 && ${ROUTING_REGRESSION_HOLDER_DETACH_SECS:-} == 0 ]] || exit 1
exec python3 "$SCRIPT_DIR/fixtures/holder_memory_qualification.py" "$@"
