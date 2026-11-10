#!/usr/bin/env bash
# Rollout A only: unchanged production holder, mixed TCP/TLS, no Mongo outage.
# Qualification is 1,800 s warm-up PLUS 1,800 s measured stationary load.
# Parent supplies local immutable Linux/amd64 engine/holder/gateway image IDs.
# On macOS first establish the launcher's printed local-VM loopback forward.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" memory_reliability "$@"
fi
: "${MEMORY_EVIDENCE_DIR:?launcher must supply a fresh evidence directory}"
: "${ROUTING_REGRESSION_MEMORY:?launcher must enable the owned memory fixture}"
[[ $ROUTING_REGRESSION_MEMORY == 1 ]] || exit 1
exec python3 "$SCRIPT_DIR/fixtures/memory_qualification.py" "$@"
