#!/usr/bin/env bash
# Separate candidate-holder qualification; never relax Rollout A's old-image gate.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" holder_pressure "$@"
fi
exec python3 "$SCRIPT_DIR/fixtures/holder_pressure.py" host "$@"
