#!/usr/bin/env bash
# Separate old-holder TCP+TLS continuity prerequisite, NOT a full memory gate.
# Default: 12 sessions, six TLS; LEGACY_CONTINUITY_SESSIONS permits 4..64.
# No stationary soak; retain engine/holder 2-GiB + 3-GiB combined limits.
# Supply immutable Linux/amd64 engine/gateway images and the exact old holder.
# On macOS first establish the launcher's printed local-VM loopback forward.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" legacy_holder_continuity "$@"
fi
: "${MEMORY_EVIDENCE_DIR:?owned launcher must supply a fresh evidence directory}"
[[ ${ROUTING_REGRESSION_MEMORY:-0} == 1 && ${ROUTING_REGRESSION_HOLDER_DETACH_SECS:-} == 600 ]] || exit 1
exec python3 "$SCRIPT_DIR/fixtures/legacy_holder_continuity.py" "$@"
