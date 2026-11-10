#!/usr/bin/env bash
# Candidate-only archival B proof. See archive_qualification.py module contract.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# Smoke shortens durations only; B never uses the LEGACY continuity profile.
# Reject unsupported session counts before starting the owned Docker stack.
ARCHIVE_SESSIONS=${ARCHIVE_SESSIONS:-250}
[[ $ARCHIVE_SESSIONS =~ ^[0-9]+$ ]] && [[ $ARCHIVE_SESSIONS -ge 250 && $ARCHIVE_SESSIONS -le 500 ]] || {
    printf '%s\n' 'ARCHIVE_SESSIONS must be 250..500, including smoke (at least 125 TLS).' >&2
    exit 1
}
export ARCHIVE_SESSIONS
if [[ ${ROUTING_REGRESSION_READY:-0} != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" archive_reliability "$@"
fi
: "${ARCHIVE_EVIDENCE_DIR:?owned launcher must supply fresh evidence directory}"
: "${ARCHIVE_COMPOSE_FILE:?owned launcher must supply archive-only overlay}"
[[ ${ROUTING_REGRESSION_MEMORY:-0} == 1 ]] || exit 1
# Reuse the physical/load constructor without changing its strict A defaults.
export MEMORY_EVIDENCE_DIR="$ARCHIVE_EVIDENCE_DIR"
export MEMORY_SESSIONS=${ARCHIVE_SESSIONS:-250}
export MEMORY_WARMUP_SECONDS=1800 MEMORY_SOAK_SECONDS=1800
exec python3 "$SCRIPT_DIR/fixtures/archive_qualification.py" "$@"
