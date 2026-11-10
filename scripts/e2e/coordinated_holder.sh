#!/usr/bin/env bash
# Physical coordinated path only; old-holder continuity remains a failed gate.
# Run on native Colima Linux x86_64 as host root. Required immutable inputs:
# ROUTING_REGRESSION_{ENGINE,HOLDER,GATEWAY}_IMAGE, COORDINATED_{ENGINE,HOLDER}_IMAGE;
# HOLDER_MAINTENANCE_HELPER points to the final Site maintenance source beside
# its coordinated/kernel tools. COORDINATED_SOURCE_REVISION is the retained
# archival reconstruction, not a claim that the old binary is reproducible.
# COORDINATED_QUALIFICATION_FILE is an actual image-bound build/source/consumer
# bootstrap receipt: qualified=false, purpose=isolatedqualification, checks=[].
# COORDINATED_LIFECYCLE_FILE is the actual schema-1 old-holder review.
# COORDINATED_RECEIPT_DIR/<sha256> contains the original artifact and lifecycle
# receipt bytes. No physical qualification is claimed before the fixture runs.
# Each fresh run uses COORDINATED_CASE=complete|already-stopped|ambiguous|
# unknown-authority|replacement|restart-inflight|term-refusal|continuous-restart.
# All containers and root-private artifacts survive EVERY outcome; isolate each
# run from earlier restart authorities. No VM/runtime operations happen at edit.
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
: "${COORDINATED_ROOT_DIR:?fresh root-private native host evidence path required}"
: "${COORDINATED_QUALIFICATION_FILE:?actual image-bound scratch bootstrap receipt required}"
: "${COORDINATED_LIFECYCLE_FILE:?actual old-holder lifecycle review receipt required}"
: "${COORDINATED_RECEIPT_DIR:?actual hash-named receipt bytes required}"
exec python3 "$SCRIPT_DIR/fixtures/coordinated_holder.py" "$@"
