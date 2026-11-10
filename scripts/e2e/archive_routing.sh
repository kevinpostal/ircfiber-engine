#!/usr/bin/env bash
# Actual candidate-only, two-engine archival/migration qualification.
# Required command (all IDs must already exist in the chosen local context):
# ROUTED_DOCKER_CONTEXT=colima-build-x64 ROUTED_EXTERNAL_FORWARD=1 ROUTED_PORT=18207 \
# ARCHIVE_ENGINE_OLD_IMAGE=sha256:<old> ARCHIVE_ENGINE_IMAGE=sha256:<B> \
# ARCHIVE_GATEWAY_IMAGE=sha256:<B> ARCHIVE_HOLDER_IMAGE=sha256:<candidate> \
# bash scripts/e2e/archive_routing.sh
# macOS: ssh -F ~/.colima/ssh_config -o ExitOnForwardFailure=yes -N \
#   -L 127.0.0.1:18207:203.0.207.4:8090 colima-build-x64
set -euo pipefail
: "${ARCHIVE_ENGINE_OLD_IMAGE:?provide immutable unsupported engine A image ID}"
: "${ARCHIVE_ENGINE_IMAGE:?provide immutable engine B image ID}"
: "${ARCHIVE_GATEWAY_IMAGE:?provide immutable gateway B image ID}"
: "${ARCHIVE_HOLDER_IMAGE:?provide immutable holder candidate image ID}"
[[ $ARCHIVE_ENGINE_OLD_IMAGE != "$ARCHIVE_ENGINE_IMAGE" ]] || {
    printf 'FAIL: old unsupported engine and B candidate must be distinct images\n' >&2; exit 1;
}
export ROUTED_IMMUTABLE_IMAGES=1 ROUTED_DRIVER=archive_routing_driver.py
export ROUTED_ENGINE_IMAGE=$ARCHIVE_ENGINE_IMAGE
export ROUTED_OLD_ENGINE_IMAGE=$ARCHIVE_ENGINE_OLD_IMAGE
export ROUTED_GATEWAY_IMAGE=$ARCHIVE_GATEWAY_IMAGE
export ROUTED_HOLDER_IMAGE=$ARCHIVE_HOLDER_IMAGE
export ROUTED_MONGO_TEST_COMMANDS=true
exec bash "$(dirname "${BASH_SOURCE[0]}")/routed_ipv6_policy.sh"
