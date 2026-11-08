#!/usr/bin/env bash
# Physical routed-prefix proof. Only a unique labelled, internal Compose project
# is touched; the regular development/production holders are never addressed.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for binary in docker python3; do command -v "$binary" >/dev/null || fail "missing $binary"; done
[[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]] || fail 'unset Docker endpoint overrides; use ROUTED_DOCKER_CONTEXT for a local context'
export ROUTED_DOCKER_CONTEXT=${ROUTED_DOCKER_CONTEXT:-$(docker context show)}
dock() { command docker --context "$ROUTED_DOCKER_CONTEXT" "$@"; }
endpoint=$(dock context inspect "$ROUTED_DOCKER_CONTEXT" --format '{{.Endpoints.docker.Host}}')
[[ $endpoint == unix:///* ]] || fail 'only a local Unix-socket Docker context is permitted'
export ROUTED_RUN="routed-$(date +%s)-$$"
export ROUTED_PORT=${ROUTED_PORT:-18090}
[[ $ROUTED_PORT =~ ^[0-9]+$ && $ROUTED_PORT -gt 1024 && $ROUTED_PORT -lt 65536 ]] || fail 'invalid fixture gateway port'
export GATEWAY_URL=${GATEWAY_URL:-http://127.0.0.1:$ROUTED_PORT}
[[ $GATEWAY_URL == "http://127.0.0.1:$ROUTED_PORT" ]] || fail 'GATEWAY_URL must be this run’s loopback HTTP listener'
export ROUTED_EXTERNAL_FORWARD=${ROUTED_EXTERNAL_FORWARD:-0}
[[ $ROUTED_EXTERNAL_FORWARD == 0 || $ROUTED_EXTERNAL_FORWARD == 1 ]] || fail 'ROUTED_EXTERNAL_FORWARD must be 0 or 1'
# Docker internal networks intentionally have no published gateway port.
# Linux uses the driver's loopback TCP relay. VM contexts require an existing,
# operator-owned SSH forward into that local VM, never a public listener.
printf 'Gateway access: Linux loopback relay, or ROUTED_EXTERNAL_FORWARD=1 with an operator-owned local-VM SSH forward: -L 127.0.0.1:%s:203.0.113.4:8090\n' "$ROUTED_PORT"
if [[ $(uname -s) != Linux && $ROUTED_EXTERNAL_FORWARD != 1 ]]; then
    fail 'VM context prerequisite: establish the printed loopback SSH forward using your existing VM SSH configuration, then set ROUTED_EXTERNAL_FORWARD=1'
fi
export ROUTED_VERIFIED=0
COMPOSE="$SCRIPT_DIR/fixtures/docker-compose.routed-ipv6.yml"
dc() { dock compose --project-name "$ROUTED_RUN" -f "$COMPOSE" "$@"; }
# Refuse an accidental collision rather than adopting someone else's resources.
[[ -z $(dock ps -aq --filter "label=com.docker.compose.project=$ROUTED_RUN") ]] || fail 'project already exists'
cleanup() {
    local status=$? id kind ids label_template
    trap - EXIT
    if [[ $status -ne 0 ]]; then dc logs --no-color --tail 40 >&2 || true; fi
    # A mismatched/unlabelled resource aborts cleanup. No name-based rm/prune.
    for kind in container network volume; do
        case "$kind" in
            container)
                ids=$(dock ps -aq --filter "label=com.docker.compose.project=$ROUTED_RUN")
                label_template='{{index .Config.Labels "ircfiber.fixture.run"}}';;
            network)
                ids=$(dock network ls -q --filter "label=com.docker.compose.project=$ROUTED_RUN")
                label_template='{{index .Labels "ircfiber.fixture.run"}}';;
            volume)
                ids=$(dock volume ls -q --filter "label=com.docker.compose.project=$ROUTED_RUN")
                label_template='{{index .Labels "ircfiber.fixture.run"}}';;
        esac
        for id in $ids; do
            if [[ $(dock "$kind" inspect --format "$label_template" "$id") != "$ROUTED_RUN" ]]; then
                printf 'Refusing cleanup of non-fixture %s %s\n' "$kind" "$id" >&2
                exit 1
            fi
        done
    done
    dc down --volumes --remove-orphans >/dev/null || true
    exit "$status"
}
trap cleanup EXIT
# Unique image tags + a mandatory build from the current tree prevent a stale
# :local image from impersonating newly implemented transport behavior.
dc build --pull endpoint native-engine native-holder gateway
python3 "$SCRIPT_DIR/fixtures/routed_policy_driver.py" "$COMPOSE"
