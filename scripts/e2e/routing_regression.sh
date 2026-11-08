#!/usr/bin/env bash
# Run the original runtime regressions on a unique, labelled internal stack.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
mode=${1:-}
case "$mode" in egress_failover|hot_swap) shift;; *) fail 'expected egress_failover or hot_swap';; esac
for binary in docker python3 jq curl; do command -v "$binary" >/dev/null || fail "missing $binary"; done
[[ -z ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]] || fail 'unset Docker endpoint overrides; use ROUTING_REGRESSION_DOCKER_CONTEXT'
context=${ROUTING_REGRESSION_DOCKER_CONTEXT:-$(docker context show)}
dock() { command docker --context "$context" "$@"; }
endpoint=$(dock context inspect "$context" --format '{{.Endpoints.docker.Host}}')
[[ $endpoint == unix:///* ]] || fail 'only a local Unix-socket Docker context is permitted'
export ROUTING_REGRESSION_RUN="regression-$(date +%s)-$$"
export ROUTING_REGRESSION_PORT=${ROUTING_REGRESSION_PORT:-18091}
[[ $ROUTING_REGRESSION_PORT =~ ^[0-9]+$ && $ROUTING_REGRESSION_PORT -gt 1024 && $ROUTING_REGRESSION_PORT -lt 65536 ]] || fail 'invalid fixture gateway port'
export GATEWAY_URL=${GATEWAY_URL:-http://127.0.0.1:$ROUTING_REGRESSION_PORT}
[[ $GATEWAY_URL == "http://127.0.0.1:$ROUTING_REGRESSION_PORT" ]] || fail 'GATEWAY_URL must be this run’s loopback HTTP listener'
export ROUTING_REGRESSION_EXTERNAL_FORWARD=${ROUTING_REGRESSION_EXTERNAL_FORWARD:-0}
[[ $ROUTING_REGRESSION_EXTERNAL_FORWARD == 0 || $ROUTING_REGRESSION_EXTERNAL_FORWARD == 1 ]] || fail 'invalid external-forward flag'
printf 'Gateway access: Linux loopback relay, or ROUTING_REGRESSION_EXTERNAL_FORWARD=1 with operator-owned local-VM SSH forward: -L 127.0.0.1:%s:192.0.2.4:8090\n' "$ROUTING_REGRESSION_PORT"
if [[ $(uname -s) != Linux && $ROUTING_REGRESSION_EXTERNAL_FORWARD != 1 ]]; then
    fail 'establish the printed private local-VM forward, then set ROUTING_REGRESSION_EXTERNAL_FORWARD=1'
fi
export COMPOSE_FILE="$SCRIPT_DIR/fixtures/docker-compose.routing-regression.yml"
export COMPOSE_PROJECT_NAME="$ROUTING_REGRESSION_RUN"
dc() { dock compose --project-name "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" "$@"; }
[[ -z $(dock ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME") ]] || fail 'project already exists'
cleanup() {
    local status=$? kind ids id template key
    trap - EXIT
    for kind in container network volume; do
        case "$kind" in
            container)
                ids=$(dock ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
                template='{{index .Config.Labels "ircfiber.fixture.run"}}';;
            network)
                ids=$(dock network ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
                template='{{index .Labels "ircfiber.fixture.run"}}';;
            volume)
                ids=$(dock volume ls -q --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
                template='{{index .Labels "ircfiber.fixture.run"}}';;
        esac
        for id in $ids; do
            if [[ $(dock "$kind" inspect --format "$template" "$id") != "$ROUTING_REGRESSION_RUN" ]]; then
                printf 'Refusing cleanup of unowned %s %s\n' "$kind" "$id" >&2
                exit 1
            fi
        done
    done
    if [[ $status -ne 0 ]]; then
        dc logs --no-color --tail 50 >&2 || true
        dc exec -T redis redis-cli --raw MGET \
            irc:egress:admission:north irc:egress:admission:south >&2 || true
        for key in $(dc exec -T redis redis-cli --raw --scan --pattern 'irc:state:*' 2>/dev/null); do
            printf 'FIXTURE STATE %s\n' "$key" >&2
            dc exec -T redis redis-cli --raw HGET "$key" data >&2 || true
        done
        dc logs --no-color ircfiber-engine 2>&1 |
            grep -E 'reconnect_scheduled|egress_|connection_error|Host circuit|unproven|earlier holder|Routing|routing' >&2 || true
    fi
    dc down --volumes --remove-orphans >/dev/null || true
    exit "$status"
}
trap cleanup EXIT
dc build --pull mock-irc ircfiber-engine ircfiber-holder ircfiber-gateway
dc up -d --wait --wait-timeout 120 redis mongo
dc exec -T redis redis-cli SET irc:config:egressRoutingPolicy \
    '{"schema":1,"revision":0,"global":{"order":["mullvad","nordvpn","direct"],"blockedRoutes":[]},"hosts":[]}' NX >/dev/null
dc exec -T redis redis-cli SET irc:config:routingSchemaVersion 1 NX >/dev/null
[[ $(dc exec -T redis redis-cli --raw GET irc:config:routingSchemaVersion) == 1 ]] || fail 'fixture schema seed failed'
dc up -d --wait --wait-timeout 120 mock-irc ircfiber-holder ircfiber-gateway egress-a ircfiber-engine
export DOCKER_CONTEXT="$context" ROUTING_REGRESSION_READY=1
export HOTSWAP_MOCK_COMPOSE="" HOTSWAP_USE_RUNNING_STACK=1
python3 "$SCRIPT_DIR/fixtures/fixture_gateway.py" "$context" "$COMPOSE_PROJECT_NAME" "$COMPOSE_FILE" \
    ircfiber-gateway 192.0.2.4 "$ROUTING_REGRESSION_PORT" -- bash "$SCRIPT_DIR/$mode.sh" "$@"
