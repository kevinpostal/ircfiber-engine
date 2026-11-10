#!/usr/bin/env bash
# Run the original runtime regressions on a unique, labelled internal stack.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
mode=${1:-}
case "$mode" in egress_failover|hot_swap|memory_reliability|holder_pressure|holder_engine_qualification|archive_reliability|holder_memory_reliability|legacy_holder_continuity|coordinated_holder) shift;; *) fail 'unsupported routing qualification mode';; esac
qualification=0
case "$mode" in memory_reliability|holder_pressure|holder_engine_qualification|archive_reliability|holder_memory_reliability|legacy_holder_continuity|coordinated_holder) qualification=1;; esac
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
compose_args=(-f "$COMPOSE_FILE")
if [[ $mode == archive_reliability ]]; then
    export ARCHIVE_COMPOSE_FILE="$SCRIPT_DIR/fixtures/docker-compose.archive-reliability.yml"
    compose_args+=(-f "$ARCHIVE_COMPOSE_FILE")
fi
if [[ $mode == coordinated_holder ]]; then
    export COORDINATED_COMPOSE_FILE="$SCRIPT_DIR/fixtures/docker-compose.coordinated-holder.yml"
    compose_args+=(-f "$COORDINATED_COMPOSE_FILE")
fi
dc() { dock compose --project-name "$COMPOSE_PROJECT_NAME" "${compose_args[@]}" "$@"; }
[[ -z $(dock ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME") ]] || fail 'project already exists'
export ROUTING_REGRESSION_MEMORY=0
[[ $mode != memory_reliability ]] || export ROUTING_REGRESSION_MEMORY=1
export ROUTING_REGRESSION_ENGINE_HOLDER_ADDR=unix:///run/ircfiber/holder.sock
[[ $mode != memory_reliability ]] || export ROUTING_REGRESSION_ENGINE_HOLDER_ADDR=tcp://192.0.2.10:7690
export ROUTING_REGRESSION_HOLDER_DETACH_SECS=600 ROUTING_REGRESSION_HOLDER_SWAP=3g
if [[ $mode == holder_pressure || $mode == holder_engine_qualification ]]; then
    export ROUTING_REGRESSION_HOLDER_DETACH_SECS=0 ROUTING_REGRESSION_HOLDER_SWAP=3145728000
fi
if [[ $mode == holder_memory_reliability ]]; then
    export ROUTING_REGRESSION_MEMORY=1
    export ROUTING_REGRESSION_ENGINE_HOLDER_ADDR=tcp://192.0.2.10:7690
    export ROUTING_REGRESSION_HOLDER_DETACH_SECS=0
    export ROUTING_REGRESSION_MOCK_COMMAND='python3 -u /fixture/holder_memory_qualification.py serve'
    export MEMORY_EVIDENCE_DIR=${MEMORY_EVIDENCE_DIR:-${TMPDIR:-/tmp}/$ROUTING_REGRESSION_RUN-holder-memory}
    [[ ! -e $MEMORY_EVIDENCE_DIR ]] || fail 'holder working-set evidence directory must be fresh'
    mkdir -m 700 "$MEMORY_EVIDENCE_DIR"
    printf 'Corrected-holder working-set evidence: %s\n' "$MEMORY_EVIDENCE_DIR"
fi
if [[ $mode == legacy_holder_continuity ]]; then
    export ROUTING_REGRESSION_MEMORY=1
    export ROUTING_REGRESSION_ENGINE_HOLDER_ADDR=tcp://192.0.2.10:7690
    export ROUTING_REGRESSION_MOCK_COMMAND='python3 -u /fixture/legacy_holder_continuity.py serve'
    export LEGACY_CONTINUITY_SESSIONS=${LEGACY_CONTINUITY_SESSIONS:-12}
    [[ $LEGACY_CONTINUITY_SESSIONS =~ ^[0-9]{1,2}$ ]] &&
        (( 10#$LEGACY_CONTINUITY_SESSIONS >= 4 && 10#$LEGACY_CONTINUITY_SESSIONS <= 64 )) ||
        fail 'legacy continuity requires 4..64 sessions (default 12, including six TLS)'
    export MEMORY_EVIDENCE_DIR=${MEMORY_EVIDENCE_DIR:-${TMPDIR:-/tmp}/$ROUTING_REGRESSION_RUN-legacy-continuity}
    [[ ! -e $MEMORY_EVIDENCE_DIR ]] || fail 'legacy continuity evidence directory must be fresh'
    mkdir -m 700 "$MEMORY_EVIDENCE_DIR"
    printf 'Old-holder TCP+TLS continuity evidence (not full memory/rollout qualification): %s\n' "$MEMORY_EVIDENCE_DIR"
fi
if [[ $mode == archive_reliability ]]; then
    export ROUTING_REGRESSION_MEMORY=1
    export ROUTING_REGRESSION_ENGINE_HOLDER_ADDR=tcp://192.0.2.10:7690
    export ROUTING_REGRESSION_HOLDER_DETACH_SECS=0
    export ROUTING_REGRESSION_MOCK_COMMAND='python3 -u /fixture/archive_qualification.py serve'
    export ARCHIVE_CASE=${ARCHIVE_CASE:-full}
    case "$ARCHIVE_CASE" in
        full|smoke) export ROUTING_REGRESSION_ARCHIVE_MAX_BYTES=536870912;;
        quota) export ROUTING_REGRESSION_ARCHIVE_MAX_BYTES=33554432;;
        *) fail 'ARCHIVE_CASE must be full, smoke or quota';;
    esac
    export ARCHIVE_EVIDENCE_DIR=${ARCHIVE_EVIDENCE_DIR:-${TMPDIR:-/tmp}/$ROUTING_REGRESSION_RUN-archive}
    [[ ! -e $ARCHIVE_EVIDENCE_DIR ]] || fail 'archive evidence directory must be fresh'
    mkdir -m 700 "$ARCHIVE_EVIDENCE_DIR"
    printf 'Archive evidence: %s\n' "$ARCHIVE_EVIDENCE_DIR"
fi
if [[ $mode == holder_engine_qualification ]]; then
    export ROUTING_REGRESSION_ENGINE_HOLDER_ADDR=tcp://192.0.2.10:7690
    export ROUTING_REGRESSION_MOCK_COMMAND='python3 -u /fixture/holder_engine_qualification.py serve'
    export ROUTING_REGRESSION_SOCKS_COMMAND='python3 -u /fixture/holder_engine_qualification.py socks'
    export HOLDER_MAINTENANCE_HELPER="$SCRIPT_DIR/../../../site/scripts/ircfiber-holder-maintenance.py"
    export HOLDER_ENGINE_EVIDENCE_DIR=${HOLDER_ENGINE_EVIDENCE_DIR:-${TMPDIR:-/tmp}/$ROUTING_REGRESSION_RUN-holder-engine}
    [[ ! -e $HOLDER_ENGINE_EVIDENCE_DIR ]] || fail 'holder engine evidence directory must be fresh'
    mkdir -m 700 "$HOLDER_ENGINE_EVIDENCE_DIR"
fi
if [[ $mode == coordinated_holder ]]; then
    export ROUTING_REGRESSION_HOLDER_SWAP=3145728000
    export ROUTING_REGRESSION_MOCK_COMMAND='python3 -u /fixture/holder_engine_qualification.py serve'
    export ROUTING_REGRESSION_SOCKS_COMMAND='python3 -u /fixture/holder_engine_qualification.py socks'
    export HOLDER_MAINTENANCE_HELPER="$SCRIPT_DIR/../../../site/scripts/ircfiber-holder-maintenance.py"
    export HOLDER_ENGINE_EVIDENCE_DIR=${HOLDER_ENGINE_EVIDENCE_DIR:-${TMPDIR:-/tmp}/$ROUTING_REGRESSION_RUN-coordinated}
    [[ ! -e $HOLDER_ENGINE_EVIDENCE_DIR ]] || fail 'coordinated evidence directory must be fresh'
    mkdir -m 700 "$HOLDER_ENGINE_EVIDENCE_DIR"
    export COORDINATED_SESSIONS=${COORDINATED_SESSIONS:-16} COORDINATED_CASE=${COORDINATED_CASE:-complete}
    [[ $COORDINATED_SESSIONS =~ ^[0-9]+$ ]] && (( COORDINATED_SESSIONS >= 16 && COORDINATED_SESSIONS <= 250 )) ||
        fail 'coordinated physical fixture requires 16..250 sessions; separate full-load gate remains mandatory'
    [[ $COORDINATED_CASE == complete || $COORDINATED_CASE == ambiguous ]] || fail 'unsupported coordinated case'
    [[ ${COORDINATED_SOURCE_REVISION:-} == fea67fb48f891791a443367f9169ed32bc5a923e ]] ||
        fail 'COORDINATED_SOURCE_REVISION must be the reviewed old-holder IPC lifecycle commit, not engine base provenance'
    for variable in COORDINATED_ENGINE_IMAGE COORDINATED_HOLDER_IMAGE; do
        supplied=${!variable:-}
        [[ $supplied =~ ^sha256:[0-9a-f]{64}$ ]] || fail "$variable requires an immutable local image"
        [[ $(dock image inspect --format '{{.Os}}/{{.Architecture}} {{.Id}}' "$supplied") == "linux/amd64 $supplied" ]] ||
            fail "$variable must resolve to the exact immutable Linux/amd64 image"
        export "$variable=$supplied"
    done
fi
if [[ $qualification == 1 ]]; then
    export ROUTING_REGRESSION_LOG_LEVEL=info ROUTING_REGRESSION_CA_FILE=/fixture-certs/ca-certificates.crt
fi
build_services=(mock-irc)
for component in ENGINE HOLDER GATEWAY; do
    variable=ROUTING_REGRESSION_${component}_IMAGE
    service=$(printf '%s' "$component" | tr '[:upper:]' '[:lower:]')
    supplied=${!variable:-}
    if [[ -n $supplied ]]; then
        [[ $supplied =~ ^sha256:[a-f0-9]{64}$ ]] || fail "$variable must be an immutable local image ID"
        [[ $(dock image inspect --format '{{.Os}}/{{.Architecture}} {{.Id}}' "$supplied") == "linux/amd64 $supplied" ]] ||
            fail "$variable must resolve to the exact local Linux/amd64 image"
    else
        [[ $qualification == 0 ]] || fail "qualification requires $variable (no implicit source builds)"
        supplied="$ROUTING_REGRESSION_RUN-$service:fresh"
        build_services+=("ircfiber-$service")
    fi
    export "$variable=$supplied"
done
if [[ $mode == holder_memory_reliability ]]; then
    [[ $ROUTING_REGRESSION_HOLDER_IMAGE != sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09 ]] ||
        fail 'corrected-holder working-set qualification requires an explicit new holder candidate'
fi
if [[ $mode == legacy_holder_continuity ]]; then
    [[ $ROUTING_REGRESSION_HOLDER_IMAGE == sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09 ]] ||
        fail 'legacy continuity requires the exact unchanged old holder image'
fi
if [[ $mode == coordinated_holder ]]; then
    [[ $ROUTING_REGRESSION_HOLDER_IMAGE == sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09 ]] ||
        fail 'coordinated qualification requires the exact preserved old holder'
    [[ $ROUTING_REGRESSION_ENGINE_IMAGE == sha256:f9a5a59d2ba3ae99c002a1a6666007ecbe5bd36e032f8277622de7fbdbb06c89 ]] ||
        fail 'coordinated qualification requires the exact preserved old f9a5 engine'
    [[ $COORDINATED_HOLDER_IMAGE != "$ROUTING_REGRESSION_HOLDER_IMAGE" &&
       $COORDINATED_ENGINE_IMAGE != "$ROUTING_REGRESSION_ENGINE_IMAGE" ]] ||
        fail 'old and candidate application generations must be distinct'
fi
if [[ $mode == archive_reliability ]]; then
    [[ $ROUTING_REGRESSION_HOLDER_IMAGE != sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09 ]] ||
        fail 'B requires the qualified new holder candidate, not the old Rollout-A holder'
fi
if [[ $mode == memory_reliability ]]; then
    export ROUTING_REGRESSION_LOG_LEVEL=info ROUTING_REGRESSION_CA_FILE=/fixture-certs/ca-certificates.crt
    [[ $ROUTING_REGRESSION_HOLDER_IMAGE == sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09 ]] ||
        fail 'Rollout A must use the exact unchanged production holder image; step-8 qualification is separate'
    export MEMORY_EVIDENCE_DIR=${MEMORY_EVIDENCE_DIR:-${TMPDIR:-/tmp}/$ROUTING_REGRESSION_RUN-memory}
    [[ ! -e $MEMORY_EVIDENCE_DIR ]] || fail 'memory evidence directory must not already exist'
    mkdir -m 700 "$MEMORY_EVIDENCE_DIR"
    printf 'Memory evidence: %s\n' "$MEMORY_EVIDENCE_DIR"
fi
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
    if [[ $status -ne 0 && $qualification == 0 ]]; then
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
    if [[ $status -ne 0 && $mode == memory_reliability && ! -f $MEMORY_EVIDENCE_DIR/result.json ]]; then
        printf '{"state":"failed","reason":"owned launcher failed before qualification completed"}\n' \
            > "$MEMORY_EVIDENCE_DIR/result.json"
    fi
    if [[ $status -ne 0 && $mode == archive_reliability && ! -f $ARCHIVE_EVIDENCE_DIR/result.json ]]; then
        printf '{"state":"failed","qualified":false,"reason":"owned launcher failed before qualification completed"}\n' \
            > "$ARCHIVE_EVIDENCE_DIR/result.json"
    fi
    if [[ $status -ne 0 && $mode == holder_memory_reliability && ! -f $MEMORY_EVIDENCE_DIR/result.json ]]; then
        printf '{"state":"failed","qualified":false,"rolloutAQualified":false,"archiveBQualified":false,"holderWorkingSetQualified":false,"scope":"corrected-holder working-set only","reason":"owned launcher failed before qualification completed"}\n' \
            > "$MEMORY_EVIDENCE_DIR/result.json"
    fi
    if [[ $status -ne 0 && $mode == legacy_holder_continuity && ! -f $MEMORY_EVIDENCE_DIR/result.json ]]; then
        # Capture each bounded diagnostic independently while the owned stack
        # still exists, including launcher failures before the Python run starts.
        DOCKER_CONTEXT="$context" python3 "$SCRIPT_DIR/fixtures/legacy_holder_continuity.py" --capture-launcher-failure || true
        if [[ ! -f $MEMORY_EVIDENCE_DIR/result.json ]]; then
            printf '{"state":"failed","legacyContinuityQualified":false,"qualified":false,"rolloutAQualified":false,"holderWorkingSetQualified":false,"archiveBQualified":false,"stationaryMemoryQualified":false,"scope":"old-holder continuity only","reason":"launcher and pre-cleanup evidence capture failed"}\n' \
                > "$MEMORY_EVIDENCE_DIR/result.json"
        fi
    fi
    dc down --volumes --remove-orphans >/dev/null || true
    exit "$status"
}
trap cleanup EXIT
dc build --pull "${build_services[@]}"
if [[ $mode == holder_engine_qualification || $mode == coordinated_holder ]]; then
    dc run --rm --no-deps mock-irc python3 /fixture/holder_engine_qualification.py certificates
elif [[ $qualification == 1 ]]; then
    dc run --rm --no-deps mock-irc python3 /fixture/memory_fixture.py certificates
fi
dc up -d --wait --wait-timeout 120 redis mongo
dc exec -T redis redis-cli SET irc:config:egressRoutingPolicy \
    '{"schema":1,"revision":0,"global":{"order":["mullvad","nordvpn","direct"],"blockedRoutes":[]},"hosts":[]}' NX >/dev/null
dc exec -T redis redis-cli SET irc:config:routingSchemaVersion 1 NX >/dev/null
[[ $(dc exec -T redis redis-cli --raw GET irc:config:routingSchemaVersion) == 1 ]] || fail 'fixture schema seed failed'
services=(mock-irc ircfiber-holder ircfiber-gateway egress-a ircfiber-engine)
[[ $mode != holder_engine_qualification && $mode != coordinated_holder ]] || services+=(egress-b)
dc up -d --no-build --wait --wait-timeout 120 "${services[@]}"
export DOCKER_CONTEXT="$context" ROUTING_REGRESSION_READY=1
export HOTSWAP_MOCK_COMPOSE="" HOTSWAP_USE_RUNNING_STACK=1
python3 "$SCRIPT_DIR/fixtures/fixture_gateway.py" "$context" "$COMPOSE_PROJECT_NAME" "$COMPOSE_FILE" \
    ircfiber-gateway 192.0.2.4 "$ROUTING_REGRESSION_PORT" -- bash "$SCRIPT_DIR/$mode.sh" "$@"
