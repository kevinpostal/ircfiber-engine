#!/usr/bin/env bash
# Socket-preserving engine hot-swap proof in an owned disposable fixture.
# Direct invocation enters routing_regression.sh, which builds and starts
# isolated services and supplies the explicit Docker context/project.
#
# Only the fixture engine is restarted/killed. Holder, gateway, storage and
# mock keep their containers and start times throughout both swaps. Physical
# assertions cover the target's same holder ID/timestamp, one additional mock
# socket (beside any signup default), no QUIT, post-swap JOIN/NAMES and a
# holder PONG while the engine is demonstrably stopped. No engine log wording
# is part of the proof.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${ROUTING_REGRESSION_READY:-0}" != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" hot_swap "$@"
fi

: "${COMPOSE_FILE:?routing regression wrapper must supply COMPOSE_FILE}"
: "${COMPOSE_PROJECT_NAME:?routing regression wrapper must supply COMPOSE_PROJECT_NAME}"
: "${DOCKER_CONTEXT:?routing regression wrapper must supply DOCKER_CONTEXT}"
: "${ROUTING_REGRESSION_RUN:?routing regression wrapper must supply ROUTING_REGRESSION_RUN}"
: "${GATEWAY_URL:?routing regression wrapper must supply GATEWAY_URL}"
GATEWAY=${GATEWAY_URL%/}
USERNAME=${HOTSWAP_USER:-hotswap}
PASSWORD=${HOTSWAP_PASS:-hotswap123}
EMAIL=${HOTSWAP_EMAIL:-hotswap@local.test}
ENGINE_SERVICE=ircfiber-engine
HOLDER_SERVICE=ircfiber-holder
MOCK_SERVICE=mock-irc
MOCK_HOST=mock-irc
MOCK_LINES=/tmp/mock-irc.lines
MOCK_RESULT=/tmp/holder-mock-irc.result
MOCK_INJECT=/tmp/mock-irc.inject
NET_NAME="HotSwap_${ROUTING_REGRESSION_RUN}"
NET_ID=""
JAR=""

dk() { docker --context "$DOCKER_CONTEXT" "$@"; }
dc() { dk compose -f "$COMPOSE_FILE" --project-name "$COMPOSE_PROJECT_NAME" "$@"; }
say() { printf '\033[36m→ %s\033[0m\n' "$*"; }
ok() { printf '\033[92m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
    if [[ -n "$NET_ID" && -z "${KEEP_NETWORK:-}" ]]; then
        api DELETE "/api/networks/$NET_ID" >/dev/null || true
    fi
    [[ -z "$JAR" ]] || rm -f "$JAR"
}
trap cleanup EXIT

# wait_for <seconds> <description> <shell condition> — polls (1 s) until the
# condition, evaluated in this shell (so the helpers below are visible),
# succeeds or the deadline passes.
wait_for() {
    local secs=$1 what=$2 cond=$3
    local i
    for ((i = 0; i < secs; i++)); do
        if eval "$cond" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    fail "timeout after ${secs}s waiting for: $what"
}

mock_lines() { dk exec "$MOCK" sh -c "cat $MOCK_LINES 2>/dev/null || true"; }
mock_lines_count() { mock_lines | wc -l | tr -d ' '; }
mock_lines_since() { mock_lines | tail -n +"$(( $1 + 1 ))"; }
mock_distinct() { dk exec "$MOCK" cat "$MOCK_RESULT" | grep '^distinct=' | cut -d= -f2; }
mock_user_count() { mock_lines | grep -c '^USER ' || true; }
holder_status() { dk exec "$HOLDER" /app/irc-fiber-holder --status; }
holder_list() { dk exec "$HOLDER" /app/irc-fiber-holder --list; }
# The holder entry for our network: "<id> <connectedAtMs> <state>".
holder_entry() {
    holder_list | jq -er --arg n "$NET_NAME" \
        '[.connections[] | select(.tag.name == $n)] |
         if length == 1 then .[0] | "\(.id) \(.connectedAtMs) \(.state)"
         else error("expected exactly one held target") end'
}
api() {
    local method=$1 path=$2 body=${3:-}
    python3 "$SCRIPT_DIR/fixtures/fixture_http.py" "$JAR" "$GATEWAY" "$method" "$path" "$body"
}
api_form() {
    local path=$1 field key value body=""
    shift
    for field in "$@"; do
        key=${field%%=*}
        value=$(jq -rn --arg value "${field#*=}" '$value | @uri')
        body+="${body:+&}$key=$value"
    done
    python3 "$SCRIPT_DIR/fixtures/fixture_http.py" "$JAR" "$GATEWAY" POST "$path" "$body" \
        application/x-www-form-urlencoded
}
join_channel() {
    local chan=$1
    api POST "/api/networks/$NET_ID/join" "{\"channel\":\"$chan\"}" >/dev/null
}

[[ "$GATEWAY" =~ ^http://127\.0\.0\.1:[0-9]+$ ]] ||
    fail 'routing regression requires the wrapper loopback HTTP gateway'
[[ "$COMPOSE_FILE" == /* && -f "$COMPOSE_FILE" ]] ||
    fail 'routing regression requires an absolute fixture Compose file'
[[ "$COMPOSE_PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]+$ ]] ||
    fail 'invalid fixture project name'
[[ "$ROUTING_REGRESSION_RUN" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] ||
    fail 'invalid fixture run identity'
[[ -z "${HOTSWAP_MOCK_COMPOSE:-}" && "${HOTSWAP_USE_RUNNING_STACK:-0}" == 1 ]] ||
    fail 'routing regression must use the wrapper running fixture without overlays'

# Resolve every identity from the explicit project, then require both fixture
# labels before any exec, restart, kill or API mutation. Supplied container
# overrides, if present, must resolve to that very same Compose container.
owned_container() {
    local service=$1 id labels
    id=$(dc ps -q "$service")
    [[ -n "$id" && "$id" != *$'\n'* ]] || fail "expected one running fixture $service"
    labels=$(dk inspect --format '{{json .Config.Labels}}' "$id")
    jq -e --arg run "$ROUTING_REGRESSION_RUN" --arg project "$COMPOSE_PROJECT_NAME" --arg service "$service" \
        '."ircfiber.fixture" == "routing-regression"
         and ."ircfiber.fixture.run" == $run
         and ."com.docker.compose.project" == $project
         and ."com.docker.compose.service" == $service' <<<"$labels" >/dev/null ||
        fail "refusing unowned fixture container $service"
    printf '%s\n' "$id"
}
ENGINE=$(owned_container "$ENGINE_SERVICE")
HOLDER=$(owned_container "$HOLDER_SERVICE")
MOCK=$(owned_container "$MOCK_SERVICE")
for override in HOTSWAP_ENGINE_CONTAINER HOTSWAP_HOLDER_CONTAINER HOTSWAP_MOCK_CONTAINER; do
    case "$override" in
        HOTSWAP_ENGINE_CONTAINER) expected=$ENGINE ;;
        HOTSWAP_HOLDER_CONTAINER) expected=$HOLDER ;;
        HOTSWAP_MOCK_CONTAINER) expected=$MOCK ;;
    esac
    [[ -z "${!override:-}" || "${!override}" == "$expected" ]] ||
        fail "$override does not match the owned Compose container"
done
UNCHANGED_SERVICES=(redis mongo ircfiber-gateway "$HOLDER_SERVICE" "$MOCK_SERVICE")
UNCHANGED_IDS=()
UNCHANGED_STARTS=()
for service in "${UNCHANGED_SERVICES[@]}"; do
    id=$(owned_container "$service")
    UNCHANGED_IDS+=("$id")
    UNCHANGED_STARTS+=("$(dk inspect --format '{{.State.StartedAt}}' "$id")")
done
assert_unchanged_services() {
    local i id started
    for ((i = 0; i < ${#UNCHANGED_SERVICES[@]}; i++)); do
        id=$(owned_container "${UNCHANGED_SERVICES[$i]}")
        started=$(dk inspect --format '{{.State.StartedAt}}' "$id")
        [[ "$id" == "${UNCHANGED_IDS[$i]}" && "$started" == "${UNCHANGED_STARTS[$i]}" ]] ||
            fail "${UNCHANGED_SERVICES[$i]} changed during the engine-only swap"
    done
}
[[ "$(dk inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$ENGINE")" == no ]] ||
    fail 'fixture engine must disable automatic restarts for the engine-down proof'
[[ -f "$SCRIPT_DIR/fixtures/fixture_http.py" ]] || fail 'missing shared fixture HTTP helper'
JAR=$(mktemp /tmp/hot-swap-XXXXXX.cookies)
wait_for 90 "gateway /health" 'curl -fsS "$GATEWAY/health"'
wait_for 60 "holder --status" 'holder_status'
ENGINE_SERVER_ID=$(dk exec "$ENGINE" printenv IRCFIBER_SERVER_ID)
[[ "$ENGINE_SERVER_ID" == fixture-regression ]] || fail 'unexpected fixture engine identity'
wait_for 60 'policy-aware direct-capable engine registration' \
    "dc exec -T redis redis-cli --raw hget 'irc:server:$ENGINE_SERVER_ID' data | jq -e '.routingPolicyVersion == 1 and (.supportedRoutes | index(\"direct\") != null)'"
wait_for 30 "mock-irc listening" 'dk exec "$MOCK" test -f "$MOCK_RESULT"'

# ── Session + network ────────────────────────────────────────────────────
say "logging in to the disposable fixture"
api_form /register "username=$USERNAME" "email=$EMAIL" "password=$PASSWORD" >/dev/null
api_form /login "username=$USERNAME" "password=$PASSWORD" >/dev/null
NETWORKS=$(api GET /api/networks)
jq -e 'type == "array"' <<<"$NETWORKS" >/dev/null || fail 'login failed (no session)'

# Signup may provision a first-party default on this same mock. Let it settle
# before measuring the one additional target socket; it must not reconnect
# during either swap either.
default_held_open() {
    holder_list | jq -e --arg name "$DEFAULT_NAME" \
        '.connections[] | select(.tag.name == $name and .state == "open")' >/dev/null
}
while IFS= read -r DEFAULT_NAME; do
    [[ -n "$DEFAULT_NAME" ]] || continue
    wait_for 60 "signup default held open" 'default_held_open'
done < <(jq -r '.[] | select(.host == "default.regression.test") | .name' <<<"$NETWORKS")
DEFAULT_COUNT=$(jq '[.[] | select(.host == "default.regression.test")] | length' <<<"$NETWORKS")
wait_for 60 "signup default mock registration" \
    '[[ "$(mock_distinct)" == "$DEFAULT_COUNT" && "$(mock_user_count)" == "$DEFAULT_COUNT" ]]'
BASELINE_DISTINCT=$(mock_distinct)
[[ "$BASELINE_DISTINCT" =~ ^[0-9]+$ ]] || fail 'mock socket baseline is unavailable'
EXPECTED_DISTINCT=$((BASELINE_DISTINCT + 1))

MARK=$(mock_lines_count)
say "creating network $NET_NAME → $MOCK_HOST:16668 (plain TCP)"
RESP=$(api POST /api/networks "{\"name\":\"$NET_NAME\",\"host\":\"$MOCK_HOST\",\"port\":16668,\"tls\":\"disabled\",\"nick\":\"hotswap\",\"realName\":\"Hot Swap\",\"routing\":{\"order\":[\"direct\"],\"preferredExit\":\"\"},\"autoJoinChannels\":[]}")
NET_ID=$(printf '%s' "$RESP" | jq -r '.id // .networkId // empty')
[[ -n "$NET_ID" ]] || fail 'create network returned no network identity'
ok "network $NET_ID"

wait_for 60 "target registration at the mock" 'mock_lines_since "$MARK" | grep -q "^USER "'
wait_for 30 "holder shows $NET_NAME open" 'holder_entry | grep -q " open$"'
read -r ID0 CONNECTED0 _ < <(holder_entry)
[[ -n "$ID0" && "$ID0" != null && "$CONNECTED0" =~ ^[0-9]+$ && "$CONNECTED0" -gt 0 ]] ||
    fail 'target holder identity or connection timestamp is unavailable'
ok "registered; holder id=$ID0 connectedAtMs=$CONNECTED0"

# A channel joined before the swaps must be re-baselined after both attaches.
MARK=$(mock_lines_count)
join_channel '#pre'
wait_for 20 "JOIN #pre at the mock" 'mock_lines_since "$MARK" | grep -q "^JOIN #pre"'
ok "JOIN #pre relayed"

# ── Assertions shared by both swaps ──────────────────────────────────────
# $1 = mock lines mark, $2 = phase label
assert_swapped() {
    local mock_mark=$1 phase=$2
    local status open attached detached id connected state result

    status=$(holder_status)
    open=$(jq -r .open <<<"$status"); attached=$(jq -r .attached <<<"$status"); detached=$(jq -r .detached <<<"$status")
    [[ "$detached" == 0 && "$attached" == "$open" && "$open" -ge 1 ]] \
        || fail "$phase: holder status open=$open attached=$attached detached=$detached: $status"
    ok "$phase: holder attached=$attached open=$open detached=0"

    read -r id connected state < <(holder_entry)
    [[ "$id" == "$ID0" && "$connected" == "$CONNECTED0" && "$state" == open ]] \
        || fail "$phase: session changed: id $ID0→$id connectedAtMs $CONNECTED0→$connected state=$state"
    ok "$phase: same holder session $id (connectedAtMs $connected)"

    result=$(dk exec "$MOCK" cat "$MOCK_RESULT")
    grep -q "^distinct=$EXPECTED_DISTINCT$" <<<"$result" ||
        fail "$phase: mock expected exactly one target socket above baseline $BASELINE_DISTINCT: $result"
    ok "$phase: target still has exactly one server-side socket"

    if mock_lines | grep -q '^QUIT'; then fail "$phase: a QUIT reached the mock"; fi
    ok "$phase: no QUIT at the mock"

    mock_lines_since "$mock_mark" | grep -q '^NAMES #pre' \
        || fail "$phase: no NAMES #pre re-baseline after attach"
    ok "$phase: NAMES #pre re-baselined"
    assert_unchanged_services
}

# ── (a) graceful: SIGTERM = detach, new engine reattaches ────────────────
say "(a) graceful swap: restarting only the fixture engine"
MARK=$(mock_lines_count)
dc restart "$ENGINE_SERVICE"
wait_for 90 "NAMES #pre after graceful attach" 'mock_lines_since "$MARK" | grep -q "^NAMES #pre"'
join_channel '#hot'
wait_for 20 "JOIN #hot at the mock" 'mock_lines_since "$MARK" | grep -q "^JOIN #hot$"'
assert_swapped "$MARK" graceful
ok "graceful: JOIN #hot relayed through the swapped engine"
printf '\033[92mPASS graceful\033[0m\n'

# ── (b) crash: SIGKILL, holder auto-PONGs, new engine reattaches ─────────
say "(b) crash swap: killing only the fixture engine"
MARK=$(mock_lines_count)
dk kill -s KILL "$ENGINE" >/dev/null
wait_for 15 "fixture engine stopped" '[[ "$(dk inspect --format "{{.State.Running}}" "$ENGINE")" == false ]]'
say "engine down — injecting a PING at the mock"
dk exec "$MOCK" sh -c "printf 'PING :hotswap-down\r\n' > $MOCK_INJECT"
wait_for 15 "PONG from the holder" 'mock_lines_since "$MARK" | grep -q "^PONG :hotswap-down$"'
[[ "$(dk inspect --format '{{.State.Running}}' "$ENGINE")" == false ]] ||
    fail 'engine was running during the holder-only PONG proof'
ok "crash: holder answered PING while the engine was down"
dc start "$ENGINE_SERVICE"
wait_for 90 "NAMES #pre after crash attach" 'mock_lines_since "$MARK" | grep -q "^NAMES #pre"'
join_channel '#hot2'
wait_for 20 "JOIN #hot2 at the mock" 'mock_lines_since "$MARK" | grep -q "^JOIN #hot2$"'
assert_swapped "$MARK" crash
ok "crash: JOIN #hot2 relayed through the restarted engine"
printf '\033[92mPASS crash\033[0m\n'
