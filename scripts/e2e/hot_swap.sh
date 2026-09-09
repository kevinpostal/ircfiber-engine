#!/usr/bin/env bash
# Engine hot-swap proof (Linux/docker, local stack).
#
# Brings up the local stack (site/deploy/local/docker-compose.yml: redis,
# mongo, ircd, gateway, ircfiber-holder, ircfiber-engine) plus a mock IRC
# server (fixtures/holder_mock_irc.py as service `mock-irc`), creates a
# plain-TCP network pointing at mock-irc:16668 through the gateway API, and
# then replaces the engine twice while the holder keeps the IRC socket:
#
#   (a) graceful — `docker compose restart ircfiber-engine` (SIGTERM = detach)
#   (b) crash    — `docker kill -s KILL ircfiber-engine` + `up -d`
#
# After each swap it asserts, against the holder, the engine log and the
# mock's line file:
#   * holder --status: detached == 0, attached == open >= 1
#   * our session keeps the same holder id and connectedAtMs (never re-dialed)
#   * engine log shows "event":"attached"
#   * the mock saw exactly one server-side socket (result file distinct=1)
#   * no QUIT ever reached the mock
#   * a JOIN issued after the swap is relayed (JOIN #hot / #hot2 at the mock)
#   * NAMES re-sync happens only on the crash path (b), never on (a)
#   * during (b), while the engine is down, a PING :x injected by the mock is
#     answered PONG :x by the holder and never reaches the engine log
#
# Prints `PASS graceful` and `PASS crash`; exits non-zero on the first
# failed assertion. Env: GATEWAY_URL (http://127.0.0.1:8090), COMPOSE_FILE
# (the local stack compose), KEEP_NETWORK=1 to leave the test network.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INFRA_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
COMPOSE_FILE=${COMPOSE_FILE:-$INFRA_ROOT/site/deploy/local/docker-compose.yml}
MOCK_COMPOSE=$SCRIPT_DIR/fixtures/docker-compose.mock-irc.yml
GATEWAY=${GATEWAY_URL:-http://127.0.0.1:8090}
USERNAME=${HOTSWAP_USER:-hotswap}
PASSWORD=${HOTSWAP_PASS:-hotswap123}
EMAIL=${HOTSWAP_EMAIL:-hotswap@local.test}
ENGINE=ircfiber-engine
HOLDER=ircfiber-holder
MOCK=mock-irc
MOCK_LINES=/tmp/mock-irc.lines
MOCK_RESULT=/tmp/holder-mock-irc.result
MOCK_INJECT=/tmp/mock-irc.inject
NET_NAME="HotSwap_$(date +%s)"
NET_ID=""
JAR=$(mktemp /tmp/hot-swap-XXXXXX.cookies)

dc() { docker compose -f "$COMPOSE_FILE" -f "$MOCK_COMPOSE" "$@"; }
say() { printf '\033[36m→ %s\033[0m\n' "$*"; }
ok() { printf '\033[92m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
    if [[ -n "$NET_ID" && -z "${KEEP_NETWORK:-}" ]]; then
        curl -s -b "$JAR" -X DELETE "$GATEWAY/api/networks/$NET_ID" -o /dev/null || true
    fi
    rm -f "$JAR"
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

engine_log() { docker logs "$ENGINE" 2>&1; }
engine_log_lines() { engine_log | wc -l | tr -d ' '; }
# Engine log lines after a mark (a line count taken earlier).
engine_log_since() { engine_log | tail -n +"$(( $1 + 1 ))"; }
mock_lines() { docker exec "$MOCK" sh -c "cat $MOCK_LINES 2>/dev/null || true"; }
mock_lines_count() { mock_lines | wc -l | tr -d ' '; }
mock_lines_since() { mock_lines | tail -n +"$(( $1 + 1 ))"; }
holder_status() { docker exec "$HOLDER" /app/irc-fiber-holder --status; }
holder_list() { docker exec "$HOLDER" /app/irc-fiber-holder --list; }
# The holder entry for our network: "<id> <connectedAtMs> <state>".
holder_entry() {
    holder_list | jq -r --arg n "$NET_NAME" \
        '.connections[] | select(.tag.name == $n) | "\(.id) \(.connectedAtMs) \(.state)"'
}
api() {
    local method=$1 path=$2 body=${3:-}
    if [[ -n "$body" ]]; then
        curl -s -b "$JAR" -X "$method" -H 'Content-Type: application/json' -d "$body" "$GATEWAY$path"
    else
        curl -s -b "$JAR" -X "$method" "$GATEWAY$path"
    fi
}
join_channel() {
    local chan=$1
    api POST "/api/networks/$NET_ID/join" "{\"channel\":\"$chan\"}" >/dev/null
}
attached_count() { engine_log_since "$1" | grep -c '"event":"attached"' || true; }

# ── 0. Stack ─────────────────────────────────────────────────────────────
say "starting local stack + mock-irc ($COMPOSE_FILE)"
dc up -d --remove-orphans redis mongo "$MOCK" "$HOLDER" ircfiber-gateway "$ENGINE"
wait_for 90 "gateway /health" 'curl -fsS "$GATEWAY/health"'
wait_for 60 "holder --status" 'holder_status'
wait_for 30 "mock-irc listening" 'docker logs "$MOCK" 2>&1 | grep -q listening'
ok "stack up"

# ── 1. Session + network ─────────────────────────────────────────────────
say "logging in as $USERNAME"
curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/register" \
    -d "username=$USERNAME" -d "email=$EMAIL" -d "password=$PASSWORD" -L -o /dev/null || true
curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/login" \
    -d "username=$USERNAME" -d "password=$PASSWORD" -L -o /dev/null
api GET /api/networks | jq -e 'type == "array"' >/dev/null || fail "login failed (no session)"

LOG_MARK=$(engine_log_lines)
say "creating network $NET_NAME → $MOCK:16668 (plain TCP)"
RESP=$(api POST /api/networks "{\"name\":\"$NET_NAME\",\"host\":\"$MOCK\",\"port\":16668,\"tls\":\"disabled\",\"nick\":\"hotswap\",\"realName\":\"Hot Swap\",\"autoJoinChannels\":[]}")
NET_ID=$(printf '%s' "$RESP" | jq -r '.id // .networkId // empty')
[[ -n "$NET_ID" ]] || fail "create network failed: $RESP"
ok "network $NET_ID"

wait_for 60 "engine register_complete" 'engine_log_since "$LOG_MARK" | grep -q register_complete'
wait_for 30 "holder shows $NET_NAME open" 'holder_entry | grep -q " open$"'
read -r ID0 CONNECTED0 _ < <(holder_entry)
ok "registered; holder id=$ID0 connectedAtMs=$CONNECTED0"

# A channel joined before the swaps: on the crash path the reattached engine
# must re-sync it with NAMES; on the graceful path it must not.
MARK=$(mock_lines_count)
join_channel '#pre'
wait_for 20 "JOIN #pre at the mock" 'mock_lines_since "$MARK" | grep -q "^JOIN #pre"'
ok "JOIN #pre relayed"

# ── Assertions shared by both swaps ──────────────────────────────────────
# $1 = engine log mark, $2 = mock lines mark, $3 = phase label
assert_swapped() {
    local log_mark=$1 mock_mark=$2 phase=$3
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

    [[ "$(attached_count "$log_mark")" -ge 1 ]] || fail "$phase: no \"event\":\"attached\" in the engine log"
    ok "$phase: engine logged event attached"

    result=$(docker exec "$MOCK" cat "$MOCK_RESULT")
    grep -q '^distinct=1$' <<<"$result" || fail "$phase: mock saw more than one socket: $result"
    ok "$phase: mock saw exactly one server-side socket"

    if mock_lines | grep -q '^QUIT'; then fail "$phase: a QUIT reached the mock"; fi
    ok "$phase: no QUIT at the mock"

    if [[ "$phase" == graceful ]]; then
        if mock_lines_since "$mock_mark" | grep -q '^NAMES'; then fail "$phase: NAMES sent on the graceful path"; fi
        ok "$phase: no NAMES re-sync (META was graceful)"
    else
        mock_lines_since "$mock_mark" | grep -q '^NAMES #pre' || fail "$phase: no NAMES #pre re-sync after crash attach"
        ok "$phase: NAMES #pre re-sync after crash"
    fi
}

# ── (a) graceful: SIGTERM = detach, new engine reattaches ────────────────
say "(a) graceful swap: docker compose restart $ENGINE"
LOG_MARK=$(engine_log_lines); MARK=$(mock_lines_count)
dc restart "$ENGINE"
wait_for 90 "engine reattached after restart" '[[ "$(attached_count "$LOG_MARK")" -ge 1 ]]'
sleep 2
assert_swapped "$LOG_MARK" "$MARK" graceful
join_channel '#hot'
wait_for 20 "JOIN #hot at the mock" 'mock_lines_since "$MARK" | grep -q "^JOIN #hot$"'
ok "graceful: JOIN #hot relayed through the swapped engine"
printf '\033[92mPASS graceful\033[0m\n'

# ── (b) crash: SIGKILL, holder auto-PONGs, new engine reattaches ─────────
say "(b) crash swap: docker kill -s KILL $ENGINE"
LOG_MARK=$(engine_log_lines); MARK=$(mock_lines_count)
docker kill -s KILL "$ENGINE" >/dev/null
sleep 1
say "engine down — injecting PING :x at the mock (expect the holder's PONG)"
docker exec "$MOCK" sh -c "printf 'PING :x\r\n' > $MOCK_INJECT"
wait_for 15 "PONG :x from the holder" 'mock_lines_since "$MARK" | grep -q "^PONG :x$"'
ok "crash: holder answered PING :x while the engine was down"
dc up -d --no-deps "$ENGINE"
wait_for 90 "engine reattached after crash" '[[ "$(attached_count "$LOG_MARK")" -ge 1 ]]'
sleep 2
assert_swapped "$LOG_MARK" "$MARK" crash
if engine_log_since "$LOG_MARK" | grep -q 'PING :x'; then fail "crash: the injected PING :x reached the engine log"; fi
ok "crash: PING :x never reached the engine"
join_channel '#hot2'
wait_for 20 "JOIN #hot2 at the mock" 'mock_lines_since "$MARK" | grep -q "^JOIN #hot2$"'
ok "crash: JOIN #hot2 relayed through the restarted engine"
printf '\033[92mPASS crash\033[0m\n'
