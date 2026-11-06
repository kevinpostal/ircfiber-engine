#!/usr/bin/env bash
# Local holder-backed Nord failover, correlation and fail-closed proof.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INFRA_ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
BASE=${COMPOSE_FILE:-$INFRA_ROOT/site/deploy/local/docker-compose.yml}
MOCK=$SCRIPT_DIR/fixtures/docker-compose.mock-irc.yml
OVERLAY=$SCRIPT_DIR/fixtures/docker-compose.egress-failure.yml
GATEWAY=${GATEWAY_URL:-http://127.0.0.1:8090}
USER=${EGRESS_TEST_USER:-egressfailover}
PASS=${EGRESS_TEST_PASS:-egressfailover123}
JAR=$(mktemp /tmp/egress-failover-XXXXXX.cookies)
NAME_A="EgressAlpha_$(date +%s)"
NAME_B="EgressBeta_$(date +%s)"
ID_A= ID_B=

dc() { docker compose -f "$BASE" -f "$MOCK" -f "$OVERLAY" "$@"; }
logs() { docker logs ircfiber-engine 2>&1; }
mark() { logs | wc -l | tr -d ' '; }
since() { logs | tail -n +"$(( $1 + 1 ))"; }
holder_list() { docker exec ircfiber-holder /app/irc-fiber-holder --list; }
entries() { holder_list | jq -c --arg a "$ID_A" --arg b "$ID_B" '.connections[] | select(.tag.networkId == $a or .tag.networkId == $b)'; }
api() { curl -fsS -b "$JAR" -X "$1" -H 'Content-Type: application/json' -d "${3:-}" "$GATEWAY$2"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
wait_for() {
    local seconds=$1 description=$2 condition=$3 i
    for ((i=0; i<seconds; i++)); do
        if eval "$condition" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    fail "timeout waiting for $description"
}
cleanup() {
    for id in "$ID_A" "$ID_B"; do
        if [[ -n "$id" ]]; then curl -s -b "$JAR" -X DELETE "$GATEWAY/api/networks/$id" -o /dev/null || true; fi
    done
    dc stop egress-a egress-b >/dev/null 2>&1 || true
    dc rm -f egress-a egress-b >/dev/null 2>&1 || true
    rm -f "$JAR"
}
trap cleanup EXIT

# Do not remove unrelated local services or the live holder during setup.
dc stop egress-b >/dev/null 2>&1 || true
dc rm -f egress-b >/dev/null 2>&1 || true
dc up -d --build --quiet-build redis mongo mock-irc ircfiber-holder ircfiber-gateway egress-a ircfiber-engine
wait_for 120 'gateway health' 'curl -fsS "$GATEWAY/health"'
wait_for 60 'holder status' 'docker exec ircfiber-holder /app/irc-fiber-holder --status'
wait_for 30 'north SOCKS listener' 'docker logs egress-a 2>&1 | grep -q "SOCKS exit listening"'

curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/register" \
    -d "username=$USER" -d "email=$USER@local.test" -d "password=$PASS" -L -o /dev/null || true
curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/login" \
    -d "username=$USER" -d "password=$PASS" -L -o /dev/null
curl -fsS -b "$JAR" "$GATEWAY/api/networks" | jq -e 'type == "array"' >/dev/null || fail 'login failed'

START_MS=$(date +%s000)
START=$(mark)
create() {
    local response
    response=$(api POST /api/networks "{\"name\":\"$1\",\"host\":\"$2\",\"port\":16668,\"tls\":\"disabled\",\"nick\":\"egresstest\",\"realName\":\"Egress test\",\"egressNodeId\":\"nordvpn\",\"autoJoinChannels\":[]}")
    jq -er '.id // .networkId' <<<"$response" || fail "create failed: $response"
}
ID_A=$(create "$NAME_A" alpha.example.org)
ID_B=$(create "$NAME_B" beta.example.net)
registered_both() {
    local recent
    recent=$(since "$1" | grep '"event":"register_complete"' || true)
    grep -F "\"network\":\"$NAME_A\"" <<<"$recent" >/dev/null &&
        grep -F "\"network\":\"$NAME_B\"" <<<"$recent" >/dev/null
}
wait_for 180 'both networks registered via north' '[[ "$(entries | jq -r "select(.state == \"open\" and .tag.egressLabel == \"north\") | .tag.networkId" | sort -u | wc -l | tr -d " ")" == 2 ]]'
wait_for 60 'both registration events' 'registered_both "$START"'
[[ "$(entries | jq -r 'select(.tag.egressLabel == "") | .id' | wc -l | tr -d ' ')" == 0 ]] || fail 'direct holder entry before failover'
printf 'Registered both networks via north; waiting for stable sessions (65s)\n'
sleep 65

dc up -d egress-b
wait_for 30 'south SOCKS listener' 'docker logs egress-b 2>&1 | grep -q "SOCKS exit listening"'
DROP=$(mark)
docker kill --signal=USR1 egress-a >/dev/null
wait_for 180 'both networks re-registered through south' '[[ "$(entries | jq -r "select(.state == \"open\" and .tag.egressLabel == \"south\") | .tag.networkId" | sort -u | wc -l | tr -d " ")" == 2 ]]'
wait_for 30 'two south registration events' 'registered_both "$DROP"'
count=$(since "$DROP" | grep '"event":"egress_quarantined"' | grep -c '"label":"north"' || true)
[[ "$count" == 1 ]] || fail "expected one north quarantine transition, got $count"
alert_count() {
    docker exec ircfiber-redis redis-cli --raw lrange irc:logs:outbox 0 -1 |
        jq -s --argjson start "$START_MS" '[.[] | select(.type == "notice" and .actor == "engine"
            and .ts >= $start and (.text | contains("VPN exit north quarantined"))
            and (.text | contains("2 distinct IRC hosts")))] | length'
}
wait_for 10 'north #staff outbox notice' '[[ "$(alert_count)" == 1 ]]'
[[ "$(entries | jq -r 'select(.tag.egressLabel == "") | .id' | wc -l | tr -d ' ')" == 0 ]] || fail 'direct holder socket during failover'
if since "$DROP" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial during failover'
fi
printf 'PASS: one north quarantine; both networks re-registered through south\n'

ALL_DOWN=$(mark)
docker kill --signal=USR1 egress-b >/dev/null
wait_for 180 'reconnect backoff after both exits fail' 'since "$ALL_DOWN" | grep -q "\"event\":\"reconnect_scheduled\""'
wait_for 180 'fail-closed Nord error after both exits fail' 'since "$ALL_DOWN" | grep -q "No healthy NordVPN exit available\|SOCKS"'
[[ "$(entries | jq -r 'select(.state == "open" and .tag.egressLabel == "") | .id' | wc -l | tr -d ' ')" == 0 ]] || fail 'direct holder socket with all exits down'
if since "$ALL_DOWN" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial with all exits down'
fi
printf 'PASS: all exits down; reconnecting with backoff and no direct dial\n'
