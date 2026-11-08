#!/usr/bin/env bash
# Local holder-backed Nord failover, correlation, durable admission
# (quarantine persistence across a hot swap, drain, fail-closed, single
# recovery trial: failed then sustained) and no-direct proof.
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
admission_key() { printf 'irc:egress:admission:%s' "$1"; }
redis() { docker exec ircfiber-redis redis-cli --raw "$@"; }
admission() { redis get "$(admission_key "$1")"; }
# The engine's own published verdict (its snapshotter reads the store).
published_state() {
    local key
    key=$(redis --scan --pattern 'irc:egress:slots:*' | head -n 1)
    [[ -n "$key" ]] && redis hget "$key" "$1" | jq -r '.admission.state'
}
clear_admission() { redis del "$(admission_key north)" "$(admission_key south)" >/dev/null 2>&1 || true; }
cleanup() {
    for id in "$ID_A" "$ID_B"; do
        if [[ -n "$id" ]]; then curl -s -b "$JAR" -X DELETE "$GATEWAY/api/networks/$id" -o /dev/null || true; fi
    done
    clear_admission
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
clear_admission

curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/register" \
    -d "username=$USER" -d "email=$USER@local.test" -d "password=$PASS" -L -o /dev/null || true
curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/login" \
    -d "username=$USER" -d "password=$PASS" -L -o /dev/null
curl -fsS -b "$JAR" "$GATEWAY/api/networks" | jq -e 'type == "array"' >/dev/null || fail 'login failed'

START_MS=$(date +%s000)
START=$(mark)
create() {
    local response
    response=$(api POST /api/networks "{\"name\":\"$1\",\"host\":\"$2\",\"port\":16668,\"tls\":\"disabled\",\"nick\":\"egresstest\",\"realName\":\"Egress test\",\"routing\":{\"order\":[\"nordvpn\"],\"preferredExit\":\"\"},\"autoJoinChannels\":[]}")
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
            and .ts >= $start and (.text | contains("VPN exit north quarantined: excluded from new connections"))
            and (.text | contains("2 distinct IRC hosts"))
            and (.text | contains("5-minute minimum cooldown, then one verified recovery session")))] | length'
}
wait_for 10 'north #staff outbox notice' '[[ "$(alert_count)" == 1 ]]'
[[ "$(entries | jq -r 'select(.tag.egressLabel == "") | .id' | wc -l | tr -d ' ')" == 0 ]] || fail 'direct holder socket during failover'
if since "$DROP" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial during failover'
fi
printf 'PASS: one north quarantine; both networks re-registered through south\n'

# ── Durable admission ──────────────────────────────────────────────────────
admission north | jq -e '.open == true and .failures == 1 and .endpoint == "egress-a:1080"' >/dev/null ||
    fail "north quarantine not persisted: $(admission north)"
wait_for 30 'north published as quarantined' '[[ "$(published_state north)" == quarantined ]]'

# The quarantine survives an engine hot swap; nothing dials north afterwards.
QUARANTINE=$(admission north)
SWAP=$(mark)
dc restart ircfiber-engine >/dev/null
wait_for 120 'both sessions reattached' '[[ "$(since "$SWAP" | grep "\"event\":\"attached\"" | grep -cE "\"network\":\"($NAME_A|$NAME_B)\"")" -ge 2 ]]'
wait_for 30 'north still published as quarantined' '[[ "$(published_state north)" == quarantined ]]'
[[ "$(admission north)" == "$QUARANTINE" ]] || fail 'hot swap changed the north quarantine record'
printf 'PASS: north quarantine survived the hot swap\n'

# Drain south (fixture writes the v1 record; the engine must publish it as
# `draining`, which proves it parsed it). Live sockets on south stay up.
drain_south() {
    redis set "$(admission_key south)" "$(jq -nc --argjson now "$(date +%s000)" '{v:1,
        endpoint:"egress-b:1080",draining:true,drainReason:"e2e drain",open:false,retryAtMs:0,
        failures:0,circuitReason:"",trialToken:"",trialUntilMs:0,trialRegisteredAtMs:0,gen:1,
        updatedAtMs:$now}')" >/dev/null
}
south_ids() { entries | jq -r 'select(.state == "open" and .tag.egressLabel == "south") | .id' | sort | tr '\n' ' '; }
BEFORE_DRAIN=$(south_ids)
drain_south
wait_for 30 'south published as draining' '[[ "$(published_state south)" == draining ]]'
sleep 15
[[ "$(south_ids)" == "$BEFORE_DRAIN" ]] || fail "drain disturbed live south sockets: $BEFORE_DRAIN -> $(south_ids)"
printf 'PASS: south drained; its live sockets were not touched\n'

# Every exit refused (north quarantined, south drained): fail closed, no dial.
connects() { docker logs "$1" 2>&1 | grep -c '^CONNECT' || true; }
BLOCKED=$(mark)
NORTH_CONNECTS=$(connects egress-a)
docker kill --signal=USR1 egress-b >/dev/null
wait_for 180 'admission fail-closed error' 'since "$BLOCKED" | grep -q "No healthy NordVPN exit available.*not admitting new connections"'
wait_for 120 'reconnect backoff' 'since "$BLOCKED" | grep -q "\"event\":\"reconnect_scheduled\""'
[[ "$(connects egress-a)" == "$NORTH_CONNECTS" ]] || fail 'quarantined north was dialed'
[[ "$(entries | jq -r 'select(.state == "open") | .id' | wc -l | tr -d ' ')" == 0 ]] || fail 'a socket opened while every exit was refused'
if since "$BLOCKED" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial while every exit was refused'
fi
printf 'PASS: quarantined + drained exits refused; reconnecting with backoff and no direct dial\n'

# Recovery: the cooldown is fast-forwarded on the record (fixture only).
fast_forward_north() {
    local rec
    rec=$(admission north | jq -c --argjson now "$(date +%s000)" '.retryAtMs = ($now - 1000)')
    redis set "$(admission_key north)" "$rec" >/dev/null
}
claims() { since "$1" | grep '"event":"egress_trial_claimed"' | grep -c '"label":"north"' || true; }
settled() { since "$1" | grep '"event":"egress_trial_settled"' | grep '"label":"north"' | grep "\"outcome\":\"$2\"" | grep -c '"result":"ok"' || true; }
registered_via_north() { entries | jq -r 'select(.state == "open" and .tag.egressLabel == "north") | .tag.networkId' | sort -u | wc -l | tr -d ' '; }

# A trial session lost before 60 s registered fails: next cooldown 10 min.
dc up -d --force-recreate egress-a >/dev/null
wait_for 30 'fresh north SOCKS listener' 'docker logs egress-a 2>&1 | grep -q "SOCKS exit listening"'
TRIAL1=$(mark)
fast_forward_north
wait_for 30 'north published as recovering' '[[ "$(published_state north)" == recovering ]]'
wait_for 150 'one north trial session registered' '[[ "$(registered_via_north)" == 1 ]]'
[[ "$(claims "$TRIAL1")" == 1 ]] || fail "expected exactly one north trial claim, got $(claims "$TRIAL1")"
docker kill --signal=USR1 egress-a >/dev/null
wait_for 60 'failed trial settled' '[[ "$(settled "$TRIAL1" failure)" == 1 ]]'
admission north | jq -e '.open == true and .failures == 2 and .trialToken == ""
    and (.retryAtMs - .updatedAtMs) == 600000' >/dev/null || fail "failed trial cooldown wrong: $(admission north)"
[[ "$(published_state north)" != healthy ]] || fail 'north healthy after a failed trial'
printf 'PASS: one trial at a time; a trial lost before 60s reopens north for 10 minutes\n'

# A trial whose path goes silent (SIGUSR2 blackhole: sockets open, bytes
# dropped) before 60 s never heals north: registered uptime alone is not
# proof; only an answered post-window keepalive is.
published_failures() {
    local key
    key=$(redis --scan --pattern 'irc:egress:slots:*' | head -n 1)
    redis hget "$key" north | jq -r '.admission.failures'
}
dc up -d --force-recreate egress-a >/dev/null
wait_for 30 'fresh north SOCKS listener' 'docker logs egress-a 2>&1 | grep -q "SOCKS exit listening"'
TRIALB=$(mark)
FAILS_BEFORE=$(admission north | jq -r '.failures')
fast_forward_north
wait_for 150 'one north trial session registered' '[[ "$(registered_via_north)" == 1 ]]'
docker kill --signal=USR2 egress-a >/dev/null
wait_for 300 'silent trial counted as failed' '[[ "$(published_state north)" == quarantined && "$(published_failures)" -gt "$FAILS_BEFORE" ]]'
[[ "$(settled "$TRIALB" success)" == 0 ]] || fail 'a silent trial path healed north'
[[ "$(claims "$TRIALB")" == 1 ]] || fail "expected exactly one north trial claim, got $(claims "$TRIALB")"
printf 'PASS: a trial path that went silent before 60s was never healed and backed off\n'

# A trial session registered for 60 s that then answers a keepalive closes
# the circuit; then both networks use north.
dc up -d --force-recreate egress-a >/dev/null
wait_for 30 'fresh north SOCKS listener' 'docker logs egress-a 2>&1 | grep -q "SOCKS exit listening"'
wait_for 180 'silent north session gone' '[[ "$(registered_via_north)" == 0 ]]'
TRIAL2=$(mark)
fast_forward_north
wait_for 150 'one north trial session registered' '[[ "$(registered_via_north)" == 1 ]]'
wait_for 150 'sustained trial settled' '[[ "$(settled "$TRIAL2" success)" == 1 ]]'
[[ "$(claims "$TRIAL2")" == 1 ]] || fail "expected exactly one north trial claim, got $(claims "$TRIAL2")"
admission north | jq -e '.open == false and .failures == 0' >/dev/null || fail "north not healed: $(admission north)"
wait_for 30 'north published as healthy' '[[ "$(published_state north)" == healthy ]]'
wait_for 180 'both networks registered via north' '[[ "$(registered_via_north)" == 2 ]]'
[[ "$(published_state south)" == draining ]] || fail 'the north trial changed the south drain'
if since "$TRIAL1" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial during recovery'
fi
printf 'PASS: sustained 60s trial healed north; both networks back on north, south still drained, no direct\n'
