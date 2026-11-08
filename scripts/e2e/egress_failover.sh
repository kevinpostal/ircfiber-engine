#!/usr/bin/env bash
# Local holder-backed Nord failover, correlation, durable admission
# (quarantine persistence across a hot swap, drain, fail-closed, failed/silent
# and sustained recovery, best-effort staff notices) and no-direct proof.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [[ "${ROUTING_REGRESSION_READY:-0}" != 1 ]]; then
    exec bash "$SCRIPT_DIR/routing_regression.sh" egress_failover "$@"
fi
: "${COMPOSE_FILE:?isolated wrapper must supply COMPOSE_FILE}"
: "${COMPOSE_PROJECT_NAME:?isolated wrapper must supply COMPOSE_PROJECT_NAME}"
: "${DOCKER_CONTEXT:?isolated wrapper must supply DOCKER_CONTEXT}"
: "${ROUTING_REGRESSION_RUN:?isolated wrapper must supply ROUTING_REGRESSION_RUN}"
[[ "$COMPOSE_FILE" == "$SCRIPT_DIR/fixtures/docker-compose.routing-regression.yml" ]] ||
    { printf 'FAIL: refusing a non-regression Compose file\n' >&2; exit 1; }
export DOCKER_CONTEXT
GATEWAY=${GATEWAY_URL:-http://127.0.0.1:18091}
USER=${EGRESS_TEST_USER:-egressfailover}
PASS=${EGRESS_TEST_PASS:-egressfailover123}
JAR=$(mktemp /tmp/egress-failover-XXXXXX.cookies)
NAME_A="EgressAlpha_$(date +%s)"
NAME_B="EgressBeta_$(date +%s)"
ID_A= ID_B=

dk() { docker --context "$DOCKER_CONTEXT" "$@"; }
dc() { dk compose --project-name "$COMPOSE_PROJECT_NAME" -f "$COMPOSE_FILE" "$@"; }
container() {
    local id
    id=$(dc ps -q "$1")
    [[ -n "$id" && "$id" != *$'\n'* ]] || fail "expected one running fixture service: $1"
    [[ "$(dk inspect -f '{{index .Config.Labels "ircfiber.fixture.run"}}' "$id")" == "$ROUTING_REGRESSION_RUN" &&
       "$(dk inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$id")" == "$COMPOSE_PROJECT_NAME" ]] ||
        fail "service $1 is not owned by this regression run"
    printf '%s' "$id"
}
service_logs() { dk logs "$(container "$1")" 2>&1; }
logs() { service_logs ircfiber-engine; }
mark() { logs | wc -l | tr -d ' '; }
since() { logs | tail -n +"$(( $1 + 1 ))"; }
holder_list() { dk exec "$(container ircfiber-holder)" /app/irc-fiber-holder --list; }
entries() { holder_list | jq -c --arg a "$ID_A" --arg b "$ID_B" '.connections[] | select(.tag.networkId == $a or .tag.networkId == $b)'; }
http() { python3 "$SCRIPT_DIR/fixtures/fixture_http.py" "$JAR" "$GATEWAY" "$@"; }
api() { http "$1" "$2" "${3:-}"; }
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
redis() { dk exec "$(container redis)" redis-cli --raw "$@"; }
admission() { redis get "$(admission_key "$1")"; }
recovery_events() {
    redis lrange irc:logs:outbox 0 -1 |
        jq -cs '[.[] | select(.type == "notice" and .actor == "engine" and .kind == "egress_recovery")]'
}
recovery_count() { recovery_events | jq -r 'length'; }
north_sessions() {
    entries | jq -r 'select(.state == "open" and .tag.egressLabel == "north") | "\(.id) \(.connectedAtMs)"' | sort
}
trial_registered() {
    admission north | jq -e '.open == true and .trialToken != "" and .trialRegisteredAtMs > 0'
}
trial_nick() {
    case "$(entries | jq -r 'select(.state == "open" and .tag.egressLabel == "north") | .tag.networkId')" in
        "$ID_A") printf egresstestA;;
        "$ID_B") printf egresstestB;;
        *) fail 'expected exactly one identifiable north trial socket';;
    esac
}
inject_pongs() {
    local nick=$1 token=$2 count=$3
    # Opt-in, per-nick files deliver on the actual upstream socket, never an
    # engine hook; atomic rename prevents a partial IRC line being consumed.
    dk exec "$(container mock-irc)" python3 -c '
import os, pathlib, sys
nick, token, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
assert nick in ("egresstestA", "egresstestB") and token.startswith("LAG") and token[3:].isdigit()
path = pathlib.Path("/tmp/mock-irc.inject.target." + nick)
tmp = path.with_suffix(path.suffix + ".tmp")
tmp.write_bytes(("PONG :" + token + "\r\n").encode() * count)
os.replace(tmp, path)
' "$nick" "$token" "$count"
    wait_for 10 'targeted upstream PONG injection consumed' \
        '! dk exec "$(container mock-irc)" test -e "/tmp/mock-irc.inject.target.$nick"'
}
pong_count() {
    since "$1" | grep '"event":"pong_received"' | grep -F "\"network\":\"$2\"" | wc -l | tr -d ' '
}
recovery_ping() {
    # Observe only the actual trial socket. Engine notice timestamps have
    # second precision, so include the complete enqueue second.
    dk exec "$(container mock-irc)" python3 -c '
import pathlib, sys
start, end = map(int, sys.argv[1:3])
nick = sys.argv[3]
tokens = {line[6:] for line in pathlib.Path("/tmp/mock-irc.lines.target." + nick).read_text().splitlines()
          if line.startswith("PING :LAG") and line[9:].isdigit()
          and start + 60000 <= int(line[9:]) < end + 1000}
assert len(tokens) == 1, ("expected one successful post-window trial PING", tokens)
print(next(iter(tokens)))
' "$1" "$2" "$3"
}
restore_outbox() {
    [[ -n "${OUTBOX_BACKUP:-}" ]] || return 0
    redis eval '
if redis.call("TYPE", KEYS[1]).ok ~= "string" or redis.call("GET", KEYS[1]) ~= ARGV[1]
    or redis.call("TYPE", KEYS[2]).ok ~= "list" then
    return redis.error_reply("fixture outbox sentinel or backup changed")
end
redis.call("DEL", KEYS[1])
redis.call("RENAME", KEYS[2], KEYS[1])
return 1' 2 irc:logs:outbox "$OUTBOX_BACKUP" "$OUTBOX_SENTINEL" | grep -qx 1 ||
        fail 'could not restore the owned fixture outbox'
    OUTBOX_BACKUP=
}
# The engine's own published verdict (its snapshotter reads the store).
published_state() {
    local key
    key=$(redis --scan --pattern 'irc:egress:slots:*' | head -n 1)
    [[ -n "$key" ]] && redis hget "$key" "$1" | jq -r '.admission.state'
}
cleanup() {
    local status=$?
    if [[ $status -ne 0 ]]; then
        holder_list >&2 || true
        admission north >&2 || true
        admission south >&2 || true
        for id in "$ID_A" "$ID_B"; do
            if [[ -n "$id" ]]; then
                printf 'FINAL NETWORK STATE %s\n' "$id" >&2
                redis hget "irc:state:$ENGINE_SERVER_ID:$id" data >&2 || true
            fi
        done
    fi
    if [[ -n "${OUTBOX_BACKUP:-}" ]]; then restore_outbox || true; fi
    for id in "$ID_A" "$ID_B"; do
        if [[ -n "$id" ]]; then api DELETE "/api/networks/$id" >/dev/null || true; fi
    done
    rm -f "$JAR"
}

if ! [[ "$GATEWAY" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?/?$ ]]; then
    rm -f "$JAR"
    fail 'fixture routing seed requires a loopback GATEWAY_URL'
fi
trap cleanup EXIT

# The wrapper owns fresh builds, baseline startup and policy seeding. Never
# inherit/recreate the user's local stack or relax the fixture policy here.
[[ -z "$(dc ps -q egress-b)" ]] || fail 'south must start down'
wait_for 120 'gateway health' 'curl -fsS "$GATEWAY/health"'
wait_for 60 'holder status' 'dk exec "$(container ircfiber-holder)" /app/irc-fiber-holder --status'
[[ "$(redis get irc:config:routingSchemaVersion)" == 1 ]] ||
    fail 'fixture routing schema is not version 1'
redis get irc:config:egressRoutingPolicy | jq -e '.schema == 1' >/dev/null ||
    fail 'fixture routing policy was not seeded'
ENGINE_SERVER_ID=$(dk exec "$(container ircfiber-engine)" printenv IRCFIBER_SERVER_ID)
[[ -n "$ENGINE_SERVER_ID" ]] || fail 'fixture engine has no explicit server identity'
wait_for 60 'healthy engine registration' \
    '[[ "$(redis hget "irc:server:$ENGINE_SERVER_ID" isHealthy)" == true ]]'
listening() {
    dk exec "$(container "$1")" python3 -c \
        'import socket; socket.create_connection(("127.0.0.1", 1080), 2).close()'
}
signal_exit() { dk kill --signal="$1" "$(container "$2")" >/dev/null; }
wait_for 30 'north SOCKS listener' 'listening egress-a'

http POST /register "username=$USER&email=$USER@local.test&password=$PASS" \
    application/x-www-form-urlencoded >/dev/null
http POST /login "username=$USER&password=$PASS" \
    application/x-www-form-urlencoded >/dev/null
api GET /api/networks | jq -e 'type == "array"' >/dev/null || fail 'login failed'

START=$(mark)
# Seed the deployed engine's legacy contract before it can consume the
# current gateway's routing-only add messages. No production API shim.
dc stop ircfiber-engine >/dev/null
create() {
    local response id config
    response=$(api POST /api/networks "{\"name\":\"$1\",\"host\":\"$2\",\"port\":16668,\"tls\":\"disabled\",\"nick\":\"$3\",\"realName\":\"Egress test\",\"routing\":{\"order\":[\"nordvpn\"],\"preferredExit\":\"\"},\"autoJoinChannels\":[]}")
    id=$(jq -er '.id // .networkId' <<<"$response") || fail "create failed: $response"
    config=$(dk exec "$(container mongo)" mongosh --quiet ircfiber_regression_fixture --eval \
        "const q={id:'$id'}; db.networks.updateOne(q,{\$set:{disabled:false,egressNodeId:'nordvpn'}}); print(JSON.stringify(db.networks.findOne(q)));")
    redis del "irc:user-networks:$(jq -er '.userId' <<<"$config")" >/dev/null
    printf '%s' "$id"
}
ID_A=$(create "$NAME_A" alpha.example.org egresstestA)
ID_B=$(create "$NAME_B" beta.example.net egresstestB)
# This queue belongs exclusively to the disposable fixture. Boot reconciliation
# reloads the persisted rows, rather than stale current-gateway config envelopes.
redis del "irc:control:$ENGINE_SERVER_ID" >/dev/null
dc start ircfiber-engine >/dev/null
registered_both() {
    local recent
    recent=$(since "$1" | grep '"event":"register_complete"' || true)
    grep -F "\"network\":\"$NAME_A\"" <<<"$recent" >/dev/null &&
        grep -F "\"network\":\"$NAME_B\"" <<<"$recent" >/dev/null
}
wait_for 180 'both networks registered via north' '[[ "$(entries | jq -r "select(.state == \"open\" and .tag.egressLabel == \"north\") | .tag.networkId" | sort -u | wc -l | tr -d " ")" == 2 ]]'
wait_for 60 'both registration events' 'registered_both "$START"'
for id in "$ID_A" "$ID_B"; do
    redis hget "irc:state:$ENGINE_SERVER_ID:$id" data |
        jq -e '.config.egressNodeId == "nordvpn"' >/dev/null ||
        fail 'deployed legacy engine did not retain its fixture-only VPN tier pin'
done
[[ "$(entries | jq -r 'select(.tag.egressLabel == "") | .id' | wc -l | tr -d ' ')" == 0 ]] || fail 'direct holder entry before failover'
printf 'Registered both networks via north; waiting for stable sessions (65s)\n'
sleep 65

dc up -d --no-build --no-deps egress-b
wait_for 30 'south SOCKS listener' 'listening egress-b'
DROP=$(mark)
signal_exit USR1 egress-a
wait_for 180 'both networks re-registered through south' '[[ "$(entries | jq -r "select(.state == \"open\" and .tag.egressLabel == \"south\") | .tag.networkId" | sort -u | wc -l | tr -d " ")" == 2 ]]'
wait_for 30 'two south registration events' 'registered_both "$DROP"'
count=$(since "$DROP" | grep '"event":"egress_quarantined"' | grep -c '"label":"north"' || true)
[[ "$count" == 1 ]] || fail "expected one north quarantine transition, got $count"
[[ "$(entries | jq -r 'select(.tag.egressLabel == "") | .id' | wc -l | tr -d ' ')" == 0 ]] || fail 'direct holder socket during failover'
if since "$DROP" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial during failover'
fi
printf 'PASS: one north quarantine; both networks re-registered through south\n'

# ── Durable admission ──────────────────────────────────────────────────────
admission north | jq -e '.open == true and .failures == 1 and .endpoint == "192.0.2.30:1080"' >/dev/null ||
    fail "north quarantine not persisted: $(admission north)"
wait_for 30 'north published as quarantined' '[[ "$(published_state north)" == quarantined ]]'

# The quarantine survives an engine hot swap; nothing dials north afterwards.
QUARANTINE=$(admission north)
HELD_SOUTH=$(entries | jq -r 'select(.state == "open" and .tag.egressLabel == "south") | "\(.id) \(.connectedAtMs)"' | sort)
SWAP=$(mark)
dc restart ircfiber-engine >/dev/null
wait_for 120 'both sessions reattached' '[[ "$(since "$SWAP" | grep "\"event\":\"attached\"" | grep -cE "\"network\":\"($NAME_A|$NAME_B)\"")" -ge 2 ]]'
[[ "$(entries | jq -r 'select(.state == "open" and .tag.egressLabel == "south") | "\(.id) \(.connectedAtMs)"' | sort)" == "$HELD_SOUTH" ]] ||
    fail 'quarantine hot swap replaced a live south holder session'
wait_for 30 'north still published as quarantined' '[[ "$(published_state north)" == quarantined ]]'
[[ "$(admission north)" == "$QUARANTINE" ]] || fail 'hot swap changed the north quarantine record'
[[ "$(recovery_count)" == 0 ]] || fail 'quarantine hot-swap reattachment announced recovery'
printf 'PASS: north quarantine survived the hot swap\n'

# Drain south (fixture writes the v1 record; the engine must publish it as
# `draining`, which proves it parsed it). Live sockets on south stay up.
drain_south() {
    redis set "$(admission_key south)" "$(jq -nc --argjson now "$(date +%s000)" '{v:1,
        endpoint:"192.0.2.31:1080",draining:true,drainReason:"e2e drain",open:false,retryAtMs:0,
        failures:0,circuitReason:"",trialToken:"",trialUntilMs:0,trialRegisteredAtMs:0,gen:1,
        updatedAtMs:$now}')" >/dev/null
}
south_ids() { entries | jq -r 'select(.state == "open" and .tag.egressLabel == "south") | .id' | sort | tr '\n' ' '; }
BEFORE_DRAIN=$(south_ids)
drain_south
wait_for 30 'south published as draining' '[[ "$(published_state south)" == draining ]]'
SOUTH_DRAIN_RECORD=$(admission south)
sleep 15
[[ "$(south_ids)" == "$BEFORE_DRAIN" ]] || fail "drain disturbed live south sockets: $BEFORE_DRAIN -> $(south_ids)"
printf 'PASS: south drained; its live sockets were not touched\n'

# Every exit refused (north quarantined, south drained): fail closed, no dial.
connects() { service_logs "$1" | grep -c '^CONNECT' || true; }
BLOCKED=$(mark)
NORTH_CONNECTS=$(connects egress-a)
SOUTH_CONNECTS=$(connects egress-b)
signal_exit USR1 egress-b
wait_for 120 'reconnect backoff' 'since "$BLOCKED" | grep -q "\"event\":\"reconnect_scheduled\""'
wait_for 180 'all target sockets closed' '[[ "$(entries | jq -r "select(.state == \"open\") | .id" | wc -l | tr -d " ")" == 0 ]]'
sleep 15
[[ "$(connects egress-a)" == "$NORTH_CONNECTS" ]] || fail 'quarantined north was dialed'
[[ "$(connects egress-b)" == "$SOUTH_CONNECTS" ]] || fail 'drained south was dialed'
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
dc up -d --no-build --no-deps --force-recreate egress-a >/dev/null
wait_for 30 'fresh north SOCKS listener' 'listening egress-a'
TRIAL1=$(mark)
fast_forward_north
wait_for 30 'north published as recovering' '[[ "$(published_state north)" == recovering ]]'
wait_for 150 'one north trial session registered' '[[ "$(registered_via_north)" == 1 ]]'
[[ "$(claims "$TRIAL1")" == 1 ]] || fail "expected exactly one north trial claim, got $(claims "$TRIAL1")"
signal_exit USR1 egress-a
wait_for 60 'failed trial settled' '[[ "$(settled "$TRIAL1" failure)" == 1 ]]'
admission north | jq -e '.open == true and .failures == 2 and .trialToken == ""
    and (.retryAtMs - .updatedAtMs) == 600000' >/dev/null || fail "failed trial cooldown wrong: $(admission north)"
[[ "$(published_state north)" != healthy ]] || fail 'north healthy after a failed trial'
[[ "$(recovery_count)" == 0 ]] || fail 'failed trial announced recovery'
printf 'PASS: one trial at a time; a trial lost before 60s reopens north for 10 minutes\n'

# A trial whose path goes silent (SIGUSR2 blackhole: sockets open, bytes
# dropped) before 60 s never heals north: registered uptime alone is not
# proof; only an answered post-window keepalive is.
published_failures() {
    local key
    key=$(redis --scan --pattern 'irc:egress:slots:*' | head -n 1)
    redis hget "$key" north | jq -r '.admission.failures'
}
dc up -d --no-build --no-deps --force-recreate egress-a >/dev/null
wait_for 30 'fresh north SOCKS listener' 'listening egress-a'
TRIALB=$(mark)
FAILS_BEFORE=$(admission north | jq -r '.failures')
fast_forward_north
wait_for 150 'one north trial session registered' '[[ "$(registered_via_north)" == 1 ]]'
signal_exit USR2 egress-a
wait_for 300 'silent trial counted as failed' '[[ "$(published_state north)" == quarantined && "$(published_failures)" -gt "$FAILS_BEFORE" ]]'
[[ "$(settled "$TRIALB" success)" == 0 ]] || fail 'a silent trial path healed north'
[[ "$(claims "$TRIALB")" == 1 ]] || fail "expected exactly one north trial claim, got $(claims "$TRIALB")"
[[ "$(recovery_count)" == 0 ]] || fail 'silent trial announced recovery'
printf 'PASS: a trial path that went silent before 60s was never healed and backed off\n'

# A trial session registered for 60 s that then answers a keepalive closes
# the circuit; then both networks use north.
dc up -d --no-build --no-deps --force-recreate egress-a >/dev/null
wait_for 30 'fresh north SOCKS listener' 'listening egress-a'
wait_for 180 'silent north session gone' '[[ "$(registered_via_north)" == 0 ]]'
TRIAL2=$(mark)
fast_forward_north
wait_for 150 'one north trial session registered' '[[ "$(registered_via_north)" == 1 ]]'
wait_for 10 'north trial registration persisted' 'trial_registered'
TRIAL2_REGISTERED=$(admission north | jq -r '.trialRegisteredAtMs')
TRIAL2_SOCKET=$(north_sessions)
TRIAL2_NICK=$(trial_nick)
if [[ "$TRIAL2_NICK" == egresstestA ]]; then TRIAL2_NAME=$NAME_A; else TRIAL2_NAME=$NAME_B; fi
EARLY_PONG=$(mark)
inject_pongs "$TRIAL2_NICK" LAG1 2
wait_for 10 'foreign PONGs received on trial wire' '[[ "$(pong_count "$EARLY_PONG" "$TRIAL2_NAME")" -ge 2 ]]'
sleep 10
[[ "$(recovery_count)" == 0 ]] || fail 'trial announced recovery before its sustain window'

# Reattach the live trial before the real sustain deadline. This must retain
# its original registration mark and token, not heal merely by restoring META.
TRIAL2_RECORD=$(admission north | jq -c '{endpoint,draining,open,failures,trialToken,trialRegisteredAtMs,gen}')
TRIAL_SWAP=$(mark)
dc restart ircfiber-engine >/dev/null
wait_for 25 'trial socket reattached before sustain deadline' \
    'since "$TRIAL_SWAP" | grep "\"event\":\"attached\"" | grep -Fq "\"network\":\"$TRIAL2_NAME\""'
[[ "$(north_sessions)" == "$TRIAL2_SOCKET" ]] || fail 'trial hot swap replaced its held socket'
[[ "$(admission north | jq -c '{endpoint,draining,open,failures,trialToken,trialRegisteredAtMs,gen}')" == "$TRIAL2_RECORD" ]] ||
    fail 'trial hot swap changed admission ownership or sustain clock'
[[ "$(date +%s000)" -lt "$((TRIAL2_REGISTERED + 60000))" ]] ||
    fail 'trial reattachment did not complete before the sustain deadline'
[[ "$(recovery_count)" == 0 ]] || fail 'trial hot-swap reattachment announced recovery'
wait_for 150 'sustained trial settled' '[[ "$(settled "$TRIAL2" success)" == 1 ]]'
[[ "$(claims "$TRIAL2")" == 1 ]] || fail "expected exactly one north trial claim, got $(claims "$TRIAL2")"
admission north | jq -e '.open == false and .failures == 0' >/dev/null || fail "north not healed: $(admission north)"
wait_for 10 'one verified recovery queued for staff' '[[ "$(recovery_count)" == 1 ]]'
recovery_events | jq -e --argjson registered "$TRIAL2_REGISTERED" \
    --arg user "$USER" --arg a "$ID_A" --arg b "$ID_B" '
    length == 1 and (.[0] |
        .ts >= ($registered + 60000) and
        (.text | startswith("VPN exit north recovered:")) and
        (.text | contains("60 seconds") and contains("post-window keepalive") and contains("admission reopened")) and
        (.text | contains($user) or contains($a) or contains($b) | not) and
        ((keys - ["type", "ts", "actor", "kind", "text"]) | length == 0))' >/dev/null ||
    fail 'recovery payload lacks verified timing/label or includes identity context'
RECOVERY_PING=$(recovery_ping "$TRIAL2_REGISTERED" "$(recovery_events | jq -r '.[0].ts')" "$TRIAL2_NICK")
LATE_PONG=$(mark)
inject_pongs "$TRIAL2_NICK" "$RECOVERY_PING" 8
wait_for 10 'duplicate matching PONGs received on original trial socket' \
    '[[ "$(pong_count "$LATE_PONG" "$TRIAL2_NAME")" -ge 8 ]]'
[[ "$(recovery_count)" == 1 && "$(settled "$TRIAL2" success)" == 1 ]] ||
    fail 'duplicate/late matching PONG repeated recovery settlement or announcement'
entries | jq -r 'select(.state == "open") | "\(.id) \(.connectedAtMs)"' | grep -Fxq "$TRIAL2_SOCKET" ||
    fail 'successful recovery or PONG replay replaced the trial socket'
wait_for 30 'north published as healthy' '[[ "$(published_state north)" == healthy ]]'
# The non-trial peer may already be on the normal 300s reconnect tier.
wait_for 360 'both networks registered via north' '[[ "$(registered_via_north)" == 2 ]]'
[[ "$(published_state south)" == draining ]] || fail 'the north trial changed the south drain'
if since "$TRIAL1" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial during recovery'
fi
printf 'PASS: sustained 60s trial healed north; both networks back on north, south still drained, no direct\n'

# A second genuine two-host loss reopens the circuit. Only its cooldown is
# fast-forwarded; both successful trials must sustain a real registered 60s.
printf 'Waiting for both north sessions to be stable before second quarantine (65s)\n'
sleep 65
DROP2=$(mark)
signal_exit USR1 egress-a
wait_for 180 'second two-host north quarantine' \
    '[[ "$(admission north | jq -r ".open")" == true && "$(north_sessions)" == "" ]]'
[[ "$(since "$DROP2" | grep '"event":"egress_quarantined"' | grep -c '"label":"north"' || true)" == 1 ]] ||
    fail 'second socket loss did not cause exactly one quarantine transition'
[[ "$(recovery_count)" == 1 ]] || fail 'second quarantine announced an unverified recovery'
dc up -d --no-build --no-deps --force-recreate egress-a >/dev/null
wait_for 30 'fresh north listener for second sustained recovery' 'listening egress-a'
TRIAL3=$(mark)
fast_forward_north
wait_for 150 'second sustained trial registered' '[[ "$(registered_via_north)" == 1 ]] && trial_registered'
TRIAL3_REGISTERED=$(admission north | jq -r '.trialRegisteredAtMs')
TRIAL3_SOCKET=$(north_sessions)
ENGINE_BEFORE_FAILURE=$(container ircfiber-engine)
[[ "$(claims "$TRIAL3")" == 1 ]] || fail 'second recovery claimed multiple trials'
[[ "$(recovery_count)" == 1 ]] || fail 'second trial announced before verification'

# Preserve the entire owned list (including the first recovery); the only
# corruption is a fixture string sentinel installed before this settlement.
OUTBOX_SENTINEL="recovery-announcement-failure:$ROUTING_REGRESSION_RUN"
OUTBOX_BACKUP="irc:logs:outbox:fixture:$ROUTING_REGRESSION_RUN"
[[ "$(redis type "$OUTBOX_BACKUP")" == none ]] || fail 'fixture outbox backup already exists'
redis rename irc:logs:outbox "$OUTBOX_BACKUP" | grep -qx OK || fail 'could not preserve fixture outbox'
redis set irc:logs:outbox "$OUTBOX_SENTINEL" | grep -qx OK || fail 'could not install wrong-type fixture outbox'
wait_for 150 'second real sustained recovery despite announcement failure' '[[ "$(settled "$TRIAL3" success)" == 1 ]]'
wait_for 10 'caught recovery announcement error' \
    'since "$TRIAL3" | grep -q "VPN exit recovery #staff announcement failed"'
[[ "$(date +%s000)" -ge "$((TRIAL3_REGISTERED + 60000))" ]] ||
    fail 'second successful recovery skipped the sustain window'
admission north | jq -e '.open == false and .failures == 0 and .trialToken == ""' >/dev/null ||
    fail 'announcement failure undid successful admission or retained trial ownership'
[[ "$(redis type irc:logs:outbox)" == string && "$(redis get irc:logs:outbox)" == "$OUTBOX_SENTINEL" ]] ||
    fail 'announcement failure changed the wrong-type sentinel'
[[ "$(container ircfiber-engine)" == "$ENGINE_BEFORE_FAILURE" ]] || fail 'announcement error stopped/replaced the engine'
entries | jq -r 'select(.state == "open") | "\(.id) \(.connectedAtMs)"' | grep -Fxq "$TRIAL3_SOCKET" ||
    fail 'announcement failure replaced the surviving trial socket'
[[ "$(admission south)" == "$SOUTH_DRAIN_RECORD" ]] || fail 'announcement failure changed unrelated south drain'
restore_outbox
wait_for 30 'north healthy after failed announcement' '[[ "$(published_state north)" == healthy ]]'
wait_for 360 'both networks registered after failed announcement' '[[ "$(registered_via_north)" == 2 ]]'
# Two further real keepalive intervals prove there is no retained completed
# token/retry and that normal IRC processing survives the failed best-effort push.
sleep 65
[[ "$(settled "$TRIAL3" success)" == 1 && "$(claims "$TRIAL3")" == 1 ]] ||
    fail 'completed trial was settled or claimed again after announcement failure'
[[ "$(since "$TRIAL3" | grep -c 'VPN exit recovery #staff announcement failed' || true)" == 1 ]] ||
    fail 'recovery announcement failure was retried'
[[ "$(recovery_count)" == 1 ]] || fail 'failed recovery announcement was replayed after outbox restoration'
entries | jq -r 'select(.state == "open") | "\(.id) \(.connectedAtMs)"' | grep -Fxq "$TRIAL3_SOCKET" ||
    fail 'trial socket did not survive subsequent keepalives'
[[ "$(admission south)" == "$SOUTH_DRAIN_RECORD" ]] || fail 'second recovery changed unrelated drain state'
if since "$TRIAL1" | grep '"event":"tcp_open"' | grep -E '"host":"(alpha.example.org|beta.example.net)"' | grep -q '"egress":"direct"'; then
    fail 'direct TCP dial during either recovery cycle'
fi
printf 'PASS: second sustained recovery survived wrong-type staff outbox; admission, engine, trial socket and south drain intact; no retry\n'
