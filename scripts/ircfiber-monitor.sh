#!/bin/bash
# IRC Fiber enterprise monitor — 99.9% SLA hardened
set -uo pipefail
LOG=/var/log/ircfiber/monitor.log
REDIS_DOCKER=ircfiber-redis
GATEWAY=ircfiber-gateway
ENGINE=ircfiber-engine-ovh
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LOCK=/tmp/ircfiber-monitor.lock
COOLDOWN_ENGINE=/tmp/ircfiber-monitor-engine-cooldown
COOLDOWN_GATEWAY=/tmp/ircfiber-monitor-gateway-cooldown
FAIL=0
REASON=""
exec 9>"$LOCK" 2>/dev/null || exec 9>/tmp/ircfiber-monitor.lock
flock -n 9 || { echo "[$TIMESTAMP] SKIP overlapping run" | logger -t ircfiber-monitor; exit 0; }
mkdir -p /var/log/ircfiber 2>/dev/null || true
touch "$LOG" 2>/dev/null || true
chown deploy:deploy /var/log/ircfiber 2>/dev/null || true
chown deploy:deploy "$LOG" 2>/dev/null || true
chmod 664 "$LOG" 2>/dev/null || true
retry_redis_hlen() {
  local hlen=""
  for i in 1 2 3; do
    hlen=$(docker exec $REDIS_DOCKER redis-cli --raw hlen "irc:assignments" 2>&1 | tr -d "\r" | head -n1)
    if [[ "$hlen" =~ ^[0-9]+$ ]]; then echo "$hlen"; return 0; fi
    sleep 1
  done
  echo "$hlen"
}
api_ok=0
for i in 1 2; do if docker exec $GATEWAY curl --max-time 4 -s http://127.0.0.1:8090/api/version 2>&1 | grep -q "engines"; then api_ok=1; break; fi; sleep 2; done
if [ $api_ok -eq 0 ]; then FAIL=1; REASON="${REASON} api_version_fail"; fi
servers_ok=0
for i in 1 2; do if docker exec $REDIS_DOCKER redis-cli --raw smembers "irc:servers" 2>&1 | grep -q "ovh"; then servers_ok=1; break; fi; sleep 1; done
if [ $servers_ok -eq 0 ]; then FAIL=1; REASON="${REASON} redis_servers_empty"; fi
HLEN=$(retry_redis_hlen)
if ! [[ "$HLEN" =~ ^[0-9]+$ ]]; then HLEN=""; fi
HB=$(docker exec $REDIS_DOCKER redis-cli --raw hget "irc:server:ovh" "lastHeartbeat" 2>&1 | tr -d "\r" | head -n1)
AGE_S=""
if [[ "$HB" =~ ^[0-9]+$ ]] && [ "$HB" -gt 0 ] 2>/dev/null; then NOW=$(date +%s000); AGE_MS=$((NOW - HB)); AGE_S=$((AGE_MS / 1000)); if [ "$AGE_S" -gt 90 ]; then FAIL=1; REASON="${REASON} heartbeat_stale_${AGE_S}s"; fi; else FAIL=1; REASON="${REASON} heartbeat_missing"; AGE_S="?"; fi
if [ -z "$HLEN" ] || [ "$HLEN" -eq 0 ] 2>/dev/null; then if [[ "$AGE_S" =~ ^[0-9]+$ ]] && [ "$AGE_S" -lt 60 ]; then echo "[$TIMESTAMP] WARN assignments_empty but heartbeat fresh ${AGE_S}s — not restarting engine (transient)" | tee -a "$LOG" 2>/dev/null || logger -t ircfiber-monitor "WARN assignments_empty hb_age=${AGE_S}s hlen=$HLEN"; else FAIL=1; REASON="${REASON} assignments_empty"; fi; fi
FD=""; GW_PID=$(docker exec $GATEWAY sh -c "pidof irc-fiber 2>/dev/null || pgrep -f irc-fiber 2>/dev/null | head -n1" 2>&1 | tr -d "\r" | xargs)
if [ -n "$GW_PID" ] && [[ "$GW_PID" =~ ^[0-9]+$ ]]; then FD=$(docker exec $GATEWAY sh -c "ls /proc/$GW_PID/fd 2>&1 | wc -l" 2>&1 | tr -d "\r" | xargs); else FD=$(docker exec $GATEWAY sh -c "ls /proc/1/fd 2>&1 | wc -l" 2>&1 | tr -d "\r" | xargs); fi
if [ -n "$FD" ] && [[ "$FD" =~ ^[0-9]+$ ]] && [ "$FD" -gt 900 ] 2>/dev/null; then FAIL=1; REASON="${REASON} fd_high_${FD}"; fi
if docker logs --tail 100 $GATEWAY 2>&1 | grep -q "Too many open files"; then FAIL=1; REASON="${REASON} too_many_open_files"; fi
if ! curl --max-time 5 -k --resolve ircfiber.com:443:127.0.0.1 -s https://ircfiber.com/api/version 2>&1 | grep -q "engines"; then sleep 2; if ! curl --max-time 5 -k --resolve ircfiber.com:443:127.0.0.1 -s https://ircfiber.com/api/version 2>&1 | grep -q "engines"; then FAIL=1; REASON="${REASON} caddy_api_fail"; fi; fi
if [ $FAIL -eq 1 ]; then echo "[$TIMESTAMP] FAIL $REASON hlen=${HLEN:-?} hb=${HB:-?} age=${AGE_S:-?}s fd=${FD:-?}" | tee -a "$LOG" 2>/dev/null || true; logger -t ircfiber-monitor "FAIL $REASON hlen=${HLEN:-?} hb=${HB:-?} age=${AGE_S:-?}s fd=${FD:-?}"; if echo "$REASON" | grep -qE "assignments_empty|heartbeat_stale|heartbeat_missing|redis_servers_empty"; then if [ -f "$COOLDOWN_ENGINE" ] && [ $(($(date +%s) - $(stat -c %Y "$COOLDOWN_ENGINE" 2>/dev/null || echo 0))) -lt 600 ]; then echo "[$TIMESTAMP] SKIP engine restart — cooldown active" | tee -a "$LOG" 2>/dev/null || true; else echo "[$TIMESTAMP] AUTO-RESTART engine $ENGINE due to $REASON" | tee -a "$LOG" 2>/dev/null || true; touch "$COOLDOWN_ENGINE"; docker restart $ENGINE 2>&1 | tee -a "$LOG" 2>/dev/null || true; sleep 8; fi; fi; if echo "$REASON" | grep -qE "api_version_fail|caddy_api_fail|too_many_open_files|fd_high"; then sleep 3; if ! docker exec $GATEWAY curl --max-time 4 -s http://127.0.0.1:8090/api/version 2>&1 | grep -q "engines"; then if [ -f "$COOLDOWN_GATEWAY" ] && [ $(($(date +%s) - $(stat -c %Y "$COOLDOWN_GATEWAY" 2>/dev/null || echo 0))) -lt 600 ]; then echo "[$TIMESTAMP] SKIP gateway restart — cooldown active" | tee -a "$LOG" 2>/dev/null || true; else echo "[$TIMESTAMP] AUTO-RESTART gateway $GATEWAY due to $REASON" | tee -a "$LOG" 2>/dev/null || true; touch "$COOLDOWN_GATEWAY"; docker restart $GATEWAY 2>&1 | tee -a "$LOG" 2>/dev/null || true; fi; else echo "[$TIMESTAMP] Gateway api recovered after wait — not restarting (fd_high was transient)" | tee -a "$LOG" 2>/dev/null || true; fi; fi; logger -t ircfiber-monitor "FAIL $REASON"; exit 1; else echo "[$TIMESTAMP] OK hlen=$HLEN hb_age=${AGE_S:-?}s fd=${FD:-?}" >> "$LOG" 2>/dev/null || true; exit 0; fi
