#!/bin/bash
# IRC Fiber enterprise monitor — 99.9% SLA hardened
# v2: mirror-aware assignments_empty, strike-based, auto-heal from per-engine mirrors.
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
STALE_STATE=/tmp/ircfiber-monitor-engine-stale
STALE_THRESHOLD_S=120
STALE_STRIKES=3
ASSIGN_STALE_STATE=/tmp/ircfiber-monitor-assignments-stale
ASSIGN_STRIKES=3
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
# Sum HLEN of all per-engine assignment mirrors (irc:server-assignments:*).
# If canonical is evicted (allkeys-lru) but mirrors survive, this returns >0
# and we can auto-heal without killing the engine.
mirror_hlen() {
  local total=0
  local keys
  # SCAN for mirrors; use redis-cli --scan if available, else KEYS (small set)
  keys=$(docker exec $REDIS_DOCKER redis-cli --raw keys "irc:server-assignments:*" 2>&1 | tr -d "\r")
  if [ -z "$keys" ]; then echo "0"; return 0; fi
  while IFS= read -r k; do
    [ -z "$k" ] && continue
    local hl
    hl=$(docker exec $REDIS_DOCKER redis-cli --raw hlen "$k" 2>&1 | tr -d "\r" | head -n1)
    if [[ "$hl" =~ ^[0-9]+$ ]]; then total=$((total + hl)); fi
  done <<< "$keys"
  echo "$total"
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
STRIKES=0
if [[ "$HB" =~ ^[0-9]+$ ]] && [ "$HB" -gt 0 ] 2>/dev/null; then
  NOW=$(date +%s000); AGE_MS=$((NOW - HB)); AGE_S=$((AGE_MS / 1000))
  if [ "$AGE_S" -gt "$STALE_THRESHOLD_S" ]; then
    STRIKES=$(cat "$STALE_STATE" 2>/dev/null | tr -cd '0-9'); [ -z "$STRIKES" ] && STRIKES=0
    STRIKES=$((STRIKES + 1)); echo "$STRIKES" > "$STALE_STATE"
    if [ "$STRIKES" -ge "$STALE_STRIKES" ]; then
      FAIL=1; REASON="${REASON} heartbeat_stale_${AGE_S}s_x${STRIKES}"
    else
      logger -t ircfiber-monitor "WARN heartbeat_stale ${AGE_S}s strike=${STRIKES}/${STALE_STRIKES} (deferring restart)"
    fi
  else
    rm -f "$STALE_STATE" 2>/dev/null || true
  fi
else
  STRIKES=$(cat "$STALE_STATE" 2>/dev/null | tr -cd '0-9'); [ -z "$STRIKES" ] && STRIKES=0
  STRIKES=$((STRIKES + 1)); echo "$STRIKES" > "$STALE_STATE"
  if [ "$STRIKES" -ge "$STALE_STRIKES" ]; then
    FAIL=1; REASON="${REASON} heartbeat_missing_x${STRIKES}"; AGE_S="?"
  else
    logger -t ircfiber-monitor "WARN heartbeat_missing strike=${STRIKES}/${STALE_STRIKES} (deferring restart)"
  fi
fi
# ── Enterprise assignments_empty: mirror-aware, strike-based, auto-heal ──
# Old logic: HLEN==0 && AGE_S>=60 => immediate FAIL (killed engine on transient LRU eviction).
# New: require mirrors also empty AND sustained strikes. If mirrors have data, canonical was
# evicted — the engine's heartbeat (bootstrap.d:508) already repopulates from mirrors/local,
# so monitor should heal, not kill.
if [ -z "$HLEN" ] || [ "$HLEN" -eq 0 ] 2>/dev/null; then
  # Heartbeat fresh (<60s): this is almost certainly transient (deploy, LRU blip) — defer.
  if [[ "$AGE_S" =~ ^[0-9]+$ ]] && [ "$AGE_S" -lt 60 ]; then
    echo "[$TIMESTAMP] WARN assignments_empty but heartbeat fresh ${AGE_S}s — not restarting engine (transient)" | tee -a "$LOG" 2>/dev/null || logger -t ircfiber-monitor "WARN assignments_empty hb_age=${AGE_S}s hlen=$HLEN mirror_check=deferred"
    rm -f "$ASSIGN_STALE_STATE" 2>/dev/null || true
  else
    # Check mirrors before declaring empty. This is the key enterprise fix:
    # `irc:assignments` is allkeys-lru-evirable (until redis.conf changes to volatile-lru),
    # but `irc:server-assignments:*` mirrors are the recovery source.
    MHLEN=$(mirror_hlen)
    if [[ "$MHLEN" =~ ^[0-9]+$ ]] && [ "$MHLEN" -gt 0 ]; then
      # Canonical empty but mirrors have data — auto-heal attempt, do NOT fail.
      # Try to copy first mirror's fields back to canonical so next tick sees HLEN>0.
      # Best-effort; engine will also repopulate on next heartbeat, so failure here is non-fatal.
      echo "[$TIMESTAMP] WARN assignments_empty canonical=0 but mirror has ${MHLEN} entries — eviction suspected, attempting heal (not restarting)" | tee -a "$LOG" 2>/dev/null || true
      logger -t ircfiber-monitor "WARN assignments_empty canonical_empty mirror=${MHLEN} age=${AGE_S}s — auto-heal attempt (no restart)"
      # Attempt heal: pick first mirror key and repopulate canonical via Lua/script
      # Use SCAN to avoid blocking; we do a simple redis-cli eval that copies one mirror.
      docker exec $REDIS_DOCKER redis-cli --raw eval "local ks=redis.call('KEYS','irc:server-assignments:*'); if #ks==0 then return 0 end; local n=0; for _,k in ipairs(ks) do local fields=redis.call('HGETALL',k); for i=1,#fields,2 do if redis.call('HEXISTS','irc:assignments',fields[i])==0 then redis.call('HSET','irc:assignments',fields[i],fields[i+1]); n=n+1; end; end; end; return n;" 0 2>&1 | tr -d "\r" | head -n1 | xargs -I{} sh -c 'echo "[$TIMESTAMP] HEAL assignments copied {} entries from mirrors" | tee -a "$LOG"' 2>/dev/null || true
      rm -f "$ASSIGN_STALE_STATE" 2>/dev/null || true
    else
      # Both canonical and mirrors empty — could be real empty (fresh DB) or full wipe.
      # Require sustained strikes before killing, same as heartbeat.
      ASTRIKES=$(cat "$ASSIGN_STALE_STATE" 2>/dev/null | tr -cd '0-9'); [ -z "$ASTRIKES" ] && ASTRIKES=0
      ASTRIKES=$((ASTRIKES + 1)); echo "$ASTRIKES" > "$ASSIGN_STALE_STATE"
      if [ "$ASTRIKES" -ge "$ASSIGN_STRIKES" ]; then
        FAIL=1; REASON="${REASON} assignments_empty_x${ASTRIKES}"
        echo "[$TIMESTAMP] FAIL assignments_empty sustained ${ASTRIKES}/${ASSIGN_STRIKES} canonical=0 mirror=0 age=${AGE_S}s — will restart" | tee -a "$LOG" 2>/dev/null || true
      else
        echo "[$TIMESTAMP] WARN assignments_empty canonical=0 mirror=0 strike=${ASTRIKES}/${ASSIGN_STRIKES} age=${AGE_S}s — deferring restart" | tee -a "$LOG" 2>/dev/null || true
        logger -t ircfiber-monitor "WARN assignments_empty strike=${ASTRIKES}/${ASSIGN_STRIKES} canonical=0 mirror=0 age=${AGE_S}s (deferring restart)"
      fi
    fi
  fi
else
  rm -f "$ASSIGN_STALE_STATE" 2>/dev/null || true
fi
FD=""; GW_PID=$(docker exec $GATEWAY sh -c "pidof irc-fiber 2>/dev/null || pgrep -f irc-fiber 2>/dev/null | head -n1" 2>&1 | tr -d "\r" | xargs)
if [ -n "$GW_PID" ] && [[ "$GW_PID" =~ ^[0-9]+$ ]]; then FD=$(docker exec $GATEWAY sh -c "ls /proc/$GW_PID/fd 2>&1 | wc -l" 2>&1 | tr -d "\r" | xargs); else FD=$(docker exec $GATEWAY sh -c "ls /proc/1/fd 2>&1 | wc -l" 2>&1 | tr -d "\r" | xargs); fi
if [ -n "$FD" ] && [[ "$FD" =~ ^[0-9]+$ ]] && [ "$FD" -gt 900 ] 2>/dev/null; then FAIL=1; REASON="${REASON} fd_high_${FD}"; fi
if docker logs --tail 100 $GATEWAY 2>&1 | grep -q "Too many open files"; then FAIL=1; REASON="${REASON} too_many_open_files"; fi
if ! curl --max-time 5 -k --resolve ircfiber.com:443:127.0.0.1 -s https://ircfiber.com/api/version 2>&1 | grep -q "engines"; then sleep 2; if ! curl --max-time 5 -k --resolve ircfiber.com:443:127.0.0.1 -s https://ircfiber.com/api/version 2>&1 | grep -q "engines"; then FAIL=1; REASON="${REASON} caddy_api_fail"; fi; fi
if [ $FAIL -eq 1 ]; then echo "[$TIMESTAMP] FAIL $REASON hlen=${HLEN:-?} hb=${HB:-?} age=${AGE_S:-?}s fd=${FD:-?}" | tee -a "$LOG" 2>/dev/null || true; logger -t ircfiber-monitor "FAIL $REASON hlen=${HLEN:-?} hb=${HB:-?} age=${AGE_S:-?}s fd=${FD:-?}"; if echo "$REASON" | grep -qE "assignments_empty|heartbeat_stale|heartbeat_missing|redis_servers_empty"; then if [ -f "$COOLDOWN_ENGINE" ] && [ $(($(date +%s) - $(stat -c %Y "$COOLDOWN_ENGINE" 2>/dev/null || echo 0))) -lt 600 ]; then echo "[$TIMESTAMP] SKIP engine restart — cooldown active" | tee -a "$LOG" 2>/dev/null || true; else echo "[$TIMESTAMP] AUTO-RESTART engine $ENGINE due to $REASON" | tee -a "$LOG" 2>/dev/null || true; touch "$COOLDOWN_ENGINE"; docker restart $ENGINE 2>&1 | tee -a "$LOG" 2>/dev/null || true; fi; elif echo "$REASON" | grep -qE "fd_high|too_many_open_files|caddy_api_fail|api_version_fail"; then if [ -f "$COOLDOWN_GATEWAY" ] && [ $(($(date +%s) - $(stat -c %Y "$COOLDOWN_GATEWAY" 2>/dev/null || echo 0))) -lt 600 ]; then echo "[$TIMESTAMP] SKIP gateway restart — cooldown active" | tee -a "$LOG" 2>/dev/null || true; else echo "[$TIMESTAMP] AUTO-RESTART gateway $GATEWAY due to $REASON" | tee -a "$LOG" 2>/dev/null || true; touch "$COOLDOWN_GATEWAY"; docker restart $GATEWAY 2>&1 | tee -a "$LOG" 2>/dev/null || true; fi; fi; else echo "[$TIMESTAMP] OK hlen=${HLEN:-?} hb_age=${AGE_S:-?}s fd=${FD:-?}" | tee -a "$LOG" 2>/dev/null || true; fi
