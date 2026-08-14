#!/bin/bash
set -uo pipefail
LOG=/var/log/ircfiber/monitor.log
REDIS_DOCKER=ircfiber-redis
GATEWAY=ircfiber-gateway
ENGINE=ircfiber-engine-ovh
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
FAIL=0
REASON=""

if ! docker exec $GATEWAY curl --max-time 4 -s http://127.0.0.1:8090/api/version 2>&1 | grep -q "engines"; then
  FAIL=1
  REASON="${REASON} api_version_fail"
fi
if ! docker exec $REDIS_DOCKER redis-cli --raw smembers "irc:servers" 2>&1 | grep -q "ovh"; then
  FAIL=1
  REASON="${REASON} redis_servers_empty"
fi
HLEN=$(docker exec $REDIS_DOCKER redis-cli --raw hlen "irc:assignments" 2>&1 | tr -d "\r")
if [ -z "$HLEN" ] || [ "$HLEN" -eq 0 ] 2>/dev/null; then
  FAIL=1
  REASON="${REASON} assignments_empty"
fi
HB=$(docker exec $REDIS_DOCKER redis-cli --raw hget "irc:server:ovh" "lastHeartbeat" 2>&1 | tr -d "\r")
if [ -n "$HB" ] && [ "$HB" -gt 0 ] 2>/dev/null; then
  NOW=$(date +%s000)
  AGE_MS=$((NOW - HB))
  AGE_S=$((AGE_MS / 1000))
  if [ "$AGE_S" -gt 90 ]; then
    FAIL=1
... more output
