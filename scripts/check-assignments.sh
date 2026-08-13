#!/usr/bin/env bash
# check-assignments.sh — health check for irc:assignments vs Mongo
set -euo pipefail
HOST="${1:-203.0.113.10}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_ircfiber}"
SSH="ssh -F /dev/null -o IdentitiesOnly=yes -i $SSH_KEY deploy@$HOST"

$SSH bash -s <<'EOSSH'
set -euo pipefail
MONGO_URL="mongodb://ircfiber:jqgwEv3GJwwizulaj3Fnbd8imqcMH4Gh@172.30.0.1:27017/ircfiber"
MONGO_COUNT=$(docker exec ircfiber-mongo mongosh --quiet "$MONGO_URL" --eval 'db.networks.countDocuments({disabled:{$ne:true}})' 2>&1 | grep -E '^[0-9]+$' | tail -1)
MONGO_TOTAL=$(docker exec ircfiber-mongo mongosh --quiet "$MONGO_URL" --eval 'db.networks.countDocuments()' 2>&1 | grep -E '^[0-9]+$' | tail -1)
REDIS_HLEN=$(docker exec ircfiber-redis redis-cli HLEN irc:assignments 2>&1)
MIRROR_HLEN=$(docker exec ircfiber-redis redis-cli HLEN irc:server-assignments:ovh 2>&1)
SERVERS=$(docker exec ircfiber-redis redis-cli SMEMBERS irc:servers 2>&1 | wc -l | tr -d ' ')
echo "Mongo total networks: $MONGO_TOTAL"
echo "Mongo active (disabled!=true): $MONGO_COUNT"
echo "Redis irc:assignments HLEN: $REDIS_HLEN"
echo "Redis irc:server-assignments:ovh HLEN: $MIRROR_HLEN"
echo "Redis irc:servers members: $SERVERS"
if [ "$REDIS_HLEN" = "0" ] && [ "$MONGO_COUNT" != "0" ]; then
  echo "CRITICAL: assignments empty but mongo has $MONGO_COUNT active networks — engine will be disconnected!"
  exit 2
elif [ "$REDIS_HLEN" != "$MONGO_COUNT" ]; then
  echo "WARN: assignments $REDIS_HLEN != mongo active $MONGO_COUNT (disabled networks may account for diff)"
else
  echo "OK: assignments matches mongo active"
fi
echo "--- sample assignments ---"
docker exec ircfiber-redis redis-cli HGETALL irc:assignments 2>&1 | head -n 20
echo "--- engine heartbeat (last 5) ---"
docker logs --tail 50 ircfiber-engine-ovh 2>&1 | grep -E "Heartbeat sent|getCanonicalNetworks done|assignedNetworks" | tail -n 20
EOSSH
