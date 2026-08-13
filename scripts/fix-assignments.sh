#!/usr/bin/env bash
# fix-assignments.sh — rebuild irc:assignments from MongoDB (non-disabled networks)
# Does not restart engine; the engine's heartbeat will pick up the new assignments
# within 10s and connect. For immediate reconnect, run with --restart.
set -euo pipefail
HOST="${1:-203.0.113.10}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519_ircfiber}"
SSH="ssh -F /dev/null -o IdentitiesOnly=yes -i $SSH_KEY deploy@$HOST"

echo "==> Rebuilding irc:assignments on $HOST from MongoDB (skip disabled)..."
$SSH bash -s <<'EOSSH'
set -euo pipefail
MONGO_URL="mongodb://ircfiber:jqgwEv3GJwwizulaj3Fnbd8imqcMH4Gh@172.30.0.1:27017/ircfiber"
# Get all non-disabled network ids via mongosh
IDS=$(docker exec ircfiber-mongo mongosh --quiet "$MONGO_URL" --eval 'db.networks.find({disabled:{$ne:true}},{id:1,_id:0}).toArray().forEach(x=>print(x.id))' 2>&1 | grep -E '^[0-9a-f-]{36}$')
COUNT=$(echo "$IDS" | wc -l | tr -d ' ')
echo "Found $COUNT active networks in MongoDB"
if [ "$COUNT" -eq 0 ]; then
  echo "No active networks — nothing to do"
  exit 0
fi
for id in $IDS; do
  docker exec ircfiber-redis redis-cli HSET irc:assignments "$id" ovh > /dev/null
done
HLEN=$(docker exec ircfiber-redis redis-cli HLEN irc:assignments 2>&1)
echo "HLEN irc:assignments now $HLEN"
# Also repopulate per-engine mirror so getAllAssignments recovery works even if heartbeat is slow
# Mirror is irc:server-assignments:ovh
docker exec ircfiber-redis redis-cli DEL irc:server-assignments:ovh > /dev/null || true
for id in $IDS; do
  docker exec ircfiber-redis redis-cli HSET irc:server-assignments:ovh "$id" ovh > /dev/null
done
MLEN=$(docker exec ircfiber-redis redis-cli HLEN irc:server-assignments:ovh 2>&1)
echo "HLEN irc:server-assignments:ovh now $MLEN"
EOSSH
if [[ "${1:-}" == "--restart" ]] || [[ "${2:-}" == "--restart" ]]; then
  echo "==> Restarting engine for immediate reconnect..."
  ssh -F /dev/null -o IdentitiesOnly=yes -i "$SSH_KEY" deploy@"$HOST" 'docker restart ircfiber-engine-ovh && sleep 3 && docker logs --tail 30 ircfiber-engine-ovh 2>&1 | grep -E "Network loading|assignedNetworks|Heartbeat sent" | tail -n 20'
fi
echo "==> Done. Engine will pick up assignments within ~10s (heartbeat). Check with: make check-assignments"
