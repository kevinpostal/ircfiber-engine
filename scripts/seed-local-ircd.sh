#!/usr/bin/env bash
# Seed a LocalIRCD network (ircd:6667) for the local dev stack.
# Idempotent: skips if LocalIRCD already exists.
# Usage: ./scripts/seed-local-ircd.sh  [or: make local-ircd]
set -euo pipefail

GATEWAY="${GATEWAY_URL:-http://127.0.0.1:8090}"
USERNAME="${LOCAL_IRCD_USER:-localdev}"
PASSWORD="${LOCAL_IRCD_PASS:-localdev123}"
EMAIL="${LOCAL_IRCD_EMAIL:-localdev@local.test}"
NICK="${LOCAL_IRCD_NICK:-localdev}"
HOST="${LOCAL_IRCD_HOST:-ircd}"
PORT="${LOCAL_IRCD_PORT:-6667}"

JAR=$(mktemp /tmp/ircfiber-seed-XXXXXX.cookies)
trap 'rm -f "$JAR"' EXIT

wait_for_gateway() {
  echo "→ Waiting for gateway $GATEWAY/health ..."
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if curl -fsS "$GATEWAY/health" >/dev/null 2>&1; then echo "  gateway healthy"; return 0; fi
    sleep 2
  done
  echo "  gateway not healthy after 30s" >&2; return 1
}

wait_for_gateway

# Register (ignore 409 if username taken) — follow redirects to capture session cookie
echo "→ Ensuring user $USERNAME ..."
curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/register" \
  -d "username=$USERNAME" -d "email=$EMAIL" -d "password=$PASSWORD" -L -o /dev/null || true

# Login to get authenticated session cookie
echo "→ Logging in ..."
curl -s -c "$JAR" -b "$JAR" -X POST "$GATEWAY/login" \
  -d "username=$USERNAME" -d "password=$PASSWORD" -L -o /dev/null

# Check existing networks
EXISTING=$(curl -s -b "$JAR" "$GATEWAY/api/networks" || echo "[]")
if echo "$EXISTING" | grep -q '"name"[[:space:]]*:[[:space:]]*"LocalIRCD"'; then
  echo "✓ LocalIRCD already exists"
  echo "  Open: http://127.0.0.1:8090/irc/LocalIRCD"
  exit 0
fi

echo "→ Creating LocalIRCD → $HOST:$PORT (tls disabled) ..."
RESP=$(curl -s -b "$JAR" -X POST "$GATEWAY/api/networks" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"LocalIRCD\",\"host\":\"$HOST\",\"port\":$PORT,\"tls\":\"disabled\",\"nick\":\"$NICK\",\"realName\":\"$NICK\",\"autoJoinChannels\":[\"#test\"]}")

if echo "$RESP" | grep -q '"error"'; then
  echo "  create failed: $RESP" >&2; exit 1
fi
echo "✓ Created LocalIRCD: $RESP"
echo "  Open: http://127.0.0.1:8090/irc/LocalIRCD"

# Poll for engine health (optional)
echo "→ Waiting for engine to accept..."
for i in 1 2 3 4 5; do sleep 2; curl -fsS "$GATEWAY/api/networks" -b "$JAR" | grep -q '"name":"LocalIRCD"' && break; done
