#!/usr/bin/env bash
# IRC Fiber — /signoz/ws/logs/v5/{orgId} BLOCKER preflight.
#
# Confirms the live SigNoz instance (behind ircfiber-caddy) actually
# serves the /signoz/ws/logs/v5/{orgId} WebSocket endpoint BEFORE
# w3-t1-live-tail-store is built. Building on top of an unverified
# endpoint would surface as "connected, zero messages" or a silent
# 404 days into the work — this script catches it in 10 s.
#
# Run from the deploy host (ircfiber-ovh-1) where the upstream chain is
# reachable end-to-end:
#   - ircfiber-caddy with SIGNOZ_API_KEY env var set
#   - signoz-signoz container on ircfiber_net reachable
#   - A live SIGNOZ-API-KEY EDITOR session for /api/v1/user
#
# Exit codes:
#   0 — HTTP 101 Switching Protocols received (wsUrl is live, w3-t1 may proceed)
#   1 — any failure (network refused, 401, 404, 502, orgId missing, etc.)
#
# Override the prod base URL / log location for local smoke testing:
#   PROD=http://127.0.0.1:8090 LOG=/tmp/ws.log bash scripts/ws-preflight.sh
set -u

PROD="${PROD:-https://ircfiber.com}"
LOG="${LOG:-docs/plan/20260630-admin-signoz-logs-panel/ws-preflight.log}"
mkdir -p "$(dirname "$LOG")"

# Stable RFC 6455 Sec-WebSocket-Key (16 random bytes, base64).
# The value is irrelevant — SigNoz's handshake reply is what we're checking.
WS_KEY='x3JJHMbDL1EzLkh9GBhXDw=='

# SigNoz orgIds can contain '-' and alphanumerics; both /api/v1/user and
# signoz.ts wsUrl() are fine on that character set. The script does NOT
# URL-encode the orgId — matches /signoz/ws/logs/v5/{orgId} literal path
# the live-tail consumer will dial.  See the README note in this script's
# plan dir for the (unfixed) divergence with frontend/src/lib/signoz.ts,
# which percent-encodes via encodeURIComponent.
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
say() { printf '[%s] %s\n' "$(ts)" "$*" | tee -a "$LOG"; }

# Detect a network-level failure (curl never reached an HTTP layer).
# curl on a refused connection prints "Failed to connect to <host>"
# or "Connection timed out" on stderr; combined with `2>&1` above they
# end up in WS_RESP / USER_JSON.
is_network_failure() {
  printf '%s' "$1" | grep -qiE 'connect refused|connection timed out|failed to connect|could not resolve host'
}

say '=== SigNoz /signoz/ws/logs/v5 WS preflight ==='
say "prod: $PROD"
say "log:  $LOG"

# ─── Step 1: orgId discovery ──────────────────────────────────────────
say 'Step 1: orgId discovery via GET /api/v1/user'
USER_JSON=$(curl -isS -m 10 -w '\n%{http_code}' "$PROD/api/v1/user" 2>&1 || true)

if is_network_failure "$USER_JSON"; then
  say "FAIL  could not reach $PROD/api/v1/user"
  say '      error: '"$(printf '%s' "$USER_JSON" | tr '\n' ' ' | sed 's/  */ /g' | head -c 200)"
  say '      remediation: VITE_SIGNOZ_URL unset OR ircfiber-caddy missing SIGNOZ_API_KEY'
  exit 1
fi

USER_CODE=$(printf '%s\n' "$USER_JSON" | tail -1)
# sed '$d' is portable: GNU `head -n -1` rejects the negative count on
# macOS/BSD (head: illegal line count -- -1), so we use sed to drop the
# last line (the %{http_code} that curl -w appended) instead.
USER_BODY=$(printf '%s\n' "$USER_JSON" | sed '$d')
if [ "$USER_CODE" != "200" ]; then
  say "FAIL  /api/v1/user returned $USER_CODE"
  say "      body: $USER_BODY"
  say '      remediation: VITE_SIGNOZ_URL unset OR ircfiber-caddy missing SIGNOZ_API_KEY - run signoz_mcp role first'
  exit 1
fi
ORG_ID=$(printf '%s' "$USER_BODY" | sed -n 's/.*"orgId":"\([^"]*\)".*/\1/p')
if [ -z "$ORG_ID" ]; then
  say "FAIL  /api/v1/user returned 200 but no orgId field in body"
  say "      body: $USER_BODY"
  say '      remediation: signoz instance may be misconfigured - check SigNoz admin UI'
  exit 1
fi
say "      orgId: $ORG_ID"

# ─── Step 2: WS upgrade ──────────────────────────────────────────────
WS_URL="$PROD/signoz/ws/logs/v5/$ORG_ID"
say "Step 2: WS upgrade test against $WS_URL"
# -i: include response headers in output (we need the status line)
# --no-buffer: surface 101 immediately instead of waiting for body
# -m 10: 10 s safety net — once 101 is sent, curl sits on the open
#         socket until the WS layer times out, which we don't need
WS_RESP=$(curl -isS -m 10 --no-buffer \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H "Sec-WebSocket-Key: $WS_KEY" \
  "$WS_URL" 2>&1 || true)
STATUS_LINE=$(printf '%s\n' "$WS_RESP" | head -1)
say "      response status line: $STATUS_LINE"

if is_network_failure "$WS_RESP"; then
  say 'FAIL  connection refused / timeout'
  say '      remediation: VITE_SIGNOZ_URL unset OR ircfiber-caddy missing SIGNOZ_API_KEY'
  exit 1
fi

CODE=$(printf '%s' "$STATUS_LINE" | awk '{print $2}')
case "$CODE" in
  101)
    say 'PASS  HTTP 101 Switching Protocols - WS endpoint is live'
    say "      orgId: $ORG_ID"
    say "      endpoint: $WS_URL"
    say '      next step: w3-t1-live-tail-store can proceed'
    exit 0
    ;;
  401)
    say 'FAIL  HTTP 401 - SIGNOZ_API_KEY invalid'
    say '      remediation: rotate via signoz_mcp role (ansible-playbook playbooks/signoz_mcp.yml -e vault_signoz_admin_password=...)'
    exit 1
    ;;
  404)
    say 'FAIL  HTTP 404 - /signoz/ws/logs/* not in Caddyfile.j2 handle_path block'
    say '      remediation: deploy/roles/caddy/templates/Caddyfile.j2:60-79 may need a dedicated handle_path /signoz/ws/logs/* block with flush_interval -1'
    exit 1
    ;;
  502)
    say 'FAIL  HTTP 502 - signoz-signoz container not reachable'
    say "      remediation: check 'docker compose ps' on ircfiber-ovh-1; signoz may be down"
    exit 1
    ;;
  *)
    say "FAIL  HTTP $CODE"
    say '      response (first 20 lines):'
    printf '%s\n' "$WS_RESP" | head -20 | sed 's/^/      /' >> "$LOG"
    exit 1
    ;;
esac
