#!/usr/bin/env bash
# Find 3 Mullvad exit nodes not G-lined on irc.supernets.org:6697
# Tests via socat OPENSSL over SOCKS5 (real IRC banner), fast
# Usage: ./scripts/find-mullvad-good-exits.sh [limit]  # default 40
set -uo pipefail

HOST="vps-efb4b52d"
SSH="ssh -n -F /dev/null -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_ircfiber -o StrictHostKeyChecking=no deploy@203.0.113.10"
LIMIT=${1:-40}
TEST_SIDECAR="tailscale-mullvad-nl"

echo "Listing Mullvad exits on $HOST..."
EXITS_RAW=$($SSH "sudo docker exec tailscale-mullvad-de tailscale exit-node list 2>&1 | grep mullvad.ts.net | head -n $LIMIT" 2>&1)
EXITS=$(echo "$EXITS_RAW" | awk '{print $1" "$2}' | sort -u | head -n $LIMIT)
TOTAL=$(echo "$EXITS" | grep -c . || echo 0)
echo "Found $TOTAL exits, testing..."

GOOD=()
COUNT=0

# Ensure socat is installed on gateway (for IRC test)
$SSH "sudo docker exec ircfiber-gateway sh -c 'which socat >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq socat)'" >/dev/null 2>&1 || true

while IFS= read -r line; do
  [ -z "$line" ] && continue
  IP=$(echo "$line" | awk '{print $1}')
  HN=$(echo "$line" | awk '{print $2}')
  [ -z "$IP" ] || [ -z "$HN" ] && continue
  COUNT=$((COUNT+1))
  echo "[$COUNT/$TOTAL] Testing $HN ($IP) ..."

  $SSH "sudo docker exec $TEST_SIDECAR tailscale set --exit-node=$IP 2>&1 | head -2" >/dev/null 2>&1 || true
  sleep 4

  AM_IP=$($SSH "sudo docker exec ircfiber-gateway sh -c \"timeout 6 curl --socks5-hostname $TEST_SIDECAR:1055 -s https://am.i.mullvad.net/json 2>&1 | grep -o '\\\"ip\\\"[^,]*' | head -1\"" 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1 || echo "")
  if [ -z "$AM_IP" ]; then
    echo "  -> SKIP $HN (no am.i, exit not ready)"
    continue
  fi

  # Test IRC via socat over SOCKS5: expect irc.supernets.org NOTICE within 7s
  IRC_OUT=$($SSH "sudo docker exec ircfiber-gateway timeout 7 socat -t 7 OPENSSL:irc.supernets.org:6697,verify=0 SOCKS5:$TEST_SIDECAR:irc.supernets.org:6697 2>&1 | head -20" 2>&1 | head -20)
  if echo "$IRC_OUT" | grep -q "NOTICE.*irc\.supernets\|AUTH\|Checking Ident"; then
    echo "  -> GOOD $HN $AM_IP (IRC banner ok)"
    GOOD+=("$IP $HN $AM_IP")
  elif echo "$IRC_OUT" | grep -q "SOCKS5.*granted\|Connected"; then
    # Got SOCKS but no banner = maybe G-lined (server drops) - check for closing
    if echo "$IRC_OUT" | grep -q "G-lined\|Killed\|Closing"; then
      echo "  -> BAD $HN $AM_IP (G-lined/Killed)"
    else
      echo "  -> BAD $HN $AM_IP (SOCKS ok but no IRC banner, likely G-lined)"
      # Debug: show first line
      echo "     out: $(echo "$IRC_OUT" | head -1 | cut -c1-80)"
    fi
  else
    echo "  -> BAD $HN $AM_IP (no SOCKS/IRC)"
    echo "     out: $(echo "$IRC_OUT" | head -1 | cut -c1-80)"
  fi

  if [ ${#GOOD[@]} -ge 3 ]; then
    echo "Found 3 good exits, stopping."
    break
  fi
  sleep 1
done <<< "$EXITS"

echo ""
echo "=== Results: ${#GOOD[@]} good exits ==="
for g in "${GOOD[@]}"; do echo "$g"; done

if [ ${#GOOD[@]} -ge 3 ]; then
  echo ""
  echo "Switch host_vars to (3 not G-lined):"
  for g in "${GOOD[@]:0:3}"; do
    IP=$(echo "$g" | awk '{print $1}')
    HN=$(echo "$g" | awk '{print $2}')
    # Derive short name
    SHORT=$(echo "$HN" | cut -d'-' -f1)
    echo "  - { name: \"$SHORT\", exit_node: \"$IP\" } # $HN"
  done
  echo ""
  echo "Then: ansible-playbook -i deploy/inventories/production/hosts.ini deploy/playbooks/engine.yml -l vps-efb4b52d --vault-password-file deploy/.vault_pass.txt"
  echo "Or manual: update /etc/ircfiber/engine/env-ovh pool and restart engine"
else
  echo "Not enough good exits (need 3, got ${#GOOD[@]}), try larger limit."
fi
