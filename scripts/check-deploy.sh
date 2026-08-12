#!/usr/bin/env bash
# check-deploy.sh — show what needs deploying to OVH
# Compares local engine/frontend fingerprints vs what's on the host
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
SSH_KEY="${HOME}/.ssh/id_ed25519_ircfiber"
SSH_HOST="deploy@203.0.113.10"
SSH="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"

ENGINE_CURRENT=$(./scripts/engine-fingerprint.sh)
ENGINE_SHORT=$(./scripts/engine-fingerprint.sh --short)
FRONTEND_CURRENT=$(git rev-parse HEAD 2>/dev/null || echo "no-git")
FRONTEND_SHORT=$(echo "$FRONTEND_CURRENT" | cut -c1-12)

ENGINE_DEPLOYED=$($SSH $SSH_HOST "cat /opt/ircfiber/.engine-deploy-hash 2>/dev/null || cat /opt/ircfiber-src/.engine-deploy-hash 2>/dev/null || echo none" 2>&1 | tr -d '\r' | head -n1)
FRONTEND_DEPLOYED=$($SSH $SSH_HOST "cat /opt/ircfiber/.frontend-deploy-hash 2>/dev/null || cat /opt/ircfiber-src/.frontend-deploy-hash 2>/dev/null || cat /opt/ircfiber-src/public/dist/.deploy-hash 2>/dev/null || echo none" 2>&1 | tr -d '\r' | head -n1)

# Fallback: check backend/views/index.dt hash as proxy for frontend deploy
if [[ "$FRONTEND_DEPLOYED" == "none" ]]; then
  FRONTEND_DEPLOYED=$($SSH $SSH_HOST "sha256sum /opt/ircfiber-src/backend/views/index.dt 2>/dev/null | cut -d' ' -f1 | cut -c1-12 || echo none" 2>&1 | tr -d '\r' | head -n1)
fi

cat <<EOF
Engine  current: $ENGINE_SHORT ($ENGINE_CURRENT)
Engine deployed: $ENGINE_DEPLOYED
Frontend  current: $FRONTEND_SHORT
Frontend deployed: $FRONTEND_DEPLOYED

EOF

NEED_ENGINE=false
NEED_FRONTEND=false
if [[ "$ENGINE_DEPLOYED" == "none" || "$ENGINE_DEPLOYED" != "$ENGINE_SHORT" && "$ENGINE_DEPLOYED" != "$ENGINE_CURRENT" ]]; then
  # also check dirty suffix
  if [[ "$ENGINE_CURRENT" == *"-dirty"* ]]; then
    NEED_ENGINE=true
  elif [[ "$ENGINE_DEPLOYED" != "${ENGINE_CURRENT:0:12}" && "$ENGINE_DEPLOYED" != "$ENGINE_CURRENT" ]]; then
    NEED_ENGINE=true
  fi
fi
if [[ "$FRONTEND_DEPLOYED" == "none" || ( "$FRONTEND_DEPLOYED" != "$FRONTEND_CURRENT" && "$FRONTEND_DEPLOYED" != "$FRONTEND_SHORT" && "${FRONTEND_DEPLOYED:0:12}" != "$FRONTEND_SHORT" ) ]]; then
  NEED_FRONTEND=true
fi

if $NEED_ENGINE; then
  echo "🔴 Engine  NEEDS deploy (make update)"
else
  echo "🟢 Engine  up to date (gateway-only deploy suffices)"
fi
if $NEED_FRONTEND; then
  echo "🔴 Frontend NEEDS deploy (make update-gateway or make update)"
else
  echo "🟢 Frontend up to date"
fi

if $NEED_ENGINE; then
  echo ""
  echo "→ Run: make update"
elif $NEED_FRONTEND; then
  echo ""
  echo "→ Run: make update-gateway  (engine stays up)"
else
  echo ""
  echo "→ Nothing to deploy"
fi
