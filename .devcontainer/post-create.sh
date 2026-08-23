#!/usr/bin/env bash
set -e
echo "IRC Fiber engine post-create: 1Password -> vault"
if command -v op >/dev/null 2>&1 && [ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
  op inject -i deploy/inventories/production/group_vars/vault.example.yml -o deploy/inventories/production/group_vars/vault.yml || true
  op read "op://IRC Fiber/vault/password" > deploy/.vault_pass.txt 2>/dev/null || true
fi
if [ -n "${ANSIBLE_VAULT_PASSWORD:-}" ] && [ ! -s deploy/.vault_pass.txt ]; then
  echo "$ANSIBLE_VAULT_PASSWORD" > deploy/.vault_pass.txt
  echo "Wrote vault password from Codespaces secret"
fi
./scripts/generate-version.sh || true
echo "engine post-create done"
