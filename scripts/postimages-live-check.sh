#!/usr/bin/env bash
# Manual probe of postimages.org's anonymous web-upload contract.
# NOT run in CI. Usage: ./scripts/postimages-live-check.sh path/to/test.png
set -euo pipefail
IMG="${1:?usage: $0 <image-file>}"

echo "== 1. scrape token from homepage =="
HOME_HTML=$(curl -s https://postimages.org/)
TOKEN=$(echo "$HOME_HTML" | grep -oE '"token"\s*:\s*"[a-f0-9]+"' | head -1 | grep -oE '[a-f0-9]{8,}')
echo "token: $TOKEN"

echo "== 2. upload =="
SESSION=$(hexdump -n16 -e '16/1 "%02x"' /dev/urandom)
RESP=$(curl -s -X POST https://postimages.org/json/rfc \
  -F "token=$TOKEN" \
  -F "upload_session=$SESSION" \
  -F "numfiles=1" \
  -F "optsize=0" \
  -F "expire=0" \
  -F "file=@$IMG")
echo "response: $RESP"

PAGE_URL=$(echo "$RESP" | grep -oE '"url"\s*:\s*"[^"]+"' | head -1 | sed -E 's/.*"(https[^"]+)".*/\1/')
echo "== 3. resolve direct image url from $PAGE_URL =="
curl -s "$PAGE_URL" | grep -oE '<meta property="og:image" content="[^"]+"' || echo "OG IMAGE NOT FOUND — inspect page HTML"
