#!/usr/bin/env bash
# Manual probe of catbox.moe anonymous upload API.
# NOT run in CI. Usage: ./scripts/postimages-live-check.sh path/to/test.png
set -euo pipefail
IMG="${1:?usage: $0 <image-file>}"

echo "== upload to catbox.moe =="
RESP=$(curl -s -F "reqtype=fileupload" -F "fileToUpload=@$IMG" https://catbox.moe/user/api.php)
echo "response: $RESP"
echo ""
echo "If you see a https://files.catbox.moe/ URL, it works."
