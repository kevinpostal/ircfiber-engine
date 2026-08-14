#!/usr/bin/env bash
# One-time setup for the Aristotle SDK (aristotlelib) in this repo.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ ! -d .venv-aristotle ]; then python3 -m venv .venv-aristotle; fi
.venv-aristotle/bin/pip install --quiet --upgrade aristotlelib
echo "Aristotle SDK ready:"
.venv-aristotle/bin/aristotle --version
echo "Next: export ARISTOTLE_API_KEY=... (Dashboard > API Keys at aristotle.harmonic.fun), then run scripts/aristotle/submit.sh"
