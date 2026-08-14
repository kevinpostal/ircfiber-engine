#!/usr/bin/env bash
# Submit the IRC Fiber formalization project to Aristotle (fills the sorries
# in docs/aristotle/RequestProject). Uses the repo-local venv from setup.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [ -z "${ARISTOTLE_API_KEY:-}" ]; then
  echo "ARISTOTLE_API_KEY is not set" >&2
  exit 1
fi
PROMPT_FILE="docs/aristotle/prompt.txt"
PROJECT_DIR="docs/aristotle/RequestProject"
cat > "$PROMPT_FILE" <<'EOF'
IRC Fiber formal verification project (Lean 4.28, core-only, no mathlib).
Fill every sorry in the modules under IrcFiber/. Each module mirrors a real
TypeScript module of the IRC Fiber chat client. See the doc comments at the
top of each .lean file for the exact obligations. Keep lake build green; use
only core Lean + Std (omega, simp, native_decide). If an obligation is false,
find a concrete counterexample and state it instead.
EOF
if [ "${1:-}" = "--wait" ]; then
  .venv-aristotle/bin/aristotle submit "$(cat "$PROMPT_FILE")" \
    --project-dir "$PROJECT_DIR" --wait --destination /tmp/aristotle-out.tar.gz
  echo "Result archive: /tmp/aristotle-out.tar.gz (extract and copy the filled .lean files back into docs/aristotle/RequestProject/IrcFiber/)"
else
  .venv-aristotle/bin/aristotle submit "$(cat "$PROMPT_FILE")" --project-dir "$PROJECT_DIR"
fi
