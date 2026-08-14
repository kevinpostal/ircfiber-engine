# Aristotle SDK — IRC Fiber formal verification

Wraps the [Aristotle](https://aristotle.harmonic.fun/) SDK (aristotlelib) for
the formal-verification project at docs/aristotle/RequestProject/.

## What this is for

The Lean 4 modules under docs/aristotle/RequestProject/IrcFiber/ mirror
selected IRC Fiber frontend logic and carry `sorry` obligations that
Aristotle fills (proves, or finds counterexamples). The workflow matches the
prior img2irc and chat-infinite-scroll engagements.

## Usage

    ./scripts/aristotle/setup.sh              # creates .venv-aristotle + installs aristotlelib
    export ARISTOTLE_API_KEY=…                # Dashboard → API Keys
    ./scripts/aristotle/submit.sh             # async submit → prints project id
    ./scripts/aristotle/submit.sh --wait      # blocking; writes /tmp/aristotle-out.tar.gz

Poll / download:

    .venv-aristotle/bin/aristotle list
    .venv-aristotle/bin/aristotle show <id>
    .venv-aristotle/bin/aristotle tasks <id>
    .venv-aristotle/bin/aristotle download <id>

## After Aristotle finishes

1. Download the filled project (aristotle download <id>, or the --wait archive).
2. Copy the proved *.lean files back into docs/aristotle/RequestProject/IrcFiber/.
3. Verify locally:

       cd docs/aristotle/RequestProject
       lake build IrcFiber.Ordinal IrcFiber.Suspicious IrcFiber.Reconnect IrcFiber.HoleDetector IrcFiber.Splitter

4. Re-run the mirrored vitest suites unchanged (they are the oracles the
   proofs describe):

       cd frontend
       npx vitest run --project=lib src/lib/wsHoleDetector.test.ts src/lib/messageSplitter.test.ts src/lib/messageBatcher.test.ts src/lib/suspiciousConnection.test.ts src/lib/connectionWarnings.test.ts

## Notes

- The Lean project is deliberately mathlib-free so local builds are fast and
  offline; lean-toolchain pins leanprover/lean4:v4.28.0 so Aristotle builds the
  same toolchain.
- .venv-aristotle and docs/aristotle/prompt.txt are gitignored (see .gitignore).
