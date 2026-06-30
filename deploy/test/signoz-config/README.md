# signoz-config — local ClickHouse config validator

A self-contained docker-compose sandbox that brings up just
`clickhouse-keeper` + `clickhouse` with the production override file
bind-mounted from `deploy/roles/signoz/files/clickhouse-server-overrides.xml`.

## Why

In June 2026 we shipped a new `clickhouse-server-overrides.xml` that
turned out to fail at boot with `Code: 36. DB::Exception: ... is
greater than ...`. ClickHouse exits 36 and restarts forever in that
state. The OVH production container had a 1.7 GB internal memory cap
and the err.log went from MBs to 700+ MB within hours while the
daemon was in a restart loop, eventually filling the container's
writable layer. The bug took 30+ minutes to surface in production
and required manual rollback.

This sandbox catches the same class of bug locally in ~3 seconds.
The role pre-flight task (see `roles/signoz/tasks/main.yml`) runs the
validator on the Ansible controller before touching the host, so a
bad config can't be deployed.

## What's tested

The validator runs five checks:

1. **XML well-formedness** — `xmllint --noout` (falls back to Python
   `ElementTree` if xmllint isn't installed).
2. **ClickHouse starts** — wait up to 60s for the daemon to accept
   `SELECT 1`.
3. **Config actually applied** — query `system.server_settings` for
   the values we shipped and confirm they match.
4. **Restart-loop detection** — exit code 36 (the canonical
   "config reject" code) is surfaced separately so it shows up
   in CI logs as a distinct failure mode.
5. **No silent no-op** — if the bind mount silently fails (e.g. the
   file path is wrong), the test fails with `server_settings miss`
   rather than a green checkmark.

The regression runner (`test-clickhouse-config-regressions.sh`)
swaps in each known-bad fixture and verifies the harness catches it.

## Layout

```
signoz-config/
├── README.md
├── docker-compose.test.yml             # keeper + clickhouse sandbox
├── test-clickhouse-config.sh          # main validator
├── test-clickhouse-config-regressions.sh  # known-bad fixture suite
├── test-signoz-config.sh              # CI entrypoint
└── fixtures/
    ├── README.txt
    ├── underflow-pool/                # background_pool_size=1, ratio=1
    │   └── clickhouse-server-overrides.xml
    └── underflow-optimize-pool/       # pool=4 ratio=5, optimize default=25
        └── clickhouse-server-overrides.xml
```

## Usage

Run from the project root:

```bash
# Validate the current production config
./deploy/test/signoz-config/test-signoz-config.sh

# Run the regression suite
./deploy/test/signoz-config/test-clickhouse-config-regressions.sh
```

Or from the `signoz-config/` directory:

```bash
cd deploy/test/signoz-config
./test-clickhouse-config.sh
```

## First run

The first run pulls `clickhouse/clickhouse-keeper:25.5.6` and
`clickhouse/clickhouse-server:25.5.6` (~750 MB combined). Subsequent
runs reuse the local image cache and complete in ~30s.

## Manual poke around

```bash
cd deploy/test/signoz-config
docker compose -f docker-compose.test.yml up -d
docker exec -it test-clickhouse clickhouse-client
# ... poke around
docker compose -f docker-compose.test.yml down --volumes
```

The `--volumes` flag removes the `ircfiber-test-clickhouse-data`
named volume so the next run starts from an empty schema.

## CI integration

`test-signoz-config.sh` is safe to wire into:

- a git pre-push hook (`pre-commit` config)
- a GitHub Actions job that runs before the deploy step
- a `make` target alongside the existing `make observability-test`

The pre-flight check is also embedded into
`roles/signoz/tasks/main.yml`, so the production deploy itself
fails fast on a bad config before touching the host. Pass
`--check` to ansible to skip the validator (it spins up a
container, which is the side-effect we want to avoid in dry runs).

## What it does NOT catch

- The nested `<logger><size>` form is cosmetic on 25.5.6 (wrong
  log path, daemon still works). Removed from fixtures.
- Merge-pool behavior under sustained load. The OVH incident
  was a 1.7 GB cap with 80k+ background merges failing over
  hours; the local sandbox doesn't generate that load pattern.
  If we need to load-test, set up a soak test that ingests a
  realistic log volume for an hour.
- ClickHouse config drift between the local test image and the
  OVH production image. Both pin `25.5.6` — bump the test
  image tag and the deploy role's `clickhouse_image` together.
