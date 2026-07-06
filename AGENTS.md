# IRC Fiber — Testing Guide

## Test Suites

Two vitest projects under `frontend/`:

- **`lib`** — Pure utility tests, no DOM, runs in Node (`src/lib/**/*.test.ts`)
- **`client`** — Svelte component + store tests, runs in headless Chromium (`src/**/*.test.ts`, `*.svelte.test.ts`)

```bash
cd frontend

# Run all tests
npm test

# Lib only (fast, no browser)
npm run test:lib

# Client only (Svelte components + stores)
npm run test:client

# Watch mode
npm run test:watch
```

## Testing Patterns

### Lib tests (Node, fast)
Use vitest directly — no browser context needed:
```typescript
import { describe, expect, it } from 'vitest';
import { mentionNicks } from './autolinker';

describe('mentionNicks', () => {
  it('wraps a single mention', () => {
    const result = mentionNicks('hello @Alice', new Set(['alice']));
    expect(result).toContain('mention');
  });
});
```

### E2E / Visual Tests (Playwright)
Capturing + comparing CSS between IRCCloud and our app:
```bash
# Capture both pages and produce comparison_full.json
node capture_comparison.js
```

Key scripts in project root:
- `capture_comparison.js` — Full CSS comparison (IRCloud vs local)
- `capture_css.js` — Initial CSS capture
- `test_mention.js` — Verify `.mention` elements render correctly
- `check_links.js` — Inspect IRCCloud link styling

### Run lib tests for a single file
```bash
npx vitest run --project=lib src/lib/autolinker.test.ts
```

## Debugging

Add `console.debug()` in Svelte components and capture via Playwright:
```typescript
page.on('console', msg => { if (msg.text().includes('[tag]')) logs.push(msg.text()); });
```

The `capture_comparison.js` script also captures IRCCloud's live CSS for reference.

---

# IRC Fiber — Graceful Engine Hot-Reload

The engine supports **graceful hot-reload** (handoff) — IRC connections survive a code change without any disconnect.

## Flow

1. `make engine-handoff` records the old engine's PID, starts a new engine with `IRCFIBER_RELOAD_FROM_PID=$pid`
2. New engine connects to old engine's Unix socket at `/tmp/ircfiber-handoff-<serverId>.sock`
3. **Handshake:** `READY` → `HELLO <pid>` → `GO`
4. For each IRC connection:
   - Old engine pauses the event loop, captures state snapshot (channels, caps, nicks)
   - Sends `RECORD plain|tls <nidLen>:<nid>` header
   - Transfers JSON state + raw socket FD via `SCM_RIGHTS` (plain TCP only)
   - Waits for `ACK` from new engine
5. **TLS records (fd < 0):** queued in `pendingHandoffRecords` on the new engine. After the last ACK, the old engine calls `notifyHandoffComplete` which synchronously writes QUIT on every live TLS socket via `forcePostHandoffQuit` — this releases the nick on the IRC server BEFORE the new engine attempts registration. See "TLS nick collision fix" below for why.
6. Old engine writes `DONE <count>`, marks itself `draining:true` in Redis, returns from `serveReload`
7. New engine reads `DONE`, calls `startPendingHandoffReconnects()` which drains the queued TLS records. Each queued soft-reconnect runs on its own fiber with a 500ms settling delay so the IRC server has time to fully process the old engine's QUIT before the new engine's NICK hits the wire.
8. New engine adopts all FDs (plain) or soft-reconnects (TLS), publishes `CONNECTED` synthetic events
9. Old engine exits via the post-handoff early-check in `processEvents` (sets `isShutdownRequested=true` after seeing `postHandoffQuitAtMs > 0`, then runs cleanup + `exit(0)` if not PID 1).

## TLS nick collision fix (Jul 4 2026)

### The bug

Before this fix, a hot reload on a TLS network produced `Zodiac_` (with trailing
underscore) as a ghost member in every joined channel. The chain:

1. OLD engine had `Zodiac` registered on the IRC server.
2. NEW engine started `performRegistration` immediately on receiving the
   RECORD (per-record, not after DONE).
3. NEW engine sent `NICK Zodiac` while the OLD engine's TLS socket still
   held the registration — 433 → fallback to `Zodiac_`.
4. NEW engine JOINed `#ircfiber` as `Zodiac_`, racing the OLD's still-live
   connection. The channel briefly showed both.
5. `persistNick` saved `Zodiac_`, making the bad nick sticky across every
   subsequent reconnect.

### The fix (three layers)

| Layer | Change | File |
|---|---|---|
| 1. Queue TLS reconnects | `adoptFromHandoff` no longer calls `addAndStartNetwork` for fd<0 records; it appends to `pendingHandoffRecords`. | `source/ircfiber/irc/manager.d` |
| 2. Drain after DONE | `adoptFromOldEngine` calls `startPendingHandoffReconnects()` after the protocol's DONE marker, so the old engine has called `notifyHandoffComplete` first. The drain wraps each soft-reconnect in a 500ms-delayed task so the IRC server fully processes the QUIT before the new engine's NICK arrives. | `source/ircfiber/engine/reload_orchestrator.d`, `source/ircfiber/irc/manager.d` |
| 3. Synchronous QUIT on TLS | `notifyHandoffComplete` now calls `forcePostHandoffQuit` (new method on `PersistentIRCClient`) for TLS records. It writes QUIT on the live TLS socket SYNCHRONOUSLY before the handoff protocol sends DONE — by the time the new engine reads DONE, the IRC server has freed the nick. Plain-TCP records still use `schedulePostHandoffQuit` (flag-based) since their FD was transferred via SCM_RIGHTS and the QUIT would write to a dead socket. | `source/ircfiber/irc/manager.d`, `source/ircfiber/irc/connection.d` |

### The OLD-engine exit path

After the pause releases in `serveReload`'s scope exit, every client's
event-loop `processEvents()` early-check at `connection.d:2275` sees
`postHandoffQuitAtMs > 0`, sets `isShutdownRequested = true`, closes the
transport, and returns. The outer `runConnectionLoop` then breaks, runs
cleanup(), and calls `exit(0)` (if not PID 1). For deployments where the
OLD engine is supervised and needs a fast-exit signal, set
`IRCFIBER_FORCE_EXIT_ON_HANDOFF=1` in the OLD engine's environment to
force-exit immediately after DONE is written (defense in depth — useful
when the connection loop is blocked in `waitForData()` with a long
timeout).

## Wire Protocol

```
New engine →            READY\n
          ← Old engine  HELLO <pid>\n
          ←             GO\n
                         ... for each record:
          ←             RECORD plain|tls <nidLen>:<nid>\n
          ←             [4-byte JSON length][JSON bytes]
          ←             [4-byte FD count][SCM_RIGHTS cmsg with FDs]
New engine →            ACK\n
          ←             DONE <count>\n
```

## Key Files

| File | Purpose |
|---|---|
| `source/ircfiber/engine/handoff.d` | Unix socket plumbing, SCM_RIGHTS FD transfer, JSON serde for HandoffState |
| `source/ircfiber/engine/reload_orchestrator.d` | `adoptFromOldEngine` (client) + `serveReload` (server) + `triggerHandoff` + DONE-time queue drain |
| `source/ircfiber/irc/connection.d` | `pauseForHandoff/resumeAfterHandoff/snapshotForHandoff/adoptAndStart` + `forcePostHandoffQuit` (synchronous TLS QUIT) + post-handoff early exit check |
| `source/ircfiber/irc/manager.d` | `pauseAllForHandoff/snapshotAllForHandoff/adoptFromHandoff` (queues TLS records) + `notifyHandoffComplete` (synchronous QUIT for TLS) + `startPendingHandoffReconnects` (drains queue with 500ms settling delay) |
| `source/app_engine.d` | Two-path boot (fresh vs. handoff), PID file writing after adoption |

## Commands

```
make engine-handoff          # Graceful handoff (IRC sockets preserved)
make engine-handoff-redis    # Trigger via redis-cli LPUSH (remote)
make engine-restart          # Hard restart (closes sockets, reconnect)
```

## Admin Endpoint

`GET /api/admin/handoff/status` — Returns last handoff duration, count per type (plain/TLS), draining servers.

## Testing Notes

- AdoptedSocket tests use raw POSIX `socketpair(2)` — no vibe.d fibers required
- SCM_RIGHTS FD transfer test uses pipe + socketpair — works on macOS and Linux
- End-to-end handoff requires a running engine and a Linux environment (or macOS with BSD SCM_RIGHTS)
- The `consumer.d` test runner may hang on macOS when vibe.d fiber context is required — disable via `excludedSourceFiles` in `dub.sdl` if needed

## Deploy book pre-flight validation

The SigNoz role runs a **local ClickHouse config validator** before touching any host. It catches the class of bug that puts `signoz-clickhouse` into a restart loop on the live server (e.g. `background_pool_size * background_merges_mutations_concurrency_ratio < 20` default mutations free entries, or `< 25` for the partition-optimizer default). The OVH server hit this in June 2026 and the bad config took 30+ minutes to surface as a 728 MB `err.log` filling the writable layer.

Run **before** touching the OVH server when changing `deploy/roles/signoz/files/clickhouse-server-overrides.xml`:

```bash
# Validate the current production-equivalent config locally
./deploy/test/signoz-config/test-clickhouse-config.sh

# Run the regression suite against known-bad fixtures
./deploy/test/signoz-config/test-clickhouse-config-regressions.sh
```

The same validator is embedded as a preflight task in the `logging` role, so `ansible-playbook playbooks/logging.yml` aborts before any docker commands run on the host if the config is bad. Pass `--check` to skip the validator in a dry run. See `deploy/test/signoz-config/README.md` for the full rationale and what's tested.

---

# IRC Fiber — Deploy Architecture

## Architecture mismatch: local ARM64 vs remote x86_64

Local dev is on Apple Silicon (ARM64). The production server `ircfiber-ovh-1` (40.160.227.49) is **x86_64**. **Never** compile D binaries locally and SCP them — they produce `exec format error` on the server.

Always build via the **remote BuildKit** (docker build on the server) or use `make update` which handles this automatically. The only exception is frontend dist assets (`public/dist/`) which are platform-independent JS/CSS/HTML and can be pushed directly via the SSH tar pipe in the Makefile.

```bash
# Correct: builds on the remote server
make update                        # full deploy (frontend + binaries + handoff)
make handoff                       # engine-only handoff (builds on remote)

# WRONG: local binary won't run on x86_64
scp irc-fiber deploy@server:/tmp/  # ← do not do this
```

## Handoff deployment flow

`deploy-update.yml` builds the binary INSIDE a Docker container on the remote server using BuildKit:
1. Rsync local source → `/opt/ircfiber-src/` on remote
2. `docker build --target builder` — compiles D code via dub + LDC
3. Extracts binary from builder image
4. `docker cp` into running gateway container + restart
5. Engine hot-reload (handoff) — no IRC disconnect

Key issue: `rsync delete: false` (now fixed to `delete: true`) allowed stale source files like `source/ircfiber/web/admin.d` to persist on the remote after the admin code was refactored into the `admin/` package directory. This caused `dub build` to fail with "package name conflicts with module name" — the error was hidden by `|| true` in the Containerfile's RUN command.

## Admin SPA deployment

Frontend assets (`public/dist/admin.html`, `assets/*`) are pushed to the gateway container via the Makefile's SSH tar pipe AFTER the playbook completes:
```bash
tar cz --no-xattrs -C public/dist . | ssh deploy@server \
  'docker exec -i ircfiber-gateway sh -c "rm -rf /app/public/dist/ && mkdir -p /app/public/dist/ && tar xzf - -C /app/public/dist"'
```
The `--no-xattrs` flag prevents macOS extended attributes from creating duplicate `file 2.ext` entries on Linux.

## Admin -> SigNoz logs integration

The admin SPA at `ircfiber.com/admin#/logs` is a **native Svelte panel** that talks to SigNoz through the existing Caddy reverse-proxy. A deep link to the Tailscale-only SigNoz listener is offered as a fallback for the features the native panel does not cover (saved views, pivots, anomalies).

### Architecture decision (Option D)

Two prior attempts to embed the SigNoz UI via iframe were abandoned:
- `7795a73 fix(deploy): proxy SigNoz API and asset paths from root`
- `287d089 fix(deploy): scope SigNoz static proxy to index-* bundles`

Root cause: SigNoz v0.130's combined-image React bundle bootstraps a session JWT via client-side state. A static `SIGNOZ-API-KEY` header that Caddy injects server-side cannot be replayed by the bundle. The bundle loads, `/api/v1/user` returns 401, and SigNoz renders the cloud-icon error page.

A Caddy-side login proxy (POST `/api/v2/sessions` per iframe load) was considered and rejected because: (a) it would leak the admin password into the Caddyfile env, (b) it would hit session rate-limits, (c) any SigNoz version bump could break the login API contract.

**Option D** (the shipped architecture) replaces the iframe with a native Svelte panel for the 95% case (filter, paginate, time range, severity, row expand) plus a fallback link to the tailnet listener for the 5% case (server-side saved views, pivots, anomalies). Full task graph, rejected options, and pre-mortem live in [`docs/plan/20260630-admin-signoz-logs-panel/plan.yaml`](docs/plan/20260630-admin-signoz-logs-panel/plan.yaml).

### File layout

| File | Purpose |
|---|---|
| `frontend/src/lib/signoz.ts` | REST + WS wrapper: `queryRange`, `services`, `fields`, `fieldValues`, `currentUser`, `wsUrl(orgId)`. No Svelte imports. |
| `frontend/src/admin/stores/logsStore.ts` | UI state store: `LogsState`, debounced `runQuery` (200ms trailing), `setQuery`/`setService`/`setSeverity`/`setTimeRange`, `resetFilters`, `toggleExpandedRow`. |
| `frontend/src/admin/stores/logsLiveTail.ts` | WS reconnect with exponential backoff (1s to 30s cap, +/-20% jitter, 10-attempt cap). 5-state status machine: `idle` / `connecting` / `open` / `reconnecting` / `closed`. |
| `frontend/src/admin/stores/savedViews.ts` | localStorage-backed SavedView persistence. Stable interface (`listViews` / `saveView` / `loadView` / `deleteView`) is the future contract for a SigNoz SavedView backend. |
| `frontend/src/admin/lib/signozUrl.ts` | `TAILNET_SIGNOZ_URL` + `TAILNET_SIGNOZ_LOGS_URL` constants. Single source of truth for the tailnet listener IP. |
| `frontend/src/admin/components/logs/LogsToolbar.svelte` | Query bar + service multi-select + severity chips + time picker + live toggle + copy-as-cURL. |
| `frontend/src/admin/components/logs/LogRow.svelte` | One row (32px fixed height, severity chip, trace link). |
| `frontend/src/admin/components/logs/LogTable.svelte` | Offset virtualization (20-row overscan) + scroll restoration. Fixed row-height invariant. |
| `frontend/src/admin/components/logs/JsonDrawer.svelte` | Overlay JSON viewer (absolutely-positioned, anchored to clicked row). NOT inline expansion -- preserves LogTable's row-height invariant. Dismisses on Esc / backdrop / X. |
| `frontend/src/admin/components/logs/FilterCheatsheet.svelte` | `?` opens, `Esc` closes. Lists every supported filter field with examples. |
| `frontend/src/admin/pages/Logs.svelte` | Page composition: header + tailnet-fallback strip + view dropdown + `<LogsToolbar>` + state machine (skeleton / error / empty / table) + `<JsonDrawer>` + `<FilterCheatsheet>`. |

### Dev proxy (Vite)

`frontend/vite.config.ts` proxies SigNoz paths directly to a configurable `VITE_SIGNOZ_URL` (default `http://127.0.0.1:8080`, the host port mapped from docker-compose's `signoz` service). The SigNoz rules MUST come BEFORE the catch-all `/api` rule that targets the IRC Fiber gateway -- the gateway does not speak SigNoz protocol.

| Proxy rule | Target | WS |
|---|---|---|
| `/api/v1/` through `/api/v5/` | `VITE_SIGNOZ_URL` | no |
| `/signoz/` | `VITE_SIGNOZ_URL` | yes (`ws:true`) |

Override at run time:
```bash
VITE_SIGNOZ_URL=http://100.126.197.92:3003 npm run dev:local
```

If `VITE_SIGNOZ_URL` is unset and no local SigNoz is running, the panel renders a clear empty state ("SigNoz URL not configured") rather than failing silently.

### Caddy (prod)

`deploy/roles/caddy/templates/Caddyfile.j2` is unchanged from the prior proxy setup:
- `/api/v1/` through `/api/v5/` -> `signoz-signoz:8080` with `header_up SIGNOZ-API-KEY "{$SIGNOZ_API_KEY}"`
- `/signoz/ws/logs/*` -> `signoz-signoz:8080` with `flush_interval -1` for live-tail WS upgrades (dedicated `handle_path` block, separate from the document tree so the WS upgrade cannot be intercepted by SigNoz's SPA shell)
- `/signoz/*` and `/signoz` document tree -> `signoz-signoz:8080` (kept so a future fallback link routed through Caddy resolves; not used by the native panel)
- `@signoz_static` matcher scopes `/assets/index-*` and `/css/*` to SigNoz hashed bundles so admin SPA assets are not shadowed

If `/etc/ircfiber/signoz-mcp/.api_key` is missing, the entire `{% if caddy_signoz_api_key %}` block in `Caddyfile.j2` is skipped (no startup error, just no proxy) -- re-run the `signoz_mcp` + `caddy` roles to enable.

### Tailnet fallback link

`Logs.svelte` renders an "Open SigNoz" link in the page header pointing to `TAILNET_SIGNOZ_LOGS_URL` (e.g. `http://100.126.197.92:3003/logs`). This is the deep link into the Tailscale-only SigNoz listener for features the native panel intentionally does not implement in v1: server-side saved views, pivots, anomaly overlays, query-builder joins. The IP literal lives only in `frontend/src/admin/lib/signozUrl.ts` -- do not hard-code it elsewhere.

### Saved views (localStorage)

`frontend/src/admin/stores/savedViews.ts` persists user-named query snapshots to `localStorage` under `ircfiber:admin:logs:views`. On quota error, the store prunes to the most-recent 50 views and surfaces a toast warning. The snapshot shape (`query`, `services`, `severities`, `timeRange`) deliberately matches `logsStore.ts`'s `LogsState` minus volatile fields so the future SigNoz SavedView backend swap keeps the public API stable.

### Rollout

```bash
# 1. Ensure signoz_mcp role has run so the API key file exists
ansible-playbook playbooks/signoz_mcp.yml -e vault_signoz_admin_password=...

# 2. Re-run the caddy role to render the route + pick up the key
ansible-playbook playbooks/site.yml --tags caddy

# 3. Build + ship the frontend (make update bundles on the remote)
make update

# 4. Verify REST
curl -fsS https://ircfiber.com/api/v1/services -H 'X-Requested-With: smoke' | head
# Should return JSON with the "IRC Fiber" service inventory
```

WS upgrade smoke test (should return `101 Switching Protocols`; `200` means the dedicated `/signoz/ws/logs/*` `handle_path` block in `Caddyfile.j2` is missing):
```bash
curl -i --http1.1 \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Version: 13' \
  https://ircfiber.com/signoz/ws/logs/v5/default
```

### Plan reference

Full task graph (18 tasks across 4 waves): [`docs/plan/20260630-admin-signoz-logs-panel/plan.yaml`](docs/plan/20260630-admin-signoz-logs-panel/plan.yaml). Wave 1 covers `signoz.ts` + `logsStore` + `savedViews` + Vite dev proxy + `signozUrl.ts`. Wave 2 covers the Svelte components (`LogRow`, `LogTable`, `JsonDrawer`, `LogsToolbar`, `FilterCheatsheet`, `Logs.svelte` rewrite). Wave 3 covers the WS preflight + `logsLiveTail` + Caddy WS audit. Wave 4 covers keyboard shortcuts, copy-as-cURL, empty/error states, and this `AGENTS.md` update.

## Engine priority and assignment architecture

`assignNetwork()` in `source/ircfiber/irc/registry.d` selects a server for new networks. Fixed from pure least-loaded to priority-aware:
- Higher `priority` wins
- `fallbackOnly` servers excluded unless no other healthy servers exist
- Tiebreaker: fewest assigned networks

Engine config overrides (`priority`, `fallbackOnly`, `maxConnections`) are stored in `irc:engine:config:<serverId>` in Redis. The engine reads them at boot and every 10s in the heartbeat loop. However, the heartbeat was only writing `lastHeartbeat`/`isHealthy` — the `data` field (containing priority etc.) was never synced to Redis. Fixed by adding `syncServerState()` which persists the full server record every heartbeat cycle.

Existing network assignments are sticky — they stay on the current server until explicitly reassigned (via admin API `/api/admin/servers/:id/reassign`) or the server dies. `healthCheckAll()` now has a Phase 3 that reconciles orphaned assignments: networks in `irc:assignments` that don't appear in the assigned server's `assignedNetworks` list are reassigned to a proper home.

## Server reboot behavior

Engine config overrides (`priority`, `fallbackOnly`, `maxConnections`) are stored in Redis keys `irc:engine:config:<serverId>`. Redis persists to disk, so these survive reboots. On server restart (all containers start simultaneously):

1. Redis/Mongo start first (host network mode)
2. Gateway + Engine containers start on `ircfiber_net` bridge network
3. Each engine reads its assigned networks from `irc:assignments` (Redis hash)
4. **Key fix**: During boot, if a lower-priority engine sees networks assigned to a higher-priority engine (but that engine hasn't heartbeated yet), it **defers reclaim** instead of stealing them (`bootstrap.d:216-224`). This prevents a lower-priority engine from taking over a higher-priority engine's networks during a full reboot.

All containers use `restart_policy: unless-stopped`, so `docker restart` on the host recovers everything automatically.

---

# IRC Fiber — Connection Holder Architecture

For the **enterprise-grade zero-disconnect hot-reload** solution, see [docs/CONNECTION_HOLDER.md](docs/CONNECTION_HOLDER.md). Key points:

- **Holder** (`ircfiber-conn-holder`) is a long-lived daemon owning IRC TCP/TLS sockets.
- **Engine** (`irc-fiber-engine`) is exec-reloadable, talks to holder via Unix-domain IPC.
- When engine hot-reloads, holder keeps IRC connection alive — IRC server sees ONE continuous connection.
- Enable via `IRCFIBER_HOLDER_SOCK` env var pointing to the shared Unix socket path.

## Holder mode is mandatory when configured

When `IRCFIBER_HOLDER_SOCK` is set, the engine **never** falls back to direct TCP if the holder daemon becomes unreachable. The connection loop throws `"Holder transport unavailable; will retry"` on every iteration until `handleDisconnection()` rebuilds the `HolderTransport` (a fast retry — the backoff is reset for this case so a transient holder restart costs at most 10 seconds, not the normal 15-minute exponential cap).

Why this matters: silently falling back to direct TCP would create a **second socket on the IRC server** that the holder still owns. Most IRC servers ghost one of the two connections, the engine would appear connected while being shadowed, and any subsequent hot-reload would have nothing to hand off (the canonical socket lives in the holder). The strict mode prevents this silent regression.

Deployments without a holder (the legacy direct-TCP path) are unaffected — `useHolderMode` is set per-client based on whether `enableHolderMode()` was called at boot.

## Holder health observability surface

When holder mode is active but the daemon is unreachable, the engine surfaces the degradation through five layers so operations gets paged instead of staring at "Connecting...":

| Surface | What it shows | Where |
|---|---|---|
| **Structured log** | `event:holder_missing` warning with `networkName`, `sinceMs`, `traceId`, `spanId` | `tail -f irc-fiber.log` |
| **OTel traces** | Dedicated spans `irc.holder.attempt`, `irc.holder.rebuild`, `irc.holder.strict_mode_throw`, `irc.holder.recovered` | SigNoz flamegraphs |
| **OTel metrics** | Counters `holder.unavailable_total`, `holder.recovered_total`, `holder.strict_mode_throws_total`; gauge `holder.missing_networks`; histogram `holder.recovery_duration_seconds` | SigNoz dashboards + alerts |
| **Heartbeat state** | `holderUnavailableFor:[...]` array on the `irc:server:<serverId>` record | Redis |
| **Admin API** | `GET /api/admin/servers/:id/holder-state` returns per-network holder health with `available`, `missingSince`, `lastError` | Admin SPA |

Logs carry `traceId`/`spanId` so a `holder_missing` log line in SigNoz is one click away from the flamegraph of the strict-mode throws that preceded it. The metrics pipeline (`source/ircfiber/observability.d`) exports to the same OTel collector as traces via `/v1/metrics` every 10 s from the heartbeat task.

Pinned tests:
- `make observability-test` — JSON shape of counter / gauge / histogram payloads against the OTLP 1.5 spec.
- `make connection-holder-strict-test` — JSON shape of the admin endpoint response.

## Build & test the holder

```bash
cd frontend  # actually run from project root
# Local fast tests (~25s)
./run-holder-tests.sh          # 4 tests: protocol, compile, raw IPC e2e, engine integration
./run-holder-enterprise-tests.sh  # 11 tests: health endpoints, graceful shutdown, multi-network, chaos
```

## Deploy the holder to OVH

```bash
bash scripts/deploy-holder-ovh.sh  # Builds remotely (Linux x86_64) + deploys both containers
```

## Key files

| File | Purpose |
|---|---|
| `source/conn_holder/main.d` | Holder entry point with graceful shutdown |
| `source/conn_holder/protocol.d` | Binary frame IPC protocol |
| `source/conn_holder/irc_client.d` | Per-network IRC connection (raw TCP / TLS) |
| `source/conn_holder/raw_fd_stream.d` | Vibe.d Stream wrapper for raw POSIX fd |
| `source/conn_holder/ipc_server.d` | Unix-domain socket IPC server |
| `source/conn_holder/client.d` | Engine-side HolderClient wrapper |
| `source/conn_holder/health_server.d` | Health/metrics HTTP server |
| `source/ircfiber/engine/holder_transport.d` | Engine-side IRC abstraction (same API as AdoptedSocket) |
| `scripts/deploy-holder-ovh.sh` | OVH deployment script |
| `docker-compose.holder.yml` | Two-container deployment |
| `deploy/playbooks/deploy-holder.yml` | Ansible playbook |

## ⚠️ Common pitfalls when modifying holder code

1. **Never use `usleep()` in a vibe.d fiber** — it blocks the entire event loop thread. Use `vibe.core.core.sleep(Duration)` instead.
2. **Never use raw `accept()`** — use non-blocking fd + `poll(timeout)` in a loop with `yield()`.
3. **TLSStream.read with IOMode.once returns 0 if no decrypted bytes pending** — this is NOT EOF. Check `leastSize > 0` first, or use `dataAvailableForRead` + a small throwaway buffer to trigger decryption.
4. **TLS empty read is a no-op** — pass at least 1 byte in the buffer.
5. **Always update ALL three ConnectionManager paths** when adding holder mode: `addNetwork`, `addAndStartNetwork`, AND `adoptFromHandoff`.
6. **Build D binaries on the target architecture** (Linux x86_64 for OVH) — local Mac ARM64 binaries won't run on Linux. Use BuildKit.
7. **When committing new binaries to a Docker image**, the original entrypoint is preserved. Override with `--entrypoint /app/mybin` when running the new container.
8. **DNS resolution**: use `getaddrinfo()` not `inet_pton()` if you want hostname support (IRC servers are hostnames, not IPs).

---

# IRC Fiber — Engine Janitor

The `EngineJanitor` (in `source/ircfiber/irc/engine_janitor.d`) prevents orphan-engine garbage from accumulating in Redis after a crash. Without it, dead engines leave `irc:state:<id>:*`, `scrollback:<id>:*`, and `dedup:<id>:*` keys forever — the gateway keeps routing to a dead server while the frontend renders a frozen ghost of the channel.

## How it works

Four layers run automatically in **every** gateway and engine process:

1. **TTL auto-expiry** — every per-engine state key gets `EXPIRE 600s`. The engine heartbeat bumps TTL every 10 s. A dead engine's state self-evicts within 10 min, even if no janitor ever runs.
2. **Distributed janitor** — every process tries to acquire `irc:janitor:lock` via `SET NX EX 30`. Holder runs the reap; losers yield. Lua scripts make the reap atomic against late heartbeats.
3. **Bootstrap purge** — on engine boot (skipping handoff), `purgeLocalServerNamespace(serverId)` SCANs+UNLINKs `*:<serverId>:*` so reusing a `serverId` after a crash doesn't carry garbage across epochs.
4. **Frontend staleness** — `lastSeenAt` per network, `isNetworkStale()` helper, grey "● stale" pill in the sidebar. Buffer cache in localStorage uses a 24 h TTL guard.

## Environment knobs

| Env var | Default | Range | Effect |
|---|---|---|---|
| `IRCFIBER_STATE_TTL` | 600 | 60–86400 | TTL on per-engine state keys (seconds) |
| `IRCFIBER_JANITOR_INTERVAL` | 60 | 5–3600 | Seconds between janitor cycles |
| `IRCFIBER_JANITOR_LOCK_TTL` | 30 | 5–300 | Distributed lock TTL |
| `IRCFIBER_BOOTSTRAP_PURGE` | 1 | 0/1 | Disable bootstrap-time namespace purge |
| `JSMIGRATE_DRY_RUN` | 1 | 0/1 | Migration tool: dry-run vs. apply |
| `IRCFIBER_MIGRATE_TTL` | 600 | 60–86400 | Migration tool TTL to apply |

Invalid values fall back to defaults with a `WARN:` line at startup.

## Build targets

```bash
# Run all 9 janitor tests
./run-janitor-tests.sh
# or
make janitor-tests

# Build the migration tool + run dry-run
make janitor-migrate

# Manually trigger / observe (admin session required)
make janitor-status
make janitor-audit
make janitor-cycle
make janitor-reap SERVER=testengine1
```

## Admin endpoints (gated behind admin session)

| Endpoint | Purpose |
|---|---|
| `GET  /api/admin/janitor/status` | Lock holder, actor, totals, last cycle |
| `GET  /api/admin/janitor/events?limit=100` | Recent audit events (most-recent-first) |
| `POST /api/admin/janitor/cycle` | Force one reap cycle right now |
| `POST /api/admin/janitor/reap/<serverId>` | Manually purge one server's namespace |

Audit events look like:
```json
{"ts":1782703502123,"kind":"engine_reap","serverId":"testengine1","actor":"pid:19490:host=zodiac-mbp","reason":"lease_expired","keysDeleted":42}
```
Stored in the `irc:janitor:events` Redis LIST (capped at 1000 via `LTRIM`).

## Test binaries

| Binary | Config | Tests |
|---|---|---|
| `janitor-test` | `dub build --config=janitor-test` | purge idempotency, basic reap |
| `janitor-lock-test` | `dub build --config=janitor-lock-test` | manualReap, lock mutual exclusion |
| `janitor-safety-test` | `dub build --config=janitor-safety-test` | getStatus, getRecentEvents, TTL bump |

`./run-janitor-tests.sh` builds all three and aggregates `[PASS]/[FAIL]/[SKIP]`.

## Deploy / rollout

```bash
# 1. (Optional) Backfill TTL on existing keys locally — already done by `make update` automatically
JSMIGRATE_DRY_RUN=1 ./janitor-migrate
JSMIGRATE_DRY_RUN=0 ./janitor-migrate

# 2. Deploy via your normal pipeline:
make update        # full deploy (engine + frontend + handoff + janitor-migrate + verification)
make handoff       # engine-only hot reload
make gateway-restart  # gateway-only reload

# Skip the migration step on a `make update`:
SKIP_MIGRATE=1 make update

# 3. Verify after deploy:
curl -s http://127.0.0.1:8090/api/admin/janitor/status
```

The migration step is **idempotent** — running it again is a no-op. When invoked through `make update`, the playbook:
1. Builds `janitor-migrate` cross-arch via BuildKit
2. Extracts to `/opt/ircfiber/bin/janitor-migrate` on the target
3. Waits 60 s for the new engine to register and start heartbeating
4. Runs `JSMIGRATE_DRY_RUN=1` (dry-run) and prints the result
5. Runs `JSMIGRATE_DRY_RUN=0` (apply) and prints the result
6. Waits one janitor cycle, then fetches `/api/admin/janitor/status` and prints it

Skipped automatically when `ircfiber_engine_id` is not defined (i.e. only the gateway is in scope).



# IRC Fiber — IRC Engine vs IRC Server Parity Tests

`tests/irc_parity/` holds end-to-end tests that drive the IRC Fiber engine
against real IRC servers (ngircd, UnrealIRCd + Anope) and a custom mock IRC,
then assert that the engine's stored state in Redis matches what the wire
protocol says. Use these to verify parity for IRC features (JOIN, NAMES, MODE,
kick, ban, services-style auto-op, etc.).

## Layout

- `tests/irc_parity/__init__.py` — `IrcClient` (minimal synchronous IRC
  client over raw TCP), `ParsedLine` (RFC 2812 line parser with IRCv3
  message-tag support), and `assert_user_prefix` / `wait_engine_snapshot_contains`
  helpers.
- `tests/irc_parity/test_irc_parity.py` — pytest scenarios. The first scenario
  verifies that a user auto-opped on JOIN by services is correctly recorded
  with the `@` prefix in the engine's `irc:state:<server>:<network>` Redis
  snapshot.
- `tests/irc_parity/fixtures/mock-irc-op/` — Dockerfile + server.py for a
  mock IRC server that simulates Anope/Chanserv auto-op on JOIN.

## Running

The parity tests are integration tests, so they require the docker-compose
stack to be running:

```bash
# Bring up redis, mongo, gateway, engine, and the IRC fixtures.
docker compose -f docker-compose.test.yml up -d redis mongo gateway engine mock-irc-op

# Port-forward mock-irc-op so the test runner (running on the docker host)
# can also reach it as 127.0.0.1:6667.
docker run -d --rm --name mock-irc-op \
  --network irc_fiber_irc_network -p 6667:6667 mock-irc-op:parity

pip3 install --break-system-packages pytest

# Run the parity tests
python3 -m pytest tests/irc_parity -v
```

By default the engine inside docker reaches the IRC server via the docker
service name (`mock-irc-op`). Override with `IRC_NETWORK_HOST_FOR_ENGINE` if
you point the engine at a different hostname.

## Adding a new parity scenario

```python
from tests.irc_parity import IrcClient, assert_user_prefix, wait_engine_snapshot_contains


def test_kick_removes_user_from_snapshot(scenario):
    # `scenario` fixture gives you a connected network with the engine
    # attached to the mock IRC server.
    ...

    # Wait up to 15s for the engine's snapshot to reflect the change.
    snapshot = wait_engine_snapshot_contains(
        redis_container="irc_fiber_redis",
        server_id="debugengine1",
        network_id=scenario["network_id"],
        predicate=lambda s: scenario["username"] not in (s or ""),
        timeout=15.0,
    )
```

The engine writes a fresh snapshot every 10 s, so predicates that depend
on the snapshot must allow up to ~12 s of latency.

# IRC Fiber — Member List Operator Status Fix

Fix for: "It does not show me as having Operator status in the members list
when I join a channel. The members list does not update my Operator status in
real-time, nor does it update if I hard refresh."

## Root cause

Three independent bugs combined to drop the IRC prefix char (`@`, `+`, `%`,
etc.) from users' nicks stored in the member list:

1. **Frontend MODE handler was parsing the wrong param.** IRCv3 wires
   `MODE #chan +o alice` as `params = ["#chan", "+o", "alice"]`, but the
   handler read `params[0]` as the mode string — which is the channel name.
   This corrupted the prefix update path on every channel MODE event.

2. **`normalizeUser` stripped the prefix on snapshot round-trip.** When
   the engine sent `users: ["@alice"]` over the WebSocket, the handler
   converted it to `{ nick: "alice", prefix: "@", ... }` and the
   `<span class="member-nick">{member.nick}</span>` template then displayed
   the bare nick. Hard refresh = fresh sync = bug on every reload.

3. **Engine `channelUsers` dedup was exact-match.** A race between the
   self-JOIN handler (which added `user` bare) and the server's 353
   (which arrived as `@user` prefixed) left two entries in
   `channelUsers`. The frontend's `updateNetworkFromSync` then deduped by
   stripped nick and kept the FIRST one — the bare entry from JOIN —
   dropping the op prefix.

## Fixes

- `frontend/src/stores/ircStore.svelte.ts`
  - `updateChannelUsers` MODE branch now reads `params[0]` as the target
    and `params[1]` as the mode string, with a guard so a user-mode
    `MODE nick :+i` is a no-op for the channel user list.
  - 353 handler now does **in-place promotion** in place of the
    skip-if-exists path: when a NAMES entry's bare nick already exists
    in the buffer, the existing entry's `nick` is rewritten to the
    prefixed form and its `prefix` / `category` are updated.
  - `normalizeUser` (the snapshot-path converter) now stores `nick: user`
    (preserving the IRC prefix char) instead of `nick: bareNick`. The
    `prefix` and `category` fields are still set so sorting and the
    ops/voiced/halfop category grouping keep working.
  - `MemberList.svelte` renders `{member.nick}` so users with a prefix
    display their `@` / `+` / `%` / `&` / `~` / `!` indicator.

- `source/ircfiber/irc/connection.d`
  - JOIN handler now does stripped-nick dedup (was exact-match) so a
    prior prefixed entry is not shadowed.
  - 353 handler does stripped-nick dedup with in-place promotion to
    the prefixed form, so a services-granted op survives the snapshot.
  - MODE handler accepts `O` (IRC Operator) in addition to `qaohv`.

## Tests

- `frontend/src/stores/ircStore.mode-bug.test.ts` — 4 regression tests
  for the MODE-handler param bug.
- `tests/irc_parity/test_irc_parity.py` — end-to-end test that drives
  the engine against a mock IRC server auto-opping joiners and asserts
  the engine's `irc:state:<server>:<network>` snapshot contains `@user`
  (single entry, no bare duplicate).
- All existing unit tests still pass: 604 client + 379 lib vitest tests.

# IRC Parity Testing — Findings and Bugs

`tests/irc_parity/` holds end-to-end tests that drive the IRC Fiber engine
against the in-repo docker-compose stack (mock-irc-op, ircd-test,
unreal_sasl + Anope, redis, mongo, gateway, engine) and verify the engine's
stored state matches the wire protocol.

## Mock-irc-op (configurable synthetic IRCd)

The mock-irc-op fixture (`tests/irc_parity/fixtures/mock-irc-op/`) is a
Python-based IRCd that simulates Anope/Chanserv-style auto-op on JOIN.
The mock IRC supports the full lifecycle: NICK, USER, JOIN, 353 (with
NAMES), 366, PART, KICK, NICK change, TOPIC, MODE (channel and user),
WHOIS (311), 433 (NICKNAMEINUSE), PING/PONG, QUIT, PRIVMSG.

## Tests

`tests/irc_parity/test_irc_parity.py` has 10 scenarios, 9 passing:

- `TestMockIrcOperator::test_user_appears_with_prefix_after_join` — PASS
  Mock IRC auto-ops joiner; engine shows @user in snapshot.
- `TestKickRemovesUser::test_kick_removes_user` — PASS
  A 2nd user kicks the engine user; engine removes them from the snapshot.
- `TestPartRemovesUser::test_part_removes_user` — PASS
  Engine PARTs; engine removes from the snapshot.
- `TestModeChange::test_deop_via_mode_minus_o` — PASS
  A 2nd user issues MODE -o on the engine user; engine updates snapshot.
- `TestModeChange::test_voice_via_mode_plus_v` — PASS
  MODE +v sets the engine user's voice prefix; engine updates snapshot.
- `TestModeChange::test_multi_target_mode` — **FAIL** (bug, see below)
- `TestTopic::test_topic_set_and_seen` — PASS
  A 2nd user sets a channel topic; engine captures it in `topics`.
- `TestNickChange::test_other_user_nick_change_visible_in_snapshot` — PASS
  A 2nd user changes their nick; engine updates the snapshot with the new
  nick.
- `TestMultipleUsers::test_multiple_users_in_roster` — PASS
  Multiple users in the same channel all appear in the engine's roster.
- `TestNickInUse::test_engine_handles_433_gracefully` — PASS (trivially;
  no negative scenario exercised).

## Known bugs discovered

### BUG #1: Engine doesn't track the status of users who join AFTER it

When a user joins a channel where the engine is already present, the
engine only sees the JOIN message (no NAMES list, since 353 is only sent
to the joining user). The engine's JOIN handler at
`source/ircfiber/irc/connection.d:2484-2522` stores the user as bare (no
prefix):

```d
} else {
    channelUsers[chan] ~= event.nick;  // bare nick, no prefix
    ...
}
```

When the server later issues a multi-target MODE like `MODE #chan +vv user1 user2`,
the MODE handler at `source/ircfiber/irc/connection.d:2904` only updates the
user1 entry (which has a prefix from the engine's own 353); user2 is
stored as bare and the MODE doesn't change it.

**Reproduction**: `tests/irc_parity/test_irc_parity.py::TestModeChange::test_multi_target_mode`
The snapshot after the test shows `+engine_user, mod, helper` — the helper
should be `+helper` but stays bare.

**Fix ideas** (none implemented yet):
1. Issue a `WHO %channel` after a JOIN broadcast to discover each user's
   status, and re-promote the channel roster entry with the discovered
   prefix.
2. Issue `NAMES #chan` periodically to refresh the roster.
3. Parse IRCv3 `extended-monitor` or `account-notify` to track which
   nicks are services-identified, but those don't carry mode prefixes.
4. Conservatively: when a `MODE +X` is processed and the target user is
   stored bare, mark the target user with a placeholder so the snapshot
   doesn't lie about who has what mode.

### BUG #2 (related): Engine's MODE handler runs before the engine sees the
   joining user's status

Even with bug #1 fixed, the race is: the helper sends JOIN → mock IRC
broadcasts the helper's JOIN to the engine → engine adds `helper` bare →
mod sends MODE +vv engine helper → engine processes MODE.

If the helper's 353 (with prefix) hasn't yet arrived at the engine when
the MODE is processed, the engine can't apply the prefix. The
`test_voice_via_mode_plus_v` test works only because mod joined BEFORE
the helper and was in the roster when the MODE was processed.

## Setup

```bash
docker compose -f docker-compose.test.yml up -d redis mongo gateway engine ircd-test mock-irc-op

# Or start the existing stack (unreal_sasl + Anope) and use it instead of
# ircd-test / mock-irc-op:
docker run --rm -d --name mock-irc-op --network irc_fiber_irc_network -p 6667:6667 \
  $(docker build -q tests/irc_parity/fixtures/mock-irc-op)

docker run --rm -d --network irc_fiber_irc_network --name irc_fiber_engine \
  -e IRCFIBER_REDIS_URL=redis://irc_fiber_redis:6379/0 \
  -e IRCFIBER_MONGO_URL=mongodb://irc_fiber_mongo:27017/ircfiber \
  -e IRCFIBER_LOG_LEVEL=debug \
  -e IRCFIBER_SERVER_ID=debugengine1 \
  irc-fiber:latest /app/irc-fiber-engine

docker run -d --network irc_fiber_irc_network --name irc_fiber_gateway -p 8090:8090 \
  -e IRCFIBER_REDIS_URL=redis://irc_fiber_redis:6379/0 \
  -e IRCFIBER_MONGO_URL=mongodb://irc_fiber_mongo:27017/ircfiber \
  irc-fiber:latest /app/irc-fiber

# Deploy the latest frontend
docker cp public/dist/. irc_fiber_gateway:/app/public/dist/

pip3 install --break-system-packages pytest

# Run the parity tests
python3 -m pytest tests/irc_parity/test_irc_parity.py -v
```

## Using the real unreal_sasl + Anope stack

The unreal_sasl container has Anope services linked. To exercise the
auto-op-on-JOIN scenario against real services, register a nick with
NickServ (no email confirmation needed), identify, register a channel,
give yourself SOP, and have the engine connect with SASL PLAIN as that
same nick. The engine's network config requires `sasl: "plain"`,
`saslUsername: "<nick>"`, `saslPassword: "<password>"`.

A reference test for this flow is sketched in
`tests/irc_parity/test_real_services.py` (not currently runnable in
the in-repo docker stack because the engine's SASL handshake with
unreal_sasl needed a different password and the engine's connection
flickered under repeated test runs; this is a work-in-progress).

# IRC Fiber — Distroless OTel collector healthcheck pattern

The `ircfiber-signoz-ingester` (and the bridge `ircfiber-otel-collector`)
both use `otel/opentelemetry-collector-contrib`, which is a **distroless**
image: no shell, no wget, no nc, no `/bin/sh`. Docker compose v2 healthchecks
only support `CMD`, `CMD-SHELL`, and `NONE` — and `CMD-SHELL` rewrites to
`/bin/sh -c …` internally, which immediately fails on a distroless image
(`exec: /bin/sh: no such file`), leaving the container marked unhealthy
forever even when the collector is happily accepting OTLP.

Right pattern for a distroless collector healthcheck:

```yaml
healthcheck:
  test: ["CMD", "/otelcol-contrib", "validate", "--config=/etc/otel-collector-config.yaml"]
  interval: 60s
  timeout: 5s
  retries: 3
  start_period: 30s
```

This probes **config validity**, not liveness — `validate` only checks that
the YAML parses. That's actually what we want for "container is broken":
if the config is malformed, `validate` exits 1 and Docker marks the
container unhealthy (visible in `docker ps`). If the collector process
crashes mid-flight, `restart: unless-stopped` (via `x-logging-common` in
`docker-compose.logging.yml.j2`) brings it back; the bridge collector will
show `connection-refused` against OTLP if the listener is down, which is
the real liveness signal at the application layer.

Also: the `clickhouse` exporter in the OTel collector runs `CREATE DATABASE`
on startup to bootstrap the schema, so it crashes once if ClickHouse
isn't ready yet (typically ~5–15s after the container starts). Docker
`restart: unless-stopped` handles this in 1–2 retries — no `depends_on:
condition: service_healthy` needed, because that would require the
healthcheck above to be live (and we just said it can't be).

See `deploy/roles/logging/templates/docker-compose.logging.yml.j2` for
the deployed config.

## IRC Fiber — Observability

The IRC Fiber stack uses **SigNoz** as its single observability store for
logs, traces, and metrics. Grafana is retained as a cross-data-source
dashboard layer, configured to query SigNoz via the Infinity datasource
plugin (`yesoreyeram-infinity-datasource`) at `signoz-signoz:8080`.

### Architecture

```
┌─────────────────┐     OTLP HTTP      ┌──────────────┐
│  Fluent Bit     │ ──────────────────► │              │
│  (container     │     port 4318       │  signoz-     │
│   log tailer)   │                     │  ingester    │
└─────────────────┘                     │  (OTLP       │
                                        │   receiver)  │
┌─────────────────┐     OTLP HTTP      │              │
│  IRC Fiber      │ ──────────────────► │              │
│  Engine/Gateway │     port 4318       │              │
│  (D processes)  │                     └──────┬───────┘
└─────────────────┘                            │
                                     ┌─────────▼─────────┐
                                     │  signoz-query-     │
                                     │  service           │
                                     │  port 8080 (int)   │
                                     │  port 3301 (host)  │
                                     └──┬──────┬──────┬───┘
                                        │      │      │
                          ┌─────────────┘      │      └─────────────┐
                          ▼                    ▼                    ▼
                   ┌──────────┐        ┌────────────┐       ┌──────────────┐
                   │ ClickHouse│        │ SigNoz     │       │ Grafana      │
                   │ (storage) │        │ Frontend   │       │ (dashboards) │
                   └──────────┘        └────────────┘       └──────────────┘
```

**Data paths:**

| Signal | Source | Destination | Protocol |
|---|---|---|---|
| Logs | Fluent Bit (Docker log tailer) | signoz-ingester:4318 | OTLP HTTP |
| Logs (Caddy access) | Bridge otel-collector (filelog/caddy receiver) | signoz-ingester:4317 | OTLP gRPC |
| Traces | Engine/Gateway (D tracing.d) | signoz-ingester:4318 (local dev) or bridge (prod) | OTLP HTTP |
| Metrics | Bridge otel-collector (hostmetrics + docker_stats receivers) | signoz-ingester:4317 | OTLP gRPC |

In **production**, the bridge (`ircfiber-otel-collector`, deployed by the
`signoz_bridge` role) sits on both `ircfiber_net` and `ircfiber_logging`
networks, proxying OTLP from D services to signoz-ingester. In **local dev**
the engine/gateway write OTLP directly to `signoz-ingester:4318`.

### Port clarification

| Port | Service | Bind | Purpose |
|---|---|---|---|
| 3301 | signoz-query-service | host:3301 | SigNoz REST API + UI access (dev) |
| 8080 | signoz-query-service | container:8080 | Internal query-service API (no host map) |
| 4317 | signoz-ingester | container:4317 | OTLP gRPC intake (bridge export target) |
| 4318 | signoz-ingester | container:4318 | OTLP HTTP intake (Fluent Bit + engine) |
| 13133 | signoz-ingester | container:13133 | Health check endpoint |

### File layout

| File | Purpose |
|---|---|
| `deploy/roles/signoz_bridge/defaults/main.yml` | Bridge container defaults (image, ports, networks, resources) |
| `deploy/roles/signoz_bridge/tasks/main.yml` | Ansible tasks: network join, container create, healthcheck |
| `deploy/roles/signoz_bridge/templates/otel-collector-config.yaml.j2` | OTel collector config: OTLP receivers, hostmetrics, docker_stats, filelog/caddy, transform/newrelic, redaction, batch export |
| `deploy/roles/logging/templates/fluent-bit.conf.j2` | Production Fluent Bit config (Docker JSON log tail, engine_json parser, docker metadata enrichment, OTLP output) |
| `deploy/local/fluent-bit.conf` | Dev Fluent Bit config (minimal — no docker socket enrichment) |
| `deploy/roles/logging/defaults/main.yml` | Versions, container names, resource limits, alert gating |
| `deploy/roles/logging/tasks/main.yml` | Orchestration: network/volume creation, template rendering, compose deploy, healthchecks |
| `deploy/roles/logging/templates/docker-compose.logging.yml.j2` | SigNoz Foundry + Grafana docker-compose template (production) |
| `deploy/roles/logging/templates/grafana-datasources.yml.j2` | Grafana SigNoz datasource via Infinity plugin |
| `deploy/roles/logging/templates/grafana-dashboards.yml.j2` | Grafana dashboards provider config |
| `deploy/roles/logging/files/dashboards/` | 6 Grafana dashboard JSON definitions |
| `deploy/roles/signoz_alerts/files/alert_rules.yml` | SigNoz alert rules (7 host + container + service alerts) |
| `deploy/roles/logging/tasks/deploy-alerts.yml` | Ansible alert deployment (gated by `deploy_signoz_alerts`) |
| `deploy/roles/logging/tasks/cleanup-old-stack.yml` | Remove old Loki/Promtail/Tempo/otel-collector/Prometheus |

### Grafana

Repurposed from the old Loki+Tempo+Prometheus setup. Now uses **SigNoz**
as its sole provisioned datasource via the Infinity plugin:

```yaml
datasources:
  - name: SigNoz
    type: yesoreyeram-infinity-datasource
    url: http://signoz-signoz:8080
```

Provisioned dashboards (6):

| Dashboard | Focus |
|---|---|
| `container-health.json` | Docker container CPU/memory/restart counts |
| `irc-bugs-errors.json` | Error rate by service, top error messages |
| `irc-connection-lifecycle.json` | Connection events, disconnects, reconnects |
| `irc-distributed-traces.json` | Trace waterfall, span duration, service map |
| `irc-handoff.json` | Handoff duration, socket counts, TLS vs plain |
| `irc-protocol-events.json` | JOIN/PART/KICK/MODE event rates |

The `GF_INSTALL_PLUGINS` env var installs `yesoreyeram-infinity-datasource`
at Grafana boot.

### Local dev

Docker Compose at `deploy/local/docker-compose.yml` brings up 11 containers
on the `ircfiber_local` bridge (172.28.0.0/16):

```
redis, mongo, signoz-clickhouse, signoz-query-service, signoz-ingester,
signoz-frontend, signoz-alertmanager, fluent-bit, ircfiber-gateway,
ircfiber-engine, ircd
```

Makefile targets:

```bash
# Start
make local-dev-up           # docker compose up -d

# Smoke test (gateway health + SigNoz API + OTLP ingestion + Fluent Bit)
make local-dev-smoke

# Access points:
# - SigNoz UI/REST: http://localhost:3301
# - Gateway health: http://localhost:8090/health
# - Admin panel: http://localhost:5173 (via `npm run dev:local`)
# - IRC daemon: localhost:6667

# Stop
make local-dev-down        # preserves data volumes
make local-dev-down-clean  # wipes ClickHouse data too
```

See `deploy/local/README.md` for full instructions, prerequisites, and troubleshooting.

### Alert rules

14 Loki alert rules were migrated to SigNoz LOGS_BASED_ALERT rules
(gated under `deploy_signoz_alerts: true` in the logging role).

Rule definitions: `deploy/roles/logging/signoz-alerts.yml.j2`
Deployment: `deploy/roles/logging/tasks/deploy-alerts.yml`

| Rule | Filter | Threshold | Severity |
|---|---|---|---|
| IrcfiberTLSFailures | `attribute.event = 'tls_fail'` | >3 in 5m | warning |
| IrcfiberReconnectStorm | `attribute.event = 'reconnect_scheduled'` | >10 in 5m | warning |
| ... (14 total) | See signoz-alerts.yml.j2 for full table | | |

### Configuration & cleanup

The old Loki/Promtail/Tempo/Prometheus stack was removed in favor of
SigNoz + Fluent Bit. The opt-in cleanup task at
`deploy/roles/logging/tasks/cleanup-old-stack.yml` removes remaining
containers, volumes, and config directories.

### Plan reference

Full task graph (14 tasks across 4 waves):
[`docs/plan/20260701-signoz-unified-observability-and-local-docker/plan.yaml`](docs/plan/20260701-signoz-unified-observability-and-local-docker/plan.yaml)
