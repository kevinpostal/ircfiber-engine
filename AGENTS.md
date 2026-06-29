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
5. Old engine sends `DONE <count>`, marks itself `draining:true` in Redis, exits cleanly (rc=0)
6. New engine adopts all FDs, replays state, publishes `CONNECTED` synthetic events
7. **TLS connections:** FD transfer is impossible (TLS session state is in userspace). The new engine does a soft-reconnect (Happy Eyeballs → TLS → CAP → SASL → JOIN) and publishes a `DISCONNECTED` synthetic event before reconnecting

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
| `source/ircfiber/engine/reload_orchestrator.d` | `adoptFromOldEngine` (client) + `serveReload` (server) + `triggerHandoff` |
| `source/ircfiber/engine/adopted_socket.d` | Thin POSIX fd wrapper replacing `TCPConnection` for adopted sockets |
| `source/ircfiber/irc/connection.d` | `pauseForHandoff/resumeAfterHandoff/snapshotForHandoff/adoptAndStart` |
| `source/ircfiber/irc/manager.d` | `pauseAllForHandoff/snapshotAllForHandoff/adoptFromHandoff` |
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
4. **Key fix**: During boot, if a lower-priority engine sees networks assigned to a higher-priority engine (but that engine hasn't heartbeated yet), it **defers reclaim** instead of stealing them (`bootstrap.d:216-224`). This prevents backup1 from taking over OVH's networks during a full reboot.

All containers use `restart_policy: unless-stopped`, so `docker restart` on the host recovers everything automatically.

---

# IRC Fiber — Connection Holder Architecture

For the **enterprise-grade zero-disconnect hot-reload** solution, see [docs/CONNECTION_HOLDER.md](docs/CONNECTION_HOLDER.md). Key points:

- **Holder** (`ircfiber-conn-holder`) is a long-lived daemon owning IRC TCP/TLS sockets.
- **Engine** (`irc-fiber-engine`) is exec-reloadable, talks to holder via Unix-domain IPC.
- When engine hot-reloads, holder keeps IRC connection alive — IRC server sees ONE continuous connection.
- Enable via `IRCFIBER_HOLDER_SOCK` env var pointing to the shared Unix socket path.

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

