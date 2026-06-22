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
