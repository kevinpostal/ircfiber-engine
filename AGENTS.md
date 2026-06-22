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
