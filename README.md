# IRC Fiber

A modern, self-hosted IRC bouncer and web client with an IRCCloud-style UI. Connect to multiple IRC networks, persist message history, and access your chats from anywhere via a web browser.

## Highlights

- **Multi-network bouncer** — Stay connected to IRC networks 24/7, replay history on demand.
- **IRCCloud-style web UI** — Sidebar, chat list, member panel, MOTD rendering, and message grouping modeled on IRCCloud.
- **WebSocket real-time** — Live message delivery, typing indicators, member list sync.
- **Message history** — Backfill via IRCv3 `CHATHISTORY` extension with a load-more button.
- **Snippets, uploads, pastebins** — Built-in sharing tools.
- **User accounts** — Per-user preferences, pinned buffers, network collapse state.
- **Cross-platform** — Native binary via LDC, Docker images for amd64/arm64/armv7.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | D (LDC2) on [vibe-d](https://vibed.org/) (Redis + MongoDB) |
| Frontend | Svelte 5 + TypeScript, Vite |
| Styling | SCSS (split into partials under `frontend/src/styles/`) |
| Templates | [Diet-NG](https://github.com/rejectedsoftware/diet-ng) |
| Icons | Font Awesome 6 |
| Monospace | Hack font |
| E2E tests | Playwright |
| Unit tests (FE) | Vitest |

## Quick Start

### Native build (macOS / Linux)

```bash
# 1. Install D compiler + dub
#    macOS:  brew install ldc dub
#    Linux:  apt install ldc dub (or use your distro's package)

# 2. Start the backing services (Redis + MongoDB)
make docker-up-backend

# 3. Build & run
make
```

Open `http://localhost:8080` and sign up.

### Docker

```bash
make docker-up         # full stack (gateway, engine, redis, mongo, test ircd)
make docker-down       # stop everything
```

## Project Structure

```
IRC_FIBER/
├── backend/                 D vibe.d REST API — HTTP + WebSocket + Admin (gateway)
│   ├── source/
│   │   ├── app.d            Gateway entry point (listenHTTP + router + WS)
│   │   └── ircfiber/
│   │       ├── api/         REST + WebSocket + session (rest.d, websocket.d, session.d)
│   │       ├── web/         HTTP routes + Admin SPA + Diet handlers (web/, admin/*, common.d)
│   │       ├── auth.d       Password hashing / session auth
│   │       ├── storage/session.d  Redis session store (14-day TTL)
│   │       └── upload/      Local file upload handler
│   ├── views/               Diet templates (layout, index, login, register, message_fragment, admin/*)
│   ├── dub.sdl              Gateway build config (depends on ../common)
│   └── dub.selections.json
├── common/                  D shared library — inter-service contract + models + storage
│   ├── source/ircfiber/
│   │   ├── redis/protocol.d  RedisKeys, IRCCommand, ControlMessage, NetworkStateSnapshot, StateTTL
│   │   ├── models/          Domain types (IRCEvent, Message, Network, User, IRCChannel)
│   │   ├── db/              Mongo models (user, network, messages, prefs, pastebins, uploads)
│   │   ├── storage/         Redis + buffer (buffer.d, redis.d) — scrollback & dedup
│   │   ├── irc/             ServerRegistry + ConnectionServer + EngineJanitor (shared)
│   │   ├── logging.d, tracing.d, observability.d, async.d, threadpool.d, resource.d, default_network.d
│   │   └── ...
│   ├── dub.sdl              Library config (targetType library)
│   └── dub.selections.json
├── engine/                  D IRC engine daemon — persistent IRC connections
│   ├── source/
│   │   ├── app_engine.d     Engine entry point (bootstrap + consumers + handoff)
│   │   └── ircfiber/
│   │       ├── irc/         IRC client (connection, manager, parser, SASL, CHATHISTORY, reconnect, tls_safe)
│   │       └── engine/      Event loop (bootstrap, consumer, processor, state, handoff, reload_orchestrator)
│   ├── dub.sdl              Engine build config (depends on ../common)
│   └── dub.selections.json
├── frontend/                Svelte 5 + Vite — enterprise SPA
│   ├── src/
│   │   ├── components/      Svelte components (Sidebar, ChatArea, MessageRow, etc.)
│   │   ├── lib/             Utility modules (autolinker, ircFormatting, messageBuilder, …)
│   │   ├── stores/          Svelte stores (ircStore, preferences, wsConnection, …)
│   │   ├── styles/          SCSS partials
│   │   │   ├── base/
│   │   │   ├── components/
│   │   │   ├── layout/
│   │   │   └── themes/
│   │   ├── test/            Vitest helpers (factories, mocks, context helpers)
│   │   ├── App.svelte
│   │   ├── app.css
│   │   ├── main.ts
│   │   └── types.ts
│   ├── index.html
│   ├── package.json
│   ├── svelte.config.js
│   ├── tsconfig.json
│   ├── vite.config.ts       (publicDir: ../public, outDir: ../public/dist)
│   └── README.md            Frontend docs
├── public/                  Static assets + Vite build output (served by backend)
│   ├── dist/                Vite build output (backend serves at /public/dist + /assets/*)
│   ├── fonts/               Source Sans Pro (woff2)
│   └── favicon*
├── config/                  dev.conf / prod.conf (shared by backend + engine)
├── Makefile                 Top-level (backend + engine + common + frontend, 50+ targets)
├── Containerfile            Multi-stage BuildKit (base → builder[common+backend+engine] → runtime-gateway + runtime-engine)
├── docker-compose.yml       Full stack (gateway + engine + redis + mongo + ircd)
├── docker-compose.test.yml  Test stack
└── README.md
```

## Architecture

Three D packages + one SPA:

- **Gateway** (`backend/source/app.d`) — vibe.d HTTP + WebSocket server, sessions, user preferences, static frontend. Build with `dub --root=backend`.
- **Common** (`common/source/ircfiber/redis/protocol.d`, `common/source/ircfiber/models/*`, `common/source/ircfiber/db/*`) — inter-service contract (`RedisKeys`, `IRCCommand`, `NetworkStateSnapshot`), shared models, storage, observability. `dub --root=common` builds a library; both gateway and engine depend on it via `path="../common"`.
- **Engine** (`engine/source/app_engine.d`) — Maintains persistent IRC connections, parses server traffic, fans events out via Redis pub/sub. Build with `dub --root=engine`.

The frontend (`frontend/`, Svelte 5 + Vite) talks to the gateway over WebSocket; the gateway forwards events to the browser, persists messages to MongoDB, and stores ephemeral state in Redis. Swapping the gateway language (Node, Django, etc.) only requires re-implementing the `common` contract (Redis keys + `irc:stream`/`irc:events` + `NetworkStateSnapshot` JSON) — the engine and frontend stay unchanged.

### Graceful Engine Hot-Reload

The engine supports **zero-disconnect hot-reload** (`make engine-handoff`). On save:
1. A new engine process starts alongside the old one
2. The old engine pauses its event loops, serialises each connection's state (channels, caps, nicks), and **transfers the raw TCP socket FD** to the new engine via Unix `SCM_RIGHTS`
3. The new engine replays the state and resumes I/O on the adopted sockets
4. IRC connections are **never closed** — the server sees no quit/rejoin
5. TLS connections (where FD transfer is impossible) do a fast soft-reconnect (~1-2s, automatic)

See `AGENTS.md` for the full protocol specification.

## Make Targets

Run `make` (or `make help`) to list all targets. Highlights:

| Target | What it does |
|--------|--------------|
| `make` / `make build` | Build the D backend + Svelte frontend |
| `make frontend` | Build the Svelte bundle only |
| `make frontend-dev` | Run Vite dev server with HMR |
| `make up` | Build and start gateway + engine in background |
| `make down` | Stop background processes |
| `make run` | Build and run in the foreground |
| `make test` | Run D backend unit tests |
| `make test-frontend` | Run Vitest (lib + client) |
| `make docker-up` | Start full stack (incl. test IRCD) via Docker |
| `make docker-shell-mongo` | Open mongosh against the DB |
| `make dscanner-all` | D-Scanner syntax / lint / complexity |
| `make watch-engine` | Auto-rebuild engine + graceful hot-reload on save (preserves IRC sockets) |
| `make engine-handoff` | Graceful engine hot-reload (transfer FDs, no disconnect) |
| `make engine-handoff-redis` | Trigger handoff via `redis-cli LPUSH` (remote/scripting) |
| `make engine-restart` | Hard restart (closes sockets, forces reconnect) |
| `make cross-linux-arm64` | Cross-compile for Linux ARM64 |

## Development

### Frontend tests

```bash
cd frontend
npm test                # all tests
npm run test:lib        # pure-utility tests, fast
npm run test:client     # Svelte component tests (Playwright/Chromium)
npm run test:watch      # watch mode
```

### E2E tests (Playwright)

```bash
cd e2e
npx playwright test                    # all specs
npx playwright test scrollback.spec.js # one spec
```

### Code quality (D)

```bash
make dscanner-syntax
make dscanner-lint
make dscanner-unused
MIT — see [backend/dub.sdl](backend/dub.sdl) + [common/dub.sdl](common/dub.sdl) + [engine/dub.sdl](engine/dub.sdl).
