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
├── source/                  D backend (LDC2)
│   ├── ircfiber/
│   │   ├── api/             REST + WebSocket endpoints
│   │   ├── auth.d           Authentication / sessions
│   │   ├── db/              MongoDB models (user, network, messages, prefs, pastebins, uploads)
│   │   ├── engine/          Event consumer / processor / state
│   │   ├── irc/             IRC client (connection, registry, manager, SASL, CHATHISTORY, reconnect)
│   │   ├── models/          Domain types (IRCEvent, Message, Network, User, IRCChannel)
│   │   ├── redis/           Redis protocol / client
│   │   ├── storage/         Buffer / session / redis storage layer
│   │   ├── upload/          Local file upload handler
│   │   └── web/             HTTP routes / static / WebSocket
│   ├── app.d                App entry point (gateway)
│   └── app_engine.d         App entry point (IRC engine)
├── views/                   Diet templates (layout, index, login, register, message_fragment)
├── frontend/                Svelte 5 + Vite
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
│   ├── e2e/                 Playwright E2E specs
│   ├── index.html
│   ├── package.json
│   ├── svelte.config.js
│   ├── tsconfig.json
│   └── vite.config.ts
├── public/                  Static assets + built frontend output
│   ├── dist/                Vite build output
│   ├── fonts/               Source Sans Pro (woff2)
│   └── favicon*
├── config/                  dev.conf / prod.conf
├── docker/                  Dockerfiles + ngircd config
├── e2e/                     Top-level Playwright specs
├── data/                    Local dev data (networks.json, users.json)
├── Makefile                 50+ targets: build, run, docker, test, dscanner, cross-compile
├── Containerfile            Multi-arch build
├── docker-compose.yml       Full stack
├── docker-compose.test.yml  Test stack
├── dub.sdl                  D build config
└── README.md
```

## Architecture

Two processes:

- **Gateway** (`app.d`) — HTTP + WebSocket server, sessions, user preferences, static frontend.
- **Engine** (`app_engine.d`) — Maintains persistent IRC connections, parses server traffic, fans events out via Redis pub/sub.

The frontend talks to the gateway over WebSocket; the gateway forwards events to the browser, persists messages to MongoDB, and stores ephemeral state in Redis.

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
make dscanner-all
```

## License

MIT — see [dub.sdl](dub.sdl).
