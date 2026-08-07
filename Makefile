# ============================================================================
# IRC Fiber Makefile
# ============================================================================
# Best practices:
# - Use ?= for environment-overridable variables
# - Use := for immediate expansion
# - Explicit .DEFAULT_GOAL
# - .DELETE_ON_ERROR for cleanup on failure
# ============================================================================

.DELETE_ON_ERROR:
.DEFAULT_GOAL := help

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
DUB         := dub --root=engine
DUB_COMMON  := dub --root=common
DUB_BACKEND := dub --root=backend
DUB_ENGINE  := dub --root=engine
LDC         := ldc2
APP         := backend/irc-fiber
GATEWAY_IMAGE ?= irc-fiber-gateway
ENGINE_IMAGE  ?= irc-fiber-engine
GATEWAY_APP := backend/irc-fiber
ENGINE_APP  := engine/irc-fiber-engine
DUB_PKG     := $(HOME)/.dub/packages

# Dev backend selection for `make run` / `make start` / `make dev`.
# Default is `tailnet` — points the Vite dev server at the tailnet
# gateway (https://ircfiber-ovh-1.tail544547.ts.net). Override per-call:
#
#   make run                      # tailnet (default)
#   make run-tailnet              # explicit tailnet
#   make run-local                # local docker-compose (http://127.0.0.1:8090)
#   make run BACKEND=local        # same as run-local, no separate target
#   make run BACKEND=https://x     # custom backend URL
#
# For the D backend runner (the previous `make run`), use `make run-gateway`.
BACKEND ?= local
VITE_BACKEND_URL ?= https://ircfiber-ovh-1.tail544547.ts.net

ifeq ($(BACKEND),tailnet)
  EFFECTIVE_BACKEND_URL := https://ircfiber-ovh-1.tail544547.ts.net
else ifeq ($(BACKEND),local)
  EFFECTIVE_BACKEND_URL := http://127.0.0.1:8090
else
  # Treat BACKEND as a literal URL when it's neither "tailnet" nor "local"
  EFFECTIVE_BACKEND_URL := $(BACKEND)
endif

# D-Scanner detection (system > dub package > fallback)
DSCANNER := $(or $(shell which dscanner 2>/dev/null),\
                  $(shell ls -1 $(DUB_PKG)/dscanner/*/dscanner/bin/dscanner 2>/dev/null | tail -1),\
                  dub run dscanner --)

# Source files — enterprise split: backend (vibe.d API), common (shared lib), engine (IRC daemon)
SRCS        := $(shell find backend/source common/source engine/source -name '*.d' 2>/dev/null)
DT_SRCS     := $(shell find backend/views -name '*.dt' 2>/dev/null)

# Colors & icons
R  := \033[0m
B  := \033[1m
D  := \033[2m
K  := \033[30m
G  := \033[32m
Y  := \033[33m
C  := \033[36m
BG := \033[92m
BY := \033[93m
_BC := \033[42m
_BY := \033[43m
_BM := \033[45m
_BB := \033[44m
_BCn:= \033[46m

OK := ✓
WR := ⚠
BL := •
AR := →

# ----------------------------------------------------------------------------
# Phony Targets
# ----------------------------------------------------------------------------
# Phony targets (grouped by category)
.PHONY: all help
.PHONY: build build-gateway build-engine build-release build-debug build-ldc2 janitor-migrate frontend frontend-dev frontend-install

# Component Workflows (primary user-facing targets)
.PHONY: dev dev-docker dev-live debug debug-live stop
.PHONY: engine engine-rebuild engine-handoff engine-handoff-redis engine-restart engine-test
.PHONY: gateway gateway-rebuild gateway-restart
.PHONY: up down gateway-up gateway-down engine-up engine-down engine-logs gateway-logs
.PHONY: status logs logs-engine logs-gateway logs-supervisor crash-logs

# Deprecated aliases (kept for back-compat — see ALIASES section at bottom)
.PHONY: start run run-tailnet run-local run-gateway run-engine
.PHONY: down-tailnet restart-web restart-engine-tailnet

.PHONY: test test-frontend test-all test-watch test-coverage test-lib test-client handoff-test exec-reload-test exec-reload-it clean fmt fmt-check lint deps-check
.PHONY: dscanner-install dscanner-all dscanner-syntax dscanner-lint dscanner-unused \
        dscanner-complexity dscanner-imports dscanner-fix dscanner-size dscanner-outline
.PHONY: ensure-colima docker-up docker-down docker-logs docker-build \
        docker-up-web docker-down-web docker-restart-web \
        docker-up-backend docker-down-backend docker-restart-backend docker-restart \
        docker-restart-code \
        docker-up-test docker-down-test test-server-log test-server-log-playwright \
        docker-shell docker-shell-engine docker-shell-redis docker-shell-mongo docker-shell-ircd ircd-up ircd-down \
        local-dev-up local-dev-down local-dev-down-clean local-dev-smoke
.PHONY: cross-linux-x64 cross-linux-arm64 cross-linux-armv7
.PHONY: verify precommit ci install-env
.PHONY: sync-db-to-tailnet sync-mongo-to-tailnet sync-redis-to-tailnet

# ----------------------------------------------------------------------------
# Component Workflows
# ----------------------------------------------------------------------------
# Pick ONE primary workflow. Compose with the component operations below.
#
# USE-CASE MATRIX
# ──────────────────────────────────────────────────────────────────────────
# I want to…                           Command              What runs
# ──────────────────────────────────────────────────────────────────────────
# Change Svelte / CSS / HTML only      make dev             Vite (HMR), Vite → local gateway
#   (no local D backend)               make dev-live        Vite (HMR), Vite → tailnet gateway
# Change gateway D code                make debug           Gateway + engine (supervised), local DBs
# Change engine D code                 make debug           Same; then `make engine-rebuild && make engine-restart`
#                                       make watch-engine    Same but auto-rebuilds on save
# Debug gateway/engine against LIVE    make debug-live      Gateway + supervised engine → tailnet DBs
#   (prod-shaped data)
# Run D unit tests                     make test            dub test (gateway+engine shared modules)
#                                       make engine-test     same — engine reuses shared modules
# Watch the engine and auto-rebuild    make watch-engine    supervisor picks up new binary on save
# Tail logs                            make logs            all in parallel
#                                       make logs-engine     engine only
#                                       make logs-gateway    gateway only
#                                       make logs-supervisor supervisor only (crashes + restarts)
# Stop everything                      make stop            kills supervisor + gateway, leaves Vite alone
# ──────────────────────────────────────────────────────────────────────────
#
# COMPOSITION
#   Terminal 1: make debug-live
#   Terminal 2: make dev             (HMR against the local gateway from terminal 1)
#   Terminal 3: make logs            (live tail)
#   Make a change to source/*.d → engine auto-rebuilds and supervisor restarts.
#   Make a change to frontend/src/*.svelte → Vite hot-reloads instantly.
#
# BACKEND (for `make dev` / `make dev-live`)
#   make dev BACKEND=local  (default; expects local gateway on :8090)
#   make dev BACKEND=tailnet
#   make dev BACKEND=http://my-gateway:8090
#
# TAILNET OVERRIDES
#   make debug-live IRCFIBER_SERVER_ID=mybox   (set a unique engine id)
# ──────────────────────────────────────────────────────────────────────────

# Tailnet connection settings (used by debug-live)
TAILNET_MONGO_URL ?= mongodb://ircfiber:jqgwEv3GJwwizulaj3Fnbd8imqcMH4Gh@100.126.197.92:27017/ircfiber
TAILNET_REDIS_URL ?= redis://100.126.197.92:6379/0

# Local docker connection settings (used by debug)
LOCAL_MONGO_URL ?= mongodb://127.0.0.1:27017/ircfiber
LOCAL_REDIS_URL ?= redis://127.0.0.1:6379/0

# Default engine server-id used by `make stop` when IRCFIBER_SERVER_ID is
# not exported. The Redis purge after stop must match the namespace the
# engine actually wrote to, otherwise stale `*:<sid>:*` keys linger.
IRCFIBER_DEFAULT_SERVER_ID ?= localengine

# Shared paths for supervisor / logs / pidfiles / crash dumps (relative to project root — avoids space issues)
ENGINE_BIN          := engine/irc-fiber-engine
GATEWAY_BIN         := backend/irc-fiber
# Fallback for legacy `engine/irc-fiber` (pre-split) and `engine/irc-fiber-gateway`.
GATEWAY_BIN_FALLBACK := backend/irc-fiber
GATEWAY_EFF_BIN      := $(or $(wildcard $(GATEWAY_BIN)),$(GATEWAY_BIN_FALLBACK),$(wildcard engine/irc-fiber),engine/irc-fiber)
ENGINE_LOGFILE      := /tmp/irc-fiber-engine.log
GATEWAY_LOGFILE     := /tmp/irc-fiber.log
SUPERVISOR_LOGFILE  := /tmp/irc-fiber-engine.supervisor.log
SUPERVISOR_PIDFILE  := /tmp/irc-fiber-engine-supervisor.pid
ENGINE_PIDFILE      := /tmp/irc-fiber-engine.pid
GATEWAY_PIDFILE     := /tmp/irc-fiber.pid
CRASH_DIR           := $(HOME)/.ircfiber/crashes/


# ─── PRIMARY WORKFLOWS ──────────────────────────────────────────────────────

# Frontend-only dev (Vite). Pairs with `debug` or `debug-live` for a gateway.
dev: frontend-install ## Component > Frontend dev (Vite HMR) — pairs with `make debug*` for backend
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Frontend dev (Vite)  $(R)"
	@printf '%b\n' "$(D)Backend: $(BACKEND)  →  $(EFFECTIVE_BACKEND_URL)$(R)"
	@printf '%b\n' "$(D)Open http://localhost:5173 when ready$(R)"
	@printf '%b\n' "$(D)Pair with: make debug  or  make debug-live  (in another terminal)$(R)"
	@cd frontend && VITE_BACKEND_URL=$(EFFECTIVE_BACKEND_URL) npm run dev

# Production bundle: vite build + inject-manifest (re-syncs backend/views/index.dt
# with the content-hashed CSS/JS URLs so the gateway-rendered SPA shell never
# references a stale bundle).
frontend: ## Build > Production frontend bundle (dist/ + views/index.dt hashes)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building frontend bundle  $(R)"
	@npm --prefix frontend run build

# Frontend dev pointing at the tailnet gateway (no local D backend at all).
dev-live: ## Component > Frontend dev (Vite) against the TAILNET gateway
	@$(MAKE) --no-print-directory dev BACKEND=tailnet

# Docker + Vite dev — starts Docker backend (redis/mongo/ircd/gateway/engine)
# then launches the Vite dev server with HMR. Fastest full-stack dev cycle:
#   - Docker runs backend
#   - Vite serves frontend with live reload on save
#   - For D code changes: `make docker-restart-code` in another terminal
dev-docker: ensure-colima ## Dev > Docker backend + Vite frontend dev (fastest full-stack cycle)
	@if ! docker compose ps redis mongo ircd ircfiber-gateway ircfiber-engine 2>/dev/null | grep -q "healthy"; then \
		docker compose up -d redis mongo ircd ircfiber-gateway ircfiber-engine; \
		printf "%b\n" "$(BG)$(OK) Docker backend started$(R)"; \
	else \
		printf "%b\n" "$(BG)$(OK) Docker backend already running$(R)"; \
	fi
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Vite dev server  $(R)"
	@cd frontend && VITE_BACKEND_URL=http://127.0.0.1:8090 npm run dev

# Full local stack — gateway + supervised engine, both against local docker DBs.
# Uses Docker's staged builder cache (Containerfile `builder` stage):
#   - Base layer (Ubuntu + LDC) cached via --mount=type=cache for apt
#   - Dub incremental cache via --mount=type=cache for /build/.dub + /root/.dub
#     so only changed .d files recompile (not the whole tree).
#   - `docker compose build` is BuildKit-cached: no source change → instant
#     CACHED layers; D change → only affected dub configs recompile.
#   - Host `build-gateway`/`build-engine` are NOT needed here — the builder
#     stage compiles inside Docker. Use `debug-host` for host-native binaries.
#   - Stamp file `.docker-build-stamp` skips `docker compose build` entirely
#     when no relevant source changed (instant second `make debug`).
debug: ## Component > Full stack via docker-compose: gateway (REST API) + engine (IRC) as separate containers — logs via docker
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Starting Docker backend (redis/mongo/ircd)  $(R)"
	@$(_docker_setup)
	@bash -c '\
		stamp=.docker-build-stamp; \
		needs_build=0; \
		if [ ! -f "$$stamp" ]; then needs_build=1; \
		else \
			if [ Containerfile -nt "$$stamp" ] || [ engine/dub.sdl -nt "$$stamp" ] || [ engine/dub.selections.json -nt "$$stamp" ] || [ backend/dub.sdl -nt "$$stamp" ] || [ backend/dub.selections.json -nt "$$stamp" ] || [ common/dub.sdl -nt "$$stamp" ] || [ common/dub.selections.json -nt "$$stamp" ]; then needs_build=1; \
			elif find backend/source backend/views common/source engine/source config public -type f -newer "$$stamp" 2>/dev/null | grep -q .; then needs_build=1; \
			elif find deploy/roles/engine/files deploy/roles/gateway -type f -newer "$$stamp" 2>/dev/null | grep -q .; then needs_build=1; \
			fi; \
		fi; \
		if [ "$$needs_build" = "1" ]; then \
			printf "\n%b\n" "$(_BCn)$(K)$(B)  Building split images (gateway + engine) — cached builder  $(R)"; \
			DOCKER_BUILDKIT=1 docker compose build ircfiber-gateway ircfiber-engine; \
			touch "$$stamp"; \
		else \
			printf "\n%b\n" "$(BG)$(OK) Images up-to-date — skipping docker build (cached) $(R) $(D)(touch Containerfile or backend/source to force)$(R)"; \
		fi; \
		'
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Starting gateway + engine as separate containers  $(R)"
	@docker compose up -d ircfiber-gateway ircfiber-engine
	@printf '\n%b\n' "$(BG)$(OK) Gateway+Engine running as separate containers$(R) $(D)(ircfiber-gateway:8090, ircfiber-engine)$(R)"
	@printf '%b\n' "$(C)  ─ containers $(R)"; docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" | grep -E "ircfiber-gateway|ircfiber-engine|irc_redis|irc_mongo|ircd" | sed "s/^/    /" || true
	@printf '\n%b\n' "$(Y)$(WR) ctrl-c to stop → make down  •  tail logs:  make logs  (docker logs -f)$(R)"
	@printf '%b\n' "$(D)  Also: make gateway-logs / engine-logs / status$(R)"
	@trap 'printf "\n%b\n" "$(Y)$(WR) stopping...$(R)"; docker compose stop ircfiber-gateway ircfiber-engine 2>/dev/null || true; printf "%b\n" "$(BG)$(OK) debug stopped (containers left for logs; run make down to remove)$(R)"; exit 0' INT TERM; \
	docker compose logs -f ircfiber-gateway ircfiber-engine
# Host-native debug (fast D iteration, no docker build) — keeps old supervisor+gateway host binaries
debug-host: build-gateway build-engine ## Component > Full stack HOST-NATIVE: gateway + engine (supervised), local docker DBs — ctrl-c to stop (legacy)
	@$(_docker_setup)
	@bash -c 'set -u; \
		pkill -f irc-fiber-engine-supervisor 2>/dev/null || true; \
		killall -9 irc-fiber irc-fiber-gateway irc-fiber-engine 2>/dev/null || true; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Engine (supervised) → local docker  $(R)"; \
		rm -f "$(GATEWAY_PIDFILE)" "$(SUPERVISOR_PIDFILE)" "$(ENGINE_PIDFILE)"; \
		: > "$(SUPERVISOR_LOGFILE)"; \
		: > "$(GATEWAY_LOGFILE)"; \
		IRCFIBER_MONGO_URL="$(LOCAL_MONGO_URL)" IRCFIBER_REDIS_URL="$(LOCAL_REDIS_URL)" \
			IRCFIBER_SERVER_ID="$${IRCFIBER_SERVER_ID:-localengine}" \
			IRCFIBER_BIND_ADDRESS="$${IRCFIBER_BIND_ADDRESS:-127.0.0.1}" \
			ENGINE_BIN="$(ENGINE_BIN)" \
			ENGINE_PIDFILE="$(ENGINE_PIDFILE)" \
			ENGINE_LOGFILE="$(ENGINE_LOGFILE)" \
			SUPERVISOR_LOGFILE="$(SUPERVISOR_LOGFILE)" \
			SUPERVISOR_PIDFILE="$(SUPERVISOR_PIDFILE)" \
			CRASH_DIR="$(CRASH_DIR)" \
			"$(SUPERVISOR_SCRIPT)" > /tmp/irc-fiber-engine.supervisor.out 2>&1 & \
		SUP_PID=$$!; echo $$SUP_PID > "$(SUPERVISOR_PIDFILE)"; \
		printf "%b\n" "$(C)$(AR) engine supervisor pid=$$SUP_PID (auto-restarts on crash)$(R)"; \
		sleep 3; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Gateway → local docker  $(R)"; \
		printf "%b\n" "$(Y)$(WR) ctrl-c to stop everything  •  tail logs:  make logs-host  in another terminal$(R)"; \
		cleanup() { \
			printf "\n%b\n" "$(Y)$(WR) stopping...$(R)"; \
			kill -TERM "$$SUP_PID" 2>/dev/null || true; \
			killall -9 irc-fiber irc-fiber-gateway irc-fiber-engine 2>/dev/null || true; \
			rm -f "$(GATEWAY_PIDFILE)" "$(SUPERVISOR_PIDFILE)" "$(ENGINE_PIDFILE)"; \
			printf "%b\n" "$(BG)$(OK) debug stopped$(R)"; \
			exit 0; \
		}; \
		trap cleanup INT TERM EXIT; \
		IRCFIBER_MONGO_URL="$(LOCAL_MONGO_URL)" IRCFIBER_REDIS_URL="$(LOCAL_REDIS_URL)" \
			"$(GATEWAY_EFF_BIN)" >> "$(GATEWAY_LOGFILE)" 2>&1; \
		GW_EXIT=$$?; \
		printf "\n%b\n" "$(Y)$(WR) gateway exited (code $$GW_EXIT)$(R)"; \
		cleanup; \
		exit $$GW_EXIT'
# Full local stack — gateway + supervised engine, both against TAILNET DBs.
# For when you want to debug your local D code against the live site's data.
# Runs in the FOREGROUND — supervisor stays backgrounded for engine auto-restart,
# gateway runs in this terminal. ctrl-c cleanly tears down both.
#
# Why no `tee` for live terminal output? SIGINT in a pipeline is delivered to
# the foreground process group; bash's `trap` is supposed to fire on SIGINT,
# but with a pipeline like `irc-fiber | tee log`, the signal can be consumed
# by `tee` (whose default handler exits) before bash's trap reliably runs,
# leaving the supervisor orphaned. We redirect to a log file instead — use
# `make logs` in another terminal for live tailing, and the colored startup
# banner above still prints to this terminal.
debug-live: frontend ## Component > Gateway + engine in Docker against TAILNET DBs — ctrl-c to stop
	@printf '\n\033[46m\033[30m\033[1m  Gateway + engine (docker) → tailnet DBs  \033[0m\n'
	@printf '\033[2m  Mongo: %s\033[0m\n' "$(TAILNET_MONGO_URL)"
	@printf '\033[2m  Redis: %s\033[0m\n' "$(TAILNET_REDIS_URL)"
	@printf '\033[2m  Containerfile target: builder (compiles gateway+engine on first run)\033[0m\n'
	@printf '\033[33m⚠ ctrl-c to stop  •  tail logs:  docker compose -p ircfiber-tailnet -f docker-compose.tailnet.yml logs -f\033[0m\n'
	@docker compose -p ircfiber-tailnet -f docker-compose.tailnet.yml down --remove-orphans 2>/dev/null || true
	TAILNET_MONGO_URL="$(TAILNET_MONGO_URL)" TAILNET_REDIS_URL="$(TAILNET_REDIS_URL)" IRCFIBER_SERVER_ID="$(or $(IRCFIBER_SERVER_ID),localdebug)" \
		docker compose -p ircfiber-tailnet -f docker-compose.tailnet.yml up --build

# Stop everything (tailnet + local docker stacks + native processes). Does NOT kill a Vite dev server.
stop: ## Component > Stop debug/debug-live + local docker stacks (tailnet + local + native)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Stopping everything  $(R)"; \
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
		docker compose -p ircfiber-tailnet -f docker-compose.tailnet.yml down --remove-orphans 2>/dev/null && \
			printf "%b\n" "$(C)  → docker compose tailnet stack stopped$(R)" || true; \
		if [ -f deploy/local/docker-compose.yml ]; then \
			docker compose -f deploy/local/docker-compose.yml --profile observability down --remove-orphans --timeout 15 2>/dev/null || true; \
			docker compose -f deploy/local/docker-compose.yml down --remove-orphans --timeout 15 2>/dev/null && \
				printf "%b\n" "$(C)  → docker compose local stack stopped$(R)" || true; \
		docker compose stop ircfiber-gateway ircfiber-engine 2>/dev/null || true; \
		docker compose -f deploy/local/docker-compose.yml stop ircfiber-gateway ircfiber-engine 2>/dev/null || true; \
	fi; \
	killall -9 irc-fiber irc-fiber-gateway 2>/dev/null || true; \
	killall -9 irc-fiber-engine 2>/dev/null || true; \
	pkill -f irc-fiber-engine-supervisor 2>/dev/null || true; \
	for f in $(SUPERVISOR_PIDFILE) $(ENGINE_PIDFILE) $(GATEWAY_PIDFILE); do \
		if [ -f "$$f" ]; then \
			pid=$$(cat "$$f"); \
			if [ -n "$$pid" ] && kill -0 "$$pid" 2>/dev/null; then \
				kill "$$pid" 2>/dev/null || true; \
				printf "%b\n" "$(C)  → stopped $$(basename $$f) (pid $$pid)$(R)"; \
			fi; \
			rm -f "$$f"; \
		fi; \
	done; \
	sid=$${IRCFIBER_SERVER_ID:-$(IRCFIBER_DEFAULT_SERVER_ID)}; \
	if command -v redis-cli >/dev/null 2>&1; then \
		redis_url=$${IRCFIBER_REDIS_URL:-$(LOCAL_REDIS_URL)}; \
		del_keys=$$(redis-cli -u "$$redis_url" --scan --pattern "*:$${sid}:*" 2>/dev/null | head -10000); \
		if [ -n "$$del_keys" ]; then \
			n=$$(printf '%s\n' "$$del_keys" | wc -l | tr -d ' '); \
			printf '%s\n' "$$del_keys" | xargs redis-cli -u "$$redis_url" DEL >/dev/null 2>&1 || true; \
			printf "%b\n" "$(C)  → purged $$n Redis key(s) matching *:$${sid}:*$(R)"; \
		else \
			printf "%b\n" "$(D)  → no Redis keys to purge for *:$${sid}:*$(R)"; \
		fi; \
	else \
		printf "%b\n" "$(Y)$(WR) redis-cli not installed — skipping Redis purge$(R)"; \
	fi; \
	rm -f /tmp/ircfiber-handoff-$${sid}.sock 2>/dev/null || true; \
	printf '%b\n' "$(BG)$(OK) Stopped. (Vite dev server, if running, was not touched.)$(R)"

# ─── COMPONENT OPERATIONS ───────────────────────────────────────────────────

# Engine: run in foreground (single shot, no supervisor). For ad-hoc debugging.
engine: build-engine ## Component > Engine in foreground (no auto-restart) — ctrl-c to exit
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Engine (foreground)  $(R)"
	@printf '%b\n' "$(Y)$(WR) No supervisor — crashes will not auto-restart. Use \`make debug\` or \`make debug-live\` for supervised mode.$(R)"
	@printf '%b\n' "$(D)  Mongo: $${IRCFIBER_MONGO_URL:-mongodb://127.0.0.1:27017/ircfiber}$(R)"
	@printf '%b\n' "$(D)  Redis: $${IRCFIBER_REDIS_URL:-redis://127.0.0.1:6379/0}$(R)"
	@IRCFIBER_SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine} IRCFIBER_BIND_ADDRESS=$${IRCFIBER_BIND_ADDRESS:-127.0.0.1} \
		"$(ENGINE_BIN)"

# Engine: rebuild binary only.
engine-rebuild: build-engine ## Component > Rebuild engine binary (no restart)
	@printf '%b\n' "$(BG)$(OK) Engine binary rebuilt. Run \`make engine-restart\` (supervised) or \`make engine\` (foreground) to apply.$(R)"

# Engine: graceful handoff — old engine serves FDs to a freshly-started
# new engine. Sockets are preserved across the reload, so IRC connections
# are NOT closed. The new engine inherits the old engine's `serverId` and
# takes over seamlessly.
#
# Flow:
#   1. Send `gracefulReload` control message to the old engine via
#      redis-cli LPUSH. The old engine picks it up on its BLPOP poll
#      and starts `serveReload`, which creates a Unix listener on
#      `/tmp/ircfiber-handoff-<serverId>.sock`.
#   2. Wait for the socket file to appear (≤30s).
#   3. Spawn the new engine with `IRCFIBER_RELOAD_FROM_PID=<oldpid>`.
#      The new engine connects to the listener, receives state+FDs,
#      adopts every connection, then starts its normal consumer loop.
#   4. Wait for the old engine to exit (≤30s). The supervisor respawns
#      with the new binary, which picks up the serverId the new engine
#      is already running under.
engine-handoff: ## Component > Hot-reload engine (preserves IRC sockets — no disconnect)
	@bash -c ' \
		printf "%b\n" "$(_BCn)$(K)$(B)  Hot-reloading engine (graceful handoff)  $(R)"; \
		if [ ! -f $(ENGINE_PIDFILE) ]; then \
			printf "%b\n" "$(Y)$(WR) No engine running. Run \`make engine\` to start one.$(R)"; \
			exit 0; \
		fi; \
		pid=$$(cat $(ENGINE_PIDFILE) 2>/dev/null || echo ""); \
		if [ -z "$$pid" ] || ! kill -0 $$pid 2>/dev/null; then \
			printf "%b\n" "$(Y)$(WR) No engine running. Run \`make engine\` to start one.$(R)"; \
			exit 0; \
		fi; \
		if [ -z "$${IRCFIBER_SERVER_ID:-}" ]; then \
			printf "%b\n" "$(Y)$(WR) IRCFIBER_SERVER_ID not set — using \"localengine\".$(R)"; \
			sid=localengine; \
		else \
			sid="$$IRCFIBER_SERVER_ID"; \
		fi; \
		bind=$${IRCFIBER_BIND_ADDRESS:-127.0.0.1}; \
		redis_url=$${REDIS_URL:-redis://127.0.0.1:6379/0}; \
		sock=/tmp/ircfiber-handoff-$$sid.sock; \
		rm -f "$$sock" 2>/dev/null || true; \
		# Step 1: tell the old engine to start serving the handoff.
		msg="{\"action\":\"gracefulReload\",\"config\":{\"newEnginePid\":0,\"socketPath\":\"$$sock\",\"deadlineMs\":30000}}"; \
		printf "%b\n" "$(C)  → LPUSH irc:control:$$sid (gracefulReload)$(R)"; \
		redis-cli -u "$$redis_url" LPUSH "irc:control:$$sid" "$$msg" >/dev/null 2>&1; \
		if [ $$? -ne 0 ]; then \
			printf "%b\n" "$(Y)$(WR) redis-cli failed. Falling back to hard kill (no graceful handoff).$(R)"; \
			kill $$pid 2>/dev/null || true; \
			exit 1; \
		fi; \
		# Step 2: wait for the old engine to create the listener socket.
		printf "%b\n" "$(C)  → waiting for old engine to create $$sock…$(R)"; \
		for i in $$(seq 1 60); do \
			if [ -S "$$sock" ]; then break; fi; \
			if ! kill -0 $$pid 2>/dev/null; then \
				printf "%b\n" "$(Y)$(WR) old engine died before creating the listener$(R)"; \
				exit 1; \
			fi; \
			sleep 0.5; \
		done; \
		if [ ! -S "$$sock" ]; then \
			printf "%b\n" "$(Y)$(WR) timed out waiting for handoff socket$(R)"; \
			exit 1; \
		fi; \
		# Step 3: spawn the new engine. It will connect to the listener
		# and adopt the live IRC sockets. The old engine exits 0 once
		# the transfer is complete.
		printf "%b\n" "$(C)  → spawning new engine (IRCFIBER_RELOAD_FROM_PID=$$pid)$(R)"; \
		IRCFIBER_SERVER_ID=$$sid IRCFIBER_BIND_ADDRESS=$$bind IRCFIBER_RELOAD_FROM_PID=$$pid \
			"$(ENGINE_BIN)" > /tmp/ircfiber-engine-handoff.log 2>&1 & \
		new_pid=$$!; \
		printf "%b\n" "$(C)  → new engine pid=$$new_pid, waiting for old engine to exit…$(R)"; \
		# Step 4: wait for the old engine to exit (rc=0).
		for i in $$(seq 1 60); do \
			if ! kill -0 $$pid 2>/dev/null; then \
				printf "%b\n" "$(BG)$(OK) old engine exited cleanly (handoff complete)$(R)"; \
				printf "%b\n" "$(D)  new engine pid=$$new_pid is now running — supervisor will see clean rc=0 and respawn if needed$(R)"; \
				exit 0; \
			fi; \
			sleep 0.5; \
		done; \
		printf "%b\n" "$(Y)$(WR) old engine still alive after 30s; killing new engine and old engine$(R)"; \
		kill $$new_pid 2>/dev/null || true; \
		kill $$pid 2>/dev/null || true; \
		exit 1; \
	'

# Engine: hot-reload via redis-cli (no Makefile child process). Useful when
# the Makefile is running on a different machine than the engine, or when
# you want to trigger a handoff from a script or the admin dashboard.
#
# Usage: make engine-handoff-redis IRCFIBER_SERVER_ID=myengine
#   Requires: redis-cli on PATH, REDIS_URL (or defaults to localhost:6379)
#
# Sends a gracefulReload control message to irc:control:<serverId> via
# redis-cli LPUSH. The engine picks it up on its next BLPOP poll, then
# starts its handoff listener. The caller must then launch the new engine
# with IRCFIBER_RELOAD_FROM_PID=<old_pid> on the same host.
engine-handoff-redis: ## Component > Trigger graceful handoff via redis-cli (no child process)
	@bash -c ' \
		printf "%b\n" "$(_BCn)$(K)$(B)  Triggering engine handoff via redis-cli  $(R)"; \
		if [ -z "$${IRCFIBER_SERVER_ID:-}" ]; then \
			printf "%b\n" "$(Y)$(WR) IRCFIBER_SERVER_ID is required. Usage: make engine-handoff-redis IRCFIBER_SERVER_ID=myengine$(R)"; \
			exit 1; \
		fi; \
		sid="$$IRCFIBER_SERVER_ID"; \
		redis_url="$${REDIS_URL:-redis://127.0.0.1:6379/0}"; \
		# Build the control message JSON \
		msg="{\"action\":\"gracefulReload\",\"config\":{\"newEnginePid\":0,\"socketPath\":\"/tmp/ircfiber-handoff-$$sid.sock\",\"deadlineMs\":30000}}"; \
		printf "%b\n" "$(C)  → LPUSH irc:control:$$sid $(D)$$msg$(R)"; \
		redis-cli -u "$$redis_url" LPUSH "irc:control:$$sid" "$$msg" 2>&1; \
		rc=$$?; \
		if [ $$rc -eq 0 ]; then \
			printf "%b\n" "$(BG)$(OK) Handoff message sent to engine (serverId=$$sid)$(R)"; \
			printf "%b\n" "$(D)  Next step: start the new engine on the same host:$(R)"; \
			printf "%b\n" "$(D)    IRCFIBER_SERVER_ID=$$sid IRCFIBER_RELOAD_FROM_PID=<old_pid> $(ENGINE_BIN)$(R)"; \
		else \
			printf "%b\n" "$(Y)$(WR) redis-cli failed (rc=$$rc). Check REDIS_URL and redis-cli availability.$(R)"; \
			exit $$rc; \
		fi; \
	'

# Engine: kill the current engine — supervisor respawns with the latest binary.
# Prefer `engine-handoff` for development to avoid closing IRC sockets.
engine-restart: ## Component > Restart engine (supervisor respawns with new binary)
	@bash -c ' \
		printf "%b\n" "$(_BCn)$(K)$(B)  Restarting engine  $(R)"; \
		if [ ! -f $(SUPERVISOR_PIDFILE) ]; then \
			printf "%b\n" "$(Y)$(WR) No supervisor running — engine is in foreground. Use \`make engine\` instead.$(R)"; \
			exit 0; \
		fi; \
		if [ -f $(ENGINE_PIDFILE) ]; then \
			pid=$$(cat $(ENGINE_PIDFILE)); \
			if [ -n "$$pid" ] && kill -0 $$pid 2>/dev/null; then \
				printf "%b\n" "$(C)  → sending SIGTERM to engine (pid $$pid)$(R)"; \
				kill $$pid 2>/dev/null || true; \
			else \
				printf "%b\n" "$(Y)$(WR) engine pidfile stale; supervisor will respawn on next heartbeat$(R)"; \
			fi; \
		else \
			killall -9 irc-fiber-engine 2>/dev/null || true; \
		fi; \
		printf "%b\n" "$(BG)$(OK) supervisor will respawn engine$(R)"; \
	'

# Engine: run D unit tests (uses dub test; engine + gateway share these modules).
engine-test: test ## Component > Run D unit tests (engine + gateway share these modules)

# Gateway: run in foreground.
gateway: build ## Component > Gateway in foreground — ctrl-c to exit
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Gateway (foreground)  $(R)"
	@printf '%b\n' "$(D)  Mongo: $${IRCFIBER_MONGO_URL:-mongodb://127.0.0.1:27017/ircfiber}$(R)"
	@printf '%b\n' "$(D)  Redis: $${IRCFIBER_REDIS_URL:-redis://127.0.0.1:6379/0}$(R)"
	@IRCFIBER_MONGO_URL=$${IRCFIBER_MONGO_URL:-mongodb://127.0.0.1:27017/ircfiber} \
		IRCFIBER_REDIS_URL=$${IRCFIBER_REDIS_URL:-redis://127.0.0.1:6379/0} \
		"$(GATEWAY_BIN)"

# Gateway: rebuild only.
gateway-rebuild: build-gateway ## Component > Rebuild gateway binary (no restart)

# Gateway: stop + relaunch in background (uses whatever env was set when last launched).
gateway-restart: ## Component > Stop + relaunch gateway in background
	@bash -c ' \
		printf "%b\n" "$(_BCn)$(K)$(B)  Restarting gateway  $(R)"; \
		if [ -f $(GATEWAY_PIDFILE) ]; then \
			pid=$$(cat $(GATEWAY_PIDFILE)); \
			if [ -n "$$pid" ] && kill -0 $$pid 2>/dev/null; then \
				kill $$pid 2>/dev/null || true; \
				printf "%b\n" "$(C)  → stopped gateway (pid $$pid)$(R)"; \
			fi; \
		fi; \
		killall -9 irc-fiber irc-fiber-gateway 2>/dev/null || true; \
		sleep 1; \
		rm -f $(GATEWAY_PIDFILE); \
		: > $(GATEWAY_LOGFILE); \
		IRCFIBER_MONGO_URL=$${IRCFIBER_MONGO_URL:-$(LOCAL_MONGO_URL)} \
		IRCFIBER_REDIS_URL=$${IRCFIBER_REDIS_URL:-$(LOCAL_REDIS_URL)} \
			nohup "$(GATEWAY_EFF_BIN)" > $(GATEWAY_LOGFILE) 2>&1 & \
		GW_PID=$$!; \
		echo $$GW_PID > $(GATEWAY_PIDFILE); \
		printf "%b\n" "$(C)  → started gateway (pid $$GW_PID)$(R)"; \
		printf "%b\n" "$(BG)$(OK) Gateway restarted$(R) $(D)(http://localhost:8090)$(R)"; \
	'

# ─── OBSERVABILITY ──────────────────────────────────────────────────────────

# Status: show what's running, port bindings, last log lines.
status: ## Component > Print running processes, ports, recent log lines
	@bash -c ' \
		printf "\n%b\n" "$(_BC)$(K)$(B)  IRC Fiber status  $(R)"; \
		printf "%b\n" "$(C)  ─ processes $(R)"; \
		ps -o pid,etime,command -p $$(pgrep -f irc-fiber 2>/dev/null) 2>/dev/null | sed "s/^/    /" || printf "    (no irc-fiber running)\n"; \
		ps -o pid,etime,command -p $$(pgrep -f irc-fiber-engine 2>/dev/null) 2>/dev/null | sed "s/^/    /" || printf "    (no irc-fiber-engine running)\n"; \
		ps -o pid,etime,command -p $$(pgrep -f irc-fiber-engine-supervisor 2>/dev/null) 2>/dev/null | sed "s/^/    /" || printf "    (no supervisor running)\n"; \
		printf "\n%b\n" "$(C)  ─ port bindings $(R)"; \
		lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk "/irc-fiber|node/ {print \"    \"$$0}" || true; \
		printf "\n%b\n" "$(C)  ─ gateway tail $(R)"; \
		tail -3 $(GATEWAY_LOGFILE) 2>/dev/null | sed "s/^/    /" || printf "    (no log)\n"; \
		printf "\n%b\n" "$(C)  ─ engine tail $(R)"; \
		tail -3 $(ENGINE_LOGFILE) 2>/dev/null | sed "s/^/    /" || printf "    (no log)\n"; \
# Logs: docker logs for split containers (gateway + engine). Use logs-host for host-native debug.
logs: ## Component > Tail gateway + engine docker logs (split containers)
	@docker compose logs -f ircfiber-gateway ircfiber-engine 2>&1 | sed -u "s/^\([a-z-]*\) |/$(K)[\1]$(R) /" || \
		(printf "%b\n" "$(Y)$(WR) No docker containers — try make debug (docker) or make logs-host (host) $(R)"; exit 1)

logs-host: ## Component > Tail engine + gateway + supervisor host logs (debug-host)
	@bash -c ' \
		touch $(ENGINE_LOGFILE) $(GATEWAY_LOGFILE) $(SUPERVISOR_LOGFILE); \
		trap "kill 0" INT TERM EXIT; \
		tail -F $(GATEWAY_LOGFILE) | sed -u "s/^/$(K)[gw]$(R) /" & \
		tail -F $(ENGINE_LOGFILE) | sed -u "s/^/$(Y)[en]$(R) /" & \
		tail -F $(SUPERVISOR_LOGFILE) | sed -u "s/^/$(C)[sv]$(R) /" & \
		wait; \
	'

logs-engine: ## Component > Tail engine docker logs
	@docker compose logs -f ircfiber-engine

logs-gateway: ## Component > Tail gateway docker logs
	@docker compose logs -f ircfiber-gateway

logs-engine-host: ## Component > Tail engine host log only (debug-host)
	@touch $(ENGINE_LOGFILE); tail -F $(ENGINE_LOGFILE)

logs-gateway-host: ## Component > Tail gateway host log only (debug-host)
	@touch $(GATEWAY_LOGFILE); tail -F $(GATEWAY_LOGFILE)
		tail -F $(SUPERVISOR_LOGFILE) | sed -u "s/^/$(C)[sv]$(R) /" & \
		wait; \
logs-supervisor: ## Component > Tail supervisor log (host, debug-host only)
	@touch $(SUPERVISOR_LOGFILE); tail -F $(SUPERVISOR_LOGFILE)


crash-logs: ## Component > List persistent crash dumps (use CAT=1 to view latest)
	@bash -c ' \
		d="$(CRASH_DIR)"; \
		mkdir -p "$$d"; \
		if ls "$$d"crash-*.txt >/dev/null 2>&1; then \
			total=$$(ls "$$d"crash-*.txt 2>/dev/null | wc -l | tr -d " "); \
			printf "\n%b\n" "$(_BCn)$(K)$(B)  IRC Fiber Crash Dumps ($$total total)  $(R)"; \
			printf "%b\n" "$(D)  Dir: $$d$(R)"; \
			printf "\n"; \
			if [ "$${CAT:-0}" = "1" ]; then \
				latest=$$(ls -t "$$d"crash-*.txt 2>/dev/null | head -1); \
				if [ -n "$$latest" ]; then \
					printf "%b\n" "$(C)  ─ Most recent: $$(basename $$latest) $(R)"; \
					printf "\n"; \
					cat "$$latest"; \
				fi; \
			else \
				printf "  %-24s %-8s %-8s %-s\n" "Crash" "Exit" "Size" "Path"; \
				printf "  %-24s %-8s %-8s %-s\n" "-----" "----" "----" "----"; \
				ls -tr "$$d"crash-*.txt 2>/dev/null | while read -r f; do \
					base=$$(basename "$$f" .txt); \
					exitcode=$$(echo "$$base" | sed "s/.*exit//"); \
					sz=$$(wc -c < "$$f" | tr -d " "); \
					echo "  $$base  exit=$$exitcode  $$sz bytes  $$f"; \
				done; \
				printf "\n%b\n" "$(D)  View latest: make crash-logs CAT=1$(R)"; \
			fi; \
		else \
			printf "\n%b\n" "$(Y)$(WR) No crash dumps found in $$d$(R)"; \
		fi; \
	'

# ─── AUTO-REBUILD (file watch) ──────────────────────────────────────────────

# Watch engine sources, rebuild + restart on change.
watch-engine: ## Component > Watch engine/source/*.d — rebuild engine + hot-reload on save (preserves IRC sockets)
	@bash -c ' \
		printf "\n%b\n" "$(_BC)$(K)$(B)  Watching engine sources  $(R)"; \
		printf "%b\n" "$(D)Polls every 2s. Install fswatch for instant: brew install fswatch$(R)"; \
		printf "%b\n" "$(D)Triggers: make engine-rebuild + make engine-handoff (NO socket close)$(R)"; \
		if [ ! -f $(SUPERVISOR_PIDFILE) ]; then \
			printf "%b\n" "$(Y)$(WR) No supervisor running. Start one first: make debug  or  make debug-live$(R)"; \
			exit 1; \
		fi; \
		WATCH=$$(find engine/source common/source -name "*.d" -type f 2>/dev/null); \
		LAST=$$(echo "$$WATCH" | xargs stat -f %m 2>/dev/null | sort -n | tail -1); \
		printf "%b\n" "$(C)  watching engine/source + common/source …$(R)"; \
		while true; do \
			sleep 2; \
			CURR=$$(echo "$$WATCH" | xargs stat -f %m 2>/dev/null | sort -n | tail -1); \
			if [ "$$CURR" != "$$LAST" ]; then \
				printf "\n%b\n" "$(Y)→ change detected, hot-reloading engine…$(R)"; \
				$(MAKE) --no-print-directory engine-rebuild && \
					$(MAKE) --no-print-directory engine-handoff; \
				LAST=$$CURR; \
			fi; \
		done; \
	'

# Watch gateway sources, rebuild + restart on change.
watch-gateway: ## Component > Watch backend/source/*.d — rebuild gateway + relaunch on save
	@bash -c ' \
		printf "\n%b\n" "$(_BC)$(K)$(B)  Watching gateway sources  $(R)"; \
		printf "%b\n" "$(D)Polls every 2s. Install fswatch for instant: brew install fswatch$(R)"; \
		WATCH=$$(find backend/source common/source -name "*.d" -type f 2>/dev/null); \
		LAST=$$(echo "$$WATCH" | xargs stat -f %m 2>/dev/null | sort -n | tail -1); \
		printf "%b\n" "$(C)  watching backend/source + common/source …$(R)"; \
		while true; do \
			sleep 2; \
			CURR=$$(echo "$$WATCH" | xargs stat -f %m 2>/dev/null | sort -n | tail -1); \
			if [ "$$CURR" != "$$LAST" ]; then \
				printf "\n%b\n" "$(Y)→ change detected, rebuilding gateway…$(R)"; \
				$(MAKE) --no-print-directory gateway-rebuild && \
					$(MAKE) --no-print-directory gateway-restart; \
				LAST=$$CURR; \
			fi; \
		done; \
	'

# Watch both engine and gateway.
watch: watch-engine watch-gateway ## Component > Watch both engine + gateway sources

# ─── DEPRECATED ALIASES (back-compat) ───────────────────────────────────────
# Prefer the new Component Workflow names. These are kept so old docs / muscle
# memory still work but emit a deprecation hint the first time they're used.
start: dev
run: dev
run-tailnet: dev-live
run-local: dev
run-gateway: gateway
run-engine: engine
down-tailnet: stop
restart-web: gateway-restart
restart-engine-tailnet: engine-restart
logs-web: logs-gateway
logs-engine-tailnet: logs-engine
watch-web: watch-gateway

# ----------------------------------------------------------------------------
# Main Build Targets
# ----------------------------------------------------------------------------

all: build ## Utils > Build the default target

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    OPENSSL_LIB := $(shell brew --prefix openssl 2>/dev/null || echo /usr/local)/lib
endif

build: build-gateway build-engine ## Build > Build the application with dub (gateway+engine)
	@printf '\n%b\n' "$(BG)$(OK) Build complete (gateway+engine)$(R)"

build-gateway: frontend ## Build > Build the gateway binary (irc-fiber)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber Gateway  $(R)"
	@bash -o pipefail -c '$(DUB_BACKEND) build --config=gateway --build=release 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@bash -o pipefail -c '$(DUB_BACKEND) build --build=release 2>&1 | tail -5' || true
	@if [ -f $(GATEWAY_APP) ]; then \
		SIZE=$$(ls -lh $(GATEWAY_APP) | awk '{print $$5}'); \
		printf '\n%b\n' "$(BG)$(OK) Gateway build successful$(R) $(D)($$SIZE)$(R)"; \
	elif [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) | awk '{print $$5}'); \
		printf '\n%b\n' "$(BG)$(OK) Gateway build successful (legacy $(APP))$(R) $(D)($$SIZE)$(R)"; \
	else \
		printf '\n%b\n' "$(BG)$(OK) Gateway dub complete$(R)"; \
	fi

build-engine: ## Build > Build the IRC engine binary
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber Engine  $(R)"
	@bash -o pipefail -c '$(DUB_ENGINE) build --config=engine --build=release 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@printf '\n%b\n' "$(BG)$(OK) Engine build successful$(R)"
# Janitor migrate tool — backfills TTLs on existing Redis state/scrollback/
# dedup keys. Default is dry-run; set JSMIGRATE_DRY_RUN=0 to actually apply.
janitor-migrate: ## Build > Run janitor-migrate (TTL backfill). Dry-run by default.
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Building janitor-migrate  $(R)"
	@$(DUB_ENGINE) build --config=janitor-migrate 2>&1 | tail -5
	@printf '%b\n' "$(BG)$(OK) Running janitor-migrate (dry-run)$(R)"
	@JSMIGRATE_DRY_RUN=1 ./engine/janitor-migrate 2>/dev/null || JSMIGRATE_DRY_RUN=1 ./janitor-migrate

# Default-network migration — ensure every existing user has the
# irc.ircfiber.com:6697 connection. Idempotent. Skip with DRY_RUN=0 to
# actually write to Mongo.
ircfiber-default-migrate: ## Build > Backfill the default IRC Fiber network for every existing user
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Building ircfiber-default-migrate  $(R)"
	@$(DUB_ENGINE) build --config=ircfiber-default-migrate 2>&1 | tail -5
	@printf '%b\n' "$(BG)$(OK) Running ircfiber-default-migrate (dry-run)$(R)"
	@DRY_RUN=1 ./engine/ircfiber-default-migrate --dry-run 2>/dev/null || DRY_RUN=1 ./ircfiber-default-migrate --dry-run

# Python gateway (Step 3 swappable API)
api-python-up: ## Python API > Bring up Python gateway alongside D gateway (local dev)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Python gateway up  $(R)"
	@docker compose -f deploy/local/docker-compose.yml -f deploy/local/docker-compose.override.python.yml up -d irc-fiber-api-py
	@printf '%b\n' "$(BG)$(OK) Python gateway running at http://127.0.0.1:8001 (health: /api/ping)$(R)"

api-python-down: ## Python API > Stop Python gateway
	@docker compose -f deploy/local/docker-compose.yml -f deploy/local/docker-compose.override.python.yml down --remove-orphans || true
	@printf '%b\n' "$(BG)$(OK) Python gateway stopped$(R)"

api-python-build: ## Python API > Build Python gateway image
	@docker build -t irc-fiber-api-py:local api-python
	@printf '%b\n' "$(BG)$(OK) Python image built$(R)"

api-python-test: ## Python API > Run auth compat tests
	@python3 -m pytest api-python/tests/test_auth_compat.py -v

build-release: ## Build > Optimized release build
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber (Release)  $(R)"
	@bash -o pipefail -c '$(DUB) build --build=release 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@SIZE=$$(ls -lh $(APP) 2>/dev/null | awk '{print $$5}'); \
		printf '\n%b\n' "$(BG)$(OK) Release build successful$(R) $(D)($$SIZE)$(R)"

build-debug: ## Build > Explicit debug build
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber (Debug)  $(R)"
	@bash -o pipefail -c '$(DUB) build --build=debug 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | grep -v "during/source/during/package.d" | grep -v "Deprecation: accessing" | tail -8'
	@printf '\n%b\n' "$(BG)$(OK) Debug build successful$(R)"

# Build with direct ldc2 (no dub dependency resolution overhead)
# Uses ldc2 as compiler while dub manages the build process and linking.
# For pure ldc2 without dub, see compiler-direct skill.
build-ldc2: ## Build > LDC2 build (dub-managed, use 'make build' for gdc/dmd)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber (LDC2)  $(R)"
	@$(DUB) build --compiler=ldc2 --build=debug --force 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8
	@if [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) 2>/dev/null | awk '{print $$5}'); \
		printf '\n%b\n' "$(BG)$(OK) LDC2 build successful$(R) $(D)($$SIZE)$(R)"; \
	else \
		printf '\n%b\n' "$(Y)$(WR) LDC2 build failed$(R)"; \
		exit 1; \
	fi
	@if [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) 2>/dev/null | awk '{print $$5}'); \
		printf '\n%b\n' "$(BG)$(OK) LDC2 build successful$(R) $(D)($$SIZE)$(R)"; \
	else \
		printf '\n%b\n' "$(Y)$(WR) LDC2 build failed$(R)"; \
		exit 1; \
	fi

# ----------------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------------

# Bash snippet: kill old processes, check docker backends
define _docker_setup
	@killall -9 irc-fiber-engine 2>/dev/null || true; \
	killall -9 irc-fiber 2>/dev/null || true; \
	sleep 1; \
	SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine}; \
	if docker info >/dev/null 2>&1; then \
		docker compose exec -T redis redis-cli del irc:server:$$SERVER_ID irc:servers irc:network:assignments >/dev/null 2>&1 || true; \
	fi; \
	if ! docker info >/dev/null 2>&1; then \
		printf "%b\n" "$(Y)$(WR) Docker is not running$(R)"; \
		printf "%b\n" "$(D)Start Docker first, or run: make docker-up-backend$(R)"; \
		exit 1; \
	fi; \
	if ! docker compose ps mongo redis ircd 2>/dev/null | grep -q "healthy"; then \
		printf "%b\n" "$(Y)$(WR) Backend services not running. Starting them now...$(R)"; \
		docker compose up -d mongo redis ircd; \
		printf "%b\n" "$(C)→ Waiting for services to be ready...$(R)"; \
		for i in 1 2 3 4 5 6 7 8 9 10; do \
			if docker compose ps mongo redis ircd 2>/dev/null | grep -q "healthy"; then \
				printf "%b\n" "$(BG)$(OK) Backend services ready$(R)"; \
				break; \
			fi; \
			if [ $$i -eq 10 ]; then \
				printf "%b\n" "$(Y)$(WR) Services still starting, continuing anyway...$(R)"; \
			fi; \
			sleep 1; \
		done; \
	else \
		printf "%b\n" "$(BG)$(OK) Backend services already running$(R)"; \
	fi
endef

# ----------------------------------------------------------------------------
# Testing & Quality
# ----------------------------------------------------------------------------
#
# Layered test targets so you can run just what you need:
#
#   make test               # D backend tests only (fast)
#   make test-frontend      # Svelte/Vitest only (fast, no browser by default)
#   make test-lib           # Pure utility tests (Node, fastest)
#   make test-client        # Component + store tests (headless Chromium)
#   make test-all           # D backend + all frontend tests
#   make test-coverage      # Code coverage report for the frontend
#   make test-watch         # Vitest watch mode (frontend, re-runs on save)
#   make test-ci            # Headless, single-run, JUnit output — for CI
#
# Quality / lint:
#
#   make lint               # All linters (D + frontend)
#   make lint-d             # D-Scanner style + syntax + unused checks
#   make lint-frontend      # svelte-check (TS) + svelte-check (Svelte)
#   make fmt                # Format D sources
#   make fmt-check          # Fail if any D source is unformatted (CI gate)
#
# Aggregators (run everything):
#
#   make verify             # lint + test (pre-push gate)
#   make precommit          # fmt-check + lint + test (pre-commit gate)
#   make ci                 # Everything, headless, fail-fast on first error

test: ## Test > D backend unit tests (fast)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running D backend tests  $(R)"
	@$(DUB) build --config=unittest -b unittest 2>&1 | tail -5
	@timeout 30 ./engine/irc-fiber-test 2>&1 | tail -20; code=$${PIPESTATUS[0]}; if [ $$code -eq 124 ]; then printf '\n%b\n' "$(Y)$(WR) test binary hung (timeout 30s) — vibe eventcore leak?$(R)"; exit 1; fi; exit $$code

test-real: ## Test > Real unittest driver (replaces no-op unitThreadedLight)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building real unittest driver  $(R)"
	@$(DUB) build --config=unit-test-real -b unittest 2>&1 | tail -3
	@timeout 30 ./engine/irc-fiber-test-real 2>&1 | tail -30; code=$${PIPESTATUS[0]}; if [ $$code -eq 124 ]; then printf '\n%b\n' "$(Y)$(WR) test-real hung (timeout 30s)$(R)"; exit 1; fi; exit $$code
prefs-test: ## Test > User-preferences defensive-parse suite (skips if Redis missing)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Prefs defensive-parse tests  $(R)"
	@$(DUB) build --config=prefs-test 2>&1 | tail -3
	@./engine/prefs-test

dedup-test: ## Test > REST scrollback Redis/MongoDB dedup (refresh-on-low-volume-channel regression)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Scrollback dedup tests  $(R)"
	@$(DUB) build --config=dedup-test 2>&1 | tail -3
	@./engine/dedup-test

parser-test: ## Test > IRC parser defensive guards + RFC 2812 coverage
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Parser defensive-parse tests  $(R)"
	@$(DUB) build --config=parser-test 2>&1 | tail -3
	@./engine/parser-test

consumer-test: ## Test > consumer reconnect-dedup helpers
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Consumer reconnect-dedup tests  $(R)"
	@$(DUB) build --config=consumer-test 2>&1 | tail -3
	@./engine/consumer-test

connection-registration-test: ## Test > ConnectionServer.registrationUnavailableFor JSON contract for the admin registration-stuck surface
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Registration-timeout admin contract tests  $(R)"
	@$(DUB) build --config=connection-registration-test 2>&1 | tail -3
	@./engine/connection-registration-test

observability-test: ## Test > OTel metrics pipeline (counter/gauge/histogram JSON contract)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  OTel observability metrics tests  $(R)"
	@$(DUB) build --config=observability-test 2>&1 | tail -3
	@./engine/observability-test

janitor-test: ## Test > EngineJanitor basic reap (orphan → reaped, live → skipped)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  EngineJanitor basic-reap tests  $(R)"
	@$(DUB) build --config=janitor-test 2>&1 | tail -3
	@./engine/janitor-test

janitor-lock-test: ## Test > EngineJanitor distributed lock + manualReap()
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  EngineJanitor lock + manual-reap tests  $(R)"
	@$(DUB) build --config=janitor-lock-test 2>&1 | tail -3
	@./engine/janitor-lock-test

janitor-safety-test: ## Test > EngineJanitor status / events / purgeLocalServerNamespace / bumpServerStateTTLs
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  EngineJanitor safety + helpers tests  $(R)"
	@$(DUB) build --config=janitor-safety-test 2>&1 | tail -3
	@./engine/janitor-safety-test

janitor-tests: ## Test > All EngineJanitor test suites (basic + lock + safety)
	@./run-janitor-tests.sh

parser-fuzz-test: ## Test > parser property-based fuzz (10k random lines)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Parser fuzz tests  $(R)"
	@$(DUB) build --config=parser-fuzz-test 2>&1 | tail -3
	@./engine/parser-fuzz-test

test-fast: ## Test > All fast standalone test suites (prefs/parser/consumer/observability/registration)
	@for t in prefs-test parser-test consumer-test observability-test connection-registration-test session-queue-test oob-test; do \
		printf '\n%b\n' "$(_BCn)$(K)$(B)  $$t  $(R)"; \
		$(DUB) build --config=$$t 2>&1 | tail -1 || exit 1; \
		./engine/$$t 2>&1 | tail -3; \
	done

# Real-CI runner. Builds with `-b unittest` so the compiler emits
# unittest instances that `__traits(getUnitTests)` can enumerate at
# runtime. Uses the heavy unit-threaded runner's `disableDefaultRunner`
# mixin to skip D's runtime auto-unittest hook (which would hang on
# vibe-d's leaked fibers past main()) so MY main() is the
# authoritative test executor. Result: every unittest block in modules
# imported by app_test_real.d runs exactly once.
unit-test-real: ## Test > Real unittest driver (replaces no-op unitThreadedLight)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building real unittest driver  $(R)"
	@$(DUB) build --config=unit-test-real --compiler=ldc2 --build=debug -b unittest 2>&1 | tail -3
	@./engine/irc-fiber-test-real

test-frontend: ## Test > Svelte/Vitest frontend tests (both projects)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running frontend tests  $(R)"
	@cd frontend && npm run test 2>&1 | tail -20

test-lib: ## Test > Frontend lib tests only (Node, fastest — pure utilities)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running frontend lib tests  $(R)"
	@cd frontend && npm run test:lib 2>&1 | tail -15

test-client: ## Test > Frontend client tests only (headless Chromium — components/stores)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running frontend client tests  $(R)"
	@cd frontend && npm run test:client 2>&1 | tail -15

handoff-test: ## Test > Standalone handoff SCM_RIGHTS tests (no vibe.d, no engine deps)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Handoff tests  $(R)"
	@$(DUB) build --config=handoff-test 2>&1 | tail -3
	@./engine/handoff-test

exec-reload-test: ## Test > exec(2)-based hot-reload: TCP socket identity survives fork+SCM_RIGHTS
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Exec-reload tests  $(R)"
	@$(DUB) build --config=exec-reload-test 2>&1 | tail -3
	@./engine/exec-reload-test
# Full end-to-end exec-reload integration test against a mock IRC server.
# Spawns a Python TCP listener, opens a connection from the OLD engine
# path, execs into the NEW engine path, and verifies the same TCP socket
# survives. Run from the repo root so the binary is in $PWD.
exec-reload-it: ## Test > Full exec-reload flow: OLD engine → exec → NEW engine, mock IRC server
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Exec-reload integration test  $(R)"
	@$(DUB) build --config=exec-reload-integration 2>&1 | tail -3
	@chmod +x engine/source/exec_reload_mock_irc.py
	@bash -c 'set -e; rm -f /tmp/exec-reload-test.result; \
	  python3 engine/source/exec_reload_mock_irc.py 16667 /tmp/exec-reload-test.result & \
	  MOCK_PID=$$!; \
	  sleep 0.5; \
	  ./exec-reload-integration old /tmp/exec-reload-test.snapshot /tmp/exec-reload-test.marker && \
	  wait $$MOCK_PID 2>/dev/null || true; \
	  echo; echo "--- mock_irc result file ---"; \
	  cat /tmp/exec-reload-test.result 2>/dev/null || echo "(no result file)"'

test-all: test test-frontend ## Test > D backend + frontend (everything)
	@printf '\n%b\n' "$(BG)$(OK) All test suites passed$(R)"

test-coverage: ## Test > Frontend coverage report (HTML + text)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Generating frontend coverage report  $(R)"
	@cd frontend && npm run test:coverage 2>&1 | tail -20
	@printf '%b\n' "$(D)Open frontend/coverage/index.html in a browser$(R)"

test-watch: ## Test > Vitest watch mode (frontend, re-runs on save)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Vitest watch mode  $(R)"
	@cd frontend && npm run test:watch

test-ci: ## Test > CI-mode: headless, single-run, JUnit XML output
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  CI-mode frontend tests (JUnit XML)  $(R)"
	@cd frontend && CI=1 npm run test -- --reporter=default --reporter=junit --outputFile=test-results/junit.xml
	@$(DUB) test --build=unittest-cov 2>&1 | tail -10

# --- Lint ---------------------------------------------------------------------

lint: lint-d lint-frontend ## Quality > All linters
	@printf '\n%b\n' "$(BG)$(OK) All linters passed$(R)"

lint-d: dscanner-syntax dscanner-lint dscanner-unused dscanner-complexity ## Quality > D backend linters
	@printf '\n%b\n' "$(BG)$(OK) D backend lint passed$(R)"

lint-frontend: ## Quality > Frontend type-check (svelte-check)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running svelte-check  $(R)"
	@cd frontend && npm run check 2>&1 | tail -30

# --- Format -------------------------------------------------------------------

fmt: ## Quality > Format D sources in-place
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Formatting D sources  $(R)"
	@find engine/source -name "*.d" -exec dfmt -i {} \; 2>/dev/null || \
		printf '%b\n' "$(Y)$(WR) dfmt not found. Install: dub fetch dfmt$(R)"
	@printf '%b\n' "$(BG)$(OK) D sources formatted$(R)"

fmt-check: ## Quality > Verify all D sources are formatted (CI gate, no writes)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Checking D source formatting  $(R)"
	@UNFORMATTED=$$(find engine/source -name "*.d" -exec dfmt -c {} \; 2>&1 | grep -v "^$" || true); \
		printf '%b\n' "$(Y)$(WR) Unformatted sources detected:$(R)"; \
		echo "$$UNFORMATTED"; \
		printf '%b\n' "$(D)Fix with: make fmt$(R)"; \
		exit 1; \
	else \
		printf '%b\n' "$(BG)$(OK) All D sources formatted$(R)"; \
	fi

# --- Aggregators --------------------------------------------------------------

verify: lint test ## Verify > lint + test (pre-push gate)
	@printf '\n%b\n' "$(BG)$(OK) verify passed (lint + test)$(R)"

precommit: fmt-check lint test ## Verify > fmt-check + lint + test (pre-commit gate)
	@printf '\n%b\n' "$(BG)$(OK) precommit passed (fmt + lint + test)$(R)"

pre-deploy-gate: ## Verify > Run pre-deploy loadtest gate (p99 /health < 200ms)
	@printf '%b\n' "$(D)  Loadtest gate...$(R)"
	@scripts/pre-deploy-loadtest.sh
	@printf '%b\n' "$(G)  Loadtest gate passed$(R)"

pre-deploy: pre-deploy-gate ## Verify > Run all pre-deploy gates (loadtest, etc.)

ci: precommit ## Verify > Full CI suite (fmt + lint + test, fail-fast)
	@printf '\n%b\n' "$(BG)$(OK) CI pipeline passed$(R)"

# --- Environment --------------------------------------------------------------

install-env: frontend-install deps-check ## Utils > Install dev environment (frontend deps + verify CLI tools)
	@printf '\n%b\n' "$(BG)$(OK) Dev environment ready$(R)"

# ----------------------------------------------------------------------------
# Code Quality (D-Scanner)
# ----------------------------------------------------------------------------

dscanner-install: ## Quality > Install D-Scanner if missing
	@command -v dscanner >/dev/null 2>&1 || dub fetch dscanner

# D-Scanner rule template: $(1)=target suffix, $(2)=label, $(3)=flag, $(4)=post-filter
define _ds_rule
dscanner-$(1): ## Quality > $(2)
	@printf '\n%b\n' "$(D)--- D-Scanner $(2) ---$(R)"
	@$(DSCANNER) $(3) $(SRCS) 2>/dev/null $(4)
endef

$(eval $(call _ds_rule,syntax,syntax check,--syntaxCheck,|| true))
dscanner-syntax: ## Quality > Syntax check
$(eval $(call _ds_rule,lint,lint,--styleCheck,|| true))
dscanner-lint: ## Quality > Style lint
$(eval $(call _ds_rule,unused,unused check,--styleCheck,| grep -E "unused_(variable|parameter|import)" || printf '%b\n' "$(G)$(OK) No unused symbols found$(R)"))
dscanner-unused: ## Quality > Find unused imports/symbols
$(eval $(call _ds_rule,complexity,complexity check,--styleCheck,| grep "cyclomatic_complexity" || printf '%b\n' "$(G)$(OK) No high-complexity functions found$(R)"))
dscanner-complexity: ## Quality > Cyclomatic complexity check
$(eval $(call _ds_rule,imports,import analysis,--imports,|| true))
dscanner-imports: ## Quality > Import analysis
$(eval $(call _ds_rule,fix,auto-fix,--fixStyle,|| true))
dscanner-fix: ## Quality > Auto-fix style issues
$(eval $(call _ds_rule,size,SLOC count,--sloc,|| true))
dscanner-size: ## Quality > SLOC count
$(eval $(call _ds_rule,outline,outline,--outline,|| true))
dscanner-outline: ## Quality > Outline

dscanner-all: dscanner-syntax dscanner-lint dscanner-unused dscanner-complexity ## Quality > Run all D-Scanner checks

# ----------------------------------------------------------------------------
# Docker Compose
# ----------------------------------------------------------------------------

ensure-colima:
	@if ! command -v docker >/dev/null 2>&1; then \
		if command -v colima >/dev/null 2>&1; then \
			if colima status >/dev/null 2>&1; then \
				printf '\n%b\n' "$(Y)$(WR) Colima is running but Docker CLI is not installed$(R)"; \
			else \
				printf '\n%b\n' "$(Y)$(WR) Docker daemon is not reachable$(R)"; \
			fi; \
			printf '%b' "$(C)Install Docker CLI now? [Y/n] $(R)"; \
			read -r answer < /dev/tty; \
			case "$$answer" in \
				[Nn]|[Nn][Oo]) \
					printf '%b\n' "$(Y)$(WR) Aborted. Install manually: brew install docker$(R)"; \
					exit 1; \
					;; \
				*) \
					printf '%b\n' "$(C)→ Installing Docker CLI...$(R)"; \
					brew install docker docker-compose 2>/dev/null || \
						brew install docker 2>/dev/null || \
						(printf '%b\n' "$(Y)$(WR) brew not found. Install Docker CLI manually.$(R)"; exit 1); \
					;; \
			esac; \
		else \
			printf '\n%b\n' "$(Y)$(WR) Docker is not installed and Colima is not available$(R)"; \
			printf '%b\n' "$(D)Install: brew install colima docker docker-compose$(R)"; \
			exit 1; \
		fi; \
	elif ! docker info >/dev/null 2>&1; then \
		if command -v colima >/dev/null 2>&1 && ! colima status >/dev/null 2>&1; then \
			printf '\n%b\n' "$(Y)$(WR) Docker daemon is not reachable$(R)"; \
			printf '%b' "$(C)Colima appears installed but stopped. Start it now? [Y/n] $(R)"; \
			read -r answer < /dev/tty; \
			case "$$answer" in \
				[Nn]|[Nn][Oo]) \
					printf '%b\n' "$(Y)$(WR) Aborted. Start manually: colima start$(R)"; \
					exit 1; \
					;; \
				*) \
					printf '%b\n' "$(C)→ Starting Colima...$(R)"; \
					colima start; \
					;; \
			esac; \
		else \
			printf '\n%b\n' "$(Y)$(WR) Docker daemon is not reachable$(R)"; \
			printf '%b\n' "$(D)Check: docker info  |  colima status$(R)"; \
			exit 1; \
		fi; \
	fi

docker-up: ensure-colima ## Docker > Start all services with Docker Compose
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Building Docker images — staged cache  $(R)"
	@# Gateway and engine now build from separate targets (runtime-gateway/engine) — build both.
	@# Uses BuildKit staged cache (--mount=type=cache for apt + /build/.dub): no source change → CACHED.
	@DOCKER_BUILDKIT=1 docker compose build ircfiber-gateway ircfiber-engine
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Docker Services  $(R)"
	@docker compose up -d
docker-down: ensure-colima ## Docker > Stop ALL IRC Fiber containers (3 compose stacks + loose containers)
	@printf '%b\n' "$(D)→ Stopping test stack (docker-compose.yml)...$(R)"
	@docker compose down --remove-orphans --timeout 10 2>/dev/null; true
	@printf '%b\n' "$(BG)$(OK) Test stack stopped$(R)"
	@printf '%b\n' "$(D)→ Stopping test stack (docker-compose.test.yml)...$(R)"
	@docker compose -f docker-compose.test.yml down --timeout 10 2>/dev/null; true
	@printf '%b\n' "$(BG)$(OK) Test stack stopped$(R)"
	@printf '%b\n' "$(D)→ Stopping local dev stack (deploy/local/docker-compose.yml)...$(R)"
	@if [ -f deploy/local/docker-compose.yml ]; then \
		docker compose -f deploy/local/docker-compose.yml down --remove-orphans --timeout 15 2>/dev/null; true; \
	else \
		printf '%b\n' "$(D)  (skipped — deploy/local/docker-compose.yml not present)$(R)"; \
	fi
	@if docker network inspect irc_fiber_irc_network >/dev/null 2>&1; then \
		printf '%b\n' "$(D)→ Detaching any external containers from irc_fiber_irc_network...$(R)"; \
		attached=$$(docker network inspect irc_fiber_irc_network --format '{{range .Containers}}{{.Name}} {{end}}' | tr ' ' '\n' | grep -v '^$$' | sort -u); \
		if [ -n "$$attached" ]; then \
			printf '%b\n' "$$attached" | while IFS= read -r name; do \
				docker network disconnect -f irc_fiber_irc_network "$$name" 2>/dev/null; true; \
			done; \
		fi; \
		docker network rm irc_fiber_irc_network 2>/dev/null; true; \
	fi
	@if docker network inspect irc_fiber_local ircfiber_local ircfiber_dev_irc_network >/dev/null 2>&1; then \
		for net in irc_fiber_local ircfiber_local ircfiber_dev_irc_network; do \
			if docker network inspect $$net >/dev/null 2>&1; then \
				attached=$$(docker network inspect $$net --format '{{range .Containers}}{{.Name}} {{end}}' | tr ' ' '\n' | grep -v '^$$' | sort -u); \
				if [ -n "$$attached" ]; then \
					printf '%b\n' "$$attached" | while IFS= read -r name; do \
						docker network disconnect -f $$net "$$name" 2>/dev/null; true; \
					done; \
				fi; \
				docker network rm $$net 2>/dev/null; true; \
			fi; \
		done; \
	fi
	@printf '%b\n' "$(D)→ Stopping any remaining IRC Fiber containers (fallback for compose-metadata drift)...$(R)"
	@docker container ls -q 2>/dev/null \
		| xargs -r docker inspect --format '{{.Name}} {{.Id}} {{index .Config.Labels "com.docker.compose.project"}} {{index .Config.Labels "com.docker.compose.config-hash"}}' 2>/dev/null \
		| grep -E '(irc[_-]fiber|ircd_test|irc_engine|ircd[_-]|irc_redis|irc_mongo|anope|unreal_sasl|mock-irc-op|sweet_|builder-img|ircfiber[_-])' \
		| awk '{print $$2}' \
		| xargs -r docker stop --timeout 10 2>/dev/null; true
	@printf '%b\n' "$(D)→ Removing stopped containers with IRC Fiber compose labels...$(R)"
	@docker container prune --force --filter "label=com.docker.compose.project=irc_fiber" 2>/dev/null; true
	@docker container prune --force --filter "label=com.docker.compose.project=ircfiber_prod" 2>/dev/null; true
	@docker container prune --force --filter "label=com.docker.compose.project=local" 2>/dev/null; true
	@docker container prune --force --filter "label=com.docker.compose.project=ircfiber_local" 2>/dev/null; true
	@docker container prune --force --filter "label=com.docker.compose.project=ircfiber_dev" 2>/dev/null; true
	@printf '%b\n' "$(BG)$(OK) All IRC Fiber containers stopped$(R)"

docker-down-test: ensure-colima ## Docker > Stop test services (ircd + mongo + redis)
	@printf '\n%b\n' "$(D)→ Stopping Docker test services (docker-compose.test.yml)...$(R)"
	@docker compose -f docker-compose.test.yml down
	@printf '%b\n' "$(BG)$(OK) Test services stopped$(R)"

docker-up-test: ensure-colima ## Docker > Start full test stack (ircd + mongo + redis + gateway + engine)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting test stack (docker-compose.test.yml)  $(R)"
	@docker compose -f docker-compose.test.yml up -d ircd redis mongo ircfiber-gateway ircfiber-engine
	@printf '\n%b\n' "$(D)Waiting for gateway health check at http://127.0.0.1:8090/health ...$(R)"
	@for i in $$(seq 1 30); do \
		if curl -fsS http://127.0.0.1:8090/health >/dev/null 2>&1; then \
			printf '%b\n' "$(BG)$(OK) Test stack healthy$(R)"; exit 0; \
		fi; \
		sleep 1; \
	done
	@printf '%b\n' "$(Y)$(WR) Gateway did not become healthy in 30s$(R)"

test-server-log: docker-up-test ## Test > Run server-log timeline integration test (Node + WebSocket, against local ircd)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running server-log timeline integration test  $(R)"
	@PLAYWRIGHT_BASE_URL=$${PLAYWRIGHT_BASE_URL:-http://127.0.0.1:8090} node tests/server-log-timeline.test.mjs

test-server-log-playwright: docker-up-test ## Test > Run server-log timeline Playwright spec (browser-level)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running server-log Playwright spec  $(R)"
	@cd e2e && npx playwright test server-log-timeline.spec.js

test-connection-log-timing: ## Test > Measure connection-log render timing (Playwright, requires local dev stack running with ircd)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Measuring connection-log render timing  $(R)"
	@cd e2e && TEST_IRC_HOST=ircd npx playwright test connection-log-timing.spec.js

test-connection-log-timing-local: ## Test > Same, but for local dev with native engine (ircd on localhost:6667)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Measuring connection-log render timing (local dev)  $(R)"
	@cd e2e && TEST_IRC_HOST=127.0.0.1 npx playwright test connection-log-timing.spec.js

seed-test-network: docker-up-test ## Utils > Seed a LocalIRCd network against the test stack (admin/REDACTED by default)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Seeding test network LocalIRCd  $(R)"
	@FIBER_USERNAME=$${FIBER_USERNAME:-admin} FIBER_PASSWORD=$${FIBER_PASSWORD:-REDACTED} ./scripts/seed-test-network.sh

docker-prune: ensure-colima ## Docker > Remove dangling images, stopped containers, build cache (safe — keeps volumes)
	@printf '%b\n' "$(D)→ Pruning stale Docker resources...$(R)"
	@docker system prune -af --volumes=false 2>&1 | tail -2
	@printf '%b\n' "$(BG)$(OK) Docker resources pruned$(R)"

docker-clean: ensure-colima ## Docker > Full cleanup including unused volumes (⚠ destroys mongo/redis data)
	@printf '%b\n' "$(Y)$(WR) This removes ALL unused Docker resources INCLUDING volumes!$(R)"
	@printf '%b\n' "$(Y)$(WR) MongoDB and Redis data will be lost!$(R)"
	@printf '%b' "$(C)Are you sure? [y/N] $(R)"; \
		read -r answer < /dev/tty; \
		case "$$answer" in \
			[Yy]|[Yy][Ee][Ss]) ;; \
			*) printf '%b\n' "$(Y)$(WR) Aborted$(R)"; exit 1 ;; \
		esac
	@docker system prune -af --volumes 2>&1 | tail -2
	@printf '%b\n' "$(BG)$(OK) Full Docker cleanup complete$(R)"

docker-logs: ensure-colima ## Docker > Tail Docker logs
	@docker compose logs -f

docker-build: ensure-colima ## Docker > Rebuild Docker image
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Building Docker Image  $(R)"
	@docker compose build
	@printf '%b\n' "$(BG)$(OK) Docker image built$(R)"

docker-restart-gateway: docker-restart-web

docker-up-web: ensure-colima ## Docker > Start web server only
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Web Server (Gateway)  $(R)"
	@docker compose up -d ircfiber-gateway
	@printf '%b\n' "$(BG)$(OK) Web server started$(R) $(D)(http://localhost:8090)$(R)"

docker-down-web: ensure-colima ## Docker > Stop web server only
	@printf '%b\n' "$(D)→ Stopping web server...$(R)"
	@docker compose stop ircfiber-gateway
	@printf '%b\n' "$(BG)$(OK) Web server stopped$(R)"

docker-restart-web: ensure-colima ## Docker > Restart web server only
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Restarting Web Server (Gateway)  $(R)"
	@docker compose build ircfiber-gateway
	@docker compose up -d --force-recreate ircfiber-gateway
	@printf '%b\n' "$(BG)$(OK) Web server restarted$(R) $(D)(http://localhost:8090)$(R)"

docker-up-backend: ensure-colima ## Docker > Start backend services only
	@printf '\n%b\n' "$(D)→ Pruning stale Docker layers...$(R)"
	@docker system prune -af --volumes=false 2>&1 | tail -2
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Backend Services  $(R)"
	@docker compose up -d ircfiber-engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services started$(R)"

docker-down-backend: ensure-colima ## Docker > Stop backend services only
	@printf '%b\n' "$(D)→ Stopping backend services...$(R)"
	@docker compose stop ircfiber-engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services stopped$(R)"

docker-restart-backend: ensure-colima ## Docker > Restart backend services only
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Restarting Backend Services  $(R)"
	@docker compose up -d --build --force-recreate ircfiber-engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services restarted$(R)"
# ─── Split containers: API (gateway) vs Engine — easy start/stop ─────────────
up: docker-up ## Docker > Start both API + Engine as separate containers (split)
down: docker-down ## Docker > Stop both
gateway-up: docker-up-web ## Docker > Start API (gateway) container only
gateway-down: docker-down-web ## Docker > Stop API container only
engine-up: ## Docker > Start Engine container only
	@docker compose up -d ircfiber-engine
engine-down: ## Docker > Stop Engine container only
	@docker compose stop ircfiber-engine
engine-logs: logs-engine ## Docker > Tail engine container logs
gateway-logs: logs-gateway ## Docker > Tail gateway container logs
# ----------------------------------------------------------------------------
# Docker — interactive shells
# ----------------------------------------------------------------------------
# Usage:
#   make docker-shell              # gateway (irc_fiber_test) by default
#   make docker-shell-engine       # IRC engine
#   make docker-shell-redis        # redis with redis-cli as entrypoint
#   make docker-shell-mongo        # mongo with mongosh as entrypoint
#   make docker-shell-ircd         # test ircd
#   make docker-shell SVC=redis    # any service by container name
#
# Compose files: respects DOCKER_COMPOSE (default: docker-compose.yml).
# Both docker-compose.yml and docker-compose.test.yml use the same
# container_name values, so `docker exec` always finds the right one.
DOCKER_COMPOSE ?= docker-compose.yml
SHELL_SVC ?= ircfiber-gateway
docker-shell: ensure-colima ## Docker > Open bash shell in the gateway container
	@SVC=$${SVC:-$(SHELL_SVC)}; \
		printf '\n%b\n' "$(_BCn)$(K)$(B)  Opening shell in $${SVC}  $(R)"; \
		if ! docker ps --format '{{.Names}}' | grep -q "$${SVC}"; then \
			printf '%b\n' "$(Y)$(WR) Container $${SVC} is not running.$(R)"; \
			printf '%b\n' "$(D)  • For the full Docker stack:    make docker-up$(R)"; \
			printf '%b\n' "$(D)  • Just redis/mongo containers: make docker-up-backend$(R)"; \
			printf '%b\n' "$(D)  • If you used 'make up', the engine/gateway are running on the host, not in Docker.$(R)"; \
			exit 1; \
		fi; \
		SHELL_BIN=$$(docker exec -it --user root "$${SVC}" sh -c 'command -v bash >/dev/null 2>&1 && echo bash || echo sh'); \
		docker exec -it --user root "$${SVC}" "$${SHELL_BIN}"

docker-shell-engine: ensure-colima ## Docker > Open bash shell in the IRC engine container
	@SVC=irc_engine; \
		printf '\n%b\n' "$(_BCn)$(K)$(B)  Opening shell in $${SVC}  $(R)"; \
		if ! docker ps --format '{{.Names}}' | grep -q "$${SVC}"; then \
			printf '%b\n' "$(Y)$(WR) Container $${SVC} is not running.$(R)"; \
			printf '%b\n' "$(D)  • For the full Docker stack:    make docker-up$(R)"; \
			printf '%b\n' "$(D)  • If you used 'make up', the engine is running on the host as ./irc-fiber-engine.$(R)"; \
			printf '%b\n' "$(D)  • Host logs:  make logs-engine  (host:  tail -f /tmp/irc-fiber-engine.log)$(R)"; \
			exit 1; \
		fi; \
		SHELL_BIN=$$(docker exec -it --user root "$${SVC}" sh -c 'command -v bash >/dev/null 2>&1 && echo bash || echo sh'); \
		docker exec -it --user root "$${SVC}" "$${SHELL_BIN}"

docker-shell-redis: ensure-colima ## Docker > Open redis-cli against the redis container
	@SVC=redis; \
		printf '\n%b\n' "$(_BCn)$(K)$(B)  Opening redis-cli in $${SVC}  $(R)"; \
		if ! docker ps --format '{{.Names}}' | grep -q "$${SVC}"; then \
			printf '%b\n' "$(Y)$(WR) Container $${SVC} is not running.$(R)"; \
			printf '%b\n' "$(D)  • Start it:  make docker-up-backend  (or  make docker-up  for everything)$(R)"; \
			printf '%b\n' "$(D)  • If you used 'make up', redis is running on the host at 127.0.0.1:6379.$(R)"; \
			printf '%b\n' "$(D)  • Host fallback:  redis-cli -h 127.0.0.1 -p 6379$(R)"; \
			exit 1; \
		fi; \
		docker exec -it "$${SVC}" redis-cli

docker-shell-mongo: ensure-colima ## Docker > Open mongosh against the mongo container
	@SVC=mongo; \
		printf '\n%b\n' "$(_BCn)$(K)$(B)  Opening mongosh in $${SVC}  $(R)"; \
		if ! docker ps --format '{{.Names}}' | grep -q "$${SVC}"; then \
			printf '%b\n' "$(Y)$(WR) Container $${SVC} is not running.$(R)"; \
			printf '%b\n' "$(D)  • Start it:  make docker-up-backend  (or  make docker-up  for everything)$(R)"; \
			printf '%b\n' "$(D)  • If you used 'make up', mongo is running on the host at 127.0.0.1:27017.$(R)"; \
			printf '%b\n' "$(D)  • Host fallback:  mongosh mongodb://127.0.0.1:27017/ircfiber$(R)"; \
			exit 1; \
		fi; \
		docker exec -it "$${SVC}" mongosh ircfiber

docker-shell-ircd: ensure-colima ## Docker > Open bash shell in the test ircd container
	@SVC=ircd; \
		printf '\n%b\n' "$(_BCn)$(K)$(B)  Opening shell in $${SVC}  $(R)"; \
		if ! docker ps --format '{{.Names}}' | grep -q "$${SVC}"; then \
			printf '%b\n' "$(Y)$(WR) Container $${SVC} is not running. Start it: make ircd-up$(R)"; \
			exit 1; \
		fi; \
		SHELL_BIN=$$(docker exec -it --user root "$${SVC}" sh -c 'command -v bash >/dev/null 2>&1 && echo bash || echo sh'); \
		docker exec -it --user root "$${SVC}" "$${SHELL_BIN}"

ircd-up: ensure-colima ## Docker > Start test IRCD (localhost:6667)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting IRCD Test Server  $(R)"
	@docker compose up -d ircd
	@printf '%b\n' "$(BG)$(OK) IRCD started$(R) $(D)(localhost:6667)$(R)"

ircd-down: ensure-colima ## Docker > Stop test IRCD
	@printf '%b\n' "$(D)→ Stopping IRCD...$(R)"
	@docker compose stop ircd
	@printf '%b\n' "$(BG)$(OK) IRCD stopped$(R)"

docker-restart: docker-restart-web docker-restart-backend ## Docker > Restart all Docker services
	@printf '%b\n' "$(BG)$(OK) All services restarted$(R)"

docker-restart-code: ensure-colima ## Dev > Rebuild frontend + D binaries + restart gateway & engine (keeps redis/mongo/ircd running)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Rebuilding frontend (Vite)  $(R)"
	@npm --prefix frontend run build 2>&1 | tail -3
	@printf '%b\n' "$(BG)$(OK) Frontend built$(R)"
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Rebuilding D binaries  $(R)"
	@# Gateway and engine now use separate images/targets — build both.
	@docker compose build ircfiber-gateway ircfiber-engine
	@printf '%b\n' "$(BG)$(OK) Binaries built$(R)"
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Restarting gateway + engine  $(R)"
	@docker compose up -d --force-recreate ircfiber-gateway ircfiber-engine
# ----------------------------------------------------------------------------
# Dev — local compose stack
# ----------------------------------------------------------------------------

.PHONY: local-dev-up local-dev-down local-dev-down-clean local-dev-smoke local-dev-up-observability
.PHONY: local-up local-up-observability local-down local-down-clean

local-up:                                 ## Local > Up without SigNoz (default, ~300 MB)
	docker compose -f deploy/local/docker-compose.yml up -d

local-up-observability:                   ## Local > Up with SigNoz (observability, ~4 GB)
	IRCFIBER_OTEL_ENABLED=1 docker compose --profile observability -f deploy/local/docker-compose.yml up -d

local-down:                               ## Local > Down (preserve data)
	docker compose -f deploy/local/docker-compose.yml down

local-down-clean:                         ## Local > Down + wipe volumes (Caution: destroys data)
	docker compose -f deploy/local/docker-compose.yml down -v

local-dev-up:                               ## Dev > Bring up local SigNoz + IRC Fiber stack
	docker compose -f deploy/local/docker-compose.yml up -d

local-dev-down:                             ## Dev > Stop local stack (preserve data)
	docker compose -f deploy/local/docker-compose.yml down

local-dev-down-clean:                       ## Dev > Stop local stack and wipe all volumes (Caution: destroys ClickHouse data)
	docker compose -f deploy/local/docker-compose.yml down -v

local-dev-up-observability:                 ## Dev > Bring up local stack WITH SigNoz (~4 GB)
	IRCFIBER_OTEL_ENABLED=1 docker compose --profile observability -f deploy/local/docker-compose.yml up -d

local-dev-smoke:                            ## Dev > Run observability smoke test against local stack
	bash tests/local-dev/smoke-observability.sh

# ----------------------------------------------------------------------------
# Data Sync — Local Docker → Tailnet
# ----------------------------------------------------------------------------
#
# Delegate to the Ansible playbook. The playbook handles vault decryption
# natively, gets confirmation via the `pause` module, and runs against
# the tailnet host via SSH (dedicated unpassphrased key configured in
# ~/.ssh/config). Tags let you run Mongo or Redis only.
#
#   make sync-db-to-tailnet                 # both, interactive
#   make sync-mongo-to-tailnet              # Mongo only
#   make sync-redis-to-tailnet              # Redis only
#   SYNC_YES=1 make sync-db-to-tailnet      # skip confirmation

sync-db-to-tailnet: ## Data > Sync local Mongo + Redis to tailnet (playbook, prompts unless SYNC_YES=1)
	@cd deploy && \
		[ -n "$$SYNC_YES" ] && A="-e sync_yes=true" || A=""; \
		[ -n "$$SYNC_TAG" ] && A="$$A --tags $$SYNC_TAG"; \
		ansible-playbook playbooks/sync-db-to-tailnet.yml $$A

sync-mongo-to-tailnet: ## Data > Sync only local Mongo → tailnet
	@$(MAKE) --no-print-directory sync-db-to-tailnet SYNC_TAG=mongo

sync-redis-to-tailnet: ## Data > Sync only local Redis → tailnet
	@$(MAKE) --no-print-directory sync-db-to-tailnet SYNC_TAG=redis

# ----------------------------------------------------------------------------
# Deploy — incremental remote builds via Ansible + SSH
# ----------------------------------------------------------------------------
#
# Targets your production tailnet host (ircfiber-ovh-1) using the ansible
# playbooks in deploy/. All deploy commands run from the deploy/ directory.
#
# Vault: by default reads deploy/.vault_pass.txt. Override with:
#   VAULT_PASS_FILE=~/.vault_pass.txt make update
#
# Usage:
#   make update           # fast incremental binary deploy (rsync + BuildKit)
#   make update-full      # full docker image rebuild (Containerfile, all layers)
#   make update-assets    # asset-only: just public/* (no build, no restart)
#   make update-status    # show running images on the target
#   make update-clean     # nuke builder cache on the target (forces cold path)
#   make deploy           # alias for update-full
#
# Override target host:
#   TARGET=my-other-host make update
# ----------------------------------------------------------------------------

# Vault pass: by default reads deploy/.vault_pass.txt (resolves relative to
# the deploy/ cwd of every consuming recipe). Set VAULT_PASS_FILE to override.
_vault_arg = --vault-password-file $(or $(VAULT_PASS_FILE),.vault_pass.txt)
_target      = $(or $(TARGET),ircfiber-ovh-1)
_target_ssh   = $(or $(TARGET_SSH),40.160.227.49)
_playbook    = cd deploy && ansible-playbook -l $(_target) $(_vault_arg)

update: frontend build build-engine ## Deploy > Build frontend + gateway + engine, handoff-deploy (zero disconnect for engines)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploy → $(_target)  $(R)"
	@$(_playbook) playbooks/deploy-update.yml $(if $(SKIP_MIGRATE),-e skip_migrate=true)
	# The playbook's rsync handles public/ + backend/views/ (dist/ included since
	# the read-only mount on the container means docker cp writes silently
	# fail). The shell-level push below is a belt-and-suspenders fallback
	# in case a build produced a new dist AFTER the rsync step (the
	# `frontend` target runs first, but `inject-manifest.js` updates
	# backend/views/index.dt in place, so re-syncing dist/ + views/ here is safe).
	# Chain the SigNoz dashboards + alerts deploys so structured
	# log changes, new dashboards, and new alert rules all land in
	# the same `make update` invocation. Both are idempotent (by
	# title / by compositeKey) and safe to re-run. Skip with
	# `SKIP_SIGNOZ=1` when you only want binary + frontend deploy.
ifeq ($(SKIP_SIGNOZ),1)
	@printf '%b\n' "$(Y)$(WR) SKIP_SIGNOZ=1 — skipping dashboards + alerts deploy$(R)"
else
	@printf '%b\n' "$(_BCn)$(K)$(B)  Deploying SigNoz dashboards + alerts  $(R)"
	@$(_playbook) playbooks/signoz_dashboards.yml 2>&1 | tail -20
	@$(_playbook) playbooks/signoz_alerts.yml 2>&1 | tail -20
endif

# Alias: fast path is the default
update-fast: update ## Deploy > Force hot path (same as `make update`)

# Full docker image rebuild: builds Containerfile from scratch on the target
# (or via registry), recreates gateway + engine containers.
update-full: ## Deploy > Full docker image rebuild + container recreate
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Full image rebuild → $(_target)  $(R)"
	@$(_playbook) playbooks/deploy.yml $(if $(SKIP_MIGRATE),-e skip_migrate=true)

deploy: update-full ## Deploy > Alias for update-full

# Build frontend + push public/ + views/ to running gateway via SSH.
# The gateway reads these files from disk at request time, so no binary
# change, no container restart, no reconnect. ~2-3s after build.
#
# Container's /app/public and /app/views are READ-ONLY bind mounts from
# /opt/ircfiber-src/{public,views}/ on the host — the rsync inside the
# playbook already pushes there, so the push below only matters for
# `make update-assets` (which doesn't run the playbook).
update-assets: frontend ## Deploy > Build frontend + push public/* to running gateway (no restart)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Asset push → $(_target_ssh) ($(_target))  $(R)"
	@printf '%b\n' "$(D)  Tarring public/ → ssh → docker exec tar -xf - (clean extract)$(R)"
	@tar cz --no-xattrs --format=ustar -C public . | ssh deploy@$(_target_ssh) 'docker exec -i ircfiber-gateway sh -c "rm -rf /app/public/dist/ /app/public/.vite/ /app/public/assets/ 2>/dev/null; tar xzf - -C /app/public"'
	@printf '%b\n' "$(D)  Pushing backend/views/index.dt (updated bundle hashes)$(R)"
	@ssh deploy@$(_target_ssh) 'docker exec -i ircfiber-gateway sh -c "cat > /app/views/index.dt"' < backend/views/index.dt

# Show running container images and versions on the target.
update-status: ## Deploy > Show running containers & image versions
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploy status → $(_target)  $(R)"
	@$(_playbook) playbooks/status.yml

# Nuke BuildKit cache + builder image on the target.
# Forces cold rebuild: full dub download + compile next update.
update-clean: ## Deploy > Nuke BuildKit cache + builder image on target
	@printf '\n%b\n' "$(_BY)$(K)$(B)  Cleaning builder cache → $(_target_ssh) ($(_target))  $(R)"
	@ssh deploy@$(_target_ssh) 'docker rmi ircfiber-builder:latest 2>/dev/null; docker builder prune --force 2>/dev/null; echo "Builder cache cleared"'

# ── Graceful engine handoff deploy ────────────────────────────────────────
# Hot-reloads the engine binary WITHOUT closing IRC sockets. The new binary
# is started inside the existing container alongside the old engine. The old
# engine transfers its live TCP sockets to the new engine via SCM_RIGHTS FD
# transfer (for plain connections) and soft-reconnects TLS connections.
#
# Usage:
#   make handoff                                       # all engine hosts
#   make handoff TARGET=ircfiber-ovh-1                 # single host
#   make handoff-backup                                # backup engine only
handoff: build-engine ## Deploy > Graceful engine hot-reload (zero IRC disconnect)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Hot-reload engine → $(_target)  $(R)"
	@printf '%b\n' "$(D)  New engine runs inside existing container — IRC sockets preserved$(R)"
	@$(_playbook) playbooks/deploy-handoff.yml

# Zero-disconnect engine hot-reload via exec(2).
# Replaces the OLD engine's process image with the NEW binary in-place.
# The TCP socket survives the exec (same PID, same FDs), so the IRC
# server sees ONE continuous connection — no QUIT, no reconnect, no
# nick collision. This is true Erlang-style hot code loading.
#
# Usage:
#   make update-exec                                 # all engine hosts
#   make update-exec TARGET=ircfiber-ovh-1           # single host
update-exec: build-engine ## Deploy > Zero-disconnect exec-based engine hot-reload
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Zero-disconnect exec-reload engine → $(_target)  $(R)"
	@printf '%b\n' "$(D)  OLD engine exec()s into NEW binary in-place — IRC socket survives$(R)"
	@$(_playbook) playbooks/deploy-update-exec.yml

# ----------------------------------------------------------------------------
# Cross Compilation
# ----------------------------------------------------------------------------
# Cross Compilation
# ----------------------------------------------------------------------------

# Cross-compilation template: $(1)=target suffix, $(2)=display name, $(3)=arch flag
define _cross_rule
cross-linux-$(1): ## Cross > Cross-compile for Linux $(2)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Cross-compiling for Linux $(2)  $(R)"
	@$(DUB) build --config=release --arch=$(3) 2>&1 | tail -8 || \
		printf '%b\n' "$(Y)$(WR) Cross-compilation may require a Linux $(2) toolchain$(R)"
endef

$(eval $(call _cross_rule,x64,x64,x86_64-linux-gnu))
cross-linux-x64: ## Cross > Cross-compile for Linux x64
$(eval $(call _cross_rule,arm64,ARM64,aarch64-linux-gnu))
cross-linux-arm64: ## Cross > Cross-compile for Linux ARM64
$(eval $(call _cross_rule,armv7,ARMv7,arm-linux-gnueabihf))
cross-linux-armv7: ## Cross > Cross-compile for Linux ARMv7

# ----------------------------------------------------------------------------
# Dependency Check
# ----------------------------------------------------------------------------

deps-check: ## Utils > Check for required dependencies
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Checking Dependencies  $(R)"
	@which $(DUB) >/dev/null && printf '  %b\n' "$(G)$(OK) dub$(R)" || \
		printf '  %b\n' "$(Y)$(WR) dub - Install D compiler package$(R)"
	@which $(LDC) >/dev/null && printf '  %b\n' "$(G)$(OK) ldc2$(R)" || \
		printf '  %b\n' "$(Y)$(WR) ldc2 - Install: brew install ldc$(R)"
	@which docker >/dev/null && printf '  %b\n' "$(G)$(OK) docker$(R)" || \
		printf '  %b\n' "$(D)$(BL) docker - optional$(R)"
	@which redis-cli >/dev/null && printf '  %b\n' "$(G)$(OK) redis-cli$(R)" || \
		printf '  %b\n' "$(D)$(BL) redis-cli - optional$(R)"
	@which mongosh >/dev/null && printf '  %b\n' "$(G)$(OK) mongosh$(R)" || \
		printf '  %b\n' "$(D)$(BL) mongosh - optional$(R)"

# ----------------------------------------------------------------------------
# Utility Targets
# ----------------------------------------------------------------------------

clean: ## Utils > Remove build artifacts
	@printf '%b\n' "$(D)→ Cleaning build artifacts...$(R)"
	@rm -f $(APP) *.o .docker-build-stamp
	@rm -rf .dub
	@$(DUB) clean 2>/dev/null || true
	@printf '%b\n' "$(BG)$(OK) Clean complete$(R)"

# ----------------------------------------------------------------------------
# Help — auto-generated from ## comments on each target
# ----------------------------------------------------------------------------

help: ## Utils > Show this help (use-case matrix in the source header)
	@printf '\n\033[1mIRC Fiber — Component Workflows\033[0m\n'
	@printf '\033[2m=====================================\033[0m\n'
	@printf '\n\033[1mUSE-CASE MATRIX\033[0m\n'
	@printf '  \033[36mI want to change only the frontend (Svelte/CSS/HTML)…\033[0m\n'
	@printf '    Terminal 1: \033[92mmake dev-live\033[0m   (Vite HMR, no local D backend)\n'
	@printf '  \033[36mI want to change the engine D code and see it live…\033[0m\n'
	@printf '    Terminal 1: \033[92mmake debug-live\033[0m  (supervised engine → tailnet DBs)\n'
	@printf '    Terminal 2: \033[92mmake watch-engine\033[0m (rebuilds + restarts on .d save)\n'
	@printf '    Terminal 3: \033[92mmake logs\033[0m         (live tail)\n'
	@printf '  \033[36mI want to change the gateway D code…\033[0m\n'
	@printf '    Terminal 1: \033[92mmake debug-live\033[0m  (or \033[92mmake debug\033[0m for local DBs)\n'
	@printf '    Terminal 2: \033[92mmake watch-gateway\033[0m\n'
	@printf '  \033[36mI want full visual + D iteration on my machine…\033[0m\n'
	@printf '    Terminal 1: \033[92mmake debug\033[0m        (full local stack)\n'
	@printf '    Terminal 2: \033[92mmake dev\033[0m          (Vite HMR against the local gateway)\n'
	@printf '  \033[36mI want to test engine reconnect against a real IRC server…\033[0m\n'
	@printf '    \033[92mmake debug-live\033[0m  → open \033[36mhttp://localhost:8090\033[0m → click Reconnect\n'
	@printf '  \033[36mI want to deploy to my tailnet server…\033[0m\n'
	@printf '    \033[92mmake update\033[0m          (fast incremental binary deploy + push SigNoz dashboards/alerts)\n'
	@printf '    \033[92mSKIP_SIGNOZ=1 make update\033[0m  (skip dashboards + alerts deploy)\n'
	@printf '    \033[92mmake update-full\033[0m      (full docker image rebuild)\n'
	@printf '    \033[92mmake update-assets\033[0m     (asset-only: public/*, ~2-3s)\n'
	@printf '    \033[92mmake update-status\033[0m     (show running containers)\n'
	@printf '    \033[92mmake deploy-signoz\033[0m      (push only dashboards + alerts — for refreshing observability config without a code deploy)\n'
	@printf '\n'
	@awk 'BEGIN {FS = ":.*##[ \t]*"} \
		/^[a-zA-Z0-9_-]+:.*##/ { \
			target = $$1; \
			rest = $$2; \
			p = index(rest, ">"); \
			if (p > 0) { \
				cat = substr(rest, 1, p - 1); \
				desc = substr(rest, p + 1); \
				gsub(/^[ \t]+|[ \t]+$$/, "", cat); \
				gsub(/^[ \t]+|[ \t]+$$/, "", desc); \
			} else { \
				cat = "Other"; desc = rest; \
			} \
			if (!(cat in seen)) { \
				seen[cat] = ++ncat; \
				order[ncat] = cat; \
			} \
			idx = ++cnt[cat]; \
			t[cat, idx] = target; \
			d[cat, idx] = desc; \
			w = length(target); \
			if (w > mw[cat]) mw[cat] = w; \
		} \
		END { \
			for (i = 1; i <= ncat; i++) { \
				c = order[i]; \
				col = ""; \
				if (c == "Component")     col = "\033[46m\033[30m\033[1m"; \
				else if (c == "Quick Start") col = "\033[42m\033[30m\033[1m"; \
				else if (c == "Build")       col = "\033[46m\033[30m\033[1m"; \
				else if (c == "Docker")      col = "\033[43m\033[30m\033[1m"; \
				else if (c == "Quality")     col = "\033[45m\033[30m\033[1m"; \
				else if (c == "Cross")       col = "\033[44m\033[30m\033[1m"; \
				if (c == "Utils") printf "\n\033[2m%s:\033[0m\n", c; \
				else           printf "\n%s  %s  \033[0m\n", col, c; \
				w = mw[c] + 1; \
				for (j = 1; j <= cnt[c]; j++) { \
					printf "  \033[92mmake %-*s\033[0m %s\n", w, t[c, j], d[c, j]; \
				} \
			} \
			print ""; \
		}' $(MAKEFILE_LIST)

# ── SigNoz dashboards + alerts deploy ─────────────────────────────
# Pushes the pre-built dashboards + alert rules + notification
# channel to the SigNoz API. Idempotent: matches by title (dashboards)
# or by compositeKey (alerts). Both are run automatically as part
# of `make update`; these targets are for the case where you only
# want to refresh observability config (e.g. after editing a JSON
# dashboard by hand).
#
# Usage:
#   make deploy-signoz-dashboards
#   make deploy-signoz-alerts
#   make deploy-signoz              # both
deploy-signoz-dashboards: ## SigNoz > Push pre-built dashboards (idempotent, by title)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploying SigNoz dashboards → $(_target)  $(R)"
	@$(_playbook) playbooks/signoz_dashboards.yml

deploy-signoz-alerts: ## SigNoz > Push alert rules + notification channel (idempotent, by compositeKey)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploying SigNoz alerts → $(_target)  $(R)"
	@$(_playbook) playbooks/signoz_alerts.yml

deploy-signoz: deploy-signoz-dashboards deploy-signoz-alerts ## SigNoz > Push both dashboards + alerts

# ── IRC daemon (Ergo) deploy ────────────────────────────────────────────────────
# Deploys an Ergo IRC daemon to OVH for product support + testing.
# Requires vault_ircd_oper_password to be set in vault.yml first.
#
# Usage:
#   make deploy-ircd
#   make deploy-ircd TARGET=ircfiber-ovh-1
deploy-ircd: ## IRCd > Deploy Ergo IRC daemon to OVH (ports 6667 + 6697)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploy IRCd → $(_target)  $(R)"
	@$(_playbook) playbooks/ircd.yml

# ── Remote container restart ────────────────────────────────────────────────
# Restart Docker containers on the remote host via Ansible. Wraps the
# restart.yml playbook which supports selecting specific components.
# By default restarts ALL containers (caddy, cloudflared, gateway,
# engine, mongo, redis).
#
# Usage:
#   make deploy-restart                                  # restart everything
#   make deploy-restart COMPONENTS=gateway,engine        # selective restart
#   make deploy-restart COMPONENTS=gateway               # gateway only
#   make deploy-restart TARGET=ircfiber-ovh-1          # different host
# Convenience: restart specific container(s) by name.
# The color variable $(C) is taken (cyan ANSI escape), so the shorthand
# for components is COMP or a trailing argument. Override at invocation:
#
#   make deploy-restart                 # restart EVERYTHING
#   make deploy-restart-gateway         # gateway only
#   make deploy-restart-engine          # engine only
#   make deploy-restart COMP=gateway,engine   # gateway + engine
#   make deploy-restart COMP=gateway          # gateway only

deploy-restart: ## Deploy > Restart remote Docker containers (default: all; override COMP=gateway,engine)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Restarting containers → $(_target)  $(R)"
	@comps="$(or $(COMP),$(COMPONENTS))"; \
		if [ -z "$$comps" ]; then \
			printf '%b\n' "$(C)  → Restarting ALL containers$(R)"; \
		else \
			printf '%b\n' "$(C)  → Restarting: $$comps$(R)"; \
		fi
	@$(_playbook) $(if $(or $(COMP),$(COMPONENTS)),-e components=$(or $(COMP),$(COMPONENTS)),) playbooks/restart.yml

deploy-restart-gateway: ## Deploy > Restart gateway container only
	@$(MAKE) --no-print-directory deploy-restart COMP=gateway

deploy-restart-engine: ## Deploy > Restart engine container only
	@$(MAKE) --no-print-directory deploy-restart COMP=engine

deploy-restart-mongo: ## Deploy > Restart MongoDB container only
	@$(MAKE) --no-print-directory deploy-restart COMP=mongo

deploy-restart-redis: ## Deploy > Restart Redis container only
	@$(MAKE) --no-print-directory deploy-restart COMP=redis

deploy-restart-caddy: ## Deploy > Restart Caddy container only
	@$(MAKE) --no-print-directory deploy-restart COMP=caddy

