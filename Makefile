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
DUB         := dub
LDC         := ldc2
APP         := irc-fiber
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

# Source files
SRCS        := $(shell find source -name '*.d')
DT_SRCS     := $(shell find views -name '*.dt')

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
.PHONY: build build-engine build-release build-debug build-ldc2 frontend frontend-dev frontend-install

# Component Workflows (primary user-facing targets)
.PHONY: dev dev-live debug debug-live stop
.PHONY: engine engine-rebuild engine-restart engine-test
.PHONY: gateway gateway-rebuild gateway-restart
.PHONY: status logs logs-engine logs-gateway logs-supervisor crash-logs
.PHONY: watch watch-engine watch-gateway

# Deprecated aliases (kept for back-compat — see ALIASES section at bottom)
.PHONY: start run run-tailnet run-local run-gateway run-engine
.PHONY: up down down-tailnet restart-web restart-engine-tailnet
.PHONY: logs-web logs-engine-tailnet watch-web

.PHONY: test test-frontend test-all test-watch test-coverage test-lib test-client clean fmt fmt-check lint deps-check
.PHONY: dscanner-install dscanner-all dscanner-syntax dscanner-lint dscanner-unused \
        dscanner-complexity dscanner-imports dscanner-fix dscanner-size dscanner-outline
.PHONY: ensure-colima docker-up docker-down docker-logs docker-build \
        docker-up-web docker-down-web docker-restart-web \
        docker-up-backend docker-down-backend docker-restart-backend docker-restart \
        docker-down-test \
        docker-shell docker-shell-engine docker-shell-redis docker-shell-mongo docker-shell-ircd ircd-up ircd-down
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

# Default backend for `make dev` / `make dev-live`
BACKEND ?= local
VITE_BACKEND_URL ?= https://ircfiber-ovh-1.tail544547.ts.net

ifeq ($(BACKEND),tailnet)
  EFFECTIVE_BACKEND_URL := https://ircfiber-ovh-1.tail544547.ts.net
else ifeq ($(BACKEND),local)
  EFFECTIVE_BACKEND_URL := http://127.0.0.1:8090
else
  EFFECTIVE_BACKEND_URL := $(BACKEND)
endif

# Tailnet connection settings (used by debug-live)
TAILNET_MONGO_URL ?= mongodb://ircfiber:jqgwEv3GJwwizulaj3Fnbd8imqcMH4Gh@100.126.197.92:27017/ircfiber
TAILNET_REDIS_URL ?= redis://100.126.197.92:6379/0

# Local docker connection settings (used by debug)
LOCAL_MONGO_URL ?= mongodb://127.0.0.1:27017/ircfiber
LOCAL_REDIS_URL ?= redis://127.0.0.1:6379/0

# Shared paths for supervisor / logs / pidfiles / crash dumps (relative to project root — avoids space issues)
ENGINE_BIN          := ./irc-fiber-engine
GATEWAY_BIN         := ./irc-fiber
SUPERVISOR_SCRIPT   := ./scripts/irc-fiber-engine-supervisor.sh
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

# Frontend dev pointing at the tailnet gateway (no local D backend at all).
dev-live: ## Component > Frontend dev (Vite) against the TAILNET gateway
	@$(MAKE) --no-print-directory dev BACKEND=tailnet

# Full local stack — gateway + supervised engine, both against local docker DBs.
# For when you're editing the D code and want a clean local environment.
# Runs in the FOREGROUND — supervisor stays backgrounded for engine auto-restart,
# gateway runs in this terminal. ctrl-c cleanly tears down both. Run
# `make logs` in another terminal for live tailing.
debug: build build-engine ## Component > Full stack: gateway + engine (supervised), local docker DBs — ctrl-c to stop
	@$(_docker_setup)
	@bash -c 'set -u; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Engine (supervised) → local docker  $(R)"; \
		rm -f "$(GATEWAY_PIDFILE)" "$(SUPERVISOR_PIDFILE)" "$(ENGINE_PIDFILE)"; \
		: > "$(SUPERVISOR_LOGFILE)"; \
		: > "$(GATEWAY_LOGFILE)"; \
		IRCFIBER_MONGO_URL="$(LOCAL_MONGO_URL)" IRCFIBER_REDIS_URL="$(LOCAL_REDIS_URL)" \
			IRCFIBER_SERVER_ID="$${IRCFIBER_SERVER_ID:-localengine}" \
			IRCFIBER_BIND_ADDRESS="$${IRCFIBER_BIND_ADDRESS:-127.0.0.1}" \
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
		printf "%b\n" "$(Y)$(WR) ctrl-c to stop everything  •  tail logs:  make logs  in another terminal$(R)"; \
		cleanup() { \
			printf "\n%b\n" "$(Y)$(WR) stopping...$(R)"; \
			kill -TERM "$$SUP_PID" 2>/dev/null || true; \
			killall -9 irc-fiber irc-fiber-engine 2>/dev/null || true; \
			rm -f "$(GATEWAY_PIDFILE)" "$(SUPERVISOR_PIDFILE)" "$(ENGINE_PIDFILE)"; \
			printf "%b\n" "$(BG)$(OK) debug stopped$(R)"; \
			exit 0; \
		}; \
		trap cleanup INT TERM EXIT; \
		IRCFIBER_MONGO_URL="$(LOCAL_MONGO_URL)" IRCFIBER_REDIS_URL="$(LOCAL_REDIS_URL)" \
			"$(GATEWAY_BIN)" >> "$(GATEWAY_LOGFILE)" 2>&1; \
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
debug-live: build build-engine ## Component > Full stack: gateway + engine (supervised), TAILNET DBs — ctrl-c to stop
	@bash -c 'set -u; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Engine (supervised) → TAILNET  $(R)"; \
		printf "%b\n" "$(D)  Mongo: $(TAILNET_MONGO_URL)$(R)"; \
		printf "%b\n" "$(D)  Redis: $(TAILNET_REDIS_URL)$(R)"; \
		killall -9 irc-fiber 2>/dev/null || true; \
		sleep 1; \
		rm -f "$(GATEWAY_PIDFILE)" "$(SUPERVISOR_PIDFILE)" "$(ENGINE_PIDFILE)"; \
		: > "$(SUPERVISOR_LOGFILE)"; \
		: > "$(GATEWAY_LOGFILE)"; \
		IRCFIBER_MONGO_URL="$(TAILNET_MONGO_URL)" IRCFIBER_REDIS_URL="$(TAILNET_REDIS_URL)" \
			IRCFIBER_SERVER_ID="$${IRCFIBER_SERVER_ID:-localengine}" \
			IRCFIBER_BIND_ADDRESS="$${IRCFIBER_BIND_ADDRESS:-127.0.0.1}" \
			ENGINE_PIDFILE="$(ENGINE_PIDFILE)" \
			ENGINE_LOGFILE="$(ENGINE_LOGFILE)" \
			SUPERVISOR_LOGFILE="$(SUPERVISOR_LOGFILE)" \
			SUPERVISOR_PIDFILE="$(SUPERVISOR_PIDFILE)" \
			CRASH_DIR="$(CRASH_DIR)" \
			"$(SUPERVISOR_SCRIPT)" > /tmp/irc-fiber-engine.supervisor.out 2>&1 & \
		SUP_PID=$$!; echo $$SUP_PID > "$(SUPERVISOR_PIDFILE)"; \
		printf "%b\n" "$(C)$(AR) engine supervisor pid=$$SUP_PID (auto-restarts on crash)$(R)"; \
		sleep 3; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Gateway → TAILNET  $(R)"; \
		printf "%b\n" "$(Y)$(WR) ctrl-c to stop everything  •  tail logs:  make logs  in another terminal$(R)"; \
		cleanup() { \
			printf "\n%b\n" "$(Y)$(WR) stopping...$(R)"; \
			kill -TERM "$$SUP_PID" 2>/dev/null || true; \
			killall -9 irc-fiber irc-fiber-engine 2>/dev/null || true; \
			rm -f "$(GATEWAY_PIDFILE)" "$(SUPERVISOR_PIDFILE)" "$(ENGINE_PIDFILE)"; \
			printf "%b\n" "$(BG)$(OK) debug-live stopped$(R)"; \
			exit 0; \
		}; \
		trap cleanup INT TERM EXIT; \
		IRCFIBER_MONGO_URL="$(TAILNET_MONGO_URL)" IRCFIBER_REDIS_URL="$(TAILNET_REDIS_URL)" \
			"$(GATEWAY_BIN)" >> "$(GATEWAY_LOGFILE)" 2>&1; \
		GW_EXIT=$$?; \
		printf "\n%b\n" "$(Y)$(WR) gateway exited (code $$GW_EXIT)$(R)"; \
		cleanup; \
		exit $$GW_EXIT'

# Stop everything (supervisor + gateway). Does NOT kill a Vite dev server.
stop: ## Component > Stop engine (supervised) + gateway
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Stopping everything  $(R)"; \
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
	killall -9 irc-fiber 2>/dev/null || true; \
	killall -9 irc-fiber-engine 2>/dev/null || true; \
	pkill -f irc-fiber-engine-supervisor 2>/dev/null || true; \
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

# Engine: kill the current engine — supervisor respawns with the latest binary.
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
gateway-rebuild: build ## Component > Rebuild gateway binary (no restart)

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
		killall -9 irc-fiber 2>/dev/null || true; \
		sleep 1; \
		rm -f $(GATEWAY_PIDFILE); \
		: > $(GATEWAY_LOGFILE); \
		IRCFIBER_MONGO_URL=$${IRCFIBER_MONGO_URL:-$(LOCAL_MONGO_URL)} \
		IRCFIBER_REDIS_URL=$${IRCFIBER_REDIS_URL:-$(LOCAL_REDIS_URL)} \
			nohup "$(GATEWAY_BIN)" > $(GATEWAY_LOGFILE) 2>&1 & \
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
		printf "\n%b\n" "$(C)  ─ supervisor tail $(R)"; \
		tail -3 $(SUPERVISOR_LOGFILE) 2>/dev/null | sed "s/^/    /" || printf "    (no log)\n"; \
		printf "%b\n" "$(C)  > crash dumps $(R)"; \
		d="$(CRASH_DIR)"; \
		mkdir -p "$$d"; \
		count=$$(ls "$$d"crash-*.txt 2>/dev/null | wc -l | tr -d " "); \
		if [ "$$count" -gt 0 ]; then \
			printf "    %s crash dump(s) - view with: make crash-logs\n" "$$count"; \
			printf "    Most recent: %s\n" "$$(ls -t "$$d"crash-*.txt 2>/dev/null | head -1)"; \
		else \
			printf "    (no crash dumps)\n"; \
		fi; \
	'

# Logs: tail all three log streams in parallel (engine / gateway / supervisor).
logs: ## Component > Tail engine + gateway + supervisor logs in parallel
	@bash -c ' \
		touch $(ENGINE_LOGFILE) $(GATEWAY_LOGFILE) $(SUPERVISOR_LOGFILE); \
		trap "kill 0" INT TERM EXIT; \
		tail -F $(GATEWAY_LOGFILE) | sed -u "s/^/$(K)[gw]$(R) /" & \
		tail -F $(ENGINE_LOGFILE) | sed -u "s/^/$(Y)[en]$(R) /" & \
		tail -F $(SUPERVISOR_LOGFILE) | sed -u "s/^/$(C)[sv]$(R) /" & \
		wait; \
	'

logs-engine: ## Component > Tail engine log only
	@touch $(ENGINE_LOGFILE); tail -F $(ENGINE_LOGFILE)

logs-gateway: ## Component > Tail gateway log only
	@touch $(GATEWAY_LOGFILE); tail -F $(GATEWAY_LOGFILE)

logs-supervisor: ## Component > Tail supervisor log (crashes + restarts)
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
watch-engine: ## Component > Watch source/*.d — rebuild engine + supervisor respawns on save
	@bash -c ' \
		printf "\n%b\n" "$(_BC)$(K)$(B)  Watching engine sources  $(R)"; \
		printf "%b\n" "$(D)Polls every 2s. Install fswatch for instant: brew install fswatch$(R)"; \
		printf "%b\n" "$(D)Triggers: make engine-rebuild + make engine-restart$(R)"; \
		if [ ! -f $(SUPERVISOR_PIDFILE) ]; then \
			printf "%b\n" "$(Y)$(WR) No supervisor running. Start one first: make debug  or  make debug-live$(R)"; \
			exit 1; \
		fi; \
		WATCH=$$(find source -name "*.d" -type f 2>/dev/null); \
		LAST=$$(echo "$$WATCH" | xargs stat -f %m 2>/dev/null | sort -n | tail -1); \
		printf "%b\n" "$(C)  watching source/*.d …$(R)"; \
		while true; do \
			sleep 2; \
			CURR=$$(echo "$$WATCH" | xargs stat -f %m 2>/dev/null | sort -n | tail -1); \
			if [ "$$CURR" != "$$LAST" ]; then \
				printf "\n%b\n" "$(Y)→ change detected, rebuilding engine…$(R)"; \
				$(MAKE) --no-print-directory engine-rebuild && \
					$(MAKE) --no-print-directory engine-restart; \
				LAST=$$CURR; \
			fi; \
		done; \
	'

# Watch gateway sources, rebuild + restart on change.
watch-gateway: ## Component > Watch source/*.d — rebuild gateway + relaunch on save
	@bash -c ' \
		printf "\n%b\n" "$(_BC)$(K)$(B)  Watching gateway sources  $(R)"; \
		printf "%b\n" "$(D)Polls every 2s. Install fswatch for instant: brew install fswatch$(R)"; \
		WATCH=$$(find source -name "*.d" -type f 2>/dev/null); \
		LAST=$$(echo "$$WATCH" | xargs stat -f %m 2>/dev/null | sort -n | tail -1); \
		printf "%b\n" "$(C)  watching source/*.d …$(R)"; \
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
up: debug
down: stop
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
else
    OPENSSL_LIB := $(shell pkg-config --variable=libdir openssl 2>/dev/null || echo /usr/lib)
endif

build: frontend ## Build > Build the application with dub
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber  $(R)"
	@bash -o pipefail -c '$(DUB) build 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@if [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) | awk '{print $$5}'); \
		printf '\n%b\n' "$(BG)$(OK) Build successful$(R) $(D)($$SIZE)$(R)"; \
	else \
		printf '\n%b\n' "$(BG)$(OK) Dub build complete$(R)"; \
	fi

frontend: ## Build > Build Svelte 5 frontend bundle
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building Svelte frontend  $(R)"
	@cd frontend && npm run build > /tmp/irc-fiber-frontend-build.log 2>&1; \
		if [ $$? -eq 0 ]; then \
			grep '✓ built in\|inject-manifest' /tmp/irc-fiber-frontend-build.log 2>/dev/null || true; \
		else \
			cat /tmp/irc-fiber-frontend-build.log; \
			exit 1; \
		fi
	@node frontend/inject-manifest.js
	@printf '\n%b\n' "$(BG)$(OK) Frontend build complete$(R)"

frontend-dev: ## Build > Run Svelte frontend dev server
	@cd frontend && npm run dev

frontend-install: ## Build > Install Svelte frontend dependencies
	@cd frontend && npm install

build-engine: ## Build > Build the IRC engine binary
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber Engine  $(R)"
	@bash -o pipefail -c '$(DUB) build --config=engine 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@printf '\n%b\n' "$(BG)$(OK) Engine build successful$(R)"

build-engine-zig-alpine: ## Build > Cross-compile Zig engine for Alpine (musl)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building Zig Engine (Alpine target)  $(R)"
	@mkdir -p engine/zig-out/bin
	@zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe --cache-dir engine/.zig-cache
	@cp zig-out/bin/ircfiber-engine engine/zig-out/bin/ircfiber-engine
	@printf '%b\n' "$(BG)$(OK) Zig engine built for Alpine$(R) $(D)($(shell ls -lh engine/zig-out/bin/ircfiber-engine | awk '{print $$5}'))$(R)"

build-engine-native: ## Build > Build Zig engine for local testing (macOS)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building Zig Engine (native)  $(R)"
	@mkdir -p engine/zig-out/bin
	@cd engine && zig build-exe src/core.zig src/redis_registration.c -O Debug -femit-bin=ircfiber-engine -lc
	@printf '%b\n' "$(BG)$(OK) Zig engine built (native)$(R)"

engine-test-local: build-engine-native ## Test > Run Zig engine against local Redis + IRC
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Testing Zig Engine locally  $(R)"
	@printf '%b\n' "$(D)  Ensure redis-server is running locally (brew services start redis)$(R)"
	@cd engine && timeout 5 ./ircfiber-engine 2>&1 || true
	@redis-cli SMEMBERS irc:servers 2>&1
	@redis-cli HGET irc:server:ovh isHealthy 2>&1
	@redis-cli HGET irc:server:ovh lastHeartbeat 2>&1
	@redis-cli DEL irc:server:ovh 2>&1
	@redis-cli SREM irc:servers ovh 2>&1
	@printf '%b\n' "$(BG)$(OK) Local test complete$(R)"

build-engine-zig: ## Build > Build Zig engine for all targets
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber Engine (Zig)  $(R)"
	@cd engine && zig build -Doptimize=ReleaseSafe
	@cd engine && zig build-exe src/core.zig -target x86_64-linux-musl -O ReleaseSafe -femit-bin=zig-out/bin/ircfiber-engine-alpine -lc
	@cd engine && zig build-exe src/core.zig -target x86_64-linux-gnu -O ReleaseSafe -femit-bin=zig-out/bin/ircfiber-engine-linux -lc
	@printf '\n%b\n' "$(D)  Targets: macOS (native) + Linux (glibc) + Linux (musl/Alpine)$(R)"
	@printf '\n%b\n' "$(BG)$(OK) Zig engine build successful$(R)"

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
	@$(DUB) test 2>&1 | tail -20

test-frontend: ## Test > Svelte/Vitest frontend tests (both projects)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running frontend tests  $(R)"
	@cd frontend && npm run test 2>&1 | tail -20

test-lib: ## Test > Frontend lib tests only (Node, fastest — pure utilities)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running frontend lib tests  $(R)"
	@cd frontend && npm run test:lib 2>&1 | tail -15

test-client: ## Test > Frontend client tests only (headless Chromium — components/stores)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running frontend client tests  $(R)"
	@cd frontend && npm run test:client 2>&1 | tail -15

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
	@find source -name "*.d" -exec dfmt -i {} \; 2>/dev/null || \
		printf '%b\n' "$(Y)$(WR) dfmt not found. Install: dub fetch dfmt$(R)"
	@printf '%b\n' "$(BG)$(OK) D sources formatted$(R)"

fmt-check: ## Quality > Verify all D sources are formatted (CI gate, no writes)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Checking D source formatting  $(R)"
	@UNFORMATTED=$$(find source -name "*.d" -exec dfmt -c {} \; 2>&1 | grep -v "^$" || true); \
	if [ -n "$$UNFORMATTED" ]; then \
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
	@printf '\n%b\n' "$(D)→ Pruning stale Docker layers before start...$(R)"
	@docker system prune -af --volumes=false 2>&1 | tail -2
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Docker Services  $(R)"
	@docker compose up -d
	@printf '%b\n' "$(BG)$(OK) Services started$(R) $(D)(http://localhost:8090)$(R)"

docker-down: ensure-colima ## Docker > Stop all Docker services
	@printf '%b\n' "$(D)→ Stopping Docker services (docker-compose.yml)...$(R)"
	@docker compose down
	@printf '%b\n' "$(BG)$(OK) Services stopped$(R)"

docker-down-test: ensure-colima ## Docker > Stop test services (ircd + mongo + redis)
	@printf '%b\n' "$(D)→ Stopping Docker test services (docker-compose.test.yml)...$(R)"
	@docker compose -f docker-compose.test.yml down
	@printf '%b\n' "$(BG)$(OK) Test services stopped$(R)"

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
	@docker compose up -d irc_fiber
	@printf '%b\n' "$(BG)$(OK) Web server started$(R) $(D)(http://localhost:8090)$(R)"

docker-down-web: ensure-colima ## Docker > Stop web server only
	@printf '%b\n' "$(D)→ Stopping web server...$(R)"
	@docker compose stop irc_fiber
	@printf '%b\n' "$(BG)$(OK) Web server stopped$(R)"

docker-restart-web: ensure-colima ## Docker > Restart web server only
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Restarting Web Server (Gateway)  $(R)"
	@docker compose build irc_fiber
	@docker compose up -d --force-recreate irc_fiber
	@printf '%b\n' "$(BG)$(OK) Web server restarted$(R) $(D)(http://localhost:8090)$(R)"

docker-up-backend: ensure-colima ## Docker > Start backend services only
	@printf '\n%b\n' "$(D)→ Pruning stale Docker layers...$(R)"
	@docker system prune -af --volumes=false 2>&1 | tail -2
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Backend Services  $(R)"
	@docker compose up -d irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services started$(R)"

docker-down-backend: ensure-colima ## Docker > Stop backend services only
	@printf '%b\n' "$(D)→ Stopping backend services...$(R)"
	@docker compose stop irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services stopped$(R)"

docker-restart-backend: ensure-colima ## Docker > Restart backend services only
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Restarting Backend Services  $(R)"
	@docker compose up -d --build --force-recreate irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services restarted$(R)"

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
SHELL_SVC ?= irc_fiber

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
# Vault: by default prompts for the vault password. Set VAULT_PASS_FILE
# to a path containing the vault password to skip the prompt:
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

# Vault pass: use file if set, otherwise ask on every invocation.
_vault_arg = $(if $(VAULT_PASS_FILE),--vault-password-file $(VAULT_PASS_FILE),--ask-vault-pass)
_target      = $(or $(TARGET),ircfiber-ovh-1)
_target_ssh   = $(or $(TARGET_SSH),40.160.227.49)
_playbook    = cd deploy && ansible-playbook -l $(_target) $(_vault_arg)

update: build-engine ## Deploy > Build D engine, deploy to all hosts
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploy → $(_target)  $(R)"
	@$(_playbook) playbooks/deploy-update.yml

# Deploy engine only to the backup server.
# Usage: make update-backup VAULT_PASS_FILE=.vault_pass.txt
update-backup: build-engine ## Deploy > Deploy engine to backup server (ircfiber-backup-1)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploy engine → ircfiber-backup-1  $(R)"
	@cd deploy && ansible-playbook -l ircfiber-backup-1 $(if $(VAULT_PASS_FILE),--vault-password-file ../$(VAULT_PASS_FILE),--vault-password-file .vault_pass.txt) playbooks/deploy-update.yml

# Alias: fast path is the default
update-fast: update ## Deploy > Force hot path (same as `make update`)

# Full docker image rebuild: builds Containerfile from scratch on the target
# (or via registry), recreates gateway + engine containers.
update-full: ## Deploy > Full docker image rebuild + container recreate
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Full image rebuild → $(_target)  $(R)"
	@$(_playbook) playbooks/deploy.yml

deploy: update-full ## Deploy > Alias for update-full

# Build frontend + push public/ to running gateway via SSH.
# The gateway reads these files from disk at request time, so no binary
# change, no container restart, no reconnect. ~2-3s after build.
update-assets: frontend ## Deploy > Build frontend + push public/* to running gateway (no restart)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Asset push → $(_target_ssh) ($(_target))  $(R)"
	@printf '%b\n' "$(D)  Tarring public/ → ssh → docker exec tar -xf -$(R)"
	@tar cz -C public . | ssh deploy@$(_target_ssh) 'docker exec -i ircfiber-gateway tar xzf - -C /app/public'

# Show running container images and versions on the target.
update-status: ## Deploy > Show running containers & image versions
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Deploy status → $(_target)  $(R)"
	@$(_playbook) playbooks/status.yml

# Nuke BuildKit cache + builder image on the target.
# Forces cold rebuild: full dub download + compile next update.
update-clean: ## Deploy > Nuke BuildKit cache + builder image on target
	@printf '\n%b\n' "$(_BY)$(K)$(B)  Cleaning builder cache → $(_target_ssh) ($(_target))  $(R)"
	@ssh deploy@$(_target_ssh) 'docker rmi ircfiber-builder:latest 2>/dev/null; docker builder prune --force 2>/dev/null; echo "Builder cache cleared"'

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
	@rm -f $(APP) *.o
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
	@printf '    \033[92mmake update\033[0m          (fast incremental binary deploy)\n'
	@printf '    \033[92mmake update-full\033[0m      (full docker image rebuild)\n'
	@printf '    \033[92mmake update-assets\033[0m     (asset-only: public/*, ~2-3s)\n'
	@printf '    \033[92mmake update-status\033[0m     (show running containers)\n'
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
