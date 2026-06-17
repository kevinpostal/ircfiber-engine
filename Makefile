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
# gateway (https://ircfiber-prod-1.tail544547.ts.net). Override per-call:
#
#   make run                      # tailnet (default)
#   make run-tailnet              # explicit tailnet
#   make run-local                # local docker-compose (http://127.0.0.1:8090)
#   make run BACKEND=local        # same as run-local, no separate target
#   make run BACKEND=https://x     # custom backend URL
#
# For the D backend runner (the previous `make run`), use `make run-gateway`.
BACKEND ?= local
VITE_BACKEND_URL ?= https://ircfiber-prod-1.tail544547.ts.net

ifeq ($(BACKEND),tailnet)
  EFFECTIVE_BACKEND_URL := https://ircfiber-prod-1.tail544547.ts.net
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
.PHONY: all help build build-engine build-release build-debug build-ldc2 frontend frontend-dev frontend-install
.PHONY: start run run-tailnet run-local run-gateway run-engine up down restart-web logs-web logs-engine watch-web
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
.PHONY: deploy update

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
	@cd frontend && npm run build 2>&1 | grep -E 'built|error|Error' | tail -8
	@printf '\n%b\n' "$(BG)$(OK) Frontend build complete$(R)"

frontend-dev: ## Build > Run Svelte frontend dev server
	@cd frontend && npm run dev

frontend-install: ## Build > Install Svelte frontend dependencies
	@cd frontend && npm install

build-engine: ## Build > Build the IRC engine binary
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber Engine  $(R)"
	@bash -o pipefail -c '$(DUB) build --config=engine 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@printf '\n%b\n' "$(BG)$(OK) Engine build successful$(R)"

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

# Bash snippet: kill old processes, clear redis, check/start backend services
define _docker_setup
killall -9 irc-fiber-engine 2>/dev/null || true; \
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
# Run & Test
# ----------------------------------------------------------------------------
#
# `make run` is the primary entry point for the dev loop. It starts the
# Svelte dev server pointed at the backend selected by the BACKEND
# variable (default: tailnet). The D backend runner is at `make run-gateway`
# (renamed from the old `make run`).
#
#   make run               # frontend dev, tailnet backend (default)
#   make run-tailnet       # explicit
#   make run-local         # frontend dev, local docker backend
#   make run-gateway       # D gateway, local backend (was `make run`)
#   make run-engine        # D engine only, local backend

start: run ## Quick Start > Alias for `make run` (frontend dev server)

run: frontend-install ## Quick Start > Start frontend dev server (default: tailnet)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting frontend dev server  $(R)"
	@printf '%b\n' "$(D)Backend: $(BACKEND)  →  $(EFFECTIVE_BACKEND_URL)$(R)"
	@printf '%b\n' "$(D)Open http://localhost:5173 when ready$(R)"
	@printf '%b\n' "$(D)Switch:  make run-local   |   make run-tailnet   |   make run BACKEND=<url>$(R)"
	@cd frontend && VITE_BACKEND_URL=$(EFFECTIVE_BACKEND_URL) npm run dev

run-tailnet: build ## Quick Start > Build + run D gateway with tailnet Mongo+Redis
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting IRC Fiber Gateway (tailnet DBs)  $(R)"
	@printf '%b\n' "$(C)$(AR) The built frontend is served at http://localhost:8090$(R)"
	@printf '%b\n' "$(D)Open that URL in your browser — no separate Vite server needed.$(R)"
	@printf '%b\n' "$(D)Vite dev server (HMR for frontend work): make run-local$(R)"
	@printf '%b\n' "$(D)Engine: already running on the tailnet.$(R)"
	@bash -c ' \
		IRCFIBER_MONGO_URL="mongodb://ircfiber:MongoAppPass2026@100.107.178.48:27017/ircfiber" \
		IRCFIBER_REDIS_URL="redis://100.107.178.48:6379/0" \
		./irc-fiber; \
	'

run-local: ## Quick Start > Frontend dev server, local docker backend
	@$(MAKE) --no-print-directory run BACKEND=local

run-gateway: build build-engine ## Quick Start > Build + run D gateway locally (was `make run`)
	@bash -c ' \
		printf "\n%b\n" "$(_BC)$(K)$(B)  Cleaning up existing processes  $(R)"; \
		$(_docker_setup); \
		printf "%b\n" "$(BG)$(OK) Cleanup complete$(R)"; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Starting IRC Fiber Engine  $(R)"; \
		env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 IRCFIBER_SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine} IRCFIBER_BIND_ADDRESS=$${IRCFIBER_BIND_ADDRESS:-127.0.0.1} nohup ./irc-fiber-engine > /tmp/irc-fiber-engine.log 2>&1 & \
		ENGINE_PID=$$!; \
		printf "%b\n" "$(C)$(AR) Engine PID: $$ENGINE_PID$(R)"; \
		sleep 3; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Starting IRC Fiber Gateway  $(R)"; \
		printf "%b\n" "$(C)$(AR) http://localhost:8090$(R)"; \
		trap "printf \"\\n%b\\n\" \"$(D)→ Stopping engine (PID $$ENGINE_PID)...$(R)\"; kill $$ENGINE_PID 2>/dev/null; exit" INT TERM EXIT; \
		env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 ./irc-fiber; \
	'

run-engine: build ## Quick Start > Run the IRC engine (needs backends running)
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Starting IRC Fiber Engine  $(R)"
	@env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 IRCFIBER_SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine} IRCFIBER_BIND_ADDRESS=$${IRCFIBER_BIND_ADDRESS:-127.0.0.1} ./irc-fiber-engine

# ----------------------------------------------------------------------------
# Background Run & Live Reload
# ----------------------------------------------------------------------------

up: build build-engine ## Quick Start > Start engine + gateway in background
	@bash -c ' \
		printf "\n%b\n" "$(_BC)$(K)$(B)  Starting IRC Fiber (Background)  $(R)"; \
		$(_docker_setup); \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Starting IRC Fiber Engine  $(R)"; \
		env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 IRCFIBER_SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine} IRCFIBER_BIND_ADDRESS=$${IRCFIBER_BIND_ADDRESS:-127.0.0.1} nohup ./irc-fiber-engine > /tmp/irc-fiber-engine.log 2>&1 & \
		ENGINE_PID=$$!; \
		echo $$ENGINE_PID > /tmp/irc-fiber-engine.pid; \
		printf "%b\n" "$(C)$(AR) Engine PID: $$ENGINE_PID$(R)"; \
		sleep 3; \
		printf "\n%b\n" "$(_BCn)$(K)$(B)  Starting IRC Fiber Gateway  $(R)"; \
		printf "%b\n" "$(C)$(AR) http://localhost:8090$(R)"; \
		env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 nohup ./irc-fiber > /tmp/irc-fiber.log 2>&1 & \
		GATEWAY_PID=$$!; \
		echo $$GATEWAY_PID > /tmp/irc-fiber.pid; \
		printf "%b\n" "$(C)$(AR) Gateway PID: $$GATEWAY_PID$(R)"; \
		printf "\n%b\n" "$(BG)$(OK) IRC Fiber running in background$(R)"; \
		printf "%b\n" "$(D)Logs:  make logs-web  |  make logs-engine$(R)"; \
		printf "%b\n" "$(D)Stop:  make down$(R)"; \
		printf "%b\n" "$(D)Watch: make watch-web$(R)"; \
	'

down: ## Quick Start > Stop background engine + gateway
	@printf '%b\n' "$(D)→ Stopping IRC Fiber...$(R)"
	@if [ -f /tmp/irc-fiber.pid ]; then \
		kill $$(cat /tmp/irc-fiber.pid) 2>/dev/null || true; \
		rm -f /tmp/irc-fiber.pid; \
	fi
	@if [ -f /tmp/irc-fiber-engine.pid ]; then \
		kill $$(cat /tmp/irc-fiber-engine.pid) 2>/dev/null || true; \
		rm -f /tmp/irc-fiber-engine.pid; \
	fi
	@killall -9 irc-fiber 2>/dev/null || true
	@killall -9 irc-fiber-engine 2>/dev/null || true
	@printf '%b\n' "$(BG)$(OK) Stopped$(R)"

restart-web: build ## Quick Start > Rebuild and restart just the gateway
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Restarting Gateway  $(R)"
	@if [ -f /tmp/irc-fiber.pid ]; then \
		kill $$(cat /tmp/irc-fiber.pid) 2>/dev/null || true; \
		rm -f /tmp/irc-fiber.pid; \
	fi
	@killall -9 irc-fiber 2>/dev/null || true
	@sleep 1
	@env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 nohup ./irc-fiber > /tmp/irc-fiber.log 2>&1 & \
		GATEWAY_PID=$$!; \
		echo $$GATEWAY_PID > /tmp/irc-fiber.pid; \
		printf '%b\n' "$(C)$(AR) Gateway PID: $$GATEWAY_PID$(R)"
	@printf '%b\n' "$(BG)$(OK) Gateway restarted$(R) $(D)(http://localhost:8090)$(R)"

logs-web: ## Quick Start > Tail gateway logs
	@if [ -f /tmp/irc-fiber.log ]; then \
		tail -f /tmp/irc-fiber.log; \
	else \
		printf '%b\n' "$(Y)$(WR) No gateway log found. Run: make up$(R)"; \
	fi

logs-engine: ## Quick Start > Tail engine logs
	@if [ -f /tmp/irc-fiber-engine.log ]; then \
		tail -f /tmp/irc-fiber-engine.log; \
	else \
		printf '%b\n' "$(Y)$(WR) No engine log found. Run: make up$(R)"; \
	fi

watch-web: ## Quick Start > Auto-rebuild gateway on file changes
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Watching for file changes  $(R)"
	@printf '%b\n' "$(D)Polls every 2s. Install fswatch for instant updates: brew install fswatch$(R)"
	@bash -c ' \
		LAST=$$(find source views public frontend/src -type f -print0 2>/dev/null | xargs -0 stat -f %m 2>/dev/null | sort -n | tail -1); \
		printf "%b\n" "$(C)→ Watching source/, views/, public/, frontend/src/ for changes...$(R)"; \
		while true; do \
			sleep 2; \
			CURR=$$(find source views public frontend/src -type f -print0 2>/dev/null | xargs -0 stat -f %m 2>/dev/null | sort -n | tail -1); \
			if [ "$$CURR" != "$$LAST" ]; then \
				printf "\n%b\n" "$(Y)→ Change detected, restarting gateway...$(R)"; \
				$(MAKE) --no-print-directory restart-web; \
				LAST=$$CURR; \
			fi; \
		done; \
	'

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

stop: docker-down
down: docker-down

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

update: frontend ## Deploy > Build on VPS Docker native (fastest), inject binary
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Building on VPS (native x86_64 Docker)  $(R)"
	@printf '%b\n' "$(D)  First build: 4-6 min (LDC install + full compile)$(R)"
	@printf '%b\n' "$(D)  Incremental: 10-30s (.dub/ cache mount preserves .o files)$(R)"
	@printf '%b\n' "$(D)  Note: QEMU cross-compile on Mac is 10x slower$(R)"
	@bash -c '\
		CTX="vps"; \
		SOCK="ssh://deploy@ircfiber-prod-1.tail544547.ts.net"; \
		docker context create $$CTX --docker "host=$$SOCK" 2>/dev/null || true; \
		printf "%b\n" "$(C)=== Building on VPS (native x86_64) ===$(R)"; \
		docker -c $$CTX build --target builder -t ircfiber-builder:latest -f Containerfile . 2>&1; \
		printf "%b\n" "$(C)=== Extracting binary from builder ===$(R)"; \
		TMP=$$(docker -c $$CTX run -d --entrypoint sh ircfiber-builder:latest); \
		docker -c $$CTX cp "$$TMP:/build/irc-fiber" /tmp/irc-fiber; \
		docker -c $$CTX cp "$$TMP:/build/irc-fiber-engine" /tmp/irc-fiber-engine 2>/dev/null || true; \
		docker -c $$CTX rm -f "$$TMP" >/dev/null 2>&1; \
		printf "%b\n" "$(C)=== Injecting + restarting ===$(R)"; \
		docker -c $$CTX cp /tmp/irc-fiber ircfiber-gateway:/app/irc-fiber && \
		docker -c $$CTX cp /tmp/irc-fiber-engine ircfiber-engine-localengine:/app/irc-fiber-engine 2>/dev/null; \
		docker -c $$CTX exec ircfiber-gateway chmod +x /app/irc-fiber; \
		rm -f /tmp/irc-fiber /tmp/irc-fiber-engine; \
		docker -c $$CTX restart ircfiber-gateway 2>/dev/null; \
		sleep 1; \
		docker -c $$CTX restart ircfiber-engine-localengine 2>/dev/null || true; \
		printf "%b\n" "$(BG)$(OK) Deploy complete$(R)"; \
	'

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

help:
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
			print ""; \
			print "\033[1mIRC Fiber - IRC Bouncer & Web Client\033[0m"; \
			print "\033[2m=====================================\033[0m"; \
			for (i = 1; i <= ncat; i++) { \
				c = order[i]; \
				col = ""; \
				if (c == "Quick Start") col = "\033[42m\033[30m\033[1m"; \
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
