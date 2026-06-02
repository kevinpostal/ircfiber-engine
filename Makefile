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
.PHONY: all help build build-engine build-release build-debug build-ldc2
.PHONY: start run run-engine up down restart-web logs-web logs-engine watch-web
.PHONY: test clean fmt deps-check
.PHONY: dscanner-install dscanner-all dscanner-syntax dscanner-lint dscanner-unused \
        dscanner-complexity dscanner-imports dscanner-fix dscanner-size dscanner-outline
.PHONY: ensure-colima docker-up docker-down docker-logs docker-build \
        docker-up-web docker-down-web docker-restart-web \
        docker-up-backend docker-down-backend docker-restart-backend docker-restart \
        docker-down-test ircd-up ircd-down
.PHONY: podman-up podman-down podman-logs \
        podman-up-web podman-down-web podman-restart-web \
        podman-up-backend podman-down-backend podman-restart-backend podman-restart
.PHONY: cross-linux-x64 cross-linux-arm64 cross-linux-armv7

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

build: ## Build > Build the application with dub
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Building IRC Fiber  $(R)"
	@bash -o pipefail -c '$(DUB) build 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@if [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) | awk '{print $$5}'); \
		printf '\n%b\n' "$(BG)$(OK) Build successful$(R) $(D)($$SIZE)$(R)"; \
	else \
		printf '\n%b\n' "$(BG)$(OK) Dub build complete$(R)"; \
	fi

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

start: run ## Quick Start > Alias for make run

run: build build-engine ## Quick Start > Build and run gateway in foreground
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
		LAST=$$(find source views public -type f -print0 2>/dev/null | xargs -0 stat -f %m 2>/dev/null | sort -n | tail -1); \
		printf "%b\n" "$(C)→ Watching source/, views/, public/ for changes...$(R)"; \
		while true; do \
			sleep 2; \
			CURR=$$(find source views public -type f -print0 2>/dev/null | xargs -0 stat -f %m 2>/dev/null | sort -n | tail -1); \
			if [ "$$CURR" != "$$LAST" ]; then \
				printf "\n%b\n" "$(Y)→ Change detected, restarting gateway...$(R)"; \
				$(MAKE) --no-print-directory restart-web; \
				LAST=$$CURR; \
			fi; \
		done; \
	'

test: ## Build > Run unit tests
	@printf '\n%b\n' "$(_BCn)$(K)$(B)  Running Tests  $(R)"
	@$(DUB) test 2>&1 | tail -20

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
# Docker / Podman Compose
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
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Backend Services  $(R)"
	@docker compose up -d irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services started$(R)"

docker-down-backend: ensure-colima ## Docker > Stop backend services only
	@printf '%b\n' "$(D)→ Stopping backend services...$(R)"
	@docker compose stop irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services stopped$(R)"

docker-restart-backend: ensure-colima ## Docker > Restart backend services only
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Restarting Backend Services  $(R)"
	@docker compose up -d --build --force-recreate irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services restarted$(R)"

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

podman-up: ## Podman > Start all services with Podman Compose
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Podman Services  $(R)"
	@podman compose up -d
	@printf '%b\n' "$(BG)$(OK) Services started$(R) $(D)(http://localhost:8090)$(R)"

podman-down: ## Podman > Stop all Podman services
	@printf '%b\n' "$(D)→ Stopping Podman services...$(R)"
	@podman compose down
	@printf '%b\n' "$(BG)$(OK) Services stopped$(R)"

podman-up-web: ## Podman > Start web server only (Podman)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Web Server (Podman)  $(R)"
	@podman compose up -d irc_fiber
	@printf '%b\n' "$(BG)$(OK) Web server started$(R) $(D)(http://localhost:8090)$(R)"

podman-down-web: ## Podman > Stop web server only (Podman)
	@printf '%b\n' "$(D)→ Stopping web server (Podman)...$(R)"
	@podman compose stop irc_fiber
	@printf '%b\n' "$(BG)$(OK) Web server stopped$(R)"

podman-restart-web: ## Podman > Restart web server only (Podman)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Restarting Web Server (Podman)  $(R)"
	@podman compose up -d --build --force-recreate irc_fiber
	@printf '%b\n' "$(BG)$(OK) Web server restarted$(R) $(D)(http://localhost:8090)$(R)"

podman-up-backend: ## Podman > Start backend services only (Podman)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Starting Backend Services (Podman)  $(R)"
	@podman compose up -d irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services started$(R)"

podman-down-backend: ## Podman > Stop backend services only (Podman)
	@printf '%b\n' "$(D)→ Stopping backend services (Podman)...$(R)"
	@podman compose stop irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services stopped$(R)"

podman-restart-backend: ## Podman > Restart backend services only (Podman)
	@printf '\n%b\n' "$(_BC)$(K)$(B)  Restarting Backend Services (Podman)  $(R)"
	@podman compose up -d --build --force-recreate irc_engine redis mongo ircd
	@printf '%b\n' "$(BG)$(OK) Backend services restarted$(R)"

podman-restart: podman-restart-web podman-restart-backend ## Podman > Restart all Podman services
	@printf '%b\n' "$(BG)$(OK) All Podman services restarted$(R)"

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

fmt: ## Utils > Format D source files with dfmt
	@printf '%b\n' "$(D)→ Formatting D source files...$(R)"
	@find source -name "*.d" -exec dfmt -i {} \; 2>/dev/null || \
		printf '%b\n' "$(Y)$(WR) dfmt not found. Install: dub fetch dfmt$(R)"

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
				else if (c == "Podman")      col = "\033[43m\033[30m\033[1m"; \
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
