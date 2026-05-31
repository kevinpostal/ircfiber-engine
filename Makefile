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

# D-Scanner detection
DSCANNER_BIN := $(shell which dscanner 2>/dev/null || echo "")
DSCANNER_DUB_BIN := $(shell ls -1 $(DUB_PKG)/dscanner/*/dscanner/bin/dscanner 2>/dev/null | tail -1)
ifeq ($(DSCANNER_BIN),)
    ifeq ($(DSCANNER_DUB_BIN),)
        DSCANNER := dub run dscanner --
    else
        DSCANNER := $(DSCANNER_DUB_BIN)
    endif
else
    DSCANNER := $(DSCANNER_BIN)
endif

# Source files
SRCS        := $(shell find source -name "*.d" 2>/dev/null)
DT_SRCS     := $(shell find views -name "*.dt" 2>/dev/null)

# Colors
RESET       := \033[0m
BOLD        := \033[1m
DIM         := \033[2m
GREEN       := \033[32m
YELLOW      := \033[33m
BLUE        := \033[34m
MAGENTA     := \033[35m
CYAN        := \033[36m
BRIGHT_GREEN:= \033[92m
BRIGHT_YELLOW:= \033[93m
BRIGHT_CYAN := \033[96m
BG_GREEN    := \033[42m
BG_YELLOW   := \033[43m
BG_MAGENTA  := \033[45m
BG_BLUE     := \033[44m
BG_CYAN     := \033[46m
BLACK       := \033[30m

ICON_OK     := ✓
ICON_WARN   := ⚠
ICON_BULLET := •
ICON_ARROW  := →
ICON_BOX    := □

# ----------------------------------------------------------------------------
# Phony Targets
# ----------------------------------------------------------------------------
.PHONY: all help build build-engine build-release build-debug build-ldc2 run test clean fmt stop down
.PHONY: dscanner dscanner-install dscanner-syntax dscanner-lint dscanner-unused
.PHONY: dscanner-complexity dscanner-imports dscanner-fix dscanner-size dscanner-outline dscanner-all
.PHONY: deps-check ensure-colima docker-up docker-down docker-logs docker-build docker-restart-gateway \
         docker-up-web docker-down-web docker-restart-web \
         docker-up-backend docker-down-backend docker-restart-backend docker-restart \
         docker-up-test docker-down-test docker-restart-test \
         ircd-up ircd-down \
         podman-up podman-down podman-logs \
         podman-up-web podman-down-web podman-restart-web \
         podman-up-backend podman-down-backend podman-restart-backend podman-restart \
         cross-linux-x64 cross-linux-arm64 cross-linux-armv7

# ----------------------------------------------------------------------------
# Main Build Targets
# ----------------------------------------------------------------------------

all: build

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    OPENSSL_LIB := $(shell brew --prefix openssl 2>/dev/null || echo /usr/local)/lib
else
    OPENSSL_LIB := $(shell pkg-config --variable=libdir openssl 2>/dev/null || echo /usr/lib)
endif

build:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber  $(RESET)"
	@bash -o pipefail -c '$(DUB) build 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@if [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) | awk '{print $$5}'); \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Build successful$(RESET) $(DIM)($$SIZE)$(RESET)"; \
	else \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Dub build complete$(RESET)"; \
	fi

build-engine:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber Engine  $(RESET)"
	@bash -o pipefail -c '$(DUB) build --config=engine 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Engine build successful$(RESET)"

build-release:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber (Release)  $(RESET)"
	@bash -o pipefail -c '$(DUB) build --build=release 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8'
	@SIZE=$$(ls -lh $(APP) 2>/dev/null | awk '{print $$5}'); \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Release build successful$(RESET) $(DIM)($$SIZE)$(RESET)"

build-debug:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber (Debug)  $(RESET)"
	@bash -o pipefail -c '$(DUB) build --build=debug 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | grep -v "during/source/during/package.d" | grep -v "Deprecation: accessing" | tail -8'
	@printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Debug build successful$(RESET)"

# Build with direct ldc2 (no dub dependency resolution overhead)
build-ldc2:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber (LDC2 Direct)  $(RESET)"
	@bash -o pipefail -c '$(LDC) $(SRCS) -of=$(APP) -Isource -Jviews \
		$$(find $(DUB_PKG)/vibe-d/0.10.*/vibe-d/source \
		      $(DUB_PKG)/vibe-core/2.*/vibe-core/source \
		      $(DUB_PKG)/vibe-http/1.*/vibe-http/source \
		      $(DUB_PKG)/vibe-inet/1.*/vibe-inet/source \
		      $(DUB_PKG)/vibe-serialization/1.*/vibe-serialization/source \
		      $(DUB_PKG)/vibe-stream/1.*/vibe-stream/source \
		      $(DUB_PKG)/vibe-container/1.*/vibe-container/source \
		      $(DUB_PKG)/diet-ng/1.*/diet-ng/source \
		      $(DUB_PKG)/taggedalgebraic/1.*/taggedalgebraic/source \
		      $(DUB_PKG)/stdx-allocator/2.*/stdx-allocator/source \
		      $(DUB_PKG)/eventcore/0.9.*/eventcore/source \
		      -name "*.d" | xargs -I{} echo -I{}) \
		-d-version=VibeUseFibers \
		-L=-L$(OPENSSL_LIB) -L=-lssl -L=-lcrypto \
		2>&1 | grep -v "deployment version" | tail -12'
	@if [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) 2>/dev/null | awk '{print $$5}'); \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) LDC2 build successful$(RESET) $(DIM)($$SIZE)$(RESET)"; \
	else \
		printf '\n%b\n' "$(YELLOW)$(ICON_WARN) LDC2 build failed$(RESET)"; \
		exit 1; \
	fi

# ----------------------------------------------------------------------------
# Run & Test
# ----------------------------------------------------------------------------

run: build build-engine
	@bash -c ' \
		printf "\n%b\n" "$(BG_GREEN)$(BLACK)$(BOLD)  Cleaning up existing processes  $(RESET)"; \
		killall -9 irc-fiber-engine 2>/dev/null || true; \
		killall -9 irc-fiber 2>/dev/null || true; \
		sleep 1; \
		SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine}; \
		if docker info >/dev/null 2>&1; then \
			docker compose exec -T redis redis-cli del irc:server:$$SERVER_ID irc:servers irc:network:assignments >/dev/null 2>&1 || true; \
		fi; \
		printf "%b\n" "$(BRIGHT_GREEN)$(ICON_OK) Cleanup complete$(RESET)"; \
		printf "\n%b\n" "$(BG_GREEN)$(BLACK)$(BOLD)  Checking Backend Services  $(RESET)"; \
		if ! docker info >/dev/null 2>&1; then \
			printf "%b\n" "$(YELLOW)$(ICON_WARN) Docker is not running$(RESET)"; \
			printf "%b\n" "$(DIM)Start Docker first, or run: make docker-up-backend$(RESET)"; \
			exit 1; \
		fi; \
		if ! docker compose ps mongo redis ircd 2>/dev/null | grep -q "healthy"; then \
			printf "%b\n" "$(YELLOW)$(ICON_WARN) Backend services not running. Starting them now...$(RESET)"; \
			docker compose up -d mongo redis ircd; \
			printf "%b\n" "$(CYAN)→ Waiting for services to be ready...$(RESET)"; \
			for i in 1 2 3 4 5 6 7 8 9 10; do \
				if docker compose ps mongo redis ircd 2>/dev/null | grep -q "healthy"; then \
					printf "%b\n" "$(BRIGHT_GREEN)$(ICON_OK) Backend services ready$(RESET)"; \
					break; \
				fi; \
				if [ $$i -eq 10 ]; then \
					printf "%b\n" "$(YELLOW)$(ICON_WARN) Services still starting, continuing anyway...$(RESET)"; \
				fi; \
				sleep 1; \
			done; \
		else \
			printf "%b\n" "$(BRIGHT_GREEN)$(ICON_OK) Backend services already running$(RESET)"; \
		fi; \
		printf "\n%b\n" "$(BG_CYAN)$(BLACK)$(BOLD)  Starting IRC Fiber Engine  $(RESET)"; \
		env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 IRCFIBER_SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine} IRCFIBER_BIND_ADDRESS=$${IRCFIBER_BIND_ADDRESS:-127.0.0.1} nohup ./irc-fiber-engine > /tmp/irc-fiber-engine.log 2>&1 & \
		ENGINE_PID=$$!; \
		printf "%b\n" "$(CYAN)$(ICON_ARROW) Engine PID: $$ENGINE_PID$(RESET)"; \
		sleep 3; \
		printf "\n%b\n" "$(BG_CYAN)$(BLACK)$(BOLD)  Starting IRC Fiber Gateway  $(RESET)"; \
		printf "%b\n" "$(CYAN)$(ICON_ARROW) http://localhost:8090$(RESET)"; \
		trap "printf \"\\n%b\\n\" \"$(DIM)→ Stopping engine (PID $$ENGINE_PID)...$(RESET)\"; kill $$ENGINE_PID 2>/dev/null; exit" INT TERM EXIT; \
		env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 ./irc-fiber; \
	'

run-engine: build
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Starting IRC Fiber Engine  $(RESET)"
	@if [ -z "$(IRCFIBER_SERVER_ID)" ]; then \
		export IRCFIBER_SERVER_ID=localengine; \
	fi
	@env IRCFIBER_MONGO_URL=mongodb://127.0.0.1:27017/ircfiber IRCFIBER_REDIS_URL=redis://127.0.0.1:6379/0 IRCFIBER_SERVER_ID=$${IRCFIBER_SERVER_ID:-localengine} IRCFIBER_BIND_ADDRESS=$${IRCFIBER_BIND_ADDRESS:-127.0.0.1} ./irc-fiber-engine

test:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Running Tests  $(RESET)"
	@$(DUB) test 2>&1 | tail -20

# ----------------------------------------------------------------------------
# Code Quality (D-Scanner)
# ----------------------------------------------------------------------------

dscanner-install:
	@command -v dscanner >/dev/null 2>&1 || dub fetch dscanner

dscanner-syntax:
	@printf '\n%b\n' "$(DIM)--- D-Scanner syntax check ---$(RESET)"
	@$(DSCANNER) --syntaxCheck $(SRCS) 2>/dev/null || true

dscanner-lint:
	@printf '\n%b\n' "$(DIM)--- D-Scanner lint ---$(RESET)"
	@$(DSCANNER) --styleCheck $(SRCS) 2>/dev/null || true

dscanner-unused:
	@printf '\n%b\n' "$(DIM)--- D-Scanner unused check ---$(RESET)"
	@$(DSCANNER) --styleCheck $(SRCS) 2>/dev/null | grep -E "unused_(variable|parameter|import)" || \
		printf '%b\n' "$(GREEN)$(ICON_OK) No unused symbols found$(RESET)"

dscanner-complexity:
	@printf '\n%b\n' "$(DIM)--- D-Scanner complexity check ---$(RESET)"
	@$(DSCANNER) --styleCheck $(SRCS) 2>/dev/null | grep "cyclomatic_complexity" || \
		printf '%b\n' "$(GREEN)$(ICON_OK) No high-complexity functions found$(RESET)"

dscanner-imports:
	@printf '\n%b\n' "$(DIM)--- Import analysis ---$(RESET)"
	@$(DSCANNER) --imports $(SRCS) 2>/dev/null || true

dscanner-fix:
	@printf '\n%b\n' "$(DIM)--- Auto-fix style issues ---$(RESET)"
	@$(DSCANNER) --fixStyle $(SRCS) 2>/dev/null || true

dscanner-size:
	@printf '\n%b\n' "$(DIM)--- SLOC count ---$(RESET)"
	@$(DSCANNER) --sloc $(SRCS) 2>/dev/null || true

dscanner-outline:
	@printf '\n%b\n' "$(DIM)--- Outline ---$(RESET)"
	@$(DSCANNER) --outline $(SRCS) 2>/dev/null || true

dscanner-all: dscanner-syntax dscanner-lint dscanner-unused dscanner-complexity

# ----------------------------------------------------------------------------
# Docker / Podman Compose
# ----------------------------------------------------------------------------

ensure-colima:
	@if ! docker info >/dev/null 2>&1; then \
		if command -v colima >/dev/null 2>&1; then \
			printf '\n%b\n' "$(YELLOW)$(ICON_WARN) Docker daemon is not reachable$(RESET)"; \
			printf '%b' "$(CYAN)Colima appears to be installed but not running. Start it now? [Y/n] $(RESET)"; \
			read -r answer < /dev/tty; \
			case "$$answer" in \
				[Nn]|[Nn][Oo]) \
					printf '%b\n' "$(YELLOW)$(ICON_WARN) Aborted. Start Colima manually with: colima start$(RESET)"; \
					exit 1; \
					;; \
				*) \
					printf '%b\n' "$(CYAN)→ Starting Colima...$(RESET)"; \
					colima start; \
					;; \
			esac; \
		else \
			printf '\n%b\n' "$(YELLOW)$(ICON_WARN) Docker daemon is not running and Colima is not installed$(RESET)"; \
			exit 1; \
		fi \
	fi

docker-up: ensure-colima
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Docker Services  $(RESET)"
	@docker compose up -d
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services started$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

stop: docker-down
down: docker-down

docker-down: ensure-colima
	@printf '%b\n' "$(DIM)→ Stopping Docker services (docker-compose.yml)...$(RESET)"
	@docker compose down
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services stopped$(RESET)"

docker-down-test: ensure-colima
	@printf '%b\n' "$(DIM)→ Stopping Docker test services (docker-compose.test.yml)...$(RESET)"
	@docker compose -f docker-compose.test.yml down
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Test services stopped$(RESET)"

docker-logs: ensure-colima
	@docker compose logs -f

docker-build: ensure-colima
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Building Docker Image  $(RESET)"
	@docker compose build
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Docker image built$(RESET)"

docker-restart-gateway: docker-restart-web

docker-up-web: ensure-colima
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Web Server (Gateway)  $(RESET)"
	@docker compose up -d irc_fiber
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Web server started$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

docker-down-web: ensure-colima
	@printf '%b\n' "$(DIM)→ Stopping web server...$(RESET)"
	@docker compose stop irc_fiber
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Web server stopped$(RESET)"

docker-restart-web: ensure-colima
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Restarting Web Server (Gateway)  $(RESET)"
	@docker compose build irc_fiber
	@docker compose up -d --force-recreate irc_fiber
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Web server restarted$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

docker-up-backend: ensure-colima
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Backend Services  $(RESET)"
	@docker compose up -d irc_engine redis mongo ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Backend services started$(RESET)"

docker-down-backend: ensure-colima
	@printf '%b\n' "$(DIM)→ Stopping backend services...$(RESET)"
	@docker compose stop irc_engine redis mongo ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Backend services stopped$(RESET)"

docker-restart-backend: ensure-colima
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Restarting Backend Services  $(RESET)"
	@docker compose up -d --build --force-recreate irc_engine redis mongo ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Backend services restarted$(RESET)"

ircd-up: ensure-colima
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting IRCD Test Server  $(RESET)"
	@docker compose up -d ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) IRCD started$(RESET) $(DIM)(localhost:6667)$(RESET)"

ircd-down: ensure-colima
	@printf '%b\n' "$(DIM)→ Stopping IRCD...$(RESET)"
	@docker compose stop ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) IRCD stopped$(RESET)"

docker-restart: docker-restart-web docker-restart-backend
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) All services restarted$(RESET)"

podman-up:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Podman Services  $(RESET)"
	@podman compose up -d
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services started$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

podman-down:
	@printf '%b\n' "$(DIM)→ Stopping Podman services...$(RESET)"
	@podman compose down
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services stopped$(RESET)"

podman-up-web:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Web Server (Podman)  $(RESET)"
	@podman compose up -d irc_fiber
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Web server started$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

podman-down-web:
	@printf '%b\n' "$(DIM)→ Stopping web server (Podman)...$(RESET)"
	@podman compose stop irc_fiber
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Web server stopped$(RESET)"

podman-restart-web:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Restarting Web Server (Podman)  $(RESET)"
	@podman compose up -d --build --force-recreate irc_fiber
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Web server restarted$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

podman-up-backend:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Backend Services (Podman)  $(RESET)"
	@podman compose up -d irc_engine redis mongo ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Backend services started$(RESET)"

podman-down-backend:
	@printf '%b\n' "$(DIM)→ Stopping backend services (Podman)...$(RESET)"
	@podman compose stop irc_engine redis mongo ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Backend services stopped$(RESET)"

podman-restart-backend:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Restarting Backend Services (Podman)  $(RESET)"
	@podman compose up -d --build --force-recreate irc_engine redis mongo ircd
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Backend services restarted$(RESET)"

podman-restart: podman-restart-web podman-restart-backend
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) All Podman services restarted$(RESET)"

# ----------------------------------------------------------------------------
# Cross Compilation
# ----------------------------------------------------------------------------

cross-linux-x64:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Cross-compiling for Linux x64  $(RESET)"
	@$(DUB) build --config=release --arch=x86_64-linux-gnu 2>&1 | tail -8 || \
		printf '%b\n' "$(YELLOW)$(ICON_WARN) Cross-compilation may require a Linux toolchain$(RESET)"

cross-linux-arm64:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Cross-compiling for Linux ARM64  $(RESET)"
	@$(DUB) build --config=release --arch=aarch64-linux-gnu 2>&1 | tail -8 || \
		printf '%b\n' "$(YELLOW)$(ICON_WARN) Cross-compilation may require a Linux ARM64 toolchain$(RESET)"

cross-linux-armv7:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Cross-compiling for Linux ARMv7  $(RESET)"
	@$(DUB) build --config=release --arch=arm-linux-gnueabihf 2>&1 | tail -8 || \
		printf '%b\n' "$(YELLOW)$(ICON_WARN) Cross-compilation may require a Linux ARMv7 toolchain$(RESET)"

# ----------------------------------------------------------------------------
# Dependency Check
# ----------------------------------------------------------------------------

deps-check:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Checking Dependencies  $(RESET)"
	@which $(DUB) >/dev/null && printf '  %b\n' "$(GREEN)$(ICON_OK) dub$(RESET)" || \
		printf '  %b\n' "$(YELLOW)$(ICON_WARN) dub - Install D compiler package$(RESET)"
	@which $(LDC) >/dev/null && printf '  %b\n' "$(GREEN)$(ICON_OK) ldc2$(RESET)" || \
		printf '  %b\n' "$(YELLOW)$(ICON_WARN) ldc2 - Install: brew install ldc$(RESET)"
	@which docker >/dev/null && printf '  %b\n' "$(GREEN)$(ICON_OK) docker$(RESET)" || \
		printf '  %b\n' "$(DIM)$(ICON_BULLET) docker - optional$(RESET)"
	@which redis-cli >/dev/null && printf '  %b\n' "$(GREEN)$(ICON_OK) redis-cli$(RESET)" || \
		printf '  %b\n' "$(DIM)$(ICON_BULLET) redis-cli - optional$(RESET)"
	@which mongosh >/dev/null && printf '  %b\n' "$(GREEN)$(ICON_OK) mongosh$(RESET)" || \
		printf '  %b\n' "$(DIM)$(ICON_BULLET) mongosh - optional$(RESET)"

# ----------------------------------------------------------------------------
# Utility Targets
# ----------------------------------------------------------------------------

clean:
	@printf '%b\n' "$(DIM)→ Cleaning build artifacts...$(RESET)"
	@rm -f $(APP) *.o
	@rm -rf .dub
	@$(DUB) clean 2>/dev/null || true
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Clean complete$(RESET)"

fmt:
	@printf '%b\n' "$(DIM)→ Formatting D source files...$(RESET)"
	@find source -name "*.d" -exec dfmt -i {} \; 2>/dev/null || \
		printf '%b\n' "$(YELLOW)$(ICON_WARN) dfmt not found. Install: dub fetch dfmt$(RESET)"

# ----------------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------------

help:
	@echo ""
	@echo "$(BOLD)IRC Fiber - IRC Bouncer & Web Client$(RESET)"
	@echo "$(DIM)=====================================$(RESET)"
	@echo ""
	@echo "$(BG_GREEN)$(BLACK)  Quick Start  $(RESET)"
	@echo "  $(BRIGHT_GREEN)make build$(RESET)          - Build the application with dub"
	@echo "  $(BRIGHT_GREEN)make run$(RESET)            - Build and run the gateway (auto-starts backends)"
	@echo "  $(BRIGHT_GREEN)make run-engine$(RESET)     - Run the IRC engine (needs backends running)"
	@echo "  $(BRIGHT_GREEN)make docker-up$(RESET)      - Start with Docker Compose (MongoDB + Redis)"
	@echo "  $(BRIGHT_GREEN)make stop$(RESET)           - Stop all Docker services"
	@echo ""
	@echo "$(BG_CYAN)$(BLACK)  Build Targets  $(RESET)"
	@echo "  $(GREEN)make build$(RESET)              - Default debug build"
	@echo "  $(GREEN)make build-release$(RESET)      - Optimized release build"
	@echo "  $(GREEN)make build-debug$(RESET)        - Explicit debug build"
	@echo "  $(GREEN)make build-ldc2$(RESET)         - Direct ldc2 build (no dub overhead)"
	@echo "  $(GREEN)make test$(RESET)               - Run unit tests"
	@echo ""
	@echo "$(BG_YELLOW)$(BLACK)  Docker / Podman  $(RESET)"
	@echo "  $(YELLOW)make docker-up$(RESET)          - Start all services with Docker"
	@echo "  $(YELLOW)make stop$(RESET)               - Stop all Docker services"
	@echo "  $(YELLOW)make docker-down$(RESET)        - Stop all Docker services (alias)"
	@echo "  $(YELLOW)make docker-down-test$(RESET)   - Stop test services (ircd + mongo + redis)"
	@echo "  $(YELLOW)make docker-restart$(RESET)     - Restart all Docker services"
	@echo "  $(YELLOW)make docker-up-web$(RESET)      - Start web server only"
	@echo "  $(YELLOW)make docker-down-web$(RESET)    - Stop web server only"
	@echo "  $(YELLOW)make docker-restart-web$(RESET) - Restart web server only"
	@echo "  $(YELLOW)make docker-up-backend$(RESET)  - Start backend services only"
	@echo "  $(YELLOW)make docker-down-backend$(RESET)- Stop backend services only"
	@echo "  $(YELLOW)make docker-restart-backend$(RESET)- Restart backend services only"
	@echo "  $(YELLOW)make docker-logs$(RESET)        - Tail Docker logs"
	@echo "  $(YELLOW)make docker-build$(RESET)       - Rebuild Docker image"
	@echo "  $(YELLOW)make ircd-up$(RESET)            - Start test IRCD (localhost:6667)"
	@echo "  $(YELLOW)make ircd-down$(RESET)          - Stop test IRCD"
	@echo "  $(YELLOW)make podman-up$(RESET)          - Start with Podman Compose"
	@echo "  $(YELLOW)make podman-down$(RESET)        - Stop Podman services"
	@echo "  $(YELLOW)make podman-restart$(RESET)     - Restart all Podman services"
	@echo ""
	@echo "$(BG_MAGENTA)$(BLACK)  Code Quality  $(RESET)"
	@echo "  $(MAGENTA)make dscanner-all$(RESET)       - Run all D-Scanner checks"
	@echo "  $(MAGENTA)make dscanner-syntax$(RESET)    - Syntax check"
	@echo "  $(MAGENTA)make dscanner-lint$(RESET)      - Style lint"
	@echo "  $(MAGENTA)make dscanner-unused$(RESET)    - Find unused imports/symbols"
	@echo "  $(MAGENTA)make dscanner-complexity$(RESET)- Cyclomatic complexity check"
	@echo "  $(MAGENTA)make dscanner-fix$(RESET)       - Auto-fix style issues"
	@echo ""
	@echo "$(BG_BLUE)$(BLACK)  Cross Compilation  $(RESET)"
	@echo "  $(BLUE)make cross-linux-x64$(RESET)    - Cross-compile for Linux x86_64"
	@echo "  $(BLUE)make cross-linux-arm64$(RESET)  - Cross-compile for Linux ARM64"
	@echo "  $(BLUE)make cross-linux-armv7$(RESET)  - Cross-compile for Linux ARMv7"
	@echo ""
	@echo "$(DIM)Other:$(RESET)"
	@echo "  make deps-check         - Check for required dependencies"
	@echo "  make clean              - Remove build artifacts"
	@echo "  make fmt                - Format D source files with dfmt"
	@echo ""
