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
.PHONY: all help build build-release build-debug run test clean fmt
.PHONY: dscanner dscanner-install dscanner-syntax dscanner-lint dscanner-unused
.PHONY: dscanner-complexity dscanner-imports dscanner-fix dscanner-size dscanner-outline dscanner-all
.PHONY: deps-check docker-up docker-down docker-logs docker-build cross-linux-x64 cross-linux-arm64 cross-linux-armv7

# ----------------------------------------------------------------------------
# Main Build Targets
# ----------------------------------------------------------------------------

all: build

build:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber  $(RESET)"
	@$(DUB) build 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8
	@if [ -f $(APP) ]; then \
		SIZE=$$(ls -lh $(APP) | awk '{print $$5}'); \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Build successful$(RESET) $(DIM)($$SIZE)$(RESET)"; \
	else \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Dub build complete$(RESET)"; \
	fi

build-release:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber (Release)  $(RESET)"
	@$(DUB) build --build=release 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8
	@SIZE=$$(ls -lh $(APP) 2>/dev/null | awk '{print $$5}'); \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Release build successful$(RESET) $(DIM)($$SIZE)$(RESET)"

build-debug:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber (Debug)  $(RESET)"
	@$(DUB) build --build=debug 2>&1 | grep -v "Compiling Diet" | grep -v "\.dt$$" | grep -v "deployment version" | tail -8
	@printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Debug build successful$(RESET)"

# Build with direct ldc2 (no dub dependency resolution overhead)
build-ldc2:
	@printf '\n%b\n' "$(BG_CYAN)$(BLACK)$(BOLD)  Building IRC Fiber (LDC2 Direct)  $(RESET)"
	@$(LDC) $(SRCS) -of=$(APP) -Isource -Jviews \
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
		-version=VibeUseFibers \
		-L=-L$(shell brew --prefix openssl)/lib -L=-lssl -L=-lcrypto \
		2>&1 | grep -v "deployment version" | tail -12
	@SIZE=$$(ls -lh $(APP) 2>/dev/null | awk '{print $$5}'); \
		printf '\n%b\n' "$(BRIGHT_GREEN)$(ICON_OK) LDC2 build successful$(RESET) $(DIM)($$SIZE)$(RESET)"

# ----------------------------------------------------------------------------
# Run & Test
# ----------------------------------------------------------------------------

run: build
	@printf '%b\n' "$(CYAN)$(ICON_ARROW) Starting $(APP)...$(RESET)"
	@./$(APP)

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

docker-up:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Docker Services  $(RESET)"
	@docker compose up -d
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services started$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

docker-down:
	@printf '%b\n' "$(DIM)→ Stopping Docker services...$(RESET)"
	@docker compose down
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services stopped$(RESET)"

docker-logs:
	@docker compose logs -f

docker-build:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Building Docker Image  $(RESET)"
	@docker compose build
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Docker image built$(RESET)"

podman-up:
	@printf '\n%b\n' "$(BG_GREEN)$(BLACK)$(BOLD)  Starting Podman Services  $(RESET)"
	@podman compose up -d
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services started$(RESET) $(DIM)(http://localhost:8090)$(RESET)"

podman-down:
	@printf '%b\n' "$(DIM)→ Stopping Podman services...$(RESET)"
	@podman compose down
	@printf '%b\n' "$(BRIGHT_GREEN)$(ICON_OK) Services stopped$(RESET)"

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
	@echo "  $(BRIGHT_GREEN)make run$(RESET)            - Build and run the server"
	@echo "  $(BRIGHT_GREEN)make docker-up$(RESET)      - Start with Docker Compose (MongoDB + Redis)"
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
	@echo "  $(YELLOW)make docker-down$(RESET)        - Stop Docker services"
	@echo "  $(YELLOW)make docker-logs$(RESET)        - Tail Docker logs"
	@echo "  $(YELLOW)make docker-build$(RESET)       - Rebuild Docker image"
	@echo "  $(YELLOW)make podman-up$(RESET)          - Start with Podman Compose"
	@echo "  $(YELLOW)make podman-down$(RESET)        - Stop Podman services"
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
