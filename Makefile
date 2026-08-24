# ============================================================================
# IRC Fiber — Root Workspace Makefile
# ============================================================================
# Thin wrapper so you can drive the split workspace from the root:
#
#   make help              # this file — full use-case matrix
#   make site-help         # site/Makefile.site help
#   make engine-help       # engine/Makefile.engine help
#   make dev / debug / status / logs / stop  → delegates to site (gateway+frontend)
#   make engine / engine-start / engine-logs → delegates to engine (IRC daemon)
#   make site-<target>     # explicit site passthrough (e.g. make site-dev)
#   make engine-<target>   # explicit engine passthrough (e.g. make engine-test)
#
# Underlying files:
#   site/Makefile.site     (142KB, site = gateway + Svelte frontend)
#   engine/Makefile.engine (142KB, engine = IRC daemon)
#
# Both pin DOCKER_CONTEXT=colima locally (native arm64) — staging VM only
# when you pass DOCKER_CONTEXT=colima-staging explicitly.
# ============================================================================

.DELETE_ON_ERROR:
.DEFAULT_GOAL := help

SITE_DIR    := site
ENGINE_DIR  := engine
SITE_MAKE   := $(MAKE) -C $(SITE_DIR) -f Makefile.site
ENGINE_MAKE := $(MAKE) -C $(ENGINE_DIR) -f Makefile.engine

# Docker context pinning — mirror the sub-makefiles so `make` at root
# still pins to native arm64 colima for every local docker recipe.
ifeq ($(shell docker context ls --format '{{.Name}}' 2>/dev/null | grep -x colima),colima)
export DOCKER_CONTEXT := colima
endif

# Colors (same as sub-makefiles + extras for root subsections)
R  := \033[0m
B  := \033[1m
D  := \033[2m
K  := \033[30m
G  := \033[32m
Y  := \033[33m
M  := \033[35m
C  := \033[36m
BG := \033[92m
BM := \033[95m
BY := \033[93m
_BC  := \033[42m
_BY  := \033[43m
_BM  := \033[45m
_BB  := \033[44m
_BCn := \033[46m
OK := ✓
WR := ⚠
BL := •
AR := →

# ----------------------------------------------------------------------------
# Help — root use-case matrix + organized site/engine subsections (colored)
# ----------------------------------------------------------------------------
.PHONY: help site-help engine-help

help: ## Root > Show this help + use-case matrix (site + engine)
	@printf '\n\033[1mIRC Fiber — Root Workspace\033[0m \033[2m(site + engine + common)\033[0m\n'
	@printf '\033[2m============================================================\033[0m\n'
	@printf '\n\033[1mLayout\033[0m\n'
	@printf '  \033[36m./Makefile\033[0m              → this file (wrapper)\n'
	@printf '  \033[36msite/Makefile.site\033[0m     → gateway + Svelte frontend (Containerfile.site)\n'
	@printf '  \033[36mengine/Makefile.engine\033[0m → IRC daemon (Containerfile.engine)\n'
	@printf '  \033[36mcommon/\033[0m                 → shared D lib (dub, submodule in both)\n'
	@printf '\n\033[1mUSE-CASE MATRIX\033[0m  \033[2m(run from repo root)\033[0m\n'
	@printf '  \033[36mChange Svelte / CSS / HTML only\033[0m\n'
	@printf '    \033[92mmake dev\033[0m                 Vite HMR → local gateway (:8090)\n'
	@printf '    \033[92mmake dev-live\033[0m            Vite HMR → tailnet gateway (:18090, live DBs)\n'
	@printf '  \033[36mChange gateway D code (no IRC reconnect)\033[0m\n'
	@printf '    \033[92mmake debug\033[0m               Gateway only (docker), engine untouched\n'
	@printf '    \033[92mmake debug-live\033[0m          Gateway+engine (docker) → tailnet DBs\n'
	@printf '  \033[36mChange engine D code\033[0m\n'
	@printf '    \033[92mmake engine-start\033[0m        Engine (docker, detached)\n'
	@printf '    \033[92mmake engine-rebuild && make engine-restart\033[0m\n'
	@printf '  \033[36mFull local stack (decoupled)\033[0m\n'
	@printf '    Terminal 1: \033[92mmake engine-start\033[0m   engine in background (holds IRC)\n'
	@printf '    Terminal 2: \033[92mmake debug\033[0m           gateway only\n'
	@printf '    Terminal 3: \033[92mmake dev\033[0m             Vite HMR\n'
	@printf '  \033[36mDeploy (OVH vps-efb4b52d, ansible — no manual docker build)\033[0m\n'
	@printf '    \033[92mmake deploy-site\033[0m         site only (gateway+frontend, engine stays up)\n'
	@printf '    \033[92mmake deploy-engine\033[0m       engine only (IRC daemon)\n'
	@printf '  \033[36mObserve\033[0m\n'
	@printf '    \033[92mmake status\033[0m              processes + ports + log tails\n'
	@printf '    \033[92mmake logs\033[0m                gateway + engine (docker)\n'
	@printf '    \033[92mmake stop\033[0m                stop everything (leaves Vite alone)\n'
	@printf '\n\033[2mPassthrough: make site-<target> / make engine-<target> forwards verbatim.\033[0m\n'
	@printf '\033[2m           e.g. make site-test, make engine-dscanner-lint, make site-frontend\033[0m\n'
	@printf '\n$(_BB)$(K)$(B)  ROOT — Workspace  $(R)  \033[2m(this Makefile)\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##[ \t]*Root[ \t]*>/{sub(/.*Root[ \t]*>[ \t]*/,"",$$2); printf "  \033[92mmake %-*s\033[0m \033[2m—\033[0m %s\n", 28, $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\n$(_BCn)$(K)$(B)  SITE — Gateway + Frontend  $(R)  \033[2m(site/Makefile.site)\033[0m\n'
	@printf '  \033[36m\033[1m▸ Frontend — Vite / Svelte / Assets\033[0m \033[2m(dev, build)\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(dev|dev-live|dev-docker|frontend|version)$$/ || t ~ /^frontend-/) {sub(/.*>[ \t]*/,"",c); printf "    \033[36mmake %-*s\033[0m %s\n", 26, t, c}}' $(SITE_DIR)/Makefile.site | sort -u
	@printf '\n  \033[32m\033[1m▸ Gateway — D/vibe.d REST+WS\033[0m \033[2m(debug, gateway)\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(debug|debug-all|debug-host|debug-live|gateway|gateway-rebuild|gateway-restart)$$/ || t ~ /^gateway-/ || t == "build-gateway") {sub(/.*>[ \t]*/,"",c); printf "    \033[32mmake %-*s\033[0m %s\n", 26, t, c}}' $(SITE_DIR)/Makefile.site | sort -u
	@printf '\n  \033[33m\033[1m▸ Observability — Logs / Status / Watch\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(status|logs|logs-.*|crash-logs|watch.*)$$/ || t ~ /^watch-/) {sub(/.*>[ \t]*/,"",c); printf "    \033[33mmake %-*s\033[0m %s\n", 26, t, c}}' $(SITE_DIR)/Makefile.site | sort -u
	@printf '\n  \033[35m\033[1m▸ Quality — Tests / Lint / Format\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(test|test-.*|lint|lint-.*|fmt|fmt-check|dscanner.*|verify|precommit|ci|prefs-test)$$/ || t ~ /^dscanner/ || t ~ /^prefs-test/) {sub(/.*>[ \t]*/,"",c); printf "    \033[35mmake %-*s\033[0m %s\n", 26, t, c}}' $(SITE_DIR)/Makefile.site | sort -u
	@printf '\n  \033[34m\033[1m▸ Build — Dub / Docker / Cross\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(build|build-debug|build-release|build-ldc2|build-engine|all|janitor.*|ircfiber.*)$$/ || t ~ /^(cross|ensure-colima|docker|api-python)/) {sub(/.*>[ \t]*/,"",c); printf "    \033[34mmake %-*s\033[0m %s\n", 26, t, c}}' $(SITE_DIR)/Makefile.site | sort -u
	@printf '\n  \033[31m\033[1m▸ Deploy — Ansible / SigNoz / IRCd\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^deploy/ || t ~ /^(update|update-.*|up|down|stop)$$/) {sub(/.*>[ \t]*/,"",c); printf "    \033[31mmake %-*s\033[0m %s\n", 26, t, c}}' $(SITE_DIR)/Makefile.site | sort -u
	@printf '  \033[2m… full list: make site-help\033[0m\n'
	@printf '\n$(_BC)$(K)$(B)  ENGINE — IRC Daemon  $(R)  \033[2m(engine/Makefile.engine)\033[0m\n'
	@printf '  \033[32m\033[1m▸ Engine — Connection / IRC\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(engine|engine-.*|debug|debug-.*)$$/ || t == "build-engine") {sub(/.*>[ \t]*/,"",c); printf "    \033[32mmake %-*s\033[0m %s\n", 26, t, c}}' $(ENGINE_DIR)/Makefile.engine | sort -u
	@printf '\n  \033[36m\033[1m▸ Shared — Gateway / Frontend\033[0m \033[2m(also via site)\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(gateway.*|build-gateway|frontend.*)$$/) {sub(/.*>[ \t]*/,"",c); printf "    \033[36mmake %-*s\033[0m %s\n", 26, t, c}}' $(ENGINE_DIR)/Makefile.engine | sort -u
	@printf '\n  \033[33m\033[1m▸ Observability — Logs / Status / Watch\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(status|logs|logs-.*|crash-logs|watch.*)$$/ || t ~ /^watch-/) {sub(/.*>[ \t]*/,"",c); printf "    \033[33mmake %-*s\033[0m %s\n", 26, t, c}}' $(ENGINE_DIR)/Makefile.engine | sort -u
	@printf '\n  \033[35m\033[1m▸ Quality — Tests / Lint / Format\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(test|test-.*|lint|lint-.*|fmt|fmt-check|dscanner.*|verify|precommit|ci|prefs-test)$$/ || t ~ /^dscanner/ || t ~ /^prefs-test/) {sub(/.*>[ \t]*/,"",c); printf "    \033[35mmake %-*s\033[0m %s\n", 26, t, c}}' $(ENGINE_DIR)/Makefile.engine | sort -u
	@printf '\n  \033[34m\033[1m▸ Build — Dub / Docker / Cross\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^(build|build-.*|janitor.*|ircfiber.*|all|cross)/ || t ~ /^(ensure-colima|docker)/) {sub(/.*>[ \t]*/,"",c); printf "    \033[34mmake %-*s\033[0m %s\n", 26, t, c}}' $(ENGINE_DIR)/Makefile.engine | sort -u
	@printf '\n  \033[31m\033[1m▸ Deploy — Ansible / SigNoz / IRCd\033[0m\n'
	@awk 'BEGIN{FS=":.*##[ \t]*"} /^[a-zA-Z0-9_.\/-]+:.*##/{t=$$1; c=$$2; if (t ~ /^deploy/ || t ~ /^(update|update-.*|up|down|stop)$$/) {sub(/.*>[ \t]*/,"",c); printf "    \033[31mmake %-*s\033[0m %s\n", 26, t, c}}' $(ENGINE_DIR)/Makefile.engine | sort -u
	@printf '  \033[2m… full list: make engine-help\033[0m\n'
	@printf '\n\033[2mTip: make site-<target> / make engine-<target> forwards verbatim to the sub-makefile.\033[0m\n'
	@printf '\n'

site-help: ## Root > Show site/Makefile.site help
	@$(SITE_MAKE) help

engine-help: ## Root > Show engine/Makefile.engine help
	@$(ENGINE_MAKE) help

# ----------------------------------------------------------------------------
# Aggregates
# ----------------------------------------------------------------------------
.PHONY: all version up down install-env verify ci

all: help ## Root > Alias for help

version: ## Root > Generate version file in site + engine (common/source/ircfiber/version.d)
	@$(SITE_MAKE) version
	@$(ENGINE_MAKE) version

up: ## Root > Start local stack (site gateway + engine, docker)
	@printf '\n$(BG)$(OK) Starting local stack (gateway + engine)$(R)\n'
	@$(SITE_MAKE) gateway-up || true
	@$(ENGINE_MAKE) engine-up || true
	@$(SITE_MAKE) status || true

down: ## Root > Stop local docker stacks (site + engine)
	@$(SITE_MAKE) down || true
	@$(ENGINE_MAKE) down || true

install-env: ## Root > Install dev env (frontend deps + CLI checks) — runs in site
	@$(SITE_MAKE) install-env

verify: ## Root > lint + test (site)
	@$(SITE_MAKE) verify

ci: ## Root > Full CI (fmt + lint + test, site)
	@$(SITE_MAKE) ci

# ----------------------------------------------------------------------------
# Site passthrough — frontend + gateway (most daily dev)
# ----------------------------------------------------------------------------
.PHONY: dev dev-live dev-live-tunnel dev-docker debug debug-live debug-host debug-all
.PHONY: frontend frontend-build frontend-install
.PHONY: build build-gateway build-release build-debug
.PHONY: gateway gateway-rebuild gateway-restart gateway-start gateway-up gateway-down gateway-logs
.PHONY: test test-frontend test-all test-watch

dev: ## Root > Frontend dev (Vite HMR) — pairs with make debug (site)
	@$(SITE_MAKE) dev

dev-live: ## Root > Frontend dev against LIVE DBs via tailnet (site)
	@$(SITE_MAKE) dev-live

dev-live-tunnel: ## Root > ssh -L tunnel OVH gateway → :18090 for dev-live (site)
	@$(SITE_MAKE) dev-live-tunnel

dev-docker: ## Root > Docker backend + Vite dev (site)
	@$(SITE_MAKE) dev-docker

debug: ## Root > Gateway in Docker (local DBs), engine untouched (site)
	@$(SITE_MAKE) debug

debug-live: ## Root > Gateway+engine in Docker → tailnet DBs (site)
	@$(SITE_MAKE) debug-live

debug-host: ## Root > Full stack host-native: gateway+supervised engine (site)
	@$(SITE_MAKE) debug-host

frontend: ## Root > Production frontend bundle + rebuild local gateway (site)
	@$(SITE_MAKE) frontend

frontend-build: ## Root > Production frontend bundle only (site)
	@$(SITE_MAKE) frontend-build

frontend-install: ## Root > Install frontend deps (site)
	@$(SITE_MAKE) frontend-install

build: ## Root > Build gateway binary (site)
	@$(SITE_MAKE) build

build-gateway: ## Root > Build gateway binary (site)
	@$(SITE_MAKE) build-gateway

gateway: ## Root > Gateway in foreground (site)
	@$(SITE_MAKE) gateway

gateway-rebuild: ## Root > Rebuild gateway binary (site)
	@$(SITE_MAKE) gateway-rebuild

gateway-up: ## Root > Start gateway container (site)
	@$(SITE_MAKE) gateway-up

gateway-down: ## Root > Stop gateway container (site)
	@$(SITE_MAKE) gateway-down

gateway-logs: ## Root > Tail gateway docker logs (site)
	@$(SITE_MAKE) gateway-logs

test: ## Root > Run tests (site: D + frontend)
	@$(SITE_MAKE) test

test-frontend: ## Root > Run frontend tests (site)
	@$(SITE_MAKE) test-frontend

# ----------------------------------------------------------------------------
# Engine passthrough — IRC daemon (holds TCP/TLS)
# ----------------------------------------------------------------------------
.PHONY: engine engine-rebuild engine-handoff engine-restart engine-start engine-stop engine-down engine-up engine-logs engine-test

engine: ## Root > Engine in foreground (no auto-restart, engine)
	@$(ENGINE_MAKE) engine

engine-rebuild: ## Root > Rebuild engine binary (engine)
	@$(ENGINE_MAKE) engine-rebuild

engine-handoff: ## Root > Hot-reload engine (REMOVED → hard restart, engine)
	@$(ENGINE_MAKE) engine-handoff

engine-restart: ## Root > Restart engine (host supervisor, engine)
	@$(ENGINE_MAKE) engine-restart

engine-start: ## Root > Start engine in background (detached, engine)
	@$(ENGINE_MAKE) engine-start

engine-stop: ## Root > Stop engine (engine)
	@$(ENGINE_MAKE) engine-stop

engine-up: ## Root > Start engine container (engine)
	@$(ENGINE_MAKE) engine-up

engine-down: ## Root > Stop engine container (engine)
	@$(ENGINE_MAKE) engine-down

engine-logs: ## Root > Tail engine docker logs (engine)
	@$(ENGINE_MAKE) logs-engine

engine-test: ## Root > Run D unit tests (engine)
	@$(ENGINE_MAKE) engine-test

# ----------------------------------------------------------------------------
# Observability — delegated (site owns `status`/`logs`/`stop` aggregates)
# ----------------------------------------------------------------------------
.PHONY: status logs logs-engine logs-gateway logs-supervisor crash-logs stop

status: ## Root > Show running processes, ports, log tails (site)
	@$(SITE_MAKE) status

logs: ## Root > Tail gateway + engine docker logs (site)
	@$(SITE_MAKE) logs

logs-engine: ## Root > Tail engine docker logs (site)
	@$(SITE_MAKE) logs-engine

logs-gateway: ## Root > Tail gateway docker logs (site)
	@$(SITE_MAKE) logs-gateway

logs-supervisor: ## Root > Tail supervisor log (site)
	@$(SITE_MAKE) logs-supervisor

crash-logs: ## Root > List persistent crash dumps (site)
	@$(SITE_MAKE) crash-logs

stop: ## Root > Stop debug/debug-live + local docker stacks (site)
	@$(SITE_MAKE) stop

# ----------------------------------------------------------------------------
# Deploy — ansible, decoupled (site never restarts engine)
# ----------------------------------------------------------------------------
.PHONY: deploy-site deploy-engine deploy-restart deploy-restart-gateway deploy-restart-engine

deploy-site: ## Root > Deploy site (gateway+frontend) to OVH — engine untouched
	@$(SITE_MAKE) deploy 2>/dev/null || $(SITE_MAKE) update 2>/dev/null || \
		(cd $(SITE_DIR) && ansible-playbook deploy/playbooks/deploy-site.yml -l vps-efb4b52d)

deploy-engine: ## Root > Deploy engine (IRC daemon) to OVH
	@$(ENGINE_MAKE) deploy 2>/dev/null || $(ENGINE_MAKE) update 2>/dev/null || \
		(cd $(ENGINE_DIR) && ansible-playbook deploy/playbooks/deploy-engine.yml -l vps-efb4b52d)

deploy-restart: ## Root > Restart remote containers (all; site playbook)
	@$(SITE_MAKE) deploy-restart

deploy-restart-gateway: ## Root > Restart remote gateway container only
	@$(SITE_MAKE) deploy-restart-gateway

deploy-restart-engine: ## Root > Restart remote engine container only
	@$(ENGINE_MAKE) deploy-restart-engine 2>/dev/null || $(SITE_MAKE) deploy-restart-engine

# ----------------------------------------------------------------------------
# Generic passthrough — site-<target> / engine-<target>
# ----------------------------------------------------------------------------
#   make site-foo   →  make -C site -f Makefile.site foo
#   make engine-foo →  make -C engine -f Makefile.engine foo
# Catches any target not explicitly listed above.
.PHONY: site-% engine-%

site-%: ## Root > Passthrough to site (e.g. make site-dscanner-lint)
	@$(SITE_MAKE) $*

engine-%: ## Root > Passthrough to engine (e.g. make engine-dscanner-lint)
	@$(ENGINE_MAKE) $*


