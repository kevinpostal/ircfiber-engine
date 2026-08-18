# syntax=docker/dockerfile:1.7
ARG CACHE_BUST=fixed
#
# ===================================
#
# Stage graph:
#   base             : Ubuntu 22.04 + LDC toolchain (apt cache mounted)
#   builder-common   : dub fetch + shared `common` library build
#   builder-backend  : gateway binary (`irc-fiber`) + views — from builder-common
#   builder-engine   : engine binaries (`irc-fiber-engine`, `janitor-migrate`,
#                      `ircfiber-default-migrate`) — from builder-common
#   builder          : aggregate stage for `--target builder` deploys
#                      (deploy-update.yml / deploy-handoff.yml extract binaries)
#   runtime          : legacy combined image (all binaries)
#   runtime-gateway  : slim Ubuntu + gateway binary only
#   runtime-engine   : slim Ubuntu + engine binaries only
#
# Per-service split (why):
#   The gateway and engine images used to share ONE builder RUN that compiled
#   all six dub configs. Any change in backend/ or backend/views/ re-triggered
#   the full ENGINE compile (and vice versa) — a frontend-only rewrite of
#   `backend/views/index.dt` cost a ~7-minute full rebuild of BOTH images.
#   Now `--target runtime-gateway` never compiles engine sources and
#   `--target runtime-engine` never compiles backend sources.
#
# Dub incremental caching:
#   - `/build/.dub` + `/root/.dub` are BuildKit cache mounts. dub 1.41 keeps
#     ALL build state (fetched packages AND object files) under
#     `$HOME/.dub/cache/`, so a re-run after a source change recompiles only
#     modules whose content changed — BuildKit preserves source mtimes through
#     COPY, which dub's incremental checker relies on.
#
# Cache invalidation:
#   - LDC_VERSION, ARG TARGETARCH, Dockerfile changes invalidate `base`.
#   - dub.sdl / dub.selections.json changes re-run `dub upgrade`.
#   - source/ changes re-run that stage's dub build (incremental).
#   - `CACHE_BUST=<n> --build-arg` (default fixed) forces a clean rebuild of
#     the dub steps (wipes both cache mounts in builder-common).

# ============================================================================
# Stage: base — Ubuntu + toolchain
# ============================================================================
FROM ubuntu:22.04 AS base

ARG LDC_VERSION=1.41.0
ARG TARGETARCH

# Docker ships an apt-clean hook that empties /var/cache/apt on every RUN,
# defeating cache mounts. Remove it so the cache mount persists.
RUN rm -f /etc/apt/apt.conf.d/docker-clean

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        xz-utils \
        build-essential \
        libssl-dev \
        zlib1g-dev \
        git \
        ca-certificates

# $TARGETARCH is set automatically by buildx (amd64 | arm64 | 386 | arm/v7).
# Previous version used `uname -m` which silently broke on multi-platform
# builds (always returned the kernel arch, not the requested target).
RUN case "$TARGETARCH" in \
        amd64)  LDC_ARCH=x86_64  ;; \
        arm64)  LDC_ARCH=aarch64 ;; \
        *) echo "Unsupported TARGETARCH: $TARGETARCH"; exit 1 ;; \
    esac && \
    mkdir -p /opt && \
    curl -fsSL -o /tmp/ldc.tar.xz \
        "https://github.com/ldc-developers/ldc/releases/download/v${LDC_VERSION}/ldc2-${LDC_VERSION}-linux-${LDC_ARCH}.tar.xz" && \
    tar -xf /tmp/ldc.tar.xz -C /opt && \
    ln -s "/opt/ldc2-${LDC_VERSION}-linux-${LDC_ARCH}" /opt/ldc2 && \
    rm /tmp/ldc.tar.xz

ENV PATH="/opt/ldc2/bin:${PATH}"
WORKDIR /build

# ============================================================================
# Stage: builder-common — fetch deps + build the shared common library.
#
# `dub build --parallel` parallelizes LDC compile jobs within a config
# (dub-1.x dispatches independent modules to parallel LDC invocations).
# Without `--force`, dub reuses the incremental module cache in the
# /build/.dub + /root/.dub cache mounts, so editing one file recompiles
# only that module.
#
# CACHE_BUST default "fixed"; pass `--build-arg CACHE_BUST=$(date +%s)`
# to force a clean rebuild of the dub steps.
# ============================================================================
FROM base AS builder-common
ARG GIT_HASH=unknown
ARG GIT_SHORT=unknown
ARG GIT_DESCRIBE=unknown
ARG GIT_BRANCH=unknown

# ── Build cache invalidation ─────────────────────────────────────────────
# Same sentinel trick as before, but now one sentinel per package so editing
# `backend/source/api/rest.d` does not force-rebuild the engine and vice versa.
# Each heredoc writes inside its package's source tree, invalidating the
# matching COPY below.
COPY <<EOF ./common/source/.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF

COPY common/dub.sdl common/dub.selections.json ./common/
COPY common/source/ ./common/source/

# If GIT_HASH was passed via --build-arg (from deploy-update.yml's local git),
# override the rsynced build_version.d so the binary embeds the correct version
# even when .git was excluded from rsync or rsync's checksum was stale. This
# is the safety net for the 6daa040 → caf2887 drift seen when times:false + no checksum
# left build_version.d unchanged despite a new commit. The file size is identical
# for different hashes, so size-only rsync would skip it.
RUN if [ "$GIT_HASH" != "unknown" ] && [ "$GIT_HASH" != "" ]; then \
      echo "builder-common: using GIT_HASH=$GIT_HASH GIT_SHORT=$GIT_SHORT"; \
      mkdir -p common/source/ircfiber; \
      printf 'module ircfiber.build_version;\n\n// Generated via Docker build-arg at %s\n// docker build --build-arg GIT_HASH=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$GIT_HASH" > common/source/ircfiber/build_version.d; \
      printf 'enum GIT_HASH = "%s";\n' "$GIT_HASH" >> common/source/ircfiber/build_version.d; \
      printf 'enum GIT_SHORT = "%s";\n' "${GIT_SHORT:-$GIT_HASH}" >> common/source/ircfiber/build_version.d; \
      printf 'enum GIT_DESCRIBE = "%s";\n' "${GIT_DESCRIBE:-$GIT_SHORT}" >> common/source/ircfiber/build_version.d; \
      printf 'enum GIT_BRANCH = "%s";\n' "${GIT_BRANCH:-unknown}" >> common/source/ircfiber/build_version.d; \
      printf 'enum BUILD_TIME = "%s";\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> common/source/ircfiber/build_version.d; \
      printf 'enum BUILD_HOST = "docker-builder";\n' >> common/source/ircfiber/build_version.d; \
      printf 'enum VERSION = "0.3.0";\n' >> common/source/ircfiber/build_version.d; \
      printf 'enum GIT_MESSAGE = "via build-arg";\n' >> common/source/ircfiber/build_version.d; \
      printf 'enum GIT_COMMIT_URL = "https://github.com/kevinpostal/IRC_FIBER/commit/%s";\n' "$GIT_HASH" >> common/source/ircfiber/build_version.d; \
      cat common/source/ircfiber/build_version.d; \
    fi

# When CACHE_BUST is non-default, nuke ALL caches dub/LDC might use:
# - /build/.dub (dub's global cache)
# - /root/.dub (dub's user-level cache — packages AND object files in 1.41)
# Then pass `--force` to dub to skip its own mtime/size checks.
RUN --mount=type=cache,target=/build/.dub,sharing=locked \
    --mount=type=cache,target=/root/.dub,sharing=locked \
    if [ "$CACHE_BUST" != "fixed" ]; then \
        DUB_FLAGS="--force" && \
        echo "dub cache busted (CACHE_BUST=$CACHE_BUST) --force" ; \
    else \
        DUB_FLAGS="" ; \
    fi && \
    echo "build: $CACHE_BUST" && \
    dub build --root=common --compiler=ldc2 --build=release --parallel $DUB_FLAGS
# ============================================================================
# Stage: builder-backend — gateway binary only (irc-fiber + irc-fiber-gateway)
# ============================================================================
FROM builder-common AS builder-backend

COPY <<EOF ./backend/source/.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF

COPY backend/dub.sdl backend/dub.selections.json ./backend/
COPY backend/source/ ./backend/source/
COPY backend/views/  ./backend/views/

# `--config=gateway` was a second full backend compile whose output was
# discarded (the image ships the default-config binary under both names).
# Dropped in the split — see runtime-gateway.
RUN --mount=type=cache,target=/build/.dub,sharing=locked \
    --mount=type=cache,target=/root/.dub,sharing=locked \
    if [ "$CACHE_BUST" != "fixed" ]; then \
        DUB_FLAGS="--force" && \
        echo "dub cache busted (CACHE_BUST=$CACHE_BUST)" ; \
    else \
        DUB_FLAGS="" ; \
    fi && \
    dub build --root=backend --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    cp backend/irc-fiber ./irc-fiber && \
    cp backend/irc-fiber ./irc-fiber-gateway && \
    cp -r backend/views ./views && \
    test -f ./irc-fiber
RUN find . -maxdepth 1 -type f -executable -exec strip {} +; find backend -maxdepth 2 -type f -executable -exec strip {} + 2>/dev/null; true

# ============================================================================
# Stage: builder-engine — engine binaries only (irc-fiber-engine + migrates)
# ============================================================================
FROM builder-common AS builder-engine

COPY <<EOF ./engine/source/.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF

# dub validates EVERY declared path dependency at package load — including the
# config-scoped `irc-fiber-backend` used only by test configs — so it needs
# backend/dub.sdl present even though release/migrate builds never compile
# backend sources. Only the package files, not the sources.
COPY backend/dub.sdl backend/dub.selections.json ./backend/
COPY engine/dub.sdl engine/dub.selections.json ./engine/
COPY engine/source/ ./engine/source/

RUN --mount=type=cache,target=/build/.dub,sharing=locked \
    --mount=type=cache,target=/root/.dub,sharing=locked \
    if [ "$CACHE_BUST" != "fixed" ]; then \
        DUB_FLAGS="--force" && \
        echo "dub cache busted (CACHE_BUST=$CACHE_BUST)" ; \
    else \
        DUB_FLAGS="" ; \
    fi && \
    dub build --root=engine --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    dub build --root=engine --config=janitor-migrate --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    dub build --root=engine --config=ircfiber-default-migrate --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    cp engine/irc-fiber-engine ./irc-fiber-engine && \
    cp engine/janitor-migrate ./janitor-migrate && \
    cp engine/ircfiber-default-migrate ./ircfiber-default-migrate 2>/dev/null || true && \
    test -f ./irc-fiber-engine && \
    test -f ./janitor-migrate
RUN find . -maxdepth 1 -type f -executable -exec strip {} +; find engine -maxdepth 2 -type f -executable -exec strip {} + 2>/dev/null; true

# ============================================================================
# Stage: builder — aggregate for `--target builder` extraction deploys
# (deploy-update.yml / deploy-handoff.yml / deploy-update-exec.yml docker cp
# /build/{irc-fiber,irc-fiber-engine,janitor-migrate,ircfiber-default-migrate}).
#
# Runtime-only inputs — copied AFTER the dub builds so frontend asset or
# config changes never invalidate the D compile. `public/dist` is rewritten
# on every `make frontend` (content-hashed bundles) and `config/` on deploy
# tweaks; keeping these before the RUN forced a full 6-config dub rebuild
# on every frontend-only change.
# ============================================================================
FROM base AS builder

COPY --from=builder-backend /build/irc-fiber            /build/
COPY --from=builder-backend /build/irc-fiber-gateway    /build/
COPY --from=builder-backend /build/views                /build/views
COPY --from=builder-engine  /build/irc-fiber-engine     /build/
COPY --from=builder-engine  /build/janitor-migrate      /build/
COPY --from=builder-engine  /build/ircfiber-default-migrate /build/
COPY config/ ./config/
COPY public/ ./public/

RUN test -f ./irc-fiber && \
    test -f ./irc-fiber-engine && \
    test -f ./janitor-migrate

# ============================================================================
# Stage: frontend-builder — vite build on server (avoids iCloud Mobile Documents hang)
# The local `make frontend-build` does `vite build` on the Mac, which hangs
# when the repo lives inside `~/Library/Mobile Documents` (bird sync).
# Building the frontend inside the container avoids iCloud entirely:
# the build context is sent via `rsync` to `/opt/ircfiber-src` and then
# `docker build` runs `vite build` inside the Linux container where
# `public/dist` is a normal ext4 directory.
# ============================================================================
FROM node:20-bookworm AS frontend-builder
ARG CACHE_BUST=fixed
ARG GIT_HASH=unknown
ARG GIT_SHORT=unknown
ARG GIT_DESCRIBE=unknown
COPY <<EOF ./frontend/.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF
WORKDIR /build
# Leverage Docker layer cache: copy package files first, then npm ci
COPY frontend/package.json frontend/package-lock.json frontend/bun.lock* frontend/tsconfig.json frontend/svelte.config.js frontend/vite.config.ts frontend/index.html frontend/admin.html frontend/inject-manifest.js ./frontend/
COPY frontend/src ./frontend/src/
COPY frontend/wasm-img2irc ./frontend/wasm-img2irc/
COPY public/ ./public/
COPY backend/views/ ./backend/views/
RUN if [ "$GIT_HASH" != "unknown" ] && [ "$GIT_HASH" != "" ]; then \
      echo "frontend-builder: using GIT_HASH=$GIT_HASH"; \
      mkdir -p frontend/src/lib; \
      printf '// Generated via Docker build-arg GIT_HASH=%s\n' "$GIT_HASH" > frontend/src/lib/buildInfo.ts; \
      printf 'export const BUILD_INFO = {\n' >> frontend/src/lib/buildInfo.ts; \
      printf '  commit: "%s",\n' "$GIT_HASH" >> frontend/src/lib/buildInfo.ts; \
      printf '  short: "%s",\n' "${GIT_SHORT:-$GIT_HASH}" >> frontend/src/lib/buildInfo.ts; \
      printf '  describe: "%s",\n' "${GIT_DESCRIBE:-$GIT_SHORT}" >> frontend/src/lib/buildInfo.ts; \
      printf '  branch: "unknown",\n' >> frontend/src/lib/buildInfo.ts; \
      printf '  builtAt: "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> frontend/src/lib/buildInfo.ts; \
      printf '  builtHost: "docker-builder",\n' >> frontend/src/lib/buildInfo.ts; \
      printf '  version: "0.3.0",\n' >> frontend/src/lib/buildInfo.ts; \
      printf '  message: "via build-arg",\n' >> frontend/src/lib/buildInfo.ts; \
      printf '  commitUrl: "https://github.com/kevinpostal/IRC_FIBER/commit/%s",\n' "$GIT_HASH" >> frontend/src/lib/buildInfo.ts; \
      printf '} as const;\n' >> frontend/src/lib/buildInfo.ts; \
      cat frontend/src/lib/buildInfo.ts; \
    fi
RUN cd frontend && npm ci --ignore-scripts 2>&1 | tail -5 && npm run build 2>&1 | tail -20 && node inject-manifest.js 2>&1 | tail -5 && ls -lh ../public/dist/assets/ 2>&1 | tail -5

# ============================================================================
# Stage: runtime — slim Ubuntu + all binaries (legacy combined image)
# ============================================================================
FROM ubuntu:22.04 AS runtime

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        zlib1g \
        curl \
        procps \
        ca-certificates \
        tini \
        util-linux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/irc-fiber             /app/
COPY --from=builder /build/irc-fiber-engine      /app/
COPY --from=builder /build/janitor-migrate       /app/
COPY --from=builder /build/views                 /app/views
COPY --from=builder /build/config                /app/config
COPY --from=builder /build/public                /app/public

# Data dirs.
RUN mkdir -p /app/data /app/uploads

EXPOSE 8090

# Operator scripts — the engine entrypoint enforces clean container
# state (kills stale handoff processes, removes stale markers, waits
# for holder socket) so multiple deploys in a row can't accumulate
# zombie binaries. The healthcheck verifies the engine process is
# alive without false negatives on transient handoff invocations.
COPY deploy/roles/engine/files/ircfiber-engine-entrypoint.sh /usr/local/bin/ircfiber-engine-entrypoint.sh
COPY deploy/roles/engine/files/ircfiber-engine-healthcheck.sh /usr/local/bin/ircfiber-engine-healthcheck.sh
RUN chmod 0755 /usr/local/bin/ircfiber-engine-entrypoint.sh \
              /usr/local/bin/ircfiber-engine-healthcheck.sh

# tini as init — prevents zombie processes and allows graceful
# handoff within a container. Without it, the engine runs as PID 1
# and exit(0) kills the entire container, defeating SCM_RIGHTS.
ENTRYPOINT ["/usr/bin/tini", "--"]

# ============================================================================
# Stage: runtime-gateway — slim Ubuntu + gateway binary only.
# COPYs come from builder-backend (never builder-engine), so building this
# target does NOT compile engine sources. config/public come from the build
# context so asset/config changes don't pull the aggregate `builder` stage.
# ============================================================================
FROM ubuntu:22.04 AS runtime-gateway

ARG CACHE_BUST=fixed
COPY <<EOF ./.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        zlib1g \
        curl \
        procps \
        ca-certificates \
        tini \
        util-linux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Gateway binary: accept either `irc-fiber` (default) or `irc-fiber-gateway`
# (both are the default-config binary today; the GatewayOnly config compile
# was dropped as dead work). Copy whichever exists.
COPY --from=builder-backend /build/irc-fiber-gateway /app/irc-fiber-gateway
COPY --from=builder-backend /build/irc-fiber /app/irc-fiber
COPY --from=builder-backend /build/views                 /app/views
COPY --from=frontend-builder /build/public ./public/
COPY --from=frontend-builder /build/backend/views ./views/
COPY config/ ./config/
# Data dirs.
RUN mkdir -p /app/data /app/uploads && \
    if [ -f /app/irc-fiber-gateway ] && [ ! -f /app/irc-fiber ]; then \
        cp /app/irc-fiber-gateway /app/irc-fiber; \
    fi; \
    if [ ! -f /app/irc-fiber ]; then echo "gateway binary missing" && exit 1; fi

EXPOSE 8090

ENTRYPOINT ["/usr/bin/tini", "--"]

# ============================================================================
# Stage: runtime-engine — slim Ubuntu + engine binary only (no views/public).
# COPYs come from builder-engine only — building this target never compiles
# backend sources.
# ============================================================================
FROM ubuntu:22.04 AS runtime-engine

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        zlib1g \
        curl \
        procps \
        ca-certificates \
        tini \
        util-linux && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder-engine /build/irc-fiber-engine      /app/irc-fiber-engine
COPY --from=builder-engine /build/janitor-migrate       /app/janitor-migrate
COPY config/ ./config/

# Data dirs (engine needs no public/views).
RUN mkdir -p /app/data /app/uploads

# Engine entrypoint + healthcheck
COPY deploy/roles/engine/files/ircfiber-engine-entrypoint.sh /usr/local/bin/ircfiber-engine-entrypoint.sh
COPY deploy/roles/engine/files/ircfiber-engine-healthcheck.sh /usr/local/bin/ircfiber-engine-healthcheck.sh
RUN chmod 0755 /usr/local/bin/ircfiber-engine-entrypoint.sh \
              /usr/local/bin/ircfiber-engine-healthcheck.sh

# tini as init — same rationale as runtime
ENTRYPOINT ["/usr/bin/tini", "--"]
