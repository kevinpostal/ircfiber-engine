# syntax=docker/dockerfile:1.7
#
# IRC Fiber build pipeline (BuildKit)
# ===================================
#
# Stage graph:
#   base    : Ubuntu 22.04 + LDC toolchain (apt cache mounted)
#   builder : dub build of all 4 release configs in one stage
#             - /build/.dub mounted as cache so dep fetch + module builds
#               survive across builds.
#             - `dub build --parallel` parallelizes LDC compile jobs inside
#               each config; without `--force` dub keeps its incremental
#               module cache between configs so editing one binary
#               recompiles only that binary.
#   runtime : slim Ubuntu + 4 stripped binaries
#
# Cache invalidation:
#   - LDC_VERSION, ARG TARGETARCH, Dockerfile changes invalidate `base`.
#   - dub.sdl / dub.selections.json changes re-run `dub upgrade`.
#   - source/ changes re-run `dub build` (but dub only recompiles changed
#     modules thanks to the /build/.dub cache).
#   - `CACHE_BUST=<n> --build-arg` (default 0) forces a clean rebuild of
#     the builder stage when needed.

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
# Stage: builder — compile all 4 release binaries
#
# `dub build --parallel` parallelizes LDC compile jobs within a config
# (dub-1.x dispatches independent modules to parallel LDC invocations).
# Without `--force`, dub reuses incremental module cache between the 4
# configs so editing one binary recompiles only that binary — /build/.dub
# is mounted as cache so this even survives `docker build` cache wipes.
#
# CACHE_BUST default 0; pass `docker build --build-arg CACHE_BUST=$(date +%s)`
# to force a clean rebuild of the dub steps.
# ============================================================================
FROM base AS builder

# ── Build cache invalidation ─────────────────────────────────────────────
# Same sentinel trick as before, but now one sentinel per package so editing
# `backend/source/api/rest.d` does not force-rebuild the engine and vice versa.
# Each heredoc writes inside its package's source tree, invalidating the
# matching COPY below.
ARG CACHE_BUST=fixed
COPY <<EOF ./common/source/.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF
COPY <<EOF ./backend/source/.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF
COPY <<EOF ./engine/source/.cache_bust_$CACHE_BUST
bust=$CACHE_BUST
EOF

COPY common/dub.sdl common/dub.selections.json ./common/
COPY common/source/ ./common/source/
COPY backend/dub.sdl backend/dub.selections.json ./backend/
COPY backend/source/ ./backend/source/
COPY backend/views/  ./backend/views/
COPY engine/dub.sdl engine/dub.selections.json ./engine/
COPY engine/source/ ./engine/source/
COPY config/ ./config/
COPY public/ ./public/

# When CACHE_BUST is non-default, nuke ALL caches dub/LDC might use:
# - /build/.dub (dub's global cache)
# - */dub-cache.json + *.o (per-package incremental state)
# - /root/.dub (dub's user-level cache from dub's $HOME)
# Then pass `--force` to dub to skip its own mtime/size checks.
RUN --mount=type=cache,target=/build/.dub,sharing=locked \
    --mount=type=cache,target=/root/.dub,sharing=locked \
    if [ "$CACHE_BUST" != "fixed" ]; then \
        rm -rf /build/.dub /root/.dub && \
        find common/source backend/source engine/source -name '*.o' -delete 2>/dev/null && \
        find common backend engine -name 'dub-cache.json' -delete 2>/dev/null && \
        DUB_FLAGS="--force" && \
        echo "dub cache busted (CACHE_BUST=$CACHE_BUST)" ; \
    else \
        DUB_FLAGS="" ; \
    fi && \
    echo "build: $CACHE_BUST" && \
    dub build --root=common --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    dub build --root=backend --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    dub build --root=backend --config=gateway --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    dub build --root=engine --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    dub build --root=engine --config=janitor-migrate --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    dub build --root=engine --config=ircfiber-default-migrate --compiler=ldc2 --build=release --parallel $DUB_FLAGS && \
    cp backend/irc-fiber ./irc-fiber && \
    cp backend/irc-fiber ./irc-fiber-gateway && \
    cp engine/irc-fiber-engine ./irc-fiber-engine && \
    cp engine/janitor-migrate ./janitor-migrate && \
    cp engine/ircfiber-default-migrate ./ircfiber-default-migrate 2>/dev/null || true && \
    cp -r backend/views ./views && \
    test -f ./irc-fiber && \
    test -f ./irc-fiber-engine && \
    test -f ./janitor-migrate
RUN find . -maxdepth 1 -type f -executable -exec strip {} +; find backend engine -maxdepth 2 -type f -executable -exec strip {} + 2>/dev/null; true

# ============================================================================
# Stage: runtime — slim Ubuntu + 4 binaries
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
# Stage: runtime-gateway — slim Ubuntu + gateway binary only
# ============================================================================
FROM ubuntu:22.04 AS runtime-gateway

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

# Gateway binary: accept either `irc-fiber` (legacy default) or `irc-fiber-gateway` (new).
# The builder produces both names depending on config; copy whichever exists.
# Use wildcard COPY with fallback: `irc-fiber-gateway` preferred for split builds.
COPY --from=builder /build/irc-fiber-gateway /app/irc-fiber-gateway
COPY --from=builder /build/irc-fiber /app/irc-fiber
COPY --from=builder /build/views                 /app/views
COPY --from=builder /build/config                /app/config
COPY --from=builder /build/public                /app/public

# Data dirs.
RUN mkdir -p /app/data /app/uploads && \
    if [ -f /app/irc-fiber-gateway ] && [ ! -f /app/irc-fiber ]; then \
        cp /app/irc-fiber-gateway /app/irc-fiber; \
    fi; \
    if [ ! -f /app/irc-fiber ]; then echo "gateway binary missing" && exit 1; fi

EXPOSE 8090

ENTRYPOINT ["/usr/bin/tini", "--"]

# ============================================================================
# Stage: runtime-engine — slim Ubuntu + engine binary only (no views/public)
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

COPY --from=builder /build/irc-fiber-engine      /app/irc-fiber-engine
COPY --from=builder /build/janitor-migrate       /app/janitor-migrate
COPY --from=builder /build/config                /app/config

# Data dirs (engine needs no public/views).
RUN mkdir -p /app/data /app/uploads

# Engine entrypoint + healthcheck
COPY deploy/roles/engine/files/ircfiber-engine-entrypoint.sh /usr/local/bin/ircfiber-engine-entrypoint.sh
COPY deploy/roles/engine/files/ircfiber-engine-healthcheck.sh /usr/local/bin/ircfiber-engine-healthcheck.sh
RUN chmod 0755 /usr/local/bin/ircfiber-engine-entrypoint.sh \
              /usr/local/bin/ircfiber-engine-healthcheck.sh

# tini as init — same rationale as runtime
ENTRYPOINT ["/usr/bin/tini", "--"]
