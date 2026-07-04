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

COPY dub.sdl dub.selections.json ./
COPY source/ ./source/
COPY views/  ./views/
COPY config/ ./config/
COPY public/ ./public/

ARG CACHE_BUST=0

# 4 sequential `dub build` calls inside one stage. Each dub invocation
# internally parallelizes LDC compile; the mount cache survives between
# runs and across `docker build` invocations.
RUN --mount=type=cache,target=/build/.dub \
    echo "build: $CACHE_BUST" && \
    dub build                --compiler=ldc2 --build=release --parallel && \
    dub build --config=engine --compiler=ldc2 --build=release --parallel && \
    dub build --config=conn-holder --compiler=ldc2 --build=release --parallel && \
    dub build --config=janitor-migrate --compiler=ldc2 --build=release --parallel && \
    test -f /build/irc-fiber && \
    test -f /build/irc-fiber-engine && \
    test -f /build/ircfiber-conn-holder && \
    test -f /build/janitor-migrate

# Single layer: strip all 4 binaries (one find instead of 4 RUNs).
RUN find /build -maxdepth 1 -type f -executable -exec strip {} +

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
COPY --from=builder /build/ircfiber-conn-holder  /app/
COPY --from=builder /build/janitor-migrate       /app/
COPY --from=builder /build/views                 /app/views
COPY --from=builder /build/config                /app/config
COPY --from=builder /build/public                /app/public

# Data + holder socket dirs.
RUN mkdir -p /app/data /app/uploads /var/run/ircfiber && \
    chmod 0755 /var/run/ircfiber

EXPOSE 8090

# tini as init — prevents zombie processes and allows graceful
# handoff within a container. Without it, the engine runs as PID 1
# and exit(0) kills the entire container, defeating SCM_RIGHTS.
ENTRYPOINT ["/usr/bin/tini", "--"]
