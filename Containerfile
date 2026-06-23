# syntax=docker/dockerfile:1.4
FROM ubuntu:22.04 AS builder

ARG LDC_VERSION=1.41.0
ARG TARGETARCH

RUN apt-get update && apt-get install -y \
    curl \
    xz-utils \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install LDC and Dub from official GitHub release
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64) LDC_ARCH=x86_64 ;; \
        aarch64) LDC_ARCH=aarch64 ;; \
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/ldc.tar.xz \
        "https://github.com/ldc-developers/ldc/releases/download/v${LDC_VERSION}/ldc2-${LDC_VERSION}-linux-${LDC_ARCH}.tar.xz" && \
    tar -xf /tmp/ldc.tar.xz -C /opt && \
    ln -s /opt/ldc2-${LDC_VERSION}-linux-${LDC_ARCH} /opt/ldc2 && \
    rm /tmp/ldc.tar.xz

ENV PATH="/opt/ldc2/bin:${PATH}"

WORKDIR /build

# Dependency caching layer
COPY dub.sdl dub.selections.json ./
RUN --mount=type=cache,target=/build/.dub dub fetch --cache=local || true

# Source and build — .dub/ preserved across builds via Docker cache mount
COPY source/ ./source/
COPY views/ ./views/
COPY config/ ./config/
COPY public/ ./public/

# Cache buster — ARG must be USED in the RUN command to invalidate.
# Without this, Docker serves the cached layer even when CACHE_BUST
# changes. The echo is stripped at build time, zero cost at runtime.
ARG CACHE_BUST=0

RUN --mount=type=cache,target=/build/.dub \
    echo "build: $CACHE_BUST" && \
    dub build --compiler=ldc2 --build=release --force --parallel 2>&1 | tail -5 && \
    test -f /build/irc-fiber

RUN --mount=type=cache,target=/build/.dub \
    echo "engine: $CACHE_BUST" && \
    dub build --config=engine --compiler=ldc2 --build=release --force --parallel 2>&1 | tail -5 && \
    test -f /build/irc-fiber-engine
RUN strip /build/irc-fiber 2>/dev/null || true
RUN strip /build/irc-fiber-engine 2>/dev/null || true

# Runtime stage
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    curl \
    procps \
    ca-certificates \
    tini \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/irc-fiber /app/
COPY --from=builder /build/irc-fiber-engine /app/
COPY --from=builder /build/views /app/views
COPY --from=builder /build/config /app/config
COPY --from=builder /build/public /app/public

# Create data directory for JSON fallback storage and uploads directory
RUN mkdir -p /app/data /app/uploads

EXPOSE 8090

# tini as init — prevents zombie processes and allows graceful
# handoff within a container. Without it, the engine runs as PID 1
# and exit(0) kills the entire container, defeating SCM_RIGHTS.
ENTRYPOINT ["/usr/bin/tini", "--"]
# Default command overridden in docker-compose/docker run.
