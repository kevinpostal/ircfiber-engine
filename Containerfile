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
RUN dub fetch --cache=local || true

# Source and build
COPY source/ ./source/
COPY views/ ./views/
COPY config/ ./config/
COPY public/ ./public/

RUN dub build --compiler=ldc2 --build=release --force --parallel
RUN dub build --config=engine --compiler=ldc2 --build=release --force --parallel
RUN strip /build/irc-fiber
RUN strip /build/irc-fiber-engine

# Runtime stage
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libssl3 \
    zlib1g \
    curl \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/irc-fiber /app/
COPY --from=builder /build/irc-fiber-engine /app/
COPY --from=builder /build/views /app/views
COPY --from=builder /build/config /app/config
COPY --from=builder /build/public /app/public

# Create data directory for JSON fallback storage
RUN mkdir -p /app/data

EXPOSE 8090

# No default entrypoint; command set in docker-compose
