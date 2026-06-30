#!/bin/bash
# Build Connection Holder on OVH (Linux x86_64) using Docker BuildKit.
# This is the CORRECT approach — local Mac ARM64 binaries won't run on Linux.

set -e
OVH="deploy@40.160.227.49"
ENGINE_ID="ovh"
HOLDER_CONTAINER="ircfiber-holder-${ENGINE_ID}"
VOLUME_NAME="ircfiber-holder-sockets-${ENGINE_ID}"
SRC_DIR="/opt/ircfiber-src"

echo "=== Sync source to OVH ==="
ssh $OVH "mkdir -p ${SRC_DIR}"
rsync -az --delete \
    --exclude='.git' \
    --exclude='node_modules' \
    --exclude='.dub' \
    --exclude='*.o' \
    --exclude='irc-fiber' \
    --exclude='irc-fiber-engine' \
    --exclude='ircfiber-conn-holder' \
    --exclude='frontend/node_modules' \
    --exclude='public/dist' \
    --exclude='*.log' \
    --exclude='.worktrees' \
    --exclude='.reasonix' \
    --exclude='.playwright-mcp' \
    --exclude='test-results' \
    --exclude='e2e/test-results' \
    "$(dirname "$0")/../" \
    "${OVH}:${SRC_DIR}/"

echo ""
echo "=== Build via BuildKit (on remote — produces Linux x86_64 binaries) ==="
ssh $OVH bash << EOF
set -e
cd ${SRC_DIR}
echo "Building..."
DOCKER_BUILDKIT=1 docker build \
    --target builder \
    --build-arg LDC_VERSION=1.41.0 \
    --build-arg CACHE_BUST=\$(date +%s) \
    -t ircfiber-builder:latest \
    -f Containerfile . 2>&1 | tail -10

echo ""
echo "Extracting binaries..."
mkdir -p /opt/ircfiber/bin
CID=\$(docker create ircfiber-builder:latest)
docker cp "\$CID":/build/irc-fiber-engine /opt/ircfiber/bin/irc-fiber-engine-new
docker cp "\$CID":/build/ircfiber-conn-holder /opt/ircfiber/bin/ircfiber-conn-holder
docker rm "\$CID" > /dev/null

chmod +x /opt/ircfiber/bin/irc-fiber-engine-new /opt/ircfiber/bin/ircfiber-conn-holder
strip /opt/ircfiber/bin/ircfiber-conn-holder 2>/dev/null || true

echo ""
echo "Built binaries:"
ls -lh /opt/ircfiber/bin/
file /opt/ircfiber/bin/ircfiber-conn-holder
file /opt/ircfiber/bin/irc-fiber-engine-new
EOF

echo ""
echo "=== Build image with both binaries ==="
ssh $OVH bash << 'EOF'
set -e
# Get the current engine image
ENGINE_IMAGE=$(docker ps --filter name=ircfiber-engine-ovh --format '{{.Image}}' | head -1)
[ -z "$ENGINE_IMAGE" ] && ENGINE_IMAGE="kevindpostal/ircfiber-engine:0.3.0"
echo "Base engine image: $ENGINE_IMAGE"

# Commit a new image that includes the holder binary
docker create --name temp-builder --entrypoint /bin/true "$ENGINE_IMAGE"
docker cp /opt/ircfiber/bin/ircfiber-conn-holder temp-builder:/app/ircfiber-conn-holder
docker commit temp-builder ircfiber-engine-with-holder:latest
docker rm temp-builder

docker images | grep ircfiber-engine-with-holder
EOF

echo ""
echo "=== Setup holder shared volume ==="
ssh $OVH "docker volume create ${VOLUME_NAME} 2>/dev/null || true; docker volume ls | grep ${VOLUME_NAME}"

echo ""
echo "=== Stop existing engine ==="
ssh $OVH "docker stop ircfiber-engine-ovh 2>/dev/null || true; docker rm ircfiber-engine-ovh 2>/dev/null || true; echo engine removed"

echo ""
echo "=== Start holder container ==="
ssh $OVH bash << EOF
set -e
docker stop ${HOLDER_CONTAINER} 2>/dev/null || true
docker rm ${HOLDER_CONTAINER} 2>/dev/null || true

docker run -d \
    --name ${HOLDER_CONTAINER} \
    --restart unless-stopped \
    --init \
    --ulimit nofile=65536:65536 \
    --network ircfiber_net \
    -v ${VOLUME_NAME}:/var/run/ircfiber \
    -e IRCFIBER_HOLDER_SOCK=/var/run/ircfiber/holder.sock \
    -e IRCFIBER_HOLDER_HEALTH_SOCK=/var/run/ircfiber/holder-health.sock \
    -e IRCFIBER_HOLDER_QUIT_MSG="ircfiber holder shutting down" \
    --label ircfiber.component=holder \
    --entrypoint /app/ircfiber-conn-holder \
    ircfiber-engine-with-holder:latest

sleep 2

echo ""
echo "Container status:"
docker ps --filter name=${HOLDER_CONTAINER}

echo ""
echo "Container logs:"
docker logs --tail 15 ${HOLDER_CONTAINER}
EOF

echo ""
echo "=== Verify holder health ==="
ssh $OVH bash << EOF
sleep 2
docker exec ${HOLDER_CONTAINER} sh -c '
if [ ! -S /var/run/ircfiber/holder-health.sock ]; then
    echo "FAIL: health socket not created"
    exit 1
fi
echo "Health socket: OK"

echo ""
echo "/healthz:"
curl -fsS --unix-socket /var/run/ircfiber/holder-health.sock http://localhost/healthz || echo "(healthz failed)"

echo ""
echo "/metrics (peers):"
curl -fsS --unix-socket /var/run/ircfiber/holder-health.sock http://localhost/metrics 2>/dev/null | grep -E "peers|connections|up" || echo "(metrics unavailable)"
'
EOF

echo ""
echo "=== Start engine with holder mode ==="
ssh $OVH bash << EOF
set -e
# Get the original engine env vars
ORIG_ENV=\$(docker run --rm ircfiber-engine-with-holder:latest env | grep -v PATH | tr '\n' ',' | sed 's/,$//')
echo "Container env captured"

# Use docker run with explicit env vars from the existing deployment
docker run -d \
    --name ircfiber-engine-ovh \
    --restart unless-stopped \
    --init \
    --network ircfiber_net \
    -v ${VOLUME_NAME}:/var/run/ircfiber:ro \
    -e IRCFIBER_SERVER_ID=ovh \
    -e IRCFIBER_BIND_ADDRESS=0.0.0.0 \
    -e IRCFIBER_ADMIN_PORT=8091 \
    -e IRCFIBER_LOG_LEVEL=info \
    -e IRCFIBER_MONGO_URL='mongodb://ircfiber:jqgwEv3GJwwizulaj3Fnbd8imqcMH4Gh@100.126.197.92:27017/ircfiber' \
    -e IRCFIBER_REDIS_URL='redis://100.126.197.92:6379/0' \
    -e IRCFIBER_HOLDER_SOCK=/var/run/ircfiber/holder.sock \
    --label ircfiber.component=engine \
    --entrypoint /app/irc-fiber-engine \
    ircfiber-engine-with-holder:latest

sleep 5
echo ""
echo "Container status:"
docker ps --filter name=ircfiber-engine-ovh

echo ""
echo "Engine logs (last 30 lines):"
docker logs --tail 30 ircfiber-engine-ovh 2>&1 || echo "(no logs yet)"
EOF

echo ""
echo "=== Verify holder sees engine peer ==="
ssh $OVH bash << EOF
sleep 3
echo "-- peers/connections from /metrics --"
docker exec ${HOLDER_CONTAINER} sh -c '
curl -fsS --unix-socket /var/run/ircfiber/holder-health.sock http://localhost/metrics 2>/dev/null | grep -E "peers|connections|up"
'
EOF

echo ""
echo "=== Done ==="
echo ""
echo "  Holder: ${HOLDER_CONTAINER} (long-lived, owns IRC sockets)"
echo "  Engine: ircfiber-engine-ovh (exec-reloadable, uses holder)"
echo ""
echo "To test zero-disconnect hot-reload:"
echo "  ssh deploy@40.160.227.49"
echo "  redis-cli LPUSH irc:control:ovh '{\"action\":\"beginExecReload\"...}'"
echo ""
echo "To verify via metrics:"
echo "  ssh deploy@40.160.227.49 'curl --unix-socket /var/run/ircfiber/holder-health.sock http://localhost/metrics'"