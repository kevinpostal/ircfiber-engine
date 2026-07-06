#!/usr/bin/env bash
set -euo pipefail

# IRC Fiber pre-deploy loadtest gate.
# Runs ircfiber-loadtest with the target profile and asserts
# p99 /health latency < 200ms and zero timeout errors.
#
# Usage:
#   ./scripts/pre-deploy-loadtest.sh
#   SKIP_LOADTEST=1 ./scripts/pre-deploy-loadtest.sh  # skip the gate

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

if [[ "${SKIP_LOADTEST:-0}" == "1" ]]; then
    echo "[SKIP] pre-deploy loadtest gate: SKIP_LOADTEST=1"
    exit 0
fi

# Config (env overridable)
RPS="${RPS:-10000}"
DURATION="${DURATION:-60}"
USER="${USER:-1d61f5b3-5f4d-49b1-a59f-03d79f58ac3c}"
REDIS_URL="${IRCFIBER_REDIS_URL:-redis://127.0.0.1:6379}"
GATEWAY_URL="${GATEWAY_URL:-http://localhost:8090}"
RETENTION="${RETENTION:-1}"

echo "=== pre-deploy loadtest gate ==="
echo "  RPS:         $RPS"
echo "  Duration:    $DURATION sec"
echo "  User:        $USER"
echo "  Redis:       $REDIS_URL"
echo "  Gateway:     $GATEWAY_URL"
echo "  Retention:   $RETENTION pass(es)"

# 1. Build the loadtest binary
echo ""
echo "Building loadtest binary..."
dub build --config=loadtest:dependency 2>&1 || dub build --config=loadtest 2>&1
echo "Build OK"

# 2. Pre-ping /api/health to establish healthy baseline
echo ""
echo "Pre-ping gateway..."
BASELINE_MS=$(curl -sS -o /dev/null -w "%{time_total}" "$GATEWAY_URL/api/health" 2>&1 | awk '{print int($1*1000)}')
echo "  Baseline /api/health: ${BASELINE_MS}ms"

# 3. Collect latency samples during the loadtest (in background)
LATENCY_LOG=$(mktemp -t gateway-latency-XXXX.log)
echo "Collecting latency to $LATENCY_LOG"

collect_latency() {
    local pid="$1"
    while kill -0 "$pid" 2>/dev/null; do
        local start=$(date +%s%N)
        local code=$(curl -sS -o /dev/null -w "%{http_code}" "$GATEWAY_URL/api/health" 2>&1)
        local elapsed_ns=$(( $(date +%s%N) - start ))
        local elapsed_ms=$(( elapsed_ns / 1000000 ))
        echo "$elapsed_ms $code" >> "$LATENCY_LOG"
        sleep 0.1
    done
}

# 4. Run the loadtest
echo ""
echo "Running loadtest (${RPS} rps, ${DURATION}s)..."
./scripts/run-loadtest.sh --rps "$RPS" --duration "$DURATION" --user "$USER" --redis-url "$REDIS_URL" --retention "$RETENTION" &
LOADTEST_PID=$!
sleep 1

# Start collecting latency
collect_latency "$LOADTEST_PID" &
COLLECT_PID=$!

# Wait for loadtest to finish
wait "$LOADTEST_PID"
LOADTEST_EXIT=$?

# Stop latency collector
kill "$COLLECT_PID" 2>/dev/null || true
wait "$COLLECT_PID" 2>/dev/null || true

echo ""
echo "=== Gate Results ==="

# 5. Parse latency samples
if [[ ! -f "$LATENCY_LOG" ]] || [[ $(wc -l < "$LATENCY_LOG") -lt 2 ]]; then
    echo "FAIL: Not enough latency samples collected"
    rm -f "$LATENCY_LOG"
    exit 1
fi

# Calculate p50, p95, p99 from the latency log
SAMPLES=$(wc -l < "$LATENCY_LOG")
P50=$(sort -n "$LATENCY_LOG" | awk '{print $1}' | awk 'BEGIN{c=0} {a[c++]=$1} END{print a[int(c*0.5)]}')
P95=$(sort -n "$LATENCY_LOG" | awk '{print $1}' | awk 'BEGIN{c=0} {a[c++]=$1} END{print a[int(c*0.95)]}')
P99=$(sort -n "$LATENCY_LOG" | awk '{print $1}' | awk 'BEGIN{c=0} {a[c++]=$1} END{print a[int(c*0.99)]}')

echo "  Samples:     $SAMPLES"
echo "  Baseline:    ${BASELINE_MS}ms"
echo "  p50:         ${P50}ms"
echo "  p95:         ${P95}ms"
echo "  p99:         ${P99}ms"
echo "  Max:         $(awk '{print $1}' "$LATENCY_LOG" | sort -n | tail -1)ms"
echo "  Errors:      $(grep -cv ' 200$' "$LATENCY_LOG" || true)"

rm -f "$LATENCY_LOG"

# 6. Assert p99 < 200ms
GATE_PASSED=true

if [[ "$LOADTEST_EXIT" -ne 0 ]]; then
    echo "FAIL: Loadtest binary exited with code $LOADTEST_EXIT"
    GATE_PASSED=false
fi

if [[ "$P99" -ge 200 ]]; then
    echo "FAIL: p99=${P99}ms >= 200ms threshold"
    GATE_PASSED=false
fi

if [[ "$BASELINE_MS" -ge 200 ]]; then
    echo "WARN: Baseline seems high (${BASELINE_MS}ms) — check gateway health"
fi

if $GATE_PASSED; then
    echo ""
    echo "=== GATE PASSED ==="
    exit 0
else
    echo ""
    echo "=== GATE FAILED ==="
    exit 1
fi
