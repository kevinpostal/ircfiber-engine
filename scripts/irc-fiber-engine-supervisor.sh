#!/usr/bin/env bash
# ============================================================================
# irc-fiber-engine-supervisor.sh
#
# Runs the irc-fiber-engine in a restart loop with crash persistence.
# Any non-zero exit code triggers a crash dump to ~/.ircfiber/crashes/
# for later diagnosis. Clean exits (SIGTERM via `make engine-restart`)
# restart without a crash dump.
#
# Behaviour:
#   - Launches the engine binary and monitors its exit code.
#   - On crash (exit != 0): writes a timestamped crash dump with log tail,
#     git hash, binary metadata, and error context.
#   - Restarts the engine on any exit, with exponential backoff.
#   - On SIGTERM/SIGINT to the supervisor itself, stops cleanly.
#   - Retains the last 50 crash dumps, prunes the rest.
#   - Does NOT clear the engine log — append only.
#
# Env vars (all optional, sensible defaults):
#   ENGINE_BIN             Path to engine binary (default: ./irc-fiber-engine)
#   SUPERVISOR_PIDFILE     PID file for this supervisor (default: /tmp/...)
#   ENGINE_PIDFILE         PID file for the engine (default: /tmp/...)
#   ENGINE_LOGFILE         Where engine writes stdout+stderr (default: /tmp/...)
#   SUPERVISOR_LOGFILE     Where supervisor logs its own events (default: /tmp/...)
#   CRASH_DIR              Persistent crash dump directory
#                          (default: ~/.ircfiber/crashes/)
# ============================================================================
set -u

ENGINE_BIN="${ENGINE_BIN:-./irc-fiber-engine}"
PIDFILE="${SUPERVISOR_PIDFILE:-/tmp/irc-fiber-engine-supervisor.pid}"
ENGINE_PIDFILE="${ENGINE_PIDFILE:-/tmp/irc-fiber-engine.pid}"
ENGINE_LOGFILE="${ENGINE_LOGFILE:-/tmp/irc-fiber-engine.log}"
SUPERVISOR_LOGFILE="${SUPERVISOR_LOGFILE:-/tmp/irc-fiber-engine.supervisor.log}"
CRASH_DIR="${CRASH_DIR:-$HOME/.ircfiber/crashes/}"
BACKOFF_SECONDS=2
MAX_BACKOFF_SECONDS=30
MAX_CRASH_DUMPS=50
DUMP_LOG_LINES=200
DUMP_ERROR_LINES=50

# ── Helpers ─────────────────────────────────────────────────────────────────

log() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    printf '[supervisor %s] %s\n' "$ts" "$*" | tee -a "$SUPERVISOR_LOGFILE"
}

stop_engine() {
    if [[ -f "$ENGINE_PIDFILE" ]]; then
        local pid
        pid="$(cat "$ENGINE_PIDFILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            log "Stopping engine (pid=$pid)"
            kill "$pid" 2>/dev/null || true
            # Wait up to 5s for graceful shutdown
            for _ in 1 2 3 4 5; do
                kill -0 "$pid" 2>/dev/null || break
                sleep 1
            done
            kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$ENGINE_PIDFILE"
    fi
    pkill -f "$ENGINE_BIN" 2>/dev/null || true
}

# ── Crash dump writer ───────────────────────────────────────────────────────
# Writes a structured crash dump to $CRASH_DIR when the engine exits with a
# non-zero code. Captures timestamp, git hash, exit code, log tail, and any
# ERROR/exception lines from the engine log.
write_crash_dump() {
    local rc=$1
    local ts_name
    ts_name="$(date '+%Y%m%d-%H%M%S')"
    mkdir -p "$CRASH_DIR"

    local dumpfile="${CRASH_DIR}crash-${ts_name}-exit${rc}.txt"
    local bin_mtime
    bin_mtime=$(stat -f '%Sm' "$ENGINE_BIN" 2>/dev/null || echo 'unknown')
    local git_hash
    git_hash=$(git -C "$(dirname "$ENGINE_BIN")" rev-parse --short HEAD 2>/dev/null || echo 'unknown')

    {
        echo "============================================"
        echo "  IRC Fiber Engine Crash Dump"
        echo "============================================"
        echo ""
        echo "  Exit code:       $rc"
        echo "  Timestamp:       $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "  Server ID:       ${IRCFIBER_SERVER_ID:-unknown}"
        echo "  Git commit:      $git_hash"
        echo "  Engine binary:   $(cd "$(dirname "$ENGINE_BIN")" 2>/dev/null && pwd)/$(basename "$ENGINE_BIN")"
        echo "  Binary modified: $bin_mtime"
        echo "  Engine log:      $ENGINE_LOGFILE"
        echo "  Restart count:   ${RESTART_COUNT:-0}"
        echo "  Backoff:         ${CURRENT_BACKOFF:-2}s"
        echo ""
        echo "--- Last $DUMP_LOG_LINES lines of engine log ($ENGINE_LOGFILE) ---"
        tail -"$DUMP_LOG_LINES" "$ENGINE_LOGFILE" 2>/dev/null || echo "(engine log not found)"
        echo ""
        echo "--- Error / Exception / Signal lines ---"
        grep -E -i "error|exception|abort|segfault|signal|core.?dump|panic|SIGSEGV|SIGABRT|SIGTERM|SIGINT|terminate|stack.?trace" \
            "$ENGINE_LOGFILE" 2>/dev/null | tail -"$DUMP_ERROR_LINES" \
            || echo "(none found)"
        echo ""
        echo "--- End of crash dump ---"
    } > "$dumpfile"

    log "CRASH: exit=$rc — dump written to $dumpfile ($(wc -c < "$dumpfile") bytes)"

    # Prune old crash dumps (keep newest MAX_CRASH_DUMPS)
    local count=0
    for f in "$CRASH_DIR"crash-*.txt; do
        [ -f "$f" ] && count=$((count + 1))
    done
    if [ "$count" -gt "$MAX_CRASH_DUMPS" ]; then
        local prune=$((count - MAX_CRASH_DUMPS))
        ls -t "$CRASH_DIR"crash-*.txt 2>/dev/null | tail -"$prune" | while read -r old; do
            rm -f "$old"
        done
        log "Pruned $prune old crash dumps (max $MAX_CRASH_DUMPS)"
    fi
}

# ── Signal handling ─────────────────────────────────────────────────────────
# SIGTERM/SIGINT to the SUPERVISOR itself = graceful shutdown of the whole
# stack. The supervisor kills the engine and exits 0.
trap 'log "Supervisor received signal, shutting down"; stop_engine; rm -f "$PIDFILE"; exit 0' INT TERM

# ── Supervisor start ────────────────────────────────────────────────────────

# Refuse double-start
if [[ -f "$PIDFILE" ]]; then
    existing="$(cat "$PIDFILE" 2>/dev/null || true)"
    if [[ -n "$existing" ]] && kill -0 "$existing" 2>/dev/null; then
        echo "Supervisor already running (pid=$existing). Refusing to start." >&2
        exit 1
    fi
    rm -f "$PIDFILE"
fi

echo "$$" > "$PIDFILE"
log "Starting engine supervisor (pid=$$)"
log "Env: MONGO=${IRCFIBER_MONGO_URL:-mongodb://127.0.0.1:27017/ircfiber} REDIS=${IRCFIBER_REDIS_URL:-redis://127.0.0.1:6379/0} SERVER_ID=${IRCFIBER_SERVER_ID:-localengine} BIND=${IRCFIBER_BIND_ADDRESS:-127.0.0.1}"
log "Crash dumps go to: $CRASH_DIR"

if [[ ! -x "$ENGINE_BIN" ]]; then
    log "Engine binary $ENGINE_BIN not found or not executable. Sleeping 30s then retrying."
    sleep 30
fi

# Rotate old engine log at supervisor startup only (preserve the previous
# session's log for analysis, start fresh for this session).
if [ -f "$ENGINE_LOGFILE" ] && [ -s "$ENGINE_LOGFILE" ]; then
    rotated="${ENGINE_LOGFILE}.$(date '+%Y%m%d-%H%M%S')"
    cp "$ENGINE_LOGFILE" "$rotated" 2>/dev/null || true
    : > "$ENGINE_LOGFILE"
    log "Rotated previous engine log to $rotated"
fi

# ── Main loop ───────────────────────────────────────────────────────────────
RESTART_COUNT=0
CURRENT_BACKOFF=$BACKOFF_SECONDS

while true; do
    if [[ ! -x "$ENGINE_BIN" ]]; then
        log "Engine binary $ENGINE_BIN not found. Sleeping 30s."
        sleep 30
        continue
    fi

    log "Launching $ENGINE_BIN"
    "$ENGINE_BIN" >> "$ENGINE_LOGFILE" 2>&1 &
    engine_pid=$!
    echo "$engine_pid" > "$ENGINE_PIDFILE"
    log "Engine started (pid=$engine_pid)"

    # Wait for engine to exit (any exit code triggers a restart)
    set +e
    wait "$engine_pid"
    rc=$?
    set -e
    RESTART_COUNT=$((RESTART_COUNT + 1))

    if [ "$rc" -ne 0 ]; then
        # Non-zero exit = crash. Write a persistent crash dump.
        CURRENT_BACKOFF=$((CURRENT_BACKOFF * 2))
        [ "$CURRENT_BACKOFF" -gt "$MAX_BACKOFF_SECONDS" ] && CURRENT_BACKOFF=$MAX_BACKOFF_SECONDS
        write_crash_dump "$rc"
        log "CRASH: exit=$rc (restart #$RESTART_COUNT). Backoff ${CURRENT_BACKOFF}s."
    else
        # Zero exit = clean shutdown (e.g. `make engine-restart`).
        # Reset backoff since this was intentional.
        CURRENT_BACKOFF=$BACKOFF_SECONDS
        log "Clean stop: exit=$rc (restart #$RESTART_COUNT). Backoff reset."
    fi

    rm -f "$ENGINE_PIDFILE"
    sleep "$CURRENT_BACKOFF"
    log "Restarting engine..."
done

# (unreachable — trap handles shutdown)
stop_engine
rm -f "$PIDFILE"
log "Supervisor exiting"
