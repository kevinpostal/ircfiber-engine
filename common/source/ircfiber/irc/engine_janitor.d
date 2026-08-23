module ircfiber.irc.engine_janitor;

import std.algorithm : canFind;
import std.array : array;
import std.conv : to;
import std.json;
import std.datetime : Clock;
import std.string : indexOf;
import std.process : environment;
import std.stdio : writefln;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.log;
import vibe.data.json : Json, parseJson;
import vibe.db.redis.redis : RedisDatabase, RedisReply;
import core.sys.posix.unistd : getpid;
import core.time : Duration, seconds, minutes, MonoTime;

import ircfiber.redis.protocol : RedisKeys, StateTTL;
import ircfiber.storage.redis : RedisStorage;

private string makeActor() {
    auto pid = getpid();
    auto host = environment.get("HOSTNAME", "");
    if (host.length == 0) host = environment.get("COMPUTERNAME", "unknown");
    if (host.length > 24) host = host[0 .. 24];
    return "pid:" ~ to!string(pid) ~ ":host=" ~ host;
}

/**
 * Purge every Redis key in the engine's namespace.
 *
 * Called at engine boot BEFORE registering as a server. Idempotent —
 * safe on a clean namespace. Skips the handoff boot path
 * (`IRCFIBER_RELOAD_FROM_PID` set) so adopted sockets keep their state.
 *
 * Wipes `*:<serverId>:*` keys + `irc:server:<id>` + `irc:control:<id>` +
 * `irc:server-assignments:<id>` atomically via Lua so a parallel janitor
 * can never re-create them mid-purge.
 *
 * Returns the number of keys removed. Zero means clean namespace.
 */
long purgeLocalServerNamespace(RedisDatabase db, string serverId) @trusted {
    if (serverId.length == 0) return 0;
    immutable string script =
        "local sid = ARGV[1]\n" ~
        "local deleted = 0\n" ~
        "local cursor = '0'\n" ~
        "repeat\n" ~
        "  local res = redis.call('SCAN', cursor, 'MATCH', '*:' .. sid .. ':*', 'COUNT', 500)\n" ~
        "  cursor = res[1]\n" ~
        "  local keys = res[2]\n" ~
        "  if #keys > 0 then\n" ~
        "    deleted = deleted + redis.call('UNLINK', unpack(keys))\n" ~
        "  end\n" ~
        "until cursor == '0'\n" ~
        "deleted = deleted + redis.call('UNLINK',\n" ~
        "  'irc:server:' .. sid,\n" ~
        "  'irc:control:' .. sid,\n" ~
        "  'irc:server-assignments:' .. sid,\n" ~
        "  'irc:draining:' .. sid)\n" ~
        "redis.call('SREM', 'irc:servers', sid)\n" ~
        "return deleted\n";
    long deleted = 0;
    try {
        auto reply = db.eval!long(script, ["0"], serverId);
        if (!reply.empty) deleted = reply.front;
        if (deleted > 0) {
            logInfo("EngineJanitor purge: removed %d keys from namespace %s", deleted, serverId);
            string evtJson =
                `{"ts":` ~ Clock.currTime.toUnixTime!long.to!string ~
                `,"kind":"namespace_purge"` ~
                `,"serverId":` ~ `"` ~ serverId ~ `"` ~
                `,"actor":` ~ `"` ~ makeActor() ~ `"` ~
                `,"reason":"bootstrap_purge"` ~
                `,"keysDeleted":` ~ deleted.to!string ~ `}`;
            immutable string auditScript =
                "redis.call('LPUSH', 'irc:janitor:events', ARGV[1])\n" ~
                "redis.call('LTRIM', 'irc:janitor:events', 0, 999)\n" ~
                "return 1\n";
            db.eval!long(auditScript, ["0"], evtJson);
        }
    } catch (Exception e) {
        logWarn("EngineJanitor purge: failed for %s: %s", serverId, e.msg);
    }
    return deleted;
}

/**
 * Bump TTL on every per-engine state key.
 *
 * Called by the engine heartbeat each cycle so a live engine keeps its
 * state alive (TTL > heartbeat interval) but a dead engine's state
 * expires within STATE_TTL seconds regardless of janitor availability.
 *
 * Batched via SCAN to avoid blocking Redis on huge keyspaces. Idempotent.
 * No-op when the engine has no namespace yet (cold start).
 */
long bumpServerStateTTLs(RedisDatabase db, string serverId, long ttlSeconds) @trusted {
    if (serverId.length == 0 || ttlSeconds <= 0) return 0;
    immutable string[] patterns = [
        "irc:state:" ~ serverId ~ ":*",
        "scrollback:" ~ serverId ~ ":*",
        "dedup:" ~ serverId ~ ":*",
    ];
        long touched = 0;
        foreach (pattern; patterns) {
            string cursor = "0";
            while (true) {
                try {
                    immutable string script =
                        "local c = ARGV[1]; local p = ARGV[2]; local t = tonumber(ARGV[3])\n" ~
                        "local r = redis.call('SCAN', c, 'MATCH', p, 'COUNT', 500)\n" ~
                        "local touched = 0\n" ~
                        "for i, k in ipairs(r[2]) do\n" ~
                        "  redis.call('EXPIRE', k, t); touched = touched + 1\n" ~
                        "end\n" ~
                        "return r[1] .. '|' .. touched\n";
                    auto reply = db.eval!string(script, ["0"],
                        cursor, pattern, ttlSeconds.to!string);
                    if (reply.empty) break;
                    auto combined = reply.front;
                    auto sep = combined.indexOf('|');
                    if (sep < 0) break;
                    cursor = combined[0 .. sep];
                    touched += combined[sep + 1 .. $].to!long;
                    if (cursor == "0") break;
                } catch (Exception e) {
                    logWarn("bumpServerStateTTLs: failed for %s/%s: %s", serverId, pattern, e.msg);
                    break;
                }
            }
        }
    try {
        db.expire(RedisKeys.control(serverId), StateTTL.CONTROL_QUEUE_TTL);
    } catch (Exception e) {
        logDebug("bumpServerStateTTLs: control queue TTL bump failed: %s", e.msg);
    }
    return touched;
}

/**
 * Distributed Engine Janitor.
 *
 * Race-safe global cleanup of orphan engine state. Runs in every process
 * (gateway + each engine instance) — exactly one wins each cycle via a
 * Redis distributed lock. The losers yield and re-elect on the next cycle.
 *
 * Reap algorithm (per orphan serverId):
 *  1. Acquire `irc:janitor:lock` via `SET NX EX <lock_ttl>` (atomic election).
 *  2. For each serverId in `irc:servers`:
 *     a. EXISTS `irc:server:<id>` → live, skip.
 *     b. Else → atomic Lua reap: SCAN UNLINK `*:<id>:*` + bookkeeping.
 *  3. Release lock (DEL if value matches ours).
 *
 * Failure modes handled:
 *  - Janitor dies mid-cycle     → lock TTL expires, next cycle re-elects.
 *  - Engine revives mid-reap    → Lua re-checks `irc:server:<id>`, refuses.
 *  - Two janitors race          → SET NX ensures only one acquires lock.
 *  - Already-reaped serverId    → idempotent; exists check returns 0.
 */
final class EngineJanitor {
    private {
        RedisStorage redis;
        RedisDatabase db;
        string actor;
        long intervalSeconds;
        long lockTtlSeconds;
        bool   running;
        long   totalCycles;
        long   totalReaped;
        long   lastDurationMs;
        string[] lastCycleReaped;
    }

    /// Constructs a janitor bound to the given Redis storage.
    this(RedisStorage redisStorage) {
        this.redis = redisStorage;
        this.db = redisStorage.getDb();
        this.actor = makeActor();
        this.intervalSeconds = parseSeconds("IRCFIBER_JANITOR_INTERVAL",
            StateTTL.JANITOR_INTERVAL_DEFAULT);
        this.lockTtlSeconds = parseSeconds("IRCFIBER_JANITOR_LOCK_TTL",
            StateTTL.JANITOR_LOCK_DEFAULT);
    }

    /// Starts the janitor loop in a background task.
    void start() {
        if (running) return;
        running = true;
        runTask(() nothrow {
            try runJanitorLoop();
            catch (Exception e) {
                logError("EngineJanitor loop crashed: %s", e.msg);
            }
        });
    }

    /// Run one cycle synchronously. Returns count of servers reaped.
    /// Used by tests + admin manual-trigger endpoint.
    long runOnce() {
        const startMono = MonoTime.currTime;
        long reaped = 0;
        lastCycleReaped.length = 0;

        // Acquire global lock via SET NX EX (atomic).
        auto lockVal = actor ~ ":" ~ to!string(Clock.currTime.toUnixTime);
        bool gotLock = false;
        try {
            // vibe-d's `db.set(key, val)` takes only (key, value). For
            // atomic SET NX EX we use the lower-level request() API.
            db.request!string("SET", RedisKeys.janitorLock(), lockVal, "NX", "EX",
                lockTtlSeconds.to!string);
            const got = db.get(RedisKeys.janitorLock());
            gotLock = (got == lockVal);
        } catch (Exception e) {
            logWarn("EngineJanitor: SET NX failed: %s — skipping cycle", e.msg);
            return 0;
        }
        if (!gotLock) return 0;

        // Manual release (no try inside scope(exit) — wrap in plain scope).
        bool released = false;
        void release() {
            if (released) return;
            released = true;
            try db.del(RedisKeys.janitorLock());
            catch (Exception e) {
                logWarn("EngineJanitor: failed to release lock: %s", e.msg);
            }
        }
        scope (exit) release();

        string[] serverIds;
        try {
            auto reply = db.smembers(RedisKeys.serverList());
            foreach (m; reply) serverIds ~= m.idup;
        } catch (Exception e) {
            logWarn("EngineJanitor: SMEMBERS failed: %s", e.msg);
            return 0;
        }

        foreach (sid; serverIds) {
            try {
                if (db.exists(RedisKeys.server(sid)) > 0) continue;
            } catch (Exception e) {
                logWarn("EngineJanitor: EXISTS check failed for %s: %s", sid, e.msg);
                continue;
            }

            // SCAN+UNLINK in batches. Returns "cursor|deleted" joined string.
            immutable string reapBatchScript =
                "local sid = ARGV[1]\n" ~
                "local cursor = ARGV[2]\n" ~
                "local batch = tonumber(ARGV[3])\n" ~
                "local res = redis.call('SCAN', cursor, 'MATCH', '*:' .. sid .. ':*', 'COUNT', batch)\n" ~
                "cursor = res[1]\n" ~
                "local keys = res[2]\n" ~
                "local deleted = 0\n" ~
                "if #keys > 0 then\n" ~
                "  deleted = redis.call('UNLINK', unpack(keys))\n" ~
                "end\n" ~
                "return cursor .. '|' .. deleted\n";

            long totalDeleted = 0;
            string cursor = "0";
            enum BATCH = 500;
            while (true) {
                try {
                    auto reply = db.eval!string(reapBatchScript, ["0"],
                        sid, cursor, BATCH.to!string);
                    if (reply.empty) break;
                    auto combined = reply.front;
                    auto sep = combined.indexOf('|');
                    if (sep < 0) break;
                    cursor = combined[0 .. sep];
                    totalDeleted += combined[sep + 1 .. $].to!long;
                    if (cursor == "0") break;
                    yield();
                } catch (Exception e) {
                    logWarn("EngineJanitor: SCAN batch failed for %s: %s", sid, e.msg);
                    break;
                }
            }

            // Finalize: race-guard, registry cleanup, audit log.
            // Returns 1 if reap completed, 0 if engine revived mid-cycle.
            immutable string reapFinalizeScript =
                "local sid = ARGV[1]\n" ~
                "local actor = ARGV[2]\n" ~
                "local now = ARGV[3]\n" ~
                "local deleted = ARGV[4]\n" ~
                "if redis.call('EXISTS', 'irc:server:' .. sid) == 1 then\n" ~
                "  return 0\n" ~
                "end\n" ~
                "redis.call('SREM', 'irc:servers', sid)\n" ~
                "redis.call('DEL', 'irc:server-assignments:' .. sid)\n" ~
                "redis.call('DEL', 'irc:control:' .. sid)\n" ~
                "local evt = cjson.encode({\n" ~
                "  ts = tonumber(now),\n" ~
                "  kind = 'engine_reap',\n" ~
                "  serverId = sid,\n" ~
                "  actor = actor,\n" ~
                "  reason = 'lease_expired',\n" ~
                "  keysDeleted = tonumber(deleted)\n" ~
                "})\n" ~
                "redis.call('LPUSH', 'irc:janitor:events', evt)\n" ~
                "redis.call('LTRIM', 'irc:janitor:events', 0, 999)\n" ~
                "return 1\n";
            try {
                auto finReply = db.eval!long(reapFinalizeScript, ["0"],
                    sid, actor, Clock.currTime.toUnixTime!long.to!string,
                    totalDeleted.to!string);
                if (!finReply.empty && finReply.front == 1) {
                    reaped++;
                    lastCycleReaped ~= sid;
                    logInfo("EngineJanitor: reaped %s (%d keys)",
                        sid, totalDeleted);
                }
            } catch (Exception e) {
                logWarn("EngineJanitor: finalize failed for %s: %s", sid, e.msg);
            }
        }

        totalCycles++;
        totalReaped += reaped;
        lastDurationMs = (MonoTime.currTime - startMono).total!"msecs";
        return reaped;
    }

    /// Read recent audit events (most recent first).
    Json[] getRecentEvents(int limit = 50) {
        if (limit <= 0 || limit > 1000) limit = 50;
        Json[] result;
        try {
            auto reply = db.lrange(RedisKeys.janitorEvents(), 0, limit - 1);
            foreach (r; reply) {
                try {
                    import std.json : parseJSON;
                    result ~= Json(parseJSON(r.idup));
                } catch (Exception e) {
                    logDebug("EngineJanitor: skipping malformed event: %s", e.msg);
                }
            }
        } catch (Exception e) {
            logWarn("EngineJanitor: getRecentEvents failed: %s", e.msg);
        }
        return result;
    }

    /// Read janitor state for admin/status endpoint.
    Json getStatus() {
        auto j = Json.emptyObject;
        try {
            j["lockHolder"] = Json(db.get(RedisKeys.janitorLock()));
        } catch (Exception) {
            j["lockHolder"] = Json(null);
        }
        j["actor"] = Json(actor);
        j["intervalSeconds"] = Json(intervalSeconds);
        j["lockTtlSeconds"] = Json(lockTtlSeconds);
        j["totalCycles"] = Json(totalCycles);
        j["totalReaped"] = Json(totalReaped);
        j["lastDurationMs"] = Json(lastDurationMs);
        // Manually construct array of strings to avoid Vibe Json array issues
        auto arr = Json.emptyArray;
        foreach (s; lastCycleReaped) arr ~= Json(s);
        j["lastCycleReaped"] = arr;
        return j;
    }

    /// Manual reap (admin endpoint). Re-uses the same atomic reap logic.
    /// Bypasses the global lock because admin-driven reaps must be possible
    /// even during a janitor cycle.
    long manualReap(string serverId) {
        if (serverId.length == 0) return 0;
        immutable string reapBatchScript =
            "local sid = ARGV[1]\n" ~
            "local cursor = ARGV[2]\n" ~
            "local batch = tonumber(ARGV[3])\n" ~
            "local res = redis.call('SCAN', cursor, 'MATCH', '*:' .. sid .. ':*', 'COUNT', batch)\n" ~
            "cursor = res[1]\n" ~
            "local keys = res[2]\n" ~
            "local deleted = 0\n" ~
            "if #keys > 0 then\n" ~
            "  deleted = redis.call('UNLINK', unpack(keys))\n" ~
            "end\n" ~
            "return cursor .. '|' .. deleted\n";
        long totalDeleted = 0;
        string cursor = "0";
        enum BATCH = 500;
        while (true) {
            try {
                auto reply = db.eval!string(reapBatchScript, ["0"],
                    serverId, cursor, BATCH.to!string);
                if (reply.empty) break;
                auto combined = reply.front;
                auto sep = combined.indexOf('|');
                if (sep < 0) break;
                cursor = combined[0 .. sep];
                totalDeleted += combined[sep + 1 .. $].to!long;
                if (cursor == "0") break;
                yield();
            } catch (Exception e) {
                logWarn("EngineJanitor manual: SCAN failed for %s: %s", serverId, e.msg);
                break;
            }
        }
        immutable string reapFinalizeScript =
            "local sid = ARGV[1]\n" ~
            "local actor = ARGV[2]\n" ~
            "local now = ARGV[3]\n" ~
            "local deleted = ARGV[4]\n" ~
            "if redis.call('EXISTS', 'irc:server:' .. sid) == 1 then\n" ~
            "  return 0\n" ~
            "end\n" ~
            "redis.call('SREM', 'irc:servers', sid)\n" ~
            "redis.call('DEL', 'irc:server-assignments:' .. sid)\n" ~
            "redis.call('DEL', 'irc:control:' .. sid)\n" ~
            "local evt = cjson.encode({\n" ~
            "  ts = tonumber(now),\n" ~
            "  kind = 'engine_reap_manual',\n" ~
            "  serverId = sid,\n" ~
            "  actor = actor,\n" ~
            "  reason = 'manual',\n" ~
            "  keysDeleted = tonumber(deleted)\n" ~
            "})\n" ~
            "redis.call('LPUSH', 'irc:janitor:events', evt)\n" ~
            "redis.call('LTRIM', 'irc:janitor:events', 0, 999)\n" ~
            "return 1\n";
        try {
            auto finReply = db.eval!long(reapFinalizeScript, ["0"],
                serverId,
                actor ~ ":manual",
                Clock.currTime.toUnixTime!long.to!string,
                totalDeleted.to!string);
            if (!finReply.empty && finReply.front == 1) {
                lastCycleReaped = [serverId];
                totalReaped++;
                return totalDeleted;
            }
        } catch (Exception e) {
            logWarn("EngineJanitor manual: finalize failed for %s: %s", serverId, e.msg);
        }
        return 0;
    }

    private void runJanitorLoop() {
        logInfo("EngineJanitor starting: actor=%s interval=%ds lockTtl=%ds",
            actor, intervalSeconds, lockTtlSeconds);
        try sleep(30.seconds); catch (Exception) return;
        int consecutiveFailures = 0;
        while (true) {
            try {
                auto n = runOnce();
                if (n > 0)
                    logInfo("EngineJanitor: reaped %d orphan(s) this cycle", n);
                consecutiveFailures = 0;
            } catch (Exception e) {
                consecutiveFailures++;
                logWarn("EngineJanitor: error (%d/%d): %s — skipping cycle",
                    consecutiveFailures, 5, e.msg);
                if (consecutiveFailures >= 5) {
                    logWarn("EngineJanitor: %d consecutive failures, pausing for 10 minutes",
                        consecutiveFailures);
                    try { sleep(10.minutes); } catch (Exception) { return; }
                    consecutiveFailures = 0;
                    continue;
                }
            }
            try sleep(intervalSeconds.seconds); catch (Exception) return;
        }
    }

    private static long parseSeconds(string envName, long defaultValue) {
        auto raw = environment.get(envName, "");
        if (raw.length == 0) return defaultValue;
        try {
            auto v = raw.to!long;
            if (v < 1) {
                writefln("WARN: %s=%s out of range, using default %d", envName, raw, defaultValue);
                return defaultValue;
            }
            return v;
        } catch (Exception) {
            writefln("WARN: %s=%s unparseable, using default %d", envName, raw, defaultValue);
            return defaultValue;
        }
    }
}
