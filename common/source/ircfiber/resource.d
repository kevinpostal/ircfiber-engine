module ircfiber.resource;

import std.process : environment, thisProcessID;
import std.datetime : Clock, SysTime;
import std.string : fromStringz;
import core.sys.posix.unistd : gethostname;

import core.time : seconds;

import vibe.core.core : sleep;
import vibe.core.log;
import vibe.data.json : Json;

import ircfiber.storage.redis : RedisStorage;

private __gshared string g_resourceId;
private SysTime g_startedAt;
private bool g_initialized;

/// Returns the resource/instance identifier.
/// Reads `IRCFIBER_RESOURCE_ID` env var, falls back to hostname.
string resourceId() {
    if (!g_initialized) {
        g_resourceId = environment.get("IRCFIBER_RESOURCE_ID", "");
        if (g_resourceId.length == 0) {
            try {
                char[256] buf = void;
                gethostname(buf.ptr, buf.length);
                const hostname = fromStringz(buf.ptr).idup;
                g_resourceId = hostname;
            } catch (Exception e) {
                g_resourceId = "unknown";
            }
        }
        g_startedAt = Clock.currTime;
        g_initialized = true;
        logInfo("Resource ID: %s (started at %s)", g_resourceId, g_startedAt.toISOString());
    }
    return g_resourceId;
}

/// Heartbeat loop body — writes the resource heartbeat to Redis every 10s.
/// Takes a Redis URL (string, thread-safe) and creates its own connection
/// inside the loop. Designed to be passed to `g_bgPool.runTask`.
/// Key: `irc:resource:<resourceId>` with TTL 30s (auto-expires if process dies).
/// Payload: JSON with id, pid, startedAt, lastHeartbeat.
void heartbeatLoop(string redisUrl) {
    import ircfiber.storage.redis : RedisStorage;
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connectFromUrl(redisUrl);
    } catch (Exception e) {
        logError("Heartbeat: failed to connect to Redis: %s", e.msg);
        return;
    }
    auto rid = resourceId();
    auto key = "irc:resource:" ~ rid;
    long pid = thisProcessID();
    while (true) {
        try {
            auto nowMs = Clock.currTime.toUnixTime!long * 1000L;
            auto j = Json.emptyObject;
            j["id"] = Json(rid);
            j["pid"] = Json(pid);
            j["startedAt"] = Json(g_startedAt.toISOString());
            j["lastHeartbeat"] = Json(nowMs);
            redis.setJson(key, j, 30);
        } catch (Exception e) {
            logDebug("Resource heartbeat failed: %s", e.msg);
        }
        sleep(seconds(10));
    }
}
