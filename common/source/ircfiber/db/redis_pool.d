module ircfiber.db.redis_pool;

import vibe.core.connectionpool : ConnectionPool, LockedConnection;
import vibe.db.redis.redis : RedisClient, connectRedis;
import vibe.core.log;
import std.process : environment;
import std.string;
import std.conv : to;

/// Global Redis connection pool, shared across all thread pools.
/// The pool creates connections on demand and reuses them across fibers.
/// Max 32 concurrent connections.
__gshared ConnectionPool!RedisClient g_redisPool;

/// Initialize the pool from `IRCFIBER_REDIS_URL` env var.
void initRedisPool() {
    auto redisUrl = environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");

    string host = "127.0.0.1";
    ushort port = 6379;
    if (redisUrl.startsWith("redis://")) {
        auto rest = redisUrl[8 .. $];
        auto slashIdx = rest.indexOf("/");
        if (slashIdx >= 0) rest = rest[0 .. slashIdx];
        auto colonIdx = rest.lastIndexOf(":");
        if (colonIdx >= 0) {
            host = rest[0 .. colonIdx];
            port = to!ushort(rest[colonIdx + 1 .. $]);
        } else {
            host = rest;
        }
    }

    logInfo("Redis pool: %s:%d (max 32 connections)", host, port);
    auto h = host.idup;
    auto p = port;
    g_redisPool = new ConnectionPool!RedisClient({
        logDebug("Redis pool: creating new connection");
        return connectRedis(h, p);
    }, 32);
}

/// Lock a Redis client from the pool (RAII — auto-returns on scope exit).
LockedConnection!RedisClient poolRedis() {
    return g_redisPool.lockConnection();
}

/// Shut down the pool (close all idle connections).
void shutdownRedisPool() {
    if (g_redisPool !is null) {
        g_redisPool.removeUnused((RedisClient conn) @trusted nothrow {
            try conn.shutdown();
            catch (Exception) {}
        });
    }
}
