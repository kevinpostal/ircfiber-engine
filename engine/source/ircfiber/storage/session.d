module ircfiber.storage.session;

import std.variant : Variant;

import core.sync.mutex : Mutex;

import vibe.http.session : Session, SessionStorageType, SessionStore;
import vibe.data.json : Json, parseJson;
import vibe.core.log;

import ircfiber.storage.redis : RedisStorage;

enum SESSION_KEY_PREFIX = "session:";
package enum MAX_SESSIONS_PER_USER = 10;

/// Redis-backed session store with channel-level locking and drain support.
///
/// Channel-level lock: per-session Mutex so concurrent fibers serialize
/// access to a single session (e.g. login + simultaneous WebSocket open
/// racing on sessionUserId).
///
/// Drain: when `drain()` is called, `create()` rejects new sessions and
/// all existing sessions are destroyed. Used during graceful shutdown.
final class RedisSessionStore : SessionStore {
@safe:

    private {
        RedisStorage redis;
        alias KEY_PREFIX = SESSION_KEY_PREFIX;
        enum TTL_SECONDS = 14 * 24 * 60 * 60; // 14 days

        // Channel-level locks: one Mutex per session id.
        // Lazily populated — avoid allocating mutexes for unused sessions.
        Mutex[string] m_sessionLocks;
        Mutex m_locksMutex; // protects m_sessionLocks
        bool m_draining;
    }

    /// Creates a new Redis session store.
    this(RedisStorage redisStorage) {
        this.redis = redisStorage;
        m_locksMutex = new Mutex();
    }

    /// Acquire the per-session lock. Blocks until the session is unlocked
    /// by another fiber. The lock is channel-level — one session at a time.
    void lockSession(string id) {
        Mutex mx;
        synchronized (m_locksMutex) {
            auto p = id in m_sessionLocks;
            if (p) {
                mx = *p;
            } else {
                mx = new Mutex();
                m_sessionLocks[id] = mx;
            }
        }
        mx.lock();
    }

    /// Release the per-session lock.
    void unlockSession(string id) {
        Mutex mx;
        synchronized (m_locksMutex) {
            auto p = id in m_sessionLocks;
            if (p) mx = *p;
        }
        if (mx) mx.unlock();
    }

    /// True when the store is in drain mode (no new sessions allowed).
    @property bool isDraining() const { return m_draining; }

    /// Enter drain mode: prevents `create()` from making new sessions and
    /// destroys all existing sessions. Safe to call multiple times.
    void drain() {
        m_draining = true;
        logInfo("RedisSessionStore: drain requested — destroying all sessions");
        try {
            auto db = redis.getDb();
            foreach (id; listAllSessionIds()) {
                try destroy(id);
                catch (Exception) { }
            }
        } catch (Exception e) {
            logWarn("RedisSessionStore drain error: %s", e.msg);
        }
    }

    /// Returns the storage type (JSON).
    @property SessionStorageType storageType() const {
        return SessionStorageType.json;
    }

    /// Creates a new session in Redis.
    /// Throws if the store is in drain mode.
    Session create() {
        if (m_draining) {
            logWarn("RedisSessionStore: refusing new session during drain");
            return Session.init;
        }
        auto s = createSessionInstance();
        try {
            auto db = redis.getDb();
            db.hset(keyFor(s.id), "_created", "1");
            db.expire(keyFor(s.id), TTL_SECONDS);
        } catch (Exception e) {
            logWarn("RedisSessionStore create failed: %s", e.msg);
        }
        return s;
    }

    /// Opens an existing session from Redis.
    Session open(string id) {
        if (m_draining) return Session.init;
        try {
            auto db = redis.getDb();
            if (db.exists(keyFor(id))) {
                db.expire(keyFor(id), TTL_SECONDS);
                return createSessionInstance(id);
            }
        } catch (Exception e) {
            logWarn("RedisSessionStore open failed: %s", e.msg);
        }
        return Session.init;
    }

    /// Stores a session value.
    void set(string id, string name, Variant value) @trusted {
        try {
            auto db = redis.getDb();
            string stored;
            if (value.type == typeid(Json)) {
                stored = value.get!Json.toString();
            } else if (value.type == typeid(string)) {
                stored = value.get!string;
            } else {
                import vibe.data.json : serializeToJson;
                stored = () @trusted { return serializeToJson(value).toString(); }();
            }
            db.hset(keyFor(id), name, stored);
            db.expire(keyFor(id), TTL_SECONDS);
        } catch (Exception e) {
            logWarn("RedisSessionStore set failed: %s", e.msg);
        }
    }

    /// Retrieves a session value.
    Variant get(string id, string name, lazy Variant defaultVal) @trusted {
        try {
            auto db = redis.getDb();
            auto val = db.hget(keyFor(id), name);
            if (val.length > 0) {
                auto j = () @trusted { return parseJson(val); }();
                return Variant(j);
            }
        } catch (Exception e) {
            logWarn("RedisSessionStore get failed: %s", e.msg);
        }
        return defaultVal;
    }

    /// Checks if a key exists in a session.
    bool isKeySet(string id, string key) {
        try {
            auto db = redis.getDb();
            return db.hexists(keyFor(id), key);
        } catch (Exception e) {
            logWarn("RedisSessionStore isKeySet failed: %s", e.msg);
        }
        return false;
    }

    /// Removes a key from a session.
    void remove(string id, string key) {
        try {
            auto db = redis.getDb();
            db.hdel(keyFor(id), key);
        } catch (Exception e) {
            logWarn("RedisSessionStore remove failed: %s", e.msg);
        }
    }

    /// Destroys a session entirely.
    void destroy(string id) {
        try {
            auto db = redis.getDb();
            db.del(keyFor(id));
        } catch (Exception e) {
            logWarn("RedisSessionStore destroy failed: %s", e.msg);
        }
    }

    /// Returns ALL Redis session keys matching the session key prefix.
    /// Used by admin listing — replaces hand-rolled `db.keys("session:*")`.
    string[] listAllSessionIds() {
        try {
            auto db = redis.getDb();
            auto keys = db.keys(KEY_PREFIX ~ "*");
            string[] result;
            foreach (k; keys) {
                auto key = () @trusted { return cast(string) k.idup; } ();
                result ~= key[KEY_PREFIX.length .. $];
            }
            return result;
        } catch (Exception e) {
            logWarn("RedisSessionStore listAllSessionIds failed: %s", e.msg);
            return [];
        }
    }

    /// Returns all hash fields for a given session, with JSON strings unwrapped.
    /// Returns null if the session does not exist.
    /// The caller owns the returned associative array.
    string[string] getSessionFields(string id) {
        try {
            return redis.hgetAll(keyFor(id));
        } catch (Exception e) {
            logWarn("RedisSessionStore getSessionFields failed for %s: %s", id, e.msg);
            return null;
        }
    }

    /// Returns the TTL in seconds for a session, or -1 if the key has
    /// no expiry or does not exist.
    long sessionTtl(string id) {
        try {
            auto db = redis.getDb();
            return db.ttl(keyFor(id));
        } catch (Exception e) {
            logWarn("RedisSessionStore sessionTtl failed: %s", e.msg);
            return -1;
        }
    }

    /// Iterates over all keys in a session.
    int iterateSession(string id, scope int delegate(string key) @safe del) {
        try {
            auto db = redis.getDb();
            auto fields = db.hkeys(keyFor(id));
            foreach (f; fields) {
                if (f == "_created") continue;
                if (auto ret = del(f)) return ret;
            }
        } catch (Exception e) {
            logWarn("RedisSessionStore iterateSession failed: %s", e.msg);
        }
        return 0;
    }

    private string keyFor(string id) @safe pure nothrow {
        return KEY_PREFIX ~ id;
    }
}

/// Limits the number of Redis sessions for a given userId.
/// Keeps at most `maxSessions` most-recently-active sessions.
/// The current session (`currentSessionId`) is always preserved.
/// Older sessions beyond the limit are deleted silently.
/// Safe to call on every login — no-ops when under the cap.
void limitUserSessions(RedisStorage redis, string userId,
                               string currentSessionId, int maxSessions = MAX_SESSIONS_PER_USER) {
    try {
        import std.algorithm.sorting : sort;
        import std.conv : to;

        auto db = redis.getDb();
        auto keys = db.keys(SESSION_KEY_PREFIX ~ "*");

        struct SessionEntry { string id; long lastAccess; }
        SessionEntry[] userSessions;

        foreach (k; keys) {
            auto key = () @trusted { return cast(string) k.idup; } ();
            auto sid = key[SESSION_KEY_PREFIX.length .. $];
            if (sid == currentSessionId) continue;

            auto fields = redis.hgetAll(key);
            auto uidPtr = "sessionUserId" in fields;
            if (!uidPtr) continue;

            // Strip JSON quoting (Vibe.d JSON-encodes string values)
            auto uid = *uidPtr;
            if (uid.length >= 2 && uid[0] == '"' && uid[$-1] == '"')
                uid = uid[1 .. $-1];
            if (uid != userId) continue;

            // Read lastAccess (stored as plain numeric string)
            long lastAccess = 0;
            auto laPtr = "lastAccess" in fields;
            if (laPtr && laPtr.length > 0) {
                try { lastAccess = (*laPtr).to!long; }
                catch (Exception) { }
            }

            userSessions ~= SessionEntry(sid, lastAccess);
        }

        if (userSessions.length <= maxSessions) return;

        // Sort so the NEWEST sessions come first, then delete the tail
        // (the sessions with the smallest lastAccess = oldest).
        userSessions.sort!((a, b) => a.lastAccess > b.lastAccess);

        foreach (i; maxSessions .. userSessions.length) {
            db.del(SESSION_KEY_PREFIX ~ userSessions[i].id);
        }
    } catch (Exception e) {
        logWarn("limitUserSessions error: %s", e.msg);
    }
}
