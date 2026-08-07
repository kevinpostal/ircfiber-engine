module ircfiber.storage.redis;

import std.conv : to;
import std.string;
import std.typecons : Nullable, tuple, Tuple;
import std.algorithm : canFind;

import vibe.core.log;
import vibe.data.json;
import vibe.db.redis.redis;

/// Redis connection wrapper.
final class RedisStorage {
    private {
        RedisClient client;
        RedisDatabase db;
        string host;
        ushort port;
    }

    /// Creates a new Redis storage wrapper.
    this(string host = "127.0.0.1", ushort port = 6379) {
        this.host = host;
        this.port = port;
    }

    /// Connects to Redis.
    void connect() @trusted {
        client = connectRedis(host, port);
        db = client.getDatabase(0);
        logInfo("Connected to Redis at %s:%s", host, port);
    }

    /// Connects to Redis from a URL.
    void connectFromUrl(string url) @trusted {
        if (url.startsWith("redis://")) {
            auto rest = url[8 .. $];
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
        connect();
    }

    RedisDatabase getDb() @trusted {
        return db;
    }

    RedisClient getClient() @trusted {
        return client;
    }

    void setJson(string key, Json value, long ttlSeconds = 0) @trusted {
        try {
            if (ttlSeconds > 0)
                db.setEX(key, ttlSeconds, value.toString());
            else
                db.set(key, value.toString());
        } catch (Exception e) {
            logDebug("Redis setJson failed: %s", e.msg);
        }
    }

    Json getJson(string key) @trusted {
        try {
            auto val = db.get(key);
            if (val.length == 0) return Json(null);
            return parseJson(val);
        } catch (Exception e) {
            logDebug("Redis getJson failed: %s", e.msg);
            return Json(null);
        }
    }

    /// Checks if a key exists.
    bool exists(string key) @trusted {
        try {
            return db.exists(key);
        } catch (Exception e) {
            logDebug("Redis exists failed: %s", e.msg);
            return false;
        }
    }

    /// Deletes a key.
    void del(string key) @trusted {
        try {
            db.del(key);
        } catch (Exception e) {
            logDebug("Redis del failed: %s", e.msg);
        }
    }

    // List helpers
    /// Pushes a value onto a list.
    void lpush(string key, string value) @trusted {
        try {
            db.lpush(key, value);
        } catch (Exception e) {
            logDebug("Redis lpush failed: %s", e.msg);
        }
    }

    /// Blocking pop from a list.
    Nullable!(Tuple!(string, string)) blpop(string key, long timeoutSeconds) @trusted {
        try {
            return db.blpop!string(key, timeoutSeconds);
        } catch (Exception e) {
            logDebug("Redis blpop failed: %s", e.msg);
            return Nullable!(Tuple!(string, string)).init;
        }
    }

    // Hash helpers
    /// Sets a hash field.
    void hset(string key, string field, string value) @trusted {
        try {
            db.hset(key, field, value);
        } catch (Exception e) {
            logDebug("Redis hset failed: %s", e.msg);
        }
    }

    /// Gets all fields from a hash.
    string[string] hgetAll(string key) @trusted {
        string[string] result;
        try {
            auto reply = db.hgetAll!string(key);
            string currentField;
            bool isField = true;
            foreach (r; reply) {
                if (isField) {
                    currentField = r;
                } else {
                    result[currentField] = r;
                }
                isField = !isField;
            }
        } catch (Exception e) {
            logDebug("hgetAll failed for %s: %s", key, e.msg);
        }
        return result;
    }

    // Pub/Sub helper
    /// Publishes a message to a channel.
    long publish(string channel, string message) @trusted {
        try {
            return db.publish(channel, message);
        } catch (Exception e) {
            logDebug("Redis publish failed: %s", e.msg);
            return 0;
        }
    }

/// Atomic increment. Returns the new value after increment.
/// Used for the global sequential eid counter (IRCCloud-style).
long incr(string key) @trusted {
    try {
        return db.incr(key);
    } catch (Exception e) {
        logDebug("Redis incr failed: %s", e.msg);
        return 0;
    }
}

// ────────────────────────────────────────────────────────────
// Observability helpers — used by the admin Redis monitor
// ────────────────────────────────────────────────────────────

/// Returns the full `INFO` output as a string. Throws on failure.
string infoRaw() @trusted {
    try return db.request!string("INFO");
    catch (Exception e) {
        logDebug("Redis INFO failed: %s", e.msg);
        return "";
    }
}

/// Parses a Redis `INFO` blob into a section → field → value map.
/// INFO output looks like:
///   # Server\r\nredis_version:7.0.0\r\n...
///   # Memory\r\nused_memory:123456\r\n...
string[string][string] parseInfo(string raw) {
    string[string][string] result;
    string currentSection = "default";
    foreach (line; raw.splitLines()) {
        if (line.length == 0) continue;
        if (line[0] == '#') {
            auto trimmed = line[1 .. $].strip();
            if (trimmed.length > 0) currentSection = trimmed.idup;
            continue;
        }
        auto colonIdx = line.indexOf(':');
        if (colonIdx <= 0) continue;
        auto key = line[0 .. colonIdx].idup.strip();
        auto val = line[colonIdx + 1 .. $].idup.strip();
        result[currentSection][key] = val;
    }
    return result;
}

/// Returns INFO as a parsed map.
string[string][string] infoParsed() @trusted {
    return parseInfo(infoRaw());
}

/// DBSIZE — number of keys in the selected database.
long dbsizeSafe() @trusted {
    try return db.dbSize();
    catch (Exception e) {
        logDebug("Redis DBSIZE failed: %s", e.msg);
        return -1;
    }
}

/// Returns parsed `INFO all` sections the admin cares about, with numeric
/// fields pre-parsed where possible. Returns an empty map on failure.
Json infoJson() @trusted {
    import vibe.data.json : Json;
    auto sections = parseInfo(infoRaw());
    Json result = Json.emptyObject;
    foreach (section, fields; sections) {
        Json sec = Json.emptyObject;
        foreach (k, v; fields) {
            // Try to parse as a number; fall back to string
            try {
                if (v.canFind('.')) sec[k] = Json(v.to!double);
                else sec[k] = Json(v.to!long);
            } catch (Exception) {
                sec[k] = Json(v);
            }
        }
        result[section] = sec;
    }
    return result;
}

/// SCAN-based key listing. Returns up to `count` keys matching `match`,
/// using Redis's incremental cursor so we never block the server.
/// Returns (cursorString, keys[]). The next call should pass back the
/// returned cursor (or "0" to start fresh).
struct ScanResult {
    string cursor;
    string[] keys;
}

ScanResult scanKeys(string cursor, string match, long count = 100) @trusted {
    import std.conv : to;
    ScanResult r;
    try {
        auto reply = db.request!(RedisReply!string)("SCAN", cursor, "MATCH", match, "COUNT", count.to!string);
        // Reply format: [nextCursor, [key, key, ...]]
        bool first = true;
        foreach (item; reply) {
            if (first) { r.cursor = item; first = false; }
            else r.keys ~= item;
        }
    } catch (Exception e) {
        logDebug("Redis SCAN failed: %s", e.msg);
        r.cursor = "0";
    }
    return r;
}

/// Returns up to `count` entries from the SLOWLOG.
/// Each entry is a flat array: [id, unixMs, durationMicros, [cmd, arg, ...], ip, ...]
RedisReply!string slowlog(long count = 50) @trusted {
    import std.conv : to;
    try return db.request!(RedisReply!string)("SLOWLOG", "GET", count.to!string);
    catch (Exception e) {
        logDebug("Redis SLOWLOG GET failed: %s", e.msg);
        // Return an empty reply by triggering a no-op
        return db.request!(RedisReply!string)("SLOWLOG", "LEN");
    }
}

/// Returns PUBSUB CHANNELS matching the pattern.
string[] pubsubChannels(string pattern = "*") @trusted {
    try {
        auto reply = db.request!(RedisReply!string)("PUBSUB", "CHANNELS", pattern);
        string[] result;
        foreach (item; reply) result ~= item;
        return result;
    } catch (Exception e) {
        logDebug("Redis PUBSUB CHANNELS failed: %s", e.msg);
        return null;
    }
}

/// Returns the truncated CLIENT LIST output (first ~100 lines).
string clientList(int maxLines = 100) @trusted {
    try {
        auto raw = db.request!string("CLIENT", "LIST");
        auto lines = raw.splitLines();
        if (cast(int) lines.length > maxLines) lines = lines[0 .. maxLines];
        return lines.join("\n");
    } catch (Exception e) {
        logDebug("Redis CLIENT LIST failed: %s", e.msg);
        return "";
    }
}

/// Returns metadata for a key: type, ttl (seconds), and approximate
/// memory usage. Returns an empty Json object if the key doesn't exist.
Json keyMeta(string key) @trusted {
    import vibe.data.json : Json;
    Json meta = Json.emptyObject;
    try {
        auto t = db.request!string("TYPE", key);
        meta["type"] = Json(t);
        meta["ttl"] = Json(db.ttl(key));
        try {
            auto usage = db.request!long("MEMORY", "USAGE", key);
            meta["memory"] = Json(usage);
        } catch (Exception) {
            meta["memory"] = Json(-1L);
        }
    } catch (Exception e) {
        logDebug("Redis keyMeta(%s) failed: %s", key, e.msg);
    }
    return meta;
}

/// Reads a small sample of a key's value (for the key inspector).
/// Returns a string representation. Truncates long values.
string keySample(string key, int maxLen = 256) @trusted {
    import std.conv : to;
    try {
        auto t = db.request!string("TYPE", key);
        if (t == "string") {
            auto raw = db.get(key);
            if (raw.length > maxLen) raw = raw[0 .. maxLen] ~ "…";
            return raw;
        } else if (t == "hash") {
            auto reply = db.request!(RedisReply!string)("HGETALL", key);
            string result;
            int n = 0;
            bool isField = true;
            string field;
            foreach (r; reply) {
                if (isField) field = r;
                else result ~= field ~ " → " ~ r ~ "\n";
                isField = !isField;
                if (++n >= 20) { result ~= "…(truncated)"; break; }
            }
            return result;
        } else if (t == "list") {
            auto reply = db.request!(RedisReply!string)("LRANGE", key, "0", "9");
            string result;
            int n = 0;
            foreach (r; reply) {
                result ~= (n++).to!string ~ ") " ~ r ~ "\n";
            }
            return result;
        } else if (t == "set") {
            auto reply = db.request!(RedisReply!string)("SRANDMEMBER", key, "10");
            string result;
            foreach (r; reply) result ~= r ~ "\n";
            return result;
        } else {
            return "(" ~ t ~ ")";
        }
    } catch (Exception e) {
        logDebug("Redis keySample(%s) failed: %s", key, e.msg);
        return "";
    }
}
}
