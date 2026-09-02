module ircfiber.db.lastseen;

import std.conv : to;
import std.uuid;
import vibe.core.log;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : RedisKeys;

/// Per-user, per-buffer last-seen persistence (IRCCloud `last_seen_eid`).
///
/// Storage: one Redis hash per user, `irc:lastseen:<userId>`, field
/// `<networkId>:<bufferKey>` (bufferKey exactly as the frontend sends it —
/// channels lowercased with `#`, queries verbatim), value = message `t`
/// in ms. Advance-only: a merge never moves a field backwards, so two
/// sessions racing on the same buffer converge on the newest read marker.
/// No TTL — a read marker is as durable as the preferences it sits next to.
final class LastSeenRepository {
    private RedisStorage redis;

    this(RedisStorage redis) {
        this.redis = redis;
    }

    /// Atomic per-field advance-only set: returns 1 when the field was
    /// written (missing or ARGV[1] > existing), 0 otherwise.
    private enum SET_IF_GREATER_LUA = `local cur = redis.call('HGET', KEYS[1], ARGV[1])
if (not cur) or (tonumber(ARGV[2]) > tonumber(cur)) then
    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
    return 1
end
return 0`;

    /// Every persisted field for the user. Unparsable values are skipped.
    long[string] load(UUID userId) {
        long[string] result;
        foreach (field, value; redis.hgetAll(RedisKeys.lastSeen(userId.toString()))) {
            try result[field] = value.to!long;
            catch (Exception) {}
        }
        return result;
    }

    /// Merges `incoming` advance-only and returns only the fields that
    /// actually changed (missing before, or strictly newer than stored).
    long[string] merge(UUID userId, long[string] incoming) {
        long[string] changed;
        if (incoming.length == 0) return changed;
        const key = RedisKeys.lastSeen(userId.toString());
        foreach (field, t; incoming) {
            try {
                auto reply = redis.getDb().eval!long(SET_IF_GREATER_LUA, [key], field, t.to!string);
                if (!reply.empty && reply.front == 1) changed[field] = t;
            } catch (Exception e) {
                logWarn("lastseen merge failed for %s/%s: %s", key, field, e.msg);
            }
        }
        return changed;
    }
}

@("LastSeenRepository.merge is advance-only and returns only changed fields")
unittest {
    // Requires a local Redis on 127.0.0.1:6379; skipped when unavailable.
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
    } catch (Exception e) {
        logWarn("Skipping LastSeenRepository test: Redis unavailable (%s)", e.msg);
        return;
    }
    auto userId = randomUUID();
    const key = RedisKeys.lastSeen(userId.toString());
    void cleanup() {
        try redis.getDb().del(key);
        catch (Exception) {}
    }
    cleanup();
    scope (exit) cleanup();

    auto repo = new LastSeenRepository(redis);
    assert(repo.load(userId).length == 0);

    // First write: both fields are new → both reported changed.
    auto changed = repo.merge(userId, ["net1:#dev": 1000L, "net1:alice": 500L]);
    assert(changed.length == 2);
    assert(changed["net1:#dev"] == 1000 && changed["net1:alice"] == 500);

    // Older value for #dev is ignored; newer value for alice advances.
    changed = repo.merge(userId, ["net1:#dev": 900L, "net1:alice": 600L]);
    assert(changed.length == 1);
    assert("net1:#dev" !in changed);
    assert(changed["net1:alice"] == 600);

    // Equal value is not a change.
    changed = repo.merge(userId, ["net1:#dev": 1000L]);
    assert(changed.length == 0);

    const stored = repo.load(userId);
    assert(stored["net1:#dev"] == 1000);
    assert(stored["net1:alice"] == 600);
}
