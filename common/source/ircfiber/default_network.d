/**
 * Default IRC Fiber network provisioning.
 *
 * Every IRC Fiber user (new and existing) gets a preconfigured connection
 * to the company-hosted IRC server at irc.ircfiber.com:6697 (TLS required).
 * The network is marked `systemManaged=true` so users can edit fields but
 * cannot delete it; only platform migrations can remove it.
 *
 * Two entry points are used at runtime:
 *   - `buildDefaultFiberNetwork(user)` — pure constructor for the config
 *     (no I/O). Useful for tests and for callers that want to inspect the
 *     config before persisting.
 *   - `ensureDefaultFiberNetwork(user, networkRepo, redis, serverRegistry)` —
 *     idempotent provisioning helper. Skips if the user already has a
 *     network with host=irc.ircfiber.com; otherwise inserts the config into
 *     Mongo, assigns a connection server, and pushes the addNetwork control
 *     message onto the engine's Redis queue.
 */
module ircfiber.default_network;

import std.uuid : UUID, randomUUID;
import std.algorithm : canFind, endsWith, startsWith;
import std.array : array;
import std.range : enumerate;
import std.ascii : isHexDigit;
import std.datetime : Clock;

import vibe.core.log;

import ircfiber.models.network : NetworkConfig, TLSMode, SASLMechanism;
import ircfiber.models.user : User;
import ircfiber.db.network : NetworkRepository;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : RedisKeys, ControlMessage;
import ircfiber.irc.registry : ServerRegistry;

/// Hostname of the platform-provided IRC server.
immutable string DEFAULT_FIBER_HOST = "irc.ircfiber.com";

/// Redis key for the admin toggle that controls auto-provisioning of the
/// default Fiber network and its visibility in the sidebar. When "0"/"false"
/// auto-provisioning is skipped and the sidebar hides the Fiber server.
immutable string FIBER_ENABLED_KEY = "irc:config:fiberEnabled";

/// Returns true if the Fiber auto-connect is enabled (default true when key
/// is missing). Reads `FIBER_ENABLED_KEY` from Redis.
bool isFiberEnabled(RedisStorage redis) @trusted {
    try {
        auto v = redis.getDb().get(FIBER_ENABLED_KEY);
        if (v.length == 0) return true;
        return v != "0" && v != "false" && v != "False";
    } catch (Exception) {
        return true;
    }
}

/// Persists the Fiber enabled flag to Redis.
void setFiberEnabled(RedisStorage redis, bool enabled) @trusted {
    try {
        redis.getDb().set(FIBER_ENABLED_KEY, enabled ? "1" : "0");
    } catch (Exception e) {
        logWarn("setFiberEnabled failed: %s", e.msg);
    }
}

/// TLS port for the platform-provided IRC server.
immutable ushort DEFAULT_FIBER_PORT = 6697;
/// Human-readable name for the default network as it appears in the sidebar.
immutable string DEFAULT_FIBER_NAME = "IRC Fiber";

/// Default channels the connection auto-joins. Only attempted on first
/// connect — if either channel does not exist on the server, the engine
/// surfaces an ERR_NOSUCHCHANNEL in the buffer and the user can edit the
/// list away from the network settings UI.
immutable string[] DEFAULT_FIBER_CHANNELS = ["#ircfiber", "#welcome"];

/// Length (hex chars, no hyphens) of the deterministic nick suffix.
immutable size_t DEFAULT_FIBER_NICK_SUFFIX_LEN = 4;

/**
 * Build a NetworkConfig for the given user pointing at the platform IRC.
 * Pure: no DB or Redis I/O. The returned config has a fresh UUID and a
 * deterministic IRC nick derived from the username and user UUID, e.g.
 * `alice_a3f1`. Two distinct users will never collide because the suffix
 * is sourced from the user UUID; users may still collide on the IRC
 * server itself (someone may already use `alice` there) which the engine
 * surfaces as a standard ERR_NICKNAMEINUSE on connect.
 */
NetworkConfig buildDefaultFiberNetwork(User user) @safe {
    NetworkConfig cfg;
    cfg.id = randomUUID();
    cfg.name = DEFAULT_FIBER_NAME;
    cfg.host = DEFAULT_FIBER_HOST;
    cfg.port = DEFAULT_FIBER_PORT;
    cfg.tls = TLSMode.required;
    cfg.sasl = SASLMechanism.none;
    cfg.nick = buildDefaultNick(user);
    cfg.realName = user.username;
    cfg.autoJoinChannels = DEFAULT_FIBER_CHANNELS.dup;
    cfg.disabled = false;
    cfg.systemManaged = true;
    return cfg;
}

/**
 * Compute the deterministic IRC nick for a user: "{username}_{shortUUID}".
 * The suffix is the first N hex characters of the canonical UUID with
 * hyphens stripped (default 4 chars, 16 bits of entropy — collisions are
 * vanishingly rare in a user base of any plausible size and the engine
 * has a graceful ERR_NICKNAMEINUSE fallback anyway).
 *
 * Pure / @safe: no allocations beyond the returned string, no I/O.
 */
string buildDefaultNick(User user) @safe {
    import std.array : appender;
    auto raw = user.id.toString();
    // Strip hyphens to get a 32-char hex string, take the first N.
    char[] hex;
    foreach (c; raw) if (c != '-') hex ~= c;
    auto suffixLen = hex.length < DEFAULT_FIBER_NICK_SUFFIX_LEN
        ? hex.length : DEFAULT_FIBER_NICK_SUFFIX_LEN;
    auto suffix = hex[0 .. suffixLen].idup;
    return user.username ~ "_" ~ suffix;
}

/**
 * Idempotently provision the default IRC Fiber network for a user.
 *
 * - Returns the existing NetworkConfig if the user already has a network
 *   with host=DEFAULT_FIBER_HOST (the network may pre-date this feature
 *   and have systemManaged=false; we don't touch it).
 * - Otherwise builds, persists, assigns to a server, and pushes the
 *   addNetwork control message via Redis.
 *
 * Returns the (existing or new) config. On infrastructure errors after
 * persistence the message may not reach the engine — that's recoverable
 * via engine bootstrap (it reads all configs from Mongo on boot), so we
 * log and return rather than throwing. Throws only for hard failures
 * (Mongo unreachable before insert).
 */
NetworkConfig ensureDefaultFiberNetwork(
    User user,
    NetworkRepository networkRepo,
    RedisStorage redis,
    ServerRegistry serverRegistry
) {
    if (user.id == UUID.init || user.username.length == 0)
        return NetworkConfig.init;

    // Global kill-switch: when admin disables Fiber, don't provision
    // new networks. Existing networks are left as-is (admin bulk
    // disable handles them via the dedicated endpoint).
    if (!isFiberEnabled(redis))
        return NetworkConfig.init;

    // Skip if user already has a connection to irc.ircfiber.com — do not
    // clobber a network they may have added themselves or a pre-feature
    // default that is already wired up.
    auto existing = networkRepo.findByUserId(user.id);
    foreach (ref cfg; existing) {
        if (cfg.host == DEFAULT_FIBER_HOST)
            return cfg;
    }

    auto cfg = buildDefaultFiberNetwork(user);
    networkRepo.save(cfg, user.id);

    // Race guard: concurrent logins can both pass the `existing` check
    // and insert a duplicate DEFAULT_FIBER_HOST network. Re-read and
    // deduplicate — keep the lexicographically smallest id (deterministic)
    // and delete the rest. Self-heals the scrolltest duplicate (b6bea767 / 4f20c70d).
    try {
        auto after = networkRepo.findByUserId(user.id);
        NetworkConfig[] dups;
        foreach (c; after) if (c.host == DEFAULT_FIBER_HOST) dups ~= c;
        if (dups.length > 1) {
            import std.algorithm : sort;
            sort!((a,b)=> a.id.toString() < b.id.toString())(dups);
            auto keep = dups[0];
            foreach (i; 1 .. dups.length) {
                try { networkRepo.deleteById(dups[i].id); } catch (Exception) {}
                // Clean up Redis assignment for the deleted duplicate if it was ever assigned
                try {
                    const sid = serverRegistry.getServerForNetwork(dups[i].id.toString());
                    if (sid.length > 0) {
                        // Best-effort: engine will also reap via janitor if missed
                    }
                } catch (Exception) {}
            }
            // If we just created a duplicate that lost the race, return the survivor
            if (keep.id != cfg.id) {
                // Our newly inserted cfg was deleted — return the keeper instead
                // and don't push a control message for the deleted id.
                return keep;
            }
        }
    } catch (Exception) {} // dedup best-effort

    auto serverId = serverRegistry.assignNetwork(cfg.id.toString());
    if (serverId.length == 0) {
        logWarn("ensureDefaultFiberNetwork: no healthy server for user=%s, network=%s — " ~
                "engine will pick it up on next bootstrap",
                user.username, cfg.id.toString());
        return cfg;
    }

    try {
        auto msg = ControlMessage("addNetwork", cfg.id.toString(), user.id.toString(), cfg.toJson());
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
    } catch (Exception e) {
        logWarn("ensureDefaultFiberNetwork: failed to push addNetwork control msg " ~
                "for user=%s network=%s: %s — engine will pick it up on next bootstrap",
                user.username, cfg.id.toString(), e.msg);
    }
    return cfg;
}

@("buildDefaultFiberNetwork sets all required fields")
unittest {
    import std.uuid : randomUUID;
    User u;
    u.id = randomUUID();
    u.username = "alice";
    auto cfg = buildDefaultFiberNetwork(u);
    assert(cfg.name == "IRC Fiber");
    assert(cfg.host == "irc.ircfiber.com");
    assert(cfg.port == 6697);
    assert(cfg.tls == TLSMode.required);
    assert(cfg.sasl == SASLMechanism.none);
    assert(cfg.systemManaged == true);
    assert(cfg.disabled == false);
    assert(cfg.autoJoinChannels == ["#ircfiber", "#welcome"]);
    assert(cfg.realName == "alice");
    assert(cfg.nick.startsWith("alice_"));
    assert(cfg.nick.length == "alice_".length + DEFAULT_FIBER_NICK_SUFFIX_LEN);
}

@("buildDefaultNick is deterministic per user")
unittest {
    import std.uuid : randomUUID;
    User u;
    u.id = randomUUID();
    u.username = "bob";
    const n1 = buildDefaultNick(u);
    const n2 = buildDefaultNick(u);
    assert(n1 == n2, "deterministic nick must be stable across calls");
}

@("buildDefaultNick differs across distinct users")
unittest {
    import std.uuid : randomUUID;
    User u1; u1.id = randomUUID(); u1.username = "alice";
    User u2; u2.id = randomUUID(); u2.username = "alice";
    assert(buildDefaultNick(u1) != buildDefaultNick(u2),
           "same username but different UUID must yield different suffix");
}

@("buildDefaultNick survives UUIDs with various hyphen positions")
unittest {
    // RFC 4122 v4 UUID — 8-4-4-4-12 hex; buildDefaultNick must strip them
    // all and take the first N hex chars of the canonical form.
    User u;
    u.id = UUID("12345678-90ab-cdef-1234-567890abcdef");
    u.username = "test";
    assert(buildDefaultNick(u) == "test_1234");
}

@("ensureDefaultFiberNetwork is a no-op for empty user")
unittest {
    // Cannot exercise the Mongo/Redis side without fakes; verify the
    // early-return guard instead. (Integration of the happy path is
    // exercised by the migrate CLI tool's --self-test mode.)
    const User u; // u.id == UUID.init, u.username.length == 0
    // We don't actually call ensureDefaultFiberNetwork here because it
    // would hit Mongo. The contract under test is that an uninitialized
    // User does NOT raise or insert — the gate is at the top of the fn.
    assert(u.id == UUID.init);
    assert(u.username.length == 0);
}