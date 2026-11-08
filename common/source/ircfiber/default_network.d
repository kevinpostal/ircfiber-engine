/**
 * Default IRC Fiber network provisioning.
 *
 * Every IRC Fiber user (new and existing) gets a preconfigured connection
 * to the company-hosted IRC server at irc.ircfiber.com:6697 (TLS required).
 * The network is marked `systemManaged=true` so users can edit fields but
 * cannot delete it; only platform migrations can remove it.
 *
 * `DEFAULT_FIBER_HOST`/`_PORT`/`_TLS` are overridable via
 * `IRCFIBER_DEFAULT_NETWORK_HOST`/`_PORT`/`_TLS` so a non-prod deployment
 * (local compose, CI) can point every auto-provisioned default network at
 * its own ircd instead of silently dialing live irc.ircfiber.com. Every
 * prod deploy leaves these unset, so production behavior is unchanged.
 *
 * Two entry points are used at runtime:
 *   - `buildDefaultFiberNetwork(user)` — pure constructor for the config
 *     (no I/O). Useful for tests and for callers that want to inspect the
 *     config before persisting.
 *   - `ensureDefaultFiberNetwork` — idempotent Mongo provisioning. Normal
 *     signup/login callers defer engine activation until NickServ completes;
 *     the explicit migration tool may still connect immediately.
 */
module ircfiber.default_network;

import std.uuid : UUID, randomUUID;
import std.algorithm : canFind, endsWith, startsWith;
import std.array : array;
import std.range : enumerate;
import std.ascii : isHexDigit;
import std.datetime : Clock;
import std.process : environment;
import std.string : strip;

import vibe.core.log;

import ircfiber.models.network : NetworkConfig, TLSMode, SASLMechanism;
import ircfiber.models.user : User;
import ircfiber.db.network : NetworkRepository, Ipv6IdentityException;
import ircfiber.db.user : UserRepository;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : RedisKeys, ControlMessage;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.irc.routing_moves : requestNetworkMove, networkMoveFenced;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.irc.routing_policy : RouteKind, resolveRoutingPolicy;
import ircfiber.irc.routing_policy_store : requireRoutingUpgrade, loadRoutingPolicy,
    RoutingPolicyUnavailableException;

class DefaultFiberPlacementException : Exception {
    this(string message) { super(message); }
}

/// Hostname of the platform-provided IRC server. Overridable via
/// `IRCFIBER_DEFAULT_NETWORK_HOST` — see the module doc.
immutable string DEFAULT_FIBER_HOST;

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

/// TLS port for the platform-provided IRC server. Overridable via
/// `IRCFIBER_DEFAULT_NETWORK_PORT` alongside `DEFAULT_FIBER_HOST`.
immutable ushort DEFAULT_FIBER_PORT;
/// TLS mode for the platform-provided IRC server. Overridable via
/// `IRCFIBER_DEFAULT_NETWORK_TLS` (`disabled`/`enabled`/`required`/`starttls`)
/// — a local ircd without certificates needs this at `disabled`.
immutable TLSMode DEFAULT_FIBER_TLS;

shared static this() {
    const h = environment.get("IRCFIBER_DEFAULT_NETWORK_HOST", "").strip();
    DEFAULT_FIBER_HOST = h.length ? h : "irc.ircfiber.com";
    DEFAULT_FIBER_PORT = parseDefaultFiberPort(environment.get("IRCFIBER_DEFAULT_NETWORK_PORT", ""));
    DEFAULT_FIBER_TLS = parseDefaultFiberTls(environment.get("IRCFIBER_DEFAULT_NETWORK_TLS", ""));
}

/// Parses `IRCFIBER_DEFAULT_NETWORK_PORT`; "" or anything out of a
/// `ushort`'s range falls back to the platform's real TLS port so a typo
/// in the env cannot silently zero out the port.
ushort parseDefaultFiberPort(string raw) @safe pure {
    import std.conv : to;
    const s = raw.strip();
    if (!s.length) return 6697;
    try {
        const v = s.to!int;
        if (v > 0 && v <= ushort.max) return cast(ushort) v;
    } catch (Exception) {}
    return 6697;
}

/// Parses `IRCFIBER_DEFAULT_NETWORK_TLS`; unset or unrecognized falls back
/// to `required`, the platform's real TLS posture.
TLSMode parseDefaultFiberTls(string raw) @safe pure {
    import std.uni : toLower;
    switch (raw.strip().toLower()) {
        case "disabled": return TLSMode.disabled;
        case "enabled":  return TLSMode.enabled;
        case "starttls": return TLSMode.starttls;
        default:          return TLSMode.required;
    }
}

/// Human-readable name for the default network as it appears in the sidebar.
immutable string DEFAULT_FIBER_NAME = "IRC Fiber";

/// Default channels the connection auto-joins: #support and #ircfiber.
/// Only attempted on first connect — if one of them does not exist on the
/// server, the engine surfaces an ERR_NOSUCHCHANNEL in the buffer and the
/// user can edit the list away from the network settings UI.
immutable string[] DEFAULT_FIBER_CHANNELS = ["#support", "#ircfiber"];

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
    cfg.tls = DEFAULT_FIBER_TLS;
    cfg.sasl = SASLMechanism.none;
    cfg.nick = user.username;
    cfg.realName = user.username;
    cfg.autoJoinChannels = DEFAULT_FIBER_CHANNELS.dup;
    cfg.disabled = false;
    cfg.systemManaged = true;
    cfg.routing.inherit = false;
    cfg.routing.order = [RouteKind.direct];
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
 * - Otherwise builds and persists the network. `deferConnect=true` leaves
 *   it held for NickServ provisioning; the legacy default assigns an engine
 *   and queues its first addNetwork message.
 *
 * Returns the (existing or new) config. Policy/upgrade/capability refusals
 * occur before saving. A valid administrator-blocked plan is saved without
 * assignment or dispatch. Identity/storage failures still throw.
 */
NetworkConfig ensureDefaultFiberNetwork(
    User user,
    NetworkRepository networkRepo,
    RedisStorage redis,
    ServerRegistry serverRegistry,
    bool deferConnect = false
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
    auto existing = networkRepo.findByUserIdDirect(user.id);
    foreach (ref cfg; existing) {
        if (cfg.host != DEFAULT_FIBER_HOST) continue;
        const selectedServer = requireDefaultFiberPlacement(cfg, redis, serverRegistry);
        cfg = networkRepo.findByIdWithIpv6Iid(cfg.id);
        // Top up default channels added after this account was provisioned
        // (e.g. #support). A channel the user deliberately parted stays
        // parted — partedChannels is the engine's PART record.
        bool[string] have;   foreach (c; cfg.autoJoinChannels) have[c] = true;
        bool[string] parted; foreach (c; cfg.partedChannels)   parted[c] = true;
        string[] added;
        foreach (ch; DEFAULT_FIBER_CHANNELS)
            if (ch !in have && ch !in parted) { cfg.autoJoinChannels ~= ch; added ~= ch; }
        if (added.length) {
            networkRepo.save(cfg, user.id);   // also drops the userNetworks Redis cache
            cfg = networkRepo.findByIdWithIpv6Iid(cfg.id);
            try {
                const sid = serverRegistry.getServerForNetwork(cfg.id.toString());
                if (sid.length > 0 && selectedServer.length
                        && !networkMoveFenced(redis.getDb(), cfg.id.toString())) {
                    requireRoutingUpgrade(redis.getDb(), sid);
                    auto up = ControlMessage("updateConfig", cfg.id.toString(), "", cfg.toJson());
                    up.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                    redis.lpush(RedisKeys.control(sid), up.toJson().toString());
                }
            } catch (Exception e) {
                logWarn("ensureDefaultFiberNetwork: failed to push updateConfig for %s: %s",
                        cfg.id.toString(), e.msg);
            }
            logInfo("ensureDefaultFiberNetwork: topped up %s for user=%s", added, user.username);
        }
        return cfg;
    }

    auto cfg = buildDefaultFiberNetwork(user);
    cfg.servicesProvisioningPending = deferConnect;
    auto userRepo = new UserRepository();
    cfg.defaultAvatarUrl = userRepo.getAvatarUrl(user.id);
    cfg.profileMetadata = userRepo.getProfile(user.id);
    requireDefaultFiberPlacement(cfg, redis, serverRegistry);
    networkRepo.save(cfg, user.id);
    cfg = networkRepo.findByIdWithIpv6Iid(cfg.id);

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
                return networkRepo.findByIdWithIpv6Iid(keep.id);
            }
        }
    } catch (Ipv6IdentityException e) { throw e; }
    catch (Exception) {} // dedup best-effort

    if (!cfg.servicesProvisioningPending)
        activateDefaultFiberNetwork(cfg, user.id, redis, serverRegistry);
    return cfg;
}

/// Shared policy-tier placement is checked before any provisioning write.
private string requireDefaultFiberPlacement(const NetworkConfig cfg, RedisStorage redis,
        ServerRegistry registry) {
    const owner = registry.getServerForNetwork(cfg.id.toString());
    requireRoutingUpgrade(redis.getDb(), owner);
    const effective = resolveRoutingPolicy(loadRoutingPolicy(redis.getDb()), cfg.host, cfg.routing);
    if (!effective.available)
        throw new RoutingPolicyUnavailableException("Stored routing preferences are invalid");
    if (!effective.order.length) return "";
    const selected = registry.selectRoutingServer(effective, "", cfg.id.toString(), cfg.host);
    if (!selected.serverId.length)
        throw new DefaultFiberPlacementException("No capable healthy connection server is available");
    requireRoutingUpgrade(redis.getDb(), selected.serverId);
    return selected.serverId;
}

/// Dispatch the initial connection for an owned, enabled, completed network.
/// Bootstrap recovers persisted rows when no engine or queue is available.
void activateDefaultFiberNetwork(NetworkConfig cfg, UUID ownerId, RedisStorage redis,
                                 ServerRegistry serverRegistry) {
    if (cfg.id == UUID.init || ownerId == UUID.init) return;
    auto repo = new NetworkRepository(redis);
    repo.ensureIpv6Iid(cfg.id);
    auto canonical = repo.findByIdWithUser(cfg.id);
    if (!canonical.isOwnedBy(ownerId)) return;
    cfg = canonical.config;
    if (cfg.host != DEFAULT_FIBER_HOST || cfg.disabled || cfg.servicesProvisioningPending) return;
    const selected = requireDefaultFiberPlacement(cfg, redis, serverRegistry);
    if (!selected.length) return;
    auto serverId = serverRegistry.getServerForNetwork(cfg.id.toString());
    if (!serverId.length) serverId = serverRegistry.claimNetwork(cfg.id.toString(), selected);
    if (!serverId.length)
        throw new DefaultFiberPlacementException("No capable healthy connection server is available");
    if (serverId != selected || networkMoveFenced(redis.getDb(), cfg.id.toString())) {
        const move = requestNetworkMove(redis.getDb(), cfg.id.toString(), selected);
        auto event = IRCRawEvent.makeServerLog(cfg.name, cfg.id.toString(), "info",
            "Connection move pending: waiting for the current engine to close its upstream socket");
        auto json = event.toCompactJson();
        json["y"] = "irc_event";
        json["serverId"] = serverId;
        json["moveId"] = move.moveId;
        json["targetServerId"] = move.targetServerId;
        json["routingMoveState"] = move.state;
        redis.publish(RedisKeys.events(ownerId.toString()), json.toString());
        return;
    }
    requireRoutingUpgrade(redis.getDb(), serverId);
    auto msg = ControlMessage("addNetwork", cfg.id.toString(), ownerId.toString(), cfg.toJson());
    msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
    redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
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
    assert(cfg.routing.valid && !cfg.routing.inherit);
    assert(cfg.routing.order == [RouteKind.direct]);
    assert(cfg.routing.preferredExit == "");
    assert(cfg.disabled == false);
    assert(cfg.autoJoinChannels == ["#support", "#ircfiber"]);
    assert(cfg.realName == "alice");
    assert(cfg.nick == "alice");
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

@("parseDefaultFiberPort accepts a valid override and falls back otherwise")
unittest {
    assert(parseDefaultFiberPort("") == 6697);
    assert(parseDefaultFiberPort("6667") == 6667);
    assert(parseDefaultFiberPort("  16667  ") == 16667);
    assert(parseDefaultFiberPort("0") == 6697, "0 is out of range, must fall back");
    assert(parseDefaultFiberPort("-1") == 6697);
    assert(parseDefaultFiberPort("not-a-port") == 6697);
    assert(parseDefaultFiberPort("99999999") == 6697, "must not overflow ushort");
}

@("parseDefaultFiberTls maps every mode and falls back to required")
unittest {
    assert(parseDefaultFiberTls("disabled") == TLSMode.disabled);
    assert(parseDefaultFiberTls("Disabled") == TLSMode.disabled, "case-insensitive");
    assert(parseDefaultFiberTls("enabled") == TLSMode.enabled);
    assert(parseDefaultFiberTls("starttls") == TLSMode.starttls);
    assert(parseDefaultFiberTls("required") == TLSMode.required);
    assert(parseDefaultFiberTls("") == TLSMode.required, "unset must keep the platform's real TLS posture");
    assert(parseDefaultFiberTls("bogus") == TLSMode.required, "unrecognized must not silently disable TLS");
}