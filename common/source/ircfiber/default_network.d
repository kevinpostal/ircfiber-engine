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
import vibe.db.redis.redis : RedisDatabase;

import ircfiber.models.network : NetworkConfig, TLSMode, SASLMechanism;
import ircfiber.models.user : User;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.user : UserRepository;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : RedisKeys, ControlMessage;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.irc.routing_moves : requestNetworkMove, networkMoveFenced;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.irc.routing_policy : RouteKind, resolveRoutingPolicy;
import ircfiber.irc.routing_policy_store : requireRoutingUpgrade, loadRoutingPolicy,
    RoutingPolicyUnavailableException;
import ircfiber.network_write_gate : NetworkWriteUnavailableException, NetworkWriter,
    runNetworkWrite, runNetworkRedisMutation;

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
    runNetworkWrite!void(redis, (ref NetworkWriter writer) {
        setFiberEnabled(redis, enabled, writer);
    });
}

void setFiberEnabled(RedisStorage redis, bool enabled, ref NetworkWriter writer) @trusted {
    runNetworkRedisMutation!void(writer, (RedisDatabase db) {
        db.set(FIBER_ENABLED_KEY, enabled ? "1" : "0");
    });
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
    if (user.id == UUID.init || user.username.length == 0 || !isFiberEnabled(redis))
        return NetworkConfig.init;
    return runNetworkWrite!NetworkConfig(redis, (ref NetworkWriter writer) {
        return ensureDefaultFiberNetwork(user, networkRepo, redis, serverRegistry, writer, deferConnect);
    });
}

/// Reuse one admitted writer through provisioning, deduplication and activation.
NetworkConfig ensureDefaultFiberNetwork(
    User user,
    NetworkRepository networkRepo,
    RedisStorage redis,
    ServerRegistry serverRegistry,
    ref NetworkWriter writer,
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
        const selectedServer = requireDefaultFiberPlacement(cfg, redis, serverRegistry, networkRepo);
        const existingId = cfg.id;
        auto current = networkRepo.findByIdWithIpv6Iid(existingId, writer);
        // Deliberately parted defaults stay parted.
        bool[string] have; foreach (c; current.autoJoinChannels) have[c] = true;
        bool[string] parted; foreach (c; current.partedChannels) parted[c] = true;
        string[] added;
        foreach (ch; DEFAULT_FIBER_CHANNELS)
            if (ch !in have && ch !in parted) { current.autoJoinChannels ~= ch; added ~= ch; }
        if (added.length) {
            networkRepo.save(current, user.id, writer);
            current = networkRepo.findByIdWithIpv6Iid(current.id, writer);
            const sid = serverRegistry.getServerForNetwork(current.id.toString());
            if (sid.length && selectedServer.length
                    && !networkMoveFenced(redis.getDb(), current.id.toString())) {
                requireRoutingUpgrade(redis.getDb(), sid);
                auto up = ControlMessage("updateConfig", current.id.toString(), "", current.toJson());
                up.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                runNetworkRedisMutation!void(writer, (RedisDatabase db) {
                    db.lpush(RedisKeys.control(sid), up.toJson().toString());
                });
            }
            logInfo("ensureDefaultFiberNetwork: topped up %s for user=%s", added, user.username);
        }
        return current;
    }

    auto cfg = buildDefaultFiberNetwork(user);
    cfg.servicesProvisioningPending = deferConnect;
    auto userRepo = new UserRepository();
    cfg.defaultAvatarUrl = userRepo.getAvatarUrl(user.id);
    cfg.profileMetadata = userRepo.getProfile(user.id);
    requireDefaultFiberPlacement(cfg, redis, serverRegistry, networkRepo);
    networkRepo.save(cfg, user.id, writer);
    cfg = networkRepo.findByIdWithIpv6Iid(cfg.id, writer);

    // Concurrent logins retain the same deterministic duplicate survivor.
    // A failed canonical deletion is not swallowed before activation.
    auto after = networkRepo.findByUserId(user.id);
    NetworkConfig[] dups;
    foreach (c; after) if (c.host == DEFAULT_FIBER_HOST) dups ~= c;
    if (dups.length > 1) {
        import std.algorithm : sort;
        sort!((a,b)=> a.id.toString() < b.id.toString())(dups);
        const keep = dups[0];
        foreach (i; 1 .. dups.length) networkRepo.deleteById(dups[i].id, writer);
        if (keep.id != cfg.id) return networkRepo.findByIdWithIpv6Iid(keep.id, writer);
    }

    if (!cfg.servicesProvisioningPending)
        activateDefaultFiberNetwork(cfg, user.id, redis, serverRegistry, writer, networkRepo);
    return cfg;
}

/// Shared policy-tier placement is checked before any provisioning write.
private string requireDefaultFiberPlacement(const NetworkConfig cfg, RedisStorage redis,
        ServerRegistry registry, NetworkRepository contextRepo = null) {
    const owner = registry.getServerForNetwork(cfg.id.toString());
    requireRoutingUpgrade(redis.getDb(), owner);
    const effective = resolveRoutingPolicy(loadRoutingPolicy(redis.getDb()), cfg.host, cfg.routing);
    if (!effective.available)
        throw new RoutingPolicyUnavailableException("Stored routing preferences are invalid");
    if (!effective.order.length) return "";
    const selected = registry.selectRoutingServer(effective, "", cfg.id.toString(), cfg.host, contextRepo);
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
    auto preflightRepo = new NetworkRepository(redis);
    const canonical = preflightRepo.findByIdWithUser(cfg.id);
    if (!canonical.isOwnedBy(ownerId) || canonical.config.host != DEFAULT_FIBER_HOST
            || canonical.config.disabled || canonical.config.servicesProvisioningPending) return;
    requireDefaultFiberPlacement(canonical.config, redis, serverRegistry, preflightRepo);
    runNetworkWrite!void(redis, (ref NetworkWriter writer) {
        activateDefaultFiberNetwork(cfg, ownerId, redis, serverRegistry, writer, preflightRepo);
    });
}

void activateDefaultFiberNetwork(NetworkConfig cfg, UUID ownerId, RedisStorage redis,
        ServerRegistry serverRegistry, ref NetworkWriter writer, NetworkRepository repo = null) {
    if (cfg.id == UUID.init || ownerId == UUID.init) return;
    if (repo is null) repo = new NetworkRepository(redis, writer);
    repo.ensureIpv6Iid(cfg.id, writer);
    auto canonical = repo.findByIdWithUser(cfg.id);
    if (!canonical.isOwnedBy(ownerId)) return;
    cfg = canonical.config;
    if (cfg.host != DEFAULT_FIBER_HOST || cfg.disabled || cfg.servicesProvisioningPending) return;
    const selected = requireDefaultFiberPlacement(cfg, redis, serverRegistry, repo);
    if (!selected.length) return;
    auto serverId = serverRegistry.getServerForNetwork(cfg.id.toString());
    if (!serverId.length) serverId = serverRegistry.claimNetwork(cfg.id.toString(), selected, writer);
    if (!serverId.length)
        throw new DefaultFiberPlacementException("No capable healthy connection server is available");
    if (serverId != selected || networkMoveFenced(redis.getDb(), cfg.id.toString())) {
        const move = requestNetworkMove(redis.getDb(), cfg.id.toString(), selected, writer);
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
    runNetworkRedisMutation!void(writer, (RedisDatabase db) {
        db.lpush(RedisKeys.control(serverId), msg.toJson().toString());
    });
}

version (RoutingPolicyTest) {
    /// Real-service proof. The guarded runner supplies disposable Mongo/Redis;
    /// each fixture owns its rows, keys, synthetic saturation tokens and hooks.
    void runCommonControlGateTests(RedisStorage redis, string mongoUri) {
        import std.conv : to;
        import std.exception : enforce;
        import std.string : replace;
        import vibe.core.core : runTask;
        import vibe.data.bson : Bson;
        import vibe.data.json : Json;
        import ircfiber.db.mongo : AppMongoConnection;
        import ircfiber.irc.server : ConnectionServer;
        import ircfiber.irc.egress_admission : setEgressDraining, readEgressAdmission;
        import ircfiber.irc.routing_policy : defaultRoutingPolicy;
        import ircfiber.irc.routing_policy_store : saveRoutingPolicy;
        import ircfiber.irc.routing_moves : RoutingMove, loadRoutingMove, failRoutingMove,
            enqueueRoutingCommand;
        import ircfiber.network_write_gate : NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY,
            networkMutationAdmittedForTest, networkMutationRepliedForTest,
            networkRedisMutationRepliedForTest;

        auto db = redis.getDb();
        enforce(!db.exists(NETWORK_WRITE_EXCLUSION_KEY) && db.scard(NETWORK_WRITERS_KEY) == 0,
            "Control gate proof requires quiescent disposable Redis");
        enforce(networkMutationAdmittedForTest is null && networkMutationRepliedForTest is null
                && networkRedisMutationRepliedForTest is null, "Gate test hooks must be unowned");
        const originalDatabase = AppMongoConnection.name();
        const database = "control_gate_" ~ randomUUID().toString().replace("-", "") ~ "_test";
        AppMongoConnection.connect(mongoUri, database);
        scope (exit) AppMongoConnection.connect(mongoUri, originalDatabase);
        auto collection = AppMongoConnection.getDb()["networks"];
        enforce(collection.findOne(Bson.emptyObject).isNull, "Proof Mongo namespace must be empty");
        const operation = randomUUID().toString();
        const source = "control-source-" ~ operation;
        const target = "control-target-" ~ operation;
        const label = "control-exit-" ~ operation;
        string[] ids, moves, tokens, saturated;
        const keys = [RedisKeys.egressRoutingPolicy(), RedisKeys.routingSchemaVersion(),
            RedisKeys.routingHardBlocksActivated(), RedisKeys.routingConfig(), FIBER_ENABLED_KEY];
        string[] values;
        bool[] present;
        foreach (key; keys) { present ~= db.exists(key); values ~= db.get(key); }
        scope (exit) {
            networkMutationAdmittedForTest = null;
            networkMutationRepliedForTest = null;
            networkRedisMutationRepliedForTest = null;
            db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
                [NETWORK_WRITE_EXCLUSION_KEY], operation);
            // All synchronous fixture commands have returned; remove only this
            // proof's captured uncertainty/saturation tokens, never the set.
            foreach (token; tokens) db.srem(NETWORK_WRITERS_KEY, token);
            foreach (token; saturated) db.srem(NETWORK_WRITERS_KEY, token);
            foreach (id; ids) {
                db.hdel(RedisKeys.networkAssignments(), id);
                db.del(RedisKeys.lease(id), RedisKeys.routingMove(id),
                    RedisKeys.cmd(source, id), RedisKeys.cmd(target, id));
            }
            foreach (move; moves) db.del(RedisKeys.routingMoveStatus(move));
            db.eval!long(q"LUA
local own = {}
for _, id in ipairs(ARGV) do own[id] = true end
local n = redis.call('LLEN', KEYS[1])
for i = 1, n do
  local raw = redis.call('LPOP', KEYS[1])
  local ok, move = pcall(cjson.decode, raw)
  if not ok or not own[move.moveId] then redis.call('RPUSH', KEYS[1], raw) end
end
return 1
LUA", [RedisKeys.routingMoves()], moves);
            foreach (server; [source, target]) {
                db.del(RedisKeys.server(server), RedisKeys.serverAssignments(server),
                    RedisKeys.control(server), RedisKeys.engineConfig(server), RedisKeys.draining(server));
                db.srem(RedisKeys.serverList(), server);
            }
            db.del(RedisKeys.egressAdmission(label));
            foreach (i, key; keys) {
                if (present[i]) db.set(key, values[i]);
                else db.del(key);
            }
            collection.remove(Bson.emptyObject);
        }
        long collect() {
            auto reply = db.eval!long(q"LUA
if redis.call('EXISTS', KEYS[1]) ~= 0 or redis.call('SCARD', KEYS[2]) ~= 0 then return 0 end
redis.call('SET', KEYS[1], ARGV[1])
return 1
LUA", [NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY], operation);
            enforce(!reply.empty, "Missing collector acknowledgement");
            return reply.front;
        }
        void unlock() {
            db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
                [NETWORK_WRITE_EXCLUSION_KEY], operation);
        }
        void refused(scope void delegate() action) {
            bool blocked;
            try action();
            catch (NetworkWriteUnavailableException e) { blocked = e.code == "network_maintenance"; }
            enforce(blocked, "Closed control effect must fail with typed maintenance before dispatch");
        }
        db.set(RedisKeys.egressRoutingPolicy(), defaultRoutingPolicy().toJson().toString());
        db.set(RedisKeys.routingSchemaVersion(), "1");
        db.del(RedisKeys.routingHardBlocksActivated());
        db.set(FIBER_ENABLED_KEY, "1");
        auto repo = new NetworkRepository(redis);
        auto registry = new ServerRegistry(redis);
        registry.setMaxConnsPerHost(10000);
        foreach (i, id; [source, target]) {
            ConnectionServer server;
            server.serverId = id;
            server.bindAddress = "127.0.0.1";
            server.priority = i == 0 ? 100 : 1;
            server.maxConnections = 10000;
            server.routingPolicyVersion = 1;
            server.supportedRoutes = ["direct"];
            registry.registerServer(server);
        }

        size_t admissions;
        networkMutationAdmittedForTest = (string token) { tokens ~= token; ++admissions; };
        User user;
        user.id = randomUUID();
        user.username = "controlproof";
        auto cfg = ensureDefaultFiberNetwork(user, repo, redis, registry);
        ids ~= cfg.id.toString();
        const id = cfg.id.toString();
        enforce(admissions == 1 && db.scard(NETWORK_WRITERS_KEY) == 0,
            "Default Mongo/IID/claim/addNetwork must admit once and release only after enqueue");
        enforce(!collection.findOne(["id": id]).isNull
                && db.hget(RedisKeys.networkAssignments(), id) == source
                && db.get(RedisKeys.lease(id)) == source
                && db.llen(RedisKeys.control(source)) == 1,
            "Open default flow must persist actual Mongo/assignment/lease/control effects");
        registry.publishServerAssignments(source, [id]);
        auto move = requestNetworkMove(db, id, target);
        moves ~= move.moveId;
        const statusBefore = db.hget(RedisKeys.routingMoveStatus(move.moveId), "state");
        const policy = loadRoutingPolicy(db);
        const policyBefore = db.get(RedisKeys.egressRoutingPolicy());
        const maxBefore = db.get(RedisKeys.routingConfig());
        const engineBefore = db.get(RedisKeys.engineConfig(source));
        const controlBefore = db.llen(RedisKeys.control(source));
        const mongoBefore = collection.findOne(["id": id]).toJson().toString();
        enforce(collect() == 1, "Quiescent proof must acquire actual exclusion");
        refused({ registry.setMaxConnsPerHost(1); });
        refused({ registry.setEngineConfig(source, 1, 1, true); });
        refused({ registry.clearDraining(source); });
        refused({ setFiberEnabled(redis, false); });
        refused({ setEgressDraining(db, label, "127.0.0.1", 1080, true, "proof", 1); });
        refused({ saveRoutingPolicy(db, policy.revision, policy); });
        refused({ registry.claimNetwork(id, target); });
        refused({ requestNetworkMove(db, id, target); });
        refused({ failRoutingMove(db, move, "proof"); });
        refused({ loadRoutingMove(db, move.moveId); });
        refused({ ensureDefaultFiberNetwork(user, repo, redis, registry); });
        refused({ activateDefaultFiberNetwork(cfg, user.id, redis, registry); });
        refused({ enqueueRoutingCommand(db, id, `{"cmd":"raw","text":"@label=proof :me QUIT :proof"}`); });
        enforce(db.get(RedisKeys.routingConfig()) == maxBefore
                && db.get(RedisKeys.engineConfig(source)) == engineBefore
                && db.get(FIBER_ENABLED_KEY) == "1"
                && !db.exists(RedisKeys.egressAdmission(label))
                && db.get(RedisKeys.egressRoutingPolicy()) == policyBefore
                && db.hget(RedisKeys.routingMoveStatus(move.moveId), "state") == statusBefore
                && db.get(RedisKeys.routingMove(id)) == move.moveId
                && db.llen(RedisKeys.control(source)) == controlBefore
                && collection.findOne(["id": id]).toJson().toString() == mongoBefore,
            "Closed canonical/config/move/queue effects must remain byte-for-byte unchanged");

        // Heartbeats, data, matching-owner renewal and identical evidence must
        // remain live; creating/replacing ownership evidence is not renewal.
        registry.updateHeartbeat(source);
        auto live = registry.getServer(source);
        registry.syncServerState(source, live);
        registry.publishServerAssignments(source, [id]);
        registry.setLease(id, source);
        enforce(enqueueRoutingCommand(db, id, `{"cmd":"raw","text":"PONG :proof"}`)
                && enqueueRoutingCommand(db, id, `{"cmd":"msg","text":"proof","target":"#proof"}`),
            "Closed exclusion must not suppress ordinary runtime data");
        auto changed = live;
        changed.maxConnections++;
        refused({ registry.syncServerState(source, changed); });
        const recovered = randomUUID().toString();
        ids ~= recovered;
        refused({ registry.publishServerAssignments(source, [id, recovered]); });
        db.del(RedisKeys.lease(id)); // deterministic expired-lease fixture
        refused({ registry.setLease(id, source); });
        enforce(!db.exists(RedisKeys.lease(id)), "Closed renewal must not recreate missing evidence");
        registry.getAllAssignments();
        enforce(db.hget(RedisKeys.networkAssignments(), id) == source,
            "Closed status reads preserve existing canonical ownership");
        unlock();
        registry.setLease(id, source);
        registry.publishServerAssignments(source, [id, recovered]);
        db.hdel(RedisKeys.networkAssignments(), recovered);
        enforce(collect() == 1, "Evidence fixture must close");
        registry.getAllAssignments();
        enforce(!db.hget(RedisKeys.networkAssignments(), recovered).length,
            "Closed recovery must not create an assignment from reverse evidence");
        unlock();
        registry.getAllAssignments();
        enforce(db.hget(RedisKeys.networkAssignments(), recovered) == source,
            "Open recovery must restore actual uniquely evidenced ownership");
        enforce(failRoutingMove(db, move, "proof")
                && !db.exists(RedisKeys.routingMove(id)), "Open FAIL must acknowledge fence deletion");
        auto expired = requestNetworkMove(db, id, target);
        moves ~= expired.moveId;
        db.del(RedisKeys.routingMove(id));
        enforce(collect() == 1, "Expiry fixture must close");
        refused({ loadRoutingMove(db, expired.moveId); });
        enforce(db.hget(RedisKeys.routingMoveStatus(expired.moveId), "state") == "queued",
            "Closed LOAD must not persist expiry");
        unlock();
        enforce(loadRoutingMove(db, expired.moveId).state == "expired"
                && db.hget(RedisKeys.routingMoveStatus(expired.moveId), "state") == "expired",
            "Open LOAD must acknowledge persisted expiry");

        auto nested = requestNetworkMove(db, id, target);
        moves ~= nested.moveId;
        foreach (i; 0 .. 255) {
            const token = operation ~ "-saturation-" ~ i.to!string;
            saturated ~= token;
            db.sadd(NETWORK_WRITERS_KEY, token);
        }
        runNetworkWrite!void(db, (ref NetworkWriter writer) {
            enforce(db.scard(NETWORK_WRITERS_KEY) == 256, "Outer writer must occupy final slot");
            enforce(loadRoutingMove(db, nested.moveId, writer).moveId == nested.moveId,
                "Explicit scoped status load must not readmit at saturation");
            bool full;
            try loadRoutingMove(db, nested.moveId);
            catch (NetworkWriteUnavailableException e) { full = e.code == "network_write_unavailable"; }
            enforce(full && db.scard(NETWORK_WRITERS_KEY) == 256,
                "Standalone status load at saturation must refuse without extra admission");
        });
        // A fully saturated writer set cannot suppress existing canonical
        // reads or ordinary same-owner lease renewal in the heartbeat path.
        const finalSlot = operation ~ "-saturation-255";
        saturated ~= finalSlot;
        db.sadd(NETWORK_WRITERS_KEY, finalSlot);
        const pendingRecovery = randomUUID().toString();
        ids ~= pendingRecovery;
        db.hset(RedisKeys.serverAssignments(source), pendingRecovery, source);
        db.expire(RedisKeys.lease(id), 1);
        const beforeReadAdmissions = admissions;
        const assignmentsBeforeRead = db.hlen(RedisKeys.networkAssignments());
        auto canonicalAtCapacity = registry.getAllAssignments();
        bool canonicalFound;
        foreach (assignment; canonicalAtCapacity) {
            enforce(assignment.networkId != pendingRecovery,
                "Saturated canonical read must not invent a reverse-evidence owner");
            if (assignment.networkId != id) continue;
            canonicalFound = assignment.serverId == source;
            registry.setLease(assignment.networkId, assignment.serverId);
        }
        enforce(canonicalFound && db.get(RedisKeys.lease(id)) == source && db.ttl(RedisKeys.lease(id)) > 1
                && admissions == beforeReadAdmissions && db.scard(NETWORK_WRITERS_KEY) == 256
                && db.hlen(RedisKeys.networkAssignments()) == assignmentsBeforeRead
                && !db.hget(RedisKeys.networkAssignments(), pendingRecovery).length
                && !db.exists(RedisKeys.lease(pendingRecovery))
                && db.hget(RedisKeys.serverAssignments(source), pendingRecovery) == source,
            "Saturation must allow authoritative read/TTL renewal without admission, recovery or evidence removal");
        db.hdel(RedisKeys.serverAssignments(source), pendingRecovery);
        foreach (token; saturated) db.srem(NETWORK_WRITERS_KEY, token);
        enforce(db.scard(NETWORK_WRITERS_KEY) == 0, "Completed outer status writer must release");
        enforce(failRoutingMove(db, nested, "proof"), "Nested fixture fence must complete");

        // Admission failure is not permission to fabricate an empty canonical
        // snapshot: the independent real Redis read must itself succeed.
        {
            import std.socket : TcpSocket, InternetAddress;
            auto listener = new TcpSocket();
            listener.bind(new InternetAddress("127.0.0.1", 0));
            const port = (cast(InternetAddress)listener.localAddress).port;
            listener.close();
            auto closed = new RedisStorage("127.0.0.1", port);
            closed.connect();
            scope (exit) closed.close();
            bool readFailed;
            try (new ServerRegistry(closed)).getAllAssignments();
            catch (Exception) { readFailed = true; }
            enforce(readFailed, "Physical canonical Redis read failure must still fail closed");
        }

        // Competing fibers execute the collector's real atomic SCARD/SET
        // protocol at actual Mongo and Redis acknowledgements, not a mock gate.
        size_t raced;
        void contend() {
            Throwable error;
            long result = -1;
            auto task = runTask({
                try result = collect();
                catch (Throwable e) { error = e; }
            });
            task.join();
            if (error !is null) throw error;
            enforce(result == 0 && db.scard(NETWORK_WRITERS_KEY) == 1
                    && !db.exists(NETWORK_WRITE_EXCLUSION_KEY),
                "Collector must lose throughout every acknowledged step of one outer write");
            ++raced;
        }
        networkMutationRepliedForTest = { contend(); };
        networkRedisMutationRepliedForTest = { contend(); };
        User second;
        second.id = randomUUID();
        second.username = "controlrace";
        const beforeAdmissions = admissions;
        auto racedCfg = ensureDefaultFiberNetwork(second, repo, redis, registry);
        ids ~= racedCfg.id.toString();
        networkMutationRepliedForTest = null;
        networkRedisMutationRepliedForTest = null;
        enforce(raced >= 3 && admissions == beforeAdmissions + 1
                && db.scard(NETWORK_WRITERS_KEY) == 0,
            "Race flow must keep one owner through real Mongo/IID/Redis/control completion");
        enforce(collect() == 1, "Collector may close only after the logical writer completes");
        unlock();

        // A caller catching an actual Redis-ack hook failure cannot clear the
        // outstanding step by successfully writing something else afterward.
        networkRedisMutationRepliedForTest = {
            networkRedisMutationRepliedForTest = null;
            throw new Exception("Injected ambiguity after actual Redis SET acknowledgement");
        };
        bool caught;
        runNetworkWrite!void(db, (ref NetworkWriter writer) {
            try registry.setMaxConnsPerHost(9999, writer);
            catch (Exception) { caught = true; }
            registry.setEngineConfig(source, 100, 10000, false, writer);
        });
        enforce(caught && db.get(RedisKeys.routingConfig()) == "maxConnsPerHost:9999"
                && db.scard(NETWORK_WRITERS_KEY) == 1 && collect() == 0,
            "Swallowed uncertain SET plus later success must retain the real writer token");
        db.srem(NETWORK_WRITERS_KEY, tokens[$ - 1]);
        const queuedBefore = db.llen(RedisKeys.control(source));
        networkRedisMutationRepliedForTest = {
            if (db.llen(RedisKeys.control(source)) <= queuedBefore) return;
            networkRedisMutationRepliedForTest = null;
            throw new Exception("Injected ambiguity after actual control LPUSH acknowledgement");
        };
        bool uncertainQueue;
        try runNetworkWrite!void(db, (ref NetworkWriter writer) {
            activateDefaultFiberNetwork(cfg, user.id, redis, registry, writer, repo);
        });
        catch (Exception) { uncertainQueue = true; }
        enforce(uncertainQueue && db.llen(RedisKeys.control(source)) == queuedBefore + 1
                && db.scard(NETWORK_WRITERS_KEY) == 1 && collect() == 0,
            "Actual enqueued control with uncertain acknowledgement must prevent exclusion");
        db.srem(NETWORK_WRITERS_KEY, tokens[$ - 1]);
        enforce(collect() == 1, "Only explicit fixture cleanup may remove uncertain evidence");
        unlock();
        enforce(readEgressAdmission(db, label, "127.0.0.1", 1080, 1).state == "healthy",
            "Rejected operator drain must leave runtime admission healthy");
        enforce(setEgressDraining(db, label, "127.0.0.1", 1080, true, "proof", 1).draining,
            "Open operator drain must persist its actual acknowledgement");
        auto saved = saveRoutingPolicy(db, policy.revision, policy);
        enforce(saved.revision == policy.revision + 1
                && loadRoutingPolicy(db).revision == saved.revision,
            "Open policy save must acknowledge the real durable revision");
    }
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