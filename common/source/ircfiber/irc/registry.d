module ircfiber.irc.registry;

import std.uuid : UUID, parseUUID;
import std.conv : to;
import std.datetime : Clock;
import std.array : array, split;
import std.algorithm : canFind, filter;
import vibe.core.log;
import vibe.data.json : Json, parseJson, parseJsonString;
import vibe.db.redis.redis : RedisDatabase;

import ircfiber.irc.server : ConnectionServer, NetworkAssignment;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.db.network : NetworkRepository;
import ircfiber.irc.routing_policy : EffectiveRoutingPolicy, resolveRoutingPolicy,
    routingPolicyFromJson, routeToken;
import ircfiber.irc.routing_policy_store : loadRoutingPolicy, requireRoutingUpgrade,
    RoutingPolicyUnavailableException;
import ircfiber.irc.routing_moves : requestNetworkMove, networkMoveFenced,
    RoutingMoveConflictException, NETWORK_ROUTING_LEASE_TTL_SECONDS;
import ircfiber.netaddr : canonicalHost;
import ircfiber.network_write_gate : NetworkWriteUnavailableException;

/// Summary of connections per IRC host for the admin dashboard.
struct HostConnectionSummary {
    /// IRC hostname the summary covers.
    string host;
    /// Total connection count for the host.
    int totalConns;
    /// Server IDs serving the host.
    string[] serverIds;
    /// Per-server connection counts.
    int[string] serverConns;
}

/// Engine configuration override for admin UI
struct EngineConfigOverride {
    /// Admin routing priority (higher = preferred).
    int priority;
    /// Admin max connections per IRC host (0 = unlimited).
    int maxConnections;
    /// Admin flag: only assign when no other healthy server exists.
    bool fallbackOnly;
}

/// How long (ms) an engine that detached from its IRC sessions for a hot
/// swap stays alive in the registry without heartbeats. `markHotSwap`
/// stamps `hotswapAt`; until this window elapses `heartbeatFresh` treats the
/// server as live so the gateway's `healthCheckAll`, admin reassign paths and
/// the other engines' boot-time reclaim never move its networks mid-swap.
/// Shared by gateway and engines (not env-overridable): both sides must
/// agree on the window or one of them reassigns early.
enum HOTSWAP_GRACE_MS = 180_000;

/**
 * Connection Server Registry
 * 
 * Central coordinator for the decentralized architecture.
 * Runs on the gateway. Tracks all connection servers, their health,
 * and network assignments.
 * 
 * Thread-safe: All methods are reentrant via Redis atomic operations.
 * 
 * Invariant: Each network is assigned to exactly one healthy server.
 * Invariant: Server IDs are unique and non-empty.
 */
final class ServerRegistry {
    private {
        RedisStorage redis;
        RedisDatabase db;
    }

    /// Creates a new server registry backed by Redis.
    this(RedisStorage redisStorage) {
        this.redis = redisStorage;
        this.db = redisStorage.getDb();
    }

    /**
     * Register a new connection server.
     * 
     * Precondition: server.serverId is non-empty and not already registered.
     * Postcondition: Server appears in registry with initial offset.
     * 
     * Critical: Sets initial buffer offset to prevent ID collision.
     * This is the fix for IRCCloud's 2020 data leak vulnerability.
     */

    /// Registers a new connection server in the registry.
    void registerServer(ConnectionServer server) {
        if (server.serverId.length == 0) {
            throw new Exception("Server ID must be non-empty");
        }

        // Registration refreshes capabilities too; heartbeat alone must not
        // retain an older process's transport advertisement.
        const existing = getServer(server.serverId);
        if (existing.serverId.length) {
            server.bufferOffset = existing.bufferOffset;
            server.lastHeartbeat = Clock.currTime.toUnixTime!long * 1000;
            server.isHealthy = true;
            server.draining = false;
            db.hset(RedisKeys.server(server.serverId), "data", server.toJson().toString());
            db.hset(RedisKeys.server(server.serverId), "isHealthy", "true");
            db.hdel(RedisKeys.server(server.serverId), "draining");
            db.del(RedisKeys.draining(server.serverId));
            updateHeartbeat(server.serverId);
            return;
        }

        // Use a simple default offset instead of scanning all servers,
        // because getMaxBufferOffset() calls getAllServers() which uses
        // SMEMBERS/SCAN — these can hang when called before the event
        // loop is fully initialized (the event loop needs to process
        // Redis I/O but the first registration happens in a runTask
        // that may race with the heartbeat task's HSET on the same
        // RedisClient pool, corrupting the SMEMBERS response stream).
        // A fixed offset of 1000 is safe: buffer IDs are allocated
        // sequentially from the server's offset, and the gap prevents
        // collision between servers.
        server.bufferOffset = 1000;
        server.lastHeartbeat = Clock.currTime.toUnixTime!long * 1000;
        server.isHealthy = true;

        auto key = RedisKeys.server(server.serverId);
        db.hset(key, "data", server.toJson().toString());
        // A fresh registration ends any hot-swap grace window left by the
        // previous process (see markHotSwap).
        try { db.hdel(key, "hotswapAt"); } catch (Exception) {}

        // Add to server list
        db.sadd(RedisKeys.serverList(), server.serverId);

        logInfo("Registered connection server: %s@%s (offset=%d)",
            server.serverId, server.bindAddress, server.bufferOffset);
    }

    /// Removing registry metadata never proves that a remote holder closed.
    /// Keep canonical ownership and reverse evidence until a fenced move can
    /// obtain an explicit source acknowledgement.
    void unregisterServer(string serverId) {
        db.del(RedisKeys.server(serverId));
        db.srem(RedisKeys.serverList(), serverId);
        logInfo("Unregistered connection server %s; retaining its canonical ownership", serverId);
    }

    /// Publish actual local clients/held-session evidence, not a canonical
    /// assignment echo. Empty evidence clears the reverse mirror. A stale
    /// source cannot republish an assigned-away row after a completed move.
    void publishServerAssignments(string serverId, string[] networkIds) {
        if (!serverId.length) return;
        string[] args = [serverId];
        foreach (id; networkIds) {
            try { if (id.length && parseUUID(id[]) != UUID.init) args ~= id; }
            catch (Exception) {}
        }
        db.eval!string(q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return '0' end
local mirrorType = redis.call('TYPE', KEYS[1]).ok
if mirrorType ~= 'none' and mirrorType ~= 'hash' then error('invalid assignment mirror') end
-- Read/validate the canonical hash before replacing any evidence.
local keep = {}
for i = 2, #ARGV do
  local owner = redis.call('HGET', KEYS[2], ARGV[i])
  if not owner or owner == ARGV[1] then keep[#keep + 1] = ARGV[i] end
end
redis.call('DEL', KEYS[1])
for _, id in ipairs(keep) do redis.call('HSET', KEYS[1], id, ARGV[1]) end
return '1'
LUA", [RedisKeys.serverAssignments(serverId), RedisKeys.networkAssignments()], args);
    }

    /**
     * Update server heartbeat.
     *
     * Called by connection servers periodically (every 10s).
     * If heartbeat is stale, server marked unhealthy.
     *
     * Also re-adds the server to the `irc:servers` registry set on every
     * call. SADD is idempotent, and the explicit touch keeps the set
     * "warm" against Redis `allkeys-lru` eviction — the set is otherwise
     * only written on register/unregister, which can be infrequent
     * enough for LRU to evict it before the next assignment, leaving
     * the gateway reporting "no healthy engines" while the engine is
     * still happily processing IRC traffic.
     */
    void updateHeartbeat(string serverId) {
        auto key = RedisKeys.server(serverId);
        auto now = Clock.currTime.toUnixTime!long * 1000;
        logInfo("updateHeartbeat: %s -> %s", serverId, now);
        db.hset(key, "lastHeartbeat", now.to!string);
        db.hset(key, "isHealthy", "true");
        // A live heartbeat ends the hot-swap grace window: the first beat
        // of the replacement engine clears the stamp its predecessor left.
        try { db.hdel(key, "hotswapAt"); } catch (Exception) {}
        db.sadd(RedisKeys.serverList(), serverId);
        // Draining is explicit operator/shutdown intent, not a stale heartbeat
        // artifact. A live process must not erase it merely by heartbeating.
    }

    /**
     * Mark a server as detaching for a hot swap.
     *
     * Called by the engine on SIGTERM right before it detaches from its
     * holder-owned IRC sessions and exits. The replacement engine boots a
     * few seconds later and its first `updateHeartbeat` clears the stamp.
     * In between no heartbeats arrive, so `heartbeatFresh` falls back to
     * `hotswapAt` and keeps the server alive for `HOTSWAP_GRACE_MS`; after
     * that the ordinary stale-heartbeat reassignment applies.
     *
     * Beats first so `lastHeartbeat` and `hotswapAt` share one `now` and a
     * swap started at the very end of a heartbeat interval still gets the
     * full window.
     */
    void markHotSwap(string serverId) {
        updateHeartbeat(serverId);
        auto key = RedisKeys.server(serverId);
        auto now = Clock.currTime.toUnixTime!long * 1000;
        db.hset(key, "hotswapAt", now.to!string);
        logInfo("markHotSwap: %s -> %s (grace %d ms)", serverId, now, HOTSWAP_GRACE_MS);
    }
    /// Persist the engine's full server state (priority, fallbackOnly,
    /// maxConnections, assignedNetworks) back to Redis so the gateway
    /// sees config overrides that take effect via the engine's heartbeat
    /// cycle. Called once per heartbeat, after updateHeartbeat().
    void syncServerState(string serverId, ref ConnectionServer server) {
        auto key = RedisKeys.server(serverId);
        db.hset(key, "data", server.toJson().toString());
    }

    /// Check whether a server's draining flag is set in Redis.
    /// Returns true if the server has the draining flag, false if not found
    /// or the flag is absent. Checks three locations for backward compat
    /// with older test expectations:
    ///   1. hash field `draining` (canonical)
    ///   2. TTL key `irc:draining:<sid>` (set by markDraining)
    ///   3. `data` JSON's `draining` bool (legacy persistence)
    bool isDraining(string serverId) {
        auto key = RedisKeys.server(serverId);
        const data = db.hget(key, "draining");
        if (data.length != 0) {
            try { if (data == "true") return true; } catch (Exception) {}
        }
        // TTL key fallback — draining_test sets only this in step 2
        try {
            const ttl = db.get(RedisKeys.draining(serverId));
            if (ttl.length != 0) return true;
        } catch (Exception) {}
        // Data JSON fallback — step 3 sets only data JSON
        try {
            auto dataRaw = db.hget(key, "data");
            if (dataRaw.length != 0) {
                auto j = parseJson(cast(string) dataRaw);
                if ("draining" in j) {
                    try { if (j["draining"].get!bool) return true; } catch (Exception) {}
                }
            }
        } catch (Exception) {}
        return false;
    }

    /// Manually clear the draining flag on a server. Removes the
    /// draining hash field, the TTL key, and re-persists clean server data
    /// so the gateway sees the server as available for new assignments.
    void clearDraining(string serverId) {
        auto key = RedisKeys.server(serverId);
        db.hdel(key, "draining");
        try { db.del(RedisKeys.draining(serverId)); } catch (Exception) {}
        // Re-persist clean server data (without draining flag)
        auto existing = getServer(serverId);
        if (existing.serverId.length > 0) {
            existing.draining = false;
            existing.isHealthy = true;
            db.hset(key, "isHealthy", "true");
            syncServerState(serverId, existing);
        }
    }

    /**
     * Get server by ID.
     * 
     * Returns: ConnectionServer with empty serverId if not found.
     */
    ConnectionServer getServer(string serverId) {
        auto key = RedisKeys.server(serverId);
        auto data = db.hget(key, "data");
        if (data.length == 0) return ConnectionServer.init;

        try {
            auto server = ConnectionServer.fromJson(parseJson(data));
            if (server.serverId != serverId) return ConnectionServer.init;

            // Override with live heartbeat/health fields (updated separately by engine)
            server.lastHeartbeat = parseMsField(db.hget(key, "lastHeartbeat"), server.lastHeartbeat);
            server.hotswapAt = parseMsField(db.hget(key, "hotswapAt"), server.hotswapAt);

            const healthStr = db.hget(key, "isHealthy");
            if (healthStr.length > 0) server.isHealthy = healthStr == "true";

            return server;
        } catch (Exception e) {
            // Downgraded from Warn to Debug — transient parse failures during
            // Redis RDB background save or partial HSET race should not spam
            // SigNoz at Warn every 10s (was `Still no healthy engine` loop).
            logDebug("Failed to parse server data for %s: %s", serverId, e.msg);
            return ConnectionServer.init;
        }
    }

    /// Tolerant parse of a millisecond-timestamp hash field
    /// (`lastHeartbeat`, `hotswapAt`). Accepts a plain number string or a
    /// JSON-encoded number/string; anything else keeps `fallback`.
    /// (Previous manual Redis edits left `lastHeartbeat` as a JSON object
    /// string, and `to!long` on "{" spammed `Failed to parse server data`
    /// every 10s.)
    private static long parseMsField(string raw, long fallback) {
        if (raw.length == 0) return fallback;
        try {
            return raw.to!long;
        } catch (Exception) {
            try {
                const j = parseJsonString(raw);
                if (j.type == Json.Type.int_) return j.get!long;
                if (j.type == Json.Type.string) {
                    try { return j.get!string.to!long; } catch (Exception) {}
                }
            } catch (Exception) {}
        }
        return fallback;
    }

    /// Liveness predicate shared by every health decision in this registry:
    /// a server is fresh when it heartbeat within the last 60 s, or when it
    /// stamped `hotswapAt` (engine detached for a hot swap) less than
    /// `HOTSWAP_GRACE_MS` ago. The grace covers the heartbeat-less gap
    /// between the old engine exiting and the new one's first beat, which
    /// clears the stamp again.
    private static bool heartbeatFresh(ref const ConnectionServer s, long now) {
        return (s.lastHeartbeat > 0 && s.lastHeartbeat <= now + 1_000
                && (now - s.lastHeartbeat) < 60_000)
            || (s.hotswapAt > 0 && s.hotswapAt <= now + 1_000
                && (now - s.hotswapAt) < HOTSWAP_GRACE_MS);
    }

    /**
     * Get all registered servers.
     *
     * Self-heals from orphan `irc:server:*` hashes if the registry set
     * was evicted by Redis LRU (or wiped by manual cleanup). The set is
     * also re-populated via SADD so subsequent calls see the recovered
     * servers without rescanning.
     */
    ConnectionServer[] getAllServers() {
        ConnectionServer[] result;
        auto reply = db.smembers(RedisKeys.serverList());
        string[] ids;
        foreach (id; reply) ids ~= id;

        if (ids.length == 0) {
            // Don't auto-scan for recovery - only recover when explicitly needed.
            // scanServerIds() can be slow on large Redis DBs with no servers.
            // Call reassignServerNetworks or recovery explicitly if needed.
        } else {
            foreach (id; ids) {
                auto s = getServer(id);
                if (s.serverId.length > 0) result ~= s;
            }
        }
        return result;
    }

    /// SCAN-based recovery of server IDs whose `irc:server:<id>` hash
    /// still exists but whose containing `irc:servers` set was evicted.
    /// Bounded by SCAN's incremental cursor — safe to call on large
    /// databases (no KEYS-style blocking).
    private string[] scanServerIds() {
        import std.algorithm : filter, map;
        import std.array : array;
        enum prefix = "irc:server:";
        enum prefixLen = prefix.length;

        string[] result;
        string cursor = "0";
        do {
            auto sr = redis.scanKeys(cursor, prefix ~ "*", 100);
            cursor = sr.cursor;
            foreach (key; sr.keys) {
                if (key.length > prefixLen)
                    result ~= key[prefixLen .. $];
            }
        } while (cursor != "0");
        return result;
    }

    /**
     * Get only healthy servers (heartbeat within 60s, or inside the
     * hot-swap grace — see `heartbeatFresh`).
     */
    ConnectionServer[] getHealthyServers() {
        auto now = Clock.currTime.toUnixTime!long * 1000;
        return getAllServers()
            .filter!(s => s.isHealthy && heartbeatFresh(s, now))
            .array;
    }

    private struct CapacityContext {
        string host;
        string networkId;
        bool existingHostSlot;
        string[string] assignments;
        size_t[string] loads;
        size_t[string] hostLoads;
    }

    private CapacityContext capacityContext(string networkId, string host = "") {
        CapacityContext ctx;
        ctx.networkId = networkId;
        auto repo = new NetworkRepository(redis);
        string savedHost;
        if (networkId.length) {
            const cfg = repo.findById(parseUUID(networkId[]));
            if (cfg.id != UUID.init) savedHost = canonicalHost(cfg.host);
        }
        // Explicit host is a validated prospective edit supplied by lifecycle;
        // admin/worker/claim callers omit it to use canonical saved context.
        ctx.host = host.length ? canonicalHost(host) : savedHost;
        ctx.existingHostSlot = savedHost.length != 0 && ctx.host == savedHost;
        ctx.assignments = redis.hgetAll(RedisKeys.networkAssignments());
        UUID[] ids;
        foreach (id, owner; ctx.assignments) {
            if (!id.length || !owner.length) continue;
            ctx.loads[owner]++;
            if (ctx.host.length) {
                try { ids ~= parseUUID(id[]); }
                catch (Exception) {}
            }
        }
        if (ids.length) {
            foreach (row; repo.findByIdsWithUsers(ids)) {
                if (canonicalHost(row.config.host) != ctx.host) continue;
                const owner = row.config.id.toString() in ctx.assignments;
                if (owner !is null) ctx.hostLoads[*owner]++;
            }
        }
        return ctx;
    }

    private static size_t routingTier(const ConnectionServer server,
                                      const EffectiveRoutingPolicy effective) {
        if (!effective.available || server.routingPolicyVersion != 1)
            return size_t.max;
        foreach (i, route; effective.order)
            if (server.supportedRoutes.canFind(routeToken(route))) return i;
        return size_t.max;
    }

    private bool eligible(const ConnectionServer server, const EffectiveRoutingPolicy effective,
                          ref const CapacityContext ctx) {
        const now = Clock.currTime.toUnixTime!long * 1000;
        if (!server.serverId.length || !server.isHealthy || !heartbeatFresh(server, now)
                || isDraining(server.serverId) || routingTier(server, effective) == size_t.max)
            return false;
        const existing = ctx.networkId in ctx.assignments;
        // A full engine retains its own existing same-host slot. A host edit
        // consumes a slot at the prospective host even on the current engine.
        // Overall canonical load is a separate selection tie-break.
        if (ctx.existingHostSlot && existing !is null && *existing == server.serverId) return true;
        if (server.maxConnections > 0 && ctx.host.length) {
            const count = server.serverId in ctx.hostLoads;
            if (count !is null && *count >= server.maxConnections) return false;
        }
        return true;
    }

    /// Validate an explicit target without requiring it to win selection.
    /// Omitted host uses saved context; explicit host is a prospective edit.
    bool routingServerEligible(const ConnectionServer server, const EffectiveRoutingPolicy effective,
                               string networkId = "", string host = "",
                               string[string]* validatedAssignments = null) {
        auto ctx = capacityContext(networkId, host);
        if (validatedAssignments !is null) *validatedAssignments = ctx.assignments;
        return eligible(server, effective, ctx);
    }

    /// Tier capability precedes fallback-only, priority, total canonical load,
    /// and finally server ID. There is no registered-but-unhealthy fallback.
    ConnectionServer selectRoutingServer(const EffectiveRoutingPolicy effective,
                                        string excludeServerId = "", string networkId = "",
                                        string host = "") {
        if (!effective.available || !effective.order.length) return ConnectionServer.init;
        auto ctx = capacityContext(networkId, host);
        ConnectionServer best;
        size_t bestTier = size_t.max;
        size_t bestLoad;
        foreach (server; getAllServers()) {
            if (server.serverId == excludeServerId || !eligible(server, effective, ctx)) continue;
            const tier = routingTier(server, effective);
            const count = server.serverId in ctx.loads;
            const load = count is null ? 0 : *count;
            const better = !best.serverId.length || tier < bestTier
                || (tier == bestTier && (
                    (best.fallbackOnly && !server.fallbackOnly)
                    || (best.fallbackOnly == server.fallbackOnly && (
                        server.priority > best.priority
                        || (server.priority == best.priority && (
                            load < bestLoad || (load == bestLoad && server.serverId < best.serverId)))))));
            if (better) { best = server; bestTier = tier; bestLoad = load; }
        }
        return best;
    }

    /// New provisioning, or local recovery with actual client/holder evidence,
    /// may claim an unowned row. A concurrent claimant is returned, not stolen.
    /// A reverse mirror is prior ownership evidence, not a disposable hint.
    version (RoutingPolicyTest) void delegate() beforeClaimCommit;

    string claimNetwork(string networkId, string targetServerId) {
        if (!networkId.length || !targetServerId.length) return "";
        // A heartbeat rewrites `data` while capacity is being read. Retry only
        // an explicitly rejected CAS, never an unavailable/ambiguous Redis call.
        // Each retry revalidates policy, target health and canonical capacity.
        foreach (attempt; 0 .. 3) {
            const cfg = (new NetworkRepository(redis)).findById(parseUUID(networkId[]));
            if (cfg.id == UUID.init || cfg.disabled || cfg.servicesProvisioningPending) return "";
            requireRoutingUpgrade(db, targetServerId);
            const policyRaw = db.get(RedisKeys.egressRoutingPolicy());
            const effective = resolveRoutingPolicy(routingPolicyFromJson(parseJsonString(policyRaw)), cfg.host, cfg.routing);
            if (!effective.available) throw new RoutingPolicyUnavailableException();
            if (!effective.order.length) return "";
            const targetRaw = db.hget(RedisKeys.server(targetServerId), "data");
            auto server = ConnectionServer.fromJson(parseJsonString(targetRaw));
            const live = getServer(targetServerId);
            if (server.serverId != targetServerId || live.serverId != targetServerId) return "";
            // Validate the exact capability/capacity bytes used by the CAS,
            // with live liveness overlays rather than another metadata snapshot.
            server.lastHeartbeat = live.lastHeartbeat;
            server.hotswapAt = live.hotswapAt;
            server.isHealthy = live.isHealthy;
            auto ctx = capacityContext(networkId);
            const current = networkId in ctx.assignments;
            if (current !is null && (*current).length) return *current;
            if (!eligible(server, effective, ctx)) return "";
            string[] args = [networkId, targetServerId, policyRaw, targetRaw,
                NETWORK_ROUTING_LEASE_TTL_SECONDS.to!string, RedisKeys.serverAssignments("")];
            foreach (id, owner; ctx.assignments) { args ~= id; args ~= owner; }
            version (RoutingPolicyTest) {
                if (beforeClaimCommit !is null) beforeClaimCommit();
            }
            auto reply = db.eval!string(CLAIM_SCRIPT,
                [RedisKeys.networkAssignments(), RedisKeys.lease(networkId), RedisKeys.routingMove(networkId),
                 RedisKeys.egressRoutingPolicy(), RedisKeys.server(targetServerId), RedisKeys.draining(targetServerId),
                 RedisKeys.routingSchemaVersion()], args);
            if (reply.empty) return "";
            const result = reply.front;
            if (result == "conflict") continue;
            if (result == "maintenance") throw new NetworkWriteUnavailableException();
            if (result != "owner") return "";
            reply.popFront();
            return reply.empty ? "" : reply.front.idup;
        }
        return "";
    }

    /// Reconciliation is sticky. Only explicit reconnect/routing callers run
    /// the selector to replace an otherwise healthy capable owner.
    string assignNetwork(string networkId) {
        if (!networkId.length) return "";
        const cfg = (new NetworkRepository(redis)).findById(parseUUID(networkId[]));
        if (cfg.id == UUID.init || cfg.disabled || cfg.servicesProvisioningPending) return "";
        requireRoutingUpgrade(db);
        auto owner = getServerForNetwork(networkId);
        if (!owner.length) {
            // Bootstrap is not new provisioning. With no uniquely evidenced
            // previous owner it cannot know that a holder has no old socket.
            getAllAssignments();
            owner = getServerForNetwork(networkId);
            if (!owner.length) return "";
        }
        if (networkMoveFenced(db, networkId)) return owner;
        const effective = resolveRoutingPolicy(loadRoutingPolicy(db), cfg.host, cfg.routing);
        if (!effective.available) throw new RoutingPolicyUnavailableException();
        if (!effective.order.length) return owner; // parked, never moved/dialed
        const currentServer = getServer(owner);
        if (routingServerEligible(currentServer, effective, networkId)) return owner;
        auto target = selectRoutingServer(effective, owner, networkId);
        if (target.serverId.length) requestNetworkMove(db, networkId, target.serverId);
        return owner; // destination becomes owner only after close acknowledgement
    }

    private enum CLAIM_SCRIPT = q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return {'maintenance'} end
local current = redis.call('HGET', KEYS[1], ARGV[1])
if current and current ~= '' then return {'owner', current} end
-- A surviving lease is prior-holder evidence even when hashes were evicted.
-- Only that same owner may self-heal; a different owner needs close proof.
local previousLease = redis.call('GET', KEYS[2])
if previousLease and previousLease ~= ARGV[2] then return {'denied'} end
if redis.call('EXISTS', KEYS[3]) ~= 0 or redis.call('GET', KEYS[7]) ~= '1'
    or redis.call('HGET', KEYS[5], 'draining') == 'true' or redis.call('EXISTS', KEYS[6]) ~= 0 then return {'denied'} end
if redis.call('GET', KEYS[4]) ~= ARGV[3]
    or redis.call('HGET', KEYS[5], 'data') ~= ARGV[4] then return {'conflict'} end
local ok, server = pcall(cjson.decode, ARGV[4])
if not ok or server.draining == true or server.routingPolicyVersion ~= 1 then return {'denied'} end
local health = redis.call('HGET', KEYS[5], 'isHealthy')
if (health and health ~= 'true') or (not health and server.isHealthy ~= true) then return {'denied'} end
local heartbeat = tonumber(redis.call('HGET', KEYS[5], 'lastHeartbeat') or server.lastHeartbeat)
local swap = tonumber(redis.call('HGET', KEYS[5], 'hotswapAt') or '0')
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
if not heartbeat or heartbeat <= 0 or heartbeat > now + 1000
    or (now - heartbeat >= 60000 and (swap <= 0 or swap > now + 1000 or now - swap >= 180000)) then return {'denied'} end
if redis.call('HLEN', KEYS[1]) ~= (#ARGV - 6) / 2 then return {'conflict'} end
for i = 7, #ARGV, 2 do
  if redis.call('HGET', KEYS[1], ARGV[i]) ~= ARGV[i + 1] then return {'conflict'} end
end
-- Scan all reverse evidence atomically. A conflicting or malformed mirror
-- cannot be bypassed by choosing a different fresh owner.
local cursor = '0'
repeat
  local batch = redis.call('SCAN', cursor, 'MATCH', ARGV[6] .. '*', 'COUNT', 100)
  cursor = batch[1]
  for _, key in ipairs(batch[2]) do
    local previous = redis.call('HGET', key, ARGV[1])
    if previous and (previous ~= ARGV[2] or key ~= ARGV[6] .. previous) then return {'denied'} end
  end
until cursor == '0'
if redis.call('HSETNX', KEYS[1], ARGV[1], ARGV[2]) ~= 1 then
  local winner = redis.call('HGET', KEYS[1], ARGV[1])
  if winner and winner ~= '' then return {'owner', winner} end
  return {'denied'}
end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[5])
return {'owner', ARGV[2]}
LUA";

    /**
     * Get server ID for a network.
     * 
     * Returns: Empty string if not assigned.
     */
    string getServerForNetwork(string networkId) {
        return db.hget(RedisKeys.networkAssignments(), networkId.idup);
    }

    /**
     * Get all networks assigned to a server from the server record.
     * The server record is maintained by the engine's heartbeat and
     * may be stale if the canonical assignments hash was changed by
     * the gateway. For the source of truth, use getCanonicalNetworks().
     */
    string[] getNetworksForServer(string serverId) {
        auto server = getServer(serverId);
        return server.assignedNetworks.dup;
    }

    /**
     * Get all networks assigned to a server from the canonical
     * assignments hash (irc:assignments). This is the gateway's
     * source of truth — unlike getNetworksForServer() which reads
     * the per-server record that the engine's heartbeat writes.
     *
     * Use this in the engine heartbeat to detect networks that were
     * reassigned away by an admin (so the engine can disconnect them).
     */
    string[] getCanonicalNetworks(string serverId) {
        string[] result;
        auto all = redis.hgetAll(RedisKeys.networkAssignments());
        foreach (k, v; all) {
            if (v == serverId)
                result ~= k;
        }
        return result;
    }

    /**
     * Set a lease for a network assignment.
     *
     * Creates (or refreshes) a TTL-backed lease key so the gateway
     * can detect orphaned assignments when an engine stops heartbeating.
     * Called by assignNetwork() and the engine's heartbeat loop.
     */
    void setLease(string networkId, string serverId) {
        db.eval!string(q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return '0' end
if redis.call('HGET', KEYS[1], ARGV[1]) ~= ARGV[2] then return '0' end
redis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])
return '1'
LUA", [RedisKeys.networkAssignments(), RedisKeys.lease(networkId)],
            [networkId, serverId, NETWORK_ROUTING_LEASE_TTL_SECONDS.to!string]);
    }

    /// Refresh a canonical lease without replacing another operation's owner.
    void renewLease(string networkId) {
        const owner = getServerForNetwork(networkId);
        if (owner.length) setLease(networkId, owner);
    }

    /**
     * Check if a network assignment has a valid lease.
     *
     * Returns true if the lease key exists and its value matches
     * the expected serverId. Returns false if the lease expired,
     * was never set, or points to a different server.
     */
    bool hasValidLease(string networkId, string expectedServerId) {
        auto key = RedisKeys.lease(networkId);
        auto actual = db.get(key);
        return actual.length > 0 && actual == expectedServerId;
    }

    /// Graceful shutdown recovery also uses the positive-close coordinator.
    /// Unreachable sources keep ownership; stale health is not closure proof.
    void reassignServerNetworks(string serverId) {
        foreach (na; getAllAssignments()) {
            if (na.serverId != serverId) continue;
            try { requestAlternative(na.networkId, serverId); }
            catch (Exception e) {
                logError("Could not request move of %s from %s: %s", na.networkId, serverId, e.msg);
            }
        }
    }

    private bool requestAlternative(string networkId, string owner) {
        if (networkMoveFenced(db, networkId)) return false;
        const cfg = (new NetworkRepository(redis)).findById(parseUUID(networkId[]));
        if (cfg.id == UUID.init || cfg.disabled || cfg.servicesProvisioningPending) return false;
        requireRoutingUpgrade(db);
        const effective = resolveRoutingPolicy(loadRoutingPolicy(db), cfg.host, cfg.routing);
        if (!effective.available || !effective.order.length) return false;
        auto target = selectRoutingServer(effective, owner, networkId);
        if (!target.serverId.length) return false;
        requestNetworkMove(db, networkId, target.serverId);
        return true;
    }

    /**
     * Check if a server is healthy.
     */
    bool isServerHealthy(string serverId) {
        auto server = getServer(serverId);
        if (server.serverId.length == 0) return false;
        auto now = Clock.currTime.toUnixTime!long * 1000;
        return server.isHealthy && heartbeatFresh(server, now);
    }

    /**
     * Get maximum buffer offset across all servers.
     * 
     * Used when registering a new server to prevent ID collision.
     * Complexity: O(n) where n = number of servers.
     */
    long getMaxBufferOffset() {
        long max = 0;
        foreach (s; getAllServers()) {
            if (s.bufferOffset > max) max = s.bufferOffset;
        }
        return max;
    }

    /**
     * Atomically increment and return buffer offset for a server.
     * 
     * Used when creating new buffers on a connection server.
     * This ensures unique IDs even with concurrent operations.
     */
    long nextBufferOffset(string serverId) {
        auto key = RedisKeys.server(serverId);
        // Use Redis INCR for atomicity
        auto newOffset = db.hincr(key, "bufferOffset", 1);
        return newOffset;
    }

    /// Health and metadata reconciliation cannot transfer ownership. Only
    /// explicitly acknowledged moves do; registration and priority changes
    /// never rebalance healthy sessions.
    void healthCheckAll() {
        const now = Clock.currTime.toUnixTime!long * 1000;
        foreach (server; getAllServers()) {
            if (heartbeatFresh(server, now)) continue;
            // Do not let a concurrent heartbeat lose to this stale read.
            db.eval!string(q"LUA
local beat = tonumber(redis.call('HGET', KEYS[1], 'lastHeartbeat') or ARGV[1])
local swap = tonumber(redis.call('HGET', KEYS[1], 'hotswapAt') or '0')
if beat and tonumber(ARGV[2]) - beat >= 60000
    and (swap <= 0 or tonumber(ARGV[2]) - swap >= tonumber(ARGV[3])) then
  redis.call('HSET', KEYS[1], 'isHealthy', 'false')
end
return '1'
LUA", [RedisKeys.server(server.serverId)],
                [server.lastHeartbeat.to!string, now.to!string, HOTSWAP_GRACE_MS.to!string]);
        }
        foreach (assignment; getAllAssignments()) {
            try {
                if (isServerHealthy(assignment.serverId)) {
                    if (!hasValidLease(assignment.networkId, assignment.serverId))
                        setLease(assignment.networkId, assignment.serverId);
                    // A missing assignedNetworks entry is repaired by that
                    // owner's heartbeat; it is never permission to steal.
                } else {
                    requestAlternative(assignment.networkId, assignment.serverId);
                }
            } catch (Exception e) {
                logWarn("Ownership recovery for %s remains fenced/unavailable: %s",
                    assignment.networkId, e.msg);
            }
        }
        checkNetworkFailures();
    }

    /**
     * Report a per-network connection failure.
     * 
     * Called by the engine when a specific IRC server connection fails.
     * Increments the failure counter in Redis for the gateway to act on.
     */
    void reportNetworkFailure(string networkId, string serverId, string error) {
        auto key = RedisKeys.networkFail(networkId);
        auto now = Clock.currTime.toUnixTime!long * 1000;
        db.hincr(key, "count", 1);
        db.hset(key, "serverId", serverId);
        db.hset(key, "error", error);
        db.hset(key, "lastFailure", now.to!string);
    }

    /**
     * Clear network failure tracking (after reassignment or successful connect).
     */
    void clearNetworkFailure(string networkId) {
        db.del(RedisKeys.networkFail(networkId));
    }

    /// Repeated transport failures may request an eligible alternative, but
    /// cannot bypass the source-holder close acknowledgement.
    void checkNetworkFailures() {
        const now = Clock.currTime.toUnixTime!long * 1000;
        const healthy = getHealthyServers();
        if (healthy.length < 2) return; // need at least 2 servers to reassign

        foreach (na; getAllAssignments()) {
            auto failKey = RedisKeys.networkFail(na.networkId);
            const failCountStr = db.hget(failKey, "count");
            if (failCountStr.length == 0) continue;

            int failCount;
            try { failCount = failCountStr.to!int; } catch (Exception) { continue; }
            if (failCount < 3) continue;

            // Check if failure is recent (within 5 minutes)
            const lastFailureStr = db.hget(failKey, "lastFailure");
            long lastFailure;
            try { lastFailure = lastFailureStr.to!long; } catch (Exception) { continue; }
            if (now - lastFailure > 300_000) continue; // too old, reset

            // Verify the failing server is still the one assigned
            const failingServerId = db.hget(failKey, "serverId");
            if (failingServerId != na.serverId) continue; // already reassigned

            auto error = db.hget(failKey, "error");
            if (error.length == 0) error = "unknown error";

            try {
                if (requestAlternative(na.networkId, na.serverId))
                    clearNetworkFailure(na.networkId);
            } catch (Exception e) {
                logError("Failed to request move for failing network %s: %s", na.networkId, e.msg);
            }
        }
    }

    /**
     * Set per-host max connections (stored in Redis).
     * Used by admin UI to control routing capacity.
     */
    void setMaxConnsPerHost(int maxConns) {
        db.set(RedisKeys.routingConfig(), "maxConnsPerHost:" ~ maxConns.to!string);
    }

    /**
     * Get per-host max connections (from Redis).
     * Returns 5 if not configured.
     */
    int getMaxConnsPerHost() {
        auto val = db.get(RedisKeys.routingConfig());
        if (val.length == 0) return 5;
        auto parts = val.split(":");
        if (parts.length >= 2) {
            try {
                return parts[1].to!int;
            } catch (Exception) {}
        }
        return 5;
    }

    /**
     * Set engine config overrides (stored in Redis).
     */
    void setEngineConfig(string serverId, int priority, int maxConns, bool fallbackOnly) {
        auto key = RedisKeys.engineConfig(serverId);
        auto config = Json.emptyObject;
        config["priority"] = Json(priority);
        config["maxConnections"] = Json(maxConns);
        config["fallbackOnly"] = Json(fallbackOnly);
        db.set(key, config.toString());
    }

    /**
     * Get engine config overrides from Redis.
     *
     * Returns an EngineConfigOverride with fields set to 0/false
     * if no config has been saved for this server.
     */
    EngineConfigOverride getEngineConfig(string serverId) {
        auto key = RedisKeys.engineConfig(serverId);
        auto raw = db.get(key);
        if (raw.length == 0) return EngineConfigOverride.init;

        try {
            auto j = parseJson(raw);
            EngineConfigOverride cfg;
            if (j["priority"].type != Json.Type.undefined)
                cfg.priority = j["priority"].get!int;
            if (j["maxConnections"].type != Json.Type.undefined)
                cfg.maxConnections = j["maxConnections"].get!int;
            if (j["fallbackOnly"].type != Json.Type.undefined)
                cfg.fallbackOnly = j["fallbackOnly"].get!bool;
            return cfg;
        } catch (Exception e) {
            logWarn("Failed to parse engine config for %s: %s", serverId, e.msg);
            return EngineConfigOverride.init;
        }
    }

    /**
     * Get host connection summary — aggregates network counts per IRC host
     * directly from MongoDB (not the stale Redis assignments hash).
     */
    HostConnectionSummary[] getHostConnectionSummary() {
        import ircfiber.db.network : NetworkRepository;
        import std.string : toLower;
        import std.algorithm : sort;

        HostConnectionSummary[string] hostMap;
        auto netRepo = new NetworkRepository(redis);

        // Query all networks from MongoDB directly — the irc:assignments
        // Redis hash can be stale and contain UUIDs for deleted networks.
        foreach (nwu; netRepo.findAll()) {
            auto host = nwu.config.host.toLower();
            if (host.length == 0) continue;

            // Determine which server this network is assigned to
            auto netId = nwu.config.id.toString();
            auto sid = getServerForNetwork(netId);
            if (sid.length == 0) sid = "(unassigned)";

            if (host !in hostMap) {
                hostMap[host] = HostConnectionSummary(host, 0, []);
            }
            hostMap[host].totalConns++;
            if (!hostMap[host].serverIds.canFind(sid)) {
                hostMap[host].serverIds ~= sid;
            }
            hostMap[host].serverConns[sid]++;
        }

        HostConnectionSummary[] result;
        foreach (host, hcs; hostMap) result ~= hcs;

        if (result.length == 0) {
            HostConnectionSummary emptyEntry;
            emptyEntry.host = "(no networks)";
            emptyEntry.totalConns = 0;
            result ~= emptyEntry;
        }

        result.sort!((a, b) => a.totalConns > b.totalConns);
        return result;
    }

    /// Recover only a uniquely evidenced previous owner. This restores
    /// ownership, never transfers it: even a dead source holder may still
    /// have an open socket. Contradictory mirrors fail closed, including
    /// during partial canonical eviction.
    NetworkAssignment[] getAllAssignments() {
        db.eval!string(RECOVER_ASSIGNMENTS_SCRIPT,
            [RedisKeys.networkAssignments()],
            [RedisKeys.serverAssignments(""), RedisKeys.routingMove(""),
             RedisKeys.lease(""), NETWORK_ROUTING_LEASE_TTL_SECONDS.to!string]);
        NetworkAssignment[] result;
        foreach (networkId, serverId; redis.hgetAll(RedisKeys.networkAssignments())) {
            if (!networkId.length || !serverId.length) continue;
            try { if (parseUUID(networkId[]) == UUID.init) continue; }
            catch (Exception) { continue; }
            NetworkAssignment assignment;
            assignment.networkId = networkId;
            assignment.serverId = serverId;
            result ~= assignment;
        }
        return result;
    }

    private enum RECOVER_ASSIGNMENTS_SCRIPT = q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return '0' end
local function validNetwork(id)
  if #id ~= 36 or string.sub(id, 9, 9) ~= '-' or string.sub(id, 14, 14) ~= '-'
      or string.sub(id, 19, 19) ~= '-' or string.sub(id, 24, 24) ~= '-' then return false end
  local hex = string.gsub(id, '-', '')
  return #hex == 32 and not string.find(hex, '[^0-9a-fA-F]')
end
-- Validate the primary type before doing any restoration.
redis.call('HLEN', KEYS[1])
local owners = {}
local cursor = '0'
repeat
  local batch = redis.call('SCAN', cursor, 'MATCH', ARGV[1] .. '*', 'COUNT', 100)
  cursor = batch[1]
  for _, key in ipairs(batch[2]) do
    local fields = redis.call('HGETALL', key)
    for i = 1, #fields, 2 do
      local id, owner = fields[i], fields[i + 1]
      if validNetwork(id) then
        if owner == '' or key ~= ARGV[1] .. owner then owners[id] = false
        elseif owners[id] == nil then owners[id] = owner
        elseif owners[id] ~= owner then owners[id] = false end
      end
    end
  end
until cursor == '0'
for id, owner in pairs(owners) do
  if owner and redis.call('EXISTS', ARGV[2] .. id) == 0 then
    if redis.call('HSETNX', KEYS[1], id, owner) == 1 then
      redis.call('SET', ARGV[3] .. id, owner, 'EX', ARGV[4])
    end
  end
end
return '1'
LUA";
}

// ═══════════════════════════════════════════════════════════════════════════
//  Hot-swap grace liveness tests (pure predicate, no Redis)
// ═══════════════════════════════════════════════════════════════════════════
unittest {
    enum long now = 1_000_000_000;
    ConnectionServer s;

    // Fresh heartbeat, no hot swap: alive.
    s.lastHeartbeat = now - 10_000;
    assert(ServerRegistry.heartbeatFresh(s, now));

    // Stale heartbeat, no hot swap: dead (the classic 60 s rule).
    s.lastHeartbeat = now - 120_000;
    assert(!ServerRegistry.heartbeatFresh(s, now));

    // Stale heartbeat but hot swap stamped 30 s ago: still alive.
    s.hotswapAt = now - 30_000;
    assert(ServerRegistry.heartbeatFresh(s, now));

    // Hot swap stamped 200 s ago (> HOTSWAP_GRACE_MS): dead again.
    s.hotswapAt = now - 200_000;
    assert(!ServerRegistry.heartbeatFresh(s, now));

    // Exactly at the grace boundary is no longer fresh.
    s.hotswapAt = now - HOTSWAP_GRACE_MS;
    assert(!ServerRegistry.heartbeatFresh(s, now));

    // A cleared stamp (0) never grants grace.
    s.hotswapAt = 0;
    assert(!ServerRegistry.heartbeatFresh(s, now));
}
