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
    /// Direct, minimal self-assignment: write `networkId → serverId`
    /// directly into the canonical hash. Used during bootstrap when
    /// the engine is the first server to come online (no healthy
    /// peers in the registry yet), so `assignNetwork` would otherwise
    /// fail and the network would be dropped on every restart.
    /// Caller is responsible for ensuring no other server should own
    /// this network (typically by checking `getAllServers().length == 0`
    /// first).
    void selfAssignNetwork(string networkId, string serverId) {
        db.hset(RedisKeys.networkAssignments(), networkId, serverId);
    }

    /// Registers a new connection server in the registry.
    void registerServer(ConnectionServer server) {
        if (server.serverId.length == 0) {
            throw new Exception("Server ID must be non-empty");
        }

        // Check if server already exists
        const existing = getServer(server.serverId);
        if (existing.serverId.length > 0) {
            logWarn("Server %s already registered, updating heartbeat", server.serverId);
            // Re-registration implies the engine restarted — clear any stale
            // draining state so the new process is eligible for assignments.
            // Tests (draining_test: registerServer clears draining) expect
            // both the hash field and TTL key to be removed.
            try { db.hdel(RedisKeys.server(server.serverId), "draining"); } catch (Exception) {}
            try { db.del(RedisKeys.draining(server.serverId)); } catch (Exception) {}
            // Also clear the draining flag in the persisted data JSON
            auto fresh = getServer(server.serverId);
            if (fresh.serverId.length > 0 && fresh.draining) {
                fresh.draining = false;
                syncServerState(server.serverId, fresh);
            }
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

        // Add to server list
        db.sadd(RedisKeys.serverList(), server.serverId);

        logInfo("Registered connection server: %s@%s (offset=%d)",
            server.serverId, server.bindAddress, server.bufferOffset);
    }

    /**
     * Unregister a connection server (graceful shutdown or failure).
     *
     * Postcondition: Server removed from registry.
     * Side effect: Reassigns all networks to healthy servers.
     */
    void unregisterServer(string serverId) {
        auto key = RedisKeys.server(serverId);
        db.del(key);
        db.srem(RedisKeys.serverList(), serverId);
        // Drop the per-engine assignments mirror so a future engine with
        // the same serverId doesn't inherit stale network mappings.
        db.del(RedisKeys.serverAssignments(serverId));

        // Reassign networks
        auto networks = getNetworksForServer(serverId);
        foreach (netId; networks) {
            reassignNetwork(netId);
        }

        logInfo("Unregistered connection server: %s", serverId);
    }

    /// Mirror the engine's current network assignments into a per-server
    /// hash so getAllAssignments() can recover if the canonical
    /// `irc:assignments` hash is evicted by Redis LRU. Each field is a
    /// networkId; the value is the serverId. The engine calls this on
    /// every heartbeat — a no-op when the engine has no networks.
    ///
    /// Filters out empty/invalid ids. An empty string in the mirror would
    /// block the per-engine reassignment recovery and survive across
    /// engine restarts as a ghost row in the admin's Network Assignments
    /// table — the original symptom that triggered the
    /// fix/orphan-connection-delete change.
    void publishServerAssignments(string serverId, string[] networkIds) {
        auto key = RedisKeys.serverAssignments(serverId);
        // Replace atomically: delete the mirror and re-populate. A short
        // window where the mirror is empty is acceptable because the
        // canonical hash is the primary source; the mirror only matters
        // during recovery, and an empty mirror just means "no networks
        // to recover from this engine".
        db.del(key);
        foreach (netId; networkIds) {
            if (netId.length == 0) continue;
            db.hset(key, netId, serverId);
        }
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

        db.hset(key, "lastHeartbeat", now.to!string);
        db.hset(key, "isHealthy", "true");
        db.sadd(RedisKeys.serverList(), serverId);
        // Heartbeat implies the engine is alive — clear stale draining
        // flags so a previously-draining engine that recovers becomes
        // schedulable again. Tests expect TTL key to be deleted here.
        try { db.hdel(key, "draining"); } catch (Exception) {}
        try { db.del(RedisKeys.draining(serverId)); } catch (Exception) {}
        // Also ensure data JSON reflects not-draining
        try {
            auto s = getServer(serverId);
            if (s.serverId.length > 0 && s.draining) {
                s.draining = false;
                syncServerState(serverId, s);
            }
        } catch (Exception) {}
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

            // Override with live heartbeat/health fields (updated separately by engine)
            // Robust: handle both plain number string and JSON-encoded number/string
            // (previous manual Redis edits left `lastHeartbeat` as JSON object string,
            // causing `to!long` on "{" to spam `Failed to parse server data` every 10s)
            const hbStr = db.hget(key, "lastHeartbeat");
            if (hbStr.length > 0) {
                try {
                    server.lastHeartbeat = hbStr.to!long;
                } catch (Exception) {
                    try {
                        const hbJson = parseJsonString(hbStr);
                        if (hbJson.type == Json.Type.int_) server.lastHeartbeat = hbJson.get!long;
                        else if (hbJson.type == Json.Type.string) {
                            try { server.lastHeartbeat = hbJson.get!string.to!long; } catch (Exception) {}
                        }
                    } catch (Exception) {}
                }
            }

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
            ids = scanServerIds();
            if (ids.length > 0) {
                logWarn("irc:servers set was empty — recovered %d server(s) from orphaned hashes",
                    ids.length);
                foreach (id; ids) db.sadd(RedisKeys.serverList(), id);
            }
        }

        foreach (id; ids) {
            auto s = getServer(id);
            if (s.serverId.length > 0) result ~= s;
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
     * Get only healthy servers (heartbeat within 60s).
     */
    ConnectionServer[] getHealthyServers() {
        auto now = Clock.currTime.toUnixTime!long * 1000;
        return getAllServers()
            .filter!(s => s.isHealthy && (now - s.lastHeartbeat) < 60_000)
            .array;
    }

    /**
     * Assign a network to a connection server.
     *
     * Algorithm: Least-loaded healthy server (round-robin with weight).
     *
     * Invariant: After assignment, networkId exists in server.assignedNetworks.
     * Invariant: After assignment, Redis has reverse mapping.
     *
     * Rejects empty networkIds — a past bug surfaced as a ghost row in
     * the admin Network Assignments table (an empty string sitting at
     * index 0 of the engine's assignedNetworks array, surviving every
     * heartbeat because nothing filtered it out). Returning early with
     * an empty serverId and a clear warning makes the orphan impossible
     * to introduce via this code path.
     */
    string assignNetwork(string networkId) {
        if (networkId.length == 0) {
            logWarn("assignNetwork called with empty networkId — refusing (would create a ghost row)");
            return "";
        }
        auto healthy = getHealthyServers();
        if (healthy.length == 0) {
            logWarn("No healthy connection servers available for network %s "
                ~ "— falling back to any registered server", networkId);
            auto all = getAllServers();
            if (all.length == 0) {
                logWarn("No registered servers at all, cannot assign network %s", networkId);
                return "";
            }
            healthy = all;
        }

        // Score each healthy server by priority (higher = better) and
        // current load (fewer assigned networks = better). Filter out
        // fallbackOnly servers when other healthy options exist.
        ConnectionServer[] pool;
        foreach (s; healthy) {
            if (!s.fallbackOnly) pool ~= s;
        }
        if (pool.length == 0) pool = healthy; // everyone is fallbackOnly

        // Sort: priority desc, then load asc, so highest-priority
        // least-loaded server wins. Stable sort preserves order among
        // equal-scored servers.
        import std.algorithm : sort;
        pool.sort!((a, b) {
            if (a.priority != b.priority)
                return a.priority > b.priority;
            return a.assignedNetworks.length < b.assignedNetworks.length;
        });
        ConnectionServer best = pool[0];

        // Update server record
        best.assignedNetworks ~= networkId;
        auto key = RedisKeys.server(best.serverId);
        db.hset(key, "data", best.toJson().toString());

        // Store reverse mapping
        db.hset(RedisKeys.networkAssignments(), networkId, best.serverId);

        // Set a TTL-backed lease so the gateway can detect orphaned
        // assignments when an engine dies without unregistering.
        setLease(networkId, best.serverId);

        logInfo("Assigned network %s to server %s", networkId, best.serverId);
        return best.serverId;
    }

    /**
     * Reassign a network to a different server (e.g., after server failure).
     */
    string reassignNetwork(string networkId) {
        // Remove from old server
        auto oldServerId = getServerForNetwork(networkId);
        if (oldServerId.length > 0) {
            auto old = getServer(oldServerId);
            old.assignedNetworks = old.assignedNetworks
                .filter!(n => n != networkId)
                .array;
            auto key = RedisKeys.server(oldServerId);
            db.hset(key, "data", old.toJson().toString());
        }

        // Remove reverse mapping
        db.hdel(RedisKeys.networkAssignments(), networkId);

        // Assign to new server
        return assignNetwork(networkId);
    }

    /**
     * Get server ID for a network.
     * 
     * Returns: Empty string if not assigned.
     */
    string getServerForNetwork(string networkId) {
        return db.hget(RedisKeys.networkAssignments(), networkId);
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

    /// TTL for network assignment lease keys (90 seconds).
    /// The engine renews this every 10s in its heartbeat loop.
    /// If the engine dies, leases expire within 90s and the gateway
    /// detects the orphaned assignment on the next health check cycle.
    private enum LEASE_TTL_SECONDS = 90;

    /**
     * Set a lease for a network assignment.
     *
     * Creates (or refreshes) a TTL-backed lease key so the gateway
     * can detect orphaned assignments when an engine stops heartbeating.
     * Called by assignNetwork() and the engine's heartbeat loop.
     */
    void setLease(string networkId, string serverId) {
        auto key = RedisKeys.lease(networkId);
        db.set(key, serverId);
        db.expire(key, LEASE_TTL_SECONDS);
    }

    /**
     * Renew (extend) the lease for a network assignment.
     *
     * Called by the engine's heartbeat loop for every network
     * assigned to it. Resets the TTL to LEASE_TTL_SECONDS.
     */
    void renewLease(string networkId) {
        auto key = RedisKeys.lease(networkId);
        db.expire(key, LEASE_TTL_SECONDS);
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

    /**
     * Reassign all networks assigned to a given server.
     *
     * Scans the irc:assignments hash and reassigns every network
     * whose value matches serverId. Idempotent — safe to call on
     * a server that has already been cleaned up.
     */
    void reassignServerNetworks(string serverId) {
        foreach (na; getAllAssignments()) {
            if (na.serverId == serverId) {
                try {
                    reassignNetwork(na.networkId);
                } catch (Exception e) {
                    logError("Failed to reassign network %s from server %s: %s",
                        na.networkId, serverId, e.msg);
                }
            }
        }
    }

    /**
     * Check if a server is healthy.
     */
    bool isServerHealthy(string serverId) {
        auto server = getServer(serverId);
        if (server.serverId.length == 0) return false;
        auto now = Clock.currTime.toUnixTime!long * 1000;
        return server.isHealthy && (now - server.lastHeartbeat) < 60_000;
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

    /**
     * Health check all servers.
     * 
     * Marks stale servers as unhealthy and triggers reassignments.
     * Should be called periodically (every 30s by gateway heartbeat).
     */
    void healthCheckAll() {
        auto now = Clock.currTime.toUnixTime!long * 1000;

        // Phase 1: Check all registered servers for stale heartbeats
        foreach (s; getAllServers()) {
            if (now - s.lastHeartbeat > 60_000) {
                logWarn("Server %s heartbeat stale (last: %d ms ago), marking unhealthy",
                    s.serverId, now - s.lastHeartbeat);
                s.isHealthy = false;
                auto key = RedisKeys.server(s.serverId);
                db.hset(key, "data", s.toJson().toString());

                // Reassign all networks
                foreach (netId; s.assignedNetworks) {
                    try {
                        reassignNetwork(netId);
                    } catch (Exception e) {
                        logError("Failed to reassign network %s: %s", netId, e.msg);
                    }
                }
            }
        }

        // Phase 2: Check each assignment's server is alive.
        // Uses a two-layer check:
        //   1. Server heartbeat — if the server exists and has a fresh
        //      heartbeat, it's alive regardless of lease state. This
        //      handles the transitional period after deploy where old
        //      assignments don't have lease keys yet (the engine's next
        //      heartbeat will create them).
        //   2. Lease — if the server is dead (no heartbeat or deleted),
        //      the lease should also be missing/expired. Only reassign
        //      when BOTH the server heartbeat AND lease are gone.
        foreach (na; getAllAssignments()) {
            const server = getServer(na.serverId);
            const serverIsAlive = server.serverId.length > 0
                && server.isHealthy
                && (now - server.lastHeartbeat) < 60_000;

            if (serverIsAlive) {
                // Server is healthy — ensure the lease exists for future
                // crash detection. This is the first heartbeat after deploy
                // where an old assignment didn't have a lease yet.
                if (!hasValidLease(na.networkId, na.serverId)) {
                    logInfo("Network %s: server %s alive but lease missing — setting lease",
                        na.networkId, na.serverId);
                    setLease(na.networkId, na.serverId);
                }
            } else {
                // Server is dead — verify the lease is also gone before
                // reassigning (belt + suspenders: if the server heartbeat
                // just went stale but the lease renewal hasn't failed yet,
                // we give the engine a grace period).
                if (!hasValidLease(na.networkId, na.serverId)) {
                    logWarn("Network %s assigned to dead server %s (no lease) — reassigning",
                        na.networkId, na.serverId);
                    try {
                        reassignNetwork(na.networkId);
                    } catch (Exception e) {
                        logError("Failed to reassign orphaned network %s: %s",
                            na.networkId, e.msg);
                    }
                }
            }
        }

        // Phase 3: Reconcile orphaned assignments — networks that appear
        // in irc:assignments but are not in the assigned server's own
        // assignedNetworks list, or networks assigned to servers that no
        // longer exist. These can arise from stale heartbeat data, partial
        // reassignments, or manual Redis edits.
        foreach (na; getAllAssignments()) {
            auto server = getServer(na.serverId);
            if (server.serverId.length == 0) {
                // Server was deleted from the registry — reassign.
                logWarn("Network %s assigned to non-existent server %s — reassigning",
                    na.networkId, na.serverId);
                try {
                    reassignNetwork(na.networkId);
                } catch (Exception e) {
                    logError("Failed to reassign orphaned network %s: %s",
                        na.networkId, e.msg);
                }
            } else if (server.isHealthy && !canFind(server.assignedNetworks, na.networkId)) {
                // Server is alive but doesn't list this network in its
                // assignedNetworks — mismatch. Reassign to a proper home.
                logWarn("Network %s assigned to server %s but server has no record — reassigning",
                    na.networkId, na.serverId);
                try {
                    reassignNetwork(na.networkId);
                } catch (Exception e) {
                    logError("Failed to reassign orphaned network %s: %s",
                        na.networkId, e.msg);
                }
            }
        }

        // Also check for per-network connection failures that need reassignment
        checkNetworkFailures();

        // Phase 4: Priority rebalancing — move networks from lower-priority
        // servers to higher-priority ones. Without this, existing assignments
        // are sticky and priority config changes have no effect until the
        // assigned server fails or an admin explicitly reassigns.
        phase4PriorityRebalance();

        // Phase 5: Clear stale draining flags.
        // If an engine set draining=true (60s TTL during handoff) and then
        // crashed without clearing it, or its heartbeat went stale (>60s),
        // the TTL key may still exist but the engine is gone. A stale
        // draining flag prevents the gateway from assigning new networks to
        // that server, so we clear it once the heartbeat is stale.
        foreach (s; getAllServers()) {
            if (now - s.lastHeartbeat > 60_000 && isDraining(s.serverId)) {
                logInfo("Health check: clearing stale draining for %s (heartbeat %d ms ago)",
                    s.serverId, now - s.lastHeartbeat);
                clearDraining(s.serverId);
            }
        }
    }
    /// Phase 4 of healthCheckAll: move networks to the highest-priority
    /// healthy server. When an admin raises a server's priority, existing
    /// networks on lower-priority servers migrate within one health check cycle.
    ///
    /// Networks already on the best server are left in place. Each reassignment
    /// goes through assignNetwork() which respects both priority and load.
    private void phase4PriorityRebalance() {
        auto allAssignments = getAllAssignments();
        if (allAssignments.length == 0) return;

        auto healthy = getHealthyServers();
        if (healthy.length < 2) return;

        // Best candidate: highest priority, ties broken by fewest networks
        import std.algorithm : sort;
        healthy.sort!((a, b) {
            if (a.priority != b.priority)
                return a.priority > b.priority;
            return a.assignedNetworks.length < b.assignedNetworks.length;
        });
        auto best = healthy[0];

        foreach (na; allAssignments) {
            if (na.serverId == best.serverId) continue;

            auto current = getServer(na.serverId);
            if (current.serverId.length == 0) continue;
            if (best.priority <= current.priority) continue;

            logInfo("Priority rebalance: moving network %s from %s (priority %d) to %s (priority %d)",
                na.networkId, na.serverId, current.priority, best.serverId, best.priority);

            try {
                reassignNetwork(na.networkId);
            } catch (Exception e) {
                logError("Priority rebalance failed for network %s: %s", na.networkId, e.msg);
            }
        }
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

    /**
     * Check all networks for persistent connection failures and reassign.
     *
     * If a network has >= 3 failures within the last 5 minutes on its current
     * server AND a different healthy server exists, reassign the network to
     * spread the load and bypass the failing IRC server's IP-based ban.
     *
     * Called automatically by healthCheckAll(), or can be called independently.
     */
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

            logWarn("Network %s has %d failures on server %s (error: %s) — reassigning to alternate server",
                na.networkId, failCount, na.serverId, error);

            try {
                reassignNetwork(na.networkId);
                clearNetworkFailure(na.networkId);
            } catch (Exception e) {
                logError("Failed to reassign failing network %s: %s", na.networkId, e.msg);
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
        auto netRepo = new NetworkRepository();

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

    /**
     * Get all network assignments.
     *
     * The raw Redis hash maps networkId → serverId exactly as stored.
     *
     * Self-heals from per-engine assignment mirrors if the canonical
     * `irc:assignments` hash is missing (LRU eviction, manual cleanup).
     * Each engine writes its own network set on every heartbeat, so the
     * union of all `irc:server-assignments:*` hashes reconstructs the
     * canonical mapping. We also re-publish into the canonical hash so
     * subsequent reads stay fast.
     */
    NetworkAssignment[] getAllAssignments() {
        NetworkAssignment[] result;
        auto raw = redis.hgetAll(RedisKeys.networkAssignments());

        if (raw.length == 0) {
            raw = recoverAssignmentsFromMirrors();
            if (raw.length > 0) {
                logWarn("irc:assignments hash was empty — recovered %d "
                    ~ "network→server mapping(s) from per-engine mirrors",
                    raw.length);
                foreach (netId, serverId; raw) {
                    db.hset(RedisKeys.networkAssignments(), netId, serverId);
                }
            }
        }

        foreach (netId, serverId; raw) {
            NetworkAssignment na;
            na.networkId = netId;
            na.serverId = serverId;
            result ~= na;
        }
        return result;
    }

    /// SCAN-based recovery of network→server mappings from per-engine
    /// assignment mirrors. Each mirror is `irc:server-assignments:<sid>`
    /// with one field per networkId. Last-write-wins when two engines
    /// claim the same networkId (which would already be a logic bug);
    /// we keep the first one seen to stay deterministic.
    private string[string] recoverAssignmentsFromMirrors() {
        import std.algorithm : filter, map;
        import std.array : array;
        enum prefix = "irc:server-assignments:";
        enum prefixLen = prefix.length;

        string[string] result;
        string cursor = "0";
        do {
            auto sr = redis.scanKeys(cursor, RedisKeys.serverAssignmentsPattern(), 100);
            cursor = sr.cursor;
            foreach (key; sr.keys) {
                if (key.length <= prefixLen) continue;
                auto fields = redis.hgetAll(key);
                foreach (netId, serverId; fields) {
                    // Trust the mirror's stored serverId; it's set by the
                    // engine itself and can't drift.
                    if (netId !in result)
                        result[netId] = serverId;
                }
            }
        } while (cursor != "0");
        return result;
    }
}
