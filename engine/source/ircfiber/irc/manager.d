module ircfiber.irc.manager;

import std.uuid : UUID;
import std.conv : to;
import std.string : toStringz;

import ircfiber.engine.event_channel : EngineEventChannel;
import vibe.core.log;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : Network, NetworkConfig, TLSMode;
import ircfiber.irc.connection : PersistentIRCClient, HistoryRequestResult, ClientMemoryCounters;
import ircfiber.irc.bnc_ownership : BncCommandOwner;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.holder_client : HolderClient, HolderEntry, AttachResult;
import ircfiber.engine.session_snapshot : SessionSnapshot;
import ircfiber.redis.protocol : RedisKeys, IRCCommand;
import ircfiber.logging : logJsonMap;
import std.uuid : parseUUID;
import vibe.data.json : Json;
import std.datetime : Clock;
import core.time : Duration;

/// Per-host circuit breaker state. Tracks consecutive failures to the
/// same host so we don't hammer unresponsive servers (getting us banned).
private struct HostCircuitBreaker {
    /// Number of consecutive failures since last success.
    int failCount;
    /// Unix-ms timestamp when the circuit was last tripped (opened).
    /// 0 = circuit is closed (normal operation).
    long openedAt;
    /// Unix-ms of the most recent attempt.
    long lastAttemptAt;
}

struct MemoryNetworkCounters {
    string networkId;
    /// Sum of entries across general identity caches, not distinct nicknames.
    ulong identities;
    ulong members;
}

struct MemoryOwnerCounters {
    ulong activeGenerations;
    ulong retiredGenerations;
    ulong completedRetiredGenerations;
    ulong members;
    ulong namesMembers;
    ulong realnames;
    ulong realnameProbed;
    ulong idents;
    ulong accounts;
    ulong away;
    ulong bots;
    ulong userMetadata;
    ulong pendingMetaFlags;
    ulong ordinaryMetaPublishers;
    ulong metaBuilds;
    ulong eventBufferFill;
    ulong eventBufferCapacity;
    MemoryNetworkCounters[5] largestNetworks;
    size_t largestNetworkCount;
}

private void addMemoryCounters(ref MemoryOwnerCounters total,
        const ref ClientMemoryCounters client) nothrow @safe {
    total.members += client.members;
    total.namesMembers += client.namesMembers;
    total.realnames += client.realnames;
    total.realnameProbed += client.realnameProbed;
    total.idents += client.idents;
    total.accounts += client.accounts;
    total.away += client.away;
    total.bots += client.bots;
    total.userMetadata += client.userMetadata;
    total.pendingMetaFlags += client.pendingMetaFlags;
    total.ordinaryMetaPublishers += client.ordinaryMetaPublishers;
    total.metaBuilds += client.metaBuilds;
}

private void addLargestNetwork(ref MemoryOwnerCounters total, string networkId,
        const ref MemoryOwnerCounters network) nothrow @safe {
    const identities = network.realnames + network.realnameProbed + network.idents
        + network.accounts + network.away + network.bots + network.userMetadata;
    size_t position;
    while (position < total.largestNetworkCount
            && total.largestNetworks[position].identities >= identities) position++;
    if (position >= total.largestNetworks.length) return;
    if (total.largestNetworkCount < total.largestNetworks.length)
        total.largestNetworkCount++;
    for (size_t i = total.largestNetworkCount - 1; i > position; i--)
        total.largestNetworks[i] = total.largestNetworks[i - 1];
    total.largestNetworks[position] = MemoryNetworkCounters(networkId, identities, network.members);
}

private string maintenanceText(Json object, string field, size_t maximum, bool required = true) {
    auto value = object[field].get!string;
    if ((required && !value.length) || value.length > maximum)
        throw new Exception("invalid maintenance field: " ~ field);
    foreach (c; value) if (c < 0x20 || c == 0x7f)
        throw new Exception("control character in maintenance field: " ~ field);
    return value;
}

private bool maintenanceHex(string value, size_t length) {
    if (value.length != length) return false;
    foreach (c; value) if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) return false;
    return true;
}

private bool validateMaintenanceProvenance(Json projection, string oldInstance, long oldPid) {
    import std.algorithm : canFind;
    if (projection["mode"].type == Json.Type.undefined) {
        if (projection["coordinated"].type != Json.Type.undefined
                || projection["affinityBasis"].type != Json.Type.undefined)
            throw new Exception("maintenance provenance has no declared coordinated mode");
        return false;
    }
    if (projection["mode"].get!string != "coordinated"
            || projection["affinityBasis"].get!string != "current_verified")
        throw new Exception("unsupported coordinated maintenance affinity basis");
    auto proof = projection["coordinated"];
    if (proof.type != Json.Type.object
            || !maintenanceHex(maintenanceText(proof, "evidenceSha256", 64), 64)
            || !maintenanceHex(maintenanceText(proof, "sourceRevision", 40), 40))
        throw new Exception("coordinated immutable capture provenance unavailable");
    foreach (string field, value; proof)
        if (!["oldEngine", "oldHolder", "newHolder", "firstEngine",
                "evidenceSha256", "sourceRevision"].canFind(field))
            throw new Exception("unexpected coordinated capture field: " ~ field);
    bool[string] identities;
    foreach (field; ["oldEngine", "oldHolder", "newHolder", "firstEngine"]) {
        auto identity = proof[field];
        if (identity.type != Json.Type.object)
            throw new Exception("coordinated identity is not an object");
        foreach (string property, value; identity) {
            if (!["id", "image", "pid", "hostPid", "startedAt", "instance"].canFind(property)
                    || (field == "firstEngine" && property != "id" && property != "image")
                    || (property == "instance" && field != "newHolder"))
                throw new Exception("unexpected coordinated identity field: " ~ property);
        }
        const id = maintenanceText(identity, "id", 64);
        const image = maintenanceText(identity, "image", 71);
        if (!maintenanceHex(id, 64) || id in identities || image.length != 71
                || image[0 .. 7] != "sha256:" || !maintenanceHex(image[7 .. $], 64))
            throw new Exception("coordinated exact container/image identity invalid");
        identities[id] = true;
        if (field != "firstEngine") {
            maintenanceText(identity, "startedAt", 64);
            if (identity["pid"].get!long <= 0)
                throw new Exception("coordinated process identity unavailable");
            if (identity["hostPid"].get!long <= 0)
                throw new Exception("coordinated kernel process identity unavailable");
        }
    }
    if (proof["oldHolder"]["pid"].get!long != oldPid)
        throw new Exception("coordinated old holder process identity mismatch");
    const instance = maintenanceText(proof["newHolder"], "instance", 36);
    maintenanceUuid(instance);
    if (instance == oldInstance)
        throw new Exception("coordinated holder incarnation did not change");
    return true;
}

private UUID maintenanceUuid(string value, bool allowZero = false) {
    const original = value;
    auto cursor = value;
    auto parsed = parseUUID(cursor);
    if (original.length != 36 || cursor.length || parsed.toString() != original
            || (!allowZero && parsed == UUID.init))
        throw new Exception("noncanonical maintenance UUID");
    return parsed;
}

/// Validate the complete DTO before taking a hold or applying any row. Private
/// old META is deliberately not a part of this restoration contract.
private bool validateMaintenanceProjection(Json projection, string operation, string serverId, long now) {
    import std.algorithm : canFind;
    import std.string : split;
    maintenanceUuid(operation);
    if (projection["version"].get!int != 1
            || projection["operationId"].get!string != operation
            || projection["serverId"].get!string != serverId || !serverId.length)
        throw new Exception("active holder maintenance manifest mismatch");
    const prepared = projection["preparedAtMs"].get!long;
    const deadline = projection["deadlineMs"].get!long;
    if (prepared <= 0 || prepared > now || deadline <= prepared
            || deadline - prepared > 600000)
        throw new Exception("active holder maintenance preparation interval is invalid");
    const oldInstance = maintenanceText(projection, "oldHolderInstance", 36, false);
    if (oldInstance.length) maintenanceUuid(oldInstance);
    if (projection["oldHolderPid"].get!long <= 0)
        throw new Exception("active holder maintenance old process identity unavailable");
    const coordinated = validateMaintenanceProvenance(projection, oldInstance,
        projection["oldHolderPid"].get!long);
    auto rows = projection["rows"];
    if (rows.type != Json.Type.array || rows.length > 4096)
        throw new Exception("active holder maintenance manifest exceeds row bound");
    bool[string] networks, sockets;
    string[string] slots;
    size_t projectedBytes = 64 * 1024;
    foreach (row; rows) {
        if (row.type != Json.Type.object) throw new Exception("maintenance row is not an object");
        foreach (string field, value; row)
            if (!["networkId", "userId", "host", "port", "tls", "oldHolderId",
                    "oldConnectedAtMs", "registeredAtMs", "route", "routeIdentity",
                    "routingPreferences", "state", "newHolderId", "newConnectedAtMs",
                    "observed001AtMs", "actualRoute", "classifiedAtMs", "reason",
                    "historicalExitUnprovable"].canFind(field))
                throw new Exception("unexpected maintenance row field: " ~ field);
        const network = maintenanceText(row, "networkId", 36);
        maintenanceUuid(network);
        maintenanceUuid(maintenanceText(row, "userId", 36), true);
        const socket = maintenanceText(row, "oldHolderId", 256);
        if (network in networks || socket in sockets)
            throw new Exception("duplicate maintenance network/old socket ownership");
        networks[network] = true;
        sockets[socket] = true;
        maintenanceText(row, "host", 253);
        const port = row["port"].get!long;
        const tls = maintenanceText(row, "tls", 8);
        if (port <= 0 || port > ushort.max
                || (tls != "none" && tls != "starttls" && tls != "implicit"))
            throw new Exception("invalid maintenance destination");
        const connected = row["oldConnectedAtMs"].get!long;
        const registered = row["registeredAtMs"].get!long;
        if (connected <= 0 || registered < connected || registered > prepared)
            throw new Exception("invalid maintenance registration evidence");
        auto route = row["route"];
        if (route.type != Json.Type.object) throw new Exception("maintenance route is not an object");
        foreach (string field, value; route)
            if (!["provider", "slot", "exitId", "nativeIpv6"].canFind(field))
                throw new Exception("unexpected maintenance route field: " ~ field);
        const provider = maintenanceText(route, "provider", 16);
        const slot = maintenanceText(route, "slot", 256, false);
        const exit = maintenanceText(route, "exitId", 256, false);
        const native = maintenanceText(route, "nativeIpv6", 64, false);
        const identity = maintenanceText(row, "routeIdentity", 2048);
        if (provider == "direct" || provider == "ipv6") {
            if (slot.length || exit.length || (provider == "direct" && native.length)
                    || (provider == "ipv6" && !native.length)
                    || identity != "direct|" ~ native)
                throw new Exception("inconsistent maintenance direct/native route");
        } else if (provider == "mullvad" || provider == "nordvpn") {
            const parts = identity.split("|");
            if (!slot.length || !exit.length || native.length || parts.length != 5
                    || parts[0] != "vpn" || parts[1] != slot || !parts[2].length
                    || exit != (parts[3].length ? parts[3] : "slot:" ~ slot))
                throw new Exception("incomplete maintenance concrete exit proof");
            if (auto prior = slot in slots) {
                if (*prior != identity) throw new Exception("nonunique maintenance concrete route");
            } else slots[slot] = identity;
        } else throw new Exception("unknown maintenance route provider");
        if (row["routingPreferences"].type != Json.Type.object)
            throw new Exception("frozen maintenance routing preferences unavailable");
        if (coordinated && row["historicalExitUnprovable"].type != Json.Type.bool_)
            throw new Exception("coordinated historical-exit uncertainty must be explicitly disclosed");
        const state = maintenanceText(row, "state", 16);
        if (state != "pending") {
            const classified = row["classifiedAtMs"].get!long;
            maintenanceText(row, "reason", 2048);
            if (classified <= prepared || classified > deadline)
                throw new Exception("invalid maintenance classification evidence");
            if (state == "recovered") {
                if (maintenanceText(row, "newHolderId", 256) == socket
                        || row["newConnectedAtMs"].get!long <= 0
                        || row["observed001AtMs"].get!long != classified
                        || row["actualRoute"] != route)
                    throw new Exception("invalid maintenance actual 001 evidence");
            } else if (state != "refused" && state != "unresolved")
                throw new Exception("invalid maintenance classification");
        }
        const rowBytes = row.toString().length;
        const evidenceBytes = rowBytes * 2 + 4096;
        if (rowBytes > 8192 || evidenceBytes > 2 * 1024 * 1024 - projectedBytes)
            throw new Exception("holder maintenance manifest exceeds bounded projection capacity");
        projectedBytes += evidenceBytes;
    }
    return coordinated;
}

/// Manages IRC network connections for users.
final class ConnectionManager {
    /// Bounded (five seconds total) before a newly created fresh producer.
    /// False/unavailable records an archival gap but never disables live IRC.
    bool delegate(string networkId, string ownerId) prepareFreshArchiveScope;

    private {
        PersistentIRCClient[string] clients;
        // Removed generations can still be inside holder DIAL. Keep them
        // until their actual loop/attach completion, not just map removal.
        PersistentIRCClient[][string] retiredClients;
        bool[string] knownNetworks;
        bool[string] moveStops;
        bool observingRetiredProvenance;
        bool terminating;
        EngineEventChannel mainEventChannel;
        UUID[string] networkOwners;
        RedisStorage redis;
        string serverId;
        /// Per-host circuit breakers for smart rate limiting.
        /// Keyed by host:port string (e.g. "irc.supernets.org:6697").
        HostCircuitBreaker[string] hostBreakers;
        /// Client of this engine's connection holder (null only in tests).
        HolderClient holder;
        /// Networks removed on this engine, `networkId` → unix ms.
        ///
        /// Stopping a client emits its farewell events (the QUIT echo and
        /// the server's `ERROR :Quit:`) into the shared event channel, and
        /// the processor persists whatever it drains — AFTER the delete path
        /// has cleared that network's scrollback. The result was a deleted
        /// network keeping a `_server` and `#channel` buffer, which is how
        /// its rooms stayed renderable at /irc/<name>/channel/%23chan long
        /// after the sidebar dropped it. The processor consults this map and
        /// drops those events instead.
        long[string] removedAtMs;
        string maintenanceId;
        long maintenanceDeadlineMs;
        long maintenancePreparedAtMs;
        string maintenanceOldInstance;
        long maintenanceOldPid;
        Json[] maintenanceRows;
        PersistentIRCClient[] maintenanceAnchors;
        string[] restoredMaintenanceSlots;
        bool maintenanceWorkerRunning;
        bool maintenanceProbeRunning;
        bool maintenanceGenerationLost;
        bool maintenanceRestorePending = true;
        Json maintenanceProvenance;
    }

    /// Creates a new connection manager with the given event channel.
    this(EngineEventChannel eventChannel, RedisStorage redisStore = null, string sid = "",
         HolderClient holderClient = null) nothrow @safe {
        this.mainEventChannel = eventChannel;
        this.redis = redisStore;
        this.serverId = sid;
        this.holder = holderClient;
    }

    /// Observe rooted generations without snapshots, duplicated arrays or META.
    MemoryOwnerCounters memoryCounters() nothrow @safe {
        MemoryOwnerCounters result;
        result.activeGenerations = clients.length;
        result.eventBufferFill = mainEventChannel.bufferFill;
        result.eventBufferCapacity = typeof(mainEventChannel).bufferSize;
        foreach (entry; clients.byKeyValue) {
            const key = entry.key;
            auto client = entry.value;
            MemoryOwnerCounters network;
            auto counts = client.memoryCounters();
            addMemoryCounters(network, counts);
            addMemoryCounters(result, counts);
            if (auto retired = key in retiredClients) {
                foreach (old; *retired) {
                    result.retiredGenerations++;
                    if (old.getMoveQuiescent()) result.completedRetiredGenerations++;
                    counts = old.memoryCounters();
                    addMemoryCounters(network, counts);
                    addMemoryCounters(result, counts);
                }
            }
            addLargestNetwork(result, key, network);
        }
        foreach (entry; retiredClients.byKeyValue) {
            const key = entry.key;
            auto retired = entry.value;
            if (key in clients) continue;
            MemoryOwnerCounters network;
            foreach (old; retired) {
                result.retiredGenerations++;
                if (old.getMoveQuiescent()) result.completedRetiredGenerations++;
                const counts = old.memoryCounters();
                addMemoryCounters(network, counts);
                addMemoryCounters(result, counts);
            }
            addLargestNetwork(result, key, network);
        }
        return result;
    }

    /// Networks whose IRC registration timed out (REGISTRATION_OVERALL_TIMEOUT_SECS
    /// elapsed without 001 being received from the server). Returns
    /// networkIds whose client.getRegistrationTimeoutSince() > 0.
    /// Surfaced to the admin SPA via the per-server health snapshot so
    /// operators can distinguish "this network is stuck in registration"
    /// from "this network has a slow DNS" — two different root causes
    /// with two different fixes.
    string[] networksAwaitingRegistration() const {
        string[] result;
        foreach (key, client; clients) {
            if (client.getRegistrationTimeoutSince > 0)
                result ~= key;
        }
        return result;
    }

    bool hasNetworkHistory(UUID id) const {
        return (id.toString() in knownNetworks) !is null;
    }

    /// Reclaim only generations that have positively finished all local work.
    /// This never closes a transport. Dial/holder provenance outlives the graph
    /// until independently observed durable and physical quiescence.
    void reapRetiredClients(long nowMs) {
        import ircfiber.irc.dial_guard : networkDialsQuiescent;
        reapCompletedClientRoots(nowMs);
        // A stalled external observation must not prevent subsequent local
        // sweeps from releasing completed graphs or expiring tombstones.
        if (observingRetiredProvenance) return;
        observingRetiredProvenance = true;
        scope(exit) observingRetiredProvenance = false;

        // Local collection must not depend on either external service. Missing
        // or failed observations preserve only the small provenance records.
        if (holder is null || redis is null || !serverId.length) return;
        string[] candidates;
        foreach (key; knownNetworks.byKey)
            if (provenanceUnowned(key)) candidates ~= key;
        if (!candidates.length) return;

        // Redis and LIST yield. Never hold an associative-array iterator or
        // client graph across them, and recheck ownership after each admission.
        bool[string] quietNetworks;
        foreach (key; candidates) {
            try {
                if (networkDialsQuiescent(redis, serverId, key, holder)
                        && provenanceUnowned(key))
                    quietNetworks[key] = true;
            } catch (Exception) {
                // An unavailable durable ledger is not closure evidence.
            }
        }
        if (!quietNetworks.length) return;
        try {
            // One fresh physical inventory (or genuine legacy LIST) for the
            // provenance pass, never an assignment/count-derived substitute.
            foreach (entry; holder.scan())
                if (entry.state == "open") quietNetworks.remove(entry.tag.networkId);
        } catch (Exception) {
            return;
        }
        foreach (key; quietNetworks.byKey)
            if (provenanceUnowned(key)) knownNetworks.remove(key);
    }

    // Keep client-bearing locals out of the frame that may wait on Redis/IPC.
    private void reapCompletedClientRoots(long nowMs) {
        // No yielding while compacting roots. Clear the entire vacated tail:
        // shrinking a slice alone leaves its backing allocation rooting clients.
        string[] emptyRetired;
        foreach (key, ref generations; retiredClients) {
            size_t kept;
            foreach (client; generations) {
                if (!client.getMoveQuiescent()) generations[kept++] = client;
            }
            generations[kept .. $] = null;
            generations = generations[0 .. kept];
            if (!kept) {
                generations = null;
                emptyRetired ~= key;
            }
        }
        foreach (key; emptyRetired) retiredClients.remove(key);

        string[] expired;
        foreach (key, at; removedAtMs)
            if (nowMs >= at && nowMs - at > REMOVED_MEMORY_MS) expired ~= key;
        foreach (key; expired) removedAtMs.remove(key);
    }

    private bool provenanceUnowned(string key) const {
        return key !in clients && key !in retiredClients && key !in moveStops
            && key !in removedAtMs;
    }

    /// Adds a network for a user and starts its IRC client.
    void addNetwork(NetworkConfig config, UUID userId) {
        if (config.servicesProvisioningPending) return;
        auto key = config.id.toString();
        if (terminating || key in moveStops) return;
        knownNetworks[key] = true;
        if (key in clients) {
            logWarn("Network %s already managed", config.name);
            return;
        }

        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId, holder);
        applyMaintenanceAffinity(client, key, userId);
        clients[key] = client;
        networkOwners[key] = userId;
        removedAtMs.remove(key);
        // Defer start() to avoid runTask() inside the bootstrap loop.
        // The caller must call startDeferredClients() after all networks
        // are loaded.
    }

    /// Adds a network and starts its IRC client immediately.
    /// Used when a single network needs to start outside the bootstrap loop
    /// (e.g. reconnectNetwork control message).
    void addAndStartNetwork(NetworkConfig config, UUID userId) {
        if (config.servicesProvisioningPending) return;
        auto key = config.id.toString();
        if (terminating || key in moveStops) return;
        knownNetworks[key] = true;
        if (key in clients) {
            logWarn("Network %s already managed", config.name);
            return;
        }

        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId, holder);
        applyMaintenanceAffinity(client, key, userId);
        clients[key] = client;
        networkOwners[key] = userId;
        startFreshClient(client, key);
        // Re-adding clears the removal marker (reconnectNetwork removes and
        // immediately re-adds), or every event of the new client would be
        // dropped as belonging to a deleted network.
        removedAtMs.remove(key);
    }

    private void startFreshClient(PersistentIRCClient client, string key) {
        auto prepare = prepareFreshArchiveScope;
        if (prepare is null) {
            client.start();
            return;
        }
        client.start(() {
            const owner = client.getOwnerId.toString();
            bool ready;
            try ready = prepare(key, owner);
            catch (Exception) {}
            if (!ready) {
                try logJsonMap("error", "engine", "Archive scope unavailable before fresh producer; live IRC preserved",
                    ["event": "archive_gap", "networkId": key, "reason": "scope_preparation_unavailable"]);
                catch (Exception) {}
            }
            auto current = key in clients;
            return !terminating && !client.getStopping && current !is null && *current is client
                && client.getOwnerId.toString() == owner;
        });
    }

    /// Starts IRC clients for all networks that were added via addNetwork.
    /// Clients attached to a held connection are already running.
    void startDeferredClients() {
        foreach (key, client; clients) {
            if (client.getConnected) continue;
            startFreshClient(client, key);
            logInfo("Started IRC client for %s", client.getConfig.name);
        }
    }

    /// Removes a network and stops its IRC client.
    void removeNetwork(UUID networkId) {
        auto key = networkId.toString();
        // Marked before `stop()`: stopping is what emits the QUIT/ERROR
        // farewell into the shared event channel, and those must already be
        // droppable by the time the processor drains them.
        const nowMs = Clock.currTime.toUnixTime!long * 1000;
        removedAtMs[key] = nowMs;
        if (auto p = key in clients) {
            auto client = *p;
            // Root the stopped generation before stop(), which may yield.
            retiredClients[key] ~= client;
            clients.remove(key);
            networkOwners.remove(key);
            // Mirror MongoDB's disabled flag into the stopped generation.
            client.getConfig().disabled = true;
            client.stop();
            client = null;
        }
        reapCompletedClientRoots(nowMs);
    }

    /// Positive source closure, bounded independently of the control consumer.
    /// Missing/untracked generations and ambiguous IPC are not closure proof.
    bool stopNetworkForMove(UUID networkId, Duration timeout) {
        import vibe.core.core : sleep;
        import core.time : msecs;
        import ircfiber.irc.dial_guard : networkDialsQuiescent;
        import ircfiber.term_signal : termSignal;
        const key = networkId.toString();
        if (terminating || termSignal() != 0 || holder is null || key !in knownNetworks
                || key in moveStops) return false;
        moveStops[key] = true;
        scope(exit) {
            moveStops.remove(key);
            reapCompletedClientRoots(Clock.currTime.toUnixTime!long * 1000);
        }
        const deadline = Clock.currTime + timeout;
        PersistentIRCClient[] generations;
        scope(exit) {
            generations[] = null;
            generations = null;
        }
        if (auto old = key in retiredClients) generations ~= *old;
        if (auto client = key in clients) generations ~= *client;
        foreach (client; generations) client.requestMoveStop();
        foreach (client; generations) client.stop();
        while (true) {
            if (terminating || termSignal() != 0 || Clock.currTime >= deadline) return false;
            bool quiet = true;
            foreach (client; generations) if (!client.getMoveQuiescent) quiet = false;
            if (quiet && networkDialsQuiescent(redis, serverId, key, holder)) break;
            sleep(25.msecs);
        }
        // Every generation is now unable to create another entry. CLOSE all,
        // including entries a late DIAL returned after stop() first ran.
        foreach (entry; holder.scan()) {
            if (Clock.currTime >= deadline || terminating || termSignal() != 0) return false;
            if (entry.tag.networkId == key && entry.state == "open")
                holder.closeClaim(entry.id, entry.instance, entry.connectedAtMs, "routing move");
        }
        if (Clock.currTime >= deadline || terminating || termSignal() != 0) return false;
        foreach (entry; holder.scan())
            if (entry.tag.networkId == key && entry.state == "open") return false;
        if (!networkDialsQuiescent(redis, serverId, key, holder)) return false;
        clients.remove(key);
        networkOwners.remove(key);
        return true;
    }

    /// How long a removal is remembered. Long enough to outlive the event
    /// pipeline draining a stopped client's farewell, short enough that an
    /// id re-added later (a network recreated with the same UUID by a
    /// restore) is not silenced. `addNetwork`/`addAndStartNetwork` clear the
    /// marker explicitly, so this is only a backstop.
    private enum long REMOVED_MEMORY_MS = 60_000;

    /// True when this network was removed here and its trailing events must
    /// not be persisted or published. Prunes stale entries as it goes.
    bool isRemoved(string networkId) {
        if (networkId.length == 0) return false;
        const now = Clock.currTime.toUnixTime!long * 1000;
        auto at = networkId in removedAtMs;
        if (at is null) return false;
        if (now - *at > REMOVED_MEMORY_MS) {
            removedAtMs.remove(networkId);
            return false;
        }
        return true;
    }

    /// Disconnects a network without removing it. If `quitReason` is set
    /// the engine will send `QUIT :<reason>` before closing the socket so
    /// the IRC server emits a final ERROR back to the client.
    void disconnectNetwork(UUID networkId, string quitReason = "") {
        const key = networkId.toString();
        if (auto p = key in clients) {
            (*p).stop(quitReason);
        }
    }

    /// Drops the transport of every network currently egressing through the
    /// named Mullvad slot, so each one's own reconnect loop re-dials and
    /// re-runs egress selection — landing on the slot's new exit.
    ///
    /// Used after an operator force-swaps a slot that was carrying
    /// connections. Without it those sockets keep pointing at a relay the
    /// sidecar no longer routes through: nothing errors, the connection just
    /// goes quiet until the server's ping timeout minutes later. A deliberate
    /// close turns that into a ~5 s reconnect.
    int bounceNetworksOnEgress(string egressLabel) {
        if (egressLabel.length == 0) return 0;
        int bounced = 0;
        foreach (id, client; clients) {
            if (client is null) continue;
            if (client.getActiveEgressLabel != egressLabel) continue;
            if (!client.getConnected) continue;
            logInfo("Egress swap: bouncing %s so it re-dials through the new exit",
                client.getConfig.name);
            client.transportClose("egress retargeted");
            bounced++;
        }
        return bounced;
    }

    PersistentIRCClient getClient(UUID networkId) {
        const key = networkId.toString();
        if (auto p = key in clients) {
            return *p;
        }
        return null;
    }

    Network[] getNetworks() {
        Network[] result;
        foreach (client; clients) {
            Network net;
            net.config = client.getConfig;
            net.isConnected = client.getConnected;
            net.status = client.getState.to!string;
            net.currentNick = client.getCurrentNick;
            result ~= net;
        }
        return result;
    }

    Network[] getNetworksForUser(UUID userId) {
        Network[] result;
        foreach (id, client; clients) {
            if (networkOwners.get(id, UUID.init) == userId) {
                Network net;
                net.config = client.getConfig;
                net.isConnected = client.getConnected;
                net.status = client.getState.to!string;
                net.currentNick = client.getCurrentNick;
                result ~= net;
            }
        }
        return result;
    }

    string[] getJoinedChannels(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getJoinedChannels;
        }
        return [];
    }

    /// Record a connection failure to a host. After FAIL_THRESHOLD consecutive
    /// failures within the window, the circuit opens for COOLDOWN_MS.
    void recordHostFailure(string host, int port) {
        auto key = host ~ ":" ~ port.to!string;
        auto now = Clock.currTime.toUnixTime!long * 1000;
        auto breaker = key in hostBreakers;
        if (breaker !is null) {
            // Reset window if too much time passed since last attempt
            if (now - breaker.lastAttemptAt > HOST_CIRCUIT_WINDOW_MS) {
                breaker.failCount = 0;
                breaker.openedAt = 0;
            }
            breaker.failCount++;
            breaker.lastAttemptAt = now;
            if (breaker.failCount >= HOST_FAIL_THRESHOLD && breaker.openedAt == 0) {
                breaker.openedAt = now;
                logWarn("Host circuit breaker OPENED for %s after %d failures (cooling down %d ms)",
                    key, breaker.failCount, HOST_COOLDOWN_MS);
            }
        } else {
            hostBreakers[key] = HostCircuitBreaker(1, 0, now);
        }
    }

    /// Record a successful connection — resets the breaker for this host.
    void recordHostSuccess(string host, int port) {
        auto key = host ~ ":" ~ port.to!string;
        if (auto breaker = key in hostBreakers) {
            if (breaker.openedAt > 0) {
                logInfo("Host circuit breaker CLOSED for %s (connection succeeded)", key);
            }
            hostBreakers.remove(key);
        }
    }

    /// Check if the circuit breaker allows a new connection attempt.
    /// Returns true if the connection is allowed, false if cooling down.
    bool canConnectToHost(string host, int port) {
        auto key = host ~ ":" ~ port.to!string;
        if (auto breaker = key in hostBreakers) {
            if (breaker.openedAt > 0) {
                const now = Clock.currTime.toUnixTime!long * 1000;
                if (now - breaker.openedAt < HOST_COOLDOWN_MS) {
                    return false;
                }
                // Cooldown expired — close the circuit (reset for next cycle)
                hostBreakers.remove(key);
                logInfo("Host circuit breaker CLOSED for %s (cooldown expired)", key);
            }
        }
        return true;
    }

    /// Time window for counting failures (rolling 30 minutes).
    private static immutable HOST_CIRCUIT_WINDOW_MS = 30 * 60 * 1000;
    /// Consecutive failures before opening the circuit.
    private static immutable HOST_FAIL_THRESHOLD = 5;
    /// Cooldown duration when circuit is open (30 minutes).
    private static immutable HOST_COOLDOWN_MS = 30 * 60 * 1000;

    string[string] getChannelTopics(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getChannelTopics;
        }
        return null;
    }

    string[][string] getChannelUsers(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getChannelUsers;
        }
        return null;
    }

    /// Returns the realname cache (nick → realname) for a network.
    /// IRCCloud parity: populated from extended-join (JOIN params[2]) and
    /// RPL_WHOISUSER (311). Used by the frontend to render
    /// <span class="author-realname"> next to the nick.
    string[string] getRealnames(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getRealnames;
        }
        return null;
    }

    string[string] getAccounts(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getAccounts;
        }
        return null;
    }

    /// Nick → away message ("" = away without text); absent = present.
    string[string] getAway(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getAway;
        }
        return null;
    }

    /// Nick → "1" for users flagged as bots.
    string[string] getBots(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getBots;
        }
        return null;
    }

    /// draft/metadata-2 user keys: nick → key → value.
    string[string][string] getUserMetadata(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getUserMetadata;
        }
        return null;
    }

    /// draft/metadata-2 channel keys: lowercase channel → key → value.
    string[string][string] getChannelMetadata(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getChannelMetadata;
        }
        return null;
    }

    /// Drops the network's entry from the public-avatar registry. Only for
    /// an explicit removal: a reconnect re-adds it on the next 900.
    void forgetPublicAvatar(UUID networkId) {
        if (auto client = getClient(networkId)) client.forgetPublicAvatar();
    }

    string[string] getIdents(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getIdents;
        }
        return null;
    }

    /// Checks if a given IRCv3 capability is negotiated for a network.
    bool hasCap(UUID networkId, string cap) {
        if (auto client = getClient(networkId)) {
            return client.hasCap(cap);
        }
        return false;
    }

    /// Returns all negotiated capabilities for a network.
    string[] getAckedCaps(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getAckedCaps();
        }
        return [];
    }

    /// Sends a message to a target on a network, with optional client
    /// tags (`+reply`, for example).
    void sendMessage(UUID networkId, string target, string text,
                     string[string] tags = null) {
        if (auto client = getClient(networkId)) {
            client.sendMessage(target, text, tags);
        }
    }

    /// Sends a labeled message to a target on a network.
    void sendLabeledMessage(UUID networkId, string target, string text, string label,
                            string[string] tags = null) {
        if (auto client = getClient(networkId)) {
            client.sendLabeledMessage(target, text, label, tags);
        }
    }

    /// Pushes a read marker upstream (draft/read-marker); no-op without
    /// the cap or a live connection.
    void sendMarkRead(UUID networkId, string target, long timestampMs) {
        if (auto client = getClient(networkId)) {
            client.sendMarkRead(target, timestampMs);
        }
    }

    /// Joins a channel on a network.
    void joinChannel(UUID networkId, string channel) {
        if (auto client = getClient(networkId)) {
            client.joinChannel(channel);
        }
    }

    /// Parts a channel on a network.
    void partChannel(UUID networkId, string channel, string reason = "") {
        if (auto client = getClient(networkId)) {
            client.partChannel(channel, reason);
        }
    }

    /// Sends a raw IRC line a client asked for to a network.
    void sendRaw(UUID networkId, string line) {
        if (auto client = getClient(networkId)) {
            client.sendRaw(line, true);
        }
    }

    /// Private BNC commands never use the web message-echo label registry.
    void submitBncRaw(UUID networkId, string line, string wireLabel,
            BncCommandOwner owner, string[string] clientTags = null) {
        if (auto client = getClient(networkId))
            client.submitBncRaw(line, wireLabel, owner, clientTags);
    }

    void submitBncMessage(UUID networkId, string target, string text, string wireLabel,
            BncCommandOwner owner, string[string] clientTags = null) {
        if (auto client = getClient(networkId))
            client.submitBncMessage(target, text, wireLabel, owner, clientTags);
    }

    void handleBncMonitor(UUID networkId, IRCCommand command, long nowMs) {
        if (auto client = getClient(networkId))
            client.handleBncMonitor(command, nowMs);
    }

    /// Admission result distinguishes queued work from unsupported/invalid requests.
    HistoryRequestResult requestChathistory(UUID networkId, string channel, string command,
                            string refMsgid, int limit) {
        if (auto client = getClient(networkId))
            return client.requestChathistory(channel, command, refMsgid, limit);
        return HistoryRequestResult.unsupported;
    }

    /// Called only by the ordered processor after the page's Redis verdict.
    void confirmHistoryPage(UUID networkId, string requestId, bool committed) {
        if (auto client = getClient(networkId))
            client.confirmHistoryPage(requestId, committed);
    }

    /// Returns the latest msgid observed for the channel on the given network.
    string getLatestMsgid(UUID networkId, string channel) {
        if (auto client = getClient(networkId)) {
            return client.getLatestMsgid(channel);
        }
        return "";
    }

    /// Returns the earliest msgid observed for the channel on the given network.
    string getEarliestMsgid(UUID networkId, string channel) {
        if (auto client = getClient(networkId)) {
            return client.getEarliestMsgid(channel);
        }
        return "";
    }

    /// Information about a buffer (channel or query).
    struct BufferInfo {
        /// Buffer name.
        string name;
        /// Buffer type (channel, query, server).
        string type;
        /// Whether the buffer is currently joined.
        bool isJoined;
    }

    BufferInfo[] getBuffersForNetwork(UUID networkId) {
        BufferInfo[] result;
        result ~= BufferInfo("_server", "server", true);
        if (auto client = getClient(networkId)) {
            foreach (ch; client.getJoinedChannels) {
                result ~= BufferInfo(ch, "channel", true);
            }
            foreach (q; client.getQueryBuffers) {
                result ~= BufferInfo(q, "query", true);
            }
        }
        return result;
    }

    /// Clears unread count for a channel (frontend hook).
    void clearUnread(string _networkIdStr, string _channel) {
        cast(void)_networkIdStr;
        cast(void)_channel;
        // Unread tracking is handled entirely in the frontend
        // (see public/ircfiber.js incrementUnread / setActiveBuffer).
        // This method exists as a hook if engine-side tracking is ever needed.
    }

    /// Updates configuration for an existing network.
    void updateConfig(NetworkConfig config) {
        const key = config.id.toString();
        if (auto p = key in clients) {
            (*p).updateConfig(config);
        }
    }

    string getOwnerId(UUID networkId) {
        const key = networkId.toString();
        if (auto p = key in networkOwners) {
            return p.toString();
        }
        return "";
    }

    /// Checks if a network is managed by UUID.
    bool hasNetwork(UUID networkId) {
        return (networkId.toString() in clients) !is null;
    }

    /// Checks if a network is managed by string ID.
    bool hasNetwork(string networkIdStr) {
        return (networkIdStr in clients) !is null;
    }

    /// Decommission: QUIT every network, wait briefly for the servers to
    /// close (so the holder sees upstream EOF and the UI gets the final
    /// `ERROR :Closing Link`), then close whatever is still open through
    /// the holder explicitly. Must run inside the event loop (the signal
    /// watcher task drives it): the upstream sockets live in the holder
    /// process, so nothing closes them "on exit" any more.
    void shutdown() {
        terminating = true;
        import vibe.core.core : sleep;
        import core.time : msecs;
        foreach (client; clients) {
            client.stop();
        }
        foreach (_; 0 .. 30) {
            bool anyAlive;
            foreach (client; clients) if (client.transportAlive) { anyAlive = true; break; }
            if (!anyAlive) break;
            sleep(100.msecs);
        }
        foreach (client; clients) {
            try client.transportClose();
            catch (Exception e) logWarn("shutdown: closing %s failed: %s", client.getConfig.name, e.msg);
        }
        clients = null;
        networkOwners = null;
    }

    // ── Hot-swap API (engine SIGTERM) ────────────────────────────────────────

    /// Pause every client's event loop so the detach can publish an exact
    /// snapshot of per-connection state. After this returns, no client is
    /// performing I/O on its relay stream. Returns the clients paused so
    /// the caller can iterate them in the same order.
    PersistentIRCClient[] pauseAllForDetach() {
        PersistentIRCClient[] paused;
        foreach (key, client; clients) {
            client.pauseForDetach();
            paused ~= client;
        }
        // Give every event loop a chance to observe the pause. The loops
        // check the counter at the next yield checkpoint; with
        // PROCESS_READ_TIMEOUT_MS = 50ms worst case we wait a bit longer
        // than that to be safe.
        foreach (client; paused) {
            client.waitForDetachPause();
        }
        return paused;
    }

    /// Hot-swap detach of every client: publish META, close the relay
    /// streams, leave every upstream socket with the holder. No QUIT, no
    /// DISCONNECTED events. Bounded (each META write has a 10 s holder
    /// timeout; the process exits right after this returns).
    void detachAllForHotSwap() {
        terminating = true;
        foreach (client; clients) client.inhibitNewDials();
        foreach (generations; retiredClients)
            foreach (client; generations) client.inhibitNewDials();
        // A successful hot swap drains tracked DIALs before process exit.
        // On timeout the durable marker remains, denying later move ack.
        import ircfiber.irc.dial_guard : networkDialsQuiescent;
        import vibe.core.core : sleep;
        import core.time : seconds, msecs;
        const deadline = Clock.currTime + 60.seconds;
        foreach (key; knownNetworks.byKey) {
            while (!networkDialsQuiescent(redis, serverId, key, holder)) {
                if (Clock.currTime >= deadline)
                    throw new Exception("hot swap has an unproven in-flight holder DIAL");
                sleep(25.msecs);
            }
        }
        auto paused = pauseAllForDetach();
        size_t live;
        foreach (client; paused) {
            try {
                if (client.getConnected) live++;
                client.detachForHotSwap();
            } catch (Exception e) {
                logWarn("detachForHotSwap failed for %s: %s", client.getConfig.name, e.msg);
            }
        }
        logJsonMap("info", "connection",
            "Detached all networks for hot swap",
            ["clients": paused.length.to!string,
             "live": live.to!string,
             "event": "detach_all"]);
    }

    private static long maintenanceNowMs() {
        import std.datetime.systime : unixTimeToStdTime;
        return (Clock.currStdTime - unixTimeToStdTime(0)) / 10000;
    }

    private string maintenanceKey(string operationId) const {
        return "irc:holder:maintenance:" ~ serverId ~ ":" ~ operationId;
    }

    private string maintenanceActiveKey() const {
        return "irc:holder:maintenance:active:" ~ serverId;
    }

    private void applyMaintenanceAffinity(PersistentIRCClient client, string key, UUID userId) {
        client.setMaintenanceRegistrationGate(&maintenanceRegistrationAllowed);
        if (maintenanceNowMs() >= maintenanceDeadlineMs) return;
        foreach (row; maintenanceRows) {
            if (row["networkId"].get!string != key) continue;
            if (row["userId"].get!string != userId.toString())
                throw new Exception("maintenance owner changed; refusing replacement generation");
            client.restoreMaintenanceRoute(row, maintenanceDeadlineMs, maintenanceGenerationLost);
            return;
        }
    }

    private bool maintenanceRegistrationAllowed() const nothrow {
        return !maintenanceRestorePending;
    }

    /// Called before bootstrap starts clients. Redis is the durable evidence
    /// projection, not an instruction to replace the holder.
    void restoreHolderMaintenance() {
        import vibe.data.json : parseJsonString;
        if (maintenanceId.length || redis is null) return;
        // Reconciliation runs independently of bootstrap retries. Unknown
        // marker availability must not authorize an unfenced fresh DIAL.
        maintenanceRestorePending = true;
        auto db = redis.getDb();
        auto operation = db.get(maintenanceActiveKey());
        if (!operation.length) {
            maintenanceRestorePending = false;
            return;
        }
        auto raw = db.get(maintenanceKey(operation));
        if (!raw.length || raw.length > 2 * 1024 * 1024)
            throw new Exception("active holder maintenance manifest unavailable");
        auto projection = parseJsonString(raw);
        const now = maintenanceNowMs();
        if (projection["deadlineMs"].get!long <= now) {
            maintenanceRestorePending = false;
            return;
        }
        import ircfiber.db.network : NetworkRepository;
        string observedInstance;
        long observedPid;
        if (projection["mode"].type != Json.Type.undefined) {
            if (holder is null) throw new Exception("coordinated new holder identity unavailable");
            auto status = holder.status();
            observedInstance = status.instance;
            observedPid = status.pid;
        }
        import ircfiber.irc.routing_moves : networkMoveFenced;
        auto repository = new NetworkRepository(redis);
        installMaintenanceProjection(projection, operation, now, (Json row) {
            const network = row["networkId"].get!string;
            auto current = repository.findByIdWithUser(maintenanceUuid(network));
            if (current.config.id == UUID.init || current.config.disabled
                    || current.config.servicesProvisioningPending
                    || current.userId.toString() != row["userId"].get!string
                    || db.hget(RedisKeys.networkAssignments(), network) != serverId
                    || networkMoveFenced(db, network))
                throw new Exception("maintenance canonical network ownership/configuration changed");
            if (auto existing = network in clients) {
                auto config = (*existing).getConfig;
                if ((*existing).getOwnerId != current.userId || config.host != current.config.host
                        || config.port != current.config.port || config.tls != current.config.tls
                        || config.routing != current.config.routing)
                    throw new Exception("maintenance existing client differs from canonical configuration");
            }
            PersistentIRCClient.validateMaintenanceRoute(current.config, row);
        }, observedInstance, observedPid);
        startMaintenanceWorker();
    }

    private void installMaintenanceProjection(Json projection, string operation, long now,
            scope void delegate(Json) validateCanonicalRow,
            string observedInstance = "", long observedPid = 0) {
        const coordinated = validateMaintenanceProjection(projection, operation, serverId, now);
        const deadline = projection["deadlineMs"].get!long;
        if (deadline <= now) return;
        if (coordinated && (observedInstance != projection["coordinated"]["newHolder"]["instance"].get!string
                || observedPid != projection["coordinated"]["newHolder"]["pid"].get!long))
            throw new Exception("coordinated live holder differs from the captured replacement identity");
        // No client is reachable/started and no hold is acquired until every
        // row passes the canonical database and current route/admission checks.
        foreach (row; projection["rows"]) validateCanonicalRow(row);
        auto acquired = new string[projection["rows"].length];
        size_t acquiredCount;
        auto applied = new PersistentIRCClient[clients.length];
        size_t appliedCount;
        scope(failure) {
            import ircfiber.irc.connection : releaseMaintenanceSlot;
            foreach (slot; acquired[0 .. acquiredCount]) releaseMaintenanceSlot(slot);
            foreach (client; applied[0 .. appliedCount]) client.releaseMaintenanceRoute();
            restoredMaintenanceSlots = null;
            maintenanceRows = null;
            maintenanceId = "";
            maintenanceDeadlineMs = 0;
            maintenanceProvenance = Json.undefined;
            maintenanceGenerationLost = false;
        }
        import ircfiber.irc.connection : reserveMaintenanceSlot;
        foreach (row; projection["rows"]) {
            const slot = row["route"]["slot"].get!string;
            if (!slot.length) continue;
            if (!reserveMaintenanceSlot(slot, row["routeIdentity"].get!string, deadline))
                throw new Exception("maintenance concrete route hold unavailable");
            acquired[acquiredCount++] = slot;
        }
        maintenancePreparedAtMs = projection["preparedAtMs"].get!long;
        maintenanceDeadlineMs = deadline;
        maintenanceOldInstance = projection["oldHolderInstance"].get!string;
        maintenanceOldPid = projection["oldHolderPid"].get!long;
        maintenanceRows = projection["rows"].get!(Json[]);
        maintenanceProvenance = coordinated ? projection["coordinated"] : Json.undefined;
        maintenanceGenerationLost = coordinated;
        restoredMaintenanceSlots = acquired[0 .. acquiredCount];
        // Reconciliation may already have adopted same-socket readers. Only
        // a later fresh registration uses affinity; no session/auth is applied.
        foreach (client; clients) {
            applied[appliedCount++] = client;
            applyMaintenanceAffinity(client, client.getConfig.id.toString(), client.getOwnerId);
        }
        maintenanceId = operation;
        maintenanceRestorePending = false;
    }

    void holderMaintenance(string operationId, string phase, long deadlineMs, string targetServer) {
        const now = maintenanceNowMs();
        maintenanceUuid(operationId);
        if (targetServer != serverId || !serverId.length)
            throw new Exception("invalid holder maintenance identity/target");
        if (phase != "prepare" && phase != "status")
            throw new Exception("invalid holder maintenance phase");
        if (maintenanceRestorePending)
            throw new Exception("active holder maintenance restoration is not validated");
        if (maintenanceId.length) {
            if (maintenanceId != operationId || maintenanceDeadlineMs != deadlineMs)
                throw new Exception("holder maintenance manifest is already frozen");
            publishMaintenance();
            return;
        }
        if (phase != "prepare" || deadlineMs <= now || deadlineMs > now + 600_000)
            throw new Exception("holder maintenance deadline must be within 600 seconds");
        if (holder is null || redis is null)
            throw new Exception("holder maintenance control dependencies unavailable");
        auto status = holder.status();
        // Freeze on this event-loop turn without yielding. Every registered
        // client is represented; no sampling/truncation or connected-count gate.
        maintenanceId = operationId;
        maintenanceDeadlineMs = deadlineMs;
        maintenancePreparedAtMs = now;
        maintenanceOldInstance = status.instance;
        maintenanceOldPid = status.pid;
        bool ready;
        scope(failure) {
            if (!ready) {
                foreach (anchor; maintenanceAnchors) anchor.releaseMaintenanceRoute();
                maintenanceAnchors = null;
                maintenanceRows = null;
                maintenanceId = "";
                maintenanceDeadlineMs = 0;
            }
        }
        size_t projectedBytes = 64 * 1024; // header and evidence-field reserve
        foreach (key, client; clients) {
            if (client.attachPending)
                throw new Exception("holder registered attachment is not settled; cannot freeze complete manifest");
            if (!client.getConnected || !client.getHolderId.length) continue;
            if (maintenanceRows.length >= 4096)
                throw new Exception("holder maintenance registered manifest exceeds 4096 rows");
            client.freezeMaintenanceRoute(deadlineMs);
            maintenanceAnchors ~= client;
            auto config = client.getConfig;
            auto row = Json.emptyObject;
            row["networkId"] = key;
            row["userId"] = networkOwners[key].toString();
            row["host"] = config.host;
            row["port"] = cast(int) config.port;
            row["tls"] = config.tls == TLSMode.disabled ? "none"
                : config.tls == TLSMode.starttls ? "starttls" : "implicit";
            row["oldHolderId"] = client.getHolderId;
            row["oldConnectedAtMs"] = client.getHolderConnectedAtMs;
            row["registeredAtMs"] = client.getObserved001AtMs > 0
                ? client.getObserved001AtMs : client.getConnectedAtMs;
            row["route"] = client.maintenanceRoute();
            row["routeIdentity"] = client.getFrozenRouteIdentity;
            row["routingPreferences"] = config.routing.toJson();
            row["state"] = "pending";
            const rowBytes = row.toString().length;
            // Reserve future actual-route/refusal evidence before ready can
            // authorize maintenance, not after a holder has been replaced.
            const evidenceBytes = rowBytes * 2 + 4096;
            if (rowBytes > 8192 || evidenceBytes > 2 * 1024 * 1024 - projectedBytes)
                throw new Exception("holder maintenance manifest exceeds bounded projection capacity");
            projectedBytes += evidenceBytes;
            maintenanceRows ~= row;
        }
        // After publication starts its return may be ambiguous. Never release
        // frozen routes on a Redis timeout that may have stored ready evidence.
        ready = true;
        startMaintenanceWorker();
        publishMaintenance();
    }

    private size_t[4] classifyMaintenance(long now) {
        size_t pending, recovered, refused, unresolved;
        foreach (ref row; maintenanceRows) {
            const key = row["networkId"].get!string;
            auto pointer = key in clients;
            if (pointer !is null && row["state"].get!string != "recovered") {
                auto client = *pointer;
                const changed = (maintenanceGenerationLost || client.getHolderGenerationLost)
                    && client.getHolderInstance.length
                    && client.getHolderInstance != maintenanceOldInstance
                    && (maintenanceProvenance.type != Json.Type.object
                        || client.getHolderInstance == maintenanceProvenance["newHolder"]["instance"].get!string);
                const welcomeAt = client.getObserved001AtMs;
                auto route = changed && welcomeAt > maintenancePreparedAtMs && welcomeAt <= maintenanceDeadlineMs
                    ? client.maintenanceRoute() : Json.undefined;
                if (changed && welcomeAt > maintenancePreparedAtMs && welcomeAt <= maintenanceDeadlineMs
                        && client.getHolderId.length
                        && client.getHolderId != row["oldHolderId"].get!string
                        && client.getHolderConnectedAtMs > 0 && route == row["route"]) {
                    row["state"] = "recovered";
                    row["newHolderId"] = client.getHolderId;
                    row["newConnectedAtMs"] = client.getHolderConnectedAtMs;
                    row["observed001AtMs"] = welcomeAt;
                    row["actualRoute"] = route;
                    row["classifiedAtMs"] = welcomeAt;
                    row["reason"] = "Observed numeric 001 on new holder generation with frozen route";
                } else if (row["state"].get!string != "recovered" && changed
                        && client.getExternalRefusalAtMs > maintenancePreparedAtMs
                        && client.getExternalRefusalAtMs <= maintenanceDeadlineMs) {
                    row["state"] = "refused";
                    row["reason"] = client.getExternalRefusalReason;
                    row["classifiedAtMs"] = client.getExternalRefusalAtMs;
                }
            }
            auto state = row["state"].get!string;
            if (state == "pending" && now >= maintenanceDeadlineMs) {
                row["state"] = "unresolved";
                row["reason"] = "No actual new-generation 001 with frozen route or explicit server refusal before deadline";
                row["classifiedAtMs"] = maintenanceDeadlineMs;
                state = "unresolved";
            }
            switch (state) {
                case "recovered": recovered++; break;
                case "refused": refused++; break;
                case "unresolved": unresolved++; break;
                case "pending": pending++; break;
                default: throw new Exception("invalid holder maintenance classification");
            }
        }
        return [pending, recovered, refused, unresolved];
    }

    private Json buildMaintenanceProjection(long now) {
        const counts = classifyMaintenance(now);
        const pending = counts[0], recovered = counts[1], refused = counts[2], unresolved = counts[3];
        auto projection = Json.emptyObject;
        projection["version"] = 1;
        projection["operationId"] = maintenanceId;
        projection["serverId"] = serverId;
        projection["deadlineMs"] = maintenanceDeadlineMs;
        projection["preparedAtMs"] = maintenancePreparedAtMs;
        projection["sampledAtMs"] = now;
        projection["oldHolderInstance"] = maintenanceOldInstance;
        projection["oldHolderPid"] = maintenanceOldPid;
        if (maintenanceProvenance.type == Json.Type.object) {
            projection["mode"] = "coordinated";
            projection["affinityBasis"] = "current_verified";
            projection["coordinated"] = maintenanceProvenance;
        }
        projection["state"] = unresolved ? "failed"
            : (pending || !maintenanceGenerationLost) ? "ready" : "classified";
        auto rows = Json.emptyArray;
        foreach (row; maintenanceRows) rows ~= row;
        projection["rows"] = rows;
        projection["unresolvedCount"] = cast(long) (unresolved + pending);
        projection["recoveredCount"] = cast(long) recovered;
        projection["refusedCount"] = cast(long) refused;
        return projection;
    }

    private void publishMaintenance() {
        if (!maintenanceId.length) return;
        auto projection = buildMaintenanceProjection(maintenanceNowMs());
        auto encoded = projection.toString();
        if (encoded.length > 2 * 1024 * 1024)
            throw new Exception("holder maintenance projection exceeds 2 MiB");
        auto db = redis.getDb();
        db.eval!string(
            "redis.call('SET',KEYS[1],ARGV[1],'EX',86400); redis.call('SET',KEYS[2],ARGV[2],'EX',86400); return '1'",
            [maintenanceKey(maintenanceId), maintenanceActiveKey()], [encoded, maintenanceId]);
    }

    private void startMaintenanceProbe() {
        if (maintenanceProbeRunning) return;
        maintenanceProbeRunning = true;
        import vibe.core.core : runTask;
        runTask(() nothrow {
            scope(exit) maintenanceProbeRunning = false;
            try {
                auto status = holder.status();
                if ((maintenanceOldInstance.length && status.instance.length
                        && status.instance != maintenanceOldInstance)
                        || (!maintenanceOldInstance.length && (status.instance.length
                            || (status.pid > 0 && status.pid != maintenanceOldPid))))
                    maintenanceGenerationLost = true;
            } catch (Exception) {
                // Unavailable incarnation evidence is unknown, not process loss.
            }
        });
    }

    private void startMaintenanceWorker() {
        if (maintenanceWorkerRunning) return;
        maintenanceWorkerRunning = true;
        import vibe.core.core : runTask, sleep;
        import core.time : seconds;
        runTask(() nothrow {
            scope(exit) maintenanceWorkerRunning = false;
            while (true) {
                try {
                    const expired = maintenanceNowMs() >= maintenanceDeadlineMs;
                    if (expired) {
                        foreach (anchor; maintenanceAnchors) {
                            try anchor.releaseMaintenanceRoute(); catch (Exception) {}
                        }
                        maintenanceAnchors = null;
                        import ircfiber.irc.connection : releaseMaintenanceSlot;
                        foreach (slot; restoredMaintenanceSlots) releaseMaintenanceSlot(slot);
                        restoredMaintenanceSlots = null;
                    }
                    if (!expired) startMaintenanceProbe();
                    publishMaintenance();
                    if (expired) return;
                } catch (Exception e) {
                    try logJsonMap("error", "connection", "Holder maintenance evidence projection unavailable",
                        ["event": "holder_maintenance_projection_failed", "operationId": maintenanceId,
                         "reason": e.msg]); catch (Exception) {}
                    // Keep retrying final classification independently of heartbeat.
                }
                try sleep(1.seconds); catch (Exception) {}
            }
        });
    }

    /// Attach a network to a connection the holder kept across the engine
    /// restart (planned hot swap or crash). Creates the client exactly like
    /// `addNetwork`, attaches, and restores `snapshot`. `ERR busy` means
    /// another engine process still holds the relay (a slow shutdown of
    /// the previous engine): the client stays `disconnected` and retries
    /// the attach every 5 s — it never dials fresh while an open entry
    /// exists for the network. Transient/non-authoritative errors retain that
    /// claim too; only closed/not-found or incarnation loss permits fresh DIAL.
    void attachNetwork(NetworkConfig config, UUID userId, HolderEntry entry, SessionSnapshot snapshot) {
        import ircfiber.holder_client : HolderErrorException, HolderUnavailableException;
        import ircfiber.engine.session_snapshot : fromJSON;
        import vibe.core.core : runTask, sleep;
        import core.time : seconds;
        if (config.servicesProvisioningPending) return;
        auto key = config.id.toString();
        const ownerId = userId.toString();
        if (terminating || key in moveStops) return;
        if (!entry.id.length || entry.connectedAtMs <= 0 || entry.state != "open"
                || entry.tag.networkId != key || entry.tag.userId != ownerId)
            throw new HolderUnavailableException("held restoration claim does not match network owner");
        // The parsed snapshot is the only restoration state retained by a
        // deferred attach; do not root its source META tree in the retry task.
        entry = entry.ownedIdentity();
        knownNetworks[key] = true;
        if (key in clients) {
            logWarn("Network %s already managed", config.name);
            return;
        }
        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId, holder);
        applyMaintenanceAffinity(client, key, userId);
        client.claimPendingHeldEntry(entry);
        clients[key] = client;
        networkOwners[key] = userId;
        removedAtMs.remove(key);

        bool tryAttach(bool refreshSnapshot = false) {
            if (terminating || client.getStopping) return true;
            client.beginHeldAttach();
            scope(exit) client.endHeldAttach();
            AttachResult r;
            try {
                auto status = holder.status();
                if (status.instance != entry.instance) {
                    client.abandonPendingHeldEntry();
                    startFreshClient(client, key);
                    return true; // old incarnation lost, never touch a colliding ID
                }
                if (refreshSnapshot) {
                    // A busy/transient attempt may outlive the previous
                    // engine's final strict marker. Read canonical META again
                    // before the next ATTACH, never after taking the relay.
                    auto observed = holder.info(entry.id);
                    scope(exit) observed.meta = Json.undefined;
                    if (observed.id != entry.id)
                        throw new HolderUnavailableException("holder returned a different restoration id");
                    if (observed.instance != entry.instance
                            || observed.connectedAtMs != entry.connectedAtMs) {
                        client.abandonPendingHeldEntry();
                        startFreshClient(client, key);
                        return true;
                    }
                    if (observed.tag.networkId != key || observed.tag.userId != ownerId)
                        throw new HolderUnavailableException("held restoration owner changed before retry");
                    if (observed.state == "closed")
                        throw new HolderErrorException("closed", "observed closed holder entry");
                    if (observed.state != "open" || !observed.hasMeta)
                        throw new HolderUnavailableException("held restoration snapshot unavailable");
                    auto latest = fromJSON(observed.meta);
                    if (!latest.wasConnected)
                        throw new HolderUnavailableException("held restoration snapshot no longer registered");
                    snapshot = latest;
                }
                r = holder.attachIdentity(entry.id);
                // ATTACH's response describes the very relay now owned. This
                // replaces a redundant INFO, which could race the attachment.
                // Mismatch closes IPC only: never CLOSE the newly seen claim.
                if (r.entry.id != entry.id || r.entry.state != "open"
                        || r.entry.tag.networkId != key
                        || r.entry.tag.userId != ownerId) {
                    r.stream.close();
                    throw new HolderUnavailableException("holder claim changed during attach");
                }
                if (r.entry.instance != entry.instance || r.entry.connectedAtMs != entry.connectedAtMs) {
                    r.stream.close();
                    client.abandonPendingHeldEntry();
                    startFreshClient(client, key);
                    return true;
                }
            } catch (HolderErrorException e) {
                if (e.code != "closed" && e.code != "not_found") {
                    logJsonMap("warn", "connection", "Held attach deferred; preserving socket claim",
                        ["network": config.name, "holderId": entry.id,
                         "code": e.code, "event": "attach_retry"]);
                    client.attachPending = true;
                    return false;
                }
                logJsonMap("warn", "connection", "Attach failed — dialing fresh",
                    ["network": config.name, "holderId": entry.id, "code": e.code, "err": e.msg,
                     "event": "attach_fail"]);
                client.abandonPendingHeldEntry();
                startFreshClient(client, key);
                return true;
            } catch (Exception e) {
                logJsonMap("warn", "connection", "Held attach unavailable; preserving socket claim",
                    ["network": config.name, "holderId": entry.id, "err": e.msg, "event": "attach_retry"]);
                client.attachPending = true;
                return false;
            }
            if (terminating || client.getStopping) {
                r.stream.close();
                holder.closeClaim(entry.id, entry.instance, entry.connectedAtMs, "routing move during attach");
                return true;
            }
            client.attachPending = false;
            client.attachHeld(r, snapshot, snapshot.graceful);
            return true;
        }

        if (tryAttach()) return;
        runTask(() nothrow {
            while (true) {
                try sleep(5.seconds); catch (Exception) {}
                if (key !in clients || clients[key] !is client) return;
                bool done;
                try done = tryAttach(true);
                catch (Exception e) {
                    string m; try { m = e.msg; } catch (Exception) { m = "unknown"; }
                    try logWarn("attach retry for %s failed: %s", config.name, m); catch (Exception) {}
                }
                if (done) return;
            }
        });
    }
}

version (MemoryReliabilityHarness) {
    import ircfiber.irc.connection : Ircv3Check;

    /// Exercise real remove/re-add ownership and the same attach-operation
    /// guards used around holder ATTACH, without opening upstream sockets.
    Ircv3Check[] retiredClientMemoryRegressionChecks() {
        import core.time : seconds;
        Ircv3Check[] checks;
        auto channel = EngineEventChannel.create();
        scope(exit) channel.close();
        auto manager = new ConnectionManager(channel);
        NetworkConfig config;
        config.id = parseUUID("ed19e1ce-a22e-4aa5-8ef3-010000000001");
        config.nick = "memory-owner";
        config.host = "memory-owner.invalid";
        const key = config.id.toString();

        bool returnedToBaseline = true;
        foreach (_; 0 .. 256) {
            manager.addNetwork(config, UUID.init);
            manager.removeNetwork(config.id);
            returnedToBaseline = returnedToBaseline
                && manager.clients.length == 0
                && manager.retiredClients.length == 0;
        }
        checks ~= Ircv3Check("completed remove/re-add generations release every retired root",
            returnedToBaseline);

        // Multiple pending generations exercise in-place compaction and tail
        // clearing, not merely removal of an associative-array key.
        PersistentIRCClient[3] attaching;
        foreach (ref client; attaching) {
            manager.addNetwork(config, UUID.init);
            client = manager.clients[key];
            client.beginHeldAttach();
            manager.removeNetwork(config.id);
        }
        auto originalSlots = manager.retiredClients[key];
        checks ~= Ircv3Check("pending held ATTACH operations retain all removed generations",
            originalSlots.length == 3
            && !attaching[0].getMoveQuiescent()
            && !attaching[1].getMoveQuiescent()
            && !attaching[2].getMoveQuiescent());
        attaching[0].endHeldAttach();
        attaching[1].endHeldAttach();
        const expiry = manager.removedAtMs[key] + ConnectionManager.REMOVED_MEMORY_MS + 1;
        manager.reapRetiredClients(expiry);
        checks ~= Ircv3Check("reaping compacts pending ownership and clears vacated backing slots",
            manager.retiredClients[key].length == 1
            && manager.retiredClients[key][0] is attaching[2]
            && originalSlots[0] is attaching[2]
            && originalSlots[1] is null && originalSlots[2] is null);
        checks ~= Ircv3Check("maintenance expires removal tombstones without isRemoved traffic",
            key !in manager.removedAtMs);
        checks ~= Ircv3Check("pending late-attach ownership keeps independent dial provenance",
            manager.hasNetworkHistory(config.id) && !manager.provenanceUnowned(key));

        attaching[2].endHeldAttach();
        manager.observingRetiredProvenance = true;
        manager.reapRetiredClients(expiry);
        checks ~= Ircv3Check("an outstanding provenance read cannot block local graph reclamation",
            manager.retiredClients.length == 0 && originalSlots[0] is null);
        manager.observingRetiredProvenance = false;
        checks ~= Ircv3Check("missing holder and durable ledger retain late-DIAL provenance, not graphs",
            manager.hasNetworkHistory(config.id)
            && !manager.stopNetworkForMove(config.id, 1.seconds)
            && manager.retiredClients.length == 0);

        // A configured holder is not a substitute for a durable Redis proof.
        // No IPC is attempted: the missing-ledger branch must fail closed.
        manager.holder = new HolderClient("memory-owner", "tcp://127.0.0.1:1", "owned-fixture-token");
        manager.reapRetiredClients(expiry);
        checks ~= Ircv3Check("a holder alone cannot erase durable late-DIAL uncertainty",
            manager.hasNetworkHistory(config.id) && manager.retiredClients.length == 0);
        attaching[] = null;
        originalSlots = null;
        return checks;
    }
}

version (MemoryReliabilityHarness)
private Json maintenanceProvenanceFixture(string instance = "00000000-0000-4000-8000-000000000002") {
    auto proof = Json.emptyObject;
    string[4] ids = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444"];
    foreach (i, field; ["oldEngine", "oldHolder", "newHolder", "firstEngine"]) {
        auto identity = Json.emptyObject;
        identity["id"] = ids[i];
        identity["image"] = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        if (field != "firstEngine") {
            identity["pid"] = field == "oldEngine" ? 41 : field == "oldHolder" ? 42 : 43;
            identity["startedAt"] = "2026-11-09T00:00:00Z";
            identity["hostPid"] = field == "oldEngine" ? 41 : field == "oldHolder" ? 4200 : 4300;
        }
        if (field == "newHolder") identity["instance"] = instance;
        proof[field] = identity;
    }
    proof["evidenceSha256"] = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    proof["sourceRevision"] = "ffffffffffffffffffffffffffffffffffffffff";
    return proof;
}

version (MemoryReliabilityHarness)
Ircv3Check[] holderMaintenanceClassificationChecks(PersistentIRCClient client, string oldId, long oldWelcome,
        bool observedRefusal = false) {
    auto channel = EngineEventChannel.create();
    scope(exit) channel.close();
    auto manager = new ConnectionManager(channel);
    Ircv3Check[] checks;
    const key = client.getConfig.id.toString();
    manager.clients[key] = client;
    manager.maintenancePreparedAtMs = oldWelcome;
    manager.maintenanceDeadlineMs = oldWelcome + 600000;
    manager.maintenanceOldInstance = "00000000-0000-4000-8000-000000000001";
    auto row = Json.emptyObject;
    row["networkId"] = key;
    row["oldHolderId"] = oldId;
    row["route"] = client.maintenanceRoute();
    row["state"] = "pending";
    manager.maintenanceRows = [row];
    const now = client.getObserved001AtMs;
    auto counts = manager.classifyMaintenance(now);
    if (observedRefusal) {
        manager.maintenanceGenerationLost = true;
        counts = manager.classifyMaintenance(now);
        checks ~= Ircv3Check("observed external refusal is classified refused and never recovered",
            counts == [size_t(0), 0, 1, 0]
            && manager.maintenanceRows[0]["reason"].get!string == client.getExternalRefusalReason
            && manager.maintenanceRows[0]["classifiedAtMs"].get!long == client.getExternalRefusalAtMs);
        return checks;
    }
    checks ~= Ircv3Check("actual 001 alone cannot classify recovery without holder generation loss",
        counts == [size_t(1), 0, 0, 0]);
    manager.maintenanceGenerationLost = true;
    manager.maintenanceOldInstance = client.getHolderInstance;
    counts = manager.classifyMaintenance(now);
    checks ~= Ircv3Check("same-incarnation reconnect is not planned-holder recovery",
        counts == [size_t(1), 0, 0, 0]);
    manager.maintenanceOldInstance = "00000000-0000-4000-8000-000000000001";
    auto wrongRoute = client.maintenanceRoute();
    wrongRoute["exitId"] = "different-concrete-exit";
    manager.maintenanceRows[0]["route"] = wrongRoute;
    counts = manager.classifyMaintenance(now);
    checks ~= Ircv3Check("new-generation actual 001 on a different route remains unresolved",
        counts == [size_t(1), 0, 0, 0]);
    manager.maintenanceRows[0]["route"] = client.maintenanceRoute();
    counts = manager.classifyMaintenance(now);
    checks ~= Ircv3Check("new-generation actual wire 001 and exact frozen affinity classify recovered",
        counts == [size_t(0), 1, 0, 0]
        && manager.maintenanceRows[0]["observed001AtMs"].get!long == now);
    manager.maintenanceRows[0]["state"] = "pending";
    manager.maintenanceRows[0]["historicalExitUnprovable"] = true;
    manager.maintenanceProvenance = maintenanceProvenanceFixture("00000000-0000-4000-8000-000000000003");
    counts = manager.classifyMaintenance(now);
    checks ~= Ircv3Check("actual 001 on an unqualified third holder incarnation remains unclassified",
        counts == [size_t(1), 0, 0, 0]);
    manager.maintenanceProvenance = maintenanceProvenanceFixture(client.getHolderInstance);
    auto coordinatedStatus = manager.buildMaintenanceProjection(now);
    checks ~= Ircv3Check("coordinated recovery uses the qualified incarnation and actual wire 001 without erasing unknown historical affinity",
        coordinatedStatus["recoveredCount"].get!long == 1
        && coordinatedStatus["rows"][0]["observed001AtMs"].get!long == now
        && coordinatedStatus["rows"][0]["historicalExitUnprovable"].get!bool
        && coordinatedStatus["coordinated"] == manager.maintenanceProvenance);
    manager.maintenanceRows[0]["state"] = "pending";
    manager.maintenanceRows[0]["oldHolderId"] = client.getHolderId;
    counts = manager.classifyMaintenance(manager.maintenanceDeadlineMs);
    checks ~= Ircv3Check("a retained/restored socket is not a new registration and deadline failure is not refusal",
        counts == [size_t(0), 0, 0, 1]);
    return checks;
}

version (MemoryReliabilityHarness)
Ircv3Check[] holderMaintenanceRestorationRegressionChecks(Json heldRoute, string heldIdentity) {
    import vibe.data.json : parseJsonString;
    auto channel = EngineEventChannel.create();
    scope(exit) channel.close();
    Ircv3Check[] checks;
    const operation = "8d232162-5749-416a-88d9-bbd9aee4f001";
    const now = ConnectionManager.maintenanceNowMs();
    auto direct = Json.emptyObject;
    direct["provider"] = "direct";
    direct["slot"] = "";
    direct["exitId"] = "";
    direct["nativeIpv6"] = "";
    Json row(string network, string socket, Json route, string identity) {
        auto result = Json.emptyObject;
        result["networkId"] = network;
        result["userId"] = "00000000-0000-4000-8000-000000000001";
        result["host"] = "maintenance.invalid";
        result["port"] = 6667;
        result["tls"] = "none";
        result["oldHolderId"] = socket;
        result["oldConnectedAtMs"] = now - 300;
        result["registeredAtMs"] = now - 200;
        result["route"] = route;
        result["routeIdentity"] = identity;
        NetworkConfig config;
        result["routingPreferences"] = config.routing.toJson();
        result["state"] = "pending";
        return result;
    }
    auto projection = Json.emptyObject;
    projection["version"] = 1;
    projection["operationId"] = operation;
    projection["serverId"] = "fixture";
    projection["preparedAtMs"] = now - 100;
    projection["deadlineMs"] = now + 599000;
    projection["oldHolderInstance"] = "";
    projection["oldHolderPid"] = 42;
    projection["rows"] = Json([
        row("00000000-0000-4000-8000-000000000011", "old-one", direct, "direct|"),
        row("00000000-0000-4000-8000-000000000012", "old-two", direct, "direct|")]);
    auto encoded = projection.toString();
    void qualify(ref Json value) {
        value["mode"] = "coordinated";
        value["affinityBasis"] = "current_verified";
        value["coordinated"] = maintenanceProvenanceFixture();
        value["rows"][0]["historicalExitUnprovable"] = false;
        value["rows"][1]["historicalExitUnprovable"] = true;
    }
    void rejected(string name, scope void delegate(ref Json) mutate) {
        auto candidate = parseJsonString(encoded);
        mutate(candidate);
        auto manager = new ConnectionManager(channel, null, "fixture");
        manager.maintenanceRestorePending = true;
        size_t canonicalChecks;
        bool refused;
        try manager.installMaintenanceProjection(candidate, operation, now,
            (Json value) { canonicalChecks++; });
        catch (Exception) refused = true;
        checks ~= Ircv3Check(name, refused && canonicalChecks == 0
            && !manager.maintenanceId.length && !manager.maintenanceRows.length
            && !manager.restoredMaintenanceSlots.length && manager.maintenanceRestorePending);
    }
    rejected("invalid last row cannot partially restore a preceding valid maintenance row",
        (ref Json value) { value["rows"][1]["port"] = 65536; });
    rejected("duplicate network ownership is rejected before any route hold",
        (ref Json value) { value["rows"][1]["networkId"] = value["rows"][0]["networkId"]; });
    rejected("one old socket cannot authorize two replacement registrations",
        (ref Json value) { value["rows"][1]["oldHolderId"] = "old-one"; });
    rejected("restored destination TLS must be a supported wire mode",
        (ref Json value) { value["rows"][1]["tls"] = "TLS"; });
    rejected("native/direct route identity mismatch fails before any row is applied",
        (ref Json value) { value["rows"][1]["routeIdentity"] = "direct|2001:db8::1"; });
    rejected("old private auth META is evidence only and is not a restoration DTO field",
        (ref Json value) {
            auto evidence = Json.emptyObject;
            evidence["wasConnected"] = true;
            evidence["servicesLegacyAuthPending"] = 4;
            value["rows"][1]["meta"] = evidence;
        });
    rejected("coordinated activation without qualified immutable capture is unavailable",
        (ref Json value) { value["mode"] = "coordinated"; });
    rejected("maintenance interval cannot exceed the frozen 600-second bound",
        (ref Json value) { value["deadlineMs"] = now + 600000; });
    rejected("coordinated current-exit recovery requires an explicit uncertainty flag on every row",
        (ref Json value) {
            qualify(value);
            value["rows"][1].remove("historicalExitUnprovable");
        });
    rejected("coordinated activation cannot silently select an unapproved affinity basis",
        (ref Json value) { qualify(value); value["affinityBasis"] = "preferred"; });
    rejected("coordinated capture cannot reuse another protected container identity",
        (ref Json value) {
            qualify(value);
            value["coordinated"]["firstEngine"]["id"] = value["coordinated"]["oldHolder"]["id"];
        });
    rejected("coordinated capture requires its immutable private evidence digest",
        (ref Json value) { qualify(value); value["coordinated"].remove("evidenceSha256"); });
    rejected("private old socket authentication evidence cannot be published as coordinated provenance",
        (ref Json value) {
            qualify(value);
            value["coordinated"]["oldHolder"]["servicesLegacyAuthPending"] = 4;
        });
    {
        auto candidate = parseJsonString(encoded);
        qualify(candidate);
        auto manager = new ConnectionManager(channel, null, "fixture");
        manager.maintenanceRestorePending = true;
        bool refused;
        size_t canonicalChecks;
        try manager.installMaintenanceProjection(candidate, operation, now,
            (Json value) { canonicalChecks++; }, "00000000-0000-4000-8000-000000000003", 43);
        catch (Exception) refused = true;
        checks ~= Ircv3Check("another live holder incarnation cannot consume the qualified current-exit manifest",
            refused && canonicalChecks == 0 && !manager.maintenanceId.length
            && manager.maintenanceRestorePending);
    }
    {
        auto candidate = parseJsonString(encoded);
        qualify(candidate);
        auto manager = new ConnectionManager(channel, null, "fixture");
        manager.maintenanceRestorePending = true;
        manager.installMaintenanceProjection(candidate, operation, now, (Json value) {},
            "00000000-0000-4000-8000-000000000002", 43);
        auto status = manager.buildMaintenanceProjection(now);
        checks ~= Ircv3Check("first A restores only proven replacement affinity, never restored connection/auth success",
            manager.maintenanceGenerationLost && !manager.maintenanceRestorePending
            && manager.clients.length == 0 && status["recoveredCount"].get!long == 0
            && status["unresolvedCount"].get!long == 2);
        checks ~= Ircv3Check("classification/status preserve immutable process/capture scope and honest historical uncertainty",
            status["coordinated"] == candidate["coordinated"]
            && status["affinityBasis"].get!string == "current_verified"
            && !status["rows"][0]["historicalExitUnprovable"].get!bool
            && status["rows"][1]["historicalExitUnprovable"].get!bool);
    }
    {
        auto manager = new ConnectionManager(channel, null, "fixture");
        manager.maintenanceRestorePending = true;
        size_t canonicalChecks;
        bool refused;
        try manager.installMaintenanceProjection(parseJsonString(encoded), operation, now, (Json value) {
            if (++canonicalChecks == 2) throw new Exception("canonical owner/config changed");
        });
        catch (Exception) refused = true;
        checks ~= Ircv3Check("late canonical ownership/config failure publishes no ready state or holds",
            refused && canonicalChecks == 2 && !manager.maintenanceId.length
            && !manager.maintenanceRows.length && manager.maintenanceRestorePending);
    }
    {
        auto manager = new ConnectionManager(channel, null, "fixture");
        manager.maintenanceRestorePending = true;
        manager.installMaintenanceProjection(parseJsonString(encoded), operation, now, (Json value) {});
        checks ~= Ircv3Check("complete online DTO permits distinct networks with the same legitimate owner",
            manager.maintenanceId == operation && manager.maintenanceRows.length == 2
            && !manager.maintenanceRestorePending && manager.clients.length == 0);
    }
    {
        auto candidate = parseJsonString(encoded);
        candidate["rows"][0]["route"] = heldRoute;
        candidate["rows"][0]["routeIdentity"] = heldIdentity;
        auto unavailable = Json.emptyObject;
        unavailable["provider"] = "nordvpn";
        unavailable["slot"] = "missing-maintenance-fixture";
        unavailable["exitId"] = "slot:missing-maintenance-fixture";
        unavailable["nativeIpv6"] = "";
        candidate["rows"][1]["route"] = unavailable;
        candidate["rows"][1]["routeIdentity"] = "vpn|missing-maintenance-fixture|127.0.0.1:1||";
        auto manager = new ConnectionManager(channel, null, "fixture");
        manager.maintenanceRestorePending = true;
        bool refused;
        try manager.installMaintenanceProjection(candidate, operation, now, (Json value) {});
        catch (Exception) refused = true;
        checks ~= Ircv3Check("late slot reservation failure cannot claim prepared ready",
            refused && !manager.maintenanceId.length && !manager.maintenanceRows.length
            && !manager.restoredMaintenanceSlots.length && manager.maintenanceRestorePending);
    }
    return checks;
}
