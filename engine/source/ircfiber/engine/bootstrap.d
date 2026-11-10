module ircfiber.engine.bootstrap;

import std.process : environment;
import std.random : unpredictableSeed;
import std.conv : to;
import std.string : lastIndexOf;
import std.conv : to;
import std.datetime : Clock;
import std.algorithm : canFind, min;
import std.uuid : UUID, parseUUID;
import core.sys.posix.unistd : getpid;
import vibe.core.core : runTask, sleep, runApplication;
import ircfiber.engine.event_channel : EngineEventChannel;
import ircfiber.logging : logJsonMap, logException, flushAndSendLogs;
import vibe.data.json : Json;
import ircfiber.tracing : withSpan, flushAndSendSpans, Span, isTracingEnabled;
import ircfiber.observability : flushAndSendMetrics, recordGauge, isMetricsEnabled;
import ircfiber.db.circuit_breaker : exportMongoCircuitMetrics;
import vibe.core.log;
import core.time : seconds, msecs;
import ircfiber.build_info : buildInfo;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.irc.manager : ConnectionManager;
import ircfiber.irc.server : ConnectionServer;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.irc.engine_janitor : EngineJanitor, purgeLocalServerNamespace, bumpServerStateTTLs;
import ircfiber.irc.connection : setEgressRedis, supportedRoutingRoutes;
version (MemoryReliabilityHarness) import ircfiber.irc.connection : Ircv3Check;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.user : UserRepository;
import ircfiber.db.messages : MessageRepository;
import ircfiber.redis.protocol : RedisKeys, StateTTL;
import ircfiber.holder_client : HolderClient, HolderEntry, HolderUnavailableException;
import ircfiber.engine.session_snapshot : SessionSnapshot, fromJSON;
import ircfiber.irc.routing_moves : networkMoveFenced;
import ircfiber.engine.archive_spool : ArchiveSpool, ArchiveSpoolConfig;
import ircfiber.engine.archive_worker : ArchiveWorker;
import ircfiber.engine.archive_control : ArchiveControl;
import ircfiber.runtime_diagnostic : RuntimeDiagnosticMailbox;

/// Context holding all engine dependencies.
struct EngineContext {
    /// IRC connection manager.
    ConnectionManager connManager;
    /// Redis storage.
    RedisStorage redis;
    /// Buffer manager (Redis hot cache).
    BufferManager bufferManager;
    /// Message repository (MongoDB permanent storage).
    MessageRepository messageRepo;
    /// Network repository.
    NetworkRepository networkRepo;
    /// Main event channel.
    EngineEventChannel eventChannel;
    /// Server registry.
    ServerRegistry serverRegistry;  // NEW
    /// This engine's server identity.
    ConnectionServer localServer;   // NEW: this engine's identity
    /// Client of this engine's connection holder (owns every IRC socket).
    HolderClient holder;
    ArchiveSpool archiveSpool;
    ArchiveWorker archiveWorker;
    ArchiveControl archiveControl;
    RuntimeDiagnosticMailbox runtimeDiagnostics;

    // Only an in-flight physical LIST/INVENTORY scan is shareable. Completed
    // observations are never a cache for a later heartbeat.
    private HolderListObservation holderListInFlight;
}

/// One physical request and the callers already waiting for its result.
/// Full restoration readers lease META; evidence readers receive an owned
/// metadata-free projection which can safely outlive their callback.
private class HolderListObservation {
    import vibe.core.sync : TaskMutex;

    TaskMutex completion;
    HolderEntry[] entries;
    HolderEntry[] identities;
    bool requireMeta;
    Throwable failure;
    size_t readers;

    this() {
        completion = new TaskMutex;
    }

    HolderEntry[] identityEntries() {
        if (!requireMeta) return entries;
        if (identities is null) identities = ownedHolderIdentities(entries);
        return identities;
    }

    void release() {
        assert(readers > 0);
        if (--readers == 0) {
            entries = null;
            identities = null;
            failure = null;
        }
    }
}

/// Join only a still-running LIST, never a previously successful heartbeat.
/// The returned lease must cover every restoration use of its META.
private HolderListObservation acquireFreshHolderList(ref EngineContext ctx, bool requireMeta = false) {
    auto observation = ctx.holderListInFlight;
    const initiator = observation is null;
    if (initiator) {
        observation = new HolderListObservation;
        observation.requireMeta = requireMeta;
        observation.completion.lock();
        ctx.holderListInFlight = observation;
    }
    observation.readers++;
    scope(failure) observation.release();

    if (initiator) {
        try {
            if (ctx.holder is null)
                throw new Exception("Holder LIST unavailable: no holder client");
            observation.entries = ctx.holder.scan(observation.requireMeta);
        } catch (Throwable e) {
            observation.failure = e;
        } finally {
            // Stop admission before releasing waiters: any later caller must
            // obtain fresh physical evidence, even while restoration yields.
            ctx.holderListInFlight = null;
            observation.completion.unlock();
        }
    } else {
        observation.completion.lock();
        observation.completion.unlock();
    }
    if (observation.failure !is null) throw observation.failure;
    return observation;
}

private void withFreshHolderList(ref EngineContext ctx,
        scope void delegate(HolderEntry[]) consume) {
    auto observation = acquireFreshHolderList(ctx);
    scope(exit) {
        consume = null;
        observation.release();
    }
    consume(observation.identityEntries());
}

private HolderEntry[] ownedHolderIdentities(HolderEntry[] entries) {
    auto identities = new HolderEntry[entries.length];
    foreach (i, entry; entries) identities[i] = entry.ownedIdentity();
    return identities;
}

/// Identity scans deliberately omit META. Absence alone says nothing about
/// registration: fetch only the selected restoration entry and validate its
/// claim before consuming snapshots or services/manual-auth markers.
private HolderEntry restorationEntry(HolderClient holder, HolderEntry entry) {
    if (entry.hasMeta) return entry;
    auto detail = holder.info(entry.id);
    if (detail.id != entry.id || detail.connectedAtMs != entry.connectedAtMs
            || (entry.instance.length && detail.instance != entry.instance)
            || detail.state != entry.state
            || detail.tag.networkId != entry.tag.networkId
            || detail.tag.userId != entry.tag.userId)
        throw new HolderUnavailableException("holder entry changed before restoration");
    return detail;
}

/// Refresh on initial/re-registration and heartbeat: an older or unavailable
/// holder must withdraw native capability rather than retain stale claims.
void refreshRoutingCapabilities(ref EngineContext ctx, bool publish = false) {
    import vibe.data.json : Json;
    ctx.localServer.routingPolicyVersion = 1;
    ctx.localServer.supportedRoutes = supportedRoutingRoutes(ctx.holder, ctx.localServer.ipv6Prefix);
    if (!publish) return;
    auto routes = Json.emptyArray;
    foreach (route; ctx.localServer.supportedRoutes) routes ~= Json(route);
    auto db = ctx.redis.getDb();
    const key = RedisKeys.server(ctx.localServer.serverId);
    db.hset(key, "routingPolicyVersion", "1");
    db.hset(key, "supportedRoutes", routes.toString());
    db.hset(key, "ipv6Prefix", ctx.localServer.ipv6Prefix);
}

/**
 * Bootstrap a decentralized connection server.
 * 
 * Each engine process runs as an independent connection server with:
 * - A unique server ID (from env IRCFIBER_SERVER_ID)
 * - A dedicated outbound IP (from env IRCFIBER_BIND_ADDRESS)
 * - Local buffer storage (namespaced by server ID)
 * - Registration with the central gateway registry
 * 
 * Precondition: Server ID is non-empty and unique.
 * Postcondition: Server is registered, networks loaded, consumers started.
 */
EngineContext bootstrapEngine() {
    logInfo("Starting IRC Fiber Engine (Decentralized)...");

    // Get server identity from environment
    auto serverId = environment.get("IRCFIBER_SERVER_ID", "");
    auto bindAddress = environment.get("IRCFIBER_BIND_ADDRESS", "0.0.0.0");
    auto adminPort = environment.get("IRCFIBER_ADMIN_PORT", "8091").to!ushort;

    if (serverId.length == 0) {
        // Auto-generate a fallback ID so the engine starts even when the
        // user forgets to set IRCFIBER_SERVER_ID.  Uses hostname + PID to
        // avoid collisions between engines on different machines.
        auto hostname = environment.get("HOSTNAME", "");
        if (hostname.length == 0)
            hostname = environment.get("COMPUTERNAME", "unknown");
        if (hostname.length > 16) hostname = hostname[0 .. 16];
        serverId = hostname ~ "-" ~ to!string(unpredictableSeed % 1_000_000_000);
        logWarn(
            "IRCFIBER_SERVER_ID not set. Auto-generated: %s. " ~
            "Set the env var to pin a stable identity.",
            serverId
        );
    }

    logInfo("Server identity: id=%s bind=%s port=%d", serverId, bindAddress, adminPort);

    // Connect to MongoDB
    auto mongoUrl = environment.get("IRCFIBER_MONGO_URL", "mongodb://127.0.0.1:27017/ircfiber");
    auto mongoDbName = "ircfiber";
    auto mongoSlash = mongoUrl.lastIndexOf("/");
    if (mongoSlash > "mongodb://".length) {
        mongoDbName = mongoUrl[mongoSlash + 1 .. $];
        import std.string : indexOf;
        auto qIdx = mongoDbName.indexOf("?");
        if (qIdx >= 0) mongoDbName = mongoDbName[0 .. qIdx];
        if (mongoDbName.length == 0) mongoDbName = "ircfiber";
    }
    foreach (attempt; 0 .. 30) {
        try {
            AppMongoConnection.connect(mongoUrl, mongoDbName);
            break;
        } catch (Exception e) {
            if (attempt == 29) {
                throw new Exception("MongoDB connection failed after 30 attempts: " ~ e.msg);
            } else {
                logInfo("MongoDB connection attempt %d failed (%s), retrying in 1s...", attempt + 1, e.msg);
                sleep(1.seconds);
            }
        }
    }

    // Connect to Redis
    auto redisUrl = environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");
    auto redis = new RedisStorage();
    foreach (attempt; 0 .. 30) {
        try {
            redis.connectFromUrl(redisUrl);
            setEgressRedis(redis);
            break;
        } catch (Exception e) {
            if (attempt == 29) {
                throw new Exception("Redis connection failed after 30 attempts: " ~ e.msg);
            } else {
                logInfo("Redis connection attempt %d failed, retrying in 1s...", attempt + 1);
                sleep(1.seconds);
            }
        }
    }

    NetworkRepository.initRedis(redis);

    // ── Connection holder ─────────────────────────────────────────
    // The holder owns every IRC socket; the engine attaches to it. Boot
    // blocks until the control session is up (≤ IRCFIBER_HOLDER_CONNECT_
    // TIMEOUT_SECS, then exit 75 so the restart policy retries); a
    // protocol/serverId mismatch exits 78.
    HolderClient holder;
    try {
        holder = new HolderClient(serverId);
    } catch (Exception e) {
        logError("Invalid IRCFIBER_HOLDER_ADDR: %s", e.msg);
        import core.stdc.stdlib : exit;
        exit(78);
    }
    holder.connectControl();
    long heldLive;
    bool heldStateKnown;
    try {
        auto heldStatus = holder.status();
        heldLive = heldStatus.open;
        heldStateKnown = heldStatus.openAvailable;
    } catch (Exception e) {
        logWarn("Holder STATUS failed at boot (%s) — preserving namespace until live state is known", e.msg);
    }
    bool maintenanceStateKnown;
    bool maintenanceActive;
    try {
        maintenanceActive = redis.getDb().get("irc:holder:maintenance:active:" ~ serverId).length != 0;
        maintenanceStateKnown = true;
    } catch (Exception e) {
        logWarn("Holder maintenance marker unavailable at boot — preserving namespace");
    }

    // ── Bootstrap-time namespace purge (Layer 3) ─────────────────
    // Wipes `*:<serverId>:*` keys + companion keys before this engine
    // registers itself. Prevents "same serverId, new epoch" from inheriting
    // 40+ fossilized keys from a prior boot (the exact failure mode that
    // built up testengine1's garbage pile on Jun 22).
    //
    // Skipped when the holder still carries live sessions for this engine
    // (hot swap / crash restart): their state is about to be re-attached.
    // Override with IRCFIBER_BOOTSTRAP_PURGE=0 to disable (debugging).
    {
        const purgeEnv = environment.get("IRCFIBER_BOOTSTRAP_PURGE", "1");
        if (purgeEnv == "0" || purgeEnv == "false") {
            logInfo("Bootstrap purge: disabled by IRCFIBER_BOOTSTRAP_PURGE");
        } else if (!maintenanceStateKnown || maintenanceActive) {
            // A coordinated replacement intentionally starts with zero open
            // sockets. Its frozen manifest/assignments must survive until
            // pre-client restoration validates them; unknown is not absent.
            logInfo("Bootstrap purge: skipped, holder maintenance is active or unavailable");
        } else if (!heldStateKnown) {
            logInfo("Bootstrap purge: skipped, holder live-session count unavailable");
        } else if (heldLive > 0) {
            logInfo("Bootstrap purge: skipped, holder holds %d live sessions", heldLive);
        } else {
            try {
                const purged = purgeLocalServerNamespace(redis.getDb(), serverId);
                if (purged > 0)
                    logInfo("Bootstrap purge: removed %d stale keys from namespace %s", purged, serverId);
                else
                    logInfo("Bootstrap purge: namespace %s is clean", serverId);
            } catch (Exception e) {
                logWarn("Bootstrap purge: failed for %s — proceeding anyway: %s", serverId, e.msg);
            }
        }
    }

    auto bufferManager = new BufferManager(redis);
    logInfo("Bootstrap: BufferManager created");
    auto eventChannel = EngineEventChannel.create();
    logInfo("Bootstrap: eventChannel created");
    auto connManager = new ConnectionManager(eventChannel, redis, serverId, holder);
    logInfo("Bootstrap: ConnectionManager created");
    auto networkRepo = new NetworkRepository();
    auto messageRepo = new MessageRepository();
    logInfo("Bootstrap: repositories created");
    auto serverRegistry = new ServerRegistry(redis);
    logInfo("Bootstrap: ServerRegistry created, deferred registration to event loop");

    // Defer server registration to run after runApplication() starts the
    // vibe.d event loop. Redis hset/hget/sadd operations need a running
    // event loop to process I/O — calling them before runApplication()
    // would hang forever on epoll_wait.
    ConnectionServer localServer;
    localServer.serverId = serverId;
    localServer.bindAddress = bindAddress;
    localServer.port = adminPort;
    localServer.isHealthy = true;
    localServer.routingPolicyVersion = 1;
    localServer.lastHeartbeat = Clock.currTime.toUnixTime!long * 1000;
    localServer.bufferOffset = 0; // Registry will set proper offset
    auto bi = buildInfo();
    localServer.gitHash = bi.commit;
    localServer.gitShort = bi.shortHash;
    localServer.gitDescribe = bi.describe;
    localServer.gitBranch = bi.branch;
    localServer.buildTime = bi.builtAt;
    localServer.version_ = bi.version_;
    localServer.gitMessage = bi.message;
    localServer.gitCommitUrl = bi.commitUrl;
    localServer.assignedNetworks = [];

    // Apply admin-saved engine config overrides from Redis.
    // The admin panel writes to irc:engine:config:<serverId> but the engine
    // starts with whatever was in the env vars. We read the saved config and
    // overlay it onto our local server record so admin changes take effect
    // without restarting the engine.
    try {
        auto cfg = serverRegistry.getEngineConfig(localServer.serverId);
        if (cfg.priority != 0) {
            localServer.priority = cfg.priority;
            logInfo("Applied engine config: priority=%d", cfg.priority);
        }
        if (cfg.maxConnections != 0) {
            localServer.maxConnections = cfg.maxConnections;
            logInfo("Applied engine config: maxConnections=%d", cfg.maxConnections);
        }
        if (cfg.fallbackOnly) {
            localServer.fallbackOnly = true;
            logInfo("Applied engine config: fallbackOnly=true");
        }
    } catch (Exception e) {
        logWarn("Failed to apply engine config overrides: %s", e.msg);
    }

    // ── Orphan guard: build valid-user-ID set ────────────────────────
    // Networks whose userId doesn't match any existing MongoDB user are
    // orphaned connections from deleted accounts. Skip them at bootstrap
    // and persist the disabled flag so they don't reload on restart.
    bool[string] validUserIds;
    try {
        auto userRepo = new UserRepository();
        foreach (id; userRepo.allUserIds()) {
            validUserIds[id] = true;
        }
        logInfo("Orphan guard: loaded %d valid user IDs", validUserIds.length);
    } catch (Exception e) {
        logWarn("Orphan guard: failed to load user IDs (%s) — proceeding without validation", e.msg);
    }

    // Network loading is deferred to run after runApplication() starts the
    // vibe.d event loop. Redis operations (HGET, SMEMBERS, HSET) need the
    // event loop to process I/O — calling them here would hang on Linux
    // (epoll driver) because the event loop isn't running yet.
    // See loadNetworksWithRetry(), run from the registration task in
    // app_engine.d inside a runTask after runApplication().
    logInfo("Bootstrap: network loading deferred to event loop");

    EngineContext ctx;
    ctx.connManager = connManager; ctx.redis = redis; ctx.bufferManager = bufferManager;
    ctx.messageRepo = messageRepo; ctx.networkRepo = networkRepo;
    ctx.eventChannel = eventChannel; ctx.serverRegistry = serverRegistry;
    ctx.localServer = localServer; ctx.holder = holder;
    ctx.runtimeDiagnostics = new RuntimeDiagnosticMailbox;
    // Recovery/fsync and latest diagnostic writes share one native disk owner.
    // Holder attachment and event draining do not wait for journal recovery.
    try {
        ctx.archiveSpool = new ArchiveSpool(ArchiveSpoolConfig.fromEnvironment(), ctx.runtimeDiagnostics);
        ctx.archiveControl = new ArchiveControl;
    } catch (Exception e) {
        logJsonMap("error", "engine", "Archive initialization unavailable; live sockets preserved",
            ["event":"archive_gap", "reason":"initialization_failed"]);
    }
    return ctx;
}

private bool networksLoading;
private bool reconciliationRunning;

/// Load networks from MongoDB and start IRC clients.
/// Must be called from a runTask (the event loop must be running because
/// Redis operations need the event loop to process I/O).
void loadNetworks(ref EngineContext ctx) {
    networksLoading = true;
    scope(exit) networksLoading = false;
    ctx.connManager.restoreHolderMaintenance();
    import ircfiber.db.user : UserRepository;
    logInfo("Network loading task: loading networks from MongoDB");

    // Re-query valid user IDs for orphan guard
    bool[string] validUserIds;
    try {
        auto userRepo = new UserRepository();
        foreach (id; userRepo.allUserIds()) {
            validUserIds[id] = true;
        }
        logInfo("Network loading: loaded %d valid user IDs", validUserIds.length);
    } catch (Exception e) {
        logWarn("Network loading: failed to load user IDs (%s) — proceeding without validation", e.msg);
    }

    auto allNetworks = ctx.networkRepo.findAll();
    logInfo("Network loading: %d networks from MongoDB", allNetworks.length);

    // Sessions the holder kept across the restart (hot swap / crash),
    // indexed by networkId. An `open` entry wins over retained `closed`
    // ones; every entry not consumed below is cleaned up afterwards.
    HolderEntry[string] held;
    HolderEntry[] heldAll;
    HolderListObservation heldObservation;
    scope(exit) {
        held = null;
        heldAll = null;
        if (heldObservation !is null) heldObservation.release();
    }
    if (ctx.holder !is null) {
        try {
            heldObservation = acquireFreshHolderList(ctx, true);
            heldAll = heldObservation.entries;
        }
        catch (Exception e) throw new Exception("Holder LIST unavailable; ownership recovery cannot dial safely: " ~ e.msg);
    }
    foreach (e; heldAll) {
        auto nid = e.tag.networkId;
        if (nid.length == 0) continue;
        if (auto p = nid in held) { if (p.state == "open" || e.state != "open") continue; }
        held[nid] = e;
    }
    bool[string] consumed;
    if (heldAll.length)
        logInfo("Network loading: holder has %d session(s) for %d network(s)", heldAll.length, held.length);

    int loadedCount = 0;
    int attachedCount = 0;
    int skippedCount = 0;
    int orphanCount = 0;
    auto serverId = ctx.localServer.serverId;

    foreach (nw; allNetworks) {
        if (nw.config.disabled || nw.config.servicesProvisioningPending) {
            skippedCount++;
            continue;
        }

        // New/recovered clients must use the persisted reservation. In
        // particular, bootstrap must not dial a row left saved but unassigned
        // when HTTP provisioning failed to reserve its IID.
        try {
            import ircfiber.engine.consumer : loadCanonicalNetwork;
            nw = loadCanonicalNetwork(ctx, nw.config.id);
        } catch (Exception e) {
            logWarn("Network loading: identity unavailable for %s — no new dial (%s)",
                nw.config.id.toString(), e.msg);
            // Allocation/storage failure must not close an established
            // holder socket during the unconsumed-entry cleanup below.
            if (auto entry = nw.config.id.toString() in held)
                if (entry.state == "open") consumed[entry.id] = true;
            skippedCount++;
            continue;
        }
        if (nw.config.disabled || nw.config.servicesProvisioningPending) {
            skippedCount++;
            continue;
        }

        const nidForAssignment = nw.config.id.toString();
        if (networkMoveFenced(ctx.redis.getDb(), nidForAssignment)) {
            // The coordinator owns closure while fenced; never clean up its
            // source entries or instantiate another generation underneath it.
            foreach (entry; heldAll)
                if (entry.tag.networkId == nidForAssignment) consumed[entry.id] = true;
            continue;
        }
        auto assignedServer = ctx.serverRegistry.getServerForNetwork(nidForAssignment);
        if (!assignedServer.length) {
            // Restore unique prior ownership first; arbitrary saved rows are
            // not new provisioning and must not be assigned opportunistically.
            assignedServer = ctx.serverRegistry.assignNetwork(nidForAssignment);
            if (!assignedServer.length) {
                if (auto entry = nidForAssignment in held) {
                    if (entry.state == "open") {
                        assignedServer = ctx.serverRegistry.claimNetwork(nidForAssignment, serverId);
                        // An empty/unavailable plan cannot turn missing
                        // assignment storage into permission to close a socket.
                        if (!assignedServer.length) consumed[entry.id] = true;
                    }
                }
            }
        }
        const shouldLoad = assignedServer == serverId
            && !networkMoveFenced(ctx.redis.getDb(), nidForAssignment);

        if (shouldLoad) {
            import std.uuid : UUID;
            auto uidStr = nw.userId.toString();
            const isZeroUser = (uidStr == "00000000-0000-0000-0000-000000000000");
            if (!isZeroUser && validUserIds.length > 0 && (uidStr.length == 0 || uidStr !in validUserIds)) {
                logWarn("ORPHAN BOOTSTRAP: network '%s' (id=%s, host=%s, nick=%s) owner=%s not found — disabling",
                    nw.config.name, nw.config.id.toString(), nw.config.host, nw.config.nick, uidStr);
                try {
                    ctx.networkRepo.setDisabled(nw.config.id, true);
                } catch (Exception e) {
                    logWarn("Failed to disable orphaned network %s: %s", nw.config.name, e.msg);
                }
                orphanCount++;
                skippedCount++;
                continue;
            }
            const nid = nw.config.id.toString();
            bool attached = false;
            if (auto e = nid in held) {
                consumed[e.id] = true;
                if (e.state == "open") {
                    // This may join an already streaming identity observation.
                    // Resolve selected META without issuing a second LIST.
                    *e = restorationEntry(ctx.holder, *e);
                    scope(exit) e.meta = Json.undefined;
                    SessionSnapshot snap;
                    bool usable = false;
                    if (e.hasMeta) {
                        try { snap = fromJSON(e.meta); usable = snap.wasConnected; }
                        catch (Exception ex) logWarn("Held session %s for %s has unreadable META (%s) — re-dialing", e.id, nw.config.name, ex.msg);
                    }
                    if (usable) {
                        logJsonMap("info", "connection", "Attaching to held session",
                            ["network": nw.config.name, "holderId": e.id,
                             "graceful": snap.graceful ? "true" : "false",
                             "connectedAtMs": e.connectedAtMs.to!string, "event": "attach_start"]);
                        ctx.connManager.attachNetwork(nw.config, nw.userId, *e, snap);
                        attached = true;
                        attachedCount++;
                    } else {
                        // The previous engine died before registration finished
                        // (or never wrote META): the socket is not a usable
                        // session. Close it and dial fresh.
                        logInfo("Held session %s for %s was never registered — closing and re-dialing", e.id, nw.config.name);
                        try ctx.holder.closeClaim(e.id, e.instance, e.connectedAtMs, "engine restarted"); catch (Exception ex) logWarn("holder CLOSE %s failed: %s", e.id, ex.msg);
                    }
                }
            }
            if (!attached) {
                import ircfiber.engine.consumer : canonicalRoutingParked;
                if (canonicalRoutingParked(ctx, nw.config)) continue;
                ctx.connManager.addNetwork(nw.config, nw.userId);
                if (auto e = nid in held) if (e.state == "closed") {
                    // Dropped while no engine was reading: tell the user why
                    // before the fresh dial's timeline starts.
                    if (auto client = ctx.connManager.getClient(nw.config.id))
                        client.emitLog("warn", "Connection dropped while the engine was down: "
                            ~ (e.closeReason.length ? e.closeReason : "unknown reason"));
                    try ctx.holder.forgetClaim(e.id, e.instance, e.connectedAtMs); catch (Exception ex) logWarn("holder FORGET %s failed: %s", e.id, ex.msg);
                }
            }
            loadedCount++;
            // Spawn the command consumer for this network so WS-queued
            // cmds (join, msg, part) don't sit in irc:cmd:<server>:<nid>
            // forever. Without this, startCommandConsumers in consumer.d
            // (which runs in a separate runSafe task) can race against
            // loadNetworks and find an empty network list, spawning NO
            // consumers at boot — and nobody respawns them because we're
            // in the startup path, not the control-message path that calls
            // spawnAndAddNetwork. See consumer.d issue 2026-07-03.
            import ircfiber.engine.consumer : spawnNetworkCommandConsumer;
            spawnNetworkCommandConsumer(ctx, nw.config.id.toString());
        }
    }

    // Whatever the holder still has that no loaded network consumed: the
    // network was disabled, deleted or reassigned while the engine was down.
    foreach (e; heldAll) {
        if (e.id in consumed) continue;
        try {
            if (e.state == "open") {
                logInfo("Closing held session %s (%s): network no longer assigned here", e.id, e.tag.name);
                ctx.holder.closeClaim(e.id, e.instance, e.connectedAtMs, "network no longer assigned");
            } else {
                ctx.holder.forgetClaim(e.id, e.instance, e.connectedAtMs);
            }
        } catch (Exception ex) {
            logWarn("Holder cleanup of %s failed: %s", e.id, ex.msg);
        }
    }

    if (orphanCount > 0) {
        logWarn("Network loading: skipped %d orphaned network(s) with no valid owner " ~
            "(disabled in MongoDB)", orphanCount);
    }
    logInfo("Network loading: loaded %d networks (attached=%d to held sessions, skipped=%d disabled/pending)",
        loadedCount, attachedCount, skippedCount);

    ctx.connManager.startDeferredClients();
}

/// `loadNetworks` with bounded retry. Must run inside a runTask so the Redis
/// and Mongo operations have a running event loop to process I/O.
///
/// Retries because a host reboot starts mongod and the engine at the same
/// time: the first `findAll()` then hits a mongod that is still starting
/// ("not master and slaveOk=false"), the one-shot load threw, and the
/// engine sat with zero connections until an operator restarted it by hand
/// (prod, 2026-09-13 — 50 user networks stayed offline after a reboot).
/// Every attempt is idempotent: `addNetwork` skips networks the manager
/// already holds, and held holder sessions are consumed only once.
void loadNetworksWithRetry(ref EngineContext ctx) {
    enum attempts = 60;          // 60 × 5 s ≈ 5 min of mongod startup slack
    enum retryDelay = 5.seconds;
    foreach (attempt; 1 .. attempts + 1) {
        try {
            loadNetworks(ctx);
            return;
        } catch (Exception e) {
            if (attempt == attempts) {
                logError("Network loading failed after %d attempts: %s — no networks are connected",
                    attempts, e.msg);
                return;
            }
            logWarn("Network loading attempt %d/%d failed (%s) — retrying in %s",
                attempt, attempts, e.msg, retryDelay);
            sleep(retryDelay);
        }
    }
}

private void startNetworkReconciliation(ref EngineContext ctx, HolderEntry[] physicalEntries) {
    if (networksLoading || reconciliationRunning) return;
    // withFreshHolderList hands us owned, metadata-free evidence. Retain that
    // array, never the restoration observation, across asynchronous adoption.
    auto identities = physicalEntries;
    physicalEntries = null;
    reconciliationRunning = true;
    runTask(() nothrow {
        scope(exit) identities = null;
        scope(exit) reconciliationRunning = false;
        try {
            import ircfiber.engine.consumer : loadCanonicalNetwork, spawnNetworkCommandConsumer;
            import ircfiber.irc.routing_policy_store : loadRoutingPolicy;
            import ircfiber.irc.routing_policy : resolveRoutingPolicy;
            import ircfiber.irc.dial_guard : ownsNetworkForDial;
            import std.uuid : parseUUID;
            const sid = ctx.localServer.serverId;
            ctx.serverRegistry.getAllAssignments();
            foreach (network; ctx.connManager.getNetworks()) {
                const nid = network.config.id.toString();
                if (networkMoveFenced(ctx.redis.getDb(), nid)) continue;
                auto owner = ctx.serverRegistry.getServerForNetwork(nid);
                if (!owner.length) {
                    // Actual local client evidence permits atomic self-heal;
                    // a competing/ambiguous prior owner must not be overwritten.
                    try owner = ctx.serverRegistry.claimNetwork(nid, sid);
                    catch (Exception e) logWarn("Local ownership recovery blocked for %s: %s", nid, e.msg);
                    if (!owner.length) continue;
                }
                auto row = ctx.networkRepo.findByIdWithUser(network.config.id);
                auto client = ctx.connManager.getClient(network.config.id);
                if (owner != sid || row.config.id == UUID.init || row.config.disabled
                        || row.config.servicesProvisioningPending || (client !is null && client.getStopping)
                        || ctx.connManager.getOwnerId(network.config.id) != row.userId.toString()) {
                    if (!ctx.connManager.stopNetworkForMove(network.config.id, 60.seconds))
                        logWarn("Reconciliation source closure unproven for %s; retaining stopped generation", nid);
                }
            }
            // Resolve eligibility against the heartbeat's one physical scan.
            // Restore only selected entries via INFO, never another LIST.
            string[] missing;
            foreach (nid; ctx.serverRegistry.getCanonicalNetworks(sid)) {
                try {
                    if (networkMoveFenced(ctx.redis.getDb(), nid)) continue;
                    if (ctx.connManager.hasNetwork(nid)) {
                        spawnNetworkCommandConsumer(ctx, nid);
                        continue;
                    }
                    auto row = loadCanonicalNetwork(ctx, parseUUID(nid[]));
                    if (row.config.disabled || row.config.servicesProvisioningPending) continue;
                    if (!ownsNetworkForDial(ctx.redis, sid, nid)) continue;
                    missing ~= nid;
                } catch (Exception e) {
                    logWarn("Network reconciliation deferred for %s: %s", nid, e.msg);
                }
            }
            if (missing.length == 0) return;
            {
                auto entries = identities;
                HolderEntry[string] heldByNetwork;
                foreach (entry; entries)
                    if (entry.state == "open" && entry.tag.networkId.length
                            && entry.tag.networkId !in heldByNetwork)
                        heldByNetwork[entry.tag.networkId] = entry;
                scope(exit) heldByNetwork = null;

                foreach (nid; missing) {
                    try {
                        // LIST admission and earlier restorations may yield:
                        // reload tenant/config and ownership before adoption.
                        if (networkMoveFenced(ctx.redis.getDb(), nid)) continue;
                        if (ctx.connManager.hasNetwork(nid)) {
                            spawnNetworkCommandConsumer(ctx, nid);
                            continue;
                        }
                        auto row = loadCanonicalNetwork(ctx, parseUUID(nid[]));
                        if (row.config.disabled || row.config.servicesProvisioningPending) continue;
                        if (!ownsNetworkForDial(ctx.redis, sid, nid)) continue;
                        HolderEntry held;
                        if (auto entry = nid in heldByNetwork) held = *entry;
                        bool adopted;
                        if (held.id.length) {
                            held = restorationEntry(ctx.holder, held);
                            scope(exit) held.meta = Json.undefined;
                            SessionSnapshot snapshot;
                            bool usable;
                            if (held.hasMeta) {
                                try { snapshot = fromJSON(held.meta); usable = snapshot.wasConnected; }
                                catch (Exception) {}
                            }
                            // Existing held sessions adopt even when new routes
                            // are empty or durable policy is temporarily unreadable.
                            if (usable) {
                                ctx.connManager.attachNetwork(row.config, row.userId, held, snapshot);
                                adopted = true;
                            } else ctx.holder.closeClaim(held.id, held.instance, held.connectedAtMs, "recovering incomplete registration");
                        }
                        if (!adopted) {
                            auto policy = loadRoutingPolicy(ctx.redis.getDb());
                            if (resolveRoutingPolicy(policy, row.config.host, row.config.routing).order.length == 0) continue;
                            if (!ownsNetworkForDial(ctx.redis, sid, nid)) continue;
                            ctx.connManager.addAndStartNetwork(row.config, row.userId);
                        }
                        spawnNetworkCommandConsumer(ctx, nid);
                    } catch (Exception e) {
                        logWarn("Network reconciliation deferred for %s: %s", nid, e.msg);
                    }
                }
            }
        } catch (Exception e) {
            try logWarn("Network reconciliation failed: %s", e.msg); catch (Exception) {}
        }
    });
}

/**
 * Start heartbeat task to keep server registered and network leases renewed.
 *
 * Sends heartbeat every 10 seconds to the gateway registry. The gateway marks
 * a server unhealthy if the heartbeat is stale for >60s, so this gives a 6x
 * safety margin and lets the gateway recover quickly after an engine restart.
 *
 * Also renews the TTL-backed lease for every network assigned to this server.
 * If the engine crashes, the leases expire within LEASE_TTL_SECONDS (90s) and
 * the gateway's health check detects the orphaned assignments and reassigns
 * them — a safety net for both crash and graceful-shutdown paths.
 */
void startHeartbeatTask(ref EngineContext ctx) {
    runTask(() nothrow {
        int beat = 0;
        // Backoff state — when a heartbeat cycle throws (e.g. Redis
        // unreachable), we don't want to busy-loop into the same
        // exception at 100% CPU. Hold off for `backoffMs`, doubling
        // each consecutive failure up to a 60s cap. A successful
        // cycle resets the counter.
        long backoffMs = 0;
        import core.time : msecs;

        while (true) {
            try logJsonMap("debug", "heartbeat", "Heartbeat loop top", ["beat": beat.to!string]);
            catch (Throwable) {}
            try {
                ctx.localServer.lastHeartbeat = Clock.currTime.toUnixTime!long * 1000;
                ctx.localServer.routingPolicyVersion = 1;
                ctx.serverRegistry.updateHeartbeat(ctx.localServer.serverId);
                refreshRoutingCapabilities(ctx, true);
                // Holder identity/counters next to the heartbeat so operators
                // can see the holder every engine rides (skipped when the
                // holder is unreachable — the engine's own beat still counts).
                if (ctx.holder !is null) {
                    try {
                        auto hs = ctx.holder.status();
                        auto key = RedisKeys.server(ctx.localServer.serverId);
                        auto rdb = ctx.redis.getDb();
                        rdb.hset(key, "holderVersion", hs.holder);
                        rdb.hset(key, "holderPid", hs.pid.to!string);
                        rdb.hset(key, "holderOpen", hs.open.to!string);
                        rdb.hset(key, "holderAttached", hs.attached.to!string);
                        rdb.hset(key, "holderDetached", hs.detached.to!string);
                    } catch (HolderUnavailableException) {
                    } catch (Throwable e) {
                        string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                        try logDebug("Heartbeat: holder status skipped: %s", m); catch (Throwable) {}
                    }
                }

                // Layer 1: TTL bump. Extend the lifetime of every state
                // key (irc:state, scrollback, dedup) so a dead engine
                // self-evicts within STATE_TTL even without a janitor.
                auto stateTtl = parseStateTtl();
                if (stateTtl > 0) {
                    try {
                        auto touched = bumpServerStateTTLs(
                            ctx.redis.getDb(),
                            ctx.localServer.serverId,
                            stateTtl);
                        if (touched > 0 && beat == 0)
                            logInfo("Heartbeat: bumped TTL on %d state keys (%ds)",
                                touched, stateTtl);
                    } catch (Throwable e) {
                        string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                        try logDebug("Heartbeat: TTL bump failed: %s", m);
                        catch (Throwable) {}
                    }
                }
                // Draining is durable operator intent, not a stale process
                // bit to clear merely because a replacement starts beating.
                ctx.localServer.draining = ctx.serverRegistry.isDraining(ctx.localServer.serverId);

                // Surface per-network registration-timeout markers.
                ctx.localServer.registrationUnavailableFor =
                    ctx.connManager.networksAwaitingRegistration();
                try recordGauge(
                    "ircfiber.registration.timeout_networks",
                    cast(long)ctx.localServer.registrationUnavailableFor.length,
                    ["serverId":   ctx.localServer.serverId]);
                catch (Throwable) {}
                try ctx.serverRegistry.syncServerState(ctx.localServer.serverId, ctx.localServer);
                catch (Throwable) {}

                // Read canonical assignments from irc:assignments.
                ctx.serverRegistry.getAllAssignments();
                auto canonical = ctx.serverRegistry.getCanonicalNetworks(ctx.localServer.serverId);

                // Renew leases for networks still assigned to us.
                foreach (netId; canonical) {
                    try ctx.serverRegistry.renewLease(netId);
                    catch (Throwable) {}
                }


                // Actual canonical reconciliation runs separately so a bounded
                // holder close cannot stall heartbeat/control traffic.

                ctx.localServer.assignedNetworks = canonical;

                // Self-heal ghost "" entries.
                import std.algorithm : filter;
                import std.array : array;
                ctx.localServer.assignedNetworks = ctx.localServer.assignedNetworks
                    .filter!(n => n.length > 0)
                    .array;

                // Reverse mirrors are physical recovery evidence, not a copy
                // of planned canonical assignments. An unavailable LIST must
                // preserve evidence instead of declaring sockets gone.
                try {
                    string[] evidence;
                    withFreshHolderList(ctx, (HolderEntry[] entries) {
                        foreach (entry; entries) {
                            if (!entry.tag.networkId.length) continue;
                            auto client = ctx.connManager.getClient(parseUUID(entry.tag.networkId));
                            if (client !is null) client.observeHolderEntry(entry);
                        }
                        foreach (network; ctx.connManager.getNetworks())
                            evidence ~= network.config.id.toString();
                        foreach (entry; entries)
                            if (entry.state == "open" && entry.tag.networkId.length
                                    && !evidence.canFind(entry.tag.networkId))
                                evidence ~= entry.tag.networkId;
                        startNetworkReconciliation(ctx, entries);
                    });
                    ctx.serverRegistry.publishServerAssignments(ctx.localServer.serverId, evidence);
                } catch (Throwable) {}

                // Persist the now-clean assignedNetworks back to the server record.
                try ctx.serverRegistry.syncServerState(
                    ctx.localServer.serverId, ctx.localServer);
                catch (Throwable) {}

                // Re-read engine config from Redis so admin changes take effect.
                try {
                    auto cfg = ctx.serverRegistry.getEngineConfig(ctx.localServer.serverId);
                    if (cfg.priority != 0) ctx.localServer.priority = cfg.priority;
                    if (cfg.maxConnections != 0) ctx.localServer.maxConnections = cfg.maxConnections;
                    ctx.localServer.fallbackOnly = cfg.fallbackOnly;
                } catch (Throwable) { }

                // Heartbeat health is visible via Redis TTL + engine.heartbeat span
                // (every 60s). The per-beat "Heartbeat sent" line is debug
                // so prod SigNoz isn't flooded at 8640 lines/day/engine.
                try logJsonMap("debug", "heartbeat", "Heartbeat sent",
                    ["serverId": ctx.localServer.serverId, "beat": beat.to!string, "assigned": ctx.localServer.assignedNetworks.length.to!string]);
                catch (Throwable) {}
                // server load, so the Distributed Traces view always has
                // fresh data with actual metrics (not just "up=1").
                // Guarded by isTracingEnabled() to avoid allocating a
                // span when OTel is disabled (withSpan itself is no-op,
                // but the guard saves the attrs array alloc).
                if (isTracingEnabled() && beat++ % 6 == 0) {
                    try withSpan("engine.heartbeat", ["serverId": ctx.localServer.serverId], (ref Span s) {
                        s.attr("healthy", "1");
                        s.setStatusOk();
                    }); catch (Throwable) {}
                } else if (!isTracingEnabled()) {
                    beat++;
                } else {
                    // Tracing enabled but not a heartbeat-span cycle — still advance beat.
                    // The beat++ already happened in the `if` condition when tracing
                    // enabled, but when beat%6!=0 the post-increment still fired;
                    // no extra increment needed here.
                }
                // Cycle succeeded — clear backoff so the next failure
                // starts from the short end of the curve again.
                backoffMs = 0;
            } catch (Throwable e) {
                // Enterprise: catch Throwable (covers SyncError, AssertError)
                // Previously only Exception, so SyncError from vibe-d's
                // __gshared/Mutex robust path killed the heartbeat fiber
                // as FATAL (futex_do_wait wedge at 07:29:53 beat=0).
                // Now log and backoff so the next beat recovers.
                string msg;
                try { msg = e.msg; } catch (Throwable) { msg = "unknown throwable"; }
                try logError("Heartbeat failed (throwable): %s", msg);
                catch (Throwable) {}
                // Exponential backoff: 1s, 2s, 4s, ... capped at 60s.
                // Doubles on each consecutive failure; reset to 0 on
                // success above. Without this backoff a Redis outage
                // pegs the engine at 100% CPU retrying the same
                // throw on every iteration of `while (true)`.
                if (backoffMs == 0) backoffMs = 1_000;
                else backoffMs = min(backoffMs * 2, 60_000L);
                try sleep(backoffMs.msecs);
                catch (Throwable) { /* nothrow lambda — swallow */ }
                continue;
            }
            // Normal cadence — only when the try block completed
            // without throwing. The catch branch above uses `continue`
            // to skip this sleep and instead applies its own backoff.
            try sleep(10.seconds);
            catch (Throwable) { /* nothrow lambda — swallow */ }
        }
    });
}

private bool telemetryFlushRunning;

/// One periodic exporter owner, independent of Redis heartbeat success.
/// Each queue enforces its own one-in-flight export and bounded HTTP deadline,
/// including when an error-path/shutdown flush overlaps this fiber.
void startTelemetryFlushTask() {
    if (telemetryFlushRunning) return;
    telemetryFlushRunning = true;
    try {
        runTask(() nothrow {
            scope(exit) telemetryFlushRunning = false;
            while (true) {
                // Separate guards ensure one failing exporter cannot suppress
                // the other queues or permanently terminate periodic export.
                try exportMongoCircuitMetrics(); catch (Throwable) {}
                try flushAndSendSpans(); catch (Throwable) {}
                try flushAndSendMetrics(); catch (Throwable) {}
                try flushAndSendLogs(); catch (Throwable) {}
                try sleep(10.seconds); catch (Throwable) {}
            }
        });
    } catch (Throwable e) {
        telemetryFlushRunning = false;
        throw e;
    }
}
/// Read IRCFIBER_STATE_TTL env var with sensible bounds. Cached per-call
/// (heartbeat runs at 10 s — cheap).
private long parseStateTtl() {
    import std.conv : to;
    const raw = environment.get("IRCFIBER_STATE_TTL", "");
    if (raw.length == 0) return StateTTL.DEFAULT;
    try {
        auto v = raw.to!long;
        if (v < 30 || v > 86_400) return StateTTL.DEFAULT;
        return v;
    } catch (Exception) {
        return StateTTL.DEFAULT;
    }
}

/**
 * Start orphan reaper task — periodically disconnects networks whose
 * owning user no longer exists in MongoDB. Runs every 5 minutes.
 *
 * Without this, deleting a user directly from MongoDB (bypassing the
 * admin API) leaves their IRC connections running forever: the engine
 * keeps the sockets open, publishes events to a non-existent user's
 * Redis channel, and wastes resources.
 *
 * Each cycle:
 *   1. Re-queries MongoDB for current valid user IDs
 *   2. Checks every active network in ConnectionManager
 *   3. For any orphan (owner not in valid set):
 *      a. Removes from ConnectionManager (sends QUIT, closes socket)
 *      b. Persists disabled=true in MongoDB
 *      c. Cleans up Redis: state keys, assignments, fail counter, lease
 *      d. Logs full audit info
 */
void startOrphanReaperTask(ref EngineContext ctx) {
    runTask(() nothrow {
        try {
            // First sleep: let the engine finish booting and establish
            // initial connections before we start checking.
            sleep(60.seconds);
        } catch (Exception) { }
        while (true) {
            try {
                sleep(300.seconds); // 5 minutes between cycles
            } catch (Exception) { }
            try {
                // Re-query valid user IDs each cycle to catch user
                // deletions that happened after engine boot.
                bool[string] validUserIds;
                try {
                    auto userRepo = new UserRepository();
                    foreach (id; userRepo.allUserIds()) {
                        validUserIds[id] = true;
                    }
                } catch (Exception e) {
                    logWarn("Orphan reaper: failed to query user IDs (%s) — skipping cycle", e.msg);
                    continue;
                }

                if (validUserIds.length == 0) {
                    logWarn("Orphan reaper: no users found in MongoDB — skipping cycle (safety guard)");
                    continue;
                }

                foreach (net; ctx.connManager.getNetworks()) {
                    auto netId = net.config.id.toString();
                    auto persisted = ctx.networkRepo.findByIdWithUser(net.config.id);
                    if (persisted.config.id == UUID.init) continue;
                    auto ownerId = persisted.userId.toString();
                    if (ownerId != ctx.connManager.getOwnerId(net.config.id)
                            || ctx.serverRegistry.getServerForNetwork(netId) != ctx.localServer.serverId
                            || networkMoveFenced(ctx.redis.getDb(), netId)) continue;

                    // An empty ownerId means the network is not in
                    // networkOwners at all — that's a different bug.
                    // We only act when the owner ID is set but the
                    // user no longer exists in MongoDB.
                    if (ownerId.length == 0) continue;
                    if (ownerId in validUserIds) continue;

                    logWarn("ORPHAN REAPER: network '%s' (id=%s, host=%s, nick=%s) owner=%s not found — disconnecting",
                        net.config.name, netId, net.config.host,
                        net.config.nick,
                        ownerId);

                    // Closure must precede cleanup; a stale cached tenant may
                    // not disable a row transferred while the close was waiting.
                    if (!ctx.connManager.stopNetworkForMove(net.config.id, 60.seconds)) continue;
                    auto latest = ctx.networkRepo.findByIdWithUser(net.config.id);
                    if (latest.userId != persisted.userId
                            || ctx.serverRegistry.getServerForNetwork(netId) != ctx.localServer.serverId
                            || networkMoveFenced(ctx.redis.getDb(), netId)) continue;

                    // 2. Persist disabled flag in MongoDB
                    try {
                        auto netRepo = new NetworkRepository();
                        netRepo.setDisabled(net.config.id, true);
                        logInfo("Orphan reaper: set disabled=true for network %s", netId);
                    } catch (Exception e) {
                        logWarn("Orphan reaper: failed to set disabled flag for %s: %s", netId, e.msg);
                    }

                    // 3. Clean up Redis: state snapshots, assignments, fail counters, leases
                    try {
                        auto db = ctx.redis.getDb();
                        db.del(RedisKeys.state(ctx.localServer.serverId, netId));
                        db.del(RedisKeys.state_legacy(netId));
                        db.del(RedisKeys.networkFail(netId));
                        logInfo("Orphan reaper: cleaned Redis state for network %s", netId);
                    } catch (Exception e) {
                        logWarn("Orphan reaper: failed to clean Redis for %s: %s", netId, e.msg);
                    }
                }
            } catch (Exception e) {
                logError("Orphan reaper cycle failed: %s", e.msg);
            }
        }
    });
}

version (MemoryReliabilityHarness)
Ircv3Check[] holderScanObservationRegressionChecks() {
    import ircfiber.irc.connection : Ircv3Check;
    import vibe.core.net : listenTCP, TCPConnection;
    import vibe.stream.operations : readLine;
    import vibe.data.json : Json, parseJsonString;
    import ircfiber.holder_client : HolderErrorException;
    import ircfiber.engine.session_snapshot : toJSON;
    import core.memory : GC;
    import core.time : MonoTime;
    import std.string : startsWith, strip;
    Ircv3Check[] checks;
    EngineContext context;
    bool gate = true, failNext, legacy;
    bool largeLegacy, legacyGate, infoGate, changedInfo, queueStatus, errorLegacy;
    int invalidLegacy, sparseLegacy;
    size_t scans, pages, lists, infos, legacyStarted;
    auto rawChunk = new char[4096];
    rawChunk[] = 'x';
    auto numberChunk = new char[4096];
    numberChunk[] = '0';
    string escapedChunk;
    foreach (_; 0 .. 682) escapedChunk ~= `\u0061`;
    SessionSnapshot fixtureSnapshot;
    fixtureSnapshot.wasConnected = true;
    fixtureSnapshot.graceful = true;
    fixtureSnapshot.connectedAtMs = 700;
    fixtureSnapshot.sessionNick = "restored-nick";
    fixtureSnapshot.servicesLegacyAuthPending = 2;
    fixtureSnapshot.servicesQuietPrefixes = ["NickServ!services@fixture"];
    fixtureSnapshot.servicesQuietUntilMs = 1700000030000;
    Json legacyRow() {
        auto row = Json.emptyObject;
        row["id"] = "legacy";
        row["instance"] = "legacy-instance";
        row["ordinal"] = 42;
        row["state"] = "open";
        row["attached"] = true;
        row["host"] = "irc.fixture";
        row["port"] = 6697;
        row["peerIp"] = "2001:db8::1";
        row["localIp"] = "2001:db8::2";
        row["connectedAtMs"] = 700;
        row["detachedSinceMs"] = 800;
        row["bufferedBytes"] = 901;
        row["closeReason"] = "prior reason";
        row["closedAtMs"] = 902;
        row["gapGeneration"] = 9;
        row["gapAckGeneration"] = 8;
        row["droppedBytes"] = 903;
        row["droppedLines"] = 904;
        row["gapStartedAtMs"] = 905;
        row["deliveryAmbiguous"] = true;
        auto tag = Json.emptyObject;
        tag["networkId"] = "e655e477-7d91-4000-8000-000000000001";
        tag["userId"] = "owner";
        tag["name"] = "é雪🌲";
        tag["egressLabel"] = "route";
        row["tag"] = tag;
        auto tls = Json.emptyObject;
        tls["ok"] = true;
        tls["version"] = "TLSv1.3";
        tls["cipher"] = "fixture-cipher";
        tls["certCn"] = "fixture-cn";
        tls["certIssuer"] = "fixture-issuer";
        tls["certNotAfterMs"] = 1700000000000L;
        row["tls"] = tls;
        return row;
    }
    TCPConnection[] peers;
    auto listener = listenTCP(0, (TCPConnection peer) {
        peers ~= peer;
        bool statusQueued;
        try {
            while (!peer.empty) {
                const line = (cast(const(char)[]) peer.readLine(65536, "\n")).idup.strip;
                auto response = Json.emptyObject;
                if (line.startsWith("HELLO ")) {
                    response["proto"] = 1;
                    if (!legacy) {
                        response["instance"] = "00000000-0000-4000-8000-000000000001";
                        auto capabilities = Json.emptyArray;
                        capabilities ~= Json("inventory_v1");
                        response["capabilities"] = capabilities;
                    }
                } else if (line.startsWith("INVENTORY ")) {
                    const request = parseJsonString(line["INVENTORY ".length .. $]);
                    const after = request["after"].type == Json.Type.int_ ? request["after"].get!int : 0;
                    if (after == 0) scans++;
                    pages++;
                    while (gate) sleep(1.msecs);
                    if (failNext) { failNext = false; peer.close(); return; }
                    response["instance"] = "00000000-0000-4000-8000-000000000001";
                    response["through"] = 2;
                    response["after"] = after;
                    response["nextAfter"] = after + 1;
                    response["more"] = after == 0;
                    auto rows = Json.emptyArray;
                    foreach (i; after + 1 .. after + 2) {
                        auto row = Json.emptyObject;
                        row["ordinal"] = i;
                        row["id"] = "held-" ~ i.to!string;
                        row["state"] = "open";
                        row["connectedAtMs"] = i * 100;
                        rows ~= row;
                    }
                    response["connections"] = rows;
                } else if (line.startsWith("INFO ") || line.startsWith("ATTACH ")) {
                    const attaching = line.startsWith("ATTACH ");
                    if (!attaching) infos++;
                    while (infoGate) sleep(1.msecs);
                    const offset = attaching ? "ATTACH ".length : "INFO ".length;
                    const id = parseJsonString(line[offset .. $])["id"].get!string;
                    if (id == "legacy") {
                        response = legacyRow();
                        if (changedInfo) response["connectedAtMs"] = 701;
                        if (largeLegacy) {
                            const row = response.toString();
                            peer.write("OK " ~ row[0 .. $ - 1] ~ ",\"meta\":{\"escaped\":\"");
                            foreach (_; 0 .. 512) peer.write(escapedChunk);
                            peer.write("\",\"nested\":[null,true,{\"large\":\"");
                            foreach (_; 0 .. 512) peer.write(cast(const(ubyte)[]) rawChunk);
                            peer.write("\"}]}}\r\n");
                        } else {
                            response["meta"] = toJSON(fixtureSnapshot);
                            peer.write("OK " ~ response.toString() ~ "\r\n");
                        }
                        if (attaching) peer.write(":fixture NOTICE nick :first replay line\r\n");
                        peer.flush();
                        continue;
                    }
                    response["state"] = "open";
                    response["id"] = id;
                    response["instance"] = "00000000-0000-4000-8000-000000000001";
                    response["connectedAtMs"] = id == "held-1" ? 100 : 200;
                    auto tag = Json.emptyObject;
                    tag["networkId"] = id == "held-1"
                        ? "e655e477-7d91-4000-8000-000000000001"
                        : "e655e477-7d91-4000-8000-000000000002";
                    response["tag"] = tag;
                    auto metadata = Json.emptyObject;
                    metadata["fixture"] = id;
                    response["meta"] = metadata;
                } else if (line == "LIST") {
                    lists++;
                    if (errorLegacy) {
                        errorLegacy = false;
                        peer.write("ERR {\"code\":\"busy\",\"msg\":\"already attached\",\"unknown\":{\"ignored\":\"");
                        foreach (_; 0 .. 512) peer.write(escapedChunk);
                        peer.write("\"}}\r\n");
                        peer.flush();
                        continue;
                    }
                    if (sparseLegacy) {
                        auto sparse = Json.emptyObject;
                        sparse["id"] = "sparse";
                        sparse["state"] = "open";
                        sparse["tag"] = Json(null);
                        sparse["tls"] = Json(null);
                        if (sparseLegacy == 2) sparse["meta"] = Json(null);
                        if (sparseLegacy == 3) sparse["meta"] = Json.emptyObject;
                        peer.write("OK {\"connections\":[" ~ sparse.toString() ~ "]}\r\n");
                        peer.flush();
                        continue;
                    }
                    const mode = invalidLegacy;
                    invalidLegacy = 0;
                    auto row = legacyRow().toString();
                    // Pause inside the response, after the range has begun
                    // consuming it, to exercise both observation join orders.
                    peer.write("OK {\"connections\":[" ~ row[0 .. $ - 1] ~ ",\"meta\":");
                    peer.flush();
                    legacyStarted = lists;
                    while (legacyGate) sleep(1.msecs);
                    if (mode == 1) {
                        peer.write("{\"bad\":[1,]}}]}\n");
                    } else if (mode == 2) {
                        peer.write("{\"bad\":\"truncated");
                        peer.flush();
                        peer.close();
                        return;
                    } else if (mode == 3) {
                        peer.write("{} }]} trailing\n");
                    } else if (mode == 4) {
                        peer.write("{\"oversized\":\"");
                        foreach (_; 0 .. 16385) peer.write(cast(const(ubyte)[]) rawChunk);
                        peer.write("\"}}]}\n");
                    } else if (mode == 5) {
                        foreach (_; 0 .. 12) { peer.write(" "); peer.flush(); sleep(1.seconds); }
                        peer.write("{} }]}\n");
                    } else if (mode == 6) {
                        foreach (_; 0 .. 129) peer.write("[");
                        peer.write("0");
                        foreach (_; 0 .. 129) peer.write("]");
                        peer.write("}]}\n");
                    } else if (mode == 7) {
                        // This outer key is decoded to select a DTO field,
                        // unlike arbitrarily long keys in discarded META.
                        peer.write("{} }],\"");
                        foreach (_; 0 .. 17) peer.write(cast(const(ubyte)[]) rawChunk);
                        peer.write("\":0}\n");
                    } else if (largeLegacy) {
                        peer.write("{\"plain\":\"");
                        foreach (_; 0 .. 512) peer.write(cast(const(ubyte)[]) rawChunk);
                        peer.write("\",\"escaped\":\"");
                        foreach (_; 0 .. 512) peer.write(escapedChunk);
                        peer.write("\",\"nested\":[{\"");
                        foreach (_; 0 .. 256) peer.write(cast(const(ubyte)[]) rawChunk);
                        peer.write("\":{\"number\":1");
                        foreach (_; 0 .. 64) peer.write(cast(const(ubyte)[]) numberChunk);
                        peer.write(".01e+2,\"values\":[null,true,false,{\"escaped\":\"\\ud83c\\udf32\"}]}}]}}]}\r\n");
                    } else {
                        const metadata = toJSON(fixtureSnapshot).toString();
                        // Force fragmentation across escaped strings/scalars.
                        foreach (i; 0 .. metadata.length) {
                            peer.write(metadata[i .. i + 1]);
                            if (i % 31 == 0) peer.flush();
                        }
                        peer.write("}]}\r\n");
                    }
                    if (queueStatus) {
                        peer.write("OK {\"proto\":1,\"open\":1}\r\n");
                        statusQueued = true;
                        queueStatus = false;
                    }
                    peer.flush();
                    continue;
                } else if (line == "STATUS") {
                    if (statusQueued) { statusQueued = false; continue; }
                    response["proto"] = 1;
                    response["open"] = 1;
                } else throw new Exception("unexpected scan fixture verb");
                peer.write("OK " ~ response.toString() ~ "\n");
                peer.flush();
            }
        } catch (Exception) {}
        try peer.close(); catch (Exception) {}
    }, "127.0.0.1");
    void cleanup() {
        gate = false;
        legacyGate = false;
        infoGate = false;
        foreach (peer; peers) try peer.close(); catch (Exception) {}
        try listener.stopListening(); catch (Exception) {}
        sleep(25.msecs);
    }
    scope(exit) cleanup();
    const address = "tcp://127.0.0.1:" ~ listener.bindAddress.port.to!string;
    context.holder = new HolderClient("fixture", address);
    context.holder.connectControl();
    HolderListObservation first, second;
    Throwable failure;
    runTask({
        try first = acquireFreshHolderList(context);
        catch (Throwable e) failure = e;
    });
    foreach (_; 0 .. 1000) { if (scans) break; sleep(1.msecs); }
    runTask({
        try second = acquireFreshHolderList(context);
        catch (Throwable e) failure = e;
    });
    foreach (_; 0 .. 1000) {
        if (context.holderListInFlight !is null && context.holderListInFlight.readers == 2) break;
        sleep(1.msecs);
    }
    gate = false;
    foreach (_; 0 .. 1000) { if (first !is null && second !is null || failure !is null) break; sleep(1.msecs); }
    if (failure !is null) throw failure;
    assert(first !is null && second !is null);
    checks ~= Ircv3Check("only physically overlapping holder scans share one observation",
        first is second && scans == 1 && pages == 2 && infos == 2 && first.readers == 2);
    bool metadataFree = first.entries.length == 2;
    bool[string] indexed;
    foreach (entry; first.entries) {
        metadataFree = metadataFree && !entry.hasMeta;
        indexed[entry.tag.networkId] = true;
    }
    checks ~= Ircv3Check("inventory resolves multiple missing-network identities one INFO at a time without retaining META",
        metadataFree && indexed.length == 2 && lists == 0);
    auto later = acquireFreshHolderList(context);
    checks ~= Ircv3Check("later heartbeat stays fresh even while earlier restoration leases remain held",
        later !is first && scans == 2 && pages == 4 && infos == 2);
    first.release();
    checks ~= Ircv3Check("an observation remains owned until its last waiting consumer releases",
        first.entries.length == 2 && first.readers == 1);
    second.release();
    checks ~= Ircv3Check("last consumer releases the observation graph", first.entries.length == 0);
    later.release();
    string[] reverseEvidence = ["prior-physical-network"];
    failNext = true;
    bool rejected;
    try withFreshHolderList(context, (HolderEntry[] entries) { reverseEvidence = null; });
    catch (Exception) rejected = true;
    checks ~= Ircv3Check("failed physical scan never invokes mirror replacement with fabricated emptiness",
        rejected && reverseEvidence == ["prior-physical-network"]);
    foreach (_; 0 .. 1000) { if (context.holder.controlAlive) break; sleep(1.msecs); }
    legacy = true;
    auto old = new HolderClient("fixture", address);
    old.connectControl();
    largeLegacy = true;
    queueStatus = true;
    auto oldEntries = old.scan();
    bool identityFields = oldEntries.length == 1;
    if (identityFields) {
        auto e = oldEntries[0];
        identityFields = !e.hasMeta && e.id == "legacy" && e.instance == "legacy-instance"
            && e.ordinal == 42 && e.tag.networkId == "e655e477-7d91-4000-8000-000000000001"
            && e.tag.userId == "owner" && e.tag.name == "é雪🌲" && e.tag.egressLabel == "route"
            && e.state == "open" && e.attached && e.host == "irc.fixture" && e.port == 6697
            && e.peerIp == "2001:db8::1" && e.localIp == "2001:db8::2"
            && e.connectedAtMs == 700 && e.detachedSinceMs == 800 && e.bufferedBytes == 901
            && e.closeReason == "prior reason" && e.closedAtMs == 902
            && e.gapGeneration == 9 && e.gapAckGeneration == 8 && e.droppedBytes == 903
            && e.droppedLines == 904 && e.gapStartedAtMs == 905 && e.deliveryAmbiguous
            && e.tlsOk && e.tls.version_ == "TLSv1.3" && e.tls.cipher == "fixture-cipher"
            && e.tls.certCn == "fixture-cn" && e.tls.certIssuer == "fixture-issuer"
            && e.tls.certNotAfterMs == 1700000000000L;
    }
    checks ~= Ircv3Check("fragmented genuine legacy LIST skips multi-megabyte META and long discarded numbers while preserving claims TLS UTF8 and gap fields",
        lists == 1 && identityFields);
    bool boundedStrings = identityFields;
    if (boundedStrings) {
        foreach (value; [oldEntries[0].id, oldEntries[0].instance, oldEntries[0].tag.networkId,
                oldEntries[0].tag.userId, oldEntries[0].tag.name, oldEntries[0].tag.egressLabel,
                oldEntries[0].state, oldEntries[0].host, oldEntries[0].peerIp, oldEntries[0].localIp,
                oldEntries[0].closeReason, oldEntries[0].tls.version_, oldEntries[0].tls.cipher,
                oldEntries[0].tls.certCn, oldEntries[0].tls.certIssuer])
            boundedStrings = boundedStrings && GC.query(value.ptr).size <= 65536;
    }
    checks ~= Ircv3Check("legacy identity scalar backing allocations do not retain the large response",
        boundedStrings);
    checks ~= Ircv3Check("a pipelined next STATUS survives LF CRLF frame disposal on the same control",
        old.status().open == 1 && old.controlAlive);
    auto infoIdentity = old.infoIdentity("legacy");
    checks ~= Ircv3Check("streaming INFO skips multi-megabyte META while preserving identity and unacknowledged gaps",
        !infoIdentity.hasMeta && infoIdentity.id == oldEntries[0].id
            && infoIdentity.instance == oldEntries[0].instance
            && infoIdentity.connectedAtMs == 700 && infoIdentity.state == "open"
            && infoIdentity.tag.networkId == oldEntries[0].tag.networkId
            && infoIdentity.tag.userId == oldEntries[0].tag.userId
            && infoIdentity.gapGeneration == 9 && infoIdentity.gapAckGeneration == 8
            && infoIdentity.deliveryAmbiguous && old.status().open == 1);
    auto attachedIdentity = old.attachIdentity("legacy");
    const firstReplay = (cast(const(char)[]) attachedIdentity.stream.readLine(65536, "\n")).idup.strip;
    checks ~= Ircv3Check("streaming ATTACH preserves replay TLS and gap facts without consuming replay bytes or rebuilding META",
        !attachedIdentity.entry.hasMeta && attachedIdentity.entry.id == "legacy"
            && attachedIdentity.entry.instance == "legacy-instance"
            && attachedIdentity.entry.connectedAtMs == 700 && attachedIdentity.entry.state == "open"
            && attachedIdentity.entry.tag.networkId == oldEntries[0].tag.networkId
            && attachedIdentity.entry.tag.userId == oldEntries[0].tag.userId
            && attachedIdentity.entry.bufferedBytes == 901
            && attachedIdentity.entry.tlsOk && attachedIdentity.entry.tls.version_ == "TLSv1.3"
            && attachedIdentity.entry.gapGeneration == 9 && attachedIdentity.entry.gapAckGeneration == 8
            && attachedIdentity.entry.droppedBytes == 903 && attachedIdentity.entry.droppedLines == 904
            && attachedIdentity.entry.gapStartedAtMs == 905 && attachedIdentity.entry.deliveryAmbiguous
            && firstReplay == ":fixture NOTICE nick :first replay line");
    attachedIdentity.stream.close();
    largeLegacy = false;
    auto attachedCheckpoint = old.attach("legacy");
    const checkpointReplay = (cast(const(char)[]) attachedCheckpoint.stream.readLine(65536, "\n")).idup.strip;
    const checkpoint = fromJSON(attachedCheckpoint.entry.meta);
    checks ~= Ircv3Check("full ATTACH retains checkpoint META and strict markers for direct restoration consumers",
        attachedCheckpoint.entry.hasMeta && checkpoint.wasConnected && checkpoint.graceful
            && checkpoint.connectedAtMs == 700 && checkpoint.sessionNick == "restored-nick"
            && checkpoint.servicesLegacyAuthPending == 2
            && checkpoint.servicesQuietPrefixes == fixtureSnapshot.servicesQuietPrefixes
            && checkpoint.servicesQuietUntilMs == fixtureSnapshot.servicesQuietUntilMs
            && checkpointReplay == ":fixture NOTICE nick :first replay line");
    attachedCheckpoint.stream.close();
    auto complete = old.list();
    bool restored;
    if (complete.length == 1 && complete[0].hasMeta) {
        auto snapshot = fromJSON(complete[0].meta);
        restored = snapshot.wasConnected && snapshot.graceful && snapshot.connectedAtMs == 700
            && snapshot.sessionNick == "restored-nick" && snapshot.servicesLegacyAuthPending == 2
            && snapshot.servicesQuietPrefixes == fixtureSnapshot.servicesQuietPrefixes
            && snapshot.servicesQuietUntilMs == fixtureSnapshot.servicesQuietUntilMs;
    }
    checks ~= Ircv3Check("explicit full legacy LIST preserves restoration and strict services markers",
        lists == 2 && restored);
    complete = null;
    errorLegacy = true;
    bool errorDecoded;
    try old.scan();
    catch (HolderErrorException e) { errorDecoded = e.code == "busy" && e.msg == "already attached"; }
    checks ~= Ircv3Check("streamed ERR consumes unknown large subtrees and its terminator before throwing",
        errorDecoded && old.controlAlive && old.status().open == 1);
    foreach (kind; 1 .. 4) {
        sparseLegacy = kind;
        auto sparse = old.scan();
        checks ~= Ircv3Check("legacy identity scan consumes missing null and empty META with nullable wire fields "
                ~ kind.to!string,
            sparse.length == 1 && !sparse[0].hasMeta && sparse[0].id == "sparse"
                && sparse[0].tag.networkId.length == 0 && !sparse[0].tlsOk);
    }
    sparseLegacy = 0;

    EngineContext oldContext;
    oldContext.holder = old;
    foreach (firstFull; [false, true]) foreach (secondFull; [false, true]) {
        HolderListObservation a, b;
        failure = null;
        const before = lists;
        legacyGate = true;
        runTask({
            try a = acquireFreshHolderList(oldContext, firstFull);
            catch (Throwable e) failure = e;
        });
        foreach (_; 0 .. 1000) { if (legacyStarted > before) break; sleep(1.msecs); }
        runTask({
            try b = acquireFreshHolderList(oldContext, secondFull);
            catch (Throwable e) failure = e;
        });
        foreach (_; 0 .. 1000) {
            if (oldContext.holderListInFlight !is null && oldContext.holderListInFlight.readers == 2) break;
            sleep(1.msecs);
        }
        legacyGate = false;
        foreach (_; 0 .. 1000) { if (a !is null && b !is null || failure !is null) break; sleep(1.msecs); }
        if (failure !is null) throw failure;
        assert(a !is null && b !is null);
        auto evidence = a.identityEntries();
        const separate = !firstFull || (evidence[0].id.ptr != a.entries[0].id.ptr
            && evidence[0].tag.networkId.ptr != a.entries[0].tag.networkId.ptr
            && evidence[0].tls.cipher.ptr != a.entries[0].tls.cipher.ptr);
        checks ~= Ircv3Check("overlap retains first scan requirement and projects independent identity backing "
                ~ firstFull.to!string ~ "/" ~ secondFull.to!string,
            a is b && a.requireMeta == firstFull && lists == before + 1
                && a.entries[0].hasMeta == firstFull && !evidence[0].hasMeta && separate);
        // The captured identities intentionally outlive both observation leases.
        auto captured = ownedHolderIdentities(evidence);
        a.release();
        b.release();
        const beforeInfo = infos;
        HolderEntry recovered;
        infoGate = true;
        bool infoDone;
        runTask({
            try recovered = restorationEntry(old, captured[0]);
            catch (Throwable e) failure = e;
            infoDone = true;
        });
        foreach (_; 0 .. 1000) { if (infos > beforeInfo) break; sleep(1.msecs); }
        const graphReleased = a.entries.length == 0 && a.identities.length == 0;
        infoGate = false;
        foreach (_; 0 .. 1000) { if (infoDone) break; sleep(1.msecs); }
        if (failure !is null) throw failure;
        checks ~= Ircv3Check("delayed selected INFO after callback lease release preserves markers without another LIST "
                ~ firstFull.to!string ~ "/" ~ secondFull.to!string,
            graphReleased && infoDone && recovered.hasMeta && !captured[0].hasMeta
                && fromJSON(recovered.meta).servicesLegacyAuthPending == 2
                && lists == before + 1 && infos == beforeInfo + 1);
        recovered = HolderEntry.init;
        captured = null;
        evidence = null;
    }
    changedInfo = true;
    rejected = false;
    try restorationEntry(old, oldEntries[0]);
    catch (HolderUnavailableException) rejected = true;
    changedInfo = false;
    checks ~= Ircv3Check("selected INFO rejects a changed physical claim rather than adopting its META", rejected);

    foreach (mode; 1 .. 8) {
        invalidLegacy = mode;
        rejected = false;
        reverseEvidence = ["prior-physical-network"];
        string reason;
        const started = MonoTime.currTime;
        try withFreshHolderList(oldContext, (HolderEntry[] entries) { reverseEvidence = null; });
        catch (HolderUnavailableException e) { rejected = true; reason = e.msg; }
        const elapsed = MonoTime.currTime - started;
        checks ~= Ircv3Check("invalid framed legacy response preserves mirrors and invalidates control "
                ~ mode.to!string,
            rejected && !old.controlAlive && reverseEvidence == ["prior-physical-network"]
                && (mode != 4 || reason.canFind("exceeds receive limit"))
                && (mode != 5 || elapsed >= 9.seconds && elapsed < 12.seconds));
        foreach (_; 0 .. 2000) { if (old.controlAlive) break; sleep(1.msecs); }
    }
    return checks;
}
