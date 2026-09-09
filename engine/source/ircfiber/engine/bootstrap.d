module ircfiber.engine.bootstrap;

import std.process : environment;
import std.random : unpredictableSeed;
import std.conv : to;
import std.string : lastIndexOf;
import std.conv : to;
import std.datetime : Clock;
import std.algorithm : canFind, min;
import std.uuid : UUID;
import core.sys.posix.unistd : getpid;
import vibe.core.core : runTask, sleep, runApplication;
import vibe.core.channel : Channel, createChannel;
import ircfiber.logging : logJsonMap, logException, flushAndSendLogs;
import ircfiber.tracing : withSpan, flushAndSendSpans, Span, isTracingEnabled;
import ircfiber.observability : flushAndSendMetrics, recordGauge, isMetricsEnabled;
import ircfiber.db.circuit_breaker : exportMongoCircuitMetrics;
import vibe.core.log;
import core.time : seconds;
import ircfiber.build_info : buildInfo;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.irc.manager : ConnectionManager;
import ircfiber.irc.server : ConnectionServer;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.irc.engine_janitor : EngineJanitor, purgeLocalServerNamespace, bumpServerStateTTLs;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.user : UserRepository;
import ircfiber.db.messages : MessageRepository;
import ircfiber.redis.protocol : RedisKeys, StateTTL;
import ircfiber.engine.holder_client : HolderClient, HolderEntry, HolderUnavailableException;
import ircfiber.engine.session_snapshot : SessionSnapshot, fromJSON;

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
    Channel!IRCRawEvent eventChannel;
    /// Server registry.
    ServerRegistry serverRegistry;  // NEW
    /// This engine's server identity.
    ConnectionServer localServer;   // NEW: this engine's identity
    /// Client of this engine's connection holder (owns every IRC socket).
    HolderClient holder;
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
    size_t heldLive;
    try {
        foreach (e; holder.list()) if (e.state == "open") heldLive++;
    } catch (Exception e) {
        logWarn("Holder LIST failed at boot (%s) — assuming no live sessions", e.msg);
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
    auto eventChannel = createChannel!IRCRawEvent();
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
    // See startNetworkLoadingTask() called from runNormalEngineAfterBootstrap()
    // which runs the actual network load inside a runTask after runApplication().
    logInfo("Bootstrap: network loading deferred to event loop");

    return EngineContext(connManager, redis, bufferManager, messageRepo, networkRepo,
        eventChannel, serverRegistry, localServer, holder);
}

/// Load networks from MongoDB and start IRC clients.
/// Must be called from a runTask (the event loop must be running because
/// Redis operations need the event loop to process I/O).
void loadNetworks(ref EngineContext ctx) {
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
    if (ctx.holder !is null) {
        try heldAll = ctx.holder.list();
        catch (Exception e) logWarn("Network loading: holder LIST failed (%s) — dialing every network fresh", e.msg);
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
        if (nw.config.disabled) {
            skippedCount++;
            continue;
        }

        auto assignedServer = ctx.serverRegistry.getServerForNetwork(nw.config.id.toString());
        bool shouldLoad = false;

        if (assignedServer == serverId) {
            shouldLoad = true;
        } else if (assignedServer.length == 0) {
            const sid = ctx.serverRegistry.assignNetwork(nw.config.id.toString());
            if (sid.length == 0) {
                const allServers = ctx.serverRegistry.getAllServers();
                if (allServers.length == 0) {
                    logInfo("No servers registered yet — self-assigning %s (bootstrap race fix)",
                        nw.config.name);
                    try ctx.serverRegistry.selfAssignNetwork(nw.config.id.toString(), serverId);
                    catch (Exception e) {
                        logWarn("Self-assign failed for %s: %s", nw.config.name, e.msg);
                        continue;
                    }
                    shouldLoad = true;
                } else {
                    logWarn("Skipping network %s — no healthy connection server available", nw.config.name);
                    continue;
                }
            } else {
                shouldLoad = true;
            }
        } else {
            if (!ctx.serverRegistry.isServerHealthy(assignedServer)) {
                auto assignedCfg = ctx.serverRegistry.getEngineConfig(assignedServer);
                if (assignedCfg.priority > ctx.localServer.priority) {
                    logInfo("Network %s assigned to %s (priority %d > %d) — deferring reclaim",
                        nw.config.name, assignedServer, assignedCfg.priority, ctx.localServer.priority);
                } else {
                    logInfo("Reclaiming network %s from stale server %s", nw.config.name, assignedServer);
                    try {
                        ctx.serverRegistry.reassignNetwork(nw.config.id.toString());
                        shouldLoad = true;
                    } catch (Exception e) {
                        logWarn("Failed to reassign network %s: %s", nw.config.name, e.msg);
                    }
                }
            }
        }

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
                        try ctx.holder.close(e.id, "engine restarted"); catch (Exception ex) logWarn("holder CLOSE %s failed: %s", e.id, ex.msg);
                    }
                }
            }
            if (!attached) {
                ctx.connManager.addNetwork(nw.config, nw.userId);
                if (auto e = nid in held) if (e.state == "closed") {
                    // Dropped while no engine was reading: tell the user why
                    // before the fresh dial's timeline starts.
                    if (auto client = ctx.connManager.getClient(nw.config.id))
                        client.emitLog("warn", "Connection dropped while the engine was down: "
                            ~ (e.closeReason.length ? e.closeReason : "unknown reason"));
                    try ctx.holder.forget(e.id); catch (Exception ex) logWarn("holder FORGET %s failed: %s", e.id, ex.msg);
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
                ctx.holder.close(e.id, "network no longer assigned");
            } else {
                ctx.holder.forget(e.id);
            }
        } catch (Exception ex) {
            logWarn("Holder cleanup of %s failed: %s", e.id, ex.msg);
        }
    }

    if (orphanCount > 0) {
        logWarn("Network loading: skipped %d orphaned network(s) with no valid owner " ~
            "(disabled in MongoDB)", orphanCount);
    }
    logInfo("Network loading: loaded %d networks (attached=%d to held sessions, skipped=%d disabled)",
        loadedCount, attachedCount, skippedCount);

    ctx.connManager.startDeferredClients();
}

/// Start the network loading task. Called before runApplication() — all
/// runTask futures execute after the event loop starts, ensuring Redis
/// operations (SMEMBERS, HGET, HSET, SCAN) have I/O processing available.
void startNetworkLoadingTask(ref EngineContext ctx) {
    runTask(() nothrow {
        try {
            loadNetworks(ctx);
        } catch (Exception e) {
            logError("Network loading task failed: %s", e.msg);
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
        // Bootstrap drain recovery: on the first heartbeat cycle,
        // clear any stale draining flag that may have been left by a
        // previous instance of this server that crashed mid-drain.
        // We do this before the main loop so the gateway sees the
        // cleared state immediately, not 10s later.
        int beat = 0;
        bool firstCycle = true;
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
                // On the first cycle, explicitly clear stale draining.
                if (firstCycle) {
                    firstCycle = false;
                    try {
                        if (ctx.serverRegistry.isDraining(ctx.localServer.serverId)) {
                            logWarn("Bootstrap: found stale draining flag for server %s — clearing",
                                ctx.localServer.serverId);
                        }
                        ctx.serverRegistry.clearDraining(ctx.localServer.serverId);
                    } catch (Throwable e) {
                        string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                        try logWarn("Bootstrap: failed to check/clear draining: %s", m);
                        catch (Throwable) {}
                    }
                }

                ctx.localServer.lastHeartbeat = Clock.currTime.toUnixTime!long * 1000;
                ctx.serverRegistry.updateHeartbeat(ctx.localServer.serverId);
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
                // Ensure the local server struct never perpetuates a
                // draining state across heartbeats.
                ctx.localServer.draining = false;

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
                auto canonical = ctx.serverRegistry.getCanonicalNetworks(ctx.localServer.serverId);

                // Renew leases for networks still assigned to us.
                foreach (netId; canonical) {
                    try ctx.serverRegistry.renewLease(netId);
                    catch (Throwable) {}
                }


                // Reconcile connManager against canonical: add any
                // missing networks (load from Mongo if needed), remove
                // any networks that no longer belong to us.
                import std.algorithm : canFind, filter, map;
                import std.array : array;
                import std.uuid : UUID;
                auto currentNetIds = ctx.connManager.getNetworks()
                    .map!(n => n.config.id.toString()).array;

                // Guard: if canonical is empty but we have local networks,
                // this is likely a transient Redis wipe (assignments hash
                // evicted) — not a legitimate admin reassignment. Disconnecting
                // all networks would drop every IRC session. Instead, keep
                // the local networks and try to repopulate the canonical
                // hash from the local state so the next heartbeat recovers.
                if (canonical.length == 0 && currentNetIds.length > 0) {
                    auto allAssignments = ctx.serverRegistry.getAllAssignments();
                    if (allAssignments.length == 0) {
                        logError("CRITICAL: canonical empty (0) but local has %d networks and getAllAssignments also 0 — Redis wipe suspected, not disconnecting. Attempting to repopulate canonical from local state.", currentNetIds.length);
                        foreach (netId; currentNetIds) {
                            try {
                                ctx.serverRegistry.selfAssignNetwork(netId, ctx.localServer.serverId);
                                logInfo("Repopulated assignment %s -> %s from local state", netId, ctx.localServer.serverId);
                            } catch (Throwable e) {
                                string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                                try logError("Failed to repopulate %s: %s", netId, m);
                                catch (Throwable) {}
                            }
                        }
                        // Re-read canonical after repopulation
                        canonical = ctx.serverRegistry.getCanonicalNetworks(ctx.localServer.serverId);
                        if (canonical.length == 0) {
                            logWarn("Still 0 canonical after repopulation — skipping disconnect this cycle to avoid mass drop");
                            canonical = currentNetIds.dup;
                        }
                    } else {
                        logWarn("Canonical 0 but getAllAssignments has %d entries and local has %d — canonical may be stale, not disconnecting this cycle", allAssignments.length, currentNetIds.length);
                        canonical = allAssignments.filter!(na => na.serverId == ctx.localServer.serverId).map!(na => na.networkId).array;
                    }
                }

                // Disconnect networks no longer in canonical.
                foreach (netId; currentNetIds) {
                    if (!canFind(canonical, netId)) {
                        logWarn("Network %s no longer assigned to this server — disconnecting", netId);
                        try ctx.connManager.removeNetwork(UUID(netId));
                        catch (Throwable e) {
                            string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                            try logError("Failed to disconnect from stolen network %s: %s", netId, m);
                            catch (Throwable) {}
                        }
                    }
                }

                ctx.localServer.assignedNetworks = canonical;

                // Self-heal ghost "" entries.
                import std.algorithm : filter;
                import std.array : array;
                ctx.localServer.assignedNetworks = ctx.localServer.assignedNetworks
                    .filter!(n => n.length > 0)
                    .array;

                // Mirror assignedNetworks into a per-engine hash.
                try ctx.serverRegistry.publishServerAssignments(
                    ctx.localServer.serverId,
                    ctx.localServer.assignedNetworks);
                catch (Throwable) {}

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
                // Flush pending OTel spans / metrics / logs to the collector.
                // All three are nothrow and internally catch Throwable, so the
                // heartbeat fiber never dies on export failure.
                try flushAndSendSpans(); catch (Throwable) {}
                try exportMongoCircuitMetrics(); catch (Throwable) {}
                try flushAndSendMetrics(); catch (Throwable) {}
                try flushAndSendLogs(); catch (Throwable) {}
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
                    auto ownerId = ctx.connManager.getOwnerId(net.config.id);

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

                    // 1. Remove from connection manager — sends QUIT, closes socket
                    ctx.connManager.removeNetwork(net.config.id);

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
                        db.hdel(RedisKeys.networkAssignments(), netId);
                        db.del(RedisKeys.networkFail(netId));
                        db.del(RedisKeys.lease(netId));
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
