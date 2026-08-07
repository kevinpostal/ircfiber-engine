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
import ircfiber.logging : logJsonMap, logException;
import ircfiber.tracing : withSpan, flushAndSendSpans, Span, isTracingEnabled;
import ircfiber.observability : flushAndSendMetrics, recordGauge, isMetricsEnabled;
import ircfiber.db.circuit_breaker : exportMongoCircuitMetrics;
import vibe.core.log;
import core.time : seconds;

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
    }
    // During handoff boot, the new engine doesn't need Mongo — it
    // adopts live connections from the old engine. The 30-second
    // retry delay would cause the handoff protocol to time out.
    // We try once and warn on failure instead.
    if (environment.get("IRCFIBER_RELOAD_FROM_PID", "").length > 0) {
        try {
            AppMongoConnection.connect(mongoUrl, mongoDbName);
            logInfo("MongoDB connected during handoff boot");
        } catch (Exception e) {
            logWarn("MongoDB not available during handoff: %s — proceeding without persistence", e.msg);
        }
    } else {
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

    // ── Bootstrap-time namespace purge (Layer 3) ─────────────────
    // Wipes `*:<serverId>:*` keys + companion keys before this engine
    // registers itself. Prevents "same serverId, new epoch" from inheriting
    // 40+ fossilized keys from a prior boot (the exact failure mode that
    // built up testengine1's garbage pile on Jun 22).
    //
    // Skipped on handoff boots (`IRCFIBER_RELOAD_FROM_PID` set) so
    // adopted sockets keep their state.
    // Override with IRCFIBER_BOOTSTRAP_PURGE=0 to disable (debugging).
    if (environment.get("IRCFIBER_RELOAD_FROM_PID", "").length == 0) {
        const purgeEnv = environment.get("IRCFIBER_BOOTSTRAP_PURGE", "1");
        if (purgeEnv != "0" && purgeEnv != "false") {
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
    auto connManager = new ConnectionManager(eventChannel, redis, serverId);
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
        eventChannel, serverRegistry, localServer);
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

    int loadedCount = 0;
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
            ctx.connManager.addNetwork(nw.config, nw.userId);
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

    if (orphanCount > 0) {
        logWarn("Network loading: skipped %d orphaned network(s) with no valid owner " ~
            "(disabled in MongoDB)", orphanCount);
    }
    logInfo("Network loading: loaded %d networks (skipped=%d disabled)", loadedCount, skippedCount);

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
        // previous instance of this server that crashed mid-handoff.
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
                    } catch (Exception e) {
                        logWarn("Bootstrap: failed to check/clear draining: %s", e.msg);
                    }
                }

                ctx.serverRegistry.updateHeartbeat(ctx.localServer.serverId);

                // Layer 1: TTL bump. Extend the lifetime of every state
                // key (irc:state, scrollback, dedup) so a dead engine
                // self-evicts within STATE_TTL even without a janitor.
                // Read TTL from env at startup; configurable per-deployment.
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
                    } catch (Exception e) {
                        logDebug("Heartbeat: TTL bump failed: %s", e.msg);
                    }
                }

                // Ensure the local server struct never perpetuates a
                // draining state across heartbeats — the heartbeat is
                // the signal that draining has ended.
                ctx.localServer.draining = false;

                // Surface per-network registration-timeout markers so the
                // admin SPA can show "Registration timeout for 47s on
                // irc.gangnet.org" with the actual reason, rather than
                // a generic "Connecting..." that operators have to grep
                // logs to diagnose. RFC 2812 §2.3 says "it is not advised
                // to wait forever for the reply"; when the engine
                // enforces that and the server never replied, the network
                // gets a per-network stuck marker.
                ctx.localServer.registrationUnavailableFor =
                    ctx.connManager.networksAwaitingRegistration();
                recordGauge(
                    "ircfiber.registration.timeout_networks",
                    cast(long)ctx.localServer.registrationUnavailableFor.length,
                    ["serverId":   ctx.localServer.serverId]);
                ctx.serverRegistry.syncServerState(ctx.localServer.serverId, ctx.localServer);

                // Read canonical assignments from irc:assignments (the
                // gateway's source of truth). This is the authoritative
                // list of networks this server should be connected to.
                auto canonical = ctx.serverRegistry.getCanonicalNetworks(ctx.localServer.serverId);

                // Renew leases for networks still assigned to us. The
                // gateway detects orphaned engines via lease expiry.
                foreach (netId; canonical) {
                    ctx.serverRegistry.renewLease(netId);
                }

                // Reconcile connManager against canonical: add any
                // missing networks (load from Mongo if needed), remove
                // any networks that no longer belong to us.
                import std.algorithm : canFind, map;
                import std.array : array;
                import std.uuid : UUID;
                auto currentNetIds = ctx.connManager.getNetworks()
                    .map!(n => n.config.id.toString()).array;

                // Disconnect networks no longer in canonical.
                foreach (netId; currentNetIds) {
                    if (!canFind(canonical, netId)) {
                        logWarn("Network %s no longer assigned to this server — disconnecting", netId);
                        try ctx.connManager.removeNetwork(UUID(netId));
                        catch (Exception e) {
                            logError("Failed to disconnect from stolen network %s: %s", netId, e.msg);
                        }
                    }
                }

                // Authoritative source for assignedNetworks: the canonical
                // hash. This avoids the race where the engine's local view
                // (connManager) is briefly out of sync with Redis, which
                // used to cause spurious "no longer assigned" disconnects.
                ctx.localServer.assignedNetworks = canonical;

                // Self-heal: a past bug could leave the engine's
                // assignedNetworks array holding a ghost "" entry that
                // survived every heartbeat because the per-engine mirror
                // and the canonical irc:assignments hash were both clean.
                // Strip empty ids so the engine's in-memory + Redis state
                // matches canonical. A second syncServerState() below
                // re-persists the cleaned value to the server record;
                // the first syncServerState() (earlier in this loop)
                // wrote whatever localServer had at that point.
                import std.algorithm : filter;
                import std.array : array;
                ctx.localServer.assignedNetworks = ctx.localServer.assignedNetworks
                    .filter!(n => n.length > 0)
                    .array;

                // Mirror assignedNetworks into a per-engine hash so
                // getAllAssignments() can recover if `irc:assignments` is
                // evicted. Keyed by serverId to avoid collision between
                // engines; deleted on graceful shutdown via
                // unregisterServer(). Empty ids are filtered inside
                // publishServerAssignments() as a second line of defence.
                ctx.serverRegistry.publishServerAssignments(
                    ctx.localServer.serverId,
                    ctx.localServer.assignedNetworks);

                // Persist the now-clean assignedNetworks back to the
                // server record. The earlier syncServerState() call
                // (above) wrote whatever localServer had — which on the
                // first heartbeat after a legacy deploy could include a
                // ghost "" entry from the orphan-empty-string bug. This
                // second write ensures the server record on Redis is
                // scrubbed on the very first cycle, not the second.
                ctx.serverRegistry.syncServerState(
                    ctx.localServer.serverId, ctx.localServer);

                // Re-read engine config from Redis so admin changes to
                // priority, maxConnections, or fallbackOnly take effect
                // within ~10 seconds without an engine restart.
                try {
                    auto cfg = ctx.serverRegistry.getEngineConfig(ctx.localServer.serverId);
                    if (cfg.priority != 0) ctx.localServer.priority = cfg.priority;
                    if (cfg.maxConnections != 0) ctx.localServer.maxConnections = cfg.maxConnections;
                    ctx.localServer.fallbackOnly = cfg.fallbackOnly;
                } catch (Exception) { }

                // Downgraded from logInfo to debug — 10s cadence was flooding SigNoz logs
                // (8640 entries/day per engine). Heartbeat health is visible via
                // Redis TTL + engine.heartbeat span; info logging is redundant.
                logDebug("Heartbeat sent for server %s", ctx.localServer.serverId);
                // Shows the number of healthy, registered networks plus
                // server load, so the Distributed Traces view always has
                // fresh data with actual metrics (not just "up=1").
                // Guarded by isTracingEnabled() to avoid allocating a
                // span when OTel is disabled (withSpan itself is no-op,
                // but the guard saves the attrs array alloc).
                if (isTracingEnabled() && beat++ % 6 == 0) {
                    withSpan("engine.heartbeat", ["serverId": ctx.localServer.serverId], (ref Span s) {
                        s.attr("healthy", "1");
                        s.setStatusOk();
                    });
                } else if (!isTracingEnabled()) {
                    beat++;
                }
                // Flush pending OTel spans collected from connection
                // lifecycle events (register, disconnect, reconnect)
                // and any HTTP gateway spans that trickled in.
                // Flush pending OTel spans to the otel-collector.
                flushAndSendSpans();
                // Flush OTel metrics counters / gauges / histograms
                // recorded by connection.d (reconnect, ghost, registration
                // timeout) and the heartbeat
                // (registration.timeout_networks gauge). Same 10s cadence
                // as the trace flush — every dashboard panel sees a
                // fresh data point at the same wall-clock boundary.
                exportMongoCircuitMetrics();
                flushAndSendMetrics();
                // Cycle succeeded — clear backoff so the next failure
                // starts from the short end of the curve again.
                backoffMs = 0;
            } catch (Exception e) {
                logError("Heartbeat failed: %s", e.msg);
                // Exponential backoff: 1s, 2s, 4s, ... capped at 60s.
                // Doubles on each consecutive failure; reset to 0 on
                // success above. Without this backoff a Redis outage
                // pegs the engine at 100% CPU retrying the same
                // throw on every iteration of `while (true)`.
                if (backoffMs == 0) backoffMs = 1_000;
                else backoffMs = min(backoffMs * 2, 60_000L);
                try sleep(backoffMs.msecs);
                catch (Exception) { /* nothrow lambda — swallow */ }
                continue;
            }
            // Normal cadence — only when the try block completed
            // without throwing. The catch branch above uses `continue`
            // to skip this sleep and instead applies its own backoff.
            try sleep(10.seconds);
            catch (Exception) { /* nothrow lambda — swallow */ }
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
