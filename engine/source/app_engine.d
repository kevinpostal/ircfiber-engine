module app_engine;

// Collect before transient roster/snapshot allocations consume the container
// ceiling. Embed this: vibe.d reparses raw argv and rejects --DRT-gcopt.
extern(C) __gshared string[] rt_options = ["gcopt=heapSizeFactor:1.2"];

import std.algorithm : canFind;
import std.conv : to;
import std.process : environment;
import std.string : toStringz, lastIndexOf;

import core.time : msecs, seconds;
import std.datetime : Clock;
import core.sys.posix.unistd : getpid;
import vibe.core.core : runTask, runApplication, sleep, yield;
import vibe.core.log;

import ircfiber.logging : logException, configureLogging, setLoggingEnabled, isLoggingEnabled;
import ircfiber.engine.bootstrap : bootstrapEngine, startHeartbeatTask,
    startOrphanReaperTask, startTelemetryFlushTask, loadNetworksWithRetry, refreshRoutingCapabilities, EngineContext;
import ircfiber.tracing : configureTracing,
    isEnvEnabled, setTracingEnabled, isTracingEnabled;
import ircfiber.observability : configureMetrics, setMetricsEnabled, isMetricsEnabled;
import ircfiber.engine.consumer : startControlConsumer, startCommandConsumers;
import ircfiber.engine.processor : startEventProcessor;
import ircfiber.engine.state : startStateSnapshotter, writeStateSnapshots;
import ircfiber.irc.connection : startDailyReachabilityRefresh;
import ircfiber.irc.services_registry : initializeServicesOperations;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.logging : logJsonMap;
import ircfiber.runtime_memory : RuntimeTelemetryCounters, sampleRuntimeMemory, logRuntimeMemorySample;
import ircfiber.term_signal : installTermSignalFlag, termSignal;
import vibe.core.core : exitEventLoop;
import core.sys.posix.signal : SIGTERM;
import ircfiber.engine.archive_spool : ArchiveSpoolStatus, ArchiveRecord;
import ircfiber.engine.archive_worker : ArchiveWorker;
import ircfiber.engine.archive_control : applyArchiveRedisPurge, stopArchive;
import ircfiber.runtime_memory : compactRuntimeMemorySample;
import ircfiber.runtime_diagnostic : DiagnosticStatus;
/// Global engine context shared across the process.
__gshared EngineContext g_ctx;

/// Configure OTel from env. Returns true if enabled.
private bool setupOtel(string svcName) {
    bool enabled = isEnvEnabled("IRCFIBER_OTEL_ENABLED");
    string raw = environment.get("IRCFIBER_OTEL_ENDPOINT", "");
    if (!enabled || raw.length == 0) {
        setTracingEnabled(false);
        setMetricsEnabled(false);
        setLoggingEnabled(false);
        logInfo("OTel disabled for %s (IRCFIBER_OTEL_ENABLED=%s, endpoint='%s')",
            svcName, enabled ? "1 (empty endpoint)" : "0", raw);
        return false;
    }
    string base = raw;
    if (base.length > 0 && base[$-1] == '/')
        base = base[0 .. $-1];
    string tracesEp;
    string metricsEp;
    string logsEp;
    if (base.canFind("/v1/traces")) {
        tracesEp = base;
    } else if (base.canFind("/v1/metrics")) {
        tracesEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/traces";
    } else if (base.canFind("/v1/logs")) {
        tracesEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/traces";
    } else {
        tracesEp = base ~ "/v1/traces";
    }
    if (base.canFind("/v1/metrics")) {
        metricsEp = base;
    } else if (base.canFind("/v1/traces")) {
        metricsEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/metrics";
    } else if (base.canFind("/v1/logs")) {
        metricsEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/metrics";
    } else {
        metricsEp = base ~ "/v1/metrics";
    }
    if (base.canFind("/v1/logs")) {
        logsEp = base;
    } else if (base.canFind("/v1/traces")) {
        logsEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/logs";
    } else if (base.canFind("/v1/metrics")) {
        logsEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/logs";
    } else {
        logsEp = base ~ "/v1/logs";
    }
    configureTracing(tracesEp, svcName, "0.3.0");
    configureMetrics(metricsEp, svcName, "0.3.0");
    configureLogging(logsEp, svcName, "0.3.0");
    // configure* sets enabled flag; be explicit for clarity.
    setTracingEnabled(true);
    setMetricsEnabled(true);
    setLoggingEnabled(true);
    logInfo("OTel enabled for %s: traces=%s metrics=%s logs=%s", svcName, tracesEp, metricsEp, logsEp);
    return true;
}

/// Configure Bugsink error reporting from env. Independent switch from
/// setupOtel() above — see ircfiber.errors module docs.
private bool setupBugsink(string svcName) {
    import ircfiber.errors : configureErrorReporting, setErrorReportingEnabled;
    bool enabled = isEnvEnabled("IRCFIBER_BUGSINK_ENABLED");
    string dsn = environment.get("IRCFIBER_BUGSINK_DSN", "");
    if (!enabled || dsn.length == 0) {
        setErrorReportingEnabled(false);
        logInfo("Bugsink disabled for %s (IRCFIBER_BUGSINK_ENABLED=%s, dsn set=%s)",
            svcName, enabled, dsn.length > 0);
        return false;
    }
    configureErrorReporting(dsn, svcName, "0.3.0", "production");
    setErrorReportingEnabled(true);
    logInfo("Bugsink enabled for %s", svcName);
    return true;
}

void main() {
    initializeServicesOperations();
    // Global crash handler: ensure buffered OTLP logs are shipped even if
    // the process terminates via an uncaught Throwable. vibe.d's event loop
    // normally swallows fiber exceptions, but a top-level Error (e.g.
    // AssertError from a data race) would otherwise kill the process with
    // pending logs still in queue.
    scope (failure) {
        try {
            import ircfiber.logging : flushAndSendLogs;
            import ircfiber.tracing : flushAndSendSpans;
            import ircfiber.observability : flushAndSendMetrics;
            try flushAndSendLogs(); catch (Throwable) {}
            try flushAndSendSpans(); catch (Throwable) {}
            try flushAndSendMetrics(); catch (Throwable) {}
        } catch (Throwable) {}
    }
    // ── Bootstrap ─────────────────────────────────────────────────
    // One startup path: read Mongo, connect the holder, attach any session
    // the holder kept across the restart (hot swap / crash), dial the rest.

    auto ctx = bootstrapEngine();
    g_ctx = ctx;

    // OTel must be configured AFTER bootstrap so any bootstrap failures
    // (Mongo/Redis unreachable) are still captured to stderr. bootstrap
    // itself does not emit OTLP — it only uses vibe.core.log which goes
    // to stderr unconditionally.
    try cast(void) setupOtel("ircfiber-engine");
    catch (Throwable e) {
        string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
        try logError("setupOtel failed: %s", m); catch (Throwable) {}
    }

    try cast(void) setupBugsink("ircfiber-engine");
    catch (Throwable e) {
        string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
        try logError("setupBugsink failed: %s", m); catch (Throwable) {}
    }

    // Write a fresh state snapshot immediately so the frontend sees the
    // current connection state (connecting) right away, rather than stale
    // data from before the restart. Without this, there is a window where
    // the frontend shows a "Reconnect" button even though the engine is
    // actively reconnecting.
    cast(void) writeStateSnapshots(ctx);

    // The main context outlives every client task. Prepare only fresh
    // producers; held ATTACH/readers never wait on archival Mongo I/O.
    if (ctx.archiveControl !is null) {
        ctx.connManager.prepareFreshArchiveScope = (string network, string owner) {
            return ctx.archiveControl.prepareScope(ctx, network, owner);
        };
    }

    // Register this server in the Redis registry. Must happen after
    // runApplication() starts the vibe.d event loop because Redis
    // hset/hget/sadd/smembers need the event loop to process I/O.
    // Deferred registration is set up in bootstrap.d; we finalize it here.
    runTask(() nothrow {
        try {
            logInfo("Registration task STARTING for server %s", ctx.localServer.serverId);
            refreshRoutingCapabilities(ctx);
            ctx.serverRegistry.registerServer(ctx.localServer);
            logInfo("Server registered via event loop: %s@%s",
                ctx.localServer.serverId, ctx.localServer.bindAddress);
            try {
                ctx.localServer.lastHeartbeat = Clock.currTime.toUnixTime!long * 1000;
                ctx.serverRegistry.updateHeartbeat(ctx.localServer.serverId);
            } catch (Throwable e) {
                string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                try logWarn("Initial heartbeat failed: %s", m); catch (Throwable) {}
            }
            loadNetworksWithRetry(ctx);
        } catch (Throwable e) {
            logException("registration", e, "Registration task failed");
        }
    });
    if (ctx.archiveSpool !is null && ctx.archiveControl !is null) {
        try {
            ctx.archiveWorker = new ArchiveWorker(ctx.archiveSpool, ctx.messageRepo,
                (ref const ArchiveRecord record) {
                    return applyArchiveRedisPurge(ctx, record);
                });
            ctx.archiveWorker.start();
            ctx.archiveControl.start(ctx);
        } catch (Throwable e) {
            ctx.localServer.archiveVersion = 0;
            logJsonMap("error", "engine", "Archive consumer unavailable; live sockets preserved",
                ["event":"archive_gap", "reason":"consumer_initialization_failed"]);
        }
    }
    startHeartbeatTask(ctx);
    startOrphanReaperTask(ctx);
    startTelemetryFlushTask();
    startRuntimeMemorySampler(ctx);
    startRetiredClientMaintenance(ctx);

    // Start the distributed EngineJanitor in the engine process too.
    // Each engine elects itself as janitor for ~lockTtl seconds; if the
    // gateway is offline, engines collectively keep the keyspace clean.
    {
        import ircfiber.irc.engine_janitor : EngineJanitor;
        auto janitor = new EngineJanitor(ctx.redis);
        janitor.start();
        logInfo("EngineJanitor: started in engine process");
    }

    auto runSafe = (void delegate() dg) {
        runTask(() nothrow {
            try {
                dg();
            } catch (Throwable e) {
                logException("runtime", e, "Task crashed");
            }
        });
    };

    runSafe({ try { startEventProcessor(ctx); }
              catch (Throwable e) { logException("event_processor", e, "Event processor crashed"); } });
    runSafe({ try { startControlConsumer(ctx); }
              catch (Throwable e) { logException("control_consumer", e, "Control consumer crashed"); } });
    runSafe({ try { startCommandConsumers(ctx); }
              catch (Throwable e) { logException("command_consumers", e, "Command consumers crashed"); } });
    runSafe({ try { startStateSnapshotter(ctx); }
              catch (Throwable e) { logException("state_snapshotter", e, "State snapshotter crashed"); } });
    runSafe({ try { startDailyReachabilityRefresh(); }
              catch (Throwable e) { logException("daily_reachability_refresh", e, "Daily reachability refresh crashed"); } });

    // ── Signals ─────────────────────────────────────────────────────
    // SIGTERM = hot swap: detach every session (META + close the relay,
    // no QUIT), keep the registry entry, exit. The next engine attaches
    // to the same sockets. Docker/k8s send SIGTERM on stop/recreate.
    // SIGINT = decommission: the classic path below QUITs every network,
    // publishes irc:shutdown and unregisters so other engines take over.
    // Both run inside the event loop (vibe's default handler would exit
    // the loop first and I/O after runApplication() is not reliable).
    installTermSignalFlag();
    bool detachedForHotSwap = false;
    bool decommissioned = false;
    runTask(() nothrow {
        while (termSignal() == 0) {
            try sleep(100.msecs); catch (Exception) {}
        }
        const signo = termSignal();
        if (signo == SIGTERM) {
            try {
                logJsonMap("info", "engine", "SIGTERM — hot swap: detaching sessions into the holder",
                    ["server": ctx.localServer.serverId, "event": "hotswap_begin"]);
                try ctx.serverRegistry.markHotSwap(ctx.localServer.serverId);
                catch (Exception e) logWarn("markHotSwap failed: %s", e.msg);
                ctx.connManager.detachAllForHotSwap();
                detachedForHotSwap = true;
                logJsonMap("info", "engine", "Hot swap detach complete — exiting",
                    ["server": ctx.localServer.serverId, "event": "hotswap_detached"]);
            } catch (Throwable e) {
                string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                try logError("Hot swap detach failed: %s — exiting anyway (holder keeps the sockets)", m);
                catch (Throwable) {}
                detachedForHotSwap = true;
            }
        } else {
            try logJsonMap("info", "engine", "SIGINT — decommission: QUIT every network and unregister",
                ["server": ctx.localServer.serverId, "event": "decommission_begin"]);
            catch (Throwable) {}
            try decommission(ctx);
            catch (Throwable e) {
                string m; try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                try logError("Decommission failed: %s", m); catch (Throwable) {}
            }
            decommissioned = true;
        }
        try stopArchive(ctx);
        catch (Throwable) {
            try logJsonMap("error", "engine", "Archive shutdown unavailable",
                ["event":"archive_shutdown_unclean"]); catch (Throwable) {}
        }
        exitEventLoop();
    });

    logInfo("IRC Fiber Engine (Decentralized) running on server=%s", ctx.localServer.serverId);
    runApplication();

    if (detachedForHotSwap) {
        // Assignments and lease stay: the new engine reclaims them as
        // `assignedServer == serverId`; the registry keeps us "healthy"
        // for HOTSWAP_GRACE_MS so nothing gets reassigned mid-swap.
        logInfo("IRC Fiber Engine hot-swap exit complete (sessions held by the holder)");
        return;
    }
    // Natural loop exit without a signal: same decommission, best effort
    // (the upstream sockets are the holder's; CLOSEs may not complete
    // without the loop — the holder's detach timeout covers the rest).
    if (!decommissioned) decommission(ctx);
    logInfo("IRC Fiber Engine shutdown complete");
}

private bool retiredMaintenanceRunning;

/// Reclamation must progress even when Redis heartbeat/export tasks fail.
private void startRetiredClientMaintenance(ref EngineContext ctx) {
    if (retiredMaintenanceRunning) return;
    retiredMaintenanceRunning = true;
    try {
        runTask(() nothrow {
            scope(exit) retiredMaintenanceRunning = false;
            while (termSignal() == 0) {
                try {
                    ctx.connManager.reapRetiredClients(Clock.currTime.toUnixTime!long * 1000);
                } catch (Throwable) {
                    try logJsonMap("warn", "engine", "Retired ownership maintenance unavailable",
                        ["event": "retired_maintenance_failed"]);
                    catch (Throwable) {}
                }
                try sleep(10.seconds); catch (Throwable) {}
            }
        });
    } catch (Throwable error) {
        retiredMaintenanceRunning = false;
        throw error;
    }
}

private bool memorySamplerRunning;

/// One local sampler, independent of Redis, collector health and OTLP enablement.
/// No snapshot serialization, forced collection, disk writes or gateway pools.
private void startRuntimeMemorySampler(ref EngineContext ctx) {
    if (memorySamplerRunning) return;
    memorySamplerRunning = true;
    try {
        runTask(() nothrow {
            scope(exit) memorySamplerRunning = false;
            while (true) {
                try {
                    auto sample = sampleRuntimeMemory();
                    if (ctx.connManager !is null) {
                        const counters = ctx.connManager.memoryCounters();
                        sample.ownersAvailable = true;
                        static foreach (i; 0 .. typeof(sample.owners).tupleof.length) {
                            sample.owners.tupleof[i] = __traits(getMember, counters,
                                __traits(identifier, typeof(sample.owners).tupleof[i]));
                        }
                        sample.largestNetworkCount = counters.largestNetworkCount < 5 ? counters.largestNetworkCount : 5;
                        foreach (i; 0 .. sample.largestNetworkCount) {
                            sample.largestNetworks[i].networkId = counters.largestNetworks[i].networkId;
                            sample.largestNetworks[i].identities = counters.largestNetworks[i].identities;
                            sample.largestNetworks[i].members = counters.largestNetworks[i].members;
                        }
                    }
                    ArchiveSpoolStatus archive;
                    if (ctx.archiveSpool !is null && ctx.archiveSpool.tryStatus(archive)) {
                        sample.archive.available = true;
                        sample.archive.ready = archive.ready;
                        sample.archive.failed = archive.failed;
                        sample.archive.stopping = archive.stopping;
                        sample.archive.replayInFlight = archive.replayInFlight;
                        sample.archive.ingressCommands = archive.ingressCommands;
                        sample.archive.ingressBytes = archive.ingressBytes;
                        sample.archive.pendingOperations = archive.pendingOperations;
                        sample.archive.pendingBytes = archive.pendingBytes;
                        sample.archive.checkpoint = archive.checkpoint;
                        sample.archive.durableSequence = archive.durableSequence;
                        sample.archive.gapCount = archive.gapCount;
                        sample.archive.sampledAtMs = archive.sampledAtMs;
                        sample.archive.diskBytesKnown = archive.diskBytesKnown;
                        sample.archive.freeBytesKnown = archive.freeBytesKnown;
                        sample.archive.diskBytes = archive.diskBytes;
                        sample.archive.maxBytes = archive.maxBytes;
                        sample.archive.minFreeBytes = archive.minFreeBytes;
                        sample.archive.freeBytes = archive.freeBytes;
                        sample.archive.controlReserveBytes = archive.controlReserveBytes;
                        sample.archive.stateReserveBytes = archive.stateReserveBytes;
                        sample.archive.diskSampledAtMs = archive.diskSampledAtMs;
                        sample.archive.diskThreads = archive.diskThreads;
                        sample.archive.consumerFibers = ctx.archiveWorker is null
                            ? 0 : ctx.archiveWorker.activeConsumerFibers();
                    }
                    DiagnosticStatus diagnostic;
                    if (ctx.runtimeDiagnostics !is null && ctx.runtimeDiagnostics.tryStatus(diagnostic)) {
                        sample.diagnosticFile.available = true;
                        sample.diagnosticFile.lastWrittenAtMs = diagnostic.lastWrittenAtMs;
                        sample.diagnosticFile.pendingBytes = diagnostic.pendingBytes;
                        sample.diagnosticFile.inFlightBytes = diagnostic.inFlightBytes;
                        sample.diagnosticFile.failures = diagnostic.failures;
                        sample.diagnosticFile.lastResult = diagnostic.lastResult.to!string;
                    }
                    import ircfiber.observability : sampleMetricsQueue, METRICS_MAX_POINTS, METRICS_MAX_BYTES;
                    import ircfiber.tracing : sampleTracingQueue, TRACING_MAX_SPANS, TRACING_MAX_BYTES;
                    import ircfiber.logging : sampleLoggingQueue, LOGGING_MAX_ENTRIES, LOGGING_MAX_BYTES;
                    sample.metrics = runtimeQueueCounters(sampleMetricsQueue(), METRICS_MAX_POINTS, METRICS_MAX_BYTES);
                    sample.tracing = runtimeQueueCounters(sampleTracingQueue(), TRACING_MAX_SPANS, TRACING_MAX_BYTES);
                    sample.logging = runtimeQueueCounters(sampleLoggingQueue(), LOGGING_MAX_ENTRIES, LOGGING_MAX_BYTES);
                    logRuntimeMemorySample(sample, "engine");
                    if (ctx.runtimeDiagnostics !is null)
                        ctx.runtimeDiagnostics.tryPublish(compactRuntimeMemorySample(sample));
                } catch (Throwable e) {
                    // A bad sample must not terminate future observation. Do not
                    // use logException: its immediate network export can stall
                    // local sampling behind a failed collector.
                    try logJsonMap("warn", "engine", "Runtime memory sample unavailable",
                        ["event": "memory_sample_failed"]);
                    catch (Throwable) {}
                }
                try sleep(30.seconds); catch (Throwable) {}
            }
        });
    } catch (Throwable e) {
        memorySamplerRunning = false;
        throw e;
    }
}

private RuntimeTelemetryCounters runtimeQueueCounters(T)(const T queue, ulong maxCount, ulong maxBytes) {
    return RuntimeTelemetryCounters(queue.count, queue.bytes, queue.droppedCount,
        queue.droppedBytes, maxCount, maxBytes, true, queue.lastExportSuccessAtMs);
}

/// QUIT every network (closing their upstream sockets in the holder),
/// publish `irc:shutdown` so the gateway reassigns instantly, and
/// unregister (cleans the Redis server hash, the server list and the
/// leases). Runs inside the event loop from the SIGINT watcher.
private void decommission(ref EngineContext ctx) {
    ctx.connManager.shutdown();
    if (ctx.redis && ctx.localServer.serverId.length > 0) {
        try {
            ctx.redis.publish(
                RedisKeys.shutdownChannel(),
                ctx.localServer.serverId
            );
            logInfo("Published shutdown for server %s", ctx.localServer.serverId);
        } catch (Exception e) {
            logWarn("Failed to publish shutdown: %s", e.msg);
        }
    }
    if (ctx.serverRegistry && ctx.localServer.serverId.length > 0) {
        ctx.serverRegistry.unregisterServer(ctx.localServer.serverId);
    }
}

