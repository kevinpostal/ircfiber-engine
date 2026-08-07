module app_engine;

import std.algorithm : canFind;
import std.conv : to;
import std.process : environment;
import std.string : toStringz, lastIndexOf;

import core.time : msecs, seconds;
import core.sys.posix.unistd : getpid;
import vibe.core.core : runTask, runApplication, sleep, yield;
import vibe.core.log;

import ircfiber.logging : logException;
import ircfiber.engine.bootstrap : bootstrapEngine, startHeartbeatTask, startOrphanReaperTask, loadNetworks, EngineContext;
import ircfiber.tracing : configureTracing, startTracingExporter,
    isEnvEnabled, setTracingEnabled, isTracingEnabled;
import ircfiber.observability : configureMetrics, setMetricsEnabled, isMetricsEnabled;
import ircfiber.engine.consumer : startControlConsumer, startCommandConsumers,
    setHandoffCallback, consumeHandoffRequest;
import ircfiber.engine.processor : startEventProcessor;
import ircfiber.engine.reload_orchestrator : adoptFromOldEngine, serveReload, ReloadResult;
import ircfiber.engine.state : startStateSnapshotter, writeStateSnapshots;
import ircfiber.engine.handoff : handoffSocketPath;
import ircfiber.redis.protocol : RedisKeys;
__gshared EngineContext g_ctx;

/// Configure OTel from env. Returns true if enabled.
private bool setupOtel(string svcName) {
    bool enabled = isEnvEnabled("IRCFIBER_OTEL_ENABLED");
    string raw = environment.get("IRCFIBER_OTEL_ENDPOINT", "");
    if (!enabled || raw.length == 0) {
        setTracingEnabled(false);
        setMetricsEnabled(false);
        logInfo("OTel disabled for %s (IRCFIBER_OTEL_ENABLED=%s, endpoint='%s')",
            svcName, enabled ? "1 (empty endpoint)" : "0", raw);
        return false;
    }
    string base = raw;
    if (base.length > 0 && base[$-1] == '/')
        base = base[0 .. $-1];
    string tracesEp;
    string metricsEp;
    if (base.canFind("/v1/traces")) {
        tracesEp = base;
    } else if (base.canFind("/v1/metrics")) {
        tracesEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/traces";
    } else {
        tracesEp = base ~ "/v1/traces";
    }
    if (base.canFind("/v1/metrics")) {
        metricsEp = base;
    } else if (base.canFind("/v1/traces")) {
        metricsEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/metrics";
    } else {
        metricsEp = base ~ "/v1/metrics";
    }
    configureTracing(tracesEp, svcName, "0.3.0");
    configureMetrics(metricsEp, svcName, "0.3.0");
    // configure* sets enabled flag; be explicit for clarity.
    setTracingEnabled(true);
    setMetricsEnabled(true);
    startTracingExporter();
    logInfo("OTel enabled for %s: traces=%s metrics=%s", svcName, tracesEp, metricsEp);
    return true;
}

void main() {
    // ── Bootstrap ─────────────────────────────────────────────────
    // Three startup paths:
    //   1. Fresh boot — read Mongo, start consumers, run normally.
    //   2. Handoff    — IRCFIBER_RELOAD_FROM_PID is set; connect to
    //                   the old engine's handoff socket, adopt live
    //                   connections, then run normally.
    //   3. Exec-reload — IRCFIBER_EXEC_RELOAD_ACTIVE is set; we were
    //                   just exec(2)'d from an old engine. The IRC TCP
    //                   socket FDs are inherited (because we cleared
    //                   O_CLOEXEC before exec). Read the checkpoint
    //                   file, adopt each FD via adoptExecSocket (which
    //                   does a fresh TLS handshake for TLS connections),
    //                   then continue as a normal engine.
    string reloadFrom = environment.get("IRCFIBER_RELOAD_FROM_PID", "");
    if (reloadFrom.length > 0) {
        runHandoffEngine(reloadFrom);
        return;
    }
    if (environment.get("IRCFIBER_EXEC_RELOAD_ACTIVE", "") == "1") {
        runExecReloadEngine();
        return;
    }

    auto ctx = bootstrapEngine();
    g_ctx = ctx;

    setupOtel("ircfiber-engine");

    // Write a fresh state snapshot immediately so the frontend sees the
    // current connection state (connecting) right away, rather than stale
    // data from before the restart. Without this, there is a window where
    // the frontend shows a "Reconnect" button even though the engine is
    // actively reconnecting.
    writeStateSnapshots(ctx);

    // Register this server in the Redis registry. Must happen after
    // runApplication() starts the vibe.d event loop because Redis
    // hset/hget/sadd/smembers need the event loop to process I/O.
    // Deferred registration is set up in bootstrap.d; we finalize it here.
    runTask(() nothrow {
        try {
            logInfo("Registration task STARTING for server %s", ctx.localServer.serverId);
            ctx.serverRegistry.registerServer(ctx.localServer);
            logInfo("Server registered via event loop: %s@%s",
                ctx.localServer.serverId, ctx.localServer.bindAddress);
            try {
                ctx.serverRegistry.updateHeartbeat(ctx.localServer.serverId);
            } catch (Exception e) {
                logWarn("Initial heartbeat failed: %s", e.msg);
            }
            // Load networks here — runs after registration but inside the same
            // task so Redis operations (HGET, SMEMBERS, HSET) are not concurrent
            // with the heartbeat task. On Linux (epoll driver), concurrent Redis
            // operations from different tasks can cause fiber scheduling issues
            // that hang SMEMBERS/SCAN responses.
            loadNetworks(ctx);
        } catch (Exception e) {
            logError("Registration task failed: %s", e.msg);
        }
    });
    startHeartbeatTask(ctx);
    startOrphanReaperTask(ctx);

    // Start the distributed EngineJanitor in the engine process too.
    // Each engine elects itself as janitor for ~lockTtl seconds; if the
    // gateway is offline, engines collectively keep the keyspace clean.
    {
        import ircfiber.irc.engine_janitor : EngineJanitor;
        auto janitor = new EngineJanitor(ctx.redis);
        janitor.start();
        logInfo("EngineJanitor: started in engine process");
    }

    // Register the handoff callback. The control consumer (started
    // below) will invoke it when a `gracefulReload` message arrives.
    setHandoffCallback(() => performHandoff());

    auto runSafe = (void delegate() dg) {
        runTask(() nothrow {
            try {
                dg();
            } catch (Exception e) {
                // logException captures e.toString() + D stack trace.
                logException("runtime", e, "Task crashed");
            }
        });
    };

    runSafe({ try { startEventProcessor(ctx); }
              catch (Exception e) { logException("event_processor", e, "Event processor crashed"); } });
    runSafe({ try { startControlConsumer(ctx); }
              catch (Exception e) { logException("control_consumer", e, "Control consumer crashed"); } });
    runSafe({ try { startCommandConsumers(ctx); }
              catch (Exception e) { logException("command_consumers", e, "Command consumers crashed"); } });
    runSafe({ try { startStateSnapshotter(ctx); }
              catch (Exception e) { logException("state_snapshotter", e, "State snapshotter crashed"); } });

    logInfo("IRC Fiber Engine (Decentralized) running on server=%s", ctx.localServer.serverId);
    runApplication();

    ctx.connManager.shutdown();

    // Publish shutdown announcement so the gateway reassigns
    // our networks instantly (no lease expiry delay).
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

    // Unregister on shutdown — cleans Redis server hash, removes
    // from server list, and reassigns networks. Also cleans up
    // lease keys (by deleting the server, which Phase 2 detects,
    // and the leases expire within LEASE_TTL_SECONDS).
    if (ctx.serverRegistry && ctx.localServer.serverId.length > 0) {
        ctx.serverRegistry.unregisterServer(ctx.localServer.serverId);
    }
    logInfo("IRC Fiber Engine shutdown complete");
}

/// Boot path #2: this engine is the *new* one. Don't read Mongo or
/// start any clients — instead, connect to the old engine's
/// handoff socket and adopt the live IRC connections. After that
/// completes, behave like a normal engine (heartbeat, snapshots,
/// consumers) but skip the Mongo load.
private void runHandoffEngine(string oldPidStr) {
    logInfo("Handoff boot: old engine pid=%s", oldPidStr);
    int oldPid;
    try { oldPid = to!int(oldPidStr); }
    catch (Exception e) {
        logError("Invalid IRCFIBER_RELOAD_FROM_PID='%s': %s", oldPidStr, e.msg);
        return;
    }
    // First run a normal bootstrap (so we have a ConnectionManager,
    // Redis, Mongo, server registry). The bootstrap skips loading
    // assigned networks because we will adopt them in a moment.
    auto ctx = bootstrapEngine();
    g_ctx = ctx;
    ctx.localServer.serverId = environment.get("IRCFIBER_SERVER_ID", "hfover");

    setupOtel("ircfiber-engine");
    writeStateSnapshots(ctx);
    startHeartbeatTask(ctx);
    // Start orphan reaper for the handoff path too — adopted connections
    // from the old engine may include orphans. The reaper waits 60s
    // before its first check, giving the adoption time to settle.
    startOrphanReaperTask(ctx);
    setHandoffCallback(() => performHandoff());

    // Adopt from the old engine.
    string socketPath = handoffSocketPath(ctx.localServer.serverId);
    ReloadResult result;
    try {
        result = adoptFromOldEngine(ctx.connManager, socketPath);
    } catch (Exception e) {
        logError("Handoff adoption failed: %s — falling back to fresh boot", e.msg);
        // Clear any stale draining state left by the old engine.
        // If the old engine's serveReload() partially executed and
        // called markDraining() before the socket broke, the draining
        // flag would persist forever because this new engine never
        // starts its event loop (we return without runApplication()).
        try {
            ctx.serverRegistry.clearDraining(ctx.localServer.serverId);
            logInfo("Cleared draining state for %s after failed handoff", ctx.localServer.serverId);
        } catch (Exception e2) {
            logWarn("Failed to clear draining after handoff failure: %s", e2.msg);
        }
        return;
    }
    logInfo("Handoff: %d plain + %d tls adopted in %d ms",
        result.plainCount, result.tlsCount, result.durationMs);

    // Write our PID to the canonical pidfile so the supervisor
    // picks up the right engine after the old one exits. Without
    // this, the supervisor's pidfile still points to the old engine
    // and the heartbeat check fails.
    import std.stdio : File;
    try {
        auto f = File("/tmp/irc-fiber-engine.pid", "w");
        f.write(getpid());
        f.close();
        logInfo("Handoff: wrote PID %d to /tmp/irc-fiber-engine.pid", getpid());
    } catch (Exception e) {
        logWarn("Handoff: failed to write PID file: %s", e.msg);
    }

    // Persist handoff metrics to Redis so the gateway's admin
    // endpoint can return them.
    import std.datetime : Clock;
    try {
        import vibe.data.json : Json;
        auto info = Json.emptyObject;
        info["elapsedMs"] = Json(result.durationMs);
        info["plainCount"] = Json(result.plainCount);
        info["tlsCount"] = Json(result.tlsCount);
        info["timestamp"] = Json(Clock.currTime.toISOExtString());
        auto db = ctx.redis.getDb();
        db.hset("ircfiber:handoff:last", "info", info.toString());
        db.hset("ircfiber:handoff:last", "serverId", ctx.localServer.serverId);
        db.hset("ircfiber:handoff:last", "timestamp", Clock.currTime.toUnixTime!long.to!string);
        logInfo("Handoff: metrics stored in Redis");
    } catch (Exception e) {
        logWarn("Handoff: failed to store metrics: %s", e.msg);
    }

    // ⚠ Supervisor race note:
    // After a successful handoff, the old engine exits cleanly (rc=0).
    // The supervisor sees rc=0 as "clean stop" -> resets backoff ->
    // respawns with the *new* binary. But we (the new engine) are
    // already running with the old engine's serverId. The supervisor's
    // respawn will try to register the same serverId, which should
    // be harmless (the second process will see the existing heartbeat
    // on that serverId and exit/back off). Production: consider a
    // one-shot `IRCFIBER_IS_HANDOFF_CHILD=1` flag that tells the
    // new engine to write its pid to the supervisor's pidfile, so
    // the supervisor detects the new PID on the next health check.

    // Now start the standard consumers/snapshotter. Note we don't
    // call bootstrapEngine() again — that would re-load Mongo.
    auto runSafe = (void delegate() dg) {
        runTask(() nothrow {
            try { dg(); }
            catch (Exception e) { logException("runtime", e, "Task crashed"); }
        });
    };
    runSafe({ try { startEventProcessor(ctx); }
              catch (Exception e) { logException("event_processor", e, "Event processor crashed"); } });
    runSafe({ try { startControlConsumer(ctx); }
              catch (Exception e) { logException("control_consumer", e, "Control consumer crashed"); } });
    runSafe({ try { startCommandConsumers(ctx); }
              catch (Exception e) { logException("command_consumers", e, "Command consumers crashed"); } });
    runSafe({ try { startStateSnapshotter(ctx); }
              catch (Exception e) { logException("state_snapshotter", e, "State snapshotter crashed"); } });

    runApplication();
}

/// Handoff callback invoked from the control consumer when a
/// `gracefulReload` message arrives. Pauses every connection,
/// serves the state+FDs to the new engine, then exits cleanly so
/// the supervisor can respawn the new binary.
private bool performHandoff() {
    int newPid;
    string socketPath;
    long deadlineMs;
    if (!consumeHandoffRequest(newPid, socketPath, deadlineMs)) {
        logError("performHandoff: no handoff request");
        return false;
    }
    logInfo("performHandoff: newPid=%d socketPath=%s deadlineMs=%d",
        newPid, socketPath, deadlineMs);
    try {
        serveReload(g_ctx, socketPath);
    } catch (Exception e) {
        logError("serveReload failed: %s", e.msg);
        return false;
    }
    // We transferred every connection. Write a completion signal
    // that the Ansible playbook (or supervisor) can detect. The old
    // engine keeps running as PID 1 until the playbook kills it.
    // This avoids exit(0) killing the Docker container when the
    // engine is PID 1 (the new engine process needs the container
    // to stay alive).
    logInfo("performHandoff: handoff complete — writing done marker");
    try {
        import std.file : write;
        import std.datetime : Clock;
        import std.conv : to;
        auto marker = "/tmp/ircfiber-handoff-done-" ~ g_ctx.localServer.serverId;
        write(marker, Clock.currTime.toUnixTime!long.to!string);
        logInfo("performHandoff: done marker written to %s", marker);
    } catch (Exception e) {
        logWarn("performHandoff: failed to write done marker: %s", e.msg);
    }
    return true;
}

/// Boot path #3: this engine was just exec(2)'d from a previous one.
/// The IRC TCP socket FDs are inherited (O_CLOEXEC was cleared before
/// exec). We read the checkpoint file written by the old engine,
/// adopt each FD via `adoptExecSocket` (which performs a fresh TLS
/// handshake on TLS connections — the IRC server's IRC layer above
/// TLS sees no change), then continue as a normal engine.
///
/// The IRC server sees ONE continuous TCP connection across the
/// entire reload — same TCP socket, just fresh TLS handshake.
/// `make update` becomes a true zero-disconnect hot-reload.
private void runExecReloadEngine() {
    import ircfiber.engine.exec_reload;
    import ircfiber.engine.handoff : HandoffState;
    import std.file : readText, exists, remove;
    import std.json : parseJSON;

    logInfo("Exec-reload boot: pid=%d (inherited FDs from old engine)", getpid());
    auto markerPath = environment.get("IRCFIBER_EXEC_RELOAD_MARKER", "");
    if (markerPath.length == 0 || !exists(markerPath)) {
        logError("Exec-reload boot: marker %s not found — falling back to fresh boot",
            markerPath);
        // Fall back to fresh boot path
        auto ctx = bootstrapEngine();
        g_ctx = ctx;
        runNormalEngineAfterBootstrap();
        return;
    }
// Marker contains the path to the checkpoint file.
    string checkpointPath;
    try {
        import std.string : strip;
        checkpointPath = readText(markerPath).strip;
        logInfo("Exec-reload boot: marker -> checkpoint %s", checkpointPath);
    } catch (Exception e) {
        logError("Exec-reload boot: cannot read marker %s: %s — fresh boot fallback",
            markerPath, e.msg);
        auto ctx = bootstrapEngine();
        g_ctx = ctx;
        runNormalEngineAfterBootstrap();
        return;
    }
    if (!exists(checkpointPath)) {
        logError("Exec-reload boot: checkpoint %s not found — fresh boot fallback",
            checkpointPath);
        auto ctx = bootstrapEngine();
        g_ctx = ctx;
        runNormalEngineAfterBootstrap();
        return;
    }
    ExecReloadSnapshot snap;
    try {
        auto content = readText(checkpointPath);
        auto json = parseJSON(content);
        snap = snapshotFromJson(json);
        logInfo("Exec-reload boot: parsed snapshot with %d records (serverId=%s, capturedPid=%d)",
            snap.records.length, snap.serverId, snap.capturedPid);
    } catch (Exception e) {
        logError("Exec-reload boot: failed to parse checkpoint %s: %s — fresh boot fallback",
            checkpointPath, e.msg);
        auto ctx = bootstrapEngine();
        g_ctx = ctx;
        runNormalEngineAfterBootstrap();
        return;
    }

    // Clean up the marker file now that we've consumed it.
    try remove(markerPath);
    catch (Exception) {}

    // Build the engine context. We need a normal bootstrap because
    // Mongo/Redis/etc. need to be re-initialized in this new process
    // (exec wiped all the old connections to those services).
    auto ctx = bootstrapEngine();
    g_ctx = ctx;

    // Adopt each IRC connection from the checkpoint. The TCP FDs
    // are inherited from the old engine (same PID, same fdtable).
    int adopted = 0;
    foreach (rec; snap.records) {
        if (rec.fd < 0) {
            logWarn("Exec-reload boot: record for %s has no FD — skipping", rec.state.config.name);
            continue;
        }
        try {
            import std.uuid : parseUUID;
            auto cfg = rec.state.config;
            auto uid = (() {
                if (rec.state.userId.length > 0) {
                    try return parseUUID(rec.state.userId);
                    catch (Exception) return cfg.id;
                }
                return cfg.id;
            })();
            ctx.connManager.addNetwork(cfg, uid);
            // Find the client we just added and adopt the existing FD.
            auto client = ctx.connManager.getClient(cfg.id);
            if (client is null) {
                logError("Exec-reload boot: cannot find client for %s after addNetwork", cfg.name);
                continue;
            }
            client.adoptExecSocket(rec.fd, rec.state);
            adopted++;
            logInfo("Exec-reload boot: adopted %s on fd=%d (wasTls=%s)",
                cfg.name, rec.fd, rec.wasTls);
        } catch (Exception e) {
            logError("Exec-reload boot: failed to adopt %s on fd=%d: %s",
                rec.state.config.name, rec.fd, e.msg);
        }
    }
    logInfo("Exec-reload boot: adopted %d/%d IRC connections from old engine",
        adopted, snap.records.length);

    // Re-establish the handoff callback for subsequent hot-reloads.
    setHandoffCallback(() => performHandoff());

    // Now run the rest of the normal engine startup: heartbeat,
    // consumers, snapshots, etc.
    runNormalEngineAfterBootstrap();
}

/// Common post-bootstrap path: register the server, start heartbeat,
/// start consumers, and run the event loop. Shared by fresh-boot and
/// exec-reload paths.
private void runNormalEngineAfterBootstrap() {
    import ircfiber.engine.consumer : setHandoffCallback, startControlConsumer,
        startCommandConsumers;
import ircfiber.engine.processor : startEventProcessor;
import ircfiber.engine.state : startStateSnapshotter;
import ircfiber.models.irc_event : IRCRawEvent;
    // OTel handled centrally via setupOtel (env-gated, no-op when disabled).
    setupOtel("ircfiber-engine");

    auto ctx = g_ctx;
    writeStateSnapshots(ctx);
    runTask(() nothrow {
        try {
            ctx.serverRegistry.registerServer(ctx.localServer);
            logInfo("Server registered via event loop: %s@%s",
                ctx.localServer.serverId, ctx.localServer.bindAddress);
            try ctx.serverRegistry.updateHeartbeat(ctx.localServer.serverId);
            catch (Exception e) logWarn("Initial heartbeat failed: %s", e.msg);
            loadNetworks(ctx);
        } catch (Exception e) {
            logError("Registration task failed: %s", e.msg);
        }
    });
    startHeartbeatTask(ctx);
    startOrphanReaperTask(ctx);

    auto runSafe = (void delegate() dg) {
        runTask(() nothrow {
            try dg();
            catch (Exception e) logException("runtime", e, "Task crashed");
        });
    };
    runSafe({ try startEventProcessor(ctx);
              catch (Exception e) logException("event_processor", e, "Event processor crashed"); });
    runSafe({ try startControlConsumer(ctx);
              catch (Exception e) logException("control_consumer", e, "Control consumer crashed"); });
    runSafe({ try startCommandConsumers(ctx);
              catch (Exception e) logException("command_consumers", e, "Command consumers crashed"); });
    runSafe({ try startStateSnapshotter(ctx);
              catch (Exception e) logException("state_snapshotter", e, "State snapshotter crashed"); });

    logInfo("IRC Fiber Engine (Decentralized) running on server=%s (pid=%d)",
        ctx.localServer.serverId, getpid());
    runApplication();

    ctx.connManager.shutdown();
    if (ctx.redis && ctx.localServer.serverId.length > 0) {
        try ctx.redis.publish(RedisKeys.shutdownChannel(), ctx.localServer.serverId);
        catch (Exception e) logWarn("Failed to publish shutdown: %s", e.msg);
    }
    if (ctx.serverRegistry && ctx.localServer.serverId.length > 0) {
        ctx.serverRegistry.unregisterServer(ctx.localServer.serverId);
    }
    logInfo("IRC Fiber Engine shutdown complete (pid=%d)", getpid());
}
