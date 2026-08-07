module ircfiber.engine.consumer;

import std.uuid : parseUUID;
import std.conv : to;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.log;
import vibe.data.json : parseJsonString, Json, deserializeJson;

import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.redis.protocol : RedisKeys, ControlMessage, IRCCommand;
import ircfiber.models.network : NetworkConfig, TLSMode, SASLMechanism;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.logging : logJsonMap;
import std.datetime.systime : Clock;
import core.time : seconds, Duration, msecs;

// ─────────────────────────────────────────────────────────────────────────
// Reconnect-in-flight dedup
// ─────────────────────────────────────────────────────────────────────────
//
// The control consumer is a single fiber (startControlConsumer), so this
// module-local map is touched only on one thread — no locks needed.
//
// Map keyed by `networkId.toString()` → unix-ms timestamp of when the
// reconnect was dispatched. Entries auto-expire after RECONNECT_DEDUP_TTL
// so a failed addAndStartNetwork doesn't permanently block subsequent
// reconnects. `clearReconnectInFlight` is called after the connection
// actually transitions to connected, OR from a small post-dispatch delay.
private long[string] pendingReconnects;
private enum RECONNECT_DEDUP_TTL_MS = 5_000;

bool isReconnectInFlight(string networkId) {
    if (auto t = networkId in pendingReconnects) {
        if (Clock.currTime.toUnixTime!long * 1000 - *t < RECONNECT_DEDUP_TTL_MS)
            return true;
        // Stale — TTL expired, drop it
        pendingReconnects.remove(networkId);
    }
    return false;
}

void markReconnectInFlight(string networkId) {
    pendingReconnects[networkId] = Clock.currTime.toUnixTime!long * 1000;
}

void clearReconnectInFlight(string networkId) nothrow {
    pendingReconnects.remove(networkId);
}

private void runSafeTask(void delegate() dg) {
    runTask(() nothrow {
        try {
            dg();
        } catch (Exception e) {
            logError("Task crashed: %s", e.msg);
        }
    });
}

/**
 * Start control consumer for this connection server.
 *
 * Listens on the server-specific control queue (irc:control:<serverId>)
 * instead of the global queue. This prevents multiple servers from
 * consuming the same control messages.
 *
 * Precondition: ctx.localServer.serverId is set.
 */
void startControlConsumer(ref EngineContext ctx) {
    auto serverId = ctx.localServer.serverId;
    runSafeTask({
        while (true) {
            try {
                auto result = ctx.redis.blpop(RedisKeys.control(serverId), 5);
                if (!result.isNull) {
                    auto raw = result.get[1];
                    try {
                        auto json = parseJsonString(raw);
                        auto msg = ControlMessage.fromJson(json);
                        handleControlMessage(ctx, msg);
                    } catch (Exception e) {
                        logWarn("Failed to parse control message: %s", e.msg);
                    }
                }
            } catch (Exception e) {
                logError("Control consumer error: %s", e.msg);
                sleep(1.seconds);
            }
            yield();
        }
    });
}

// ── Graceful reload plumbing ───────────────────────────────────────────────
//
// The control consumer runs on its own vibe.d fiber. The actual handoff
// (pausing every connection, transferring FDs, etc.) needs to happen
// in a coordinated way that the rest of the engine can observe. We use
// a shared atomic flag and a one-shot callback registered by
// `app_engine.d`.
//
// Flow:
//   1. Watch-engine sends `gracefulReload` to irc:control:<serverId>
//   2. This consumer flips `g_handoffRequested = true` and stores the
//      handoff parameters
//   3. The main loop in `app_engine.d` checks the flag and invokes
//      `g_handoffCallback`, which is responsible for the actual
//      pause/snapshot/serve/done cycle.
//   4. After handoff completes, the engine exits with rc=0 (clean
//      shutdown), the supervisor respawns the new binary.

private class HandoffRequest {
    bool pending;
    int newEnginePid;
    string socketPath;
    long deadlineMs;
}

private __gshared HandoffRequest g_handoffRequest;

/// Callback signature: invoked from the main loop on receipt of a
/// gracefulReload control message. Returns true on success (engine
/// will exit cleanly), false on failure (engine continues running).
private alias HandoffCallback = bool delegate();

private __gshared HandoffCallback g_handoffCallback;

/// Check whether a handoff has been requested. If so, consume the
/// request (returns true once) and populate `newEnginePid`/
/// `socketPath`/`deadlineMs` for the caller. Thread-safe.
bool consumeHandoffRequest(out int newEnginePid, out string socketPath, out long deadlineMs) {
    import core.atomic : atomicLoad;
    if (g_handoffRequest is null || !atomicLoad(g_handoffRequest.pending)) return false;
    synchronized (g_handoffRequest) {
        if (!g_handoffRequest.pending) return false;
        newEnginePid = g_handoffRequest.newEnginePid;
        socketPath   = g_handoffRequest.socketPath;
        deadlineMs   = g_handoffRequest.deadlineMs;
        g_handoffRequest.pending = false;
    }
    return true;
}

/// Register the callback that performs the actual handoff. Called
/// once at startup by `app_engine.d`.
void setHandoffCallback(HandoffCallback cb) {
    g_handoffCallback = cb;
    if (g_handoffRequest is null) g_handoffRequest = new HandoffRequest();
}

private void handleGracefulReload(ref EngineContext ctx, ControlMessage msg) {
    int newPid = 0;
    string socketPath = "";
    long deadlineMs = 0;
    if (msg.config.type == Json.Type.undefined) return;
    // Numeric values in our wire format are always JSON ints.
    // The `Json.Type` enum has trailing underscores on some members
    // (`int_`, `null_`) which trip the D parser in some contexts; we
    // compare against the underlying integer value directly.
    // The enum order is: undefined=0, null_=1, bool_=2, int_=3,
    // bigInt=4, float_=5, string=6, array=7, object=8.
    enum TYPE_INT = 3;
    enum TYPE_STRING = 6;
    // Access individual fields via Json.opIndex(string). Missing keys
    // yield a Json with .type == .undefined; we guard on that.
    if (msg.config.type == Json.Type.undefined) return;
    Json pidV, pathV, dlV;
    try { pidV = msg.config["newEnginePid"]; } catch (Exception) {}
    try { pathV = msg.config["socketPath"]; } catch (Exception) {}
    try { dlV = msg.config["deadlineMs"]; } catch (Exception) {}
    if (pidV.type == cast(Json.Type) TYPE_INT) newPid = cast(int) pidV.get!long;
    if (pathV.type == cast(Json.Type) TYPE_STRING) socketPath = pathV.get!string;
    if (dlV.type == cast(Json.Type) TYPE_INT) deadlineMs = dlV.get!long;
    if (socketPath.length == 0) {
        logError("gracefulReload: missing socketPath");
        return;
    }
    // `newEnginePid` is informational only (we don't use it for FD
    // transfer) — the *old* engine never references it. We accept
    // 0 as "unknown" so the Makefile doesn't have to look up its
    // own pid and stuff it into the control message.
    if (newPid < 0) newPid = 0;
    logInfo("gracefulReload requested: newPid=%d socketPath=%s deadlineMs=%d",
        newPid, socketPath, deadlineMs);
    logInfo("gracefulReload: invoking handoff callback (pending=%s, cb=%s)",
        g_handoffRequest.pending, g_handoffCallback !is null);
    if (g_handoffRequest is null) g_handoffRequest = new HandoffRequest();
    synchronized (g_handoffRequest) {
        if (g_handoffRequest.pending) {
            logInfo("gracefulReload: handoff already in progress, ignoring");
            return;
        }
        g_handoffRequest.pending       = true;
        g_handoffRequest.newEnginePid  = newPid;
        g_handoffRequest.socketPath    = socketPath;
        g_handoffRequest.deadlineMs    = deadlineMs;
    }
    // Invoke the handoff callback synchronously. This blocks the
    // control-consumer fiber but that's fine — the consumer is the
    // only one watching this control queue, and a brief block
    // doesn't drop any messages (BLPOP will time out and retry).
    if (g_handoffCallback) {
        try {
            g_handoffCallback();
        } catch (Exception e) {
            logError("Handoff callback threw: %s", e.msg);
        }
    } else {
        logError("gracefulReload: no handoff callback registered; engine will exit normally");
    }
}

/// Handle a `beginExecReload` control message. This is the
/// zero-disconnect hot-reload path: pause all clients, snapshot state,
/// clear O_CLOEXEC on IRC socket FDs, write a checkpoint file, then
/// replace the process image via execve(2).
///
/// This function NEVER returns on success — the process is replaced
/// in-place by the new binary. The new binary detects the exec-reload
/// marker and reads the checkpoint file to restore its state.
private void handleExecReload(ref EngineContext ctx, ControlMessage msg) {
    import ircfiber.engine.reload_orchestrator : serveExecReload;

    if (auto binP = "binary" in msg.config) {
        auto binVal = *binP;
        if (binVal.type == Json.Type.string) {
            auto binary = binVal.get!string;
            logInfo("beginExecReload: target binary=%s", binary);
            try {
                serveExecReload(ctx, binary);
            } catch (Exception e) {
                logError("beginExecReload failed: %s", e.msg);
            }
            return;
        }
    }
    logError("beginExecReload: missing or invalid 'binary' field in msg.config");
}

/**
 * Start command consumers for networks assigned to this server.
 * 
 * Each network has a per-server command queue:
 * irc:cmd:<serverId>:<networkId>
 * 
 * This isolates command queues per server, preventing command leakage
 * between servers.
 */
void startCommandConsumers(ref EngineContext ctx) {
    foreach (net; ctx.connManager.getNetworks()) {
        spawnNetworkCommandConsumer(ctx, net.config.id.toString());
    }
}

void spawnNetworkCommandConsumer(ref EngineContext ctx, string networkId) {
    auto serverId = ctx.localServer.serverId;
    runSafeTask({
        auto key = RedisKeys.cmd(serverId, networkId);
        while (true) {
            try {
                // If `addNetwork`/`reconnectNetwork` control handlers
                // haven't finalized the network yet (race vs. `loadNetworks`
                // at boot, vs. transient state during handoff), wait it out
                // instead of exiting the loop. `break` here used to leak
                // the consumer forever for any network added after a fresh
                // engine start, leaving WS-queued cmds stuck in
                // `irc:cmd:<server>:<network>`. See consumer.d issue 2026-07-03.
                if (!ctx.connManager.hasNetwork(networkId)) {
                    sleep(5.seconds);
                    if (!ctx.connManager.hasNetwork(networkId)) continue;
                }
                auto result = ctx.redis.blpop(key, 5);
                if (!result.isNull) {
                    auto raw = result.get[1];
                    // Parse the JSON envelope first so genuine parse errors
                    // (malformed payload from the gateway) are not silently
                    // mislabeled as command-execution failures. Without this
                    // split, every TLS-write error on a dead connection was
                    // logged as "Failed to parse command", making diagnosis
                    // impossible during reconnect storms.
                    Json json;
                    try {
                        json = parseJsonString(raw);
                    } catch (Exception e) {
                        logJsonMap("warn", "consumer",
                            "Malformed command JSON from Redis",
                            [
                                "networkId": networkId,
                                "error":     e.msg,
                                "event":     "cmd_parse_fail"
                            ]);
                        logWarn("Failed to parse command for %s: %s", networkId, e.msg);
                        continue;
                    }
                    IRCCommand cmd;
                    try {
                        cmd = IRCCommand.fromJson(json);
                    } catch (Exception e) {
                        logJsonMap("warn", "consumer",
                            "Valid JSON but invalid IRCCommand shape",
                            [
                                "networkId": networkId,
                                "error":     e.msg,
                                "event":     "cmd_shape_fail"
                            ]);
                        logWarn("Failed to parse command shape for %s: %s", networkId, e.msg);
                        continue;
                    }
                    try {
                        handleNetworkCommand(ctx, networkId, cmd);
                    } catch (Exception e) {
                        // Execution failure (most often: TLS write to a
                        // closed IRC connection). The connection's writeRaw
                        // already logs `tls_write_fail` so the upstream
                        // root cause is captured there — this entry just
                        // shows that the command was dropped from the queue.
                        logJsonMap("warn", "consumer",
                            "Command execution failed (likely closed connection)",
                            [
                                "networkId": networkId,
                                "cmd":       cmd.cmd,
                                "target":    cmd.target,
                                "error":     e.msg,
                                "event":     "cmd_exec_fail"
                            ]);
                        logWarn("Failed to execute command for %s: cmd=%s error=%s",
                            networkId, cmd.cmd, e.msg);
                    }
                }
            } catch (Exception e) {
                logError("Command consumer error for %s: %s", networkId, e.msg);
                sleep(1.seconds);
            }
            yield();
        }
    });
}

private void handleControlMessage(ref EngineContext ctx, ControlMessage msg) {
    import std.uuid : UUID;
    logInfo("Control message [server=%s]: %s network=%s", ctx.localServer.serverId, msg.action, msg.networkId);

    switch (msg.action) {
        case "gracefulReload":
            // The `make watch-engine` Makefile target (and external
            // tools) sends this control message to ask the engine to
            // hand off its live IRC connections to a freshly-built
            // binary instead of exiting. The new engine is started as
            // a *child* of the old one with the same `serverId`, so
            // the gateway sees no disruption.
            //
            // Expected msg fields:
            //   msg.config["newEnginePid"]   = JSON integer (pid_t)
            //   msg.config["socketPath"]     = JSON string
            //   msg.config["deadlineMs"]     = JSON integer (ms)
            handleGracefulReload(ctx, msg);
            break;
        case "beginExecReload":
            // Zero-disconnect hot-reload via exec(2). Replaces the
            // current process image with `msg.config["binary"]`. The
            // new binary inherits the IRC socket FDs (after we clear
            // O_CLOEXEC on them) so the TCP connection survives and
            // the IRC server sees no disconnect.
            //
            // Expected msg fields:
            //   msg.config["binary"] = JSON string (path to new binary)
            handleExecReload(ctx, msg);
            break;
        case "addNetwork":
            if (msg.config.type != Json.Type.undefined) {
                auto cfg = parseNetworkConfig(msg.config);
                auto uid = parseUUID(msg.userId);

                // Claim ownership in registry
                auto sid = ctx.serverRegistry.assignNetwork(cfg.id.toString());
                if (sid.length == 0) {
                    logWarn("Cannot add network %s — no healthy connection server available, will retry", cfg.name);
                }
                
                ctx.connManager.addAndStartNetwork(cfg, uid);
                spawnNetworkCommandConsumer(ctx, cfg.id.toString());
            }
            break;
        case "removeNetwork":
            if (msg.networkId.length) {
                ctx.connManager.removeNetwork(parseUUID(msg.networkId));
            }
            break;
        case "disconnectNetwork":
            if (msg.networkId.length) {
                auto id = parseUUID(msg.networkId);
                const key = id.toString();
                // Stop the client if it's connected (sends QUIT), then remove
                // it from the manager so no auto-reconnect loop can retry.
                ctx.connManager.disconnectNetwork(id, msg.reason);
                ctx.connManager.removeNetwork(id);
                // Clean up the stale Redis state snapshot so the gateway
                // returns the correct disconnected state — otherwise the
                // frontend's periodic sync will see the old 'connecting'
                // snapshot and overwrite the local disconnected state.
                try {
                    auto db = ctx.redis.getDb();
                    db.del(RedisKeys.state(ctx.localServer.serverId, key));
                    db.del(RedisKeys.state_legacy(key));
                } catch (Exception e) {
                    logWarn("disconnectNetwork: failed to clean Redis state for %s: %s", key, e.msg);
                }
            }
            break;
        case "reconnectNetwork":
            if (msg.networkId.length && msg.config.type != Json.Type.undefined) {
                auto id = parseUUID(msg.networkId);
                // Idempotency: a double-click in the frontend (or a
                // bounce/retry from the gateway's WebSocket) can publish
                // two `reconnectNetwork` messages within <50 ms. Without
                // dedup, the second one calls `removeNetwork` on the
                // freshly-started client, dropping the live connection
                // and producing a "connect→remove" loop. Block the
                // second one and let the original proceed.
                if (isReconnectInFlight(msg.networkId)) {
                    logJsonMap("debug", "consumer",
                        "Reconnect dedup — another reconnectNetwork is in-flight",
                        [
                            "networkId": msg.networkId,
                            "event":     "reconnect_dedup"
                        ]);
                    return; // Discard silently — the in-flight one will
                            // produce its own user-visible events.
                }
                markReconnectInFlight(msg.networkId);

                auto cfg = parseNetworkConfig(msg.config);
                // Emit a "queued" notice *immediately* so the frontend
                // sees user-visible feedback the instant the control
                // message is consumed — the connection fiber can't run
                // until the next event-loop tick, which on a busy engine
                // can be 50-200ms after this point. Bridging that gap is
                // the difference between "click → spinner" and "click →
                // text appears instantly".
                try {
                    auto queued = IRCRawEvent.makeServerLog(
                        cfg.name, cfg.id.toString(), "queued",
                        "Reconnect requested — preparing connection to "
                        ~ cfg.host ~ ":" ~ cfg.port.to!string
                        ~ (cfg.tls == TLSMode.disabled ? " (plain text)" : " (TLS)") ~ "..."
                    );
                    ctx.eventChannel.put(queued);
                } catch (Exception e) {
                    logWarn("Failed to emit queued server-log notice for %s: %s",
                        cfg.name, e.msg);
                }
                ctx.connManager.removeNetwork(id);
                // Jul 8 2026 fix: ensure the network→server assignment is
                // published to `irc:assignments` before addAndStartNetwork.
                // Pre-fix, reconnectNetwork only removed + added the local
                // client without writing the canonical assignment, so the
                // gateway's server-routing tables and the admin API
                // believed the network was unassigned — even though the
                // local client was connecting. This caused SuperNets and
                // Gang Net (after my Bug 3 disabled-flag fix re-enabled
                // them in MongoDB) to be missing from the assignment
                // hash, blocking the admin "Connected" indicator and
                // confusing the gateway's load-balancer.
                auto sid = ctx.serverRegistry.assignNetwork(msg.networkId);
                if (sid.length == 0 || sid != ctx.localServer.serverId) {
                    logWarn("reconnectNetwork[%s]: assignNetwork returned %s (local=%s) — self-assigning to local",
                        msg.networkId, sid, ctx.localServer.serverId);
                    ctx.serverRegistry.selfAssignNetwork(msg.networkId, ctx.localServer.serverId);
                }
                auto uid = msg.userId.length ? parseUUID(msg.userId) : UUID.init;
                ctx.connManager.addAndStartNetwork(cfg, uid);
                spawnNetworkCommandConsumer(ctx, cfg.id.toString());

                // Clear the dedup flag after the TTL window has elapsed so
                // a legitimate retry (after a failed connect, for example)
                // is allowed to proceed. The TTL is small enough that
                // duplicate-publish dedup is still effective. Wrapped in
                // `nothrow` to satisfy vibe-core 2.14's stricter
                // runTask callback contract.
                void cleanupFn() nothrow {
                    try {
                        sleep((RECONNECT_DEDUP_TTL_MS + 100).msecs);
                    } catch (Exception) {}
                    clearReconnectInFlight(msg.networkId);
                }
                runTask(&cleanupFn);
            }
            break;
        case "updateConfig":
            if (msg.networkId.length && msg.config.type != Json.Type.undefined) {
                auto cfg = parseNetworkConfig(msg.config);
                ctx.connManager.updateConfig(cfg);
            }
            break;
        case "migrateNetwork":
            // NEW: Handle migration to another server
            if (msg.networkId.length) {
                auto id = parseUUID(msg.networkId);
                ctx.connManager.disconnectNetwork(id, "");
                ctx.connManager.removeNetwork(id);
                logInfo("Network %s migrated away from server %s", msg.networkId, ctx.localServer.serverId);
            }
            break;
        default:
            logWarn("Unknown control action: %s", msg.action);
    }
}

private void handleNetworkCommand(ref EngineContext ctx, string networkId, IRCCommand cmd) {
    import std.uuid : UUID;
    auto nid = parseUUID(networkId);

    switch (cmd.cmd) {
        case "msg":
            if (cmd.label.length > 0) {
                ctx.connManager.sendLabeledMessage(nid, cmd.target, cmd.text, cmd.label);
            } else {
                ctx.connManager.sendMessage(nid, cmd.target, cmd.text);
            }
            break;
        case "editmsg":
            if (cmd.label.length > 0) {
                ctx.connManager.sendEditMessage(nid, cmd.target, cmd.label, cmd.text);
            }
            break;
        case "join":
            ctx.connManager.joinChannel(nid, cmd.target.length ? cmd.target : cmd.channel);
            break;
        case "part":
            ctx.connManager.partChannel(nid, cmd.target.length ? cmd.target : cmd.channel);
            break;
        case "raw":
            ctx.connManager.sendRaw(nid, cmd.text);
            break;
        case "chathistory":
            // chathistory:<channel>:<command>:<refMsgid>:<limit>
            // refMsgid may be empty for LATEST. Stored in cmd.text as a
            // single colon-delimited payload to keep the protocol schema
            // additive (no new field needed in the struct).
            import ircfiber.irc.chathistory : parseChathistoryPayload;
            auto p = parseChathistoryPayload(cmd.text);
            if (p.channel.length == 0) {
                logWarn("chathistory command missing fields: %s", cmd.text);
                break;
            }
            ctx.connManager.requestChathistory(nid, p.channel, p.command, p.refMsgid, p.limit);
            break;
        default:
            logWarn("Unknown network command: %s", cmd.cmd);
    }
}

/// Parse an int, returning `defaultVal` on any failure. Used to parse
/// integer fields out of the chathistory command payload.
private int parseIntSafe(string s, int defaultVal = 100) {
    import std.conv : to;
    try { return s.to!int; } catch (Exception) { return defaultVal; }
}

private NetworkConfig parseNetworkConfig(Json j) {
    NetworkConfig cfg;
    cfg.id = parseUUID(j["id"].get!string);
    cfg.name = j["name"].get!string;
    cfg.host = j["host"].get!string;
    cfg.port = cast(ushort) j["port"].get!int;
    cfg.tls = j["tls"].get!string.to!TLSMode;
    if (j["sasl"].type != Json.Type.undefined) cfg.sasl = j["sasl"].get!string.to!SASLMechanism;
    if (j["saslUsername"].type != Json.Type.undefined) cfg.saslUsername = j["saslUsername"].get!string;
    if (j["saslPassword"].type != Json.Type.undefined) cfg.saslPassword = j["saslPassword"].get!string;
    cfg.autoJoinChannels = deserializeJson!(string[])(j["autoJoinChannels"]);
    if (j["partedChannels"].type != Json.Type.undefined)
        cfg.partedChannels = deserializeJson!(string[])(j["partedChannels"]);
    cfg.nick = j["nick"].get!string;
    if (j["realName"].type != Json.Type.undefined) cfg.realName = j["realName"].get!string;
    else cfg.realName = cfg.nick;
    if (j["nspass"].type != Json.Type.undefined) cfg.nspass = j["nspass"].get!string;
    if (j["commands"].type != Json.Type.undefined) cfg.commands = j["commands"].get!string;
    if (j["serverPass"].type != Json.Type.undefined) cfg.serverPass = j["serverPass"].get!string;
    return cfg;
}
