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
import ircfiber.storage.buffer : BufferManager;
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

/// Returns true iff a reconnect for `networkId` is currently in flight.
bool isReconnectInFlight(string networkId) {
    if (auto t = networkId in pendingReconnects) {
        if (Clock.currTime.toUnixTime!long * 1000 - *t < RECONNECT_DEDUP_TTL_MS)
            return true;
        // Stale — TTL expired, drop it
        pendingReconnects.remove(networkId);
    }
    return false;
}

/// Marks a reconnect for `networkId` as in flight.
void markReconnectInFlight(string networkId) {
    pendingReconnects[networkId] = Clock.currTime.toUnixTime!long * 1000;
}

/// Clears the in-flight reconnect marker for `networkId`.
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

/// Spawns the command consumer task for the given network.
void spawnNetworkCommandConsumer(ref EngineContext ctx, string networkId) {
    auto serverId = ctx.localServer.serverId;
    runSafeTask({
        auto key = RedisKeys.cmd(serverId, networkId);
        while (true) {
            try {
                // If `addNetwork`/`reconnectNetwork` control handlers
                // haven't finalized the network yet (race vs. `loadNetworks`
                // at boot, vs. transient state during a hot swap), wait it out
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
        case "addNetwork":
            if (msg.config.type != Json.Type.undefined) {
                auto cfg = parseNetworkConfig(msg.config);
                auto uid = parseUUID(msg.userId);
                // A queued addNetwork for a network that has since been
                // parked (SASL rejection) or admin-disabled must not
                // resurrect it: fresh rows are never disabled, so this only
                // fires on stale control traffic.
                if (cfg.disabled) {
                    logWarn("addNetwork[%s]: network is parked/disabled — ignoring stale control message", cfg.id.toString());
                    break;
                }

                // Claim ownership in registry
                const sid = ctx.serverRegistry.assignNetwork(cfg.id.toString());
                if (sid.length == 0) {
                    logWarn("Cannot add network %s — no healthy connection server available, will retry", cfg.name);
                }
                
                ctx.connManager.addAndStartNetwork(cfg, uid);
                spawnNetworkCommandConsumer(ctx, cfg.id.toString());
            }
            break;
        case "removeNetwork":
            if (msg.networkId.length) {
                const key = msg.networkId;
                ctx.connManager.removeNetwork(parseUUID(msg.networkId));
                // Tearing the client down emits its own farewell events —
                // the QUIT echo and the `ERROR :Quit:` line — and those get
                // persisted like any other event, into scrollback keys the
                // gateway has usually just deleted. Result: a deleted
                // network kept a `_server` and `#channel` buffer with a
                // 30-day TTL, which is what let its rooms still render at
                // /irc/<name>/channel/%23chan after the sidebar had
                // (correctly) dropped it. Clearing here, after teardown, is
                // the only point that runs *last*.
                try {
                    auto bm = new BufferManager(ctx.redis);
                    bm.clearNetworkBuffers(ctx.localServer.serverId, key);
                } catch (Exception e) {
                    logWarn("removeNetwork: clearing buffers for %s failed: %s", key, e.msg);
                }
                try {
                    auto db = ctx.redis.getDb();
                    db.del(RedisKeys.state(ctx.localServer.serverId, key));
                    db.del(RedisKeys.state_legacy(key));
                } catch (Exception e) {
                    logWarn("removeNetwork: failed to clean Redis state for %s: %s", key, e.msg);
                }
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
        case "retargetEgress":
            // Admin "swap exit" from the Mullvad page. The gateway cannot
            // touch a slot's tailscaled (the socket is on the engine host),
            // so it asks us. Payload:
            //   msg.config["label"]      = slot label ("de")
            //   msg.config["locationId"] = target location ("se-sto")
            // Result is observed through the slot registry the snapshotter
            // publishes (locationId / state / error), so there is nothing to
            // reply to; a refusal is logged and recorded as the slot's error.
            {
                import ircfiber.irc.connection : retargetSlotByLabel;
                string label, locationId;
                bool force = false;
                if (msg.config.type == Json.Type.object) {
                    if (auto l = "label" in msg.config)
                        if (l.type == Json.Type.string) label = l.get!string;
                    if (auto v = "locationId" in msg.config)
                        if (v.type == Json.Type.string) locationId = v.get!string;
                    // Operator override of the in-use lock (admin confirmed).
                    if (auto f = "force" in msg.config)
                        if (f.type == Json.Type.bool_) force = f.get!bool;
                }
                const reason = retargetSlotByLabel(label, locationId, force);
                int bounced = 0;
                // The slot now exits somewhere else, so the sockets riding it
                // are pointing through a path the sidecar no longer uses.
                // Close them and let each network's reconnect loop re-dial.
                if (reason.length == 0 && force)
                    bounced = ctx.connManager.bounceNetworksOnEgress(label);
                logJsonMap(reason.length ? "warn" : "info", "consumer",
                    reason.length ? "Egress retarget refused" : "Egress retarget done",
                    ["label": label, "locationId": locationId,
                     "forced": force ? "true" : "false",
                     "bounced": bounced.to!string,
                     "reason": reason, "event": "egress_retarget"]);
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
    if (j["operUsername"].type != Json.Type.undefined) cfg.operUsername = j["operUsername"].get!string;
    if (j["operPassword"].type != Json.Type.undefined) cfg.operPassword = j["operPassword"].get!string;
    // Fields the gateway ships in NetworkConfig.toJson() that were silently
    // dropped here, so a pin/delay set via the API only took effect after a
    // restart re-read Mongo (db/network.d honours both).
    if (j["autoJoinDelaySeconds"].type == Json.Type.int_) {
        const v = j["autoJoinDelaySeconds"].get!int;
        if (v > 0) cfg.autoJoinDelaySeconds = cast(uint) v;
    }
    if (j["egressNodeId"].type == Json.Type.string) cfg.egressNodeId = j["egressNodeId"].get!string;
    if (j["systemManaged"].type == Json.Type.bool_) cfg.systemManaged = j["systemManaged"].get!bool;
    return cfg;
}
