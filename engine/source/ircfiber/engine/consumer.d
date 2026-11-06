module ircfiber.engine.consumer;

import std.uuid : parseUUID;
import std.conv : to;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.log;
import vibe.data.json : parseJsonString, Json, deserializeJson;

import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.redis.protocol : RedisKeys, ControlMessage, IRCCommand;
import ircfiber.models.network : NetworkConfig, TLSMode, SASLMechanism, sanitizeIdent;
import ircfiber.services.config : decodeStoredServicesConfig;
import ircfiber.services.protocol : ServicesResult;
import ircfiber.storage.redis : RedisStorage;
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
// Map keyed by `networkId.toString()` → when the reconnect was dispatched
// and with which configuration. Entries auto-expire after
// RECONNECT_DEDUP_TTL so a failed addAndStartNetwork doesn't permanently
// block subsequent reconnects. `clearReconnectInFlight` is called after the
// connection actually transitions to connected, OR from a small
// post-dispatch delay.
//
// Only a reconnect carrying the *same* configuration is a duplicate (a
// double-click, a gateway retry). One with a changed configuration — a SASL
// edit that re-enables a network the engine parked — must replace the
// client: dropping it left the parked client idling while Mongo said
// enabled, until the next engine restart.
private struct PendingReconnect {
    long atMs;
    string config;
}
private PendingReconnect[string] pendingReconnects;
private enum RECONNECT_DEDUP_TTL_MS = 5_000;

/// Returns true iff a reconnect for `networkId` with this `config` (its
/// serialized JSON) is currently in flight.
bool isReconnectInFlight(string networkId, string config = "") {
    if (auto p = networkId in pendingReconnects) {
        if (Clock.currTime.toUnixTime!long * 1000 - p.atMs < RECONNECT_DEDUP_TTL_MS)
            return p.config == config;
        // Stale — TTL expired, drop it
        pendingReconnects.remove(networkId);
    }
    return false;
}

/// Marks a reconnect for `networkId` with this `config` as in flight.
void markReconnectInFlight(string networkId, string config = "") {
    pendingReconnects[networkId] = PendingReconnect(Clock.currTime.toUnixTime!long * 1000, config);
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
                // Stale control traffic must not start a held or disabled row,
                // nor replace an already-running initial connection.
                if (cfg.disabled || cfg.servicesProvisioningPending) {
                    logWarn("addNetwork[%s]: network is disabled or awaiting services — ignoring",
                            cfg.id.toString());
                    break;
                }
                if (ctx.connManager.hasNetwork(cfg.id)) break;
                const assigned = ctx.serverRegistry.getServerForNetwork(cfg.id.toString());
                if (assigned.length && assigned != ctx.localServer.serverId) break;
                if (!assigned.length)
                    ctx.serverRegistry.selfAssignNetwork(cfg.id.toString(), ctx.localServer.serverId);

                ctx.connManager.addAndStartNetwork(cfg, uid);
                spawnNetworkCommandConsumer(ctx, cfg.id.toString());
            }
            break;
        case "removeNetwork":
            if (msg.networkId.length) {
                const key = msg.networkId;
                ctx.connManager.forgetPublicAvatar(parseUUID(msg.networkId));
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
                auto cfg = parseNetworkConfig(msg.config);
                if (cfg.disabled || cfg.servicesProvisioningPending) {
                    logWarn("reconnectNetwork[%s]: network is disabled or awaiting services — ignoring",
                            cfg.id.toString());
                    break;
                }
                auto id = parseUUID(msg.networkId);
                // Idempotency: a double-click in the frontend (or a
                // bounce/retry from the gateway's WebSocket) can publish
                // two `reconnectNetwork` messages within <50 ms. Without
                // dedup, the second one calls `removeNetwork` on the
                // freshly-started client, dropping the live connection
                // and producing a "connect→remove" loop. Block the
                // second one and let the original proceed — unless it
                // carries a different configuration (see pendingReconnects).
                const configKey = msg.config.toString();
                if (isReconnectInFlight(msg.networkId, configKey)) {
                    logJsonMap("debug", "consumer",
                        "Reconnect dedup — another reconnectNetwork is in-flight",
                        [
                            "networkId": msg.networkId,
                            "event":     "reconnect_dedup"
                        ]);
                    return; // Discard silently — the in-flight one will
                            // produce its own user-visible events.
                }
                markReconnectInFlight(msg.networkId, configKey);

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
    import ircfiber.irc.connection : staleFiberMlsCommand;
    auto nid = parseUUID(networkId);

    // A FIBERMLS probe that waited in the command list (engine restart,
    // consumer backlog) is no longer a live request: never sent late. The
    // text is bearer material and is not logged.
    if ((cmd.cmd == "msg" || cmd.cmd == "raw")
        && staleFiberMlsCommand(cmd.text, cmd.timestampMs,
            (Clock.currStdTime - 621_355_968_000_000_000L) / 10_000)) {
        logJsonMap("debug", "consumer", "Stale FIBERMLS command dropped",
            ["networkId": networkId, "event": "fibermls_stale_command_dropped"]);
        return;
    }

    switch (cmd.cmd) {
        case "msg":
            if (cmd.label.length > 0) {
                ctx.connManager.sendLabeledMessage(nid, cmd.target, cmd.text, cmd.label, cmd.tags);
            } else {
                ctx.connManager.sendMessage(nid, cmd.target, cmd.text, cmd.tags);
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
        case "markread":
            // draft/read-marker: a web/bouncer read advanced `irc:lastseen`;
            // push it upstream (no-op without the cap).
            ctx.connManager.sendMarkRead(nid, cmd.target, cmd.timestampMs);
            break;
        case "services":
            handleServicesCommand(ctx, networkId, cmd, false);
            break;
        case "services_manual":
            handleServicesCommand(ctx, networkId, cmd, true);
            break;
        default:
            logWarn("Unknown network command: %s", cmd.cmd);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Actual-user services requests
// ─────────────────────────────────────────────────────────────────────────
//
// The command list carries routing metadata only: `label` = request id,
// `userId` = the gateway's authenticated owner, `timestampMs` = issue time,
// `text` = a `ServicesPayloadReference`. The request itself (credentials,
// memo text, broadcast text) waits in an owner/network-scoped single-use key
// (EX 15) that is fetched and deleted atomically here, so an absent, stale
// or already-consumed payload can never execute. Results go to a scoped
// reply list (one entry, EX 60) that only the originating gateway fiber
// reads; nothing is published on the owner's event stream. Nothing here
// logs payloads or results.

/// GET+DEL in one step; '' (never a valid payload) when absent.
private enum SERVICES_PAYLOAD_TAKE_LUA =
    "local v = redis.call('GET', KEYS[1]) "
    ~ "if v then redis.call('DEL', KEYS[1]) return v end "
    ~ "return ''";

/// Writes the reply only while this engine still holds the network
/// (KEYS[1] assignments hash, ARGV[1] network, ARGV[2] server), keeps the
/// first result only, and expires the list.
private enum SERVICES_REPLY_LUA =
    "if redis.call('HGET', KEYS[1], ARGV[1]) ~= ARGV[2] then return 0 end "
    ~ "redis.call('RPUSH', KEYS[2], ARGV[3]) "
    ~ "redis.call('LTRIM', KEYS[2], 0, 0) "
    ~ "redis.call('EXPIRE', KEYS[2], tonumber(ARGV[4])) "
    ~ "return 1";

/// Clock skew tolerated for a gateway timestamp from the future.
private enum long SERVICES_FUTURE_SKEW_MS = 5_000;

/// Why a routed services command must not run, or "" to proceed. `owner`
/// is the engine's own record of the network owner — never the command's.
string servicesCommandRejection(string owner, string cmdUserId, long issuedMs, long nowMs) @safe pure nothrow {
    import ircfiber.services.protocol : ServicesKeys;
    if (!owner.length) return "network_unowned";
    if (cmdUserId != owner) return "owner_mismatch";
    if (issuedMs <= 0 || nowMs - issuedMs > ServicesKeys.payloadTTLSeconds * 1000L
            || issuedMs - nowMs > SERVICES_FUTURE_SKEW_MS)
        return "request_expired";
    return "";
}

/// Bound private replies. Optional raw details yield to the canonical view;
/// dropping required data/capabilities makes a confirmed result uncertain.
string boundedServicesReply(ServicesResult r) {
    import ircfiber.services.protocol : ServicesKeys, ServiceStatus;
    auto text = r.toJson().toString();
    if (text.length <= ServicesKeys.maxReplyBytes) return text;
    r.details = null;
    text = r.toJson().toString();
    if (text.length <= ServicesKeys.maxReplyBytes) return text;
    r.data = Json.undefined;
    r.capabilities = Json.undefined;
    if (r.status == ServiceStatus.confirmed) r.status = ServiceStatus.unconfirmed;
    r.reasonCode = "result_too_large";
    return r.toJson().toString();
}

@("services reply bounds preserve canonical state before optional details") unittest {
    import std.array : replicate;
    import ircfiber.services.protocol : ServiceAction, ServiceStatus, ServicesKeys;
    ServicesResult result;
    result.action = ServiceAction.channelAccessList;
    result.status = ServiceStatus.confirmed;
    result.data = Json(["kind": Json("channelAccess"), "channel": Json("#c")]);
    result.details = ["x".replicate(ServicesKeys.maxReplyBytes)];
    auto bounded = parseJsonString(boundedServicesReply(result));
    assert(bounded["status"].get!string == "confirmed");
    assert(bounded["data"]["channel"].get!string == "#c");
    assert(bounded["details"].type == Json.Type.undefined);
    result.data["oversized"] = Json("x".replicate(ServicesKeys.maxReplyBytes));
    bounded = parseJsonString(boundedServicesReply(result));
    assert(bounded["status"].get!string == "unconfirmed");
    assert(bounded["reasonCode"].get!string == "result_too_large");
    assert(bounded["data"].type == Json.Type.undefined);
}

private bool canonicalUuid(string s) nothrow {
    import ircfiber.services.protocol : requireUUID;
    try {
        requireUUID(s);
        return true;
    } catch (Exception) {
        return false;
    }
}

private void handleServicesCommand(ref EngineContext ctx, string networkId, IRCCommand cmd, bool manual) {
    import ircfiber.services.protocol : ServicesKeys, ServicesPayloadReference, ServicesRequest,
        ServicesManualPayload, ServiceAction, ServiceStatus;

    const nid = parseUUID(networkId);
    const requestId = cmd.label;
    const serverId = ctx.localServer.serverId;
    auto redis = ctx.redis;
    void note(string level, string message, string reason) {
        logJsonMap(level, "services", message,
            ["networkId": networkId, "requestId": canonicalUuid(requestId) ? requestId : "",
             "manual": manual ? "true" : "false", "reason": reason, "event": "services_request"]);
    }
    if (!canonicalUuid(requestId) || !canonicalUuid(networkId)) {
        note("warn", "Services command without a canonical request id dropped", "invalid_identifier");
        return;
    }

    // The action named by a payload this handler consumed, so a rejection
    // still answers with the action the gateway is waiting for.
    auto action = ServiceAction.discover;
    void learnAction(string raw) {
        try {
            auto j = parseJsonString(raw);
            if (j["action"].type == Json.Type.string) action = j["action"].get!string.to!ServiceAction;
        } catch (Exception) {}
    }
    // Answers a typed request under the given owner scope (the gateway
    // fiber waiting there); manual lines have no reply channel.
    void answer(string scopeOwner, ServiceStatus status, string reason) {
        if (manual || !canonicalUuid(scopeOwner)) return;
        ServicesResult r;
        r.network = networkId;
        r.requestId = requestId;
        r.action = action;
        r.status = status;
        r.reasonCode = reason;
        writeServicesReply(redis, serverId, scopeOwner, networkId, r);
    }
    // A rejected request's payload is consumed too: it must never run later.
    void burnPayload(string scopeOwner) {
        if (!canonicalUuid(scopeOwner)) return;
        try {
            auto reply = redis.getDb().eval!string(SERVICES_PAYLOAD_TAKE_LUA,
                [ServicesKeys.payload(scopeOwner, networkId, requestId)]);
            if (!reply.empty) learnAction(reply.front);
        } catch (Exception) {}
    }

    const owner = ctx.connManager.getOwnerId(nid);
    const now = (Clock.currStdTime - 621_355_968_000_000_000L) / 10_000;
    const rejection = servicesCommandRejection(owner, cmd.userId, cmd.timestampMs, now);
    if (rejection.length) {
        note("warn", "Services command rejected", rejection);
        burnPayload(cmd.userId);
        answer(cmd.userId, rejection == "request_expired" ? ServiceStatus.stale : ServiceStatus.unavailable,
            rejection);
        return;
    }

    ServicesPayloadReference reference;
    try reference = ServicesPayloadReference.fromJson(parseJsonString(cmd.text), owner, networkId);
    catch (Exception) {
        note("warn", "Services command with an invalid payload reference", "invalid_reference");
        burnPayload(owner);
        answer(owner, ServiceStatus.unavailable, "invalid_reference");
        return;
    }
    if (reference.requestId != requestId) {
        note("warn", "Services reference names another request", "invalid_reference");
        burnPayload(owner);
        answer(owner, ServiceStatus.unavailable, "invalid_reference");
        return;
    }
    // Only the engine the network is assigned to may consume or answer.
    try {
        if (redis.getDb().hget!string(RedisKeys.networkAssignments(), networkId) != serverId) {
            note("info", "Services command for a network assigned elsewhere ignored", "not_assigned");
            return;
        }
    } catch (Exception) {
        note("warn", "Services assignment check failed", "redis_error");
        answer(owner, ServiceStatus.unavailable, "engine_unavailable");
        return;
    }

    string raw;
    try {
        auto reply = redis.getDb().eval!string(SERVICES_PAYLOAD_TAKE_LUA, [reference.payloadKey]);
        raw = reply.empty ? "" : reply.front;
    }
    catch (Exception) {
        note("warn", "Services payload fetch failed", "redis_error");
        answer(owner, ServiceStatus.unavailable, "engine_unavailable");
        return;
    }
    if (!raw.length) {
        note("info", "Services payload absent, expired or already consumed", "payload_unavailable");
        answer(owner, ServiceStatus.stale, "payload_unavailable");
        return;
    }
    if (raw.length > ServicesKeys.maxPayloadBytes) {
        note("warn", "Services payload over the size bound", "payload_invalid");
        answer(owner, ServiceStatus.unavailable, "payload_invalid");
        return;
    }
    learnAction(raw);

    auto client = ctx.connManager.getClient(nid);
    if (manual) {
        ServicesManualPayload p;
        try p = ServicesManualPayload.fromJson(parseJsonString(raw));
        catch (Exception) {
            note("warn", "Manual services payload invalid", "payload_invalid");
            return;
        }
        if (p.requestId != requestId) {
            note("warn", "Manual services payload names another request", "payload_invalid");
            return;
        }
        if (client is null) {
            note("info", "Manual services line for a network without a client dropped", "offline");
            return;
        }
        client.sendManualService(p);
        return;
    }

    ServicesRequest request;
    try request = ServicesRequest.fromJson(parseJsonString(raw));
    catch (Exception) {
        note("warn", "Services request payload invalid", "invalid_request");
        answer(owner, ServiceStatus.unavailable, "invalid_request");
        return;
    }
    if (request.requestId != requestId) {
        note("warn", "Services payload names another request", "invalid_request");
        answer(owner, ServiceStatus.unavailable, "invalid_request");
        return;
    }
    if (client is null) {
        ServicesResult r;
        r.network = networkId;
        r.requestId = requestId;
        r.action = request.action;
        r.status = ServiceStatus.unavailable;
        r.reasonCode = "offline";
        writeServicesReply(redis, serverId, owner, networkId, r);
        return;
    }
    const ownerScope = owner;
    client.executeServices(request, (ServicesResult r) {
        r.network = networkId;
        // The connection may call back from its read fiber: never block it
        // on Redis.
        runTask(() nothrow {
            try writeServicesReply(redis, serverId, ownerScope, networkId, r);
            catch (Exception) {}
        });
    }, cmd.timestampMs); // every bound counts from the gateway's issue time
}

/// Fenced, bounded, expiring reply write. Never throws.
private void writeServicesReply(RedisStorage redis, string serverId, string owner, string networkId,
        ServicesResult r) nothrow {
    import ircfiber.services.protocol : ServicesKeys;
    try {
        const key = ServicesKeys.reply(owner, networkId, r.requestId);
        auto reply = redis.getDb().eval!long(SERVICES_REPLY_LUA, [RedisKeys.networkAssignments(), key],
            networkId, serverId, boundedServicesReply(r), ServicesKeys.replyTTLSeconds.to!string);
        const written = reply.empty ? 0 : reply.front;
        if (written != 1)
            logJsonMap("info", "services", "Services reply not written: network no longer assigned here",
                ["networkId": networkId, "requestId": r.requestId, "event": "services_reply_unassigned"]);
    } catch (Exception e) {
        try logJsonMap("warn", "services", "Services reply write failed",
            ["networkId": networkId, "requestId": r.requestId, "event": "services_reply_fail"]);
        catch (Exception) {}
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
    if (j["ident"].type != Json.Type.undefined) cfg.ident = sanitizeIdent(j["ident"].get!string);
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
    if (j["avatarUrl"].type == Json.Type.string) cfg.avatarUrl = j["avatarUrl"].get!string;
    if (j["defaultAvatarUrl"].type == Json.Type.string) cfg.defaultAvatarUrl = j["defaultAvatarUrl"].get!string;
    if (j["profileMetadata"].type == Json.Type.object)
        foreach (string k, v; j["profileMetadata"])
            if (v.type == Json.Type.string) cfg.profileMetadata[k] = v.get!string;
    if (j["monitoredNicks"].type == Json.Type.array)
        foreach (v; j["monitoredNicks"])
            if (v.type == Json.Type.string) cfg.monitoredNicks ~= v.get!string;
    if (j["systemManaged"].type == Json.Type.bool_) cfg.systemManaged = j["systemManaged"].get!bool;
    if (j["disabled"].type == Json.Type.bool_) cfg.disabled = j["disabled"].get!bool;
    if (j["servicesProvisioningPending"].type == Json.Type.bool_)
        cfg.servicesProvisioningPending = j["servicesProvisioningPending"].get!bool;
    string servicesError;
    cfg.services = decodeStoredServicesConfig(j["services"], servicesError);
    if (servicesError.length) logWarn("Invalid services config in engine control; trust cleared");
    return cfg;
}
