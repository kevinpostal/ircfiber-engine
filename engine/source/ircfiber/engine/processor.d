module ircfiber.engine.processor;

import vibe.core.core : runTask, yield;
import vibe.core.log;

import std.uuid : parseUUID;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : Network;
import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.engine.state : writeStateSnapshotForNetwork;
import ircfiber.redis.protocol : RedisKeys;

/// IRC server-log phase events that are purely transient connection-state
/// (TCP open, TLS handshake, registration steps). They never appear in
/// OOB replay because each connection attempt has its own set, and the
/// dedup set in Redis (`dedup:<srv>:<net>:<buf>`) already prevents them
/// from being inserted twice. Excluding them from Mongo skips 5-7 writes
/// per connect, removing the 5-10s latency window that made the live UI
/// feel frozen.
///
/// Server-log phases are emitted via `IRCRawEvent.makeServerLog()` which
/// sets `command = "NOTICE"` and tags the event with the phase name
/// (`connecting`, `tcp_open`, `tls`, `tls_done`, `registering`, etc).
/// We also exclude the synthetic CONNECT / DISCONNECT lifecycle events
/// used by the engine to signal handoff boundaries — those are
/// transient by design (one per attempt) and the engine's own
/// in-memory ConnectionState is the authoritative source.
private bool isTransientServerLogPhase(ref IRCRawEvent event) nothrow @safe {
    if (event.command == "CONNECT") return true;
    if (event.command == "DISCONNECT") return true;
    if (event.command == "NOTICE") {
        // Server-log phase is tagged onto the NOTICE. Real IRC NOTICEs
        // (e.g. "* Looking up your hostname") carry no phase tag.
        try {
            if (event.getTag("phase").length > 0) return true;
        } catch (Exception) { /* no tags → not a phase event */ }
    }
    return false;
}

/**
 * Event processor for decentralized connection server.
 *
 * Publishes events to user channels and writes state snapshots
 * with server ID attribution. This allows the gateway to track
 * which server manages each network.
 *
 * Every event is also persisted to MongoDB via MessageRepository for
 * infinite scrollback history (IRCCloud-style: Redis is the hot cache,
 * MongoDB is the permanent store).
 */
void startEventProcessor(ref EngineContext ctx) {
    auto serverId = ctx.localServer.serverId;

    while (true) {
        bool processedAny = false;

        // Drain up to 50 events per iteration before yielding.  During
        // ASCII art bursts (40+ PRIVMSG lines arriving in a single TCP
        // read) this keeps all events in the same fiber slice so Redis
        // operations can be batched by the client and the WebSocket
        // gateway receives the burst as a contiguous stream.
        foreach (batch; 0 .. 50) {
            try {
                IRCRawEvent event;
                if (!ctx.eventChannel.tryConsumeOne(event)) break;
                processedAny = true;

                // IRCCloud-style: assign a global sequential eid to every
                // event. This is the primary key for pagination, dedup,
                // and stream resume — always present, never missing.
                event.eid = ctx.redis.incr(RedisKeys.globalEid());
                logDebug("Engine event [server=%s]: %s %s (eid=%d)", serverId, event.network, event.command, event.eid);

                // CHANNEL_LIST chunks are publish-only: they are a live
                // reply to a /LIST request, not scrollback. Never written
                // to Redis scrollback, Mongo, or the user stream (a 20k
                // channel network would otherwise fill all three).
                const bool transientList = event.command == "CHANNEL_LIST";

                // Store buffer with server namespace (prevents ID collision).
                // The buffer is the source of truth for the _server
                // channel scrollback; the MongoDB write below makes it
                // durable across restarts and Redis flushes.
                if (!transientList) ctx.bufferManager.appendIRCEvent(event, serverId);

                // ── MongoDB persistence — async, AFTER publish ──
                // The 2026-07-13 fix moves the Mongo write BACK to a
                // fire-and-forget task (it was sync on the hot path from
                // 2026-07-07 to 2026-07-13, but that added 1+ second of
                // Mongo round-trip latency to every phase event —
                // turning a real-time connection log stream into a
                // 5-10 second "connected" surprise, since each phase
                // (queued → connecting → tcp_open → tls → tls_done →
                // registering → welcome) waited on a Mongo write before
                // hitting the live stream).
                //
                // Durability story: Redis is the hot cache AND the
                // scrollback source of truth (appendIRCEvent above has
                // already written the event to `scrollback:<srv>:<net>:
                // <buf>` and `dedup:<srv>:<net>:<buf>`). Mongo is only
                // for OOB replay when a client connects to a cold
                // buffer. A gateway crash between Redis publish and
                // Mongo write means OOB replay misses a few seconds of
                // events for that one client session — acceptable vs
                // the alternative of making the live UI feel frozen
                // during every connection attempt.
                //
                // Transient phase events (server-log phases like
                // tcp_open / tls / tls_done) are SKIPPED entirely from
                // Mongo. They never reach the OOB replay path because
                // they're per-connection state that only exists in
                // Redis's `_server` scrollback (with the eid-tied dedup
                // set above already preventing duplicates). Skipping
                // them cuts the Mongo write load for a single connect
                // from ~7 writes to ~2 (welcome + the lifecycle events).
                Network matchedNet;
                bool foundNet = false;
                string userIdStr = "";
                foreach (net; ctx.connManager.getNetworks()) {
                    if (net.config.id.toString() == event.networkId) {
                        userIdStr = ctx.connManager.getOwnerId(net.config.id);
                        matchedNet = net;
                        foundNet = true;
                        break;
                    }
                }
                if (foundNet && userIdStr.length > 0 && !transientList && !isTransientServerLogPhase(event)) {
                    runTask(() nothrow {
                        try {
                            ctx.messageRepo.appendIRCEvent(event, serverId);
                        } catch (Exception e) {
                            try logWarn("MongoDB write failed for event %s/%s eid=%d: %s " ~
                                "(event still in Redis scrollback)",
                                event.network, event.command, event.eid, e.msg);
                            catch (Exception) {}
                        }
                    });
                }

                // ── Publish to live stream AFTER durability ──
                // Order matters: the durable write is the source of
                // truth. Only after it's committed do we notify the
                // gateway, so a client that misses the frame can
                // recover from Mongo via the next replay/oob.
                auto json = event.toCompactJson();
                json["y"] = "irc_event";
                json["serverId"] = serverId;
                auto msg = json.toString();

                if (userIdStr.length > 0) {
                    ctx.redis.publish(RedisKeys.events(userIdStr), msg);
                    if (!transientList) {
                        auto streamKey = RedisKeys.userStream(userIdStr);
                        ctx.redis.getDb().lpush(streamKey, msg);
                        ctx.redis.getDb().ltrim(streamKey, 0, 999);
                    }
                }

                if (foundNet && (event.command == "001"
                    || event.command == "CONNECT" || event.command == "CONNECTED"
                    || event.command == "DISCONNECT" || event.command == "DISCONNECTED"
                    || event.command == "JOIN"
                    || event.command == "PART" || event.command == "KICK"
                    || event.command == "366"
                    // W1-T01: CONNECTION_RETRY_STATUS + CONNECTION_FAIL
                    // are the synthetic events that carry structured
                    // retry/fail payloads to the frontend. Writing a
                    // snapshot immediately on receipt ensures the WS
                    // sync payload's `retryStatus` / `failInfo` fields
                    // are fresh for any new client connection without
                    // waiting for the 10s heartbeat cycle. Without
                    // this the user-facing banner can lag the engine
                    // state by up to 10s on a fast-fail network.
                    || event.command == "CONNECTION_RETRY_STATUS"
                    || event.command == "CONNECTION_FAIL")) {
                    try {
                        writeStateSnapshotForNetwork(ctx, matchedNet, serverId);
                    } catch (Exception e) {
                        logWarn("Failed to snapshot state for %s: %s", event.network, e.msg);
                    }
                }

                // Persist autoJoinChannels changes to MongoDB when we join/part/kick
                if (foundNet && (event.command == "JOIN" || event.command == "PART" || event.command == "KICK")) {
                    auto client = ctx.connManager.getClient(matchedNet.config.id);
                    if (client !is null) {
                        bool isOwnEvent = false;
                        if (event.command == "JOIN" && event.nick == client.getCurrentNick) {
                            isOwnEvent = true;
                        } else if (event.command == "PART" && event.nick == client.getCurrentNick) {
                            isOwnEvent = true;
                        } else if (event.command == "KICK") {
                            auto params = event.getParams();
                            if (params.length >= 2 && params[1] == client.getCurrentNick) {
                                isOwnEvent = true;
                            }
                        }
                        if (isOwnEvent) {
                            runTask(() nothrow {
                                try {
                                    auto ownerIdStr = ctx.connManager.getOwnerId(matchedNet.config.id);
                                    if (ownerIdStr.length > 0) {
                                        ctx.networkRepo.save(client.getConfig, parseUUID(ownerIdStr));
                                    }
                                } catch (Exception e) {
                                    logWarn("Failed to persist autoJoinChannels for %s: %s", event.network, e.msg);
                                }
                            });
                        }
                    }
                }
            } catch (Exception e) {
                logError("Engine event processor error: %s", e.msg);
            }
        }
        // Yield only when no events were processed, so other fibers
        // (IRC connection, etc.) get CPU time.
        if (!processedAny) yield();
    }
}
