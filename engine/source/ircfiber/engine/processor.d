module ircfiber.engine.processor;

import vibe.core.core : runTask, yield;
import vibe.core.log;

import std.uuid : parseUUID;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : Network, normalizeChannelName;
import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.engine.state : writeStateSnapshotForNetwork;
import ircfiber.redis.protocol : RedisKeys, StateTTL;
import ircfiber.engine.session_snapshot : HistoryRecovery, historyRecoveryFromJSON,
    historyRecoveryToJSON;
import ircfiber.irc.mls_peer : normalizeFiberChannel;
import vibe.data.json : Json, parseJsonString;

import ircfiber.engine.archive_spool : ArchiveAdmission;
import ircfiber.logging : logJsonMap;
import std.datetime : Clock;
import std.conv : to;

private long lastArchiveRejectionNotice;
private void noteArchiveAdmission(ArchiveAdmission admission) {
    if (admission == ArchiveAdmission.queued) return;
    const now = Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L;
    if (now - lastArchiveRejectionNotice < 60_000) return;
    lastArchiveRejectionNotice = now;
    logJsonMap("error", "engine", "Archive admission rejected; live delivery preserved",
        ["event":"archive_gap", "admission":admission.to!string]);
}

private void archiveRename(ref EngineContext ctx, string serverId, string networkId,
        string from, string toChannel, long cutoffEid) {
    auto admission = ArchiveAdmission.unavailable;
    if (ctx.archiveSpool !is null) {
        string pendingOwner;
        if (ctx.archiveControl !is null && ctx.connManager !is null)
            pendingOwner = ctx.archiveControl.pendingScopeOwner(networkId,
                ctx.connManager.getOwnerId(parseUUID(networkId[])));
        if (ctx.archiveControl !is null
                && (ctx.archiveControl.scopeReady(networkId) || pendingOwner.length)
                && ctx.archiveControl.orderFrozenControls(ctx, networkId, cutoffEid))
            admission = ctx.archiveSpool.tryRename(serverId, networkId,
                normalizeChannelName(from), normalizeChannelName(toChannel), cutoffEid,
                Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L, pendingOwner);
        else ctx.archiveSpool.reportAdmissionUnavailable();
    }
    noteArchiveAdmission(admission);
}

private struct HistoryCheckpoint {
    string requestId;
    string connectionEpoch;
    string target;
    HistoryRecovery recovery;
}

private HistoryCheckpoint parseHistoryCheckpoint(string text) {
    auto j = parseJsonString(text);
    if (j.type != Json.Type.object || j["requestId"].type != Json.Type.string
            || !j["requestId"].get!string.length
            || j["connectionEpoch"].type != Json.Type.string
            || !j["connectionEpoch"].get!string.length
            || j["target"].type != Json.Type.string)
        throw new Exception("Invalid history checkpoint envelope");
    HistoryCheckpoint checkpoint;
    checkpoint.requestId = j["requestId"].get!string;
    checkpoint.connectionEpoch = j["connectionEpoch"].get!string;
    checkpoint.target = j["target"].get!string;
    checkpoint.recovery = historyRecoveryFromJSON(j["recovery"]);
    if (checkpoint.recovery.target != checkpoint.target)
        throw new Exception("History checkpoint target mismatch");
    return checkpoint;
}

private string historyStorageKey(string networkId, string requestId, string epoch) {
    return networkId ~ "\0" ~ epoch ~ "\0" ~ requestId;
}

private string historyCheckpointField(string target, string[string] isupport) {
    if (target.length == 0 || target == "*targets") return "*targets";
    string mapping = "rfc1459";
    if (auto value = "CASEMAPPING" in isupport) mapping = *value;
    return normalizeFiberChannel(target, mapping);
}

private bool isHistorical(ref const IRCRawEvent event) {
    return event.getTag("batch") == "chathistory";
}

/// Runs in the same ordered drain as the page rows, before assigning an eid.
/// Redis scrollback/dedup remains authoritative, independent of archive replay.
private void consumeHistoryCheckpoint(ref EngineContext ctx, ref IRCRawEvent event,
        ref bool[string] failedStorage) {
    auto checkpoint = parseHistoryCheckpoint(event.text);
    const failureKey = historyStorageKey(event.networkId, checkpoint.requestId, checkpoint.connectionEpoch);
    auto nid = parseUUID(event.networkId[]);
    auto client = ctx.connManager.getClient(nid);
    if (client is null || client.getConnectionEpoch() != checkpoint.connectionEpoch
            || !client.ownsHistoryRequest(checkpoint.requestId, checkpoint.connectionEpoch)) {
        failedStorage.remove(failureKey);
        return;
    }
    bool committed;
    try {
        import ircfiber.irc.dial_guard : ownsNetworkForDial;
        const serverId = ctx.localServer.serverId;
        auto row = ctx.networkRepo.findByIdWithUser(nid);
        const owner = ctx.connManager.getOwnerId(nid);
        if (owner.length && owner == row.userId.toString() && row.config.id == nid
                && !row.config.disabled && !row.config.servicesProvisioningPending
                && ownsNetworkForDial(ctx.redis, serverId, event.networkId)
                && failureKey !in failedStorage
                && ctx.archiveControl !is null && ctx.archiveControl.scopeReady(event.networkId)
                && ctx.connManager.getClient(nid) is client
                && client.ownsHistoryRequest(checkpoint.requestId, checkpoint.connectionEpoch)) {
            const field = historyCheckpointField(checkpoint.target, client.getIsupport());
            // Fence the write itself, not just the preceding yielding lookups.
            auto result = ctx.redis.getDb().eval!string(
                "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 then return '0' end "
                ~ "redis.call('HSET',KEYS[3],ARGV[3],ARGV[4]); return '1'",
                [RedisKeys.networkAssignments(), RedisKeys.routingMove(event.networkId),
                    RedisKeys.historyRecovery(event.networkId)],
                [event.networkId, serverId, field, historyRecoveryToJSON(checkpoint.recovery).toString()]);
            committed = !result.empty && result.front == "1";
        }
    } catch (Exception e) {
        logWarn("History checkpoint storage failed for %s: %s", event.networkId, e.msg);
    }
    failedStorage.remove(failureKey);
    // A replacement client must never acknowledge its predecessor's page.
    if (ctx.connManager.getClient(nid) is client
            && client.ownsHistoryRequest(checkpoint.requestId, checkpoint.connectionEpoch))
        ctx.connManager.confirmHistoryPage(nid, checkpoint.requestId, committed);
}

private void noteHistoryStorageFailure(ref EngineContext ctx, ref IRCRawEvent event,
        ref bool[string] failedStorage) {
    const requestId = event.getTag("history_request");
    const epoch = event.getTag("history_epoch");
    if (!requestId.length || !epoch.length) return;
    failedStorage[historyStorageKey(event.networkId, requestId, epoch)] = true;
    if (auto client = ctx.connManager.getClient(parseUUID(event.networkId[])))
        client.failHistoryStorage(requestId, epoch);
}

private void noteAcceptedLiveHistory(ref EngineContext ctx, ref IRCRawEvent event) {
    if (isHistorical(event)) return;
    if (auto client = ctx.connManager.getClient(parseUUID(event.networkId[])))
        client.noteAcceptedLiveHistory(event);
}

/// Private BNC envelopes never acquire an eid, enter storage, or touch the
/// resumable user stream. The network's canonical owner selects the channel.
private void publishPrivateBncEvent(ref EngineContext ctx, ref IRCRawEvent event) {
    const response = event.command == "BNC_RESPONSE";
    const raw = response ? event.bncResponsePayload : event.bncPresencePayload;
    if (!raw.length || isHistorical(event)) return;
    auto payload = parseJsonString(raw);
    if (payload.type != Json.Type.object || payload["nid"].type != Json.Type.string
            || payload["nid"].get!string != event.networkId) return;
    const owner = ctx.connManager.getOwnerId(parseUUID(event.networkId[]));
    if (!owner.length) return;
    payload["type"] = response ? "bnc_response" : "bnc_presence";
    // Fence publication as well as admission against an assignment move.
    auto publication = ctx.redis.getDb().eval!string(
        "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 then return '0' end "
        ~ "redis.call('PUBLISH',KEYS[3],ARGV[3]); return '1'",
        [RedisKeys.networkAssignments(), RedisKeys.routingMove(event.networkId), RedisKeys.events(owner)],
        [event.networkId, ctx.localServer.serverId, payload.toString()]);
    if (publication.empty || publication.front != "1") return;
}

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
/// used by the engine to signal attempt boundaries — those are
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
 * Accepted non-transient events enter the bounded durable journal for strict
 * Mongo replay. Rejected archival admission is an explicit gap, never a reason
 * to hold live IRC delivery or create waiting per-event fibers.
 */
void startEventProcessor(ref EngineContext ctx) {
    auto serverId = ctx.localServer.serverId;
    bool[string] failedHistoryStorage;

    while (true) {
        bool processedAny = false;

        // Drain up to 50 events per iteration before yielding.  During
        // ASCII art bursts (40+ PRIVMSG lines arriving in a single TCP
        // read) this keeps all events in the same fiber slice so Redis
        // operations can be batched by the client and the WebSocket
        // gateway receives the burst as a contiguous stream.
        foreach (batch; 0 .. 50) {
            IRCRawEvent event;
            bool storageResolved;
            try {
                storageResolved = false;
                if (!ctx.eventChannel.tryConsumeOne(event)) break;
                processedAny = true;

                if (event.command == "ARCHIVE_SHUTDOWN_BARRIER") {
                    storageResolved = true;
                    if (ctx.archiveControl !is null && ctx.archiveControl.consumeShutdownBarrier(event))
                        return;
                    continue;
                }

                if (event.command == "ARCHIVE_MOVE_BARRIER") {
                    storageResolved = true;
                    if (ctx.archiveControl !is null) ctx.archiveControl.consumeMoveBarrier(ctx, event);
                    continue;
                }

                if (event.command == "ARCHIVE_CONTROL") {
                    storageResolved = true;
                    if (ctx.archiveControl !is null) ctx.archiveControl.consume(ctx, event);
                    continue;
                }

                // A network removed on this engine keeps emitting for a
                // moment: stopping the client produces the QUIT echo and
                // the server's `ERROR :Quit:`. Persisting those re-creates
                // the scrollback the delete path just cleared, which left a
                // deleted network's rooms readable at
                // /irc/<name>/channel/%23chan. Nothing downstream wants
                // them, so drop them here — before the eid is spent.
                if (ctx.connManager !is null && ctx.connManager.isRemoved(event.networkId)) {
                    logDebug("Dropping %s for removed network %s",
                        event.command, event.networkId);
                    continue;
                }

                if (event.command == "HISTORY_CHECKPOINT") {
                    consumeHistoryCheckpoint(ctx, event, failedHistoryStorage);
                    continue;
                }
                if (event.command == "BNC_RESPONSE" || event.command == "BNC_PRESENCE") {
                    storageResolved = true;
                    publishPrivateBncEvent(ctx, event);
                    continue;
                }
                const historical = isHistorical(event);

                // Internal identity changes refresh proof immediately, without
                // exposing a synthetic chat event or spending a history eid.
                if (!historical && event.command == "own_prefix") {
                    foreach (net; ctx.connManager.getNetworks()) {
                        if (net.config.id.toString() != event.networkId) continue;
                        writeStateSnapshotForNetwork(ctx, net, serverId);
                        break;
                    }
                    continue;
                }

                // IRCCloud-style: assign a global sequential eid to every
                // event. This is the primary key for pagination, dedup,
                // and stream resume — always present, never missing.
                event.eid = ctx.redis.getDb().incr(RedisKeys.globalEid());
                logDebug("Engine event [server=%s]: %s %s (eid=%d)", serverId, event.network, event.command, event.eid);

                // Publish-only events: assigned an eid and published live,
                // but never written to Redis scrollback, Mongo, or the user
                // stream.
                //
                // CHANNEL_LIST chunks are a live reply to a /LIST request,
                // not scrollback (a 20k channel network would otherwise fill
                // all three sinks). WHO replies (352/354/315) are the same:
                // the connection only publishes the ones answering a
                // client's own WHO, and a big channel's roster would
                // otherwise land row by row in the `_server` scrollback.
                //
                // Non-ACTION CTCP (connection.d tags it `ctcp`, routed to
                // `_server`) is a live server-log diagnostic. Its raw
                // parameters can carry PING tokens or DCC addresses, so it
                // is deliberately never persisted anywhere.
                //
                // Safe identity/epoch and capability invalidations for the
                // owner's browsers: live only, never scrollback, Mongo or
                // the user stream.
                const bool publishOnly = event.command == "CHANNEL_LIST"
                    || event.command == "352" || event.command == "354"
                    || event.command == "315"
                    || event.command == "SERVICES_STATE"
                    || event.command == "SERVICES_INVALIDATED"
                    || event.getTag("ctcp").length > 0;

                // Rename Redis immediately and journal the cutoff mutation at
                // this FIFO position before appending the renamed event.
                // A frozen purge follows the physical Redis lineage across
                // later successful renames, not the reusable channel spelling.
                if (!historical && event.command == "RENAME") {
                    try {
                        auto rp = event.getParams();
                        if (rp.length >= 2 && rp[0].length > 0 && rp[1].length > 0) {
                            ctx.bufferManager.renameBuffer(serverId, event.networkId, rp[0], rp[1]);
                            archiveRename(ctx, serverId, event.networkId, rp[0], rp[1], event.eid);
                        }
                    } catch (Exception e) {
                        logWarn("RENAME storage rename failed: %s", e.msg);
                    }
                }

                // Store buffer with server namespace (prevents ID collision).
                // Redis is the hot scrollback/checkpoint authority. Journal
                // admission below is independent and reports gaps explicitly.
                //
                // The dedup verdict is authoritative for ALL THREE sinks.
                // It used to gate only the Redis scrollback while Mongo and
                // the live WebSocket publish below ran unconditionally, so a
                // re-emitted event (an IRCv3 batch replayed on rejoin, a
                // roster fan-out that matched a nick twice) reached the
                // browser as a second row with its own id and eid — nothing
                // downstream can collapse those — while the scrollback kept
                // exactly one. That is the "it showed my JOIN twice" class
                // of bug: duplicated live rows over a clean scrollback.
                const stored = publishOnly || ctx.bufferManager.appendIRCEvent(event, serverId);
                // A false dedup verdict means already accepted, never storage failure.
                storageResolved = true;
                if (!publishOnly) noteAcceptedLiveHistory(ctx, event);
                if (!stored) {
                    logDebug("Dropping duplicate %s eid=%d for %s/%s (already in scrollback)",
                        event.command, event.eid, event.network,
                        event.channel.length ? event.channel : "_server");
                    continue;
                }

                // Archive admission is bounded/nonblocking. Redis acceptance,
                // checkpoints and live delivery do not wait for disk or Mongo.
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
                // stopNetworkForMove removes the active client only after its
                // producer loops stop. Preserve canonical attribution for the
                // already-queued tail until the final processor barrier.
                if (!userIdStr.length && ctx.archiveControl !is null)
                    userIdStr = ctx.archiveControl.movingOwner(event.networkId);
                auto json = event.toCompactJson();
                if (userIdStr.length > 0 && !publishOnly
                        && !isTransientServerLogPhase(event) && event.getTag("archive_gap").length == 0) {
                    auto admission = ArchiveAdmission.unavailable;
                    if (ctx.archiveSpool !is null) {
                        string pendingOwner;
                        if (ctx.archiveControl !is null)
                            pendingOwner = ctx.archiveControl.pendingScopeOwner(event.networkId, userIdStr);
                        if (ctx.archiveControl !is null
                                && (ctx.archiveControl.scopeReady(event.networkId) || pendingOwner.length))
                            admission = ctx.archiveSpool.tryAppend(serverId, event.networkId,
                                event.channel.length ? normalizeChannelName(event.channel) : "_server",
                                event.eid, json.toString(), pendingOwner);
                        else ctx.archiveSpool.reportAdmissionUnavailable();
                    }
                    noteArchiveAdmission(admission);
                }

                // Only the live/user-stream envelope gets publication fields.
                json["y"] = "irc_event";
                json["serverId"] = serverId;
                auto msg = json.toString();

                if (userIdStr.length > 0) {
                    ctx.redis.publish(RedisKeys.events(userIdStr), msg);
                    if (!publishOnly) {
                        auto streamKey = RedisKeys.userStream(userIdStr);
                        ctx.redis.getDb().lpush(streamKey, msg);
                        ctx.redis.getDb().ltrim(streamKey, 0, 999);
                        ctx.redis.getDb().expire(streamKey, StateTTL.USER_STREAM_TTL);
                    }
                }

                if (!historical && foundNet && (event.command == "001"
                    || event.command == "CONNECT" || event.command == "CONNECTED"
                    || event.command == "DISCONNECT" || event.command == "DISCONNECTED"
                    || event.command == "JOIN"
                    || event.command == "PART" || event.command == "KICK"
                    || event.command == "366"
                    // account-notify: a login/logout must republish the
                    // `accounts` map so member-list badges don't wait for
                    // the next JOIN/heartbeat.
                    || event.command == "ACCOUNT"
                    // End of a client's WHO: a `WHO #chan %na` (the E2EE
                    // roster probe) has filled `accounts` for the channel.
                    || event.command == "315"
                    // draft/metadata-2: a key change republishes the
                    // `userMetadata` / `channelMetadata` maps so a
                    // reloading client sees it at once.
                    || event.command == "METADATA"
                    // Member state the snapshot carries (away, host,
                    // realname, caps, renamed channel, MONITOR status).
                    || event.command == "AWAY" || event.command == "CHGHOST"
                    || event.command == "NICK" || event.command == "you_nickchange"
                    || event.command == "396"
                    || event.command == "SETNAME" || event.command == "CAP"
                    || event.command == "RENAME"
                    || event.command == "730" || event.command == "731"
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
                    || event.command == "CONNECTION_FAIL"
                    // Observed services login / connection epoch changed.
                    || event.command == "SERVICES_STATE")) {
                    try {
                        writeStateSnapshotForNetwork(ctx, matchedNet, serverId);
                    } catch (Exception e) {
                        logWarn("Failed to snapshot state for %s: %s", event.network, e.msg);
                    }
                }

                // NICK-follow storage rename (IRCCloud rename model): when a
                // DM counterparty changes nick, rename Redis and journal the
                // ordered Mongo cutoff mutation so history follows
                // the conversation across reloads/backfill. Only for the
                // base event the connection tagged `query_follow`, i.e. the
                // renamer is verifiably the person the DM was held with
                // (connection.d `dmFollowsNick`) — never on the nick alone,
                // and never on the per-channel dups.
                // Runs INLINE (not runTask): a follow-up PRIVMSG under the
                // new nick must append after the rename, otherwise RENAMENX
                // sees an existing destination and the history splits.
                // Best-effort try/catch: storage must never break the loop.
                if (!historical && userIdStr.length > 0 && event.command == "NICK" && event.channel.length == 0
                    && event.getTag("query_follow").length > 0) {
                    try {
                        auto nickParams = event.getParams();
                        if (nickParams.length > 0 && event.nick.length > 0) {
                            string newNick = nickParams[$ - 1];
                            if (newNick.length > 0) {
                                ctx.bufferManager.renameBuffer(
                                    serverId, event.networkId, event.nick, newNick);
                                archiveRename(ctx, serverId, event.networkId, event.nick, newNick, event.eid);
                            }
                        }
                    } catch (Exception e) {
                        logWarn("NICK storage rename failed: %s", e.msg);
                    }
                }

                // Persist autoJoinChannels changes to MongoDB when we join/part/kick
                if (!historical && foundNet && (event.command == "JOIN" || event.command == "PART" || event.command == "KICK"
                                 || event.command == "RENAME")) {
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
                        } else if (event.command == "RENAME") {
                            // Whoever renamed it, our autojoin list followed.
                            isOwnEvent = true;
                        }
                        if (isOwnEvent) {
                            runTask(() nothrow {
                                try {
                                    import ircfiber.irc.dial_guard : ownsNetworkForDial;
                                    const ownerIdStr = ctx.connManager.getOwnerId(matchedNet.config.id);
                                    auto row = ctx.networkRepo.findByIdWithUser(matchedNet.config.id);
                                    if (ownerIdStr.length > 0 && row.userId.toString() == ownerIdStr
                                            && ownsNetworkForDial(ctx.redis, serverId, event.networkId)) {
                                        // Runtime channel bookkeeping must not
                                        // write an older routing/IID/tenant copy.
                                        row.config.autoJoinChannels = client.getConfig.autoJoinChannels;
                                        row.config.partedChannels = client.getConfig.partedChannels;
                                        ctx.networkRepo.save(row.config, row.userId);
                                    }
                                } catch (Exception e) {
                                    logWarn("Failed to persist autoJoinChannels for %s: %s", event.network, e.msg);
                                }
                            });
                        }
                    }
                }
            } catch (Exception e) {
                if (!storageResolved && event.command != "HISTORY_CHECKPOINT") {
                    try noteHistoryStorageFailure(ctx, event, failedHistoryStorage);
                    catch (Exception failure) logWarn("Could not attribute history storage failure: %s", failure.msg);
                }
                logError("Engine event processor error: %s", e.msg);
            }
        }
        // Yield only when no events were processed, so other fibers
        // (IRC connection, etc.) get CPU time.
        if (!processedAny) yield();
    }
}

/// Standalone regressions for the exact internal envelope and storage attribution.
void historyCheckpointRegressionChecks() {
    auto record = parseJsonString(`{"version":1,"target":"#Case[","lowerBound":{"msgid":"z","timestampMs":1000,"hasServerTime":true},"nextBefore":{"msgid":"a","timestampMs":1000,"hasServerTime":true},"discoveryUpperBoundMs":2000,"state":"recovering","reasonCode":"reconnect"}`);
    auto envelope = Json.emptyObject;
    envelope["requestId"] = "request-1";
    envelope["connectionEpoch"] = "epoch-1";
    envelope["target"] = "#Case[";
    envelope["recovery"] = record;
    auto checkpoint = parseHistoryCheckpoint(envelope.toString());
    assert(checkpoint.requestId == "request-1" && checkpoint.connectionEpoch == "epoch-1");
    assert(checkpoint.recovery.lowerBound.msgid == "z");
    assert(checkpoint.recovery.nextBefore.msgid == "a");
    assert(historyCheckpointField(checkpoint.target, ["CASEMAPPING": "rfc1459"]) == "#case{");
    assert(historyCheckpointField(checkpoint.target, ["CASEMAPPING": "ascii"]) == "#case[");
    assert(historyCheckpointField("", null) == "*targets");
    assert(historyCheckpointField("*targets", null) == "*targets");
    bool[string] failures;
    const failureKey = historyStorageKey("network-1", checkpoint.requestId, checkpoint.connectionEpoch);
    failures[failureKey] = true;
    assert(historyStorageKey("network-1", "request-2", "epoch-1") !in failures);
    assert(historyStorageKey("network-1", "request-1", "epoch-2") !in failures);
    assert(historyStorageKey("network-2", "request-1", "epoch-1") !in failures);
    assert(failureKey in failures);
    foreach (kind; 0 .. 5) {
        auto invalid = parseJsonString(envelope.toString());
        if (kind == 0) invalid["target"] = "#other";
        if (kind == 1) invalid.remove("connectionEpoch");
        if (kind == 2) invalid["requestId"] = "";
        if (kind == 3) invalid["recovery"]["state"] = "done";
        if (kind == 4) invalid["recovery"]["version"] = 2;
        bool rejected;
        try parseHistoryCheckpoint(invalid.toString()); catch (Exception) rejected = true;
        assert(rejected, "Malformed or misattributed checkpoint must fail closed");
    }
    IRCRawEvent historical;
    historical.tagsJson = `{"batch":"chathistory","history_request":"request-1","history_epoch":"epoch-1"}`;
    assert(isHistorical(historical));
    // Internal attribution must not become a public compact key.
    auto compact = historical.toCompactJson();
    assert(compact["history_request"].type == Json.Type.undefined);
    assert(compact["history_epoch"].type == Json.Type.undefined);
    historical.tagsJson = `{"batch":"live-labeled-response"}`;
    assert(!isHistorical(historical), "A live response batch is not historical");
}
