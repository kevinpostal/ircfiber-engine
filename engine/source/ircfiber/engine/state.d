module ircfiber.engine.state;

import vibe.core.core : runTask, sleep;
import vibe.core.log;
import vibe.data.json : Json;
import core.time : seconds;
import std.datetime : Clock;
import std.string : startsWith;
import std.uni : toLower;

import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.models.network : Network;
import ircfiber.redis.protocol : RedisKeys, NetworkStateSnapshot,
    RetryStatus, FailInfoSnapshot, PROTOCOL_VERSION;
import std.conv : to;
private void runSafeTask(void delegate() dg) {
    runTask(() nothrow {
        try {
            dg();
        } catch (Exception e) {
            logError("Task crashed: %s", e.msg);
        }
    });
}

/// Starts the periodic state snapshot task.
void startStateSnapshotter(ref EngineContext ctx) {
    runSafeTask({
        while (true) {
            try {
                writeStateSnapshots(ctx);
            } catch (Exception e) {
                logError("State snapshotter error: %s", e.msg);
            }
            sleep(10.seconds);
        }
    });
}

/// Writes state snapshots for all networks to Redis.
void writeStateSnapshots(ref EngineContext ctx) {
    auto serverId = ctx.localServer.serverId;
    foreach (net; ctx.connManager.getNetworks()) {
        try {
            writeStateSnapshotForNetwork(ctx, net, serverId);
        } catch (Exception e) {
            logWarn("Failed to snapshot network %s: %s", net.config.name, e.msg);
        }
    }
    // Freeze protocol version so gateways (D or future Python) can assert
    // compatibility at startup. Not yet enforced — see docs/CONTRACT.md.
    try {
        ctx.redis.getDb().set(RedisKeys.protocolVersion(), PROTOCOL_VERSION.to!string);
    } catch (Exception e) {
        logWarn("Failed to write protocol version: %s", e.msg);
    }
}
/// Writes a state snapshot for a network (legacy non-decentralized).
void writeStateSnapshotForNetwork(ref EngineContext ctx, Network net) {
    // Legacy non-decentralized version
    writeStateSnapshotForNetwork(ctx, net, "");
}

/**
 * Write state snapshot with server attribution.
 * 
 * In decentralized mode, the serverId is included in the snapshot
 * and the Redis key is namespaced by server.
 */
void writeStateSnapshotForNetwork(ref EngineContext ctx, Network net, string serverId) {
    auto snap = NetworkStateSnapshot();
    snap.config = net.config.toJson();
    snap.connected = net.isConnected;
    snap.status = net.status;
    snap.currentNick = net.currentNick.length ? net.currentNick : net.config.nick;

    // Read away status from the IRC client
    const clientForAway = ctx.connManager.getClient(net.config.id);
    if (clientForAway) {
        snap.isAway = clientForAway.getIsAway;
        snap.awayMessage = clientForAway.getAwayMessage;
    }

    auto clientForCaps = ctx.connManager.getClient(net.config.id);
    if (clientForCaps) {
        snap.caps = clientForCaps.getAckedCaps();
    }

    snap.ownerId = ctx.connManager.getOwnerId(net.config.id);
    snap.serverId = serverId;  // NEW: attribute to server
    snap.partedChannels = net.config.partedChannels;
    snap.updatedAt = Clock.currTime.toUnixTime!long * 1000;

    auto buffers = Json.emptyArray;
    auto serverBuf = Json.emptyObject;
    serverBuf["name"] = Json("_server");
    serverBuf["type"] = Json("server");
    serverBuf["isJoined"] = Json(true);
    buffers ~= serverBuf;

    foreach (ch; ctx.connManager.getJoinedChannels(net.config.id)) {
        auto buf = Json.emptyObject;
        buf["name"] = Json(ch.startsWith("#") ? ch.toLower() : ch);
        buf["type"] = Json("channel");
        buf["isJoined"] = Json(true);
        buffers ~= buf;
    }
    foreach (ch; net.config.partedChannels) {
        auto normalized = ch.startsWith("#") ? ch.toLower() : ch;
        bool already = false;
        foreach (ref b; buffers) {
            if (b["name"].get!string == normalized) { already = true; break; }
        }
        if (!already) {
            auto buf = Json.emptyObject;
            buf["name"] = Json(normalized);
            buf["type"] = Json("channel");
            buf["isJoined"] = Json(false);
            buffers ~= buf;
        }
    }
    auto client = ctx.connManager.getClient(net.config.id);
    if (client) {
        foreach (q; client.getQueryBuffers) {
            auto buf = Json.emptyObject;
            buf["name"] = Json(q);
            buf["type"] = Json("query");
            buf["isJoined"] = Json(true);
            buffers ~= buf;
        }
    }
    snap.buffers = buffers;

    auto topics = ctx.connManager.getChannelTopics(net.config.id);
    auto topicJson = Json.emptyObject;
    if (topics !is null) {
        foreach (k, v; topics) topicJson[k.startsWith("#") ? k.toLower() : k] = Json(v);
    }
    snap.topics = topicJson;

    auto users = ctx.connManager.getChannelUsers(net.config.id);
    auto usersJson = Json.emptyObject;
    if (users !is null) {
        foreach (k, v; users) {
            auto arr = Json.emptyArray;
            foreach (n; v) arr ~= Json(n);
            usersJson[k.startsWith("#") ? k.toLower() : k] = arr;
        }
    }
    snap.users = usersJson;

    // IRCCloud-style: send the realname cache so the frontend can render
    // <span class="author-realname"> next to the nick. Keys are bare nicks.
    auto realnames = ctx.connManager.getRealnames(net.config.id);
    auto realnamesJson = Json.emptyObject;
    if (realnames !is null) {
        foreach (k, v; realnames) realnamesJson[k] = Json(v);
    }
    snap.realnames = realnamesJson;

    // Accounts from extended-join
    auto netAccounts = ctx.connManager.getAccounts(net.config.id);
    auto accountsJson = Json.emptyObject;
    if (netAccounts !is null) {
        foreach (k, v; netAccounts) accountsJson[k] = Json(v);
    }
    snap.accounts = accountsJson;

    // Idents from userhost-in-names / extended-join
    auto netIdents = ctx.connManager.getIdents(net.config.id);
    auto identsJson = Json.emptyObject;
    if (netIdents !is null) {
        foreach (k, v; netIdents) identsJson[k] = Json(v);
    }
    snap.idents = identsJson;

    // Full ISUPPORT inventory (every key=value or bare flag from the
    // server's 005 replies). Surfaced to the frontend in the WS sync
    // payload so the categorised "Server features" panel can render
    // from structured data instead of re-parsing the 005 message
    // stream. Empty during the brief window between connect-start and
    // welcome — the frontend falls back to its own parsing during that
    // interval.
    auto clientForIsupport = ctx.connManager.getClient(net.config.id);
    if (clientForIsupport) {
        snap.isupport = clientForIsupport.getIsupport();
    }

    // W1-T01-rev1: structured retry + fail info from the engine's
    // reconnect loop. Populated every heartbeat cycle (10s) so a
    // fresh WS sync arriving on a stalled network still sees the
    // current attempt count + next-retry deadline. The
    // `processor.d` event loop also triggers an immediate snapshot
    // write on every CONNECTION_RETRY_STATUS / CONNECTION_FAIL event
    // for real-time updates without waiting for the next heartbeat.
    //
    // Retry status is nullable on the engine getter
    // (PersistentIRCClient.getRetryStatus returns
    // `Nullable!RetryStatus`) and on the snapshot
    // (NetworkStateSnapshot.retryStatus is gated by
    // `hasRetryStatus`). When the engine reports a null retry
    // (network is healthy / freshly reset), we mark the snapshot as
    // "no retry" so the WS sync payload omits the field entirely
    // rather than serialising a zero-valued `{0, 0, 0}` object that
    // would mislead the frontend's nullable check. The protocol
    // layer's `fromJson` treats a missing retryStatus field as
    // `hasRetryStatus = false` so legacy snapshots still deserialise
    // cleanly.
    auto clientForRetry = ctx.connManager.getClient(net.config.id);
    if (clientForRetry) {
        // The engine's RetryStatus (in ircfiber.irc.connection) is a
        // separate type from the protocol's RetryStatus (in
        // ircfiber.redis.protocol) — they have the same field layout
        // but live in different layers so the protocol doesn't leak
        // engine-side dependencies. Copy field-by-field here.
        auto rsNullable = clientForRetry.getRetryStatus();
        if (rsNullable.isNull) {
            // Healthy / freshly reset — mark no retry on the snapshot.
            snap.retryStatus = RetryStatus.init;
            snap.hasRetryStatus = false;
        } else {
            auto rs = rsNullable.get();
            snap.retryStatus = RetryStatus(rs.attemptCount, rs.nextRetryAtMs, rs.delayMs);
            snap.hasRetryStatus = true;
        }
        // failInfo is populated from a client-side scratch field
        // (`lastFailInfo`) that the disconnect path writes alongside
        // the legacy `lastDisconnectReason` string — see
        // connection.d emitConnectionFail. When the client is null
        // (race during engine restart) or lastFailInfo is empty
        // (network is healthy), we leave failInfo default-empty so
        // the WS sync payload omits the field.
        const fi = clientForRetry.getLastFailInfo();
        if (fi.type_.length > 0 || fi.reason.length > 0) {
            auto snapFi = FailInfoSnapshot();
            snapFi.type_ = fi.type_;
            snapFi.reason = fi.reason;
            snapFi.killedReason = fi.killedReason;
            if (fi.sslVerifyError.type != Json.Type.undefined) {
                snapFi.sslVerifyError = fi.sslVerifyError;
            }
            snap.failInfo = snapFi;
        }
    }

    // Use server-namespaced key if in decentralized mode
    if (serverId.length > 0) {
        ctx.redis.hset(RedisKeys.state(serverId, net.config.id.toString()), "data", snap.toJson().toString());
    } else {
        // Legacy non-namespaced key
        ctx.redis.hset(RedisKeys.state_legacy(net.config.id.toString()), "data", snap.toJson().toString());
    }
}
