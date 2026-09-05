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
    RetryStatus, FailInfoSnapshot, TlsInfo, PROTOCOL_VERSION;
import ircfiber.irc.connection : EgressSlotView, egressLocations, egressSlotViews,
    refreshEgressState;
import ircfiber.irc.egress_catalog : ExitLocation;
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
    // Egress slots + location catalog for `GET /api/egress`. Done here
    // because this task is off every connection fiber: refreshEgressState()
    // shells out to each slot's tailscaled.
    publishEgressState(ctx, serverId);
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

/// One slot's published state. Keys must match the gateway's reader
/// (site/backend/source/ircfiber/egress.d).
private Json slotViewToJson(EgressSlotView v) {
    auto j = Json.emptyObject;
    j["label"] = Json(v.label);
    j["host"] = Json(v.host);
    j["port"] = Json(cast(long) v.port);
    j["locationId"] = Json(v.locationId);
    j["hostname"] = Json(v.exitHostname);
    j["country"] = Json(v.exitCountry);
    j["countryCode"] = Json(v.exitCountryCode);
    j["city"] = Json(v.exitCity);
    j["controllable"] = Json(v.controllable);
    j["state"] = Json(v.state);
    j["activeConns"] = Json(cast(long) v.activeConns);
    j["heldUntilMs"] = Json(v.heldUntilMs);
    j["error"] = Json(v.lastError);
    return j;
}

/// The pickable location catalog as a JSON array.
private Json locationsToJson(ExitLocation[] locs) {
    auto arr = Json.emptyArray;
    foreach (l; locs) {
        auto j = Json.emptyObject;
        j["id"] = Json(l.id);
        j["country"] = Json(l.country);
        j["countryCode"] = Json(l.countryCode);
        j["city"] = Json(l.city);
        j["cityCode"] = Json(l.cityCode);
        j["relays"] = Json(cast(long) l.relays);
        arr ~= j;
    }
    return arr;
}

/// Refreshes and publishes this engine's egress slots and location catalog.
/// Slots expire after 60 s so a dead engine's exits vanish from the picker
/// instead of lingering; the catalog lives 30 min so it survives a few
/// missed refreshes. A Redis hiccup must never kill the snapshotter.
private void publishEgressState(ref EngineContext ctx, string serverId) {
    // Legacy single-engine mode has no server namespace to publish under.
    if (serverId.length == 0) return;
    try {
        refreshEgressState();
        auto slots = egressSlotViews();
        auto slotsKey = RedisKeys.egressSlots(serverId);
        foreach (v; slots)
            ctx.redis.getDb().hset(slotsKey, v.label, slotViewToJson(v).toString());
        if (slots.length > 0) ctx.redis.getDb().expire(slotsKey, 60);
        auto catalogKey = RedisKeys.egressCatalog(serverId);
        auto locs = egressLocations();
        if (locs.length > 0) {
            ctx.redis.getDb().set(catalogKey, locationsToJson(locs).toString());
            ctx.redis.getDb().expire(catalogKey, 1800);
        }
    } catch (Exception e) {
        logWarn("Failed to publish egress state: %s", e.msg);
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
    auto clientForIsupport = ctx.connManager.getClient(net.config.id);
    if (clientForIsupport) {
        snap.isupport = clientForIsupport.getIsupport();
    }
    // Active Mullvad egress that won the Happy Eyeballs race for this
    // network. Surfaced to admin "which IP per IRC server".
    auto clientForEgress = ctx.connManager.getClient(net.config.id);
    if (clientForEgress) {
        snap.activeEgressLabel = clientForEgress.getActiveEgressLabel();
        snap.activeEgressHost = clientForEgress.getActiveEgressHost();
        snap.activeEgressIp = clientForEgress.getActiveEgressIp();
        snap.activeEgressLocation = clientForEgress.getActiveEgressLocation();
        // Socket endpoints of the live connection: the peer's family is
        // the admin's "IPv6 or IPv4?" answer; the local IP shows the
        // per-user bind (or the shared host/NAT66 address). Gated on
        // connected so a stale pair never outlives its socket.
        if (snap.connected) {
            snap.peerIp = clientForEgress.getActivePeerIp();
            snap.localIp = clientForEgress.getActiveLocalIp();
        }
        // Live-connection telemetry for the server-log header: lag
        // probe RTT, RPL_WELCOME instant and negotiated TLS details.
        snap.lagMs = clientForEgress.getLagMs();
        snap.connectedAtMs = clientForEgress.getConnectedAtMs();
        snap.hasTlsInfo = clientForEgress.hasTlsInfo();
        snap.tlsInfo = clientForEgress.hasTlsInfo() ? clientForEgress.getTlsInfo() : TlsInfo.init;
    }

    // W1-T01-rev1: structured retry + fail info from the engine's
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
