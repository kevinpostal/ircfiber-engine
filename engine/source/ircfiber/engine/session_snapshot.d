/**
 * Per-connection IRC session state that survives an engine hot swap.
 *
 * The engine publishes a `SessionSnapshot` as the holder's opaque META for
 * every live connection (on registration, on every own NICK/JOIN/PART/KICK,
 * CAP change, 005 burst, AWAY change, and every 30 s as a catch-up). A new
 * engine attaching to the held socket restores it so the session continues
 * with the same nick, channel list, member lists and IRCv3 caps — none of
 * which the IRC server will re-send because the registration already
 * happened upstream.
 *
 * Wire form: JSON object with `schemaTag == "IRCFv1"`; every other key is
 * optional on read (absent == empty). Newer optional keys: `graceful`,
 * `metaAtMs`, `usersDropped`, the `egress*`/`peerIp`/`localIp` block.
 */
module ircfiber.engine.session_snapshot;

import std.conv : to;
import std.uuid : parseUUID;

import vibe.data.json : Json;

import ircfiber.models.network : NetworkConfig, TLSMode;

/// Schema tag every snapshot carries; `fromJSON` rejects anything else.
enum SESSION_SNAPSHOT_SCHEMA = "IRCFv1";

/// Snapshot of the ISUPPORT-derived server features.
struct ServerFeaturesSnapshot {
    /// ISUPPORT NETWORK= value.
    string network;
    /// ISUPPORT PREFIX= value.
    string prefix = "@+";
    /// ISUPPORT CHANMODES= value.
    string chanModes;
    /// ISUPPORT CHANLIMIT max channels.
    int maxChannels = 0;
    /// ISUPPORT NICKLEN max nick length.
    int maxNickLen  = 30;
    /// ISUPPORT TOPICLEN max topic length.
    int topicLen    = 0;
}

/// Everything the next engine needs to keep a held socket *functionally*
/// the same session. State owned by the IRC server (nick registration,
/// JOIN list, cap negotiation) is preserved by the socket itself; this is
/// the in-memory bookkeeping that has to match it.
struct SessionSnapshot {
    /// = `SESSION_SNAPSHOT_SCHEMA`.
    string schemaTag = SESSION_SNAPSHOT_SCHEMA;
    /// Identity of the network this session belongs to (id/name/host/port/
    /// tls/nick only — the attaching engine uses its own Mongo config, so
    /// no credentials are ever written into the holder).
    NetworkConfig config;
    /// Owner user UUID ("" when unknown to the client).
    string userId;
    /// Engine serverId that wrote the snapshot.
    string serverId;
    /// Current IRC nick.
    string sessionNick;
    /// Whether the user is away.
    bool isAway;
    /// Away message, if away.
    string awayMessage;
    /// Cached server features snapshot.
    ServerFeaturesSnapshot serverFeatures;
    /// Full ISUPPORT map from the server's 005 replies (sent once per
    /// registration — the next engine cannot re-learn it).
    string[string] isupportMap;
    /// Server software/version token from RPL_MYINFO (004).
    string serverSoftware;
    /// Negotiated IRCv3 capabilities.
    string[] ackedCaps;
    /// Active query PM targets.
    string[] queryBuffers;
    /// Connect attempts before this session (flushed to the next CONNECT).
    string[] failureReasons;
    /// Lines buffered but not yet written. On a graceful detach this also
    /// carries what the flood pacer was still holding, so nothing typed
    /// during the swap window is lost.
    string[] outboundQueue;
    /// Joined channels → "".
    string[string] channelState;
    /// Channel → topic.
    string[string] channelTopics;
    /// Channel → member list. Cleared (with `usersDropped = true`) when the
    /// snapshot would exceed the holder's META limit.
    string[][string] channelUsers;
    /// Nick → realname.
    string[string] realnames;
    /// Nick → account name (extended-join / account-notify).
    string[string] accounts;
    /// Nick → ident.
    string[string] idents;
    /// Label → sent-at unix ms (labeled-response).
    long[string] pendingLabels;
    /// Lowercased channel → latest msgid.
    string[string] channelLatestMsgid;
    /// Lowercased channel → earliest msgid.
    string[string] channelEarliestMsgid;
    /// Lowercased channel → chathistory fetch in flight.
    bool[string] chathistoryInFlight;
    /// True if the upstream transport is plain TCP (informational; the
    /// holder owns TLS either way).
    bool transportWasPlain;
    /// True if the session was registered (`state == connected`) when the
    /// snapshot was written. False means the engine died mid-registration;
    /// the next engine closes the held socket and dials fresh.
    bool wasConnected;
    /// Unix-ms timestamp of when the snapshot was captured.
    long capturedAtMs;
    /// True when written by `detachForHotSwap()` (planned swap, state is
    /// exact); false for the periodic/eventful upkeep writes, after which a
    /// crash-attach re-syncs member lists with `NAMES`.
    bool graceful;
    /// Unix ms of the META write.
    long metaAtMs;
    /// `channelUsers` was dropped to fit the META size limit.
    bool usersDropped;

    // ── Egress bookkeeping (Mullvad slot the session rides) ──────────
    /// Slot label ("" = direct).
    string egressLabel;
    /// "host:port" of the SOCKS sidecar; "" for direct.
    string egressHost;
    /// Resolved sidecar IP; "" for direct.
    string egressIp;
    /// Per-host ban key of the exit ("de-ber" or `slot:<label>`).
    string egressLocationId;
    /// Human location text ("Berlin, Germany"); "" when unknown.
    string egressLocationText;
    /// Remote IP the upstream socket connected to.
    string peerIp;
    /// Local source IP of the upstream socket.
    string localIp;
}

// ── Serialisation ─────────────────────────────────────────────────────

/// Serializes a snapshot to a JSON object.
Json toJSON(ref SessionSnapshot s) {
    auto j = Json.emptyObject;
    j["schemaTag"] = s.schemaTag;
    j["sessionNick"] = s.sessionNick;
    j["isAway"] = s.isAway;
    j["awayMessage"] = s.awayMessage;
    j["userId"] = s.userId;
    j["serverId"] = s.serverId;
    j["transportWasPlain"] = s.transportWasPlain;
    j["wasConnected"] = s.wasConnected;
    j["capturedAtMs"] = s.capturedAtMs;
    j["graceful"] = s.graceful;
    j["metaAtMs"] = s.metaAtMs;
    j["usersDropped"] = s.usersDropped;

    auto cfg = Json.emptyObject;
    cfg["id"] = s.config.id.toString();
    cfg["name"] = s.config.name;
    cfg["host"] = s.config.host;
    cfg["port"] = cast(int) s.config.port;
    cfg["tls"] = s.config.tls.to!string;
    cfg["nick"] = s.config.nick;
    j["config"] = cfg;

    j["serverFeatures"] = serverFeaturesToJSON(s.serverFeatures);
    j["isupport"] = stringMapToJSON(s.isupportMap);
    j["serverSoftware"] = s.serverSoftware;
    j["ackedCaps"] = jsonArrayOf(s.ackedCaps);
    j["queryBuffers"] = jsonArrayOf(s.queryBuffers);
    j["failureReasons"] = jsonArrayOf(s.failureReasons);
    j["outboundQueue"] = jsonArrayOf(s.outboundQueue);
    j["channelState"] = stringMapToJSON(s.channelState);
    j["channelTopics"] = stringMapToJSON(s.channelTopics);
    j["channelUsers"] = stringListMapToJSON(s.channelUsers);
    j["realnames"] = stringMapToJSON(s.realnames);
    j["accounts"] = stringMapToJSON(s.accounts);
    j["idents"] = stringMapToJSON(s.idents);
    j["pendingLabels"] = longMapToJSON(s.pendingLabels);
    j["channelLatestMsgid"] = stringMapToJSON(s.channelLatestMsgid);
    j["channelEarliestMsgid"] = stringMapToJSON(s.channelEarliestMsgid);
    j["chathistoryInFlight"] = boolMapToJSON(s.chathistoryInFlight);

    j["egressLabel"] = s.egressLabel;
    j["egressHost"] = s.egressHost;
    j["egressIp"] = s.egressIp;
    j["egressLocationId"] = s.egressLocationId;
    j["egressLocationText"] = s.egressLocationText;
    j["peerIp"] = s.peerIp;
    j["localIp"] = s.localIp;
    return j;
}

/// Serializes server features to a JSON object.
Json serverFeaturesToJSON(ref ServerFeaturesSnapshot f) {
    auto j = Json.emptyObject;
    j["network"] = f.network;
    j["prefix"] = f.prefix;
    j["chanModes"] = f.chanModes;
    j["maxChannels"] = f.maxChannels;
    j["maxNickLen"] = f.maxNickLen;
    j["topicLen"] = f.topicLen;
    return j;
}

private Json jsonArrayOf(string[] arr) {
    auto v = Json.emptyArray;
    foreach (s; arr) v ~= Json(s);
    return v;
}

private Json stringMapToJSON(string[string] m) {
    auto v = Json.emptyObject;
    foreach (k, val; m) v[k] = val;
    return v;
}

private Json longMapToJSON(long[string] m) {
    auto v = Json.emptyObject;
    foreach (k, val; m) v[k] = val;
    return v;
}

private Json boolMapToJSON(bool[string] m) {
    auto v = Json.emptyObject;
    foreach (k, val; m) v[k] = val;
    return v;
}

private Json stringListMapToJSON(string[][string] m) {
    auto v = Json.emptyObject;
    foreach (k, arr; m) v[k] = jsonArrayOf(arr);
    return v;
}

private string str(Json j) { return j.type == Json.Type.string ? j.get!string : ""; }
private bool boolean(Json j) { return j.type == Json.Type.bool_ ? j.get!bool : false; }
private long integer(Json j) {
    if (j.type == Json.Type.int_) return j.get!long;
    if (j.type == Json.Type.float_) return cast(long) j.get!double;
    return 0;
}
private bool isObj(Json j) { return j.type == Json.Type.object; }
private bool isArr(Json j) { return j.type == Json.Type.array; }

/// Deserializes a snapshot. Throws when `schemaTag` is not
/// `SESSION_SNAPSHOT_SCHEMA` (a META written by an incompatible engine must
/// never be replayed onto a live socket).
SessionSnapshot fromJSON(Json j) {
    if (!isObj(j)) throw new Exception("SessionSnapshot: META is not a JSON object");
    SessionSnapshot s;
    s.schemaTag = str(j["schemaTag"]);
    if (s.schemaTag != SESSION_SNAPSHOT_SCHEMA)
        throw new Exception("SessionSnapshot: unsupported schemaTag '" ~ s.schemaTag ~ "'");

    s.sessionNick = str(j["sessionNick"]);
    s.isAway = boolean(j["isAway"]);
    s.awayMessage = str(j["awayMessage"]);
    s.userId = str(j["userId"]);
    s.serverId = str(j["serverId"]);
    s.transportWasPlain = boolean(j["transportWasPlain"]);
    s.wasConnected = boolean(j["wasConnected"]);
    s.capturedAtMs = integer(j["capturedAtMs"]);
    s.graceful = boolean(j["graceful"]);
    s.metaAtMs = integer(j["metaAtMs"]);
    s.usersDropped = boolean(j["usersDropped"]);

    auto cfg = j["config"];
    if (isObj(cfg)) {
        auto id = str(cfg["id"]);
        if (id.length) { try s.config.id = parseUUID(id); catch (Exception) {} }
        s.config.name = str(cfg["name"]);
        s.config.host = str(cfg["host"]);
        s.config.port = cast(ushort) integer(cfg["port"]);
        s.config.tls = toTLSMode(str(cfg["tls"]));
        s.config.nick = str(cfg["nick"]);
    }

    auto f = j["serverFeatures"];
    if (isObj(f)) {
        s.serverFeatures.network = str(f["network"]);
        s.serverFeatures.prefix = str(f["prefix"]);
        s.serverFeatures.chanModes = str(f["chanModes"]);
        s.serverFeatures.maxChannels = cast(int) integer(f["maxChannels"]);
        s.serverFeatures.maxNickLen = cast(int) integer(f["maxNickLen"]);
        s.serverFeatures.topicLen = cast(int) integer(f["topicLen"]);
    }

    if (isObj(j["isupport"])) foreach (string k, v; j["isupport"]) s.isupportMap[k] = str(v);
    s.serverSoftware = str(j["serverSoftware"]);

    if (isArr(j["ackedCaps"])) foreach (v; j["ackedCaps"]) s.ackedCaps ~= str(v);
    if (isArr(j["queryBuffers"])) foreach (v; j["queryBuffers"]) s.queryBuffers ~= str(v);
    if (isArr(j["failureReasons"])) foreach (v; j["failureReasons"]) s.failureReasons ~= str(v);
    if (isArr(j["outboundQueue"])) foreach (v; j["outboundQueue"]) s.outboundQueue ~= str(v);

    if (isObj(j["channelState"])) foreach (string k, v; j["channelState"]) s.channelState[k] = str(v);
    if (isObj(j["channelTopics"])) foreach (string k, v; j["channelTopics"]) s.channelTopics[k] = str(v);
    if (isObj(j["channelUsers"])) {
        foreach (string k, v; j["channelUsers"]) {
            string[] arr;
            if (isArr(v)) foreach (e; v) arr ~= str(e);
            s.channelUsers[k] = arr;
        }
    }
    if (isObj(j["realnames"])) foreach (string k, v; j["realnames"]) s.realnames[k] = str(v);
    if (isObj(j["accounts"])) foreach (string k, v; j["accounts"]) s.accounts[k] = str(v);
    if (isObj(j["idents"])) foreach (string k, v; j["idents"]) s.idents[k] = str(v);
    if (isObj(j["pendingLabels"])) foreach (string k, v; j["pendingLabels"]) s.pendingLabels[k] = integer(v);
    if (isObj(j["channelLatestMsgid"])) foreach (string k, v; j["channelLatestMsgid"]) s.channelLatestMsgid[k] = str(v);
    if (isObj(j["channelEarliestMsgid"])) foreach (string k, v; j["channelEarliestMsgid"]) s.channelEarliestMsgid[k] = str(v);
    if (isObj(j["chathistoryInFlight"])) foreach (string k, v; j["chathistoryInFlight"]) s.chathistoryInFlight[k] = boolean(v);

    s.egressLabel = str(j["egressLabel"]);
    s.egressHost = str(j["egressHost"]);
    s.egressIp = str(j["egressIp"]);
    s.egressLocationId = str(j["egressLocationId"]);
    s.egressLocationText = str(j["egressLocationText"]);
    s.peerIp = str(j["peerIp"]);
    s.localIp = str(j["localIp"]);
    return s;
}

private TLSMode toTLSMode(string s) {
    if (s == "enabled") return TLSMode.enabled;
    if (s == "required") return TLSMode.required;
    if (s == "starttls") return TLSMode.starttls;
    return TLSMode.disabled;
}

@("SessionSnapshot round-trips and rejects foreign schemas")
unittest {
    SessionSnapshot s;
    s.sessionNick = "Zodiac";
    s.wasConnected = true;
    s.graceful = true;
    s.channelState["#staff"] = "";
    s.channelUsers["#staff"] = ["@Zodiac", "FiberEye"];
    s.ackedCaps = ["sasl", "multi-prefix"];
    s.pendingLabels["abc"] = 42;
    s.egressLabel = "de";
    s.outboundQueue = ["PRIVMSG #staff :hi"];
    auto j = toJSON(s);
    auto back = fromJSON(j);
    assert(back.sessionNick == "Zodiac" && back.wasConnected && back.graceful);
    assert(back.channelUsers["#staff"] == ["@Zodiac", "FiberEye"]);
    assert(back.ackedCaps == ["sasl", "multi-prefix"]);
    assert(back.pendingLabels["abc"] == 42);
    assert(back.egressLabel == "de" && back.outboundQueue == ["PRIVMSG #staff :hi"]);

    auto bad = Json.emptyObject;
    bad["schemaTag"] = "IRCFv0";
    bool threw;
    try fromJSON(bad); catch (Exception) threw = true;
    assert(threw);
}
