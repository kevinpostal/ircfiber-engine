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
 * `metaAtMs`, `usersDropped`, the `egress*` (including `egressTrial*`)/
 * `peerIp`/`localIp`, `activeRoute` and `routingFallbackReason` block.
 */
module ircfiber.engine.session_snapshot;

import std.conv : to;
import std.uuid : parseUUID;

import vibe.data.json : Json;

import ircfiber.models.network : NetworkConfig, TLSMode;
import ircfiber.irc.bnc_ownership : BncPendingWrite, BncCommandOwner;

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

/// Committed server cursor; opaque msgids retain server order.
struct HistoryCursor {
    string msgid;
    long timestampMs;
    bool hasServerTime;
}

struct HistoryRecovery {
    string target;
    HistoryCursor lowerBound;
    HistoryCursor nextBefore;
    long discoveryUpperBoundMs;
    string state;
    string reasonCode;
    HistoryCursor upperBound;
    long boundaryOverlapMs;
    bool timestampFallback;
}

struct PendingHistoryRequest {
    string requestId;
    string target;
    string command;
    string batchRef;
    string connectionEpoch;
    long sentAtMs;
    long lastActivityMs;
    int effectiveLimit;
    bool automaticRecovery;
    string selector;
}

struct HistoryPageSnapshot {
    PendingHistoryRequest request;
    HistoryCursor first;
    HistoryCursor last;
    long ordinaryCount;
    bool historySeen;
    bool lowerBoundSeen;
    bool malformed;
    bool endReceived;
    bool awaitingCommit;
    bool quarantined;
    string label;
    HistoryRecovery proposed;
}

/// Socket-local ancestry and partial multiline data, never runtime handles.
struct OpenBatchSnapshot {
    string reference;
    string type;
    string target;
    string label;
    string parent;
    string historyBatchRef;
    string requestId;
    bool historical;
    bool contextMessage;
    bool quarantined;
    long openedAtMs;
    long bufferedBytes;
    long payloadBytes;
    int segments;
    string command;
    string firstEventJson;
    string[] lines;
    bool[] concat;
}

/// Nonsecret retained-socket ownership only; never native credentials/replies.
struct NativeQuietMarker {
    string socketId;
    string command;
    string account;
    string mode;
    bool unresolved;
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
    string[string] capValues;
    /// Active query PM targets.
    string[] queryBuffers;
    /// Folded DM nick → the counterparty's services account / user@host,
    /// as their latest message showed them (the DM nick-follow identity).
    string[string] queryAccounts;
    string[string] queryHosts;
    /// Connect attempts before this session (flushed to the next CONNECT).
    string[] failureReasons;
    /// Lines buffered but not yet written. On a graceful detach this also
    /// carries what the flood pacer was still holding, so nothing typed
    /// during the swap window is lost.
    string[] outboundQueue;
    /// Complete socket-specific private operations, ancestry and MONITOR state.
    string bncOwnershipPayload;
    /// Owned paced writes cannot become ordinary reconnect traffic.
    BncPendingWrite[] bncPendingWrites;
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
    /// Nick → away message ("" = away without text).
    string[string] away;
    /// Nick → "1" for users flagged as bots.
    string[string] bots;
    /// Nick → key → value (draft/metadata-2 user keys).
    string[string][string] userMetadata;
    /// Lowercased channel → key → value (draft/metadata-2 channel keys).
    string[string][string] channelMetadata;
    /// Nick → ident.
    string[string] idents;
    /// Label → sent-at unix ms (labeled-response).
    long[string] pendingLabels;
    /// Lowercased channel → latest msgid.
    string[string] channelLatestMsgid;
    /// Lowercased channel → earliest msgid.
    string[string] channelEarliestMsgid;
    /// Lowercased channel → server-time ms of the latest/earliest msgid.
    long[string] channelLatestTs;
    long[string] channelEarliestTs;
    HistoryRecovery[string] historyRecovery;
    HistoryPageSnapshot[] historyPages;
    OpenBatchSnapshot[] openBatches;
    PendingHistoryRequest[] historyManualQueue;
    PendingHistoryRequest[] historyAutomaticQueue;
    bool historyLastAutomatic;
    string[] historyDiscoverySeen;
    bool historyDiscoveryOverlap;
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
    /// Connection generation: unix ms of RPL_WELCOME for this socket. An
    /// attaching engine keeps it so a hot swap never invents a new
    /// transport generation (MLS peer tickets are bound to it). 0 = unknown.
    long connectedAtMs;
    /// Server-observed `nick!user@host` of this connection (self JOIN/WHO,
    /// confirmed NICK, CHGHOST); "" when unverified. Restored only together
    /// with a matching `connectedAtMs` on a graceful attach.
    string ownPrefix;
    /// Server-stated own services login (`unknown`/`none`/`account`) and
    /// account name; "" / unknown in a META from an older engine. Restored
    /// under the same graceful same-generation rule as `ownPrefix`. The
    /// connection epoch is deliberately absent: every attach mints a new one.
    string servicesAccountState;
    /// Observed account; "" unless `servicesAccountState == "account"`.
    string servicesAccount;
    /// Non-secret services marker: `nick!user@host` of each pseudoclient an
    /// in-flight services transaction was talking to, and the unix-ms
    /// deadline until which an attaching engine treats backlog lines from
    /// them as that transaction's private replies (never persisted). No
    /// fence tokens, commands, credentials or reply text.
    string[] servicesQuietPrefixes;
    long servicesQuietUntilMs;
    NativeQuietMarker servicesNativeQuiet;
    /// Legacy NickServ authentication commands (manual/automatic) sent on
    /// this socket whose verdict had not arrived: a count only, no text.
    /// Restored on any attach to the same held socket; 0 in older META.
    long servicesLegacyAuthPending;

    // ── Transport and optional VPN slot bookkeeping ─────────────────
    /// Slot label ("" = unproxied).
    string egressLabel;
    /// Optional IRCFv1 additions: actual transport, not a proposed bind.
    string activeRoute;
    string routingFallbackReason;
    /// "host:port" of the SOCKS sidecar; "" for direct.
    string egressHost;
    /// Resolved sidecar IP; "" for direct.
    string egressIp;
    /// Concrete host-ban key: direct, ipv6:<source>, VPN location or slot label.
    string egressLocationId;
    /// Human location text ("Berlin, Germany"); "" when unknown.
    string egressLocationText;
    /// Remote IP the upstream socket connected to.
    string peerIp;
    /// Local source IP of the upstream socket.
    string localIp;
    /// Owner token of the exit's single recovery trial this session is
    /// running ("" = not a trial), plus the endpoint it was claimed for.
    /// Carried across a hot swap so the next engine can settle it; the
    /// admission store still decides (fenced token, registered >= 60 s).
    string egressTrialToken;
    string egressTrialHost;
    ushort egressTrialPort;
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
    j["connectedAtMs"] = s.connectedAtMs;
    j["ownPrefix"] = s.ownPrefix;
    j["servicesAccountState"] = s.servicesAccountState;
    j["servicesAccount"] = s.servicesAccount;
    j["servicesQuietPrefixes"] = jsonArrayOf(s.servicesQuietPrefixes);
    j["servicesQuietUntilMs"] = s.servicesQuietUntilMs;
    j["servicesLegacyAuthPending"] = s.servicesLegacyAuthPending;
    if (s.servicesNativeQuiet != NativeQuietMarker.init)
        j["servicesNativeQuiet"] = nativeQuietToJSON(s.servicesNativeQuiet);

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
    j["capValues"] = stringMapToJSON(s.capValues);
    j["queryBuffers"] = jsonArrayOf(s.queryBuffers);
    j["queryAccounts"] = stringMapToJSON(s.queryAccounts);
    j["queryHosts"] = stringMapToJSON(s.queryHosts);
    j["failureReasons"] = jsonArrayOf(s.failureReasons);
    j["outboundQueue"] = jsonArrayOf(s.outboundQueue);
    j["bncOwnershipPayload"] = s.bncOwnershipPayload;
    auto ownedWrites = Json.emptyArray;
    foreach (w; s.bncPendingWrites) {
        auto v = Json.emptyObject;
        v["line"] = w.line; v["epoch"] = w.epoch;
        v["wireLabel"] = w.wireLabel;
        v["sid"] = w.owner.session; v["binding"] = w.owner.binding;
        v["request"] = w.owner.request; v["deadlineMs"] = w.owner.deadlineMs;
        ownedWrites ~= v;
    }
    j["bncPendingWrites"] = ownedWrites;
    j["channelState"] = stringMapToJSON(s.channelState);
    j["channelTopics"] = stringMapToJSON(s.channelTopics);
    j["channelUsers"] = stringListMapToJSON(s.channelUsers);
    j["realnames"] = stringMapToJSON(s.realnames);
    j["accounts"] = stringMapToJSON(s.accounts);
    j["away"] = stringMapToJSON(s.away);
    j["bots"] = stringMapToJSON(s.bots);
    j["userMetadata"] = nestedStringMapToJSON(s.userMetadata);
    j["channelMetadata"] = nestedStringMapToJSON(s.channelMetadata);
    j["idents"] = stringMapToJSON(s.idents);
    j["pendingLabels"] = longMapToJSON(s.pendingLabels);
    j["channelLatestMsgid"] = stringMapToJSON(s.channelLatestMsgid);
    j["channelEarliestMsgid"] = stringMapToJSON(s.channelEarliestMsgid);
    j["channelLatestTs"] = longMapToJSON(s.channelLatestTs);
    j["channelEarliestTs"] = longMapToJSON(s.channelEarliestTs);
    auto recovery = Json.emptyObject;
    foreach (key, record; s.historyRecovery) recovery[key] = historyRecoveryToJSON(record);
    j["historyRecovery"] = recovery;
    auto pages = Json.emptyArray;
    foreach (page; s.historyPages) pages ~= historyPageToJSON(page);
    j["historyPages"] = pages;
    auto batches = Json.emptyArray;
    foreach (batch; s.openBatches) batches ~= openBatchToJSON(batch);
    j["openBatches"] = batches;
    auto manual = Json.emptyArray;
    foreach (request; s.historyManualQueue) manual ~= historyRequestToJSON(request);
    j["historyManualQueue"] = manual;
    auto automatic = Json.emptyArray;
    foreach (request; s.historyAutomaticQueue) automatic ~= historyRequestToJSON(request);
    j["historyAutomaticQueue"] = automatic;
    j["historyLastAutomatic"] = s.historyLastAutomatic;
    j["historyDiscoverySeen"] = jsonArrayOf(s.historyDiscoverySeen);
    j["historyDiscoveryOverlap"] = s.historyDiscoveryOverlap;

    j["egressLabel"] = s.egressLabel;
    j["activeRoute"] = s.activeRoute;
    j["routingFallbackReason"] = s.routingFallbackReason;
    j["egressHost"] = s.egressHost;
    j["egressIp"] = s.egressIp;
    j["egressLocationId"] = s.egressLocationId;
    j["egressLocationText"] = s.egressLocationText;
    j["peerIp"] = s.peerIp;
    j["localIp"] = s.localIp;
    j["egressTrialToken"] = s.egressTrialToken;
    j["egressTrialHost"] = s.egressTrialHost;
    j["egressTrialPort"] = cast(long) s.egressTrialPort;
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

private Json jsonArrayOf(const(string)[] arr) {
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


private Json stringListMapToJSON(string[][string] m) {
    auto v = Json.emptyObject;
    foreach (k, arr; m) v[k] = jsonArrayOf(arr);
    return v;
}

/// `outer → inner → value` (metadata maps) as nested JSON objects.
Json nestedStringMapToJSON(string[string][string] m) {
    auto v = Json.emptyObject;
    foreach (k, inner; m) v[k] = stringMapToJSON(inner);
    return v;
}

/// Reverse of `nestedStringMapToJSON`; tolerates any non-object shape.
string[string][string] nestedStringMapFromJSON(Json j) {
    string[string][string] m;
    if (!isObj(j)) return m;
    foreach (string k, inner; j) {
        if (!isObj(inner)) continue;
        string[string] row;
        foreach (string ik, iv; inner) if (iv.type == Json.Type.string) row[ik] = iv.get!string;
        if (row.length) m[k] = row;
    }
    return m;
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

private void requireHistoryFields(Json j, string[] names, Json.Type type) {
    foreach (name; names)
        if (j[name].type != type)
            throw new Exception("Invalid history transfer field: " ~ name);
}

bool validHistoryRecoveryState(string state) {
    return state == "recovering" || state == "complete"
        || state == "retention_exhausted" || state == "unavailable" || state == "stalled";
}

Json historyCursorToJSON(const ref HistoryCursor cursor) {
    auto j = Json.emptyObject;
    j["msgid"] = cursor.msgid;
    j["timestampMs"] = cursor.timestampMs;
    j["hasServerTime"] = cursor.hasServerTime;
    return j;
}

HistoryCursor historyCursorFromJSON(Json j) {
    if (!isObj(j) || j["msgid"].type != Json.Type.string
            || j["timestampMs"].type != Json.Type.int_
            || j["hasServerTime"].type != Json.Type.bool_)
        throw new Exception("Invalid history cursor");
    return HistoryCursor(str(j["msgid"]), integer(j["timestampMs"]), boolean(j["hasServerTime"]));
}

Json historyRecoveryToJSON(const ref HistoryRecovery recovery) {
    auto j = Json.emptyObject;
    j["version"] = 1;
    j["target"] = recovery.target;
    j["lowerBound"] = historyCursorToJSON(recovery.lowerBound);
    j["nextBefore"] = historyCursorToJSON(recovery.nextBefore);
    j["discoveryUpperBoundMs"] = recovery.discoveryUpperBoundMs;
    j["state"] = recovery.state;
    j["reasonCode"] = recovery.reasonCode;
    if (recovery.upperBound != HistoryCursor.init)
        j["upperBound"] = historyCursorToJSON(recovery.upperBound);
    if (recovery.boundaryOverlapMs) j["boundaryOverlapMs"] = recovery.boundaryOverlapMs;
    if (recovery.timestampFallback) j["timestampFallback"] = true;
    return j;
}

HistoryRecovery historyRecoveryFromJSON(Json j) {
    if (!isObj(j) || j["version"].type != Json.Type.int_ || integer(j["version"]) != 1
            || j["target"].type != Json.Type.string
            || j["discoveryUpperBoundMs"].type != Json.Type.int_
            || j["state"].type != Json.Type.string
            || !validHistoryRecoveryState(str(j["state"]))
            || j["reasonCode"].type != Json.Type.string)
        throw new Exception("Invalid history recovery record");
    HistoryRecovery recovery;
    recovery.target = str(j["target"]);
    recovery.lowerBound = historyCursorFromJSON(j["lowerBound"]);
    recovery.nextBefore = historyCursorFromJSON(j["nextBefore"]);
    recovery.discoveryUpperBoundMs = integer(j["discoveryUpperBoundMs"]);
    recovery.state = str(j["state"]);
    recovery.reasonCode = str(j["reasonCode"]);
    if (j["upperBound"].type != Json.Type.undefined)
        recovery.upperBound = historyCursorFromJSON(j["upperBound"]);
    if (j["boundaryOverlapMs"].type != Json.Type.undefined) {
        if (j["boundaryOverlapMs"].type != Json.Type.int_ || integer(j["boundaryOverlapMs"]) < 0)
            throw new Exception("Invalid history boundary overlap");
        recovery.boundaryOverlapMs = integer(j["boundaryOverlapMs"]);
    }
    if (j["timestampFallback"].type != Json.Type.undefined) {
        if (j["timestampFallback"].type != Json.Type.bool_)
            throw new Exception("Invalid history timestamp fallback");
        recovery.timestampFallback = boolean(j["timestampFallback"]);
    }
    return recovery;
}

Json historyRequestToJSON(const ref PendingHistoryRequest request) {
    auto j = Json.emptyObject;
    j["requestId"] = request.requestId;
    j["target"] = request.target;
    j["command"] = request.command;
    j["batchRef"] = request.batchRef;
    j["connectionEpoch"] = request.connectionEpoch;
    j["sentAtMs"] = request.sentAtMs;
    j["lastActivityMs"] = request.lastActivityMs;
    j["effectiveLimit"] = request.effectiveLimit;
    j["automaticRecovery"] = request.automaticRecovery;
    j["selector"] = request.selector;
    return j;
}

PendingHistoryRequest historyRequestFromJSON(Json j) {
    if (!isObj(j)) throw new Exception("Invalid pending history request");
    requireHistoryFields(j, ["requestId", "target", "command", "batchRef", "connectionEpoch"], Json.Type.string);
    requireHistoryFields(j, ["sentAtMs", "lastActivityMs", "effectiveLimit"], Json.Type.int_);
    requireHistoryFields(j, ["automaticRecovery"], Json.Type.bool_);
    if (j["selector"].type != Json.Type.undefined && j["selector"].type != Json.Type.string)
        throw new Exception("Invalid pending history selector");
    if (integer(j["effectiveLimit"]) < 0 || integer(j["effectiveLimit"]) > int.max)
        throw new Exception("Invalid pending history limit");
    PendingHistoryRequest request;
    request.requestId = str(j["requestId"]);
    request.target = str(j["target"]);
    request.command = str(j["command"]);
    request.batchRef = str(j["batchRef"]);
    request.connectionEpoch = str(j["connectionEpoch"]);
    request.sentAtMs = integer(j["sentAtMs"]);
    request.lastActivityMs = integer(j["lastActivityMs"]);
    request.effectiveLimit = cast(int) integer(j["effectiveLimit"]);
    request.automaticRecovery = boolean(j["automaticRecovery"]);
    request.selector = str(j["selector"]);
    return request;
}

Json historyPageToJSON(const ref HistoryPageSnapshot page) {
    auto j = Json.emptyObject;
    j["request"] = historyRequestToJSON(page.request);
    j["first"] = historyCursorToJSON(page.first);
    j["last"] = historyCursorToJSON(page.last);
    j["ordinaryCount"] = page.ordinaryCount;
    j["historySeen"] = page.historySeen;
    j["lowerBoundSeen"] = page.lowerBoundSeen;
    j["malformed"] = page.malformed;
    j["endReceived"] = page.endReceived;
    j["awaitingCommit"] = page.awaitingCommit;
    j["quarantined"] = page.quarantined;
    j["label"] = page.label;
    // An open page has no proposed checkpoint until its close.
    if (page.proposed.state.length) j["proposed"] = historyRecoveryToJSON(page.proposed);
    return j;
}

HistoryPageSnapshot historyPageFromJSON(Json j) {
    if (!isObj(j)) throw new Exception("Invalid history page");
    requireHistoryFields(j, ["ordinaryCount"], Json.Type.int_);
    requireHistoryFields(j, ["malformed", "endReceived", "awaitingCommit", "quarantined",
        "historySeen", "lowerBoundSeen"], Json.Type.bool_);
    requireHistoryFields(j, ["label"], Json.Type.string);
    HistoryPageSnapshot page;
    page.request = historyRequestFromJSON(j["request"]);
    page.first = historyCursorFromJSON(j["first"]);
    page.last = historyCursorFromJSON(j["last"]);
    page.ordinaryCount = integer(j["ordinaryCount"]);
    page.historySeen = boolean(j["historySeen"]);
    page.lowerBoundSeen = boolean(j["lowerBoundSeen"]);
    page.malformed = boolean(j["malformed"]);
    page.endReceived = boolean(j["endReceived"]);
    page.awaitingCommit = boolean(j["awaitingCommit"]);
    page.quarantined = boolean(j["quarantined"]);
    page.label = str(j["label"]);
    if (j["proposed"].type != Json.Type.undefined)
        page.proposed = historyRecoveryFromJSON(j["proposed"]);
    if (page.awaitingCommit && !page.proposed.state.length)
        throw new Exception("History page awaiting commit without a proposal");
    return page;
}

Json openBatchToJSON(const ref OpenBatchSnapshot batch) {
    auto j = Json.emptyObject;
    j["reference"] = batch.reference;
    j["type"] = batch.type;
    j["target"] = batch.target;
    j["label"] = batch.label;
    j["parent"] = batch.parent;
    j["historyBatchRef"] = batch.historyBatchRef;
    j["requestId"] = batch.requestId;
    j["historical"] = batch.historical;
    j["contextMessage"] = batch.contextMessage;
    j["quarantined"] = batch.quarantined;
    j["openedAtMs"] = batch.openedAtMs;
    j["bufferedBytes"] = batch.bufferedBytes;
    j["payloadBytes"] = batch.payloadBytes;
    j["segments"] = batch.segments;
    j["command"] = batch.command;
    j["firstEventJson"] = batch.firstEventJson;
    j["lines"] = jsonArrayOf(batch.lines);
    auto concat = Json.emptyArray;
    foreach (value; batch.concat) concat ~= Json(value);
    j["concat"] = concat;
    return j;
}

OpenBatchSnapshot openBatchFromJSON(Json j) {
    if (!isObj(j)) throw new Exception("Invalid open history batch");
    requireHistoryFields(j, ["reference", "type", "target", "label", "parent", "historyBatchRef",
        "requestId", "command", "firstEventJson"], Json.Type.string);
    requireHistoryFields(j, ["historical", "contextMessage", "quarantined"], Json.Type.bool_);
    requireHistoryFields(j, ["openedAtMs", "bufferedBytes", "payloadBytes", "segments"], Json.Type.int_);
    if (integer(j["segments"]) < 0 || integer(j["segments"]) > int.max)
        throw new Exception("Invalid multiline segment count");
    requireHistoryFields(j, ["lines", "concat"], Json.Type.array);
    foreach (line; j["lines"])
        if (line.type != Json.Type.string) throw new Exception("Invalid multiline segment");
    foreach (value; j["concat"])
        if (value.type != Json.Type.bool_) throw new Exception("Invalid multiline concat flag");
    OpenBatchSnapshot batch;
    batch.reference = str(j["reference"]);
    batch.type = str(j["type"]);
    batch.target = str(j["target"]);
    batch.label = str(j["label"]);
    batch.parent = str(j["parent"]);
    batch.historyBatchRef = str(j["historyBatchRef"]);
    batch.requestId = str(j["requestId"]);
    batch.historical = boolean(j["historical"]);
    batch.contextMessage = boolean(j["contextMessage"]);
    batch.quarantined = boolean(j["quarantined"]);
    batch.openedAtMs = integer(j["openedAtMs"]);
    batch.bufferedBytes = integer(j["bufferedBytes"]);
    batch.payloadBytes = integer(j["payloadBytes"]);
    batch.segments = cast(int) integer(j["segments"]);
    batch.command = str(j["command"]);
    batch.firstEventJson = str(j["firstEventJson"]);
    if (isArr(j["lines"])) foreach (line; j["lines"]) batch.lines ~= str(line);
    if (isArr(j["concat"])) foreach (value; j["concat"]) batch.concat ~= boolean(value);
    if (batch.lines.length != batch.concat.length)
        throw new Exception("Invalid multiline concat state");
    return batch;
}

Json nativeQuietToJSON(const ref NativeQuietMarker marker) {
    auto j = Json.emptyObject;
    j["socketId"] = marker.socketId;
    j["command"] = marker.command;
    j["account"] = marker.account;
    j["mode"] = marker.mode;
    j["unresolved"] = marker.unresolved;
    return j;
}

NativeQuietMarker nativeQuietFromJSON(Json j) {
    NativeQuietMarker invalid;
    invalid.mode = "invalid";
    invalid.unresolved = true;
    if (!isObj(j)) return invalid;
    foreach (name; ["socketId", "command", "account", "mode"])
        if (j[name].type != Json.Type.string) return invalid;
    if (j["unresolved"].type != Json.Type.bool_
            || !str(j["socketId"]).length || str(j["mode"]) != "unlabelled"
            || (str(j["command"]) != "REGISTER" && str(j["command"]) != "VERIFY"))
        return invalid;
    return NativeQuietMarker(str(j["socketId"]), str(j["command"]), str(j["account"]),
        str(j["mode"]), boolean(j["unresolved"]));
}

/// Deserializes a snapshot. Throws when `schemaTag` is not
/// `SESSION_SNAPSHOT_SCHEMA` (a META written by an incompatible engine must
/// never be replayed onto a live socket).
SessionSnapshot fromJSON(Json j) {
    if (!isObj(j)) throw new Exception("SessionSnapshot: META is not a JSON object");
    SessionSnapshot s;
    s.schemaTag = str(j["schemaTag"]);
    if (s.schemaTag != SESSION_SNAPSHOT_SCHEMA)
        throw new Exception("SessionSnapshot: unsupported schemaTag '" ~ s.schemaTag ~ "'");
    foreach (name; ["historyPages", "openBatches", "historyManualQueue",
            "historyAutomaticQueue", "historyDiscoverySeen"])
        if (j[name].type != Json.Type.undefined && !isArr(j[name]))
            throw new Exception("Invalid history transfer array: " ~ name);
    if (j["historyRecovery"].type != Json.Type.undefined && !isObj(j["historyRecovery"]))
        throw new Exception("Invalid history recovery map");

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
    s.connectedAtMs = integer(j["connectedAtMs"]);
    s.ownPrefix = str(j["ownPrefix"]);
    s.servicesAccountState = str(j["servicesAccountState"]);
    s.servicesAccount = str(j["servicesAccount"]);
    if (isArr(j["servicesQuietPrefixes"]))
        foreach (v; j["servicesQuietPrefixes"]) s.servicesQuietPrefixes ~= str(v);
    s.servicesQuietUntilMs = integer(j["servicesQuietUntilMs"]);
    if (j["servicesNativeQuiet"].type != Json.Type.undefined)
        s.servicesNativeQuiet = nativeQuietFromJSON(j["servicesNativeQuiet"]);
    {
        // Absent (older META): 0, by contract. Present but not a sane count
        // (wrong type, negative, beyond the bound): fail closed — 64 saturates
        // the next engine's ledger, so structured authentication waits for a
        // real verdict or a new socket rather than trusting garbage as "none".
        auto v = j["servicesLegacyAuthPending"];
        if (v.type == Json.Type.undefined) s.servicesLegacyAuthPending = 0;
        else if (v.type != Json.Type.int_) s.servicesLegacyAuthPending = 64;
        else {
            const pending = v.get!long;
            s.servicesLegacyAuthPending = pending < 0 || pending > 64 ? 64 : pending;
        }
    }

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
    if (isObj(j["capValues"])) foreach (string k, v; j["capValues"]) s.capValues[k] = str(v);
    s.serverSoftware = str(j["serverSoftware"]);

    if (isArr(j["ackedCaps"])) foreach (v; j["ackedCaps"]) s.ackedCaps ~= str(v);
    if (isArr(j["queryBuffers"])) foreach (v; j["queryBuffers"]) s.queryBuffers ~= str(v);
    if (isObj(j["queryAccounts"])) foreach (string k, v; j["queryAccounts"]) s.queryAccounts[k] = str(v);
    if (isObj(j["queryHosts"])) foreach (string k, v; j["queryHosts"]) s.queryHosts[k] = str(v);
    if (isArr(j["failureReasons"])) foreach (v; j["failureReasons"]) s.failureReasons ~= str(v);
    if (isArr(j["outboundQueue"])) foreach (v; j["outboundQueue"]) s.outboundQueue ~= str(v);
    if (j["bncOwnershipPayload"].type != Json.Type.undefined) {
        if (j["bncOwnershipPayload"].type != Json.Type.string)
            throw new Exception("Invalid BNC ownership snapshot");
        s.bncOwnershipPayload = j["bncOwnershipPayload"].get!string;
    }
    if (j["bncPendingWrites"].type != Json.Type.undefined) {
        if (!isArr(j["bncPendingWrites"])) throw new Exception("Invalid BNC write queue");
        foreach (v; j["bncPendingWrites"]) {
            if (s.bncPendingWrites.length >= 2_000 || !isObj(v))
                throw new Exception("Invalid BNC write queue");
            foreach (key; ["line", "epoch", "wireLabel", "sid", "binding", "request"])
                if (v[key].type != Json.Type.string) throw new Exception("Invalid BNC write metadata");
            BncPendingWrite w;
            w.line = v["line"].get!string; w.epoch = v["epoch"].get!string;
            w.wireLabel = v["wireLabel"].get!string;
            w.owner = BncCommandOwner(v["sid"].get!string, v["binding"].get!string,
                v["request"].get!string, v["deadlineMs"].get!long);
            if (!w.line.length) throw new Exception("Invalid BNC queued line");
            if (w.owner == BncCommandOwner.init) {
                if (w.epoch.length || w.wireLabel.length)
                    throw new Exception("Unowned paced entry has private metadata");
            } else {
                if (!w.epoch.length || w.owner.deadlineMs <= 0)
                    throw new Exception("Invalid BNC write admission");
                foreach (id; [w.owner.session, w.owner.binding, w.owner.request])
                    if (id.length != 36) throw new Exception("Invalid BNC owner UUID");
                    else parseUUID(id);
                if (w.wireLabel.length != 40 || w.wireLabel[0 .. 4] != "bnc-")
                    throw new Exception("Invalid BNC operation UUID");
                parseUUID(w.wireLabel[4 .. $]);
            }
            foreach (c; w.line) if (c == '\r' || c == '\n' || c == '\0')
                throw new Exception("Invalid BNC queued line");
            s.bncPendingWrites ~= w;
        }
    }

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
    if (isObj(j["away"])) foreach (string k, v; j["away"]) s.away[k] = str(v);
    if (isObj(j["bots"])) foreach (string k, v; j["bots"]) s.bots[k] = str(v);
    s.userMetadata = nestedStringMapFromJSON(j["userMetadata"]);
    s.channelMetadata = nestedStringMapFromJSON(j["channelMetadata"]);
    if (isObj(j["idents"])) foreach (string k, v; j["idents"]) s.idents[k] = str(v);
    if (isObj(j["pendingLabels"])) foreach (string k, v; j["pendingLabels"]) s.pendingLabels[k] = integer(v);
    if (isObj(j["channelLatestMsgid"])) foreach (string k, v; j["channelLatestMsgid"]) s.channelLatestMsgid[k] = str(v);
    if (isObj(j["channelEarliestMsgid"])) foreach (string k, v; j["channelEarliestMsgid"]) s.channelEarliestMsgid[k] = str(v);
    if (isObj(j["channelLatestTs"])) foreach (string k, v; j["channelLatestTs"]) s.channelLatestTs[k] = integer(v);
    if (isObj(j["channelEarliestTs"])) foreach (string k, v; j["channelEarliestTs"]) s.channelEarliestTs[k] = integer(v);
    if (isObj(j["historyRecovery"]))
        foreach (string key, record; j["historyRecovery"])
            s.historyRecovery[key] = historyRecoveryFromJSON(record);
    if (isArr(j["historyPages"]))
        foreach (page; j["historyPages"]) s.historyPages ~= historyPageFromJSON(page);
    if (isArr(j["openBatches"]))
        foreach (batch; j["openBatches"]) s.openBatches ~= openBatchFromJSON(batch);
    if (isArr(j["historyManualQueue"]))
        foreach (request; j["historyManualQueue"]) s.historyManualQueue ~= historyRequestFromJSON(request);
    if (isArr(j["historyAutomaticQueue"]))
        foreach (request; j["historyAutomaticQueue"]) s.historyAutomaticQueue ~= historyRequestFromJSON(request);
    s.historyLastAutomatic = boolean(j["historyLastAutomatic"]);
    if (isArr(j["historyDiscoverySeen"]))
        foreach (target; j["historyDiscoverySeen"]) s.historyDiscoverySeen ~= str(target);
    s.historyDiscoveryOverlap = boolean(j["historyDiscoveryOverlap"]);

    s.egressLabel = str(j["egressLabel"]);
    s.activeRoute = str(j["activeRoute"]);
    if (s.activeRoute != "ipv6" && s.activeRoute != "mullvad"
            && s.activeRoute != "nordvpn" && s.activeRoute != "direct") s.activeRoute = "";
    s.routingFallbackReason = str(j["routingFallbackReason"]);
    s.egressHost = str(j["egressHost"]);
    s.egressIp = str(j["egressIp"]);
    s.egressLocationId = str(j["egressLocationId"]);
    s.egressLocationText = str(j["egressLocationText"]);
    s.peerIp = str(j["peerIp"]);
    s.localIp = str(j["localIp"]);
    s.egressTrialToken = str(j["egressTrialToken"]);
    s.egressTrialHost = str(j["egressTrialHost"]);
    s.egressTrialPort = cast(ushort) integer(j["egressTrialPort"]);
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
    s.egressTrialToken = "nonce:7";
    s.egressTrialHost = "socks.example";
    s.egressTrialPort = 1080;
    s.outboundQueue = ["PRIVMSG #staff :hi"];
    s.queryHosts["p34c3"] = "~user@788114F4.IP";
    s.queryAccounts["p34c3"] = "p34c3";
    auto j = toJSON(s);
    auto back = fromJSON(j);
    assert(back.sessionNick == "Zodiac" && back.wasConnected && back.graceful);
    assert(back.channelUsers["#staff"] == ["@Zodiac", "FiberEye"]);
    assert(back.ackedCaps == ["sasl", "multi-prefix"]);
    assert(back.pendingLabels["abc"] == 42);
    assert(back.egressLabel == "de" && back.outboundQueue == ["PRIVMSG #staff :hi"]);
    assert(back.egressTrialToken == "nonce:7" && back.egressTrialHost == "socks.example"
        && back.egressTrialPort == 1080);
    // A hot swap must not forget who each DM partner is, or every
    // conversation stops following its partner's renames until they speak.
    assert(back.queryHosts["p34c3"] == "~user@788114F4.IP" && back.queryAccounts["p34c3"] == "p34c3");

    // Identity proof and connection generation survive the swap intact.
    s.connectedAtMs = 1_700_000_000_123;
    s.ownPrefix = "Zodiac!~z@fiber.example";
    auto proof = fromJSON(toJSON(s));
    assert(proof.connectedAtMs == 1_700_000_000_123);
    assert(proof.ownPrefix == "Zodiac!~z@fiber.example");
    // The observed services login rides along; no epoch is carried.
    s.servicesAccountState = "account";
    s.servicesAccount = "zodiac";
    auto login = fromJSON(toJSON(s));
    assert(login.servicesAccountState == "account" && login.servicesAccount == "zodiac");
    auto loginJson = toJSON(s);
    assert(loginJson["connectionEpoch"].type == Json.Type.undefined);
    // A META from an older engine has neither: unknown, never invented.
    auto legacy = toJSON(s);
    legacy.remove("connectedAtMs");
    legacy.remove("ownPrefix");
    legacy.remove("servicesAccountState");
    legacy.remove("servicesAccount");
    auto old = fromJSON(legacy);
    assert(old.connectedAtMs == 0 && old.ownPrefix == "");
    assert(old.servicesAccountState == "" && old.servicesAccount == "");
    assert(old.servicesQuietPrefixes.length == 0 && old.servicesQuietUntilMs == 0);
    // The services marker carries prefixes and a deadline, nothing else.
    s.servicesQuietPrefixes = ["NickServ!services@services.example"];
    s.servicesQuietUntilMs = 1_700_000_030_000;
    auto quiet = fromJSON(toJSON(s));
    assert(quiet.servicesQuietPrefixes == ["NickServ!services@services.example"]
        && quiet.servicesQuietUntilMs == 1_700_000_030_000);
    // The legacy-auth handoff is a bounded count; older META reads 0.
    assert(old.servicesLegacyAuthPending == 0);
    s.servicesLegacyAuthPending = 2;
    assert(fromJSON(toJSON(s)).servicesLegacyAuthPending == 2);
    auto hostile = toJSON(s);
    hostile["servicesLegacyAuthPending"] = 1_000_000;
    assert(fromJSON(hostile).servicesLegacyAuthPending == 64);
    hostile["servicesLegacyAuthPending"] = -1;
    assert(fromJSON(hostile).servicesLegacyAuthPending == 64, "a corrupt present count fails closed");
    hostile["servicesLegacyAuthPending"] = "2";
    assert(fromJSON(hostile).servicesLegacyAuthPending == 64, "a mistyped present count fails closed");
    hostile.remove("servicesLegacyAuthPending");
    assert(fromJSON(hostile).servicesLegacyAuthPending == 0, "an absent count is an older engine's META");

    auto bad = Json.emptyObject;
    bad["schemaTag"] = "IRCFv0";
    bool threw;
    try fromJSON(bad); catch (Exception) threw = true;
    assert(threw);
}

/// Callable from the standalone connection harness; no Redis/Mongo required.
void historySnapshotRegressionChecks() {
    import vibe.data.json : parseJsonString;
    HistoryRecovery recovery;
    recovery.target = "#Case[";
    recovery.lowerBound = HistoryCursor("opaque-z", 1_700_000_000_100, true);
    recovery.nextBefore = HistoryCursor("opaque-a", 1_700_000_000_100, true);
    recovery.upperBound = HistoryCursor("newest-opaque", 1_700_000_009_000, true);
    recovery.boundaryOverlapMs = 1_700_000_000_900;
    recovery.timestampFallback = true;
    recovery.discoveryUpperBoundMs = 1_700_000_010_000;
    recovery.state = "recovering";
    recovery.reasonCode = "reconnect";
    PendingHistoryRequest request = PendingHistoryRequest("request-1", "#Case[", "BEFORE",
        "history-root", "epoch-1", 100, 200, 20, true);
    request.selector = "msgid=opaque-a";
    HistoryPageSnapshot page;
    page.request = request;
    page.first = recovery.nextBefore;
    page.last = recovery.lowerBound;
    page.historySeen = true;
    page.lowerBoundSeen = true;
    page.ordinaryCount = 20;
    page.endReceived = true;
    page.awaitingCommit = true;
    page.label = "history-label";
    page.proposed = recovery;
    OpenBatchSnapshot root;
    root.reference = "history-root";
    root.type = "chathistory";
    root.target = recovery.target;
    root.label = page.label;
    root.historyBatchRef = root.reference;
    root.requestId = request.requestId;
    root.historical = true;
    root.openedAtMs = 100;
    OpenBatchSnapshot child = root;
    child.reference = "multiline-child";
    child.parent = root.reference;
    child.type = "draft/multiline";
    child.command = "PRIVMSG";
    child.firstEventJson = `{"c":"PRIVMSG","px":"old!u@h","p":["#Case[","one"]}`;
    child.lines = ["one", "two"];
    child.concat = [false, true];
    child.bufferedBytes = 6;
    child.payloadBytes = 6;
    child.segments = 2;
    child.contextMessage = true;
    child.quarantined = true;

    SessionSnapshot snapshot;
    snapshot.historyRecovery["#case{"] = recovery;
    snapshot.capValues = ["draft/account-registration": "custom-account-name,min-password-length=12"];
    snapshot.servicesNativeQuiet = NativeQuietMarker("socket-1", "VERIFY", "account-1", "unlabelled", true);
    auto discovery = recovery;
    discovery.target = "*targets";
    snapshot.historyRecovery["*targets"] = discovery;
    snapshot.historyPages = [page];
    snapshot.openBatches = [root, child];
    snapshot.historyManualQueue = [request];
    snapshot.historyAutomaticQueue = [request];
    snapshot.historyLastAutomatic = true;
    snapshot.historyDiscoverySeen = ["NewPeer", "OldPeer"];
    snapshot.historyDiscoveryOverlap = true;
    // Round-trip actual JSON bytes, not a shared in-memory Json object.
    auto restored = fromJSON(parseJsonString(toJSON(snapshot).toString()));
    assert(restored.historyRecovery == snapshot.historyRecovery);
    assert(restored.capValues == snapshot.capValues);
    assert(restored.servicesNativeQuiet == snapshot.servicesNativeQuiet);
    assert(restored.historyPages == snapshot.historyPages);
    assert(restored.openBatches == snapshot.openBatches);
    assert(restored.historyManualQueue == snapshot.historyManualQueue);
    assert(restored.historyAutomaticQueue == snapshot.historyAutomaticQueue);
    assert(restored.historyLastAutomatic);
    assert(restored.historyDiscoverySeen == snapshot.historyDiscoverySeen);
    assert(restored.historyDiscoveryOverlap);
    assert(toJSON(snapshot)["chathistoryInFlight"].type == Json.Type.undefined);
    // Equal timestamps never reorder or replace opaque msgid boundaries.
    assert(restored.historyPages[0].first.msgid == "opaque-a");
    assert(restored.historyPages[0].last.msgid == "opaque-z");
    foreach (state; ["recovering", "complete", "retention_exhausted", "unavailable", "stalled"]) {
        recovery.state = state;
        assert(historyRecoveryFromJSON(parseJsonString(historyRecoveryToJSON(recovery).toString())) == recovery);
    }
    foreach (kind; 0 .. 7) {
        auto invalid = historyRecoveryToJSON(recovery);
        if (kind == 0) invalid["state"] = "finished";
        if (kind == 1) invalid["version"] = 2;
        if (kind == 2) invalid["lowerBound"]["hasServerTime"] = "true";
        if (kind == 3) invalid.remove("nextBefore");
        if (kind == 4) invalid["boundaryOverlapMs"] = "1000";
        if (kind == 5) invalid["boundaryOverlapMs"] = -1;
        if (kind == 6) invalid["timestampFallback"] = 1;
        bool rejected;
        try historyRecoveryFromJSON(invalid); catch (Exception) rejected = true;
        assert(rejected, "Malformed checkpoint must never restore as complete coverage");
    }
    auto malformedBatch = openBatchToJSON(child);
    malformedBatch["concat"] = Json.emptyArray;
    bool rejected;
    try openBatchFromJSON(malformedBatch); catch (Exception) rejected = true;
    assert(rejected, "Partial multiline concatenation cannot be silently lost");
    foreach (name; ["historyPages", "openBatches", "historyManualQueue",
            "historyAutomaticQueue", "historyDiscoverySeen"]) {
        auto invalid = toJSON(snapshot);
        invalid[name] = Json.emptyObject;
        bool invalidRejected;
        try fromJSON(invalid); catch (Exception) invalidRejected = true;
        assert(invalidRejected, "Malformed transfer state cannot become an empty history queue");
    }
    auto olderRecovery = historyRecoveryToJSON(recovery);
    olderRecovery.remove("upperBound");
    olderRecovery.remove("boundaryOverlapMs");
    olderRecovery.remove("timestampFallback");
    assert(historyRecoveryFromJSON(olderRecovery).upperBound == HistoryCursor.init);
    assert(historyRecoveryFromJSON(olderRecovery).boundaryOverlapMs == 0);
    assert(!historyRecoveryFromJSON(olderRecovery).timestampFallback);
    auto olderRequest = historyRequestToJSON(request);
    olderRequest.remove("selector");
    assert(historyRequestFromJSON(olderRequest).selector.length == 0);
    olderRequest["selector"] = false;
    rejected = false;
    try historyRequestFromJSON(olderRequest); catch (Exception) rejected = true;
    assert(rejected, "Present selectors must retain their exact string value");
    SessionSnapshot emptySnapshot;
    assert(fromJSON(toJSON(emptySnapshot)).servicesNativeQuiet == NativeQuietMarker.init);
    foreach (kind; 0 .. 5) {
        auto invalid = toJSON(snapshot);
        if (kind == 0) invalid["servicesNativeQuiet"] = "corrupt";
        if (kind == 1) invalid["servicesNativeQuiet"]["mode"] = "labelled";
        if (kind == 2) invalid["servicesNativeQuiet"]["command"] = "PRIVMSG";
        if (kind == 3) invalid["servicesNativeQuiet"]["socketId"] = "";
        if (kind == 4) invalid["servicesNativeQuiet"]["unresolved"] = "true";
        auto blocked = fromJSON(invalid).servicesNativeQuiet;
        assert(blocked.mode == "invalid" && blocked.unresolved && blocked.socketId.length == 0);
    }
    import ircfiber.redis.protocol : NetworkStateSnapshot;
    NetworkStateSnapshot publicSnapshot;
    publicSnapshot.capValues = snapshot.capValues;
    auto publicRoundtrip = NetworkStateSnapshot.fromJson(parseJsonString(publicSnapshot.toJson().toString()));
    assert(publicRoundtrip.capValues == snapshot.capValues);
    auto legacyPublic = publicSnapshot.toJson();
    legacyPublic.remove("capValues");
    assert(NetworkStateSnapshot.fromJson(legacyPublic).capValues.length == 0);
}
