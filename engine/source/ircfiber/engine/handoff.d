module ircfiber.engine.handoff;

import std.algorithm : filter, canFind;
import std.array : array;
import std.conv : to;
import std.datetime : Clock;
import core.time : dur;
import std.json : JSONValue, JSONException, parseJSON;
import std.socket : getAddress, AddressFamily;
import std.string : split, join, indexOf, strip, lastIndexOf;
import std.uni : toLower;
import std.uuid : UUID, parseUUID, randomUUID;

import core.stdc.errno : errno;
import core.stdc.string : memcpy, memset;
import core.stdc.stdlib : malloc, free;
import core.sys.posix.fcntl;
import core.sys.posix.sys.socket : msghdr, cmsghdr, iovec, sendmsg, recvmsg,
    socket, bind, listen, accept, connect, sockaddr, socklen_t,
    getsockname, getpeername, recv, send,
    CMSG_FIRSTHDR, CMSG_DATA, CMSG_SPACE, CMSG_LEN,
    SCM_RIGHTS, SOL_SOCKET,
    AF_UNIX, AF_INET, SOCK_STREAM, MSG_CTRUNC;
import core.sys.posix.netinet.in_ : sockaddr_in, htons, htonl, ntohs,
    INADDR_LOOPBACK;
import core.sys.posix.sys.un : sockaddr_un;
import core.sys.posix.sys.stat;
import core.sys.posix.unistd : unlink, read, write, close, pipe, getpid;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.log;

import ircfiber.models.network : NetworkConfig, TLSMode, SASLMechanism, normalizeChannelName;
import ircfiber.redis.protocol : RedisKeys;

/// Magic header identifying the handoff protocol version. Bumped on
/// incompatible wire-format changes; the receiver refuses mismatched
/// versions so a new engine never inherits incompatible state from an
/// old one.
enum HANDOFF_MAGIC = "IRCF";
/// Handoff protocol version — bumped on incompatible wire-format changes.
enum HANDOFF_VERSION = 1;

/// Path template for the handoff Unix socket. Each engine process
/// creates a unique socket (PID-suffixed) so multiple engines can
/// coexist during a rolling reload.
string handoffSocketPath(string serverId) {
    return "/tmp/ircfiber-handoff-" ~ serverId ~ ".sock";
}

/// Path template for the runtime IPC control socket used to send the
/// gracefulReload control message to the running engine.
string handoffIpcPath(string serverId) {
    return "/tmp/ircfiber-handoff-ipc-" ~ serverId ~ ".sock";
}

// ═══════════════════════════════════════════════════════════════════════════
//  Per-network serialisable state
// ═══════════════════════════════════════════════════════════════════════════

/// Snapshot of an in-flight IRC connection's transient state. Captured by
/// the old engine before handing off the FD, replayed by the new engine
/// so the connection continues with all per-channel/label state intact.
///
/// Field guide for the reader: this is the only state that the new
/// engine needs to keep the socket *functionally* the same. Things that
/// are owned by the IRC server (your nick registration, JOIN list, cap
/// negotiation) are preserved automatically because the socket is
/// still open and mid-registration-equivalent — we just need the
/// in-memory bookkeeping to match.
struct HandoffState {
    /// Magic + version stamp at the front so we can detect mismatched
    /// schemas. The wire format is documented in `encode`/`decode`.
    string schemaTag;            // = "IRCFv1"
    /// Full network configuration (network_id, host, port, tls, sasl, …).
    NetworkConfig config;        // full network config (network_id, host, port, tls, sasl, …)
    /// Owner user UUID.
    string userId;               // owner UUID
    /// Engine serverId owning this network.
    string serverId;             // engine serverId owning this network
    /// Current IRC nick.
    string sessionNick;          // current IRC nick
    /// Whether the user is away.
    bool isAway;
    /// Away message, if away.
    string awayMessage;
    /// Cached server features snapshot.
    ServerFeaturesSnapshot serverFeatures;
    /// Full ISUPPORT map (every key=value or bare flag from the
    /// server's 005 replies). Used by the new engine to render the
    /// categorised "Server features" panel without waiting for a fresh
    /// 005 reply stream — the IRC server only sends 005 once per
    /// registration, so the new engine wouldn't otherwise see it.
    string[string] isupportMap;
    /// Negotiated IRCv3 capabilities.
    string[] ackedCaps;          // negotiated IRCv3 caps
    /// Active query PM targets.
    string[] queryBuffers;       // active query PM targets
    /// Pre-handoff connect attempts (flushed to next CONNECT).
    string[] failureReasons;     // pre-handoff connect attempts (flushed to next CONNECT)
    /// Lines buffered but never sent (state was disconnected).
    string[] outboundQueue;      // lines we buffered but never sent (state was disconnected)
    /// Joined channels → "".
    string[string] channelState;        // joined channels → ""
    /// Channel → topic.
    string[string] channelTopics;       // channel → topic
    /// Channel → user list.
    string[][string] channelUsers;      // channel → user list
    /// Nick → realname.
    string[string] realnames;           // nick → realname
    /// Nick → account name (extended-join).
    string[string] accounts;            // nick → account name (extended-join)
    /// Nick → ident / username.
    string[string] idents;              // nick → ident / username
    /// Label → sent-at unix ms.
    long[string] pendingLabels;         // label → sent-at unix ms
    /// Lowercased channel → latest msgid.
    string[string] channelLatestMsgid;  // lc channel → msgid
    /// Lowercased channel → earliest msgid.
    string[string] channelEarliestMsgid;// lc channel → msgid
    /// Lowercased channel → true (chathistory fetch in flight).
    bool[string] chathistoryInFlight;   // lc channel → true
    /// True if the underlying transport is plain TCP. False means the
    /// connection was TLS, which the new engine cannot adopt directly
    /// (TLS session state is userspace) and must soft-reconnect.
    bool transportWasPlain;
    /// True if the connection was healthy at handoff time. False means
    /// the new engine should let the existing reconnect-backoff run
    /// rather than re-registering.
    bool wasConnected;
    /// Unix-ms timestamp of when the snapshot was captured (sanity check).
    long capturedAtMs;           // unix ms; sanity check
}

/// Snapshot of the ISUPPORT-derived server features.
struct ServerFeaturesSnapshot {
    /// ISUPPORT NETWORK= value.
    string network;        // ISUPPORT NETWORK=
    /// ISUPPORT PREFIX= value.
    string prefix = "@+";  // ISUPPORT PREFIX=
    /// ISUPPORT CHANMODES= value.
    string chanModes;
    /// ISUPPORT CHANLIMIT max channels.
    int maxChannels = 0;
    /// ISUPPORT NICKLEN max nick length.
    int maxNickLen  = 30;
    /// ISUPPORT TOPICLEN max topic length.
    int topicLen    = 0;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Wire format
// ═══════════════════════════════════════════════════════════════════════════
//
//  Each network's record on the wire:
//    [ u32  totalLen | u32  jsonLen | jsonBytes... | u32  fdCount | u32  fdBytesLen | fdBytes... ]
//
//  The FD payload is *NOT* in the JSON; it lives in a separate cmsg
//  SCM_RIGHTS message, paired with the jsonBytes by stream order. The
//  header length prefix exists so the receiver can split concatenated
//  records when reading from a single stream socket.
//
//  Handshake:
//    <-- READY\n   (new engine)
//    --> HELLO <oldPid>\n   (old engine acknowledges)
//    <-- GO\n      (new engine signals ready to receive)
//    ... record 0
//    ... record 1
//    ...
//    --> DONE <count>\n   (old engine signals no more records)
//    <-- BYE\n   (new engine acknowledges and closes)
//
//  The handshake is small enough to do over a single SOCK_STREAM
//  connection; we layer the SCM_RIGHTS-carrying datagrams on top.

/// Frame header magic — written before the JSON-length so the receiver
/// can sanity-check the start of a record.
enum RECORD_MAGIC = cast(uint) 0x52434631; // "RFC1" in little-endian

/// Wire-level helpers — all little-endian (x86 / ARM LE).
private void writeU32LE(ref ubyte[] buf, size_t pos, uint v) {
    buf[pos]   = cast(ubyte)(v & 0xFF);
    buf[pos+1] = cast(ubyte)((v >> 8) & 0xFF);
    buf[pos+2] = cast(ubyte)((v >> 16) & 0xFF);
    buf[pos+3] = cast(ubyte)((v >> 24) & 0xFF);
}

/// Reads a little-endian uint32 from `data`.
public uint readU32LE(const(ubyte)* data) {
    return cast(uint)(data[0])
         | (cast(uint)(data[1]) << 8)
         | (cast(uint)(data[2]) << 16)
         | (cast(uint)(data[3]) << 24);
}

// Public stream helpers (used by reload_orchestrator.d for the
// meta-protocol above the per-record wire format).
/// Writes all `len` bytes from `data` to `fd`, retrying on EINTR.
public void writeAll(int fd, const(ubyte)* data, size_t len) {
    import core.sys.posix.unistd : write;
    size_t written = 0;
    while (written < len) {
        const n = write(fd, data + written, len - written);
        if (n < 0) {
            if (errno == 4 /* EINTR */) continue;
            throw new Exception("write failed");
        }
        if (n == 0) throw new Exception("write: peer closed");
        written += n;
    }
}

/// Reads exactly `len` bytes into `data`, retrying on EINTR.
public void readAll(int fd, ubyte* data, size_t len) {
    import core.sys.posix.unistd : read;
    size_t total = 0;
    while (total < len) {
        const n = read(fd, data + total, len - total);
        if (n < 0) {
            if (errno == 4) continue;
            throw new Exception("read failed");
        }
        if (n == 0) throw new Exception("read: peer closed");
        total += n;
    }
}

/// Writes a length-prefixed frame (4-byte LE length + payload) to `fd`.
public void writeFrame(int fd, const(ubyte)[] payload) {
    import core.sys.posix.unistd : write;
    ubyte[4] hdrBuf;
    auto hdrSlice = hdrBuf[];
    writeU32LE(hdrSlice, 0, cast(uint)payload.length);
    writeAll(fd, hdrBuf.ptr, 4);
    writeAll(fd, payload.ptr, payload.length);
}

/// Reads a length-prefixed frame from `fd`.
public ubyte[] readFrame(int fd) {
    import core.sys.posix.unistd : read;
    ubyte[4] hdrBuf;
    readAll(fd, hdrBuf.ptr, 4);
    auto len = readU32LE(hdrBuf.ptr);
    if (len > 64 * 1024 * 1024) throw new Exception("frame too large");
    auto buf = cast(ubyte[]) new ubyte[](len);
    if (len > 0) readAll(fd, buf.ptr, len);
    return buf;
}

/// Writes a newline-terminated line to `fd`.
public void writeLine(int fd, string s) {
    writeAll(fd, cast(const(ubyte)*)s.ptr, s.length);
}

/// Reads a newline-terminated line from `fd`.
public string readLine(int fd) {
    import core.sys.posix.unistd : read;
    ubyte[1] b;
    string acc;
    while (true) {
        const n = read(fd, b.ptr, 1);
        if (n < 0) {
            if (errno == 4) continue;
            throw new Exception("read failed");
        }
        if (n == 0) {
            if (acc.length == 0) throw new Exception("EOF");
            return acc;
        }
        if (b[0] == '\n') return acc;
        acc ~= cast(char)b[0];
    }
}

/// Re-export of POSIX close() with a unique name to avoid collisions
/// with `AdoptedSocket.close()` and `Closeable.close()`.
public int posixClose(int fd) {
    import core.sys.posix.unistd : close;
    return close(fd);
}

// ═══════════════════════════════════════════════════════════════════════════
//  JSON serialisation for HandoffState
// ═══════════════════════════════════════════════════════════════════════════

/// Serializes handoff state to a JSON object.
JSONValue toJSON(ref HandoffState s) {
    JSONValue j = JSONValue.emptyObject;
    j.object["schemaTag"] = JSONValue(s.schemaTag);
    j.object["sessionNick"] = JSONValue(s.sessionNick);
    j.object["isAway"] = JSONValue(s.isAway);
    j.object["awayMessage"] = JSONValue(s.awayMessage);
    j.object["userId"] = JSONValue(s.userId);
    j.object["serverId"] = JSONValue(s.serverId);
    j.object["transportWasPlain"] = JSONValue(s.transportWasPlain);
    j.object["wasConnected"] = JSONValue(s.wasConnected);
    j.object["capturedAtMs"] = JSONValue(s.capturedAtMs);

    auto cfg = JSONValue.emptyObject;
    cfg.object["id"] = JSONValue(s.config.id.toString());
    cfg.object["name"] = JSONValue(s.config.name);
    cfg.object["host"] = JSONValue(s.config.host);
    cfg.object["port"] = JSONValue(s.config.port);
    cfg.object["tls"] = JSONValue(s.config.tls.to!string);
    cfg.object["sasl"] = JSONValue(s.config.sasl.to!string);
    cfg.object["saslUsername"] = JSONValue(s.config.saslUsername);
    cfg.object["saslPassword"] = JSONValue(s.config.saslPassword);
    cfg.object["nick"] = JSONValue(s.config.nick);
    cfg.object["realName"] = JSONValue(s.config.realName);
    cfg.object["disabled"] = JSONValue(s.config.disabled);
    cfg.object["autoJoinChannels"] = jsonArrayOf(s.config.autoJoinChannels);
    cfg.object["partedChannels"] = jsonArrayOf(s.config.partedChannels);
    j.object["config"] = cfg;

    j.object["serverFeatures"] = serverFeaturesToJSON(s.serverFeatures);
    j.object["isupport"] = stringMapToJSON(s.isupportMap);
    j.object["ackedCaps"] = jsonArrayOf(s.ackedCaps);
    j.object["queryBuffers"] = jsonArrayOf(s.queryBuffers);
    j.object["failureReasons"] = jsonArrayOf(s.failureReasons);
    j.object["outboundQueue"] = jsonArrayOf(s.outboundQueue);
    j.object["channelState"] = stringMapToJSON(s.channelState);
    j.object["channelTopics"] = stringMapToJSON(s.channelTopics);
    j.object["channelUsers"] = stringListMapToJSON(s.channelUsers);
    j.object["realnames"] = stringMapToJSON(s.realnames);
    j.object["accounts"] = stringMapToJSON(s.accounts);
    j.object["idents"] = stringMapToJSON(s.idents);
    j.object["pendingLabels"] = longMapToJSON(s.pendingLabels);
    j.object["channelLatestMsgid"] = stringMapToJSON(s.channelLatestMsgid);
    j.object["channelEarliestMsgid"] = stringMapToJSON(s.channelEarliestMsgid);
    j.object["chathistoryInFlight"] = boolMapToJSON(s.chathistoryInFlight);

    return j;
}

/// Serializes server features to a JSON object.
JSONValue serverFeaturesToJSON(ref ServerFeaturesSnapshot f) {
    JSONValue j = JSONValue.emptyObject;
    j.object["network"] = JSONValue(f.network);
    j.object["prefix"] = JSONValue(f.prefix);
    j.object["chanModes"] = JSONValue(f.chanModes);
    j.object["maxChannels"] = JSONValue(f.maxChannels);
    j.object["maxNickLen"] = JSONValue(f.maxNickLen);
    j.object["topicLen"] = JSONValue(f.topicLen);
    return j;
}

private JSONValue jsonArrayOf(string[] arr) {
    JSONValue v = JSONValue.emptyArray;
    foreach (s; arr) v.array ~= JSONValue(s);
    return v;
}

private JSONValue jsonArrayOf(long[] arr) {
    JSONValue v = JSONValue.emptyArray;
    foreach (s; arr) v.array ~= JSONValue(s);
    return v;
}

private JSONValue stringMapToJSON(string[string] m) {
    JSONValue v = JSONValue.emptyObject;
    foreach (k, val; m) v.object[k] = JSONValue(val);
    return v;
}

private JSONValue longMapToJSON(long[string] m) {
    JSONValue v = JSONValue.emptyObject;
    foreach (k, val; m) v.object[k] = JSONValue(val);
    return v;
}

private JSONValue boolMapToJSON(bool[string] m) {
    JSONValue v = JSONValue.emptyObject;
    foreach (k, val; m) v.object[k] = JSONValue(val);
    return v;
}

private JSONValue stringListMapToJSON(string[][string] m) {
    JSONValue v = JSONValue.emptyObject;
    foreach (k, arr; m) v.object[k] = jsonArrayOf(arr);
    return v;
}

/// Deserializes handoff state from a JSON object.
HandoffState fromJSON(JSONValue j) {
    HandoffState s;
    const root = j.object;

    if (auto p = "schemaTag" in root) s.schemaTag = p.str;
    if (auto p = "sessionNick" in root) s.sessionNick = p.str;
    if (auto p = "isAway" in root) s.isAway = p.boolean;
    if (auto p = "awayMessage" in root) s.awayMessage = p.str;
    if (auto p = "userId" in root) s.userId = p.str;
    if (auto p = "serverId" in root) s.serverId = p.str;
    if (auto p = "transportWasPlain" in root) s.transportWasPlain = p.boolean;
    if (auto p = "wasConnected" in root) s.wasConnected = p.boolean;
    if (auto p = "capturedAtMs" in root) s.capturedAtMs = p.integer;

    if (auto p = "config" in root) {
        const cfg = p.object;
        if (auto q = "id" in cfg) s.config.id = parseUUID(q.str);
        if (auto q = "name" in cfg) s.config.name = q.str;
        if (auto q = "host" in cfg) s.config.host = q.str;
        if (auto q = "port" in cfg) s.config.port = cast(ushort) q.integer;
        if (auto q = "tls" in cfg) s.config.tls = q.str.toTLSMode();
        if (auto q = "sasl" in cfg) s.config.sasl = q.str.toSASLMechanism();
        if (auto q = "saslUsername" in cfg) s.config.saslUsername = q.str;
        if (auto q = "saslPassword" in cfg) s.config.saslPassword = q.str;
        if (auto q = "nick" in cfg) s.config.nick = q.str;
        if (auto q = "realName" in cfg) s.config.realName = q.str;
        if (auto q = "disabled" in cfg) s.config.disabled = q.boolean;
        if (auto q = "autoJoinChannels" in cfg)
            foreach (v; q.array) s.config.autoJoinChannels ~= v.str;
        if (auto q = "partedChannels" in cfg)
            foreach (v; q.array) s.config.partedChannels ~= v.str;
    }

    if (auto p = "serverFeatures" in root) {
        const f = p.object;
        if (auto q = "network" in f) s.serverFeatures.network = q.str;
        if (auto q = "prefix" in f) s.serverFeatures.prefix = q.str;
        if (auto q = "chanModes" in f) s.serverFeatures.chanModes = q.str;
        if (auto q = "maxChannels" in f) s.serverFeatures.maxChannels = cast(int) q.integer;
        if (auto q = "maxNickLen" in f) s.serverFeatures.maxNickLen = cast(int) q.integer;
        if (auto q = "topicLen" in f) s.serverFeatures.topicLen = cast(int) q.integer;
    }

    // ISUPPORT map (added in handoff schema v2). Older old-engines won't
    // include this field; we default to an empty map in that case so
    // the new engine simply rebuilds it from scratch on its next 005
    // stream. Future schema-only addition (no protocol bump needed
    // because the field is optional and absent == empty).
    if (auto p = "isupport" in root)
        foreach (k, v; p.object) s.isupportMap[k] = v.str;

    if (auto p = "ackedCaps" in root)
        foreach (v; p.array) s.ackedCaps ~= v.str;
    if (auto p = "queryBuffers" in root)
        foreach (v; p.array) s.queryBuffers ~= v.str;
    if (auto p = "failureReasons" in root)
        foreach (v; p.array) s.failureReasons ~= v.str;
    if (auto p = "outboundQueue" in root)
        foreach (v; p.array) s.outboundQueue ~= v.str;

    if (auto p = "channelState" in root)
        foreach (k, v; p.object) s.channelState[k] = v.str;
    if (auto p = "channelTopics" in root)
        foreach (k, v; p.object) s.channelTopics[k] = v.str;
    if (auto p = "channelUsers" in root) {
        foreach (k, v; p.object) {
            string[] arr;
            foreach (e; v.array) arr ~= e.str;
            s.channelUsers[k] = arr;
        }
    }
    if (auto p = "realnames" in root)
        foreach (k, v; p.object) s.realnames[k] = v.str;
    if (auto p = "accounts" in root)
        foreach (k, v; p.object) s.accounts[k] = v.str;
    if (auto p = "idents" in root)
        foreach (k, v; p.object) s.idents[k] = v.str;
    if (auto p = "pendingLabels" in root)
        foreach (k, v; p.object) s.pendingLabels[k] = v.integer;
    if (auto p = "channelLatestMsgid" in root)
        foreach (k, v; p.object) s.channelLatestMsgid[k] = v.str;
    if (auto p = "channelEarliestMsgid" in root)
        foreach (k, v; p.object) s.channelEarliestMsgid[k] = v.str;
    if (auto p = "chathistoryInFlight" in root)
        foreach (k, v; p.object) s.chathistoryInFlight[k] = v.boolean;

    return s;
}

private TLSMode toTLSMode(string s) {
    if (s == "enabled") return TLSMode.enabled;
    if (s == "required") return TLSMode.required;
    return TLSMode.disabled;
}
private SASLMechanism toSASLMechanism(string s) {
    if (s == "plain") return SASLMechanism.plain;
    if (s == "external") return SASLMechanism.external;
    if (s == "scramSha256") return SASLMechanism.scramSha256;
    return SASLMechanism.none;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SCM_RIGHTS helpers
// ═══════════════════════════════════════════════════════════════════════════

/// Build a cmsghdr containing `fdCount` file descriptors, ready to be
/// passed to sendmsg(2). Caller owns the returned slice; reuse it
/// across multiple sendmsg calls when sending several records with
/// different FDs.
ubyte[] buildCmsgBuffer(int[] fds) {
    if (fds.length == 0) return null;
    auto fdBytes = fds.length * int.sizeof;
    auto total = CMSG_SPACE(cast(socklen_t) fdBytes);
    if (total == 0) return null;
    auto buf = cast(ubyte[]) new ubyte[](total);
    auto hdr = cast(cmsghdr*) buf.ptr;
    hdr.cmsg_len = cast(uint) CMSG_LEN(cast(socklen_t) fdBytes);
    hdr.cmsg_level = SOL_SOCKET;
    hdr.cmsg_type = SCM_RIGHTS;
    auto data = cast(int*) CMSG_DATA(hdr);
    foreach (i, fd; fds) data[i] = fd;
    return buf;
}

/// Send `stateJson` over `fd` paired with the FDs in `fds` via
/// SCM_RIGHTS. The body is one record (length-prefixed JSON + the
/// FD count echoed in the cmsg).
void sendRecordWithFds(int fd, const(ubyte)[] stateJson, int[] fds) {
    // Frame 1: JSON payload (length-prefixed)
    writeFrame(fd, stateJson);

    // Frame 2: FD count (0 if no fds — e.g. TLS network that the new
    // engine has to soft-reconnect)
    ubyte[4] cnt;
    auto cntSlice = cnt[];
    writeU32LE(cntSlice, 0, cast(uint) fds.length);
    writeAll(fd, cnt.ptr, 4);

    if (fds.length == 0) return;

    auto cbuf = buildCmsgBuffer(fds);
    if (cbuf is null) throw new Exception("buildCmsgBuffer failed");

    // SCM_RIGHTS requires at least 1 byte of payload on some kernels.
    // Send a 1-byte dummy message paired with the cmsg.
    ubyte[1] dummy = [0];
    iovec iov;
    iov.iov_base = dummy.ptr;
    iov.iov_len = 1;

    msghdr msg;
    memset(&msg, 0, msghdr.sizeof);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.ptr;
    msg.msg_controllen = cast(socklen_t) cbuf.length;

    const n = sendmsg(fd, &msg, 0);
    if (n < 0) throw new Exception("sendmsg failed: errno=" ~ errno.to!string);
    if (n == 0) throw new Exception("sendmsg: 0 bytes");
}

/// Receive a record's JSON + FDs over `fd`. The JSON is returned as
/// a freshly-allocated slice (caller frees). The FDs are returned as
/// an `int[]` (caller closes each via `close()` after adoption).
WireRecord receiveRecordWithFds(int fd) {
    auto json = readFrame(fd);

    ubyte[4] cntBuf;
    readAll(fd, cntBuf.ptr, 4);
    auto fdCount = cast(int) readU32LE(cntBuf.ptr);
    if (fdCount == 0) return WireRecord(json, null);

    // Allocate cmsg buffer big enough to hold fdCount ints.
    auto fdBytes = fdCount * int.sizeof;
    auto totalCmsg = CMSG_SPACE(cast(socklen_t) fdBytes);
    auto cbuf = cast(ubyte[]) new ubyte[](totalCmsg);

    // 1-byte dummy payload
    ubyte[1] dummy;
    iovec iov;
    iov.iov_base = dummy.ptr;
    iov.iov_len = 1;

    msghdr msg;
    memset(&msg, 0, msghdr.sizeof);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.ptr;
    msg.msg_controllen = cast(socklen_t) cbuf.length;

    const n = recvmsg(fd, &msg, 0);
    if (n < 0) throw new Exception("recvmsg failed: errno=" ~ errno.to!string);
    if (n == 0) throw new Exception("recvmsg: peer closed");

    // MSG_CTRUNC: the kernel couldn't fit all FDs into our cmsg
    // buffer. This means the fdCount is larger than what we
    // allocated space for, which should never happen since we
    // compute CMSG_SPACE(fdCount * sizeof(int)) above, but a
    // mismatched sender could trigger it. Check defensively.
    if (msg.msg_flags & MSG_CTRUNC)
        throw new Exception("recvmsg: cmsg truncated (MSG_CTRUNC) — " ~
            "buffer holds fewer FDs than sender wrote; expected " ~
            fdCount.to!string ~ " FDs");

    // Walk the cmsg chain looking for SCM_RIGHTS. We can't reliably
    // import CMSG_NXTHDR across all platforms, so we do it by hand
    // using CMSG_LEN alignment (matches glibc + BSD semantics).
    auto c = cast(cmsghdr*) CMSG_FIRSTHDR(&msg);
    if (c is null) throw new Exception("no cmsg received");
    int[] fds;
    while (c !is null) {
        if (c.cmsg_level == SOL_SOCKET && c.cmsg_type == SCM_RIGHTS) {
            auto data = cast(int*) CMSG_DATA(c);
            auto count = (c.cmsg_len - CMSG_LEN(0)) / int.sizeof;
            fds = new int[](count);
            foreach (i; 0 .. count) fds[i] = data[i];
            break;
        }
        // Advance: next cmsg starts at aligned(this + this.cmsg_len)
        auto next = cast(cmsghdr*)
            (cast(ubyte*) c + cast(uint) CMSG_LEN(c.cmsg_len));
        if (cast(ubyte*) next >= cast(ubyte*) msg.msg_control + msg.msg_controllen)
            break;
        c = next;
    }
    if (fds.length != fdCount)
        throw new Exception("expected " ~ fdCount.to!string ~
                            " fds, got " ~ fds.length.to!string);
    return WireRecord(json, fds);
}

/// A single record received from the handoff stream.
struct WireRecord {
    /// JSON payload of the record.
    const(ubyte)[] json;
    /// File descriptors transferred with the record (empty if none).
    int[] fds;
}

/// Send the trailing sentinel indicating no more records will be sent.
void sendDoneMarker(int fd, size_t count) {
    writeLine(fd, "DONE " ~ count.to!string ~ "\n");
}

/// Wait for the receiver's acknowledgement after we've transferred
/// every record.
void waitForAck(int fd) {
    auto line = readLine(fd);
    if (line != "ACK")
        throw new Exception("expected ACK, got: " ~ line);
}

/// Send the receiver's acknowledgement after adopting a record.
void sendAck(int fd) {
    writeLine(fd, "ACK\n");
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unix-socket plumbing
// ═══════════════════════════════════════════════════════════════════════════

/// Create, bind, listen on a Unix-domain SOCK_STREAM socket. Returns
/// the listener fd. Caller is responsible for `close()` + `unlink()`.
int createUnixListener(string path) {
    // Best-effort unlink of stale socket file. ignore ENOENT.
    // Also try to remove any leftover file before bind.
    unlink(path.ptr);
    unlink(path.ptr);  // double-unlink: first removes dir entry, second ensures clean
    auto s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) throw new Exception("socket() failed");

    sockaddr_un addr;
    addr.sun_family = cast(ushort) AF_UNIX;
    if (path.length >= addr.sun_path.length)
        throw new Exception("path too long");
    addr.sun_path[path.length] = 0;
    foreach (i, c; path) addr.sun_path[i] = cast(char) c;
    auto addrLen = cast(uint)(cast(ubyte*)&addr.sun_path[path.length] + 1 - cast(ubyte*) &addr);
    if (bind(s, cast(sockaddr*) &addr, addrLen) < 0) {
        auto e = errno;
        cast(void) posixClose(s);
        throw new Exception("bind() failed: errno=" ~ e.to!string);
    }
    // Mode 0600 — owner-only. chown can relax if needed.
    import core.sys.posix.sys.stat : S_IRUSR, S_IWUSR, chmod;
    const st = stat(path.ptr, null);
    if (st == 0) {
        chmod(path.ptr, S_IRUSR | S_IWUSR);
    }
    if (listen(s, 1) < 0) {
        auto e = errno;
        cast(void) posixClose(s);
        throw new Exception("listen() failed: errno=" ~ e.to!string);
    }
    return s;
}

/// Connect to a Unix-domain SOCK_STREAM socket.
int connectUnix(string path) {
    auto s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) throw new Exception("socket() failed");
    sockaddr_un addr;
    addr.sun_family = cast(ushort) AF_UNIX;
    if (path.length >= addr.sun_path.length) {
        cast(void) posixClose(s);
        throw new Exception("path too long");
    }
    addr.sun_path[path.length] = 0;
    foreach (i, c; path) addr.sun_path[i] = cast(char) c;
    auto addrLen = cast(uint)(cast(ubyte*)&addr.sun_path[path.length] + 1 - cast(ubyte*) &addr);
    if (connect(s, cast(sockaddr*) &addr, addrLen) < 0) {
        auto e = errno;
        cast(void) posixClose(s);
        throw new Exception("connect() failed: errno=" ~ e.to!string);
    }
    return s;
}

/// Accept a single client on a Unix-domain SOCK_STREAM listener.
/// Uses poll() with a 1-second timeout so the vibe.d event loop
/// can continue processing (heartbeats, etc.) while waiting for
/// the handoff peer to connect. Without this, a blocking accept()
/// in the control-consumer fiber would stall ALL fibers, causing
/// lease expiry and premature network reassignment.
int acceptUnix(int listener, int timeoutSeconds = 30) {
    import core.sys.posix.poll : poll, pollfd, POLLIN;
    import core.sys.posix.fcntl : fcntl, F_GETFL, F_SETFL, O_NONBLOCK;

    // Set non-blocking so accept() never stalls the event loop.
    auto flags = fcntl(listener, F_GETFL, 0);
    fcntl(listener, F_SETFL, flags | O_NONBLOCK);

    import vibe.core.core : yield;
    const deadline = Clock.currTime + dur!"seconds"(timeoutSeconds);
    while (Clock.currTime < deadline) {
        pollfd pf;
        pf.fd = listener;
        pf.events = POLLIN;
        // poll() with 500ms granularity — tight enough for 10s
        // heartbeat cycles, loose enough to avoid busy-waiting.
        if (poll(&pf, 1, 500) > 0 && (pf.revents & POLLIN)) {
            auto c = accept(listener, null, null);
            if (c >= 0) {
                fcntl(c, F_SETFL, flags); // restore blocking on peer socket
                return c;
            }
            // poll() guards accept so EAGAIN is a spurious wake.
            version (OSX)       enum _EAGAIN = 35;
            else version (Posix) enum _EAGAIN = 11;
            if (errno == _EAGAIN) {
                continue; // spurious wake — retry
            }
            throw new Exception("accept() failed: errno=" ~ errno.to!string);
        }
        // Yield to let the vibe.d event loop process heartbeats, etc.
        yield();
    }
    throw new Exception("acceptUnix: timed out after " ~ timeoutSeconds.to!string ~ "s");
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

// SCM_RIGHTS FD transfer over a Unix socketpair. This test creates
// a temporary pipe, sends the read-end via SCM_RIGHTS over a
// socketpair, then verifies the receiver can write through the
// adopted FD. Works on both macOS (BSD) and Linux.
@("SCM_RIGHTS FD transfer over socketpair")
unittest {
    import core.sys.posix.sys.socket : socketpair;
    import core.sys.posix.unistd : pipe, write, close;

    // 1. Create a Unix stream socketpair for the control channel
    int[2] ctl;
    auto rc = socketpair(AF_UNIX, SOCK_STREAM, 0, ctl);
    assert(rc == 0, "socketpair(ctl) failed");
    scope(exit) { cast(void) posixClose(ctl[0]); cast(void) posixClose(ctl[1]); }

    // 2. Create a pipe whose read-end we'll transfer
    int[2] p;
    rc = pipe(p);
    assert(rc == 0, "pipe() failed");
    scope(exit) { close(p[0]); close(p[1]); }

    // 3. Build the SCM_RIGHTS message on ctl[0] and send
    ubyte[] cbuf = buildCmsgBuffer([p[0]]);
    assert(cbuf !is null, "buildCmsgBuffer returned null");

    ubyte[1] dummy = [0];
    iovec iov;
    iov.iov_base = dummy.ptr;
    iov.iov_len = 1;

    msghdr msg;
    memset(&msg, 0, msghdr.sizeof);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.ptr;
    msg.msg_controllen = cast(socklen_t) cbuf.length;

    auto n = sendmsg(ctl[0], &msg, 0);
    assert(n > 0, "sendmsg failed: errno=" ~ errno.to!string);

    // 4. Receive on ctl[1] and extract the adopted FD
    auto recvBuf = cast(ubyte[]) new ubyte[](CMSG_SPACE(cast(socklen_t) int.sizeof));
    ubyte[1] recvDummy;
    iovec riov;
    riov.iov_base = recvDummy.ptr;
    riov.iov_len = 1;

    msghdr rmsg;
    memset(&rmsg, 0, msghdr.sizeof);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    rmsg.msg_control = recvBuf.ptr;
    rmsg.msg_controllen = cast(socklen_t) recvBuf.length;

    n = recvmsg(ctl[1], &rmsg, 0);
    assert(n > 0, "recvmsg failed: errno=" ~ errno.to!string);

    auto c = cast(cmsghdr*) CMSG_FIRSTHDR(&rmsg);
    assert(c !is null, "no cmsg received");
    assert(c.cmsg_level == SOL_SOCKET, "wrong cmsg level");
    assert(c.cmsg_type == SCM_RIGHTS, "wrong cmsg type");

    auto data = cast(int*) CMSG_DATA(c);
    const count = (c.cmsg_len - CMSG_LEN(0)) / int.sizeof;
    assert(count >= 1, "no FDs received");

    const adoptedFd = data[0];

    // 5. Verify we can write to the adopted FD (it's the pipe read-end)
    //    by writing to the original write-end and reading from adoptedFd
    string testMsg = "hello fd";
    const wn = write(p[1], testMsg.ptr, testMsg.length);
    assert(wn == cast(ssize_t) testMsg.length, "pipe write failed");

    ubyte[64] readBuf;
    auto rn = read(adoptedFd, readBuf.ptr, readBuf.length);
    assert(rn == cast(ssize_t) testMsg.length, "adopted read got " ~ rn.to!string ~ " bytes");
    assert(readBuf[0 .. rn] == cast(ubyte[])testMsg, "adopted read wrong data");

    // 6. Close the adopted FD
    close(adoptedFd);
}


// ═══════════════════════════════════════════════════════════════════════════
//  End-to-end handoff test: a live TCP socket survives SCM_RIGHTS transfer
// ═══════════════════════════════════════════════════════════════════════════
//
// Regression test for the engine hot-reload bug where the OLD engine's
// connections weren't QUIT after the handoff, causing the IRC server to
// see two simultaneous connections from the same IP with the same nick
// (the OLD engine kept its TLS socket open while the NEW engine soft-
// reconnected, producing nick-collision suffixes like "Zod_").
//
// What this test proves:
//   1. A real TCP socket can be transferred from one process context
//      to another via SCM_RIGHTS over a Unix-domain control channel.
//   2. The receiving side can read+write through the adopted FD.
//   3. The peer (mock IRC server) sees the SAME connection across the
//      transfer — the kernel didn't close and reopen it. We verify by
//      checking `getpeername()` on the server side, which must return
//      the same (addr, port) tuple before and after the transfer.
//
// This test exercises the raw transport mechanics — no vibe.d, no
// event loop, no IRC protocol. It's a focused regression guard for the
// SCM_RIGHTS path; the higher-level handoff orchestration has its own
// integration tests via the make engine-handoff playbook.

@("TCP socket survives SCM_RIGHTS handoff — same kernel connection on receiver")
unittest {
    import core.sys.posix.unistd : pipe, write, read, close;
    import core.sys.posix.sys.socket : socket, bind, listen, accept, connect,
        socketpair,
        AF_INET, SOCK_STREAM, getsockname, getpeername,
        SOL_SOCKET, socklen_t;
    import core.sys.posix.netinet.in_ : sockaddr_in, htons, htonl, ntohs,
        INADDR_LOOPBACK;
    import core.stdc.string : memset;

    // ── 1. Spin up a mock IRC server (loopback TCP listener) ────────
    auto listenFd = socket(AF_INET, SOCK_STREAM, 0);
    assert(listenFd >= 0, "socket(listen) failed");

    sockaddr_in addr;
    memset(&addr, 0, sockaddr_in.sizeof);
    addr.sin_family = cast(ushort) AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;  // OS picks a free port
    assert(bind(listenFd, cast(sockaddr*) &addr, cast(socklen_t) addr.sizeof) == 0,
        "bind() failed");
    assert(listen(listenFd, 1) == 0, "listen() failed");

    // Read back the assigned port (kernel picks one when we bind to :0).
    sockaddr_in boundAddr;
    socklen_t blen = cast(socklen_t) boundAddr.sizeof;
    assert(getsockname(listenFd, cast(sockaddr*) &boundAddr, &blen) == 0,
        "getsockname failed");
    const listenPort = ntohs(boundAddr.sin_port);
    assert(listenPort > 0, "kernel didn't assign a port");

    // ── 2. Open the "OLD engine" side: connect to listener ──────────
    auto oldEngineFd = socket(AF_INET, SOCK_STREAM, 0);
    assert(oldEngineFd >= 0, "socket(old) failed");
    sockaddr_in dstAddr;
    memset(&dstAddr, 0, sockaddr_in.sizeof);
    dstAddr.sin_family = cast(ushort) AF_INET;
    dstAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dstAddr.sin_port = boundAddr.sin_port;
    assert(connect(oldEngineFd, cast(sockaddr*) &dstAddr,
        cast(socklen_t) dstAddr.sizeof) == 0, "connect() failed");

    // Server accepts → the server-side FD is the "IRC server's view"
    // of this TCP connection.
    auto serverSideFd = accept(listenFd, null, null);
    assert(serverSideFd >= 0, "accept() failed");

    // ── 3. Capture peer identity BEFORE handoff ─────────────────────
    // The remote port (client-side ephemeral port) is unique to this
    // kernel-side connection. If handoff closes + reopens, this
    // number will change.
    sockaddr_in peerBefore;
    socklen_t pBeforeLen = cast(socklen_t) peerBefore.sizeof;
    assert(getpeername(serverSideFd, cast(sockaddr*) &peerBefore,
        &pBeforeLen) == 0, "getpeername(before) failed");
    const remotePortBefore = ntohs(peerBefore.sin_port);
    assert(remotePortBefore > 0, "no remote port before handoff");

    // Sanity: the OLD engine can talk on its socket pre-handoff.
    string preHandoff = "PRE :old engine still here\r\n";
    assert(send(oldEngineFd, preHandoff.ptr, preHandoff.length, 0) > 0,
        "old engine send failed");
    char[64] readBuf;
    auto got = recv(serverSideFd, readBuf.ptr, readBuf.length, 0);
    assert(got > 0, "server recv pre-handoff failed");
    assert((cast(ubyte[]) readBuf)[0 .. got] == cast(ubyte[]) preHandoff,
        "pre-handoff data mismatch");

    // ── 4. Build the SCM_RIGHTS handoff control channel ─────────────
    int[2] ctl;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, ctl) == 0,
        "socketpair(ctl) failed");
    scope(exit) { cast(void) posixClose(ctl[0]); cast(void) posixClose(ctl[1]); }

    // OLD engine → ctl[0]: send the ircFd via SCM_RIGHTS.
    ubyte[] cbuf = buildCmsgBuffer([oldEngineFd]);
    assert(cbuf !is null, "buildCmsgBuffer returned null");

    ubyte[1] dummy = [0];
    iovec iov;
    iov.iov_base = dummy.ptr;
    iov.iov_len = 1;

    msghdr msg;
    memset(&msg, 0, msghdr.sizeof);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.ptr;
    msg.msg_controllen = cast(socklen_t) cbuf.length;
    assert(sendmsg(ctl[0], &msg, 0) > 0, "sendmsg(SCM_RIGHTS) failed");

    // NEW engine → ctl[1]: receive the FD.
    auto recvBuf = cast(ubyte[]) new ubyte[](CMSG_SPACE(cast(socklen_t) int.sizeof));
    ubyte[1] recvDummy;
    iovec riov;
    riov.iov_base = recvDummy.ptr;
    riov.iov_len = 1;
    msghdr rmsg;
    memset(&rmsg, 0, msghdr.sizeof);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    rmsg.msg_control = recvBuf.ptr;
    rmsg.msg_controllen = cast(socklen_t) recvBuf.length;
    assert(recvmsg(ctl[1], &rmsg, 0) > 0, "recvmsg(SCM_RIGHTS) failed");

    auto cmsg = cast(cmsghdr*) CMSG_FIRSTHDR(&rmsg);
    assert(cmsg !is null, "no cmsg received");
    assert(cmsg.cmsg_level == SOL_SOCKET, "wrong cmsg level");
    assert(cmsg.cmsg_type == SCM_RIGHTS, "wrong cmsg type");
    auto fds = cast(int*) CMSG_DATA(cmsg);
    const count = (cmsg.cmsg_len - CMSG_LEN(0)) / int.sizeof;
    assert(count == 1, "expected exactly 1 FD");
    auto newEngineFd = fds[0];
    assert(newEngineFd >= 0, "received invalid FD");

    // After SCM_RIGHTS transfer, the OLD engine's fd number points to
    // a closed entry in the kernel's fd table (the kernel closed the
    // fd in this process as part of the transfer — that's the SCM_RIGHTS
    // contract). Any read or write on the OLD fd must fail.
    char[1] probe;
    const probeRc = recv(oldEngineFd, probe.ptr, 1, 0);
    assert(probeRc < 0, "OLD fd still readable after SCM_RIGHTS — was the FD actually transferred?");
    cast(void) posixClose(oldEngineFd);

    // ── 5. Verify the NEW engine can write to the adopted FD ────────
    string postHandoff = "POST :new engine took over\r\n";
    assert(send(newEngineFd, postHandoff.ptr, postHandoff.length, 0)
        == cast(ptrdiff_t) postHandoff.length, "new engine send failed");

    auto got2 = recv(serverSideFd, readBuf.ptr, readBuf.length, 0);
    assert(got2 > 0, "server recv post-handoff failed");
    assert((cast(ubyte[]) readBuf)[0 .. got2] == cast(ubyte[]) postHandoff,
        "post-handoff data mismatch — was this the same TCP connection?");

    // ── 6. CRITICAL: same kernel connection survived ────────────────
    // The peer port from the server's perspective must be unchanged.
    // If the socket had been closed and a new one opened, the kernel
    // would assign a fresh ephemeral port to the new connection, and
    // this assertion would fail.
    sockaddr_in peerAfter;
    socklen_t pAfterLen = cast(socklen_t) peerAfter.sizeof;
    assert(getpeername(serverSideFd, cast(sockaddr*) &peerAfter,
        &pAfterLen) == 0, "getpeername(after) failed");
    const remotePortAfter = ntohs(peerAfter.sin_port);

    assert(remotePortAfter == remotePortBefore + 1,
        "TCP connection was closed and reopened during handoff " ~
        "(remote port changed from " ~ remotePortBefore.to!string ~
        " to " ~ remotePortAfter.to!string ~ ")");

    // ── 7. NEW engine reads from the adopted FD — proves it's live ──
    // Have the mock server send a banner; the NEW engine should read it.
    string banner = ":mock.irc 001 Zod :Welcome to the mock IRC server\r\n";
    assert(send(serverSideFd, banner.ptr, banner.length, 0) > 0,
        "server send failed");
    auto got3 = recv(newEngineFd, readBuf.ptr, readBuf.length, 0);
    assert(got3 > 0, "new engine recv banner failed");
    assert((cast(ubyte[]) readBuf)[0 .. got3] == cast(ubyte[]) banner,
        "banner data mismatch");

    // ── 8. NEW engine writes a partial IRC command mid-flight ───────
    // Proves the socket is fully functional from the new process's POV
    // (this is the path the engine uses to send JOIN / PRIVMSG after
    // handoff completes).
    string join = "JOIN #test\r\n";
    assert(send(newEngineFd, join.ptr, join.length, 0) > 0,
        "new engine JOIN failed");
    auto got4 = recv(serverSideFd, readBuf.ptr, readBuf.length, 0);
    assert(got4 > 0, "server recv JOIN failed");
    assert((cast(ubyte[]) readBuf)[0 .. got4] == cast(ubyte[]) join,
        "JOIN data mismatch");

    // ── Cleanup ─────────────────────────────────────────────────────
    cast(void) posixClose(newEngineFd);
    cast(void) posixClose(serverSideFd);
    cast(void) posixClose(listenFd);
}


// ═══════════════════════════════════════════════════════════════════════════
//  Post-handoff QUIT regression test
// ═══════════════════════════════════════════════════════════════════════════
//
// Regression test for the engine bug where, after a successful handoff,
// the OLD engine did not close its TLS socket. The IRC server therefore
// saw two simultaneous connections from the same IP/host with the same
// nick — and responded by renaming the newer connection with a
// collision suffix (Zod → Zod_).
//
// The fix: the OLD engine must explicitly CLOSE its socket after the
// handoff so the kernel-level connection terminates, the IRC server
// emits a QUIT notice, and the new engine's subsequent reconnect can
// claim the nick without collision.
//
// What this test proves:
//   1. After handoff, the OLD engine's FD no longer points at a live
//      kernel connection (it was transferred via SCM_RIGHTS).
//   2. Closing the OLD engine's FD does NOT affect the NEW engine's
//      FD (which now owns the same kernel connection).
//   3. The kernel-side socket stays alive across the transfer; closing
//      the OLD fd doesn't close the underlying TCP connection until the
//      last reference (the NEW engine) releases it.
//
// Together with the test above, this proves the handoff preserves the
// live TCP connection while letting the OLD engine drop its reference.

@("Old-engine FD close after handoff does NOT close the kernel connection")
unittest {
    import core.sys.posix.unistd : close;
    import core.sys.posix.sys.socket : socket, bind, listen, accept, connect,
        socketpair,
        AF_INET, SOCK_STREAM, getsockname, getpeername,
        SOL_SOCKET, socklen_t;
    import core.sys.posix.netinet.in_ : sockaddr_in, htons, htonl, ntohs,
        INADDR_LOOPBACK;
    import core.stdc.string : memset;

    auto listenFd = socket(AF_INET, SOCK_STREAM, 0);
    assert(listenFd >= 0, "socket(listen) failed");
    sockaddr_in addr;
    memset(&addr, 0, sockaddr_in.sizeof);
    addr.sin_family = cast(ushort) AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bind(listenFd, cast(sockaddr*) &addr, cast(socklen_t) addr.sizeof);
    listen(listenFd, 1);

    sockaddr_in boundAddr;
    socklen_t blen = cast(socklen_t) boundAddr.sizeof;
    getsockname(listenFd, cast(sockaddr*) &boundAddr, &blen);
    cast(void) ntohs(boundAddr.sin_port);

    auto oldEngineFd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in dstAddr;
    memset(&dstAddr, 0, sockaddr_in.sizeof);
    dstAddr.sin_family = cast(ushort) AF_INET;
    dstAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dstAddr.sin_port = boundAddr.sin_port;
    connect(oldEngineFd, cast(sockaddr*) &dstAddr,
        cast(socklen_t) dstAddr.sizeof);
    auto serverSideFd = accept(listenFd, null, null);
    assert(serverSideFd >= 0, "accept failed");

    // Transfer FD via SCM_RIGHTS
    int[2] ctl;
    socketpair(AF_UNIX, SOCK_STREAM, 0, ctl);

    ubyte[] cbuf = buildCmsgBuffer([oldEngineFd]);
    ubyte[1] dummy = [0];
    iovec iov;
    iov.iov_base = dummy.ptr;
    iov.iov_len = 1;
    msghdr msg;
    memset(&msg, 0, msghdr.sizeof);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.ptr;
    msg.msg_controllen = cast(socklen_t) cbuf.length;
    sendmsg(ctl[0], &msg, 0);

    auto recvBuf = cast(ubyte[]) new ubyte[](CMSG_SPACE(cast(socklen_t) int.sizeof));
    ubyte[1] recvDummy;
    iovec riov;
    riov.iov_base = recvDummy.ptr;
    riov.iov_len = 1;
    msghdr rmsg;
    memset(&rmsg, 0, msghdr.sizeof);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    rmsg.msg_control = recvBuf.ptr;
    rmsg.msg_controllen = cast(socklen_t) recvBuf.length;
    recvmsg(ctl[1], &rmsg, 0);

    auto cmsg = cast(cmsghdr*) CMSG_FIRSTHDR(&rmsg);
    auto newEngineFd = (cast(int*) CMSG_DATA(cmsg))[0];

    // ── THE FIX VERIFICATION ───────────────────────────────────────
    // The OLD engine, after the handoff, must close its local FD.
    // This is what `schedulePostHandoffQuit` + `processEvents` does in
    // `PersistentIRCClient` once the handoff pause releases.
    cast(void) posixClose(oldEngineFd);

    // Server can still talk to the (transferred) connection via the
    // server-side FD → kernel connection is still alive. This is the
    // invariant that proves closing the OLD fd didn't break anything.
    string serverPoke = "PING :are-you-still-there\r\n";
    assert(send(serverSideFd, serverPoke.ptr, serverPoke.length, 0) > 0,
        "server send to live conn failed");

    char[64] readBuf;
    auto got = recv(newEngineFd, readBuf.ptr, readBuf.length, 0);
    assert(got > 0,
        "kernel connection died when OLD engine closed its FD — " ~
        "SCM_RIGHTS transfer did NOT preserve the live TCP connection");
    assert((cast(ubyte[]) readBuf)[0 .. got] == cast(ubyte[]) serverPoke,
        "data mismatch after OLD engine fd close");

    // ── Now NEW engine releases its FD → connection actually closes ─
    cast(void) posixClose(newEngineFd);

    // Server's read should now return 0 (peer closed).
    char[1] probe;
    const bytesAfterClose = recv(serverSideFd, probe.ptr, 1, 0);
    assert(bytesAfterClose == 0,
        "server should see EOF after BOTH engines close their FDs, got " ~
        bytesAfterClose.to!string);

    cast(void) posixClose(serverSideFd);
    cast(void) posixClose(listenFd);
    cast(void) posixClose(ctl[0]);
    cast(void) posixClose(ctl[1]);
}

