/**
 * Engine-side client of the connection holder (`irc-fiber-holder`).
 *
 * The holder owns every IRC TCP/SOCKS5/TLS socket and relays plaintext IRC
 * bytes to the engine over one stream per IRC connection. This module
 * speaks holder IPC protocol v1: one control session (request/response,
 * serialised by a TaskMutex) plus per-connection `DIAL`/`ATTACH` streams
 * that switch to raw relay mode after the holder's final status line.
 *
 * Strict single path: the engine never opens IRC sockets itself. When the
 * holder is unreachable, `dial()` throws `HolderUnavailableException` and
 * the connection loop retries; there is no direct fallback (that would
 * double-socket the server).
 *
 * Address: `IRCFIBER_HOLDER_ADDR` — `unix:///run/ircfiber/holder.sock`
 * (default) or `tcp://host:port`. Token: `IRCFIBER_HOLDER_TOKEN` (sent in
 * HELLO/DIAL/ATTACH when non-empty; mandatory on TCP holders).
 */
module ircfiber.holder_client;

import core.time : Duration, MonoTime, msecs, seconds;
import std.conv : to;
import std.datetime : Clock;
import std.process : environment;
import std.socket : AddressFamily;
import std.string : startsWith, lastIndexOf, strip;

import vibe.core.core : runTask, sleep, setTimer;
import vibe.core.log;
import vibe.core.net : TCPConnection, NetworkAddress, resolveHost, connectTCP;
import vibe.core.sync : TaskMutex;
import vibe.data.json : Json, JsonStringSerializer, parseJsonString;
import vibe.data.serialization : deserialize, optional, name;

import ircfiber.logging : logJsonMap;
import ircfiber.redis.protocol : TlsInfo;

/// Protocol version this client speaks.
enum HOLDER_PROTO = 1;
/// Longest IPC line this client may RECEIVE (64 MiB).
///
/// `LIST` answers with every held connection INCLUDING its `META`, which
/// `bootstrap` needs to restore each session, so the reply grows with the
/// number of connected users: 66 sessions of a few hundred KB each is
/// already tens of MiB, far past the 1 MiB request cap this used to
/// share. Reading a response with the request cap made `list()` — and so
/// every engine hot swap — fail once the network had enough users.
/// New holders use bounded metadata-free INVENTORY pages and per-entry INFO.
/// This larger limit remains necessary for the genuine legacy LIST fallback;
/// INVENTORY responses have their own 64 KiB receive limit.
enum HOLDER_MAX_RESPONSE = 64 * 1024 * 1024;
/// Default holder address (docker: shared named volume).
enum HOLDER_DEFAULT_ADDR = "unix:///run/ircfiber/holder.sock";

/// The holder cannot be reached (socket missing/refused, control session
/// down, IPC I/O failure). Callers retry; they never dial directly.
class HolderUnavailableException : Exception {
    this(string msg, string file = __FILE__, size_t line = __LINE__) { super(msg, file, line); }
}

/// The holder answered `ERR {"code":…}` to a request. `code` is one of
/// `proto`, `server_id`, `auth`, `bad_request`, `not_found`, `busy`,
/// `closed`, `too_large`.
class HolderErrorException : Exception {
    string code;
    this(string code, string msg, string file = __FILE__, size_t line = __LINE__) {
        super(msg, file, line);
        this.code = code;
    }
}

/// A `DIAL` ended with `FAILED`. `msg` is the holder's reason verbatim — the
/// engine's egress policy keys on substrings such as `TLS handshake timed out`.
class DialFailedException : Exception {
    /// `dns` | `tcp` | `socks5` | `tls` | `starttls` | `holder`.
    string phase;
    this(string phase, string reason, string file = __FILE__, size_t line = __LINE__) {
        super(reason, file, line);
        this.phase = phase;
    }
}

/// Identifies the IRC connection in holder listings (`tag` in DIAL/LIST).
struct DialTag {
    string networkId;
    string userId;
    string name;
    /// Mullvad slot label the engine dialed through; "" for direct.
    string egressLabel;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["networkId"] = networkId;
        j["userId"] = userId;
        j["name"] = name;
        j["egressLabel"] = egressLabel;
        return j;
    }

    static DialTag fromJson(Json j) {
        DialTag t;
        if (j.type != Json.Type.object) return t;
        t.networkId = jsonStr(j, "networkId");
        t.userId = jsonStr(j, "userId");
        t.name = jsonStr(j, "name");
        t.egressLabel = jsonStr(j, "egressLabel");
        return t;
    }
}

/// SOCKS5 sidecar the holder must CONNECT through (one DIAL = one egress).
struct DialProxy {
    string host;
    ushort port;
    string username;
    string password;
}

/// One dial attempt through exactly one egress.
struct DialRequest {
    DialTag tag;
    string host;
    ushort port;
    /// `none` | `implicit` | `starttls`.
    string tls = "implicit";
    string sni;
    bool hasProxy;
    DialProxy proxy;
    /// Actual requested source bind, never evidence of the socket's source.
    string bindIp6;
    int connectTimeoutMs = 10_000;
    int tlsTimeoutMs = 10_000;
    int starttlsTimeoutMs = 15_000;
    string addressFamily = "any";

    void validate() const {
        if (addressFamily != "any" && addressFamily != "ipv6")
            throw new HolderErrorException("bad_request", "unknown addressFamily");
        if (addressFamily == "ipv6") {
            import core.sys.posix.arpa.inet : inet_pton;
            import core.sys.posix.sys.socket : AF_INET6;
            if (hasProxy || !bindIp6.length || bindIp6.length > 45)
                throw new HolderErrorException("bad_request", "ipv6 requires an IPv6 source and no proxy");
            char[46] text = void;
            foreach (i, c; bindIp6) {
                if (c == '\0')
                    throw new HolderErrorException("bad_request", "invalid IPv6 source");
                text[i] = c;
            }
            text[bindIp6.length] = '\0';
            ubyte[16] address;
            if (inet_pton(AF_INET6, text.ptr, address.ptr) != 1)
                throw new HolderErrorException("bad_request", "invalid IPv6 source");
        }
    }

    Json toJson(string token) const {
        validate();
        auto j = Json.emptyObject;
        if (token.length) j["token"] = token;
        j["tag"] = tag.toJson();
        j["host"] = host;
        j["port"] = cast(int) port;
        j["tls"] = tls;
        j["sni"] = sni;
        if (hasProxy) {
            auto p = Json.emptyObject;
            p["host"] = proxy.host;
            p["port"] = cast(int) proxy.port;
            if (proxy.username.length) p["username"] = proxy.username;
            if (proxy.password.length) p["password"] = proxy.password;
            j["proxy"] = p;
        } else {
            j["proxy"] = Json(null);
        }
        j["bindIp6"] = bindIp6.length ? Json(bindIp6) : Json(null);
        j["addressFamily"] = addressFamily;
        j["connectTimeoutMs"] = connectTimeoutMs;
        j["tlsTimeoutMs"] = tlsTimeoutMs;
        j["starttlsTimeoutMs"] = starttlsTimeoutMs;
        return j;
    }
}

/// One `EVENT` line of a dial, forwarded to the connection's timeline in
/// real time. `egress*` are filled by the engine wrapper from the candidate
/// proxy, not by the holder.
struct DialEvent {
    /// `attempt` | `attempt_fail` | `dns` | `tcp_open` | `tls` | `starttls` | `info`.
    string phase;
    string text;
    string peerIp;
    string localIp;
    ushort peerPort;
    ushort localPort;
    string egressLabel;
    string egressHost;
    string egressIp;
    string egressLocationText;
}

/// Progress sink for a dial. Never throws: it runs inside the dial loop.
alias DialProgress = void delegate(ref DialEvent) nothrow;

/// `CONNECTED` payload plus the relay stream.
struct DialResult {
    TCPConnection stream;
    string instance;
    string id;
    string peerIp;
    string localIp;
    ushort peerPort;
    ushort localPort;
    long connectedAtMs;
    bool tlsOk;
    TlsInfo tls;
}

/// One `LIST`/`INFO`/`ATTACH` entry.
struct HolderEntry {
    string id;
    string instance;
    ulong ordinal;
    long gapGeneration;
    long gapAckGeneration;
    long droppedBytes;
    long droppedLines;
    long gapStartedAtMs;
    bool deliveryAmbiguous;
    DialTag tag;
    /// `open` | `closed`.
    string state;
    bool attached;
    string host;
    ushort port;
    bool tlsOk;
    TlsInfo tls;
    string peerIp;
    string localIp;
    long connectedAtMs;
    /// 0 when attached or never detached.
    long detachedSinceMs;
    long bufferedBytes;
    string closeReason;
    long closedAtMs;
    /// Opaque engine META (SessionSnapshot JSON); `Json.undefined` when unset.
    Json meta;

    static HolderEntry fromJson(Json j) {
        HolderEntry e;
        e.id = jsonStr(j, "id");
        e.instance = jsonStr(j, "instance");
        e.ordinal = cast(ulong) jsonLong(j, "ordinal");
        e.gapGeneration = jsonLong(j, "gapGeneration");
        e.gapAckGeneration = jsonLong(j, "gapAckGeneration");
        e.droppedBytes = jsonLong(j, "droppedBytes");
        e.droppedLines = jsonLong(j, "droppedLines");
        e.gapStartedAtMs = jsonLong(j, "gapStartedAtMs");
        e.deliveryAmbiguous = jsonBool(j, "deliveryAmbiguous");
        e.tag = DialTag.fromJson(j["tag"]);
        e.state = jsonStr(j, "state");
        e.attached = jsonBool(j, "attached");
        e.host = jsonStr(j, "host");
        e.port = cast(ushort) jsonLong(j, "port");
        e.tlsOk = parseTls(j["tls"], e.tls);
        e.peerIp = jsonStr(j, "peerIp");
        e.localIp = jsonStr(j, "localIp");
        e.connectedAtMs = jsonLong(j, "connectedAtMs");
        e.detachedSinceMs = jsonLong(j, "detachedSinceMs");
        e.bufferedBytes = jsonLong(j, "bufferedBytes");
        e.closeReason = jsonStr(j, "closeReason");
        e.closedAtMs = jsonLong(j, "closedAtMs");
        auto m = j["meta"];
        e.meta = (m.type == Json.Type.undefined || m.type == Json.Type.null_) ? Json.undefined : m;
        return e;
    }

    /// True when the entry carries an engine META object.
    bool hasMeta() const { return meta.type == Json.Type.object; }

    /// Independent small backing allocations, suitable for asynchronous evidence
    /// consumers even when this entry came from a full legacy restoration LIST.
    HolderEntry ownedIdentity() const {
        HolderEntry e;
        e.id = id.idup;
        e.instance = instance.idup;
        e.state = state.idup;
        e.host = host.idup;
        e.peerIp = peerIp.idup;
        e.localIp = localIp.idup;
        e.closeReason = closeReason.idup;
        e.ordinal = ordinal;
        e.gapGeneration = gapGeneration;
        e.gapAckGeneration = gapAckGeneration;
        e.droppedBytes = droppedBytes;
        e.droppedLines = droppedLines;
        e.gapStartedAtMs = gapStartedAtMs;
        e.deliveryAmbiguous = deliveryAmbiguous;
        e.tag = DialTag(tag.networkId.idup, tag.userId.idup, tag.name.idup, tag.egressLabel.idup);
        e.attached = attached;
        e.port = port;
        e.tlsOk = tlsOk;
        e.tls.version_ = tls.version_.idup;
        e.tls.cipher = tls.cipher.idup;
        e.tls.certCn = tls.certCn.idup;
        e.tls.certIssuer = tls.certIssuer.idup;
        e.tls.certNotAfterMs = tls.certNotAfterMs;
        e.connectedAtMs = connectedAtMs;
        e.detachedSinceMs = detachedSinceMs;
        e.bufferedBytes = bufferedBytes;
        e.closedAtMs = closedAtMs;
        return e;
    }
}

/// `STATUS` payload.
struct HolderStatus {
    int proto;
    string instance;
    string[] capabilities;
    string serverId;
    string holder;
    long pid;
    long uptimeMs;
    long open;
    /// False for missing/malformed counts: unknown is not an empty holder.
    bool openAvailable;
    long attached;
    long detached;
    long closed;
    long bufferedBytes;
    /// Missing capability metadata is an old holder: shared direct only.
    string[] dialFamilies;

    bool supportsFamily(string family) const {
        if (family == "any") return true;
        if (family != "ipv6") return false;
        foreach (value; dialFamilies) if (value == family) return true;
        return false;
    }

    static HolderStatus fromJson(Json j) {
        HolderStatus s;
        s.proto = cast(int) jsonLong(j, "proto");
        s.instance = jsonStr(j, "instance");
        if (j["capabilities"].type == Json.Type.array)
            foreach (value; j["capabilities"])
                if (value.type == Json.Type.string) s.capabilities ~= value.get!string;
        s.serverId = jsonStr(j, "serverId");
        s.holder = jsonStr(j, "holder");
        s.pid = jsonLong(j, "pid");
        s.uptimeMs = jsonLong(j, "uptimeMs");
        s.open = jsonLong(j, "open");
        if (j.type == Json.Type.object && j["open"].type == Json.Type.int_)
            s.openAvailable = j["open"].get!long >= 0;
        s.attached = jsonLong(j, "attached");
        s.detached = jsonLong(j, "detached");
        s.closed = jsonLong(j, "closed");
        s.bufferedBytes = jsonLong(j, "bufferedBytes");
        if (j["dialFamilies"].type == Json.Type.array) {
            bool valid = true;
            foreach (value; j["dialFamilies"]) {
                if (value.type != Json.Type.string
                        || (value.get!string != "any" && value.get!string != "ipv6")) {
                    valid = false;
                    break;
                }
                s.dialFamilies ~= value.get!string;
            }
            if (!valid) s.dialFamilies = null;
        }
        return s;
    }
}

/// `ATTACH` result: the relay stream plus the entry as the holder sees it.
struct AttachResult {
    TCPConnection stream;
    HolderEntry entry;
}

// ── JSON helpers (tolerant: missing/null → default) ─────────────────────

private string jsonStr(Json j, string key) {
    if (j.type != Json.Type.object) return "";
    auto v = j[key];
    return v.type == Json.Type.string ? v.get!string : "";
}

private long jsonLong(Json j, string key) {
    if (j.type != Json.Type.object) return 0;
    auto v = j[key];
    if (v.type == Json.Type.int_) return v.get!long;
    if (v.type == Json.Type.float_) return cast(long) v.get!double;
    return 0;
}

private bool jsonBool(Json j, string key) {
    if (j.type != Json.Type.object) return false;
    auto v = j[key];
    return v.type == Json.Type.bool_ ? v.get!bool : false;
}

private bool parseTls(Json j, out TlsInfo info) {
    if (j.type != Json.Type.object) return false;
    info.version_ = jsonStr(j, "version");
    info.cipher = jsonStr(j, "cipher");
    info.certCn = jsonStr(j, "certCn");
    info.certIssuer = jsonStr(j, "certIssuer");
    info.certNotAfterMs = jsonLong(j, "certNotAfterMs");
    return jsonBool(j, "ok");
}

private long unixMsNow() {
    return Clock.currTime.toUnixTime!long * 1000;
}

/// A consuming input range for exactly one LF-terminated response. Like
/// readUntilSmall, peek first and consume only through this delimiter: a
/// disposable range must never hide bytes belonging to the next response.
/// char front is a UTF-8 octet, not a ubyte promoted to a Unicode codepoint.
private final class FrameInputRange {
    @safe:
    private TCPConnection stream;
    private MonoTime deadline;
    private size_t limit, received, position, available, consumed;
    private bool terminated;
    private ubyte[] storage;

    this(TCPConnection stream, MonoTime deadline, size_t limit) {
        this.stream = stream;
        this.deadline = deadline;
        this.limit = limit;
        // Byte-array storage is not a conservatively scanned class payload.
        storage = new ubyte[65536];
    }

    private void checkDeadline() {
        const remaining = deadline - MonoTime.currTime;
        if (remaining <= 0.seconds) throw new Exception("holder response deadline exceeded");
        stream.readTimeout = remaining;
    }

    @property bool empty() {
        if (position < available) return false;
        if (terminated) return true;
        checkDeadline();
        if (stream.empty) throw new Exception("truncated holder response");
        checkDeadline();
        auto bytes = stream.peek();
        size_t count = bytes.length < storage.length ? bytes.length : storage.length;
        // No peek support: one octet cannot cross the response boundary.
        if (!count) count = 1;
        else foreach (i; 0 .. count)
            if (bytes[i] == '\n') { count = i + 1; break; }
        if (count > limit - received)
            throw new Exception("holder response exceeds receive limit");
        stream.read(storage[0 .. count]);
        received += count;
        position = 0;
        available = count;
        if (storage[count - 1] == '\n') {
            terminated = true;
            available--;
        }
        return available == 0;
    }

    @property char front() {
        if (empty) throw new Exception("truncated holder response value");
        return cast(char) storage[position];
    }

    void popFront() {
        if (empty) throw new Exception("truncated holder response value");
        position++;
        if ((++consumed & 4095) == 0) checkDeadline();
    }

    void finish() {
        while (!empty) {
            const c = front;
            if (c != ' ' && c != '\t' && c != '\r')
                throw new Exception("trailing data in holder response");
            popFront();
        }
        checkDeadline();
    }
}

/// No custom fromJson hooks here: unknown META is consumed by the existing
/// serializer's allocation-free skipValue rather than constructing a Json tree.
private struct HolderWireTag {
    @optional string networkId;
    @optional string userId;
    @optional string name;
    @optional string egressLabel;
}

private struct HolderWireTls {
    @optional bool ok;
    @optional @name("version") string version_;
    @optional string cipher;
    @optional string certCn;
    @optional string certIssuer;
    @optional long certNotAfterMs;
}

private struct HolderWireEntry {
    @optional string id;
    @optional string instance;
    @optional ulong ordinal;
    @optional long gapGeneration;
    @optional long gapAckGeneration;
    @optional long droppedBytes;
    @optional long droppedLines;
    @optional long gapStartedAtMs;
    @optional bool deliveryAmbiguous;
    @optional HolderWireTag tag;
    @optional string state;
    @optional bool attached;
    @optional string host;
    @optional ushort port;
    @optional HolderWireTls tls;
    @optional string peerIp;
    @optional string localIp;
    @optional long connectedAtMs;
    @optional long detachedSinceMs;
    @optional long bufferedBytes;
    @optional string closeReason;
    @optional long closedAtMs;

    HolderEntry entry() {
        HolderEntry e;
        foreach (field; __traits(allMembers, HolderWireEntry)) {
            static if (field != "tag" && field != "tls" && field != "entry")
                __traits(getMember, e, field) = __traits(getMember, this, field);
        }
        e.tag = DialTag(tag.networkId, tag.userId, tag.name, tag.egressLabel);
        e.tlsOk = tls.ok;
        e.tls.version_ = tls.version_;
        e.tls.cipher = tls.cipher;
        e.tls.certCn = tls.certCn;
        e.tls.certIssuer = tls.certIssuer;
        e.tls.certNotAfterMs = tls.certNotAfterMs;
        return e;
    }
}

private struct HolderWireList {
    @optional HolderWireEntry[] connections;
}

private struct HolderWireError {
    @optional string code;
    @optional string msg;
}

private T readIpcResponse(T)(TCPConnection stream, MonoTime deadline, size_t maxBytes) {
    auto input = new FrameInputRange(stream, deadline, maxBytes);
    char[8] verb;
    size_t length;
    while (!input.empty && input.front != ' ') {
        if (length == verb.length) throw new Exception("invalid holder response verb");
        verb[length++] = input.front;
        input.popFront();
    }
    if (input.empty) throw new Exception("missing holder response payload");
    input.popFront();
    if (verb[0 .. length] == "ERR") {
        auto error = deserialize!(JsonStringSerializer!(FrameInputRange, false, 128, 65536), HolderWireError)(input);
        input.finish();
        throw new HolderErrorException(error.code, error.msg);
    }
    if (verb[0 .. length] != "OK") throw new Exception("unexpected holder response verb");
    static if (is(T == Json)) {
        // Full restoration deliberately retains META. Keep the existing JSON
        // tree API, without imposing a forward-range contract on the stream.
        import std.array : appender;
        auto payload = appender!string;
        while (!input.empty) { payload.put(input.front); input.popFront(); }
        auto result = parseJsonString(payload.data);
        input.finish();
        return result;
    } else {
        auto result = deserialize!(JsonStringSerializer!(FrameInputRange, false, 128, 65536), T)(input);
        input.finish();
        return result;
    }
}

/// Full-line users (DIAL/ATTACH) share the same exact-delimiter reader.
private string readIpcLine(TCPConnection c, size_t maxBytes = HOLDER_MAX_RESPONSE) {
    import std.array : appender;
    const timeout = c.readTimeout == Duration.max ? 10.seconds : c.readTimeout;
    auto input = new FrameInputRange(c, MonoTime.currTime + timeout, maxBytes);
    auto out_ = appender!string;
    while (!input.empty) { out_.put(input.front); input.popFront(); }
    input.finish();
    auto line = out_.data;
    if (line.length && line[$ - 1] == '\r') line = line[0 .. $ - 1];
    return line;
}

/// Splits `VERB <json>` into the verb and its payload (`Json.undefined`
/// when the line has no payload).
private void splitStatusLine(string line, out string verb, out Json payload) {
    import std.string : indexOf;
    const sp = line.indexOf(' ');
    if (sp < 0) { verb = line; payload = Json.undefined; return; }
    verb = line[0 .. sp];
    auto rest = line[sp + 1 .. $].strip;
    payload = rest.length ? parseJsonString(rest) : Json.undefined;
}

/// Throws `HolderErrorException` for an `ERR` line, returns the payload
/// for `OK`, and throws `HolderUnavailableException` for anything else.
private Json expectOk(string line) {
    string verb; Json payload;
    splitStatusLine(line, verb, payload);
    if (verb == "OK") return payload;
    if (verb == "ERR") throw new HolderErrorException(jsonStr(payload, "code"), jsonStr(payload, "msg"));
    throw new HolderUnavailableException("holder sent unexpected line: " ~ line);
}

/// Fills `addr` with an AF_UNIX socket address for `path` (NUL-terminated;
/// a leading NUL selects the Linux abstract namespace). Throws when the
/// path does not fit `sun_path`.
private void fillUnixAddr(ref NetworkAddress addr, string path) {
    import core.sys.posix.sys.un : sockaddr_un;
    addr.family = AddressFamily.UNIX;
    auto sun = addr.sockAddrUnix;
    if (path.length >= sun.sun_path.length)
        throw new Exception("unix socket path too long: " ~ path);
    sun.sun_path[] = 0;
    foreach (i, c; path) sun.sun_path[i] = cast(typeof(sun.sun_path[0])) c;
    // BSD `sun_len`: the kernel overwrites it from the addrlen argument,
    // but vibe-core's `NetworkAddress.toAddressString` slices
    // `sun_path[0 .. sun_len]` — set it to the path length so error
    // messages render instead of asserting on an out-of-range slice.
    static if (__traits(hasMember, sockaddr_un, "sun_len"))
        sun.sun_len = cast(ubyte) path.length;
}

private __gshared uint g_unixBindSeq;

private void unlinkQuietly(string path) nothrow {
    import std.file : exists, remove;
    try { if (exists(path)) remove(path); } catch (Exception) {}
}

/**
 * Connects to a holder address.
 *
 * AF_UNIX needs care with vibe-core 2.14.0: `connectTCP(NetworkAddress)`
 * always binds the client socket, and with the default bind address it
 * binds an all-zero `sockaddr_un` — on Linux that is the single abstract
 * name `"\0"*108`, so the second concurrent unix connection in a process
 * fails with EADDRINUSE. The alternative (`eventcore.connectStream` +
 * `createStreamConnection`) asserts because `createStreamConnection`
 * stores the peer address in a 16-byte `UnknownAddress`. So every unix
 * connect binds an explicit per-connection local name: an abstract one on
 * Linux (freed with the socket), a temporary file elsewhere (unlinked right
 * after the connect). Same helper as the holder CLI (`holder.ipc`).
 */
private TCPConnection connectHolderAddr(NetworkAddress addr, Duration timeout) {
    import std.process : thisProcessID;
    if (addr.family != AddressFamily.UNIX) return connectTCP(addr, NetworkAddress.init, timeout);
    const seq = ++g_unixBindSeq;
    const local = "ircfiber-uds-" ~ thisProcessID.to!string ~ "-" ~ seq.to!string;
    NetworkAddress bind;
    version (linux) {
        fillUnixAddr(bind, "\0" ~ local);
        return connectTCP(addr, bind, timeout);
    } else {
        import std.file : tempDir;
        import std.path : buildPath;
        const path = buildPath(tempDir(), local);
        fillUnixAddr(bind, path);
        scope (exit) unlinkQuietly(path);
        return connectTCP(addr, bind, timeout);
    }
}

/// Client of one holder (this engine's). One instance per engine, owned
/// by `EngineContext.holder`.
final class HolderClient {
    private {
        string addrText;
        NetworkAddress addr;
        string token;
        string serverId;
        TCPConnection control;
        bool controlUp;
        bool reconnecting;
        TaskMutex mutex;
        /// Set once the first control session was established; afterwards a
        /// loss is logged as `holder_unavailable` and repaired in background.
        bool booted;
        string currentInstance;
        bool inventoryCapable;
        // Identity/state only. Never retain a META tree between observations.
        DialTag[string] knownTags;
    }

    enum CONTROL_TIMEOUT = 10.seconds;
    enum DIAL_TIMEOUT = 60.seconds;
    enum OPEN_TIMEOUT = 5.seconds;

    /// `addrText` empty → `IRCFIBER_HOLDER_ADDR` / default; `token` empty →
    /// `IRCFIBER_HOLDER_TOKEN`.
    this(string serverId, string addrText = "", string token = "") {
        this.serverId = serverId;
        this.addrText = addrText.length ? addrText : environment.get("IRCFIBER_HOLDER_ADDR", HOLDER_DEFAULT_ADDR);
        this.token = token.length ? token : environment.get("IRCFIBER_HOLDER_TOKEN", "");
        this.addr = parseHolderAddr(this.addrText);
        this.mutex = new TaskMutex;
    }

    /// Human form of the configured address (safe for UNIX addresses, whose
    /// `NetworkAddress.toString` asserts).
    @property string address() const { return addrText; }

    /// `unix://<path>` → AF_UNIX address; `tcp://<host>:<port>` → resolved
    /// host + port. Anything else throws (boot fails with exit 78).
    static NetworkAddress parseHolderAddr(string text) {
        text = text.strip;
        if (text.startsWith("unix://")) {
            auto path = text["unix://".length .. $];
            if (path.length == 0) throw new Exception("IRCFIBER_HOLDER_ADDR: empty unix socket path");
            NetworkAddress a;
            try fillUnixAddr(a, path);
            catch (Exception e) throw new Exception("IRCFIBER_HOLDER_ADDR: " ~ e.msg);
            return a;
        }
        if (text.startsWith("tcp://")) {
            auto hp = text["tcp://".length .. $];
            const colon = hp.lastIndexOf(':');
            if (colon <= 0 || colon == hp.length - 1)
                throw new Exception("IRCFIBER_HOLDER_ADDR: tcp:// needs host:port, got '" ~ text ~ "'");
            auto host = hp[0 .. colon];
            if (host.length > 2 && host[0] == '[' && host[$ - 1] == ']') host = host[1 .. $ - 1];
            auto a = resolveHost(host);
            a.port = hp[colon + 1 .. $].to!ushort;
            return a;
        }
        throw new Exception("IRCFIBER_HOLDER_ADDR must be unix://<path> or tcp://<host>:<port>, got '" ~ text ~ "'");
    }

    // ── Control session ────────────────────────────────────────────────

    /// Establishes the control session, retrying a refused/missing holder
    /// every second for `IRCFIBER_HOLDER_CONNECT_TIMEOUT_SECS` (default 60)
    /// and then exiting 75 (the container restart policy retries). A
    /// protocol/serverId mismatch is a deployment error → exit 78.
    void connectControl() {
        import core.stdc.stdlib : exit;
        const timeoutSecs = environment.get("IRCFIBER_HOLDER_CONNECT_TIMEOUT_SECS", "60").to!long;
        const deadline = unixMsNow() + timeoutSecs * 1000;
        string lastErr;
        while (true) {
            try {
                openControl();
                booted = true;
                logInfo("Holder control session established at %s", addrText);
                return;
            } catch (HolderErrorException e) {
                if (e.code == "proto" || e.code == "server_id" || e.code == "auth") {
                    logJsonMap("error", "holder", "Holder rejected this engine — fix the deployment",
                        ["addr": addrText, "code": e.code, "err": e.msg, "event": "holder_rejected"]);
                    exit(78);
                }
                lastErr = e.code ~ ": " ~ e.msg;
            } catch (Exception e) {
                lastErr = e.msg;
            }
            if (unixMsNow() >= deadline) {
                logJsonMap("error", "holder", "Connection holder unreachable at boot",
                    ["addr": addrText, "err": lastErr, "timeoutSecs": timeoutSecs.to!string,
                     "event": "holder_boot_timeout"]);
                exit(75);
            }
            logWarn("Holder not reachable at %s (%s) — retrying in 1s", addrText, lastErr);
            sleep(1.seconds);
        }
    }

    /// Whether the control session is currently believed to be up.
    @property bool controlAlive() const { return controlUp; }
    @property string instance() const { return currentInstance; }

    private void observeIdentity(Json payload) {
        const observed = jsonStr(payload, "instance");
        if (observed != currentInstance) knownTags = null;
        currentInstance = observed;
        inventoryCapable = false;
        if (payload["capabilities"].type == Json.Type.array)
            foreach (capability; payload["capabilities"])
                if (capability.type == Json.Type.string
                        && capability.get!string == "inventory_v1") inventoryCapable = true;
    }

    private void openControl() {
        auto c = open(OPEN_TIMEOUT);
        scope (failure) { try c.close(); catch (Exception) {} }
        c.readTimeout = CONTROL_TIMEOUT;
        auto hello = Json.emptyObject;
        hello["proto"] = HOLDER_PROTO;
        hello["serverId"] = serverId;
        hello["engine"] = environment.get("IRCFIBER_BUILD_SHORT", "dev");
        if (token.length) hello["token"] = token;
        const deadline = MonoTime.currTime + CONTROL_TIMEOUT;
        auto timeout = setTimer(CONTROL_TIMEOUT, {
            try c.close(); catch (Exception) {}
        });
        scope(exit) timeout.stop();
        writeLine(c, "HELLO " ~ hello.toString());
        auto ok = readIpcResponse!Json(c, deadline, HOLDER_MAX_RESPONSE);
        if (jsonLong(ok, "proto") != HOLDER_PROTO)
            throw new HolderErrorException("proto", "holder speaks proto " ~ jsonLong(ok, "proto").to!string);
        observeIdentity(ok);
        control = c;
        controlUp = true;
        logJsonMap("info", "holder", "Holder control session up",
            ["addr": addrText, "holder": jsonStr(ok, "holder"), "pid": jsonLong(ok, "pid").to!string,
             "uptimeMs": jsonLong(ok, "uptimeMs").to!string, "event": "holder_control_up"]);
    }

    /// Opens a fresh IPC stream to the holder (control, DIAL or ATTACH).
    private TCPConnection open(Duration timeout) {
        try {
            return connectHolderAddr(addr, timeout);
        } catch (HolderUnavailableException e) {
            throw e;
        } catch (Exception e) {
            throw new HolderUnavailableException("holder connect failed: " ~ e.msg);
        }
    }

    private static void writeLine(TCPConnection c, string line) {
        c.write(cast(const(ubyte)[]) (line ~ "\n"));
        c.flush();
    }

    private static void closeQuietly(TCPConnection c) nothrow {
        try c.close(); catch (Exception) {}
    }

    /// Marks the control session dead and repairs it in the background
    /// (1 s cadence, forever). Logged once per outage.
    private void controlLost(string why) {
        if (controlUp) {
            controlUp = false;
            try control.close(); catch (Exception) {}
            if (booted)
                logJsonMap("error", "holder", "Holder control session lost",
                    ["addr": addrText, "err": why, "event": "holder_unavailable"]);
        }
        if (reconnecting || !booted) return;
        reconnecting = true;
        runTask(() nothrow {
            scope (exit) reconnecting = false;
            while (!controlUp) {
                try {
                    openControl();
                    logJsonMap("info", "holder", "Holder control session recovered",
                        ["addr": addrText, "event": "holder_recovered"]);
                    return;
                } catch (Exception e) {
                    string m; try { m = e.msg; } catch (Exception) { m = "unknown"; }
                    try logDebug("Holder control reconnect failed: %s", m); catch (Exception) {}
                }
                try sleep(1.seconds); catch (Exception) {}
            }
        });
    }

    /// One control request. Serialised (one in flight), 10 s timeout.
    private Json request(string verb, Json payload = Json.undefined) {
        mutex.lock();
        scope (exit) mutex.unlock();
        return requestLocked(verb, payload);
    }

    /// The caller owns mutex, including snapshot construction and retries.
    private Json requestLocked(string verb, Json payload = Json.undefined) {
        return requestDecodedLocked!Json(verb, payload);
    }

    /// The same lock and framing for full restoration and metadata-free
    /// evidence. Start the deadline before writing, not once each chunk arrives.
    private T requestDecodedLocked(T)(string verb, Json payload = Json.undefined) {
        if (!controlUp) {
            controlLost("control session down");
            throw new HolderUnavailableException("holder control session down");
        }
        const deadline = MonoTime.currTime + CONTROL_TIMEOUT;
        auto stream = control;
        auto timeout = setTimer(CONTROL_TIMEOUT, {
            try stream.close(); catch (Exception) {}
        });
        scope(exit) timeout.stop();
        try {
            const line = payload.type == Json.Type.undefined ? verb : verb ~ " " ~ payload.toString();
            writeLine(stream, line);
            return readIpcResponse!T(stream, deadline, verb == "INVENTORY" ? 65536 : HOLDER_MAX_RESPONSE);
        } catch (HolderErrorException e) {
            // A valid ERR has consumed its terminator. The control is reusable.
            throw e;
        } catch (Exception e) {
            controlLost(e.msg);
            throw new HolderUnavailableException("holder control I/O failed: " ~ e.msg);
        }
    }

    private static Json idPayload(string id) {
        auto j = Json.emptyObject;
        j["id"] = id;
        return j;
    }

    /// Every connection the holder knows about (open and retained closed).
    HolderEntry[] list() {
        auto ok = request("LIST");
        HolderEntry[] out_;
        auto arr = ok["connections"];
        if (arr.type == Json.Type.array)
            foreach (e; arr) out_ ~= HolderEntry.fromJson(e);
        return out_;
    }

    /// A fresh physical scan. New holders send bounded, META-free pages;
    /// legacy holders genuinely require LIST (no invented LIST options).
    /// Unknown tags are learned through streaming INFO with META skipped.
    /// includeMeta is a pre-read requirement for old LIST only; INVENTORY
    /// restoration still fetches selected entries through INFO.
    HolderEntry[] scan(bool includeMeta = false) {
        if (!inventoryCapable) {
            knownTags = null;
            if (includeMeta) return list();
            mutex.lock();
            scope(exit) mutex.unlock();
            auto wire = requestDecodedLocked!HolderWireList("LIST");
            auto entries = new HolderEntry[wire.connections.length];
            foreach (i, row; wire.connections) entries[i] = row.entry();
            return entries;
        }
        HolderEntry[] result;
        DialTag[string] liveTags;
        string scanInstance;
        long after, through;
        bool first = true;
        while (true) {
            auto payload = Json.emptyObject;
            if (!first) {
                payload["instance"] = scanInstance;
                payload["after"] = after;
                payload["through"] = through;
            }
            auto page = request("INVENTORY", payload);
            const identity = jsonStr(page, "instance");
            if (!identity.length || (first ? identity != currentInstance : identity != scanInstance))
                throw new HolderUnavailableException("holder changed during inventory");
            if (first) { scanInstance = identity; through = jsonLong(page, "through"); }
            else if (jsonLong(page, "through") != through)
                throw new HolderUnavailableException("holder inventory boundary changed");
            if (through < 0 || jsonLong(page, "after") != after)
                throw new HolderUnavailableException("invalid holder inventory cursor");
            auto rows = page["connections"];
            if (rows.type != Json.Type.array || rows.length > 128)
                throw new HolderUnavailableException("invalid bounded holder inventory");
            auto previous = cast(ulong) after;
            foreach (row; rows) {
                auto entry = HolderEntry.fromJson(row);
                entry.instance = scanInstance;
                if (!entry.id.length || entry.ordinal <= previous
                        || entry.ordinal > cast(ulong) through || result.length >= 65536)
                    throw new HolderUnavailableException("invalid holder inventory ordinal");
                previous = entry.ordinal;
                if (auto tag = entry.id in knownTags) entry.tag = *tag;
                else {
                    auto detail = infoIdentity(entry.id);
                    if (detail.id != entry.id || detail.instance != scanInstance
                            || detail.connectedAtMs != entry.connectedAtMs || detail.state != entry.state)
                        throw new HolderUnavailableException("holder entry changed during inventory");
                    entry.tag = detail.tag;
                }
                liveTags[entry.id] = entry.tag;
                result ~= entry;
            }
            if (!jsonBool(page, "more")) break;
            const next = jsonLong(page, "nextAfter");
            if (next <= after || next < cast(long) previous || next > through || rows.length == 0)
                throw new HolderUnavailableException("holder inventory made no progress");
            after = next;
            first = false;
        }
        knownTags = liveTags;
        return result;
    }

    void acknowledgeGap(string id, long generation) {
        auto payload = idPayload(id);
        payload["generation"] = generation;
        request("GAP_ACK", payload);
    }

    /// Holder-wide counters and identity.
    HolderStatus status() {
        auto payload = request("STATUS");
        observeIdentity(payload);
        return HolderStatus.fromJson(payload);
    }

    /// One entry by id. `HolderErrorException("not_found")` when unknown.
    HolderEntry info(string id) {
        auto entry = HolderEntry.fromJson(request("INFO", idPayload(id)));
        if (!entry.instance.length) entry.instance = currentInstance;
        return entry;
    }

    /// Fresh claim/state evidence without materializing the opaque META tree.
    /// INFO still consumes and validates the complete wire response.
    HolderEntry infoIdentity(string id) {
        mutex.lock();
        scope(exit) mutex.unlock();
        auto entry = requestDecodedLocked!HolderWireEntry("INFO", idPayload(id)).entry();
        if (!entry.instance.length) entry.instance = currentInstance;
        return entry;
    }

    /// Replaces the entry's opaque META (≤ 8 MiB; `too_large` above).
    void setMeta(string id, Json meta) {
        auto j = idPayload(id);
        j["meta"] = meta;
        request("META", j);
    }

    /// Construct META only after control admission. The callback MUST NOT
    /// yield; undefined cancels a stale publication without sending anything.
    /// It is scoped to this call, never retained by the holder client.
    void setMetaLazy(string id, scope Json delegate(bool dropMembers) buildMeta) {
        mutex.lock();
        scope (exit) {
            buildMeta = null;
            mutex.unlock();
        }
        void attempt(bool dropMembers) {
            auto meta = buildMeta(dropMembers);
            scope (exit) meta = Json.undefined;
            if (meta.type == Json.Type.undefined) return;
            auto payload = idPayload(id);
            payload["meta"] = meta;
            scope (exit) payload = Json.undefined;
            requestLocked("META", payload);
        }
        try attempt(false);
        catch (HolderErrorException e) {
            if (e.code != "too_large") throw e;
            // The first tree has been relinquished before building another.
            // The lock stays held, so a strict marker cannot be overtaken.
            attempt(true);
        }
    }

    /// Closes the upstream. Non-empty `quit` → the holder sends
    /// `QUIT :<quit>` and waits ≤ 2 s for EOF; empty → immediate close.
    /// Idempotent for unknown ids.
    void close(string id, string quit = "") {
        auto j = idPayload(id);
        j["quit"] = quit;
        request("CLOSE", j);
    }

    /// Drops a retained `closed` entry.
    void forget(string id) {
        request("FORGET", idPayload(id));
    }

    /// Guard and mutation share the lock: a legacy c-N reused after holder
    /// death must never close/forget another process's socket.
    private bool mutateClaim(string verb, string id, string incarnation, long connectedAtMs, string quit) {
        mutex.lock();
        scope(exit) mutex.unlock();
        auto entry = requestDecodedLocked!HolderWireEntry("INFO", idPayload(id)).entry();
        if (entry.id != id || entry.instance != incarnation
                || connectedAtMs <= 0 || entry.connectedAtMs != connectedAtMs)
            return false;
        auto payload = idPayload(id);
        if (verb == "CLOSE") payload["quit"] = quit;
        requestLocked(verb, payload);
        return true;
    }

    bool closeClaim(string id, string incarnation, long connectedAtMs, string quit = "") {
        return mutateClaim("CLOSE", id, incarnation, connectedAtMs, quit);
    }

    bool forgetClaim(string id, string incarnation, long connectedAtMs) {
        return mutateClaim("FORGET", id, incarnation, connectedAtMs, "");
    }

    // ── DIAL / ATTACH ──────────────────────────────────────────────────

    /// One dial attempt through exactly the egress in `req`. `EVENT` lines
    /// are forwarded to `progress` as they arrive; returns the relay stream
    /// on `CONNECTED`; throws `DialFailedException` on `FAILED`,
    /// `HolderUnavailableException` when the holder cannot be reached.
    /// onResponse commits pacing once the holder has processed this DIAL.
    /// A completed local write alone does not prove remote admission.
    DialResult dial(DialRequest req, DialProgress progress,
            scope void delegate() beforeSend = null,
            scope void delegate() onResponse = null) {
        auto requestPayload = req.toJson(token);
        if (req.addressFamily == "ipv6" && !status().supportsFamily("ipv6"))
            throw new DialFailedException("holder", "holder lacks IPv6-only dial capability");
        const dialIncarnation = currentInstance;
        auto c = open(OPEN_TIMEOUT);
        bool keep;
        scope (exit) if (!keep) closeQuietly(c);
        c.readTimeout = DIAL_TIMEOUT;
        // Admit at the actual DIAL boundary, after stream setup can yield.
        if (beforeSend !is null) beforeSend();
        if (currentInstance != dialIncarnation)
            throw new HolderErrorException("incarnation_changed", "holder changed before DIAL; request was not sent");
        try {
            writeLine(c, "DIAL " ~ requestPayload.toString());
        } catch (Exception e) {
            throw new HolderUnavailableException("holder dial write failed: " ~ e.msg);
        }
        while (true) {
            string line;
            try {
                line = readIpcLine(c);
            } catch (Exception e) {
                throw new DialFailedException("holder", "holder dial timed out");
            }
            string verb; Json payload;
            try splitStatusLine(line, verb, payload);
            catch (Exception e) throw new HolderUnavailableException("holder sent malformed dial line: " ~ e.msg);
            if (onResponse !is null) {
                onResponse();
                onResponse = null;
            }
            switch (verb) {
                case "EVENT":
                    if (progress !is null) {
                        DialEvent ev;
                        ev.phase = jsonStr(payload, "phase");
                        ev.text = jsonStr(payload, "text");
                        ev.peerIp = jsonStr(payload, "peerIp");
                        ev.localIp = jsonStr(payload, "localIp");
                        ev.peerPort = cast(ushort) jsonLong(payload, "peerPort");
                        ev.localPort = cast(ushort) jsonLong(payload, "localPort");
                        progress(ev);
                    }
                    continue;
                case "CONNECTED":
                    DialResult r;
                    r.stream = c;
                    r.instance = jsonStr(payload, "instance");
                    if (!r.instance.length) r.instance = currentInstance;
                    r.id = jsonStr(payload, "id");
                    r.peerIp = jsonStr(payload, "peerIp");
                    r.localIp = jsonStr(payload, "localIp");
                    r.peerPort = cast(ushort) jsonLong(payload, "peerPort");
                    r.localPort = cast(ushort) jsonLong(payload, "localPort");
                    r.connectedAtMs = jsonLong(payload, "connectedAtMs");
                    r.tlsOk = parseTls(payload["tls"], r.tls);
                    if (r.id.length == 0) throw new HolderUnavailableException("holder CONNECTED without id");
                    if (inventoryCapable && knownTags.length < 65536) knownTags[r.id] = req.tag;
                    c.readTimeout = Duration.max;
                    keep = true;
                    return r;
                case "FAILED":
                    throw new DialFailedException(jsonStr(payload, "phase"), jsonStr(payload, "reason"));
                case "ERR":
                    throw new HolderErrorException(jsonStr(payload, "code"), jsonStr(payload, "msg"));
                default:
                    throw new HolderUnavailableException("holder sent unexpected dial line: " ~ line);
            }
        }
    }

    /// Re-attaches to a held connection. Throws `HolderErrorException` with
    /// `not_found` / `busy` / `closed`, `HolderUnavailableException` when
    /// the holder cannot be reached.
    AttachResult attach(string id) {
        return attachDecoded!Json(id);
    }

    /// Engine restoration already has canonical META. Consume it on the wire
    /// without constructing another tree; retain fresh relay and claim facts.
    AttachResult attachIdentity(string id) {
        return attachDecoded!HolderWireEntry(id);
    }

    private AttachResult attachDecoded(T)(string id) {
        auto c = open(OPEN_TIMEOUT);
        bool keep;
        scope (exit) if (!keep) closeQuietly(c);
        c.readTimeout = CONTROL_TIMEOUT;
        auto j = idPayload(id);
        if (token.length) j["token"] = token;
        HolderEntry entry;
        const deadline = MonoTime.currTime + CONTROL_TIMEOUT;
        try {
            writeLine(c, "ATTACH " ~ j.toString());
            auto wire = readIpcResponse!T(c, deadline, HOLDER_MAX_RESPONSE);
            static if (is(T == Json)) {
                // Bot checkpoints genuinely restore directly from ATTACH.
                entry = HolderEntry.fromJson(wire);
                if (!entry.id.length) entry.id = id;
            } else {
                entry = wire.entry();
            }
        } catch (HolderErrorException e) {
            throw e;
        } catch (Exception e) {
            throw new HolderUnavailableException("holder attach I/O failed: " ~ e.msg);
        }
        AttachResult r;
        r.stream = c;
        r.entry = entry;
        c.readTimeout = Duration.max;
        keep = true;
        return r;
    }
}

@("parseHolderAddr accepts unix:// and tcp://")
unittest {
    import core.sys.posix.sys.un : sockaddr_un;
    auto u = HolderClient.parseHolderAddr("unix:///run/ircfiber/holder.sock");
    assert(u.family == AddressFamily.UNIX);
    auto sun = u.sockAddrUnix;
    import std.string : fromStringz;
    assert(fromStringz(cast(const(char)*) sun.sun_path.ptr) == "/run/ircfiber/holder.sock");

    auto t = HolderClient.parseHolderAddr("tcp://127.0.0.1:7690");
    assert(t.family == AddressFamily.INET);
    assert(t.port == 7690);

    bool threw;
    try HolderClient.parseHolderAddr("http://x"); catch (Exception) threw = true;
    assert(threw);
}

@("splitStatusLine and expectOk")
unittest {
    string verb; Json payload;
    splitStatusLine(`OK {"proto":1,"serverId":"ovh"}`, verb, payload);
    assert(verb == "OK" && payload["serverId"].get!string == "ovh");
    splitStatusLine("STATUS", verb, payload);
    assert(verb == "STATUS" && payload.type == Json.Type.undefined);
    bool threw;
    try expectOk(`ERR {"code":"busy","msg":"already attached"}`);
    catch (HolderErrorException e) { threw = e.code == "busy"; }
    assert(threw);
}
