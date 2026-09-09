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
module ircfiber.engine.holder_client;

import core.time : Duration, msecs, seconds;
import std.conv : to;
import std.datetime : Clock;
import std.process : environment;
import std.socket : AddressFamily;
import std.string : startsWith, lastIndexOf, strip;

import vibe.core.core : runTask, sleep;
import vibe.core.log;
import vibe.core.net : TCPConnection, NetworkAddress, resolveHost, connectTCP;
import vibe.core.sync : TaskMutex;
import vibe.data.json : Json, parseJsonString;
import vibe.stream.operations : readLine;

import ircfiber.build_info : buildInfo;
import ircfiber.logging : logJsonMap;
import ircfiber.redis.protocol : TlsInfo;

/// Protocol version this client speaks.
enum HOLDER_PROTO = 1;
/// Longest IPC line either side may send (1 MiB).
enum HOLDER_MAX_LINE = 1024 * 1024;
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
    /// Per-user IPv6 source bind for direct dials; "" = none.
    string bindIp6;
    int connectTimeoutMs = 10_000;
    int tlsTimeoutMs = 10_000;
    int starttlsTimeoutMs = 15_000;

    Json toJson(string token) const {
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
            j["proxy"] = p;
        } else {
            j["proxy"] = Json(null);
        }
        j["bindIp6"] = bindIp6.length ? Json(bindIp6) : Json(null);
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
}

/// `STATUS` payload.
struct HolderStatus {
    int proto;
    string serverId;
    string holder;
    long pid;
    long uptimeMs;
    long open;
    long attached;
    long detached;
    long closed;
    long bufferedBytes;

    static HolderStatus fromJson(Json j) {
        HolderStatus s;
        s.proto = cast(int) jsonLong(j, "proto");
        s.serverId = jsonStr(j, "serverId");
        s.holder = jsonStr(j, "holder");
        s.pid = jsonLong(j, "pid");
        s.uptimeMs = jsonLong(j, "uptimeMs");
        s.open = jsonLong(j, "open");
        s.attached = jsonLong(j, "attached");
        s.detached = jsonLong(j, "detached");
        s.closed = jsonLong(j, "closed");
        s.bufferedBytes = jsonLong(j, "bufferedBytes");
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

/// Reads one `\n`-terminated IPC line (CR stripped). Throws on EOF/timeout.
private string readIpcLine(TCPConnection c) {
    auto raw = readLine(c, HOLDER_MAX_LINE, "\n");
    auto line = cast(string) raw.idup;
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

    private void openControl() {
        auto c = open(OPEN_TIMEOUT);
        scope (failure) { try c.close(); catch (Exception) {} }
        c.readTimeout = CONTROL_TIMEOUT;
        auto hello = Json.emptyObject;
        hello["proto"] = HOLDER_PROTO;
        hello["serverId"] = serverId;
        hello["engine"] = buildInfo().shortHash;
        if (token.length) hello["token"] = token;
        writeLine(c, "HELLO " ~ hello.toString());
        auto ok = expectOk(readIpcLine(c));
        if (jsonLong(ok, "proto") != HOLDER_PROTO)
            throw new HolderErrorException("proto", "holder speaks proto " ~ jsonLong(ok, "proto").to!string);
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
        if (!controlUp) {
            controlLost("control session down");
            throw new HolderUnavailableException("holder control session down");
        }
        string line = payload.type == Json.Type.undefined ? verb : verb ~ " " ~ payload.toString();
        string reply;
        try {
            writeLine(control, line);
            reply = readIpcLine(control);
        } catch (Exception e) {
            controlLost(e.msg);
            throw new HolderUnavailableException("holder control I/O failed: " ~ e.msg);
        }
        try {
            return expectOk(reply);
        } catch (HolderUnavailableException e) {
            controlLost(e.msg);
            throw e;
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

    /// Holder-wide counters and identity.
    HolderStatus status() {
        return HolderStatus.fromJson(request("STATUS"));
    }

    /// One entry by id. `HolderErrorException("not_found")` when unknown.
    HolderEntry info(string id) {
        return HolderEntry.fromJson(request("INFO", idPayload(id)));
    }

    /// Replaces the entry's opaque META (≤ 8 MiB; `too_large` above).
    void setMeta(string id, Json meta) {
        auto j = idPayload(id);
        j["meta"] = meta;
        request("META", j);
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

    // ── DIAL / ATTACH ──────────────────────────────────────────────────

    /// One dial attempt through exactly the egress in `req`. `EVENT` lines
    /// are forwarded to `progress` as they arrive; returns the relay stream
    /// on `CONNECTED`; throws `DialFailedException` on `FAILED`,
    /// `HolderUnavailableException` when the holder cannot be reached.
    DialResult dial(DialRequest req, DialProgress progress) {
        auto c = open(OPEN_TIMEOUT);
        bool keep;
        scope (exit) if (!keep) closeQuietly(c);
        c.readTimeout = DIAL_TIMEOUT;
        try {
            writeLine(c, "DIAL " ~ req.toJson(token).toString());
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
                    r.id = jsonStr(payload, "id");
                    r.peerIp = jsonStr(payload, "peerIp");
                    r.localIp = jsonStr(payload, "localIp");
                    r.peerPort = cast(ushort) jsonLong(payload, "peerPort");
                    r.localPort = cast(ushort) jsonLong(payload, "localPort");
                    r.connectedAtMs = jsonLong(payload, "connectedAtMs");
                    r.tlsOk = parseTls(payload["tls"], r.tls);
                    if (r.id.length == 0) throw new HolderUnavailableException("holder CONNECTED without id");
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
        auto c = open(OPEN_TIMEOUT);
        bool keep;
        scope (exit) if (!keep) closeQuietly(c);
        c.readTimeout = CONTROL_TIMEOUT;
        auto j = idPayload(id);
        if (token.length) j["token"] = token;
        string reply;
        try {
            writeLine(c, "ATTACH " ~ j.toString());
            reply = readIpcLine(c);
        } catch (Exception e) {
            throw new HolderUnavailableException("holder attach I/O failed: " ~ e.msg);
        }
        auto ok = expectOk(reply);
        AttachResult r;
        r.stream = c;
        r.entry = HolderEntry.fromJson(ok);
        if (r.entry.id.length == 0) r.entry.id = id;
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
