/**
 * Holder IPC: listener, first-line dispatch (`HELLO` / `DIAL` / `ATTACH`),
 * the control-session request loop and the registry of held connections.
 *
 * Also hosts the address helpers shared with the CLI client
 * (`parseHolderAddr`, `connectHolderAddr`).
 */
module holder.ipc;

import core.time : Duration, msecs, seconds;
import std.conv : to;
import std.process : environment, thisProcessID;
import std.string : startsWith, indexOf, lastIndexOf;
import vibe.core.core : runTask, sleep;
import vibe.core.net : NetworkAddress, TCPConnection, TCPListener, connectTCP, createStreamConnection,
    listenTCP, resolveHost;
import vibe.core.stream : IOMode;
import vibe.data.json : Json, parseJsonString;
import ircfiber.async : safeFiberRun;
import ircfiber.logging : logJsonMap;
import holder.dial : DialFailed, DialOutcome, dialUpstream, unixMsNow;
import holder.held : Held;
import holder.protocol;

// ── Addresses ───────────────────────────────────────────────────────────────

/// Parsed `IRCFIBER_HOLDER_ADDR`.
struct HolderAddr {
    bool isUnix;
    /// Filesystem path for unix addresses.
    string path;
    string host;
    ushort port;

    /// Socket address to listen on / dial. For a listening `0.0.0.0` /
    /// `::` this resolves to the loopback so a CLI client can dial it.
    NetworkAddress toNetworkAddress(bool forClient) {
        NetworkAddress addr;
        if (isUnix) {
            fillUnixAddr(addr, path);
            return addr;
        }
        auto h = host;
        if (forClient && (h == "0.0.0.0" || h == "::" || h == "[::]")) h = "127.0.0.1";
        addr = resolveHost(h);
        addr.port = port;
        return addr;
    }
}

/// Parses `unix:///path` or `tcp://host:port`; anything else throws.
HolderAddr parseHolderAddr(string s) {
    HolderAddr a;
    if (s.startsWith("unix://")) {
        a.isUnix = true;
        a.path = s["unix://".length .. $];
        if (a.path.length == 0 || a.path[0] != '/')
            throw new Exception("unix holder address must be absolute: " ~ s);
        return a;
    }
    if (s.startsWith("tcp://")) {
        auto hp = s["tcp://".length .. $];
        const colon = hp.lastIndexOf(":");
        if (colon <= 0 || colon == hp.length - 1)
            throw new Exception("tcp holder address needs host:port: " ~ s);
        a.host = hp[0 .. colon];
        if (a.host.length >= 2 && a.host[0] == '[' && a.host[$ - 1] == ']') a.host = a.host[1 .. $ - 1];
        const port = hp[colon + 1 .. $].to!long;
        if (port <= 0 || port > 65_535) throw new Exception("tcp holder port out of range: " ~ s);
        a.port = cast(ushort) port;
        return a;
    }
    throw new Exception("holder address must be unix:///path or tcp://host:port: " ~ s);
}

/// Fills `addr` with an AF_UNIX socket address for `path` (NUL-terminated;
/// a leading NUL selects the Linux abstract namespace). Throws when the
/// path does not fit `sun_path`.
void fillUnixAddr(ref NetworkAddress addr, string path) {
    import core.sys.posix.sys.un : sockaddr_un;
    import std.socket : AddressFamily;
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

/// Connects to a holder address.
///
/// AF_UNIX needs care with vibe-core 2.14.0: `connectTCP(NetworkAddress)`
/// always binds the client socket, and with the default bind address it
/// binds an all-zero `sockaddr_un` — on Linux that is the single abstract
/// name `"\0"*108`, so the second concurrent unix connection in a process
/// fails with EADDRINUSE. The alternative (`eventcore.connectStream` +
/// `createStreamConnection`) asserts because `createStreamConnection`
/// stores the peer address in a 16-byte `UnknownAddress`. So every unix
/// connect binds an explicit per-connection local name: an abstract one
/// on Linux (freed with the socket), a temporary file elsewhere (unlinked
/// right after the connect).
TCPConnection connectHolderAddr(NetworkAddress addr, Duration timeout) {
    import std.socket : AddressFamily;
    if (addr.family != AddressFamily.UNIX) return connectTCP(addr, NetworkAddress.init, timeout);
    const seq = ++g_unixBindSeq;
    const local = "ircfiber-uds-" ~ thisProcessID.to!string ~ "-" ~ seq.to!string;
    NetworkAddress bind;
    version (linux) {
        fillUnixAddr(bind, "\0" ~ local);
        return connectTCP(addr, bind, timeout);
    } else {
        import std.file : exists, remove, tempDir;
        import std.path : buildPath;
        const path = buildPath(tempDir(), local);
        fillUnixAddr(bind, path);
        scope (exit) unlinkQuietly(path);
        return connectTCP(addr, bind, timeout);
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

struct HolderConfig {
    string serverId;
    string addrText;
    HolderAddr addr;
    string token;
    string buildShort;
    string quitMsg;
    size_t detachBufferBytes;
    long detachMaxSecs;
    long closedRetainSecs;

    /// Over TCP the token is mandatory; over unix it is enforced when set.
    @property bool tokenRequired() const { return !addr.isUnix; }
}

private long envLong(string name, long def) {
    auto v = environment.get(name, "");
    if (v.length == 0) return def;
    try {
        const n = v.to!long;
        return n > 0 ? n : def;
    } catch (Exception) return def;
}

/// Reads every holder knob from the environment. `serverId` and the
/// address are validated by the caller (exit 78 on misconfiguration).
HolderConfig configFromEnv() {
    HolderConfig c;
    c.serverId = environment.get(ENV_SERVER_ID, "");
    c.addrText = environment.get(ENV_ADDR, DEFAULT_ADDR);
    c.addr = parseHolderAddr(c.addrText);
    c.token = environment.get(ENV_TOKEN, "");
    c.buildShort = environment.get(ENV_BUILD_SHORT, "dev");
    c.quitMsg = environment.get(ENV_QUIT_MSG, DEFAULT_QUIT_MSG);
    c.detachBufferBytes = cast(size_t) envLong(ENV_DETACH_BUFFER_BYTES, DETACH_BUFFER_BYTES);
    c.detachMaxSecs = envLong(ENV_DETACH_MAX_SECS, DETACH_MAX_SECS);
    c.closedRetainSecs = envLong(ENV_CLOSED_RETAIN_SECS, CLOSED_RETAIN_SECS);
    return c;
}

// ── Server ──────────────────────────────────────────────────────────────────

/// Thrown by request handlers; `code` becomes the `ERR` code.
private final class RequestError : Exception {
    string code;
    this(string code, string msg) { super(msg); this.code = code; }
}

/// Reads one `\n`-terminated line of at most `maxBytes`; throws
/// `RequestError(too_large)` beyond that and a plain exception on EOF.
private string readRequestLine(ref TCPConnection c, size_t maxBytes) {
    import vibe.stream.operations : readLine;
    try {
        return cast(string) readLine(c, maxBytes, "\n");
    } catch (Exception e) {
        if (e.msg.indexOf("maximum number of bytes") >= 0 || e.msg.indexOf("byte limit") >= 0
            || e.msg.indexOf("too long") >= 0)
            throw new RequestError(ERR_TOO_LARGE, "request line exceeds " ~ maxBytes.to!string ~ " bytes");
        throw e;
    }
}

private void writeLine(ref TCPConnection c, string line) {
    c.write(cast(const(ubyte)[]) (line ~ "\n"));
    c.flush();
}

/// The holder daemon: listener + registry of `Held` connections.
final class HolderServer {
    HolderConfig cfg;
    private Held[string] helds;
    private ulong nextId;
    private immutable long startedAtMs;
    private TCPListener listener;
    private bool shuttingDown;

    this(HolderConfig cfg) {
        this.cfg = cfg;
        this.startedAtMs = unixMsNow();
    }

    /// Binds the listen address and starts the closed-entry sweeper.
    void start() {
        auto addr = cfg.addr.toNetworkAddress(false);
        if (cfg.addr.isUnix) {
            import std.file : exists, remove;
            if (exists(cfg.addr.path)) remove(cfg.addr.path);
        }
        listener = listenTCP(&onConnection, addr);
        if (cfg.addr.isUnix) {
            import core.sys.posix.sys.stat : chmod;
            import std.conv : octal;
            import std.string : toStringz;
            chmod(cfg.addr.path.toStringz, octal!660);
        }
        logJsonMap("info", "holder", "Holder listening",
            ["addr": cfg.addrText, "serverId": cfg.serverId, "holder": cfg.buildShort, "event": "listen"]);
        safeFiberRun("holder_sweeper", "", &sweepClosed);
    }

    /// `STATUS` payload.
    Json statusJson() {
        long open, attached, detached, closed, buffered;
        foreach (h; helds) {
            if (h.isOpen) {
                open++;
                if (h.attached) attached++; else detached++;
                buffered += h.entry().bufferedBytes;
            } else {
                closed++;
            }
        }
        auto j = Json.emptyObject;
        j["proto"] = PROTO_VERSION;
        j["serverId"] = cfg.serverId;
        j["holder"] = cfg.buildShort;
        j["pid"] = cast(long) thisProcessID;
        j["uptimeMs"] = unixMsNow() - startedAtMs;
        j["open"] = open;
        j["attached"] = attached;
        j["detached"] = detached;
        j["closed"] = closed;
        j["bufferedBytes"] = buffered;
        return j;
    }

    /// Holder SIGTERM: QUIT every open session (full reconnect event).
    void quitAll() {
        shuttingDown = true;
        foreach (h; helds) h.sendQuit(cfg.quitMsg, CLOSE_HOLDER_SHUTDOWN);
    }

    /// Stops listening and removes the unix socket file.
    void stop() {
        try { listener.stopListening(); } catch (Exception) {}
        if (cfg.addr.isUnix) {
            import std.file : exists, remove;
            try { if (exists(cfg.addr.path)) remove(cfg.addr.path); } catch (Exception) {}
        }
    }

    private void sweepClosed() {
        while (!shuttingDown) {
            sleep(30.seconds);
            const cutoff = unixMsNow() - cfg.closedRetainSecs * 1000;
            string[] gone;
            foreach (id, h; helds) if (!h.isOpen && h.closedAtMs > 0 && h.closedAtMs < cutoff) gone ~= id;
            foreach (id; gone) helds.remove(id);
        }
    }

    // ── Connection handling ─────────────────────────────────────────────

    private void onConnection(TCPConnection c) @trusted nothrow {
        try handle(c);
        catch (Exception e) {
            try logJsonMap("warn", "holder", "IPC connection failed", ["error": e.msg, "event": "ipc_error"]);
            catch (Exception) {}
        }
        try c.close(); catch (Exception) {}
    }

    private void handle(TCPConnection c) @trusted {
        string verb;
        Json payload;
        try {
            auto line = readRequestLine(c, MAX_LINE);
            parseFirstLine(line, verb, payload);
        } catch (RequestError e) {
            writeLine(c, errLine(e.code, e.msg));
            return;
        } catch (Exception e) {
            // EOF before a request line (healthcheck probes, port scans).
            return;
        }
        if (shuttingDown) { writeLine(c, errLine(ERR_CLOSED, "holder shutting down")); return; }
        switch (verb) {
            case "HELLO": controlSession(c, payload); break;
            case "DIAL": dial(c, payload); break;
            case "ATTACH": attach(c, payload); break;
            default: writeLine(c, errLine(ERR_PROTO, "expected HELLO, DIAL or ATTACH"));
        }
    }

    private string tokenError(Json payload) {
        string presented = payload.type == Json.Type.object && payload["token"].type == Json.Type.string
            ? payload["token"].get!string : "";
        return checkToken(presented, cfg.token, cfg.tokenRequired);
    }

    private Held lookup(Json payload) {
        auto id = payload.type == Json.Type.object && payload["id"].type == Json.Type.string
            ? payload["id"].get!string : "";
        if (id.length == 0) throw new RequestError(ERR_BAD_REQUEST, "id required");
        auto h = id in helds;
        if (h is null) throw new RequestError(ERR_NOT_FOUND, "unknown connection " ~ id);
        return *h;
    }

    // ── HELLO → control session ─────────────────────────────────────────

    private void controlSession(ref TCPConnection c, Json payload) {
        auto hello = HelloRequest.fromJson(payload);
        if (auto code = checkHello(hello, cfg.serverId, cfg.token, cfg.tokenRequired)) {
            writeLine(c, errLine(code, code == ERR_PROTO ? "unsupported proto " ~ hello.proto.to!string
                : code == ERR_SERVER_ID ? "holder serves " ~ cfg.serverId : "bad token"));
            return;
        }
        auto ok = Json.emptyObject;
        ok["proto"] = PROTO_VERSION;
        ok["serverId"] = cfg.serverId;
        ok["holder"] = cfg.buildShort;
        ok["pid"] = cast(long) thisProcessID;
        ok["uptimeMs"] = unixMsNow() - startedAtMs;
        writeLine(c, okLine(ok));
        logJsonMap("info", "holder", "Control session opened",
            ["engine": hello.engine, "event": "hello"]);
        while (true) {
            string verb;
            Json req;
            try {
                auto line = readRequestLine(c, MAX_META + 4096);
                parseFirstLine(line, verb, req);
            } catch (RequestError e) {
                writeLine(c, errLine(e.code, e.msg));
                continue;
            } catch (Exception) {
                break; // engine closed the control session
            }
            string reply;
            try {
                reply = okLine(controlRequest(verb, req));
            } catch (RequestError e) {
                reply = errLine(e.code, e.msg);
            } catch (Exception e) {
                reply = errLine(ERR_BAD_REQUEST, e.msg);
            }
            writeLine(c, reply);
        }
        logJsonMap("info", "holder", "Control session closed", ["engine": hello.engine, "event": "hello_closed"]);
    }

    private Json controlRequest(string verb, Json req) {
        switch (verb) {
            case "LIST": {
                auto arr = Json.emptyArray;
                foreach (h; helds) arr ~= h.entry().toJson();
                auto j = Json.emptyObject;
                j["connections"] = arr;
                return j;
            }
            case "STATUS":
                return statusJson();
            case "INFO":
                return lookup(req).entry().toJson();
            case "META": {
                auto h = lookup(req);
                auto meta = req["meta"];
                if (meta.type == Json.Type.undefined) throw new RequestError(ERR_BAD_REQUEST, "meta required");
                if (meta.toString().length > MAX_META) throw new RequestError(ERR_TOO_LARGE, "meta exceeds 8 MiB");
                h.meta = meta;
                return Json.emptyObject;
            }
            case "CLOSE": {
                auto id = req.type == Json.Type.object && req["id"].type == Json.Type.string ? req["id"].get!string : "";
                if (id.length == 0) throw new RequestError(ERR_BAD_REQUEST, "id required");
                if (auto h = id in helds) {
                    auto quit = req["quit"].type == Json.Type.string ? req["quit"].get!string : "";
                    (*h).close(quit);
                    helds.remove(id);
                }
                return Json.emptyObject;
            }
            case "FORGET": {
                auto id = req.type == Json.Type.object && req["id"].type == Json.Type.string ? req["id"].get!string : "";
                if (id.length == 0) throw new RequestError(ERR_BAD_REQUEST, "id required");
                if (auto h = id in helds) {
                    if ((*h).isOpen) throw new RequestError(ERR_BUSY, "connection is open; use CLOSE");
                    helds.remove(id);
                }
                return Json.emptyObject;
            }
            default:
                throw new RequestError(ERR_BAD_REQUEST, "unknown request " ~ verb);
        }
    }

    // ── DIAL → relay ────────────────────────────────────────────────────

    private void dial(ref TCPConnection c, Json payload) {
        if (auto code = tokenError(payload)) { writeLine(c, errLine(code, "bad token")); return; }
        DialRequest req;
        try req = DialRequest.fromJson(payload);
        catch (Exception e) { writeLine(c, errLine(ERR_BAD_REQUEST, e.msg)); return; }

        auto fields = ["network": req.tag.name, "networkId": req.tag.networkId,
                       "host": req.host, "port": req.port.to!string, "tls": req.tls,
                       "egress": req.tag.egressLabel];
        if (req.hasProxy) fields["proxy"] = req.proxy.host ~ ":" ~ req.proxy.port.to!string;
        const startMs = unixMsNow();
        DialOutcome outcome;
        try {
            outcome = dialUpstream(req, (EventLine ev) { writeLine(c, "EVENT " ~ ev.toJson().toString()); });
        } catch (DialFailed e) {
            fields["event"] = "dial_fail";
            fields["phase"] = e.phase;
            fields["error"] = e.msg;
            fields["tookMs"] = (unixMsNow() - startMs).to!string;
            logJsonMap("warn", "holder", "Dial failed", fields);
            writeLine(c, "FAILED " ~ FailedLine(e.phase, e.msg).toJson().toString());
            return;
        } catch (Exception e) {
            fields["event"] = "dial_fail";
            fields["phase"] = "tcp";
            fields["error"] = e.msg;
            logJsonMap("warn", "holder", "Dial failed", fields);
            writeLine(c, "FAILED " ~ FailedLine("tcp", e.msg).toJson().toString());
            return;
        }
        auto id = "c-" ~ (++nextId).to!string;
        auto held = new Held(id, req, outcome, cfg.detachBufferBytes, cfg.detachMaxSecs);
        helds[id] = held;
        fields["event"] = "dial_ok";
        fields["id"] = id;
        fields["peerIp"] = held.peerIp;
        fields["tookMs"] = (unixMsNow() - startMs).to!string;
        logJsonMap("info", "holder", "Dial succeeded", fields);
        auto connected = ConnectedLine(id, held.peerIp, held.localIp, held.peerPort, held.localPort,
            held.connectedAtMs, held.tlsInfo);
        try {
            writeLine(c, "CONNECTED " ~ connected.toJson().toString());
        } catch (Exception) {
            return; // engine vanished: the session stays held for ATTACH
        }
        held.attach(c);
    }

    // ── ATTACH → relay ──────────────────────────────────────────────────

    private void attach(ref TCPConnection c, Json payload) {
        if (auto code = tokenError(payload)) { writeLine(c, errLine(code, "bad token")); return; }
        Held held;
        try held = lookup(payload);
        catch (RequestError e) { writeLine(c, errLine(e.code, e.msg)); return; }
        if (!held.isOpen) { writeLine(c, errLine(ERR_CLOSED, "upstream closed: " ~ held.closeReason)); return; }
        if (held.attached) { writeLine(c, errLine(ERR_BUSY, "already attached")); return; }
        writeLine(c, okLine(held.entry().toJson()));
        held.attach(c);
    }
}
