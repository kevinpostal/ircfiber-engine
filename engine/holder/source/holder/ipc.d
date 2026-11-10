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
import ircfiber.irc.ipv6 : ipv6InRoutedPrefix;
import holder.dial : DialFailed, DialOutcome, dialUpstream, unixMsNow;
import holder.held : Held, HeldMemoryCounters, HeldAdmissionException,
    sampleHeldMemory, heldAdmissionAvailable, HeldQueueCounters, sampleHeldQueues, mergeHeldQueueProgress;
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
    /// Provider-owned, strictly validated /64. Empty disables source binds.
    string routedIpv6Prefix;

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
    c.detachMaxSecs = parseDetachMaxSecs(environment.get(ENV_DETACH_MAX_SECS, DETACH_MAX_SECS.to!string));
    c.closedRetainSecs = envLong(ENV_CLOSED_RETAIN_SECS, CLOSED_RETAIN_SECS);
    c.routedIpv6Prefix = environment.get("IRCFIBER_IPV6_PREFIX", "");
    return c;
}

/// Run only after authenticating DIAL. This applies to source-bound requests
/// of either family mode; "any" must not be an escape from pool ownership.
void validateSourcePool(const ref DialRequest req, string routedPrefix) {
    req.validateTransport();
    if (req.bindIp6.length && !ipv6InRoutedPrefix(routedPrefix, req.bindIp6))
        throw new Exception("DIAL: IPv6 source is outside the configured routed pool");
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
    private static final class Record {
        string id;
        ulong ordinal;
        Held owner;
        Entry tombstone;
        bool visible = true;
        Record previous, next, closedPrevious, closedNext;

        Entry entry(bool includeMeta = true) {
            return owner !is null ? owner.entry(includeMeta) : tombstone;
        }
    }
    private Record[string] records;
    private Record[ulong] ordinals;
    private Record first, last, firstClosed, lastClosed;
    private size_t tombstoneCount;
    private long nextTombstoneExpiryMs = long.max;
    private ulong nextId;
    private immutable long startedAtMs;
    immutable string instance;
    private TCPListener listener;
    private bool shuttingDown;

    this(HolderConfig cfg) {
        this.cfg = cfg;
        this.startedAtMs = unixMsNow();
        import std.uuid : randomUUID;
        this.instance = randomUUID().toString();
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

    /// No snapshots or META trees are constructed to report ownership.
    Json statusJson() {
        pruneTombstones(unixMsNow());
        long open, attached, detached, closed;
        ulong buffered;
        for (auto record = first; record !is null; record = record.next) {
            if (!record.visible) continue;
            auto h = record.owner;
            if (h !is null && h.isOpen) {
                ++open;
                if (h.attached) ++attached; else ++detached;
                buffered += h.bufferedBytes;
            } else ++closed;
        }
        auto j = Json.emptyObject;
        j["proto"] = PROTO_VERSION;
        j["serverId"] = cfg.serverId;
        j["instance"] = instance;
        j["capabilities"] = capabilitiesJson();
        j["dialFamilies"] = Json([Json("any"), Json("ipv6")]);
        j["holder"] = cfg.buildShort;
        j["pid"] = cast(long) thisProcessID;
        j["uptimeMs"] = unixMsNow() - startedAtMs;
        j["open"] = open;
        j["attached"] = attached;
        j["detached"] = detached;
        j["closed"] = closed;
        j["bufferedBytes"] = counterJson(buffered);
        auto counters = sampleHeldMemory();
        static foreach (i; 0 .. HeldMemoryCounters.tupleof.length)
            j[__traits(identifier, HeldMemoryCounters.tupleof[i])] = counterJson(counters.tupleof[i]);
        j["tombstones"] = cast(long) tombstoneCount;
        j["retiringEntries"] = counterJson(counters.tombstones);
        return j;
    }

    /// Used by the independent runtime sampler; no metadata or identity text.
    size_t tinyTombstones() const { return tombstoneCount; }

    HeldQueueCounters[3] runtimeQueues() {
        auto result = sampleHeldQueues();
        for (auto record = first; record !is null; record = record.next)
            if (record.owner !is null) mergeHeldQueueProgress(record.owner, result);
        return result;
    }

    private Json capabilitiesJson() {
        auto values = Json.emptyArray;
        foreach (capability; HOLDER_CAPABILITIES) values ~= Json(capability);
        return values;
    }

    private Record registerHeld(Held held) {
        auto record = new Record;
        record.id = held.id;
        record.ordinal = held.ordinal;
        record.owner = held;
        appendRecord(record);
        held.onRetireQuiescent = { retire(record); };
        return record;
    }

    private void appendRecord(Record record) {
        record.previous = last;
        if (last !is null) last.next = record; else first = record;
        last = record;
        records[record.id] = record;
        ordinals[record.ordinal] = record;
    }

    /// Called only after every reader/writer/timer relinquishes ownership.
    /// Keep no tags, TLS certificates, request strings, META or payload backing.
    private void retire(Record record) {
        auto h = record.owner;
        if (h is null || !h.getRetireQuiescent()) return;
        auto e = h.entry(false);
        auto tiny = Entry.init;
        tiny.id = record.id;
        tiny.instance = instance;
        tiny.ordinal = record.ordinal;
        tiny.state = "closed";
        tiny.connectedAtMs = e.connectedAtMs;
        tiny.closedAtMs = e.closedAtMs;
        tiny.closeReason = boundedCloseReason(e.closeReason);
        tiny.gapGeneration = e.gapGeneration;
        tiny.gapAckGeneration = e.gapAckGeneration;
        tiny.droppedBytes = e.droppedBytes;
        tiny.droppedLines = e.droppedLines;
        tiny.gapStartedAtMs = e.gapStartedAtMs;
        tiny.deliveryAmbiguous = e.deliveryAmbiguous;
        tiny.attachmentGeneration = e.attachmentGeneration;
        tiny.attachmentWriterCompletions = e.attachmentWriterCompletions;
        tiny.upstreamWriterDone = e.upstreamWriterDone;
        tiny.tlsFinalized = e.tlsFinalized;
        record.tombstone = tiny;
        h.onRetireQuiescent = null;
        record.owner = null;
        if (!record.visible) { removeRecord(record); return; }
        retainClosedRecord(record, unixMsNow());
    }

    private void retainClosedRecord(Record record, long nowMs) {
        record.closedPrevious = lastClosed;
        if (lastClosed !is null) lastClosed.closedNext = record; else firstClosed = record;
        lastClosed = record;
        ++tombstoneCount;
        const expires = record.tombstone.closedAtMs + tombstoneRetentionMs();
        if (expires < nextTombstoneExpiryMs) nextTombstoneExpiryMs = expires;
        pruneTombstones(nowMs);
    }

    private void removeRecord(Record record) {
        if (record.previous !is null) record.previous.next = record.next; else first = record.next;
        if (record.next !is null) record.next.previous = record.previous; else last = record.previous;
        if (record.owner is null) {
            if (record.closedPrevious !is null) record.closedPrevious.closedNext = record.closedNext;
            else if (firstClosed is record) firstClosed = record.closedNext;
            if (record.closedNext !is null) record.closedNext.closedPrevious = record.closedPrevious;
            else if (lastClosed is record) lastClosed = record.closedPrevious;
            if (record.visible) --tombstoneCount;
        }
        records.remove(record.id);
        ordinals.remove(record.ordinal);
        record.previous = record.next = record.closedPrevious = record.closedNext = null;
    }

    private long tombstoneRetentionMs() const {
        // Configuration may request less retention, never more than one hour.
        const retain = cfg.closedRetainSecs < CLOSED_RETAIN_SECS ? cfg.closedRetainSecs : CLOSED_RETAIN_SECS;
        return retain * 1000;
    }

    private void pruneTombstones(long nowMs) {
        while (tombstoneCount > MAX_TOMBSTONES) removeRecord(firstClosed);
        // Constant-time ordinary close/admission. Only scan bounded tombstones
        // when the next known expiry is due, not on every completed session.
        if (nowMs < nextTombstoneExpiryMs) return;
        nextTombstoneExpiryMs = long.max;
        auto record = firstClosed;
        while (record !is null) {
            auto next = record.closedNext;
            const expires = record.tombstone.closedAtMs + tombstoneRetentionMs();
            if (expires <= nowMs) removeRecord(record);
            else if (expires < nextTombstoneExpiryMs) nextTombstoneExpiryMs = expires;
            record = next;
        }
    }

    private Json inventory(Json request) {
        const after = jsonUnsigned(request, "after");
        const hasThrough = request["through"].type != Json.Type.undefined;
        const through = hasThrough ? jsonUnsigned(request, "through", true) : nextId;
        auto requestedInstance = request["instance"];
        if ((hasThrough || after) && (requestedInstance.type != Json.Type.string
            || requestedInstance.get!string != instance))
            throw new RequestError(ERR_BAD_REQUEST, "inventory instance mismatch");
        if (!hasThrough && after) throw new RequestError(ERR_BAD_REQUEST, "through required after page one");
        if (requestedInstance.type != Json.Type.undefined && (requestedInstance.type != Json.Type.string
            || requestedInstance.get!string != instance))
            throw new RequestError(ERR_BAD_REQUEST, "inventory instance mismatch");
        if (after > through || through > nextId)
            throw new RequestError(ERR_BAD_REQUEST, "invalid inventory cursor");

        auto rows = Json.emptyArray;
        size_t rowBytes, rowCount;
        ulong cursor = after;
        Record record;
        if (auto previous = after in ordinals) record = (*previous).next;
        else {
            record = first;
            while (record !is null && record.ordinal <= after) record = record.next;
        }
        bool more;
        while (record !is null && record.ordinal <= through) {
            if (record.visible) {
                auto row = record.entry(false).inventoryJson();
                const bytes = row.toString().length + (rowCount ? 1 : 0);
                // The bounded instance, cursors, flags and OK/newline envelope
                // occupy <512 bytes even with maximum-width integer cursors.
                if (rowCount == MAX_INVENTORY_ROWS || rowBytes + bytes + 512 > MAX_INVENTORY_BYTES) {
                    more = true;
                    break;
                }
                rows ~= row;
                rowBytes += bytes;
                ++rowCount;
            }
            cursor = record.ordinal;
            record = record.next;
        }
        if (!more) cursor = through;
        auto page = Json.emptyObject;
        page["instance"] = instance;
        page["through"] = cast(long) through;
        page["after"] = cast(long) after;
        page["nextAfter"] = cast(long) cursor;
        page["more"] = more;
        page["connections"] = rows;
        return page;
    }

    /// Holder SIGTERM: QUIT every open session (full reconnect event).
    void quitAll() {
        shuttingDown = true;
        for (auto record = first; record !is null; record = record.next)
            if (record.owner !is null) record.owner.sendQuit(cfg.quitMsg, CLOSE_HOLDER_SHUTDOWN);
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
            const now = unixMsNow();
            pruneTombstones(now);
            auto delayMs = nextTombstoneExpiryMs > now ? nextTombstoneExpiryMs - now : 1;
            if (delayMs > 30_000) delayMs = 30_000;
            sleep(delayMs.msecs);
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

    private Record lookupRecord(Json payload, bool allowMissing = false) {
        auto id = payload.type == Json.Type.object && payload["id"].type == Json.Type.string
            ? payload["id"].get!string : "";
        if (id.length == 0 || id.length > 128) throw new RequestError(ERR_BAD_REQUEST, "bounded id required");
        auto record = id in records;
        if (record is null || !(*record).visible) {
            if (allowMissing) return null;
            throw new RequestError(ERR_NOT_FOUND, "unknown connection");
        }
        return *record;
    }

    private Held lookup(Json payload) {
        auto record = lookupRecord(payload);
        if (record.owner is null || !record.owner.isOpen)
            throw new RequestError(ERR_CLOSED, "upstream closed");
        return record.owner;
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
        ok["instance"] = instance;
        ok["capabilities"] = capabilitiesJson();
        writeLine(c, okLine(ok));
        logJsonMap("info", "holder", "Control session opened",
            ["engine": hello.engine, "event": "hello"]);
        while (true) {
            string verb;
            Json req;
            string rawLine;
            try {
                rawLine = readRequestLine(c, MAX_META + 4096);
                parseFirstLine(rawLine, verb, req);
            } catch (RequestError e) {
                writeLine(c, errLine(e.code, e.msg));
                continue;
            } catch (Exception) {
                break; // engine closed the control session
            }
            string reply;
            try {
                if (verb != "META" && rawLine.length > MAX_LINE)
                    throw new RequestError(ERR_TOO_LARGE, "request exceeds 1 MiB");
                const metaBytes = verb == "META" ? rawMetaEncodedBytes(rawLine) : 0;
                reply = okLine(controlRequest(verb, req, metaBytes));
            } catch (RequestError e) {
                reply = errLine(e.code, e.msg);
            } catch (Exception e) {
                reply = errLine(ERR_BAD_REQUEST, e.msg);
            }
            writeLine(c, reply);
        }
        logJsonMap("info", "holder", "Control session closed", ["engine": hello.engine, "event": "hello_closed"]);
    }

    private Json controlRequest(string verb, Json req, size_t metaBytes = 0) {
        pruneTombstones(unixMsNow());
        switch (verb) {
            case "LIST": {
                auto arr = Json.emptyArray;
                for (auto record = first; record !is null; record = record.next)
                    if (record.visible) arr ~= record.entry().toJson();
                auto j = Json.emptyObject;
                j["connections"] = arr;
                return j;
            }
            case "INVENTORY":
                return inventory(req);
            case "STATUS":
                return statusJson();
            case "INFO":
                return lookupRecord(req).entry().toJson();
            case "META": {
                if (!metaBytes) throw new RequestError(ERR_BAD_REQUEST, "META wire size required");
                auto h = lookup(req);
                auto meta = req["meta"];
                if (meta.type == Json.Type.undefined) throw new RequestError(ERR_BAD_REQUEST, "meta required");
                if (!h.replaceMeta(meta, metaBytes))
                    throw new RequestError(ERR_TOO_LARGE, "META entry or aggregate byte budget exceeded");
                return Json.emptyObject;
            }
            case "GAP_ACK": {
                auto h = lookup(req);
                const generation = jsonUnsigned(req, "generation", true);
                if (!h.acknowledgeGap(generation))
                    throw new RequestError(ERR_BAD_REQUEST, "future gap generation");
                return h.entry(false).inventoryJson();
            }
            case "CLOSE": {
                auto record = lookupRecord(req, true);
                if (record is null) return Json.emptyObject;
                if (record.owner !is null && record.owner.isOpen) {
                    auto quit = req["quit"].type == Json.Type.string ? req["quit"].get!string : "";
                    if (quit.length > 512) throw new RequestError(ERR_BAD_REQUEST, "quit exceeds 512 bytes");
                    record.owner.close(quit);
                }
                return Json.emptyObject;
            }
            case "FORGET": {
                auto record = lookupRecord(req, true);
                if (record is null) return Json.emptyObject;
                if (record.owner !is null && record.owner.isOpen)
                    throw new RequestError(ERR_BUSY, "connection is open; use CLOSE");
                if (record.owner is null) removeRecord(record);
                else record.visible = false; // owner remains until explicit completion
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
        try {
            req = DialRequest.fromJson(payload);
            validateSourcePool(req, cfg.routedIpv6Prefix);
        }
        catch (Exception e) { writeLine(c, errLine(ERR_BAD_REQUEST, e.msg)); return; }
        if (!heldAdmissionAvailable() || nextId == long.max) {
            writeLine(c, "FAILED " ~ FailedLine("capacity", "holder admission capacity exhausted").toJson().toString());
            return;
        }

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
        if (nextId == long.max) {
            // Exhaustion is unreachable in practice, but never reuse an ID.
            if (outcome.tls !is null) outcome.tls.finalize();
            outcome.conn.close();
            writeLine(c, errLine(ERR_CLOSED, "holder ordinal exhausted"));
            return;
        }
        const ordinal = ++nextId;
        auto id = "c-" ~ instance ~ "-" ~ ordinal.to!string;
        Held held;
        try held = new Held(id, req, outcome, cfg.detachBufferBytes, cfg.detachMaxSecs, ordinal, instance);
        catch (HeldAdmissionException) {
            // Constructor admission failed before any owner was started.
            // No existing held connection is disturbed by capacity pressure.
            try { if (outcome.tls !is null) outcome.tls.finalize(); } catch (Exception) {}
            try outcome.conn.close(); catch (Exception) {}
            writeLine(c, "FAILED " ~ FailedLine("capacity", "holder admission capacity exhausted").toJson().toString());
            return;
        }
        catch (Exception e) {
            try { if (outcome.tls !is null) outcome.tls.finalize(); } catch (Exception) {}
            try outcome.conn.close(); catch (Exception) {}
            throw e;
        }
        registerHeld(held);
        fields["event"] = "dial_ok";
        fields["id"] = id;
        fields["peerIp"] = held.peerIp;
        fields["tookMs"] = (unixMsNow() - startMs).to!string;
        logJsonMap("info", "holder", "Dial succeeded", fields);
        auto connected = ConnectedLine(id, held.peerIp, held.localIp, held.peerPort, held.localPort,
            held.connectedAtMs, held.tlsInfo, instance);
        held.attach(c, "CONNECTED " ~ connected.toJson().toString());
    }

    // ── ATTACH → relay ──────────────────────────────────────────────────

    private void attach(ref TCPConnection c, Json payload) {
        if (auto code = tokenError(payload)) { writeLine(c, errLine(code, "bad token")); return; }
        Held held;
        try held = lookup(payload);
        catch (RequestError e) { writeLine(c, errLine(e.code, e.msg)); return; }
        if (!held.isOpen) { writeLine(c, errLine(ERR_CLOSED, "upstream closed: " ~ held.closeReason)); return; }
        if (held.attached) { writeLine(c, errLine(ERR_BUSY, "already attached")); return; }
        held.attach(c);
    }
}

version (unittest) {
    // Exercise the actual ordered registry/page/prune implementation without
    // opening a listener, dialing a server, or inventing transport stand-ins.
    private HolderServer.Record inventoryFixture(HolderServer server, long nowMs) {
        auto record = new HolderServer.Record;
        record.ordinal = ++server.nextId;
        record.id = "c-" ~ server.instance ~ "-" ~ record.ordinal.to!string;
        record.tombstone.id = record.id;
        record.tombstone.instance = server.instance;
        record.tombstone.ordinal = record.ordinal;
        record.tombstone.state = "closed";
        record.tombstone.closedAtMs = nowMs;
        record.tombstone.connectedAtMs = nowMs - 1;
        record.tombstone.gapGeneration = long.max;
        record.tombstone.gapAckGeneration = long.max - 1;
        record.tombstone.droppedBytes = ulong.max;
        record.tombstone.droppedLines = ulong.max;
        record.tombstone.gapStartedAtMs = long.max;
        record.tombstone.deliveryAmbiguous = true;
        server.appendRecord(record);
        server.retainClosedRecord(record, nowMs);
        return record;
    }
}

@("Inventory freezes its high-water and survives deletion of its cursor")
unittest {
    import std.exception : assertThrown;
    HolderConfig cfg;
    cfg.closedRetainSecs = CLOSED_RETAIN_SECS;
    auto server = new HolderServer(cfg);
    auto other = new HolderServer(cfg);
    assert(server.instance != other.instance);
    const now = unixMsNow();
    foreach (_; 0 .. 260) inventoryFixture(server, now);
    auto first = server.controlRequest("INVENTORY", Json.emptyObject);
    assert(first["through"].get!long == 260);
    assert(first["connections"].length == MAX_INVENTORY_ROWS && first["more"].get!bool);
    assert(okLine(first).length + 1 <= MAX_INVENTORY_BYTES);
    auto cursor = first["nextAfter"].get!long;
    assert(cursor == 128);
    auto oldCursor = server.ordinals[cast(ulong) cursor];
    server.removeRecord(oldCursor);
    inventoryFixture(server, now); // excluded until the next scan
    auto request = Json.emptyObject;
    request["instance"] = server.instance;
    request["through"] = first["through"];
    request["after"] = cursor;
    auto second = server.controlRequest("INVENTORY", request);
    assert(second["connections"].length == MAX_INVENTORY_ROWS);
    assert(second["connections"][0]["ordinal"].get!long == 129);
    assert(okLine(second).length + 1 <= MAX_INVENTORY_BYTES);
    request["after"] = second["nextAfter"];
    auto finalPage = server.controlRequest("INVENTORY", request);
    assert(!finalPage["more"].get!bool && finalPage["nextAfter"].get!long == 260);
    assert(finalPage["connections"].length == 4);
    foreach (row; finalPage["connections"].get!(Json[])) {
        assert(row["ordinal"].get!long <= 260);
        assert(row["meta"].type == Json.Type.undefined && row["tag"].type == Json.Type.undefined);
    }
    request["instance"] = other.instance;
    assertThrown(server.controlRequest("INVENTORY", request));
    request["instance"] = server.instance;
    request["after"] = 261;
    assertThrown(server.controlRequest("INVENTORY", request));
    request["after"] = 0;
    request["through"] = 262;
    assertThrown(server.controlRequest("INVENTORY", request));
    request["through"] = 260;
    request["after"] = 1.5;
    assertThrown(server.controlRequest("INVENTORY", request));
}

@("Terminal registry remains count bounded and expires independently of lookups")
unittest {
    HolderConfig cfg;
    cfg.closedRetainSecs = long.max; // cannot extend the hard one-hour ceiling
    auto server = new HolderServer(cfg);
    const now = unixMsNow();
    foreach (_; 0 .. MAX_TOMBSTONES + 10) {
        inventoryFixture(server, now);
        assert(server.tinyTombstones() <= MAX_TOMBSTONES);
    }
    assert(server.records.length == MAX_TOMBSTONES);
    assert(server.ordinals.length == MAX_TOMBSTONES);
    assert(server.first.ordinal == 11 && server.last.ordinal == MAX_TOMBSTONES + 10);
    auto missing = Json.emptyObject;
    missing["id"] = "already-forgotten";
    server.controlRequest("CLOSE", missing);
    server.controlRequest("FORGET", missing);
    server.pruneTombstones(now + CLOSED_RETAIN_SECS * 1000);
    assert(server.tinyTombstones() == 0 && server.records.length == 0 && server.ordinals.length == 0);
    assert(server.first is null && server.last is null && server.firstClosed is null && server.lastClosed is null);
}
