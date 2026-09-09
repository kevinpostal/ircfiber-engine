/**
 * One held upstream IRC connection: the relay state machine between the
 * IRC server socket (TCP or TLS) and the engine's IPC stream.
 *
 * Lifetimes: one upstream-reader fiber per `Held` for the connection
 * lifetime and one engine→upstream pump per attachment (run inline in the
 * IPC handler fiber that attached). Detached, inbound bytes accumulate in
 * `DetachBuffer`, which answers `PING` itself so the server never times
 * the session out while the engine is being swapped.
 */
module holder.held;

import core.time : Duration, msecs, seconds;
import std.conv : to;
import vibe.core.core : sleep, yield;
import vibe.core.net : TCPConnection, WaitForDataStatus;
import vibe.core.stream : IOMode;
import vibe.data.json : Json;
import vibe.stream.tls : TLSStream;
import ircfiber.async : safeFiberRun;
import ircfiber.logging : logJsonMap;
import holder.dial : DialOutcome, unixMsNow;
import holder.protocol;
import holder.tls_safe : safeTLSRead;

/// Read chunk for the upstream reader and the engine pump.
private enum STREAM_BUFFER_SIZE = 16_384;
/// Upstream idle wait between checks; only bounds how often the loop
/// re-evaluates its state — it never polls for data.
private enum UPSTREAM_WAIT = 30.seconds;

/// Returns the `PONG` line (without CRLF) answering `line` when it is a
/// server `PING`, else `null`. Builds the reply exactly as the engine does:
/// `PONG :` + the last parameter (empty when PING carried none).
string pingReply(string line) @safe pure nothrow {
    string verb, rest;
    ircVerb(line, verb, rest);
    if (verb != "PING") return null;
    return "PONG :" ~ ircLastParam(rest);
}

/// Inbound bytes buffered while no engine is attached. Complete lines are
/// scanned once; `PING`s are answered through `pong` and dropped, every
/// other byte (including a trailing partial line) is kept verbatim for
/// the next `ATTACH`.
struct DetachBuffer {
    private ubyte[] kept;
    private ubyte[] partial;

    /// Appends `chunk`; each completed line that is a `PING` is passed to
    /// `pong` (as the `PONG …` reply text, no CRLF) instead of being kept.
    void push(const(ubyte)[] chunk, scope void delegate(string) pong) {
        partial ~= chunk;
        size_t start = 0;
        foreach (i, b; partial) {
            if (b != '\n') continue;
            auto line = partial[start .. i + 1];
            start = i + 1;
            auto text = cast(string) line;
            while (text.length && (text[$ - 1] == '\n' || text[$ - 1] == '\r')) text = text[0 .. $ - 1];
            const reply = pingReply(text);
            if (reply !is null) pong(reply);
            else kept ~= line;
        }
        partial = partial[start .. $].dup;
    }

    /// Bytes currently held (complete lines + partial tail).
    @property size_t length() const @safe pure nothrow { return kept.length + partial.length; }

    /// Whether the buffer exceeds `limit` bytes.
    bool overflows(size_t limit) const @safe pure nothrow { return length > limit; }

    /// Removes and returns everything buffered, in arrival order.
    ubyte[] take() {
        auto data = kept ~ partial;
        kept = null;
        partial = null;
        return data;
    }
}

/// Upstream connection held on behalf of the engine.
final class Held {
    string id;
    Tag tag;
    string host;
    ushort port;
    TlsInfoJson tlsInfo;
    string peerIp;
    string localIp;
    ushort peerPort;
    ushort localPort;
    long connectedAtMs;
    /// "open" | "closed"
    string state = "open";
    bool attached;
    long detachedSinceMs;
    string closeReason;
    long closedAtMs;
    Json meta = Json(null);

    private TCPConnection conn;
    private TLSStream tls;
    private TCPConnection ipc;
    /// Bumped per attachment so a stale pump never detaches its successor.
    private ulong attachGen;
    private DetachBuffer detachBuf;
    private immutable size_t detachBufferBytes;
    private immutable long detachMaxMs;
    /// Set once a QUIT is in flight or the entry is closing; the reader
    /// keeps draining upstream (to see the server's EOF) but relays nothing.
    private bool closing;

    this(string id, ref DialRequest req, ref DialOutcome o, size_t detachBufferBytes, long detachMaxSecs) {
        this.id = id;
        this.tag = req.tag;
        this.host = req.host;
        this.port = req.port;
        this.tlsInfo = o.tlsInfo;
        this.peerIp = o.peerIp;
        this.localIp = o.localIp;
        this.peerPort = o.peerPort;
        this.localPort = o.localPort;
        this.connectedAtMs = unixMsNow();
        this.conn = o.conn;
        this.tls = o.tls;
        this.detachBufferBytes = detachBufferBytes;
        this.detachMaxMs = detachMaxSecs * 1000;
        // STARTTLS chatter received before 670 is the first thing the
        // engine must see; it rides the detach buffer like any other
        // bytes that arrived while nobody was attached.
        if (o.preTlsLines.length) detachBuf.push(o.preTlsLines, &sendPong);
        this.detachedSinceMs = connectedAtMs;
        safeFiberRun("holder_reader", tag.name, &readerLoop);
        safeFiberRun("holder_detach_timer", tag.name, &detachTimer);
    }

    /// Snapshot for `LIST` / `INFO` / `ATTACH`.
    Entry entry() {
        Entry e;
        e.id = id;
        e.tag = tag;
        e.state = state;
        e.attached = attached;
        e.host = host;
        e.port = port;
        e.tls = tlsInfo;
        e.peerIp = peerIp;
        e.localIp = localIp;
        e.connectedAtMs = connectedAtMs;
        e.detachedSinceMs = attached ? 0 : detachedSinceMs;
        e.bufferedBytes = detachBuf.length;
        e.closeReason = closeReason;
        e.closedAtMs = closedAtMs;
        e.meta = meta;
        return e;
    }

    @property bool isOpen() const @safe pure nothrow { return state == "open"; }

    private string[string] logFields(string event) {
        return ["id": id, "network": tag.name, "networkId": tag.networkId,
                "host": host, "event": event];
    }

    // ── Upstream I/O ────────────────────────────────────────────────────

    private void writeUpstream(const(ubyte)[] bytes) {
        if (tls !is null) { tls.write(bytes); tls.flush(); }
        else { conn.write(bytes); conn.flush(); }
    }

    private void sendPong(string reply) {
        try {
            writeUpstream(cast(const(ubyte)[]) (reply ~ "\r\n"));
            logJsonMap("debug", "holder", "Answered PING while detached", logFields("auto_pong"));
        } catch (Exception e) {
            markClosed("write_error: " ~ e.msg);
        }
    }

    /// Reads one chunk from upstream, blocking until data, EOF or error.
    /// Returns 0 when the wait timed out (loop again). Throws on EOF/error.
    private size_t readUpstream(ubyte[] buf) {
        if (tls !is null) {
            // NEVER touch the TLS stream unless bytes are already pending:
            // `leastSize`/`read` pull from vibe's BIO, whose `onBioRead`
            // calls `TCPConnection.leastSize`, which blocks for
            // `readTimeout` until the peer sends a byte. `noMoreData`
            // (peer FIN) deliberately falls through so SSL_read surfaces
            // the close as the usual "closed by peer" exception.
            // `markClosed` may run on another fiber while this one waits;
            // after `finalize()` the SSL object is gone, so never touch the
            // TLS stream once the entry is closed.
            if (!isOpen) throw new Exception("closed");
            if (!tls.dataAvailableForRead) {
                if (conn.waitForDataEx(UPSTREAM_WAIT) == WaitForDataStatus.timeout) return 0;
                if (!isOpen) throw new Exception("closed");
            }
            auto n = safeTLSRead(tls, buf);
            if (n == 0) {
                if (!conn.connected) throw new Exception("TLS connection closed by peer");
                // Incomplete TLS record on the wire: let the loop breathe.
                yield();
            }
            return n;
        }
        final switch (conn.waitForDataEx(UPSTREAM_WAIT)) {
            case WaitForDataStatus.timeout: return 0;
            case WaitForDataStatus.noMoreData: throw new Exception("closed by peer");
            case WaitForDataStatus.dataAvailable: break;
        }
        if (!isOpen) throw new Exception("closed");
        auto n = conn.read(buf, IOMode.once);
        if (n == 0) throw new Exception("closed by peer");
        return n;
    }

    /// Upstream-reader fiber: lives as long as the upstream socket.
    private void readerLoop() {
        ubyte[STREAM_BUFFER_SIZE] buf;
        while (isOpen) {
            size_t n;
            try {
                n = readUpstream(buf[]);
            } catch (Exception e) {
                if (closing) {
                    // QUIT grace or shutdown: the server answered with EOF.
                    markClosed(closeReason.length ? closeReason : CLOSE_PEER_CLOSED);
                    return;
                }
                const msg = e.msg;
                const peer = msg == "closed by peer" || msg == "TLS connection closed by peer"
                    || (tls !is null && msg.length >= 32 && msg[0 .. 32] == "TLS connection closed by peer (v");
                markClosed(peer ? CLOSE_PEER_CLOSED
                    : (tls !is null ? "tls_read_error: " ~ msg : "read_error: " ~ msg));
                return;
            }
            // While a QUIT is in flight nothing is relayed or buffered; the
            // loop only stays alive to observe the server's EOF.
            if (n == 0 || closing) continue;
            auto chunk = buf[0 .. n];
            if (attached) {
                try {
                    ipc.write(chunk);
                    ipc.flush();
                } catch (Exception e) {
                    // Engine went away mid-relay: keep the session, buffer.
                    detach("ipc_write_failed: " ~ e.msg);
                    detachBuf.push(chunk, &sendPong);
                }
            } else {
                detachBuf.push(chunk, &sendPong);
                if (detachBuf.overflows(detachBufferBytes)) {
                    logJsonMap("warn", "holder", "Detach buffer overflow — closing upstream",
                        logFields("detach_overflow"));
                    closeWithQuit(QUIT_ENGINE_UNAVAILABLE_OVERFLOW, CLOSE_DETACH_OVERFLOW);
                    return;
                }
            }
        }
    }

    /// Closes the session when the engine has been away longer than
    /// `IRCFIBER_HOLDER_DETACH_MAX_SECS`.
    private void detachTimer() {
        while (isOpen) {
            sleep(1.seconds);
            if (!isOpen || closing || attached) continue;
            if (detachedSinceMs > 0 && unixMsNow() - detachedSinceMs > detachMaxMs) {
                logJsonMap("warn", "holder", "Engine did not return — closing upstream",
                    logFields("detach_timeout"));
                closeWithQuit(QUIT_ENGINE_UNAVAILABLE, CLOSE_DETACH_TIMEOUT);
                return;
            }
        }
    }

    // ── Attach / detach ─────────────────────────────────────────────────

    /// Flushes the detach buffer to `stream`, then relays engine bytes
    /// upstream until the engine closes the stream or the upstream dies.
    /// Blocks the caller for the whole attachment. Throws with the
    /// protocol error code (`busy` / `closed`) as the message when refused.
    void attach(TCPConnection stream) {
        if (!isOpen || closing) throw new Exception(ERR_CLOSED);
        if (attached) throw new Exception(ERR_BUSY);
        ipc = stream;
        attached = true;
        detachedSinceMs = 0;
        const gen = ++attachGen;
        logJsonMap("info", "holder", "Engine attached", logFields("attach"));
        auto pending = detachBuf.take();
        try {
            if (pending.length) { ipc.write(pending); ipc.flush(); }
        } catch (Exception e) {
            if (attachGen == gen) detach("ipc_write_failed: " ~ e.msg);
            return;
        }
        pumpLoop(gen);
    }

    /// Engine→upstream pump for attachment `gen`.
    private void pumpLoop(ulong gen) {
        ubyte[STREAM_BUFFER_SIZE] buf;
        while (isOpen && attached && attachGen == gen) {
            size_t n;
            try {
                final switch (ipc.waitForDataEx(Duration.max)) {
                    case WaitForDataStatus.timeout: continue;
                    case WaitForDataStatus.noMoreData: throw new Exception("engine closed stream");
                    case WaitForDataStatus.dataAvailable: break;
                }
                n = ipc.read(buf[], IOMode.once);
                if (n == 0) throw new Exception("engine closed stream");
            } catch (Exception e) {
                if (attachGen == gen && attached) detach(e.msg);
                return;
            }
            if (!isOpen || closing) return;
            try {
                writeUpstream(buf[0 .. n]);
            } catch (Exception e) {
                markClosed("write_error: " ~ e.msg);
                return;
            }
        }
    }

    /// Drops the current attachment (engine gone); the session stays open
    /// and inbound bytes start buffering.
    private void detach(string why) {
        if (!attached) return;
        attached = false;
        detachedSinceMs = unixMsNow();
        auto fields = logFields("detach");
        fields["reason"] = why;
        logJsonMap("info", "holder", "Engine detached", fields);
        try { ipc.close(); } catch (Exception) {}
        ipc = TCPConnection.init;
    }

    // ── Close ───────────────────────────────────────────────────────────

    /// Marks the entry closed, tears down the sockets and the attachment.
    private void markClosed(string reason) {
        if (!isOpen) return;
        state = "closed";
        closeReason = reason;
        closedAtMs = unixMsNow();
        closing = true;
        auto fields = logFields(attached ? "upstream_closed" : "close");
        fields["reason"] = reason;
        logJsonMap("info", "holder", "Upstream connection closed", fields);
        if (attached) {
            attached = false;
            try { ipc.close(); } catch (Exception) {}
            ipc = TCPConnection.init;
        }
        try { if (tls !is null) tls.finalize(); } catch (Exception) {}
        try { conn.close(); } catch (Exception) {}
    }

    /// Writes `QUIT :<text>` upstream without waiting; the reader fiber
    /// closes the entry with `reason` when the server answers with EOF.
    /// Used by the holder's own shutdown (bounded by the caller's grace).
    void sendQuit(string quitText, string reason) {
        if (!isOpen || closing) return;
        closing = true;
        closeReason = reason;
        try {
            writeUpstream(cast(const(ubyte)[]) ("QUIT :" ~ quitText ~ "\r\n"));
        } catch (Exception) {
            markClosed(reason);
        }
    }

    /// Writes `QUIT :<text>` upstream, waits ≤ `QUIT_GRACE_PERIOD_MS` for the
    /// server to close, then closes with `reason`.
    void closeWithQuit(string quitText, string reason) {
        if (!isOpen) return;
        sendQuit(quitText, reason);
        const deadline = unixMsNow() + QUIT_GRACE_PERIOD_MS;
        while (isOpen && unixMsNow() < deadline) sleep(50.msecs);
        markClosed(reason);
    }

    /// `CLOSE` request: non-empty `quit` → `QUIT :<quit>` + grace; empty →
    /// close immediately (the engine already sent QUIT in-band).
    void close(string quit) {
        if (!isOpen) return;
        if (quit.length) closeWithQuit(quit, "closed_by_engine");
        else markClosed("closed_by_engine");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

@("pingReply answers PING exactly like the engine, ignores other lines")
unittest {
    assert(pingReply("PING :irc.example.org") == "PONG :irc.example.org");
    assert(pingReply(":irc.example.org PING :abc") == "PONG :abc");
    assert(pingReply("@time=2026 :irc.example.org PING x :abc def") == "PONG :abc def");
    assert(pingReply("PING") == "PONG :");
    assert(pingReply("PING abc") == "PONG :abc");
    assert(pingReply(":nick!u@h PRIVMSG #c :PING") is null);
    assert(pingReply("PONG :x") is null);
    assert(pingReply("") is null);
}

@("DetachBuffer answers PING, drops it, keeps everything else")
unittest {
    DetachBuffer b;
    string[] pongs;
    b.push(cast(const(ubyte)[]) ":s NOTICE * :hi\r\nPING :tok\r\n:s 001 n :welcome\r\n", (r) { pongs ~= r; });
    assert(pongs == ["PONG :tok"]);
    assert(cast(string) b.take() == ":s NOTICE * :hi\r\n:s 001 n :welcome\r\n");
    assert(b.length == 0);
}

@("DetachBuffer carries a partial line across chunks")
unittest {
    DetachBuffer b;
    string[] pongs;
    b.push(cast(const(ubyte)[]) ":s PRIVMSG #c :hel", (r) { pongs ~= r; });
    assert(b.length == 18 && pongs.length == 0);
    b.push(cast(const(ubyte)[]) "lo\r\nPI", (r) { pongs ~= r; });
    assert(pongs.length == 0);
    b.push(cast(const(ubyte)[]) "NG :a\r\n:s JOIN", (r) { pongs ~= r; });
    assert(pongs == ["PONG :a"]);
    assert(cast(string) b.take() == ":s PRIVMSG #c :hello\r\n:s JOIN");
    assert(b.length == 0);
}

@("DetachBuffer overflow flag counts kept + partial bytes")
unittest {
    DetachBuffer b;
    b.push(cast(const(ubyte)[]) "abc\r\n", (r) {});
    assert(!b.overflows(5));
    b.push(cast(const(ubyte)[]) "d", (r) {});
    assert(b.length == 6 && b.overflows(5));
    // PINGs never count toward the bound.
    DetachBuffer p;
    p.push(cast(const(ubyte)[]) "PING :x\r\nPING :y\r\n", (r) {});
    assert(p.length == 0 && !p.overflows(0));
}
