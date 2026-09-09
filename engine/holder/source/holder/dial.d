/**
 * Upstream dialing for the holder: DNS + Happy Eyeballs (direct), a single
 * SOCKS5 CONNECT (Mullvad sidecar), implicit TLS and STARTTLS.
 *
 * Moved from the engine's connection.d (`resolveAllAddresses`,
 * `interleaveAddressFamilies`, `happyEyeballsConnectWithProxy`,
 * `socks5ConnectViaProxy`, `finishHappyEyeballs`,
 * `createTLSStreamWithTimeout`, `captureTlsInfo`, `classifyStarttlsReply`
 * and the STARTTLS wait loop) with every pool/ban/observability/tracing
 * call stripped: the holder has no Mullvad pool and no OTel. One `DIAL` is
 * one attempt through exactly the egress the engine chose; policy stays
 * in the engine.
 */
module holder.dial;

import core.time : Duration, msecs, seconds;
import std.algorithm : canFind, countUntil;
import std.conv : to;
import std.datetime : Clock;
import std.socket : AddressFamily, getAddress;
import std.string : indexOf, lastIndexOf, split, strip, toLower, toStringz;
import vibe.core.channel : Channel, createChannel;
import vibe.core.core : runWorkerTask, sleep, yield;
import vibe.core.log : logDebug, logWarn;
import vibe.core.net : NetworkAddress, TCPConnection, WaitForDataStatus, connectTCP;
import vibe.core.stream : IOMode;
import vibe.core.task : Task;
import vibe.stream.tls : TLSContext, TLSContextKind, TLSPeerValidationMode, TLSStream,
    createTLSContext, createTLSStream;
import ircfiber.async : safeFiberRun;
import ircfiber.redis.protocol : TlsInfo;
import holder.protocol : DialRequest, EventLine, TlsInfoJson, ircVerb;

// ── Timeouts (moved verbatim from connection.d) ─────────────────────────────
// Bounded network steps only: vibe's connectTCP/createTLSStream have no
// timeout of their own.
enum CONNECT_TIMEOUT_SECONDS               = 10;
enum TLS_HANDSHAKE_TIMEOUT_SECONDS         = 10;
enum HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS   = 15;
enum HAPPY_EYEBALLS_DELAY_MS               = 250;
enum STARTTLS_REPLY_TIMEOUT_MS             = 15_000;
enum DNS_CACHE_TTL_MS                      = 30_000;
/// Read chunk while waiting for the STARTTLS reply.
private enum STARTTLS_READ_BUFFER          = 8192;

/// A `DIAL` that did not reach `CONNECTED`. `phase` is the wire `FAILED`
/// phase; `msg` is the exception text of the moved code verbatim (the
/// engine keys on `TLS handshake timed out`).
final class DialFailed : Exception {
    string phase;
    this(string phase, string reason, string file = __FILE__, size_t line = __LINE__) {
        super(reason, file, line);
        this.phase = phase;
    }
}

/// Sink for `EVENT` lines, invoked at the moment each phase happens.
alias EventSink = void delegate(EventLine);

/// Result of a successful dial: the upstream socket, the TLS stream when
/// negotiated, and the address/TLS details the engine reports.
struct DialOutcome {
    TCPConnection conn;
    TLSStream tls;
    TlsInfoJson tlsInfo;
    string peerIp;
    string localIp;
    ushort peerPort;
    ushort localPort;
    /// Server lines received before STARTTLS `670`, delivered as the first
    /// relay bytes after `CONNECTED`.
    ubyte[] preTlsLines;
}

/// Current wall-clock time in unix milliseconds.
long unixMsNow() @safe {
    import std.datetime.systime : unixTimeToStdTime;
    return (Clock.currStdTime - unixTimeToStdTime(0)) / 10_000;
}

// ── Host normalisation ──────────────────────────────────────────────────────

string stripHostBrackets(string host) @safe pure {
    host = host.strip();
    // Handle full ircs:// / irc:// URLs pasted into host field
    auto schemeSep = host.indexOf("://");
    if (schemeSep >= 0) {
        host = host[schemeSep + 3 .. $];
        auto slash = host.indexOf("/");
        if (slash >= 0) host = host[0 .. slash];
        auto bracketClose = host.indexOf("]");
        if (bracketClose >= 0) {
            auto open = host.indexOf("[");
            if (open >= 0) host = host[open .. bracketClose + 1];
            else host = host[0 .. bracketClose + 1];
        } else {
            auto colon = host.lastIndexOf(":");
            if (colon >= 0) {
                auto after = host[colon + 1 .. $];
                bool allDigits = after.length > 0;
                foreach (c; after) if (c < '0' || c > '9') { allDigits = false; break; }
                bool looksLikeIPv6 = host.canFind("::") || host.countUntil(":") != host.lastIndexOf(":");
                if (allDigits && !looksLikeIPv6) host = host[0 .. colon];
            }
        }
        host = host.strip();
    }
    // Standalone bracketed IPv6 literal, with or without trailing :port (no scheme)
    // e.g. "[2001:db8::1]" or "[2001:db8::1]:6697"
    if (host.length >= 2 && host[0] == '[') {
        auto close = host.indexOf("]");
        if (close > 0) return host[1 .. close];
    }
    return host;
}

// ── DNS (worker thread + 30 s cache) ────────────────────────────────────────

struct ResolvedAddr {
    string ip;
    AddressFamily family;
}

private __gshared ResolvedAddr[][string] dnsCache;
private __gshared long[string]           dnsCacheTime;
private __gshared Object gDnsLock;
shared static this() {
    try { gDnsLock = new Object(); } catch (Throwable) {}
}

ResolvedAddr[] resolveAllAddresses(string host, ushort port) {
    const now = Clock.currTime.toUnixTime!long * 1000;
    auto normalizedHost = stripHostBrackets(host);
    auto cacheKey = normalizedHost;
    // Check cache under lock (enterprise: avoid SyncError on __gshared AA).
    if (gDnsLock !is null) synchronized (gDnsLock) {
        if (auto t = cacheKey in dnsCacheTime) {
            if (now - *t < DNS_CACHE_TTL_MS) {
                if (auto cached = cacheKey in dnsCache) return (*cached).dup;
            }
        }
    } else {
        if (auto t = cacheKey in dnsCacheTime) {
            if (now - *t < DNS_CACHE_TTL_MS) {
                if (auto cached = cacheKey in dnsCache) return *cached;
            }
        }
    }
    auto ch = createChannel!string();
    runWorkerTask((string h, ushort p, Channel!string c) nothrow {
        try {
            auto addrs = getAddress(h, p);
            string encoded;
            // getaddrinfo without a socktype hint returns one entry per
            // (address, socktype) — the same IP three times (STREAM, DGRAM,
            // RAW). Dedupe so Happy Eyeballs does not race three identical
            // connects and then wait three race timeouts for the same host.
            bool[string] seen;
            foreach (addr; addrs) {
                auto key = addr.toAddrString();
                if (key in seen) continue;
                seen[key] = true;
                if (encoded.length > 0) encoded ~= "|";
                encoded ~= key
                    ~ (addr.addressFamily == AddressFamily.INET6 ? "/6" : "/4");
            }
            try { c.put(encoded); } catch (Exception) {}
        } catch (Exception) {
            try { c.put(""); } catch (Exception) {}
        }
    }, normalizedHost, port, ch);
    string encoded;
    if (ch.tryConsumeOne(encoded, 5.seconds) && encoded.length > 0) {
        ResolvedAddr[] result;
        foreach (entry; encoded.split("|")) {
            auto sep = entry.lastIndexOf("/");
            if (sep > 0) {
                auto ip  = entry[0 .. sep];
                auto fam = entry[sep + 1 .. $] == "6"
                    ? AddressFamily.INET6 : AddressFamily.INET;
                result ~= ResolvedAddr(ip, fam);
            }
        }
        if (result.length > 0) {
            if (gDnsLock !is null) synchronized (gDnsLock) {
                dnsCache[cacheKey]     = result;
                dnsCacheTime[cacheKey] = now;
            } else {
                dnsCache[cacheKey]     = result;
                dnsCacheTime[cacheKey] = now;
            }
            return result;
        }
    }
    auto fam = AddressFamily.INET;
    if (normalizedHost.canFind(":")) {
        auto colonCount = 0;
        foreach (c; normalizedHost) if (c == ':') colonCount++;
        if (colonCount >= 2 || normalizedHost.canFind("::")) fam = AddressFamily.INET6;
        else {
            bool isIPv6 = true;
            foreach (c; normalizedHost) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':')) { isIPv6 = false; break; }
            if (isIPv6 && colonCount >= 1) fam = AddressFamily.INET6;
        }
    }
    return [ResolvedAddr(normalizedHost, fam)];
}

ResolvedAddr[] interleaveAddressFamilies(ResolvedAddr[] addrs) {
    ResolvedAddr[] v6, v4;
    foreach (a; addrs) {
        if (a.family == AddressFamily.INET6) v6 ~= a;
        else v4 ~= a;
    }
    ResolvedAddr[] out_;
    size_t i6, i4;
    while (i6 < v6.length || i4 < v4.length) {
        if (i6 < v6.length) out_ ~= v6[i6++];
        if (i4 < v4.length) out_ ~= v4[i4++];
    }
    return out_;
}

/// Shortens a vibe/eventcore connect error to something a user can act on.
string shortConnectError(string msg) @safe {
    const l = msg.toLower();
    if (l.canFind("timed out") || l.canFind("timeout")) return "timed out after " ~ CONNECT_TIMEOUT_SECONDS.to!string ~ "s";
    if (l.canFind("refused")) return "connection refused";
    if (l.canFind("unreachable")) return "network unreachable";
    if (l.canFind("reset")) return "connection reset";
    if (l.canFind("socks")) return "SOCKS egress error: " ~ msg;
    return msg.length > 90 ? msg[0 .. 90] ~ "…" : msg;
}

private void report(EventSink emit, string phase, string text) {
    if (emit !is null) emit(EventLine(phase, text));
}

// ── SOCKS5 ──────────────────────────────────────────────────────────────────

// SOCKS5 → TLS handoff: connectTCP to sidecar, handshake on same TCPConnection,
// then return it for createTLSStreamWithTimeout (avoids private TCPConnection(fd) ctor).
//
// `target` is the IRC hostname (SOCKS5 ATYP=domain) or an IP literal (ATYP
// 1/4). Names are resolved BY THE EXIT: the holder's own resolver can be
// split-horizon (on prod `irc.ircfiber.com` is a Docker alias → fd00:f1b3:1::7,
// unreachable from a remote sidecar) and the exit's answer is the one that
// matches the address the IRC network will see anyway.
TCPConnection socks5ConnectViaProxy(string proxyHost, ushort proxyPort, string target, ushort targetPort,
                                    Duration connectTimeout) {
    import core.sys.posix.arpa.inet : inet_pton;
    import core.sys.posix.sys.socket : AF_INET, AF_INET6;
    auto proxyConn = connectTCP(proxyHost, proxyPort, null, 0, connectTimeout);
    scope(failure) try { proxyConn.close(); } catch (Exception) {}
    // The exit dials the IRC server before answering CONNECT; bound that wait
    // like every other connect step (an unbounded read here wedged fibers on
    // a hung sidecar). Reset afterwards — the socket carries TLS + IRC next.
    proxyConn.readTimeout = HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS.seconds;
    ubyte[3] greet = [0x05, 0x01, 0x00];
    proxyConn.write(greet[]);
    ubyte[2] greetResp;
    proxyConn.read(greetResp[]);
    if (greetResp[0] != 0x05 || greetResp[1] != 0x00) throw new Exception("SOCKS5 proxy auth failed");
    ubyte[] req;
    req ~= cast(ubyte)0x05; req ~= cast(ubyte)0x01; req ~= cast(ubyte)0x00;
    ubyte[4] ip4;
    ubyte[16] ip6;
    if (inet_pton(AF_INET, target.toStringz, ip4.ptr) == 1) {
        req ~= cast(ubyte)0x01; req ~= ip4[];
    } else if (inet_pton(AF_INET6, target.toStringz, ip6.ptr) == 1) {
        req ~= cast(ubyte)0x04; req ~= ip6[];
    } else {
        if (target.length == 0 || target.length > 255) throw new Exception("SOCKS5 bad target name " ~ target);
        req ~= cast(ubyte)0x03; req ~= cast(ubyte) target.length; req ~= cast(const(ubyte)[]) target;
    }
    req ~= cast(ubyte)(targetPort >> 8); req ~= cast(ubyte)(targetPort & 0xFF);
    proxyConn.write(req);
    ubyte[4] hdr;
    proxyConn.read(hdr[]);
    if (hdr[0] != 0x05 || hdr[1] != 0x00) throw new Exception("SOCKS5 CONNECT failed rep=" ~ hdr[1].to!string);
    ubyte atyp = hdr[3];
    size_t remain = 0;
    if (atyp == 0x01) remain = 4 + 2;
    else if (atyp == 0x04) remain = 16 + 2;
    else if (atyp == 0x03) { ubyte l; proxyConn.read((&l)[0 .. 1]); remain = l + 2; }
    else throw new Exception("SOCKS5 bad ATYP");
    if (remain > 0) { ubyte[] tmp = new ubyte[remain]; proxyConn.read(tmp); }
    proxyConn.readTimeout = Duration.max;
    return proxyConn;
}

// ── Happy Eyeballs (direct) ─────────────────────────────────────────────────

/**
 * Interrupts any still-running connection tasks and closes any sockets that
 * lost the race. This prevents resource leaks and ensures a silent/black-holed
 * peer does not leave fibers stuck indefinitely.
 */
private void finishHappyEyeballs(TCPConnection[] conns, Task[] tasks, int winnerIdx) {
    foreach (i, c; conns) {
        if (cast(int)i != winnerIdx && c && c.connected) {
            try { c.close(); } catch (Exception) {}
        }
    }
    foreach (i, t; tasks) {
        if (cast(int)i != winnerIdx && t != Task.init) {
            try { t.interrupt(); } catch (Exception) {}
        }
    }
}

/// Direct dial: DNS + Happy Eyeballs race across every resolved address
/// (250 ms stagger, `ipv6BindAddr` as the IPv6 local bind). Throws
/// `DialFailed("dns"|"tcp", …)`.
private TCPConnection happyEyeballsDirect(string host, ushort port, string ipv6BindAddr,
                                          Duration connectTimeout, EventSink emit) {
    const egressLabel = ipv6BindAddr.length > 0 ? "ipv6:" ~ ipv6BindAddr : "direct";
    auto addrs = resolveAllAddresses(host, port);
    if (addrs.length == 0) {
        report(emit, "attempt_fail", "DNS lookup for " ~ host ~ " returned no addresses.");
        throw new DialFailed("dns", "DNS resolution failed for " ~ host);
    }

    auto interleaved = interleaveAddressFamilies(addrs);
    {
        string list;
        foreach (i, a; interleaved) {
            if (i >= 4) { list ~= ", …"; break; }
            if (i) list ~= ", ";
            list ~= a.ip;
        }
        report(emit, "dns", "Resolved " ~ host ~ " → " ~ interleaved.length.to!string
            ~ (interleaved.length == 1 ? " address" : " addresses") ~ " (" ~ list ~ "), connecting via " ~ egressLabel ~ ".");
    }
    const connectTimeoutSecs = connectTimeout.total!"seconds";
    logDebug("Happy Eyeballs: racing %d addresses for %s (connect timeout %ds, race timeout %ds)",
        interleaved.length, host, connectTimeoutSecs, HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS);
    immutable raceStartMs = Clock.currTime.toUnixTime!long * 1000;

    auto winnerCh = createChannel!int();
    auto conns = new TCPConnection[interleaved.length];
    auto tasks = new Task[interleaved.length];
    bool done = false;
    size_t failed = 0;

    foreach (idx, addr; interleaved) {
        // Before launching the next attempt, see if an earlier one already won.
        if (idx > 0) {
            int winIdx;
            if (winnerCh.tryConsumeOne(winIdx, HAPPY_EYEBALLS_DELAY_MS.msecs)) {
                if (winIdx < 0) {
                    failed++;
                } else if (conns[winIdx] && conns[winIdx].connected) {
                    done = true;
                    finishHappyEyeballs(conns, tasks, winIdx);
                    logDebug("Happy Eyeballs: winner %s for %s", interleaved[winIdx].ip, host);
                    return conns[winIdx];
                }
            }
        }

        auto connIdx = idx;
        auto addrIp  = addr.ip;
        auto addrFam = addr.family;
        // With per-user IPv6, bind the source to the user's deterministic
        // /128 — IPv6→IPv6 only, to avoid EINVAL when racing an IPv4 A record.
        auto bindForThisAddr = (ipv6BindAddr.length > 0 && addrFam == AddressFamily.INET6) ? ipv6BindAddr : null;
        report(emit, "attempt", "Trying " ~ addrIp ~ ":" ~ port.to!string ~ " via " ~ egressLabel
            ~ (bindForThisAddr ? " bind=" ~ bindForThisAddr : "")
            ~ " (up to " ~ connectTimeoutSecs.to!string ~ "s)…");
        tasks[connIdx] = safeFiberRun("happy_eyeballs_attempt", host, {
            immutable attemptStartMs = Clock.currTime.toUnixTime!long * 1000;
            try {
                // vibe.d connectTCP third param is string localAddr (bind IP)
                TCPConnection conn = bindForThisAddr.length > 0
                    ? connectTCP(addrIp, port, bindForThisAddr, 0, connectTimeout)
                    : connectTCP(addrIp, port, null, 0, connectTimeout);
                if (done) {
                    try { conn.close(); } catch (Exception) {}
                    return;
                }
                conns[connIdx] = conn;
                try { winnerCh.put(cast(int) connIdx); } catch (Exception) {
                    try { conn.close(); } catch (Exception) {}
                }
            } catch (Exception e) {
                logDebug("Happy Eyeballs: %s failed: %s", addrIp, e.msg);
                if (!done) {
                    const tookMs = Clock.currTime.toUnixTime!long * 1000 - attemptStartMs;
                    report(emit, "attempt_fail", addrIp ~ " via " ~ egressLabel ~ ": "
                        ~ shortConnectError(e.msg) ~ " (" ~ (tookMs / 1000).to!string ~ "s).");
                    // -1 = "one attempt failed": lets the race loop below give
                    // up as soon as every address has failed instead of
                    // sleeping out HAPPY_EYEBALLS_RACE_TIMEOUT per address
                    // (45 s of silence for a 3-address host that refuses
                    // within 10 s).
                    try { winnerCh.put(-1); } catch (Exception) {}
                }
            }
        });
    }

    // Wait for a winner. Each attempt reports either its index (success) or
    // -1 (failure); the race ends on the first success, once every attempt
    // has failed, or when the per-address race timeout expires.
    while (failed < interleaved.length) {
        int winIdx;
        if (!winnerCh.tryConsumeOne(winIdx, HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS.seconds)) break;
        if (winIdx < 0) { failed++; continue; }
        if (conns[winIdx] && conns[winIdx].connected) {
            done = true;
            finishHappyEyeballs(conns, tasks, winIdx);
            logDebug("Happy Eyeballs: winner %s for %s", interleaved[winIdx].ip, host);
            return conns[winIdx];
        }
    }

    done = true;
    finishHappyEyeballs(conns, tasks, -1);
    const tookMs = Clock.currTime.toUnixTime!long * 1000 - raceStartMs;
    report(emit, "attempt_fail", "No address for " ~ host ~ " answered via " ~ egressLabel
        ~ " (" ~ (tookMs / 1000).to!string ~ "s).");
    throw new DialFailed("tcp", "All connection attempts failed for " ~ host ~ ":" ~ port.to!string);
}

// ── TLS ─────────────────────────────────────────────────────────────────────

/**
 * Create a TLS stream with a bounded handshake timeout.
 *
 * vibe.d's createTLSStream performs the SSL handshake inside the constructor
 * and has no timeout parameter. If the server accepts TCP but never completes
 * the TLS handshake, the fiber blocks forever: OpenSSL's SSL_connect blocks
 * on a raw read() that does NOT yield to vibe's scheduler, so a plain
 * task.interrupt() never fires (observed 2026-08-18 20:55:17: tcp_open
 * succeeded via socks-mullvad-se/172.22.0.3 but no tls_handshake for 5h).
 *
 *  - Capture the underlying fd and call POSIX shutdown(SHUT_RDWR) on timeout
 *    to force SSL_connect's blocked read() to return. close() alone is not
 *    sufficient when the BIO holds a dup of the fd.
 *  - Use shared atomic flag + channel so the timeout fires even if the
 *    channel's internal mutex is wedged (SyncError).
 *  - Catch Throwable (not just Exception) so SyncError propagates as a
 *    clean timeout exception instead of killing the TaskFiber.
 */
TLSStream createTLSStreamWithTimeout(TCPConnection connection, TLSContext ctx, string host, Duration timeout) {
    import core.atomic : atomicLoad, atomicStore;
    import core.sys.posix.sys.socket : shutdown, SHUT_RDWR;
    shared bool handshakeDone = false;
    auto doneCh = createChannel!bool();
    TLSStream resultStream;
    Throwable resultThrowable;

    // TCPConnection has scoped destruction and cannot be captured directly in
    // a closure. Store it on the heap so the handshake task can safely use it
    // while this function waits on the completion channel.
    static final class ConnHolder {
        TCPConnection conn;
        this(TCPConnection c) { this.conn = c; }
    }
    auto holder = new ConnHolder(connection);
    // Capture fd early — after close() the fd becomes -1.
    int rawFd = -1;
    try { rawFd = cast(int) connection.fd; } catch (Exception) {}

    auto task = safeFiberRun("tls_handshake", host, {
        try {
            resultStream = createTLSStream(holder.conn, ctx, host);
            atomicStore(handshakeDone, true);
            try { doneCh.put(true); } catch (Throwable) {}
        } catch (Throwable e) {
            resultThrowable = e;
            atomicStore(handshakeDone, true);
            try { doneCh.put(false); } catch (Throwable) {}
        }
    });

    bool ok;
    bool consumed = false;
    try {
        consumed = doneCh.tryConsumeOne(ok, timeout);
    } catch (Throwable e) {
        // Channel SyncError (observed 2026-08-17 cnTb-fin) — treat as timeout.
        logWarn("TLS handshake channel SyncError for %s: %s — forcing timeout path", host, e.msg);
        consumed = false;
    }
    if (!consumed) {
        // Timeout: force-unblock the handshake task.
        logWarn("TLS handshake timed out for %s after %s (fd=%d) — shutting down socket to unblock OpenSSL", host, timeout.to!string, rawFd);
        // 1) shutdown() forces SSL_connect's blocked read to return (close alone may not).
        if (rawFd >= 0) {
            try { shutdown(rawFd, SHUT_RDWR); } catch (Throwable) {}
        }
        // 2) vibe-level close to release the TCPConnection object.
        try { holder.conn.close(); } catch (Throwable) {}
        // 3) interrupt the fiber (best-effort — may already be blocked in C).
        try { task.interrupt(); } catch (Throwable) {}
        // Give the handshake task a brief grace to observe the shutdown and exit.
        try { sleep(200.msecs); } catch (Throwable) {}
        // If it still hasn't completed, the task will be reaped on next GC; we throw now
        // so the engine retries via the next egress instead of wedging forever.
        if (!atomicLoad(handshakeDone)) {
            logWarn("TLS handshake task for %s still not done after shutdown — abandoning (fiber will be GC'd)", host);
        }
        throw new Exception("TLS handshake timed out after " ~ timeout.to!string ~ " for " ~ host);
    }

    if (!ok) {
        if (resultThrowable !is null) {
            // Preserve original error chain for operator triage.
            if (auto e = cast(Exception) resultThrowable) throw e;
            throw new Exception("TLS handshake failed for " ~ host ~ ": " ~ resultThrowable.msg);
        }
        throw new Exception("TLS handshake failed for " ~ host);
    }

    return resultStream;
}

/// Compile-time index of the field named `name` in `T.tupleof`, or -1.
/// Used to reach vibe-stream's private `OpenSSLStream.m_tls` with the
/// index verified by name rather than hard-coded.
private template fieldIndexOf(T, string name) {
    enum fieldIndexOf = () {
        ptrdiff_t idx = -1;
        static foreach (i, _; typeof(T.tupleof))
            static if (__traits(identifier, T.tupleof[i]) == name) idx = i;
        return idx;
    }();
}

/// Parses an ASN.1 GeneralizedTime (`YYYYMMDDHHMMSS[.fff]Z`, as
/// produced by `ASN1_TIME_to_generalizedtime`) into unix ms. Returns 0
/// when the string is malformed.
long parseAsn1GeneralizedTimeMs(string s) @safe nothrow {
    import std.datetime.date : DateTime;
    import std.datetime.systime : SysTime;
    import std.datetime.timezone : UTC;
    if (s.length < 15 || s[$ - 1] != 'Z') return 0;
    foreach (c; s[0 .. 14]) if (c < '0' || c > '9') return 0;
    try {
        auto dt = DateTime(s[0 .. 4].to!int, s[4 .. 6].to!int, s[6 .. 8].to!int,
            s[8 .. 10].to!int, s[10 .. 12].to!int, s[12 .. 14].to!int);
        return SysTime(dt, UTC()).toUnixTime!long * 1000;
    } catch (Exception) return 0;
}

/// Reads protocol version, cipher and peer-certificate details from the
/// freshly handshaken `tlsStream`. Any failure (non-OpenSSL backend,
/// missing peer cert, OpenSSL error) leaves `ok == false`.
TlsInfoJson captureTlsInfo(TLSStream tlsStream, string name) nothrow {
    TlsInfoJson result;
    try {
        import vibe.stream.openssl : OpenSSLStream;
        import deimos.openssl.ssl : SSL_get_version, SSL_get_cipher_name;
        import deimos.openssl.x509 : X509_NAME, X509_get_subject_name, X509_get_issuer_name,
            X509_NAME_get_text_by_NID, X509_get0_notAfter;
        import deimos.openssl.asn1 : ASN1_TIME, ASN1_STRING, ASN1_TIME_to_generalizedtime, ASN1_STRING_free;
        import deimos.openssl.obj_mac : NID_commonName;
        import std.string : fromStringz;

        auto ossl = cast(OpenSSLStream) tlsStream;
        if (ossl is null) return result;
        // `m_tls` (the SSL*) is private in vibe-stream; reach it via
        // tupleof with the index pinned by name so a field reorder
        // upstream fails at compile time instead of reading garbage.
        enum tlsIdx = fieldIndexOf!(OpenSSLStream, "m_tls");
        static assert(tlsIdx >= 0 && __traits(identifier, OpenSSLStream.tupleof[tlsIdx]) == "m_tls");
        auto ssl = ossl.tupleof[tlsIdx];
        if (ssl is null) return result;
        auto x509 = ossl.peerCertificateX509;
        if (x509 is null) return result;

        static string nameCn(X509_NAME* name) {
            if (name is null) return "";
            char[256] buf;
            const n = X509_NAME_get_text_by_NID(name, NID_commonName, buf.ptr, buf.length);
            return n > 0 ? buf[0 .. n].idup : "";
        }
        TlsInfo info;
        info.version_ = SSL_get_version(ssl).fromStringz.idup;
        info.cipher = SSL_get_cipher_name(ssl).fromStringz.idup;
        info.certCn = nameCn(X509_get_subject_name(x509));
        info.certIssuer = nameCn(X509_get_issuer_name(x509));
        auto notAfter = X509_get0_notAfter(x509);
        if (notAfter !is null) {
            auto gen = ASN1_TIME_to_generalizedtime(cast(ASN1_TIME*) notAfter, null);
            if (gen !is null) {
                scope (exit) ASN1_STRING_free(cast(ASN1_STRING*) gen);
                auto str = cast(ASN1_STRING*) gen;
                if (str.data !is null && str.length > 0)
                    info.certNotAfterMs = parseAsn1GeneralizedTimeMs(
                        (cast(const(char)*) str.data)[0 .. str.length].idup);
            }
        }
        result.info = info;
        result.ok = true;
    } catch (Exception e) {
        try logWarn("TLS detail capture failed for %s: %s", name, e.msg);
        catch (Exception) {}
    }
    return result;
}

// ── STARTTLS ────────────────────────────────────────────────────────────────
// Plain-text connect with tls:"starttls": the holder sends STARTTLS and
// waits for 670 RPL_STARTTLS (begin the handshake) or 691 ERR_STARTTLS
// (abort, fail closed). Anything else keeps waiting.

/// Classify one server line during the STARTTLS handshake. Pure.
enum StarttlsResult { waiting, success, failed }

StarttlsResult classifyStarttlsReply(string command) @safe pure nothrow @nogc {
    if (command == "670") return StarttlsResult.success;
    if (command == "691") return StarttlsResult.failed;
    return StarttlsResult.waiting;
}

@("classifyStarttlsReply maps 670/691")
unittest {
    assert(classifyStarttlsReply("670") == StarttlsResult.success);
    assert(classifyStarttlsReply("691") == StarttlsResult.failed);
    assert(classifyStarttlsReply("NOTICE") == StarttlsResult.waiting);
    assert(classifyStarttlsReply("001") == StarttlsResult.waiting);
}

/// Sends `STARTTLS` and waits ≤ `timeout` for `670`, queueing every other
/// server line into `preTlsLines`. Throws `DialFailed("starttls", …)` on
/// `691`/`421` or timeout.
private void awaitStarttlsGoAhead(ref TCPConnection conn, Duration timeout, ref ubyte[] preTlsLines) {
    conn.write(cast(const(ubyte)[]) "STARTTLS\r\n");
    conn.flush();
    ubyte[STARTTLS_READ_BUFFER] buf;
    ubyte[] partial;
    immutable startMs = Clock.currTime.toUnixTime!long * 1000;
    immutable timeoutMs = timeout.total!"msecs";
    while (true) {
        const elapsed = Clock.currTime.toUnixTime!long * 1000 - startMs;
        if (elapsed >= timeoutMs) break;
        const st = conn.waitForDataEx((timeoutMs - elapsed).msecs);
        if (st == WaitForDataStatus.timeout) continue;
        if (st == WaitForDataStatus.noMoreData)
            throw new DialFailed("starttls", "Connection closed while waiting for STARTTLS reply");
        auto received = conn.read(buf[], IOMode.once);
        if (received == 0) { yield(); continue; }
        partial ~= buf[0 .. received];
        ptrdiff_t idx;
        while ((idx = (cast(string) partial).indexOf("\n")) >= 0) {
            auto line = partial[0 .. idx + 1];
            partial   = partial[idx + 1 .. $];
            auto text = cast(string) line;
            while (text.length && (text[$ - 1] == '\n' || text[$ - 1] == '\r')) text = text[0 .. $ - 1];
            if (text.length == 0) continue;
            string verb, rest;
            ircVerb(text, verb, rest);
            auto res = classifyStarttlsReply(verb);
            if (res == StarttlsResult.failed || verb == "421")
                throw new DialFailed("starttls", "STARTTLS rejected (691 ERR_STARTTLS)");
            if (res == StarttlsResult.success) return;
            // Still waiting — NOTICE AUTH etc. belongs to the engine.
            preTlsLines ~= line.dup;
        }
    }
    throw new DialFailed("starttls", "STARTTLS timeout: no 670 RPL_STARTTLS received");
}

// ── Entry point ─────────────────────────────────────────────────────────────

private void recordAddrs(ref DialOutcome o, ref TCPConnection conn) {
    try {
        auto ra = conn.remoteAddress;
        auto la = conn.localAddress;
        o.peerIp = ra.toAddressString();
        o.localIp = la.toAddressString();
        o.peerPort = ra.port;
        o.localPort = la.port;
    } catch (Exception) {}
}

private TLSContext clientTlsContext() {
    auto ctx = createTLSContext(TLSContextKind.client);
    // TODO: peer validation — the engine has always connected with
    // peerValidationMode = none (self-signed ircds, no CA pinning UI).
    ctx.peerValidationMode = TLSPeerValidationMode.none;
    return ctx;
}

/// Performs one dial exactly as requested. Emits `EVENT`s through `emit`
/// as each phase happens; throws `DialFailed` (phase + verbatim reason)
/// on any failure, after closing whatever it opened.
DialOutcome dialUpstream(ref DialRequest req, EventSink emit) {
    DialOutcome o;
    const target = stripHostBrackets(req.host);
    const connectTimeout = req.connectTimeoutMs.msecs;

    if (req.hasProxy) {
        // One CONNECT with the hostname: the exit resolves it (see
        // socks5ConnectViaProxy). The engine already emitted the `attempt`
        // line for proxied dials; on failure it composes `attempt_fail`.
        try {
            o.conn = socks5ConnectViaProxy(req.proxy.host, req.proxy.port, target, req.port, connectTimeout);
        } catch (Exception e) {
            const l = e.msg.toLower();
            throw new DialFailed(l.canFind("socks") ? "socks5" : "tcp", e.msg);
        }
    } else {
        o.conn = happyEyeballsDirect(req.host, req.port, req.bindIp6, connectTimeout, emit);
    }
    scope (failure) {
        try { if (o.tls !is null) o.tls.finalize(); } catch (Exception) {}
        try { o.conn.close(); } catch (Exception) {}
    }
    recordAddrs(o, o.conn);
    if (emit !is null) emit(EventLine("tcp_open", "", o.peerIp, o.localIp, o.peerPort, o.localPort));

    if (req.tls == "starttls") {
        report(emit, "starttls", "");
        awaitStarttlsGoAhead(o.conn, req.starttlsTimeoutMs.msecs, o.preTlsLines);
    }
    if (req.tls == "implicit" || req.tls == "starttls") {
        if (req.tls == "implicit") report(emit, "tls", "");
        try {
            o.tls = createTLSStreamWithTimeout(o.conn, clientTlsContext(), stripHostBrackets(req.sni),
                req.tlsTimeoutMs.msecs);
        } catch (Exception e) {
            throw new DialFailed("tls", e.msg);
        }
        o.tlsInfo = captureTlsInfo(o.tls, req.tag.name);
    }
    return o;
}

@("stripHostBrackets handles URLs and bracketed literals")
unittest {
    assert(stripHostBrackets("irc.example.org") == "irc.example.org");
    assert(stripHostBrackets("ircs://irc.example.org:6697/") == "irc.example.org");
    assert(stripHostBrackets("[2001:db8::1]:6697") == "2001:db8::1");
    assert(stripHostBrackets("[2001:db8::1]") == "2001:db8::1");
}

@("interleaveAddressFamilies alternates v6/v4")
unittest {
    auto r = interleaveAddressFamilies([
        ResolvedAddr("1.1.1.1", AddressFamily.INET), ResolvedAddr("2.2.2.2", AddressFamily.INET),
        ResolvedAddr("::1", AddressFamily.INET6)]);
    assert(r.length == 3 && r[0].ip == "::1" && r[1].ip == "1.1.1.1" && r[2].ip == "2.2.2.2");
}

@("parseAsn1GeneralizedTimeMs parses OpenSSL generalized time")
unittest {
    assert(parseAsn1GeneralizedTimeMs("20240101000000Z") == 1_704_067_200_000);
    assert(parseAsn1GeneralizedTimeMs("20240101000000.500Z") == 1_704_067_200_000);
    assert(parseAsn1GeneralizedTimeMs("240101000000Z") == 0);
    assert(parseAsn1GeneralizedTimeMs("") == 0);
}
