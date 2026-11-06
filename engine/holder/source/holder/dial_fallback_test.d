/**
 * Real-socket regression harness for `dialUpstream`'s direct per-address
 * fallback (dub: `dub run :holder --config=dial-fallback-test` from
 * `engine/engine`).
 *
 * One TLS hostname resolves (through the real resolver cache) to `::1`
 * then `127.0.0.1` on one port; loopback listeners play the upstream ircd
 * on each address. The client side is the production `dialUpstream`; the
 * TLS servers present a freshly minted CA-signed certificate and accept
 * only the original SNI hostname. Needs the `openssl` CLI and IPv6
 * loopback: either missing is a FAIL (exit 2), never a skipped pass.
 */
module holder.dial_fallback_test;

version (HolderDialHarness):

import core.time : Duration, MonoTime, msecs, seconds;
import std.algorithm : canFind, count;
import std.conv : to;
import std.file : mkdirRecurse, rmdirRecurse, tempDir, write;
import std.path : buildPath;
import std.process : environment, execute;
import std.random : uniform;
import std.socket : AddressFamily, Internet6Address, TcpSocket;
import std.stdio : stderr, writeln;
import std.string : strip;
import vibe.core.core : exitEventLoop, runEventLoop, runTask, setTimer, sleep;
import vibe.core.net : TCPConnection, TCPListener, WaitForDataStatus, connectTCP, listenTCP;
import vibe.core.stream : IOMode;
import vibe.stream.operations : readLine;
import vibe.stream.tls : TLSContext, TLSContextKind, TLSStream, createTLSContext, createTLSStream;
import holder.dial : DialFailed, DialOutcome, ResolvedAddr, createTLSStreamWithTimeout, dialUpstream,
    seedResolvedAddresses;
import holder.protocol : DialRequest, EventLine;

private enum HOST = "fallback.harness.test";
private enum BLOCKED_HOST = "blocked.harness.test";

private void removeHarnessDirectory(string path) nothrow {
    try { rmdirRecurse(path); } catch (Exception) {}
}

/// What a loopback listener does with each accepted connection.
private enum Upstream {
    /// Accepts TCP, then closes ~100 ms later without a TLS byte (the
    /// production EOF-before-ServerHello shape).
    closesBeforeTls,
    /// Accepts TCP and never answers; holds until the client closes.
    silent,
    /// Speaks plaintext IRC on a TLS port; holds until the client closes.
    plaintext,
    /// Completes TLS (SNI-checked) and one application line round trip.
    tls,
    /// STARTTLS: one NOTICE, `670` to `STARTTLS`, then closes.
    starttlsThenCloses,
    /// STARTTLS: one NOTICE, `670`, TLS, application round trip.
    starttlsTls,
}

private final class Endpoint {
    string ip;
    Upstream behavior;
    int accepts;
    bool clientClosed;
    string[] sni;
    string received;
    TCPListener listener;
    this(string ip, Upstream behavior) { this.ip = ip; this.behavior = behavior; }
}

private __gshared TLSContext gCertCtx;
private __gshared string gCaFile;
private __gshared string[] gFailures;
private __gshared int gCases;

// ── Fixtures ────────────────────────────────────────────────────────────────

/// Mints a throwaway CA and a server certificate for HOST (SAN + serverAuth)
/// in `dir`. Returns false with a reason when the openssl CLI is unusable.
private bool mintCertificates(string dir, out string why) {
    const cfg = buildPath(dir, "openssl.cnf");
    write(cfg, "[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = " ~ HOST ~ "\n"
        ~ "[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n"
        ~ "subjectKeyIdentifier = hash\n"
        ~ "[v3_srv]\nbasicConstraints = critical,CA:FALSE\n"
        ~ "keyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\n"
        ~ "subjectAltName = DNS:" ~ HOST ~ "\n");
    const ca = buildPath(dir, "ca.crt"), caKey = buildPath(dir, "ca.key");
    const csr = buildPath(dir, "srv.csr"), crt = buildPath(dir, "srv.crt"), key = buildPath(dir, "srv.key");
    const steps = [
        ["openssl", "req", "-x509", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", ca,
            "-days", "2", "-subj", "/CN=ircfiber-holder-harness-ca", "-config", cfg, "-extensions", "v3_ca"],
        ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr,
            "-subj", "/CN=" ~ HOST, "-config", cfg],
        ["openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey,
            "-set_serial", uniform(1, int.max).to!string, "-out", crt, "-days", "2",
            "-extfile", cfg, "-extensions", "v3_srv"],
    ];
    foreach (cmd; steps) {
        try {
            auto r = execute(cmd);
            if (r.status != 0) { why = cmd[0 .. 2].to!string ~ " failed: " ~ r.output.strip; return false; }
        } catch (Exception e) {
            why = "cannot run openssl: " ~ e.msg;
            return false;
        }
    }
    gCaFile = ca;
    gCertCtx = createTLSContext(TLSContextKind.server);
    gCertCtx.useCertificateChainFile(crt);
    gCertCtx.usePrivateKeyFile(key);
    return true;
}

/// Explicit IPv6 loopback probe: the harness needs `::1` to be bindable.
private bool ipv6LoopbackAvailable(out string why) {
    try {
        auto s = new TcpSocket(AddressFamily.INET6);
        scope (exit) s.close();
        s.bind(new Internet6Address("::1", 0));
        return true;
    } catch (Exception e) {
        why = e.msg;
        return false;
    }
}

// ── Loopback upstreams ──────────────────────────────────────────────────────

/// Reads and discards until the client closes (true) or `limit` passes.
private bool drainUntilClientCloses(TCPConnection c, Duration limit) {
    ubyte[1024] buf;
    while (true) {
        const st = c.waitForDataEx(limit);
        if (st == WaitForDataStatus.noMoreData) return true;
        if (st == WaitForDataStatus.timeout) return false;
        c.read(buf[], IOMode.once);
    }
}

private void send(ref TCPConnection c, string line) {
    c.write(cast(const(ubyte)[]) line);
    c.flush();
}

/// Server side of the TLS leg: SNI must be HOST, then one line each way.
private void serveTls(Endpoint ep, TCPConnection c) {
    auto certCtx = gCertCtx;
    auto sctx = createTLSContext(TLSContextKind.serverSNI);
    sctx.sniCallback = (string name) @safe {
        ep.sni ~= name;
        return name == HOST ? certCtx : null;
    };
    auto tls = createTLSStream(c, sctx);
    ep.received = cast(string) readLine(tls).idup;
    tls.write(cast(const(ubyte)[]) (":" ~ ep.ip ~ " PONG " ~ ep.received ~ "\r\n"));
    tls.flush();
    tls.finalize();
}

private void serve(Endpoint ep, TCPConnection c) {
    ep.accepts++;
    final switch (ep.behavior) {
        case Upstream.closesBeforeTls:
            sleep(100.msecs);
            c.close();
            return;
        case Upstream.silent:
            ep.clientClosed = drainUntilClientCloses(c, 20.seconds);
            return;
        case Upstream.plaintext:
            send(c, ":" ~ ep.ip ~ " NOTICE * :*** plaintext on a TLS port\r\n");
            ep.clientClosed = drainUntilClientCloses(c, 20.seconds);
            return;
        case Upstream.tls:
            serveTls(ep, c);
            return;
        case Upstream.starttlsThenCloses:
        case Upstream.starttlsTls:
            send(c, ":" ~ ep.ip ~ " NOTICE * :*** pre-TLS from " ~ ep.ip ~ "\r\n");
            const verb = cast(string) readLine(c).idup;
            if (verb != "STARTTLS") throw new Exception("expected STARTTLS, got " ~ verb);
            send(c, ":" ~ ep.ip ~ " 670 * :STARTTLS successful, go ahead\r\n");
            if (ep.behavior == Upstream.starttlsThenCloses) { c.close(); return; }
            serveTls(ep, c);
            return;
    }
}

private TCPListener listenOn(Endpoint ep, ushort port) {
    return listenTCP(port, (TCPConnection c) @trusted nothrow {
        try serve(ep, c);
        catch (Exception e) {
            try stderr.writeln("  [upstream ", ep.ip, "] ", e.msg); catch (Exception) {}
        }
    }, ep.ip);
}

/// Binds `v6` on `::1` and `v4` on `127.0.0.1` to one free port.
private ushort bindPair(Endpoint v6, Endpoint v4) {
    foreach (attempt; 0 .. 20) {
        auto l6 = listenOn(v6, 0);
        const port = l6.bindAddress.port;
        try {
            v4.listener = listenOn(v4, port);
        } catch (Exception) {
            l6.stopListening();
            continue;
        }
        v6.listener = l6;
        return port;
    }
    throw new Exception("could not bind ::1 and 127.0.0.1 to one port");
}

private void stopPair(Endpoint v6, Endpoint v4) {
    if (v6.listener) v6.listener.stopListening();
    if (v4.listener) v4.listener.stopListening();
}

// ── Assertions ──────────────────────────────────────────────────────────────

private string gCase;

private void check(bool ok, string what) {
    if (ok) return;
    gFailures ~= gCase ~ ": " ~ what;
    stderr.writeln("  FAIL ", what);
}

private DialRequest request(string host, ushort port, string tls, long tlsTimeoutMs = 5_000,
                            string bindIp6 = "") {
    DialRequest r;
    r.tag.name = "dial-fallback-harness";
    r.host = host;
    r.sni = host;
    r.port = port;
    r.tls = tls;
    r.bindIp6 = bindIp6;
    r.connectTimeoutMs = 3_000;
    r.tlsTimeoutMs = tlsTimeoutMs;
    r.starttlsTimeoutMs = 5_000;
    return r;
}

private void seedBothFamilies(string host) {
    seedResolvedAddresses(host, [ResolvedAddr("::1", AddressFamily.INET6),
                                 ResolvedAddr("127.0.0.1", AddressFamily.INET)]);
}

private size_t phases(const EventLine[] events, string phase) {
    return events.count!(e => e.phase == phase);
}

private bool anyEvent(const EventLine[] events, string phase, string needle) {
    foreach (e; events) if (e.phase == phase && e.text.canFind(needle)) return true;
    return false;
}

private void dumpEvents(const EventLine[] events) {
    foreach (e; events)
        stderr.writeln("    event ", e.phase, " ", e.text, e.peerIp.length ? " peer=" ~ e.peerIp : "");
}

/// One application round trip over the dialed TLS stream.
private void roundTrip(ref DialOutcome o, Endpoint expected) {
    if (o.tls is null) { check(false, "no TLS stream for the application round trip"); return; }
    o.tls.write("PING :roundtrip-" ~ expected.ip ~ "\r\n");
    o.tls.flush();
    const reply = cast(string) readLine(o.tls).idup;
    check(reply == ":" ~ expected.ip ~ " PONG PING :roundtrip-" ~ expected.ip,
        "application round trip through " ~ expected.ip ~ ", got `" ~ reply ~ "`");
}

private void closeOutcome(ref DialOutcome o) {
    try { if (o.tls !is null) o.tls.finalize(); } catch (Exception) {}
    try { o.conn.close(); } catch (Exception) {}
}

private void begin(string name) {
    gCase = name;
    gCases++;
    writeln("case ", name);
}

// ── Cases ───────────────────────────────────────────────────────────────────

/// The positive fixture is genuinely trusted: CA-validated for HOST.
private void caseTrustedFixture() {
    begin("fixture: CA-validated TLS for " ~ HOST);
    auto v6 = new Endpoint("::1", Upstream.tls), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    auto ctx = createTLSContext(TLSContextKind.client); // trustedCert + host check
    ctx.useTrustedCertificateFile(gCaFile);
    auto conn = connectTCP("127.0.0.1", port);
    TLSStream tls;
    try tls = createTLSStreamWithTimeout(conn, ctx, HOST, 5.seconds);
    catch (Exception e) { check(false, "trusted handshake failed: " ~ e.msg); conn.close(); return; }
    tls.write("PING :roundtrip-127.0.0.1\r\n");
    tls.flush();
    check(cast(string) readLine(tls).idup == ":127.0.0.1 PONG PING :roundtrip-127.0.0.1", "trusted round trip");
    check(v4.sni == [HOST], "server saw SNI " ~ v4.sni.to!string);
    tls.finalize();
    conn.close();
}

/// The reported production shape: the TCP winner drops the handshake, the
/// other family completes it. IPv6 attempts bind the IPv6 source only.
private void caseFirstClosesSecondCompletes() {
    begin("implicit TLS: ::1 closes before TLS, 127.0.0.1 completes");
    const failuresBefore = gFailures.length;
    auto v6 = new Endpoint("::1", Upstream.closesBeforeTls), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    EventLine[] events;
    auto req = request(HOST, port, "implicit", 5_000, "::1");
    DialOutcome o;
    try o = dialUpstream(req, (EventLine e) { events ~= e; });
    catch (DialFailed e) { check(false, "dial failed [" ~ e.phase ~ "] " ~ e.msg); dumpEvents(events); return; }
    scope (exit) closeOutcome(o);
    check(o.tls !is null, "TLS stream negotiated");
    check(o.peerIp == "127.0.0.1", "connected peer is 127.0.0.1, got " ~ o.peerIp);
    check(o.tlsInfo.ok && o.tlsInfo.info.certCn == HOST, "peer certificate CN " ~ o.tlsInfo.info.certCn);
    check(v4.sni == [HOST], "original hostname sent as SNI: " ~ v4.sni.to!string);
    check(v6.accepts == 1 && v4.accepts == 1, "each address tried once: ::1="
        ~ v6.accepts.to!string ~ " 127.0.0.1=" ~ v4.accepts.to!string);
    check(phases(events, "tcp_open") == 2, "two tcp_open events");
    check(anyEvent(events, "attempt", "::1:" ~ port.to!string ~ " via ipv6:::1 bind=::1"), "IPv6 attempt bound to ::1");
    check(!anyEvent(events, "attempt", "127.0.0.1:" ~ port.to!string ~ " via ipv6:::1 bind="), "IPv4 attempt not bound");
    check(anyEvent(events, "attempt_fail", "::1 via ipv6:::1: TLS failed: "), "::1 TLS failure reported");
    check(anyEvent(events, "attempt_fail", "trying the next address"), "fallback announced");
    roundTrip(o, v4);
    if (gFailures.length > failuresBefore) dumpEvents(events);
}

/// A silent first address costs exactly the TLS timeout, without
/// stalling the event loop, and its socket is closed before moving on.
private void caseSilentTimeoutThenSecond() {
    begin("implicit TLS: ::1 silent (bounded timeout, scheduler progresses), 127.0.0.1 completes");
    auto v6 = new Endpoint("::1", Upstream.silent), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    int ticks;
    bool ticking = true;
    runTask(() nothrow {
        while (ticking) {
            try sleep(50.msecs); catch (Exception) { return; }
            ticks++;
        }
    });
    scope (exit) ticking = false;
    EventLine[] events;
    auto req = request(HOST, port, "implicit", 1_500);
    const start = MonoTime.currTime;
    DialOutcome o;
    try o = dialUpstream(req, (EventLine e) { events ~= e; });
    catch (DialFailed e) { check(false, "dial failed [" ~ e.phase ~ "] " ~ e.msg); dumpEvents(events); return; }
    scope (exit) closeOutcome(o);
    const tookMs = (MonoTime.currTime - start).total!"msecs";
    check(o.tls !is null && o.peerIp == "127.0.0.1", "TLS via 127.0.0.1, got " ~ o.peerIp);
    check(tookMs >= 1_400 && tookMs < 6_000, "bounded by the TLS timeout: " ~ tookMs.to!string ~ " ms");
    check(ticks >= 15, "scheduler kept running during the handshake wait: " ~ ticks.to!string ~ " ticks");
    check(anyEvent(events, "attempt_fail", "TLS handshake timed out"), "timeout reported for ::1");
    sleep(300.msecs);
    check(v6.clientClosed, "timed-out ::1 socket closed by the client");
    check(v6.accepts == 1 && v4.accepts == 1, "each address tried once");
    roundTrip(o, v4);
}

/// Every address fails TLS: FAILED phase tls with the first reason, both
/// sockets closed, and the plaintext answer is never returned as a session.
private void caseAllFail() {
    begin("implicit TLS: every address fails — closes cleanly, never plaintext");
    auto v6 = new Endpoint("::1", Upstream.silent), v4 = new Endpoint("127.0.0.1", Upstream.plaintext);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    EventLine[] events;
    auto req = request(HOST, port, "implicit", 1_000);
    DialFailed failed;
    try {
        auto o = dialUpstream(req, (EventLine e) { events ~= e; });
        check(false, "dial must not succeed; returned peer " ~ o.peerIp ~ (o.tls is null ? " WITHOUT TLS" : ""));
        closeOutcome(o);
    } catch (DialFailed e) failed = e;
    if (failed !is null) {
        check(failed.phase == "tls", "phase tls, got " ~ failed.phase);
        check(failed.msg.canFind("TLS handshake timed out"), "first failure kept verbatim: " ~ failed.msg);
        check(failed.msg.canFind("(2 addresses failed TLS)"), "attempt count in reason: " ~ failed.msg);
    }
    sleep(300.msecs);
    check(v6.clientClosed && v4.clientClosed, "both failed sockets closed by the client: ::1="
        ~ v6.clientClosed.to!string ~ " 127.0.0.1=" ~ v4.clientClosed.to!string);
    check(v6.accepts == 1 && v4.accepts == 1, "each address tried once");
    check(phases(events, "tcp_open") == 2, "two tcp_open events");
}

/// Plain TCP keeps first-connect semantics: no protocol step, no fallback.
private void casePlainTcpUnchanged() {
    begin("plain TCP: first connected address wins, nothing else dialed");
    auto v6 = new Endpoint("::1", Upstream.silent), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    EventLine[] events;
    auto req = request(HOST, port, "none");
    DialOutcome o;
    try o = dialUpstream(req, (EventLine e) { events ~= e; });
    catch (DialFailed e) { check(false, "dial failed [" ~ e.phase ~ "] " ~ e.msg); return; }
    check(o.tls is null && o.peerIp == "::1", "plain TCP to ::1, got " ~ o.peerIp);
    check(phases(events, "tcp_open") == 1 && phases(events, "tls") == 0, "one tcp_open, no tls event");
    sleep(300.msecs);
    check(v4.accepts == 0, "127.0.0.1 never dialed");
    closeOutcome(o);
}

/// STARTTLS: the failed address's pre-TLS lines are not relayed.
private void caseStarttlsFallback() {
    begin("STARTTLS: ::1 drops after 670, 127.0.0.1 completes; only its pre-TLS lines kept");
    auto v6 = new Endpoint("::1", Upstream.starttlsThenCloses),
         v4 = new Endpoint("127.0.0.1", Upstream.starttlsTls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    EventLine[] events;
    auto req = request(HOST, port, "starttls");
    DialOutcome o;
    try o = dialUpstream(req, (EventLine e) { events ~= e; });
    catch (DialFailed e) { check(false, "dial failed [" ~ e.phase ~ "] " ~ e.msg); dumpEvents(events); return; }
    scope (exit) closeOutcome(o);
    check(o.tls !is null && o.peerIp == "127.0.0.1", "STARTTLS via 127.0.0.1, got " ~ o.peerIp);
    check(cast(string) o.preTlsLines == ":127.0.0.1 NOTICE * :*** pre-TLS from 127.0.0.1\r\n",
        "pre-TLS lines are the winner's only: `" ~ cast(string) o.preTlsLines ~ "`");
    check(phases(events, "starttls") == 2 && phases(events, "tcp_open") == 2, "starttls/tcp_open per address");
    check(v4.sni == [HOST], "original hostname sent as SNI after STARTTLS");
    roundTrip(o, v4);
}

/// The destination policy still runs before any connect.
private void caseDestinationPolicy() {
    begin("destination policy: non-allowlisted private resolution is refused before connecting");
    auto v6 = new Endpoint("::1", Upstream.tls), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(BLOCKED_HOST);
    auto req = request(BLOCKED_HOST, port, "implicit");
    try {
        auto o = dialUpstream(req, null);
        check(false, "dial to a private address must be refused");
        closeOutcome(o);
    } catch (DialFailed e) {
        check(e.phase == "blocked", "phase blocked, got " ~ e.phase);
    }
    check(v6.accepts == 0 && v4.accepts == 0, "no address dialed");
}

int main() {
    string why;
    if (!ipv6LoopbackAvailable(why)) {
        stderr.writeln("FAIL: IPv6 loopback ::1 is unavailable (", why, "). This harness needs both families;",
            " enable IPv6 on lo (Linux: sysctl -w net.ipv6.conf.lo.disable_ipv6=0; Docker: --sysctl",
            " net.ipv6.conf.all.disable_ipv6=0) — it is never skipped.");
        return 2;
    }
    const dir = buildPath(tempDir, "ircfiber-dial-harness-" ~ uniform(0, int.max).to!string);
    mkdirRecurse(dir);
    scope (exit) removeHarnessDirectory(dir);
    if (!mintCertificates(dir, why)) {
        stderr.writeln("FAIL: cannot mint fresh harness certificates: ", why);
        return 2;
    }
    environment["IRCFIBER_DIAL_PRIVATE_HOSTS"] = HOST;

    bool timedOut;
    runTask(() nothrow {
        auto watchdog = setTimer(120.seconds, { timedOut = true; exitEventLoop(); });
        scope (exit) { watchdog.stop(); exitEventLoop(); }
        try {
            caseTrustedFixture();
            caseFirstClosesSecondCompletes();
            caseSilentTimeoutThenSecond();
            caseAllFail();
            casePlainTcpUnchanged();
            caseStarttlsFallback();
            caseDestinationPolicy();
        } catch (Throwable t) {
            try gFailures ~= gCase ~ ": unexpected " ~ t.toString(); catch (Throwable) {}
        }
    });
    runEventLoop();
    if (timedOut) gFailures ~= "harness watchdog: did not finish within 120 s (stuck in " ~ gCase ~ ")";
    if (gFailures.length) {
        stderr.writeln("\nFAIL ", gFailures.length, " check(s):");
        foreach (f; gFailures) stderr.writeln("  - ", f);
        return 1;
    }
    writeln("\nPASS ", gCases, " dial fallback cases");
    return 0;
}
