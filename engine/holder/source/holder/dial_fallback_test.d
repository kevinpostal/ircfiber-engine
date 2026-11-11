/**
 * Real-socket regression harness for direct per-address fallback, strict
 * native IPv6 and authenticated source-pool enforcement (dub:
 * `dub run :holder --config=dial-fallback-test` from `engine/engine`).
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
import vibe.data.json : Json, parseJsonString;
import holder.ipc : HolderConfig, HolderServer, connectHolderAddr, parseHolderAddr, runHolderMetaRegressions;
import ircfiber.holder_client : HolderClient, ClientDialRequest = DialRequest, DialFailedException;
import holder.dial : DialFailed, DialOutcome, ResolvedAddr, createTLSStreamWithTimeout, dialUpstream,
    seedResolvedAddresses;
import holder.protocol : DialRequest, EventLine, ConnectedLine, parseFirstLine;

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

/// The same physical listeners used by the dual-stack cases must never see
/// an IPv4 accept from a native attempt, including protocol failures.
private void caseNativeFailure(Upstream behavior, string tls, long timeoutMs = 1_000) {
    begin("IPv6-only " ~ tls ~ " " ~ behavior.to!string ~ ": no IPv4 fallback");
    auto v6 = new Endpoint("::1", behavior), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    auto req = request(HOST, port, tls, timeoutMs, "::1");
    req.addressFamily = "ipv6";
    req.starttlsTimeoutMs = timeoutMs;
    int ticks;
    bool ticking = true;
    runTask(() nothrow {
        while (ticking) {
            try sleep(50.msecs); catch (Exception) { return; }
            ticks++;
        }
    });
    scope (exit) ticking = false;
    const start = MonoTime.currTime;
    DialFailed failed;
    try {
        auto o = dialUpstream(req, null);
        check(false, "native failure unexpectedly returned " ~ o.peerIp);
        closeOutcome(o);
    } catch (DialFailed e) failed = e;
    const expectedPhase = tls == "starttls" && behavior == Upstream.silent ? "starttls" : "tls";
    check(failed !is null && failed.phase == expectedPhase, "native protocol failure is terminal");
    check((MonoTime.currTime - start).total!"msecs" < 6_000, "native failure remains bounded");
    sleep(300.msecs);
    check(v6.accepts == 1, "one IPv6 socket was tried");
    check(v4.accepts == 0, "healthy IPv4 listener received ZERO accepts");
    if (behavior == Upstream.silent || behavior == Upstream.plaintext)
        check(v6.clientClosed, "failed IPv6 socket closed");
    if (behavior == Upstream.silent)
        check(ticks >= 15, "scheduler progresses during the native protocol deadline");
}

private void caseNativeTcpFailure() {
    begin("IPv6-only TCP refusal: healthy IPv4 listener is never tried");
    auto v6 = new Endpoint("::1", Upstream.silent), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    v6.listener.stopListening();
    v6.listener = TCPListener.init;
    seedBothFamilies(HOST);
    auto req = request(HOST, port, "implicit", 1_000, "::1");
    req.addressFamily = "ipv6";
    DialFailed failed;
    try {
        auto o = dialUpstream(req, null);
        check(false, "native TCP refusal unexpectedly returned " ~ o.peerIp);
        closeOutcome(o);
    } catch (DialFailed e) failed = e;
    check(failed !is null && failed.phase == "tcp", "native TCP refusal stays a failed dial");
    sleep(300.msecs);
    check(v4.accepts == 0, "TCP refusal produced ZERO IPv4 accepts");
}

private void caseNativeSuccess() {
    begin("IPv6-only TLS: original SNI, actual source, no IPv4 socket");
    auto v6 = new Endpoint("::1", Upstream.tls), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    auto req = request(HOST, port, "implicit", 5_000, "::1");
    req.addressFamily = "ipv6";
    auto o = dialUpstream(req, null);
    scope (exit) closeOutcome(o);
    check(o.peerIp == "::1" && o.localIp == "::1", "observed native peer and bound source are IPv6");
    check(v6.sni == [HOST], "native TLS preserves the original SNI");
    roundTrip(o, v6);
    sleep(300.msecs);
    check(v6.accepts == 1 && v4.accepts == 0, "only the IPv6 listener accepted");
}

private void caseNativeAOnly() {
    begin("IPv6-only A-only DNS: no_ipv6_destination, zero TCP accepts");
    auto v6 = new Endpoint("::1", Upstream.tls), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedResolvedAddresses(HOST, [ResolvedAddr("127.0.0.1", AddressFamily.INET)]);
    auto req = request(HOST, port, "implicit", 5_000, "::1");
    req.addressFamily = "ipv6";
    DialFailed failed;
    try {
        auto o = dialUpstream(req, null);
        check(false, "A-only destination unexpectedly connected");
        closeOutcome(o);
    } catch (DialFailed e) failed = e;
    check(failed !is null && failed.phase == "no_ipv6_destination", "A-only native dial has an explicit phase");
    sleep(300.msecs);
    check(v6.accepts == 0 && v4.accepts == 0, "A-only native dial opened zero sockets");
    // A public IPv4 literal is also removed, without ever contacting it.
    req.host = "192.0.2.1";
    failed = null;
    try {
        auto o = dialUpstream(req, null);
        check(false, "IPv4 literal unexpectedly connected");
        closeOutcome(o);
    } catch (DialFailed e) failed = e;
    check(failed !is null && (failed.phase == "no_ipv6_destination" || failed.phase == "blocked"),
        "IPv4 literal is refused before TCP (destination protection may reject documentation space)");
}

/// Exercises the actual authenticated IPC boundary, not only a helper.
/// No production loopback exception is added: successful loopback source
/// fixtures above call dialUpstream directly inside HolderDialHarness.
private void caseSourcePoolBoundary(string dir) {
    begin("authenticated IPC: strict family, native/proxy and source-pool boundaries");
    auto v6 = new Endpoint("::1", Upstream.tls), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedBothFamilies(HOST);
    seedBothFamilies(BLOCKED_HOST);
    HolderConfig cfg;
    cfg.serverId = "dial-harness";
    cfg.token = "fixture-only-token";
    cfg.addrText = "unix://" ~ buildPath(dir, "holder.sock");
    cfg.addr = parseHolderAddr(cfg.addrText);
    cfg.closedRetainSecs = 60;
    cfg.detachMaxSecs = 60;
    cfg.detachBufferBytes = 64 * 1024;
    auto server = new HolderServer(cfg);
    server.start();
    scope (exit) { server.quitAll(); server.stop(); }
    check(server.statusJson()["dialFamilies"] == Json([Json("any"), Json("ipv6")]), "STATUS advertises both dial families");

    string exchange(Json payload) {
        auto c = connectHolderAddr(cfg.addr.toNetworkAddress(true), 3.seconds);
        scope (exit) c.close();
        send(c, "DIAL " ~ payload.toString() ~ "\n");
        foreach (_; 0 .. 10) {
            if (c.waitForDataEx(3.seconds) != WaitForDataStatus.dataAvailable)
                throw new Exception("IPC DIAL response timed out");
            auto line = cast(string) readLine(c, 1024 * 1024, "\n").idup;
            if (line.length >= 6 && line[0 .. 6] == "EVENT ") continue;
            return line;
        }
        throw new Exception("too many IPC events");
    }
    void rejected(Json payload, string label, string code = "bad_request") {
        const line = exchange(payload);
        check(line.length > 4 && line[0 .. 4] == "ERR ", label ~ ": expected ERR, got " ~ line);
        if (line.length > 4 && line[0 .. 4] == "ERR ")
            check(parseJsonString(line[4 .. $])["code"].get!string == code, label ~ ": rejection code");
    }
    auto req = request(HOST, port, "implicit", 1_000, "::1");
    req.addressFamily = "ipv6";
    req.token = cfg.token;
    auto payload = req.toJson();
    rejected(payload, "unconfigured source pool");
    server.cfg.routedIpv6Prefix = "2001:db8:1234:5678::/64";
    rejected(payload, "loopback is not a production pool exception");
    payload["bindIp6"] = "2001:db8:1234:5679:a516:4466:5544:123";
    rejected(payload, "out-of-prefix native source");
    payload["addressFamily"] = "any";
    rejected(payload, "any mode cannot bypass source-pool ownership");
    payload["addressFamily"] = "unknown";
    rejected(payload, "unknown family");
    payload["addressFamily"] = Json(null);
    rejected(payload, "non-string family");
    payload["addressFamily"] = "ipv6";
    payload["bindIp6"] = "";
    rejected(payload, "native without source");
    payload["bindIp6"] = "2001:db8:1234:5678:a516:4466:5544:123";
    auto proxy = Json.emptyObject;
    proxy["host"] = "127.0.0.1";
    proxy["port"] = cast(int) port;
    payload["proxy"] = proxy;
    rejected(payload, "native with proxy");
    payload["proxy"] = Json(null);
    payload["token"] = "wrong";
    rejected(payload, "authentication precedes dial validation", "auth");
    payload["token"] = cfg.token;
    payload["host"] = BLOCKED_HOST;
    auto response = exchange(payload);
    check(response.length > 7 && response[0 .. 7] == "FAILED ", "in-pool source passes IPC validation");
    if (response.length > 7 && response[0 .. 7] == "FAILED ")
        check(parseJsonString(response[7 .. $])["phase"].get!string == "blocked",
            "public destination guard still runs before native filtering");
    sleep(300.msecs);
    check(v6.accepts == 0 && v4.accepts == 0, "all boundary negatives opened ZERO upstream sockets");
}

/// A real IPC peer with the pre-capability STATUS shape. Its any-family DIAL
/// uses physical upstream sockets; the shared client's native guard must stop
/// before opening a DIAL channel to a holder that cannot constrain the family.
private void caseOldHolderCapability() {
    begin("old holder: native DIAL count zero, any still carries an upstream round trip");
    auto v6 = new Endpoint("::1", Upstream.tls), v4 = new Endpoint("127.0.0.1", Upstream.tls);
    const port = bindPair(v6, v4);
    scope (exit) stopPair(v6, v4);
    seedResolvedAddresses(HOST, [ResolvedAddr("127.0.0.1", AddressFamily.INET)]);
    int dialCommands, statusCommands;
    TCPConnection[] controls;
    string[] fixtureErrors;
    auto oldStatus = Json.emptyObject;
    oldStatus["proto"] = 1;
    oldStatus["serverId"] = "old-holder-fixture";
    oldStatus["holder"] = "pre-dialFamilies-fixture";
    // Deliberately no dialFamilies, just like a retained old holder.
    void serveOldHolder(TCPConnection c) {
        scope (exit) c.close();
        string verb;
        Json payload;
        parseFirstLine(cast(string) readLine(c, 1024 * 1024, "\n").idup, verb, payload);
        if (verb == "HELLO") {
            check(payload["serverId"].get!string == "old-holder-fixture", "old-holder HELLO identity");
            controls ~= c;
            send(c, "OK " ~ oldStatus.toString() ~ "\n");
            while (true) {
                string line;
                try line = cast(string) readLine(c, 1024 * 1024, "\n").idup;
                catch (Exception) { return; } // fixture teardown closes control
                parseFirstLine(line, verb, payload);
                if (verb != "STATUS") throw new Exception("unexpected old-holder control " ~ verb);
                statusCommands++;
                send(c, "OK " ~ oldStatus.toString() ~ "\n");
            }
        }
        if (verb != "DIAL") throw new Exception("unexpected old-holder first line " ~ verb);
        dialCommands++;
        // Old holders did not read addressFamily; simulate that wire behavior.
        payload["addressFamily"] = "any";
        auto req = DialRequest.fromJson(payload);
        auto o = dialUpstream(req, null);
        scope (exit) closeOutcome(o);
        auto connected = ConnectedLine("old-c-1", o.peerIp, o.localIp, o.peerPort, o.localPort, 1, o.tlsInfo);
        send(c, "CONNECTED " ~ connected.toJson().toString() ~ "\n");
        const line = cast(string) readLine(c).idup;
        o.tls.write(cast(const(ubyte)[]) (line ~ "\r\n"));
        o.tls.flush();
        send(c, cast(string) readLine(o.tls).idup ~ "\r\n");
    }
    auto listener = listenTCP(0, (TCPConnection c) @trusted nothrow {
        try serveOldHolder(c);
        catch (Exception e) {
            try fixtureErrors ~= e.msg; catch (Exception) {}
        }
    }, "127.0.0.1");
    void closeFixture() {
        listener.stopListening();
        foreach (c; controls) {
            try { c.close(); } catch (Exception) {}
        }
    }
    scope (exit) closeFixture();
    auto client = new HolderClient("old-holder-fixture",
        "tcp://127.0.0.1:" ~ listener.bindAddress.port.to!string, "fixture-only-token");
    client.connectControl();
    const status = client.status();
    check(status.supportsFamily("any") && !status.supportsFamily("ipv6"),
        "missing capability preserves any only");
    ClientDialRequest nativeReq;
    nativeReq.host = HOST;
    nativeReq.port = port;
    nativeReq.tls = "implicit";
    nativeReq.sni = HOST;
    nativeReq.addressFamily = "ipv6";
    nativeReq.bindIp6 = "2001:db8:1234:5678:a516:4466:5544:123";
    DialFailedException rejected;
    try {
        auto unexpected = client.dial(nativeReq, null);
        unexpected.stream.close();
        check(false, "shared client must refuse native transport through old holder");
    } catch (DialFailedException e) rejected = e;
    check(rejected !is null && rejected.phase == "holder", "native rejected at holder capability gate");
    sleep(300.msecs);
    check(statusCommands >= 2, "native request performs a fresh STATUS capability check");
    check(dialCommands == 0, "old holder received ZERO native DIAL commands");
    check(v6.accepts == 0 && v4.accepts == 0, "capability failure opened ZERO upstream sockets");

    auto anyReq = nativeReq;
    anyReq.addressFamily = "any";
    anyReq.bindIp6 = "";
    auto result = client.dial(anyReq, null);
    scope (exit) result.stream.close();
    check(result.peerIp == "127.0.0.1", "old holder any request reaches physical IPv4 upstream");
    send(result.stream, "PING :old-holder-any\r\n");
    check(cast(string) readLine(result.stream).idup == ":127.0.0.1 PONG PING :old-holder-any",
        "any mode carries a real upstream application round trip");
    check(dialCommands == 1 && v4.accepts == 1 && v6.accepts == 0,
        "one permitted any DIAL and one physical IPv4 accept");
    check(v4.sni == [HOST], "old-holder any transport retains SNI");
    check(fixtureErrors.length == 0, "old-holder IPC fixture completed without errors");
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
            caseNativeSuccess();
            caseNativeFailure(Upstream.closesBeforeTls, "implicit");
            caseNativeFailure(Upstream.silent, "implicit");
            caseNativeFailure(Upstream.plaintext, "implicit");
            caseNativeFailure(Upstream.starttlsThenCloses, "starttls");
            caseNativeFailure(Upstream.silent, "starttls");
            caseNativeTcpFailure();
            caseNativeAOnly();
            caseSourcePoolBoundary(dir);
            caseOldHolderCapability();
            begin("holder META: owned bounded wire storage and public-consumer round trips");
            runHolderMetaRegressions(dir, (bool passed, string name) { check(passed, name); });
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
