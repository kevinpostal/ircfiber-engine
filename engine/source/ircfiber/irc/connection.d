module ircfiber.irc.connection;

import std.array : join;
import std.string : toUpper, toStringz, indexOf, lastIndexOf, split, startsWith, strip, stripLeft;
import std.base64 : Base64;
import std.conv : to;
import std.datetime : Clock, SysTime;
import std.uni : toLower;
import std.algorithm : canFind, countUntil, remove;
import std.socket : getAddress, AddressFamily;
import std.uuid : randomUUID;
import std.typecons : Nullable;
import core.sys.posix.unistd : getpid;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.channel : Channel;
import vibe.core.log;
import vibe.core.net : connectTCP, TCPConnection;
import vibe.core.task : Task;
import vibe.data.json : Json;
import vibe.stream.tls : TLSContext, TLSContextKind, TLSPeerValidationMode,
    TLSStream, createTLSContext, createTLSStream;
import vibe.stream.operations : IOMode;
import core.time : Duration, dur, msecs, seconds;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : NetworkConfig, SASLMechanism, TLSMode, normalizeChannelName;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.irc.reconnect : ExponentialBackoff;
import ircfiber.irc.sasl : buildSaslPlainPayload, ScramSha256Client;
import ircfiber.irc.tls_safe : safeTLSRead;
import ircfiber.storage.buffer : sanitizeUtf8;
import ircfiber.engine.handoff : HandoffState, ServerFeaturesSnapshot;
import ircfiber.logging : logJsonMap, logException;
import ircfiber.observability : recordCounter, recordGauge, recordHistogram;
import ircfiber.tracing : withSpan, Span;
import ircfiber.engine.adopted_socket : AdoptedSocket;
import ircfiber.async : safeFiberRun;

/// IRC connection state.
///
/// W1-T01 (plan B1): added `waiting_to_retry` to the engine enum so
/// the frontend's already-declared `ConnectionState.waiting_to_retry`
/// variant (frontend/src/types.ts:17-23) is reachable from the engine.
/// Without this, the connecting-state status during the backoff sleep
/// would mask the new `waiting_to_retry` + countdown banner branch.
enum ConnectionState {
    disconnected,
    connecting,
    connected,
    disconnecting,
    /// Backoff timer sleeping before the next reconnect attempt.
    /// Set by the engine at connection.d:1595 (just before the
    /// deadline sleep) and cleared by the existing line 1704 when
    /// `attemptConnection()` runs. The frontend renders the
    /// "Reconnecting in {N}s ({Nth} attempt)" copy from the
    /// `retryStatus` snapshot field paired with this state.
    waiting_to_retry
}

// ── IRCv3 capabilities we request ────────────────────────────────────────────
// Sent as CAP REQ :cap1 cap2 ...
// The server will ACK or NAK each; we track which we got.
private immutable string[] DESIRED_CAPS_BASE = [
    "away-notify",
    "account-notify",
    "extended-join",
    "multi-prefix",
    "userhost-in-names",
    "cap-notify",
    "server-time",
    "message-tags",
    "batch",
    "echo-message",
    "chghost",
    "invite-notify",
    "chathistory",
    "msgid",
    "labeled-response",
    "draft/edit-message",
];

private immutable string[] DESIRED_CAPS_SASL = ["sasl"];

// ── Tunables ──────────────────────────────────────────────────────────────────
private enum RECONNECT_MAX_DELAY_SECS     = 60;
private enum REGISTRATION_READ_TIMEOUT_MS = 100;
private enum REGISTRATION_MAX_READS       = 400;   // more reads for CAP LS round-trips
private enum SASL_MAX_READS               = 100;
private enum SASL_READ_TIMEOUT_MS         = 100;
private enum PROCESS_READ_TIMEOUT_MS      = 50;
private enum STREAM_BUFFER_SIZE           = 4096;
private enum DNS_CACHE_TTL_MS             = 30_000;
private enum QUIT_GRACE_PERIOD_MS         = 2_000;  // wait this long for server to close after QUIT

// ── Per-host circuit breaker ─────────────────────────────────────────────────
// Prevents hammering unresponsive servers with rapid reconnect attempts.
// Shared across all PersistentIRCClient instances in the same process.
// After HOST_FAIL_THRESHOLD consecutive failures to the same host:port within
// HOST_WINDOW_MS, the circuit opens and blocks further attempts for
// HOST_COOLDOWN_MS. Reset on any successful connection.
private struct HostCircuitBreaker {
    int failCount;
    long openedAt;   // 0 = closed
    long lastAttemptAt;
}
private HostCircuitBreaker[string] _hostBreakers;
private shared static immutable HOST_WINDOW_MS   = 30 * 60 * 1000;  // 30 min
private shared static immutable HOST_FAIL_THRESHOLD = 5;
private shared static immutable HOST_COOLDOWN_MS = 5 * 60 * 1000;  // 5 min (was 30 min 2026-07-14 — excessive for the reconnect pattern)

/// Record a connection failure to a host. Shared across all clients.
void recordHostFailure(string host, int port) {
    auto key = host ~ ":" ~ port.to!string;
    auto now = Clock.currTime.toUnixTime!long * 1000;
    auto breaker = key in _hostBreakers;
    if (breaker !is null) {
        if (now - breaker.lastAttemptAt > HOST_WINDOW_MS) {
            breaker.failCount = 0;
            breaker.openedAt = 0;
        }
        breaker.failCount++;
        breaker.lastAttemptAt = now;
        if (breaker.failCount >= HOST_FAIL_THRESHOLD && breaker.openedAt == 0) {
            breaker.openedAt = now;
            logWarn("Host circuit breaker OPENED for %s after %d failures (cooling down %d ms)",
                key, breaker.failCount, HOST_COOLDOWN_MS);
        }
    } else {
        _hostBreakers[key] = HostCircuitBreaker(1, 0, now);
    }
}

/// Record a successful connection — resets the breaker for this host.
void recordHostSuccess(string host, int port) {
    auto key = host ~ ":" ~ port.to!string;
    if (auto breaker = key in _hostBreakers) {
        _hostBreakers.remove(key);
        logInfo("Host circuit breaker CLOSED for %s (connection succeeded)", key);
    }
}

/// Check if the circuit breaker allows a new connection. Returns false
/// (don't connect) when the circuit is open and still in cooldown.
bool canConnectToHost(string host, int port) {
    auto key = host ~ ":" ~ port.to!string;
    if (auto breaker = key in _hostBreakers) {
        if (breaker.openedAt > 0) {
            const now = Clock.currTime.toUnixTime!long * 1000;
            if (now - breaker.openedAt < HOST_COOLDOWN_MS) {
                return false;
            }
            _hostBreakers.remove(key);
            logInfo("Host circuit breaker CLOSED for %s (cooldown expired)", key);
        }
    }
    return true;
}

// ── Enterprise connection timeouts ───────────────────────────────────────────
// These bounds prevent a single silent/black-holed peer from hanging an engine
// fiber forever. vibe.d's connectTCP defaults to Duration.max; TLS handshake
// has no timeout at all. Every blocking network step must be bounded.
private enum CONNECT_TIMEOUT_SECONDS               = 10;
private enum TLS_HANDSHAKE_TIMEOUT_SECONDS         = 10;
private enum HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS   = 15;
// Hard upper bound on the CAP+NICK+USER+SASL handshake from the moment we
// send the first registration byte to either RPL_WELCOME (001) or a fatal
// error reply (e.g. 433 ERR_NICKNAMEINUSE, 464 ERR_PASSWDMISMATCH). 30s
// is plenty for a healthy IRC server (CAP+SASL+001 typically completes
// in <2s) and short enough that a black-holed server can't wedge a
// network's join state forever. RFC 2812 §2.3 explicitly says "it is
// not advised to wait forever for the reply" — this is the enforcement.
// We surface stuck states via ircfiber.registration.timeout in the
// admin API so operators can identify the offending peer.
private enum REGISTRATION_OVERALL_TIMEOUT_SECS    = 30;
// Cap on the auto-appended-underscore fallback chain during registration.
// After this many 433s we stop appending `_` (which produces the
// `Zod___`, `Zod____`, ... ghost member entries that accumulate in
// shared channels across reconnect cycles) and instead switch to a
// unique random-suffix nick that we persist for future reconnects.
// Reset to 0 on every 001.
private enum REGISTRATION_MAX_FALLBACK_ATTEMPTS  = 3;
// Length of the random hex suffix appended to the configured nick when
// the engine has to abandon the fallback chain. 5 hex chars → ~1M
// combinations — collision odds on a populated network are negligible,
// and the suffix is short enough to fit comfortably inside IRC's 9-31
// char nick limit on most servers.
private enum REGISTRATION_RANDOM_SUFFIX_HEX_LEN  = 5;
// Fractions of REGISTRATION_OVERALL_TIMEOUT_SECS at which we emit a
// warning event so operators can see the registration is in progress
// (e.g. 50% / 75%). Helps diagnose slow networks without waiting
// for the full timeout to fire.
private enum REGISTRATION_WARN_AT_FRACTION_1     = 50;
private enum REGISTRATION_WARN_AT_FRACTION_2     = 75;

// ── Happy Eyeballs (RFC 8305) ─────────────────────────────────────────────────
//
// Races IPv6 and IPv4 connections with a 250ms stagger so a broken
// address family never causes a visible delay. The algorithm:
//   1. Resolve DNS → collect all A + AAAA records
//   2. Interleave address families (IPv6 first, then IPv4, alternating)
//   3. Start first attempt immediately; after 250ms launch the next, etc.
//   4. Use whichever TCP connection succeeds first; close the losers.

private enum HAPPY_EYEBALLS_DELAY_MS = 250;

// ── Mullvad egress (SOCKS5) pool ─────────────────────────────────────────────
// 2 sidecars on 1 VPS, scalable to 5 via IRCFIBER_MULLVAD_POOL env.
// Each entry is socks5://host:port (resolve locally → CONNECT <ip>:<port>).
// Egress selection per NetworkConfig.egressNodeId: "" = random healthy,
// else label pin (e.g. "se"/"us"). Advisory: per-connection round-robin,
// no per-host sticky; circuit-breaker marks proxy dead 30s after 3 fails.
private struct MullvadProxy {
    string host;
    ushort port;
    string label;
    int failCount;
    long deadUntilMs;
}
private __gshared MullvadProxy[] mullvadPool;
private __gshared size_t mullvadRR;
private __gshared bool mullvadPoolLoaded;

private string mullvadLabelFromHost(string h) {
    auto base = h.split(":")[0];
    auto dash = base.lastIndexOf("-");
    if (dash >= 0 && dash+1 < base.length) return base[dash+1 .. $].toLower();
    auto dot = base.indexOf(".");
    if (dot > 0) return base[0 .. dot].toLower();
    return base.toLower();
}

private void loadMullvadPool() {
    if (mullvadPoolLoaded) return;
    mullvadPoolLoaded = true;
    import std.process : environment;
    auto raw = environment.get("IRCFIBER_MULLVAD_POOL", "");
    if (raw.length == 0) return;
    foreach (entry; raw.split(",")) {
        auto e = entry.strip();
        if (e.length == 0) continue;
        auto p = e.indexOf("://");
        if (p >= 0) e = e[p+3 .. $];
        auto colon = e.lastIndexOf(":");
        string host; ushort port = 1080;
        if (colon >= 0) {
            host = e[0 .. colon].strip();
            try { port = e[colon+1 .. $].strip().to!ushort; } catch (Exception) {}
        } else host = e;
        if (host.length == 0) continue;
        auto label = mullvadLabelFromHost(host);
        mullvadPool ~= MullvadProxy(host, port, label, 0, 0);
        logInfo("Mullvad pool: %s → %s:%d (label=%s)", entry, host, port, label);
    }
}

private MullvadProxy* pickMullvadProxy(string egressNodeId) {
    loadMullvadPool();
    if (mullvadPool.length == 0) return null;
    const now = Clock.currTime.toUnixTime!long * 1000;
    foreach (ref pr; mullvadPool) if (pr.deadUntilMs != 0 && now >= pr.deadUntilMs) { pr.failCount = 0; pr.deadUntilMs = 0; }
    if (egressNodeId.length > 0) {
        foreach (ref pr; mullvadPool) if (pr.label == egressNodeId.toLower()) {
            if (pr.deadUntilMs != 0 && now < pr.deadUntilMs) {
                logWarn("Mullvad pinned %s is dead until %d, falling back to random healthy", egressNodeId, pr.deadUntilMs);
                break;
            }
            return &pr;
        }
        logWarn("Mullvad pinned egress '%s' not found in pool, using random healthy", egressNodeId);
    }
    import std.random : uniform;
    MullvadProxy*[] healthy;
    foreach (ref pr; mullvadPool) if (pr.deadUntilMs == 0 || now >= pr.deadUntilMs) healthy ~= &pr;
    if (healthy.length == 0) return null;
    if (healthy.length == 1) return healthy[0];
    return healthy[uniform(0, healthy.length)];
}

private MullvadProxy*[] getHealthyProxies() {
    loadMullvadPool();
    if (mullvadPool.length == 0) return [];
    const now = Clock.currTime.toUnixTime!long * 1000;
    foreach (ref pr; mullvadPool) if (pr.deadUntilMs != 0 && now >= pr.deadUntilMs) { pr.failCount = 0; pr.deadUntilMs = 0; }
    MullvadProxy*[] healthy;
    foreach (ref pr; mullvadPool) if (pr.deadUntilMs == 0 || now >= pr.deadUntilMs) healthy ~= &pr;
    return healthy;
}

private void recordMullvadSuccess(string label) {
    foreach (ref pr; mullvadPool) if (pr.label == label) { pr.failCount = 0; pr.deadUntilMs = 0; break; }
}
private void recordMullvadFailure(string label) {
    foreach (ref pr; mullvadPool) if (pr.label == label) {
        pr.failCount++;
        if (pr.failCount >= 3) {
            pr.deadUntilMs = Clock.currTime.toUnixTime!long * 1000 + 30_000;
            logWarn("Mullvad proxy %s (%s:%d) marked dead for 30s after 3 fails", label, pr.host, pr.port);
        }
        break;
    }
}

// SOCKS5 → TLS handoff: connectTCP to sidecar, handshake on same TCPConnection,
// then return it for createTLSStreamWithTimeout (avoids private TCPConnection(fd) ctor).
private TCPConnection socks5ConnectViaProxy(MullvadProxy* proxy, string targetIp, ushort targetPort, AddressFamily fam) {
    import core.sys.posix.arpa.inet : inet_pton;
    import core.sys.posix.sys.socket : AF_INET, AF_INET6;
    auto proxyConn = connectTCP(proxy.host, proxy.port, null, 0, CONNECT_TIMEOUT_SECONDS.seconds);
    scope(failure) try { proxyConn.close(); } catch (Exception) {}
    ubyte[3] greet = [0x05, 0x01, 0x00];
    proxyConn.write(greet[]);
    ubyte[2] greetResp;
    proxyConn.read(greetResp[]);
    if (greetResp[0] != 0x05 || greetResp[1] != 0x00) throw new Exception("SOCKS5 proxy auth failed");
    ubyte[] req;
    req ~= cast(ubyte)0x05; req ~= cast(ubyte)0x01; req ~= cast(ubyte)0x00;
    if (fam == AddressFamily.INET) {
        req ~= cast(ubyte)0x01;
        ubyte[4] ip4;
        if (inet_pton(AF_INET, targetIp.toStringz, ip4.ptr) != 1) throw new Exception("SOCKS5 bad IPv4 " ~ targetIp);
        req ~= ip4[];
    } else if (fam == AddressFamily.INET6) {
        req ~= cast(ubyte)0x04;
        ubyte[16] ip6;
        if (inet_pton(AF_INET6, targetIp.toStringz, ip6.ptr) != 1) throw new Exception("SOCKS5 bad IPv6 " ~ targetIp);
        req ~= ip6[];
    } else throw new Exception("SOCKS5 unknown family");
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
    return proxyConn;
}

private struct ResolvedAddr {
    string ip;
    AddressFamily family;
}

private string stripHostBrackets(string host) @safe pure {
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

private __gshared ResolvedAddr[][string] dnsCache;
private __gshared long[string]           dnsCacheTime;

private ResolvedAddr[] resolveAllAddresses(string host, ushort port) {
    import std.datetime : Clock;
    const now = Clock.currTime.toUnixTime!long * 1000;
    auto normalizedHost = stripHostBrackets(host);
    auto cacheKey = normalizedHost;
    if (auto t = cacheKey in dnsCacheTime) {
        if (now - *t < DNS_CACHE_TTL_MS) {
            if (auto cached = cacheKey in dnsCache) return *cached;
        }
    }
    import vibe.core.core : runWorkerTask;
    import vibe.core.channel : createChannel;
    import core.time : seconds;
    auto ch = createChannel!string();
    runWorkerTask((string h, ushort p, Channel!string c) nothrow {
        try {
            auto addrs = getAddress(h, p);
            string encoded;
            foreach (addr; addrs) {
                if (encoded.length > 0) encoded ~= "|";
                encoded ~= addr.toAddrString()
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
            dnsCache[cacheKey]     = result;
            dnsCacheTime[cacheKey] = now;
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

private ResolvedAddr[] interleaveAddressFamilies(ResolvedAddr[] addrs) {
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

private TCPConnection happyEyeballsConnectWithProxy(string host, ushort port, MullvadProxy* proxy) {
    if (proxy !is null) logInfo("Mullvad egress %s (%s:%d) for %s:%d", proxy.label, proxy.host, proxy.port, host, port);
    auto addrs = resolveAllAddresses(host, port);
    if (addrs.length == 0) throw new Exception("DNS resolution failed for " ~ host);

    auto interleaved = interleaveAddressFamilies(addrs);
    logDebug("Happy Eyeballs: racing %d addresses for %s (connect timeout %ds, race timeout %ds)",
        interleaved.length, host, CONNECT_TIMEOUT_SECONDS, HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS);

    import vibe.core.channel : createChannel;

    auto winnerCh = createChannel!int();
    auto conns = new TCPConnection[interleaved.length];
    auto tasks = new Task[interleaved.length];
    bool done = false;

    foreach (idx, addr; interleaved) {
        // Before launching the next attempt, see if an earlier one already won.
        if (idx > 0) {
            int winIdx;
            if (winnerCh.tryConsumeOne(winIdx, HAPPY_EYEBALLS_DELAY_MS.msecs)) {
                if (conns[winIdx] && conns[winIdx].connected) {
                    finishHappyEyeballs(conns, tasks, winIdx);
                    logDebug("Happy Eyeballs: winner %s for %s", interleaved[winIdx].ip, host);
                    return conns[winIdx];
                }
            }
        }

        auto connIdx = idx;
        auto addrIp  = addr.ip;
        auto addrFam = addr.family;
        auto proxyForTask = proxy;
        safeFiberRun("happy_eyeballs_attempt", host, {
            try {
                TCPConnection conn;
                if (proxyForTask !is null) {
                    try {
                        conn = socks5ConnectViaProxy(proxyForTask, addrIp, port, addrFam);
                        recordMullvadSuccess(proxyForTask.label);
                    } catch (Exception se) {
                        recordMullvadFailure(proxyForTask.label);
                        throw se;
                    }
                } else {
                    conn = connectTCP(addrIp, port, null, 0, CONNECT_TIMEOUT_SECONDS.seconds);
                }
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
            }
        });


    }

    // Wait for a winner, one address at a time, up to the race timeout.
    foreach (_; 0 .. interleaved.length) {
        int winIdx;
        if (winnerCh.tryConsumeOne(winIdx, HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS.seconds)) {
            if (conns[winIdx] && conns[winIdx].connected) {
                finishHappyEyeballs(conns, tasks, winIdx);
                logDebug("Happy Eyeballs: winner %s for %s", interleaved[winIdx].ip, host);
                return conns[winIdx];
            }
        }
    }

    finishHappyEyeballs(conns, tasks, -1);
    throw new Exception("All connection attempts failed for " ~ host ~ ":" ~ port.to!string);
}

private TCPConnection happyEyeballsConnect(string host, ushort port, string egressNodeId = "") {
    // Try pinned/primary, then other healthy Mullvad proxies, then direct.
    // This ensures Docker or a single Mullvad exit going down doesn't drop IRC.
    MullvadProxy*[] toTry;
    auto primary = pickMullvadProxy(egressNodeId);
    if (primary !is null) toTry ~= primary;
    auto healthy = getHealthyProxies();
    foreach (p; healthy) {
        bool already = false;
        foreach (q; toTry) if (q is p) { already = true; break; }
        if (!already) toTry ~= p;
    }
    toTry ~= null; // direct fallback
    Exception lastErr;
    foreach (proxy; toTry) {
        try {
            return happyEyeballsConnectWithProxy(host, port, proxy);
        } catch (Exception e) {
            lastErr = e;
            logWarn("happyEyeballsConnect via %s failed for %s:%d: %s, trying next egress", proxy ? proxy.label : "direct", host, port, e.msg);
            // recordMullvadFailure already done inside WithProxy for socks failures
            continue;
        }
    }
    throw lastErr ? lastErr : new Exception("All connection attempts failed for " ~ host ~ ":" ~ port.to!string);
}


/**
 * Clean up Happy Eyeballs loser tasks and connections.
 *
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

/**
 * Create a TLS stream with a bounded handshake timeout.
 *
 * vibe.d's createTLSStream performs the SSL handshake inside the constructor
 * and has no timeout parameter. If the server accepts TCP but never completes
 * the TLS handshake, the fiber blocks forever. This helper runs the handshake
 * in a sub-task and enforces a hard timeout; on timeout it closes the
 * underlying TCP connection to unblock the stuck task.
 */
private TLSStream createTLSStreamWithTimeout(TCPConnection connection, TLSContext ctx, string host, Duration timeout) {
    import vibe.core.channel : createChannel;
    auto doneCh = createChannel!bool();
    TLSStream resultStream;
    Exception resultException;

    // TCPConnection has scoped destruction and cannot be captured directly in
    // a closure. Store it on the heap so the handshake task can safely use it
    // while this function waits on the completion channel.
    static final class ConnHolder {
        TCPConnection conn;
        this(TCPConnection c) { this.conn = c; }
    }
    auto holder = new ConnHolder(connection);

    auto task = safeFiberRun("tls_handshake", host, {
        try {
            resultStream = createTLSStream(holder.conn, ctx, host);
            try { doneCh.put(true); } catch (Exception) {}
        } catch (Exception e) {
            resultException = e;
            try { doneCh.put(false); } catch (Exception) {}
        }
    });

    bool ok;
    if (!doneCh.tryConsumeOne(ok, timeout)) {
        // Timeout: interrupt the handshake task and tear down the socket so
        // the task unblocks instead of leaking a stuck fiber.
        try { task.interrupt(); } catch (Exception) {}
        try { holder.conn.close(); } catch (Exception) {}
        throw new Exception("TLS handshake timed out after " ~ timeout.to!string);
    }

    if (!ok) {
        if (resultException !is null) throw resultException;
        throw new Exception("TLS handshake failed");
    }

    return resultStream;
}

// ── Nick prefix helpers ───────────────────────────────────────────────────────

private string stripNickPrefix(string nick) {
    if (nick.length > 0 && (nick[0] == '~' || nick[0] == '&' || nick[0] == '@' || nick[0] == '%' || nick[0] == '+')) {
        nick = nick[1 .. $];
    }
    // Strip hostmask suffix when userhost-in-names is active (nick!user@host)
    auto bang = nick.indexOf("!");
    if (bang > 0) nick = nick[0 .. bang];
    return nick;
}

private string nickPrefix(string nick) {
    if (nick.length > 0 && (nick[0] == '~' || nick[0] == '&' || nick[0] == '@' || nick[0] == '%' || nick[0] == '+')) {
        return nick[0 .. 1];
    }
    return "";
}

// ── mIRC color / formatting strip ────────────────────────────────────────────

/// Strip mIRC color codes and formatting characters from a string.
/// Codes: \x03 (color), \x02 (bold), \x1D (italic), \x1F (underline),
///        \x1E (strikethrough), \x11 (monospace), \x16 (reverse), \x0F (reset)
string stripMircFormatting(string s) {
    import std.array : Appender;
    Appender!string buf;
    buf.reserve(s.length);
    size_t i = 0;
    while (i < s.length) {
        char c = s[i];
        if (c == '\x03') {
            // \x03[fg[,bg]]  — skip up to 2 optional digit groups
            i++;
            if (i < s.length && s[i] >= '0' && s[i] <= '9') {
                i++;
                if (i < s.length && s[i] >= '0' && s[i] <= '9') i++;
                if (i < s.length && s[i] == ',') {
                    i++;
                    if (i < s.length && s[i] >= '0' && s[i] <= '9') {
                        i++;
                        if (i < s.length && s[i] >= '0' && s[i] <= '9') i++;
                    }
                }
            }
        } else if (c == '\x02' || c == '\x1D' || c == '\x1F' || c == '\x1E' ||
                   c == '\x11' || c == '\x16' || c == '\x0F') {
            i++;
        } else {
            buf.put(c);
            i++;
        }
    }
    return buf.data;
}

// ── CTCP helpers ──────────────────────────────────────────────────────────────

private enum CTCP_DELIM = '\x01';

private bool isCtcp(string text) {
    return text.length >= 2 && text[0] == CTCP_DELIM && text[$ - 1] == CTCP_DELIM;
}

/// Extract CTCP command and optional parameter from a message text.
/// Returns ("", "") if not a CTCP message.
private string[2] parseCtcp(string text) {
    if (!isCtcp(text)) return ["", ""];
    auto inner = text[1 .. $ - 1];
    auto sp    = inner.indexOf(" ");
    if (sp >= 0) return [inner[0 .. sp], inner[sp + 1 .. $]];
    return [inner, ""];
}

/// Build a CTCP reply string (NOTICE).
private string ctcpReply(string command, string param) {
    if (param.length > 0)
        return "\x01" ~ command ~ " " ~ param ~ "\x01";
    return "\x01" ~ command ~ "\x01";
}

// ── ISUPPORT (005) ────────────────────────────────────────────────────────────

/// Key server features extracted from 005 ISUPPORT messages. Legacy
/// struct kept for downstream code that consumes only the 6 most-used
/// tokens — new code should use `PersistentIRCClient.isupportMap`
/// (and its getter `getIsupport()`) to read the *full* feature
/// inventory that the server advertised.
struct ServerFeatures {
    string network;      /// NETWORK=<name>
    string prefix = "@+"; /// PREFIX=(ov)@+  — mode-char to symbol pairs
    string chanModes;    /// CHANMODES=A,B,C,D
    int maxChannels = 0; /// CHANLIMIT=#:N
    int maxNickLen  = 30;/// NICKLEN=N
    int topicLen    = 0; /// TOPICLEN=N
}

/// W1-T01: structured retry state surfaced from the engine's
/// reconnect loop. The frontend renders the ordinal "Nth attempt"
/// label from `attemptCount`, the 1s countdown from `nextRetryAtMs`,
/// and the "Reconnecting…" state badge from `delayMs`. Nullable in
/// the snapshot sense — zero-valued RetryStatus means "no retry
/// scheduled" so the snapshot writer can ship a uniform JSON object
/// without nullable handling (and the WS sync payload conditionally
/// omits the field when both fields are zero).
///
/// Serialised by `NetworkStateSnapshot.toJson()` / deserialised by
/// `NetworkStateSnapshot.fromJson()` in ircfiber/redis/protocol.d.
struct RetryStatus {
    /// 1-based reconnect attempt number. 0 when no retry is pending.
    int  attemptCount;
    /// Unix-ms of the scheduled next reconnect attempt. 0 when no
    /// retry is pending.
    long nextRetryAtMs;
    /// Scheduled delay in milliseconds (informational; the live
    /// countdown is derived from `nextRetryAtMs - now`).
    long delayMs;
}

/// W1-T01: structured disconnect information built by
/// `parseReasonToFailInfo` and emitted via
/// `IRCRawEvent.makeConnectionFail`. The frontend reads the nested
/// shape from the wire and renders IRCCloud-style failure messages
/// (Wave 2 renderReasons.ts) — `type` selects the branch, `reason`
/// is the IRCCloud `RENDER_REASONS` key, `killedReason` carries the
/// kill description for `type=="killed"`, and `sslVerifyError` is
/// the nested {type, error} object for SSL verification failures
/// (per plan B2 — MUST be nested, not flat).
package(ircfiber) struct FailInfo {
    /// One of: "connecting_failed" | "killed" | "socket_closed" |
    /// "ssl_verify_error" | "connecting_restricted" | "connection_blocked"
    string type_;
    /// Raw reason key (matches IRCCloud's RENDER_REASONS table).
    /// Examples: "econnrefused", "nxdomain", "ssl_certificate_error",
    /// "killed", "crash", "pool_lost".
    string reason;
    /// When `type_=="killed"`, carries the kill description
    /// (e.g. "(Ghost)" for supernets.org's UnrealIRCd ghost
    /// protection). Empty for non-kill failures.
    string killedReason;
    /// Populated only when `reason=="ssl_certificate_error"` /
    /// `"ssl_verify_error"`; carries the structured SSL verify
    /// detail nested object `{type, error}` so the frontend can
    /// look up the human string via `renderSSLVerify`. `Json.init`
    /// (default) otherwise.
    Json sslVerifyError;
}

/// W1-T01: helper that builds the nested sslVerifyError Json object
/// so call-sites stay tidy and the wire shape matches the frontend's
/// TS interface exactly. Mirrors the helper documented in plan W1-T01
/// section C — kept `package(ircfiber)` so connection.d's helpers can
/// reach it without exposing FailInfo to the rest of the engine.
package(ircfiber) void setSSLVerify(ref FailInfo dst, string type_, string error) {
    auto inner = Json.emptyObject;
    inner["type"]  = type_;
    inner["error"] = error;
    dst.sslVerifyError = inner;
}

/// Parse a single ISUPPORT token like "PREFIX=(ov)@+" or "NICKLEN=30".
///
/// Side-effects:
///   · Legacy `ServerFeatures f` — patched with the 6 commonly-consumed
///     tokens (NETWORK, PREFIX, CHANMODES, NICKLEN, TOPICLEN,
///     CHANLIMIT) for backward compatibility.
///   · `string[string] map` — receives the FULL inventory keyed upper-
///     case so the frontend (which has a knowledge base of ~80 tokens
///     from RFC 2811/2812/7194 plus every documented IRCv3 extension)
///     can render the complete feature list.
///
/// ISUPPORT keys are case-insensitive per RFC 2812 — we always
/// uppercase them so consumers can do `if ("KICKLEN" in net.isupport)`
/// without worrying about how the server happened to spell the
/// trailing token.
private void applyIsupport(
    ref ServerFeatures f,
    ref string[string] map,
    string token,
) {
    auto eq = token.indexOf("=");
    string key = eq >= 0 ? token[0 .. eq] : token;
    string val = eq >= 0 ? token[eq + 1 .. $] : "";
    if (key.length == 0) return;
    map[toUpper(key)] = val;

    switch (key) {
        case "NETWORK":   f.network     = val; break;
        case "PREFIX":    f.prefix      = val; break;
        case "CHANMODES": f.chanModes   = val; break;
        case "NICKLEN":
            try { f.maxNickLen = val.to!int; } catch (Exception) {}
            break;
        case "TOPICLEN":
            try { f.topicLen = val.to!int; } catch (Exception) {}
            break;
        case "CHANLIMIT":
            // format: #:50
            auto colon = val.indexOf(":");
            if (colon >= 0) {
                try { f.maxChannels = val[colon + 1 .. $].to!int; } catch (Exception) {}
            }
            break;
        default: break;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PersistentIRCClient
// ─────────────────────────────────────────────────────────────────────────────

/// How long (ms) to wait before sending auto-JOINs so the configured
/// `delaySeconds` (measured from `registrationStartMs`, i.e. ≈ TCP
/// connect) is satisfied. Returns 0 when no delay is configured or the
/// window has already elapsed — callers then join immediately.
///
/// Drives the SuperNETs/DangerousIRCd auto-join fix: those IRCds reject
/// JOIN inside the first 5s after connect with 421 "You must be connected
/// for at least 5 seconds before you can use this command".
long remainingJoinDelayMs(uint delaySeconds, long nowMs, long registrationStartMs) @safe pure nothrow {
    if (delaySeconds == 0) return 0;
    const elapsed = nowMs - registrationStartMs;
    const remaining = delaySeconds * 1000L - elapsed;
    return remaining > 0 ? remaining : 0;
}

@("remainingJoinDelayMs returns 0 when no delay is configured")
unittest {
    assert(remainingJoinDelayMs(0, 1_000_000, 900_000) == 0);
}

@("remainingJoinDelayMs waits out the full window right after connect")
unittest {
    // delay 6s, connected 100ms ago → wait 5.9s
    assert(remainingJoinDelayMs(6, 900_100, 900_000) == 5_900);
}

@("remainingJoinDelayMs returns 0 once the window has elapsed")
unittest {
    assert(remainingJoinDelayMs(6, 907_000, 900_000) == 0);
    assert(remainingJoinDelayMs(6, 906_000, 900_000) == 0);
}

/// Persistent IRC client with auto-reconnect and IRCv3 support.
final class PersistentIRCClient {
    private {
        NetworkConfig      config;
        TCPConnection      connection;
        TLSStream          tlsStream;
        /// For handoff-adopted connections, we bypass vibe.d's
        /// TCPConnection entirely and use raw POSIX I/O on the
        /// transferred socket fd. When non-null, `processEvents`
        /// uses this instead of `connection`.
        AdoptedSocket      adoptedSocket;

        // Set when REGISTRATION_OVERALL_TIMEOUT_SECS elapses without 001
        // (or a fatal registration error). unix-ms of the most recent
        // timeout; 0 means registration has never timed out on this
        // network in this engine process. Surfaced to the admin API as
        // "networksAwaitingRegistration" so operators can see exactly
        // which networks are stuck in 'connecting' because of registration
        // timeouts (vs. slow DNS).
        long                registrationTimeoutSince;
        Channel!IRCRawEvent eventChannel;
        ExponentialBackoff  backoff;
        ConnectionState     state;
        bool                isShutdownRequested;
        // W1-T01: structured retry-status fields surfaced by the
        // engine at every reconnect-loop cycle (connection.d around
        // line 1595) AND cleared (set to 0) at every `backoff.reset()`
        // site so the frontend's `applyRetryStatus(networkId, null)`
        // fires and clears `net.failInfo` per plan B3. Read via the
        // `getRetryStatus()` getter; the snapshot writer in
        // engine/state.d populates `snap.retryStatus` from this
        // struct.
        int                 attemptCount;
        long                nextRetryAtMs;
        // W1-T01-rev1: persisted current-retry delay so the snapshot
        // and WS sync payload surface `delayMs > 0` during an active
        // backoff. The live countdown is still derived from
        // `nextRetryAtMs - now`; this field carries the schedule's
        // nominal delay (set at every backoff-delay calculation site,
        // and cleared at every backoff.reset() site by
        // emitZeroRetryStatus so a successful reconnect emits
        // `{attemptCount: 0, nextRetryAtMs: 0, delayMs: 0}`).
        long                activeRetryDelayMs;
        // W1-T01: structured fail-info snapshot field. Stored as a
        // `FailInfo` (private to connection.d, package(ircfiber))
        // and read by the snapshot writer via `getLastFailInfo()`.
        // Cleared on every `backoff.reset()` site alongside
        // `attemptCount` / `nextRetryAtMs` so a successful reconnect
        // clears the disconnect copy too — see `emitZeroRetryStatus`.
        FailInfo            lastFailInfo;

        // IRC state
        string              sessionNick;
        // The nick we asked the IRC server for at the start of THIS
        // registration attempt. Differs from sessionNick only when a 433
        // collision made the server append `_` until the nick was free.
        // We only persist sessionNick when it equals requestedNick — that
        // way a transient fallback (`Zodiac__`) never becomes the new
        // "last negotiated nick" and locks the user out of their intended
        // nick (`Zodiac`) when the nick later frees up.
        string              requestedNick;
        // How many 433/432s we've hit during this registration attempt.
        // Used by the registration loop to cap the fallback chain at
        // MAX_REGISTRATION_FALLBACK_ATTEMPTS — beyond that we switch to
        // a unique random-suffix nick so the channel doesn't accumulate
        // ghost member entries (one per fallback nick per connect cycle).
        // Reset to 0 on every successful 001.
        int                 registrationFallbackAttempts;
        // True once the 001 handler has persisted the random-suffix nick
        // for this connection lifetime. Guards against re-persisting on
        // a future re-registration that lands on the same suffix (rare,
        // but the suffix was already chosen for uniqueness).
        bool                randomNickPersisted;
        bool                isAway = false;
        string              awayMessage;
        string[string]      channelState;
        string[string]      channelTopics;
        string[][string]    channelUsers;
        long[string]        lastWhoTime;  // throttle: chan→last WHO timestamp
        long                lastWhoisTime; // throttle: 1/s for WHOIS queries
        // IRCCloud-style realname cache. Populated from extended-join
        // (realname param) and RPL_WHOISUSER (311). Used to render the
        // <span class="author-realname"> next to the nick.
        string[string]      realnames;
        // IRCv3 extended-join / account-notify: nick → account name (or "*" for none)
        string[string]      accounts;
        // Ident (username) extracted from nick!user@host in JOIN/353
        string[string]      idents;
        string[]            queryBuffers;
                string              lastErrorText;
                string[]            failureReasons;
                 // Tracks when the server told us we're throttled (unix ms).
                 // While set, the reconnect delay is floored to 5 minutes.
                 long                throttledUntil;
                 string[]            outboundQueue;
         enum MAX_OUTBOUND_QUEUE = 100;
                 // Set to `true` after we emit a `cmd_dropped_no_conn`
                 // structured event for the current disconnect cycle.
                 // Reset to `false` when `attemptConnection()` succeeds
                 // and the queue starts draining. Prevents a flood of N
                 // identical logs (one per queued message) on reconnect.
                 bool                droppedNoConnWarned;

        // IRCv3 capabilities that were ACK'd by the server
        bool[string]        ackedCaps;

        // IRCv3 BATCH tracking
        string              activeBatchRef;
        string              activeBatchType;
        string              activeBatchTarget;

        // ISUPPORT features
        ServerFeatures      serverFeatures;
        /// Full ISUPPORT map (every key=value or bare flag the server sent
        /// in 005 replies, keyed upper-case). The legacy
        /// `serverFeatures` struct still mirrors the 6 most-used tokens
        /// (NETWORK, PREFIX, CHANMODES, NICKLEN, TOPICLEN, CHANLIMIT)
        /// for downstream code that pre-dates the catalog; new code
        /// should consume `isupportMap` instead so the full feature
        /// inventory (incl. ELIST, MONITOR, CHATHISTORY, MSGREFTYPES,
        /// server-specific tokens like DYNAMITE) survives to the
        /// frontend.
        string[string]      isupportMap;

        // IRCv3 labeled-response tracking.
        // Key: label value, Value: unix-ms timestamp when the PRIVMSG/NOTICE
        // was sent. Used to (a) suppress the duplicate when the labeled
        // echo arrives, and (b) TTL-stale entries that never got an echo.
        long[string]        pendingLabels;

        // Per-channel latest/earliest msgid observed. Drives CHATHISTORY
        // pagination cursors and is updated on every PRIVMSG/NOTICE we see
        // (including those arriving inside a chathistory batch).
        string[string]      channelLatestMsgid;  // keyed by lowercase channel
        string[string]      channelEarliestMsgid;

        // Pending chathistory request bookkeeping. Tracks in-flight LATEST /
        // BEFORE / AFTER / AROUND requests so we can throttle and so the
        // REST gateway can correlate which channels we still owe a fetch to.
        bool[string]        chathistoryInFlight;  // keyed by lowercase channel

        // Smart routing: Redis access for failure reporting + reassignment detection.
        RedisStorage        redis;
        /// This engine's server ID (used for failure reporting + assignment check).
        string              serverId;
        /// Last DISCONNECT reason surfaced to the UI. Mirrors the loop-local
        /// lastEmittedReason so JSON lifecycle logs (disconnected /
        /// reconnect_scheduled) can attribute the reason even after the
        /// loop-local variable goes out of scope.
        string              lastDisconnectReason;

        // ── Handoff support ───────────────────────────────────────────────────
        /// When non-zero, the connection's event loop will not perform any
        /// network I/O and will yield until this drops back to zero. Set by
        /// `pauseForHandoff()`; cleared by `resumeAfterHandoff()`. The pause
        /// is observed at the `yield()` checkpoints inside
        /// `processEvents()` so a single in-flight line is always allowed to
        /// finish before the loop stops.
        shared(int)         handoffPauseCount;
        /// When set to a non-zero timestamp (unix ms), the next time the
        /// event loop wakes up it will QUIT gracefully and close the
        /// connection. Used after a successful handoff to the new engine
        /// so the *old* engine doesn't keep the FD alive on the IRC server.
        /// The new engine has already adopted the same socket.
        shared(long)        postHandoffQuitAtMs;
        // Tracks sessionNick before an optimistic NICK update in sendRaw.
        // The NICK handler checks this to correlate the server's echo back
        // to us post-optimistic-update, since event.nick (old nick) won't
        // match sessionNick after the optimistic change.
        string              optimisticNickOld;
        // W1-T08: idle detection — last time data was received (unix secs).
        // Used by processEvents to emit synthetic "idle" events after 120s
        // of no incoming IRC traffic.
        long                lastDataReceivedSecs;
        // PONG timeout — last time a PONG was received (unix secs).
        // Used to detect half-open TCP connections where keepalive
        // PINGs go out but responses are silently dropped.
        long                lastPongReceivedSecs;
        bool                idleEmitted;
    }

    /// Creates a new persistent IRC client.
    this(NetworkConfig cfg, Channel!IRCRawEvent ch, RedisStorage redisStore = null, string sid = "") {
        this.config       = cfg;
        this.eventChannel = ch;
        this.redis        = redisStore;
        this.serverId     = sid;
        this.backoff      = new ExponentialBackoff(3.seconds, RECONNECT_MAX_DELAY_SECS.seconds);
        this.state        = ConnectionState.disconnected;
        this.sessionNick  = cfg.nick.length > 0 ? cfg.nick : "ircfiber";
        this.lastDataReceivedSecs = Clock.currTime.toUnixTime!long;
        this.lastPongReceivedSecs = Clock.currTime.toUnixTime!long;
        this.idleEmitted  = false;
        // Each registration attempt starts the fallback counter fresh —
        // a successful 001 in the previous attempt should not leak into the
        // current one (the nick counter is part of attempt-scoped state).
        this.registrationFallbackAttempts = 0;
        this.randomNickPersisted = false;
    }

    /// Starts the connection loop in a background task.
    void start() {
        // Set state immediately so any snapshot taken before the fiber runs
        // reflects the actual intent. Without this, a freshly created client
        // stays in 'disconnected' until the event loop schedules the fiber,
        // which could trick the frontend into thinking no reconnect is happening
        // (e.g. after an engine restart where state snapshots are written before
        // the connection-loop fiber gets to run).
        state = ConnectionState.connecting;

        safeFiberRun("connection_loop", config.name, {
            try {
                runConnectionLoop();
            } catch (Exception e) {
                logException("connection", e,
                    "Connection loop crashed — restarting in 5s",
                    ["network": config.name, "event": "connection_crashed"]);
                try sleep(5.seconds); catch (Exception) {}
                if (!isShutdownRequested) {
                    try {
                        runConnectionLoop();
                    } catch (Exception e2) {
                        logError("Connection loop for %s crashed again: %s", config.name, e2.msg);
                    }
                }
            }
        });

    }

    /// Stops the connection and requests shutdown. If `quitReason` is
    /// supplied (or default empty), a QUIT is sent first so the server
    /// emits a final ERROR and closes the link cleanly; otherwise the
    /// socket is closed immediately.
    void stop(string quitReason = "") {
        isShutdownRequested = true;

        if (state == ConnectionState.connected
            && (tlsStream !is null || (connection && connection.connected))) {
            try {
                 writeRaw("QUIT :" ~ quitReason);
            } catch (Exception e) {
                logWarn("Failed to send QUIT for %s: %s", config.host, e.msg);
                transportClose();
                return;
            }
            // Force-close after a short grace period if the server hasn't
            // closed the socket itself by then.
            runTask({
                try {
                    sleep(QUIT_GRACE_PERIOD_MS.msecs);
                    if (state != ConnectionState.disconnected && transportAlive) {
                        logInfo("QUIT grace period elapsed for %s; forcing close", config.host);
                        transportClose();
                    }
                } catch (Exception) {}
            });
            return;
        }

        transportClose();
    }

    // ── Handoff API (called by ConnectionManager before/after engine reload) ──

    /// Pause the event loop so the connection can be safely serialised
    /// and its FD handed off to a new engine process. Idempotent.
    /// The pause is observed at the next `yield()` inside
    /// `processEvents()`; the loop finishes its current line first, then
    /// yields until `resumeAfterHandoff()` is called.
    void pauseForHandoff() {
        import core.atomic : atomicOp, atomicLoad;
        atomicOp!"+="(handoffPauseCount, 1);
        logJsonMap("info", "handoff",
            "Handoff pause requested",
            ["network": config.name,
             "event": "handoff_prepare"]);
    }

    /// Mark this connection as handed off. The next time the event
    /// loop observes the pause release, it will send a graceful QUIT
    /// (if the transport is still writable) and close without
    /// reconnecting. This prevents the OLD engine from racing the
    /// NEW engine for the same nick on the IRC server, especially
    /// for TLS connections where the FD can't be transferred via
    /// SCM_RIGHTS and the new engine must soft-reconnect.
    void schedulePostHandoffQuit(long timestampMs) {
        import core.atomic : atomicStore;
        atomicStore(postHandoffQuitAtMs, timestampMs);
    }

    /// Synchronously send QUIT on the live transport NOW, instead of
    /// waiting for the event loop's pause release. Used by the OLD
    /// engine's `notifyHandoffComplete` for TLS records — without
    /// this, the OLD engine's QUIT is delayed until the connection
    /// loop wakes from `pauseForHandoff()`, by which time the NEW
    /// engine has already started its TLS soft-reconnect and hit
    /// 433 on the still-registered nick (falling back to `Zodiac_`,
    /// `Zodiac__`, etc.). Writing QUIT synchronously here puts it on
    /// the wire before the NEW engine even sees the handoff's DONE
    /// marker, so the IRC server frees the nick first.
    ///
    /// The flag-based path (`schedulePostHandoffQuit`) is kept as a
    /// belt-and-suspenders backup in case the synchronous write fails
    /// or the loop never resumes (e.g. fiber scheduler deadlock).
    void forcePostHandoffQuit(long timestampMs) {
        import core.atomic : atomicStore;
        atomicStore(postHandoffQuitAtMs, timestampMs);
        try {
            if (transportAlive && state == ConnectionState.connected) {
                try {
                    writeRaw("QUIT :engine-handoff");
                    logJsonMap("info", "handoff",
                        "Forced synchronous QUIT for " ~ config.name,
                        ["network": config.name,
                         "sessionNick": sessionNick,
                         "event": "post_handoff_quit_forced"]);
                } catch (Exception e) {
                    logInfo("Forced post-handoff QUIT for %s: %s", config.name, e.msg);
                }
            }
        } catch (Exception e) {
            logWarn("Forced post-handoff cleanup failed for %s: %s", config.name, e.msg);
        }
    }

    /// Inverse of `pauseForHandoff()`. When the count returns to zero
    /// the event loop resumes I/O. Idempotent.
    void resumeAfterHandoff() {
        import core.atomic : atomicOp, atomicLoad;
        const prev = atomicOp!"-="(handoffPauseCount, 1);
        if (prev < 1) {
            // Defensive: restore so we don't underflow.
            atomicOp!"+="(handoffPauseCount, 1);
            return;
        }
        if (prev - 1 == 0) {
            logJsonMap("info", "handoff",
                "Handoff pause released",
                ["network": config.name,
                 "event": "handoff_complete"]);
        }
    }

    /// Wait until the event loop has acknowledged the pause by
    /// observing the counter at a yield checkpoint. Bounded by a
    /// 2-second deadline so a stalled loop doesn't deadlock the
    /// handoff protocol.
    void waitForHandoffPause() {
        import core.atomic : atomicLoad;
        import core.time : msecs;
        const deadline = Clock.currTime.toUnixTime!long * 1000 + 2_000;
        while (Clock.currTime.toUnixTime!long * 1000 < deadline) {
            // The loop drops into `yield()` only between reads. We
            // poll the count after a short sleep. If the loop is busy
            // parsing a long line the wait will hit the deadline and
            // we'll fall back to a forced pause (the loop checks
            // `handoffPauseCount` on every yield anyway).
            sleep(20.msecs);
            // Heuristic: if the loop is reading, it'll see the count
            // and yield. We can't observe "in-yield" from here, so
            // just sleep until the deadline — by then, any in-flight
            // line will have completed (lines are bounded by 4096
            // bytes and parsed in microseconds).
            break;
        }
    }

    /// Returns the underlying TCP socket fd if the connection is
    /// plain (non-TLS). Returns -1 for TLS connections — those
    /// cannot be transferred via SCM_RIGHTS and must be soft-
    /// reconnected by the new engine.
    int rawSocketFd() {
        if (state != ConnectionState.connected) return -1;
        if (tlsStream !is null) return -1;
        return transportFd();
    }

    /// Persist the last-negotiated nick to Redis so subsequent
    /// reconnects use this value instead of the configured nick.
    /// Called on successful registration (001) and on every
    /// confirmed NICK echo from the server. The stored nick is
    /// read in the constructor via loadPersistedNick().
    private void persistNick(string nick) {
        if (redis is null) return;
        try {
            auto rdb = redis.getDb();
            rdb.set(RedisKeys.networkNick(config.id.toString()), nick);
            logDebug("Persisted nick '%s' for %s", nick, config.name);
        } catch (Exception e) {
            logWarn("Failed to persist nick '%s' for %s: %s", nick, config.name, e.msg);
        }
    }

    /// Drop the persisted-nick entry. Called when registration succeeded
    /// only after a 433 collision fallback (`requestedNick` differs from
    /// `sessionNick`). Without this, the next reconnect would re-register
    /// the fallback nick (`Zodiac__`) instead of retrying the user's
    /// intended nick (`Zodiac`) — and would persist that fallback again,
    /// making the bad nick sticky across reconnects. After clear, the
    /// next reconnect falls back to config.nick.
    private void clearPersistedNick() {
        if (redis is null) return;
        try {
            auto rdb = redis.getDb();
            rdb.del(RedisKeys.networkNick(config.id.toString()));
            logInfo("Cleared persisted nick for %s — used fallback '%s' (requested '%s')",
                config.name, sessionNick, requestedNick);
        } catch (Exception e) {
            logWarn("Failed to clear persisted nick for %s: %s", config.name, e.msg);
        }
    }

    /// Read the last-negotiated nick from Redis. Returns empty
    /// string if no persisted nick exists or Redis is unavailable.
    private string loadPersistedNick() {
        if (redis is null) return "";
        try {
            auto rdb = redis.getDb();
            auto persisted = rdb.get(RedisKeys.networkNick(config.id.toString()));
            if (persisted.length > 0) {
                logInfo("Loaded persisted nick '%s' for %s (config: '%s')", persisted, config.name, config.nick);
                return persisted;
            }
        } catch (Exception e) {
            logWarn("Failed to load persisted nick for %s: %s", config.name, e.msg);
        }
        return "";
    }

    /// Build a snapshot of every piece of per-connection in-memory
    /// state the new engine needs to seamlessly continue this
    /// connection. The returned struct is plain-old-data; no
    /// references back into this engine.
    HandoffState snapshotForHandoff() {
        import ircfiber.engine.handoff : ServerFeaturesSnapshot;
        HandoffState s;
        s.schemaTag = "IRCFv1";
        s.config = config;
        s.userId = config.id.toString(); // userId is a UUID stored alongside in mongo; client only knows networkId
        // userId is actually owned by ConnectionManager; we re-resolve
        // it from there in the new engine via Redis. Leaving "" is
        // safe: the snapshot is for *this* network only, and the new
        // engine gets userId from `connManager` when re-instantiating.
        s.userId = "";
        s.serverId = serverId;
        s.sessionNick = sessionNick;
        s.isAway = isAway;
        s.awayMessage = awayMessage;
        s.ackedCaps = getAckedCaps();
        s.queryBuffers = queryBuffers.dup;
        s.failureReasons = failureReasons.dup;
        s.outboundQueue = outboundQueue.dup;
        s.channelState = channelState.dup;
        s.channelTopics = channelTopics.dup;
        // Duplicate the associative array of user lists.
        foreach (k, v; channelUsers) s.channelUsers[k] = v.dup;
        s.realnames = realnames.dup;
        s.accounts = accounts.dup;
        s.idents = idents.dup;
        s.pendingLabels = pendingLabels.dup;
        s.channelLatestMsgid = channelLatestMsgid.dup;
        s.channelEarliestMsgid = channelEarliestMsgid.dup;
        s.chathistoryInFlight = chathistoryInFlight.dup;
        s.transportWasPlain = (tlsStream is null);
        s.wasConnected = (state == ConnectionState.connected);
        s.capturedAtMs = Clock.currTime.toUnixTime!long * 1000;
        s.serverFeatures = ServerFeaturesSnapshot(
            serverFeatures.network, serverFeatures.prefix,
            serverFeatures.chanModes, serverFeatures.maxChannels,
            serverFeatures.maxNickLen, serverFeatures.topicLen);
        // Hand off the FULL ISUPPORT map so the new engine can render
        // the categorised "Server features" panel without waiting for
        // the IRC server to re-send 005 — which it won't, since the
        // session is already registered. Without this, the panel would
        // render empty for an arbitrary interval until another 005
        // arrives (it usually never does on subsequent reconnects).
        s.isupportMap = isupportMap.dup;
        return s;
    }

    /// Adopt a connection from a handoff. Wraps the raw socket fd in
    /// an `AdoptedSocket` for raw POSIX I/O and also registers it
    /// with vibe.d's event driver via `adoptStream` so the event
    /// loop's `waitForData` works.
    void adoptAndStart(int fd, ref HandoffState s) {
        import vibe.core.core : runTask;
        import eventcore.core : eventDriver;
        import eventcore.driver : StreamSocketFD;
        import vibe.core.net : createStreamConnection;
        // Register the fd with vibe.d's event driver. This makes
        // `waitForData` (via the event loop's yield) wake up when
        // data arrives. We still use AdoptedSocket for actual
        // reads/writes because TCPConnection.connected can be
        // unreliable for externally-adopted fds.
        auto streamFd = eventDriver.sockets.adoptStream(fd);
        if (streamFd == StreamSocketFD.invalid) {
            logWarn("adoptAndStart: eventcore refused to adopt fd=%d, falling back to raw fd", fd);
        } else {
            try {
                connection = createStreamConnection(streamFd);
                logInfo("adoptAndStart: fd=%d registered with event driver", fd);
            } catch (Exception e) {
                logWarn("adoptAndStart: createStreamConnection failed for fd=%d: %s", fd, e.msg);
            }
        }
        adoptedSocket = new AdoptedSocket(fd);
        if (!adoptedSocket.connected) {
            logError("adoptAndStart: adopted socket fd=%d is not connected", fd);
            state = ConnectionState.disconnected;
            logJsonMap("error", "handoff",
                "Adopted socket not connected",
                ["network": s.config.name,
                 "fd": fd.to!string,
                 "reason": "socket_not_connected",
                 "event": "handoff_fail"]);
            return;
        }
        // Replay the snapshot. Order matters: config first (so the
        // rehydration of channels into per-channel maps uses the
        // right config), then state maps.
        config = s.config;
        sessionNick = s.sessionNick;
        isAway = s.isAway;
        awayMessage = s.awayMessage;
        foreach (cap; s.ackedCaps) ackedCaps[cap] = true;
        queryBuffers = s.queryBuffers.dup;
        failureReasons = s.failureReasons.dup;
        outboundQueue = s.outboundQueue.dup;
        channelState = s.channelState.dup;
        channelTopics = s.channelTopics.dup;
        foreach (k, v; s.channelUsers) channelUsers[k] = v.dup;
        realnames = s.realnames.dup;
        pendingLabels = s.pendingLabels.dup;
        channelLatestMsgid = s.channelLatestMsgid.dup;
        channelEarliestMsgid = s.channelEarliestMsgid.dup;
        chathistoryInFlight = s.chathistoryInFlight.dup;
        serverFeatures.network = s.serverFeatures.network;
        serverFeatures.prefix = s.serverFeatures.prefix;
        serverFeatures.chanModes = s.serverFeatures.chanModes;
        serverFeatures.maxChannels = s.serverFeatures.maxChannels;
        serverFeatures.maxNickLen = s.serverFeatures.maxNickLen;
        serverFeatures.topicLen = s.serverFeatures.topicLen;
        // Inherit the full ISUPPORT map so the categorised "Server
        // features" panel renders correctly on the new engine without
        // waiting for a fresh 005 reply stream (which won't come —
        // the IRC server's registration already completed upstream).
        isupportMap = s.isupportMap.dup;
        // Resume the loop without going through the full registration
        // dance: the socket is already authenticated upstream.
        state = ConnectionState.connected;
        backoff.reset();
        throttledUntil = 0;
        // W1-T01 (plan B3): zero-valued CONNECTION_RETRY_STATUS emit at
        // every backoff.reset() site so the frontend's
        // applyRetryStatus(networkId, null) clears both net.retryStatus
        // AND net.failInfo. Without this the banner would keep showing
        // a stale "Disconnected: ..." text after a successful reconnect.
        emitZeroRetryStatus();
        logInfo("Adopted live connection for %s (fd=%d, %d joined channels, %d acked caps)",
            config.host, fd, channelState.length, ackedCaps.length);
        logJsonMap("info", "handoff",
            "Adopted live socket",
            ["network": config.name,
             "fd": fd.to!string,
             "channels": channelState.length.to!string,
             "caps": ackedCaps.length.to!string,
             "event": "adopted_socket"]);
        try eventChannel.put(IRCRawEvent.makeConnected(config.name, config.id.toString()));
        catch (Exception e) logWarn("handoff: failed to publish CONNECTED: %s", e.msg);
        // Spawn the resumed event loop. We use a separate code path
        // (`runAdoptedLoop`) so we can skip registration cleanly.
        // Wrapped in `taskNothrow` so the loop can throw freely while
        // still satisfying vibe-core 2.14's nothrow callback contract.
        safeFiberRun("adopted_loop", config.name, {
            try {
                runAdoptedLoop();
            } catch (Exception e) {
                logException("connection", e,
                    "Adopted connection crashed",
                    ["network": config.name, "host": config.host,
                     "event": "adopted_crash"]);
                state = ConnectionState.disconnected;
                try eventChannel.put(IRCRawEvent.makeDisconnected(config.name, config.id.toString(), e.msg));
                catch (Exception) {}
            }
        });

    }

    /// Resumed event loop for an adopted connection. Same as
    /// `processEvents()` but skips `processOutboundQueue()` for the
    /// first iteration (the queue was already drained before
    /// handoff; if anything was queued during the handoff window the
    /// new engine's queue is already populated).
    private void runAdoptedLoop() {
        processEvents();
    }

    /// Adopt a connection that survived an exec(2) reload. The TCP
    /// file descriptor is reused; for TLS, a fresh TLS handshake is
    /// performed on the SAME TCP socket so the IRC server's IRC
    /// layer (above TLS) sees no change — the IRC session continues
    /// uninterrupted.
    ///
    /// This is the post-exec-restart entry point. The new engine
    /// calls this once per IRC network after reading the checkpoint
    /// file written by the old engine.
    void adoptExecSocket(int fd, ref HandoffState s) {
        import vibe.core.core : runTask;
        import eventcore.core : eventDriver;
        import eventcore.driver : StreamSocketFD;
        import vibe.core.net : createStreamConnection;
        import core.time : seconds;

        logInfo("adoptExecSocket: %s fd=%d wasTls=%s",
            s.config.name, fd, !s.transportWasPlain);

        // 1. Adopt the FD into vibe.d's event driver. Same as
        // `adoptAndStart` — we get a `connection` field that the rest
        // of the engine uses for non-blocking I/O.
        auto streamFd = eventDriver.sockets.adoptStream(fd);
        if (streamFd == StreamSocketFD.invalid) {
            logError("adoptExecSocket: eventcore refused to adopt fd=%d — falling back to AdoptedSocket", fd);
        } else {
            try {
                connection = createStreamConnection(streamFd);
                logInfo("adoptExecSocket: fd=%d registered with event driver", fd);
            } catch (Exception e) {
                logException("connection", e,
                    "adoptExecSocket: createStreamConnection failed",
                    ["fd": fd.to!string, "network": config.name,
                     "event": "adopt_stream_fail"]);
            }
        }
        // Always also keep a raw POSIX wrapper as fallback. This lets
        // us read/write even if vibe.d's TCPConnection gets into a bad
        // state (which can happen with externally-adopted FDs).
        adoptedSocket = new AdoptedSocket(fd);
        if (!adoptedSocket.connected) {
            logError("adoptExecSocket: adopted socket fd=%d is not connected — aborting", fd);
            state = ConnectionState.disconnected;
            return;
        }

        // 2. If the connection was TLS, do a fresh handshake on the
        // SAME TCP socket. The IRC server's TLS layer re-authenticates,
        // but its IRC layer (above TLS) doesn't notice — IRC sessions
        // are keyed to the TCP 4-tuple, not the TLS identity.
        if (!s.transportWasPlain) {
            logInfo("adoptExecSocket: %s was TLS — doing fresh TLS handshake on existing TCP", s.config.name);
            try {
                auto ctx = createTLSContext(TLSContextKind.client);
                ctx.peerValidationMode = TLSPeerValidationMode.none;
                tlsStream = createTLSStreamWithTimeout(connection, ctx, stripHostBrackets(config.host),
                    TLS_HANDSHAKE_TIMEOUT_SECONDS.seconds);
                logInfo("adoptExecSocket: TLS handshake complete for %s on existing TCP", s.config.name);
            } catch (Exception e) {
                logError("adoptExecSocket: TLS handshake failed for %s on existing TCP: %s"
                    ~ " — falling back to AdoptedSocket only",
                    s.config.name, e.msg);
                // Don't bail — we still have the raw TCP socket via
                // adoptedSocket. The new engine can continue using it
                // for plain-text IRC, but the IRC server will likely
                // disconnect because it expects TLS. Mark for reconnect.
                tlsStream = null;
                state = ConnectionState.disconnected;
                try eventChannel.put(IRCRawEvent.makeDisconnected(
                    config.name, config.id.toString(),
                    "TLS re-handshake failed after exec reload"));
                catch (Exception) {}
                return;
            }
        }

        // 3. Restore the in-memory state from the snapshot. Same as
        // `adoptAndStart` — config first, then state maps.
        config = s.config;
        sessionNick = s.sessionNick;
        isAway = s.isAway;
        awayMessage = s.awayMessage;
        foreach (cap; s.ackedCaps) ackedCaps[cap] = true;
        queryBuffers = s.queryBuffers.dup;
        channelState = s.channelState.dup;
        channelTopics = s.channelTopics.dup;
        foreach (k, v; s.channelUsers) channelUsers[k] = v.dup;
        realnames = s.realnames.dup;
        pendingLabels = s.pendingLabels.dup;
        channelLatestMsgid = s.channelLatestMsgid.dup;
        channelEarliestMsgid = s.channelEarliestMsgid.dup;
        chathistoryInFlight = s.chathistoryInFlight.dup;
        serverFeatures.network = s.serverFeatures.network;
        serverFeatures.prefix = s.serverFeatures.prefix;
        serverFeatures.chanModes = s.serverFeatures.chanModes;
        serverFeatures.maxChannels = s.serverFeatures.maxChannels;
        serverFeatures.maxNickLen = s.serverFeatures.maxNickLen;
        serverFeatures.topicLen = s.serverFeatures.topicLen;
        // Carry the full ISUPPORT map forward so the categorised panel
        // renders without waiting for a redundant 005 reply stream.
        isupportMap = s.isupportMap.dup;

        // 4. Mark connected and reset backoff. We DO NOT re-register
        // with the IRC server (NICK, USER, CAP, SASL, JOIN) — the
        // session is already active on the IRC side because the TCP
        // connection never closed. The new engine just resumes
        // reading/writing IRC traffic.
        state = ConnectionState.connected;
        backoff.reset();
        throttledUntil = 0;
        // W1-T01 (plan B3): see adoptAndStart above — same zero-valued
        // CONNECTION_RETRY_STATUS emit so the frontend clears its
        // stale failInfo / retryStatus on this successful reconnect.
        emitZeroRetryStatus();
        logInfo("adoptExecSocket: %s ready (fd=%d, %d joined channels, %d acked caps)",
            config.host, fd, channelState.length, ackedCaps.length);
        try eventChannel.put(IRCRawEvent.makeConnected(config.name, config.id.toString()));
        catch (Exception e) logWarn("adoptExecSocket: failed to publish CONNECTED: %s", e.msg);

        // 5. After a moment, send a CAP LS to refresh the cap list
        // and verify the IRC session is alive. This is purely a
        // sanity check — the server may reply with our already-acked
        // caps, which we just acknowledge and discard.
        safeFiberRun("post_adopt_cap_ls", config.name, {
            try {
                sleep(500.msecs);
                if (state == ConnectionState.connected) {
                    sendRaw("CAP LS 302");
                    logInfo("adoptExecSocket: sent CAP LS to refresh state for %s", config.name);
                }
            } catch (Exception e) {
                logWarn("adoptExecSocket: post-adopt CAP LS failed: %s", e.msg);
            }
        });

        // 6. Spawn the resumed event loop.
        safeFiberRun("adopted_exec_loop", config.name, {
            try {
                runAdoptedLoop();
            } catch (Exception e) {
                logException("connection", e,
                    "Adopted-exec connection crashed",
                    ["network": config.name, "host": config.host,
                     "event": "adopted_exec_crash"]);
                state = ConnectionState.disconnected;
                try eventChannel.put(IRCRawEvent.makeDisconnected(
                    config.name, config.id.toString(), e.msg));
                catch (Exception) {}
            }
        });

    }

    @property bool            getConnected()     const { return state == ConnectionState.connected; }
    @property ConnectionState getState()         const { return state; }
    @property string          getCurrentNick()   const { return sessionNick; }
    @property bool            getIsAway()        const { return isAway; }

    /// Unix-ms timestamp of the most recent registration timeout for
    /// this network (REGISTRATION_OVERALL_TIMEOUT_SECS exceeded without
    /// 001). 0 when the network has never timed out. Read-only. Used by
    /// `ConnectionManager.networksAwaitingRegistration()` so the admin
    /// SPA can show "this network is stuck in registration" with the
    /// actual reason and elapsed duration, rather than just "Connecting..."
    /// forever.
    @property long getRegistrationTimeoutSince() const { return registrationTimeoutSince; }

    /// Read-only accessor for the IRC network config (host, port, name).
    /// Used by the admin API to render per-network state without
    /// duplicating the fields elsewhere.
    @property inout(NetworkConfig) getConfig() inout { return config; }

    /// Whether the underlying transport is alive, regardless of
    /// whether it wraps a vibe.d TCPConnection or an adopted socket.
    @property bool transportAlive() const {
        if (adoptedSocket !is null) return adoptedSocket.connected;
        return connection.connected;
    }

    /// Read from the transport. For adopted sockets, uses direct
    /// POSIX read(); for normal connections, delegates to vibe.d.
    size_t transportRead(ubyte[] buf) {
        if (adoptedSocket !is null) return adoptedSocket.read(buf);
        if (!connection.waitForData(0.seconds)) return 0;
        return connection.read(buf, IOMode.once);
    }

    /// Write a line to the transport, appending CRLF.
    void transportWrite(const(char)[] line) {
        if (adoptedSocket !is null) {
            adoptedSocket.write(cast(const(ubyte)[]) (line ~ "\r\n"));
        } else if (connection.connected) {
            connection.write((line ~ "\r\n").dup);
            connection.flush();
        }
    }

    /// Close the transport. Idempotent.
    void transportClose() {
        if (adoptedSocket !is null) {
            adoptedSocket.close();
            adoptedSocket = null;
        }
        if (connection.connected) connection.close();
    }

    /// Underlying fd, for snapshot.
    int transportFd() const {
        if (adoptedSocket !is null) return adoptedSocket.fd;
        return cast(int) connection.fd;
    }


    @property string          getAwayMessage()   const { return awayMessage; }
    @property string[]        getJoinedChannels()      { return channelState.keys.dup; }
    @property string[string]  getChannelTopics()       { return channelTopics; }
    @property string[][string] getChannelUsers()       { return channelUsers; }
    @property string[string]  getRealnames()          { return realnames; }
    @property string[string]  getAccounts()           { return accounts; }
    @property string[string]  getIdents()             { return idents; }
    @property string[]        getQueryBuffers()         { return queryBuffers.dup; }
    @property ServerFeatures  getServerFeatures()      { return serverFeatures; }

    /// Returns a copy of the FULL ISUPPORT map (every key=value or
    /// bare flag from the server's 005 replies, keyed upper-case).
    /// This is the canonical feature inventory the frontend renders
    /// in its categorised "Server features" panel — the legacy
    /// `getServerFeatures` struct only carries the 6 most-consumed
    /// tokens for backward compatibility with code written before the
    /// catalog was added.
    @property string[string] getIsupport()            { return isupportMap.dup; }

    /// W1-T01: 1-based reconnect attempt number. 0 before the first
    /// `backoff.nextDelay()` call and after a successful `backoff.reset()`.
    /// Mirrors `ExponentialBackoff.currentAttempt()` so the frontend
    /// renders the ordinal "Nth attempt" label without depending on
    /// the backoff internals. Read by the snapshot writer
    /// (engine/state.d) and the WS sync payload (api/websocket.d).
    @property int getAttemptCount() const              { return attemptCount; }

    /// W1-T01: unix-ms of the most recent scheduled reconnect
    /// attempt. 0 when no retry is pending (i.e. connected, freshly
    /// reset, or never cycled). The frontend renders the 1s countdown
    /// from this field via `Math.max(0, nextRetryAtMs - Date.now())`.
    @property long getNextRetryAtMs() const            { return nextRetryAtMs; }

    /// W1-T01-rev1: read-only accessor returning the wire-shape retry
    /// status. Returns a populated `Nullable!RetryStatus` while a
    /// backoff is scheduled (so the snapshot writer can persist the
    /// real `delayMs`), and a null `Nullable!RetryStatus` when the
    /// network is healthy / freshly reset. Callers (state.d heartbeat
    /// writer, websocket.d sync, processor.d immediate-write path)
    /// check `isNull` and skip emission when null so the wire shape
    /// carries an absent `retryStatus` rather than a zero-valued one
    /// (the previous all-zero default made `delayMs > 0` unreachable
    /// from the heartbeat snapshot, which broke the closed-port
    /// smoke assertion — see review-wave1 HIGH 1).
    @property Nullable!RetryStatus getRetryStatus() const {
        if (attemptCount == 0 && nextRetryAtMs == 0) {
            return Nullable!RetryStatus();
        }
        return Nullable!RetryStatus(
            RetryStatus(attemptCount, nextRetryAtMs, activeRetryDelayMs));
    }

    /// W1-T01: read-only accessor returning the most recent FailInfo
    /// for the current disconnect cycle. The snapshot writer mirrors
    /// this onto `snap.failInfo` so the WS sync payload ships a
    /// structured failInfo to fresh clients (the in-memory store also
    /// receives the same data via the CONNECTION_FAIL event for
    /// already-connected sessions). Empty struct when the network is
    /// healthy.
    @property FailInfo getLastFailInfo() const {
        return lastFailInfo;
    }

    /// Whether a given IRCv3 capability was negotiated.
    bool hasCap(string cap) const { return (cap in ackedCaps) !is null && ackedCaps[cap]; }

    /// Returns all negotiated capabilities.
    string[] getAckedCaps() const {
        string[] result;
        foreach (cap, acked; ackedCaps) {
            if (acked) result ~= cap;
        }
        return result;
    }

    /// Updates the network configuration.
    void updateConfig(NetworkConfig cfg) { config = cfg; }

    // ── Connection loop ───────────────────────────────────────────────────────

    /// Runs the full connect / IRC-protocol / disconnect loop until
    /// `isShutdownRequested` becomes true. Package-visible so the
    /// `start()` worker task and any test harness can invoke it;
    /// callers must still set initial state via `start()`.
    package void runConnectionLoop() {
        bool wasEverConnected    = false;
        // Last reason we surfaced to the UI. We re-emit a DISCONNECT event
        // whenever the reason changes so persistently-failing connections
        // (e.g. TLS handshake reset) don't loop silently — but identical,
        // repeating errors are deduped via failureReasons + buildFailureSummary
        // on the next successful connect.
        string lastEmittedReason;

        // Bug 3 fix (Jul 8 2026): the engine previously ignored
        // `config.disabled` once the network was already loaded. An admin
        // disconnect call would set the flag in MongoDB and send a
        // `disconnectNetwork` control message, but on the next reconnect
        // window the engine would start a new connect attempt — SuperNets
        // sat in this loop for hours. The flag is now consulted at the
        // top of every iteration: if the network is administratively
        // disabled, the loop idles (with a 5s poll so we re-check the
        // flag without burning CPU) until either the admin re-enables it
        // (next reconnectNetwork control message removes the network and
        // re-adds it) or shutdown is requested.
        if (config.disabled) {
            logInfo("runConnectionLoop[%s]: network is administratively disabled — idling until re-enabled or shutdown",
                config.name);
            emitLog("disabled",
                "Network disabled by admin — connection loop idling. " ~
                "Re-enable via the admin panel or `reconnectNetwork` control message.");
            try eventChannel.put(IRCRawEvent.makeDisconnected(config.name, config.id.toString,
                "Network disabled by admin"));
            catch (Exception) {}
            while (!isShutdownRequested && config.disabled) {
                sleep(5.seconds);
            }
            if (isShutdownRequested) return;
            logInfo("runConnectionLoop[%s]: network re-enabled — resuming connection loop", config.name);
        }

        while (!isShutdownRequested) {
            try {
                if (!getConnected) {
                    attemptConnection();

                    // If stop() was called while we were connecting, close the
                    // fresh socket right away and exit the loop — otherwise the
                    // IRC server ends up with a zombie connection from us.
                    if (isShutdownRequested) {
                        transportClose();
                        break;
                    }

                    wasEverConnected = true;
                    lastEmittedReason = "";
                    lastDisconnectReason = "";

                    if (failureReasons.length > 0) {
                        auto summaryEvt          = IRCRawEvent(config.name, "CONNECT");
                        summaryEvt.networkId     = config.id.toString();
                        summaryEvt.text          = buildFailureSummary(failureReasons);
                        eventChannel.put(summaryEvt);
                        failureReasons = [];
                    }
                }
                processEvents();
                // Enterprise belt-and-suspenders: after processEvents returns,
                // check postHandoffQuitAtMs again.  If the early check inside
                // processEvents was somehow missed (e.g. the connection state
                // loop exited before reaching it), we catch it here and prevent
                // a reconnection cycle that would collide with the new engine.
                import core.atomic : atomicLoad;
                if (atomicLoad(postHandoffQuitAtMs) > 0) {
                    logInfo("Post-handoff: %s - hard fallback triggered", config.name);
                    isShutdownRequested = true;
                    try transportClose(); catch (Exception) {}
                    break;
                }
            } catch (Exception e) {
                // Downgraded from logException(error) with hex stack spam.
                // `transport not alive` and `Registration timed out` are expected
                // during normal reconnect (gangnet every 5s) — not `error`.
                // Use warn without stack to avoid SigNoz `has_error` flood and
                // useless `??:? [0x...]` addresses.
                logJsonMap("warn", "connection",
                    "Connection error",
                    ["network": config.name, "host": config.host,
                     "err": e.msg,
                     "event": "connection_error"]);
                // Save the disconnect reason BEFORE handleDisconnection so
                // it emits the DISCONNECTED event with the right text.
                string reason = e.msg.length > 0 ? e.msg : "Connection closed unexpectedly";
                if (reason == "Peer closed connection" || reason == "Connection lost"
                    || reason == "Server closed during registration") {
                    reason = "Connection closed unexpectedly";
                }
                if (!wasEverConnected) reason = "Failed to connect: " ~ reason;

                string displayReason = reason;
                if (lastErrorText.length > 0) {
                    const extracted = extractQuitReason(lastErrorText);
                    if (extracted.length > 0) displayReason = extracted;
                }
                if (displayReason != lastEmittedReason) {
                    lastEmittedReason = displayReason;
                    lastDisconnectReason = displayReason;
                }

                // handleDisconnection now emits the DISCONNECTED lifecycle
                // event so the frontend sees the state transition for ALL
                // disconnect paths (data-loss, PONG timeout, server ERROR,
                // squashed ERROR, etc.). The emitLog("error") + DISCONNECT
                // previously done here are removed — they're superseded by
                // the centralized event in handleDisconnection().
                handleDisconnection();

                if (isShutdownRequested) break;

                failureReasons ~= reason;
                lastErrorText = "";

                // Report the failure to Redis for smart routing (per-network failover).
                // The gateway's health monitor checks this and may reassign the network
                // to a different engine if failures exceed the threshold.
                if (redis !is null && serverId.length > 0 && !wasEverConnected) {
                    try {
                        auto rdb = redis.getDb();
                        auto failKey = RedisKeys.networkFail(config.id.toString());
                        auto now = Clock.currTime.toUnixTime!long * 1000;
                        rdb.hincr(failKey, "count", 1);
                        rdb.hset(failKey, "serverId", serverId);
                        rdb.hset(failKey, "error", reason);
                        rdb.hset(failKey, "lastFailure", now.to!string);
                        logInfo("Reported connection failure for %s to smart routing", config.name);
                    } catch (Exception) {}
                }
            }

            if (isShutdownRequested) break;
            if (!shouldReconnect) break;

            // Smart routing: check if this network was reassigned to another engine.
            // If so, stop retrying and let the new engine handle it.
            if (redis !is null && serverId.length > 0) {
                try {
                    auto assignedSid = redis.getDb().hget(RedisKeys.networkAssignments(), config.id.toString());
                    if (assignedSid.length > 0 && assignedSid != serverId) {
                        logInfo("Network %s reassigned to server %s — stopping retry loop",
                            config.name, assignedSid);
                        break;
                    }
                } catch (Exception) {}
            }

            // If the server throttled or banned us, wait out the window
            // BEFORE computing the exponential backoff. Previously this
            // sleep happened with state==disconnected and no retryStatus,
            // so the UI showed a frozen "Disconnected:" banner for up to
            // 5 min (throttle) or 30 min (ZLINE ban) with no countdown.
            // Now we surface the same waiting_to_retry + queued line that
            // the normal backoff path uses, so the banner shows
            // "Reconnecting in 300s (Nth attempt)" and the user can
            // still hit "Reconnect" to bypass via /reconnect.
            if (throttledUntil > 0) {
                const now = Clock.currTime.toUnixTime!long * 1000;
                if (now < throttledUntil) {
                    auto remaining = throttledUntil - now;
                    logWarn("Server throttled/banned, waiting %s before retrying %s", remaining.msecs, config.host);
                    // Surface as retry so the frontend doesn't freeze.
                    state = ConnectionState.waiting_to_retry;
                    // Use the next attempt number for the countdown label.
                    // backoff.currentAttempt() is 0 before the first
                    // nextDelay(), so bump to 1 for the first visible try.
                    int displayAttempt = backoff.currentAttempt();
                    if (displayAttempt == 0) displayAttempt = 1;
                    attemptCount = displayAttempt;
                    nextRetryAtMs = throttledUntil;
                    activeRetryDelayMs = remaining;
                    emitLog("queued",
                        "Server " ~ (isBanError(lastEmittedReason) ? "ban" : "throttle")
                        ~ " window active — retry in "
                        ~ (remaining / 1000).to!string ~ "s.");
                    try eventChannel.put(IRCRawEvent.makeConnectionRetryStatus(
                        config.name, config.id.toString(),
                        attemptCount, nextRetryAtMs, activeRetryDelayMs));
                    catch (Exception e) logWarn("Failed to publish throttled retry status: %s", e.msg);
                    // Chunked sleep so stop() / isShutdownRequested is
                    // honoured within 1s and the countdown stays live.
                    const deadline = Clock.currTime + remaining.msecs;
                    while (Clock.currTime < deadline) {
                        if (isShutdownRequested) break;
                        sleep(1.seconds);
                    }
                    if (isShutdownRequested) {
                        throttledUntil = 0;
                        break;
                    }
                }
                throttledUntil = 0;
            }

            // Ghost / Overridden backoff: when the server closes the
            // connection because a previous session for our nick is
            // still active (e.g. supernets.org with UnrealIRCd's
            // "Overridden" ghost protection), normal 15-30s reconnect
            // intervals hit the same wall. The ghost timeout on
            // UnrealIRCd is ~30-60s, so we apply a 10s floor and reset
            // the exponential backoff so the next attempt starts fresh.
            //
            // This addresses the "supernets requires a second
            // connection with a delay between" pattern that produced
            // an indefinite 15s-18s reconnect cycle on the OVH
            // deployment on 2026-07-02.
            if (lastEmittedReason.canFind("Overridden")
                || lastEmittedReason.canFind("ERR_NICKNAMEINUSE")
                || lastEmittedReason.canFind("welcome_timeout")
                || lastEmittedReason.canFind("tls_read_error_post_001")) {
                logWarn("Ghost failure detected for %s — retrying in 10s (previous session still active)",
                    config.name);
                emitLog("warn",
                    "Previous session still active (ghost) — retrying in 10s.");
                sleep(10.seconds);
                backoff.reset();
                // W1-T01-rev1: every backoff.reset() site now emits a
                // zero-valued CONNECTION_RETRY_STATUS so the frontend's
                // applyRetryStatus(networkId, null) clears the stale
                // banner. This is the 4th such site (was missed in the
                // original wave 1 commit — review-wave1 MEDIUM
                // finding). The retry status the next attempt emits
                // will repopulate the banner with the fresh schedule.
                emitZeroRetryStatus();
            }

            auto delay = backoff.nextDelay();

            // Per-host circuit breaker: after N consecutive failures to the
            // same host, extend the delay to the remaining cooldown so we
            // don't keep hammering a server that's clearly rejecting us.
            auto hostKey = config.host ~ ":" ~ config.port.to!string;
            if (auto breaker = hostKey in _hostBreakers) {
                if (breaker.openedAt > 0) {
                    const now = Clock.currTime.toUnixTime!long * 1000;
                    const elapsed = now - breaker.openedAt;
                    if (elapsed < HOST_COOLDOWN_MS) {
                        auto remaining = HOST_COOLDOWN_MS - elapsed;
                        const remainingDur = dur!"msecs"(remaining);
                        if (remainingDur > delay) {
                            delay = remainingDur;
                            logWarn("Host circuit breaker active for %s — extending delay to %s",
                                hostKey, delay);
                        }
                    } else {
                        // Cooldown expired — close the circuit
                        _hostBreakers.remove(hostKey);
                        logInfo("Host circuit breaker reset for %s (cooldown expired)", hostKey);
                    }
                }
            }

            // 2026-07-08: per-host minimum delay to prevent pile-up.
            // When 5 networks on the same host reconnect simultaneously
            // (e.g. after a shared upstream reset), all 5 hit the
            // same host at the same instant. Backoff already has ±25%
            // jitter, but a fresh 5s minimum gives the host time to
            // recover between attempts when multiple networks are
            // reconnecting.
            enum MIN_RECONNECT_DELAY_MS = 5_000;
            if (delay.total!"msecs" < MIN_RECONNECT_DELAY_MS) {
                delay = dur!"msecs"(MIN_RECONNECT_DELAY_MS);
            }

            logInfo("Reconnecting to %s in %s", config.host, delay);
            logJsonMap("info", "connection",
                "Reconnect scheduled",
                ["network": config.name,
                 "host": config.host, "port": config.port.to!string,
                 "delayMs": delay.total!"msecs".to!string,
                 "attempt": backoff.currentAttempt().to!string,
                 "reason": lastEmittedReason.length > 0 ? lastEmittedReason : "connection_lost",
                 "event": "reconnect_scheduled"]);
            recordCounter("ircfiber.reconnect.scheduled", 1,
                ["network": config.name, "host": config.host,
                 "port": config.port.to!string,
                 "reason": lastEmittedReason.length > 0 ? lastEmittedReason : "connection_lost"]);
            // W1-T01 (plan B1): set state to `waiting_to_retry` for the
            // duration of the backoff sleep so the frontend's
            // "Reconnecting in {N}s ({Nth} attempt)" banner branch
            // (already wired in types.ts:19) is reachable. The state
            // flips back to `connecting` in `attemptConnectionImpl`
            // when the sleep exits and `attemptConnection()` runs.
            state = ConnectionState.waiting_to_retry;
            // W1-T01: compute the structured retry-state up front so the
            // both the legacy "queued" server-log line and the
            // CONNECTION_RETRY_STATUS event see the same numbers.
            attemptCount         = backoff.currentAttempt();
            const delayMs        = cast(long) delay.total!"msecs";
            nextRetryAtMs        = Clock.currTime.toUnixTime!long * 1000 + delayMs;
            // W1-T01-rev1: persist the real schedule delay so the
            // snapshot writer's getRetryStatus() surfaces `delayMs > 0`
            // during the active backoff window. Cleared by
            // emitZeroRetryStatus() on every backoff.reset() site.
            activeRetryDelayMs   = delayMs;
            // Reset the PONG/data timestamp so the new connection attempt
            // gets a fresh 300s grace period. Without this, a stale
            // `lastPongReceivedSecs` from a previous successful
            // connection (or the engine-start time) makes the
            // 5-minute PONG timeout fire immediately on the first
            // no-data iteration of the new attempt, producing a
            // death loop where the engine reconnects and trips the
            // PONG timeout without giving the new connection a
            // chance to send or receive any traffic.
            lastPongReceivedSecs = Clock.currTime.toUnixTime!long;
            lastDataReceivedSecs = Clock.currTime.toUnixTime!long;
            // W1-T01-rev1: ordering — emit the user-visible queued log
            // line FIRST so it lands in the chat timestamped before the
            // structured retry event (per plan W1-T01 ordering
            // requirement; the previous order had CONNECTION_RETRY_STATUS
            // first, which logged the structured event before the user
            // saw the matching "Reconnect scheduled in Ns" line in the
            // `_server` buffer).
            emitLog("queued",
                "Reconnect attempt scheduled in "
                ~ (delay.total!"seconds" < 1 ? "<1s"
                    : (delay.total!"seconds").to!string ~ "s")
                ~ " (exponential backoff).");
            try eventChannel.put(IRCRawEvent.makeConnectionRetryStatus(
                config.name, config.id.toString(),
                attemptCount, nextRetryAtMs, delayMs));
            catch (Exception e) logWarn("Failed to publish CONNECTION_RETRY_STATUS for %s: %s",
                config.name, e.msg);
            // Sleep in 1s chunks so a concurrent stop() (isShutdownRequested)
            // is honoured within ~1s instead of waiting for the full delay.
            // This lets the user cancel a pending reconnect almost instantly.
            const deadline = Clock.currTime + delay;
            while (Clock.currTime < deadline) {
                if (isShutdownRequested) break;
                sleep(1.seconds);
            }
        }

        // DISCONNECT lifecycle event is now emitted by
        // handleDisconnection() (called via cleanup() below), which
        // covers ALL disconnect paths.  The per-path emitLog("error") +
        // DISCONNECT that was previously duplicated in the catch block
        // and the exit block have been centralized there.
        // Handoff suppression is gated inside handleDisconnection() by
        // postHandoffQuitAtMs == 0.
        cleanup();
        // If this engine was handed off (postHandoffQuitAtMs was set),
        // and we're not PID 1 (the container init process), exit cleanly
        // to free resources.  PID 1 must stay alive to keep the container
        // running; it will just spin the event loop with no connections.
        import core.atomic : atomicLoad;
        if (getpid() != 1 && atomicLoad(postHandoffQuitAtMs) > 0) {
            logInfo("Post-handoff: exiting old engine process (pid=%d)", getpid());
            import core.stdc.stdlib : exit;
            exit(0);
        }
    }

    // ── Connection attempt ────────────────────────────────────────────────────

    /// Emit a tagged server-log entry into the event channel so the
    /// frontend's `_server` buffer mirrors every phase of the connect.
    /// Failures are swallowed (eventChannel.put can throw if the channel
    /// is closed during shutdown) so the connection attempt itself is
    /// never blocked by a logging error.
    private void emitLog(string phase, string text) nothrow {
        try {
            auto evt = IRCRawEvent.makeServerLog(config.name, config.id.toString(), phase, text);
            eventChannel.put(evt);
        } catch (Exception e) {
            try logWarn("Failed to emit server-log phase=%s for %s: %s", phase, config.name, e.msg);
            catch (Exception) {}
        }
    }

    /// W1-T01 (plan B3): emit a zero-valued CONNECTION_RETRY_STATUS
    /// event AND clear the in-memory retry state. Called at every
    /// `backoff.reset()` site (registration success, handoff adoption,
    /// exec-reload adoption, fail-cycle success). The frontend's
    /// `applyRetryStatus(networkId, null)` on receipt of this event
    /// clears BOTH `net.retryStatus` AND `net.failInfo` so the banner
    /// doesn't keep showing "Reconnecting..." / "Disconnected: ...".
    private void emitZeroRetryStatus() nothrow {
        attemptCount         = 0;
        nextRetryAtMs        = 0;
        // W1-T01-rev1: also clear the persisted active delay so the
        // nullable getRetryStatus() collapses to null and the snapshot
        // / WS sync payload stops emitting retryStatus until the next
        // backoff fires. Without this, a freshly-reset client's
        // Nullable still surfaces the previous attempt's delay.
        activeRetryDelayMs   = 0;
        // B3: clear the snapshot-side failInfo too, otherwise the WS
        // sync payload keeps shipping the previous disconnect's
        // failInfo to fresh clients even after a successful reconnect.
        lastFailInfo         = FailInfo.init;
        try {
            auto evt = IRCRawEvent.makeConnectionRetryStatus(
                config.name, config.id.toString(), 0, 0L, 0L);
            eventChannel.put(evt);
        } catch (Exception e) {
            try logWarn("Failed to publish zero CONNECTION_RETRY_STATUS for %s: %s",
                config.name, e.msg);
            catch (Exception) {}
        }
    }

    /// W1-T01: build a structured FailInfo from a disconnect reason
    /// string + the engine's `lastErrorText` and publish a
    /// `CONNECTION_FAIL` event. Called from `handleDisconnection()`
    /// (centralised site — covers the catch block, post-handoff exits,
    /// data-loss detection, and server-error paths). Failures during
    /// the put are swallowed so they don't mask the existing
    /// DISCONNECTED lifecycle event. Also stashes the FailInfo on
    /// the client so the snapshot writer (`engine/state.d`) can ship
    /// it to fresh WS clients via the sync payload.
    private void emitConnectionFail(string reason, string errText) nothrow {
        try {
            auto info = parseReasonToFailInfo(reason, errText);
            // Stash on the client so a fresh WS sync arriving in the
            // next 10s heartbeat (or sooner if the snapshot writer
            // runs from processor.d) picks up the structured reason
            // without depending on the event stream. Cleared by
            // emitZeroRetryStatus() at every backoff.reset() site.
            lastFailInfo = info;
            auto evt = IRCRawEvent.makeConnectionFail(
                config.name, config.id.toString(),
                info.type_, info.reason, info.killedReason, info.sslVerifyError);
            eventChannel.put(evt);
        } catch (Exception e) {
            try logWarn("Failed to publish CONNECTION_FAIL for %s: %s",
                config.name, e.msg);
            catch (Exception) {}
        }
    }

    /// Publish a synthetic `ISUPPORT` event carrying the engine's
    /// parsed feature map so the frontend can render the categorised
    /// "Server features" panel without re-parsing raw 005 lines.
    /// Called from the 005 handler after every successful token that
    /// crossed the threshold (welcomed=true) — the panel keeps up
    /// incrementally as tokens stream in, and then settles once the
    /// server's 005 reply stream ends.
    private void publishIsupportEvent() nothrow {
        try {
            auto evt = IRCRawEvent.makeIsupport(
                config.name, config.id.toString(), isupportMap);
            eventChannel.put(evt);
        } catch (Exception e) {
            try logWarn("Failed to publish ISUPPORT for %s: %s", config.name, e.msg);
            catch (Exception) {}
        }
    }

    private void attemptConnection() {
        // Jul 8 2026 UX fix: emit a "Connecting" event to the chat IMMEDIATELY
        // so the user sees feedback the moment the engine starts attempting
        // the connect. Without this, the first user-visible event is
        // "Connected" (or "Disconnected" on failure) — and depending on
        // server response time, that gap can feel like "nothing is
        // happening" for 1-2 seconds. The existing code only emitted
        // "queued" on RETRY attempts (where there's a backoff delay);
        // fresh connects went straight to "Connecting → Connected"
        // without a "queued" marker. The frontend already groups all
        // events between two CONNECTED events as "Connection steps";
        // an early "Connecting" event makes the timeline show "queued →
        // tcp_open → tls → registered → connected" instead of an empty
        // gap. We dedup on consecutive identical events so this can't
        // spam the chat.
        emitLog("connecting",
            "Connecting to " ~ config.host ~ ":" ~ config.port.to!string
            ~ (config.tls == TLSMode.disabled ? "" : " (TLS)") ~ "...");
        // Trace span: covers TCP + TLS + REGISTER. The full IRC connect
        // attempt is captured in a single root span, with child spans
        // added by performRegistration() for finer granularity.
        withSpan("irc.connect",
            ["network": config.name, "host": config.host, "port": config.port.to!string],
            (ref Span s) {
            try {
                attemptConnectionImpl(true);
                s.setStatusOk();
            } catch (Exception e) {
                s.setStatusError(e.msg);
                throw e;
            }
        });
    }

    private void attemptConnectionImpl(bool) {
        // If the user clicked Disconnect (or the manager removed this client)
        // while we were waiting on the backoff timer, abort the connection
        // attempt instead of starting a new Happy Eyeballs / TLS / registration
        // cycle. Without this guard, the outer while (!isShutdownRequested)
        // check can race with stop() and let one connect slip through after
        // a disconnect, which is what the user saw as "Reconnect attempt
        // scheduled in 34s" still firing after they clicked Disconnect.
        if (isShutdownRequested) {
            logInfo("attemptConnection[%s]: skipped — shutdown requested", config.name);
            throw new Exception("Shutdown requested");
        }
        state = ConnectionState.connecting;
        ackedCaps.clear();
        serverFeatures = ServerFeatures.init;
        // Drop any tokens leftover from the previous connection attempt;
        // the new server's 005 stream will repopulate this map. Without
        // the clear, a reconnect to a less-featureful server would leave
        // stale tokens in the synchronised state.
        isupportMap.clear();

        logInfo("Connecting to %s:%s (Happy Eyeballs)", config.host, config.port);
        logJsonMap("info", "connection",
            "Reconnect attempt starting",
            ["network": config.name, "host": config.host,
             "port": config.port.to!string,
             "attempt": backoff.currentAttempt().to!string,
             "event": "reconnect_attempt"]);

        withSpan("irc.tcp_connect",
            ["network": config.name, "host": config.host, "port": config.port.to!string, "egress": config.egressNodeId],
            (ref Span ts) {
            connection = happyEyeballsConnect(config.host, config.port, config.egressNodeId);
            ts.setStatusOk();
        });
        emitLog("tcp_open",
            "TCP connection established to " ~ config.host ~ ":" ~ config.port.to!string ~ ".");
        logJsonMap("info", "connection",
            "TCP open",
            ["network": config.name, "host": config.host,
             "port": config.port.to!string,
             "tls": (config.tls != TLSMode.disabled) ? "true" : "false",
             "event": "tcp_open"]);

        if (config.tls != TLSMode.disabled) {
            emitLog("tls",
                "Starting TLS handshake with " ~ config.host ~ "...");

            auto ctx = createTLSContext(TLSContextKind.client);
            // TODO(security): TLSPeerValidationMode.none was inherited from main; re-enable peer
            // validation in a follow-up security hardening PR. Wave 1 cannot surface
            // nested SSL detail until then.
            ctx.peerValidationMode = TLSPeerValidationMode.none;
            bool tlsOk = false;
            withSpan("irc.tls_handshake",
                ["network": config.name, "host": config.host,
                 "port": config.port.to!string, "sni": config.host],
                (ref Span tls) {
            try {
                tlsStream = createTLSStreamWithTimeout(connection, ctx, stripHostBrackets(config.host),
                    TLS_HANDSHAKE_TIMEOUT_SECONDS.seconds);
                tlsOk = true;
                logInfo("Connected to %s:%s with TLS", config.host, config.port);
                logJsonMap("info", "connection",
                    "Connected with TLS",
                    ["network": config.name, "host": config.host,
                     "port": config.port.to!string,
                     "sni": config.host,
                     "event": "tls_handshake"]);
                emitLog("tls_done", "TLS handshake complete — connection is now encrypted.");
                tls.setStatusOk();
            } catch (Exception e) {
                logJsonMap("warn", "connection",
                    "TLS handshake failed",
                    ["network": config.name, "host": config.host,
                     "err": e.msg,
                     "event": "tls_fail"]);
                tls.setStatusError(e.msg);
                throw e;
            }
            });
            if (!tlsOk) {
                string tlsError = "TLS handshake failed";
                // TLS-only ports must not fall back to plain even when config says "enabled".
                // 6697/6698/7000 are de-facto TLS ports — plain on them gets 0 bytes
                // and leads to "Registration timed out → transport not alive" loop.
                // Treat enabled+TLS-port as required by default.
                bool isTlsOnlyPort = config.port == 6697 || config.port == 6698
                    || config.port == 7000 || config.port == 6699;
                bool mustRequireTls = config.tls == TLSMode.required
                    || (config.tls == TLSMode.enabled && isTlsOnlyPort);
                if (mustRequireTls) {
                    if (connection && connection.connected) {
                        try { connection.close(); } catch (Exception) {}
                    }
                    emitLog("error", tlsError);
                    throw new Exception(tlsError);
                }

                logWarn("TLS handshake failed for %s, falling back to plain text",
                    config.host);
                emitLog("warn",
                    "TLS handshake failed — falling back to plain text as configured.");

                if (connection && connection.connected) {
                    try { connection.close(); } catch (Exception) {}
                }
                connection = happyEyeballsConnect(config.host, config.port, config.egressNodeId);
                emitLog("tcp_open",
                    "Re-established plain-text TCP connection to " ~ config.host ~ ".");
                logJsonMap("info", "connection",
                    "TLS handshake failed; fell back to plain text",
                    ["network": config.name, "host": config.host,
                     "event": "tls_plain_fallback"]);
                logInfo("Connected to %s:%s without TLS", config.host, config.port);
            }
        } else {
            emitLog("info",
                "Plain-text mode — no TLS handshake will be performed.");
            logInfo("Connected to %s:%s (plain)", config.host, config.port);
        }

        emitLog("registering",
            "Sending registration: CAP LS 302, NICK " ~ sessionNick
            ~ ", USER " ~ sessionNick ~ "...");
        logJsonMap("info", "connection",
            "Sending registration",
            ["network": config.name, "nick": sessionNick,
             "event": "register_sending"]);
        withSpan("irc.register", ["network": config.name],
                    (ref Span s) {
            performRegistration();
            s.setStatusOk();
        });

        // Surface a "welcome" notice when the registration completed and
        // the engine is about to flip state to `connected`. The actual
        // state flip happens below; we emit the notice first so the
        // server log timeline ends on a clear success line before any
        // MOTD text begins to stream in.
        emitLog("welcome",
            "Connection registered as " ~ sessionNick
            ~ ". Server handshake complete.");
        logJsonMap("info", "connection",
            "Registration complete",
            ["network": config.name, "nick": sessionNick,
             "event": "register_complete"]);

        state = ConnectionState.connected;
        backoff.reset();
        throttledUntil = 0;
        droppedNoConnWarned = false;
        recordHostSuccess(config.host, config.port);
        // Welcome received — clear any prior registration-timeout marker so
        // the admin SPA doesn't keep showing this network as stuck.
        registrationTimeoutSince = 0;
        // W1-T01 (plan B3): zero-valued CONNECTION_RETRY_STATUS emit at
        // every backoff.reset() site. Without this the frontend keeps
        // showing stale retryStatus / failInfo after a successful
        // reconnect cycle — see the smoke scenario 3 in plan W1-T01
        // section G.
        emitZeroRetryStatus();
    }

    // ── Registration (CAP + NICK + USER + SASL) ───────────────────────────────

    private void performRegistration() {
        // Build cap list
        string[] desiredCaps = DESIRED_CAPS_BASE.dup;
        if (config.sasl != SASLMechanism.none) desiredCaps ~= DESIRED_CAPS_SASL;

        // CAP LS 302 first — lets us inspect what the server offers
        sendRaw("CAP LS 302");
        // Use last-negotiated nick from Redis if available, falling back
        // to the configured nick. This avoids the 433 collision → rename
        // → reconnect race on every reconnect. loadPersistedNick is safe
        // to call here (inside a fiber); the constructor deliberately does
        // NOT call it to avoid Redis calls outside a fiber context.
        auto persisted = loadPersistedNick();
        if (persisted.length > 0 && persisted != sessionNick) {
            logInfo("Switching to persisted nick '%s' for %s (was '%s')", persisted, config.name, sessionNick);
            sessionNick = persisted;
        }
        // requestedNick = what the USER wants, i.e. their configured nick
        // in `cfg.nick`. The actual NICK we send may differ (persisted
        // override above, or a 433 fallback below), but cfg.nick stays
        // anchored to user intent — so on 001 we can tell whether we
        // landed on the requested nick or a fallback. (Fallbacks must NOT
        // be persisted — see clearPersistedNick.)
        requestedNick = config.nick.length > 0 ? config.nick : sessionNick;
        // PASS must be sent before NICK/USER per RFC 1459 §4.1
        if (config.serverPass.length > 0) sendRaw("PASS " ~ config.serverPass);
        sendRaw("NICK " ~ sessionNick);
        sendRaw("USER " ~ sessionNick ~ " 0 * :" ~ config.realName);

        ubyte[STREAM_BUFFER_SIZE] buf;
        string partial;
        bool welcomed    = false; // 001 received (for timeout warning)
        bool motdDone    = false; // 376/422 received (end of MOTD)
        bool saslDone    = (config.sasl == SASLMechanism.none);
        bool capEndSent  = false;
        bool capReqSent  = false;
        bool capLsDone   = false;
        string[] serverCaps;

        // SCRAM state (may be null)
        ScramSha256Client* scram = null;
        int scramStep = 0; // 0=not started, 1=sent client-first, 2=sent client-final

        // RFC 2812 §2.3 — "client should expect a reply as specified but it
        // is not advised to wait forever for the reply." Bound the entire
        // CAP+NICK+USER+SASL handshake to REGISTRATION_OVERALL_TIMEOUT_SECS
        // so a black-holed server (open TCP, never sends 001) cannot wedge
        // the network's join state forever. The 400-read loop bound below
        // only protects against a tight loop on partial data; it does not
        // protect against a peer that accepts bytes but never replies.
        immutable registrationStartMs = Clock.currTime.toUnixTime!long * 1000;
        immutable registrationOverallTimeoutMs
            = REGISTRATION_OVERALL_TIMEOUT_SECS * 1000;
        long registrationLastWarnMs = 0;
        immutable registrationWarnThresholdMs1
            = (registrationOverallTimeoutMs * REGISTRATION_WARN_AT_FRACTION_1) / 100;
        immutable registrationWarnThresholdMs2
            = (registrationOverallTimeoutMs * REGISTRATION_WARN_AT_FRACTION_2) / 100;

        foreach (_; 0 .. REGISTRATION_MAX_READS) {
            // Hard upper bound: if the server hasn't completed registration
            // (sent 001) within REGISTRATION_OVERALL_TIMEOUT_SECS, give up
            // and let the connection loop's exponential backoff schedule a
            // retry. This is what RFC 2812 calls out as required behavior.
            immutable nowMs = Clock.currTime.toUnixTime!long * 1000;
            if (nowMs - registrationStartMs > registrationOverallTimeoutMs) {
                if (!welcomed) {
                    registrationTimeoutSince = nowMs;
                    logWarn("PersistentIRCClient[%s] registration TIMEOUT after %ds"
                        ~ " (CAP+SASL+001 not received) — black-holed or slow"
                        ~ " server; will retry with backoff",
                        config.name, REGISTRATION_OVERALL_TIMEOUT_SECS);
                    logJsonMap("warn", "connection",
                        "Registration timeout",
                        ["network":  config.name,
                         "networkId": config.id.toString(),
                         "host":     config.host ~ ":" ~ config.port.to!string,
                         "elapsed":  (nowMs - registrationStartMs).to!string,
                         "event":    "registration_timeout"]);
                    recordCounter("ircfiber.registration.timeout", 1,
                        ["network":  config.name,
                         "networkId": config.id.toString(),
                         "host":     config.host ~ ":" ~ config.port.to!string]);
                    throw new Exception(
                        "Registration timeout: 001 not received within "
                        ~ REGISTRATION_OVERALL_TIMEOUT_SECS.to!string
                        ~ "s (likely black-holed server)");
                }
                // welcomed == true means registration completed; remaining
                // reads are post-001 MOTD/376 traffic. Let the existing
                // 400-read cap bound that loop naturally.
            }
            // Soft warnings at 50% / 75% of the timeout so operators can
            // see "this network is taking unusually long to welcome us"
            // before the hard timeout fires. Cheaper than a per-second log
            // line; just one event per threshold per registration attempt.
            immutable elapsedMs = nowMs - registrationStartMs;
            if (registrationLastWarnMs < registrationWarnThresholdMs1
                && elapsedMs >= registrationWarnThresholdMs1) {
                registrationLastWarnMs = elapsedMs;
                logWarn("PersistentIRCClient[%s] registration slow — %dms elapsed, still waiting for 001",
                    config.name, cast(int) elapsedMs);
                logJsonMap("warn", "connection",
                    "Registration slow",
                    ["network":  config.name,
                     "networkId": config.id.toString(),
                     "host":     config.host ~ ":" ~ config.port.to!string,
                     "elapsed":  elapsedMs.to!string,
                     "event":    "registration_slow"]);
                recordCounter("ircfiber.registration.slow", 1,
                    ["network":  config.name,
                     "networkId": config.id.toString(),
                     "host":     config.host ~ ":" ~ config.port.to!string]);
            } else if (registrationLastWarnMs < registrationWarnThresholdMs2
                && elapsedMs >= registrationWarnThresholdMs2) {
                registrationLastWarnMs = elapsedMs;
                logWarn("PersistentIRCClient[%s] registration very slow — %dms elapsed",
                    config.name, cast(int) elapsedMs);
                logJsonMap("warn", "connection",
                    "Registration very slow",
                    ["network":  config.name,
                     "networkId": config.id.toString(),
                     "host":     config.host ~ ":" ~ config.port.to!string,
                     "elapsed":  elapsedMs.to!string,
                     "event":    "registration_very_slow"]);
                recordCounter("ircfiber.registration.very_slow", 1,
                    ["network":  config.name,
                     "networkId": config.id.toString(),
                     "host":     config.host ~ ":" ~ config.port.to!string]);
            }

            // Use a non-zero timeout so the fiber blocks until data actually
            // arrives.  With waitForData(0) on macOS/kqueue, the poll can miss
            // server responses (CAP LS, 001) entirely, causing a 40s timeout.
            auto received = readFromStream(buf[], REGISTRATION_READ_TIMEOUT_MS.msecs);
            if (received == 0) {
                // waitForData already blocked for the full timeout above;
                // a minimal yield prevents tight-looping the event loop.
                yield();
            } else {
                partial ~= sanitizeUtf8(cast(string) buf[0 .. received]);

                ptrdiff_t idx;
                while ((idx = partial.indexOf("\r\n")) >= 0) {
                    auto line = partial[0 .. idx];
                    partial   = partial[idx + 2 .. $];
                    if (line.length == 0) continue;

                    auto evt = parseIRCLine(line);

                    switch (evt.command) {
                        case "PING":
                            auto params = evt.getParams();
                            sendRaw("PONG :" ~ (params.length > 0 ? params[$ - 1] : ""));
                            break;

                        // ── 001 welcomed ─────────────────────────────────────
                        case "001":
                            welcomed = true;
                            // Registration completed. Reset the fallback
                            // counter so the next reconnect attempts the
                            // user's configured nick from scratch — if
                            // the random-suffix nick is what landed us
                            // here, the user's intended nick may now be
                            // free and we should re-derive requestedNick
                            // from cfg.nick on the next attempt.
                            registrationFallbackAttempts = 0;
                            // Only persist the nick if it matches the one
                            // we asked for — otherwise we're on a 433
                            // fallback (e.g. `Zodiac__`) and persisting
                            // it would lock the user out of their
                            // intended nick (`Zodiac`) the next time it
                            // frees up. The random-suffix nick
                            // (`Zodiac_a1b2c`) IS persisted above (in
                            // the 433 handler) so subsequent reconnects
                            // re-use the same nick until cfg.nick frees
                            // up.
                            if (sessionNick == requestedNick)
                                persistNick(sessionNick);
                            else if (!randomNickPersisted) {
                                // First non-fallback 001 with a fallback
                                // nick: persist the fallback as the
                                // session stickiness. Done here rather
                                // than in the 433 handler so the value
                                // we persist is the post-server-confirmed
                                // nick (e.g. 'Zod_a1b2c' if the server
                                // normalized case).
                                persistNick(sessionNick);
                                randomNickPersisted = true;
                            }
                            logJsonMap("info", "connection",
                                "RPL_WELCOME received",
                                ["network": config.name,
                                 "nick": sessionNick,
                                 "hostmask": evt.prefix.length > 0 ? evt.prefix : "",
                                 "event": "welcome"]);
                            break;

                        // ── End of MOTD ───────────────────────────────────────
                        // Keep reading until MOTD is complete so all 372 lines
                        // are published BEFORE emitLog("welcome") below rather
                        // than being split by it into separate event batches.
                        case "376":
                        case "422":
                            motdDone = true;
                            welcomed = true;
                            break;

                        // ── Nick in use ───────────────────────────────────────
                        case "433":
                        case "432":
                            registrationFallbackAttempts++;
                            if (registrationFallbackAttempts <= REGISTRATION_MAX_FALLBACK_ATTEMPTS) {
                                // The classic `Zod` → `Zod_` → `Zod__` chain.
                                // Each fallback _is_ a NICK change on the
                                // IRC server, so each one is a unique
                                // member entry in any channels the user
                                // auto-joins after registration completes.
                                // Across many reconnect cycles those
                                // accumulate as ghost entries (one per
                                // cycle), so we cap the chain at
                                // REGISTRATION_MAX_FALLBACK_ATTEMPTS and
                                // fall through to a unique random nick.
                                sessionNick ~= "_";
                                sendRaw("NICK " ~ sessionNick);
                            } else {
                                // Configure nick + every short-underscore
                                // variant is taken (or the server is
                                // rejecting us). Generate a unique random
                                // suffix and persist it so the next
                                // reconnect uses the same nick — no more
                                // ghost nick accumulation in shared
                                // channels. The suffix is generated with
                                // std.random.uniform!rndGen which gives a
                                // thread-local PRNG; for a one-shot
                                // uniqueness probe that's enough — the
                                // suffix only needs to not collide with
                                // anything currently in the channel.
                                import std.random : uniform, Mt19937, unpredictableSeed, Random;
                                auto rng = Random(unpredictableSeed);
                                ubyte[] nibbles = new ubyte[REGISTRATION_RANDOM_SUFFIX_HEX_LEN];
                                foreach (ref n; nibbles) n = cast(ubyte) uniform(0, 16, rng);
                                char[] hex = new char[](nibbles.length);
                                foreach (i, b; nibbles) hex[i] = "0123456789abcdef"[b];
                                auto suffix = cast(string) hex;
                                sessionNick = requestedNick ~ "_" ~ suffix;
                                persistNick(sessionNick);
                                logWarn("Nick '%s' persistently unavailable for %s after %d fallbacks; "
                                    ~ "switching to random nick '%s' and persisting",
                                    requestedNick, config.name, REGISTRATION_MAX_FALLBACK_ATTEMPTS, sessionNick);
                                sendRaw("NICK " ~ sessionNick);
                            }
                            break;

                        // ── ISUPPORT ──────────────────────────────────────────
                        case "005":
                            auto params = evt.getParams();
                            // params[0] = our nick; params[1..n-1] = tokens; params[n-1] = "are supported..."
                            bool mapChanged = false;
                            foreach (token; params[1 .. $ > 1 ? $ - 1 : $]) {
                                if (token.length == 0) continue;
                                immutable auto before = isupportMap.length;
                                applyIsupport(serverFeatures, isupportMap, token);
                                if (isupportMap.length != before) mapChanged = true;
                            }
                            // After the 005 stream finishes (welcomed =
                            // true), publish one network_isupport event
                            // so the frontend's categorised panel can
                            // render the catalog lookup without having
                            // to re-parse the raw 005 message stream.
                if (mapChanged) publishIsupportEvent();
                            break;

                        // ── RPL_WHOISUSER (311): nick user host * :realname ──
                        // Stores the realname so the frontend can render
                        // <span class="author-realname"> next to the nick
                        // (IRCCloud parity).
                        case "311": {
                            auto params = evt.getParams();
                            // params[0] = our nick, params[1] = target nick,
                            // params[2] = ident, params[3] = host,
                            // params[4] = "*", params[5] = realname
                            if (params.length >= 6) {
                              auto nick = params[1];
                              const rn   = params[5];
                              if (nick.length > 0 && rn.length > 0 && rn != nick)
                                realnames[nick] = rn;
                            }
                            break;
                        }

                        // ── CAP LS / ACK / NAK ────────────────────────────────
                        case "CAP":
                            auto params = evt.getParams();
                            if (params.length < 2) break;

                            // params[0] = our nick (or *), params[1] = subcommand
                            const sub = params.length >= 2 ? params[1] : "";
                            auto capLine = params.length >= 3 ? params[$ - 1] : "";

                            if (sub == "LS") {
                                // Accumulate caps (multi-line uses trailing '*')
                                const bool isMultiline = (params.length >= 3 && params[2] == "*");
                                foreach (cap; capLine.split(" ")) {
                                    auto eqPos = cap.indexOf("=");
                                    auto capName = eqPos >= 0 ? cap[0 .. eqPos] : cap;
                                    if (capName.length > 0) serverCaps ~= capName;
                                }
                                if (!isMultiline) {
                                    capLsDone = true;
                                    // Request only caps we want AND the server offers
                                    string[] toRequest;
                                    foreach (desired; desiredCaps) {
                                        if (serverCaps.canFind(desired)) toRequest ~= desired;
                                    }
                                    // ── ngIRCd workaround ───────────────────────────────
                                    // ngIRCd 27 only offers `multi-prefix` and stalls if
                                    // the client sends `CAP REQ :multi-prefix` AFTER it
                                    // has already sent NICK/USER (which the engine does
                                    // immediately after CAP LS). Manual test:
                                    //   CAP LS + NICK+USER, LS=multi-prefix, REQ -> ACK but no 001
                                    //   CAP LS + NICK+USER, LS=multi-prefix, END -> immediate 001 + MOTD
                                    // So when the server's entire cap list is a single
                                    // `multi-prefix` entry, skip the REQ and go straight
                                    // to CAP END. The cap is non-essential for local
                                    // testing and this avoids a 30s registration timeout
                                    // that wedges the LocalIRCD network.
                                    const bool singleMultiPrefixOnly = serverCaps.length == 1
                                        && serverCaps[0] == "multi-prefix"
                                        && toRequest.length == 1
                                        && toRequest[0] == "multi-prefix";
                                    if (singleMultiPrefixOnly) {
                                        logJsonMap("info", "connection",
                                            "Skipping CAP REQ for single multi-prefix (ngIRCd workaround)",
                                            ["network": config.name,
                                             "host": config.host, "port": config.port.to!string,
                                             "event": "cap_skipped_ngircd"]);
                                        toRequest = [];
                                    }
                                    if (toRequest.length > 0) {
                                        sendRaw("CAP REQ :" ~ toRequest.join(" "));
                                        capReqSent = true;
                                        logJsonMap("debug", "connection",
                                            "CAP REQ sent",
                                            ["network": config.name,
                                             "host": config.host, "port": config.port.to!string,
                                             "caps": toRequest.join(" "),
                                             "event": "cap_negotiating"]);
                                        recordCounter("ircfiber.cap.negotiating", 1,
                                            ["network": config.name, "host": config.host,
                                             "port": config.port.to!string]);
                                    } else {
                                        if (saslDone && !capEndSent) {
                                            sendRaw("CAP END");
                                            capEndSent = true;
                                            logJsonMap("info", "connection",
                                                "CAP negotiation complete",
                                                ["network": config.name,
                                                 "acks": "0",
                                                 "event": "cap_negotiated"]);
                                        }
                                    }
                                }
                            } else if (sub == "ACK") {
                                foreach (cap; capLine.split(" ")) {
                                    auto c = cap.strip();
                                    if (c.length > 0) ackedCaps[c] = true;
                                }
                                // If SASL was acked, start authentication
                                if (ackedCaps.get("sasl", false) && !saslDone && config.sasl != SASLMechanism.none) {
                                    emitLog("sasl_start",
                                        "Starting SASL " ~ saslMechanismName(config.sasl) ~ " authentication");
                                    logJsonMap("info", "auth",
                                        "SASL starting",
                                        ["network": config.name, "host": config.host,
                                         "port": config.port.to!string,
                                         "mechanism": saslMechanismName(config.sasl),
                                         "event": "sasl_start"]);
                                    recordCounter("ircfiber.sasl.start", 1,
                                        ["network": config.name, "host": config.host,
                                         "port": config.port.to!string,
                                         "mechanism": saslMechanismName(config.sasl)]);
                                    final switch (config.sasl) {
                                        case SASLMechanism.none: break;
                                        case SASLMechanism.plain:
                                            sendRaw("AUTHENTICATE PLAIN");
                                            break;
                                        case SASLMechanism.external:
                                            sendRaw("AUTHENTICATE EXTERNAL");
                                            break;
                                        case SASLMechanism.scramSha256:
                                            sendRaw("AUTHENTICATE SCRAM-SHA-256");
                                            break;
                                    }
                                } else if (saslDone && !capEndSent) {
                                    sendRaw("CAP END");
                                    capEndSent = true;
                                    logJsonMap("info", "connection",
                                        "CAP negotiation complete",
                                        ["network": config.name,
                                         "host": config.host, "port": config.port.to!string,
                                         "acks": capLine,
                                         "event": "cap_negotiated"]);
                                    recordCounter("ircfiber.cap.negotiated", 1,
                                        ["network": config.name, "host": config.host,
                                         "port": config.port.to!string]);
                                }
                            } else if (sub == "NAK") {
                                // Ignore NAK'd caps; they just won't be used
                                if (saslDone && !capEndSent) {
                                    sendRaw("CAP END");
                                    capEndSent = true;
                                    logJsonMap("info", "connection",
                                        "CAP negotiation complete",
                                        ["network": config.name,
                                         "naks": capLine,
                                         "event": "cap_negotiated"]);
                                }
                            } else if (sub == "NEW") {
                                // Server added new caps (cap-notify); request any we want
                                foreach (cap; capLine.split(" ")) {
                                    if (desiredCaps.canFind(cap)) {
                                        sendRaw("CAP REQ :" ~ cap);
                                    }
                                }
                            } else if (sub == "DEL") {
                                // Server removed caps
                                foreach (cap; capLine.split(" ")) {
                                    ackedCaps.remove(cap.strip());
                                }
                            }
                            break;

                        // ── AUTHENTICATE ──────────────────────────────────────
                        case "AUTHENTICATE":
                            logJsonMap("debug", "auth",
                                "SASL authenticate",
                                ["network": config.name,
                                 "mechanism": saslMechanismName(config.sasl),
                                 "event": "sasl_authenticate"]);
                            auto params = evt.getParams();
                            auto challenge = params.length > 0 ? params[0] : "";

                            if (config.sasl == SASLMechanism.plain) {
                                if (challenge == "+") {
                                    sendSaslAuthenticate(buildSaslPlainPayload(config.saslUsername,
                                        config.saslPassword));
                                } else {
                                    // Unexpected challenge — abort SASL per RFC 4422 §3.5
                                    logWarn("SASL PLAIN: unexpected challenge from %s, aborting", config.host);
                                    sendRaw("AUTHENTICATE *");
                                    saslDone = true;
                                }
                            } else if (config.sasl == SASLMechanism.external) {
                                if (challenge == "+") {
                                    sendRaw("AUTHENTICATE +"); // empty authzid
                                } else {
                                    // Unexpected challenge — abort
                                    logWarn("SASL EXTERNAL: unexpected challenge from %s, aborting", config.host);
                                    sendRaw("AUTHENTICATE *");
                                    saslDone = true;
                                }
                            } else if (config.sasl == SASLMechanism.scramSha256) {
                                if (scramStep == 0 && challenge == "+") {
                                    // Server indicates readiness — send client-first-message
                                    auto s = new ScramSha256Client(config.saslUsername, config.saslPassword);
                                    scram  = s;
                                    sendSaslAuthenticate(scram.clientFirstMessage());
                                    scramStep = 1;
                                } else if (scramStep == 1 && challenge != "+" && challenge.length > 0) {
                                    // Server-first-message — send client-final-message
                                    sendSaslAuthenticate(scram.clientFinalMessage(challenge));
                                    scramStep = 2;
                                } else if (scramStep == 2 && challenge != "+" && challenge.length > 0) {
                                    // Server-final-message (mutual auth verification)
                                    if (!scram.verifyServerFinal(challenge)) {
                                        logWarn("SCRAM: server signature verification FAILED for %s", config.host);
                                    }
                                } else {
                                    // Unexpected state — abort SASL
                                    logWarn("SASL SCRAM: unexpected challenge (step=%s) from %s, aborting",
                                        scramStep, config.host);
                                    sendRaw("AUTHENTICATE *");
                                    saslDone = true;
                                }
                            } else {
                                // SASL mechanism not configured but server sent AUTHENTICATE — abort
                                logWarn("SASL: unexpected AUTHENTICATE from %s (no mechanism selected), aborting",
                                    config.host);
                                sendRaw("AUTHENTICATE *");
                                saslDone = true;
                            }
                            break;

                        // ── SASL success / failure ────────────────────────────
                        case "903": // RPL_SASLSUCCESS
                            saslDone = true;
                            emitLog("sasl_done",
                                "SASL " ~ saslMechanismName(config.sasl) ~ " authentication succeeded");
                            if (!capEndSent) {
                                sendRaw("CAP END");
                                capEndSent = true;
                            }
                            logJsonMap("info", "auth",
                                "SASL success",
                                ["network": config.name,
                                 "host": config.host, "port": config.port.to!string,
                                 "mechanism": saslMechanismName(config.sasl),
                                 "event": "sasl_success"]);
                            recordCounter("ircfiber.sasl.success", 1,
                                ["network": config.name, "host": config.host,
                                 "port": config.port.to!string,
                                 "mechanism": saslMechanismName(config.sasl)]);
                            break;
                        case "904": // ERR_SASLFAIL
                        case "905": // ERR_SASLTOOLONG
                            emitLog("sasl_fail",
                                "SASL " ~ saslMechanismName(config.sasl) ~ " authentication failed: " ~ evt.text);
                            logJsonMap("warn", "auth",
                                "SASL fail",
                                ["network": config.name,
                                 "host": config.host, "port": config.port.to!string,
                                 "mechanism": saslMechanismName(config.sasl),
                                 "err": evt.text,
                                 "event": "sasl_fail"]);
                            recordCounter("ircfiber.sasl.failure", 1,
                                ["network": config.name, "host": config.host,
                                 "port": config.port.to!string,
                                 "mechanism": saslMechanismName(config.sasl)]);
                            throw new Exception("SASL authentication failed: " ~ evt.text);
                        case "906": // ERR_SASLABORTED
                            emitLog("sasl_fail", "SASL authentication aborted");
                            logJsonMap("warn", "auth",
                                "SASL aborted",
                                ["network": config.name,
                                 "host": config.host, "port": config.port.to!string,
                                 "mechanism": saslMechanismName(config.sasl),
                                 "event": "sasl_fail"]);
                            recordCounter("ircfiber.sasl.failure", 1,
                                ["network": config.name, "host": config.host,
                                 "port": config.port.to!string,
                                 "mechanism": saslMechanismName(config.sasl)]);
                            throw new Exception("SASL aborted");
                        case "907": // ERR_SASLALREADY
                            saslDone = true;
                            emitLog("sasl_done", "SASL already authenticated (907)");
                            break;

                        case "ERROR":
                            lastErrorText = evt.text;
                            if (isThrottleError(evt.text)) {
                                throttledUntil = Clock.currTime.toUnixTime!long * 1000 + 300_000;
                            }
                            evt.network     = config.name;
                            evt.timestampMs = resolveTimestamp(evt);
                            eventChannel.put(evt);
                            throw new Exception("Server closed connection during registration: " ~ evt.text);

                        default:
                            break;
                    }

                    // Skip WHOIS / WHOX / NAMES / WHO replies during
                    // registration too — engine consumes what it needs
                    // (311 → realnames, 352 → channelUsers) above, the
                    // rest is metadata noise the frontend has no UI for.
                    // Without this, the WS frame stream fills with 2000+
                    // WHOX 354 lines on a SuperNets-scale channel and
                    // the scrollback Redis key bloats with one entry per
                    // user. The frontend's `isSkippedCommand` already
                    // filters most of these at display time; this is the
                    // symmetric engine-side guard so we don't burn
                    // bandwidth / storage shipping what we'll discard.
                    const noPublishDuringRegistration = [
                        "311", "312", "313", "315", "317", "318", "319",
                        "330", "332", "333", "354", "366", "376", "401",
                        "422",
                    ];
                    if (evt.command != "PING" && evt.command != "ERROR"
                        && !noPublishDuringRegistration.canFind(evt.command)) {
                        evt.network     = config.name;
                        evt.timestampMs = resolveTimestamp(evt);
                        eventChannel.put(evt);
                    }
                }
            }
            if (motdDone && saslDone) break;
            yield();
        }

        if (!welcomed) logWarn("Registration timed out for %s, proceeding anyway", config.host);

        // SuperNETs/DangerousIRCd throttles JOIN until the client has been
        // connected for ≥5s (421 "You must be connected for at least 5
        // seconds before you can use this command"). Per-network
        // autoJoinDelaySeconds (default 0 = join immediately) waits out the
        // remaining window measured from registration start (≈ connect) so
        // the auto-joins below land after the throttle instead of being
        // bounced.
        if (config.autoJoinDelaySeconds > 0) {
            immutable nowMs = Clock.currTime.toUnixTime!long * 1000;
            immutable delayMs = remainingJoinDelayMs(
                config.autoJoinDelaySeconds, nowMs, registrationStartMs);
            if (delayMs > 0) {
                logInfo("Auto-join delay: waiting %d ms for %s (configured %d s, connected %d ms ago)",
                    delayMs, config.name, config.autoJoinDelaySeconds, nowMs - registrationStartMs);
                sleep(delayMs.msecs);
            }
        }

        foreach (chan; config.autoJoinChannels) sendRaw("JOIN " ~ chan);

        // ── Post-registration commands ─────────────────────────────────────
        // NickServ IDENTIFY (if configured) — sent BEFORE user-supplied
        // commands so the user's commands can rely on being identified.
        if (config.nspass.length > 0) {
            sendRaw("PRIVMSG NickServ :IDENTIFY " ~ config.nspass);
        }

        // User-supplied commands to run on connect (one per line).
        // Supports WAIT N for delays (e.g. "WAIT 15" pauses 15 seconds).
        if (config.commands.length > 0) {
            import std.ascii : isDigit;
            foreach (line; config.commands.split("\n")) {
                auto trimmed = line.strip();
                if (trimmed.length == 0) continue;
                if (trimmed.length > 5 && trimmed[0 .. 5] == "WAIT ") {
                    int seconds = 0;
                    foreach (ch; trimmed[5 .. $]) {
                        if (isDigit(ch)) seconds = seconds * 10 + (ch - '0');
                        else break;
                    }
                    if (seconds > 0) {
                        logInfo("Waiting %d seconds before next command…", seconds);
                        sleep(seconds.seconds);
                        continue;
                    }
                }
                sendRaw(trimmed);
            }
        }
    }

    // ── SASL AUTHENTICATE message fragmentation ──────────────────────────────
    //
    // IRC lines are limited to ~512 bytes. SASL base64 payloads exceeding
    // 400 bytes must be split into multiple AUTHENTICATE messages per the
    // IRCv3 SASL spec. Each fragment is exactly 400 bytes (or less for the
    // final piece). If the final fragment is exactly 400 bytes, an empty
    // AUTHENTICATE + is sent as a terminator.

    private string saslMechanismName(SASLMechanism m) const {
        final switch (m) {
            case SASLMechanism.none:        return "none";
            case SASLMechanism.plain:       return "PLAIN";
            case SASLMechanism.external:    return "EXTERNAL";
            case SASLMechanism.scramSha256: return "SCRAM-SHA-256";
        }
    }

    private void sendSaslAuthenticate(string base64Payload) {
        immutable maxFragment = 400;
        if (base64Payload.length <= maxFragment) {
            sendRaw("AUTHENTICATE " ~ base64Payload);
            return;
        }
        size_t offset = 0;
        while (offset < base64Payload.length) {
            auto end = offset + maxFragment < base64Payload.length ? offset + maxFragment : base64Payload.length;
            auto chunk = base64Payload[offset .. end];
            sendRaw("AUTHENTICATE " ~ chunk);
            offset += maxFragment;
        }
        // If the last chunk was exactly maxFragment bytes, the server
        // expects an empty AUTHENTICATE + to signal end of data.
        if (base64Payload.length % maxFragment == 0) {
            sendRaw("AUTHENTICATE +");
        }
    }

    // ── Event processing loop ─────────────────────────────────────────────────

private void processEvents() {
        // Check post-handoff QUIT *before* the connection-state loop.
        // The connection may have dropped during the handoff pause (IRC
        // server ping timeout, etc.), which would exit the inner while
        // loop without ever reaching the postHandoffQuitAtMs check at
        // the bottom — causing the old engine to reconnect and collide
        // with the new engine's nick registration.
        import core.atomic : atomicLoad;
        if (atomicLoad(postHandoffQuitAtMs) > 0) {
            if (transportAlive) {
                try writeRaw("QUIT :engine-handoff");
                catch (Exception) {}
            }
            isShutdownRequested = true;
            try transportClose(); catch (Exception) {}
            logInfo("Post-handoff: %s closed by OLD engine (early check)", config.name);
            logJsonMap("info", "handoff",
                "Post-handoff: " ~ config.name ~ " closed by OLD engine (early check)",
                ["network": config.name,
                 "event": "post_handoff_quit"]);
            return;
        }

        ubyte[] buffer = new ubyte[4096];
        string partial;
        auto lastKeepalive = Clock.currTime.toUnixTime!long;
        auto lastLabelSweep = lastKeepalive;
        auto lastWhoEnrichCheck = lastKeepalive;
        // engine forces a `transportAlive` probe instead of waiting for
        // either the 120 s idle heuristic or the next I/O attempt — this
        // closes the window where a TCP RST has already been received
        // but we haven't tried to read or write yet, leaving the UI
        // showing "connected" for up to 120 s after the server cut us.
        int consecutiveZeroReads = 0;
        enum MAX_ZERO_READS_BEFORE_PROBE = 10;

        while (state == ConnectionState.connected) {
            auto now = Clock.currTime.toUnixTime!long;
            if (!transportAlive) throw new Exception("Connection lost: transport not alive (adopted="
                ~ (adoptedSocket !is null).to!string ~ ")");

            // Proactive disconnect probe: every N consecutive zero-reads
            // (after a successful read earlier), touch the transport to
            // see if the underlying socket is still alive. This used to
            // take up to 120 s idle before the engine noticed a dead
            // connection — now it's bounded by N * PROCESS_READ_TIMEOUT_MS.
            if (consecutiveZeroReads >= MAX_ZERO_READS_BEFORE_PROBE
                && lastDataReceivedSecs > 0) {
                logJsonMap("debug", "connection",
                    "Proactive disconnect probe (no data for %s ms)",
                    [
                        "network": config.name,
                        "idleMs": (now * 1000 - lastDataReceivedSecs * 1000).to!string,
                        "event": "disconnect_probe"
                    ]);
                if (!transportAlive) throw new Exception(
                    "Proactive probe: transport not alive (adopted=" ~
                    (adoptedSocket !is null).to!string ~ ")");
                consecutiveZeroReads = 0; // reset so we don't spam every iter
            }

            // Same fix as performRegistration: don't gate on waitForData()
            // (raw socket), because tlsStream may have buffered decrypted data
            // that the underlying TCP socket doesn't know about. Just try to
            // read — IOMode.once is non-blocking.
            auto received = readFromStream(buffer[]);
            if (received == 0) {
                consecutiveZeroReads++;
                sleep(PROCESS_READ_TIMEOUT_MS.msecs);
            } else {
                consecutiveZeroReads = 0;
                lastDataReceivedSecs = now;
                // Any data receipt proves the connection is alive — reset
                // the PONG timeout too (not just PONG responses). This
                // prevents false disconnects before the first keepalive
                // PING/PONG exchange completes.
                lastPongReceivedSecs = now;
                idleEmitted = false;
                partial ~= sanitizeUtf8(cast(string) buffer[0 .. received]);

                ptrdiff_t idx;
                while ((idx = partial.indexOf("\r\n")) >= 0) {
                    auto line = partial[0 .. idx];
                    partial   = partial[idx + 2 .. $];
                    if (line.length > 0) processLine(line);
                }
            }

            yield();
            // Handoff pause: if a handoff has been requested, spin here
            // until it's released. We check *after* yield() so any
            // pending wake-ups get processed; the count is shared/atomic
            // so reads from the engine thread are well-defined.
            import core.atomic : atomicLoad;
            while (atomicLoad(handoffPauseCount) > 0) {
                import core.time : msecs;
                sleep(10.msecs);
            }
            // Post-handoff quit: if the connection was handed off to a
            // new engine, this OLD engine must release the IRC server's
            // nick registration BEFORE the new engine soft-reconnects.
            // We send QUIT on the still-live socket (best effort — if
            // the FD was transferred to the new engine, the write fails
            // silently) and exit the loop without reconnecting. Without
            // this, TLS handoffs cause nick collisions ("Zod" → "Zod_").
            if (atomicLoad(postHandoffQuitAtMs) > 0) {
                try {
                    if (transportAlive && state == ConnectionState.connected) {
                        try writeRaw("QUIT :engine-handoff");
                        catch (Exception e) {
                            logInfo("Post-handoff QUIT for %s: %s", config.name, e.msg);
                        }
                    }
                } catch (Exception e) {
                    logWarn("Post-handoff cleanup failed for %s: %s", config.name, e.msg);
                }
                // Don't reconnect — the new engine owns this network now.
                // Force the outer loop to exit by setting shutdown + breaking.
                isShutdownRequested = true;
                // Best-effort close. transportClose() handles adoptedSocket.
                try transportClose(); catch (Exception) {}
                logInfo("Post-handoff: %s closed by OLD engine", config.name);
                logJsonMap("info", "handoff",
                    "Post-handoff: " ~ config.name ~ " closed by OLD engine",
                    ["network": config.name,
                     "event": "post_handoff_quit"]);
                break;
            }
            processOutboundQueue();

            if (now - lastKeepalive >= 120) {
                sendRaw("PING :keepalive");
                lastKeepalive = now;
                logJsonMap("debug", "connection",
                    "PING sent",
                    ["network": config.name,
                     "event": "ping_sent"]);
            }
            // PONG timeout: if no PONG has been received in 300s (5 min),
            // the connection is half-open (server silently died but local
            // socket stays ESTABLISHED). Throw to trigger the auto-reconnect
            // with exponential backoff — same as TCP read failure.
            if (now - lastPongReceivedSecs >= 300) {
                throw new Exception(
                    "PONG timeout — no response for 300s (network: " ~
                    config.name ~ ")");
            }
            // Defense-in-depth A (idle-reaper): some IRC servers stop
            // sending PINGs entirely but also stop sending any data (e.g.
            // a NAT middlebox silently dropped the connection while the
            // local TCP socket still reports `connected`). The PONG
            // timeout above can't fire because lastPongReceivedSecs was
            // last reset on a previous byte; the d207a4d writeRaw
            // reaper only triggers on a client send. This guard closes
            // the gap: if we've had at least one byte of activity,
            // sent ≥2 keepalives since then, and still seen ZERO bytes
            // for 600 s (10 min), the half-open is unambiguous. Throw
            // so the runConnectionLoop() catch block runs
            // handleDisconnection() and schedules a fresh reconnect.
            // The threshold is well above the 120 s W1-T08 idle event
            // (which the UI uses as a status hint, not a reaper), so a
            // merely-quiet channel will not falsely trip.
            if (lastDataReceivedSecs > 0
                && now - lastDataReceivedSecs >= 600
                && now - lastKeepalive >= 240) {
                throw new Exception(
                    "Idle half-open detected — no data for "
                    ~ (now - lastDataReceivedSecs).to!string
                    ~ "s after keepalive (network: " ~ config.name ~ ")");
            }
            // Periodically (every ~30s) drop labels we never got an echo for
            // so a chatty client with a flaky echo path doesn't leak memory.
            if (now - lastLabelSweep >= 30) {
                expireStalePendingLabels(30_000);
                lastLabelSweep = now;
            }

            // Periodic realname enrichment: if we have channels with users
            // but no realnames (e.g. snapshot-loaded state after a restart),
            // trigger WHO to populate them. Rate-limited to 60s per check
            // and 2s per channel via lastWhoTime.
            if (now - lastWhoEnrichCheck >= 60) {
                lastWhoEnrichCheck = now;
                foreach (chan, users; channelUsers) {
                    if (users.length == 0) continue;
                    bool needsWho = false;
                    foreach (u; users) {
                        const bare = stripNickPrefix(u);
                        if (bare !in realnames) { needsWho = true; break; }
                    }
                    if (needsWho && (chan !in lastWhoTime || now - lastWhoTime[chan] >= 2)) {
                        sendRaw("WHO " ~ chan);
                        lastWhoTime[chan] = now;
                        // Downgraded from info to debug — 60s per channel was spamming SigNoz
                        // with WHO periodic enrichment logs (263-user channel = 1 log/min).
                        // Useful for debugging WHO, but not for production info level.
                        logJsonMap("debug", "protocol",
                            "WHO periodic enrichment",
                            ["network": config.name, "channel": chan,
                                "users": users.length.to!string,
                                "event": "who_periodic"]);
                    }
                }
            }
            // W1-T08: Connection idle detection — after 120s without any
            // incoming data, emit a synthetic "idle" event so the frontend
            // can show a stale-connection indicator.
            if (!idleEmitted && now - lastDataReceivedSecs >= 120) {
                auto idleEvt = IRCRawEvent(config.name, "idle");
                idleEvt.networkId = config.id.toString();
                idleEvt.addTag("since_ms", ((now - lastDataReceivedSecs) * 1000).to!string);
                eventChannel.put(idleEvt);
                idleEmitted = true;
            }
        }
    }

    /// Returns `true` if `text` (the trailing parameter of an IRC event)
    /// looks like a squashed `ERROR :Closing Link: ...` shoved onto a
    /// numeric reply by an IRCd that violated the per-line protocol. We
    /// match two canonical signals: the literal "ERROR" command-name
    /// appearing as a sub-token OR the templated `Closing Link:` prefix
    /// that IRCds use when closing the link.
    ///
    /// The match is intentionally conservative — a stray user saying
    /// "I got an ERROR this morning" is not a server shutdown.
    private static bool looksLikeSquashedError(string text) {
        if (text.length == 0) return false;
        // "Closing Link:" — case-sensitive prefix per RFC 2812 §3.7.2.
        if (text.startsWith("Closing Link:") || text.indexOf(" ERROR ") >= 0) {
            return true;
        }
        return false;
    }

    /// Common implementation of the `case "ERROR":` body — sets
    /// `lastErrorText`, applies the throttle-detection policy, transitions
    /// the FSM to `disconnecting`, and emits the structured
    /// `event=server_error_detected` log. Used by both the registration-
    /// loop ERROR branch and the post-registration squashed-numeric
    /// detector in `processLine`.
    private void handleServerError(string text) {
        lastErrorText = text;
        // Ban (ZLINE/GLINE/KLINE) takes precedence over throttle — it needs
        // a much longer pause and a different FailInfo so the UI doesn't
        // spin a 5s retry loop that immediately re-hits the same wall.
        if (isBanError(text)) {
            // 30 min ban window. The server's ZLINE will still be in
            // place after 5 min, so a short throttle would just hammer.
            // The reconnect loop's HostCircuitBreaker (5 min) + this
            // window together give a 30 min visible countdown; the user
            // can still click "Reconnect" to force a retry earlier.
            throttledUntil = Clock.currTime.toUnixTime!long * 1000 + 30 * 60 * 1000;
            // Surface as connection_blocked so the banner renders
            // "Connections to this server have been blocked" + the raw
            // ban text in the server log, not an empty "Disconnected:".
            lastDisconnectReason = text;
            emitConnectionFail(text, text);
            logJsonMap("error", "connection",
                "Server BAN detected (ZLINE/GLINE) — 30m backoff",
                ["network": config.name, "message": text, "event": "server_ban_detected"]);
        } else if (isThrottleError(text)) {
            throttledUntil = Clock.currTime.toUnixTime!long * 1000 + 300_000; // 5 min
            lastDisconnectReason = text;
            emitConnectionFail(text, text);
        } else {
            // Non-throttle ERROR still benefits from a structured
            // disconnect reason so the banner doesn't render empty.
            lastDisconnectReason = text;
            emitConnectionFail(text, text);
        }
        state = ConnectionState.disconnecting;
        // Emit DISCONNECTED immediately so the frontend sees the
        // state transition even when the caller (processEvents'
        // data loop) exits without throwing (squashed ERROR path).
        // Without this, the old attempt card stays "Connected" while
        // a new reconnect cycle silently opens a second card.
        import core.atomic : atomicLoad;
        if (atomicLoad(postHandoffQuitAtMs) == 0) {
            try eventChannel.put(IRCRawEvent.makeDisconnected(
                config.name, config.id.toString(), text));
            catch (Exception) {}
        }
        logJsonMap("error", "connection",
            "Server ERROR detected",
            [
                "network": config.name,
                "message": text,
                "event":   "server_error_detected"
            ]);
        logWarn("Server ERROR for %s: %s", config.name, text);
    }

    private void processLine(string line) {
        auto event      = parseIRCLine(line);
        event.network   = config.name;
        event.timestampMs = resolveTimestamp(event);

        // Fix DM echo channel: parser sets channel=nick for all non-channel
        // PRIVMSG/NOTICE (correct for incoming, wrong for our own echo).
        // When echo-message is negotiated, the server echoes our own
        // PRIVMSG as `:ourNick!... PRIVMSG target :text`. Parser then
        // sets channel=ourNick, but the conversation buffer should be
        // `target` (the recipient). Detect our own nick and rewrite.
        if ((event.command == "PRIVMSG" || event.command == "NOTICE")
            && event.nick.length > 0 && sessionNick.length > 0) {
            import std.uni : icmp;
            if (icmp(event.nick, sessionNick) == 0) {
                auto p = event.getParams();
                if (p.length > 0 && p[0].length > 0
                    && p[0][0] != '#' && p[0][0] != '&'
                    && p[0][0] != '+' && p[0][0] != '!') {
                    // Outgoing DM echo — channel should be the target nick,
                    // not our own nick.
                    event.channel = p[0];
                }
            }
        }

        if (event.command == "PING") {
            auto params = event.getParams();
            sendRaw("PONG :" ~ (params.length > 0 ? params[$ - 1] : ""));
            return;
        }

        if (event.command == "PONG") {
            lastPongReceivedSecs = Clock.currTime.toUnixTime!long;
            logJsonMap("debug", "connection",
                "PONG received",
                ["network": config.name,
                 "event": "pong_received"]);
            return; // keepalive reply — don't publish to UI
        }

        // ── Squashed numeric+ERROR detection ────────────────────────────
        // Some IRC servers (SuperNets observed in the wild, June 2026)
        // cram an `ERROR :Closing Link:` onto the same line as the MOTD-end
        // numeric reply: `:server 376 Luis ERROR :Closing Link:`. The
        // parser correctly handles the resulting 376 with that trailing,
        // but the dispatch switch below has no `case "376"` post-registration,
        // so the line silently falls through to `default:` and the
        // ERROR-with-closing-link signal is lost — the connection never
        // transitions to disconnecting and stays open with a dead socket.
        //
        // Detect this pattern by examining the trailing text for canonical
        // ERROR signals ("ERROR" command-name as a sub-token, or "Closing
        // Link:" templated prefix), and re-dispatch as case "ERROR" if so.
        if (looksLikeSquashedError(event.text)) {
            handleServerError(event.text);
            // Continue to also publish the original 376 event for the UI
            // so existing handlers (MIB/366) still get visibility into
            // the channel/topic state.
        }

        string[] quitChannels;
        string[] nickChannels;
        string[] chghostChannels;

        switch (event.command) {

            // ── Channel membership ────────────────────────────────────────────
            case "JOIN":
                auto params = event.getParams();
                if (params.length > 0) {
                    auto chan = normalizeChannelName(params[0]);
                    channelState[chan] = "";
                    if (event.nick == sessionNick) {
                        // Add our nick to channelUsers immediately so the
                        // current user always appears in the member list,
                        // even if the IRC server omits us from RPL_NAMREPLY
                        // (353).  The 353 handler dedups at line 2013, so
                        // adding here early is safe — 353 won't duplicate.
                        if (chan !in channelUsers) channelUsers[chan] = [];
                        if (!channelUsers[chan].canFind(event.nick))
                            channelUsers[chan] ~= event.nick;
                        if (!config.autoJoinChannels.canFind(chan))
                            config.autoJoinChannels ~= chan;
                        auto pi = config.partedChannels.countUntil(chan);
                        if (pi >= 0) config.partedChannels = config.partedChannels.remove(pi);
                        // Request server-side history if available
                        if (hasCap("chathistory")) {
                            sendRaw("CHATHISTORY LATEST " ~ chan ~ " 100");
                        }
                        // Skip the JSON log for our own auto-joins to avoid noise;
                        // we still log JOINs the user initiates from the client.
                        if (!config.autoJoinChannels.canFind(chan)) {
                            logJsonMap("info", "protocol",
                                "JOIN",
                                ["network": config.name,
                                 "nick": event.nick,
                                 "channel": chan,
                                 "event": "join"]);
                        }
                    } else {
                        // extended-join: params may be [channel, account, realname]
                        channelUsers[chan] ~= event.nick;
                        // IRCv3 extended-join: extract account name from params[1]
                        // ("*" means not logged in; empty string means not provided).
                        if (params.length >= 3) {
                          const acct = params[1];
                          if (acct.length > 0)
                            accounts[event.nick] = acct;
                          const rn = params[2];
                          if (rn.length > 0 && rn != event.nick)
                            realnames[event.nick] = rn;
                        }
                        // Extract ident from the event prefix (nick!user@host)
                        if (event.prefix.length > 0) {
                            auto bang = event.prefix.indexOf("!");
                            if (bang > 0) {
                                auto userAt = event.prefix[bang+1 .. $];
                                auto at = userAt.indexOf("@");
                                if (at > 0)
                                    idents[event.nick] = userAt[0 .. at];
                            }
                        }
                        // Fallback: send WHOIS to discover the realname when
                        // extended-join didn't carry it (the older spec
                        // doesn't include realname in JOIN, or the cap is
                        // unavailable). 311/354 will populate realnames[].
                        // Rate-limit to 1/s so a 2000-user channel burst on
                        // SuperNets doesn't flood the server log with 354
                        // WHOX responses.
                        if (event.nick !in realnames) {
                            import std.datetime : Clock;
                            const whoisNow = Clock.currTime.toUnixTime!long;
                            if (whoisNow - lastWhoisTime >= 1) {
                                sendRaw("WHOIS " ~ event.nick);
                                lastWhoisTime = whoisNow;
                            }
                        }
                        // Issue WHO to discover the new user's mode prefix.
                        // The 352 handler promotes bare entries to their
                        // prefixed form without overwriting MODE changes.
                        import std.datetime : Clock;
                        const whoNow = Clock.currTime.toUnixTime!long;
                        if (chan !in lastWhoTime || whoNow - lastWhoTime[chan] >= 2) {
                            sendRaw("WHO " ~ chan ~ " %tn");
                            lastWhoTime[chan] = whoNow;
                        }
                        logJsonMap("debug", "protocol",
                            "JOIN",
                            ["network": config.name,
                             "nick": event.nick,
                             "channel": chan,
                             "event": "join"]);
                    }
                }
                break;

            case "PART":
                auto params = event.getParams();
                if (params.length > 0) {
                    auto chan = normalizeChannelName(params[0]);
                    if (event.nick == sessionNick) {
                        channelState.remove(chan);
                        channelUsers.remove(chan);
                        channelTopics.remove(chan);
                        auto i = config.autoJoinChannels.countUntil(chan);
                        if (i >= 0) config.autoJoinChannels = config.autoJoinChannels.remove(i);
                        if (!config.partedChannels.canFind(chan))
                            config.partedChannels ~= chan;
                    } else {
                        removeFromUsers(chan, event.nick);
                    }
                    logJsonMap("debug", "protocol",
                        "PART",
                        ["network": config.name,
                         "nick": event.nick,
                         "channel": chan,
                         "reason": event.text,
                         "event": "part"]);
                }
                break;

            case "KICK":
                auto params = event.getParams();
                if (params.length >= 2) {
                    auto chan       = normalizeChannelName(params[0]);
                    auto targetNick = params[1];
                    if (targetNick == sessionNick) {
                        channelState.remove(chan);
                        channelUsers.remove(chan);
                        channelTopics.remove(chan);
                        auto i = config.autoJoinChannels.countUntil(chan);
                        if (i >= 0) config.autoJoinChannels = config.autoJoinChannels.remove(i);
                        if (!config.partedChannels.canFind(chan))
                            config.partedChannels ~= chan;
                    } else {
                        removeFromUsers(chan, targetNick);
                    }
                    logJsonMap("info", "protocol",
                        "KICK",
                        ["network": config.name,
                         "channel": chan,
                         "kicker": event.nick,
                         "target": targetNick,
                         "reason": event.text,
                         "event": "kick"]);
                }
                break;

            case "QUIT":
                foreach (chan, ref users; channelUsers) {
                    foreach (i, u; users) {
                        if (stripNickPrefix(u) == event.nick) {
                            quitChannels ~= chan;
                            users = users.remove(i);
                            break;
                        }
                    }
                }
                // Skip logging our own QUITs when we're about to reconnect
                // (it just adds noise during reconnect storms).
                if (event.nick != sessionNick) {
                    logJsonMap("debug", "protocol",
                        "QUIT",
                        ["network": config.name,
                         "nick": event.nick,
                         "reason": event.text,
                         "event": "quit"]);
                }
                break;

                        case "ERROR":
                            handleServerError(event.text);
                            break;

            case "305": // RPL_UNAWAY — no longer away
                isAway = false;
                awayMessage = "";
                break;

            case "306": // RPL_NOWAWAY — marked as away
                isAway = true;
                awayMessage = event.text;
                break;

            case "433": // ERR_NICKNAMEINUSE
            case "432": // ERR_ERRONEUSNICKNAME
                // Post-registration nick change rejected. The user sent /nick
                // via sendRaw which optimistically updated sessionNick. When the
                // server rejects it, revert sessionNick and notify the user.
                if (optimisticNickOld.length > 0) {
                    logInfo("Nick change rejected (cmd=%s): reverting '%s' → '%s' for %s",
                        event.command, sessionNick, optimisticNickOld, config.name);
                    const oldNick = optimisticNickOld;
                    sessionNick = oldNick;
                    optimisticNickOld = "";
                    persistNick(sessionNick);
                    auto notice = IRCRawEvent.makeServerLog(config.name, config.id.toString(),
                        "notice", "Nick change to '" ~ event.text ~ "' rejected — reverting to '" ~ sessionNick ~ "'");
                    eventChannel.put(notice);

                    // Mirror the 433/432 numeric to the frontend as a
                    // synthetic event so the client can revert its
                    // optimistic currentNick and clear pendingSelfNickChange.
                    // Without this signal, the UI keeps the rejected nick
                    // until the next page reload — when the sync
                    // populates currentNick from the engine snapshot, the
                    // user sees their pre-change nick "return" and
                    // concludes the change never happened.
                    auto revertEvt = IRCRawEvent(config.name, event.command);
                    revertEvt.networkId = config.id.toString();
                    revertEvt.text = oldNick;
                    revertEvt.paramsJson = `["` ~ oldNick ~ `"]`;
                    eventChannel.put(revertEvt);
                }
                break;

            case "NICK":
                auto params = event.getParams();
                if (params.length > 0) {
                    const newNick = params[$ - 1];
                    foreach (chan, ref users; channelUsers) {
                        // Mutate EVERY entry that matches the old nick. The
                        // same user can appear twice in channelUsers — once
                        // as a bare entry (from JOIN), once with the host
                        // attached (from 353 with userhost-in-names, or
                        // WHO). Without this, a NICK change leaves the
                        // host-bearing entry stale and the channel roster
                        // ends up showing both the old and the new nick.
                        foreach (i, ref u; users) {
                            if (stripNickPrefix(u) == event.nick) {
                                if (!canFind(nickChannels, chan))
                                    nickChannels ~= chan;
                                u = nickPrefix(u) ~ newNick;
                                // Don't break — keep mutating duplicates.
                            }
                        }
                    }
                    // Two paths for detecting this is OUR nick change:
                    // 1. Normal — event.nick (old nick) matches current sessionNick.
                    // 2. Optimistic — user sent /nick via sendRaw which already
                    //    updated sessionNick. The old nick before the update is
                    //    tracked in optimisticNickOld. We match against that.
                    bool isSelf = false;
                    if (event.nick == sessionNick) {
                        isSelf = true;
                        sessionNick = newNick;
                        persistNick(sessionNick);
                    } else if (optimisticNickOld.length > 0 && event.nick == optimisticNickOld) {
                        isSelf = true;
                        sessionNick = newNick;
                        optimisticNickOld = "";
                        persistNick(sessionNick);
                    }
                    // IRCCloud-style you_nickchange: emit a dedicated message
                    // type for self-nick changes so the frontend can update
                    // currentNick AND all channel member lists from a single
                    // authoritative event, without relying on per-channel NICK
                    // fan-out (which the per-channel broadcast below also does,
                    // but as redundant events that the frontend can ignore for
                    // self-update purposes).
                    // IRCCloud-style you_nickchange: emit a dedicated message
                    // type for self-nick changes so the frontend gets a single
                    // authoritative event that carries [oldNick, newNick] params.
                    // The frontend handler updates currentNick AND ALL channel
                    // member lists immediately, mimicking IRCCloud's realtime
                    // event-driven member list architecture.
                    if (isSelf) {
                        auto youChange = IRCRawEvent(config.name, "you_nickchange");
                        youChange.networkId = config.id.toString();
                        youChange.nick = event.nick;
                        youChange.text = newNick;
                        youChange.setParams([event.nick, newNick]);
                        eventChannel.put(youChange);
                    }
                    logJsonMap("info", "protocol",
                        "NICK",
                        ["network": config.name,
                         "oldNick": event.nick,
                         "newNick": newNick,
                         "event": "nick_change"]);
                }
                break;

            case "CHGHOST":
                foreach (chan, ref users; channelUsers) {
                    foreach (u; users) {
                        string bare = u;
                        if (bare.length > 0 && (bare[0] == '~' || bare[0] == '&' ||
                            bare[0] == '@' || bare[0] == '%' || bare[0] == '+'))
                            bare = bare[1 .. $];
                        if (bare == event.nick) {
                            chghostChannels ~= chan;
                            break;
                        }
                    }
                }
                break;

            // ── Topics ────────────────────────────────────────────────────────
            case "TOPIC":
                auto params = event.getParams();
                if (params.length >= 2) {
                    channelTopics[params[0]] = params[$ - 1];
                    logJsonMap("info", "protocol",
                        "TOPIC",
                        ["network": config.name,
                         "channel": params[0],
                         "topic": params[$ - 1],
                         "by": event.nick,
                         "event": "topic_change"]);
                }
                break;

            case "332":
                // RPL_TOPIC: ":server 332 <nick> <channel> :<topic>" → params = [nick, channel, topic]
                auto params = event.getParams();
                if (params.length >= 3) {
                    channelTopics[params[1]] = params[$ - 1];
                    logJsonMap("debug", "protocol",
                        "TOPIC (332)",
                        ["network": config.name,
                         "channel": params[1],
                         "topic": params[$ - 1],
                         "event": "topic_change"]);
                }
                break;

            // ── NAMES list ────────────────────────────────────────────────────
            case "353":
                auto params = event.getParams();
                if (params.length >= 3) {
                    auto chan  = params[2];
                    auto nicks = params[$ - 1].split(" ");
                    // Defense-in-depth B (engine drift self-heal): the IRC
                    // server only sends RPL_NAMREPLY (353) for channels the
                    // client is currently in. If we receive one and the
                    // channel isn't in channelState, the JOIN self-echo was
                    // dropped somewhere upstream — adopt the channel anyway
                    // so it survives the next channelState.keys-based
                    // snapshot iteration. Without this, the engine could
                    // ship a snapshot that lists the channel under
                    // snapshot.users (which uses channelUsers, not
                    // channelState) but OMIT it from snapshot.buffers
                    // (which iterates channelState.keys). The frontend
                    // would then render the channel as inactive with no
                    // member list, even though NAMES just arrived.
                    // (Symptom reproduced on #superbowl / SuperNets with
                    // 175 names populated but no buffer entry.) The PART /
                    // KICK self handlers at line 2775/2801 already clear
                    // channelState correctly, so adopting on 353 doesn't
                    // hide a genuine leave.
                    if (chan !in channelState) {
                        channelState[chan] = "";
                        if (!config.autoJoinChannels.canFind(chan)
                            && config.partedChannels.countUntil(chan) >= 0) {
                            // Channel we previously parted came back — restore
                            // the autoJoinChannels slot so the next reconnect
                            // re-issues JOIN without prompting.
                            config.partedChannels =
                                config.partedChannels.remove(
                                    config.partedChannels.countUntil(chan));
                            config.autoJoinChannels ~= chan;
                        }
                        logJsonMap("warn", "connection",
                            "channelState drift: adopted channel from RPL_NAMREPLY",
                            ["network":   config.name,
                             "channel":   chan,
                             "reason":    "join-echo-dropped-but-names-arrived",
                             "event":     "channelstate_self_heal"]);
                    }
                    if (chan !in channelUsers) channelUsers[chan] = [];
                    foreach (n; nicks) {
                        if (n.length == 0) continue;
                        // userhost-in-names format: [mode]nick!user@host
                        // Store the full string (as-is) for the frontend,
                        // but extract ident at the engine level too.
                        if (!channelUsers[chan].canFind(n))
                            channelUsers[chan] ~= n;
                        auto bare = stripNickPrefix(n);
                        auto bang = n.indexOf("!");
                        if (bang > 0) {
                            auto userAt = n[bang+1 .. $];
                            auto at = userAt.indexOf("@");
                            if (at > 0 && bare.length > 0)
                                idents[bare] = userAt[0 .. at];
                        }
                    }
                    logJsonMap("info", "protocol",
                        "NAMES (353)",
                        ["network": config.name,
                         "channel": chan,
                         "count": nicks.length.to!string,
                         "totalUsers": channelUsers[chan].length.to!string,
                         "realnames": realnames.length.to!string,
                         "event": "numeric"]);
                    // If we have many users but no realnames, trigger WHO to populate them.
                    // This handles the initial NAMES burst where 366 may be delayed or missed.
                    {
                        import std.datetime : Clock;
                        const whoNow = Clock.currTime.toUnixTime!long;
                        bool needsWho = false;
                        foreach (u; channelUsers[chan]) {
                            const bare = stripNickPrefix(u);
                            if (bare !in realnames) { needsWho = true; break; }
                        }
                        if (needsWho && channelUsers[chan].length > 5
                            && (chan !in lastWhoTime || whoNow - lastWhoTime[chan] >= 2)) {
                            sendRaw("WHO " ~ chan);
                            lastWhoTime[chan] = whoNow;
                            logJsonMap("info", "protocol",
                                "WHO after NAMES(353) to populate realnames",
                                ["network": config.name, "channel": chan, "event": "who_after_names_353"]);
                        }
                    }
                }
                break;
            // ── End of NAMES (RPL_ENDOFNAMES, 366) — trigger WHO to enrich ──
            // After NAMES we have the full member list but no realnames yet
            // (realnames only arrive via extended-join JOIN or WHOIS 311).
            // Issue a WHO to populate both mode prefixes (for any bare
            // entries that still need promotion) and realnames (via our
            // enhanced 352 handler). Rate-limited to 2s per channel to avoid
            // flooding on netsplits or repeated NAMES bursts.
            case "366": {
                auto params = event.getParams();
                logJsonMap("info", "protocol",
                    "366 received",
                    ["network": config.name, "channel": params.length>=2?params[1]:"?", "event": "rpl_endofnames"]);
                if (params.length >= 2) {
                    auto chan = params[1];
                    import std.datetime : Clock;
                    const whoNow = Clock.currTime.toUnixTime!long;
                    if (chan in channelUsers) {
                        bool needsWho = false;
                        foreach (u; channelUsers[chan]) {
                            const bare = stripNickPrefix(u);
                            if (bare !in realnames) { needsWho = true; break; }
                        }
                        logJsonMap("info", "protocol",
                            "366 needsWho check",
                            ["network": config.name, "channel": chan,
                                "needsWho": needsWho?"true":"false",
                                "users": channelUsers[chan].length.to!string,
                                "realnames": realnames.length.to!string,
                                "event": "rpl_endofnames_check"]);
                        if (needsWho && (chan !in lastWhoTime || whoNow - lastWhoTime[chan] >= 2)) {
                            sendRaw("WHO " ~ chan);
                            lastWhoTime[chan] = whoNow;
                            logJsonMap("info", "protocol",
                                "WHO after NAMES to populate realnames",
                                ["network": config.name, "channel": chan, "event": "who_after_names"]);
                        }
                    } else {
                        logJsonMap("info", "protocol",
                            "366 no channelUsers entry",
                            ["network": config.name, "channel": chan, "event": "rpl_endofnames_no_users"]);
                    }
                }
                break;
            }

            // ── WHO reply (RPL_WHOREPLY, 352) ────────────────────────────────
            // Only promotes BARE entries (no existing prefix) so explicit
            // MODE changes like +v are not overwritten by a WHO response
            // that may arrive after the MODE.
            case "352": {
                auto mp = event.getParams();
                logJsonMap("debug", "protocol",
                    "352 received",
                    ["network": config.name,
                        "params": event.getParams().join(" "), "text": event.text,
                        "event": "rpl_whoreply"]);
                if (mp.length >= 7) {
                    auto chan = mp[1];
                    auto nick = mp[5];
                    auto flags = mp[6];
                    char[5] order = ['~', '&', '@', '%', '+'];
                    char chosen = '\0';
                    foreach (c; order) {
                        if (flags.indexOf(c) >= 0) { chosen = c; break; }
                    }
                    // Extract realname from trailing text: ":<hopcount> <realname>"
                    // event.text holds the trailing part stripped of leading ':'.
                    // Hopcount is digits; the real name follows the first space.
                    {
                        auto txt = event.text;
                        if (txt.length > 0) {
                            string rn;
                            auto sp = txt.indexOf(' ');
                            if (sp >= 0) rn = txt[sp+1 .. $].strip();
                            else {
                                size_t i = 0;
                                while (i < txt.length && txt[i] >= '0' && txt[i] <= '9') i++;
                                if (i < txt.length && txt[i] == ' ') rn = txt[i+1 .. $].strip();
                                else if (i == 0) rn = txt.strip();
                            }
                            if (rn.length > 0 && rn != nick) {
                                realnames[nick] = rn;
                                logJsonMap("debug", "protocol",
                                    "WHO realname captured (352)",
                                    ["network": config.name, "nick": nick, "realname": rn, "event": "who_realname"]);
                            }
                        }
                    }
                    if (chosen != '\0' && chan in channelUsers) {
                        bool foundBare = false;
                        size_t j = 0;
                        while (j < channelUsers[chan].length) {
                            auto existing = channelUsers[chan][j];
                            if (stripNickPrefix(existing) == nick) {
                                if (existing.length == 0 ||
                                    (existing[0] != '~' && existing[0] != '&' &&
                                     existing[0] != '@' && existing[0] != '%' &&
                                     existing[0] != '+')) {
                                    // Bare entry — promote it to the
                                    // prefixed form from the WHO response.
                                    if (!foundBare) {
                                        channelUsers[chan][j] = chosen ~ nick;
                                        foundBare = true;
                                        j++;
                                    } else {
                                        // Already promoted an entry for this
                                        // nick; remove the stale duplicate.
                                        channelUsers[chan] = channelUsers[chan][0 .. j]
                                            ~ channelUsers[chan][j + 1 .. $];
                                    }
                                } else if (!foundBare) {
                                    // Already has a prefix (set by 353 or
                                    // MODE). Keep it, but mark as found so
                                    // subsequent bare duplicates get removed.
                                    foundBare = true;
                                    j++;
                                } else {
                                    // Duplicate prefixed entry — remove.
                                    channelUsers[chan] = channelUsers[chan][0 .. j]
                                        ~ channelUsers[chan][j + 1 .. $];
                                }
                            } else {
                                j++;
                            }
                        }
                        // If no entry existed at all (race with JOIN handler),
                        // add the user with the discovered prefix.
                        if (!foundBare) {
                            channelUsers[chan] ~= chosen ~ nick;
                        }
                    }
                }
                return;
            }

            // ── End of WHO (RPL_ENDOFWHO, 315) — no-op for state ───────────
            // WHO reply (352) rows themselves are consumed above (realname
            // cache + channelUsers prefix promotion) and are never
            // published. The matching 315 terminator has no state and no
            // UI consumer — returning here keeps it off the eventChannel
            // and out of Redis scrollback. Without this, SuperNets
            // (which re-WHOs every few seconds to refresh realnames)
            // floods each channel's scrollback with one 315 row per
            // WHO, pushing the user's actual PRIVMSGs out of the
            // displayed window on every page load and making recent
            // messages appear to "disappear" behind a wall of
            // "End of WHO list" noise.
            case "315":
                return;

            // ── WHOX reply (RPL_WHOX, 354) — engine consumes nothing ──────
            // The engine issues `WHO %tn` from the JOIN handler to populate
            // channelUsers with each user's mode prefix; the WHO reply (352)
            // does that work. The WHOX (354) variant is only sent when the
            // server has the `WHOX` capability enabled AND we asked for the
            // extended token set — on SuperNets / UnrealIRCd this is a 2000+
            // line flood per channel join. The engine does not use any WHOX
            // fields, and the frontend has no consumer for them either (the
            // `classifyServerLog` filter in the Svelte side just drops them
            // as `skip`). Returning here keeps them off the eventChannel
            // entirely — saves WS bandwidth and prevents them from being
            // persisted to Redis scrollback where they'd burn storage and
            // re-flood the timeline on every reconnect / page load.
            case "354":
                return;

            // ── Away notify (away-notify cap) ─────────────────────────────────
            case "AWAY":
                // Broadcast to all channels this user is in so the UI can update.
                // event.text is the away message (empty = returned from away).
                foreach (chan, users; channelUsers) {
                    foreach (u; users) {
                        if (stripNickPrefix(u) == event.nick) {
                            auto dup        = event;
                            dup.channel     = chan;
                            dup.id          = randomUUID().toString();
                            eventChannel.put(dup);
                        }
                    }
                }
                return; // don't double-publish below

            // ── Account notify (account-notify cap) ──────────────────────────
            case "ACCOUNT":
                // params[0] = account name or "*" (logged out)
                // Broadcast to shared channels
                foreach (chan, users; channelUsers) {
                    foreach (u; users) {
                        if (stripNickPrefix(u) == event.nick) {
                            auto dup    = event;
                            dup.channel = chan;
                            dup.id      = randomUUID().toString();
                            eventChannel.put(dup);
                        }
                    }
                }
                return;

            // ── ISUPPORT ─────────────────────────────────────────────────────
            case "005":
                auto params = event.getParams();
                bool mapChanged = false;
                foreach (token; params[1 .. $ > 1 ? $ - 1 : $]) {
                    if (token.length == 0) continue;
                    immutable auto before = isupportMap.length;
                    applyIsupport(serverFeatures, isupportMap, token);
                    if (isupportMap.length != before) mapChanged = true;
                }
                if (mapChanged) publishIsupportEvent();
                break;

            // ── CTCP ──────────────────────────────────────────────────────────
            case "PRIVMSG":
                if (handlePrivmsg(event)) return; // consumed; don't publish
                // Non-CTCP channel-target PRIVMSGs only — query PRIVMSGs are
                // skipped to avoid logging the content of every DM.
                {
                    auto mp = event.getParams();
                    auto to = mp.length > 0 ? mp[0] : "";
                    if (to.length > 0 && (to[0] == '#' || to[0] == '&')) {
                        logJsonMap("debug", "protocol",
                            "PRIVMSG",
                            ["network": config.name,
                             "from": event.nick,
                             "to": to,
                             "isQuery": "false",
                             "event": "privmsg"]);
                    }
                }
                break;

            // ── NOTICE ─────────────────────────────────────────────────────────
            case "NOTICE":
                {
                    auto mp = event.getParams();
                    auto to = mp.length > 0 ? mp[0] : "";
                    logJsonMap("debug", "protocol",
                        "NOTICE",
                        ["network": config.name,
                         "from": event.nick,
                         "to": to,
                         "event": "notice"]);
                }
                break;

            // ── INVITE ─────────────────────────────────────────────────────────
            case "INVITE":
                {
                    auto mp = event.getParams();
                    auto to      = mp.length > 0 ? mp[0] : "";
                    auto channel = mp.length > 1 ? mp[1] : "";
                    logJsonMap("info", "protocol",
                        "INVITE",
                        ["network": config.name,
                         "from": event.nick,
                         "to": to,
                         "channel": channel,
                         "event": "invite"]);
                }
                break;

            // ── BATCH (chathistory) ──────────────────────────────────────────
            case "BATCH":
                auto params = event.getParams();
                if (params.length >= 2) {
                    auto ref_ = params[0];
                    const batchType = params[1];
                    if (ref_.startsWith("+")) {
                        activeBatchRef = ref_[1 .. $];
                        activeBatchType = batchType;
                        activeBatchTarget = params.length >= 3 ? params[2] : "";
                    } else if (ref_.startsWith("-")) {
                        // Batch ended — clear in-flight flag for the channel
                        // so the next CHATHISTORY request can go through.
                        if (activeBatchType == "chathistory" && activeBatchTarget.length > 0) {
                            clearChathistoryInFlight(activeBatchTarget);
                        }
                        activeBatchRef = "";
                        activeBatchType = "";
                        activeBatchTarget = "";
                    }
                }
                return; // Don't publish BATCH events to the UI

            // ── Channel mode (ban/quiet/op/voice/etc.) ───────────────────────
            case "MODE":
                auto mp = event.getParams();
                if (mp.length > 0 && (mp[0].startsWith("#") || mp[0].startsWith("&"))) {
                    event.channel = mp[0];
                    // Sync channelUsers with MODE changes so periodic
                    // snapshots preserve the correct prefixes. Without this,
                    // ops/voice set via MODE are lost on the next sync
                    // because the frontend gets the stale snapshot and
                    // overwrites its live MODE-driven update.
                    if (mp.length >= 2) {
                        logJsonMap("info", "protocol",
                            "MODE",
                            ["network": config.name,
                             "channel": mp[0],
                             "mode": mp.length >= 2 ? mp[1] : "",
                             "by": event.nick,
                             "event": "mode_change"]);
                    }
                    if (mp.length >= 3) {
                        const chan = mp[0];
                        auto modeStr = mp[1];
                        // Modifying the array through `ref` inside a foreach
                        // over `*members` (AA value pointer) can leave stale
                        // references for subsequent outer-loop iterations.
                        // Re-read the AA value on each mode character so
                        // multi-target MODE commands like `+vv alice bob`
                        // correctly find and update both targets.
                        bool adding = true;
                        size_t targetIdx = 2;
                        foreach (ch; modeStr) {
                            if (ch == '+') { adding = true; continue; }
                            if (ch == '-') { adding = false; continue; }
                            if (ch == 'q' || ch == 'a' || ch == 'o' || ch == 'O' || ch == 'h' || ch == 'v') {
                                if (targetIdx >= mp.length) break;
                                const targetNick = mp[targetIdx++];
                                    if (auto members = chan in channelUsers) {
                                    foreach (i, ref u; *members) {
                                        if (stripNickPrefix(u) == targetNick) {
                                            if (adding) {
                                                char newPrefix;
                                                switch (ch) {
                                                    case 'q': newPrefix = '~'; break;
                                                    case 'a': newPrefix = '&'; break;
                                                    case 'o': newPrefix = '@'; break;
                                                    case 'O': newPrefix = '@'; break;
                                                    case 'h': newPrefix = '%'; break;
                                                    case 'v': newPrefix = '+'; break;
                                                    default: break;
                                                }
                                                if (newPrefix) {
                                                    if (u.length > 0 && (u[0] == '~' || u[0] == '&'
                                                        || u[0] == '@' || u[0] == '%'
                                                        || u[0] == '+'))
                                                        u = newPrefix ~ u[1 .. $];
                                                    else
                                                        u = newPrefix ~ u;
                                                }
                                            } else {
                                                if (u.length > 0 && (u[0] == '~' || u[0] == '&'
                                                    || u[0] == '@' || u[0] == '%'
                                                    || u[0] == '+'))
                                                        u = u[1 .. $];
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                break;

            case "671": // RPL_WHOISSECURE — suppress "is using a Secure Connection" noise
                return;

            // ── W1-T08: RPL_TRYAGAIN (263) — Server busy ─────────────────
            case "263": {
                import ircfiber.irc.parser : extractTempUnavailableCountdown;
                auto countdownMs = extractTempUnavailableCountdown(event);
                auto tue = IRCRawEvent(config.name, "temp_unavailable");
                tue.networkId = config.id.toString();
                tue.addTag("countdown_ms", countdownMs.to!string);
                tue.addTag("serverTs", event.timestampMs.to!string);
                eventChannel.put(tue);
                return; // don't publish as regular numeric event
            }

            default:
                // Numeric replies (3 digits): surface warn-level ones
                // (433/464/etc.) and skip already-handled numerics (001,
                // 311, 353, 354, 376, 422, …). The `354` entry was added
                // because the SuperNets WHOX flood now returns early at
                // the main switch above — this guard is the symmetric
                // protection in case a future code path bypasses that.
                if (event.command.length == 3) {
                    const bool isHandled = (event.command == "001" || event.command == "305"
                        || event.command == "306" || event.command == "311"
                        || event.command == "354" || event.command == "376"
                        || event.command == "422" || event.command == "432"
                        || event.command == "433" || event.command == "671"
                        || event.command == "903" || event.command == "904"
                        || event.command == "905" || event.command == "906"
                        || event.command == "907");
                    if (!isHandled && isWarnNumeric(event.command)) {
                        logJsonMap("warn", "protocol",
                            "Numeric reply",
                            ["network": config.name,
                             "numeric": event.command,
                             "message": event.text,
                             "event": "numeric"]);
                    }
                }
                break;
        }

        // Track private query buffers for both incoming and outgoing DMs.
        // The old check `channel.length==0` never fired because parser always
        // sets channel for PRIVMSG. Instead detect DM by target not being a
        // channel prefix.
        if (event.command == "PRIVMSG" || event.command == "NOTICE") {
            auto p = event.getParams();
            if (p.length > 0 && p[0].length > 0
                && p[0][0] != '#' && p[0][0] != '&'
                && p[0][0] != '+' && p[0][0] != '!') {
                string other;
                import std.uni : icmp;
                if (event.nick.length > 0 && sessionNick.length > 0
                    && icmp(event.nick, sessionNick) == 0) {
                    other = p[0];
                } else {
                    other = event.nick;
                }
                if (other.length > 0 && !queryBuffers.canFind(other)) {
                    queryBuffers ~= other;
                }
            }
        }

        // Set channel for channel-scoped events that didn't set it explicitly.
        // For PRIVMSG the channel is params[0] (e.g. "#scroll").  For numeric
        // replies like 404 the target nick is params[0] and the channel is
        // params[1] (e.g. ":server 404 nick #channel :reason").  Walk all
        // params to find the first channel-like value.
        if (event.channel.length == 0) {
            auto p = event.getParams();
            foreach (param; p) {
                if (param.length > 0 && (param[0] == '#' || param[0] == '&')) {
                    event.channel = param;
                    break;
                }
            }
        }
        // DM fallback: parser no longer sets channel for non-channel PRIVMSG
        // (see parser.d). Resolve to counterparty here session-aware.
        if (event.channel.length == 0
            && (event.command == "PRIVMSG" || event.command == "NOTICE")) {
            auto p = event.getParams();
            if (p.length > 0 && p[0].length > 0
                && p[0][0] != '#' && p[0][0] != '&'
                && p[0][0] != '+' && p[0][0] != '!') {
                import std.uni : icmp;
                if (event.nick.length > 0 && sessionNick.length > 0
                    && icmp(event.nick, sessionNick) == 0) {
                    event.channel = p[0];
                } else {
                    event.channel = event.nick;
                }
            }
        }

        // If this event is inside a chathistory batch, tag it
        if (activeBatchType == "chathistory" && activeBatchRef.length > 0) {
            event.addTag("batch", "chathistory");
        }

        // Correlate labeled echoes (labeled-response cap) and record msgids
        // so CHATHISTORY pagination has stable cursors. This runs for both
        // live messages and those arriving inside a chathistory batch.
        if (event.command == "PRIVMSG" || event.command == "NOTICE"
            || event.command == "TAGMSG") {
            auto msgLabel = event.getTag("label");
            if (msgLabel.length > 0 && clearPendingLabel(msgLabel)) {
                event.addTag("labeled_echo", "true");
            }
            // Self-echo detection: tag PRIVMSG/NOTICE events from the
            // session's own nick. This runs regardless of msgid presence
            // so the suppression below catches all echo paths, including
            // servers that don't assign msgid tags.
            if (event.nick == sessionNick
                && (event.command == "PRIVMSG" || event.command == "NOTICE")) {
                event.addTag("self_echo", "true");
                // IRCCloud-style duplicate suppression: when the IRC server
                // echoes our own PRIVMSG back but echo-message was NOT
                // negotiated, the engine already emitted a synthetic
                // self-message event (emitSyntheticSelfMessage). Publishing
                // the server echo too creates a duplicate in the UI because
                // the synthetic (with label) replaces the optimistic, while
                // the server echo (no label if labeled-response is also
                // absent) gets a different eid and appends as a second copy.
                //
                // The labeled-response path is safe: the label was correlated
                // above, so labeled_echo is set and the frontend can do
                // in-place replacement. Without it, there's no correlation \xe2\x80\x94
                // skip the echo entirely.
                if (!hasCap("echo-message") && event.getTag("labeled_echo") != "true") {
                    return;
                }
            }
            auto msgid = event.getTag("msgid");
            if (msgid.length > 0) {
                if (event.command == "PRIVMSG" || event.command == "NOTICE") {
                    // Update per-channel msgid cursors for CHATHISTORY
                    // pagination. We use the buffer's "own" channel \xe2\x80\x94 for
                    // PRIVMSGs the params[0] is the recipient, so the
                    // channel is whichever buffer this event ends up in.
                    // The frontend will fetch the buffer's actual name; on
                    // the engine we record against the channel the
                    // event is being routed to.
                    string bufName = event.channel.length > 0 ? event.channel
                        : (event.nick.length > 0 ? event.nick : "");
                    if (bufName.length > 0) recordChannelMsgid(bufName, msgid);
                } else if (event.command == "TAGMSG" && event.channel.length > 0) {
                    // +react, +typing, etc. carry msgid referring to the
                    // target message. We don't update cursors for these.
                }
            }
        }

        eventChannel.put(event);

        // Broadcast QUIT / NICK / CHGHOST events to each affected channel
        foreach (chan; quitChannels) {
            auto dup     = event;
            dup.channel  = chan;
            dup.id       = randomUUID().toString();
            eventChannel.put(dup);
        }
        foreach (chan; nickChannels) {
            auto dup    = event;
            dup.channel = chan;
            dup.id      = randomUUID().toString();
            eventChannel.put(dup);
        }
        foreach (chan; chghostChannels) {
            auto dup    = event;
            dup.channel = chan;
            dup.id      = randomUUID().toString();
            eventChannel.put(dup);
        }
    }

    // ── CTCP dispatch ─────────────────────────────────────────────────────────

    /// Returns true if the CTCP was handled AND should not be published to the event bus.
    private bool handlePrivmsg(ref IRCRawEvent event) {
        if (!isCtcp(event.text)) return false;

        auto ctcp  = parseCtcp(event.text);
        auto cmd   = ctcp[0];
        auto param = ctcp[1];
        logJsonMap("debug", "protocol",
            "CTCP",
            ["network": config.name,
             "from": event.nick,
             "type": cmd,
             "event": "ctcp"]);

        switch (cmd) {
            case "ACTION":
                // Leave event intact; JS renders \x01ACTION...\x01 as /me.
                return false; // still publish to UI

            case "VERSION":
                sendRaw("NOTICE " ~ event.nick ~ " :" ~ ctcpReply("VERSION", "IRC Fiber 1.0 (vibe.d)"));
                return true; // don't show in UI

            case "PING":
                sendRaw("NOTICE " ~ event.nick ~ " :" ~ ctcpReply("PING", param));
                return true;

            case "TIME":
                import std.datetime : Clock;
                sendRaw("NOTICE " ~ event.nick ~ " :" ~ ctcpReply("TIME", Clock.currTime.toString()));
                return true;

            case "CLIENTINFO":
                sendRaw("NOTICE " ~ event.nick ~ " :" ~ ctcpReply("CLIENTINFO", "ACTION VERSION PING TIME CLIENTINFO"));
                return true;

            default:
                return false; // unknown CTCP — let it pass through
        }
    }

    // ── IRC line parser ───────────────────────────────────────────────────────

    private IRCRawEvent parseIRCLine(string line) {
        import ircfiber.irc.parser : parseIRCLinePublic;
        return parseIRCLinePublic(line, config);
    }

    // ── Timestamp resolution ──────────────────────────────────────────────────

    /// Use `server-time` tag if present, otherwise fall back to local wall clock.
    private long resolveTimestamp(const ref IRCRawEvent event) {
        // server-time tag value: 2023-01-01T12:00:00.000Z
        auto ts = event.getTag("time");
        if (ts.length > 0) {
            try {
                import std.datetime : SysTime, DateTime, UTC;
                // vibe.d's SysTime.fromISOExtString handles RFC3339/ISO8601
                auto st = SysTime.fromISOExtString(ts);
                return st.toUnixTime!long * 1000 + st.fracSecs.total!"msecs";
            } catch (Exception) {}
        }
        return Clock.currTime.toUnixTime!long * 1000;
    }

    // ── Outbound queue ────────────────────────────────────────────────────────

    private void processOutboundQueue() {
        if (outboundQueue.length == 0) return;
        if (state != ConnectionState.connected) return;

        auto queue = outboundQueue;
        outboundQueue = [];

        foreach (l; queue) writeRaw(l);
    }

    private void writeRaw(string line) {
        if (tlsStream !is null) {
            try {
                tlsStream.write((line ~ "\r\n").dup);
                tlsStream.flush();
            } catch (Exception e) {
                // The TLS stream is now in an unrecoverable state. Release
                // it so the next writeRaw() falls into the transportAlive
                // branch and the connection state machine can react via
                // handleDisconnection(), instead of silently looping on the
                // same dead stream and flooding the consumer with identical
                // "Failed to parse command" warnings for every queued msg.
                logJsonMap("error", "connection",
                    "TLS write failed — marking stream dead",
                    [
                        "network":   config.name,
                        "networkId": config.id.toString(),
                        "error":     e.msg,
                        "event":     "tls_write_fail"
                    ]);
                logWarn("writeRaw: TLS write failed for %s (%s) — stream torn down",
                    config.name, e.msg);
                try { tlsStream.finalize(); } catch (Exception) {}
                try { tlsStream.destroy(); } catch (Exception) {}
                tlsStream = null;
                throw e;
            }
        } else if (transportAlive) {
            try transportWrite(line);
            catch (Exception e) {
                logJsonMap("error", "connection",
                    "Transport write failed",
                    [
                        "network":   config.name,
                        "networkId": config.id.toString(),
                        "error":     e.msg,
                        "event":     "transport_write_fail"
                    ]);
                throw e;
            }
        } else {
            // No active stream AND no live transport — the message would
            // be silently dropped. Emit one structured event PER
            // disconnect cycle (not per-message) so the operator sees
            // *that* the connection is dead but isn't drowned in
            // identical warnings. The flag is reset on successful
            // (re-)connection.
            if (!droppedNoConnWarned) {
                logJsonMap("warn", "connection",
                    "Outbound message dropped — no active connection",
                    [
                        "network":   config.name,
                        "networkId": config.id.toString(),
                        "queueLen":  outboundQueue.length.to!string,
                        "state":     state.to!string,
                        "event":     "cmd_dropped_no_conn"
                    ]);
                droppedNoConnWarned = true;
            }
            // If the engine THINKS we're connected but the transport is
            // actually dead (FD died, TLS teardown error, etc.), the
            // network state is lying. Throw an exception so the outer
            // catch block in runConnectionLoop() runs
            // handleDisconnection() (which tears down transports) and
            // then schedules a fresh reconnect with backoff. Without
            // this, new JOINs and other commands silently disappear
            // into the void and the user sees "Connected" with a
            // frozen buffer list for up to the 120 s idle-heuristic
            // window.
            if (state == ConnectionState.connected) {
                throw new Exception("Stale connection detected: transport dead but"
                    ~ " state=connected — forcing reconnect for " ~ config.name);
            }
        }
    }

    // ── Disconnect / cleanup ──────────────────────────────────────────────────

    private void handleDisconnection() {
        withSpan("irc.disconnect", ["network": config.name, "reason": lastDisconnectReason], (ref Span s) {
            state = ConnectionState.disconnected;
            try {
                if (tlsStream) {
                    tlsStream.finalize();
                    tlsStream.destroy();
                    tlsStream = null;
                }
            } catch (Exception e) {
                logWarn("Error cleaning up TLS stream for %s: %s", config.host, e.msg);
                tlsStream = null;
            }
            try {
                transportClose();
            } catch (Exception e) {
                logWarn("Error closing transport for %s: %s", config.host, e.msg);
            }
            // Emit DISCONNECTED lifecycle event so the frontend always
            // learns about the state transition, even when the disconnect
            // happens outside the catch block (e.g. processEvents data-loss
            // detection or handleServerError squashed ERROR).
            import core.atomic : atomicLoad;
            if (atomicLoad(postHandoffQuitAtMs) == 0) {
                try eventChannel.put(IRCRawEvent.makeDisconnected(
                    config.name, config.id.toString(),
                    lastDisconnectReason.length > 0 ? lastDisconnectReason : "Connection lost"));
                catch (Exception) {}
            }
            // W1-T01: structured fail-info emit. Sits next to the legacy
            // DISCONNECTED event so the frontend's `applyFail` and the
            // legacy `disconnectReason` write can co-exist (per plan R2
            // dual-emit). Skipped on post-handoff exits because the
            // disconnect is intentional and the new engine already has
            // the socket — emitting a fail would surface a phantom
            // "Disconnected" banner to the user mid-handoff.
            //
            // W1-T01-rev1: also skip when the user (or admin) called
            // stop() — `isShutdownRequested == true` means the
            // disconnect was intentional and the frontend should see
            // the no-fail "disconnected" branch instead of a
            // "Disconnected: <reason>" banner with a Reconnect button.
            // Without this guard, every /quit click produced a
            // CONNECTION_FAIL event + a populated snap.failInfo,
            // leaving the banner stuck on the user until the next
            // successful reconnect.
            if (atomicLoad(postHandoffQuitAtMs) == 0 && !isShutdownRequested) {
                emitConnectionFail(
                    lastDisconnectReason.length > 0 ? lastDisconnectReason : "connection_lost",
                    lastErrorText);
            }
            logJsonMap("info", "connection",
                "Disconnected",
                ["network": config.name,
                 "reason": lastDisconnectReason.length > 0 ? lastDisconnectReason : "connection_lost",
                 "attempt": backoff.currentAttempt().to!string,
                 "event": "disconnected"]);
            // Record host failure for the circuit breaker — unless this is
            // a shutdown (user-initiated disconnect), which shouldn't count.
            if (!isShutdownRequested) {
                recordHostFailure(config.host, config.port);
            }
            s.setStatusOk();
        });
    }

    private bool shouldReconnect() {
        if (isShutdownRequested) return false;
        // Bug 3 fix (Jul 8 2026): respect the disabled flag mid-loop too.
        // Without this, a network that's administratively disabled but
        // already inside the connection loop would reconnect indefinitely.
        if (config.disabled) {
            // Re-enter the idle loop in `runConnectionLoop` — it owns
            // the per-iteration config.disabled check.
            return false;
        }
        return true;
    }

    private void cleanup() { handleDisconnection(); }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private bool waitForData(Duration timeout) {
        return connection.waitForData(timeout);
    }

    private size_t readFromStream(ubyte[] buffer, Duration timeout = 0.seconds) {
        if (tlsStream !is null) return safeTLSRead(tlsStream, buffer);
        if (adoptedSocket !is null) return adoptedSocket.read(buffer);
        // Plain TCP: gate on waitForData() with a (potentially zero) timeout.
        // Calling connection.read(IOMode.once) with no data available causes
        // the vibe.d read loop to busy-poll until readTimeout expires on this
        // platform (cfrunloop/kqueue), burning a full CPU core per idle
        // connection.  Only enter read() when data is buffered.
        //
        // During registration (performRegistration) we pass a non-zero timeout
        // so the fiber actually blocks until data arrives.  During the main
        // event loop (processEvents) we use 0.seconds and rely on the outer
        // sleep loop for pacing — the zero keeps the loop responsive.
        if (!connection.waitForData(timeout)) return 0;
        return connection.read(buffer, IOMode.once);
    }

    private void removeFromUsers(string chan, string nick) {
        if (auto users = chan in channelUsers) {
            foreach (i, u; *users) {
                if (stripNickPrefix(u) == nick) {
                    *users = (*users).remove(i);
                    break;
                }
            }
        }
    }

    /// Keywords servers use to indicate the client is connecting too fast
    /// and should wait before trying again.
    private static immutable string[] THROTTLE_KEYWORDS = [
        "throttled", "reconnecting too fast", "excess flood",
        "too many connections", "rate limit", "try again later",
        "slow down", "you are banned", "temporary ban",
    ];

    /// Keywords that indicate a hard ban (ZLINE/GLINE/KLINE/ELINE) — the
    /// server has explicitly rejected this IP/nick and will keep rejecting
    /// until the ban expires (often hours/days). We treat this as a
    /// non-retriable block with a much longer backoff so we don't hammer
    /// and don't freeze the UI on a 5s loop that immediately re-hits the
    /// same wall and then parks for 5 min with no countdown.
    private static immutable string[] BAN_KEYWORDS = [
        "z-lined", "z:lined", "zline", "z:line",
        "g-lined", "g:lined", "gline", "g:line",
        "k-lined", "k:lined", "kline", "k:line",
        "e-lined", "e:lined", "eline",
        "enter the void",
        "you are banned",
        "banned from",
        "permanently banned",
    ];

    /// Returns `true` if `text` contains any throttle-related keywords.
    private static bool isThrottleError(string text) {
        if (text.length == 0) return false;
        import std.string : toLower;
        auto lower = toLower(text);
        foreach (kw; THROTTLE_KEYWORDS) {
            if (lower.indexOf(kw) >= 0) return true;
        }
        return false;
    }

    /// Returns `true` if `text` indicates a hard ban.
    private static bool isBanError(string text) {
        if (text.length == 0) return false;
        import std.string : toLower;
        auto lower = toLower(text);
        foreach (kw; BAN_KEYWORDS) {
            if (lower.indexOf(kw) >= 0) return true;
        }
        return false;
    }

    /// Numeric replies worth logging at warn/error level. These signal
    /// recoverable failures the operator should know about. Routine
    /// numerics (372 MOTD line, 318 end of WHOIS, etc.) are deliberately
    /// omitted so we don't flood the structured log.
    private static bool isWarnNumeric(string cmd) {
        switch (cmd) {
            // Auth / capability / mode issues
            case "464": // ERR_PASSWDMISMATCH
            case "465": // ERR_YOUREBANNEDCREEP
            case "467": // ERR_KEYSET
            case "471": // ERR_CHANNELISFULL
            case "473": // ERR_INVITEONLYCHAN
            case "474": // ERR_BANNEDFROMCHAN
            case "475": // ERR_BADCHANNELKEY
            case "476": // ERR_BADCHANMASK
            case "477": // ERR_NOCHANMODES
            case "482": // ERR_CHANOPRIVSNEEDED
            case "489": // ERR_SECUREONLYCHAN
            case "491": // ERR_NOOPERHOST
            // Nick / channel / user errors
            case "401": // ERR_NOSUCHNICK
            case "403": // ERR_NOSUCHCHANNEL
            case "404": // ERR_CANNOTSENDTOCHAN
            case "405": // ERR_TOOMANYCHANNELS
            case "407": // ERR_TOOMANYTARGETS
            case "411": // ERR_NORECIPIENT
            case "412": // ERR_NOTEXTTOSEND
            case "421": // ERR_UNKNOWNCOMMAND
            case "431": // ERR_NONICKNAMEGIVEN
            case "436": // ERR_NICKCOLLISION
            case "437": // ERR_UNAVAILRESOURCE
            case "441": // ERR_USERNOTINCHANNEL
            case "442": // ERR_NOTONCHANNEL
            case "443": // ERR_USERONCHANNEL
            case "444": // ERR_NOLOGIN
            case "445": // ERR_SUMMONDISABLED
            case "446": // ERR_USERSDISABLED
            case "451": // ERR_NOTREGISTERED
            case "458": // ERR_NICKTOOFAST
            case "461": // ERR_NEEDMOREPARAMS
            case "462": // ERR_ALREADYREGISTERED
            case "463": // ERR_NOPERMFORHOST
            case "466": // ERR_PASSWDMISMATCH (alt)
            case "468": // ERR_YOUREBANNED (alt)
            case "470": // ERR_LINELEN
            case "472": // ERR_UNKNOWNMODE
            case "478": // ERR_BANLISTFULL
            case "481": // ERR_NOPRIVILEGES
            case "483": // ERR_CANTKILLSERVER
            case "484": // ERR_RESTRICTED
            case "485": // ERR_UNIQOPPRIVSNEEDED
            case "486": // ERR_NONONREG
            case "487": // ERR_NOSERVICEHOST
            case "488": // ERR_NOSCHAN
            case "501": // ERR_UMODEUNKNOWNFLAG
            case "502": // ERR_USERSDONTMATCH
                return true;
            default:
                return false;
        }
    }

    private string extractQuitReason(string errorText) {
        auto start = errorText.indexOf("(Quit:");
        if (start >= 0) {
            start += 6;
            auto end = errorText.indexOf(")", start);
            if (end > start) return errorText[start .. end].strip();
        }
        auto lastOpen  = errorText.lastIndexOf("(");
        if (lastOpen >= 0) {
            auto lastClose = errorText.lastIndexOf(")");
            if (lastClose > lastOpen) return errorText[lastOpen + 1 .. lastClose].strip();
        }
        return "";
    }

    /// W1-T01 (plan R1): substring-keyed map from disconnect reason
    /// text to structured (type, reason). Keys are matched
    /// case-insensitively against the disconnect reason. Order
    /// matters — more-specific entries must come before general
    /// ones (e.g. `"ssl_certificate_error"` before `"ssl_error"`).
    ///
    /// Each entry maps to one of the IRCCloud-style failInfo
    /// categories:
    ///   "connecting_failed" — the common case (DNS/TCP/TLS handshake)
    ///   "killed"            — server actively disconnected us
    private static immutable struct ReasonMapEntry {
        string substring;
        string type_;
        string reason;
    }
    private static immutable ReasonMapEntry[] reasonMap = [
        { "ssl_certificate_error",  "connecting_failed", "ssl_certificate_error" },
        { "ssl_verify_error",       "connecting_failed", "ssl_certificate_error" },
        { "ssl_error",              "connecting_failed", "ssl_error"             },
        { "nxdomain",               "connecting_failed", "nxdomain"              },
        { "econnrefused",           "connecting_failed", "econnrefused"          },
        { "etimedout",              "connecting_failed", "etimedout"             },
        { "timeout",                "connecting_failed", "etimedout"             },
        { "pool_lost",              "connecting_failed", "pool_lost"             },
        { "enetdown",               "connecting_failed", "enetdown"              },
        { "ehostunreach",           "connecting_failed", "ehostunreach"          },
        { "crash",                  "connecting_failed", "crash"                 },
        { "tls_read_error_post_001","connecting_failed", "ssl_error"             },
        { "welcome_timeout",        "connecting_failed", "etimedout"             },
        // Ban family — ZLINE/GLINE/KLINE/ELINE. Must come before the
        // generic "banned" catch so the specific ban type is preserved.
        // The frontend renders these as `connection_blocked` ("Connections
        // to this server have been blocked") which is the correct UX for
        // a ban: no countdown spin, just a clear blocked headline until
        // the ban expires or the user changes nick/IP.
        { "z-lined",                "connection_blocked", "zlined"               },
        { "z:lined",                "connection_blocked", "zlined"               },
        { "zline",                  "connection_blocked", "zlined"               },
        { "enter the void",         "connection_blocked", "zlined"               },
        { "g-lined",                "connection_blocked", "glined"               },
        { "g:lined",                "connection_blocked", "glined"               },
        { "gline",                  "connection_blocked", "glined"               },
        { "k-lined",                "connection_blocked", "klined"               },
        { "k:lined",                "connection_blocked", "klined"               },
        { "kline",                  "connection_blocked", "klined"               },
        { "e-lined",                "connection_blocked", "elined"               },
        { "eline",                  "connection_blocked", "elined"               },
        // Killed family — server actively disconnected us. The exact
        // reason key on the wire is "killed" so the frontend's
        // renderReasons.ts table can dispatch cleanly.
        { "killed",                 "killed",            "killed"                },
        // W1-T01-rev1: lowercase the three mixed-case entries that the
        // review flagged as dead mappings. The parser lowercases the
        // incoming reason (see parseReasonToFailInfo below) so these
        // substrings must also be lowercase to ever match. Mixed-case
        // form would have fallen through to the catch-all
        // "connecting_failed" branch in the previous commit.
        { "overridden",             "killed",            "killed"                },
        { "err_nicknameinuse",      "killed",            "killed"                },
        { "connection closed",      "connecting_failed", "closed"                },
    ];

    /// W1-T01: build a FailInfo from a disconnect reason text + the
    /// engine's lastErrorText (used for SSL verification detail).
    /// Substring matching is case-insensitive. When no keyword matches
    /// the defaults are `type="connecting_failed"`, `reason=<unchanged>`
    /// so unknown reasons still reach the frontend's renderReasons.ts
    /// table and render as the raw reason string (per plan TG1: unknown
    /// reasons pass through unchanged).
    package(ircfiber) FailInfo parseReasonToFailInfo(string reason, string lastErrorText) const {
        FailInfo info;
        if (reason.length == 0) {
            // Defensive: empty reason yields a generic connecting_failed
            // with a synthetic key so the frontend renders SOMETHING
            // (raw reason = "" would render as empty, which is worse).
            info.type_ = "connecting_failed";
            info.reason = "connection_lost";
            return info;
        }
        auto lower = toLower(reason);
        foreach (entry; reasonMap) {
            if (lower.canFind(entry.substring)) {
                info.type_ = entry.type_;
                info.reason = entry.reason;
                break;
            }
        }
        if (info.type_.length == 0) {
            // No keyword matched — emit as connecting_failed with the
            // raw reason so the frontend's renderReasons.ts table can
            // still look it up. Falls through to renderReason(reason)
            // which returns the input unchanged for unknown keys (the
            // "disconnect: {reason}" branch).
            info.type_ = "connecting_failed";
            info.reason = reason;
        }
        // For `type_=="killed"`, capture the kill description
        // (parenthesised fragment or full reason) into killedReason
        // so the Wave 3 banner renders "Disconnected - Killed: X".
        if (info.type_ == "killed") {
            auto parenStart = reason.indexOf('(');
            if (parenStart > 0 && reason.canFind(')')) {
                info.killedReason = reason[parenStart .. $].strip();
            } else {
                info.killedReason = reason;
            }
        }
        // For SSL verification errors, populate the nested
        // sslVerifyError object so the frontend's renderSSLVerify can
        // look up the human string. v1 does a best-effort extraction:
        // if lastErrorText contains a "(type, error)" pair we split
        // it; otherwise we use the full lastErrorText as the "error"
        // with a generic "bad_cert" type so the frontend renders
        // "bad_cert: <lastErrorText>" which is at least informative.
        if (info.reason == "ssl_certificate_error" && lastErrorText.length > 0) {
            // Best-effort: look for the vibe.d TLS error pattern
            // "certificate verify failed: <detail>". Anything inside
            // the first "(" is the structured (type, error) detail.
            string detail = lastErrorText;
            auto parenOpen = lastErrorText.indexOf('(');
            auto parenClose = lastErrorText.lastIndexOf(')');
            if (parenOpen >= 0 && parenClose > parenOpen) {
                detail = lastErrorText[parenOpen + 1 .. parenClose].strip();
            }
            // detail is typically "type: error" or just "error".
            string sslType  = "bad_cert";
            string sslError = detail;
            auto colon = detail.indexOf(':');
            if (colon > 0 && colon + 1 < detail.length) {
                sslType  = detail[0 .. colon].strip();
                sslError = detail[colon + 1 .. $].strip();
            }
            setSSLVerify(info, sslType, sslError);
        }
        return info;
    }

    private string buildFailureSummary(string[] reasons) {
        if (reasons.length == 0) return "";
        string[] parts;
        string current;
        int count;
        foreach (r; reasons) {
            if (r == current) {
                count++;
            } else {
                if (current.length > 0)
                    parts ~= current ~ (count > 1 ? " (x" ~ count.to!string ~ ")" : "");
                current = r;
                count   = 1;
            }
        }
        if (current.length > 0)
            parts ~= current ~ (count > 1 ? " (x" ~ count.to!string ~ ")" : "");
        return parts.join(", ");
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Sends a raw IRC line.
    void sendRaw(string line) {
        // Track own away status
        if (line == "AWAY" || line == "away") {
            isAway = false;
            awayMessage = "";
        } else if (line.startsWith("AWAY :") || line.startsWith("away :")) {
            isAway = true;
            awayMessage = line[6 .. $].strip();
        }
        // Optimistic nick update — prevent sync from clobbering the UI
        // before the server echoes back the NICK response. Save the
        // previous sessionNick so the NICK handler can correlate the
        // server's echo back to us even after this optimistic change.
        if (line.startsWith("NICK ") || line.startsWith("nick ")) {
            const newNick = line[5 .. $].strip();
            if (newNick.length > 0) {
                optimisticNickOld = sessionNick;
                sessionNick = newNick;
            }
        }
        if (state == ConnectionState.disconnected ||
            (state == ConnectionState.connecting && !transportAlive)) {
            if (outboundQueue.length < MAX_OUTBOUND_QUEUE) outboundQueue ~= line;
            return;
        }
        writeRaw(line);
    }

    /// Sends a PRIVMSG to a target.
    void sendMessage(string target, string text) {
        sendRaw("PRIVMSG " ~ target ~ " :" ~ text);
        if (!hasCap("echo-message")) {
            emitSyntheticSelfMessage(target, text, "PRIVMSG");
        }
    }

    /// Sends a labeled PRIVMSG when labeled-response cap is active.
    /// The label is registered in `pendingLabels` so the echo-message
    /// correlation in `processLine()` can suppress the duplicate.
    void sendLabeledMessage(string target, string text, string label) {
        // Register label BEFORE sending so the echo handler can find it
        // even on a fast round-trip.
        pendingLabels[label] = Clock.currTime.toUnixTime!long * 1000;
        if (hasCap("labeled-response")) {
            sendRaw("@label=" ~ label ~ " PRIVMSG " ~ target ~ " :" ~ text);
        } else {
            sendRaw("PRIVMSG " ~ target ~ " :" ~ text);
        }
        if (!hasCap("echo-message")) {
            emitSyntheticSelfMessage(target, text, "PRIVMSG", label);
        }
    }

    /// Sends an edited PRIVMSG using the draft/edit-message IRCv3 cap.
    /// Re-uses the original message's label so the echo replaces the
    /// existing message in-place on the frontend.
    void sendEditMessage(string target, string originalLabel, string newBody) {
        if (!hasCap("draft/edit-message")) return; // silent no-op
        pendingLabels[originalLabel] = Clock.currTime.toUnixTime!long * 1000;
        sendRaw("@label=" ~ originalLabel ~ " PRIVMSG " ~ target ~ " :" ~ newBody);
        if (!hasCap("echo-message")) {
            emitSyntheticSelfMessage(target, newBody, "PRIVMSG", originalLabel);
        }
    }

    /// Sends a labeled NOTICE when labeled-response cap is active.
    void sendLabeledNotice(string target, string text, string label) {
        pendingLabels[label] = Clock.currTime.toUnixTime!long * 1000;
        if (hasCap("labeled-response")) {
            sendRaw("@label=" ~ label ~ " NOTICE " ~ target ~ " :" ~ text);
        } else {
            sendRaw("NOTICE " ~ target ~ " :" ~ text);
        }
        if (!hasCap("echo-message")) {
            emitSyntheticSelfMessage(target, text, "NOTICE", label);
        }
    }

    /// Emit a synthetic self-message event when the IRC server does not
    /// support echo-message. Without this, messages sent by the user are
    /// never persisted or replayed after refresh, because the server never
    /// echoes them back to us.
    private void emitSyntheticSelfMessage(string target, string text,
                                          string command, string label = "") {
        auto event = IRCRawEvent(config.name, command);
        event.networkId = config.id.toString();
        event.nick = sessionNick;
        event.prefix = sessionNick ~ "!~" ~ sessionNick ~ "@" ~ config.host;
        event.hostmask = "~" ~ sessionNick ~ "@" ~ config.host;
        event.text = text;
        event.setParams([target, text]);
        event.channel = target;
        event.addTag("self_echo", "true");
        event.addTag("synthetic", "true");
        if (label.length > 0) {
            event.addTag("label", label);
        }
        eventChannel.put(event);
    }

    /// Checks if a label is pending (awaiting echo from server).
    bool isPendingLabel(string label) const {
        return (label in pendingLabels) !is null;
    }

    /// Clears a pending label and returns true if it was found.
    bool clearPendingLabel(string label) {
        if (auto p = label in pendingLabels) {
            pendingLabels.remove(label);
            return true;
        }
        return false;
    }

    /// Drops pending labels older than `maxAgeMs` to bound the map's
    /// growth when the server never echoes (e.g. partial disconnect).
    void expireStalePendingLabels(long maxAgeMs = 30_000) {
        const now = Clock.currTime.toUnixTime!long * 1000;
        string[] stale;
        foreach (label, sentAt; pendingLabels) {
            if (now - sentAt > maxAgeMs) stale ~= label;
        }
        foreach (l; stale) pendingLabels.remove(l);
    }

    /// Records the latest/earliest msgid we've observed for a channel
    /// so CHATHISTORY pagination knows where to fetch next. Channel key
    /// is lowercased to match the rest of the codebase's conventions.
    void recordChannelMsgid(string channel, string msgid) {
        if (channel.length == 0 || msgid.length == 0) return;
        import std.uni : toLower;
        auto key = toLower(channel);
        if (key !in channelLatestMsgid) channelLatestMsgid[key] = msgid;
        if (key !in channelEarliestMsgid) channelEarliestMsgid[key] = msgid;
        // Msgids are RFC-style monotonic: lexicographic > means newer.
        if (msgid > channelLatestMsgid[key]) channelLatestMsgid[key] = msgid;
        if (msgid < channelEarliestMsgid[key]) channelEarliestMsgid[key] = msgid;
    }

    /// Returns the latest msgid we've seen for the channel, or "" if none.
    string getLatestMsgid(string channel) const {
        if (channel.length == 0) return "";
        import std.uni : toLower;
        auto key = toLower(channel);
        return channelLatestMsgid.get(key, "");
    }

    /// Returns the earliest msgid we've seen for the channel, or "" if none.
    string getEarliestMsgid(string channel) const {
        if (channel.length == 0) return "";
        import std.uni : toLower;
        auto key = toLower(channel);
        return channelEarliestMsgid.get(key, "");
    }

    /// Sends a CHATHISTORY request if the cap is negotiated. The server
    /// will respond with a BATCH wrapping the historical messages, which
    /// are already persisted via the normal event processor.
    /// `command` is one of: "LATEST", "BEFORE", "AFTER", "AROUND", "BETWEEN".
    /// For BEFORE/AFTER/AROUND `refMsgid` must be non-empty.
    void requestChathistory(string channel, string command, string refMsgid, int limit) {
        if (!hasCap("chathistory")) return;
        import ircfiber.irc.chathistory : buildChathistoryLine;
        auto line = buildChathistoryLine(command, channel, refMsgid, limit);
        if (line is null) {
            logWarn("Invalid CHATHISTORY request: cmd=%s channel=%s refMsgid=%s",
                command, channel, refMsgid);
            return;
        }
        import std.uni : toLower;
        auto key = toLower(channel);
        // Throttle: at most one in-flight request per channel.
        if (key in chathistoryInFlight) {
            logInfo("CHATHISTORY %s %s already in flight, skipping", command, channel);
            return;
        }
        chathistoryInFlight[key] = true;
        sendRaw(line);
        logInfo("CHATHISTORY %s %s sent (refMsgid=%s, limit=%d)",
            command, channel, refMsgid.length ? refMsgid : "<none>", limit);
    }

    /// Clears the in-flight flag for a channel — called when the
    /// corresponding BATCH ends.
    void clearChathistoryInFlight(string channel) {
        if (channel.length == 0) return;
        import std.uni : toLower;
        chathistoryInFlight.remove(toLower(channel));
    }

    /// True if a CHATHISTORY request is currently in flight for the channel.
    bool isChathistoryInFlight(string channel) const {
        if (channel.length == 0) return false;
        import std.uni : toLower;
        return (toLower(channel) in chathistoryInFlight) !is null;
    }

    /// Sends a JOIN command.
    void joinChannel(string channel) {
        sendRaw("JOIN " ~ channel);
    }

    /// Sends a PART command.
    void partChannel(string channel, string reason = "") {
        if (reason.length > 0) sendRaw("PART " ~ channel ~ " :" ~ reason);
        else                    sendRaw("PART " ~ channel);
    }
}
