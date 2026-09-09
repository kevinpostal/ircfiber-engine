module ircfiber.irc.connection;

import std.array : join;
import std.string : toUpper, toStringz, indexOf, lastIndexOf, split, startsWith, endsWith, strip, stripLeft;
import std.base64 : Base64;
import std.conv : to;
import std.datetime : Clock, SysTime;
import std.uni : toLower;
import std.algorithm : canFind, countUntil, remove;
import std.socket : getAddress, AddressFamily;
import std.uuid : UUID, randomUUID, parseUUID;
import std.typecons : Nullable;
import core.sync.mutex : Mutex;
import core.sys.posix.unistd : getpid;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.channel : Channel;
import vibe.core.log;
import vibe.core.net : connectTCP, TCPConnection;
import vibe.core.task : Task;
import vibe.data.json : Json;
import vibe.stream.operations : IOMode;
import core.time : Duration, dur, msecs, seconds;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : NetworkConfig, SASLMechanism, TLSMode, normalizeChannelName;
import ircfiber.redis.protocol : RedisKeys, TlsInfo;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.irc.reconnect : ExponentialBackoff;
import ircfiber.irc.sasl : buildSaslPlainPayload, ScramSha256Client;
import ircfiber.storage.buffer : sanitizeUtf8;
import ircfiber.engine.session_snapshot : SessionSnapshot, ServerFeaturesSnapshot, SESSION_SNAPSHOT_SCHEMA, toJSON;
import ircfiber.engine.holder_client : HolderClient, DialTag, DialProxy, DialRequest, DialResult, DialEvent,
    DialProgress, AttachResult, HolderEntry, DialFailedException, HolderUnavailableException, HolderErrorException;
import ircfiber.logging : logJsonMap, logException;
import ircfiber.observability : recordCounter, recordGauge, recordHistogram;
import ircfiber.tracing : withSpan, Span;
import ircfiber.async : safeFiberRun;
import ircfiber.irc.ipv6 : ipv6ForUser, normalizePrefix;
import ircfiber.irc.parser : ChannelListRow, parseChannelListRow;
import ircfiber.irc.pacer : FakeLagPacer, FloodLimits, ChannelLineLimit, LineRateWindow,
    MultilineLimits, UNKNOWN_USER_LIMITS, KNOWN_USER_LIMITS, parseMultilineCap,
    parseChannelFloodLines, payloadBudget, sanitizeLine, splitMessage,
    multilineByteCount, multilineBatchCostMs, userModesGrantOper, statusModesOf,
    statusExemptsFromFlood, parseEffectiveFloodNotice, floodExceptionExempts,
    serverAnswersFloodQuery, targetFloodLimit, CommandRateBucket, CommandRateLimit,
    floodTrustedHost, ircdSoftwareFromVersion, parseCommandRateLimit,
    parseFloodTrustedHosts, serverHasTargetFlood;
import ircfiber.irc.egress_catalog : ExitLocation, ExitRelay, locationMatches,
    locationsFromRelays, parseExitOnline, parseExitRelays, parseSelectedExit,
    pickRelayForPin;

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
// Sent as CAP REQ :cap1 cap2 ... — but only for names the server actually
// advertised in CAP LS (see the `serverCaps.canFind(desired)` intersection in
// the handshake), so a name no server offers is simply dead weight, not a
// failed REQ.
//
// Two such dead entries were removed:
//   `msgid`       — never a capability. The `msgid` tag rides on
//                   `message-tags`; asking for it could never be ACKed.
//   `chathistory` — the spec name is `draft/chathistory`. With only the
//                   bare name in this list, `hasCap` was false on every
//                   server, so the `CHATHISTORY LATEST` request on self-JOIN
//                   and `requestChathistory()` were unreachable. The bare
//                   name stays below purely for tolerance: a server that
//                   ships it un-prefixed still negotiates, and
//                   `hasChathistoryCap()` accepts either spelling.
private immutable string[] DESIRED_CAPS_BASE = [
    "away-notify",
    "account-notify",
    "account-tag",
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
    "draft/chathistory",
    "chathistory",
    "labeled-response",
    "standard-replies",
    "setname",
    "draft/edit-message",
    "draft/message-redaction",
    "draft/multiline",
];

private immutable string[] DESIRED_CAPS_SASL = ["sasl"];

// ── Tunables ──────────────────────────────────────────────────────────────────
private enum RECONNECT_MAX_DELAY_SECS     = 60;
private enum REGISTRATION_READ_TIMEOUT_MS = 100;
// Bounds the read loop on partial data; must cover
// REGISTRATION_OVERALL_TIMEOUT_SECS at one 100 ms read per iteration.
private enum REGISTRATION_MAX_READS       = 1200;
private enum SASL_MAX_READS               = 100;
private enum SASL_READ_TIMEOUT_MS         = 100;
private enum PROCESS_READ_TIMEOUT_MS      = 50;
private enum STREAM_BUFFER_SIZE           = 4096;
private enum QUIT_GRACE_PERIOD_MS         = 2_000;  // wait this long for server to close after QUIT
private enum STARTTLS_REPLY_TIMEOUT_MS      = 15_000; // wait this long for 670 after STARTTLS

// ── Flood trust (the one ircd whose limits we know) ──────────────────────────
// The engine paces nothing until a server complains, because IRC never
// advertises its flood configuration and modelling a guess throttled real
// pastes. The exception is the platform ircd: the deploy renders the same
// `commandrate`/`threshold` into its InspIRCd `<connect name="ircfiber-engine">`
// block and into this env, so the model there is a fact, not an assumption.
private struct FloodTrustSettings {
    string[] hosts;
    CommandRateLimit rate;
}

/// Parsed once per thread — the environment cannot change under a process.
private FloodTrustSettings floodTrustSettings() {
    import std.process : environment;

    static bool loaded;
    static FloodTrustSettings cached;
    if (loaded) return cached;
    loaded = true;
    cached.hosts = parseFloodTrustedHosts(environment.get("IRCFIBER_FLOOD_TRUSTED_HOSTS", ""));
    cached.rate = parseCommandRateLimit(
        environment.get("IRCFIBER_FLOOD_TRUSTED_THRESHOLD", ""),
        environment.get("IRCFIBER_FLOOD_TRUSTED_COMMANDRATE", ""));
    return cached;
}

/// WEBIRC password for irc.ircfiber.com (`<gateway type="webirc">` in the
/// ircd config), from IRCFIBER_IRCD_WEBIRC_PASSWORD. Empty = never send
/// WEBIRC. Read once per thread, same as the flood-trust settings.
private string webircPassword() {
    import std.process : environment;
    import std.string : strip;

    static bool loaded;
    static string cached;
    if (loaded) return cached;
    loaded = true;
    cached = environment.get("IRCFIBER_IRCD_WEBIRC_PASSWORD", "").strip;
    return cached;
}

/// True when `ip` parses and is a public unicast address: not loopback,
/// RFC 1918, link-local, CGNAT, 0.0.0.0/8, IPv6 loopback/ULA/link-local or
/// v4-mapped. Load-bearing, not hygiene: the gateway's client-IP resolver
/// trusts CF-Connecting-IP / X-Forwarded-For / X-Real-IP from any peer, and
/// the address forwarded via WEBIRC is what the ircd classifies on — a
/// forged 172.30.0.9 would land in the engine's own connect class,
/// 127.0.0.1 in `localhost`. A private address is never a legitimate
/// browser origin here, so the session keeps the engine's IP instead.
package bool isPublicUnicast(string ip) {
    import core.sys.posix.arpa.inet : inet_pton;
    import core.sys.posix.sys.socket : AF_INET, AF_INET6;
    import std.string : strip, toStringz;

    ip = ip.strip;
    if (ip.length == 0 || ip.length > 45) return false;
    ubyte[16] b;
    if (inet_pton(AF_INET, ip.toStringz, b.ptr) == 1) {
        const o1 = b[0], o2 = b[1];
        if (o1 == 0 || o1 == 10 || o1 == 127) return false;        // 0/8, 10/8, loopback
        if (o1 == 100 && o2 >= 64 && o2 <= 127) return false;       // CGNAT 100.64/10
        if (o1 == 169 && o2 == 254) return false;                   // link-local
        if (o1 == 172 && o2 >= 16 && o2 <= 31) return false;        // 172.16/12
        if (o1 == 192 && o2 == 168) return false;                   // 192.168/16
        if (o1 >= 224) return false;                                // multicast / reserved
        return true;
    }
    if (inet_pton(AF_INET6, ip.toStringz, b.ptr) == 1) {
        bool allZero = true;
        foreach (i; 0 .. 15) if (b[i] != 0) { allZero = false; break; }
        if (allZero && b[15] <= 1) return false;                    // :: and ::1
        if ((b[0] & 0xFE) == 0xFC) return false;                    // ULA fc00::/7
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return false;    // link-local fe80::/10
        if (b[0] == 0xFF) return false;                             // multicast
        bool mapped = true;                                         // ::ffff:a.b.c.d
        foreach (i; 0 .. 10) if (b[i] != 0) { mapped = false; break; }
        if (mapped && b[10] == 0xFF && b[11] == 0xFF) return false;
        return true;
    }
    return false;
}

unittest {
    assert(isPublicUnicast("203.0.113.7"));
    assert(isPublicUnicast("2001:db8::1"));
    foreach (bad; ["", "nope", "127.0.0.1", "10.1.2.3", "172.30.0.9", "192.168.1.1",
                   "100.64.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1",
                   "::1", "::", "fd00:f1b3:1::e", "fe80::1", "::ffff:203.0.113.7", "ff02::1"])
        assert(!isPublicUnicast(bad), bad);
}

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
    /// How many times the breaker has opened without a successful
    /// connection in between; drives the escalating cooldown.
    int openCount;
}
private HostCircuitBreaker[string] _hostBreakers;
private __gshared Object gHostBreakerLock;
private shared static this() {
    try {
        if (gMullvadLock is null) gMullvadLock = new Object();
        gHostBreakerLock = new Object();
    } catch (Throwable) {}
}
private shared static immutable HOST_WINDOW_MS   = 30 * 60 * 1000;  // 30 min
private shared static immutable HOST_FAIL_THRESHOLD = 5;
private shared static immutable HOST_COOLDOWN_MS = 5 * 60 * 1000;  // first cooldown; doubles per re-open
private shared static immutable HOST_COOLDOWN_MAX_MS = 60 * 60 * 1000;

/// Cooldown for the Nth opening of a host breaker: 5, 10, 20, 40, 60 min.
private long hostCooldownMs(int openCount) @safe pure nothrow @nogc {
    long ms = HOST_COOLDOWN_MS;
    foreach (i; 1 .. openCount) {
        ms *= 2;
        if (ms >= HOST_COOLDOWN_MAX_MS) return HOST_COOLDOWN_MAX_MS;
    }
    return ms;
}

/// Record a connection failure to a host. Shared across all clients.
void recordHostFailure(string host, int port) {
    if (gHostBreakerLock !is null) synchronized (gHostBreakerLock) {
        recordHostFailureLocked(host, port);
        return;
    }
    recordHostFailureLocked(host, port);
}
private void recordHostFailureLocked(string host, int port) {
    auto key = host ~ ":" ~ port.to!string;
    auto now = Clock.currTime.toUnixTime!long * 1000;
    auto breaker = key in _hostBreakers;
    if (breaker !is null) {
        if (now - breaker.lastAttemptAt > HOST_WINDOW_MS) {
            breaker.failCount = 0;
            breaker.openedAt = 0;
            breaker.openCount = 0;
        }
        breaker.failCount++;
        breaker.lastAttemptAt = now;
        if (breaker.failCount >= HOST_FAIL_THRESHOLD && breaker.openedAt == 0) {
            breaker.openedAt = now;
            breaker.openCount++;
            logWarn("Host circuit breaker OPENED for %s after %d failures (opening #%d, cooling down %d ms)",
                key, breaker.failCount, breaker.openCount, hostCooldownMs(breaker.openCount));
        }
    } else {
        _hostBreakers[key] = HostCircuitBreaker(1, 0, now, 0);
    }
}

/// Record a successful connection — resets the breaker for this host.
void recordHostSuccess(string host, int port) {
    if (gHostBreakerLock !is null) synchronized (gHostBreakerLock) {
        auto key = host ~ ":" ~ port.to!string;
        if (auto breaker = key in _hostBreakers) {
            _hostBreakers.remove(key);
            logInfo("Host circuit breaker CLOSED for %s (connection succeeded)", key);
        }
        return;
    }
    auto key = host ~ ":" ~ port.to!string;
    if (auto breaker = key in _hostBreakers) {
        _hostBreakers.remove(key);
        logInfo("Host circuit breaker CLOSED for %s (connection succeeded)", key);
    }
}

/// Check if the circuit breaker allows a new connection. Returns false
/// (don't connect) when the circuit is open and still in cooldown.
bool canConnectToHost(string host, int port) {
    if (gHostBreakerLock !is null) synchronized (gHostBreakerLock) {
        return canConnectToHostLocked(host, port);
    }
    return canConnectToHostLocked(host, port);
}
private bool canConnectToHostLocked(string host, int port) {
    auto key = host ~ ":" ~ port.to!string;
    if (auto breaker = key in _hostBreakers) {
        if (breaker.openedAt > 0) {
            const now = Clock.currTime.toUnixTime!long * 1000;
            if (now - breaker.openedAt < hostCooldownMs(breaker.openCount)) {
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
// Upper bounds on the CAP+NICK+USER+SASL handshake, from the first
// registration byte we send to either RPL_WELCOME (001) or a fatal error
// reply (433, 464, …). RFC 2812 §2.3: "it is not advised to wait forever
// for the reply" — this is the enforcement. Two tiers:
//
//   SILENT  (30 s): the server has sent us nothing at all. That is a
//           black-holed peer (open TCP, never replies); waiting longer only
//           wedges the network's join state.
//   OVERALL (90 s): the server has sent at least one line, so it is alive
//           and merely slow. The usual cause is the ident lookup: ircds
//           connect back to port 113 and wait out their own timer before
//           `No Ident response` → 001. Mullvad exits DROP inbound 113 (no
//           RST), so e.g. DALnet (bahamut-2.2.4) sends `Checking Ident`
//           at +0.4 s and 001 at +37 s — a 30 s cutoff never registered.
//
// Stuck states surface via ircfiber.registration.timeout in the admin API.
private enum REGISTRATION_SILENT_TIMEOUT_SECS     = 30;
private enum REGISTRATION_OVERALL_TIMEOUT_SECS    = 90;
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
// Direct dials race IPv6 and IPv4 inside the connection holder (holder.dial):
// DNS → interleave families → 250 ms stagger → first winner. The engine only
// picks the egress and forwards the holder's timeline events.

// ── Mullvad egress (SOCKS5) slots ────────────────────────────────────────────
// A fixed pool of long-lived *slots* (one SOCKS sidecar each) configured at
// deploy time via IRCFIBER_MULLVAD_POOL. Slot count is fixed at runtime:
// happyEyeballsConnect holds raw MullvadProxy* into `mullvadPool` outside the
// lock, so the array is only ever mutated in place.
//
// Each slot is *retargeted* to a Mullvad exit location on demand
// (`tailscale --socket=<slot> set --exit-node=…`) rather than a sidecar being
// launched per location — Mullvad-over-Tailscale is device-license limited.
// A slot carrying live connections (`activeConns > 0`) or inside its sticky
// hold (`heldUntilMs`) is never retargeted, so picking a location can never
// yank another network's egress.
//
// Egress selection per NetworkConfig.egressNodeId ("pin"): "" = automatic,
// "direct" = host address, "de" = any city in country, "de-ber" = that city.
// Smart picker is host-aware: when a server G/K/Z-lines an egress, that
// *location* is auto-banned for that host for 12 h (no hostname hardcode).
// Global circuit-breaker still marks a slot dead 30 s after 3 generic fails.
private struct MullvadProxy {
    string host;
    ushort port;
    string label;
    int failCount;
    long deadUntilMs;
    // ── Slot identity/state. Mutated in place under gMullvadLock only. ──
    /// tailscaled LocalAPI socket for this slot; "" = not controllable
    /// (static sidecar, no shared control volume) — never retargeted.
    string controlSocket;
    /// Current exit location id ("de-ber"); "" until the first status read.
    string locationId;
    /// Current exit relay host name ("de-ber-wg-003").
    string exitHostname;
    string exitCountry;
    string exitCountryCode;
    string exitCity;
    /// "ready" | "retargeting" | "error".
    string state = "ready";
    string lastError;
    /// Live connections currently egressing through this slot.
    int activeConns;
    /// Slot is reserved (retarget in flight) or in its post-release sticky
    /// hold until this unix-ms timestamp.
    long heldUntilMs;
}
private __gshared MullvadProxy[] mullvadPool;
private __gshared size_t mullvadRR;
private __gshared bool mullvadPoolLoaded;
private __gshared Object gMullvadLock;
/// Mullvad relay catalog as the slots' own tailscaled reports it, plus the
/// unix-ms it was last rebuilt. Guarded by gMullvadLock.
private __gshared ExitRelay[] gExitRelays;
private __gshared long gExitRelaysAtMs;
/// Per-host egress ban: hostLower -> locationId -> expiryMs. When a server
/// G/K/Z-lines an egress IP, we remember that *location* is banned for that
/// host for HOST_EGRESS_BAN_MS so future connects to the same host skip it
/// without hardcoding any hostname in the binary. Keyed by location, not by
/// slot label, because a slot's address changes when it is retargeted.
private enum HOST_EGRESS_BAN_MS = 12 * 60 * 60 * 1000L; // 12 h
// Shorter host-ban used when a ban is inferred from repeated TLS closes
// rather than read from an ERROR line (see the reconnect loop).
private enum TLS_CLOSED_ROTATE_BAN_MS = 15 * 60 * 1000L; // 15 min
private enum TLS_CLOSED_ROTATE_AFTER  = 2;
/// Sticky hold after the last connection releases a slot, so a reconnect
/// loop keeps its location instead of losing the slot to another network.
private enum SLOT_HOLD_MS               = 120_000L;
/// Reservation held while a retarget is in flight (two concurrent connects
/// must not fight over the same free slot).
private enum RETARGET_RESERVE_MS        = 60_000L;
/// How long to wait for ExitNodeStatus.Online after `tailscale set`.
private enum RETARGET_READY_TIMEOUT_MS  = 20_000L;
private enum RETARGET_POLL_MS           = 500L;
private enum TS_CMD_TIMEOUT_SECS        = 10;
/// Catalog refresh interval — the relay list changes rarely.
private enum EGRESS_CATALOG_TTL_MS      = 15 * 60 * 1000L;
private __gshared long[string][string] hostEgressBanUntil;
shared static this() {
    // Enterprise: single global mutex protects all __gshared Mullvad state.
    // vibe.d fibers are cooperative but connection loops run on different
    // task fibers concurrently (Happy Eyeballs races, TLS handshake task,
    // main loop). Unprotected __gshared access caused SyncError@(0) on
    // 2026-08-17 cnTb-fin — this mutex eliminates that class of crash.
    try { gMullvadLock = new Object(); } catch (Throwable) {}
    try { if (gIpv6Lock is null) gIpv6Lock = new Object(); } catch (Throwable) {}
}

// ── Per-user IPv6 (IRCCloud-style) ───────────────────────────────────────────
// Each user gets a deterministic /128 inside a routed /64 (or /48).
// The host is configured with `ip -6 route add local <prefix>/64 dev lo`
// and `net.ipv6.ip_nonlocal_bind=1` so any IID in the prefix is bindable
// without a per-user `ip addr add`. The engine then does
//   connectTCP(dst, port, ipv6ForUser(prefix, ownerId), 0, timeout)
// which gives each UID its own source IP — bypassing per-IP session limits.
private __gshared string gIpv6Prefix;
private __gshared string gIpv6PoolHost;
private __gshared bool gIpv6Loaded;
private __gshared Object gIpv6Lock;

private void loadIpv6Config() {
    if (gIpv6Lock !is null) synchronized (gIpv6Lock) {
        if (gIpv6Loaded) return;
        gIpv6Loaded = true;
        loadIpv6ConfigUnlocked();
        return;
    }
    if (gIpv6Loaded) return;
    gIpv6Loaded = true;
    loadIpv6ConfigUnlocked();
}
private void loadIpv6ConfigUnlocked() {
    import core.stdc.stdlib : getenv;
    import core.stdc.string : strlen;
    import std.string : toStringz;
    auto ep = getenv(toStringz("IRCFIBER_IPV6_PREFIX"));
    if (ep !is null) {
        auto raw = ep[0 .. strlen(ep)].idup;
        gIpv6Prefix = normalizePrefix(raw);
        if (gIpv6Prefix.length > 0)
            logInfo("IPv6 per-user: prefix=%s (from IRCFIBER_IPV6_PREFIX)", gIpv6Prefix);
        else if (raw.strip().length > 0)
            logWarn("IPv6 per-user: IRCFIBER_IPV6_PREFIX='%s' looks invalid (no colon)", raw);
    }
    auto hp = getenv(toStringz("IRCFIBER_IPV6_POOL_HOST"));
    if (hp !is null) {
        auto raw = hp[0 .. strlen(hp)].idup.strip();
        gIpv6PoolHost = raw;
        if (gIpv6PoolHost.length > 0)
            logInfo("IPv6 per-user: poolHost=%s (from IRCFIBER_IPV6_POOL_HOST)", gIpv6PoolHost);
    }
    if (gIpv6Prefix.length == 0)
        logInfo("IPv6 per-user: disabled (IRCFIBER_IPV6_PREFIX not set) — using direct/Mullvad egress");
}

/// Returns the deterministic IPv6 source address for a user, or "" if IPv6 is
/// not configured or the uid is nil. Handles both UUID and string forms.
string ipv6BindForUser(UUID uid) {
    loadIpv6Config();
    string p;
    if (gIpv6Lock !is null) synchronized (gIpv6Lock) { p = gIpv6Prefix; }
    else p = gIpv6Prefix;
    if (p.length == 0) return "";
    if (uid == UUID.init) return "";
    return ipv6ForUser(p, uid);
}
string ipv6BindForUser(string userIdStr) {
    if (userIdStr.length == 0) return "";
    try {
        import std.uuid : parseUUID;
        return ipv6BindForUser(parseUUID(userIdStr));
    } catch (Exception) {
        loadIpv6Config();
        string p;
        if (gIpv6Lock !is null) synchronized (gIpv6Lock) { p = gIpv6Prefix; }
        else p = gIpv6Prefix;
        if (p.length == 0) return "";
        return ipv6ForUser(p, userIdStr);
    }
}
private string mullvadLabelFromHost(string h) {
    auto base = h.split(":")[0];
    auto dash = base.lastIndexOf("-");
    if (dash >= 0 && dash+1 < base.length) return base[dash+1 .. $].toLower();
    auto dot = base.indexOf(".");
    if (dot > 0) return base[0 .. dot].toLower();
    return base.toLower();
}

private void loadMullvadPool() {
    if (gMullvadLock !is null) synchronized (gMullvadLock) {
        if (mullvadPoolLoaded) return;
        mullvadPoolLoaded = true;
        loadMullvadPoolUnlocked();
        return;
    }
    // Fallback if mutex not yet initialized (shared static this ordering)
    if (mullvadPoolLoaded) return;
    mullvadPoolLoaded = true;
    loadMullvadPoolUnlocked();
}

/// Reads an env var via getenv. `std.process.environment` returned an empty
/// string in the deployed binary despite the variable being present in
/// /proc/self/environ, so every egress env read goes through getenv.
private string envRaw(string name) nothrow {
    import core.stdc.stdlib : getenv;
    import core.stdc.string : strlen;
    try {
        auto p = getenv(toStringz(name));
        if (p is null) return "";
        return p[0 .. strlen(p)].idup.strip();
    } catch (Exception) {
        return "";
    }
}

/// `<IRCFIBER_EGRESS_CONTROL_DIR>/<label>/tailscaled.sock` when that socket
/// exists, else "" — a slot whose sidecar does not share its control socket
/// with the engine is static and never retargeted.
private string slotControlSocketPath(string label) nothrow {
    import std.file : exists;
    try {
        auto dir = envRaw("IRCFIBER_EGRESS_CONTROL_DIR");
        if (dir.length == 0) dir = "/egress";
        auto path = dir ~ "/" ~ label ~ "/tailscaled.sock";
        return exists(path) ? path : "";
    } catch (Exception) {
        return "";
    }
}

/// tailscale CLI used to drive a slot's tailscaled (overridden by the local
/// verification shim via IRCFIBER_EGRESS_TAILSCALE_BIN).
private string tailscaleBin() nothrow {
    auto b = envRaw("IRCFIBER_EGRESS_TAILSCALE_BIN");
    return b.length ? b : "/usr/local/bin/tailscale";
}

// Reads IRCFIBER_MULLVAD_POOL directly via getenv, for the reason envRaw
// documents. Caller holds gMullvadLock and has set mullvadPoolLoaded = true.
private void loadMullvadPoolUnlocked() {
    import core.stdc.stdlib : getenv;
    import core.stdc.string : strlen;
    auto envp = getenv(toStringz("IRCFIBER_MULLVAD_POOL"));
    if (envp is null) {
        logWarn("Mullvad pool: IRCFIBER_MULLVAD_POOL not set (getenv null)");
        return;
    }
    auto raw = envp[0 .. strlen(envp)].idup;
    if (raw.length == 0) {
        logWarn("Mullvad pool: IRCFIBER_MULLVAD_POOL is empty");
        return;
    }
    foreach (entry; raw.split(",")) {
        auto e = entry.strip();
        if (e.length == 0) continue;
        auto p = e.indexOf("://");
        if (p >= 0) e = e[p+3 .. $];
        // Optional explicit label `de@100.94.116.56:1080` — required when
        // several sidecars share one bare IP on different ports, where
        // mullvadLabelFromHost() would collapse them all to one label and
        // pins/host-bans could no longer tell the exits apart. Must match
        // the gateway's parser (site/backend/source/ircfiber/egress.d).
        string explicitLabel;
        auto at = e.indexOf("@");
        if (at >= 0) { explicitLabel = e[0 .. at].strip().toLower(); e = e[at+1 .. $]; }
        auto colon = e.lastIndexOf(":");
        string host; ushort port = 1080;
        if (colon >= 0) {
            host = e[0 .. colon].strip();
            try { port = e[colon+1 .. $].strip().to!ushort; } catch (Exception) {}
        } else host = e;
        if (host.length == 0) continue;
        auto label = explicitLabel.length > 0 ? explicitLabel : mullvadLabelFromHost(host);
        auto sock = slotControlSocketPath(label);
        mullvadPool ~= MullvadProxy(host, port, label, 0, 0, sock);
        logInfo("Mullvad pool: %s → %s:%d (label=%s)", entry, host, port, label);
        logInfo("Mullvad slot %s: controllable=%s (socket=%s)", label,
            sock.length ? "true" : "false", sock.length ? sock : "-");
    }
    logInfo("Mullvad pool loaded: %d slots", cast(int) mullvadPool.length);
}

private MullvadProxy*[] getHealthyProxies() {
    loadMullvadPool();
    if (gMullvadLock !is null) synchronized (gMullvadLock) {
        return getHealthyProxiesLocked();
    }
    return getHealthyProxiesLocked();
}
private MullvadProxy*[] getHealthyProxiesLocked() {
    if (mullvadPool.length == 0) return [];
    const now = Clock.currTime.toUnixTime!long * 1000;
    foreach (ref pr; mullvadPool) if (pr.deadUntilMs != 0 && now >= pr.deadUntilMs) { pr.failCount = 0; pr.deadUntilMs = 0; }
    MullvadProxy*[] healthy;
    foreach (ref pr; mullvadPool) if (pr.deadUntilMs == 0 || now >= pr.deadUntilMs) healthy ~= &pr;
    return healthy;
}

private void recordMullvadSuccess(string label) {
    if (gMullvadLock !is null) synchronized (gMullvadLock) {
        foreach (ref pr; mullvadPool) if (pr.label == label) { pr.failCount = 0; pr.deadUntilMs = 0; break; }
        return;
    }
    foreach (ref pr; mullvadPool) if (pr.label == label) { pr.failCount = 0; pr.deadUntilMs = 0; break; }
}
private void recordMullvadFailure(string label) {
    if (gMullvadLock !is null) synchronized (gMullvadLock) {
        foreach (ref pr; mullvadPool) if (pr.label == label) {
            pr.failCount++;
            if (pr.failCount >= 3) {
                pr.deadUntilMs = Clock.currTime.toUnixTime!long * 1000 + 30_000;
                logWarn("Mullvad proxy %s (%s:%d) marked dead for 30s after 3 fails", label, pr.host, pr.port);
            }
            break;
        }
        return;
    }
    foreach (ref pr; mullvadPool) if (pr.label == label) {
        pr.failCount++;
        if (pr.failCount >= 3) {
            pr.deadUntilMs = Clock.currTime.toUnixTime!long * 1000 + 30_000;
            logWarn("Mullvad proxy %s (%s:%d) marked dead for 30s after 3 fails", label, pr.host, pr.port);
        }
        break;
    }
}

/// Is `locationId` (or the `slot:<label>` key of a slot whose location is
/// unknown, or `DIRECT_EGRESS_LABEL`) banned for this host right now?
private bool isEgressBannedForHost(string hostLower, string locationId) {
    if (hostLower.length == 0 || locationId.length == 0) return false;
    // Called only from synchronized contexts (getHealthyProxiesForHost) or with mutex held.
    if (auto outer = hostLower in hostEgressBanUntil) {
        if (auto expiry = locationId in *outer) {
            const now = Clock.currTime.toUnixTime!long * 1000;
            if (now < *expiry) return true;
            (*outer).remove(locationId);
            if ((*outer).length == 0) hostEgressBanUntil.remove(hostLower);
        }
    }
    return false;
}

/// Per-host ban key for a slot. A ban must follow the *address*, not the
/// slot: a slot is retargeted over time, so keying by label would move the
/// ban with the slot instead of leaving it on the banned exit. Slots whose
/// location the engine cannot read (static sidecars, no control socket) keep
/// a stable per-slot key so host-bans still work for them.
private string slotBanKey(const(MullvadProxy)* p) nothrow {
    if (p is null) return "";
    return p.locationId.length ? p.locationId : "slot:" ~ p.label;
}

private void banEgressForHost(string host, string locationId, long durationMs = HOST_EGRESS_BAN_MS) {
    if (host.length == 0 || locationId.length == 0) return;
    import std.string : toLower;
    auto hl = host.toLower();
    const exp = Clock.currTime.toUnixTime!long * 1000 + durationMs;
    if (gMullvadLock !is null) synchronized (gMullvadLock) {
        hostEgressBanUntil[hl][locationId.toLower()] = exp;
    } else {
        hostEgressBanUntil[hl][locationId.toLower()] = exp;
    }
    logWarn("Mullvad host-ban: egress %s banned for %s for %d ms (until %d)", locationId, hl, durationMs, exp);
}

private MullvadProxy*[] getHealthyProxiesForHost(string hostLower) {
    // The host-aware path skips the unlocked getHealthyProxies() wrapper, so
    // it must load the pool itself (the wrapper is the only other caller of
    // loadMullvadPool). Without this the pool stays empty and every network
    // falls back to direct egress.
    loadMullvadPool();
    // Entire read-modify is synchronized to avoid SyncError on hostEgressBanUntil (AA).
    if (gMullvadLock !is null) synchronized (gMullvadLock) {
        return getHealthyProxiesForHostLocked(hostLower);
    }
    return getHealthyProxiesForHostLocked(hostLower);
}
private MullvadProxy*[] getHealthyProxiesForHostLocked(string hostLower) {
    auto healthy = getHealthyProxiesLocked();
    if (hostLower.length == 0) return healthy;
    const now = Clock.currTime.toUnixTime!long * 1000;
    if (auto outer = hostLower in hostEgressBanUntil) {
        string[] dead;
        foreach (lbl, exp; *outer) if (now >= exp) dead ~= lbl;
        foreach (lbl; dead) {
            (*outer).remove(lbl);
            logInfo("Mullvad host-ban expired: %s for %s", lbl, hostLower);
        }
        if ((*outer).length == 0) hostEgressBanUntil.remove(hostLower);
    }
    MullvadProxy*[] out_;
    foreach (p; healthy) if (!isEgressBannedForHost(hostLower, slotBanKey(p))) out_ ~= p;
    return out_;
}

/// Pseudo-label for the un-proxied host IP. Lives in the same per-host ban
/// table as the Mullvad labels so a Z/G/K-line on the bare OVH address is
/// remembered exactly like a banned exit, and `NetworkConfig.egressNodeId`
/// can pin it ("direct") the same way it pins a Mullvad label.
enum DIRECT_EGRESS_LABEL = "direct";

/// True when, after `bannedKey` was just banned for `hostLower`, at least
/// one other route to the host remains: a healthy exit whose location is not
/// host-banned, a free controllable slot that could be retargeted to an
/// unbanned location, or the direct path if that is not host-banned. Drives
/// the ban policy: failover now vs. wait out the ban window.
private bool hasAlternativeEgressForHost(string hostLower, string bannedKey) {
    loadMullvadPool();
    bool check() {
        foreach (p; getHealthyProxiesForHostLocked(hostLower))
            if (slotBanKey(p) != bannedKey) return true;
        // A free controllable slot is an alternative in itself: it can be
        // retargeted to any city in the catalog that is not host-banned.
        const now = Clock.currTime.toUnixTime!long * 1000;
        if (gExitRelays.length > 0) {
            foreach (ref pr; mullvadPool)
                if (pr.controlSocket.length > 0 && pr.activeConns == 0
                    && now >= pr.heldUntilMs && pr.state != "retargeting")
                    return true;
        }
        return bannedKey != DIRECT_EGRESS_LABEL && !isEgressBannedForHost(hostLower, DIRECT_EGRESS_LABEL);
    }
    if (gMullvadLock !is null) synchronized (gMullvadLock) return check();
    return check();
}

/// Direct path host-banned? Read under the pool lock like the proxy checks.
private bool isDirectBannedForHost(string hostLower) {
    if (gMullvadLock !is null) synchronized (gMullvadLock) return isEgressBannedForHost(hostLower, DIRECT_EGRESS_LABEL);
    return isEgressBannedForHost(hostLower, DIRECT_EGRESS_LABEL);
}

// ── Egress slot control: read location, retarget, refcount ───────────────────
// A slot is retargeted only while it is idle: `activeConns == 0`, past its
// sticky hold, and not already reserved. That is the whole guarantee that
// choosing a location for one network never drops another network's socket.

/// Unix ms. Wrapped so the `nothrow` slot bookkeeping below can use it.
private long nowMsSafe() nothrow {
    try {
        return Clock.currTime.toUnixTime!long * 1000;
    } catch (Exception) {
        return 0;
    }
}

/// Loads the pool from `nothrow` context (the loader logs, which can throw).
private void loadMullvadPoolSafe() nothrow {
    try {
        loadMullvadPool();
    } catch (Exception) {}
}

/// Runs `action` under `gMullvadLock`, swallowing any throw so the slot
/// bookkeeping can live in `nothrow` code paths. Never yields inside the
/// lock — every `action` below is pure in-memory bookkeeping.
private void withPoolLock(scope void delegate() action) nothrow {
    try {
        if (gMullvadLock !is null) synchronized (gMullvadLock) action();
        else action();
    } catch (Exception e) {
        try { logWarn("Mullvad slot bookkeeping failed: %s", e.msg); } catch (Exception) {}
    }
}

private struct TsResult {
    /// Process exited 0.
    bool ok;
    /// stdout, whether or not the process succeeded.
    string output;
}

/// Runs `<bin> --socket=<socket> <args…>` against one slot's tailscaled with
/// a hard `timeout(1)` ceiling. Uses `vibe.core.process.execute`, which
/// yields the calling fiber instead of blocking the event-loop thread — the
/// std.process version would stall every other IRC connection for the
/// duration. Returns `ok == false` and whatever stdout was produced on
/// failure; callers that only need the payload (status reads) use `output`.
private TsResult tailscaleCmd(string socket, string[] args) nothrow {
    TsResult r;
    if (socket.length == 0) return r;
    try {
        import vibe.core.process : vibeExecute = execute;
        auto cmd = ["timeout", TS_CMD_TIMEOUT_SECS.to!string, tailscaleBin(),
                    "--socket=" ~ socket] ~ args;
        auto res = vibeExecute(cmd);
        r.ok = res.status == 0;
        r.output = res.output;
        if (!r.ok)
            logWarn("tailscale %s (%s) exited %d: %s", args.join(" "), socket, res.status,
                res.output.length > 200 ? res.output[0 .. 200] : res.output);
    } catch (Exception e) {
        try { logWarn("tailscale %s (%s) failed: %s", args.join(" "), socket, e.msg); } catch (Exception) {}
        r.ok = false;
    }
    return r;
}

/// Re-reads one slot's exit location and health from its own tailscaled, and
/// refreshes the shared relay catalog from the same payload. No-op for a
/// static slot. Must run off the connection fibers (it shells out).
private void refreshSlotFromStatus(size_t idx) nothrow {
    string socket;
    withPoolLock({
        if (idx < mullvadPool.length) socket = mullvadPool[idx].controlSocket;
    });
    if (socket.length == 0) return;
    auto st = tailscaleCmd(socket, ["status", "--json"]);
    if (st.output.length == 0) {
        withPoolLock({
            if (idx >= mullvadPool.length) return;
            auto p = &mullvadPool[idx];
            if (p.state == "retargeting") return;
            p.state = "error";
            p.lastError = "tailscale status unavailable";
        });
        return;
    }
    auto sel = parseSelectedExit(st.output);
    const online = parseExitOnline(st.output);
    auto relays = parseExitRelays(st.output);
    withPoolLock({
        if (idx >= mullvadPool.length) return;
        auto p = &mullvadPool[idx];
        if (sel.locationId.length) {
            p.locationId = sel.locationId;
            p.exitHostname = sel.hostname;
            p.exitCountry = sel.country;
            p.exitCountryCode = sel.countryCode;
            p.exitCity = sel.city;
        }
        // A retarget in flight owns the slot's state field.
        if (p.state != "retargeting") {
            if (sel.hostname.length == 0) {
                p.state = "error";
                p.lastError = "no exit node selected";
            } else if (!online) {
                p.state = "error";
                p.lastError = "exit node offline";
            } else {
                p.state = "ready";
                p.lastError = "";
            }
        }
        if (relays.length > 0) {
            gExitRelays = relays;
            gExitRelaysAtMs = nowMsSafe();
        }
    });
}

/// Points slot `idx` at the best relay for `pin` and waits for tailscaled to
/// report the new exit online. Returns false (leaving the slot in `error`
/// with its hold cleared, so it can be retried) on any failure.
/// The caller must already have reserved the slot via `acquireSlotForPin`.
private bool retargetSlot(size_t idx, string pin) nothrow {
    string socket, label;
    ExitRelay relay;
    withPoolLock({
        if (idx >= mullvadPool.length) return;
        socket = mullvadPool[idx].controlSocket;
        label = mullvadPool[idx].label;
        relay = pickRelayForPin(gExitRelays, pin);
    });
    if (socket.length == 0 || relay.ip.length == 0) return false;
    try {
        logInfo("Mullvad slot %s: retargeting to %s (%s / %s)", label, relay.locationId,
            relay.hostname, relay.ip);
    } catch (Exception) {}
    if (!tailscaleCmd(socket, ["set", "--exit-node=" ~ relay.ip]).ok) {
        withPoolLock({
            if (idx >= mullvadPool.length) return;
            auto p = &mullvadPool[idx];
            p.state = "error";
            p.lastError = "tailscale set failed";
            p.heldUntilMs = 0;
        });
        return false;
    }
    const deadline = nowMsSafe() + RETARGET_READY_TIMEOUT_MS;
    bool ready = false;
    while (nowMsSafe() < deadline) {
        auto st = tailscaleCmd(socket, ["status", "--json"]);
        if (st.output.length && parseExitOnline(st.output)
            && parseSelectedExit(st.output).hostname == relay.hostname) {
            ready = true;
            break;
        }
        try {
            sleep(RETARGET_POLL_MS.msecs);
        } catch (Exception) {
            break;
        }
    }
    withPoolLock({
        if (idx >= mullvadPool.length) return;
        auto p = &mullvadPool[idx];
        if (ready) {
            p.locationId = relay.locationId;
            p.exitHostname = relay.hostname;
            p.exitCountry = relay.country;
            p.exitCountryCode = relay.countryCode;
            p.exitCity = relay.city;
            p.state = "ready";
            p.lastError = "";
        } else {
            p.state = "error";
            p.lastError = "exit node did not come online";
            p.heldUntilMs = 0;
        }
    });
    if (!ready) {
        try {
            logWarn("Mullvad slot %s: retarget to %s timed out after %d ms", label,
                relay.locationId, RETARGET_READY_TIMEOUT_MS);
        } catch (Exception) {}
    }
    return ready;
}

/// Refreshes every controllable slot's location and the relay catalog.
/// Cheap no-op inside `EGRESS_CATALOG_TTL_MS` — retargets update slot state
/// synchronously, so a periodic read only picks up out-of-band changes.
/// Shells out: call only from the state snapshotter task, never from a
/// connection fiber's hot path.
void refreshEgressState() nothrow {
    loadMullvadPoolSafe();
    size_t[] idxs;
    long lastAt;
    withPoolLock({
        lastAt = gExitRelaysAtMs;
        foreach (i, ref p; mullvadPool) if (p.controlSocket.length > 0) idxs ~= i;
    });
    if (idxs.length == 0) return;
    if (lastAt != 0 && nowMsSafe() - lastAt < EGRESS_CATALOG_TTL_MS) return;
    foreach (i; idxs) refreshSlotFromStatus(i);
}

/// Copy-by-value snapshot of one slot, taken under the lock, for publishing.
struct EgressSlotView {
    string label;
    string host;
    string locationId;
    string exitHostname;
    string exitCountry;
    string exitCountryCode;
    string exitCity;
    string state;
    string lastError;
    ushort port;
    bool controllable;
    int activeConns;
    long heldUntilMs;
}

/// Every slot's current state, for `irc:egress:slots:<serverId>`.
EgressSlotView[] egressSlotViews() nothrow {
    loadMullvadPoolSafe();
    EgressSlotView[] views;
    withPoolLock({
        foreach (ref p; mullvadPool) {
            EgressSlotView v;
            v.label = p.label;
            v.host = p.host;
            v.port = p.port;
            // A retargetable slot reports its real location; a static one has
            // none to report (its `slot:` ban key never leaves the engine).
            v.locationId = p.locationId;
            v.exitHostname = p.exitHostname;
            v.exitCountry = p.exitCountry;
            v.exitCountryCode = p.exitCountryCode;
            v.exitCity = p.exitCity;
            v.state = p.state;
            v.lastError = p.lastError;
            v.controllable = p.controlSocket.length > 0;
            v.activeConns = p.activeConns;
            v.heldUntilMs = p.heldUntilMs;
            views ~= v;
        }
    });
    return views;
}

/// The pickable location catalog, for `irc:egress:catalog:<serverId>`.
ExitLocation[] egressLocations() nothrow {
    ExitRelay[] relays;
    withPoolLock({ relays = gExitRelays.dup; });
    try {
        return locationsFromRelays(relays);
    } catch (Exception) {
        return null;
    }
}

/// Moves one named slot to `pin` on an operator's instruction (admin
/// "swap exit"), rather than because a connect needs it. Returns "" on
/// success, else a short reason the gateway can surface:
///   "unknown-slot" | "not-controllable" | "busy" | "retargeting"
///   | "no-catalog" | "retarget-failed"
///
/// `force` is the operator overriding the in-use lock. Without it a slot
/// carrying live connections is refused, never yanked — which is the right
/// default for an automatic pin, but on a busy deployment every slot is in
/// use, so an operator who wants to move an exit has no other way. With
/// `force`, the connections riding the slot are reconnected onto the new
/// exit right after the retarget instead of being left to notice the change
/// when their socket eventually breaks.
///
/// Shells out, so this runs on the control-consumer task, never on a
/// connection fiber.
string retargetSlotByLabel(string label, string pin, bool force = false) nothrow {
    if (label.length == 0 || pin.length == 0) return "unknown-slot";
    loadMullvadPoolSafe();
    size_t idx = size_t.max;
    string reason;
    int wasCarrying = 0;
    withPoolLock({
        const now = nowMsSafe();
        foreach (i, ref p; mullvadPool) {
            if (p.label != label) continue;
            if (p.controlSocket.length == 0) { reason = "not-controllable"; return; }
            if (p.activeConns > 0 && !force) { reason = "busy"; return; }
            if (p.state == "retargeting") { reason = "retargeting"; return; }
            if (pickRelayForPin(gExitRelays, pin).ip.length == 0) { reason = "no-catalog"; return; }
            wasCarrying = p.activeConns;
            // Reserve exactly as acquireSlotForPin does, so a connect landing
            // between here and the retarget cannot claim the same slot.
            p.state = "retargeting";
            p.heldUntilMs = now + RETARGET_RESERVE_MS;
            idx = i;
            return;
        }
        reason = "unknown-slot";
    });
    if (idx == size_t.max) return reason.length ? reason : "unknown-slot";
    if (!retargetSlot(idx, pin)) return "retarget-failed";
    // The operator asked for this location, so hold the slot briefly: a
    // connect that arrives now should use it, not move it again.
    withPoolLock({
        if (idx < mullvadPool.length) mullvadPool[idx].heldUntilMs = nowMsSafe() + SLOT_HOLD_MS;
    });
    try {
        logJsonMap("info", "connection",
            "Operator retargeted a Mullvad slot",
            ["slot": label,
             "location": pin,
             "forced": force ? "true" : "false",
             "carrying": wasCarrying.to!string,
             "event": "egress_retargeted"]);
    } catch (Exception) {}
    return "";
}

/// Finds or prepares a slot for `pin` (a country or city pin, lower-case).
/// Returns null when nothing is available, with `reason` set to one of
/// "no-pin" | "no-catalog" | "all-busy" | "retarget-failed" | "not-controllable".
///
/// A slot already sitting on a matching location is shared as-is — that is
/// the common case and it never disturbs the connections already on it. Only
/// a genuinely idle slot is ever retargeted, and it is reserved (state
/// "retargeting" + a `RETARGET_RESERVE_MS` hold) before the lock is released
/// so two concurrent connects cannot fight over the same slot.
private MullvadProxy* acquireSlotForPin(string hostLower, string pin, out string reason) nothrow {
    reason = "";
    if (pin.length == 0) {
        reason = "no-pin";
        return null;
    }
    loadMullvadPoolSafe();
    MullvadProxy* match = null;
    size_t candidate = size_t.max;
    int controllable = 0;
    withPoolLock({
        const now = nowMsSafe();
        // A slot the engine cannot drive (no control socket) has no readable
        // location, so it is addressed by its label — the pre-slot behaviour,
        // kept for deployments whose sidecars live on another host. Only
        // non-controllable slots answer to a label, so a retargetable pool
        // never has two ways to name the same exit.
        foreach (i, ref p; mullvadPool) {
            if (p.controlSocket.length > 0 || p.label != pin) continue;
            if (p.deadUntilMs != 0 && now < p.deadUntilMs) continue;
            if (isEgressBannedForHost(hostLower, slotBanKey(&mullvadPool[i]))) continue;
            match = &mullvadPool[i];
            return;
        }
        foreach (i, ref p; mullvadPool) {
            if (!locationMatches(p.locationId, pin)) continue;
            if (p.deadUntilMs != 0 && now < p.deadUntilMs) continue;
            if (isEgressBannedForHost(hostLower, slotBanKey(&mullvadPool[i]))) continue;
            match = &mullvadPool[i];
            return;
        }
        long lru = long.max;
        foreach (i, ref p; mullvadPool) {
            if (p.controlSocket.length == 0) continue;
            controllable++;
            if (p.activeConns != 0 || now < p.heldUntilMs || p.state == "retargeting") continue;
            if (p.heldUntilMs <= lru) {
                lru = p.heldUntilMs;
                candidate = i;
            }
        }
        if (candidate == size_t.max) return;
        mullvadPool[candidate].state = "retargeting";
        mullvadPool[candidate].heldUntilMs = now + RETARGET_RESERVE_MS;
    });
    if (match !is null) return match;
    if (candidate == size_t.max) {
        reason = controllable > 0 ? "all-busy" : "not-controllable";
        return null;
    }
    bool haveRelay = false;
    withPoolLock({ haveRelay = pickRelayForPin(gExitRelays, pin).ip.length > 0; });
    if (!haveRelay) {
        withPoolLock({
            if (candidate >= mullvadPool.length) return;
            mullvadPool[candidate].state = "ready";
            mullvadPool[candidate].heldUntilMs = 0;
        });
        reason = "no-catalog";
        return null;
    }
    if (!retargetSlot(candidate, pin)) {
        reason = "retarget-failed";
        return null;
    }
    return &mullvadPool[candidate];
}

/// True when a user's pin addresses the exact route identified by `banKey`
/// (see `slotBanKey`): the literal `direct` pseudo-label, a location the pin
/// matches, or the label of a static slot. Drives "the user pinned the route
/// that just got banned, so do not fail over behind their back".
private bool pinCoversBanKey(string pin, string banKey) nothrow {
    if (pin.length == 0 || banKey.length == 0) return false;
    if (pin == banKey) return true;
    if (banKey.length > 5 && banKey[0 .. 5] == "slot:" && banKey[5 .. $] == pin) return true;
    return locationMatches(banKey, pin);
}

/// Location id of the best online relay that is not host-banned for
/// `hostLower` — the target for an automatic retarget when every existing
/// slot is banned for this host. "" when the catalog offers nothing better.
/// A city id (not a country) so the retarget cannot land on a banned city.
private string bestUnbannedLocationFor(string hostLower) nothrow {
    string best;
    long bestPriority = long.min;
    withPoolLock({
        foreach (r; gExitRelays) {
            if (!r.online || r.locationId.length == 0) continue;
            if (isEgressBannedForHost(hostLower, r.locationId)) continue;
            if (r.priority > bestPriority) {
                bestPriority = r.priority;
                best = r.locationId;
            }
        }
    });
    return best;
}

/// Takes a reference on `label`'s slot: it can no longer be retargeted, and
/// keeps a sticky hold for SLOT_HOLD_MS past the last release so a reconnect
/// loop does not lose its location to another network.
private void holdSlot(string label) nothrow {
    if (label.length == 0) return;
    withPoolLock({
        foreach (ref p; mullvadPool) if (p.label == label) {
            p.activeConns++;
            p.heldUntilMs = nowMsSafe() + SLOT_HOLD_MS;
            break;
        }
    });
}

/// Drops a reference taken by `holdSlot` (floored at zero) and starts the
/// sticky hold window.
private void releaseSlot(string label) nothrow {
    if (label.length == 0) return;
    withPoolLock({
        foreach (ref p; mullvadPool) if (p.label == label) {
            if (p.activeConns > 0) p.activeConns--;
            p.heldUntilMs = nowMsSafe() + SLOT_HOLD_MS;
            break;
        }
    });
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

/// User-visible connect progress sink: each holder dial `EVENT` (plus the
/// engine-composed `attempt`/`attempt_fail`/`info` lines) lands in the
/// network's `_server` buffer via `PersistentIRCClient.onDialEvent`.
/// Optional (null → silent) so the module-level helpers stay usable
/// without a client.
alias ConnectProgress = DialProgress;

private void report(ConnectProgress progress, string phase, string text) nothrow {
    if (progress is null) return;
    DialEvent ev;
    ev.phase = phase;
    ev.text = text;
    progress(ev);
}

/// Shortens a vibe/eventcore connect error to something a user can act on.
private string shortConnectError(string msg) @safe {
    import std.string : toLower;
    const l = msg.toLower();
    if (l.canFind("timed out") || l.canFind("timeout")) return "timed out after " ~ CONNECT_TIMEOUT_SECONDS.to!string ~ "s";
    if (l.canFind("refused")) return "connection refused";
    if (l.canFind("unreachable")) return "network unreachable";
    if (l.canFind("reset")) return "connection reset";
    if (l.canFind("socks")) return "SOCKS egress error: " ~ msg;
    return msg.length > 90 ? msg[0 .. 90] ~ "…" : msg;
}

/// Best-effort Tailnet IP of a SOCKS sidecar for admin display ("" when
/// it cannot be resolved right now).
private string resolveProxyIp(MullvadProxy* proxy) nothrow {
    try {
        auto a = getAddress(proxy.host, proxy.port);
        if (a.length > 0) return a[0].toAddrString();
    } catch (Exception) {}
    return "";
}

/// "Berlin, Germany" / "Germany" / "" for the UI.
private string proxyLocationText(const MullvadProxy* proxy) nothrow {
    return proxy.exitCity.length ? proxy.exitCity ~ ", " ~ proxy.exitCountry : proxy.exitCountry;
}

/// One dial through exactly one egress, performed by the holder. Direct
/// dials (`proxy is null`) are DNS + Happy Eyeballs (+ optional per-user
/// IPv6 bind) inside the holder, which composes their `dns`/`attempt`/
/// `attempt_fail` timeline lines; proxied dials are a single SOCKS5
/// CONNECT through the sidecar (the exit resolves the name), and this
/// wrapper composes their `attempt`/`attempt_fail` lines and keeps the
/// Mullvad success/failure accounting. Every forwarded event carries the
/// candidate egress identity so the timeline can name it.
private TCPConnection happyEyeballsConnectWithProxy(HolderClient holder, DialTag tag, string host, ushort port,
                                                    string tlsMode, MullvadProxy* proxy,
                                                    string ipv6BindAddr, ConnectProgress progress,
                                                    out DialResult dr) {
    if (proxy !is null) logInfo("Mullvad egress %s (%s:%d) for %s:%d", proxy.label, proxy.host, proxy.port, host, port);
    else if (ipv6BindAddr.length > 0) logInfo("IPv6 per-user egress %s for %s:%d", ipv6BindAddr, host, port);
    const egressLabel = proxy !is null ? "Mullvad exit " ~ proxy.label : (ipv6BindAddr.length > 0 ? "ipv6:" ~ ipv6BindAddr : "direct");
    if (holder is null) throw new HolderUnavailableException("no connection holder configured");

    DialRequest req;
    req.tag = tag;
    req.tag.egressLabel = proxy !is null ? proxy.label : "";
    req.host = host;
    req.port = port;
    req.tls = tlsMode;
    req.sni = stripHostBrackets(host);
    if (proxy !is null) {
        req.hasProxy = true;
        req.proxy = DialProxy(proxy.host, proxy.port);
    }
    req.bindIp6 = proxy is null ? ipv6BindAddr : "";
    req.connectTimeoutMs = CONNECT_TIMEOUT_SECONDS * 1000;
    req.tlsTimeoutMs = TLS_HANDSHAKE_TIMEOUT_SECONDS * 1000;
    req.starttlsTimeoutMs = STARTTLS_REPLY_TIMEOUT_MS;

    // Candidate egress identity for the timeline (the holder does not know
    // which slot it is dialing through).
    string evLabel, evHost, evIp, evLocation;
    if (proxy !is null) {
        evLabel = proxy.label;
        evHost = proxy.host ~ ":" ~ proxy.port.to!string;
        evIp = resolveProxyIp(proxy);
        evLocation = proxyLocationText(proxy);
    }
    DialProgress wrapped = (ref DialEvent ev) nothrow {
        ev.egressLabel = evLabel;
        ev.egressHost = evHost;
        ev.egressIp = evIp;
        ev.egressLocationText = evLocation;
        if (progress !is null) progress(ev);
    };

    if (proxy is null) {
        // Direct: the holder resolves, races and reports; nothing to account.
        dr = holder.dial(req, wrapped);
        return dr.stream;
    }
    // One CONNECT with the hostname: the exit resolves it (see the holder's
    // SOCKS5 dial). Racing locally-resolved addresses through a single
    // proxy only multiplied its fail count — and on prod fed it the
    // Docker-internal address of irc.ircfiber.com.
    auto target = stripHostBrackets(host);
    immutable startMs = Clock.currTime.toUnixTime!long * 1000;
    report(wrapped, "attempt", "Trying " ~ target ~ ":" ~ port.to!string ~ " via " ~ egressLabel
        ~ " (exit resolves the name, up to " ~ HAPPY_EYEBALLS_RACE_TIMEOUT_SECONDS.to!string ~ "s)…");
    try {
        dr = holder.dial(req, wrapped);
        recordMullvadSuccess(proxy.label);
        return dr.stream;
    } catch (HolderUnavailableException e) {
        // The exit was never tried — leave its counters alone.
        throw e;
    } catch (Exception e) {
        recordMullvadFailure(proxy.label);
        const tookMs = Clock.currTime.toUnixTime!long * 1000 - startMs;
        report(wrapped, "attempt_fail", target ~ " via " ~ egressLabel ~ ": "
            ~ shortConnectError(e.msg) ~ " (" ~ (tookMs / 1000).to!string ~ "s).");
        throw e;
    }
}

/// Which egress a `happyEyeballsConnect` call actually used. Returned per
/// call (not via a global) because many networks connect concurrently on
/// different fibers and the ban policy keys off the location — a crossed
/// value would ban the wrong exit.
struct EgressUsed {
    /// "" = direct, else the slot label ("de"). Identifies the slot whose
    /// refcount the caller now holds.
    string label;
    /// "host:port" of the SOCKS sidecar; "" for direct.
    string host;
    /// Resolved IP of the sidecar for admin display; "" for direct.
    string ip;
    /// Per-host ban key of the exit: its location id ("de-ber") when known,
    /// else `slot:<label>` for a slot whose location cannot be read.
    string locationId;
    /// Human text for the UI, e.g. "Berlin, Germany"; "" when unknown.
    string locationText;
}

/// User-facing copy for a pin that could not be honoured. A pin problem
/// never hard-fails a connect — being offline is worse than being in the
/// wrong city — so every branch ends "connecting via another exit".
private string egressPinFallbackCopy(string reason) nothrow {
    switch (reason) {
        case "all-busy":
            return "All exits are in use right now — connecting via another exit; "
                ~ "your location will be used when one frees up.";
        case "retarget-failed":
            return "Could not switch an exit to that location — connecting via another exit.";
        case "no-catalog":
            return "No exit locations are available on this server — connecting via another exit.";
        default:
            return "That location is not available on this server — connecting via another exit.";
    }
}

/// Egress policy loop: picks the egresses to try (direct-first for the
/// first-party ircd, pins, rotation, host bans, direct fallback) and issues
/// one holder `DIAL` per candidate through `happyEyeballsConnectWithProxy`.
/// `tlsMode` (`none`/`implicit`/`starttls`) is performed by the holder as
/// part of the dial, so a TLS failure on one exit moves on to the next; a
/// `TLS handshake timed out` bans the exit for this host. `dr` carries the
/// holder's `CONNECTED` facts for the winning dial.
private TCPConnection happyEyeballsConnect(HolderClient holder, DialTag tag, string host, ushort port,
                                           string tlsMode, string egressNodeId,
                                           string ipv6BindAddr, ConnectProgress progress,
                                           out EgressUsed used, out DialResult dr) {
    import std.string : toLower;
    auto hostLower = host.toLower();
    // Fast-path for the first-party InspIRCd instance (irc.ircfiber.com):
    // On prod the host resolves via Docker alias to 172.30.0.5 internally.
    // Trying Mullvad first wastes 12s (3 exits × 4s) and hits the public
    // hairpin, which is flaky. Try direct first; fall back to Mullvad only
    // if the internal path fails. This is what fixed the 2026-08-26 outage
    // where every Mullvad exit was throttled and direct via public IP
    // also failed, but direct via internal alias succeeded.
    // Skipped while the ircd has the direct address banned (connectban
    // Z-line): the ban policy already failed the network over to an exit.
    if (hostLower == "irc.ircfiber.com" && egressNodeId.length == 0 && !isDirectBannedForHost(hostLower)) {
        try {
            auto directConn = happyEyeballsConnectWithProxy(holder, tag, host, port, tlsMode, null, ipv6BindAddr, progress, dr);
            used = EgressUsed.init;
            return directConn;
        } catch (HolderUnavailableException e) {
            throw e;
        } catch (Exception e) {
            logWarn("happyEyeballsConnect direct to %s failed (%s), trying Mullvad pool", host, e.msg);
        }
    }
    // Generic host-aware egress picker: no per-hostname hardcode.
    // - Globally dead proxies (failCount >= 3) are already filtered by
    //   getHealthyProxies() / getHealthyProxiesForHost().
    // - Per-host G/K/Z bans learned via banEgressForHost() are filtered
    //   by getHealthyProxiesForHost(hostLower) so a G-lined exit for one
    //   host never blocks it for another.
    auto healthyForHost = getHealthyProxiesForHost(hostLower);
    // Smart routing: spread load for hosts with many networks (e.g. 6x SuperNets)
    // by rotating the healthy list per call via global round-robin. Without this,
    // all 6 networks for irc.supernets.org would try de first at the same time,
    // hammering that exit's 32/10m limit and getting "Too many unknown connections".
    // With rotation, they try de, ch, nl, se, gb, us respectively, spreading 6 conns
    // across 6 exits (1 per IP) and staying under per-IP limits. Session-limit
    // throttling (isThrottleError) already bans the hammered exit for 12h via
    // banEgressForHost, but rotation prevents the initial herd.
    if (healthyForHost.length > 1 && egressNodeId.length == 0) {
        size_t startIdx = 0;
        if (gMullvadLock !is null) synchronized (gMullvadLock) {
            startIdx = mullvadRR++ % healthyForHost.length;
        } else {
            startIdx = mullvadRR++ % healthyForHost.length;
        }
        if (startIdx != 0) {
            auto rotated = healthyForHost[startIdx .. $] ~ healthyForHost[0 .. startIdx];
            healthyForHost = rotated;
        }
        logDebug("Mullvad smart routing for %s: startIdx=%d", hostLower, startIdx);
    }
    MullvadProxy*[] toTry;
    // Pinned "direct": the user asked for the bare host IP — never route
    // through an exit. If the host has banned it, the ban policy already
    // told them to pick another route; honour the pin and let the ban
    // window run.
    const pinDirect = egressNodeId.length > 0 && egressNodeId.toLower() == DIRECT_EGRESS_LABEL;
    string egressBusyNote;
    if (egressNodeId.length > 0 && !pinDirect) {
        // Country/city pin: reuse a slot already on that location, else
        // retarget an idle one. A slot carrying live connections is never
        // touched, so honouring this pin cannot drop another network.
        string reason;
        auto slot = acquireSlotForPin(hostLower, egressNodeId.toLower(), reason);
        if (slot !is null) {
            toTry ~= slot;
        } else {
            logWarn("Mullvad pin '%s' unavailable for %s (%s) — using automatic",
                egressNodeId, hostLower, reason);
            logJsonMap("warn", "connection", "Egress pin unavailable",
                ["host": hostLower, "pin": egressNodeId, "reason": reason,
                 "event": "egress_busy"]);
            egressBusyNote = egressPinFallbackCopy(reason);
        }
    } else if (egressNodeId.length == 0 && healthyForHost.length == 0) {
        // Automatic, and every existing exit is host-banned or dead: retarget
        // one idle slot to the best location this host has not banned rather
        // than falling straight through to the (possibly banned) direct route.
        // At most one retarget per connect attempt — this is the only call.
        auto target = bestUnbannedLocationFor(hostLower);
        if (target.length > 0) {
            string reason;
            auto slot = acquireSlotForPin(hostLower, target, reason);
            if (slot !is null) {
                logInfo("Automatic egress: slot %s retargeted to %s for %s (no healthy exit left)",
                    slot.label, target, hostLower);
                toTry ~= slot;
            } else {
                logWarn("Automatic egress: no slot could take %s for %s (%s)",
                    target, hostLower, reason);
            }
        }
    }
    if (egressBusyNote.length > 0) report(progress, "info", egressBusyNote);
    if (!pinDirect) {
        foreach (p; healthyForHost) {
            bool already = false;
            foreach (q; toTry) if (q is p) { already = true; break; }
            if (!already) toTry ~= p;
        }
    }
    // Direct fallback — the sidecars are egress, not a proxy mesh; the bare
    // host IP is the last resort. Skipped while the host has it banned and
    // an exit is still available; kept when it is the only route (or
    // pinned) so the attempt surfaces the ban instead of failing silently.
    if (pinDirect || toTry.length == 0 || !isDirectBannedForHost(hostLower)) toTry ~= null;
    else logWarn("Direct egress is host-banned for %s — trying %d exit(s) only", hostLower, cast(int) toTry.length);
    Exception lastErr;
    foreach (proxy; toTry) {
        try {
            auto conn = happyEyeballsConnectWithProxy(holder, tag, host, port, tlsMode, proxy, ipv6BindAddr, progress, dr);
            used = EgressUsed.init;
            if (proxy !is null) {
                used.label = proxy.label;
                used.host = proxy.host ~ ":" ~ proxy.port.to!string;
                // Best-effort resolve Tailnet IP for admin display.
                used.ip = resolveProxyIp(proxy);
                used.locationId = slotBanKey(proxy);
                used.locationText = proxyLocationText(proxy);
                // Take the slot's refcount: it can no longer be retargeted
                // while this connection lives. Released by the client's
                // releaseEgressSlot() on every disconnect / reconnect.
                holdSlot(proxy.label);
            }
            return conn;
        } catch (HolderUnavailableException e) {
            // The exit was never tried: no ban, no counters — just retry
            // later from the connection loop.
            throw e;
        } catch (Exception e) {
            lastErr = e;
            logWarn("happyEyeballsConnect via %s failed for %s:%d: %s, trying next egress", proxy ? proxy.label : "direct", host, port, e.msg);
            // On TLS timeout specifically, ban this egress for this host so the next proxy is tried immediately
            // rather than re-cycling the same wedged exit.
            if (proxy !is null && e.msg.canFind("TLS handshake timed out")) {
                banEgressForHost(host, slotBanKey(proxy));
            }
            continue;
        }
    }
    used = EgressUsed.init;
    throw lastErr ? lastErr : new Exception("All connection attempts failed for " ~ host ~ ":" ~ port.to!string);
}
// ── Nick prefix helpers ───────────────────────────────────────────────────────
//
// Every char a server can put in front of a nick in NAMES, highest rank
// first. `*` is InspIRCd's <operprefix> and `!` its <ojoin>; the rest are
// the usual status modes. With `multi-prefix` (which this engine always
// requests) a nick arrives carrying the WHOLE run it holds — an opered
// channel founder is `*~@+Zodiac` — so every one of these helpers works on
// the run, not on nick[0]. Treating only `~&@%+` as prefixes made
// `*~@+Zodiac` look like a bare nick: `sameNick` stopped matching it, and
// the 352 handler "promoted" it by replacing the run with the single char
// from the WHO flags, which is how the channel owner ended up rendered as
// an op.
private enum nickPrefixChars = "*!~&@%+";

private bool isNickPrefixChar(char c) @safe pure nothrow @nogc {
    foreach (p; nickPrefixChars) if (p == c) return true;
    return false;
}

/// Length of the leading run of prefix chars (0 when the nick is bare).
private size_t nickPrefixRun(string nick) @safe pure nothrow @nogc {
    size_t i = 0;
    while (i < nick.length && isNickPrefixChar(nick[i])) i++;
    return i;
}

private string stripNickPrefix(string nick) {
    nick = nick[nickPrefixRun(nick) .. $];
    // Strip hostmask suffix when userhost-in-names is active (nick!user@host)
    auto bang = nick.indexOf("!");
    if (bang > 0) nick = nick[0 .. bang];
    return nick;
}

private string nickPrefix(string nick) {
    return nick[0 .. nickPrefixRun(nick)];
}

/// Sweeps per channel per connection before the engine gives up asking.
enum int MAX_WHO_ENRICH_ATTEMPTS = 3;

/// Whether `member` (`@nick`, `nick!user@host`, or bare) still needs a
/// realname probe. `probed` records nicks the server has already answered
/// for — `realnames` cannot double as that record because an answer equal
/// to the nick is deliberately not stored.
bool memberNeedsRealname(string member, const string[string] realnames,
                         const bool[string] probed) {
    const bare = stripNickPrefix(member);
    if (bare.length == 0) return false;
    return (bare !in realnames) && (bare !in probed);
}

/// Whether the realname sweep should still issue `WHO <chan>`.
/// `attempts` = sweeps already sent for this channel on this connection.
bool channelNeedsRealnameWho(const string[] members,
                             const string[string] realnames,
                             const bool[string] probed,
                             int attempts,
                             int maxAttempts = MAX_WHO_ENRICH_ATTEMPTS) {
    if (attempts >= maxAttempts) return false;
    foreach (m; members)
        if (memberNeedsRealname(m, realnames, probed)) return true;
    return false;
}

/// Channel status mode letter → the prefix char it renders as, `'\0'` for a
/// mode that takes no member target. `y`/`Y` are InspIRCd's operprefix and
/// ojoin modes: without them a `MODE #chan +yo nick1 nick2` consumed no
/// target for `y` and applied `o` to the wrong nick.
private char prefixForModeChar(char m) @safe pure nothrow @nogc {
    switch (m) {
        case 'q': return '~';
        case 'a': return '&';
        case 'o': case 'O': return '@';
        case 'h': return '%';
        case 'v': return '+';
        case 'y': return '*';
        case 'Y': return '!';
        default: return '\0';
    }
}

/// Add `p` to a member entry's prefix run, keeping the run in rank order.
/// Idempotent, and it never drops the other prefixes the member holds —
/// replacing the first char (what this used to do) turned `~alice` into
/// `+alice` on a `+v`, demoting an owner to voiced.
private string addNickPrefix(string entry, char p) @safe pure {
    const run = nickPrefixRun(entry);
    const bare = entry[run .. $];
    string kept;
    foreach (c; nickPrefixChars) {
        if (c == p) { kept ~= c; continue; }
        foreach (h; entry[0 .. run]) if (h == c) { kept ~= c; break; }
    }
    return kept ~ bare;
}

/// Remove exactly `p` from a member entry's prefix run, leaving any other
/// status the member still holds in place.
private string removeNickPrefix(string entry, char p) @safe pure {
    const run = nickPrefixRun(entry);
    string kept;
    foreach (c; entry[0 .. run]) if (c != p) kept ~= c;
    return kept ~ entry[run .. $];
}

@("nick prefix helpers handle a multi-prefix run")
unittest {
    assert(stripNickPrefix("*~@+Zodiac") == "Zodiac");
    assert(stripNickPrefix("Zodiac") == "Zodiac");
    assert(stripNickPrefix("@bob!user@host") == "bob");
    assert(nickPrefix("*~@+Zodiac") == "*~@+");
    assert(nickPrefix("bare") == "");
    // Rank order is preserved and an already-held prefix is a no-op.
    assert(addNickPrefix("@bob", '~') == "~@bob");
    assert(addNickPrefix("~@bob", '+') == "~@+bob");
    assert(addNickPrefix("~@bob", '@') == "~@bob");
    assert(addNickPrefix("bob", '+') == "+bob");
    // Removing one status keeps the others.
    assert(removeNickPrefix("*~@+Zodiac", '+') == "*~@Zodiac");
    assert(removeNickPrefix("*~@Zodiac", '~') == "*@Zodiac");
    assert(removeNickPrefix("bob", '@') == "bob");
}

// ── CASEMAPPING-aware nick comparison ─────────────────────────────────────────
// modern.ircdocs.horse (Implementation Notes → Casemapping) asks clients to
// discover CASEMAPPING from RPL_ISUPPORT and casefold nick/channel keys
// with it. Servers differ: "ascii" folds A-Z only, "rfc1459" additionally
// maps []\^ → {}|~, "rfc1459-strict" maps []\ → {|} but leaves ^ and ~
// distinct. Unknown values fall back to rfc1459 (the common default).

/// Fold one byte per the named CASEMAPPING. Pure — unit-testable.
char foldCaseChar(char c, string mapping) @safe pure nothrow @nogc {
    if (c >= 'A' && c <= 'Z') return cast(char)(c + ('a' - 'A'));
    if (mapping == "ascii") return c;
    switch (c) {
        case '[': return '{';
        case ']': return '}';
        case '\\': return '|';
        case '^': return (mapping == "rfc1459-strict") ? '^' : '~';
        default: return c;
    }
}

/// CASEMAPPING-aware equality for already-bare nicks. Pure.
bool nicksEqualMapped(string a, string b, string mapping) @safe pure nothrow {
    if (a.length != b.length) return false;
    foreach (i; 0 .. a.length) {
        if (foldCaseChar(a[i], mapping) != foldCaseChar(b[i], mapping))
            return false;
    }
    return true;
}

@("foldCaseChar ascii folds A-Z only")
unittest {
    assert(foldCaseChar('A', "ascii") == 'a');
    assert(foldCaseChar('[', "ascii") == '[');
    assert(foldCaseChar('^', "ascii") == '^');
}

@("foldCaseChar rfc1459 maps brackets and caret")
unittest {
    assert(foldCaseChar('[', "rfc1459") == '{');
    assert(foldCaseChar(']', "rfc1459") == '}');
    assert(foldCaseChar('\\', "rfc1459") == '|');
    assert(foldCaseChar('^', "rfc1459") == '~');
}

@("foldCaseChar strict leaves caret distinct")
unittest {
    assert(foldCaseChar('[', "rfc1459-strict") == '{');
    assert(foldCaseChar('^', "rfc1459-strict") == '^');
}

@("nicksEqualMapped folds case per mapping")
unittest {
    assert(nicksEqualMapped("Zod", "zod", "ascii"));
    assert(nicksEqualMapped("a[b", "a{b", "rfc1459"));
    assert(!nicksEqualMapped("a[b", "a{b", "ascii"));
    assert(!nicksEqualMapped("a^b", "a~b", "rfc1459-strict"));
    assert(nicksEqualMapped("a^b", "a~b", "rfc1459"));
    assert(!nicksEqualMapped("Zod", "Zod_", "rfc1459"));
}

// ── MONITOR command builder (IRCv3 monitor) ───────────────────────────────────
// Verbs: "+" / "-" (targets required, comma-separated nicks),
// "C" (clear), "L" (list), "S" (status query). Returns null when the
// verb/target combination is invalid.

/// Build a MONITOR wire line. Pure — unit-testable.
string buildMonitorLine(string verb, string targets) @safe pure {
    import std.uni : toUpper;
    auto v = toUpper(verb);
    if (v == "+" || v == "-") {
        if (targets.length == 0) return null;
        return "MONITOR " ~ v ~ " " ~ targets;
    }
    if (v == "C" || v == "L" || v == "S") return "MONITOR " ~ v;
    return null;
}

@("buildMonitorLine builds +/- with targets")
unittest {
    assert(buildMonitorLine("+", "alice,bob") == "MONITOR + alice,bob");
    assert(buildMonitorLine("-", "alice") == "MONITOR - alice");
}

@("buildMonitorLine builds bare C/L/S verbs")
unittest {
    assert(buildMonitorLine("C", "") == "MONITOR C");
    assert(buildMonitorLine("l", "") == "MONITOR L");
    assert(buildMonitorLine("S", "") == "MONITOR S");
}

@("buildMonitorLine rejects empty targets and unknown verbs")
unittest {
    assert(buildMonitorLine("+", "") is null);
    assert(buildMonitorLine("-", "") is null);
    assert(buildMonitorLine("X", "alice") is null);
}

// ── Lag probe + TLS detail helpers ───────────────────────────────────────────

/// Current wall-clock time in unix milliseconds.
private long unixMsNow() @safe {
    import std.datetime.systime : unixTimeToStdTime;
    return (Clock.currStdTime - unixTimeToStdTime(0)) / 10_000;
}

/// Wire token for the keepalive lag probe: `PING :LAG<sentUnixMs>`.
/// The server echoes the token back in PONG so the round trip can be
/// measured without any per-connection bookkeeping beyond the
/// outstanding send timestamp.
string lagPingToken(long sentMs) @safe pure {
    return "LAG" ~ sentMs.to!string;
}

/// Extracts the send timestamp from a PONG parameter produced by
/// `lagPingToken`. Returns -1 when the parameter is not a lag token
/// (e.g. a server-initiated PONG or a legacy `keepalive` reply).
long parseLagPongParam(string param) @safe pure nothrow {
    if (param.length <= 3 || param[0 .. 3] != "LAG") return -1;
    foreach (c; param[3 .. $]) if (c < '0' || c > '9') return -1;
    try return param[3 .. $].to!long;
    catch (Exception) return -1;
}

/// Formats a unix-ms timestamp as `YYYY-MM-DD` (UTC).
string formatUnixMsDate(long ms) @safe {
    import std.datetime.systime : SysTime;
    import std.datetime.timezone : UTC;
    return SysTime.fromUnixTime(ms / 1000, UTC()).toISOExtString()[0 .. 10];
}

/// Builds the `tls_done` server-log line. With TLS details present the
/// line reads `TLS handshake complete — <version> · <cipher> · cert <CN>
/// (issuer <issuer>, expires <YYYY-MM-DD>)`; otherwise the generic
/// fallback is returned.
string formatTlsDoneText(bool hasInfo, TlsInfo info, string fallback) @safe {
    if (!hasInfo) return fallback;
    return "TLS handshake complete — " ~ info.version_ ~ " · " ~ info.cipher
        ~ " · cert " ~ info.certCn ~ " (issuer " ~ info.certIssuer
        ~ ", expires " ~ formatUnixMsDate(info.certNotAfterMs) ~ ")";
}

@("lagPingToken / parseLagPongParam round-trip")
unittest {
    assert(lagPingToken(1_700_000_000_123) == "LAG1700000000123");
    assert(parseLagPongParam("LAG1700000000123") == 1_700_000_000_123);
    assert(parseLagPongParam("keepalive") == -1);
    assert(parseLagPongParam("LAG") == -1);
    assert(parseLagPongParam("LAGabc") == -1);
    assert(parseLagPongParam("") == -1);
}

@("formatTlsDoneText renders details or falls back")
unittest {
    auto info = TlsInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384", "irc.example.org", "R11", 1_704_067_200_000);
    assert(formatTlsDoneText(true, info, "fallback")
        == "TLS handshake complete — TLSv1.3 · TLS_AES_256_GCM_SHA384 · cert irc.example.org (issuer R11, expires 2024-01-01)");
    assert(formatTlsDoneText(false, info, "fallback") == "fallback");
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

/// Packs channel names into `JOIN` argument strings that stay inside the
/// 512-byte IRC line limit (`maxArgLen` counts only the argument, so the
/// caller's `"JOIN "` prefix and the CRLF have room).
///
/// One comma-joined JOIN per batch instead of one JOIN per channel: a
/// server that rate-limits *per command* (SuperNETs/DangerousIRCd answers
/// `421 … connected for at least 5 seconds` to every early JOIN) then
/// produces a single refusal to wait out, and the user's server log gets
/// one line instead of one per channel.
string[] joinBatches(const(string)[] chans, size_t maxArgLen = 400) pure @safe {
    string[] out_;
    string cur;
    foreach (chan; chans) {
        if (chan.length == 0) continue;
        if (cur.length == 0) {
            cur = chan;
            continue;
        }
        if (cur.length + 1 + chan.length > maxArgLen) {
            out_ ~= cur;
            cur = chan;
            continue;
        }
        cur ~= "," ~ chan;
    }
    if (cur.length) out_ ~= cur;
    return out_;
}

/// Parses the grace period out of an ERR_UNKNOWNCOMMAND (421) JOIN throttle,
/// e.g. SuperNETs' `421 <nick> JOIN :You must be connected for at least 5
/// seconds before you can use this command` (verified on
/// irc.supernets.org, openwater.supernets.org, 2026-09-05). Returns 0 when
/// the text is not a throttle notice, so callers can tell "the server is
/// making us wait" apart from a genuinely unknown command.
///
/// The server is the authority on its own window: reading the number here
/// means a network that says 10 seconds is honoured without configuration.
uint parseJoinThrottleSeconds(string text) @safe pure nothrow {
    import std.string : indexOf, toLower;
    if (text.length == 0) return 0;
    string lower;
    try { lower = toLower(text); } catch (Exception) { return 0; }
    immutable marker = "connected for at least";
    auto at = lower.indexOf(marker);
    if (at < 0) return 0;
    uint secs = 0;
    bool sawDigit = false;
    foreach (c; lower[at + marker.length .. $]) {
        if (c >= '0' && c <= '9') {
            sawDigit = true;
            secs = secs * 10 + cast(uint)(c - '0');
            if (secs > 600) return 600; // absurd window: clamp, never spin
        } else if (sawDigit) {
            break;
        } else if (c != ' ') {
            return 0; // digits must follow the marker, not prose
        }
    }
    return sawDigit ? secs : 0;
}

@("parseJoinThrottleSeconds reads the SuperNETs 421 text")
unittest {
    assert(parseJoinThrottleSeconds(
        "You must be connected for at least 5 seconds before you can use this command") == 5);
    assert(parseJoinThrottleSeconds(
        "You must be connected for at least 10 seconds before you can use this command") == 10);
}

@("parseJoinThrottleSeconds ignores unrelated 421 text")
unittest {
    assert(parseJoinThrottleSeconds("Unknown command") == 0);
    assert(parseJoinThrottleSeconds("") == 0);
    // Same shape, no number — must not be read as "wait 0".
    assert(parseJoinThrottleSeconds("You must be connected for at least a while") == 0);
}

@("parseJoinThrottleSeconds clamps an absurd window")
unittest {
    assert(parseJoinThrottleSeconds("connected for at least 99999 seconds") == 600);
}

/// Thrown when services definitively reject our SASL credential (904/905).
/// The stored password does not match the live NickServ account, so every
/// reconnect would re-enter the same nick war. The run loop catches this
/// separately from generic failures and parks the network (persisted
/// `disabled`, same as the admin-disconnect path) instead of backing off
/// and retrying forever. A proven credential — NickServ-password site login
/// or admin link/reset — re-enables via `reconnectNetwork`.
class SaslParkedException : Exception {
    this(string msg) { super(msg); }
}

/// Persistent IRC client with auto-reconnect and IRCv3 support.
final class PersistentIRCClient {
    private {
        NetworkConfig      config;
        /// Relay stream to the holder (AF_UNIX or TCP). Plain IRC bytes;
        /// the holder owns the upstream TCP/SOCKS5/TLS socket.
        TCPConnection      connection;
        /// Client of this engine's holder; null only in unit tests.
        HolderClient       holder;
        /// Holder id (`c-<n>`) of the live upstream connection; "" when
        /// there is none.
        string             holderConnId;

        /// unix-ms when the current registration handshake began (≈ TCP
        /// connect). The JOIN-throttle window is measured from there, and
        /// the retry below needs it after registration has returned.
        long                registrationStartedAtMs;
        /// Channels whose JOIN we sent but have not seen confirmed (our own
        /// JOIN echo) or refused (471/473/474/…). Bounded; cleared per
        /// connection. Drives the JOIN-throttle retry.
        string[]            joinsAwaitingConfirm;
        /// Throttle retry rounds already used on this connection, and whether
        /// one is waiting out the window right now. Bounded so a server that
        /// keeps answering "wait" cannot become a JOIN loop.
        int                 joinThrottleRounds;
        bool                joinThrottleRetryInFlight;

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
        /// One DISCONNECTED lifecycle event per drop. Set by whichever path
        /// emits first (handleServerError on a server ERROR, or
        /// handleDisconnection) and cleared when the next attempt starts, so
        /// the `_server` timeline no longer shows two or three
        /// "Disconnected" rows for a single disconnect.
        bool                disconnectedEmitted;

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
        // True when this registration attempt landed on the random-suffix
        // escape-hatch nick (persisted in the 433 handler). Tells the 001
        // handler to keep that persisted nick; a plain `_` fallback with
        // this false clears the persisted key so the next reconnect
        // retries the configured nick. Reset at every attempt start.
        bool                randomNickPersisted;
        bool                isAway = false;
        string              awayMessage;
        string[string]      channelState;
        string[string]      channelTopics;
        string[][string]    channelUsers;
        long[string]        lastWhoTime;  // throttle: chan→last WHO timestamp
        // Sweeps already sent per channel on this connection; capped by
        // MAX_WHO_ENRICH_ATTEMPTS so a server that answers WHO without
        // naming every member cannot keep the sweep alive forever.
        int[string]         whoEnrichAttempts;
        long                lastWhoisTime; // throttle: 1/s for WHOIS queries
        // IRCCloud-style realname cache. Populated from extended-join
        // (realname param) and RPL_WHOISUSER (311). Used to render the
        // <span class="author-realname"> next to the nick.
        string[string]      realnames;
        // Nicks the server has already answered a realname question for.
        // Distinct from `realnames`, which deliberately does not store an
        // answer equal to the nick (the UI would double-print it) — without
        // this set those nicks stayed "unknown" and re-triggered WHO/WHOIS
        // on every sweep, forever. Survives reconnects: the answer does not
        // change with the socket.
        bool[string]        realnameProbed;
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
        /// CAP values as advertised in `CAP LS`/`CAP NEW`, keyed by cap name
        /// (`draft/multiline` → `max-bytes=5250,max-lines=15`). The names
        /// alone live in `ackedCaps`; the values carry the only flood limits
        /// any ircd actually tells clients about, and UnrealIRCd re-sends
        /// them via CAP DEL + CAP NEW when we move between its
        /// known-users / unknown-users groups.
        string[string]      capValues;

        // ── Outbound flood pacing ────────────────────────────────────────
        /// Local model of the server's fake-lag accumulator. See
        /// ircfiber.irc.pacer.
        FakeLagPacer        pacer;
        /// Message lines waiting for the pacer to admit them. Only user
        /// traffic (PRIVMSG/NOTICE) is parked here; protocol-critical lines
        /// (PING/PONG/CAP/NICK/registration) always go out immediately.
        string[]            pacedQueue;
        enum MAX_PACED_QUEUE = 2_000;
        /// Per-channel `+f` line-rate ceiling and its sliding window,
        /// keyed by lowercase channel.
        ChannelLineLimit[string] chanFloodLimit;
        LineRateWindow[string]   chanFloodWindow;
        /// True when this network's ircd flood configuration is one we
        /// author ourselves (`IRCFIBER_FLOOD_TRUSTED_HOSTS` — in production
        /// `irc.ircfiber.com`, whose `<connect name="ircfiber-engine">`
        /// class every platform user is multiplexed through).
        ///
        /// There the guessing stops: `trustedRate` is that class's real
        /// `commandrate`/`threshold`, and it MUST be respected because the
        /// class runs `fakelag="no"` — InspIRCd kills an over-rate client
        /// with `Excess Flood` instead of delaying it (verified against
        /// `scripts/flood-ircd`: 300 lines at once → kill on line 101).
        bool                floodTrusted;
        /// ditto — the `<connect>` numbers, from the env the deploy renders.
        CommandRateLimit    trustedRate;
        /// Local model of InspIRCd's per-user command-penalty counter.
        /// Only used while `floodTrusted`.
        CommandRateBucket   cmdBucket;
        /// Unix ms of the last "still sending" server-log line, so a long
        /// paste reports progress instead of looking hung.
        long                lastPacedNoticeMs;
        /// Our own `nick!user@host` as other clients see it (396
        /// RPL_VISIBLEHOST, or the echo of our own JOIN). Drives the
        /// per-line payload budget; empty until known.
        string              ownHostmask;
        /// Unix ms of the last paced write, for the relax-after-quiet rule.
        long                lastPacedWriteMs;
        /// Unix ms of the last genuine flood complaint, for the decay rule.
        long                lastFloodComplaintMs;
        /// True once 903 RPL_SASLSUCCESS arrived on this connection: we are
        /// identified to services, so the server's looser `known-users`
        /// flood limits apply.
        bool                saslSucceeded;
        /// Set while a multiline batch is being written, so `writeRaw` does
        /// not charge each line individually.
        bool                chargeSuppressed;
        /// Monotonic counter for `draft/multiline` BATCH reference tags.
        uint                batchSeq;
        /// True when we currently hold IRCOp status on this connection
        /// (381 / user mode `+o` / 221). Grants the pacer's fake-lag
        /// exemption optimistically — `immune:lag` is a privilege an oper
        /// block can withhold, so the first flood complaint revokes it.
        bool                isOper;
        /// Channels where our own status modes exempt us from `+f`
        /// (floodprot's `check_channel_access(client, channel, "hoaq")`),
        /// or where a `~F:`/`~flood:` `+e` entry matches us. Keyed
        /// lowercase.
        bool[string]        chanFloodExempt;
        /// Channels we have already probed with `MODE <chan> f`, so the
        /// query is issued at most once per channel per connection.
        bool[string]        chanFloodProbed;

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
        /// Server software/version token from RPL_MYINFO (004), e.g.
        /// `UnrealIRCd-6.1.7`, `InspIRCd-4`, `ergo-2.13.0`. The only
        /// machine-readable statement a server makes about *which ircd it
        /// is*; used to decide whether server-specific probes are safe to
        /// send (see `probeChannelFlood`). Empty until 004 arrives.
        string              serverSoftware;

        // /LIST accumulation (transient, per TCP connection; NOT part of
        // the session snapshot). Rows from 322 are buffered here and
        // flushed as synthetic CHANNEL_LIST chunks of CHANNEL_LIST_CHUNK
        // rows; 323 / 416 / 263-while-listing finish the request.
        ChannelListRow[]    channelListPending;
        bool                channelListInFlight;
        bool                channelListEmittedFirst;
        string              channelListPattern;
        enum CHANNEL_LIST_CHUNK = 200;

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

        // Per-user IPv6 (IRCCloud-style): deterministic source IP per UID.
        import std.uuid : UUID;
        UUID                ownerId;
        /// Browser IP forwarded via WEBIRC on the fiber network ("" = none).
        string              clientIp;
        string              ipv6BindCache;
        bool                ipv6BindResolved;
        // Smart routing: Redis access for failure reporting + reassignment detection.
        RedisStorage        redis;
        /// This engine's server ID (used for failure reporting + assignment check).
        string              serverId;
        /// Last DISCONNECT reason surfaced to the UI. Mirrors the loop-local
        /// lastEmittedReason so JSON lifecycle logs (disconnected /
        /// reconnect_scheduled) can attribute the reason even after the
        string              lastDisconnectReason;
        /// Label of the SOCKS egress that won the current TCP connect (""
        /// = direct). Used by handleServerError() to host-ban the egress
        /// when the server later G/K/Z-lines us — generic, no hostname
        /// hardcode.
        string              activeEgressLabel;
        /// Full proxy host that won (e.g. "tailscale-mullvad-de:1055").
        string              activeEgressHost;
        /// Resolved Tailnet IP of the active proxy (e.g. "100.117.47.8").
        string              activeEgressIp;
        /// Per-host ban key of the active egress: its location id
        /// ("de-ber") or `slot:<label>`. Survives a disconnect so the ban
        /// policy in the reconnect loop can still attribute the failure.
        string              activeEgressLocationId;
        /// Human-readable location of the active egress ("Berlin, Germany").
        /// "" for direct or an unknown location. This is what the UI shows.
        string              activeEgressLocation;
        /// Slot whose refcount this client currently holds ("" = none).
        /// Distinct from activeEgressLabel, which deliberately survives a
        /// disconnect for the ban policy; this one is cleared the moment the
        /// hold ends, so a slot is never pinned by a dead connection.
        string              egressSlotLabel;
        /// Whether `egressSlotLabel`'s refcount is currently taken.
        bool                egressSlotHeld;
        /// Remote IP the Happy Eyeballs race actually connected to (e.g.
        /// "2001:6b0:e:2a18::120" for an AAAA winner). The family of this
        /// address is the only reliable "did we use IPv6" signal — the
        /// egress fields above only describe the SOCKS hop.
        string              activePeerIp;
        /// Local source IP of the live socket: the per-user IPv6 bind, the
        /// container/host address, or the Tailnet IP of the SOCKS sidecar.
        string              activeLocalIp;
        /// Consecutive "SSL/TLS tunnel closed" failures on the current
        /// egress for this host; drives the inferred-ban egress rotation
        /// in the reconnect loop. Reset on any other failure and on 001.
        int                 consecutiveTlsClosed;

        // ── Hot-swap support ──────────────────────────────────────────────────
        /// When non-zero, the connection's event loop will not perform any
        /// network I/O and will yield until this drops back to zero. Set by
        /// `pauseForDetach()`; cleared by `resumeAfterDetach()`. The pause
        /// is observed at the `yield()` checkpoints inside
        /// `processEvents()` so a single in-flight line is always allowed to
        /// finish before the loop stops.
        shared(int)         detachPauseCount;
        /// Set by `detachForHotSwap()`: the relay stream was closed on
        /// purpose, the session lives on in the holder and this process is
        /// exiting. Every disconnect/reconnect path returns silently.
        bool                detachedForHotSwap;
        /// TLS mode of the dial in flight (`none`/`implicit`/`starttls`),
        /// for the timeline adapter's wording.
        string              dialTlsMode;
        /// The dial in flight is the TLS→plain fallback re-dial.
        bool                dialPlainFallback;
        /// A META write already failed on this connection (log once).
        bool                metaWarned;
        /// Own NICK/JOIN/PART/KICK/AWAY/005 applied since the last META write.
        bool                metaDirty;
        /// A connection-loop fiber currently owns this client.
        bool                loopRunning;
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
        // Last time a `keepalive_missed` info line was emitted (unix secs).
        // Throttles that line to at most once per minute per network.
        long                lastKeepaliveMissedLogSecs;
        bool                idleEmitted;
        // ── Connection telemetry (surfaced via the state snapshot) ──────────
        /// Round trip of the last answered `PING :LAG<ms>` probe. -1 until
        /// the first PONG of a connection is measured; reset on disconnect.
        long                lagMs = -1;
        /// Send time (unix ms) of the outstanding lag probe; 0 when none.
        long                lagProbeSentMs;
        /// Unix ms of RPL_WELCOME for the live connection; 0 otherwise.
        long                connectedAtMs;
        /// Line counters for the live connection, logged on disconnect so a
        /// silent server-side kill can be attributed without re-deriving it.
        /// `whoOut` counts our own WHO/WHOIS probes.
        long                linesIn, linesOut, whoOut;
        /// Whether `tlsInfo` describes the live TLS session.
        bool                tlsInfoValid;
        /// Negotiated TLS session details for the live connection.
        TlsInfo             tlsInfo;
    }

    /// Set by the manager while an attach to a held session is being
    /// retried (`ERR busy`): `start()` must not dial fresh meanwhile — an
    /// open holder entry for this network means the server already has
    /// our session.
    package(ircfiber) bool attachPending;

    /// Creates a new persistent IRC client.
    this(NetworkConfig cfg, Channel!IRCRawEvent ch, RedisStorage redisStore = null, string sid = "", UUID owner = UUID.init, HolderClient holderClient = null) {
        this.holder       = holderClient;
        this.config       = cfg;
        this.eventChannel = ch;
        this.redis        = redisStore;
        this.serverId     = sid;
        this.ownerId      = owner;
        this.ipv6BindResolved = false;
        this.ipv6BindCache = "";
        // Never park: Duration.zero = retry forever at the 6 h tier (tiers/caps/jitter unchanged). The reconnect_gave_up path below is retained but unreachable unless a future cap returns.
        this.backoff      = new ExponentialBackoff(3.seconds, RECONNECT_MAX_DELAY_SECS.seconds, 0, Duration.zero);
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

    /// Starts the connection loop in a background task. No-op for a
    /// session that is already running (attached from the holder), while a
    /// loop fiber already owns this client, or while the manager is still
    /// retrying an attach to a held session (a fresh dial would double-
    /// socket the server).
    void start() {
        if (state == ConnectionState.connected) return;
        if (loopRunning || attachPending) return;
        // Set state immediately so any snapshot taken before the fiber runs
        // reflects the actual intent. Without this, a freshly created client
        // stays in 'disconnected' until the event loop schedules the fiber,
        // which could trick the frontend into thinking no reconnect is happening
        // (e.g. after an engine restart where state snapshots are written before
        // the connection-loop fiber gets to run).
        state = ConnectionState.connecting;
        spawnConnectionLoop("connection_loop");
    }

    /// Runs `runConnectionLoop()` on a fiber with one crash restart. Exactly
    /// one loop fiber per client: a second one (prod 2026-09-09 — attach
    /// fallback `start()` + `startDeferredClients()` after the holder died
    /// mid-boot) dials every reconnect twice and hands the second session
    /// a `_` nick.
    private void spawnConnectionLoop(string label) {
        if (loopRunning) {
            logJsonMap("warn", "connection", "Connection loop already running — not starting another",
                ["network": config.name, "label": label, "event": "loop_already_running"]);
            return;
        }
        loopRunning = true;
        safeFiberRun(label, config.name, {
            scope (exit) loopRunning = false;
            try {
                runConnectionLoop();
            } catch (Throwable e) {
                // Enterprise: catch Throwable (SyncError previously killed fiber as FATAL).
                string msg;
                try { msg = e.msg; } catch (Throwable) { msg = "unknown"; }
                logJsonMap("error", "connection",
                    "Connection loop crashed — restarting in 5s",
                    ["network": config.name, "event": "connection_crashed", "err": msg]);
                recordCounter("ircfiber.connection.loop_crash", 1, ["host": config.host]);
                try sleep(5.seconds); catch (Throwable) {}
                if (!isShutdownRequested) {
                    try {
                        runConnectionLoop();
                    } catch (Throwable e2) {
                        string m2;
                        try { m2 = e2.msg; } catch (Throwable) { m2 = "unknown"; }
                        logJsonMap("error", "connection",
                            "Connection loop crashed again",
                            ["network": config.name, "event": "connection_crashed_again", "err": m2]);
                        // Last resort: mark disconnected so snapshot reflects reality.
                        try { state = ConnectionState.disconnected; } catch (Throwable) {}
                    }
                }
            }
        });
    }

    /// Stops the connection and requests shutdown. If `quitReason` is
    /// supplied (or default empty), a QUIT is sent first so the server
    /// emits a final ERROR and closes the link cleanly; otherwise the
    /// socket is closed immediately. Either way the holder's upstream
    /// socket is closed too (see `transportClose`).
    void stop(string quitReason = "") {
        isShutdownRequested = true;

        if (state == ConnectionState.connected && connection.connected) {
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

    // ── Detach API (called by ConnectionManager before a hot-swap detach) ──

    /// Pause the event loop so the session state can be snapshotted
    /// exactly before the relay stream is closed. Idempotent (counted).
    /// The pause is observed at the next `yield()` inside
    /// `processEvents()`; the loop finishes its current line first, then
    /// spins until `resumeAfterDetach()` brings the count back to zero.
    void pauseForDetach() {
        import core.atomic : atomicOp;
        atomicOp!"+="(detachPauseCount, 1);
        logJsonMap("info", "connection",
            "Detach pause requested",
            ["network": config.name,
             "event": "detach_prepare"]);
    }

    /// Inverse of `pauseForDetach()`. When the count returns to zero the
    /// event loop resumes I/O. Idempotent.
    void resumeAfterDetach() {
        import core.atomic : atomicOp;
        const prev = atomicOp!"-="(detachPauseCount, 1);
        if (prev < 1) {
            // Defensive: restore so we don't underflow.
            atomicOp!"+="(detachPauseCount, 1);
            return;
        }
        if (prev - 1 == 0) {
            logJsonMap("info", "connection",
                "Detach pause released",
                ["network": config.name,
                 "event": "detach_released"]);
        }
    }

    /// Wait until the event loop has acknowledged the pause by observing
    /// the counter at a yield checkpoint. The loop only drops into
    /// `yield()` between reads, and a line is parsed in microseconds, so a
    /// short sleep is enough for any in-flight line to complete; a stalled
    /// loop cannot deadlock the detach (bounded).
    void waitForDetachPause() {
        sleep(20.msecs);
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

    /// The browser IP the gateway recorded for this connection's owner at
    /// its last websocket handshake (`RedisKeys.webircIp`), or "" when
    /// none / Redis unavailable. Read from Redis at connect time rather
    /// than taken from the control message, so engine-initiated reconnects
    /// and engine restarts keep forwarding it without the gateway.
    private string loadClientIp() {
        import std.string : strip;
        if (redis is null || ownerId == UUID.init) return "";
        try {
            return redis.getDb().get(RedisKeys.webircIp(ownerId.toString())).strip;
        } catch (Exception e) {
            logWarn("Failed to load client ip for %s: %s", config.name, e.msg);
            return "";
        }
    }

    /// Build the per-connection in-memory state the next engine needs to
    /// seamlessly continue this session on the held socket. Plain-old-data;
    /// no references back into this engine. With `graceful` (planned hot
    /// swap) the lines the flood pacer is still holding ride along in
    /// `outboundQueue`, so nothing typed during the swap window is lost.
    SessionSnapshot snapshotSession(bool graceful = false) {
        SessionSnapshot s;
        s.schemaTag = SESSION_SNAPSHOT_SCHEMA;
        s.config = config;
        s.userId = ownerId == UUID.init ? "" : ownerId.toString();
        s.serverId = serverId;
        s.sessionNick = sessionNick;
        s.isAway = isAway;
        s.awayMessage = awayMessage;
        s.ackedCaps = getAckedCaps();
        s.queryBuffers = queryBuffers.dup;
        s.failureReasons = failureReasons.dup;
        s.outboundQueue = outboundQueue.dup;
        if (graceful && pacedQueue.length > 0) s.outboundQueue ~= pacedQueue.dup;
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
        s.transportWasPlain = !tlsInfoValid;
        s.wasConnected = (state == ConnectionState.connected);
        s.capturedAtMs = unixMsNow();
        s.graceful = graceful;
        s.metaAtMs = s.capturedAtMs;
        s.serverFeatures = ServerFeaturesSnapshot(
            serverFeatures.network, serverFeatures.prefix,
            serverFeatures.chanModes, serverFeatures.maxChannels,
            serverFeatures.maxNickLen, serverFeatures.topicLen);
        // The FULL ISUPPORT map and the 004 software token: the server sends
        // them once per registration, so an attaching engine cannot re-learn
        // them — without them the "Server features" panel renders empty and
        // the ircd-specific probes stay off.
        s.isupportMap = isupportMap.dup;
        s.serverSoftware = serverSoftware;
        // Egress bookkeeping the next engine must re-take (slot hold, ban
        // attribution, admin display).
        s.egressLabel = activeEgressLabel;
        s.egressHost = activeEgressHost;
        s.egressIp = activeEgressIp;
        s.egressLocationId = activeEgressLocationId;
        s.egressLocationText = activeEgressLocation;
        s.peerIp = activePeerIp;
        s.localIp = activeLocalIp;
        return s;
    }

    /// Writes the session snapshot as the holder's META for the live
    /// connection, so a hot swap or a crash can re-attach it with the
    /// registered state. No-op without a live holder connection or before
    /// registration completes. Holder trouble is logged once per connection
    /// and never disturbs the session.
    void publishMeta(bool graceful) nothrow {
        if (holder is null || holderConnId.length == 0 || state != ConnectionState.connected) return;
        try {
            auto s = snapshotSession(graceful);
            try {
                holder.setMeta(holderConnId, toJSON(s));
            } catch (HolderErrorException e) {
                if (e.code != "too_large") throw e;
                // Member lists are the only unbounded part; drop them and
                // let the attaching engine re-sync with NAMES.
                s.channelUsers = null;
                s.usersDropped = true;
                holder.setMeta(holderConnId, toJSON(s));
            }
            metaWarned = false;
        } catch (Exception e) {
            if (metaWarned) return;
            metaWarned = true;
            string m; try { m = e.msg; } catch (Exception) { m = "unknown"; }
            try logJsonMap("warn", "connection", "Holder META write failed — session state may be stale for a swap",
                ["network": config.name, "holderId": holderConnId, "err": m, "event": "meta_write_fail"]);
            catch (Exception) {}
        }
    }

    /// Attach to a live connection the holder kept across an engine restart
    /// (planned hot swap or crash). Restores the snapshot the previous
    /// engine published, re-takes the egress slot hold, and resumes the
    /// event loop without any registration — the socket is already
    /// registered upstream. `graceful == false` (or `usersDropped`) means
    /// the member lists may have drifted: re-sync every channel with NAMES.
    void attachHeld(AttachResult r, SessionSnapshot s, bool graceful) {
        connection = r.stream;
        holderConnId = r.entry.id;
        detachedForHotSwap = false;
        isShutdownRequested = false;
        // Replay the snapshot. `config` stays the one loaded from Mongo (the
        // snapshot only carries identity); everything else is session state.
        if (s.sessionNick.length) sessionNick = s.sessionNick;
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
        accounts = s.accounts.dup;
        idents = s.idents.dup;
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
        isupportMap = s.isupportMap.dup;
        serverSoftware = s.serverSoftware;
        // Socket / TLS facts come from the holder (it owns the socket).
        activePeerIp = r.entry.peerIp;
        activeLocalIp = r.entry.localIp;
        tlsInfoValid = r.entry.tlsOk;
        tlsInfo = r.entry.tls;
        // Real signon time: the session never dropped.
        connectedAtMs = r.entry.connectedAtMs > 0 ? r.entry.connectedAtMs : unixMsNow();
        // Egress bookkeeping: the session still rides its Mullvad slot, so
        // re-take the hold — `retargetSlotByLabel` must refuse to move it
        // and `bounceNetworksOnEgress(label)` must find it, exactly as
        // before the swap.
        activeEgressLabel = s.egressLabel.length ? s.egressLabel : r.entry.tag.egressLabel;
        activeEgressHost = s.egressHost;
        activeEgressIp = s.egressIp;
        activeEgressLocationId = s.egressLocationId;
        activeEgressLocation = s.egressLocationText;
        egressSlotLabel = activeEgressLabel;
        egressSlotHeld = activeEgressLabel.length > 0;
        if (egressSlotHeld) holdSlot(activeEgressLabel);
        // Per-session pacing model: the fake-lag accumulator is unknown
        // after a swap; start it at zero as a registered user and keep the
        // learned limits. Trust is per host and re-derived from config.
        pacer.resetAccrual();
        pacer.adopt(assumedFloodLimits());
        applyFloodTrust();
        const nowSecs = Clock.currTime.toUnixTime!long;
        lastDataReceivedSecs = nowSecs;
        lastPongReceivedSecs = nowSecs;
        idleEmitted = false;
        state = ConnectionState.connected;
        backoff.reset();
        throttledUntil = 0;
        consecutiveTlsClosed = 0;
        droppedNoConnWarned = false;
        disconnectedEmitted = false;
        registrationTimeoutSince = 0;
        // Zero-valued CONNECTION_RETRY_STATUS at every backoff.reset() site
        // so the frontend clears any stale retry/fail banner.
        emitZeroRetryStatus();
        const upSecs = (unixMsNow() - connectedAtMs) / 1000;
        // No CONNECTED lifecycle event: the session never changed. One
        // server-log line tells the user what happened.
        emitLog("info", "Engine reattached to live connection (hot swap); connected for "
            ~ formatUptime(upSecs) ~ (activeEgressLabel.length ? " via " ~ egressDisplay() : "") ~ ".");
        logInfo("Attached to held connection %s for %s (%d joined channels, %d acked caps, graceful=%s)",
            holderConnId, config.host, channelState.length, ackedCaps.length, graceful);
        logJsonMap("info", "connection",
            "Attached to held connection",
            ["network": config.name, "host": config.host,
             "holderId": holderConnId,
             "graceful": graceful ? "true" : "false",
             "channels": channelState.length.to!string,
             "caps": ackedCaps.length.to!string,
             "uptimeSecs": upSecs.to!string,
             "egress": activeEgressLabel.length ? activeEgressLabel : "direct",
             "event": "attached"]);
        if (!graceful || s.usersDropped) {
            // Crash path: member lists may have drifted while no engine was
            // reading. NAMES is paced by writeRaw like any other line.
            foreach (chan; channelState.byKey) sendRaw("NAMES " ~ chan);
        }
        // Fresh META from the attached engine: the previous one was the
        // detach snapshot (`graceful == true`), and a crash before the next
        // upkeep write must not be mistaken for a planned swap.
        publishMeta(false);
        // Resume the ordinary loop: `state == connected` skips the dial and
        // enters processEvents() (whose first iteration drains the restored
        // outboundQueue); a later drop reconnects with backoff as usual.
        spawnConnectionLoop("attached_loop");
    }

    /// Hot-swap detach: publish the exact session state as META, close the
    /// relay stream and leave the upstream socket (and its egress slot)
    /// with the holder for the next engine. No QUIT, no CLOSE, no
    /// DISCONNECTED event; `state` stays `connected` — the truth during the
    /// gap. A client still dialing/registering just stops; the holder
    /// keeps a META-less entry that the next engine closes and re-dials.
    void detachForHotSwap() {
        const live = state == ConnectionState.connected && holderConnId.length > 0;
        if (live) publishMeta(true);
        isShutdownRequested = true;
        detachedForHotSwap = true;
        try { if (connection.connected) connection.close(); }
        catch (Exception e) { logWarn("detachForHotSwap: closing relay for %s: %s", config.name, e.msg); }
        if (live) {
            logJsonMap("info", "connection",
                "Detached for hot swap — session left with the holder",
                ["network": config.name, "host": config.host,
                 "holderId": holderConnId,
                 "channels": channelState.length.to!string,
                 "queued": (outboundQueue.length + pacedQueue.length).to!string,
                 "event": "detached"]);
        }
        holderConnId = "";
    }

    /// `"3d 4h"`, `"4h 12m"`, `"12m 5s"`, `"5s"` for the reattach line.
    private static string formatUptime(long secs) @safe pure {
        if (secs < 0) secs = 0;
        const d = secs / 86_400, h = (secs % 86_400) / 3600, m = (secs % 3600) / 60, s = secs % 60;
        if (d > 0) return d.to!string ~ "d " ~ h.to!string ~ "h";
        if (h > 0) return h.to!string ~ "h " ~ m.to!string ~ "m";
        if (m > 0) return m.to!string ~ "m " ~ s.to!string ~ "s";
        return s.to!string ~ "s";
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

    /// Whether the relay stream to the holder is alive.
    @property bool transportAlive() const {
        return connection.connected;
    }

    /// Read from the transport (non-blocking).
    size_t transportRead(ubyte[] buf) {
        if (!connection.waitForData(0.seconds)) return 0;
        return connection.read(buf, IOMode.once);
    }

    /// Write a line to the transport, appending CRLF.
    void transportWrite(const(char)[] line) {
        if (connection.connected) {
            connection.write((line ~ "\r\n").dup);
            connection.flush();
        }
    }

    /// Close the transport: the relay stream to the holder **and** the
    /// upstream IRC socket the holder owns for it. Non-empty `quit` makes
    /// the holder send `QUIT :<quit>` first (≤ 2 s grace); empty means the
    /// QUIT already went out in-band (or none is wanted). Idempotent. Every
    /// engine-initiated disconnect goes through here — only
    /// `detachForHotSwap()` closes the relay without closing upstream.
    void transportClose(string quit = "") {
        if (connection.connected) connection.close();
        if (holderConnId.length && holder !is null) {
            const id = holderConnId;
            holderConnId = "";
            try holder.close(id, quit);
            catch (HolderUnavailableException e) {
                logWarn("transportClose: holder unavailable, upstream %s for %s left to the holder's detach timeout (%s)",
                    id, config.name, e.msg);
            } catch (Exception e) {
                logWarn("transportClose: holder CLOSE %s failed for %s: %s", id, config.name, e.msg);
            }
        }
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
    /// Mullvad egress actually used for the live TCP connection.
    /// "" = direct (no SOCKS), else label like "de"/"se".
    @property string getActiveEgressLabel() const { return activeEgressLabel; }
    @property string getActiveEgressHost() const { return activeEgressHost; }
    @property string getActiveEgressIp() const { return activeEgressIp; }
    /// Location text of the live egress ("Berlin, Germany"); "" when direct
    /// or unknown. Published in the state snapshot for the UI.
    @property string getActiveEgressLocation() const { return activeEgressLocation; }
    /// Text for user-facing copy about the live egress: the location when
    /// known ("Berlin, Germany"), else the internal slot label.
    private string egressDisplay() const nothrow {
        return activeEgressLocation.length ? activeEgressLocation : activeEgressLabel;
    }
    /// Remote/local IPs of the live TCP socket; "" when not connected.
    @property string getActivePeerIp() const { return activePeerIp; }
    @property string getActiveLocalIp() const { return activeLocalIp; }
    /// Round trip of the last answered lag probe in ms; -1 when unknown.
    @property long getLagMs() const nothrow { return lagMs; }
    /// Unix ms of RPL_WELCOME for the live connection; 0 when not connected.
    @property long getConnectedAtMs() const nothrow { return connectedAtMs; }
    /// Seconds since the last inbound byte; 0 when never. Surfaced via the
    /// state snapshot so the UI can hint staleness before the reaper fires.
    @property long getDataAgeSecs() const { return lastDataReceivedSecs > 0 ? Clock.currTime.toUnixTime!long - lastDataReceivedSecs : 0; }
    /// Seconds since the last PONG; 0 when never.
    @property long getPongAgeSecs() const { return lastPongReceivedSecs > 0 ? Clock.currTime.toUnixTime!long - lastPongReceivedSecs : 0; }
    /// Whether `getTlsInfo()` describes the live TLS session.
    @property bool hasTlsInfo() const nothrow { return tlsInfoValid; }
    /// Negotiated TLS session details (valid only when `hasTlsInfo`).
    @property TlsInfo getTlsInfo() const nothrow { return tlsInfo; }

    /// Clears per-connection telemetry. Called on every disconnect and
    /// before each reconnect attempt so a stale lag/uptime/TLS tuple
    /// from the previous socket never leaks into the next snapshot.
    private void resetConnectionTelemetry() nothrow {
        // Every connect attempt and every disconnect passes through here, so
        // this is the one place that guarantees a slot hold cannot outlive
        // the socket that took it.
        releaseEgressSlot();
        lagMs = -1;
        lagProbeSentMs = 0;
        connectedAtMs = 0;
        tlsInfoValid = false;
        tlsInfo = TlsInfo.init;
        // Per-connection: a fresh socket may legitimately re-ask once.
        // `realnameProbed` is deliberately NOT cleared — the knowledge that
        // a nick has no distinct realname outlives the socket.
        whoEnrichAttempts = null;
        linesIn = 0;
        linesOut = 0;
        whoOut = 0;
        // A new socket gets a fresh throttle budget; pending JOINs from the
        // old one are meaningless (the reconnect re-sends the auto-joins).
        joinsAwaitingConfirm = [];
        joinThrottleRounds = 0;
        joinThrottleRetryInFlight = false;
    }

    /// Max channels tracked for the throttle retry. The auto-join burst is
    /// the realistic upper bound; the cap only stops an unbounded list when
    /// a server never answers a JOIN at all.
    private enum MAX_PENDING_JOINS = 64;

    /// Records the targets of an outgoing `JOIN <chans>[ <keys>]`.
    private void recordPendingJoins(string argstr) nothrow {
        try {
            auto targets = argstr.strip();
            auto sp = targets.indexOf(' ');
            if (sp >= 0) targets = targets[0 .. sp]; // drop channel keys
            foreach (raw; targets.split(",")) {
                auto chan = normalizeChannelName(raw.strip());
                if (chan.length == 0) continue;
                if (joinsAwaitingConfirm.canFind(chan)) continue;
                if (joinsAwaitingConfirm.length >= MAX_PENDING_JOINS) return;
                joinsAwaitingConfirm ~= chan;
            }
        } catch (Exception) {}
    }

    /// Drops a channel from the pending set — it either joined or the server
    /// refused it for a reason waiting will not fix.
    private void clearPendingJoin(string chan) nothrow {
        try {
            auto norm = normalizeChannelName(chan);
            auto i = joinsAwaitingConfirm.countUntil(norm);
            if (i >= 0) joinsAwaitingConfirm = joinsAwaitingConfirm.remove(i);
        } catch (Exception) {}
    }

    /// Max throttle retry rounds per connection. A server that keeps saying
    /// "wait" must never turn into a JOIN loop, but one round is not always
    /// enough: observed on prod, SuperNETs rate-limits *per command*, so the
    /// first round can itself be partially throttled.
    private enum MAX_JOIN_THROTTLE_ROUNDS = 3;

    /// SuperNETs/DangerousIRCd (and UnrealIRCd anti-flood) answer a JOIN sent
    /// inside the first N seconds after connect with `421 <nick> JOIN :You
    /// must be connected for at least N seconds…` and drop the channel, so an
    /// auto-join burst that raced the window leaves the user in no channels.
    ///
    /// The retry re-sends the unconfirmed channels as ONE comma-separated
    /// JOIN rather than a burst of them. Prod evidence (2026-09-05, five
    /// auto-joins on Supernets): a burst of five separate JOINs sent right
    /// after the window landed only the first — the rest were dropped
    /// silently by the per-command rate limit. One command is one rate-limit
    /// hit, and `TARGMAX=…JOIN:` there is unlimited (`CHANLIMIT=#:10`).
    private void scheduleJoinThrottleRetry(uint windowSecs) nothrow {
        if (joinThrottleRetryInFlight) return;
        if (joinThrottleRounds >= MAX_JOIN_THROTTLE_ROUNDS) return;
        if (joinsAwaitingConfirm.length == 0) return;
        joinThrottleRounds++;
        joinThrottleRetryInFlight = true;
        // +1s cushion: the window is measured server-side from its own view
        // of the connect, which is never earlier than ours. Later rounds are
        // answering a fresh 421, so wait the whole window again.
        auto waitMs = joinThrottleRounds == 1
            ? remainingJoinDelayMs(windowSecs + 1, nowMsSafe(), registrationStartedAtMs)
            : (windowSecs + 1) * 1000L;
        if (waitMs <= 0) waitMs = 500;
        try {
            logJsonMap("warn", "connection",
                "JOIN throttled — retrying after the server's grace period",
                ["network": config.name,
                 "channels": joinsAwaitingConfirm.join(","),
                 "round": joinThrottleRounds.to!string,
                 "windowSecs": windowSecs.to!string,
                 "waitMs": waitMs.to!string,
                 "event": "join_throttled"]);
            runTask({
                try {
                    sleep(waitMs.msecs);
                    scope(exit) joinThrottleRetryInFlight = false;
                    if (state != ConnectionState.connected) return;
                    // Anything confirmed or refused while we waited is gone
                    // from the pending set — never re-ask for it. A further
                    // round picks up whatever does not fit in one line.
                    auto batches = joinBatches(joinsAwaitingConfirm);
                    if (batches.length == 0) return;
                    logInfo("Re-sending throttled JOIN(s) for %s as one command: %s",
                        config.name, batches[0]);
                    sendRaw("JOIN " ~ batches[0]);
                } catch (Exception e) {
                    joinThrottleRetryInFlight = false;
                    logWarn("JOIN throttle retry failed for %s: %s", config.name, e.msg);
                }
            });
        } catch (Exception) {
            joinThrottleRetryInFlight = false;
        }
    }

    /// Drops this client's slot refcount if it holds one. Idempotent by
    /// construction — `egressSlotHeld` is cleared before the release.
    private void releaseEgressSlot() nothrow {
        if (!egressSlotHeld) return;
        egressSlotHeld = false;
        releaseSlot(egressSlotLabel);
        egressSlotLabel = "";
    }

    /// Whether a given IRCv3 capability was negotiated.
    bool hasCap(string cap) const { return (cap in ackedCaps) !is null && ackedCaps[cap]; }

    /// Whether server-side history is available. IRCv3 names it
    /// `draft/chathistory`; accept a bare `chathistory` too for servers
    /// that ship the un-prefixed spelling.
    bool hasChathistoryCap() const {
        return hasCap("draft/chathistory") || hasCap("chathistory");
    }

    /// CASEMAPPING-aware nick equality for membership lookups. Strips
    /// channel prefixes and userhost-in-names suffixes from both sides,
    /// then folds per the server's ISUPPORT CASEMAPPING (default
    /// rfc1459). Replaces bare `==` at every site that matches an event
    /// nick against the channel roster or the session nick.
    bool sameNick(string a, string b) {
        string mapping = "rfc1459";
        if (auto m = "CASEMAPPING" in isupportMap)
            if (m.length) mapping = *m;
        return nicksEqualMapped(stripNickPrefix(a), stripNickPrefix(b), mapping);
    }

    /// Returns all negotiated capabilities.
    string[] getAckedCaps() const {
        string[] result;
        foreach (cap, acked; ackedCaps) {
            if (acked) result ~= cap;
        }
        return result;
    }

    /// Updates the network configuration.
    void updateConfig(NetworkConfig cfg) { config = cfg; ipv6BindResolved = false; ipv6BindCache = ""; }

    /// Owner UUID (for per-user IPv6). Exposed for the manager / session snapshot.
    @property UUID getOwnerId() const { return ownerId; }
    void setOwnerId(UUID uid) { ownerId = uid; ipv6BindResolved = false; ipv6BindCache = ""; }

    /// Cached per-user IPv6 bind address (empty when prefix unset).
    string resolveIpv6Bind() {
        if (ipv6BindResolved) return ipv6BindCache;
        ipv6BindResolved = true;
        ipv6BindCache = ipv6BindForUser(ownerId);
        if (ipv6BindCache.length > 0)
            logInfo("IPv6 bind for %s owner %s → %s", config.name, ownerId.toString(), ipv6BindCache);
        return ipv6BindCache;
    }
    /// IPv6 actually used (for admin display)
    @property string getIpv6Bind() { return resolveIpv6Bind(); }

    // ── Connection loop ───────────────────────────────────────────────────────

    /// Runs the full connect / IRC-protocol / disconnect loop until
    /// `isShutdownRequested` becomes true. Package-visible so the
    /// `start()` worker task and any test harness can invoke it;
    /// callers must still set initial state via `start()`.
    package void runConnectionLoop() {
        // An attached session (hot swap) enters the loop already connected;
        // its first drop must not read "Failed to connect".
        bool wasEverConnected    = state == ConnectionState.connected;
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
                // A hot-swap detach ends this loop: the holder keeps the
                // session and the process is exiting.
                if (detachedForHotSwap) return;
            } catch (Throwable e) {
                // Enterprise: catch Throwable (not just Exception) — SyncError@(0) from
                // unsynchronized __gshared access previously killed the TaskFiber
                // (observed 2026-08-17 cnTb-fin FATAL) and the TLS wedge left the
                // loop stuck forever. SyncError must be treated as a recoverable
                // disconnect, not a fiber terminator.
                if (detachedForHotSwap) return;
                string errMsg;
                try { errMsg = e.msg; } catch (Throwable) { errMsg = "unknown throwable"; }
                // Holder outage: not a network failure and not this network's
                // fault — no backoff growth, no ban policy, no failure report.
                // Retry on a short fixed cadence until the holder is back.
                if (cast(HolderUnavailableException) e) {
                    logJsonMap("warn", "connection", "Connection holder unavailable — retrying in 5s",
                        ["network": config.name, "host": config.host, "err": errMsg,
                         "event": "holder_unavailable_retry"]);
                    emitLog("error", "Connection holder unavailable — retrying in 5s");
                    try transportClose(); catch (Throwable) {}
                    state = ConnectionState.waiting_to_retry;
                    backoff.reset();
                    emitZeroRetryStatus();
                    foreach (_; 0 .. 50) {
                        if (isShutdownRequested) break;
                        sleep(100.msecs);
                    }
                    continue;
                }
                // SASL park (parkOnSaslRejection already persisted `disabled`,
                // mirrored it in-memory, tore the socket down and emitted the
                // user-visible error): skip the disconnect/backoff machinery
                // and idle exactly like the admin-disabled path. A proven
                // credential re-enables via control and this loop resumes.
                if (auto se = cast(SaslParkedException) e) {
                    string seMsg;
                    try { seMsg = se.msg; } catch (Throwable) { seMsg = "SASL rejected"; }
                    lastEmittedReason = seMsg;
                    lastDisconnectReason = seMsg;
                    while (!isShutdownRequested && config.disabled) {
                        sleep(5.seconds);
                    }
                    if (isShutdownRequested) return;
                    logInfo("runConnectionLoop[%s]: network re-enabled after SASL park — resuming", config.name);
                    continue;
                }
                // Downgraded from logException(error) with hex stack spam.
                // `transport not alive` and `Registration timed out` are expected
                // during normal reconnect — not `error`.
                logJsonMap("warn", "connection",
                    "Connection error",
                    ["network": config.name, "host": config.host,
                     "err": errMsg,
                     "event": "connection_error"]);
                // Record SyncError distinctly for observability.
                if (errMsg.canFind("SyncError") || typeid(e).toString().canFind("SyncError")) {
                    recordCounter("ircfiber.connection.sync_error", 1, ["host": config.host]);
                    logWarn("SyncError recovered for %s: %s — treating as disconnect, will reconnect", config.name, errMsg);
                }
                // Save the disconnect reason BEFORE handleDisconnection so
                // it emits the DISCONNECTED event with the right text.
                string reason = errMsg.length > 0 ? errMsg : "Connection closed unexpectedly";
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
                // disconnect paths. Wrapped in Throwable catch so a secondary
                // SyncError there doesn't kill the loop.
                try {
                    handleDisconnection();
                } catch (Throwable he) {
                    try logWarn("handleDisconnection threw for %s: %s", config.name, he.msg);
                    catch (Throwable) {}
                    try { transportClose(); } catch (Throwable) {}
                    state = ConnectionState.disconnected;
                }

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
                    } catch (Throwable) {}
                }
                // Track TLS timeout vs generic disconnect for egress rotation.
                if (reason.canFind("TLS handshake timed out") || errMsg.canFind("TLS handshake timed out")) {
                    recordCounter("ircfiber.tls_handshake.timeout_disconnect", 1, ["host": config.host]);
                    // Ban the egress this network used for this host so the next attempt tries a different exit.
                    if (activeEgressLocationId.length > 0) banEgressForHost(config.host, activeEgressLocationId);
                    recordHostFailure(config.host, config.port);
                }
                // An IP ban on a TLS port never reaches us as text: InspIRCd
                // answers a Z-lined address with a plaintext ERROR and closes,
                // which the TLS client reports as "SSL/TLS tunnel closed"
                // right after tcp_open. Two of those in a row on the same
                // egress, with another route available, means rotate — the
                // same failover a spelled-out Z-line gets in applyBanPolicy,
                // but with a shorter host-ban since we are inferring.
                const tlsClosed = reason.canFind("tunnel closed") || errMsg.canFind("tunnel closed");
                consecutiveTlsClosed = tlsClosed ? consecutiveTlsClosed + 1 : 0;
                if (tlsClosed && consecutiveTlsClosed >= TLS_CLOSED_ROTATE_AFTER) {
                    import std.string : toLower;
                    const banKey = activeEgressLocationId.length > 0
                        ? activeEgressLocationId : DIRECT_EGRESS_LABEL;
                    const pinnedHere = pinCoversBanKey(config.egressNodeId.toLower(), banKey);
                    if (!pinnedHere && hasAlternativeEgressForHost(config.host.toLower(), banKey)) {
                        banEgressForHost(config.host, banKey, TLS_CLOSED_ROTATE_BAN_MS);
                        consecutiveTlsClosed = 0;
                        emitLog("info", "TLS handshake keeps being closed via "
                            ~ (activeEgressLabel.length ? "Mullvad exit " ~ egressDisplay() : "the direct host IP")
                            ~ " — likely an IP ban on that address; switching to a different exit.");
                        logJsonMap("warn", "connection", "Repeated TLS close — rotating egress",
                            ["network": config.name, "host": config.host, "egress": banKey, "event": "egress_tls_close_rotate"]);
                    }
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

            // Give up after a week of uninterrupted failure (see
            // ExponentialBackoff): the host is not coming back on its own.
            // Park the loop (like the admin-disabled path) until the user
            // hits Reconnect — that control message replaces this client
            // with a fresh one — or the engine restarts.
            if (delay == Duration.max) {
                const streak = backoff.failingFor();
                const summary = "Gave up reconnecting to " ~ config.host ~ ":" ~ config.port.to!string
                    ~ " after " ~ backoff.currentAttempt().to!string ~ " attempts over "
                    ~ (streak.total!"hours").to!string ~ " h ("
                    ~ (lastEmittedReason.length > 0 ? lastEmittedReason : "connection_lost")
                    ~ "). Use Reconnect to try again.";
                logWarn("%s: %s", config.name, summary);
                logJsonMap("warn", "connection", "Reconnect budget exhausted — parking network",
                    ["network": config.name, "host": config.host, "port": config.port.to!string,
                     "attempts": backoff.currentAttempt().to!string,
                     "streakHours": (streak.total!"hours").to!string,
                     "reason": lastEmittedReason.length > 0 ? lastEmittedReason : "connection_lost",
                     "event": "reconnect_gave_up"]);
                recordCounter("ircfiber.reconnect.gave_up", 1,
                    ["network": config.name, "host": config.host]);
                state = ConnectionState.disconnected;
                emitZeroRetryStatus();
                lastDisconnectReason = summary;
                emitLog("error", summary);
                try eventChannel.put(IRCRawEvent.makeDisconnected(config.name, config.id.toString(), summary));
                catch (Exception) {}
                while (!isShutdownRequested) sleep(5.seconds);
                break;
            }

            // Per-host circuit breaker: after N consecutive failures to the
            // same host, extend the delay to the remaining cooldown so we
            // don't keep hammering a server that's clearly rejecting us.
            // The cooldown doubles every time the breaker re-opens
            // (5 → 10 → 20 → 40 → 60 min) — see hostCooldownMs().
            auto hostKey = config.host ~ ":" ~ config.port.to!string;
            if (auto breaker = hostKey in _hostBreakers) {
                if (breaker.openedAt > 0) {
                    const now = Clock.currTime.toUnixTime!long * 1000;
                    const elapsed = now - breaker.openedAt;
                    const cooldown = hostCooldownMs(breaker.openCount);
                    if (elapsed < cooldown) {
                        auto remaining = cooldown - elapsed;
                        const remainingDur = dur!"msecs"(remaining);
                        if (remainingDur > delay) {
                            delay = remainingDur;
                            logWarn("Host circuit breaker active for %s — extending delay to %s",
                                hostKey, delay);
                        }
                    } else {
                        // Cooldown expired — half-open: allow attempts again but
                        // remember how often this host has tripped so the next
                        // opening cools down for longer.
                        breaker.openedAt = 0;
                        breaker.failCount = 0;
                        logInfo("Host circuit breaker reset for %s (cooldown expired, opened %d× so far)",
                            hostKey, breaker.openCount);
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
            resetConnectionTelemetry();
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
        // and the exit block have been centralized there. A hot-swap
        // detach returns early inside handleDisconnection().
        cleanup();
    }

    // ── Connection attempt ────────────────────────────────────────────────────

    /// Emit a tagged server-log entry into the event channel so the
    /// frontend's `_server` buffer mirrors every phase of the connect.
    /// Failures are swallowed (eventChannel.put can throw if the channel
    /// is closed during shutdown) so the connection attempt itself is
    /// never blocked by a logging error.
    package(ircfiber) void emitLog(string phase, string text) nothrow {
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
    /// `backoff.reset()` site (registration success, holder attach,
    /// fail-cycle success). The frontend's
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
    /// (centralised site — covers the catch block,
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

    /// Starts a new /LIST accumulation. Called from `sendRaw` when we see
    /// an outgoing LIST, or lazily from the 321/322 handlers when the
    /// request originated elsewhere (e.g. before a hot swap).
    private void beginChannelList(string pattern) {
        channelListInFlight = true;
        channelListEmittedFirst = false;
        channelListPending.length = 0;
        channelListPattern = pattern;
    }

    /// Emits the buffered /LIST rows as one CHANNEL_LIST chunk. `done`
    /// marks the final chunk (may carry 0 rows); `error` is attached when
    /// the server aborted the list; `code` is the aborting numeric
    /// ("416" too many matches, "263" try again) so the frontend can pick
    /// IRCCloud's `list_response_toomany` vs `try_again` copy.
    private void flushChannelList(bool done, string error = "", string code = "") nothrow {
        try {
            auto j = Json.emptyObject;
            j["pattern"] = channelListPattern;
            j["first"] = !channelListEmittedFirst;
            j["done"] = done;
            auto rows = Json.emptyArray;
            foreach (ref r; channelListPending) {
                auto o = Json.emptyObject;
                o["name"] = r.name;
                o["users"] = r.users;
                o["topic"] = r.topic;
                o["modes"] = r.modes;
                rows ~= o;
            }
            j["rows"] = rows;
            if (error.length) {
                j["error"] = error;
                if (code.length) j["code"] = code;
            }
            eventChannel.put(IRCRawEvent.makeChannelList(
                config.name, config.id.toString(), j.toString()));
            channelListEmittedFirst = true;
            channelListPending.length = 0;
            if (done) channelListInFlight = false;
        } catch (Exception e) {
            try logWarn("flushChannelList[%s]: %s", config.name, e.msg);
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

    /// TLS mode string for the holder `DIAL` request.
    private static string holderTlsMode(TLSMode tls) @safe pure nothrow {
        if (tls == TLSMode.disabled) return "none";
        if (tls == TLSMode.starttls) return "starttls";
        return "implicit";
    }

    /// Timeline adapter for holder dial events: the holder reports *when*
    /// each phase happens (real timestamps), the engine owns the wording.
    /// `attempt`/`attempt_fail`/`dns`/`info` texts arrive holder-composed
    /// (or wrapper-composed for proxied dials) and are emitted verbatim.
    private void onDialEvent(ref DialEvent ev) nothrow {
        switch (ev.phase) {
            case "tcp_open":
                activeEgressLabel = ev.egressLabel;
                activeEgressHost = ev.egressHost;
                activeEgressIp = ev.egressIp;
                activeEgressLocation = ev.egressLocationText;
                activePeerIp = ev.peerIp;
                activeLocalIp = ev.localIp;
                if (dialPlainFallback) {
                    emitLog("tcp_open", "Re-established plain-text TCP connection to " ~ config.host ~ " via "
                        ~ (activeEgressLabel.length ? egressDisplay() ~ " (" ~ activeEgressHost
                            ~ (activeEgressIp.length ? "/" ~ activeEgressIp : "") ~ ")" : "direct") ~ ".");
                    return;
                }
                emitLog("tcp_open",
                    "TCP connection established to " ~ config.host ~ ":" ~ config.port.to!string
                    ~ (activePeerIp.length ? " [" ~ activePeerIp ~ "]" : "")
                    ~ (activeEgressLabel.length ? " via " ~ egressDisplay() ~ " (" ~ activeEgressHost ~ (activeEgressIp.length ? "/" ~ activeEgressIp : "") ~ ")" : " (direct)")
                    ~ (activeLocalIp.length ? " from " ~ activeLocalIp : "") ~ ".");
                try logJsonMap("info", "connection",
                    "TCP open",
                    ["network": config.name, "host": config.host,
                     "port": config.port.to!string,
                     "egress": activeEgressLabel.length ? activeEgressLabel : "direct",
                     "egressHost": activeEgressHost,
                     "egressIp": activeEgressIp,
                     "peerIp": activePeerIp,
                     "localIp": activeLocalIp,
                     "tls": dialTlsMode != "none" ? "true" : "false",
                     "event": "tcp_open"]);
                catch (Exception) {}
                return;
            case "starttls":
                emitLog("tls", "Requesting STARTTLS upgrade with " ~ config.host ~ "...");
                return;
            case "tls":
                emitLog("tls", dialTlsMode == "starttls"
                    ? "Server accepted STARTTLS — starting TLS handshake..."
                    : "Starting TLS handshake with " ~ config.host ~ "...");
                return;
            default:
                emitLog(ev.phase, ev.text);
                return;
        }
    }

    /// One holder-backed connect through the egress policy loop. Sets the
    /// transport, the holder connection id, the active egress/socket
    /// bookkeeping and the TLS details; emits the post-connect timeline.
    private void dialViaHolder(string tlsMode, string ipv6Bind) {
        if (holder is null) throw new HolderUnavailableException("no connection holder configured");
        dialTlsMode = tlsMode;
        DialResult dr;
        withSpan("irc.tcp_connect",
            ["network": config.name, "host": config.host, "port": config.port.to!string,
             "egress": config.egressNodeId, "ipv6Bind": ipv6Bind, "tls": tlsMode],
            (ref Span ts) {
            EgressUsed used;
            // Release before the new connect: happyEyeballsConnect takes the
            // hold on the slot it wins, and releasing afterwards would cancel
            // it out when the same slot is reused.
            releaseEgressSlot();
            auto tag = DialTag(config.id.toString(), ownerId.toString(), config.name, "");
            connection = happyEyeballsConnect(holder, tag, config.host, config.port, tlsMode,
                config.egressNodeId, ipv6Bind, &onDialEvent, used, dr);
            holderConnId = dr.id;
            activeEgressLabel = used.label;
            activeEgressHost = used.host;
            activeEgressIp = used.ip;
            activeEgressLocationId = used.locationId;
            activeEgressLocation = used.locationText;
            egressSlotLabel = used.label;
            egressSlotHeld = used.label.length > 0;
            activePeerIp = dr.peerIp;
            activeLocalIp = dr.localIp;
            tlsInfoValid = dr.tlsOk;
            tlsInfo = dr.tls;
            ts.setStatusOk();
        });
        // No OS TCP keepalive here: the upstream socket lives in the holder — the 30 s app-level LAG probes in processEvents() hold NAT mappings and meet the ~2 min detection goal.
        logInfo("TCP via egress '%s' (%s/%s) to %s:%d peer=%s local=%s holder=%s", activeEgressLabel.length ? activeEgressLabel : "direct", activeEgressHost.length ? activeEgressHost : "direct", activeEgressIp.length ? activeEgressIp : "-", config.host, config.port, activePeerIp.length ? activePeerIp : "-", activeLocalIp.length ? activeLocalIp : "-", holderConnId);
        if (tlsMode == "starttls") {
            logInfo("Connected to %s:%s with STARTTLS", config.host, config.port);
            logJsonMap("info", "connection",
                "Connected with STARTTLS",
                ["network": config.name, "host": config.host,
                 "port": config.port.to!string,
                 "event": "tls_handshake"]);
            emitLog("tls_done", formatTlsDoneText(tlsInfoValid, tlsInfo,
                "STARTTLS handshake complete — connection is now encrypted."));
        } else if (tlsMode != "none") {
            logInfo("Connected to %s:%s with TLS", config.host, config.port);
            logJsonMap("info", "connection",
                "Connected with TLS",
                ["network": config.name, "host": config.host,
                 "port": config.port.to!string,
                 "sni": config.host,
                 "event": "tls_handshake"]);
            emitLog("tls_done", formatTlsDoneText(tlsInfoValid, tlsInfo,
                "TLS handshake complete — connection is now encrypted."));
        } else {
            emitLog("info",
                "Plain-text mode — no TLS handshake will be performed.");
            logInfo("Connected to %s:%s (plain)", config.host, config.port);
        }
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
        disconnectedEmitted = false;
        ackedCaps.clear();
        capValues.clear();
        // Fake lag is per TCP session, and so is our own hostmask, the
        // channel `+f` inventory and the sliding windows. The pacer's
        // *tightening* deliberately survives: it is what we learned about
        // this server, and an Excess Flood kill must not be forgotten by
        // the reconnect it caused. Queued user lines survive too — they
        // were never delivered.
        saslSucceeded = false;
        pacer.resetAccrual();
        pacer.adopt(assumedFloodLimits());
        chargeSuppressed = false;
        ownHostmask = "";
        chanFloodLimit.clear();
        // Oper status and every channel exemption are per TCP session; a
        // reconnect starts as a plain user until the server says otherwise.
        isOper = false;
        pacer.setImmune(false);
        chanFloodExempt.clear();
        chanFloodProbed.clear();
        lastFloodNoticeChannel = "";
        chanFloodWindow.clear();
        lastPacedWriteMs = 0;
        // The command-penalty counter is per TCP session too. The trust
        // itself is per host, so re-derive it here: a network can be edited
        // between attempts.
        cmdBucket.clear();
        lastPacedNoticeMs = 0;
        applyFloodTrust();
        // A dropped connection can strand us inside a `BATCH +chathistory`
        // (the closing `BATCH -` never arrives — verified live: every row
        // for #superbowl stored with `batch=chathistory`, so the bouncer's
        // missed-message replay skipped the whole backlog). Batch state is
        // per TCP connection, so it dies with the old socket; the same goes
        // for in-flight CHATHISTORY flags the dead connection can never
        // answer (they would suppress fresh backfills forever).
        activeBatchRef = "";
        activeBatchType = "";
        activeBatchTarget = "";
        chathistoryInFlight.clear();
        serverFeatures = ServerFeatures.init;
        // Drop any tokens leftover from the previous connection attempt;
        // the new server's 005 stream will repopulate this map. Without
        // the clear, a reconnect to a less-featureful server would leave
        // stale tokens in the synchronised state.
        isupportMap.clear();
        channelListPending.length = 0;
        channelListInFlight = false;
        channelListEmittedFirst = false;
        channelListPattern = "";

        logInfo("Connecting to %s:%s (Happy Eyeballs)", config.host, config.port);
        logJsonMap("info", "connection",
            "Reconnect attempt starting",
            ["network": config.name, "host": config.host,
             "port": config.port.to!string,
             "attempt": backoff.currentAttempt().to!string,
             "event": "reconnect_attempt"]);

        // Resolve per-user IPv6 once (cached). Empty when IRCFIBER_IPV6_PREFIX unset.
        string ipv6Bind = resolveIpv6Bind();
        logInfo("Connecting to %s:%s (Happy Eyeballs) ipv6Bind=%s egress=%s owner=%s",
            config.host, config.port, ipv6Bind.length ? ipv6Bind : "-", config.egressNodeId, ownerId.toString());
        dialPlainFallback = false;
        try {
            dialViaHolder(holderTlsMode(config.tls), ipv6Bind);
        } catch (DialFailedException e) {
            if (e.phase != "tls" && e.phase != "starttls") throw e;
            logJsonMap("warn", "connection",
                "TLS handshake failed",
                ["network": config.name, "host": config.host,
                 "err": e.msg,
                 "event": "tls_fail"]);
            // TLS-only ports must not fall back to plain even when config says "enabled".
            // 6697/6698/7000 are de-facto TLS ports — plain on them gets 0 bytes
            // and leads to "Registration timed out → transport not alive" loop.
            // Treat enabled+TLS-port as required by default. STARTTLS fails
            // closed as well.
            bool isTlsOnlyPort = config.port == 6697 || config.port == 6698
                || config.port == 7000 || config.port == 6699;
            bool mustRequireTls = config.tls == TLSMode.required || config.tls == TLSMode.starttls
                || (config.tls == TLSMode.enabled && isTlsOnlyPort);
            if (mustRequireTls) {
                emitLog("error", "TLS handshake failed");
                throw e;
            }
            logWarn("TLS handshake failed for %s, falling back to plain text", config.host);
            emitLog("warn", "TLS handshake failed — falling back to plain text as configured.");
            dialPlainFallback = true;
            dialViaHolder("none", resolveIpv6Bind());
            logInfo("Plain fallback TCP via egress '%s' (%s/%s) to %s:%d", activeEgressLabel.length ? activeEgressLabel : "direct", activeEgressHost.length ? activeEgressHost : "direct", activeEgressIp.length ? activeEgressIp : "-", config.host, config.port);
            logJsonMap("info", "connection", "TLS handshake failed; fell back to plain text", ["network": config.name, "host": config.host, "egress": activeEgressLabel.length ? activeEgressLabel : "direct", "egressHost": activeEgressHost, "egressIp": activeEgressIp, "event": "tls_plain_fallback"]);
            logInfo("Connected to %s:%s without TLS via %s", config.host, config.port, activeEgressLabel.length ? activeEgressLabel : "direct");
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
        connectedAtMs = unixMsNow();
        emitLog("welcome",
            "Connection registered as " ~ sessionNick
            ~ ". Server handshake complete.");
        logJsonMap("info", "connection",
            "Registration complete",
            ["network": config.name, "nick": sessionNick,
             "event": "register_complete"]);

        state = ConnectionState.connected;
        backoff.reset();
        consecutiveTlsClosed = 0;
        throttledUntil = 0;
        droppedNoConnWarned = false;
        // The handshake (CAP LS / NICK / USER / CAP REQ / CAP END / SASL) is
        // accounted separately by the server — UnrealIRCd meters it with
        // handshake-data-flood, not fake lag — so charging it to the bucket
        // would make the first message after every connect wait for nothing.
        // Start the fake-lag model at zero from the moment we are a
        // registered user.
        pacer.resetAccrual();
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
        // First META for this session: from here a hot swap (or a crash)
        // can re-attach the held socket with the registered state.
        publishMeta(false);
    }

    /// Definitive SASL rejection (904/905): services are reachable and refuse
    /// the stored credential, so the password no longer matches the live
    /// NickServ account (rotated on IRC, dropped and re-registered, or lost
    /// in an Anope restart). Persist `disabled` — survives restarts, skips
    /// bootstrap, renders as admin-disabled — mirror it in-memory so the run
    /// loop idles, and tear the half-registered socket down. Recovery is a
    /// proven credential: NickServ-password site login or admin link/reset,
    /// both of which re-enable and push `reconnectNetwork`. The account name
    /// is logged; the credential never is.
    private void parkOnSaslRejection(string detail) {
        import ircfiber.db.network : NetworkRepository;
        const msg = "SASL " ~ saslMechanismName(config.sasl) ~ " rejected for account \"" ~
            config.saslUsername ~ "\" (" ~ detail ~ ") — stored credential does not match " ~
            "the live NickServ account. Parked (disabled); log into the site with " ~
            "the NickServ password to reconnect.";
        try {
            (new NetworkRepository()).setDisabled(config.id, true);
        } catch (Exception e) {
            logWarn("sasl_park[%s]: persisting disabled failed: %s", config.name, e.msg);
        }
        config.disabled = true;
        try transportClose(); catch (Exception e) logWarn("sasl_park[%s]: transport close failed: %s", config.name, e.msg);
        state = ConnectionState.disconnected;
        emitLog("error", msg);
        logWarn("sasl_park[%s]: %s", config.name, msg);
        logJsonMap("warn", "auth", "SASL rejected — parking network",
            ["network": config.name, "host": config.host,
             "account": config.saslUsername, "event": "sasl_parked"]);
        recordCounter("ircfiber.sasl.parked", 1, ["network": config.name, "host": config.host]);
        try eventChannel.put(IRCRawEvent.makeDisconnected(config.name, config.id.toString(), msg));
        catch (Exception) {}
        emitZeroRetryStatus();
    }

    // ── Registration (CAP + NICK + USER + SASL) ───────────────────────────────

    private void performRegistration() {
        // Build cap list
        string[] desiredCaps = desiredCapList();

        // WEBIRC before anything else, and only to irc.ircfiber.com: the ircd
        // swaps this session's address for the user's own (and re-matches
        // the connect class on the `webirc="ircfiber"` constraint) before
        // registration continues. Never to another host, never a
        // non-public address (see isPublicUnicast). Every branch logs so
        // prod can account for each fiber connection.
        {
            import std.uni : toLower;
            import ircfiber.default_network : DEFAULT_FIBER_HOST;
            const bool fiber = config.host.toLower == DEFAULT_FIBER_HOST;
            const webSecret = fiber ? webircPassword() : "";
            if (fiber) clientIp = loadClientIp();
            if (fiber && webSecret.length && isPublicUnicast(clientIp)) {
                sendRaw("WEBIRC " ~ webSecret ~ " ircfiber " ~ clientIp ~ " " ~ clientIp);
                logJsonMap("info", "connection", "WEBIRC sent",
                    ["network": config.name, "ip": clientIp, "event": "webirc_sent"]);
            } else if (fiber) {
                logJsonMap("info", "connection", "WEBIRC skipped",
                    ["network": config.name, "event": "webirc_skipped",
                     "reason": webSecret.length == 0 ? "no-password"
                             : clientIp.length == 0 ? "no-client-ip" : "non-public-ip"]);
            }
        }

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
        // Fresh attempt: a previous attempt's random-suffix escape hatch
        // must not shield this attempt's plain `_` fallback from the
        // 001 handler's clearPersistedNick below.
        randomNickPersisted = false;
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
        // is not advised to wait forever for the reply." Bound the
        // CAP+NICK+USER+SASL handshake: REGISTRATION_SILENT_TIMEOUT_SECS
        // while the server has sent nothing (black-holed peer),
        // REGISTRATION_OVERALL_TIMEOUT_SECS once it has spoken (alive but
        // slow — typically waiting out its own ident timer). The read-loop
        // bound below only protects against a tight loop on partial data.
        immutable registrationStartMs = Clock.currTime.toUnixTime!long * 1000;
        // Mirrored onto the client so the JOIN-throttle retry can measure
        // the server's grace window after this function has returned.
        registrationStartedAtMs = registrationStartMs;
        immutable registrationOverallTimeoutMs
            = REGISTRATION_OVERALL_TIMEOUT_SECS * 1000;
        long registrationLastWarnMs = 0;
        immutable registrationWarnThresholdMs1
            = (registrationOverallTimeoutMs * REGISTRATION_WARN_AT_FRACTION_1) / 100;
        immutable registrationWarnThresholdMs2
            = (registrationOverallTimeoutMs * REGISTRATION_WARN_AT_FRACTION_2) / 100;

        foreach (_; 0 .. REGISTRATION_MAX_READS) {
            // Hard upper bound: give up and let the connection loop's
            // exponential backoff schedule a retry. This is what RFC 2812
            // calls out as required behavior.
            immutable nowMs = Clock.currTime.toUnixTime!long * 1000;
            immutable serverSilent = linesIn == 0;
            immutable timeoutSecs = serverSilent
                ? REGISTRATION_SILENT_TIMEOUT_SECS : REGISTRATION_OVERALL_TIMEOUT_SECS;
            if (nowMs - registrationStartMs > timeoutSecs * 1000) {
                if (!welcomed) {
                    registrationTimeoutSince = nowMs;
                    immutable why = serverSilent
                        ? "server sent nothing — black-holed"
                        : "server replied but never completed registration";
                    logWarn("PersistentIRCClient[%s] registration TIMEOUT after %ds"
                        ~ " (CAP+SASL+001 not received; %s); will retry with backoff",
                        config.name, timeoutSecs, why);
                    logJsonMap("warn", "connection",
                        "Registration timeout",
                        ["network":  config.name,
                         "networkId": config.id.toString(),
                         "host":     config.host ~ ":" ~ config.port.to!string,
                         "elapsed":  (nowMs - registrationStartMs).to!string,
                         "linesIn":  linesIn.to!string,
                         "event":    "registration_timeout"]);
                    recordCounter("ircfiber.registration.timeout", 1,
                        ["network":  config.name,
                         "networkId": config.id.toString(),
                         "host":     config.host ~ ":" ~ config.port.to!string]);
                    throw new Exception(
                        "Registration timeout: 001 not received within "
                        ~ timeoutSecs.to!string ~ "s (" ~ why ~ ")");
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
                emitLog("registering", "Still waiting for the server to accept the registration ("
                    ~ (elapsedMs / 1000).to!string ~ "s) — servers often stall here on ident/hostname lookups; giving up at "
                    ~ REGISTRATION_OVERALL_TIMEOUT_SECS.to!string ~ "s.");
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
                emitLog("registering", "No welcome after " ~ (elapsedMs / 1000).to!string
                    ~ "s — the server accepted the TCP/TLS connection but has not completed registration.");
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
                    linesIn++;

                    auto evt = parseIRCLine(line);
                    // Set by a case below to keep this line out of the
                    // generic publish at the bottom of the loop.

                    switch (evt.command) {
                        // 375/372 pass through verbatim like every other
                        // registration numeric: the ircd's motdpool module
                        // renders the per-connect, per-user MOTD.

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
                            // fallback (e.g. `Zodiac_`) and we clear any
                            // persisted nick so the next reconnect retries
                            // the configured nick instead of locking the
                            // fallback in. (The random-suffix escape hatch
                            // below keeps its persisted nick, gated by
                            // randomNickPersisted.)
                            if (sessionNick == requestedNick)
                                persistNick(sessionNick);
                            else if (!randomNickPersisted)
                                clearPersistedNick();
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
                                // Escape-hatch nick: keep it persisted so
                                // the 001 handler below doesn't clear it.
                                randomNickPersisted = true;
                                logWarn("Nick '%s' persistently unavailable for %s after %d fallbacks; "
                                    ~ "switching to random nick '%s' and persisting",
                                    requestedNick, config.name, REGISTRATION_MAX_FALLBACK_ATTEMPTS, sessionNick);
                                sendRaw("NICK " ~ sessionNick);
                            }
                            break;

                        // ── RPL_MYINFO ────────────────────────────────────────
                        // `004 <nick> <server> <version> <umodes> <cmodes>…` —
                        // the only place a server names its own software, and
                        // what gates the ircd-specific probes (probeChannelFlood).
                        case "004": {
                            auto myinfo = evt.getParams();
                            if (myinfo.length >= 3) serverSoftware = myinfo[2];
                            break;
                        }

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
                              if (nick.length > 0) {
                                // The server answered — record that even when
                                // the answer is the nick itself and therefore
                                // not stored below.
                                realnameProbed[nick] = true;
                                if (rn.length > 0 && rn != nick)
                                  realnames[nick] = rn;
                              }
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
                                recordCapValues(capLine);
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
                                } else if (!saslDone && config.sasl != SASLMechanism.none
                                    && !ackedCaps.get("sasl", false)) {
                                    // The server granted caps but NOT sasl — it does
                                    // not support SASL on this connection. Fall back to
                                    // no-SASL registration instead of deadlocking waiting
                                    // for an AUTHENTICATE that will never come (the
                                    // 2026-08-12 BLCKND outage: sasl configured, server
                                    // never granted it, CAP END never sent, server closed
                                    // with "Registration Timeout" after ~40s, forever).
                                    logWarn("SASL not granted by %s (server does not offer sasl) — proceeding without SASL",
                                        config.host);
                                    saslDone = true;
                                    if (!capEndSent) {
                                        sendRaw("CAP END");
                                        capEndSent = true;
                                        logJsonMap("info", "connection",
                                            "CAP negotiation complete",
                                            ["network": config.name,
                                             "host": config.host, "port": config.port.to!string,
                                             "acks": capLine,
                                             "sasl": "not-granted",
                                             "event": "cap_negotiated"]);
                                        recordCounter("ircfiber.cap.negotiated", 1,
                                            ["network": config.name, "host": config.host,
                                             "port": config.port.to!string]);
                                    }
                                }
                            } else if (sub == "NAK") {
                                // Ignore NAK'd caps; they just won't be used. If the
                                // server NAK'd the whole request while we configured
                                // SASL, the server does not offer it — proceed without
                                // SASL so registration cannot deadlock (BLCKND outage).
                                if (!saslDone && config.sasl != SASLMechanism.none
                                    && capLine.canFind("sasl")) {
                                    logWarn("SASL NAK'd by %s (server does not offer sasl) — proceeding without SASL",
                                        config.host);
                                    saslDone = true;
                                }
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
                                // Server added new caps (cap-notify); request any we want.
                                // UnrealIRCd also uses CAP DEL + CAP NEW to *update* a
                                // value — the multiline max-lines/max-bytes change when
                                // we move between its known-users and unknown-users
                                // groups — so the values have to be re-read here.
                                recordCapValues(capLine);
                                foreach (cap; capLine.split(" ")) {
                                    auto capName = capNameOf(cap);
                                    if (desiredCaps.canFind(capName)) {
                                        sendRaw("CAP REQ :" ~ capName);
                                    }
                                }
                            } else if (sub == "DEL") {
                                // Server removed caps
                                foreach (cap; capLine.split(" ")) {
                                    auto capName = capNameOf(cap);
                                    ackedCaps.remove(capName);
                                    capValues.remove(capName);
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
                            // UnrealIRCd's `known-users` security group is
                            // "identified to services OR connected > 2h", and
                            // it carries looser flood limits. Being identified
                            // is the half we can actually observe.
                            saslSucceeded = true;
                            pacer.adopt(KNOWN_USER_LIMITS);
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
                            // Definitive: services are reachable and refuse the
                            // stored credential. Retrying would re-enter the
                            // same nick war forever — park instead. 906
                            // (aborted, usually our own timeout) stays on the
                            // retry path below.
                            parkOnSaslRejection(evt.text);
                            throw new SaslParkedException("SASL authentication failed: " ~ evt.text);
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

                        case "465": // ERR_YOUREBANNEDCREEP — server ban during registration
                            lastErrorText = evt.text;
                            if (isBanError(evt.text)) applyBanPolicy(evt.text);
                            else if (isThrottleError(evt.text)) throttledUntil = Clock.currTime.toUnixTime!long * 1000 + 300_000;
                            evt.network = config.name; evt.timestampMs = resolveTimestamp(evt); eventChannel.put(evt);
                            throw new Exception("Server banned connection during registration: " ~ evt.text);
                        case "ERROR":
                            lastErrorText = evt.text;
                            if (isBanError(evt.text)) applyBanPolicy(evt.text);
                            else if (isThrottleError(evt.text)) throttledUntil = Clock.currTime.toUnixTime!long * 1000 + 300_000;
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
        // Auto-OPER (if configured) — sent before the auto-join block below so
        // oper-only (+O) channels in the auto-join list are joinable. The IRCd
        // processes OPER then JOIN in receive order on this one connection, so +o
        // is set before each JOIN is evaluated; no need to await the 381 reply.
        // performRegistration() runs on every (re)connect, so this re-opers too.
        if (config.operUsername.length > 0 && config.operPassword.length > 0) {
            sendRaw("OPER " ~ config.operUsername ~ " " ~ config.operPassword);
        }

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

        // One comma-joined JOIN (per 400-byte batch) instead of one command
        // per channel. Servers that rate-limit per command answered every
        // single JOIN of the burst with its own refusal — nine identical
        // "You must be connected for at least 5 seconds" rows in the user's
        // server log for a nine-channel network. Same batching the throttle
        // retry already uses.
        string[] autoJoin;
        foreach (chan; config.autoJoinChannels) {
            string ch = chan.strip();
            if (ch.length == 0) continue;
            if (ch[0] != '#' && ch[0] != '&' && ch[0] != '+' && ch[0] != '!')
                ch = "#" ~ ch;
            autoJoin ~= ch[0 .. 1] ~ ch[1 .. $].toLower();
        }
        foreach (batch; joinBatches(autoJoin))
            sendRaw("JOIN " ~ batch);

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
        // Detached for a hot swap: the holder owns the session now and the
        // process is exiting. Never read, write or reconnect from here.
        if (detachedForHotSwap) return;
        import core.atomic : atomicLoad;

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
            if (!transportAlive) throw new Exception("Connection lost: transport not alive");

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
                if (!transportAlive) throw new Exception("Proactive probe: transport not alive");
                consecutiveZeroReads = 0; // reset so we don't spam every iter
            }

            // Non-blocking read (0 s waitForData gate); the outer sleep paces
            // the loop.
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
                // Own NICK/JOIN/PART/KICK/AWAY/005 changed the session state:
                // refresh the holder META once per read batch (an auto-join
                // burst is one write, not ten).
                if (metaDirty && state == ConnectionState.connected) {
                    metaDirty = false;
                    publishMeta(false);
                }
            }

            yield();
            // Detach pause: while a hot-swap detach is being prepared, spin
            // here so the snapshot the engine publishes is exact. We check
            // *after* yield() so any pending wake-ups get processed; the
            // count is shared/atomic so reads from the engine thread are
            // well-defined.
            while (atomicLoad(detachPauseCount) > 0) {
                sleep(10.msecs);
            }
            // The detach closed our relay stream and the process is exiting:
            // leave without reconnecting or emitting a disconnect.
            if (detachedForHotSwap) return;
            processOutboundQueue();

            if (now - lastKeepalive >= 30) {
                lagProbeSentMs = unixMsNow();
                sendRaw("PING :" ~ lagPingToken(lagProbeSentMs));
                lastKeepalive = now;
                logJsonMap("debug", "connection",
                    "PING sent",
                    ["network": config.name,
                     "event": "ping_sent"]);
                // Catch-up META write (member-list drift from other users'
                // JOIN/PART/NICK, which do not trigger a write of their own).
                publishMeta(false);
            }
            // Silent-drop early warning: a LAG probe is outstanding and no
            // PONG (or any data, which also resets the PONG clock) has
            // arrived for 60 s. Info level so prod sees it without a debug
            // restart; throttled to one line per minute per network.
            // Per-probe ping_sent/pong_received traffic stays at debug.
            if (lagProbeSentMs != 0
                && now - lastPongReceivedSecs >= 60
                && now - lastKeepaliveMissedLogSecs >= 60) {
                lastKeepaliveMissedLogSecs = now;
                logJsonMap("info", "connection",
                    "LAG probe unanswered for 60s — peer may be silently dead",
                    ["network": config.name,
                     "host": config.host,
                     "lagMs": lagMs.to!string,
                     "dataAgeSecs": (lastDataReceivedSecs > 0 ? now - lastDataReceivedSecs : -1).to!string,
                     "pongAgeSecs": (now - lastPongReceivedSecs).to!string,
                     "egress": activeEgressLabel.length ? activeEgressLabel : "direct",
                     "event": "keepalive_missed"]);
            }
            // PONG timeout: if no PONG has been received in 120s (2 min),
            // the connection is half-open (server silently died but local
            // socket stays ESTABLISHED). Throw to trigger the auto-reconnect
            // with exponential backoff — same as TCP read failure.
            if (now - lastPongReceivedSecs >= 120) {
                throw new Exception(
                    "PONG timeout — no response for 120s (network: " ~
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
            // for 300 s (5 min), the half-open is unambiguous. Throw
            // so the runConnectionLoop() catch block runs
            // handleDisconnection() and schedules a fresh reconnect.
            // The threshold is well above the 120 s W1-T08 idle event
            // (which the UI uses as a status hint, not a reaper), so a
            // merely-quiet channel will not falsely trip.
            if (lastDataReceivedSecs > 0
                && now - lastDataReceivedSecs >= 300
                && now - lastKeepalive >= 120) {
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
                    auto ap = chan in whoEnrichAttempts;
                    const attempts = ap ? *ap : 0;
                    if (!channelNeedsRealnameWho(users, realnames, realnameProbed, attempts))
                        continue;
                    if (chan in lastWhoTime && now - lastWhoTime[chan] < 2) continue;
                    sendRaw("WHO " ~ chan);
                    lastWhoTime[chan] = now;
                    whoEnrichAttempts[chan] = attempts + 1;
                    // info, not debug: bounded now (at most
                    // MAX_WHO_ENRICH_ATTEMPTS per channel per connection), and
                    // this counter is the production proof the sweep
                    // terminates instead of running once a minute forever.
                    logJsonMap("info", "protocol",
                        "WHO periodic enrichment",
                        ["network": config.name, "channel": chan,
                            "users": users.length.to!string,
                            "attempt": whoEnrichAttempts[chan].to!string,
                            "event": "who_periodic"]);
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

    /// Server banned us (Z/G/K-line, "banned from", ...). Ban the egress
    /// that was in use for this host — the bare host IP counts as an
    /// egress too (DIRECT_EGRESS_LABEL) — then either fail over right
    /// away or wait out the ban window:
    ///   - another route remains (an exit that is healthy and not banned
    ///     for this host, or the direct path) → `throttledUntil = 0` so
    ///     the reconnect loop retries on the normal short backoff and the
    ///     picker, which now skips the banned egress, lands on a
    ///     different IP. This is the whole point of the Mullvad pool: a
    ///     ban on one address must not cost the user 30 minutes.
    ///   - nothing else to try (empty pool, everything banned, or the user
    ///     pinned the banned route) → keep the 30-minute window as before.
    /// Both branches tell the user what happened in the _server buffer.
    private void applyBanPolicy(string text) {
        import std.string : toLower;
        const banKey = activeEgressLocationId.length > 0
            ? activeEgressLocationId : DIRECT_EGRESS_LABEL;
        const via = activeEgressLabel.length > 0
            ? "Mullvad exit " ~ egressDisplay() ~ (activeEgressIp.length ? " (" ~ activeEgressIp ~ ")" : "")
            : "the direct host IP" ~ (activeLocalIp.length ? " (" ~ activeLocalIp ~ ")" : "");
        banEgressForHost(config.host, banKey);
        logJsonMap("warn", "connection", "Egress host-banned after G/K/Z-line",
            ["network": config.name, "host": config.host, "egress": banKey, "event": "egress_host_ban"]);
        // A pin covers the banned route when it names it exactly ("direct"),
        // when it is the country/city pin that resolved to this location, or
        // when it is the label of a static slot.
        const pinnedBanned = pinCoversBanKey(config.egressNodeId.toLower(), banKey);
        if (!pinnedBanned && hasAlternativeEgressForHost(config.host.toLower(), banKey)) {
            throttledUntil = 0;
            emitLog("info", "Banned via " ~ via ~ " — retrying through a different exit.");
            logJsonMap("warn", "connection", "Server BAN detected — failing over to another egress",
                ["network": config.name, "message": text, "egress": banKey, "event": "server_ban_failover"]);
        } else {
            throttledUntil = Clock.currTime.toUnixTime!long * 1000 + 30 * 60 * 1000;
            emitLog("info", "Banned via " ~ via ~ " and no other exit is available"
                ~ (pinnedBanned ? " (this network is pinned to it — change \"Connect via\" to use another route)" : "")
                ~ " — retrying in 30 minutes.");
            logJsonMap("error", "connection", "Server BAN detected (ZLINE/GLINE) — 30m backoff",
                ["network": config.name, "message": text, "egress": banKey, "event": "server_ban_detected"]);
        }
    }

    /// Common implementation of the `case "ERROR":` body — sets
    /// `lastErrorText`, applies the throttle-detection policy, transitions
    /// the FSM to `disconnecting`, and emits the structured
    /// `event=server_error_detected` log. Used by both the registration-
    /// loop ERROR branch and the post-registration squashed-numeric
    /// detector in `processLine`.
    private void handleServerError(string text) {
        lastErrorText = text;
        if (isBanError(text)) {
            lastDisconnectReason = text;
            emitConnectionFail(text, text);
            applyBanPolicy(text);
        } else if (isThrottleError(text)) {
            throttledUntil = Clock.currTime.toUnixTime!long * 1000 + 300_000; // 5 min
            lastDisconnectReason = text;
            emitConnectionFail(text, text);
            // "Excess Flood" means our send rate model was too optimistic.
            // The client object outlives the reconnect, so tightening here
            // carries over to the new TCP session.
            if (text.toLower().canFind("flood"))
                onFloodComplaint("excess_flood", text);
        } else {
            lastDisconnectReason = text;
            emitConnectionFail(text, text);
        }
        // Emit DISCONNECTED immediately so the frontend sees the
        // state transition even when the caller (processEvents'
        // data loop) exits without throwing (squashed ERROR path).
        // Without this, the old attempt card stays "Connected" while
        // a new reconnect cycle silently opens a second card.
        if (!detachedForHotSwap && !disconnectedEmitted) {
            disconnectedEmitted = true;
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
        linesIn++;
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
            {
                auto pongParams = event.getParams();
                const sentMs = pongParams.length > 0 ? parseLagPongParam(pongParams[$ - 1]) : -1;
                if (sentMs > 0 && sentMs == lagProbeSentMs) {
                    lagMs = unixMsNow() - sentMs;
                    lagProbeSentMs = 0;
                }
            }
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
                    if (sameNick(event.nick, sessionNick)) {
                        // Confirmed: the throttle retry must not re-ask.
                        clearPendingJoin(chan);
                        metaDirty = true;
                        // Our own JOIN echo is the one line that reliably
                        // carries the `nick!user@host` other clients see —
                        // 396 RPL_VISIBLEHOST only gives the host. The
                        // payload budget subtracts this prefix, so without
                        // it we have to assume the IRCv3 worst case.
                        if (event.prefix.length > 0
                            && event.prefix.indexOf("!") > 0
                            && event.prefix.indexOf("@") > 0)
                            ownHostmask = event.prefix;
                        // Add our nick to channelUsers immediately so the
                        // current user always appears in the member list,
                        // even if the IRC server omits us from RPL_NAMREPLY
                        // (353).  The 353 handler dedups at line 2013, so
                        // adding here early is safe — 353 won't duplicate.
                        if (chan !in channelUsers) channelUsers[chan] = [];
                        if (!channelUsers[chan].canFind(event.nick))
                            channelUsers[chan] ~= event.nick;
                        bool wasAutoJoin = config.autoJoinChannels.canFind(chan);
                        if (!wasAutoJoin)
                            config.autoJoinChannels ~= chan;
                        auto pi = config.partedChannels.countUntil(chan);
                        if (pi >= 0) config.partedChannels = config.partedChannels.remove(pi);
                        // Request server-side history if available. Goes
                        // through requestChathistory so it uses the spec
                        // wire format and takes the per-channel in-flight
                        // slot the BATCH close releases — the hand-rolled
                        // `sendRaw` here did neither.
                        requestChathistory(chan, "LATEST", "", 100);
                        // Log our own JOINs at info so the web join at
                        // /irc/Supernets/channel/superbowl is visible in SigNoz.
                        // Fixed: was checking autoJoinChannels *after* appending, so the
                        // second canFind was always true and the log never emitted.
                        logJsonMap("info", "protocol",
                            "JOIN",
                            ["network": config.name,
                             "nick": event.nick,
                             "channel": chan,
                             "event": "join"]);
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
                          // The realname param was supplied, so the question
                          // is answered even when it equals the nick.
                          if (event.nick.length > 0)
                            realnameProbed[event.nick] = true;
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
                        if (memberNeedsRealname(event.nick, realnames, realnameProbed)) {
                            import std.datetime : Clock;
                            const whoisNow = Clock.currTime.toUnixTime!long;
                            if (whoisNow - lastWhoisTime >= 1) {
                                sendRaw("WHOIS " ~ event.nick);
                                lastWhoisTime = whoisNow;
                            }
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
                    if (sameNick(event.nick, sessionNick)) {
                        channelState.remove(chan);
                        metaDirty = true;
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
                        metaDirty = true;
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
                        if (sameNick(u, event.nick)) {
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

                        case "465": // ERR_YOUREBANNEDCREEP — treat as host-ban like ERROR
                            handleServerError(event.text);
                            break;

            case "305": // RPL_UNAWAY — no longer away
                isAway = false;
                awayMessage = "";
                metaDirty = true;
                break;

            case "306": // RPL_NOWAWAY — marked as away
                isAway = true;
                awayMessage = event.text;
                metaDirty = true;
                break;

            case "421": { // ERR_UNKNOWNCOMMAND — or a JOIN throttle wearing its clothes
                auto ps = event.getParams();
                // `421 <nick> JOIN :You must be connected for at least 5 seconds…`
                const rejected = ps.length > 1 ? ps[1] : "";
                import std.uni : icmp;
                if (rejected.length == 4 && icmp(rejected, "JOIN") == 0) {
                    const window = parseJoinThrottleSeconds(event.text);
                    if (window > 0) scheduleJoinThrottleRetry(window);
                }
                break;
            }

            case "403": // ERR_NOSUCHCHANNEL
            case "405": // ERR_TOOMANYCHANNELS
            case "471": // ERR_CHANNELISFULL
            case "473": // ERR_INVITEONLYCHAN
            case "474": // ERR_BANNEDFROMCHAN
            case "475": // ERR_BADCHANNELKEY
            case "477": // ERR_NOCHANMODES / registration required
            case "489": { // ERR_SECUREONLYCHAN
                // A refusal waiting will not fix: stop tracking the channel so
                // a later throttle retry does not re-ask for it.
                auto ps = event.getParams();
                if (ps.length > 1) clearPendingJoin(ps[1]);
                break;
            }
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
                            if (sameNick(u, event.nick)) {
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
                    if (sameNick(event.nick, sessionNick)) {
                        isSelf = true;
                        sessionNick = newNick;
                        metaDirty = true;
                        persistNick(sessionNick);
                    } else if (optimisticNickOld.length > 0 && sameNick(event.nick, optimisticNickOld)) {
                        isSelf = true;
                        sessionNick = newNick;
                        metaDirty = true;
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
                    } else {
                        // Query-partner NICK following (IRCCloud rename
                        // model): keep the tracked counterparty on the new
                        // nick so sync + future echoes use it. If the new
                        // nick is already tracked separately, drop the stale
                        // entry instead of merging — never destroy history.
                        // (Redis/Mongo key migration happens in the event
                        // processor, which owns the stores.)
                        ptrdiff_t oldIdx = -1, newIdx = -1;
                        foreach (i, q; queryBuffers) {
                            if (oldIdx < 0 && sameNick(q, event.nick)) oldIdx = i;
                            if (newIdx < 0 && sameNick(q, newNick)) newIdx = i;
                        }
                        if (oldIdx >= 0 && newIdx < 0) {
                            queryBuffers[oldIdx] = newNick;
                        } else if (oldIdx >= 0 && newIdx >= 0 && newIdx != oldIdx) {
                            queryBuffers[oldIdx] = queryBuffers[$ - 1];
                            queryBuffers.length--;
                        }
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
                        if (sameNick(stripNickPrefix(u), event.nick)) {
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
                        auto ap = chan in whoEnrichAttempts;
                        const attempts = ap ? *ap : 0;
                        needsWho = channelNeedsRealnameWho(
                            channelUsers[chan], realnames, realnameProbed, attempts);
                        if (needsWho && channelUsers[chan].length > 5
                            && (chan !in lastWhoTime || whoNow - lastWhoTime[chan] >= 2)) {
                            sendRaw("WHO " ~ chan);
                            lastWhoTime[chan] = whoNow;
                            whoEnrichAttempts[chan] = attempts + 1;
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
                    // Our own prefix is now known for this channel, so we
                    // can tell whether `+f` even applies to us, and ask the
                    // server what its effective limit actually is.
                    refreshFloodExemption(chan);
                    probeChannelFlood(chan);
                    import std.datetime : Clock;
                    const whoNow = Clock.currTime.toUnixTime!long;
                    if (chan in channelUsers) {
                        auto ap = chan in whoEnrichAttempts;
                        const attempts = ap ? *ap : 0;
                        const needsWho = channelNeedsRealnameWho(
                            channelUsers[chan], realnames, realnameProbed, attempts);
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
                            whoEnrichAttempts[chan] = attempts + 1;
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
                    if (nick.length > 0) realnameProbed[nick] = true;
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
                            if (sameNick(existing, nick)) {
                                // A run of prefix chars — including the
                                // operprefix `*` a multi-prefix NAMES puts
                                // first — means the entry already carries
                                // the server's own, richer answer. Only a
                                // genuinely bare entry gets the single char
                                // WHO's flags field can express.
                                if (nickPrefixRun(existing) == 0) {
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

            // ── RPL_WHOISUSER (311) in the main loop ──────────────────────
            // The handshake switch has its own 311 case, so a WHOIS answer
            // arriving after registration used to update nothing: the
            // JOIN-time `WHOIS <nick>` could never satisfy the check that
            // triggered it and fired again on every JOIN. `break` (not
            // `return`) keeps WHOIS output flowing to the server buffer.
            case "311": {
                auto p = event.getParams();
                if (p.length >= 6) {
                    auto nick = p[1];
                    const rn = p[5];
                    if (nick.length > 0) {
                        realnameProbed[nick] = true;
                        if (rn.length > 0 && rn != nick) realnames[nick] = rn;
                    }
                }
                break;
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
            // After End-of-WHO the roster is resolved: a member the server
            // did not name in any 352 will never be named, so marking the
            // whole channel probed is what stops the 60 s sweep from asking
            // again forever.
            case "315": {
                auto p = event.getParams();
                if (p.length >= 2) {
                    if (auto members = p[1] in channelUsers)
                        foreach (u; *members) {
                            const bare = stripNickPrefix(u);
                            if (bare.length) realnameProbed[bare] = true;
                        }
                }
                return;
            }

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
            // ONE event per shared channel, not one per matching roster
            // entry: the same nick legitimately appears twice in
            // channelUsers — bare from the JOIN handler, host-bearing from
            // 353 with userhost-in-names or from WHO (see the NICK handler
            // below, which mutates every copy for exactly that reason).
            // sameNick strips both the mode prefix and the !user@host
            // suffix, so a per-entry loop matched twice and published two
            // events with distinct ids — two identical rows in the client.
            case "AWAY":
                // event.text is the away message (empty = returned from away).
                foreach (chan, users; channelUsers) {
                    foreach (u; users) {
                        if (sameNick(u, event.nick)) {
                            auto dup        = event;
                            dup.channel     = chan;
                            dup.id          = randomUUID().toString();
                            eventChannel.put(dup);
                            break; // one per channel
                        }
                    }
                }
                return; // don't double-publish below

            // ── Account notify (account-notify cap) ──────────────────────────
            case "ACCOUNT":
                // params[0] = account name or "*" (logged out).
                // Server-log only: per-channel fan-out spammed every shared
                // channel with "nick logged in as account" rows. A single
                // _server event (empty channel falls through to the publish
                // below) keeps the login visible without the channel noise —
                // QUIT/NICK/CHGHOST dual-publish, ACCOUNT does not.
                {
                    auto ap = event.getParams();
                    if (ap.length >= 1 && ap[0].length > 0 && event.nick.length > 0) {
                        accounts[event.nick] = ap[0];
                        // Colon-less `ACCOUNT acct` parses with empty text;
                        // the timeline renders msg.text, so normalize it.
                        if (event.text.length == 0)
                            event.text = ap[0];
                    }
                }
                event.channel = "";
                break;

            // ── Realname change (setname cap) ──────────────────────────────
            // `:nick!user@host SETNAME :new real name` — one trailing
            // param (https://ircv3.net/specs/extensions/setname).
            // Updates the realname cache and fans out to shared channels
            // like AWAY so the UI can refresh member details.
            case "SETNAME":
                if (event.text.length > 0 && event.nick.length > 0) {
                    realnameProbed[event.nick] = true;
                    realnames[event.nick] = event.text;
                }
                foreach (chan, users; channelUsers) {
                    foreach (u; users) {
                        if (sameNick(u, event.nick)) {
                            auto dup    = event;
                            dup.channel = chan;
                            dup.id      = randomUUID().toString();
                            eventChannel.put(dup);
                            break; // one per channel
                        }
                    }
                }
                return;

            // ── Standard replies (standard-replies cap) ────────────────────
            // FAIL/WARN/NOTE carry a command name plus code and human text,
            // e.g. `:server FAIL PRIVMSG CANNOT_SEND_TO_CHANNEL #chan :...`.
            // They fall through to the normal publish path below so they
            // land in the target buffer (or _server when no channel is
            // named). A `label` tag on a FAIL is correlated with our
            // pending sends in the labeled-response block below.
            case "FAIL":
            case "WARN":
            case "NOTE":
                // `FAIL BATCH MULTILINE_MAX_LINES 15 :Too many lines` and
                // MULTILINE_MAX_BYTES carry the server's real limit, which
                // beats whatever the CAP said (a channel's +f can lower it).
                // Record it so the next paste chunks correctly instead of
                // failing again.
                applyMultilineFail(event);
                break;

            // ── Message redaction (draft/message-redaction cap) ────────────
            // `REDACT <target> <msgid> [<reason>]` — publishes into the
            // target buffer so the frontend can tombstone the message by
            // msgid. Routed explicitly because the trailing channel walk
            // only matches #-channels while a DM redaction targets a
            // bare nick.
            case "REDACT": {
                auto rp = event.getParams();
                if (rp.length > 0 && event.channel.length == 0)
                    event.channel = normalizeChannelName(rp[0]);
                break;
            }

            // ── Monitor replies (IRCv3 monitor, ISUPPORT MONITOR) ──────────
            // 730 RPL_MONONLINE / 731 RPL_MONOFFLINE / 732 RPL_MONLIST /
            // 733 RPL_ENDOFMONLIST. Published as-is into the server buffer
            // so watch-status changes are visible. 734 ERR_MONLISTFULL is
            // deliberately left to the default numeric path (warn-logged).
            case "730":
            case "731":
            case "732":
            case "733":
                break;

            // ── RPL_MYINFO (see the handshake handler) ───────────────────────
            case "004": {
                auto myinfo = event.getParams();
                if (myinfo.length >= 3) serverSoftware = myinfo[2];
                break;
            }

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
                if (mapChanged) { publishIsupportEvent(); metaDirty = true; }
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
                    // Server-sourced flood warnings ("Message to #chan
                    // throttled due to flooding", "You must wait…") are the
                    // only notice we act on; a user saying "flood" is not a
                    // signal, so this requires a server prefix (no nick).
                    if (event.nick.length == 0 && isFloodNotice(event.text))
                        onFloodComplaint("notice", event.text);
                    // Reply to our `MODE <chan> f` probe. This is the only
                    // way to read the numbers behind `+F <profile>`, whose
                    // limits are otherwise server-side config.
                    if (event.nick.length == 0) applyEffectiveFloodNotice(event.text);
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

            // ── BATCH (chathistory / chanhistory replay) ──────────────────────
            // The close form carries a SINGLE parameter and arrives as a
            // trailing on InspIRCd 4 (`:irc.example.org BATCH :-1`). The old
            // `params.length >= 2` guard skipped it, so the batch never
            // closed: `activeBatchType` stayed "chathistory" for the life of
            // the connection and every later event was tagged
            // `batch=chathistory` (see the tag block below). The frontend
            // routes tagged events down the backfill/prepend path, which
            // suppresses notifications and unread counts for all live
            // traffic. parseBatchOpen/parseBatchClose own both shapes.
            case "BATCH": {
                import ircfiber.irc.parser : parseBatchOpen, parseBatchClose;
                auto params = event.getParams();
                string batchRef, batchType, batchTarget;
                if (parseBatchOpen(params, batchRef, batchType, batchTarget)) {
                    activeBatchRef = batchRef;
                    activeBatchType = batchType;
                    activeBatchTarget = batchTarget;
                } else if (parseBatchClose(params, batchRef)) {
                    // Clear in-flight flag for the channel so the next
                    // CHATHISTORY request can go through. A ref mismatch
                    // means our tracking drifted — clear anyway, because
                    // staying open is the failure mode above.
                    if (activeBatchType == "chathistory" && activeBatchTarget.length > 0) {
                        clearChathistoryInFlight(activeBatchTarget);
                    }
                    activeBatchRef = "";
                    activeBatchType = "";
                    activeBatchTarget = "";
                }
                return; // Don't publish BATCH events to the UI
            }

            // ── Channel mode (ban/quiet/op/voice/etc.) ───────────────────────
            case "MODE":
                auto mp = event.getParams();
                if (mp.length > 0 && (mp[0].startsWith("#") || mp[0].startsWith("&") || mp[0].startsWith("!") || mp[0].startsWith("+"))) {
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
                    // Channel flood mode: `MODE #chan +f [5t]:15` is the one
                    // per-channel flood limit clients can actually read, and
                    // it caps both our line rate and a multiline batch.
                    if (mp.length >= 3) applyChannelFloodMode(mp[0], mp[1], mp[2 .. $]);
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
                            const modePrefix = prefixForModeChar(ch);
                            if (modePrefix != '\0') {
                                if (targetIdx >= mp.length) break;
                                const targetNick = mp[targetIdx++];
                                bool found = false;
                                if (auto members = chan in channelUsers) {
                                    foreach (i, ref u; *members) {
                                        if (sameNick(u, targetNick)) {
                                            found = true;
                                            // Merge into / remove from the run
                                            // rather than rewriting its first
                                            // char: a `+v` on `~alice` used to
                                            // overwrite the owner prefix and
                                            // demote her to voiced.
                                            u = adding
                                                ? addNickPrefix(u, modePrefix)
                                                : removeNickPrefix(u, modePrefix);
                                            break;
                                        }
                                    }
                                    if (!found && adding)
                                        *members ~= modePrefix ~ targetNick;
                                } else if (adding) {
                                    channelUsers[chan] = [modePrefix ~ targetNick];
                                }
                            }
                        }
                    }
                    // Our own status may have just changed, which decides
                    // whether floodprot's "hoaq" exemption covers us.
                    refreshFloodExemption(mp[0]);
                } else if (mp.length >= 2 && sameNick(mp[0], sessionNick)) {
                    // User-mode change on ourselves: `MODE <us> +o` is the
                    // live signal that we just gained (or lost) the
                    // `immune:lag` privilege every IRCOp holds by default.
                    if (userModesGrantOper(mp[1])) setOperState(true, "mode_self");
                    else if (mp[1].canFind("-o") || mp[1].canFind("-O"))
                        setOperState(false, "mode_self");
                }
                break;

            case "671": // RPL_WHOISSECURE — suppress "is using a Secure Connection" noise
                return;

            // ── /LIST: 321/322/323 are folded into CHANNEL_LIST chunks ──
            // and never published raw (raw 322 rows carry channel=#chan
            // and would otherwise be persisted into per-channel scrollback).
            case "321": // RPL_LISTSTART — header
                if (!channelListInFlight) beginChannelList("");
                return;
            case "322": { // RPL_LIST — one row
                ChannelListRow row;
                if (parseChannelListRow(event, row)) {
                    if (!channelListInFlight) beginChannelList("");
                    channelListPending ~= row;
                    if (channelListPending.length >= CHANNEL_LIST_CHUNK) flushChannelList(false);
                }
                return;
            }
            case "323": // RPL_LISTEND
                flushChannelList(true);
                return;
            case "416": // ERR_TOOMANYMATCHES — server truncated/refused the list
                if (channelListInFlight) {
                    flushChannelList(true, event.text.length ? event.text : "Output too large, truncated", "416");
                    return;
                }
                break;

            // 324 RPL_CHANNELMODEIS: `<nick> <channel> <modes> [params…]`.
            // Sent on join/`MODE #chan`, so this is how we learn an
            // already-set +f rather than waiting for someone to change it.
            case "324": {
                auto cp = event.getParams();
                if (cp.length >= 3)
                    applyChannelFloodMode(cp[1], cp[2], cp[3 .. $]);
                break;
            }

            // 381 RPL_YOUREOPER / 221 RPL_UMODEIS: the two authoritative
            // statements of our own oper status. An IRCOp holds
            // `immune:lag` by default, which switches fake lag off
            // entirely (UnrealIRCd src/parse.c).
            case "381":
                setOperState(true, "381");
                break;
            case "221": {
                auto up = event.getParams();
                const modes = up.length >= 2 ? up[1] : event.text;
                setOperState(userModesGrantOper(modes), "221");
                break;
            }

            // ── Rate-limit signals the server sends instead of killing us ──
            // 439 ERR_TARGETTOOFAST ("target change too fast"), 707
            // ERR_TARGETTOOFAST / ERR_TARGCHANGE on some ircds. Both mean
            // the server is already dropping or deferring our traffic,
            // which is the last warning before an Excess Flood kill.
            case "439":
            case "707":
                onFloodComplaint(event.command, event.text);
                break;

            // ── W1-T08: RPL_TRYAGAIN (263) — Server busy ─────────────────
            case "263": {
                if (channelListInFlight) {
                    // A LIST-triggered RPL_TRYAGAIN fails the list rather
                    // than raising the buffer-level "Server busy" chip.
                    flushChannelList(true, event.text.length ? event.text : "Server busy, try again later", "263");
                    return;
                }
                // Deliberately NOT a flood complaint. 263 RPL_TRYAGAIN is a
                // COMMAND rate limit, not a message one — Libera's text is
                // literally "This command could not be completed because it
                // has been used recently, and is rate-limited", and it is
                // answering our own periodic WHO/WHOIS probes. Treating it
                // as a chat-flood signal ratcheted a live Libera connection
                // to the 8 s penalty cap within 15 minutes of deploy,
                // throttling the user's messages for traffic they never
                // sent. Only message-related signals (439/707, a flood
                // NOTICE, FAIL, Excess Flood) tighten the pacer.
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
                        || event.command == "321" || event.command == "322"
                        || event.command == "323"
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
                // Outgoing echo (nick == session nick): the counterparty is
                // our typed target. Incoming: the sender's nick, which the
                // server reports in authoritative case.
                bool outgoing = event.nick.length > 0 && sessionNick.length > 0
                    && icmp(event.nick, sessionNick) == 0;
                if (outgoing) {
                    other = p[0];
                } else {
                    other = event.nick;
                }
                if (other.length > 0) {
                    // Casemapping-aware dedup: "nickserv" and "NickServ" are
                    // the same counterparty (sameNick folds per ISUPPORT
                    // CASEMAPPING, default rfc1459). Incoming traffic adopts
                    // the server case so the tracked name — and everything
                    // derived from it — converges to what is actually on
                    // IRC; outgoing traffic adopts whatever is tracked.
                    ptrdiff_t found = -1;
                    foreach (i, q; queryBuffers) {
                        if (sameNick(q, other)) { found = i; break; }
                    }
                    if (found < 0) {
                        queryBuffers ~= other;
                    } else if (!outgoing && queryBuffers[found] != other) {
                        queryBuffers[found] = other;
                    }
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
                    // Our echo carries the typed target; resolve to the
                    // tracked canonical form so a repeat `/msg nickserv`
                    // reuses the server-case channel instead of forking a
                    // lowercase twin on the wire.
                    event.channel = p[0];
                    foreach (q; queryBuffers) {
                        if (sameNick(q, p[0])) { event.channel = q; break; }
                    }
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
            || event.command == "TAGMSG" || event.command == "FAIL"
            || event.command == "WARN" || event.command == "NOTE") {
            auto msgLabel = event.getTag("label");
            if (msgLabel.length > 0 && clearPendingLabel(msgLabel)) {
                event.addTag("labeled_echo", "true");
            } else if (msgLabel.length > 0 && event.nick.length > 0
                && !sameNick(event.nick, sessionNick)
                && (event.command == "PRIVMSG" || event.command == "NOTICE")) {
                // Remote edit (draft/edit-message from another client):
                // the label names the original message but we never sent
                // it, so it is not in pendingLabels. Tag it so the
                // frontend can replace the original in place instead of
                // appending a duplicate.
                event.addTag("edit_of", msgLabel);
            }
            // IRCv3 account-tag: track the author's account name for
            // identity display without a WHOIS round trip.
            auto acctTag = event.getTag("account");
            if (acctTag.length > 0 && acctTag != "*" && event.nick.length > 0)
                accounts[event.nick] = acctTag;
            // Self-echo detection: tag PRIVMSG/NOTICE events from the
            // session's own nick. This runs regardless of msgid presence
            // so the suppression below catches all echo paths, including
            // servers that don't assign msgid tags.
            if (sameNick(event.nick, sessionNick)
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
        // Use ms-precision wall clock, not second-precision (toUnixTime*1000
        // truncates ms and makes two PRIVMSGs in the same second hash-collide
        // in BufferManager's dedup fallback). See buffer.d hasDedupKey fix.
        return (Clock.currTime - SysTime.fromUnixTime(0)).total!"msecs";
    }

    // ── CAP values + flood pacing ─────────────────────────────────────────────

    /// Cap list we ask for on this connection.
    private string[] desiredCapList() {
        string[] caps = DESIRED_CAPS_BASE.dup;
        if (config.sasl != SASLMechanism.none) caps ~= DESIRED_CAPS_SASL;
        return caps;
    }

    /// `draft/multiline=max-bytes=5250` → `draft/multiline`.
    private static string capNameOf(string token) {
        auto t = token.strip();
        const eq = t.indexOf("=");
        return eq >= 0 ? t[0 .. eq] : t;
    }

    /// Stores the `=value` part of every cap token in a CAP LS / CAP NEW
    /// line. Bare caps get an empty string so presence is still recorded.
    private void recordCapValues(string capLine) {
        foreach (token; capLine.split(" ")) {
            auto t = token.strip();
            if (t.length == 0) continue;
            const eq = t.indexOf("=");
            if (eq >= 0) capValues[t[0 .. eq]] = t[eq + 1 .. $];
            else if ((t in capValues) is null) capValues[t] = "";
        }
    }

    /// The server's advertised multiline limits, or an unusable value when
    /// the cap was not negotiated. `batch` is a hard dependency of the spec.
    private MultilineLimits multilineLimits() {
        if (!hasCap("draft/multiline") || !hasCap("batch"))
            return MultilineLimits.init;
        if (auto v = "draft/multiline" in capValues)
            return parseMultilineCap(*v);
        return MultilineLimits.init;
    }

    /// Payload bytes available for one PRIVMSG/NOTICE line to `target`.
    private size_t linePayloadBudget(string target, string command) {
        int linelen = 512;
        if (auto v = "LINELEN" in isupportMap) {
            try { linelen = (*v).to!int; } catch (Exception) { linelen = 512; }
        }
        return payloadBudget(linelen, ownHostmask, command, target);
    }

    /// Flood group we assume for the fake-lag model. UnrealIRCd promotes a
    /// user to `known-users` when they are identified to services OR have
    /// been connected over two hours; we only claim the first, because the
    /// second is not observable from here without guessing the server's
    /// `security-group` config.
    private FloodLimits assumedFloodLimits() {
        const identified = config.sasl != SASLMechanism.none && saslSucceeded;
        return identified ? KNOWN_USER_LIMITS : UNKNOWN_USER_LIMITS;
    }

    /// Resolves `IRCFIBER_FLOOD_TRUSTED_HOSTS` for this network.
    ///
    /// Everything else the pacer knows is a guess about a configuration IRC
    /// never advertises, which is why it now stays out of the way until the
    /// server complains (see `FakeLagPacer`). Our own ircd is the exception:
    /// the deploy renders the same `commandrate`/`threshold` into the
    /// InspIRCd `<connect>` block and into this env, so here the numbers are
    /// facts — and `fakelag="no"` on that class makes exceeding them a kill,
    /// not a delay, so they are respected rather than assumed away.
    private void applyFloodTrust() {
        auto cfgTrust = floodTrustSettings();
        const trusted = floodTrustedHost(cfgTrust.hosts, config.host);
        if (trusted == floodTrusted) {
            floodTrusted = trusted;
            trustedRate = cfgTrust.rate;
            return;
        }
        floodTrusted = trusted;
        trustedRate = cfgTrust.rate;
        if (!trusted) return;
        logJsonMap("info", "connection",
            "Platform ircd — pacing against its own connect class",
            ["network":     config.name,
             "networkId":   config.id.toString(),
             "host":        config.host,
             "commandRate": trustedRate.commandRateMilli.to!string,
             "threshold":   trustedRate.threshold.to!string,
             "event":       "flood_trusted_host"]);
    }

    /// Queues a user-originated message line behind the pacer.
    ///
    /// Protocol-critical traffic (PING/PONG, CAP, NICK, registration) must
    /// never be delayed and is written by `sendRaw` directly; it is still
    /// *charged* to the bucket so the model tracks the server's real view.
    private void enqueuePaced(string line) {
        if (pacedQueue.length >= MAX_PACED_QUEUE) {
            logJsonMap("warn", "connection",
                "Paced outbound queue full — dropping line",
                ["network": config.name,
                 "networkId": config.id.toString(),
                 "queued": pacedQueue.length.to!string,
                 "event": "flood_queue_full"]);
            return;
        }
        pacedQueue ~= line;
        // Give the first line a chance to leave immediately rather than
        // waiting for the next 50 ms event-loop tick.
        drainPacedQueue();
    }

    /// Channel `+f` ceiling for a target, if one is known AND it applies to
    /// us. UnrealIRCd's floodprot skips the whole check for members with
    /// `hoaq` status (or a matching `~F:` exception), so holding ops means
    /// there is no per-channel ceiling to respect.
    private ChannelLineLimit floodLimitFor(string target) {
        auto key = target.toLower();
        if (auto ex = key in chanFloodExempt) if (*ex) return ChannelLineLimit.init;
        if (auto l = key in chanFloodLimit) return *l;
        return ChannelLineLimit.init;
    }

    /// Recomputes whether our own status on `channel` exempts us from `+f`
    /// and records it. Called whenever NAMES or a MODE change could have
    /// altered our prefix.
    private void refreshFloodExemption(string channel) {
        auto key = normalizeChannelName(channel).toLower();
        auto prefixToken = isupportMap.get("PREFIX", "(qaohv)~&@%+");
        bool exempt = false;
        if (auto members = key in channelUsers) {
            // `channelUsers` can hold us twice: the bare nick appended by
            // our own JOIN echo AND the prefixed form from 353. Checking
            // only the first match therefore misses the status entirely, so
            // every matching entry contributes.
            foreach (entry; *members) {
                auto bare = stripNickPrefix(entry);
                auto bang = bare.indexOf("!");
                if (bang > 0) bare = bare[0 .. bang];
                if (!sameNick(bare, sessionNick)) continue;
                if (statusExemptsFromFlood(statusModesOf(entry, prefixToken))) {
                    exempt = true;
                    break;
                }
            }
        }
        const was = (key in chanFloodExempt) !is null && chanFloodExempt[key];
        if (exempt) chanFloodExempt[key] = true;
        else if (key in chanFloodExempt) chanFloodExempt.remove(key);
        if (exempt != was) {
            logJsonMap("info", "connection",
                exempt ? "Channel flood exemption gained"
                       : "Channel flood exemption lost",
                ["network": config.name,
                 "channel": channel,
                 "event":   "channel_flood_exempt"]);
        }
    }

    /// Grants or withdraws the fake-lag exemption from observed oper state.
    private void setOperState(bool oper, string signal) {
        if (isOper == oper) return;
        isOper = oper;
        pacer.setImmune(oper);
        logJsonMap("info", "connection",
            oper ? "IRCOp status detected — fake-lag pacing disabled"
                 : "IRCOp status lost — fake-lag pacing re-enabled",
            ["network": config.name,
             "networkId": config.id.toString(),
             "signal":  signal,
             "event":   "flood_immunity"]);
    }

    /// Asks the server for a channel's *effective* flood setting — the only
    /// way to read the numbers behind `+F <profile>`.
    ///
    /// Sent ONLY to servers that answer `MODE <chan> f` as a query
    /// (UnrealIRCd's `floodprot_override_mode`). Anywhere else the same
    /// line is a mode CHANGE with a missing parameter and the server
    /// answers with an error the user then reads in their channel —
    /// InspIRCd replies `696 <chan> f * :You must specify a parameter for
    /// the flood mode. Syntax: [*]<messages>:<period>.` on every join.
    private void probeChannelFlood(string channel) {
        if (!serverAnswersFloodQuery(serverSoftware)) return;
        auto key = normalizeChannelName(channel).toLower();
        if (key in chanFloodProbed) return;
        chanFloodProbed[key] = true;
        enqueuePaced("MODE " ~ channel ~ " f");
    }

    /// Target of a PRIVMSG/NOTICE line, for the `+f` window. Empty when the
    /// line is not a message.
    private static string messageTargetOf(string line) {
        auto l = line;
        if (l.startsWith("@")) {
            const sp = l.indexOf(" ");
            if (sp < 0) return "";
            l = l[sp + 1 .. $];
        }
        const sp1 = l.indexOf(" ");
        if (sp1 < 0) return "";
        const verb = l[0 .. sp1].toUpper();
        if (verb != "PRIVMSG" && verb != "NOTICE") return "";
        auto rest = l[sp1 + 1 .. $].stripLeft();
        const sp2 = rest.indexOf(" ");
        return sp2 < 0 ? rest : rest[0 .. sp2];
    }

    /// True when a wire line is a NOTICE (target-flood limits notices much
    /// more tightly than PRIVMSGs).
    private static bool isNoticeLine(string line) {
        auto l = line;
        if (l.startsWith("@")) {
            const sp = l.indexOf(" ");
            if (sp < 0) return false;
            l = l[sp + 1 .. $];
        }
        return l.length >= 6 && l[0 .. 6].toUpper() == "NOTICE";
    }

    /// `a` permits fewer lines per second than `b`.
    private static bool stricterLimit(ChannelLineLimit a, ChannelLineLimit b) {
        if (!b.valid()) return true;
        if (!a.valid()) return false;
        return cast(long)a.lines * b.seconds < cast(long)b.lines * a.seconds;
    }

    /// Writes as many paced lines as the server will currently accept.
    ///
    /// Called from `processOutboundQueue` on every event-loop tick (50 ms).
    ///
    /// Three gates, in order of how much we actually know:
    ///   1. the platform ircd's real `<connect>` command rate, when this is
    ///      a trusted host — a fact, and one that kills us if ignored;
    ///   2. the fake-lag/recvq model, which only paces after the server has
    ///      complained (`FakeLagPacer` is unarmed until then — IRCCloud
    ///      sends at wire speed and so do we);
    ///   3. per-target ceilings: a channel's advertised `+f`, always, and
    ///      UnrealIRCd's unadvertised `target-flood`, only on software that
    ///      has it AND only once the server has already complained. That
    ///      assumed ceiling is what throttled a 500-line paste to ~7
    ///      lines/second on an InspIRCd network that has no such limit.
    private void drainPacedQueue() {
        if (pacedQueue.length == 0) return;
        if (state != ConnectionState.connected) return;

        const now = unixMsNow();
        // Walk the tightening back once a minute has passed since the last
        // COMPLAINT, not since the last write. Keying it on write activity
        // meant a busy connection could never relax: one 707 pinned it at
        // the penalty cap until reconnect.
        if (lastFloodComplaintMs > 0 && now - lastFloodComplaintMs > 60_000) {
            pacer.relax();
            lastFloodComplaintMs = now;   // one step per minute of quiet
        }
        const startedWith = pacedQueue.length;

        while (pacedQueue.length > 0) {
            auto line = pacedQueue[0];
            // The server charges fake lag on the whole command it receives.
            const cmdBytes = line.length + 2;      // + CRLF
            if (floodTrusted && cmdBucket.waitMs(now, trustedRate) > 0) {
                reportPacing(now, startedWith);
                return;
            }
            if (pacer.waitMs(cmdBytes, now) > 0) {
                reportPacing(now, startedWith);
                return;
            }

            auto target = messageTargetOf(line);
            if (target.length > 0) {
                auto key = target.toLower();
                auto w = key in chanFloodWindow;
                if (w is null) {
                    chanFloodWindow[key] = LineRateWindow.init;
                    w = key in chanFloodWindow;
                }
                // `+f` is advertised by the channel itself, so it is always
                // honoured — exceeding it gets us kicked or the channel
                // moderated, which loses the rest of the paste. UnrealIRCd's
                // `target-flood` is neither advertised nor universal: it
                // silently DROPS messages, so it is respected once the
                // server has shown it rate-limits us, but never assumed on
                // an ircd that does not implement it at all.
                auto lim = floodLimitFor(target);
                if (pacer.isArmed() && !floodTrusted
                    && serverHasTargetFlood(ircdSoftwareFromVersion(serverSoftware))) {
                    const isChan = target[0] == '#' || target[0] == '&'
                        || target[0] == '!' || target[0] == '+';
                    auto tf = targetFloodLimit(isChan, isNoticeLine(line));
                    if (!lim.valid() || stricterLimit(tf, lim)) lim = tf;
                }
                if (lim.valid()) {
                    if (w.waitMs(now, lim) > 0) {
                        reportPacing(now, startedWith);
                        return;
                    }
                    w.record(now);
                }
            }

            pacedQueue = pacedQueue[1 .. $];
            lastPacedWriteMs = now;      // writeRaw charges the bucket
            try writeRaw(line);
            catch (Exception e) {
                logInfo("Paced write failed for %s: %s", config.name, e.msg);
                return;
            }
        }
    }

    /// Tells the user their paste is still going out, at most every 5 s.
    ///
    /// A queue that drains slowly is indistinguishable from a hung client:
    /// the reported symptom was "it posted a chunk and then waited way too
    /// long", with nothing anywhere saying why. Only fires for a backlog big
    /// enough to be worth a line in the server log.
    private void reportPacing(long nowMs, size_t startedWith) {
        enum size_t PACED_NOTICE_MIN_QUEUE = 25;
        enum long PACED_NOTICE_INTERVAL_MS = 5_000;
        if (pacedQueue.length < PACED_NOTICE_MIN_QUEUE) return;
        if (lastPacedNoticeMs > 0 && nowMs - lastPacedNoticeMs < PACED_NOTICE_INTERVAL_MS) return;
        lastPacedNoticeMs = nowMs;
        const sent = startedWith > pacedQueue.length ? startedWith - pacedQueue.length : 0;
        const reason = floodTrusted
            ? "the server accepts " ~ (trustedRate.commandRateMilli / 1000).to!string
              ~ " lines/second"
            : pacer.isArmed()
                ? "the server asked us to slow down"
                : "a channel rate limit (+f)";
        emitLog("flood_pacing",
            "Sending queued lines: " ~ pacedQueue.length.to!string ~ " left ("
            ~ sent.to!string ~ " sent this pass) — " ~ reason);
        logJsonMap("info", "connection",
            "Pacing outbound queue",
            ["network":   config.name,
             "networkId": config.id.toString(),
             "queued":    pacedQueue.length.to!string,
             "trusted":   floodTrusted.to!string,
             "armed":     pacer.isArmed().to!string,
             "event":     "flood_pacing"]);
    }

    /// Server NOTICE texts that mean "you are sending too fast". Deliberately
    /// narrow: only phrases ircds emit for rate limiting, never a user's
    /// chatter (the caller also requires a server prefix).
    private static bool isFloodNotice(string text) {
        auto t = text.toLower();
        return t.canFind("flood")
            || t.canFind("throttl")
            || t.canFind("too fast")
            || t.canFind("slow down")
            || t.canFind("rate limit");
    }

    /// `FAIL BATCH MULTILINE_MAX_LINES <limit>` / `MULTILINE_MAX_BYTES
    /// <limit>`: the server's authoritative limit for the batch we just
    /// tried. Overwrite the CAP-derived value so the retry fits, and treat
    /// TIMEOUT as a flood signal (the batch went out too slowly).
    private void applyMultilineFail(ref IRCRawEvent event) {
        if (event.command != "FAIL") return;
        auto p = event.getParams();
        if (p.length < 3 || p[0].toUpper() != "BATCH") return;
        const code = p[1].toUpper();
        auto ml = multilineLimits();
        int newLines = ml.maxLines;
        int newBytes = ml.maxBytes;
        if (code == "MULTILINE_MAX_LINES") {
            try newLines = p[2].to!int; catch (Exception) return;
        } else if (code == "MULTILINE_MAX_BYTES") {
            try newBytes = p[2].to!int; catch (Exception) return;
        } else {
            return;
        }
        if (newBytes <= 0) return;
        capValues["draft/multiline"] =
            "max-bytes=" ~ newBytes.to!string ~ ",max-lines=" ~ newLines.to!string;
        logJsonMap("info", "connection",
            "Multiline limits corrected by server FAIL",
            ["network":  config.name,
             "code":     code,
             "maxLines": newLines.to!string,
             "maxBytes": newBytes.to!string,
             "event":    "multiline_limits_updated"]);
    }

    /// Applies the effective `+f` limit reported by a `MODE <chan> f`
    /// probe reply. The notice names the channel in single quotes, and the
    /// follow-up lines ("Plus flood setting via +f: '…'") carry no channel
    /// name — those are attributed to the channel the last one named.
    private string lastFloodNoticeChannel;
    private void applyEffectiveFloodNotice(string text) {
        if (text.length == 0) return;
        // "Channel '#x' has effective flood setting …" / "… on #x"
        foreach (chan; channelState.byKey()) {
            if (text.canFind(chan)) { lastFloodNoticeChannel = chan; break; }
        }
        if (lastFloodNoticeChannel.length == 0) return;
        if (text.canFind("No channel mode +f")) {
            auto key = lastFloodNoticeChannel.toLower();
            if (key in chanFloodLimit) chanFloodLimit.remove(key);
            return;
        }
        auto lim = parseEffectiveFloodNotice(text);
        if (!lim.valid()) return;
        auto key = lastFloodNoticeChannel.toLower();
        auto existing = key in chanFloodLimit;
        // Keep the strictest limit seen for this channel: `+f` and `+F` are
        // reported on separate notices and both apply.
        if (existing !is null
            && cast(long)existing.lines * lim.seconds <= cast(long)lim.lines * existing.seconds)
            return;
        chanFloodLimit[key] = lim;
        logJsonMap("info", "connection",
            "Effective channel flood limit learned",
            ["network": config.name,
             "channel": lastFloodNoticeChannel,
             "lines":   lim.lines.to!string,
             "seconds": lim.seconds.to!string,
             "event":   "channel_flood_effective"]);
    }

    /// Applies a channel mode change, tracking only `+f`/`-f` (the channel
    /// flood limit). `params` are the mode arguments after the mode string.
    private void applyChannelFloodMode(string channel, string modeStr, string[] params) {
        auto key = normalizeChannelName(channel).toLower();
        bool adding = true;
        size_t argIdx = 0;
        foreach (c; modeStr) {
            if (c == '+') { adding = true; continue; }
            if (c == '-') { adding = false; continue; }
            if (c == 'f') {
                if (!adding) {
                    chanFloodLimit.remove(key);
                    if (auto w = key in chanFloodWindow) w.clear();
                } else if (argIdx < params.length) {
                    auto lim = parseChannelFloodLines(params[argIdx]);
                    if (lim.valid()) {
                        chanFloodLimit[key] = lim;
                        logJsonMap("info", "connection",
                            "Channel flood limit observed",
                            ["network": config.name,
                             "channel": channel,
                             "lines":   lim.lines.to!string,
                             "seconds": lim.seconds.to!string,
                             "event":   "channel_flood_limit"]);
                    } else {
                        chanFloodLimit.remove(key);
                    }
                }
                // `f` takes an argument in both directions on UnrealIRCd.
                argIdx++;
                continue;
            }
            // Any other mode may or may not consume an argument; we cannot
            // know without CHANMODES parsing, and guessing would misalign
            // `f`'s argument. Only trust `+f` when it is the first
            // argument-taking mode in the string, which is the common case
            // (`MODE #chan +f [5t]:15`, `MODE #chan -f`).
            if (params.length > 0) break;
        }
    }

    /// A flood complaint arrived (263 / 439 / 707 / flood NOTICE / FAIL /
    /// Excess Flood). Backs the pacer off and records why.
    private void onFloodComplaint(string signal, string detail) {
        const nowMs = unixMsNow();
        lastFloodComplaintMs = nowMs;
        pacer.tighten(nowMs);
        logJsonMap("warn", "connection",
            "Server flood complaint — tightening outbound pacing",
            ["network":     config.name,
             "networkId":   config.id.toString(),
             "signal":      signal,
             "detail":      detail,
             "penaltyMs":   pacer.limits().penaltyMs.to!string,
             "steps":       pacer.penaltySteps().to!string,
             "queued":      pacedQueue.length.to!string,
             "event":       "flood_tightened"]);
        recordCounter("ircfiber.flood.tightened", 1,
            ["network": config.name, "signal": signal]);
    }

    // ── Outbound queue ────────────────────────────────────────────────────────

    private void processOutboundQueue() {
        if (state != ConnectionState.connected) return;

        // Reconnect buffer first: these lines were written while the
        // transport was down and must not be reordered behind a paste.
        if (outboundQueue.length > 0) {
            auto queue = outboundQueue;
            outboundQueue = [];
            foreach (l; queue) writeRaw(l);
        }

        // Then whatever the flood pacer is holding back.
        drainPacedQueue();
    }

    private void writeRaw(string line) {
        linesOut++;
        if (line.length >= 3 && line[0 .. 3] == "WHO") whoOut++;
        // Every byte the server reads costs us fake lag, not just paced
        // message lines: our own WHO/WHOIS probes, JOIN bursts, NICK and
        // MODE all count too. Charging here — the single point where bytes
        // reach a socket — keeps the model honest. Multiline batches are
        // charged as one clamped lump instead, so they suppress this.
        if (!chargeSuppressed) pacer.charge(line.length + 2, unixMsNow());
        // InspIRCd charges one penalty point per COMMAND, whatever its
        // length, and it charges them for our PING/WHO/JOIN/MODE traffic
        // too — so the bucket has to see every line, not just paced ones.
        if (floodTrusted) cmdBucket.record(unixMsNow(), trustedRate);
        if (transportAlive) {
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
        // A hot-swap detach is not a disconnect: the session lives on in the
        // holder and the next engine re-attaches. Nothing to emit or reset.
        if (detachedForHotSwap) return;
        withSpan("irc.disconnect", ["network": config.name, "reason": lastDisconnectReason], (ref Span s) {
            // Captured before resetConnectionTelemetry() zeroes them: the
            // "disconnected" log below is the only forensic record of how
            // long the session lasted and how much we asked of the server.
            const uptimeSecs   = connectedAtMs > 0 ? (unixMsNow() - connectedAtMs) / 1000 : 0;
            const nowSecs      = Clock.currTime.toUnixTime!long;
            const idleSecs     = lastDataReceivedSecs > 0 ? nowSecs - lastDataReceivedSecs : -1;
            const egressAtDrop = activeEgressLabel.length ? activeEgressLabel : "direct";
            const linesInAtDrop  = linesIn;
            const linesOutAtDrop = linesOut;
            const whoOutAtDrop   = whoOut;
            state = ConnectionState.disconnected;
            resetConnectionTelemetry();
            // When the relay ended from the holder's side (upstream EOF, TLS
            // read error, detach timeout…) the holder knows why; surface that
            // instead of the generic "Connection lost".
            if (holderConnId.length && holder !is null) {
                try {
                    auto e = holder.info(holderConnId);
                    if (e.state == "closed" && e.closeReason.length) {
                        if (lastDisconnectReason.length == 0
                            || lastDisconnectReason == "Connection closed unexpectedly"
                            || lastDisconnectReason == "Connection lost")
                            lastDisconnectReason = e.closeReason;
                        try holder.forget(holderConnId); catch (Exception) {}
                        holderConnId = "";
                    }
                } catch (Exception) {}
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
            if (!disconnectedEmitted) {
                disconnectedEmitted = true;
                try eventChannel.put(IRCRawEvent.makeDisconnected(
                    config.name, config.id.toString(),
                    lastDisconnectReason.length > 0 ? lastDisconnectReason : "Connection lost"));
                catch (Exception) {}
            }
            // W1-T01: structured fail-info emit. Sits next to the legacy
            // DISCONNECTED event so the frontend's `applyFail` and the
            // legacy `disconnectReason` write can co-exist (per plan R2
            // dual-emit).
            //
            // W1-T01-rev1: skip when the user (or admin) called
            // stop() — `isShutdownRequested == true` means the
            // disconnect was intentional and the frontend should see
            // the no-fail "disconnected" branch instead of a
            // "Disconnected: <reason>" banner with a Reconnect button.
            // Without this guard, every /quit click produced a
            // CONNECTION_FAIL event + a populated snap.failInfo,
            // leaving the banner stuck on the user until the next
            // successful reconnect.
            if (!isShutdownRequested) {
                emitConnectionFail(
                    lastDisconnectReason.length > 0 ? lastDisconnectReason : "connection_lost",
                    lastErrorText);
            }
            logJsonMap("info", "connection",
                "Disconnected",
                ["network": config.name,
                 "reason": lastDisconnectReason.length > 0 ? lastDisconnectReason : "connection_lost",
                 "attempt": backoff.currentAttempt().to!string,
                 "uptimeSecs": uptimeSecs.to!string,
                 "idleSecs": idleSecs.to!string,
                 "egress": egressAtDrop,
                 "linesIn": linesInAtDrop.to!string,
                 "linesOut": linesOutAtDrop.to!string,
                 "whoOut": whoOutAtDrop.to!string,
                 "pongAgeSecs": (lastPongReceivedSecs > 0 ? nowSecs - lastPongReceivedSecs : -1).to!string,
                 "dataAgeSecs": (lastDataReceivedSecs > 0 ? nowSecs - lastDataReceivedSecs : -1).to!string,
                 "lastError": lastErrorText,
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
        // The transport is always the holder relay (plain bytes over a vibe
        // TCPConnection; TLS lives in the holder). Gate on waitForData() with
        // a (potentially zero) timeout: calling connection.read(IOMode.once)
        // with no data available makes the vibe.d read loop busy-poll until
        // readTimeout expires on this platform (cfrunloop/kqueue), burning a
        // full CPU core per idle connection. Only enter read() when data is
        // buffered.
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
                if (sameNick(u, nick)) {
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
        "d-lined", "d:lined", "dline", "d:line",
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
        // /LIST from any client path (web slash command, bouncer client, /raw).
        import std.uni : icmp;
        if (line.length >= 4 && icmp(line[0 .. 4], "LIST") == 0
            && (line.length == 4 || line[4] == ' ')) {
            beginChannelList(line.length > 5 ? line[5 .. $].strip() : "");
        }
        // Remember what we asked to join. Every JOIN — auto-join burst, a
        // sidebar click, /raw, a bouncer client — funnels through here, so
        // this is the one place that knows the target set the JOIN-throttle
        // retry has to re-send (421 names the command, never the channel).
        if (line.length >= 5 && icmp(line[0 .. 5], "JOIN ") == 0) {
            recordPendingJoins(line[5 .. $]);
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
        sendUserMessage("PRIVMSG", target, text, "");
    }

    /// Sends a labeled PRIVMSG when labeled-response cap is active.
    /// The label is registered in `pendingLabels` so the echo-message
    /// correlation in `processLine()` can suppress the duplicate.
    void sendLabeledMessage(string target, string text, string label) {
        sendUserMessage("PRIVMSG", target, text, label);
    }

    /// One logical user message → protocol lines on the wire.
    ///
    /// `text` may contain newlines and may exceed one line: this is the
    /// single place that decides how a message becomes IRC traffic.
    ///
    ///  1. CR/LF/NUL are stripped from every logical line, so a message body
    ///     can never inject a second command.
    ///  2. Lines are split to the server's real byte budget (ISUPPORT
    ///     `LINELEN` minus our own `nick!user@host` and the command
    ///     framing), never mid-code-point.
    ///  3. When the server negotiated `draft/multiline` and the whole
    ///     message fits its advertised `max-lines`/`max-bytes` (and the
    ///     channel's `+f` line ceiling), it goes out as ONE batch: the
    ///     server then treats it as a single message for flood purposes, so
    ///     it cannot trip `+f` or target-flood. A batch must be written
    ///     contiguously — `set::multiline::batch-timeout` aborts a slow one
    ///     — so it is admitted as a unit or not at all.
    ///  4. Otherwise the lines are queued behind the fake-lag pacer.
    private void sendUserMessage(string command, string target, string text,
                                 string label) {
        const budget = linePayloadBudget(target, command);
        bool[] concat;
        auto lines = splitMessage(text, budget, concat);
        if (lines.length == 0) return;
        // A single empty line is only meaningful inside a multiline batch;
        // as a bare PRIVMSG it is an error on most servers.
        if (lines.length == 1 && lines[0].length == 0) return;

        const bool labeled = label.length > 0 && hasCap("labeled-response");
        if (label.length > 0)
            pendingLabels[label] = Clock.currTime.toUnixTime!long * 1000;

        if (lines.length > 1 && tryMultilineBatch(command, target, lines, concat, labeled ? label : "")) {
            // Batch accepted.
        } else {
            foreach (i, line; lines) {
                if (line.length == 0) continue;   // no blank bare messages
                string wire = (labeled && i == 0)
                    ? "@label=" ~ label ~ " " ~ command ~ " " ~ target ~ " :" ~ line
                    : command ~ " " ~ target ~ " :" ~ line;
                enqueuePaced(wire);
            }
        }

        if (!hasCap("echo-message")) {
            foreach (i, line; lines) {
                if (line.length == 0) continue;
                emitSyntheticSelfMessage(target, line, command,
                                         (label.length > 0 && i == 0) ? label : "");
            }
        }
    }

    /// Writes `lines` as one `draft/multiline` BATCH, or returns false when
    /// the server's limits (or its current fake lag) do not allow it.
    private bool tryMultilineBatch(string command, string target,
                                   string[] lines, bool[] concat, string label) {
        const ml = multilineLimits();
        if (!ml.usable()) return false;
        if (state != ConnectionState.connected) return false;

        // UnrealIRCd also clamps a batch to the channel's +f 'm'/'t' limit.
        int maxLines = ml.maxLines;
        auto floodLim = floodLimitFor(target);
        if (floodLim.valid() && (maxLines == 0 || floodLim.lines < maxLines))
            maxLines = floodLim.lines;
        if (maxLines > 0 && lines.length > maxLines) return false;
        if (multilineByteCount(lines, concat) > cast(size_t)ml.maxBytes) return false;

        // Anything already queued must go first, or the paste would arrive
        // out of order.
        if (pacedQueue.length > 0) return false;

        const now = unixMsNow();
        if (!pacer.canStartBatch(now)) return false;

        const ref_ = nextBatchRef();
        // The whole batch is one fake-lag lump, so the per-write charge in
        // writeRaw must stand down for its duration.
        chargeSuppressed = true;
        scope (exit) chargeSuppressed = false;
        try {
            auto open = "BATCH +" ~ ref_ ~ " draft/multiline " ~ target;
            writeRaw(label.length > 0 ? "@label=" ~ label ~ " " ~ open : open);
            foreach (i, line; lines) {
                const bool isConcat = i < concat.length && concat[i];
                auto tags = isConcat
                    ? "@batch=" ~ ref_ ~ ";draft/multiline-concat "
                    : "@batch=" ~ ref_ ~ " ";
                writeRaw(tags ~ command ~ " " ~ target ~ " :" ~ line);
            }
            writeRaw("BATCH -" ~ ref_);
        } catch (Exception e) {
            logInfo("Multiline batch write failed for %s: %s", config.name, e.msg);
            return false;
        }
        // The server charges the whole batch one clamped lump when it closes.
        pacer.chargeBatch(lines, now);
        lastPacedWriteMs = now;
        logJsonMap("debug", "connection",
            "Sent multiline batch",
            ["network":   config.name,
             "networkId": config.id.toString(),
             "target":    target,
             "lines":     lines.length.to!string,
             "bytes":     multilineByteCount(lines, concat).to!string,
             "event":     "multiline_batch_sent"]);
        recordCounter("ircfiber.multiline.batch", 1, ["network": config.name]);
        return true;
    }

    /// Batch reference tags must be unique per connection.
    private string nextBatchRef() {
        return "f" ~ (++batchSeq).to!string;
    }

    /// Whether the server advertised MONITOR support (ISUPPORT token).
    bool monitorSupported() {
        return ("MONITOR" in isupportMap) !is null;
    }

    /// Sends a MONITOR command (IRCv3 monitor: + add, - remove,
    /// C clear, L list, S status query). Silent no-op when the server
    /// did not advertise MONITOR or the verb is invalid.
    void sendMonitor(string verb, string targets = "") {
        if (!monitorSupported()) return;
        auto line = buildMonitorLine(verb, targets);
        if (line is null) return;
        sendRaw(line);
    }

    /// Sends a message redaction using the draft/message-redaction cap:
    /// `REDACT <target> <msgid> [<reason>]`. Silent no-op when the cap
    /// was not negotiated.
    void sendRedactMessage(string target, string msgid, string reason = "") {
        if (!hasCap("draft/message-redaction")) return;
        if (target.length == 0 || msgid.length == 0) return;
        auto line = "REDACT " ~ target ~ " " ~ msgid;
        if (reason.length > 0) line ~= " :" ~ reason;
        sendRaw(line);
    }

    /// Sends a realname change (`SETNAME :<realname>`). The spec requires
    /// servers to accept this even when the setname cap was not
    /// negotiated, so this sends unconditionally.
    void sendSetName(string realname) {
        if (realname.length == 0) return;
        sendRaw("SETNAME :" ~ realname);
    }

    /// Sends an edited PRIVMSG using the draft/edit-message IRCv3 cap.
    /// Re-uses the original message's label so the echo replaces the
    /// existing message in-place on the frontend.
    void sendEditMessage(string target, string originalLabel, string newBody) {
        if (!hasCap("draft/edit-message")) return; // silent no-op
        // An edit replaces one existing row, so the label must stay on the
        // first line regardless of labeled-response — but the body still
        // needs the same sanitising, byte-splitting and pacing as any other
        // user message.
        const budget = linePayloadBudget(target, "PRIVMSG");
        bool[] concat;
        auto lines = splitMessage(newBody, budget, concat);
        if (lines.length == 0 || (lines.length == 1 && lines[0].length == 0)) return;
        pendingLabels[originalLabel] = Clock.currTime.toUnixTime!long * 1000;
        foreach (i, line; lines) {
            if (line.length == 0) continue;
            enqueuePaced(i == 0
                ? "@label=" ~ originalLabel ~ " PRIVMSG " ~ target ~ " :" ~ line
                : "PRIVMSG " ~ target ~ " :" ~ line);
        }
        if (!hasCap("echo-message")) {
            foreach (i, line; lines) {
                if (line.length == 0) continue;
                emitSyntheticSelfMessage(target, line, "PRIVMSG",
                                         i == 0 ? originalLabel : "");
            }
        }
    }

    /// Sends a labeled NOTICE when labeled-response cap is active.
    void sendLabeledNotice(string target, string text, string label) {
        sendUserMessage("NOTICE", target, text, label);
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
        if (!hasChathistoryCap()) return;
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

    /// Sends a JOIN command. Ensures leading `#` so bare names like `testing`
    /// never become a PRIVMSG target (auto-join normalization defense).
    void joinChannel(string channel) {
        channel = channel.strip();
        if (channel.length > 0 && channel[0] != '#' && channel[0] != '&' && channel[0] != '+' && channel[0] != '!')
            channel = "#" ~ channel;
        if (channel.length > 0) channel = channel[0 .. 1] ~ channel[1 .. $].toLower();
        sendRaw("JOIN " ~ channel);
    }

    /// Sends a PART command.
    void partChannel(string channel, string reason = "") {
        if (reason.length > 0) sendRaw("PART " ~ channel ~ " :" ~ reason);
        else                    sendRaw("PART " ~ channel);
    }
}
