/**
 * Holder IPC protocol v1: constants, request/response parsing and the
 * JSON shapes exchanged with the engine.
 *
 * Every IPC connection starts with one `\n`-terminated request line
 * (`VERB <one-line JSON>`). Responses are `OK <json>` / `ERR <json>`.
 * `DIAL` additionally streams `EVENT <json>` lines before its terminal
 * `CONNECTED <json>` / `FAILED <json>`.
 */
module holder.protocol;

import std.conv : to;
import std.array : Appender, appender;
import std.string : indexOf, strip;
import vibe.data.json : Json, parseJsonString;
import ircfiber.redis.protocol : TlsInfo;

/// Protocol version carried in `HELLO` and `STATUS`.
enum int PROTO_VERSION = 1;

// ── Error codes ─────────────────────────────────────────────────────────────
enum ERR_PROTO       = "proto";
enum ERR_SERVER_ID   = "server_id";
enum ERR_AUTH        = "auth";
enum ERR_BAD_REQUEST = "bad_request";
enum ERR_NOT_FOUND   = "not_found";
enum ERR_BUSY        = "busy";
enum ERR_CLOSED      = "closed";
enum ERR_TOO_LARGE   = "too_large";

// ── Environment ─────────────────────────────────────────────────────────────
enum ENV_ADDR                 = "IRCFIBER_HOLDER_ADDR";
enum ENV_TOKEN                = "IRCFIBER_HOLDER_TOKEN";
enum ENV_SERVER_ID            = "IRCFIBER_SERVER_ID";
enum ENV_BUILD_SHORT          = "IRCFIBER_BUILD_SHORT";
enum ENV_DETACH_BUFFER_BYTES  = "IRCFIBER_HOLDER_DETACH_BUFFER_BYTES";
enum ENV_DETACH_MAX_SECS      = "IRCFIBER_HOLDER_DETACH_MAX_SECS";
enum ENV_CLOSED_RETAIN_SECS   = "IRCFIBER_HOLDER_CLOSED_RETAIN_SECS";
enum ENV_QUIT_MSG             = "IRCFIBER_HOLDER_QUIT_MSG";

// ── Defaults ────────────────────────────────────────────────────────────────
enum string DEFAULT_ADDR           = "unix:///run/ircfiber/holder.sock";
enum size_t DETACH_BUFFER_BYTES    = 4_194_304;
enum long   DETACH_MAX_SECS        = 600;
enum long   CLOSED_RETAIN_SECS     = 3600;
enum string DEFAULT_QUIT_MSG       = "IRC Fiber maintenance";
/// Same value as connection.d: how long `CLOSE` waits for upstream EOF after QUIT.
enum long   QUIT_GRACE_PERIOD_MS   = 2_000;
/// Longest accepted request line (everything except `META`).
enum size_t MAX_LINE               = 1 << 20;
/// Largest accepted `META` payload.
enum size_t MAX_META               = 8 << 20;
/// Longest accepted response line, read by the `--status` / `--list`
/// client. `LIST` answers with every held connection including its
/// `META`, so the reply grows with the number of connected users and
/// passed MAX_LINE (a *request* limit) once the network had a few dozen
/// sessions — which failed `--list` outright, and with it the engine
/// deploy gate that compares the session list either side of a swap.
enum size_t MAX_RESPONSE           = 64 << 20;
/// Complete INVENTORY response, including OK prefix and newline.
enum size_t MAX_INVENTORY_BYTES = 64 << 10;
enum size_t MAX_INVENTORY_ROWS = 128;
enum size_t MAX_TOMBSTONES = 4096;
enum string[] HOLDER_CAPABILITIES =
    ["inventory_v1", "gap_ack_v1", "bounded_meta_v1", "independent_pong_v1"];
/// Wire message the holder sends upstream when the engine never came back.
enum string QUIT_ENGINE_UNAVAILABLE          = "engine unavailable";
enum string QUIT_ENGINE_UNAVAILABLE_OVERFLOW = "engine unavailable (buffer overflow)";

// ── Close reasons (`closeReason` in entries) ────────────────────────────────
enum CLOSE_PEER_CLOSED       = "peer_closed";
enum CLOSE_DETACH_TIMEOUT    = "detach_timeout";
enum CLOSE_DETACH_OVERFLOW   = "detach_buffer_overflow";
enum CLOSE_HOLDER_SHUTDOWN   = "holder_shutdown";

// ── Helpers ─────────────────────────────────────────────────────────────────

private string jstr(Json j, string key) {
    if (j.type != Json.Type.object) return "";
    auto v = j[key];
    return v.type == Json.Type.string ? v.get!string : "";
}

private long jlong(Json j, string key, long def = 0) {
    if (j.type != Json.Type.object) return def;
    auto v = j[key];
    if (v.type == Json.Type.int_) return v.get!long;
    if (v.type == Json.Type.float_) return cast(long) v.get!double;
    if (v.type == Json.Type.string) { try return v.get!string.to!long; catch (Exception) return def; }
    return def;
}

private bool jbool(Json j, string key) {
    if (j.type != Json.Type.object) return false;
    auto v = j[key];
    return v.type == Json.Type.bool_ && v.get!bool;
}

/// Engine-side identity of a held connection (opaque to the holder except
/// `networkId`, which the engine uses to find its sessions on attach).
struct Tag {
    string networkId;
    string userId;
    string name;
    /// Mullvad slot label the engine dialed through; `""` for direct.
    string egressLabel;

    static Tag fromJson(Json j) {
        Tag t;
        t.networkId = jstr(j, "networkId");
        t.userId = jstr(j, "userId");
        t.name = jstr(j, "name");
        t.egressLabel = jstr(j, "egressLabel");
        return t;
    }

    Json toJson() const {
        auto j = Json.emptyObject;
        j["networkId"] = networkId;
        j["userId"] = userId;
        j["name"] = name;
        j["egressLabel"] = egressLabel;
        return j;
    }
}

/// SOCKS5 sidecar to dial through.
struct ProxySpec {
    string host;
    ushort port;
    string username;
    string password;
}

/// `DIAL` request payload.
struct DialRequest {
    string token;
    Tag tag;
    string host;
    ushort port;
    /// "none" | "implicit" | "starttls"
    string tls = "none";
    string sni;
    bool hasProxy;
    ProxySpec proxy;
    string bindIp6;
    /// "any" preserves dual-stack Happy Eyeballs; "ipv6" never dials IPv4.
    string addressFamily = "any";
    long connectTimeoutMs = 10_000;
    long tlsTimeoutMs = 10_000;
    long starttlsTimeoutMs = 15_000;

    static DialRequest fromJson(Json j) {
        if (j.type != Json.Type.object) throw new Exception("DIAL payload must be an object");
        DialRequest r;
        r.token = jstr(j, "token");
        r.tag = Tag.fromJson(j["tag"]);
        r.host = jstr(j, "host");
        if (r.host.length == 0) throw new Exception("DIAL: host required");
        const port = jlong(j, "port");
        if (port <= 0 || port > 65_535) throw new Exception("DIAL: port out of range");
        r.port = cast(ushort) port;
        r.tls = jstr(j, "tls");
        if (r.tls.length == 0) r.tls = "none";
        if (r.tls != "none" && r.tls != "implicit" && r.tls != "starttls")
            throw new Exception("DIAL: tls must be none|implicit|starttls");
        r.sni = jstr(j, "sni");
        if (r.sni.length == 0) r.sni = r.host;
        auto p = j["proxy"];
        if (p.type == Json.Type.object) {
            r.hasProxy = true;
            r.proxy.host = jstr(p, "host");
            const pp = jlong(p, "port");
            if (r.proxy.host.length == 0 || pp <= 0 || pp > 65_535)
                throw new Exception("DIAL: proxy needs host and port");
            r.proxy.port = cast(ushort) pp;
            r.proxy.username = jstr(p, "username");
            r.proxy.password = jstr(p, "password");
        }
        r.bindIp6 = jstr(j, "bindIp6");
        auto family = j["addressFamily"];
        if (family.type != Json.Type.undefined) {
            if (family.type != Json.Type.string)
                throw new Exception("DIAL: addressFamily must be any|ipv6");
            r.addressFamily = family.get!string;
        }
        r.validateTransport();
        r.connectTimeoutMs = jlong(j, "connectTimeoutMs", r.connectTimeoutMs);
        r.tlsTimeoutMs = jlong(j, "tlsTimeoutMs", r.tlsTimeoutMs);
        r.starttlsTimeoutMs = jlong(j, "starttlsTimeoutMs", r.starttlsTimeoutMs);
        if (r.connectTimeoutMs <= 0 || r.tlsTimeoutMs <= 0 || r.starttlsTimeoutMs <= 0)
            throw new Exception("DIAL: timeouts must be positive");
        return r;
    }

    /// Also used by in-process callers, so bypassing JSON cannot relax the
    /// native tier's family/bind/proxy contract.
    void validateTransport() const {
        if (addressFamily != "any" && addressFamily != "ipv6")
            throw new Exception("DIAL: addressFamily must be any|ipv6");
        if (addressFamily == "ipv6") {
            if (hasProxy) throw new Exception("DIAL: ipv6 cannot use a proxy");
            if (!validIpv6Source(bindIp6))
                throw new Exception("DIAL: ipv6 requires a valid IPv6 source bind");
        }
    }

    Json toJson() const {
        validateTransport();
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

/// A literal IPv6 source, never an IPv4-mapped address. Pool authorization
/// belongs to the authenticated IPC boundary; this only checks wire shape.
package bool validIpv6Source(string source) @trusted nothrow @nogc {
    import core.sys.posix.arpa.inet : inet_pton;
    import core.sys.posix.sys.socket : AF_INET6;
    if (source.length == 0 || source.length >= 46) return false;
    char[46] text;
    foreach (i, c; source) {
        if (c == '\0') return false;
        text[i] = c;
    }
    text[source.length] = '\0';
    ubyte[16] bytes;
    if (inet_pton(AF_INET6, text.ptr, bytes.ptr) != 1) return false;
    bool zeroPrefix = true;
    foreach (b; bytes[0 .. 10]) if (b) zeroPrefix = false;
    if (zeroPrefix && bytes[10] == 0xff && bytes[11] == 0xff) return false;
    bool unspecified = true;
    foreach (b; bytes) if (b) unspecified = false;
    return !unspecified && bytes[0] != 0xff;
}

/// `tls` object in `CONNECTED` and entries: the engine's `TlsInfo` plus `ok`.
struct TlsInfoJson {
    bool ok;
    TlsInfo info;

    static TlsInfoJson fromJson(Json j) {
        TlsInfoJson t;
        t.ok = jbool(j, "ok");
        t.info.version_ = jstr(j, "version");
        t.info.cipher = jstr(j, "cipher");
        t.info.certCn = jstr(j, "certCn");
        t.info.certIssuer = jstr(j, "certIssuer");
        t.info.certNotAfterMs = jlong(j, "certNotAfterMs");
        return t;
    }

    Json toJson() const {
        auto j = info.toJson();
        j["ok"] = ok;
        return j;
    }
}

/// One held connection as reported by `LIST` / `INFO` / `ATTACH`.
struct Entry {
    string id;
    string instance;
    ulong ordinal;
    ulong gapGeneration, gapAckGeneration, droppedBytes, droppedLines;
    long gapStartedAtMs;
    bool deliveryAmbiguous;
    /// Numeric I/O ownership evidence, available via INFO/ATTACH only.
    size_t relayBytes, outboundBytes, pongBytes, relayWriterFlightBytes;
    long relayWriteInFlightMs, upstreamWriteInFlightMs;
    ulong attachmentGeneration, attachmentWriterCompletions;
    bool upstreamWriterDone, tlsFinalized;
    Tag tag;
    /// "open" | "closed"
    string state;
    bool attached;
    string host;
    ushort port;
    TlsInfoJson tls;
    string peerIp;
    string localIp;
    long connectedAtMs;
    /// 0 = attached (serialised as null).
    long detachedSinceMs;
    size_t bufferedBytes;
    /// Empty = open (serialised as null).
    string closeReason;
    /// 0 = open (serialised as null).
    long closedAtMs;
    /// Validated, independently owned wire JSON; no retained roster graph.
    ValidatedMeta meta;

    private Json fieldsJson() const {
        auto j = Json.emptyObject;
        j["id"] = id;
        j["instance"] = instance;
        writeGapFields(j);
        j["relayBytes"] = counterJson(relayBytes);
        j["outboundBytes"] = counterJson(outboundBytes);
        j["pongBytes"] = counterJson(pongBytes);
        j["relayWriterFlightBytes"] = counterJson(relayWriterFlightBytes);
        j["relayWriteInFlightMs"] = relayWriteInFlightMs;
        j["upstreamWriteInFlightMs"] = upstreamWriteInFlightMs;
        j["attachmentGeneration"] = counterJson(attachmentGeneration);
        j["attachmentWriterCompletions"] = counterJson(attachmentWriterCompletions);
        j["upstreamWriterDone"] = upstreamWriterDone;
        j["tlsFinalized"] = tlsFinalized;
        j["tag"] = tag.toJson();
        j["state"] = state;
        j["attached"] = attached;
        j["host"] = host;
        j["port"] = cast(int) port;
        j["tls"] = tls.toJson();
        j["peerIp"] = peerIp;
        j["localIp"] = localIp;
        j["connectedAtMs"] = connectedAtMs;
        j["detachedSinceMs"] = detachedSinceMs > 0 ? Json(detachedSinceMs) : Json(null);
        j["bufferedBytes"] = cast(long) bufferedBytes;
        j["closeReason"] = closeReason.length ? Json(closeReason) : Json(null);
        j["closedAtMs"] = closedAtMs > 0 ? Json(closedAtMs) : Json(null);
        return j;
    }

    void appendTo(ref Appender!string output) const {
        const fields = fieldsJson().toString();
        output.put(fields[0 .. $ - 1]);
        output.put(`,"meta":`);
        meta.appendTo(output);
        output.put('}');
    }

    string toString() const {
        auto output = appender!string();
        appendTo(output);
        return output.data;
    }

    /// Deliberately excludes routing tags, TLS and META. All strings originate
    /// from holder-controlled bounded identifiers/state, never user payload.
    Json inventoryJson() const {
        auto j = Json.emptyObject;
        j["id"] = id;
        j["state"] = state;
        j["attached"] = attached;
        j["connectedAtMs"] = connectedAtMs;
        j["bufferedBytes"] = cast(long) bufferedBytes;
        writeGapFields(j);
        return j;
    }

    private void writeGapFields(ref Json j) const {
        j["ordinal"] = cast(long) ordinal;
        j["gapGeneration"] = counterJson(gapGeneration);
        j["gapAckGeneration"] = counterJson(gapAckGeneration);
        j["droppedBytes"] = counterJson(droppedBytes);
        j["droppedLines"] = counterJson(droppedLines);
        j["gapStartedAtMs"] = gapStartedAtMs;
        j["deliveryAmbiguous"] = deliveryAmbiguous;
    }

}

/// `EVENT` line emitted while a `DIAL` is in progress.
struct EventLine {
    /// "attempt" | "attempt_fail" | "dns" | "tcp_open" | "tls" | "starttls"
    string phase;
    string text;
    string peerIp;
    string localIp;
    ushort peerPort;
    ushort localPort;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["phase"] = phase;
        j["text"] = text;
        j["peerIp"] = peerIp;
        j["localIp"] = localIp;
        j["peerPort"] = cast(int) peerPort;
        j["localPort"] = cast(int) localPort;
        return j;
    }

    static EventLine fromJson(Json j) {
        EventLine e;
        e.phase = jstr(j, "phase");
        e.text = jstr(j, "text");
        e.peerIp = jstr(j, "peerIp");
        e.localIp = jstr(j, "localIp");
        e.peerPort = cast(ushort) jlong(j, "peerPort");
        e.localPort = cast(ushort) jlong(j, "localPort");
        return e;
    }
}

/// Terminal `CONNECTED` line of a `DIAL`.
struct ConnectedLine {
    string id;
    string peerIp;
    string localIp;
    ushort peerPort;
    ushort localPort;
    long connectedAtMs;
    TlsInfoJson tls;
    string instance;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["id"] = id;
        j["instance"] = instance;
        j["peerIp"] = peerIp;
        j["localIp"] = localIp;
        j["peerPort"] = cast(int) peerPort;
        j["localPort"] = cast(int) localPort;
        j["connectedAtMs"] = connectedAtMs;
        j["tls"] = tls.toJson();
        return j;
    }

    static ConnectedLine fromJson(Json j) {
        ConnectedLine c;
        c.id = jstr(j, "id");
        c.peerIp = jstr(j, "peerIp");
        c.localIp = jstr(j, "localIp");
        c.peerPort = cast(ushort) jlong(j, "peerPort");
        c.localPort = cast(ushort) jlong(j, "localPort");
        c.connectedAtMs = jlong(j, "connectedAtMs");
        c.tls = TlsInfoJson.fromJson(j["tls"]);
        c.instance = jstr(j, "instance");
        return c;
    }
}

/// Terminal `FAILED` line of a `DIAL`.
struct FailedLine {
    /// "dns" | "blocked" | "no_ipv6_destination" | "bad_request" |
    /// "tcp" | "socks5" | "tls" | "starttls"
    string phase;
    string reason;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["phase"] = phase;
        j["reason"] = reason;
        return j;
    }

    static FailedLine fromJson(Json j) {
        return FailedLine(jstr(j, "phase"), jstr(j, "reason"));
    }
}

/// `HELLO` payload.
struct HelloRequest {
    int proto;
    string serverId;
    string engine;
    string token;

    static HelloRequest fromJson(Json j) {
        HelloRequest h;
        h.proto = cast(int) jlong(j, "proto", -1);
        h.serverId = jstr(j, "serverId");
        h.engine = jstr(j, "engine");
        h.token = jstr(j, "token");
        return h;
    }

    Json toJson() const {
        auto j = Json.emptyObject;
        j["proto"] = proto;
        j["serverId"] = serverId;
        j["engine"] = engine;
        if (token.length) j["token"] = token;
        return j;
    }
}

/// Token check shared by `HELLO`/`DIAL`/`ATTACH`: over TCP the token is
/// required, over unix it is enforced only when configured. Returns
/// `null` when accepted, else the error code.
string checkToken(string presented, string expected, bool tokenRequired) @safe pure nothrow {
    if (expected.length == 0) return tokenRequired ? ERR_AUTH : null;
    return presented == expected ? null : ERR_AUTH;
}

/// Full `HELLO` validation: proto, serverId pairing, token. Returns `null`
/// when accepted, else the error code to send.
string checkHello(ref const HelloRequest h, string serverId, string token, bool tokenRequired) @safe pure nothrow {
    if (h.proto != PROTO_VERSION) return ERR_PROTO;
    if (h.serverId != serverId) return ERR_SERVER_ID;
    return checkToken(h.token, token, tokenRequired);
}

/// Splits `VERB <json>` into its verb and payload. A missing payload
/// yields an empty object; a malformed payload throws.
void parseFirstLine(string line, out string verb, out Json payload) {
    line = line.strip();
    const sp = line.indexOf(' ');
    if (sp < 0) {
        verb = line;
        payload = Json.emptyObject;
        return;
    }
    verb = line[0 .. sp];
    auto rest = line[sp + 1 .. $].strip();
    payload = rest.length ? parseJsonString(rest) : Json.emptyObject;
}

/// Strict unsigned wire counters/cursors. Missing values default only when
/// explicitly permitted, never coerce floats, signs or decimal strings.
ulong jsonUnsigned(Json j, string key, bool required = false) {
    auto value = j[key];
    if (value.type == Json.Type.undefined && !required) return 0;
    if (value.type == Json.Type.int_ && value.get!long >= 0)
        return cast(ulong) value.get!long;
    throw new Exception(key ~ " must be an unsigned integer");
}

/// Vibe JSON has signed 64-bit integers. Saturate diagnostics rather than
/// wrap a long-running counter negative.
Json counterJson(ulong value) {
    return Json(cast(long) (value > long.max ? long.max : value));
}

/// Tombstones preserve a reason category, not an exception message (which may
/// own a large backing allocation or contain arbitrary/non-UTF8 peer bytes).
string boundedCloseReason(string reason) {
    const colon = reason.indexOf(':');
    if (colon >= 0) reason = reason[0 .. colon];
    char[128] text;
    const length = reason.length < text.length ? reason.length : text.length;
    foreach (i; 0 .. length)
        text[i] = reason[i] >= ' ' && reason[i] <= '~' ? reason[i] : '?';
    return text[0 .. length].idup;
}

/// Parse startup timeout without the legacy positive-only fallback. Zero is
/// unlimited; an explicitly empty, signed, overflowing or malformed knob fails.
long parseDetachMaxSecs(string value) {
    if (!value.length) throw new Exception(ENV_DETACH_MAX_SECS ~ " must be nonnegative");
    ulong result;
    foreach (c; value) {
        if (c < '0' || c > '9' || result > (long.max - (c - '0')) / 10)
            throw new Exception(ENV_DETACH_MAX_SECS ~ " must be a nonnegative integer");
        result = result * 10 + c - '0';
    }
    return cast(long) result;
}

/// A raw value can reach the serializer only through complete request parsing.
/// The parser's duplicate-key/type semantics are also used for cached counters.
/// No parsed roster, envelope, or substring of a request is retained.
struct ValidatedMeta {
    private string text;
    private ulong members;
    private bool membersKnown;

    @property size_t encodedBytes() const { return text.length; }
    bool memberCount(out ulong result) const {
        result = members;
        return membersKnown;
    }

    void appendTo(ref Appender!string output) const {
        output.put(text.length ? text : "null");
    }

    static ValidatedMeta fromRequest(string line, out Json envelope) {
        import std.utf : validate;
        validate(line);
        // Vibe's DOM parser accepts non-JSON forms (e.g. trailing commas and
        // literal string controls). Validate strict wire syntax before parsing
        // so its permissive extensions can never be replayed as raw JSON.
        const raw = rawMetaValue(line);
        string verb;
        Json parsed;
        scope(exit) parsed = Json.undefined;
        parseFirstLine(line, verb, parsed);
        if (verb != "META" || parsed.type != Json.Type.object)
            throw new Exception("META payload must be an object");
        ValidatedMeta result;
        result.membersKnown = metaMemberCount(parsed["meta"], result.members);
        // Keep only the field consumed by META dispatch. In particular the
        // returned envelope cannot keep the parsed membership graph alive.
        envelope = Json.emptyObject;
        auto id = parsed["id"];
        if (id.type == Json.Type.string) envelope["id"] = id.get!string.idup;
        // JSON whitespace may contain CR; never splice it into line framing.
        // The strict syntax scan has rejected literal controls in strings.
        auto owned = raw.dup;
        foreach (ref c; owned) if (c == '\r' || c == '\n') c = ' ';
        result.text = cast(string) owned;
        return result;
    }
}

/// Stored memberships, not unique nicks or fresh engine state. Strict bool
/// markers and roster array types are preserved; dropped/missing is unknown.
private bool metaMemberCount(Json value, out ulong members) {
    members = 0;
    if (value.type != Json.Type.object) return false;
    auto dropped = value["usersDropped"];
    if (dropped.type != Json.Type.bool_ || dropped.get!bool) return false;
    auto rosters = value["channelUsers"];
    if (rosters.type != Json.Type.object) return false;
    foreach (roster; rosters.get!(Json[string]).byValue) {
        if (roster.type != Json.Type.array) return false;
        if (ulong.max - members < roster.length) return false;
        members += roster.length;
    }
    return true;
}

/// Validate the complete envelope and locate its META slice before DOM parsing.
/// Duplicate escaped meta keys and nesting beyond 256 are refused as before.
/// The resulting slice stays private until fromRequest also parses its values.
private string rawMetaValue(string line) {
    line = line.strip;
    const space = line.indexOf(' ');
    if (space < 0) throw new Exception("META payload required");
    auto text = line[space + 1 .. $].strip;
    if (!text.length || text[0] != '{') throw new Exception("META payload must be an object");
    size_t i = 1;
    string raw;
    bool found;
    while (true) {
        skipJsonSpace(text, i);
        if (i == text.length) throw new Exception("unterminated META object");
        if (text[i] == '}') break;
        const keyStart = i;
        skipJsonString(text, i);
        if (i - keyStart > 128) throw new Exception("META field name too long");
        auto key = parseJsonString(text[keyStart .. i]).get!string;
        skipJsonSpace(text, i);
        if (i == text.length || text[i++] != ':') throw new Exception("META colon required");
        skipJsonSpace(text, i);
        const start = i;
        skipJsonValue(text, i);
        if (key == "meta") {
            if (found) throw new Exception("duplicate meta field");
            found = true;
            raw = text[start .. i];
        }
        skipJsonSpace(text, i);
        if (i == text.length) throw new Exception("unterminated META object");
        if (text[i] == '}') break;
        if (text[i++] != ',') throw new Exception("META comma required");
        skipJsonSpace(text, i);
        if (i < text.length && text[i] == '}') throw new Exception("trailing META comma");
    }
    ++i; // closing envelope brace
    skipJsonSpace(text, i);
    if (i != text.length) throw new Exception("trailing META content");
    if (!found) throw new Exception("meta required");
    return raw;
}

private void skipJsonSpace(string text, ref size_t i) {
    while (i < text.length && (text[i] == ' ' || text[i] == '\t'
        || text[i] == '\r' || text[i] == '\n')) ++i;
}

private uint jsonHex4(string text, ref size_t i) {
    if (text.length - i < 4) throw new Exception("incomplete JSON Unicode escape");
    uint value;
    foreach (_; 0 .. 4) {
        const c = text[i++];
        uint digit;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        else throw new Exception("invalid JSON Unicode escape");
        value = value * 16 + digit;
    }
    return value;
}

private void skipJsonString(string text, ref size_t i) {
    if (i == text.length || text[i++] != '"') throw new Exception("JSON string required");
    while (i < text.length) {
        const c = text[i++];
        if (c == '"') return;
        if (c < 0x20) throw new Exception("literal JSON string control");
        if (c != '\\') continue;
        if (i == text.length) break;
        switch (text[i++]) {
            case '"', '\\', '/', 'b', 'f', 'n', 'r', 't': break;
            case 'u': {
                const unit = jsonHex4(text, i);
                if (unit >= 0xd800 && unit <= 0xdbff) {
                    if (text.length - i < 2 || text[i .. i + 2] != `\u`)
                        throw new Exception("missing JSON low surrogate");
                    i += 2;
                    const low = jsonHex4(text, i);
                    if (low < 0xdc00 || low > 0xdfff) throw new Exception("invalid JSON low surrogate");
                } else if (unit >= 0xdc00 && unit <= 0xdfff)
                    throw new Exception("unpaired JSON low surrogate");
                break;
            }
            default: throw new Exception("invalid JSON escape");
        }
    }
    throw new Exception("unterminated JSON string");
}

private bool jsonDigit(char c) { return c >= '0' && c <= '9'; }

private void skipJsonValue(string text, ref size_t i, size_t depth = 0) {
    if (i == text.length) throw new Exception("JSON value required");
    if (text[i] == '"') { skipJsonString(text, i); return; }
    if (text[i] == '{' || text[i] == '[') {
        if (depth == 256) throw new Exception("META nesting exceeds 256");
        const object = text[i++] == '{';
        const closing = object ? '}' : ']';
        skipJsonSpace(text, i);
        if (i < text.length && text[i] == closing) { ++i; return; }
        while (true) {
            if (object) {
                skipJsonString(text, i);
                skipJsonSpace(text, i);
                if (i == text.length || text[i++] != ':') throw new Exception("JSON colon required");
                skipJsonSpace(text, i);
            }
            skipJsonValue(text, i, depth + 1);
            skipJsonSpace(text, i);
            if (i == text.length) throw new Exception("unterminated JSON value");
            if (text[i] == closing) { ++i; return; }
            if (text[i++] != ',') throw new Exception("JSON comma required");
            skipJsonSpace(text, i);
        }
    }
    static foreach (literal; ["true", "false", "null"]) {
        if (text.length - i >= literal.length && text[i .. i + literal.length] == literal) {
            i += literal.length;
            return;
        }
    }
    if (text[i] == '-') ++i;
    if (i == text.length || !jsonDigit(text[i])) throw new Exception("JSON number required");
    if (text[i] == '0') ++i;
    else while (i < text.length && jsonDigit(text[i])) ++i;
    if (i < text.length && text[i] == '.') {
        ++i;
        if (i == text.length || !jsonDigit(text[i])) throw new Exception("JSON fraction required");
        while (i < text.length && jsonDigit(text[i])) ++i;
    }
    if (i < text.length && (text[i] == 'e' || text[i] == 'E')) {
        ++i;
        if (i < text.length && (text[i] == '+' || text[i] == '-')) ++i;
        if (i == text.length || !jsonDigit(text[i])) throw new Exception("JSON exponent required");
        while (i < text.length && jsonDigit(text[i])) ++i;
    }
}

/// `OK <json>` response line (no trailing newline).
string okLine(Json payload) {
    return "OK " ~ payload.toString();
}

/// Serialize only the bounded entry fields as a DOM; META is a validated value.
string okLine(Entry payload, bool newline = false) {
    auto output = appender!string();
    output.put("OK ");
    payload.appendTo(output);
    if (newline) output.put('\n');
    return output.data;
}

/// `ERR {"code":..,"msg":..}` response line (no trailing newline).
string errLine(string code, string msg) {
    auto j = Json.emptyObject;
    j["code"] = code;
    j["msg"] = msg;
    return "ERR " ~ j.toString();
}

/// Splits a raw IRC line (without CRLF) into its command verb and the
/// remainder after the verb, skipping optional `@tags ` and `:prefix `.
/// `verb` is empty when the line carries no command.
void ircVerb(string line, out string verb, out string rest) @safe pure nothrow {
    size_t i = 0;
    static void skipWord(string s, ref size_t i) @safe pure nothrow {
        while (i < s.length && s[i] != ' ') i++;
        while (i < s.length && s[i] == ' ') i++;
    }
    if (i < line.length && line[i] == '@') skipWord(line, i);
    if (i < line.length && line[i] == ':') skipWord(line, i);
    const start = i;
    while (i < line.length && line[i] != ' ') i++;
    verb = line[start .. i];
    while (i < line.length && line[i] == ' ') i++;
    rest = line[i .. $];
}

/// Last parameter of an IRC line remainder (after the verb), i.e. the
/// trailing `:text` when present, else the last space-separated token.
/// Mirrors `params[$ - 1]` of the engine's parser.
string ircLastParam(string rest) @safe pure nothrow {
    if (rest.length == 0) return "";
    if (rest[0] == ':') return rest[1 .. $];
    foreach (i; 0 .. rest.length - 1) {
        if (rest[i] == ' ' && rest[i + 1] == ':') return rest[i + 2 .. $];
    }
    size_t end = rest.length;
    while (end > 0 && rest[end - 1] == ' ') end--;
    size_t start = end;
    while (start > 0 && rest[start - 1] != ' ') start--;
    return rest[start .. end];
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

@("parseFirstLine splits verb and payload")
unittest {
    string verb; Json payload;
    parseFirstLine("HELLO {\"proto\":1,\"serverId\":\"ovh\"}\n", verb, payload);
    assert(verb == "HELLO");
    assert(payload["proto"].get!long == 1);
    parseFirstLine("LIST\n", verb, payload);
    assert(verb == "LIST" && payload.type == Json.Type.object && payload.length == 0);
    parseFirstLine("STATUS", verb, payload);
    assert(verb == "STATUS");
}

@("HELLO with proto 2 is rejected with proto; wrong serverId with server_id")
unittest {
    string verb; Json payload;
    parseFirstLine(`HELLO {"proto":2,"serverId":"ovh","engine":"x"}`, verb, payload);
    auto h = HelloRequest.fromJson(payload);
    assert(checkHello(h, "ovh", "", false) == ERR_PROTO);
    h.proto = 1;
    assert(checkHello(h, "k8s", "", false) == ERR_SERVER_ID);
    assert(checkHello(h, "ovh", "", false) is null);
}

@("token: required on TCP, optional on unix, enforced when set")
unittest {
    assert(checkToken("", "", true) == ERR_AUTH);
    assert(checkToken("", "", false) is null);
    assert(checkToken("abc", "abc", true) is null);
    assert(checkToken("", "abc", false) == ERR_AUTH);
    assert(checkToken("wrong", "abc", true) == ERR_AUTH);
    HelloRequest h = HelloRequest(1, "t", "x", "");
    assert(checkHello(h, "t", "", true) == ERR_AUTH);
    h.token = "abc";
    assert(checkHello(h, "t", "abc", true) is null);
}

@("HELLO round-trips")
unittest {
    auto h = HelloRequest(1, "ovh", "abc123", "tok");
    auto back = HelloRequest.fromJson(parseJsonString(h.toJson().toString()));
    assert(back == h);
}

@("DialRequest round-trips with and without proxy")
unittest {
    DialRequest r;
    r.token = "t";
    r.tag = Tag("n", "u", "Libera", "se");
    r.host = "irc.libera.chat";
    r.port = 6697;
    r.tls = "implicit";
    r.sni = "irc.libera.chat";
    r.hasProxy = true;
    r.proxy = ProxySpec("tailscale-mullvad-se", 1055);
    r.bindIp6 = "";
    auto back = DialRequest.fromJson(parseJsonString(r.toJson().toString()));
    assert(back == r);
    r.hasProxy = false;
    r.proxy = ProxySpec.init;
    r.bindIp6 = "2001:db8::1";
    r.tls = "starttls";
    back = DialRequest.fromJson(parseJsonString(r.toJson().toString()));
    assert(back == r);
    assert(r.toJson()["proxy"].type == Json.Type.null_);
}

@("DialRequest applies defaults and validates")
unittest {
    import std.exception : assertThrown;
    auto r = DialRequest.fromJson(parseJsonString(`{"host":"h","port":6667}`));
    assert(r.tls == "none" && r.sni == "h" && !r.hasProxy);
    assert(r.connectTimeoutMs == 10_000 && r.tlsTimeoutMs == 10_000 && r.starttlsTimeoutMs == 15_000);
    assertThrown(DialRequest.fromJson(parseJsonString(`{"port":6667}`)));
    assertThrown(DialRequest.fromJson(parseJsonString(`{"host":"h","port":70000}`)));
    assertThrown(DialRequest.fromJson(parseJsonString(`{"host":"h","port":1,"tls":"maybe"}`)));
    assertThrown(DialRequest.fromJson(parseJsonString(`{"host":"h","port":1,"proxy":{"host":"p"}}`)));
}

@("Entry round-trips, nulls for open entries")
unittest {
    Entry e;
    e.id = "c-12";
    e.tag = Tag("n", "u", "Libera", "");
    e.state = "open";
    e.attached = true;
    e.host = "irc.libera.chat";
    e.port = 6697;
    e.tls = TlsInfoJson(true, TlsInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384", "irc.libera.chat", "R11", 1_704_067_200_000));
    e.peerIp = "1.2.3.4";
    e.localIp = "10.0.0.2";
    e.connectedAtMs = 1_700_000_000_000;
    auto j = parseJsonString(e.toString());
    assert(j["detachedSinceMs"].type == Json.Type.null_);
    assert(j["closeReason"].type == Json.Type.null_);
    assert(j["closedAtMs"].type == Json.Type.null_);
    assert(j["meta"].type == Json.Type.null_);
    assert(j["tls"]["ok"].get!bool && j["tls"]["version"].get!string == "TLSv1.3");
    assert(j["id"].get!string == e.id && Tag.fromJson(j["tag"]) == e.tag);
    assert(j["state"].get!string == e.state && j["attached"].get!bool == e.attached);
    assert(TlsInfoJson.fromJson(j["tls"]) == e.tls && j["peerIp"].get!string == e.peerIp);
    assert(j["connectedAtMs"].get!long == e.connectedAtMs);

    e.state = "closed";
    e.attached = false;
    e.detachedSinceMs = 5;
    e.closeReason = CLOSE_PEER_CLOSED;
    e.closedAtMs = 6;
    e.bufferedBytes = 7;
    Json envelope;
    e.meta = ValidatedMeta.fromRequest(`META {"meta":{"nick":"z"}}`, envelope);
    auto back = parseJsonString(e.toString());
    assert(back["detachedSinceMs"].get!long == 5 && back["closeReason"].get!string == CLOSE_PEER_CLOSED);
    assert(back["closedAtMs"].get!long == 6 && back["bufferedBytes"].get!long == 7);
    assert(back["meta"]["nick"].get!string == "z");
}

@("EVENT / CONNECTED / FAILED round-trip")
unittest {
    auto ev = EventLine("tcp_open", "", "1.2.3.4", "10.0.0.2", 6697, 51_000);
    assert(EventLine.fromJson(parseJsonString(ev.toJson().toString())) == ev);
    auto c = ConnectedLine("c-1", "1.2.3.4", "10.0.0.2", 6697, 51_000, 123, TlsInfoJson(false, TlsInfo.init));
    assert(ConnectedLine.fromJson(parseJsonString(c.toJson().toString())) == c);
    auto f = FailedLine("tls", "TLS handshake timed out after 10 secs for irc.example.org");
    assert(FailedLine.fromJson(parseJsonString(f.toJson().toString())) == f);
}

@("okLine / errLine shapes")
unittest {
    assert(okLine(Json.emptyObject) == "OK {}");
    auto e = errLine(ERR_AUTH, "bad token");
    assert(e[0 .. 4] == "ERR ");
    auto j = parseJsonString(e[4 .. $]);
    assert(j["code"].get!string == "auth" && j["msg"].get!string == "bad token");
}

@("ircVerb skips tags and prefix; ircLastParam mirrors params[$-1]")
unittest {
    string verb, rest;
    ircVerb("PING :irc.example.org", verb, rest);
    assert(verb == "PING" && rest == ":irc.example.org");
    ircVerb(":server PING :abc", verb, rest);
    assert(verb == "PING" && ircLastParam(rest) == "abc");
    ircVerb("@time=x :server PING abc", verb, rest);
    assert(verb == "PING" && ircLastParam(rest) == "abc");
    ircVerb("PING", verb, rest);
    assert(verb == "PING" && ircLastParam(rest) == "");
    ircVerb(":irc.example.org 670 nick :STARTTLS successful, go ahead with TLS handshake", verb, rest);
    assert(verb == "670");
    assert(ircLastParam("a b :c d") == "c d");
    assert(ircLastParam("a b") == "b");
}

@("Native DIAL is strict and additive to old any requests")
unittest {
    import std.exception : assertThrown;
    auto legacy = DialRequest.fromJson(parseJsonString(`{"host":"h","port":6667}`));
    assert(legacy.addressFamily == "any");
    auto nativeReq = DialRequest.fromJson(parseJsonString(
        `{"host":"h","port":6697,"addressFamily":"ipv6","bindIp6":"2001:db8:1234:5678:a516:4466:5544:123"}`));
    assert(nativeReq.addressFamily == "ipv6");
    assert(DialRequest.fromJson(parseJsonString(nativeReq.toJson().toString())) == nativeReq);
    foreach (bad; [
        `{"host":"h","port":1,"addressFamily":"v6"}`,
        `{"host":"h","port":1,"addressFamily":null}`,
        `{"host":"h","port":1,"addressFamily":6}`,
        `{"host":"h","port":1,"addressFamily":""}`,
        `{"host":"h","port":1,"addressFamily":"ipv6"}`,
        `{"host":"h","port":1,"addressFamily":"ipv6","bindIp6":"127.0.0.1"}`,
        `{"host":"h","port":1,"addressFamily":"ipv6","bindIp6":"::"}`,
        `{"host":"h","port":1,"addressFamily":"ipv6","bindIp6":"::ffff:7f00:1"}`,
        `{"host":"h","port":1,"addressFamily":"ipv6","bindIp6":"2001:db8::1","proxy":{"host":"p","port":1080}}`,
    ]) assertThrown(DialRequest.fromJson(parseJsonString(bad)));
    nativeReq.hasProxy = true;
    assertThrown(nativeReq.toJson());
}

@("META wire accounting honors escapes, nested values and duplicate keys")
unittest {
    import std.exception : assertThrown;
    auto value = `{ "text" : "escaped \" } ],", "nested" : [null, {"x":true}] }`;
    auto line = `META {"id":"c-test","meta": ` ~ value ~ ` , "extra":[{},1]}`;
    Json envelope;
    assert(ValidatedMeta.fromRequest(line, envelope).encodedBytes == value.length);
    assert(ValidatedMeta.fromRequest(`META {"meta":null}`, envelope).encodedBytes == 4);
    assert(ValidatedMeta.fromRequest(`META {"m\u0065ta":"\u00e9"}`, envelope).encodedBytes == `"\u00e9"`.length);
    assert(ValidatedMeta.fromRequest("META {\"meta\":\"é\"}", envelope).encodedBytes == "\"é\"".length);
    assertThrown(ValidatedMeta.fromRequest(`META {"meta":{},"m\u0065ta":[]}`, envelope));
    assertThrown(ValidatedMeta.fromRequest(`META {"id":"none"}`, envelope));
    string deep = "META {\"meta\":";
    foreach (_; 0 .. 257) deep ~= "[";
    deep ~= "0";
    foreach (_; 0 .. 257) deep ~= "]";
    deep ~= "}";
    assertThrown(ValidatedMeta.fromRequest(deep, envelope));
}

@("Zero detach timeout is unlimited and invalid configuration is rejected")
unittest {
    import std.exception : assertThrown;
    assert(parseDetachMaxSecs("0") == 0);
    assert(parseDetachMaxSecs("600") == 600);
    foreach (bad; ["", "-1", "+1", "1x", " 0", "9223372036854775808"])
        assertThrown(parseDetachMaxSecs(bad));
}

@("Entry gap fields round trip while inventory excludes restoration payloads")
unittest {
    Entry entry;
    entry.id = "c-instance-42";
    entry.ordinal = 42;
    entry.state = "open";
    entry.attached = true;
    entry.gapGeneration = 3;
    entry.gapAckGeneration = 2;
    entry.droppedBytes = 12345;
    entry.droppedLines = 67;
    entry.gapStartedAtMs = 9988;
    entry.deliveryAmbiguous = true;
    entry.relayBytes = 4096;
    entry.outboundBytes = 128;
    entry.pongBytes = 64;
    entry.relayWriterFlightBytes = 1024;
    entry.relayWriteInFlightMs = 100;
    entry.upstreamWriteInFlightMs = 200;
    entry.attachmentGeneration = 4;
    entry.attachmentWriterCompletions = 3;
    entry.upstreamWriterDone = true;
    entry.tlsFinalized = true;
    Json envelope;
    entry.meta = ValidatedMeta.fromRequest(`META {"meta":{"private":"not-in-inventory"}}`, envelope);
    entry.tag.name = "not-in-inventory-either";
    auto full = parseJsonString(entry.toString());
    assert(full["ordinal"].get!long == 42 && full["gapGeneration"].get!long == 3 && full["gapAckGeneration"].get!long == 2);
    assert(full["droppedBytes"].get!long == 12345 && full["droppedLines"].get!long == 67);
    assert(full["gapStartedAtMs"].get!long == 9988 && full["deliveryAmbiguous"].get!bool);
    assert(full["relayBytes"].get!long == 4096 && full["outboundBytes"].get!long == 128 && full["pongBytes"].get!long == 64);
    assert(full["relayWriterFlightBytes"].get!long == 1024 && full["relayWriteInFlightMs"].get!long == 100);
    assert(full["upstreamWriteInFlightMs"].get!long == 200 && full["attachmentGeneration"].get!long == 4);
    assert(full["attachmentWriterCompletions"].get!long == 3 && full["upstreamWriterDone"].get!bool && full["tlsFinalized"].get!bool);
    auto row = entry.inventoryJson();
    assert(row["meta"].type == Json.Type.undefined && row["tag"].type == Json.Type.undefined);
    assert(row["gapGeneration"].get!long == 3 && row["deliveryAmbiguous"].get!bool);
    assert(counterJson(ulong.max).get!long == long.max);
}

@("Tombstone reasons retain only bounded printable categories")
unittest {
    assert(boundedCloseReason("tls_read_error: large private exception") == "tls_read_error");
    assert(boundedCloseReason("closed_by_engine") == "closed_by_engine");
    assert(boundedCloseReason("bad\nreason") == "bad?reason");
    string longReason;
    foreach (_; 0 .. 1000) longReason ~= "x";
    assert(boundedCloseReason(longReason).length == 128);
}

@("Incarnation is explicit on restoration and fresh-DIAL responses")
unittest {
    Entry entry;
    entry.id = "c-example-1";
    entry.instance = "00000000-0000-4000-8000-000000000000";
    assert(parseJsonString(entry.toString())["instance"].get!string == entry.instance);
    ConnectedLine connected;
    connected.id = entry.id;
    connected.instance = entry.instance;
    assert(ConnectedLine.fromJson(connected.toJson()).instance == entry.instance);
}

@("Owned META round-trips through the shared consumer without framing injection")
unittest {
    import ircfiber.holder_client : HolderEntry;
    import std.exception : assertThrown;
    auto request = ("META {\"id\":\"owned\",\"meta\":{\r\"wasConnected\":true,"
        ~ "\"graceful\":\"false\",\"text\":\"line\\nquote\\\"\\\\é\","
        ~ "\"usersDropped\":false,\"channelUsers\":{\"#one\":[\"a\",\"b\"]}}}").dup;
    Json envelope;
    auto meta = ValidatedMeta.fromRequest(cast(string) request, envelope);
    const bytes = meta.encodedBytes;
    request[] = 'x'; // Caller-owned mutable storage must no longer be referenced.
    Entry entry;
    entry.id = envelope["id"].get!string;
    entry.meta = meta;
    const line = okLine(entry, true);
    size_t newlines;
    foreach (c; line) {
        assert(c != '\r');
        if (c == '\n') ++newlines;
    }
    assert(newlines == 1 && line[$ - 1] == '\n');
    const consumer = HolderEntry.fromJson(parseJsonString(line[3 .. $ - 1]));
    assert(consumer.id == "owned" && consumer.hasMeta);
    assert(consumer.meta["wasConnected"].type == Json.Type.bool_ && consumer.meta["wasConnected"].get!bool);
    assert(consumer.meta["graceful"].type == Json.Type.string && consumer.meta["graceful"].get!string == "false");
    assert(consumer.meta["text"].get!string == "line\nquote\"\\é");
    assert(consumer.meta["channelUsers"]["#one"].length == 2);
    ulong members;
    assert(meta.memberCount(members) && members == 2 && bytes == meta.encodedBytes);
    assert(envelope["meta"].type == Json.Type.undefined && envelope.length == 1);
    foreach (bad; [
        `META {"meta":{"x":tru}}`,
        `META {"meta":[1,]}`,
        `META {"meta":{"text":"bad\q"}}`,
        `META {"meta":{"x":1],"later":{}}`,
        `META {"meta":1.}`,
        `META {"meta":01}`,
        `META {"meta":0e+}`,
        `META {"meta":{},"extra":[],}`,
        `META {"meta":{}} trailing`,
        `META {"meta":"\ud800"}`,
        `META {"meta":"\udc00"}`,
        "META {\"meta\":\"literal\tcontrol\"}",
        "META {\"meta\":{\"text\":\"literal\nnewline\"}}"
    ]) assertThrown(ValidatedMeta.fromRequest(bad, envelope));
}

@("Cached META memberships preserve parser duplicate and strict marker semantics")
unittest {
    Json envelope;
    ulong members;
    auto complete = ValidatedMeta.fromRequest(
        `META {"meta":{"usersDropped":true,"usersDropped":false,"channelUsers":{"#one":["a","b"],"#two":["a"]}}}`,
        envelope);
    assert(complete.memberCount(members) && members == 3);
    Entry entry;
    entry.meta = complete;
    const decoded = parseJsonString(entry.toString())["meta"];
    assert(!decoded["usersDropped"].get!bool && decoded["channelUsers"]["#two"].length == 1);
    foreach (value; [
        `null`, `{}`, `{"usersDropped":true,"channelUsers":{}}`,
        `{"usersDropped":"false","channelUsers":{}}`,
        `{"usersDropped":0,"channelUsers":{}}`,
        `{"usersDropped":false,"channelUsers":{"#one":null}}`
    ]) {
        auto unavailable = ValidatedMeta.fromRequest(`META {"meta":` ~ value ~ `}`, envelope);
        assert(!unavailable.memberCount(members));
    }
    auto empty = ValidatedMeta.fromRequest(`META {"meta":{"usersDropped":false,"channelUsers":{}}}`, envelope);
    assert(empty.memberCount(members) && members == 0);
}
