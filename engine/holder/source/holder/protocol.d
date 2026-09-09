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
        }
        r.bindIp6 = jstr(j, "bindIp6");
        r.connectTimeoutMs = jlong(j, "connectTimeoutMs", r.connectTimeoutMs);
        r.tlsTimeoutMs = jlong(j, "tlsTimeoutMs", r.tlsTimeoutMs);
        r.starttlsTimeoutMs = jlong(j, "starttlsTimeoutMs", r.starttlsTimeoutMs);
        if (r.connectTimeoutMs <= 0 || r.tlsTimeoutMs <= 0 || r.starttlsTimeoutMs <= 0)
            throw new Exception("DIAL: timeouts must be positive");
        return r;
    }

    Json toJson() const {
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
    /// `Json(null)` when the engine never set one.
    Json meta = Json(null);

    Json toJson() const {
        auto j = Json.emptyObject;
        j["id"] = id;
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
        j["meta"] = meta.type == Json.Type.undefined ? Json(null) : meta;
        return j;
    }

    static Entry fromJson(Json j) {
        Entry e;
        e.id = jstr(j, "id");
        e.tag = Tag.fromJson(j["tag"]);
        e.state = jstr(j, "state");
        e.attached = jbool(j, "attached");
        e.host = jstr(j, "host");
        e.port = cast(ushort) jlong(j, "port");
        e.tls = TlsInfoJson.fromJson(j["tls"]);
        e.peerIp = jstr(j, "peerIp");
        e.localIp = jstr(j, "localIp");
        e.connectedAtMs = jlong(j, "connectedAtMs");
        e.detachedSinceMs = jlong(j, "detachedSinceMs");
        e.bufferedBytes = cast(size_t) jlong(j, "bufferedBytes");
        e.closeReason = jstr(j, "closeReason");
        e.closedAtMs = jlong(j, "closedAtMs");
        auto m = j["meta"];
        e.meta = (m.type == Json.Type.undefined) ? Json(null) : m;
        return e;
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

    Json toJson() const {
        auto j = Json.emptyObject;
        j["id"] = id;
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
        return c;
    }
}

/// Terminal `FAILED` line of a `DIAL`.
struct FailedLine {
    /// "dns" | "tcp" | "socks5" | "tls" | "starttls"
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

/// `OK <json>` response line (no trailing newline).
string okLine(Json payload) {
    return "OK " ~ payload.toString();
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
    auto j = e.toJson();
    assert(j["detachedSinceMs"].type == Json.Type.null_);
    assert(j["closeReason"].type == Json.Type.null_);
    assert(j["closedAtMs"].type == Json.Type.null_);
    assert(j["meta"].type == Json.Type.null_);
    assert(j["tls"]["ok"].get!bool && j["tls"]["version"].get!string == "TLSv1.3");
    auto back = Entry.fromJson(parseJsonString(j.toString()));
    assert(back.id == e.id && back.tag == e.tag && back.state == e.state && back.attached == e.attached);
    assert(back.tls == e.tls && back.peerIp == e.peerIp && back.connectedAtMs == e.connectedAtMs);
    assert(back.meta.type == Json.Type.null_);

    e.state = "closed";
    e.attached = false;
    e.detachedSinceMs = 5;
    e.closeReason = CLOSE_PEER_CLOSED;
    e.closedAtMs = 6;
    e.bufferedBytes = 7;
    e.meta = parseJsonString(`{"nick":"z"}`);
    back = Entry.fromJson(parseJsonString(e.toJson().toString()));
    assert(back.detachedSinceMs == 5 && back.closeReason == CLOSE_PEER_CLOSED && back.closedAtMs == 6);
    assert(back.bufferedBytes == 7 && back.meta["nick"].get!string == "z");
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
