/**
 * Network-scoped IRC services trust configuration.
 *
 * Each `NetworkConfig` carries a `ServicesConfig`: which services package
 * to expect (`auto` discovery, `anope`, or `disabled`), the services
 * pseudo-server the user approved, and per-service WHOIS pins (nick, ident,
 * host) for NickServ, ChanServ, BotServ, MemoServ, HostServ, OperServ and
 * Global. A service is trusted only when the server and that service's
 * full pin are present; anything less is discovery, never authority.
 *
 * No credentials live here: the wire shape is closed (unknown fields are
 * rejected), so a password cannot be smuggled into this object.
 *
 * Managed vs external: the platform network's services are never taken
 * from stored or client data. `effectiveServicesConfig(stored, managedHost)`
 * substitutes `managedServicesConfig()` when the *server* established the
 * network dials the platform ircd (`cfg.host == DEFAULT_FIBER_HOST`), so a
 * browser cannot declare a network managed or rewrite the managed pins.
 * The managed pseudo-server name defaults to `services.ircfiber.com` and is
 * overridable with `IRCFIBER_MANAGED_SERVICES_SERVER` for local/CI stacks.
 *
 * Legacy documents without a `services` field — and malformed stored
 * values — decode to the default: automatic discovery, nothing trusted.
 */
module ircfiber.services.config;

import std.process : environment;
import std.string : strip;

import vibe.data.json;

/// Which services package a network is expected to run.
enum ServicesProvider {
    /// Discover services on connect; nothing is trusted until pinned.
    auto_,
    /// Anope (2.0 / 2.1).
    anope,
    /// Services integration switched off for this network.
    disabled
}

/// Wire name of a provider (`auto`, `anope`, `disabled`).
string providerName(ServicesProvider p) @safe pure nothrow @nogc {
    final switch (p) {
        case ServicesProvider.auto_:    return "auto";
        case ServicesProvider.anope:    return "anope";
        case ServicesProvider.disabled: return "disabled";
    }
}

/// Parses a provider wire name; false for anything else.
bool parseProvider(string s, out ServicesProvider p) @safe pure nothrow @nogc {
    switch (s) {
        case "auto":     p = ServicesProvider.auto_;    return true;
        case "anope":    p = ServicesProvider.anope;    return true;
        case "disabled": p = ServicesProvider.disabled; return true;
        default:         return false;
    }
}

/// The seven services the UI integrates.
enum ServiceId {
    /// NickServ
    nickServ,
    /// ChanServ
    chanServ,
    /// BotServ
    botServ,
    /// MemoServ
    memoServ,
    /// HostServ
    hostServ,
    /// OperServ
    operServ,
    /// Global
    global
}

/// Number of `ServiceId` members.
enum size_t SERVICE_COUNT = ServiceId.max + 1;

/// Wire keys of `ServicesConfig.pins`, indexed by `ServiceId`.
immutable string[SERVICE_COUNT] SERVICE_KEYS = [
    "nickserv", "chanserv", "botserv", "memoserv", "hostserv", "operserv", "global"
];

/// Conventional pseudoclient nicks, indexed by `ServiceId`.
immutable string[SERVICE_COUNT] SERVICE_DEFAULT_NICKS = [
    "NickServ", "ChanServ", "BotServ", "MemoServ", "HostServ", "OperServ", "Global"
];

/// Parses a `pins` key; false for anything that is not one of the seven.
bool parseServiceId(string key, out ServiceId id) @safe pure nothrow @nogc {
    foreach (i, k; SERVICE_KEYS) {
        if (k == key) {
            id = cast(ServiceId) i;
            return true;
        }
    }
    return false;
}

/// Longest pinned pseudoclient nick.
enum size_t MAX_SERVICE_NICK = 32;
/// Longest pinned ident (USERLEN is 10 on most ircds; `~` adds one).
enum size_t MAX_SERVICE_IDENT = 16;
/// Longest pinned host.
enum size_t MAX_SERVICE_HOST = 255;
/// Longest services server name (RFC 2812 servername bound).
enum size_t MAX_SERVICES_SERVER = 63;

/// Ident every managed Anope pseudoclient uses (`user = "services"` in the
/// deployed service blocks).
enum string MANAGED_SERVICES_IDENT = "services";
/// Pseudo-server name of the platform's Anope when the env does not override it.
enum string DEFAULT_MANAGED_SERVICES_SERVER = "services.ircfiber.com";

/// Pseudo-server (and pseudoclient host) of the managed network's services.
/// `IRCFIBER_MANAGED_SERVICES_SERVER`; invalid or unset → the production name.
immutable string MANAGED_SERVICES_SERVER;

shared static this() {
    MANAGED_SERVICES_SERVER = parseManagedServicesServer(
        environment.get("IRCFIBER_MANAGED_SERVICES_SERVER", ""));
}

/// Parses `IRCFIBER_MANAGED_SERVICES_SERVER`. A typo falls back to the
/// production name, which simply fails the pin check (fail closed) rather
/// than trusting an arbitrary value.
string parseManagedServicesServer(string raw) @safe pure {
    const s = raw.strip();
    return s.length && isValidServerName(s) ? s : DEFAULT_MANAGED_SERVICES_SERVER;
}

/// WHOIS identity a service must present: `nick!ident@host`.
struct ServicePin {
    /// Pseudoclient nick (renamed services are overridden here).
    string nick;
    /// Approved ident; empty until approval.
    string ident;
    /// Approved host; empty until approval.
    string host;

    /// Nothing configured for this service.
    bool isEmpty() const @safe pure nothrow @nogc {
        return nick.length == 0 && ident.length == 0 && host.length == 0;
    }

    /// Nick, ident and host are all approved.
    bool isComplete() const @safe pure nothrow @nogc {
        return nick.length != 0 && ident.length != 0 && host.length != 0;
    }
}

/// Per-network services trust configuration.
struct ServicesConfig {
    /// Expected services package.
    ServicesProvider provider = ServicesProvider.auto_;
    /// Approved services pseudo-server; empty = not approved.
    string server;
    /// Per-service pins, indexed by `ServiceId`.
    ServicePin[SERVICE_COUNT] pins;

    /// Automatic discovery with nothing configured (legacy/new networks).
    bool isDefault() const @safe pure nothrow {
        return this == ServicesConfig.init;
    }

    /// Wire/storage form. Unconfigured pins are omitted.
    Json toJson() const {
        auto p = Json.emptyObject;
        foreach (i, ref pin; pins) {
            if (pin.isEmpty) continue;
            p[SERVICE_KEYS[i]] = Json([
                "nick": Json(pin.nick),
                "ident": Json(pin.ident),
                "host": Json(pin.host)
            ]);
        }
        return Json([
            "provider": Json(providerName(provider)),
            "server": Json(server),
            "pins": p
        ]);
    }
}

/// True when `id` has an approved identity on this network: integration not
/// disabled, an approved services server, and nick+ident+host pinned.
bool isServiceTrusted(const ref ServicesConfig cfg, ServiceId id) @safe pure nothrow @nogc {
    return cfg.provider != ServicesProvider.disabled
        && cfg.server.length != 0
        && cfg.pins[id].isComplete;
}

/// The managed network's services, derived from the deployment (never from
/// stored or client data).
ServicesConfig managedServicesConfig(string server = MANAGED_SERVICES_SERVER) @safe pure nothrow {
    ServicesConfig cfg;
    cfg.provider = ServicesProvider.anope;
    cfg.server = server;
    foreach (i, nick; SERVICE_DEFAULT_NICKS)
        cfg.pins[i] = ServicePin(nick, MANAGED_SERVICES_IDENT, server);
    return cfg;
}

/// The configuration a connection must enforce. `managedHost` must come from
/// the server's own knowledge (`cfg.host == DEFAULT_FIBER_HOST`); when set,
/// the stored value is ignored entirely.
ServicesConfig effectiveServicesConfig(const ServicesConfig stored, bool managedHost) @safe pure nothrow {
    if (managedHost) return managedServicesConfig();
    ServicesConfig copy = stored;
    return copy;
}

/// What a network create/update persists, given the prior stored value and
/// the validated request value (`requested is null` when the body omitted
/// `services`):
/// - managed host: always the default. The managed value is derived at use
///   (`effectiveServicesConfig`), so a request can neither declare a network
///   managed nor alter its pins.
/// - host changed: the default. Trust approved for one network never carries
///   to another, even when the same request re-sends the old pins.
/// - otherwise the request value, or the prior value when omitted.
ServicesConfig servicesConfigToStore(const ServicesConfig prior, const(ServicesConfig)* requested,
                                     bool managedHost, bool hostChanged) @safe pure nothrow {
    if (managedHost || hostChanged) return ServicesConfig.init;
    ServicesConfig result = requested !is null ? *requested : prior;
    return result;
}

/// Strict parse of a client-supplied or stored `services` object.
/// Returns null on success, else a reason safe to show the client (no input
/// is echoed). `cfg` is only assigned on success.
///
/// Shape: `{ "provider": "auto"|"anope"|"disabled", "server"?: string,
/// "pins"?: { <service>: { "nick": string, "ident"?: string, "host"?: string } } }`.
/// Unknown fields or services, non-string values, invalid identifiers,
/// ident/host pinned without the other, prefixes pinned without a server,
/// and two services sharing a nick are all rejected.
string parseServicesConfig(Json j, out ServicesConfig cfg) {
    if (j.type != Json.Type.object) return "services must be an object";
    ServicesConfig parsed;
    bool haveProvider;
    foreach (string key, value; j) {
        switch (key) {
            case "provider":
                if (value.type != Json.Type.string || !parseProvider(value.get!string, parsed.provider))
                    return "services.provider must be one of auto, anope, disabled";
                haveProvider = true;
                break;
            case "server": {
                if (value.type != Json.Type.string) return "services.server must be a string";
                const s = value.get!string;
                if (s.length && !isValidServerName(s))
                    return "services.server is not a valid IRC server name";
                parsed.server = s;
                break;
            }
            case "pins": {
                const err = parsePins(value, parsed.pins);
                if (err.length) return err;
                break;
            }
            default:
                return "services contains an unrecognised field";
        }
    }
    if (!haveProvider) return "services.provider is required";

    char[][SERVICE_COUNT] folded;
    foreach (i, ref pin; parsed.pins) {
        if (pin.isEmpty) continue;
        if (pin.ident.length && !parsed.server.length)
            return "services.server is required when a service prefix is pinned";
        folded[i] = foldNick(pin.nick);
        foreach (k; 0 .. i)
            if (folded[k].length && folded[k] == folded[i])
                return "services.pins assigns one nick to two services";
    }
    cfg = parsed;
    return null;
}

/// Decodes a persisted value (Mongo document, Redis cache, engine control
/// JSON). Absent/null is the legacy default; a malformed value also yields
/// the default — no trust — and reports why in `error` for logging.
ServicesConfig decodeStoredServicesConfig(Json j, out string error) {
    if (j.type == Json.Type.undefined || j.type == Json.Type.null_) return ServicesConfig.init;
    ServicesConfig cfg;
    error = parseServicesConfig(j, cfg);
    return error.length ? ServicesConfig.init : cfg;
}

private string parsePins(Json j, ref ServicePin[SERVICE_COUNT] pins) {
    if (j.type != Json.Type.object) return "services.pins must be an object";
    foreach (string key, value; j) {
        ServiceId id;
        if (!parseServiceId(key, id)) return "services.pins contains an unknown service";
        const where = "services.pins." ~ SERVICE_KEYS[id];
        if (value.type != Json.Type.object) return where ~ " must be an object";
        ServicePin pin;
        foreach (string field, v; value) {
            if (v.type != Json.Type.string) return where ~ " values must be strings";
            switch (field) {
                case "nick":  pin.nick = v.get!string;  break;
                case "ident": pin.ident = v.get!string; break;
                case "host":  pin.host = v.get!string;  break;
                default:      return where ~ " contains an unrecognised field";
            }
        }
        if (!isValidServiceNick(pin.nick)) return where ~ ".nick is not a valid IRC nick";
        if ((pin.ident.length == 0) != (pin.host.length == 0))
            return where ~ " must pin ident and host together";
        if (pin.ident.length && !isValidServiceIdent(pin.ident))
            return where ~ ".ident is not a valid ident";
        if (pin.host.length && !isValidServiceHost(pin.host))
            return where ~ ".host is not a valid host";
        pins[id] = pin;
    }
    return null;
}

private bool isAsciiAlpha(char c) @safe pure nothrow @nogc {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

private bool isAsciiDigit(char c) @safe pure nothrow @nogc {
    return c >= '0' && c <= '9';
}

private bool isNickSpecial(char c) @safe pure nothrow @nogc {
    return c == '[' || c == ']' || c == '\\' || c == '`' || c == '_'
        || c == '^' || c == '{' || c == '|' || c == '}';
}

/// RFC 2812 nick: letter/special first, then letters, digits, specials, `-`.
bool isValidServiceNick(string s) @safe pure nothrow @nogc {
    if (s.length == 0 || s.length > MAX_SERVICE_NICK) return false;
    if (!isAsciiAlpha(s[0]) && !isNickSpecial(s[0])) return false;
    foreach (c; s[1 .. $])
        if (!isAsciiAlpha(c) && !isAsciiDigit(c) && !isNickSpecial(c) && c != '-') return false;
    return true;
}

/// Ident: optional leading `~`, then `[A-Za-z0-9_.-]`.
bool isValidServiceIdent(string s) @safe pure nothrow @nogc {
    if (s.length == 0 || s.length > MAX_SERVICE_IDENT) return false;
    const body_ = s[0] == '~' ? s[1 .. $] : s;
    if (body_.length == 0) return false;
    foreach (c; body_)
        if (!isAsciiAlpha(c) && !isAsciiDigit(c) && c != '_' && c != '.' && c != '-') return false;
    return true;
}

/// Host as shown in WHOIS: hostname, IP, or cloak (`[A-Za-z0-9.:/_-]`),
/// never starting with `:` (it would read as a trailing parameter).
bool isValidServiceHost(string s) @safe pure nothrow @nogc {
    if (s.length == 0 || s.length > MAX_SERVICE_HOST || s[0] == ':') return false;
    foreach (c; s)
        if (!isAsciiAlpha(c) && !isAsciiDigit(c) && c != '.' && c != '-'
                && c != '_' && c != ':' && c != '/') return false;
    return true;
}

/// IRC server name: two or more non-empty `[A-Za-z0-9_-]` labels joined by `.`.
bool isValidServerName(string s) @safe pure nothrow @nogc {
    if (s.length == 0 || s.length > MAX_SERVICES_SERVER) return false;
    size_t labels, labelLen;
    foreach (c; s) {
        if (c == '.') {
            if (labelLen == 0) return false;
            ++labels;
            labelLen = 0;
        } else if (isAsciiAlpha(c) || isAsciiDigit(c) || c == '-' || c == '_') {
            ++labelLen;
        } else {
            return false;
        }
    }
    if (labelLen == 0) return false;
    return labels + 1 >= 2;
}

/// RFC 1459 fold — the widest common casemapping, so a duplicate under any
/// network's mapping is caught.
private char[] foldNick(string s) @safe pure nothrow {
    auto outp = new char[s.length];
    foreach (i, c; s) {
        if (c >= 'A' && c <= 'Z') outp[i] = cast(char)(c + 32);
        else if (c == '[') outp[i] = '{';
        else if (c == ']') outp[i] = '}';
        else if (c == '\\') outp[i] = '|';
        else if (c == '^') outp[i] = '~';
        else outp[i] = c;
    }
    return outp;
}

@("services config: legacy and null decode to default, no trust")
unittest {
    string err;
    auto legacy = decodeStoredServicesConfig(Json.undefined, err);
    assert(legacy.isDefault && err.length == 0);
    auto nul = decodeStoredServicesConfig(Json(null), err);
    assert(nul.isDefault && err.length == 0);
    foreach (id; 0 .. SERVICE_COUNT)
        assert(!isServiceTrusted(legacy, cast(ServiceId) id));
    assert(ServicesConfig.init.provider == ServicesProvider.auto_);
}

@("services config: pins round-trip through JSON and BSON")
unittest {
    import vibe.data.bson : Bson;
    ServicesConfig cfg;
    cfg.provider = ServicesProvider.anope;
    cfg.server = "services.example.net";
    cfg.pins[ServiceId.nickServ] = ServicePin("NS", "services", "services.example.net");
    cfg.pins[ServiceId.chanServ] = ServicePin("ChanServ", "~svc", "svc/cloak:1");
    cfg.pins[ServiceId.global] = ServicePin("Announcer", "", "");

    ServicesConfig back;
    assert(parseServicesConfig(cfg.toJson(), back) is null);
    assert(back == cfg);

    string err;
    auto viaText = decodeStoredServicesConfig(parseJsonString(cfg.toJson().toString()), err);
    assert(err.length == 0 && viaText == cfg);
    auto viaBson = decodeStoredServicesConfig(Bson.fromJson(cfg.toJson()).toJson(), err);
    assert(err.length == 0 && viaBson == cfg);

    assert(isServiceTrusted(back, ServiceId.nickServ));
    assert(isServiceTrusted(back, ServiceId.chanServ));
    assert(!isServiceTrusted(back, ServiceId.global));   // nick override only
    assert(!isServiceTrusted(back, ServiceId.memoServ)); // nothing pinned
    back.provider = ServicesProvider.disabled;
    assert(!isServiceTrusted(back, ServiceId.nickServ));
}

@("services config: strict parser rejects unknown, malformed and injected input")
unittest {
    ServicesConfig cfg;
    bool rejects(string text) {
        ServicesConfig tmp;
        return parseServicesConfig(parseJsonString(text), tmp) !is null;
    }
    assert(parseServicesConfig(parseJsonString(`{"provider":"auto"}`), cfg) is null && cfg.isDefault);
    assert(rejects(`[]`));
    assert(rejects(`{}`));                                         // provider required
    assert(rejects(`{"provider":"atheme"}`));
    assert(rejects(`{"provider":true}`));
    assert(rejects(`{"provider":"auto","managed":true}`));         // cannot declare managed
    assert(rejects(`{"provider":"auto","password":"x"}`));
    assert(rejects(`{"provider":"auto","server":"nodots"}`));
    assert(rejects(`{"provider":"auto","server":"a..b"}`));
    assert(rejects(`{"provider":"auto","server":"svc.example\r\nQUIT"}`));
    assert(rejects(`{"provider":"auto","server":"svc.example\u0000"}`));
    assert(rejects(`{"provider":"auto","pins":[]}`));
    assert(rejects(`{"provider":"auto","pins":{"fooserv":{"nick":"Foo"}}}`));
    assert(rejects(`{"provider":"auto","pins":{"nickserv":"NickServ"}}`));
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{}}}`));  // nick required
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{"nick":"Nick Serv"}}}`));
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{"nick":"NickServ\r\nPRIVMSG x :y"}}}`));
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{"nick":"1NS"}}}`));
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{"nick":"NickServ","password":"x"}}}`));
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{"nick":"NickServ","ident":1}}}`));
    // ident and host pinned together, and only with an approved server.
    assert(rejects(`{"provider":"auto","server":"s.example","pins":{"nickserv":{"nick":"NickServ","ident":"services"}}}`));
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{"nick":"NickServ","ident":"services","host":"s.example"}}}`));
    assert(rejects(`{"provider":"auto","server":"s.example","pins":{"nickserv":{"nick":"NickServ","ident":"ser@vices","host":"s.example"}}}`));
    assert(rejects(`{"provider":"auto","server":"s.example","pins":{"nickserv":{"nick":"NickServ","ident":"services","host":":bad"}}}`));
    assert(rejects(`{"provider":"auto","server":"s.example","pins":{"nickserv":{"nick":"NickServ","ident":"services","host":"a b"}}}`));
    // Two services cannot share a nick under RFC 1459 folding.
    assert(rejects(`{"provider":"auto","pins":{"nickserv":{"nick":"Serv[1]"},"chanserv":{"nick":"serv{1}"}}}`));
    // A rejected parse leaves `cfg` at its default.
    ServicesConfig untouched;
    assert(parseServicesConfig(parseJsonString(`{"provider":"anope","bogus":1}`), untouched) !is null);
    assert(untouched.isDefault);
}

@("services config: stored corruption falls back to no trust")
unittest {
    string err;
    auto cfg = decodeStoredServicesConfig(
        parseJsonString(`{"provider":"anope","server":"s.example","pins":{"nickserv":{"nick":"NickServ","ident":"x","host":"s.example","extra":"1"}}}`),
        err);
    assert(err.length != 0);
    assert(cfg.isDefault);
}

@("services config: managed config is derived, never taken from storage")
unittest {
    ServicesConfig stored;
    stored.provider = ServicesProvider.anope;
    stored.server = "evil.example";
    stored.pins[ServiceId.nickServ] = ServicePin("NickServ", "services", "evil.example");

    auto managed = effectiveServicesConfig(stored, true);
    assert(managed == managedServicesConfig());
    assert(managed.server == MANAGED_SERVICES_SERVER);
    foreach (i; 0 .. SERVICE_COUNT) {
        assert(managed.pins[i].nick == SERVICE_DEFAULT_NICKS[i]);
        assert(managed.pins[i].ident == MANAGED_SERVICES_IDENT);
        assert(managed.pins[i].host == MANAGED_SERVICES_SERVER);
        assert(isServiceTrusted(managed, cast(ServiceId) i));
    }
    assert(effectiveServicesConfig(stored, false) == stored);
    assert(effectiveServicesConfig(ServicesConfig.init, false).isDefault);

    assert(parseManagedServicesServer("") == DEFAULT_MANAGED_SERVICES_SERVER);
    assert(parseManagedServicesServer(" services.local.test ") == "services.local.test");
    assert(parseManagedServicesServer("bad name") == DEFAULT_MANAGED_SERVICES_SERVER);
}

@("services config: create/update store decision")
unittest {
    ServicesConfig prior;
    prior.provider = ServicesProvider.anope;
    prior.server = "services.example.net";
    prior.pins[ServiceId.nickServ] = ServicePin("NickServ", "services", "services.example.net");
    ServicesConfig requested;
    requested.provider = ServicesProvider.disabled;

    // Omitted body field keeps the stored value; a supplied one replaces it.
    assert(servicesConfigToStore(prior, null, false, false) == prior);
    assert(servicesConfigToStore(prior, &requested, false, false) == requested);
    // Managed hosts never store client data.
    assert(servicesConfigToStore(prior, &prior, true, false).isDefault);
    assert(servicesConfigToStore(prior, null, true, false).isDefault);
    // A host change drops prior and re-sent trust.
    assert(servicesConfigToStore(prior, null, false, true).isDefault);
    assert(servicesConfigToStore(prior, &prior, false, true).isDefault);
}

@("services config: identifier validators")
unittest {
    assert(isValidServiceNick("NickServ"));
    assert(isValidServiceNick("[Bot]-1"));
    assert(!isValidServiceNick(""));
    assert(!isValidServiceNick("-x"));
    assert(!isValidServiceNick("a\x00b"));
    assert(isValidServiceIdent("~services"));
    assert(!isValidServiceIdent("~"));
    assert(!isValidServiceIdent("a\nb"));
    assert(isValidServiceHost("2001:db8::1"));
    assert(isValidServiceHost("user/cloak"));
    assert(!isValidServiceHost("a@b"));
    assert(isValidServerName("services.ircfiber.com"));
    assert(isValidServerName("00A.discord.bridge"));
    assert(!isValidServerName("services."));
    assert(!isValidServerName(".services"));
}
