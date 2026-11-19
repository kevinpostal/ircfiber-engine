module ircfiber.models.network;

import std.algorithm : canFind, uniq, map, startsWith;
import std.array : array, appender;
import std.string : strip;
import std.uuid;
import std.uni : toLower;
import vibe.data.json;
import std.conv;
import ircfiber.services.config : ServicesConfig;
import ircfiber.irc.routing_policy : RoutingPreferences;
/// TLS mode options
enum TLSMode {
    /// TLS disabled
    disabled,
    /// TLS enabled
    enabled,
    /// TLS required
    required,
    /// Plain-text connect followed by a STARTTLS upgrade
    /// (`STARTTLS` command, `670 RPL_STARTTLS` reply, then the TLS
    /// handshake on the same connection). Fails closed: a `691`
    /// `ERR_STARTTLS` reply or a timeout aborts the attempt instead
    /// of continuing in plain text.
    starttls
}

/// A configured endpoint, including its registration credential.
struct BncServerEndpoint {
    string host;
    ushort port;
    TLSMode tls;
    string serverPass;

    bool sameAddress(const BncServerEndpoint other) const @safe {
        import std.uni : icmp;
        static string dnsHost(string name) {
            return name.length && name[$ - 1] == '.' ? name[0 .. $ - 1] : name;
        }
        if (port != other.port || tls != other.tls) return false;
        if (icmp(dnsHost(host), dnsHost(other.host)) == 0) return true;
        ubyte[16] left, right;
        return address6(host, left) && address6(other.host, right) && left == right;
    }

    private static bool address6(string name, ref ubyte[16] result) nothrow @trusted @nogc {
        import core.sys.posix.arpa.inet : inet_pton;
        import core.sys.posix.sys.socket : AF_INET6;
        if (!name.length || name.length > 45) return false;
        char[46] buffer = void;
        bool colon;
        foreach (i, char c; name) {
            if (c == 0) return false;
            colon = colon || c == ':';
            buffer[i] = c;
        }
        buffer[name.length] = 0;
        return colon && inet_pton(AF_INET6, buffer.ptr, result.ptr) == 1;
    }
}

bool isCanonicalServerFingerprint(string value) @safe pure nothrow @nogc {
    if (value.length != 64) return false;
    foreach (char c; value)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

/// Accepted user inputs are bare hex or exactly 32 colon-separated bytes.
string normalizeServerFingerprint(string value) @safe pure {
    const separated = value.length == 95;
    if (!separated && value.length != 64) return "";
    char[64] result = void;
    foreach (i, ref c; result) {
        const pos = separated ? i + i / 2 : i;
        if (separated && i > 0 && i % 2 == 0 && value[pos - 1] != ':') return "";
        c = value[pos];
        if (c >= 'A' && c <= 'F') c = cast(char)(c + ('a' - 'A'));
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return "";
    }
    return result[].idup;
}

/// Absent fields preserve legacy behavior; incorrect published types or
/// pins without verification fail closed, including when loaded from Mongo.
void decodeServerCertificatePolicy(Json verify, Json pins, out bool verification, out string[] fingerprints) {
    import std.exception : enforce;
    if (verify.type != Json.Type.undefined) {
        enforce(verify.type == Json.Type.bool_, "Invalid server certificate verification policy");
        verification = verify.get!bool;
    }
    if (pins.type == Json.Type.undefined) return;
    enforce(pins.type == Json.Type.array, "Invalid server fingerprint list");
    if (!pins.length) return;
    enforce(verification, "Server fingerprint allowlist requires verification");
    fingerprints = new string[pins.length];
    foreach (i; 0 .. pins.length) {
        const pin = pins[i];
        enforce(pin.type == Json.Type.string && isCanonicalServerFingerprint(pin.get!string),
            "Invalid server certificate fingerprint");
        fingerprints[i] = pin.get!string;
    }
}

/// SASL authentication mechanism
enum SASLMechanism {
    /// No SASL
    none,
    /// SASL PLAIN
    plain,
    /// SASL EXTERNAL
    external,
    /// SASL SCRAM-SHA-256
    scramSha256
}

/// Normalize an IRC channel/buffer name to canonical form.
/// Channels (`#`/`&`/`+`/`!` prefix) are case-insensitive and lowercased
/// so `#Zod` and `#zod` collapse. Bare names (DM nick buffers like
/// `Zodiac`, `alice`) are **not** `#`-prefixed — they must stay bare or
/// the frontend's `normalizeChannelName` (`name[0] !== '#'? return name`)
/// and the engine's `scrollback:<srv>:<net>:<chan>` keys diverge and DM
/// history disappears after reload (see AGENTS.md DM invariant). `_server`
/// is left untouched.
string normalizeChannelName(string name) @safe {
    if (name.length == 0 || name == "_server") return name;
    // Channel prefixes: lowercased for dedup. Bare nicks: returned as-is.
    if (name[0] == '#' || name[0] == '&' || name[0] == '+' || name[0] == '!')
        return name[0 .. 1] ~ name[1 .. $].toLower();
    return name;
}

/// Normalize a channel name for the auto-join list — ensures a leading `#`.
/// Bare names like `testing` or `MyChan` become `#testing` / `#mychan`.
/// Already-prefixed names (`#foo`, `&foo`, `+foo`, `!foo`) are just lowercased.
/// `_server` is left untouched (should never appear in auto-join, but be safe).
string normalizeAutoJoinChannel(string name) @safe {
    if (name.length == 0 || name == "_server") return name;
    auto trimmed = name.strip();
    if (trimmed.length == 0) return "";
    if (trimmed[0] == '#' || trimmed[0] == '&' || trimmed[0] == '+' || trimmed[0] == '!')
        return trimmed[0 .. 1] ~ trimmed[1 .. $].toLower();
    return "#" ~ trimmed.toLower();
}

/// Longest ident accepted. InspIRCd 4 advertises `USERLEN=10` and most
/// ircds truncate at 10; keeping the stored value inside that bound means
/// the registered ident is what the user sees.
enum size_t IDENT_MAX = 10;

/// Sanitises a user-supplied ident: keeps `[A-Za-z0-9_.-]`, drops every
/// other byte (spaces, `@`, `!`, `:` would corrupt the USER line), then
/// truncates to `IDENT_MAX`. Returns "" when nothing survives, which means
/// "use the nick".
string sanitizeIdent(string raw) @safe pure {
    auto app = appender!string();
    foreach (char c; raw) {
        if (app.data.length >= IDENT_MAX) break;
        const keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (keep) app.put(c);
    }
    return app.data;
}

/// Deduplicate and normalize a list of IRC channel names for auto-join.
/// Case-insensitive: "#Zod" and "#ZOD" collapse to one entry.
/// Bare names are auto-prefixed with `#` so `testing` → `#testing` and
/// never gets misrouted as a PRIVMSG to a nick (user-reported bug).
string[] dedupChannels(string[] channels) @safe {
    if (channels.length == 0) return channels;
    string[] outArr;
    bool[string] seen;
    foreach (ch; channels) {
        auto norm = normalizeAutoJoinChannel(ch);
        if (norm.length > 0 && norm !in seen) {
            seen[norm] = true;
            outArr ~= norm;
        }
    }
    return outArr;
}

enum IrcCaseMapping { rfc1459, ascii, strictRfc1459 }

IrcCaseMapping ircCaseMapping(string mode) @safe pure nothrow @nogc {
    if (mode == "ascii") return IrcCaseMapping.ascii;
    if (mode == "strict-rfc1459" || mode == "rfc1459-strict") return IrcCaseMapping.strictRfc1459;
    return IrcCaseMapping.rfc1459;
}

char foldIrcCaseChar(char c, IrcCaseMapping mapping) @safe pure nothrow @nogc {
    if (c >= 'A' && c <= 'Z') return cast(char)(c + ('a' - 'A'));
    if (mapping == IrcCaseMapping.ascii) return c;
    switch (c) {
        case '[': return '{';
        case ']': return '}';
        case '\\': return '|';
        case '^': return mapping == IrcCaseMapping.strictRfc1459 ? '^' : '~';
        default: return c;
    }
}

bool ircCaseEquals(string a, string b, IrcCaseMapping mapping) @safe pure nothrow @nogc {
    if (a.length != b.length) return false;
    foreach (i, char c; a)
        if (foldIrcCaseChar(c, mapping) != foldIrcCaseChar(b[i], mapping)) return false;
    return true;
}

string foldIrcName(string name, IrcCaseMapping mapping) @trusted pure {
    import std.exception : assumeUnique;
    char[] folded;
    foreach (i, char c; name) {
        const changed = foldIrcCaseChar(c, mapping);
        if (changed == c) continue;
        if (folded is null) folded = name.dup;
        folded[i] = changed;
    }
    return folded is null ? name : assumeUnique(folded);
}

/// Explicit clear requires both the timestamp and event-sequence fences.
struct BncPlaybackCutoff {
    long eid;
    long timestampMs;

    bool active() const @safe pure nothrow @nogc { return eid > 0 || timestampMs > 0; }

    bool allows(long time, long eventId) const @safe pure nothrow @nogc {
        return !active() || (time >= timestampMs
            && (eventId > eid || (eventId <= 0 && time > timestampMs)));
    }

    void advance(BncPlaybackCutoff next) @safe pure nothrow @nogc {
        if (eid < next.eid) eid = next.eid;
        if (timestampMs < next.timestampMs) timestampMs = next.timestampMs;
    }

    Json toJson() const { return Json(["eid": Json(eid), "timestampMs": Json(timestampMs)]); }

    static BncPlaybackCutoff fromJson(Json j) {
        if (j.type == Json.Type.undefined) return BncPlaybackCutoff.init;
        import std.exception : enforce;
        const e = j["eid"].get!long;
        const t = j["timestampMs"].get!long;
        enforce(e >= 0 && t >= 0, "Invalid BNC playback cutoff");
        return BncPlaybackCutoff(e, t);
    }
}

enum BncAutoClear { inherit, on, off }

/// Consumed playback is ordered by the delivered row, not the explicit-clear fence.
struct BncPlaybackConsumption {
    long timestampMs;
    long eid;

    bool active() const @safe pure nothrow @nogc { return timestampMs > 0 || eid > 0; }
    bool allows(long time, long eventId) const @safe pure nothrow @nogc {
        return !active() || time > timestampMs || (time == timestampMs && eventId > eid);
    }
    void advance(BncPlaybackConsumption next) @safe pure nothrow @nogc {
        if (allows(next.timestampMs, next.eid)) this = next;
    }
    Json toJson() const { return Json(["timestampMs": Json(timestampMs), "eid": Json(eid)]); }
    static BncPlaybackConsumption fromJson(Json j) {
        auto point = BncPlaybackCutoff.fromJson(j);
        return BncPlaybackConsumption(point.timestampMs, point.eid);
    }
}

struct BncPlaybackTarget {
    int lines = -1;
    BncPlaybackCutoff cleared;
    BncAutoClear autoClear;
    BncPlaybackConsumption consumed;
}

/// BNC view only. The web and explicit CHATHISTORY still use the archive.
struct BncPlaybackPolicy {
    BncPlaybackCutoff channelsCleared;
    BncPlaybackCutoff queriesCleared;
    BncPlaybackTarget[string] targets;

    bool active() const { return channelsCleared.active || queriesCleared.active || targets.length != 0; }

    Json toJson() const {
        import std.algorithm : sort;
        auto rows = Json.emptyArray;
        foreach (name; sort(targets.keys)) {
            const target = targets[name];
            rows ~= Json(["name": Json(name), "lines": Json(target.lines), "cleared": target.cleared.toJson(),
                "autoClear": Json(target.autoClear.to!string), "consumed": target.consumed.toJson()]);
        }
        return Json(["channelsCleared": channelsCleared.toJson(), "queriesCleared": queriesCleared.toJson(),
            "targets": rows]);
    }

    static BncPlaybackPolicy fromJson(Json j) {
        if (j.type == Json.Type.undefined) return BncPlaybackPolicy.init;
        import std.exception : enforce;
        BncPlaybackPolicy policy;
        policy.channelsCleared = BncPlaybackCutoff.fromJson(j["channelsCleared"]);
        policy.queriesCleared = BncPlaybackCutoff.fromJson(j["queriesCleared"]);
        const rows = j["targets"];
        enforce(rows.type == Json.Type.array, "Invalid BNC playback target list");
        foreach (row; rows) {
            const name = row["name"].get!string;
            const lines = row["lines"].get!long;
            enforce(name.length && name !in policy.targets && lines >= -1 && lines <= 1000,
                "Invalid BNC playback target");
            auto target = BncPlaybackTarget(cast(int) lines, BncPlaybackCutoff.fromJson(row["cleared"]));
            if (row["autoClear"].type != Json.Type.undefined) target.autoClear = row["autoClear"].get!string.to!BncAutoClear;
            target.consumed = BncPlaybackConsumption.fromJson(row["consumed"]);
            policy.targets[name] = target;
        }
        return policy;
    }
}

/// Inherit keeps pre-existing web-configured registration scripts active.
enum BncPerformState { inherit, loaded, unloaded }

enum BNC_CONTROL_NETWORK_FIELDS = ["altNick", "quitMessage", "bncNickRevision", "bncJoinDelaySeconds",
    "bncFloodIntervalMs", "bncFloodBurst", "bncUnsavedChannels", "bncChannelKeys", "bncChannelDefaultModes"];

/// Ordered records make the whole BSON value stable for conditional writes.
Json encodeBncStringMap(const string[string] values) {
    import std.algorithm : sort;
    auto rows = Json.emptyArray;
    foreach (key; sort(values.keys)) rows ~= Json(["name": Json(key), "value": Json(values[key])]);
    return rows;
}

/// Network configuration
struct NetworkConfig {
    /// The network ID
    UUID id;
    /// Internal immutable random identity, reserved atomically after insertion.
    /// Server/cache/control JSON only; browser responses redact this field.
    string ipv6Iid;
    /// The network name
    string name;
    /// The server host
    string host;
    /// The server port
    ushort port = 6667;
    /// The TLS mode
    TLSMode tls = TLSMode.enabled;
    /// The SASL mechanism
    SASLMechanism sasl = SASLMechanism.none;
    /// The SASL username
    string saslUsername;
    /// The SASL password
    string saslPassword;
    /// Oper credentials — sent as `OPER <operUsername> <operPassword>` after
    /// registration completes and BEFORE auto-join, so oper-only (+O) channels
    /// in the auto-join list are joinable. Empty (either field) disables it.
    /// Re-sent on every (re)connect. operPassword must be a single token: IRC
    /// OPER has no trailing parameter, so an embedded space truncates it.
    string operUsername;
    /// Oper password (see operUsername).
    string operPassword;
    /// Channels to auto-join
    string[] autoJoinChannels;
    /// Channels the user has parted (kept for inactive sidebar)
    string[] partedChannels;
    /// Reconnect suppression independent of saved intent or current membership.
    string[] disabledChannels;
    /// BNC presentation order, regardless of the website's sidebar ordering.
    string[] channelOrder;
    BncPlaybackPolicy bncPlayback;
    string altNick;
    string quitMessage;
    long bncNickRevision;
    uint bncJoinDelaySeconds;
    uint bncFloodIntervalMs;
    uint bncFloodBurst = 9;
    string[] bncUnsavedChannels;
    string[string] bncChannelKeys;
    string[string] bncChannelDefaultModes;
    /// The nick
    string nick;
    /// The real name
    string realName;
    /// IRC username sent as the first `USER` parameter (ZNC/ircd "ident").
    /// Empty — the default, and what every existing network has — means
    /// "use the nick", which is exactly what the engine sent before this
    /// field existed, so untouched networks register identically.
    string ident;
    /// Whether the network is disabled (admin-initiated disconnect that
    /// persists across redeploys). Disabled networks are not loaded
    /// during engine bootstrap and must be manually re-enabled.
    bool disabled = false;
    /// Initial signup only: held until a completed NickServ provisioning attempt.
    /// Independent of admin disable; absent on legacy networks means false.
    bool servicesProvisioningPending = false;
    /// NickServ password — sent as PRIVMSG NickServ :IDENTIFY <nspass> after connect
    string nspass;
    /// Commands to execute on connect (one per line, WAIT N supported for delays)
    string commands;
    BncPerformState bncPerformState;

    bool bncPerformLoaded() const @safe pure nothrow @nogc {
        return bncPerformState == BncPerformState.loaded
            || (bncPerformState == BncPerformState.inherit && commands.length != 0);
    }
    /// Seconds to wait after connecting before auto-JOINs are sent.
    /// Measured from the start of the registration handshake (≈ TCP
    /// connect). Some IRCds throttle JOIN until the client has been
    /// connected for a grace period — SuperNETs/DangerousIRCd rejects
    /// JOINs inside the first 5 seconds with 421 "You must be connected
    /// for at least 5 seconds before you can use this command". Setting
    /// this to 6 (or higher) waits out that window so the auto-joins
    /// land cleanly. 0 (default) preserves legacy behavior: JOIN is
    /// sent immediately after registration completes.
    uint autoJoinDelaySeconds = 0;
    /// Server password — sent as PASS <serverPass> before NICK/USER during registration
    string serverPass;
    /// The selected tuple occupies this index in the ordered ring. The
    /// remaining tuples are stored in order, without duplicating the scalar.
    BncServerEndpoint[] bncAlternateServers;
    uint bncSelectedServerIndex;
    /// Opt-in: exact leaf allowlist when nonempty, system PKI otherwise.
    bool verifyServerCertificates;
    string[] trustedServerFingerprints;
    /// Whether this network is provisioned by the platform (cannot be removed
    /// by the user via the API; admin tools can still override). The default
    /// IRC Fiber network is provisioned this way so every user has a working
    /// connection to the hosted IRC server out of the box.
    bool systemManaged = false;
    /// Saved route order and optional eligible VPN exit preference.
    /// Invalid stored values remain blocked rather than inheriting defaults.
    RoutingPreferences routing;
    /// Per-network avatar override; empty defers to `defaultAvatarUrl`.
    string avatarUrl = "";
    /// Denormalized copy of the owner's account default avatar, kept in
    /// sync so the engine can resolve the effective avatar without a
    /// round trip to Mongo.
    string defaultAvatarUrl = "";
    /// Denormalized copy of the owner's profile metadata (`PROFILE_KEYS`
    /// from `ircfiber.metadata`), kept in sync like `defaultAvatarUrl` so
    /// the engine can publish it on connect without a Mongo round trip.
    string[string] profileMetadata;
    /// Persisted MONITOR list; replayed by the engine after every reconnect.
    string[] monitoredNicks;
    /// Services trust configuration (provider, approved services server,
    /// per-service pins). Never holds credentials. Legacy networks decode to
    /// the default — automatic discovery, nothing trusted. The platform
    /// network's effective value is derived server-side
    /// (`ircfiber.services.config.effectiveServicesConfig`), never stored.
    ServicesConfig services;
    /// Avatar actually published: the override if set, else the default.
    string effectiveAvatarUrl() const @safe pure nothrow {
        return avatarUrl.length ? avatarUrl : defaultAvatarUrl;
    }

    bool hasUpstreamServer() const @safe pure nothrow @nogc {
        return host.length != 0 && port != 0;
    }

    BncServerEndpoint selectedBncServer() const @safe pure nothrow @nogc {
        return BncServerEndpoint(host, port, tls, serverPass);
    }

    BncServerEndpoint[] bncServers() const {
        if (!hasUpstreamServer()) return null;
        const i = bncSelectedServerIndex;
        auto servers = new BncServerEndpoint[bncAlternateServers.length + 1];
        servers[0 .. i] = bncAlternateServers[0 .. i];
        servers[i] = selectedBncServer();
        servers[i + 1 .. $] = bncAlternateServers[i .. $];
        return servers;
    }

    /// Updates the scalar and its ring together; an empty list parks the row.
    void selectBncServer(const BncServerEndpoint[] servers, uint index) {
        const endpoint = servers.length ? servers[index] : BncServerEndpoint.init;
        host = endpoint.host;
        port = endpoint.port;
        tls = endpoint.tls;
        serverPass = endpoint.serverPass;
        bncSelectedServerIndex = servers.length ? index : 0;
        bncAlternateServers = null;
        if (servers.length > 1) {
            bncAlternateServers = new BncServerEndpoint[servers.length - 1];
            bncAlternateServers[0 .. index] = servers[0 .. index];
            bncAlternateServers[index .. $] = servers[index + 1 .. $];
        }
    }

    Json bncAlternateServersJson() const {
        auto rows = Json.emptyArray;
        foreach (server; bncAlternateServers)
            rows ~= Json(["host": Json(server.host), "port": Json(server.port),
                "tls": Json(server.tls.to!string), "serverPass": Json(server.serverPass)]);
        return rows;
    }

    /// Shared reader for Mongo, the account cache and queued engine controls.
    /// Bad metadata is not silently reinterpreted as a different selection.
    void decodeBncServers(Json alternates, Json index) {
        import std.exception : enforce;
        if (alternates.type != Json.Type.undefined) {
            enforce(alternates.type == Json.Type.array, "Invalid alternate server array");
            foreach (row; alternates) {
                const host = row["host"].get!string;
                const port = row["port"].get!long;
                enforce(host.length && port > 0 && port <= ushort.max, "Invalid alternate server address");
                bncAlternateServers ~= BncServerEndpoint(host, cast(ushort) port,
                    row["tls"].get!string.to!TLSMode, row["serverPass"].get!string);
            }
        }
        if (index.type != Json.Type.undefined) {
            const position = index.get!long;
            enforce(position >= 0 && position <= bncAlternateServers.length
                && position <= uint.max, "Invalid selected server index");
            bncSelectedServerIndex = cast(uint) position;
        }
        enforce(hasUpstreamServer() || !bncAlternateServers.length, "Missing selected server");
    }

    void decodeBncTlsPolicy(Json verify, Json pins) {
        decodeServerCertificatePolicy(verify, pins, verifyServerCertificates, trustedServerFingerprints);
    }

    void decodeBncChannels(Json disabled, Json order) {
        if (disabled.type != Json.Type.undefined) disabledChannels = deserializeJson!(string[])(disabled);
        if (order.type != Json.Type.undefined) channelOrder = deserializeJson!(string[])(order);
    }

    void decodeBncControlField(string field)(Json j) {
        if (j.type == Json.Type.undefined) return;
        import std.exception : enforce;
        alias T = typeof(__traits(getMember, this, field));
        static if (is(T == string[string])) {
            enforce(j.type == Json.Type.array, "Invalid BNC channel settings map");
            string[string] values;
            foreach (i; 0 .. j.length) {
                auto row = j[i];
                const name = row["name"].get!string;
                enforce(name.length && name !in values, "Invalid BNC channel setting");
                values[name] = row["value"].get!string;
            }
            __traits(getMember, this, field) = values;
        } else static if (is(T == string[])) {
            __traits(getMember, this, field) = deserializeJson!(string[])(j);
        } else static if (is(T == string)) {
            __traits(getMember, this, field) = j.get!string;
        } else {
            const value = j.get!long;
            enum long minimum = field == "bncFloodBurst" ? 1 : 0;
            enum long maximum = field == "bncFloodBurst" ? 1000
                : field == "bncFloodIntervalMs" ? 60_000 : field == "bncJoinDelaySeconds" ? 65_535 : long.max;
            enforce(value >= minimum && value <= maximum, "Invalid BNC network setting");
            __traits(getMember, this, field) = cast(T) value;
        }
    }

    /// Do not construct credential-bearing alternate rows for public sync.
    Json toPublicJson() const {
        return serializeConfig(false);
    }

    /// Serialize to JSON
    Json toJson() const {
        return serializeConfig(true);
    }

    private Json serializeConfig(bool internal) const {
        auto json = Json([
            "id": Json(id.toString()),
            "ipv6Iid": Json(ipv6Iid),
            "name": Json(name),
            "host": Json(host),
            "port": Json(port),
            "tls": Json(tls.to!string),
            "sasl": Json(sasl.to!string),
            "saslUsername": Json(saslUsername),
            "saslPassword": Json(saslPassword),
            "operUsername": Json(operUsername),
            "operPassword": Json(operPassword),
            "autoJoinChannels": serializeToJson(autoJoinChannels),
            "partedChannels": serializeToJson(partedChannels),
            "nick": Json(nick),
            "realName": Json(realName),
            "ident": Json(ident),
            "disabled": Json(disabled),
            "servicesProvisioningPending": Json(servicesProvisioningPending),
            "nspass": Json(nspass),
            "commands": Json(commands),
            "serverPass": Json(serverPass),
            "systemManaged": Json(systemManaged),
            "autoJoinDelaySeconds": Json(autoJoinDelaySeconds),
            "routing": routing.valid ? routing.toJson() : Json(null),
            "avatarUrl": Json(avatarUrl),
            "defaultAvatarUrl": Json(defaultAvatarUrl),
            "profileMetadata": serializeToJson(profileMetadata),
            "monitoredNicks": serializeToJson(monitoredNicks),
            "services": services.toJson()
        ]);
        if (internal) {
            json["bncAlternateServers"] = bncAlternateServersJson();
            json["bncSelectedServerIndex"] = Json(bncSelectedServerIndex);
            json["verifyServerCertificates"] = Json(verifyServerCertificates);
            json["trustedServerFingerprints"] = serializeToJson(trustedServerFingerprints);
            json["disabledChannels"] = serializeToJson(disabledChannels);
            json["channelOrder"] = serializeToJson(channelOrder);
            json["bncPlayback"] = bncPlayback.toJson();
            json["bncPerformState"] = Json(bncPerformState.to!string);
            static foreach (field; BNC_CONTROL_NETWORK_FIELDS) {
                static if (field == "bncChannelKeys" || field == "bncChannelDefaultModes")
                    json[field] = encodeBncStringMap(__traits(getMember, this, field));
                else json[field] = serializeToJson(__traits(getMember, this, field));
            }
        }
        return json;
    }
}

/// Field key half used in `irc:lastseen`: "_server"/"" unchanged;
/// name[0]=='#' → toLower; anything else → RFC 1459 fold (A-Z→a-z, [→{,
/// ]→}, \→|, ^→~). Mirrors the frontend's `normalizeChannelName`
/// (`site/frontend/src/lib/utils.ts`) exactly — including its `^`→`~`
/// direction — so web, bouncer and engine write identical fields.
string lastSeenBufferKey(string name) @safe pure nothrow {
    if (name.length == 0 || name == "_server") return name;
    if (name[0] == '#') {
        try return toLower(name);
        catch (Exception) {
            // Invalid UTF-8: fall back to an ASCII-only lowercase.
        }
        auto lowered = appender!string();
        foreach (char c; name) lowered.put((c >= 'A' && c <= 'Z') ? cast(char)(c + 32) : c);
        return lowered.data;
    }
    auto folded = appender!string();
    foreach (char c; name) {
        if (c >= 'A' && c <= 'Z') folded.put(cast(char)(c + 32));
        else if (c == '[') folded.put('{');
        else if (c == ']') folded.put('}');
        else if (c == '\\') folded.put('|');
        else if (c == '^') folded.put('~');
        else folded.put(c);
    }
    return folded.data;
}

@("lastSeenBufferKey mirrors the frontend normalizeChannelName")
unittest {
    assert(lastSeenBufferKey("#Chan") == "#chan");
    assert(lastSeenBufferKey("Nick[x]") == "nick{x}");
    assert(lastSeenBufferKey("A\\B^") == "a|b~");
    assert(lastSeenBufferKey("#[Foo]") == "#[foo]");
    assert(lastSeenBufferKey("_server") == "_server");
    assert(lastSeenBufferKey("") == "");
}

/// Network state
struct Network {
    /// The network configuration
    NetworkConfig config;
    /// Whether connected
    bool isConnected;
    /// The connection status
    string status;
    /// The current nick
    string currentNick;
    
    /// Serialize to JSON
    Json toJson() const {
        auto j = config.toJson();
        j["connected"] = Json(isConnected);
        j["status"] = Json(status);
        j["currentNick"] = Json(currentNick);
        return j;
    }
}

@("NetworkConfig toJson includes expected fields")
unittest {
    NetworkConfig cfg;
    cfg.id = randomUUID();
    cfg.name = "Libera";
    cfg.host = "irc.libera.chat";
    cfg.port = 6697;
    cfg.tls = TLSMode.required;
    cfg.nick = "testnick";
    cfg.realName = "Test User";
    cfg.autoJoinChannels = ["#d", "#vibed"];
    cfg.autoJoinDelaySeconds = 6;

    auto json = cfg.toJson();
    assert(json["name"].get!string == "Libera");
    assert(json["host"].get!string == "irc.libera.chat");
    assert(json["port"].get!int == 6697);
    assert(json["tls"].get!string == "required");
    assert(json["nick"].get!string == "testnick");
    assert(json["autoJoinDelaySeconds"].get!int == 6);
    assert(json["profileMetadata"].type == Json.Type.object);
    assert(json["monitoredNicks"].type == Json.Type.array);
    // Legacy/new networks: automatic discovery, nothing pinned.
    assert(json["services"]["provider"].get!string == "auto");
    assert(json["services"]["server"].get!string == "");
    assert(json["services"]["pins"].length == 0);
}

@("sanitizeIdent keeps ident-safe bytes and caps length")
unittest {
    assert(sanitizeIdent("zodiac") == "zodiac");
    assert(sanitizeIdent("zod iac!") == "zodiac");
    assert(sanitizeIdent("averylongidentvalue").length == 10);
    assert(sanitizeIdent("  ") == "");
    assert(sanitizeIdent("a_b.c-d") == "a_b.c-d");
}

@("Network toJson merges config and state")
unittest {
    Network n;
    n.config.id = randomUUID();
    n.config.name = "TestNet";
    n.isConnected = true;
    n.status = "connected";
    n.currentNick = "mynick";

    auto json = n.toJson();
    assert(json["name"].get!string == "TestNet");
    assert(json["connected"].get!bool == true);
    assert(json["status"].get!string == "connected");
    assert(json["currentNick"].get!string == "mynick");
}
