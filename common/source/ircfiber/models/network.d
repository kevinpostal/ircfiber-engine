module ircfiber.models.network;

import std.algorithm : canFind, uniq, map, startsWith;
import std.array : array;
import std.string : strip;
import std.uuid;
import std.uni : toLower;
import vibe.data.json;
import std.conv;
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

/// Network configuration
struct NetworkConfig {
    /// The network ID
    UUID id;
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
    /// Channels to auto-join
    string[] autoJoinChannels;
    /// Channels the user has parted (kept for inactive sidebar)
    string[] partedChannels;
    /// The nick
    string nick;
    /// The real name
    string realName;
    /// Whether the network is disabled (admin-initiated disconnect that
    /// persists across redeploys). Disabled networks are not loaded
    /// during engine bootstrap and must be manually re-enabled.
    bool disabled = false;
    /// NickServ password — sent as PRIVMSG NickServ :IDENTIFY <nspass> after connect
    string nspass;
    /// Commands to execute on connect (one per line, WAIT N supported for delays)
    string commands;
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
    /// Whether this network is provisioned by the platform (cannot be removed
    /// by the user via the API; admin tools can still override). The default
    /// IRC Fiber network is provisioned this way so every user has a working
    /// connection to the hosted IRC server out of the box.
    bool systemManaged = false;
    /// Mullvad egress selection ("pin"). Grammar:
    ///   ""            automatic — any healthy exit slot, host-ban aware, direct last
    ///   "direct"      the host's own address, no SOCKS hop
    ///   "de"          country pin — any city in that country (2 letters, lower-case)
    ///   "de-ber"      city pin — `<countryCode>-<cityCode>`, lower-case
    ///   "de"          also the label of a *static* slot (see below)
    /// The engine resolves a country/city pin against its Mullvad location
    /// catalog and retargets a free exit slot to that location; a slot that is
    /// already serving live connections is never retargeted.
    ///
    /// A slot whose tailscaled the engine cannot reach (sidecars on another
    /// host — no control socket) has no readable location, so it is addressed
    /// by its IRCFIBER_MULLVAD_POOL label instead. Only such slots answer to
    /// a label, so a retargetable pool never has two names for one exit.
    string egressNodeId = "";
    /// Serialize to JSON
    Json toJson() const {
        return Json([
            "id": Json(id.toString()),
            "name": Json(name),
            "host": Json(host),
            "port": Json(port),
            "tls": Json(tls.to!string),
            "sasl": Json(sasl.to!string),
            "saslUsername": Json(saslUsername),
            "saslPassword": Json(saslPassword),
            "autoJoinChannels": serializeToJson(autoJoinChannels),
            "partedChannels": serializeToJson(partedChannels),
            "nick": Json(nick),
            "realName": Json(realName),
            "disabled": Json(disabled),
            "nspass": Json(nspass),
            "commands": Json(commands),
            "serverPass": Json(serverPass),
            "systemManaged": Json(systemManaged),
            "autoJoinDelaySeconds": Json(autoJoinDelaySeconds),
            "egressNodeId": Json(egressNodeId)
        ]);
    }
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
