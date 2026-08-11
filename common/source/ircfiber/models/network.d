module ircfiber.models.network;

import std.algorithm : canFind, uniq, map, startsWith;
import std.array : array;
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
    required
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

/// Deduplicate and normalize a list of IRC channel names.
/// Case-insensitive: "#Zod" and "#ZOD" collapse to one entry.
string[] dedupChannels(string[] channels) @safe {
    if (channels.length == 0) return channels;
    string[] outArr;
    bool[string] seen;
    foreach (ch; channels) {
        auto norm = normalizeChannelName(ch);
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
    /// Mullvad egress selection: "" = random from healthy pool,
    /// else label like "se" / "us" pinning to a specific sidecar SOCKS proxy.
    /// Maps to IRCFIBER_MULLVAD_POOL entries.
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
