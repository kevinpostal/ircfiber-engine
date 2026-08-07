module ircfiber.irc.parser;

import std.array : join;
import std.string : indexOf, startsWith, split;
import std.uuid : parseUUID;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : NetworkConfig;

/// Parse a single IRC protocol line into an IRCRawEvent.
///
/// The line format (RFC 2812 + IRCv3 message-tags):
///
///     [@tags] [:prefix] command [param1 param2 ...] [:trailing]
///
/// Examples:
///     @time=2024-01-01T00:00:00.000Z :Alice!alice@host PRIVMSG #chan :hello
///     PING :server
///     :server 001 Nick :Welcome to the IRC Network
///
/// The parser populates network, networkId, command, params, prefix,
/// nick, hostmask, tags, and (best-effort) channel/text fields. The
/// engine applies business logic on top (channel user lists, realname
/// caching, msgid correlation, etc.).
///
/// Pure function — no global state, no I/O. Safe to call from any
/// fiber.

/// Extract the prefix symbols from an ISUPPORT PREFIX value.
///
/// ISUPPORT sends `PREFIX=(qaohv)~&@%+` where the part before `)` is the
/// mode letters and the part after `)` is the corresponding prefix symbols
/// displayed before nicknames. This function extracts the symbol portion.
///
/// Params:
///   prefixToken = raw PREFIX value (e.g. `(qaohv)~&@%+` or `(ov)@+`)
///
/// Returns:
///   The symbol string (e.g. `~&@%+` or `@+`), or empty string if the
///   input is not in the expected `(modechars)symbols` format.
public string parseIsupportPrefix(string prefixToken) {
    if (prefixToken.length == 0 || prefixToken[0] != '(') return "";
    auto close = prefixToken.indexOf(")");
    if (close < 0 || close + 1 >= prefixToken.length) return "";
    return prefixToken[close + 1 .. $];
}

public IRCRawEvent parseIRCLinePublic(string line, NetworkConfig config) {
    import std.algorithm : filter;
    import std.array : array;
    import std.conv : to;
    import ircfiber.logging : logJsonMap;

    IRCRawEvent event = IRCRawEvent(config.name, "");
    event.networkId = config.id.toString();

    // ── Defensive guards ─────────────────────────────────────────────
    // Goal: never throw on attacker-controlled input. Drop NUL bytes,
    // cap length to 8 KiB (16× the RFC 1459 limit), bail to a safe
    // empty event for empty/whitespace-only lines.

    // Strip NUL bytes — they confuse both downstream D code and any C
    // bridge that the frontend uses. `to!string` correctly encodes the
    // dchar[] as UTF-8 (a `cast(string)` reinterpret would treat each
    // dchar's 32-bit code unit as raw bytes, corrupting the data).
    if (line.indexOf('\0') >= 0) {
        line = to!string(line.filter!(c => c != '\0').array);
    }

    // Cap input length. RFC 2812 limits lines to 512 bytes including
    // CRLF; we cap at 8 KiB to allow long MOTDs and CAP LS values
    // while still bounding memory under hostile input.
    enum MAX_LINE_LEN = 8 * 1024;
    if (line.length > MAX_LINE_LEN) {
        logJsonMap("warn", "protocol",
            "IRC line exceeded defensive cap — truncating",
            [
                "network": config.name,
                "networkId": config.id.toString(),
                "length": line.length.to!string,
                "event": "line_too_long"
            ]);
        line = line[0 .. MAX_LINE_LEN];
    }

    if (line.length == 0) {
        // Empty line — return safe empty event.
        return event;
    }

    // ── Tags ─────────────────────────────────────────────────────────
    // @key=value;key2=value2 [...]
    if (line.startsWith("@")) {
        auto space = line.indexOf(" ");
        if (space > 0) {
            auto tagStr = line[1 .. space];
            line        = line[space + 1 .. $];
            foreach (tag; tagStr.split(";")) {
                if (tag.length == 0) continue;
                auto eq = tag.indexOf("=");
                if (eq > 0) {
                    event.addTag(tag[0 .. eq], tag[eq + 1 .. $]);
                } else {
                    // Valueless tag — record as present with empty value.
                    event.addTag(tag, "");
                }
            }
        } else {
            // Malformed tag block ("@" with no terminating space). Drop
            // the tag entirely and continue — better than throwing or
            // swallowing the entire line.
            line = line[1 .. $];
            if (line.length == 0) return event;
        }
    }

    // ── Prefix ───────────────────────────────────────────────────────
    // :nick!user@host  (or just :nick)
    if (line.startsWith(":")) {
        auto space = line.indexOf(" ");
        if (space > 0) {
            event.prefix = line[1 .. space];
            line         = line[space + 1 .. $];
            auto excl    = event.prefix.indexOf("!");
            if (excl > 0) {
                event.nick     = event.prefix[0 .. excl];
                event.hostmask = event.prefix[excl + 1 .. $];
            } else {
                // No user/host in prefix — the whole prefix is the nick.
                event.nick = event.prefix;
            }
        } else {
            // Malformed prefix (just ":" with no command after). Drop
            // it and continue; the subsequent "parts" pass will see an
            // empty line and return event with empty command.
            line = line[1 .. $];
        }
    }

    // ── Trailing parameter ───────────────────────────────────────────
    string trailing;
    auto colon = line.indexOf(" :");
    if (colon >= 0) {
        trailing = line[colon + 2 .. $];
        line     = line[0 .. colon];
    }

    auto parts = line.split(" ");
    if (parts.length > 0) {
        event.command = parts[0];
        if (parts.length > 1) event.setParams(parts[1 .. $]);
    }

    if (trailing.length > 0) {
        auto params = event.getParams();
        params ~= trailing;
        event.setParams(params);
        event.text = trailing;
    }

    // RPL_ISUPPORT (005): the trailing "are supported by this server"
    // is RFC 2812 §5.1.4 boilerplate, not useful as msg.text. Servers
    // typically send ISUPPORT as multiple 005 replies, each carrying a
    // subset of tokens plus the same trailing — so without this override
    // every 005 in the `_server` log renders as the trailer three times
    // and the actual tokens (CHANTYPES=#, EXCEPTS, KICKLEN, …) are
    // hidden inside msg.params that numericBody() never reads.
    //
    // Rewrite event.text to the joined ISUPPORT tokens (skip the user's
    // nick at params[0] and the exact canonical trailer) so the server
    // log shows real ISUPPORT data instead of three copies of the
    // trailer. We use an exact-match check for the RFC trailer so
    // near-variants ("are supported by my server", "supported by this
    // server") are preserved as legitimate tokens rather than stripped.
    if (event.command == "005") {
        auto p = event.getParams();
        if (p.length > 1) {
            string[] tokens;
            foreach (idx, tok; p) {
                if (idx == 0) continue;
                if (idx + 1 == p.length && tok == "are supported by this server")
                    continue;
                tokens ~= tok;
            }
            // Empty tokens → no real ISUPPORT data was delivered (just
            // the boilerplate trailer). Clear text so the _server log
            // doesn't render the placeholder either.
            event.text = tokens.length > 0 ? tokens.join(" ") : "";
        } else {
            event.text = "";
        }
    }

    // ── Channel derivation ───────────────────────────────────────────
    auto params = event.getParams();
    if (params.length > 0 && params[0].startsWith("#")) {
        event.channel = params[0];
    }
    if (event.command == "353" && params.length >= 3 && params[2].startsWith("#")) {
        event.channel = params[2];
    }
    if (event.command == "332" && params.length >= 2 && params[1].startsWith("#")) {
        event.channel = params[1];
    }
    if (event.command == "366" && params.length >= 2 && params[1].startsWith("#")) {
        event.channel = params[1];
    }
    if (event.command == "PRIVMSG" && params.length > 0 && !params[0].startsWith("#")) {
        event.channel = event.nick.length ? event.nick : params[0];
    }
    // JOIN error numerics (471, 473, etc.) carry the target channel as
    // a non-leading parameter.
    if (event.channel.length == 0) {
        foreach (p; params) {
            if (p.length > 0 && p[0] == '#') { event.channel = p; break; }
        }
    }

    return event;
}

/// Try to extract a countdown value from an RPL_TRYAGAIN (263) event.
/// Returns `defaultMs` when the command is 263 but no explicit countdown
/// can be parsed. Returns 0 if the command is not 263 at all.
///
/// RPL_TRYAGAIN format (non-standard): some IRCds include a countdown in
/// seconds as the third param, others embed it in the message text as
/// "try again in N seconds".
public int extractTempUnavailableCountdown(const ref IRCRawEvent event, int defaultMs = 30000) {
    if (event.command != "263") return 0;
    auto params = event.getParams();
    // Some IRCds send countdown as seconds in params[2]
    if (params.length >= 3) {
        import std.conv : to;
        string candidate = params[2];
        // Ensure it looks numeric before trying to parse
        if (candidate.length > 0 && candidate[0] >= '0' && candidate[0] <= '9') {
            try return candidate.to!int * 1000;
            catch (Exception) {}
        }
    }
    // Try to extract from message text
    if (event.text.length > 0) {
        import std.regex : regex, matchFirst;
        auto m = matchFirst(event.text, regex(`(\d+)\s*seconds?`, "i"));
        if (m) {
            import std.conv : to;
            try return m[1].to!int * 1000;
            catch (Exception) {}
        }
    }
    return defaultMs;
}

/// Convenience: same as `parseIRCLinePublic` but takes the network
/// name and ID as separate arguments (avoids constructing a full
/// NetworkConfig when the caller already has these primitives).
public IRCRawEvent parseIRCLineNamed(string line, string networkName, string networkId) {
    import std.uuid : UUID;
    import ircfiber.models.network : NetworkConfig;
    NetworkConfig cfg;
    cfg.name = networkName;
    try cfg.id = parseUUID(networkId);
    catch (Exception) {}
    return parseIRCLinePublic(line, cfg);
}