module ircfiber.irc.chathistory;

import std.conv : to;

/**
 * Build a CHATHISTORY wire line per the ratified IRCv3 chathistory spec.
 *
 * Spec: https://ircv3.net/specs/extensions/chathistory
 *
 *   CHATHISTORY LATEST  <target> <selector|*> <limit>
 *   CHATHISTORY BEFORE  <target> <selector> <limit>
 *   CHATHISTORY AFTER   <target> <selector> <limit>
 *   CHATHISTORY AROUND  <target> <selector> <limit>
 *   CHATHISTORY BETWEEN <target> <selector> <selector> <limit>
 *   CHATHISTORY TARGETS <selector> <selector> <limit>
 *
 * A selector is `msgid=<id>` or `timestamp=<server-time>`; `*` means
 * unbounded and is only valid for LATEST.
 *
 * This used to emit the abandoned 3.3 draft ordering — selector before
 * target (`CHATHISTORY BEFORE <msgid> <target> <limit>`) and no selector
 * at all on LATEST. Every modern server (ergo, soju, InspIRCd, and IRC
 * Fiber's own bouncer in `bnc/wire.d`, which parses `*` / `timestamp=` /
 * `msgid=`) rejects that with `FAIL CHATHISTORY INVALID_PARAMS`. It went
 * unnoticed because the engine requested a capability name no server
 * offers (`chathistory` instead of `draft/chathistory`), so this builder
 * was unreachable.
 *
 * Returns the wire line, or `null` if the inputs are invalid.
 *
 * `command` is case-insensitive on the way in (normalized to upper case).
 * `refMsgid` may be a bare msgid (wrapped as `msgid=…`), an already
 * qualified `msgid=`/`timestamp=` selector, or `*`. BETWEEN and TARGETS
 * take a comma-separated pair. `limit` is clamped to [1, 1000].
 */
string buildChathistoryLine(string command, string channel, string refMsgid, int limit) @safe {
    import std.uni : toUpper;
    if (limit <= 0) limit = 100;
    if (limit > 1000) limit = 1000;

    auto cmd = toUpper(command);
    final switch (cmd) {
        case "LATEST":
            if (channel.length == 0) return null;
            // No cursor means "the newest <limit> messages" — `*`.
            const sel = refMsgid.length ? selector(refMsgid) : "*";
            return "CHATHISTORY LATEST " ~ channel ~ " " ~ sel ~ " " ~ limit.to!string;
        case "BEFORE":
        case "AFTER":
        case "AROUND":
            if (channel.length == 0 || refMsgid.length == 0) return null;
            return "CHATHISTORY " ~ cmd ~ " " ~ channel ~ " " ~ selector(refMsgid)
                ~ " " ~ limit.to!string;
        case "BETWEEN": {
            if (channel.length == 0) return null;
            auto pair = selectorPair(refMsgid);
            if (pair[0].length == 0) return null;
            return "CHATHISTORY BETWEEN " ~ channel ~ " " ~ pair[0] ~ " " ~ pair[1]
                ~ " " ~ limit.to!string;
        }
        case "TARGETS": {
            // TARGETS is bounded by two timestamps; there is no valid
            // bare form, so refuse rather than emit a line the server
            // answers with FAIL.
            auto pair = selectorPair(refMsgid);
            if (pair[0].length == 0) return null;
            return "CHATHISTORY TARGETS " ~ pair[0] ~ " " ~ pair[1] ~ " " ~ limit.to!string;
        }
    }
}

/// Qualifies a bare reference as a `msgid=` selector. Values that already
/// carry a selector kind (`msgid=`, `timestamp=`) or are `*` pass through.
private string selector(string ref_) @safe {
    import std.algorithm : startsWith;
    if (ref_ == "*") return ref_;
    if (ref_.startsWith("msgid=") || ref_.startsWith("timestamp=")) return ref_;
    return "msgid=" ~ ref_;
}

/// Splits a `<a>,<b>` reference pair into two selectors. Returns two
/// empty strings when the input is not a pair.
private string[2] selectorPair(string refs) @safe {
    import std.string : indexOf;
    string[2] out_;
    const comma = refs.indexOf(",");
    if (comma <= 0 || comma + 1 >= refs.length) return out_;
    out_[0] = selector(refs[0 .. comma]);
    out_[1] = selector(refs[comma + 1 .. $]);
    return out_;
}

/// Parse a chathistory command payload of the form
///   "<channel>:<COMMAND>:<refMsgid>:<limit>"
/// Returns a tuple of (channel, command, refMsgid, limit). If the
/// payload is malformed, `channel` is empty.
struct ChathistoryPayload {
    /// Channel the history request targets.
    string channel;
    /// Chathistory sub-command (LATEST, BEFORE, AFTER, AROUND, BETWEEN, TARGETS).
    string command;
    /// Reference message id (or comma-separated pair for BETWEEN).
    string refMsgid;
    /// Maximum number of messages to return, clamped to [1, 1000].
    int    limit;
}

/// Parses a `channel:command:refMsgid:limit` payload into a `ChathistoryPayload`.
ChathistoryPayload parseChathistoryPayload(string text) @safe {
    ChathistoryPayload p;
    string[] parts;
    size_t prev = 0;
    foreach (i, ch; text) {
        if (ch == ':') { parts ~= text[prev .. i]; prev = i + 1; }
    }
    parts ~= text[prev .. $];
    if (parts.length < 3) return p;
    p.channel = parts[0];
    p.command = parts[1];
    p.refMsgid = parts[2];
    p.limit    = parts.length >= 4 ? parseLimit(parts[3]) : 100;
    return p;
}

private int parseLimit(string s) @safe {
    import std.conv : to;
    try {
        auto n = s.to!int;
        if (n <= 0) return 100;
        if (n > 1000) return 1000;
        return n;
    } catch (Exception) {
        return 100;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

@("LATEST with no cursor selects the unbounded newest window")
unittest {
    const line = buildChathistoryLine("LATEST", "#channel", "", 100);
    assert(line == "CHATHISTORY LATEST #channel * 100", line);
}

@("LATEST accepts lowercase command")
unittest {
    const line = buildChathistoryLine("latest", "#channel", "", 50);
    assert(line == "CHATHISTORY LATEST #channel * 50", line);
}

@("LATEST with a cursor qualifies it as a msgid selector")
unittest {
    const line = buildChathistoryLine("LATEST", "#channel", "abc123", 50);
    assert(line == "CHATHISTORY LATEST #channel msgid=abc123 50", line);
}

@("BEFORE puts the target first, then the selector")
unittest {
    const line = buildChathistoryLine("BEFORE", "#channel", "abc123", 25);
    assert(line == "CHATHISTORY BEFORE #channel msgid=abc123 25", line);
}

@("AFTER puts the target first, then the selector")
unittest {
    const line = buildChathistoryLine("AFTER", "#channel", "abc123", 25);
    assert(line == "CHATHISTORY AFTER #channel msgid=abc123 25", line);
}

@("AROUND puts the target first, then the selector")
unittest {
    const line = buildChathistoryLine("AROUND", "#channel", "abc123", 25);
    assert(line == "CHATHISTORY AROUND #channel msgid=abc123 25", line);
}

@("An already-qualified selector is passed through untouched")
unittest {
    const ts = buildChathistoryLine("BEFORE", "#c", "timestamp=2026-09-07T03:00:00.000Z", 10);
    assert(ts == "CHATHISTORY BEFORE #c timestamp=2026-09-07T03:00:00.000Z 10", ts);
    const mid = buildChathistoryLine("AFTER", "#c", "msgid=xyz", 10);
    assert(mid == "CHATHISTORY AFTER #c msgid=xyz 10", mid);
}

@("BETWEEN expands a comma pair into two selectors after the target")
unittest {
    const line = buildChathistoryLine("BETWEEN", "#channel", "aaa,bbb", 50);
    assert(line == "CHATHISTORY BETWEEN #channel msgid=aaa msgid=bbb 50", line);
}

@("BETWEEN refuses a single reference")
unittest {
    assert(buildChathistoryLine("BETWEEN", "#channel", "aaa", 50) is null);
}

@("TARGETS requires a bounded window")
unittest {
    // The bare `CHATHISTORY TARGETS` this used to emit is not a valid
    // wire form — the server answers FAIL. Refuse it instead.
    assert(buildChathistoryLine("TARGETS", "", "", 0) is null);
    const line = buildChathistoryLine("TARGETS", "",
        "timestamp=2026-09-01T00:00:00.000Z,timestamp=2026-09-07T00:00:00.000Z", 20);
    assert(line == "CHATHISTORY TARGETS timestamp=2026-09-01T00:00:00.000Z"
        ~ " timestamp=2026-09-07T00:00:00.000Z 20", line);
}

@("Limit is clamped to [1, 1000]")
unittest {
    assert(buildChathistoryLine("LATEST", "#x", "", 0) == "CHATHISTORY LATEST #x * 100");
    assert(buildChathistoryLine("LATEST", "#x", "", -5) == "CHATHISTORY LATEST #x * 100");
    assert(buildChathistoryLine("LATEST", "#x", "", 99_999) == "CHATHISTORY LATEST #x * 1000");
    assert(buildChathistoryLine("LATEST", "#x", "", 1) == "CHATHISTORY LATEST #x * 1");
    assert(buildChathistoryLine("LATEST", "#x", "", 1000) == "CHATHISTORY LATEST #x * 1000");
}

@("BEFORE/AFTER/AROUND refuse empty ref msgid")
unittest {
    assert(buildChathistoryLine("BEFORE", "#x", "", 50) is null);
    assert(buildChathistoryLine("AFTER",  "#x", "", 50) is null);
    assert(buildChathistoryLine("AROUND", "#x", "", 50) is null);
}

@("Empty channel returns null for channel-bearing commands")
unittest {
    assert(buildChathistoryLine("LATEST", "", "", 50) is null);
}

@("Unknown command throws (final switch is exhaustive)")
unittest {
    // The final switch in buildChathistoryLine doesn't have a default
    // case, so an unknown command raises a D SwitchError. The engine
    // catches that and logs a warning — we just want the function to
    // fail loudly rather than silently emit a malformed wire line.
    import core.exception : SwitchError;
    import std.exception : assertThrown;
    assertThrown!SwitchError(buildChathistoryLine("FOO", "#x", "", 50));
}

@("parseChathistoryPayload splits on colons")
unittest {
    const p = parseChathistoryPayload("#chan:BEFORE:abc123:50");
    assert(p.channel == "#chan", p.channel);
    assert(p.command == "BEFORE", p.command);
    assert(p.refMsgid == "abc123", p.refMsgid);
    assert(p.limit == 50, p.limit.to!string);
}

@("parseChathistoryPayload defaults limit to 100 when missing")
unittest {
    const p = parseChathistoryPayload("#chan:LATEST:");
    assert(p.channel == "#chan", p.channel);
    assert(p.command == "LATEST", p.command);
    assert(p.refMsgid == "", p.refMsgid);
    assert(p.limit == 100, p.limit.to!string);
}

@("parseChathistoryPayload clamps and validates limit")
unittest {
    auto p = parseChathistoryPayload("#chan:LATEST::0");
    assert(p.limit == 100, p.limit.to!string);

    p = parseChathistoryPayload("#chan:LATEST::99999");
    assert(p.limit == 1000, p.limit.to!string);

    p = parseChathistoryPayload("#chan:LATEST::not-a-number");
    assert(p.limit == 100, p.limit.to!string);
}

@("parseChathistoryPayload handles malformed input")
unittest {
    const p = parseChathistoryPayload("only:two");
    assert(p.channel.length == 0, p.channel);
}
