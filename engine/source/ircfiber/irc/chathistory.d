module ircfiber.irc.chathistory;

import std.conv : to;

/**
 * Build a CHATHISTORY wire line per IRCv3 chathistory-3.4.
 *
 * Spec: https://ircv3.net/specs/extensions/chathistory
 *
 *   CHATHISTORY LATEST <target> <limit>
 *   CHATHISTORY BEFORE <msgid> <target> <limit>
 *   CHATHISTORY AFTER  <msgid> <target> <limit>
 *   CHATHISTORY AROUND <msgid> <target> <limit>
 *   CHATHISTORY BETWEEN <after-msgid>,<before-msgid> <target> <limit>
 *   CHATHISTORY TARGETS
 *
 * Returns the wire line, or `null` if the inputs are invalid.
 *
 * The `command` is case-insensitive on the way in (we normalize to
 * upper case). `limit` is clamped to [1, 1000] — most servers cap
 * around 100 but the spec leaves it open.
 */
string buildChathistoryLine(string command, string channel, string refMsgid, int limit) @safe {
    import std.uni : toUpper;
    if (limit <= 0) limit = 100;
    if (limit > 1000) limit = 1000;

    auto cmd = toUpper(command);
    final switch (cmd) {
        case "LATEST":
            if (channel.length == 0) return null;
            return "CHATHISTORY LATEST " ~ channel ~ " " ~ limit.to!string;
        case "BEFORE":
        case "AFTER":
        case "AROUND":
            if (channel.length == 0 || refMsgid.length == 0) return null;
            return "CHATHISTORY " ~ cmd ~ " " ~ refMsgid ~ " " ~ channel ~ " " ~ limit.to!string;
        case "BETWEEN":
            if (channel.length == 0 || refMsgid.length == 0) return null;
            // refMsgid is expected to be "after,before" — two msgids
            // comma-separated. The engine consumer hands us this
            // string verbatim, so we just slot it in.
            return "CHATHISTORY BETWEEN " ~ refMsgid ~ " " ~ channel ~ " " ~ limit.to!string;
        case "TARGETS":
            return "CHATHISTORY TARGETS";
    }
}

/// Parse a chathistory command payload of the form
///   "<channel>:<COMMAND>:<refMsgid>:<limit>"
/// Returns a tuple of (channel, command, refMsgid, limit). If the
/// payload is malformed, `channel` is empty.
struct ChathistoryPayload {
    string channel;
    string command;
    string refMsgid;
    int    limit;
}

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

@("LATEST line is built without a ref msgid")
unittest {
    auto line = buildChathistoryLine("LATEST", "#channel", "", 100);
    assert(line == "CHATHISTORY LATEST #channel 100", line);
}

@("LATEST accepts lowercase command")
unittest {
    auto line = buildChathistoryLine("latest", "#channel", "", 50);
    assert(line == "CHATHISTORY LATEST #channel 50", line);
}

@("BEFORE includes ref msgid between command and channel")
unittest {
    auto line = buildChathistoryLine("BEFORE", "#channel", "abc123", 25);
    assert(line == "CHATHISTORY BEFORE abc123 #channel 25", line);
}

@("AFTER includes ref msgid between command and channel")
unittest {
    auto line = buildChathistoryLine("AFTER", "#channel", "abc123", 25);
    assert(line == "CHATHISTORY AFTER abc123 #channel 25", line);
}

@("AROUND includes ref msgid between command and channel")
unittest {
    auto line = buildChathistoryLine("AROUND", "#channel", "abc123", 25);
    assert(line == "CHATHISTORY AROUND abc123 #channel 25", line);
}

@("BETWEEN ref msgid is a comma-separated pair")
unittest {
    auto line = buildChathistoryLine("BETWEEN", "#channel", "after,before", 50);
    assert(line == "CHATHISTORY BETWEEN after,before #channel 50", line);
}

@("TARGETS doesn't need a channel or ref msgid")
unittest {
    auto line = buildChathistoryLine("TARGETS", "", "", 0);
    assert(line == "CHATHISTORY TARGETS", line);
}

@("Limit is clamped to [1, 1000]")
unittest {
    assert(buildChathistoryLine("LATEST", "#x", "", 0) == "CHATHISTORY LATEST #x 100");
    assert(buildChathistoryLine("LATEST", "#x", "", -5) == "CHATHISTORY LATEST #x 100");
    assert(buildChathistoryLine("LATEST", "#x", "", 99999) == "CHATHISTORY LATEST #x 1000");
    assert(buildChathistoryLine("LATEST", "#x", "", 1) == "CHATHISTORY LATEST #x 1");
    assert(buildChathistoryLine("LATEST", "#x", "", 1000) == "CHATHISTORY LATEST #x 1000");
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
    auto p = parseChathistoryPayload("#chan:BEFORE:abc123:50");
    assert(p.channel == "#chan", p.channel);
    assert(p.command == "BEFORE", p.command);
    assert(p.refMsgid == "abc123", p.refMsgid);
    assert(p.limit == 50, p.limit.to!string);
}

@("parseChathistoryPayload defaults limit to 100 when missing")
unittest {
    auto p = parseChathistoryPayload("#chan:LATEST:");
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
    auto p = parseChathistoryPayload("only:two");
    assert(p.channel.length == 0, p.channel);
}
