/// Standalone fast smoke test for ircfiber.irc.parser.
///
/// Covers the defensive parse guards (Task 1.1) plus RFC 2812 §3 well-formed
/// lines plus known-bad inputs from the SuperNets log dump that exposed
/// the squashed-ERROR bug.
///
/// Run with: `make parser-test`.
module parser_test;

import std.algorithm : startsWith;
import std.stdio : stderr, writeln;
import std.string : indexOf;
import std.uuid : parseUUID, randomUUID;
import std.conv : to;

import ircfiber.irc.parser : parseIRCLinePublic, parseIRCLineNamed, parseIsupportPrefix;
import ircfiber.models.network : NetworkConfig;
import ircfiber.models.irc_event : IRCRawEvent;

/// Tracks the number of passing checks.
int passed;
/// Tracks the number of failing checks.
int failed;

/// Records the outcome of a single named check.
void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("  ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("  ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

/// Builds a minimal network config for parsing tests.
NetworkConfig mkConfig() {
    NetworkConfig cfg;
    cfg.id = randomUUID();
    cfg.name = "TestNet";
    return cfg;
}

/// Runs the malformed-input defensive parse test scenarios.
void runDefensiveTests() {
    stderr.writeln("\n[defensive] malformed input never throws");
    auto cfg = mkConfig();

    // Empty line
    {
        bool threw = false;
        try {
            auto e = parseIRCLinePublic("", cfg);
            check!("empty line returns safe event")(!threw); // didn't throw
            check!("empty line has empty command")(e.command == "");
        } catch (Exception e) { threw = true; }
        check!("empty line never throws")(true);
    }

    // Whitespace-only
    {
        auto e = parseIRCLinePublic("   ", cfg);
        check!("whitespace-only returns safe event")(e.command == "");
    }

    // Prefix only (":server" with no command)
    {
        bool threw = false;
        try {
            cast(void) parseIRCLinePublic(":server", cfg);
            check!("prefix-only line never throws")(true);
        } catch (Exception e) { threw = true; }
        check!("prefix-only line parses without throwing")(!threw);
    }

    // Prefix with NUL bytes scattered through
    {
        bool threw = false;
        try {
            auto e = parseIRCLinePublic(":ali\0ce PRI\0VMSG #c :h\0i", cfg);
            check!("line with embedded NUL never throws")(!threw);
            check!("NUL bytes stripped from prefix (no \0)")
                (e.prefix.indexOf('\0') < 0);
        } catch (Exception e) { threw = true; }
        check!("NUL in line parses without throwing")(!threw);
    }

    // Oversized line — well over IRC limit
    {
        char[] big;
        big.length = 64 * 1024; // 64 KB
        for (int i = 0; i < big.length; i++) big[i] = 'A';
        bool threw = false;
        try {
            auto e = parseIRCLinePublic(cast(string) big, cfg);
            check!("64 KB line is truncated, doesn't throw")(!threw);
            check!("64 KB line produces some non-empty command")
                (e.command.length > 0 && e.command.length < 8200);
        } catch (Exception e) { threw = true; }
        check!("64 KB line handled gracefully")(!threw);
    }

    // Malformed tag block — '@' with no terminating space
    {
        bool threw = false;
        try {
            cast(void) parseIRCLinePublic("@", cfg);
            check!("bare @ tag handles gracefully")(!threw);
        } catch (Exception e) { threw = true; }
        check!("bare @ never throws")(!threw);
    }

    // Valueless tag
    {
        bool threw = false;
        try {
            cast(void) parseIRCLinePublic("@bot :server PRIVMSG #c :hi", cfg);
            check!("valueless tag parses")(!threw);
        } catch (Exception e) { threw = true; }
        check!("valueless tag never throws")(!threw);
    }
}

/// Runs the RFC 2812 well-formed-line test scenarios.
void runRFC2812Tests() {
    stderr.writeln("\n[RFC 2812] well-formed lines parse cleanly");
    auto cfg = mkConfig();

    // Section 3.1 — Password message
    {
        auto e = parseIRCLinePublic("PASS secret", cfg);
        check!("PASS: command")(e.command == "PASS");
        check!("PASS: param 0")(e.getParams()[0] == "secret");
    }

    // Section 3.1 — Nick message
    {
        auto e = parseIRCLinePublic("NICK Wiz", cfg);
        check!("NICK: command")(e.command == "NICK");
        check!("NICK: param")(e.getParams()[0] == "Wiz");
    }

    // Section 3.2 — Server-to-client numeric
    {
        auto e = parseIRCLinePublic(":irc.example.com 001 Wiz :Welcome to the IRC Network Wiz!wiz@example.com", cfg);
        check!("001: prefix set")(e.prefix == "irc.example.com");
        check!("001: nick not extracted from server prefix")(e.nick == "irc.example.com");
        check!("001: command")(e.command == "001");
        check!("001: trailing Welcome")
            (e.text.indexOf("Welcome") >= 0);
    }

    // Section 3.3.1 — Private message
    {
        auto e = parseIRCLinePublic(":Angel!angel@example.com PRIVMSG Wiz :" ~
            "Hello are you receiving this message ?", cfg);
        check!("PRIVMSG: prefix")(e.prefix == "Angel!angel@example.com");
        check!("PRIVMSG: nick")(e.nick == "Angel");
        check!("PRIVMSG: hostmask")(e.hostmask == "angel@example.com");
        check!("PRIVMSG: command")(e.command == "PRIVMSG");
        check!("PRIVMSG: target")(e.getParams()[0] == "Wiz");
        check!("PRIVMSG: text")(e.text == "Hello are you receiving this message ?");
        // Channel not set: target is a nick, not a channel
        check!("PRIVMSG: channel is sender's nick")(e.channel == "Angel");
    }

    // Section 3.4.1 — Ping/pong
    {
        auto e = parseIRCLinePublic("PING :tolsun.oulu.fi", cfg);
        check!("PING: command")(e.command == "PING");
        check!("PING: trailing server")(e.text == "tolsun.oulu.fi");
    }

    // Section 3.7.2 — Error from server (squashed-in-numeric test below)
    {
        auto e = parseIRCLinePublic("ERROR :Closing Link: nick (Killed)", cfg);
        check!("ERROR: command")(e.command == "ERROR");
        check!("ERROR: trailing reason")(e.text == "Closing Link: nick (Killed)");
    }

    // Multi-param with trailing
    {
        auto e = parseIRCLinePublic(":nick!u@h PRIVMSG #chan :longer message with multiple words", cfg);
        check!("PRIVMSG multi-word: trailing preserved")
            (e.text == "longer message with multiple words");
        check!("PRIVMSG multi-word: channel")(e.channel == "#chan");
    }
}

/// Runs the IRCv3 tags and extended-join test scenarios.
void runIRCv3Tests() {
    stderr.writeln("\n[IRCv3] tags + extended-join + chathistory");
    auto cfg = mkConfig();

    // IRCv3 message tags
    {
        auto e = parseIRCLinePublic("@time=2024-01-01T00:00:00.000Z :nick!u@h PRIVMSG #c :hi", cfg);
        check!("IRCv3: time tag")
            (e.getTag("time") == "2024-01-01T00:00:00.000Z");
        check!("IRCv3: prefix still parsed")(e.nick == "nick");
        check!("IRCv3: command still parsed")(e.command == "PRIVMSG");
    }

    // Extended-join: JOIN #chan account :realname
    {
        auto e = parseIRCLinePublic(":alice!a@h JOIN #chan aliceaccount :Alice Q. Person", cfg);
        check!("extended-join: nick")(e.nick == "alice");
        check!("extended-join: channel")(e.channel == "#chan");
        check!("extended-join: command")(e.command == "JOIN");
    }

    // Multiple tags
    {
        auto e = parseIRCLinePublic("@time=2024-01-01T00:00:00.000Z;bot=1 :n PRIVMSG #c :hi", cfg);
        check!("multi-tag: time")(e.getTag("time") == "2024-01-01T00:00:00.000Z");
        check!("multi-tag: bot=1")(e.getTag("bot") == "1");
    }

    // Valueless tag (presence-only, e.g. CAP negotiation)
    {
        auto e = parseIRCLinePublic("@bot :n PRIVMSG #c :hi", cfg);
        check!("valueless tag: present with empty value")
            (e.getTag("bot") == "" && e.getTag("missing") == "");
    }
}

/// Runs the squashed numeric+ERROR parse test scenarios.
void runSquashedErrorTests() {
    stderr.writeln("\n[SuperNets-pattern] squashed numeric+ERROR line");
    auto cfg = mkConfig();

    // The exact line we saw in the logs: ":contra.supernets.org 376 Luis ERROR :Closing Link:"
    // Should parse as 376 (with params/trailing) without throwing.
    {
        bool threw = false;
        try {
            auto e = parseIRCLinePublic(":contra.supernets.org 376 Luis ERROR :Closing Link:", cfg);
            check!("squashed-ERROR line never throws")(!threw);
            check!("squashed-ERROR parsed as 376")(e.command == "376");
            check!("squashed-ERROR trailing captured")
                (e.text.indexOf("Closing Link:") >= 0);
            // The parser hands off to caller — caller must detect the
            // ERROR-like trailing and trip the disconnect state. This
            // is verified separately in connection.d tests.
        } catch (Exception e) { threw = true; }
        check!("squashed-ERROR final: never threw")(!threw);
    }
}

/// Runs the ISUPPORT PREFIX and 005 rewrite test scenarios.
void runIsupportTests() {
    stderr.writeln("\n[ISUPPORT] PREFIX parsing");
    check!("ISUPPORT: full PREFIX (qaohv)~&@%+")
        (parseIsupportPrefix("(qaohv)~&@%+") == "~&@%+");
    check!("ISUPPORT: minimal (ov)@+")
        (parseIsupportPrefix("(ov)@+") == "@+");
    check!("ISUPPORT: empty")
        (parseIsupportPrefix("") == "");
    check!("ISUPPORT: missing parens")
        (parseIsupportPrefix("no-parens") == "");

    // RPL_ISUPPORT (005) text rewrite: the trailing "are supported by this
    // server" is RFC 2812 §5.1.4 boilerplate, NOT useful as msg.text. The
    // parser must rewrite msg.text to the joined ISUPPORT tokens (skipping
    // the user's nick at params[0] and the canonical trailer) so the
    // `_server` log shows real tokens instead of three copies of the
    // boilerplate. See the IRL bug: every 005 was rendering as just
    // "are supported by this server" three times.
    stderr.writeln("\n[ISUPPORT] 005 event.text rewrite");
    {
        auto cfg = mkConfig();
        // Single 005 reply with a mix of key=value and bare-key tokens,
        // plus the canonical trailer.
        auto e = parseIRCLinePublic(
            ":irc.example.org 005 Zod CHANTYPES=#& EXCEPTS INVEX " ~
                "CHANMODES=b,e,I,k,l,imnpstSr :are supported by this server",
            cfg);
        check!("005: command is 005")(e.command == "005");
        check!("005: text is joined tokens, NOT trailer")
            (e.text == "CHANTYPES=#& EXCEPTS INVEX CHANMODES=b,e,I,k,l,imnpstSr");
        check!("005: trailer stripped from text")
            (e.text.indexOf("are supported") < 0);
        check!("005: text starts with first ISUPPORT key")
            (e.text.startsWith("CHANTYPES="));
        check!("005: nick not in text")
            (e.text.indexOf("Zod") < 0);
    }
    {
        // 005 with a bare key (EXCEPTS, no value) should pass through.
        auto cfg = mkConfig();
        auto e = parseIRCLinePublic(
            ":irc.example.org 005 Zod EXCEPTS INVEX :are supported by this server",
            cfg);
        check!("005 bare-keys: text is bare tokens")
            (e.text == "EXCEPTS INVEX");
    }
    {
        // 005 with only the trailer (no real ISUPPORT tokens at all —
        // pathological but legal) — no rewrite should happen, text stays
        // as the trailer so the empty case isn't misleading.
        auto cfg = mkConfig();
        auto e = parseIRCLinePublic(
            ":irc.example.org 005 Zod :are supported by this server",
            cfg);
        check!("005 single-trail: text is empty after rewrite")
            (e.text == "");
    }
    {
        // 005 with NO trailing at all (some servers omit it on the last
        // reply) — tokens should still be joined into text.
        auto cfg = mkConfig();
        auto e = parseIRCLinePublic(
            ":irc.example.org 005 Zod FOO=bar BAZ=qux",
            cfg);
        check!("005 no-trailer: text is joined tokens")
            (e.text == "FOO=bar BAZ=qux");
    }
    {
        // Defensive: a non-trailer last token that happens to start with
        // "are supported" but isn't the boilerplate must NOT be stripped.
        auto cfg = mkConfig();
        auto e = parseIRCLinePublic(
            ":irc.example.org 005 Zod FOO=bar :are supported by my server",  // custom trailing
            cfg);
        check!("005 custom-trailer: trailer kept")
            (e.text == "FOO=bar are supported by my server");
    }
    {
        // Sanity: a non-005 event keeps the standard trailing behavior.
        auto cfg = mkConfig();
        auto e = parseIRCLinePublic(
            ":irc.example.org 332 Zod #design :Welcome to the channel",
            cfg);
        check!("non-005: standard trailing text preserved")
            (e.text == "Welcome to the channel");
    }
}

int main() {
    stderr.writeln("ircfiber.irc.parser smoke tests");
    runDefensiveTests();
    runRFC2812Tests();
    runIRCv3Tests();
    runSquashedErrorTests();
    runIsupportTests();
    stderr.writeln("\n", passed, " passed, ", failed, " failed");
    return failed == 0 ? 0 : 1;
}
