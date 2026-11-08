/**
 * Sensitive service-traffic classifier shared by the gateway, engine,
 * bouncer trace and (mirrored by hand) the frontend input path.
 *
 * Decides whether one outgoing line, or one message to a service, carries
 * material that must never reach optimistic echoes, input history, the
 * ordinary command list, scrollback, snapshots or logs: credentials
 * (IDENTIFY, REGISTER, GROUP, RECOVER/GHOST/RELEASE, CONFIRM codes,
 * SET PASSWORD, OperServ LOGIN) and private memo traffic (MemoServ SEND,
 * RSEND, READ, ...). Ordinary chat and non-service targets are never
 * matched: the classifier is an allowlist of service commands, not a
 * blanket suppression rule.
 *
 * A service target is recognised by its conventional nick, by the nick a
 * network pinned in `ServicesConfig` (renamed services), with or without a
 * `@server` suffix, and through the usual command aliases (`NS`,
 * `NICKSERV`, `CS`, `MS`, `OS`, `HS`, `BS`, bare `IDENTIFY`). Nicks are
 * compared under RFC 1459 folding, the widest common casemapping, so no
 * network's mapping can make a spelling slip past. Pure functions.
 */
module ircfiber.services.privacy;

import ircfiber.services.config : ServiceId, ServicesConfig, SERVICE_COUNT, SERVICE_DEFAULT_NICKS;

/// True when `text`, sent to `service`, is a sensitive command. IRC
/// formatting is ignored for classification: services tokenise the raw
/// body, and the unknown-command reply echoes the whole input, so
/// `\x02IDENTIFY\x02 acct pw` or a coloured verb is still a credential.
/// Multi-line text (`hi\nIDENTIFY pw`, which a client splits into several
/// messages) is sensitive when ANY of its CR/LF-separated lines is.
bool isSensitiveServiceMessage(ServiceId service, string text) @safe pure nothrow {
    size_t start;
    foreach (i; 0 .. text.length + 1) {
        if (i < text.length && text[i] != '\r' && text[i] != '\n') continue;
        if (i > start && sensitiveCommand(service, text[start .. i])) return true;
        start = i + 1;
    }
    return false;
}

/// One line of service text.
private bool sensitiveCommand(ServiceId service, string text) @safe pure nothrow {
    string rest = skipSpaces(stripFormatting(text));
    // A leading `/` (some clients pass `/msg NickServ /IDENTIFY`) is ignored.
    if (rest.length && rest[0] == '/') rest = rest[1 .. $];
    const verb = upperWord(rest);
    final switch (service) {
        case ServiceId.nickServ:
            switch (verb) {
                case "IDENTIFY": case "ID": case "LOGIN": case "REGISTER": case "GROUP":
                case "RECOVER": case "GHOST": case "RELEASE": case "CONFIRM": case "RESETPASS":
                    return true;
                case "SET": {
                    const option = upperWord(rest);
                    return option == "PASSWORD" || option == "PASS" || option == "EMAIL";
                }
                case "SASET": {
                    // SASET <nick> PASSWORD|EMAIL <value>
                    word(rest);
                    const option = upperWord(rest);
                    return option == "PASSWORD" || option == "PASS" || option == "EMAIL";
                }
                default:
                    return false;
            }
        case ServiceId.memoServ:
            switch (verb) {
                case "SEND": case "RSEND": case "SENDALL": case "STAFF": case "READ":
                    return true;
                default:
                    return false;
            }
        case ServiceId.operServ:
            return verb == "LOGIN" || verb == "IDENTIFY";
        case ServiceId.chanServ:
            switch (verb) {
                // Anope 1.x/Atheme channel passwords; never sent by this UI,
                // but a pasted one must not be echoed either.
                case "IDENTIFY":
                    return true;
                case "SET": {
                    // SET <#chan> PASSWORD <pw> | SET <#chan> MLOCK <+k key>
                    word(rest);
                    const option = upperWord(rest);
                    if (option == "PASSWORD") return true;
                    return option == "MLOCK" && modesCarryKey(rest);
                }
                case "MODE": {
                    // MODE <#chan> LOCK ADD|SET|DEL <modes> [params]: a channel key.
                    word(rest);
                    if (upperWord(rest) != "LOCK") return false;
                    return modesCarryKey(rest);
                }
                default:
                    return false;
            }
        case ServiceId.global:
            // Broadcast text stays out of history and logs until it is sent.
            if (verb == "GLOBAL") return true;
            return verb == "QUEUE" && upperWord(rest) == "ADD";
        case ServiceId.botServ:
        case ServiceId.hostServ:
            return false;
    }
}

/// `s` with IRC formatting removed (bold, colour `\x03[N[N]][,N[N]]`, hex
/// colour `\x04[RRGGBB[,RRGGBB]]`, italics, underline, strike, monospace,
/// reverse, reset; Anope's `\x1B` no-break marker becomes a space). Returns
/// `s` itself, without allocating, when it carries no formatting.
private string stripFormatting(string s) @safe pure nothrow {
    static bool isFormat(char c) @safe pure nothrow @nogc {
        return c == '\x02' || c == '\x03' || c == '\x04' || c == '\x0F' || c == '\x11'
            || c == '\x16' || c == '\x1B' || c == '\x1D' || c == '\x1E' || c == '\x1F';
    }
    static bool isDigit(char c) @safe pure nothrow @nogc { return c >= '0' && c <= '9'; }
    static bool isHex(char c) @safe pure nothrow @nogc {
        return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
    static bool hex6(string t) @safe pure nothrow @nogc {
        if (t.length < 6) return false;
        foreach (c; t[0 .. 6]) if (!isHex(c)) return false;
        return true;
    }
    bool any;
    foreach (c; s) if (isFormat(c)) { any = true; break; }
    if (!any) return s;
    char[] o;
    o.reserve(s.length);
    for (size_t i = 0; i < s.length; ++i) {
        const c = s[i];
        if (!isFormat(c)) { o ~= c; continue; }
        if (c == '\x1B') { o ~= ' '; continue; }
        if (c == '\x03') {
            size_t n;
            while (n < 2 && i + 1 < s.length && isDigit(s[i + 1])) { ++i; ++n; }
            if (n && i + 2 < s.length && s[i + 1] == ',' && isDigit(s[i + 2])) {
                ++i;
                n = 0;
                while (n < 2 && i + 1 < s.length && isDigit(s[i + 1])) { ++i; ++n; }
            }
        } else if (c == '\x04') {
            if (hex6(s[i + 1 .. $])) {
                i += 6;
                if (i + 1 < s.length && s[i + 1] == ',' && hex6(s[i + 2 .. $])) i += 7;
            }
        }
    }
    return () @trusted { return cast(string) o; }();
}

/// Some `+`/`-` mode word in `rest` names the channel key mode `k`.
private bool modesCarryKey(string rest) @safe pure nothrow @nogc {
    while (rest.length) {
        const w = word(rest);
        if (w.length && (w[0] == '+' || w[0] == '-'))
            foreach (c; w)
                if (c == 'k') return true;
    }
    return false;
}

/// Resolves a message target to a service: the conventional nick or the
/// pinned nick of `cfg`, optionally `nick@server`. False for anything else,
/// including channels.
bool serviceTarget(string target, const ServicesConfig cfg, out ServiceId id) @safe pure nothrow {
    if (target.length == 0) return false;
    if (target[0] == '#' || target[0] == '&' || target[0] == '!' || target[0] == '+') return false;
    string nick = target;
    foreach (i, c; target) {
        if (c == '@') {
            nick = target[0 .. i];
            break;
        }
    }
    if (nick.length == 0) return false;
    foreach (i; 0 .. SERVICE_COUNT) {
        const pinned = cfg.pins[i].nick;
        if ((pinned.length && foldEquals(nick, pinned)) || foldEquals(nick, SERVICE_DEFAULT_NICKS[i])) {
            id = cast(ServiceId) i;
            return true;
        }
    }
    return false;
}

/// True when a RAW outgoing IRC line (optionally `@tags` and/or `:prefix`
/// prefixed, as an own echo is) carries a sensitive service command:
/// PRIVMSG/NOTICE/SQUERY to a service, or a services alias command.
///
/// Raw text is split at CR/LF into physical lines BEFORE any parsing:
/// every one is its own IRC command, so `PRIVMSG bob :hi\nID pw` carries a
/// second command `ID pw` and is sensitive. For a chat message whose body
/// a client splits into several messages to the same target, use
/// `sensitiveServiceMessage` instead.
bool sensitiveServiceLine(string line, const ServicesConfig cfg) @safe pure nothrow {
    size_t start;
    foreach (i; 0 .. line.length + 1) {
        if (i < line.length && line[i] != '\r' && line[i] != '\n') continue;
        if (i > start && sensitiveLineOne(line[start .. i], cfg)) return true;
        start = i + 1;
    }
    return false;
}

/// True when a chat message (`targets` = one target or a comma list, `text`
/// = the body, possibly multi-line, sent as messages to those targets)
/// reaches a service with a sensitive command on ANY of its lines. A
/// multi-line body to a person stays ordinary chat.
bool sensitiveServiceMessage(string targets, string text, const ServicesConfig cfg) @safe pure nothrow {
    ServiceId id;
    size_t start;
    foreach (i; 0 .. targets.length + 1) {
        if (i < targets.length && targets[i] != ',') continue;
        if (serviceTarget(targets[start .. i], cfg, id) && isSensitiveServiceMessage(id, text))
            return true;
        start = i + 1;
    }
    return false;
}

/// One physical raw line.
private bool sensitiveLineOne(string line, const ServicesConfig cfg) @safe pure nothrow {
    string rest = skipSpaces(line);
    if (rest.length && rest[0] == '@') rest = afterWord(rest);
    if (rest.length && rest[0] == ':') rest = afterWord(rest);
    const verb = upperWord(rest);
    switch (verb) {
        case "REGISTER": case "VERIFY":
            return true;
        case "PRIVMSG": case "NOTICE": case "SQUERY": {
            // `PRIVMSG bob,NickServ :IDENTIFY pw` reaches NickServ too.
            const targets = word(rest);
            return sensitiveServiceMessage(targets, trailing(rest), cfg);
        }
        case "GS":
            return isSensitiveServiceMessage(ServiceId.global, trailing(rest));
        case "GLOBAL":
            // ircd alias straight to Global (`GLOBAL <message>`).
            return trailing(rest).length > 0;
        case "NS": case "NICKSERV":
            return isSensitiveServiceMessage(ServiceId.nickServ, trailing(rest));
        case "MS": case "MEMOSERV":
            return isSensitiveServiceMessage(ServiceId.memoServ, trailing(rest));
        case "OS": case "OPERSERV":
            return isSensitiveServiceMessage(ServiceId.operServ, trailing(rest));
        case "CS": case "CHANSERV":
            return isSensitiveServiceMessage(ServiceId.chanServ, trailing(rest));
        case "IDENTIFY": case "ID": case "LOGIN":
            // ircd aliases straight to NickServ (`IDENTIFY <pass>`, the
            // managed InspIRCd `ID <pass>` → SQUERY NickServ :IDENTIFY).
            return true;
        default:
            // A pinned renamed service used as an alias command (`/NS2 ...`)
            // is not a standard ircd alias; only the forms above are known.
            return false;
    }
}

// ── Lexing helpers (no allocation beyond the folded comparison) ──────────

private string skipSpaces(string s) @safe pure nothrow @nogc {
    size_t i;
    while (i < s.length && s[i] == ' ') ++i;
    return s[i .. $];
}

/// Pops the next space-delimited word (not a trailing parameter).
private string word(ref string s) @safe pure nothrow @nogc {
    s = skipSpaces(s);
    size_t i;
    while (i < s.length && s[i] != ' ') ++i;
    auto w = s[0 .. i];
    s = skipSpaces(s[i .. $]);
    return w;
}

private string afterWord(string s) @safe pure nothrow @nogc {
    word(s);
    return s;
}

/// Pops the next word, ASCII-uppercased (allocates only when it must).
private string upperWord(ref string s) @safe pure nothrow {
    auto w = word(s);
    foreach (c; w)
        if (c >= 'a' && c <= 'z') {
            auto u = new char[w.length];
            foreach (i, d; w) u[i] = (d >= 'a' && d <= 'z') ? cast(char)(d - 32) : d;
            return () @trusted { return cast(string) u; }();
        }
    return w;
}

/// The remainder as message text: a leading `:` (trailing marker) dropped.
/// Text without the marker is taken whole, so `PRIVMSG NickServ IDENTIFY pw`
/// cannot slip past by omitting it.
private string trailing(string s) @safe pure nothrow @nogc {
    s = skipSpaces(s);
    return s.length && s[0] == ':' ? s[1 .. $] : s;
}

private char fold(char c) @safe pure nothrow @nogc {
    if (c >= 'A' && c <= 'Z') return cast(char)(c + 32);
    if (c == '[') return '{';
    if (c == ']') return '}';
    if (c == '\\') return '|';
    if (c == '^') return '~';
    return c;
}

private bool foldEquals(string a, string b) @safe pure nothrow @nogc {
    if (a.length != b.length) return false;
    foreach (i; 0 .. a.length)
        if (fold(a[i]) != fold(b[i])) return false;
    return true;
}

@("privacy: credentials and memo traffic to services are sensitive, chat is not")
unittest {
    ServicesConfig cfg;
    assert(sensitiveServiceLine("PRIVMSG NickServ :IDENTIFY hunter2", cfg));
    assert(sensitiveServiceLine("privmsg nickserv :identify acct hunter2", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ@services.example :IDENTIFY hunter2", cfg));
    assert(sensitiveServiceLine("PRIVMSG NICKSERV IDENTIFY hunter2", cfg), "no trailing marker");
    assert(sensitiveServiceLine("@label=x PRIVMSG NickServ :GHOST me pw", cfg));
    assert(sensitiveServiceLine(":me!u@h PRIVMSG NickServ :REGISTER pw a@b.c", cfg), "own echo form");
    assert(sensitiveServiceLine("PRIVMSG NickServ :SET PASSWORD newpw", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :SASET bob PASSWORD newpw", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :CONFIRM ABCDEF", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :RECOVER me pw", cfg));
    assert(sensitiveServiceLine("PRIVMSG MemoServ :SEND bob private words", cfg));
    assert(sensitiveServiceLine("PRIVMSG MemoServ :READ 3", cfg));
    assert(sensitiveServiceLine("PRIVMSG OperServ :LOGIN operpw", cfg));
    assert(sensitiveServiceLine("NS IDENTIFY hunter2", cfg));
    assert(sensitiveServiceLine("NICKSERV :identify hunter2", cfg));
    assert(sensitiveServiceLine("MS SEND bob hi", cfg));
    assert(sensitiveServiceLine("IDENTIFY hunter2", cfg));
    assert(sensitiveServiceLine("SQUERY NickServ :IDENTIFY pw", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :SET EMAIL me@example.org", cfg));
    assert(sensitiveServiceLine("PRIVMSG bob,NickServ :IDENTIFY pw", cfg), "comma target list");
    assert(sensitiveServiceLine("PRIVMSG Global :GLOBAL network maintenance", cfg));
    assert(sensitiveServiceLine("PRIVMSG Global :QUEUE ADD maintenance", cfg));
    // Formatting never hides a credential: services tokenise the raw body
    // and the unknown-command reply echoes all of it.
    assert(sensitiveServiceLine("PRIVMSG NickServ :\x02IDENTIFY\x02 alice canary", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :\x0304,12IDENTIFY\x03 alice canary", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :\x04FF0000ID\x04ENTIFY canary", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :\x1Fid\x1F\x1Dentify\x0F canary", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :\x02 \x02IDENTIFY canary", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :SET \x02PASSWORD\x02 canary", cfg));
    assert(sensitiveServiceLine("PRIVMSG MemoServ :\x0303SEND\x03 bob secret", cfg));
    assert(sensitiveServiceLine("NS \x02IDENTIFY\x02 canary", cfg));
    assert(isSensitiveServiceMessage(ServiceId.nickServ, "\x16GHOST\x16 me pw"));
    assert(!sensitiveServiceLine("PRIVMSG NickServ :\x02INFO\x02 bob", cfg));
    assert(!sensitiveServiceLine("PRIVMSG bob :\x02IDENTIFY\x02 canary", cfg), "ordinary chat untouched");
    // No formatting: the text itself is classified, without a copy.
    const plain = "IDENTIFY pw";
    assert(stripFormatting(plain) is plain);
    // ircd aliases: managed InspIRCd `ID <pass>` and `GLOBAL <message>`.
    assert(sensitiveServiceLine("ID canary", cfg));
    assert(sensitiveServiceLine("id :canary", cfg));
    assert(sensitiveServiceLine("GLOBAL network maintenance tonight", cfg));
    assert(!sensitiveServiceLine("GLOBAL", cfg));
    // Multi-line bodies are split into several messages: any private line
    // makes the whole body private.
    assert(isSensitiveServiceMessage(ServiceId.nickServ, "hi\nIDENTIFY canary"));
    assert(isSensitiveServiceMessage(ServiceId.nickServ, "hi\r\n\x02IDENTIFY\x02 canary"));
    assert(isSensitiveServiceMessage(ServiceId.memoServ, "LIST\nSEND bob secret"));
    assert(!isSensitiveServiceMessage(ServiceId.nickServ, "hi\nINFO bob\n"));
    // Message semantics: the body becomes several messages to the target.
    assert(sensitiveServiceMessage("NickServ", "hi\nIDENTIFY canary", cfg));
    assert(sensitiveServiceMessage("MemoServ", "LIST\nSEND bob secret", cfg));
    assert(sensitiveServiceMessage("bob,NickServ@x.y", "IDENTIFY canary", cfg));
    assert(!sensitiveServiceMessage("bob", "hi\nid like pizza", cfg), "chat continuation stays chat");
    assert(!sensitiveServiceMessage("bob", "hi\nIDENTIFY canary", cfg));
    assert(!sensitiveServiceMessage("NickServ", "hi\nINFO bob", cfg));
    // Raw semantics: every physical line is its own command.
    assert(sensitiveServiceLine("PRIVMSG NickServ :hi\nIDENTIFY canary", cfg));
    assert(sensitiveServiceLine("JOIN #c\nPRIVMSG NickServ :IDENTIFY canary", cfg),
        "a smuggled second command line is judged on its own");
    assert(sensitiveServiceLine("NS INFO bob\r\nID canary", cfg));
    assert(sensitiveServiceLine("PRIVMSG bob :hi\nID password", cfg), "raw second command ID → NickServ");
    assert(sensitiveServiceLine("PRIVMSG bob :hi\r\nPRIVMSG MemoServ :SEND x y", cfg));
    assert(!sensitiveServiceLine("PRIVMSG bob :hi\nthere IDENTIFY", cfg));
    assert(!sensitiveServiceLine("PRIVMSG bob :hi\r\nJOIN #c", cfg));
    assert(sensitiveServiceLine("PRIVMSG ChanServ :MODE #c LOCK ADD +k sekrit", cfg));
    assert(sensitiveServiceLine("PRIVMSG ChanServ :MODE #c LOCK SET +ntk sekrit", cfg));
    assert(!sensitiveServiceLine("PRIVMSG ChanServ :MODE #c LOCK ADD +nt", cfg));
    assert(!sensitiveServiceLine("PRIVMSG ChanServ :MODE #c LOCK LIST", cfg));
    assert(!sensitiveServiceLine("PRIVMSG Global :QUEUE LIST", cfg));

    assert(!sensitiveServiceLine("PRIVMSG NickServ :INFO bob", cfg));
    assert(!sensitiveServiceLine("PRIVMSG NickServ :SET HIDE EMAIL ON", cfg));
    assert(!sensitiveServiceLine("PRIVMSG ChanServ :ACCESS #c LIST", cfg));
    assert(!sensitiveServiceLine("PRIVMSG MemoServ :LIST", cfg));
    assert(!sensitiveServiceLine("PRIVMSG bob :IDENTIFY hunter2", cfg), "ordinary chat untouched");
    assert(!sensitiveServiceLine("PRIVMSG #NickServ :IDENTIFY hunter2", cfg));
    assert(!sensitiveServiceLine("PRIVMSG NickServ2 :IDENTIFY x", cfg));
    assert(!sensitiveServiceLine("JOIN #identify", cfg));
    assert(!sensitiveServiceLine("", cfg));
}

@("privacy: renamed pinned services are recognised under RFC 1459 folding")
unittest {
    import ircfiber.services.config : ServicePin;
    ServicesConfig cfg;
    cfg.server = "svc.example";
    cfg.pins[ServiceId.nickServ] = ServicePin("Nick[Bot]", "svc", "svc.example");
    cfg.pins[ServiceId.memoServ] = ServicePin("Post", "", "");
    assert(sensitiveServiceLine("PRIVMSG nick{bot} :IDENTIFY pw", cfg));
    assert(sensitiveServiceLine("PRIVMSG Nick[Bot]@svc.example :IDENTIFY pw", cfg));
    assert(sensitiveServiceLine("PRIVMSG post :SEND bob hello", cfg));
    assert(sensitiveServiceLine("PRIVMSG NickServ :IDENTIFY pw", cfg), "conventional nick still matched");
    ServiceId id;
    assert(serviceTarget("POST@x.y", cfg, id) && id == ServiceId.memoServ);
    assert(!serviceTarget("#post", cfg, id));
    assert(!serviceTarget("@svc", cfg, id));
}
