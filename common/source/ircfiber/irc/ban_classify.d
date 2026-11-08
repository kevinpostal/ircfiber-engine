module ircfiber.irc.ban_classify;

import std.ascii : isDigit, isHexDigit, toLower;

/// Keywords servers use to indicate the client is connecting too fast and
/// should wait before trying again.
immutable string[] THROTTLE_KEYWORDS = [
    "throttled", "reconnecting too fast", "excess flood",
    "too many connections", "rate limit", "try again later",
    "slow down", "you are banned", "temporary ban",
];

/// Keywords that indicate a hard ban (ZLINE/GLINE/KLINE/ELINE) — the server
/// has explicitly rejected this IP/nick and will keep rejecting until the
/// ban expires (often hours/days).
immutable string[] BAN_KEYWORDS = [
    "z-lined", "z:lined", "zline", "z:line",
    "g-lined", "g:lined", "gline", "g:line",
    "k-lined", "k:lined", "kline", "k:line",
    "d-lined", "d:lined", "dline", "d:line",
    "e-lined", "e:lined", "eline",
    "enter the void",
    "you are banned",
    "banned from",
    "permanently banned",
];

/// Read refusal text without IRC presentation bytes or letter spacing.
/// Keywords are ASCII; leave other bytes intact rather than allocating a copy.
private char nextRefusalChar(ref string text) @safe pure nothrow @nogc {
    while (text.length) {
        const c = text[0];
        text = text[1 .. $];
        if (c == '\x03') {
            size_t n;
            while (n < 2 && text.length && isDigit(text[0])) { text = text[1 .. $]; ++n; }
            if (n && text.length > 1 && text[0] == ',' && isDigit(text[1])) {
                text = text[1 .. $];
                n = 0;
                while (n < 2 && text.length && isDigit(text[0])) { text = text[1 .. $]; ++n; }
            }
        } else if (c == '\x04') {
            static bool hex6(string s) @safe pure nothrow @nogc {
                if (s.length < 6) return false;
                foreach (b; s[0 .. 6]) if (!isHexDigit(b)) return false;
                return true;
            }
            if (hex6(text)) {
                text = text[6 .. $];
                if (text.length && text[0] == ',' && hex6(text[1 .. $])) text = text[7 .. $];
            }
        } else if (c > ' ') {
            return toLower(c);
        }
    }
    return '\0';
}

private bool containsRefusalKeyword(string text, string keyword) @safe pure nothrow @nogc {
    while (text.length) {
        auto candidate = text;
        nextRefusalChar(text);
        auto needle = keyword;
        while (needle.length) {
            const expected = nextRefusalChar(needle);
            if (expected == '\0') return true;
            if (nextRefusalChar(candidate) != expected) break;
            if (!needle.length) return true;
        }
    }
    return false;
}

/// Returns `true` if `text` contains any throttle-related keywords.
bool isThrottleError(string text) {
    foreach (kw; THROTTLE_KEYWORDS) if (containsRefusalKeyword(text, kw)) return true;
    return false;
}

/// Returns `true` if `text` indicates a hard ban, including decorated refusals.
bool isBanError(string text) {
    foreach (kw; BAN_KEYWORDS) if (containsRefusalKeyword(text, kw)) return true;
    return false;
}

unittest {
    // Captured Super Nets ERROR: missing this ban retried the same VPN IP.
    assert(isBanError("Closing Link: Zodiac[193.19.206.22] (\x038,4   E N T E R   T H E   V O I D   \x0f)"));
    assert(isBanError("\x02You\x03" ~ "04,01 are\x04FF0000,000000 banned\x0f"));
    assert(isBanError("K-lined: proxy address"));
    assert(isThrottleError("\x03" ~ "04 R E C O N N E C T I N G  T O O  F A S T\x0f"));
    assert(!isBanError("Closing Link: nick (Registration timeout)"));
    assert(!isBanError("Closing Link: nick (E N T E R T H E V O I)"));
    assert(!isBanError(""));
    assert(!isThrottleError("Closing Link: nick (Connection reset)"));
}
