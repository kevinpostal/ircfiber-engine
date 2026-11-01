module ircfiber.irc.ban_classify;

import std.string : toLower, indexOf;

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

/// Returns `true` if `text` contains any throttle-related keywords.
bool isThrottleError(string text) {
    if (text.length == 0) return false;
    auto lower = toLower(text);
    foreach (kw; THROTTLE_KEYWORDS) if (lower.indexOf(kw) >= 0) return true;
    return false;
}

/// Returns `true` if `text` indicates a hard ban.
bool isBanError(string text) {
    if (text.length == 0) return false;
    auto lower = toLower(text);
    foreach (kw; BAN_KEYWORDS) if (lower.indexOf(kw) >= 0) return true;
    return false;
}
