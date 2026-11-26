module ircfiber.irc.webirc_suppress;

import std.datetime : Clock;
import std.string : toLower;
import vibe.core.log : logWarn;

/// WEBIRC-swap suppression after a Z-line kill, keyed `hostLower|ip`.
/// Swapping into an address the server just banned gets this session killed
/// with it (p34c3, 2026-09-10: every site attach re-asserted a Mullvad exit
/// under an active connectban loop-ban, and each 5-minute ban reaped the
/// swapped engine session). After applyBanPolicy records one,
/// performRegistration skips asserting that IP for ZLINE_SWAP_SUPPRESS_MS
/// and the session keeps the engine IP: slightly wrong geo display, stays
/// alive. Recorded unconditionally when a fiber session dies asserting an
/// IP — whether the ban targeted the asserted address or the socket, the
/// next swap into it is unsafe either way.
enum long ZLINE_SWAP_SUPPRESS_MS = 30 * 60 * 1000L; // 30 min

private __gshared long[string] gSuppressedUntil;
// This table has no compound invariant with the egress pool. Both registration
// and ban-policy callers invoke the API outside gMullvadLock. Never acquire the
// pool lock here: one eagerly initialized lock owns every access to this table.
private __gshared Object gLock;
shared static this() { gLock = new Object(); }

private string suppressKey(string hostLower, string ip) @safe pure {
    return hostLower ~ "|" ~ ip;
}

private long nowMs() nothrow {
    try return Clock.currTime.toUnixTime!long * 1000;
    catch (Exception) return 0;
}

void suppressWebircSwapFor(string host, string ip, long durationMs = ZLINE_SWAP_SUPPRESS_MS) {
    if (host.length == 0 || ip.length == 0) return;
    const hl = host.toLower();
    const exp = nowMs() + durationMs;
    synchronized (gLock) gSuppressedUntil[suppressKey(hl, ip)] = exp;
    logWarn("WEBIRC swap suppressed: %s for %s for %d ms (until %d)", ip, hl, durationMs, exp);
}

bool webircSwapSuppressed(string hostLower, string ip) {
    if (hostLower.length == 0 || ip.length == 0) return false;
    const now = nowMs();
    const k = suppressKey(hostLower, ip);
    synchronized (gLock) {
        if (auto p = k in gSuppressedUntil) {
            if (now < *p) return true;
            gSuppressedUntil.remove(k);
        }
    }
    return false;
}

@("webircSwapSuppressed skips recently Z-lined addresses only")
unittest {
    assert(gLock !is null, "WEBIRC suppression lock is initialized before first use");
    assert(suppressKey("irc.ircfiber.com", "1.2.3.4") == "irc.ircfiber.com|1.2.3.4");
    assert(!webircSwapSuppressed("irc.ircfiber.com", "9.9.9.9"),
           "an address never recorded is never suppressed");
    assert(!webircSwapSuppressed("", "1.2.3.4") && !webircSwapSuppressed("irc.ircfiber.com", ""));
    suppressWebircSwapFor("irc.ircfiber.com", "1.2.3.4");
    assert(webircSwapSuppressed("irc.ircfiber.com", "1.2.3.4"));
    assert(!webircSwapSuppressed("irc.ircfiber.com", "1.2.3.5"),
           "suppression is per-address");
    assert(!webircSwapSuppressed("irc.example.org", "1.2.3.4"),
           "suppression is per-host");
    suppressWebircSwapFor("irc.ircfiber.com", "5.6.7.8", 0);
    assert(!webircSwapSuppressed("irc.ircfiber.com", "5.6.7.8"),
           "a zero-duration record is already lapsed");
    suppressWebircSwapFor("", "");
    assert(!webircSwapSuppressed("irc.ircfiber.com", "9.9.9.9"),
           "empty records change nothing");
}
