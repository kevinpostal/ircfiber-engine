module ircfiber.irc.ipv6_config;

import vibe.core.log : logInfo, logWarn;
import ircfiber.irc.ipv6 : parseRoutedIpv6Prefix;

// ── Saved-connection IPv6 reservations ───────────────────────────────────────
// A provider-owned, aligned global-unicast /64 and the persisted connection IID
// determine a reservation. It is not a source address until an IPv6-only native
// holder dial uses it; shared-direct Happy Eyeballs must not bind this pool.
private __gshared string gIpv6Prefix;
private __gshared bool gIpv6Loaded;
private __gshared Object gIpv6Lock;
shared static this() { gIpv6Lock = new Object(); }

/// The configured /64, loading it from IRCFIBER_IPV6_PREFIX once.
string configuredIpv6Prefix() {
    synchronized (gIpv6Lock) {
        if (!gIpv6Loaded) {
            gIpv6Loaded = true;
            gIpv6Prefix = readPrefixFromEnv();
        }
        return gIpv6Prefix;
    }
}

private string readPrefixFromEnv() {
    import std.process : environment;
    const raw = environment.get("IRCFIBER_IPV6_PREFIX", "");
    ubyte[16] prefix;
    if (raw.length && parseRoutedIpv6Prefix(raw, prefix)) {
        logInfo("IPv6 connection pool: prefix=%s (from IRCFIBER_IPV6_PREFIX)", raw);
        return raw;
    }
    if (raw.length) logWarn("IPv6 connection pool disabled: IRCFIBER_IPV6_PREFIX must be an aligned global-unicast /64");
    logInfo("IPv6 connection pool: disabled");
    return "";
}

/// Test seam: pin the prefix (marks it loaded). Returns the previous state.
package struct Ipv6ConfigState { string prefix; bool loaded; }
package Ipv6ConfigState overrideIpv6Prefix(string prefix) {
    synchronized (gIpv6Lock) {
        auto prev = Ipv6ConfigState(gIpv6Prefix, gIpv6Loaded);
        gIpv6Prefix = prefix; gIpv6Loaded = true;
        return prev;
    }
}
package void restoreIpv6Config(Ipv6ConfigState st) {
    synchronized (gIpv6Lock) { gIpv6Prefix = st.prefix; gIpv6Loaded = st.loaded; }
}

@("IPv6 configuration validates environment once and restores both cache fields")
unittest {
    import std.process : environment;
    assert(gIpv6Lock !is null, "IPv6 lock is initialized before first use");
    const oldEnv = environment.get("IRCFIBER_IPV6_PREFIX", null);
    const saved = overrideIpv6Prefix("");
    scope(exit) {
        restoreIpv6Config(saved);
        if (oldEnv is null) environment.remove("IRCFIBER_IPV6_PREFIX");
        else environment["IRCFIBER_IPV6_PREFIX"] = oldEnv;
    }
    foreach (raw; ["", "2001:db8:1:2::", "2001:db8:1:2::/48",
                   "2001:db8:1:2::1/64", "fd00:1234::/64"]) {
        environment["IRCFIBER_IPV6_PREFIX"] = raw;
        restoreIpv6Config(Ipv6ConfigState("", false));
        assert(configuredIpv6Prefix() == "");
    }
    enum valid = "2001:db8:1234:5678::/64";
    environment["IRCFIBER_IPV6_PREFIX"] = valid;
    restoreIpv6Config(Ipv6ConfigState("", false));
    assert(configuredIpv6Prefix() == valid);
    environment["IRCFIBER_IPV6_PREFIX"] = "invalid";
    assert(configuredIpv6Prefix() == valid, "loaded config is not re-read");
    const loaded = overrideIpv6Prefix("");
    assert(configuredIpv6Prefix() == "", "explicit empty override disables the pool");
    restoreIpv6Config(loaded);
    assert(configuredIpv6Prefix() == valid, "restore preserves loaded state and value");
}
