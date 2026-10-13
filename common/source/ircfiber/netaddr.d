/**
 * Address classification for outbound connections chosen by users.
 *
 * Every server-side dial whose target a user picks (an IRC network's
 * host, an image-proxy URL) must land on the public internet: the
 * processes doing the dialing sit next to Redis, Mongo, the ircd's WEBIRC
 * listener and the tailnet, none of which authenticate a peer that is
 * already inside.
 */
module ircfiber.netaddr;

import std.string : strip, toLower;

/// True when `ip` parses and is a public unicast address: not loopback,
/// RFC 1918, link-local, CGNAT (incl. the tailnet), 0.0.0.0/8, IPv6
/// loopback/ULA/link-local, multicast or v4-mapped. Hostnames and anything
/// unparsable are not public.
bool isPublicUnicast(string ip) @trusted {
    import core.sys.posix.arpa.inet : inet_pton;
    import core.sys.posix.sys.socket : AF_INET, AF_INET6;
    import std.string : toStringz;

    ip = ip.strip;
    if (ip.length == 0 || ip.length > 45) return false;
    ubyte[16] b;
    if (inet_pton(AF_INET, ip.toStringz, b.ptr) == 1) {
        const o1 = b[0], o2 = b[1];
        if (o1 == 0 || o1 == 10 || o1 == 127) return false;        // 0/8, 10/8, loopback
        if (o1 == 100 && o2 >= 64 && o2 <= 127) return false;       // CGNAT 100.64/10
        if (o1 == 169 && o2 == 254) return false;                   // link-local
        if (o1 == 172 && o2 >= 16 && o2 <= 31) return false;        // 172.16/12
        if (o1 == 192 && o2 == 168) return false;                   // 192.168/16
        if (o1 >= 224) return false;                                // multicast / reserved
        return true;
    }
    if (inet_pton(AF_INET6, ip.toStringz, b.ptr) == 1) {
        bool allZero = true;
        foreach (i; 0 .. 15) if (b[i] != 0) { allZero = false; break; }
        if (allZero && b[15] <= 1) return false;                    // :: and ::1
        if ((b[0] & 0xFE) == 0xFC) return false;                    // ULA fc00::/7
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return false;    // link-local fe80::/10
        if (b[0] == 0xFF) return false;                             // multicast
        bool mapped = true;                                         // ::ffff:a.b.c.d
        foreach (i; 0 .. 10) if (b[i] != 0) { mapped = false; break; }
        if (mapped && b[10] == 0xFF && b[11] == 0xFF) return false;
        return true;
    }
    return false;
}

/// True when `host` is an IPv4 or IPv6 literal (brackets already removed).
bool isIpLiteral(string host) @trusted {
    import core.sys.posix.arpa.inet : inet_pton;
    import core.sys.posix.sys.socket : AF_INET, AF_INET6;
    import std.string : toStringz;

    host = host.strip;
    if (host.length == 0 || host.length > 45) return false;
    ubyte[16] b;
    return inet_pton(AF_INET, host.toStringz, b.ptr) == 1
        || inet_pton(AF_INET6, host.toStringz, b.ptr) == 1;
}

/// Lower-cased host without a trailing root dot, for allowlist matching.
string canonicalHost(string host) @safe pure {
    auto h = host.strip.toLower;
    while (h.length && h[$ - 1] == '.') h = h[0 .. $ - 1];
    return h;
}

/// True when `host` is one of `privateAllowHosts` — first-party names
/// (the hosted ircd) that legitimately resolve to an internal address.
bool isPrivateAllowedHost(string host, const string[] privateAllowHosts) @safe pure {
    const h = canonicalHost(host);
    if (h.length == 0) return false;
    foreach (a; privateAllowHosts)
        if (canonicalHost(a) == h) return true;
    return false;
}

/// The subset of `ips` (resolved addresses of `host`) a user-chosen dial
/// may connect to: all of them for an allowlisted first-party host,
/// otherwise only public unicast ones.
string[] dialableAddresses(string host, const string[] ips, const string[] privateAllowHosts) @safe {
    string[] out_;
    const allowAll = isPrivateAllowedHost(host, privateAllowHosts);
    foreach (ip; ips)
        if (allowAll || isPublicUnicast(ip)) out_ ~= ip;
    return out_;
}

/// True for names that only resolve inside our own networks (single-label
/// Docker/MagicDNS names, `*.ts.net`, `*.local`, `*.internal`,
/// `*.localhost`, cluster DNS). Used where the name is resolved by a
/// third party (a SOCKS exit) and cannot be checked by address.
bool isInternalOnlyName(string host) @safe pure {
    import std.algorithm : canFind, endsWith;
    const h = canonicalHost(host);
    if (h.length == 0) return true;
    if (!h.canFind('.')) return true;
    foreach (suffix; [".ts.net", ".local", ".internal", ".localhost", ".localdomain",
                      ".lan", ".home.arpa", ".svc", ".cluster.local"])
        if (h.endsWith(suffix)) return true;
    return false;
}

@("isPublicUnicast accepts public, rejects private/reserved/unparsable")
unittest {
    assert(isPublicUnicast("203.0.113.7"));
    assert(isPublicUnicast("8.8.8.8"));
    assert(isPublicUnicast("2001:db8::1"));
    foreach (bad; ["", "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255",
                   "192.168.1.1", "100.64.0.1", "100.94.72.103", "169.254.169.254",
                   "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fd7a:115c:a1e0::1",
                   "fc00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8",
                   "localhost", "redis", "999.1.1.1"])
        assert(!isPublicUnicast(bad), bad);
    assert(isPublicUnicast("172.15.0.1"));
    assert(isPublicUnicast("172.32.0.1"));
}

@("dialableAddresses keeps only public addresses unless the host is allowlisted")
unittest {
    const allow = ["irc.ircfiber.com"];
    assert(dialableAddresses("evil.example", ["127.0.0.1", "203.0.113.9"], allow) == ["203.0.113.9"]);
    assert(dialableAddresses("127.0.0.1", ["127.0.0.1"], allow).length == 0);
    assert(dialableAddresses("rebind.example", ["10.0.0.5", "fd00::1"], allow).length == 0);
    assert(dialableAddresses("IRC.ircfiber.com.", ["172.30.0.5"], allow) == ["172.30.0.5"]);
    assert(dialableAddresses("irc.ircfiber.com.evil.example", ["172.30.0.5"], allow).length == 0);
}

@("isInternalOnlyName flags names that never resolve publicly")
unittest {
    foreach (n; ["redis", "localhost", "ircfiber-prod-1", "box.tail1234.ts.net",
                 "printer.local", "db.internal", "x.localhost", "mongo.ircfiber.svc",
                 "mongo.ircfiber.svc.cluster.local", ""])
        assert(isInternalOnlyName(n), n);
    foreach (n; ["irc.libera.chat", "irc.supernets.org", "example.com."])
        assert(!isInternalOnlyName(n), n);
}

@("isIpLiteral")
unittest {
    assert(isIpLiteral("127.0.0.1"));
    assert(isIpLiteral("::1"));
    assert(!isIpLiteral("irc.example.com"));
    assert(!isIpLiteral("2130706433"));
}
