/** Stable per-saved-connection addresses inside a provider-owned routed /64.
 * Parsing/composition does not allocate an identity or imply that a socket used it.
 */
module ircfiber.irc.ipv6;

import core.sys.posix.arpa.inet : inet_pton, inet_ntop;
import core.sys.posix.sys.socket : AF_INET6;

/// Only aligned global-unicast /64 CIDRs are routed pools. No guessed subnet,
/// missing mask, surrounding whitespace, scoped address or textual fallback.
bool parseRoutedIpv6Prefix(string cidr, out ubyte[16] prefix) @trusted nothrow @nogc {
    prefix[] = 0;
    if (cidr.length < 5 || cidr.length > 48 || cidr[$ - 3 .. $] != "/64") return false;
    const address = cidr[0 .. $ - 3];
    if (address.length > 45) return false;
    foreach (char c; address)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == ':')) return false;
    char[46] text = void;
    text[0 .. address.length] = address;
    text[address.length] = '\0';
    ubyte[16] parsed;
    if (inet_pton(AF_INET6, text.ptr, parsed.ptr) != 1) return false;
    // The documentation prefix is deliberately accepted for isolated fixtures;
    // enabling a node still requires provider ownership and return-path proof.
    if ((parsed[0] & 0xe0) != 0x20) return false;
    foreach (b; parsed[8 .. 16]) if (b != 0) return false;
    prefix = parsed;
    return true;
}

/// Binary source membership; does not assert provider ownership or reachability.
bool ipv6InRoutedPrefix(string cidr, string source) @trusted nothrow @nogc {
    ubyte[16] prefix;
    if (!parseRoutedIpv6Prefix(cidr, prefix) || !source.length || source.length > 45)
        return false;
    foreach (char c; source)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
                || (c >= 'A' && c <= 'F') || c == ':')) return false;
    char[46] text = void;
    text[0 .. source.length] = source;
    text[source.length] = '\0';
    ubyte[16] address;
    return inet_pton(AF_INET6, text.ptr, address.ptr) == 1
        && address[0 .. 8] == prefix[0 .. 8];
}

private int hexNibble(char c) @safe pure nothrow @nogc {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

private bool usableIid(const ubyte[8] iid) @safe pure nothrow @nogc {
    // RFC 4291 modified EUI-64 universal/local bit: locally assigned IID.
    if ((iid[0] & 0x02) != 0) return false;
    bool lowInfrastructure = true;
    foreach (b; iid[0 .. 6]) if (b != 0) lowInfrastructure = false;
    if (lowInfrastructure) return false;
    // RFC 2526 reserved subnet-anycast IDs for modified EUI-64 subnets.
    if (iid[0] == 0xfd && iid[7] >= 0x80) {
        bool reserved = true;
        foreach (b; iid[1 .. 7]) if (b != 0xff) reserved = false;
        if (reserved) return false;
    }
    return true;
}

private bool parseIid(string hex, out ubyte[8] iid) @safe pure nothrow @nogc {
    iid[] = 0;
    if (hex.length != 16) return false;
    foreach (i; 0 .. 8) {
        const high = hexNibble(hex[i * 2]);
        const low = hexNibble(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return false;
        iid[i] = cast(ubyte)((high << 4) | low);
    }
    return usableIid(iid);
}

bool validIpv6Iid(string iidHex) @safe pure nothrow @nogc {
    ubyte[8] iid;
    return parseIid(iidHex, iid);
}

/// Returns a source reservation, never evidence of the active transport.
string ipv6ForConnection(string routedPrefix, string iidHex) @trusted {
    ubyte[16] address;
    ubyte[8] iid;
    if (!parseRoutedIpv6Prefix(routedPrefix, address) || !parseIid(iidHex, iid)) return "";
    address[8 .. 16] = iid[];
    char[46] text;
    if (inet_ntop(AF_INET6, address.ptr, text.ptr, cast(uint)text.length) is null) return "";
    size_t length;
    while (length < text.length && text[length]) ++length;
    return text[0 .. length].idup;
}

/// Eight CSPRNG bytes, fail closed. This creates a candidate IID only; Mongo's
/// unique reservation is the sole authority for the saved connection identity.
bool generateIpv6Iid(out string iidHex) @trusted {
    import deimos.openssl.rand : RAND_bytes;
    enum digits = "0123456789abcdef";
    iidHex = null;
    ubyte[8] raw;
    scope(exit) raw[] = 0;
    foreach (_; 0 .. 8) {
        if (RAND_bytes(raw.ptr, cast(int)raw.length) != 1) return false;
        raw[0] &= cast(ubyte)~0x02;
        if (!usableIid(raw)) continue;
        char[16] hex;
        foreach (i, b; raw) {
            hex[i * 2] = digits[b >> 4];
            hex[i * 2 + 1] = digits[b & 0x0f];
        }
        iidHex = hex[].idup;
        return true;
    }
    return false;
}

@("binary /64 composition preserves all four prefix and IID hextets")
unittest {
    assert(ipv6ForConnection("2001:db8:1234:5678::/64", "a516446655440123")
        == "2001:db8:1234:5678:a516:4466:5544:123");
    assert(ipv6ForConnection("2001:0DB8:0000:0000:0000:0000:0000:0000/64", "a516446655440123")
        == "2001:db8::a516:4466:5544:123");
    foreach (prefix; ["", "2001:db8::", "2001:db8::/128", "2001:db8::/48", "2001:db8::1/64",
            "2001:db8:1/64", " 2001:db8::/64", "2001:db8::/64 ", "2001:db8::/064", "2001:db8::%en0/64",
            "::ffff:192.0.2.0/64", "192.0.2.0/64", "fc00::/64", "fe80::/64", "ff02::/64", "::/64", "::1/64"])
        assert(ipv6ForConnection(prefix, "a516446655440123") == "", prefix);
}

@("source membership uses binary prefix boundaries")
unittest {
    assert(ipv6InRoutedPrefix("2001:db8:1:2::/64", "2001:0DB8:0001:0002::1234"));
    foreach (source; ["2001:db8:1:3::1234", "2001:db8:1:20::1234", "::1",
            "2001:db8:1:2::1234%en0", "2001:db8:1:2::1234\0", "192.0.2.1"])
        assert(!ipv6InRoutedPrefix("2001:db8:1:2::/64", source), source);
    assert(!ipv6InRoutedPrefix("2001:db8:1:2::1/64", "2001:db8:1:2::1234"));
}

@("IID syntax, local bit, infrastructure and subnet-anycast reservations are enforced")
unittest {
    assert(validIpv6Iid("a516446655440123"));
    assert(validIpv6Iid("0000000000010000"));
    assert(validIpv6Iid("fdffffffffffff7f"));
    foreach (iid; ["", "a51644665544012", "a5164466554401234", "A516446655440123", "g516446655440123",
            "a716446655440123", "0000000000000000", "000000000000ffff", "fdffffffffffff80", "fdffffffffffffff"])
        assert(ipv6ForConnection("2001:db8::/64", iid) == "", iid);
}

@("generated IID satisfies the source identity constraints")
unittest {
    string iid;
    assert(generateIpv6Iid(iid));
    assert(validIpv6Iid(iid));
}
