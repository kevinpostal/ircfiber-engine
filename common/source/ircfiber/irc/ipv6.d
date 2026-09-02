module ircfiber.irc.ipv6;

import std.uuid : UUID, parseUUID;
import std.string : strip, endsWith, indexOf, toLower;
import std.conv : to;
import std.algorithm : canFind;

// ─────────────────────────────────────────────────────────────────────────────
// IRCCloud-style per-user IPv6 (id-UID → 2001:db8::UID_HEX)
// ─────────────────────────────────────────────────────────────────────────────
// Each IRCCloud user connects from their own unique IPv6 address, mapped
// from their user ID. We replicate that: given a routed /64 (or /48) and
// a stable per-user UUID, derive a deterministic /128 inside the prefix.
//
// Provider gives you e.g. 2001:67c:2f08:1::/64 routed to the VPS.
// User 550e8400-e29b-41d4-a716-446655440000 → take low 64 bits
// (a716:4466:5544:0000) → 2001:67c:2f08:1:a716:4466:5544:0000
// Tiny UIDs: short hex still works, e.g. id 1234 (0x4d2) → ::4d2
// (but we always emit a full 64-bit IID for stability).
//
// Host must allow binding to any address in the prefix without an
// explicit `ip addr add` per user:
//   sysctl -w net.ipv6.ip_nonlocal_bind=1
//   ip -6 route add local <prefix>/64 dev lo
// or `ip addr add` + NDP proxy. The `local` route is cheapest.

/// Strip CIDR suffix (/64, /48...) and whitespace.
string normalizePrefix(string raw) @safe pure {
    auto s = raw.strip();
    if (s.length == 0) return "";
    auto slash = s.indexOf("/");
    if (slash >= 0) s = s[0 .. slash].strip();
    return s;
}

/// True if string looks like an IPv6 prefix (contains colon).
bool isIPv6Prefix(string raw) @safe pure {
    auto p = normalizePrefix(raw);
    return p.length > 0 && p.canFind(":");
}

/// Derive the 64-bit Interface ID hex for a user from their UUID.
/// Takes the low 64 bits (data[8..16]) of the std.uuid UUID, which for
/// v4 UUIDs is random and stable per user. Falls back to FNV-1a of the
/// string form if parsing fails.
string iidHexForUser(UUID uid) @safe pure {
    // UUID data is ubyte[16]; low 64 bits are data[8..16]
    // Format as 16 lowercase hex chars.
    import std.format : format;
    ubyte[16] d = uid.data;
    ulong lo = (cast(ulong) d[8] << 56) | (cast(ulong) d[9] << 48)
             | (cast(ulong) d[10] << 40) | (cast(ulong) d[11] << 32)
             | (cast(ulong) d[12] << 24) | (cast(ulong) d[13] << 16)
             | (cast(ulong) d[14] << 8)  | (cast(ulong) d[15]);
    // Avoid all-zero IID (would collide with subnet-router anycast ::).
    // If lo==0 (nil UUID), use a non-zero sentinel.
    if (lo == 0) lo = 0xFFFF_FFFF_FFFF_FFFEUL;
    return format("%016x", lo);
}

/// FNV-1a 64-bit hash of a string, formatted as 16 hex chars.
/// Used when we only have a string userId (e.g. from Redis) or a non-UUID.
string iidHexForString(string s) @safe pure nothrow {
    import std.format : format;
    ulong h = 14695981039346656037UL;
    foreach (c; s) {
        h ^= cast(ubyte) c;
        h *= 1099511628211UL;
    }
    if (h == 0) h = 0xFFFF_FFFF_FFFF_FFFEUL;
    try return format("%016x", h);
    catch (Exception) return "ffff000000000001";
}

/// Build the full per-user IPv6 address.
/// prefix: e.g. "2001:67c:2f08:1::", "2001:db8:abcd:0012::/64", "2001:db8::1"
// Returns "" if prefix is empty/invalid.
string ipv6ForUser(string prefixRaw, UUID uid) @safe pure {
    auto p = normalizePrefix(prefixRaw);
    if (p.length == 0) return "";
    if (!p.canFind(":")) return "";
    auto iidHex = iidHexForUser(uid);
    return joinPrefixAndIID(p, iidHex);
}

/// String overload: derive IID via FNV-1a of the string (for call sites that
/// only have a string userId).
string ipv6ForUser(string prefixRaw, string userIdStr) @safe pure {
    auto p = normalizePrefix(prefixRaw);
    if (p.length == 0) return "";
    if (!p.canFind(":")) return "";
    if (userIdStr.length == 0) return "";
    // Try to parse as UUID first for stability with the UUID overload.
    try {
        import std.uuid : parseUUID;
        auto uid = parseUUID(userIdStr);
        return ipv6ForUser(prefixRaw, uid);
    } catch (Exception) {}
    auto iidHex = iidHexForString(userIdStr);
    return joinPrefixAndIID(p, iidHex);
}

private string joinPrefixAndIID(string prefix, string iidHex) @safe pure {
    // iidHex is 16 hex chars → 4 groups of 4: aaaa:bbbb:cccc:dddd
    assert(iidHex.length == 16);
    auto g1 = iidHex[0 .. 4];
    auto g2 = iidHex[4 .. 8];
    auto g3 = iidHex[8 .. 12];
    auto g4 = iidHex[12 .. 16];
    auto iid = g1 ~ ":" ~ g2 ~ ":" ~ g3 ~ ":" ~ g4;

    // Normalize prefix handling:
    // - "2001:db8:1::"  → "2001:db8:1:" + iid  (avoid ":::")
    // - "2001:db8:1::/64" already stripped → "2001:db8:1::"
    // - "2001:db8:1:"    → "2001:db8:1:" + iid
    // - "2001:db8:1"     → "2001:db8:1:" + iid
    // - "2001:db8::1"    → "2001:db8::1:" + iid  (rare, but keep)
    if (prefix.endsWith("::")) {
        // Keep the :: compression, append IID directly after it.
        // "2001:db8:1::" + "a716:4466:5544:0000" → "2001:db8:1::a716:4466:5544:0000"
        // But "::" already ends with ":", so just append IID without extra colon.
        return prefix ~ iid;
    } else if (prefix.endsWith(":")) {
        return prefix ~ iid;
    } else {
        return prefix ~ ":" ~ iid;
    }
}

/// Generate the rDNS-style hostname for a user, IRCCloud style:
/// id-1234.highgate.irccloud.com → id-<short>.poolHost
/// For UUIDs we use the first 8 hex chars (or a short hash) as the id.
string rdnsForUser(UUID uid, string poolHost) @safe pure {
    if (poolHost.length == 0) return "";
    auto s = uid.toString();
    // Use first 8 hex chars without dashes as short id (like IRCCloud's integer)
    string hex;
    foreach (c; s) if (c != '-') hex ~= c;
    if (hex.length > 8) hex = hex[0 .. 8];
    return "id-" ~ hex.toLower() ~ "." ~ poolHost;
}

// ── Tests ────────────────────────────────────────────────────────────────────

@("normalizePrefix strips CIDR and whitespace")
unittest {
    assert(normalizePrefix(" 2001:db8::/64 ") == "2001:db8::");
    assert(normalizePrefix("2001:db8::1") == "2001:db8::1");
    assert(normalizePrefix("") == "");
}

@("ipv6ForUser deterministic and valid")
unittest {
    import std.uuid : parseUUID;
    auto uid = parseUUID("550e8400-e29b-41d4-a716-446655440000");
    auto a = ipv6ForUser("2001:67c:2f08:1::", uid);
    auto b = ipv6ForUser("2001:67c:2f08:1::", uid);
    assert(a == b);
    assert(a == "2001:67c:2f08:1::a716:4466:5544:0000");
    // CIDR suffix is ignored
    assert(ipv6ForUser("2001:67c:2f08:1::/64", uid) == a);
    // Different user → different address
    auto uid2 = parseUUID("550e8400-e29b-41d4-a716-446655440001");
    assert(ipv6ForUser("2001:67c:2f08:1::", uid2) != a);
}

@("ipv6ForUser string overload matches UUID overload")
unittest {
    import std.uuid : parseUUID;
    auto uid = parseUUID("550e8400-e29b-41d4-a716-446655440000");
    assert(ipv6ForUser("2001:db8::", uid) == ipv6ForUser("2001:db8::", uid.toString()));
}

@("ipv6ForUser empty prefix returns empty")
unittest {
    import std.uuid : parseUUID;
    auto uid = parseUUID("550e8400-e29b-41d4-a716-446655440000");
    assert(ipv6ForUser("", uid) == "");
    assert(ipv6ForUser("not-an-ipv6", uid) == "");
}

@("ipv6ForUser prefix without :: still works")
unittest {
    import std.uuid : parseUUID;
    auto uid = parseUUID("550e8400-e29b-41d4-a716-446655440000");
    // Prefix without trailing :: gets a colon inserted
    assert(ipv6ForUser("2001:db8:1", uid) == "2001:db8:1:a716:4466:5544:0000");
    assert(ipv6ForUser("2001:db8:1:", uid) == "2001:db8:1:a716:4466:5544:0000");
}

@("nil UUID does not produce ::")
unittest {
    import std.uuid : UUID;
    auto nil = UUID.init;
    auto a = ipv6ForUser("2001:db8::", nil);
    assert(a.length > 0);
    assert(a != "2001:db8::0000:0000:0000:0000");
}

@("rdnsForUser formats id-xxxx.pool")
unittest {
    import std.uuid : parseUUID;
    auto uid = parseUUID("550e8400-e29b-41d4-a716-446655440000");
    assert(rdnsForUser(uid, "highgate.irccloud.com") == "id-550e8400.highgate.irccloud.com");
    assert(rdnsForUser(uid, "") == "");
}
