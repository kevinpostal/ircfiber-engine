/// IRCv3 `draft/metadata-2` key registry and value validation shared by the
/// engine (inbound METADATA lines, outbound profile SETs), the gateway REST
/// profile endpoint and the bouncer.
module ircfiber.metadata;

/// Registry user keys we store and surface (https://ircv3.net/registry#metadata-keys).
immutable string[] USER_METADATA_KEYS = ["avatar", "bot", "color", "display-name", "homepage", "pronouns", "status"];
/// Registry channel keys we store and surface.
immutable string[] CHANNEL_METADATA_KEYS = ["avatar", "display-name"];
/// Keys a user may set on themselves via the web UI or the bouncer.
immutable string[] PROFILE_KEYS = ["display-name", "pronouns", "status", "homepage", "color"]; // user-settable via web/bouncer
/// Matches the ircd's advertised `draft/metadata-2=max-value-bytes=512`.
enum MAX_METADATA_VALUE_BYTES = 512;

/// avatar, homepage: starts with http:// or https:// (ASCII case-insensitive), no whitespace.
/// color: exactly '#' + 6 hex digits.
/// others: valid UTF-8 (std.utf.validate), no byte < 0x20, no 0x7F.
/// All: 1..MAX_METADATA_VALUE_BYTES bytes.
bool isValidMetadataValue(string key, string value) @safe pure nothrow {
    if (value.length == 0 || value.length > MAX_METADATA_VALUE_BYTES) return false;

    switch (key) {
    case "avatar":
    case "homepage":
        if (!hasHttpScheme(value)) return false;
        foreach (char c; value) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') return false;
        }
        return true;
    case "color":
        if (value.length != 7 || value[0] != '#') return false;
        foreach (char c; value[1 .. $]) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
        }
        return true;
    default:
        foreach (char c; value) {
            if (c < 0x20 || c == 0x7F) return false;
        }
        import std.utf : validate;
        try validate(value);
        catch (Exception) return false;
        return true;
    }
}

private bool hasHttpScheme(string value) @safe pure nothrow @nogc {
    static bool prefixCi(string s, string prefix) @safe pure nothrow @nogc {
        if (s.length < prefix.length) return false;
        foreach (i, char p; prefix) {
            char c = s[i];
            if (c >= 'A' && c <= 'Z') c = cast(char)(c + 32);
            if (c != p) return false;
        }
        return true;
    }
    return prefixCi(value, "http://") || prefixCi(value, "https://");
}

@("isValidMetadataValue accepts and rejects per key class")
unittest {
    // avatar / homepage: http(s) URL, scheme case-insensitive, no whitespace.
    assert(isValidMetadataValue("avatar", "https://example.com/a.png"));
    assert(isValidMetadataValue("homepage", "HTTP://Example.com"));
    assert(!isValidMetadataValue("avatar", "ftp://example.com/a.png"));
    assert(!isValidMetadataValue("homepage", "https://example.com/a b"));
    assert(!isValidMetadataValue("homepage", "javascript:alert(1)"));

    // color: '#' + exactly 6 hex digits.
    assert(isValidMetadataValue("color", "#800040"));
    assert(isValidMetadataValue("color", "#AbCdEf"));
    assert(!isValidMetadataValue("color", "red"));
    assert(!isValidMetadataValue("color", "#12345"));
    assert(!isValidMetadataValue("color", "#12345g"));

    // others: valid UTF-8, no C0 controls, no DEL.
    assert(isValidMetadataValue("pronouns", "they/them"));
    assert(isValidMetadataValue("display-name", "Zoë ✨"));
    assert(!isValidMetadataValue("status", "line\nbreak"));
    assert(!isValidMetadataValue("display-name", "del\x7F"));
    assert(!isValidMetadataValue("display-name", "bad\xFFutf8"));

    // All keys: non-empty.
    assert(!isValidMetadataValue("pronouns", ""));
    assert(!isValidMetadataValue("avatar", ""));
}

@("isValidMetadataValue enforces the 512-byte boundary")
unittest {
    import std.array : replicate;
    assert(isValidMetadataValue("status", "a".replicate(MAX_METADATA_VALUE_BYTES)));
    assert(!isValidMetadataValue("status", "a".replicate(MAX_METADATA_VALUE_BYTES + 1)));
    enum prefix = "https://e.x/";
    assert(isValidMetadataValue("avatar", prefix ~ "a".replicate(MAX_METADATA_VALUE_BYTES - prefix.length)));
    assert(!isValidMetadataValue("avatar", prefix ~ "a".replicate(MAX_METADATA_VALUE_BYTES - prefix.length + 1)));
}
