/// FIBERMLS peer-discovery control protocol: strict CTCP framing, ticket
/// material and the roster-identity checks the issuing engine needs.
///
/// Wire (private, single line, never split):
///
/// ```
/// PRIVMSG <peer>      :\x01FIBERMLS 1 QUERY <nonce> <channel64>\x01
/// NOTICE  <requester> :\x01FIBERMLS 1 ID <nonce> <ticket>\x01
/// ```
///
/// `nonce` and `ticket` are 32 random bytes as 64 lowercase hex characters;
/// `channel64` is the channel's UTF-8 bytes as unpadded base64url. Any text
/// whose CTCP command is `FIBERMLS` (in any letter case) is reserved: it is
/// either one exact packet or noise the caller consumes without rendering.
///
/// Pure apart from `generateTicketHex` (OpenSSL RAND_bytes). Parsing slices
/// its input; the only allocation is the decoded channel.
module ircfiber.irc.mls_peer;

import std.conv : to;
import std.json : JSONValue;
import std.uni : toLower;

enum FIBERMLS_COMMAND = "FIBERMLS";
enum FIBERMLS_VERSION = "1";
/// Hex characters in a nonce or ticket (32 bytes).
enum FIBERMLS_TOKEN_HEX_LEN = 64;
/// Upper bound on a decoded channel name, independent of the payload limit.
enum FIBERMLS_MAX_CHANNEL_BYTES = 200;
/// Lifetime of an issued ticket.
enum FIBERMLS_TICKET_TTL_SECS = 30;
/// RFC default when the server has not advertised PREFIX.
enum DEFAULT_PREFIX_SYMBOLS = "@+";

private enum char SOH = '\x01';
private enum QUERY_HEAD = "\x01FIBERMLS 1 QUERY ";
private enum ID_HEAD = "\x01FIBERMLS 1 ID ";

enum FiberMlsKind : ubyte {
    /// Not a FIBERMLS packet: existing CTCP/message handling applies.
    notReserved,
    /// Reserved but not one exact packet: consume silently.
    malformed,
    /// Reserved, well formed up to a version this engine does not speak.
    unsupportedVersion,
    /// Reserved and longer than the negotiated payload limit.
    oversized,
    query,
    id,
}

struct FiberMlsPacket {
    FiberMlsKind kind;
    /// Slice of the input; set for `query` and `id`.
    string nonce;
    /// Slice of the input; set for `id`.
    string ticket;
    /// Decoded, validated channel (not casemapped); set for `query`.
    string channel;

    /// Whether the line belongs to the protocol and must not reach chat,
    /// query tracking, history or notifications.
    bool isControl() const @safe pure nothrow @nogc {
        return kind != FiberMlsKind.notReserved;
    }
}

/// Whether `text` claims the reserved CTCP command: SOH then `FIBERMLS`
/// (ASCII case-insensitive) ended by space, SOH or end of text.
bool isReservedFiberMls(string text) @safe pure nothrow @nogc {
    enum n = FIBERMLS_COMMAND.length;
    if (text.length < 1 + n || text[0] != SOH) return false;
    foreach (i, c; FIBERMLS_COMMAND) {
        char t = text[1 + i];
        if (t >= 'a' && t <= 'z') t = cast(char)(t - ('a' - 'A'));
        if (t != c) return false;
    }
    return text.length == 1 + n || text[1 + n] == ' ' || text[1 + n] == SOH;
}

/// Parses one PRIVMSG/NOTICE trailing parameter. Command-agnostic: the
/// caller answers only a PRIVMSG `query` and accepts only a NOTICE `id`;
/// every other control result is consumed without a reply.
///
/// `maxPayloadBytes` is the negotiated payload limit for this line;
/// `chantypes` is ISUPPORT CHANTYPES (RFC default `#&` when absent).
FiberMlsPacket parseFiberMls(string text, size_t maxPayloadBytes, string chantypes = "#&") @safe pure nothrow {
    FiberMlsPacket p;
    if (!isReservedFiberMls(text)) return p;
    if (text.length > maxPayloadBytes) {
        p.kind = FiberMlsKind.oversized;
        return p;
    }
    p.kind = FiberMlsKind.malformed;
    if (text.length < 2 || text[$ - 1] != SOH) return p;
    const inner = text[1 .. $ - 1];

    // Exactly single-space separated, no empty token, no stray framing.
    string[6] tok;
    size_t n = 0;
    size_t start = 0;
    foreach (i; 0 .. inner.length + 1) {
        if (i < inner.length) {
            const c = inner[i];
            if (c == SOH || c == '\r' || c == '\n' || c == '\0') return p;
            if (c != ' ') continue;
        }
        if (i == start || n == tok.length) return p;
        tok[n++] = inner[start .. i];
        start = i + 1;
    }
    if (n < 2 || tok[0] != FIBERMLS_COMMAND) return p;
    if (tok[1] != FIBERMLS_VERSION) {
        if (isVersionToken(tok[1])) p.kind = FiberMlsKind.unsupportedVersion;
        return p;
    }
    if (n != 5 || !isLowerHex64(tok[3])) return p;

    if (tok[2] == "QUERY") {
        string channel;
        if (!decodeChannel64(tok[4], chantypes, channel)) return p;
        p.nonce = tok[3];
        p.channel = channel;
        p.kind = FiberMlsKind.query;
    } else if (tok[2] == "ID") {
        if (!isLowerHex64(tok[4])) return p;
        p.nonce = tok[3];
        p.ticket = tok[4];
        p.kind = FiberMlsKind.id;
    }
    return p;
}

private bool isVersionToken(string s) @safe pure nothrow @nogc {
    if (s.length == 0 || s.length > 4) return false;
    foreach (c; s) if (c < '0' || c > '9') return false;
    return true;
}

/// CTCP body of a discovery query, SOH included; null when the nonce or
/// channel is invalid or the packet exceeds `maxPayloadBytes`.
string buildFiberMlsQuery(string nonce, string channel, size_t maxPayloadBytes,
                          string chantypes = "#&") @trusted pure nothrow {
    if (!isLowerHex64(nonce) || !isValidFiberChannel(channel, chantypes)) return null;
    const encLen = base64UrlLength(channel.length);
    const total = QUERY_HEAD.length + nonce.length + 1 + encLen + 1;
    if (total > maxPayloadBytes) return null;
    auto buf = new char[total];
    size_t o = 0;
    buf[o .. o + QUERY_HEAD.length] = QUERY_HEAD;
    o += QUERY_HEAD.length;
    buf[o .. o + nonce.length] = nonce;
    o += nonce.length;
    buf[o++] = ' ';
    o += encodeBase64Url(cast(const(ubyte)[]) channel, buf[o .. o + encLen]);
    buf[o] = SOH;
    return cast(string) buf;
}

/// CTCP body of an ID reply, SOH included; null when a token is invalid or
/// the packet exceeds `maxPayloadBytes`.
string buildFiberMlsId(string nonce, string ticket, size_t maxPayloadBytes) @safe pure nothrow {
    if (!isLowerHex64(nonce) || !isLowerHex64(ticket)) return null;
    if (ID_HEAD.length + nonce.length + 1 + ticket.length + 1 > maxPayloadBytes) return null;
    return ID_HEAD ~ nonce ~ " " ~ ticket ~ "\x01";
}

/// Exactly 64 characters of `[0-9a-f]`.
bool isLowerHex64(string s) @safe pure nothrow @nogc {
    if (s.length != FIBERMLS_TOKEN_HEX_LEN) return false;
    foreach (c; s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// ── Channels ─────────────────────────────────────────────────────────────────

/// Nonempty, at most `FIBERMLS_MAX_CHANNEL_BYTES`, strict UTF-8, first byte
/// in `chantypes`, and free of space, comma and control characters.
bool isValidFiberChannel(const(char)[] channel, string chantypes) @safe pure nothrow @nogc {
    if (channel.length < 2 || channel.length > FIBERMLS_MAX_CHANNEL_BYTES) return false;
    bool typed = false;
    foreach (t; chantypes) if (t == channel[0]) { typed = true; break; }
    if (!typed) return false;
    foreach (c; channel)
        if (c < 0x20 || c == 0x7F || c == ' ' || c == ',') return false;
    return isStrictUtf8(channel);
}

/// Unpadded base64url of the channel's bytes.
string encodeChannel64(string channel) @trusted pure nothrow {
    auto buf = new char[base64UrlLength(channel.length)];
    encodeBase64Url(cast(const(ubyte)[]) channel, buf);
    return cast(string) buf;
}

/// Strict unpadded base64url decode of a channel: url alphabet only, no
/// padding, zero trailing bits, then `isValidFiberChannel`. One allocation,
/// only on success.
bool decodeChannel64(string encoded, string chantypes, out string channel) @trusted pure nothrow {
    enum maxEncoded = base64UrlLength(FIBERMLS_MAX_CHANNEL_BYTES);
    if (encoded.length == 0 || encoded.length > maxEncoded || encoded.length % 4 == 1)
        return false;
    char[FIBERMLS_MAX_CHANNEL_BYTES] buf = void;
    size_t o = 0;
    uint acc = 0;
    uint bits = 0;
    foreach (c; encoded) {
        const v = base64UrlValue(c);
        if (v < 0) return false;
        acc = (acc << 6) | cast(uint) v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            buf[o++] = cast(char)((acc >> bits) & 0xFF);
        }
    }
    // Leftover bits (2 or 4) must be zero: one encoding per channel.
    if ((acc & ((1u << bits) - 1)) != 0) return false;
    if (!isValidFiberChannel(buf[0 .. o], chantypes)) return false;
    channel = buf[0 .. o].idup;
    return true;
}

/// Length of the unpadded base64 encoding of `n` bytes.
size_t base64UrlLength(size_t n) @safe pure nothrow @nogc {
    return (n * 4 + 2) / 3;
}

private immutable char[64] B64URL =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

private int base64UrlValue(char c) @safe pure nothrow @nogc {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

/// Writes the unpadded base64url of `src` into `dst`, which must hold
/// `base64UrlLength(src.length)` characters; returns that length.
private size_t encodeBase64Url(const(ubyte)[] src, char[] dst) @safe pure nothrow @nogc {
    size_t o = 0;
    size_t i = 0;
    for (; i + 3 <= src.length; i += 3) {
        const v = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2];
        dst[o++] = B64URL[(v >> 18) & 63];
        dst[o++] = B64URL[(v >> 12) & 63];
        dst[o++] = B64URL[(v >> 6) & 63];
        dst[o++] = B64URL[v & 63];
    }
    const rest = src.length - i;
    if (rest == 1) {
        const v = src[i] << 16;
        dst[o++] = B64URL[(v >> 18) & 63];
        dst[o++] = B64URL[(v >> 12) & 63];
    } else if (rest == 2) {
        const v = (src[i] << 16) | (src[i + 1] << 8);
        dst[o++] = B64URL[(v >> 18) & 63];
        dst[o++] = B64URL[(v >> 12) & 63];
        dst[o++] = B64URL[(v >> 6) & 63];
    }
    return o;
}

/// Well-formed UTF-8: no overlongs, surrogates or code points past U+10FFFF.
bool isStrictUtf8(const(char)[] s) @safe pure nothrow @nogc {
    size_t i = 0;
    while (i < s.length) {
        const ubyte b = s[i];
        if (b < 0x80) { i++; continue; }
        size_t n;
        uint cp;
        uint min;
        if ((b & 0xE0) == 0xC0)      { n = 1; cp = b & 0x1F; min = 0x80; }
        else if ((b & 0xF0) == 0xE0) { n = 2; cp = b & 0x0F; min = 0x800; }
        else if ((b & 0xF8) == 0xF0) { n = 3; cp = b & 0x07; min = 0x10000; }
        else return false;
        if (s.length - i <= n) return false;
        foreach (k; 1 .. n + 1) {
            const ubyte c = s[i + k];
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += n + 1;
    }
    return true;
}

// ── CASEMAPPING ──────────────────────────────────────────────────────────────
// Same semantics as connection.d's foldCaseChar: "ascii" folds A-Z only,
// "rfc1459-strict" also maps []\ to {}|, and every other value (including
// absent/unknown) is rfc1459, which additionally maps ^ to ~. Bytes >= 0x80
// are never folded, so UTF-8 channel names stay byte-exact outside ASCII.

char foldIrcChar(char c, string mapping) @safe pure nothrow @nogc {
    if (c >= 'A' && c <= 'Z') return cast(char)(c + ('a' - 'A'));
    if (mapping == "ascii") return c;
    switch (c) {
        case '[': return '{';
        case ']': return '}';
        case '\\': return '|';
        case '^': return mapping == "rfc1459-strict" ? '^' : '~';
        default: return c;
    }
}

bool ircNamesEqual(const(char)[] a, const(char)[] b, string mapping) @safe pure nothrow @nogc {
    if (a.length != b.length) return false;
    foreach (i; 0 .. a.length)
        if (foldIrcChar(a[i], mapping) != foldIrcChar(b[i], mapping)) return false;
    return true;
}

/// `channel` folded per CASEMAPPING: the ticket's scope and the key both
/// engines and the backend compare. Returns the input when already folded.
string normalizeFiberChannel(string channel, string mapping) @trusted pure nothrow {
    size_t first = channel.length;
    foreach (i, c; channel)
        if (foldIrcChar(c, mapping) != c) { first = i; break; }
    if (first == channel.length) return channel;
    auto buf = new char[channel.length];
    buf[0 .. first] = channel[0 .. first];
    foreach (i; first .. channel.length) buf[i] = foldIrcChar(channel[i], mapping);
    return cast(string) buf;
}

/// Canonical network scope: lowercased configured host, colon, port. Must
/// match the backend's `canonicalNetworkKey`.
string canonicalNetworkKey(string host, ushort port) @safe pure {
    return toLower(host) ~ ":" ~ port.to!string;
}

// ── Tickets ──────────────────────────────────────────────────────────────────

string lowerHex(const(ubyte)[] bytes) @trusted pure nothrow {
    enum digits = "0123456789abcdef";
    auto buf = new char[bytes.length * 2];
    foreach (i, b; bytes) {
        buf[2 * i] = digits[b >> 4];
        buf[2 * i + 1] = digits[b & 0x0F];
    }
    return cast(string) buf;
}

/// Fresh ticket: 32 bytes from OpenSSL RAND_bytes as lowercase hex. False,
/// with `hex` null, unless RAND_bytes reports success; there is no fallback.
bool generateTicketHex(out string hex) @trusted {
    import deimos.openssl.rand : RAND_bytes;

    ubyte[FIBERMLS_TOKEN_HEX_LEN / 2] raw = void;
    if (RAND_bytes(raw.ptr, cast(int) raw.length) != 1) return false;
    hex = lowerHex(raw[]);
    raw[] = 0;
    return true;
}

/// Stored value of `irc:mls:peer:<ticket>`. The backend compares the exact
/// stored string on consumption, so the value is written once and never
/// rebuilt.
struct PeerTicket {
    string networkId;
    string ownerId;
    string serverId;
    long connectedAtMs;
    string issuerPrefix;
    string requesterPrefix;
    string networkKey;
    /// CASEMAPPING-normalized channel.
    string channel;
    string nonce;
    /// Unix milliseconds.
    long issuedAt;

    string toJson() const @safe {
        JSONValue v = [
            "version": JSONValue(1),
            "networkId": JSONValue(networkId),
            "ownerId": JSONValue(ownerId),
            "serverId": JSONValue(serverId),
            "connectedAtMs": JSONValue(connectedAtMs),
            "issuerPrefix": JSONValue(issuerPrefix),
            "requesterPrefix": JSONValue(requesterPrefix),
            "networkKey": JSONValue(networkKey),
            "channel": JSONValue(channel),
            "nonce": JSONValue(nonce),
            "issuedAt": JSONValue(issuedAt),
        ];
        return v.toString();
    }
}

// ── Prefix and roster identity ───────────────────────────────────────────────

struct IrcPrefix {
    string nick;
    string user;
    string host;
}

/// Strict `nick!user@host`: three nonempty parts, one `!` and one `@`, no
/// whitespace or control bytes. Slices the input.
bool parseFullPrefix(string prefix, out IrcPrefix result) @safe pure nothrow @nogc {
    ptrdiff_t bang = -1;
    ptrdiff_t at = -1;
    foreach (i, c; prefix) {
        if (c <= ' ' || c == 0x7F) return false;
        if (c == '!') {
            if (bang >= 0 || at >= 0) return false;
            bang = i;
        } else if (c == '@') {
            if (at >= 0 || bang < 0) return false;
            at = i;
        }
    }
    if (bang <= 0 || at <= bang + 1 || at + 1 >= prefix.length) return false;
    result = IrcPrefix(prefix[0 .. bang], prefix[bang + 1 .. at], prefix[at + 1 .. $]);
    return true;
}

/// Same connection identity: nick equal under CASEMAPPING, user and host
/// byte-exact. No relaxation for cloaks or idents.
bool sameIdentity(in IrcPrefix a, in IrcPrefix b, string mapping) @safe pure nothrow @nogc {
    return a.nick.length && a.user.length && a.host.length
        && ircNamesEqual(a.nick, b.nick, mapping) && a.user == b.user && a.host == b.host;
}

/// Status symbols of an ISUPPORT PREFIX value: `(qaohv)~&@%+` → `~&@%+`.
/// Empty or malformed values grant no assumed mode symbols. Callers use
/// the RFC default only when the server has not advertised PREFIX.
string prefixSymbolsFromIsupport(string token) @safe pure nothrow @nogc {
    if (token.length == 0) return "";
    if (token[0] != '(') return "";
    foreach (i, c; token) {
        if (c != ')') continue;
        const modes = i - 1;
        const symbols = token[i + 1 .. $];
        if (modes == 0 || symbols.length != modes) return "";
        return symbols;
    }
    return "";
}

struct RosterIdentity {
    string nick;
    string user;
    string host;
    /// Entry carried a complete `!user@host`.
    bool hasHostmask;
    /// Entry carried a `!` or `@` that is not a complete hostmask.
    bool malformed;
}

/// Splits a roster entry `[status...]nick[!user@host]` using the network's
/// PREFIX `symbols`. Slices the input.
RosterIdentity parseRosterEntry(string entry, string symbols) @safe pure nothrow @nogc {
    size_t start = 0;
    outer: while (start < entry.length) {
        foreach (s; symbols) if (s == entry[start]) { start++; continue outer; }
        break;
    }
    const name = entry[start .. $];
    RosterIdentity r;
    ptrdiff_t bang = -1;
    foreach (i, c; name) if (c == '!' || c == '@') { bang = i; break; }
    if (bang < 0) {
        r.nick = name;
        return r;
    }
    r.nick = name[0 .. bang];
    IrcPrefix p;
    if (name[bang] == '!' && parseFullPrefix(name, p)) {
        r.user = p.user;
        r.host = p.host;
        r.hasHostmask = true;
    } else {
        r.malformed = true;
    }
    return r;
}

enum RosterMatch : ubyte {
    /// No entry with the source's nick.
    absent,
    /// Nick present but no entry states user@host: not proof.
    unverified,
    /// An entry states exactly the source's user@host and none contradicts it.
    match,
    /// An entry for the nick states a different or malformed hostmask.
    conflict,
}

/// Checks a request's server-observed `source` prefix against one channel
/// roster. Only `match` is sufficient to issue a ticket.
RosterMatch matchRosterIdentity(const(string)[] roster, in IrcPrefix source, string symbols,
                                string mapping) @safe pure nothrow @nogc {
    if (source.nick.length == 0 || source.user.length == 0 || source.host.length == 0)
        return RosterMatch.conflict;
    auto result = RosterMatch.absent;
    foreach (entry; roster) {
        const id = parseRosterEntry(entry, symbols);
        if (id.nick.length == 0 || !ircNamesEqual(id.nick, source.nick, mapping)) continue;
        if (id.malformed) return RosterMatch.conflict;
        if (!id.hasHostmask) {
            if (result == RosterMatch.absent) result = RosterMatch.unverified;
            continue;
        }
        if (id.user != source.user || id.host != source.host) return RosterMatch.conflict;
        result = RosterMatch.match;
    }
    return result;
}

// ── Tests ────────────────────────────────────────────────────────────────────

version (unittest) {
    private enum N1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private enum T1 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    private enum LIMIT = 400;

    private FiberMlsKind kindOf(string text, size_t limit = LIMIT) {
        return parseFiberMls(text, limit).kind;
    }
}

@("FIBERMLS parses an exact QUERY and decodes the channel")
unittest {
    const p = parseFiberMls("\x01FIBERMLS 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmc\x01", LIMIT);
    assert(p.kind == FiberMlsKind.query);
    assert(p.isControl);
    assert(p.nonce == N1);
    assert(p.channel == "#testing");
    assert(p.ticket is null);
}

@("FIBERMLS parses an exact ID reply")
unittest {
    const p = parseFiberMls("\x01FIBERMLS 1 ID " ~ N1 ~ " " ~ T1 ~ "\x01", LIMIT);
    assert(p.kind == FiberMlsKind.id);
    assert(p.nonce == N1 && p.ticket == T1);
    assert(p.channel is null);
}

@("FIBERMLS leaves other text and CTCP untouched")
unittest {
    assert(kindOf("hello") == FiberMlsKind.notReserved);
    assert(kindOf("FIBERMLS 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmc") == FiberMlsKind.notReserved);
    assert(kindOf("\x01VERSION\x01") == FiberMlsKind.notReserved);
    assert(kindOf("\x01ACTION waves\x01") == FiberMlsKind.notReserved);
    assert(kindOf("\x01FIBERMLSX 1\x01") == FiberMlsKind.notReserved);
    assert(kindOf("\x01 FIBERMLS 1\x01") == FiberMlsKind.notReserved);
    assert(kindOf("") == FiberMlsKind.notReserved);
    assert(!parseFiberMls("\x01PING 1\x01", LIMIT).isControl);
}

@("FIBERMLS consumes reserved framing errors as malformed")
unittest {
    const q = "FIBERMLS 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmc";
    assert(kindOf("\x01" ~ q) == FiberMlsKind.malformed);              // no closing SOH
    assert(kindOf("\x01" ~ q ~ "\x01\x01") == FiberMlsKind.malformed); // doubled SOH
    assert(kindOf("\x01" ~ q ~ "\x01 ") == FiberMlsKind.malformed);    // trailing text
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1 ~ "\x01I3Rlc3Rpbmc\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01" ~ q ~ "\r\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01" ~ q ~ "\n\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS") == FiberMlsKind.malformed);
    assert(kindOf("\x01fibermls 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmc\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FiberMLS 1 ID " ~ N1 ~ " " ~ T1 ~ "\x01") == FiberMlsKind.malformed);
    assert(parseFiberMls("\x01FIBERMLS\x01", LIMIT).isControl);
}

@("FIBERMLS requires exact single-space token counts")
unittest {
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1 ~ "\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmc extra\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 QUERY  " ~ N1 ~ " I3Rlc3Rpbmc\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmc \x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS  1 ID " ~ N1 ~ " " ~ T1 ~ "\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 ID " ~ N1 ~ "\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 ID " ~ N1 ~ " " ~ T1 ~ " x\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 ID " ~ N1 ~ "\t" ~ T1 ~ "\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 HELLO " ~ N1 ~ " " ~ T1 ~ "\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 query " ~ N1 ~ " I3Rlc3Rpbmc\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 a b c d e f g\x01") == FiberMlsKind.malformed);
}

@("FIBERMLS distinguishes unsupported versions from junk")
unittest {
    assert(kindOf("\x01FIBERMLS 2 QUERY " ~ N1 ~ " I3Rlc3Rpbmc\x01") == FiberMlsKind.unsupportedVersion);
    assert(kindOf("\x01FIBERMLS 10\x01") == FiberMlsKind.unsupportedVersion);
    assert(kindOf("\x01FIBERMLS 01 ID " ~ N1 ~ " " ~ T1 ~ "\x01") == FiberMlsKind.unsupportedVersion);
    assert(kindOf("\x01FIBERMLS v1 ID " ~ N1 ~ " " ~ T1 ~ "\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 12345\x01") == FiberMlsKind.malformed);
}

@("FIBERMLS requires lowercase 64-hex nonce and ticket")
unittest {
    import std.string : toUpper;

    assert(isLowerHex64(N1));
    assert(!isLowerHex64(N1.toUpper));
    assert(!isLowerHex64(N1[0 .. 63]));
    assert(!isLowerHex64(N1 ~ "0"));
    assert(!isLowerHex64(N1[0 .. 63] ~ "g"));
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1.toUpper ~ " I3Rlc3Rpbmc\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1[0 .. 62] ~ " I3Rlc3Rpbmc\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 ID " ~ N1 ~ " " ~ T1[0 .. 63] ~ "Z\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 ID " ~ N1[1 .. $] ~ " " ~ T1 ~ "\x01") == FiberMlsKind.malformed);
}

@("FIBERMLS base64url channel decoding is strict")
unittest {
    string ch;
    assert(decodeChannel64("I3Rlc3Rpbmc", "#&", ch) && ch == "#testing");
    assert(decodeChannel64("I2NhZsOp", "#&", ch) && ch == "#café");
    assert(decodeChannel64("I2E", "#&", ch) && ch == "#a");
    assert(!decodeChannel64("I2F", "#&", ch));          // nonzero trailing bits
    assert(!decodeChannel64("I3Rlc3Rpbmd", "#&", ch));  // nonzero trailing bits
    assert(!decodeChannel64("I3Rlc3Rpbmc=", "#&", ch)); // padding
    assert(!decodeChannel64("I3Rlc", "#&", ch));        // length % 4 == 1
    assert(!decodeChannel64("I+2ggA", "#&", ch));       // standard alphabet
    assert(!decodeChannel64("I/Rl", "#&", ch));
    assert(!decodeChannel64("I3Rl c3Rp", "#&", ch));
    assert(!decodeChannel64("", "#&", ch));
    assert(ch is null);
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmc=\x01") == FiberMlsKind.malformed);
    assert(kindOf("\x01FIBERMLS 1 QUERY " ~ N1 ~ " I3Rlc3Rpbmd\x01") == FiberMlsKind.malformed);
}

@("FIBERMLS channel must be valid UTF-8 and a channel name")
unittest {
    string ch;
    assert(!decodeChannel64(encodeChannel64("\x23\xC0\xAF"), "#&", ch));     // overlong
    assert(!decodeChannel64(encodeChannel64("\x23\xED\xA0\x80"), "#&", ch)); // surrogate
    assert(!decodeChannel64(encodeChannel64("\x23\xF4\x90\x80\x80"), "#&", ch)); // > U+10FFFF
    assert(!decodeChannel64(encodeChannel64("\x23\xC3"), "#&", ch));         // truncated
    assert(!decodeChannel64(encodeChannel64("\x23\x80"), "#&", ch));         // stray continuation
    assert(!decodeChannel64("dGVzdGluZw", "#&", ch));                        // "testing": no chantype
    assert(!decodeChannel64("I2EgYg", "#&", ch));                            // space
    assert(!decodeChannel64("I2EsYg", "#&", ch));                            // comma
    assert(!decodeChannel64("I3QH", "#&", ch));                              // BEL
    assert(!decodeChannel64(encodeChannel64("#a\x00"), "#&", ch));           // NUL
    assert(!decodeChannel64("I3Rlc3Rpbmc", "&", ch));                        // CHANTYPES respected
    assert(!decodeChannel64("I3Rlc3Rpbmc", "", ch));
    assert(!decodeChannel64(encodeChannel64("#"), "#&", ch));
    assert(decodeChannel64(encodeChannel64("#\xF0\x9F\x94\x92"), "#", ch) && ch == "#\xF0\x9F\x94\x92");
}

@("FIBERMLS bounds channel length and negotiated payload size")
unittest {
    import std.array : replicate;

    const longest = "#" ~ "a".replicate(FIBERMLS_MAX_CHANNEL_BYTES - 1);
    string ch;
    assert(decodeChannel64(encodeChannel64(longest), "#", ch) && ch == longest);
    assert(!decodeChannel64(encodeChannel64(longest ~ "a"), "#", ch));

    const id = "\x01FIBERMLS 1 ID " ~ N1 ~ " " ~ T1 ~ "\x01";
    assert(kindOf(id, id.length) == FiberMlsKind.id);
    assert(kindOf(id, id.length - 1) == FiberMlsKind.oversized);
    assert(parseFiberMls(id, id.length - 1).isControl);
    assert(kindOf("\x01FIBERMLS junk\x01", 5) == FiberMlsKind.oversized);
    assert(kindOf("plain text", 1) == FiberMlsKind.notReserved);
}

@("FIBERMLS builders emit exactly what the parser accepts")
unittest {
    const q = buildFiberMlsQuery(N1, "#café", LIMIT);
    assert(q == "\x01FIBERMLS 1 QUERY " ~ N1 ~ " I2NhZsOp\x01");
    const pq = parseFiberMls(q, q.length);
    assert(pq.kind == FiberMlsKind.query && pq.channel == "#café" && pq.nonce == N1);
    assert(buildFiberMlsQuery(N1, "#café", q.length - 1) is null);
    assert(buildFiberMlsQuery(N1, "nochan", LIMIT) is null);
    assert(buildFiberMlsQuery(N1[1 .. $], "#a", LIMIT) is null);

    const r = buildFiberMlsId(N1, T1, LIMIT);
    assert(r.length == 145);
    const pr = parseFiberMls(r, r.length);
    assert(pr.kind == FiberMlsKind.id && pr.nonce == N1 && pr.ticket == T1);
    assert(buildFiberMlsId(N1, T1, 144) is null);
    assert(buildFiberMlsId(N1, "TICKET", LIMIT) is null);

}

@("FIBERMLS channel normalization follows CASEMAPPING")
unittest {
    assert(normalizeFiberChannel("#Testing", "ascii") == "#testing");
    assert(normalizeFiberChannel("#A[b]^", "rfc1459") == "#a{b}~");
    assert(normalizeFiberChannel("#A[b]^", "rfc1459-strict") == "#a{b}^");
    assert(normalizeFiberChannel("#A[b]^", "ascii") == "#a[b]^");
    assert(normalizeFiberChannel("#CAFÉ", "rfc1459") == "#cafÉ");
    const already = "#testing";
    assert(normalizeFiberChannel(already, "rfc1459") is already);
    assert(ircNamesEqual("Zod[1]", "zod{1}", "rfc1459"));
    assert(!ircNamesEqual("Zod[1]", "zod{1}", "ascii"));
    assert(canonicalNetworkKey("IRC.GangNet.org", 6697) == "irc.gangnet.org:6697");
}

@("FIBERMLS ticket JSON and hex encoding")
unittest {
    import std.json : parseJSON;

    assert(lowerHex([0x00, 0x0f, 0xa5, 0xff]) == "000fa5ff");
    const t = PeerTicket("net-1", "owner-1", "srv-1", 1_700_000_000_123, "Carlo!c@host.a",
                         "Zod!z@host.b", "irc.gangnet.org:6697", "#testing", N1, 1_700_000_001_000);
    const j = parseJSON(t.toJson());
    assert(j["version"].integer == 1);
    assert(j["networkId"].str == "net-1");
    assert(j["ownerId"].str == "owner-1");
    assert(j["serverId"].str == "srv-1");
    assert(j["connectedAtMs"].integer == 1_700_000_000_123);
    assert(j["issuerPrefix"].str == "Carlo!c@host.a");
    assert(j["requesterPrefix"].str == "Zod!z@host.b");
    assert(j["networkKey"].str == "irc.gangnet.org:6697");
    assert(j["channel"].str == "#testing");
    assert(j["nonce"].str == N1);
    assert(j["issuedAt"].integer == 1_700_000_001_000);
    assert(j.object.length == 11);
}

@("FIBERMLS ticket generation yields distinct lowercase hex")
unittest {
    string a, b;
    assert(generateTicketHex(a) && generateTicketHex(b));
    assert(isLowerHex64(a) && isLowerHex64(b) && a != b);
}

@("FIBERMLS full prefixes parse strictly")
unittest {
    IrcPrefix p;
    assert(parseFullPrefix("Carlo!~carlo@gang.net", p));
    assert(p.nick == "Carlo" && p.user == "~carlo" && p.host == "gang.net");
    assert(!parseFullPrefix("Carlo", p));
    assert(!parseFullPrefix("irc.gangnet.org", p));
    assert(!parseFullPrefix("Carlo!carlo", p));
    assert(!parseFullPrefix("Carlo@gang.net", p));
    assert(!parseFullPrefix("!c@h", p));
    assert(!parseFullPrefix("C!@h", p));
    assert(!parseFullPrefix("C!c@", p));
    assert(!parseFullPrefix("C!c!d@h", p));
    assert(!parseFullPrefix("C!c@h@i", p));
    assert(!parseFullPrefix("C!c@h i", p));
    assert(!parseFullPrefix("C!c@h\x01", p));

    IrcPrefix a, b;
    assert(parseFullPrefix("Zod[1]!z@h", a) && parseFullPrefix("zod{1}!z@h", b));
    assert(sameIdentity(a, b, "rfc1459"));
    assert(!sameIdentity(a, b, "ascii"));
    assert(parseFullPrefix("zod{1}!Z@h", b) && !sameIdentity(a, b, "rfc1459"));
    assert(parseFullPrefix("zod{1}!z@H", b) && !sameIdentity(a, b, "rfc1459"));
    assert(!sameIdentity(IrcPrefix.init, IrcPrefix.init, "rfc1459"));
}

@("FIBERMLS PREFIX symbols come from ISUPPORT")
unittest {
    assert(prefixSymbolsFromIsupport("(qaohv)~&@%+") == "~&@%+");
    assert(prefixSymbolsFromIsupport("(ov)@+") == "@+");
    assert(prefixSymbolsFromIsupport("(Yov)!@+") == "!@+");
    assert(prefixSymbolsFromIsupport("") == "");
}

@("FIBERMLS roster entries strip only the network's status symbols")
unittest {
    auto r = parseRosterEntry("@+Carlo!~c@gang.net", "@+");
    assert(r.nick == "Carlo" && r.user == "~c" && r.host == "gang.net" && r.hasHostmask && !r.malformed);
    r = parseRosterEntry("Carlo", "@+");
    assert(r.nick == "Carlo" && !r.hasHostmask && !r.malformed);
    // `%` is not a status symbol here, so it stays part of the name.
    r = parseRosterEntry("%Carlo", "@+");
    assert(r.nick == "%Carlo");
    r = parseRosterEntry("!@Carlo!c@h", "!@+");
    assert(r.nick == "Carlo" && r.hasHostmask);
    r = parseRosterEntry("Carlo!c", "@+");
    assert(r.nick == "Carlo" && r.malformed && !r.hasHostmask);
    r = parseRosterEntry("Carlo@h", "@+");
    assert(r.nick == "Carlo" && r.malformed);
}

@("FIBERMLS roster identity requires the observed user@host")
unittest {
    IrcPrefix src;
    assert(parseFullPrefix("Carlo!~c@gang.net", src));
    const sym = "~&@%+";

    assert(matchRosterIdentity(["@carlo!~c@gang.net", "Zod!z@h"], src, sym, "rfc1459") == RosterMatch.match);
    assert(matchRosterIdentity(["Zod!z@h"], src, sym, "rfc1459") == RosterMatch.absent);
    assert(matchRosterIdentity([], src, sym, "rfc1459") == RosterMatch.absent);
    assert(matchRosterIdentity(["+Carlo"], src, sym, "rfc1459") == RosterMatch.unverified);
    assert(matchRosterIdentity(["Carlo", "Carlo!~c@gang.net"], src, sym, "rfc1459") == RosterMatch.match);
    assert(matchRosterIdentity(["Carlo!~c@other.net"], src, sym, "rfc1459") == RosterMatch.conflict);
    assert(matchRosterIdentity(["Carlo!c@gang.net"], src, sym, "rfc1459") == RosterMatch.conflict);
    assert(matchRosterIdentity(["Carlo!~c@gang.net", "carlo!~c@spoof"], src, sym, "rfc1459") == RosterMatch.conflict);
    assert(matchRosterIdentity(["Carlo!~c"], src, sym, "rfc1459") == RosterMatch.conflict);
    // A nonmember sharing only a prefix-like spelling does not match.
    assert(matchRosterIdentity(["Carlo_!~c@gang.net"], src, sym, "rfc1459") == RosterMatch.absent);
    // A malformed advertised PREFIX must not turn a different nick into proof.
    assert(matchRosterIdentity(["@Carlo!~c@gang.net"], src,
        prefixSymbolsFromIsupport("(ov)@"), "rfc1459") != RosterMatch.match);

    IrcPrefix bracket;
    assert(parseFullPrefix("Zod[1]!z@h", bracket));
    assert(matchRosterIdentity(["zod{1}!z@h"], bracket, sym, "rfc1459") == RosterMatch.match);
    assert(matchRosterIdentity(["zod{1}!z@h"], bracket, sym, "ascii") == RosterMatch.absent);
    assert(matchRosterIdentity(["Carlo!~c@gang.net"], IrcPrefix.init, sym, "rfc1459") == RosterMatch.conflict);
}
