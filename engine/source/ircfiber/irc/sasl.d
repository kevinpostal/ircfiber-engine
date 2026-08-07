/// SASL authentication mechanisms for IRC: PLAIN, SCRAM-SHA-256, EXTERNAL.
module ircfiber.irc.sasl;

import std.base64 : Base64;
import std.conv : to;
import std.string : indexOf, replace;
import std.digest.sha : SHA256;
import std.digest.hmac : HMAC;
import std.random : uniform;
import std.array : join, Appender;

// ──────────────────────────────────────────────────────────────────────────────
// SASL PLAIN
// ──────────────────────────────────────────────────────────────────────────────

/// Build a base64-encoded SASL PLAIN payload.
/// RFC 4616 format:  [authzid]\0<authcid>\0<passwd>
/// The initial NUL separator is always present — even when authzid is empty,
/// the message starts with a NUL byte.  Without this, servers (InspIRCd,
/// Charybdis, etc.) reject the auth with ERR_SASLFAIL because they consume
/// the NUL-less payload as authzid and fail to parse the remaining fields.
/// When authzid is supplied explicitly, it is prepended before the NUL.
/// Unauthenticated EXTERNAL mechanisms may pass an empty authzid to request
/// the certificate-derived identity.
string buildSaslPlainPayload(string username, string password, string authzid = "") {
    auto auth = (authzid.length > 0 ? authzid : "") ~ "\0" ~ username ~ "\0" ~ password;
    return cast(string) Base64.encode(cast(ubyte[]) auth);
}

// ──────────────────────────────────────────────────────────────────────────────
// HMAC-SHA256 helper
// ──────────────────────────────────────────────────────────────────────────────

private ubyte[32] hmacSha256(const(ubyte)[] key, const(ubyte)[] data) {
    auto h = HMAC!SHA256(key);
    h.put(data);
    return h.finish();
}

// ──────────────────────────────────────────────────────────────────────────────
// SHA-256 helper
// ──────────────────────────────────────────────────────────────────────────────

private ubyte[32] sha256(const(ubyte)[] data) {
    import std.digest.sha : sha256Of;
    return sha256Of(data);
}

// ──────────────────────────────────────────────────────────────────────────────
// PBKDF2-SHA-256  (used by SCRAM)
// ──────────────────────────────────────────────────────────────────────────────

private ubyte[32] pbkdf2Sha256(const(ubyte)[] password, const(ubyte)[] salt, int iterations) {
    // U1 = HMAC(password, salt || 0x00000001)
    ubyte[4] intBlock = [0, 0, 0, 1];
    ubyte[] saltBlock = salt.dup ~ intBlock[];

    ubyte[32] u = hmacSha256(password, saltBlock);
    ubyte[32] result = u;

    foreach (_; 1 .. iterations) {
        u = hmacSha256(password, u[]);
        foreach (i; 0 .. 32) result[i] ^= u[i];
    }

    return result;
}

// ──────────────────────────────────────────────────────────────────────────────
// SCRAM-SHA-256 client state machine
// ──────────────────────────────────────────────────────────────────────────────

/// Holds the state for a single SCRAM-SHA-256 handshake.
struct ScramSha256Client {
    private {
        string username;
        string password;
        string cnonce;
        string clientFirstMessageBare;
        ubyte[32] serverSignature;
        bool _verified = false;
    }

    /// Create a new SCRAM client for the given credentials.
    this(string user, string pass) {
        username = user;
        password = pass;
        cnonce   = generateNonce();
    }

    /// Returns the base64-encoded client-first-message.
    /// Send:  AUTHENTICATE <result>
    string clientFirstMessage() {
        clientFirstMessageBare = "n=" ~ saslName(username) ~ ",r=" ~ cnonce;
        auto msg = "n,," ~ clientFirstMessageBare; // gs2-header: no channel binding
        return cast(string) Base64.encode(cast(ubyte[]) msg);
    }

    /// Process the base64-encoded server-first-message.
    /// Returns the base64-encoded client-final-message.
    /// Throws on malformed server message.
    string clientFinalMessage(string serverFirstB64) {
        import std.exception : enforce;

        auto serverFirst = cast(string) Base64.decode(serverFirstB64);

        string serverNonce;
        string saltB64;
        int iterations;

        foreach (part; serverFirst.split(",")) {
            if (part.length < 3) continue;
            switch (part[0 .. 2]) {
                case "r=": serverNonce = part[2 .. $]; break;
                case "s=": saltB64    = part[2 .. $]; break;
                case "i=": try { iterations = part[2 .. $].to!int; } catch (Exception) {} break;
                default: break;
            }
        }

        enforce(serverNonce.length > 0,            "SCRAM: missing server nonce");
        enforce(serverNonce.startsWith(cnonce),     "SCRAM: server nonce does not contain client nonce");
        enforce(saltB64.length > 0,                "SCRAM: missing salt");
        enforce(iterations > 0,                    "SCRAM: invalid iteration count");

        auto salt = Base64.decode(saltB64);

        // SaltedPassword = PBKDF2(password, salt, iterations)
        ubyte[32] saltedPassword = pbkdf2Sha256(cast(ubyte[]) password, cast(ubyte[]) salt, iterations);

        // ClientKey = HMAC(SaltedPassword, "Client Key")
        ubyte[32] clientKey = hmacSha256(saltedPassword[], cast(ubyte[]) "Client Key");

        // StoredKey = H(ClientKey)
        ubyte[32] storedKey = sha256(clientKey[]);

        // client-final-message-without-proof
        auto channelBinding    = "c=" ~ cast(string) Base64.encode(cast(ubyte[]) "n,,");
        auto cfmWithoutProof   = channelBinding ~ ",r=" ~ serverNonce;

        // AuthMessage = client-first-message-bare + "," + server-first + "," + cfm-without-proof
        auto authMessage = clientFirstMessageBare ~ "," ~ serverFirst ~ "," ~ cfmWithoutProof;

        // ClientSignature = HMAC(StoredKey, AuthMessage)
        ubyte[32] clientSignature = hmacSha256(storedKey[], cast(ubyte[]) authMessage);

        // ClientProof = ClientKey XOR ClientSignature
        ubyte[32] clientProof;
        foreach (i; 0 .. 32) clientProof[i] = clientKey[i] ^ clientSignature[i];

        // Pre-compute expected ServerSignature for mutual auth verification
        ubyte[32] serverKey = hmacSha256(saltedPassword[], cast(ubyte[]) "Server Key");
        serverSignature     = hmacSha256(serverKey[], cast(ubyte[]) authMessage);

        auto cfm = cfmWithoutProof ~ ",p=" ~ cast(string) Base64.encode(clientProof[]);
        return cast(string) Base64.encode(cast(ubyte[]) cfm);
    }

    /// Verify the base64-encoded server-final-message.
    /// Returns true if mutual authentication succeeds.
    bool verifyServerFinal(string serverFinalB64) {
        auto serverFinal = cast(string) Base64.decode(serverFinalB64);
        if (serverFinal.length < 3 || serverFinal[0 .. 2] != "v=") return false;
        auto theirSig = Base64.decode(serverFinal[2 .. $]);
        if (theirSig.length != 32) return false;
        foreach (i; 0 .. 32) {
            if (theirSig[i] != serverSignature[i]) return false;
        }
        _verified = true;
        return true;
    }

    /// Whether mutual authentication succeeded.
    bool verified() const { return _verified; }

    // ── helpers ──────────────────────────────────────────────────────────────

    private static string generateNonce() {
        import std.ascii : digits, uppercase, lowercase;
        enum chars = digits ~ uppercase ~ lowercase;
        char[24] buf;
        foreach (ref c; buf) c = chars[uniform(0u, cast(uint) chars.length)];
        return buf.idup;
    }

    private static string saslName(string name) {
        return name.replace("=", "=3D").replace(",", "=2C");
    }
}

private string[] split(string s, string delim) {
    import std.string : split;
    return s.split(delim);
}

private bool startsWith(string s, string prefix) {
    import std.string : startsWith;
    return s.startsWith(prefix);
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

@("SASL PLAIN payload encodes correctly")
unittest {
    // Without authzid: RFC 4616 requires leading NUL: \0authcid\0passwd
    auto payload = buildSaslPlainPayload("user", "pass");
    auto decoded = cast(string) Base64.decode(payload);
    assert(decoded == "\0user\0pass", "PLAIN payload mismatch: " ~ decoded);

    // With authzid: authzid\0authcid\0passwd
    auto authzidPayload = buildSaslPlainPayload("user", "pass", "admin");
    auto authzidDecoded = cast(string) Base64.decode(authzidPayload);
    assert(authzidDecoded == "admin\0user\0pass", "PLAIN payload with authzid mismatch: " ~ authzidDecoded);
}

@("ScramSha256Client generates valid client-first-message")
unittest {
    auto c   = ScramSha256Client("user", "pencil");
    auto msg = c.clientFirstMessage();
    assert(msg.length > 0);
    auto decoded = cast(string) Base64.decode(msg);
    assert(decoded.startsWith("n,,n=user,r="), "Expected gs2-header, got: " ~ decoded);
}
