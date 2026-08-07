module ircfiber.auth;

import std.datetime : Clock;
import std.uuid : parseUUID;
import std.string : startsWith;
import std.base64 : Base64;
import std.digest.sha : sha256Of;
import std.random : uniform;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse;
import vibe.data.json : Json;

import ircfiber.models.user : User;
import ircfiber.db.user : UserRepository;

private enum SALT_LENGTH = 16;
private enum HASH_LENGTH = 32;
private enum PBKDF2_ITERATIONS = 10_000;

/**
 * Hashes a password using PBKDF2-like SHA-256 with a random salt.
 * Returns a Base64-encoded string containing salt + hash.
 */
string hashPassword(string password) @trusted {
    ubyte[SALT_LENGTH] salt;
    foreach (ref b; salt) {
        b = cast(ubyte) uniform(0, 256);
    }

    auto hash = sha256Of(password ~ cast(string) salt);
    foreach (_; 0 .. PBKDF2_ITERATIONS) {
        hash = sha256Of(hash ~ salt ~ cast(ubyte[]) password);
    }

    return Base64.encode(salt ~ hash);
}

/**
 * Verifies a password against a Base64-encoded hash.
 * Returns false for any invalid input or mismatch.
 */
bool verifyPassword(string password, string hashB64) @trusted {
    try {
        auto data = Base64.decode(hashB64);
        if (data.length < SALT_LENGTH + HASH_LENGTH) {
            return false;
        }

        auto salt = data[0 .. SALT_LENGTH];
        auto expectedHash = data[SALT_LENGTH .. $];
        auto hash = sha256Of(password ~ cast(string) salt);

        foreach (_; 0 .. PBKDF2_ITERATIONS) {
            hash = sha256Of(hash ~ cast(ubyte[]) salt ~ cast(ubyte[]) password);
        }

        return hash == expectedHash;
    } catch (Exception) {
        return false;
    }
}

/**
 * Authenticates a request by looking up the session user ID.
 * Returns User.init if no valid session exists.
 */
User authenticateRequest(scope HTTPServerRequest req, UserRepository repo) {
    if (!req.session) {
        return User.init;
    }

    auto sid = req.session.get("sessionUserId", "");
    if (sid.length == 0) {
        return User.init;
    }

    try {
        auto uid = parseUUID(sid);
        return repo.findById(uid);
    } catch (Exception) {
        return User.init;
    }
}

/**
 * Requires authentication for the current request.
 * Redirects to /login for web routes, returns 401 JSON for API/WebSocket routes.
 */
void requireAuth(scope HTTPServerRequest req, scope HTTPServerResponse res) {
    auto repo = new UserRepository();
    auto user = authenticateRequest(req, repo);

    if (user.username.length == 0) {
        auto path = req.requestPath.toString();
        if (path.startsWith("/api/") || path == "/ws") {
            res.statusCode = 401;
            res.writeJsonBody(Json(["error": Json("Unauthorized")]));
        } else if (path.startsWith("/admin")) {
            res.redirect("/admin/login");
        } else {
            res.redirect("/login");
        }
        return;
    }

    // Touch the session's lastAccess timestamp so `limitUserSessions`
    // can accurately sort sessions by recency when pruning old ones.
    try {
        req.session.set("lastAccess", Clock.currTime.toUnixTime() * 1000L);
    } catch (Exception) {}

    req.context["user"] = user;
}

/**
 * Checks if a user has the admin role.
 * Returns false for uninitialized users or users without the "admin" role.
 */
bool isAdmin(User user) {
    if (user.username.length == 0) return false;
    foreach (role; user.roles) {
        if (role == "admin") return true;
    }
    return false;
}

/**
 * Requires the admin role for the current request.
 * Must be called AFTER requireAuth (which populates req.context["user"]).
 * Returns 403 for non-admin users.
 */
void requireAdmin(scope HTTPServerRequest req, scope HTTPServerResponse res) {
    if (res.headerWritten) return;

    auto userPtr = "user" in req.context;
    if (!userPtr) {
        res.statusCode = 403;
        res.writeJsonBody(Json(["error": Json("Forbidden")]));
        return;
    }

    auto user = (*userPtr).get!User;
    if (!isAdmin(user)) {
        res.statusCode = 403;
        auto path = req.requestPath.toString();
        if (path.startsWith("/api/") || path == "/ws") {
            res.writeJsonBody(Json(["error": Json("Forbidden")]));
        } else {
            res.writeBody("Forbidden");
        }
        return;
    }
}

@("hashPassword produces verifiable hash")
unittest {
    auto hash = hashPassword("secret123");
    assert(hash.length > 0);
    assert(verifyPassword("secret123", hash));
}

@("verifyPassword fails for wrong password")
unittest {
    auto hash = hashPassword("correct");
    assert(!verifyPassword("wrong", hash));
}

@("verifyPassword fails for invalid base64")
unittest {
    assert(!verifyPassword("password", "not-valid-base64!!!"));
}
