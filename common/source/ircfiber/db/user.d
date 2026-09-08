module ircfiber.db.user;

import std.uuid;
import std.array;
import std.algorithm;
import std.datetime;
import vibe.db.mongo.mongo;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.models.user;
import ircfiber.db.mongo;

/// Repository for user accounts.
final class UserRepository {
    private MongoCollection collection;

    /// Creates a new user repository.
    this() {
        collection = AppMongoConnection.getDb()["users"];
        ensureIndexes();
    }

    /**
     * Case-insensitive uniqueness on usernames, enforced by the database so
     * two simultaneous signups for case-variants of one name cannot both
     * land (both pass the application-level `findByUsernameCI` checks, then
     * the loser hits E11000). Collation strength 2 folds case but not
     * accents; signup restricts usernames to the ASCII IRC-nick charset, so
     * the two rules agree exactly. Idempotent: re-creating an identical
     * index is a server-side no-op.
     *
     * `bncToken_1` backs the admin bouncer page (`listWithBncToken`).
     */
    private void ensureIndexes() @trusted {
        try {
            AppMongoConnection.getDb().runCommandChecked(Bson([
                "createIndexes": Bson("users"),
                "indexes": Bson([Bson([
                    "key": Bson(["username": Bson(1)]),
                    "name": Bson("username_ci_unique"),
                    "unique": Bson(true),
                    "collation": Bson(["locale": Bson("en"), "strength": Bson(2)])
                ])])
            ]));
        } catch (Exception e) {
            logWarn("users username_ci_unique index: %s", e.msg);
        }
        try collection.createIndex(Bson(["bncToken": Bson(1)]));
        catch (Exception e) logWarn("users bncToken index: %s", e.msg);
    }

    /// Finds a user by username.
    User findByUsername(string username) {
        auto doc = collection.findOne(["username": username]);
        if (doc.isNull) return User.init;
        return docFromBson(doc);
    }

    /**
     * Finds a user whose username matches case-insensitively.
     *
    * Every website username is also the owner's IRC nick and their NickServ
    * account name, and IRC nicks are case-insensitive — so `Alice` and
    * `alice` are one identity and must never become two website accounts.
    *
    * This is the uniqueness gate for every user-creation path (public
    * signup, admin API, admin web form); the `username_ci_unique` index is
    * the backstop for races between two simultaneous checks.
    *
    * ASCII case folding only: the rfc1459 casemapping also equates
    * `[]\` with `{}|`, which the Anope-side availability check catches.
     */
    User findByUsernameCI(string username) {
        if (username.length == 0) return User.init;
        auto doc = collection.findOne(Bson([
            "username": Bson([
                "$regex": Bson("^" ~ escapeRegexLiteral(username) ~ "$"),
                "$options": Bson("i")
            ])
        ]));
        if (doc.isNull) return User.init;
        return docFromBson(doc);
    }

    /// Finds a user by ID.
    User findById(UUID id) {
        auto doc = collection.findOne(["id": id.toString()]);
        if (doc.isNull) return User.init;
        return docFromBson(doc);
    }

    /// Creates a new user account.
    void create(User user) {
        collection.insertOne(userToBson(user));
    }

    /// Updates an existing user account. `$set` rather than a replace so
    /// fields outside `User` (the bouncer token) survive profile edits.
    void update(User user) {
        collection.updateOne(["id": user.id.toString()], Bson(["$set": userToBson(user)]));
    }

    /// Returns the user's bouncer password, or `""` when none is set. Kept
    /// off `User`/`toJson` so it never rides on `/api/me` or session caches.
    string getBncToken(UUID id) {
        auto doc = collection.findOne(["id": id.toString()]);
        if (doc.isNull) return "";
        try return doc["bncToken"].get!string;
        catch (Exception) return "";
    }

    /// Sets (or, with an empty token, clears) the user's bouncer password.
    void setBncToken(UUID id, string token) {
        auto selector = Bson(["id": Bson(id.toString())]);
        auto update = token.length
            ? Bson(["$set": Bson(["bncToken": Bson(token)])])
            : Bson(["$unset": Bson(["bncToken": Bson("")])]);
        collection.updateOne(selector, update);
    }

    /// Every user that currently has a bouncer password. Admin-only (the
    /// bouncer page); the token itself is never returned.
    User[] listWithBncToken() {
        User[] result;
        auto filter = Bson(["bncToken": Bson(["$exists": Bson(true), "$ne": Bson("")])]);
        foreach (doc; collection.find(filter)) {
            if (doc.isNull) continue;
            result ~= docFromBson(doc);
        }
        return result;
    }

    /// Deletes a user by ID.
    void deleteById(UUID id) {
        collection.deleteOne(["id": id.toString()]);
    }

    /// Counts all users.
    int count() {
        return cast(int) collection.countDocuments(Bson.emptyObject);
    }

    /// Finds all users with limit and offset.
    User[] findAll(int limit, int) {
        User[] results;
        FindOptions findOpts;
        findOpts.limit = limit;
        foreach (doc; collection.find(Bson.emptyObject, findOpts)) {
            if (doc.isNull) continue;
            results ~= docFromBson(doc);
        }
        return results;
    }

    /// Returns all user IDs as an array of UUID strings.
    /// Uses a projection to fetch only the `id` field — efficient
    /// for building a validity set at engine bootstrap time.
    /// Returns empty array on failure (caller should handle gracefully).
    string[] allUserIds() {
        string[] ids;
        try {
            FindOptions findOpts;
            findOpts.projection = Bson(["id": Bson(1), "_id": Bson(0)]);
            foreach (doc; collection.find(Bson.emptyObject, findOpts)) {
                if (doc.isNull) continue;
                ids ~= doc["id"].get!string;
            }
        } catch (Exception e) {
            logWarn("Failed to query allUserIds: %s", e.msg);
        }
        return ids;
    }

    /// Searches users by username or email substring.
    User[] search(string query, int limit) {
        User[] results;
        import std.string : toLower;
        // Build BSON with regex filter
        auto regexDoc = Bson(["$regex": Bson(query), "$options": Bson("i")]);
        auto usernameFilter = Bson(["username": regexDoc]);
        auto emailFilter = Bson(["email": regexDoc]);
        auto filter = Bson(["$or": Bson([usernameFilter, emailFilter])]);

        FindOptions searchOpts;
        searchOpts.limit = limit;
        foreach (doc; collection.find(filter, searchOpts)) {
            if (doc.isNull) continue;
            results ~= docFromBson(doc);
        }
        return results;
    }

    private Bson userToBson(User u) {
        Bson[string] fields;
        fields["id"] = Bson(u.id.toString());
        fields["username"] = Bson(u.username);
        fields["email"] = Bson(u.email);
        fields["passwordHash"] = Bson(u.passwordHash);
        fields["roles"] = Bson(u.roles.map!(r => Bson(r)).array);
        fields["signupIp"] = Bson(u.signupIp);
        fields["lastLoginIp"] = Bson(u.lastLoginIp);
        // Cast to double to avoid vibe.d BSON long_/double_ type mismatch
        fields["lastLoginAt"] = Bson(cast(double) u.lastLoginAt.toUnixTime);
        fields["createdAt"] = Bson(cast(double) u.createdAt.toUnixTime);
        fields["loginIps"] = Bson(u.loginIps.map!(r => Bson(r)).array);
        return Bson(fields);
    }

    private long readBsonTimestamp(const(Bson) b) {
        switch (b.type) with (Bson.Type) {
            case long_:
                return b.get!long;
            case double_:
                return cast(long) b.get!double;
            case null_:
                return 0;
            case int_:
                return b.get!int;
            default:
                return 0;
        }
    }

    private User docFromBson(const(Bson) doc) {
        User u;
        u.id = parseUUID(doc["id"].get!string);
        u.username = doc["username"].get!string;
        u.email = doc["email"].get!string;
        u.passwordHash = doc["passwordHash"].get!string;
        if (doc["roles"].type != Bson.Type.null_)
            u.roles = deserializeBson!(string[])(doc["roles"]);
        if (doc["signupIp"].type != Bson.Type.null_)
            u.signupIp = doc["signupIp"].get!string;
        if (doc["lastLoginIp"].type != Bson.Type.null_)
            u.lastLoginIp = doc["lastLoginIp"].get!string;
        if (doc["lastLoginAt"].type != Bson.Type.null_) {
            auto ts = readBsonTimestamp(doc["lastLoginAt"]);
            if (ts > 0) u.lastLoginAt = SysTime(unixTimeToStdTime(ts));
        }
        if (doc["createdAt"].type != Bson.Type.null_) {
            auto ts = readBsonTimestamp(doc["createdAt"]);
            if (ts > 0) u.createdAt = SysTime(unixTimeToStdTime(ts));
        }
        if (doc["loginIps"].type != Bson.Type.null_)
            u.loginIps = deserializeBson!(string[])(doc["loginIps"]);
        return u;
    }
}

/**
 * Escape every PCRE metacharacter so a stored value is matched literally.
 * Legacy usernames predate the IRC-nick charset gate and can contain `.`,
 * `[`, `\`, `^`, `{`, `|`, `}` — all of which would otherwise turn a
 * uniqueness lookup into a pattern match (`bob.smith` matching `bobXsmith`).
 */
private string escapeRegexLiteral(string s) @safe pure {
    string res;
    foreach (char c; s) {
        switch (c) {
            case '\\': case '^': case '$': case '.': case '[': case ']':
            case '|':  case '(': case ')': case '?': case '*': case '+':
            case '{':  case '}': case '/': case '-':
                res ~= '\\';
                res ~= c;
                break;
            default:
                res ~= c;
        }
    }
    return res;
}

@("escapeRegexLiteral neutralises metacharacters in legacy usernames")
unittest {
    assert(escapeRegexLiteral("alice") == "alice");
    assert(escapeRegexLiteral("bob.smith") == "bob\\.smith");
    assert(escapeRegexLiteral("a[b]c") == "a\\[b\\]c");
    assert(escapeRegexLiteral("x|y") == "x\\|y");
    assert(escapeRegexLiteral(".*") == "\\.\\*", "a wildcard username must not match everything");
}
