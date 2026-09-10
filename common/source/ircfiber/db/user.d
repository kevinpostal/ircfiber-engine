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
        try {
            IndexOptions o;
            o.unique = true;
            o.sparse = true;
            collection.createIndex(Bson(["oauthIdentities.provider": Bson(1), "oauthIdentities.subject": Bson(1)]), o);
        } catch (Exception e) logWarn("users oauthIdentities index: %s", e.msg);
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

    /// Finds a user by linked OAuth identity. `$elemMatch` keeps provider
    /// and subject bound to the same array element (dot-notation across
    /// array elements could false-match across two identities).
    User findByOAuth(string provider, string subject) {
        if (provider.length == 0 || subject.length == 0) return User.init;
        auto doc = collection.findOne(Bson(["oauthIdentities": Bson(["$elemMatch": Bson(["provider": Bson(provider), "subject": Bson(subject)])])]));
        if (doc.isNull) return User.init;
        return docFromBson(doc);
    }

    /// Finds a user whose email matches case-insensitively (anchored
    /// literal regex, same idiom as `findByUsernameCI`). Used by social
    /// signup to link a verified provider email onto an existing row.
    User findByEmailCI(string email) {
        if (email.length == 0) return User.init;
        auto doc = collection.findOne(Bson([
            "email": Bson([
                "$regex": Bson("^" ~ escapeRegexLiteral(email) ~ "$"),
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

    /// Users created by `!adduser` (`provisionedFrom` non-empty), newest
    /// first is left to the caller — Mongo returns natural order here and
    /// the admin list is small. Legacy rows without the key never match
    /// (`$exists` guard), so no migration is needed.
    User[] listProvisioned(int limit = 200) {
        User[] results;
        FindOptions findOpts;
        findOpts.limit = limit;
        auto filter = Bson(["provisionedFrom": Bson(["$exists": Bson(true), "$ne": Bson("")])]);
        foreach (doc; collection.find(filter, findOpts)) {
            if (doc.isNull) continue;
            results ~= docFromBson(doc);
        }
        return results;
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

    /// Bulk-campaign audience. Shared filter: subscribed rows with a
    /// non-empty email, plus optional role (element of the `roles` array),
    /// `createdAt` range (unix ms; 0/negative = open) and `q` substring on
    /// username+email (same escaped-regex idiom as `search`). No new index:
    /// sub-500 collections scan fine on `username_ci_unique` + `bncToken_1`.
    long countCampaignAudience(string role, long createdAfterMs, long createdBeforeMs, string q) {
        return cast(long) collection.countDocuments(campaignAudienceFilter(role, createdAfterMs, createdBeforeMs, q));
    }

    /// Same filters but INCLUDING opted-out rows (only the opt-out clause
    /// is dropped): the campaign send reports `skippedUnsubscribed` as this
    /// minus `countCampaignAudience`.
    long countCampaignAudienceTotal(string role, long createdAfterMs, long createdBeforeMs, string q) {
        return cast(long) collection.countDocuments(campaignAudienceFilter(role, createdAfterMs, createdBeforeMs, q, false));
    }

    /// Same filter as `countCampaignAudience`, `limit` applied.
    User[] fetchCampaignAudience(string role, long createdAfterMs, long createdBeforeMs, string q, int limit) {
        User[] results;
        FindOptions campaignOpts;
        campaignOpts.limit = limit;
        foreach (doc; collection.find(campaignAudienceFilter(role, createdAfterMs, createdBeforeMs, q), campaignOpts)) {
            if (doc.isNull) continue;
            results ~= docFromBson(doc);
        }
        return results;
    }

    /// List-Unsubscribe consumer: flips the first row whose email matches
    /// case-insensitively (anchored literal regex, same idiom as
    /// `findByUsernameCI`). Returns whether a row was updated.
    bool setEmailUnsubscribed(string email) {
        if (email.length == 0) return false;
        auto doc = collection.findOne(Bson([
            "email": Bson([
                "$regex": Bson("^" ~ escapeRegexLiteral(email) ~ "$"),
                "$options": Bson("i")
            ])
        ]));
        if (doc.isNull) return false;
        try {
            collection.updateOne(
                Bson(["id": Bson(doc["id"].get!string)]),
                Bson(["$set": Bson(["emailUnsubscribed": Bson(true)])]));
            return true;
        } catch (Exception e) {
            logWarn("users setEmailUnsubscribed failed: %s", e.msg);
            return false;
        }
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
        fields["provisionedFrom"] = Bson(u.provisionedFrom);
        fields["lastLoginIp"] = Bson(u.lastLoginIp);
        // Cast to double to avoid vibe.d BSON long_/double_ type mismatch
        fields["lastLoginAt"] = Bson(cast(double) u.lastLoginAt.toUnixTime);
        fields["createdAt"] = Bson(cast(double) u.createdAt.toUnixTime);
        fields["loginIps"] = Bson(u.loginIps.map!(r => Bson(r)).array);
        fields["emailUnsubscribed"] = Bson(u.emailUnsubscribed);
        Bson[] ids;
        foreach (o; u.oauthIdentities)
            ids ~= Bson(["provider": Bson(o.provider), "subject": Bson(o.subject)]);
        fields["oauthIdentities"] = Bson(ids);
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
        try { if (doc["provisionedFrom"].type != Bson.Type.null_) u.provisionedFrom = doc["provisionedFrom"].get!string; } catch (Exception) {}
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
        // Missing key (pre-campaign rows) reads as false: still subscribed.
        // Tolerant: a wrongly typed value keeps false rather than throwing.
        try { if (doc["emailUnsubscribed"].type == Bson.Type.bool_) u.emailUnsubscribed = doc["emailUnsubscribed"].get!bool; } catch (Exception) {}
        // Missing key (pre-OAuth rows) reads as []: unlinked.
        try {
            if (doc["oauthIdentities"].type == Bson.Type.array)
                foreach (e; doc["oauthIdentities"])
                    u.oauthIdentities ~= OAuthIdentity(e["provider"].get!string, e["subject"].get!string);
        } catch (Exception) { u.oauthIdentities = []; }
        return u;
    }
}

/**
 * Shared bulk-campaign audience filter (free function so backend unit tests
 * can assert its shape without a Mongo connection; the repository methods
 * above are thin wrappers over it).
 *
 * Base: subscribed rows with a non-empty email. `createdAt` is stored as
 * double unix seconds, so the ms bounds convert (`/ 1000.0`); 0/negative
 * means open on that side.
 */
/// `onlySubscribed=false` drops just the opt-out clause (the email
/// presence clause stays): the campaign send counts `skippedUnsubscribed`
/// as the difference between the two counts.
Bson campaignAudienceFilter(string role, long createdAfterMs, long createdBeforeMs, string q, bool onlySubscribed = true) {
    Bson[] andParts = [
        Bson(["email": Bson(["$exists": Bson(true), "$ne": Bson("")])]),
    ];
    if (onlySubscribed)
        andParts ~= Bson(["emailUnsubscribed": Bson(["$ne": Bson(true)])]);
    if (role.length > 0)
        andParts ~= Bson(["roles": Bson(role)]);
    if (createdAfterMs > 0 || createdBeforeMs > 0) {
        Bson[string] range;
        if (createdAfterMs > 0) range["$gte"] = Bson(cast(double) createdAfterMs / 1000.0);
        if (createdBeforeMs > 0) range["$lte"] = Bson(cast(double) createdBeforeMs / 1000.0);
        andParts ~= Bson(["createdAt": Bson(range)]);
    }
    if (q.length > 0) {
        auto rx = Bson(["$regex": Bson(escapeRegexLiteral(q)), "$options": Bson("i")]);
        andParts ~= Bson(["$or": Bson([Bson(["username": rx]), Bson(["email": rx])])]);
    }
    return Bson(["$and": Bson(andParts)]);
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
