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
    }

    /// Finds a user by username.
    User findByUsername(string username) {
        auto doc = collection.findOne(["username": username]);
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

    /// Updates an existing user account.
    void update(User user) {
        auto bson = userToBson(user);
        collection.replaceOne(["id": user.id.toString()], bson);
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
    User[] findAll(int limit, int offset) {
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
