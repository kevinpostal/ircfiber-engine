module ircfiber.db.push_devices;

import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// One APNs device registration of the iOS app.
struct PushDevice {
    /// APNs device token, lower-case hex (`_id`).
    string token;
    /// Owning user id.
    string userId;
    /// APNs environment: `"sandbox"` or `"production"`.
    string environment;
    /// App bundle id the token was issued for (the APNs topic).
    string bundleId;
    /// Device model as reported by the app (`iPhone16,1`).
    string model;
    /// The app's install id (`X-IRCFiber-Device`); empty for registrations made without it.
    string deviceId;
    /// First registration (unix ms).
    long createdAt;
    /// Latest registration (unix ms).
    long lastSeenAt;

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(token), "userId": Bson(userId), "environment": Bson(environment),
            "bundleId": Bson(bundleId), "model": Bson(model), "deviceId": Bson(deviceId),
            "createdAt": Bson(createdAt), "lastSeenAt": Bson(lastSeenAt),
        ]);
    }

    /// Deserializes from Bson.
    static PushDevice fromBson(Bson b) @trusted {
        PushDevice d;
        d.token = b["_id"].get!string;
        d.userId = b["userId"].get!string;
        d.environment = b["environment"].get!string;
        d.bundleId = b["bundleId"].get!string;
        d.model = b["model"].get!string;
        auto id = b["deviceId"];
        d.deviceId = id.type == Bson.Type.string ? id.get!string : "";
        d.createdAt = b["createdAt"].get!long;
        d.lastSeenAt = b["lastSeenAt"].get!long;
        return d;
    }
}

/// Persistence for APNs device registrations; collection `push_devices`.
final class PushDeviceRepository {
    private MongoCollection collection;

    /// Constructs a repository bound to the push_devices collection.
    this() {
        collection = AppMongoConnection.getDb()["push_devices"];
        ensureIndexes();
    }

    private void ensureIndexes() @trusted {
        try {
            collection.createIndex(Bson(["userId": Bson(1)]));
        } catch (Exception e) {
            logWarn("Failed to create push_devices index: %s", e.msg);
        }
    }

    /// Inserts or refreshes a registration, keeping the stored `createdAt`.
    /// A token re-registered by another account moves to that account.
    ///
    /// Update-then-insert rather than `upsert`: vibe-d 0.10.3 reads an
    /// upsert's created `_id` as an ObjectID and throws on a string `_id`
    /// (see `prefs_mongo.savePrefsDoc`).
    void upsert(PushDevice d) @trusted {
        Bson setDoc = Bson.emptyObject;
        setDoc["userId"] = Bson(d.userId);
        setDoc["environment"] = Bson(d.environment);
        setDoc["bundleId"] = Bson(d.bundleId);
        setDoc["model"] = Bson(d.model);
        setDoc["deviceId"] = Bson(d.deviceId);
        setDoc["lastSeenAt"] = Bson(d.lastSeenAt);
        auto selector = Bson(["_id": Bson(d.token)]);
        if (collection.updateOne(selector, Bson(["$set": setDoc])).matchedCount > 0) return;
        auto fresh = d;
        if (fresh.createdAt == 0) fresh.createdAt = d.lastSeenAt;
        try {
            collection.insertOne(fresh.toBson());
        } catch (Exception e) {
            // E11000: a concurrent registration of the same token won the
            // insert; apply this one's fields on top of it.
            collection.updateOne(selector, Bson(["$set": setDoc]));
        }
    }

    /// Every device registered by a user.
    PushDevice[] listByUser(string userId) @trusted {
        PushDevice[] result;
        foreach (doc; collection.find(Bson(["userId": Bson(userId)])))
            result ~= PushDevice.fromBson(doc);
        return result;
    }

    /// Distinct user ids that have at least one device.
    string[] userIds() @trusted {
        bool[string] seen;
        string[] result;
        FindOptions opts;
        opts.projection = Bson(["userId": Bson(1)]);
        foreach (doc; collection.find(Bson.emptyObject, opts)) {
            const u = doc["userId"].get!string;
            if (u in seen) continue;
            seen[u] = true;
            result ~= u;
        }
        return result;
    }

    /// Removes one of the user's devices. False when it was not theirs.
    bool remove(string userId, string token) @trusted {
        return collection.deleteOne(Bson(["_id": Bson(token), "userId": Bson(userId)])).deletedCount > 0;
    }

    /// Removes a token APNs rejected, whoever owns it.
    void removeToken(string token) @trusted {
        collection.deleteOne(Bson(["_id": Bson(token)]));
    }

    /// Removes every registration one install of the user's made ("Remove" in
    /// Settings → Sessions → Mobile devices); returns how many. 0 without
    /// querying for an empty `deviceId`, which would match the legacy ones.
    size_t removeByDevice(string userId, string deviceId) @trusted {
        if (!deviceId.length) return 0;
        return cast(size_t) collection.deleteMany(Bson(["userId": Bson(userId), "deviceId": Bson(deviceId)])).deletedCount;
    }

    /// Removes every device of a user (account deletion).
    void removeAllForUser(string userId) @trusted {
        collection.deleteMany(Bson(["userId": Bson(userId)]));
    }
}

@("PushDevice round-trips through Bson")
unittest {
    PushDevice d;
    d.token = "ab12";
    d.userId = "u1";
    d.environment = "sandbox";
    d.bundleId = "com.ircfiber.ios";
    d.model = "iPhone16,1";
    d.deviceId = "11111111-2222-4333-8444-555555555555";
    d.createdAt = 1_765_000_000_000;
    d.lastSeenAt = 1_765_000_100_000;
    auto b = d.toBson();
    assert(b["_id"].get!string == "ab12");
    assert(PushDevice.fromBson(b) == d);
}

@("PushDevice registered before install ids decodes with an empty deviceId")
unittest {
    auto b = Bson([
        "_id": Bson("ab12"), "userId": Bson("u1"), "environment": Bson("production"),
        "bundleId": Bson("com.ircfiber.ios"), "model": Bson("iPhone16,1"),
        "createdAt": Bson(1L), "lastSeenAt": Bson(2L),
    ]);
    const d = PushDevice.fromBson(b);
    assert(d.deviceId == "" && d.token == "ab12" && d.lastSeenAt == 2);
}
