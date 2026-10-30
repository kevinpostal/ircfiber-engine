module ircfiber.db.device_registry;

import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// Latest known state of one mobile install, across every account — the
/// admin fleet directory. `UserPreferences.devices` (Redis, per-user) is
/// the source of truth for sync/settings; this is a denormalized read model
/// for cross-user admin queries, upserted on every check-in alongside it.
struct DeviceRegistryEntry {
    string deviceId;      // _id
    string userId;
    string username;      // denormalized for admin search/sort, no join needed
    string model;
    string osVersion;
    string appVersion;
    string lastIp;
    long createdAt;
    long lastSeenAt;

    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(deviceId), "userId": Bson(userId), "username": Bson(username),
            "model": Bson(model), "osVersion": Bson(osVersion), "appVersion": Bson(appVersion),
            "lastIp": Bson(lastIp), "createdAt": Bson(createdAt), "lastSeenAt": Bson(lastSeenAt),
        ]);
    }

    static DeviceRegistryEntry fromBson(Bson b) @trusted {
        DeviceRegistryEntry e;
        e.deviceId = b["_id"].get!string;
        e.userId = b["userId"].get!string;
        e.username = b["username"].get!string;
        e.model = b["model"].get!string;
        e.osVersion = b["osVersion"].get!string;
        e.appVersion = b["appVersion"].get!string;
        e.lastIp = b["lastIp"].get!string;
        e.createdAt = b["createdAt"].get!long;
        e.lastSeenAt = b["lastSeenAt"].get!long;
        return e;
    }
}

/// Persistence for the admin device directory; collection `device_registry`.
final class DeviceRegistryRepository {
    private MongoCollection collection;

    this() {
        collection = AppMongoConnection.getDb()["device_registry"];
        ensureIndexes();
    }

    private void ensureIndexes() @trusted {
        try {
            collection.createIndex(Bson(["userId": Bson(1)]));
            collection.createIndex(Bson(["lastSeenAt": Bson(-1)]));
        } catch (Exception e) {
            logWarn("Failed to create device_registry index: %s", e.msg);
        }
    }

    /// Upserts one device's latest state, keeping its stored `createdAt`.
    /// Update-then-insert rather than `upsert` (see PushDeviceRepository.upsert
    /// for why: vibe-d 0.10.3's upsert-created `_id` read).
    void upsert(DeviceRegistryEntry e) @trusted {
        Bson setDoc = Bson.emptyObject;
        setDoc["userId"] = Bson(e.userId);
        setDoc["username"] = Bson(e.username);
        setDoc["model"] = Bson(e.model);
        setDoc["osVersion"] = Bson(e.osVersion);
        setDoc["appVersion"] = Bson(e.appVersion);
        setDoc["lastIp"] = Bson(e.lastIp);
        setDoc["lastSeenAt"] = Bson(e.lastSeenAt);
        auto selector = Bson(["_id": Bson(e.deviceId)]);
        if (collection.updateOne(selector, Bson(["$set": setDoc])).matchedCount > 0) return;
        auto fresh = e;
        if (fresh.createdAt == 0) fresh.createdAt = e.lastSeenAt;
        try {
            collection.insertOne(fresh.toBson());
        } catch (Exception e2) {
            collection.updateOne(selector, Bson(["$set": setDoc]));
        }
    }

    /// Paginated, most-recently-seen first (admin Devices list).
    DeviceRegistryEntry[] list(int offset, int limit) @trusted {
        FindOptions opts;
        opts.sort = Bson(["lastSeenAt": Bson(-1)]);
        opts.skip = offset;
        opts.limit = limit;
        DeviceRegistryEntry[] result;
        foreach (doc; collection.find(Bson.emptyObject, opts))
            result ~= DeviceRegistryEntry.fromBson(doc);
        return result;
    }

    long count() @trusted { return collection.countDocuments(Bson.emptyObject); }

    /// One device by id, or `DeviceRegistryEntry.init` (empty `deviceId`) when absent.
    DeviceRegistryEntry findById(string deviceId) @trusted {
        auto doc = collection.findOne(Bson(["_id": Bson(deviceId)]));
        return doc.isNull ? DeviceRegistryEntry.init : DeviceRegistryEntry.fromBson(doc);
    }

    /// Removes every device of a user (account deletion / device removal).
    void remove(string deviceId) @trusted { collection.deleteOne(Bson(["_id": Bson(deviceId)])); }
    void removeAllForUser(string userId) @trusted { collection.deleteMany(Bson(["userId": Bson(userId)])); }
}
