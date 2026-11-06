module ircfiber.db.device_registry;

import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// A device not seen for this many days (or never seen) is inactive. Inactive
/// devices are only hidden from the default fleet view; nothing is deleted or
/// revoked because of inactivity.
enum DEVICE_INACTIVE_DAYS = 90;
/// `DEVICE_INACTIVE_DAYS` in milliseconds (`lastSeenAt` is unix ms).
enum long DEVICE_INACTIVE_MS = DEVICE_INACTIVE_DAYS * 24L * 60 * 60 * 1000;

/// Which activity bucket a fleet query returns.
enum DeviceFleetStatus { active, inactive, all }

/// Hardware models only emulators/simulators report (case-insensitive,
/// matched by MongoDB `$regexMatch`). The iOS app in the Simulator sends
/// `<simulated model> (Simulator)` (`isDeviceModel` accepts exactly that
/// suffix). Android sends `<MANUFACTURER>_<MODEL>`: the stock emulator images
/// are `sdk_gphone*`, `Android SDK built for *` and `google_sdk`, Genymotion
/// reports its own manufacturer. Older iOS Simulator builds sent the host
/// architecture `x86_64`/`i386`, which no iOS hardware reports; bare `arm64`
/// is deliberately absent because iPad apps on Apple silicon Macs may report
/// it from real hardware.
private enum string EMULATOR_MODEL_PATTERN =
    ` \(simulator\)$|^(x86_64|i386)$|(^|_)sdk_gphone|(^|_)android_sdk_built_for|(^|_)google_sdk$|^genymotion_`;

/// Largest page `fleet` serves (the admin API's own cap).
private enum int FLEET_MAX_LIMIT = 200;
/// Largest page `reconcileOrphans` scans.
private enum int RECONCILE_MAX_BATCH = 1000;
/// Server-side bound for one fleet aggregation.
private enum long FLEET_MAX_TIME_MS = 10_000;

/// Latest known state of one client install (iOS app or web browser), across
/// every account — the admin fleet directory. `UserPreferences.devices`
/// (Redis, per-user) is the source of truth for sync/settings; this is a
/// denormalized read model for cross-user admin queries, upserted on every
/// check-in alongside it.
struct DeviceRegistryEntry {
    string deviceId;      // _id
    string userId;
    /// Stored at check-in; fleet reads replace it with the owner's live username.
    string username;
    string model;
    string osVersion;
    string appVersion;
    string lastIp;
    long createdAt;
    long lastSeenAt;
    /// `"web"` or `"app"` (`DeviceProfile.kind`); documents written before it read as `"app"`.
    string kind = "app";
    /// Display name: the user's label, else the client's automatic one; "" when neither.
    string name;

    // Computed by fleet reads (`fleet`/`findFleetById`) and never persisted:
    // the owner flag is joined live from `users`, so a classification change
    // applies to every device of the account at once.
    /// The owning account is explicitly marked as a test account.
    bool isTestAccount;
    /// `model` is a recognized emulator/simulator model.
    bool isEmulator;
    /// `isTestAccount || isEmulator`: hidden unless tests are included.
    bool isTest;
    /// `"active"` or `"inactive"` as of the query's `nowMs`.
    string status;

    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(deviceId), "userId": Bson(userId), "username": Bson(username),
            "model": Bson(model), "osVersion": Bson(osVersion), "appVersion": Bson(appVersion),
            "lastIp": Bson(lastIp), "createdAt": Bson(createdAt), "lastSeenAt": Bson(lastSeenAt),
            "kind": Bson(kind), "name": Bson(name),
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
        const kind = b.tryIndex("kind");
        if (!kind.isNull && kind.get.type == Bson.Type.string) e.kind = kind.get.get!string;
        const name = b.tryIndex("name");
        if (!name.isNull && name.get.type == Bson.Type.string) e.name = name.get.get!string;
        return e;
    }

    /// An enriched fleet document (stored fields plus the computed ones).
    private static DeviceRegistryEntry fromFleetBson(Bson b) @trusted {
        auto e = fromBson(b);
        e.isTestAccount = b["isTestAccount"].get!bool;
        e.isEmulator = b["isEmulator"].get!bool;
        e.isTest = b["isTest"].get!bool;
        e.status = b["isActive"].get!bool ? "active" : "inactive";
        return e;
    }
}

/// Counts over the whole live-owner fleet as of one `nowMs`, independent of
/// the status and test filters: `total == active + inactive`, and `test`
/// (a subset of `total`) counts test-account and emulator devices.
struct DeviceFleetSummary { long total, active, inactive, test; }

/// One fleet page. `total` counts every device matching the page's status and
/// test filters.
struct DeviceFleetPage {
    DeviceRegistryEntry[] devices;
    long total;
    DeviceFleetSummary summary;
}

/// Progress of one `reconcileOrphans` page. Pass `nextId` as the next
/// `afterId`; `done` means the keyset walk reached the end.
struct DeviceReconcileBatch {
    string nextId;
    size_t scanned, deleted;
    bool done;
}

/// Persistence for the admin device directory; collection `device_registry`.
final class DeviceRegistryRepository {
    private MongoCollection collection;
    private MongoCollection users;

    this() {
        collection = AppMongoConnection.getDb()["device_registry"];
        users = AppMongoConnection.getDb()["users"];
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
    /// `lastSeenAt` only moves forward (`$max`), so a delayed check-in or
    /// profile snapshot never makes a device look older than a heartbeat
    /// already recorded. Update-then-insert rather than `upsert` (see
    /// PushDeviceRepository.upsert for why: vibe-d 0.10.3's upsert-created
    /// `_id` read).
    void upsert(DeviceRegistryEntry e) @trusted {
        Bson setDoc = Bson.emptyObject;
        setDoc["userId"] = Bson(e.userId);
        setDoc["username"] = Bson(e.username);
        setDoc["model"] = Bson(e.model);
        setDoc["osVersion"] = Bson(e.osVersion);
        setDoc["appVersion"] = Bson(e.appVersion);
        setDoc["lastIp"] = Bson(e.lastIp);
        setDoc["kind"] = Bson(e.kind);
        setDoc["name"] = Bson(e.name);
        auto update = Bson([
            "$set": setDoc,
            "$max": Bson(["lastSeenAt": Bson(e.lastSeenAt)]),
        ]);
        auto selector = Bson(["_id": Bson(e.deviceId)]);
        if (collection.updateOne(selector, update).matchedCount > 0) return;
        auto fresh = e;
        if (fresh.createdAt == 0) fresh.createdAt = e.lastSeenAt;
        try {
            collection.insertOne(fresh.toBson());
        } catch (Exception e2) {
            collection.updateOne(selector, update);
        }
    }

    /// Heartbeat: raises an existing row's `lastSeenAt` to `nowMs` (never
    /// lowers it) while `userId` owns it; no other field changes and no row is
    /// created. True when the owned row exists. Throws on database errors.
    bool touch(string deviceId, string userId, long nowMs) @trusted {
        return collection.updateOne(
            Bson(["_id": Bson(deviceId), "userId": Bson(userId)]),
            Bson(["$max": Bson(["lastSeenAt": Bson(nowMs)])])).matchedCount > 0;
    }

    /**
     * One page of the admin fleet, most recently seen first (`_id` breaks
     * ties, so pages never overlap or skip). Only devices whose `userId` is a
     * live `users.id` exist here: an orphan left by an interrupted account
     * deletion disappears at once, before the nightly repair removes it.
     * Status is judged against `nowMs`; the page, its `total` and `summary`
     * come from one aggregation over the same rows, so they always agree.
     * Throws on invalid arguments and on database errors.
     */
    DeviceFleetPage fleet(int offset, int limit, DeviceFleetStatus status, bool includeTests, long nowMs) @trusted {
        if (offset < 0) throw new Exception("fleet: offset must be nonnegative");
        if (limit < 1 || limit > FLEET_MAX_LIMIT) throw new Exception("fleet: limit out of range");

        Bson pageFilter = Bson.emptyObject;
        final switch (status) {
            case DeviceFleetStatus.active: pageFilter["isActive"] = Bson(true); break;
            case DeviceFleetStatus.inactive: pageFilter["isActive"] = Bson(false); break;
            case DeviceFleetStatus.all: break;
        }
        if (!includeTests) pageFilter["isTest"] = Bson(false);

        Bson[] pageStages = [Bson(["$match": pageFilter]), Bson(["$sort": fleetSort()])];
        if (offset > 0) pageStages ~= Bson(["$skip": Bson(offset)]);
        pageStages ~= Bson(["$limit": Bson(limit)]);

        static Bson countIf(Bson cond) {
            return Bson(["$sum": Bson(["$cond": Bson([cond, Bson(1), Bson(0)])])]);
        }
        Bson group = Bson.emptyObject;
        group["_id"] = Bson(null);
        group["all"] = Bson(["$sum": Bson(1)]);
        group["active"] = countIf(Bson("$isActive"));
        group["test"] = countIf(Bson("$isTest"));
        group["testActive"] = countIf(Bson(["$and": Bson([Bson("$isTest"), Bson("$isActive")])]));

        auto pipeline = fleetStages(nowMs);
        pipeline ~= Bson(["$facet": Bson([
            "summary": Bson([Bson(["$group": group])]),
            "devices": Bson(pageStages),
        ])]);

        DeviceFleetPage result;
        foreach (doc; collection.aggregate!Bson(pipeline, fleetOptions())) {
            long all, active, test, testActive;
            foreach (s; doc["summary"]) {
                all = readCount(s["all"]);
                active = readCount(s["active"]);
                test = readCount(s["test"]);
                testActive = readCount(s["testActive"]);
            }
            result.summary = DeviceFleetSummary(all, active, all - active, test);
            // The filtered set: drop test devices from the bucket unless included.
            const scopeTotal = includeTests ? all : all - test;
            const scopeActive = includeTests ? active : active - testActive;
            final switch (status) {
                case DeviceFleetStatus.active: result.total = scopeActive; break;
                case DeviceFleetStatus.inactive: result.total = scopeTotal - scopeActive; break;
                case DeviceFleetStatus.all: result.total = scopeTotal; break;
            }
            foreach (d; doc["devices"]) result.devices ~= DeviceRegistryEntry.fromFleetBson(d);
        }
        return result;
    }

    /// One device with its fleet classification as of `nowMs`, or
    /// `DeviceRegistryEntry.init` (empty `deviceId`) when it is absent or its
    /// owner no longer exists. Inactive and test devices are returned.
    DeviceRegistryEntry findFleetById(string deviceId, long nowMs) @trusted {
        if (!deviceId.length) return DeviceRegistryEntry.init;
        Bson[] pipeline = [Bson(["$match": Bson(["_id": Bson(deviceId)])])];
        pipeline ~= fleetStages(nowMs);
        pipeline ~= Bson(["$limit": Bson(1)]);
        foreach (doc; collection.aggregate!Bson(pipeline, fleetOptions()))
            return DeviceRegistryEntry.fromFleetBson(doc);
        return DeviceRegistryEntry.init;
    }

    /// Removes one device regardless of owner (administrative cleanup).
    void remove(string deviceId) @trusted { collection.deleteOne(Bson(["_id": Bson(deviceId)])); }

    /// Removes one device only while `userId` owns it, so a caller acting for
    /// one account can never delete another account's row. True when removed.
    bool remove(string deviceId, string userId) @trusted {
        return collection.deleteOne(Bson(["_id": Bson(deviceId), "userId": Bson(userId)])).deletedCount > 0;
    }

    /// Removes every device of a user (account deletion).
    void removeAllForUser(string userId) @trusted { collection.deleteMany(Bson(["userId": Bson(userId)])); }

    /**
     * One bounded page of the orphan repair: scans up to `batchSize` rows
     * with `_id > afterId` (all rows when `afterId` is ""), in `_id` order,
     * and deletes those whose `userId` matches no `users.id`. The owner set
     * is re-read right before deleting, and each delete is conditional on the
     * row's original `_id`, `userId` and `lastSeenAt`, so a device refreshed
     * or reassigned meanwhile survives (and is not counted). Age alone never
     * deletes anything. `nextId` advances past every scanned row, deleted or
     * not. Throws on invalid arguments or any database error (fail closed),
     * including an empty `users` collection while devices exist, which
     * signals a wrong database rather than a fleet of orphans.
     */
    DeviceReconcileBatch reconcileOrphans(string afterId, int batchSize) @trusted {
        if (batchSize < 1 || batchSize > RECONCILE_MAX_BATCH)
            throw new Exception("reconcileOrphans: batchSize out of range");

        DeviceReconcileBatch batch;
        batch.nextId = afterId;

        // `$gte ""` covers every string `_id` (device ids are strings); the
        // keyset bound keeps each page an `_id` index range scan.
        string rangeOp = afterId.length ? "$gt" : "$gte";
        auto idRange = Bson([rangeOp: Bson(afterId)]);
        Bson[] pipeline = [
            Bson(["$match": Bson(["_id": idRange])]),
            Bson(["$sort": Bson(["_id": Bson(1)])]),
            Bson(["$limit": Bson(batchSize)]),
            Bson(["$project": Bson(["userId": Bson(1), "lastSeenAt": Bson(1)])]),
            Bson(["$lookup": Bson([
                "from": Bson("users"), "localField": Bson("userId"), "foreignField": Bson("id"),
                "pipeline": Bson([Bson(["$limit": Bson(1)]), Bson(["$project": Bson(["_id": Bson(1)])])]),
                "as": Bson("owner")])]),
        ];
        Bson[] candidates;
        foreach (doc; collection.aggregate!Bson(pipeline, fleetOptions())) {
            batch.scanned++;
            batch.nextId = doc["_id"].get!string;
            if (doc["owner"].length == 0) candidates ~= doc;
        }
        batch.done = batch.scanned < cast(size_t) batchSize;
        if (!candidates.length) return batch;

        if (users.estimatedDocumentCount() == 0)
            throw new Exception("reconcileOrphans: users collection is empty; refusing to delete devices");

        // Re-check owners immediately before deleting.
        Bson[] ownerIds;
        foreach (c; candidates)
            if (c["userId"].type == Bson.Type.string) ownerIds ~= c["userId"];
        bool[string] liveOwners;
        if (ownerIds.length) {
            FindOptions opts;
            opts.projection = Bson(["id": Bson(1), "_id": Bson(0)]);
            foreach (u; users.find(Bson(["id": Bson(["$in": Bson(ownerIds)])]), opts))
                liveOwners[u["id"].get!string] = true;
        }

        foreach (c; candidates) {
            auto owner = c["userId"];
            if (owner.type == Bson.Type.string && (owner.get!string in liveOwners) !is null) continue;
            // A missing field reads back as Bson null here, and `field: null`
            // matches a missing field, so the condition stays exact.
            Bson cond = Bson.emptyObject;
            cond["_id"] = c["_id"];
            cond["userId"] = owner;
            cond["lastSeenAt"] = c["lastSeenAt"];
            batch.deleted += cast(size_t) collection.deleteOne(cond).deletedCount;
        }
        return batch;
    }
}

/// Enrichment stages shared by `fleet` and `findFleetById`: keeps rows with a
/// live owner and adds `username` (owner's live name), `isTestAccount`,
/// `isEmulator`, `isTest` and `isActive`.
private Bson[] fleetStages(long nowMs) @trusted {
    // Active means seen less than DEVICE_INACTIVE_MS before nowMs; never-seen
    // (missing/nonpositive/non-numeric) rows are inactive.
    const activeAfter = nowMs - DEVICE_INACTIVE_MS > 0 ? nowMs - DEVICE_INACTIVE_MS : 0;
    static Bson stringOr(string path) {
        return Bson(["$cond": Bson([
            Bson(["$eq": Bson([Bson(["$type": Bson(path)]), Bson("string")])]),
            Bson(path), Bson("")])]);
    }
    return [
        Bson(["$lookup": Bson([
            "from": Bson("users"), "localField": Bson("userId"), "foreignField": Bson("id"),
            "pipeline": Bson([
                Bson(["$limit": Bson(1)]),
                Bson(["$project": Bson(["_id": Bson(0), "username": Bson(1), "isTestAccount": Bson(1)])]),
            ]),
            "as": Bson("owner")])]),
        Bson(["$match": Bson(["owner.0": Bson(["$exists": Bson(true)])])]),
        Bson(["$set": Bson(["owner": Bson(["$arrayElemAt": Bson([Bson("$owner"), Bson(0)])])])]),
        Bson(["$set": Bson([
            "username": Bson(["$ifNull": Bson([Bson("$owner.username"), Bson("$username")])]),
            "isTestAccount": Bson(["$eq": Bson([Bson("$owner.isTestAccount"), Bson(true)])]),
            "isEmulator": Bson(["$regexMatch": Bson([
                "input": stringOr("$model"),
                "regex": Bson(EMULATOR_MODEL_PATTERN),
                "options": Bson("i")])]),
            "isActive": Bson(["$and": Bson([
                Bson(["$isNumber": Bson("$lastSeenAt")]),
                Bson(["$gt": Bson([Bson("$lastSeenAt"), Bson(activeAfter)])]),
            ])]),
        ])]),
        Bson(["$set": Bson(["isTest": Bson(["$or": Bson([Bson("$isTestAccount"), Bson("$isEmulator")])])])]),
        Bson(["$project": Bson(["owner": Bson(0)])]),
    ];
}

/// Most recently seen first, `_id` as the deterministic tiebreak. Built
/// key by key: field order is sort priority, and a Bson from an associative
/// array has none.
private Bson fleetSort() @trusted {
    Bson s = Bson.emptyObject;
    s["lastSeenAt"] = Bson(-1);
    s["_id"] = Bson(1);
    return s;
}

private AggregateOptions fleetOptions() @trusted {
    AggregateOptions o;
    o.maxTimeMS = FLEET_MAX_TIME_MS;
    return o;
}

/// `$sum` yields int or long depending on magnitude.
private long readCount(const Bson b) @trusted {
    switch (b.type) with (Bson.Type) {
        case int_: return b.get!int;
        case long_: return b.get!long;
        case double_: return cast(long) b.get!double;
        default: return 0;
    }
}

@("device inactivity window is exactly 90 days in milliseconds")
unittest {
    static assert(DEVICE_INACTIVE_MS == 90L * 24 * 60 * 60 * 1000);
}
