module ircfiber.db.history_visibility;

import ircfiber.archive_protocol : isCanonicalArchiveOperationId;
import ircfiber.db.history_retention;
import ircfiber.db.mongo : AppMongoConnection;
import std.algorithm.comparison : min;
import std.datetime : Clock;
import vibe.data.bson : Bson;
import vibe.db.mongo.mongo : MongoDatabase;

/// An initialized view belongs to one operation and one immutable network.
/// Empty/default views cannot be used as permission to bypass active policy.
struct HistoryReadScope {
    private string networkKey, ownerKey;
    private bool enabled;
    private long directFloor, publicFloor;
    string ownerId() const pure nothrow { return ownerKey; }
    string networkId() const pure nothrow { return networkKey; }
    bool active() const { require(networkKey.length != 0); return enabled; }
    long floor(bool direct) const { require(networkKey.length != 0); return direct ? directFloor : publicFloor; }
    bool allows(long timestampMs, bool direct) const { return timestampMs > 0 && (!active || timestampMs > floor(direct)); }

    Bson filter(Bson oldFilter) const {
        if (!active) return Bson(["$and": Bson([oldFilter, Bson(["networkId": Bson(networkKey),
            "t": Bson(["$gt": Bson(0L)]), "$or": Bson([
                Bson(["historyOwnerId": Bson(["$exists": Bson(false)])]),
                Bson(["historyOwnerId": Bson(ownerKey)])])])])]);
        auto required = Bson(["networkId": Bson(networkKey), "historyOwnerId": Bson(ownerKey),
            "t": Bson(["$gt": Bson(directFloor)])]);
        // Only original private records were historically exempt from TTL. A
        // subsequent buffer rename cannot change the legacy cutoff decision.
        if (publicFloor > directFloor) required["$or"] = Bson([
            Bson(["historyWasDirect": Bson(true)]), Bson(["t": Bson(["$gt": Bson(publicFloor)])])]);
        return Bson(["$and": Bson([oldFilter, required])]);
    }
}

/// Reads only installation/owner/fence/policy metadata; the search worker needs
/// neither accounts nor fund data. Missing/foreign/fenced networks have no
/// entry. An undecodable/missing policy is an error, never an empty Normal page.
final class HistoryReadBatch {
    private HistoryReadScope[string] scopes;
    private bool enabled;
    this(MongoDatabase db, string[] networkIds, string expectedOwner = "", long nowMs = 0) {
        const state = (new HistoryRetentionRepository(db)).loadInstallationState();
        enabled = state.active;
        if (!nowMs) nowMs = (Clock.currTime.stdTime - 621355968000000000L) / 10_000L;
        require(nowMs > 0);
        if (expectedOwner.length) require(isCanonicalArchiveOperationId(expectedOwner));
        Bson[] keys;
        bool[string] seen;
        foreach (id; networkIds) {
            if (!id.length || id in seen) continue;
            seen[id] = true;
            if (!enabled || isCanonicalArchiveOperationId(id)) keys ~= Bson(id);
        }
        if (!keys.length) return;
        bool[string] fenced;
        foreach (row; findKeys(db, "history_network_fences", "_id", keys, Bson(["_id": Bson(1)])))
            fenced[row["_id"].get!string] = true;
        string[string] owners;
        Bson[] policyKeys;
        bool[string] policySeen;
        foreach (row; findKeys(db, "networks", "id", keys, Bson(["_id": Bson(0), "id": Bson(1), "userId": Bson(1)]))) {
            auto id = row["id"].get!string;
            require(id in seen && id !in owners);
            string owner = row["userId"].type == Bson.Type.string ? row["userId"].get!string : "";
            owners[id] = owner;
            if (id in fenced || !isCanonicalArchiveOperationId(owner) || (expectedOwner.length && owner != expectedOwner)) continue;
            if (!enabled) { scopes[id] = HistoryReadScope(id, owner, false); continue; }
            if (owner !in policySeen) { policySeen[owner] = true; policyKeys ~= Bson(owner); }
        }
        if (!enabled) return;
        HistoryPolicy[string] policies;
        foreach (row; findKeys(db, "account_history_policy", "_id", policyKeys, Bson.init)) {
            const owner = row["_id"].get!string;
            require(owner in policySeen && owner !in policies);
            policies[owner] = decodePolicy(row, owner);
        }
        require(policies.length == policyKeys.length);
        foreach (id, owner; owners) {
            if (id in fenced || owner !in policies || (expectedOwner.length && owner != expectedOwner)) continue;
            auto policy = policies[owner];
            scopes[id] = HistoryReadScope(id, owner, true, policy.visibleFloor(nowMs, true), policy.visibleFloor(nowMs, false));
        }
    }
    bool active() const pure nothrow { return enabled; }
    bool contains(string networkId) const pure nothrow { return (networkId in scopes) !is null; }
    HistoryReadScope network(string networkId) {
        auto value = networkId in scopes;
        require(value !is null);
        return *value;
    }
}

HistoryReadScope historyReadScope(string networkId, string expectedOwner = "", long nowMs = 0) {
    require(AppMongoConnection.isConnected());
    return (new HistoryReadBatch(AppMongoConnection.getDb(), [networkId], expectedOwner, nowMs)).network(networkId);
}
private void require(bool ok) {
    if (!ok) throw new HistoryRetentionException(HistoryRetentionFailure.unavailable);
}
private Bson[] findKeys(MongoDatabase db, string collection, string field, Bson[] keys, Bson projection) {
    Bson[] result;
    result.reserve(keys.length);
    foreach (page; 0 .. (keys.length + 255) / 256) {
        auto batch = keys[page * 256 .. min(keys.length, (page + 1) * 256)];
        auto cmd = Bson.emptyObject;
        cmd["find"] = Bson(collection);
        cmd["filter"] = Bson([field: Bson(["$in": Bson(batch)])]);
        if (projection.type == Bson.Type.object) cmd["projection"] = projection;
        cmd["limit"] = Bson(cast(long) batch.length + 1);
        cmd["batchSize"] = cmd["limit"];
        cmd["singleBatch"] = Bson(true);
        cmd["maxTimeMS"] = Bson(2000);
        cmd["readConcern"] = Bson(["level": Bson("majority")]);
        auto cursor = db.runCommandChecked(cmd)["cursor"];
        auto rows = cursor["firstBatch"];
        require(cursor["id"].get!long == 0 && cursor["ns"].get!string == db.name ~ "." ~ collection
            && rows.type == Bson.Type.array && rows.length <= batch.length);
        foreach (row; rows.byValue) result ~= row;
    }
    return result;
}
