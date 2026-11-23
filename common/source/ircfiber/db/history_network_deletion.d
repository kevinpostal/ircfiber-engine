module ircfiber.db.history_network_deletion;

import std.uuid : UUID;
import vibe.data.bson : Bson;
import vibe.db.mongo.mongo : MongoDatabase;
import ircfiber.db.history_retention : HistoryRetentionException, HistoryRetentionFailure;

private enum FENCES = "history_network_fences";
private enum PAGE = 256;
/// Majority checks for the owning creation path. Read the catalog before the
/// fence: an absent catalog after deletion must not be mistaken for a new ID.
bool historyNetworkSaveUpdatesExisting(MongoDatabase db, string networkId, string ownerId) {
    validId(networkId); validId(ownerId);
    auto rows = page(db, "networks", Bson(["id": Bson(networkId)]),
        Bson(["_id": Bson(0), "userId": Bson(1)]), 2);
    if (rows.length > 1) fail();
    if (rows.length && (rows[0]["userId"].type != Bson.Type.string
            || rows[0]["userId"].get!string != ownerId)) fail();
    if (historyNetworkDeletionOwner(db, networkId).length) fail();
    return rows.length != 0;
}

/// Empty means no durable fence, never inferred deletion. Malformed or
/// unavailable evidence throws and must not authorize a compensating erase.
string historyNetworkDeletionOwner(MongoDatabase db, string networkId) {
    validId(networkId);
    auto fence = loadFence(db, networkId);
    return fence.isNull ? "" : fenceOwner(fence);
}


/// Immutable, content-free deletion authority and permanent cleanup queue. A
/// missing catalog row is never deletion evidence. Even a retry must prove the
/// same owner from the catalog or an already majority-committed tombstone.
void recordHistoryNetworkFence(MongoDatabase db, string networkId, string ownerId) {
    validId(networkId); validId(ownerId);
    auto fence = loadFence(db, networkId);
    if (!fence.isNull && fenceOwner(fence) != ownerId) fail();
    auto rows = page(db, "networks", Bson(["id": Bson(networkId)]),
        Bson(["_id": Bson(0), "userId": Bson(1)]), 2);
    if (rows.length > 1) fail();
    if (!rows.length) {
        if (fence.isNull) fail();
        return;
    }
    if (rows[0]["userId"].type != Bson.Type.string
            || rows[0]["userId"].get!string != ownerId) fail();
    if (!fence.isNull) return;

    auto command = Bson.emptyObject;
    command["update"] = Bson(FENCES);
    command["updates"] = Bson([Bson([
        "q": Bson(["_id": Bson(networkId)]),
        "u": Bson(["$setOnInsert": Bson(["_id": Bson(networkId), "ownerId": Bson(ownerId)])]),
        "upsert": Bson(true), "multi": Bson(false)])]);
    auto reply = run(db, command, true, true);
    // Concurrent upserts can report duplicate key. Only independent majority
    // evidence of exactly the requested immutable identity makes that safe.
    fence = loadFence(db, networkId);
    if (fence.isNull || fenceOwner(fence) != ownerId) fail();
    if (!has(reply, "writeErrors") && integer(reply["n"]) != 1) fail();
}

/// Repository-level guard so every deletion path fences before losing the
/// owner. Ownerless/missing rows are not erased; retries use durable fences.
string fenceHistoryNetworkForDeletion(MongoDatabase db, string networkId) {
    validId(networkId);
    auto rows = page(db, "networks", Bson(["id": Bson(networkId)]),
        Bson(["_id": Bson(0), "userId": Bson(1)]), 2);
    if (rows.length > 1) fail();
    string owner;
    if (rows.length) {
        if (rows[0]["userId"].type != Bson.Type.string) fail();
        owner = rows[0]["userId"].get!string;
    } else {
        auto fence = loadFence(db, networkId);
        if (fence.isNull) fail();
        owner = fenceOwner(fence);
    }
    recordHistoryNetworkFence(db, networkId, owner);
    return owner;
}

/// Call only after deleting the account's fenced network catalog rows. The
/// majority absence proof refuses to discard policy while any ownership remains.
void removeHistoryPolicyAfterNetworkFences(MongoDatabase db, string ownerId) {
    validId(ownerId);
    if (page(db, "networks", Bson(["userId": Bson(ownerId)]),
            Bson(["_id": Bson(1)]), 1).length) fail();
    auto command = Bson.emptyObject;
    command["delete"] = Bson("account_history_policy");
    command["deletes"] = Bson([Bson(["q": Bson(["_id": Bson(ownerId)]), "limit": Bson(1)])]);
    auto reply = run(db, command, true);
    const n = integer(reply["n"]);
    if (n < 0 || n > 1) fail();
}

/// One scope and at most one 256-record physical deletion page per turn.
/// Every tombstone remains in this keyset roster forever, including empty ones:
/// a writer admitted before fencing can finish after an empty pass. No lease,
/// successful empty scan, restart, or lost dirty signal can retire that defense.
/// Advance before work so an unavailable/corrupt scope cannot starve others.
void sweepHistoryNetworkFences(MongoDatabase db, ref string cursor) {
    auto filter = cursor.length
        ? Bson(["_id": Bson(["$gt": Bson(cursor)])]) : Bson.emptyObject;
    auto rows = page(db, FENCES, filter, Bson(["_id": Bson(1), "ownerId": Bson(1)]),
        1, Bson(["_id": Bson(1)]));
    if (!rows.length) { cursor = ""; return; }
    auto fence = rows[0];
    if (fence["_id"].type != Bson.Type.string) fail();
    cursor = fence["_id"].get!string.idup;
    validId(cursor);
    fenceOwner(fence);
    auto scopeFilter = Bson(["networkId": Bson(cursor)]);
    // Include legacy rows without historyOwnerId. Authority is the immutable
    // deleted network identity, not a guessed current owner or engine scope.
    if (deletePage(db, "messages", scopeFilter)) return;
    // Suppression has no plaintext. Its only purpose is a surviving source;
    // once the network is writer-fenced no source in that identity is visible.
    import ircfiber.db.history_suppression : HistorySuppressionRepository;
    (new HistorySuppressionRepository(db)).deleteFencedNetworkPage(cursor);
}

private bool deletePage(MongoDatabase db, string collection, Bson filter) {
    auto rows = page(db, collection, filter, Bson(["_id": Bson(1)]), PAGE);
    if (!rows.length) return false;
    Bson[] ids;
    foreach (row; rows) {
        if (!has(row, "_id")) fail();
        ids ~= row["_id"];
    }
    filter["_id"] = Bson(["$in": Bson(ids)]);
    auto command = Bson.emptyObject;
    command["delete"] = Bson(collection);
    command["deletes"] = Bson([Bson(["q": filter, "limit": Bson(0)])]);
    const n = integer(run(db, command, true)["n"]);
    if (n < 0 || n > rows.length) fail();
    return true;
}

private Bson loadFence(MongoDatabase db, string networkId) {
    auto rows = page(db, FENCES, Bson(["_id": Bson(networkId)]), Bson.init, 2);
    if (rows.length > 1) fail();
    return rows.length ? rows[0] : Bson(null);
}

private string fenceOwner(Bson fence) {
    if (fence["ownerId"].type != Bson.Type.string) fail();
    auto owner = fence["ownerId"].get!string;
    validId(owner);
    return owner;
}

private Bson[] page(MongoDatabase db, string collection, Bson filter,
        Bson projection, int limit, Bson sort = Bson.init) {
    auto command = Bson.emptyObject;
    command["find"] = Bson(collection);
    command["filter"] = filter;
    if (projection.type != Bson.Type.undefined) command["projection"] = projection;
    if (sort.type != Bson.Type.undefined) command["sort"] = sort;
    command["limit"] = Bson(limit);
    command["batchSize"] = Bson(limit);
    command["singleBatch"] = Bson(true);
    command["readConcern"] = Bson(["level": Bson("majority")]);
    auto reply = run(db, command);
    auto cursor = reply["cursor"];
    if (cursor.type != Bson.Type.object || integer(cursor["id"]) != 0
            || cursor["ns"].type != Bson.Type.string
            || cursor["ns"].get!string != db.name ~ "." ~ collection
            || cursor["firstBatch"].type != Bson.Type.array
            || cursor["firstBatch"].length > limit) fail();
    Bson[] result;
    foreach (row; cursor["firstBatch"].byValue) {
        if (row.type != Bson.Type.object) fail();
        result ~= row;
    }
    return result;
}

private Bson run(MongoDatabase db, Bson command, bool write = false, bool duplicate = false) {
    command["maxTimeMS"] = Bson(5000);
    if (write) {
        command["ordered"] = Bson(true);
        command["writeConcern"] = Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
    }
    Bson reply;
    try reply = db.runCommandUnchecked(command);
    catch (Exception) { fail(); }
    if (reply.type != Bson.Type.object || integer(reply["ok"]) != 1
            || has(reply, "writeConcernError") || has(reply, "writeConcernErrors")) fail();
    if (has(reply, "writeErrors")) {
        auto errors = reply["writeErrors"];
        if (errors.type != Bson.Type.array) fail();
        if (errors.length && (!duplicate || errors.length != 1
                || errors[0].type != Bson.Type.object || integer(errors[0]["code"]) != 11000
                || integer(errors[0]["index"]) != 0)) fail();
    }
    return reply;
}

private bool has(Bson doc, string field) {
    if (doc.type != Bson.Type.object) return false;
    foreach (key, value; doc.byKeyValue) if (key == field) return true;
    return false;
}

private long integer(Bson value) {
    if (value.type == Bson.Type.int_) return value.get!int;
    if (value.type == Bson.Type.long_) return value.get!long;
    if (value.type == Bson.Type.double_ && value.get!double == 1.0) return 1;
    fail();
    return 0;
}

private void validId(string value) {
    UUID id;
    try id = UUID(value);
    catch (Exception) { fail(); }
    if (id == UUID.init || id.toString() != value) fail();
}

private void fail() {
    throw new HistoryRetentionException(HistoryRetentionFailure.unavailable);
}
