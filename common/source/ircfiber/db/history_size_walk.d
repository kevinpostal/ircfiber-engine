module ircfiber.db.history_size_walk;

import ircfiber.db.history_retention : HistoryPolicy, HistoryRetentionException, HistoryRetentionFailure,
    NORMAL_BYTES, NORMAL_WINDOW_MS;
import std.algorithm.comparison : max;
import vibe.data.bson : Bson;
import vibe.db.mongo.mongo : MongoDatabase;

enum HISTORY_WINDOW_INDEX = "history_owner_window_v1";
enum HISTORY_PAGE_SIZE = 256;

/// The order matters for both the covered projection and the exclusive resume key.
Bson historyWindowKeys() {
    auto keys = Bson.emptyObject;
    keys["historyOwnerId"] = Bson(1);
    keys["t"] = Bson(-1);
    keys["_id"] = Bson(-1);
    keys["historyBytes"] = Bson(1);
    return keys;
}

/// One account, one policy CAS snapshot. Keep only this cursor between turns,
/// not the rows. A cursor may be abandoned on crash; nothing is deleted until
/// finish and a successful grant/floor CAS. Concurrent new arrivals are picked
/// up on the next dirty/roster sweep.
struct HistorySizeWalk {
    private string ownerId;
    private long lastTime;
    private string lastId;
    private long floor;
    private long bytes;
    private bool finished;

    @disable this();
    this(const ref HistoryPolicy policy, long nowMs) {
        if (policy.pro || nowMs <= 0 || !policy.ownerId.length || policy.normalFromMs > nowMs)
            throw new HistoryRetentionException(HistoryRetentionFailure.invalidInput);
        ownerId = policy.ownerId;
        floor = max(policy.expiredThroughMs, nowMs - NORMAL_WINDOW_MS);
    }

    long bytesExamined() const pure nothrow { return bytes; }
    long cutoff() const {
        if (!finished) throw new HistoryRetentionException(HistoryRetentionFailure.unavailable);
        return floor;
    }

    Bson pageCommand() const {
        auto filter = Bson(["historyOwnerId": Bson(ownerId), "t": Bson(["$gt": Bson(floor)])]);
        if (lastId.length) filter["$or"] = Bson([
            Bson(["t": Bson(["$lt": Bson(lastTime)])]),
            Bson(["t": Bson(lastTime), "_id": Bson(["$lt": Bson(lastId)])])]);
        auto sort = Bson.emptyObject;
        sort["t"] = Bson(-1);
        sort["_id"] = Bson(-1);
        auto cmd = Bson.emptyObject;
        cmd["find"] = Bson("messages");
        cmd["filter"] = filter;
        cmd["sort"] = sort;
        cmd["projection"] = Bson(["t": Bson(1), "_id": Bson(1), "historyBytes": Bson(1)]);
        cmd["hint"] = Bson(HISTORY_WINDOW_INDEX);
        cmd["batchSize"] = Bson(HISTORY_PAGE_SIZE);
        cmd["limit"] = Bson(HISTORY_PAGE_SIZE);
        cmd["singleBatch"] = Bson(true);
        cmd["readConcern"] = Bson(["level": Bson("majority")]);
        cmd["maxTimeMS"] = Bson(5000);
        return cmd;
    }

    /// One bounded find per invocation. An empty page, not a short batch,
    /// proves exhaustion (Mongo can stop a batch at its wire-size limit).
    bool advance(MongoDatabase db) {
        if (finished) return true;
        auto reply = db.runCommandChecked(pageCommand());
        auto cursor = reply["cursor"];
        auto batch = cursor["firstBatch"];
        if (cursor["id"].type != Bson.Type.long_ || cursor["id"].get!long != 0 ||
                cursor["ns"].type != Bson.Type.string || cursor["ns"].get!string != db.name ~ ".messages" ||
                batch.type != Bson.Type.array || batch.length > HISTORY_PAGE_SIZE)
            throw new HistoryRetentionException(HistoryRetentionFailure.malformed);
        if (!batch.length) return finished = true;
        foreach (doc; batch.byValue) {
            auto t = doc["t"];
            if (doc["historyBytes"].type != Bson.Type.long_ || doc["_id"].type != Bson.Type.string ||
                    (t.type != Bson.Type.long_ && t.type != Bson.Type.int_))
                throw new HistoryRetentionException(HistoryRetentionFailure.malformed);
            const time = t.type == Bson.Type.long_ ? t.get!long : t.get!int;
            const size = doc["historyBytes"].get!long;
            const id = doc["_id"].get!string;
            if (size <= 0 || size > 16 * 1024 * 1024 || !id.length || time <= floor ||
                    (lastId.length && (time > lastTime || (time == lastTime && id >= lastId))))
                throw new HistoryRetentionException(HistoryRetentionFailure.malformed);
            bytes += size;
            if (bytes > NORMAL_BYTES) {
                floor = time; // the entire overflowing timestamp group expires, including ties above this _id
                return finished = true;
            }
            // Borrow IDs within this page; only the final ID outlives the reply.
            lastTime = time;
            lastId = id;
        }
        lastId = lastId.idup;
        return false;
    }
}
