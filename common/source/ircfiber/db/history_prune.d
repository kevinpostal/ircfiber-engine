module ircfiber.db.history_prune;

import ircfiber.db.history_retention : HistoryPolicy, HistoryRetentionRepository,
    HistoryRetentionException, HistoryRetentionFailure, HistoryRetentionState, NORMAL_WINDOW_MS;
import ircfiber.db.history_size_walk : HistorySizeWalk, HISTORY_PAGE_SIZE, HISTORY_WINDOW_INDEX;
import ircfiber.db.history_suppression : HistorySuppressionRepository;
import core.time : MonoTime, msecs;
import vibe.data.bson : Bson;
import vibe.db.mongo.mongo : MongoDatabase;

/// One owner at a fixed clock. Resume by retaining the job between fiber turns;
/// after a crash, construct another job from a freshly loaded policy. The floor
/// is durable before any source removal, so restarting is idempotent.
final class HistoryPruneJob {
    private MongoDatabase database;
    private HistoryRetentionRepository policies;
    private HistorySuppressionRepository suppression;
    private HistoryPolicy policy;
    private long nowMs;
    private HistorySizeWalk walk = HistorySizeWalk.init;
    private enum Phase { inspect, size, clean, done }
    private Phase phase;
    private long examined;
    private long pruned;
    private struct DeleteKey { Bson witness; long bytes; }
    private DeleteKey[] page;
    private size_t nextRow;

    this(MongoDatabase db, HistoryPolicy snapshot, long clockMs) {
        requireClock(clockMs);
        database = db;
        policies = new HistoryRetentionRepository(db);
        suppression = new HistorySuppressionRepository(db);
        policy = snapshot;
        nowMs = clockMs;
    }

    long bytesExamined() const pure nothrow { return examined; }
    long bytesPruned() const pure nothrow { return pruned; }

    /// At most one 256-row source/index page is read per turn. Physical deletes
    /// are time-sliced too; a retained page has already had its evidence fenced.
    /// Exceptions mean retry/unavailable, never successful completion.
    bool advance() {
        if (phase == Phase.done) return true;
        requireActive(policies);
        if (phase == Phase.inspect) {
            auto current = policies.loadPolicy(policy.ownerId);
            if (current.isNull) fail(HistoryRetentionFailure.unavailable);
            policy = current.get;
            if (!policy.pro && (policy.normalFromMs == 0 || policy.due(nowMs))) {
                walk = HistorySizeWalk(policy, nowMs);
                phase = Phase.size;
            } else {
                phase = Phase.clean;
            }
        }
        if (phase == Phase.size) {
            const previousBytes = walk.bytesExamined;
            const complete = walk.advance(database);
            examined += walk.bytesExamined - previousBytes;
            if (!complete) return false;
            auto replacement = policy;
            replacement.expiredThroughMs = walk.cutoff;
            if (policy.due(nowMs)) {
                replacement.normalFromMs = 0;
                replacement.noticeAtMs = 0;
            }
            if (!policies.compareAndSwapPolicy(policy, replacement, nowMs)) {
                // No speculative cutoff survives a lost grant/floor CAS.
                phase = Phase.inspect;
                return false;
            }
            policy = replacement;
            phase = Phase.clean;
            return false; // never read a second page in the size-walk turn
        }
        if (policy.expiredThroughMs == 0) {
            phase = Phase.done;
            return true; // in particular, never scan an uncapped Pro archive
        }
        if (!page.length) {
            auto pending = loadPage();
            if (!pending.length) {
                phase = Phase.done;
                return true;
            }
            // Do not retain plaintext in a shadow archive. This call persists
            // only compact suppression witnesses before any exact-ID removal.
            // Release all payloads before yielding; only exact deletion keys
            // survive a slow series of majority-acknowledged deletes.
            suppression.preserveBeforeDelete(pending);
            page.length = pending.length;
            foreach (i, ref row; pending) {
                // A channel clear can remove and reuse an _id between evidence
                // preservation and this worker's delete. Match the witnessed
                // generation and search relations, not just ID/charge/time ≤ cut.
                auto witness = Bson.emptyObject;
                foreach (key; ["_id", "serverId", "networkId", "channel", "t", "eid", "msgid",
                        "searchVersion", "searchKind", "searchAliases", "searchTarget"]) {
                    auto field = row.tryIndex(key);
                    witness[key] = field.isNull ? Bson(["$exists": Bson(false)]) : field.get;
                }
                page[i] = DeleteKey(witness, row["historyBytes"].get!long);
            }
            nextRow = 0;
        }
        const started = MonoTime.currTime;
        do {
            const size = page[nextRow].bytes;
            size_t end = nextRow + 1;
            while (end < page.length && page[end].bytes == size) ++end;
            // Equal-charge groups make n * size exact even when another cleaner
            // concurrently removes some or all of these IDs.
            Bson[] witnesses;
            witnesses.length = end - nextRow;
            foreach (i; nextRow .. end) witnesses[i - nextRow] = page[i].witness;
            const removed = deleteGroup(witnesses, size);
            pruned += removed * size;
            nextRow = end;
        } while (nextRow < page.length && MonoTime.currTime - started < msecs(25));
        if (nextRow == page.length) {
            page = null;
            nextRow = 0;
        }
        return false;
    }

    private Bson[] loadPage() {
        auto sort = Bson.emptyObject;
        sort["t"] = Bson(-1);
        sort["_id"] = Bson(-1);
        auto command = Bson.emptyObject;
        command["find"] = Bson("messages");
        command["filter"] = Bson(["historyOwnerId": Bson(policy.ownerId),
            "t": Bson(["$lte": Bson(policy.expiredThroughMs)])]);
        command["projection"] = Bson(["_id": Bson(1), "historyOwnerId": Bson(1), "historyBytes": Bson(1),
            "serverId": Bson(1), "networkId": Bson(1), "channel": Bson(1), "t": Bson(1),
            "eid": Bson(1), "msgid": Bson(1), "payload": Bson(1), "searchVersion": Bson(1),
            "searchKind": Bson(1), "searchTarget": Bson(1), "searchAliases": Bson(1)]);
        command["sort"] = sort;
        command["hint"] = Bson(HISTORY_WINDOW_INDEX);
        command["limit"] = Bson(HISTORY_PAGE_SIZE);
        command["batchSize"] = Bson(HISTORY_PAGE_SIZE);
        command["singleBatch"] = Bson(true);
        command["readConcern"] = Bson(["level": Bson("majority")]);
        command["maxTimeMS"] = Bson(5000);
        auto reply = run(database, command);
        auto cursor = reply["cursor"];
        auto batch = cursor["firstBatch"];
        requireData(cursor.type == Bson.Type.object && cursor["id"].type == Bson.Type.long_
            && cursor["id"].get!long == 0 && cursor["ns"].type == Bson.Type.string
            && cursor["ns"].get!string == database.name ~ ".messages"
            && batch.type == Bson.Type.array && batch.length <= HISTORY_PAGE_SIZE);
        Bson[] result;
        result.reserve(batch.length);
        foreach (row; batch.byValue) {
            requireData(row.type == Bson.Type.object && row["_id"].type == Bson.Type.string
                && row["_id"].get!string.length != 0
                && row["historyOwnerId"].type == Bson.Type.string
                && row["historyOwnerId"].get!string == policy.ownerId
                && row["historyBytes"].type == Bson.Type.long_);
            const size = row["historyBytes"].get!long;
            const time = integer(row["t"]);
            requireData(size > 0 && size <= 16 * 1024 * 1024
                && time > 0 && time <= policy.expiredThroughMs);
            result ~= row;
        }
        return result;
    }

    private long deleteGroup(Bson[] witnesses, long size) {
        auto filter = Bson(["$or": Bson(witnesses),
            "historyOwnerId": Bson(policy.ownerId), "historyBytes": Bson(size),
            "t": Bson(["$lte": Bson(policy.expiredThroughMs)])]);
        auto command = Bson.emptyObject;
        command["delete"] = Bson("messages");
        command["deletes"] = Bson([Bson(["q": filter, "limit": Bson(0)])]);
        command["ordered"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        command["writeConcern"] = majorityWriteConcern();
        auto reply = run(database, command);
        const removed = integer(reply["n"]);
        requireData(removed >= 0 && removed <= witnesses.length);
        return removed;
    }
}

/// Grant helper shared by admin/donor callers. A due Normal promotion computes
/// the complete cut and publishes it WITH the grant in one exact-snapshot CAS.
/// It never publishes a cleared deadline while that computation is pending.
/// On completion applied=false means reload policy and recompute/retry grants;
/// replacement is available only after a successful CAS. No deletion occurs.
final class HistoryGrantJob {
    private MongoDatabase database;
    private HistoryRetentionRepository policies;
    private HistoryPolicy expected;
    private HistoryPolicy proposed;
    private bool manualPro;
    private bool donorPro;
    private long nowMs;
    private HistorySizeWalk walk = HistorySizeWalk.init;
    private bool initialized;
    private bool needsWalk;
    private bool finished;
    private bool accepted;

    this(MongoDatabase db, HistoryPolicy snapshot, bool manual, bool donor, long clockMs) {
        requireClock(clockMs);
        database = db;
        policies = new HistoryRetentionRepository(db);
        expected = snapshot;
        manualPro = manual;
        donorPro = donor;
        nowMs = clockMs;
    }

    bool applied() const pure nothrow { return accepted; }
    long bytesExamined() const { return needsWalk ? walk.bytesExamined : 0; }
    HistoryPolicy replacement() const {
        if (!finished || !accepted) fail(HistoryRetentionFailure.unavailable);
        return proposed;
    }

    bool advance() {
        if (finished) return true;
        auto state = requireActive(policies, true);
        if (!initialized) {
            auto current = policies.loadPolicy(expected.ownerId);
            if (current.isNull) fail(HistoryRetentionFailure.unavailable);
            if (current.get != expected) return finished = true;
            needsWalk = !expected.pro && (manualPro || donorPro) && expected.due(nowMs);
            if (needsWalk) walk = HistorySizeWalk(expected, nowMs);
            initialized = true;
        }
        if (needsWalk && state.maintenancePaused) fail(HistoryRetentionFailure.unavailable);
        if (needsWalk && !walk.advance(database)) return false;
        proposed = expected.withGrants(manualPro, donorPro, nowMs,
            needsWalk ? walk.cutoff : -1);
        if (state.maintenancePaused && proposed.expiredThroughMs > expected.expiredThroughMs)
            fail(HistoryRetentionFailure.unavailable);
        accepted = policies.compareAndSwapPolicy(expected, proposed, nowMs);
        return finished = true;
    }
}

private HistoryRetentionState requireActive(HistoryRetentionRepository repository, bool allowPaused = false) {
    auto state = repository.loadInstallationState();
    if (!state.active || (!allowPaused && state.maintenancePaused))
        fail(HistoryRetentionFailure.unavailable);
    return state;
}
private void requireClock(long nowMs) {
    if (nowMs <= 0 || nowMs > long.max - NORMAL_WINDOW_MS)
        fail(HistoryRetentionFailure.invalidInput);
}
private void fail(HistoryRetentionFailure reason) { throw new HistoryRetentionException(reason); }
private void requireData(bool valid) { if (!valid) fail(HistoryRetentionFailure.malformed); }
private bool has(const Bson document, string field) {
    if (document.type != Bson.Type.object) return false;
    foreach (key, value; document.byKeyValue) if (key == field) return true;
    return false;
}
private long integer(const Bson value) {
    if (value.type == Bson.Type.long_) return value.get!long;
    if (value.type == Bson.Type.int_) return value.get!int;
    if (value.type == Bson.Type.double_) {
        const number = value.get!double;
        requireData(number >= -9_007_199_254_740_991.0 && number <= 9_007_199_254_740_991.0);
        const result = cast(long)number;
        requireData(number == cast(double)result);
        return result;
    }
    fail(HistoryRetentionFailure.malformed);
    return 0;
}
private Bson majorityWriteConcern() {
    return Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
}
private Bson run(MongoDatabase db, Bson command) {
    Bson reply;
    try reply = db.runCommandUnchecked(command);
    catch (Exception) { fail(HistoryRetentionFailure.unavailable); }
    requireData(reply.type == Bson.Type.object);
    if (has(reply, "writeConcernError") || has(reply, "writeConcernErrors"))
        fail(HistoryRetentionFailure.unavailable);
    if (integer(reply["ok"]) != 1) fail(HistoryRetentionFailure.unavailable);
    if (has(reply, "writeErrors")) {
        requireData(reply["writeErrors"].type == Bson.Type.array);
        if (reply["writeErrors"].length) fail(HistoryRetentionFailure.unavailable);
    }
    return reply;
}
