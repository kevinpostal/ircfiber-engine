module ircfiber.db.history_retention;

public import ircfiber.db.history_policy_model;
import ircfiber.db.mongo : AppMongoConnection;
import std.algorithm.comparison : max;
import std.conv : to;
import std.typecons : Nullable;
import std.uuid : UUID;
import vibe.data.bson : Bson;
import vibe.db.mongo.mongo : MongoDatabase;

enum HistoryRetentionPhase { legacy, prepare, active }
enum HistoryRetentionFailure { invalidInput, malformed, unavailable, reconciliationRequired }

/// Messages intentionally exclude commands, account identifiers and driver errors.
class HistoryRetentionException : Exception {
    HistoryRetentionFailure failure;
    this(HistoryRetentionFailure reason) {
        failure = reason;
        super("History retention " ~ to!string(reason));
    }
}

/// Absence of policy-v1 means legacy compatibility, never active retention.
/// Additional fields on the singleton belong to resumable migration tooling.
struct HistoryRetentionState {
    HistoryRetentionPhase phase;
    long cutoverAtMs;
    long legacyTtlSeconds;
    bool donorReconciliationComplete;
    // Operational pause is independent of active read policy and never resets floors.
    bool maintenancePaused;

    bool active() const pure nothrow @safe { return phase == HistoryRetentionPhase.active; }
    long legacyPublicFloor() const {
        requireInput(cutoverAtMs >= 0 && legacyTtlSeconds >= 0
            && legacyTtlSeconds <= long.max / 1000);
        return cutoverAtMs > 0 ? max(0L, cutoverAtMs - legacyTtlSeconds * 1000) : 0;
    }
}

/// No constructor DDL, TTL manipulation, pruning or permission expansion.
/// All durable decisions use majority reads and majority+journal writes, also
/// on standalone Mongo; no multi-document transaction is required.
final class HistoryRetentionRepository {
    private MongoDatabase database;
    private enum policies = "account_history_policy";
    private enum installation = "history_retention_state";

    this(MongoDatabase db) { database = db; }

    HistoryRetentionState loadInstallationState() {
        auto doc = findOne(installation, Bson(["_id": Bson("policy-v1")]));
        return doc.isNull ? HistoryRetentionState.init : decodeState(doc);
    }

    /// Operator-only initialization; does not enable retention by default.
    HistoryRetentionState initializeInstallationState(HistoryRetentionState initial) {
        validateState(initial);
        insertOnly(installation, Bson(["_id": Bson("policy-v1")]), encodeState(initial));
        return loadInstallationState();
    }

    /// Updates known fields only, preserving migration cursors/sub-phases.
    /// Migration must verify TTL retirement before asking to publish active.
    bool compareAndSwapInstallationState(HistoryRetentionState expected,
            HistoryRetentionState replacement) {
        validateState(expected); validateState(replacement);
        requireInput(replacement.phase >= expected.phase
            && (!expected.cutoverAtMs || replacement.cutoverAtMs == expected.cutoverAtMs)
            && (!expected.legacyTtlSeconds || replacement.legacyTtlSeconds == expected.legacyTtlSeconds)
            && (!expected.donorReconciliationComplete || replacement.donorReconciliationComplete));
        auto filter = encodeState(expected);
        // _id is immutable and need not be included in $set.
        auto fields = stateFields(replacement);
        return updateOne(installation, filter, Bson(["$set": fields]), false);
    }

    /// A missing row is not Normal or Pro. Callers must suspend archival
    /// reads until provisioning/migration supplies a durable policy.
    Nullable!HistoryPolicy loadPolicy(string ownerId) {
        validateOwner(ownerId);
        auto doc = findOne(policies, Bson(["_id": Bson(ownerId)]));
        return doc.isNull ? Nullable!HistoryPolicy.init : Nullable!HistoryPolicy(decodePolicy(doc, ownerId));
    }

    /// Explicit migration seeding. Normal notices cannot precede completion
    /// of historical donor reconciliation. Pro rows may be seeded beforehand.
    HistoryPolicy initializeExistingPolicy(string ownerId, bool manualPro,
            bool donorPro, long nowMs) {
        validateOwner(ownerId); validateClock(nowMs);
        auto state = loadInstallationState();
        requirePrepared(state);
        if (!manualPro && !donorPro && !state.donorReconciliationComplete)
            fail(HistoryRetentionFailure.reconciliationRequired);
        HistoryPolicy policy;
        policy.ownerId = ownerId;
        policy.manualPro = manualPro; policy.donorPro = donorPro;
        policy.legacyPublicThroughMs = state.legacyPublicFloor();
        if (!policy.pro) {
            policy.noticeAtMs = nowMs;
            policy.normalFromMs = nowMs + NORMAL_WINDOW_MS;
        }
        return initializePolicy(policy);
    }

    /// Idempotent insert, never a replacement. Only migration grace or Pro
    /// can use this entry point; new immediate Normal uses provisioning.
    HistoryPolicy initializePolicy(HistoryPolicy initial) {
        validatePolicy(initial);
        auto state = loadInstallationState();
        requirePrepared(state);
        requireInput(initial.legacyPublicThroughMs >= state.legacyPublicFloor());
        if (!initial.pro) {
            if (!state.donorReconciliationComplete)
                fail(HistoryRetentionFailure.reconciliationRequired);
            if (state.cutoverAtMs <= 0) fail(HistoryRetentionFailure.unavailable);
            requireInput(initial.normalFromMs != 0 && initial.noticeAtMs != 0);
        }
        return insertPolicy(initial);
    }

    /// The predicate includes both grant bits, revision, deadline, notice and
    /// both irreversible floors. A stale sweep cannot win after a grant.
    bool compareAndSwapPolicy(HistoryPolicy expected, HistoryPolicy replacement, long nowMs = 0) {
        validatePolicy(expected); validatePolicy(replacement);
        requirePrepared(loadInstallationState());
        requireInput(expected.ownerId == replacement.ownerId
            && replacement.expiredThroughMs >= expected.expiredThroughMs
            && replacement.legacyPublicThroughMs >= expected.legacyPublicThroughMs);
        const grantsChanged = expected.manualPro != replacement.manualPro
            || expected.donorPro != replacement.donorPro;
        if (grantsChanged) {
            validateClock(nowMs);
            // Validate the complete transition, not just a plausible new tier.
            requireInput(expected.withGrants(replacement.manualPro, replacement.donorPro,
                nowMs, replacement.expiredThroughMs) == replacement);
        } else {
            requireInput(replacement.revision == expected.revision);
            if (replacement.normalFromMs != expected.normalFromMs) {
                validateClock(nowMs);
                requireInput(expected.due(nowMs) && replacement.normalFromMs == 0
                    && replacement.noticeAtMs == 0
                    && replacement.expiredThroughMs >= max(expected.expiredThroughMs, nowMs - NORMAL_WINDOW_MS));
            } else {
                requireInput(replacement.noticeAtMs == expected.noticeAtMs);
            }
        }
        auto fields = policyFields(replacement);
        if (expected.pro != replacement.pro || expected.normalFromMs != replacement.normalFromMs)
            fields["refreshPending"] = Bson(true);
        auto predicate = encodePolicy(expected);
        predicate["noticeIssuancePending"] = Bson(["$exists": Bson(false)]);
        return updateOne(policies, predicate, Bson(["$set": fields]), false);
    }

    /// All grant callers should derive the transition here, rather than
    /// constructing a new deadline or floor independently.
    bool compareAndSwapGrants(HistoryPolicy expected, bool manualPro,
            bool donorPro, long nowMs, long dueCutThroughMs = -1) {
        return compareAndSwapPolicy(expected,
            expected.withGrants(manualPro, donorPro, nowMs, dueCutThroughMs), nowMs);
    }

    /// Historical reconciliation may seed a missing Pro row or change a grant
    /// on a prepared account. Never perform an active Normal cut in preparation.
    /// A prepared Normal row always has migration grace; refusing an already
    /// due/missing notice also makes racing the final activation harmless.
    bool compareAndSwapPreparedDonor(HistoryPolicy expected, bool donor, long nowMs) {
        if (loadInstallationState().phase != HistoryRetentionPhase.prepare)
            fail(HistoryRetentionFailure.unavailable);
        if (!expected.pro && donor && (!expected.normalFromMs || expected.due(nowMs)))
            fail(HistoryRetentionFailure.reconciliationRequired);
        return compareAndSwapGrants(expected, expected.manualPro, donor, nowMs);
    }

    /// Used after a canonical account insert and to repair interrupted new
    /// account provisioning. Legacy/prepare modes leave old behavior intact.
    void provision(string ownerId, long createdAtMs) {
        validateOwner(ownerId);
        requireInput(createdAtMs > 0);
        auto state = loadInstallationState();
        if (!state.active) return;
        auto existing = loadPolicy(ownerId);
        if (!existing.isNull) return;
        // Never trust a rounded legacy User timestamp to classify a signup
        // on the cutover boundary. Read immutable canonical creation evidence.
        auto user = findOne("users", Bson(["id": Bson(ownerId)]),
            Bson(["_id": Bson(0), "createdAtMs": Bson(1), "createdAt": Bson(1)]));
        if (user.isNull) fail(HistoryRetentionFailure.unavailable);
        bool exact;
        long canonicalMs;
        if (has(user, "createdAtMs")) {
            canonicalMs = strictLong(user, "createdAtMs");
            requireData(canonicalMs > 0 && canonicalMs == createdAtMs);
            exact = true;
        } else {
            // Old accounts have second-precision doubles. The whole second
            // containing cutover is ambiguous and therefore remains existing.
            auto seconds = user["createdAt"];
            requireData(seconds.type == Bson.Type.double_ || seconds.type == Bson.Type.long_
                || seconds.type == Bson.Type.int_);
            long wholeSeconds;
            if (seconds.type == Bson.Type.double_) {
                const value = seconds.get!double;
                requireData(value > 0 && value <= cast(double)(long.max / 1000 - 1));
                wholeSeconds = cast(long)value;
                requireData(value == cast(double)wholeSeconds);
            } else {
                wholeSeconds = integer(seconds);
                requireData(wholeSeconds > 0 && wholeSeconds <= long.max / 1000);
            }
            canonicalMs = wholeSeconds * 1000;
            requireData(canonicalMs == createdAtMs);
        }
        const newAccount = exact ? canonicalMs >= state.cutoverAtMs
            : canonicalMs > state.cutoverAtMs;
        if (!newAccount) fail(HistoryRetentionFailure.reconciliationRequired);
        HistoryPolicy policy;
        policy.ownerId = ownerId;
        insertPolicy(policy);
    }

    private HistoryPolicy insertPolicy(HistoryPolicy policy) {
        validatePolicy(policy);
        auto document = encodePolicy(policy);
        if (policy.normalFromMs || policy.pro) document["refreshPending"] = Bson(true);
        insertOnly(policies, Bson(["_id": Bson(policy.ownerId)]), document);
        auto result = loadPolicy(policy.ownerId);
        if (result.isNull) fail(HistoryRetentionFailure.unavailable);
        return result.get;
    }

    /// Publishing an account-scoped invalidation is idempotent. Never acknowledge
    /// a new grant/deadline using the successful publish of an older snapshot.
    void acknowledgeRefresh(string owner, long revision, long normalFromMs) {
        validateOwner(owner);
        updateOne(policies, Bson(["_id": Bson(owner), "revision": Bson(revision),
            "normalFromMs": Bson(normalFromMs), "refreshPending": Bson(true)]),
            Bson(["$unset": Bson(["refreshPending": Bson(1)])]), false);
    }

    private Bson findOne(string collection, Bson filter, Bson projection = Bson.init) {
        auto command = Bson.emptyObject;
        command["find"] = Bson(collection);
        command["filter"] = filter;
        if (projection.type != Bson.Type.undefined) command["projection"] = projection;
        command["limit"] = Bson(2L);
        command["singleBatch"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        command["readConcern"] = Bson(["level": Bson("majority")]);
        auto reply = run(command);
        auto cursor = reply["cursor"];
        requireData(cursor.type == Bson.Type.object
            && cursor["ns"].type == Bson.Type.string
            && cursor["ns"].get!string == database.name ~ "." ~ collection
            && integer(cursor["id"]) == 0
            && cursor["firstBatch"].type == Bson.Type.array
            && cursor["firstBatch"].length <= 1);
        if (!cursor["firstBatch"].length) return Bson(null);
        auto doc = cursor["firstBatch"][0];
        requireData(doc.type == Bson.Type.object);
        return doc;
    }

    private void insertOnly(string collection, Bson filter, Bson document) {
        // Concurrent upserts may race on _id. A duplicate result is safe only
        // after an independent majority read proves the winning row durable.
        if (!updateOne(collection, filter, Bson(["$setOnInsert": document]), true))
            fail(HistoryRetentionFailure.unavailable);
    }

    private bool updateOne(string collection, Bson filter, Bson update, bool upsert) {
        auto command = Bson.emptyObject;
        command["update"] = Bson(collection);
        command["updates"] = Bson([Bson(["q": filter, "u": update,
            "upsert": Bson(upsert), "multi": Bson(false)])]);
        command["ordered"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        command["writeConcern"] = Bson(["w": Bson("majority"),
            "j": Bson(true), "wtimeout": Bson(5000)]);
        auto reply = run(command, upsert);
        if (has(reply, "writeErrors") && reply["writeErrors"].length) {
            // run() permits only a single duplicate-key upsert error here.
            auto winner = findOne(collection, filter);
            if (winner.isNull) fail(HistoryRetentionFailure.unavailable);
            return true;
        }
        const matched = integer(reply["n"]);
        const modified = integer(reply["nModified"]);
        requireData(matched >= 0 && matched <= 1 && modified >= 0 && modified <= matched);
        if (has(reply, "upserted")) {
            auto inserted = reply["upserted"];
            requireData(upsert && inserted.type == Bson.Type.array && inserted.length <= 1);
            if (inserted.length) {
                requireData(matched == 1 && modified == 0 && inserted[0].type == Bson.Type.object
                    && integer(inserted[0]["index"]) == 0
                    && inserted[0]["_id"].type == Bson.Type.string
                    && inserted[0]["_id"].get!string == filter["_id"].get!string);
            }
        }
        return matched == 1;
    }

    private Bson run(Bson command, bool allowDuplicate = false) {
        Bson reply;
        try reply = database.runCommandUnchecked(command);
        catch (Exception) { fail(HistoryRetentionFailure.unavailable); }
        requireData(reply.type == Bson.Type.object);
        // Presence is failure even when the value is malformed or null.
        if (has(reply, "writeConcernError") || has(reply, "writeConcernErrors"))
            fail(HistoryRetentionFailure.unavailable);
        if (integer(reply["ok"]) != 1) fail(HistoryRetentionFailure.unavailable);
        if (has(reply, "writeErrors")) {
            auto errors = reply["writeErrors"];
            requireData(errors.type == Bson.Type.array);
            if (errors.length) {
                if (!allowDuplicate || errors.length != 1 || errors[0].type != Bson.Type.object
                    || integer(errors[0]["code"]) != 11000
                    || integer(errors[0]["index"]) != 0)
                    fail(HistoryRetentionFailure.unavailable);
            }
        }
        return reply;
    }
}

/// Shared gateway/engine provisioning entry point. Errors are never interpreted
/// as Pro, a successful initialization, or permission to prune.
void provisionHistoryPolicy(string ownerId, long createdAtMs) {
    if (!AppMongoConnection.isConnected()) fail(HistoryRetentionFailure.unavailable);
    auto repository = new HistoryRetentionRepository(AppMongoConnection.getDb());
    repository.provision(ownerId, createdAtMs);
}

private void fail(HistoryRetentionFailure reason) { throw new HistoryRetentionException(reason); }
private void requireInput(bool valid) { if (!valid) fail(HistoryRetentionFailure.invalidInput); }
private void requireData(bool valid) { if (!valid) fail(HistoryRetentionFailure.malformed); }
private void validateOwner(string ownerId) {
    try {
        requireInput(ownerId.length == 36 && UUID(ownerId) != UUID.init
            && UUID(ownerId).toString() == ownerId);
    } catch (HistoryRetentionException error) { throw error; }
    catch (Exception) { fail(HistoryRetentionFailure.invalidInput); }
}
private void validateClock(long nowMs) {
    requireInput(nowMs > 0 && nowMs <= long.max - NORMAL_WINDOW_MS);
}
private void requirePrepared(HistoryRetentionState state) {
    if (state.phase == HistoryRetentionPhase.legacy)
        fail(HistoryRetentionFailure.unavailable);
}
private bool has(const Bson doc, string field) {
    if (doc.type != Bson.Type.object) return false;
    foreach (key, value; doc.byKeyValue) if (key == field) return true;
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
private long strictLong(const Bson doc, string field) {
    requireData(doc[field].type == Bson.Type.long_);
    return doc[field].get!long;
}
private bool strictBool(const Bson doc, string field) {
    requireData(doc[field].type == Bson.Type.bool_);
    return doc[field].get!bool;
}
private void validateState(HistoryRetentionState state) {
    requireInput(state.phase >= HistoryRetentionPhase.legacy && state.phase <= HistoryRetentionPhase.active
        && state.cutoverAtMs >= 0 && state.legacyTtlSeconds >= 0
        && state.legacyTtlSeconds <= long.max / 1000);
    if (state.active)
        requireInput(state.cutoverAtMs > 0 && state.legacyTtlSeconds > 0
            && state.donorReconciliationComplete);
}
private HistoryRetentionState decodeState(Bson doc) {
    requireData(doc["_id"].type == Bson.Type.string && doc["_id"].get!string == "policy-v1"
        && doc["phase"].type == Bson.Type.string);
    HistoryRetentionState state;
    switch (doc["phase"].get!string) {
        case "legacy": state.phase = HistoryRetentionPhase.legacy; break;
        case "prepare": state.phase = HistoryRetentionPhase.prepare; break;
        case "active": state.phase = HistoryRetentionPhase.active; break;
        default: fail(HistoryRetentionFailure.malformed);
    }
    state.cutoverAtMs = strictLong(doc, "cutoverAtMs");
    state.legacyTtlSeconds = strictLong(doc, "legacyTtlSeconds");
    state.donorReconciliationComplete = strictBool(doc, "donorReconciliationComplete");
    try validateState(state);
    catch (HistoryRetentionException) { fail(HistoryRetentionFailure.malformed); }
    if (has(doc, "maintenancePaused")) state.maintenancePaused = strictBool(doc, "maintenancePaused");
    if (has(doc, "migrationHold")) state.maintenancePaused = strictBool(doc, "migrationHold") || state.maintenancePaused;
    return state;
}
private Bson stateFields(HistoryRetentionState state) {
    const phase = state.phase == HistoryRetentionPhase.active ? "active"
        : state.phase == HistoryRetentionPhase.prepare ? "prepare" : "legacy";
    return Bson(["phase": Bson(phase), "cutoverAtMs": Bson(state.cutoverAtMs),
        "legacyTtlSeconds": Bson(state.legacyTtlSeconds),
        "donorReconciliationComplete": Bson(state.donorReconciliationComplete)]);
}
private Bson encodeState(HistoryRetentionState state) {
    auto doc = Bson.emptyObject;
    doc["_id"] = Bson("policy-v1");
    foreach (key, value; stateFields(state).byKeyValue) doc[key] = value;
    return doc;
}
private void validatePolicy(HistoryPolicy policy) {
    validateOwner(policy.ownerId);
    requireInput(policy.revision >= 0 && policy.expiredThroughMs >= 0
        && policy.legacyPublicThroughMs >= 0 && policy.noticeAtMs >= 0
        && policy.normalFromMs >= 0
        && ((policy.normalFromMs == 0 && policy.noticeAtMs == 0)
            || (!policy.pro && policy.noticeAtMs > 0
                && policy.noticeAtMs <= long.max - NORMAL_WINDOW_MS
                && policy.normalFromMs == policy.noticeAtMs + NORMAL_WINDOW_MS)));
}
package HistoryPolicy decodePolicy(Bson doc, string ownerId) {
    requireData(doc["_id"].type == Bson.Type.string && doc["_id"].get!string == ownerId);
    // Preparation may encounter a prior donor downgrade. Preserve its floors
    // and revision but don't serve or prune it until the operator issues the
    // first user-visible active notice. Absence, not elapsed wall time, admits it.
    if (has(doc, "noticeIssuancePending")) {
        requireData(strictBool(doc, "noticeIssuancePending"));
        fail(HistoryRetentionFailure.reconciliationRequired);
    }
    HistoryPolicy policy;
    policy.ownerId = ownerId;
    policy.manualPro = strictBool(doc, "manualPro");
    policy.donorPro = strictBool(doc, "donorPro");
    policy.revision = strictLong(doc, "revision");
    policy.noticeAtMs = strictLong(doc, "noticeAtMs");
    policy.normalFromMs = strictLong(doc, "normalFromMs");
    policy.expiredThroughMs = strictLong(doc, "expiredThroughMs");
    policy.legacyPublicThroughMs = strictLong(doc, "legacyPublicThroughMs");
    try validatePolicy(policy);
    catch (HistoryRetentionException) { fail(HistoryRetentionFailure.malformed); }
    return policy;
}
private Bson policyFields(HistoryPolicy policy) {
    return Bson(["manualPro": Bson(policy.manualPro), "donorPro": Bson(policy.donorPro),
        "revision": Bson(policy.revision), "noticeAtMs": Bson(policy.noticeAtMs),
        "normalFromMs": Bson(policy.normalFromMs), "expiredThroughMs": Bson(policy.expiredThroughMs),
        "legacyPublicThroughMs": Bson(policy.legacyPublicThroughMs)]);
}
private Bson encodePolicy(HistoryPolicy policy) {
    auto doc = Bson.emptyObject;
    doc["_id"] = Bson(policy.ownerId);
    foreach (key, value; policyFields(policy).byKeyValue) doc[key] = value;
    return doc;
}

unittest {
    import std.exception : assertThrown;
    enum owner = "11111111-1111-4111-8111-111111111111";
    auto policy = HistoryPolicy(owner);
    policy.expiredThroughMs = 100;
    policy.legacyPublicThroughMs = 200;
    auto doc = encodePolicy(policy);
    assert(decodePolicy(doc, owner) == policy);
    doc["revision"] = Bson(0); // int32 must not stand in for the CAS int64.
    assertThrown!HistoryRetentionException(decodePolicy(doc, owner));
    doc = encodePolicy(policy);
    doc["manualPro"] = Bson("false");
    assertThrown!HistoryRetentionException(decodePolicy(doc, owner));
    doc = encodePolicy(policy);
    doc["expiredThroughMs"] = Bson(-1L);
    assertThrown!HistoryRetentionException(decodePolicy(doc, owner));
    doc = encodePolicy(policy);
    assertThrown!HistoryRetentionException(decodePolicy(doc, "22222222-2222-4222-8222-222222222222"));
    policy.normalFromMs = 1;
    assertThrown!HistoryRetentionException(validatePolicy(policy));
}

unittest {
    import std.exception : assertThrown;
    HistoryRetentionState state;
    assert(!state.active && state.legacyPublicFloor == 0);
    state.legacyTtlSeconds = long.max;
    assertThrown!HistoryRetentionException(state.legacyPublicFloor);
    state.legacyTtlSeconds = 0;
    state.phase = HistoryRetentionPhase.prepare;
    auto doc = encodeState(state);
    doc["migrationPhase"] = Bson("backfill");
    assert(decodeState(doc) == state);
    state.phase = HistoryRetentionPhase.active;
    assertThrown!HistoryRetentionException(validateState(state));
    state.cutoverAtMs = NORMAL_WINDOW_MS * 10;
    state.legacyTtlSeconds = 30 * 86_400;
    state.donorReconciliationComplete = true;
    validateState(state);
    assert(state.legacyPublicFloor == state.cutoverAtMs - 30 * 86_400_000L);
    assert(decodeState(encodeState(state)) == state);
    doc = encodeState(state);
    doc["phase"] = Bson("unknown");
    assertThrown!HistoryRetentionException(decodeState(doc));
    doc = encodeState(state);
    doc["donorReconciliationComplete"] = Bson(false);
    assertThrown!HistoryRetentionException(decodeState(doc));
    doc = encodeState(state);
    doc["cutoverAtMs"] = Bson(1.0);
    assertThrown!HistoryRetentionException(decodeState(doc));
    assert(integer(Bson(1.0)) == 1);
    assertThrown!HistoryRetentionException(integer(Bson(0.5)));
    assertThrown!HistoryRetentionException(integer(Bson(null)));
}
