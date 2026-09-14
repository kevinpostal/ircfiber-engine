module ircfiber.db.prefs_mongo;

import std.datetime : Clock;
import vibe.data.bson;
import vibe.data.json : Json, parseJsonString;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// Durable mirror of the Redis prefs blob. Redis stays the hot path and the
/// prefVersion allocator; this collection is what survives a Redis flush,
/// a cold restart without AOF recovery, or a corrupt-blob self-heal DEL.
enum PREFS_COLLECTION = "user_preferences";

/// One `user_preferences` document. `_id` is the user UUID string, so the
/// implicit `_id` index is the only index needed — no `createIndex` call.
struct PrefsDoc {
    bool found;
    Json blob;          /// exactly what `UserPreferences.toJson()` produced
    long prefVersion;
    long updatedAtMs;
}

/// True when `doc` is an object carrying `key`. Bson has no `in` operator.
private bool hasField(const Bson doc, string key) @trusted {
    if (doc.type != Bson.Type.object) return false;
    foreach (k, v; doc.byKeyValue)
        if (k == key) return true;
    return false;
}

/// Reads an integral field regardless of whether it was stored as int32,
/// int64 or double — Mongo drivers and shells disagree on numeric width,
/// and `get!long` throws on a mismatch.
private long readLong(const Bson v) @trusted {
    switch (v.type) {
        case Bson.Type.int_:    return cast(long) v.get!int;
        case Bson.Type.long_:   return v.get!long;
        case Bson.Type.double_: return cast(long) v.get!double;
        default:                return 0;
    }
}

/// Encodes one prefs document.
///
/// `blob` is stored as a JSON *string*, not a Bson sub-document, because
/// `bufferPrefs` / `membersCollapsed` / `collapsed` are keyed by
/// "networkId:#channel" and IRC channel names legally contain `.` and `$` —
/// both illegal-ish in Bson field names. The string round-trips byte for
/// byte through `UserPreferences.toJson`/`fromJson`. Same precedent as
/// `img2irc_saves.d`'s `params` field.
Bson prefsDocToBson(string userId, Json blob, long prefVersion, long updatedAtMs) @trusted {
    return Bson([
        "_id":         Bson(userId),
        "blob":        Bson(blob.toString()),
        "prefVersion": Bson(prefVersion),
        "updatedAt":   Bson(updatedAtMs),
    ]);
}

/// Decodes one prefs document. Returns `PrefsDoc.init` (`found == false`)
/// for a missing/empty document or an unparseable blob — a corrupt durable
/// copy must not resurrect as garbage.
PrefsDoc prefsDocFromBson(Bson doc) @trusted {
    PrefsDoc r;
    if (!hasField(doc, "blob")) return r;
    auto raw = doc["blob"];
    if (raw.type != Bson.Type.string) return r;
    auto text = raw.get!string;
    if (text.length == 0) return r;
    try {
        r.blob = parseJsonString(text);
    } catch (Exception e) {
        logWarn("prefs_mongo: unparseable durable blob: %s", e.msg);
        return PrefsDoc.init;
    }
    if (r.blob.type != Json.Type.object) return PrefsDoc.init;
    if (hasField(doc, "prefVersion")) r.prefVersion = readLong(doc["prefVersion"]);
    if (hasField(doc, "updatedAt")) r.updatedAtMs = readLong(doc["updatedAt"]);
    r.found = true;
    return r;
}

/// Loads the durable copy. Never throws: Mongo being down must not break a
/// pref read, since Redis remains authoritative.
PrefsDoc loadPrefsDoc(string userId) @trusted {
    if (!AppMongoConnection.isConnected()) return PrefsDoc.init;
    try {
        auto coll = AppMongoConnection.getDb()[PREFS_COLLECTION];
        auto doc = coll.findOne(Bson(["_id": Bson(userId)]));
        if (doc.isNull) return PrefsDoc.init;
        return prefsDocFromBson(doc);
    } catch (Exception e) {
        logWarn("prefs_mongo: load failed for %s: %s", userId, e.msg);
        return PrefsDoc.init;
    }
}

/// Writes the durable copy. Never throws.
///
/// Deliberately update-then-insert rather than a single `upsert`: vibe-d
/// 0.10.3 maps the upsert reply's `upserted[]._id` with `get!BsonObjectID`,
/// so an upsert that *creates* a document with a string `_id` throws
/// `BSON value is type 'string', expected to be one of objectID` after the
/// write already committed (see `fibereye/store.d:519-533`).
void savePrefsDoc(string userId, Json blob, long prefVersion) @trusted {
    if (!AppMongoConnection.isConnected()) return;
    const updatedAtMs = Clock.currTime.toUnixTime!long * 1000;
    try {
        auto coll = AppMongoConnection.getDb()[PREFS_COLLECTION];
        // MUST be an explicit empty object: a default-initialised `Bson`
        // is `undefined`, and `opIndexAssign` on it throws
        // "BSON value is type 'undefined', expected to be one of object".
        Bson setDoc = Bson.emptyObject;
        setDoc["blob"] = Bson(blob.toString());
        setDoc["prefVersion"] = Bson(prefVersion);
        setDoc["updatedAt"] = Bson(updatedAtMs);
        // Stale-write guard: only advance, never regress. The *stored*
        // value is the one constrained, so a fallback save carrying
        // prefVersion 0 cannot clobber a stored 57.
        auto selector = Bson([
            "_id": Bson(userId),
            "prefVersion": Bson(["$lte": Bson(prefVersion)]),
        ]);
        auto res = coll.updateOne(selector, Bson(["$set": setDoc]));
        if (res.matchedCount > 0) return;
        try {
            coll.insertOne(prefsDocToBson(userId, blob, prefVersion, updatedAtMs));
        } catch (Exception e) {
            // E11000 duplicate key => a newer document is already stored
            // (the selector missed because its prefVersion is higher).
            // Skipping is the correct outcome.
            logDiagnostic("prefs_mongo: insert skipped for %s: %s", userId, e.msg);
        }
    } catch (Exception e) {
        logWarn("prefs_mongo: save failed for %s: %s", userId, e.msg);
    }
}

/// Erases the durable copy. Never throws.
void deletePrefsDoc(string userId) @trusted {
    if (!AppMongoConnection.isConnected()) return;
    try {
        auto coll = AppMongoConnection.getDb()[PREFS_COLLECTION];
        coll.deleteOne(Bson(["_id": Bson(userId)]));
    } catch (Exception e) {
        logWarn("prefs_mongo: delete failed for %s: %s", userId, e.msg);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Unit tests — encode/decode only; the `unittest` configuration has no
// Mongo connection. End-to-end durability is covered by prefs_test.d.
// ─────────────────────────────────────────────────────────────────────────

@("prefsDoc round-trips channel names containing dots and dollars")
unittest {
    auto blob = parseJsonString(
        `{"pinnedChannels":["net1:#foo.bar","net2:#a$b"],"prefVersion":57}`);
    auto bson = prefsDocToBson("11111111-2222-3333-4444-555555555555", blob, 57, 1_757_740_000_000L);
    auto doc = prefsDocFromBson(bson);
    assert(doc.found, "round trip must be found");
    assert(doc.prefVersion == 57, "prefVersion must survive");
    assert(doc.updatedAtMs == 1_757_740_000_000L, "updatedAt must survive");
    auto pinned = doc.blob["pinnedChannels"];
    assert(pinned.type == Json.Type.array, "pinnedChannels must stay an array");
    assert(pinned[0].get!string == "net1:#foo.bar",
        "a channel name with a dot must survive the Bson round trip");
    assert(pinned[1].get!string == "net2:#a$b",
        "a channel name with a dollar must survive the Bson round trip");
}

@("prefsDocFromBson reports not-found for an empty document")
unittest {
    auto doc = prefsDocFromBson(Bson.emptyObject);
    assert(!doc.found, "an empty document must not be reported as found");
}

@("prefsDocFromBson reports not-found for a corrupt blob")
unittest {
    Bson b = Bson.emptyObject;
    b["_id"] = Bson("u1");
    b["blob"] = Bson("{not json");
    b["prefVersion"] = Bson(9L);
    auto doc = prefsDocFromBson(b);
    assert(!doc.found, "an unparseable durable blob must not resurrect");
    assert(doc.prefVersion == 0, "a corrupt document must not leak its version");
}
