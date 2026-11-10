module ircfiber.db.messages;

import std.uuid;
import std.conv;
import std.algorithm;
import std.array;
import std.json;
import std.datetime : Clock, days;
import vibe.core.core : runTask;
import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;     // FindOptions
import vibe.data.bson;
import vibe.data.json;
import vibe.core.log;
import ircfiber.db.mongo;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : normalizeChannelName;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.buffer : sanitizeUtf8;
import ircfiber.network_write_gate : NetworkWriter, runNetworkWrite, runNetworkMutation,
    NetworkMutationException;
import ircfiber.network_write_gate : retainNetworkWriteUncertainty;

version (RoutingPolicyTest) {
    /// Real storage regression, invoked with the runner's explicitly guarded URI.
    void archiveCatalogWriterGateCases(RedisStorage redis, string mongoUri) {
        import std.exception : enforce;
        import std.string : endsWith, replace;
        import ircfiber.network_write_gate : NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY,
            networkMutationAdmittedForTest, networkMutationRepliedForTest,
            networkMutationReplyObservedForTest, runNetworkRedisMutation;
        import vibe.db.redis.redis : RedisDatabase;
        enforce(mongoUri.length && AppMongoConnection.name().endsWith("_test"),
            "Archive catalog proof requires an explicitly admitted test Mongo URI");
        const originalDatabase = AppMongoConnection.name();
        const database = "archive_gate_" ~ randomUUID().toString().replace("-", "") ~ "_test";
        AppMongoConnection.connect(mongoUri, database);
        scope (exit) AppMongoConnection.connect(mongoUri, originalDatabase);
        auto networks = AppMongoConnection.getDb()["networks"];
        auto messages = AppMongoConnection.getDb()["messages"];
        enforce(networks.findOne(Bson.emptyObject).isNull && messages.findOne(Bson.emptyObject).isNull,
            "Archive proof requires a fresh random namespace");
        auto db = redis.getDb();
        enforce(!db.exists(NETWORK_WRITE_EXCLUSION_KEY) && db.scard(NETWORK_WRITERS_KEY) == 0,
            "Archive proof requires dedicated quiescent Redis");
        const operation = randomUUID().toString();
        const id = randomUUID().toString();
        const owner = randomUUID().toString();
        const afterCatch = "archive-gate:after-caught:" ~ operation;
        string[] tokens;
        scope (exit) {
            networkMutationAdmittedForTest = null;
            networkMutationRepliedForTest = null;
            networkMutationReplyObservedForTest = null;
            db.del(afterCatch);
            db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
                [NETWORK_WRITE_EXCLUSION_KEY], operation);
            foreach (token; tokens) db.srem(NETWORK_WRITERS_KEY, token);
            messages.deleteMany(Bson(["networkId": Bson(id)]));
            networks.deleteOne(Bson(["id": Bson(id)]));
        }
        networks.insertOne(Bson(["id": Bson(id), "userId": Bson(owner), "nick": Bson("Preserve")]));
        auto repository = new MessageRepository();
        const timestamp = Clock.currTime().toUnixTime!long * 1000;
        const payload = `{"eid":1,"t":` ~ timestamp.to!string ~ `,"text":"preserved"}`;
        repository.appendArchivedCompactMessage("archive-gate-original", id, "#proof", payload);
        auto before = networks.findOne(["id": id]).toString();
        auto historyBefore = messages.findOne(["networkId": id]).toString();
        auto closed = db.eval!long(
            "if redis.call('EXISTS',KEYS[1]) ~= 0 or redis.call('SCARD',KEYS[2]) ~= 0 then return 0 end redis.call('SET',KEYS[1],ARGV[1]); return 1",
            [NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY], operation);
        enforce(!closed.empty && closed.front == 1, "Archive fixture could not close writer gate");
        foreach (discovery; [false, true]) {
            bool refused;
            try {
                if (discovery) repository.archivedServerScopes(redis, id);
                else repository.registerArchiveScopes(redis, id, ["archive-gate-new"], owner);
            } catch (ArchiveWriteException e) { refused = e.failure == ArchiveWriteFailure.unavailable; }
            enforce(refused && networks.findOne(["id": id]).toString() == before
                && messages.findOne(["networkId": id]).toString() == historyBefore,
                "Closed catalog CAS changed canonical metadata/history or violated archive failure contract");
        }
        enforce(repository.appendArchivedCompactMessage("archive-gate-original", id, "#proof", payload)
            == ArchiveWriteResult.alreadyPersisted,
            "Canonical exclusion incorrectly blocked independent message/history writes");
        db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
            [NETWORK_WRITE_EXCLUSION_KEY], operation);
        networkMutationAdmittedForTest = (string token) { tokens ~= token; };
        auto scopes = repository.registerArchiveScopes(redis, id, ["archive-gate-new"], owner);
        enforce(scopes.length == 2 && scopes.canFind("archive-gate-original")
            && scopes.canFind("archive-gate-new") && db.scard(NETWORK_WRITERS_KEY) == 0,
            "Open catalog did not majority-CAS complete legacy provenance and release ownership");
        enforce(networks.findOne(["id": id])["nick"].get!string == "Preserve"
            && messages.findOne(["networkId": id]).toString() == historyBefore,
            "Catalog CAS damaged unrelated canonical fields or archive rows");
        networkMutationRepliedForTest = { throw new Exception("Lost catalog acknowledgement"); };
        bool uncertain;
        try repository.registerArchiveScopes(redis, id, ["archive-gate-lost"], owner);
        catch (ArchiveWriteException e) { uncertain = e.failure == ArchiveWriteFailure.unavailable; }
        networkMutationRepliedForTest = null;
        enforce(uncertain && networks.findOne(["id": id])["archiveServers"].length == 3
            && db.scard(NETWORK_WRITERS_KEY) == 1 && db.ttl(NETWORK_WRITERS_KEY) == -1,
            "Real catalog commit with lost acknowledgement did not retain writer evidence");
        foreach (token; tokens) db.srem(NETWORK_WRITERS_KEY, token);
        foreach (variant; 0 .. 5) {
            const server = "archive-gate-malformed-" ~ variant.to!string;
            networkMutationReplyObservedForTest = (ref Bson reply) {
                final switch (variant) {
                    case 0: reply["writeConcernError"] = Bson(null); break;
                    case 1: reply["writeErrors"] = Bson(null); break;
                    case 2: reply["n"] = Bson(-1); break;
                    case 3: reply["n"] = Bson(0.5); break;
                    case 4: reply["n"] = Bson(2); break;
                }
            };
            bool rejected;
            runNetworkWrite!void(redis, (ref NetworkWriter writer) {
                try repository.registerArchiveScopes(redis, id, [server], owner, writer);
                catch (ArchiveWriteException) { rejected = true; }
                // The real engine can catch a failed catalog handoff and
                // successfully record a later Redis failure transition.
                runNetworkRedisMutation!void(writer, (RedisDatabase commandDb) {
                    commandDb.set(afterCatch, "acknowledged");
                });
            });
            networkMutationReplyObservedForTest = null;
            auto collected = db.eval!long(
                "if redis.call('SCARD',KEYS[2]) ~= 0 then return 0 end redis.call('SET',KEYS[1],ARGV[1]); return 1",
                [NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY], operation);
            enforce(rejected && networks.findOne(["id": id])["archiveServers"].length == 4 + variant
                && db.get(afterCatch) == "acknowledged" && db.scard(NETWORK_WRITERS_KEY) == 1
                && db.ttl(NETWORK_WRITERS_KEY) == -1 && !collected.empty && collected.front == 0,
                "Caught malformed catalog ACK plus a later acknowledged effect released writer evidence");
            foreach (token; tokens) db.srem(NETWORK_WRITERS_KEY, token);
        }
    }
}

/// Exact references follow Mongo's (t, eid, _id) order, never opaque msgid order.
/// A non-exact zero timestamp is unbounded.
struct HistoryBoundary {
    long timestampMs;
    long eid;
    string storageId;
    string msgid;
    bool exact;
    bool hasEid;
}

int compareHistoryBoundaries(const ref HistoryBoundary a, const ref HistoryBoundary b) {
    if (a.timestampMs != b.timestampMs) return a.timestampMs < b.timestampMs ? -1 : 1;
    if (!a.exact || !b.exact) return 0;
    if (a.hasEid != b.hasEid) return a.hasEid ? 1 : -1;
    if (a.hasEid && a.eid != b.eid) return a.eid < b.eid ? -1 : 1;
    import std.string : cmp;
    return cmp(a.storageId, b.storageId);
}

/// Success means the raw archival command met majority+journal write concern.
enum ArchiveWriteResult { inserted, alreadyPersisted }

enum ArchiveWriteFailure { invalidInput, unavailable, rejected, identityMismatch, invalidReply }

/// Deliberately excludes Mongo error text, payloads, IDs and connection details.
final class ArchiveWriteException : Exception {
    immutable ArchiveWriteFailure failure;
    immutable long mongoCode;

    this(ArchiveWriteFailure failure, long mongoCode = 0) {
        super("Archival Mongo operation failed: " ~ to!string(failure));
        this.failure = failure;
        this.mongoCode = mongoCode;
    }
}

/// Days a `messages` row stays in Mongo before the TTL monitor deletes it.
/// Read once per process by `MessageRepository.ensureIndexes`.
enum MESSAGE_RETENTION_DAYS_DEFAULT = 30;

/// `IRCFIBER_MESSAGE_RETENTION_DAYS` (positive int) or the default.
/// Non-numeric / <= 0 values fall back to the default with a WARN line.
int messageRetentionDays() @trusted {
    import std.process : environment;
    const raw = environment.get("IRCFIBER_MESSAGE_RETENTION_DAYS", "");
    if (raw.length == 0) return MESSAGE_RETENTION_DAYS_DEFAULT;
    try {
        const v = raw.to!int;
        if (v > 0) return v;
    } catch (Exception) {}
    logWarn("IRCFIBER_MESSAGE_RETENTION_DAYS=%s invalid; using %s", raw, MESSAGE_RETENTION_DAYS_DEFAULT);
    return MESSAGE_RETENTION_DAYS_DEFAULT;
}

/**
 * Rolling message storage (IRCCloud-style).
 *
 * MongoDB stores every message the engine sees; rows expire after
 * `messageRetentionDays()` via the `tsAt` TTL index (Mongo's TTL monitor
 * deletes them in the background). Redis keeps a hot cache of the most
 * recent N messages for fast access. When the cache is exhausted, the
 * REST API falls through to MongoDB for scrollback within the retention
 * window.
 *
 * Each document is indexed by (serverId, networkId, channel, t, msgid)
 * for efficient paginated queries. The full compact JSON payload is
 * stored in the `payload` field as a JSON string and returned verbatim
 * by the API.
 */
final class MessageRepository {
    private MongoCollection collection;

    /// Docs store the IRC command inside the `payload` JSON string
    /// (`"c":"315"`). Exclude the noise commands the chat UI cannot
    /// render (mirrors `BufferManager.isScrollbackNoiseRow`) so the
    /// Mongo fall-through returns REAL messages, not a wall of invisible
    /// WHO/NAMES/TAGMSG rows that push PRIVMSGs out of the visible
    /// window. Only applied to channel buffers — the `_server` log
    /// needs its numerics/MOTD.
    private static immutable string NOISE_PAYLOAD_RE =
        `"c"\s*:\s*"(315|352|332|333|353|354|366|367|368|376|422|311|312|313|317|318|319|330|301|671|401|324|329|303|PONG|TAGMSG|QUIT|you_nickchange)"`;

    /// A reaction TAGMSG (`+draft/react` / `+draft/unreact`, compact keys
    /// `rx` / `ux`, naming its target row in `rp`) is message state the
    /// client folds into that row's chips, so it is exempt from the
    /// TAGMSG exclusion above — otherwise a reaction only ever existed
    /// for clients that were connected when it happened. Typing TAGMSGs
    /// have no `rp`/`rx` and stay excluded. Mirrors
    /// `BufferManager.isScrollbackNoiseRow`.
    private static immutable string REACT_PAYLOAD_RE =
        `"(rx|ux)"\s*:\s*"`;

    /// Positive match for chat rows only (bouncer playback / CHATHISTORY):
    /// the limit must apply to PRIVMSG/NOTICE/REDACT, not to JOIN/MODE churn.
    /// REDACT rides the same window so cap-negotiated bouncer clients replay
    /// tombstone state (clients without draft/message-redaction get nothing:
    /// formatEvent drops REDACT for them).
    private static immutable string CHAT_PAYLOAD_RE = `"c"\s*:\s*"(PRIVMSG|NOTICE|REDACT)"`;
    /// CHAT_PAYLOAD_RE widened for IRCv3 `draft/event-playback` clients:
    /// channel events replay alongside the chat rows.
    private static immutable string EVENT_PAYLOAD_RE =
        `"c"\s*:\s*"(PRIVMSG|NOTICE|REDACT|TAGMSG|JOIN|PART|QUIT|KICK|MODE|NICK|TOPIC|ACCOUNT|CHGHOST|SETNAME|METADATA|RENAME|AWAY)"`;

    private static void applyNoiseExclusion(ref Bson filter, string channel) {
        if (channel == "_server")
            return;
        /* Keep a row when it is not noise, OR when it is a reaction. */
        filter["$or"] = Bson([
            Bson(["payload": Bson(["$not": Bson(BsonRegex(NOISE_PAYLOAD_RE, ""))])]),
            Bson(["payload": Bson(["$regex": Bson(REACT_PAYLOAD_RE)])])
        ]);
    }

    /// The gateway constructs a repository per request; the index and
    /// backfill work below must run once per process, not per request.
    private static bool indexesEnsured;

    /// Creates a repository bound to the messages collection.
    this() {
        collection = AppMongoConnection.getDb()["messages"];
        ensureIndexes();
    }

    /// Build the compound query indexes, the `tsAt` TTL index (retention),
    /// and backfill `tsAt` on legacy rows in the background.
    private void ensureIndexes() @trusted {
        if (indexesEnsured) return;
        indexesEnsured = true;
        // Key order is the index: equality fields first, then the sorted or
        // ranged field, then fields only some reads filter on. Built field by
        // field — a `Bson(["a": …, "b": …])` literal is an associative array
        // whose iteration order is unspecified, and prod ended up with
        // `t_-1_networkId_1_channel_1_serverId_1`, which turns every newest-N
        // read on a busy channel into a 17 s fetch-and-filter walk over all
        // networks (#superbowl, 2026-10-25). `serverId` never leads: reads for
        // a network without an engine assignment (bnc CHATHISTORY while the
        // engine is down, REST history) omit it. Trailing, it still filters in
        // the index for the reads that carry it (REST backlog count).
        try {
            // Primary compound index: pagination by timestamp
            collection.createIndex(indexKeys(["networkId", "channel", "-t", "serverId"]));
            collection.createIndex(indexKeys(["networkId", "channel", "-t", "-eid", "-_id", "serverId"]));
            // eid index: the network-wide replay (`getAfterEidForNetwork`) walks
            // eid in order and stops at its limit; eid cursor lookups are one key.
            collection.createIndex(indexKeys(["networkId", "-eid", "channel", "serverId"]));
            // Exact identities must not scan an entire network's eid range during attach replay.
            collection.createIndex(indexKeys(["networkId", "channel", "msgid", "serverId", "eid"]));
        } catch (Exception e) {
            logWarn("Failed to create messages compound index: %s", e.msg);
        }
        dropSupersededIndexes();

        const retentionDays = messageRetentionDays();
        try {
            IndexOptions o;
            o.expireAfter = retentionDays.days;
            collection.createIndex(Bson(["tsAt": Bson(1)]), o);
        } catch (Exception e) {
            // IndexOptionsConflict (code 85): index exists with a different
            // expireAfterSeconds. Change it in place instead of drop+recreate.
            try {
                auto cmd = Bson.emptyObject;              // field order matters: command name first
                cmd["collMod"] = Bson("messages");
                auto idx = Bson.emptyObject;
                idx["keyPattern"] = Bson(["tsAt": Bson(1)]);
                idx["expireAfterSeconds"] = Bson(cast(long) retentionDays * 86_400);
                cmd["index"] = idx;
                AppMongoConnection.runCommand(cmd);
                logInfo("messages TTL index retention set to %s days via collMod", retentionDays);
            } catch (Exception e2) {
                logWarn("messages TTL index: createIndex (%s) and collMod (%s) both failed; "
                    ~ "retention NOT enforced — db.messages.dropIndex(\"tsAt_1\") and restart",
                    e.msg, e2.msg);
            }
        }

        // Rows written before `tsAt` existed never age out unless they get
        // one. `{tsAt: {$exists: false}}` is served by the non-sparse tsAt_1
        // index, so after the first run this is a cheap seek returning 0.
        // Runs in a fiber so engine boot and gateway requests never block.
        runTask({
            try {
                auto filter = Bson(["tsAt": Bson(["$exists": Bson(false)])]);
                Bson[] pipeline = [Bson(["$set": Bson(["tsAt": Bson(["$toDate": Bson("$t")])])])];
                auto res = collection.updateMany(filter, Bson(pipeline));
                if (res.modifiedCount > 0)
                    logInfo("messages retention backfill: set tsAt on %s legacy rows", res.modifiedCount);
            } catch (Exception e) {
                logWarn("messages retention backfill failed: %s", e.msg);
            }
        });
    }

    /// Index key document with the fields in exactly this order; a leading
    /// `-` makes the key descending (`["networkId", "-t"]`).
    private static Bson indexKeys(string[] fields) @trusted {
        auto keys = Bson.emptyObject;
        foreach (f; fields) {
            if (f.length > 1 && f[0] == '-') keys[f[1 .. $]] = Bson(-1);
            else keys[f] = Bson(1);
        }
        return keys;
    }

    /// Earlier layouts: associative-array order (`t` first) from builds
    /// before 2026-10-25, and the `serverId`-first and `serverId`-less pairs
    /// briefly deployed that day. Dropped once the current pair exists so
    /// writes stop maintaining copies. Best-effort.
    private void dropSupersededIndexes() @trusted {
        static immutable string[] superseded = [
            "t_-1_networkId_1_channel_1_serverId_1",
            "serverId_1_networkId_1_channel_1_t_-1",
            "serverId_1_networkId_1_channel_1_eid_-1",
            "networkId_1_channel_1_t_-1",
            "networkId_1_channel_1_eid_-1",
        ];
        try {
            bool[string] present;
            foreach (idx; collection.listIndexes()) present[idx["name"].get!string] = true;
            if ("networkId_1_channel_1_t_-1_serverId_1" !in present
                || "networkId_1_eid_-1_channel_1_serverId_1" !in present) return;
            foreach (name; superseded)
                if (name in present) {
                    collection.dropIndex(name);
                    logInfo("messages: dropped superseded index %s", name);
                }
        } catch (Exception e) logWarn("messages superseded index drop: %s", e.msg);
    }

    /// Normalize channel name via the canonical helper in
    /// ircfiber.models.network so all stores (Mongo, Redis buffer,
    /// in-memory lists) share the same key shape.
    private alias normalizeChannel = ircfiber.models.network.normalizeChannelName;

    /// Read a `t` (unix-ms) value from a Mongo doc regardless of which
    /// numeric BSON type the driver produced. The engine writes `t` as
    /// int64 (Json int → Bson long_), but vibe.d's `get!double` throws
    /// on long_ values ("BSON value is type 'long_', expected to be one
    /// of double_"), which made cursor lookups throw and killed the
    /// Mongo fall-through on the infinite-scrollback path. Returns 0
    /// when the value is missing or not numeric.
    private static long readBsonTimestamp(const(Bson) b) {
        switch (b.type) with (Bson.Type) {
            case long_:
                return b.get!long;
            case double_:
                return cast(long) b.get!double;
            case int_:
                return b.get!int;
            case null_:
                return 0;
            default:
                return 0;
        }
    }

    /// Append a compact message JSON to storage. Called from the event
    /// processor for every event the engine sees. `tsAt` mirrors `t` as a
    /// BSON Date so the TTL index can age the row out.
    void appendMessage(string serverId, string networkId, string channel, Json message) @trusted {
        if (serverId.length == 0) {
            logError("MessageRepository.appendMessage: serverId is empty");
            return;
        }
        channel = normalizeChannel(channel);

        auto payloadStr = message.toString();

        // Build document via Json first (vibe.d handles all types
        // correctly at the Json layer), then convert to Bson.
        long ts;
        if (auto t = "t" in message) {
            if (t.type == Json.Type.int_) ts = t.get!long;
        }
        if (ts == 0) ts = Clock.currTime.toUnixTime!long * 1000;

        string msgid;
        if (auto m = "m" in message) {
            if (m.type == Json.Type.string) msgid = m.get!string;
        }

        // IRCCloud-style eid: global sequential event ID, always present.
        // Stored as a top-level field so cursor lookups are O(1) indexed.
        long eid;
        if (auto e = "eid" in message) {
            if (e.type == Json.Type.int_) eid = e.get!long;
        }

        try {
            collection.insertOne(messageDocument(serverId, networkId, channel,
                payloadStr, ts, eid, msgid));
        } catch (Exception e) {
            logDebug("Mongo insert (probably duplicate): %s", e.msg);
        }
    }

    private static Bson messageDocument(string serverId, string networkId, string channel,
            string payload, long timestampMs, long eid, string msgid) @trusted {
        auto jdoc = Json([
            "_id": Json(serverId ~ ":" ~ networkId ~ ":" ~ channel ~ ":" ~
                (eid > 0 ? to!string(eid) : (msgid.length > 0 ? msgid : to!string(timestampMs)))),
            "serverId": Json(serverId),
            "networkId": Json(networkId),
            "channel": Json(channel),
            "t": Json(timestampMs),
            "payload": Json(payload)
        ]);
        if (msgid.length > 0) jdoc["msgid"] = Json(msgid);
        if (eid > 0) jdoc["eid"] = Json(eid);
        auto doc = Bson(jdoc);
        doc["tsAt"] = Bson(BsonDate(timestampMs));
        return doc;
    }

    /// Replay the original compact event, never assigning an eid or wall-clock
    /// timestamp here. A duplicate must be the same immutable event; its current
    /// channel is intentionally ignored because ordered renames can change it.
    ArchiveWriteResult appendArchivedMessage(string serverId, string networkId,
            string channel, Json message) @trusted {
        return appendArchivedPayload(serverId, networkId, channel, message, message.toString());
    }

    /// Journal replay keeps the admitted compact bytes verbatim. Do not
    /// serialize a parsed object again on every uncertain-write retry.
    ArchiveWriteResult appendArchivedCompactMessage(string serverId, string networkId,
            string channel, string compactJson) @trusted {
        Json message;
        try message = parseJsonString(compactJson);
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput); }
        return appendArchivedPayload(serverId, networkId, channel, message, compactJson);
    }

    private ArchiveWriteResult appendArchivedPayload(string serverId, string networkId,
            string channel, Json message, string payload) @trusted {
        channel = normalizeChannel(channel);
        if (!serverId.length || !networkId.length || !channel.length
                || message.type != Json.Type.object)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        const eidValue = "eid" in message;
        const timestampValue = "t" in message;
        if (eidValue is null || eidValue.type != Json.Type.int_ || eidValue.get!long <= 0
                || timestampValue is null || timestampValue.type != Json.Type.int_
                || timestampValue.get!long <= 0)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        const eid = eidValue.get!long;
        const timestampMs = timestampValue.get!long;
        string msgid;
        if (auto m = "m" in message)
            if (m.type == Json.Type.string) msgid = m.get!string;
        const doc = messageDocument(serverId, networkId, channel, payload, timestampMs, eid, msgid);
        auto command = Bson.emptyObject; // Mongo requires the verb first.
        command["insert"] = Bson("messages");
        command["documents"] = Bson([doc]);
        command["ordered"] = Bson(true);
        command["writeConcern"] = archiveWriteConcern();
        const reply = runArchiveCommand(command);
        checkArchiveReply(reply);
        const errors = reply["writeErrors"];
        if (errors.type == Bson.Type.array && errors.length == 1) {
            const error = errors[0];
            if (error.type != Bson.Type.object || !archiveIntegerEquals(error["code"], 11000)
                    || !archiveIntegerEquals(error["index"], 0)
                    || !archiveIntegerEquals(reply["n"], 0))
                throw new ArchiveWriteException(ArchiveWriteFailure.rejected,
                    archiveErrorCode(error));
            verifyArchivedDuplicate(doc);
            return ArchiveWriteResult.alreadyPersisted;
        }
        checkArchiveWriteErrors(reply);
        if (!archiveIntegerEquals(reply["n"], 1))
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        return ArchiveWriteResult.inserted;
    }

    /// Returns the acknowledged modified count, including zero on replay.
    /// Only pre-cutoff eids and eid-absent legacy rows can move; reuse of the
    /// old buffer after the barrier must not be renamed by a retry.
    long renameArchivedChannel(string serverId, string networkId, string oldChannel,
            string newChannel, long cutoffEid, long legacyTimestampCutoffMs) @trusted {
        auto filter = archiveCutoffFilter(serverId, networkId, oldChannel,
            cutoffEid, legacyTimestampCutoffMs);
        newChannel = normalizeChannel(newChannel);
        if (!newChannel.length)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        auto command = Bson.emptyObject;
        command["update"] = Bson("messages");
        command["updates"] = Bson([Bson([
            "q": filter,
            "u": Bson(["$set": Bson(["channel": Bson(newChannel)])]),
            "multi": Bson(true),
            "upsert": Bson(false)
        ])]);
        command["ordered"] = Bson(true);
        command["writeConcern"] = archiveWriteConcern();
        const reply = runArchiveCommand(command);
        checkArchiveReply(reply);
        checkArchiveWriteErrors(reply);
        const matched = archiveReplyCount(reply, "n");
        const modified = archiveReplyCount(reply, "nModified");
        if (modified > matched)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        return modified;
    }

    /// Idempotent purge of the frozen buffer prefix, never unconditional DEL.
    /// The caller retains the same cutoffs for every retry of the operation.
    long deleteArchivedChannel(string serverId, string networkId, string channel,
            long cutoffEid, long legacyTimestampCutoffMs) @trusted {
        auto filter = archiveCutoffFilter(serverId, networkId, channel,
            cutoffEid, legacyTimestampCutoffMs);
        auto command = Bson.emptyObject;
        command["delete"] = Bson("messages");
        command["deletes"] = Bson([Bson(["q": filter, "limit": Bson(0)])]);
        command["ordered"] = Bson(true);
        command["writeConcern"] = archiveWriteConcern();
        const reply = runArchiveCommand(command);
        checkArchiveReply(reply);
        checkArchiveWriteErrors(reply);
        return archiveReplyCount(reply, "n");
    }

    /// Canonical network metadata survives Redis eviction and ordinary config
    /// $set saves. At most 64 distinct engines per existing network; deletion
    /// still deletes the network, not its Mongo message history.
    /// Empty means a majority read found no canonical network; never recreate it.
    /// Fresh producers pass their canonical owner: the same majority read and
    /// catalog CAS must match it. Offline historical discovery has no producer
    /// owner and deliberately leaves that expectation empty.
    string[] registerArchiveScopes(RedisStorage redis, string networkId, string[] servers,
            string expectedOwner = "") @trusted {
        if (!servers.length) throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        return synchronizeArchiveScopes(redis, networkId, servers, false, expectedOwner);
    }

    string[] registerArchiveScopes(RedisStorage redis, string networkId, string[] servers,
            string expectedOwner, ref NetworkWriter writer) @trusted {
        import ircfiber.archive_protocol : isCanonicalArchiveOperationId;
        if (redis is null || !servers.length || servers.length > 66
                || !isCanonicalArchiveOperationId(networkId)
                || (expectedOwner.length && !isCanonicalArchiveOperationId(expectedOwner)))
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        foreach (server; servers) if (!server.length || server.length > 128)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        try return synchronizeAdmittedArchiveScopes(networkId, servers, false, expectedOwner, writer);
        catch (ArchiveWriteException e) { throw e; }
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.unavailable); }
    }

    /// Includes pre-journal rows before any clear. Never truncate a 65th scope.
    string[] archivedServerScopes(RedisStorage redis, string networkId,
            string[] retainedProjection = null) @trusted {
        auto scopes = synchronizeArchiveScopes(redis, networkId, retainedProjection, true);
        if (!scopes.length) throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
        return scopes;
    }

    private static void addArchiveScope(ref string[64] scopes, ref size_t count, string server) @trusted {
        if (!server.length || server.length > 128)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        foreach (known; scopes[0 .. count]) if (known == server) return;
        if (count == scopes.length)
            throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
        scopes[count++] = server;
    }

    private static Bson archiveNetworkCatalog(string networkId) @trusted {
        auto command = Bson.emptyObject;
        command["find"] = Bson("networks");
        command["filter"] = Bson(["id": Bson(networkId)]);
        command["projection"] = Bson(["_id": Bson(0), "id": Bson(1),
            "userId": Bson(1), "archiveScopeVersion": Bson(1), "archiveServers": Bson(1)]);
        command["limit"] = Bson(1L); command["singleBatch"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        command["readConcern"] = Bson(["level": Bson("majority")]);
        auto reply = runArchiveCommand(command);
        checkArchiveReply(reply); checkArchiveWriteErrors(reply);
        auto cursor = reply["cursor"];
        if (cursor.type != Bson.Type.object || cursor["firstBatch"].type != Bson.Type.array
                || cursor["firstBatch"].length > 1)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        if (!cursor["firstBatch"].length) return Bson(null);
        auto doc = cursor["firstBatch"][0];
        if (doc.type != Bson.Type.object || doc["id"].type != Bson.Type.string
                || doc["id"].get!string != networkId)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        return doc;
    }

    private static void killArchiveCursor(long cursorId) @trusted {
        if (!cursorId) return;
        try {
            auto kill = Bson.emptyObject; kill["killCursors"] = Bson("messages");
            kill["cursors"] = Bson([Bson(cursorId)]);
            runArchiveCommand(kill);
        } catch (Exception) {}
    }

    private static void legacyArchiveScopes(string networkId, ref string[64] scopes,
            ref size_t count) @trusted {
        // Limit on the server, stream batches, and bound each returned scalar.
        // Missing/non-string attribution fails rather than dropping a scope.
        auto command = Bson.emptyObject;
        command["aggregate"] = Bson("messages");
        command["pipeline"] = Bson([
            Bson(["$match": Bson(["networkId": Bson(networkId)])]),
            Bson(["$group": Bson(["_id": Bson("$serverId")])]),
            Bson(["$limit": Bson(65)]),
            Bson(["$project": Bson(["_id": Bson(["$substrBytes":
                Bson([Bson("$_id"), Bson(0), Bson(129)])])])])
        ]);
        command["cursor"] = Bson(["batchSize": Bson(65)]);
        command["maxTimeMS"] = Bson(5000);
        command["readConcern"] = Bson(["level": Bson("majority")]);
        long cursorId;
        scope(exit) killArchiveCursor(cursorId);
        size_t rows;
        bool first = true;
        while (true) {
            auto reply = runArchiveCommand(command);
            checkArchiveReply(reply); checkArchiveWriteErrors(reply);
            auto cursor = reply["cursor"];
            const field = first ? "firstBatch" : "nextBatch";
            if (cursor.type != Bson.Type.object || !archiveInteger(cursor["id"], cursorId)
                    || cursor["ns"].type != Bson.Type.string
                    || cursor[field].type != Bson.Type.array || cursor[field].length > 65 - rows)
                throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
            foreach (row; cursor[field].byValue) {
                if (row.type != Bson.Type.object || row["_id"].type != Bson.Type.string)
                    throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
                ++rows;
                if (rows > 64) throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
                addArchiveScope(scopes, count, row["_id"].get!string);
            }
            if (!cursorId) break;
            if (rows == 65 || cursor[field].length == 0)
                throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
            command = Bson.emptyObject; command["getMore"] = Bson(cursorId);
            command["collection"] = Bson("messages");
            command["batchSize"] = Bson(cast(int)(65 - rows));
            command["maxTimeMS"] = Bson(5000);
            first = false;
        }
    }

    private static string[] synchronizeArchiveScopes(RedisStorage redis, string networkId,
            string[] additions, bool includeLegacy, string expectedOwner = "") @trusted {
        import ircfiber.archive_protocol : isCanonicalArchiveOperationId;
        if (!isCanonicalArchiveOperationId(networkId) || additions.length > 66)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        if (expectedOwner.length && !isCanonicalArchiveOperationId(expectedOwner))
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        foreach (server; additions) if (!server.length || server.length > 128)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        try {
            return runNetworkWrite!(string[])(redis, (ref NetworkWriter writer) {
                return synchronizeAdmittedArchiveScopes(networkId, additions, includeLegacy, expectedOwner, writer);
            });
        } catch (ArchiveWriteException e) { throw e; }
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.unavailable); }
    }

    private static string[] synchronizeAdmittedArchiveScopes(string networkId, string[] additions,
            bool includeLegacy, string expectedOwner, ref NetworkWriter writer) @trusted {
        // Exact-array CAS prevents concurrent registrations overflowing 64.
        // Contention is a retry, never a weakened write concern or subset read.
        foreach (_; 0 .. 4) {
            auto doc = archiveNetworkCatalog(networkId);
            if (doc.isNull) return null;
            if (expectedOwner.length && (doc["userId"].type != Bson.Type.string
                    || doc["userId"].get!string != expectedOwner))
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
            bool initialized;
            foreach (key, value; doc.byKeyValue) if (key == "archiveScopeVersion") {
                if (!archiveIntegerEquals(value, 1))
                    throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
                initialized = true;
            }
            string[64] scopes;
            size_t count, originalCount;
            if (initialized) {
                if (doc["archiveServers"].type != Bson.Type.array || doc["archiveServers"].length > scopes.length)
                    throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
                foreach (scopeId; doc["archiveServers"].byValue) {
                    if (scopeId.type != Bson.Type.string)
                        throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
                    addArchiveScope(scopes, count, scopeId.get!string);
                }
                if (count != doc["archiveServers"].length)
                    throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
                originalCount = count;
            } else {
                foreach (key, value; doc.byKeyValue) if (key == "archiveServers")
                    throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
            }
            // The first registered engine remains the immutable response
            // coordinator even after Redis projection loss and later moves.
            foreach (server; additions) addArchiveScope(scopes, count, server);
            if (includeLegacy || !initialized) legacyArchiveScopes(networkId, scopes, count);
            if (initialized && count == originalCount) return scopes[0 .. count].dup;
            auto query = Bson(["id": Bson(networkId)]);
            if (expectedOwner.length) query["userId"] = Bson(expectedOwner);
            if (initialized) {
                query["archiveScopeVersion"] = Bson(1);
                query["archiveServers"] = doc["archiveServers"];
            } else {
                query["archiveScopeVersion"] = Bson(["$exists": Bson(false)]);
                query["archiveServers"] = Bson(["$exists": Bson(false)]);
            }
            Bson[64] encodedScopes;
            foreach (i; 0 .. count) encodedScopes[i] = Bson(scopes[i]);
            auto command = Bson.emptyObject; command["update"] = Bson("networks");
            command["updates"] = Bson([Bson(["q": query, "u": Bson(["$set": Bson([
                "archiveScopeVersion": Bson(1), "archiveServers": Bson(encodedScopes[0 .. count])])]),
                "multi": Bson(false), "upsert": Bson(false)])]);
            command["ordered"] = Bson(true); command["writeConcern"] = archiveWriteConcern();
            Bson reply;
            try reply = runNetworkMutation(writer, command);
            catch (NetworkMutationException e) {
                // Keep the archive failure/code contract without exposing raw
                // driver text. The gate has already retained uncertain ownership.
                checkArchiveReply(e.reply);
                checkArchiveWriteErrors(e.reply);
                throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
            }
            long matched;
            try {
                checkArchiveReply(reply); checkArchiveWriteErrors(reply);
                matched = archiveReplyCount(reply, "n");
                if (matched != 0 && matched != 1)
                    throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
            } catch (ArchiveWriteException e) {
                // A caller may catch a typed catalog failure and continue its
                // logical operation. That must not confirm a malformed ACK.
                retainNetworkWriteUncertainty(writer);
                throw e;
            }
            if (matched == 1) return scopes[0 .. count].dup;
        }
        throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
    }

    private static Bson archiveCutoffFilter(string serverId, string networkId,
            string channel, long cutoffEid, long legacyTimestampCutoffMs) @trusted {
        channel = normalizeChannel(channel);
        if (!serverId.length || !networkId.length || !channel.length
                || cutoffEid <= 0 || legacyTimestampCutoffMs <= 0)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        return Bson([
            "serverId": Bson(serverId), "networkId": Bson(networkId), "channel": Bson(channel),
            "$or": Bson([
                Bson(["eid": Bson(["$gt": Bson(0L), "$lte": Bson(cutoffEid)])]),
                Bson(["eid": Bson(["$exists": Bson(false)]),
                    "t": Bson(["$lte": Bson(legacyTimestampCutoffMs)])])
            ])
        ]);
    }

    private static Bson archiveWriteConcern() @trusted {
        return Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
    }

    private static Bson runArchiveCommand(Bson command) @trusted {
        if (!AppMongoConnection.isConnected())
            throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
        try {
            return AppMongoConnection.getDb().runCommandUnchecked(command);
        } catch (Exception) {
            // Driver exceptions can embed a command/document or connection URI.
            throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
        }
    }

    private static bool archiveInteger(const Bson value, out long number) @trusted {
        switch (value.type) {
            case Bson.Type.int_: number = value.get!int; return true;
            case Bson.Type.long_: number = value.get!long; return true;
            case Bson.Type.double_:
                const n = value.get!double;
                // Only exactly representable integers are accepted from doubles.
                if (!(n >= -9_007_199_254_740_991.0 && n <= 9_007_199_254_740_991.0))
                    return false;
                number = cast(long)n;
                return n == cast(double)number;
            default: return false;
        }
    }

    private static bool archiveIntegerEquals(const Bson value, long expected) @trusted {
        long actual;
        return archiveInteger(value, actual) && actual == expected;
    }

    private static long archiveErrorCode(const Bson error) @trusted {
        long code;
        if (error.type == Bson.Type.object) archiveInteger(error["code"], code);
        return code;
    }

    private static long archiveReplyCount(const Bson reply, string field) @trusted {
        long count;
        if (!archiveInteger(reply[field], count) || count < 0)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        return count;
    }

    private static void checkArchiveReply(const Bson reply) @trusted {
        if (reply.type != Bson.Type.object)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        // Check presence, not truthiness: even a malformed/null concern error
        // must not turn an uncertain write into a checkpoint acknowledgment.
        foreach (key, value; reply.byKeyValue)
            if (key == "writeConcernError")
                throw new ArchiveWriteException(ArchiveWriteFailure.rejected,
                    archiveErrorCode(value));
        if (!archiveIntegerEquals(reply["ok"], 1))
            throw new ArchiveWriteException(ArchiveWriteFailure.rejected, archiveErrorCode(reply));
    }

    private static void checkArchiveWriteErrors(const Bson reply) @trusted {
        foreach (key, value; reply.byKeyValue) {
            if (key != "writeErrors") continue;
            if (value.type != Bson.Type.array)
                throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
            foreach (error; value.byValue)
                throw new ArchiveWriteException(ArchiveWriteFailure.rejected, archiveErrorCode(error));
        }
    }

    private static void verifyArchivedDuplicate(const Bson expected) @trusted {
        auto command = Bson.emptyObject;
        command["find"] = Bson("messages");
        command["filter"] = Bson(["_id": expected["_id"]]);
        command["limit"] = Bson(1L);
        command["singleBatch"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        // A local read could mistake an earlier uncertain/uncommitted insert
        // for durable archival success after a duplicate-key response.
        command["readConcern"] = Bson(["level": Bson("majority")]);
        const reply = runArchiveCommand(command);
        checkArchiveReply(reply);
        checkArchiveWriteErrors(reply);
        const cursor = reply["cursor"];
        if (cursor.type != Bson.Type.object || cursor["firstBatch"].type != Bson.Type.array)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        const batch = cursor["firstBatch"];
        if (batch.length == 0)
            throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
        if (batch.length != 1 || batch[0].type != Bson.Type.object)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        const stored = batch[0];
        foreach (field; ["_id", "serverId", "networkId", "payload"]) {
            if (stored[field].type != Bson.Type.string
                    || stored[field].get!string != expected[field].get!string)
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
        }
        foreach (field; ["eid", "t"])
            if (!archiveIntegerEquals(stored[field], expected[field].get!long))
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
    }

    /// Rename a buffer's channel field after a NICK-follow, so Mongo
    /// backfill/search follows the conversation. Best-effort: returns
    /// the number of documents modified. `_id`s embed the old channel
    /// and are left as-is (still unique; only `channel` is queried).
    long renameChannel(string serverId, string networkId, string oldChan, string newChan) @trusted {
        oldChan = normalizeChannel(oldChan);
        newChan = normalizeChannel(newChan);
        if (serverId.length == 0 || networkId.length == 0
            || oldChan.length == 0 || newChan.length == 0 || oldChan == newChan)
            return 0;
        try {
            auto res = collection.updateMany(
                Bson(["serverId": Bson(serverId),
                      "networkId": Bson(networkId),
                      "channel": Bson(oldChan)]),
                Bson(["$set": Bson(["channel": Bson(newChan)])]));
            if (res.modifiedCount > 0)
                logInfo("Renamed Mongo channel %s:%s %s -> %s (%s docs)",
                    serverId, networkId, oldChan, newChan, res.modifiedCount.to!string);
            return res.modifiedCount;
        } catch (Exception e) {
            logWarn("renameChannel failed: %s", e.msg);
            return 0;
        }
    }

    /// Convenience: append directly from an IRCRawEvent.
    void appendIRCEvent(IRCRawEvent event, string serverId) @trusted {
        const networkId = event.networkId.length > 0 ? event.networkId : event.network;
        const channel = event.channel.length > 0 ? normalizeChannel(event.channel) : "_server";
        auto msg = event.toCompactJson();
        appendMessage(serverId, networkId, channel, msg);
    }

    /// Read a payload back from Mongo and convert the stored JSON
    /// string into a Json object. Returns an empty array on parse
    /// error so a single bad document doesn't kill the whole page.
    ///
    /// Returns oldest-first (IRCCloud/Redis convention) — the find()
    /// above returns newest-first (sort by t desc) and we reverse here
    /// so the caller can treat MongoDB and Redis results identically.
    private Json[] readPayloads(Bson filter, int count) @trusted {
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        FindOptions options;
        options.sort = Bson(["t": Bson(-1)]);
        options.limit = cast(long)count;

        Json[] out_;
        foreach (doc; collection.find(filter, options)) {
            const p = doc["payload"];
            if (p.type == Bson.Type.string) {
                auto raw = p.get!string;
                try {
                    out_ ~= parseJsonString(raw);
                } catch (Exception e) {
                    logWarn("Failed to parse stored message payload: %s", e.msg);
                }
            }
        }
        // Match Redis _getRecentFiltered which does messages.reverse.
        out_.reverse;
        return out_;
    }

    /**
     * Fetch the most recent `count` messages for a channel, newest-first
     * by timestamp. Used as the MongoDB fallback for the `_server` buffer
     * scrollback during WebSocket state dump when Redis is cold.
     */
    Json[] getRecent(string serverId, string networkId, string channel,
                     int count = 50) @trusted {
        channel = normalizeChannel(channel);
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        Bson filter;
        if (serverId.length > 0) {
            filter = Bson([
                "serverId": Bson(serverId),
                "networkId": Bson(networkId),
                "channel": Bson(channel)
            ]);
        } else {
            filter = Bson([
                "networkId": Bson(networkId),
                "channel": Bson(channel)
            ]);
        }
        return readPayloads(filter, count);
    }

    /**
     * Fetch older messages using an eid cursor (IRCCloud-style).
     *
     * The cursor is an eid. We look up the cursor in MongoDB by its
     * eid to get its timestamp, then return up to `count` messages
     * with timestamp strictly less than the cursor's timestamp.
     *
     * If the cursor eid is not found (legacy message without eid),
     * `fallbackTs` is used instead.
     *
     * This is the primary pagination path — eid is always present
     * for every new event, matching IRCCloud's architecture.
     */
    Json[] getBeforeEid(string serverId, string networkId, string channel,
                        long beforeEid, long fallbackTs, int count) @trusted {
        channel = normalizeChannel(channel);
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        long beforeTs = 0;
        if (beforeEid > 0) {
            Bson cursorFilter;
            if (serverId.length > 0) {
                cursorFilter = Bson([
                    "serverId": Bson(serverId),
                    "networkId": Bson(networkId),
                    "channel": Bson(channel),
                    "eid": Bson(beforeEid)
                ]);
            } else {
                cursorFilter = Bson([
                    "networkId": Bson(networkId),
                    "channel": Bson(channel),
                    "eid": Bson(beforeEid)
                ]);
            }
            auto cursorDoc = collection.findOne(cursorFilter);
            if (!cursorDoc.isNull) {
                beforeTs = readBsonTimestamp(cursorDoc["t"]);
            }
        }

        if (beforeTs == 0) {
            beforeTs = fallbackTs;
        }

        if (beforeTs == 0) {
            return [];
        }

        Bson filter;
        if (serverId.length > 0) {
            filter = Bson([
                "serverId": Bson(serverId),
                "networkId": Bson(networkId),
                "channel": Bson(channel),
                "t": Bson(["$lt": Bson(beforeTs)])
            ]);
        } else {
            filter = Bson([
                "networkId": Bson(networkId),
                "channel": Bson(channel),
                "t": Bson(["$lt": Bson(beforeTs)])
            ]);
        }
        applyNoiseExclusion(filter, channel);
        return readPayloads(filter, count);
    }

    Json[] getBeforeMsgid(string serverId, string networkId, string channel,
                          string beforeMsgid, long fallbackTs, int count) @trusted {
        channel = normalizeChannel(channel);
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;
        long beforeTs = 0;
        Bson cursorFilter;
        if (serverId.length > 0) {
            cursorFilter = Bson([
                "serverId": Bson(serverId),
                "networkId": Bson(networkId),
                "channel": Bson(channel),
                "msgid": Bson(beforeMsgid)
            ]);
        } else {
            cursorFilter = Bson([
                "networkId": Bson(networkId),
                "channel": Bson(channel),
                "msgid": Bson(beforeMsgid)
            ]);
        }
        auto cursorDoc = collection.findOne(cursorFilter);
        if (!cursorDoc.isNull) {
            beforeTs = readBsonTimestamp(cursorDoc["t"]);
        }

        if (beforeTs == 0) {
            // Cursor msgid not found in MongoDB — use the timestamp
            // fallback from the frontend's `before` parameter.
            beforeTs = fallbackTs;
        }

        if (beforeTs == 0) {
            // No timestamp fallback either — return empty (no more history).
            return [];
        }

        Bson filter;
        if (serverId.length > 0) {
            filter = Bson([
                "serverId": Bson(serverId),
                "networkId": Bson(networkId),
                "channel": Bson(channel),
                "t": Bson(["$lt": Bson(beforeTs)])
            ]);
        } else {
            filter = Bson([
                "networkId": Bson(networkId),
                "channel": Bson(channel),
                "t": Bson(["$lt": Bson(beforeTs)])
            ]);
        }
        applyNoiseExclusion(filter, channel);
        return readPayloads(filter, count);
    }

    /// Exclusive bounds; selected rows are always returned in ascending storage order.
    Json[] getWindow(string serverId, string networkId, string channel,
                     HistoryBoundary after, HistoryBoundary before, int count,
                     bool fromNewest, bool events = false) @trusted {
        return historyWindow(serverId, networkId, channel, after, before, count, fromNewest, events);
    }

    private static Bson boundaryFilter(HistoryBoundary boundary, bool after, bool inclusive = false) {
        const op = after ? "$gt" : "$lt";
        const edgeOp = inclusive ? (after ? "$gte" : "$lte") : op;
        if (!boundary.exact)
            return Bson(["t": Bson([edgeOp: Bson(boundary.timestampMs)])]);
        Bson[] alternatives = [Bson(["t": Bson([op: Bson(boundary.timestampMs)])])];
        if (boundary.hasEid) {
            if (!after)
                alternatives ~= Bson(["t": Bson(boundary.timestampMs), "eid": Bson(["$exists": Bson(false)])]);
            alternatives ~= Bson(["t": Bson(boundary.timestampMs), "eid": Bson([op: Bson(boundary.eid)])]);
        } else if (after) {
            alternatives ~= Bson(["t": Bson(boundary.timestampMs), "eid": Bson(["$exists": Bson(true)])]);
        }
        auto same = Bson(["t": Bson(boundary.timestampMs),
            "eid": boundary.hasEid ? Bson(boundary.eid) : Bson(["$exists": Bson(false)]),
            "_id": Bson([edgeOp: Bson(boundary.storageId)])]);
        alternatives ~= same;
        return Bson(["$or": Bson(alternatives)]);
    }

    private Json[] historyWindow(string serverId, string networkId, string channel,
            HistoryBoundary after, HistoryBoundary before, int count, bool fromNewest,
            bool events, bool includeAfter = false) @trusted {
        if (count <= 0) return [];
        count = min(count, 1000);
        channel = normalizeChannel(channel);
        Bson filter = serverId.length > 0
            ? Bson(["serverId": Bson(serverId), "networkId": Bson(networkId), "channel": Bson(channel)])
            : Bson(["networkId": Bson(networkId), "channel": Bson(channel)]);
        Bson[] bounds;
        if (after.exact || after.timestampMs != 0) bounds ~= boundaryFilter(after, true, includeAfter);
        if (before.exact || before.timestampMs != 0) bounds ~= boundaryFilter(before, false);
        if (bounds.length) filter["$and"] = Bson(bounds);
        filter["payload"] = Bson(["$regex": Bson(events ? EVENT_PAYLOAD_RE : CHAT_PAYLOAD_RE)]);
        FindOptions options;
        auto order = Bson.emptyObject;
        foreach (key; ["t", "eid", "_id"]) order[key] = Bson(fromNewest ? -1 : 1);
        options.sort = order;
        options.limit = cast(long) count;
        Json[] rows;
        foreach (doc; collection.find(filter, options)) {
            if (doc["payload"].type != Bson.Type.string) continue;
            try rows ~= parseJsonString(doc["payload"].get!string);
            catch (Exception e) logWarn("Failed to parse stored message payload: %s", e.msg);
        }
        if (fromNewest) rows.reverse;
        return rows;
    }

    /// Include the selected exact row once, between strict older/newer halves.
    Json[] getAround(string serverId, string networkId, string channel,
            HistoryBoundary center, int count, bool events = false) @trusted {
        if (count <= 0) return [];
        const half = count / 2;
        return historyWindow(serverId, networkId, channel, HistoryBoundary.init, center, half, true, events)
            ~ historyWindow(serverId, networkId, channel, center, HistoryBoundary.init,
                count - half, false, events, true);
    }


    /// False is an unknown reference, never an unbounded window.
    bool boundaryOfMsgid(string serverId, string networkId, string channel, string msgid,
            out HistoryBoundary boundary) @trusted {
        channel = normalizeChannel(channel);
        Bson filter = serverId.length > 0
            ? Bson(["serverId": Bson(serverId), "networkId": Bson(networkId), "channel": Bson(channel), "msgid": Bson(msgid)])
            : Bson(["networkId": Bson(networkId), "channel": Bson(channel), "msgid": Bson(msgid)]);
        FindOptions options;
        options.sort = indexKeys(["t", "eid", "_id"]);
        options.limit = 1;
        // Bson.init is undefined, not null; an empty cursor must leave
        // an explicit null sentinel for the unknown-reference result.
        Bson doc = Bson(null);
        foreach (candidate; collection.find(filter, options)) { doc = candidate; break; }
        if (doc.isNull) return false;
        boundary.timestampMs = readBsonTimestamp(doc["t"]);
        boundary.hasEid = doc["eid"].type == Bson.Type.long_ || doc["eid"].type == Bson.Type.int_;
        boundary.eid = readBsonTimestamp(doc["eid"]);
        boundary.storageId = doc["_id"].get!string;
        boundary.msgid = msgid;
        boundary.exact = true;
        return true;
    }

    /// Filter the actual latest retained chat row, not the latest within the interval.
    long latestTimestamp(string serverId, string networkId, string channel,
                         long afterTs, long beforeTs) @trusted {
        auto rows = getWindow(serverId, networkId, channel, HistoryBoundary.init, HistoryBoundary.init, 1, true);
        foreach (ev; rows) {
            if (ev.type != Json.Type.object) continue;
            if (auto t = "t" in ev) if (t.type == Json.Type.int_) {
                const ts = t.get!long;
                return (afterTs == 0 || ts > afterTs) && (beforeTs == 0 || ts < beforeTs) ? ts : 0;
            }
        }
        return 0;
    }

    /// Previously delivered identities among a reconnect page; timestamps are not identity.
    bool[string] deliveredHistoryKeys(string serverId, string networkId, Json[] rows, long throughEid) @trusted {
        Bson[] identities;
        foreach (row; rows) {
            if (row["m"].type != Json.Type.string || !row["m"].get!string.length) continue;
            if (row["ch"].type != Json.Type.string) continue;
            identities ~= Bson(["channel": Bson(normalizeChannel(row["ch"].get!string)),
                "msgid": Bson(row["m"].get!string)]);
        }
        bool[string] keys;
        if (!identities.length) return keys;
        auto filter = Bson(["serverId": Bson(serverId), "networkId": Bson(networkId),
            "eid": Bson(["$lte": Bson(throughEid)]), "$or": Bson(identities)]);
        foreach (doc; collection.find(filter)) {
            if (doc["msgid"].type == Bson.Type.string && doc["channel"].type == Bson.Type.string)
                keys[doc["channel"].get!string ~ "\0m" ~ doc["msgid"].get!string] = true;
        }
        return keys;
    }

    /// Fetch older messages using a timestamp cursor (fallback when
    /// no msgid is available).
    Json[] getBeforeTimestamp(string serverId, string networkId, string channel,
                             long beforeTs, int count) @trusted {
        channel = normalizeChannel(channel);

        Bson filter;
        if (beforeTs > 0) {
            if (serverId.length > 0) {
                filter = Bson([
                    "serverId": Bson(serverId),
                    "networkId": Bson(networkId),
                    "channel": Bson(channel),
                    "t": Bson(["$lt": Bson(beforeTs)])
                ]);
            } else {
                filter = Bson([
                    "networkId": Bson(networkId),
                    "channel": Bson(channel),
                    "t": Bson(["$lt": Bson(beforeTs)])
                ]);
            }
        } else {
            if (serverId.length > 0) {
                filter = Bson([
                    "serverId": Bson(serverId),
                    "networkId": Bson(networkId),
                    "channel": Bson(channel)
                ]);
            } else {
                filter = Bson([
                    "networkId": Bson(networkId),
                    "channel": Bson(channel)
                ]);
            }
        }
        applyNoiseExclusion(filter, channel);
        return readPayloads(filter, count);
    }

    /**
     * Fetch events with eid > `afterEid` for a given network+channel
     * (IRCCloud OOB / hole-filling endpoint).
     *
     * Used by the gateway's `/api/oob?since=<eid>` handler to fill holes
     * the WS missed without a full reconnect. The result is
     * oldest-first (the caller can append them to the local buffer in
     * the same order they would have arrived live).
     *
     * Performance: uses the `(serverId, networkId, channel, eid)`
     * compound index (descending on eid) so this is O(log N) for the
     * index seek + O(count) for the read.
     */
    Json[] getAfterEid(string serverId, string networkId, string channel,
                       long afterEid, int count) @trusted {
        if (serverId.length == 0) return [];
        channel = normalizeChannel(channel);
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        Bson filter = Bson([
            "serverId": Bson(serverId),
            "networkId": Bson(networkId),
            "channel": Bson(channel),
            "eid": Bson(["$gt": Bson(afterEid)])
        ]);
        return readPayloads(filter, count);
    }

    /**
     * Fetch events with eid > `afterEid` across ALL channels for a
     * network (used by the /api/oob endpoint when the client doesn't
     * know which channel the missing events landed in).
     *
     * Returns events sorted by eid ascending so the client can dedup
     * by eid and append to the appropriate buffer.
     */
    Json[] getAfterEidForNetwork(string serverId, string networkId,
                                 long afterEid, int count) @trusted {
        if (serverId.length == 0) return [];
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        // Bypass the per-channel readPayloads helper because we don't
        // want a per-channel cap here — we want N events across the
        // whole network.
        FindOptions options;
        options.sort = Bson(["eid": Bson(1)]);
        options.limit = cast(long)count;

        Bson filter = Bson([
            "serverId": Bson(serverId),
            "networkId": Bson(networkId),
            "eid": Bson(["$gt": Bson(afterEid)])
        ]);
        Json[] out_;
        foreach (doc; collection.find(filter, options)) {
            const p = doc["payload"];
            if (p.type == Bson.Type.string) {
                auto raw = p.get!string;
                try {
                    out_ ~= parseJsonString(raw);
                } catch (Exception e) {
                    logWarn("getAfterEidForNetwork: bad payload: %s", e.msg);
                }
            }
        }
        return out_;
    }

    /// Delete all messages for a given buffeer from permanent storage.
    /// Called from the "Clear backlog" flow to ensure the MongoDB
    /// fallback doesn't re-surface deleted messages after a page
    /// refresh (the two-tier lookup in getMessages falls through to
    /// MongoDB when Redis is cold).
    void deleteByChannel(string serverId, string networkId, string channel) @trusted {
        if (serverId.length == 0 || networkId.length == 0 || channel.length == 0) return;
        channel = normalizeChannel(channel);
        Bson filter = Bson([
            "serverId": Bson(serverId),
            "networkId": Bson(networkId),
            "channel": Bson(channel)
        ]);
        auto res = collection.deleteMany(filter);
        logInfo("Deleted %s messages from MongoDB for %s:%s:%s",
            res.deletedCount.to!string, serverId, networkId, channel);
    }

    /// Count total messages in a buffer (IRCCloud exposes this as
    /// `backlog_size` to the client).
    long count(string serverId, string networkId, string channel) @trusted {
        channel = normalizeChannel(channel);
        Bson filter;
        if (serverId.length > 0) {
            filter = Bson([
                "serverId": Bson(serverId),
                "networkId": Bson(networkId),
                "channel": Bson(channel)
            ]);
        } else {
            filter = Bson([
                "networkId": Bson(networkId),
                "channel": Bson(channel)
            ]);
        }
        return cast(long)collection.countDocuments(filter);
    }

    /// Result of a Redis→Mongo sync pass for a single buffer.
    struct SyncResult {
        /// Entries pulled from Redis.
        long scanned;       // entries pulled from Redis
        /// New Mongo docs written.
        long inserted;      // new Mongo docs written
        /// Entries that already existed in Mongo.
        long duplicates;    // entries that already existed in Mongo
        /// Entries that failed JSON parsing.
        long parseErrors;   // entries that failed JSON parsing
    }

    /**
     * Drain a Redis scrollback buffer into MongoDB. Idempotent —
     * existing documents (matched by `_id = serverId:networkId:channel:msgid`
     * or `:timestamp`) are silently dropped because the underlying
     * `insertOne` is wrapped in a try/catch in `appendMessage`.
     *
     * Use this to backfill messages that were appended to Redis during
     * a window when the event→Mongo path was down (e.g. before a
     * restart, or if the engine was offline). After the sync, Mongo's
     * `backlog_size` will reflect everything in Redis for this buffer.
     */
    SyncResult syncFromRedis(
        RedisStorage redis,
        string serverId, string networkId, string channel
    ) @trusted {
        import std.range : walkLength;
        SyncResult r;
        if (serverId.length == 0) {
            logError("syncFromRedis: serverId is empty");
            return r;
        }

        channel = normalizeChannel(channel);
        auto key = "scrollback:" ~ serverId ~ ":" ~ networkId ~ ":" ~ channel;
        auto db = redis.getDb();
        auto raw = db.lrange!(ubyte[])(key, 0, 5000);
        r.scanned = raw.walkLength;

        const long before = count(serverId, networkId, channel);
        foreach (entry; raw) {
            string s;
            try { s = () @trusted { return cast(string)entry.idup; } (); }
            catch (Exception e) { r.parseErrors++; continue; }
            s = sanitizeUtf8(s);
            if (s.length == 0) { r.parseErrors++; continue; }
            try {
                auto msg = parseJson(s);
                if (msg.type != Json.Type.object) { r.parseErrors++; continue; }
                appendMessage(serverId, networkId, channel, msg);
            } catch (Exception e) {
                r.parseErrors++;
            }
        }
        const long after = count(serverId, networkId, channel);
        r.inserted = after - before;
        r.duplicates = r.scanned - r.inserted - r.parseErrors;
        if (r.duplicates < 0) r.duplicates = 0;
        return r;
    }

    /// Enumerate every Redis scrollback key and sync it to Mongo. Returns
    /// one SyncResult per buffer. Uses KEYS (not SCAN) for simplicity —
    /// fine for a one-shot backfill, but for a multi-million key Redis
    /// you'd want to swap in a SCAN-based iterator.
    SyncResult[] syncAllFromRedis(RedisStorage redis) @trusted {
        import std.string : indexOf;
        SyncResult[] all;
        auto db = redis.getDb();
        auto reply = db.keys("scrollback:*");
        foreach (k; reply) {
            auto key = () @trusted { return cast(string)k.idup; } ();
            // scrollback:<serverId>:<networkId>:<channel>
            auto rest = key["scrollback:".length .. $];
            auto p1 = rest.indexOf(':');
            if (p1 < 0) continue;
            auto serverId = rest[0 .. p1];
            auto rest2 = rest[p1 + 1 .. $];
            auto p2 = rest2.indexOf(':');
            if (p2 < 0) continue;
            auto networkId = rest2[0 .. p2];
            auto channel = rest2[p2 + 1 .. $];
            all ~= syncFromRedis(redis, serverId, networkId, channel);
        }
        return all;
    }
}
