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

        auto jdoc = Json([
            "_id": Json(serverId ~ ":" ~ networkId ~ ":" ~ channel ~ ":" ~
                (eid > 0 ? to!string(eid) : (msgid.length > 0 ? msgid : to!string(ts)))),
            "serverId": Json(serverId),
            "networkId": Json(networkId),
            "channel": Json(channel),
            "t": Json(ts),
            "payload": Json(payloadStr)
        ]);
        if (msgid.length > 0) jdoc["msgid"] = Json(msgid);
        if (eid > 0) jdoc["eid"] = Json(eid);

        try {
            auto doc = Bson(jdoc);
            doc["tsAt"] = Bson(BsonDate(ts));
            collection.insertOne(doc);
        } catch (Exception e) {
            logDebug("Mongo insert (probably duplicate): %s", e.msg);
        }
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
