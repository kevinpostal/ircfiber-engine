module ircfiber.db.messages;

import std.uuid;
import std.conv;
import std.algorithm;
import std.array;
import std.json;
import std.datetime : Clock;
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

/**
 * Permanent message storage (IRCCloud-style).
 *
 * MongoDB stores every message that ever passed through the engine.
 * Redis keeps a hot cache of the most recent N messages for fast access.
 * When the cache is exhausted (e.g. very old history), the REST API
 * falls through to MongoDB for true infinite scrollback.
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
    /// render (mirrors `BufferManager.isScrollbackNoiseCommand`) so the
    /// Mongo fall-through returns REAL messages, not a wall of invisible
    /// WHO/NAMES/TAGMSG rows that push PRIVMSGs out of the visible
    /// window. Only applied to channel buffers — the `_server` log
    /// needs its numerics/MOTD.
    private static immutable string NOISE_PAYLOAD_RE =
        `"c"\s*:\s*"(315|352|332|333|353|354|366|367|368|376|422|311|312|313|317|318|319|330|301|671|401|324|329|303|PONG|TAGMSG|QUIT|you_nickchange)"`;

    /// Positive match for chat rows only (bouncer playback / CHATHISTORY):
    /// the limit must apply to PRIVMSG/NOTICE, not to JOIN/MODE churn.
    private static immutable string CHAT_PAYLOAD_RE = `"c"\s*:\s*"(PRIVMSG|NOTICE)"`;

    private static Bson noisePayloadExclusion() @trusted {
        return Bson([
            "payload": Bson(["$not": Bson(BsonRegex(NOISE_PAYLOAD_RE, ""))])
        ]);
    }

    private static void applyNoiseExclusion(ref Bson filter, string channel) {
        if (channel != "_server") {
            filter["payload"] = noisePayloadExclusion()["payload"];
        }
    }

    /// Creates a repository bound to the messages collection.
    this() {
        collection = AppMongoConnection.getDb()["messages"];
        ensureIndexes();
    }

    /// Build the primary compound index for paginated queries.
    private void ensureIndexes() @trusted {
        try {
            // Primary compound index: pagination by timestamp
            collection.createIndex(
                Bson([
                    "serverId": Bson(1),
                    "networkId": Bson(1),
                    "channel": Bson(1),
                    "t": Bson(-1)
                ])
            );
            // eid index: fast cursor lookups for eid-based pagination
            collection.createIndex(
                Bson([
                    "serverId": Bson(1),
                    "networkId": Bson(1),
                    "channel": Bson(1),
                    "eid": Bson(-1)
                ])
            );
        } catch (Exception e) {
            logWarn("Failed to create messages compound index: %s", e.msg);
        }
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

    /// Append a compact message JSON to permanent storage. Called from
    /// the event processor for every event the engine sees.
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
            collection.insertOne(Bson(jdoc));
        } catch (Exception e) {
            logDebug("Mongo insert (probably duplicate): %s", e.msg);
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

    /**
     * IRCv3 CHATHISTORY-style window query (used by the bouncer).
     *
     * Returns up to `count` chat rows with `afterTs < t < beforeTs`
     * (either bound 0 = unbounded), taken from the newest end of the
     * window (`fromNewest`, for LATEST/BEFORE) or the oldest end (AFTER).
     * Always oldest-first. Only PRIVMSG/NOTICE rows count towards `count`
     * (the `phase` filter is still the caller's job).
     */
    Json[] getWindow(string serverId, string networkId, string channel,
                     long afterTs, long beforeTs, int count, bool fromNewest) @trusted {
        channel = normalizeChannel(channel);
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        Bson filter = serverId.length > 0
            ? Bson(["serverId": Bson(serverId), "networkId": Bson(networkId), "channel": Bson(channel)])
            : Bson(["networkId": Bson(networkId), "channel": Bson(channel)]);
        if (afterTs > 0 || beforeTs > 0) {
            Bson range = Bson.emptyObject;
            if (afterTs > 0) range["$gt"] = Bson(afterTs);
            if (beforeTs > 0) range["$lt"] = Bson(beforeTs);
            filter["t"] = range;
        }
        // `$regex` operator form: a bare BsonRegex value in a top-level
        // filter field matched nothing through vibe.d 0.10.3 in practice.
        filter["payload"] = Bson(["$regex": Bson(CHAT_PAYLOAD_RE)]);
        if (fromNewest) return readPayloads(filter, count);

        FindOptions options;
        options.sort = Bson(["t": Bson(1)]);
        options.limit = cast(long) count;
        Json[] out_;
        foreach (doc; collection.find(filter, options)) {
            const p = doc["payload"];
            if (p.type != Bson.Type.string) continue;
            try out_ ~= parseJsonString(p.get!string);
            catch (Exception e) logWarn("Failed to parse stored message payload: %s", e.msg);
        }
        return out_;
    }

    /// Timestamp (unix ms) of the row with `msgid` in a buffer, or 0 when unknown.
    long timestampOfMsgid(string serverId, string networkId, string channel, string msgid) @trusted {
        channel = normalizeChannel(channel);
        Bson filter = serverId.length > 0
            ? Bson(["serverId": Bson(serverId), "networkId": Bson(networkId), "channel": Bson(channel), "msgid": Bson(msgid)])
            : Bson(["networkId": Bson(networkId), "channel": Bson(channel), "msgid": Bson(msgid)]);
        auto doc = collection.findOne(filter);
        return doc.isNull ? 0 : readBsonTimestamp(doc["t"]);
    }

    /// Timestamp (unix ms) of the newest chat row of a buffer inside
    /// `afterTs < t < beforeTs` (0 = unbounded), or 0 when there is none.
    /// Backs CHATHISTORY TARGETS.
    long latestTimestamp(string serverId, string networkId, string channel,
                         long afterTs, long beforeTs) @trusted {
        auto rows = getWindow(serverId, networkId, channel, afterTs, beforeTs, 1, true);
        foreach (ev; rows) {
            if (ev.type != Json.Type.object) continue;
            if (auto t = "t" in ev) if (t.type == Json.Type.int_) return t.get!long;
        }
        return 0;
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
