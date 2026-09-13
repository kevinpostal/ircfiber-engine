module ircfiber.storage.buffer;

import std.array;
import std.algorithm;
import std.conv;
import std.utf;

import vibe.core.log;
import vibe.data.json;
import vibe.db.redis.redis;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : normalizeChannelName;
import ircfiber.storage.redis : RedisStorage;

/**
 * Sanitize a string to valid UTF-8. Valid UTF-8 sequences pass through
 * unchanged. Single-byte sequences that are not valid UTF-8 lead bytes
 * are remapped through CP437 (Code Page 437), the standard encoding for
 * IRC ASCII art and box-drawing characters. Multi-byte sequences that
 * start with a valid lead byte but contain an invalid continuation byte
 * still produce U+FFFD — those are genuinely malformed and rare in IRC.
 *
 * IRC is a byte protocol — servers may send CP437, ISO-8859-1, or
 * UTF-8. This function reconciles all three into valid D strings.
 */
string sanitizeUtf8(string input) @safe {
    if (input.length == 0) return input;

    // CP437 → Unicode mapping for bytes 0x80–0xFF. IRC ASCII art
    // (box-drawing, blocks, shading) lives in this range.
    static immutable dchar[128] CP437 = [
        // 0x80
        '\u00C7','\u00FC','\u00E9','\u00E2','\u00E4','\u00E0','\u00E5','\u00E7',
        '\u00EA','\u00EB','\u00E8','\u00EF','\u00EE','\u00EC','\u00C4','\u00C5',
        // 0x90
        '\u00C9','\u00E6','\u00C6','\u00F4','\u00F6','\u00F2','\u00FB','\u00F9',
        '\u00FF','\u00D6','\u00DC','\u00A2','\u00A3','\u00A5','\u20A7','\u0192',
        // 0xA0
        '\u00E1','\u00ED','\u00F3','\u00FA','\u00F1','\u00D1','\u00AA','\u00BA',
        '\u00BF','\u2310','\u00AC','\u00BD','\u00BC','\u00A1','\u00AB','\u00BB',
        // 0xB0
        '\u2591','\u2592','\u2593','\u2502','\u2524','\u2561','\u2562','\u2556',
        '\u2555','\u2563','\u2551','\u2557','\u255D','\u255C','\u255B','\u2510',
        // 0xC0
        '\u2514','\u2534','\u252C','\u251C','\u2500','\u253C','\u255E','\u255F',
        '\u255A','\u2554','\u2569','\u2566','\u2560','\u2550','\u256C','\u2567',
        // 0xD0
        '\u2568','\u2564','\u2565','\u2559','\u2558','\u2552','\u2553','\u256B',
        '\u256A','\u2518','\u250C','\u2588','\u2584','\u258C','\u2590','\u2580',
        // 0xE0
        '\u03B1','\u00DF','\u0393','\u03C0','\u03A3','\u03C3','\u00B5','\u03C4',
        '\u03A6','\u0398','\u03A9','\u03B4','\u221E','\u03C6','\u03B5','\u2229',
        // 0xF0
        '\u2261','\u00B1','\u2265','\u2264','\u2320','\u2321','\u00F7','\u2248',
        '\u00B0','\u2219','\u00B7','\u221A','\u207F','\u00B2','\u25A0','\u00A0',
    ];

    char[] result;
    result.reserve(input.length);
    size_t i = 0;
    while (i < input.length) {
        try {
            auto d = decode(input, i);
            encode(result, d);
        } catch (Exception e) {
            // Single-byte fallback: map the raw byte through CP437.
            // This handles IRC servers that send Latin-1/CP437 bytes
            // (e.g. ASCII-art block/box-drawing characters) without
            // a negotiated UTF-8 capability.
            ubyte b = cast(ubyte)input[i];
            if (b >= 0x80) {
                encode(result, CP437[b - 0x80]);
            } else {
                result ~= '\uFFFD';
            }
            i++;
        }
    }
    return () @trusted { return cast(string)result; } ();
}

/**
 * Decentralized Buffer Manager
 * 
 * All buffer keys are namespaced by server ID to prevent collision:
 * scrollback:<serverId>:<networkId>:<channel>
 * 
 * This is the critical fix for the IRCCloud 2020 data leak vulnerability.
 * Without server namespacing, buffer IDs from different servers collide
 * in shared Redis storage, causing cross-user log leakage.
 */
final class BufferManager {
    private {
        RedisStorage redis;
        enum MAX_SCROLLBACK = 5000;
        enum KEY_PREFIX = "scrollback:";
        enum TTL_DAYS = 30;
        enum UNREAD_CHUNK = 100;      // LRANGE slice per round trip
        enum UNREAD_MAX_SCAN = 1000;  // hard cap on rows scanned per buffer
        static immutable string[] UNREAD_COMMANDS = ["PRIVMSG", "NOTICE", "INVITE", "WALLOPS"];
        // Dedup-set key namespace: `dedup:<networkId>:<channel>`.
        //
        // Each buffer has a paired Redis SET holding the dedup key (msgid
        // or content hash) of every message stored for it. SADD returns 1
        // for a new key and 0 for an existing one — that is the check.
        //
        // Deliberately NOT namespaced by serverId, unlike the scrollback
        // list. networkId is a UUID, so there is no collision to defend
        // against, and a server segment made the set per-engine: after a
        // reassignment or failover the new engine started with an empty
        // set and re-published every event it had already seen — to the
        // live WebSocket stream and to Mongo, both of which are
        // network-scoped, so the client saw duplicate rows. The old
        // `dedup:<serverId>:<networkId>:<channel>` sets are adopted once
        // per buffer via RENAMENX (see adoptServerDedupSet) and otherwise
        // expire on their own TTL.
        enum DEDUP_PREFIX = "dedup:";
        enum DEDUP_MAX = 10_000;
        enum DEDUP_TTL_SECS = 30 * 86_400;  // 30 days, same as scrollback
    }

    /// Buffers whose legacy server-scoped dedup set has already been
    /// considered for adoption in this process. Keyed by the new
    /// network-scoped key.
    private bool[string] dedupAdopted;

    /// Creates a new buffer manager.
    this(RedisStorage redisStorage) {
        this.redis = redisStorage;
    }

    /**
     * Append message to namespaced buffer.
     * 
     * Precondition: serverId is non-empty.
     * Postcondition: Message is stored in server-namespaced key.
     */
    /// Normalize channel name via the canonical helper in
    /// ircfiber.models.network so Redis buffer keys, Mongo message
    /// keys, and the in-memory channel lists all agree.
    private alias normalizeChannel = ircfiber.models.network.normalizeChannelName;

    /// Appends a message to the server-namespaced buffer.
    void appendMessage(string serverId, string networkId, string channel, Json message) @trusted {
        if (serverId.length == 0) {
            logError("appendMessage: serverId is empty, cannot namespace buffer");
            return;
        }
        
        channel = normalizeChannel(channel);
        auto key = KEY_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ channel;
        auto db = redis.getDb();
        auto msgStr = message.toString();

        db.lpush(key, msgStr);
        db.ltrim(key, 0, MAX_SCROLLBACK - 1);
        db.expire(key, 86_400 * TTL_DAYS);
    }

    /**
     * Filter and collect messages from a Redis list key.
     *
     * Supports two filtering strategies:
     * - Timestamp-based (before / after): skips messages whose timestamp
     *   falls at/after `before` or at/before `after`. Used when no
     *   msgid cursor is available.
     * - Index-based (beforeIdx): skips messages at or before the given
     *   index in the Redis list. Used when a msgid cursor was resolved
     *   to a specific position, avoiding false positives from messages
     *   that share a similar timestamp but belong to the same batch
     *   (e.g. 353 NAMES / 366 ENDOFNAMES arriving just before a JOIN).
     */
    /// Commands the chat UI cannot render (mirrors the frontend's
    /// `isSkippedCommand` list). Reading them back from a channel's
    /// scrollback only pushes the user's real messages out of the
    /// visible window — a busy channel whose history is dominated by
    /// WHO 315 / NAMES 353 / TAGMSG rows would otherwise render as
    /// "a few messages + Load more backlog…" even though the full
    /// conversation is sitting in Redis. The server log (`_server`)
    /// is exempt: its timeline renders numerics/MOTD, so callers pass
    /// filterNoise=false for it.
    static bool isScrollbackNoiseCommand(string cmd) @safe {
        static immutable string[] NOISE = [
            // WHO / WHOIS / NAMES / TOPIC / MOTD / ban-list chains
            "315", "352", "332", "333", "353", "354", "366", "367", "368",
            "376", "422",
            // WHOIS replies
            "311", "312", "313", "317", "318", "319", "330",
            // misc noise the chat UI never shows
            "301", "671", "401", "PONG", "TAGMSG", "QUIT", "you_nickchange",
            // Replies to the MODE #chan / ISON probes every bouncer client
            // fires on attach (324 RPL_CHANNELMODEIS, 329 RPL_CREATIONTIME,
            // 303 RPL_ISON): rendered as blank rows otherwise.
            "324", "329", "303",
        ];
        import std.algorithm : canFind;
        return NOISE.canFind(cmd);
    }

    private Json[] _getRecentFiltered(string key, long count, long before, long after,
                                      long beforeIdx = -1, bool filterNoise = false) @trusted {
        auto db = redis.getDb();
        Json[] messages;
        auto results = db.lrange!(ubyte[])(key, 0, MAX_SCROLLBACK - 1);
        long idx;
        foreach (raw; results) {
            const curIdx = idx++;
            string r;
            try {
                r = () @trusted { return cast(string)raw.idup; } ();
                r = sanitizeUtf8(r);
            } catch (Exception e) {
                logWarn("Invalid UTF-8 in scrollback entry, skipping: %s", e.msg);
                continue;
            }
            try {
                auto msg = parseJson(r);
                if (beforeIdx >= 0) {
                    if (curIdx <= beforeIdx) continue;
                } else if (before > 0 && "t" in msg) {
                    const ts = msg["t"].get!long;
                    if (ts >= before) continue;
                }
                if (after > 0 && "t" in msg) {
                    const ts = msg["t"].get!long;
                    if (ts <= after) continue;
                }
                if (filterNoise && "c" in msg) {
                    const cmd = msg["c"].get!string;
                    if (isScrollbackNoiseCommand(cmd)) continue;
                }
                messages ~= msg;
                if (messages.length >= count) break;
            } catch (Exception e) {
                logWarn("Failed to parse scrollback message: %s", e.msg);
            }
        }
        messages.reverse;
        return messages;
    }

    /**
     * Get recent messages from namespaced buffer.
     * 
     * Precondition: serverId is non-empty.
     * Returns: Messages from server-specific buffer.
     */
    Json[] getRecent(string serverId, string networkId, string channel,
                     long count = 50, long before = 0, long after = 0,
                     long beforeIdx = -1) @trusted {
        if (serverId.length == 0) {
            logError("getRecent: serverId is empty");
            return [];
        }
        auto norm = normalizeChannel(channel);
        const filterNoise = norm != "_server";
        auto key = KEY_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ norm;
        auto res = _getRecentFiltered(key, count, before, after, beforeIdx, filterNoise);
        if (res.length == 0 && norm.length > 0 && norm[0] != '#' && norm[0] != '&' && norm[0] != '+' && norm[0] != '!') {
            import std.uni : toLower;
            auto legacyKey = KEY_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ ("#" ~ norm.toLower());
            auto legacyRes = _getRecentFiltered(legacyKey, count, before, after, beforeIdx, filterNoise);
            if (legacyRes.length > 0) return legacyRes;
        }
        return res;
    }

    /// Chat entries (PRIVMSG / NOTICE / INVITE / WALLOPS) strictly newer than
    /// `afterTs` (ms), oldest-first, at most `limit` — the NEWEST `limit` when
    /// more exist. Feeds the connect-time sync's per-buffer unread tail
    /// (IRCCloud OOB backlog). Bounded newest-first scan in UNREAD_CHUNK
    /// slices: a slice with no newer row ends the scan (a CHATHISTORY
    /// backfill batch of older rows can sit above live traffic, so the
    /// first old row must not), as does UNREAD_MAX_SCAN. Empty `serverId`
    /// reads the legacy non-namespaced key. Never throws on bad rows.
    Json[] getUnreadTail(string serverId, string networkId, string channel, long afterTs, long limit) @trusted {
        import std.algorithm : canFind;
        auto norm = normalizeChannel(channel);
        auto key = serverId.length
            ? KEY_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ norm
            : KEY_PREFIX ~ networkId ~ ":" ~ norm;
        auto db = redis.getDb();
        Json[] messages;
        for (long start = 0; start < UNREAD_MAX_SCAN && messages.length < limit; start += UNREAD_CHUNK) {
            auto results = db.lrange!(ubyte[])(key, start, start + UNREAD_CHUNK - 1);
            long rows = 0;
            bool sawNewer = false;
            foreach (raw; results) {
                rows++;
                Json msg;
                try {
                    auto r = sanitizeUtf8(() @trusted { return cast(string) raw.idup; } ());
                    msg = parseJson(r);
                } catch (Exception e) { continue; }
                auto tp = "t" in msg;
                if (tp is null || tp.type != Json.Type.int_ || tp.get!long <= afterTs) continue;
                sawNewer = true;
                auto cp = "c" in msg;
                if (cp is null || cp.type != Json.Type.string || !UNREAD_COMMANDS.canFind(cp.get!string)) continue;
                messages ~= msg;
                if (messages.length >= limit) break;
            }
            if (!sawNewer || rows < UNREAD_CHUNK) break;
        }
        messages.reverse;
        return messages;
    }

    /**
     * Get recent messages from namespaced buffer with msgid cursor support.
     * 
     * Resolves beforeMsgid/afterMsgid to timestamps by scanning the buffer,
     * then delegates to timestamp-based filtering.
     */
    Json[] getRecent(string serverId, string networkId, string channel,
                     long count, long before, long after,
                     string beforeMsgid, string afterMsgid) @trusted {
        if (serverId.length == 0) {
            logError("getRecent: serverId is empty");
            return [];
        }

        long beforeTs = before;
        long afterTs = after;
        long beforeIdx = -1;

        if (beforeMsgid.length > 0 || afterMsgid.length > 0) {
            channel = normalizeChannel(channel);
            auto key = KEY_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ channel;
            auto db = redis.getDb();
            auto results = db.lrange!(ubyte[])(key, 0, MAX_SCROLLBACK - 1);
            long idx;
            foreach (raw; results) {
                const curIdx = idx++;
                string r;
                try {
                    r = () @trusted { return cast(string)raw.idup; } ();
                    r = sanitizeUtf8(r);
                } catch (Exception e) { continue; }
                try {
                    auto msg = parseJson(r);
                    if (msg.type == Json.Type.object && "m" in msg) {
                        const msgMsgid = msg["m"].get!string;
                        if (beforeMsgid.length > 0 && msgMsgid == beforeMsgid && "t" in msg) {
                            beforeTs = msg["t"].get!long;
                            beforeIdx = curIdx;
                        }
                        if (afterMsgid.length > 0 && msgMsgid == afterMsgid && "t" in msg) {
                            afterTs = msg["t"].get!long;
                        }
                    }
                } catch (Exception e) { continue; }
            }
        }

        if (beforeIdx >= 0) {
            channel = normalizeChannel(channel);
            auto key = KEY_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ channel;
            return _getRecentFiltered(key, count, beforeTs, afterTs, beforeIdx, channel != "_server");
        }
        return getRecent(serverId, networkId, channel, count, beforeTs, afterTs);
    }

    /**
     * Legacy overload: Get recent messages without server namespace.
     * 
     * For backward compatibility with single-server (legacy) mode.
     * Uses non-namespaced key format.
     */
    Json[] getRecent(string networkId, string channel, long count = 50, long before = 0, long after = 0,
                     long beforeIdx = -1) @trusted {
        auto norm = normalizeChannel(channel);
        const filterNoise = norm != "_server";
        auto key = KEY_PREFIX ~ networkId ~ ":" ~ norm;
        auto res = _getRecentFiltered(key, count, before, after, beforeIdx, filterNoise);
        if (res.length == 0 && norm.length > 0 && norm[0] != '#' && norm[0] != '&' && norm[0] != '+' && norm[0] != '!') {
            import std.uni : toLower;
            auto legacyKey = KEY_PREFIX ~ networkId ~ ":" ~ ("#" ~ norm.toLower());
            auto legacyRes = _getRecentFiltered(legacyKey, count, before, after, beforeIdx, filterNoise);
            if (legacyRes.length > 0) return legacyRes;
        }
        return res;
    }

    /**
     * Legacy overload with msgid cursor support.
     */
    Json[] getRecent(string networkId, string channel, long count, long before, long after,
                     string beforeMsgid, string afterMsgid) @trusted {
        long beforeTs = before;
        long afterTs = after;
        long beforeIdx = -1;

        if (beforeMsgid.length > 0 || afterMsgid.length > 0) {
            channel = normalizeChannel(channel);
            auto key = KEY_PREFIX ~ networkId ~ ":" ~ channel;
            auto db = redis.getDb();
            auto results = db.lrange!(ubyte[])(key, 0, MAX_SCROLLBACK - 1);
            long idx;
            foreach (raw; results) {
                const curIdx = idx++;
                string r;
                try {
                    r = () @trusted { return cast(string)raw.idup; } ();
                    r = sanitizeUtf8(r);
                } catch (Exception e) { continue; }
                try {
                    auto msg = parseJson(r);
                    if (msg.type == Json.Type.object && "m" in msg) {
                        const msgMsgid = msg["m"].get!string;
                        if (beforeMsgid.length > 0 && msgMsgid == beforeMsgid && "t" in msg) {
                            beforeTs = msg["t"].get!long;
                            beforeIdx = curIdx;
                        }
                        if (afterMsgid.length > 0 && msgMsgid == afterMsgid && "t" in msg) {
                            afterTs = msg["t"].get!long;
                        }
                    }
                } catch (Exception e) { continue; }
            }
        }

        if (beforeIdx >= 0) {
            channel = normalizeChannel(channel);
            auto key = KEY_PREFIX ~ networkId ~ ":" ~ channel;
            return _getRecentFiltered(key, count, beforeTs, afterTs, beforeIdx, channel != "_server");
        }
        return getRecent(networkId, channel, count, beforeTs, afterTs);
    }

    /**
     * Append IRC event to server-namespaced buffer.
     *
     * This is the primary method called by the event processor.
     * The serverId ensures events are stored in the correct namespace.
     *
     * Dedup is handled by a paired Redis SET (key prefix `dedup:`) that
     * holds the dedup key for every message stored in the scrollback.
     * The dedup key is:
     *   - the `msgid` IRC tag, if the event carries one (covers PRIVMSG,
     *     NOTICE, TAGMSG, JOIN, PART, KICK, etc. on modern servers), OR
     *   - a content hash of (command + channel + sorted params + timestamp)
     *     for numeric replies (332 TOPIC, 333 TOPICWHOTIME, 366 NAMES end,
     *     005 ISUPPORT, etc.) that never carry a msgid.
     *
     * The check is `SADD dedup:<buf> <key>` which atomically returns 1
     * for a new key and 0 for an existing one. Storing the set in Redis
     * (not in-memory) means engine restarts, failovers, and network
     * reassignments between connection servers don't replay duplicates
     * — exactly the kind of edge case that bit us before (332/333
     * re-firing on every reconnect, with no in-memory cache to suppress
     * them after restart).
     *
     * The set is bounded to DEDUP_MAX entries and TTL'd to match the
     * scrollback. When the bound is hit, a sampled trim keeps the most
     * recent half — the cost of briefly re-allowing duplicates on
     * ancient history is much lower than the cost of unbounded growth.
     *
     * Returns `true` when the event was stored and `false` when the dedup
     * set already held it. Callers MUST honour `false`: the event processor
     * used to ignore it and still publish the duplicate to the live
     * WebSocket stream, so a re-emitted event (an IRCv3 batch replayed on
     * rejoin, a roster-driven fan-out that matched twice) rendered as two
     * identical rows that vanished on refresh — the scrollback had one.
     */
    bool appendIRCEvent(IRCRawEvent event, string serverId) @trusted {
        auto msg = Json([
            "network": Json(sanitizeUtf8(event.network)),
            "i": Json(sanitizeUtf8(event.id)),
            "t": Json(event.timestampMs),
            "c": Json(sanitizeUtf8(event.command)),
            "n": Json(sanitizeUtf8(event.nick)),
            "x": Json(sanitizeUtf8(event.text)),
            "ch": Json(sanitizeUtf8(event.channel))
        ]);
        if (event.prefix.length) {
            msg["px"] = Json(sanitizeUtf8(event.prefix));
        }
        auto params = event.getParams();
        if (params.length) {
            auto arr = Json.emptyArray;
            foreach (p; params) arr ~= Json(sanitizeUtf8(p));
            msg["p"] = arr;
        }
        auto msgid = event.getTag("msgid");
        if (msgid.length) {
            msg["m"] = Json(sanitizeUtf8(msgid));
        }
        // Surface labeled_echo and self_echo tags so the frontend can
        // de-dupe optimistic UI without doing string matching on labels.
        auto labeledEcho = event.getTag("labeled_echo");
        if (labeledEcho.length) msg["le"] = Json(labeledEcho);
        auto selfEcho = event.getTag("self_echo");
        if (selfEcho.length) msg["se"] = Json(selfEcho);
        // Mark messages arriving inside a CHATHISTORY batch so the
        // frontend can render them with a "from history" hint if it
        // ever wants to (currently it's used by /api/channels/messages
        // to know which msgs came from the upstream).
        auto batch = event.getTag("batch");
        if (batch.length) msg["batch"] = Json(batch);

        // eid is set by the processor before the event reaches the buffer;
        // it's required for scrollback ordering and stream resume.
        if (event.eid > 0) msg["eid"] = Json(event.eid);
        // Phase tag classifies `_server` buffer events as connection
        // lifecycle steps (queued, connecting, welcome, etc.). Without it
        // the frontend can't render the server log timeline correctly.
        auto phase = event.getTag("phase");
        if (phase.length) msg["phase"] = Json(phase);

        const networkId = event.networkId.length > 0 ? event.networkId : event.network;
        const channel = event.channel.length > 0 ? normalizeChannel(event.channel) : "_server";

        if (hasDedupKey(serverId, networkId, channel, msgid, event, params)) {
            return false;
        }
        appendMessage(serverId, networkId, channel, msg);
        return true;
    }

    /// Network-scoped dedup set key for a buffer. Channel is normalized
    /// so every caller agrees on the name.
    private string dedupSetKey(string networkId, string channel) @trusted {
        return DEDUP_PREFIX ~ networkId ~ ":" ~ normalizeChannel(channel);
    }

    /// One-time, per-buffer adoption of the pre-existing server-scoped
    /// dedup set. Without it the first append after a deploy (or after a
    /// reassignment) faces an empty set and re-stores everything the old
    /// key already knew — a single burst of duplicates, exactly what the
    /// set exists to prevent. RENAMENX moves the set into place only when
    /// the network-scoped key does not exist yet, so it never clobbers
    /// live state; leftovers from other servers keep their own TTL.
    private void adoptServerDedupSet(string serverId, string networkId,
                                     string channel, string dedupKey) @trusted {
        if (serverId.length == 0 || dedupKey in dedupAdopted) return;
        dedupAdopted[dedupKey] = true;
        const legacyKey = DEDUP_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ channel;
        try {
            if (redis.getDb().renameNX(legacyKey, dedupKey))
                logInfo("Adopted server-scoped dedup set %s -> %s", legacyKey, dedupKey);
        } catch (Exception e) {
            // Source missing (the common case) or destination exists.
            logDebug("adoptServerDedupSet: %s", e.msg);
        }
    }

    /// Compute a stable dedup key for an event and check it against
    /// the buffer's Redis dedup set. Returns true if this event is a
    /// duplicate and should be dropped. `serverId` is only used to adopt
    /// the legacy server-scoped set; it is not part of the key.
    private bool hasDedupKey(string serverId, string networkId, string channel,
                             string msgid, IRCRawEvent event, string[] params) @trusted {
        channel = normalizeChannel(channel);
        auto dedupKey = dedupSetKey(networkId, channel);
        adoptServerDedupSet(serverId, networkId, channel, dedupKey);

        string key;
        if (msgid.length > 0) {
            // Preferred path: msgid is globally unique per IRC server.
            key = "m:" ~ msgid;
        } else {
            // Fallback for numeric replies and other messages without
            // msgid. Hash (command, channel, sorted params, timestamp).
            // Sorting params keeps e.g. 353 (NAMES) from a different
            // reordering from looking like a new message, but two 353
            // replies for the same channel really are the same content
            // and will collapse to one.
            // Also include the phase tag so engine-emitted server-log
            // events (tcp_open, info, registering, welcome) that share
            // the same timestamp don't collide and get dropped as dupes.
            // Include the labeled-response label when present so rapid
            // same-text PRIVMSGs (e.g. spamming "a") that share a
            // second-precision timestamp don't collide — each label is a
            // unique UUID and makes the hash distinct.
            // BUGFIX: include nick + text so two PRIVMSGs to the same
            // channel in the same second from different nicks (e.g.
            // !wordle → pyylmao reply <200ms) don't hash-collide via
            // second-precision timestamp and get dropped as dupes. The
            // previous hash was command|channel|timestamp|params only,
            // so "PRIVMSG|#tclmafia|177...000|#tclmafia" was identical
            // for both messages despite different nicks/text. Until refresh
            // the WS live path was deduped, but REST/Mongo fallback
            // re-surfaced it.
            auto phaseKey = event.getTag("phase");
            auto labelKey = event.getTag("label");
            string hashInput = event.command ~ "|" ~ phaseKey;
            if (labelKey.length > 0) hashInput ~= "|" ~ labelKey;
            // Include nick + text to distinguish distinct PRIVMSGs that
            // share channel/params/timestamp (fast bot replies).
            hashInput ~= "|" ~ event.nick ~ "|" ~ event.text;
            key = "h:" ~ contentHash(hashInput, channel, event.timestampMs, params);
        }
        auto db = redis.getDb();
        auto added = db.sadd(dedupKey, key);
        db.expire(dedupKey, DEDUP_TTL_SECS);

        return added == 0;
    }

    /// Stable, low-collision hash for messages without msgid.
    /// Uses FNV-1a (64-bit) — simple, fast, no crypto dep needed.
    /// Collisions only ever cause one extra message to be dropped,
    /// which is far better than the duplicates we get without it.
    private string contentHash(string command, string channel, long timestamp, string[] params) @trusted {
        // Build a stable string: command|channel|timestamp|sorted-params
        auto sortedParams = params.dup;
        sortedParams.sort();
        const combined = command ~ "|" ~ channel ~ "|" ~ timestamp.to!string ~ "|" ~ sortedParams.join("\x1f");

        // FNV-1a (64-bit), offset basis = 14695981039346656037, prime = 1099511628211
        auto bytes = cast(ubyte[])combined;
        ulong hash = 14_695_981_039_346_656_037UL;
        foreach (b; bytes) {
            hash ^= b;
            hash *= 1_099_511_628_211UL;
        }
        import std.format : format;
        return format!"%016x"(hash);
    }

    /**
     * Clear a single scrollback buffer (server log or channel) and its
     * paired dedup SET.
     *
     * Powers the user-facing "Clear backlog" affordance. Unlike the
     * `clearedAt` localStorage flag in the frontend (which only hides
     * old messages client-side and is reversible via "Load more
     * backlog…"), this actually removes the stored scrollback from
     * Redis so the next sync / CHATHISTORY fetch returns an empty
     * buffer.
     *
     * Precondition: serverId / networkId / buffer are non-empty.
     */
    void clearBuffer(string serverId, string networkId, string buffer) @trusted {
        if (serverId.length == 0 || networkId.length == 0 || buffer.length == 0) {
            logWarn("clearBuffer: refusing empty arg (server=%s net=%s buf=%s)",
                serverId, networkId, buffer);
            return;
        }
        buffer = normalizeChannel(buffer);
        auto db = redis.getDb();
        auto scrollbackKey = KEY_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ buffer;
        // Both dedup spellings: the network-scoped key in use now, plus a
        // leftover server-scoped one this engine may not have adopted yet.
        // Keeping either would make "Clear backlog" permanent for every
        // message it dropped — the buffer refills only with events whose
        // dedup key is not already in the set.
        auto dedupKey = dedupSetKey(networkId, buffer);
        auto legacyDedupKey = DEDUP_PREFIX ~ serverId ~ ":" ~ networkId ~ ":" ~ buffer;
        // DEL is idempotent — missing keys just return 0.
        auto deleted = db.del(scrollbackKey, dedupKey, legacyDedupKey);
        dedupAdopted.remove(dedupKey);
        logInfo("Cleared buffer %s:%s:%s from Redis (keys deleted: %s)",
            serverId, networkId, buffer, deleted.to!string);
    }

    /**
     * Legacy single-arg variant for non-namespaced (single-server) mode.
     */
    void clearBuffer(string networkId, string buffer) @trusted {
        if (networkId.length == 0 || buffer.length == 0) {
            logWarn("clearBuffer: refusing empty arg (net=%s buf=%s)",
                networkId, buffer);
            return;
        }
        buffer = normalizeChannel(buffer);
        auto db = redis.getDb();
        auto scrollbackKey = KEY_PREFIX ~ networkId ~ ":" ~ buffer;
        auto dedupKey = dedupSetKey(networkId, buffer);
        auto deleted = db.del(scrollbackKey, dedupKey);
        dedupAdopted.remove(dedupKey);
        logInfo("Cleared legacy buffer %s:%s from Redis (keys deleted: %s)",
            networkId, buffer, deleted.to!string);
    }

    /**
     * Rename a buffer's Redis keys (scrollback list + dedup set) after a
     * NICK-follow, so history survives the rename across reloads.
     * Collision-safe: RENAMENX refuses when the destination exists, in
     * which case both histories are kept and nothing is clobbered.
     * Best-effort: missing source keys are a no-op. Migrates both the
     * namespaced (`scrollback:<srv>:<net>:<buf>`) and legacy
     * (`scrollback:<net>:<buf>`) variants. RENAME preserves TTL.
     * Returns true when at least one key moved.
     */
    bool renameBuffer(string serverId, string networkId, string oldBuf, string newBuf) @trusted {
        oldBuf = normalizeChannel(oldBuf);
        newBuf = normalizeChannel(newBuf);
        if (networkId.length == 0 || oldBuf.length == 0 || newBuf.length == 0
            || oldBuf == newBuf)
            return false;
        auto db = redis.getDb();
        bool moved = false;
        static immutable string[2] prefixes = [KEY_PREFIX, DEDUP_PREFIX];
        foreach (prefix; prefixes) {
            // Namespaced variant.
            if (serverId.length > 0) {
                try {
                    if (db.renameNX(prefix ~ serverId ~ ":" ~ networkId ~ ":" ~ oldBuf,
                                    prefix ~ serverId ~ ":" ~ networkId ~ ":" ~ newBuf))
                        moved = true;
                } catch (Exception e) {
                    logDebug("renameBuffer: %s", e.msg);
                }
            }
            // Legacy variant (no server segment).
            try {
                if (db.renameNX(prefix ~ networkId ~ ":" ~ oldBuf,
                                prefix ~ networkId ~ ":" ~ newBuf))
                    moved = true;
            } catch (Exception e) {
                logDebug("renameBuffer: %s", e.msg);
            }
        }
        if (moved) {
            // The adoption guard is keyed by destination; both names just
            // changed identity, so let a fresh adoption run if needed.
            dedupAdopted.remove(dedupSetKey(networkId, oldBuf));
            dedupAdopted.remove(dedupSetKey(networkId, newBuf));
            logInfo("Renamed buffer %s:%s %s -> %s", serverId, networkId, oldBuf, newBuf);
        }
        return moved;
    }

    /**
     * Clear ALL buffers for a network — every channel and query, plus the
     * server log and the paired dedup sets.
     *
     * Called when a network is deleted (by the gateway's delete route and
     * again by the engine after teardown, since the QUIT/ERROR farewell
     * events are persisted *after* the gateway's clear). This used to drop
     * only the `_server` key and leave the channel scrollback on its TTL,
     * which is how a deleted network stayed readable at
     * `/irc/<name>/channel/%23chan` after the sidebar had dropped it.
     *
     * Keys are enumerated by pattern because the channel names are not
     * known here. `KEYS` (not `SCAN`) deliberately: one-shot delete path,
     * pattern anchored on a UUID, and a SCAN cursor reply is a nested
     * multi-bulk that desynchronises the pooled connection when read flat.
     */
    void clearNetworkBuffers(string serverId, string networkId) @trusted {
        if (serverId.length == 0 || networkId.length == 0) {
            logWarn("clearNetworkBuffers: refusing empty arg (server=%s net=%s)",
                serverId, networkId);
            return;
        }
        // The scrollback list is server-namespaced but the dedup sets are
        // network-scoped, so a network delete needs both patterns. Leaving
        // the dedup set behind would make a re-added network inherit it:
        // an empty scrollback whose every replayed event is dropped as a
        // duplicate.
        const deleted = deleteByPrefix(serverId ~ ":" ~ networkId ~ ":")
            + deleteMatching(DEDUP_PREFIX ~ networkId ~ ":*");
        foreach (k; dedupAdopted.keys)
            if (k.startsWith(DEDUP_PREFIX ~ networkId ~ ":")) dedupAdopted.remove(k);
        logInfo("Cleared %s buffer key(s) for network %s on server %s",
            deleted.to!string, networkId, serverId);
    }

    /**
     * Legacy overload for clearing buffers without server namespace.
     */
    void clearNetworkBuffers(string networkId) @trusted {
        if (networkId.length == 0) {
            logWarn("clearNetworkBuffers: refusing empty networkId");
            return;
        }
        const deleted = deleteByPrefix(networkId ~ ":");
        logInfo("Cleared %s legacy buffer key(s) for network %s",
            deleted.to!string, networkId);
    }

    /// Deletes every scrollback + dedup key whose name starts with
    /// `<prefix>` (already including the trailing colon). Returns the
    /// number of keys removed.
    private long deleteByPrefix(string prefix) @trusted {
        long deleted = 0;
        foreach (ns; [KEY_PREFIX, DEDUP_PREFIX])
            deleted += deleteMatching(ns ~ prefix ~ "*");
        return deleted;
    }

    /// Deletes every key matching a Redis glob. Returns the number removed.
    private long deleteMatching(string pattern) @trusted {
        auto db = redis.getDb();
        long deleted = 0;
        string[] keys;
        try {
            foreach (k; db.keys(pattern))
                keys ~= () @trusted { return cast(string) k.idup; }();
        } catch (Exception e) {
            logWarn("deleteMatching: listing %s failed: %s", pattern, e.msg);
            return 0;
        }
        foreach (key; keys) {
            try deleted += db.del(key);
            catch (Exception e) logWarn("deleteMatching: DEL %s failed: %s", key, e.msg);
        }
        return deleted;
    }

    /**
     * Legacy method for backward compatibility (non-decentralized mode).
     *
     * Warning: This uses the non-namespaced key format and should only
     * be used in single-server (legacy) mode.
     */
    bool appendIRCEvent(IRCRawEvent event) @trusted {
        auto msg = Json([
            "network": Json(sanitizeUtf8(event.network)),
            "i": Json(sanitizeUtf8(event.id)),
            "t": Json(event.timestampMs),
            "c": Json(sanitizeUtf8(event.command)),
            "n": Json(sanitizeUtf8(event.nick)),
            "x": Json(sanitizeUtf8(event.text)),
            "ch": Json(sanitizeUtf8(event.channel))
        ]);
        auto params = event.getParams();
        if (params.length) {
            auto arr = Json.emptyArray;
            foreach (p; params) arr ~= Json(sanitizeUtf8(p));
            msg["p"] = arr;
        }
        auto msgid = event.getTag("msgid");
        if (msgid.length) {
            msg["m"] = Json(sanitizeUtf8(msgid));
        }

        const networkId = event.networkId.length > 0 ? event.networkId : event.network;
        const channel = event.channel.length > 0 ? normalizeChannel(event.channel) : "_server";

        // Legacy path (no serverId) — shares the network-scoped dedup set
        // with the namespaced path, so restarts and mode switches don't
        // replay duplicates. This used to be a no-op: hasDedupKey bailed
        // out whenever serverId was empty, which is every call here.
        if (hasDedupKey("", networkId, channel, msgid, event, params)) return false;

        auto key = KEY_PREFIX ~ networkId ~ ":" ~ channel;
        auto db = redis.getDb();
        auto msgStr = msg.toString();

        db.lpush(key, msgStr);
        db.ltrim(key, 0, MAX_SCROLLBACK - 1);
        db.expire(key, 86_400 * TTL_DAYS);
        return true;
    }
}

@("BufferManager.getUnreadTail returns newest chat rows after lastSeen, oldest-first, capped")
unittest {
    // Requires a local Redis on 127.0.0.1:6379; skipped when unavailable.
    import std.uuid : randomUUID;
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
    } catch (Exception e) {
        logWarn("Skipping BufferManager.getUnreadTail test: Redis unavailable (%s)", e.msg);
        return;
    }
    const netId = "netT-" ~ randomUUID().toString();
    const key = "scrollback:srvT:" ~ netId ~ ":#tail";
    const legacyKey = "scrollback:" ~ netId ~ ":#tail";
    void cleanup() {
        try { redis.getDb().del(key); redis.getDb().del(legacyKey); }
        catch (Exception) {}
    }
    cleanup();
    scope (exit) cleanup();

    auto db = redis.getDb();
    // LPUSH oldest first so slice 0 is the newest, as appendMessage does.
    db.lpush(key, `{"t":100,"c":"PRIVMSG","n":"a","x":"old"}`);
    db.lpush(key, `{"t":200,"c":"JOIN","n":"b","x":""}`);
    db.lpush(key, `{"t":300,"c":"PRIVMSG","n":"b","x":"one"}`);
    db.lpush(key, `{"t":400,"c":"NOTICE","n":"c","x":"two"}`);
    db.lpush(key, `{"t":500,"c":"PRIVMSG","n":"d","x":"three"}`);
    db.lpush(legacyKey, `{"t":600,"c":"PRIVMSG","n":"e","x":"legacy"}`);

    auto bm = new BufferManager(redis);

    auto tail = bm.getUnreadTail("srvT", netId, "#tail", 150, 100);
    assert(tail.length == 3);
    assert(tail[0]["x"].get!string == "one");
    assert(tail[1]["x"].get!string == "two");
    assert(tail[2]["x"].get!string == "three");

    auto capped = bm.getUnreadTail("srvT", netId, "#tail", 150, 2);
    assert(capped.length == 2);
    assert(capped[0]["x"].get!string == "two");
    assert(capped[1]["x"].get!string == "three");

    assert(bm.getUnreadTail("srvT", netId, "#tail", 500, 100).length == 0);

    auto legacy = bm.getUnreadTail("", netId, "#tail", 0, 100);
    assert(legacy.length == 1);
    assert(legacy[0]["x"].get!string == "legacy");
}
