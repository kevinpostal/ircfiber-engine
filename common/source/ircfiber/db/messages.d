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
import ircfiber.db.message_search : isSearchChannel, searchMetadata;
import ircfiber.db.history_retention : HistoryRetentionRepository, HistoryRetentionState,
    HistoryPolicy;
import ircfiber.db.history_suppression : HistorySuppressionRepository;
import ircfiber.db.history_visibility : HistoryReadScope, historyReadScope;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : normalizeChannelName, BncPlaybackCutoff,
    BncPlaybackConsumption, IrcCaseMapping, foldIrcCaseChar, ircCaseEquals;
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
        networks.insertOne(Bson(["id": Bson(id), "userId": Bson(owner), "nick": Bson("Preserve"),
            "archiveScopeVersion": Bson(1), "archiveServers": Bson([Bson("archive-gate-original")])]));
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

/// A BNC view over the archive; never a retention or read-marker policy.
struct BncArchiveFilter {
    int limit = -1;
    BncPlaybackCutoff category, target;
    BncPlaybackConsumption consumed;

    bool allows(long time, long eid) const @safe pure nothrow @nogc {
        return limit != 0 && category.allows(time, eid) && target.allows(time, eid)
            && consumed.allows(time, eid);
    }
}

/// Durable insert/duplicate, or an intentionally fenced/expired event.
enum ArchiveWriteResult { inserted, alreadyPersisted, expiredDiscard }

/// Operation-scoped admission, reusable for bounded backfill batches. Fields
/// are private so callers cannot manufacture an owner or relax a policy floor.
struct ArchiveWriteScope {
    private string serverId, networkId, ownerId;
    private bool deleted;
    private HistoryRetentionState installation;
    private HistoryPolicy policy;
    private long nowMs;

    bool isDeleted() const pure nothrow @safe { return deleted; }
}

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

/// Legacy search age before operator cutover. Readers never create or modify TTL.
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

/// Whether a `messages.channel` value is a private conversation (a nick),
/// as opposed to a channel, the `_server` log or a server-name pseudo buffer.
/// Legacy TTL compatibility omits `tsAt` for private conversations. Active
/// account retention includes them in both the age and logical-byte allowance.
bool isDirectBuffer(string channel) @safe pure nothrow @nogc {
    if (channel.length == 0 || channel == "_server") return false;
    if (channel[0] == '#' || channel[0] == '&') return false;
    foreach (char c; channel) {
        if (c <= 0x20 || c == 0x7F || c == '.' || c == ':' || c == '*' || c == ',') return false;
    }
    return true;
}

@("isDirectBuffer: nicks yes; channels, _server, server names, wildcards no")
@safe pure nothrow @nogc unittest {
    assert(isDirectBuffer("Boogie1488") && isDirectBuffer("a[b]\\c`d^e|f{g}h-i_j"));
    assert(!isDirectBuffer("") && !isDirectBuffer("_server") && !isDirectBuffer("#dlang") && !isDirectBuffer("&local"));
    assert(!isDirectBuffer("irc.example.org") && !isDirectBuffer("*targets") && !isDirectBuffer("two words"));
    assert(!isDirectBuffer("a,b") && !isDirectBuffer("fe80::1"));
}

/**
 * Rolling message storage (IRCCloud-style).
 *
 * MongoDB stores the durable compact archive, including DMs and protocol
 * records. Until account-policy cutover, non-DMs retain the legacy `tsAt`
 * date for the installed TTL. Active policy instead applies account-wide
 * history floors to the original event timestamp. Redis is a separate hot
 * cache, not part of the logical Mongo allowance.
 *
 * Each document is indexed by (serverId, networkId, channel, t, msgid)
 * for efficient paginated queries. The full compact JSON payload is
 * stored in the `payload` field as a JSON string and returned verbatim
 * by the API.
 */
final class MessageRepository {
    private MongoCollection collection;
    private RedisStorage maintenanceRedis;
    private long lastDirtyWarningMs;
    enum historyDirtyKey = "irc:maint:history:dirty";

    private static HistoryReadScope resolveHistoryView(string networkId, HistoryReadScope* view) {
        auto resolved = view is null ? historyReadScope(networkId) : *view;
        import std.exception : enforce;
        enforce(resolved.networkId() == networkId, "History scope does not match network");
        return resolved;
    }

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
    this(RedisStorage maintenanceRedis = null) {
        this.maintenanceRedis = maintenanceRedis;
        collection = AppMongoConnection.getDb()["messages"];
        ensureIndexes();
    }

    /// Admin-only provisioning, never performed with worker/chat credentials.
    /// A single createIndexes lets Mongo build source indexes in one scan.
    static void ensureSearchIndexes() @trusted {
        Bson[] indexes;
        void add(string name, string[] fields, Bson partial = Bson.init) {
            auto definition = Bson(["name": Bson(name), "key": indexKeys(fields)]);
            if (partial.type == Bson.Type.object)
                definition["partialFilterExpression"] = partial;
            indexes ~= definition;
        }
        add("message_search_pending", ["searchPending", "_id"], Bson(["searchPending": Bson(true)]));
        add("message_search_alias", ["networkId", "channel", "searchAliases"],
            Bson(["searchAliases": Bson(["$exists": Bson(true)])]));
        add("message_search_target", ["networkId", "channel", "searchTarget", "t", "eid", "_id"],
            Bson(["searchTarget": Bson(["$exists": Bson(true)])]));
        add("message_search_version", ["networkId", "channel", "searchVersion"]);
        // A version-leading index also serves the final global backfill gate;
        // the scoped index above alone requires a full archive scan.
        add("message_search_build_version", ["searchVersion", "_id"]);
        add("message_search_pending_time", ["t"], Bson(["searchPending": Bson(true)]));
        auto command = Bson.emptyObject;
        command["createIndexes"] = Bson("messages");
        command["indexes"] = Bson(indexes);
        AppMongoConnection.runCommand(command);
        // Ownership probes must remain indexed as the account count grows.
        auto ownership = Bson.emptyObject;
        ownership["createIndexes"] = Bson("networks");
        ownership["indexes"] = Bson([Bson([
            "name": Bson("message_search_network_owner"),
            "key": indexKeys(["id", "userId"])])]);
        AppMongoConnection.runCommand(ownership);
    }

    /// Add query indexes only. Retention DDL belongs to the operator migration.
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
    /// Read once per operation/bounded network batch, not once per event.
    ArchiveWriteScope admitArchiveWrite(string serverId, string networkId,
            string expectedOwner = "", long nowMs = 0) @trusted {
        import ircfiber.archive_protocol : isCanonicalArchiveOperationId;
        if (!serverId.length || serverId.length > 128
                || !isCanonicalArchiveOperationId(networkId)
                || (expectedOwner.length && !isCanonicalArchiveOperationId(expectedOwner)))
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        ArchiveWriteScope admission;
        admission.serverId = serverId; admission.networkId = networkId;
        import std.datetime : SysTime, DateTime, UTC;
        const epoch = SysTime(DateTime(1970, 1, 1), UTC());
        admission.nowMs = nowMs != 0 ? nowMs : (Clock.currTime - epoch).total!"msecs";
        if (admission.nowMs <= 0)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        const catalog = archiveNetworkCatalog(networkId);
        const fencedOwner = historyNetworkFenceOwner(networkId);
        if (!catalog.isNull) {
            if (catalog["userId"].type != Bson.Type.string
                    || !isCanonicalArchiveOperationId(catalog["userId"].get!string))
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
            admission.ownerId = catalog["userId"].get!string;
            if ((expectedOwner.length && expectedOwner != admission.ownerId)
                    || (fencedOwner.length && fencedOwner != admission.ownerId))
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
        } else {
            if (!fencedOwner.length)
                throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
            admission.ownerId = fencedOwner;
        }
        if (expectedOwner.length && expectedOwner != admission.ownerId)
            throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
        if (fencedOwner.length) {
            admission.deleted = true;
            return admission;
        }
        if (catalog.tryIndex("archiveScopeVersion").isNull && catalog.tryIndex("archiveServers").isNull)
            throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
        if (!archiveIntegerEquals(catalog["archiveScopeVersion"], 1)
                || catalog["archiveServers"].type != Bson.Type.array
                || !catalog["archiveServers"].length || catalog["archiveServers"].length > 64)
            throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
        string[64] servers;
        size_t count;
        foreach (server; catalog["archiveServers"].byValue) {
            if (server.type != Bson.Type.string)
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
            const value = server.get!string;
            if (!value.length || value.length > 128 || servers[0 .. count].canFind(value))
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
            servers[count++] = value;
        }
        if (!servers[0 .. count].canFind(serverId))
            throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
        try {
            auto retention = new HistoryRetentionRepository(AppMongoConnection.getDb());
            admission.installation = retention.loadInstallationState();
            if (admission.installation.active) {
                auto policy = retention.loadPolicy(admission.ownerId);
                if (policy.isNull)
                    throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
                admission.policy = policy.get;
            }
        } catch (ArchiveWriteException e) { throw e; }
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.unavailable); }
        return admission;
    }

    /// Only a majority-read durable fence proves deletion. Absence is not
    /// deletion; malformed storage or owner conflicts remain hard failures.
    bool historyNetworkDeleted(string networkId, string expectedOwner) @trusted {
        import ircfiber.archive_protocol : isCanonicalArchiveOperationId;
        if (!isCanonicalArchiveOperationId(networkId)
                || !isCanonicalArchiveOperationId(expectedOwner))
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        const owner = historyNetworkFenceOwner(networkId);
        if (owner.length && owner != expectedOwner)
            throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
        return owner.length != 0;
    }

    private static string historyNetworkFenceOwner(string networkId) @trusted {
        import ircfiber.archive_protocol : isCanonicalArchiveOperationId;
        auto command = Bson.emptyObject;
        command["find"] = Bson("history_network_fences");
        command["filter"] = Bson(["_id": Bson(networkId)]);
        command["projection"] = Bson(["_id": Bson(1), "ownerId": Bson(1)]);
        command["limit"] = Bson(2L); command["singleBatch"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        command["readConcern"] = Bson(["level": Bson("majority")]);
        const reply = runArchiveCommand(command);
        checkArchiveReply(reply); checkArchiveWriteErrors(reply);
        const cursor = reply["cursor"];
        if (cursor.type != Bson.Type.object || !archiveIntegerEquals(cursor["id"], 0)
                || cursor["ns"].type != Bson.Type.string
                || cursor["ns"].get!string != AppMongoConnection.getDb().name ~ ".history_network_fences"
                || cursor["firstBatch"].type != Bson.Type.array || cursor["firstBatch"].length > 1)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        if (!cursor["firstBatch"].length) return "";
        const row = cursor["firstBatch"][0];
        if (row.type != Bson.Type.object || row["_id"].type != Bson.Type.string
                || row["_id"].get!string != networkId || row["ownerId"].type != Bson.Type.string
                || !isCanonicalArchiveOperationId(row["ownerId"].get!string))
            throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
        return row["ownerId"].get!string;
    }

    /// Ordinary producers share the checked insert path; callers decide how a
    /// failed archive affects their independent live delivery.
    ArchiveWriteResult appendMessage(string serverId, string networkId, string channel,
            Json message) @trusted {
        return appendMessage(admitArchiveWrite(serverId, networkId), channel, message);
    }

    ArchiveWriteResult appendMessage(ArchiveWriteScope admission, string channel, Json message) @trusted {
        return appendOrdinaryPayload(admission, channel, message, message.toString());
    }

    private ArchiveWriteResult appendOrdinaryPayload(ArchiveWriteScope admission, string channel,
            Json message, string compact) @trusted {
        if (message.type != Json.Type.object)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        long timestampMs, eid;
        if (auto t = "t" in message)
            if (t.type == Json.Type.int_) timestampMs = t.get!long;
        // Compatibility for pre-cutover producers only. An active archive may
        // never rejuvenate an old row using the wall clock at drain time.
        if (timestampMs <= 0) {
            if (admission.installation.active)
                throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
            timestampMs = admission.nowMs;
        }
        if (auto e = "eid" in message)
            if (e.type == Json.Type.int_) eid = e.get!long;
        string msgid;
        if (auto m = "m" in message)
            if (m.type == Json.Type.string) msgid = m.get!string;
        return insertArchivedPayload(admission, channel, message, compact, timestampMs, eid, msgid);
    }

    private static Bson messageDocument(string serverId, string networkId, string channel,
            Json message, string payload, long timestampMs, long eid, string msgid,
            string ownerId, bool active) @trusted {
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
        // Bson.data is the encoded envelope already built above, not a JSON
        // estimate or a second serialization of the compact payload.
        const charge = cast(long)doc.data.length;
        doc["historyOwnerId"] = Bson(ownerId);
        doc["historyBytes"] = Bson(charge);
        if (isDirectBuffer(channel)) doc["historyWasDirect"] = Bson(true);
        // Preserve compatibility with the installed legacy TTL until cutover.
        if (!active && !isDirectBuffer(channel)) doc["tsAt"] = Bson(BsonDate(timestampMs));
        searchMetadata(doc, message);
        return doc;
    }

    /// The private conversations of `networkId` with a message newer than
    /// `sinceMs` (unix ms), at most `limit`. Backs re-opening query tabs lost
    /// with an in-memory session (holder restart, fresh dial). Only networks
    /// with more than `limit` candidates are ranked newest first.
    string[] recentDirectBuffers(string networkId, long sinceMs, size_t limit,
            HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        auto query = Bson.emptyObject;
        query["networkId"] = Bson(networkId);
        // Under binary ordering, all four IRC channel sigils (# & + !)
        // precede "0", and nick initials do not. Bound the channel index scan.
        query["channel"] = Bson(["$gte": Bson("0")]);
        query["t"] = Bson(["$gt": Bson(sinceMs)]);
        auto cmd = Bson.emptyObject;              // field order matters: command name first
        cmd["distinct"] = Bson("messages");
        cmd["key"] = Bson("channel");
        cmd["query"] = historyView.filter(query);
        cmd["maxTimeMS"] = Bson(15_000L);
        auto reply = AppMongoConnection.runCommand(cmd);

        string[] names;
        foreach (value; reply["values"]) {
            if (value.type != Bson.Type.string) continue;
            const name = value.get!string;
            if (isDirectBuffer(name)) names ~= name;
        }
        if (names.length <= limit) return names;

        struct Latest {
            string name;
            long timestamp;
        }
        auto ranked = new Latest[names.length];
        size_t found;
        FindOptions options;
        options.sort = Bson(["t": Bson(-1)]);
        options.limit = 1;
        options.projection = Bson(["t": Bson(1), "_id": Bson(0)]);
        foreach (name; names) {
            query["channel"] = Bson(name);
            foreach (doc; collection.find(historyView.filter(query), options))
                ranked[found++] = Latest(name, readBsonTimestamp(doc["t"]));
        }
        ranked = ranked[0 .. found];
        ranked.sort!((a, b) => a.timestamp == b.timestamp
            ? a.name < b.name : a.timestamp > b.timestamp);
        auto newest = new string[min(limit, ranked.length)];
        foreach (i; 0 .. newest.length) newest[i] = ranked[i].name;
        return newest;
    }

    /// Replay the original compact event, never assigning an eid or wall-clock
    /// timestamp here. A duplicate must be the same immutable event; its current
    /// channel is intentionally ignored because ordered renames can change it.
    ArchiveWriteResult appendArchivedMessage(string serverId, string networkId,
            string channel, Json message) @trusted {
        return appendArchivedPayload(admitArchiveWrite(serverId, networkId),
            channel, message, message.toString());
    }

    /// Journal replay keeps the admitted compact bytes verbatim. Do not
    /// serialize a parsed object again on every uncertain-write retry.
    ArchiveWriteResult appendArchivedCompactMessage(string serverId, string networkId,
            string channel, string compactJson, string expectedOwner = "") @trusted {
        return appendArchivedCompactMessage(admitArchiveWrite(serverId, networkId, expectedOwner),
            channel, compactJson);
    }

    ArchiveWriteResult appendArchivedCompactMessage(ArchiveWriteScope admission,
            string channel, string compactJson) @trusted {
        Json message;
        try message = parseJsonString(compactJson);
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput); }
        return appendArchivedPayload(admission, channel, message, compactJson);
    }

    private ArchiveWriteResult appendArchivedPayload(ArchiveWriteScope admission,
            string channel, Json message, string payload) @trusted {
        if (message.type != Json.Type.object)
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
        return insertArchivedPayload(admission, channel, message, payload, timestampMs, eid, msgid);
    }

    private ArchiveWriteResult insertArchivedPayload(ArchiveWriteScope admission, string channel,
            Json message, string payload, long timestampMs, long eid, string msgid) @trusted {
        channel = normalizeChannel(channel);
        if (!admission.serverId.length || !admission.networkId.length || !admission.ownerId.length
                || !channel.length || timestampMs <= 0)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        if (admission.deleted) return ArchiveWriteResult.expiredDiscard;
        if (admission.installation.active) {
            if (admission.policy.due(admission.nowMs))
                throw new ArchiveWriteException(ArchiveWriteFailure.unavailable);
            if (timestampMs <= admission.policy.visibleFloor(admission.nowMs, isDirectBuffer(channel))) {
                const expired = messageDocument(admission.serverId, admission.networkId, channel, message,
                    payload, timestampMs, eid, msgid, admission.ownerId, true);
                preserveHistorySuppression([expired]);
                return ArchiveWriteResult.expiredDiscard;
            }
        }
        const doc = messageDocument(admission.serverId, admission.networkId, channel, message,
            payload, timestampMs, eid, msgid, admission.ownerId, admission.installation.active);
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
            signalHistoryDirty(admission);
            return ArchiveWriteResult.alreadyPersisted;
        }
        checkArchiveWriteErrors(reply);
        if (!archiveIntegerEquals(reply["n"], 1))
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidReply);
        signalHistoryDirty(admission);
        return ArchiveWriteResult.inserted;
    }

    // A Redis outage must not change the durability result of a Mongo write.
    // The roster scan repairs lost signals. NX retains the oldest enqueue time.
    private void signalHistoryDirty(const ref ArchiveWriteScope admission) {
        if (!admission.installation.active || maintenanceRedis is null) return;
        try maintenanceRedis.getDb().request!long("ZADD", historyDirtyKey, "NX",
            admission.nowMs, admission.ownerId);
        catch (Exception) {
            if (admission.nowMs - lastDirtyWarningMs >= 60_000) {
                lastDirtyWarningMs = admission.nowMs;
                logWarn("history retention: dirty signal unavailable; relying on roster sweep");
            }
        }
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
        try new HistorySuppressionRepository(AppMongoConnection.getDb()).beforeRename(
            serverId, networkId, oldChannel, newChannel, cutoffEid, legacyTimestampCutoffMs);
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.unavailable); }
        auto command = Bson.emptyObject;
        command["update"] = Bson("messages");
        command["updates"] = Bson([Bson([
            "q": filter,
            "u": searchRenameUpdate(oldChannel, newChannel),
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
        auto suppression = new HistorySuppressionRepository(AppMongoConnection.getDb());
        try suppression.beforeClear(serverId, networkId, channel, cutoffEid, legacyTimestampCutoffMs);
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.unavailable); }
        long deleted;
        while (true) {
            FindOptions options;
            options.limit = 256;
            options.maxTimeMS = 2_000;
            Bson[] page;
            foreach (doc; collection.find(filter, options)) page ~= doc;
            if (!page.length) return deleted;
            preserveHistorySuppression(page, true);
            string[] ids;
            foreach (doc; page) ids ~= doc["_id"].get!string;
            auto exact = Bson(["$and": Bson([filter,
                Bson(["_id": Bson(["$in": serializeToBson(ids)])])])]);
            auto command = Bson.emptyObject;
            command["delete"] = Bson("messages");
            command["deletes"] = Bson([Bson(["q": exact, "limit": Bson(0)])]);
            command["ordered"] = Bson(true);
            command["writeConcern"] = archiveWriteConcern();
            const reply = runArchiveCommand(command);
            checkArchiveReply(reply);
            checkArchiveWriteErrors(reply);
            deleted += archiveReplyCount(reply, "n");
        }
    }

    private static void preserveHistorySuppression(Bson[] rows, bool clearingScope = false) {
        try new HistorySuppressionRepository(AppMongoConnection.getDb()).preserveBeforeDelete(rows, clearingScope);
        catch (Exception) { throw new ArchiveWriteException(ArchiveWriteFailure.unavailable); }
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
        command["limit"] = Bson(2L); command["singleBatch"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        command["readConcern"] = Bson(["level": Bson("majority")]);
        auto reply = runArchiveCommand(command);
        checkArchiveReply(reply); checkArchiveWriteErrors(reply);
        auto cursor = reply["cursor"];
        if (cursor.type != Bson.Type.object || !archiveIntegerEquals(cursor["id"], 0)
                || cursor["ns"].type != Bson.Type.string
                || cursor["ns"].get!string != AppMongoConnection.getDb().name ~ ".networks"
                || cursor["firstBatch"].type != Bson.Type.array || cursor["firstBatch"].length > 1)
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
            // maxTimeMS limits the initial aggregate command, not getMore.
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
        if (cursor.type != Bson.Type.object || !archiveIntegerEquals(cursor["id"], 0)
                || cursor["ns"].type != Bson.Type.string
                || cursor["ns"].get!string != AppMongoConnection.getDb().name ~ ".messages"
                || cursor["firstBatch"].type != Bson.Type.array)
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
        foreach (field; ["eid", "t"]) {
            const wanted = expected.tryIndex(field);
            const actual = stored.tryIndex(field);
            if (wanted.isNull) {
                if (!actual.isNull)
                    throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
            } else if (actual.isNull || !archiveIntegerEquals(actual.get, wanted.get.get!long)) {
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
            }
        }
        // Pre-migration duplicates can lack stamps, but may never carry a
        // contradictory owner. A rename intentionally preserves the old charge.
        foreach (key, value; stored.byKeyValue) {
            if (key == "historyOwnerId" && (value.type != Bson.Type.string
                    || value.get!string != expected["historyOwnerId"].get!string))
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
            if (key == "historyBytes" && (value.type != Bson.Type.long_ || value.get!long <= 0))
                throw new ArchiveWriteException(ArchiveWriteFailure.identityMismatch);
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
                searchRenameUpdate(oldChan, newChan));
            if (res.modifiedCount > 0)
                logInfo("Renamed Mongo channel %s:%s %s -> %s (%s docs)",
                    serverId, networkId, oldChan, newChan, res.modifiedCount.to!string);
            return res.modifiedCount;
        } catch (Exception e) {
            logWarn("renameChannel failed: %s", e.msg);
            return 0;
        }
    }

    // Eligible channel → eligible channel preserves classification, not scope.
    // Crossing the channel/DM boundary requires classification before reads.
    private static Bson searchRenameUpdate(string oldChannel, string channel) {
        auto update = Bson(["$set": Bson(["channel": Bson(channel), "searchPending": Bson(true)])]);
        if (isSearchChannel(oldChannel) != isSearchChannel(channel))
            update["$unset"] = Bson(["searchVersion": Bson(1)]);
        return update;
    }

    /// Convenience: append directly from an IRCRawEvent.
    ArchiveWriteResult appendIRCEvent(IRCRawEvent event, string serverId) @trusted {
        const networkId = event.networkId.length > 0 ? event.networkId : event.network;
        const channel = event.channel.length > 0 ? normalizeChannel(event.channel) : "_server";
        auto msg = event.toCompactJson();
        return appendMessage(serverId, networkId, channel, msg);
    }

    /// Read a payload back from Mongo and convert the stored JSON
    /// string into a Json object. Returns an empty array on parse
    /// error so a single bad document doesn't kill the whole page.
    ///
    /// Returns oldest-first (IRCCloud/Redis convention) — the find()
    /// above returns newest-first (sort by t desc) and we reverse here
    /// so the caller can treat MongoDB and Redis results identically.
    private Json[] readPayloads(Bson filter, int count, HistoryReadScope* view) @trusted {
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        FindOptions options;
        options.sort = Bson(["t": Bson(-1)]);
        options.limit = cast(long)count;

        filter = view.filter(filter);
        Json[] out_;
        foreach (doc; collection.find(filter, options)) {
            const p = doc["payload"];
            if (p.type == Bson.Type.string) {
                try {
                    Json payload;
                    if (visiblePayload(doc, view, payload)) out_ ~= payload;
                } catch (Exception e) {
                    logWarn("Failed to parse stored message payload: %s", e.msg);
                }
            }
        }
        // Match Redis _getRecentFiltered which does messages.reverse.
        out_.reverse;
        return out_;
    }

    /// The admitted envelope owns routing and event time. A rename may change
    /// its target without rewriting immutable compact bytes.
    private static bool visiblePayload(Bson doc, HistoryReadScope* view, out Json payload) {
        if (doc["payload"].type != Bson.Type.string) return false;
        payload = parseJsonString(doc["payload"].get!string);
        if (!view.active()) return true;
        if (payload.type != Json.Type.object || payload["t"].type != Json.Type.int_
                || payload["t"].get!long != readBsonTimestamp(doc["t"]))
            return false;
        foreach (key; ["nid", "networkId"]) {
            if (auto value = key in payload) {
                if (value.type != Json.Type.string || value.get!string != view.networkId())
                    return false;
            }
        }
        if (doc["channel"].type != Bson.Type.string) return false;
        payload["ch"] = Json(doc["channel"].get!string);
        return true;
    }

    /**
     * Fetch the most recent `count` messages for a channel, newest-first
     * by timestamp. Used as the MongoDB fallback for the `_server` buffer
     * scrollback during WebSocket state dump when Redis is cold.
     */
    Json[] getRecent(string serverId, string networkId, string channel,
                     int count = 50, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
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
        return readPayloads(filter, count, &historyView);
    }

    /// Initial unread tails span engine moves and count only highlight-bearing
    /// commands before selecting the newest bounded chronological page.
    Json[] getUnreadTail(string networkId, string channel, long afterTs, int count,
            HistoryReadScope* view = null) @trusted {
        if (count <= 0) return [];
        auto historyView = resolveHistoryView(networkId, view);
        auto filter = Bson(["networkId": Bson(networkId),
            "channel": Bson(normalizeChannel(channel)),
            "t": Bson(["$gt": Bson(afterTs)]),
            "payload": Bson(["$regex": Bson(`"c"\s*:\s*"(PRIVMSG|NOTICE|INVITE|WALLOPS)"`)])]);
        return readPayloads(filter, count, &historyView);
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
                        long beforeEid, long fallbackTs, int count, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
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
            auto cursorDoc = collection.findOne(historyView.filter(cursorFilter));
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
        return readPayloads(filter, count, &historyView);
    }

    Json[] getBeforeMsgid(string serverId, string networkId, string channel,
                          string beforeMsgid, long fallbackTs, int count, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
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
        auto cursorDoc = collection.findOne(historyView.filter(cursorFilter));
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
        return readPayloads(filter, count, &historyView);
    }

    /// Exclusive bounds; selected rows are always returned in ascending storage order.
    Json[] getWindow(string serverId, string networkId, string channel,
                     HistoryBoundary after, HistoryBoundary before, int count,
                     bool fromNewest, bool events = false, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        return historyWindow(serverId, networkId, channel, after, before, count, fromNewest, events, false, &historyView);
    }

    static Bson boundaryFilter(HistoryBoundary boundary, bool after, bool inclusive = false) {
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
            bool events, bool includeAfter, HistoryReadScope* view) @trusted {
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
        filter = view.filter(filter);
        FindOptions options;
        auto order = Bson.emptyObject;
        foreach (key; ["t", "eid", "_id"]) order[key] = Bson(fromNewest ? -1 : 1);
        options.sort = order;
        options.limit = cast(long) count;
        Json[] rows;
        foreach (doc; collection.find(filter, options)) {
            try {
                Json payload;
                if (visiblePayload(doc, view, payload)) rows ~= payload;
            }
            catch (Exception e) logWarn("Failed to parse stored message payload: %s", e.msg);
        }
        if (fromNewest) rows.reverse;
        return rows;
    }

    /// Include the selected exact row once, between strict older/newer halves.
    Json[] getAround(string serverId, string networkId, string channel,
            HistoryBoundary center, int count, bool events = false, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        if (count <= 0) return [];
        const half = count / 2;
        return historyWindow(serverId, networkId, channel, HistoryBoundary.init, center, half, true, events, false, &historyView)
            ~ historyWindow(serverId, networkId, channel, center, HistoryBoundary.init,
                count - half, false, events, true, &historyView);
    }


    /// False is an unknown reference, never an unbounded window.
    bool boundaryOfMsgid(string serverId, string networkId, string channel, string msgid,
            out HistoryBoundary boundary, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        channel = normalizeChannel(channel);
        Bson filter = serverId.length > 0
            ? Bson(["serverId": Bson(serverId), "networkId": Bson(networkId), "channel": Bson(channel), "msgid": Bson(msgid)])
            : Bson(["networkId": Bson(networkId), "channel": Bson(channel), "msgid": Bson(msgid)]);
        filter = historyView.filter(filter);
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
                         long afterTs, long beforeTs, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        auto rows = getWindow(serverId, networkId, channel, HistoryBoundary.init, HistoryBoundary.init, 1, true, false, &historyView);
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
    bool[string] deliveredHistoryKeys(string serverId, string networkId, Json[] rows, long throughEid,
            HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
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
        filter = historyView.filter(filter);
        foreach (doc; collection.find(filter)) {
            if (doc["msgid"].type == Bson.Type.string && doc["channel"].type == Bson.Type.string)
                keys[doc["channel"].get!string ~ "\0m" ~ doc["msgid"].get!string] = true;
        }
        return keys;
    }

    /// Fetch older messages using a timestamp cursor (fallback when
    /// no msgid is available).
    Json[] getBeforeTimestamp(string serverId, string networkId, string channel,
                             long beforeTs, int count, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
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
        return readPayloads(filter, count, &historyView);
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
                       long afterEid, int count, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
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
        return readPayloads(filter, count, &historyView);
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
                                 long afterEid, int count, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        if (count <= 0) count = 50;
        if (count > 1000) count = 1000;

        // Bypass the per-channel readPayloads helper because we don't
        // want a per-channel cap here — we want N events across the
        // whole network.
        FindOptions options;
        options.sort = Bson(["eid": Bson(1)]);
        options.limit = cast(long)count;

        Bson filter = Bson([
            "networkId": Bson(networkId),
            "eid": Bson(["$gt": Bson(afterEid)])
        ]);
        if (serverId.length) filter["serverId"] = Bson(serverId);
        filter = historyView.filter(filter);
        Json[] out_;
        foreach (doc; collection.find(filter, options)) {
            const p = doc["payload"];
            if (p.type == Bson.Type.string) {
                try {
                    Json payload;
                    if (visiblePayload(doc, &historyView, payload)) out_ ~= payload;
                } catch (Exception e) {
                    logWarn("getAfterEidForNetwork: bad payload: %s", e.msg);
                }
            }
        }
        return out_;
    }

    private enum BNC_CHANNEL_RE = `^[#&+!][^\x00-\x20\x7F,:]+$`;
    private enum BNC_QUERY_RE = `^[^#&+!.:*,<>\x00-\x20\x7F]+$`;

    private static bool isBncQuery(string name) @safe pure nothrow @nogc {
        if (!isDirectBuffer(name) || ircCaseEquals(name, "_server", IrcCaseMapping.ascii))
            return false;
        foreach (char c; name)
            if (c == '+' || c == '!' || c == '<' || c == '>') return false;
        return true;
    }

    private static bool isBncTarget(string name) @safe pure nothrow @nogc {
        if (isBncQuery(name)) return true;
        if (name.length < 2) return false;
        const prefix = name[0];
        if (prefix != '#' && prefix != '&' && prefix != '+' && prefix != '!') return false;
        foreach (char c; name)
            if (c <= 0x20 || c == 0x7F || c == ',' || c == ':')
                return false;
        return true;
    }

    private static Bson bncBufferType(bool query) {
        return query
            ? Bson(["channel": Bson(["$regex": Bson(BNC_QUERY_RE), "$ne": Bson("_server")])])
            : Bson(["channel": Bson(["$regex": Bson(BNC_CHANNEL_RE)])]);
    }

    private static Bson bncArchiveScope(string serverId, string networkId, bool events) {
        auto filter = Bson(["networkId": Bson(networkId),
            "payload": Bson(["$regex": Bson(events ? EVENT_PAYLOAD_RE : CHAT_PAYLOAD_RE)])]);
        if (serverId.length) filter["serverId"] = Bson(serverId);
        return filter;
    }

    /// Old DM writers may have used the lower-case spelling. Keep that alias
    /// inside the database predicate, including exclusions, before any limit.
    private static string[] bncStorageNames(string target) {
        import std.uni : toLower;
        string[] names = [target];
        const normalized = normalizeChannel(target);
        if (!names.canFind(normalized)) names ~= normalized;
        const lower = target.length && canFind("#&+!", target[0]) ? normalized : target.toLower();
        if (!names.canFind(lower)) names ~= lower;
        return names;
    }

    private static Bson bncTargetPredicate(string[] names) {
        return Bson(["channel": Bson(["$in": serializeToBson(names)])]);
    }

    private static void appendBncCutoff(ref Bson[] clauses, BncPlaybackCutoff cutoff) {
        if (!cutoff.active()) return;
        // A high eid never admits old upstream backfill; a recent timestamp
        // never admits an already-cleared positive eid. Legacy equal-time rows
        // are excluded as well, exactly as BncPlaybackCutoff.allows specifies.
        clauses ~= Bson(["t": Bson(["$gte": Bson(cutoff.timestampMs)])]);
        clauses ~= Bson(["$or": Bson([
            Bson(["eid": Bson(["$gt": Bson(cutoff.eid)])]),
            Bson(["t": Bson(["$gt": Bson(cutoff.timestampMs)]), "$or": Bson([
                Bson(["eid": Bson(["$exists": Bson(false)])]),
                Bson(["eid": Bson(["$lte": Bson(0L)])])
            ])])
        ])]);
    }

    private static void appendBncPolicy(ref Bson[] clauses, BncArchiveFilter policy) {
        appendBncCutoff(clauses, policy.category);
        appendBncCutoff(clauses, policy.target);
        if (policy.consumed.active())
            clauses ~= Bson(["$or": Bson([
                Bson(["t": Bson(["$gt": Bson(policy.consumed.timestampMs)])]),
                Bson(["t": Bson(policy.consumed.timestampMs),
                    "eid": Bson(["$gt": Bson(policy.consumed.eid)])])
            ])]);
    }

    private struct BncArchiveRow {
        long eid;
        string storageId;
        Json payload;
    }

    private BncArchiveRow[] readBncRows(Bson filter, int count, bool newest, bool eidOrder,
            HistoryReadScope* view) @trusted {
        filter = view.filter(filter);
        FindOptions options;
        auto order = Bson.emptyObject;
        if (!eidOrder) order["t"] = Bson(newest ? -1 : 1);
        order["eid"] = Bson(newest ? -1 : 1);
        order["_id"] = Bson(newest ? -1 : 1);
        options.sort = order;
        options.limit = cast(long) count;
        BncArchiveRow[] rows;
        foreach (doc; collection.find(filter, options)) {
            if (doc["payload"].type != Bson.Type.string) continue;
            try {
                Json payload;
                if (!visiblePayload(doc, view, payload)) continue;
                rows ~= BncArchiveRow(readBsonTimestamp(doc["eid"]), doc["_id"].get!string, payload);
            } catch (Exception) {
                logWarn("Failed to parse stored BNC archive payload");
            }
        }
        return rows;
    }

    /// Bound each category member inside Mongo before the final eid page.
    /// $topN avoids collecting an unbounded channel history with $push/$slice.
    private BncArchiveRow[] readBncLimitedRows(Bson filter, int perTarget, int count,
            long afterEid, bool partitionTargets, HistoryReadScope* view) @trusted {
        // Returning replay has always required positive eids. Rank that
        // eligible inventory first, then apply the caller's cursor below.
        filter["eid"] = Bson(["$gt": Bson(0L)]);
        filter = view.filter(filter);
        auto newest = Bson.emptyObject;
        newest["t"] = Bson(-1);
        newest["eid"] = Bson(-1);
        newest["_id"] = Bson(-1);
        auto pageOrder = Bson.emptyObject;
        pageOrder["eid"] = Bson(1);
        pageOrder["_id"] = Bson(1);
        Bson[] pipeline = [
            Bson(["$match": filter]),
            Bson(["$group": Bson(["_id": partitionTargets ? Bson("$channel") : Bson(null),
                "rows": Bson(["$topN": Bson(["n": Bson(min(perTarget, 1000)),
                    "sortBy": newest, "output": Bson([
                        "_id": Bson("$_id"), "eid": Bson("$eid"), "payload": Bson("$payload"),
                        "t": Bson("$t"), "channel": Bson("$channel")
                    ])])])])]),
            Bson(["$unwind": Bson("$rows")]),
            Bson(["$replaceRoot": Bson(["newRoot": Bson("$rows")])]),
            Bson(["$match": Bson(["eid": Bson(["$gt": Bson(max(afterEid, 0L))])])]),
            Bson(["$sort": pageOrder]),
            Bson(["$limit": Bson(cast(long) count)])
        ];
        AggregateOptions options;
        BncArchiveRow[] rows;
        foreach (doc; collection.aggregate!Bson(pipeline, options)) {
            if (doc["payload"].type != Bson.Type.string) continue;
            try {
                Json payload;
                if (!visiblePayload(doc, view, payload)) continue;
                rows ~= BncArchiveRow(readBsonTimestamp(doc["eid"]), doc["_id"].get!string, payload);
            } catch (Exception) {
                logWarn("Failed to parse stored BNC archive payload");
            }
        }
        return rows;
    }

    private static bool bncRowBefore(const ref BncArchiveRow a, const ref BncArchiveRow b) {
        return a.eid < b.eid || (a.eid == b.eid && a.storageId < b.storageId);
    }

    /// Both inputs are eid-ordered. Retain only the globally earliest page,
    /// bounding memory independently of the number of target overrides.
    private static BncArchiveRow[] mergeBncRows(BncArchiveRow[] a, BncArchiveRow[] b, int count) {
        if (!a.length) return b[0 .. min(cast(size_t) count, b.length)];
        if (!b.length) return a[0 .. min(cast(size_t) count, a.length)];
        BncArchiveRow[] merged;
        merged.length = min(cast(size_t) count, a.length + b.length);
        size_t ai, bi;
        foreach (ref row; merged) {
            if (bi == b.length || (ai < a.length && bncRowBefore(a[ai], b[bi])))
                row = a[ai++];
            else row = b[bi++];
        }
        return merged;
    }

    /// Newest eligible target rows, returned in ascending (t, eid, _id) order.
    /// Empty serverId deliberately supports offline/ownerless network history.
    Json[] getBncPlayback(string serverId, string networkId, string target,
            BncArchiveFilter policy, bool events, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        if (!networkId.length || !isBncTarget(target) || policy.limit == 0) return [];
        const count = policy.limit < 0 ? 1000 : min(policy.limit, 1000);
        auto filter = bncArchiveScope(serverId, networkId, events);
        Bson[] clauses = [bncTargetPredicate(bncStorageNames(target)),
            Bson(["$or": Bson([bncBufferType(false), bncBufferType(true)])])];
        appendBncPolicy(clauses, policy);
        filter["$and"] = Bson(clauses);
        auto stored = readBncRows(filter, count, true, false, &historyView);
        Json[] rows;
        rows.length = stored.length;
        foreach (i, ref row; stored) rows[stored.length - i - 1] = row.payload;
        return rows;
    }

    /// BNC-only returning-client replay. Positive category/target limits select
    /// each target's newest eligible N first; -1 keeps the old uncapped eid walk.
    /// Neither this path nor explicit playback changes archive/cursor state.
    Json[] getBncMissed(string serverId, string networkId, long afterEid, int limit,
            BncArchiveFilter channel, BncArchiveFilter query,
            BncArchiveFilter[string] overrides, string[] detached, bool events,
            HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        if (!networkId.length || limit <= 0) return [];
        limit = min(limit, 1000);
        string[] excluded;
        bool[string] detachedNames;
        foreach (name; detached) foreach (stored; bncStorageNames(name)) {
            if (stored in detachedNames) continue;
            detachedNames[stored] = true;
            excluded ~= stored;
        }
        foreach (name, policy; overrides) excluded ~= bncStorageNames(name);

        BncArchiveRow[] selected;
        Bson[] alternatives;
        foreach (isQuery; [false, true]) {
            const policy = isQuery ? query : channel;
            if (policy.limit == 0) continue;
            Bson[] clauses = [bncBufferType(isQuery)];
            if (excluded.length)
                clauses ~= Bson(["channel": Bson(["$nin": serializeToBson(excluded)])]);
            appendBncPolicy(clauses, policy);
            if (policy.limit < 0) {
                alternatives ~= Bson(["$and": Bson(clauses)]);
            } else {
                auto filter = bncArchiveScope(serverId, networkId, events);
                filter["$and"] = Bson(clauses);
                selected = mergeBncRows(selected,
                    readBncLimitedRows(filter, policy.limit, limit, afterEid, true, &historyView), limit);
            }
        }
        foreach (name, policy; overrides) {
            const inherited = isBncQuery(name) ? query.limit : channel.limit;
            if (policy.limit >= 0 || inherited >= 0 || !isBncTarget(name)) continue;
            auto names = bncStorageNames(name);
            if (names.any!(n => (n in detachedNames) !is null)) continue;
            Bson[] clauses = [bncTargetPredicate(names)];
            appendBncPolicy(clauses, policy);
            alternatives ~= Bson(["$and": Bson(clauses)]);
        }
        if (alternatives.length) {
            auto filter = bncArchiveScope(serverId, networkId, events);
            filter["eid"] = Bson(["$gt": Bson(max(afterEid, 0L))]);
            filter["$or"] = Bson(alternatives);
            selected = mergeBncRows(selected, readBncRows(filter, limit, false, true, &historyView), limit);
        }
        foreach (name, policy; overrides) {
            const inherited = isBncQuery(name) ? query.limit : channel.limit;
            const targetLimit = policy.limit < 0 ? inherited : policy.limit;
            if (targetLimit <= 0 || !isBncTarget(name)) continue;
            auto names = bncStorageNames(name);
            if (names.any!(n => (n in detachedNames) !is null)) continue;
            auto filter = bncArchiveScope(serverId, networkId, events);
            Bson[] clauses = [bncTargetPredicate(names)];
            appendBncPolicy(clauses, policy);
            filter["$and"] = Bson(clauses);
            auto rows = readBncLimitedRows(filter, targetLimit, limit, afterEid, false, &historyView);
            selected = mergeBncRows(selected, rows, limit);
        }
        Json[] result;
        result.length = selected.length;
        foreach (i, ref row; selected) result[i] = row.payload;
        return result;
    }

    /// Query inventory contains only retained, visible history.
    /// Mongo groups/ranks first, and the returned inventory is bounded to 1000.
    string[] recentBncQueries(string networkId, size_t limit, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        if (!networkId.length || limit == 0) return [];
        auto match = Bson(["networkId": Bson(networkId), "$and": Bson([bncBufferType(true)])]);
        match = historyView.filter(match);
        auto order = Bson.emptyObject;
        order["last"] = Bson(-1);
        order["_id"] = Bson(1);
        Bson[] pipeline = [
            Bson(["$match": match]),
            Bson(["$group": Bson(["_id": Bson("$channel"), "last": Bson(["$max": Bson("$t")])])]),
            Bson(["$sort": order]),
            Bson(["$limit": Bson(cast(long) min(limit, cast(size_t) 1000))])
        ];
        AggregateOptions options;
        string[] names;
        foreach (doc; collection.aggregate!Bson(pipeline, options))
            names ~= doc["_id"].get!string;
        return names;
    }

    /// Build a literal, bytewise IRC-folded regex, never an unescaped user
    /// regex or Mongo's broader Unicode case-insensitive matching.
    private static string bncLiteralQueryRegex(string name, IrcCaseMapping mapping) {
        auto pattern = appender!string();
        pattern.put(`\A`);
        foreach (char c; name) {
            const folded = foldIrcCaseChar(c, mapping);
            if (folded >= 'a' && folded <= 'z') {
                pattern.put('[');
                pattern.put(folded);
                pattern.put(cast(char)(folded - ('a' - 'A')));
                pattern.put(']');
                continue;
            }
            if (mapping != IrcCaseMapping.ascii) {
                if (folded == '{') { pattern.put(`(?:\[|\{)`); continue; }
                if (folded == '}') { pattern.put(`(?:\]|\})`); continue; }
                if (folded == '|') { pattern.put(`(?:\\|\|)`); continue; }
                if (folded == '~' && mapping == IrcCaseMapping.rfc1459) {
                    pattern.put(`(?:\^|~)`); continue;
                }
            }
            if (canFind(`\.^$|?*+()[]{}`, folded)) pattern.put('\\');
            pattern.put(folded);
        }
        pattern.put(`\z`);
        return pattern.data;
    }

    /// Return the stored canonical spelling, or "" when no real query exists.
    /// A literal lookup is not restricted to the newest inventory page.
    string findBncQuery(string networkId, string name, IrcCaseMapping mapping,
            HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
        if (!networkId.length || !isBncQuery(name)) return "";
        auto filter = Bson(["networkId": Bson(networkId),
            "channel": Bson(["$regex": Bson(bncLiteralQueryRegex(name, mapping))]),
            "$and": Bson([bncBufferType(true)])]);
        filter = historyView.filter(filter);
        FindOptions options;
        auto order = Bson.emptyObject;
        order["t"] = Bson(-1);
        order["_id"] = Bson(1);
        options.sort = order;
        options.limit = 1;
        foreach (doc; collection.find(filter, options)) return doc["channel"].get!string;
        return "";
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
    long count(string serverId, string networkId, string channel, HistoryReadScope* view = null) @trusted {
        auto historyView = resolveHistoryView(networkId, view);
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
        return cast(long)collection.countDocuments(historyView.filter(filter));
    }

    /// Mutually exclusive entry outcomes from one Redis→Mongo buffer pass.
    struct SyncResult {
        long scanned;
        long inserted;
        long duplicates;
        /// Intentionally expired or durably fenced records, not failed writes.
        long discarded;
        /// Invalid JSON/envelope, including absent or invalid original `t`.
        long parseErrors;
        /// Admission, identity, storage or acknowledgement failures; retryable.
        long writeErrors;
    }

    private struct RedisSyncAdmission {
        ArchiveWriteScope admittedWrite;
        bool failed;
    }

    /// Backfill without inventing timestamps/eids or mistaking a storage error
    /// for a duplicate. Owner, provenance and policy are resolved once per
    /// engine/network batch; each accepted row keeps its original event time.
    SyncResult syncFromRedis(
        RedisStorage redis,
        string serverId, string networkId, string channel
    ) @trusted {
        RedisSyncAdmission[string][string] admissions;
        return syncFromRedis(redis, serverId, networkId, channel, admissions);
    }

    private SyncResult syncFromRedis(
        RedisStorage redis, string serverId, string networkId, string channel,
        ref RedisSyncAdmission[string][string] admissions
    ) @trusted {
        import std.range : walkLength;
        if (!serverId.length || !networkId.length || !channel.length)
            throw new ArchiveWriteException(ArchiveWriteFailure.invalidInput);
        channel = normalizeChannel(channel);
        auto key = "scrollback:" ~ serverId ~ ":" ~ networkId ~ ":" ~ channel;
        auto raw = redis.getDb().lrange!(ubyte[])(key, 0, 4999);
        SyncResult r;
        if (raw.empty) return r;

        auto serverAdmissions = serverId in admissions;
        if (serverAdmissions is null) {
            admissions[serverId] = null;
            serverAdmissions = serverId in admissions;
        }
        auto admitted = networkId in *serverAdmissions;
        if (admitted is null) {
            RedisSyncAdmission admission;
            try admission.admittedWrite = admitArchiveWrite(serverId, networkId);
            catch (Exception) { admission.failed = true; }
            (*serverAdmissions)[networkId] = admission;
            admitted = networkId in *serverAdmissions;
        }
        if (admitted.failed) {
            r.writeErrors = r.scanned = raw.walkLength;
            return r;
        }

        foreach (entry; raw) {
            ++r.scanned; // RedisReply copies share one socket cursor; never count before consuming.
            Json msg;
            string compact;
            try {
                compact = sanitizeUtf8(cast(string)entry);
                msg = parseJsonString(compact);
                if (msg.type != Json.Type.object) {
                    r.parseErrors++;
                    continue;
                }
                const timestamp = "t" in msg;
                if (timestamp is null || timestamp.type != Json.Type.int_
                        || timestamp.get!long <= 0) {
                    r.parseErrors++;
                    continue;
                }
            } catch (Exception) {
                r.parseErrors++;
                continue;
            }
            try {
                final switch (appendOrdinaryPayload(admitted.admittedWrite, channel, msg, compact)) {
                    case ArchiveWriteResult.inserted: r.inserted++; break;
                    case ArchiveWriteResult.alreadyPersisted: r.duplicates++; break;
                    case ArchiveWriteResult.expiredDiscard: r.discarded++; break;
                }
            } catch (Exception) {
                r.writeErrors++;
            }
        }
        return r;
    }

    /// Enumerate buffers for a one-shot backfill. Cache unsuccessful admission
    /// too: unavailable ownership is never repeatedly guessed across buffers.
    SyncResult[] syncAllFromRedis(RedisStorage redis) @trusted {
        import std.string : indexOf;
        SyncResult[] all;
        RedisSyncAdmission[string][string] admissions;
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
            all ~= syncFromRedis(redis, serverId, networkId, channel, admissions);
        }
        return all;
    }
}

@("private conversations omit legacy TTL dates and are listed newest first")
unittest {
    import std.uuid : randomUUID;
    import std.exception : assertThrown;
    import ircfiber.testing.isolated_db : connectIsolatedTestMongo;
    if (!connectIsolatedTestMongo("messages private conversations")) return;

    const network = randomUUID().toString();
    const now = Clock.currTime.toUnixTime!long * 1000;
    auto repo = new MessageRepository();
    auto coll = AppMongoConnection.getDb()["messages"];
    scope (exit) coll.deleteMany(Bson(["networkId": Bson(network)]));
    auto networks = AppMongoConnection.getDb()["networks"];
    networks.insertOne(Bson(["id": Bson(network), "userId": Bson(randomUUID().toString()),
        "archiveScopeVersion": Bson(1), "archiveServers": Bson([Bson("ovh")])]));
    scope (exit) networks.deleteOne(Bson(["id": Bson(network)]));

    long eid;
    void put(string channel, long agoMs) {
        auto row = Json.emptyObject;
        row["t"] = Json(now - agoMs);
        row["eid"] = Json(++eid);
        row["c"] = Json("PRIVMSG");
        repo.appendMessage("ovh", network, channel, row);
    }
    put("#dlang", 1_000);
    put("_server", 1_000);
    put("+modeless", 1_000);
    put("!safe", 1_000);
    put("alice", 5_000);
    put("bob", 3_000);
    put("zack", 3_000);
    put("carol", 9_000);
    put("old", 200L * 86_400_000);

    // Only channel and server-log rows get a TTL stamp.
    assert(!coll.findOne(["networkId": network, "channel": "#dlang"]).isNull
        && coll.findOne(["networkId": network, "channel": "#dlang"])["tsAt"].type == Bson.Type.date);
    assert(coll.findOne(["networkId": network, "channel": "_server"])["tsAt"].type == Bson.Type.date);
    foreach (nick; ["alice", "bob", "carol", "old"])
        assert(coll.findOne(["networkId": network, "channel": nick])["tsAt"].type == Bson.Type.null_, nick);

    const since = now - 90L * 86_400_000;
    auto all = repo.recentDirectBuffers(network, since, 10);
    all.sort();
    assert(all == ["alice", "bob", "carol", "zack"], "channels, _server and rows outside the window are not conversations");
    assert(repo.recentDirectBuffers(network, since, 3) == ["bob", "zack", "alice"],
        "newest first; equal timestamps sort by nick");
    assert(repo.recentDirectBuffers(network, since, 1) == ["bob"]);
    assertThrown(repo.recentDirectBuffers(randomUUID().toString(), since, 10));
}
