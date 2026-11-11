/// Real Redis archive-buffer regression driver; never uses a default endpoint.
/// Parent supplies the archive-buffer-test DUB configuration (sourceFile only).
module archive_buffer_test;

import std.conv : to;
import std.array : empty, front;
import std.exception : enforce;
import std.process : environment;
import std.stdio : stderr;
import std.string : startsWith, indexOf, lastIndexOf, strip;
import std.format : format;
import std.file : tempDir, exists, mkdir, rmdirRecurse, write, readText;
import std.path : buildPath;
import std.string : toStringz;
import core.sys.posix.sys.stat : chmod, lstat, stat_t, S_ISDIR;
import core.sys.posix.unistd : geteuid;
import std.uuid : parseUUID, randomUUID;
import std.regex : matchFirst, regex;
import std.string : replace;
import ircfiber.engine.event_channel : EngineEventChannel;
import core.time : msecs, seconds, MonoTime, Duration;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep, setTimer;
import vibe.core.task : Task;
import vibe.core.net : connectTCP;
import vibe.stream.operations : readLine;
import vibe.data.json : Json, parseJsonString, serializeToJson;
import vibe.data.bson : Bson;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.messages : MessageRepository;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.archive_protocol : isCanonicalArchiveOperationId, archiveInstallCatalogLua,
    archiveOwnerKey, archiveLookupKey, archiveProjectionKey, archiveClearGroupKey, archiveOperationKey;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.engine.archive_control : applyArchiveRedisPurge, archiveHarnessCreateGroup,
    archiveHarnessObserve, archiveHarnessFreeze, archiveHarnessPin, archiveHarnessRelease,
    archiveHarnessAssumeRegisteredScope, stopArchive, ArchiveControl;
import ircfiber.engine.archive_spool : ArchiveRecord, ArchiveKind, ArchiveSpool,
    ArchiveSpoolConfig, ArchiveSpoolStatus, ArchiveShutdown, decodeArchiveRecord,
    ArchiveOperationStatus, ArchiveOperationState, ArchiveLookup;
import ircfiber.irc.manager : ConnectionManager;
import ircfiber.engine.processor : startEventProcessor;
import ircfiber.models.network : NetworkConfig;
import ircfiber.redis.protocol : RedisKeys, ControlMessage;

private size_t cases, passed, failed;

private void check(bool condition, string message) {
    enforce(condition, message);
}

private void runCase(string name, void delegate() body) {
    cases++;
    try {
        body();
        passed++;
        stderr.writeln("  PASS ", name);
    } catch (Throwable error) {
        failed++;
        stderr.writeln("  FAIL ", name, ": ", error.msg);
    }
}

private final class Fixture {
    RedisStorage redis;
    BufferManager buffers;
    string server, network, user, run;
    string[] owned;
    bool[string] remembered;
    uint nextOperation;
    EngineContext context;
    string nativeRoot;
    ArchiveSpoolConfig nativeConfig;
    bool nativeRootCreated;
    bool tasksQuiescent = true;
    string[] scopes;

    void ensureContext() {
        if (context.archiveSpool !is null) return;
        context.redis = redis;
        context.bufferManager = buffers;
        context.localServer.serverId = server;
        context.eventChannel = EngineEventChannel.create();
        context.connManager = new ConnectionManager(context.eventChannel, redis, server, null);
        nativeRoot = buildPath(tempDir(), server);
        check(!exists(nativeRoot), "native fixture root already exists");
        mkdir(nativeRoot);
        nativeRootCreated = true;
        check(chmod(nativeRoot.toStringz, 448) == 0, "cannot protect fixture directory");
        write(buildPath(nativeRoot, "owner"), server);
        ArchiveSpoolConfig config;
        config.directory = buildPath(nativeRoot, "journal");
        mkdir(config.directory);
        check(chmod(config.directory.toStringz, 448) == 0, "cannot protect journal fixture directory");
        config.maxBytes = 64 * 1024 * 1024;
        config.minFreeBytes = 0;
        config.diagnosticPath = "";
        nativeConfig = config;
        context.archiveSpool = new ArchiveSpool(config);
        ArchiveSpoolStatus status;
        auto deadline = MonoTime.currTime + 5.seconds;
        while (MonoTime.currTime < deadline) {
            if (context.archiveSpool.tryStatus(status) && (status.ready || status.failed || status.stopped)) break;
            sleep(10.msecs);
        }
        check(status.ready && !status.failed && !status.stopped, "real journal did not recover: " ~ status.failureReason);
        own(archiveOwnerKey(network));
        scopes = [server];
        own("irc:archive:clear-pending:" ~ server);
        own("irc:archive:clear-network-pending:" ~ network);
        auto installed = redis.getDb().eval!string(archiveInstallCatalogLua, [archiveOwnerKey(network)],
            [network, serializeToJson([server]).toString(), "100"]);
        check(!installed.empty && installed.front == "1", "real archive catalog installation failed");
    }
    void addScope(string otherServer) {
        ensureContext();
        scopes ~= otherServer;
        auto installed = redis.getDb().eval!string(archiveInstallCatalogLua, [archiveOwnerKey(network)],
            [network, serializeToJson(scopes).toString(), "100"]);
        check(!installed.empty && installed.front == "1", "additional real archive scope registration failed");
    }


    this(RedisStorage connection, string runId, uint index) {
        redis = connection;
        buffers = new BufferManager(redis);
        run = runId;
        server = "archive-buffer-" ~ runId ~ "-" ~ index.to!string;
        network = runId;
        user = runId;
    }

    string own(string key) {
        if (!(key in remembered)) {
            check(!redis.getDb().exists(key), "fixture namespace already contains " ~ key);
            remembered[key] = true;
            owned ~= key;
        }
        return key;
    }

    // API-created keys are registered before admission where possible. Token
    // keys are discovered only through companions of our exact owned lists.
    void discover(string key) {
        if (!(key in remembered)) {
            remembered[key] = true;
            owned ~= key;
        }
    }

    string list(string buffer, bool legacy = false) {
        return own("scrollback:" ~ (legacy ? "" : server ~ ":") ~ network ~ ":" ~ buffer);
    }

    string dedup(string buffer, bool scoped = false) {
        return own("dedup:" ~ (scoped ? server ~ ":" : "") ~ network ~ ":" ~ buffer);
    }

    string companion(string key) {
        return own("irc:archive:lineage:buffer:" ~ key);
    }

    string locator(string token) {
        check(token.length > 0, "expected a physical lineage token");
        auto key = "irc:archive:lineage:id:" ~ token;
        discover(key);
        return key;
    }

    string token(string key) {
        auto value = redis.getDb().get(companion(key)).idup;
        if (value.length) locator(value);
        return value;
    }

    string operation() {
        // Derive operation IDs deterministically from the explicit run UUID.
        auto id = run[0 .. 24] ~ format!"%012x"(++nextOperation);
        own("irc:archive:pin:" ~ server ~ ":" ~ id);
        own("irc:archive:redis-applied:" ~ server ~ ":" ~ id);
        own("irc:archive:clear:" ~ id);
        own("irc:archive:pins:" ~ server);
        own(archiveLookupKey(server, id));
        own("archive-buffer-fixture:" ~ server ~ ":eid:" ~ id);
        own("archive-buffer-fixture:" ~ server ~ ":assignments");
        return id;
    }

    void append(string buffer, long eid, long timestamp, string text) {
        auto key = list(buffer);
        companion(key);
        auto row = Json.emptyObject;
        row["c"] = "PRIVMSG"; row["ch"] = buffer; row["x"] = text;
        row["t"] = timestamp;
        if (eid > 0) row["eid"] = eid;
        buffers.appendMessage(server, network, buffer, row);
        token(key);
    }

    void legacy(string buffer, long eid, long timestamp, string text, bool oldTimestamp = false) {
        auto key = list(buffer, true);
        companion(key);
        auto row = Json.emptyObject;
        row["c"] = "PRIVMSG"; row["ch"] = buffer; row["x"] = text;
        row[oldTimestamp ? "timestamp" : "t"] = timestamp;
        if (eid > 0) row["eid"] = eid;
        // Seed the pre-lineage on-disk format through Redis, not copied Lua.
        redis.getDb().lpush(key, row.toString());
        redis.getDb().expire(key, 60);
    }

    IRCRawEvent event(string buffer, long eid, string msgid) {
        auto e = IRCRawEvent("ArchiveFixture", "PRIVMSG");
        e.networkId = network; e.channel = buffer; e.nick = "fixture";
        e.text = msgid; e.timestampMs = 1_800_000_000_000L + eid;
        e.eid = eid; e.setParams([buffer, msgid]); e.addTag("msgid", msgid);
        return e;
    }

    void appendEvent(IRCRawEvent e) {
        auto key = list(e.channel);
        companion(key); dedup(e.channel); dedup(e.channel, true);
        check(buffers.appendIRCEvent(e, server), "new fixture event was rejected");
        token(key);
    }

    string[] rows(string key) {
        string[] result;
        foreach (raw; redis.getDb().lrange(key, 0, -1)) result ~= raw.idup;
        return result;
    }

    string[] texts(string key) {
        string[] result;
        foreach (raw; rows(key)) result ~= parseJsonString(raw)["x"].get!string;
        return result;
    }

    Json freeze(string buffer, long cutoff, long timestamp) {
        ensureContext();
        auto id = operation();
        companion(list(buffer)); companion(list(buffer, true));
        auto created = archiveHarnessCreateGroup(context, id, user, network, buffer, timestamp, server, id);
        if (created == "full") return Json(null);
        check(created.length && created[0] == '{', "real group capture failed: " ~ created);
        foreach (scopeServer; scopes) {
            own(archiveLookupKey(scopeServer, id));
            auto observationContext = context;
            observationContext.localServer.serverId = scopeServer;
            auto observationDeadline = MonoTime.currTime + 2.seconds;
            bool observed;
            do {
                observed = archiveHarnessObserve(observationContext, id, user, network, buffer);
                if (!observed) sleep(5.msecs);
            } while (!observed && MonoTime.currTime < observationDeadline);
            check(observed, "real durable-ID lookup failed");
        }
        // The same production freeze script receives run-owned Redis keys;
        // no global allocator reset or synthetic frozen group is necessary.
        auto eidKey = own("archive-buffer-fixture:" ~ server ~ ":eid:" ~ id);
        auto assignmentKey = own("archive-buffer-fixture:" ~ server ~ ":assignments");
        redis.getDb().set(eidKey, (cutoff - 1).to!string);
        redis.getDb().hset(assignmentKey, network, server);
        auto raw = archiveHarnessFreeze(context, id, user, network, buffer, timestamp, eidKey, assignmentKey);
        if (raw == "full") return Json(null);
        check(raw.length && raw[0] == '{', "real global freeze failed: " ~ raw);
        auto group = parseJsonString(raw);
        check(group["cutoffEid"].get!long == cutoff
            && group["legacyTimestampCutoffMs"].get!long == timestamp, "freeze did not preserve fixture cutoff");
        foreach (token; group["scopedLineageIds"]) if (token.get!string.length) locator(token.get!string);
        if (group["legacyLineageId"].get!string.length) locator(group["legacyLineageId"].get!string);
        return group;
    }

    Json pinFrozen(Json group, string scopeServer = "") {
        check(group.type == Json.Type.object, "cannot pin rejected global freeze");
        if (!scopeServer.length) scopeServer = server;
        auto id = group["operationId"].get!string;
        own("irc:archive:pin:" ~ scopeServer ~ ":" ~ id);
        own("irc:archive:redis-applied:" ~ scopeServer ~ ":" ~ id);
        own("irc:archive:pins:" ~ scopeServer);
        auto scopeContext = context;
        scopeContext.localServer.serverId = scopeServer;
        return archiveHarnessPin(scopeContext, id, user, network,
            group["buffer"].get!string, group["cutoffEid"].get!long,
            group["legacyTimestampCutoffMs"].get!long);
    }

    Json pin(string buffer, long cutoff, long timestamp, string id = "") {
        ensureContext();
        if (id.length) return archiveHarnessPin(context, id, user, network, buffer, cutoff, timestamp);
        auto group = freeze(buffer, cutoff, timestamp);
        return group.type == Json.Type.object ? pinFrozen(group) : Json(null);
    }

    void release(Json pin) {
        auto scopeContext = context;
        scopeContext.localServer.serverId = pin["serverId"].get!string;
        check(archiveHarnessRelease(scopeContext, pin["operationId"].get!string), "final lineage release failed");
    }

    string apply(Json frozen) {
        ArchiveRecord record;
        record.kind = ArchiveKind.purge;
        record.operationId = frozen["operationId"].get!string;
        record.ownerId = frozen["userId"].get!string;
        record.serverId = frozen["serverId"].get!string;
        record.networkId = frozen["networkId"].get!string;
        record.channel = frozen["buffer"].get!string;
        record.cutoffEid = frozen["cutoffEid"].get!long;
        record.legacyCutoffMs = frozen["legacyTimestampCutoffMs"].get!long;
        record.scopedLineageId = frozen["scopedLineageId"].get!string;
        record.legacyLineageId = frozen["legacyLineageId"].get!string;
        EngineContext ctx;
        ctx.redis = redis;
        ctx.localServer.serverId = server;
        return applyArchiveRedisPurge(ctx, record).to!string;
    }

    string[] members(string key) {
        string[] result;
        foreach (member; redis.getDb().smembers(key)) result ~= member.idup;
        return result;
    }

    void waitAbsent(string key) {
        auto deadline = MonoTime.currTime + 5.seconds;
        while (redis.getDb().exists(key) && MonoTime.currTime < deadline) sleep(20.msecs);
        check(!redis.getDb().exists(key), "key did not expire: " ~ key);
    }

    ArchiveSpoolStatus nativeStatus(MonoTime deadline) {
        ArchiveSpoolStatus status;
        while (!context.archiveSpool.tryStatus(status)) {
            check(MonoTime.currTime < deadline, "native status unavailable before fixture deadline");
            sleep(1.msecs);
        }
        return status;
    }

    void cleanup() {
        check(tasksQuiescent, "live fixture tasks remain; owned journal/Redis cleanup refused");
        if (context.archiveSpool !is null)
            check(context.archiveSpool.shutdown(5.seconds, ArchiveShutdown.producersDrained),
                "native journal failed to stop; root retained");
        if (nativeRootCreated) {
            stat_t status;
            check(lstat(nativeRoot.toStringz, &status) == 0 && S_ISDIR(status.st_mode)
                && status.st_uid == geteuid() && (status.st_mode & 511) == 448
                && readText(buildPath(nativeRoot, "owner")) == server, "native cleanup ownership check failed");
            rmdirRecurse(nativeRoot);
        }
        // Catch lineage tokens created by a partially failed assertion/call.
        foreach (key; owned.dup) if (key.startsWith("scrollback:")) {
            auto value = redis.getDb().get("irc:archive:lineage:buffer:" ~ key);
            if (value.length) discover("irc:archive:lineage:id:" ~ value.idup);
        }
        foreach_reverse (key; owned) redis.getDb().del(key);
    }
}

private void renameChoices(Fixture f) {
    auto a = f.list("alice"), b = f.list("bob");
    auto la = f.list("alice", true), lb = f.list("bob", true);
    auto da = f.dedup("alice"), db = f.dedup("bob");
    auto sa = f.dedup("alice", true), sb = f.dedup("bob", true);
    f.companion(a); f.companion(b); f.companion(la); f.companion(lb);
    f.append("alice", 10, 100, "scoped-source");
    f.append("bob", 11, 100, "scoped-destination");
    f.legacy("alice", 12, 100, "legacy-source");
    f.redis.getDb().sadd(da, "network-source");
    f.redis.getDb().sadd(db, "network-destination");
    f.redis.getDb().sadd(sa, "scoped-source");
    f.redis.getDb().expire(la, 60); f.redis.getDb().expire(sa, 60);
    auto beforeA = f.token(a), beforeB = f.token(b);
    check(f.buffers.renameBuffer(f.server, f.network, "alice", "bob"), "legacy/set move not reported");
    check(f.texts(a) == ["scoped-source"] && f.texts(b) == ["scoped-destination"],
        "RENAMENX clobbered or moved a colliding scoped list");
    check(f.token(a) == beforeA && f.token(b) == beforeB, "collision changed scoped lineage");
    check(!f.redis.getDb().exists(la) && f.texts(lb) == ["legacy-source"], "independent legacy move failed");
    check(f.token(lb).length > 0, "legacy move did not establish lineage");
    check(f.members(da) == ["network-source"]
        && f.members(db) == ["network-destination"], "dedup collision was overwritten");
    check(!f.redis.getDb().exists(sa) && f.members(sb) == ["scoped-source"],
        "dedup RENAMENX decision was incorrectly coupled to list collision");
    check(f.redis.getDb().ttl(lb) > 0 && f.redis.getDb().ttl(lb) <= 60
        && f.redis.getDb().ttl(sb) > 0 && f.redis.getDb().ttl(sb) <= 60, "rename reset or lost TTL");
    check(!f.buffers.renameBuffer(f.server, f.network, "alice", "bob"), "collision/missing-source retry moved data");
}

private void cutoffPreserves(Fixture f) {
    auto scoped = f.list("#cut"), legacy = f.list("#cut", true);
    auto currentDedup = f.dedup("#cut"), oldDedup = f.dedup("#cut", true);
    f.append("#cut", 40, 9_999, "old-eid-future-time");
    f.append("#cut", 51, 1, "new-eid-old-time");
    f.append("#cut", 0, 100, "legacy-at-cutoff");
    f.append("#cut", 0, 101, "legacy-newer");
    f.legacy("#cut", 40, 9_999, "old-eid-future-time");
    f.legacy("#cut", 51, 1, "new-eid-old-time");
    f.legacy("#cut", 0, 100, "legacy-at-cutoff", true);
    f.legacy("#cut", 0, 101, "legacy-newer", true);
    f.redis.getDb().sadd(currentDedup, "newer-identity");
    f.redis.getDb().sadd(oldDedup, "legacy-newer-identity");
    foreach (key; [scoped, legacy, currentDedup, oldDedup]) f.redis.getDb().expire(key, 60);
    auto frozen = f.pin("#cut", 50, 100);
    check(frozen.type == Json.Type.object, "cutoff capture rejected");
    auto retry = f.pin("#cut", 500, 1_000, frozen["operationId"].get!string);
    check(retry == frozen, "capture retry replaced the original cutoff or incarnation");
    check(f.redis.getDb().hget(f.locator(frozen["scopedLineageId"].get!string), "refs") == "1",
        "capture retry acquired a second lineage reference");
    f.append("#cut", 52, 1, "post-freeze");
    f.redis.getDb().expire(scoped, 60);
    auto before = f.redis.getDb().ttl(scoped);
    check(f.apply(frozen) == "applied", "first cutoff application failed");
    check(f.texts(scoped) == ["post-freeze", "legacy-newer", "new-eid-old-time"],
        "positive eid must dominate timestamp; newer scoped order changed");
    check(f.texts(legacy) == ["legacy-newer", "new-eid-old-time"],
        "eid-absent timestamp/legacy timestamp cutoff or legacy order is wrong");
    foreach (key; [scoped, legacy, currentDedup, oldDedup])
        check(f.redis.getDb().ttl(key) > 0 && f.redis.getDb().ttl(key) <= before,
            "purge reset or lost remaining TTL");
    check(f.members(currentDedup) == ["newer-identity"]
        && f.members(oldDedup) == ["legacy-newer-identity"], "newer rows lost dedup");
    auto first = f.rows(scoped), firstLegacy = f.rows(legacy);
    f.append("#cut", 53, 1, "after-ack");
    check(f.apply(frozen) == "applied", "idempotent retry was rejected");
    check(f.rows(scoped)[1 .. $] == first && f.rows(legacy) == firstLegacy,
        "retry rewrote or removed rows arriving after first application");
    auto conflict = parseJsonString(frozen.toString());
    conflict["userId"] = "different-owner";
    check(f.apply(conflict) == "conflict", "marker accepted reused operation ID with different owner");
    conflict = parseJsonString(frozen.toString()); conflict["cutoffEid"] = 500L;
    check(f.apply(conflict) == "conflict", "retry changed frozen cutoff");
    f.release(frozen);
}

private void dedupSurvives(Fixture f) {
    auto old = f.event("#dedup", 10, "old");
    auto newer = f.event("#dedup", 30, "newer");
    f.appendEvent(old); f.appendEvent(newer);
    auto frozen = f.pin("#dedup", 20, 1_900_000_000_000L);
    check(f.apply(frozen) == "applied", "cutoff failed");
    check(f.texts(f.list("#dedup")) == ["newer"], "newer deduplicated event did not survive");
    check(!f.buffers.appendIRCEvent(newer, f.server), "purge discarded surviving dedup identity");
    f.release(frozen);
    auto all = f.pin("#dedup", 40, 1_900_000_000_000L);
    check(f.apply(all) == "applied", "full cutoff failed");
    check(!f.redis.getDb().exists(f.list("#dedup")) && !f.redis.getDb().exists(f.dedup("#dedup")),
        "empty buffer retained dedup");
    f.release(all);
    check(f.buffers.appendIRCEvent(newer, f.server), "empty-buffer clear permanently suppressed refill");
    f.token(f.list("#dedup"));
}

private void crossScopeDedup(Fixture f) {
    const other = f.server ~ "-other";
    f.addScope(other);
    const otherList = f.own("scrollback:" ~ other ~ ":" ~ f.network ~ ":#shared");
    f.companion(otherList);
    f.own("dedup:" ~ other ~ ":" ~ f.network ~ ":#shared");
    f.appendEvent(f.event("#shared", 10, "old-scope-message"));
    auto group = f.freeze("#shared", 20, 1_900_000_000_000L);
    auto local = f.pinFrozen(group);
    auto newer = f.event("#shared", 30, "other-scope-newer");
    check(f.buffers.appendIRCEvent(newer, other), "post-cutoff other-scope append failed");
    f.token(otherList);
    check(f.apply(local) == "applied" && !f.redis.getDb().exists(f.list("#shared")),
        "original scope did not clear its frozen prefix");
    check(!f.buffers.appendIRCEvent(newer, other) && f.texts(otherList) == ["other-scope-newer"],
        "an empty original scope discarded another scope's surviving dedup identity");
    auto remote = f.pinFrozen(group, other);
    check(f.apply(remote) == "applied" && !f.buffers.appendIRCEvent(newer, other),
        "authoritative absence in the old freeze cleared newer-scope dedup");
    f.release(local); f.release(remote);
    auto next = f.freeze("#shared", 40, 1_900_000_000_000L);
    local = f.pinFrozen(next);
    remote = f.pinFrozen(next, other);
    check(f.apply(local) == "applied" && f.apply(remote) == "applied",
        "later explicit clear did not clear every original scope");
    check(!f.redis.getDb().exists(f.dedup("#shared")) && f.buffers.appendIRCEvent(newer, other),
        "globally empty buffer did not reset its shared dedup set");
    f.token(otherList);
    f.release(local); f.release(remote);
}

private void frozenRenameReuse(Fixture f) {
    auto a = f.list("alice"), b = f.list("bob"), c = f.list("carol");
    auto la = f.list("alice", true), lb = f.list("bob", true), lc = f.list("carol", true);
    foreach (key; [b, c, lb, lc]) f.companion(key);
    f.append("alice", 10, 100, "original-scoped");
    f.legacy("alice", 11, 100, "original-legacy");
    auto group = f.freeze("alice", 20, 200);
    auto originalToken = group["scopedLineageIds"][0].get!string;
    // Both moves occur AFTER the all-scope global barrier but BEFORE local
    // journal pin transfer, the window that reusable-name capture cannot cover.
    check(f.buffers.renameBuffer(f.server, f.network, "alice", "bob"), "first rename failed");
    check(f.token(b) == originalToken, "physical incarnation did not follow first RENAMENX");
    check(f.buffers.renameBuffer(f.server, f.network, "bob", "carol"), "second rename failed");
    check(f.token(c) == originalToken, "physical incarnation did not follow second RENAMENX");
    f.append("alice", 12, 100, "reused-scoped-before-cutoff");
    f.legacy("alice", 13, 100, "reused-legacy-before-cutoff");
    f.append("bob", 14, 100, "reused-intermediate-before-cutoff");
    auto frozen = f.pinFrozen(group);
    auto reusedToken = f.token(a);
    check(reusedToken != originalToken, "reused name inherited the retired incarnation");
    auto da = f.dedup("alice"), dc = f.dedup("carol");
    f.redis.getDb().sadd(da, "reused"); f.redis.getDb().sadd(dc, "original");
    check(f.apply(frozen) == "applied", "renamed purge failed");
    check(f.texts(a) == ["reused-scoped-before-cutoff"] && f.texts(la) == ["reused-legacy-before-cutoff"]
        && f.texts(b) == ["reused-intermediate-before-cutoff"],
        "frozen purge deleted a reused name even though its eid predates cutoff");
    check(!f.redis.getDb().exists(c) && !f.redis.getDb().exists(lc), "frozen original was not cleared after multiple renames");
    check(f.redis.getDb().exists(da) && !f.redis.getDb().exists(dc), "dedup did not follow physical surviving ownership");
    check(f.apply(frozen) == "applied" && f.token(a) == reusedToken, "retry changed reused incarnation");
    f.release(frozen);
}

private void multiScopeFreeze(Fixture f) {
    auto second = f.server ~ "-old";
    f.addScope(second);
    auto primary = f.list("alice");
    auto old = f.own("scrollback:" ~ second ~ ":" ~ f.network ~ ":alice");
    auto moved = f.own("scrollback:" ~ second ~ ":" ~ f.network ~ ":bob");
    auto movedLegacy = f.list("bob", true);
    foreach (key; [old, moved, movedLegacy]) f.companion(key);
    f.append("alice", 1, 1, "primary-old");
    auto row = parseJsonString(`{"c":"PRIVMSG","eid":2,"t":1,"x":"historical-old"}`);
    f.buffers.appendMessage(second, f.network, "alice", row);
    f.token(old);
    f.legacy("alice", 3, 1, "legacy-old");
    auto group = f.freeze("alice", 20, 200);
    check(group["scopedLineageIds"].length == 2, "global barrier did not freeze both archival scopes");
    // The old archival engine can rename/reuse its original name before its
    // local pin arrives. A current-name capture at that later time is unsafe.
    check(f.buffers.renameBuffer(second, f.network, "alice", "bob"), "old-scope rename failed");
    row["eid"] = 4L; row["x"] = "historical-reused";
    f.buffers.appendMessage(second, f.network, "alice", row);
    f.token(old); f.token(moved); f.token(movedLegacy);
    f.legacy("alice", 5, 1, "legacy-reused");
    f.append("alice", 30, 1, "primary-newer");
    auto primaryPin = f.pinFrozen(group);
    check(primaryPin["legacyLineageId"].get!string.length > 0, "coordinator lost frozen legacy scope");
    check(f.apply(primaryPin) == "applied" && f.texts(primary) == ["primary-newer"],
        "coordinator did not apply its frozen scoped cutoff");
    auto delayedPin = f.pinFrozen(group, second);
    check(delayedPin["legacyLineageId"].get!string == "", "non-coordinator acquired legacy scope twice");
    check(f.apply(delayedPin) == "applied", "delayed original scope purge failed");
    check(!f.redis.getDb().exists(moved) && !f.redis.getDb().exists(movedLegacy),
        "globally frozen original histories survived delayed-scope purge");
    check(f.texts(old) == ["historical-reused"] && f.texts(f.list("alice", true)) == ["legacy-reused"],
        "delayed scope recaptured a reused physical name");
    f.release(primaryPin); f.release(delayedPin);
}

private void absentIsAuthoritative(Fixture f) {
    auto a = f.list("absent"), legacy = f.list("absent", true);
    f.companion(a); f.companion(legacy);
    auto frozen = f.pin("absent", 100, 200);
    check(frozen["scopedLineageId"].get!string == "" && frozen["legacyLineageId"].get!string == "",
        "absent buffer must be frozen as empty tokens");
    check(!f.redis.getDb().exists(a) && !f.redis.getDb().exists(legacy)
        && !f.redis.getDb().exists(f.companion(a)), "capture created an empty physical buffer");
    f.append("absent", 1, 1, "later-scoped");
    f.legacy("absent", 2, 1, "later-legacy");
    auto created = f.token(a);
    check(f.apply(frozen) == "applied", "authoritative absence application failed");
    check(f.texts(a) == ["later-scoped"] && f.texts(legacy) == ["later-legacy"],
        "empty token was resolved to a newly created reusable name");
    check(f.token(a) == created && f.apply(frozen) == "applied", "absence retry replaced new incarnation");
    f.release(frozen);
}

private void pinLifetime(Fixture f) {
    auto key = f.list("ttl");
    f.append("ttl", 30, 100, "newer");
    f.redis.getDb().expire(key, 1);
    auto frozen = f.pin("ttl", 20, 200);
    auto location = f.locator(frozen["scopedLineageId"].get!string);
    auto companion = f.companion(key);
    check(f.redis.getDb().ttl(location) == -1 && f.redis.getDb().ttl(companion) == -1,
        "pending lineage evidence must not expire with list TTL");
    f.waitAbsent(key);
    check(f.redis.getDb().exists(location) && f.redis.getDb().exists(companion), "pending evidence expired");
    f.append("ttl", 1, 1, "new-incarnation");
    check(f.redis.getDb().exists(location), "reuse deleted pinned empty proof");
    check(f.apply(frozen) == "applied" && f.texts(key) == ["new-incarnation"],
        "expired original resolved to reused buffer");
    auto marker = "irc:archive:redis-applied:" ~ f.server ~ ":" ~ frozen["operationId"].get!string;
    check(f.redis.getDb().ttl(marker) == -1, "pending result marker began retention before durable completion");
    f.release(frozen);
    check(!f.redis.getDb().exists(location), "final release leaked retired empty proof");
    check(f.redis.getDb().ttl(marker) > 0 && f.redis.getDb().ttl(marker) <= 604800,
        "completed result did not start seven-day expiry");
    f.release(frozen);
    f.append("ttl", 30, 100, "retained-newer");
    auto live = f.pin("ttl", 20, 200);
    check(f.apply(live) == "applied", "live release cutoff failed");
    auto liveLocator = f.locator(live["scopedLineageId"].get!string);
    f.redis.getDb().expire(key, 1);
    f.release(live);
    check(f.redis.getDb().ttl(liveLocator) >= 0 && f.redis.getDb().ttl(liveLocator) <= 1,
        "final live release did not inherit remaining buffer expiry");
    f.waitAbsent(key); f.waitAbsent(liveLocator); f.waitAbsent(f.companion(key));
}

private void pinCapacity(Fixture f) {
    auto key = f.list("bounded");
    f.append("bounded", 1, 1, "pending");
    Json[] pins;
    foreach (i; 0 .. 128) {
        auto pin = f.pin("bounded", 10, 20);
        check(pin.type == Json.Type.object, "pending pin rejected before fixed bound");
        pins ~= pin;
    }
    auto before = f.rows(key);
    auto rejected = f.pin("bounded", 10, 20);
    check(rejected.type == Json.Type.null_, "129th pin evicted/admitted beyond fixed bound");
    check(f.redis.getDb().scard("irc:archive:pins:" ~ f.server) == 128,
        "pending registry exceeded its fixed bound or evicted an older operation");
    foreach (pin; pins)
        check(f.redis.getDb().exists("irc:archive:pin:" ~ f.server ~ ":" ~ pin["operationId"].get!string),
            "capacity pressure evicted pending operation");
    check(f.rows(key) == before, "pin capacity failure mutated buffer");
    check(f.apply(pins[0]) == "applied", "oldest pending operation lost lineage under pressure");
    foreach (pin; pins) {
        check(f.apply(pin) == "applied", "pending empty-incarnation proof was evicted");
        f.release(pin);
    }
    check(f.redis.getDb().scard("irc:archive:pins:" ~ f.server) == 0,
        "final releases did not reclaim local pin capacity");
}

/// Real Mongo majority catalog -> real Redis projection -> fresh controller ->
/// actual processor/native replay. There is no registered-scope assumption.
private void preparedDestinationAdmission(Fixture f, string redisUrl, bool requestedRecovery = false) {
    const uri = environment.get("IRCFIBER_ARCHIVE_TEST_MONGO_URL", "");
    check(environment.get("IRCFIBER_ARCHIVE_TEST_ISOLATED", "") == "1"
        && !uri.matchFirst(regex(
            `^mongodb://(127\.0\.0\.1|localhost|\[::1\]):([0-9]+)/(?:[A-Za-z0-9_-]+)?\?replicaSet=[A-Za-z0-9_-]+$`)).empty,
        "scope admission case requires the explicit isolated loopback Mongo fixture");
    AppMongoConnection.connect(uri, "ircfiber_archive_scope_test_" ~ randomUUID().toString().replace("-", ""));
    auto database = AppMongoConnection.getDb();
    void command(Bson request) {
        auto reply = database.runCommandUnchecked(request);
        check(reply["ok"].type == Bson.Type.double_ && reply["ok"].get!double == 1,
            "scope fixture Mongo command failed");
        foreach (key, value; reply.byKeyValue) {
            check(key != "writeConcernError", "scope fixture Mongo write concern failed");
            if (key == "writeErrors")
                check(value.type == Bson.Type.array && !value.length, "scope fixture Mongo write failed");
        }
    }
    const ownership = randomUUID().toString();
    auto cleanup = Bson.emptyObject;
    cleanup["delete"] = Bson("networks");
    cleanup["deletes"] = Bson([Bson(["q": Bson(["id": Bson(f.network), "archiveFixtureOwner": Bson(ownership)]),
        "limit": Bson(1)])]);
    cleanup["writeConcern"] = Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
    bool inserted;
    scope(exit) if (inserted) command(cleanup);
    f.ensureContext();
    f.context.messageRepo = new MessageRepository;
    auto destination = new ArchiveControl;
    // A structurally valid Redis projection is not proof the canonical Mongo
    // network exists, even if it already names this destination.
    check(!destination.prepareScope(f.context, f.network, f.user),
        "Redis-only witness manufactured destination admission");
    check(!destination.scopeReady(f.network), "missing canonical network became ready");
    auto insert = Bson.emptyObject;
    insert["insert"] = Bson("networks");
    insert["documents"] = Bson([Bson(["_id": Bson(f.network), "id": Bson(f.network), "userId": Bson(f.user),
        "archiveFixtureOwner": Bson(ownership)])]);
    insert["writeConcern"] = Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
    inserted = true; // An uncertain insertion still needs exact-owner cleanup.
    command(insert);
    check(!destination.prepareScope(f.context, f.network, randomUUID().toString()),
        "majority catalog accepted a mismatched canonical owner");
    NetworkConfig network;
    auto networkCursor = f.network, ownerCursor = f.user;
    network.id = parseUUID(networkCursor);
    network.name = "ArchiveFixture"; network.nick = "fixture"; network.host = "archive-fixture.invalid";
    f.context.connManager.addNetwork(network, parseUUID(ownerCursor));
    if (requestedRecovery) {
        requestedIntentRecovery(f, network);
        return;
    }
    // Discard the test's synthetic catalog. All positive evidence below must
    // be installed by the actual strictly acknowledged source controller.
    f.redis.getDb().del(archiveOwnerKey(f.network));
    auto sourceContext = f.context;
    sourceContext.localServer.serverId = f.server ~ "-source";
    auto source = new ArchiveControl;
    check(source.prepareScope(sourceContext, f.network, f.user), "source majority registration failed");
    check(source.prepareHandoff(sourceContext, f.network, f.server),
        "source did not durably register both handoff scopes");
    auto projected = parseJsonString(f.redis.getDb().get(archiveOwnerKey(f.network)));
    check(projected["servers"].length == 2 && projected["serverId"].get!string == sourceContext.localServer.serverId,
        "handoff lost source attribution or destination catalog membership");
    f.context.archiveControl = new ArchiveControl;
    check(!f.context.archiveControl.scopeReady(f.network), "new destination was unexpectedly warm");
    check(f.context.archiveControl.prepareScope(f.context, f.network, f.user),
        "cold destination failed strict preparation of already registered provenance");
    f.own(RedisKeys.server(f.server));
    f.own(archiveProjectionKey(f.server, f.network));
    f.context.serverRegistry = new ServerRegistry(f.redis);
    f.tasksQuiescent = false;
    scope(exit) {
        f.context.archiveControl.stop();
        const deadline = MonoTime.currTime + 5.seconds;
        while (!f.context.archiveControl.isStopped() && MonoTime.currTime < deadline) sleep(10.msecs);
        check(f.context.archiveControl.isStopped(), "prepared controller still owns fixture context");
        f.context.serverRegistry.unregisterServer(f.server);
        f.tasksQuiescent = true;
    }
    f.context.archiveControl.start(f.context);
    check(f.context.archiveControl.scopeReady(f.network),
        "controller startup discarded acknowledged destination readiness");
    pausedProcessorShutdown(f, redisUrl, true);
}

/// Actual Mongo ownership/catalog, Redis request reservation, processor FIFO
/// and native journal recovery. No warm-scope assumption or fabricated anchor.
private void requestedIntentRecovery(Fixture f, NetworkConfig network) {
    check(!f.redis.getDb().hget(RedisKeys.networkAssignments(), f.network).length,
        "requested-intent fixture assignment already exists");
    f.redis.getDb().hset(RedisKeys.networkAssignments(), f.network, f.server);
    scope(exit) {
        check(f.redis.getDb().hget(RedisKeys.networkAssignments(), f.network) == f.server,
            "requested-intent assignment ownership changed; cleanup refused");
        f.redis.getDb().hdel(RedisKeys.networkAssignments(), f.network);
    }
    const buffer = "#requested";
    const id = f.operation(), queryId = f.operation(), foreignId = f.operation();
    foreach (operation; [id, queryId, foreignId]) f.own(archiveOperationKey(f.server, operation));
    f.own("irc:archive:completed-projections:" ~ f.server);
    f.own(RedisKeys.server(f.server));
    f.own(archiveProjectionKey(f.server, f.network));
    f.context.serverRegistry = new ServerRegistry(f.redis);
    f.append(buffer, 1, 1, "before-intent");
    auto created = archiveHarnessCreateGroup(f.context, id, f.user, f.network, buffer,
        1_800_000_000_000L, f.server, id);
    check(created.length && created[0] == '{', "requested group was not reserved");
    auto query = parseJsonString(archiveHarnessCreateGroup(f.context, queryId, f.user,
        f.network, buffer, 1_800_000_000_000L, f.server, queryId));
    // Historical status placeholders are deliberately not deletion intent.
    query["queryOnly"] = true;
    f.redis.getDb().set(archiveClearGroupKey(queryId), query.toString());
    const foreignUser = randomUUID().toString();
    created = archiveHarnessCreateGroup(f.context, foreignId, foreignUser, f.network,
        buffer, 1_800_000_000_000L, f.server, foreignId);
    check(created.length && created[0] == '{', "foreign placeholder setup failed");
    f.context.archiveControl = new ArchiveControl;
    bool processorStarted, processorDone;
    string processorFailure;
    size_t retriesStarted, retriesDone;
    void startProcessor() {
        processorDone = false; processorStarted = true;
        runTask(() nothrow {
            scope(exit) processorDone = true;
            try startEventProcessor(f.context);
            catch (Throwable error) { processorFailure = error.msg; }
        });
    }
    void quiesce() {
        const deadline = MonoTime.currTime + 5.seconds;
        while (retriesDone != retriesStarted && MonoTime.currTime < deadline) sleep(5.msecs);
        check(retriesDone == retriesStarted, "retry tasks still own fixture context");
        if (processorStarted && !processorDone)
            check(f.context.archiveControl.awaitShutdownBarrier(f.context, deadline),
                "requested-intent FIFO failed to drain");
        while (processorStarted && !processorDone && MonoTime.currTime < deadline) sleep(5.msecs);
        check(!processorStarted || processorDone, "requested-intent processor still owns fixture context");
        f.context.archiveControl.stop();
        while (!f.context.archiveControl.isStopped() && MonoTime.currTime < deadline) sleep(5.msecs);
        check(f.context.archiveControl.isStopped(), "requested-intent controller still owns fixture context");
        f.tasksQuiescent = true;
        check(!processorFailure.length, "requested-intent processor failed: " ~ processorFailure);
    }
    f.tasksQuiescent = false;
    scope(exit) {
        quiesce();
        f.context.serverRegistry.unregisterServer(f.server);
    }
    auto request = ControlMessage("archiveClear", f.network);
    request.userId = f.user;
    request.config = Json(["operationId": Json(id), "buffer": Json(buffer)]);
    // The initial authenticated dispatch arrives before scope readiness.
    f.context.archiveControl.accept(f.context, request);
    foreach (_; 0 .. 8) f.context.archiveControl.accept(f.context, request);
    check(f.context.eventChannel.bufferFill == 1, "duplicate same-ID dispatch duplicated FIFO admission");
    startProcessor();
    check(f.context.archiveControl.awaitShutdownBarrier(f.context, MonoTime.currTime + 5.seconds),
        "initial request did not cross actual FIFO");
    quiesce();
    auto initial = parseJsonString(f.redis.getDb().get(archiveClearGroupKey(id)));
    check(initial["cutoffEid"].get!long == 0
        && f.nativeStatus(MonoTime.currTime + 2.seconds).durableSequence == 0,
        "unready initial dispatch manufactured an archive anchor");
    // A true cold controller and reopened journal have no RAM intent/admission.
    check(f.context.archiveSpool.shutdown(5.seconds, ArchiveShutdown.producersDrained),
        "pre-anchor journal did not stop");
    f.context.archiveSpool = new ArchiveSpool(f.nativeConfig);
    auto recoveryDeadline = MonoTime.currTime + 5.seconds;
    ArchiveSpoolStatus recovered;
    do {
        recovered = f.nativeStatus(recoveryDeadline);
        if (!recovered.ready) sleep(5.msecs);
    } while (!recovered.ready && MonoTime.currTime < recoveryDeadline);
    check(recovered.ready && !recovered.failed && recovered.durableSequence == 0,
        "cold journal was not empty and ready");
    f.context.eventChannel = EngineEventChannel.create();
    f.context.connManager = new ConnectionManager(f.context.eventChannel, f.redis, f.server, null);
    auto ownerCursor = f.user;
    f.context.connManager.addNetwork(network, parseUUID(ownerCursor));
    f.context.archiveControl = new ArchiveControl;
    check(!f.context.archiveControl.scopeReady(f.network), "cold controller retained warm admission");
    f.tasksQuiescent = false;
    startProcessor();
    // GET-like probes alone must not upgrade the query-only placeholder.
    auto statusProbe = request;
    statusProbe.config = Json(["operationId": Json(queryId), "buffer": Json(buffer), "statusOnly": Json(true)]);
    f.context.archiveControl.accept(f.context, statusProbe);
    f.context.archiveControl.start(f.context);
    ArchiveOperationStatus admitted;
    const deadline = MonoTime.currTime + 15.seconds;
    bool durable;
    do {
        const lookup = f.context.archiveSpool.lookupOperationById(id, f.user, f.server, f.network, admitted);
        durable = lookup == ArchiveLookup.found && admitted.durable();
        if (!durable) sleep(10.msecs);
    } while (!durable && MonoTime.currTime < deadline);
    check(durable && admitted.state == ArchiveOperationState.admitted
        && f.context.archiveControl.scopeReady(f.network),
        "requested intent did not recover through strict Mongo preparation and real FIFO");
    const cutoff = admitted.cutoffEid, timestamp = admitted.legacyCutoffMs;
    check(cutoff > 0 && timestamp > 0, "recovered intent lacks its frozen boundary");
    for (size_t i; i < 8; ++i) {
        ++retriesStarted;
        const statusOnly = i % 2 == 0;
        runTask(() nothrow {
            scope(exit) ++retriesDone;
            try {
                auto retry = request;
                retry.config = Json(["operationId": Json(id), "buffer": Json(buffer),
                    "statusOnly": Json(statusOnly)]);
                f.context.archiveControl.accept(f.context, retry);
            } catch (Throwable error) { processorFailure = error.msg; }
        });
    }
    // Let the background cursor inspect every placeholder and repeated intent.
    sleep(4.seconds);
    quiesce();
    auto finalGroup = parseJsonString(f.redis.getDb().get(archiveClearGroupKey(id)));
    auto untouched = parseJsonString(f.redis.getDb().get(archiveClearGroupKey(queryId)));
    auto foreign = parseJsonString(f.redis.getDb().get(archiveClearGroupKey(foreignId)));
    check(finalGroup["operationId"].get!string == id && finalGroup["cutoffEid"].get!long == cutoff
        && finalGroup["legacyTimestampCutoffMs"].get!long == timestamp
        && f.nativeStatus(MonoTime.currTime + 2.seconds).durableSequence == 1,
        "concurrent same-ID status/retry allocated another cutoff or native record");
    check(untouched["queryOnly"].get!bool && untouched["cutoffEid"].get!long == 0
        && foreign["cutoffEid"].get!long == 0,
        "background progression admitted a query-only or unauthenticated placeholder");
    check(f.context.archiveSpool.shutdown(5.seconds, ArchiveShutdown.producersDrained),
        "admitted journal did not stop");
    f.context.archiveSpool = new ArchiveSpool(f.nativeConfig);
    string encoded; ulong sequence;
    const replayDeadline = MonoTime.currTime + 5.seconds;
    while (!f.context.archiveSpool.tryPeek(encoded, sequence) && MonoTime.currTime < replayDeadline) sleep(5.msecs);
    check(encoded.length > 0, "recovered requested intent is absent from native replay");
    auto record = decodeArchiveRecord(encoded, sequence);
    check(record.kind == ArchiveKind.purge && record.operationId == id && record.cutoffEid == cutoff
        && record.legacyCutoffMs == timestamp && sequence == 1,
        "cold replay did not retain exactly the recovered requested intent");
}

private void pausedProcessorShutdown(Fixture f, string redisUrl, bool preparedScope = false) {
    f.ensureContext();
    NetworkConfig network;
    auto networkCursor = f.network;
    network.id = parseUUID(networkCursor);
    network.name = "ArchiveFixture";
    network.nick = "fixture";
    network.host = "archive-fixture.invalid";
    // addNetwork defers start: the real owner exists, but no IRC DIAL/task is
    // needed for this processor/Redis/native-journal regression.
    auto ownerCursor = f.user;
    if (!f.context.connManager.hasNetwork(network.id))
        f.context.connManager.addNetwork(network, parseUUID(ownerCursor));
    check(f.context.connManager.getOwnerId(network.id) == f.user,
        "processor fixture lacks canonical local ownership");
    check(f.context.archiveWorker is null, "shutdown fixture must not wait for a Mongo worker");
    if (!preparedScope) {
    const catalogKey = archiveOwnerKey(f.network);
    const catalog = f.redis.getDb().get(catalogKey).idup;
    check(catalog.length > 0, "scope assumption requires the real fixture catalog");
    f.redis.getDb().del(catalogKey);
    scope(failure) f.redis.getDb().set(catalogKey, catalog);
    check(!archiveHarnessAssumeRegisteredScope(f.context, f.network),
        "scope seam accepted missing catalog provenance");
    f.redis.getDb().set(catalogKey, catalog);
    // Mongo registration semantics are covered independently. Only that
    // precondition is assumed here; processor, Redis I/O, FIFO ack and native
    // fsync/recovery below are all the real implementations.
    bool scopeAssumed;
    const scopeDeadline = MonoTime.currTime + 1.seconds;
    while (MonoTime.currTime < scopeDeadline) {
        if (archiveHarnessAssumeRegisteredScope(f.context, f.network)) {
            scopeAssumed = true;
            break;
        }
        sleep(1.msecs);
    }
    check(scopeAssumed && f.context.archiveControl.scopeReady(f.network),
        "registered-scope assumption did not enable real processor admission");
    check(!f.context.archiveControl.scopeReady(f.operation()),
        "registered-scope assumption enabled an unrelated network");
    } else {
        check(f.context.archiveControl !is null && f.context.archiveControl.scopeReady(f.network),
            "strictly prepared destination was not ready before its first processor event");
    }

    const buffer = "#shutdown";
    const key = f.list(buffer);
    f.companion(key);
    f.dedup(buffer); f.dedup(buffer, true);
    f.own(RedisKeys.userStream(f.user));
    auto event = f.event(buffer, 1, "paused-processor-" ~ f.server);
    const expectedTimestamp = event.timestampMs;
    const expectedText = event.text;
    auto authority = redisUrl[8 .. $];
    const slash = authority.indexOf('/');
    if (slash >= 0) authority = authority[0 .. slash];
    const colon = authority.lastIndexOf(':');
    const host = authority[0 .. colon];
    check(host == "127.0.0.1" || host == "localhost",
        "CLIENT PAUSE requires the explicit loopback disposable Redis fixture");
    auto pauseConnection = connectTCP(host, authority[colon + 1 .. $].to!ushort);
    scope(exit) pauseConnection.close();
    pauseConnection.readTimeout = 2.seconds;

    bool processorStarted, processorDone, stopStarted, stopDone, resumeStarted, resumeDone;
    string processorError, stopError, resumeError;
    MonoTime stopBegan, stopFinished;
    // Always quiesce both event-loop tasks before Fixture.cleanup touches its
    // native journal or Redis keys, including an assertion failure mid-pause.
    void quiesceTasks() {
        if (processorStarted) {
            if (!stopStarted) {
                stopStarted = true;
                try stopArchive(f.context);
                catch (Exception error) { stopError = error.msg; }
                stopDone = true;
            }
            auto deadline = MonoTime.currTime + 5.seconds;
            while (!stopDone && MonoTime.currTime < deadline) sleep(10.msecs);
            check(stopDone, "shutdown task still owns fixture context; cleanup refused");
            if (!processorDone) {
                check(f.context.archiveControl.awaitShutdownBarrier(f.context, deadline),
                    "processor FIFO did not quiesce; cleanup refused");
                while (!processorDone && MonoTime.currTime < deadline) sleep(10.msecs);
            }
            check(processorDone, "processor still owns fixture context; cleanup refused");
        }
        auto resumeDeadline = MonoTime.currTime + 2.seconds;
        while (!resumeDone && resumeStarted && MonoTime.currTime < resumeDeadline) sleep(10.msecs);
        check(!resumeStarted || resumeDone, "pause observer still owns fixture connection");
        f.tasksQuiescent = true;
    }
    scope(exit) quiesceTasks();

    // Native ingress is empty when the actual processor becomes suspended on
    // Redis INCR. The old RAM-only shutdown incorrectly declared this clean.
    pauseConnection.write("CLIENT PAUSE 500 ALL\r\n");
    pauseConnection.flush();
    const pausedAt = MonoTime.currTime;
    check((cast(const(char)[]) pauseConnection.readLine(128)).idup.strip == "+OK",
        "fixture Redis did not acknowledge bounded CLIENT PAUSE ALL");
    pauseConnection.write("PING\r\n");
    pauseConnection.flush();
    resumeStarted = true;
    f.tasksQuiescent = false;
    runTask(() nothrow {
        try {
            if ((cast(const(char)[]) pauseConnection.readLine(128)).idup.strip != "+PONG")
                resumeError = "unexpected pause-observer reply";
        } catch (Exception error) { resumeError = error.msg; }
        resumeDone = true;
    });
    f.context.eventChannel.put(event);
    check(f.context.eventChannel.bufferFill == 1, "fixture event was not queued before processor start");
    processorStarted = true;
    runTask(() nothrow {
        try startEventProcessor(f.context);
        catch (Exception error) { processorError = error.msg; }
        processorDone = true;
    });
    const pulledDeadline = pausedAt + 200.msecs;
    while (f.context.eventChannel.bufferFill && MonoTime.currTime < pulledDeadline) sleep(1.msecs);
    check(f.context.eventChannel.bufferFill == 0 && !processorDone && !resumeDone
        && MonoTime.currTime < pulledDeadline,
        "did not observe the real processor consume its event while Redis I/O was paused");
    auto status = f.nativeStatus(pausedAt + 300.msecs);
    check(status.ready
        && status.ingressCommands == 0 && status.durableSequence == 0,
        "pre-shutdown event was already journaled instead of awaiting Redis");
    stopBegan = MonoTime.currTime;
    stopStarted = true;
    runTask(() nothrow {
        try stopArchive(f.context);
        catch (Exception error) { stopError = error.msg; }
        stopFinished = MonoTime.currTime;
        stopDone = true;
    });
    const fencedDeadline = pausedAt + 300.msecs;
    while (!f.context.eventChannel.producersDrained() && MonoTime.currTime < fencedDeadline) sleep(1.msecs);
    check(f.context.eventChannel.producersDrained(), "shutdown did not fence real producer ingress");
    bool rejected;
    try f.context.eventChannel.put(f.event(buffer, 2, "after-fence"));
    catch (Exception) { rejected = true; }
    check(rejected, "a producer entered behind the shutdown fence");
    sleep(40.msecs);
    check(MonoTime.currTime < pausedAt + 400.msecs && !resumeDone && !processorDone,
        "pre-resume shutdown assertion missed the bounded real Redis pause");
    status = f.nativeStatus(pausedAt + 400.msecs);
    check(!stopDone && !resumeDone
        && !status.stopping && !status.stopped && !status.cleanShutdown,
        "shutdown closed native ingress or claimed clean while processor awaited Redis I/O");

    const shutdownDeadline = stopBegan + 5.seconds;
    while ((!stopDone || !processorDone || !resumeDone) && MonoTime.currTime < shutdownDeadline)
        sleep(10.msecs);
    check(stopDone && processorDone && resumeDone && stopFinished < shutdownDeadline,
        "processor/native drain exceeded the one five-second shutdown deadline");
    check(!processorError.length && !stopError.length && !resumeError.length,
        "real shutdown task failed: " ~ processorError ~ stopError ~ resumeError);
    status = f.nativeStatus(shutdownDeadline);
    check(status.stopped && !status.failed
        && status.durableSequence == 1 && status.checkpoint == 0,
        "accepted processor row was not synced independently of Mongo");
    const rows = f.rows(key);
    check(rows.length == 1, "Redis lost accepted row or admitted the post-fence producer");
    const stored = parseJsonString(rows[0]);
    const acceptedEid = stored["eid"].get!long;
    check(acceptedEid > 0 && stored["x"].get!string == expectedText
        && stored["t"].get!long == expectedTimestamp, "Redis row changed original event identity");
    f.token(key);
    // Reopen the same owned disk journal. Do not acknowledge/checkpoint the
    // record: Mongo is deliberately absent, so recovery must replay it.
    f.context.archiveSpool = new ArchiveSpool(f.nativeConfig);
    string encoded;
    ulong sequence;
    const recoveryDeadline = stopBegan + 5.seconds;
    bool recovered;
    while (MonoTime.currTime < recoveryDeadline) {
        if (f.context.archiveSpool.tryTake(encoded, sequence)) { recovered = true; break; }
        sleep(10.msecs);
    }
    check(recovered, "accepted Redis row missing from durable journal after reopen/recovery");
    auto record = decodeArchiveRecord(encoded, sequence);
    event.eid = acceptedEid;
    const expectedCompact = event.toCompactJson();
    check(record.kind == ArchiveKind.append && sequence == 1 && record.serverId == f.server
        && record.networkId == f.network && record.channel == buffer && record.eid == acceptedEid
        && record.timestampMs == expectedTimestamp && parseJsonString(record.compactJson) == expectedCompact,
        "recovered journal row differs from the processor-accepted Redis event");
    foreach (string field, value; stored)
        check(expectedCompact[field] == value, "Redis and recovered event disagree on " ~ field);
    status = f.nativeStatus(recoveryDeadline);
    check(status.checkpoint == 0 && status.gapCount > 0,
        "shutdown must retain conservative producer-fence uncertainty, not claim gap-free history");
    check(MonoTime.currTime < recoveryDeadline,
        "shutdown plus durable replay proof exceeded five seconds without Mongo");
}
private bool fencedIngressPreservesBlockedTail() {
    auto events = EngineEventChannel.create();
    void releaseWaiters() {
        events.fence();
        IRCRawEvent discarded;
        while (events.tryConsumeOne(discarded, Duration.zero)) {}
        if (events.producersDrained()) events.close();
    }
    scope(exit) releaseWaiters();
    auto waitingTask = Task.getThis();
    auto timeout = setTimer(3.seconds, { waitingTask.interrupt(); });
    scope(exit) timeout.stop();
    foreach (i; 0 .. events.bufferSize) {
        IRCRawEvent event;
        event.eid = i + 1;
        events.put(event);
    }
    bool entered, completed, accepted;
    runTask(() nothrow {
        entered = true;
        try {
            IRCRawEvent tail;
            tail.eid = events.bufferSize + 1;
            events.put(tail);
            accepted = true;
        } catch (Exception) {}
        completed = true;
    });
    const deadline = MonoTime.currTime + 2.seconds;
    while (!entered && MonoTime.currTime < deadline) sleep(1.msecs);
    events.fence();
    const blocked = entered && !completed && !events.producersDrained();
    bool rejected;
    try { events.put(IRCRawEvent.init); }
    catch (Exception) { rejected = true; }
    IRCRawEvent event;
    bool ordered = events.tryConsumeOne(event, Duration.zero) && event.eid == 1;
    while (!completed && MonoTime.currTime < deadline) sleep(1.msecs);
    foreach (i; 1 .. events.bufferSize + 1) {
        ordered = events.tryConsumeOne(event, Duration.zero) && event.eid == i + 1 && ordered;
    }
    const drained = events.producersDrained();
    const empty = !events.tryConsumeOne(event, Duration.zero);
    events.close();
    return blocked && rejected && accepted && completed && drained && ordered && empty;
}

private void runFixtures(RedisStorage redis, string run, string redisUrl) {
    runCase("event ingress fence preserves a blocked pre-fence tail in FIFO order and rejects later producers", {
        check(fencedIngressPreservesBlockedTail(), "full-ring admission fence lost or reordered accepted events");
    });
    uint index;
    void fixtureCase(string name, void delegate(Fixture) test) {
        runCase(name, {
            auto fixture = new Fixture(redis, run, ++index);
            scope (exit) fixture.cleanup();
            test(fixture);
        });
    }
    fixtureCase("independent scoped/legacy RENAMENX choices preserve destination, dedup and TTL", (f) { renameChoices(f); });
    fixtureCase("cutoff keeps newer scoped/legacy order, dedup and TTL; retries freeze identity", (f) { cutoffPreserves(f); });
    fixtureCase("dedup protects newer rows and permits refill only after empty-buffer purge", (f) { dedupSurvives(f); });
    fixtureCase("migration preserves other-scope dedup until every scoped buffer is empty", (f) { crossScopeDedup(f); });
    fixtureCase("frozen A-to-B rename cannot purge a reused A incarnation", (f) { frozenRenameReuse(f); });
    fixtureCase("all-scope global freeze protects delayed historical scope from renamed/reused buffers", (f) { multiScopeFreeze(f); });
    fixtureCase("empty frozen tokens are authoritative absence, not a newly created buffer", (f) { absentIsAuthoritative(f); });
    fixtureCase("pending pins survive expiry; final release starts bounded retention", (f) { pinLifetime(f); });
    fixtureCase("fixed pin capacity rejects new intent without evicting pending proof", (f) { pinCapacity(f); });
    fixtureCase("shutdown drains an actual processor suspended on real Redis I/O into durable replay", (f) {
        pausedProcessorShutdown(f, redisUrl);
    });
    fixtureCase("strict source handoff prepares a cold destination before its first real processor event", (f) {
        preparedDestinationAdmission(f, redisUrl);
    });
    fixtureCase("unanchored authenticated clear survives cold restart and concurrent status/retry without admitting probes", (f) {
        preparedDestinationAdmission(f, redisUrl, true);
    });
}

int main() {
    auto url = environment.get("IRCFIBER_ARCHIVE_TEST_REDIS_URL", "");
    auto run = environment.get("IRCFIBER_ARCHIVE_TEST_RUN_ID", "");
    if (environment.get("IRCFIBER_ARCHIVE_TEST_DISPOSABLE", "") != "1"
        || !isCanonicalArchiveOperationId(run) || !url.startsWith("redis://")
        || url.length <= 8 || url.indexOf('@') >= 0) {
        stderr.writeln("archive-buffer: explicit disposable Redis URL, DISPOSABLE=1 and canonical RUN_ID required");
        stderr.writeln("Result: 1 cases, 0 passed, 1 failed");
        return 1;
    }
    // RedisStorage currently uses database zero only; refuse misleading /N URLs.
    auto slash = url[8 .. $].indexOf('/');
    if (slash >= 0 && url[8 + slash .. $] != "/" && url[8 + slash .. $] != "/0") {
        stderr.writeln("archive-buffer: only explicit database 0 fixture URLs are supported");
        stderr.writeln("Result: 1 cases, 0 passed, 1 failed");
        return 1;
    }
    auto authority = slash >= 0 ? url[8 .. 8 + slash] : url[8 .. $];
    auto colon = authority.lastIndexOf(':');
    bool validEndpoint = colon > 0 && colon + 1 < authority.length;
    uint port;
    if (validEndpoint) {
        foreach (c; authority[0 .. colon])
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) validEndpoint = false;
        foreach (c; authority[colon + 1 .. $]) {
            if (c < '0' || c > '9' || port > 6553) { validEndpoint = false; break; }
            port = port * 10 + c - '0';
        }
    }
    if (!validEndpoint || port == 0 || port > 65535) {
        stderr.writeln("archive-buffer: fixture URL must contain an explicit host and valid port");
        stderr.writeln("Result: 1 cases, 0 passed, 1 failed");
        return 1;
    }
    runTask(() nothrow {
        RedisStorage redis;
        try {
            redis = new RedisStorage();
            redis.connectFromUrl(url); redis.ping();
            runFixtures(redis, run, url);
        } catch (Throwable error) {
            cases++; failed++;
            try stderr.writeln("  FAIL fixture setup/cleanup: ", error.msg);
            catch (Exception) {}
        }
        if (redis !is null) redis.close();
        try stderr.writeln("Result: ", cases, " cases, ", passed, " passed, ", failed, " failed");
        catch (Exception) {}
        exitEventLoop();
    });
    runEventLoop();
    return failed ? 1 : 0;
}
