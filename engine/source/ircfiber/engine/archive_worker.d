module ircfiber.engine.archive_worker;

import core.time : msecs;
import vibe.core.core : runTask, sleep;
import ircfiber.engine.archive_spool;
import ircfiber.db.messages : MessageRepository, ArchiveWriteException, ArchiveWriteFailure;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.network_write_gate : NetworkWriter, runNetworkWrite;
import ircfiber.logging : logJsonMap;
import std.algorithm : canFind;
import ircfiber.db.network : NetworkRepository;

version (RoutingPolicyTest)
void runHeldPendingCatalogArchiveRegressionChecks(RedisStorage redis, MessageRepository repository,
        NetworkRepository networks, string holderAddress, string holderToken) {
    import std.exception : enforce;
    enforce(holderAddress.length && holderToken.length, "Explicit isolated real holder endpoint/token required");
    runPendingCatalogArchiveRegressionChecks(redis, repository, networks, holderAddress, holderToken);
}

version (RoutingPolicyTest)
void runPendingCatalogArchiveRegressionChecks(RedisStorage redis, MessageRepository repository,
        NetworkRepository networks, string holderAddress = "", string holderToken = "") {
    import std.exception : enforce;
    import std.file : tempDir, mkdir, rmdirRecurse, exists;
    import std.path : buildPath;
    import std.string : endsWith, toStringz;
    import std.uuid : randomUUID;
    import std.datetime : Clock;
    import core.time : seconds, MonoTime;
    import core.sys.posix.sys.stat : chmod;
    import vibe.data.bson : Bson;
    import vibe.data.json : Json;
    import ircfiber.db.mongo : AppMongoConnection;
    import ircfiber.models.network : NetworkConfig;
    import ircfiber.engine.bootstrap : EngineContext;
    import ircfiber.engine.event_channel : EngineEventChannel;
    import ircfiber.engine.archive_control : ArchiveControl;
    import ircfiber.irc.manager : ConnectionManager;
    import ircfiber.irc.registry : ServerRegistry;
    import ircfiber.redis.protocol : RedisKeys;
    import ircfiber.network_write_gate : NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY;
    import ircfiber.archive_protocol : archiveOwnerKey;
    import ircfiber.storage.buffer : BufferManager;
    import ircfiber.models.irc_event : IRCRawEvent;
    import ircfiber.engine.processor : startEventProcessor;
    import ircfiber.holder_client : HolderClient, HolderEntry, DialRequest;
    import ircfiber.engine.session_snapshot : SessionSnapshot, toJSON, fromJSON;
    import ircfiber.models.network : TLSMode;
    import vibe.core.net : listenTCP, TCPConnection, TCPListener;
    import vibe.stream.operations : readLine;
    enforce(AppMongoConnection.name().endsWith("_test"), "Raw replay proof requires a test Mongo database");
    auto db = redis.getDb();
    enforce(!db.exists(NETWORK_WRITE_EXCLUSION_KEY) && db.scard(NETWORK_WRITERS_KEY) == 0,
        "Raw replay proof requires dedicated quiescent Redis");
    const operation = randomUUID().toString();
    const server = "raw-catalog-" ~ operation;
    const root = buildPath(tempDir(), "pending-catalog-" ~ operation);
    enforce(!exists(root), "Raw replay fixture directory already exists");
    mkdir(root);
    enforce(chmod(root.toStringz, 448) == 0, "Raw replay fixture mode failed");
    auto collection = AppMongoConnection.getDb()["networks"];
    auto messages = AppMongoConnection.getDb()["messages"];
    string[] ids;
    ArchiveSpool spool;
    ArchiveWorker worker;
    ArchiveControl control;
    EngineContext ctx;
    bool processorStarted, processorDone;
    string processorError;
    HolderClient heldClient;
    HolderEntry heldEntry;
    SessionSnapshot heldSnapshot;
    TCPListener listener;
    TCPConnection upstream;
    bool upstreamDone, readersDetached = true;
    ulong retainedSequence;
    void awaitState(scope bool delegate() predicate, string reason) {
        const deadline = MonoTime.currTime + 10.seconds;
        while (!predicate() && MonoTime.currTime < deadline) sleep(10.msecs);
        enforce(predicate(), reason);
    }
    void stop() {
        if (!readersDetached && ctx.connManager !is null) {
            ctx.connManager.detachAllForHotSwap();
            readersDetached = true;
        }
        if (processorStarted) {
            enforce(control.awaitShutdownBarrier(ctx, MonoTime.currTime + 5.seconds),
                "Raw processor FIFO barrier did not drain");
            awaitState({ return processorDone; }, "Raw event processor did not stop");
            enforce(!processorError.length, "Raw event processor failed");
            processorStarted = false;
        }
        if (control !is null) {
            control.stop();
            awaitState({ return control.isStopped(); }, "Controller did not stop");
            control = null;
        }
        if (worker !is null) {
            worker.requestStop();
            awaitState({ return worker.isStopped(); }, "Archive worker did not stop");
            worker = null;
        }
        if (spool !is null) {
            spool.requestShutdown(5.seconds, ArchiveShutdown.producersDrained);
            awaitState({
                ArchiveSpoolStatus state;
                return spool.tryStatus(state) && state.stopped;
            }, "Native journal did not stop");
            ArchiveSpoolStatus retained;
            enforce(spool.tryStatus(retained), "Cannot observe stopped durable sequence");
            retainedSequence = retained.durableSequence;
            spool = null;
        }
    }
    scope(exit) {
        stop();
        ctx.eventChannel.close();
        if (heldClient !is null && heldEntry.id.length) {
            heldClient.closeClaim(heldEntry.id, heldEntry.instance, heldEntry.connectedAtMs, "raw archive test complete");
            heldClient.forgetClaim(heldEntry.id, heldEntry.instance, heldEntry.connectedAtMs);
        }
        if (upstream !is null) {
            upstream.close();
            awaitState({ return upstreamDone; }, "Real IRC fixture did not stop");
        }
        if (listener !is null) listener.stopListening();
        db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
            [NETWORK_WRITE_EXCLUSION_KEY], operation);
        foreach (id; ids) {
            collection.deleteOne(Bson(["id": Bson(id)]));
            messages.deleteMany(Bson(["networkId": Bson(id)]));
            db.hdel(RedisKeys.networkAssignments(), id);
            db.del(archiveOwnerKey(id));
            if (ctx.bufferManager !is null) ctx.bufferManager.clearNetworkBuffers(server, id);
        }
        rmdirRecurse(root);
    }
    ArchiveSpoolConfig config;
    config.maxBytes = 64 * 1024 * 1024;
    config.minFreeBytes = 0;
    config.diagnosticPath = "";
    void open(string name) {
        config.directory = buildPath(root, name);
        if (!exists(config.directory)) {
            mkdir(config.directory);
            enforce(chmod(config.directory.toStringz, 448) == 0, "Native journal mode failed");
        }
        spool = new ArchiveSpool(config);
        awaitState({
            ArchiveSpoolStatus state;
            return spool.tryStatus(state) && state.ready && !state.failed;
        }, "Native journal did not recover");
    }
    auto id = randomUUID();
    auto owner = randomUUID();
    ids ~= id.toString();
    NetworkConfig cfg;
    cfg.id = id; cfg.name = "pending-catalog"; cfg.host = "pending.invalid"; cfg.nick = "pending";
    if (holderAddress.length) {
        listener = listenTCP(0, (TCPConnection peer) {
            upstream = peer;
            try {
                peer.write(":archive-fixture 001 pending :actual wire welcome\r\n");
                peer.flush();
                while (true) readLine(peer, 4096);
            } catch (Exception) {}
            upstreamDone = true;
        }, "127.0.0.1");
        cfg.host = "127.0.0.1";
        cfg.port = listener.bindAddress.port;
        cfg.tls = TLSMode.disabled;
    }
    networks.save(cfg, owner);
    cfg = networks.findByIdWithIpv6Iid(id);
    if (holderAddress.length) {
        heldClient = new HolderClient(server, holderAddress, holderToken);
        heldClient.connectControl();
        DialRequest request;
        request.host = cfg.host; request.port = cfg.port; request.tls = "none";
        request.tag.networkId = id.toString(); request.tag.userId = owner.toString();
        request.tag.name = cfg.name;
        auto established = heldClient.dial(request, null);
        const welcome = (cast(const(char)[]) readLine(established.stream, 4096)).idup;
        enforce(welcome.canFind(" 001 pending "), "Real held socket never received actual wire welcome");
        heldSnapshot.wasConnected = true;
        heldSnapshot.sessionNick = cfg.nick;
        heldSnapshot.connectedAtMs = established.connectedAtMs;
        heldSnapshot.graceful = true;
        heldSnapshot.activeRoute = "direct";
        heldClient.setMeta(established.id, toJSON(heldSnapshot));
        established.stream.close();
        awaitState({
            heldEntry = heldClient.info(established.id);
            return !heldEntry.attached && heldEntry.state == "open";
        }, "Real holder did not retain detached registered socket");
    }
    ctx.bufferManager = new BufferManager(redis);
    db.hset(RedisKeys.networkAssignments(), id.toString(), server);
    auto channel = EngineEventChannel.create();
    ctx.redis = redis; ctx.networkRepo = networks; ctx.messageRepo = repository;
    ctx.localServer.serverId = server;
    ctx.eventChannel = channel;
    ctx.holder = heldClient;
    ctx.connManager = new ConnectionManager(channel, redis, server, heldClient);
    if (heldClient is null) ctx.connManager.addNetwork(cfg, owner);
    ctx.serverRegistry = new ServerRegistry(redis);
    open("release-restart");
    ctx.archiveSpool = spool;
    control = new ArchiveControl;
    ctx.archiveControl = control;
    auto closed = db.eval!long(
        "if redis.call('EXISTS',KEYS[1]) ~= 0 or redis.call('SCARD',KEYS[2]) ~= 0 then return 0 end redis.call('SET',KEYS[1],ARGV[1]); return 1",
        [NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY], operation);
    enforce(!closed.empty && closed.front == 1, "Could not acquire real catalog exclusion");
    worker = new ArchiveWorker(spool, repository, null, redis);
    ctx.archiveWorker = worker;
    worker.start();
    control.start(ctx);
    void attachRetained() {
        bool checkedNegativeBindings;
        ctx.connManager.prepareHeldArchiveScope =
            (const ref NetworkConfig canonical, typeof(owner) canonicalOwner, const ref HolderEntry claim) {
                if (!checkedNegativeBindings) {
                auto badConfig = cfg;
                badConfig.id = randomUUID();
                enforce(!control.admitHeldScope(ctx, badConfig, canonicalOwner, claim),
                    "Mismatched canonical config seeded held raw admission");
                auto badClaim = heldEntry;
                badClaim.tag.userId = randomUUID().toString();
                enforce(!control.admitHeldScope(ctx, canonical, canonicalOwner, badClaim)
                    && !control.pendingScopeOwner(id.toString(), owner.toString()).length,
                    "Mismatched held entry seeded raw admission");
                auto wrongOwner = randomUUID();
                auto wrongContext = ctx;
                wrongContext.connManager = new ConnectionManager(ctx.eventChannel, redis, server);
                wrongContext.connManager.addNetwork(cfg, wrongOwner);
                enforce(!control.admitHeldScope(wrongContext, canonical, canonicalOwner, claim)
                    && !control.pendingScopeOwner(id.toString(), owner.toString()).length,
                    "Mismatched manager owner seeded held raw admission");
                    checkedNegativeBindings = true;
                }
                enforce(control.admitHeldScope(ctx, canonical, canonicalOwner, claim),
                    "Strict canonical/manager/held binding did not admit raw before ATTACH");
            };
        ctx.connManager.attachNetwork(cfg, owner, heldEntry, heldSnapshot);
        readersDetached = false;
        awaitState({
            return ctx.connManager.getClient(id) !is null && ctx.connManager.getClient(id).getConnected
                && control.pendingScopeOwner(id.toString(), owner.toString()) == owner.toString()
                && !control.scopeReady(id.toString());
        }, "Real held restore did not preserve pending admission while excluded");
    }
    if (heldClient !is null) attachRetained();
    else enforce(!control.prepareScope(ctx, id.toString(), owner.toString())
        && control.pendingScopeOwner(id.toString(), owner.toString()) == owner.toString()
        && !control.pendingScopeOwner(id.toString(), randomUUID().toString()).length,
        "Closed catalog did not retain exact validated producer owner only");
    bool acceptedRaw(string text) {
        foreach (row; db.lrange!string("scrollback:" ~ server ~ ":" ~ id.toString() ~ ":#raw", 0, -1))
            if (row.canFind(text)) return true;
        return false;
    }
    const payload = Json(["eid": Json(1L), "t": Json(Clock.currTime.toUnixTime!long * 1000),
        "m": Json("pending raw line")]).toString();
    auto raw = IRCRawEvent(cfg.name, "PRIVMSG");
    raw.networkId = id.toString(); raw.channel = "#raw"; raw.nick = "fixture";
    raw.text = "pending raw line"; raw.timestampMs = Clock.currTime.toUnixTime!long * 1000;
    raw.setParams(["#raw", raw.text]); raw.addTag("msgid", operation);
    if (heldClient is null) ctx.eventChannel.put(raw);
    processorStarted = true;
    runTask(() nothrow {
        try startEventProcessor(ctx);
        catch (Exception e) { processorError = e.msg; }
        processorDone = true;
    });
    if (heldClient !is null) {
        upstream.write("@msgid=" ~ operation ~ " :fixture!u@host PRIVMSG #raw :pending raw line\r\n");
        upstream.flush();
    }
    awaitState({
        ArchiveSpoolStatus state;
        return acceptedRaw("pending raw line") && spool.tryStatus(state) && state.durableSequence >= 1;
    }, "Raw ingress never reached real durable journal");
    sleep(200.msecs);
    ArchiveSpoolStatus state;
    enforce(spool.tryStatus(state) && !state.failed && state.checkpoint == 0
        && messages.findOne(["networkId": id.toString()]).isNull,
        "Closed catalog advanced Mongo history or journal checkpoint");
    stop();
    open("release-restart");
    if (heldClient !is null) {
        heldEntry = heldClient.info(heldEntry.id);
        heldSnapshot = fromJSON(heldEntry.meta);
        ctx.eventChannel = EngineEventChannel.create();
        ctx.connManager = new ConnectionManager(ctx.eventChannel, redis, server, heldClient);
        ctx.archiveSpool = spool;
        control = new ArchiveControl;
        ctx.archiveControl = control;
        control.start(ctx);
        attachRetained();
        processorDone = false;
        processorStarted = true;
        runTask(() nothrow {
            try startEventProcessor(ctx);
            catch (Exception e) { processorError = e.msg; }
            processorDone = true;
        });
        upstream.write("@msgid=" ~ operation ~ "-restart :fixture!u@host PRIVMSG #raw :pending raw line after restart\r\n");
        upstream.flush();
        awaitState({
            ArchiveSpoolStatus sample;
            return acceptedRaw("pending raw line after restart")
                && spool.tryStatus(sample) && sample.durableSequence > retainedSequence;
        }, "Restored held reader after journal restart did not retain new raw line");
    }
    worker = new ArchiveWorker(spool, repository, null, redis);
    worker.start();
    sleep(200.msecs);
    enforce(spool.tryStatus(state) && state.checkpoint == 0
        && messages.findOne(["networkId": id.toString()]).isNull,
        "Restarted raw journal bypassed still-closed canonical catalog");
    if (heldClient !is null) {
        stop();
        open("release-restart");
        worker = new ArchiveWorker(spool, repository, null, redis);
        worker.start();
    }
    db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
        [NETWORK_WRITE_EXCLUSION_KEY], operation);
    awaitState({
        ArchiveSpoolStatus sample;
        return spool.tryStatus(sample) && sample.checkpoint == retainedSequence && !sample.failed;
    }, "Released catalog did not replay and checkpoint retained raw line");
    enforce(!messages.findOne(["networkId": id.toString()]).isNull
        && collection.findOne(["id": id.toString()])["archiveScopeVersion"].get!int == 1,
        "Released replay lacks actual history and canonical catalog");
    bool foundRaw, foundRestart;
    foreach (message; messages.find(["networkId": id.toString()])) {
        const text = message["payload"].get!string;
        foundRaw = foundRaw || text.canFind("pending raw line");
        foundRestart = foundRestart || text.canFind("pending raw line after restart");
    }
    enforce(foundRaw && (heldClient is null || foundRestart),
        "Actual held/raw lines were not replayed after exclusion release");
    stop();
    foreach (kind; ["transferred", "deleted", "unknown"]) {
        auto badId = randomUUID();
        ids ~= badId.toString();
        if (kind != "unknown") {
            auto bad = cfg; bad.id = badId;
            networks.save(bad, owner);
            if (kind == "transferred")
                collection.updateOne(Bson(["id": Bson(badId.toString())]),
                    Bson(["$set": Bson(["userId": Bson(randomUUID().toString())])]));
            else collection.deleteOne(Bson(["id": Bson(badId.toString())]));
        }
        open(kind);
        enforce(spool.tryAppend(server, badId.toString(), "#raw", 1, payload, owner.toString())
            == ArchiveAdmission.queued, "Negative fixture raw record was not journaled");
        worker = new ArchiveWorker(spool, repository, null, redis);
        worker.start();
        awaitState({
            ArchiveSpoolStatus sample;
            return spool.tryStatus(sample) && sample.failed;
        }, "Unproven raw ownership did not quarantine native journal");
        enforce(spool.tryStatus(state) && state.checkpoint == 0
            && messages.findOne(["networkId": badId.toString()]).isNull
            && db.scard(NETWORK_WRITERS_KEY) == 0,
            "Transferred/deleted/unknown owner received history or checkpoint");
        stop();
    }
}

/// Applied is an explicit strict acknowledgment, never a normal return from the
/// old best-effort appendMessage API. Uncertain replies must return retry.
enum ArchiveApplyResult { applied, retry, conflict }
alias ArchiveApply = ArchiveApplyResult delegate(ref const ArchiveRecord record);
/// Must execute the operation-ID-marked, cutoff + physical-lineage Redis
/// mutation. Replayed only without positive, durably persisted Redis evidence.
alias ArchiveRedisPurge = ArchiveApplyResult delegate(ref const ArchiveRecord record);

/// Exactly one consumer fiber, one borrowed durable record, one Mongo call.
/// The disk owner remains independent of this fiber and its retry deadlines.
final class ArchiveWorker {
    private ArchiveSpool spool;
    private ArchiveApply apply;
    private ArchiveRedisPurge redisPurge;
    private bool started, stopping, finished;
    private size_t consumers;

    this(ArchiveSpool spool, ArchiveApply apply, ArchiveRedisPurge redisPurge = null) {
        if (spool is null || apply is null) throw new Exception("archive_worker_requires_strict_binding");
        this.spool = spool;
        this.apply = apply;
        this.redisPurge = redisPurge;
    }

    /// Real production binding to the repository's strict raw-command APIs.
    /// Purges still require the caller's atomic, idempotent Redis stage.
    this(ArchiveSpool spool, MessageRepository repository, ArchiveRedisPurge redisPurge = null,
            RedisStorage redis = null) {
        if (spool is null || repository is null) throw new Exception("archive_worker_requires_repository");
        this.spool = spool;
        this.redisPurge = redisPurge;
        this.apply = (ref const ArchiveRecord record) {
            try {
                if (record.pendingCatalog) {
                    if (redis is null) return ArchiveApplyResult.retry;
                    // The raw journal owner survives process replacement.
                    // A real majority catalog read/CAS must establish that
                    // exact owner before either Mongo history or checkpoint.
                    return runNetworkWrite!ArchiveApplyResult(redis, (ref NetworkWriter writer) {
                        string[] scopes;
                        try scopes = repository.registerArchiveScopes(redis, record.networkId,
                            [record.serverId], record.ownerId, writer);
                        catch (ArchiveWriteException e) {
                            if (e.failure != ArchiveWriteFailure.identityMismatch
                                    && e.failure != ArchiveWriteFailure.invalidInput) throw e;
                            notePendingConflict(record, "canonical_owner_or_record_mismatch");
                            return ArchiveApplyResult.conflict;
                        }
                        if (!scopes.canFind(record.serverId)) {
                            notePendingConflict(record, "canonical_network_absent");
                            return ArchiveApplyResult.conflict;
                        }
                        applyRepositoryRecord(repository, record);
                        return ArchiveApplyResult.applied;
                    });
                }
                // Previously proven admission remains drainable after deletion.
                applyRepositoryRecord(repository, record);
                return ArchiveApplyResult.applied;
            } catch (ArchiveWriteException e) {
                if (e.failure == ArchiveWriteFailure.identityMismatch || e.failure == ArchiveWriteFailure.invalidInput) {
                    if (record.pendingCatalog) notePendingConflict(record, "canonical_owner_or_record_mismatch");
                    return ArchiveApplyResult.conflict;
                }
                return ArchiveApplyResult.retry;
            } catch (Exception) {
                return ArchiveApplyResult.retry;
            }
        };
    }

    private static void notePendingConflict(ref const ArchiveRecord record, string reason) {
        logJsonMap("error", "archive", "Pending raw journal quarantined; canonical provenance unavailable",
            ["event": "archive_pending_catalog_conflict", "networkId": record.networkId, "reason": reason]);
    }

    private static void applyRepositoryRecord(MessageRepository repository, ref const ArchiveRecord record) {
        final switch (record.kind) {
            case ArchiveKind.append:
                repository.appendArchivedCompactMessage(record.serverId, record.networkId,
                    record.channel, record.compactJson);
                break;
            case ArchiveKind.rename:
                repository.renameArchivedChannel(record.serverId, record.networkId,
                    record.channel, record.newChannel, record.cutoffEid, record.legacyCutoffMs);
                break;
            case ArchiveKind.purge:
                repository.deleteArchivedChannel(record.serverId, record.networkId,
                    record.channel, record.cutoffEid, record.legacyCutoffMs);
                break;
        }
    }

    /// No nominal started flag: successful runTask scheduling is required.
    void start() {
        if (started) return;
        if (stopping) throw new Exception("archive_worker_already_stopped");
        started = true;
        try runTask(() nothrow {
            try run();
            catch (Throwable) { spool.reportWorkerFailure(); }
        });
        catch (Throwable e) { started = false; spool.reportWorkerFailure(); throw e; }
    }
    /// Does not wait for Mongo backlog or cancel an uncertain write. The spool's
    /// shutdown closes ingress and drains RAM separately within five seconds.
    void requestStop() { stopping = true; }
    bool isStopped() const { return finished || (!started && stopping); }
    size_t activeConsumerFibers() const nothrow { return consumers; }

    private void run() {
        ++consumers;
        scope(exit) { --consumers; finished = true; apply = null; redisPurge = null; }
        string encoded;
        ulong sequence;
        bool durableRedisApplied;
        while (!stopping) {
            const availableGeneration = spool.progressGeneration();
            if (!spool.tryTake(encoded, sequence, durableRedisApplied)) {
                ArchiveSpoolProgress status;
                if (spool.tryProgress(status) && (status.failed || status.stopped || status.stopping)) return;
                spool.awaitProgress(availableGeneration, 100.msecs);
                continue;
            }
            ArchiveRecord record;
            try record = decodeArchiveRecord(encoded, sequence);
            catch (Exception) { spool.reportConflict(); return; }
            record.durableRedisApplied = durableRedisApplied;
            uint delayMs = 100;
            bool redisDone = record.kind != ArchiveKind.purge || durableRedisApplied;
            while (!stopping) {
                ArchiveSpoolProgress status;
                if (spool.tryProgress(status) && (status.failed || status.stopped || status.stopping)) return;
                ArchiveApplyResult result = ArchiveApplyResult.retry;
                try {
                    if (!redisDone) {
                        ArchiveOperationStatus retained;
                        if (spool.tryOperationStatus(record.operationId, retained)
                                && retained.sequence == sequence && retained.redisApplied) {
                            record.durableRedisApplied = true;
                            redisDone = true;
                        }
                    }
                    if (!redisDone) {
                        if (redisPurge !is null) result = redisPurge(record);
                        if (result == ArchiveApplyResult.conflict) { spool.reportConflict(); return; }
                        if (result == ArchiveApplyResult.applied) {
                            // RAM admission of a persistence request is not its
                            // durable ACK. Never reach Mongo before slot sync.
                            if (!persistRedisEvidence(record)) return;
                            redisDone = true;
                        }
                    }
                    if (redisDone) result = apply(record);
                } catch (Exception) { result = ArchiveApplyResult.retry; }
                if (result == ArchiveApplyResult.conflict) { spool.reportConflict(); return; }
                if (result == ArchiveApplyResult.applied && redisDone) {
                    while (!stopping) {
                        const generation = spool.progressGeneration();
                        if (spool.tryAcknowledge(sequence)) break;
                        if (spool.tryProgress(status) && (status.failed || status.stopped || status.stopping)) return;
                        spool.awaitProgress(generation, 100.msecs);
                    }
                    // Retain one in-flight record until the disk owner confirms
                    // durable checkpoint, not merely RAM acceptance of its ACK.
                    while (!stopping) {
                        const generation = spool.progressGeneration();
                        if (spool.tryProgress(status)) {
                            if (status.failed || status.stopped || status.stopping) return;
                            if (status.checkpoint >= sequence) break;
                        }
                        spool.awaitProgress(generation, 100.msecs);
                    }
                    break;
                }
                // Sleep in small slices so stop never waits for 30-second backoff.
                uint remaining = delayMs;
                while (remaining && !stopping) {
                    auto slice = remaining > 100 ? 100 : remaining;
                    sleep(slice.msecs);
                    remaining -= slice;
                }
                delayMs = delayMs >= 15_000 ? 30_000 : delayMs * 2;
            }
            encoded = null;
            record = ArchiveRecord.init;
        }
    }

    private bool persistRedisEvidence(ref ArchiveRecord record) {
        bool requested;
        while (!stopping) {
            const generation = spool.progressGeneration();
            ArchiveSpoolProgress status;
            if (spool.tryProgress(status) && (status.failed || status.stopped || status.stopping)) return false;
            if (!requested) requested = spool.tryMarkRedisApplied(record.operationId, record.sequence);
            ArchiveOperationStatus retained;
            if (spool.tryOperationStatus(record.operationId, retained)
                    && retained.sequence == record.sequence && retained.redisApplied) {
                record.durableRedisApplied = true;
                return true;
            }
            spool.awaitProgress(generation, 100.msecs);
        }
        return false;
    }
}
