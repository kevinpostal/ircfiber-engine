module ircfiber.engine.archive_control;

import core.time : msecs, seconds, MonoTime;
import std.datetime : Clock;
import std.array : empty;
import std.conv : to;
import std.uuid : parseUUID, randomUUID;
import vibe.core.core : runTask, sleep, setTimer;
import vibe.core.task : Task;
import vibe.data.json : Json, parseJsonString, serializeToJson;
import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.engine.archive_spool;
import ircfiber.engine.archive_worker : ArchiveApplyResult;
import ircfiber.archive_protocol : archiveProtocolVersion, archiveOwnerKey,
    archiveProjectionKey, archiveOperationKey, isCanonicalArchiveOperationId,
    archiveClearGroupKey, archiveClearGroupMaxBytes, validArchiveClearGroup, archiveLookupKey,
    archiveClearGroupIncludes, archiveOwnerServers, archiveInstallCatalogLua, archiveFreezeClearGroupLua,
    archiveCompleteGroupLua, archiveDispatchControlLua;
import ircfiber.redis.protocol : ControlMessage, RedisKeys;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.storage.buffer : archiveBufferLineageLua;
import ircfiber.models.network : normalizeChannelName;
import ircfiber.logging : logJsonMap;
import ircfiber.irc.routing_moves : isRoutingMoveId;

private long nowMs() { return Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L; }
private bool canonicalId(string id) { return isCanonicalArchiveOperationId(id); }
private bool validBuffer(string value) {
    if (!value.length || value.length > 512 || normalizeChannelName(value) != value) return false;
    foreach (c; value) if (c <= ' ' || c == '\x7f') return false;
    return true;
}

/// One bounded controller fiber; journal DTOs, never RAM admission, authorize
/// the early Redis stage. The FIFO worker independently verifies its marker.
final class ArchiveControl {
    private bool stopping, started;
    private bool acceptingControls = true, shutdownRequested, shutdownAcknowledged;
    private string shutdownNonce;
    private bool capabilityProjectionDirty = true;
    private long lastGapNotice, lastFailureNotice;
    private ArchiveOperationStatus[1_152] operations, projectedOperations;
    private bool[1_152] coordinationNeeded;
    private long[1_152] coordinationRetryAt;
    private ArchiveNetworkScope[1_024] networks;
    private string capturingOperationId;
    private ulong lastGapCount;
    private string[1_024] gapNoticeNetworks;
    private long[1_024] gapNoticeTimes;
    private size_t nextGapNoticeSlot;
    private struct ScopeRegistration {
        string networkId, preparedOwnerId;
        bool ready;
        long retryAtMs;
        string moveId, moveOwnerId, barrierNonce;
        ulong barrierAsked, barrierAcknowledged;
        bool barrierReady, barrierOrdered, releaseAfterBarrier, cleanupSent;
    }
    private ScopeRegistration[1_024] registrations;
    private size_t registrationCursor, lastRegistration = size_t.max;
    private ulong moveBarrierCounter;
    private struct AuthorizedClear {
        string nonce, operationId, userId, networkId, buffer;
        bool statusOnly;
        // Authorization survives queue backpressure and an interrupted put.
        // Only consumption may release it: interruption is not non-admission.
    }
    private AuthorizedClear[128] incoming;
    private size_t scopeRegistration(string network) {
        if (!canonicalId(network)) return size_t.max;
        if (lastRegistration < registrations.length && registrations[lastRegistration].networkId == network)
            return lastRegistration;
        size_t empty = size_t.max;
        foreach (i, ref entry; registrations) {
            if (entry.networkId == network) { lastRegistration = i; return i; }
            if (!entry.networkId.length && empty == size_t.max) empty = i;
        }
        if (empty != size_t.max) {
            registrations[empty].networkId = network;
            lastRegistration = empty;
        }
        return empty;
    }

    /// Nonblocking admission guard. Only preparation/controller fibers wait on
    /// Mongo; a Redis catalog alone never seeds this process-local admission.
    bool scopeReady(string network) {
        if (stopping || !started) return false;
        const index = scopeRegistration(network);
        return index != size_t.max && registrations[index].ready;
    }

    /// Prepare before starting a fresh producer, not on the event processor or
    /// a held relay's ATTACH/read path. This also works before start(): starting
    /// the controller must not discard a positively acknowledged preparation.
    /// The caller has already loaded/validated the canonical network owner.
    bool prepareScope(ref EngineContext ctx, string network, string expectedOwner) {
        if (stopping || shutdownRequested || ctx.messageRepo is null || !canonicalId(expectedOwner)) return false;
        const index = scopeRegistration(network);
        if (index == size_t.max) return false;
        if (registrations[index].ready && registrations[index].preparedOwnerId == expectedOwner) return true;
        registrations[index].ready = false;
        registrations[index].preparedOwnerId = null;
        const deadline = MonoTime.currTime + 5.seconds;
        auto waitingTask = Task.getThis();
        auto timer = setTimer(5.seconds, { waitingTask.interrupt(); });
        scope(exit) timer.stop();
        try {
            auto scopes = registerCatalog(ctx, network, "", expectedOwner);
            if (!scopes.length || MonoTime.currTime >= deadline) return false;
            installCatalog(ctx, network, scopes);
            // One total budget covers every yielding backend stage. A timed-out
            // write can have committed, but only a confirmed reply seeds ready.
            if (stopping || shutdownRequested || MonoTime.currTime >= deadline) return false;
            registrations[index].preparedOwnerId = expectedOwner;
            registrations[index].ready = true;
            registrations[index].retryAtMs = nowMs() + 300_000;
            return true;
        } catch (Exception) { return false; }
    }

    string movingOwner(string network) const {
        foreach (ref entry; registrations)
            if (entry.networkId == network && entry.moveId.length) return entry.moveOwnerId;
        return "";
    }

    void endMove(string network, string moveId) {
        foreach (ref entry; registrations) if (entry.networkId == network && entry.moveId == moveId) {
            if (entry.barrierAsked != entry.barrierAcknowledged) {
                entry.releaseAfterBarrier = true;
                return;
            }
            clearMove(entry);
            return;
        }
    }

    private static void clearMove(ref ScopeRegistration entry) {
        entry.moveId = null; entry.moveOwnerId = null; entry.barrierNonce = null;
        entry.barrierAsked = entry.barrierAcknowledged = 0;
        entry.barrierReady = entry.barrierOrdered = entry.releaseAfterBarrier = entry.cleanupSent = false;
    }

    private void drainMoveReleases(ref EngineContext ctx) {
        foreach (ref entry; registrations) if (entry.releaseAfterBarrier && !entry.cleanupSent) {
            // A timed-out put may not have admitted its marker. Resubmit one
            // bounded, idempotent marker; never discard the queued tail owner.
            entry.cleanupSent = true;
            IRCRawEvent marker;
            marker.command = "ARCHIVE_MOVE_BARRIER"; marker.networkId = entry.networkId;
            marker.text = entry.barrierNonce;
            try ctx.eventChannel.put(marker);
            catch (Exception e) { entry.cleanupSent = false; throw e; }
            return;
        }
    }

    /// Reaching this marker proves all earlier processor events were consumed.
    /// Pre-CLOSE refuses known work; post-quiescence also waits boundedly for
    /// the final accepted source mutations to checkpoint.
    bool awaitMoveBarrier(ref EngineContext ctx, string network, string moveId,
            string user, bool drainAfterClose) {
        if (stopping || !isRoutingMoveId(moveId) || !canonicalId(user)) return false;
        scopeReady(network);
        size_t index = size_t.max;
        foreach (i, ref entry; registrations) if (entry.networkId == network) { index = i; break; }
        if (index == size_t.max || moveBarrierCounter == ulong.max
                || (registrations[index].moveId.length && registrations[index].moveId != moveId)) return false;
        registrations[index].moveId = moveId;
        registrations[index].moveOwnerId = user;
        const barrier = ++moveBarrierCounter;
        registrations[index].barrierAsked = barrier;
        registrations[index].barrierAcknowledged = 0;
        registrations[index].barrierNonce = randomUUID().toString();
        const deadline = MonoTime.currTime + 5.seconds;
        auto waitingTask = Task.getThis();
        auto timer = setTimer(5.seconds, { waitingTask.interrupt(); });
        scope(exit) timer.stop();
        try {
            IRCRawEvent marker;
            marker.command = "ARCHIVE_MOVE_BARRIER"; marker.networkId = network;
            marker.text = registrations[index].barrierNonce;
            ctx.eventChannel.put(marker);
            while (registrations[index].barrierAcknowledged != barrier) {
                if (MonoTime.currTime >= deadline) return false;
                sleep(10.msecs);
            }
            if (!registrations[index].barrierOrdered) return false;
            if (!drainAfterClose && !registrations[index].barrierReady) return false;
            while (MonoTime.currTime < deadline) {
                ulong pending;
                if (scopeReady(network)
                        && ctx.archiveSpool.tryNetworkPending(ctx.localServer.serverId, network, pending)
                        && pending == 0) return true;
                if (!drainAfterClose) return false;
                sleep(10.msecs);
            }
        } catch (Exception) {}
        return false;
    }

    void consumeMoveBarrier(ref EngineContext ctx, ref const IRCRawEvent event) {
        foreach (ref entry; registrations) if (entry.networkId == event.networkId
                && entry.moveId.length && entry.barrierNonce.length && entry.barrierNonce == event.text) {
            const ordered = orderFrozenControls(ctx, event.networkId, long.max);
            ulong pending;
            entry.barrierOrdered = ordered;
            entry.barrierReady = ordered && entry.ready
                && ctx.archiveSpool.tryNetworkPending(ctx.localServer.serverId, event.networkId, pending)
                && pending == 0;
            entry.barrierAcknowledged = entry.barrierAsked;
            if (entry.releaseAfterBarrier) clearMove(entry);
            return;
        }
    }

    private bool allScopesReady() const {
        foreach (ref entry; registrations)
            if (entry.networkId.length && !entry.ready) return false;
        return true;
    }
    private string localScopeOwner(ref EngineContext ctx, string network) {
        auto cursor = network;
        const id = parseUUID(cursor);
        if (ctx.connManager !is null) {
            const owner = ctx.connManager.getOwnerId(id);
            if (owner.length) return owner;
        }
        return movingOwner(network);
    }


    private void registerRequestedScope(ref EngineContext ctx) {
        foreach (offset; 0 .. registrations.length) {
            const i = (registrationCursor + offset) % registrations.length;
            if (!registrations[i].networkId.length || nowMs() < registrations[i].retryAtMs
                    || (registrations[i].ready && registrations[i].moveId.length)) continue;
            registrationCursor = (i + 1) % registrations.length;
            registrations[i].retryAtMs = nowMs() + 30_000;
            try {
                // Offline historical controls have no current producer owner.
                // Active producers validate the same owner on the majority
                // catalog read; never infer it from the Redis projection.
                const owner = localScopeOwner(ctx, registrations[i].networkId);
                auto scopes = registerCatalog(ctx, registrations[i].networkId, "", owner);
                if (!scopes.length) {
                    ctx.redis.getDb().eval!string("redis.call('DEL', KEYS[1]); return '1'",
                        [archiveOwnerKey(registrations[i].networkId)], cast(string[])[]);
                    registrations[i] = ScopeRegistration.init;
                    return;
                }
                installCatalog(ctx, registrations[i].networkId, scopes);
                registrations[i].preparedOwnerId = owner;
                registrations[i].ready = true;
                registrations[i].retryAtMs = nowMs() + 300_000;
            } catch (Exception) {}
            return;
        }
    }


    private string[] registerCatalog(ref EngineContext ctx, string network, string target = "",
            string expectedOwner = "") {
        string[66] additions;
        size_t count;
        const raw = ctx.redis.getDb().get(archiveOwnerKey(network));
        if (raw.length) {
            if (raw.length > archiveClearGroupMaxBytes) throw new Exception("archive_owner_oversized");
            auto prior = archiveOwnerServers(parseJsonString(raw), network);
            if (prior.type != Json.Type.array) throw new Exception("archive_owner_unknown");
            foreach (server; prior) additions[count++] = server.get!string;
        }
        additions[count++] = ctx.localServer.serverId;
        if (target.length) additions[count++] = target;
        return ctx.messageRepo.registerArchiveScopes(network, additions[0 .. count], expectedOwner);
    }

    private void installCatalog(ref EngineContext ctx, string network, string[] scopes) {
        auto result = ctx.redis.getDb().eval!string(archiveInstallCatalogLua,
            [archiveOwnerKey(network)], [network, serializeToJson(scopes).toString(), nowMs().to!string]);
        if (result.empty || result.front != "1") throw new Exception("archive_scope_catalog_unavailable");
    }

    void stop() { acceptingControls = false; stopping = true; }
    bool isStopped() const { return stopping && !started; }

    /// Fence every producer at the shared channel boundary, including retired
    /// clients and consumer/background fibers. No socket-lifecycle inference.
    bool awaitShutdownBarrier(ref EngineContext ctx, MonoTime deadline) {
        acceptingControls = false;
        shutdownRequested = true;
        ctx.eventChannel.fence();
        while (!ctx.eventChannel.producersDrained()) {
            if (MonoTime.currTime >= deadline) return false;
            sleep(10.msecs);
        }
        if (MonoTime.currTime >= deadline) return false;
        shutdownNonce = randomUUID().toString();
        IRCRawEvent marker;
        marker.command = "ARCHIVE_SHUTDOWN_BARRIER";
        marker.text = shutdownNonce;
        // All puts admitted before fence have completed, including puts that
        // were waiting on a full ring. No public put can enter behind this.
        try ctx.eventChannel.putShutdownMarker(marker);
        finally ctx.eventChannel.close();
        while (!shutdownAcknowledged) {
            if (MonoTime.currTime >= deadline) return false;
            sleep(10.msecs);
        }
        foreach (ref entry; incoming)
            if (entry.nonce.length) return false; // uncertain interrupted put
        return MonoTime.currTime < deadline;
    }

    /// True only for our private global marker. An upstream event always has a
    /// network ID; neither an IRC command nor a user control knows this nonce.
    /// The processor returns immediately after acknowledging this FIFO point.
    bool consumeShutdownBarrier(ref const IRCRawEvent event) {
        if (!shutdownRequested || !shutdownNonce.length || event.networkId.length
                || event.text != shutdownNonce) return false;
        shutdownAcknowledged = true;
        shutdownNonce = null;
        return true;
    }

    private bool userOwnsNetwork(ref EngineContext ctx, string user, string network) {
        auto cursor = network;
        const id = parseUUID(cursor);
        return !cursor.length && ctx.networkRepo.findByIdWithUser(id).userId.toString() == user;
    }

    /// Register both sides before allowing a quiescent source to close. History
    /// provenance never follows live routing and never expires with a heartbeat.
    bool prepareHandoff(ref EngineContext ctx, string network, string target) {
        if (stopping || shutdownRequested || !target.length || target.length > 128) return false;
        const index = scopeRegistration(network);
        if (index == size_t.max) return false;
        try {
            const owner = localScopeOwner(ctx, network);
            if (!canonicalId(owner)) return false;
            auto scopes = registerCatalog(ctx, network, target, owner);
            if (!scopes.length) return false;
            installCatalog(ctx, network, scopes);
            if (stopping || shutdownRequested) return false;
            registrations[index].preparedOwnerId = owner;
            registrations[index].ready = true;
            registrations[index].retryAtMs = nowMs() + 300_000;
            return true;
        } catch (Exception) { return false; }
    }

    /// Queue a barrier, not a deletion. Even offline networks use their recorded
    /// archival owner, independent of live routing/assignment.
    void accept(ref EngineContext ctx, ControlMessage msg) {
        if (!acceptingControls || stopping || ctx.archiveSpool is null || msg.config.type != Json.Type.object) return;
        const id = msg.config["operationId"].get!string;
        if (!canonicalId(id) || !canonicalId(msg.userId) || !canonicalId(msg.networkId)
                || !userOwnsNetwork(ctx, msg.userId, msg.networkId)) return;
        // Ownership lookup may yield. A shutdown begun during that lookup
        // must not allocate an authorization or put a new control afterward.
        if (!acceptingControls || stopping) return;
        bool statusOnly;
        if (auto s = "statusOnly" in msg.config) statusOnly = s.get!bool;
        string buffer;
        if (auto b = "buffer" in msg.config) buffer = b.get!string;
        if (buffer.length && !validBuffer(buffer)) return;
        size_t slot = size_t.max;
        foreach (i, ref entry; incoming) if (!entry.nonce.length) { slot = i; break; }
        if (slot == size_t.max) return;
        const nonce = randomUUID().toString();
        incoming[slot] = AuthorizedClear(nonce, id, msg.userId, msg.networkId, buffer, statusOnly);
        IRCRawEvent event;
        event.command = "ARCHIVE_CONTROL"; event.networkId = msg.networkId;
        // An upstream command cannot impersonate an authenticated internal
        // control: the nonce is one-use, bounded and never published on IRC.
        event.text = nonce;
        // Do not clear on an exception: Channel.put may have admitted before
        // interruption. Only FIFO consumption resolves this authorization.
        ctx.eventChannel.put(event);
    }

    /// Called before event eid assignment in the same processor FIFO as appends
    /// and renames. Existing IDs never allocate a replacement cutoff.
    void consume(ref EngineContext ctx, ref IRCRawEvent event) {
        if (stopping || ctx.archiveSpool is null) return;
        AuthorizedClear authorization;
        foreach (ref entry; incoming) if (entry.nonce == event.text
                && entry.networkId == event.networkId) {
            authorization = entry;
            entry = AuthorizedClear.init;
            break;
        }
        if (!authorization.nonce.length) return;
        const id = authorization.operationId, user = authorization.userId;
        string buffer = authorization.buffer;
        const statusOnly = authorization.statusOnly;
        ArchiveOperationStatus status;
        if (statusOnly) scopeReady(event.networkId);
        const lookup = ctx.archiveSpool.lookupOperationById(id, user, ctx.localServer.serverId,
            event.networkId, status);
        if (statusOnly) {
            if (lookup == ArchiveLookup.found || lookup == ArchiveLookup.conflict)
                projectOperation(ctx, status);
            projectLookup(ctx, id, user, event.networkId, buffer, lookup, status);
            return;
        }
        if (lookup == ArchiveLookup.conflict) { projectOperation(ctx, status); return; }
        if (lookup != ArchiveLookup.found && lookup != ArchiveLookup.notFound) return;
        if (lookup == ArchiveLookup.found) {
            projectOperation(ctx, status);
            if (buffer.length && status.channel != buffer) return;
        }
        if (lookup == ArchiveLookup.notFound && !scopeReady(event.networkId)) return;
        // The elected processor barrier atomically freezes ALL historical
        // scopes and one cutoff. Missing coordination never authorizes a new
        // cutoff or a clear of only the currently routed engine.
        const raw = ctx.redis.getDb().get(archiveClearGroupKey(id));
        if (!raw.length || raw.length > archiveClearGroupMaxBytes) return;
        auto group = parseJsonString(raw);
        if (!validArchiveClearGroup(group, id, user, event.networkId, buffer)
                || !archiveClearGroupIncludes(group, ctx.localServer.serverId)) return;
        if (group["cutoffEid"].get!long == 0) {
            auto frozen = ctx.redis.getDb().eval!string(archiveBufferLineageLua ~ archiveFreezeClearGroupLua,
                [archiveClearGroupKey(id), archiveOwnerKey(event.networkId), RedisKeys.globalEid(),
                 RedisKeys.networkAssignments()],
                [id, user, event.networkId, buffer, ctx.localServer.serverId, nowMs().to!string]);
            if (!frozen.empty && frozen.front == "conflict") {
                ctx.redis.getDb().eval!string(q"LUA
local raw = redis.call('GET', KEYS[1])
if not raw then return '0' end
local g = cjson.decode(raw)
if g.operationId ~= ARGV[1] or g.userId ~= ARGV[2] or g.networkId ~= ARGV[3]
    or g.cutoffEid ~= 0 then return '0' end
g.conflict = true; redis.call('SET', KEYS[1], cjson.encode(g)); return '1'
LUA", [archiveClearGroupKey(id)], [id, user, event.networkId]);
                return;
            }
            if (frozen.empty || !frozen.front.length || frozen.front[0] != '{'
                    || frozen.front.length > archiveClearGroupMaxBytes) return;
            group = parseJsonString(frozen.front);
            if (!validArchiveClearGroup(group, id, user, event.networkId, buffer)
                    || !archiveClearGroupIncludes(group, ctx.localServer.serverId)) return;
        }
        if (group["cutoffEid"].get!long == 0) {
            if (group["state"].get!string == "unknown" && nowMs() - lastFailureNotice >= 60_000) {
                lastFailureNotice = nowMs();
                logJsonMap("error", "engine", "Archive clear outcome unknown; coordinated fence unavailable",
                    ["event":"archive_clear_unknown", "operationId":id, "network":event.networkId]);
            }
            return;
        }
        if (lookup == ArchiveLookup.found) return;
        admitFrozenScope(ctx, id, user, event.networkId, group);
    }

    private bool admitFrozenScope(ref EngineContext ctx, string id, string user, string network, Json group) {
        const buffer = group["buffer"].get!string;
        if (!validBuffer(buffer)) return false;
        capturingOperationId = id;
        scope(exit) capturingOperationId = null;
        auto captured = captureArchivePin(ctx, id, user, network, buffer,
            group["cutoffEid"].get!long, group["legacyTimestampCutoffMs"].get!long);
        if (captured.type != Json.Type.object
            || captured["cutoffEid"].get!long != group["cutoffEid"].get!long
            || captured["legacyTimestampCutoffMs"].get!long != group["legacyTimestampCutoffMs"].get!long) return false;
        const admitted = ctx.archiveSpool.tryPurge(id, user, ctx.localServer.serverId,
            network, buffer, captured["cutoffEid"].get!long,
            captured["legacyTimestampCutoffMs"].get!long,
            captured["scopedLineageId"].get!string, captured["legacyLineageId"].get!string);
        // A local rejection must not discard another scope's frozen intent.
        if (admitted != ArchiveAdmission.queued) return false;
        ArchiveOperationStatus status;
        if (ctx.archiveSpool.lookupOperation(id, user, ctx.localServer.serverId,
                network, buffer, status) == ArchiveLookup.found) projectOperation(ctx, status);
        return true;
    }

    /// A->B->A must not place a later A rename ahead of an older frozen A
    /// purge. Redis observations and try-admission only: never Mongo or a
    /// waiting disk/Mongo fiber on the ordinary processor path.
    bool orderFrozenControls(ref EngineContext ctx, string network, long beforeEid) {
        try {
            auto cursor = network;
            auto user = ctx.connManager.getOwnerId(parseUUID(cursor));
            if (cursor.length) return false;
            if (!user.length) user = movingOwner(network);
            if (!user.length) return false;
            auto pending = ctx.redis.getDb().eval!string(q"LUA
local kind = redis.call('TYPE', KEYS[1]).ok
if kind ~= 'none' and kind ~= 'set' then return 'unknown' end
local n = redis.call('SCARD', KEYS[1])
if n > 128 then return 'overflow' end
if n == 0 then return '[]' end
return cjson.encode(redis.call('SMEMBERS', KEYS[1]))
LUA", ["irc:archive:clear-network-pending:" ~ network], cast(string[])[]);
            if (pending.empty || pending.front.length > 5_120 || !pending.front.length || pending.front[0] != '[')
                return false;
            auto ids = parseJsonString(pending.front);
            if (ids.type != Json.Type.array || ids.length > 128) return false;
            foreach (item; ids) {
                if (item.type != Json.Type.string || !canonicalId(item.get!string)) return false;
                const id = item.get!string;
                ArchiveOperationStatus local;
                const lookup = ctx.archiveSpool.lookupOperationById(id, user, ctx.localServer.serverId, network, local);
                if (lookup == ArchiveLookup.found || lookup == ArchiveLookup.conflict) continue;
                if (lookup != ArchiveLookup.notFound) return false;
                const raw = ctx.redis.getDb().get(archiveClearGroupKey(id));
                if (!raw.length) continue; // lost coordination cannot authorize a later purge
                if (raw.length > archiveClearGroupMaxBytes) return false;
                auto group = parseJsonString(raw);
                if (group["userId"].type != Json.Type.string) return false;
                if (group["userId"].get!string != user) continue;
                if (!validArchiveClearGroup(group, id, user, network)) return false;
                const cutoff = group["cutoffEid"].get!long;
                if (cutoff <= 0 || cutoff >= beforeEid || group["state"].get!string != "requested"
                        || !archiveClearGroupIncludes(group, ctx.localServer.serverId)) continue;
                if (!admitFrozenScope(ctx, id, user, network, group)) return false;
            }
            return true;
        } catch (Exception) { return false; }
    }

    private void projectLookup(ref EngineContext ctx, string id, string user,
            string network, string buffer, ArchiveLookup lookup, ref const ArchiveOperationStatus status) {
        if (lookup != ArchiveLookup.notFound && lookup != ArchiveLookup.found && lookup != ArchiveLookup.conflict) return;
        const raw = ctx.redis.getDb().get(archiveClearGroupKey(id));
        if (!raw.length || raw.length > archiveClearGroupMaxBytes) return;
        auto group = parseJsonString(raw);
        if (!validArchiveClearGroup(group, id, user, network, buffer)
                || !archiveClearGroupIncludes(group, ctx.localServer.serverId)) return;
        auto result = lookup == ArchiveLookup.notFound
            ? Json(["operationId": Json(id), "userId": Json(user), "networkId": Json(network),
                "serverId": Json(ctx.localServer.serverId), "buffer": Json(buffer), "state": Json("not_found")])
            : archiveOperationStatusJson(status);
        if (lookup == ArchiveLookup.notFound) {
            const pinRaw = ctx.redis.getDb().get("irc:archive:pin:" ~ ctx.localServer.serverId ~ ":" ~ id);
            if (pinRaw.length) {
                if (pinRaw.length > 4_096) throw new Exception("archive_pin_oversized");
                auto pin = parseJsonString(pinRaw);
                foreach (field; ["operationId", "userId", "networkId", "serverId", "buffer"])
                    if (pin[field].type != Json.Type.string) throw new Exception("archive_pin_invalid");
                if (pin["operationId"].get!string != id || !validBuffer(pin["buffer"].get!string)
                    || pin["cutoffEid"].type != Json.Type.int_ || pin["cutoffEid"].get!long <= 0
                    || pin["legacyTimestampCutoffMs"].type != Json.Type.int_
                    || pin["legacyTimestampCutoffMs"].get!long <= 0)
                    throw new Exception("archive_pin_invalid");
                // A frozen, locally rejected intent still binds this UUID's
                // cutoff/incarnation. It is NOT durable completion evidence.
                result = pin;
                result["state"] = "requested"; result["durable"] = false;
                result["sequence"] = 0; result["redisApplied"] = false;
                result["updatedAtMs"] = nowMs();
            }
        }
        result["version"] = archiveProtocolVersion;
        result["lookupToken"] = group["lookupToken"];
        auto cursor = network;
        auto client = ctx.connManager.getClient(parseUUID(cursor));
        result["hasLiveProducer"] = client !is null && !client.getMoveQuiescent;
        ctx.redis.getDb().setEX(archiveLookupKey(ctx.localServer.serverId, id), 90, result.toString());
    }

    private void projectOperation(ref EngineContext ctx, ref const ArchiveOperationStatus status) {
        auto j = archiveOperationStatusJson(status);
        j["version"] = archiveProtocolVersion;
        j["observedAtMs"] = nowMs();
        auto result = ctx.redis.getDb().eval!string(q"LUA
local kind = redis.call('TYPE', KEYS[2]).ok
if kind ~= 'none' and kind ~= 'zset' then return redis.error_reply('Invalid archive projection registry') end
if redis.call('ZCARD', KEYS[2]) > 1152 then return redis.error_reply('Archive projection registry overflow') end
redis.call('SET', KEYS[1], ARGV[1], 'EX', 604800)
if ARGV[2] == 'completed' then
    redis.call('ZADD', KEYS[2], ARGV[4], ARGV[3])
    local excess = redis.call('ZCARD', KEYS[2]) - 1024
    if excess > 0 then
        for _,id in ipairs(redis.call('ZRANGE', KEYS[2], 0, excess-1)) do
            redis.call('DEL', ARGV[5] .. id, ARGV[6] .. id)
            redis.call('ZREM', KEYS[2], id)
        end
    end
    redis.call('EXPIRE', KEYS[2], 604800)
end
return '1'
LUA", [archiveOperationKey(status.serverId, status.operationId),
                "irc:archive:completed-projections:" ~ status.serverId],
                [j.toString(), status.state.to!string, status.operationId,
                 status.updatedAtMs.to!string, "irc:archive:operation:" ~ status.serverId ~ ":",
                 "irc:archive:redis-applied:" ~ status.serverId ~ ":"]);
        if (result.empty || result.front != "1") throw new Exception("archive_projection_unknown");
        if (status.state == ArchiveOperationState.completed)
            ctx.redis.getDb().eval!string(archiveCompleteGroupLua,
                [archiveClearGroupKey(status.operationId)], [nowMs().to!string, status.operationId]);
    }

    /// A durably anchored clear keeps progressing after its HTTP caller leaves.
    /// One controller reuses its existing bounded operation snapshot; target
    /// queue saturation is pending, never an unbounded wakeup backlog.
    private bool coordinateGroup(ref EngineContext ctx, ref const ArchiveOperationStatus status) {
        if (!status.durable() || (status.state != ArchiveOperationState.admitted
                && status.state != ArchiveOperationState.completed)) return false;
        const raw = ctx.redis.getDb().get(archiveClearGroupKey(status.operationId));
        if (!raw.length) return false;
        if (raw.length > archiveClearGroupMaxBytes) throw new Exception("archive_coordination_oversized");
        auto group = parseJsonString(raw);
        if (!validArchiveClearGroup(group, status.operationId, status.ownerId, status.networkId, status.channel))
            throw new Exception("archive_coordination_unknown");
        if (group["state"].get!string != "requested" || group["cutoffEid"].get!long != status.cutoffEid
                || group["legacyTimestampCutoffMs"].get!long != status.legacyCutoffMs
                || group["coordinator"].get!string != ctx.localServer.serverId) return false;
        auto msg = ControlMessage("archiveClear", status.networkId);
        msg.userId = status.ownerId; msg.timestampMs = nowMs();
        msg.config = Json(["operationId": Json(status.operationId), "buffer": Json(status.channel)]);
        const encoded = msg.toJson().toString();
        bool retry;
        foreach (scopeId; group["servers"]) {
            const server = scopeId.get!string;
            if (server == ctx.localServer.serverId) continue;
            const projected = ctx.redis.getDb().get(archiveOperationKey(server, status.operationId));
            if (projected.length) {
                if (projected.length > 8_192) throw new Exception("archive_operation_oversized");
                auto operation = parseJsonString(projected);
                if (operation["operationId"].get!string != status.operationId
                    || operation["userId"].get!string != status.ownerId
                    || operation["networkId"].get!string != status.networkId
                    || operation["serverId"].get!string != server
                    || operation["buffer"].get!string != status.channel
                    || operation["cutoffEid"].get!long != status.cutoffEid
                    || operation["legacyTimestampCutoffMs"].get!long != status.legacyCutoffMs)
                    throw new Exception("archive_scope_conflict");
                const state = operation["state"].get!string;
                if (state == "failed" || ((state == "admitted" || state == "completed")
                        && operation["durable"].type == Json.Type.bool_
                        && operation["durable"].get!bool)) continue;
            }
            retry = true;
            auto sent = ctx.redis.getDb().eval!string(archiveDispatchControlLua,
                [RedisKeys.control(server)], [encoded]);
            if (sent.empty || (sent.front != "1" && sent.front != "full"))
                throw new Exception("archive_control_dispatch_unavailable");
        }
        return retry;
    }

    void start(ref EngineContext ctx) {
        if (started) return;
        started = true;
        try runTask(() nothrow {
            scope(exit) started = false;
            long nextProjection, nextScopeSeed;
            size_t cursor, coordinationCursor;
            while (!stopping) {
                try {
                    if (nowMs() >= nextScopeSeed) {
                        foreach (net; ctx.connManager.getNetworks()) scopeReady(net.config.id.toString());
                        nextScopeSeed = nowMs() + 30_000;
                    }
                    registerRequestedScope(ctx);
                    drainMoveReleases(ctx);
                    ArchiveSpoolStatus aggregate;
                    if (ctx.archiveSpool.tryStatus(aggregate)) {
                        const ready = !stopping && aggregate.ready && !aggregate.failed && !aggregate.stopping && !aggregate.stopped
                            && ctx.archiveWorker !is null && !ctx.archiveWorker.isStopped() && allScopesReady();
                        const versionNow = ready ? archiveProtocolVersion : 0;
                        if (ctx.localServer.archiveVersion != versionNow) {
                            ctx.localServer.archiveVersion = versionNow;
                            capabilityProjectionDirty = true;
                        }
                        if (capabilityProjectionDirty) {
                            ctx.serverRegistry.registerServer(ctx.localServer);
                            capabilityProjectionDirty = false;
                        }
                        if (aggregate.gapCount && (aggregate.gapCount != lastGapCount || nowMs() - lastGapNotice >= 60_000)) {
                            logJsonMap("error", "engine", "Archive gap/uncertainty; live sockets preserved",
                                ["event":"archive_gap", "server":ctx.localServer.serverId,
                                 "gaps":aggregate.gapCount.to!string]);
                            lastGapCount = aggregate.gapCount; lastGapNotice = nowMs();
                        }
                    }
                    size_t operationCount, operationTotal;
                    bool operationsComplete;
                    if (ctx.archiveSpool.trySnapshotOperations(operations[], operationCount,
                            operationTotal, operationsComplete)) {
                        // One early Redis call per pass, never per-control fibers.
                        if (operationCount) foreach (offset; 0 .. operationCount) {
                            const i = (cursor + offset) % operationCount;
                            auto s = operations[i];
                            if (!s.durable() || s.state != ArchiveOperationState.admitted || s.redisApplied) continue;
                            ArchiveRecord record;
                            record.kind = ArchiveKind.purge; record.operationId = s.operationId;
                            record.ownerId = s.ownerId; record.serverId = s.serverId;
                            record.networkId = s.networkId; record.channel = s.channel;
                            record.cutoffEid = s.cutoffEid; record.legacyCutoffMs = s.legacyCutoffMs;
                            record.scopedLineageId = s.scopedLineageId;
                            record.legacyLineageId = s.legacyLineageId;
                            if (applyArchiveRedisPurge(ctx, record) == ArchiveApplyResult.applied)
                                ctx.archiveSpool.tryMarkRedisApplied(s.operationId, s.sequence);
                            cursor = i + 1;
                            break;
                        }
                        foreach (i, ref s; operations[0 .. operationCount]) {
                            const previous = projectedOperations[i];
                            if (previous.operationId != s.operationId || previous.state != s.state
                                    || previous.sequence != s.sequence) {
                                coordinationNeeded[i] = true;
                                coordinationRetryAt[i] = 0;
                            }
                            if (nowMs() >= nextProjection || previous.operationId != s.operationId
                                    || previous.state != s.state || previous.sequence != s.sequence
                                    || previous.redisApplied != s.redisApplied
                                    || previous.updatedAtMs != s.updatedAtMs) {
                                projectOperation(ctx, s);
                                if (s.state == ArchiveOperationState.completed) releaseArchivePin(ctx, s.operationId);
                                projectedOperations[i] = s;
                            }
                        }
                        // At most one bounded fan-out pass per controller turn,
                        // round-robin with a 30-second retry. Redis-stage ACKs
                        // and accepted native FIFO work always get their turn.
                        foreach (offset; 0 .. operationCount) {
                            const i = (coordinationCursor + offset) % operationCount;
                            if (!coordinationNeeded[i] || nowMs() < coordinationRetryAt[i]) continue;
                            coordinationCursor = (i + 1) % operationCount;
                            coordinationNeeded[i] = coordinateGroup(ctx, operations[i]);
                            coordinationRetryAt[i] = nowMs() + 30_000;
                            break;
                        }
                        if (operationCount < projectedOperations.length) {
                            projectedOperations[operationCount .. $] = ArchiveOperationStatus.init;
                            coordinationNeeded[operationCount .. $] = false;
                            coordinationRetryAt[operationCount .. $] = 0;
                        }
                        operations[] = ArchiveOperationStatus.init;
                    }
                    if (nowMs() >= nextProjection) {
                        size_t networkCount, networkTotal;
                        bool networksComplete;
                        if (ctx.archiveSpool.trySnapshotNetworkScopes(networks[], networkCount,
                                networkTotal, networksComplete)) {
                            foreach (ref networkScope; networks[0 .. networkCount]) {
                                ArchiveNetworkStatus n;
                                if (ctx.archiveSpool.tryNetworkStatus(networkScope.serverId, networkScope.networkId, n))
                                    publishNetwork(ctx, n);
                                networkScope = ArchiveNetworkScope.init;
                            }
                        }
                        // Refresh known provenance, not assignment-derived ownership.
                        foreach (net; ctx.connManager.getNetworks()) {
                            const nid = net.config.id.toString();
                            ArchiveNetworkStatus n;
                            if (ctx.archiveSpool.tryNetworkStatus(ctx.localServer.serverId, nid, n))
                                publishNetwork(ctx, n);
                        }
                        nextProjection = nowMs() + 30_000;
                        reconcilePins(ctx);
                    }
                } catch (Exception) {
                    try {
                        const now = nowMs();
                        if (now - lastFailureNotice >= 60_000) {
                            lastFailureNotice = now;
                            logJsonMap("warn", "engine", "Archive status/control backend unavailable",
                                ["event":"archive_projection_unavailable"]);
                        }
                    } catch (Exception) {}
                }
                try sleep(100.msecs); catch (Exception) {}
            }
        });
        catch (Throwable e) { started = false; throw e; }
    }

    private void reconcilePins(ref EngineContext ctx) {
        auto result = ctx.redis.getDb().eval!string(q"LUA
if redis.call('SCARD', KEYS[1]) > 128 then return 'overflow' end
return cjson.encode(redis.call('SMEMBERS', KEYS[1]))
LUA", ["irc:archive:pins:" ~ ctx.localServer.serverId], cast(string[])[]);
        if (result.empty || result.front == "overflow") return;
        auto ids = parseJsonString(result.front);
        if (ids.type != Json.Type.array || ids.length > 128) return;
        foreach (item; ids.get!(Json[])) {
            const id = item.get!string;
            if (!canonicalId(id) || id == capturingOperationId) continue;
            auto raw = ctx.redis.getDb().get("irc:archive:pin:" ~ ctx.localServer.serverId ~ ":" ~ id);
            if (!raw.length) continue;
            auto pin = parseJsonString(raw);
            ArchiveOperationStatus status;
            const lookup = ctx.archiveSpool.lookupOperationById(id, pin["userId"].get!string,
                ctx.localServer.serverId, pin["networkId"].get!string, status);
            // Local absence is NOT a global rejection. Preserve the frozen
            // incarnation until this original scope durably completes.
            if (lookup == ArchiveLookup.found && status.state == ArchiveOperationState.completed)
                releaseArchivePin(ctx, id);
        }
    }

    private void publishGapNotice(ref EngineContext ctx, string networkId) {
        size_t slot = size_t.max;
        foreach (i, id; gapNoticeNetworks) if (id == networkId) { slot = i; break; }
        if (slot != size_t.max && nowMs() - gapNoticeTimes[slot] < 300_000) return;
        foreach (net; ctx.connManager.getNetworks()) {
            if (net.config.id.toString() != networkId) continue;
            auto notice = IRCRawEvent.makeServerLog(net.config.name, networkId, "error",
                "Archive gap/uncertainty detected. Live IRC remains connected; some older history may be missing.");
            // A gap notice must not recursively attempt the failed archive sink.
            notice.addTag("archive_gap", "1");
            ctx.eventChannel.put(notice);
            if (slot == size_t.max) {
                slot = nextGapNoticeSlot++ % gapNoticeNetworks.length;
                gapNoticeNetworks[slot] = networkId;
            }
            gapNoticeTimes[slot] = nowMs();
            return;
        }
    }

    private void publishNetwork(ref EngineContext ctx, ref const ArchiveNetworkStatus n) {
        // A heartbeat cannot manufacture provenance after Redis eviction.
        if (!scopeReady(n.networkId)) return;
        auto projection = archiveNetworkProjection(n);
        projection["version"] = archiveProtocolVersion;
        ctx.redis.getDb().eval!string(q"LUA
redis.call('SETEX', KEYS[1], 90, ARGV[1])
-- Refresh an existing cache only; missing provenance is rehydrated from Mongo.
redis.call('EXPIRE', KEYS[2], 604800)
return '1'
LUA", [archiveProjectionKey(n.serverId, n.networkId), archiveOwnerKey(n.networkId)], [projection.toString()]);
        if (n.gapLength) publishGapNotice(ctx, n.networkId);
    }
}

/// Capture only fixed-size metadata. Existing physical incarnations are usually
/// initialized by append/rename; legacy upgrade rows may be initialized here.
private Json captureArchivePin(ref EngineContext ctx, string id, string user,
        string network, string buffer, long cutoff, long timestamp) {
    auto scopeJson = Json.emptyObject;
    scopeJson["operationId"] = id; scopeJson["userId"] = user;
    scopeJson["networkId"] = network; scopeJson["serverId"] = ctx.localServer.serverId;
    scopeJson["buffer"] = buffer; scopeJson["cutoffEid"] = cutoff;
    scopeJson["legacyTimestampCutoffMs"] = timestamp;
    auto result = ctx.redis.getDb().eval!string(archiveBufferLineageLua ~ q"LUA
local prior = redis.call('GET', KEYS[2])
local proposed = cjson.decode(ARGV[1])
if prior then
    local old = cjson.decode(prior)
    for _,name in ipairs({'operationId','userId','networkId','serverId','buffer'}) do
        if old[name] ~= proposed[name] then return 'conflict' end
    end
    return prior
end
local groupRaw = redis.call('GET', KEYS[3])
if not groupRaw then return 'unknown' end
local group = cjson.decode(groupRaw)
if group.operationId ~= proposed.operationId or group.userId ~= proposed.userId
    or group.networkId ~= proposed.networkId or group.buffer ~= proposed.buffer
    or group.cutoffEid ~= proposed.cutoffEid
    or group.legacyTimestampCutoffMs ~= proposed.legacyTimestampCutoffMs
    or group.state == 'completed' then return 'unknown' end
local index
for i,server in ipairs(group.servers) do if server == proposed.serverId then index = tostring(i) end end
if not index then return 'unknown' end
group.attempted = group.attempted or {}
-- A completed local journal status may have aged out while a different engine
-- remains offline. Never recapture a reused buffer incarnation in that case.
if group.attempted[index] then return 'unknown' end
if redis.call('SCARD', KEYS[1]) >= 128 then return 'full' end
local scopedToken = group.scopedLineageIds[tonumber(index)]
local legacyToken = ''
if group.coordinator == proposed.serverId and group.legacyCaptured then
    legacyToken = group.legacyLineageId
end
-- Every reference was reserved by the one atomic global freeze. This local
-- durable journal takes ownership; it must never capture a newer incarnation.
for _,token in ipairs({scopedToken,legacyToken}) do
    if type(token) ~= 'string' then return 'unknown' end
    if token ~= '' then
        local refs = tonumber(redis.call('HGET', lineageLocator(token), 'refs'))
        if not refs or refs < 1 or refs > 128 then return 'unknown' end
    end
end
proposed.scopedLineageId, proposed.legacyLineageId = scopedToken, legacyToken
local encoded = cjson.encode(proposed)
redis.call('SET', KEYS[2], encoded)
redis.call('SADD', KEYS[1], proposed.operationId)
group.attempted[index] = true
redis.call('SET', KEYS[3], cjson.encode(group))
return encoded
LUA", ["irc:archive:pins:" ~ ctx.localServer.serverId,
            "irc:archive:pin:" ~ ctx.localServer.serverId ~ ":" ~ id,
            archiveClearGroupKey(id)],
            [scopeJson.toString()]);
    if (result.empty || !result.front.length || result.front[0] != '{') return Json(null);
    return parseJsonString(result.front);
}

/// Only this original scope's durable completed checkpoint permits unpinning.
/// Partial/coordinated intents keep their exact fence, including local rejects.
private void releaseArchivePin(ref EngineContext ctx, string id) {
    auto result = ctx.redis.getDb().eval!string(archiveBufferLineageLua ~ q"LUA
local raw = redis.call('GET', KEYS[2])
if not raw then redis.call('SREM', KEYS[1], ARGV[1]); return '1' end
local pin = cjson.decode(raw)
if pin.operationId ~= ARGV[1] then return '0' end
local tokens = {pin.scopedLineageId, pin.legacyLineageId}
-- Preflight all metadata before changing any reference count.
for _,token in ipairs(tokens) do
    if token ~= '' then
        local refs = tonumber(redis.call('HGET', lineageLocator(token), 'refs'))
        if not refs or refs < 1 or refs > 128 then return '0' end
        local key = redis.call('HGET', lineageLocator(token), 'key')
        if not key then return '0' end
        if key ~= '' then
            if lineageValidate(key) ~= token then return '0' end
        elseif redis.call('HGET', lineageLocator(token), 'empty') ~= '1' then return '0' end
    end
end
for _,token in ipairs(tokens) do
    if token ~= '' then
        local locator = lineageLocator(token)
        local refs = redis.call('HINCRBY', locator, 'refs', -1)
        if refs == 0 then
            local key = redis.call('HGET', locator, 'key')
            if key == '' then redis.call('DEL', locator)
            elseif redis.call('EXISTS', key) == 0 then lineageRetire(key)
            else lineageRefresh(key, token) end
        end
    end
end
redis.call('DEL', KEYS[2])
redis.call('SREM', KEYS[1], ARGV[1])
-- Result retention starts after positive durable completion, never at capture.
redis.call('EXPIRE', KEYS[3], 604800)
return '1'
LUA", ["irc:archive:pins:" ~ ctx.localServer.serverId,
            "irc:archive:pin:" ~ ctx.localServer.serverId ~ ":" ~ id,
            "irc:archive:redis-applied:" ~ ctx.localServer.serverId ~ ":" ~ id], [id]);
    if (result.empty || result.front != "1") throw new Exception("archive_lineage_unpin_unknown");
}

/// Bounded by the existing 5,000-row hot buffer. Validate every row before any
/// mutation, preserve list order and remaining TTL, atomically record identity.
ArchiveApplyResult applyArchiveRedisPurge(ref EngineContext ctx, ref const ArchiveRecord record) {
    if (record.kind != ArchiveKind.purge || !canonicalId(record.operationId)
            || record.cutoffEid <= 0 || record.legacyCutoffMs <= 0
            || (record.scopedLineageId.length && !canonicalId(record.scopedLineageId))
            || (record.legacyLineageId.length && !canonicalId(record.legacyLineageId)))
        return ArchiveApplyResult.conflict;
    auto scopeJson = Json.emptyObject;
    scopeJson["operationId"] = record.operationId; scopeJson["userId"] = record.ownerId;
    scopeJson["serverId"] = record.serverId; scopeJson["networkId"] = record.networkId;
    scopeJson["buffer"] = record.channel; scopeJson["cutoffEid"] = record.cutoffEid;
    scopeJson["legacyTimestampCutoffMs"] = record.legacyCutoffMs;
    scopeJson["scopedLineageId"] = record.scopedLineageId;
    scopeJson["legacyLineageId"] = record.legacyLineageId;
    const marker = "irc:archive:redis-applied:" ~ record.serverId ~ ":" ~ record.operationId;
    try {
        auto verdict = ctx.redis.getDb().eval!string(archiveBufferLineageLua ~ q"LUA
local prior = redis.call('GET', KEYS[1])
if prior then if prior == ARGV[1] then return 'applied' else return 'conflict' end end
local scope = cjson.decode(ARGV[1])
local pinRaw = redis.call('GET', KEYS[2])
if not pinRaw then return 'retry' end
local pin = cjson.decode(pinRaw)
for _,name in ipairs({'operationId','userId','networkId','serverId','buffer','cutoffEid',
        'legacyTimestampCutoffMs','scopedLineageId','legacyLineageId'}) do
    if pin[name] ~= scope[name] then return 'conflict' end
end
local prefixes = {'scrollback:' .. scope.serverId .. ':' .. scope.networkId .. ':',
    'scrollback:' .. scope.networkId .. ':'}
local tokens = {scope.scopedLineageId, scope.legacyLineageId}
local paths, removed = {}, {}
local buffers = {[scope.buffer] = true}
-- Resolve immutable incarnations through later *successful* RENAMENX moves.
-- Missing proof is unknown, never an assumption that a reused name was cleared.
for i,token in ipairs(tokens) do
    paths[i] = ''; removed[i] = {}
    if token ~= '' then
        local locator = lineageLocator(token)
        local refs = tonumber(redis.call('HGET', locator, 'refs'))
        if not refs or refs < 1 or refs > 128 then return 'retry' end
        local key, empty = redis.call('HGET', locator, 'key'), redis.call('HGET', locator, 'empty')
        if not key then return 'retry' end
        if empty == '1' and key == '' then
            -- Explicit pinned empty proof survives Mongo outages without TTL.
        elseif empty == '0' and string.sub(key,1,#prefixes[i]) == prefixes[i] then
            if lineageValidate(key) ~= token then return 'retry' end
            local kind = redis.call('TYPE', key).ok
            if kind ~= 'none' and kind ~= 'list' then return 'retry' end
            local rowCount = redis.call('LLEN', key)
            if rowCount > 5000 then return 'retry' end
            paths[i] = key
            buffers[string.sub(key,#prefixes[i]+1)] = true
            for rowIndex=0,rowCount-1 do
                local raw = redis.call('LINDEX', key, rowIndex)
                if not raw then return 'retry' end
                local ok,row = pcall(cjson.decode, raw)
                if not ok or type(row) ~= 'table' then return 'retry' end
                local remove
                if row.eid ~= nil then
                    if type(row.eid) ~= 'number' or row.eid <= 0 then return 'retry' end
                    remove = row.eid <= scope.cutoffEid
                else
                    local t = row.t or row.timestamp
                    if type(t) ~= 'number' or t <= 0 then return 'retry' end
                    remove = t <= scope.legacyTimestampCutoffMs
                end
                if remove then table.insert(removed[i], rowIndex) end
            end
        else return 'retry' end
    end
end
for i,key in ipairs(paths) do
    if key ~= '' then
        -- Only bounded numeric positions are retained, never a second copy of
        -- all rows. Every row was valid JSON, so '!' cannot collide with one.
        -- LSET/LREM preserve newer rows, relative order and the list's TTL.
        for _,index in ipairs(removed[i]) do redis.call('LSET', key, index, '!') end
        if #removed[i] > 0 then redis.call('LREM', key, 0, '!') end
        if redis.call('EXISTS', key) == 0 then lineageRetire(key) end
    end
end
-- The modern dedup set spans every archival server. A local empty list is
-- insufficient after migration; unavailable catalog evidence retains dedup.
local catalogKnown, servers = false, {}
if redis.call('TYPE', KEYS[3]).ok == 'string' and redis.call('STRLEN', KEYS[3]) <= 16384 then
    local ok, owner = pcall(cjson.decode, redis.call('GET', KEYS[3]))
    if ok and type(owner) == 'table' and owner.version == 1
        and owner.networkId == scope.networkId and type(owner.servers) == 'table'
        and #owner.servers > 0 and #owner.servers <= 64 then
        catalogKnown = true
        local containsScope = false
        for _,server in ipairs(owner.servers) do
            if type(server) ~= 'string' or #server == 0 or #server > 128 then
                catalogKnown = false; break
            end
            servers[#servers + 1] = server
            if server == scope.serverId then containsScope = true end
        end
        catalogKnown = catalogKnown and containsScope
    end
end
for buffer,_ in pairs(buffers) do
    local scopedEmpty = redis.call('EXISTS', prefixes[1] .. buffer) == 0
    local legacyEmpty = redis.call('EXISTS', prefixes[2] .. buffer) == 0
    if scopedEmpty and legacyEmpty then
        redis.call('DEL', 'dedup:' .. scope.serverId .. ':' .. scope.networkId .. ':' .. buffer)
    end
    local allEmpty = catalogKnown and legacyEmpty
    if allEmpty then
        for _,server in ipairs(servers) do
            if redis.call('EXISTS', 'scrollback:' .. server .. ':' .. scope.networkId .. ':' .. buffer) ~= 0 then
                allEmpty = false; break
            end
        end
    end
    if allEmpty then redis.call('DEL', 'dedup:' .. scope.networkId .. ':' .. buffer) end
end
-- This marker is bounded by the pending pin registry; expiry starts at the
-- positive journal completion checkpoint, not seven days into an outage.
redis.call('SET', KEYS[1], ARGV[1])
return 'applied'
LUA", [marker, "irc:archive:pin:" ~ record.serverId ~ ":" ~ record.operationId,
            archiveOwnerKey(record.networkId)],
            [scopeJson.toString()]);
        if (!verdict.empty && verdict.front == "applied") return ArchiveApplyResult.applied;
        if (!verdict.empty && verdict.front == "conflict") return ArchiveApplyResult.conflict;
    } catch (Exception) {}
    return ArchiveApplyResult.retry;
}

/// Called after socket-preserving detach. One deadline covers producer fencing,
/// the real processor FIFO tail and native RAM-to-disk drain; never Mongo.
void stopArchive(ref EngineContext ctx) {
    if (ctx.archiveSpool is null) return;
    const deadline = MonoTime.currTime + 5.seconds;
    auto waitingTask = Task.getThis();
    auto timer = setTimer(5.seconds, { waitingTask.interrupt(); });
    scope(exit) timer.stop();
    bool drained;
    try {
        if (ctx.archiveControl !is null)
            drained = ctx.archiveControl.awaitShutdownBarrier(ctx, deadline);
        else ctx.eventChannel.fence();
    } catch (Exception) {
        // An interrupted marker put may have succeeded. Never promote that
        // ambiguous outcome to clean, even if a late processor ack arrives.
    }
    if (ctx.archiveControl !is null) ctx.archiveControl.stop();
    if (ctx.archiveWorker !is null) ctx.archiveWorker.requestStop();
    auto remaining = deadline - MonoTime.currTime;
    if (remaining < typeof(remaining).zero) remaining = typeof(remaining).zero;
    ctx.archiveSpool.requestShutdown(remaining,
        drained ? ArchiveShutdown.producersDrained : ArchiveShutdown.unclean, true);
    ArchiveSpoolStatus state;
    try {
        while (MonoTime.currTime < deadline) {
            if (ctx.archiveSpool.tryStatus(state) && state.stopped) {
                if (state.cleanShutdown) return;
                break;
            }
            sleep(10.msecs);
        }
    } catch (Exception) {}
    logJsonMap("error", "engine", "Archive drain not proven; unclean uncertainty retained",
        ["event":"archive_shutdown_unclean"]);
}

// Test-only access to the real Redis semantic boundary. No copied Lua, fake
// frozen state, Mongo dependency, or production API is introduced by the seam.
version (MemoryReliabilityHarness) {
    /// Isolate the already-registered Mongo-scope precondition from shutdown.
    /// This is an explicit assumption, NOT a substitute Mongo registration
    /// proof. Validate its real Redis catalog and local owner before enabling
    /// only the admission flag; do not start the Mongo/controller worker.
    bool archiveHarnessAssumeRegisteredScope(ref EngineContext ctx, string network) {
        if (ctx.redis is null || ctx.connManager is null || ctx.archiveSpool is null
                || !canonicalId(network)) return false;
        auto cursor = network;
        if (!ctx.connManager.getOwnerId(parseUUID(cursor)).length || cursor.length) return false;
        const raw = ctx.redis.getDb().get(archiveOwnerKey(network));
        if (!raw.length || raw.length > archiveClearGroupMaxBytes) return false;
        const scopes = archiveOwnerServers(parseJsonString(raw), network);
        if (scopes.type != Json.Type.array) return false;
        bool containsLocal;
        foreach (scopeId; scopes)
            if (scopeId.get!string == ctx.localServer.serverId) containsLocal = true;
        if (!containsLocal) return false;
        ArchiveSpoolStatus status;
        if (!ctx.archiveSpool.tryStatus(status) || !status.ready || status.failed || status.stopped)
            return false;
        if (ctx.archiveControl is null) ctx.archiveControl = new ArchiveControl;
        auto control = ctx.archiveControl;
        if (control.stopping || control.shutdownRequested) return false;
        control.started = true;
        control.scopeReady(network);
        foreach (ref entry; control.registrations) if (entry.networkId == network) {
            entry.ready = true;
            return true;
        }
        return false;
    }

    string archiveHarnessCreateGroup(ref EngineContext ctx, string id, string user, string network,
            string buffer, long timeMs, string coordinator, string lookupToken) {
        import ircfiber.archive_protocol : archiveCaptureClearGroupLua;
        if (ctx.redis is null || !canonicalId(id) || !canonicalId(user) || !canonicalId(network)
                || !canonicalId(lookupToken) || !validBuffer(buffer)) return "unknown";
        auto result = ctx.redis.getDb().eval!string(archiveCaptureClearGroupLua,
            [archiveClearGroupKey(id), archiveOwnerKey(network)],
            [id, user, network, buffer, timeMs.to!string, "0", coordinator, lookupToken]);
        return result.empty ? "unknown" : result.front;
    }

    bool archiveHarnessObserve(ref EngineContext ctx, string id, string user, string network, string buffer) {
        if (ctx.redis is null || ctx.connManager is null || ctx.archiveSpool is null) return false;
        ArchiveOperationStatus status;
        const lookup = ctx.archiveSpool.lookupOperationById(id, user, ctx.localServer.serverId, network, status);
        if (lookup != ArchiveLookup.notFound && lookup != ArchiveLookup.found && lookup != ArchiveLookup.conflict)
            return false;
        if (ctx.archiveControl is null) ctx.archiveControl = new ArchiveControl;
        try {
            if (lookup == ArchiveLookup.found || lookup == ArchiveLookup.conflict)
                ctx.archiveControl.projectOperation(ctx, status);
            ctx.archiveControl.projectLookup(ctx, id, user, network, buffer, lookup, status);
            const raw = ctx.redis.getDb().get(archiveLookupKey(ctx.localServer.serverId, id));
            const groupRaw = ctx.redis.getDb().get(archiveClearGroupKey(id));
            if (!raw.length || !groupRaw.length) return false;
            auto group = parseJsonString(groupRaw), observation = parseJsonString(raw);
            return validArchiveClearGroup(group, id, user, network, buffer)
                && archiveClearGroupIncludes(group, ctx.localServer.serverId)
                && observation["lookupToken"].type == Json.Type.string
                && observation["lookupToken"].get!string == group["lookupToken"].get!string;
        } catch (Exception) { return false; }
    }

    string archiveHarnessFreeze(ref EngineContext ctx, string id, string user, string network,
            string buffer, long timeMs, string eidKey = "", string assignmentsKey = "") {
        if (!eidKey.length) eidKey = RedisKeys.globalEid();
        if (!assignmentsKey.length) assignmentsKey = RedisKeys.networkAssignments();
        auto result = ctx.redis.getDb().eval!string(archiveBufferLineageLua ~ archiveFreezeClearGroupLua,
            [archiveClearGroupKey(id), archiveOwnerKey(network), eidKey, assignmentsKey],
            [id, user, network, buffer, ctx.localServer.serverId, timeMs.to!string]);
        return result.empty ? "unknown" : result.front;
    }

    Json archiveHarnessPin(ref EngineContext ctx, string id, string user, string network,
            string buffer, long cutoff, long timestamp) {
        return captureArchivePin(ctx, id, user, network, buffer, cutoff, timestamp);
    }

    bool archiveHarnessRelease(ref EngineContext ctx, string id) {
        try { releaseArchivePin(ctx, id); return true; }
        catch (Exception) { return false; }
    }
}
