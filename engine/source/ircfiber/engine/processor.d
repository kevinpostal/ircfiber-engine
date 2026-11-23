module ircfiber.engine.processor;

import vibe.core.channel : Channel, createChannel;
import vibe.core.core : runTask, sleep, yield;
import core.time : msecs;
import std.algorithm.mutation : move;
import vibe.core.log;

import std.uuid : UUID, parseUUID;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : Network, NetworkConfig, normalizeChannelName,
    ircCaseMapping, ircCaseEquals;
import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.engine.state : writeStateSnapshotForNetwork;
import ircfiber.redis.protocol : RedisKeys, StateTTL;
import ircfiber.engine.session_snapshot : HistoryRecovery, historyRecoveryFromJSON,
    historyRecoveryToJSON;
import ircfiber.irc.mls_peer : normalizeFiberChannel;
import ircfiber.irc.connection : PersistentIRCClient;
import vibe.data.json : Json, parseJsonString;

import ircfiber.engine.archive_spool : ArchiveAdmission;
import ircfiber.logging : logJsonMap;
import std.datetime : Clock;
import std.conv : to;

private enum PUBLISH_AND_STREAM_LUA =
    "redis.call('PUBLISH', KEYS[1], ARGV[1]) "
    ~ "redis.call('LPUSH', KEYS[2], ARGV[1]) "
    ~ "redis.call('LTRIM', KEYS[2], 0, 999) "
    ~ "redis.call('EXPIRE', KEYS[2], ARGV[2]) "
    ~ "return 1";

/// Live publish plus resumable user-stream append in one Redis round trip.
private void publishAndStream(ref EngineContext ctx, string userId, string msg) {
    try ctx.redis.getDb().eval!long(PUBLISH_AND_STREAM_LUA,
        [RedisKeys.events(userId), RedisKeys.userStream(userId)],
        [msg, StateTTL.USER_STREAM_TTL.to!string]);
    catch (Exception e) logWarn("Live publish/stream append failed for %s: %s", userId, e.msg);
}

/// Non-throwing UUID parse for hot per-event paths.
private bool tryParseNetworkId(string id, out UUID uuid) nothrow {
    try { uuid = parseUUID(id[]); return true; }
    catch (Exception) { return false; }
}

private long lastArchiveRejectionNotice;
private void noteArchiveAdmission(ArchiveAdmission admission) {
    if (admission == ArchiveAdmission.queued) return;
    const now = Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L;
    if (now - lastArchiveRejectionNotice < 60_000) return;
    lastArchiveRejectionNotice = now;
    logJsonMap("error", "engine", "Archive admission rejected; live delivery preserved",
        ["event":"archive_gap", "admission":admission.to!string]);
}

private long lastScrollbackFailureNotice;
private ulong scrollbackFailuresSinceNotice;

private void noteScrollbackFailure(ref const IRCRawEvent event, string reason) {
    ++scrollbackFailuresSinceNotice;
    const now = Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L;
    if (now - lastScrollbackFailureNotice < 60_000) return;
    lastScrollbackFailureNotice = now;
    logJsonMap("error", "engine", "Scrollback storage failed; live delivery remains independent",
        ["event":"scrollback_failure", "networkId":event.networkId,
         "buffer":event.channel.length ? event.channel : "_server",
         "historical":isHistorical(event) ? "true" : "false",
         "failures":scrollbackFailuresSinceNotice.to!string, "error":reason]);
    scrollbackFailuresSinceNotice = 0;
}

private void archiveRename(ref EngineContext ctx, string serverId, string networkId,
        string from, string toChannel, long cutoffEid) {
    auto admission = ArchiveAdmission.unavailable;
    if (ctx.archiveSpool !is null) {
        string admittedOwner, pendingOwner;
        if (ctx.archiveControl !is null && ctx.connManager !is null) {
            const owner = ctx.connManager.getOwnerId(parseUUID(networkId[]));
            admittedOwner = ctx.archiveControl.admittedScopeOwner(networkId, owner);
            pendingOwner = ctx.archiveControl.pendingScopeOwner(networkId, owner);
        }
        if (ctx.archiveControl !is null && (admittedOwner.length || pendingOwner.length)
                && ctx.archiveControl.orderFrozenControls(ctx, networkId, cutoffEid))
            admission = ctx.archiveSpool.tryRename(serverId, networkId,
                normalizeChannelName(from), normalizeChannelName(toChannel), cutoffEid,
                Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L,
                admittedOwner.length ? admittedOwner : pendingOwner, pendingOwner.length != 0);
        else ctx.archiveSpool.reportAdmissionUnavailable();
    }
    noteArchiveAdmission(admission);
}

private struct HistoryCheckpoint {
    string requestId;
    string connectionEpoch;
    string target;
    HistoryRecovery recovery;
}

private HistoryCheckpoint parseHistoryCheckpoint(string text) {
    auto j = parseJsonString(text);
    if (j.type != Json.Type.object || j["requestId"].type != Json.Type.string
            || !j["requestId"].get!string.length
            || j["connectionEpoch"].type != Json.Type.string
            || !j["connectionEpoch"].get!string.length
            || j["target"].type != Json.Type.string)
        throw new Exception("Invalid history checkpoint envelope");
    HistoryCheckpoint checkpoint;
    checkpoint.requestId = j["requestId"].get!string;
    checkpoint.connectionEpoch = j["connectionEpoch"].get!string;
    checkpoint.target = j["target"].get!string;
    checkpoint.recovery = historyRecoveryFromJSON(j["recovery"]);
    if (checkpoint.recovery.target != checkpoint.target)
        throw new Exception("History checkpoint target mismatch");
    return checkpoint;
}

private string historyStorageKey(string networkId, string requestId, string epoch) {
    return networkId ~ "\0" ~ epoch ~ "\0" ~ requestId;
}

private string historyCheckpointField(string target, string[string] isupport) {
    if (target.length == 0 || target == "*targets") return "*targets";
    string mapping = "rfc1459";
    if (auto value = "CASEMAPPING" in isupport) mapping = *value;
    return normalizeFiberChannel(target, mapping);
}

private bool isHistorical(ref const IRCRawEvent event) {
    return event.getTag("batch") == "chathistory";
}

private struct ChannelIntentEvidence {
    bool captured, saved, parted, disabled, unsaved, explicitJoin;
    string caseMapping;

    static ChannelIntentEvidence fromEvent(const ref IRCRawEvent ev) {
        return ChannelIntentEvidence(ev.channelIntentCaptured, ev.channelIntentSaved,
            ev.channelIntentParted, ev.channelIntentDisabled, ev.channelIntentUnsaved,
            ev.channelIntentExplicit,
            ev.channelIntentCaseMapping);
    }
}

/// A delayed event owns only this channel's intent, never a runtime list.
/// Reject stale target facts before deriving a delta from the canonical row;
/// the repository CAS then fences concurrent edits to the compound lists.
private bool applyChannelIntentDelta(ref NetworkConfig cfg, ChannelIntentEvidence intent,
        string action, string channel, string renamed) {
    import std.algorithm : canFind, filter;
    import std.array : array;
    const mapping = ircCaseMapping(intent.caseMapping);
    const key = normalizeChannelName(channel);
    const replacement = normalizeChannelName(renamed);
    bool same(string a, string b) { return ircCaseEquals(a, b, mapping); }
    if (!intent.captured || !key.length
            || cfg.autoJoinChannels.canFind!(c => same(c, key)) != intent.saved
            || cfg.partedChannels.canFind!(c => same(c, key)) != intent.parted
            || cfg.disabledChannels.canFind!(c => same(c, key)) != intent.disabled
            || cfg.bncUnsavedChannels.canFind!(c => same(c, key)) != intent.unsaved)
        return false;
    if (action == "RENAME") {
        if (!replacement.length) return false;
        const sameTarget = same(key, replacement);
        bool destinationIn(string[] entries) {
            return !sameTarget && entries.canFind!(c => same(c, replacement));
        }
        // A rename cannot merge an independently configured target or undo its
        // deletion. Leave newer definitions untouched rather than guessing.
        if (destinationIn(cfg.autoJoinChannels) || destinationIn(cfg.partedChannels)
                || destinationIn(cfg.disabledChannels) || destinationIn(cfg.channelOrder)
                || destinationIn(cfg.bncUnsavedChannels))
            return false;
        bool safeMap(string[string] values) {
            bool found;
            string previous;
            foreach (name, value; values) {
                if (same(name, key)) {
                    if (found && previous != value) return false;
                    found = true;
                    previous = value;
                } else if (!sameTarget && same(name, replacement)) return false;
            }
            return true;
        }
        if (!safeMap(cfg.bncChannelKeys) || !safeMap(cfg.bncChannelDefaultModes)
                || (intent.unsaved && (intent.saved || intent.parted)))
            return false;
        void renameEntries(ref string[] entries) {
            size_t matches;
            bool changed;
            foreach (c; entries) if (same(c, key)) {
                ++matches;
                changed = changed || c != replacement;
            }
            if (!matches || (!changed && matches == 1)) return;
            auto result = entries.dup;
            size_t keep;
            bool replaced;
            foreach (c; entries) {
                if (same(c, key)) {
                    if (replaced) continue;
                    replaced = true;
                    result[keep++] = replacement;
                } else result[keep++] = c;
            }
            entries = result[0 .. keep];
        }
        void renameMap(ref string[string] values) {
            size_t matches;
            string sourceName, value;
            foreach (name, stored; values) if (same(name, key)) {
                ++matches;
                sourceName = name;
                value = stored;
            }
            if (!matches || (matches == 1 && sourceName == replacement)) return;
            const original = values;
            values = values.dup;
            foreach (name, stored; original) if (same(name, key)) values.remove(name);
            values[replacement] = value;
        }
        renameEntries(cfg.autoJoinChannels);
        renameEntries(cfg.partedChannels);
        renameEntries(cfg.disabledChannels);
        renameEntries(cfg.channelOrder);
        renameMap(cfg.bncChannelKeys);
        renameMap(cfg.bncChannelDefaultModes);
        // Keep the old name fenced against delayed membership events. Unsaved
        // runtime membership stays unsaved at its new name as well.
        if (!sameTarget && !intent.unsaved)
            cfg.bncUnsavedChannels = cfg.bncUnsavedChannels ~ key;
        if (intent.unsaved && !sameTarget)
            cfg.bncUnsavedChannels = cfg.bncUnsavedChannels ~ replacement;
    } else if (action == "JOIN") {
        // Only a positively admitted successful manual JOIN can clear saved
        // suppression. Admission evidence must still match the canonical row.
        if (!intent.explicitJoin && (intent.disabled || intent.unsaved)) return false;
        if (!cfg.autoJoinChannels.canFind!(c => same(c, key)))
            cfg.autoJoinChannels = cfg.autoJoinChannels ~ key;
        if (intent.parted)
            cfg.partedChannels = cfg.partedChannels.filter!(c => !same(c, key)).array;
        if (intent.explicitJoin && intent.disabled)
            cfg.disabledChannels = cfg.disabledChannels.filter!(c => !same(c, key)).array;
        if (intent.explicitJoin && intent.unsaved)
            cfg.bncUnsavedChannels = cfg.bncUnsavedChannels.filter!(c => !same(c, key)).array;
    } else {
        // PART, KICK and JOIN refusal are not evidence of a saved definition.
        if (intent.unsaved) return false;
        if (intent.saved)
            cfg.autoJoinChannels = cfg.autoJoinChannels.filter!(c => !same(c, key)).array;
        if (!cfg.partedChannels.canFind!(c => same(c, key)))
            cfg.partedChannels = cfg.partedChannels ~ key;
    }
    return true;
}

private bool applyChannelIntentDelta(ref NetworkConfig cfg, const ref IRCRawEvent event,
        string action, string channel, string renamed) {
    return applyChannelIntentDelta(cfg, ChannelIntentEvidence.fromEvent(event), action, channel, renamed);
}

/// Invoked by the registration runner as well as unittest builds.
void channelIntentRegressionChecks() {
    IRCRawEvent joined;
    joined.channelIntentCaptured = true;
    joined.channelIntentSaved = true;
    joined.channelIntentDisabled = true;
    joined.channelIntentExplicit = true;
    joined.channelIntentCaseMapping = "rfc1459";
    NetworkConfig cfg;
    cfg.autoJoinChannels = ["#room[", "#other"];
    cfg.disabledChannels = ["#ROOM{"];
    cfg.channelOrder = ["#other", "#room["];
    assert(applyChannelIntentDelta(cfg, joined, "JOIN", "#ROOM{", ""));
    assert(cfg.autoJoinChannels == ["#room[", "#other"]);
    assert(!cfg.disabledChannels.length && !cfg.partedChannels.length);
    assert(cfg.channelOrder == ["#other", "#room["]);

    auto automatic = joined;
    automatic.channelIntentExplicit = false;
    automatic.channelIntentDisabled = false;
    cfg.disabledChannels = ["#room["];
    const beforeStale = cfg;
    assert(!applyChannelIntentDelta(cfg, automatic, "JOIN", "#room{", ""));
    assert(cfg.autoJoinChannels == beforeStale.autoJoinChannels
        && cfg.disabledChannels == beforeStale.disabledChannels
        && cfg.channelOrder == beforeStale.channelOrder);
    automatic.channelIntentDisabled = true;
    assert(!applyChannelIntentDelta(cfg, automatic, "JOIN", "#room{", ""),
        "unsolicited JOIN is not manual proof to clear suppression");

    auto renamed = joined;
    assert(applyChannelIntentDelta(cfg, renamed, "RENAME", "#ROOM{", "#new"));
    assert(cfg.autoJoinChannels == ["#new", "#other"]);
    assert(cfg.disabledChannels == ["#new"]);
    assert(cfg.channelOrder == ["#other", "#new"]);
    auto refused = joined;
    assert(applyChannelIntentDelta(cfg, refused, "PART", "#new", ""));
    assert(cfg.autoJoinChannels == ["#other"] && cfg.partedChannels == ["#new"]);
    assert(cfg.disabledChannels == ["#new"],
        "refusal/PART/KICK are inactive membership, not enable/disable changes");
    assert(!applyChannelIntentDelta(cfg, refused, "PART", "#new", ""),
        "an old duplicate cannot retire newer/different target intent");

    auto asciiEvent = automatic;
    asciiEvent.channelIntentCaseMapping = "ascii";
    asciiEvent.channelIntentDisabled = false;
    cfg = NetworkConfig.init;
    cfg.autoJoinChannels = ["#room["];
    cfg.disabledChannels = ["#room{"];
    assert(applyChannelIntentDelta(cfg, asciiEvent, "PART", "#ROOM[", ""));
    assert(!cfg.autoJoinChannels.length && cfg.partedChannels == ["#room["]);
    assert(cfg.disabledChannels == ["#room{"]);

    IRCRawEvent fresh;
    fresh.channelIntentCaptured = true;
    fresh.channelIntentCaseMapping = "rfc1459";
    cfg = NetworkConfig.init;
    assert(applyChannelIntentDelta(cfg, fresh, "JOIN", "#new", ""));
    assert(cfg.autoJoinChannels == ["#new"],
        "ordinary confirmed JOIN still saves a channel without manual evidence");

    cfg = NetworkConfig.init;
    cfg.autoJoinChannels = ["#sibling"];
    cfg.channelOrder = ["#sibling"];
    cfg.bncUnsavedChannels = ["#ROOM{", "#other"];
    cfg.bncChannelKeys = ["#sibling": "fixture-key"];
    cfg.bncChannelDefaultModes = ["#sibling": "+nt"];
    auto explicitJoin = fresh;
    explicitJoin.channelIntentExplicit = true;
    foreach (action; ["JOIN", "PART", "KICK", "RENAME"]) {
        assert(!applyChannelIntentDelta(cfg, explicitJoin, action, "#room[", "#renamed"),
            "a tombstone added after admission fences every stale event");
        assert(cfg.autoJoinChannels == ["#sibling"] && !cfg.partedChannels.length);
        assert(cfg.bncUnsavedChannels == ["#ROOM{", "#other"]);
        assert(cfg.channelOrder == ["#sibling"]);
    }
    fresh.channelIntentUnsaved = true;
    foreach (action; ["JOIN", "PART", "KICK"]) {
        assert(!applyChannelIntentDelta(cfg, fresh, action, "#room[", ""),
            "matching runtime-only membership cannot become a saved definition");
        assert(cfg.autoJoinChannels == ["#sibling"] && !cfg.partedChannels.length);
    }
    // Refusals use the same PART delta as a genuine self-PART/KICK.
    fresh.persistChannelIntent = true;
    assert(!applyChannelIntentDelta(cfg, fresh, "PART", "#room[", ""));
    explicitJoin.channelIntentUnsaved = true;
    assert(applyChannelIntentDelta(cfg, explicitJoin, "JOIN", "#room[", ""));
    assert(cfg.autoJoinChannels == ["#sibling", "#room["]);
    assert(cfg.bncUnsavedChannels == ["#other"]);
    assert(cfg.channelOrder == ["#sibling"]);
    assert(cfg.bncChannelKeys == ["#sibling": "fixture-key"]
        && cfg.bncChannelDefaultModes == ["#sibling": "+nt"]);
    assert(!applyChannelIntentDelta(cfg, explicitJoin, "JOIN", "#room[", ""),
        "an already-consumed admission cannot clear changed intent again");

    // Rename only source-specific state, preserving order and sibling entries.
    cfg = NetworkConfig.init;
    cfg.autoJoinChannels = ["#old", "#sibling"];
    cfg.disabledChannels = ["#old"];
    cfg.channelOrder = ["#sibling", "#old", "#tail"];
    cfg.bncChannelKeys = ["#OLD": "fixture-key", "#sibling": "sibling-key"];
    cfg.bncChannelDefaultModes = ["#old": "+nt", "#sibling": "+s"];
    auto rename = IRCRawEvent.init;
    rename.channelIntentCaptured = true;
    rename.channelIntentSaved = true;
    rename.channelIntentDisabled = true;
    rename.channelIntentCaseMapping = "rfc1459";
    assert(applyChannelIntentDelta(cfg, rename, "RENAME", "#old", "#new"));
    assert(cfg.autoJoinChannels == ["#new", "#sibling"]);
    assert(cfg.disabledChannels == ["#new"]);
    assert(cfg.channelOrder == ["#sibling", "#new", "#tail"]);
    assert(cfg.bncChannelKeys == ["#new": "fixture-key", "#sibling": "sibling-key"]);
    assert(cfg.bncChannelDefaultModes == ["#new": "+nt", "#sibling": "+s"]);
    assert(cfg.bncUnsavedChannels == ["#old"]);
    auto oldJoin = IRCRawEvent.init;
    oldJoin.channelIntentCaptured = true;
    oldJoin.channelIntentCaseMapping = "rfc1459";
    assert(!applyChannelIntentDelta(cfg, oldJoin, "JOIN", "#old", ""),
        "rename must also fence a delayed formerly live-only JOIN at the old name");

    // An unsaved runtime channel can follow RENAME, but never becomes saved.
    cfg = NetworkConfig.init;
    cfg.bncUnsavedChannels = ["#old", "#sibling"];
    cfg.channelOrder = ["#sibling", "#old"];
    rename = fresh;
    rename.persistChannelIntent = false;
    assert(applyChannelIntentDelta(cfg, rename, "RENAME", "#old", "#new"));
    assert(!cfg.autoJoinChannels.length && !cfg.partedChannels.length);
    assert(cfg.bncUnsavedChannels == ["#old", "#sibling", "#new"]);
    assert(cfg.channelOrder == ["#sibling", "#new"]);
    assert(!applyChannelIntentDelta(cfg, rename, "JOIN", "#new", ""));

    // Never resurrect a deleted destination or merge distinct saved settings.
    cfg = NetworkConfig.init;
    cfg.autoJoinChannels = ["#old"];
    cfg.bncUnsavedChannels = ["#new"];
    rename.channelIntentSaved = true;
    rename.channelIntentUnsaved = false;
    assert(!applyChannelIntentDelta(cfg, rename, "RENAME", "#old", "#new"));
    assert(cfg.autoJoinChannels == ["#old"] && cfg.bncUnsavedChannels == ["#new"]);
    cfg.bncUnsavedChannels = [];
    cfg.bncChannelKeys = ["#new": "fixture-key"];
    assert(!applyChannelIntentDelta(cfg, rename, "RENAME", "#old", "#new"));
    assert(cfg.autoJoinChannels == ["#old"] && cfg.bncChannelKeys == ["#new": "fixture-key"]);

    cfg = NetworkConfig.init;
    cfg.partedChannels = ["#old", "#sibling"];
    cfg.channelOrder = ["#sibling", "#old"];
    rename.channelIntentSaved = false;
    rename.channelIntentParted = true;
    assert(applyChannelIntentDelta(cfg, rename, "RENAME", "#old", "#new"));
    assert(!cfg.autoJoinChannels.length && cfg.partedChannels == ["#new", "#sibling"]);
    assert(cfg.channelOrder == ["#sibling", "#new"] && cfg.bncUnsavedChannels == ["#old"]);

    cfg = NetworkConfig.init;
    cfg.autoJoinChannels = ["#room["];
    cfg.bncChannelKeys = ["#ROOM{": "fixture-key"];
    rename.channelIntentSaved = true;
    rename.channelIntentParted = false;
    assert(applyChannelIntentDelta(cfg, rename, "RENAME", "#room[", "#ROOM{"));
    assert(cfg.autoJoinChannels == ["#room{"] && !cfg.bncUnsavedChannels.length);
    assert(cfg.bncChannelKeys == ["#room{": "fixture-key"],
        "casemap-equivalent renames only canonicalize the same saved definition");
}

@("membership deltas are target-specific, casemapped and stale-event fenced")
unittest { channelIntentRegressionChecks(); }

/// Runs in the same ordered drain as the page rows, before assigning an eid.
/// Redis scrollback/dedup remains authoritative, independent of archive replay.
private void consumeHistoryCheckpoint(ref EngineContext ctx, ref IRCRawEvent event,
        ref bool[string] failedStorage) {
    auto checkpoint = parseHistoryCheckpoint(event.text);
    const failureKey = historyStorageKey(event.networkId, checkpoint.requestId, checkpoint.connectionEpoch);
    auto nid = parseUUID(event.networkId[]);
    auto client = ctx.connManager.getClient(nid);
    if (client is null || client.getConnectionEpoch() != checkpoint.connectionEpoch
            || !client.ownsHistoryRequest(checkpoint.requestId, checkpoint.connectionEpoch)) {
        failedStorage.remove(failureKey);
        return;
    }
    bool committed;
    try {
        import ircfiber.irc.dial_guard : ownsNetworkForDial;
        const serverId = ctx.localServer.serverId;
        auto row = ctx.networkRepo.findByIdWithUser(nid);
        const owner = ctx.connManager.getOwnerId(nid);
        if (owner.length && owner == row.userId.toString() && row.config.id == nid
                && !row.config.disabled && !row.config.servicesProvisioningPending
                && ownsNetworkForDial(ctx.redis, serverId, event.networkId)
                && failureKey !in failedStorage
                && ctx.archiveControl !is null && ctx.archiveControl.scopeReady(event.networkId)
                && ctx.connManager.getClient(nid) is client
                && client.ownsHistoryRequest(checkpoint.requestId, checkpoint.connectionEpoch)) {
            const field = historyCheckpointField(checkpoint.target, client.getIsupport());
            // Fence the write itself, not just the preceding yielding lookups.
            auto result = ctx.redis.getDb().eval!string(
                "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 then return '0' end "
                ~ "redis.call('HSET',KEYS[3],ARGV[3],ARGV[4]); return '1'",
                [RedisKeys.networkAssignments(), RedisKeys.routingMove(event.networkId),
                    RedisKeys.historyRecovery(event.networkId)],
                [event.networkId, serverId, field, historyRecoveryToJSON(checkpoint.recovery).toString()]);
            committed = !result.empty && result.front == "1";
        }
    } catch (Exception e) {
        logWarn("History checkpoint storage failed for %s: %s", event.networkId, e.msg);
    }
    failedStorage.remove(failureKey);
    // A replacement client must never acknowledge its predecessor's page.
    if (ctx.connManager.getClient(nid) is client
            && client.ownsHistoryRequest(checkpoint.requestId, checkpoint.connectionEpoch))
        ctx.connManager.confirmHistoryPage(nid, checkpoint.requestId, committed);
}

private void noteHistoryStorageFailure(ref EngineContext ctx, ref IRCRawEvent event,
        ref bool[string] failedStorage) {
    const requestId = event.getTag("history_request");
    const epoch = event.getTag("history_epoch");
    if (!requestId.length || !epoch.length) return;
    failedStorage[historyStorageKey(event.networkId, requestId, epoch)] = true;
    if (auto client = ctx.connManager.getClient(parseUUID(event.networkId[])))
        client.failHistoryStorage(requestId, epoch);
}

private void noteAcceptedLiveHistory(ref EngineContext ctx, ref IRCRawEvent event) {
    if (isHistorical(event)) return;
    if (auto client = ctx.connManager.getClient(parseUUID(event.networkId[])))
        client.noteAcceptedLiveHistory(event);
}

/// Private BNC envelopes never acquire an eid, enter storage, or touch the
/// resumable user stream. The network's canonical owner selects the channel.
private void publishPrivateBncEvent(ref EngineContext ctx, ref IRCRawEvent event) {
    const response = event.command == "BNC_RESPONSE";
    const raw = response ? event.bncResponsePayload : event.bncPresencePayload;
    if (!raw.length || isHistorical(event)) return;
    auto payload = parseJsonString(raw);
    if (payload.type != Json.Type.object || payload["nid"].type != Json.Type.string
            || payload["nid"].get!string != event.networkId) return;
    const owner = ctx.connManager.getOwnerId(parseUUID(event.networkId[]));
    if (!owner.length) return;
    payload["type"] = response ? "bnc_response" : "bnc_presence";
    // Fence publication as well as admission against an assignment move.
    auto publication = ctx.redis.getDb().eval!string(
        "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 then return '0' end "
        ~ "redis.call('PUBLISH',KEYS[3],ARGV[3]); return '1'",
        [RedisKeys.networkAssignments(), RedisKeys.routingMove(event.networkId), RedisKeys.events(owner)],
        [event.networkId, ctx.localServer.serverId, payload.toString()]);
    if (publication.empty || publication.front != "1") return;
}

/// IRC server-log phase events that are purely transient connection-state
/// (TCP open, TLS handshake, registration steps). They never appear in
/// OOB replay because each connection attempt has its own set, and the
/// dedup set in Redis (`dedup:<srv>:<net>:<buf>`) already prevents them
/// from being inserted twice. Excluding them from Mongo skips 5-7 writes
/// per connect, removing the 5-10s latency window that made the live UI
/// feel frozen.
///
/// Server-log phases are emitted via `IRCRawEvent.makeServerLog()` which
/// sets `command = "NOTICE"` and tags the event with the phase name
/// (`connecting`, `tcp_open`, `tls`, `tls_done`, `registering`, etc).
/// We also exclude the synthetic CONNECT / DISCONNECT lifecycle events
/// used by the engine to signal attempt boundaries — those are
/// transient by design (one per attempt) and the engine's own
/// in-memory ConnectionState is the authoritative source.
private bool isTransientServerLogPhase(ref IRCRawEvent event) nothrow @safe {
    if (event.command == "CONNECT") return true;
    if (event.command == "DISCONNECT") return true;
    if (event.command == "NOTICE") {
        // Server-log phase is tagged onto the NOTICE. Real IRC NOTICEs
        // (e.g. "* Looking up your hostname") carry no phase tag.
        try {
            if (event.getTag("phase").length > 0) return true;
        } catch (Exception) { /* no tags → not a phase event */ }
    }
    return false;
}

/// Processes one event on its owner's shard worker; never throws.
/// The ARCHIVE_SHUTDOWN_BARRIER is handled by the dispatcher, not here.
private void processEvent(ref EngineContext ctx, ref IRCRawEvent event, string serverId,
        ProcessorState state) {
    bool storageResolved;
    try {
        storageResolved = false;

        if (event.command == "ARCHIVE_MOVE_BARRIER") {
            storageResolved = true;
            if (ctx.archiveControl !is null) ctx.archiveControl.consumeMoveBarrier(ctx, event);
            return;
        }

        if (event.command == "ARCHIVE_CONTROL") {
            storageResolved = true;
            if (ctx.archiveControl !is null) ctx.archiveControl.consume(ctx, event);
            return;
        }

        // A network removed on this engine keeps emitting for a
        // moment: stopping the client produces the QUIT echo and
        // the server's `ERROR :Quit:`. Persisting those re-creates
        // the scrollback the delete path just cleared, which left a
        // deleted network's rooms readable at
        // /irc/<name>/channel/%23chan. Nothing downstream wants
        // them, so drop them here — before the eid is spent.
        if (ctx.connManager !is null && ctx.connManager.isRemoved(event.networkId)) {
            logDebug("Dropping %s for removed network %s",
                event.command, event.networkId);
            return;
        }

        if (event.command == "HISTORY_CHECKPOINT") {
            consumeHistoryCheckpoint(ctx, event, state.failedHistoryStorage);
            return;
        }
        if (event.command == "BNC_RESPONSE" || event.command == "BNC_PRESENCE") {
            storageResolved = true;
            publishPrivateBncEvent(ctx, event);
            return;
        }
        const historical = isHistorical(event);

        // Internal identity changes refresh proof immediately, without
        // exposing a synthetic chat event or spending a history eid.
        if (!historical && event.command == "own_prefix") {
            UUID ownNid;
            Network ownNet;
            if (tryParseNetworkId(event.networkId, ownNid)
                    && ctx.connManager.tryGetNetwork(ownNid, ownNet))
                writeStateSnapshotForNetwork(ctx, ownNet, serverId);
            return;
        }

        // IRCCloud-style: assign a global sequential eid to every
        // event. This is the primary key for pagination, dedup,
        // and stream resume — always present, never missing.
        event.eid = ctx.redis.getDb().incr(RedisKeys.globalEid());
        logDebug("Engine event [server=%s]: %s %s (eid=%d)", serverId, event.network, event.command, event.eid);

        // Publish-only events: assigned an eid and published live,
        // but never written to Redis scrollback, Mongo, or the user
        // stream.
        //
        // CHANNEL_LIST chunks are a live reply to a /LIST request,
        // not scrollback (a 20k channel network would otherwise fill
        // all three sinks). WHO replies (352/354/315) are the same:
        // the connection only publishes the ones answering a
        // client's own WHO, and a big channel's roster would
        // otherwise land row by row in the `_server` scrollback.
        //
        // Non-ACTION CTCP (connection.d tags it `ctcp`, routed to
        // `_server`) is a live server-log diagnostic. Its raw
        // parameters can carry PING tokens or DCC addresses, so it
        // is deliberately never persisted anywhere.
        //
        // Safe identity/epoch and capability invalidations for the
        // owner's browsers: live only, never scrollback, Mongo or
        // the user stream.
        const bool publishOnly = event.command == "CHANNEL_LIST"
            || event.command == "352" || event.command == "354"
            || event.command == "315"
            || event.command == "SERVICES_STATE"
            || event.command == "SERVICES_INVALIDATED"
            || event.getTag("ctcp").length > 0;

        // Rename Redis immediately and journal the cutoff mutation at
        // this FIFO position before appending the renamed event.
        // A frozen purge follows the physical Redis lineage across
        // later successful renames, not the reusable channel spelling.
        if (!historical && event.command == "RENAME") {
            try {
                auto rp = event.getParams();
                if (rp.length >= 2 && rp[0].length > 0 && rp[1].length > 0) {
                    ctx.bufferManager.renameBuffer(serverId, event.networkId, rp[0], rp[1]);
                    archiveRename(ctx, serverId, event.networkId, rp[0], rp[1], event.eid);
                }
            } catch (Exception e) {
                logWarn("RENAME storage rename failed: %s", e.msg);
            }
        }

        // Store buffer with server namespace (prevents ID collision).
        // Redis is the hot scrollback/checkpoint authority. Journal
        // admission below is independent and reports gaps explicitly.
        //
        // A confirmed duplicate is suppressed across all sinks. A
        // storage exception is NOT a duplicate verdict: live messages
        // must still reach the independent journal and publication
        // paths. Historical pages remain unacknowledged and retryable.
        bool stored = true;
        bool scrollbackFailed;
        if (!publishOnly) {
            try stored = ctx.bufferManager.appendIRCEvent(event, serverId);
            catch (Exception e) {
                scrollbackFailed = true;
                noteScrollbackFailure(event, e.msg);
            }
        }
        storageResolved = true;
        if (scrollbackFailed) {
            noteHistoryStorageFailure(ctx, event, state.failedHistoryStorage);
            if (historical) return;
        } else if (!publishOnly) {
            noteAcceptedLiveHistory(ctx, event);
        }
        if (!stored) {
            logDebug("Dropping duplicate %s eid=%d for %s/%s (already in scrollback)",
                event.command, event.eid, event.network,
                event.channel.length ? event.channel : "_server");
            return;
        }

        // Archive admission is bounded/nonblocking. Redis acceptance,
        // checkpoints and live delivery do not wait for disk or Mongo.
        Network matchedNet;
        bool foundNet = false;
        string userIdStr = "";
        UUID eventNid;
        if (ctx.connManager !is null && tryParseNetworkId(event.networkId, eventNid)
                && ctx.connManager.tryGetNetwork(eventNid, matchedNet)) {
            foundNet = true;
            userIdStr = ctx.connManager.getOwnerId(eventNid);
        }
        // stopNetworkForMove removes the active client only after its
        // producer loops stop. Preserve canonical attribution for the
        // already-queued tail until the final processor barrier.
        if (!userIdStr.length && ctx.archiveControl !is null)
            userIdStr = ctx.archiveControl.movingOwner(event.networkId);
        auto json = event.toCompactJson();
        if (userIdStr.length > 0 && !publishOnly
                && !isTransientServerLogPhase(event) && event.getTag("archive_gap").length == 0) {
            auto admission = ArchiveAdmission.unavailable;
            if (ctx.archiveSpool !is null) {
                string admittedOwner, pendingOwner;
                if (ctx.archiveControl !is null) {
                    admittedOwner = ctx.archiveControl.admittedScopeOwner(event.networkId, userIdStr);
                    pendingOwner = ctx.archiveControl.pendingScopeOwner(event.networkId, userIdStr);
                }
                if (admittedOwner.length || pendingOwner.length)
                    admission = ctx.archiveSpool.tryAppend(serverId, event.networkId,
                        event.channel.length ? normalizeChannelName(event.channel) : "_server",
                        event.eid, json.toString(), admittedOwner.length ? admittedOwner : pendingOwner,
                        pendingOwner.length != 0);
                else ctx.archiveSpool.reportAdmissionUnavailable();
            }
            noteArchiveAdmission(admission);
        }

        // Only the live/user-stream envelope gets publication fields.
        json["y"] = "irc_event";
        json["serverId"] = serverId;
        auto msg = json.toString();

        if (userIdStr.length > 0) {
            if (publishOnly) ctx.redis.publish(RedisKeys.events(userIdStr), msg);
            else publishAndStream(ctx, userIdStr, msg);
        }

        if (!historical && foundNet && (event.command == "001"
            || event.command == "CONNECT" || event.command == "CONNECTED"
            || event.command == "DISCONNECT" || event.command == "DISCONNECTED"
            || event.command == "JOIN"
            || event.command == "PART" || event.command == "KICK"
            || event.command == "366"
            // account-notify: a login/logout must republish the
            // `accounts` map so member-list badges don't wait for
            // the next JOIN/heartbeat.
            || event.command == "ACCOUNT"
            // End of a client's WHO: a `WHO #chan %na` (the E2EE
            // roster probe) has filled `accounts` for the channel.
            || event.command == "315"
            // draft/metadata-2: a key change republishes the
            // `userMetadata` / `channelMetadata` maps so a
            // reloading client sees it at once.
            || event.command == "METADATA"
            // Member state the snapshot carries (away, host,
            // realname, caps, renamed channel, MONITOR status).
            || event.command == "AWAY" || event.command == "CHGHOST"
            || event.command == "NICK" || event.command == "you_nickchange"
            || event.command == "396"
            || event.command == "SETNAME" || event.command == "CAP"
            || event.command == "RENAME"
            || event.command == "730" || event.command == "731"
            // W1-T01: CONNECTION_RETRY_STATUS + CONNECTION_FAIL
            // are the synthetic events that carry structured
            // retry/fail payloads to the frontend. Writing a
            // snapshot immediately on receipt ensures the WS
            // sync payload's `retryStatus` / `failInfo` fields
            // are fresh for any new client connection without
            // waiting for the 10s heartbeat cycle. Without
            // this the user-facing banner can lag the engine
            // state by up to 10s on a fast-fail network.
            || event.command == "CONNECTION_RETRY_STATUS"
            || event.command == "CONNECTION_FAIL"
            // Observed services login / connection epoch changed.
            || event.command == "SERVICES_STATE")) {
            try {
                writeStateSnapshotForNetwork(ctx, matchedNet, serverId);
            } catch (Exception e) {
                logWarn("Failed to snapshot state for %s: %s", event.network, e.msg);
            }
        }

        // NICK-follow storage rename (IRCCloud rename model): when a
        // DM counterparty changes nick, rename Redis and journal the
        // ordered Mongo cutoff mutation so history follows
        // the conversation across reloads/backfill. Only for the
        // base event the connection tagged `query_follow`, i.e. the
        // renamer is verifiably the person the DM was held with
        // (connection.d `dmFollowsNick`) — never on the nick alone,
        // and never on the per-channel dups.
        // Runs INLINE (not runTask): a follow-up PRIVMSG under the
        // new nick must append after the rename, otherwise RENAMENX
        // sees an existing destination and the history splits.
        // Best-effort try/catch: storage must never break the loop.
        if (!historical && userIdStr.length > 0 && event.command == "NICK" && event.channel.length == 0
            && event.getTag("query_follow").length > 0) {
            try {
                auto nickParams = event.getParams();
                if (nickParams.length > 0 && event.nick.length > 0) {
                    string newNick = nickParams[$ - 1];
                    if (newNick.length > 0) {
                        ctx.bufferManager.renameBuffer(
                            serverId, event.networkId, event.nick, newNick);
                        archiveRename(ctx, serverId, event.networkId, event.nick, newNick, event.eid);
                    }
                }
            } catch (Exception e) {
                logWarn("NICK storage rename failed: %s", e.msg);
            }
        }

        // Persist membership changes and correlated pending JOIN refusals.
        if (!historical && foundNet && (event.command == "JOIN" || event.command == "PART" || event.command == "KICK"
                         || event.command == "RENAME" || event.persistChannelIntent)) {
            auto client = ctx.connManager.getClient(matchedNet.config.id);
            if (client !is null) {
                const isOwnEvent = event.channelIntentCaptured;
                if (isOwnEvent) {
                    auto params = event.getParams();
                    string operation = event.persistChannelIntent ? "PART" : event.command;
                    string target = event.persistChannelIntent
                        ? (params.length > 1 ? params[1] : "")
                        : (event.command == "RENAME" && params.length ? params[0] : event.channel);
                    string destination = operation == "RENAME" && params.length > 1 ? params[1] : "";
                    if (target.length) {
                        auto ctxp = &ctx;
                        runTask((UUID networkId, string networkIdStr, string networkName,
                                PersistentIRCClient originClient, string action, string channel,
                                string renamed, ChannelIntentEvidence intent) nothrow {
                            try {
                                import ircfiber.irc.dial_guard : ownsNetworkForDial;
                                import ircfiber.network_write_gate : NetworkWriter, runNetworkWrite;
                                runNetworkWrite!void(ctxp.redis, (ref NetworkWriter writer) {
                                    const ownerId = ctxp.connManager.getOwnerId(networkId);
                                    auto row = ctxp.networkRepo.findByIdWithUser(networkId);
                                    if (!ownerId.length || row.userId.toString() != ownerId
                                            || ctxp.connManager.getClient(networkId) !is originClient
                                            || !ownsNetworkForDial(ctxp.redis, serverId, networkIdStr)) return;
                                    auto cfg = row.config;
                                    if (ircCaseMapping(originClient.casemapping())
                                            != ircCaseMapping(intent.caseMapping)
                                            || !applyChannelIntentDelta(cfg, intent, action, channel, renamed)) {
                                        // Never retry the old event against newer channel intent.
                                        ctxp.connManager.updateConfig(row.config);
                                        return;
                                    }
                                    const persisted = action == "RENAME"
                                        ? ctxp.networkRepo.updateOwnedFields!("autoJoinChannels", "partedChannels",
                                            "disabledChannels", "channelOrder", "bncUnsavedChannels",
                                            "bncChannelKeys", "bncChannelDefaultModes")(
                                            row.config, cfg, row.userId, writer)
                                        : ctxp.networkRepo.updateOwnedFields!("autoJoinChannels", "partedChannels",
                                            "disabledChannels", "channelOrder", "bncUnsavedChannels")(
                                            row.config, cfg, row.userId, writer);
                                    if (!persisted) {
                                        logWarn("Channel intent changed concurrently for network %s", networkIdStr);
                                        auto latest = ctxp.networkRepo.findByIdWithUser(networkId);
                                        if (latest.userId == row.userId
                                                && ctxp.connManager.getClient(networkId) is originClient)
                                            ctxp.connManager.updateConfig(latest.config);
                                    }
                                });
                            } catch (Exception e) {
                                logWarn("Failed to persist channel intent for %s: %s", networkName, e.msg);
                            }
                        }, matchedNet.config.id, event.networkId, matchedNet.config.name, client,
                            operation, target, destination, ChannelIntentEvidence.fromEvent(event));
                    }
                }
            }
        }
    } catch (Exception e) {
        if (!storageResolved && event.command != "HISTORY_CHECKPOINT") {
            try noteHistoryStorageFailure(ctx, event, state.failedHistoryStorage);
            catch (Exception failure) logWarn("Could not attribute history storage failure: %s", failure.msg);
        }
        logError("Engine event processor error: %s", e.msg);
    }
}

private enum PROCESSOR_SHARDS = 16;
/// Bounded: a full shard blocks the dispatcher (backpressure, no drops).
private enum SHARD_QUEUE_EVENTS = 2048;
private enum BACKLOG_LOG_MIN_PENDING = 1000;
private enum BACKLOG_LOG_INTERVAL_MS = 10_000;

private final class ProcessorShard {
    Channel!(IRCRawEvent, SHARD_QUEUE_EVENTS) queue;
    size_t pending;
}

private final class ProcessorState {
    ProcessorShard[PROCESSOR_SHARDS] shards;
    bool[string] failedHistoryStorage;
    ulong processed;
}

/// FNV-1a 32-bit; stable shard for an owner key.
size_t shardIndexOf(const(char)[] key) pure nothrow @safe @nogc {
    uint h = 2166136261u;
    foreach (c; key) {
        h ^= c;
        h *= 16777619u;
    }
    return h % PROCESSOR_SHARDS;
}

/// All events of one owner share a shard so their eids reach the owner's user
/// stream in increasing order (the gateway drops live frames with
/// `eid <= lastDeliveredEid`). Barriers carry their network's id and route
/// like that network's events.
private string shardKeyOf(ref EngineContext ctx, ref const IRCRawEvent event) {
    UUID nid;
    string owner;
    if (ctx.connManager !is null && tryParseNetworkId(event.networkId, nid))
        owner = ctx.connManager.getOwnerId(nid);
    if (!owner.length && ctx.archiveControl !is null)
        owner = ctx.archiveControl.movingOwner(event.networkId);
    return owner.length ? owner : event.networkId;
}

private bool anyPending(ProcessorState state) nothrow @safe @nogc {
    foreach (shard; state.shards) if (shard.pending > 0) return true;
    return false;
}

private void shardWorker(EngineContext* ctx, string serverId, ProcessorState state,
        ProcessorShard shard) nothrow {
    try {
        while (true) {
            IRCRawEvent event;
            // Blocks while empty; false only once closed and drained.
            if (!shard.queue.tryConsumeOne(event)) return;
            try processEvent(*ctx, event, serverId, state);
            catch (Exception e) logError("Engine event processor error: %s", e.msg);
            --shard.pending;
            ++state.processed;
        }
    } catch (Exception e) {
        try logError("Shard worker stopped: %s", e.msg); catch (Exception) {}
    }
}

/**
 * Event processor for decentralized connection server.
 *
 * Publishes events to user channels and writes state snapshots
 * with server ID attribution. This allows the gateway to track
 * which server manages each network.
 *
 * Accepted non-transient events enter the bounded durable journal for strict
 * Mongo replay. Rejected archival admission is an explicit gap, never a reason
 * to hold live IRC delivery or create waiting per-event fibers.
 *
 * A dispatcher drains the shared event channel and routes every event to one
 * of PROCESSOR_SHARDS ordered workers by owner, so one owner's flood no longer
 * serialises behind (or in front of) every other owner's events. Per-owner
 * order is unchanged. ARCHIVE_SHUTDOWN_BARRIER is global: it is consumed only
 * after every worker has finished everything dispatched before it.
 */
void startEventProcessor(ref EngineContext ctx) {
    auto serverId = ctx.localServer.serverId;
    auto state = new ProcessorState;
    auto ctxp = &ctx;
    foreach (ref shard; state.shards) {
        shard = new ProcessorShard;
        shard.queue = createChannel!(IRCRawEvent, SHARD_QUEUE_EVENTS)();
        runTask(&shardWorker, ctxp, serverId, state, shard);
    }
    scope(exit) foreach (shard; state.shards) shard.queue.close();

    ulong dispatched;
    long lastBacklogLog;
    while (true) {
        IRCRawEvent event;
        if (!ctx.eventChannel.tryConsumeOne(event)) {
            yield();
            continue;
        }

        if (event.command == "ARCHIVE_SHUTDOWN_BARRIER") {
            while (anyPending(state)) sleep(1.msecs);
            if (ctx.archiveControl !is null && ctx.archiveControl.consumeShutdownBarrier(event))
                return;
            continue;
        }

        auto shard = state.shards[shardIndexOf(shardKeyOf(ctx, event))];
        ++shard.pending;
        shard.queue.put(event.move);

        // Same cadence as the former 50-event batch: keep a scheduler
        // checkpoint while ingress stays full.
        if (++dispatched % 50 == 0) {
            yield();
            size_t pending, deepest;
            foreach (s; state.shards) {
                pending += s.pending;
                if (s.pending > deepest) deepest = s.pending;
            }
            if (pending >= BACKLOG_LOG_MIN_PENDING) {
                const now = Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L;
                if (now - lastBacklogLog >= BACKLOG_LOG_INTERVAL_MS) {
                    lastBacklogLog = now;
                    logJsonMap("warn", "engine", "Event processor backlog",
                        ["event":"processor_backlog", "pending":pending.to!string,
                         "deepestShard":deepest.to!string, "shards":PROCESSOR_SHARDS.to!string,
                         "processed":state.processed.to!string]);
                }
            }
        }
    }
}

/// Standalone regressions for the exact internal envelope and storage attribution.
void historyCheckpointRegressionChecks() {
    auto record = parseJsonString(`{"version":1,"target":"#Case[","lowerBound":{"msgid":"z","timestampMs":1000,"hasServerTime":true},"nextBefore":{"msgid":"a","timestampMs":1000,"hasServerTime":true},"discoveryUpperBoundMs":2000,"state":"recovering","reasonCode":"reconnect"}`);
    auto envelope = Json.emptyObject;
    envelope["requestId"] = "request-1";
    envelope["connectionEpoch"] = "epoch-1";
    envelope["target"] = "#Case[";
    envelope["recovery"] = record;
    auto checkpoint = parseHistoryCheckpoint(envelope.toString());
    assert(checkpoint.requestId == "request-1" && checkpoint.connectionEpoch == "epoch-1");
    assert(checkpoint.recovery.lowerBound.msgid == "z");
    assert(checkpoint.recovery.nextBefore.msgid == "a");
    assert(historyCheckpointField(checkpoint.target, ["CASEMAPPING": "rfc1459"]) == "#case{");
    assert(historyCheckpointField(checkpoint.target, ["CASEMAPPING": "ascii"]) == "#case[");
    assert(historyCheckpointField("", null) == "*targets");
    assert(historyCheckpointField("*targets", null) == "*targets");
    bool[string] failures;
    const failureKey = historyStorageKey("network-1", checkpoint.requestId, checkpoint.connectionEpoch);
    failures[failureKey] = true;
    assert(historyStorageKey("network-1", "request-2", "epoch-1") !in failures);
    assert(historyStorageKey("network-1", "request-1", "epoch-2") !in failures);
    assert(historyStorageKey("network-2", "request-1", "epoch-1") !in failures);
    assert(failureKey in failures);
    foreach (kind; 0 .. 5) {
        auto invalid = parseJsonString(envelope.toString());
        if (kind == 0) invalid["target"] = "#other";
        if (kind == 1) invalid.remove("connectionEpoch");
        if (kind == 2) invalid["requestId"] = "";
        if (kind == 3) invalid["recovery"]["state"] = "done";
        if (kind == 4) invalid["recovery"]["version"] = 2;
        bool rejected;
        try parseHistoryCheckpoint(invalid.toString()); catch (Exception) rejected = true;
        assert(rejected, "Malformed or misattributed checkpoint must fail closed");
    }
    IRCRawEvent historical;
    historical.tagsJson = `{"batch":"chathistory","history_request":"request-1","history_epoch":"epoch-1"}`;
    assert(isHistorical(historical));
    // Internal attribution must not become a public compact key.
    auto compact = historical.toCompactJson();
    assert(compact["history_request"].type == Json.Type.undefined);
    assert(compact["history_epoch"].type == Json.Type.undefined);
    historical.tagsJson = `{"batch":"live-labeled-response"}`;
    assert(!isHistorical(historical), "A live response batch is not historical");
}
