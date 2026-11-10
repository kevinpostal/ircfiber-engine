module ircfiber.engine.archive_spool;

import core.atomic : atomicStore, atomicLoad, cas;
import core.sync.mutex : Mutex;
import core.sync.condition : Condition;
import core.thread : Thread;
import core.time : Duration, MonoTime, msecs, seconds;
import std.datetime : Clock;
import std.conv : to;
import std.format : format;
import std.string : toStringz;
import std.uuid : randomUUID;
import vibe.data.json : Json, parseJsonString;
import vibe.core.sync : ManualEvent, createSharedManualEvent, TaskMutex, TaskCondition;
import ircfiber.runtime_diagnostic : RuntimeDiagnosticMailbox, DiagnosticWriteResult, writeLatest, runtimeDiagnosticDefaultPath;

// Json and database connections never cross the native-thread boundary.
enum ArchiveAdmission { queued, full, unavailable, oversized }
enum ArchiveKind { append, rename, purge }
enum ArchiveOperationState { unknown, admitted, completed, failed, requested }
enum ArchiveLookup { found, notFound, conflict, busy, unavailable }
enum ArchiveHealth { healthy, pending, gap, unknown }
enum size_t archiveMaxRecordBytes = 1_048_576;
enum size_t archiveSegmentBytes = 4_194_304;
enum size_t archiveMaxOperationStatuses = 1_152;
enum size_t archiveMaxTrackedNetworks = 1_024;
private enum size_t slotBytes = 4_194_304;
private enum size_t stateBytes = 2 * slotBytes;
private enum size_t controlReserve = 8_388_608;
private enum size_t maxFiles = 160;
private enum size_t maxCommands = 1_024;
private enum size_t maxIngressBytes = 8_388_608;
private enum size_t controlCommands = 128;
private enum size_t controlIngressBytes = 1_048_576;
private enum size_t maxControlRecordBytes = 8_192;
private enum size_t controlSegmentCapacity = archiveSegmentBytes - 8 - (maxControlRecordBytes + 16);
private enum size_t controlSegmentReserve = (controlReserve + controlSegmentCapacity - 1) / controlSegmentCapacity;
private enum string segmentMagic = "IFARv001";
private enum string stateMagic = "IFASv001";

struct ArchiveSpoolConfig {
    string directory = "/var/lib/ircfiber/archive";
    ulong maxBytes = 536_870_912;
    ulong minFreeBytes = 2_147_483_648;
    string diagnosticPath = runtimeDiagnosticDefaultPath;
    static ArchiveSpoolConfig fromEnvironment() {
        import std.process : environment;
        ArchiveSpoolConfig c;
        c.directory = environment.get("IRCFIBER_ARCHIVE_DIR", c.directory);
        c.maxBytes = environment.get("IRCFIBER_ARCHIVE_MAX_BYTES", c.maxBytes.to!string).to!ulong;
        c.minFreeBytes = environment.get("IRCFIBER_ARCHIVE_MIN_FREE_BYTES", c.minFreeBytes.to!string).to!ulong;
        return c;
    }
}

/// Decoded only on the consumer fiber. compactJson retains the original event,
/// including its original timestamp; neither replay nor recovery allocates eids.
struct ArchiveRecord {
    ArchiveKind kind;
    ulong sequence;
    string serverId, networkId, channel, compactJson;
    long eid, timestampMs, queuedAtMs;
    string newChannel, operationId, ownerId;
    long cutoffEid, legacyCutoffMs;
    string scopedLineageId, legacyLineageId;
    bool durableRedisApplied; // Derived from synced state, not the immutable frame.
}

struct ArchiveOperationStatus {
    string operationId, ownerId, serverId, networkId, channel;
    string scopedLineageId, legacyLineageId;
    ArchiveOperationState state;
    long cutoffEid, legacyCutoffMs, updatedAtMs;
    ulong sequence;
    bool redisApplied;
    bool durable() const {
        return sequence > 0 && (state == ArchiveOperationState.admitted || state == ArchiveOperationState.completed);
    }
}

struct ArchiveGap {
    long fromMs, throughMs;
    long firstEid, lastEid;
    string networkId; // Empty means a conservative all-network uncertainty.
    string reason;
}

/// Empty RAM ingress alone never authorizes clearing the durable session marker.
enum ArchiveShutdown { unclean, producersDrained }

struct ArchiveSpoolStatus {
    bool ready, failed, stopping, stopped, replayInFlight, cleanShutdown;
    size_t ingressCommands, ingressBytes, pendingOperations;
    size_t diskThreads;
    ulong checkpoint, durableSequence, pendingBytes, gapCount;
    // Budget-accounted bytes include preallocated state, allocated segments,
    // active-tail reservation and lock bookkeeping; not merely pending frames.
    ulong diskBytes, maxBytes, minFreeBytes, freeBytes;
    ulong controlReserveBytes, stateReserveBytes;
    bool diskBytesKnown, freeBytesKnown;
    long diskSampledAtMs;
    long oldestAtMs, sampledAtMs;
    string failureReason, spoolId;
    ArchiveGap[256] gaps;
    size_t gapLength;
}
/// Scalar hot-path view: never copies the diagnostic gap ledger onto a fiber.
struct ArchiveSpoolProgress {
    bool ready, failed, stopping, stopped, cleanShutdown;
    ulong checkpoint;
}

/// Fixed aggregate metadata, not a payload index. Unknown is mandatory during
/// recovery, after failure, and for untracked networks if 1024 scopes overflow.
struct ArchiveNetworkStatus {
    string serverId, networkId;
    ArchiveHealth state = ArchiveHealth.unknown;
    bool countsKnown, oldestKnown;
    ulong pendingMutations, pendingBytes;
    long oldestAtMs, sampledAtMs;
    ArchiveGap[256] gaps;
    size_t gapLength;
}
struct ArchiveNetworkScope { string serverId, networkId; }
private struct NetworkPending {
    string serverId, networkId;
    ulong count, bytes;
    long oldestAtMs;
    bool oldestKnown;
}

private struct Command { string encoded; ArchiveKind kind; size_t tracker = size_t.max; }
private struct Segment { ulong first, last; size_t size; string name; ulong allocated; }
private long nowMs() { return Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L; }
private ulong roundBlock(ulong n) { return (n + 4095) & ~4095UL; }
private final class JournalException : Exception { this(string reason) { super(reason); } }
private void require(bool value, string reason) { if (!value) throw new JournalException(reason); }
private bool validCanonicalUuid(string value) {
    if (value.length != 36) return false;
    import std.uuid : parseUUID, UUID;
    auto cursor = value; // parseUUID(ref string) consumes its input.
    try {
        const id = parseUUID(cursor);
        return id != UUID.init && !cursor.length && id.toString() == value;
    } catch (Exception) { return false; }
}
private bool validLineage(string value) {
    // Empty is explicit absence at the frozen barrier, not a null UUID token.
    return !value.length || validCanonicalUuid(value);
}

/// Single disk owner. Construction starts asynchronous recovery, never disk I/O
/// on the event loop. Readiness is explicit; rejected work is an archival gap.
final class ArchiveSpool {
    private Mutex mutex;
    private Condition changed;
    private shared(ManualEvent) progressSignal;
    private Thread thread;
    private ArchiveSpoolConfig config;
    private RuntimeDiagnosticMailbox diagnostics;
    private Command[maxCommands] ingress;
    private size_t head, count, bytes, dataCount, dataBytes;
    private ArchiveSpoolStatus status;
    private ArchiveOperationStatus[1_152] operations;
    private size_t operationCount;
    private NetworkPending[1_024] networks;
    private bool networkOverflow;
    private string replay;
    private ulong replaySequence, acknowledgeSequence, redisAppliedSequence, redisStageRequest;
    private bool borrowed, conflict, stopRequested;
    private bool stopCleanEligible, stopFenceTail;
    private MonoTime stopDeadline;
    private long bornAtMs;
    private shared bool rejected;
    private shared bool workerFailure;
    version (MemoryReliabilityHarness) {
        private bool harnessGateRequested, harnessGateEntered, harnessSyncFailure;
        private MonoTime harnessGateDeadline;
    }
    // Everything below is exclusively owned by the native disk thread.
    private int directoryFd = -1, lockFd = -1, stateFd = -1, appendFd = -1;
    private Segment[158] segments; // lock + state + <=158 segments =160 files.
    private size_t segmentCount;
    private ulong nextSequence = 1, checkpoint, durableSequence, stateGeneration;
    private string spoolId;
    private bool unclean, nativeFailed, writableState;
    private long sessionStart, oldestAtMs, lastDiagnostic;
    private long nextStatusExpiry = long.max;
    private ulong measuredFreeBytes;
    private bool measuredFreeKnown;
    private long measuredDiskAtMs, nextDiskSampleAtMs;
    private ArchiveGap[256] gaps;
    private size_t gapLength;
    private ArchiveOperationStatus[1_152] diskOperations;
    private size_t diskOperationCount;
    private size_t scanSegment, scanOffset = 8;

    this(ArchiveSpoolConfig config = ArchiveSpoolConfig.init, RuntimeDiagnosticMailbox diagnostics = null) {
        this.config = config;
        this.config.directory = config.directory.idup;
        this.config.diagnosticPath = config.diagnosticPath.idup;
        this.diagnostics = diagnostics;
        bornAtMs = nowMs();
        mutex = new TaskMutex;
        changed = new TaskCondition(mutex);
        progressSignal = createSharedManualEvent();
        thread = new Thread(&run);
        thread.isDaemon = true;
        thread.start();
    }

    /// Capture before inspecting progress, then wait with the captured value.
    /// One shared event coalesces native completions without callback queues.
    int progressGeneration() nothrow { return progressSignal.emitCount; }
    void awaitProgress(int observed, Duration timeout) { progressSignal.wait(timeout, observed); }

    /// Persist conservative uncertainty when scope provenance prevents admission.
    void reportAdmissionUnavailable() nothrow @nogc {
        atomicStore(rejected, true);
    }

    ArchiveAdmission tryAppend(string serverId, string networkId, string normalizedChannel,
            long eid, string compactJson) {
        if (eid <= 0 || !validScope(serverId, networkId, normalizedChannel)) return reject(ArchiveAdmission.unavailable);
        if (compactJson.length > archiveMaxRecordBytes) return reject(ArchiveAdmission.oversized);
        try {
            auto event = parseJsonString(compactJson);
            require(event.type == Json.Type.object, "invalid_event");
            require(event["eid"].get!long == eid, "event_eid_mismatch");
            auto j = baseRecord("append", serverId, networkId, normalizedChannel);
            j["eid"] = eid;
            // Existing compact events store their Unix millisecond timestamp as t.
            require(("t" in event) !is null, "event_timestamp_missing");
            require(event["t"].get!long > 0, "invalid_event_timestamp");
            j["timestampMs"] = event["t"].get!long;
            j["payload"] = compactJson;
            return enqueue(j.toString(), ArchiveKind.append, serverId, networkId, j["queuedAtMs"].get!long);
        } catch (Exception) { return reject(ArchiveAdmission.unavailable); }
    }

    ArchiveAdmission tryRename(string serverId, string networkId, string fromChannel,
            string toChannel, long cutoffEid, long legacyCutoffMs) {
        if (!validScope(serverId, networkId, fromChannel) || !toChannel.length
                || toChannel.length > 512 || cutoffEid <= 0 || legacyCutoffMs <= 0)
            return reject(ArchiveAdmission.unavailable);
        auto j = baseRecord("rename", serverId, networkId, fromChannel);
        j["newChannel"] = toChannel;
        j["cutoffEid"] = cutoffEid;
        j["legacyCutoffMs"] = legacyCutoffMs;
        return enqueue(j.toString(), ArchiveKind.rename, serverId, networkId, j["queuedAtMs"].get!long);
    }

    /// ID and scope are stable; callers must consult tryOperationStatus first on
    /// retry to reuse the first frozen cutoff. A conflicting ID is never queued.
    ArchiveAdmission tryPurge(string operationId, string ownerId, string serverId,
            string networkId, string channel, long cutoffEid, long legacyCutoffMs,
            string scopedLineageId = "", string legacyLineageId = "") {
        if (!validCanonicalUuid(operationId)) return ArchiveAdmission.unavailable;
        if (!ownerId.length || ownerId.length > 128 || !validScope(serverId, networkId, channel)
                || cutoffEid <= 0 || legacyCutoffMs <= 0
                || !validLineage(scopedLineageId) || !validLineage(legacyLineageId))
            return ArchiveAdmission.unavailable;
        auto j = baseRecord("purge", serverId, networkId, channel);
        j["operationId"] = operationId;
        j["ownerId"] = ownerId;
        j["cutoffEid"] = cutoffEid;
        j["legacyCutoffMs"] = legacyCutoffMs;
        j["scopedLineageId"] = scopedLineageId;
        j["legacyLineageId"] = legacyLineageId;
        return enqueue(j.toString(), ArchiveKind.purge, serverId, networkId, j["queuedAtMs"].get!long);
    }

    bool tryStatus(out ArchiveSpoolStatus result) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        result = status;
        result.maxBytes = config.maxBytes; result.minFreeBytes = config.minFreeBytes;
        result.controlReserveBytes = controlReserve; result.stateReserveBytes = stateBytes;
        if (atomicLoad(workerFailure)) { result.failed = true; result.ready = false; }
        result.ingressCommands = count;
        result.ingressBytes = bytes;
        result.replayInFlight = borrowed;
        return true;
    }
    bool tryProgress(out ArchiveSpoolProgress result) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        result.failed = status.failed || atomicLoad(workerFailure);
        result.ready = status.ready && !result.failed;
        result.stopping = status.stopping; result.stopped = status.stopped;
        result.cleanShutdown = status.cleanShutdown; result.checkpoint = status.checkpoint;
        return true;
    }
    bool tryOperationStatus(string id, out ArchiveOperationStatus result) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        result = ArchiveOperationStatus.init;
        foreach (i; 0 .. operationCount) if (operations[i].operationId == id) { result = operations[i]; break; }
        return true;
    }

    /// Distinguishes 409 scope conflicts from absent IDs and unavailable/busy
    /// recovery. Return found/requested is RAM admission, NOT fsync proof.
    ArchiveLookup lookupOperation(string id, string ownerId, string originalServerId,
            string networkId, string normalizedBuffer, out ArchiveOperationStatus result) {
        auto lookup = lookupOperationById(id, ownerId, originalServerId, networkId, result);
        if (lookup == ArchiveLookup.found && result.channel != normalizedBuffer) return ArchiveLookup.conflict;
        return lookup;
    }

    /// Authenticated GET lookup: the retained row supplies the original buffer.
    /// No caller-supplied buffer or current route can widen its ownership scope.
    ArchiveLookup lookupOperationById(string id, string ownerId, string originalServerId,
            string networkId, out ArchiveOperationStatus result) {
        if (!mutex.tryLock()) return ArchiveLookup.busy;
        scope(exit) mutex.unlock();
        result = ArchiveOperationStatus.init;
        foreach (i; 0 .. operationCount) if (operations[i].operationId == id) {
            result = operations[i];
            if (result.ownerId != ownerId || result.serverId != originalServerId
                    || result.networkId != networkId) return ArchiveLookup.conflict;
            return ArchiveLookup.found;
        }
        return status.ready && !status.failed && !status.stopped
            ? ArchiveLookup.notFound : ArchiveLookup.unavailable;
    }
    /// POST retry proof includes the exact physical-list incarnations captured
    /// at the original barrier. Changed tokens conflict even in the same buffer.
    ArchiveLookup lookupPurgeOperation(string id, string ownerId, string originalServerId,
            string networkId, string normalizedBuffer, string scopedLineageId,
            string legacyLineageId, out ArchiveOperationStatus result) {
        auto found = lookupOperation(id, ownerId, originalServerId, networkId, normalizedBuffer, result);
        if (found == ArchiveLookup.found && (result.scopedLineageId != scopedLineageId
                || result.legacyLineageId != legacyLineageId)) return ArchiveLookup.conflict;
        return found;
    }

    /// Copies into caller-owned fixed storage without allocating or scanning
    /// payloads. false means contention; complete=false means partial/unknown.
    /// Allocate archiveMaxOperationStatuses entries to avoid truncation.
    bool trySnapshotOperations(ArchiveOperationStatus[] destination, out size_t written,
            out size_t total, out bool complete) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        total = operationCount;
        written = destination.length < total ? destination.length : total;
        destination[0 .. written] = operations[0 .. written];
        complete = written == total && status.ready && !status.failed && !status.stopped
            && nowMs() - status.sampledAtMs <= 90_000;
        return true;
    }

    /// Includes retained zero-count scopes, not an inventory of assigned/live
    /// networks. Merge with the connection inventory for independent projections.
    /// Allocate archiveMaxTrackedNetworks entries to avoid truncation. Overflow
    /// is explicitly incomplete until the complete durable and RAM backlog drains.
    bool trySnapshotNetworkScopes(ArchiveNetworkScope[] destination, out size_t written,
            out size_t total, out bool complete) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        written = total = 0;
        foreach (n; networks) {
            if (!n.serverId.length || !n.networkId.length) continue;
            ++total;
            if (written < destination.length)
                destination[written++] = ArchiveNetworkScope(n.serverId, n.networkId);
        }
        complete = written == total && !networkOverflow && status.ready && !status.failed
            && !status.stopped && nowMs() - status.sampledAtMs <= 90_000;
        return true;
    }

    bool tryNetworkStatus(string originalServerId, string networkId, out ArchiveNetworkStatus result) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        result = ArchiveNetworkStatus.init;
        result.serverId = originalServerId; result.networkId = networkId;
        result.sampledAtMs = status.sampledAtMs;
        result.gaps = status.gaps; result.gapLength = status.gapLength;
        if (!status.ready || status.failed || atomicLoad(workerFailure) || status.stopped || status.stopping
                || nowMs() - status.sampledAtMs > 90_000) return true;
        auto index = networkIndex(originalServerId, networkId, false);
        result.countsKnown = index != size_t.max || !networkOverflow;
        if (index != size_t.max) {
            auto n = networks[index];
            result.pendingMutations = n.count; result.pendingBytes = n.bytes;
            result.oldestAtMs = n.oldestAtMs; result.oldestKnown = n.oldestKnown;
        } else result.oldestKnown = !networkOverflow;
        if (result.gapLength) result.state = ArchiveHealth.gap;
        else if (!result.countsKnown) result.state = ArchiveHealth.unknown;
        else result.state = result.pendingMutations ? ArchiveHealth.pending : ArchiveHealth.healthy;
        return true;
    }

    /// Move barrier: false means busy/unknown, never zero. Includes RAM-admitted
    /// mutations, synced uncheckpointed records, and the Mongo in-flight record.
    bool tryNetworkPending(string originalServerId, string networkId, out ulong mutations) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        if (!status.ready || status.failed || atomicLoad(workerFailure) || status.stopped || status.stopping
                || nowMs() - status.sampledAtMs > 90_000) return false;
        auto index = networkIndex(originalServerId, networkId, false);
        if (index == size_t.max) {
            if (networkOverflow) return false;
            mutations = 0; return true;
        }
        mutations = networks[index].count;
        return true;
    }

    // All aggregate changes hold the mailbox mutex. Zero-count cells may be
    // reused; overflow stays unknown until the entire journal and RAM drain.
    private size_t networkIndex(string server, string network, bool create) {
        size_t free = size_t.max;
        foreach (i; 0 .. networks.length) {
            if (networks[i].serverId == server && networks[i].networkId == network) return i;
            if (!networks[i].count && free == size_t.max) free = i;
        }
        if (!create || networkOverflow) return size_t.max;
        if (free == size_t.max) { networkOverflow = true; return size_t.max; }
        networks[free] = NetworkPending(server.idup, network.idup, 0, 0, 0, false);
        return free;
    }
    private size_t addNetworkPending(string server, string network, size_t encodedBytes, long queuedAt) {
        auto index = networkIndex(server, network, true);
        if (index == size_t.max) return index;
        auto n = &networks[index];
        if (!n.count) { n.oldestAtMs = queuedAt; n.oldestKnown = true; }
        ++n.count; n.bytes += encodedBytes + 16;
        return index;
    }
    private void removeNetworkPending(size_t index, size_t encodedBytes) {
        if (index == size_t.max) return;
        auto n = &networks[index];
        require(n.count && n.bytes >= encodedBytes + 16, "network_counter_conflict");
        --n.count; n.bytes -= encodedBytes + 16;
        // Do not invent a timestamp for the next record. The FIFO reader
        // supplies the exact oldest time when this network reaches its head.
        n.oldestAtMs = 0; n.oldestKnown = !n.count;
    }

    /// One borrowed encoded record, <=1 MiB, until checkpoint acknowledgment.
    /// The same immutable bytes are shared, not copied into a completion queue.
    bool tryTake(out string encoded, out ulong sequence) {
        bool durableRedisApplied;
        return tryTake(encoded, sequence, durableRedisApplied);
    }
    bool tryTake(out string encoded, out ulong sequence, out bool durableRedisApplied) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        if (!status.ready || status.failed || atomicLoad(workerFailure)
                || borrowed || replay is null || stopRequested) return false;
        borrowed = true;
        encoded = replay;
        sequence = replaySequence;
        foreach (i; 0 .. operationCount) if (operations[i].sequence == sequence)
            durableRedisApplied = operations[i].redisApplied;
        return true;
    }
    /// Called only after strict majority+journal Mongo success. Asynchronous:
    /// the record is not released until the checkpoint slot has been synced.
    bool tryAcknowledge(ulong sequence) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        if (!borrowed || sequence != replaySequence || acknowledgeSequence) return false;
        acknowledgeSequence = sequence;
        changed.notify();
        return true;
    }
    /// Accepts one bounded native persistence request for any synced purge,
    /// including one behind the current Mongo head. True is RAM acceptance:
    /// poll retained status.redisApplied for the actual durable acknowledgment.
    bool tryMarkRedisApplied(string id, ulong sequence) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        foreach (i; 0 .. operationCount) if (operations[i].operationId == id && operations[i].sequence == sequence) {
            if (operations[i].redisApplied) return true;
            if (operations[i].state != ArchiveOperationState.admitted || !sequence
                    || status.failed || atomicLoad(workerFailure) || stopRequested
                    || (redisStageRequest && redisStageRequest != sequence)) return false;
            redisStageRequest = sequence;
            changed.notify();
            return true;
        }
        return false;
    }
    /// Nothrow emergency signal used by the consumer-fiber boundary. Native
    /// ownership persists sticky failure and retains the unacknowledged record.
    void reportWorkerFailure() nothrow { atomicStore(workerFailure, true); }
    version (MemoryReliabilityHarness) {
        /// Native-thread-only contention fixture, bounded even if its owner fails.
        void harnessHoldAdmissionLock(shared(bool)* entered, shared(bool)* release) {
            mutex.lock();
            scope(exit) mutex.unlock();
            atomicStore(*entered, true);
            const deadline = MonoTime.currTime + 5.seconds;
            while (!atomicLoad(*release) && MonoTime.currTime < deadline) Thread.sleep(1.msecs);
        }
        /// Test-only native-drain gate, always auto-released within two seconds.
        bool harnessPauseDrain(Duration duration = 2.seconds) {
            if (duration <= Duration.zero || duration > 2.seconds || !mutex.tryLock()) return false;
            scope(exit) mutex.unlock();
            if (!status.ready || status.failed || stopRequested) return false;
            harnessGateRequested = true; harnessGateEntered = false;
            harnessGateDeadline = MonoTime.currTime + duration;
            changed.notify();
            return true;
        }
        bool harnessDrainPaused(out bool entered) {
            if (!mutex.tryLock()) return false;
            scope(exit) mutex.unlock();
            entered = harnessGateEntered && MonoTime.currTime < harnessGateDeadline;
            return true;
        }
        bool harnessResumeDrain() {
            if (!mutex.tryLock()) return false;
            scope(exit) mutex.unlock();
            harnessGateRequested = harnessGateEntered = false;
            changed.notify();
            return true;
        }
        bool harnessFailNextSync() {
            if (!mutex.tryLock()) return false;
            scope(exit) mutex.unlock();
            if (!status.ready || status.failed || stopRequested) return false;
            harnessSyncFailure = true;
            return true;
        }
        private bool harnessDrainGate() {
            mutex.lock();
            scope(exit) mutex.unlock();
            if (!harnessGateRequested || stopRequested || MonoTime.currTime >= harnessGateDeadline) {
                harnessGateRequested = harnessGateEntered = false;
                return false;
            }
            harnessGateEntered = true;
            auto remaining = harnessGateDeadline - MonoTime.currTime;
            if (remaining > 25.msecs) remaining = 25.msecs;
            if (remaining > Duration.zero) changed.wait(remaining);
            return true;
        }
    }
    void reportConflict() {
        mutex.lock();
        scope(exit) mutex.unlock();
        conflict = true;
        changed.notify();
    }
    /// Event-loop-safe shutdown initiation. Clean eligibility is explicit and
    /// immutable on the first request; a late FIFO ack cannot upgrade timeout.
    /// fencedTail records possible socket-read events rejected by the ingress
    /// fence before the owner may clear the session marker.
    void requestShutdown(Duration timeout = 5.seconds,
            ArchiveShutdown eligibility = ArchiveShutdown.unclean, bool fencedTail = false) {
        if (timeout > 5.seconds) timeout = 5.seconds;
        if (timeout < Duration.zero) timeout = Duration.zero;
        mutex.lock();
        scope(exit) mutex.unlock();
        if (!stopRequested) {
            stopRequested = true;
            stopDeadline = MonoTime.currTime + timeout;
            stopCleanEligible = timeout > Duration.zero && eligibility == ArchiveShutdown.producersDrained;
            stopFenceTail = fencedTail;
            status.stopping = true;
            changed.notifyAll();
        }
    }
    /// Native/final-exit convenience. The caller must explicitly prove that no
    /// producer can resume; this never joins a blocked syscall or waits Mongo.
    bool shutdown(Duration timeout = 5.seconds,
            ArchiveShutdown eligibility = ArchiveShutdown.unclean) {
        requestShutdown(timeout, eligibility);
        mutex.lock();
        scope(exit) mutex.unlock();
        while (!status.stopped) {
            auto remaining = stopDeadline - MonoTime.currTime;
            if (remaining <= Duration.zero) return false;
            changed.wait(remaining);
        }
        return !status.failed && status.cleanShutdown;
    }

    private static bool validScope(string server, string network, string channel) {
        return server.length && server.length <= 128 && network.length && network.length <= 128
            && channel.length && channel.length <= 512;
    }
    private static Json baseRecord(string kind, string server, string network, string channel) {
        auto j = Json.emptyObject;
        j["kind"] = kind; j["serverId"] = server; j["networkId"] = network; j["channel"] = channel;
        j["queuedAtMs"] = nowMs();
        return j;
    }
    private ArchiveAdmission reject(ArchiveAdmission admission) {
        atomicStore(rejected, true);
        return admission;
    }
    private ArchiveAdmission enqueue(string encoded, ArchiveKind kind, string serverId,
            string networkId, long queuedAt) {
        if (encoded.length > archiveMaxRecordBytes || (kind != ArchiveKind.append && encoded.length > maxControlRecordBytes))
            return reject(ArchiveAdmission.oversized);
        // Never wait for capacity or I/O. Yield only for bounded in-memory
        // bookkeeping, rather than reporting false overflow on lock contention.
        mutex.lock();
        scope(exit) mutex.unlock();
        if (!status.ready || status.failed || atomicLoad(workerFailure) || stopRequested)
            return reject(ArchiveAdmission.unavailable);
        if (kind == ArchiveKind.purge) {
            auto j = parseJsonString(encoded);
            foreach (i; 0 .. operationCount) if (operations[i].operationId == j["operationId"].get!string) {
                const s = operations[i];
                if (s.ownerId != j["ownerId"].get!string || s.serverId != j["serverId"].get!string
                    || s.networkId != j["networkId"].get!string || s.channel != j["channel"].get!string
                    || s.scopedLineageId != j["scopedLineageId"].get!string
                    || s.legacyLineageId != j["legacyLineageId"].get!string)
                    return ArchiveAdmission.unavailable;
                return s.state == ArchiveOperationState.failed ? ArchiveAdmission.unavailable : ArchiveAdmission.queued;
            }
            size_t pending;
            foreach (i; 0 .. operationCount) if (operations[i].state == ArchiveOperationState.admitted
                || operations[i].state == ArchiveOperationState.requested) ++pending;
            if (pending >= 128 || operationCount == operations.length) return reject(ArchiveAdmission.full);
        }
        if (count == maxCommands || bytes + encoded.length > maxIngressBytes
            || (kind == ArchiveKind.append && (dataCount >= maxCommands - controlCommands
                || dataBytes + encoded.length > maxIngressBytes - controlIngressBytes)))
            return reject(ArchiveAdmission.full);
        // All callers pass a newly encoded, exact-sized immutable JSON string.
        auto tracker = addNetworkPending(serverId, networkId, encoded.length, queuedAt);
        ingress[(head + count) % maxCommands] = Command(encoded, kind, tracker);
        ++count; bytes += encoded.length;
        if (kind == ArchiveKind.append) { ++dataCount; dataBytes += encoded.length; }
        if (kind == ArchiveKind.purge) {
            auto s = operationFromJson(parseJsonString(encoded));
            s.state = ArchiveOperationState.requested;
            operations[operationCount++] = s;
        }
        changed.notify();
        return ArchiveAdmission.queued;
    }

    private void run() {
        mutex.lock(); ++status.diskThreads; mutex.unlock();
        scope(exit) {
            scope(exit) progressSignal.emit();
            mutex.lock(); bool shuttingDown = stopRequested; mutex.unlock();
            if (shuttingDown && unclean && !nativeFailed)
                addGap(sessionStart, nowMs(), "shutdown_deadline_uncertainty");
            version (Posix) {
                if (appendFd >= 0) close(appendFd);
                if (stateFd >= 0) close(stateFd);
                if (lockFd >= 0) close(lockFd);
                if (directoryFd >= 0) close(directoryFd);
            }
            mutex.lock();
            scope(exit) mutex.unlock();
            status.ready = false; status.stopped = true;
            --status.diskThreads;
            status.gaps = gaps; status.gapLength = gapLength; status.gapCount = gapLength;
            foreach (i; 0 .. operationCount)
                if (!operations[i].sequence && (operations[i].state == ArchiveOperationState.admitted
                    || operations[i].state == ArchiveOperationState.requested))
                    operations[i].state = ArchiveOperationState.unknown;
            ingress[] = Command.init;
            count = bytes = dataCount = dataBytes = 0;
            replay = null; borrowed = false;
            changed.notifyAll();
        }
        try {
            version (Posix) {
                initialize();
                publish();
                bool shutdownRecorded;
                while (true) {
                    bool stop, bad, cleanEligible, fencedTail;
                    MonoTime deadline;
                    mutex.lock();
                    stop = stopRequested; deadline = stopDeadline; bad = conflict;
                    cleanEligible = stopCleanEligible; fencedTail = stopFenceTail;
                    mutex.unlock();
                    require(!atomicLoad(workerFailure), "archive_consumer_failure");
                    require(!bad, "immutable_identity_conflict");
                    if (stop && !shutdownRecorded) {
                        if (fencedTail)
                            addGap(sessionStart, nowMs(), "producer_fence_tail_uncertainty");
                        else if (!cleanEligible)
                            addGap(sessionStart, nowMs(), "shutdown_producer_uncertainty");
                        // This gap must be durable BEFORE any clean marker.
                        // Future rejected puts cannot create accepted live rows.
                        saveState();
                        shutdownRecorded = true;
                    }
                    if (cas(&rejected, true, false)) {
                        addGap(bornAtMs, nowMs(), "admission_rejected");
                        saveState();
                        emitGap();
                    }
                    if (nowMs() >= nextStatusExpiry) {
                        saveState(); // Prunes expired terminal results even idle.
                        mutex.lock();
                        try syncPublicOperations();
                        finally mutex.unlock();
                    }
                    persistRedisStage();
                    acknowledge();
                    if (stop && MonoTime.currTime >= deadline) return; // Leave durable unclean marker.
                    version (MemoryReliabilityHarness) {
                        if (!harnessDrainGate()) drainBatch();
                    } else drainBatch();
                    publish();
                    if (stop) {
                        mutex.lock(); bool empty = count == 0; mutex.unlock();
                        if (MonoTime.currTime >= deadline) return;
                        if (empty) {
                            if (!cleanEligible) return; // Keep durable unclean.
                            unclean = false; saveState();
                            if (MonoTime.currTime >= deadline) {
                                unclean = true; saveState();
                                return;
                            }
                            mutex.lock(); status.cleanShutdown = true; mutex.unlock();
                            return;
                        }
                    }
                    if (!stop) prepareReplay();
                    serviceDiagnostic();
                    progressSignal.emit();
                    mutex.lock();
                    try {
                        if (!count && !acknowledgeSequence && !redisStageRequest && !stopRequested) changed.wait(25.msecs);
                    } finally mutex.unlock();
                }
            } else throw new Exception("posix_required");
        } catch (Exception e) {
            nativeFailed = true;
            addGap(sessionStart ? sessionStart : nowMs(), nowMs(), "journal_unavailable");
            version (Posix) if (writableState) {
                try {
                    saveState();
                    mutex.lock();
                    try syncPublicOperations();
                    finally mutex.unlock();
                } catch (Exception) {}
            }
            auto journalError = cast(JournalException) e;
            mutex.lock(); status.failed = true;
            status.failureReason = journalError is null ? "journal_failure" : journalError.msg;
            mutex.unlock();
            emitGap();
            publish();
        }
    }

    private void serviceDiagnostic() {
        if (diagnostics is null) return;
        auto encoded = diagnostics.takeLatest();
        if (encoded is null) return;
        DiagnosticWriteResult result;
        try result = writeLatest(config.diagnosticPath, encoded);
        catch (Exception) result = DiagnosticWriteResult.writeError;
        encoded = null;
        diagnostics.finishWrite(result, nowMs());
    }
    private void emitGap() {
        auto now = nowMs();
        if (lastDiagnostic && now - lastDiagnostic < 30_000) return;
        lastDiagnostic = now;
        // Fixed diagnostic: no IRC contents, nicknames, credentials or paths.
        import core.stdc.stdio : fputs, stderr;
        fputs("{\"event\":\"archive_gap\",\"state\":\"degraded\",\"component\":\"engine\"}\n", stderr);
    }
    private void addGap(long first, long last, string reason) {
        if (!first) first = nowMs();
        if (last < first) last = first;
        if (gapLength && gaps[gapLength - 1].reason == reason && gaps[gapLength - 1].throughMs >= first - 1) {
            if (last > gaps[gapLength - 1].throughMs) gaps[gapLength - 1].throughMs = last;
            return;
        }
        if (gapLength == gaps.length) {
            // Conservative union is intentionally not a claim of exact loss.
            long lo = first, hi = last;
            foreach (g; gaps) { if (g.fromMs < lo) lo = g.fromMs; if (g.throughMs > hi) hi = g.throughMs; }
            gaps[] = ArchiveGap.init;
            gaps[0] = ArchiveGap(lo, hi, 0, 0, "", "merged_uncertainty");
            gapLength = 1;
        } else gaps[gapLength++] = ArchiveGap(first, last, 0, 0, "", reason.idup);
    }
    private void publish() {
        const sampled = nowMs();
        ulong accountedDisk;
        bool diskKnown;
        version (Posix) {
            if (!nativeFailed && stateFd >= 0 && spoolId.length) {
                accountedDisk = allocatedBytes();
                diskKnown = true;
                if (sampled >= nextDiskSampleAtMs) {
                    statvfs_t fs;
                    measuredFreeKnown = fstatvfs(directoryFd, &fs) == 0;
                    if (measuredFreeKnown) measuredFreeBytes = cast(ulong) fs.f_bavail * fs.f_frsize;
                    measuredDiskAtMs = sampled; nextDiskSampleAtMs = sampled + 1_000;
                }
            }
        }
        mutex.lock();
        scope(exit) mutex.unlock();
        status.ready = !nativeFailed && directoryFd >= 0;
        status.failed = nativeFailed;
        status.checkpoint = checkpoint;
        status.durableSequence = durableSequence;
        status.spoolId = spoolId;
        status.sampledAtMs = sampled;
        status.diskBytesKnown = diskKnown; status.diskBytes = accountedDisk;
        status.maxBytes = config.maxBytes; status.minFreeBytes = config.minFreeBytes;
        status.controlReserveBytes = controlReserve; status.stateReserveBytes = stateBytes;
        status.diskSampledAtMs = measuredDiskAtMs;
        status.freeBytesKnown = measuredFreeKnown && sampled - measuredDiskAtMs <= 90_000;
        status.freeBytes = measuredFreeBytes;
        status.gapLength = gapLength; status.gaps = gaps; status.gapCount = gapLength;
        status.oldestAtMs = oldestAtMs;
        status.pendingBytes = 0;
        foreach (s; segments[0 .. segmentCount]) if (s.last > checkpoint) status.pendingBytes += s.size;
        status.pendingOperations = 0;
        foreach (i; 0 .. operationCount) if (operations[i].state == ArchiveOperationState.admitted
            || operations[i].state == ArchiveOperationState.requested) ++status.pendingOperations;
    }

    private static ArchiveOperationStatus operationFromJson(Json j) {
        ArchiveOperationStatus s;
        s.operationId = j["operationId"].get!string.idup; s.ownerId = j["ownerId"].get!string.idup;
        require(validCanonicalUuid(s.operationId), "invalid_purge_identity");
        s.serverId = j["serverId"].get!string.idup; s.networkId = j["networkId"].get!string.idup;
        s.channel = j["channel"].get!string.idup;
        s.scopedLineageId = j["scopedLineageId"].get!string.idup;
        s.legacyLineageId = j["legacyLineageId"].get!string.idup;
        require(validLineage(s.scopedLineageId) && validLineage(s.legacyLineageId), "invalid_purge_lineage");
        s.cutoffEid = j["cutoffEid"].get!long; s.legacyCutoffMs = j["legacyCutoffMs"].get!long;
        s.updatedAtMs = nowMs();
        return s;
    }

    version (Posix) {
        version (MemoryReliabilityHarness) {
            private void syncFd(int fd) {
                mutex.lock(); const fail = harnessSyncFailure; harnessSyncFailure = false; mutex.unlock();
                if (fail) throw new JournalException("injected_sync_failure");
                rawSyncFd(fd);
            }
        } else private alias syncFd = rawSyncFd;
        private void initialize() {
            require(config.maxBytes >= stateBytes + controlReserve + archiveSegmentBytes, "invalid_budget");
            directoryFd = openDirectory(config.directory);
            require(directoryFd >= 0, "unsafe_archive_directory");
            stat_t st;
            require(fstat(directoryFd, &st) == 0 && st.st_uid == geteuid()
                && (st.st_mode & 18 /*0022*/) == 0, "unsafe_archive_directory_owner_mode");
            // Validate the bounded directory before creating either fixed file.
            scanDirectory();
            lockFd = openOwned("lock", true);
            require(flock(lockFd, 2 | 4) == 0, "archive_lock_busy");
            scanDirectory(); // Re-observe only after exclusive ownership.
            bool newState;
            stateFd = openOwned("state", true, &newState);
            require(fstat(stateFd, &st) == 0 && st.st_size >= 0 && st.st_size <= stateBytes,
                "invalid_state_size");
            require(!newState || !segmentCount, "journal_state_missing");
            // Interrupted first-time reserve allocation cannot have admitted
            // data. Only an entirely zero state with no segments is reusable.
            if (!segmentCount && isZeroFile(stateFd, cast(size_t) st.st_size)) newState = true;
            if (newState) {
                statvfs_t fs;
                require(fstatvfs(directoryFd, &fs) == 0, "filesystem_space_unavailable");
                auto free = cast(ulong) fs.f_bavail * fs.f_frsize;
                ulong allocated = cast(ulong) st.st_blocks * 512;
                ulong needed = allocated >= stateBytes ? 0 : stateBytes - allocated;
                require(free >= config.minFreeBytes && free - config.minFreeBytes >= needed,
                    "state_filesystem_reserve_unavailable");
                // Actually allocate the reserve rather than creating sparse slots.
                ubyte[65_536] zero;
                require(lseek(stateFd, 0, 0 /*SEEK_SET*/) == 0, "state_seek_failed");
                foreach (i; 0 .. stateBytes / zero.length) fullWrite(stateFd, zero[]);
                syncFd(stateFd); syncFd(directoryFd);
            }
            require(fstat(stateFd, &st) == 0 && st.st_size == stateBytes, "invalid_state_size");
            bool loaded = loadState();
            require(loaded || (!segmentCount && newState), "missing_valid_state");
            if (!loaded) spoolId = randomUUID().toString();
            writableState = true;
            if (nativeFailed) {
                mutex.lock(); operations = diskOperations; operationCount = diskOperationCount; mutex.unlock();
                throw new JournalException("sticky_archival_failure");
            }
            bool previousUnclean = unclean;
            long previousStart = sessionStart;
            syncFd(directoryFd);
            recoverSegments();
            if (previousUnclean) addGap(previousStart, nowMs(), "unclean_ram_admission_uncertainty");
            sessionStart = bornAtMs; unclean = true;
            saveState(); // Must precede accepting the first live archival command.
            mutex.lock();
            operations = diskOperations; operationCount = diskOperationCount;
            mutex.unlock();
            if (segmentCount) {
                appendFd = openOwned(segments[segmentCount - 1].name, false);
                require(lseek(appendFd, 0, SEEK_END) >= 0, "segment_seek_failed");
            }
        }
        private bool isZeroFile(int fd, size_t length) {
            ubyte[65_536] block;
            size_t offset;
            while (offset < length) {
                auto amount = length - offset;
                if (amount > block.length) amount = block.length;
                require(readAt(fd, block[0 .. amount], offset) == amount, "state_read_failed");
                foreach (b; block[0 .. amount]) if (b) return false;
                offset += amount;
            }
            return true;
        }

        private void scanDirectory() {
            segments[] = Segment.init;
            segmentCount = 0;
            int duplicate = openat(directoryFd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            require(duplicate >= 0, "directory_dup_failed");
            auto dir = fdopendir(duplicate);
            if (dir is null) { close(duplicate); throw new Exception("directory_scan_failed"); }
            scope(exit) closedir(dir);
            size_t files;
            while (true) {
                errno = 0;
                auto entry = readdir(dir);
                if (entry is null) { require(errno == 0, "directory_read_failed"); break; }
                import std.string : fromStringz;
                auto name = fromStringz(entry.d_name.ptr);
                if (name == "." || name == "..") continue;
                require(++files <= maxFiles, "archive_file_limit");
                if (name == "lock" || name == "state") continue;
                require(name.length == 32 && name[0 .. 8] == "segment-" && name[28 .. $] == ".log", "unexpected_archive_file");
                foreach (c; name[8 .. 28]) require(c >= '0' && c <= '9', "invalid_segment_name");
                ulong first = name[8 .. 28].to!ulong;
                require(first > 0 && segmentCount < segments.length, "segment_limit");
                segments[segmentCount++] = Segment(first, 0, 0, name.idup);
            }
            import std.algorithm : sort;
            sort!((a, b) => a.first < b.first)(segments[0 .. segmentCount]);
        }

        private void recoverSegments() {
            ulong previous;
            bool sawPending;
            foreach (i; 0 .. segmentCount) {
                auto fd = openOwned(segments[i].name, false);
                scope(exit) close(fd);
                // A previous process may have left a complete, checksummed
                // frame in the kernel cache without syncing it before exit.
                syncFd(fd);
                stat_t st;
                require(fstat(fd, &st) == 0 && st.st_size >= 0 && st.st_size <= archiveSegmentBytes, "invalid_segment_size");
                ubyte[8] magic;
                if (st.st_size < 8) {
                    require(i + 1 == segmentCount, "interior_torn_segment_header");
                    const expected = previous ? previous + 1 : checkpoint + 1;
                    require(segments[i].first == expected && expected >= nextSequence,
                        "committed_or_conflicting_torn_segment");
                    const bytes = cast(size_t) st.st_size;
                    require(readAt(fd, magic[0 .. bytes], 0) == bytes
                        && cast(string) magic[0 .. bytes] == segmentMagic[0 .. bytes],
                        "corrupt_final_segment_header");
                    // No record could have been acknowledged in this new
                    // segment. Retain the preceding prefix; remove only its
                    // identifiable, uncommitted header and sync that removal.
                    require(unlinkat(directoryFd, segments[i].name.toStringz, 0) == 0,
                        "torn_segment_remove_failed");
                    syncFd(directoryFd);
                    segments[--segmentCount] = Segment.init;
                    addGap(sessionStart, nowMs(), "torn_segment_uncertainty");
                    break;
                }
                require(readAt(fd, magic[], 0) == 8 && cast(string) magic[] == segmentMagic, "invalid_segment_magic");
                size_t offset = 8;
                while (offset < st.st_size) {
                    ubyte[16] header;
                    auto got = readAt(fd, header[], offset);
                    if (got < 16) {
                        require(i + 1 == segmentCount, "interior_torn_frame");
                        truncateFinal(fd, offset, previous ? previous + 1 : segments[i].first);
                        st.st_size = cast(typeof(st.st_size)) offset; break;
                    }
                    auto length = little!uint(header[0 .. 4]);
                    auto sequence = little!ulong(header[8 .. 16]);
                    require(length > 0 && length <= archiveMaxRecordBytes && length + 16 <= archiveSegmentBytes - 8,
                        "invalid_frame_length");
                    require(sequence == (previous ? previous + 1 : segments[i].first), "frame_sequence_conflict");
                    if (offset == 8) require(sequence == segments[i].first, "segment_identity_conflict");
                    if (offset + 16 + length > st.st_size) {
                        require(i + 1 == segmentCount, "interior_torn_frame");
                        // A corrupt length can conceal complete later frames even
                        // when the saved nextSequence predates this synced batch.
                        requireNoLaterFrame(fd, offset + 16, cast(size_t) st.st_size);
                        truncateFinal(fd, offset, sequence);
                        st.st_size = cast(typeof(st.st_size)) offset; break;
                    }
                    auto data = new ubyte[length];
                    require(readAt(fd, data, offset + 16) == length, "frame_read_failed");
                    require(frameCrc(sequence, data) == little!uint(header[4 .. 8]), "frame_checksum_corruption");
                    previous = sequence;
                    auto record = decodeArchiveRecord(cast(string) data, sequence);
                    if (sequence > checkpoint) {
                        require(sawPending || sequence == checkpoint + 1, "recovery_sequence_gap");
                        sawPending = true;
                        if (!oldestAtMs) oldestAtMs = record.timestampMs;
                        if (record.kind == ArchiveKind.purge) rememberPurge(record);
                        mutex.lock();
                        try addNetworkPending(record.serverId, record.networkId, length, record.queuedAtMs);
                        finally mutex.unlock();
                    }
                    segments[i].last = sequence;
                    offset += 16 + length;
                }
                if (offset == 8) {
                    const expected = previous ? previous + 1 : checkpoint + 1;
                    require(i + 1 == segmentCount && segments[i].first == expected
                        && expected >= nextSequence, "empty_or_conflicting_segment");
                }
                segments[i].size = offset;
                require(fstat(fd, &st) == 0, "segment_stat_failed");
                segments[i].allocated = cast(ulong) st.st_blocks * 512;
            }
            require(!previous || previous >= checkpoint, "checkpoint_past_journal");
            durableSequence = previous > checkpoint ? previous : checkpoint;
            require(durableSequence < ulong.max, "sequence_exhausted");
            require(nextSequence <= durableSequence + 1, "sequence_watermark_conflict");
            nextSequence = durableSequence + 1;
            reclaim();
        }
        /// Prove the apparent torn payload has no later checksummed frame before
        /// truncating. Stream headers and CRCs with fixed scratch storage: no
        /// payload index or second record allocation. Hostile candidate headers
        /// exhaust a finite validation budget and fail closed, preserving bytes.
        private void requireNoLaterFrame(int fd, size_t start, size_t end) {
            enum size_t scanBlockBytes = 4096;
            enum size_t maxCandidates = 128;
            enum size_t maxValidationBytes = 16 * 1024 * 1024;
            ubyte[scanBlockBytes + 15] headers;
            ubyte[scanBlockBytes] payload;
            size_t candidates, validatedBytes;
            while (start + 16 <= end) {
                auto starts = end - start - 15;
                if (starts > scanBlockBytes) starts = scanBlockBytes;
                require(readAt(fd, headers[0 .. starts + 15], start) == starts + 15,
                    "torn_frame_scan_read_failed");
                foreach (at; 0 .. starts) {
                    const length = little!uint(headers[at .. at + 4]);
                    const laterSequence = little!ulong(headers[at + 8 .. at + 16]);
                    if (!length || length > archiveMaxRecordBytes || !laterSequence
                            || length > end - (start + at + 16)) continue;
                    require(candidates < maxCandidates && length <= maxValidationBytes - validatedBytes,
                        "torn_frame_scan_budget_exhausted");
                    ++candidates; validatedBytes += length;
                    uint crc = uint.max;
                    foreach (i; 0 .. 8)
                        crc = crcTable[(crc ^ cast(ubyte)(laterSequence >> (i * 8))) & 255] ^ (crc >> 8);
                    size_t done;
                    while (done < length) {
                        auto amount = length - done;
                        if (amount > payload.length) amount = payload.length;
                        require(readAt(fd, payload[0 .. amount], start + at + 16 + done) == amount,
                            "torn_frame_scan_read_failed");
                        foreach (b; payload[0 .. amount]) crc = crcTable[(crc ^ b) & 255] ^ (crc >> 8);
                        done += amount;
                    }
                    require(~crc != little!uint(headers[at + 4 .. at + 8]),
                        "interior_frame_length_corruption");
                }
                start += starts;
            }
        }

        private void truncateFinal(int fd, size_t offset, ulong expectedSequence) {
            require(expectedSequence >= nextSequence, "durable_frame_truncated");
            require(ftruncate(fd, cast(long) offset) == 0, "torn_frame_truncate_failed");
            syncFd(fd);
            addGap(sessionStart, nowMs(), "torn_final_frame_uncertainty");
        }

        private bool drainBatch() {
            size_t batchBytes, batchCount;
            bool hasPurge;
            const deadline = MonoTime.currTime + 25.msecs;
            while (true) {
                mutex.lock();
                bool expired, available;
                Command command;
                try {
                    expired = MonoTime.currTime >= deadline || (stopRequested && MonoTime.currTime >= stopDeadline);
                    available = count > batchCount;
                    if (!available && batchCount && !stopRequested) {
                        auto remaining = deadline - MonoTime.currTime;
                        if (remaining > Duration.zero) {
                            changed.wait(remaining);
                            available = count > batchCount;
                        }
                    }
                    if (available) command = ingress[(head + batchCount) % maxCommands];
                } finally mutex.unlock();
                if (expired) break;
                if (!available) break;
                if (batchCount && (batchBytes + command.encoded.length + 16 > 65_536
                        || MonoTime.currTime >= deadline)) break;
                if (!canWrite(command)) {
                    if (batchCount) break; // Sync admitted prefix first.
                    addGap(sessionStart, nowMs(), "disk_capacity_rejected");
                    if (command.kind == ArchiveKind.purge) failQueuedPurge(command.encoded);
                    saveState(); emitGap();
                    releaseHead(command, true);
                    continue;
                }
                // Never rotate away from an unsynced batch's file.
                if (batchCount && segments[segmentCount - 1].size
                        + command.encoded.length + 16 > archiveSegmentBytes) break;
                writeCommand(command);
                hasPurge = hasPurge || command.kind == ArchiveKind.purge;
                batchBytes += command.encoded.length + 16;
                ++batchCount;
            }
            if (!batchCount) return false;
            syncFd(appendFd);
            syncFd(directoryFd);
            stat_t st;
            require(fstat(appendFd, &st) == 0, "segment_stat_failed");
            segments[segmentCount - 1].allocated = cast(ulong) st.st_blocks * 512;
            durableSequence = nextSequence - 1;
            if (hasPurge) {
                foreach (i; 0 .. batchCount) {
                    mutex.lock(); auto command = ingress[(head + i) % maxCommands]; mutex.unlock();
                    if (command.kind != ArchiveKind.purge) continue;
                    auto record = decodeArchiveRecord(command.encoded, durableSequence - batchCount + 1 + i);
                    rememberPurge(record);
                }
                saveState();
            }
            foreach (i; 0 .. batchCount) {
                mutex.lock(); auto command = ingress[head]; mutex.unlock();
                releaseHead(command);
            }
            return true;
        }
        private void releaseHead(ref Command command, bool lost = false) {
            mutex.lock();
            scope(exit) mutex.unlock();
            if (lost) removeNetworkPending(command.tracker, command.encoded.length);
            bytes -= command.encoded.length;
            if (command.kind == ArchiveKind.append) { --dataCount; dataBytes -= command.encoded.length; }
            ingress[head] = Command.init;
            head = (head + 1) % maxCommands; --count;
            if (!count && checkpoint == durableSequence) networkOverflow = false;
            bool control = command.kind == ArchiveKind.purge;
            command = Command.init;
            if (control) syncPublicOperations();
        }
        // Called with mailbox mutex held. Preserve RAM-admitted purge IDs that
        // have not reached the disk yet when publishing durable completions.
        private void syncPublicOperations() {
            ArchiveOperationStatus[128] queued;
            size_t n;
            foreach (i; 0 .. operationCount) {
                auto s = operations[i];
                if (s.sequence || s.state != ArchiveOperationState.requested) continue;
                bool found;
                foreach (d; diskOperations[0 .. diskOperationCount])
                    if (d.operationId == s.operationId) { found = true; break; }
                if (!found && n < queued.length) queued[n++] = s;
            }
            operations = diskOperations;
            operationCount = diskOperationCount;
            foreach (s; queued[0 .. n]) {
                require(operationCount < operations.length, "public_operation_limit");
                operations[operationCount++] = s;
            }
        }
        private ulong allocatedBytes() {
            ulong used = stateBytes;
            foreach (i; 0 .. segmentCount) {
                auto s = segments[i];
                auto reserved = roundBlock(s.size);
                if (i + 1 == segmentCount) reserved = archiveSegmentBytes;
                used += s.allocated > reserved ? s.allocated : reserved;
            }
            // Stable lock, filesystem bookkeeping and frame block rounding.
            return used + 4096;
        }
        private bool canWrite(ref Command command) {
            statvfs_t fs;
            require(fstatvfs(directoryFd, &fs) == 0, "filesystem_space_unavailable");
            ulong required = roundBlock(command.encoded.length + 16 + 8);
            ulong free = cast(ulong) fs.f_bavail * fs.f_frsize;
            if (free < config.minFreeBytes || free - config.minFreeBytes < required) return false;
            bool newSegment = !segmentCount || segments[segmentCount - 1].size + command.encoded.length + 16 > archiveSegmentBytes;
            // Three file slots guarantee 8 MiB of bounded control frames even
            // when large append frames leave unusable tails in data segments.
            if (command.kind == ArchiveKind.append
                    && (segmentCount > segments.length - controlSegmentReserve
                        || (newSegment && segmentCount >= segments.length - controlSegmentReserve))) return false;
            ulong reservation = newSegment ? archiveSegmentBytes : 0;
            auto used = allocatedBytes();
            auto limit = config.maxBytes - (command.kind == ArchiveKind.append ? controlReserve : 0);
            if (used > limit || reservation > limit - used) return false;
            return !newSegment || segmentCount < segments.length;
        }
        private void writeCommand(ref Command command) {
            require(nextSequence < ulong.max, "sequence_exhausted");
            if (!segmentCount || segments[segmentCount - 1].size + command.encoded.length + 16 > archiveSegmentBytes) {
                if (appendFd >= 0) { close(appendFd); appendFd = -1; }
                auto name = format("segment-%020u.log", nextSequence);
                appendFd = openOwned(name, true, null, true);
                fullWrite(appendFd, cast(const(ubyte)[]) segmentMagic);
                syncFd(appendFd); syncFd(directoryFd);
                segments[segmentCount++] = Segment(nextSequence, 0, 8, name);
            }
            ubyte[16] header;
            putLittle!uint(header[0 .. 4], cast(uint) command.encoded.length);
            putLittle!uint(header[4 .. 8], frameCrc(nextSequence, cast(const(ubyte)[]) command.encoded));
            putLittle!ulong(header[8 .. 16], nextSequence);
            fullWrite(appendFd, header[]);
            fullWrite(appendFd, cast(const(ubyte)[]) command.encoded);
            auto r = decodeArchiveRecord(command.encoded, nextSequence);
            segments[segmentCount - 1].last = nextSequence;
            segments[segmentCount - 1].size += 16 + command.encoded.length;
            if (!oldestAtMs) oldestAtMs = r.timestampMs;
            ++nextSequence;
        }

        private void prepareReplay() {
            mutex.lock(); bool occupied = replay !is null; mutex.unlock();
            if (occupied || checkpoint >= durableSequence) return;
            foreach (i; 0 .. segmentCount) {
                if (segments[i].last <= checkpoint) continue;
                auto fd = openOwned(segments[i].name, false);
                scope(exit) close(fd);
                size_t offset = (scanSegment == i && scanOffset >= 8) ? scanOffset : 8;
                while (offset < segments[i].size) {
                    ubyte[16] h;
                    require(readAt(fd, h[], offset) == 16, "replay_header_failed");
                    auto len = little!uint(h[0 .. 4]);
                    auto seq = little!ulong(h[8 .. 16]);
                    require(len && len <= archiveMaxRecordBytes && offset + 16 + len <= segments[i].size, "replay_frame_corruption");
                    if (seq <= checkpoint) { offset += 16 + len; continue; }
                    require(seq == checkpoint + 1, "replay_sequence_gap");
                    auto payload = new ubyte[len];
                    require(readAt(fd, payload, offset + 16) == len && frameCrc(seq, payload) == little!uint(h[4 .. 8]), "replay_checksum_corruption");
                    scanSegment = i; scanOffset = offset + 16 + len;
                    auto record = decodeArchiveRecord(cast(string) payload, seq);
                    mutex.lock();
                    replay = cast(string) payload; replaySequence = seq; borrowed = false;
                    redisAppliedSequence = 0;
                    foreach (operationIndex; 0 .. operationCount)
                        if (operations[operationIndex].sequence == seq && operations[operationIndex].redisApplied)
                            redisAppliedSequence = seq;
                    auto tracker = networkIndex(record.serverId, record.networkId, false);
                    if (tracker != size_t.max) {
                        networks[tracker].oldestAtMs = record.queuedAtMs;
                        networks[tracker].oldestKnown = true;
                    }
                    mutex.unlock();
                    return;
                }
            }
            throw new Exception("durable_record_missing");
        }
        private void persistRedisStage() {
            mutex.lock(); const sequence = redisStageRequest; mutex.unlock();
            if (!sequence) return;
            bool found;
            foreach (i; 0 .. diskOperationCount) if (diskOperations[i].sequence == sequence) {
                require(diskOperations[i].state == ArchiveOperationState.admitted, "invalid_redis_stage_state");
                diskOperations[i].redisApplied = true;
                found = true;
                break;
            }
            require(found && sequence <= durableSequence, "redis_stage_identity_conflict");
            saveState(); // Positive Redis evidence becomes visible only here.
            mutex.lock();
            scope(exit) mutex.unlock();
            syncPublicOperations();
            if (replaySequence == sequence) redisAppliedSequence = sequence;
            redisStageRequest = 0;
            changed.notifyAll();
        }
        private void acknowledge() {
            mutex.lock(); auto seq = acknowledgeSequence;
            bool redisReady = seq && redisAppliedSequence == seq;
            mutex.unlock();
            if (!seq) return;
            require(seq == checkpoint + 1, "checkpoint_order_violation");
            auto completedRecord = decodeArchiveRecord(replay, seq);
            const completedBytes = replay.length;
            foreach (i; 0 .. diskOperationCount) if (diskOperations[i].sequence == seq) {
                require(redisReady, "purge_redis_stage_unconfirmed");
                diskOperations[i].redisApplied = true;
                diskOperations[i].state = ArchiveOperationState.completed;
                diskOperations[i].updatedAtMs = nowMs();
            }
            checkpoint = seq;
            saveState(); // Never unlink or relinquish replay before this sync.
            // Completion survives a later reclaim failure and remains queryable
            // even when the archival service becomes unavailable.
            mutex.lock();
            try syncPublicOperations();
            finally mutex.unlock();
            reclaim();
            mutex.lock();
            try {
                auto tracker = networkIndex(completedRecord.serverId, completedRecord.networkId, false);
                removeNetworkPending(tracker, completedBytes);
                if (!count && checkpoint == durableSequence) networkOverflow = false;
                replay = null; replaySequence = 0; borrowed = false; acknowledgeSequence = 0;
                redisAppliedSequence = 0;
                syncPublicOperations();
            } finally mutex.unlock();
            if (checkpoint == durableSequence) oldestAtMs = 0;
        }
        private void reclaim() {
            size_t remove;
            // Retain the writable tail; an empty journal still retains sequence
            // identity in state, so a subsequent recreation cannot reuse eids.
            while (remove + 1 < segmentCount && segments[remove].last <= checkpoint) {
                require(unlinkat(directoryFd, segments[remove].name.toStringz, 0) == 0, "segment_reclaim_failed");
                ++remove;
            }
            if (!remove) return;
            syncFd(directoryFd);
            foreach (i; remove .. segmentCount) segments[i - remove] = segments[i];
            segments[segmentCount - remove .. segmentCount] = Segment.init;
            segmentCount -= remove;
            scanSegment = 0; scanOffset = 8;
        }

        private void rememberPurge(ref ArchiveRecord r) {
            foreach (i; 0 .. diskOperationCount) if (diskOperations[i].operationId == r.operationId) {
                auto s = diskOperations[i];
                require(s.sequence == r.sequence && s.ownerId == r.ownerId && s.serverId == r.serverId
                    && s.networkId == r.networkId && s.channel == r.channel && s.cutoffEid == r.cutoffEid
                    && s.legacyCutoffMs == r.legacyCutoffMs
                    && s.scopedLineageId == r.scopedLineageId
                    && s.legacyLineageId == r.legacyLineageId, "purge_identity_conflict");
                return;
            }
            pruneOperations();
            size_t pending;
            foreach (i; 0 .. diskOperationCount) if (diskOperations[i].state == ArchiveOperationState.admitted) ++pending;
            require(pending < 128 && diskOperationCount < diskOperations.length, "purge_status_limit");
            ArchiveOperationStatus s;
            s.operationId = r.operationId; s.ownerId = r.ownerId; s.serverId = r.serverId;
            s.networkId = r.networkId; s.channel = r.channel;
            s.scopedLineageId = r.scopedLineageId; s.legacyLineageId = r.legacyLineageId;
            s.cutoffEid = r.cutoffEid; s.legacyCutoffMs = r.legacyCutoffMs;
            s.sequence = r.sequence; s.state = ArchiveOperationState.admitted; s.updatedAtMs = nowMs();
            diskOperations[diskOperationCount++] = s;
        }
        private void failQueuedPurge(string encoded) {
            auto s = operationFromJson(parseJsonString(encoded));
            s.state = ArchiveOperationState.failed;
            pruneOperations();
            if (diskOperationCount < diskOperations.length) diskOperations[diskOperationCount++] = s;
        }
        private void pruneOperations() {
            size_t kept, complete;
            const cutoff = nowMs() - 7L * 24 * 60 * 60 * 1000;
            foreach (i; 0 .. diskOperationCount) {
                auto s = diskOperations[i];
                if (s.state != ArchiveOperationState.admitted && s.updatedAtMs <= cutoff) continue;
                if (s.state != ArchiveOperationState.admitted) ++complete;
                diskOperations[kept++] = s;
            }
            diskOperations[kept .. diskOperationCount] = ArchiveOperationStatus.init;
            diskOperationCount = kept;
            // Keep <=1024 terminal statuses, always preserving all pending work.
            while (complete > 1_024) {
                size_t oldest = size_t.max;
                foreach (i; 0 .. diskOperationCount) if (diskOperations[i].state != ArchiveOperationState.admitted
                    && (oldest == size_t.max || diskOperations[i].updatedAtMs < diskOperations[oldest].updatedAtMs)) oldest = i;
                foreach (i; oldest + 1 .. diskOperationCount) diskOperations[i - 1] = diskOperations[i];
                diskOperations[--diskOperationCount] = ArchiveOperationStatus.init;
                --complete;
            }
            nextStatusExpiry = long.max;
            foreach (s; diskOperations[0 .. diskOperationCount]) {
                if (s.state == ArchiveOperationState.admitted) continue;
                const expiry = s.updatedAtMs + 7L * 24 * 60 * 60 * 1000;
                if (expiry < nextStatusExpiry) nextStatusExpiry = expiry;
            }
        }

        private Json stateJson() {
            pruneOperations();
            auto j = Json.emptyObject;
            j["spoolId"] = spoolId; j["checkpoint"] = checkpoint; j["nextSequence"] = nextSequence;
            j["unclean"] = unclean; j["sessionStart"] = sessionStart; j["failed"] = nativeFailed;
            auto gs = Json.emptyArray;
            foreach (g; gaps[0 .. gapLength]) {
                auto x = Json.emptyObject; x["from"] = g.fromMs; x["through"] = g.throughMs;
                x["reason"] = g.reason; gs ~= x;
            }
            j["gaps"] = gs;
            auto ops = Json.emptyArray;
            foreach (s; diskOperations[0 .. diskOperationCount]) {
                auto x = Json.emptyObject;
                x["operationId"] = s.operationId; x["ownerId"] = s.ownerId; x["serverId"] = s.serverId;
                x["networkId"] = s.networkId; x["channel"] = s.channel;
                x["scopedLineageId"] = s.scopedLineageId; x["legacyLineageId"] = s.legacyLineageId;
                x["cutoffEid"] = s.cutoffEid; x["legacyCutoffMs"] = s.legacyCutoffMs;
                x["state"] = cast(int) s.state; x["sequence"] = s.sequence;
                x["updatedAtMs"] = s.updatedAtMs; x["redisApplied"] = s.redisApplied;
                ops ~= x;
            }
            j["operations"] = ops;
            return j;
        }
        private void saveState() {
            auto encoded = stateJson().toString();
            require(encoded.length <= slotBytes - 24, "state_capacity_exhausted");
            require(stateGeneration < ulong.max, "state_generation_exhausted");
            const generation = stateGeneration + 1;
            const offset = (generation % 2) * slotBytes;
            ubyte[24] header;
            header[0 .. 8] = cast(const(ubyte)[]) stateMagic;
            putLittle!ulong(header[8 .. 16], generation);
            putLittle!uint(header[16 .. 20], cast(uint) encoded.length);
            putLittle!uint(header[20 .. 24], frameCrc(generation, cast(const(ubyte)[]) encoded));
            fullWriteAt(stateFd, cast(const(ubyte)[]) encoded, offset + 24);
            fullWriteAt(stateFd, header[], offset);
            syncFd(stateFd);
            stateGeneration = generation;
        }
        private bool loadState() {
            string selected;
            ulong best;
            foreach (slot; 0 .. 2) {
                ubyte[24] h;
                if (readAt(stateFd, h[], slot * slotBytes) != h.length || cast(string) h[0 .. 8] != stateMagic) continue;
                auto generation = little!ulong(h[8 .. 16]);
                auto length = little!uint(h[16 .. 20]);
                if (!generation || !length || length > slotBytes - 24) continue;
                auto payload = new ubyte[length];
                if (readAt(stateFd, payload, slot * slotBytes + 24) != length
                    || frameCrc(generation, payload) != little!uint(h[20 .. 24])) continue;
                if (generation > best) { selected = cast(string) payload; best = generation; }
            }
            if (!best) return false;
            auto j = parseJsonString(selected);
            spoolId = j["spoolId"].get!string.idup;
            require(spoolId.length == 36, "invalid_spool_identity");
            checkpoint = j["checkpoint"].get!ulong; nextSequence = j["nextSequence"].get!ulong;
            require(nextSequence > checkpoint, "invalid_state_sequence");
            unclean = j["unclean"].get!bool; sessionStart = j["sessionStart"].get!long;
            require(!unclean || sessionStart > 0, "invalid_unclean_interval");
            nativeFailed = j["failed"].get!bool;
            require(j["gaps"].length <= gaps.length && j["operations"].length <= diskOperations.length, "state_limits_invalid");
            foreach (g; j["gaps"]) addGap(g["from"].get!long, g["through"].get!long, g["reason"].get!string);
            size_t pending, complete;
            foreach (x; j["operations"]) {
                auto s = operationFromJson(x);
                s.sequence = x["sequence"].get!ulong; s.state = cast(ArchiveOperationState) x["state"].get!int;
                require(s.state == ArchiveOperationState.admitted || s.state == ArchiveOperationState.completed
                    || s.state == ArchiveOperationState.failed, "invalid_operation_state");
                s.updatedAtMs = x["updatedAtMs"].get!long; s.redisApplied = x["redisApplied"].get!bool;
                if (s.state == ArchiveOperationState.admitted) ++pending; else ++complete;
                diskOperations[diskOperationCount++] = s;
            }
            require(pending <= 128 && complete <= 1_024, "operation_status_limit");
            stateGeneration = best;
            return true;
        }

        private int openOwned(string name, bool create, bool* created = null, bool exclusive = false) {
            int flags = O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
            int fd = -1;
            if (create) {
                fd = openat(directoryFd, name.toStringz, flags | O_CREAT | O_EXCL, 384);
                if (fd >= 0) { if (created !is null) *created = true; }
                else require(errno == EEXIST && !exclusive, "archive_create_failed");
            }
            if (fd < 0) fd = openat(directoryFd, name.toStringz, flags);
            require(fd >= 0, "archive_open_failed");
            stat_t st;
            if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid()
                    || st.st_nlink != 1 || (st.st_mode & 63 /*0077*/) != 0) {
                close(fd); throw new Exception("unsafe_archive_file");
            }
            return fd;
        }
    }
}

/// Event-loop serialization of copied DTOs only. The native owner never shares
/// mutable Json. A durable admitted purge is the bounded notification carrying
/// its operation ID and the one frozen Redis/Mongo cutoff.
Json archiveOperationStatusJson(ref const ArchiveOperationStatus operation) {
    auto j = Json.emptyObject;
    j["operationId"] = operation.operationId;
    j["userId"] = operation.ownerId;
    j["serverId"] = operation.serverId;
    j["networkId"] = operation.networkId;
    j["buffer"] = operation.channel;
    j["state"] = operation.state.to!string;
    j["cutoffEid"] = operation.cutoffEid;
    j["legacyTimestampCutoffMs"] = operation.legacyCutoffMs;
    j["scopedLineageId"] = operation.scopedLineageId;
    j["legacyLineageId"] = operation.legacyLineageId;
    j["sequence"] = operation.sequence;
    j["durable"] = operation.durable();
    j["redisApplied"] = operation.redisApplied;
    j["updatedAtMs"] = operation.updatedAtMs;
    return j;
}

/// Matches the history API's optional archive envelope. All current ledger
/// intervals are conservative uncertainty, not falsely precise missing eids.
/// Age is omitted when the next oldest timestamp cannot be known without a
/// payload index. Counts remain exact for tracked scopes, including RAM work.
Json archiveNetworkProjection(ref const ArchiveNetworkStatus sample, long evaluatedAtMs = 0) {
    const now = evaluatedAtMs > 0 ? evaluatedAtMs : nowMs();
    bool fresh = sample.sampledAtMs > 0 && sample.sampledAtMs <= now + 5_000
        && now - sample.sampledAtMs <= 90_000 && sample.gapLength <= sample.gaps.length;
    auto intervals = Json.emptyArray;
    if (sample.gapLength <= sample.gaps.length) foreach (g; sample.gaps[0 .. sample.gapLength]) {
        if (g.fromMs <= 0 || g.throughMs < g.fromMs || g.throughMs > now + 5_000) {
            fresh = false;
            intervals = Json.emptyArray;
            break;
        }
        auto range = Json.emptyObject;
        range["startMs"] = g.fromMs; range["endMs"] = g.throughMs;
        intervals ~= range;
    }
    auto j = Json.emptyObject;
    j["state"] = (fresh ? sample.state : ArchiveHealth.unknown).to!string;
    if (sample.sampledAtMs > 0) j["sampledAtMs"] = sample.sampledAtMs;
    if (intervals.length) j["uncertainty"] = intervals;
    if (fresh && sample.countsKnown) {
        j["pendingBytes"] = sample.pendingBytes;
        if (!sample.pendingMutations) j["oldestAgeMs"] = 0L;
        else if (sample.oldestKnown && sample.oldestAtMs > 0 && sample.oldestAtMs <= now)
            j["oldestAgeMs"] = now - sample.oldestAtMs;
    }
    return j;
}

ArchiveRecord decodeArchiveRecord(string encoded, ulong sequence) {
    require(encoded.length && encoded.length <= archiveMaxRecordBytes, "invalid_record_size");
    auto j = parseJsonString(encoded);
    ArchiveRecord r;
    r.sequence = sequence;
    auto kind = j["kind"].get!string;
    if (kind == "append") r.kind = ArchiveKind.append;
    else if (kind == "rename") r.kind = ArchiveKind.rename;
    else if (kind == "purge") r.kind = ArchiveKind.purge;
    else throw new Exception("invalid_record_kind");
    r.serverId = j["serverId"].get!string; r.networkId = j["networkId"].get!string; r.channel = j["channel"].get!string;
    require(r.serverId.length && r.serverId.length <= 128 && r.networkId.length && r.networkId.length <= 128
        && r.channel.length && r.channel.length <= 512, "invalid_record_scope");
    r.queuedAtMs = j["queuedAtMs"].get!long;
    require(r.queuedAtMs > 0, "invalid_record_queued_time");
    r.timestampMs = r.queuedAtMs;
    if (r.kind == ArchiveKind.append) {
        r.eid = j["eid"].get!long; r.timestampMs = j["timestampMs"].get!long; r.compactJson = j["payload"].get!string;
        require(r.eid > 0 && r.timestampMs > 0 && r.compactJson.length, "invalid_append_identity");
    } else {
        r.cutoffEid = j["cutoffEid"].get!long; r.legacyCutoffMs = j["legacyCutoffMs"].get!long;
        require(r.cutoffEid > 0 && r.legacyCutoffMs > 0, "invalid_control_cutoff");
        if (r.kind == ArchiveKind.rename) {
            r.newChannel = j["newChannel"].get!string;
            require(r.newChannel.length && r.newChannel.length <= 512, "invalid_rename_target");
        } else {
            r.operationId = j["operationId"].get!string; r.ownerId = j["ownerId"].get!string;
            r.scopedLineageId = j["scopedLineageId"].get!string;
            r.legacyLineageId = j["legacyLineageId"].get!string;
            require(validLineage(r.scopedLineageId) && validLineage(r.legacyLineageId), "invalid_purge_lineage");
            require(validCanonicalUuid(r.operationId) && r.ownerId.length && r.ownerId.length <= 128, "invalid_purge_identity");
        }
    }
    return r;
}

private immutable uint[256] crcTable = makeCrcTable();
private uint[256] makeCrcTable() {
    uint[256] table;
    foreach (i; 0 .. table.length) {
        uint c = cast(uint) i;
        foreach (bit; 0 .. 8) c = (c >> 1) ^ (0xEDB88320U & (0U - (c & 1)));
        table[i] = c;
    }
    return table;
}
private uint frameCrc(ulong sequence, const(ubyte)[] payload) {
    uint crc = uint.max;
    foreach (i; 0 .. 8) crc = crcTable[(crc ^ cast(ubyte)(sequence >> (i * 8))) & 255] ^ (crc >> 8);
    foreach (b; payload) crc = crcTable[(crc ^ b) & 255] ^ (crc >> 8);
    return ~crc;
}
private T little(T)(const(ubyte)[] bytes) {
    T value;
    foreach (i; 0 .. T.sizeof) value |= cast(T) bytes[i] << (i * 8);
    return value;
}
private void putLittle(T)(ubyte[] bytes, T value) {
    foreach (i; 0 .. T.sizeof) bytes[i] = cast(ubyte)(value >> (i * 8));
}

version (Posix) {
    import core.sys.posix.fcntl : open, O_RDWR, O_RDONLY, O_CREAT, O_EXCL, O_CLOEXEC, O_NOFOLLOW, O_DIRECTORY, O_NONBLOCK;
    import core.sys.posix.unistd : close, write, pread, pwrite, fsync, ftruncate, geteuid, lseek;
    import core.stdc.stdio : SEEK_END;
    import core.sys.posix.sys.stat : stat_t, fstat, S_ISREG;
    import core.sys.posix.sys.statvfs : statvfs_t, fstatvfs;
    import core.sys.posix.dirent : DIR, readdir, closedir;
    import core.stdc.errno : errno, EINTR, EEXIST;
    private extern(C) int openat(int, const(char)*, int, ...) nothrow @nogc;
    private extern(C) int unlinkat(int, const(char)*, int) nothrow @nogc;
    private extern(C) int flock(int, int) nothrow @nogc;
    private extern(C) DIR* fdopendir(int) nothrow @nogc;

    private int openDirectory(string path) {
        if (!path.length || path.length > 4096 || path[0] != '/' || path[$ - 1] == '/') return -1;
        foreach (c; path) if (c == '\0') return -1;
        int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) return -1;
        size_t begin = 1;
        foreach (i; 1 .. path.length + 1) {
            if (i != path.length && path[i] != '/') continue;
            auto part = path[begin .. i];
            if (!part.length || part == "." || part == "..") { close(fd); return -1; }
            auto next = openat(fd, part.toStringz, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            close(fd); if (next < 0) return -1;
            fd = next; begin = i + 1;
        }
        return fd;
    }
    private void rawSyncFd(int fd) {
        while (fsync(fd) != 0) if (errno != EINTR) throw new JournalException("archive_sync_failed");
    }
    private void fullWrite(int fd, const(ubyte)[] data) {
        size_t done;
        while (done < data.length) {
            auto n = write(fd, data.ptr + done, data.length - done);
            if (n < 0 && errno == EINTR) continue;
            require(n > 0 && cast(size_t) n <= data.length - done, "archive_write_failed");
            done += cast(size_t) n;
        }
    }
    private void fullWriteAt(int fd, const(ubyte)[] data, ulong offset) {
        size_t done;
        while (done < data.length) {
            auto n = pwrite(fd, data.ptr + done, data.length - done, cast(long)(offset + done));
            if (n < 0 && errno == EINTR) continue;
            require(n > 0 && cast(size_t) n <= data.length - done, "archive_state_write_failed");
            done += cast(size_t) n;
        }
    }
    private size_t readAt(int fd, ubyte[] data, ulong offset) {
        size_t done;
        while (done < data.length) {
            auto n = pread(fd, data.ptr + done, data.length - done, cast(long)(offset + done));
            if (n < 0 && errno == EINTR) continue;
            require(n >= 0 && cast(size_t) n <= data.length - done, "archive_read_failed");
            if (!n) break;
            done += cast(size_t) n;
        }
        return done;
    }
}
