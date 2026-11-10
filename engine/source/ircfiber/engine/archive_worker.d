module ircfiber.engine.archive_worker;

import core.time : msecs;
import vibe.core.core : runTask, sleep;
import ircfiber.engine.archive_spool;
import ircfiber.db.messages : MessageRepository, ArchiveWriteException, ArchiveWriteFailure;

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
    this(ArchiveSpool spool, MessageRepository repository, ArchiveRedisPurge redisPurge = null) {
        if (spool is null || repository is null) throw new Exception("archive_worker_requires_repository");
        this.spool = spool;
        this.redisPurge = redisPurge;
        this.apply = (ref const ArchiveRecord record) {
            try {
                // Admission already required durable canonical provenance.
                // Do not re-query a network document here: accepted history
                // must still drain after explicit network/account deletion.
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
                return ArchiveApplyResult.applied;
            } catch (ArchiveWriteException e) {
                if (e.failure == ArchiveWriteFailure.identityMismatch || e.failure == ArchiveWriteFailure.invalidInput)
                    return ArchiveApplyResult.conflict;
                return ArchiveApplyResult.retry;
            } catch (Exception) {
                return ArchiveApplyResult.retry;
            }
        };
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
