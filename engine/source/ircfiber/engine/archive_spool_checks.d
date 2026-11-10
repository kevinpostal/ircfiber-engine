module ircfiber.engine.archive_spool_checks;

// Native journal checks are deliberately absent from service/release builds.
version (MemoryReliabilityHarness) {

import core.thread : Thread;
import core.time : Duration, MonoTime, msecs, seconds;
import core.atomic : atomicStore, atomicLoad;
import vibe.core.core : setTimer;
import core.stdc.stdlib : free;
import core.sys.posix.signal : SIGKILL;
import core.sys.posix.stdlib : realpath;
import core.sys.posix.sys.stat : stat_t, lstat, chmod, S_ISDIR, S_ISREG;
import core.sys.posix.unistd : geteuid;
import std.algorithm : sort;
import std.conv : to;
import std.file : mkdir, rmdirRecurse, exists, read, readText, write,
    dirEntries, SpanMode, tempDir, thisExePath;
import std.format : format;
import std.path : buildPath, baseName, dirName;
import std.process : spawnProcess, tryWait, kill;
import std.stdio : stderr;
import std.string : toStringz, fromStringz, startsWith;
import std.uuid : randomUUID, parseUUID;
import ircfiber.irc.connection : Ircv3Check;
import ircfiber.engine.archive_spool : ArchiveSpool, ArchiveSpoolConfig,
    ArchiveSpoolStatus, ArchiveAdmission, ArchiveRecord, ArchiveKind, ArchiveShutdown,
    ArchiveOperationStatus, ArchiveOperationState, ArchiveLookup,
    decodeArchiveRecord, archiveMaxRecordBytes, archiveSegmentBytes;

private enum ulong fixtureBudget = 32UL * 1024 * 1024;
private enum string fixturePrefix = "ircfiber-archive-check-";
private enum string originalCompact =
    "{\"eid\":71001,\"t\":1700000000123,\"m\":\"original compact\"}";
private enum long originalEid = 71001;
private enum long originalTimestamp = 1_700_000_000_123;

private void requireCheck(bool condition, string reason) {
    if (!condition) throw new Exception(reason);
}

private bool until(scope bool delegate() predicate, Duration timeout = 5.seconds) {
    const deadline = MonoTime.currTime + timeout;
    do {
        if (predicate()) return true;
        Thread.sleep(2.msecs);
    } while (MonoTime.currTime < deadline);
    return false;
}

private ArchiveSpoolStatus awaitStatus(ArchiveSpool spool,
        scope bool delegate(ref ArchiveSpoolStatus) predicate,
        Duration timeout = 5.seconds) {
    ArchiveSpoolStatus status;
    requireCheck(until({
        if (!spool.tryStatus(status)) return false;
        return predicate(status);
    }, timeout), "bounded journal status wait expired");
    return status;
}

private void awaitReady(ArchiveSpool spool) {
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready || s.failed || s.stopped);
    requireCheck(status.ready && !status.failed && !status.stopped,
        "journal not ready: " ~ status.failureReason);
}

private void stopOwned(ref ArchiveSpool spool) {
    if (spool is null) return;
    // shutdown itself owns the five-second deadline. No second drain timeout.
    spool.shutdown(5.seconds, ArchiveShutdown.producersDrained);
    ArchiveSpoolStatus status;
    requireCheck(spool.tryStatus(status) && status.stopped,
        "journal owner did not stop within its five-second deadline; fixture retained");
    spool = null;
}

private string canonical(string path) {
    auto resolved = realpath(path.toStringz, null);
    requireCheck(resolved !is null, "fixture realpath failed");
    scope(exit) free(resolved);
    return fromStringz(resolved).idup;
}

private void validateRoot(string root) {
    requireCheck(canonical(root) == root && dirName(root) == canonical(tempDir()),
        "child requires a canonical direct temporary-directory child");
    auto name = baseName(root);
    requireCheck(name.startsWith(fixturePrefix), "not an archive fixture root");
    auto token = name[fixturePrefix.length .. $];
    auto cursor = token;
    requireCheck(parseUUID(cursor).toString() == token && cursor.length == 0, "invalid fixture UUID");
    stat_t st;
    requireCheck(lstat(root.toStringz, &st) == 0 && S_ISDIR(st.st_mode)
        && st.st_uid == geteuid() && (st.st_mode & 511) == 448,
        "fixture root must be an owned non-symlink mode-0700 directory");
    auto owner = buildPath(root, "owner");
    requireCheck(lstat(owner.toStringz, &st) == 0 && S_ISREG(st.st_mode)
        && st.st_uid == geteuid() && readText(owner) == token,
        "fixture ownership token mismatch");
    auto journal = buildPath(root, "journal");
    requireCheck(canonical(journal) == journal && lstat(journal.toStringz, &st) == 0
        && S_ISDIR(st.st_mode) && st.st_uid == geteuid() && (st.st_mode & 511) == 448,
        "fixture journal must be an owned non-symlink mode-0700 directory");
}

private string createRoot() {
    auto token = randomUUID().toString();
    auto root = buildPath(canonical(tempDir()), fixturePrefix ~ token);
    mkdir(root);
    scope(failure) rmdirRecurse(root);
    requireCheck(chmod(root.toStringz, 448) == 0, "fixture chmod failed");
    mkdir(buildPath(root, "journal"));
    requireCheck(chmod(buildPath(root, "journal").toStringz, 448) == 0,
        "journal fixture chmod failed");
    write(buildPath(root, "owner"), token);
    validateRoot(root);
    return root;
}

private ArchiveSpoolConfig fixtureConfig(string root) {
    validateRoot(root);
    ArchiveSpoolConfig config;
    config.directory = buildPath(root, "journal");
    config.maxBytes = fixtureBudget;
    config.minFreeBytes = 0;
    config.diagnosticPath = "";
    return config;
}

private void removeOwned(string root) {
    validateRoot(root);
    rmdirRecurse(root);
}

private ArchiveRecord takeRecord(ArchiveSpool spool) {
    string encoded;
    ulong sequence;
    bool redisApplied;
    requireCheck(until({ return spool.tryTake(encoded, sequence, redisApplied); }),
        "durable replay did not become available");
    auto record = decodeArchiveRecord(encoded, sequence);
    record.durableRedisApplied = redisApplied;
    return record;
}

private void acknowledge(ArchiveSpool spool, ulong sequence) {
    requireCheck(until({ return spool.tryAcknowledge(sequence); }), "RAM acknowledgement refused");
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.checkpoint >= sequence || s.failed);
    requireCheck(!status.failed && status.checkpoint >= sequence,
        "RAM acknowledgement was not durably checkpointed");
}

private void noRecord(ArchiveSpool spool) {
    string encoded;
    ulong sequence;
    requireCheck(!until({ return spool.tryTake(encoded, sequence); }, 25.msecs),
        "unexpected or duplicate replay record");
}

private bool hasGap(ref ArchiveSpoolStatus status, string reason) {
    foreach (gap; status.gaps[0 .. status.gapLength])
        if (gap.reason == reason && gap.fromMs > 0 && gap.throughMs >= gap.fromMs) return true;
    return false;
}

private void checkOriginal(ref ArchiveRecord record) {
    requireCheck(record.kind == ArchiveKind.append && record.serverId == "original-server"
        && record.networkId == "original-network" && record.channel == "#original"
        && record.eid == originalEid && record.timestampMs == originalTimestamp
        && record.compactJson == originalCompact,
        "replay changed original attribution, eid, timestamp or compact bytes");
}

// The parent executable must dispatch this hook before constructing any ordinary
// harness state. A child has a fresh runtime: never fork a process with D threads.
bool runArchiveSpoolChild(string[] args, out int result) {
    result = 0;
    if (args.length < 2 || args[1] != "--archive-spool-child") return false;
    result = 90;
    if (args.length != 4 || (args[3] != "pending" && args[3] != "checkpoint")) return true;
    ArchiveSpool spool;
    try {
        validateRoot(args[2]);
        spool = new ArchiveSpool(fixtureConfig(args[2]));
        awaitReady(spool);
        queueAppend(spool, "original-server", "original-network", "#original",
            originalEid, originalCompact);
        auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.durableSequence >= 1 || s.failed);
        requireCheck(!status.failed && status.durableSequence == 1 && status.checkpoint == 0,
            "child append was not synced before crash boundary");
        if (args[3] == "checkpoint") {
            auto record = takeRecord(spool);
            checkOriginal(record);
            acknowledge(spool, record.sequence);
        }
        write(buildPath(args[2], "child-ready"), args[3]);
        // Only the parent kills; self-timeout makes a missing parent bounded too.
        Thread.sleep(10.seconds);
        result = 92;
    } catch (Throwable error) {
        stderr.writeln("[archive-spool-child] ", error.toString());
        result = 91;
    }
    try { stopOwned(spool); }
    catch (Throwable error) { stderr.writeln(error.toString()); result = 93; }
    return true;
}

private void crashChild(string root, string mode) {
    validateRoot(root);
    auto child = spawnProcess([thisExePath(), "--archive-spool-child", root, mode]);
    bool reaped;
    scope(exit) {
        if (!reaped) {
            // Own exactly the process we spawned; never use a shell/PID file.
            kill(child, SIGKILL);
            requireCheck(until({
                auto state = tryWait(child);
                reaped = state.terminated;
                return reaped;
            }), "SIGKILL child could not be reaped; fixture retained");
        }
    }
    auto marker = buildPath(root, "child-ready");
    requireCheck(until({
        auto state = tryWait(child);
        if (state.terminated) {
            reaped = true;
            throw new Exception("archive child exited before crash boundary: " ~ state.status.to!string
                ~ "; ensure the runner dispatches runArchiveSpoolChild first");
        }
        return exists(marker) && readText(marker) == mode;
    }, 8.seconds), "archive child did not reach the durable crash boundary");
    kill(child, SIGKILL);
    int exitStatus;
    requireCheck(until({
        auto state = tryWait(child);
        reaped = state.terminated;
        if (reaped) exitStatus = state.status;
        return reaped;
    }), "SIGKILL child did not terminate within five seconds");
    // Phobos preserves the terminating POSIX signal as a negative status.
    requireCheck(exitStatus == -SIGKILL,
        "child did not terminate by SIGKILL: " ~ exitStatus.to!string);
}

private string[] segmentPaths(string root) {
    string[] result;
    foreach (entry; dirEntries(buildPath(root, "journal"), SpanMode.shallow))
        if (entry.name.baseName.startsWith("segment-")) result ~= entry.name;
    sort(result);
    return result;
}

private string segmentPath(string root, ulong firstSequence) {
    return buildPath(root, "journal", format("segment-%020u.log", firstSequence));
}

private void fixtureBounds(string root, ref ArchiveSpoolStatus status) {
    requireCheck(status.ingressCommands <= 1024 && status.ingressBytes <= 8 * 1024 * 1024
        && status.pendingBytes <= fixtureBudget && status.gapLength <= 256,
        "journal exceeded fixed ingress, pending-byte or gap bounds");
    size_t files;
    ulong allocated;
    foreach (entry; dirEntries(buildPath(root, "journal"), SpanMode.shallow)) {
        stat_t st;
        requireCheck(lstat(entry.name.toStringz, &st) == 0 && S_ISREG(st.st_mode),
            "unexpected non-regular fixture artifact");
        ++files;
        allocated += cast(ulong) st.st_blocks * 512;
        if (entry.name.baseName.startsWith("segment-"))
            requireCheck(st.st_size <= archiveSegmentBytes, "segment exceeded four MiB");
    }
    requireCheck(files <= 160 && allocated <= fixtureBudget,
        "journal exceeded file count or actual allocated-disk budget");
}

private void crashReplayCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    crashChild(root, "pending");
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    requireCheck(status.checkpoint == 0 && status.durableSequence == 1
        && hasGap(status, "unclean_ram_admission_uncertainty"),
        "unclean crash concealed live/RAM admission uncertainty");
    auto record = takeRecord(spool);
    checkOriginal(record);
    requireCheck(record.sequence == 1, "replay sequence changed");
    // Borrowing is exclusive, including before the durable acknowledgement.
    noRecord(spool);
    acknowledge(spool, record.sequence);
    noRecord(spool);
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    noRecord(spool);
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    requireCheck(status.checkpoint == 1 && hasGap(status, "unclean_ram_admission_uncertainty"),
        "clean recovery erased sticky crash uncertainty or checkpoint");
}

private void checkpointCrashCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    crashChild(root, "checkpoint");
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    requireCheck(status.checkpoint == 1 && status.durableSequence == 1,
        "durable checkpoint was lost across SIGKILL");
    noRecord(spool);
    enum string nextCompact = "{\"eid\":71002,\"t\":1700000000456,\"m\":\"next\"}";
    queueAppend(spool, "next-server", "next-network", "#next", 71002, nextCompact);
    auto record = takeRecord(spool);
    requireCheck(record.sequence == 2 && record.eid == 71002 && record.compactJson == nextCompact,
        "sequence reused after checkpoint/reclamation and recreation");
    acknowledge(spool, record.sequence);
    noRecord(spool);
}

private void seedPrefix(string root, size_t records = 1, bool laggingWatermark = false) {
    ArchiveSpool spool = new ArchiveSpool(fixtureConfig(root));
    scope(exit) stopOwned(spool);
    awaitReady(spool);
    // Retain authentic pre-batch slots to model a crash after segment fsync but
    // before any subsequent state save. The saved nextSequence is exactly one.
    auto initialState = laggingWatermark ? read(buildPath(root, "journal", "state")) : null;
    foreach (i; 0 .. records) {
        auto eid = originalEid + cast(long) i;
        auto compact = i == 0 ? originalCompact :
            format("{\"eid\":%s,\"t\":%s,\"m\":\"later\"}", eid, originalTimestamp);
        queueAppend(spool, "original-server", "original-network", "#original", eid, compact);
        auto status = awaitStatus(spool,
            (ref ArchiveSpoolStatus s) => s.durableSequence >= i + 1 || s.failed);
        requireCheck(!status.failed, "prefix seed failed");
    }
    stopOwned(spool);
    if (laggingWatermark) write(buildPath(root, "journal", "state"), initialState);
}

private void tornFrameCheck(bool partialPayload) {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    seedPrefix(root);
    auto paths = segmentPaths(root);
    requireCheck(paths.length == 1, "small prefix unexpectedly spans segments");
    auto prefix = cast(ubyte[]) read(paths[0]);
    // A declared, not-yet-written next frame or a torn frame header. No valid
    // checksums are synthesized: the actual disk owner wrote the valid prefix.
    ubyte[] tail = new ubyte[partialPayload ? 19 : 7];
    tail[0] = 64;
    if (partialPayload) tail[8] = 2;
    write(paths[0], prefix ~ tail);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    requireCheck(hasGap(status, "torn_final_frame_uncertainty"), "torn frame uncertainty missing");
    auto record = takeRecord(spool);
    checkOriginal(record);
    acknowledge(spool, record.sequence);
    noRecord(spool);
    stopOwned(spool);
    // Reclamation may remove the file only after our positive checkpoint.
    requireCheck(!exists(paths[0]) || (cast(ubyte[]) read(paths[0])) == prefix,
        "recovery did not retain the exact valid frame prefix");
}

private void tornSegmentHeaderCheck() {
    // Every interrupted prefix of the eight-byte magic, including zero bytes.
    foreach (length; 0 .. 8) {
        auto root = createRoot();
        ArchiveSpool spool;
        scope(exit) { stopOwned(spool); removeOwned(root); }
        seedPrefix(root);
        auto path = segmentPath(root, 2);
        write(path, "IFARv001"[0 .. length]);
        requireCheck(chmod(path.toStringz, 384) == 0, "torn-header fixture chmod failed");
        spool = new ArchiveSpool(fixtureConfig(root));
        awaitReady(spool);
        auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
        requireCheck(!exists(path) && hasGap(status, "torn_segment_uncertainty"),
            "incomplete final segment header was not conservatively removed");
        auto record = takeRecord(spool);
        checkOriginal(record);
        acknowledge(spool, record.sequence);
        queueAppend(spool, "original-server", "original-network", "#original", 71002,
            "{\"eid\":71002,\"t\":1700000000123}");
        record = takeRecord(spool);
        requireCheck(record.sequence == 2, "torn uncommitted header consumed a sequence");
        acknowledge(spool, record.sequence);
        noRecord(spool);
    }
}

private uint frameLength(const(ubyte)[] bytes, size_t offset) {
    requireCheck(offset + 16 <= bytes.length, "fixture frame header missing");
    uint value;
    foreach (i; 0 .. 4) value |= cast(uint) bytes[offset + i] << (8 * i);
    return value;
}

private void interiorCorruptionCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    seedPrefix(root, 3);
    auto paths = segmentPaths(root);
    requireCheck(paths.length == 1, "three small frames unexpectedly span segments");
    auto damaged = cast(ubyte[]) read(paths[0]);
    auto second = 8 + 16 + frameLength(damaged, 8);
    auto third = second + 16 + frameLength(damaged, second);
    requireCheck(third + 16 < damaged.length, "fixture has no valid frame after corruption");
    damaged[second + 16] ^= 1;
    write(paths[0], damaged);
    spool = new ArchiveSpool(fixtureConfig(root));
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.failed && s.stopped);
    requireCheck(!status.ready && status.checkpoint == 0 && status.gapCount > 0
        && status.failureReason == "frame_checksum_corruption",
        "interior checksum corruption did not fail closed with the expected reason");
    noRecord(spool);
    stopOwned(spool);
    requireCheck((cast(ubyte[]) read(paths[0])) == damaged, "interior corruption evidence was modified or discarded");
    // A sticky failure must not become healthy just by restarting the owner.
    spool = new ArchiveSpool(fixtureConfig(root));
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.failed && s.stopped);
    requireCheck(!status.ready && (cast(ubyte[]) read(paths[0])) == damaged,
        "restart hid corruption or removed its evidence");
}

private void overshootingLengthCheck(bool conflictingSequence) {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    seedPrefix(root, 3, true);
    auto paths = segmentPaths(root);
    requireCheck(paths.length == 1, "three small frames unexpectedly span segments");
    auto damaged = cast(ubyte[]) read(paths[0]);
    auto second = 8 + 16 + frameLength(damaged, 8);
    auto third = second + 16 + frameLength(damaged, second);
    requireCheck(third + 16 < damaged.length && damaged.length < archiveMaxRecordBytes,
        "fixture lacks a complete later frame within the overshooting length");
    // Still within the allowed record size, but extends beyond EOF and conceals
    // the genuine checksummed third frame. The old state watermark cannot help.
    uint length = cast(uint) archiveMaxRecordBytes;
    foreach (i; 0 .. 4) damaged[second + i] = cast(ubyte)(length >> (8 * i));
    if (conflictingSequence) damaged[second + 8] = 9;
    write(paths[0], damaged);
    spool = new ArchiveSpool(fixtureConfig(root));
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.failed && s.stopped);
    requireCheck(!status.ready && status.checkpoint == 0 && status.gapCount > 0
        && status.failureReason == (conflictingSequence
            ? "frame_sequence_conflict" : "interior_frame_length_corruption"),
        "overshooting interior length did not fail closed before truncation");
    noRecord(spool);
    stopOwned(spool);
    requireCheck((cast(ubyte[]) read(paths[0])) == damaged,
        "length recovery truncated a valid later frame or changed corruption evidence");
    spool = new ArchiveSpool(fixtureConfig(root));
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.failed && s.stopped);
    requireCheck(!status.ready && status.failureReason == "sticky_archival_failure"
        && (cast(ubyte[]) read(paths[0])) == damaged, "restart concealed length corruption");
}

private ArchiveAdmission submitPurge(ArchiveSpool spool, ref ArchiveOperationStatus request) {
    ArchiveAdmission admission;
    requireCheck(until({
        admission = spool.tryPurge(request.operationId, request.ownerId, request.serverId,
            request.networkId, request.channel, request.cutoffEid, request.legacyCutoffMs,
            request.scopedLineageId, request.legacyLineageId);
        return admission != ArchiveAdmission.full;
    }), "purge admission remained contended");
    return admission;
}

private void checkPurgeIdentity(ref ArchiveOperationStatus actual, ref ArchiveOperationStatus expected) {
    requireCheck(actual.operationId == expected.operationId && actual.ownerId == expected.ownerId
        && actual.serverId == expected.serverId && actual.networkId == expected.networkId
        && actual.channel == expected.channel && actual.cutoffEid == expected.cutoffEid
        && actual.legacyCutoffMs == expected.legacyCutoffMs
        && actual.scopedLineageId == expected.scopedLineageId
        && actual.legacyLineageId == expected.legacyLineageId, "purge status changed frozen identity or cutoff");
}

private ArchiveOperationStatus awaitPurge(ArchiveSpool spool, ref ArchiveOperationStatus expected,
        ArchiveOperationState state, bool redisApplied = false) {
    ArchiveOperationStatus actual;
    requireCheck(until({
        return spool.tryOperationStatus(expected.operationId, actual) && actual.state == state
            && actual.redisApplied == redisApplied;
    }), "purge status did not reach its expected durable stage");
    checkPurgeIdentity(actual, expected);
    requireCheck(actual.sequence == (state == ArchiveOperationState.requested ? 0 : 1)
        && actual.durable() == (state != ArchiveOperationState.requested), "purge durability stage is dishonest");
    return actual;
}

private void checkPurgeRecord(ref ArchiveRecord record, ref ArchiveOperationStatus expected,
        bool redisApplied = false) {
    requireCheck(record.kind == ArchiveKind.purge && record.sequence == 1
        && record.operationId == expected.operationId && record.ownerId == expected.ownerId
        && record.serverId == expected.serverId && record.networkId == expected.networkId
        && record.channel == expected.channel && record.cutoffEid == expected.cutoffEid
        && record.legacyCutoffMs == expected.legacyCutoffMs
        && record.scopedLineageId == expected.scopedLineageId
        && record.legacyLineageId == expected.legacyLineageId
        && record.durableRedisApplied == redisApplied, "purge replay changed frozen identity, cutoff or Redis stage");
}

private void positivePurgeCheck(bool withLineages) {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    ArchiveOperationStatus expected;
    expected.operationId = "719bd528-fbdd-4b7c-9f37-370ade89cc51";
    expected.ownerId = "purge-owner"; expected.serverId = "original-server";
    expected.networkId = "original-network"; expected.channel = "#original";
    expected.cutoffEid = originalEid; expected.legacyCutoffMs = originalTimestamp;
    if (withLineages) {
        expected.scopedLineageId = "27d277e0-1013-46bd-a59d-d5d77510f4d8";
        expected.legacyLineageId = "f0d35967-3a36-4260-bff6-78cc61f927dc";
    }
    foreach (badId; ["00000000-0000-0000-0000-000000000000",
            "719BD528-FBDD-4B7C-9F37-370ADE89CC51", "not-a-uuid"]) {
        auto invalid = expected; invalid.operationId = badId;
        requireCheck(submitPurge(spool, invalid) == ArchiveAdmission.unavailable, "invalid operation UUID admitted");
    }
    auto invalid = expected; invalid.scopedLineageId = "00000000-0000-0000-0000-000000000000";
    requireCheck(submitPurge(spool, invalid) == ArchiveAdmission.unavailable, "null lineage UUID admitted");
    invalid = expected; invalid.legacyLineageId = "not-a-uuid";
    requireCheck(submitPurge(spool, invalid) == ArchiveAdmission.unavailable, "malformed lineage UUID admitted");
    pauseDrain(spool);
    requireCheck(submitPurge(spool, expected) == ArchiveAdmission.queued, "valid canonical purge rejected");
    awaitPurge(spool, expected, ArchiveOperationState.requested);
    // An identical action retry keeps the FIRST barrier, even if a caller has
    // already observed newer messages. Conflicting scope/lineage is rejected.
    auto retry = expected; retry.cutoffEid += 100; retry.legacyCutoffMs += 100;
    requireCheck(submitPurge(spool, retry) == ArchiveAdmission.queued, "idempotent purge retry rejected");
    foreach (field; 0 .. 6) {
        auto conflict = retry;
        switch (field) {
            case 0: conflict.ownerId = "another-owner"; break;
            case 1: conflict.serverId = "another-server"; break;
            case 2: conflict.networkId = "another-network"; break;
            case 3: conflict.channel = "#another"; break;
            case 4: conflict.scopedLineageId = "84c15191-1a35-49c9-a7be-83da02c7ced1"; break;
            case 5: conflict.legacyLineageId = "84c15191-1a35-49c9-a7be-83da02c7ced1"; break;
            default: throw new Exception("invalid conflict fixture field");
        }
        requireCheck(submitPurge(spool, conflict) == ArchiveAdmission.unavailable,
            "conflicting operation ID was admitted");
    }
    awaitPurge(spool, expected, ArchiveOperationState.requested);
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ingressCommands == 1);
    requireCheck(status.durableSequence == 0, "purge retry duplicated ingress or escaped the drain gate");
    requireCheck(until({ return spool.harnessResumeDrain(); }), "purge drain release failed");
    awaitPurge(spool, expected, ArchiveOperationState.admitted);
    auto record = takeRecord(spool);
    checkPurgeRecord(record, expected);
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    awaitPurge(spool, expected, ArchiveOperationState.admitted);
    record = takeRecord(spool);
    checkPurgeRecord(record, expected);
    requireCheck(until({ return spool.tryMarkRedisApplied(expected.operationId, record.sequence); }),
        "purge Redis stage could not be queued");
    awaitPurge(spool, expected, ArchiveOperationState.admitted, true);
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    awaitPurge(spool, expected, ArchiveOperationState.admitted, true);
    ArchiveOperationStatus lookedUp;
    requireCheck(until({
        return spool.lookupPurgeOperation(expected.operationId, expected.ownerId, expected.serverId,
            expected.networkId, expected.channel, expected.scopedLineageId, expected.legacyLineageId,
            lookedUp) == ArchiveLookup.found;
    }), "recovered purge not queryable by its original scope and lineages");
    checkPurgeIdentity(lookedUp, expected);
    record = takeRecord(spool);
    checkPurgeRecord(record, expected, true);
    acknowledge(spool, record.sequence);
    awaitPurge(spool, expected, ArchiveOperationState.completed, true);
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    awaitPurge(spool, expected, ArchiveOperationState.completed, true);
    requireCheck(submitPurge(spool, retry) == ArchiveAdmission.queued, "completed retry lost its retained result");
    awaitPurge(spool, expected, ArchiveOperationState.completed, true);
    noRecord(spool);
}

private string quotaCompact(long eid, string body) {
    return format("{\"eid\":%s,\"t\":%s,\"m\":\"%s\"}", eid, originalTimestamp, body);
}

private void quotaAndOversizeCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    // Fast rejection occurs before any giant JSON is parsed or queued.
    auto huge = new char[archiveMaxRecordBytes + 1];
    huge[] = 'x';
    requireCheck(spool.tryAppend("quota-server", "quota-network", "#quota", 1, huge.idup)
        == ArchiveAdmission.oversized, "oversized record was not explicitly rejected");
    auto status = awaitStatus(spool,
        (ref ArchiveSpoolStatus s) => hasGap(s, "admission_rejected") || s.failed);
    requireCheck(!status.failed, "oversize rejection failed the live journal");
    fixtureBounds(root, status);
    // One command at a time, waiting for its disk disposition. This tests the
    // disk quota, not a scheduler-dependent attempt to fill an active queue.
    auto body = new char[512 * 1024];
    body[] = 'q';
    auto bodyText = body.idup;
    ulong accepted;
    bool exhausted;
    foreach (attempt; 0 .. 80) {
        const eid = 80000L + attempt;
        auto compact = quotaCompact(eid, bodyText);
        queueAppend(spool, "quota-server", "quota-network", "#quota", eid, compact);
        status = awaitStatus(spool, (ref ArchiveSpoolStatus s) =>
            (s.ingressCommands == 0 && (s.durableSequence > accepted
                || hasGap(s, "disk_capacity_rejected"))) || s.failed);
        requireCheck(!status.failed, "quota exhaustion became an I/O failure");
        fixtureBounds(root, status);
        if (status.durableSequence == accepted) {
            requireCheck(hasGap(status, "disk_capacity_rejected"), "capacity rejection was silent");
            exhausted = true;
            break;
        }
        requireCheck(status.durableSequence == accepted + 1, "quota fixture sequence discontinuity");
        ++accepted;
    }
    requireCheck(exhausted && accepted > 0, "finite disk budget did not saturate within bounded input");
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    requireCheck(status.durableSequence == accepted && status.checkpoint == 0
        && hasGap(status, "disk_capacity_rejected") && hasGap(status, "admission_rejected"),
        "quota recovery lost old records or sticky gap evidence");
    fixtureBounds(root, status);
    foreach (i; 0 .. accepted) {
        auto record = takeRecord(spool);
        requireCheck(record.sequence == i + 1 && record.eid == 80000L + i
            && record.serverId == "quota-server" && record.networkId == "quota-network"
            && record.timestampMs == originalTimestamp
            && record.compactJson == quotaCompact(cast(long)(80000 + i), bodyText),
            "quota exhaustion evicted/reordered/changed an earlier durable record");
        acknowledge(spool, record.sequence);
    }
    noRecord(spool);
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    requireCheck(status.checkpoint == accepted && hasGap(status, "disk_capacity_rejected"),
        "draining/recovered health erased historical capacity loss");
}

private void startupIoFailureCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    // Real public-API filesystem failure, safe even as root: a regular file is
    // not an openable journal directory. No invented EIO or global disk fill.
    auto obstruction = buildPath(root, "not-a-directory");
    write(obstruction, "retain this evidence");
    auto config = fixtureConfig(root);
    config.directory = obstruction;
    spool = new ArchiveSpool(config);
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.failed && s.stopped);
    requireCheck(!status.ready && status.gapCount > 0 && status.failureReason.length > 0,
        "filesystem failure was not explicitly unavailable/degraded");
    requireCheck(spool.tryAppend("original-server", "original-network", "#original",
        originalEid, originalCompact) == ArchiveAdmission.unavailable,
        "failed journal accepted an archival message");
    requireCheck(readText(obstruction) == "retain this evidence", "failed open changed unrelated fixture bytes");
}

private void pauseDrain(ArchiveSpool spool) {
    requireCheck(until({ return spool.harnessPauseDrain(2.seconds); }),
        "native drain gate could not be requested");
    requireCheck(until({
        bool entered;
        return spool.harnessDrainPaused(entered) && entered;
    }), "native drain gate did not become active");
}

private void requirePaused(ArchiveSpool spool) {
    bool entered;
    requireCheck(until({ return spool.harnessDrainPaused(entered); }) && entered,
        "native drain gate expired before the boundary observation");
}

private void queueAppend(ArchiveSpool spool, string server, string network,
        string channel, long eid, string compact) {
    ArchiveAdmission admission;
    requireCheck(until({
        admission = spool.tryAppend(server, network, channel, eid, compact);
        return admission != ArchiveAdmission.full;
    }) && admission == ArchiveAdmission.queued,
        "valid append could not enter the bounded ingress");
}

private void queueRename(ArchiveSpool spool) {
    ArchiveAdmission admission;
    requireCheck(until({
        admission = spool.tryRename("queue-server", "queue-network", "#before", "#after",
            90000, originalTimestamp);
        return admission != ArchiveAdmission.full;
    }) && admission == ArchiveAdmission.queued, "reserved control admission failed");
}

private void commandSaturationCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    pauseDrain(spool);
    foreach (i; 0 .. 896) {
        // Renew in finite batches, rather than assuming 896 encodes take <2s.
        if (i && i % 64 == 0) pauseDrain(spool);
        const eid = 90000L + i;
        queueAppend(spool, "queue-server", "queue-network", "#queue", eid,
            format("{\"eid\":%s,\"t\":%s}", eid, originalTimestamp));
    }
    requirePaused(spool);
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ingressCommands == 896);
    requireCheck(status.durableSequence == 0 && status.ingressBytes <= 7 * 1024 * 1024,
        "paused data escaped its reserved count/byte budget");
    requireCheck(spool.tryAppend("queue-server", "queue-network", "#queue", 99999,
        "{\"eid\":99999,\"t\":1700000000123}") == ArchiveAdmission.full,
        "897th data command consumed control-reserved slots");
    foreach (i; 0 .. 128) {
        if (i % 32 == 0) pauseDrain(spool);
        queueRename(spool);
    }
    requirePaused(spool);
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ingressCommands == 1024);
    requireCheck(status.durableSequence == 0, "paused commands reached disk unexpectedly");
    requireCheck(spool.tryRename("queue-server", "queue-network", "#before", "#after",
        90000, originalTimestamp) == ArchiveAdmission.full, "1025th total command was admitted");
    fixtureBounds(root, status);
    requireCheck(until({ return spool.harnessResumeDrain(); }), "drain gate release failed");
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) =>
        (s.ingressCommands == 0 && s.durableSequence == 1024 && s.gapCount > 0) || s.failed);
    requireCheck(!status.failed && hasGap(status, "admission_rejected"),
        "queue saturation did not retain an explicit gap");
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    requireCheck(status.durableSequence == 1024 && hasGap(status, "admission_rejected"),
        "queue recovery lost accepted commands or sticky rejection evidence");
    auto first = takeRecord(spool);
    requireCheck(first.sequence == 1 && first.eid == 90000,
        "queue saturation evicted the oldest accepted command");
}

private void byteSaturationCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    auto body = new char[768 * 1024];
    body[] = 'b';
    auto bodyText = body.idup;
    pauseDrain(spool);
    size_t admitted;
    foreach (i; 0 .. 16) {
        pauseDrain(spool);
        const eid = 91000L + i;
        auto compact = quotaCompact(eid, bodyText);
        auto before = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
        auto admission = spool.tryAppend("byte-server", "byte-network", "#bytes", eid, compact);
        if (admission == ArchiveAdmission.full) {
            // A mutex miss is NOT proof: existing bytes must exclude even the
            // compact payload alone, before the archive-envelope overhead.
            if (before.ingressBytes + compact.length <= 7 * 1024 * 1024) {
                queueAppend(spool, "byte-server", "byte-network", "#bytes", eid, compact);
                ++admitted;
                continue;
            }
            requirePaused(spool);
            auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
            requireCheck(status.ingressCommands == admitted && admitted < 896
                && status.ingressBytes <= 7 * 1024 * 1024 && status.durableSequence == 0,
                "byte saturation did not remain within fixed bounds");
            fixtureBounds(root, status);
            requireCheck(until({ return spool.harnessResumeDrain(); }), "drain release failed");
            status = awaitStatus(spool, (ref ArchiveSpoolStatus s) =>
                (s.ingressCommands == 0 && s.durableSequence == admitted && s.gapCount > 0) || s.failed);
            requireCheck(!status.failed && hasGap(status, "admission_rejected"),
                "byte rejection lost explicit uncertainty");
            return;
        }
        requireCheck(admission == ArchiveAdmission.queued, "valid byte-boundary payload rejected");
        ++admitted;
    }
    requireCheck(false, "seven-MiB data byte budget did not saturate");
}

private void syncFailureCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    seedPrefix(root);
    auto paths = segmentPaths(root);
    requireCheck(paths.length == 1, "sync fixture prefix unexpectedly spans segments");
    auto prefix = cast(ubyte[]) read(paths[0]);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    pauseDrain(spool);
    requireCheck(until({ return spool.harnessFailNextSync(); }), "sync fault could not be armed");
    queueAppend(spool, "original-server", "original-network", "#original", 71002,
        "{\"eid\":71002,\"t\":1700000000123}");
    requireCheck(until({ return spool.harnessResumeDrain(); }), "drain release failed");
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.failed && s.stopped);
    requireCheck(!status.ready && status.checkpoint == 0 && status.gapCount > 0
        && status.failureReason == "injected_sync_failure",
        "injected native sync failure did not fail closed with explicit uncertainty");
    noRecord(spool);
    stopOwned(spool);
    auto evidence = cast(ubyte[]) read(paths[0]);
    requireCheck(evidence.length >= prefix.length && evidence[0 .. prefix.length] == prefix,
        "failed sync destroyed the previously durable prefix");
    spool = new ArchiveSpool(fixtureConfig(root));
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.failed && s.stopped);
    requireCheck(!status.ready && status.checkpoint == 0 && (cast(ubyte[]) read(paths[0])) == evidence,
        "restart hid sticky sync failure or discarded its evidence");
}

private void admissionContentionCheck() {
    auto root = createRoot();
    ArchiveSpool spool;
    Thread blocker;
    shared bool entered, release;
    scope(exit) {
        atomicStore(release, true);
        if (blocker !is null) blocker.join();
        stopOwned(spool);
        removeOwned(root);
    }
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    blocker = new Thread({ spool.harnessHoldAdmissionLock(&entered, &release); });
    blocker.start();
    requireCheck(until({ return atomicLoad(entered); }), "native mailbox contention not established");
    bool timerFired;
    auto timer = setTimer(25.msecs, {
        timerFired = true;
        atomicStore(release, true);
    });
    scope(exit) timer.stop();
    const admission = spool.tryAppend("original-server", "original-network", "#original",
        originalEid, originalCompact);
    requireCheck(timerFired && admission == ArchiveAdmission.queued,
        "bookkeeping contention blocked the event loop or rejected below-capacity history");
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.durableSequence == 1 || s.failed);
    requireCheck(!status.failed && status.gapCount == 0 && status.diskThreads == 1,
        "contention fabricated archival loss or changed disk-owner count");
    auto record = takeRecord(spool);
    checkOriginal(record);
    acknowledge(spool, record.sequence);
}

/// The empty-ingress race: a timeout must not become clean merely because
/// the native owner drains before a delayed processor acknowledges its tail.
private void shutdownEligibilityCheck(bool proved) {
    auto root = createRoot();
    ArchiveSpool spool;
    scope(exit) { stopOwned(spool); removeOwned(root); }
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    if (proved) queueAppend(spool, "original-server", "original-network", "#original",
        originalEid, originalCompact);
    spool.requestShutdown(5.seconds,
        proved ? ArchiveShutdown.producersDrained : ArchiveShutdown.unclean, proved);
    // Model a late successful marker after the first (unclean) request.
    // It may race before, during or after native drain, but cannot upgrade it.
    if (!proved) spool.requestShutdown(5.seconds, ArchiveShutdown.producersDrained);
    auto status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.stopped);
    requireCheck(!status.failed && status.cleanShutdown == proved,
        "empty ingress or late eligibility changed the first shutdown decision");
    requireCheck(status.ingressCommands == 0 && status.durableSequence == (proved ? 1 : 0)
        && status.checkpoint == 0, "shutdown waited Mongo or lost an accepted RAM record");
    stopOwned(spool);
    spool = new ArchiveSpool(fixtureConfig(root));
    awaitReady(spool);
    status = awaitStatus(spool, (ref ArchiveSpoolStatus s) => s.ready);
    if (proved) {
        requireCheck(hasGap(status, "producer_fence_tail_uncertainty")
            && !hasGap(status, "unclean_ram_admission_uncertainty"),
            "proved drain lost its durable tail warning or left an unclean session");
        auto record = takeRecord(spool);
        checkOriginal(record);
    } else requireCheck(hasGap(status, "unclean_ram_admission_uncertainty")
        && hasGap(status, "shutdown_producer_uncertainty"),
        "unproven empty drain cleared durable restart uncertainty");
}

Ircv3Check[] archiveSpoolRegressionChecks() {
    Ircv3Check[] checks;
    void run(string name, scope void delegate() test) {
        bool passed;
        try { test(); passed = true; }
        catch (Throwable error) { stderr.writeln("[archive-spool] ", name, ": ", error.toString()); }
        checks ~= Ircv3Check(name, passed);
    }
    run("journal SIGKILL before checkpoint replays original identity exactly once and retains uncertainty",
        { crashReplayCheck(); });
    run("journal durable checkpoint survives SIGKILL and next sequence remains monotonic",
        { checkpointCrashCheck(); });
    run("journal torn final frame header preserves synced prefix", { tornFrameCheck(false); });
    run("journal torn final frame payload preserves synced prefix", { tornFrameCheck(true); });
    run("journal final segment headers of zero through seven bytes recover conservatively",
        { tornSegmentHeaderCheck(); });
    run("journal interior checksum corruption fails sticky and preserves original evidence",
        { interiorCorruptionCheck(); });
    run("journal overshooting interior length preserves later frames with a lagging state watermark",
        { overshootingLengthCheck(false); });
    run("journal overshooting length validates sequence before considering final truncation",
        { overshootingLengthCheck(true); });
    run("journal native purge preserves UUID scope cutoffs and both lineages through fsync recovery and completion",
        { positivePurgeCheck(true); });
    run("journal native purge accepts explicit absent lineages and retains idempotent completion",
        { positivePurgeCheck(false); });
    run("journal quota and oversize retain sticky gaps, fixed bounds and all old durable records",
        { quotaAndOversizeCheck(); });
    run("journal actual filesystem open failure rejects work without altering evidence",
        { startupIoFailureCheck(); });
    run("journal 896 data plus 128 reserved controls saturate bounded ingress with sticky loss",
        { commandSaturationCheck(); });
    run("journal seven-MiB data byte reservation rejects without unbounded RAM",
        { byteSaturationCheck(); });
    run("journal injected native sync failure retains durable prefix and sticky uncertainty",
        { syncFailureCheck(); });
    run("journal bookkeeping contention preserves history while event-loop timers remain responsive",
        { admissionContentionCheck(); });
    run("journal empty ingress and a late processor ack cannot upgrade an unclean shutdown",
        { shutdownEligibilityCheck(false); });
    run("journal proven producer tail drains RAM without Mongo and persists fenced-tail uncertainty",
        { shutdownEligibilityCheck(true); });
    return checks;
}

} // version (MemoryReliabilityHarness)
