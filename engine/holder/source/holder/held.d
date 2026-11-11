/** Bounded socket-owning relay. Only the reader finalizes TLS. */
module holder.held;

import core.time : Duration, msecs, seconds;
import std.algorithm : min;
import vibe.core.core : sleep, yield;
import vibe.core.net : TCPConnection, WaitForDataStatus;
import vibe.core.stream : IOMode;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : Task;
import vibe.stream.tls : TLSStream;
import vibe.stream.openssl : OpenSSLStream;
import ircfiber.async : safeFiberRun;
import ircfiber.logging : logJsonMap;
import holder.dial : DialOutcome, unixMsNow;
import holder.protocol;
import holder.tls_safe : safeTLSRead;
import holder.bounded;

private enum STREAM_BUFFER_SIZE = 16_384;
private enum UPSTREAM_WAIT = 30.seconds;
private enum size_t META_TOTAL_LIMIT = 128 * 1024 * 1024;
final class HeldAdmissionException : Exception {
    this() { super(ERR_BUSY); }
}

/// These are event-loop-local, allocation-free snapshots, not serialized META.
struct HeldMemoryCounters {
    ulong liveEntries, tombstones, readerTasks, upstreamWriterTasks;
    ulong attachmentWriterTasks, pumpTasks, timerTasks, relayBytes, outboundBytes, pongBytes;
    ulong metaBytes, metaRejectedBytes, gapEntries, droppedBytes, droppedLines;
    ulong pongSaturations, commandSaturations, relaySaturations;
    ulong metaMembersKnown, openMembersKnown;
}
private HeldMemoryCounters counts;
private LocalManualEvent commandSpace;
HeldMemoryCounters sampleHeldMemory() {
    auto result = counts;
    result.relayBytes = laneBytes[0];
    result.outboundBytes = laneBytes[1];
    result.pongBytes = laneBytes[2];
    return result;
}

/// Fixed numeric snapshots; reservations include blocked writers, descriptors,
/// framing and scratch. Completion counters advance only after actual flush.
struct HeldQueueCounters {
    ulong reservedBytes, maxBytes, sessionMaxBytes;
    ulong queuedBytes, queuedReservedBytes, queuedDescriptors;
    ulong inFlightBytes, inFlightReservedBytes, inFlightDescriptors;
    ulong descriptorBytes, framingBytes, scratchBytes;
    ulong completedWrites, completedBytes, maxQueuedDescriptorsPerSession, maxInFlightDescriptorsPerSession;
    long lastWriteCompletedAtMs;
    long oldestUnprogressedBacklogAtMs;
}
HeldQueueCounters[3] sampleHeldQueues() {
    HeldQueueCounters[3] result;
    foreach (i, ref q; result) {
        q.reservedBytes = laneBytes[i];
        q.maxBytes = GLOBAL_LIMITS[i];
        q.sessionMaxBytes = SESSION_LIMITS[i];
        auto c = laneCounters[i];
        static foreach (name; ["queuedBytes", "queuedReservedBytes", "queuedDescriptors",
            "inFlightBytes", "inFlightReservedBytes", "inFlightDescriptors", "descriptorBytes",
            "framingBytes", "completedWrites", "completedBytes", "lastWriteCompletedAtMs"])
            __traits(getMember, q, name) = __traits(getMember, c, name);
        q.scratchBytes = q.reservedBytes - q.queuedReservedBytes -
            q.inFlightReservedBytes - q.descriptorBytes - q.framingBytes;
        q.maxQueuedDescriptorsPerSession = 256;
        q.maxInFlightDescriptorsPerSession = 1;
    }
    return result;
}

/// Include live and retiring owners: one busy connection must not hide a
/// different connection whose queued or writer-held payload is stuck.
void mergeHeldQueueProgress(Held owner, ref HeldQueueCounters[3] totals) {
    ByteLane*[3] lanes = [&owner.relay, &owner.commands, &owner.pongs];
    foreach (i, lane; lanes) {
        const oldest = lane.oldestUnprogressedBacklogAtMs;
        if (oldest > 0 && (!totals[i].oldestUnprogressedBacklogAtMs ||
            oldest < totals[i].oldestUnprogressedBacklogAtMs))
            totals[i].oldestUnprogressedBacklogAtMs = oldest;
    }
}

bool heldAdmissionAvailable() {
    return laneBytes[0] <= GLOBAL_LIMITS[0] - STREAM_BUFFER_SIZE - LINE_LIMIT;
}

string pingReply(string line) @safe pure nothrow {
    string verb, rest;
    ircVerb(line, verb, rest);
    if (verb != "PING") return null;
    return "PONG :" ~ ircLastParam(rest);
}

private final class Attachment {
    TCPConnection stream;
    ulong generation;
    string responseLine;
    OwnedBytes flight;
    bool uncertain;
    long writeStartedAtMs;
    this(TCPConnection stream, ulong generation) {
        this.stream = stream;
        this.generation = generation;
    }
}

final class Held {
    string id;
    string instance;
    ulong ordinal;
    Tag tag;
    string host;
    ushort port;
    TlsInfoJson tlsInfo;
    string peerIp, localIp;
    ushort peerPort, localPort;
    long connectedAtMs;
    string state = "open";
    bool attached;
    long detachedSinceMs;
    string closeReason;
    long closedAtMs;
    private ValidatedMeta storedMeta;
    private size_t metaSize;
    private ulong metaMembers;
    private bool membersKnown;
    private TCPConnection conn;
    private TLSStream tls;
    private Attachment attachment;
    private Attachment writerAttachment;
    private ulong attachGen;
    private ByteLane relay, commands, pongs;
    private GapLedger gap;
    private immutable long detachMaxMs;
    private bool closing, tornDown, writerDone;
    private bool tlsFinalized;
    private long upstreamWriteStartedAtMs;
    private ulong attachmentWriterCompletions;
    private bool commandBoundary = true;
    private uint readers, writers, relayWriters, pumps, timers;
    private LocalManualEvent upstreamChanged, relayChanged, writerCompleted;
    private void delegate() retireCallback;
    private bool retiredNotified;

    this(string id, ref DialRequest req, ref DialOutcome outcome,
         size_t detachBufferBytes, long detachMaxSecs, ulong ordinal = 0, string instance = null) {
        if (detachMaxSecs < 0 || detachMaxSecs > long.max / 1000)
            throw new Exception("invalid detach timeout");
        this.id = id;
        this.ordinal = ordinal;
        this.instance = instance;
        // Do not let tiny parsed scalar views pin a whole control request.
        tag.networkId = req.tag.networkId.idup;
        tag.userId = req.tag.userId.idup;
        tag.name = req.tag.name.idup;
        tag.egressLabel = req.tag.egressLabel.idup;
        host = req.host.idup;
        port = req.port;
        tlsInfo = outcome.tlsInfo;
        peerIp = outcome.peerIp.idup;
        localIp = outcome.localIp.idup;
        peerPort = outcome.peerPort;
        localPort = outcome.localPort;
        connectedAtMs = detachedSinceMs = unixMsNow();
        conn = outcome.conn;
        tls = outcome.tls;
        detachMaxMs = detachMaxSecs * 1000;
        relay.configure(LaneKind.relay, min(detachBufferBytes ? detachBufferBytes : SESSION_LIMITS[0], SESSION_LIMITS[0]));
        commands.configure(LaneKind.command);
        pongs.configure(LaneKind.pong);
        if (!relay.reserve(STREAM_BUFFER_SIZE)) throw new HeldAdmissionException();
        if (!relay.prepareFraming()) {
            relay.unreserve(STREAM_BUFFER_SIZE);
            throw new HeldAdmissionException();
        }
        upstreamChanged = createManualEvent();
        relayChanged = createManualEvent();
        writerCompleted = createManualEvent();
        if (!commandSpace) commandSpace = createManualEvent();
        ++counts.liveEntries;
        // Register both owners before either can yield, including early EOF.
        readers = writers = 1;
        ++counts.readerTasks;
        ++counts.upstreamWriterTasks;
        if (detachMaxMs) { timers = 1; ++counts.timerTasks; }
        try {
            if (outcome.preTlsLines.length) receive(outcome.preTlsLines);
        } catch (Throwable) { markClosed("initial_buffer_failed"); }
        if (launchOwner("holder_upstream_writer", &upstreamWriterLoop) == Task.init) {
            writers = 0;
            --counts.upstreamWriterTasks;
            writerDone = true;
            markClosed("upstream_writer_start_failed");
        }
        if (launchOwner("holder_reader", &readerLoop) == Task.init) {
            markClosed("reader_start_failed");
            // This is the sole logical reader, run inline only after closure;
            // its normal completion fence still owns TLS finalization.
            readerLoop();
        }
        if (detachMaxMs && launchOwner("holder_detach_timer", &detachTimer) == Task.init) {
            timers = 0;
            --counts.timerTasks;
            markClosed("detach_timer_start_failed");
        }
    }
    private Task launchOwner(string name, void delegate() body) {
        try return safeFiberRun(name, tag.name, body);
        catch (Throwable) { return Task.init; }
    }

    bool replaceMeta(ValidatedMeta value) {
        const encodedBytes = value.encodedBytes;
        if (!encodedBytes || !isOpen || encodedBytes > MAX_META || encodedBytes > META_TOTAL_LIMIT ||
            counts.metaBytes - metaSize > META_TOTAL_LIMIT - encodedBytes) {
            counts.metaRejectedBytes = saturatingAdd(counts.metaRejectedBytes, encodedBytes);
            return false;
        }
        ulong newMembers;
        const newKnown = value.memberCount(newMembers);
        if (membersKnown) {
            counts.metaMembersKnown -= metaMembers;
            --counts.openMembersKnown;
        }
        membersKnown = newKnown;
        metaMembers = newKnown ? newMembers : 0;
        if (membersKnown) {
            counts.metaMembersKnown += metaMembers;
            ++counts.openMembersKnown;
        }
        counts.metaBytes = counts.metaBytes - metaSize + encodedBytes;
        metaSize = encodedBytes;
        storedMeta = value;
        return true;
    }
    bool acknowledgeGap(ulong observedGeneration) {
        const wasPending = gap.generation > gap.acknowledged;
        if (!gap.acknowledge(observedGeneration)) return false;
        if (isOpen && wasPending && gap.generation == gap.acknowledged) --counts.gapEntries;
        return true;
    }
    Entry entry(bool includeMeta = true) {
        Entry e;
        e.id = id;
        e.instance = instance;
        e.ordinal = ordinal;
        e.tag = tag;
        e.state = state;
        e.attached = attached;
        e.host = host;
        e.port = port;
        e.tls = tlsInfo;
        e.peerIp = peerIp;
        e.localIp = localIp;
        e.connectedAtMs = connectedAtMs;
        e.detachedSinceMs = attached ? 0 : detachedSinceMs;
        // Exactly the raw complete-line prefix a new attachment will replay.
        e.bufferedBytes = relay.queuedBytes;
        e.closeReason = closeReason;
        e.closedAtMs = closedAtMs;
        e.gapGeneration = gap.generation;
        e.gapAckGeneration = gap.acknowledged;
        e.droppedBytes = gap.droppedBytes;
        e.droppedLines = gap.droppedLines;
        e.gapStartedAtMs = gap.startedAtMs;
        e.deliveryAmbiguous = gap.ambiguous;
        e.relayBytes = relay.bytes;
        e.outboundBytes = commands.bytes;
        e.pongBytes = pongs.bytes;
        e.attachmentGeneration = attachGen;
        e.attachmentWriterCompletions = attachmentWriterCompletions;
        e.upstreamWriterDone = writerDone;
        e.tlsFinalized = tlsFinalized;
        e.upstreamWriteInFlightMs = elapsedWrite(upstreamWriteStartedAtMs);
        if (writerAttachment !is null) {
            e.relayWriterFlightBytes = writerAttachment.flight.length;
            e.relayWriteInFlightMs = elapsedWrite(writerAttachment.writeStartedAtMs);
        }
        if (includeMeta) e.meta = storedMeta;
        return e;
    }
    @property size_t bufferedBytes() const { return relay.queuedBytes; }
    @property bool isOpen() const @safe pure nothrow { return state == "open"; }
    bool getRetireQuiescent() const {
        return !isOpen && !readers && !writers && !relayWriters && !pumps && !timers;
    }
    @property void onRetireQuiescent(void delegate() callback) {
        retireCallback = callback;
        notifyRetired();
    }
    private void notifyRetired() {
        if (retiredNotified || retireCallback is null || !getRetireQuiescent()) return;
        retiredNotified = true;
        auto callback = retireCallback;
        retireCallback = null;
        --counts.tombstones;
        callback();
    }
    private void loss(size_t bytes, size_t lines, bool ambiguous = false) {
        const pending = gap.generation > gap.acknowledged;
        gap.lose(bytes, lines, unixMsNow(), ambiguous);
        if (isOpen && !pending && gap.generation > gap.acknowledged) ++counts.gapEntries;
        counts.droppedBytes = saturatingAdd(counts.droppedBytes, bytes);
        counts.droppedLines = saturatingAdd(counts.droppedLines, lines);
    }
    private void sendPong(string parameter) {
        const prefix = cast(const(ubyte)[]) "PONG :";
        const suffix = cast(const(ubyte)[]) "\r\n";
        const token = cast(const(ubyte)[]) parameter;
        if (pongs.containsParts(prefix, token, suffix)) return;
        if (!pongs.enqueueParts(prefix, token, suffix)) {
            counts.pongSaturations = saturatingAdd(counts.pongSaturations, 1);
            // Saturation is explicit; never kill an upstream to make room.
            loss(0, 0);
            return;
        }
        upstreamChanged.emit();
    }
    private void receive(const(ubyte)[] chunk) {
        relay.frame(chunk, (line) {
            auto text = cast(string) line;
            while (text.length && (text[$ - 1] == '\n' || text[$ - 1] == '\r')) text = text[0 .. $ - 1];
            string verb, rest;
            ircVerb(text, verb, rest);
            if (verb == "PING") { sendPong(ircLastParam(rest)); return; }
            if (!relay.enqueue(line)) {
                counts.relaySaturations = saturatingAdd(counts.relaySaturations, 1);
                loss(line.length, 1);
                if (attached) detach(attachment, "relay_pressure");
            } else {
                gap.admitted();
                relayChanged.emit();
            }
        }, (bytes, lines) {
            counts.relaySaturations = saturatingAdd(counts.relaySaturations, 1);
            loss(bytes, lines);
            if (attached) detach(attachment, "relay_framing_pressure");
        });
    }
    private void writeUpstream(const(ubyte)[] bytes) {
        upstreamWriteStartedAtMs = unixMsNow();
        scope(exit) upstreamWriteStartedAtMs = 0;
        if (tls !is null) { tls.write(bytes); tls.flush(); }
        else { conn.write(bytes); conn.flush(); }
    }
    private void drainPongs() {
        while (isOpen && !pongs.empty) {
            auto value = pongs.take();
            scope(exit) { pongs.release(value); commandSpace.emit(); }
            writeUpstream(value.data);
            pongs.writeCompleted(value.length, unixMsNow());
        }
    }
    // One writer owns TCP/TLS writes. PONGs may interrupt a batch only at LF,
    // never the middle of a command, even when engine reads split that command.
    private void upstreamWriterLoop() {
        scope(exit) {
            commands.clear();
            pongs.clear();
            writerDone = true;
            writers = 0;
            --counts.upstreamWriterTasks;
            writerCompleted.emit();
            commandSpace.emit();
            notifyRetired();
        }
        bool boundary = true;
        try {
            while (isOpen) {
                const ec = upstreamChanged.emitCount;
                if (boundary) drainPongs();
                auto value = commands.take();
                if (!value.length) {
                    upstreamChanged.wait(Duration.max, ec);
                    continue;
                }
                scope(exit) { commands.release(value); commandSpace.emit(); }
                size_t start;
                foreach (i, b; value.data) {
                    if (b != '\n') continue;
                    if (boundary) drainPongs();
                    writeUpstream(value.data[start .. i + 1]);
                    commands.writeCompleted(i + 1 - start, unixMsNow());
                    boundary = true;
                    start = i + 1;
                }
                if (start < value.length) {
                    if (boundary) drainPongs();
                    writeUpstream(value.data[start .. $]);
                    commands.writeCompleted(value.length - start, unixMsNow());
                    boundary = false;
                }
            }
        } catch (Throwable e) { markClosed("write_error: " ~ e.msg); }
    }
    private size_t readUpstream(ubyte[] buf) {
        if (tls !is null) {
            if (!isOpen) throw new Exception("closed");
            if (!tls.dataAvailableForRead) {
                if (conn.waitForDataEx(UPSTREAM_WAIT) == WaitForDataStatus.timeout) return 0;
                if (!isOpen) throw new Exception("closed");
            }
            auto n = safeTLSRead(tls, buf);
            if (!n) {
                if (!conn.connected) throw new Exception("TLS connection closed by peer");
                yield();
            }
            return n;
        }
        final switch (conn.waitForDataEx(UPSTREAM_WAIT)) {
            case WaitForDataStatus.timeout: return 0;
            case WaitForDataStatus.noMoreData: throw new Exception("closed by peer");
            case WaitForDataStatus.dataAvailable: break;
        }
        if (!isOpen) throw new Exception("closed");
        auto n = conn.read(buf, IOMode.once);
        if (!n) throw new Exception("closed by peer");
        return n;
    }
    private void teardownUpstream() {
        if (tornDown) return;
        try conn.close(); catch (Throwable) {}
        // Closing raw TCP wakes a writer blocked inside TLS/TCP. No timeout can
        // establish that OpenSSL is unused; only positive completion can.
        while (!writerDone) {
            const ec = writerCompleted.emitCount;
            if (!writerDone) {
                try writerCompleted.wait(Duration.max, ec);
                catch (Throwable) {} // An interruption is not completion.
            }
        }
        tornDown = true;
        if (tls !is null) {
            try {
                // Raw TCP is already closed to wake blocked I/O. Graceful
                // finalize() can throw in SSL_shutdown before freeing SSL.
                // The pinned dependency's abort performs native cleanup only,
                // after this reader and the completed writer stopped using TLS.
                auto openssl = cast(OpenSSLStream) tls;
                if (openssl is null) throw new Exception("unsupported TLS backend for terminal abort");
                openssl.abort();
                tlsFinalized = true;
            }
            catch (Throwable e) {
                tlsFinalized = false;
                try logJsonMap("error", "holder", "TLS finalization failed",
                    ["event": "holder_tls_finalize_failed", "id": id,
                     "exceptionType": e.classinfo.name,
                     "reason": e.msg[0 .. min(e.msg.length, 512)].idup]);
                catch (Throwable) {} // Diagnostics must not prevent owner release.
            }
            tls = null;
        } else tlsFinalized = true;
    }
    private void readerLoop() {
        scope(exit) {
            teardownUpstream();
            relay.unreserve(STREAM_BUFFER_SIZE);
            readers = 0;
            --counts.readerTasks;
            notifyRetired();
        }
        ubyte[STREAM_BUFFER_SIZE] buf;
        try {
            while (isOpen) {
                const n = readUpstream(buf[]);
                if (n && !closing) receive(buf[0 .. n]);
            }
        } catch (Throwable e) {
            enum wrappedPeer = "TLS connection closed by peer (v";
            const peer = e.msg == "closed by peer" || e.msg == "TLS connection closed by peer" ||
                (e.msg.length >= wrappedPeer.length && e.msg[0 .. wrappedPeer.length] == wrappedPeer);
            markClosed(closing && closeReason.length ? closeReason :
                (peer ? CLOSE_PEER_CLOSED : (tls !is null ? "tls_read_error: " : "read_error: ") ~ e.msg));
        }
    }
    private void detachTimer() {
        scope(exit) { timers = 0; --counts.timerTasks; notifyRetired(); }
        while (isOpen) {
            const ec = relayChanged.emitCount;
            relayChanged.wait(1.seconds, ec);
            if (!isOpen || closing || attached) continue;
            if (detachedSinceMs > 0 && unixMsNow() - detachedSinceMs > detachMaxMs) {
                closeWithQuit(QUIT_ENGINE_UNAVAILABLE, CLOSE_DETACH_TIMEOUT);
                return;
            }
        }
    }

    /// Captures response, gap state and raw replay fence before its first yield.
    /// The attachment writer, never the IPC handler/reader, owns every send.
    void attach(TCPConnection stream, string responseLine = null) {
        if (!isOpen || closing) throw new Exception(ERR_CLOSED);
        if (attached || relayWriters || pumps || attachGen == ulong.max) throw new Exception(ERR_BUSY);
        auto current = new Attachment(stream, ++attachGen);
        attachment = current;
        attached = true;
        detachedSinceMs = 0;
        scope(failure) { if (owns(current)) detach(current, "attachment_setup_failed"); }
        current.responseLine = responseLine is null ? okLine(entry(), true) : responseLine ~ "\n";
        responseLine = null;
        ++relayWriters;
        ++counts.attachmentWriterTasks;
        ++pumps;
        ++counts.pumpTasks;
        scope(exit) {
            if (owns(current)) detach(current, "pump_completed");
            --pumps;
            --counts.pumpTasks;
            notifyRetired();
        }
        writerAttachment = current;
        if (launchOwner("holder_attachment_writer",
                { attachmentWriterLoop(current); }) == Task.init) {
            --relayWriters;
            --counts.attachmentWriterTasks;
            current.responseLine = null;
            writerAttachment = null;
            detach(current, "attachment_writer_start_failed");
            return;
        }
        pumpLoop(current);
    }
    private bool owns(Attachment current) {
        return isOpen && attached && attachment is current && current.generation == attachGen;
    }
    private void attachmentWriterLoop(Attachment current) {
        scope(exit) {
            current.responseLine = null;
            if (current.flight.length) relay.release(current.flight);
            if (writerAttachment is current) writerAttachment = null;
            attachmentWriterCompletions = saturatingAdd(attachmentWriterCompletions, 1);
            --relayWriters;
            --counts.attachmentWriterTasks;
            notifyRetired();
        }
        try {
            if (!owns(current)) return;
            writeAttachment(current, cast(const(ubyte)[]) current.responseLine);
            current.responseLine = null;
            while (owns(current)) {
                const ec = relayChanged.emitCount;
                current.flight = relay.take();
                if (!current.flight.length) {
                    relayChanged.wait(Duration.max, ec);
                    continue;
                }
                current.uncertain = false;
                writeAttachment(current, current.flight.data);
                relay.writeCompleted(current.flight.length, unixMsNow());
                relay.release(current.flight);
                current.uncertain = false;
            }
        } catch (Throwable) {
            if (current.flight.length && !current.uncertain) {
                loss(current.flight.length, countLines(current.flight.data), true);
                current.uncertain = true;
            }
            if (owns(current)) detach(current, "ipc_write_failed");
        }
    }
    private void writeAttachment(Attachment current, const(ubyte)[] bytes) {
        current.writeStartedAtMs = unixMsNow();
        scope(exit) current.writeStartedAtMs = 0;
        current.stream.write(bytes);
        current.stream.flush();
    }
    private static long elapsedWrite(long startedAtMs) {
        if (!startedAtMs) return 0;
        const elapsed = unixMsNow() - startedAtMs;
        return elapsed > 0 ? elapsed : 0;
    }
    private void pumpLoop(Attachment current) {
        // Scratch is reserved too; only engine input waits on command capacity.
        bool scratch;
        ubyte[] buf;
        scope(exit) {
            buf = null;
            if (scratch) { commands.unreserve(STREAM_BUFFER_SIZE); commandSpace.emit(); }
        }
        while (owns(current) && !closing) {
            if (!scratch) {
                const ec = commandSpace.emitCount;
                if (!commands.reserve(STREAM_BUFFER_SIZE)) {
                    counts.commandSaturations = saturatingAdd(counts.commandSaturations, 1);
                    waitCommandSpace(current, ec);
                    continue;
                }
                scratch = true;
                buf = new ubyte[STREAM_BUFFER_SIZE];
            }
            size_t n;
            try {
                final switch (current.stream.waitForDataEx(Duration.max)) {
                    case WaitForDataStatus.timeout: continue;
                    case WaitForDataStatus.noMoreData: throw new Exception("engine closed stream");
                    case WaitForDataStatus.dataAvailable: break;
                }
                n = current.stream.read(buf[], IOMode.once);
                if (!n) throw new Exception("engine closed stream");
            } catch (Throwable) {
                if (owns(current)) detach(current, "ipc_read_failed");
                return;
            }
            size_t start;
            while (start < n && owns(current) && !closing) {
                size_t end = start;
                while (end < n && buf[end] != '\n') ++end;
                if (end < n) ++end;
                const ec = commandSpace.emitCount;
                if (commands.enqueue(buf[start .. end])) {
                    commandBoundary = buf[end - 1] == '\n';
                    start = end;
                    upstreamChanged.emit();
                    continue;
                }
                counts.commandSaturations = saturatingAdd(counts.commandSaturations, 1);
                waitCommandSpace(current, ec);
            }
        }
    }
    private void waitCommandSpace(Attachment current, int observed) {
        // A full command lane must not pin an attachment forever after EOF.
        // The bounded probe does not consume or allocate any engine input.
        commandSpace.wait(1.seconds, observed);
        if (!owns(current)) return;
        try {
            if (current.stream.waitForDataEx(0.msecs) == WaitForDataStatus.noMoreData)
                detach(current, "ipc_eof_while_backpressured");
        } catch (Throwable) {
            if (owns(current)) detach(current, "ipc_failed_while_backpressured");
        }
    }
    private void detach(Attachment current, string why) {
        if (!owns(current)) return;
        attached = false;
        detachedSinceMs = unixMsNow();
        attachment = null;
        if (current.flight.length && !current.uncertain) {
            loss(current.flight.length, countLines(current.flight.data), true);
            current.uncertain = true;
        }
        attachGen = saturatingAdd(attachGen, 1);
        commands.discardIncompleteCommands();
        commandBoundary = true;
        relayChanged.emit();
        commandSpace.emit();
        try current.stream.close(); catch (Throwable) {}
        try logJsonMap("info", "holder", "Engine detached",
            ["id": id, "event": "detach", "reason": why]);
        catch (Throwable) {}
    }
    private void markClosed(string reason) {
        if (!isOpen) return;
        if (attached) detach(attachment, "upstream_closed");
        state = "closed";
        closing = true;
        closeReason = reason[0 .. min(reason.length, 256)].idup;
        closedAtMs = unixMsNow();
        --counts.liveEntries;
        ++counts.tombstones;
        if (gap.generation > gap.acknowledged) --counts.gapEntries;
        if (membersKnown) {
            counts.metaMembersKnown -= metaMembers;
            --counts.openMembersKnown;
            membersKnown = false;
            metaMembers = 0;
        }
        counts.metaBytes -= metaSize;
        metaSize = 0;
        storedMeta = ValidatedMeta.init;
        relay.clear();
        commands.clear();
        pongs.clear();
        upstreamChanged.emit();
        relayChanged.emit();
        commandSpace.emit();
        try conn.close(); catch (Throwable) {}
        notifyRetired();
    }
    void sendQuit(string quitText, string reason) {
        if (!isOpen || closing) return;
        closing = true;
        closeReason = reason[0 .. min(reason.length, 256)].idup;
        // Explicit administrative shutdown is the only pressure path allowed to
        // close upstream. QUIT still traverses the sole upstream writer.
        auto text = quitText.length > 512 ? quitText[0 .. 512] : quitText;
        if (!commandBoundary || !commands.enqueueParts(
                cast(const(ubyte)[]) "QUIT :", cast(const(ubyte)[]) text,
                cast(const(ubyte)[]) "\r\n")) {
            markClosed(closeReason);
            return;
        }
        upstreamChanged.emit();
    }
    void closeWithQuit(string quitText, string reason) {
        if (!isOpen) return;
        sendQuit(quitText, reason);
        const deadline = unixMsNow() + QUIT_GRACE_PERIOD_MS;
        while (isOpen && unixMsNow() < deadline) sleep(50.msecs);
        markClosed(reason);
    }
    void close(string quit) {
        if (!isOpen) return;
        if (quit.length) closeWithQuit(quit, "closed_by_engine");
        else markClosed("closed_by_engine");
    }
}

private size_t countLines(const(ubyte)[] bytes) {
    size_t count;
    foreach (b; bytes) if (b == '\n') ++count;
    return count;
}

/// Executes the real bounded queue/framing/loss primitives without sockets.
/// The holder subpackage's unittest collector reports each failed invariant.
version (unittest)
void runHeldBufferRegressions(scope void delegate(bool, string) check) {
    const initial = laneBytes;
    ByteLane lane;
    lane.configure(LaneKind.relay);
    scope(exit) lane.clear();
    check(lane.prepareFraming(), "framing credit reserved before receiving");
    string[] seen;
    size_t lostBytes, lostLines;
    void push(string text) {
        lane.frame(cast(const(ubyte)[]) text,
            (line) { seen ~= (cast(string) line).idup; },
            (bytes, lines) { lostBytes += bytes; lostLines += lines; });
    }
    push(":s NOTICE * :PING is payload\r\nPI");
    push("NG :token\r\n:s 001 n :ok\n");
    check(seen == [":s NOTICE * :PING is payload\r\n", "PING :token\r\n", ":s 001 n :ok\n"], "fragmented framing preserves raw delimiters");
    check(pingReply(seen[0]) is null && pingReply("@t=x :s PING :token") == "PONG :token", "PING recognition uses IRC verb, not substring");
    auto oversized = new char[LINE_LIMIT + 1];
    oversized[] = 'x';
    push(cast(string) oversized);
    push("PING :not-a-command\r\n:s NOTICE * :after\r\n");
    check(seen[$ - 1] == ":s NOTICE * :after\r\n" && seen.length == 4 && lostLines == 1 && lostBytes == oversized.length + "PING :not-a-command\r\n".length, "oversized tail discards through delimiter");
    check(lane.enqueue(cast(const(ubyte)[]) "one\r\n"), "FIFO admission");
    auto flight = lane.take();
    check(lane.enqueue(cast(const(ubyte)[]) "two\r\n"), "new arrivals queue behind writer-held prefix");
    const charged = lane.bytes;
    check(cast(string) flight.data == "one\r\n" && lane.queuedBytes == 5, "dequeue preserves FIFO and raw replay byte count");
    auto queueEvidence = sampleHeldQueues()[0];
    check(queueEvidence.queuedBytes >= 5 && queueEvidence.inFlightBytes >= 5 &&
        queueEvidence.inFlightReservedBytes >= flight.allocation.length &&
        queueEvidence.framingBytes >= LINE_LIMIT && queueEvidence.descriptorBytes > 0,
        "numeric evidence includes framing, descriptors, queued and writer-held storage");
    lane.clear();
    check(lane.bytes == flight.allocation.length && laneBytes[0] == initial[0] + flight.allocation.length && charged >= flight.length, "terminal clear retains blocked writer reservation");
    lane.release(flight);
    check(laneBytes == initial, "vacated buffers release all reservations");
    queueEvidence = sampleHeldQueues()[0];
    check(queueEvidence.reservedBytes == initial[0] &&
        queueEvidence.inFlightBytes == 0 && queueEvidence.queuedBytes == 0,
        "numeric queue evidence clears only after the writer releases its reference");
    bool burstAccepted = true;
    foreach (_; 0 .. 5_000)
        burstAccepted = lane.enqueue(cast(const(ubyte)[]) "x\r\n") && burstAccepted;
    check(burstAccepted && lane.queuedBytes == 15_000 && lane.bytes < SESSION_LIMITS[0],
        "tiny-line burst packs descriptors without dropping below byte budget");
    auto burst = lane.take();
    check(burst.data.length == 15_000 && burst.data[0 .. 3] == cast(const(ubyte)[]) "x\r\n" &&
        burst.data[$ - 3 .. $] == cast(const(ubyte)[]) "x\r\n", "packed slab preserves first and last wire line");
    lane.release(burst);
    lane.clear();
    check(lane.prepareFraming(), "framing credit available before queue saturation");
    const filler = lane.limit - lane.bytes;
    check(lane.reserve(filler), "fill remaining relay credit");
    const lostBeforePing = lostBytes;
    push("PI");
    push("NG :still-live\r\n");
    check(seen[$ - 1] == "PING :still-live\r\n" && lostBytes == lostBeforePing,
        "fragmented PING remains recognizable at full relay budget");
    lane.unreserve(filler);
    lane.clear();
    ByteLane[16] reservations;
    scope(exit) foreach (ref reservation; reservations)
        reservation.unreserve(reservation.bytes);
    bool allReserved = true;
    foreach (ref reservation; reservations) {
        reservation.configure(LaneKind.relay);
        const available = GLOBAL_LIMITS[0] - laneBytes[0];
        allReserved = reservation.reserve(min(available, SESSION_LIMITS[0])) && allReserved;
    }
    check(allReserved, "all aggregate owners reserve within their session caps");
    ByteLane overflow;
    overflow.configure(LaneKind.relay);
    check(laneBytes[0] == GLOBAL_LIMITS[0] && !overflow.reserve(1),
        "aggregate cap refuses even one unreserved byte");
    foreach (ref reservation; reservations) reservation.unreserve(reservation.bytes);
    ByteLane commands;
    commands.configure(LaneKind.command);
    scope(exit) commands.clear();
    auto chunk = new ubyte[16 * 1024];
    size_t accepted;
    while (commands.enqueue(chunk)) ++accepted;
    check(accepted > 0 && commands.bytes <= SESSION_LIMITS[1] && !commands.enqueue(chunk), "ordinary storage backpressures at byte budget");
    ByteLane urgent;
    urgent.configure(LaneKind.pong);
    scope(exit) urgent.clear();
    check(urgent.enqueue(cast(const(ubyte)[]) "PONG :urgent\r\n") && urgent.contains(cast(const(ubyte)[]) "PONG :urgent\r\n"), "urgent storage independent of saturated ordinary storage");
    check(!commands.take().length, "unterminated command is never lent to upstream writer");
    commands.discardIncompleteCommands();
    check(commands.queuedBytes == 0, "attachment loss discards only unadmitted command tail");
    check(commands.enqueue(cast(const(ubyte)[]) "PRIVMSG #c :par") &&
          !commands.take().length &&
          commands.enqueue(cast(const(ubyte)[]) "tial\r\n"), "fragmented command waits for complete LF");
    auto first = commands.take();
    auto last = commands.take();
    check(cast(string) first.data == "PRIVMSG #c :par" &&
          cast(string) last.data == "tial\r\n", "complete command fragments preserve wire bytes");
    commands.release(first);
    commands.release(last);
    GapLedger gap;
    gap.lose(5, 1, 10);
    check(gap.generation == 1 && !gap.acknowledge(2), "future gap acknowledgment refused");
    gap.acknowledge(1);
    gap.lose(6, 1, 20, true);
    gap.acknowledge(1);
    check(gap.generation == 2 && gap.acknowledged == 1 && gap.ambiguous && gap.droppedBytes == 11, "old acknowledgment cannot erase later ambiguous loss");
    check(saturatingAdd(ulong.max - 1, 4) == ulong.max, "loss counters saturate");
    gap.generation = ulong.max;
    gap.acknowledged = ulong.max - 1;
    check(!gap.acknowledge(ulong.max) && gap.acknowledged < gap.generation,
        "saturated gap generation cannot falsely acknowledge later losses");
    commands.clear();
    urgent.clear();
    check(laneBytes == initial, "all regression owners relinquish their reservations");
}

unittest {
    runHeldBufferRegressions((bool passed, string name) {
        assert(passed, name);
    });
}

