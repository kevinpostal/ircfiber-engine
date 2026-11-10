module holder.bounded;

// All owners run on the holder's one event-loop thread. Reservations include
// descriptor arrays, framing capacity and buffers lent to a blocked writer.
package enum LaneKind { relay, command, pong }
package enum size_t LINE_LIMIT = 64 * 1024;
package enum size_t[3] SESSION_LIMITS = [4 * 1024 * 1024, 64 * 1024, 64 * 1024];
package enum size_t[3] GLOBAL_LIMITS = [64 * 1024 * 1024, 8 * 1024 * 1024, 4 * 1024 * 1024];
package size_t[3] laneBytes;

package struct LaneCounters {
    ulong queuedBytes, queuedReservedBytes, queuedDescriptors;
    ulong inFlightBytes, inFlightReservedBytes, inFlightDescriptors;
    ulong descriptorBytes, framingBytes;
    ulong completedWrites, completedBytes;
    long lastWriteCompletedAtMs;
}
package LaneCounters[3] laneCounters;


package ulong saturatingAdd(ulong a, ulong b) @safe pure nothrow @nogc {
    return ulong.max - a < b ? ulong.max : a + b;
}

package struct GapLedger {
    ulong generation, acknowledged, droppedBytes, droppedLines;
    long startedAtMs;
    bool ambiguous;
    private bool episode;

    void lose(ulong bytes, ulong lines, long now, bool uncertain = false) {
        if (!episode) {
            generation = saturatingAdd(generation, 1);
            if (!startedAtMs) startedAtMs = now;
            episode = true;
        }
        droppedBytes = saturatingAdd(droppedBytes, bytes);
        droppedLines = saturatingAdd(droppedLines, lines);
        ambiguous |= uncertain;
    }
    void admitted() { episode = false; }
    bool acknowledge(ulong observed) {
        // Once generation space is exhausted, fail closed: acknowledging max
        // would falsely cover every later loss that can no longer increment it.
        if (observed > generation || observed == ulong.max) return false;
        if (observed > acknowledged) acknowledged = observed;
        // A later loss is a new episode even if no data was admitted between.
        if (observed == generation) episode = false;
        return true;
    }
}

package struct OwnedBytes {
    ubyte[] allocation;
    size_t used;
    bool inFlight;
    @property ubyte[] data() { return allocation[0 .. used]; }
    @property const(ubyte)[] data() const { return allocation[0 .. used]; }
    @property size_t length() const { return used; }
}

package struct ByteLane {
    LaneKind kind;
    size_t limit;
    size_t bytes;
    size_t queuedBytes;
    private OwnedBytes[] slots;
    private size_t head, count, readyCount;
    private ubyte[] tail;
    private size_t tailLength;
    private bool discarding, framingReserved;
    private size_t inFlightPayloadBytes;
    private long backlogProgressAtMs;
    private enum size_t SLOT_COUNT = 256;
    private enum size_t DESCRIPTORS = SLOT_COUNT * OwnedBytes.sizeof;

    void configure(LaneKind kind, size_t limit = 0) {
        this.kind = kind;
        this.limit = limit ? limit : SESSION_LIMITS[cast(size_t) kind];
    }
    bool prepareFraming() {
        assert(!tail.length && !framingReserved);
        if (!reserve(LINE_LIMIT)) return false;
        // Keep this credit unavailable to queued relay data: a fragmented PING
        // must still be recognizable when the relay queue is otherwise full.
        framingReserved = true;
        laneCounters[cast(size_t) kind].framingBytes += LINE_LIMIT;
        return true;
    }
    bool reserve(size_t amount) {
        const k = cast(size_t) kind;
        if (amount > limit || bytes > limit - amount ||
            amount > GLOBAL_LIMITS[k] || laneBytes[k] > GLOBAL_LIMITS[k] - amount) return false;
        bytes += amount;
        laneBytes[k] += amount;
        return true;
    }
    void unreserve(size_t amount) {
        assert(amount <= bytes && amount <= laneBytes[cast(size_t) kind]);
        bytes -= amount;
        laneBytes[cast(size_t) kind] -= amount;
    }
    bool enqueue(const(ubyte)[] value) {
        return enqueueParts(null, value, null);
    }
    bool enqueueParts(const(ubyte)[] prefix, const(ubyte)[] value, const(ubyte)[] suffix) {
        const length = prefix.length + value.length + suffix.length;
        const startsBacklog = length && !queuedBytes && !inFlightPayloadBytes;
        // Pack complete relay lines into bounded slabs. A burst of tiny lines
        // must not exhaust descriptors while most of its byte budget is idle.
        if (kind == LaneKind.relay && count) {
            auto last = &slots[(head + count - 1) % SLOT_COUNT];
            if (length <= last.allocation.length - last.used) {
                copyParts(last.allocation[last.used .. last.used + length], prefix, value, suffix);
                last.used += length;
                queuedBytes += length;
                laneCounters[cast(size_t) kind].queuedBytes += length;
                if (startsBacklog) {
                    import std.datetime : Clock;
                    backlogProgressAtMs = Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L;
                }
                return true;
            }
        }
        if (count == SLOT_COUNT) return false;
        const descriptors = slots.length ? 0 : DESCRIPTORS;
        size_t capacity = kind == LaneKind.relay && length < 16_384 ? 16_384 : length;
        if (!reserve(capacity + descriptors)) {
            capacity = length;
            if (!reserve(capacity + descriptors)) return false;
        }
        bool installedDescriptors;
        scope(failure) {
            unreserve(capacity + (installedDescriptors ? 0 : descriptors));
        }
        if (!slots.length) {
            slots = new OwnedBytes[SLOT_COUNT];
            installedDescriptors = true;
            laneCounters[cast(size_t) kind].descriptorBytes += DESCRIPTORS;
        }
        auto allocation = new ubyte[capacity];
        copyParts(allocation[0 .. length], prefix, value, suffix);
        slots[(head + count) % SLOT_COUNT] = OwnedBytes(allocation, length);
        ++count;
        queuedBytes += length;
        if (startsBacklog) {
            import std.datetime : Clock;
            backlogProgressAtMs = Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L;
        }
        auto counters = &laneCounters[cast(size_t) kind];
        counters.queuedBytes += length;
        counters.queuedReservedBytes += capacity;
        ++counters.queuedDescriptors;
        // Command callers split on LF. Never lend an incomplete command to
        // the writer: an engine that stalls mid-command cannot block PONG.
        if (kind == LaneKind.command && length && allocation[length - 1] == '\n')
            readyCount = count;
        return true;
    }
    private static void copyParts(ubyte[] target, const(ubyte)[] prefix,
                                  const(ubyte)[] value, const(ubyte)[] suffix) {
        target[0 .. prefix.length] = prefix;
        target[prefix.length .. prefix.length + value.length] = value;
        target[prefix.length + value.length .. $] = suffix;
    }
    bool contains(const(ubyte)[] value) const {
        return containsParts(null, value, null);
    }
    bool containsParts(const(ubyte)[] prefix, const(ubyte)[] value, const(ubyte)[] suffix) const {
        foreach (i; 0 .. count) {
            auto slot = slots[(head + i) % SLOT_COUNT].data;
            if (slot.length == prefix.length + value.length + suffix.length &&
                slot[0 .. prefix.length] == prefix &&
                slot[prefix.length .. prefix.length + value.length] == value &&
                slot[prefix.length + value.length .. $] == suffix) return true;
        }
        return false;
    }
    OwnedBytes take() {
        if (!count || (kind == LaneKind.command && !readyCount)) return OwnedBytes.init;
        auto result = slots[head];
        slots[head] = OwnedBytes.init;
        head = (head + 1) % SLOT_COUNT;
        --count;
        if (kind == LaneKind.command) --readyCount;
        queuedBytes -= result.length;
        inFlightPayloadBytes += result.length;
        auto counters = &laneCounters[cast(size_t) kind];
        counters.queuedBytes -= result.length;
        counters.queuedReservedBytes -= result.allocation.length;
        --counters.queuedDescriptors;
        counters.inFlightBytes += result.length;
        counters.inFlightReservedBytes += result.allocation.length;
        ++counters.inFlightDescriptors;
        result.inFlight = true;
        return result; // Reservation belongs to the writer until release().
    }
    void release(ref OwnedBytes value) {
        if (value.inFlight) {
            inFlightPayloadBytes -= value.length;
            auto counters = &laneCounters[cast(size_t) kind];
            counters.inFlightBytes -= value.length;
            counters.inFlightReservedBytes -= value.allocation.length;
            --counters.inFlightDescriptors;
        }
        unreserve(value.allocation.length);
        value = OwnedBytes.init;
        if (!queuedBytes && !inFlightPayloadBytes) backlogProgressAtMs = 0;
    }
    @property bool empty() const { return count == 0; }
    @property size_t partialBytes() const { return tailLength; }
    /// Owner-local age cannot be refreshed by some other busy session.
    @property long oldestUnprogressedBacklogAtMs() const {
        return queuedBytes || inFlightPayloadBytes ? backlogProgressAtMs : 0;
    }
    void writeCompleted(size_t length, long now) {
        auto c = &laneCounters[cast(size_t) kind];
        c.completedWrites = saturatingAdd(c.completedWrites, 1);
        c.completedBytes = saturatingAdd(c.completedBytes, length);
        c.lastWriteCompletedAtMs = now;
        if ((queuedBytes || inFlightPayloadBytes) && now > backlogProgressAtMs)
            backlogProgressAtMs = now;
    }
    void discardIncompleteCommands() {
        assert(kind == LaneKind.command);
        while (count > readyCount) {
            const index = (head + count - 1) % SLOT_COUNT;
            auto value = slots[index];
            slots[index] = OwnedBytes.init;
            --count;
            queuedBytes -= value.length;
            auto counters = &laneCounters[cast(size_t) kind];
            counters.queuedBytes -= value.length;
            counters.queuedReservedBytes -= value.allocation.length;
            --counters.queuedDescriptors;
            release(value);
        }
    }

    private void clearTail() {
        assert(framingReserved || !tail.length);
        tailLength = 0;
    }
    private bool appendTail(const(ubyte)[] part) {
        const needed = tailLength + part.length;
        if (needed > LINE_LIMIT) return false;
        if (!tail.length) tail = new ubyte[LINE_LIMIT];
        tail[tailLength .. needed] = part;
        tailLength = needed;
        return true;
    }

    // Callback borrows its line only until it returns. No queue is hidden here.
    // Lost tails are discarded through LF, so payload substrings never become PING.
    void frame(const(ubyte)[] chunk, scope void delegate(const(ubyte)[]) line,
               scope void delegate(size_t, size_t) loss) {
        assert(framingReserved);
        size_t start;
        foreach (i, b; chunk) {
            if (b != '\n') continue;
            const part = chunk[start .. i + 1];
            start = i + 1;
            if (discarding) {
                loss(part.length, 1);
                discarding = false;
            } else if (!tailLength && part.length <= LINE_LIMIT) {
                line(part);
            } else if (appendTail(part)) {
                line(tail[0 .. tailLength]);
                clearTail();
            } else {
                loss(tailLength + part.length, 1);
                clearTail();
            }
        }
        auto rest = chunk[start .. $];
        if (!rest.length) return;
        if (discarding) loss(rest.length, 0);
        else if (!appendTail(rest)) {
            loss(tailLength + rest.length, 0);
            clearTail();
            discarding = true;
        }
    }
    void clear() {
        readyCount = count;
        while (!empty) { auto value = take(); release(value); }
        if (framingReserved) {
            tail = null;
            tailLength = 0;
            framingReserved = false;
            laneCounters[cast(size_t) kind].framingBytes -= LINE_LIMIT;
            unreserve(LINE_LIMIT);
        } else clearTail();
        unreserve(slots.length * OwnedBytes.sizeof);
        laneCounters[cast(size_t) kind].descriptorBytes -= slots.length * OwnedBytes.sizeof;
        slots = null;
        head = count = readyCount = 0;
        discarding = false;
    }
}

unittest {
    ByteLane blocked, active;
    blocked.configure(LaneKind.relay);
    active.configure(LaneKind.relay);
    scope(exit) { blocked.clear(); active.clear(); }
    assert(blocked.enqueue(cast(const(ubyte)[]) "blocked\n"));
    const blockedSince = blocked.oldestUnprogressedBacklogAtMs;
    assert(blockedSince > 0);
    auto flight = blocked.take();
    scope(exit) if (flight.inFlight) blocked.release(flight);
    assert(blocked.oldestUnprogressedBacklogAtMs == blockedSince);
    assert(active.enqueue(cast(const(ubyte)[]) "active\n"));
    active.writeCompleted(7, blockedSince + 1);
    assert(active.oldestUnprogressedBacklogAtMs >= blockedSince + 1);
    assert(blocked.oldestUnprogressedBacklogAtMs == blockedSince,
        "another owner's successful flush cannot refresh a stalled backlog");
    blocked.clear();
    assert(blocked.oldestUnprogressedBacklogAtMs == blockedSince,
        "clearing queue slots does not hide a blocked writer");
    blocked.release(flight);
    assert(blocked.oldestUnprogressedBacklogAtMs == 0);
    active.clear();
    assert(active.oldestUnprogressedBacklogAtMs == 0);
}
