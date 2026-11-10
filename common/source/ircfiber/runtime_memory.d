module ircfiber.runtime_memory;

import core.memory : GC;
import std.datetime : Clock;
import std.json : JSONValue, JSONOptions;
import std.string : lineSplitter, strip, startsWith;
import std.algorithm : splitter;
import ircfiber.logging : logJsonMap;

/// Unavailable is never a measured zero. Reasons are bounded, not exception text.
enum MemoryAvailability { available, missing, denied, malformed, unlimited, unsupported, readError }

struct MemoryNumber {
    ulong value;
    MemoryAvailability availability = MemoryAvailability.missing;
}

/// Counts of actual owners, supplied by the engine without building snapshots.
struct RuntimeOwnerCounters {
    ulong activeGenerations, retiredGenerations, completedRetiredGenerations;
    ulong members, namesMembers, realnames, realnameProbed, idents, accounts, away, bots, userMetadata;
    ulong pendingMetaFlags, ordinaryMetaPublishers, metaBuilds, eventBufferFill, eventBufferCapacity;
}

struct RuntimeNetworkCounters {
    string networkId;
    ulong identities, members;
}

struct RuntimeTelemetryCounters {
    ulong count, bytes, droppedCount, droppedBytes;
    ulong maxCount, maxBytes;
    bool available;
    long lastExportSuccessAtMs;
}

struct RuntimeArchiveCounters {
    bool available, ready, failed, stopping, replayInFlight;
    ulong ingressCommands, ingressBytes, pendingOperations, pendingBytes;
    ulong checkpoint, durableSequence, gapCount;
    ulong consumerFibers, diskThreads;
    long sampledAtMs;
    bool diskBytesKnown, freeBytesKnown;
    ulong diskBytes, maxBytes, minFreeBytes, freeBytes, controlReserveBytes, stateReserveBytes;
    long diskSampledAtMs;
}

struct RuntimeDiagnosticCounters {
    bool available;
    long lastWrittenAtMs;
    ulong pendingBytes, inFlightBytes, failures;
    string lastResult;
}

struct RuntimeMemorySample {
    long sampledAtMs;
    MemoryNumber gcUsedBytes, gcFreeBytes, gcCollections;
    MemoryNumber gcCollectionNs, gcPauseNs, gcMaxCollectionNs, gcMaxPauseNs;
    MemoryNumber rssBytes, highWaterBytes, swapBytes, threads;
    MemoryNumber cgroupBytes, cgroupMaxBytes, cgroupSwapBytes, cgroupSwapMaxBytes;
    MemoryNumber cgroupAnonBytes, cgroupFileBytes, cgroupKernelBytes, cgroupSockBytes, cgroupSlabBytes;
    MemoryNumber cgroupMaxEvents, cgroupOomEvents, cgroupOomKillEvents;
    MemoryNumber cgroupPressureSomeUs, cgroupPressureFullUs;
    bool ownersAvailable;
    RuntimeOwnerCounters owners;
    RuntimeNetworkCounters[5] largestNetworks;
    size_t largestNetworkCount;
    RuntimeArchiveCounters archive;
    RuntimeDiagnosticCounters diagnosticFile;
    RuntimeTelemetryCounters metrics, tracing, logging;
}

private MemoryNumber measured(ulong value) nothrow @safe {
    return MemoryNumber(value, MemoryAvailability.available);
}

private MemoryNumber unavailable(MemoryAvailability reason) nothrow @safe {
    return MemoryNumber(0, reason);
}

/// Overflow, signs, empty text and trailing garbage are malformed, not zero.
private MemoryNumber parseNumber(scope const(char)[] text) nothrow @safe {
    text = text.strip;
    if (text == "max") return unavailable(MemoryAvailability.unlimited);
    if (!text.length) return unavailable(MemoryAvailability.malformed);
    ulong value;
    foreach (c; text) {
        if (c < '0' || c > '9' || value > (ulong.max - (c - '0')) / 10)
            return unavailable(MemoryAvailability.malformed);
        value = value * 10 + c - '0';
    }
    return measured(value);
}

private struct SmallFile {
    string text;
    MemoryAvailability availability;
}

/// Reads only procfs/cgroup pseudo-files, with a strict cap on every allocation.
private SmallFile readSmall(string path, size_t maxBytes = 8_192) {
    version (linux) {
        import core.sys.posix.fcntl : open, O_RDONLY, O_CLOEXEC;
        import core.sys.posix.unistd : read, close;
        import core.stdc.errno : errno, EINTR, ENOENT, EACCES, EPERM;
        import std.string : toStringz;
        int fd = open(path.toStringz, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            auto reason = errno == ENOENT ? MemoryAvailability.missing :
                (errno == EACCES || errno == EPERM) ? MemoryAvailability.denied : MemoryAvailability.readError;
            return SmallFile(null, reason);
        }
        scope(exit) close(fd);
        char[1_024] chunk;
        char[] bytes;
        while (true) {
            auto n = read(fd, chunk.ptr, chunk.length);
            if (n < 0) {
                if (errno == EINTR) continue;
                return SmallFile(null, MemoryAvailability.readError);
            }
            if (!n) return SmallFile(cast(string) bytes, MemoryAvailability.available);
            if (cast(size_t) n > maxBytes - bytes.length)
                return SmallFile(null, MemoryAvailability.malformed);
            bytes ~= chunk[0 .. cast(size_t) n];
        }
    } else {
        return SmallFile(null, MemoryAvailability.unsupported);
    }
}

private MemoryNumber readNumber(string path) {
    auto file = readSmall(path, 128);
    return file.availability == MemoryAvailability.available ? parseNumber(file.text) : unavailable(file.availability);
}

private void readStatus(ref RuntimeMemorySample sample) {
    auto file = readSmall("/proc/self/status");
    sample.rssBytes = sample.highWaterBytes = sample.swapBytes = sample.threads = unavailable(file.availability);
    if (file.availability != MemoryAvailability.available) return;
    sample.rssBytes = sample.highWaterBytes = sample.swapBytes = sample.threads = unavailable(MemoryAvailability.missing);
    foreach (line; file.text.lineSplitter) {
        if (line.startsWith("VmRSS:")) sample.rssBytes = parseStatusBytes(line[6 .. $]);
        else if (line.startsWith("VmHWM:")) sample.highWaterBytes = parseStatusBytes(line[6 .. $]);
        else if (line.startsWith("VmSwap:")) sample.swapBytes = parseStatusBytes(line[7 .. $]);
        else if (line.startsWith("Threads:")) sample.threads = parseNumber(line[8 .. $]);
    }
}

private MemoryNumber parseStatusBytes(scope const(char)[] text) nothrow @safe {
    text = text.strip;
    if (!text.endsWithKiB) return unavailable(MemoryAvailability.malformed);
    auto number = parseNumber(text[0 .. $ - 2]);
    if (number.availability == MemoryAvailability.available) {
        if (number.value > ulong.max / 1_024) return unavailable(MemoryAvailability.malformed);
        number.value *= 1_024;
    }
    return number;
}

private bool endsWithKiB(scope const(char)[] text) nothrow @safe {
    return text.length >= 2 && text[$ - 2 .. $] == "kB";
}

private struct CgroupLocation {
    string directory;
    MemoryAvailability availability = MemoryAvailability.missing;
}

/// Decode only mountinfo's defined path escapes; reject other escapes.
private string mountPath(string text) {
    if (!text.length || text[0] != '/') return null;
    char[] decoded;
    foreach (size_t i; 0 .. text.length) {
        // Most paths have no escapes, so avoid an unnecessary allocation.
        if (text[i] == '\\') {
            decoded = text[0 .. i].dup;
            size_t j = i;
            while (j < text.length) {
                if (text[j] != '\\') { decoded ~= text[j++]; continue; }
                if (j + 4 > text.length) return null;
                auto escape = text[j .. j + 4];
                if (escape == "\\040") decoded ~= ' ';
                else if (escape == "\\011") decoded ~= '\t';
                else if (escape == "\\012") decoded ~= '\n';
                else if (escape == "\\134") decoded ~= '\\';
                else return null;
                j += 4;
            }
            return cast(string) decoded;
        }
    }
    return text;
}

private bool validAbsolutePath(string path) {
    if (!path.length || path[0] != '/') return false;
    foreach (part; path.splitter('/')) if (part == ".." || part == ".") return false;
    return true;
}

private CgroupLocation resolveSelfCgroup() {
    auto membership = readSmall("/proc/self/cgroup");
    if (membership.availability != MemoryAvailability.available) return CgroupLocation(null, membership.availability);
    string relative;
    foreach (line; membership.text.lineSplitter) {
        if (line.startsWith("0::")) { relative = line[3 .. $]; break; }
    }
    // v1 combined memory+swap accounting has different semantics. Do not
    // silently label those numbers as v2 swap-only values.
    if (!relative.length) return CgroupLocation(null, MemoryAvailability.unsupported);
    if (!validAbsolutePath(relative)) return CgroupLocation(null, MemoryAvailability.malformed);
    auto mounts = readSmall("/proc/self/mountinfo", 65_536);
    if (mounts.availability != MemoryAvailability.available) return CgroupLocation(null, mounts.availability);
    foreach (line; mounts.text.lineSplitter) {
        string rootColumn, mountColumn, filesystem;
        size_t index;
        bool afterSeparator;
        foreach (column; line.splitter(' ')) {
            if (!column.length) continue;
            if (index == 3) rootColumn = column;
            if (index == 4) mountColumn = column;
            if (afterSeparator) { filesystem = column; break; }
            if (index >= 6 && column == "-") afterSeparator = true;
            ++index;
        }
        if (filesystem != "cgroup2") continue;
        auto root = mountPath(rootColumn);
        auto mount = mountPath(mountColumn);
        if (!validAbsolutePath(root) || !validAbsolutePath(mount)) continue;
        string suffix;
        if (root == "/") suffix = relative == "/" ? "" : relative;
        else if (relative == root) suffix = "";
        else if (relative.length > root.length && relative[0 .. root.length] == root && relative[root.length] == '/')
            suffix = relative[root.length .. $];
        else continue;
        return CgroupLocation((mount == "/" ? "" : mount) ~ suffix, MemoryAvailability.available);
    }
    return CgroupLocation(null, MemoryAvailability.missing);
}

private void readCgroup(ref RuntimeMemorySample sample) {
    auto location = resolveSelfCgroup();
    // No numeric fallback when procfs, mount resolution or cgroup v2 is absent.
    static foreach (name; ["cgroupBytes", "cgroupMaxBytes", "cgroupSwapBytes", "cgroupSwapMaxBytes",
        "cgroupAnonBytes", "cgroupFileBytes", "cgroupKernelBytes", "cgroupSockBytes", "cgroupSlabBytes",
        "cgroupMaxEvents", "cgroupOomEvents", "cgroupOomKillEvents", "cgroupPressureSomeUs", "cgroupPressureFullUs"])
        __traits(getMember, sample, name) = unavailable(location.availability);
    if (location.availability != MemoryAvailability.available) return;
    auto directory = location.directory;
    sample.cgroupBytes = readNumber(directory ~ "/memory.current");
    sample.cgroupMaxBytes = readNumber(directory ~ "/memory.max");
    sample.cgroupSwapBytes = readNumber(directory ~ "/memory.swap.current");
    sample.cgroupSwapMaxBytes = readNumber(directory ~ "/memory.swap.max");
    auto stats = readSmall(directory ~ "/memory.stat");
    sample.cgroupAnonBytes = tableNumber(stats, "anon");
    sample.cgroupFileBytes = tableNumber(stats, "file");
    sample.cgroupKernelBytes = tableNumber(stats, "kernel");
    sample.cgroupSockBytes = tableNumber(stats, "sock");
    sample.cgroupSlabBytes = tableNumber(stats, "slab");
    auto events = readSmall(directory ~ "/memory.events");
    sample.cgroupMaxEvents = tableNumber(events, "max");
    sample.cgroupOomEvents = tableNumber(events, "oom");
    sample.cgroupOomKillEvents = tableNumber(events, "oom_kill");
    auto pressure = readSmall(directory ~ "/memory.pressure");
    sample.cgroupPressureSomeUs = pressureTotal(pressure, "some");
    sample.cgroupPressureFullUs = pressureTotal(pressure, "full");
}

private MemoryNumber tableNumber(ref const SmallFile file, string key) {
    if (file.availability != MemoryAvailability.available) return unavailable(file.availability);
    foreach (line; file.text.lineSplitter) {
        if (line.length > key.length && line[0 .. key.length] == key && (line[key.length] == ' ' || line[key.length] == '\t'))
            return parseNumber(line[key.length .. $]);
    }
    return unavailable(MemoryAvailability.missing);
}

private MemoryNumber pressureTotal(ref const SmallFile file, string key) {
    if (file.availability != MemoryAvailability.available) return unavailable(file.availability);
    foreach (line; file.text.lineSplitter) {
        if (line.length <= key.length || line[0 .. key.length] != key || line[key.length] != ' ') continue;
        foreach (word; line.splitter(' ')) if (word.startsWith("total=")) return parseNumber(word[6 .. $]);
        return unavailable(MemoryAvailability.malformed);
    }
    return unavailable(MemoryAvailability.missing);
}

/// GC stats are collection-updated estimates, not an exact live-object census.
/// Sampling never requests a collection and does not infer a native leak from
/// RSS minus heap. OS availability is independent of GC availability.
RuntimeMemorySample sampleRuntimeMemory() {
    RuntimeMemorySample sample;
    sample.sampledAtMs = Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L;
    auto heap = GC.stats();
    sample.gcUsedBytes = measured(heap.usedSize);
    sample.gcFreeBytes = measured(heap.freeSize);
    auto profile = GC.profileStats();
    sample.gcCollections = measured(profile.numCollections);
    sample.gcCollectionNs = durationNumber(profile.totalCollectionTime.total!"nsecs");
    sample.gcPauseNs = durationNumber(profile.totalPauseTime.total!"nsecs");
    sample.gcMaxCollectionNs = durationNumber(profile.maxCollectionTime.total!"nsecs");
    sample.gcMaxPauseNs = durationNumber(profile.maxPauseTime.total!"nsecs");
    readStatus(sample);
    readCgroup(sample);
    return sample;
}

private MemoryNumber durationNumber(long value) nothrow @safe {
    return value < 0 ? unavailable(MemoryAvailability.malformed) : measured(cast(ulong) value);
}

private JSONValue numeric(ref const MemoryNumber number) {
    return number.availability == MemoryAvailability.available ? JSONValue(number.value) : JSONValue(null);
}

private JSONValue queueJson(ref const RuntimeTelemetryCounters queue) {
    if (!queue.available) return JSONValue(null);
    auto json = JSONValue.emptyObject;
    static foreach (name; ["count", "bytes", "droppedCount", "droppedBytes", "maxCount", "maxBytes", "lastExportSuccessAtMs"])
        json[name] = JSONValue(__traits(getMember, queue, name));
    return json;
}

/// Compact schema for stderr and the later dedicated disk worker. No I/O here.
/// Bounded to five <=128-byte network IDs; no nicks, META, messages or paths.
/// Journal/diagnostic data remain null unless a nonblocking mailbox read succeeds.
JSONValue runtimeMemorySampleJson(const ref RuntimeMemorySample sample) {
    auto json = JSONValue.emptyObject;
    json["event"] = JSONValue("memory_sample");
    json["schemaVersion"] = JSONValue(1);
    json["sampledAtMs"] = JSONValue(sample.sampledAtMs);
    json["gcAccounting"] = JSONValue("collection_updated_estimate");
    auto availability = JSONValue.emptyObject;
    static foreach (name; ["gcUsedBytes", "gcFreeBytes", "gcCollections", "gcCollectionNs", "gcPauseNs", "gcMaxCollectionNs", "gcMaxPauseNs",
        "rssBytes", "highWaterBytes", "swapBytes", "threads", "cgroupBytes", "cgroupMaxBytes", "cgroupSwapBytes", "cgroupSwapMaxBytes",
        "cgroupAnonBytes", "cgroupFileBytes", "cgroupKernelBytes", "cgroupSockBytes", "cgroupSlabBytes", "cgroupMaxEvents",
        "cgroupOomEvents", "cgroupOomKillEvents", "cgroupPressureSomeUs", "cgroupPressureFullUs"]) {
        json[name] = numeric(__traits(getMember, sample, name));
        availability[name] = JSONValue(__traits(getMember, sample, name).availability.toString);
    }
    json["availability"] = availability;
    auto owners = JSONValue(null);
    if (sample.ownersAvailable) {
        owners = JSONValue.emptyObject;
        static foreach (i; 0 .. RuntimeOwnerCounters.tupleof.length)
            owners[__traits(identifier, RuntimeOwnerCounters.tupleof[i])] = JSONValue(sample.owners.tupleof[i]);
    }
    json["owners"] = owners;
    JSONValue[] networks;
    foreach (i; 0 .. (sample.largestNetworkCount < 5 ? sample.largestNetworkCount : 5)) {
        auto network = JSONValue.emptyObject;
        network["networkId"] = sample.largestNetworks[i].networkId.length <= 128 ? JSONValue(sample.largestNetworks[i].networkId) : JSONValue(null);
        network["identities"] = JSONValue(sample.largestNetworks[i].identities);
        network["members"] = JSONValue(sample.largestNetworks[i].members);
        networks ~= network;
    }
    json["largestNetworks"] = sample.ownersAvailable ? JSONValue(networks) : JSONValue(null);
    auto queues = JSONValue.emptyObject;
    queues["metrics"] = queueJson(sample.metrics);
    queues["tracing"] = queueJson(sample.tracing);
    queues["logging"] = queueJson(sample.logging);
    json["telemetry"] = queues;
    auto archive = JSONValue(null);
    if (sample.archive.available) {
        archive = JSONValue.emptyObject;
        static foreach (name; ["ready", "failed", "stopping", "replayInFlight",
                "ingressCommands", "ingressBytes", "sampledAtMs", "consumerFibers", "diskThreads"])
            archive[name] = JSONValue(__traits(getMember, sample.archive, name));
        static foreach (name; ["pendingOperations", "pendingBytes", "checkpoint", "durableSequence", "gapCount"])
            archive[name] = sample.archive.ready
                ? JSONValue(__traits(getMember, sample.archive, name)) : JSONValue(null);
        static foreach (name; ["maxBytes", "minFreeBytes", "controlReserveBytes", "stateReserveBytes"])
            archive[name] = JSONValue(__traits(getMember, sample.archive, name));
        archive["diskBytes"] = sample.archive.diskBytesKnown
            ? JSONValue(sample.archive.diskBytes) : JSONValue(null);
        archive["freeBytes"] = sample.archive.freeBytesKnown
            ? JSONValue(sample.archive.freeBytes) : JSONValue(null);
        archive["diskSampledAtMs"] = sample.archive.diskSampledAtMs > 0
            ? JSONValue(sample.archive.diskSampledAtMs) : JSONValue(null);
        archive["maxIngressCommands"] = JSONValue(1_024);
        archive["maxIngressBytes"] = JSONValue(8_388_608);
        archive["maxPendingOperations"] = JSONValue(128);
        archive["maxReplayBytes"] = JSONValue(1_048_576);
    }
    json["archive"] = archive;
    auto diagnostic = JSONValue(null);
    if (sample.diagnosticFile.available) {
        diagnostic = JSONValue.emptyObject;
        static foreach (name; ["pendingBytes", "inFlightBytes", "failures"])
            diagnostic[name] = JSONValue(__traits(getMember, sample.diagnosticFile, name));
        diagnostic["lastWrittenAtMs"] = sample.diagnosticFile.lastWrittenAtMs > 0
            ? JSONValue(sample.diagnosticFile.lastWrittenAtMs) : JSONValue(null);
        diagnostic["lastResult"] = JSONValue(sample.diagnosticFile.lastResult);
        diagnostic["maxPendingBytes"] = JSONValue(8_192);
        diagnostic["maxInFlightBytes"] = JSONValue(8_192);
    }
    json["diagnosticFile"] = diagnostic;
    return json;
}

private string toString(MemoryAvailability availability) {
    final switch (availability) {
        case MemoryAvailability.available: return "available";
        case MemoryAvailability.missing: return "missing";
        case MemoryAvailability.denied: return "denied";
        case MemoryAvailability.malformed: return "malformed";
        case MemoryAvailability.unlimited: return "unlimited";
        case MemoryAvailability.unsupported: return "unsupported";
        case MemoryAvailability.readError: return "read_error";
    }
}

/// Latest compact snapshot producer for a future off-loop disk owner. No writes,
/// no persistent history, and never an empty/zero replacement for unknown data.
string compactRuntimeMemorySample(const ref RuntimeMemorySample sample) {
    return compactRuntimeDiagnosticJson(runtimeMemorySampleJson(sample));
}

/// Shared holder/engine encoder; never truncate a diagnostic into invalid JSON.
string compactRuntimeDiagnosticJson(JSONValue diagnostic) {
    auto text = diagnostic.toString(JSONOptions.doNotEscapeSlashes);
    // All unbounded external text was excluded above. Keep this hard contract
    // if future fields are added: fail visibly instead of truncating JSON.
    if (text.length > 8_192) throw new Exception("memory diagnostic exceeds 8 KiB");
    return text;
}

void logRuntimeMemorySample(const ref RuntimeMemorySample sample, string component) {
    logJsonMap("info", component, "Runtime memory sample", runtimeMemorySampleJson(sample), true);
}
