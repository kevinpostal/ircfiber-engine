module ircfiber.runtime_diagnostic;

import core.sync.mutex : Mutex;
import core.sync.condition : Condition;
import core.thread : Thread;
import core.time : Duration, MonoTime, seconds;

/// Only encoded immutable bytes cross this boundary, never Json or Vibe objects.
enum size_t runtimeDiagnosticMaxBytes = 8_192;
enum runtimeDiagnosticDefaultPath = "/tmp/ircfiber-runtime-memory.json";
enum DiagnosticAdmission { queued, busy, oversized, stopped }
enum DiagnosticWriteResult { unavailable, written, invalidPath, unsafeFile, openError, writeError, syncError, renameError }

struct DiagnosticStatus {
    ulong accepted, coalesced, written, failures;
    size_t pendingBytes, inFlightBytes;
    long lastWrittenAtMs;
    DiagnosticWriteResult lastResult;
    bool stopping, workerStopped;
}

/// One pending value plus one borrowed value, each <=8 KiB. A later archive
/// worker can own takeLatest/writeLatest/finishWrite itself, without this class
/// creating a second native thread. Never call writeLatest on the event loop.
final class RuntimeDiagnosticMailbox {
    private Mutex mutex;
    private Condition changed;
    private string pending;
    private DiagnosticStatus state;

    this() {
        mutex = new Mutex;
        changed = new Condition(mutex);
    }
    DiagnosticAdmission tryPublish(string encoded) {
        if (!encoded.length || encoded.length > runtimeDiagnosticMaxBytes) return DiagnosticAdmission.oversized;
        if (!mutex.tryLock()) return DiagnosticAdmission.busy;
        scope(exit) mutex.unlock();
        if (state.stopping) return DiagnosticAdmission.stopped;
        if (pending !is null) increment(state.coalesced);
        pending = encoded.idup; // Do not pin an arbitrarily large producer slice.
        state.pendingBytes = encoded.length;
        increment(state.accepted);
        changed.notify();
        return DiagnosticAdmission.queued;
    }
    /// Native owner only. No wait if waitForWork=false. Never lends two values.
    string takeLatest(bool waitForWork = false) {
        mutex.lock();
        scope(exit) mutex.unlock();
        while (waitForWork && pending is null && !state.stopping) changed.wait();
        if (state.inFlightBytes || state.stopping) return null;
        auto value = pending;
        pending = null;
        state.pendingBytes = 0;
        state.inFlightBytes = value.length;
        return value;
    }
    void finishWrite(DiagnosticWriteResult result, long writtenAtMs) {
        mutex.lock();
        scope(exit) mutex.unlock();
        assert(state.inFlightBytes);
        state.inFlightBytes = 0;
        state.lastResult = result;
        if (result == DiagnosticWriteResult.written) {
            increment(state.written);
            state.lastWrittenAtMs = writtenAtMs;
        } else increment(state.failures);
        changed.notifyAll();
    }
    bool tryStatus(out DiagnosticStatus result) {
        if (!mutex.tryLock()) return false;
        scope(exit) mutex.unlock();
        result = state;
        return true;
    }
    void requestStop() {
        mutex.lock();
        scope(exit) mutex.unlock();
        state.stopping = true;
        pending = null;
        state.pendingBytes = 0;
        changed.notifyAll();
    }
    private void stopped() {
        mutex.lock();
        scope(exit) mutex.unlock();
        state.workerStopped = true;
        changed.notifyAll();
    }
    /// Bounded native wait; a stuck filesystem call is never joined or killed.
    bool stop(Duration timeout = 1.seconds) {
        requestStop();
        if (timeout > 1.seconds) timeout = 1.seconds;
        const deadline = MonoTime.currTime + timeout;
        mutex.lock();
        scope(exit) mutex.unlock();
        while (!state.workerStopped) {
            const remaining = deadline - MonoTime.currTime;
            if (remaining <= Duration.zero) return false;
            changed.wait(remaining);
        }
        return true;
    }
}

private void increment(ref ulong value) { if (value != ulong.max) ++value; }

/// Holder-only convenience owner. Engine archive integration uses the mailbox
/// and writeLatest directly. A daemon thread cannot hold shutdown hostage.
final class RuntimeDiagnosticWriter {
    RuntimeDiagnosticMailbox mailbox;
    private Thread worker;
    private string path;
    this(string path = runtimeDiagnosticDefaultPath) {
        this.path = path.idup;
        mailbox = new RuntimeDiagnosticMailbox;
        worker = new Thread(&run);
        worker.isDaemon = true;
        worker.start();
    }
    private void run() {
        scope(exit) mailbox.stopped();
        while (true) {
            auto value = mailbox.takeLatest(true);
            if (value is null) return;
            DiagnosticWriteResult result;
            try result = writeLatest(path, value);
            catch (Exception) { result = DiagnosticWriteResult.writeError; }
            value = null; // Relinquish the borrowed bytes before its reservation.
            import std.datetime : Clock;
            mailbox.finishWrite(result, Clock.currTime.stdTime / 10_000 - 62_135_596_800_000L);
        }
    }
}

/// Native disk-owner API. Exactly two fixed names, <=16 KiB total payload.
/// No exception text, credentials, history files, signals or forced GC.
DiagnosticWriteResult writeLatest(string path, string encoded) {
    if (!encoded.length || encoded.length > runtimeDiagnosticMaxBytes) return DiagnosticWriteResult.writeError;
    version (Posix) return atomicWrite(path, encoded);
    else return DiagnosticWriteResult.unavailable;
}

version (Posix) {
    import core.sys.posix.fcntl : open, O_RDONLY, O_WRONLY, O_CREAT, O_NOFOLLOW, O_NONBLOCK, AT_SYMLINK_NOFOLLOW;
    version (OSX) {
        // Darwin's SDK defines these, but this druntime omits their declarations.
        private enum O_DIRECTORY = 0x00100000;
        private enum O_CLOEXEC = 0x01000000;
    } else import core.sys.posix.fcntl : O_CLOEXEC, O_DIRECTORY;
    import core.sys.posix.unistd : close, write, fsync, ftruncate, geteuid;
    import core.sys.posix.sys.stat : stat_t, fstat, fchmod, S_ISREG;
    // This druntime version does not declare the POSIX.1-2008 *at APIs.
    private extern(C) int openat(int, const(char)*, int, ...) nothrow @nogc;
    private extern(C) int unlinkat(int, const(char)*, int) nothrow @nogc;
    private extern(C) int renameat(int, const(char)*, int, const(char)*) nothrow @nogc;
    private extern(C) int fstatat(int, const(char)*, stat_t*, int) nothrow @nogc;
    import core.stdc.errno : errno, EINTR, ENOENT;
    import std.string : toStringz;

    private bool safeFile(ref stat_t st) { return S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1; }

    // Walk every directory component without following symlinks. The default
    // /tmp is a real directory in the Linux holder; unsupported paths fail shut.
    private int openParent(string path, out string name) {
        if (!path.length || path.length > 4_096 || path[0] != '/' || path[$ - 1] == '/') return -1;
        foreach (c; path) if (c == '\0') return -1;
        int dir = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dir < 0) return -1;
        size_t start = 1;
        foreach (i; 1 .. path.length) {
            if (path[i] != '/') continue;
            auto part = path[start .. i];
            if (!part.length || part == "." || part == "..") { close(dir); return -1; }
            int next = openat(dir, part.toStringz, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            close(dir);
            if (next < 0) return -1;
            dir = next;
            start = i + 1;
        }
        name = path[start .. $];
        if (name == "." || name == ".." || name.length > 240) { close(dir); return -1; }
        return dir;
    }

    // Inject only the POSIX write primitive in unit coverage; all path,
    // ownership, cleanup and atomic-replace operations remain real.
    private alias WriteCall = typeof(&write);
    private DiagnosticWriteResult atomicWrite(string path, string encoded, WriteCall writeCall = &write) {
        string name;
        int dir = openParent(path, name);
        if (dir < 0) return DiagnosticWriteResult.invalidPath;
        scope(exit) close(dir);
        const temporary = name ~ ".tmp";
        stat_t st;
        if (fstatat(dir, name.toStringz, &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (!safeFile(st)) return DiagnosticWriteResult.unsafeFile;
        } else if (errno != ENOENT) return DiagnosticWriteResult.openError;
        int fd = openat(dir, temporary.toStringz, O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 384 /*0600*/);
        if (fd < 0) return DiagnosticWriteResult.openError;
        // Do not truncate a hardlink, foreign file, pipe or symlink. One mailbox
        // has one disk owner; callers must not share a path across disk owners.
        bool owned;
        scope(exit) {
            close(fd); // Never retry close: EINTR may already have closed it.
            if (owned) unlinkat(dir, temporary.toStringz, 0);
        }
        if (fstat(fd, &st) != 0 || !safeFile(st)) return DiagnosticWriteResult.unsafeFile;
        owned = true;
        if (fchmod(fd, 384) != 0 || ftruncate(fd, 0) != 0) return DiagnosticWriteResult.writeError;
        size_t offset;
        while (offset < encoded.length) {
            auto n = writeCall(fd, encoded.ptr + offset, encoded.length - offset);
            if (n < 0) { if (errno == EINTR) continue; return DiagnosticWriteResult.writeError; }
            if (!n || cast(size_t) n > encoded.length - offset) return DiagnosticWriteResult.writeError;
            offset += cast(size_t) n;
        }
        while (fsync(fd) != 0) { if (errno != EINTR) return DiagnosticWriteResult.syncError; }
        if (renameat(dir, temporary.toStringz, dir, name.toStringz) != 0) return DiagnosticWriteResult.renameError;
        owned = false;
        while (fsync(dir) != 0) { if (errno != EINTR) return DiagnosticWriteResult.syncError; }
        return DiagnosticWriteResult.written;
    }
}

unittest {
    auto box = new RuntimeDiagnosticMailbox;
    assert(box.tryPublish("{\"v\":1}") == DiagnosticAdmission.queued);
    auto first = box.takeLatest();
    assert(first == "{\"v\":1}");
    assert(box.tryPublish("{\"v\":2}") == DiagnosticAdmission.queued);
    assert(box.tryPublish("{\"v\":3}") == DiagnosticAdmission.queued);
    assert(box.takeLatest() is null); // No second borrowed allocation.
    DiagnosticStatus status;
    assert(box.tryStatus(status) && status.pendingBytes == 7 && status.inFlightBytes == 7 && status.coalesced == 1);
    first = null;
    box.finishWrite(DiagnosticWriteResult.writeError, 0);
    assert(box.takeLatest() == "{\"v\":3}");
    box.finishWrite(DiagnosticWriteResult.written, 123);
    assert(box.tryPublish(new immutable(char)[8_193]) == DiagnosticAdmission.oversized);
    box.requestStop();
    assert(box.tryPublish("{}") == DiagnosticAdmission.stopped);
    assert(box.tryStatus(status) && status.failures == 1 && status.written == 1 && status.lastWrittenAtMs == 123 && !status.pendingBytes);
    assert(!box.stop(Duration.zero)); // No pretend worker completion.
    box.stopped();
    assert(box.stop(Duration.zero));
    auto closing = new RuntimeDiagnosticMailbox;
    assert(closing.tryPublish("{}") == DiagnosticAdmission.queued);
    auto borrowed = closing.takeLatest();
    closing.requestStop();
    assert(closing.tryStatus(status) && status.inFlightBytes == 2 && !status.pendingBytes);
    borrowed = null;
    closing.finishWrite(DiagnosticWriteResult.writeError, 0);
    assert(closing.tryStatus(status) && !status.inFlightBytes && !status.written);
    // Cross-native-thread contention must reject immediately, not wait.
    auto contended = new RuntimeDiagnosticMailbox;
    DiagnosticAdmission admission;
    contended.mutex.lock();
    auto producer = new Thread({ admission = contended.tryPublish("{}"); });
    producer.start();
    producer.join();
    contended.mutex.unlock();
    assert(admission == DiagnosticAdmission.busy);
}

version (Posix) unittest {
    import std.file : tempDir, mkdir, rmdirRecurse, readText, exists;
    import std.uuid : randomUUID;
    import core.sys.posix.unistd : symlink;
    auto dir = tempDir ~ "/ircfiber-diagnostic-" ~ randomUUID().toString();
    mkdir(dir);
    scope(exit) rmdirRecurse(dir);
    auto path = dir ~ "/sample.json";
    // Linux /tmp path is canonical; macOS tempDir may contain a symlink.
    import core.sys.posix.stdlib : realpath;
    import core.stdc.stdlib : free;
    auto canonical = realpath(dir.toStringz, null);
    assert(canonical !is null);
    scope(exit) free(canonical);
    import std.string : fromStringz;
    path = canonical.fromStringz.idup ~ "/sample.json";
    assert(writeLatest(path, "{\"a\":1}") == DiagnosticWriteResult.written);
    assert(readText(path) == "{\"a\":1}" && !exists(path ~ ".tmp"));
    assert(atomicWrite(path, "{\"a\":2}", &testShortWrite) == DiagnosticWriteResult.written);
    assert(readText(path) == "{\"a\":2}");
    assert(atomicWrite(path, "{\"a\":3}", &testFailedWrite) == DiagnosticWriteResult.writeError);
    assert(readText(path) == "{\"a\":2}" && !exists(path ~ ".tmp"));
    assert(symlink(path.toStringz, (path ~ ".tmp").toStringz) == 0);
    assert(writeLatest(path, "{}") == DiagnosticWriteResult.openError);
    assert(readText(path) == "{\"a\":2}");
    assert(writeLatest(dir ~ "/../bad.json", "{}") == DiagnosticWriteResult.invalidPath);
}

version (Posix) version (unittest) {
    import core.sys.posix.sys.types : ssize_t;
    private extern(C) ssize_t testShortWrite(int fd, scope const void* bytes, size_t length) nothrow @nogc {
        static bool interrupt = true;
        if (interrupt) { interrupt = false; errno = EINTR; return -1; }
        return write(fd, bytes, length > 2 ? 2 : length);
    }
    private extern(C) ssize_t testFailedWrite(int fd, scope const void* bytes, size_t length) nothrow @nogc {
        import core.stdc.errno : EIO;
        errno = EIO;
        return -1;
    }
}
