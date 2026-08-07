module ircfiber.engine.adopted_socket;

import std.conv : to;
import std.datetime : Clock;
import core.stdc.errno : errno;
import core.sys.posix.poll : pollfd, POLLIN, POLLOUT, poll;
import core.sys.posix.unistd : close_unix = close, read_unix = read, write_unix = write;
import core.sys.posix.sys.socket : SO_ERROR, getsockopt, socketpair, AF_UNIX, SOCK_STREAM;
import core.sys.posix.sys.time : timeval;
import core.time : Duration, seconds, msecs;
import core.thread : Thread;

// POSIX close, exported under a unique name to avoid clashing with
// AdoptedSocket.close() / Closeable.close() in std.stream.
alias posixClose = close_unix;

/**
 * Thin wrapper around an adopted raw socket fd, exposing the subset
 * of vibe.d's `TCPConnection` API used by `PersistentIRCClient`.
 *
 * We can't use `TCPConnection(fd)` because vibe.d only exposes a
 * `private` constructor for wrapping a fd — and we need to take over
 * an already-open IRC socket that was transferred via SCM_RIGHTS.
 *
 * Behavioural differences from `TCPConnection`:
 * - `read(buf, IOMode.once)` returns 0 on EAGAIN/EWOULDBLOCK instead
 *   of blocking. This matches the caller's expectation of
 *   non-blocking I/O on the event-loop fiber.
 * - `waitForData(0.seconds)` uses `poll(POLLIN)` with a 0-ms timeout
 *   so the caller can spin without burning CPU.
 * - No TLS support — the adopted socket must be plain TCP. TLS
 *   handoff is handled by soft-reconnect in the manager.
 */
final class AdoptedSocket {
    private int m_fd;
    private bool m_closed;

    this(int fd) {
        m_fd = fd;
    }

    ~this() {
        if (!m_closed && m_fd >= 0) {
            try posixClose(m_fd);
            catch (Exception) {}
            m_closed = true;
        }
    }

    /// Underlying file descriptor. -1 after close().
    @property int fd() const { return m_closed ? -1 : m_fd; }

    /// True iff the socket is open. We can't cheaply detect remote
    /// close (would require a poll() call), so callers should treat
    /// `read() == 0` as EOF.
    @property bool connected() const { return !m_closed && m_fd >= 0; }

    /// Wait up to `timeout` for the socket to have data ready.
    /// Returns true iff data is available (or EOF).
    bool waitForData(Duration timeout) {
        if (!connected) return false;
        if (timeout.total!"msecs" <= 0) {
            pollfd[1] pfd = [pollfd(m_fd, POLLIN, 0)];
            return poll(pfd.ptr, 1, 0) > 0;
        }
        auto ms = timeout.total!"msecs";
        if (ms > int.max) ms = int.max;
        pollfd[1] pfd = [pollfd(m_fd, POLLIN, 0)];
        return poll(pfd.ptr, 1, cast(int) ms) > 0;
    }

    /// Read up to `buf.length` bytes. Returns the number read (0 ==
    /// no data available right now; on a clean close from the peer
    /// the caller will get 0 *and* `connected` will become false on
    /// the next poll cycle).
    size_t read(ubyte[] buf) {
        if (!connected) return 0;
        auto n = .read_unix(m_fd, buf.ptr, buf.length);
        if (n < 0) {
            if (errno == 11 /* EAGAIN */ || errno == 35 /* EWOULDBLOCK */) return 0;
            if (errno == 4 /* EINTR */) return 0;
            // Connection reset or other fatal error — mark closed.
            m_closed = true;
            return 0;
        }
        if (n == 0) {
            // EOF — peer closed.
            m_closed = true;
        }
        return cast(size_t) n;
    }

    /// Write bytes to the socket. Returns false on error; the caller
    /// should treat false as "give up on this connection".
    bool write(scope const(ubyte)[] data) {
        if (!connected) return false;
        size_t written = 0;
        while (written < data.length) {
            auto n = .write_unix(m_fd, data.ptr + written, data.length - written);
            if (n < 0) {
                if (errno == 4) continue;
                if (errno == 11 || errno == 35) {
                    // Would block — the caller (writeRaw) only invokes
                    // us when the connection is presumably writable,
                    // so this is rare. Spin briefly.
                    Thread.sleep(5.msecs);
                    continue;
                }
                m_closed = true;
                return false;
            }
            written += n;
        }
        return true;
    }

    /// Flush is a no-op for a non-streaming POSIX socket — writes
    /// land in the kernel buffer immediately. Provided for API
    /// parity with `TCPConnection`.
    void flush() {}

    /// Close the socket. Idempotent.
    void close() {
        if (!m_closed && m_fd >= 0) {
            posixClose(m_fd);
            m_fd = -1;
        }
        m_closed = true;
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

// AdoptedSocket does not depend on vibe.d fibers — these tests use
// raw POSIX socketpair(2) and are safe to run in any context.

@("AdoptedSocket write/read roundtrip")
unittest {
    import core.sys.posix.sys.socket : socketpair;
    import core.sys.posix.unistd : write;
    int[2] fds;
    auto rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(rc == 0, "socketpair failed");

    auto sock = new AdoptedSocket(fds[0]);
    scope(exit) sock.close();
    scope(exit) posixClose(fds[1]);

    // Write through the raw fd
    string msg = "PING :keepalive";
    auto n = write(fds[1], msg.ptr, msg.length);
    assert(n == cast(ptrdiff_t) msg.length, "write failed");

    // Read through AdoptedSocket
    ubyte[64] buf;
    auto got = sock.read(buf[]);
    assert(got == msg.length, "read returned wrong length: " ~ got.to!string);
    assert(buf[0 .. got] == cast(ubyte[])msg, "read wrong data");
}

@("AdoptedSocket waitForData detects data")
unittest {
    import core.sys.posix.sys.socket : socketpair;
    import core.sys.posix.unistd : write;
    import core.time : Duration;
    int[2] fds;
    auto rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(rc == 0);

    auto sock = new AdoptedSocket(fds[0]);
    scope(exit) sock.close();
    scope(exit) posixClose(fds[1]);

    // No data yet — waitForData with 0 timeout should return false
    assert(!sock.waitForData(Duration.zero), "false positive on empty socket");

    // Write data
    ubyte[1] one = [42];
    write(fds[1], one.ptr, 1);

    // Now data should be available
    assert(sock.waitForData(Duration.zero), "missed available data");
}

@("AdoptedSocket close marks closed")
unittest {
    import core.sys.posix.sys.socket : socketpair;
    int[2] fds;
    auto rc = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
    assert(rc == 0);

    auto sock = new AdoptedSocket(fds[0]);
    assert(sock.connected, "should be connected after creation");
    assert(sock.fd >= 0, "fd should be valid");

    sock.close();
    assert(!sock.connected, "should not be connected after close");
    assert(sock.fd == -1, "fd should be -1 after close");

    // Second close is idempotent
    sock.close();
    assert(!sock.connected, "still not connected after idempotent close");

    posixClose(fds[1]);
}
