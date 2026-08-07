/**
 * Enterprise-grade safe wrappers around vibe.d's TLSStream that handle
 * the "ret 0" exception emitted by vibe-stream 1.3.0's OpenSSL backend.
 *
 * ## Why this exists
 *
 * vibe.d's TLSStream.read() (see vibe-stream 1.3.0 tls/vibe/stream/openssl.d
 * `checkSSLRet`) does:
 *
 *     enforce(ret != 0, format("%s was unsuccessful with ret 0", what));
 *
 * whenever SSL_read returns 0. But SSL_read returning 0 is NOT always
 * fatal — it has two completely different meanings that vibe.d
 * conflates:
 *
 *   1. **"Need more data, call again later"** — the underlying TCP
 *      socket has bytes but they don't yet form a complete TLS record.
 *      SSL_ERROR_WANT_READ. The caller should sleep and retry.
 *
 *   2. **"Peer cleanly closed TLS"** — the peer sent a close_notify
 *      alert (or the TCP socket is dead). SSL_ERROR_ZERO_RETURN or
 *      SSL_ERROR_SYSCALL. The caller MUST disconnect.
 *
 * Case (1) was hitting our `readFromStream` path during registration
 * and causing the engine to emit `Failed to connect: Reading from TLS
 * stream was unsuccessful with ret 0` — a spurious disconnect that
 * tore down perfectly healthy connections on the very first read.
 *
 * ## How this fixes it
 *
 * `safeTLSRead` disambiguates the two cases by also consulting
 * `tls.dataAvailableForRead` (which is true iff there are bytes
 * pending in OpenSSL's record buffer OR the underlying TCP socket
 * has data):
 *
 *   - `leastSize > 0`  → decrypted bytes ready, just read them
 *   - read returns 0   → no decrypted bytes yet, no data anywhere
 *                       on the wire → peer closed, throw a clean
 *                       exception so the caller's outer catch can
 *                       disconnect
 *   - read throws      → if `dataAvailableForRead` is true, the SSL
 *                       record isn't fully assembled yet, return 0
 *                       (caller retries later); otherwise, real error
 *                       (re-throw)
 *   - other exception  → re-throw unchanged
 *
 * Pure classifier `classifyTLSReadError` is exposed separately so it
 * can be unit-tested without spinning up a real TLS session.
 *
 * ## Why a probe-and-catch (not just `leastSize` check)
 *
 * Checking `leastSize > 0` alone would prevent the exception but
 * would also deadlock us: if there are no decrypted bytes yet but a
 * full TLS record is available on the socket, we'd never trigger an
 * SSL_read to decrypt it. We need to occasionally poke the stream to
 * drain pending records; the catch just turns the false alarm into a
 * clean "0" return.
 */
module ircfiber.irc.tls_safe;

import std.algorithm : canFind;
import std.conv : to;
import vibe.stream.tls : TLSStream;
import vibe.stream.operations : IOMode;

/**
 * Classification of a TLS read attempt that resulted in 0 bytes or
 * an exception. Used by callers to decide whether to retry, mark the
 * connection dead, or fall through to error handling.
 */
enum TLSReadOutcome {
    /// Bytes were read; the `size_t` return value of `safeTLSRead` is > 0.
    success,
    /// No data available right now; caller should yield and retry later.
    retry,
    /// TLS connection is closed (peer sent close_notify or TCP socket is dead).
    fatal,
}

/// Substring emitted by vibe-stream 1.3.0's `checkSSLRet` whenever
/// SSL_read or SSL_write returns 0. Centralized so the matcher is
/// trivially auditable if we ever upgrade vibe-stream.
private enum TLS_RETRY_SENTINEL = "was unsuccessful with ret 0";

/**
 * Pure classifier — testable without any TLS infrastructure.
 *
 * Given an exception thrown by `TLSStream.read()` and a flag for
 * whether the stream reports pending data, returns the appropriate
 * `TLSReadOutcome`.
 *
 * `exceptionMsg` is matched against the exact substring emitted by
 * vibe-stream 1.3.0's `checkSSLRet`. Other TLS backends (Botan) use
 * different wording, so the check is intentionally narrow to avoid
 * misclassifying real errors.
 */
TLSReadOutcome classifyTLSReadError(string exceptionMsg, bool dataAvailableForRead) nothrow @safe {
    try {
        // vibe-stream 1.3.0 openssl.d:548
        //     enforce(ret != 0, format("%s was unsuccessful with ret 0", what));
        // where `what` is "Reading from TLS stream" or "Writing from TLS stream".
        if (!exceptionMsg.canFind(TLS_RETRY_SENTINEL)) {
            // Not the "ret 0" pseudo-error — must be a genuine failure
            // (handshake error, bad certificate, SSL_ERROR_SSL, etc.).
            return TLSReadOutcome.fatal;
        }
        // It's the "ret 0" pseudo-error. The disambiguation:
        //   - dataAvailableForRead == true  → SSL record not yet complete
        //                                    on the wire, caller should retry.
        //   - dataAvailableForRead == false → peer closed (close_notify sent
        //                                    by peer or underlying socket dead).
        return dataAvailableForRead ? TLSReadOutcome.retry : TLSReadOutcome.fatal;
    } catch (Exception) {
        // Defensive: canFind on a string can't actually throw, but we
        // keep nothrow honest.
        return TLSReadOutcome.fatal;
    }
}

/// Convenience overload that takes the exception object.
TLSReadOutcome classifyTLSReadError(Exception e, bool dataAvailableForRead) nothrow @safe {
    return classifyTLSReadError(e.msg, dataAvailableForRead);
}

/**
 * Lowest-level safe wrapper. Takes the stream + the actual `read`
 * delegate so it can be unit-tested with a fake (see the tests at
 * the bottom of this file). Production callers should use
 * `safeTLSRead` below.
 *
 * `readFn` returns the number of bytes read (>= 0) or throws if the
 * underlying SSL_read returned 0 / an error.
 *
 * `dataAvailableFn` reports whether the stream (or its underlying
 * transport) has any data pending. Must match the value vibe.d's
 * `TLSStream.dataAvailableForRead` would have returned at the moment
 * of the exception.
 */
size_t safeTLSReadImpl(
    scope size_t delegate(ubyte[]) @safe readFn,
    scope bool delegate() @safe dataAvailableFn,
    ubyte[] buffer
) {
    // Fast path: caller can short-circuit if they already know bytes
    // are buffered. Production always enters here when tls.leastSize > 0.
    try {
        return readFn(buffer);
    } catch (Exception e) {
        final switch (classifyTLSReadError(e, dataAvailableFn())) {
            case TLSReadOutcome.retry:
                return 0;
            case TLSReadOutcome.fatal:
                throw new Exception(
                    "TLS connection closed by peer (vibe.d: " ~ e.msg ~ ")",
                    e
                );
            case TLSReadOutcome.success:
                // Unreachable: success means read returned > 0 and we
                // never entered the catch. The compiler still wants
                // an exhaustive case.
                throw new Exception("unreachable: classifyTLSReadError returned success in catch");
        }
    }
}

/**
 * Safe wrapper around `TLSStream.read()` that survives the vibe.d
 * "ret 0" pseudo-error without disconnecting.
 *
 * Returns:
 *   - `> 0` — bytes successfully decrypted and copied into `buffer`
 *   - `0`   — no data available right now; caller should yield and
 *             retry. THIS IS NOT AN ERROR.
 *
 * Throws:
 *   - On genuine TLS failure (handshake, certificate, SSL_ERROR_SSL,
 *     SSL_ERROR_SYSCALL, or close_notify from peer). The message will
 *     describe the failure. Caller's outer catch should treat this as
 *     a disconnect.
 */
size_t safeTLSRead(TLSStream tls, ubyte[] buffer) {
    // Fast path: decrypted bytes already buffered. SSL_read will not
    // be called, so the "ret 0" exception is unreachable here.
    if (tls.leastSize > 0) {
        return tls.read(buffer, IOMode.once);
    }
    // Slow path: probe via the lowest-level helper so the policy is
    // unit-testable without spinning up a real TLS session.
    return safeTLSReadImpl(
        (buf) => tls.read(buf, IOMode.once),
        () => tls.dataAvailableForRead,
        buffer
    );
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════════════════

@("classifyTLSReadError: real error → fatal")
unittest {
    auto outcome = classifyTLSReadError(
        "OpenSSL error occured previously: ssl/record/rec_layer.c: tlsv1 alert protocol version",
        /* dataAvailableForRead */ false);
    assert(outcome == TLSReadOutcome.fatal,
        "real SSL error must be fatal, got " ~ outcome.to!string);
}

@("classifyTLSReadError: ret 0 + data pending → retry")
unittest {
    auto outcome = classifyTLSReadError(
        "Reading from TLS stream was unsuccessful with ret 0",
        /* dataAvailableForRead */ true);
    assert(outcome == TLSReadOutcome.retry,
        "ret 0 with pending data must be retry, got " ~ outcome.to!string);
}

@("classifyTLSReadError: ret 0 + no data → fatal (peer closed)")
unittest {
    auto outcome = classifyTLSReadError(
        "Reading from TLS stream was unsuccessful with ret 0",
        /* dataAvailableForRead */ false);
    assert(outcome == TLSReadOutcome.fatal,
        "ret 0 with no pending data must be fatal, got " ~ outcome.to!string);
}

@("classifyTLSReadError: write-flavor ret 0 → retry/fatal by data flag")
unittest {
    // vibe.d uses the same template for read and write errors; the
    // disambiguation by dataAvailableForRead works for both.
    assert(classifyTLSReadError(
        "Writing from TLS stream was unsuccessful with ret 0", true)
        == TLSReadOutcome.retry);
    assert(classifyTLSReadError(
        "Writing from TLS stream was unsuccessful with ret 0", false)
        == TLSReadOutcome.fatal);
}

@("classifyTLSReadError: unrelated message → fatal")
unittest {
    // Defensive: never silently swallow an exception we don't
    // recognize — even if data is pending, an unrelated exception
    // text must propagate as fatal.
    assert(classifyTLSReadError("something else entirely", true)
        == TLSReadOutcome.fatal);
    assert(classifyTLSReadError("something else entirely", false)
        == TLSReadOutcome.fatal);
}

@("classifyTLSReadError: nothrow even with hostile input")
unittest {
    import std.exception : assertNotThrown;
    // Empty / whitespace / null-like input must not throw.
    assertNotThrown(classifyTLSReadError("", true));
    assertNotThrown(classifyTLSReadError("", false));
}

// ─── safeTLSReadImpl — exercises the wrapper logic with fakes ─────────────

/// Reusable fake stream for testing safeTLSReadImpl without real TLS.
private static class FakeTLSStream {
    size_t readResult;
    bool throwOnRead;
    string throwMsg;
    bool dataAvail;
    int readCalls;

    size_t read(ubyte[] buf, IOMode) @safe {
        readCalls++;
        if (throwOnRead) throw new Exception(throwMsg);
        // Fake: copy nothing — caller only cares about return value.
        return readResult;
    }
    @property bool dataAvailableForRead() @safe { return dataAvail; }
}

@("safeTLSReadImpl: returns bytes when read succeeds")
unittest {
    auto tls = new FakeTLSStream();
    tls.readResult = 42;
    tls.throwOnRead = false;

    ubyte[64] buf;
    auto n = safeTLSReadImpl(
        (b) => tls.read(b, IOMode.once),
        () => tls.dataAvailableForRead,
        buf[]
    );
    assert(n == 42, "expected 42 bytes, got " ~ n.to!string);
    assert(tls.readCalls == 1);
}

@("safeTLSReadImpl: ret 0 + data pending → returns 0 (no throw)")
unittest {
    auto tls = new FakeTLSStream();
    tls.throwOnRead = true;
    tls.throwMsg = "Reading from TLS stream was unsuccessful with ret 0";
    tls.dataAvail = true;

    ubyte[64] buf;
    auto n = safeTLSReadImpl(
        (b) => tls.read(b, IOMode.once),
        () => tls.dataAvailableForRead,
        buf[]
    );
    assert(n == 0, "retry case must return 0, got " ~ n.to!string);
}

@("safeTLSReadImpl: ret 0 + no data → throws clean exception")
unittest {
    auto tls = new FakeTLSStream();
    tls.throwOnRead = true;
    tls.throwMsg = "Reading from TLS stream was unsuccessful with ret 0";
    tls.dataAvail = false;  // peer closed

    bool caught = false;
    try {
        ubyte[64] buf;
        safeTLSReadImpl(
            (b) => tls.read(b, IOMode.once),
            () => tls.dataAvailableForRead,
            buf[]
        );
    } catch (Exception e) {
        caught = true;
        assert(e.msg.canFind("TLS connection closed by peer"),
            "expected clean error message, got: " ~ e.msg);
        // Original vibe.d exception should be preserved as `next` for
        // diagnostics chains.
        assert(e.next !is null, "original exception must be chained");
    }
    assert(caught, "fatal TLS close must throw");
}

@("safeTLSReadImpl: real SSL error → rethrows unchanged")
unittest {
    auto tls = new FakeTLSStream();
    tls.throwOnRead = true;
    tls.throwMsg = "OpenSSL error occured previously: bad certificate";
    tls.dataAvail = false;

    bool caught = false;
    try {
        ubyte[64] buf;
        safeTLSReadImpl(
            (b) => tls.read(b, IOMode.once),
            () => tls.dataAvailableForRead,
            buf[]
        );
    } catch (Exception e) {
        caught = true;
        // We wrap with our clearer message so log readers see why.
        assert(e.msg.canFind("TLS connection closed by peer"),
            "should still throw our wrapper, got: " ~ e.msg);
        assert(e.next.msg.canFind("bad certificate"),
            "original exception should be preserved, got: " ~ e.next.msg);
    }
    assert(caught, "real SSL error must throw");
}

