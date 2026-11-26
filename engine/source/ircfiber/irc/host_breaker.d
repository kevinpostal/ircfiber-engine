/// Per-host circuit breaker shared by every PersistentIRCClient in the process.
///
/// After HOST_FAIL_THRESHOLD consecutive failures to the same host:port within
/// HOST_WINDOW_MS the circuit opens. Each re-opening doubles the cooldown
/// (5, 10, 20, 40, 60 min). Any successful connection resets the host.
/// All state is behind one lock; callers never touch the table directly.
module ircfiber.irc.host_breaker;

import core.time : Duration, dur;
import std.conv : to;
import std.datetime : Clock;
import vibe.core.log : logInfo, logWarn;

private struct HostCircuitBreaker {
    int failCount;
    long openedAt;   // 0 = closed
    long lastAttemptAt;
    /// Openings without a success in between; drives escalating cooldown.
    int openCount;
}

private __gshared HostCircuitBreaker[string] gBreakers;
private __gshared Object gLock;

shared static this() { gLock = new Object(); }

package enum long HOST_WINDOW_MS       = 30 * 60 * 1000;
package enum int  HOST_FAIL_THRESHOLD  = 5;
package enum long HOST_COOLDOWN_MS     = 5 * 60 * 1000;
package enum long HOST_COOLDOWN_MAX_MS = 60 * 60 * 1000;

/// Cooldown for the Nth opening of a host breaker.
long hostCooldownMs(int openCount) @safe pure nothrow @nogc {
    long ms = HOST_COOLDOWN_MS;
    foreach (i; 1 .. openCount) {
        ms *= 2;
        if (ms >= HOST_COOLDOWN_MAX_MS) return HOST_COOLDOWN_MAX_MS;
    }
    return ms;
}

private string key(string host, int port) { return host ~ ":" ~ port.to!string; }
private long nowMs() { return Clock.currTime.toUnixTime!long * 1000; }

/// Record a connection failure to a host.
void recordHostFailure(string host, int port) {
    const k = key(host, port);
    const now = nowMs();
    synchronized (gLock) {
        auto b = k in gBreakers;
        if (b is null) {
            gBreakers[k] = HostCircuitBreaker(1, 0, now, 0);
            return;
        }
        if (now - b.lastAttemptAt > HOST_WINDOW_MS) {
            b.failCount = 0;
            b.openedAt = 0;
            b.openCount = 0;
        }
        b.failCount++;
        b.lastAttemptAt = now;
        if (b.failCount >= HOST_FAIL_THRESHOLD && b.openedAt == 0) {
            b.openedAt = now;
            b.openCount++;
            logWarn("Host circuit breaker OPENED for %s after %d failures (opening #%d, cooling down %d ms)",
                k, b.failCount, b.openCount, hostCooldownMs(b.openCount));
        }
    }
}

/// Record a successful connection; resets the breaker for this host.
void recordHostSuccess(string host, int port) {
    const k = key(host, port);
    synchronized (gLock) {
        if (k in gBreakers) {
            gBreakers.remove(k);
            logInfo("Host circuit breaker CLOSED for %s (connection succeeded)", k);
        }
    }
}

/// False while the circuit is open and still cooling down.
bool canConnectToHost(string host, int port) {
    const k = key(host, port);
    synchronized (gLock) {
        if (auto b = k in gBreakers) {
            if (b.openedAt > 0) {
                if (nowMs() - b.openedAt < hostCooldownMs(b.openCount)) return false;
                gBreakers.remove(k);
                logInfo("Host circuit breaker CLOSED for %s (cooldown expired)", k);
            }
        }
    }
    return true;
}

/// Remaining cooldown for an open breaker, or Duration.zero. When the
/// cooldown has elapsed the breaker goes half-open: attempts are allowed
/// again but openCount is kept so the next opening cools down longer.
Duration hostCooldownRemaining(string host, int port) {
    const k = key(host, port);
    synchronized (gLock) {
        if (auto b = k in gBreakers) {
            if (b.openedAt > 0) {
                const elapsed = nowMs() - b.openedAt;
                const cooldown = hostCooldownMs(b.openCount);
                if (elapsed < cooldown) return dur!"msecs"(cooldown - elapsed);
                b.openedAt = 0;
                b.failCount = 0;
                logInfo("Host circuit breaker reset for %s (cooldown expired, opened %d\u00d7 so far)",
                    k, b.openCount);
            }
        }
    }
    return Duration.zero;
}

unittest {
    assert(hostCooldownMs(1) == HOST_COOLDOWN_MS);
    assert(hostCooldownMs(2) == 2 * HOST_COOLDOWN_MS);
    assert(hostCooldownMs(10) == HOST_COOLDOWN_MAX_MS);
    enum h = "breaker.test";
    foreach (i; 0 .. HOST_FAIL_THRESHOLD - 1) recordHostFailure(h, 1);
    assert(canConnectToHost(h, 1));
    recordHostFailure(h, 1);
    assert(!canConnectToHost(h, 1));
    assert(hostCooldownRemaining(h, 1) > Duration.zero);
    recordHostSuccess(h, 1);
    assert(canConnectToHost(h, 1));
    assert(hostCooldownRemaining(h, 1) == Duration.zero);
}
