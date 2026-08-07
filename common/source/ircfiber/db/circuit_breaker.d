module ircfiber.db.circuit_breaker;

import std.datetime : Clock, SysTime, Duration;
import std.process : environment;
import std.conv : to;
import vibe.core.log;

/// Circuit breaker for MongoDB connections.
///
/// Prevents retry storms when MongoDB is down. After N consecutive
/// failures, the breaker opens and all subsequent Mongo calls are
/// short-circuited for `coolDownMs` (default 60s). After that, a
/// single test request transitions to half-open — success closes,
/// failure reopens.
final class MongoCircuitBreaker {
    private int failures;
    private SysTime openedAt;
    private int state; // 0=closed, 1=open, 2=half_open
    private long coolDownMs_;

    this() {
        auto raw = environment.get("IRCFIBER_MONGO_CIRCUIT_COOLDOWN_MS", "60000");
        coolDownMs_ = raw.to!long;
    }

    @property long coolDownMs() const { return coolDownMs_; }
    @property int stateCode() const { return state; }
    @property int failuresCount() const { return failures; }
    @property bool isOpen() const { return state == 1; }
    @property bool isClosed() const { return state == 0; }
    @property bool isHalfOpen() const { return state == 2; }

    /// Returns true if the caller should attempt a Mongo request.
    bool allowRequest() {
        if (state == 0) return true;          // closed: allow
        if (state == 1) {                     // open: check if cooled down
            auto elapsed = (Clock.currTime - openedAt).total!"msecs";
            if (elapsed >= coolDownMs_) {
                state = 2;                     // half-open: allow one attempt
                return true;
            }
            return false;
        }
        // half_open: allow exactly one request (the caller will either succeed or fail)
        return true;
    }

    /// Call after a successful Mongo operation.
    void recordSuccess() {
        if (state == 2) {
            logInfo("MongoCircuitBreaker: half-open probe succeeded, closing");
        }
        failures = 0;
        state = 0;   // closed
    }

    /// Call after a Mongo exception. Re-opens on threshold.
    void recordFailure() {
        failures++;
        if (failures >= 5) {       // threshold
            state = 1;             // open
            openedAt = Clock.currTime;
            logWarn("MongoCircuitBreaker OPEN after %d consecutive failures (cooldown=%dms)",
                failures, coolDownMs_);
        } else if (state == 2) {
            logWarn("MongoCircuitBreaker: half-open probe failed (%d/%d), staying open",
                failures, 5);
            state = 1;
            openedAt = Clock.currTime;
        }
    }
}

/// Singleton instance.
private __gshared MongoCircuitBreaker g_mongoBreaker;

/// Initialize the global circuit breaker. Called once from AppMongoConnection.connect().
void initMongoCircuitBreaker() {
    if (g_mongoBreaker is null) {
        g_mongoBreaker = new MongoCircuitBreaker();
        logInfo("MongoCircuitBreaker initialized (cooldown=%dms, threshold=5)",
            g_mongoBreaker.coolDownMs);
    }
}

/// Returns true if the caller should attempt a Mongo request.
/// Fail-open when the breaker hasn't been initialized yet (null) — the
/// early test harness (prefs-test, etc.) runs without a Mongo connection
/// and must not be gated by a Mongo breaker. Returning true here lets
/// Redis-backed prefs work before Mongo is up, while still protecting
/// live Mongo paths once initMongoCircuitBreaker() has run.
bool mongoAllowRequest() {
    return g_mongoBreaker is null || g_mongoBreaker.allowRequest();
}

/// Call after a successful Mongo operation.
void mongoRecordSuccess() {
    if (g_mongoBreaker !is null) g_mongoBreaker.recordSuccess();
}

/// Call after a Mongo exception.
void mongoRecordFailure() {
    if (g_mongoBreaker !is null) g_mongoBreaker.recordFailure();
}

/// Export OTel gauge for the circuit breaker state.
/// Called from the heartbeat flush alongside flushAndSendMetrics().
void exportMongoCircuitMetrics() {
    if (g_mongoBreaker !is null) {
        import ircfiber.observability : recordGauge;
        recordGauge("mongo_circuit_state", g_mongoBreaker.stateCode);
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

@("MongoCircuitBreaker: starts closed and allows requests")
unittest {
    auto cb = new MongoCircuitBreaker();
    assert(cb.isClosed, "breaker must start closed");
    assert(cb.allowRequest(), "closed breaker must allow requests");
    assert(cb.stateCode == 0);
    assert(cb.failuresCount == 0);
}

@("MongoCircuitBreaker: opens after 5 consecutive failures")
unittest {
    auto cb = new MongoCircuitBreaker();
    // 5 failures
    foreach (i; 0 .. 5) {
        assert(cb.allowRequest(), "breaker must allow requests before opening");
        cb.recordFailure();
    }
    assert(cb.isOpen, "breaker must be open after 5 failures");
    assert(!cb.allowRequest(), "open breaker must reject requests");
    assert(cb.stateCode == 1);
}

@("MongoCircuitBreaker: success resets failure count and closes")
unittest {
    auto cb = new MongoCircuitBreaker();
    cb.recordFailure();
    cb.recordFailure();
    assert(cb.failuresCount == 2);
    cb.recordSuccess();
    assert(cb.isClosed, "breaker must close on success");
    assert(cb.failuresCount == 0);
    assert(cb.allowRequest(), "closed breaker must allow requests");
}

@("MongoCircuitBreaker: half-open probe success closes the breaker")
unittest {
    import core.time : msecs;
    auto cb = new MongoCircuitBreaker();
    // Force open with 5 failures
    foreach (i; 0 .. 5) cb.recordFailure();
    assert(cb.isOpen);
    // Artificially set cool down to 0 so half-open activates
    cb.coolDownMs_ = 0;
    assert(cb.allowRequest(), "breaker must enter half-open after cool down");
    assert(cb.isHalfOpen, "breaker must be half-open after expired cool down");
    // Success closes
    cb.recordSuccess();
    assert(cb.isClosed, "breaker must close after half-open success");
    assert(cb.allowRequest(), "closed breaker must allow requests");
}

@("MongoCircuitBreaker: half-open probe failure reopens the breaker")
unittest {
    auto cb = new MongoCircuitBreaker();
    // Force open with 5 failures
    foreach (i; 0 .. 5) cb.recordFailure();
    assert(cb.isOpen);
    // Artificially set cool down to 0
    cb.coolDownMs_ = 0;
    assert(cb.allowRequest(), "breaker must enter half-open after cool down");
    assert(cb.isHalfOpen);
    // Failure reopens
    cb.recordFailure();
    assert(cb.isOpen, "breaker must reopen after half-open failure");
    assert(!cb.allowRequest(), "reopened breaker must reject requests");
    assert(cb.failuresCount == 6, "failure counter must increment");
}

@("MongoCircuitBreaker: singleton helpers work with null breaker (no crash)")
unittest {
    // Before init, requests must succeed (fail-open) so early tests and
    // Redis-backed prefs aren't blocked by an uninitialized Mongo breaker.
    assert(mongoAllowRequest(), "null breaker allowRequest must return true (fail-open)");
    // These must not throw
    mongoRecordSuccess();
    mongoRecordFailure();
}
