module ircfiber.db.history_policy_model;

import std.algorithm.comparison : max;
import std.exception : enforce;

enum NORMAL_DAYS = 14;
enum long NORMAL_BYTES = 16_777_216;
enum long NORMAL_WINDOW_MS = NORMAL_DAYS * 86_400_000L;

/// All cutoffs are inclusive UTC epoch milliseconds. Only acknowledged cuts
/// belong in expiredThroughMs; never advance it speculatively in a reader.
struct HistoryPolicy {
    string ownerId;
    bool manualPro;
    bool donorPro;
    long revision;
    long noticeAtMs;
    long normalFromMs;
    long expiredThroughMs;
    long legacyPublicThroughMs;

    bool pro() const pure nothrow @safe { return manualPro || donorPro; }
    bool due(long nowMs) const pure nothrow @safe {
        return normalFromMs != 0 && nowMs >= normalFromMs;
    }

    long visibleFloor(long nowMs, bool direct) const {
        enforce(nowMs > 0 && !due(nowMs), "History cut pending or clock unavailable");
        const floor = max(expiredThroughMs, direct ? 0L : legacyPublicThroughMs);
        return !pro && normalFromMs == 0 ? max(floor, nowMs - NORMAL_WINDOW_MS) : floor;
    }

    /// A grant arriving after a grace deadline must include the result of a
    /// complete Normal byte walk from this exact snapshot in the same CAS.
    HistoryPolicy withGrants(bool manual, bool donor, long nowMs, long dueCutThroughMs = -1) const {
        enforce(nowMs > 0 && nowMs <= long.max - NORMAL_WINDOW_MS, "Invalid policy clock");
        HistoryPolicy next = this;
        if (manualPro == manual && donorPro == donor) return next;
        enforce(revision < long.max, "History grant revision exhausted");
        next.manualPro = manual;
        next.donorPro = donor;
        ++next.revision;
        if (next.pro == pro) return next;
        if (pro) {
            next.noticeAtMs = nowMs;
            next.normalFromMs = nowMs + NORMAL_WINDOW_MS;
        } else {
            if (due(nowMs)) {
                enforce(dueCutThroughMs >= max(expiredThroughMs, nowMs - NORMAL_WINDOW_MS),
                    "Promotion requires completed history cut");
                next.expiredThroughMs = dueCutThroughMs;
            } else if (normalFromMs == 0) {
                next.expiredThroughMs = max(expiredThroughMs, nowMs - NORMAL_WINDOW_MS);
            }
            next.noticeAtMs = next.normalFromMs = 0;
        }
        return next;
    }
}

unittest {
    import std.exception : assertThrown;
    enum now = NORMAL_WINDOW_MS * 10;
    auto normal = HistoryPolicy("account");
    auto pro = normal.withGrants(false, true, now);
    assert(pro.expiredThroughMs == now - NORMAL_WINDOW_MS);
    auto both = pro.withGrants(true, true, now + 1);
    auto manual = both.withGrants(true, false, now + 2);
    assert(manual.normalFromMs == 0 && manual.expiredThroughMs == pro.expiredThroughMs);
    auto grace = manual.withGrants(false, false, now + 3);
    auto deadline = grace.normalFromMs;
    assert(deadline == now + 3 + NORMAL_WINDOW_MS && grace.noticeAtMs == now + 3);
    assert(grace.withGrants(false, false, deadline) == grace);
    assert(grace.visibleFloor(deadline - 1, true) == pro.expiredThroughMs);
    assertThrown(grace.visibleFloor(deadline, true));
    assertThrown(grace.withGrants(true, false, deadline));
    assert(grace.withGrants(false, true, deadline - 1).expiredThroughMs == pro.expiredThroughMs);
    auto restored = grace.withGrants(false, true, deadline, now + 17);
    assert(restored.visibleFloor(deadline + NORMAL_WINDOW_MS, true) == now + 17);
    restored.legacyPublicThroughMs = now + 20;
    assert(restored.visibleFloor(deadline, false) == now + 20);
    assert(restored.visibleFloor(deadline, true) == now + 17);
}
