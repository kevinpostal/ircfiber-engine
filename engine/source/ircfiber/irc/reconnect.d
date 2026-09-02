module ircfiber.irc.reconnect;

import core.time : Duration, dur, hours, minutes, seconds, days, msecs;
import std.random : uniform;
import std.datetime : Clock, SysTime;

/// Exponential backoff with jitter for reconnections.
///
/// The delay cap escalates with the length of the failure streak so a host
/// that is down for good (e.g. irc.hybridirc.net refusing every attempt for
/// days) is probed a few times a day instead of every minute, while a
/// transient drop still reconnects within seconds:
///
///   attempt  1–8   cap  1 min   (≈ first 8 min)
///   attempt  9–14  cap  5 min   (≈ next 30 min)
///   attempt 15–20  cap 15 min   (≈ next 1.5 h)
///   attempt 21–30  cap  1 h     (≈ next 10 h)
///   attempt 31+    cap  6 h
///
/// After `giveUpAfter` of uninterrupted failure `nextDelay()` returns
/// `Duration.max`: the caller parks the network until a manual reconnect.
final class ExponentialBackoff {
    private {
        Duration initialDelay;
        Duration maxDelay;
        int maxAttempts;
        int attempt;
        Duration giveUpAfter;
        long streakStartMs;
    }

    /// Tiered caps applied on top of `maxDelay` once the streak grows.
    private static immutable Duration[] TIER_CAPS = [
        1.minutes, 5.minutes, 15.minutes, 1.hours, 6.hours,
    ];

    /// Attempt numbers at which each tier begins (1-based, ascending).
    private static immutable int[] TIER_STARTS = [1, 9, 15, 21, 31];

    /// Creates a new exponential backoff strategy.
    ///
    /// `maxDelay` bounds the first tier; later tiers use their own caps.
    /// `maxAttempts` 0 = unlimited. `giveUpAfter` Duration.zero = never.
    this(Duration initialDelay, Duration maxDelay, int maxAttempts = 0,
         Duration giveUpAfter = 7.days) pure nothrow @safe {
        this.initialDelay = initialDelay;
        this.maxDelay = maxDelay;
        this.maxAttempts = maxAttempts;
        this.giveUpAfter = giveUpAfter;
        this.attempt = 0;
    }

    /// Resets the attempt counter and the failure streak.
    void reset() pure nothrow @safe {
        attempt = 0;
        streakStartMs = 0;
    }

    /// Current attempt number (1-based after the first nextDelay()). Returns 0
    /// before any nextDelay() call.
    int currentAttempt() const pure nothrow @safe {
        return attempt;
    }

    /// How long the current failure streak has lasted (zero when idle).
    Duration failingFor() const @safe {
        if (streakStartMs == 0) return Duration.zero;
        return dur!"msecs"(nowMs() - streakStartMs);
    }

    /// Delay cap for a given attempt number.
    static Duration capFor(int attempt, Duration firstTierCap) pure nothrow @safe {
        Duration cap = firstTierCap;
        foreach (i, start; TIER_STARTS) {
            if (attempt >= start) cap = i == 0 ? firstTierCap : TIER_CAPS[i];
        }
        return cap;
    }

    /// True once the streak has exhausted its budget; `nextDelay()` then
    /// returns `Duration.max`.
    bool exhausted() const @safe {
        if (maxAttempts > 0 && attempt >= maxAttempts) return true;
        if (giveUpAfter > Duration.zero && streakStartMs != 0 && failingFor() >= giveUpAfter) return true;
        return false;
    }

    /// Returns the next delay with jitter, or `Duration.max` when the
    /// streak's budget is exhausted.
    Duration nextDelay() @safe {
        if (streakStartMs == 0) streakStartMs = nowMs();
        if (exhausted()) return Duration.max;

        attempt++;
        const cap = capFor(attempt, maxDelay);
        const maxMs = cap.total!"msecs";
        // 1L << 62 would overflow for absurd attempt counts; clamp the shift.
        const shift = attempt - 1 > 40 ? 40 : attempt - 1;
        long base = initialDelay.total!"msecs" * (1L << shift);
        if (base > maxMs || base < 0) base = maxMs;

        // Add ±25% jitter
        auto jitter = cast(long)(base * 0.25);
        auto minDelay = base - jitter;
        auto maxDly = base + jitter;
        auto actual = uniform(minDelay, maxDly + 1);

        return dur!"msecs"(actual);
    }

    private static long nowMs() @trusted {
        return (Clock.currTime - SysTime.fromUnixTime(0)).total!"msecs";
    }
}

@safe unittest {
    auto b = new ExponentialBackoff(3.seconds, 60.seconds);
    // First tier is capped by maxDelay.
    foreach (i; 0 .. 8) assert(b.nextDelay() <= 75.seconds);
    assert(b.currentAttempt() == 8);
    // Tier 2: 5 min cap (+25% jitter).
    auto d9 = b.nextDelay();
    assert(d9 > 60.seconds && d9 <= 375.seconds, "tier 2 cap");
    foreach (i; 0 .. 5) b.nextDelay();
    auto d15 = b.nextDelay();
    assert(d15 > 5.minutes && d15 <= 1125.seconds, "tier 3 cap");
    foreach (i; 0 .. 5) b.nextDelay();
    auto d21 = b.nextDelay();
    assert(d21 > 15.minutes && d21 <= 75.minutes, "tier 4 cap");
    foreach (i; 0 .. 9) b.nextDelay();
    auto d31 = b.nextDelay();
    assert(d31 > 1.hours && d31 <= 450.minutes, "tier 5 cap");
    assert(!b.exhausted());
    b.reset();
    assert(b.currentAttempt() == 0 && b.failingFor() == Duration.zero);

    auto capped = new ExponentialBackoff(3.seconds, 60.seconds, 2);
    capped.nextDelay(); capped.nextDelay();
    assert(capped.exhausted());
    assert(capped.nextDelay() == Duration.max);

    auto instant = new ExponentialBackoff(3.seconds, 60.seconds, 0, 1.msecs);
    instant.nextDelay();
    // Streak started at the first call; a 1 ms budget is exhausted by now
    // or on the next tick.
    import core.thread : Thread;
    () @trusted { Thread.sleep(2.msecs); } ();
    assert(instant.nextDelay() == Duration.max);
}
