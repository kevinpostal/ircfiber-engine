module ircfiber.irc.reconnect;

import core.time : Duration, dur;
import std.random : uniform;

/// Exponential backoff with jitter for reconnections.
final class ExponentialBackoff {
    private {
        Duration initialDelay;
        Duration maxDelay;
        int maxAttempts;
        int attempt;
    }

    /// Creates a new exponential backoff strategy.
    this(Duration initialDelay, Duration maxDelay, int maxAttempts = 0) pure nothrow @safe {
        this.initialDelay = initialDelay;
        this.maxDelay = maxDelay;
        this.maxAttempts = maxAttempts;
        this.attempt = 0;
    }

    /// Resets the attempt counter.
    void reset() pure nothrow @safe {
        attempt = 0;
    }

    /// Current attempt number (1-based after the first nextDelay()). Returns 0
    /// before any nextDelay() call.
    int currentAttempt() const pure nothrow @safe {
        return attempt;
    }

    /// Returns the next delay with jitter.
    Duration nextDelay() @safe {
        if (maxAttempts > 0 && attempt >= maxAttempts) {
            return Duration.max;
        }

        attempt++;
        auto base = initialDelay.total!"msecs" * (1L << (attempt - 1));
        const maxMs = maxDelay.total!"msecs";
        if (base > maxMs) {
            base = maxMs;
        }

        // Add ±25% jitter
        auto jitter = cast(long)(base * 0.25);
        auto minDelay = base - jitter;
        auto maxDly = base + jitter;
        auto actual = uniform(minDelay, maxDly + 1);

        return dur!"msecs"(actual);
    }
}
