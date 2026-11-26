/// Native process-sharing and lock-initialization regression gate.
module architecture_test;

import core.thread : Thread;
import std.stdio : writeln;
import ircfiber.irc.host_breaker : recordHostFailure, recordHostSuccess, canConnectToHost, hostCooldownRemaining;
import ircfiber.irc.webirc_suppress : suppressWebircSwapFor, webircSwapSuppressed;
import ircfiber.irc.ipv6_config : configuredIpv6Prefix;
import core.time : Duration;
import std.conv : to;

private Thread webircWorker(string ip) {
    return new Thread({
        foreach (iteration; 0 .. 50) {
            suppressWebircSwapFor("ARCHITECTURE-WEBIRC.TEST", ip);
            assert(webircSwapSuppressed("architecture-webirc.test", ip));
            suppressWebircSwapFor("architecture-expired.test", ip, 0);
            assert(!webircSwapSuppressed("architecture-expired.test", ip));
            // Concurrent first-use initialization and immutable cached reads.
            configuredIpv6Prefix();
        }
    });
}

int main() {
    enum host = "architecture-cross-thread.test";
    recordHostSuccess(host, 6697);
    scope(exit) recordHostSuccess(host, 6697);
    // Each failure arrives from a different OS thread, but every client in the
    // process must observe the same host breaker. Sequential joins isolate the
    // sharing invariant from simultaneous mutation.
    foreach (i; 0 .. 5) {
        auto worker = new Thread({ recordHostFailure(host, 6697); });
        worker.start();
        worker.join();
    }
    assert(!canConnectToHost(host, 6697), "failures from other threads must open the process-wide host breaker");
    assert(hostCooldownRemaining(host, 6697) > Duration.zero);
    assert(canConnectToHost(host, 6667), "host breaker keys include the port");
    auto resetter = new Thread({ recordHostSuccess(host, 6697); });
    resetter.start();
    resetter.join();
    assert(canConnectToHost(host, 6697), "success on another thread resets the shared breaker");

    // The module owns an eagerly initialized lock independent of connection.d
    // and gMullvadLock. Parallel table insert/read/remove must stay consistent.
    Thread[] workers;
    foreach (index; 0 .. 8) {
        const ip = "203.0.113." ~ (index + 1).to!string;
        workers ~= webircWorker(ip);
    }
    foreach (worker; workers) worker.start();
    foreach (worker; workers) worker.join();
    foreach (index; 0 .. 8) {
        const ip = "203.0.113." ~ (index + 1).to!string;
        assert(webircSwapSuppressed("architecture-webirc.test", ip),
            "suppression written on a worker must be visible on the main thread");
        assert(!webircSwapSuppressed("architecture-other.test", ip));
    }
    writeln("architecture process-sharing, concurrent WEBIRC and IPv6 initialization checks passed");
    return 0;
}
