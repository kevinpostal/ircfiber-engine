/// Native process-sharing and lock-initialization regression gate.
module architecture_test;

import core.thread : Thread;
import std.stdio : writeln;
import ircfiber.irc.host_breaker : recordHostFailure, recordHostSuccess, canConnectToHost;

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
    writeln("architecture process-sharing checks passed");
    return 0;
}
