/// Standalone fast test for ircfiber.irc.pacer (outbound flood pacing).
///
/// Pure code — no IRC server, Redis or Mongo needed:
///   dub build --config=pacer-test --compiler=ldc2 && ./pacer-test
///
/// The module's own `@safe unittest` blocks are the tests; this main just
/// runs them (the shared `unittest` config cannot build in the split repo —
/// its `app_test.d` imports `ircfiber.auth`, which lives in site/backend).
module pacer_test;

import std.stdio : writefln, writeln;

import ircfiber.irc.pacer;

private int failures;

int main() {
    static foreach (unitTest; __traits(getUnitTests, ircfiber.irc.pacer)) {
        try {
            unitTest();
        } catch (Throwable t) {
            failures++;
            writefln("FAIL %s — %s", __traits(identifier, unitTest), t.msg);
        }
    }
    if (failures) {
        writefln("pacer tests: %d FAILED", failures);
        return 1;
    }
    writeln("pacer tests: PASS");
    return 0;
}
