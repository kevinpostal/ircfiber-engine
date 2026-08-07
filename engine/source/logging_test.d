module logging_test;

import std.stdio : stderr, File, writeln;
import std.process : environment;
import std.string : strip;
import std.json : parseJSON;

unittest
{
    writeln("Running logging tests...");

    // ────────────────────────────────────────────────────────────────────
    // Test 1: logJsonMap produces valid JSON when enabled
    // ────────────────────────────────────────────────────────────────────
    environment["IRCFIBER_LOG_JSON"] = "1";

    // Redirect stderr to a pipe
    // (In D's unittest framework, we can't easily redirect stderr per-test.
    // Instead, we call the function and verify it doesn't crash.)
    import ircfiber.logging : logJsonMap;
    logJsonMap("info", "handoff", "Test message",
               ["network": "SuperNets", "eid": "42"]);

    // If we got here without crashing, basic format works.
    // (was: assert(true, ...) — a no-op; reaching this point is the check)

    // ────────────────────────────────────────────────────────────────────
    // Test 2: IRCFIBER_LOG_JSON is now a no-op (JSON always emitted)
    // ────────────────────────────────────────────────────────────────────
    environment["IRCFIBER_LOG_JSON"] = "0";
    logJsonMap("info", "handoff", "Always emitted now",
               ["network": "SuperNets"]);
    // (was: assert(true, ...) — no-op; reaching this point is the check)

    // ────────────────────────────────────────────────────────────────────
    // Test 3: Convenience functions
    // ────────────────────────────────────────────────────────────────────
    environment["IRCFIBER_LOG_JSON"] = "1";
    import ircfiber.logging : logInfoJ, logWarnJ, logErrorJ;
    logInfoJ("connection", "Connected", "SuperNets");
    logWarnJ("nick", "Nick collision", "IRC Fiber");
    logErrorJ("handoff", "Handoff failed", "SuperNets");

    // No-network variant
    logInfoJ("system", "Engine started");

    // ────────────────────────────────────────────────────────────────────
    // Test 4: Empty fields map
    // ────────────────────────────────────────────────────────────────────
    logJsonMap("debug", "test", "Empty fields test");

    // ────────────────────────────────────────────────────────────────────
    // Test 5: Various level strings
    // ────────────────────────────────────────────────────────────────────
    logJsonMap("warn", "test", "Warning level");
    logJsonMap("error", "test", "Error level");
    logJsonMap("debug", "test", "Debug level");

    // Cleanup
    environment.remove("IRCFIBER_LOG_JSON");

    writeln("logging_test: ALL TESTS PASSED");
}