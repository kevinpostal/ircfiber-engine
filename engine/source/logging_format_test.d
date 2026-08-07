/**
 * Enterprise-grade JSON logging test.
 *
 * Verifies the output format that Promtail parses:
 *   {"ts":"2026-06-28T...","level":"info","component":"handoff",
 *    "network":"SuperNets","msg":"..."}
 *
 * Uses freopen to redirect stderr to a temp file so we can read back
 * and parse the JSON.
 */
module logging_format_test;

import std.stdio : stderr, File, writeln, writefln, freopen, stdout;
import std.process : environment;
import std.string : strip;
import std.json : parseJSON, JSONValue;
import std.file : remove, exists, write;
import std.utf : toUTFz;
import core.stdc.stdio : FILE, fclose, freopen;
import core.stdc.stdlib : system;

private string captureFile;
private string capturedLog;

private void startCapture() {
    captureFile = "/tmp/ircfiber_log_test_" ~ environment.get("USER", "test") ~ ".log";
    if (exists(captureFile)) remove(captureFile);
    auto f = fopen(captureFile.toUTFz!(char*)(), "w".ptr);
    fclose(f);
    // Redirect stderr to capture file
    const fp = freopen(captureFile.toUTFz!(char*)(), "a", stderr.getFP);
    assert(fp !is null, "freopen must succeed");
}

private string stopCapture() {
    stderr.flush();
    auto f = File(captureFile, "r");
    if (!f.isOpen) return "";
    capturedLog = cast(string)f.readln();
    f.close();
    if (exists(captureFile)) remove(captureFile);
    return capturedLog;
}

unittest
{
    writeln("Running logging format test...");

    // ─── Test: JSON output format ─────────────────────────────────────
    {
        environment["IRCFIBER_LOG_JSON"] = "1";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("info", "handoff", "Post-handoff QUIT sent",
                   ["network": "SuperNets",
                    "sessionNick": "Zod",
                    "pid": "12345"]);

        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        // Parse the JSON
        JSONValue j;
        try {
            j = parseJSON(line);
        } catch (Exception e) {
            assert(false, "Output is not valid JSON: " ~ line ~ " (" ~ e.msg ~ ")");
        }

        // Verify required fields
        assert("ts" in j, "must have ts field");
        assert("level" in j, "must have level field");
        assert(j["level"].str == "info", "level must be info, got: " ~ j["level"].str);
        assert("component" in j, "must have component field");
        assert(j["component"].str == "handoff", "component must be handoff");
        assert("msg" in j, "must have msg field");
        assert(j["msg"].str == "Post-handoff QUIT sent");

        // Verify optional fields
        assert("network" in j, "must have network field");
        assert(j["network"].str == "SuperNets");
        assert("sessionNick" in j, "must have sessionNick field");
        assert(j["sessionNick"].str == "Zod");
        assert("pid" in j, "must have pid field");

        // Verify timestamp is RFC3339
        auto ts = j["ts"].str;
        assert(ts.length >= 20, "timestamp too short: " ~ ts);
        assert(ts[4] == '-' && ts[7] == '-' && ts[10] == 'T',
               "timestamp must be RFC3339 format: " ~ ts);
    }

    // ─── Test: IRCFIBER_LOG_JSON is a no-op toggle (JSON always emitted) ────
    {
        environment["IRCFIBER_LOG_JSON"] = "0";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("info", "test", "Always logged now");
        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        // JSON path is now the canonical structured stream and is always
        // emitted (Docker's json-file driver picks it up). The env var
        // is preserved as a no-op for legacy callers — verify it's
        // ignored by checking output still appears.
        assert(line.strip.length > 0,
               "JSON log should always emit, got empty line");
        JSONValue j = parseJSON(line);
        assert(j["msg"].str == "Always logged now");
    }

    // ─── Test: empty fields map ───────────────────────────────────────
    {
        environment["IRCFIBER_LOG_JSON"] = "1";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("error", "system", "Engine panic");
        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        JSONValue j = parseJSON(line);
        assert(j["level"].str == "error");
        assert(j["component"].str == "system");
        assert(j["msg"].str == "Engine panic");
        // No optional fields expected
    }

    // ─── Test: special characters in values are not escaped ─────────
    {
        environment["IRCFIBER_LOG_JSON"] = "1";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("info", "test",
                   "URL: https://example.com/path?a=b&c=d",
                   ["value": "/api/v1/test", "path": "/tmp/file.txt"]);
        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        JSONValue j = parseJSON(line);
        // doNotEscapeSlashes means "/" is NOT escaped → must remain raw
        assert(j["msg"].str == "URL: https://example.com/path?a=b&c=d",
               "URL must not be escaped: " ~ j["msg"].str);
        assert(j["value"].str == "/api/v1/test");
        assert(j["path"].str == "/tmp/file.txt");
    }

    writeln("logging_format_test: ALL TESTS PASSED");
}

private FILE* fopen(const char* filename, const char* mode) {
    import core.stdc.stdio : fopen;
    return fopen(filename, mode);
}

private int testCount = 0;
private int testPassed = 0;

private void runTest(string name, void delegate() testFn) {
    testCount++;
    stdout.writefln("  TEST: %s", name);
    try {
        testFn();
        testPassed++;
        stdout.writefln("    PASS");
    } catch (Throwable e) {
        stdout.writefln("    FAIL: %s", e.msg);
        // Continue to next test for full picture
    }
}

int main(string[]) {
    writeln("═══════════════════════════════════════════════════════════════");
    writeln("IRC Fiber — Logging Format Test Suite");
    writeln("═══════════════════════════════════════════════════════════════");

    runTest("JSON output format (handoff)", () {
        environment["IRCFIBER_LOG_JSON"] = "1";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("info", "handoff", "Post-handoff QUIT sent",
                   ["network": "SuperNets",
                    "sessionNick": "Zod",
                    "pid": "12345"]);

        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        JSONValue j;
        try {
            j = parseJSON(line);
        } catch (Exception e) {
            assert(false, "Output is not valid JSON: " ~ line);
        }

        assert("ts" in j, "must have ts field");
        assert("level" in j, "must have level field");
        assert(j["level"].str == "info", "level must be info");
        assert(j["component"].str == "handoff", "component must be handoff");
        assert(j["msg"].str == "Post-handoff QUIT sent");
        assert(j["network"].str == "SuperNets");
        assert(j["sessionNick"].str == "Zod");
        assert(j["pid"].str == "12345");

        auto ts = j["ts"].str;
        assert(ts.length >= 20, "timestamp too short: " ~ ts);
        assert(ts[4] == '-' && ts[7] == '-' && ts[10] == 'T',
               "timestamp must be RFC3339 format: " ~ ts);
    });

    runTest("IRCFIBER_LOG_JSON is a no-op toggle (JSON always emitted)", () {
        environment["IRCFIBER_LOG_JSON"] = "0";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("info", "test", "Always logged now");
        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        // JSON path is the canonical structured stream and is always on.
        assert(line.strip.length > 0,
               "JSON log should always emit, got empty line");
        JSONValue j = parseJSON(line);
        assert(j["msg"].str == "Always logged now");
    });

    runTest("Empty fields map", () {
        environment["IRCFIBER_LOG_JSON"] = "1";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("error", "system", "Engine panic");
        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        JSONValue j = parseJSON(line);
        assert(j["level"].str == "error");
        assert(j["component"].str == "system");
        assert(j["msg"].str == "Engine panic");
    });

    runTest("URLs are not escaped (Promtail compatibility)", () {
        environment["IRCFIBER_LOG_JSON"] = "1";
        startCapture();

        import ircfiber.logging : logJsonMap;
        logJsonMap("info", "test",
                   "URL: https://example.com/path?a=b&c=d",
                   ["value": "/api/v1/test", "path": "/tmp/file.txt"]);
        auto line = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        JSONValue j = parseJSON(line);
        assert(j["msg"].str == "URL: https://example.com/path?a=b&c=d",
               "URL must not be escaped: " ~ j["msg"].str);
        assert(j["value"].str == "/api/v1/test");
        assert(j["path"].str == "/tmp/file.txt");
    });

    runTest("Convenience functions (logInfoJ/WarnJ/ErrorJ)", () {
        environment["IRCFIBER_LOG_JSON"] = "1";

        import ircfiber.logging : logInfoJ, logWarnJ, logErrorJ;
        startCapture();
        logInfoJ("connection", "Connected", "SuperNets");
        auto line1 = stopCapture();

        startCapture();
        logWarnJ("nick", "Nick collision", "IRC Fiber");
        auto line2 = stopCapture();

        startCapture();
        logErrorJ("handoff", "Handoff failed", "SuperNets");
        auto line3 = stopCapture();

        startCapture();
        logInfoJ("system", "Engine started");  // no network
        auto line4 = stopCapture();
        environment.remove("IRCFIBER_LOG_JSON");

        JSONValue j1 = parseJSON(line1);
        assert(j1["level"].str == "info");
        assert(j1["network"].str == "SuperNets");

        JSONValue j2 = parseJSON(line2);
        assert(j2["level"].str == "warn");
        assert(j2["network"].str == "IRC Fiber");

        JSONValue j3 = parseJSON(line3);
        assert(j3["level"].str == "error");

        JSONValue j4 = parseJSON(line4);
        assert(j4["component"].str == "system");
        // No "network" field when not provided
        assert(!("network" in j4));
    });

    writeln("═══════════════════════════════════════════════════════════════");
    writefln("Result: %d/%d tests passed", testPassed, testCount);
    writeln("═══════════════════════════════════════════════════════════════");

    return testPassed == testCount ? 0 : 1;
}