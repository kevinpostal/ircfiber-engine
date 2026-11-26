/// Native compatibility gate for the canonical common startup contract.
module startup_test;

import std.process : environment, execute;
import std.file : thisExePath;
import std.stdio : writeln;
import ircfiber.engine.startup : configureEngineReporting, runEngineProcess;
import ircfiber.errors : configureErrorReporting, isErrorReportingEnabled;
import ircfiber.holder_client : HolderStartupException;

int main(string[] args) {
    if (args.length == 2) {
        if (environment.get("IRCFIBER_STARTUP_TEST_REPORT", "") == "1")
            configureEngineReporting("ircfiber-engine", "test");
        else
            configureErrorReporting(false, "", "ircfiber-engine", "test", "test");
        if (args[1] == "timeout")
            return runEngineProcess((ref bool bootstrapped) { throw new HolderStartupException("private startup failure", 75); });
        if (args[1] == "rejected")
            return runEngineProcess((ref bool bootstrapped) { throw new HolderStartupException("private startup failure", 78); });
        if (args[1] == "success") return runEngineProcess((ref bool bootstrapped) {});
        if (args[1] == "unexpected" || args[1] == "bootstrap-unexpected") {
            auto original = new Exception("private unrelated failure");
            try runEngineProcess((ref bool bootstrapped) {
                bootstrapped = args[1] == "unexpected";
                throw original;
            });
            catch (Exception e) { return e is original ? 79 : 80; }
            return 81;
        }
        return 82;
    }
    foreach (scenario, expected; ["success": 0, "timeout": 75, "rejected": 78, "unexpected": 79, "bootstrap-unexpected": 79]) {
        const result = execute([thisExePath(), scenario]);
        assert(result.status == expected, scenario ~ " must preserve the process-owner exit contract");
        assert(result.output.length == 0, "startup reporting must not print private exception details");
    }

    enum variables = ["IRCFIBER_BUGSINK_ENABLED", "IRCFIBER_BUGSINK_DSN", "IRCFIBER_BUGSINK_DSN_FILE"];
    string[string] saved;
    foreach (variable; variables) saved[variable] = environment.get(variable, null);
    scope(exit) {
        configureErrorReporting(false, "", "ircfiber-engine", "test", "test");
        foreach (variable; variables) {
            if (saved[variable] is null) environment.remove(variable);
            else environment[variable] = saved[variable];
        }
    }
    environment["IRCFIBER_BUGSINK_ENABLED"] = "1";
    environment["IRCFIBER_BUGSINK_DSN"] = "http://key@127.0.0.1:1/42";
    environment.remove("IRCFIBER_BUGSINK_DSN_FILE");
    assert(configureEngineReporting("ircfiber-engine", "test"));
    environment["IRCFIBER_BUGSINK_ENABLED"] = "0";
    assert(!configureEngineReporting("ircfiber-engine", "test"));
    assert(!isErrorReportingEnabled(), "disabled setup clears previously enabled credentials");
    environment["IRCFIBER_BUGSINK_ENABLED"] = "1";
    environment["IRCFIBER_BUGSINK_DSN_FILE"] = "/nonexistent/ircfiber-startup-test/ingest-dsn";
    assert(!configureEngineReporting("ircfiber-engine", "test"),
        "an explicit missing file is authoritative over a valid environment DSN");
    assert(!isErrorReportingEnabled());
    writeln("startup compatibility: PASS status 0/75/78, unchanged unrelated exceptions, private output, atomic reporter disable, authoritative DSN file");
    return 0;
}
