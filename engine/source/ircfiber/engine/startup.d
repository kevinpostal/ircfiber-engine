/// Engine process-owner adapters for the canonical common library contract.
module ircfiber.engine.startup;

import std.process : environment;
import ircfiber.errors : configureErrorReporting, isErrorReportingEnabled,
    readIngestDsnFile, captureException, waitErrorReport;
import ircfiber.holder_client : HolderStartupException;
import ircfiber.tracing : isEnvEnabled;

/// Configure atomically, clearing any previous credentials first. An explicit
/// ingest file is authoritative, including when absent or unusable.
bool configureEngineReporting(string service, string release) {
    const reportEnvironment = environment.get("IRCFIBER_BUGSINK_ENVIRONMENT", "production");
    configureErrorReporting(false, "", service, release, reportEnvironment);
    if (isEnvEnabled("IRCFIBER_BUGSINK_ENABLED")) {
        const file = environment.get("IRCFIBER_BUGSINK_DSN_FILE", "");
        const dsn = file.length ? readIngestDsnFile(file)
                               : environment.get("IRCFIBER_BUGSINK_DSN", "");
        configureErrorReporting(true, dsn, service, release, reportEnvironment);
    }
    return isErrorReportingEnabled();
}

/// Common no longer exits from connectControl. The process owner reports once,
/// waits for its bounded private report, and returns the original 75/78 status.
/// Other exceptions are reported at their static bootstrap/terminal owner and
/// retain their existing propagation and crash behavior.
int runEngineProcess(scope void delegate(ref bool bootstrapped) run) {
    bool bootstrapped;
    try {
        run(bootstrapped);
        return 0;
    } catch (HolderStartupException failure) {
        waitErrorReport(captureException!("engine", "bootstrap")(failure));
        return failure.exitCode;
    } catch (Throwable failure) {
        if (bootstrapped)
            waitErrorReport(captureException!("engine", "terminal")(failure));
        else
            waitErrorReport(captureException!("engine", "bootstrap")(failure));
        throw failure;
    }
}
