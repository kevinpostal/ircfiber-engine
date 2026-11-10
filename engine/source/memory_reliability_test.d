module memory_reliability_test;

import std.stdio : stderr;
import ircfiber.irc.connection : memoryIdentityRegressionChecks, metaPublicationRegressionChecks,
    holderRecoveryRegressionChecks, maintenanceAdmissionRegressionChecks;
import ircfiber.engine.bootstrap : holderScanObservationRegressionChecks;
import ircfiber.irc.manager : retiredClientMemoryRegressionChecks;
import ircfiber.engine.archive_spool_checks : archiveSpoolRegressionChecks, runArchiveSpoolChild;
import ircfiber.archive_protocol : isCanonicalArchiveOperationId;

private size_t passed, failed;

private void record(string name, bool success) {
    if (success) passed++;
    else failed++;
    stderr.writeln(success ? "  PASS " : "  FAIL ", name);
}


int main(string[] args) {
    int childResult;
    if (runArchiveSpoolChild(args, childResult)) return childResult;
    const canonicalOperation = "791f3ebc-1ae5-4f87-a656-fd8804c76817";
    record("canonical archive operation UUID accepted",
        isCanonicalArchiveOperationId(canonicalOperation));
    record("uppercase archive operation UUID rejected",
        !isCanonicalArchiveOperationId("791F3EBC-1AE5-4F87-A656-FD8804C76817"));
    record("nil archive operation UUID rejected",
        !isCanonicalArchiveOperationId("00000000-0000-0000-0000-000000000000"));
    record("malformed and trailing archive operation UUIDs rejected",
        !isCanonicalArchiveOperationId("791f3ebc-1ae5-4f87-a656-fd8804c7681z")
            && !isCanonicalArchiveOperationId("791f3ebc-1ae5-4f87-a656-fd8804c76817x"));
    stderr.writeln("[memory-reliability] live identity and retired generation ownership");
    try {
        foreach (check; memoryIdentityRegressionChecks()) record(check.name, check.passed);
    } catch (Throwable error) {
        record("identity lifecycle regression completed", false);
        stderr.writeln(error.toString());
    }
    try {
        foreach (check; retiredClientMemoryRegressionChecks()) record(check.name, check.passed);
    } catch (Throwable error) {
        record("retired generation regression completed", false);
        stderr.writeln(error.toString());
    }
    try {
        foreach (check; metaPublicationRegressionChecks()) record(check.name, check.passed);
    } catch (Throwable error) {
        record("META publication regression completed", false);
        stderr.writeln(error.toString());
    }
    try {
        foreach (check; holderRecoveryRegressionChecks()) record(check.name, check.passed);
    } catch (Throwable error) {
        record("holder relay recovery regression completed", false);
        stderr.writeln(error.toString());
    }
    try {
        foreach (check; maintenanceAdmissionRegressionChecks()) record(check.name, check.passed);
    } catch (Throwable error) {
        record("maintenance restoration admission regression completed", false);
        stderr.writeln(error.toString());
    }
    try {
        foreach (check; holderScanObservationRegressionChecks()) record(check.name, check.passed);
    } catch (Throwable error) {
        record("holder inventory observation regression completed", false);
        stderr.writeln(error.toString());
    }
    try {
        foreach (check; archiveSpoolRegressionChecks()) record(check.name, check.passed);
    } catch (Throwable error) {
        record("archive journal crash regression completed", false);
        stderr.writeln(error.toString());
    }
    stderr.writeln("Result: ", passed, " passed, ", failed, " failed");
    return failed ? 1 : 0;
}
