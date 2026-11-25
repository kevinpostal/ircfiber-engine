/// Privacy-preserving, best-effort Sentry store reporting, independent of OTLP.
/// Only immutable, bounded projections cross into a short-lived sender thread.
module ircfiber.errors;

import core.atomic : atomicLoad, atomicStore;
import core.sync.mutex : Mutex;
import core.time : MonoTime, seconds, msecs;
import core.thread : Thread;
import std.array : appender;
import std.datetime : Clock;
import std.format : format;

private enum MAX_EVENT_BYTES = 32 * 1024;
private enum REPORT_TIMEOUT = 5.seconds;

private struct ReporterConfig {
    string url, key, service, release, environment;
    ulong generation;
    bool enabled;
}

private __gshared Mutex configMutex;
private __gshared ReporterConfig config;
private __gshared bool busy;

shared static this() { configMutex = new Mutex; }

bool isErrorReportingEnabled() {
    synchronized (configMutex) return config.enabled;
}

/// A configured ingest file is authoritative, including when unreadable.
/// Accept one terminal file newline; leave every other byte for strict parsing.
string readIngestDsnFile(string path) nothrow {
    import std.file : isFile;
    import std.stdio : File;
    try {
        if (!isFile(path)) return "";
        auto input = File(path, "rb");
        ubyte[2048 + 2 + 1] buffer;
        auto bytes = input.rawRead(buffer[]);
        if (bytes.length == buffer.length) return "";
        if (bytes.length && bytes[$ - 1] == '\n') {
            bytes = bytes[0 .. $ - 1];
            if (bytes.length && bytes[$ - 1] == '\r') bytes = bytes[0 .. $ - 1];
        }
        return bytes.length <= 2048 ? cast(string) bytes.idup : "";
    } catch (Exception) { return ""; }
}

private struct ParsedDsn {
    string scheme, key, hostPort, projectId;
    bool valid;
}

private bool asciiDigit(char c) pure nothrow {
    return c >= '0' && c <= '9';
}

private bool asciiAlpha(char c) pure nothrow {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

private bool safeToken(string value, size_t maxLength) pure nothrow {
    if (!value.length || value.length > maxLength) return false;
    foreach (char c; value)
        if (!asciiAlpha(c) && !asciiDigit(c) && c != '_' && c != '-'
            && c != '.' && c != '+') return false;
    return true;
}

private bool validAuthority(string authority) {
    import std.string : indexOf, lastIndexOf;
    string host, port;
    if (!authority.length) return false;
    if (authority[0] == '[') {
        const end = authority.indexOf(']');
        if (end <= 1) return false;
        host = authority[1 .. end];
        if (cast(size_t)end + 1 < authority.length) {
            if (authority[end + 1] != ':') return false;
            port = authority[end + 2 .. $];
            if (!port.length) return false;
        }
        // Numeric parsing only: never perform DNS during configuration.
        import std.socket : Internet6Address;
        Internet6Address.parse(host);
    } else {
        const colon = authority.lastIndexOf(':');
        if (colon >= 0) {
            host = authority[0 .. colon];
            port = authority[colon + 1 .. $];
            if (!port.length) return false;
        } else host = authority;
        if (!host.length || host.length > 253) return false;
        size_t labelLength;
        char previous;
        foreach (char c; host) {
            if (c == '.') {
                if (!labelLength || previous == '-') return false;
                labelLength = 0;
            } else {
                if (!asciiAlpha(c) && !asciiDigit(c) && c != '-') return false;
                if (!labelLength && c == '-') return false;
                if (++labelLength > 63) return false;
            }
            previous = c;
        }
        if (!labelLength || previous == '-') return false;
    }
    if (port.length) {
        if (port.length > 5) return false;
        uint number;
        foreach (char c; port) {
            if (!asciiDigit(c)) return false;
            number = number * 10 + c - '0';
        }
        if (!number || number > 65535) return false;
    }
    return true;
}

private ParsedDsn parseDsn(string dsn) {
    import std.string : indexOf, lastIndexOf;
    ParsedDsn parsed;
    if (!dsn.length || dsn.length > 2048) return parsed;
    foreach (char c; dsn)
        if (c <= 0x20 || c >= 0x7f || c == '?' || c == '#' || c == '\\') return parsed;
    const schemeEnd = dsn.indexOf("://");
    if (schemeEnd < 0) return parsed;
    parsed.scheme = dsn[0 .. schemeEnd];
    if (parsed.scheme != "https" && parsed.scheme != "http") return parsed;
    auto rest = dsn[schemeEnd + 3 .. $];
    const at = rest.indexOf('@');
    if (at <= 0) return parsed;
    parsed.key = rest[0 .. at];
    if (!safeToken(parsed.key, 256)) return parsed;
    auto hostAndPath = rest[at + 1 .. $];
    const slash = hostAndPath.lastIndexOf('/');
    if (slash <= 0 || slash == hostAndPath.length - 1) return parsed;
    parsed.hostPort = hostAndPath[0 .. slash];
    parsed.projectId = hostAndPath[slash + 1 .. $];
    if (parsed.projectId.length > 20) return parsed;
    foreach (char c; parsed.projectId) if (!asciiDigit(c)) return parsed;
    try {
        if (!validAuthority(parsed.hostPort)) return parsed;
    } catch (Throwable) { return parsed; }
    parsed.valid = true;
    return parsed;
}

/// Clears old credentials before parsing. Disabled or invalid config cannot
/// be rearmed separately, and never changes the application's OTLP settings.
void configureErrorReporting(bool enabled, string dsn, string svcName,
                             string svcVersion, string environment) {
    synchronized (configMutex) {
        const generation = config.generation + 1;
        config = ReporterConfig.init;
        config.generation = generation;
        if (!enabled) return;
        auto parsed = parseDsn(dsn);
        if (!parsed.valid || !safeToken(svcName, 128)
            || !safeToken(svcVersion, 128) || !safeToken(environment, 64)) {
            localDiagnostic("bugsink: invalid configuration; reporting disabled");
            return;
        }
        config.url = parsed.scheme ~ "://" ~ parsed.hostPort ~ "/api/"
            ~ parsed.projectId ~ "/store/";
        config.key = parsed.key.idup;
        config.service = svcName.idup;
        config.release = svcVersion.idup;
        config.environment = environment.idup;
        config.enabled = true;
    }
}

private void localDiagnostic(string message) nothrow {
    // Never route sender failures through logging.d or print transport text.
    try {
        import std.stdio : stderr;
        stderr.writeln(message);
    } catch (Throwable) {}
}

private string jsonEscape(string value) {
    auto sink = appender!string();
    foreach (char c; value) {
        switch (c) {
            case '"': sink ~= `\"`; break;
            case '\\': sink ~= `\\`; break;
            default:
                if (c < 0x20) sink ~= format("\\u%04x", cast(uint)c);
                else sink ~= c;
        }
    }
    return sink.data;
}

private string safeSymbol(string symbol) pure nothrow {
    if (!symbol.length || symbol.length > 256) return "unknown";
    foreach (char c; symbol)
        if (!asciiAlpha(c) && !asciiDigit(c) && c != '_' && c != '.'
            && c != ':' && c != '!' && c != '(' && c != ')'
            && c != '[' && c != ']' && c != ',') return "unknown";
    return symbol;
}

enum BncFailureReason {
    missingWorkerId,
    storageInitializationFailed,
    holderRegistrationFailed,
    sweepTaskStartFailed,
    holderShutdownDisconnectedClients,
    holderControlStreamLost,
    sessionStartFailed,
}

string bncFailureReasonLabel(BncFailureReason reason) pure nothrow {
    final switch (reason) {
        case BncFailureReason.missingWorkerId: return "BNC worker ID is missing";
        case BncFailureReason.storageInitializationFailed: return "BNC worker storage initialization failed";
        case BncFailureReason.holderRegistrationFailed: return "BNC worker holder registration failed";
        case BncFailureReason.sweepTaskStartFailed: return "BNC worker sweep task failed to start";
        case BncFailureReason.holderShutdownDisconnectedClients: return "BNC holder shutdown disconnected active clients";
        case BncFailureReason.holderControlStreamLost: return "BNC worker holder control stream lost";
        case BncFailureReason.sessionStartFailed: return "BNC worker session start failed";
    }
}

private string bncOperation(BncFailureReason reason) pure nothrow {
    final switch (reason) {
        case BncFailureReason.missingWorkerId: return "missing-worker-id";
        case BncFailureReason.storageInitializationFailed: return "storage-initialization";
        case BncFailureReason.holderRegistrationFailed: return "holder-registration";
        case BncFailureReason.sweepTaskStartFailed: return "sweep-task-start";
        case BncFailureReason.holderShutdownDisconnectedClients: return "holder-shutdown";
        case BncFailureReason.holderControlStreamLost: return "holder-control-loss";
        case BncFailureReason.sessionStartFailed: return "session-start";
    }
}

private string buildSentryEventJson(const ref ReporterConfig cfg, string component,
        string operation, string exceptionType, string moduleName, string functionName,
        size_t line, string eventId, string timestamp, string bncReason = "",
        long affectedSessions = -1, bool active = false) {
    // Bound before encoding as well as after it; no oversized input is copied.
    if (!safeToken(cfg.service, 128) || !safeToken(cfg.release, 128)
        || !safeToken(cfg.environment, 64) || !safeToken(component, 64)
        || !safeToken(operation, 96) || eventId.length != 32
        || timestamp.length > 64 || bncReason.length > 96) return null;
    auto sink = appender!string();
    sink ~= format(
        `{"event_id":"%s","timestamp":"%s","platform":"other","level":"error",`
        ~ `"logger":"ircfiber.%s","message":"%s","release":"%s","environment":"%s",`
        ~ `"exception":{"values":[{"type":"%s","value":"%s"}]},`
        ~ `"tags":{"component":"%s","operation":"%s","service":"%s"},`
        ~ `"extra":{"module":"%s","function":"%s","line":%s`,
        eventId, jsonEscape(timestamp), component, operation, jsonEscape(cfg.release),
        jsonEscape(cfg.environment), jsonEscape(safeSymbol(exceptionType)), operation,
        component, operation, jsonEscape(cfg.service), jsonEscape(safeSymbol(moduleName)),
        jsonEscape(safeSymbol(functionName)), line);
    if (bncReason.length)
        sink ~= format(`,"reason":"%s","affected_sessions":%s,"active":%s`,
            bncReason, affectedSessions < -1 ? -1 : affectedSessions, active ? "true" : "false");
    sink ~= `}}`;
    auto body = sink.data;
    return body.length <= MAX_EVENT_BYTES ? body : null;
}

private struct ReportState { bool done; }

/// Opaque handle for a terminal owner. Busy/disabled/dropped reports return init.
struct ErrorReport {
    private shared(ReportState)* state;
    private MonoTime deadline;
}

/// Static labels make it impossible to accidentally interpolate chat/credentials.
/// No Throwable, arbitrary extras, message or stack text crosses the handoff.
ErrorReport captureException(string component, string operation)(
        Throwable error, string moduleName = __MODULE__,
        string functionName = __FUNCTION__, size_t line = __LINE__) nothrow {
    static assert(safeToken(component, 64), "component must be a static safe token");
    static assert(safeToken(operation, 96), "operation must be a static safe token");
    if (error is null) return ErrorReport.init;
    try return enqueueReport(component, operation, safeSymbol(error.classinfo.name),
        safeSymbol(moduleName), safeSymbol(functionName), line);
    catch (Throwable) { return ErrorReport.init; }
}

/// One instance per sequential job loop; recovery means a completed healthy round.
struct FailureEpisode(string component, string operation) {
    private bool failed;

    void failure(Throwable error, string moduleName = __MODULE__,
            string functionName = __FUNCTION__, size_t line = __LINE__) nothrow {
        if (failed) return;
        failed = true;
        captureException!(component, operation)(error, moduleName, functionName, line);
    }

    void success() nothrow { failed = false; }
}

/// BNC has a dedicated project and fixed, explicitly allowlisted impact fields.
ErrorReport captureBncImpact(BncFailureReason reason, long affectedSessions = -1,
                            bool active = false) nothrow {
    try return enqueueReport("bnc-worker", bncOperation(reason), "BncWorkerFailure",
        "ircfiber.bnc.worker", "failureBoundary", 0,
        bncFailureReasonLabel(reason), affectedSessions, active);
    catch (Throwable) { return ErrorReport.init; }
}

private ErrorReport enqueueReport(string component, string operation,
        string exceptionType, string moduleName, string functionName, size_t line,
        string bncReason = "", long affectedSessions = -1, bool active = false) {
    ReporterConfig snapshot;
    synchronized (configMutex) {
        if (!config.enabled || busy) return ErrorReport.init;
        busy = true;
        snapshot = config;
    }
    bool handedOff;
    scope (exit) if (!handedOff) {
        synchronized (configMutex) busy = false;
    }
    auto deadline = MonoTime.currTime + REPORT_TIMEOUT;
    import ircfiber.tracing : newTraceId;
    auto body = buildSentryEventJson(snapshot, component, operation, exceptionType,
        moduleName, functionName, line, newTraceId(),
        Clock.currTime.toUTC().toISOExtString(), bncReason, affectedSessions, active);
    if (!body.length) return ErrorReport.init;
    auto state = new shared ReportState;
    auto data = new immutable ReportData(snapshot.url, snapshot.key,
        snapshot.release, body, snapshot.generation, deadline);
    // No closure retains the caller's fiber, exception or application context.
    auto worker = new SenderThread(data, state);
    worker.start();
    handedOff = true;
    return ErrorReport(state, deadline);
}

private struct ReportData {
    string url, key, release, body;
    ulong generation;
    MonoTime deadline;
}

/// No idle non-daemon pool may keep an otherwise finished process alive.
private final class SenderThread : Thread {
    private immutable(ReportData)* data;
    private shared(ReportState)* state;

    this(immutable(ReportData)* data, shared(ReportState)* state) {
        this.data = data;
        this.state = state;
        super(&run);
    }

    private void run() nothrow { sendReport(data, state); }
}

private void finishReport(shared(ReportState)* state) nothrow {
    configMutex.lock_nothrow();
    busy = false;
    configMutex.unlock_nothrow();
    // A terminal waiter may immediately admit its next report.
    atomicStore(state.done, true);
}

private void sendReport(immutable(ReportData)* data, shared(ReportState)* state) nothrow {
    scope (exit) finishReport(state);
    try {
        synchronized (configMutex)
            if (!config.enabled || config.generation != data.generation) return;
        import std.net.curl : HTTP, CurlOption;
        // vibe's client logs request headers (including Sentry auth) at trace.
        // This transport has no application logger, and verbose is never enabled.
        // Blocking I/O lives only on this private sender thread, never on an
        // application's request/socket/native worker or while holding a lock.
        auto client = HTTP(data.url);
        scope (exit) client.shutdown();
        client.verbose = false;
        client.proxy = ""; // Do not inherit HTTP(S)_PROXY or disclose the key there.
        client.handle.set(CurlOption.followlocation, 0L);
        client.handle.set(CurlOption.maxredirs, 0L);
        client.handle.set(CurlOption.protocols, 3L); // CURLPROTO_HTTP | CURLPROTO_HTTPS
        client.connectTimeout = 2.seconds;
        client.dataTimeout = 2.seconds;
        client.addRequestHeader("Connection", "close");
        client.addRequestHeader("X-Sentry-Auth", "Sentry sentry_version=7, sentry_key="
            ~ data.key ~ ", sentry_client=ircfiber-d/" ~ data.release);
        client.setPostData(cast(const(void)[])data.body, "application/json");
        client.onReceive = (ubyte[] chunk) { return chunk.length; };
        const remaining = data.deadline - MonoTime.currTime;
        if (remaining.total!"msecs" <= 0) return;
        client.operationTimeout = remaining;
        client.perform();
        const status = client.statusLine.code;
        if (status < 200 || status >= 300) localDiagnostic("bugsink: report rejected");
    } catch (Throwable) {
        localDiagnostic("bugsink: report transport failed");
    }
}

/// Only terminal owners wait. Admission time, not wait time, starts the deadline.
/// Native startup callers do not need to start the application's event loop.
void waitErrorReport(ErrorReport report) nothrow {
    if (report.state is null) return;
    try {
        import core.thread : Thread;
        import vibe.core.core : sleep;
        import vibe.core.task : Task;
        while (!atomicLoad(report.state.done)) {
            auto remaining = report.deadline - MonoTime.currTime;
            if (remaining <= 0.seconds) return;
            auto interval = remaining < 10.msecs ? remaining : 10.msecs;
            if (Task.getThis() == Task.init) Thread.sleep(interval);
            else sleep(interval);
        }
    } catch (Throwable) {}
}

unittest {
    foreach (dsn; [
        "http://key@localhost:8080/42",
        "https://abc123@errors.invalid/1",
        "https://key@[::1]:8080/2",
        "https://key@[2001:db8::1]/3",
    ]) assert(parseDsn(dsn).valid, dsn);
    const parsed = parseDsn("http://key@localhost:8080/42");
    assert(parsed.scheme == "http");
    assert(parsed.key == "key");
    assert(parsed.hostPort == "localhost:8080");
    assert(parsed.projectId == "42");

    foreach (dsn; [
        "", "disabled", "not-a-dsn",
        "ftp://key@localhost/1",
        "https://localhost/1",
        "https://@localhost/1",
        "https://key:password@localhost/1",
        "https://key@user@localhost/1",
        "https://key@/1",
        "https://key@localhost/",
        "https://key@localhost/project",
        "https://key@localhost/1/2",
        "https://key@localhost/1?query=credential",
        "https://key@localhost/1#credential",
        "https://key\r\n@localhost/1",
        "https://key\0@localhost/1",
        "https://key@local host/1",
        "https://key@localhost:0/1",
        "https://key@localhost:65536/1",
        "https://key@localhost:/1",
        "https://key@localhost:abc/1",
        "https://key@[localhost]/1",
        "https://key@[::::]/1",
        "https://key@[::1]suffix/1",
        "https://key@-localhost/1",
        "https://key@localhost./1",
        "https://key@localhost\\other/1",
    ]) assert(!parseDsn(dsn).valid, dsn);
}

unittest {
    configureErrorReporting(true, "http://key@localhost:8080/42",
        "test-service", "test-release", "test");
    assert(isErrorReportingEnabled());
    synchronized (configMutex) {
        assert(config.url == "http://localhost:8080/api/42/store/");
        assert(config.key == "key");
    }
    configureErrorReporting(true, "invalid-dsn",
        "test-service", "test-release", "test");
    assert(!isErrorReportingEnabled());
    synchronized (configMutex) {
        assert(config.url.length == 0);
        assert(config.key.length == 0);
    }
    configureErrorReporting(false, "http://ignored@localhost:8080/42",
        "test-service", "test-release", "test");
    synchronized (configMutex) {
        assert(!config.enabled && !config.url.length && !config.key.length);
    }
    assert(captureException!("test", "disabled")(new Exception("private")).state is null);
    waitErrorReport(ErrorReport.init);
}

unittest {
    import std.json : parseJSON;
    import std.string : indexOf;
    const cfg = ReporterConfig("", "", "test-service", "test-release", "test");
    enum id = "0123456789abcdef0123456789abcdef";
    enum timestamp = "2026-11-25T12:00:00Z";
    auto error = new Exception("PRIVATE_CHAT_CREDENTIAL_MARKER");
    auto body = buildSentryEventJson(cfg, "gateway", "request-dispatch",
        error.classinfo.name, "ircfiber.web", "ircfiber.web.dispatch", 42, id, timestamp);
    assert(body.length && body.length <= MAX_EVENT_BYTES);
    auto event = parseJSON(body);
    assert(event["event_id"].str == id);
    assert(event["message"].str == "request-dispatch");
    assert(event["release"].str == "test-release");
    assert(event["environment"].str == "test");
    assert(event["exception"]["values"][0]["type"].str == "object.Exception");
    assert(event["exception"]["values"][0]["value"].str == "request-dispatch");
    assert(event["tags"]["component"].str == "gateway");
    assert(event["tags"]["operation"].str == "request-dispatch");
    assert(event["tags"]["service"].str == "test-service");
    assert(event["extra"]["module"].str == "ircfiber.web");
    assert(event["extra"]["function"].str == "ircfiber.web.dispatch");
    assert(event["extra"]["line"].integer == 42);
    assert(event["extra"].object.length == 3);
    assert(body.indexOf("PRIVATE_CHAT_CREDENTIAL_MARKER") < 0);
    assert(body.indexOf("stack_trace") < 0);
    assert(body.indexOf("server_name") < 0);
    assert(("request" in event.object) is null);

    char[257] oversized;
    oversized[] = 'x';
    body = buildSentryEventJson(cfg, "gateway", "request-dispatch",
        "type\nPRIVATE_CHAT_CREDENTIAL_MARKER", oversized[].idup,
        "/home/private/credential.d", 0, id, timestamp);
    event = parseJSON(body);
    assert(event["exception"]["values"][0]["type"].str == "unknown");
    assert(event["extra"]["module"].str == "unknown");
    assert(event["extra"]["function"].str == "unknown");
    assert(body.indexOf("PRIVATE_CHAT_CREDENTIAL_MARKER") < 0);
    assert(body.indexOf("/home/private") < 0);
    assert(safeSymbol("ircfiber.Worker.run") == "ircfiber.Worker.run");
    assert(safeSymbol("") == "unknown");
    assert(safeSymbol(oversized[].idup) == "unknown");
    auto hugeConfig = ReporterConfig("", "", "test-service", oversized[].idup, "test");
    assert(!buildSentryEventJson(hugeConfig, "gateway", "request-dispatch",
        "Exception", "module", "function", 0, id, timestamp).length);

    body = buildSentryEventJson(cfg, "bnc-worker", "holder-control-loss",
        "BncWorkerFailure", "ircfiber.bnc.worker", "unknown", 0, id, timestamp,
        bncFailureReasonLabel(BncFailureReason.holderControlStreamLost), 7, true);
    event = parseJSON(body);
    assert(event["extra"]["reason"].str == "BNC worker holder control stream lost");
    assert(event["extra"]["affected_sessions"].integer == 7);
    assert(event["extra"]["active"].boolean);
    assert(event["extra"].object.length == 6);
}

unittest {
    // Waiting on a completed or expired token requires no event loop/network.
    auto state = new shared ReportState;
    atomicStore(state.done, true);
    waitErrorReport(ErrorReport(state, MonoTime.currTime + REPORT_TIMEOUT));
    atomicStore(state.done, false);
    waitErrorReport(ErrorReport(state, MonoTime.currTime - 1.msecs));
}
