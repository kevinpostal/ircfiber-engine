module ircfiber.logging;

import std.stdio : stderr;
import std.json : JSONValue, JSONOptions;
import std.datetime : Clock, SysTime;
import std.conv : to;
import std.string : strip, toStringz;
import std.format : format;
import std.array : appender;
import core.sync.mutex : Mutex;

/// Module-level log threshold. Messages below this level are suppressed.
/// Controlled by `IRCFIBER_LOG_LEVEL` env var:
///   "none"   – suppress everything (emergency only)
///   "error"  – only errors
///   "warn"   – errors + warnings
///   "info"   – default: errors + warnings + info (suppress debug)
///   "debug"  – everything (full verbosity, high volume)
///
/// The env var is read once at module init, so a process restart is
/// required to change it. Default `info` keeps the logs clean for
/// production — debug-level messages like `disconnect_probe` (10/sec)
/// are suppressed unless explicitly enabled.
private __gshared int g_logLevel = 3; // 0=none 1=error 2=warn 3=info 4=debug — default info per header comment
private void initLogLevel() {
    import core.stdc.stdlib : getenv;
    import core.stdc.string : strlen;
    auto env = getenv("IRCFIBER_LOG_LEVEL".toStringz);
    if (env !is null) {
        const s = env[0 .. strlen(env)];
        if (s == "none")   g_logLevel = 0;
        else if (s == "error")  g_logLevel = 1;
        else if (s == "warn")   g_logLevel = 2;
        else if (s == "info")   g_logLevel = 3;
        else if (s == "debug")  g_logLevel = 4;
    }
}
private int levelRank(string level) {
    if (level == "error") return 1;
    if (level == "warn")  return 2;
    if (level == "info")  return 3;
    if (level == "debug") return 4;
    return 3; // treat unknown as info
}
/// Ensure init runs once.  The `thread_local` trick gives us a cheap
/// per-fiber flag so the `getenv`/`strlen`/`toStringz` overhead only
/// fires on the first call from any fiber, not on every log line.
private bool logLevelInitd;
private void ensureLogLevelInitd() {
    if (!logLevelInitd) {
        initLogLevel();
        logLevelInitd = true;
    }
}

/// Structured JSON logging for the irc-fiber engine.
///
/// Emits one JSON object per line to stderr, so the container's Docker
/// json-file driver can pick it up. The format is deliberately minimal
/// so Promtail can parse it without a custom regex:
///
///   {"ts":"2026-06-28T12:34:56.789Z","level":"info","component":"handoff","network":"SuperNets","msg":"..."}
///
/// Standard fields (always present):
///   ts          RFC3339Nano timestamp (UTC)
///   level       info | warn | error | debug
///   msg         Human-readable message
///
/// Optional fields (added by callers via the variadic template):
///   component   e.g. "handoff", "nick", "connection"
///   network     e.g. "SuperNets", "IRC Fiber"
///   nick        IRC nick (no prefix, lowercase as stored)
///   event       e.g. "connect", "disconnect", "nick_change"
///   pid         Process ID (filled automatically)
///   eid         IRC event ID (for correlation)
///   networkId   UUID of the network config
///   host        IRC server hostname
///
/// Usage:
///   logJson("info", "handoff", "Handoff complete",
///           "network", "SuperNets", "eid", 42);
///
/// Migration note: the JSON path is now the canonical structured stream
/// and is always emitted (Docker's json-file driver picks it up).
/// Legacy `logInfo/logWarn/logError` text lines continue to coexist as
/// human-readable stderr. `IRCFIBER_LOG_JSON` is preserved as a
/// recognised env var for legacy callers but is no longer consulted —
/// the JSON path is always on.

/// Emit one JSON log line to stderr with key=value pairs from a map.
///
/// This API avoids D's variadic-tuple compile-time indexing limitation.
/// Pass fields as a `string[string]` (key=value pairs). Keys must be
/// valid JSON identifiers (no escaping performed on key names).
///
/// Example:
///   logJsonMap("info", "handoff", "Handoff complete",
///              ["network": "SuperNets", "eid": "42"]);
void logJsonMap(string level, string component, string msg,
                string[string] fields = null) {
    // Level gate: skip messages below the configured threshold.
    // This is the primary mechanism to suppress high-frequency debug
    // logs (disconnect_probe, ping_sent, etc.) in production.
    ensureLogLevelInitd();
    if (levelRank(level) > g_logLevel) return;

    import ircfiber.tracing : currentTraceId, currentSpanId;

    JSONValue j = JSONValue.emptyObject;
    auto now = Clock.currTime.toUTC();
    // toISOExtString() for UTC already ends with 'Z' (e.g. 2026-08-07T05:48:14.5098568Z).
    // The old code appended another "Z" producing "...ZZ" which broke
    // fluent-bit's time parser and SigNoz's timestamp handling.
    j["ts"] = JSONValue(now.toISOExtString());
    j["level"] = JSONValue(level);
    j["component"] = JSONValue(component);
    j["msg"] = JSONValue(msg);
    // Trace correlation: when this log line is emitted from within a
    // `withSpan()` body, the current trace/span IDs are non-empty.
    // SigNoz (and any OTLP-aware log backend) joins on these so a
    // log line on e.g. `event:connection_crashed` clicks through to
    // the surrounding trace + flamegraph. Kept as last-resort
    // top-level keys so Promtail still parses them as plain JSON.
    auto traceId = currentTraceId();
    auto spanId  = currentSpanId();
    if (traceId.length) j["traceId"] = JSONValue(traceId);
    if (spanId.length)  j["spanId"]  = JSONValue(spanId);
    if (fields !is null) {
        foreach (k, v; fields) {
            j[k] = JSONValue(v);
        }
    }
    stderr.writeln(j.toString(JSONOptions.doNotEscapeSlashes));
    stderr.flush();
    // OTLP logs enqueue — mirrors stderr JSON but as OTLP logRecord
    // with severity, trace correlation, and attributes. Cheap when
    // disabled (g_logsEnabled check in enqueueLog).
    try { enqueueLog(level, component, msg, fields, traceId, spanId); }
    catch (Exception) {}
}

/// Numeric/null diagnostics retain their JSON types on stderr. Conversion to
/// string-valued OTLP attributes happens only when that optional queue is on.
/// Required local diagnostics may bypass the operator's severity threshold
/// without changing their severity or enabling the optional OTLP exporter.
void logJsonMap(string level, string component, string msg, JSONValue fields,
                bool forceLocal = false) {
    ensureLogLevelInitd();
    if (!forceLocal && levelRank(level) > g_logLevel) return;
    import ircfiber.tracing : currentTraceId, currentSpanId;
    import std.json : JSONType;
    auto j = JSONValue.emptyObject;
    j["ts"] = JSONValue(Clock.currTime.toUTC().toISOExtString());
    j["level"] = JSONValue(level);
    j["component"] = JSONValue(component);
    j["msg"] = JSONValue(msg);
    auto traceId = currentTraceId();
    auto spanId = currentSpanId();
    if (traceId.length) j["traceId"] = JSONValue(traceId);
    if (spanId.length) j["spanId"] = JSONValue(spanId);
    if (fields.type == JSONType.object)
        foreach (k, v; fields.object) j[k] = v;
    stderr.writeln(j.toString(JSONOptions.doNotEscapeSlashes));
    stderr.flush();
    if (!g_logsEnabled) return;
    string[string] attrs;
    if (fields.type == JSONType.object) foreach (k, v; fields.object)
        attrs[k] = v.type == JSONType.string ? v.str : v.toString(JSONOptions.doNotEscapeSlashes);
    try enqueueLog(level, component, msg, attrs, traceId, spanId);
    catch (Exception) {}
}

/// Convenience: tagged info log with no extra fields beyond component.
void logInfoJ(string component, string msg, string network = "") {
    if (network.length)
        logJsonMap("info", component, msg, ["network": network]);
    else
        logJsonMap("info", component, msg);
}
/// Convenience: tagged warn log with no extra fields beyond component.
void logWarnJ(string component, string msg, string network = "") {
    if (network.length)
        logJsonMap("warn", component, msg, ["network": network]);
    else
        logJsonMap("warn", component, msg);
}
/// Convenience: tagged error log with no extra fields beyond component.
void logErrorJ(string component, string msg, string network = "") {
    if (network.length)
        logJsonMap("error", component, msg, ["network": network]);
    else
        logJsonMap("error", component, msg);
}

/// Emit a structured exception log with the full D stack trace attached.
///
/// `e.toString()` produces `e.msg + file:line where it was thrown`,
/// and `e.info.toString()` chains every `Throwable` in the chain with
/// its file/line. Capturing both lets Loki/Grafana pivot on either the
/// error message text or the stack frame.
///
/// Use this from every `catch (Exception e)` block instead of writing
/// `logError("...: %s", e.msg)` — `e.msg` alone is just a sentence,
/// the stack trace tells you WHERE in the engine it fired.
///
/// `nothrow` so it can be called from `runTask(() nothrow { ... })`
/// wrappers. The stack trace is truncated to 8KB to keep Loki stream
/// size sane; the full trace remains in the engine's stderr log.
void logException(string component,
                 Throwable e,
                 string context = "",
                 string[string] extra = null) nothrow {
    try {
        auto fields = (extra is null) ? null : extra.dup;
        fields["exception"] = e.toString();
        fields["stack"] = e.info.toString();
        if (fields["stack"].length > 8192)
            fields["stack"] = fields["stack"][0 .. 8192] ~ "\n... (truncated)";
        logJsonMap("error", component, context.length ? context : e.msg, fields);
        // Best-effort immediate flush supplements the independent periodic
        // telemetry task, preserving the existing error/shutdown behavior.
        try flushAndSendLogs(); catch (Throwable) {}
        // Bugsink: independent on/off switch from the OTLP logs flush
        // above — IRCFIBER_BUGSINK_ENABLED gates this separately so ops can
        // silence error reporting (e.g. Bugsink itself is down) without
        // touching tracing/metrics/logs.
        try {
            import ircfiber.errors : captureException, isErrorReportingEnabled;
            if (isErrorReportingEnabled()) captureException(component, e, context, extra);
        } catch (Throwable) {}
    } catch (Throwable secondary) {
        // We are already in an error path — never throw from here.
        try {
            string m;
            try { m = secondary.msg; } catch (Throwable) { m = "unknown"; }
            stderr.writeln("logException failed: ", m);
        } catch (Throwable) {}
    }
}
// ── OTLP Logs export ──────────────────────────────────────────────────────
//
// Mirrors tracing.d / observability.d but for logs. Every call to
// `logJsonMap()` (which is every structured log line) optionally enqueues
// a PendingLog that is flushed every 10s via `flushAndSendLogs()` from
// the telemetry task. The wire format is OTLP/HTTP JSON to /v1/logs:
//
//   {"resourceLogs":[{"resource":{"attributes":[...]},"scopeLogs":[{"scope":{"name":"ircfiber.logging"},"logRecords":[...]}]}]}
//
// Kat: OTLP logs use severityNumber per spec (TRACE=1, DEBUG=5, INFO=9,
// WARN=13, ERROR=17, FATAL=21). SigNoz's UI groups by severity_text.

private struct PendingLog {
    long timeUnixNano;
    long observedTimeUnixNano;
    string severityText; // INFO, WARN, ERROR, DEBUG
    int severityNumber;
    string body;         // msg
    string traceId;      // hex 32, may be empty
    string spanId;       // hex 16, may be empty
    uint traceFlags;
    string[string] attributes; // component + custom fields
}

import ircfiber.observability : BoundedTelemetryQueue, telemetryStringCharge,
    telemetryAttributesCharge, copyTelemetryAttributes, sendTelemetryJson;

enum LOGGING_MAX_ENTRIES = 8192;
enum LOGGING_MAX_BYTES = 8 * 1024 * 1024;
private alias LoggingQueue = BoundedTelemetryQueue!(PendingLog, LOGGING_MAX_ENTRIES, LOGGING_MAX_BYTES);
private __gshared shared(Mutex) logsMutex;
private __gshared LoggingQueue logQueue;
private __gshared ulong reportedLoggingDrops;
private __gshared string logsEndpoint = "http://ircfiber-otel-collector:4318/v1/logs";
private __gshared string logsServiceName = "ircfiber-engine";
private __gshared string logsServiceVersion = "0.3.0";
private __gshared bool g_logsEnabled = false;
private __gshared bool logsMutexInitd;

struct LoggingQueueSample { ulong count, bytes, droppedCount, droppedBytes; long lastExportSuccessAtMs; }
LoggingQueueSample sampleLoggingQueue() {
    if (!logsMutexInitd) return LoggingQueueSample.init;
    synchronized (logsMutex)
        return LoggingQueueSample(logQueue.count, logQueue.bytes, logQueue.droppedCount, logQueue.droppedBytes,
                                  logQueue.lastExportSuccessAtMs);
}

private void initLogsOnce() {
    if (logsMutexInitd) return;
    synchronized (typeid(typeof(logsMutex))) {
        if (logsMutexInitd) return;
        logsMutex = new shared Mutex();
        synchronized (logsMutex) {} // init lazy mutex
        logsMutexInitd = true;
    }
}

/// Whether OTLP logs are enabled.
bool isLoggingEnabled() { return g_logsEnabled; }
void setLoggingEnabled(bool v) { g_logsEnabled = v; }

/// Configure OTLP logs endpoint + service identity.
void configureLogging(string otlpEndpoint, string svcName, string svcVersion) {
    logsEndpoint = otlpEndpoint;
    logsServiceName = svcName;
    logsServiceVersion = svcVersion;
    g_logsEnabled = (otlpEndpoint.length > 0 && otlpEndpoint != "disabled");
    if (g_logsEnabled) initLogsOnce();
}

private int severityNumberFor(string level) {
    if (level == "debug") return 5;
    if (level == "info")  return 9;
    if (level == "warn")  return 13;
    if (level == "error") return 17;
    return 9;
}

private string severityTextFor(string level) {
    if (level == "debug") return "DEBUG";
    if (level == "info")  return "INFO";
    if (level == "warn")  return "WARN";
    if (level == "error") return "ERROR";
    return "INFO";
}

private void enqueueLog(string level, string component, string msg,
                        string[string] fields,
                        string traceId, string spanId) {
    if (!g_logsEnabled) return;
    if (!logsMutexInitd) initLogsOnce();
    // Preflight the caller-owned fields before allocating our attribute map.
    auto initialCharge = LoggingQueue.addSaturated(768, telemetryStringCharge(msg));
    initialCharge = LoggingQueue.addSaturated(initialCharge, telemetryAttributesCharge(fields));
    synchronized (logsMutex) if (!logQueue.admits(initialCharge)) return;
    auto now = Clock.currTime.toUTC();
    long nano = now.toUnixTime() * 1_000_000_000L + now.fracSecs.total!"nsecs";
    PendingLog rec;
    rec.timeUnixNano = nano;
    rec.observedTimeUnixNano = nano;
    rec.severityText = severityTextFor(level);
    rec.severityNumber = severityNumberFor(level);
    rec.body = msg;
    rec.traceId = traceId;
    rec.spanId = spanId;
    rec.traceFlags = traceId.length ? 1 : 0;
    // Build attributes map: component + custom fields + level
    string[string] attrs;
    attrs["component"] = component;
    attrs["level"] = level;
    if (fields !is null) foreach (k, v; fields) attrs[k] = v;
    rec.attributes = attrs;
    enqueueLogRecord(rec);
}

private void enqueueLogRecord(PendingLog rec) {
    ulong charge = 768;
    string[4] strings = [rec.severityText, rec.body, rec.traceId, rec.spanId];
    foreach (s; strings)
        charge = LoggingQueue.addSaturated(charge, telemetryStringCharge(s));
    charge = LoggingQueue.addSaturated(charge, telemetryAttributesCharge(rec.attributes));
    synchronized (logsMutex) {
        if (!logQueue.admits(charge)) return;
        rec.severityText = rec.severityText.idup;
        rec.body = rec.body.idup;
        rec.traceId = rec.traceId.idup;
        rec.spanId = rec.spanId.idup;
        rec.attributes = copyTelemetryAttributes(rec.attributes);
        logQueue.put(rec, charge);
    }
}

/// Independent periodic callers and error/shutdown paths share one exporter.
void flushAndSendLogs() nothrow {
    try flushLogs((string json) => sendTelemetryJson(logsEndpoint, json));
    catch (Throwable) {
        try stderr.writeln("otel-logs: export error; bounded queue retained");
        catch (Throwable) {}
    }
}

private void flushLogs(scope bool delegate(string) send) {
    if (!g_logsEnabled || !logsMutexInitd) return;
    string json;
    ulong through;
    synchronized (logsMutex) {
        if (logQueue.exporting) return;
        if (logQueue.droppedCount != reportedLoggingDrops) {
            stderr.writeln("otel-logs: dropped_count=", logQueue.droppedCount,
                " dropped_bytes=", logQueue.droppedBytes);
            reportedLoggingDrops = logQueue.droppedCount;
        }
        if (!logQueue.count) return;
        logQueue.exporting = true;
    }
    scope (exit) synchronized (logsMutex) logQueue.exporting = false;
    synchronized (logsMutex) {
        auto batch = logQueue.snapshot();
        scope (exit) batch[] = PendingLog.init;
        through = logQueue.watermark();
        json = buildOtlpLogsJson(batch);
    }
    if (send(json)) {
        synchronized (logsMutex) {
            logQueue.acknowledge(through);
            logQueue.lastExportSuccessAtMs = (Clock.currStdTime - 621_355_968_000_000_000L) / 10_000;
        }
    } else stderr.writeln("otel-logs: export failed; bounded queue retained");
}

private string logsJsonEscape(string s) {
    auto sink = appender!string();
    foreach (c; s) {
        switch (c) {
            case '"':  sink ~= "\\\""; break;
            case '\\': sink ~= "\\\\"; break;
            case '\n': sink ~= "\\n"; break;
            case '\r': sink ~= "\\r"; break;
            case '\t': sink ~= "\\t"; break;
            default:
                if (c < 0x20) sink ~= format("\\u%04x", c);
                else sink ~= cast(char)c;
        }
    }
    return sink.data;
}

private string buildOtlpLogsJson(ref PendingLog[] batch) {
    auto sink = appender!string();
    sink ~= `{"resourceLogs":[{"resource":{"attributes":[`;
    // Resource identity (service.name / k8s.cluster.name / host.name ...) is
    // shared with traces + metrics via otelResourceAttributes so SigNoz Logs
    // Explorer filters and trace correlation line up across all three signals.
    {
        import ircfiber.tracing : otelResourceAttributes;
        bool first = true;
        foreach (kv; otelResourceAttributes(logsServiceName, logsServiceVersion)) {
            if (!first) sink ~= ",";
            first = false;
            sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, logsJsonEscape(kv[0]), logsJsonEscape(kv[1]));
        }
    }
    sink ~= `]},"scopeLogs":[{"scope":{"name":"ircfiber.logging","version":"`;
    sink ~= logsServiceVersion;
    sink ~= `"},"logRecords":[`;
    bool firstRec = true;
    foreach (ref r; batch) {
        if (!firstRec) sink ~= ",";
        firstRec = false;
        sink ~= format(`{"timeUnixNano":"%d","observedTimeUnixNano":"%d","severityNumber":%d,"severityText":"%s","body":{"stringValue":"%s"}`,
                       r.timeUnixNano, r.observedTimeUnixNano, r.severityNumber, r.severityText, logsJsonEscape(r.body));
        if (r.traceId.length) sink ~= format(`,"traceId":"%s"`, r.traceId);
        if (r.spanId.length)  sink ~= format(`,"spanId":"%s"`, r.spanId);
        if (r.traceFlags)     sink ~= format(`,"flags":%d`, r.traceFlags);
        sink ~= `,"attributes":[`;
        bool firstAttr = true;
        foreach (k, v; r.attributes) {
            if (!firstAttr) sink ~= ",";
            firstAttr = false;
            sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, logsJsonEscape(k), logsJsonEscape(v));
        }
        sink ~= `]}`;
    }
    sink ~= `]}]}]}`;
    return sink.data;
}


// Test helpers
PendingLog[] drainLogQueueForTest() {
    if (!logsMutexInitd) return null;
    synchronized (logsMutex) return logQueue.drain();
}

int logQueueLengthForTest() {
    if (!logsMutexInitd) return 0;
    synchronized (logsMutex) return cast(int)logQueue.count;
}

/// Use the same private entry point as logJsonMap, avoiding thousands of
/// irrelevant stderr lines while exercising real OTLP log ownership.
void runLoggingQueueRegressionForTest() {
    import std.array : replicate;
    import std.algorithm : canFind;
    const previous = g_logsEnabled;
    scope (exit) {
        cast(void) drainLogQueueForTest();
        g_logsEnabled = previous;
    }
    cast(void) drainLogQueueForTest();
    setLoggingEnabled(false);
    const disabled = sampleLoggingQueue();
    enqueueLog("info", "test", "disabled", null, "", "");
    flushLogs((string) { assert(false, "disabled logs exported"); return false; });
    assert(sampleLoggingQueue() == disabled);
    setLoggingEnabled(true);
    const initialDrops = sampleLoggingQueue().droppedCount;
    foreach (i; 0 .. LOGGING_MAX_ENTRIES + 3)
        enqueueLog("info", "test", i.to!string, null, "", "");
    auto bounded = sampleLoggingQueue();
    assert(bounded.count > 0 && bounded.count <= LOGGING_MAX_ENTRIES && bounded.bytes <= LOGGING_MAX_BYTES);
    assert(bounded.droppedCount > initialDrops);
    auto batch = drainLogQueueForTest();
    assert(batch[0].body != "0" && batch[$ - 1].body == (LOGGING_MAX_ENTRIES + 2).to!string);
    batch = null;
    auto large = replicate("x", 128 * 1024);
    foreach (i; 0 .. 12) enqueueLog("info", "test", large, ["i": i.to!string], "", "");
    bounded = sampleLoggingQueue();
    assert(bounded.count > 0 && bounded.count < 12 && bounded.bytes <= LOGGING_MAX_BYTES);
    const beforeOversize = sampleLoggingQueue();
    enqueueLog("info", "test", replicate("x", LOGGING_MAX_BYTES / 16), null, "", "");
    auto afterOversize = sampleLoggingQueue();
    assert(afterOversize.count == beforeOversize.count && afterOversize.bytes == beforeOversize.bytes);
    assert(afterOversize.droppedCount == beforeOversize.droppedCount + 1);
    int sends;
    flushLogs((string json) {
        ++sends;
        flushLogs((string) { ++sends; return true; });
        return false;
    });
    assert(sends == 1 && sampleLoggingQueue().count == beforeOversize.count);
    enqueueLog("info", "test", "latest_after_failure", null, "", "");
    flushLogs((string json) {
        assert(json.canFind("latest_after_failure"));
        enqueueLog("info", "test", "arrived_during_export", null, "", "");
        return true;
    });
    auto arrived = drainLogQueueForTest();
    assert(arrived.length == 1 && arrived[0].body == "arrived_during_export");
    enqueueLog("info", "test", "recovery", null, "", "");
    bool threw;
    try flushLogs(delegate bool(string json) { throw new Exception("collector unavailable"); });
    catch (Exception) { threw = true; }
    assert(threw && sampleLoggingQueue().count == 1);
    flushLogs((string) => true);
    assert(sampleLoggingQueue().count == 0 && sampleLoggingQueue().bytes == 0,
        "exception path must release the single-export guard");
}