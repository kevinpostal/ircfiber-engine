module ircfiber.logging;

import std.stdio : stderr;
import std.json : JSONValue, JSONOptions;
import std.datetime : Clock, SysTime;
import std.conv : to;
import std.string : strip, toStringz;
import std.format : format;

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
        auto s = env[0 .. strlen(env)];
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
}

/// Convenience: tagged info log with no extra fields beyond component.
void logInfoJ(string component, string msg, string network = "") {
    if (network.length)
        logJsonMap("info", component, msg, ["network": network]);
    else
        logJsonMap("info", component, msg);
}
void logWarnJ(string component, string msg, string network = "") {
    if (network.length)
        logJsonMap("warn", component, msg, ["network": network]);
    else
        logJsonMap("warn", component, msg);
}
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
    } catch (Exception secondary) {
        // We are already in an error path — never throw from here.
        try stderr.writeln("logException failed: ", secondary.msg);
        catch (Exception) {}
    }
}