/// Sentry-protocol error reporting (Bugsink-compatible) for the irc-fiber
/// gateway and engine.
///
/// Mirrors the architecture of `ircfiber.tracing` / `ircfiber.observability`
/// / `ircfiber.logging` — a module-level enabled flag + configure function,
/// read once at boot — but is an INDEPENDENT on/off switch
/// (IRCFIBER_BUGSINK_ENABLED / IRCFIBER_BUGSINK_DSN), not tied to
/// IRCFIBER_OTEL_ENABLED. Ops can disable error reporting without touching
/// traces/metrics/logs — e.g. when the Bugsink server itself is down — and
/// vice versa.
///
/// Wire protocol: Sentry's legacy "store" endpoint
/// (`POST {base}/api/{project_id}/store/`), authenticated via the
/// `X-Sentry-Auth` header (`Sentry sentry_version=7, sentry_key=<key>,
/// sentry_client=<name>/<version>`) — the same header every Sentry SDK
/// sends, confirmed against Bugsink's `compat.auth.parse_auth_header_value`.
/// No per-frame structured stacktrace: D's `Throwable.info` yields only
/// pre-formatted multi-line text, not file/function/line triples, so the
/// full trace goes into `extra.stack_trace` as a string (visible in
/// Bugsink's event detail view) rather than fabricating fake frames.
module ircfiber.errors;

import std.stdio : stderr;
import std.format : format;
import std.array : appender;
import std.datetime : Clock;

// ── Configuration ──────────────────────────────────────────────────────

private __gshared string g_ingestUrl;      // https://host[:port]/api/<id>/store/
private __gshared string g_sentryKey;
private __gshared string g_serviceName    = "ircfiber-engine";
private __gshared string g_serviceVersion = "0.3.0";
private __gshared string g_environment    = "production";
private __gshared bool   g_enabled        = false;

/// Whether Bugsink error reporting is currently enabled.
bool isErrorReportingEnabled() { return g_enabled; }
void setErrorReportingEnabled(bool v) { g_enabled = v; }

/// A parsed Sentry DSN (`scheme://key@host[:port]/project_id`).
private struct ParsedDsn {
    string scheme;
    string key;
    string hostPort;
    string projectId;
    bool   valid;
}

/// Parses a Sentry DSN. No regex (house style avoids it in this package) —
/// three manual splits on "://", "@", and the last "/".
private ParsedDsn parseDsn(string dsn) {
    ParsedDsn p;
    import std.string : indexOf, lastIndexOf;
    auto schemeEnd = dsn.indexOf("://");
    if (schemeEnd <= 0) return p;
    p.scheme = dsn[0 .. schemeEnd];
    auto rest = dsn[schemeEnd + 3 .. $];
    auto at = rest.indexOf("@");
    if (at <= 0) return p;
    p.key = rest[0 .. at];
    auto hostAndPath = rest[at + 1 .. $];
    auto slash = hostAndPath.lastIndexOf("/");
    if (slash <= 0 || slash == hostAndPath.length - 1) return p;
    p.hostPort = hostAndPath[0 .. slash];
    p.projectId = hostAndPath[slash + 1 .. $];
    if (p.scheme.length == 0 || p.hostPort.length == 0 || p.projectId.length == 0) return p;
    p.valid = true;
    return p;
}

/// Configures error reporting from a DSN. Empty or unparseable DSN leaves
/// reporting disabled (fail-safe, matching `configureTracing`/
/// `configureMetrics`/`configureLogging`'s "empty endpoint → disabled").
/// Does NOT itself flip `g_enabled` to true — callers (boot code) call
/// `setErrorReportingEnabled(true)` explicitly afterward, same two-step
/// pattern `setupOtel()` uses for the other three exporters.
void configureErrorReporting(string dsn, string svcName, string svcVersion,
                             string environment = "production") {
    g_serviceName = svcName;
    g_serviceVersion = svcVersion;
    g_environment = environment;
    if (dsn.length == 0 || dsn == "disabled") { g_enabled = false; return; }
    auto p = parseDsn(dsn);
    if (!p.valid) {
        try stderr.writeln("bugsink: unparseable DSN, error reporting stays disabled");
        catch (Throwable) {}
        g_enabled = false;
        return;
    }
    g_sentryKey = p.key;
    g_ingestUrl = p.scheme ~ "://" ~ p.hostPort ~ "/api/" ~ p.projectId ~ "/store/";
}

// ── JSON body ─────────────────────────────────────────────────────────

private string jsonEscape(string s) {
    auto sink = appender!string();
    foreach (c; s) {
        switch (c) {
            case '"':  sink ~= `\"`; break;
            case '\\': sink ~= `\\`; break;
            case '\n': sink ~= `\n`; break;
            case '\r': sink ~= `\r`; break;
            case '\t': sink ~= `\t`; break;
            default:
                if (c < 0x20) sink ~= format("\\u%04x", cast(int) c);
                else sink ~= cast(char) c;
        }
    }
    return sink.data;
}

private string hostName() {
    try {
        import core.sys.posix.unistd : gethostname;
        char[256] buf;
        if (gethostname(buf.ptr, buf.length) == 0) {
            size_t len = 0;
            while (len < buf.length && buf[len] != 0) len++;
            if (len > 0) return buf[0 .. len].idup;
        }
    } catch (Throwable) {}
    return "unknown";
}

private string buildSentryEventJson(string component, Throwable e, string context,
                                    string[string] extra, string eventId, string timestamp) {
    auto msg = context.length ? context : e.msg;
    auto sink = appender!string();
    sink ~= format(
        `{"event_id":"%s","timestamp":"%s","platform":"other","level":"error",` ~
        `"logger":"ircfiber.%s","message":"%s","server_name":"%s","release":"%s",` ~
        `"environment":"%s","exception":{"values":[{"type":"%s","value":"%s"}]}`,
        eventId, jsonEscape(timestamp), jsonEscape(component), jsonEscape(msg),
        jsonEscape(hostName()), jsonEscape(g_serviceVersion), jsonEscape(g_environment),
        jsonEscape(e.classinfo.name), jsonEscape(e.msg));
    sink ~= format(`,"tags":{"component":"%s","service":"%s"}`,
        jsonEscape(component), jsonEscape(g_serviceName));
    sink ~= format(`,"extra":{"stack_trace":"%s"`, jsonEscape(e.info.toString()));
    foreach (k, v; extra) sink ~= format(`,"%s":"%s"`, jsonEscape(k), jsonEscape(v));
    sink ~= `}}`;
    return sink.data;
}

// ── Capture + send ───────────────────────────────────────────────────

/// Reports one exception to Bugsink. No-op when disabled. Fire-and-forget,
/// synchronous within the calling fiber (same characteristic as
/// `flushAndSendLogs`'s "best-effort immediate flush" and every other
/// exporter's `sendXBatch` in this package) — a down/unreachable Bugsink
/// fails the HTTP connect quickly, is caught below, and is dropped; it
/// never retries and never throws into the caller. No explicit
/// connect/read timeout, matching the three sibling OTLP exporters in this
/// same package (they also rely on vibe.d's default socket behavior); a
/// true hang blocks only the calling fiber, not other requests or fibers
/// (vibe.d's cooperative scheduler), the same accepted risk this codebase
/// already carries for traces/metrics/logs.
void captureException(string component, Throwable e, string context = "",
                      string[string] extra = null) nothrow {
    if (!g_enabled) return;
    try {
        import ircfiber.tracing : newTraceId;
        auto eventId = newTraceId(); // 32 lowercase hex — exactly Sentry's event_id shape
        auto timestamp = Clock.currTime.toUTC().toISOExtString();
        auto json = buildSentryEventJson(component, e, context, extra, eventId, timestamp);
        auto auth = "Sentry sentry_version=7, sentry_key=" ~ g_sentryKey ~ ", sentry_client=ircfiber-d/" ~ g_serviceVersion;
        import vibe.http.client : requestHTTP, HTTPMethod;
        requestHTTP(g_ingestUrl,
            (scope req) {
                req.method = HTTPMethod.POST;
                req.headers["X-Sentry-Auth"] = auth;
                req.writeBody(cast(const ubyte[]) json, "application/json");
            },
            (res) {
                if (res.statusCode >= 400)
                    stderr.writeln("bugsink: capture failed status=", res.statusCode);
            });
    } catch (Throwable ex) {
        string m;
        try { m = ex.msg; } catch (Throwable) { m = "unknown"; }
        try stderr.writeln("bugsink: capture error: ", m);
        catch (Throwable) {}
    }
}

// ── Tests ────────────────────────────────────────────────────────────

unittest {
    auto p = parseDsn("https://abc123@ubuntu-docker.tail544547.ts.net:8443/1");
    assert(p.valid);
    assert(p.scheme == "https");
    assert(p.key == "abc123");
    assert(p.hostPort == "ubuntu-docker.tail544547.ts.net:8443");
    assert(p.projectId == "1");
}

unittest {
    assert(!parseDsn("").valid);
    assert(!parseDsn("not-a-dsn").valid);
    assert(!parseDsn("https://nokeyhere.example.com/1").valid); // no "@" → no key
    assert(!parseDsn("https://key@host.example.com/").valid);   // empty project id
}

unittest {
    configureErrorReporting("", "test-svc", "0.0.1");
    assert(!isErrorReportingEnabled()); // configure alone never flips it true
    configureErrorReporting("disabled", "test-svc", "0.0.1");
    assert(!isErrorReportingEnabled());
}
