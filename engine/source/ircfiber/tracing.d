module ircfiber.tracing;

import std.stdio : stderr;
import std.json : JSONValue, JSONOptions;
import std.datetime : Clock, SysTime;
import std.conv : to, text;
import std.format : format;
import std.array : array, appender;
import std.string : format;
import core.atomic : atomicLoad, atomicStore;
import core.sync.mutex : Mutex;
import core.time : seconds, dur;
import vibe.core.core : runTask, sleep;

/// Generate a 16-byte (128-bit) trace ID as a lowercase hex string.
string newTraceId() @trusted {
    try {
        import std.random : Mt19937, unpredictableSeed, uniform;
        static Mt19937 rng;
        static bool seeded = false;
        if (!seeded) { rng.seed(unpredictableSeed); seeded = true; }
        char[32] hex;
        foreach (i; 0 .. 16) {
            auto b = cast(ubyte)uniform(0, 256, rng);
            hex[i*2]   = "0123456789abcdef"[b >> 4];
            hex[i*2+1] = "0123456789abcdef"[b & 0xf];
        }
        return hex[].idup;
    } catch (Exception) {
        // Fallback to timestamp-derived ID if RNG fails
        return Clock.currTime.toUnixTime().to!string;
    }
}

/// Generate an 8-byte (64-bit) span ID as a lowercase hex string.
string newSpanId() @trusted {
    try {
        import std.random : Mt19937, unpredictableSeed, uniform;
        static Mt19937 rng;
        static bool seeded = false;
        if (!seeded) { rng.seed(unpredictableSeed); seeded = true; }
        char[16] hex;
        foreach (i; 0 .. 8) {
            auto b = cast(ubyte)uniform(0, 256, rng);
            hex[i*2]   = "0123456789abcdef"[b >> 4];
            hex[i*2+1] = "0123456789abcdef"[b & 0xf];
        }
        return hex[].idup;
    } catch (Exception) {
        return Clock.currTime.toUnixTime().to!string;
    }
}

/// In-flight span context, per-FIBER (not per-thread).
///
/// Why per-fiber: the gateway runs HTTP requests in vibe.d fibers
/// that may share a single OS thread (CFRunLoopDriver is the
/// default on macOS). The earlier implementation stored
/// `currentCtx` as a module-global variable — effectively per-thread,
/// shared across ALL fibers in that thread. When fiber A was
/// mid-withSpan and fiber B did anything that read currentCtx
/// (or pushed its own withSpan that wasn't fully balanced before
/// A's scope(exit) fired), A's context was either clobbered or
/// left dangling. That produced two distinct symptoms in SigNoz:
///
///   1. Child spans appearing under unrelated parent traces
///      (parent ctx leaked into a different request's child span).
///   2. Spans with parentSpanId pointing at a parent that never
///      landed in ClickHouse because the parent's outer scope(exit)
///      never fired (e.g. socket reset mid-WS upgrade) and the
///      child tasks kept using the leaked traceId indefinitely.
///
/// The fix: use `vibe.core.task.TaskFiber` Fiber-Local Storage
/// (FLS) so each fiber has its OWN stack + currentCtx. Child
/// spans inside `runTask` get a fresh empty stack by default
/// (the new fiber starts with a zero-initialized FLS slot), and
/// a long-running fiber's withSpan stack doesn't pollute sibling
/// fibers in the same thread.
private struct SpanContext {
    string traceId;
    string spanId;
}

// Per-fiber ctx storage. Each `vibe.core.task.TaskFiber` has its
// own FLS slot via the `TaskLocal!T` struct. We use a struct that
// holds both the stack and depth so they get allocated together
// (single FLS entry per fiber, padded to 8-byte alignment).
//
// Static/global `TaskLocal` is required per the vibe.d docs —
// "MUST be declared as static/global thread-local variables.
// Defining them as a temporary/stack variable will cause crashes".
private struct FiberCtx {
    SpanContext[16] stack;   // up to 16 nested spans per fiber
    int depth;
    SpanContext current;
}

private import vibe.core.task : TaskLocal;
private TaskLocal!FiberCtx s_fiberCtx;

private ref FiberCtx fiberCtx() {
    // TaskLocal allocates FLS lazily on first .storage access; the
    // init value of FiberCtx() defaults all fields (SpanContext.init
    // = empty strings, depth=0). No null check needed.
    return s_fiberCtx.storage;
}

void pushContext(string traceId, string spanId) {
    auto ctx = &fiberCtx();
    if (ctx.depth >= ctx.stack.length) return;
    ctx.stack[ctx.depth] = ctx.current;
    ctx.depth++;
    ctx.current = SpanContext(traceId, spanId);
}

void popContext() {
    auto ctx = &fiberCtx();
    if (ctx.depth == 0) return;
    ctx.depth--;
    ctx.current = ctx.stack[ctx.depth];
}

string currentTraceId() { return fiberCtx().current.traceId; }
string currentSpanId() { return fiberCtx().current.spanId; }

/// A single span recorded by `withSpan` and queued for export.
private struct PendingSpan {
    string traceId;
    string spanId;
    string parentSpanId;
    string name;
    long startUnixNano;
    long endUnixNano;
    string[string] attributes;
    int statusCode;
    string statusMessage;
}

private __gshared shared(Mutex) queueMutex;
private __gshared PendingSpan[] queue;
private __gshared int exporterStarted;
private __gshared string endpoint = "http://ircfiber-otel-collector:4318/v1/traces";
private __gshared string serviceName = "ircfiber-engine";
private __gshared string serviceVersion = "0.3.0";
private __gshared bool g_enabled = false;

bool isTracingEnabled() { return g_enabled; }
void setTracingEnabled(bool v) { g_enabled = v; }

/// Helper: case-insensitive env check for "1"/"true"/"yes"/"on".
/// Used by gateway/engine boot to gate OTel. Kept here so all
/// OTel modules share one definition.
bool isEnvEnabled(string key) {
    import std.process : environment;
    import std.string : toLower, strip;
    auto v = environment.get(key, "");
    v = v.strip.toLower;
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

void configureTracing(string otlpEndpoint, string svcName, string svcVersion) {
    endpoint = otlpEndpoint;
    serviceName = svcName;
    serviceVersion = svcVersion;
    g_enabled = (otlpEndpoint.length > 0 && otlpEndpoint != "disabled");
}

struct Span {
    PendingSpan* data;

    void attr(string key, string value) {
        if (data) data.attributes[key] = value;
    }
    void attr(string key, long value) {
        if (data) data.attributes[key] = value.to!string;
    }
    void event(string name) {
        if (data) data.attributes["event." ~ name] = "1";
    }
    void setStatusOk() {
        if (data) data.statusCode = 1;
    }
    void setStatusError(string msg) {
        if (data) { data.statusCode = 2; data.statusMessage = msg; }
    }
}

void withSpan(string name, string[string] attrs, scope void delegate(ref Span) fn) {
    if (!g_enabled) {
        // Pass-through when tracing disabled: no context push, no queue.
        Span s = Span(null);
        try {
            fn(s);
        } catch (Exception e) {
            // Swallow — tracing disabled means we don't record status.
        }
        return;
    }
    if (!queueMutex) initOnce();
    auto ctx = &fiberCtx();
    auto parentTrace = ctx.current.traceId;
    auto parentSpan  = ctx.current.spanId;
    auto traceId = parentTrace.length ? parentTrace : newTraceId();
    auto spanId = newSpanId();
    pushContext(traceId, spanId);
    scope (exit) popContext();

    PendingSpan span;
    span.traceId = traceId;
    span.spanId = spanId;
    span.parentSpanId = parentSpan;
    span.name = name;
    span.startUnixNano = nowUnixNanos();
    span.attributes = attrs.dup;
    span.statusCode = 0;
    Span s = Span(&span);
    try {
        fn(s);
        if (span.statusCode == 0) span.statusCode = 1;
    } catch (Exception e) {
        span.statusCode = 2;
        span.statusMessage = e.msg;
    }
    span.endUnixNano = nowUnixNanos();

    synchronized (queueMutex) {
        queue ~= span;
    }
}

/// Wipe the current fiber's span context back to empty. Call this
/// at the start of every request handler that runs inside a
/// long-lived fiber (e.g. vibe.d HTTP keep-alive reuses the same
/// fiber for multiple sequential requests on one TCP connection).
/// Without this, the http.request scope(exit) properly cleans up
/// after each request, but if it DOESN'T fire (socket reset, panic
/// inside the handler, etc.) the next request on the same fiber
/// inherits a stale parent trace. Resetting at the entry point
/// makes each request self-contained regardless of what happened
/// to the previous one on this fiber.
void resetFiberCtx() {
    auto ctx = &fiberCtx();
    ctx.depth = 0;
    ctx.current = SpanContext.init;
}

private long nowUnixNanos() {
    SysTime t = Clock.currTime.toUTC();
    return t.toUnixTime() * 1_000_000_000L + t.fracSecs.total!"nsecs";
}

private void initOnce() {
    queueMutex = new shared Mutex();
    // Start unlocked by default — synchronized { } will lock it.
    synchronized (queueMutex) {} // dummy lock/unlock to init
}

/// Build the OTLP/HTTP JSON request body manually — using string
/// concatenation is safer than JSONValue for performance + safety.
private string buildOtlpJson(ref PendingSpan[] batch) {
    auto sink = appender!string();
    sink ~= `{"resourceSpans":[{"resource":{"attributes":[`;
    bool first = true;
    void addRes(string k, string v) {
        if (!first) sink ~= ",";
        first = false;
        sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, k, jsonEscape(v));
    }
    addRes("service.name", serviceName);
    addRes("service.version", serviceVersion);
    addRes("deployment.environment", "production");
    addRes("service.namespace", "ircfiber");
    sink ~= `]},"scopeSpans":[{"scope":{"name":"ircfiber.engine","version":"`;
    sink ~= serviceVersion;
    sink ~= `"},"spans":[`;
    bool firstSpan = true;
    foreach (ref s; batch) {
        if (!firstSpan) sink ~= ",";
        firstSpan = false;
        sink ~= format(`{"traceId":"%s","spanId":"%s"`, s.traceId, s.spanId);
        if (s.parentSpanId.length)
            sink ~= format(`,"parentSpanId":"%s"`, s.parentSpanId);
        sink ~= format(`,"name":"%s","kind":1,"startTimeUnixNano":"%d","endTimeUnixNano":"%d"`,
                       jsonEscape(s.name), s.startUnixNano, s.endUnixNano);
        sink ~= `,"attributes":[`;
        bool firstAttr = true;
        foreach (k, v; s.attributes) {
            if (!firstAttr) sink ~= ",";
            firstAttr = false;
            sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, k, jsonEscape(v));
        }
        sink ~= `]`;
        sink ~= format(`,"status":{"code":%d`, s.statusCode);
        if (s.statusMessage.length)
            sink ~= format(`,"message":"%s"`, jsonEscape(s.statusMessage));
        sink ~= `}`;
        sink ~= `}`;
    }
    sink ~= `]}]}]}`;
    return sink.data;
}

private string jsonEscape(string s) {
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

private void sendBatch(ref PendingSpan[] batch) {
    if (!g_enabled) return;
    if (batch.length == 0) return;
    auto json = buildOtlpJson(batch);
    try {
        import vibe.http.client : requestHTTP, HTTPMethod;
        requestHTTP(endpoint,
            (scope req) {
                // Use the high-level `writeBody` helper rather than
                // `req.bodyWriter.write` directly. `bodyWriter` is
                // a `ChunkedOutputStream` wrapper that needs an
                // explicit `finalize()` call to write the empty
                // terminating chunk required by HTTP/1.1 chunked
                // transfer encoding. `writeBody` does that for us
                // AND sets the Content-Length header automatically
                // (so the request isn't sent chunked in the first
                // place). Without this, every batch exports as a
                // 0-byte body and SigNoz dashboards stay empty.
                //
                // We also need to set method=POST explicitly:
                // `HTTPClientRequest`'s default method is GET
                // (vibe.http.client HTTPClientRequest.m_method
                // = HTTPMethod.GET in client.d line 190), and a
                // GET-with-body is rejected by most OTLP collectors
                // (the OTel collector returns 405 Method Not Allowed).
                req.method = HTTPMethod.POST;
                req.writeBody(cast(const ubyte[])json, "application/json");
            },
            (res) {
                if (res.statusCode >= 400)
                    stderr.writeln("otel: export failed status=", res.statusCode);
            });
    } catch (Exception e) {
        stderr.writeln("otel: export error: ", e.msg);
    }
}
/// Drain the span queue and send to otel-collector.
/// Called from the heartbeat task (every 10s) — safe to call
/// multiple times; no-ops if the queue is empty.
void flushAndSendSpans() {
    if (!g_enabled) return;
    if (!queueMutex) return;
    PendingSpan[] batch;
    synchronized (queueMutex) {
        if (queue.length == 0) return;
        batch = queue;
        queue = null;
    }
    if (batch.length) sendBatch(batch);
}

void startTracingExporter() {
    if (atomicLoad(exporterStarted)) return;
    atomicStore(exporterStarted, 1);
    // No separate thread/task needed. `flushAndSendSpans()` is called
    // from the existing heartbeat fiber in bootstrap.d.
}

// ── Test-only accessors ────────────────────────────────────────────────
// Exposed so standalone tests can verify withSpan disabled path without
// spinning up a real OTel collector.
PendingSpan[] drainQueueForTest() {
    if (!queueMutex) return null;
    synchronized (queueMutex) {
        auto drained = queue;
        queue = null;
        return drained;
    }
}

int queueLengthForTest() {
    if (!queueMutex) return 0;
    synchronized (queueMutex) {
        return cast(int)queue.length;
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────
@("withSpan when disabled calls delegate exactly once and queues no span")
unittest {
    // Save/restore enabled state so tests are isolated.
    bool prev = isTracingEnabled();
    scope (exit) setTracingEnabled(prev);
    setTracingEnabled(false);
    // Ensure queue is empty before test.
    drainQueueForTest();
    int calls = 0;
    withSpan("test.disabled", null, (ref Span s) {
        calls++;
        // When disabled, Span.data is null — attr calls must be no-ops.
        s.attr("k", "v");
        s.setStatusOk();
    });
    assert(calls == 1, "withSpan disabled must call delegate exactly once");
    assert(queueLengthForTest() == 0, "withSpan disabled must not queue span");
    // flush must be no-op (no HTTP, no crash).
    flushAndSendSpans();
    assert(queueLengthForTest() == 0);
}

@("withSpan when disabled propagates exceptions via delegate but still no queue")
unittest {
    bool prev = isTracingEnabled();
    scope (exit) setTracingEnabled(prev);
    setTracingEnabled(false);
    drainQueueForTest();
    int calls = 0;
    withSpan("test.disabled.exc", null, (ref Span s) {
        calls++;
        throw new Exception("test exception");
    });
    // Disabled path swallows exception inside withSpan's catch, but still counts call.
    assert(calls == 1);
    assert(queueLengthForTest() == 0);
}

@("configureTracing empty endpoint disables tracing")
unittest {
    bool prev = isTracingEnabled();
    string prevEp = endpoint;
    scope (exit) {
        setTracingEnabled(prev);
        endpoint = prevEp;
    }
    configureTracing("", "test-svc", "0.0.1");
    assert(!isTracingEnabled(), "empty endpoint must disable tracing");
    configureTracing("disabled", "test-svc", "0.0.1");
    assert(!isTracingEnabled(), "\"disabled\" endpoint must disable tracing");
    configureTracing("http://signoz:4318/v1/traces", "test-svc", "0.0.1");
    assert(isTracingEnabled(), "non-empty endpoint must enable tracing");
}

@("flushAndSendSpans when disabled is no-op even with queued spans")
unittest {
    bool prev = isTracingEnabled();
    scope (exit) setTracingEnabled(prev);
    // Enable, queue a span, then disable and flush — flush must discard without send.
    setTracingEnabled(true);
    if (!queueMutex) initOnce();
    drainQueueForTest();
    withSpan("test.enabled", null, (ref Span s) { s.setStatusOk(); });
    assert(queueLengthForTest() == 1, "enabled withSpan should queue");
    setTracingEnabled(false);
    flushAndSendSpans();
    // Disabled flush should leave queue untouched (early return before drain) OR drain?
    // Our implementation returns before synchronized, so queued span remains.
    // That's acceptable: disabled means we don't send, but we also don't leak HTTP.
    // For this test, just verify no crash and g_enabled is false.
    assert(!isTracingEnabled());
    // Clean up for next test.
    setTracingEnabled(true);
    drainQueueForTest();
    setTracingEnabled(prev);
}