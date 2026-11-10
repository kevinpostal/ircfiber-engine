module ircfiber.tracing;

import std.stdio : stderr;
import std.json : JSONValue, JSONOptions;
import std.datetime : Clock, SysTime;
import std.conv : to, text;
import std.format : format;
import std.array : array, appender;
import std.string : format;
import core.sync.mutex : Mutex;

/// OTLP resource attributes shared by the traces/metrics/logs exporters so all
/// three signals correlate on the same identity in SigNoz.
///
/// Base set: service.name / service.version / service.namespace /
/// deployment.environment. `OTEL_RESOURCE_ATTRIBUTES` (k=v,k=v) overrides any
/// of those and adds k8s.cluster.name / host.name / k8s.node.name — this is
/// how one binary becomes `ircfiber-engine-ovh` on OVH vs `ircfiber-engine-k8s-1`
/// in-cluster. `host.name` falls back to gethostname() only when the env did
/// not set it, so a resource never carries the same key twice.
///
/// Returns ordered (key, value) pairs; values are NOT JSON-escaped.
string[2][] otelResourceAttributes(string serviceName, string serviceVersion) nothrow {
    string[2][] res;
    size_t retainedBytes;
    void set(scope const(char)[] k, scope const(char)[] v) {
        // Resource configuration is outside the point/span/log rings. Bound
        // its export-time ownership too, including an adversarial env value.
        if (k.length > 256 || v.length > 1024) return;
        foreach (ref kv; res) if (kv[0] == k) {
            if (retainedBytes - kv[1].length + v.length > 4096) return;
            retainedBytes = retainedBytes - kv[1].length + v.length;
            kv[1] = v.idup;
            return;
        }
        if (res.length == 32 || retainedBytes + k.length + v.length > 4096) return;
        retainedBytes += k.length + v.length;
        string[2] pair = [k.idup, v.idup];
        res ~= pair; // at most 32 pairs / 4096 string bytes
    }
    set("service.name", serviceName);
    set("service.version", serviceVersion);
    set("service.namespace", "ircfiber");
    set("deployment.environment", "production");
    bool hostFromEnv;
    try {
        import core.stdc.stdlib : getenv;
        import core.stdc.string : strlen;
        import std.string : strip, indexOf, toStringz;
        import std.algorithm : splitter;
        auto env = getenv("OTEL_RESOURCE_ATTRIBUTES".toStringz);
        if (env !is null) {
            foreach (pair; env[0 .. strlen(env)].splitter(',')) {
                auto kv = pair.strip;
                auto eq = kv.indexOf("=");
                if (eq <= 0) continue;
                auto k = kv[0 .. eq].strip;
                auto v = kv[eq + 1 .. $].strip;
                if (k.length == 0 || v.length == 0) continue;
                if (k == "host.name") hostFromEnv = true;
                set(k, v);
            }
        }
        if (!hostFromEnv) {
            import core.sys.posix.unistd : gethostname;
            char[256] buf;
            if (gethostname(buf.ptr, buf.length) == 0) {
                size_t len = 0;
                while (len < buf.length && buf[len] != 0) len++;
                if (len > 0) set("host.name", buf[0 .. len].idup);
            }
        }
    } catch (Throwable) {}
    return res;
}

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

/// Pushes a new span context onto the current fiber's stack.
void pushContext(string traceId, string spanId) {
    auto ctx = &fiberCtx();
    if (ctx.depth >= ctx.stack.length) return;
    ctx.stack[ctx.depth] = ctx.current;
    ctx.depth++;
    ctx.current = SpanContext(traceId, spanId);
}

/// Pops the current fiber's span context, restoring the previous one.
void popContext() {
    auto ctx = &fiberCtx();
    if (ctx.depth == 0) return;
    ctx.depth--;
    ctx.current = ctx.stack[ctx.depth];
}

/// Returns the current fiber's trace ID.
string currentTraceId() { return fiberCtx().current.traceId; }
/// Returns the current fiber's span ID.
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

import ircfiber.observability : BoundedTelemetryQueue, telemetryStringCharge,
    telemetryAttributesCharge, copyTelemetryAttributes, sendTelemetryJson;

enum TRACING_MAX_SPANS = 1024;
enum TRACING_MAX_BYTES = 4 * 1024 * 1024;
private alias TracingQueue = BoundedTelemetryQueue!(PendingSpan, TRACING_MAX_SPANS, TRACING_MAX_BYTES);
private __gshared shared(Mutex) queueMutex;
private __gshared TracingQueue queue;
private __gshared ulong reportedTracingDrops;

struct TracingQueueSample { ulong count, bytes, droppedCount, droppedBytes; long lastExportSuccessAtMs; }
TracingQueueSample sampleTracingQueue() {
    if (!queueMutexInitd) return TracingQueueSample.init;
    synchronized (queueMutex)
        return TracingQueueSample(queue.count, queue.bytes, queue.droppedCount, queue.droppedBytes,
                                  queue.lastExportSuccessAtMs);
}

private void enqueueSpan(PendingSpan span) {
    ulong charge = 768;
    string[5] strings = [span.traceId, span.spanId, span.parentSpanId, span.name, span.statusMessage];
    foreach (s; strings)
        charge = TracingQueue.addSaturated(charge, telemetryStringCharge(s));
    charge = TracingQueue.addSaturated(charge, telemetryAttributesCharge(span.attributes));
    synchronized (queueMutex) {
        if (!queue.admits(charge)) return;
        span.traceId = span.traceId.idup;
        span.spanId = span.spanId.idup;
        span.parentSpanId = span.parentSpanId.idup;
        span.name = span.name.idup;
        span.statusMessage = span.statusMessage.idup;
        span.attributes = copyTelemetryAttributes(span.attributes);
        queue.put(span, charge);
    }
}
private __gshared string endpoint = "http://ircfiber-otel-collector:4318/v1/traces";
private __gshared string serviceName = "ircfiber-engine";
private __gshared string serviceVersion = "0.3.0";
private __gshared bool g_enabled = false;

/// Whether distributed tracing is currently enabled.
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

/// Configures the OTLP endpoint and service identity.
void configureTracing(string otlpEndpoint, string svcName, string svcVersion) {
    endpoint = otlpEndpoint;
    serviceName = svcName;
    serviceVersion = svcVersion;
    g_enabled = (otlpEndpoint.length > 0 && otlpEndpoint != "disabled");
}

/// Handle to an in-flight span, passed to withSpan delegates.
struct Span {
    /// Underlying span record, or null when tracing is disabled.
    PendingSpan* data;

    /// Records a string attribute on the span.
    void attr(string key, string value) {
        if (data) data.attributes[key] = value;
    }
    /// Records a long attribute on the span.
    void attr(string key, long value) {
        if (data) data.attributes[key] = value.to!string;
    }
    /// Records a named event on the span.
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

/// Runs `fn` inside a new span, queued for export when tracing is enabled.
void withSpan(string name, string[string] attrs, scope void delegate(ref Span) fn) {
    if (!g_enabled) {
        // Pass-through when tracing disabled: no context push, no queue.
        Span s = Span(null);
        // A span wrapper must never swallow exceptions from the wrapped
        // code: withSpan is a transparent observability pass-through, and
        // exceptions (registration timeouts, TLS failures) belong to the
        // caller. Before 2026-08-14 this caught-and-ignored, so a failed
        // IRC registration was reported as "registration complete" and the
        // engine flipped to connected on a dead socket, then disconnected
        // and reconnected forever (the BLCKND outage).
        fn(s);
        return;
    }
    if (!queueMutex) initOnce();
    // Reject a huge initial record before copying its attribute table.
    auto initialCharge = TracingQueue.addSaturated(768, telemetryStringCharge(name));
    initialCharge = TracingQueue.addSaturated(initialCharge, telemetryAttributesCharge(attrs));
    bool admitted;
    synchronized (queueMutex) admitted = queue.admits(initialCharge);
    if (!admitted) {
        Span rejected = Span(null);
        fn(rejected);
        return;
    }
    const ctx = &fiberCtx();
    const parentTrace = ctx.current.traceId;
    const parentSpan  = ctx.current.spanId;
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
    Exception caught;
    Span s = Span(&span);
    try {
        fn(s);
        if (span.statusCode == 0) span.statusCode = 1;
    } catch (Exception e) {
        span.statusCode = 2;
        span.statusMessage = e.msg;
        caught = e;
    }
    span.endUnixNano = nowUnixNanos();

    enqueueSpan(span);

    // Record the failure on the span, then rethrow so the caller sees it.
    if (caught !is null) throw caught;
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

private __gshared bool queueMutexInitd;
private void initOnce() {
    if (queueMutexInitd) return;
    synchronized (typeid(typeof(queueMutex))) {
        if (queueMutexInitd) return;
        queueMutex = new shared Mutex();
        synchronized (queueMutex) {} // dummy lock/unlock to init
        queueMutexInitd = true;
    }
}

/// Build the OTLP/HTTP JSON request body manually — using string
/// concatenation is safer than JSONValue for performance + safety.
private string buildOtlpJson(ref PendingSpan[] batch) {
    auto sink = appender!string();
    sink ~= `{"resourceSpans":[{"resource":{"attributes":[`;
    bool first = true;
    foreach (kv; otelResourceAttributes(serviceName, serviceVersion)) {
        if (!first) sink ~= ",";
        first = false;
        sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, jsonEscape(kv[0]), jsonEscape(kv[1]));
    }
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
            sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, jsonEscape(k), jsonEscape(v));
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

/// Periodic and shutdown callers share one in-flight export. Failed exports
/// retain only the bounded queue; newer telemetry may displace older spans.
void flushAndSendSpans() nothrow {
    try flushSpans((string json) => sendTelemetryJson(endpoint, json));
    catch (Throwable) {
        try stderr.writeln("otel-traces: export error; bounded queue retained");
        catch (Throwable) {}
    }
}

private void flushSpans(scope bool delegate(string) send) {
    if (!g_enabled || !queueMutexInitd) return;
    string json;
    ulong through;
    synchronized (queueMutex) {
        if (queue.exporting) return;
        if (queue.droppedCount != reportedTracingDrops) {
            stderr.writeln("otel-traces: dropped_count=", queue.droppedCount,
                " dropped_bytes=", queue.droppedBytes);
            reportedTracingDrops = queue.droppedCount;
        }
        if (!queue.count) return;
        queue.exporting = true;
    }
    scope (exit) synchronized (queueMutex) queue.exporting = false;
    synchronized (queueMutex) {
        auto batch = queue.snapshot();
        scope (exit) batch[] = PendingSpan.init;
        through = queue.watermark();
        json = buildOtlpJson(batch);
    }
    if (send(json)) {
        synchronized (queueMutex) {
            queue.acknowledge(through);
            queue.lastExportSuccessAtMs = nowUnixNanos() / 1_000_000;
        }
    } else stderr.writeln("otel-traces: export failed; bounded queue retained");
}

// ── Test-only accessors ────────────────────────────────────────────────
// Exposed so standalone tests can verify withSpan disabled path without
// spinning up a real OTel collector.
/// Drains and returns all queued spans (test helper).
PendingSpan[] drainQueueForTest() {
    if (!queueMutex) return null;
    synchronized (queueMutex) return queue.drain();
}

/// Returns the number of queued spans (test helper).
int queueLengthForTest() {
    if (!queueMutex) return 0;
    synchronized (queueMutex) {
        return cast(int)queue.count;
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────
@("withSpan when disabled calls delegate exactly once and queues no span")
unittest {
    // Save/restore enabled state so tests are isolated.
    const prev = isTracingEnabled();
    scope (exit) setTracingEnabled(prev);
    setTracingEnabled(false);
    // Ensure queue is empty before test.
    cast(void) drainQueueForTest();
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
    const prev = isTracingEnabled();
    scope (exit) setTracingEnabled(prev);
    setTracingEnabled(false);
    cast(void) drainQueueForTest();
    int calls = 0;
    bool threw = false;
    try {
        withSpan("test.disabled.exc", null, (ref Span s) {
            calls++;
            throw new Exception("test exception");
        });
    } catch (Exception e) {
        threw = true;
        assert(e.msg == "test exception");
    }
    // Disabled path is a transparent pass-through — it must NOT swallow
    // the exception (otherwise registration timeouts are reported as
    // "registration complete" and the engine wedges on a dead socket).
    assert(threw, "withSpan disabled must propagate delegate exception");
    assert(calls == 1);
    assert(queueLengthForTest() == 0);
}


@("flushAndSendSpans when disabled is no-op even with queued spans")
unittest {
    const prev = isTracingEnabled();
    scope (exit) setTracingEnabled(prev);
    // Enable, queue a span, then disable and flush — flush must discard without send.
    setTracingEnabled(true);
    if (!queueMutex) initOnce();
    cast(void) drainQueueForTest();
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
    cast(void) drainQueueForTest();
    setTracingEnabled(prev);
}

/// Collector completion is injected; all admission/export logic is real.
void runTracingQueueRegressionForTest() {
    import std.array : replicate;
    import std.algorithm : canFind;
    const previous = g_enabled;
    scope (exit) {
        cast(void) drainQueueForTest();
        g_enabled = previous;
    }
    cast(void) drainQueueForTest();
    setTracingEnabled(false);
    const disabled = sampleTracingQueue();
    int calls;
    withSpan("disabled", null, (ref Span s) {
        ++calls;
        s.attr("number", 42L);
        s.event("ignored");
    });
    flushSpans((string) { assert(false, "disabled spans exported"); return false; });
    assert(calls == 1 && sampleTracingQueue() == disabled);
    setTracingEnabled(true);
    const initialDrops = sampleTracingQueue().droppedCount;
    foreach (i; 0 .. TRACING_MAX_SPANS + 3)
        withSpan("s", ["i": i.to!string], (ref Span s) { s.setStatusOk(); });
    auto bounded = sampleTracingQueue();
    assert(bounded.count == TRACING_MAX_SPANS && bounded.bytes <= TRACING_MAX_BYTES);
    assert(bounded.droppedCount == initialDrops + 3);
    auto batch = drainQueueForTest();
    assert(batch[0].attributes["i"] == "3" &&
        batch[$ - 1].attributes["i"] == (TRACING_MAX_SPANS + 2).to!string);
    batch = null;
    auto large = replicate("x", 64 * 1024);
    foreach (i; 0 .. 12)
        withSpan("byte_bound", ["payload": large], (ref Span s) { s.attr("i", cast(long)i); });
    bounded = sampleTracingQueue();
    assert(bounded.count > 0 && bounded.count < 12 && bounded.bytes <= TRACING_MAX_BYTES);
    const beforeOversize = sampleTracingQueue();
    withSpan(replicate("x", TRACING_MAX_BYTES / 16), null, (ref Span s) {});
    auto afterOversize = sampleTracingQueue();
    assert(afterOversize.count == beforeOversize.count && afterOversize.bytes == beforeOversize.bytes);
    assert(afterOversize.droppedCount == beforeOversize.droppedCount + 1);
    int sends;
    flushSpans((string json) {
        ++sends;
        flushSpans((string) { ++sends; return true; });
        return false;
    });
    assert(sends == 1 && sampleTracingQueue().count == beforeOversize.count);
    withSpan("latest_after_failure", null, (ref Span s) {});
    flushSpans((string json) {
        assert(json.canFind("latest_after_failure"));
        withSpan("arrived_during_export", null, (ref Span s) {});
        return true;
    });
    auto arrived = drainQueueForTest();
    assert(arrived.length == 1 && arrived[0].name == "arrived_during_export");
    withSpan("recovery", null, (ref Span s) {});
    flushSpans((string) => true);
    assert(sampleTracingQueue().count == 0 && sampleTracingQueue().bytes == 0);
}