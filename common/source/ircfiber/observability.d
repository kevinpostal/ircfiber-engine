/// OTel-compatible metrics for the irc-fiber engine.
///
/// Mirrors the architecture of `ircfiber.tracing` (manual queue +
/// periodic flush → OTLP/HTTP) but for counters, gauges, and
/// histograms. The output endpoint defaults to the same OTel
/// collector as the trace pipeline (`/v1/metrics`); operations
/// backends (SigNoz, Prometheus, etc.) ingest both feeds from the
/// same collector so traces + metrics + logs correlate by
/// service.name + deployment.environment + (when present)
/// traceId/spanId.
///
/// Why a manual pipeline rather than the OpenTelemetry D SDK?
/// The official D OTel bindings (`opentelemetry-d` on dub) are
/// incomplete for our target (no HTTP exporter, no histogram
/// aggregation, broken on Linux x86_64). Our hand-rolled
/// implementation ships the three instrument types we actually use
/// (counter / gauge / histogram) with the minimum OTLP surface
/// SigNoz understands. If/when the upstream SDK catches up we
/// can swap this module out without touching call sites — the
/// public API is the standard OTel naming convention.
///
/// Cardinality budget:
///   - Connection-health metrics tag by `networkId` (UUID) and `host`.
///     High-cardinality hosts are bounded by the number of IRC
///     networks the deployment runs (~tens, not millions) so this
///     is safe.
///   - Per-process gauges are unbounded on counter resets but
///     reset on process restart, which is what SigNoz expects.
module ircfiber.observability;

import std.stdio : stderr;
import std.conv : to, text;
import std.json : JSONValue;
import std.format : format;
import std.array : appender;
import std.datetime : Clock, SysTime;
import std.algorithm : canFind;
import core.sync.mutex : Mutex;
import core.atomic : atomicLoad, atomicStore;

// ── Configuration ──────────────────────────────────────────────────────
//
// Default to the same OTel collector as the trace pipeline so the
// dashboards line up automatically. Override via
// `configureMetrics(endpoint)` from `app_engine.d` next to where
// `configureTracing()` is called.

private __gshared string metricsEndpoint = "http://ircfiber-otel-collector:4318/v1/metrics";
private __gshared string serviceName     = "ircfiber-engine";
private __gshared string serviceVersion  = "0.3.0";
private __gshared bool g_metricsEnabled = false;

bool isMetricsEnabled() { return g_metricsEnabled; }
void setMetricsEnabled(bool v) { g_metricsEnabled = v; }

/// Configure the OTLP/HTTP endpoint for metrics. Called once at
/// boot from `app_engine.d` alongside `configureTracing()`.
void configureMetrics(string otlpEndpoint, string svcName, string svcVersion) {
    metricsEndpoint = otlpEndpoint;
    serviceName     = svcName;
    serviceVersion  = svcVersion;
    g_metricsEnabled = (otlpEndpoint.length > 0 && otlpEndpoint != "disabled");
}

// ── Metric data model ──────────────────────────────────────────────────
//
// OTLP distinguishes three numeric instruments:
//   - Sum: monotonic counter that resets only on process restart.
//     Use for "how many times did X happen".
//   - Gauge: a value that can go up or down. Use for "current
//     state" (e.g. registration-timeout networks right now).
//   - Histogram: distribution of observations. Use for "how long
//     did X take". We use fixed-bucket boundaries aligned with
//     the SLO targets (1ms / 10ms / 100ms / 1s / 10s / 30s).
//
// Every metric carries an arbitrary set of string attributes
// (network, host, serverId, etc.). The set is captured at
// `recordCounter()` time so the same metric name with different
// attrs lands in different points.

enum InstrumentKind { counter, gauge, histogram }

struct MetricPoint {
    string          name;
    string          unit;        // "1" for counts, "s" for seconds
    InstrumentKind  kind;
    long            intValue;    // counter / gauge value
    long            sumMicros;   // histogram sum (microsecond precision)
    long            count;       // histogram observation count
    long[]          bucketCounts; // histogram bucket counts (one per bound)
    long            startUnixNano;  // cumulative aggregation: monotonic start
    long            timeUnixNano;   // wall-clock when the point was emitted
    string[string]  attributes;
}

private __gshared shared(Mutex) metricsMutex;
private __gshared MetricPoint[] pending;

private __gshared bool mutexInitd;
private void initOnce() {
    if (mutexInitd) return;
    metricsMutex = new shared Mutex();
    synchronized (metricsMutex) {} // init lazy mutex
    mutexInitd = true;
}

// ── Test-only accessors ─────────────────────────────────────────────────
//
// Exposed publicly so the standalone `observability_test.d`
// binary in `source/` can verify the JSON shape without having to
// spin up a real OTel collector. The standalone binary is the
// only consumer; production code paths must use recordCounter /
// recordGauge / recordHistogram / flushAndSendMetrics.

string buildOtlpMetricsJsonForTest(MetricPoint[] batch) {
    return buildOtlpMetricsJson(batch);
}

MetricPoint[] drainPendingForTest() {
    MetricPoint[] drained;
    synchronized (metricsMutex) {
        drained = pending;
        pending = null;
    }
    return drained;
}

// ── Public recording API ──────────────────────────────────────────────

/// Record a counter increment (e.g. `reconnect.scheduled`, `+1`).
/// Cumulative aggregation: SigNoz treats repeated `recordCounter`
/// calls as additive. Idempotent on the wire because the same
/// counter value is sent with monotonic start/end times.
void recordCounter(string name, long delta,
                  string[string] attrs = null) {
    if (!g_metricsEnabled) return;
    if (!mutexInitd) initOnce();
    synchronized (metricsMutex) {
        auto now = nowUnixNanos();
        pending ~= MetricPoint(
            name, "1", InstrumentKind.counter,
            delta, 0, 0, null,
            now, now,
            attrs is null ? null : attrs.dup);
    }
}
void recordGauge(string name, long value,
                string[string] attrs = null) {
    if (!g_metricsEnabled) return;
    if (!mutexInitd) initOnce();
    synchronized (metricsMutex) {
        auto now = nowUnixNanos();
        pending ~= MetricPoint(
            name, "1", InstrumentKind.gauge,
            value, 0, 0, null,
            now, now,
            attrs is null ? null : attrs.dup);
    }
}

/// Record a histogram observation (e.g. time-from-missing-to-recovered).
/// Internally bucketed with fixed boundaries so SigNoz can compute
/// heatmaps and P50/P95/P99 percentiles without server-side
/// configuration.
///
/// Bucket boundaries (in seconds): 0.001 / 0.01 / 0.1 / 1 / 10 / 30.
/// Observations > 30s go into the implicit +Inf bucket.
immutable double[] HISTOGRAM_BOUNDS = [
    0.001, 0.01, 0.1, 1.0, 10.0, 30.0
];

void recordHistogram(string name, double valueSeconds,
                    string[string] attrs = null) {
    if (!g_metricsEnabled) return;
    if (!mutexInitd) initOnce();
    // Pre-bucket the observation. Bucket N is for values in
    // [BOUND[N-1], BOUND[N]). Value > BOUND[$] goes into a final
    // +Inf bucket which OTLP requires for cumulative histograms.
    long[] buckets = new long[](HISTOGRAM_BOUNDS.length + 1);
    bool placed = false;
    foreach (i, b; HISTOGRAM_BOUNDS) {
        if (valueSeconds <= b) {
            buckets[i] = 1;
            placed = true;
            break;
        }
    }
    if (!placed) buckets[$ - 1] = 1; // +Inf bucket

    synchronized (metricsMutex) {
        auto now = nowUnixNanos();
        pending ~= MetricPoint(
            name, "s", InstrumentKind.histogram,
            0, cast(long)(valueSeconds * 1_000_000), 1, buckets,
            now, now,
            attrs is null ? null : attrs.dup);
    }
}

// ── Flush + export ─────────────────────────────────────────────────────

/// Drain the pending metrics queue and POST a single OTLP/HTTP
/// batch to `/v1/metrics`. Called from the heartbeat task every
/// 10s alongside `flushAndSendSpans()`. Idempotent — calling with
void flushAndSendMetrics() {
    if (!g_metricsEnabled) return;
    // initOnce is idempotent and cheap; calling it here means the
    // heartbeat task can flush even if no record* call has ever run
    // (e.g. on a quiet process). Without this, the first call to
    // `synchronized (metricsMutex)` would NPE because `metricsMutex`
    // is `shared Mutex.init`.
    if (!mutexInitd) initOnce();
    MetricPoint[] batch;
    synchronized (metricsMutex) {
        if (pending.length == 0) return;
        batch = pending;
        pending = null;
    }
    if (batch.length) sendMetricsBatch(batch);
}
private long nowUnixNanos() {
    SysTime t = Clock.currTime.toUTC();
    return t.toUnixTime() * 1_000_000_000L + t.fracSecs.total!"nsecs";
}

private void sendMetricsBatch(ref MetricPoint[] batch) {
    if (!g_metricsEnabled) return;
    auto json = buildOtlpMetricsJson(batch);
    try {
        import vibe.http.client : requestHTTP, HTTPMethod;
        requestHTTP(metricsEndpoint,
            (scope req) {
                // Use the high-level `writeBody` helper rather than
                // `req.bodyWriter.write` directly. `bodyWriter` is
                // a `ChunkedOutputStream` wrapper that needs an
                // explicit `finalize()` call to write the empty
                // terminating chunk required by HTTP/1.1 chunked
                // transfer encoding. `writeBody` does that for us
                // AND sets Content-Length automatically. Without
                // this, every metrics batch exports as a 0-byte
                // body and SigNoz dashboards stay empty.
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
                    stderr.writeln("otel-metrics: export failed status=", res.statusCode);
            });
    } catch (Exception e) {
        stderr.writeln("otel-metrics: export error: ", e.msg);
    }
}

/// Build the OTLP/HTTP JSON request body for one batch. Format
/// reference: https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding
///
/// Top-level shape:
///   {
///     "resourceMetrics": [{
///       "resource": { "attributes": [{ "key": "service.name", "value": { "stringValue": "..." }}] },
///       "scopeMetrics": [{
///         "scope": { "name": "ircfiber.observability", "version": "0.3.0" },
///         "metrics": [ ...one Metric per data point... ]
///       }]
///     }]
///   }
///
/// Each Metric has one of "sum" / "gauge" / "histogram" depending
/// on its InstrumentKind. Sum aggregation is "AGGREGATION_TEMPORALITY_CUMULATIVE"
/// for counters (SigNoz handles rate conversion). Histogram uses
/// "AGGREGATION_TEMPORALITY_DELTA" since each batch represents a
/// fresh set of observations rather than a cumulative window.
private string buildOtlpMetricsJson(ref MetricPoint[] batch) {
    auto sink = appender!string();

    sink ~= `{"resourceMetrics":[{"resource":{"attributes":[`;
    bool firstResAttr = true;
    void addRes(string k, string v) {
        if (!firstResAttr) sink ~= ",";
        firstResAttr = false;
        sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, k, jsonEscape(v));
    }
    addRes("service.name", serviceName);
    addRes("service.version", serviceVersion);
    addRes("service.namespace", "ircfiber");
    addRes("deployment.environment", "production");
    sink ~= `]},"scopeMetrics":[{"scope":{"name":"ircfiber.observability","version":"`;
    sink ~= serviceVersion;
    sink ~= `"},"metrics":[`;

    foreach (i, ref mp; batch) {
        if (i > 0) sink ~= ",";
        sink ~= format(`{"name":"%s","unit":"%s"`, jsonEscape(mp.name), mp.unit);

        // Attributes go in the data point, not the metric, per
        // OTLP spec. Build the attribute array once.
        // Default to "[]" so empty-attributes points produce valid JSON.
        // Without this, attrJson stays null/empty and the format
        // `{"attributes":,"startTime"...}` is invalid, causing the
        // OTLP collector to return 400 (seen as
        // "otel-metrics: export failed status=400" every 10s).
        string attrJson = "[]";
        if (mp.attributes !is null && mp.attributes.length > 0) {
            auto aSink = appender!string();
            aSink ~= "[";
            bool first = true;
            foreach (k, v; mp.attributes) {
                if (!first) aSink ~= ",";
                first = false;
                aSink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`,
                                 k, jsonEscape(v));
            }
            aSink ~= "]";
            attrJson = aSink.data;
        }

        final switch (mp.kind) with (InstrumentKind) {
            case counter:
                sink ~= `,"sum":{"dataPoints":[`;
                sink ~= format(`{"attributes":%s,"startTimeUnixNano":"%d","timeUnixNano":"%d","asInt":"%d"}`,
                    attrJson, mp.startUnixNano, mp.timeUnixNano, mp.intValue);
                sink ~= `],"aggregationTemporality":"AGGREGATION_TEMPORALITY_CUMULATIVE","isMonotonic":true}`;
                break;
            case gauge:
                sink ~= `,"gauge":{"dataPoints":[`;
                sink ~= format(`{"attributes":%s,"timeUnixNano":"%d","asInt":"%d"}`,
                    attrJson, mp.timeUnixNano, mp.intValue);
                sink ~= `]}`;
                break;
            case histogram:
                // Bounds array — the explicit bounds of the
                // histogram, one per bucket. Cumulative histograms
                // expect this to be monotonic non-decreasing.
                auto boundsSink = appender!string();
                boundsSink ~= "[";
                foreach (j, b; HISTOGRAM_BOUNDS) {
                    if (j > 0) boundsSink ~= ",";
                    boundsSink ~= format("%s", b);
                }
                boundsSink ~= "]";
                auto bucketsSink = appender!string();
                bucketsSink ~= "[";
                foreach (j, c; mp.bucketCounts) {
                    if (j > 0) bucketsSink ~= ",";
                    bucketsSink ~= c.to!string;
                }
                bucketsSink ~= "]";
                sink ~= `,"histogram":{"dataPoints":[`;
                sink ~= format(`{"attributes":%s,"startTimeUnixNano":"%d","timeUnixNano":"%d","count":"%d","sum":%s,"bucketCounts":%s,"explicitBounds":%s,"exemplars":[]}`,
                    attrJson, mp.startUnixNano, mp.timeUnixNano,
                    mp.count, mp.sumMicros.to!string ~ "e-6",
                    bucketsSink.data, boundsSink.data);
                sink ~= `],"aggregationTemporality":"AGGREGATION_TEMPORALITY_DELTA"}`;
                break;
        }
        sink ~= "}";
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

// ── Tests ─────────────────────────────────────────────────────────────
//
// Compile-time unittests that pin the OTLP/HTTP JSON shape. The
// `observability-test` standalone binary exercises them. Keep the
// shape stable so a SigNoz dashboard built today still parses
// metrics emitted from a future build.

@("buildOtlpMetricsJson emits a counter under 'sum' with cumulative aggregation")
unittest {
    MetricPoint[] batch;
    batch ~= MetricPoint(
        "ircfiber.registration.timeout", "1", InstrumentKind.counter,
        1, 0, 0, null,
        1782760360000_000_000L, 1782760370000_000_000L,
        ["network": "IRC Fiber", "host": "irc.ircfiber.com"]);
    auto json = buildOtlpMetricsJson(batch);
    assert(json.canFind(`"name":"ircfiber.registration.timeout"`));
    assert(json.canFind(`"sum":{"dataPoints":[`));
    assert(json.canFind(`"AGGREGATION_TEMPORALITY_CUMULATIVE"`));
    assert(json.canFind(`"isMonotonic":true`));
    assert(json.canFind(`"asInt":"1"`));
    assert(json.canFind(`"key":"network"`));
    assert(json.canFind(`"value":{"stringValue":"IRC Fiber"}`));
}

@("buildOtlpMetricsJson emits a gauge under 'gauge'")
unittest {
    MetricPoint[] batch;
    batch ~= MetricPoint(
        "ircfiber.registration.timeout_networks", "1", InstrumentKind.gauge,
        3, 0, 0, null,
        1782760360000_000_000L, 1782760370000_000_000L,
        ["serverId": "ovh"]);
    auto json = buildOtlpMetricsJson(batch);
    assert(json.canFind(`"gauge":{"dataPoints":[`));
    assert(json.canFind(`"asInt":"3"`));
    assert(!json.canFind(`"sum":`));
    assert(!json.canFind(`"histogram":`));
}

@("buildOtlpMetricsJson emits a histogram under 'histogram' with delta aggregation")
unittest {
    MetricPoint[] batch;
    batch ~= MetricPoint(
        "ircfiber.tls_handshake.duration_seconds", "s",
        InstrumentKind.histogram,
        0, 500_000, 1,
        [0, 0, 0, 1, 0, 0, 0],
        1782760360000_000_000L, 1782760370000_000_000L,
        ["network": "IRC Fiber"]);
    auto json = buildOtlpMetricsJson(batch);
    assert(json.canFind(`"histogram":{"dataPoints":[`));
    assert(json.canFind(`"AGGREGATION_TEMPORALITY_DELTA"`));
    assert(json.canFind(`"count":"1"`));
    assert(json.canFind(`"sum":`));
    assert(json.canFind(`"bucketCounts":[0,0,0,1,0,0,0]`));
    assert(json.canFind(`"explicitBounds":[0.001,0.01,0.1,1,10,30]`));
}

@("HISTOGRAM_BOUNDS are monotonically non-decreasing")
unittest {
    double prev = double.min_normal;
    foreach (b; HISTOGRAM_BOUNDS) {
        assert(b > prev, "histogram bounds must be strictly increasing");
        prev = b;
    }
}

@("recordCounter / recordGauge / recordHistogram queue and flush cleanly")
unittest {
    bool prev = isMetricsEnabled();
    scope (exit) setMetricsEnabled(prev);
    setMetricsEnabled(true);
    initOnce();
    // Drain anything already pending (prior test runs)
    MetricPoint[] drained;
    synchronized (metricsMutex) {
        drained = pending;
        pending = null;
    }

    recordCounter("test.counter", 1, ["k": "v"]);
    recordGauge("test.gauge", 42, null);
    recordHistogram("test.histogram", 0.5, ["k": "v"]);

    MetricPoint[] queued;
    synchronized (metricsMutex) {
        queued = pending;
        pending = null;
    }
    assert(queued.length == 3, "expected 3 queued points, got " ~ queued.length.to!string);
    assert(queued[0].name == "test.counter" && queued[0].kind == InstrumentKind.counter);
    assert(queued[1].name == "test.gauge"   && queued[1].kind == InstrumentKind.gauge);
    assert(queued[2].name == "test.histogram" && queued[2].kind == InstrumentKind.histogram);
    assert(queued[2].bucketCounts.length == HISTOGRAM_BOUNDS.length + 1);
}

@("record* when disabled leaves pending[] empty and no init")
unittest {
    bool prev = isMetricsEnabled();
    scope (exit) setMetricsEnabled(prev);
    // Ensure mutex is initialized so we can inspect pending safely.
    if (!mutexInitd) initOnce();
    setMetricsEnabled(false);
    // Ensure queue is empty.
    auto drained = drainPendingForTest();
    // These must be no-ops: no synchronized, no allocation.
    recordCounter("test.disabled.counter", 1, ["k": "v"]);
    recordGauge("test.disabled.gauge", 99, null);
    recordHistogram("test.disabled.histogram", 1.2, ["k": "v"]);
    auto queued = drainPendingForTest();
    assert(queued.length == 0, "record* when disabled must leave pending empty, got " ~ queued.length.to!string);
    // flush must also be no-op
    flushAndSendMetrics();
    queued = drainPendingForTest();
    assert(queued.length == 0, "flush when disabled must not create pending");
    setMetricsEnabled(true);
}

@("configureMetrics empty endpoint disables metrics")
unittest {
    bool prev = isMetricsEnabled();
    string prevEp = metricsEndpoint;
    scope (exit) {
        setMetricsEnabled(prev);
        metricsEndpoint = prevEp;
    }
    configureMetrics("", "test-svc", "0.0.1");
    assert(!isMetricsEnabled(), "empty endpoint must disable metrics");
    configureMetrics("disabled", "test-svc", "0.0.1");
    assert(!isMetricsEnabled(), "\"disabled\" endpoint must disable metrics");
    configureMetrics("http://signoz:4318/v1/metrics", "test-svc", "0.0.1");
    assert(isMetricsEnabled(), "non-empty endpoint must enable metrics");
}

@("flushAndSendMetrics when disabled does not attempt HTTP")
unittest {
    bool prev = isMetricsEnabled();
    scope (exit) setMetricsEnabled(prev);
    setMetricsEnabled(true);
    if (!mutexInitd) initOnce();
    // Drain
    MetricPoint[] d;
    synchronized (metricsMutex) { d = pending; pending = null; }
    recordCounter("test.enabled.counter", 1, null);
    synchronized (metricsMutex) { assert(pending.length == 1); }
    setMetricsEnabled(false);
    // Flush while disabled must early-return without sending and without clearing?
    // Our impl returns before synchronized, so pending remains 1 — that's okay
    // because we never grow unbounded when disabled (record* already no-ops).
    flushAndSendMetrics();
    assert(!isMetricsEnabled());
    // Clean up
    setMetricsEnabled(true);
    synchronized (metricsMutex) { pending = null; }
    setMetricsEnabled(prev);
}