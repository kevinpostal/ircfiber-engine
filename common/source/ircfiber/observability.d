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

/// Whether metrics are currently enabled.
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

/// OTLP instrument kind (counter, gauge, or histogram).
enum InstrumentKind { counter, gauge, histogram }

/// A single metric data point pending export.
struct MetricPoint {
    /// Metric name.
    string          name;
    /// Unit ("1" for counts, "s" for seconds).
    string          unit;        // "1" for counts, "s" for seconds
    /// Instrument kind.
    InstrumentKind  kind;
    /// Counter / gauge value.
    long            intValue;    // counter / gauge value
    /// Histogram sum (microsecond precision).
    long            sumMicros;   // histogram sum (microsecond precision)
    /// Histogram observation count.
    long            count;       // histogram observation count
    /// Histogram bucket counts (one per bound).
    long[]          bucketCounts; // histogram bucket counts (one per bound)
    /// Cumulative aggregation start time (monotonic).
    long            startUnixNano;  // cumulative aggregation: monotonic start
    /// Wall-clock time the point was emitted.
    long            timeUnixNano;   // wall-clock when the point was emitted
    /// Metric attributes.
    string[string]  attributes;
}

enum METRICS_MAX_POINTS = 4096;
enum METRICS_MAX_BYTES = 4 * 1024 * 1024;

/// Fixed owner storage shared by the three telemetry signals. Byte charges
/// include private string copies, AA overhead and worst-case JSON expansion.
package(ircfiber) struct BoundedTelemetryQueue(T, size_t capacity, ulong byteLimit) {
    private T[capacity] slots;
    private ulong[capacity] charges;
    private ulong[capacity] sequences;
    private size_t head;
    size_t count;
    ulong bytes, droppedCount, droppedBytes;
    private ulong nextSequence;
    long lastExportSuccessAtMs;
    bool exporting;

    static ulong addSaturated(ulong a, ulong b) {
        return b > ulong.max - a ? ulong.max : a + b;
    }

    void drop(ulong charge) {
        droppedCount = addSaturated(droppedCount, 1);
        droppedBytes = addSaturated(droppedBytes, charge);
    }

    private void pop(bool dropped) {
        if (dropped) drop(charges[head]);
        bytes -= charges[head];
        slots[head] = T.init; // release all owned references, including AAs
        charges[head] = sequences[head] = 0;
        head = (head + 1) % capacity;
        --count;
    }

    bool admits(ulong charge) {
        if (charge <= byteLimit) return true;
        drop(charge);
        return false;
    }

    void put(T item, ulong charge) {
        assert(charge <= byteLimit);
        while (count == capacity || bytes > byteLimit - charge) pop(true);
        auto tail = (head + count) % capacity;
        slots[tail] = item;
        charges[tail] = charge;
        sequences[tail] = ++nextSequence;
        bytes += charge;
        ++count;
    }

    /// Allocate exactly once at a known fixed bound, never append or slice
    /// an ever-growing owner. Used only during synchronous JSON construction.
    T[] snapshot() {
        auto batch = new T[count];
        foreach (i; 0 .. count) batch[i] = slots[(head + i) % capacity];
        return batch;
    }

    ulong watermark() { return nextSequence; }
    void acknowledge(ulong through) {
        while (count && sequences[head] <= through) pop(false);
    }
    T[] drain() {
        auto batch = snapshot();
        while (count) pop(false);
        return batch;
    }
}

/// Charge both retention and encoding conservatively; clone accepted strings
/// so a tiny substring cannot pin an arbitrarily large backing allocation.
package(ircfiber) ulong telemetryStringCharge(string value) {
    return value.length > (ulong.max - 64) / 32
        ? ulong.max : 64 + cast(ulong)value.length * 32;
}

package(ircfiber) ulong telemetryAttributesCharge(string[string] attrs) {
    ulong result;
    alias Q = BoundedTelemetryQueue!(int, 1, 1);
    foreach (k, v; attrs) {
        result = Q.addSaturated(result, 256);
        result = Q.addSaturated(result, telemetryStringCharge(k));
        result = Q.addSaturated(result, telemetryStringCharge(v));
    }
    return result;
}

package(ircfiber) string[string] copyTelemetryAttributes(string[string] attrs) {
    string[string] copy;
    foreach (k, v; attrs) copy[k.idup] = v.idup;
    return copy;
}

/// An overall fiber deadline also bounds write/drain time, not merely reads.
/// Never logs through logging.d: collector/drop diagnostics must stay local.
package(ircfiber) bool sendTelemetryJson(string endpoint, string json) {
    import core.time : seconds;
    import vibe.core.core : setTimer;
    import vibe.core.task : Task;
    import vibe.http.client : requestHTTP, HTTPMethod, HTTPClientSettings;
    auto task = Task.getThis();
    if (task == Task.init) return false; // a native caller cannot honor a fiber deadline
    auto deadline = setTimer(5.seconds, { task.interrupt(); });
    scope (exit) deadline.stop();
    auto settings = new HTTPClientSettings;
    settings.connectTimeout = 2.seconds;
    settings.readTimeout = 2.seconds;
    settings.defaultKeepAliveTimeout = 0.seconds;
    bool accepted;
    requestHTTP(endpoint,
        (scope req) {
            req.method = HTTPMethod.POST;
            req.headers["Connection"] = "close";
            req.writeBody(cast(const ubyte[])json, "application/json");
        },
        (scope res) {
            accepted = res.statusCode >= 200 && res.statusCode < 300;
            // No unbounded response buffering; requestHTTP drains/disconnects.
        }, settings);
    return accepted;
}

private __gshared shared(Mutex) metricsMutex;
private alias MetricsQueue = BoundedTelemetryQueue!(MetricPoint, METRICS_MAX_POINTS, METRICS_MAX_BYTES);
private __gshared MetricsQueue pending;
private __gshared ulong reportedMetricsDrops;

struct MetricsQueueSample { ulong count, bytes, droppedCount, droppedBytes; long lastExportSuccessAtMs; }
MetricsQueueSample sampleMetricsQueue() {
    if (!mutexInitd) return MetricsQueueSample.init;
    synchronized (metricsMutex)
        return MetricsQueueSample(pending.count, pending.bytes, pending.droppedCount, pending.droppedBytes,
                                  pending.lastExportSuccessAtMs);
}

private void enqueueMetric(MetricPoint point) {
    auto charge = MetricsQueue.addSaturated(768 + point.bucketCounts.length * 32,
        telemetryStringCharge(point.name));
    charge = MetricsQueue.addSaturated(charge, telemetryStringCharge(point.unit));
    charge = MetricsQueue.addSaturated(charge, telemetryAttributesCharge(point.attributes));
    synchronized (metricsMutex) {
        if (!pending.admits(charge)) return;
        point.name = point.name.idup;
        point.unit = point.unit.idup;
        point.attributes = copyTelemetryAttributes(point.attributes);
        pending.put(point, charge);
    }
}

private __gshared bool mutexInitd;
private void initOnce() {
    if (mutexInitd) return;
    synchronized (typeid(typeof(metricsMutex))) {
        if (mutexInitd) return;
        metricsMutex = new shared Mutex();
        synchronized (metricsMutex) {} // init lazy mutex
        mutexInitd = true;
    }
}

// ── Test-only accessors ─────────────────────────────────────────────────
//
// Exposed publicly so the standalone `observability_test.d`
// binary in `source/` can verify the JSON shape without having to
// spin up a real OTel collector. The standalone binary is the
// only consumer; production code paths must use recordCounter /
// recordGauge / recordHistogram / flushAndSendMetrics.

/// Builds the OTLP metrics JSON for a batch (test helper).
string buildOtlpMetricsJsonForTest(MetricPoint[] batch) {
    return buildOtlpMetricsJson(batch);
}

/// Drains and returns all pending metric points (test helper).
MetricPoint[] drainPendingForTest() {
    if (!mutexInitd) return null;
    synchronized (metricsMutex) return pending.drain();
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
    auto now = nowUnixNanos();
    enqueueMetric(MetricPoint(
        name, "1", InstrumentKind.counter,
        delta, 0, 0, null, now, now, attrs));
}
/// Records a gauge observation.
void recordGauge(string name, long value,
                string[string] attrs = null) {
    if (!g_metricsEnabled) return;
    if (!mutexInitd) initOnce();
    auto now = nowUnixNanos();
    enqueueMetric(MetricPoint(
        name, "1", InstrumentKind.gauge,
        value, 0, 0, null, now, now, attrs));
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

/// Records a histogram observation.
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

    auto now = nowUnixNanos();
    enqueueMetric(MetricPoint(
        name, "s", InstrumentKind.histogram,
        0, cast(long)(valueSeconds * 1_000_000), 1, buckets,
        now, now, attrs));
}

// ── Flush + export ─────────────────────────────────────────────────────

/// Independent periodic callers may overlap shutdown/error flushes. Only one
/// export owns a payload; failure keeps the bounded ring for the next attempt.
void flushAndSendMetrics() nothrow {
    try flushMetrics((string json) => sendTelemetryJson(metricsEndpoint, json));
    catch (Throwable) {
        try stderr.writeln("otel-metrics: export error; bounded queue retained");
        catch (Throwable) {}
    }
}

private void flushMetrics(scope bool delegate(string) send) {
    if (!g_metricsEnabled || !mutexInitd) return;
    string json;
    ulong through;
    synchronized (metricsMutex) {
        if (pending.exporting) return;
        if (pending.droppedCount != reportedMetricsDrops) {
            stderr.writeln("otel-metrics: dropped_count=", pending.droppedCount,
                " dropped_bytes=", pending.droppedBytes);
            reportedMetricsDrops = pending.droppedCount;
        }
        if (!pending.count) return;
        pending.exporting = true;
    }
    scope (exit) synchronized (metricsMutex) pending.exporting = false;
    synchronized (metricsMutex) {
        auto batch = pending.snapshot();
        scope (exit) batch[] = MetricPoint.init;
        through = pending.watermark();
        json = buildOtlpMetricsJson(batch);
    }
    if (send(json)) {
        synchronized (metricsMutex) {
            pending.acknowledge(through);
            pending.lastExportSuccessAtMs = nowUnixNanos() / 1_000_000;
        }
    } else stderr.writeln("otel-metrics: export failed; bounded queue retained");
}
private long nowUnixNanos() {
    SysTime t = Clock.currTime.toUTC();
    return t.toUnixTime() * 1_000_000_000L + t.fracSecs.total!"nsecs";
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
    {
        import ircfiber.tracing : otelResourceAttributes;
        bool firstResAttr = true;
        foreach (kv; otelResourceAttributes(serviceName, serviceVersion)) {
            if (!firstResAttr) sink ~= ",";
            firstResAttr = false;
            sink ~= format(`{"key":"%s","value":{"stringValue":"%s"}}`, jsonEscape(kv[0]), jsonEscape(kv[1]));
        }
    }
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
                                 jsonEscape(k), jsonEscape(v));
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
                sink ~= format(`{"attributes":%s,"startTimeUnixNano":"%d","timeUnixNano":"%d","count":"%d","sum":%s,`
                    ~ `"bucketCounts":%s,"explicitBounds":%s,"exemplars":[]}`,
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
        1_782_760_360_000_000_000L, 1_782_760_370_000_000_000L,
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
        1_782_760_360_000_000_000L, 1_782_760_370_000_000_000L,
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
        1_782_760_360_000_000_000L, 1_782_760_370_000_000_000L,
        ["network": "IRC Fiber"]);
    auto json = buildOtlpMetricsJson(batch);
    assert(json.canFind(`"histogram":{"dataPoints":[`));
    assert(json.canFind(`"AGGREGATION_TEMPORALITY_DELTA"`));
    assert(json.canFind(`"count":"1"`));
    assert(json.canFind(`"sum":`));
    assert(json.canFind(`"bucketCounts":[0,0,0,1,0,0,0]`));
    assert(json.canFind(`"explicitBounds":[0.001,0.01,0.1,1,10,30]`));
}


@("recordCounter / recordGauge / recordHistogram queue and flush cleanly")
unittest {
    const prev = isMetricsEnabled();
    scope (exit) setMetricsEnabled(prev);
    setMetricsEnabled(true);
    initOnce();
    // Drain anything already pending (prior test runs)
    cast(void) drainPendingForTest();

    recordCounter("test.counter", 1, ["k": "v"]);
    recordGauge("test.gauge", 42, null);
    recordHistogram("test.histogram", 0.5, ["k": "v"]);

    auto queued = drainPendingForTest();
    assert(queued.length == 3, "expected 3 queued points, got " ~ queued.length.to!string);
    assert(queued[0].name == "test.counter" && queued[0].kind == InstrumentKind.counter);
    assert(queued[1].name == "test.gauge"   && queued[1].kind == InstrumentKind.gauge);
    assert(queued[2].name == "test.histogram" && queued[2].kind == InstrumentKind.histogram);
    assert(queued[2].bucketCounts.length == HISTOGRAM_BOUNDS.length + 1);
}

@("record* when disabled leaves pending[] empty and no init")
unittest {
    const prev = isMetricsEnabled();
    scope (exit) setMetricsEnabled(prev);
    // Ensure mutex is initialized so we can inspect pending safely.
    if (!mutexInitd) initOnce();
    setMetricsEnabled(false);
    // Ensure queue is empty.
    cast(void) drainPendingForTest();
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


@("flushAndSendMetrics when disabled does not attempt HTTP")
unittest {
    const prev = isMetricsEnabled();
    scope (exit) setMetricsEnabled(prev);
    setMetricsEnabled(true);
    if (!mutexInitd) initOnce();
    // Drain
    cast(void) drainPendingForTest();
    recordCounter("test.enabled.counter", 1, null);
    assert(sampleMetricsQueue().count == 1);
    setMetricsEnabled(false);
    // Disabled flushing leaves existing bounded data available for re-enable.
    flushAndSendMetrics();
    assert(!isMetricsEnabled());
    // Clean up
    setMetricsEnabled(true);
    cast(void) drainPendingForTest();
    setMetricsEnabled(prev);
}

/// Behavioral regressions invoked by the existing standalone telemetry test.
/// Inject only transport completion, exercising the production queue/export
/// path without contacting a collector or requiring an event loop.
void runMetricsQueueRegressionForTest() {
    import std.array : replicate;
    const previous = g_metricsEnabled;
    scope (exit) {
        cast(void) drainPendingForTest();
        g_metricsEnabled = previous;
    }
    cast(void) drainPendingForTest();
    setMetricsEnabled(false);
    const disabled = sampleMetricsQueue();
    recordCounter("disabled", 1);
    recordGauge("disabled", 1);
    recordHistogram("disabled", 1);
    flushMetrics((string) { assert(false, "disabled metrics exported"); return false; });
    assert(sampleMetricsQueue() == disabled, "disabled metrics mutated queue/drop counters");

    setMetricsEnabled(true);
    const initialDrops = sampleMetricsQueue().droppedCount;
    foreach (i; 0 .. METRICS_MAX_POINTS + 17) recordCounter("m", i);
    auto bounded = sampleMetricsQueue();
    assert(bounded.count == METRICS_MAX_POINTS && bounded.bytes <= METRICS_MAX_BYTES);
    assert(bounded.droppedCount == initialDrops + 17, "metrics must drop oldest at count limit");
    auto batch = drainPendingForTest();
    assert(batch[0].intValue == 17 && batch[$ - 1].intValue == METRICS_MAX_POINTS + 16);
    batch = null;

    auto large = replicate("x", 64 * 1024);
    foreach (i; 0 .. 12) recordCounter("byte_bound", i, ["payload": large]);
    bounded = sampleMetricsQueue();
    assert(bounded.count > 0 && bounded.count < 12 && bounded.bytes <= METRICS_MAX_BYTES,
        "metrics byte budget must evict old points");
    const beforeOversize = sampleMetricsQueue();
    recordCounter(replicate("x", METRICS_MAX_BYTES / 16), 1);
    auto afterOversize = sampleMetricsQueue();
    assert(afterOversize.count == beforeOversize.count && afterOversize.bytes == beforeOversize.bytes);
    assert(afterOversize.droppedCount == beforeOversize.droppedCount + 1);
    int sends;
    flushMetrics((string json) {
        ++sends;
        flushMetrics((string) { ++sends; return true; });
        return false;
    });
    assert(sends == 1 && sampleMetricsQueue().count == beforeOversize.count,
        "failed metrics must remain bounded/retryable; overlapping exporter must not run");
    recordCounter("latest_after_failure", 42);
    flushMetrics((string json) {
        assert(json.canFind("latest_after_failure"), "latest metric missing after collector recovery");
        recordCounter("arrived_during_export", 43);
        return true;
    });
    auto arrived = drainPendingForTest();
    assert(arrived.length == 1 && arrived[0].name == "arrived_during_export",
        "successful metrics export acknowledged an item outside its watermark");
    recordCounter("recovery", 44);
    flushMetrics((string) => true);
    assert(sampleMetricsQueue().count == 0 && sampleMetricsQueue().bytes == 0);

    // Small owned fixture exercises wrap/clearing and saturating diagnostics
    // without assigning enormous values to production counters.
    BoundedTelemetryQueue!(string, 2, 10) ring;
    ring.put("first", 4);
    ring.put("second", 4);
    ring.put("third", 4);
    assert(ring.droppedCount == 1 && ring.bytes == 8);
    auto retained = ring.drain();
    assert(retained == ["second", "third"] && ring.bytes == 0);
    foreach (slot; ring.slots) assert(slot is null, "vacated slot retained telemetry");
    ring.droppedCount = ulong.max - 1;
    ring.droppedBytes = ulong.max - 2;
    ring.drop(5);
    ring.drop(5);
    assert(ring.droppedCount == ulong.max && ring.droppedBytes == ulong.max);
}