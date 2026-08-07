/// Standalone test for the OTel metrics pipeline.
///
/// Verifies the JSON shape produced by
/// `ircfiber.observability.buildOtlpMetricsJson` against the OTLP
/// 1.5 spec for counter / gauge / histogram data points. SigNoz
/// ingests these directly via the otel-collector; a shape drift
/// silently breaks every dashboard panel. Pinning it here means
/// a future refactor fails this test instead of breaking operations.
///
/// Run with: `make observability-test`.
module observability_test;

import std.stdio : stderr, writeln;
import std.algorithm : canFind;
import std.conv : to;

import ircfiber.observability;
import ircfiber.tracing : withSpan, Span, isTracingEnabled, setTracingEnabled,
    flushAndSendSpans, configureTracing;
import ircfiber.tracing : drainQueueForTest, queueLengthForTest;

/// Tracks the number of passing checks.
int passed;
/// Tracks the number of failing checks.
int failed;

/// Records the outcome of a single named check.
void ok(string name, bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("  ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("  ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

// Helper: build a single-point batch and return the JSON shape.
private string buildOne(InstrumentKind kind, string name, string unit,
                        long intValue, long sumMicros, long count,
                        long[] bucketCounts,
                        long startNs, long timeNs,
                        string[string] attrs = null) {
    MetricPoint[] batch;
    batch ~= MetricPoint(name, unit, kind, intValue, sumMicros, count,
                          bucketCounts, startNs, timeNs, attrs);
    return buildOtlpMetricsJsonForTest(batch);
}

/// Runs the OTLP metrics contract test scenarios.
void runMetricsTests() {
    stderr.writeln("\n[observability] OTLP /v1/metrics JSON contract");

    // Drain anything already pending so the test starts from a
    // clean queue (in case the test binary is reused across runs).
    flushAndSendMetrics(); // no-op if empty

// ── Case 1: counter payload shape. SigNoz + Prometheus both
    // expect: name, sum.dataPoints[], aggregationTemporality
    // CUMULATIVE, isMonotonic:true on the sum.
    {
        auto json = buildOne(InstrumentKind.counter,
            "ircfiber.registration.timeout", "1",
            1, 0, 0, null,
            1_782_760_360_000_000_000L, 1_782_760_370_000_000_000L,
            ["network": "IRC Fiber",
             "host": "irc.ircfiber.com:6697"]);
        const bool shapeOk = json.canFind(`"name":"ircfiber.registration.timeout"`)
            && json.canFind(`"unit":"1"`)
            && json.canFind(`"sum":{"dataPoints":[`)
            && json.canFind(`"AGGREGATION_TEMPORALITY_CUMULATIVE"`)
            && json.canFind(`"isMonotonic":true`)
            && json.canFind(`"asInt":"1"`)
            && json.canFind(`"key":"network"`)
            && json.canFind(`"value":{"stringValue":"IRC Fiber"}`);
        ok("counter shape pins Sum + Cumulative + isMonotonic",
            shapeOk, "got: " ~ json);
    }

    // ── Case 2: gauge payload shape. Gauges use the `gauge` field
    // (not sum), omit aggregationTemporality + isMonotonic. Must
    // NOT include "sum" or "histogram" keys.
    {
        auto json = buildOne(InstrumentKind.gauge,
            "ircfiber.registration.timeout_networks", "1",
            3, 0, 0, null,
            1_782_760_360_000_000_000L, 1_782_760_370_000_000_000L,
            ["serverId": "ovh"]);
        const bool shapeOk = json.canFind(`"gauge":{"dataPoints":[`)
            && json.canFind(`"asInt":"3"`)
            && !json.canFind(`"sum":`)
            && !json.canFind(`"histogram":`)
            && !json.canFind(`"AGGREGATION_TEMPORALITY"`);
        ok("gauge shape pins Gauge + no sum/histogram leakage",
            shapeOk, "got: " ~ json);
    }

    // ── Case 3: histogram payload shape. Histograms use the
    // `histogram` field, DELTA aggregation (cumulative is for
    // counters), explicit bucket bounds aligned with our SLO
    // buckets (1ms / 10ms / 100ms / 1s / 10s / 30s).
    {
        // Observation: 0.5s. Should land in the [0.1, 1.0) bucket.
        auto json = buildOne(InstrumentKind.histogram,
            "ircfiber.tls_handshake.duration_seconds", "s",
            0, 500_000, 1,
            [0, 0, 0, 1, 0, 0, 0],   // +1 in 4th bucket (= [0.1, 1.0))
            1_782_760_360_000_000_000L, 1_782_760_370_000_000_000L,
            ["network": "IRC Fiber"]);
        const bool shapeOk = json.canFind(`"histogram":{"dataPoints":[`)
            && json.canFind(`"AGGREGATION_TEMPORALITY_DELTA"`)
            && json.canFind(`"count":"1"`)
            && json.canFind(`"sum":`)
            && json.canFind(`"bucketCounts":[0,0,0,1,0,0,0]`)
            && json.canFind(`"explicitBounds":[0.001,0.01,0.1,1,10,30]`)
            && json.canFind(`"unit":"s"`);
        ok("histogram shape pins DELTA aggregation + bucket bounds + counts",
           shapeOk, "got: " ~ json);
    }

    // ── Case 4: resource attributes are present and stable.
    // SigNoz uses service.name to demux feeds from multiple
    // services. If this drifts, dashboards aggregate across
    // engine+gateway incorrectly.
    {
        auto json = buildOne(InstrumentKind.counter,
            "test.metric", "1", 1, 0, 0, null, 1, 2, null);
        const bool shapeOk = json.canFind(`"key":"service.name"`)
            && json.canFind(`"value":{"stringValue":"ircfiber-engine"}`)
            && json.canFind(`"key":"service.namespace"`)
            && json.canFind(`"value":{"stringValue":"ircfiber"}`)
            && json.canFind(`"key":"deployment.environment"`)
            && json.canFind(`"value":{"stringValue":"production"}`);
        ok("resource attributes pin service.name + service.namespace + environment",
           shapeOk, "got: " ~ json);
    }

    // ── Case 5: queue + flush contract. recordCounter / recordGauge
    // / recordHistogram each push one metric point and the queue
    // drains via flushAndSendMetrics.
    {
        // Enable metrics for this case (default is disabled).
        const bool prevMetrics = isMetricsEnabled();
        scope (exit) setMetricsEnabled(prevMetrics);
        setMetricsEnabled(true);
        // Drain first so we measure just THIS case
        flushAndSendMetrics();
        drainPendingForTest();

        recordCounter("test.flush.counter", 1, ["k": "v"]);
        recordGauge("test.flush.gauge", 42, null);
        recordHistogram("test.flush.histogram", 0.5, ["k": "v"]);

        auto queued = drainPendingForTest();
        ok("queue accumulates exactly 3 metric points",
           queued.length == 3,
           "expected 3, got " ~ queued.length.to!string);
        ok("queue preserves FIFO order",
           queued[0].name == "test.flush.counter"
           && queued[1].name == "test.flush.gauge"
           && queued[2].name == "test.flush.histogram");
        ok("histogram point has one observation + 7 bucket slots",
           queued[2].count == 1
           && queued[2].bucketCounts.length == 7);
    }

    // ── Case 6: HISTOGRAM_BOUNDS monotonic. SigNoz fails to render
    // P99 if the bucket order is non-monotonic; we verify the SLO
    // buckets here so an accidental sort-revert fails this test
    // before the dashboards break.
    {
        bool monotonic = true;
        double prev = double.min_normal;
        foreach (b; HISTOGRAM_BOUNDS) {
            if (b <= prev) { monotonic = false; break; }
            prev = b;
        }
        ok("HISTOGRAM_BOUNDS are strictly monotonic", monotonic);
    }

    // ── Case 7: disabled path — record* must not queue, flush must no-op.
    {
        const bool prev = isMetricsEnabled();
        scope (exit) setMetricsEnabled(prev);
        setMetricsEnabled(true);
        flushAndSendMetrics();
        drainPendingForTest();
        setMetricsEnabled(false);
        recordCounter("test.disabled.counter", 1, ["k": "v"]);
        recordGauge("test.disabled.gauge", 42, null);
        recordHistogram("test.disabled.histogram", 0.5, ["k": "v"]);
        auto queued = drainPendingForTest();
        ok("record* when disabled leaves pending empty (no growth)",
            queued.length == 0, "got " ~ queued.length.to!string);
        flushAndSendMetrics();
        queued = drainPendingForTest();
        ok("flushAndSendMetrics when disabled is no-op", queued.length == 0);
        configureMetrics("", "test-svc", "0.0.1");
        ok("configureMetrics(\"\") disables", !isMetricsEnabled());
        configureMetrics("disabled", "test-svc", "0.0.1");
        ok("configureMetrics(\"disabled\") disables", !isMetricsEnabled());
        configureMetrics("http://signoz:4318/v1/metrics", "test-svc", "0.0.1");
        ok("configureMetrics(valid) enables", isMetricsEnabled());
        setMetricsEnabled(prev);
        drainPendingForTest();
    }

    // ── Case 8: tracing disabled — withSpan pass-through, no queue, no HTTP.
    {
        const bool prev = isTracingEnabled();
        scope (exit) setTracingEnabled(prev);
        setTracingEnabled(false);
        drainQueueForTest();
        int calls = 0;
        withSpan("test.tracing.disabled", null, (ref Span s) {
            calls++;
            s.attr("k", "v");
            s.setStatusOk();
        });
        ok("withSpan when disabled calls delegate exactly once",
            calls == 1, "got " ~ calls.to!string);
        ok("withSpan when disabled queues no span",
            queueLengthForTest() == 0, "got " ~ queueLengthForTest().to!string);
        flushAndSendSpans();
        ok("flushAndSendSpans when disabled is no-op",
            queueLengthForTest() == 0);
        configureTracing("", "test-svc", "0.0.1");
        ok("configureTracing(\"\") disables", !isTracingEnabled());
        configureTracing("disabled", "test-svc", "0.0.1");
        ok("configureTracing(\"disabled\") disables", !isTracingEnabled());
        configureTracing("http://signoz:4318/v1/traces", "test-svc", "0.0.1");
        ok("configureTracing(valid) enables", isTracingEnabled());
        setTracingEnabled(prev);
        drainQueueForTest();
    }
}

int main() {
    stderr.writeln("OTel observability metrics test");
    runMetricsTests();

    stderr.writeln("\nResult: ", passed, " passed, ", failed, " failed");
    return failed > 0 ? 1 : 0;
}