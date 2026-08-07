/// Dedicated thread pool instances for enterprise-grade task isolation.
///
/// Creates 4 named `shared TaskPool` instances, each with a fixed thread
/// count and a descriptive thread name prefix. Each pool targets a specific
/// concern so that a crash or stall in one subsystem does not propagate to
/// unrelated subsystems — the single biggest enterprise unlock within a
/// single process.
///
/// All pools are `__gshared` (shared across threads). Initialize once at
/// boot via `initThreadPools()` and terminate at shutdown via
/// `shutdownThreadPools()`.
///
/// Thread counts scale relative to `logicalProcessorCount()` but have
/// absolute minimums so even single-core hosts get dedicated threads.
///
/// | Pool       | Min Threads | Scale           | Purpose                          |
/// |------------|-------------|-----------------|----------------------------------|
/// | g_httpPool | 8           | ncpus / 2       | HTTP handlers, WS sessions       |
/// | g_ircPool  | 4           | ncpus / 4       | IRC Redis event listeners        |
/// | g_bgPool   | 2           | ncpus / 8       | OTel flush, health mon, shutdown |
/// | g_stgPool  | 2           | ncpus / 8       | DB snapshotting, buffer xcode    |
///
/// On a 16-core host: g_httpPool=8, g_ircPool=4, g_bgPool=2, g_stgPool=2.
/// On a 4-core host: g_httpPool=8, g_ircPool=4, g_bgPool=2, g_stgPool=2.
/// On a 1-core VM:  g_httpPool=8, g_ircPool=4, g_bgPool=2, g_stgPool=2.
module ircfiber.threadpool;

import vibe.core.taskpool : TaskPool;
import vibe.core.core : logicalProcessorCount;
import std.algorithm : max;

/// HTTP handler pool — dedicated OS threads for HTTP request handling,
/// WebSocket session management, and REST API calls. Isolates HTTP from
/// IRC event processing so a chat flood does not starve the admin panel.
__gshared shared(TaskPool) g_httpPool;

/// IRC event listener pool — processes Redis pub/sub events for live
/// IRC messages and delivers them to WebSocket sessions. A crash in a
/// misbehaving listener fiber terminates only its pool thread, leaving
/// HTTP and background tasks unaffected.
__gshared shared(TaskPool) g_ircPool;

/// Background task pool — periodic engine health checks, OTel span
/// flushing, shutdown listener, and janitor cycles. Long-running
/// background loops run here so they don't contend with HTTP handlers.
__gshared shared(TaskPool) g_bgPool;

/// Storage/DB transcoding pool — snapshot serialization, buffer
/// transcoding, and heavy MongoDB operations that should not block
/// the critical path.
__gshared shared(TaskPool) g_stgPool;

/// Initialize all four thread pools. Must be called once at boot from
/// the main fiber before any task dispatch. Idempotent (pools that are
/// already initialized are skipped).
void initThreadPools() nothrow {
    if (g_httpPool !is null) return;
    immutable ncpus = logicalProcessorCount();
    g_httpPool = new shared TaskPool(max(8, ncpus / 2), "http");
    g_ircPool = new shared TaskPool(max(4, ncpus / 4), "irc");
    g_bgPool = new shared TaskPool(max(2, ncpus / 8), "bg");
    g_stgPool = new shared TaskPool(max(2, ncpus / 8), "stg");
}

/// Gracefully shut down all thread pools. Waits for pending tasks to
/// finish. Must be called at shutdown. Idempotent.
void shutdownThreadPools() nothrow {
    // Shut down in reverse dependency order: storage last.
    if (g_ircPool !is null) { g_ircPool.terminate(); g_ircPool = null; }
    if (g_bgPool !is null)  { g_bgPool.terminate();  g_bgPool = null; }
    if (g_stgPool !is null) { g_stgPool.terminate(); g_stgPool = null; }
    if (g_httpPool !is null){ g_httpPool.terminate();g_httpPool = null; }
}
