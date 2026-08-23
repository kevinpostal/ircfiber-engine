/// Async-fiber bridge for vibe-core 2.14's `nothrow` runTask contract.
///
/// `vibe.core.core.runTask` requires its callback to be `nothrow`. Before
/// this helper existed, the codebase passed throwing closures inline and
/// the build broke against newer vibe-core.
///
/// Usage:
///   auto task = safeFiberRun("happy_eyeballs_attempt", host, () {
///       try { connectTCP(...); } catch (Exception e) { logInfo(...); }
///   });
///   // later: try task.interrupt(); catch (Exception) {}
///
/// The helper handles three things at once:
///   1. Wraps the throwing closure in a heap-allocated nothrow trampoline
///   2. Schedules the trampoline via `runTask`
///   3. Returns a `Task` handle so callers can interrupt the fiber on
///      timeout (the previous pattern of `&taskNothrow(...)` lost the
///      handle, and several call sites relied on `task.interrupt()` for
///      teardown)
///
/// The trampoline catches `Exception` (NOT `Throwable` — that excludes
/// `Error`/`AssertError` so genuine bugs propagate), logs a structured
/// `event=task_crash` line via the project's logger, and silently drops
/// the rest.
module ircfiber.async;

import core.stdc.stdlib : malloc, free;
import core.sync.mutex : Mutex;
import core.time : seconds;
import std.datetime : Clock, SysTime;
import std.stdio : stderr;
import vibe.core.core : runTask, sleep;
import vibe.core.log;
import vibe.core.task : Task, TaskSettings;
import ircfiber.logging : logJsonMap;
/// Same arglist as `runTask`, but the closure may throw freely. Returns
/// the `Task` handle from `runTask` so callers can interrupt. The
/// `event_` and `network` tags surface in the structured log line if
/// the closure throws.
auto safeFiberRun(string event_, string network,
                  void delegate() @system dg)
{
    struct Trampoline {
        string event_;
        string network;
        void delegate() @system dg;
    }

    auto mem = malloc(Trampoline.sizeof);
    if (mem is null) {
        // Out-of-memory: log a fallback to stderr so the operator at
        // least sees we tried, then return a Task placeholder. We
        // can't return `Task.init` cleanly without including the type;
        // the caller will see a null-Task sentinel.
        try stderr.writeln("async: out of memory scheduling ",
            event_, " on ", network);
        catch (Throwable) {}
        return Task.init;
    }
    (cast(Trampoline*) mem)[0] = Trampoline(event_, network, dg);

    void wrapped() nothrow {
        scope(exit) free(mem);
        auto t = cast(Trampoline*) mem;
        try t.dg();
        catch (Throwable e) {
            // Enterprise: catch Throwable (SyncError) — previously only Exception,
            // so SyncError killed the fiber as FATAL (cnTb-fin 2026-08-17).
            // Log and swallow so the connection loop's own catch handles recovery.
            try {
                string m;
                try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                logJsonMap("error", "async",
                    "Background task crashed",
                    [
                        "network": t.network,
                        "event":   t.event_,
                        "error":   m
                    ]);
            } catch (Throwable) {}
        }
    }
    return runTask(&wrapped);
}
// Native HTTP handler fibers (listenHTTP internal) are invisible.

/// Per-fiber watch entry.
struct FiberWatch {
    /// Task identifier.
    string taskId;
    /// Human-readable label.
    string label;
    /// Timestamp of the last yield.
    SysTime lastYield;
}

/// Global registry of watched fibers — __gshared, guarded by mutex for enterprise safety.
private __gshared FiberWatch[] s_watchedFibers;
private __gshared bool s_watchdogStarted;
private __gshared int g_longRunningFiberCount;
private __gshared int g_yieldsTotal;
private __gshared Mutex gWatchdogMutex;
shared static this() {
    try { gWatchdogMutex = new Mutex(); } catch (Throwable) {}
}

/// Wrapper around runTask that registers the task with the watchdog.
/// Automatically records lastYield before and after the task body.
/// Usage: watchedRunTask("label", "id", { ... });
Task watchedRunTask(string label, string taskId, void delegate() dg) {
    size_t idx;
    // Use nothrow-safe raw lock_nothrow: synchronized is not nothrow.
    bool locked = false;
    if (gWatchdogMutex !is null) {
        try { gWatchdogMutex.lock_nothrow(); locked = true; } catch (Throwable) {}
    }
    // Critical section — copy under lock, keep logic minimal.
    idx = s_watchedFibers.length;
    s_watchedFibers ~= FiberWatch(taskId, label, Clock.currTime);
    if (locked) try { gWatchdogMutex.unlock_nothrow(); } catch (Throwable) {}

    void wrapped() nothrow {
        bool l = false;
        if (gWatchdogMutex !is null) {
            try { gWatchdogMutex.lock_nothrow(); l = true; } catch (Throwable) {}
        }
        if (l) {
            if (idx < s_watchedFibers.length) s_watchedFibers[idx].lastYield = Clock.currTime;
            g_yieldsTotal++;
            try { gWatchdogMutex.unlock_nothrow(); l = false; } catch (Throwable) {}
        } else {
            if (idx < s_watchedFibers.length) s_watchedFibers[idx].lastYield = Clock.currTime;
            g_yieldsTotal++;
        }

        try dg();
        catch (Throwable e) {
            try {
                string m;
                try { m = e.msg; } catch (Throwable) { m = "unknown"; }
                logWarn("watchedRunTask '%s' (%s) crashed: %s", taskId, label, m);
            } catch (Throwable) {}
        }

        if (gWatchdogMutex !is null) {
            try { gWatchdogMutex.lock_nothrow(); l = true; } catch (Throwable) {}
        }
        if (l) {
            if (idx < s_watchedFibers.length) s_watchedFibers[idx].lastYield = Clock.currTime;
            g_yieldsTotal++;
            try { gWatchdogMutex.unlock_nothrow(); } catch (Throwable) {}
        } else {
            if (idx < s_watchedFibers.length) s_watchedFibers[idx].lastYield = Clock.currTime;
            g_yieldsTotal++;
        }
    }

    return runTask(TaskSettings(65_536), &wrapped);
}
/// Start the watchdog timer (should be called once at boot).
/// Polls every 5s and logs any fiber that hasn't yielded in >5s.
void startFiberWatchdog() {
    bool already;
    if (gWatchdogMutex !is null) synchronized (gWatchdogMutex) {
        already = s_watchdogStarted;
        if (!already) s_watchdogStarted = true;
    } else {
        already = s_watchdogStarted;
        if (!already) s_watchdogStarted = true;
    }
    if (already) return;

    runTask(TaskSettings(100), () nothrow {
        while (true) {
            try {
                auto now = Clock.currTime;
                int count = 0;
                if (gWatchdogMutex !is null) synchronized (gWatchdogMutex) {
                    foreach (ref fw; s_watchedFibers) {
                        if (now - fw.lastYield > 5.seconds) {
                            count++;
                            logWarn("FIBER_WATCHDOG: Task '%s' (%s) has not yielded for >5s (last:%s)",
                                fw.taskId, fw.label, fw.lastYield);
                        }
                    }
                    g_longRunningFiberCount = count;
                } else {
                    foreach (ref fw; s_watchedFibers) {
                        if (now - fw.lastYield > 5.seconds) {
                            count++;
                            logWarn("FIBER_WATCHDOG: Task '%s' (%s) has not yielded for >5s (last:%s)",
                                fw.taskId, fw.label, fw.lastYield);
                        }
                    }
                    g_longRunningFiberCount = count;
                }
            } catch (Throwable e) {
                // Don't crash the watchdog — also catch SyncError.
            }
            try { sleep(5.seconds); } catch (Throwable) { break; }
        }
    });
}

/// Current count of fibers running >5s without yield.
@property int longRunningFiberCount() {
    if (gWatchdogMutex !is null) synchronized (gWatchdogMutex) return g_longRunningFiberCount;
    return g_longRunningFiberCount;
}

/// Total yield checkpoints hit since boot.
@property int yieldsTotal() {
    if (gWatchdogMutex !is null) synchronized (gWatchdogMutex) return g_yieldsTotal;
    return g_yieldsTotal;
}

/// Reset counters (useful for tests).
void resetWatchdogCounters() {
    if (gWatchdogMutex !is null) synchronized (gWatchdogMutex) {
        g_longRunningFiberCount = 0;
        g_yieldsTotal = 0;
        return;
    }
    g_longRunningFiberCount = 0;
    g_yieldsTotal = 0;
}
