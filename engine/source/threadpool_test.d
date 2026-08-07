/// Thread pool test — verifies that the named TaskPool instances
/// compile, accept tasks, and execute them on worker threads.
///
/// Uses real OS threads (TaskPool) — no vibe.d event loop needed.
///
/// Run: dub build --config=threadpool-test && ./threadpool-test
module threadpool_test;

import core.time : msecs, Duration;
import core.thread : Thread;
import std.stdio : stderr, writeln;
import std.string : format, indexOf;
import std.uuid : UUID, randomUUID;
import std.conv : to;

import vibe.core.taskpool : TaskPool;

import ircfiber.threadpool;

int passed;
int failed;

/// Per-test label + boolean check.
void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("    ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("    ✗ ", name, " FAILED: ", msg);
    }
}

__gshared bool g_markRan;

void main() {
    test_pools_null_before_init();
    test_init_pools();
    test_bg_pool_execution();
    test_irc_pool_execution();
    test_string_uuid_args();
    test_init_idempotent();
    test_pool_names();

    stderr.writeln("---");
    stderr.writeln("Thread pool tests: ", passed, " passed, ", failed, " failed");

    import core.stdc.stdlib : exit;
    exit(failed > 0 ? 1 : 0);
}

// --- Tests ---

void test_pools_null_before_init() {
    check!("null before init: httpPool")(g_httpPool is null);
    check!("null before init: ircPool")(g_ircPool is null);
    check!("null before init: bgPool")(g_bgPool is null);
    check!("null before init: stgPool")(g_stgPool is null);
}

void test_init_pools() {
    initThreadPools();
    scope(exit) shutdownThreadPools();

    check!("init: httpPool created")(g_httpPool !is null);
    check!("init: ircPool created")(g_ircPool !is null);
    check!("init: bgPool created")(g_bgPool !is null);
    check!("init: stgPool created")(g_stgPool !is null);
    check!("init: httpPool >= 2 threads")(g_httpPool.threadCount >= 2);
    check!("init: ircPool >= 2 threads")(g_ircPool.threadCount >= 2);
    check!("init: bgPool >= 1 thread")(g_bgPool.threadCount >= 1);
    check!("init: stgPool >= 1 thread")(g_stgPool.threadCount >= 1);
}

void test_bg_pool_execution() {
    initThreadPools();
    scope(exit) shutdownThreadPools();

    g_markRan = false;
    g_bgPool.runTaskH(&markFn, 1).joinUninterruptible();

    check!("exec: bg pool task ran")(g_markRan);
}

void test_irc_pool_execution() {
    initThreadPools();
    scope(exit) shutdownThreadPools();

    g_markRan = false;
    g_ircPool.runTaskH(&markFn, 2).joinUninterruptible();

    check!("exec: irc pool task ran")(g_markRan);
}

// Module-level function pointer for TaskPool.runTask (not a delegate!)
private void stringUuidTask(string userId, UUID sessionId) nothrow {
    try {
        g_result = format("user=%s session=%s", userId, sessionId.to!string);
    } catch (Exception) {
        g_result = "error";
    }
}
__gshared string g_result;

/// Test passing string + UUID (the pattern used by irc listener dispatch).
void test_string_uuid_args() {
    initThreadPools();
    scope(exit) shutdownThreadPools();

    g_result = null;
    auto uid = "test-user-42".idup;
    auto sid = randomUUID();

    g_ircPool.runTaskH(&stringUuidTask, uid, sid).joinUninterruptible();

    check!("exec: string+UUID pool task completed")(g_result.length > 0);
    check!("exec: result contains userId")(indexOf(g_result, "test-user-42") >= 0);
}

void test_init_idempotent() {
    initThreadPools();
    initThreadPools();  // second call should be no-op
    check!("init: double init is idempotent")(g_httpPool !is null);
    shutdownThreadPools();
}

void test_pool_names() {
    initThreadPools();
    scope(exit) shutdownThreadPools();

    check!("names: httpPool != ircPool")(g_httpPool !is g_ircPool);
    check!("names: ircPool != bgPool")(g_ircPool !is g_bgPool);
    check!("names: bgPool != stgPool")(g_bgPool !is g_stgPool);
}

// --- Shared helper ---

private void markFn(int _) nothrow {
    g_markRan = true;
}
