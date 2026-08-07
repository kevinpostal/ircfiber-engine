/// Standalone fast smoke test for ircfiber.irc.engine_janitor basic reap logic.
///
/// Covers the core "orphan detection → reap" happy path plus the
/// "live server is never touched" safety property:
///
///   - test_enginejanitor_reaps_orphan
///       orphan in irc:servers but NO `irc:server:<id>` key → reaped,
///       `irc:servers` membership removed, namespace keys deleted,
///       `irc:janitor:events` audit row appended.
///
///   - test_enginejanitor_skips_live
///       live server in irc:servers WITH `irc:server:<id>` key set →
///       janitor must skip it (EXISTS guard); no namespace purge,
///       no audit event for that serverId.
///
/// Run with: `make janitor-test`.
module janitor_test;

import std.stdio : stderr, writeln;
import std.conv : to;
import std.uuid : randomUUID;
import std.json : parseJSON;

import vibe.data.json : Json;
import vibe.db.redis.redis : RedisReply;

import ircfiber.irc.engine_janitor : EngineJanitor;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.storage.redis : RedisStorage;

/// Tracks the number of passing checks.
int passed;
/// Tracks the number of failing checks.
int failed;
/// Tracks the number of skipped checks.
int skipped;

/// Per-test label + lazy boolean check (matches prefs_test.d style).
void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("    ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("    ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

/// Connect to local Redis or throw a caught Exception with a SKIP reason.
RedisStorage tryConnect() {
    auto redis = new RedisStorage();
    redis.connectFromUrl("redis://127.0.0.1:6379");
    return redis;
}

/// Best-effort cleanup of every per-engine key matching `*:<sid>:*`.
/// Also drops `irc:server:<sid>`, `irc:control:<sid>`,
/// `irc:server-assignments:<sid>`, and removes sid from `irc:servers`.
void cleanupNamespace(RedisStorage redis, string sid) {
    try {
        auto db = redis.getDb();
        // Use a Lua SCAN to avoid UNLINK-with-empty-arg problems.
        immutable string script =
            "local sid = ARGV[1]\n" ~
            "local cursor = '0'\n" ~
            "repeat\n" ~
            "  local r = redis.call('SCAN', cursor, 'MATCH', '*:' .. sid .. ':*', 'COUNT', 500)\n" ~
            "  cursor = r[1]\n" ~
            "  if #r[2] > 0 then redis.call('UNLINK', unpack(r[2])) end\n" ~
            "until cursor == '0'\n" ~
            "redis.call('UNLINK', 'irc:server:' .. sid,\n" ~
            "  'irc:control:' .. sid, 'irc:server-assignments:' .. sid,\n" ~
            "  'irc:draining:' .. sid, 'irc:janitor:lock')\n" ~
            "redis.call('SREM', 'irc:servers', sid)\n" ~
            "return 1\n";
        db.eval!long(script, ["0"], sid);
    } catch (Exception e) {
        stderr.writeln("    (cleanup best-effort failed for ", sid, ": ", e.msg, ")");
    }
}

/// Returns whether the given server id is listed in irc:servers.
bool isInServers(RedisStorage redis, string sid) {
    try {
        auto reply = redis.getDb().smembers(RedisKeys.serverList());
        foreach (m; reply) if (m == sid) return true;
    } catch (Exception) {}
    return false;
}

/// Returns whether the given key exists in Redis.
bool keyExists(RedisStorage redis, string key) {
    try return redis.exists(key); catch (Exception) return false;
}

/// Drop events list for a fresh slate, but only up to the first 200
/// entries so we don't churn a long-running deployment's history.
void clearJanitorEvents(RedisStorage redis) {
    try {
        immutable string trim = "redis.call('LTRIM', 'irc:janitor:events', 200, -1)\nreturn 1\n";
        redis.getDb().eval!long(trim, ["0"]);
    } catch (Exception) {}
}

/// Runs the reaps-orphan test scenario.
void runEnginejanitorReapsOrphan() {
    stderr.writeln("\n[reap] orphan in registry, no irc:server:<id> → reaped");
    RedisStorage redis;
    try { redis = tryConnect(); }
    catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis unavailable (", e.msg, ")");
        ++skipped;
        return;
    }
    auto db = redis.getDb();
    string sid = "jt-orphan-" ~ randomUUID().toString()[0..8];
    scope (exit) cleanupNamespace(redis, sid);

    clearJanitorEvents(redis);

    // Seed orphan state.
    db.sadd(RedisKeys.serverList(), sid);
    db.set("irc:state:" ~ sid ~ ":n1", "data");
    db.set(RedisKeys.control(sid), "queue");
    db.hset(RedisKeys.serverAssignments(sid), "n1", sid);
    check!("precondition: orphan in irc:servers")(isInServers(redis, sid));
    check!("precondition: state key present")
        (keyExists(redis, "irc:state:" ~ sid ~ ":n1"));
    check!("precondition: control queue present")
        (keyExists(redis, RedisKeys.control(sid)));
    check!("precondition: server key absent (EXISTS=0)")
        (!keyExists(redis, RedisKeys.server(sid)));

    auto janitor = new EngineJanitor(redis);
    const long reaped = janitor.runOnce();
    check!("runOnce() reports ≥1 reaped orphan")(reaped >= 1);
    check!("postcondition: sid removed from irc:servers")
        (!isInServers(redis, sid));
    check!("postcondition: state key gone")
        (!keyExists(redis, "irc:state:" ~ sid ~ ":n1"));
    check!("postcondition: control queue gone")
        (!keyExists(redis, RedisKeys.control(sid)));
    check!("postcondition: server-assignments gone")
        (!keyExists(redis, RedisKeys.serverAssignments(sid)));

    // Audit event written?
    bool foundEvent = false;
    try {
        auto reply = db.lrange(RedisKeys.janitorEvents(), 0, 9);
        foreach (line; reply) {
            try {
                auto j = Json(parseJSON(line.idup));
                if (j["kind"].get!string == "engine_reap" &&
                    j["serverId"].get!string == sid) {
                    foundEvent = true;
                    break;
                }
            } catch (Exception) {}
        }
    } catch (Exception e) {
        stderr.writeln("    (LRANGE janitor events failed: ", e.msg, ")");
    }
    check!("postcondition: irc:janitor:events has engine_reap row for sid")(foundEvent);
}

/// Runs the skips-live-server test scenario.
void runEnginejanitorSkipsLive() {
    stderr.writeln("\n[reap] live server (EXISTS=1) → never touched");
    RedisStorage redis;
    try { redis = tryConnect(); }
    catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis unavailable (", e.msg, ")");
        ++skipped;
        return;
    }
    auto db = redis.getDb();
    string sid = "jt-live-" ~ randomUUID().toString()[0..8];
    scope (exit) cleanupNamespace(redis, sid);

    clearJanitorEvents(redis);

    // Seed live + some auxiliary state.
    db.sadd(RedisKeys.serverList(), sid);
    db.set(RedisKeys.server(sid), "data");           // ← makes EXISTS=1
    db.set("irc:state:" ~ sid ~ ":n1", "data");
    db.set(RedisKeys.control(sid), "queue");
    db.hset(RedisKeys.serverAssignments(sid), "n1", sid);
    check!("precondition: live sid in irc:servers")(isInServers(redis, sid));
    check!("precondition: irc:server:<sid> present")
        (keyExists(redis, RedisKeys.server(sid)));

    auto janitor = new EngineJanitor(redis);
    const long reaped = janitor.runOnce();
    // runOnce may still reap OTHER orphans from earlier tests; what matters
    // is that OUR live sid is untouched.
    check!("postcondition: live sid still in irc:servers")
        (isInServers(redis, sid));
    check!("postcondition: live sid's server key intact")
        (keyExists(redis, RedisKeys.server(sid)));
    check!("postcondition: live sid's state key intact")
        (keyExists(redis, "irc:state:" ~ sid ~ ":n1"));
    check!("postcondition: live sid's control queue intact")
        (keyExists(redis, RedisKeys.control(sid)));
    check!("postcondition: live sid's assignments intact")
        (keyExists(redis, RedisKeys.serverAssignments(sid)));

    // No audit event for the live sid.
    bool foundEvent = false;
    try {
        auto reply = db.lrange(RedisKeys.janitorEvents(), 0, 9);
        foreach (line; reply) {
            try {
                auto j = Json(parseJSON(line.idup));
                if (j["serverId"].get!string == sid) { foundEvent = true; break; }
            } catch (Exception) {}
        }
    } catch (Exception) {}
    check!("postcondition: NO janitor event recorded for live sid")(!foundEvent);
    // Suppress unused-variable warning for `reaped`.
    if (reaped < 0) stderr.writeln("(unreachable)");
}

int main() {
    stderr.writeln("ircfiber.irc.engine_janitor basic-reap smoke tests");

    void dispatch(string name)(void function() body) {
        stderr.writeln("\n--- ", name, " ---");
        const int beforeFailed = failed;
        try {
            body();
            if (failed > beforeFailed)
                stderr.writeln("  [FAIL] ", name);
            else if (skipped > 0 && passed == 0)
                stderr.writeln("  [SKIP] ", name);
            else
                stderr.writeln("  [PASS] ", name);
        } catch (Exception e) {
            ++failed;
            stderr.writeln("  [FAIL] ", name, " — uncaught exception: ", e.msg);
        }
    }

    dispatch!("test_enginejanitor_reaps_orphan")(&runEnginejanitorReapsOrphan);
    dispatch!("test_enginejanitor_skips_live")(&runEnginejanitorSkipsLive);

    stderr.writeln("\n────────────────────────────────────────");
    stderr.writeln(passed, " passed, ", failed, " failed, ", skipped, " skipped");
    return failed == 0 ? 0 : 1;
}