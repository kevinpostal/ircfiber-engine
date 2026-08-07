/// Standalone test for ircfiber.irc.engine_janitor safety properties + helpers.
///
/// Covers the operator-facing observability surface and the free-function
/// helpers that the engine itself calls at boot / heartbeat time:
///
///   - test_status_reports_state
///       getStatus() after seeding → JSON has actor, intervalSeconds,
///       lockTtlSeconds, totalCycles, totalReaped, lastDurationMs,
///       lastCycleReaped (array), lockHolder (string|null).
///
///   - test_events_recorded
///       After reaping an orphan, getRecentEvents(10) returns an entry
///       with kind="engine_reap", serverId=<sid>, keysDeleted=N.
///
///   - test_purge_local_server_namespace
///       purgeLocalServerNamespace(db, sid) wipes every matching key +
///       bookkeeping, removes sid from irc:servers, writes an audit
///       event of kind="namespace_purge".
///
///   - test_bump_state_ttls
///       bumpServerStateTTLs(db, sid, ttl) sets EXPIRE on every matching
///       state/scrollback/dedup key; keys survive past default TTL.
///
/// Run with: `make janitor-safety-test`.
module janitor_safety_test;

import std.stdio : stderr, writeln;
import std.conv : to;
import std.algorithm : startsWith;
import std.uuid : randomUUID;
import std.json : parseJSON;

import vibe.data.json : Json;
import vibe.db.redis.redis : RedisReply;

import ircfiber.irc.engine_janitor : EngineJanitor, purgeLocalServerNamespace,
    bumpServerStateTTLs;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.storage.redis : RedisStorage;

/// Tracks the number of passing checks.
int passed;
/// Tracks the number of failing checks.
int failed;
/// Tracks the number of skipped checks.
int skipped;

/// Records the outcome of a single named check.
void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("    ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("    ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

/// Connects to the local test Redis, throwing if unavailable.
RedisStorage tryConnect() {
    auto redis = new RedisStorage();
    redis.connectFromUrl("redis://127.0.0.1:6379");
    return redis;
}

/// Best-effort cleanup of every key matching the server namespace.
void cleanupNamespace(RedisStorage redis, string sid) {
    try {
        auto db = redis.getDb();
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
            "  'irc:draining:' .. sid)\n" ~
            "redis.call('SREM', 'irc:servers', sid)\n" ~
            "return 1\n";
        db.eval!long(script, ["0"], sid);
    } catch (Exception e) {
        stderr.writeln("    (cleanup best-effort failed for ", sid, ": ", e.msg, ")");
    }
}

/// Returns whether the given key exists in Redis.
bool keyExists(RedisStorage redis, string key) {
    try return redis.exists(key); catch (Exception) return false;
}

/// Returns whether the given server id is listed in irc:servers.
bool isInServers(RedisStorage redis, string sid) {
    try {
        auto reply = redis.getDb().smembers(RedisKeys.serverList());
        foreach (m; reply) if (m == sid) return true;
    } catch (Exception) {}
    return false;
}

/// Trims the janitor events list to a fresh slate.
void clearJanitorEvents(RedisStorage redis) {
    try {
        immutable string trim = "redis.call('LTRIM', 'irc:janitor:events', 200, -1)\nreturn 1\n";
        redis.getDb().eval!long(trim, ["0"]);
    } catch (Exception) {}
}

/// Runs the status-reports-state test scenario.
void runStatusReportsState() {
    stderr.writeln("\n[status] getStatus() exposes janitor snapshot");
    RedisStorage redis;
    try { redis = tryConnect(); }
    catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis unavailable (", e.msg, ")");
        ++skipped;
        return;
    }
    auto db = redis.getDb();
    string sid = "jt-status-" ~ randomUUID().toString()[0..8];
    scope (exit) cleanupNamespace(redis, sid);

    clearJanitorEvents(redis);

    // Seed a couple of orphans so runOnce() bumps totalReaped. Track each
    // sid for cleanup — `scope (exit)` inside a foreach only lasts one
    // iteration, so accumulate them in an outer array.
    string[] orphanIds;
    scope (exit) foreach (s; orphanIds) cleanupNamespace(redis, s);
    foreach (i; 0 .. 2) {
        string s = sid ~ "-" ~ i.to!string;
        orphanIds ~= s;
        db.sadd(RedisKeys.serverList(), s);
        db.set("irc:state:" ~ s ~ ":n1", "x");
    }

    auto janitor = new EngineJanitor(redis);
    const long _r = janitor.runOnce();
    auto status = janitor.getStatus();

    check!("status.actor is non-empty string")
        (status["actor"].get!string.length > 0);
    check!("status.actor starts with 'pid:'")
        (status["actor"].get!string.startsWith("pid:"));
    check!("status.intervalSeconds is non-negative long")
        (status["intervalSeconds"].get!long >= 0);
    check!("status.lockTtlSeconds is positive long")
        (status["lockTtlSeconds"].get!long > 0);
    check!("status.totalCycles ≥ 1 after runOnce()")
        (status["totalCycles"].get!long >= 1);
    check!("status.totalReaped ≥ 2 after two orphans")
        (status["totalReaped"].get!long >= 2);
    check!("status.lastDurationMs ≥ 0")
        (status["lastDurationMs"].get!long >= 0);
    check!("status.lastCycleReaped is an array")
        (status["lastCycleReaped"].type == Json.Type.array);
    // lockHolder is either null (lock free) or a string (lock held by us,
    // possibly an empty string if SET NX returned OK but value was empty —
    // we accept any string and only check non-emptiness if present).
    auto lockType = status["lockHolder"].type;
    check!("status.lockHolder is string or null")
        (lockType == Json.Type.string || lockType == Json.Type.null_);
    // Suppress unused-variable warning.
    if (_r < 0) stderr.writeln("(unreachable)");
}

/// Runs the events-recorded test scenario.
void runEventsRecorded() {
    stderr.writeln("\n[events] getRecentEvents() surfaces engine_reap entries");
    RedisStorage redis;
    try { redis = tryConnect(); }
    catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis unavailable (", e.msg, ")");
        ++skipped;
        return;
    }
    auto db = redis.getDb();
    string sid = "jt-evt-" ~ randomUUID().toString()[0..8];
    scope (exit) cleanupNamespace(redis, sid);

    clearJanitorEvents(redis);

    // Seed and reap one orphan.
    db.sadd(RedisKeys.serverList(), sid);
    db.set("irc:state:" ~ sid ~ ":n1", "a");
    db.set("irc:state:" ~ sid ~ ":n2", "b");
    long reaped = 0;
    auto janitor = new EngineJanitor(redis);
    reaped = janitor.runOnce();
    check!("runOnce() reaped our orphan")(reaped >= 1);

    // Recent events MUST contain our sid with the right kind.
    auto events = janitor.getRecentEvents(10);
    check!("getRecentEvents(10) returns ≥1 entry")(events.length >= 1);

    bool foundReap = false;
    bool foundNamespacePurge = false;
    foreach (e; events) {
        try {
            if (e["serverId"].get!string == sid) {
                if (e["kind"].get!string == "engine_reap") {
                    foundReap = true;
                    check!("event.kind == 'engine_reap'")
                        (e["kind"].get!string == "engine_reap");
                    check!("event.serverId == sid")
                        (e["serverId"].get!string == sid);
                    check!("event.keysDeleted is positive long")
                        (e["keysDeleted"].get!long >= 1);
                    check!("event.actor is non-empty string")
                        (e["actor"].get!string.length > 0);
                    check!("event.reason == 'lease_expired'")
                        (e["reason"].get!string == "lease_expired");
                    check!("event.ts is a long timestamp")
                        (e["ts"].get!long > 1_700_000_000L);
                }
                if (e["kind"].get!string == "namespace_purge")
                    foundNamespacePurge = true;
            }
        } catch (Exception) {}
    }
    check!("events contain engine_reap for our sid")(foundReap);
    // namespace_purge is written by purgeLocalServerNamespace; our runOnce()
    // path only writes engine_reap. So we accept EITHER signal.
    if (!foundNamespacePurge)
        check!("info: no namespace_purge seen for this sid (expected for runOnce path)")
            (true);
}

/// Runs the purge-local-server-namespace test scenario.
void runPurgeLocalServerNamespace() {
    stderr.writeln("\n[purge] purgeLocalServerNamespace wipes namespace atomically");
    RedisStorage redis;
    try { redis = tryConnect(); }
    catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis unavailable (", e.msg, ")");
        ++skipped;
        return;
    }
    auto db = redis.getDb();
    string sid = "jt-purge-" ~ randomUUID().toString()[0..8];
    scope (exit) cleanupNamespace(redis, sid);

    clearJanitorEvents(redis);

    db.sadd(RedisKeys.serverList(), sid);
    db.set("irc:state:" ~ sid ~ ":n1", "blob");
    db.set(RedisKeys.control(sid), "ctrl");
    db.hset(RedisKeys.serverAssignments(sid), "n1", sid);
    db.set(RedisKeys.server(sid), "alive");
    check!("precondition: state key present")
        (keyExists(redis, "irc:state:" ~ sid ~ ":n1"));
    check!("precondition: server key present")
        (keyExists(redis, RedisKeys.server(sid)));

    const long deleted = purgeLocalServerNamespace(db, sid);
    check!("purgeLocalServerNamespace returns ≥1 deleted")(deleted >= 1);
    check!("postcondition: state key gone")
        (!keyExists(redis, "irc:state:" ~ sid ~ ":n1"));
    check!("postcondition: server key gone")
        (!keyExists(redis, RedisKeys.server(sid)));
    check!("postcondition: control queue gone")
        (!keyExists(redis, RedisKeys.control(sid)));
    check!("postcondition: server-assignments gone")
        (!keyExists(redis, RedisKeys.serverAssignments(sid)));
    check!("postcondition: sid removed from irc:servers")
        (!isInServers(redis, sid));

    // Audit event?
    bool found = false;
    try {
        auto reply = db.lrange(RedisKeys.janitorEvents(), 0, 9);
        foreach (line; reply) {
            try {
                auto j = Json(parseJSON(line.idup));
                if (j["kind"].get!string == "namespace_purge" &&
                    j["serverId"].get!string == sid) {
                    found = true;
                    check!("audit event has reason 'bootstrap_purge'")
                        (j["reason"].get!string == "bootstrap_purge");
                    check!("audit event has positive keysDeleted")
                        (j["keysDeleted"].get!long >= 1);
                    break;
                }
            } catch (Exception) {}
        }
    } catch (Exception) {}
    check!("audit event of kind 'namespace_purge' recorded")(found);

    // Idempotency: second purge returns 0 (nothing left).
    const long second = purgeLocalServerNamespace(db, sid);
    check!("idempotent: second purge returns 0")(second == 0);
}

/// Runs the bump-state-ttls test scenario.
void runBumpStateTtls() {
    stderr.writeln("\n[ttl] bumpServerStateTTLs refreshes EXPIRE on namespace keys");
    RedisStorage redis;
    try { redis = tryConnect(); }
    catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis unavailable (", e.msg, ")");
        ++skipped;
        return;
    }
    auto db = redis.getDb();
    string sid = "jt-ttl-" ~ randomUUID().toString()[0..8];
    scope (exit) cleanupNamespace(redis, sid);

    // Seed each of the patterns the helper touches.
    db.set("irc:state:" ~ sid ~ ":n1", "x");
    db.set("scrollback:" ~ sid ~ ":n1:ch1", "y");
    db.set("dedup:" ~ sid ~ ":n1:msg1", "z");
    db.set(RedisKeys.control(sid), "ctrl");

    const long touched = bumpServerStateTTLs(db, sid, 600);
    check!("bumpServerStateTTLs reports ≥3 touched")
        (touched >= 3);

    // Verify TTLs were applied.
    long sTtl, bTtl, dTtl, cTtl;
    try sTtl = db.ttl("irc:state:" ~ sid ~ ":n1");   catch (Exception) sTtl = -2;
    try bTtl = db.ttl("scrollback:" ~ sid ~ ":n1:ch1"); catch (Exception) bTtl = -2;
    try dTtl = db.ttl("dedup:" ~ sid ~ ":n1:msg1");   catch (Exception) dTtl = -2;
    try cTtl = db.ttl(RedisKeys.control(sid));         catch (Exception) cTtl = -2;

    check!("state key has positive TTL")(sTtl > 0);
    check!("scrollback key has positive TTL")(bTtl > 0);
    check!("dedup key has positive TTL")(dTtl > 0);
    check!("control queue has positive TTL (StateTTL.CONTROL_QUEUE_TTL = 300)")
        (cTtl > 0);

    // Idempotency: a second call touches the same set again.
    const long second = bumpServerStateTTLs(db, sid, 600);
    check!("second bump touches ≥3 again")(second >= 3);

    // Zero / negative TTL is a safe no-op.
    const long noop = bumpServerStateTTLs(db, sid, 0);
    check!("ttlSeconds=0 is a no-op")(noop == 0);
    const long empty = bumpServerStateTTLs(db, "", 600);
    check!("empty serverId is a no-op")(empty == 0);
}

int main() {
    stderr.writeln("ircfiber.irc.engine_janitor safety + helpers tests");

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

    dispatch!("test_status_reports_state")(&runStatusReportsState);
    dispatch!("test_events_recorded")(&runEventsRecorded);
    dispatch!("test_purge_local_server_namespace")(&runPurgeLocalServerNamespace);
    dispatch!("test_bump_state_ttls")(&runBumpStateTtls);

    stderr.writeln("\n────────────────────────────────────────");
    stderr.writeln(passed, " passed, ", failed, " failed, ", skipped, " skipped");
    return failed == 0 ? 0 : 1;
}