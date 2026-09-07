/// Standalone regression test for BufferManager's event dedup.
///
/// The dedup SET is the only thing standing between a re-emitted IRC event
/// and a duplicate row in the client: the frontend keys on `eid` (unique
/// per emission) and on a msgid that falls back to the engine's per-event
/// UUID, so two copies of one wire line are indistinguishable to it.
///
/// Covers:
///   - test_second_append_is_reported_duplicate
///       appendIRCEvent returns true then false for the same event. The
///       event processor gates the Mongo write AND the live WebSocket
///       publish on that verdict; it used to ignore it and publish anyway.
///   - test_dedup_survives_server_reassignment
///       The same event appended under a different serverId is still a
///       duplicate. The set used to be keyed `dedup:<serverId>:<net>:<buf>`,
///       so a failover or reassignment started from an empty set and
///       replayed everything it had already seen.
///   - test_legacy_server_scoped_set_is_adopted
///       A pre-existing `dedup:<serverId>:<net>:<buf>` set suppresses its
///       members after the upgrade (RENAMENX adoption), so the first
///       append after a deploy does not re-store history.
///   - test_distinct_events_are_not_collapsed
///       Same channel and timestamp, different nick/text → both stored.
///   - test_clear_buffer_drops_both_dedup_spellings
///       "Clear backlog" must not leave a dedup set behind, or the buffer
///       can never refill.
///
/// Requires the local test Redis (irc_redis_test on 6379).
/// Run with: `dub build --config=buffer-dedup-test && ./buffer-dedup-test`.
module buffer_dedup_test;

import std.conv : to;
import std.stdio : stderr, writeln;
import std.uuid : randomUUID;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.storage.redis : RedisStorage;

/// Tracks the number of passing checks.
int passed;
/// Tracks the number of failing checks.
int failed;

/// Records the outcome of a single named check.
void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("  ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("  ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

RedisStorage connect() {
    auto redis = new RedisStorage();
    redis.connectFromUrl("redis://127.0.0.1:6379");
    return redis;
}

/// A JOIN as the wire delivers it: no IRCv3 msgid (InspIRCd does not tag
/// membership events), so dedup falls through to the content hash. This is
/// the exact event class that showed up twice in the client.
IRCRawEvent joinEvent(string networkId, string channel, string nick, long ts) {
    auto ev = IRCRawEvent("TestNet", "JOIN");
    ev.networkId = networkId;
    ev.channel = channel;
    ev.nick = nick;
    ev.prefix = nick ~ "!user@cloaked.example";
    ev.timestampMs = ts;
    ev.setParams([channel]);
    return ev;
}

void cleanup(RedisStorage redis, string networkId) {
    try {
        auto db = redis.getDb();
        foreach (pattern; ["scrollback:*" ~ networkId ~ "*", "dedup:*" ~ networkId ~ "*"]) {
            string[] keys;
            foreach (k; db.keys(pattern)) keys ~= cast(string) k.idup;
            foreach (k; keys) db.del(k);
        }
    } catch (Exception e) {
        stderr.writeln("cleanup: ", e.msg);
    }
}

void test_second_append_is_reported_duplicate(RedisStorage redis) {
    stderr.writeln("\n[dedup] repeat of the same wire event");
    auto bm = new BufferManager(redis);
    const nid = randomUUID().toString();
    scope (exit) cleanup(redis, nid);

    auto ev = joinEvent(nid, "#chan", "Testing", 1_788_000_000_000L);
    ev.eid = 1;
    check!("first append stores the event")(bm.appendIRCEvent(ev, "engine1"));

    // Same wire line, re-emitted: a fresh IRCRawEvent (new UUID id) and a
    // fresh eid, exactly as the fan-out / batch-replay paths produce.
    auto again = joinEvent(nid, "#chan", "Testing", 1_788_000_000_000L);
    again.eid = 2;
    check!("re-emitted copy is reported as a duplicate")(!bm.appendIRCEvent(again, "engine1"));
    check!("the two copies really had different ids")(ev.id != again.id);

    auto stored = bm.getRecent("engine1", nid, "#chan", 50);
    check!("scrollback holds exactly one copy")(stored.length == 1, stored.length.to!string);
}

void test_dedup_survives_server_reassignment(RedisStorage redis) {
    stderr.writeln("\n[dedup] network reassigned to another engine");
    auto bm = new BufferManager(redis);
    const nid = randomUUID().toString();
    scope (exit) cleanup(redis, nid);

    auto ev = joinEvent(nid, "#chan", "Testing", 1_788_000_000_001L);
    ev.eid = 10;
    check!("stored on the first engine")(bm.appendIRCEvent(ev, "engine1"));

    auto replay = joinEvent(nid, "#chan", "Testing", 1_788_000_000_001L);
    replay.eid = 11;
    check!("the new engine still sees a duplicate")(!bm.appendIRCEvent(replay, "engine2"));
}

void test_legacy_server_scoped_set_is_adopted(RedisStorage redis) {
    stderr.writeln("\n[dedup] legacy server-scoped set adoption");
    const nid = randomUUID().toString();
    scope (exit) cleanup(redis, nid);

    // Pre-upgrade state: one engine already stored the event under the old
    // key shape. Build it by hand so the test does not depend on the old
    // code being available.
    auto seed = new BufferManager(redis);
    auto ev = joinEvent(nid, "#chan", "Testing", 1_788_000_000_002L);
    ev.eid = 20;
    seed.appendIRCEvent(ev, "engine1");
    auto db = redis.getDb();
    db.renameNX("dedup:" ~ nid ~ ":#chan", "dedup:engine1:" ~ nid ~ ":#chan");
    check!("legacy key staged")(db.exists("dedup:engine1:" ~ nid ~ ":#chan"));
    check!("network-scoped key absent")(!db.exists("dedup:" ~ nid ~ ":#chan"));

    // A fresh manager (empty adoption cache, as after a restart) must pick
    // the legacy set up rather than start blank.
    auto bm = new BufferManager(redis);
    auto replay = joinEvent(nid, "#chan", "Testing", 1_788_000_000_002L);
    replay.eid = 21;
    check!("adopted set suppresses the replay")(!bm.appendIRCEvent(replay, "engine1"));
    check!("network-scoped key now exists")(db.exists("dedup:" ~ nid ~ ":#chan"));
}

void test_distinct_events_are_not_collapsed(RedisStorage redis) {
    stderr.writeln("\n[dedup] distinct events in the same millisecond");
    auto bm = new BufferManager(redis);
    const nid = randomUUID().toString();
    scope (exit) cleanup(redis, nid);

    auto a = joinEvent(nid, "#chan", "alice", 1_788_000_000_003L);
    a.eid = 30;
    auto b = joinEvent(nid, "#chan", "bob", 1_788_000_000_003L);
    b.eid = 31;
    check!("first nick stored")(bm.appendIRCEvent(a, "engine1"));
    check!("second nick is not a duplicate")(bm.appendIRCEvent(b, "engine1"));

    auto other = joinEvent(nid, "#other", "alice", 1_788_000_000_003L);
    other.eid = 32;
    check!("same event in another channel is not a duplicate")(
        bm.appendIRCEvent(other, "engine1"));
}

void test_clear_buffer_drops_both_dedup_spellings(RedisStorage redis) {
    stderr.writeln("\n[dedup] clear backlog releases the dedup set");
    auto bm = new BufferManager(redis);
    const nid = randomUUID().toString();
    scope (exit) cleanup(redis, nid);

    auto ev = joinEvent(nid, "#chan", "Testing", 1_788_000_000_004L);
    ev.eid = 40;
    bm.appendIRCEvent(ev, "engine1");
    auto db = redis.getDb();
    // Stage a stale server-scoped set alongside the live one.
    db.sadd("dedup:engine1:" ~ nid ~ ":#chan", "h:stale");

    bm.clearBuffer("engine1", nid, "#chan");
    check!("network-scoped dedup set deleted")(!db.exists("dedup:" ~ nid ~ ":#chan"));
    check!("legacy dedup set deleted")(!db.exists("dedup:engine1:" ~ nid ~ ":#chan"));

    // The buffer must be able to refill with the very event it just dropped.
    auto again = joinEvent(nid, "#chan", "Testing", 1_788_000_000_004L);
    again.eid = 41;
    check!("cleared buffer accepts the event again")(bm.appendIRCEvent(again, "engine1"));
}

int main() {
    stderr.writeln("BufferManager dedup regression suite");
    RedisStorage redis;
    try {
        redis = connect();
        redis.getDb().exists("probe");
    } catch (Exception e) {
        stderr.writeln("FATAL: local Redis unavailable on 6379: ", e.msg);
        return 1;
    }

    test_second_append_is_reported_duplicate(redis);
    test_dedup_survives_server_reassignment(redis);
    test_legacy_server_scoped_set_is_adopted(redis);
    test_distinct_events_are_not_collapsed(redis);
    test_clear_buffer_drops_both_dedup_spellings(redis);

    writeln("\n", passed, " passed, ", failed, " failed");
    return failed == 0 ? 0 : 1;
}
