/// Standalone test for ircfiber.irc.dial_guard marker retirement.
///
/// A holder DIAL marker is retained when an engine dies or loses the IPC reply
/// mid-DIAL, so the network cannot dial again until the marker is retired. These
/// tests pin which markers may be retired and which must never be:
///
///   - test_aged_same_incarnation_retired   old, not live here → retired
///   - test_young_marker_retained           inside the proof window → kept
///   - test_live_dial_never_retired         aged but executing in-process → kept
///   - test_unstamped_marker_ages_from_first_sight   stamped, not retired
///   - test_incarnation_change              UUID holder replaced → retired;
///                                          pid-only holder cannot prove it
///   - test_unversioned_marker_untouched    legacy '1' stays unproven
///
/// Needs Redis on 127.0.0.1:6379. Run with: `make dial-guard-test`.
module dial_guard_test;

import std.conv : to;
import std.stdio : stderr, writeln;
import std.uuid : randomUUID;

import ircfiber.irc.dial_guard : beginLocalDial, endLocalDial, orphanedDialProofMs,
    retireOrphanedDials;
import ircfiber.storage.redis : RedisStorage;

int passed;
int failed;

void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("    ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("    ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

enum string holderA = "11111111-1111-4111-8111-111111111111";
enum string holderB = "22222222-2222-4222-8222-222222222222";
enum long now = 1_800_000_000_000;

struct Rig {
    RedisStorage redis;
    string sid, nid, key;
}

Rig rig() {
    auto redis = new RedisStorage();
    redis.connectFromUrl("redis://127.0.0.1:6379");
    const sid = "dgt-" ~ randomUUID().toString()[0 .. 8];
    const nid = randomUUID().toString();
    auto r = Rig(redis, sid, nid, "irc:routing:dials:" ~ sid ~ ":" ~ nid);
    redis.getDb().del(r.key);
    return r;
}

string field(Rig r, string token) {
    auto db = r.redis.getDb();
    return db.hexists(r.key, token) ? db.hget(r.key, token) : null;
}

void put(Rig r, string token, string value) {
    r.redis.getDb().hset(r.key, token, value);
}

void runAgedSameIncarnationRetired() {
    auto r = rig();
    put(r, "tokA", "holder_v1:" ~ holderA ~ "@" ~ (now - orphanedDialProofMs).to!string);
    put(r, "tokB", "holder_v1:legacy-pid:7@" ~ (now - orphanedDialProofMs - 1).to!string);
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now);
    check!("aged UUID marker retired")(field(r, "tokA") is null);
    retireOrphanedDials(r.redis, r.sid, r.nid, "legacy-pid:7", now);
    check!("aged pid-only marker retired by age")(field(r, "tokB") is null);
    r.redis.getDb().del(r.key);
}

void runYoungMarkerRetained() {
    auto r = rig();
    const v = "holder_v1:" ~ holderA ~ "@" ~ (now - orphanedDialProofMs + 1).to!string;
    put(r, "tok", v);
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now);
    check!("marker inside the proof window kept")(field(r, "tok") == v);
    r.redis.getDb().del(r.key);
}

void runLiveDialNeverRetired() {
    auto r = rig();
    const v = "holder_v1:" ~ holderA ~ "@" ~ (now - 10 * orphanedDialProofMs).to!string;
    put(r, "live", v);
    put(r, "dead", v);
    beginLocalDial(r.sid, r.nid, "live");
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now);
    check!("aged marker of an in-process dial kept")(field(r, "live") == v);
    check!("aged marker of another dial retired")(field(r, "dead") is null);
    endLocalDial(r.sid, r.nid, "live");
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now);
    check!("marker retired once its dial ended")(field(r, "live") is null);
    r.redis.getDb().del(r.key);
}

void runUnstampedMarkerAgesFromFirstSight() {
    auto r = rig();
    put(r, "old", "holder_v1:" ~ holderA);
    put(r, "pid", "holder_v1:legacy-pid:7");
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now);
    check!("unstamped marker kept on first sight")(field(r, "old") !is null);
    check!("unstamped marker stamped with first-sight time")(
        field(r, "old") == "holder_v1:" ~ holderA ~ "@" ~ now.to!string);
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now + orphanedDialProofMs - 1);
    check!("unstamped marker kept inside window after first sight")(field(r, "old") !is null);
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now + orphanedDialProofMs);
    check!("unstamped marker retired one window after first sight")(field(r, "old") is null);
    check!("other incarnation's marker not stamped by this holder")(
        field(r, "pid") is null);
    r.redis.getDb().del(r.key);
}

void runIncarnationChange() {
    auto r = rig();
    const fresh = "holder_v1:" ~ holderA ~ "@" ~ now.to!string;
    put(r, "gone", fresh);
    put(r, "pidGone", "holder_v1:legacy-pid:7@" ~ now.to!string);
    retireOrphanedDials(r.redis, r.sid, r.nid, holderB, now);
    check!("marker of a replaced UUID holder retired at any age")(field(r, "gone") is null);
    check!("marker of an old pid-only holder retired by a UUID holder")(field(r, "pidGone") is null);

    put(r, "other", "holder_v1:legacy-pid:7@" ~ now.to!string);
    retireOrphanedDials(r.redis, r.sid, r.nid, "legacy-pid:8", now);
    check!("pid-only holder cannot prove a different pid gone")(field(r, "other") !is null);
    r.redis.getDb().del(r.key);
}

void runUnversionedMarkerUntouched() {
    auto r = rig();
    put(r, "old", "1");
    retireOrphanedDials(r.redis, r.sid, r.nid, holderA, now + 100 * orphanedDialProofMs);
    check!("unversioned marker stays unproven")(field(r, "old") == "1");
    r.redis.getDb().del(r.key);
}

int main() {
    stderr.writeln("ircfiber.irc.dial_guard marker retirement tests");

    void dispatch(string name)(void function() body) {
        stderr.writeln("\n--- ", name, " ---");
        const before = failed;
        try {
            body();
            stderr.writeln(failed > before ? "  [FAIL] " : "  [PASS] ", name);
        } catch (Exception e) {
            ++failed;
            stderr.writeln("  [FAIL] ", name, " — uncaught exception: ", e.msg);
        }
    }

    dispatch!("test_aged_same_incarnation_retired")(&runAgedSameIncarnationRetired);
    dispatch!("test_young_marker_retained")(&runYoungMarkerRetained);
    dispatch!("test_live_dial_never_retired")(&runLiveDialNeverRetired);
    dispatch!("test_unstamped_marker_ages_from_first_sight")(&runUnstampedMarkerAgesFromFirstSight);
    dispatch!("test_incarnation_change")(&runIncarnationChange);
    dispatch!("test_unversioned_marker_untouched")(&runUnversionedMarkerUntouched);

    stderr.writeln("\n────────────────────────────────────────");
    stderr.writeln(passed, " passed, ", failed, " failed");
    return failed == 0 ? 0 : 1;
}
