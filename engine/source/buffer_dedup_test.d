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
/// Requires an isolated loopback Redis via IRCFIBER_HISTORY_TEST_REDIS_URL.
/// Build: `dub build --config=buffer-dedup-test`
/// Run: `IRCFIBER_HISTORY_TEST_REDIS_URL=redis://127.0.0.1:16379 ./buffer-dedup-test`
module buffer_dedup_test;

import std.conv : to;
import std.stdio : stderr, writeln;
import std.uuid : randomUUID;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.testing.isolated_db : isolatedTestRedis;

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
    auto redis = isolatedTestRedis("BufferManager dedup");
    if (redis is null)
        throw new Exception("Explicit isolated IRCFIBER_HISTORY_TEST_REDIS_URL is required");
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

void test_reply_and_reaction_history(RedisStorage redis) {
    stderr.writeln("\n[history] replies and reaction transitions survive Redis replay");
    foreach (legacy; [false, true]) {
        foreach (draftTags; [false, true]) {
            auto bm = new BufferManager(redis);
            const nid = randomUUID().toString();
            scope (exit) cleanup(redis, nid);
            IRCRawEvent event(string command, string msgid, long t) {
                auto ev = IRCRawEvent("TestNet", command);
                ev.networkId = nid;
                ev.channel = "#chan";
                ev.nick = "alice";
                ev.timestampMs = t;
                ev.addTag("msgid", msgid);
                ev.setParams(["#chan"]);
                return ev;
            }
            void append(IRCRawEvent ev) {
                if (legacy) bm.appendIRCEvent(ev);
                else bm.appendIRCEvent(ev, "engine1");
            }
            auto original = event("PRIVMSG", "original", 1);
            original.text = "hello";
            append(original);
            auto reply = event("PRIVMSG", "reply", 2);
            reply.text = "answer";
            reply.addTag(draftTags ? "+draft/reply" : "+reply", "original");
            if (!draftTags) reply.addTag("+draft/reply", "wrong-target");
            append(reply);
            auto reaction = event("TAGMSG", "reaction", 3);
            reaction.addTag(draftTags ? "+draft/reply" : "+reply", "original");
            reaction.addTag(draftTags ? "+draft/react" : "+react", "👍");
            if (!draftTags) {
                reaction.addTag("+draft/reply", "wrong-target");
                reaction.addTag("+draft/react", "👀");
            }
            append(reaction);
            auto removal = event("TAGMSG", "removal", 4);
            removal.addTag(draftTags ? "+draft/reply" : "+reply", "original");
            removal.addTag(draftTags ? "+draft/unreact" : "+unreact", "👍");
            if (!draftTags) removal.addTag("+draft/unreact", "👀");
            append(removal);
            auto typing = event("TAGMSG", "typing", 5);
            typing.addTag("+typing", "active");
            append(typing);

            auto history = legacy ? bm.getRecent(nid, "#chan", 50)
                                  : bm.getRecent("engine1", nid, "#chan", 50);
            check!("history retains both reaction transitions but excludes typing")(history.length == 4);
            if (history.length != 4) continue;
            check!("reply still names its original message")(history[1]["rp"].get!string == "original");
            check!("reaction target and emoji survive reload")(
                history[2]["rp"].get!string == "original" && history[2]["rx"].get!string == "👍");
            check!("reaction removal survives reload")(
                history[3]["rp"].get!string == "original" && history[3]["ux"].get!string == "👍");
            check!("replayed transitions retain their actor and order")(
                history[2]["n"].get!string == "alice" && history[2]["t"].get!long < history[3]["t"].get!long);
        }
    }
}

/// The production forms differ only in transport metadata and extended JOIN.
IRCRawEvent stateEvent(string nid, string command, bool historical,
        string msgid = "history-state", string time = "2026-11-10T22:00:00.123Z") {
    import std.datetime.systime : SysTime;
    auto ev = joinEvent(nid, "#chan", "alice", 0);
    ev.command = command;
    const stamp = SysTime.fromISOExtString(time);
    ev.timestampMs = stamp.toUnixTime!long * 1000 + stamp.fracSecs.total!"msecs";
    ev.addTag("time", time);
    if (command == "JOIN") {
        ev.setParams(historical ? ["#chan"] : ["#chan", "alice", "Alice Real Name"]);
        ev.text = historical ? "" : "Alice Real Name";
        if (!historical) ev.addTag("account", "alice");
    } else {
        ev.setParams(["#chan", "+v", "alice"]);
    }
    if (historical) {
        ev.addTag("batch", "chathistory");
        ev.addTag("msgid", msgid);
    }
    return ev;
}

void test_state_replay_both_arrival_orders(RedisStorage redis) {
    stderr.writeln("\n[dedup] extended/basic JOIN and voice replay, both arrival orders");
    foreach (command; ["JOIN", "MODE"]) foreach (historyFirst; [false, true]) {
        const nid = randomUUID().toString();
        scope (exit) cleanup(redis, nid);
        auto first = stateEvent(nid, command, historyFirst);
        auto second = stateEvent(nid, command, !historyFirst);
        auto bm = new BufferManager(redis);
        check!("first state form stores")(bm.appendIRCEvent(first, "engine1"));
        // Fresh process-local state and a different server namespace.
        bm = new BufferManager(redis);
        check!("opposite provenance is suppressed after reassignment")(
            !bm.appendIRCEvent(second, "engine2"));
        check!("both event UUIDs differ")(first.id != second.id);
        foreach (_; 0 .. 3) {
            auto replay = stateEvent(nid, command, true);
            check!("repeated CHATHISTORY playback stays suppressed")(
                !bm.appendIRCEvent(replay, "engine2"));
        }
        auto stored = bm.getRecent("engine1", nid, "#chan", 50);
        check!("only the first physical row persists")(stored.length == 1);
        check!("reassignment does not create a second scrollback row")(
            bm.getRecent("engine2", nid, "#chan", 50).length == 0);
        if (stored.length == 1 && command == "JOIN" && !historyFirst) {
            check!("extended JOIN payload is retained, not rewritten")(
                stored[0]["x"].get!string == "Alice Real Name"
                && stored[0]["p"].length == 3
                && stored[0]["a"].get!string == "alice");
        }
        // Once suppressed, replay identity must work without the semantic alias.
        auto primaryRetry = stateEvent(nid, command, true);
        primaryRetry.tagsJson = `{ "msgid": "history-state" }`;
        check!("suppressed replay records its primary msgid")(
            !bm.appendIRCEvent(primaryRetry, "engine2"));
    }
}

void test_state_identity_boundaries(RedisStorage redis) {
    stderr.writeln("\n[dedup] state semantic identity does not erase distinct events");
    foreach (command; ["JOIN", "MODE"]) foreach (difference; 0 .. 6) {
        const nid = randomUUID().toString();
        scope (exit) cleanup(redis, nid);
        auto bm = new BufferManager(redis);
        auto live = stateEvent(nid, command, false);
        auto replay = stateEvent(nid, command, true);
        switch (difference) {
            case 0:
                replay = stateEvent(nid, command, true, "other-time", "2026-11-10T22:00:00.124Z");
                break;
            case 1:
                replay.nick = "bob";
                replay.prefix = "bob!user@cloaked.example";
                break;
            case 2:
                replay.channel = "#other";
                replay.setParams(command == "JOIN" ? ["#other"] : ["#other", "+v", "alice"]);
                break;
            case 3:
                replay.prefix = "alice!other@cloaked.example";
                break;
            case 4:
                // Same milliseconds, distinct actual server-time precision.
                replay = stateEvent(nid, command, true, "sub-ms", "2026-11-10T22:00:00.123100Z");
                break;
            case 5:
                replay.prefix = "Alice!user@cloaked.example";
                replay.nick = "Alice";
                break;
            default: assert(0, "Unknown identity boundary");
        }
        check!("baseline state stores")(bm.appendIRCEvent(live, "engine1"));
        check!("different timestamp, nick, channel or exact prefix survives")(
            bm.appendIRCEvent(replay, "engine1"));
    }
    foreach (changedText; [false, true]) {
        const nid = randomUUID().toString();
        scope (exit) cleanup(redis, nid);
        auto bm = new BufferManager(redis);
        auto live = stateEvent(nid, "MODE", false);
        live.setParams(["#chan", "+ov", "alice", "bob"]);
        auto replay = stateEvent(nid, "MODE", true);
        replay.setParams(["#chan", "+ov", "bob", "alice"]);
        if (changedText) {
            replay.setParams(["#chan", "+ov", "alice", "bob"]);
            replay.text = "different trailing content";
        }
        check!("ordered MODE baseline stores")(bm.appendIRCEvent(live, "engine1"));
        check!("MODE retains ordered bindings and full text identity")(
            bm.appendIRCEvent(replay, "engine1"));
    }
}

void test_state_alias_provenance(RedisStorage redis) {
    stderr.writeln("\n[dedup] semantic aliases apply only across accepted provenance");
    foreach (command; ["JOIN", "MODE"]) foreach (historical; [false, true]) {
        const nid = randomUUID().toString();
        scope (exit) cleanup(redis, nid);
        auto bm = new BufferManager(redis);
        auto a = stateEvent(nid, command, historical, "tagged-a");
        a.addTag("msgid", "tagged-a");
        auto b = stateEvent(nid, command, historical, "tagged-b");
        b.addTag("msgid", "tagged-b");
        check!("first genuine msgid event stores")(bm.appendIRCEvent(a, "engine1"));
        if (historical) {
            auto live = stateEvent(nid, command, false);
            check!("live counterpart of accepted history is suppressed")(
                !bm.appendIRCEvent(live, "engine1"));
            check!("suppressed live primary is remembered")(
                !bm.appendIRCEvent(live, "engine1"));
        }
        check!("distinct genuine msgid event with identical content survives")(
            bm.appendIRCEvent(b, "engine1"));
        check!("genuine tagged retries still deduplicate")(
            !bm.appendIRCEvent(a, "engine1") && !bm.appendIRCEvent(b, "engine1"));
    }
}

void test_state_alias_requires_wire_identity(RedisStorage redis) {
    stderr.writeln("\n[dedup] incomplete or ineligible wire identity never bridges");
    foreach (command; ["JOIN", "MODE"]) foreach (invalid; 0 .. 7) {
        const nid = randomUUID().toString();
        scope (exit) cleanup(redis, nid);
        auto bm = new BufferManager(redis);
        auto live = stateEvent(nid, command, false);
        auto replay = stateEvent(nid, command, true);
        switch (invalid) {
            case 0: live.tagsJson = "{}"; break;
            case 1: live.addTag("time", "not-a-time"); break;
            case 2: live.addTag("time", "2026-11-10T22:00:00.123"); break;
            case 3: live.prefix = replay.prefix = ""; break;
            case 4:
                live.channel = replay.channel = "";
                break;
            case 5: live.addTag("msgid", "tagged-live"); break;
            case 6: live.addTag("batch", "chathistory"); break;
            default: assert(0, "Unknown invalid identity");
        }
        check!("ineligible baseline retains primary behavior")(bm.appendIRCEvent(live, "engine1"));
        check!("no semantic bridge without complete eligible identity")(
            bm.appendIRCEvent(replay, "engine1"));
    }
}

void test_state_alias_failure_atomicity(RedisStorage redis) {
    stderr.writeln("\n[dedup] alias storage validates types before any primary/alias writes");
    foreach (command; ["JOIN", "MODE"]) {
        const nid = randomUUID().toString();
        scope (exit) cleanup(redis, nid);
        auto bm = new BufferManager(redis);
        auto db = redis.getDb();
        auto live = stateEvent(nid, command, false);
        auto replay = stateEvent(nid, command, true);
        const rowKey = "scrollback:engine1:" ~ nid ~ ":#chan";
        const replayKey = "scrollback:engine2:" ~ nid ~ ":#chan";
        const dedupKey = "dedup:" ~ nid ~ ":#chan";
        db.set(rowKey, "wrong-type");
        bool rejected;
        try bm.appendIRCEvent(live, "engine1"); catch (Exception) { rejected = true; }
        check!("failed live append leaves no alias or primary")(rejected && !db.exists(dedupKey));
        db.del(rowKey);
        db.set(dedupKey, "wrong-type");
        rejected = false;
        try bm.appendIRCEvent(live, "engine1"); catch (Exception) { rejected = true; }
        check!("invalid dedup storage leaves no row")(rejected && !db.exists(rowKey));
        db.del(dedupKey);
        check!("repaired storage accepts the exact failed live row")(
            bm.appendIRCEvent(live, "engine1"));
        db.set(replayKey, "wrong-type");
        rejected = false;
        try bm.appendIRCEvent(replay, "engine2"); catch (Exception) { rejected = true; }
        check!("alias duplicate still preflights destination type")(rejected);
        auto primary = replay;
        primary.tagsJson = `{ "msgid": "history-state" }`;
        db.del(replayKey);
        check!("failed alias verdict did not poison replay primary")(
            bm.appendIRCEvent(primary, "engine2"));
        check!("live alias still suppresses another replay ID")(
            !bm.appendIRCEvent(stateEvent(nid, command, true, "history-state-2"), "engine2"));
    }
}

void test_repeated_chat_identity_is_unchanged(RedisStorage redis) {
    stderr.writeln("\n[dedup] state bridge never collapses repeated chat");
    foreach (command; ["PRIVMSG", "NOTICE"]) {
        const nid = randomUUID().toString();
        scope (exit) cleanup(redis, nid);
        auto bm = new BufferManager(redis);
        auto a = stateEvent(nid, "MODE", false);
        a.command = command;
        a.text = "same text";
        a.setParams(["#chan"]);
        auto b = a;
        b.id = randomUUID().toString();
        check!("same-millisecond same-text live chat keeps both UUIDs")(
            bm.appendIRCEvent(a, "engine1") && bm.appendIRCEvent(b, "engine1"));
        check!("live chat UUID retries remain duplicates")(
            !bm.appendIRCEvent(a, "engine1") && !bm.appendIRCEvent(b, "engine1"));
        b.addTag("batch", "chathistory");
        b.addTag("msgid", "chat-history");
        check!("state alias does not bridge chat with different primary IDs")(
            bm.appendIRCEvent(b, "engine1") && !bm.appendIRCEvent(b, "engine1"));
    }
}

int main() {
    stderr.writeln("BufferManager dedup regression suite");
    RedisStorage redis;
    try {
        redis = connect();
        redis.getDb().exists("probe");
    } catch (Exception e) {
        stderr.writeln("FATAL: isolated test Redis unavailable: ", e.msg);
        return 1;
    }

    test_second_append_is_reported_duplicate(redis);
    test_dedup_survives_server_reassignment(redis);
    test_legacy_server_scoped_set_is_adopted(redis);
    test_distinct_events_are_not_collapsed(redis);
    test_clear_buffer_drops_both_dedup_spellings(redis);
    test_reply_and_reaction_history(redis);
    test_state_replay_both_arrival_orders(redis);
    test_state_identity_boundaries(redis);
    test_state_alias_provenance(redis);
    test_state_alias_requires_wire_identity(redis);
    test_state_alias_failure_atomicity(redis);
    test_repeated_chat_identity_is_unchanged(redis);

    writeln("\n", passed, " passed, ", failed, " failed");
    return failed == 0 ? 0 : 1;
}
