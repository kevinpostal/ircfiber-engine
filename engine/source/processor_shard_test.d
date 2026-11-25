/// Standalone integration test for the event processor's per-owner ordering
/// and flood throughput.
///
/// Many owners each get a burst of PRIVMSGs, interleaved round-robin on the
/// one shared `EngineEventChannel`, as a flood in a channel every user shares
/// would arrive. The real `startEventProcessor` runs against real Redis and
/// Mongo. Asserted, whatever the processor's internal parallelism:
///   - every event reaches its owner's user stream and its network's Redis
///     scrollback, exactly once;
///   - within one owner, stream order == input order and eids strictly rise
///     (the gateway drops live frames with `eid <= lastDeliveredEid`);
///   - all eids are distinct;
///   - the live channel of one owner carries every frame, eids rising.
/// The measured admission rate is printed as `[bench]` (informational).
///
/// Requires the local Redis (6379) and MongoDB (27017) of the dev stack.
/// Env: IRCFIBER_REDIS_URL (default redis://127.0.0.1:6379),
///      PROCESSOR_TEST_MONGO_URL (default mongodb://127.0.0.1:27017/ircfiber_processortest).
/// Run with: `make -f Makefile.engine processor-shard-test`.
module processor_shard_test;

import core.stdc.stdlib : _Exit;
import core.time : MonoTime, msecs;
import std.algorithm : canFind, reverse;
import std.conv : to;
import std.process : environment;
import std.stdio : stderr, stdout, writeln;
import std.uuid : UUID, randomUUID;

import ircfiber.engine.event_channel : EngineEventChannel;
import vibe.core.core : runApplication, runTask, sleep;
import vibe.data.bson : Bson;
import vibe.data.json : Json, parseJsonString;
import vibe.db.redis.redis : RedisSubscriber;

import ircfiber.db.messages : MessageRepository;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.engine.bootstrap : EngineContext;
import ircfiber.engine.processor : startEventProcessor;
import ircfiber.irc.manager : ConnectionManager;
import ircfiber.irc.parser : parseIRCLineNamed;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : NetworkConfig;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.storage.redis : RedisStorage, stopEventSubscriber;

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

enum SERVER_ID = "processor-shard-test";
enum MONGO_DB = "ircfiber_processortest";
enum OWNERS = 24;
enum EVENTS_PER_OWNER = 400;

/// Engine context the processor fiber runs against (outlives `run`).
EngineContext g_ctx;
/// Every frame published on owner 0's live channel.
string[] published;
/// Listener on that channel (module-level: see processor_ctcp_test).
RedisSubscriber g_sub;

struct Owner {
    UUID userId;
    string uid;
    string nid;
    string[] ids; /// ev.id in input order
}

/// Every row in any Redis scrollback list of the network.
string[] scrollbackRows(RedisStorage redis, string networkId) {
    auto db = redis.getDb();
    string[] keys;
    foreach (k; db.keys("scrollback:*" ~ networkId ~ "*")) keys ~= k.idup;
    string[] rows;
    foreach (k; keys)
        foreach (r; db.lrange(k, 0, -1)) rows ~= r.idup;
    return rows;
}

/// The user's stream, oldest first.
string[] streamRowsOldestFirst(RedisStorage redis, string userId) {
    string[] rows;
    foreach (r; redis.getDb().lrange(RedisKeys.userStream(userId), 0, -1)) rows ~= r.idup;
    reverse(rows);
    return rows;
}

long totalStreamed(RedisStorage redis, ref Owner[OWNERS] owners) {
    long n;
    foreach (ref o; owners) n += redis.getDb().llen(RedisKeys.userStream(o.uid));
    return n;
}

void cleanup(RedisStorage redis, ref Owner o) {
    try {
        auto db = redis.getDb();
        string[] keys;
        foreach (pattern; ["scrollback:*" ~ o.nid ~ "*", "dedup:*" ~ o.nid ~ "*"])
            foreach (k; db.keys(pattern)) keys ~= k.idup;
        keys ~= RedisKeys.userStream(o.uid);
        foreach (k; keys) db.del(k);
    } catch (Exception e) {
        stderr.writeln("cleanup (redis): ", e.msg);
    }
    try {
        AppMongoConnection.getDb()["messages"].deleteMany(Bson(["networkId": Bson(o.nid)]));
    } catch (Exception e) {
        stderr.writeln("cleanup (mongo): ", e.msg);
    }
}

int run() {
    stderr.writeln("Event processor shard/throughput integration suite");

    const redisUrl = environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");
    RedisStorage redis;
    RedisStorage subRedis;
    try {
        redis = new RedisStorage();
        redis.connectFromUrl(redisUrl);
        redis.ping();
        subRedis = new RedisStorage();
        subRedis.connectFromUrl(redisUrl);
    } catch (Exception e) {
        stderr.writeln("FATAL: Redis unavailable: ", e.msg);
        return 2;
    }
    try {
        AppMongoConnection.connect(environment.get("PROCESSOR_TEST_MONGO_URL",
            "mongodb://127.0.0.1:27017/" ~ MONGO_DB), MONGO_DB);
        AppMongoConnection.getDb()["messages"].findOne(Bson(["_id": Bson("__probe__")]));
    } catch (Exception e) {
        stderr.writeln("FATAL: MongoDB unavailable: ", e.msg);
        return 2;
    }

    auto events = EngineEventChannel.create();
    auto mgr = new ConnectionManager(events, redis, SERVER_ID, null);

    Owner[OWNERS] owners;
    string[OWNERS] names;
    foreach (i; 0 .. OWNERS) {
        owners[i].userId = randomUUID();
        owners[i].uid = owners[i].userId.toString();
        NetworkConfig cfg;
        cfg.id = randomUUID();
        cfg.name = "ShardNet" ~ i.to!string;
        // Register a real deferred client/owner; this test never starts its dialer.
        cfg.host = "127.0.0.1";
        cfg.nick = "me";
        owners[i].nid = cfg.id.toString();
        names[i] = cfg.name;
        mgr.addNetwork(cfg, owners[i].userId);
        if (mgr.getOwnerId(cfg.id) != owners[i].uid) {
            stderr.writeln("FATAL: fixture owner not registered");
            return 2;
        }
    }

    g_ctx.connManager = mgr;
    g_ctx.redis = redis;
    g_ctx.bufferManager = new BufferManager(redis);
    g_ctx.messageRepo = new MessageRepository();
    g_ctx.eventChannel = events;
    g_ctx.localServer.serverId = SERVER_ID;

    g_sub = subRedis.getClient().createSubscriber();
    g_sub.subscribe(RedisKeys.events(owners[0].uid));
    g_sub.listen((string channel, string message) @safe nothrow { published ~= message; });

    runTask(() nothrow {
        try startEventProcessor(g_ctx);
        catch (Exception e) {
            try stderr.writeln("processor crashed: ", e.msg); catch (Exception) {}
        }
    });

    // Build every event up front so timing covers the processor only.
    IRCRawEvent[][OWNERS] built;
    foreach (i; 0 .. OWNERS) {
        foreach (n; 0 .. EVENTS_PER_OWNER) {
            auto ev = parseIRCLineNamed(
                ":flood!u@h PRIVMSG #flood :line " ~ i.to!string ~ "-" ~ n.to!string,
                names[i], owners[i].nid);
            ev.network = names[i];
            ev.networkId = owners[i].nid;
            ev.channel = "#flood";
            owners[i].ids ~= ev.id;
            built[i] ~= ev;
        }
    }

    const expected = cast(long) OWNERS * EVENTS_PER_OWNER;
    const started = MonoTime.currTime;
    // Round-robin so owners interleave in the channel, as a shared-channel flood does.
    // put() blocks (yielding) while the channel is full, so run it as its own
    // fiber and let the main fiber poll for completion.
    bool producerDone;
    runTask(() nothrow {
        try {
            foreach (n; 0 .. EVENTS_PER_OWNER)
                foreach (i; 0 .. OWNERS)
                    events.put(built[i][n]);
        } catch (Exception e) {
            try stderr.writeln("producer crashed: ", e.msg); catch (Exception) {}
        }
        producerDone = true;
    });

    long streamed;
    foreach (_; 0 .. 180 * 20) {
        streamed = totalStreamed(redis, owners);
        if (producerDone && streamed >= expected) break;
        sleep(50.msecs);
    }
    const elapsedMs = (MonoTime.currTime - started).total!"msecs";
    const rate = elapsedMs > 0 ? expected * 1000.0 / elapsedMs : 0.0;
    stderr.writeln("[bench] ", streamed, " events in ", elapsedMs, " ms = ",
        cast(long) rate, " ev/s");
    // Let in-flight tails (Mongo writes, late frames) land.
    sleep(500.msecs);

    stderr.writeln("\n[completeness] every event stored once");
    bool allComplete = true;
    string completeMsg;
    foreach (i, ref o; owners) {
        const sr = redis.getDb().llen(RedisKeys.userStream(o.uid));
        const sb = scrollbackRows(redis, o.nid).length;
        if (sr != EVENTS_PER_OWNER || sb != EVENTS_PER_OWNER) {
            allComplete = false;
            completeMsg ~= "owner " ~ i.to!string ~ " stream=" ~ sr.to!string
                ~ " scrollback=" ~ sb.to!string ~ "; ";
        }
    }
    check!("every owner has exactly EVENTS_PER_OWNER stream rows and scrollback rows")(
        allComplete, completeMsg);

    stderr.writeln("\n[order] per-owner order and eids");
    bool orderOk = true;
    bool eidsRise = true;
    string orderMsg;
    bool[long] seen;
    bool distinct = true;
    foreach (i, ref o; owners) {
        auto rows = streamRowsOldestFirst(redis, o.uid);
        if (rows.length != o.ids.length) {
            orderOk = false;
            orderMsg ~= "owner " ~ i.to!string ~ " rows=" ~ rows.length.to!string ~ "; ";
            continue;
        }
        long prev = 0;
        foreach (k, r; rows) {
            auto j = parseJsonString(r);
            if (j["i"].get!string != o.ids[k]) {
                if (orderOk) orderMsg ~= "owner " ~ i.to!string ~ " row " ~ k.to!string ~ " out of order; ";
                orderOk = false;
            }
            const eid = j["eid"].get!long;
            if (eid <= prev) {
                if (eidsRise) orderMsg ~= "owner " ~ i.to!string ~ " eid not rising at " ~ k.to!string ~ "; ";
                eidsRise = false;
            }
            prev = eid;
            if (eid in seen) distinct = false;
            seen[eid] = true;
        }
    }
    check!("stream order equals input order for every owner")(orderOk, orderMsg);
    check!("eids strictly increase within every owner")(eidsRise, orderMsg);
    check!("all eids distinct across owners")(distinct && seen.length == expected,
        seen.length.to!string);

    stderr.writeln("\n[live] owner 0 subscriber");
    check!("owner 0 received exactly EVENTS_PER_OWNER frames")(
        published.length == EVENTS_PER_OWNER, published.length.to!string);
    bool liveRise = true;
    long prevLive = 0;
    foreach (f; published) {
        const eid = parseJsonString(f)["eid"].get!long;
        if (eid <= prevLive) liveRise = false;
        prevLive = eid;
    }
    check!("owner 0 live eids strictly increase in arrival order")(liveRise);

    stderr.writeln("\n[replay] typing live only; reactions, NAMES and chat replay in a bounded tail");
    const stream = RedisKeys.userStream(owners[0].uid);
    IRCRawEvent wireEvent(string command) {
        auto ev = IRCRawEvent(names[0], command);
        ev.networkId = owners[0].nid;
        ev.channel = "#flood";
        ev.nick = "flood";
        ev.setParams(["#flood", "chat"]);
        return ev;
    }
    bool awaitLive(size_t length, string id) {
        foreach (_; 0 .. 500) {
            if (published.length >= length)
                return parseJsonString(published[length - 1])["i"].get!string == id;
            sleep(10.msecs);
        }
        return false;
    }
    auto typing = wireEvent("TAGMSG");
    typing.addTag("+typing", "active");
    events.put(typing);
    check!("typing reaches live subscribers but not the user stream")(
        awaitLive(EVENTS_PER_OWNER + 1, typing.id)
        && redis.getDb().llen(stream) == EVENTS_PER_OWNER);

    auto reaction = wireEvent("TAGMSG");
    reaction.addTag("+reply", "target-message");
    reaction.addTag("+react", "👍");
    auto expectedIds = owners[0].ids;
    foreach (_; 0 .. 110) {
        auto message = wireEvent("PRIVMSG");
        events.put(message);
        expectedIds ~= message.id;
    }
    events.put(reaction);
    expectedIds ~= reaction.id;
    foreach (command; ["353", "366"]) {
        auto roster = wireEvent(command);
        events.put(roster);
        expectedIds ~= roster.id;
    }
    check!("the live subscriber also gets the last resumable event")(
        awaitLive(expectedIds.length + 1, expectedIds[$ - 1]));
    auto tail = streamRowsOldestFirst(redis, owners[0].uid);
    bool replayOk = tail.length == 500;
    if (replayOk) {
        expectedIds = expectedIds[$ - 500 .. $];
        foreach (i, raw; tail)
            replayOk &= parseJsonString(raw)["i"].get!string == expectedIds[i];
    }
    check!("replay keeps exactly the newest 500 chat/reaction/NAMES events, in order")(replayOk);

    stopEventSubscriber(g_sub, RedisKeys.events(owners[0].uid));
    check!("live-channel listener stopped")(!g_sub.isListening);
    foreach (ref o; owners) cleanup(redis, o);
    bool clean = true;
    foreach (ref o; owners)
        if (scrollbackRows(redis, o.nid).length != 0
                || redis.getDb().llen(RedisKeys.userStream(o.uid)) != 0) clean = false;
    check!("Redis scrollback and user streams cleaned up")(clean);

    writeln("\n", passed, " passed, ", failed, " failed");
    return failed == 0 ? 0 : 1;
}

int main() {
    runTask(() nothrow {
        int rc = 1;
        try rc = run();
        catch (Throwable e) {
            try stderr.writeln("FATAL: ", e.msg); catch (Exception) {}
            rc = 1;
        }
        try { stdout.flush(); stderr.flush(); } catch (Exception) {}
        // The processor fiber loops forever, so the event loop never drains;
        // leave without runtime teardown.
        _Exit(rc);
    });
    runApplication();
    return 1;
}
