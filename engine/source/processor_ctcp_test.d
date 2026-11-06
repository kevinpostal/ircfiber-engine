/// Standalone integration test for the event processor's publish-only gate
/// on CTCP diagnostics.
///
/// The connection marks every non-ACTION CTCP request/reply with the
/// `ctcp` tag and routes it to `_server` (connection.d `handlePrivmsg` and
/// the NOTICE switch). Its raw parameters can carry PING tokens or DCC
/// addresses, so the processor must publish it live only: an eid and a
/// frame on `irc:events:<user>`, but nothing in the Redis scrollback, the
/// Mongo `messages` collection, or the per-user stream `irc:stream:<user>`.
///
/// This drives the real `startEventProcessor` loop with real sinks — no
/// predicate-only checks. An untagged PRIVMSG is fed last as a positive
/// control: it must land in all three sinks, which proves the harness
/// would see a CTCP row if the gate regressed, and (being processed after
/// the CTCP events) that their fire-and-forget Mongo writes had their turn.
///
/// Requires the local Redis (6379) and MongoDB (27017) of the dev stack.
/// Env: IRCFIBER_REDIS_URL (default redis://127.0.0.1:6379),
///      PROCESSOR_TEST_MONGO_URL (default mongodb://127.0.0.1:27017/ircfiber_processortest).
/// Run with: `make -f Makefile.engine processor-ctcp-test`.
module processor_ctcp_test;

import core.stdc.stdlib : _Exit;
import core.time : msecs;
import std.algorithm : canFind, count, filter;
import std.array : array;
import std.conv : to;
import std.process : environment;
import std.stdio : stderr, stdout, writeln;
import std.uuid : randomUUID;

import vibe.core.channel : createChannel;
import vibe.core.core : runApplication, runTask, sleep;
import vibe.data.bson : Bson;
import vibe.data.json : Json, parseJsonString;
import vibe.db.mongo.collection : FindOptions;
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

enum SERVER_ID = "processor-ctcp-test";
enum MONGO_DB = "ircfiber_processortest";
enum NETWORK_NAME = "TestNet";

/// Engine context the processor fiber runs against (outlives `run`).
EngineContext g_ctx;
/// Every frame published on the test user's live channel.
string[] published;
/// Listener on that channel (module-level: see `run`).
RedisSubscriber g_sub;

/// A CTCP event exactly as the connection hands it to the processor: the
/// original command, prefix, params and text, tagged and routed to `_server`.
IRCRawEvent ctcpEvent(string line, string networkId, string verb) {
    auto ev = parseIRCLineNamed(line, NETWORK_NAME, networkId);
    ev.network = NETWORK_NAME;
    ev.networkId = networkId;
    ev.addTag("ctcp", verb);
    ev.channel = "_server";
    return ev;
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

/// Every row in the user's Redis event stream.
string[] streamRows(RedisStorage redis, string userId) {
    string[] rows;
    foreach (r; redis.getDb().lrange(RedisKeys.userStream(userId), 0, -1)) rows ~= r.idup;
    return rows;
}

/// Every Mongo `messages` payload stored for the network.
string[] mongoPayloads(string networkId) {
    string[] rows;
    auto coll = AppMongoConnection.getDb()["messages"];
    foreach (doc; coll.find(Bson(["networkId": Bson(networkId)]), FindOptions.init))
        rows ~= doc["payload"].get!string;
    return rows;
}

bool anyContains(string[] rows, string needle) {
    return rows.canFind!(r => r.canFind(needle));
}

void cleanup(RedisStorage redis, string networkId, string userId) {
    try {
        auto db = redis.getDb();
        string[] keys;
        foreach (pattern; ["scrollback:*" ~ networkId ~ "*", "dedup:*" ~ networkId ~ "*"])
            foreach (k; db.keys(pattern)) keys ~= k.idup;
        keys ~= RedisKeys.userStream(userId);
        foreach (k; keys) db.del(k);
    } catch (Exception e) {
        stderr.writeln("cleanup (redis): ", e.msg);
    }
    try {
        AppMongoConnection.getDb()["messages"].deleteMany(Bson(["networkId": Bson(networkId)]));
    } catch (Exception e) {
        stderr.writeln("cleanup (mongo): ", e.msg);
    }
}

/// Asserts one CTCP event reached the live channel verbatim, once, with an
/// eid and the compact `ct` marker, and none of the three storage sinks.
void checkDiagnostic(string label, ref IRCRawEvent ev, string verb, string secret,
                     string[] scrollback, string[] mongo, string[] stream) {
    stderr.writeln("\n[ctcp] ", label);
    const id = ev.id;
    auto frames = published.filter!(f => f.canFind(id)).array;
    check!("published live exactly once")(frames.length == 1, frames.length.to!string);
    if (frames.length == 1) {
        auto j = parseJsonString(frames[0]);
        check!("has an eid")(j["eid"].type == Json.Type.int_ && j["eid"].get!long > 0,
            j["eid"].toString());
        check!("original command")(j["c"].get!string == ev.command, j["c"].toString());
        check!("original text, CTCP delimiters intact")(
            j["x"].type == Json.Type.string && j["x"].get!string == ev.text, j["x"].toString());
        check!("original prefix")(j["px"].type == Json.Type.string
            && j["px"].get!string == ev.prefix, j["px"].toString());
        check!("original nick")(j["n"].type == Json.Type.string
            && j["n"].get!string == ev.nick, j["n"].toString());
        string[] params;
        if (j["p"].type == Json.Type.array)
            foreach (p; j["p"]) params ~= p.get!string;
        check!("original params")(params == ev.getParams(), params.to!string);
        check!("routed to _server")(j["ch"].type == Json.Type.string
            && j["ch"].get!string == "_server", j["ch"].toString());
        check!("compact ct marker carries the verb")(j["ct"].type == Json.Type.string
            && j["ct"].get!string == verb, j["ct"].toString());
    }
    check!("absent from Redis scrollback")(!anyContains(scrollback, ev.id));
    check!("absent from Mongo messages")(!anyContains(mongo, ev.id));
    check!("absent from the user stream")(!anyContains(stream, ev.id));
    if (secret.length) {
        check!("raw parameter never stored in any sink")(!anyContains(scrollback, secret)
            && !anyContains(mongo, secret) && !anyContains(stream, secret));
    }
}

int run() {
    stderr.writeln("Event processor CTCP publish-only integration suite");

    const redisUrl = environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");
    RedisStorage redis;
    // The live-channel listener gets its own client: a subscribed
    // connection serves nothing else, and the processor and cleanup must
    // never wait behind it.
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
        // The URI needs a `/db` path: AppMongoConnection appends query
        // options and vibe-d rejects `host:port?query`.
        AppMongoConnection.connect(environment.get("PROCESSOR_TEST_MONGO_URL",
            "mongodb://127.0.0.1:27017/" ~ MONGO_DB), MONGO_DB);
        // vibe-d connects lazily — force a round trip.
        AppMongoConnection.getDb()["messages"].findOne(Bson(["_id": Bson("__probe__")]));
    } catch (Exception e) {
        stderr.writeln("FATAL: MongoDB unavailable: ", e.msg);
        return 2;
    }

    const userId = randomUUID();
    const uid = userId.toString();
    NetworkConfig cfg;
    cfg.id = randomUUID();
    cfg.name = NETWORK_NAME;
    cfg.nick = "me";
    const nid = cfg.id.toString();

    auto events = createChannel!IRCRawEvent();
    // addNetwork only registers the client and its owner; nothing dials.
    auto mgr = new ConnectionManager(events, redis, SERVER_ID, null);
    mgr.addNetwork(cfg, userId);

    g_ctx.connManager = mgr;
    g_ctx.redis = redis;
    g_ctx.bufferManager = new BufferManager(redis);
    g_ctx.messageRepo = new MessageRepository();
    g_ctx.eventChannel = events;
    g_ctx.localServer.serverId = SERVER_ID;

    // Subscribe before anything is processed; listen() returns once the
    // subscription is live. Module-level so no scope destructor runs: the
    // subscriber's destructor blocks until its listener stops, which hung
    // the run when `run()` returned with the listener still active.
    g_sub = subRedis.getClient().createSubscriber();
    g_sub.subscribe(RedisKeys.events(uid));
    g_sub.listen((string channel, string message) @safe nothrow { published ~= message; });

    runTask(() nothrow {
        try startEventProcessor(g_ctx);
        catch (Exception e) {
            try stderr.writeln("processor crashed: ", e.msg); catch (Exception) {}
        }
    });

    const pingToken = "tok-" ~ randomUUID().toString();
    const dccAddr = "3232235777";
    auto versionReq = ctcpEvent(":alice!u@h PRIVMSG me :\x01VERSION\x01", nid, "VERSION");
    auto pingReply = ctcpEvent(":alice!u@h NOTICE me :\x01PING " ~ pingToken ~ "\x01", nid, "PING");
    auto malformed = ctcpEvent(":alice!u@h PRIVMSG me :\x01DCC SEND f " ~ dccAddr ~ " 5000",
        nid, "MALFORMED");
    auto control = parseIRCLineNamed(":alice!u@h PRIVMSG #ctcp-control :plain control", NETWORK_NAME, nid);
    control.network = NETWORK_NAME;
    control.networkId = nid;
    control.channel = "#ctcp-control";

    // Control last: once its async Mongo write has landed, the earlier CTCP
    // events' writes (if the gate regressed) would have been spawned first.
    foreach (ev; [versionReq, pingReply, malformed, control]) events.put(ev);

    foreach (_; 0 .. 100) {
        if (anyContains(mongoPayloads(nid), control.id) && anyContains(published, control.id)) break;
        sleep(100.msecs);
    }
    sleep(500.msecs);

    auto scrollback = scrollbackRows(redis, nid);
    auto mongo = mongoPayloads(nid);
    auto stream = streamRows(redis, uid);

    stderr.writeln("\n[control] untagged PRIVMSG reaches every sink");
    check!("published live")(anyContains(published, control.id));
    check!("stored in Redis scrollback")(anyContains(scrollback, control.id));
    check!("stored in Mongo messages")(anyContains(mongo, control.id));
    check!("stored in the user stream")(anyContains(stream, control.id));

    checkDiagnostic("direct VERSION request", versionReq, "VERSION", "", scrollback, mongo, stream);
    checkDiagnostic("PING reply NOTICE", pingReply, "PING", pingToken, scrollback, mongo, stream);
    checkDiagnostic("malformed DCC request", malformed, "MALFORMED", dccAddr, scrollback, mongo, stream);

    stderr.writeln("\n[ctcp] eids");
    long[] eids;
    foreach (f; published) {
        auto j = parseJsonString(f);
        if (j["eid"].type == Json.Type.int_) eids ~= j["eid"].get!long;
    }
    check!("every published event has a distinct eid")(eids.length == 4
        && eids.count!(e => eids.count(e) > 1) == 0, eids.to!string);

    // Stop the listener (UNSUBSCRIBE + wait for its fiber), then remove
    // this run's keys and rows from the real stores.
    g_sub.bstop();
    check!("live-channel listener stopped")(!g_sub.isListening);
    cleanup(redis, nid, uid);
    check!("Redis scrollback cleaned up")(scrollbackRows(redis, nid).length == 0);
    check!("user stream cleaned up")(streamRows(redis, uid).length == 0);
    check!("Mongo rows cleaned up")(mongoPayloads(nid).length == 0);

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
