module loadtest.main;

import vibe.core.core : runTask, sleep, runApplication;
import core.stdc.stdlib : exit;
import vibe.db.redis.redis : connectRedis, RedisClient, RedisDatabase;
import vibe.data.json : Json;
import vibe.core.log;
import std.datetime : Clock, SysTime, Duration;
import std.conv : to;
import core.time : msecs, seconds;
import std.stdio : writeln;
import std.uuid : randomUUID;
import std.algorithm.searching : startsWith;
import std.string : indexOf, lastIndexOf;

/// Parse a Redis URL into host and port.
/// Supports "redis://host:port" format.
private void parseRedisUrl(string url, out string host, out ushort port) {
    host = "127.0.0.1";
    port = 6379;
    if (url.startsWith("redis://")) {
        auto rest = url[8 .. $];
        auto slashIdx = rest.indexOf("/");
        if (slashIdx >= 0) rest = rest[0 .. slashIdx];
        auto colonIdx = rest.lastIndexOf(":");
        if (colonIdx >= 0) {
            host = rest[0 .. colonIdx];
            port = to!ushort(rest[colonIdx + 1 .. $]);
        } else {
            host = rest;
        }
    }
}

/// Generate a synthetic PRIVMSG event matching the engine's toCompactJson format.
private string generateEvent(long eid, long ts, string nick, string channel, string text) {
    auto j = Json.emptyObject;
    j["network"] = "loadtest";
    j["i"] = randomUUID().toString();
    j["t"] = ts;
    j["c"] = "PRIVMSG";
    j["eid"] = eid;
    j["n"] = nick;
    j["ch"] = channel;
    j["x"] = text;
    j["m"] = randomUUID().toString();
    j["y"] = "irc_event";
    j["serverId"] = "loadtest";
    return j.toString();
}

/// Generate a single batch of events (returns strings ready to publish).
private string[] generateBatch(long baseEid, long ts, int count) {
    auto events = new string[count];
    foreach (i; 0 .. count) {
        auto eid = baseEid + i;
        auto nick = "user_" ~ to!string((eid % 50) + 1);
        auto chanNum = (eid % 3) + 1;
        auto channel = "#loadtest" ~ to!string(chanNum);
        auto msg = "Test message " ~ to!string(eid) ~ " from ircfiber-loadtest";
        events[i] = generateEvent(eid, ts, nick, channel, msg);
    }
    return events;
}

/// The main loadtest fiber.
private void loadtestFiber(string redisHost, ushort redisPort, string userId,
    int rps, int durationSec) nothrow {
    try {
        logInfo("Connecting to Redis at %s:%s...", redisHost, redisPort);
        auto client = connectRedis(redisHost, redisPort);
        auto db = client.getDatabase(0);
        logInfo("Connected to Redis.");

        auto channel = "irc:events:" ~ userId;

        const int batchN = 100;
        long sent = 0;
        long errors = 0;
        const startTime = Clock.currTime;
        const endAt = startTime + seconds(durationSec);

        writeln("\nPublishing events to ", channel, " ...");

        while (Clock.currTime < endAt) {
            auto nowMs = Clock.currTime.toUnixTime!long * 1000;
            const long batchBaseEid = sent + 1;

            auto batch = generateBatch(batchBaseEid, nowMs, batchN);

            foreach (evt; batch) {
                try {
                    db.publish(channel, evt);
                    sent++;
                } catch (Exception e) {
                    errors++;
                    if (errors <= 5)
                        logWarn("Publish error #%s: %s", errors, e.msg);
                }
            }

            // Rate control
            const elapsed = (Clock.currTime - startTime).total!"seconds";
            if (elapsed > 0) {
                const long expectedSent = elapsed * rps;
                if (sent > expectedSent + batchN) {
                    const long overshoot = sent - expectedSent;
                    long sleepMs = (overshoot * 1000) / rps;
                    if (sleepMs > 0) {
                        sleep((sleepMs).msecs);
                    }
                }
            }

            // Yield periodically
            if (sent % 1000 == 0) {
                sleep(1.msecs);
            }
        }

        auto elapsed = (Clock.currTime - startTime).total!"seconds";
        const long actualRps = elapsed > 0 ? sent / elapsed : 0;

        auto result = Json.emptyObject;
        result["targetRps"] = Json(rps);
        result["durationSec"] = Json(durationSec);
        result["sent"] = Json(sent);
        result["errors"] = Json(errors);
        result["actualRps"] = Json(actualRps);
        result["elapsedSec"] = Json(elapsed);

        writeln("\n--- RESULT ---");
        writeln(result.toString());
    } catch (Exception e) {
        logError("Loadtest fiber error: %s", e.msg);
    }

    exit(0);
}

void main(string[] args) {
    // ── Parse arguments ────────────────────────────────────────────────
    string redisUrlStr = "redis://127.0.0.1:6379";
    string userId = "1d61f5b3-5f4d-49b1-a59f-03d79f58ac3c"; // default test user
    int rps = 10_000;
    int durationSec = 60;
    string redisHost;
    ushort redisPort = 6379;

    foreach (i, a; args) {
        if (a == "--redis-url" && i + 1 < args.length)
            redisUrlStr = args[i + 1];
        if (a == "--user" && i + 1 < args.length)
            userId = args[i + 1];
        if (a == "--rps" && i + 1 < args.length)
            rps = to!int(args[i + 1]);
        if (a == "--duration" && i + 1 < args.length)
            durationSec = to!int(args[i + 1]);
    }

    parseRedisUrl(redisUrlStr, redisHost, redisPort);

    writeln("ircfiber-loadtest starting");
    writeln("  Redis:      ", redisHost, ":", redisPort);
    writeln("  User:       ", userId);
    writeln("  Rate:       ", rps, " events/sec");
    writeln("  Duration:   ", durationSec, " sec");

    // ── Schedule loadtest fiber and start event loop ───────────────────
    runTask(() nothrow {
        loadtestFiber(redisHost, redisPort, userId, rps, durationSec);
    });

    // Pass non-null args_out so vibe.d doesn't error on our custom flags
    string[] dummyArgs;
    runApplication(&dummyArgs);
}
