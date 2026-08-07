module app_sync;

import std.stdio : writeln, writefln;
import std.getopt : getopt, defaultGetoptPrinter;
import core.stdc.stdlib : getenv;
import std.string : toStringz;

import vibe.core.log;

import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.messages : MessageRepository;
import ircfiber.storage.redis : RedisStorage;

/**
 * One-shot Redis→Mongo backfill.
 *
 * Usage:
 *   dub run --config=sync                                       # sync every scrollback buffer
 *   dub run --config=sync -- <serverId> <networkId> <channel>   # sync one buffer
 *
 * Env:
 *   IRCFIBER_MONGO_URL  (default mongodb://localhost:27017/ircfiber)
 *   IRCFIBER_REDIS_URL  (default redis://127.0.0.1:6379)
 */
void main(string[] args) {
    string serverId, networkId, channel;

    auto helpInfo = getopt(args,
        "serverId", &serverId,
        "networkId", &networkId,
        "channel",   &channel,
    );
    if (helpInfo.helpWanted) {
        defaultGetoptPrinter("Usage: sync-redis-to-mongo [serverId networkId channel]", helpInfo.options);
        return;
    }
    // After getopt, remaining args are positional (serverId, networkId, channel)
    if (args.length >= 4) {
        serverId  = args[1];
        networkId = args[2];
        channel   = args[3];
    }

    auto mongoUrl = readEnv("IRCFIBER_MONGO_URL", "mongodb://127.0.0.1:27017/ircfiber");
    auto redisUrl = readEnv("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");

    writefln("Connecting to Mongo: %s", mongoUrl);
    AppMongoConnection.connect(mongoUrl, "ircfiber");

    writefln("Connecting to Redis: %s", redisUrl);
    auto redis = new RedisStorage();
    redis.connectFromUrl(redisUrl);

    auto repo = new MessageRepository();

    long totalScanned = 0, totalInserted = 0, totalDuplicates = 0, totalParseErrors = 0;
    size_t buffers = 0;

    if (serverId.length > 0 && networkId.length > 0 && channel.length > 0) {
        writefln("Syncing single buffer: %s:%s:%s", serverId, networkId, channel);
        auto r = repo.syncFromRedis(redis, serverId, networkId, channel);
        writefln("  scanned=%d  inserted=%d  duplicates=%d  parse_errors=%d",
                 r.scanned, r.inserted, r.duplicates, r.parseErrors);
        totalScanned += r.scanned;
        totalInserted += r.inserted;
        totalDuplicates += r.duplicates;
        totalParseErrors += r.parseErrors;
        buffers = 1;
    } else {
        writefln("Syncing ALL scrollback buffers from Redis to Mongo...");
        auto results = repo.syncAllFromRedis(redis);
        foreach (r; results) {
            if (r.scanned == 0 && r.parseErrors == 0) continue;
            writefln("  buffer#%d  scanned=%d  inserted=%d  duplicates=%d  parse_errors=%d",
                     buffers + 1, r.scanned, r.inserted, r.duplicates, r.parseErrors);
            totalScanned += r.scanned;
            totalInserted += r.inserted;
            totalDuplicates += r.duplicates;
            totalParseErrors += r.parseErrors;
            buffers++;
        }
    }

    writefln("");
    writefln("Done. Buffers synced: %d", buffers);
    writefln("  total scanned:     %d", totalScanned);
    writefln("  total inserted:    %d", totalInserted);
    writefln("  total duplicates:  %d", totalDuplicates);
    writefln("  total parse errors:%d", totalParseErrors);
}

private string readEnv(string name, string fallback) {
    import std.conv : to;
    auto p = getenv(name.toStringz);
    if (p is null) return fallback;
    return to!string(p);
}
