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
 *   dub run --config=sync                                     # every scrollback buffer
 *   dub run --config=sync -- <serverId> <networkId> <channel>   # one buffer
 *
 * Every record must carry its original positive millisecond `t`; missing
 * timestamps are reported, never replaced with the backfill time. Discarded
 * records are already expired/fenced by policy. Parse/write failures exit 1
 * and remain retryable in Redis; duplicates require durable identity proof.
 *
 * Env:
 *   IRCFIBER_MONGO_URL  (default mongodb://localhost:27017/ircfiber)
 *   IRCFIBER_REDIS_URL  (default redis://127.0.0.1:6379)
 */
int main(string[] args) {
    string serverId, networkId, channel;

    auto helpInfo = getopt(args,
        "serverId", &serverId,
        "networkId", &networkId,
        "channel",   &channel,
    );
    if (helpInfo.helpWanted) {
        defaultGetoptPrinter("Usage: sync-redis-to-mongo [serverId networkId channel]", helpInfo.options);
        return 0;
    }
    if (args.length != 1 && args.length != 4) {
        writeln("Specify all of serverId, networkId and channel, or none.");
        return 2;
    }
    // After getopt, remaining args are positional (serverId, networkId, channel).
    if (args.length == 4) {
        if (serverId.length || networkId.length || channel.length) {
            writeln("Do not mix positional buffer arguments with named options.");
            return 2;
        }
        serverId  = args[1];
        networkId = args[2];
        channel   = args[3];
    }
    const singleBuffer = serverId.length && networkId.length && channel.length;
    if (!singleBuffer && (serverId.length || networkId.length || channel.length)) {
        writeln("Specify all of serverId, networkId and channel, or none.");
        return 2;
    }
    auto mongoUrl = readEnv("IRCFIBER_MONGO_URL", "mongodb://127.0.0.1:27017/ircfiber");
    auto redisUrl = readEnv("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");

    writefln("Connecting to Mongo: %s", mongoUrl);
    AppMongoConnection.connect(mongoUrl, "ircfiber");

    writefln("Connecting to Redis: %s", redisUrl);
    auto redis = new RedisStorage();
    redis.connectFromUrl(redisUrl);

    auto repo = new MessageRepository(redis);

    MessageRepository.SyncResult[] results;
    if (singleBuffer) {
        writefln("Syncing single buffer: %s:%s:%s", serverId, networkId, channel);
        results = [repo.syncFromRedis(redis, serverId, networkId, channel)];
    } else {
        writeln("Syncing ALL scrollback buffers from Redis to Mongo...");
        results = repo.syncAllFromRedis(redis);
    }

    MessageRepository.SyncResult total;
    foreach (i, r; results) {
        if (r.scanned) {
            writefln("  buffer#%d  scanned=%d  inserted=%d  duplicates=%d"
                ~ "  discarded=%d  parse_errors=%d  write_errors=%d",
                i + 1, r.scanned, r.inserted, r.duplicates,
                r.discarded, r.parseErrors, r.writeErrors);
        }
        total.scanned += r.scanned;
        total.inserted += r.inserted;
        total.duplicates += r.duplicates;
        total.discarded += r.discarded;
        total.parseErrors += r.parseErrors;
        total.writeErrors += r.writeErrors;
    }

    writeln("");
    writefln("Done. Buffers checked: %d", results.length);
    writefln("  total scanned:      %d", total.scanned);
    writefln("  total inserted:     %d", total.inserted);
    writefln("  total duplicates:   %d", total.duplicates);
    writefln("  total discarded:    %d", total.discarded);
    writefln("  total parse errors: %d", total.parseErrors);
    writefln("  total write errors: %d", total.writeErrors);
    return total.parseErrors || total.writeErrors ? 1 : 0;
}

private string readEnv(string name, string fallback) {
    import std.conv : to;
    auto p = getenv(name.toStringz);
    if (p is null) return fallback;
    return to!string(p);
}
