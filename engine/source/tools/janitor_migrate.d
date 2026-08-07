/**
 * One-shot backfill: write TTL on existing state/scrollback/dedup keys
 * missing a TTL.
 *
 * Usage:
 *   dub run --config=janitor-migrate
 *
 * Env:
 *   IRCFIBER_REDIS_URL      (default redis://127.0.0.1:6379)
 *   IRCFIBER_MIGRATE_TTL    TTL in seconds, 60..86400 (default 600)
 *   JSMIGRATE_DRY_RUN       1 = scan only, 0 = apply (default 1)
 *
 * Exit codes:
 *   0 success
 *   1 Redis error
 *
 * Note: vibe-d's `RedisReply!string` does NOT flatten the nested multi-bulk
 * reply that SCAN returns ([cursor, [key, key, ...]]) — iterating it yields
 * garbage. We side-step that with a Lua EVAL that does the SCAN+TTL check
 * server-side and returns a JSON array.
 */
module janitor_migrate;

import std.stdio : writeln, writefln, stdout;
import std.conv : to;
import std.process : environment;
import core.stdc.stdlib : exit;

import vibe.data.json : Json, parseJson;
import vibe.db.redis.redis : RedisDatabase;

import ircfiber.storage.redis : RedisStorage;

private string envOr(string name, string fallback) {
    auto v = environment.get(name, "");
    return v.length > 0 ? v : fallback;
}

private long envLong(string name, long fallback) {
    const raw = environment.get(name, "");
    if (raw.length == 0) return fallback;
    try {
        auto v = raw.to!long;
        if (v < 60) v = 60;
        if (v > 86_400) v = 86_400;
        return v;
    } catch (Exception) return fallback;
}

private bool envBool(string name, bool fallback) {
    auto raw = environment.get(name, "");
    if (raw.length == 0) return fallback;
    if (raw.length > 0 && raw[0] == '1') return true;
    if (raw.length > 0 && raw[0] == '0') return false;
    return fallback;
}

private immutable string[] patterns = [
    "irc:state:*:*",
    "scrollback:*:*:*",
    "dedup:*:*:*",
];

/// SCAN MATCH in batch, return only the keys whose TTL is -1 (missing).
/// Returns a JSON array of matching keys (strings). `apply==true` writes
/// the TTL inside Lua so the caller doesn't need a second round trip.
private string scanMissingKeys(RedisDatabase db, string pattern,
                               long ttlSeconds, bool apply) {
    immutable string script =
        "local p = ARGV[1]\n" ~
        "local ttl = tonumber(ARGV[2])\n" ~
        "local apply = tonumber(ARGV[3])\n" ~
        "local out = {}\n" ~
        "local cursor = '0'\n" ~
        "repeat\n" ~
        "  local res = redis.call('SCAN', cursor, 'MATCH', p, 'COUNT', 500)\n" ~
        "  cursor = res[1]\n" ~
        "  for i, k in ipairs(res[2]) do\n" ~
        "    if redis.call('TTL', k) == -1 then\n" ~
        "      if apply == 1 then redis.call('EXPIRE', k, ttl) end\n" ~
        "      table.insert(out, k)\n" ~
        "    end\n" ~
        "  end\n" ~
        "until cursor == '0'\n" ~
        "return cjson.encode(out)\n";
    auto reply = db.eval!string(script, ["0"],
        pattern, ttlSeconds.to!string, (apply ? "1" : "0"));
    if (reply.empty) return "[]";
    return reply.front;
}

/// Returns count of keys matching the pattern (regardless of TTL).
private long countPattern(RedisDatabase db, string pattern) {
    immutable string script =
        "local p = ARGV[1]\n" ~
        "local n = 0\n" ~
        "local cursor = '0'\n" ~
        "repeat\n" ~
        "  local res = redis.call('SCAN', cursor, 'MATCH', p, 'COUNT', 500)\n" ~
        "  cursor = res[1]\n" ~
        "  n = n + #res[2]\n" ~
        "until cursor == '0'\n" ~
        "return n\n";
    try {
        auto reply = db.eval!long(script, ["0"], pattern);
        if (reply.empty) return 0;
        return reply.front;
    } catch (Exception e) {
        writefln("  count SCAN failed for %s: %s", pattern, e.msg);
        return 0;
    }
}

void main() {
    auto redisUrl = envOr("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");
    auto ttl = envLong("IRCFIBER_MIGRATE_TTL", 600);
    auto dryRun = envBool("JSMIGRATE_DRY_RUN", true);

    writefln("janitor-migrate (dry_run=%s) ttl=%ds url=%s",
        dryRun ? "true" : "false", ttl, redisUrl);
    stdout.flush();

    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connectFromUrl(redisUrl);
    } catch (Exception e) {
        writefln("ERROR: cannot connect to Redis at %s: %s", redisUrl, e.msg);
        exit(1);
    }

    auto db = redis.getDb();
    long totalScanned = 0;
    long totalMissing = 0;
    long totalApplied = 0;

    foreach (pattern; patterns) {
        const long scanned = countPattern(db, pattern);
        totalScanned += scanned;

        string jsonKeys;
        try {
            jsonKeys = scanMissingKeys(db, pattern, ttl, !dryRun);
        } catch (Exception e) {
            writefln("ERROR: SCAN failed for %s: %s", pattern, e.msg);
            exit(1);
        }

        Json parsed = parseJson(jsonKeys);
        long missing = 0;
        if (parsed.type == Json.Type.array) {
            foreach (k; parsed) missing++;
            if (!dryRun) totalApplied += missing;
        }
        totalMissing += missing;

        writefln("  pattern=%s scanned=%d missing_ttl=%d applied=%d",
            pattern, scanned, missing, dryRun ? 0 : missing);
        stdout.flush();
    }

    Json outJson = Json.emptyObject;
    outJson["scanned"] = Json(totalScanned);
    outJson["missing_ttl"] = Json(totalMissing);
    outJson["applied"] = Json(totalApplied);
    outJson["dry_run"] = Json(dryRun);
    outJson["ttl_seconds"] = Json(ttl);
    Json patArr = Json.emptyArray;
    foreach (p; patterns) patArr ~= Json(p);
    outJson["patterns"] = patArr;
    writeln(outJson.toString());
    stdout.flush();
}
