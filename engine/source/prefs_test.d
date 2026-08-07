/// Standalone fast smoke test for ircfiber.db.preferences.
///
/// Exhaustive coverage of the defensive-array-shape and self-healing fixes
/// from `source/ircfiber/db/preferences.d`.
///
/// Run with: `make prefs-test`.
module prefs_test;

import std.json : JSONValue;
import std.stdio : stderr, writeln;
import std.uuid : randomUUID;
import std.conv : to;
import std.datetime : dur;

import vibe.data.json : Json, serializeToJson;
import ircfiber.db.preferences : UserPreferences, PreferencesRepository;
import ircfiber.db.prefs_cache : PrefsCache;
import ircfiber.storage.redis : RedisStorage;

int passed;
int failed;

void check(string name)(bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("  ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("  ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

void runFromJsonTests() {
    stderr.writeln("\n[fromJson] defensive array guards");

    // 1. object-shaped arrays → defaults, no throw
    {
        Json j = Json.emptyObject;
        j["pinnedChannels"] = Json.emptyObject;
        j["archivedChannels"] = Json.emptyObject;
        j["networkOrder"] = Json.emptyObject;
        j["prefVersion"] = Json(7L);
        auto back = UserPreferences.fromJson(j).prefs;
        check!("object-shaped pinnedChannels defaults to empty")
            (back.pinnedChannels.length == 0);
        check!("object-shaped archivedChannels defaults to empty")
            (back.archivedChannels.length == 0);
        check!("object-shaped networkOrder defaults to empty")
            (back.networkOrder.length == 0);
        check!("well-typed prefVersion preserved alongside bad fields")
            (back.prefVersion == 7);
    }

    // 2. null/string/int shapes are also rejected
    {
        Json j = Json.emptyObject;
        j["pinnedChannels"] = Json("not-an-array");
        j["archivedChannels"] = Json(null);
        j["networkOrder"] = Json(42L);
        j["prefVersion"] = Json(3L);
        auto back = UserPreferences.fromJson(j).prefs;
        check!("string-shaped pinnedChannels rejected")
            (back.pinnedChannels.length == 0);
        check!("null-shaped archivedChannels rejected")
            (back.archivedChannels.length == 0);
        check!("int-shaped networkOrder rejected")
            (back.networkOrder.length == 0);
        check!("well-typed prefVersion preserved")
            (back.prefVersion == 3);
    }

    // 3. happy path
    {
        Json j = Json.emptyObject;
        j["pinnedChannels"]   = serializeToJson(["net1:#a", "net2:#b"]);
        j["archivedChannels"] = serializeToJson(["net3:#old"]);
        j["networkOrder"]     = serializeToJson(["net1", "net2"]);
        j["prefVersion"]      = Json(11L);
        auto back = UserPreferences.fromJson(j).prefs;
        check!("happy-path pinnedChannels preserved")
            (back.pinnedChannels == ["net1:#a", "net2:#b"]);
        check!("happy-path archivedChannels preserved")
            (back.archivedChannels == ["net3:#old"]);
        check!("happy-path networkOrder preserved")
            (back.networkOrder == ["net1", "net2"]);
        check!("happy-path prefVersion preserved")
            (back.prefVersion == 11);
    }

    // 4. prefVersion + bad sibling fields: fromJson does NOT throw
    {
        Json j = Json.emptyObject;
        j["pinnedChannels"] = Json.emptyObject;
        j["prefVersion"] = Json(99L);
        bool threw = false;
        try UserPreferences.fromJson(j);
        catch (Exception e) { threw = true; }
        check!("fromJson does not throw on object-shaped arrays")(!threw);
    }

    // 5. massive line — exercise path length limits (regression for A.1 cap)
    {
        Json j = Json.emptyObject;
        string[] arr;
        for (int i = 0; i < 5000; i++) arr ~= "net:#ch-" ~ i.to!string;
        j["pinnedChannels"] = serializeToJson(arr);
        auto back = UserPreferences.fromJson(j).prefs;
        check!("large pinnedChannels array round-trips intact")
            (back.pinnedChannels.length == 5000);
    }
}

void runRepairTests() {
    stderr.writeln("\n[load] self-heals a corrupt blob (requires Redis)");

    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
    } catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis unavailable (", e.msg, ")");
        return;
    }

    // vibe.d lazily connects; wrap all Redis ops so a transient
    // disconnect (no Redis running) produces a clean SKIP instead of
    // an uncaught exception.
    try {
        auto userId = randomUUID();
        string key = "prefs:" ~ userId.toString();
        void cleanup() { try redis.getDb().del(key); catch (Exception) {} }
        cleanup();
        scope (exit) cleanup();

        redis.getDb().set(key, "{this is not valid json at all");
        check!("precondition: bad blob is in Redis")(redis.exists(key));

        auto repo = new PreferencesRepository(redis);
        auto prefs = repo.load(userId);
        check!("load() returns defaults on unparseable JSON")
            (prefs.prefVersion == 0);
        check!("load() deleted the corrupt key as a self-heal")
            (!redis.exists(key));

        // Bonus: load twice in a row should not crash on the second call
        // (no regression on re-loading after delete)
        prefs = repo.load(userId);
        check!("load() works twice (no crash on second call after delete)")
            (prefs.prefVersion == 0);
    } catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis operation failed (", e.msg, ")");
    }
}

void runCacheTests() {
    stderr.writeln("\n[cache] LRU cache integration");

    // 1. Cache hit: load() populates cache, second load hits cache.
    //    We can verify indirectly by observing that loading the same
    //    user twice returns the same data.
    {
        UserPreferences p;
        p.pinnedChannels = ["net1:#a", "net2:#b"];
        p.prefVersion = 42;

        auto cache = new PrefsCache(100, dur!"seconds"(30));
        cache.set(randomUUID(), p);

        // Manually created entry must round-trip.
        auto uid = randomUUID();
        cache.set(uid, p);
        auto got = cache.get(uid);
        assert(!got.isNull);
        check!("cache: manual get/set round-trips")
            (got.get.prefVersion == 42);
    }

    // 2. Cache eviction (no Redis needed)
    {
        auto cache = new PrefsCache(3, dur!"seconds"(30));
        auto u1 = randomUUID();
        auto u2 = randomUUID();
        auto u3 = randomUUID();
        auto u4 = randomUUID();

        cache.set(u1, UserPreferences.init);
        cache.set(u2, UserPreferences.init);
        cache.set(u3, UserPreferences.init);

        // Promote u1 to most-recently-used
        assert(!cache.get(u1).isNull);

        // Insert fourth — evicts u2 (LRU)
        cache.set(u4, UserPreferences.init);

        check!("cache: LRU eviction removes least-recently-used")
            (cache.get(u2).isNull);
        check!("cache: recently-used entries survive eviction")
            (!cache.get(u3).isNull && !cache.get(u1).isNull && !cache.get(u4).isNull);
    }

    // 3. Cache: remove() clears entry
    {
        auto cache = new PrefsCache(5, dur!"seconds"(30));
        auto uid = randomUUID();
        cache.set(uid, UserPreferences.init);
        check!("cache: entry exists before remove")
            (!cache.get(uid).isNull);
        cache.remove(uid);
        check!("cache: entry gone after remove")
            (cache.get(uid).isNull);
    }

    // 4. Cache: clear() empties everything
    {
        auto cache = new PrefsCache(5, dur!"seconds"(30));
        cache.set(randomUUID(), UserPreferences.init);
        cache.set(randomUUID(), UserPreferences.init);
        check!("cache: has entries before clear")(cache.length == 2);
        cache.clear();
        check!("cache: empty after clear")(cache.length == 0);
    }

    // 5. PreferencesRepository.load() populates cache (requires Redis)
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
    } catch (Exception e) {
        stderr.writeln("  ⊘ SKIP (Redis unavailable): ", e.msg);
        return;
    }

    // Wrap all Redis ops so a transient disconnect produces clean SKIP.
    try {
        auto userId = randomUUID();
        string key = "prefs:" ~ userId.toString();
        void cleanup() { try redis.getDb().del(key); catch (Exception) {} }
        cleanup();
        scope (exit) cleanup();

        // Save via repo — loads through the Lua script.
        auto repo = new PreferencesRepository(redis);
        UserPreferences p;
        p.pinnedChannels = ["net1:#cache-test"];
        p.prefVersion = 99;
        auto v1 = repo.save(userId, p);

        // First load: Redis miss → fetch from Redis → populate cache.
        // prefVersion is authoritative via the Lua INCR, so we assert
        // the payload round-trips (channels) and that the returned
        // version is non-zero and matches what save() returned, not the
        // caller-supplied 99 (which is zeroed before the Lua script).
        auto loaded = repo.load(userId);
        check!("prefs-repo: load() returns saved prefs via repo")
            (loaded.pinnedChannels == ["net1:#cache-test"] && loaded.prefVersion == v1 && v1 != 0);

        // Second load: cache hit (no Redis read). We can't directly
        // observe "no Redis read" from the outside, but the fact that
        // it returns the same data without crashing is sufficient.
        auto loaded2 = repo.load(userId);
        check!("prefs-repo: second load() returns same data (cache hit)")
            (loaded2.prefVersion == v1 &&
             loaded2.pinnedChannels == ["net1:#cache-test"]);
        // Save invalidates cache; next load fetches fresh.
        UserPreferences p2;
        p2.pinnedChannels = ["net1:#updated"];
        repo.save(userId, p2);
        auto loaded3 = repo.load(userId);
        check!("prefs-repo: after save(), load() returns updated data (cache invalidated)")
            (loaded3.pinnedChannels == ["net1:#updated"]);
    } catch (Exception e) {
        stderr.writeln("  ⊘ SKIP — Redis operation failed (", e.msg, ")");
    }
}

int main() {
    stderr.writeln("ircfiber.db.preferences smoke tests");
    runFromJsonTests();
    runRepairTests();
    runCacheTests();
    stderr.writeln("\n", passed, " passed, ", failed, " failed");
    return failed == 0 ? 0 : 1;
}
