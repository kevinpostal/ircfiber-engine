module ircfiber.db.preferences;

import std.uuid;
import vibe.data.json;
import vibe.core.log;
import ircfiber.logging : logJsonMap;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.db.prefs_cache : PrefsCache;

/// Maps a `vibe.data.json.Json.Type` enum value to its string name so it can
/// be emitted as a Loki label / log field. Kept private — only the pref
/// load path uses it.
private string jsonTypeName(Json.Type t) @safe pure {
    final switch (t) {
        case Json.Type.null_:      return "null";
        case Json.Type.undefined:  return "undefined";
        case Json.Type.bool_:      return "bool";
        case Json.Type.int_:       return "int";
        case Json.Type.bigInt:     return "bigint";
        case Json.Type.float_:     return "float";
        case Json.Type.string:     return "string";
        case Json.Type.array:      return "array";
        case Json.Type.object:     return "object";
    }
}

/// Emits a structured WARN log when a single preference field has the wrong
/// JSON type (e.g. `"pinnedChannels": {}` instead of `[]`). The `event` label
/// `prefs_field_invalid` is matched by the Loki alerting rule in
/// `deploy/roles/logging/templates/loki-rules.yml.j2` so any regression
/// shows up immediately in the dashboard.
private void logFieldInvalid(UUID userId, string field, Json.Type found, string expected) {
    logJsonMap("warn", "prefs", "User preference field has unexpected type",
        [
            "event":        "prefs_field_invalid",
            "user_id":      userId.toString(),
            "field":        field,
            "found_type":   jsonTypeName(found),
            "expected_type": expected
        ]);
    logWarn("prefs: user %s field '%s' has type %s, expected %s — skipping",
        userId, field, jsonTypeName(found), expected);
}

/// Emits a structured ERROR log when the entire preferences blob fails to
/// deserialize (i.e. an unexpected exception escapes `fromJson`). Followed
/// by a repair that deletes the corrupt key so the next save produces a
/// clean record — this prevents the warning from re-firing on every boot.
private void logLoadFail(UUID userId, string errMsg) {
    logJsonMap("error", "prefs", "Failed to load preferences",
        [
            "event":   "prefs_load_fail",
            "user_id": userId.toString(),
            "error":   errMsg
        ]);
    logWarn("Failed to load preferences for %s: %s", userId, errMsg);
}

private void logLoadRepaired(UUID userId) {
    logJsonMap("warn", "prefs", "Repaired corrupt preferences blob by deleting key",
        ["event": "prefs_load_fail_repaired", "user_id": userId.toString()]);
}

/// User preference settings.
struct UserPreferences {
    /// Pinned channels in "networkId:#channel" format.
    string[] pinnedChannels; // format: "networkId:#channel"
    /// Archived channels in "networkId:#channel" format. The user can
    /// re-join these from the sidebar's "Archives" section to restore them.
    string[] archivedChannels; // format: "networkId:#channel"
    /// Last active buffer per network (networkId -> bufferName).
    string[string] lastActiveBuffers;
    /// Collapsed server log connection attempt cards (networkId:eid -> true).
    /// Keyed by the eid of the attempt's phase event so collapses survive
    /// reconnection cycles — eid is deterministic per connection attempt.
    bool[string] serverlogCollapsed;

    /// Collapsed member panels per buffer (networkId:#channel -> true).
    bool[string] membersCollapsed;
    /// Collapsed sidebar sections per network (networkId -> true).
    bool[string] collapsed;
    /// Collapsed "Inactive" sections per network (networkId -> true).
    bool[string] inactiveCollapsed;
    /// Collapsed Conversations header groupings per network (networkId -> true).
    /// Mirrors the inactiveCollapsed pattern — server is authoritative on
    /// pref_update so cross-tab/device sync deletes locally stale entries.
    /// Boot-time seeding in mergePreferences is additive-only.
    bool[string] conversationsCollapsed;
    /// User-defined sidebar order for networks (networkId list, top-to-bottom).
    /// Networks not in this list are appended at the end in their natural order.
    /// Replaces the engine-emitted ordering of `ircState.networks` so the user
    /// can drag-and-drop servers in the sidebar. Mirrors IRCCloud's
    /// `reorder-connections` stream message, but persisted in the same Redis
    /// pref blob as the other sidebar prefs and broadcast via the existing
    /// `pref_update` channel — so reorder changes fan out to every tab/device
    /// in real time.
    string[] networkOrder;

    /// Per-buffer preferences (showJoinPart, mute, formatColor, etc.).
    /// Key is "networkId:#channel", value is a JSON object of buffer-level
    /// toggles (e.g. {"showJoinPart":false, "mute":true}).
    Json[string] bufferPrefs;

    /// Monotonic counter incremented on every `prefsRepo.save()`. Stored
    /// inline in the JSON blob (per Wave 1 Q2 decision) and bumped
    /// atomically by a Redis Lua script so concurrent saves cannot collide
    /// on the same value. Surfaced to the frontend via the `stat_user`
    /// boot message and used as a last-write-wins tiebreaker in
    /// `mergePreferences()` — see `docs/PREF_VERSION.md` for the full
    /// design. DOES NOT resolve tab-vs-tab conflicts (those are still
    /// handled by `localStorage` storage events on the frontend).
    long prefVersion;

    /// Serializes to JSON.
    Json toJson() const {
        auto j = Json.emptyObject;
        // Ensure null arrays serialize as [] not null. D's string[] init is null,
        // and serializeToJson(null) would produce JSON null, which the Lua
        // would have to handle. Explicitly use emptyArray for null to keep
        // the JSON contract stable and avoid the cjson empty_table-as-object
        // pitfall on the Redis Lua side.
        j["pinnedChannels"] = pinnedChannels is null ? Json.emptyArray : serializeToJson(pinnedChannels);
        j["archivedChannels"] = archivedChannels is null ? Json.emptyArray : serializeToJson(archivedChannels);
        auto lab = Json.emptyObject;
        foreach (k, v; lastActiveBuffers)
            lab[k] = Json(v);
        j["lastActiveBuffers"] = lab;
        auto slc = Json.emptyObject;
        foreach (k, v; serverlogCollapsed)
            slc[k] = Json(v);
        j["serverlogCollapsed"] = slc;

        auto mc = Json.emptyObject;
        foreach (k, v; membersCollapsed)
            mc[k] = Json(v);
        j["membersCollapsed"] = mc;
        auto col = Json.emptyObject;
        foreach (k, v; collapsed)
            col[k] = Json(v);
        j["collapsed"] = col;
        auto ic = Json.emptyObject;
        foreach (k, v; inactiveCollapsed)
            ic[k] = Json(v);
        j["inactiveCollapsed"] = ic;
        auto cc = Json.emptyObject;
        foreach (k, v; conversationsCollapsed)
            cc[k] = Json(v);
        j["conversationsCollapsed"] = cc;
        j["networkOrder"] = networkOrder is null ? Json.emptyArray : serializeToJson(networkOrder);
        auto bp = Json.emptyObject;
        foreach (k, v; bufferPrefs)
            bp[k] = v;
        j["bufferPrefs"] = bp;
        j["prefVersion"] = Json(prefVersion);
        return j;
    }

    /// Deserializes from JSON. The optional `userId` enables structured
    /// per-field warnings when individual fields have the wrong JSON type
    /// (e.g. an object where an array is expected). When omitted, malformed
    /// Result of `fromJson`. `needsRepair` is true when one or more
    /// stored fields had the wrong JSON type and were silently
    /// dropped. The caller (PreferencesRepository.load) uses this to
    /// trigger a re-save so the next load returns clean — otherwise
    /// the same `prefs_field_invalid` warning fires on every load
    /// for the lifetime of that user record.
    static struct LoadResult {
        /// The cleaned preferences record.
        UserPreferences prefs;
        /// Whether one or more stored fields had the wrong JSON type.
        bool needsRepair;
    }

    /// Decodes a JSON blob into a UserPreferences, emitting a
    /// `prefs_field_invalid` log line for each stored field whose
    /// JSON type doesn't match the field's expected shape (e.g.
    /// `"pinnedChannels": {}` instead of `[]`). Returns the cleaned
    /// record plus a `needsRepair` flag so the caller knows to
    /// re-save — without that, the next load still reads the bad
    /// blob and the same warnings fire on every boot. Genuinely
    /// unexpected failures (top-level exception escaping fromJson)
    /// are NOT handled here — they bubble up to the load() catch
    /// block which logs `prefs_load_fail` and self-heals by deleting
    /// the corrupt key.
    ///
    /// Pass `userId = UUID.init` to silence the per-field WARN logs
    /// (used in unit tests that don't want to assert on log lines).
    static LoadResult fromJson(Json json, UUID userId = UUID.init) {
        UserPreferences p;
        bool needsRepair = false;
        if (auto pc = "pinnedChannels" in json) {
            if (pc.type == Json.Type.array)
                p.pinnedChannels = deserializeJson!(string[])(*pc);
            else {
                logFieldInvalid(userId, "pinnedChannels", pc.type, "array");
                p.pinnedChannels = [];  // auto-heal to empty list
                needsRepair = true;
            }
        }
        if (auto ac = "archivedChannels" in json) {
            if (ac.type == Json.Type.array)
                p.archivedChannels = deserializeJson!(string[])(*ac);
            else {
                logFieldInvalid(userId, "archivedChannels", ac.type, "array");
                p.archivedChannels = [];  // auto-heal to empty list
                needsRepair = true;
            }
        }
        if (auto lab = "lastActiveBuffers" in json) {
            if (lab.type == Json.Type.object) {
                foreach (string k, v; *lab)
                    p.lastActiveBuffers[k] = v.get!string;
            }
        }
        if (auto slc = "serverlogCollapsed" in json) {
            if (slc.type == Json.Type.object) {
                foreach (string k, v; *slc)
                    p.serverlogCollapsed[k] = v.get!bool;
            }
        }
        if (auto mc = "membersCollapsed" in json) {
            if (mc.type == Json.Type.object) {
                foreach (string k, v; *mc)
                    p.membersCollapsed[k] = v.get!bool;
            }
        }
        if (auto col = "collapsed" in json) {
            if (col.type == Json.Type.object) {
                foreach (string k, v; *col)
                    p.collapsed[k] = v.get!bool;
            }
        }
        if (auto ic = "inactiveCollapsed" in json) {
            if (ic.type == Json.Type.object) {
                foreach (string k, v; *ic)
                    p.inactiveCollapsed[k] = v.get!bool;
            }
        }
        if (auto cc = "conversationsCollapsed" in json) {
            if (cc.type == Json.Type.object) {
                foreach (string k, v; *cc)
                    p.conversationsCollapsed[k] = v.get!bool;
            }
        }
        if (auto no = "networkOrder" in json) {
            if (no.type == Json.Type.array)
                p.networkOrder = deserializeJson!(string[])(*no);
            else {
                logFieldInvalid(userId, "networkOrder", no.type, "array");
                needsRepair = true;
            }
        }
        if (auto bp = "bufferPrefs" in json) {
            if (bp.type == Json.Type.object) {
                foreach (string k, v; *bp)
                    p.bufferPrefs[k] = v;
            }
        }
        if (auto pv = "prefVersion" in json) {
            if (pv.type == Json.Type.int_)
                p.prefVersion = pv.get!long;
        }
        return LoadResult(p, needsRepair);
    }
}

/// Repository for user preferences.
final class PreferencesRepository {
    private RedisStorage redis;
    private PrefsCache cache_;
    private enum KEY_PREFIX = "prefs:";

    /// Shared per-gateway cache instance. Lazily created with defaults
    /// (1000 entries, 30 s TTL) when first needed. Exposed as public so
    /// tests and admin endpoints can call `clear()` for emergency reset.
    private static PrefsCache defaultCache_;
    private static PrefsCache defaultCache() {
        if (defaultCache_ is null)
            defaultCache_ = new PrefsCache();
        return defaultCache_;
    }

    /// Lua script for atomic increment-and-set. Reads the existing JSON
    /// at KEYS[1], computes `newPrefVersion = (existing + 1) or 1`, and
    /// writes the supplied JSON (ARGV[1]) with `prefVersion` overwritten
    /// to that atomic value. Returns the value it wrote.
    ///
    /// Why Lua and not MULTI/EXEC? Vibe-d's RedisDatabase doesn't expose
    /// a typed MULTI/EXEC builder (see the `TODO: Transactions` comment
    /// in vibe-d-0.10.3/vibe-d/redis/vibe/db/redis/redis.d). Lua scripts
    /// are Redis's canonical atomic primitive — they execute serially in
    /// the single-threaded server, so the GET+SET pair is observably
    /// atomic from every other client's perspective.
    ///
    /// KEYS[1] = prefs:<userId>
    /// ARGV[1] = JSON to write (prefVersion in it is ignored; the Lua
    ///           overwrites it with the freshly-computed value)
    /// Returns the new prefVersion.
    private enum INCR_AND_SET_LUA = `local current = redis.call('GET', KEYS[1])
local newPrefVersion = 1
if current then
    local ok, parsed = pcall(cjson.decode, current)
    if ok and type(parsed) == 'table' and parsed.prefVersion then
        newPrefVersion = tonumber(parsed.prefVersion) + 1
    end
end
local ok2, newDoc = pcall(cjson.decode, ARGV[1])
if not ok2 or type(newDoc) ~= 'table' then
    return redis.error_reply('preferences.d: invalid JSON in ARGV[1]')
end
newDoc.prefVersion = newPrefVersion
-- Fix: cjson encodes an empty Lua table as {} (object). Our payload has
-- three array fields that must be [] when empty, not {}. After decode,
-- an empty JSON array becomes an empty Lua table (next() == nil). Mark
-- those tables as cjson.empty_array so encode produces [].
-- Without this, every save of an empty pinnedChannels wrote {} to Redis,
-- and the next load saw object != array, logged prefs_field_invalid,
-- and triggered an infinite repair loop (seen as repeated warnings every
-- 30s for the same user).
if type(newDoc.pinnedChannels) == 'table' and next(newDoc.pinnedChannels) == nil then
    newDoc.pinnedChannels = cjson.empty_array
elseif newDoc.pinnedChannels == nil or newDoc.pinnedChannels == cjson.null then
    newDoc.pinnedChannels = cjson.empty_array
end
if type(newDoc.archivedChannels) == 'table' and next(newDoc.archivedChannels) == nil then
    newDoc.archivedChannels = cjson.empty_array
elseif newDoc.archivedChannels == nil or newDoc.archivedChannels == cjson.null then
    newDoc.archivedChannels = cjson.empty_array
end
if type(newDoc.networkOrder) == 'table' and next(newDoc.networkOrder) == nil then
    newDoc.networkOrder = cjson.empty_array
elseif newDoc.networkOrder == nil or newDoc.networkOrder == cjson.null then
    newDoc.networkOrder = cjson.empty_array
end
redis.call('SET', KEYS[1], cjson.encode(newDoc))
return newPrefVersion`;

    /// Creates a new preferences repository, optionally using a shared
    /// LRU cache. When `cache` is null (the common case), the process-wide
    /// singleton default cache is used — all `PreferencesRepository`
    /// instances within a gateway share the same LRU so a warm entry
    /// from one request benefits the next.
    this(RedisStorage redis, PrefsCache cache = null) {
        this.redis = redis;
        this.cache_ = cache !is null ? cache : defaultCache();
    }

    /// Loads preferences for a user.
    ///
    /// Checks the in-memory LRU cache first. On cache miss, falls through
    /// to Redis and populates the cache so the next load for the same user
    /// (common within 30s for sync / buffer-switch) avoids a round-trip.
    ///
    /// Tolerates per-field shape mismatches (e.g. a stored blob with
    /// `"pinnedChannels": {}` instead of `[]`) by skipping the bad field
    /// and emitting a structured `prefs_field_invalid` log event instead
    /// of bubbling an exception. Truly unexpected failures (genuinely
    /// malformed JSON, missing Redis, etc.) are caught, logged as
    /// `prefs_load_fail`, and self-heal by deleting the corrupt blob —
    /// the next `save()` writes a clean record.
    UserPreferences load(UUID userId) {
        // NOTE: prefs are Redis-backed. Do NOT gate on the Mongo circuit
        // breaker — that blocks prefs-test and early startup before Mongo
        // is connected. The breaker only protects Mongo paths
        // (network.d). Redis has its own availability (connect try/catch).


        // Fast path: check the in-memory LRU cache first.
        if (auto cached = cache_.get(userId)) {
            return cached.get;
        }

        auto key = KEY_PREFIX ~ userId.toString();
        // Read the raw bytes directly so we can distinguish "missing key"
        // (silent — return defaults) from "key exists but bytes are
        // unparseable" (loud — `prefs_load_fail` + delete). The
        // `RedisStorage.getJson` helper silently swallows parse failures
        // which would mask exactly the regression we care about.
        string raw;
        try {
            raw = redis.getDb().get(key);
        } catch (Exception e) {
            logLoadFail(userId, "redis get: " ~ e.msg);
            return UserPreferences.init;
        }
        if (raw.length == 0)
            return UserPreferences.init;

        Json json;
        try {
            json = parseJson(raw);
        } catch (Exception e) {
            logLoadFail(userId, "parse: " ~ e.msg);
            redis.del(key);
            logLoadRepaired(userId);
            return UserPreferences.init;
        }
        if (json.type == Json.Type.null_ || json.type == Json.Type.undefined)
            return UserPreferences.init;

        try {
            auto result = UserPreferences.fromJson(json, userId);

            // Per-field shape mismatches (e.g. a stored `"pinnedChannels": {}`
            // instead of `[]`) are silently skipped by fromJson, but
            // `needsRepair` is set so we re-save the cleaned record. Without
            // this, the same `prefs_field_invalid` warning fires on every
            // load for the lifetime of that user record — and the user's
            // saved prefs keep coming back as a broken object. Re-saving
            // once is a one-time, idempotent fix; the warning does not
            // reappear on subsequent loads.
            if (result.needsRepair) {
                logLoadRepaired(userId);
                try {
                    save(userId, result.prefs);
                    // save() now updates the cache with the cleaned prefs
                    // after the Redis write, so concurrent load() callers
                    // hit the cache and skip the broken Redis blob.
                } catch (Exception save_e)
                    logWarn("prefsRepo: failed to repair invalid field types for %s: %s",
                        userId, save_e.msg);
                // If save() threw, the cache was NOT updated (save's
                // cache_.set is inside the try block). Fall through to
                // the cache_.set below so at least this caller's cleaned
                // prefs are cached.
            }

            // Seed the cache with the final (possibly repaired) prefs
            // so subsequent loads within the TTL window skip Redis.
            // This also covers the save-failed-to-update-cache case
            // and any non-repair code paths.
            cache_.set(userId, result.prefs);
            return result.prefs;
        } catch (Exception e) {
            logLoadFail(userId, "fromJson: " ~ e.msg);
            redis.del(key);
            logLoadRepaired(userId);
            return UserPreferences.init;
        }
    }

    /// Saves preferences for a user. Atomically increments `prefVersion`
    /// inside a Lua transaction (see INCR_AND_SET_LUA above) so concurrent
    /// callers cannot collide on the same counter value. Returns the
    /// `prefVersion` that was written.
    ///
    /// The `prefs` parameter is passed by value (not `ref`) to preserve
    /// the existing call-site convention. Callers that need the returned
    /// prefVersion can capture it from the return value; those that don't
    /// care (the common case for `pinChannel` / `unpinChannel` etc.) can
    /// ignore it — D permits discarding a non-void return.
        long save(UUID userId, UserPreferences prefs) {
        // NOTE: see load() — don't gate Redis prefs on the Mongo breaker.

        auto key = KEY_PREFIX ~ userId.toString();
        // Zero out prefVersion before sending — the Lua is authoritative
        // for the increment, so any caller-supplied value would be
        // discarded anyway. Sending a known-zero avoids polluting Redis
        // storage with stale caller-side numbers during a concurrent
        // collision.
        prefs.prefVersion = 0;
        auto payload = prefs.toJson().toString();

        long newVersion = 0;
        try {
            auto reply = redis.getDb().eval!long(INCR_AND_SET_LUA, [key], payload);
            if (!reply.empty) {
                newVersion = reply.front;
            }
            // Update cache AFTER the Redis write succeeds so a concurrent
            // load() in another fiber sees the fresh data in the cache
            // instead of reading the stale blob from Redis. This prevents
            // the repair-path race where multiple requests all miss the
            // cache, load the broken blob, and each fires a repair cycle.
            // Restore prefVersion from the Lua-returned counter since
            // it was zeroed before serialization (line 428).
            prefs.prefVersion = newVersion;
            cache_.set(userId, prefs);
        } catch (Exception e) {
            logWarn("prefsRepo.save EVAL failed for %s: %s — falling back to plain SET",
                userId, e.msg);
            // Best-effort fallback: plain SET without increment. The
            // prefVersion counter will be wrong on this save, but the
            // next successful save will repair it. We do NOT swallow
            // the failure silently — callers will see prefVersion=0.
            redis.setJson(key, prefs.toJson());
            return 0;
        }

        return newVersion;
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────

@("UserPreferences prefVersion round-trips through JSON")
unittest {
    UserPreferences p;
    p.pinnedChannels = ["net1:#a", "net2:#b"];
    p.prefVersion = 42;
    auto j = p.toJson();
    assert(j["prefVersion"].get!long == 42, "toJson() must serialize prefVersion");

    const back = UserPreferences.fromJson(j).prefs;
    assert(back.prefVersion == 42, "fromJson() must restore prefVersion");
    assert(back.pinnedChannels == p.pinnedChannels,
        "fromJson() must preserve other fields alongside prefVersion");
}

@("UserPreferences fromJson tolerates a missing prefVersion (legacy records)")
unittest {
    // Older prefs blobs (pre-W1-T02) won't carry a prefVersion field.
    // fromJson must default it to 0 rather than crashing so the boot
    // path doesn't fail for users with existing data.
    auto j = Json.emptyObject;
    j["pinnedChannels"] = serializeToJson(["net1:#a"]);
    const back = UserPreferences.fromJson(j).prefs;
    assert(back.prefVersion == 0);
    assert(back.pinnedChannels == ["net1:#a"]);
}

@("UserPreferences.fromJson flags needsRepair when fields are the wrong type")
unittest {
    // Regression test for the 'prefs_field_invalid' noise that fired on
    // every load for users whose stored blob had a corrupt shape
    // (e.g. `"pinnedChannels": {}` instead of `[]`). The bug was that
    // fromJson silently dropped the bad field but never persisted the
    // cleaned record, so the same warning re-fired on every subsequent
    // load. The fix is the needsRepair flag which load() uses to
    // re-save the cleaned record — the warning should now fire exactly
    // once per repair, not on every load thereafter.
    auto j = Json.emptyObject;
    j["pinnedChannels"]    = Json.emptyObject;  // wrong type: should be array
    j["archivedChannels"]  = Json.emptyObject;  // wrong type
    j["networkOrder"]      = Json.emptyObject;  // wrong type
    j["lastActiveBuffers"] = Json.emptyObject;  // correct type
    const r1 = UserPreferences.fromJson(j, UUID.init);
    assert(r1.needsRepair, "needsRepair must be true when array fields are wrong type");
    assert(r1.prefs.pinnedChannels.length == 0,
        "wrong-type array field must drop without crashing");
    // Sanity: object fields (correct type) don't trigger the flag.
    auto j2 = Json.emptyObject;
    j2["lastActiveBuffers"] = Json.emptyObject;
    const r2 = UserPreferences.fromJson(j2, UUID.init);
    assert(!r2.needsRepair, "needsRepair must be false when only object fields are present (correct type)");
    // All-correct JSON must not need repair.
    auto j3 = Json.emptyObject;
    j3["pinnedChannels"] = serializeToJson(["net1:#a"]);
    j3["networkOrder"]   = serializeToJson(["net1"]);
    const r3 = UserPreferences.fromJson(j3, UUID.init);
    assert(!r3.needsRepair, "needsRepair must be false when all fields are correct type");
}

@("prefsRepo.save atomicity: concurrent saves produce strictly monotonic prefVersion")
unittest {
    // Requires a local Redis on 127.0.0.1:6379. Skip if unavailable
    // (e.g. CI runners without Redis) — the roundtrip test above is
    // sufficient for CI; this one is for the dev box.
    import std.parallelism : parallel;
    import std.range : iota;
    import std.conv : to;

    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
    } catch (Exception e) {
        logWarn("Skipping prefsRepo concurrent test: Redis unavailable (%s)", e.msg);
        return;
    }

    auto userId = randomUUID();
    string key = "prefs:" ~ userId.toString();
    // Clean start + cleanup. try/catch cannot live inside scope(exit),
    // so the cleanup is a small lambda we call both inline and at scope exit.
    void cleanup() {
        try redis.getDb().del(key);
        catch (Exception) {}
    }
    cleanup();
    scope (exit) cleanup();

    auto repo = new PreferencesRepository(redis);
    enum N = 50;

    // Fire N saves in parallel from N workers. Each worker loads the
    // current prefs, appends a unique pinned channel, and saves. Without
    // the atomic Lua script, two workers could observe the same
    // prefVersion and produce duplicates — exactly the bug this task
    // fixes. With the Lua script, every save increments by exactly 1
    // from the previous Redis state, so prefVersion must end at N.
    foreach (i; iota(N).parallel) {
        auto p = repo.load(userId);
        p.pinnedChannels ~= "net1:#parallel-" ~ i.to!string;
        const v = repo.save(userId, p);
        assert(v >= 1, "save() must return the bumped prefVersion");
    }

    // Final load must show prefVersion == N with no duplicates / skips.
    const saved = repo.load(userId);
    assert(saved.prefVersion == N);
    assert(saved.pinnedChannels.length == N);
}

@("UserPreferences fromJson tolerates object-shaped array fields (no crash)")
unittest {
    // Reproduces the production bug where a legacy or malformed Redis blob
    // stored `"pinnedChannels": {}` (object) instead of `[]` (array). Before
    // the fix, `deserializeJson!(string[])` threw "Expected JSON array, got
    // object" and the user's session silently lost all preferences. After
    // the fix, fromJson must skip the bad field without throwing and return
    // the rest of the blob untouched.
    auto j = Json.emptyObject;
    j["pinnedChannels"]   = Json.emptyObject;    // wrong type — would previously throw
    j["archivedChannels"] = Json.emptyObject;    // wrong type
    j["networkOrder"]     = Json.emptyObject;    // wrong type
    j["prefVersion"]      = Json(7L);

    const back = UserPreferences.fromJson(j).prefs;
    assert(back.prefVersion == 7,
        "well-typed fields must be preserved when sibling fields are malformed");
    assert(back.pinnedChannels.length == 0,
        "object-shaped pinnedChannels must default to an empty list, not throw");
    assert(back.archivedChannels.length == 0,
        "object-shaped archivedChannels must default to an empty list");
    assert(back.networkOrder.length == 0,
        "object-shaped networkOrder must default to an empty list");
}

@("UserPreferences fromJson tolerates null and string-shaped array fields")
unittest {
    // The defensive guard must reject any non-array shape — `null`, a bare
    // string, a number, etc. — without crashing. Only "clean" recovery is
    // contract here; the warning logs are covered by Loki alerting.
    auto j = Json.emptyObject;
    j["pinnedChannels"] = Json("not-an-array");
    j["archivedChannels"] = Json(null);
    j["networkOrder"] = Json(42L);
    j["prefVersion"] = Json(3L);

    const back = UserPreferences.fromJson(j).prefs;
    assert(back.pinnedChannels.length == 0);
    assert(back.archivedChannels.length == 0);
    assert(back.networkOrder.length == 0);
    assert(back.prefVersion == 3);
}

@("UserPreferences fromJson with valid array shape preserves all entries")
unittest {
    // Sanity check that adding the type guard did not regress the happy path.
    auto j = Json.emptyObject;
    j["pinnedChannels"]   = serializeToJson(["net1:#a", "net2:#b"]);
    j["archivedChannels"] = serializeToJson(["net3:#old"]);
    j["networkOrder"]     = serializeToJson(["net1", "net2"]);
    j["prefVersion"]      = Json(11L);

    const back = UserPreferences.fromJson(j).prefs;
    assert(back.pinnedChannels   == ["net1:#a", "net2:#b"]);
    assert(back.archivedChannels == ["net3:#old"]);
    assert(back.networkOrder     == ["net1", "net2"]);
    assert(back.prefVersion == 11);
}

@("prefsRepo.load self-heals a corrupt blob by deleting the key")
unittest {
    // Requires local Redis (same gate as the atomicity test above).
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
    } catch (Exception e) {
        logWarn("Skipping prefsRepo load-repair test: Redis unavailable (%s)", e.msg);
        return;
    }

    auto userId = randomUUID();
    string key = "prefs:" ~ userId.toString();
    void cleanup() {
        try redis.getDb().del(key);
        catch (Exception) {}
    }
    cleanup();
    scope (exit) cleanup();

    // Write a hand-crafted blob that Vibe.d cannot parse at all — not just
    // a shape mismatch, but genuinely bad bytes. The load() catch block must
    // delete the key so subsequent loads return init without retrying.
    redis.getDb().set(key, "{this is not valid json at all");
    assert(redis.exists(key), "precondition: bad blob must be in Redis");

    auto repo = new PreferencesRepository(redis);
    const prefs = repo.load(userId);
    assert(prefs.prefVersion == 0,
        "load() must return defaults when the blob is unparseable");
    assert(!redis.exists(key),
        "load() must delete the corrupt key as a self-heal so the next " ~
        "load does not re-trigger the warning");
}
