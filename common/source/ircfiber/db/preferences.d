module ircfiber.db.preferences;

import std.algorithm.searching : canFind;
import std.string : strip;
import std.uni : icmp;
import std.uuid;
import vibe.data.json;
import vibe.core.log;
import vibe.core.sync : TaskMutex;
import ircfiber.logging : logJsonMap;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.db.prefs_cache : PrefsCache;
import ircfiber.db.prefs_mongo : loadPrefsDoc, savePrefsDoc, deletePrefsDoc;
import ircfiber.redis.protocol : RedisKeys;

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

/// Default bouncer playback size (lines per buffer on attach).
enum int BNC_PLAYBACK_DEFAULT = 200;
/// Upper bound accepted from the UI; keeps a 30-channel attach under ~1 MB.
enum int BNC_PLAYBACK_MAX = 1000;

/// Clamps a requested playback size into `[0, BNC_PLAYBACK_MAX]`.
int clampBncPlaybackLines(int v) @safe pure nothrow @nogc {
    if (v < 0) return 0;
    if (v > BNC_PLAYBACK_MAX) return BNC_PLAYBACK_MAX;
    return v;
}

/// Hard ceiling for simultaneously attached bouncer clients per account.
enum int BNC_MAX_CLIENTS_CEILING = 32;
/// Longest stored auto-away message.
enum size_t BNC_AWAY_MAX = 200;

/// Clamps a requested client cap into `[0, BNC_MAX_CLIENTS_CEILING]`.
int clampBncMaxClients(int v) @safe pure nothrow @nogc {
    if (v < 0) return 0;
    if (v > BNC_MAX_CLIENTS_CEILING) return BNC_MAX_CLIENTS_CEILING;
    return v;
}

/// Truncates an auto-away message to `BNC_AWAY_MAX` bytes.
string truncateBncAway(string v) @safe pure nothrow {
    return v.length > BNC_AWAY_MAX ? v[0 .. BNC_AWAY_MAX] : v;
}

/// `modeIndicator` values (web Settings → Messages → Mode indicators, iOS Settings → Display).
immutable string[] DISPLAY_MODE_INDICATORS = ["dots", "symbols", "hidden"];
/// `timestampFormat` values; "auto" follows the device/browser locale.
immutable string[] DISPLAY_TIMESTAMP_FORMATS = ["auto", "12h", "24h"];
/// The boolean account display prefs, in wire order.
immutable string[] DISPLAY_BOOL_PREFS = ["showUserIcons", "monospaceFont", "enlargeEmoji", "coloriseMentions", "formatColors", "showTimestamps"];
/// Mobile device profiles kept per account; creating one past this drops the one seen least recently.
enum MAX_DEVICE_PROFILES = 20;
/// The iOS app's install id header; selects the device's own settings profile.
enum DEVICE_HEADER = "X-IRCFiber-Device";
/// The iOS app's hardware model header (`iPhone17,1`), shown in Settings → Sessions → Mobile devices.
enum DEVICE_MODEL_HEADER = "X-IRCFiber-Device-Model";
/// `lastSeenAt` is rewritten at most this often by reads, so GET /api/me stays read-only in steady state.
enum long DEVICE_SEEN_GRANULARITY_MS = 3_600_000;
/// Bool fields a device profile shares with the account's flat fields, in wire order.
immutable string[] DEVICE_BOOL_PREFS = ["showMemberPrefixes", "desktopNotifications", "notificationSound", "autoDismissNotifs", "muteAll", "displayPrefsSet", "showUserIcons", "monospaceFont", "enlargeEmoji", "coloriseMentions", "formatColors", "showTimestamps"];
/// The settings a device profile keeps apart from the web's: everything in it but `displayPrefsSet` and the metadata.
private immutable string[] DEVICE_SETTINGS = ["showMemberPrefixes", "desktopNotifications", "notificationSound", "autoDismissNotifs", "muteAll", "showUserIcons", "monospaceFont", "modeIndicator", "enlargeEmoji", "coloriseMentions", "formatColors", "showTimestamps", "timestampFormat"];
/// The notification prefs (POST /api/me/notification-prefs), in wire order.
immutable string[] NOTIFICATION_PREFS = ["desktopNotifications", "notificationSound", "autoDismissNotifs", "muteAll"];
/// Highlight words per account, and the longest word in bytes.
enum MAX_HIGHLIGHT_WORDS = 100;
enum MAX_HIGHLIGHT_WORD_BYTES = 64;

/// One iOS install's own display, member-list and notification settings (`UserPreferences.devices`).
/// The settings fields have the names, types and defaults of the account's flat fields, so
/// `displayPrefsJson`, `applyDisplayPrefsPatch` and `applyNotificationPatch` take either.
struct DeviceProfile {
    bool showMemberPrefixes = false;
    bool desktopNotifications = true;
    bool notificationSound = true;
    bool autoDismissNotifs = true;
    bool muteAll = false;
    /// Always true: a profile starts as a copy of settings the account already has, so the app
    /// never runs a first-time seed from its own storage.
    bool displayPrefsSet = true;
    bool showUserIcons = true;
    bool monospaceFont = true;
    string modeIndicator = "dots";
    bool enlargeEmoji = true;
    bool coloriseMentions = true;
    bool formatColors = true;
    bool showTimestamps = true;
    string timestampFormat = "auto";
    /// Hardware model from `DEVICE_MODEL_HEADER` (`iPhone17,1`); "" until the app sends a valid one.
    string model;
    /// Unix ms of the device's first request.
    long createdAt;
    /// Unix ms of the last settings change.
    long updatedAt;
    /// Unix ms of the device's last request, at `DEVICE_SEEN_GRANULARITY_MS` granularity.
    long lastSeenAt;
    /// This install's own bouncer password, minted by POST /api/me/bouncer-token;
    /// "" until minted. NOT in DEVICE_SETTINGS/DEVICE_BOOL_PREFS, so copySettings
    /// and accountProfile (the web<->device sync) never touch it.
    string bncToken;
    /// Unix ms the token above was minted; 0 when unset.
    long bncTokenCreatedAtMs;

    /// Serializes every field under its own name.
    Json toJson() const {
        auto j = Json.emptyObject;
        static foreach (key; DEVICE_BOOL_PREFS)
            j[key] = Json(__traits(getMember, this, key));
        j["modeIndicator"] = Json(modeIndicator);
        j["timestampFormat"] = Json(timestampFormat);
        j["model"] = Json(model);
        j["createdAt"] = Json(createdAt);
        j["updatedAt"] = Json(updatedAt);
        j["lastSeenAt"] = Json(lastSeenAt);
        j["bncToken"] = Json(bncToken);
        j["bncTokenCreatedAtMs"] = Json(bncTokenCreatedAtMs);
        return j;
    }

    /// Decodes a stored profile. A present field of the wrong type (or an unknown enum value, or a
    /// malformed model) keeps its default and sets `bad`; missing fields keep their defaults and
    /// unknown keys are ignored.
    static DeviceProfile fromJson(Json j, out bool bad) {
        DeviceProfile d;
        static foreach (key; DEVICE_BOOL_PREFS) {
            if (auto v = key in j) {
                if (v.type == Json.Type.bool_)
                    __traits(getMember, d, key) = v.get!bool;
                else
                    bad = true;
            }
        }
        if (auto v = "modeIndicator" in j) {
            if (v.type == Json.Type.string && DISPLAY_MODE_INDICATORS.canFind(v.get!string))
                d.modeIndicator = v.get!string;
            else
                bad = true;
        }
        if (auto v = "timestampFormat" in j) {
            if (v.type == Json.Type.string && DISPLAY_TIMESTAMP_FORMATS.canFind(v.get!string))
                d.timestampFormat = v.get!string;
            else
                bad = true;
        }
        if (auto v = "model" in j) {
            // "" is a stored "no model yet", not damage.
            if (v.type == Json.Type.string && (v.get!string.length == 0 || isDeviceModel(v.get!string)))
                d.model = v.get!string;
            else
                bad = true;
        }
        static foreach (key; ["createdAt", "updatedAt", "lastSeenAt"]) {
            if (auto v = key in j) {
                if (v.type == Json.Type.int_)
                    __traits(getMember, d, key) = v.get!long;
                else
                    bad = true;
            }
        }
        if (auto v = "bncToken" in j) {
            if (v.type == Json.Type.string)
                d.bncToken = v.get!string;
            else
                bad = true;
        }
        if (auto v = "bncTokenCreatedAtMs" in j) {
            if (v.type == Json.Type.int_)
                d.bncTokenCreatedAtMs = v.get!long;
            else
                bad = true;
        }
        return d;
    }
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

    /// IRCCloud-style ignore masks (nick!user@host globs), synced across
    /// devices. One global list (deliberate deviation from IRCCloud's
    /// per-connection scoping) — matches the frontend's single storage key.
    string[] ignores;

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

    /// Whether to show mode-prefix glyphs (@, +, %, etc.) in the member
    /// list. Default FALSE: a new account starts with the clean IRCCloud
    /// look (band colour carries the rank). Accounts that already have a
    /// stored prefs document are unaffected — `toJson` always writes the
    /// field, so their saved value wins over this default.
    /// Synced cross-tab via localStorage + cross-device via pref_update
    /// (`showMemberPrefixes` key) + `stat_user` boot seed. The setter writes
    /// to localStorage immediately so a fast refresh (<500ms debounce) keeps
    /// the choice; the Settings UI also POSTs to
    /// `/api/me/show-member-prefixes` which then fans out via WS.
    bool showMemberPrefixes = false;

    /// Global notification preferences — flat bools keep `prefVersion` fan-out
    /// uniform (one counter for all prefs) and avoid a nested `notificationPrefs`
    /// object migration. Cross-device via `pref_update` key `notificationPrefs`
    /// + `stat_user` boot seed. Mirrors `showMemberPrefixes` handling.
    bool desktopNotifications = true;
    bool notificationSound = true;
    bool autoDismissNotifs = true;
    bool muteAll = false;
    /// The web's chat display prefs (web Settings → Interface/Messages; each iOS install keeps its own in `devices`).
    /// Flat like the notification prefs; fanned out as one `displayPrefs` object
    /// (`displayPrefsJson`). Defaults equal the web's DEFAULT_PREFS. `displayPrefsSet` stays false
    /// until the first POST /api/me/display-prefs; the first web client after the upgrade then
    /// seeds the account from its localStorage values.
    bool displayPrefsSet = false;
    bool showUserIcons = true;
    bool monospaceFont = true;
    string modeIndicator = "dots";
    bool enlargeEmoji = true;
    bool coloriseMentions = true;
    bool formatColors = true;
    bool showTimestamps = true;
    string timestampFormat = "auto";
    /// Each iOS install's own settings, keyed by its lower-case install id (`X-IRCFiber-Device`);
    /// the flat fields above are the web's.
    DeviceProfile[string] devices;
    /// Words highlighted like the own nick (whole word, case-insensitive); web and app share them.
    string[] highlightWords;

    /// Lines per buffer the bouncer replays when a client without
    /// `draft/chathistory` attaches (ZNC "playback buffer"). 0 disables.
    /// Set from Settings → Bouncer → Access via
    /// `/api/me/bouncer/settings`; read by the bnc process on attach.
    int bncPlaybackLines = BNC_PLAYBACK_DEFAULT;
    /// Reject a bouncer client that attaches without TLS.
    bool bncRequireTls = false;
    /// When non-empty, a bouncer client's IP must match one of these
    /// CIDRs (`ircfiber.ipintel.cidr.cidrContains`).
    string[] bncAllowedCidrs;
    /// Max simultaneously attached bouncer clients (0 = unlimited).
    int bncMaxClients = 0;
    /// Sent as `AWAY :<message>` on the network when this account's last
    /// bouncer client detaches, cleared on attach. Empty disables it.
    string bncAwayMessage;
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
        j["ignores"] = ignores is null ? Json.emptyArray : serializeToJson(ignores);
        auto bp = Json.emptyObject;
        foreach (k, v; bufferPrefs)
            bp[k] = v;
        j["bufferPrefs"] = bp;
        j["prefVersion"] = Json(prefVersion);
        j["showMemberPrefixes"] = Json(showMemberPrefixes);
        j["desktopNotifications"] = Json(desktopNotifications);
        j["notificationSound"] = Json(notificationSound);
        j["autoDismissNotifs"] = Json(autoDismissNotifs);
        j["muteAll"] = Json(muteAll);
        j["displayPrefsSet"] = Json(displayPrefsSet);
        static foreach (key; DISPLAY_BOOL_PREFS)
            j[key] = Json(__traits(getMember, this, key));
        j["modeIndicator"] = Json(modeIndicator);
        j["timestampFormat"] = Json(timestampFormat);
        auto devs = Json.emptyObject;
        foreach (id, ref d; devices)
            devs[id] = d.toJson();
        j["devices"] = devs;
        j["highlightWords"] = highlightWords is null ? Json.emptyArray : serializeToJson(highlightWords);
        j["bncPlaybackLines"] = Json(bncPlaybackLines);
        j["bncRequireTls"] = Json(bncRequireTls);
        j["bncAllowedCidrs"] = bncAllowedCidrs is null ? Json.emptyArray : serializeToJson(bncAllowedCidrs);
        j["bncMaxClients"] = Json(bncMaxClients);
        j["bncAwayMessage"] = Json(bncAwayMessage);
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
        if (auto ig = "ignores" in json) {
            if (ig.type == Json.Type.array)
                p.ignores = deserializeJson!(string[])(*ig);
            else {
                logFieldInvalid(userId, "ignores", ig.type, "array");
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
        if (auto smp = "showMemberPrefixes" in json) {
            if (smp.type == Json.Type.bool_)
                p.showMemberPrefixes = smp.get!bool;
            else {
                logFieldInvalid(userId, "showMemberPrefixes", smp.type, "bool");
                needsRepair = true;
            }
        }
        if (auto v = "desktopNotifications" in json) {
            if (v.type == Json.Type.bool_)
                p.desktopNotifications = v.get!bool;
            else {
                logFieldInvalid(userId, "desktopNotifications", v.type, "bool");
                needsRepair = true;
            }
        }
        if (auto v = "notificationSound" in json) {
            if (v.type == Json.Type.bool_)
                p.notificationSound = v.get!bool;
            else {
                logFieldInvalid(userId, "notificationSound", v.type, "bool");
                needsRepair = true;
            }
        }
        if (auto v = "autoDismissNotifs" in json) {
            if (v.type == Json.Type.bool_)
                p.autoDismissNotifs = v.get!bool;
            else {
                logFieldInvalid(userId, "autoDismissNotifs", v.type, "bool");
                needsRepair = true;
            }
        }
        if (auto v = "muteAll" in json) {
            if (v.type == Json.Type.bool_)
                p.muteAll = v.get!bool;
            else {
                logFieldInvalid(userId, "muteAll", v.type, "bool");
                needsRepair = true;
            }
        }
        if (auto v = "displayPrefsSet" in json) {
            if (v.type == Json.Type.bool_)
                p.displayPrefsSet = v.get!bool;
            else {
                logFieldInvalid(userId, "displayPrefsSet", v.type, "bool");
                needsRepair = true;
            }
        }
        static foreach (key; DISPLAY_BOOL_PREFS) {
            if (auto v = key in json) {
                if (v.type == Json.Type.bool_)
                    __traits(getMember, p, key) = v.get!bool;
                else {
                    logFieldInvalid(userId, key, v.type, "bool");
                    needsRepair = true;
                }
            }
        }
        if (auto v = "modeIndicator" in json) {
            if (v.type == Json.Type.string && DISPLAY_MODE_INDICATORS.canFind(v.get!string))
                p.modeIndicator = v.get!string;
            else {
                logFieldInvalid(userId, "modeIndicator", v.type, "one of dots, symbols, hidden");
                needsRepair = true;
            }
        }
        if (auto v = "timestampFormat" in json) {
            if (v.type == Json.Type.string && DISPLAY_TIMESTAMP_FORMATS.canFind(v.get!string))
                p.timestampFormat = v.get!string;
            else {
                logFieldInvalid(userId, "timestampFormat", v.type, "one of auto, 12h, 24h");
                needsRepair = true;
            }
        }
        if (auto v = "devices" in json) {
            if (v.type != Json.Type.object) {
                logFieldInvalid(userId, "devices", v.type, "object");
                needsRepair = true;
            } else {
                foreach (string id, entry; *v) {
                    if (!isDeviceId(id) || entry.type != Json.Type.object) {
                        needsRepair = true;
                        continue;
                    }
                    bool bad;
                    p.devices[id] = DeviceProfile.fromJson(entry, bad);
                    if (bad) needsRepair = true;
                }
            }
        }
        if (auto v = "highlightWords" in json) {
            if (v.type == Json.Type.array)
                p.highlightWords = normalizeHighlightWords(*v);
            else {
                logFieldInvalid(userId, "highlightWords", v.type, "array");
                p.highlightWords = [];
                needsRepair = true;
            }
        }
        if (auto v = "bncPlaybackLines" in json) {
            if (v.type == Json.Type.int_)
                p.bncPlaybackLines = clampBncPlaybackLines(cast(int) v.get!long);
            else {
                logFieldInvalid(userId, "bncPlaybackLines", v.type, "int");
                needsRepair = true;
            }
        }
        if (auto v = "bncRequireTls" in json) {
            if (v.type == Json.Type.bool_)
                p.bncRequireTls = v.get!bool;
            else {
                logFieldInvalid(userId, "bncRequireTls", v.type, "bool");
                needsRepair = true;
            }
        }
        if (auto v = "bncAllowedCidrs" in json) {
            if (v.type == Json.Type.array) {
                try p.bncAllowedCidrs = deserializeJson!(string[])(*v);
                catch (Exception) {
                    logFieldInvalid(userId, "bncAllowedCidrs", v.type, "array of string");
                    p.bncAllowedCidrs = [];
                    needsRepair = true;
                }
            } else {
                logFieldInvalid(userId, "bncAllowedCidrs", v.type, "array");
                p.bncAllowedCidrs = [];
                needsRepair = true;
            }
        }
        if (auto v = "bncMaxClients" in json) {
            if (v.type == Json.Type.int_)
                p.bncMaxClients = clampBncMaxClients(cast(int) v.get!long);
            else {
                logFieldInvalid(userId, "bncMaxClients", v.type, "int");
                needsRepair = true;
            }
        }
        if (auto v = "bncAwayMessage" in json) {
            if (v.type == Json.Type.string)
                p.bncAwayMessage = truncateBncAway(v.get!string);
            else {
                logFieldInvalid(userId, "bncAwayMessage", v.type, "string");
                needsRepair = true;
            }
        }
        return LoadResult(p, needsRepair);
    }
}

/// A JSON array of `items`; never JSON null, even for a null slice.
Json stringArrayJson(const string[] items) {
    auto j = Json.emptyArray;
    foreach (s; items)
        j ~= Json(s);
    return j;
}

/// The display prefs of the account or of a device profile as one object:
/// `displayPrefsSet` plus the eight synced keys. This is the `displayPrefs`
/// value of GET /api/me, `stat_user` and the `displayPrefs` pref_update.
Json displayPrefsJson(P)(const ref P p) {
    auto j = Json.emptyObject;
    j["displayPrefsSet"] = Json(p.displayPrefsSet);
    static foreach (key; DISPLAY_BOOL_PREFS)
        j[key] = Json(__traits(getMember, p, key));
    j["modeIndicator"] = Json(p.modeIndicator);
    j["timestampFormat"] = Json(p.timestampFormat);
    return j;
}

/// Validates a POST /api/me/display-prefs body without applying it. Returns
/// "" when valid, else the 400 error text. Unknown keys are ignored (as in
/// `updateNotificationPrefs`); `any` is true when a recognised key is present.
string checkDisplayPrefsPatch(Json patch, out bool any) {
    if (patch.type != Json.Type.object)
        return "body must be object";
    static foreach (key; DISPLAY_BOOL_PREFS) {
        if (auto v = key in patch) {
            if (v.type != Json.Type.bool_)
                return key ~ " must be boolean";
            any = true;
        }
    }
    if (auto v = "modeIndicator" in patch) {
        if (v.type != Json.Type.string || !DISPLAY_MODE_INDICATORS.canFind(v.get!string))
            return "modeIndicator must be one of dots, symbols, hidden";
        any = true;
    }
    if (auto v = "timestampFormat" in patch) {
        if (v.type != Json.Type.string || !DISPLAY_TIMESTAMP_FORMATS.canFind(v.get!string))
            return "timestampFormat must be one of auto, 12h, 24h";
        any = true;
    }
    return "";
}

/// Writes each recognised key present in `patch` into the account or a device
/// profile and marks its display prefs as set. The caller must have passed
/// `patch` through `checkDisplayPrefsPatch` first.
void applyDisplayPrefsPatch(P)(ref P p, Json patch) {
    static foreach (key; DISPLAY_BOOL_PREFS) {
        if (auto v = key in patch)
            __traits(getMember, p, key) = v.get!bool;
    }
    if (auto v = "modeIndicator" in patch)
        p.modeIndicator = v.get!string;
    if (auto v = "timestampFormat" in patch)
        p.timestampFormat = v.get!string;
    p.displayPrefsSet = true;
}

/// Writes each notification pref `patch` holds as a bool into the account or a
/// device profile; true when any was there. The caller answers a non-bool with 400.
bool applyNotificationPatch(P)(ref P p, Json patch) {
    bool any;
    static foreach (key; NOTIFICATION_PREFS) {
        if (auto v = key in patch) {
            if (v.type == Json.Type.bool_) {
                __traits(getMember, p, key) = v.get!bool;
                any = true;
            }
        }
    }
    return any;
}

/// Whether `s` is an install id as the app sends it: a canonical 36-character UUID, in any case.
bool isDeviceId(string s) @safe {
    if (s.length != 36) return false;
    try {
        cast(void) UUID(s);
        return true;
    } catch (Exception) {
        return false;
    }
}

/// Whether `s` is a hardware model identifier (`iPhone17,1`): 1–32 of `[A-Za-z0-9,._-]`.
bool isDeviceModel(string s) @safe pure {
    import std.ascii : isAlphaNum;

    if (s.length == 0 || s.length > 32) return false;
    foreach (char c; s)
        if (!isAlphaNum(c) && c != ',' && c != '.' && c != '_' && c != '-') return false;
    return true;
}

/// The web's settings as a device profile, metadata zero: what a new device
/// starts from and what "Reset to web settings" copies back.
DeviceProfile accountProfile(const ref UserPreferences p) {
    DeviceProfile d;
    static foreach (key; DEVICE_SETTINGS)
        __traits(getMember, d, key) = __traits(getMember, p, key);
    return d;
}

/// Copies the settings of `from` into `to`, keeping `to`'s model and timestamps.
void copySettings(ref DeviceProfile to, const ref DeviceProfile from) {
    static foreach (key; DEVICE_SETTINGS)
        __traits(getMember, to, key) = __traits(getMember, from, key);
}

/// This device's profile, created on first contact as a copy of the web's
/// settings. Also keeps the device's model and, at `DEVICE_SEEN_GRANULARITY_MS`
/// granularity, when it was last seen. `changed` means the blob must be saved.
/// Creating a profile past `MAX_DEVICE_PROFILES` drops the one seen least
/// recently (ties: the smallest id).
///
/// `deviceId` must already be valid and lower-case; `model` is "" when absent
/// or invalid. The pointer is into `p.devices`, valid until it next changes.
DeviceProfile* ensureDeviceProfile(ref UserPreferences p, string deviceId, string model, long nowMs, out bool changed) {
    if (auto prof = deviceId in p.devices) {
        if (model.length && model != prof.model) {
            prof.model = model;
            changed = true;
        }
        if (nowMs - prof.lastSeenAt >= DEVICE_SEEN_GRANULARITY_MS) {
            prof.lastSeenAt = nowMs;
            changed = true;
        }
        return prof;
    }
    while (p.devices.length >= MAX_DEVICE_PROFILES) {
        string oldest;
        long oldestSeen;
        foreach (id, ref d; p.devices) {
            if (!oldest.length || d.lastSeenAt < oldestSeen || (d.lastSeenAt == oldestSeen && id < oldest)) {
                oldest = id;
                oldestSeen = d.lastSeenAt;
            }
        }
        p.devices.remove(oldest);
    }
    auto fresh = accountProfile(p);
    fresh.model = model;
    fresh.createdAt = fresh.updatedAt = fresh.lastSeenAt = nowMs;
    p.devices[deviceId] = fresh;
    changed = true;
    return deviceId in p.devices;
}

/// The mute and sound a push to one APNs registration follows.
struct PushNotify {
    bool muteAll;
    bool sound;
}

/// The device profile's mute and sound when `deviceId` names a stored one,
/// else the account's (a registration made without an install id).
PushNotify pushNotifyFor(const ref UserPreferences p, string deviceId) {
    if (deviceId.length)
        if (auto d = deviceId in p.devices)
            return PushNotify(d.muteAll, d.notificationSound);
    return PushNotify(p.muteAll, p.notificationSound);
}

/// Cleans a highlight-word list: keeps strings only, trims them, drops empty
/// words and words over `MAX_HIGHLIGHT_WORD_BYTES`, and drops case-insensitive
/// duplicates (first spelling wins, input order kept). A non-array yields [].
/// The `MAX_HIGHLIGHT_WORDS` cap is the caller's to enforce.
string[] normalizeHighlightWords(Json arr) {
    if (arr.type != Json.Type.array)
        return [];
    string[] words;
    foreach (item; arr) {
        if (item.type != Json.Type.string)
            continue;
        string w = item.get!string.strip;
        if (w.length == 0 || w.length > MAX_HIGHLIGHT_WORD_BYTES)
            continue;
        if (words.canFind!((a, b) => icmp(a, b) == 0)(w))
            continue;
        words ~= w;
    }
    return words;
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

    /// Publishes a `pref_update` frame on the user's event channel, the
    /// single implementation shared by the REST handlers and the bouncer.
    void publishPrefUpdate(string userId, string prefKey, Json value, long prefVersion) {
        try {
            auto json = Json.emptyObject;
            json["type"] = Json("pref_update");
            json["key"] = Json(prefKey);
            json["value"] = value;
            json["prefVersion"] = Json(prefVersion);
            redis.publish(RedisKeys.events(userId), json.toString());
        } catch (Exception e) {
            logWarn("prefs: pref_update publish failed for %s/%s: %s", userId, prefKey, e.msg);
        }
    }

    /// Lua script for atomic increment-and-set. Reads the existing JSON
    /// at KEYS[1], computes `newPrefVersion = (existing + 1) or 1`, and
    /// writes ARGV[1] with its leading `"prefVersion":0` replaced by that
    /// value. Returns the value it wrote.
    ///
    /// Why Lua and not MULTI/EXEC? Vibe-d's RedisDatabase doesn't expose
    /// a typed MULTI/EXEC builder (see the `TODO: Transactions` comment
    /// in vibe-d-0.10.3/vibe-d/redis/vibe/db/redis/redis.d). Lua scripts
    /// are Redis's canonical atomic primitive — they execute serially in
    /// the single-threaded server, so the GET+SET pair is observably
    /// atomic from every other client's perspective.
    ///
    /// The payload is spliced as a string, never decoded and re-encoded:
    /// Redis's bundled cjson has no `empty_array`, so a cjson round trip
    /// turns every `[]` into `{}`. That made each save corrupt the empty
    /// array fields, each load "repair" them, and the repair save corrupt
    /// them again — an endless loop bumping prefVersion on every load.
    ///
    /// KEYS[1] = prefs:<userId>
    /// ARGV[1] = JSON to write; must start with `PAYLOAD_PREFIX`
    ///           (see `versionedPayload`)
    /// Returns the new prefVersion.
    private enum PAYLOAD_PREFIX = `{"prefVersion":0,`;
    private enum INCR_AND_SET_LUA = `local current = redis.call('GET', KEYS[1])
local newPrefVersion = 1
if current then
    local ok, parsed = pcall(cjson.decode, current)
    if ok and type(parsed) == 'table' and parsed.prefVersion then
        newPrefVersion = tonumber(parsed.prefVersion) + 1
    end
end
local prefix = '` ~ PAYLOAD_PREFIX ~ `'
local doc = ARGV[1]
if string.sub(doc, 1, #prefix) ~= prefix or not pcall(cjson.decode, doc) then
    return redis.error_reply('preferences.d: ARGV[1] must be JSON starting with ' .. prefix)
end
redis.call('SET', KEYS[1], '{"prefVersion":' .. string.format('%d', newPrefVersion) .. ',' .. string.sub(doc, #prefix + 1))
return newPrefVersion`;

    /// `prefs` as JSON with `"prefVersion":0` first, the shape
    /// `INCR_AND_SET_LUA` splices the real version into.
    private static string versionedPayload(const ref UserPreferences prefs) {
        auto j = prefs.toJson();
        j.remove("prefVersion");
        const rest = j.toString();   // "{...}", never empty: toJson always emits every field
        return PAYLOAD_PREFIX ~ rest[1 .. $];
    }

    /// Creates a new preferences repository, optionally using a shared
    /// LRU cache. When `cache` is null (the common case), the process-wide
    /// singleton default cache is used — all `PreferencesRepository`
    /// instances within a gateway share the same LRU so a warm entry
    /// from one request benefits the next.
    this(RedisStorage redis, PrefsCache cache = null) {
        this.redis = redis;
        this.cache_ = cache !is null ? cache : defaultCache();
    }

    /// Restores prefs from the durable Mongo copy when Redis has nothing
    /// usable, and writes them straight back into Redis.
    ///
    /// The Redis rehydration is NOT an optimisation. `INCR_AND_SET_LUA`
    /// derives the next prefVersion from whatever is in Redis; with an
    /// empty key the counter restarts at 1, and the frontend's
    /// last-write-wins gate (strictly-greater on `lastServerPrefVersion`)
    /// would then reject every `stat_user` until the counter climbed back
    /// past its old value. Restoring the blob verbatim keeps it monotonic.
    private UserPreferences restoreFromDurable(UUID userId, string key, out bool found) {
        found = false;
        auto doc = loadPrefsDoc(userId.toString());
        if (!doc.found) return UserPreferences.init;
        UserPreferences prefs;
        try {
            prefs = UserPreferences.fromJson(doc.blob, userId).prefs;
        } catch (Exception e) {
            logWarn("prefs: durable copy for %s failed to deserialize: %s", userId, e.msg);
            return UserPreferences.init;
        }
        redis.setJson(key, doc.blob);   // plain SET — no version bump
        cache_.set(userId, prefs);
        found = true;
        logInfo("prefs: restored %s from MongoDB (prefVersion %d)", userId, prefs.prefVersion);
        return prefs;
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
    /// `bypassCache` skips the in-process LRU (30 s TTL, no cross-replica
    /// invalidation) so a fresh login always sees another device's writes.
    UserPreferences load(UUID userId, bool bypassCache = false) {
        // NOTE: prefs are Redis-backed. Do NOT gate on the Mongo circuit
        // breaker — that blocks prefs-test and early startup before Mongo
        // is connected. The breaker only protects Mongo paths
        // (network.d). Redis has its own availability (connect try/catch).


        // Fast path: check the in-memory LRU cache first.
        if (!bypassCache) {
            if (auto cached = cache_.get(userId)) {
                return cached.get;
            }
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
        if (raw.length == 0) {
            bool restored;
            auto durable = restoreFromDurable(userId, key, restored);
            return restored ? durable : UserPreferences.init;
        }

        Json json;
        try {
            json = parseJson(raw);
        } catch (Exception e) {
            logLoadFail(userId, "parse: " ~ e.msg);
            redis.del(key);
            logLoadRepaired(userId);
            bool restored;
            auto durable = restoreFromDurable(userId, key, restored);
            return restored ? durable : UserPreferences.init;
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
            bool restored;
            auto durable = restoreFromDurable(userId, key, restored);
            return restored ? durable : UserPreferences.init;
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
        // The Lua is authoritative for prefVersion; zero it so the cached
        // copy below never carries a stale caller-side number.
        prefs.prefVersion = 0;
        const payload = versionedPayload(prefs);

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
            savePrefsDoc(userId.toString(), prefs.toJson(), prefs.prefVersion);
            return 0;
        }

        // Write through to the durable copy. Redis stays authoritative on
        // read; this is what survives a flush or a corrupt-blob repair.
        savePrefsDoc(userId.toString(), prefs.toJson(), prefs.prefVersion);
        return newVersion;
    }

    /// Per-user lock table for `mutate()`. Keyed by user id string.
    ///
    /// `save()` is atomic for the *counter*, but a caller doing
    /// `load()` → change a field → `save()` is not: two concurrent
    /// requests for the same user both read the old blob, and whichever
    /// reaches the Lua second wins on EVERY field while also getting the
    /// higher `prefVersion`. That is a lost update, and because the
    /// frontend resolves conflicts by highest `prefVersion`, the stale
    /// value also wins on the client.
    ///
    /// Observed live: toggling "Desktop notifications" when notification
    /// permission has not been granted writes `true` then immediately
    /// `false`; the requests were sent in that order but were assigned
    /// prefVersion 19 and 18 respectively, so the server kept `true`.
    private TaskMutex[string] userLocks;

    private TaskMutex lockFor(UUID userId) {
        const key = userId.toString();
        if (auto m = key in userLocks) return *m;
        auto m = new TaskMutex;
        userLocks[key] = m;
        return m;
    }

    /// Serialized read-modify-write of one user's preferences.
    ///
    /// `apply` receives the freshly loaded struct by reference and should
    /// mutate the fields it owns. Returns the `prefVersion` written, or 0
    /// when `apply` reports nothing changed (no save is issued then).
    ///
    /// Every mutating pref endpoint MUST go through this instead of
    /// hand-rolling `load()`/`save()`, otherwise it reintroduces the lost
    /// update above.
    long mutate(UUID userId, scope bool delegate(ref UserPreferences) apply) {
        auto lock = lockFor(userId);
        synchronized (lock) {
            auto prefs = load(userId);
            if (!apply(prefs)) return 0;
            return save(userId, prefs);
        }
    }

    /// Convenience overload for callers that always save.
    long mutate(UUID userId, scope void delegate(ref UserPreferences) apply) {
        return mutate(userId, (ref UserPreferences p) { apply(p); return true; });
    }

    /// Erases every copy of a user's preferences: Redis, the in-process
    /// cache, and the durable Mongo document. Callers that only DEL the
    /// Redis key would see the prefs resurrected by `load()`'s fallback.
    void deleteForUser(UUID userId) {
        try
            redis.del(KEY_PREFIX ~ userId.toString());
        catch (Exception e)
            logWarn("prefs: redis del failed for %s: %s", userId, e.msg);
        cache_.remove(userId);
        deletePrefsDoc(userId.toString());
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
    j["ignores"]           = Json.emptyObject;  // wrong type
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
    j3["ignores"]        = serializeToJson(["spammer!*@*"]);
    const r3 = UserPreferences.fromJson(j3, UUID.init);
    assert(!r3.needsRepair, "needsRepair must be false when all fields are correct type");
}

@("prefsRepo.mutate serializes concurrent read-modify-writes: prefVersion ends at N")
unittest {
    // Requires a local Redis on 127.0.0.1:6379. Skip if unavailable
    // (e.g. CI runners without Redis) — the roundtrip test above is
    // sufficient for CI; this one is for the dev box.
    //
    // The savers are vibe.d tasks, not std.parallelism workers: vibe's Redis
    // ConnectionPool asserts "called from a foreign thread" the moment a
    // non-vibe thread touches it, so the std.parallelism version could never
    // pass on a box that actually has Redis. Tasks are also the concurrency
    // model the gateway serves requests with, and they interleave at every
    // Redis round trip.
    //
    // The savers go through mutate(), not raw load()/save(): save() is atomic
    // for the counter only, and a hand-rolled load → modify → save is a
    // documented lost update (see PreferencesRepository.userLocks). mutate()
    // serializes per user with a TaskMutex, so N concurrent appends must all
    // survive with prefVersion ending exactly at N.
    import vibe.core.core : runTask, runEventLoop, exitEventLoop, setTimer, Task;
    import core.time : seconds;
    import std.conv : to;

    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
        redis.ping();
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

    long[] versions;
    string[] saverErrors;
    string timeout;
    string setupError;
    // NOTE: vibe runTask delegates must be nothrow — every throwing call
    // lives inside try/catch and failures are collected for asserts below.
    runTask(() @system nothrow {
        try {
            auto watchdog = setTimer(30.seconds, {
                timeout = "concurrent mutate test timed out";
                exitEventLoop();
            });
            scope (exit) {
                watchdog.stop();
                exitEventLoop();
            }
            Task[] savers;
            foreach (i; 0 .. N) {
                savers ~= runTask((int k) @system nothrow {
                    try {
                        versions ~= repo.mutate(userId, (ref UserPreferences p) {
                            p.pinnedChannels ~= "net1:#parallel-" ~ k.to!string;
                            return true;
                        });
                    } catch (Exception e) {
                        try saverErrors ~= e.msg;
                        catch (Exception) {}
                    }
                }, i);
            }
            foreach (t; savers) {
                try t.join();
                catch (Exception e) {
                    try saverErrors ~= e.msg;
                    catch (Exception) {}
                }
            }
        } catch (Exception e) {
            try setupError = e.msg;
            catch (Exception) {}
            exitEventLoop();
        }
    });
    runEventLoop();

    assert(setupError.length == 0, setupError);

    assert(timeout.length == 0, timeout);
    assert(saverErrors.length == 0, saverErrors.length ? saverErrors[0] : "saver failed");
    assert(versions.length == N, "every saver must return a prefVersion");
    foreach (v; versions) assert(v >= 1, "save() must return the bumped prefVersion");

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
    j["ignores"]          = Json.emptyObject;    // wrong type
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
    assert(back.ignores.length == 0,
        "object-shaped ignores must default to an empty list");
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
    j["ignores"] = Json("nope");
    j["prefVersion"] = Json(3L);

    const back = UserPreferences.fromJson(j).prefs;
    assert(back.pinnedChannels.length == 0);
    assert(back.archivedChannels.length == 0);
    assert(back.networkOrder.length == 0);
    assert(back.ignores.length == 0);
    assert(back.prefVersion == 3);
}

@("UserPreferences fromJson with valid array shape preserves all entries")
unittest {
    // Sanity check that adding the type guard did not regress the happy path.
    auto j = Json.emptyObject;
    j["pinnedChannels"]   = serializeToJson(["net1:#a", "net2:#b"]);
    j["archivedChannels"] = serializeToJson(["net3:#old"]);
    j["networkOrder"]     = serializeToJson(["net1", "net2"]);
    j["ignores"]          = serializeToJson(["spammer!*@*", "*!*@bad.host"]);
    j["prefVersion"]      = Json(11L);

    const back = UserPreferences.fromJson(j).prefs;
    assert(back.pinnedChannels   == ["net1:#a", "net2:#b"]);
    assert(back.archivedChannels == ["net3:#old"]);
    assert(back.networkOrder     == ["net1", "net2"]);
    assert(back.ignores          == ["spammer!*@*", "*!*@bad.host"]);
    assert(back.prefVersion == 11);
}

@("prefsRepo.load self-heals a corrupt blob by deleting the key")
unittest {
    // Requires local Redis (same gate as the atomicity test above).
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
        redis.ping();
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

@("prefsRepo.save keeps every empty array field an array in Redis (no repair loop)")
unittest {
    // Requires local Redis (same gate as the atomicity test above).
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
        redis.ping();
    } catch (Exception e) {
        logWarn("Skipping prefsRepo empty-array test: Redis unavailable (%s)", e.msg);
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

    // The save Lua re-encodes with cjson, which turns an empty array into {}
    // unless the field is re-marked. Every array field of toJson must come
    // back as an array, or the next load repairs and re-saves forever.
    auto repo = new PreferencesRepository(redis, new PrefsCache());
    repo.save(userId, UserPreferences.init);
    const stored = parseJsonString(redis.getDb().get(key));
    foreach (string field, v; UserPreferences.init.toJson()) {
        if (v.type != Json.Type.array) continue;
        assert(stored[field].type == Json.Type.array,
            "empty " ~ field ~ " must stay [] after save");
    }
    assert(!UserPreferences.fromJson(stored).needsRepair,
        "a freshly saved default record must not need repair");
}

@("display prefs and highlight words round-trip; legacy blobs get the defaults")
unittest {
    UserPreferences p;
    p.displayPrefsSet = true;
    p.showUserIcons = false;
    p.monospaceFont = false;
    p.modeIndicator = "symbols";
    p.enlargeEmoji = false;
    p.coloriseMentions = false;
    p.formatColors = false;
    p.showTimestamps = false;
    p.timestampFormat = "24h";
    p.highlightWords = ["deploy", "prod"];
    const r = UserPreferences.fromJson(p.toJson());
    assert(!r.needsRepair);
    assert(r.prefs.displayPrefsSet && !r.prefs.showUserIcons && !r.prefs.monospaceFont);
    assert(!r.prefs.enlargeEmoji && !r.prefs.coloriseMentions && !r.prefs.formatColors && !r.prefs.showTimestamps);
    assert(r.prefs.modeIndicator == "symbols" && r.prefs.timestampFormat == "24h");
    assert(r.prefs.highlightWords == ["deploy", "prod"]);
    const dp = displayPrefsJson(r.prefs);
    assert(dp["displayPrefsSet"].get!bool && !dp["showUserIcons"].get!bool && !dp["showTimestamps"].get!bool);
    assert(dp["modeIndicator"].get!string == "symbols" && dp["timestampFormat"].get!string == "24h");

    // A blob saved before these fields existed decodes to the defaults.
    auto legacy = Json.emptyObject;
    legacy["pinnedChannels"] = serializeToJson(["net1:#a"]);
    const l = UserPreferences.fromJson(legacy);
    assert(!l.needsRepair);
    assert(!l.prefs.displayPrefsSet && l.prefs.showUserIcons && l.prefs.monospaceFont);
    assert(l.prefs.enlargeEmoji && l.prefs.coloriseMentions && l.prefs.formatColors && l.prefs.showTimestamps);
    assert(l.prefs.modeIndicator == "dots" && l.prefs.timestampFormat == "auto");
    assert(l.prefs.highlightWords.length == 0);
    // An empty list is stored and sent as [], never null.
    assert(UserPreferences.init.toJson()["highlightWords"].type == Json.Type.array);
    assert(stringArrayJson(null).type == Json.Type.array);
}

@("fromJson repairs an unknown modeIndicator/timestampFormat to the default")
unittest {
    auto j = Json.emptyObject;
    j["modeIndicator"] = Json("stars");
    j["timestampFormat"] = Json("relative");
    const r = UserPreferences.fromJson(j);
    assert(r.needsRepair);
    assert(r.prefs.modeIndicator == "dots");
    assert(r.prefs.timestampFormat == "auto");

    auto k = Json.emptyObject;
    k["modeIndicator"] = Json(3);
    k["showUserIcons"] = Json("no");
    k["highlightWords"] = Json("deploy");
    const s = UserPreferences.fromJson(k);
    assert(s.needsRepair);
    assert(s.prefs.modeIndicator == "dots" && s.prefs.showUserIcons);
    assert(s.prefs.highlightWords.length == 0);
}

@("checkDisplayPrefsPatch: type and enum errors, unknown keys ignored, any flag")
unittest {
    bool any;
    assert(checkDisplayPrefsPatch(Json.emptyArray, any) == "body must be object");
    auto j = Json.emptyObject;
    j["showUserIcons"] = Json("yes");
    assert(checkDisplayPrefsPatch(j, any) == "showUserIcons must be boolean");
    j = Json.emptyObject;
    j["modeIndicator"] = Json("stars");
    assert(checkDisplayPrefsPatch(j, any) == "modeIndicator must be one of dots, symbols, hidden");
    j = Json.emptyObject;
    j["timestampFormat"] = Json("relative");
    assert(checkDisplayPrefsPatch(j, any) == "timestampFormat must be one of auto, 12h, 24h");
    j = Json.emptyObject;
    j["bogus"] = Json(1);
    j["displayPrefsSet"] = Json(true);
    assert(checkDisplayPrefsPatch(j, any) == "");
    assert(!any, "unknown and server-managed keys do not count");
    j["formatColors"] = Json(false);
    assert(checkDisplayPrefsPatch(j, any) == "");
    assert(any);
    j = Json.emptyObject;
    j["showTimestamps"] = Json(false);
    assert(checkDisplayPrefsPatch(j, any) == "" && any, "showTimestamps alone is a display pref (iOS sends single-key patches)");
}

@("applyDisplayPrefsPatch writes only the given keys and sets displayPrefsSet")
unittest {
    UserPreferences p;
    p.monospaceFont = false;
    auto patch = Json.emptyObject;
    patch["showUserIcons"] = Json(false);
    patch["timestampFormat"] = Json("12h");
    patch["bogus"] = Json(1);
    applyDisplayPrefsPatch(p, patch);
    assert(p.displayPrefsSet);
    assert(!p.showUserIcons && p.timestampFormat == "12h");
    assert(!p.monospaceFont, "keys absent from the patch keep their value");
    assert(p.modeIndicator == "dots" && p.enlargeEmoji && p.coloriseMentions && p.formatColors);
}

@("normalizeHighlightWords trims, drops empty/oversized/non-strings, dedupes case-insensitively")
unittest {
    import std.array : replicate;

    auto j = Json.emptyArray;
    j ~= Json("  Deploy ");
    j ~= Json("deploy");
    j ~= Json("");
    j ~= Json(7);
    j ~= Json(replicate("x", MAX_HIGHLIGHT_WORD_BYTES + 1));
    j ~= Json("prod");
    assert(normalizeHighlightWords(j) == ["Deploy", "prod"]);
    const longest = replicate("y", MAX_HIGHLIGHT_WORD_BYTES);
    assert(normalizeHighlightWords(serializeToJson([longest])) == [longest]);
    assert(normalizeHighlightWords(Json("deploy")).length == 0);
}

@("device profiles round-trip; malformed entries are dropped or defaulted and flag a repair")
unittest {
    enum a = "11111111-2222-4333-8444-555555555555";
    enum b = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    UserPreferences p;
    DeviceProfile d1;
    d1.showUserIcons = false;
    d1.muteAll = true;
    d1.modeIndicator = "symbols";
    d1.timestampFormat = "24h";
    d1.model = "iPhone17,1";
    d1.createdAt = 1;
    d1.updatedAt = 2;
    d1.lastSeenAt = 3;
    DeviceProfile d2;
    d2.showMemberPrefixes = true;
    d2.notificationSound = false;
    p.devices[a] = d1;
    p.devices[b] = d2;
    const r = UserPreferences.fromJson(p.toJson());
    assert(!r.needsRepair, "a stored profile without a model is not damage");
    assert(r.prefs.devices.length == 2);
    assert(r.prefs.devices[a] == d1 && r.prefs.devices[b] == d2);
    // An account without devices stores {} and reads back none.
    assert(UserPreferences.init.toJson()["devices"].type == Json.Type.object);
    const none = UserPreferences.fromJson(UserPreferences.init.toJson());
    assert(!none.needsRepair && none.prefs.devices.length == 0);

    auto devs = Json.emptyObject;
    devs["not-a-uuid"] = Json.emptyObject;
    auto broken = Json.emptyObject;
    broken["showUserIcons"] = Json("x");
    devs[a] = broken;
    auto j = Json.emptyObject;
    j["devices"] = devs;
    const s = UserPreferences.fromJson(j);
    assert(s.needsRepair);
    assert(s.prefs.devices.keys == [a]);
    assert(s.prefs.devices[a].showUserIcons, "a wrong-typed field keeps its default");

    auto k = Json.emptyObject;
    k["devices"] = Json.emptyArray;
    const t = UserPreferences.fromJson(k);
    assert(t.needsRepair && t.prefs.devices.length == 0);
}

@("ensureDeviceProfile seeds from the web, then writes only for a new model or an hour later")
unittest {
    enum id = "11111111-2222-4333-8444-555555555555";
    enum long now = 1_800_000_000_000;
    UserPreferences p;
    p.showUserIcons = false;
    p.muteAll = true;
    p.timestampFormat = "12h";
    bool changed;
    auto prof = ensureDeviceProfile(p, id, "iPhone17,1", now, changed);
    assert(changed);
    assert(!prof.showUserIcons && prof.muteAll && prof.timestampFormat == "12h");
    assert(prof.displayPrefsSet, "a device answers displayPrefsSet even before the web set its prefs");
    assert(prof.model == "iPhone17,1");
    assert(prof.createdAt == now && prof.updatedAt == now && prof.lastSeenAt == now);

    prof = ensureDeviceProfile(p, id, "iPhone17,1", now + 10 * 60_000, changed);
    assert(!changed, "a request 10 minutes later writes nothing");
    assert(prof.lastSeenAt == now);
    prof = ensureDeviceProfile(p, id, "", now + 2 * 3_600_000, changed);
    assert(changed && prof.lastSeenAt == now + 2 * 3_600_000);
    assert(prof.model == "iPhone17,1", "a request without a model keeps the stored one");
    prof = ensureDeviceProfile(p, id, "iPhone18,2", now + 2 * 3_600_000, changed);
    assert(changed && prof.model == "iPhone18,2");
    assert(prof.createdAt == now && p.devices.length == 1);
}

@("ensureDeviceProfile drops the profile seen least recently past MAX_DEVICE_PROFILES")
unittest {
    import std.format : format;

    UserPreferences p;
    foreach (i; 1 .. MAX_DEVICE_PROFILES + 1) {
        DeviceProfile d;
        d.lastSeenAt = i;
        p.devices[format("%08x-0000-4000-8000-000000000000", i)] = d;
    }
    bool changed;
    ensureDeviceProfile(p, "ffffffff-0000-4000-8000-000000000000", "", 100, changed);
    assert(changed && p.devices.length == MAX_DEVICE_PROFILES);
    assert("00000001-0000-4000-8000-000000000000" !in p.devices);
    assert("00000002-0000-4000-8000-000000000000" in p.devices);
    assert("ffffffff-0000-4000-8000-000000000000" in p.devices);
}

@("a device's patches leave the web's settings alone; copySettings restores the web's")
unittest {
    enum id = "11111111-2222-4333-8444-555555555555";
    UserPreferences p;
    bool changed;
    auto prof = ensureDeviceProfile(p, id, "iPad16,3", 1000, changed);
    auto patch = Json.emptyObject;
    patch["showUserIcons"] = Json(false);
    applyDisplayPrefsPatch(*prof, patch);
    auto notif = Json.emptyObject;
    notif["muteAll"] = Json(true);
    notif["notificationSound"] = Json("loud");
    assert(applyNotificationPatch(*prof, notif));
    prof.showMemberPrefixes = true;
    assert(!prof.showUserIcons && prof.muteAll && prof.notificationSound, "a non-bool is not applied");
    assert(p.showUserIcons && !p.muteAll && !p.showMemberPrefixes, "the web's settings are untouched");
    assert(!displayPrefsJson(*prof)["showUserIcons"].get!bool && displayPrefsJson(p)["showUserIcons"].get!bool);

    const web = accountProfile(p);
    copySettings(*prof, web);
    assert(prof.showUserIcons && !prof.muteAll && !prof.showMemberPrefixes);
    assert(prof.model == "iPad16,3" && prof.createdAt == 1000, "a reset keeps the device's identity");
    assert(!applyNotificationPatch(p, Json.emptyObject));
}

@("pushNotifyFor: a device's own mute and sound, else the account's")
unittest {
    enum muted = "11111111-2222-4333-8444-555555555555";
    enum silent = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    UserPreferences p;
    DeviceProfile m;
    m.muteAll = true;
    p.devices[muted] = m;
    DeviceProfile s;
    s.notificationSound = false;
    p.devices[silent] = s;
    assert(pushNotifyFor(p, muted) == PushNotify(true, true));
    assert(pushNotifyFor(p, silent) == PushNotify(false, false));
    assert(pushNotifyFor(p, "") == PushNotify(false, true));
    assert(pushNotifyFor(p, "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee") == PushNotify(false, true));
    p.muteAll = true;
    assert(pushNotifyFor(p, silent) == PushNotify(false, false), "the account's mute does not reach a device");
    assert(pushNotifyFor(p, "") == PushNotify(true, true));
}

@("isDeviceId takes canonical UUIDs in either case; isDeviceModel takes model identifiers")
unittest {
    import std.array : replicate;
    import std.uni : toUpper;

    assert(isDeviceId("11111111-2222-4333-8444-555555555555"));
    assert(isDeviceId(toUpper("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee")));
    assert(!isDeviceId(""));
    assert(!isDeviceId("11111111222243338444555555555555"));
    assert(!isDeviceId("nope"));
    assert(!isDeviceId("11111111-2222-4333-8444-55555555555g"));
    assert(isDeviceModel("iPhone17,1") && isDeviceModel("x86_64") && isDeviceModel(replicate("a", 32)));
    assert(!isDeviceModel(""));
    assert(!isDeviceModel(replicate("a", 33)));
    assert(!isDeviceModel("a b"));
}
