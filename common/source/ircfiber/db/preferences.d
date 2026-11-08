module ircfiber.db.preferences;

import std.typecons : Nullable;
import std.algorithm.searching : canFind;
import std.string : strip;
import std.uni : icmp;
import std.uuid;
import vibe.data.json;
import vibe.core.log;
import vibe.core.sync : TaskMutex;
import ircfiber.logging : logJsonMap;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.i18n : isSupportedLanguage;
import ircfiber.db.prefs_cache : PrefsCache;
import ircfiber.db.prefs_mongo : loadPrefsDoc, savePrefsDoc, deletePrefsDoc;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.db.notification_policy : NotificationPolicy, defaultPolicy, migrateFromV1, isTzName,
    projDesktop, projSound, projMuteAll, projHighlightWords, removeClient, CLIENT_WEB;

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

/// Wall-clock unix ms (the v1 migration stamp and the `muteAll` projection).
private long unixNowMs() @safe {
    import std.datetime.systime : Clock, SysTime;
    import std.datetime.timezone : UTC;
    import std.datetime.date : DateTime;

    return (Clock.currTime(UTC()) - SysTime(DateTime(1970, 1, 1), UTC())).total!"msecs";
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
/// `textSize` client-pref values: the web Text size presets.
immutable string[] TEXT_SIZE_VALUES = ["s", "m", "l", "xl", "xxl"];
/// `chatScalePct`: message-text size in percent, 80–140 in steps of 5.
bool isChatScalePct(long v) @safe pure nothrow @nogc { return v >= 80 && v <= 140 && v % 5 == 0; }
/// The boolean account display prefs, in wire order.
immutable string[] DISPLAY_BOOL_PREFS = ["showUserIcons", "monospaceFont", "enlargeEmoji", "coloriseMentions", "formatColors", "showTimestamps"];
/// Device profiles kept per account (web browsers and app installs); creating one past this
/// drops the least recently seen web profile, or the least recently seen of any kind when none is web.
enum MAX_DEVICE_PROFILES = 40;
/// A client install's id header (iOS app install or web browser); selects the device's own settings profile.
enum DEVICE_HEADER = "X-IRCFiber-Device";
/// The iOS app's hardware model header (`iPhone17,1`), shown in Settings → Sessions → Devices.
enum DEVICE_MODEL_HEADER = "X-IRCFiber-Device-Model";
enum DEVICE_OS_VERSION_HEADER = "X-IRCFiber-Device-OS";
enum DEVICE_APP_VERSION_HEADER = "X-IRCFiber-Device-App-Version";
/// `web` or `app`; absent or any other value means `app` (the iOS app predates the header).
enum DEVICE_KIND_HEADER = "X-IRCFiber-Device-Kind";
/// The client's automatic label (`Chrome on macOS`), stored as `DeviceProfile.autoName`.
enum DEVICE_NAME_HEADER = "X-IRCFiber-Device-Name";
/// `DeviceProfile.kind` values.
enum DEVICE_KIND_WEB = "web";
/// ditto
enum DEVICE_KIND_APP = "app";
/// Longest device name (user-chosen or automatic) in bytes.
enum MAX_DEVICE_NAME_BYTES = 64;
/// `lastSeenAt` is rewritten at most this often by reads, so GET /api/me stays read-only in steady state.
enum long DEVICE_SEEN_GRANULARITY_MS = 3_600_000;
/// Bool fields a device profile shares with the account's flat fields, in wire order.
immutable string[] DEVICE_BOOL_PREFS = ["showMemberPrefixes", "displayPrefsSet", "showUserIcons", "monospaceFont", "enlargeEmoji", "coloriseMentions", "formatColors", "showTimestamps"];
/// The settings a device profile keeps apart from the web's: everything in it but `displayPrefsSet` and the metadata.
private immutable string[] DEVICE_SETTINGS = ["showMemberPrefixes", "showUserIcons", "monospaceFont", "modeIndicator", "enlargeEmoji", "coloriseMentions", "formatColors", "showTimestamps", "timestampFormat", "chatScalePct"];
/// An app install's IANA timezone (`Europe/Berlin`), stored as `DeviceProfile.tz`.
enum DEVICE_TZ_HEADER = "X-IRCFiber-Device-TZ";
/// Highlight words per account, and the longest word in bytes.
enum MAX_HIGHLIGHT_WORDS = 100;
enum MAX_HIGHLIGHT_WORD_BYTES = 64;

/// How a `clientPrefs` value is validated.
enum ClientPrefKind { bool_, enum_, int_, intEnum }

/// One `clientPrefs` key: its kind and allowed values (`options` for enum_,
/// `min`..`max` for int_ (inclusive), `ints` for intEnum).
struct ClientPrefSpec {
    string key;
    ClientPrefKind kind;
    immutable(string)[] options;
    long min;
    long max;
    immutable(long)[] ints;
}

/// Per-device web client prefs, in wire order (the frontend keeps the identical list).
immutable ClientPrefSpec[] CLIENT_PREFS = [
    ClientPrefSpec("theme", ClientPrefKind.enum_, ["dark", "light", "gruvbox", "monokai"]),
    ClientPrefSpec("textSize", ClientPrefKind.enum_, TEXT_SIZE_VALUES),
    ClientPrefSpec("compactMode", ClientPrefKind.bool_),
    ClientPrefSpec("sidebarLeft", ClientPrefKind.bool_),
    ClientPrefSpec("messageLayout", ClientPrefKind.enum_, ["compact", "comfortable", "separate"]),
    ClientPrefSpec("defaultScrollPreset", ClientPrefKind.int_, null, 0, 4),
    ClientPrefSpec("inlineImages", ClientPrefKind.bool_),
    ClientPrefSpec("inlineVideos", ClientPrefKind.bool_),
    ClientPrefSpec("inlinePastes", ClientPrefKind.bool_),
    ClientPrefSpec("autoplayMedia", ClientPrefKind.bool_),
    ClientPrefSpec("linkPreviewSize", ClientPrefKind.enum_, ["small", "medium", "large"]),
    ClientPrefSpec("groupConsecutiveMessages", ClientPrefKind.bool_),
    ClientPrefSpec("typingIndicator", ClientPrefKind.bool_),
    ClientPrefSpec("showOthersTyping", ClientPrefKind.bool_),
    ClientPrefSpec("markAwayWhenInactive", ClientPrefKind.bool_),
    ClientPrefSpec("awayAfterMinutes", ClientPrefKind.intEnum, null, 0, 0, [5, 15, 30, 60]),
    ClientPrefSpec("removeTrackers", ClientPrefKind.bool_),
    ClientPrefSpec("blurUnrecognizedLinks", ClientPrefKind.bool_),
];

/// One client install's own display, member-list and web client settings
/// (`UserPreferences.devices`): an iOS app install or a web browser. Its
/// notification overrides live in `UserPreferences.notificationPolicy.clients`.
/// The settings fields have the names, types and defaults of the account's flat
/// fields, so `displayPrefsJson` and `applyDisplayPrefsPatch` take either.
struct DeviceProfile {
    bool showMemberPrefixes = false;
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
    /// Message-text size in percent (80–140, step 5); the web Advanced "Message text" multiplier.
    int chatScalePct = 100;
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
    /// Software version this install last reported, `X-IRCFiber-Device-OS` ("18.1") and
    /// X-IRCFiber-Device-App-Version` ("1.1.0 (3)"); "" until the app sends one.
    string osVersion;
    string appVersion;
    /// Client IP at the device's last request (`getClientIp`); "" until known.
    string lastIp;
    /// `DEVICE_KIND_WEB` or `DEVICE_KIND_APP`; fixed when the profile is created.
    string kind = DEVICE_KIND_APP;
    /// The user's label from Settings → Sessions → Devices; "" = none (show `autoName`/`model`).
    string name;
    /// The client's automatic label from `DEVICE_NAME_HEADER` (`Chrome on macOS`); "" until sent.
    string autoName;
    /// This device's web client prefs (`CLIENT_PREFS` keys only; a missing key is the client default).
    /// Replaced, never mutated in place: struct copies share the object.
    Json clientPrefs = Json.emptyObject;
    /// False until this device first writes `clientPrefs` (or a reset/defaults copy sets them), so
    /// a browser that already had local prefs pushes them instead of taking the account's.
    bool clientPrefsSet = false;
    /// This install's IANA timezone from `DEVICE_TZ_HEADER` (metadata; quiet hours with
    /// `tzMode == "device"` use it); "" until the app sends a valid one.
    string tz;

    /// Serializes every field under its own name.
    Json toJson() const {
        auto j = Json.emptyObject;
        static foreach (key; DEVICE_BOOL_PREFS)
            j[key] = Json(__traits(getMember, this, key));
        j["modeIndicator"] = Json(modeIndicator);
        j["timestampFormat"] = Json(timestampFormat);
        j["chatScalePct"] = Json(chatScalePct);
        j["model"] = Json(model);
        j["createdAt"] = Json(createdAt);
        j["updatedAt"] = Json(updatedAt);
        j["lastSeenAt"] = Json(lastSeenAt);
        j["bncToken"] = Json(bncToken);
        j["bncTokenCreatedAtMs"] = Json(bncTokenCreatedAtMs);
        j["osVersion"] = Json(osVersion);
        j["appVersion"] = Json(appVersion);
        j["lastIp"] = Json(lastIp);
        j["kind"] = Json(kind);
        j["name"] = Json(name);
        j["autoName"] = Json(autoName);
        j["clientPrefs"] = clientPrefs.clone;
        j["clientPrefsSet"] = Json(clientPrefsSet);
        j["tz"] = Json(tz);
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
        if (auto v = "chatScalePct" in j) {
            if (v.type == Json.Type.int_ && isChatScalePct(v.get!long))
                d.chatScalePct = cast(int) v.get!long;
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
        if (auto v = "osVersion" in j) {
            if (v.type == Json.Type.string && (v.get!string.length == 0 || isDeviceOsVersion(v.get!string)))
                d.osVersion = v.get!string;
            else
                bad = true;
        }
        if (auto v = "appVersion" in j) {
            if (v.type == Json.Type.string && (v.get!string.length == 0 || isDeviceAppVersion(v.get!string)))
                d.appVersion = v.get!string;
            else
                bad = true;
        }
        if (auto v = "lastIp" in j) {
            if (v.type == Json.Type.string)
                d.lastIp = v.get!string;
            else
                bad = true;
        }
        if (auto v = "kind" in j) {
            if (v.type == Json.Type.string && (v.get!string == DEVICE_KIND_WEB || v.get!string == DEVICE_KIND_APP))
                d.kind = v.get!string;
            else
                bad = true;
        }
        static foreach (key; ["name", "autoName"]) {
            if (auto v = key in j) {
                // "" is a stored "no name", not damage.
                if (v.type == Json.Type.string && (v.get!string.length == 0 || isDeviceName(v.get!string)))
                    __traits(getMember, d, key) = v.get!string;
                else
                    bad = true;
            }
        }
        if (auto v = "clientPrefs" in j) {
            bool cpBad;
            d.clientPrefs = sanitizeClientPrefs(*v, cpBad);
            if (cpBad) bad = true;
        }
        if (auto v = "clientPrefsSet" in j) {
            if (v.type == Json.Type.bool_)
                d.clientPrefsSet = v.get!bool;
            else
                bad = true;
        }
        if (auto v = "tz" in j) {
            // "" is a stored "no timezone yet", not damage.
            if (v.type == Json.Type.string && (v.get!string.length == 0 || isDeviceTz(v.get!string)))
                d.tz = v.get!string;
            else
                bad = true;
        }
        return d;
    }
}

/// Content version of the post-signup welcome tour; a reworked tour bumps it.
enum WELCOME_TOUR_VERSION = 1;
/// The tour's last step: 0 is the welcome, 1–5 teach, 6 is "ready".
enum WELCOME_TOUR_LAST_STEP = 6;
/// `WelcomeTour.status`: shown and resumed at `step`.
enum WELCOME_TOUR_PENDING = "pending";
/// `WelcomeTour.status`: finished at "ready". Finished tours never reopen.
enum WELCOME_TOUR_COMPLETED = "completed";
/// `WelcomeTour.status`: dismissed before "ready". Finished tours never reopen.
enum WELCOME_TOUR_SKIPPED = "skipped";

/// Whether `s` is a `WelcomeTour.status` value.
bool isWelcomeTourStatus(string s) @safe pure nothrow @nogc {
    return s == WELCOME_TOUR_PENDING || s == WELCOME_TOUR_COMPLETED || s == WELCOME_TOUR_SKIPPED;
}

/// The post-signup welcome tour's progress: `welcomeTour` in GET /api/me, `stat_user` and its
/// `pref_update`, as `{version, step, status}`. Only accounts given one at creation
/// (`enrollWelcomeTour`) have it; every other account answers JSON null and never sees the
/// tour automatically.
struct WelcomeTour {
    /// The tour content version the account was enrolled in.
    int version_ = WELCOME_TOUR_VERSION;
    /// 0 .. WELCOME_TOUR_LAST_STEP.
    int step = 0;
    /// One of `WELCOME_TOUR_PENDING`, `WELCOME_TOUR_COMPLETED`, `WELCOME_TOUR_SKIPPED`.
    string status = WELCOME_TOUR_PENDING;

    /// Completed or skipped: a terminal state.
    bool finished() const @safe pure nothrow @nogc {
        return status != WELCOME_TOUR_PENDING;
    }

    /// The wire and stored shape.
    Json toJson() const {
        auto j = Json.emptyObject;
        j["version"] = Json(version_);
        j["step"] = Json(step);
        j["status"] = Json(status);
        return j;
    }

    /// Parses a stored tour into `t`; false when `j` is not a complete, valid one.
    static bool fromJson(Json j, out WelcomeTour t) {
        if (j.type != Json.Type.object) return false;
        auto v = "version" in j;
        auto s = "step" in j;
        auto st = "status" in j;
        if (v is null || v.type != Json.Type.int_ || v.get!long < 1 || v.get!long > int.max) return false;
        if (s is null || s.type != Json.Type.int_ || s.get!long < 0 || s.get!long > WELCOME_TOUR_LAST_STEP)
            return false;
        if (st is null || st.type != Json.Type.string || !isWelcomeTourStatus(st.get!string)) return false;
        t.version_ = cast(int) v.get!long;
        t.step = cast(int) s.get!long;
        t.status = st.get!string;
        return true;
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

    /// Notification Policy v2 (`ircfiber.db.notification_policy`): the account's
    /// classes × transports matrix, snooze, quiet hours, highlight words and the
    /// per-client overrides. A stored blob without it is migrated from the v1 flat
    /// fields on load (`migrateFromV1`). `toJson` also writes the v1 projections
    /// (`desktopNotifications`, `notificationSound`, `muteAll`,
    /// `highlightWords`, device `muteAll`/`notificationSound`), never read back.
    /// Every change goes through `bumpPolicyRev`.
    NotificationPolicy notificationPolicy = defaultPolicy();
    /// The web's chat display prefs (web Settings → Interface/Messages; each iOS install keeps its own in `devices`).
    /// Flat fields; fanned out as one `displayPrefs` object
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
    /// Message-text size in percent (80–140, step 5); the web Advanced "Message text" multiplier.
    int chatScalePct = 100;
    /// Account UI language: "" follows the browser/device, else a SUPPORTED_LANGUAGES code.
    /// Account-wide (web and every iOS install); not part of DeviceProfile.
    string language = "";
    /// Each client install's own settings (iOS app installs and web browsers), keyed by its
    /// lower-case install id (`X-IRCFiber-Device`); the flat fields above are the account's,
    /// the defaults a new device starts from (and what header-less clients read and write).
    DeviceProfile[string] devices;
    /// The account's web client prefs: the defaults a new device's `clientPrefs` start from
    /// (`CLIENT_PREFS` keys only). Replaced, never mutated in place.
    Json clientPrefs = Json.emptyObject;

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
    /// When true, the account's regular IRC Fiber login password
    /// (`users.passwordHash`, verified by `ircfiber.auth.verifyPassword`)
    /// also authenticates bouncer clients (SASL PLAIN / PASS), alongside
    /// the dedicated `bncToken`. On by default. Admin revoke
    /// (`web/admin/bnc.d` `apiBncRevoke`) clears it; the self-service
    /// dedicated-password Revoke does not.
    bool bncAllowPasswordAuth = true;
    /// The post-signup welcome tour (`WelcomeTour`). Null for accounts created before it or
    /// otherwise never enrolled: they never see the tour automatically. Account-wide.
    Nullable!WelcomeTour welcomeTour;
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
        // v1 projections of `notificationPolicy` (account view): an older
        // gateway reading this blob keeps v1 behaviour. Never read back.
        const nowMs = unixNowMs();
        j["desktopNotifications"] = Json(projDesktop(notificationPolicy));
        j["notificationSound"] = Json(projSound(notificationPolicy, ""));
        j["muteAll"] = Json(projMuteAll(notificationPolicy, "", nowMs));
        j["displayPrefsSet"] = Json(displayPrefsSet);
        static foreach (key; DISPLAY_BOOL_PREFS)
            j[key] = Json(__traits(getMember, this, key));
        j["modeIndicator"] = Json(modeIndicator);
        j["timestampFormat"] = Json(timestampFormat);
        j["chatScalePct"] = Json(chatScalePct);
        j["language"] = Json(language);
        j["clientPrefs"] = clientPrefs.clone;
        auto devs = Json.emptyObject;
        foreach (id, ref d; devices) {
            auto dj = d.toJson();
            dj["muteAll"] = Json(projMuteAll(notificationPolicy, id, nowMs));
            dj["notificationSound"] = Json(projSound(notificationPolicy, id));
            devs[id] = dj;
        }
        j["devices"] = devs;
        j["highlightWords"] = stringArrayJson(projHighlightWords(notificationPolicy));
        j["notificationPolicy"] = notificationPolicy.toJson();
        j["bncPlaybackLines"] = Json(bncPlaybackLines);
        j["bncRequireTls"] = Json(bncRequireTls);
        j["bncAllowedCidrs"] = bncAllowedCidrs is null ? Json.emptyArray : serializeToJson(bncAllowedCidrs);
        j["bncMaxClients"] = Json(bncMaxClients);
        j["bncAwayMessage"] = Json(bncAwayMessage);
        j["bncAllowPasswordAuth"] = Json(bncAllowPasswordAuth);
        j["welcomeTour"] = welcomeTourJson(this);
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
        if (auto v = "chatScalePct" in json) {
            if (v.type == Json.Type.int_ && isChatScalePct(v.get!long))
                p.chatScalePct = cast(int) v.get!long;
            else {
                logFieldInvalid(userId, "chatScalePct", v.type, "integer 80–140, step 5");
                needsRepair = true;
            }
        }
        if (auto v = "language" in json) {
            if (v.type == Json.Type.string && (v.get!string.length == 0 || isSupportedLanguage(v.get!string)))
                p.language = v.get!string;
            else {
                logFieldInvalid(userId, "language", v.type, "\"\" or a supported language code");
                needsRepair = true;
            }
        }
        if (auto v = "clientPrefs" in json) {
            bool bad;
            p.clientPrefs = sanitizeClientPrefs(*v, bad);
            if (bad) {
                logFieldInvalid(userId, "clientPrefs", v.type, "object of valid client prefs");
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
        if (auto v = "bncAllowPasswordAuth" in json) {
            if (v.type == Json.Type.bool_)
                p.bncAllowPasswordAuth = v.get!bool;
            else {
                logFieldInvalid(userId, "bncAllowPasswordAuth", v.type, "bool");
                needsRepair = true;
            }
        }
        if (auto v = "welcomeTour" in json) {
            if (v.type != Json.Type.null_) {
                WelcomeTour t;
                if (WelcomeTour.fromJson(*v, t))
                    p.welcomeTour = t;
                else {
                    logFieldInvalid(userId, "welcomeTour", v.type,
                        "null or {version >= 1, step 0–6, status pending|completed|skipped}");
                    needsRepair = true;
                }
            }
        }
        // Last: the v1 migration reads the raw `devices` and moves the
        // `"<nid>:_server"` levels out of the already parsed `bufferPrefs`.
        if (auto v = "notificationPolicy" in json) {
            if (v.type == Json.Type.object) {
                bool bad;
                p.notificationPolicy = NotificationPolicy.fromJson(*v, bad);
                if (bad) {
                    logFieldInvalid(userId, "notificationPolicy", v.type, "valid notification policy");
                    needsRepair = true;
                }
            } else {
                logFieldInvalid(userId, "notificationPolicy", v.type, "object");
                p.notificationPolicy = migrateFromV1(json, unixNowMs(), p.bufferPrefs);
                needsRepair = true;
            }
        } else {
            // A v1 blob: migrate, and let load() save the result once.
            import ircfiber.observability : recordCounter;

            p.notificationPolicy = migrateFromV1(json, unixNowMs(), p.bufferPrefs);
            needsRepair = true;
            recordCounter("notify_policy_migrations_total", 1);
            logJsonMap("info", "prefs", "Migrated notification preferences to policy v2",
                ["event": "notify_policy_migrated", "user_id": userId.toString()]);
        }
        // Overrides of devices that no longer have a profile.
        string[] orphans;
        foreach (key, _; p.notificationPolicy.clients)
            if (key != CLIENT_WEB && key !in p.devices) orphans ~= key;
        foreach (key; orphans) {
            removeClient(p.notificationPolicy, key);
            needsRepair = true;
        }
        return LoadResult(p, needsRepair);
    }
}

/// `p.welcomeTour` on the wire: JSON null for an account without a tour, else its object.
/// The `welcomeTour` value of GET /api/me, `stat_user` and the pref_update.
Json welcomeTourJson(const ref UserPreferences p) {
    return p.welcomeTour.isNull ? Json(null) : p.welcomeTour.get.toJson();
}

/// Gives a just-created account the welcome tour, pending at the welcome step. Call it only
/// where an account is created, never on login; an existing tour (any state) is left alone.
/// Returns whether `p` changed.
bool enrollWelcomeTour(ref UserPreferences p) {
    if (!p.welcomeTour.isNull) return false;
    p.welcomeTour = WelcomeTour.init;
    return true;
}

/// Validates a POST /api/me/welcome-tour body `{step, status}` (other keys ignored): "" with
/// `update` set, else the 400 error text. `step` must be a JSON integer in
/// 0 .. WELCOME_TOUR_LAST_STEP, `status` one of pending, completed, skipped.
string parseWelcomeTourUpdate(Json body_, out WelcomeTour update) {
    if (body_.type != Json.Type.object)
        return "body must be object";
    auto s = "step" in body_;
    if (s is null || s.type != Json.Type.int_ || s.get!long < 0 || s.get!long > WELCOME_TOUR_LAST_STEP)
        return "step must be an integer from 0 to 6";
    auto st = "status" in body_;
    if (st is null || st.type != Json.Type.string || !isWelcomeTourStatus(st.get!string))
        return "status must be one of pending, completed, skipped";
    update.step = cast(int) s.get!long;
    update.status = st.get!string;
    return "";
}

/// Applies a client's tour save (`parseWelcomeTourUpdate`) and returns whether `p` changed.
/// Only a pending tour moves: a completed or skipped one is final, so a late or replayed save
/// cannot reopen it (replays after finishing stay on the client), and an account without a
/// tour is never enrolled by a save.
bool applyWelcomeTourUpdate(ref UserPreferences p, const WelcomeTour update) {
    if (p.welcomeTour.isNull) return false;
    auto cur = p.welcomeTour.get;
    if (cur.finished) return false;
    if (cur.step == update.step && cur.status == update.status) return false;
    cur.step = update.step;
    cur.status = update.status;
    p.welcomeTour = cur;
    return true;
}

/// The save-time rule `PreferencesRepository`'s `INCR_AND_SET_LUA` applies
/// atomically (and its plain-SET fallback applies here): a full-blob save
/// carrying `incoming` over a valid `stored` tour keeps `stored` when
/// `incoming` is null (enrolment is never undone) or when `stored` is finished
/// and `incoming` is not identical (finished tours are final). Sets `incoming`
/// to `stored` and returns true when it keeps it.
bool keepStoredWelcomeTour(ref Nullable!WelcomeTour incoming, const WelcomeTour stored) {
    if (!incoming.isNull && (!stored.finished || incoming.get == stored)) return false;
    incoming = WelcomeTour(stored.version_, stored.step, stored.status);
    return true;
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
    j["chatScalePct"] = Json(p.chatScalePct);
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
    if (auto v = "chatScalePct" in patch) {
        if (v.type != Json.Type.int_ || !isChatScalePct(v.get!long))
            return "chatScalePct must be an integer from 80 to 140 in steps of 5";
        any = true;
    }
    return "";
}

/// Validates a POST /api/admin/config/text-defaults body. "" when valid, else
/// the 400 text; `any` is true when a recognised key is present. "" / 0 mean "unset".
string checkTextDefaultsPatch(Json patch, out bool any) {
    if (patch.type != Json.Type.object)
        return "body must be object";
    if (auto v = "textSize" in patch) {
        if (v.type != Json.Type.string || (v.get!string.length && !TEXT_SIZE_VALUES.canFind(v.get!string)))
            return "textSize must be empty or one of s, m, l, xl, xxl";
        any = true;
    }
    if (auto v = "chatScalePct" in patch) {
        if (v.type != Json.Type.int_ || (v.get!long != 0 && !isChatScalePct(v.get!long)))
            return "chatScalePct must be 0 or 80–140 in steps of 5";
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
    if (auto v = "chatScalePct" in patch)
        p.chatScalePct = cast(int) v.get!long;
    p.displayPrefsSet = true;
}

/// The v1 notification prefs (`desktopNotifications`, `notificationSound`,
/// `muteAll`) projected from the policy: the account view
/// when `deviceId` is "", else that install's view (sound and mute as its pushes follow them).
Json notificationPrefsJson(const ref UserPreferences p, string deviceId, long nowMs) {
    auto j = Json.emptyObject;
    j["desktopNotifications"] = Json(projDesktop(p.notificationPolicy));
    j["notificationSound"] = Json(projSound(p.notificationPolicy, deviceId));
    j["muteAll"] = Json(projMuteAll(p.notificationPolicy, deviceId, nowMs));
    return j;
}

/// Marks a change of `p.notificationPolicy`: bumps its `rev` (the If-Match token).
/// Every mutation of the policy calls this once.
void bumpPolicyRev(ref UserPreferences p) @safe pure nothrow @nogc {
    ++p.notificationPolicy.rev;
}

/// "" when `v` is a valid value for `spec`, else the 400 error text (`<key> must be …`).
private string clientPrefError(const ref ClientPrefSpec spec, Json v) {
    import std.algorithm.iteration : map;
    import std.array : join;
    import std.conv : to;

    final switch (spec.kind) {
        case ClientPrefKind.bool_:
            return v.type == Json.Type.bool_ ? "" : spec.key ~ " must be boolean";
        case ClientPrefKind.enum_:
            return v.type == Json.Type.string && spec.options.canFind(v.get!string) ? ""
                : spec.key ~ " must be one of " ~ spec.options.join(", ");
        case ClientPrefKind.int_:
            return v.type == Json.Type.int_ && v.get!long >= spec.min && v.get!long <= spec.max ? ""
                : spec.key ~ " must be an integer from " ~ spec.min.to!string ~ " to " ~ spec.max.to!string;
        case ClientPrefKind.intEnum:
            return v.type == Json.Type.int_ && spec.ints.canFind(v.get!long) ? ""
                : spec.key ~ " must be one of " ~ spec.ints.map!(i => i.to!string).join(", ");
    }
}

/// Validates a POST /api/me/client-prefs body without applying it. Returns ""
/// when valid, else the 400 error text with the offending key in `field`.
/// JSON null is valid for every key (it deletes it); unknown keys are ignored;
/// `any` is true when a recognised key is present.
string checkClientPrefsPatch(Json patch, out bool any, out string field) {
    if (patch.type != Json.Type.object)
        return "body must be object";
    foreach (ref spec; CLIENT_PREFS) {
        if (auto v = spec.key in patch) {
            any = true;
            if (v.type == Json.Type.null_)
                continue;
            const err = clientPrefError(spec, *v);
            if (err.length) {
                field = spec.key;
                return err;
            }
        }
    }
    return "";
}

/// Replaces `prefs` with a new object holding its keys with `patch` applied:
/// each recognised key is set, or deleted when JSON null. The caller must have
/// passed `patch` through `checkClientPrefsPatch` first. Never mutates the old
/// object, so struct copies that share it are unaffected.
void applyClientPrefsPatch(ref Json prefs, Json patch) {
    auto next = Json.emptyObject;
    foreach (ref spec; CLIENT_PREFS) {
        if (auto v = spec.key in patch) {
            if (v.type != Json.Type.null_)
                next[spec.key] = v.clone;
        } else if (prefs.type == Json.Type.object) {
            if (auto old = spec.key in prefs)
                next[spec.key] = old.clone;
        }
    }
    prefs = next;
}

/// A stored `clientPrefs` value as a fresh object of its valid keys. A
/// non-object, an invalid value or an unknown key is dropped and sets `bad`.
Json sanitizeClientPrefs(Json stored, out bool bad) {
    auto clean = Json.emptyObject;
    if (stored.type != Json.Type.object) {
        bad = true;
        return clean;
    }
    if (stored.type == Json.Type.object && "textSize" !in stored) {
        if (auto fs = "fontSize" in stored) {
            if (fs.type == Json.Type.int_) {
                const n = fs.get!long;
                stored = stored.clone;
                stored["textSize"] = Json(n <= 12 ? "s" : n <= 14 ? "m" : n <= 16 ? "l" : n <= 17 ? "xl" : "xxl");
            }
        }
    }
    size_t kept;
    foreach (ref spec; CLIENT_PREFS) {
        if (auto v = spec.key in stored) {
            if (clientPrefError(spec, *v).length) {
                bad = true;
            } else {
                clean[spec.key] = v.clone;
                ++kept;
            }
        }
    }
    if (kept != stored.length) bad = true;
    return clean;
}

/// Whether `s` is a stored device name (`DEVICE_NAME_HEADER` or a rename):
/// 1–`MAX_DEVICE_NAME_BYTES` bytes of valid UTF-8, no control characters
/// (< 0x20, 0x7f) and no surrounding whitespace.
bool isDeviceName(string s) @safe {
    import std.utf : validate;

    if (s.length == 0 || s.length > MAX_DEVICE_NAME_BYTES || s.strip.length != s.length) return false;
    foreach (char c; s)
        if (c < 0x20 || c == 0x7f) return false;
    try {
        validate(s);
        return true;
    } catch (Exception) {
        return false;
    }
}

/// `raw` trimmed when that is a valid device name, else "".
string normalizeDeviceName(string raw) @safe {
    const s = raw.strip;
    return isDeviceName(s) ? s : "";
}

/// `DEVICE_KIND_WEB` for exactly "web", else `DEVICE_KIND_APP` (absent or unknown).
string normalizeDeviceKind(string raw) @safe pure nothrow @nogc {
    return raw == DEVICE_KIND_WEB ? DEVICE_KIND_WEB : DEVICE_KIND_APP;
}

/// The `device` object of GET /api/me and `stat_user`: who this device is. `ref_` is its
/// `sessionRef(id)` (the install id never leaves the server).
Json deviceIdentityJson(string ref_, const ref DeviceProfile d) {
    auto j = Json.emptyObject;
    j["ref"] = Json(ref_);
    j["kind"] = Json(d.kind);
    j["name"] = Json(d.name);
    j["autoName"] = Json(d.autoName);
    j["model"] = Json(d.model);
    j["createdAt"] = Json(d.createdAt);
    return j;
}

/// The value of the `deviceSettings` pref_update: one device's identity and every per-device setting.
/// `deviceId` must name a profile in `p.devices`.
Json deviceSettingsJson(string ref_, const ref UserPreferences p, string deviceId, long nowMs) {
    const d = &p.devices[deviceId];
    auto j = Json.emptyObject;
    j["ref"] = Json(ref_);
    j["kind"] = Json(d.kind);
    j["name"] = Json(d.name);
    j["autoName"] = Json(d.autoName);
    j["displayPrefs"] = displayPrefsJson(*d);
    j["notificationPrefs"] = notificationPrefsJson(p, deviceId, nowMs);
    j["showMemberPrefixes"] = Json(d.showMemberPrefixes);
    j["clientPrefs"] = d.clientPrefs.clone;
    j["clientPrefsSet"] = Json(d.clientPrefsSet);
    j["updatedAt"] = Json(d.updatedAt);
    return j;
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

/// Whether `s` is a hardware model identifier (`iPhone17,1`): 1–32 bytes of
/// `[A-Za-z0-9,._-]`, optionally followed by exactly ` (Simulator)` — what the
/// iOS app sends from the Simulator (`Diagnostics.modelIdentifier`). The
/// suffix counts toward the 32-byte cap and the base must be nonempty.
bool isDeviceModel(string s) @safe pure {
    import std.algorithm.searching : endsWith;
    import std.ascii : isAlphaNum;

    enum simulatorSuffix = " (Simulator)";
    if (s.length == 0 || s.length > 32) return false;
    if (s.endsWith(simulatorSuffix)) s = s[0 .. $ - simulatorSuffix.length];
    if (s.length == 0) return false;
    foreach (char c; s)
        if (!isAlphaNum(c) && c != ',' && c != '.' && c != '_' && c != '-') return false;
    return true;
}

/// Whether `s` is an OS version as the app sends it (`18.1`, `17.5.1`): 1–16 of `[0-9.]`.
bool isDeviceOsVersion(string s) @safe pure {
    if (s.length == 0 || s.length > 16) return false;
    foreach (c; s) if (c != '.' && (c < '0' || c > '9')) return false;
    return true;
}

/// Whether `s` is an app version as the app sends it (`1.1.0 (3)`): 1–32 of `[0-9A-Za-z.() -]`.
bool isDeviceAppVersion(string s) @safe pure {
    import std.ascii : isAlphaNum;

    if (s.length == 0 || s.length > 32) return false;
    foreach (c; s) if (!isAlphaNum(c) && c != '.' && c != '(' && c != ')' && c != ' ' && c != '-') return false;
    return true;
}

/// Whether `s` is a timezone as the app sends it (`DEVICE_TZ_HEADER`): an IANA name,
/// 1–64 of `[A-Za-z0-9_+\-/]`. Whether it resolves is the gateway's check.
bool isDeviceTz(string s) @safe pure nothrow @nogc {
    return isTzName(s);
}

/// The account's settings as a device profile, metadata zero (`clientPrefsSet` false):
/// what a new device starts from and what "Reset to defaults" copies back.
DeviceProfile accountProfile(const ref UserPreferences p) {
    DeviceProfile d;
    static foreach (key; DEVICE_SETTINGS)
        __traits(getMember, d, key) = __traits(getMember, p, key);
    d.clientPrefs = p.clientPrefs.clone;
    return d;
}

/// Copies the settings of `from` into `to` (`clientPrefs` included), keeping `to`'s
/// identity, `clientPrefsSet` and timestamps.
void copySettings(ref DeviceProfile to, const ref DeviceProfile from) {
    static foreach (key; DEVICE_SETTINGS)
        __traits(getMember, to, key) = __traits(getMember, from, key);
    to.clientPrefs = from.clientPrefs.clone;
}

/// "Reset to defaults": the account's settings over device `d`'s own, which then
/// counts as having client prefs (the browser takes them instead of pushing its own).
void resetDeviceToAccount(ref DeviceProfile d, const ref UserPreferences p) {
    const defaults = accountProfile(p);
    copySettings(d, defaults);
    d.clientPrefsSet = true;
}

/// "Make these the defaults for new devices": device `d`'s settings over the
/// account's flat fields (marking its display prefs set) and its client prefs.
void makeAccountDefaults(ref UserPreferences p, const ref DeviceProfile d) {
    static foreach (key; DEVICE_SETTINGS)
        __traits(getMember, p, key) = __traits(getMember, d, key);
    p.displayPrefsSet = true;
    p.clientPrefs = d.clientPrefs.clone;
}

/// This device's profile, created on first contact as a copy of the account's
/// settings (`clientPrefsSet` false). Also keeps the device's model, automatic
/// name and, at `DEVICE_SEEN_GRANULARITY_MS` granularity, when it was last seen.
/// `changed` means the blob must be saved. `kind` is stored on creation only.
/// Creating a profile past `MAX_DEVICE_PROFILES` drops the web profile seen least
/// recently, or when none is web the profile of any kind seen least recently
/// (ties: the smallest id).
///
/// `deviceId` must already be valid and lower-case; `model`, `autoName` and `tz` are ""
/// when absent or invalid. The pointer is into `p.devices`, valid until it next changes.
/// A dropped profile's notification overrides go with it.
DeviceProfile* ensureDeviceProfile(ref UserPreferences p, string deviceId, string model, long nowMs,
        out bool changed, string osVersion = "", string appVersion = "", string clientIp = "",
        string kind = DEVICE_KIND_APP, string autoName = "", string tz = "") {
    if (auto prof = deviceId in p.devices) {
        if (model.length && model != prof.model) {
            prof.model = model;
            changed = true;
        }
        if (osVersion.length && osVersion != prof.osVersion) {
            prof.osVersion = osVersion;
            changed = true;
        }
        if (appVersion.length && appVersion != prof.appVersion) {
            prof.appVersion = appVersion;
            changed = true;
        }
        if (clientIp.length && clientIp != prof.lastIp) {
            prof.lastIp = clientIp;
            changed = true;
        }
        if (autoName.length && autoName != prof.autoName) {
            prof.autoName = autoName;
            changed = true;
        }
        if (tz.length && tz != prof.tz) {
            prof.tz = tz;
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
        bool oldestWeb;
        foreach (id, ref d; p.devices) {
            const web = d.kind == DEVICE_KIND_WEB;
            if (!oldest.length || (web && !oldestWeb)
                    || (web == oldestWeb && (d.lastSeenAt < oldestSeen || (d.lastSeenAt == oldestSeen && id < oldest)))) {
                oldest = id;
                oldestSeen = d.lastSeenAt;
                oldestWeb = web;
            }
        }
        p.devices.remove(oldest);
        if (removeClient(p.notificationPolicy, oldest)) bumpPolicyRev(p);
    }
    auto fresh = accountProfile(p);
    fresh.model = model;
    fresh.osVersion = osVersion;
    fresh.appVersion = appVersion;
    fresh.lastIp = clientIp;
    fresh.kind = normalizeDeviceKind(kind);
    fresh.autoName = autoName;
    fresh.tz = tz;
    fresh.createdAt = fresh.updatedAt = fresh.lastSeenAt = nowMs;
    p.devices[deviceId] = fresh;
    changed = true;
    return deviceId in p.devices;
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
    /// `welcomeTour` is the one field decided here rather than by the
    /// caller: every save writes the whole blob, so a process (or another
    /// gateway colour) holding an older copy would otherwise put back the
    /// tour it read. A valid stored tour is kept when the incoming one is
    /// not an object (null: enrolment is never undone), and a stored
    /// completed/skipped tour is kept unless the incoming one is identical
    /// (finished tours are final). Only that one segment of the payload is
    /// replaced, by the stored tour re-encoded. A kept tour is reported by
    /// returning the new version negated, so `save` can correct its copy.
    ///
    /// KEYS[1] = prefs:<userId>
    /// ARGV[1] = JSON to write; must start with `PAYLOAD_PREFIX` followed
    ///           by ARGV[2] and a comma (see `versionedPayload`)
    /// ARGV[2] = the payload's `welcomeTour` value, exactly as spliced
    /// Returns the new prefVersion, negated when the stored tour was kept.
    private enum PAYLOAD_PREFIX = `{"prefVersion":0,"welcomeTour":`;
    static assert(WELCOME_TOUR_LAST_STEP == 6, "update the step bound in INCR_AND_SET_LUA");
    private enum INCR_AND_SET_LUA = `local current = redis.call('GET', KEYS[1])
local newPrefVersion = 1
local stored = nil
if current then
    local ok, parsed = pcall(cjson.decode, current)
    if ok and type(parsed) == 'table' then
        if parsed.prefVersion then
            newPrefVersion = tonumber(parsed.prefVersion) + 1
        end
        stored = parsed.welcomeTour
    end
end
local prefix = '` ~ PAYLOAD_PREFIX ~ `'
local doc = ARGV[1]
local tour = ARGV[2]
local okDoc, incoming = pcall(cjson.decode, doc)
if not okDoc or type(incoming) ~= 'table' or string.sub(doc, 1, #prefix + #tour + 1) ~= prefix .. tour .. ',' then
    return redis.error_reply('preferences.d: ARGV[1] must be JSON starting with ' .. prefix .. tour .. ',')
end
local rest = string.sub(doc, #prefix + #tour + 2)
local function validTour(t)
    return type(t) == 'table'
        and (t.status == 'pending' or t.status == 'completed' or t.status == 'skipped')
        and type(t.step) == 'number' and t.step >= 0 and t.step <= 6 and t.step == math.floor(t.step)
        and type(t.version) == 'number' and t.version >= 1 and t.version <= 2147483647
        and t.version == math.floor(t.version)
end
local kept = false
if validTour(stored) then
    local inc = incoming.welcomeTour
    if type(inc) ~= 'table' or (stored.status ~= 'pending'
            and not (inc.status == stored.status and inc.step == stored.step and inc.version == stored.version)) then
        tour = cjson.encode({version = stored.version, step = stored.step, status = stored.status})
        kept = true
    end
end
redis.call('SET', KEYS[1], '{"prefVersion":' .. string.format('%d', newPrefVersion) .. ',"welcomeTour":' .. tour .. ',' .. rest)
if kept then
    return -newPrefVersion
end
return newPrefVersion`;

    /// `prefs` as JSON with `"prefVersion":0` then `"welcomeTour"` first, the
    /// shape `INCR_AND_SET_LUA` splices into; `tour` is the welcomeTour value
    /// as written there.
    private static string versionedPayload(const ref UserPreferences prefs, out string tour) {
        auto j = prefs.toJson();
        j.remove("prefVersion");
        j.remove("welcomeTour");
        tour = welcomeTourJson(prefs).toString();
        const rest = j.toString();   // "{...}", never empty: toJson always emits every field
        return PAYLOAD_PREFIX ~ tour ~ "," ~ rest[1 .. $];
    }

    /// The valid `welcomeTour` stored at `key`, read back after `INCR_AND_SET_LUA`
    /// kept it; false when it cannot be read.
    private bool readStoredWelcomeTour(string key, out WelcomeTour tour) {
        try {
            auto j = parseJsonString(redis.getDb().get(key));
            if (j.type == Json.Type.object)
                if (auto v = "welcomeTour" in j)
                    return WelcomeTour.fromJson(*v, tour);
        } catch (Exception e)
            logWarn("prefs: reading the stored welcome tour at %s failed: %s", key, e.msg);
        return false;
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
        string tour;
        const payload = versionedPayload(prefs, tour);

        long newVersion = 0;
        try {
            auto reply = redis.getDb().eval!long(INCR_AND_SET_LUA, [key], payload, tour);
            if (!reply.empty) {
                newVersion = reply.front;
            }
        } catch (Exception e) {
            logWarn("prefsRepo.save EVAL failed for %s: %s — falling back to plain SET",
                userId, e.msg);
            // Best-effort fallback: plain SET without increment. The
            // prefVersion counter will be wrong on this save, but the
            // next successful save will repair it. We do NOT swallow
            // the failure silently — callers will see prefVersion=0.
            // The plain SET skips the Lua's welcome tour rule, so apply
            // it here (not atomically; this path is already degraded).
            WelcomeTour stored;
            if (readStoredWelcomeTour(key, stored))
                keepStoredWelcomeTour(prefs.welcomeTour, stored);
            redis.setJson(key, prefs.toJson());
            savePrefsDoc(userId.toString(), prefs.toJson(), prefs.prefVersion);
            return 0;
        }
        if (newVersion < 0) {
            // The Lua kept the stored welcome tour over this (older) one:
            // take it so the cache and the durable copy match Redis.
            newVersion = -newVersion;
            WelcomeTour stored;
            if (!readStoredWelcomeTour(key, stored)) {
                // Redis holds the right tour; the next save writes the durable copy.
                cache_.remove(userId);
                return newVersion;
            }
            prefs.welcomeTour = stored;
        }
        // Update cache AFTER the Redis write succeeds so a concurrent
        // load() in another fiber sees the fresh data in the cache
        // instead of reading the stale blob from Redis. This prevents
        // the repair-path race where multiple requests all miss the
        // cache, load the broken blob, and each fires a repair cycle.
        // Restore prefVersion from the Lua-returned counter since
        // it was zeroed before serialization.
        prefs.prefVersion = newVersion;
        cache_.set(userId, prefs);

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

    /// Creates an account so that it can never exist without its welcome tour:
    /// first stores the preferences of `userId` (a freshly allocated id, never an
    /// existing user's) — `seed` (may be null) plus a pending tour — and throws
    /// when that fails, before anything is inserted. Then runs `insert` (the
    /// user-row insert: true when created, false when a unique index lost a
    /// race). When `insert` returns false or throws, those just-written
    /// preferences are erased again, so failed attempts leave nothing behind.
    bool createWithWelcomeTour(UUID userId, scope void delegate(ref UserPreferences) seed,
            scope bool delegate() insert) {
        mutate(userId, (ref UserPreferences p) {
            if (seed !is null) seed(p);
            enrollWelcomeTour(p);
        });
        bool created;
        try created = insert();
        catch (Exception e) {
            eraseUncreated(userId);
            throw e;
        }
        if (!created) eraseUncreated(userId);
        return created;
    }

    /// `deleteForUser` for an account whose insert failed; failures only logged.
    private void eraseUncreated(UUID userId) {
        try deleteForUser(userId);
        catch (Exception e)
            logWarn("prefs: erasing the preferences of uncreated account %s failed: %s", userId, e.msg);
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

    /// Drops this process's cached copy of a user's preferences, so the next
    /// `load()` reads Redis (another replica or thread changed them).
    void forget(UUID userId) {
        cache_.remove(userId);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────

version (unittest) import ircfiber.db.notification_policy;

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
    // Sanity: object fields (correct type) don't trigger the flag. (Each blob
    // carries a v2 notification policy: without one it is a v1 blob and migrating
    // it is a repair of its own.)
    auto j2 = Json.emptyObject;
    j2["lastActiveBuffers"] = Json.emptyObject;
    j2["notificationPolicy"] = defaultPolicy().toJson();
    const r2 = UserPreferences.fromJson(j2, UUID.init);
    assert(!r2.needsRepair, "needsRepair must be false when only object fields are present (correct type)");
    // All-correct JSON must not need repair.
    auto j3 = Json.emptyObject;
    j3["pinnedChannels"] = serializeToJson(["net1:#a"]);
    j3["networkOrder"]   = serializeToJson(["net1"]);
    j3["ignores"]        = serializeToJson(["spammer!*@*"]);
    j3["notificationPolicy"] = defaultPolicy().toJson();
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
    p.notificationPolicy.highlight.words = [HighlightWord("deploy", false), HighlightWord("prod", true)];
    const r = UserPreferences.fromJson(p.toJson());
    assert(!r.needsRepair);
    assert(r.prefs.displayPrefsSet && !r.prefs.showUserIcons && !r.prefs.monospaceFont);
    assert(!r.prefs.enlargeEmoji && !r.prefs.coloriseMentions && !r.prefs.formatColors && !r.prefs.showTimestamps);
    assert(r.prefs.modeIndicator == "symbols" && r.prefs.timestampFormat == "24h");
    assert(r.prefs.notificationPolicy.highlight.words == [HighlightWord("deploy", false), HighlightWord("prod", true)]);
    const dp = displayPrefsJson(r.prefs);
    assert(dp["displayPrefsSet"].get!bool && !dp["showUserIcons"].get!bool && !dp["showTimestamps"].get!bool);
    assert(dp["modeIndicator"].get!string == "symbols" && dp["timestampFormat"].get!string == "24h");

    // A blob saved before these fields existed decodes to the defaults (its
    // notification policy is migrated from v1, which asks for one save).
    auto legacy = Json.emptyObject;
    legacy["pinnedChannels"] = serializeToJson(["net1:#a"]);
    const l = UserPreferences.fromJson(legacy);
    assert(l.needsRepair);
    assert(!l.prefs.displayPrefsSet && l.prefs.showUserIcons && l.prefs.monospaceFont);
    assert(l.prefs.enlargeEmoji && l.prefs.coloriseMentions && l.prefs.formatColors && l.prefs.showTimestamps);
    assert(l.prefs.modeIndicator == "dots" && l.prefs.timestampFormat == "auto");
    assert(l.prefs.notificationPolicy.highlight.words.length == 0);
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
    assert(s.prefs.notificationPolicy.highlight.words.length == 0);
}

@("chatScalePct round-trips on the account and a device; an invalid value repairs to the default")
unittest {
    UserPreferences p;
    p.chatScalePct = 125;
    const r = UserPreferences.fromJson(p.toJson());
    assert(!r.needsRepair);
    assert(r.prefs.chatScalePct == 125);

    DeviceProfile d;
    d.chatScalePct = 125;
    bool dBad;
    const rd = DeviceProfile.fromJson(d.toJson(), dBad);
    assert(!dBad);
    assert(rd.chatScalePct == 125);

    auto j = Json.emptyObject;
    j["chatScalePct"] = Json(7);
    const s = UserPreferences.fromJson(j);
    assert(s.needsRepair);
    assert(s.prefs.chatScalePct == 100);

    bool bad;
    const sd = DeviceProfile.fromJson(j, bad);
    assert(bad);
    assert(sd.chatScalePct == 100);
}

@("language round-trips; legacy blobs follow the browser; unknown codes repair to automatic")
unittest {
    UserPreferences p;
    p.language = "de";
    const r = UserPreferences.fromJson(p.toJson());
    assert(!r.needsRepair && r.prefs.language == "de");

    auto legacy = Json.emptyObject;
    legacy["pinnedChannels"] = serializeToJson(["net1:#a"]);
    const l = UserPreferences.fromJson(legacy);
    assert(l.needsRepair, "a v1 blob migrates its notification policy");
    assert(l.prefs.language == "");

    auto bad = Json.emptyObject;
    bad["language"] = Json("xx");
    const b = UserPreferences.fromJson(bad);
    assert(b.needsRepair && b.prefs.language == "");
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
    j = Json.emptyObject;
    j["chatScalePct"] = Json(80);
    assert(checkDisplayPrefsPatch(j, any) == "" && any);
    j["chatScalePct"] = Json(115);
    assert(checkDisplayPrefsPatch(j, any) == "" && any);
    j["chatScalePct"] = Json(140);
    assert(checkDisplayPrefsPatch(j, any) == "" && any);
    j["chatScalePct"] = Json(75);
    assert(checkDisplayPrefsPatch(j, any) == "chatScalePct must be an integer from 80 to 140 in steps of 5");
    j["chatScalePct"] = Json(145);
    assert(checkDisplayPrefsPatch(j, any).length);
    j["chatScalePct"] = Json(112);
    assert(checkDisplayPrefsPatch(j, any).length);
    j["chatScalePct"] = Json(1.1);
    assert(checkDisplayPrefsPatch(j, any).length);
    j["chatScalePct"] = Json("110");
    assert(checkDisplayPrefsPatch(j, any).length);
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
    assert(p.chatScalePct == 100, "absent key keeps the default");
    patch = Json.emptyObject;
    patch["chatScalePct"] = Json(130);
    applyDisplayPrefsPatch(p, patch);
    assert(p.chatScalePct == 130);
}

@("sanitizeClientPrefs migrates a legacy fontSize to textSize and flags repair")
unittest {
    auto stored = Json.emptyObject;
    stored["fontSize"] = Json(17);
    bool bad;
    const clean = sanitizeClientPrefs(stored, bad);
    assert(bad);
    assert(clean.length == 1 && clean["textSize"].get!string == "xl");
}

@("checkTextDefaultsPatch validates admin org text defaults; empty/0 mean unset")
unittest {
    bool any;
    auto j = Json.emptyObject;
    j["textSize"] = Json("");
    assert(checkTextDefaultsPatch(j, any) == "" && any);
    any = false;
    j = Json.emptyObject;
    j["textSize"] = Json("xl");
    assert(checkTextDefaultsPatch(j, any) == "" && any);
    any = false;
    j = Json.emptyObject;
    j["chatScalePct"] = Json(0);
    assert(checkTextDefaultsPatch(j, any) == "" && any);
    any = false;
    j = Json.emptyObject;
    j["chatScalePct"] = Json(110);
    assert(checkTextDefaultsPatch(j, any) == "" && any);
    j = Json.emptyObject;
    j["textSize"] = Json("huge");
    assert(checkTextDefaultsPatch(j, any).length);
    j = Json.emptyObject;
    j["chatScalePct"] = Json(115.0);
    assert(checkTextDefaultsPatch(j, any).length);
    j = Json.emptyObject;
    j["chatScalePct"] = Json(150);
    assert(checkTextDefaultsPatch(j, any).length);
    assert(checkTextDefaultsPatch(Json.emptyArray, any) == "body must be object");
    any = false;
    assert(checkTextDefaultsPatch(Json.emptyObject, any) == "" && !any);
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
    d1.tz = "Europe/Berlin";
    d1.modeIndicator = "symbols";
    d1.timestampFormat = "24h";
    d1.model = "iPhone17,1";
    d1.createdAt = 1;
    d1.updatedAt = 2;
    d1.lastSeenAt = 3;
    DeviceProfile d2;
    d2.showMemberPrefixes = true;
    d2.tz = "America/Los_Angeles";
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
    p.timestampFormat = "12h";
    bool changed;
    auto prof = ensureDeviceProfile(p, id, "iPhone17,1", now, changed);
    assert(changed);
    assert(!prof.showUserIcons && prof.timestampFormat == "12h");
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
    assert(prof.tz == "", "no timezone until the app sends one");
    prof = ensureDeviceProfile(p, id, "", now + 2 * 3_600_000, changed, "", "", "", DEVICE_KIND_APP, "", "Europe/Berlin");
    assert(changed && prof.tz == "Europe/Berlin");
    prof = ensureDeviceProfile(p, id, "", now + 2 * 3_600_000, changed, "", "", "", DEVICE_KIND_APP, "", "");
    assert(!changed && prof.tz == "Europe/Berlin", "a request without a timezone keeps the stored one");
    bool changedNew;
    auto other = ensureDeviceProfile(p, "99999999-2222-4333-8444-555555555555", "", now, changedNew,
        "", "", "", DEVICE_KIND_APP, "", "Asia/Tokyo");
    assert(changedNew && other.tz == "Asia/Tokyo", "a new profile stores the timezone it was created with");
}

@("ensureDeviceProfile updates osVersion, appVersion and lastIp independently of model")
unittest {
    enum id = "22222222-3333-4444-8555-666666666666";
    enum long now = 1_800_000_000_000;
    UserPreferences p;
    bool changed;
    auto prof = ensureDeviceProfile(p, id, "iPhone17,1", now, changed, "18.1", "1.0.0 (1)", "203.0.113.5");
    assert(changed);
    assert(prof.model == "iPhone17,1");
    assert(prof.osVersion == "18.1" && prof.appVersion == "1.0.0 (1)" && prof.lastIp == "203.0.113.5");

    // A request 10 minutes later with no change writes nothing.
    prof = ensureDeviceProfile(p, id, "iPhone17,1", now + 10 * 60_000, changed, "18.1", "1.0.0 (1)", "203.0.113.5");
    assert(!changed, "a request with nothing new writes nothing");

    // OS version alone changes — model, app version and IP untouched.
    prof = ensureDeviceProfile(p, id, "iPhone17,1", now + 10 * 60_000, changed, "18.2", "1.0.0 (1)", "203.0.113.5");
    assert(changed && prof.osVersion == "18.2");
    assert(prof.model == "iPhone17,1" && prof.appVersion == "1.0.0 (1)" && prof.lastIp == "203.0.113.5");

    // App version alone changes.
    prof = ensureDeviceProfile(p, id, "iPhone17,1", now + 10 * 60_000, changed, "18.2", "1.1.0 (2)", "203.0.113.5");
    assert(changed && prof.appVersion == "1.1.0 (2)");
    assert(prof.osVersion == "18.2" && prof.lastIp == "203.0.113.5");

    // IP alone changes.
    prof = ensureDeviceProfile(p, id, "iPhone17,1", now + 10 * 60_000, changed, "18.2", "1.1.0 (2)", "198.51.100.9");
    assert(changed && prof.lastIp == "198.51.100.9");
    assert(prof.osVersion == "18.2" && prof.appVersion == "1.1.0 (2)");
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
    auto cp = Json.emptyObject;
    cp["snoozeUntil"] = Json(-1);
    applyClientPatch(p.notificationPolicy, "00000001-0000-4000-8000-000000000000", cp);
    const rev = p.notificationPolicy.rev;
    bool changed;
    ensureDeviceProfile(p, "ffffffff-0000-4000-8000-000000000000", "", 100, changed);
    assert(changed && p.devices.length == MAX_DEVICE_PROFILES);
    assert("00000001-0000-4000-8000-000000000000" !in p.devices);
    assert("00000002-0000-4000-8000-000000000000" in p.devices);
    assert("ffffffff-0000-4000-8000-000000000000" in p.devices);
    assert("00000001-0000-4000-8000-000000000000" !in p.notificationPolicy.clients,
        "the dropped profile's notification overrides go with it");
    assert(p.notificationPolicy.rev == rev + 1);
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
    prof.showMemberPrefixes = true;
    // The v1 per-device mute and sound are now client overrides in the policy.
    auto notif = parseJsonString(`{"cells":{"dm.sound":false},"snoozeUntil":-1}`);
    string field;
    assert(validateClientPatch(id, notif, field) == "");
    applyClientPatch(p.notificationPolicy, id, notif);
    assert(!prof.showUserIcons);
    assert(p.showUserIcons && !p.showMemberPrefixes, "the web's settings are untouched");
    assert(projMuteAll(p.notificationPolicy, id, 1000) && !projMuteAll(p.notificationPolicy, "", 1000));
    assert(resolveCell(p.notificationPolicy, id, NotifyClass.dm, Transport.sound) == false);
    assert(resolveCell(p.notificationPolicy, CLIENT_WEB, NotifyClass.dm, Transport.sound) == true);
    assert(!displayPrefsJson(*prof)["showUserIcons"].get!bool && displayPrefsJson(p)["showUserIcons"].get!bool);
    const np = notificationPrefsJson(p, id, 1000);
    assert(np["muteAll"].get!bool && np["notificationSound"].get!bool, "other classes still push with sound");
    assert(!notificationPrefsJson(p, "", 1000)["muteAll"].get!bool);

    const web = accountProfile(p);
    copySettings(*prof, web);
    assert(prof.showUserIcons && !prof.showMemberPrefixes);
    assert(prof.model == "iPad16,3" && prof.createdAt == 1000, "a reset keeps the device's identity");
}

@("checkClientPrefsPatch: per-kind validation, null deletes, unknown keys ignored, any flag")
unittest {
    bool any;
    string field;
    assert(checkClientPrefsPatch(Json.emptyArray, any, field) == "body must be object");
    assert(checkClientPrefsPatch(Json("x"), any, field) == "body must be object");

    Json one(string key, Json v) {
        auto j = Json.emptyObject;
        j[key] = v;
        return j;
    }
    string err(string key, Json v) {
        bool a;
        string f;
        const e = checkClientPrefsPatch(one(key, v), a, f);
        assert(a, "a recognised key sets any");
        assert(e.length == 0 || f == key, "the error names its field");
        return e;
    }
    // bool
    assert(err("compactMode", Json(true)) == "");
    assert(err("compactMode", Json(1)) == "compactMode must be boolean");
    // enum
    foreach (theme; ["dark", "light", "gruvbox", "monokai"])
        assert(err("theme", Json(theme)) == "");
    foreach (theme; ["midnight", "dusk", "tropic", "emerald", "sand", "orchid"])
        assert(err("theme", Json(theme)).length);
    assert(err("theme", Json(true)).length);
    assert(err("theme", Json(1)).length);
    assert(err("linkPreviewSize", Json("large")) == "");
    // int range, inclusive bounds
    assert(err("defaultScrollPreset", Json(0)) == "" && err("defaultScrollPreset", Json(4)) == "");
    assert(err("defaultScrollPreset", Json(-1)) == "defaultScrollPreset must be an integer from 0 to 4");
    assert(err("defaultScrollPreset", Json(5)).length);
    assert(err("defaultScrollPreset", Json(2.5)).length, "a float is not an integer");
    assert(err("defaultScrollPreset", Json("2")).length);
    // intEnum
    assert(err("awayAfterMinutes", Json(30)) == "");
    assert(err("awayAfterMinutes", Json(10)) == "awayAfterMinutes must be one of 5, 15, 30, 60");
    assert(err("awayAfterMinutes", Json("15")).length);
    // null is valid for any key (it deletes it)
    assert(err("theme", Json(null)) == "");

    auto unknown = Json.emptyObject;
    unknown["inlineTweets"] = Json(true);
    unknown["customCSS"] = Json("body{display:none}");
    assert(checkClientPrefsPatch(unknown, any, field) == "" && !any, "unknown keys alone are not a client pref");
    unknown["inlineImages"] = Json(false);
    assert(checkClientPrefsPatch(unknown, any, field) == "" && any);
}

@("applyClientPrefsPatch sets and deletes keys into a new object, ignoring unknown keys")
unittest {
    auto base = Json.emptyObject;
    base["theme"] = Json("gruvbox");
    base["textSize"] = Json("s");
    Json prefs = base;
    auto patch = Json.emptyObject;
    patch["textSize"] = Json(null);
    patch["compactMode"] = Json(true);
    patch["inlineTweets"] = Json(true);
    patch["customCSS"] = Json("body{display:none}");
    applyClientPrefsPatch(prefs, patch);
    assert(prefs["theme"].get!string == "gruvbox");
    assert("textSize" !in prefs, "null deletes the key");
    assert(prefs["compactMode"].get!bool);
    assert("inlineTweets" !in prefs);
    assert("customCSS" !in prefs);
    assert(base["textSize"].get!string == "s" && "compactMode" !in base, "the old object is untouched");
    applyClientPrefsPatch(prefs, parseJsonString(`{"theme":null}`));
    assert("theme" !in prefs && base["theme"].get!string == "gruvbox");
}

@("clientPrefs round-trip on the account and a device; bad stored keys are dropped and flag a repair")
unittest {
    enum id = "11111111-2222-4333-8444-555555555555";
    UserPreferences p;
    auto cp = Json.emptyObject;
    cp["theme"] = Json("light");
    cp["awayAfterMinutes"] = Json(60);
    p.clientPrefs = cp;
    DeviceProfile d;
    d.kind = DEVICE_KIND_WEB;
    d.name = "Work laptop";
    d.autoName = "Chrome on macOS";
    auto dcp = Json.emptyObject;
    dcp["compactMode"] = Json(true);
    d.clientPrefs = dcp;
    d.clientPrefsSet = true;
    p.devices[id] = d;
    const r = UserPreferences.fromJson(p.toJson());
    assert(!r.needsRepair);
    assert(r.prefs.clientPrefs == cp);
    assert(r.prefs.devices[id] == d);
    // Legacy blobs: no clientPrefs anywhere, devices are apps without client prefs.
    auto legacyDev = d.toJson();
    foreach (k; ["kind", "name", "autoName", "clientPrefs", "clientPrefsSet"]) legacyDev.remove(k);
    auto legacyDevs = Json.emptyObject;
    legacyDevs[id] = legacyDev;
    auto legacy = Json.emptyObject;
    legacy["devices"] = legacyDevs;
    legacy["notificationPolicy"] = defaultPolicy().toJson();   // not a v1 notification blob
    const l = UserPreferences.fromJson(legacy);
    assert(!l.needsRepair && l.prefs.clientPrefs.length == 0);
    assert(l.prefs.devices[id].kind == DEVICE_KIND_APP && !l.prefs.devices[id].clientPrefsSet);
    assert(l.prefs.devices[id].clientPrefs.type == Json.Type.object && l.prefs.devices[id].clientPrefs.length == 0);

    auto badCp = Json.emptyObject;
    badCp["theme"] = Json("sand");
    badCp["textSize"] = Json("l");
    badCp["inlineTweets"] = Json(true);
    badCp["customCSS"] = Json("body{display:none}");
    auto j = Json.emptyObject;
    j["clientPrefs"] = badCp;
    const s = UserPreferences.fromJson(j);
    assert(s.needsRepair);
    assert(s.prefs.clientPrefs.length == 1 && s.prefs.clientPrefs["textSize"].get!string == "l");
    j["clientPrefs"] = Json.emptyArray;
    const t = UserPreferences.fromJson(j);
    assert(t.needsRepair && t.prefs.clientPrefs.type == Json.Type.object && t.prefs.clientPrefs.length == 0);

    auto devJ = d.toJson();
    devJ["clientPrefs"] = badCp;
    devJ["kind"] = Json("tablet");
    devJ["name"] = Json("bad\x01name");
    devJ["clientPrefsSet"] = Json("yes");
    bool bad;
    const dd = DeviceProfile.fromJson(devJ, bad);
    assert(bad);
    assert(dd.clientPrefs.length == 1 && dd.clientPrefs["textSize"].get!string == "l");
    assert(dd.kind == DEVICE_KIND_APP && dd.name == "" && !dd.clientPrefsSet);
    assert(dd.autoName == "Chrome on macOS");
}

@("ensureDeviceProfile seeds clientPrefs from the account, stores kind/autoName, refreshes autoName only")
unittest {
    enum id = "33333333-4444-4555-8666-777777777777";
    enum long now = 1_800_000_000_000;
    UserPreferences p;
    auto cp = Json.emptyObject;
    cp["theme"] = Json("monokai");
    p.clientPrefs = cp;
    bool changed;
    auto prof = ensureDeviceProfile(p, id, "", now, changed, "", "", "", DEVICE_KIND_WEB, "Firefox on Linux");
    assert(changed);
    assert(prof.kind == DEVICE_KIND_WEB && prof.autoName == "Firefox on Linux");
    assert(prof.clientPrefs == cp && !prof.clientPrefsSet);
    auto patch = Json.emptyObject;
    patch["theme"] = Json("gruvbox");
    applyClientPrefsPatch(prof.clientPrefs, patch);
    assert(p.clientPrefs["theme"].get!string == "monokai", "the seed is a copy, not shared");

    prof = ensureDeviceProfile(p, id, "", now + 60_000, changed, "", "", "", DEVICE_KIND_WEB, "Firefox on Linux");
    assert(!changed, "the same autoName writes nothing");
    prof = ensureDeviceProfile(p, id, "", now + 60_000, changed, "", "", "", DEVICE_KIND_APP, "");
    assert(!changed && prof.autoName == "Firefox on Linux" && prof.kind == DEVICE_KIND_WEB,
        "an absent name keeps the stored one and kind never changes");
    prof = ensureDeviceProfile(p, id, "", now + 60_000, changed, "", "", "", DEVICE_KIND_WEB, "Firefox on Windows");
    assert(changed && prof.autoName == "Firefox on Windows");

    prof = ensureDeviceProfile(p, "44444444-4444-4555-8666-777777777777", "", now, changed);
    assert(prof.kind == DEVICE_KIND_APP, "a header-less kind is an app");
    prof = ensureDeviceProfile(p, "55555555-4444-4555-8666-777777777777", "", now, changed, "", "", "", "tablet");
    assert(prof.kind == DEVICE_KIND_APP, "an unknown kind is an app");
}

@("ensureDeviceProfile evicts the least recently seen web profile before an older app profile")
unittest {
    import std.format : format;

    UserPreferences p;
    foreach (i; 1 .. MAX_DEVICE_PROFILES + 1) {
        DeviceProfile d;
        d.lastSeenAt = i;
        d.kind = i == 1 ? DEVICE_KIND_APP : DEVICE_KIND_WEB;
        p.devices[format("%08x-0000-4000-8000-000000000000", i)] = d;
    }
    bool changed;
    ensureDeviceProfile(p, "ffffffff-0000-4000-8000-000000000000", "", 100, changed, "", "", "", DEVICE_KIND_WEB);
    assert(changed && p.devices.length == MAX_DEVICE_PROFILES);
    assert("00000001-0000-4000-8000-000000000000" in p.devices, "the oldest app profile survives");
    assert("00000002-0000-4000-8000-000000000000" !in p.devices, "the oldest web profile goes");
    assert("ffffffff-0000-4000-8000-000000000000" in p.devices);
}

@("reset and make-defaults copy clientPrefs and the device settings both ways")
unittest {
    enum id = "11111111-2222-4333-8444-555555555555";
    UserPreferences p;
    auto acct = Json.emptyObject;
    acct["theme"] = Json("light");
    p.clientPrefs = acct;
    bool changed;
    auto prof = ensureDeviceProfile(p, id, "", 1000, changed, "", "", "", DEVICE_KIND_WEB, "Safari on macOS");
    auto devPrefs = Json.emptyObject;
    devPrefs["textSize"] = Json("l");
    devPrefs["theme"] = Json("monokai");
    prof.chatScalePct = 130;
    prof.clientPrefs = devPrefs;
    prof.showUserIcons = false;
    prof.monospaceFont = false;
    prof.name = "Desk";

    makeAccountDefaults(p, *prof);
    assert(p.clientPrefs == devPrefs && !p.showUserIcons && !p.monospaceFont && p.displayPrefsSet);
    assert(p.chatScalePct == 130, "makeAccountDefaults copies chatScalePct via DEVICE_SETTINGS");
    auto patch = Json.emptyObject;
    patch["textSize"] = Json("xl");
    applyClientPrefsPatch(prof.clientPrefs, patch);
    assert(p.clientPrefs["textSize"].get!string == "l", "the defaults are a copy");

    p.showUserIcons = true;
    resetDeviceToAccount(*prof, p);
    assert(prof.clientPrefs == devPrefs && prof.showUserIcons && !prof.monospaceFont);
    assert(prof.clientPrefsSet, "a reset device takes the server's client prefs");
    assert(prof.name == "Desk" && prof.kind == DEVICE_KIND_WEB && prof.createdAt == 1000,
        "a reset keeps the device's identity");
}

@("isDeviceName/normalizeDeviceName: 1–64 trimmed bytes of UTF-8 without control characters")
unittest {
    import std.array : replicate;

    assert(isDeviceName("Chrome on macOS"));
    assert(isDeviceName("Café iPad ☕"));
    assert(isDeviceName(replicate("a", 64)));
    assert(!isDeviceName(replicate("a", 65)));
    assert(!isDeviceName(""));
    assert(!isDeviceName("   "));
    assert(!isDeviceName("tab\there"));
    assert(!isDeviceName("del\x7f"));
    assert(!isDeviceName("\xff\xfe"), "invalid UTF-8");
    assert(normalizeDeviceName("  Chrome on macOS ") == "Chrome on macOS");
    assert(normalizeDeviceName(" \t ") == "");
    assert(normalizeDeviceName("a\nb") == "");
    assert(normalizeDeviceName(replicate("a", 65)) == "");
    assert(normalizeDeviceKind("web") == DEVICE_KIND_WEB);
    assert(normalizeDeviceKind("app") == DEVICE_KIND_APP && normalizeDeviceKind("") == DEVICE_KIND_APP
        && normalizeDeviceKind("WEB") == DEVICE_KIND_APP);
}

@("a device's push mute and sound: its own client override, else the account's")
unittest {
    enum muted = "11111111-2222-4333-8444-555555555555";
    enum silent = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    enum long now = 1_800_000_000_000;
    UserPreferences p;
    p.devices[muted] = DeviceProfile.init;
    p.devices[silent] = DeviceProfile.init;
    applyClientPatch(p.notificationPolicy, muted, parseJsonString(`{"snoozeUntil":-1}`));
    applyClientPatch(p.notificationPolicy, silent, parseJsonString(`{"cells":{"dm.sound":false}}`));
    const pol = &p.notificationPolicy;
    bool muteOf(string id) { return snoozeActive(snoozeOf(*pol, id), now); }
    bool soundOf(string id) { return resolveCell(*pol, id, NotifyClass.dm, Transport.sound); }
    assert(muteOf(muted) && soundOf(muted));
    assert(!muteOf(silent) && !soundOf(silent));
    assert(!muteOf("bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee") && soundOf("bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        "an install without overrides follows the account");
    p.notificationPolicy.snoozeUntil = -1;
    assert(muteOf(silent), "the account's snooze reaches a device without its own");
    applyClientPatch(p.notificationPolicy, silent, parseJsonString(`{"snoozeUntil":0}`));
    assert(!muteOf(silent), "a device snooze of 0 beats the account's");
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
    // The iOS Simulator's exact suffix only, once, on a valid base.
    assert(isDeviceModel("iPhone17,1 (Simulator)"));
    assert(isDeviceModel(replicate("a", 20) ~ " (Simulator)"));
    assert(!isDeviceModel(replicate("a", 21) ~ " (Simulator)"));
    assert(!isDeviceModel(" (Simulator)"));
    assert(!isDeviceModel("iPhone17,1 (simulator)"));
    assert(!isDeviceModel("iPhone17,1 (Simulator) (Simulator)"));
    assert(!isDeviceModel("iPhone17,1 (Simulator)\r\n"));
    assert(!isDeviceModel("iPhone17,1 (Emulator)"));
}

@("a v1 blob migrates its notification prefs to the policy and asks for one save")
unittest {
    enum dev = "11111111-2222-4333-8444-555555555555";
    auto v1 = parseJsonString(`{"desktopNotifications":false,"notificationSound":true,"autoDismissNotifs":true,
        "muteAll":true,"highlightWords":["deploy"],
        "bufferPrefs":{"n1:_server":{"mute":true},"n1:#chan":{"notifyAll":true}},
        "devices":{"` ~ dev ~ `":{"muteAll":true,"notificationSound":false,"model":"iPhone17,1"}}}`);
    const r = UserPreferences.fromJson(v1);
    assert(r.needsRepair, "the migrated blob is saved on the same load");
    const pol = &r.prefs.notificationPolicy;
    assert(pol.matrix[NotifyClass.notice] == Cells(false, true, false, false));
    assert(pol.matrix[NotifyClass.dm] == Cells(false, true, true, false));
    assert(pol.snoozeUntil == -1);
    assert(pol.clients[dev].hasSnooze && pol.clients[dev].snoozeUntil == -1);
    assert(pol.clients[dev].cells["dm.sound"] == false);
    assert(pol.networks["n1"] == "muted");
    assert("n1:_server" !in r.prefs.bufferPrefs && "n1:#chan" in r.prefs.bufferPrefs);
    assert(pol.highlight.words == [HighlightWord("deploy", false)]);
    assert(pol.presentation.coalesceSec == 0 && pol.migratedAt > 0);
    assert(r.prefs.devices[dev].model == "iPhone17,1");

    // The saved blob is v2: it loads without another migration, and keeps the
    // v1 projections for an older gateway.
    const j = r.prefs.toJson();
    assert(!j["desktopNotifications"].get!bool && j["notificationSound"].get!bool && j["muteAll"].get!bool);
    assert(j["devices"][dev]["muteAll"].get!bool && j["devices"][dev]["notificationSound"].get!bool == false);
    assert(j["highlightWords"] == parseJsonString(`["deploy"]`));
    assert("autoDismissNotifs" !in j, "the legacy expiry flag is ignored, not projected back");
    const again = UserPreferences.fromJson(j);
    assert(!again.needsRepair && again.prefs.notificationPolicy.migratedAt == pol.migratedAt);
}

@("a v2 blob round-trips byte-identical through toJson")
unittest {
    enum dev = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    UserPreferences p;
    DeviceProfile d;
    d.model = "Pixel9";
    d.tz = "America/Los_Angeles";
    p.devices[dev] = d;
    p.bufferPrefs["n1:#chan"] = parseJsonString(`{"notifyAll":true,"nAt":5}`);
    p.notificationPolicy.snoozeUntil = -1;
    p.notificationPolicy.networks["n1"] = "all";
    p.notificationPolicy.highlight.words = [HighlightWord("outage", true)];
    applyClientPatch(p.notificationPolicy, dev, parseJsonString(`{"cells":{"all.mobile":true},"snoozeUntil":0}`));
    applyClientPatch(p.notificationPolicy, CLIENT_WEB, parseJsonString(`{"cells":{"mention.sound":false}}`));
    bumpPolicyRev(p);
    assert(p.notificationPolicy.rev == 2);
    const first = p.toJson().toString();
    const r = UserPreferences.fromJson(parseJsonString(first));
    assert(!r.needsRepair);
    assert(r.prefs.toJson().toString() == first);
    assert(r.prefs.devices[dev].tz == "America/Los_Angeles");
}

@("fromJson prunes notification overrides of devices without a profile")
unittest {
    enum kept = "11111111-2222-4333-8444-555555555555";
    enum gone = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    UserPreferences p;
    p.devices[kept] = DeviceProfile.init;
    applyClientPatch(p.notificationPolicy, kept, parseJsonString(`{"snoozeUntil":-1}`));
    applyClientPatch(p.notificationPolicy, gone, parseJsonString(`{"snoozeUntil":-1}`));
    applyClientPatch(p.notificationPolicy, CLIENT_WEB, parseJsonString(`{"snoozeUntil":-1}`));
    const r = UserPreferences.fromJson(p.toJson());
    assert(r.needsRepair);
    assert(kept in r.prefs.notificationPolicy.clients && CLIENT_WEB in r.prefs.notificationPolicy.clients);
    assert(gone !in r.prefs.notificationPolicy.clients);
    assert(!UserPreferences.fromJson(r.prefs.toJson()).needsRepair);
}

@("device timezones: isDeviceTz and the stored DeviceProfile.tz")
unittest {
    assert(isDeviceTz("Europe/Berlin") && isDeviceTz("Etc/GMT-3") && !isDeviceTz("") && !isDeviceTz("Europe/Berlin\n"));
    auto j = DeviceProfile.init.toJson();
    j["tz"] = Json("not a zone");
    bool bad;
    const d = DeviceProfile.fromJson(j, bad);
    assert(bad && d.tz == "");
    j["tz"] = Json("Asia/Tokyo");
    bool bad2;
    assert(DeviceProfile.fromJson(j, bad2).tz == "Asia/Tokyo" && !bad2);
}

@("welcomeTour: legacy blobs and explicit null stay null without a repair; tours round-trip")
unittest {
    // A legacy account's stored blob has no welcomeTour key at all.
    auto legacy = UserPreferences.init.toJson();
    assert(legacy["welcomeTour"].type == Json.Type.null_, "an un-enrolled account serializes null");
    legacy.remove("welcomeTour");
    const r0 = UserPreferences.fromJson(legacy);
    assert(r0.prefs.welcomeTour.isNull, "a legacy account must never be enrolled by a load");
    assert(welcomeTourJson(r0.prefs).type == Json.Type.null_);
    assert(!UserPreferences.fromJson(UserPreferences.init.toJson()).needsRepair);

    foreach (status; [WELCOME_TOUR_PENDING, WELCOME_TOUR_COMPLETED, WELCOME_TOUR_SKIPPED]) {
        UserPreferences p;
        p.welcomeTour = WelcomeTour(WELCOME_TOUR_VERSION, 4, status);
        const first = p.toJson().toString();
        const r = UserPreferences.fromJson(parseJsonString(first));
        assert(!r.needsRepair);
        assert(!r.prefs.welcomeTour.isNull);
        assert(r.prefs.welcomeTour.get.step == 4 && r.prefs.welcomeTour.get.status == status);
        assert(r.prefs.welcomeTour.get.version_ == WELCOME_TOUR_VERSION);
        assert(r.prefs.toJson().toString() == first, "a tour must survive a reload unchanged");
        auto wire = welcomeTourJson(r.prefs);
        assert(wire["version"].get!long == 1 && wire["step"].get!long == 4 && wire["status"].get!string == status);
    }
}

@("welcomeTour: a malformed stored tour loads as null and flags a repair")
unittest {
    foreach (bad; [`[]`, `"pending"`, `{}`, `{"step":2,"status":"pending"}`,
            `{"version":0,"step":2,"status":"pending"}`, `{"version":1,"step":7,"status":"pending"}`,
            `{"version":1,"step":-1,"status":"pending"}`, `{"version":1,"step":"2","status":"pending"}`,
            `{"version":1,"step":2.5,"status":"pending"}`, `{"version":1,"step":2,"status":"done"}`,
            `{"version":1,"step":2}`]) {
        auto j = UserPreferences.init.toJson();
        j["welcomeTour"] = parseJsonString(bad);
        const r = UserPreferences.fromJson(j);
        assert(r.needsRepair, bad);
        assert(r.prefs.welcomeTour.isNull, bad);
        assert(!UserPreferences.fromJson(r.prefs.toJson()).needsRepair, "the repaired blob is clean: " ~ bad);
    }
}

@("enrollWelcomeTour: a new account starts pending at step 0; an existing tour is never reset")
unittest {
    UserPreferences p;
    assert(enrollWelcomeTour(p));
    assert(!p.welcomeTour.isNull);
    assert(p.welcomeTour.get == WelcomeTour(WELCOME_TOUR_VERSION, 0, WELCOME_TOUR_PENDING));
    assert(!enrollWelcomeTour(p), "enrolling twice changes nothing");

    p.welcomeTour = WelcomeTour(WELCOME_TOUR_VERSION, 6, WELCOME_TOUR_COMPLETED);
    assert(!enrollWelcomeTour(p));
    assert(p.welcomeTour.get.status == WELCOME_TOUR_COMPLETED && p.welcomeTour.get.step == 6);
}

@("parseWelcomeTourUpdate: integer step 0..6 and a known status, else a 400 text")
unittest {
    WelcomeTour u;
    foreach (bad; [`[]`, `null`, `"x"`, `{}`, `{"status":"pending"}`, `{"step":0}`,
            `{"step":-1,"status":"pending"}`, `{"step":7,"status":"pending"}`, `{"step":2.0,"status":"pending"}`,
            `{"step":"2","status":"pending"}`, `{"step":true,"status":"pending"}`, `{"step":null,"status":"pending"}`,
            `{"step":2,"status":"PENDING"}`, `{"step":2,"status":"done"}`, `{"step":2,"status":1}`,
            `{"step":2,"status":null}`, `{"step":99999999999999999999,"status":"pending"}`]) {
        assert(parseWelcomeTourUpdate(parseJsonString(bad), u).length, bad);
    }
    assert(parseWelcomeTourUpdate(parseJsonString(`{"step":3,"status":"pending","extra":1}`), u) == "");
    assert(u.step == 3 && u.status == WELCOME_TOUR_PENDING);
    assert(parseWelcomeTourUpdate(parseJsonString(`{"step":0,"status":"skipped"}`), u) == "");
    assert(u.step == 0 && u.status == WELCOME_TOUR_SKIPPED);
    assert(parseWelcomeTourUpdate(parseJsonString(`{"step":6,"status":"completed"}`), u) == "");
    assert(u.step == 6 && u.status == WELCOME_TOUR_COMPLETED);
}

@("applyWelcomeTourUpdate: only a pending tour moves; finished tours and legacy accounts never change")
unittest {
    // Legacy account: no save enrolls it, finishing or not.
    UserPreferences legacy;
    assert(!applyWelcomeTourUpdate(legacy, WelcomeTour(1, 2, WELCOME_TOUR_PENDING)));
    assert(!applyWelcomeTourUpdate(legacy, WelcomeTour(1, 6, WELCOME_TOUR_COMPLETED)));
    assert(legacy.welcomeTour.isNull);

    UserPreferences p;
    enrollWelcomeTour(p);
    assert(applyWelcomeTourUpdate(p, WelcomeTour(1, 3, WELCOME_TOUR_PENDING)));
    assert(p.welcomeTour.get.step == 3 && p.welcomeTour.get.status == WELCOME_TOUR_PENDING);
    assert(!applyWelcomeTourUpdate(p, WelcomeTour(1, 3, WELCOME_TOUR_PENDING)), "a repeat is not a change");
    assert(applyWelcomeTourUpdate(p, WelcomeTour(1, 1, WELCOME_TOUR_PENDING)), "going back is allowed");
    assert(applyWelcomeTourUpdate(p, WelcomeTour(1, 6, WELCOME_TOUR_COMPLETED)));

    // Late pending saves (sent before finishing, delivered after) and a replay's saves.
    assert(!applyWelcomeTourUpdate(p, WelcomeTour(1, 5, WELCOME_TOUR_PENDING)));
    assert(!applyWelcomeTourUpdate(p, WelcomeTour(1, 0, WELCOME_TOUR_PENDING)));
    assert(!applyWelcomeTourUpdate(p, WelcomeTour(1, 2, WELCOME_TOUR_SKIPPED)));
    assert(p.welcomeTour.get == WelcomeTour(WELCOME_TOUR_VERSION, 6, WELCOME_TOUR_COMPLETED));

    UserPreferences s;
    enrollWelcomeTour(s);
    assert(applyWelcomeTourUpdate(s, WelcomeTour(1, 2, WELCOME_TOUR_SKIPPED)));
    assert(!applyWelcomeTourUpdate(s, WelcomeTour(1, 6, WELCOME_TOUR_COMPLETED)));
    assert(!applyWelcomeTourUpdate(s, WelcomeTour(1, 3, WELCOME_TOUR_PENDING)));
    assert(s.welcomeTour.get == WelcomeTour(WELCOME_TOUR_VERSION, 2, WELCOME_TOUR_SKIPPED));
}

@("prefsRepo: stale full saves from independently cached repositories never reopen or erase a tour")
unittest {
    // Requires local Redis (same gate as the atomicity test above).
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
        redis.ping();
    } catch (Exception e) {
        logWarn("Skipping welcome tour persistence test: Redis unavailable (%s)", e.msg);
        return;
    }

    auto userId = randomUUID();
    auto userId2 = randomUUID();
    auto legacyId = randomUUID();
    string key = "prefs:" ~ userId.toString();
    string key2 = "prefs:" ~ userId2.toString();
    string legacyKey = "prefs:" ~ legacyId.toString();
    void cleanup() {
        foreach (k; [key, key2, legacyKey]) {
            try redis.getDb().del(k);
            catch (Exception) {}
        }
    }
    cleanup();
    scope (exit) cleanup();

    // Two processes (or gateway colours): independent caches over one Redis.
    auto a = new PreferencesRepository(redis, new PrefsCache());
    auto b = new PreferencesRepository(redis, new PrefsCache());
    WelcomeTour stored() {
        const p = new PreferencesRepository(redis, new PrefsCache()).load(userId, true);
        assert(!p.welcomeTour.isNull, "a stored tour must never be erased");
        return p.welcomeTour.get;
    }
    const completed = WelcomeTour(WELCOME_TOUR_VERSION, 6, WELCOME_TOUR_COMPLETED);

    assert(a.createWithWelcomeTour(userId, (ref UserPreferences p) { p.language = "de"; }, () => true));
    assert(stored() == WelcomeTour.init && b.load(userId).language == "de");
    // b now caches the pending tour, then a finishes it.
    const staleCopy = b.load(userId);
    const done = a.mutate(userId, (ref UserPreferences p) {
        return applyWelcomeTourUpdate(p, completed);
    });
    assert(done > 0);

    // b's unrelated save carries its stale pending tour: the field it changed
    // lands, the finished tour is kept, and b's cache learns it.
    const pinVersion = b.mutate(userId, (ref UserPreferences p) { p.pinnedChannels ~= "n1:#a"; });
    assert(pinVersion > done, "the stale save still writes (and reports a positive version)");
    assert(stored() == completed);
    assert(new PreferencesRepository(redis, new PrefsCache()).load(userId, true).pinnedChannels == ["n1:#a"]);
    assert(b.load(userId).welcomeTour.get == completed, "the saving process's cache must match Redis");

    // A late pending tour save, decided on a stale copy, cannot reopen it either.
    auto stalePending = UserPreferences.fromJson(staleCopy.toJson()).prefs;
    assert(applyWelcomeTourUpdate(stalePending, WelcomeTour(1, 4, WELCOME_TOUR_PENDING)));
    assert(b.save(userId, stalePending) > 0);
    assert(stored() == completed);
    // Nor can a stale blob without a tour, or one finishing it differently.
    b.save(userId, UserPreferences.init);
    assert(stored() == completed);
    auto skipped = UserPreferences.init;
    skipped.welcomeTour = WelcomeTour(WELCOME_TOUR_VERSION, 2, WELCOME_TOUR_SKIPPED);
    b.save(userId, skipped);
    assert(stored() == completed);
    assert(b.mutate(userId, (ref UserPreferences p) {
        return applyWelcomeTourUpdate(p, WelcomeTour(1, 3, WELCOME_TOUR_PENDING));
    }) == 0);
    assert(stored() == completed);

    // A pending tour progresses normally, but a blob without one cannot erase it.
    assert(a.createWithWelcomeTour(userId2, null, () => true));
    auto progressed = UserPreferences.init;
    progressed.welcomeTour = WelcomeTour(WELCOME_TOUR_VERSION, 3, WELCOME_TOUR_PENDING);
    b.save(userId2, progressed);
    b.save(userId2, UserPreferences.init);
    const p2 = new PreferencesRepository(redis, new PrefsCache()).load(userId2, true);
    assert(!p2.welcomeTour.isNull && p2.welcomeTour.get == WelcomeTour(WELCOME_TOUR_VERSION, 3, WELCOME_TOUR_PENDING));

    // A legacy account (blob without the key) stays without a tour.
    redis.getDb().set(legacyKey, `{"prefVersion":5,"pinnedChannels":[]}`);
    b.save(legacyId, UserPreferences.init);
    assert(new PreferencesRepository(redis, new PrefsCache()).load(legacyId, true).welcomeTour.isNull);
}

@("createWithWelcomeTour: a lost or failed insert leaves no preferences behind")
unittest {
    // Requires local Redis (same gate as the atomicity test above).
    RedisStorage redis;
    try {
        redis = new RedisStorage();
        redis.connect();
        redis.ping();
    } catch (Exception e) {
        logWarn("Skipping createWithWelcomeTour test: Redis unavailable (%s)", e.msg);
        return;
    }
    auto lost = randomUUID();
    auto failed = randomUUID();
    auto repo = new PreferencesRepository(redis, new PrefsCache());

    assert(!repo.createWithWelcomeTour(lost, null, () => false));
    assert(!redis.exists("prefs:" ~ lost.toString()), "a duplicate-key loser must not leave preferences");
    assert(repo.load(lost).welcomeTour.isNull, "nor a cached copy");

    bool threw;
    try repo.createWithWelcomeTour(failed, null, delegate bool() {
        throw new Exception("insert failed");
    });
    catch (Exception) threw = true;
    assert(threw, "an insert failure must reach the caller");
    assert(!redis.exists("prefs:" ~ failed.toString()));
}

@("keepStoredWelcomeTour: null never replaces a tour; a finished tour is final")
unittest {
    const pending = WelcomeTour(1, 2, WELCOME_TOUR_PENDING);
    const done = WelcomeTour(1, 6, WELCOME_TOUR_COMPLETED);
    Nullable!WelcomeTour t;
    assert(keepStoredWelcomeTour(t, pending) && t.get == pending);
    t.nullify();
    assert(keepStoredWelcomeTour(t, done) && t.get == done);
    t = WelcomeTour(1, 4, WELCOME_TOUR_PENDING);
    assert(!keepStoredWelcomeTour(t, pending) && t.get.step == 4, "a pending tour progresses");
    t = WelcomeTour(1, 6, WELCOME_TOUR_COMPLETED);
    assert(!keepStoredWelcomeTour(t, pending), "a pending tour can finish");
    assert(!keepStoredWelcomeTour(t, done), "an identical finished tour is no change");
    t = WelcomeTour(1, 4, WELCOME_TOUR_PENDING);
    assert(keepStoredWelcomeTour(t, done) && t.get == done);
    t = WelcomeTour(1, 2, WELCOME_TOUR_SKIPPED);
    assert(keepStoredWelcomeTour(t, done) && t.get == done, "the first finish wins");
}
