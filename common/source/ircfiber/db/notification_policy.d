module ircfiber.db.notification_policy;

/// Notification Policy v2: the stored per-account policy (classes × transports
/// matrix, snooze, quiet hours, highlight words, presentation, email cadence,
/// network levels and per-client overrides), its JSON form, merge-patch
/// validation, v1 migration and the v1 projections old clients still read.
///
/// Pure: no I/O, no timezone resolution (the gateway resolves `quiet.tz`; the
/// format check here keeps tzdata out of the engine). Stored inside the
/// preferences blob as `UserPreferences.notificationPolicy`.
///
/// Maps (`networks`, `clients`, `ClientOverride.cells`) and arrays are replaced,
/// never mutated in place: struct copies (the prefs cache hands them out) share them.
import std.algorithm.searching : canFind;
import std.algorithm.sorting : sort;
import std.string : strip;
import std.uni : icmp;
import vibe.data.json;

import ircfiber.db.preferences : MAX_HIGHLIGHT_WORDS, MAX_HIGHLIGHT_WORD_BYTES, MAX_DEVICE_PROFILES,
    normalizeHighlightWords, isDeviceId;

/// Notification classes, in wire order (`CLASS_NAMES`).
enum NotifyClass : ubyte { dm, mention, all, invite, notice, wallops }
/// Delivery transports, in wire order (`TRANSPORT_NAMES`).
enum Transport : ubyte { desktop, sound, mobile, email }

/// Wire names of `NotifyClass`, indexed by it.
immutable string[6] CLASS_NAMES = ["dm", "mention", "all", "invite", "notice", "wallops"];
/// Wire names of `Transport`, indexed by it.
immutable string[4] TRANSPORT_NAMES = ["desktop", "sound", "mobile", "email"];

/// Most quiet-hours windows per policy.
enum MAX_QUIET_WINDOWS = 14;
/// Most breakthrough VIP nicks, and the longest one in bytes.
enum MAX_VIP = 50;
enum MAX_VIP_BYTES = 64;
/// `clients` keys: `web` plus one per device profile.
enum MAX_CLIENTS = 1 + MAX_DEVICE_PROFILES;
/// The `clients` key of every browser.
enum CLIENT_WEB = "web";
/// The target of email delivery; it has no overrides.
enum TARGET_ACCOUNT = "account";

/// Allowed values of the string and integer enumerations.
immutable string[] TZ_MODES = ["account", "device"];
immutable string[] PREVIEW_LEVELS = ["full", "sender", "none"];
immutable long[] COALESCE_SECONDS = [0, 30, 120];
immutable string[] EMAIL_MODES = ["delay15", "delay60", "daily"];
immutable long[] REPEAT_SECONDS = [0, 180];
/// `networks` values; an absent key is the default ("mentions").
immutable string[] NETWORK_LEVELS = ["all", "muted"];

/// One matrix row: whether each transport delivers this class.
struct Cells {
    bool desktop, sound, mobile, email;
}

/// A quiet-hours window in local time. It belongs to its start day: when
/// `startMin > endMin` it crosses midnight into the next day. `endMin` may be
/// 1440 (`"24:00"`) only when `startMin < endMin`.
struct QuietWindow {
    /// 0 = Monday … 6 = Sunday; non-empty, unique.
    ubyte[] days;
    ushort startMin;
    ushort endMin;
}

/// A highlight word; `urgent` words break through quiet hours.
struct HighlightWord {
    string w;
    bool urgent;
}

/// One client's overrides of the account policy (`clients[<target>]`).
struct ClientOverride {
    /// `"<cls>.<transport>"` → value, only for columns the client owns.
    bool[string] cells;
    /// Whether `snoozeUntil` overrides the account's (0 = explicitly not snoozed).
    bool hasSnooze;
    long snoozeUntil;
}

/// Quiet-hours breakthrough rules.
struct QuietBreakthrough {
    string[] vip;
    int repeatSec = 180;
    bool urgentWords = true;
}

/// Quiet hours.
struct QuietHours {
    bool enabled;
    /// Account IANA timezone; "" until set (required when `enabled`).
    string tz;
    /// `account`, or `device`: app installs use their own timezone.
    string tzMode = "account";
    QuietWindow[] windows = [QuietWindow([0, 1, 2, 3, 4, 5, 6], 22 * 60, 8 * 60)];
    QuietBreakthrough breakthrough;
    /// Send one summary when a window ends.
    bool summary = true;
}

/// Highlight words and how they match.
struct HighlightSettings {
    HighlightWord[] words;
    bool wholeWord = true;
    bool caseSensitive = false;
}

/// How alerts look.
struct Presentation {
    string preview = "full";
    int coalesceSec = 30;
}

/// Email cadence.
struct EmailSettings {
    string mode = "delay15";
    int dailyHour = 8;
}

/// A server-defined matrix preset (desktop, sound and mobile; never email).
struct Preset {
    string name;
    Cells[6] cells;
}

private Cells c3(string t) pure {
    return Cells(t[0] == '1', t[1] == '1', t[2] == '1', false);
}

/// The presets, in display order. Applying one leaves the email column alone.
immutable Preset[3] PRESETS = [
    Preset("everything", [c3("111"), c3("111"), c3("111"), c3("111"), c3("111"), c3("101")]),
    Preset("focused", [c3("111"), c3("111"), c3("100"), c3("101"), c3("000"), c3("000")]),
    Preset("quiet", [c3("101"), c3("100"), c3("000"), c3("000"), c3("000"), c3("000")]),
];

/// A server-defined quiet-hours template.
struct QuietTemplate {
    string name;
    QuietWindow[] windows;
}

private enum ubyte[] WEEKDAYS_AND_SUNDAY = [0, 1, 2, 3, 6];

/// The quiet-hours templates, in display order.
immutable QuietTemplate[3] QUIET_TEMPLATES = [
    QuietTemplate("nights", [QuietWindow([0, 1, 2, 3, 4, 5, 6], 22 * 60, 8 * 60)]),
    QuietTemplate("nightsWeekends", [QuietWindow(WEEKDAYS_AND_SUNDAY, 22 * 60, 8 * 60),
        QuietWindow([4], 22 * 60, 1440), QuietWindow([5, 6], 0, 1440)]),
    QuietTemplate("offHours", [QuietWindow(WEEKDAYS_AND_SUNDAY, 18 * 60, 9 * 60),
        QuietWindow([4], 18 * 60, 1440), QuietWindow([5, 6], 0, 1440)]),
];

/// The stored policy (`UserPreferences.notificationPolicy`). `init` is the
/// new-account default (`defaultPolicy`).
struct NotificationPolicy {
    /// Format version; always 2.
    int v = 2;
    /// Bumped by every policy change; the If-Match token (`"np-<rev>"`).
    long rev = 1;
    /// Indexed by `NotifyClass`. Default: the `focused` preset, email off.
    Cells[6] matrix = PRESETS[1].cells;
    /// Account snooze: 0 = off, -1 = until resumed, else unix ms.
    long snoozeUntil;
    QuietHours quiet;
    HighlightSettings highlight;
    Presentation presentation;
    EmailSettings email;
    /// networkId → `all` or `muted`.
    string[string] networks;
    /// `web` or a lower-case install id → overrides.
    ClientOverride[string] clients;
    /// Unix ms of the v1 migration; 0 for accounts created on v2.
    long migratedAt;
    bool bannerDismissed;

    /// Serializes every field; empty arrays as `[]`, map keys sorted.
    Json toJson() const {
        auto j = Json.emptyObject;
        j["v"] = Json(2);
        j["rev"] = Json(rev);
        j["matrix"] = matrixJson(matrix, true);
        j["snoozeUntil"] = Json(snoozeUntil);
        auto q = Json.emptyObject;
        q["enabled"] = Json(quiet.enabled);
        q["tz"] = Json(quiet.tz);
        q["tzMode"] = Json(quiet.tzMode);
        q["windows"] = windowsJson(quiet.windows);
        auto bt = Json.emptyObject;
        auto vip = Json.emptyArray;
        foreach (n; quiet.breakthrough.vip) vip ~= Json(n);
        bt["vip"] = vip;
        bt["repeatSec"] = Json(quiet.breakthrough.repeatSec);
        bt["urgentWords"] = Json(quiet.breakthrough.urgentWords);
        q["breakthrough"] = bt;
        q["summary"] = Json(quiet.summary);
        j["quiet"] = q;
        auto h = Json.emptyObject;
        auto words = Json.emptyArray;
        foreach (ref w; highlight.words) {
            auto o = Json.emptyObject;
            o["w"] = Json(w.w);
            o["urgent"] = Json(w.urgent);
            words ~= o;
        }
        h["words"] = words;
        h["wholeWord"] = Json(highlight.wholeWord);
        h["caseSensitive"] = Json(highlight.caseSensitive);
        j["highlight"] = h;
        auto pr = Json.emptyObject;
        pr["preview"] = Json(presentation.preview);
        pr["coalesceSec"] = Json(presentation.coalesceSec);
        j["presentation"] = pr;
        auto em = Json.emptyObject;
        em["mode"] = Json(email.mode);
        em["dailyHour"] = Json(email.dailyHour);
        j["email"] = em;
        auto nets = Json.emptyObject;
        foreach (k; sortedKeys(networks)) nets[k] = Json(networks[k]);
        j["networks"] = nets;
        auto cl = Json.emptyObject;
        foreach (k; sortedKeys(clients)) cl[k] = clientJson(clients[k]);
        j["clients"] = cl;
        j["migratedAt"] = Json(migratedAt);
        j["bannerDismissed"] = Json(bannerDismissed);
        return j;
    }

    /// Decodes a stored policy. A present field of the wrong type or value keeps
    /// its default and sets `repair`; missing fields keep their defaults; `{}`
    /// where an array is expected is an empty array (Redis cjson writes `[]` as
    /// `{}`) and does not set `repair`.
    static NotificationPolicy fromJson(Json j, out bool repair) {
        auto p = defaultPolicy();
        if (j.type != Json.Type.object) {
            repair = true;
            return p;
        }
        if (auto v = "v" in j)
            if (v.type != Json.Type.int_ || v.get!long != 2) repair = true;
        if (auto v = "rev" in j) {
            if (v.type == Json.Type.int_ && v.get!long >= 1) p.rev = v.get!long;
            else repair = true;
        }
        if (auto m = "matrix" in j) {
            if (m.type != Json.Type.object) {
                repair = true;
            } else {
                foreach (ci, cname; CLASS_NAMES) {
                    auto row = cname in *m;
                    if (row is null) continue;
                    if (row.type != Json.Type.object) {
                        repair = true;
                        continue;
                    }
                    foreach (ti, tname; TRANSPORT_NAMES) {
                        auto cell = tname in *row;
                        if (cell is null) continue;
                        if (cell.type != Json.Type.bool_) {
                            repair = true;
                            continue;
                        }
                        const on = cell.get!bool;
                        if (on && ti == Transport.email && !emailOffered(cast(NotifyClass) ci)) {
                            repair = true;
                            continue;
                        }
                        setCell(p.matrix[ci], cast(Transport) ti, on);
                    }
                }
            }
        }
        readSnooze(j, "snoozeUntil", p.snoozeUntil, repair);
        if (auto q = "quiet" in j) {
            if (q.type != Json.Type.object) {
                repair = true;
            } else {
                readBool(*q, "enabled", p.quiet.enabled, repair);
                if (auto v = "tz" in *q) {
                    if (v.type == Json.Type.string && (v.get!string.length == 0 || isTzName(v.get!string)))
                        p.quiet.tz = v.get!string;
                    else
                        repair = true;
                }
                readEnum(*q, "tzMode", TZ_MODES, p.quiet.tzMode, repair);
                if (auto v = "windows" in *q) {
                    Json[] items;
                    QuietWindow[] ws;
                    if (!arrayItems(*v, items)) {
                        repair = true;
                    } else {
                        foreach (item; items) {
                            QuietWindow w;
                            if (parseWindow(item, w)) ws ~= w;
                            else repair = true;
                        }
                        if (ws.length > MAX_QUIET_WINDOWS) {
                            ws = ws[0 .. MAX_QUIET_WINDOWS];
                            repair = true;
                        }
                        if (ws.length) p.quiet.windows = ws;
                        else repair = true;
                    }
                }
                if (auto b = "breakthrough" in *q) {
                    if (b.type != Json.Type.object) {
                        repair = true;
                    } else {
                        if (auto v = "vip" in *b) {
                            Json[] items;
                            if (!arrayItems(*v, items)) {
                                repair = true;
                            } else {
                                bool bad;
                                p.quiet.breakthrough.vip = normalizeVip(items, bad);
                                if (bad) repair = true;
                            }
                        }
                        readIntIn(*b, "repeatSec", REPEAT_SECONDS, p.quiet.breakthrough.repeatSec, repair);
                        readBool(*b, "urgentWords", p.quiet.breakthrough.urgentWords, repair);
                    }
                }
                readBool(*q, "summary", p.quiet.summary, repair);
            }
        }
        if (auto h = "highlight" in j) {
            if (h.type != Json.Type.object) {
                repair = true;
            } else {
                if (auto v = "words" in *h) {
                    Json[] items;
                    if (!arrayItems(*v, items)) {
                        repair = true;
                    } else {
                        bool bad;
                        p.highlight.words = normalizeWordObjects(items, bad);
                        if (bad) repair = true;
                    }
                }
                readBool(*h, "wholeWord", p.highlight.wholeWord, repair);
                readBool(*h, "caseSensitive", p.highlight.caseSensitive, repair);
            }
        }
        if (auto pr = "presentation" in j) {
            if (pr.type != Json.Type.object) {
                repair = true;
            } else {
                readEnum(*pr, "preview", PREVIEW_LEVELS, p.presentation.preview, repair);
                readIntIn(*pr, "coalesceSec", COALESCE_SECONDS, p.presentation.coalesceSec, repair);
            }
        }
        if (auto em = "email" in j) {
            if (em.type != Json.Type.object) {
                repair = true;
            } else {
                readEnum(*em, "mode", EMAIL_MODES, p.email.mode, repair);
                if (auto v = "dailyHour" in *em) {
                    if (v.type == Json.Type.int_ && v.get!long >= 0 && v.get!long <= 23)
                        p.email.dailyHour = cast(int) v.get!long;
                    else
                        repair = true;
                }
            }
        }
        if (auto n = "networks" in j) {
            if (n.type != Json.Type.object) {
                repair = true;
            } else {
                foreach (string nid, lv; *n) {
                    if (nid.length && lv.type == Json.Type.string && NETWORK_LEVELS.canFind(lv.get!string))
                        p.networks[nid] = lv.get!string;
                    else
                        repair = true;
                }
            }
        }
        if (auto c = "clients" in j) {
            if (c.type != Json.Type.object) {
                repair = true;
            } else {
                foreach (string key, entry; *c) {
                    ClientOverride o;
                    if (!isClientKey(key) || !parseClient(key, entry, o)) {
                        repair = true;
                        continue;
                    }
                    if (!o.cells.length && !o.hasSnooze) {
                        repair = true;
                        continue;
                    }
                    p.clients[key] = o;
                }
                if (p.clients.length > MAX_CLIENTS) repair = true;   // the caller prunes orphans
            }
        }
        if (auto v = "migratedAt" in j) {
            if (v.type == Json.Type.int_ && v.get!long >= 0) p.migratedAt = v.get!long;
            else repair = true;
        }
        readBool(j, "bannerDismissed", p.bannerDismissed, repair);
        return p;
    }
}

/// The new-account policy (`NotificationPolicy.init` with its own arrays).
NotificationPolicy defaultPolicy() pure {
    NotificationPolicy p;
    p.quiet.windows = templateWindows("nights");
    return p;
}

/// A fresh copy of template `name`'s windows; empty for an unknown name.
QuietWindow[] templateWindows(string name) pure {
    foreach (ref t; QUIET_TEMPLATES) {
        if (t.name != name) continue;
        QuietWindow[] out_;
        foreach (ref w; t.windows) out_ ~= QuietWindow(w.days.dup, w.startMin, w.endMin);
        return out_;
    }
    return null;
}

/// Whether email delivery is offered for `cls` (only DMs and mentions).
bool emailOffered(NotifyClass cls) @safe pure nothrow @nogc {
    return cls == NotifyClass.dm || cls == NotifyClass.mention;
}

/// The column a target delivers on: `web` → desktop, `account` → email, an install → mobile.
Transport deliveryColumn(string target) @safe pure nothrow @nogc {
    if (target == CLIENT_WEB) return Transport.desktop;
    if (target == TARGET_ACCOUNT) return Transport.email;
    return Transport.mobile;
}

/// Whether a client override on `target` may set column `t`: `web` owns desktop
/// and sound, an install owns mobile and sound; `account` owns nothing.
bool ownsColumn(string target, Transport t) @safe pure nothrow @nogc {
    if (target == TARGET_ACCOUNT || target.length == 0) return false;
    if (t == Transport.sound) return true;
    return t == (target == CLIENT_WEB ? Transport.desktop : Transport.mobile);
}

/// `NotifyClass` for a wire name.
bool parseClass(string s, out NotifyClass cls) @safe pure nothrow @nogc {
    foreach (i, n; CLASS_NAMES) {
        if (n == s) {
            cls = cast(NotifyClass) i;
            return true;
        }
    }
    return false;
}

/// `Transport` for a wire name.
bool parseTransport(string s, out Transport t) @safe pure nothrow @nogc {
    foreach (i, n; TRANSPORT_NAMES) {
        if (n == s) {
            t = cast(Transport) i;
            return true;
        }
    }
    return false;
}

/// A `"<cls>.<transport>"` cell key.
string cellKey(NotifyClass cls, Transport t) @safe pure nothrow {
    return CLASS_NAMES[cls] ~ "." ~ TRANSPORT_NAMES[t];
}

/// Parses a `"<cls>.<transport>"` cell key.
bool parseCellKey(string key, out NotifyClass cls, out Transport t) @safe pure nothrow @nogc {
    foreach (i; 0 .. key.length) {
        if (key[i] == '.')
            return parseClass(key[0 .. i], cls) && parseTransport(key[i + 1 .. $], t);
    }
    return false;
}

/// One cell of a matrix row.
bool cellOf(const Cells c, Transport t) @safe pure nothrow @nogc {
    final switch (t) {
        case Transport.desktop: return c.desktop;
        case Transport.sound: return c.sound;
        case Transport.mobile: return c.mobile;
        case Transport.email: return c.email;
    }
}

/// Sets one cell of a matrix row.
void setCell(ref Cells c, Transport t, bool on) @safe pure nothrow @nogc {
    final switch (t) {
        case Transport.desktop: c.desktop = on; break;
        case Transport.sound: c.sound = on; break;
        case Transport.mobile: c.mobile = on; break;
        case Transport.email: c.email = on; break;
    }
}

/// `clients[target].cells["<cls>.<transport>"]` when set, else the account matrix.
bool resolveCell(const ref NotificationPolicy p, string target, NotifyClass cls, Transport t) {
    if (auto o = target in p.clients)
        if (auto v = cellKey(cls, t) in o.cells)
            return *v;
    return cellOf(p.matrix[cls], t);
}

/// The snooze `target` follows: its own override when set, else the account's.
long snoozeOf(const ref NotificationPolicy p, string target) {
    if (auto o = target in p.clients)
        if (o.hasSnooze) return o.snoozeUntil;
    return p.snoozeUntil;
}

/// Whether a `snoozeUntil` value is in effect at `nowMs` (-1 = until resumed).
bool snoozeActive(long snoozeUntil, long nowMs) @safe pure nothrow @nogc {
    return snoozeUntil == -1 || snoozeUntil > nowMs;
}

/// The preset whose desktop, sound and mobile cells all equal the account
/// matrix, else `"custom"`. Email never counts.
string matchPreset(const ref NotificationPolicy p) @safe pure nothrow @nogc {
    foreach (ref pr; PRESETS) {
        bool same = true;
        foreach (i; 0 .. 6) {
            const a = p.matrix[i], b = pr.cells[i];
            if (a.desktop != b.desktop || a.sound != b.sound || a.mobile != b.mobile) {
                same = false;
                break;
            }
        }
        if (same) return pr.name;
    }
    return "custom";
}

/// `{"<preset>": {"<cls>": {desktop, sound, mobile}}}` for GET responses.
Json presetsJson() {
    auto j = Json.emptyObject;
    foreach (ref pr; PRESETS) j[pr.name] = matrixJson(pr.cells, false);
    return j;
}

/// `{"<template>": [windows]}` for GET responses.
Json quietTemplatesJson() {
    auto j = Json.emptyObject;
    foreach (ref t; QUIET_TEMPLATES) j[t.name] = windowsJson(t.windows);
    return j;
}

// ── v1 projections ────────────────────────────────────────────────────────
// What v1 clients (old app builds, an older gateway reading the blob) see.
// `target` "" is the account view, else an install id.

/// `desktopNotifications`: some class delivers to web desktop.
bool projDesktop(const ref NotificationPolicy p) {
    foreach (i; 0 .. 6)
        if (resolveCell(p, CLIENT_WEB, cast(NotifyClass) i, Transport.desktop)) return true;
    return false;
}

/// `notificationSound`: account view, some class has sound on; device view,
/// some class pushes to that device with sound.
bool projSound(const ref NotificationPolicy p, string target) {
    foreach (i; 0 .. 6) {
        const cls = cast(NotifyClass) i;
        if (!target.length) {
            if (p.matrix[i].sound) return true;
        } else if (resolveCell(p, target, cls, Transport.mobile) && resolveCell(p, target, cls, Transport.sound)) {
            return true;
        }
    }
    return false;
}

/// `muteAll`: the account's (or that device's effective) snooze is active.
bool projMuteAll(const ref NotificationPolicy p, string target, long nowMs) {
    return snoozeActive(target.length ? snoozeOf(p, target) : p.snoozeUntil, nowMs);
}

/// `highlightWords`: the words without their urgency.
string[] projHighlightWords(const ref NotificationPolicy p) {
    string[] out_;
    foreach (ref w; p.highlight.words) out_ ~= w.w;
    return out_;
}

// ── v1 migration ──────────────────────────────────────────────────────────

/// The policy of a stored v1 blob (one without `notificationPolicy`). Reads
/// the flat `desktopNotifications` (D), `notificationSound` (S), `muteAll` (M),
/// `highlightWords` and the raw
/// `devices` entries; moves `mute`/`notifyAll` of each `"<nid>:_server"` entry
/// of `bufferPrefs` into `networks` (dropping the entry when nothing else is left).
///
/// A device with `muteAll: true` gets the client snooze -1. One with
/// `muteAll: false` under an account-wide mute (M) gets the client snooze 0:
/// v1 pushes followed only the device's own mute, so that install keeps getting
/// pushes. One whose `notificationSound` differs from S gets that sound for every class.
NotificationPolicy migrateFromV1(Json rawBlob, long nowMs, ref Json[string] bufferPrefs) {
    auto p = defaultPolicy();
    const D = flag(rawBlob, "desktopNotifications", true);
    const S = flag(rawBlob, "notificationSound", true);
    const M = flag(rawBlob, "muteAll", false);
    foreach (i; 0 .. 6) {
        const pushes = i != NotifyClass.notice && i != NotifyClass.wallops;
        p.matrix[i] = Cells(D, S, pushes, false);
    }
    p.snoozeUntil = M ? -1 : 0;
    p.presentation = Presentation("full", 0);
    if (rawBlob.type == Json.Type.object)
        if (auto hw = "highlightWords" in rawBlob) {
            auto words = normalizeHighlightWords(*hw);
            if (words.length > MAX_HIGHLIGHT_WORDS) words = words[0 .. MAX_HIGHLIGHT_WORDS];
            foreach (w; words) p.highlight.words ~= HighlightWord(w, false);
        }

    enum SERVER_SUFFIX = ":_server";
    string[] serverKeys;
    foreach (k, _; bufferPrefs)
        if (k.length > SERVER_SUFFIX.length && k[$ - SERVER_SUFFIX.length .. $] == SERVER_SUFFIX) serverKeys ~= k;
    foreach (k; serverKeys) {
        auto entry = bufferPrefs[k];
        const nid = k[0 .. $ - SERVER_SUFFIX.length];
        if (entry.type != Json.Type.object) continue;
        if (flag(entry, "mute", false)) p.networks[nid] = "muted";
        else if (flag(entry, "notifyAll", false)) p.networks[nid] = "all";
        auto rest = Json.emptyObject;
        foreach (string key, v; entry)
            if (key != "mute" && key != "notifyAll") rest[key] = v;
        if (rest.length) bufferPrefs[k] = rest;
        else bufferPrefs.remove(k);
    }

    if (rawBlob.type == Json.Type.object)
        if (auto devs = "devices" in rawBlob)
            if (devs.type == Json.Type.object)
                foreach (string id, d; *devs) {
                    if (d.type != Json.Type.object || !isClientKey(id) || id == CLIENT_WEB) continue;
                    ClientOverride o;
                    if (auto m = "muteAll" in d)
                        if (m.type == Json.Type.bool_ && (m.get!bool || M)) {
                            o.hasSnooze = true;
                            o.snoozeUntil = m.get!bool ? -1 : 0;
                        }
                    if (auto s = "notificationSound" in d)
                        if (s.type == Json.Type.bool_ && s.get!bool != S)
                            foreach (i; 0 .. 6) o.cells[cellKey(cast(NotifyClass) i, Transport.sound)] = s.get!bool;
                    if (o.hasSnooze || o.cells.length) p.clients[id] = o;
                }
    p.migratedAt = nowMs;
    return p;
}

// ── PATCH /api/me/notification-policy ─────────────────────────────────────

/// Validates an RFC 7396 merge-patch of the stored policy (plus `applyPreset`)
/// without applying it. Returns "" when valid, else the error code with the
/// offending dotted path in `field`:
/// `bad_request` (not a non-empty object), `field_not_patchable` (`clients`,
/// `rev`, `v`, `migratedAt`), `unknown_field`, `invalid_value`,
/// `email_not_offered`, `invalid_timezone`. JSON null is accepted only for
/// `networks.<nid>` (it deletes that override). Cross-field rules
/// (`checkPolicy`) are checked on the result.
string validatePatch(Json patch, out string field) {
    if (patch.type != Json.Type.object || patch.length == 0) return "bad_request";
    foreach (string key, v; patch) {
        field = key;
        switch (key) {
            case "clients", "rev", "v", "migratedAt":
                return "field_not_patchable";
            case "applyPreset":
                if (v.type != Json.Type.string || presetIndex(v.get!string) < 0) return "invalid_value";
                if ("matrix" in patch) return "invalid_value";
                break;
            case "matrix": {
                const err = checkMatrixPatch(v, field);
                if (err.length) return err;
                break;
            }
            case "snoozeUntil":
                if (v.type != Json.Type.int_ || v.get!long < -1) return "invalid_value";
                break;
            case "quiet": {
                const err = checkQuietPatch(v, field);
                if (err.length) return err;
                break;
            }
            case "highlight": {
                const err = checkHighlightPatch(v, field);
                if (err.length) return err;
                break;
            }
            case "presentation":
                if (v.type != Json.Type.object) return "invalid_value";
                foreach (string k, x; v) {
                    field = "presentation." ~ k;
                    if (k == "preview") {
                        if (x.type != Json.Type.string || !PREVIEW_LEVELS.canFind(x.get!string)) return "invalid_value";
                    } else if (k == "coalesceSec") {
                        if (x.type != Json.Type.int_ || !COALESCE_SECONDS.canFind(x.get!long)) return "invalid_value";
                    } else {
                        return "unknown_field";
                    }
                }
                break;
            case "email":
                if (v.type != Json.Type.object) return "invalid_value";
                foreach (string k, x; v) {
                    field = "email." ~ k;
                    if (k == "mode") {
                        if (x.type != Json.Type.string || !EMAIL_MODES.canFind(x.get!string)) return "invalid_value";
                    } else if (k == "dailyHour") {
                        if (x.type != Json.Type.int_ || x.get!long < 0 || x.get!long > 23) return "invalid_value";
                    } else {
                        return "unknown_field";
                    }
                }
                break;
            case "networks":
                if (v.type != Json.Type.object) return "invalid_value";
                foreach (string nid, x; v) {
                    field = "networks." ~ nid;
                    if (!nid.length) return "invalid_value";
                    if (x.type == Json.Type.null_) continue;
                    if (x.type != Json.Type.string || !NETWORK_LEVELS.canFind(x.get!string)) return "invalid_value";
                }
                break;
            case "bannerDismissed":
                if (v.type != Json.Type.bool_) return "invalid_value";
                break;
            default:
                return "unknown_field";
        }
    }
    field = "";
    return "";
}

/// Rules spanning fields, checked on a policy after `applyPatch`: quiet hours
/// need a timezone (`invalid_timezone`, field `quiet.tz`). Returns "" when valid.
string checkPolicy(const ref NotificationPolicy p, out string field) {
    if (p.quiet.enabled && !p.quiet.tz.length) {
        field = "quiet.tz";
        return "invalid_timezone";
    }
    return "";
}

/// Applies a merge-patch that passed `validatePatch`: objects merge, arrays
/// replace (normalized), `networks.<nid>: null` deletes; `applyPreset` sets the
/// desktop, sound and mobile cells of every class and leaves email alone.
/// Does not bump `rev` (`bumpPolicyRev` does, with the prefs).
void applyPatch(ref NotificationPolicy p, Json patch) {
    if (auto v = "applyPreset" in patch) {
        const pr = PRESETS[presetIndex(v.get!string)];
        foreach (i; 0 .. 6) {
            p.matrix[i].desktop = pr.cells[i].desktop;
            p.matrix[i].sound = pr.cells[i].sound;
            p.matrix[i].mobile = pr.cells[i].mobile;
        }
    }
    if (auto m = "matrix" in patch)
        foreach (string cname, row; *m) {
            NotifyClass cls;
            parseClass(cname, cls);
            foreach (string tname, cell; row) {
                Transport t;
                parseTransport(tname, t);
                setCell(p.matrix[cls], t, cell.get!bool);
            }
        }
    if (auto v = "snoozeUntil" in patch) p.snoozeUntil = v.get!long;
    if (auto q = "quiet" in patch) {
        if (auto v = "enabled" in *q) p.quiet.enabled = v.get!bool;
        if (auto v = "tz" in *q) p.quiet.tz = v.get!string;
        if (auto v = "tzMode" in *q) p.quiet.tzMode = v.get!string;
        if (auto v = "windows" in *q) {
            QuietWindow[] ws;
            foreach (item; *v) {
                QuietWindow w;
                parseWindow(item, w);
                ws ~= w;
            }
            p.quiet.windows = ws;
        }
        if (auto b = "breakthrough" in *q) {
            if (auto v = "vip" in *b) {
                bool bad;
                p.quiet.breakthrough.vip = normalizeVip(v.get!(Json[]), bad);
            }
            if (auto v = "repeatSec" in *b) p.quiet.breakthrough.repeatSec = cast(int) v.get!long;
            if (auto v = "urgentWords" in *b) p.quiet.breakthrough.urgentWords = v.get!bool;
        }
        if (auto v = "summary" in *q) p.quiet.summary = v.get!bool;
    }
    if (auto h = "highlight" in patch) {
        if (auto v = "words" in *h) {
            bool bad;
            p.highlight.words = normalizeWordObjects(v.get!(Json[]), bad);
        }
        if (auto v = "wholeWord" in *h) p.highlight.wholeWord = v.get!bool;
        if (auto v = "caseSensitive" in *h) p.highlight.caseSensitive = v.get!bool;
    }
    if (auto pr = "presentation" in patch) {
        if (auto v = "preview" in *pr) p.presentation.preview = v.get!string;
        if (auto v = "coalesceSec" in *pr) p.presentation.coalesceSec = cast(int) v.get!long;
    }
    if (auto em = "email" in patch) {
        if (auto v = "mode" in *em) p.email.mode = v.get!string;
        if (auto v = "dailyHour" in *em) p.email.dailyHour = cast(int) v.get!long;
    }
    if (auto n = "networks" in patch) {
        string[string] next;
        foreach (k, lv; p.networks) next[k] = lv;
        foreach (string nid, lv; *n) {
            if (lv.type == Json.Type.null_) next.remove(nid);
            else next[nid] = lv.get!string;
        }
        p.networks = next;
    }
    if (auto v = "bannerDismissed" in patch) p.bannerDismissed = v.get!bool;
}

// ── PATCH /api/me/notification-policy/clients/:ref ────────────────────────

/// Validates a client override patch `{"cells": {"<cls>.<transport>": bool|null},
/// "snoozeUntil": ms|-1|0|null}` for `target` (`web` or a lower-case install id;
/// the caller has checked the install exists). Returns "" when valid, else
/// `bad_request`, `client_not_found` (target is neither), `unknown_field`,
/// `invalid_value` or `override_not_owned` (a column the target does not own,
/// email included), with the dotted path in `field`.
string validateClientPatch(string target, Json patch, out string field) {
    if (patch.type != Json.Type.object || patch.length == 0) return "bad_request";
    if (!isClientKey(target)) return "client_not_found";
    foreach (string key, v; patch) {
        field = key;
        if (key == "cells") {
            if (v.type != Json.Type.object) return "invalid_value";
            foreach (string ck, x; v) {
                field = "cells." ~ ck;
                NotifyClass cls;
                Transport t;
                if (!parseCellKey(ck, cls, t)) return "invalid_value";
                if (!ownsColumn(target, t)) return "override_not_owned";
                if (x.type != Json.Type.bool_ && x.type != Json.Type.null_) return "invalid_value";
            }
        } else if (key == "snoozeUntil") {
            if (v.type == Json.Type.null_) continue;
            if (v.type != Json.Type.int_ || v.get!long < -1) return "invalid_value";
        } else {
            return "unknown_field";
        }
    }
    field = "";
    return "";
}

/// Applies a client patch that passed `validateClientPatch`: null deletes a
/// cell or the snooze override; an entry left empty is removed.
void applyClientPatch(ref NotificationPolicy p, string target, Json patch) {
    ClientOverride o;
    if (auto cur = target in p.clients) {
        foreach (k, v; cur.cells) o.cells[k] = v;
        o.hasSnooze = cur.hasSnooze;
        o.snoozeUntil = cur.snoozeUntil;
    }
    if (auto cells = "cells" in patch)
        foreach (string ck, x; *cells) {
            if (x.type == Json.Type.null_) o.cells.remove(ck);
            else o.cells[ck] = x.get!bool;
        }
    if (auto s = "snoozeUntil" in patch) {
        o.hasSnooze = s.type != Json.Type.null_;
        o.snoozeUntil = o.hasSnooze ? s.get!long : 0;
    }
    ClientOverride[string] next;
    foreach (k, v; p.clients)
        if (k != target) next[k] = v;
    if (o.cells.length || o.hasSnooze) next[target] = o;
    p.clients = next;
}

/// Removes `target`'s overrides; true when there were any.
bool removeClient(ref NotificationPolicy p, string target) {
    if (target !in p.clients) return false;
    ClientOverride[string] next;
    foreach (k, v; p.clients)
        if (k != target) next[k] = v;
    p.clients = next;
    return true;
}

// ── Formats ───────────────────────────────────────────────────────────────

/// Whether `s` has the shape of an IANA timezone name: 1–64 of `[A-Za-z0-9_+\-/]`.
/// Whether it resolves is the gateway's check.
bool isTzName(string s) @safe pure nothrow @nogc {
    if (s.length == 0 || s.length > 64) return false;
    foreach (char c; s) {
        const ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || c == '_' || c == '+' || c == '-' || c == '/';
        if (!ok) return false;
    }
    return true;
}

/// Parses `"HH:MM"` (00:00–23:59, or `"24:00"` when `allow24`) into minutes.
bool parseHhmm(string s, bool allow24, out ushort minutes) @safe pure nothrow @nogc {
    if (s.length != 5 || s[2] != ':') return false;
    foreach (i, c; s)
        if (i != 2 && (c < '0' || c > '9')) return false;
    const h = (s[0] - '0') * 10 + (s[1] - '0');
    const m = (s[3] - '0') * 10 + (s[4] - '0');
    if (m > 59) return false;
    if (h == 24 && m == 0 && allow24) {
        minutes = 1440;
        return true;
    }
    if (h > 23) return false;
    minutes = cast(ushort) (h * 60 + m);
    return true;
}

/// Minutes of the day as `"HH:MM"` (1440 → `"24:00"`).
string formatHhmm(ushort minutes) @safe pure nothrow {
    const h = minutes / 60, m = minutes % 60;
    return [cast(char) ('0' + h / 10), cast(char) ('0' + h % 10), ':',
        cast(char) ('0' + m / 10), cast(char) ('0' + m % 10)].idup;
}

/// Parses a window `{days, start, end}`; false when any rule of the contract fails.
bool parseWindow(Json j, out QuietWindow w) {
    if (j.type != Json.Type.object) return false;
    foreach (string k, _; j)
        if (k != "days" && k != "start" && k != "end") return false;
    auto days = "days" in j, start = "start" in j, end = "end" in j;
    if (days is null || start is null || end is null) return false;
    if (days.type != Json.Type.array || days.length == 0 || days.length > 7) return false;
    ubyte[] ds;
    foreach (d; *days) {
        if (d.type != Json.Type.int_ || d.get!long < 0 || d.get!long > 6) return false;
        const b = cast(ubyte) d.get!long;
        if (ds.canFind(b)) return false;
        ds ~= b;
    }
    if (start.type != Json.Type.string || end.type != Json.Type.string) return false;
    ushort s, e;
    if (!parseHhmm(start.get!string, false, s) || !parseHhmm(end.get!string, true, e)) return false;
    if (s == e || (e == 1440 && s > e)) return false;
    w = QuietWindow(ds, s, e);
    return true;
}

// ── private helpers ───────────────────────────────────────────────────────

private Json matrixJson(const Cells[6] m, bool withEmail) {
    auto j = Json.emptyObject;
    foreach (i, name; CLASS_NAMES) {
        auto row = Json.emptyObject;
        row["desktop"] = Json(m[i].desktop);
        row["sound"] = Json(m[i].sound);
        row["mobile"] = Json(m[i].mobile);
        if (withEmail) row["email"] = Json(m[i].email);
        j[name] = row;
    }
    return j;
}

private Json windowsJson(const QuietWindow[] ws) {
    auto arr = Json.emptyArray;
    foreach (ref w; ws) {
        auto o = Json.emptyObject;
        auto days = Json.emptyArray;
        foreach (d; w.days) days ~= Json(cast(int) d);
        o["days"] = days;
        o["start"] = Json(formatHhmm(w.startMin));
        o["end"] = Json(formatHhmm(w.endMin));
        arr ~= o;
    }
    return arr;
}

private Json clientJson(const ref ClientOverride o) {
    auto j = Json.emptyObject;
    auto cells = Json.emptyObject;
    foreach (k; sortedKeys(o.cells)) cells[k] = Json(o.cells[k]);
    j["cells"] = cells;
    if (o.hasSnooze) j["snoozeUntil"] = Json(o.snoozeUntil);
    return j;
}

private string[] sortedKeys(V)(const V[string] aa) {
    string[] keys;
    foreach (k, _; aa) keys ~= k;
    keys.sort();
    return keys;
}

/// `web` or a lower-case install id.
private bool isClientKey(string key) {
    import std.uni : toLower;

    return key == CLIENT_WEB || (isDeviceId(key) && key.toLower == key);
}

private bool parseClient(string key, Json j, out ClientOverride o) {
    if (j.type != Json.Type.object) return false;
    foreach (string k, v; j) {
        if (k == "cells") {
            if (v.type != Json.Type.object) return false;
            foreach (string ck, x; v) {
                NotifyClass cls;
                Transport t;
                if (!parseCellKey(ck, cls, t) || !ownsColumn(key, t) || x.type != Json.Type.bool_) return false;
                o.cells[ck] = x.get!bool;
            }
        } else if (k == "snoozeUntil") {
            if (v.type != Json.Type.int_ || v.get!long < -1) return false;
            o.hasSnooze = true;
            o.snoozeUntil = v.get!long;
        } else {
            return false;
        }
    }
    return true;
}

private int presetIndex(string name) @safe pure nothrow @nogc {
    foreach (i, ref pr; PRESETS)
        if (pr.name == name) return cast(int) i;
    return -1;
}

/// Array items of `v`; `{}` (a cjson-mangled `[]`) is empty. False for anything else.
private bool arrayItems(Json v, out Json[] items) {
    if (v.type == Json.Type.array) {
        items = v.get!(Json[]);
        return true;
    }
    return v.type == Json.Type.object && v.length == 0;
}

/// Trimmed, 1–`MAX_VIP_BYTES`-byte, case-insensitively unique nicks (first
/// spelling wins), at most `MAX_VIP`; anything dropped sets `bad`.
private string[] normalizeVip(const Json[] items, out bool bad) {
    string[] out_;
    foreach (item; items) {
        if (item.type != Json.Type.string) {
            bad = true;
            continue;
        }
        const n = item.get!string.strip;
        if (!n.length || n.length > MAX_VIP_BYTES) {
            bad = true;
            continue;
        }
        if (out_.canFind!((a, b) => icmp(a, b) == 0)(n)) continue;
        out_ ~= n;
    }
    if (out_.length > MAX_VIP) {
        out_ = out_[0 .. MAX_VIP];
        bad = true;
    }
    return out_;
}

/// `{w, urgent}` items normalized like `normalizeHighlightWords` (the first
/// spelling keeps its `urgent`), at most `MAX_HIGHLIGHT_WORDS`; anything
/// malformed or dropped (other than a duplicate) sets `bad`.
private HighlightWord[] normalizeWordObjects(const Json[] items, out bool bad) {
    auto raw = Json.emptyArray;
    bool[] urgent;
    string[] stripped;
    foreach (item; items) {
        if (item.type != Json.Type.object) {
            bad = true;
            continue;
        }
        auto w = "w" in item;
        if (w is null || w.type != Json.Type.string) {
            bad = true;
            continue;
        }
        bool u;
        if (auto x = "urgent" in item) {
            if (x.type == Json.Type.bool_) u = x.get!bool;
            else bad = true;
        }
        const s = w.get!string.strip;
        if (!s.length || s.length > MAX_HIGHLIGHT_WORD_BYTES) bad = true;
        raw ~= Json(s);
        stripped ~= s;
        urgent ~= u;
    }
    auto kept = normalizeHighlightWords(raw);
    if (kept.length > MAX_HIGHLIGHT_WORDS) {
        kept = kept[0 .. MAX_HIGHLIGHT_WORDS];
        bad = true;
    }
    HighlightWord[] out_;
    foreach (k; kept) {
        bool u;
        foreach (i, s; stripped)
            if (s == k) {
                u = urgent[i];
                break;
            }
        out_ ~= HighlightWord(k, u);
    }
    return out_;
}

private string checkMatrixPatch(Json v, ref string field) {
    if (v.type != Json.Type.object) return "invalid_value";
    foreach (string cname, row; v) {
        field = "matrix." ~ cname;
        NotifyClass cls;
        if (!parseClass(cname, cls)) return "unknown_field";
        if (row.type != Json.Type.object) return "invalid_value";
        foreach (string tname, cell; row) {
            field = "matrix." ~ cname ~ "." ~ tname;
            Transport t;
            if (!parseTransport(tname, t)) return "unknown_field";
            if (cell.type != Json.Type.bool_) return "invalid_value";
            if (t == Transport.email && cell.get!bool && !emailOffered(cls)) return "email_not_offered";
        }
    }
    return "";
}

private string checkQuietPatch(Json v, ref string field) {
    if (v.type != Json.Type.object) return "invalid_value";
    foreach (string k, x; v) {
        field = "quiet." ~ k;
        switch (k) {
            case "enabled", "summary":
                if (x.type != Json.Type.bool_) return "invalid_value";
                break;
            case "tz":
                if (x.type != Json.Type.string) return "invalid_value";
                if (x.get!string.length && !isTzName(x.get!string)) return "invalid_timezone";
                break;
            case "tzMode":
                if (x.type != Json.Type.string || !TZ_MODES.canFind(x.get!string)) return "invalid_value";
                break;
            case "windows":
                if (x.type != Json.Type.array || x.length == 0 || x.length > MAX_QUIET_WINDOWS) return "invalid_value";
                foreach (item; x) {
                    QuietWindow w;
                    if (!parseWindow(item, w)) return "invalid_value";
                }
                break;
            case "breakthrough":
                if (x.type != Json.Type.object) return "invalid_value";
                foreach (string bk, b; x) {
                    field = "quiet.breakthrough." ~ bk;
                    if (bk == "vip") {
                        if (b.type != Json.Type.array || b.length > MAX_VIP) return "invalid_value";
                        foreach (n; b)
                            if (n.type != Json.Type.string || !n.get!string.strip.length
                                    || n.get!string.strip.length > MAX_VIP_BYTES) return "invalid_value";
                    } else if (bk == "repeatSec") {
                        if (b.type != Json.Type.int_ || !REPEAT_SECONDS.canFind(b.get!long)) return "invalid_value";
                    } else if (bk == "urgentWords") {
                        if (b.type != Json.Type.bool_) return "invalid_value";
                    } else {
                        return "unknown_field";
                    }
                }
                break;
            default:
                return "unknown_field";
        }
    }
    return "";
}

private string checkHighlightPatch(Json v, ref string field) {
    if (v.type != Json.Type.object) return "invalid_value";
    foreach (string k, x; v) {
        field = "highlight." ~ k;
        if (k == "wholeWord" || k == "caseSensitive") {
            if (x.type != Json.Type.bool_) return "invalid_value";
        } else if (k == "words") {
            if (x.type != Json.Type.array || x.length > MAX_HIGHLIGHT_WORDS) return "invalid_value";
            foreach (item; x) {
                if (item.type != Json.Type.object) return "invalid_value";
                foreach (string wk, wv; item) {
                    if (wk == "w") {
                        if (wv.type != Json.Type.string) return "invalid_value";
                        const s = wv.get!string.strip;
                        if (!s.length || s.length > MAX_HIGHLIGHT_WORD_BYTES) return "invalid_value";
                    } else if (wk == "urgent") {
                        if (wv.type != Json.Type.bool_) return "invalid_value";
                    } else {
                        return "unknown_field";
                    }
                }
                if ("w" !in item) return "invalid_value";
            }
        } else {
            return "unknown_field";
        }
    }
    return "";
}

private bool flag(Json o, string key, bool dflt) {
    if (o.type != Json.Type.object) return dflt;
    if (auto v = key in o)
        if (v.type == Json.Type.bool_) return v.get!bool;
    return dflt;
}

private void readBool(Json o, string key, ref bool dst, ref bool repair) {
    if (auto v = key in o) {
        if (v.type == Json.Type.bool_) dst = v.get!bool;
        else repair = true;
    }
}

private void readEnum(Json o, string key, const string[] allowed, ref string dst, ref bool repair) {
    if (auto v = key in o) {
        if (v.type == Json.Type.string && allowed.canFind(v.get!string)) dst = v.get!string;
        else repair = true;
    }
}

private void readIntIn(Json o, string key, const long[] allowed, ref int dst, ref bool repair) {
    if (auto v = key in o) {
        if (v.type == Json.Type.int_ && allowed.canFind(v.get!long)) dst = cast(int) v.get!long;
        else repair = true;
    }
}

private void readSnooze(Json o, string key, ref long dst, ref bool repair) {
    if (auto v = key in o) {
        if (v.type == Json.Type.int_ && v.get!long >= -1) dst = v.get!long;
        else repair = true;
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────

version (unittest) {
    private enum DEV = "11111111-2222-4333-8444-555555555555";

    private string patchError(string json) {
        string field;
        return validatePatch(parseJsonString(json), field);
    }

    private string patchField(string json) {
        string field;
        validatePatch(parseJsonString(json), field);
        return field;
    }

    private string clientError(string target, string json) {
        string field;
        return validateClientPatch(target, parseJsonString(json), field);
    }
}

@("defaultPolicy: focused matrix, email off, nights template, v2/rev 1")
unittest {
    const p = defaultPolicy();
    assert(p.v == 2 && p.rev == 1 && p.snoozeUntil == 0 && p.migratedAt == 0 && !p.bannerDismissed);
    assert(matchPreset(p) == "focused");
    foreach (i; 0 .. 6) assert(!p.matrix[i].email);
    assert(p.matrix[NotifyClass.all] == Cells(true, false, false, false));
    assert(p.matrix[NotifyClass.invite] == Cells(true, false, true, false));
    assert(!p.quiet.enabled && p.quiet.tz == "" && p.quiet.tzMode == "account" && p.quiet.summary);
    assert(p.quiet.windows == [QuietWindow([0, 1, 2, 3, 4, 5, 6], 1320, 480)]);
    assert(p.quiet.breakthrough.repeatSec == 180 && p.quiet.breakthrough.urgentWords && !p.quiet.breakthrough.vip.length);
    assert(p.highlight.wholeWord && !p.highlight.caseSensitive && !p.highlight.words.length);
    assert(p.presentation == Presentation("full", 30));
    assert(p.email == EmailSettings("delay15", 8));
    assert(!p.networks.length && !p.clients.length);
    // defaultPolicy hands out its own windows array.
    auto a = defaultPolicy(), b = defaultPolicy();
    assert(a.quiet.windows.ptr !is b.quiet.windows.ptr);
}

@("NotificationPolicy JSON: the default and a full policy round-trip; empty arrays are []")
unittest {
    const d = defaultPolicy();
    auto j = d.toJson();
    assert(j["quiet"]["breakthrough"]["vip"].type == Json.Type.array);
    assert(j["highlight"]["words"].type == Json.Type.array);
    assert(j["networks"].type == Json.Type.object && j["clients"].type == Json.Type.object);
    assert(j["matrix"]["all"]["email"].type == Json.Type.bool_);
    bool repair;
    auto back = NotificationPolicy.fromJson(j, repair);
    assert(!repair && back.toJson() == j);

    auto p = defaultPolicy();
    p.rev = 7;
    p.snoozeUntil = -1;
    p.matrix[NotifyClass.dm].email = true;
    p.quiet.enabled = true;
    p.quiet.tz = "Europe/Berlin";
    p.quiet.tzMode = "device";
    p.quiet.windows = templateWindows("offHours");
    p.quiet.breakthrough = QuietBreakthrough(["Alice", "bob"], 0, false);
    p.quiet.summary = false;
    p.highlight = HighlightSettings([HighlightWord("outage", true), HighlightWord("deploy", false)], false, true);
    p.presentation = Presentation("sender", 120);
    p.email = EmailSettings("daily", 23);
    p.networks["n1"] = "muted";
    p.networks["n2"] = "all";
    ClientOverride web;
    web.cells["mention.sound"] = false;
    web.hasSnooze = true;
    web.snoozeUntil = 0;
    p.clients[CLIENT_WEB] = web;
    ClientOverride dev;
    dev.cells["all.mobile"] = true;
    p.clients[DEV] = dev;
    p.migratedAt = 123;
    p.bannerDismissed = true;
    const pj = p.toJson();
    assert(pj["clients"][CLIENT_WEB]["snoozeUntil"].get!long == 0, "an explicit 0 snooze is kept");
    assert("snoozeUntil" !in pj["clients"][DEV]);
    assert(pj["quiet"]["windows"][1]["end"].get!string == "24:00");
    auto p2 = NotificationPolicy.fromJson(pj, repair);
    assert(!repair);
    assert(p2.toJson().toString() == pj.toString(), "byte-identical round trip");
    assert(p2.clients[CLIENT_WEB].hasSnooze && p2.clients[CLIENT_WEB].snoozeUntil == 0);
    assert(!p2.clients[DEV].hasSnooze);
}

@("NotificationPolicy.fromJson: {} is an empty array; damage keeps defaults and flags repair")
unittest {
    bool repair;
    auto j = defaultPolicy().toJson();
    j["quiet"]["breakthrough"]["vip"] = Json.emptyObject;
    j["highlight"]["words"] = Json.emptyObject;
    auto p = NotificationPolicy.fromJson(j, repair);
    assert(!repair && !p.quiet.breakthrough.vip.length && !p.highlight.words.length);

    auto bad = defaultPolicy().toJson();
    bad["rev"] = Json(0);
    bad["matrix"]["notice"]["email"] = Json(true);          // email is not offered for notices
    bad["matrix"]["dm"]["desktop"] = Json("yes");
    bad["quiet"]["tzMode"] = Json("planet");
    bad["quiet"]["windows"] = parseJsonString(`[{"days":[],"start":"22:00","end":"08:00"}]`);
    bad["presentation"]["coalesceSec"] = Json(45);
    bad["email"]["dailyHour"] = Json(24);
    bad["networks"] = parseJsonString(`{"n1":"loud","n2":"all"}`);
    bad["clients"] = parseJsonString(`{"web":{"cells":{"dm.mobile":true}},"` ~ DEV ~ `":{"cells":{"dm.mobile":false}},"NOPE":{"snoozeUntil":-1}}`);
    p = NotificationPolicy.fromJson(bad, repair);
    assert(repair);
    assert(p.rev == 1 && !p.matrix[NotifyClass.notice].email && p.matrix[NotifyClass.dm].desktop);
    assert(p.quiet.tzMode == "account" && p.quiet.windows == defaultPolicy().quiet.windows);
    assert(p.presentation.coalesceSec == 30 && p.email.dailyHour == 8);
    assert(p.networks == ["n2": "all"]);
    assert(p.clients.length == 1 && DEV in p.clients, "web may not override mobile; bad keys drop");

    NotificationPolicy.fromJson(Json("x"), repair);
    assert(repair);
}

@("NotificationPolicy.fromJson: a stored presentation.autoDismiss is ignored and dropped on save")
unittest {
    bool repair;
    auto j = defaultPolicy().toJson();
    j["presentation"] = parseJsonString(`{"preview":"sender","coalesceSec":120,"autoDismiss":false}`);
    auto p = NotificationPolicy.fromJson(j, repair);
    assert(!repair && p.presentation == Presentation("sender", 120));
    assert("autoDismiss" !in p.toJson()["presentation"]);
}

@("validatePatch: every error code")
unittest {
    assert(patchError(`[]`) == "bad_request");
    assert(patchError(`{}`) == "bad_request");
    foreach (k; ["clients", "rev", "v", "migratedAt"])
        assert(patchError(`{"` ~ k ~ `":1}`) == "field_not_patchable" && patchField(`{"` ~ k ~ `":1}`) == k);
    assert(patchError(`{"colour":1}`) == "unknown_field");
    assert(patchError(`{"matrix":{"spam":{"desktop":true}}}`) == "unknown_field");
    assert(patchField(`{"matrix":{"dm":{"pigeon":true}}}`) == "matrix.dm.pigeon");
    assert(patchError(`{"matrix":{"dm":{"desktop":1}}}`) == "invalid_value");
    assert(patchError(`{"matrix":{"all":{"email":true}}}`) == "email_not_offered");
    assert(patchField(`{"matrix":{"all":{"email":true}}}`) == "matrix.all.email");
    assert(patchError(`{"matrix":{"all":{"email":false}}}`) == "");
    assert(patchError(`{"matrix":{"mention":{"email":true}}}`) == "");
    assert(patchError(`{"applyPreset":"loud"}`) == "invalid_value");
    assert(patchError(`{"applyPreset":"quiet","matrix":{"dm":{"sound":true}}}`) == "invalid_value");
    assert(patchError(`{"applyPreset":"everything"}`) == "");
    assert(patchError(`{"snoozeUntil":-2}`) == "invalid_value");
    assert(patchError(`{"snoozeUntil":-1}`) == "");
    assert(patchError(`{"quiet":{"tz":"Europe/Berlin; rm"}}`) == "invalid_timezone");
    assert(patchError(`{"quiet":{"tz":""}}`) == "");
    assert(patchError(`{"quiet":{"tzMode":"moon"}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"windows":[]}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"windows":[{"days":[0,0],"start":"22:00","end":"08:00"}]}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"windows":[{"days":[7],"start":"22:00","end":"08:00"}]}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"windows":[{"days":[1],"start":"22:00","end":"22:00"}]}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"windows":[{"days":[1],"start":"24:00","end":"08:00"}]}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"windows":[{"days":[1],"start":"22:00","end":"24:00"}]}}`) == "");
    assert(patchError(`{"quiet":{"windows":[{"days":[1],"start":"9:00","end":"17:00"}]}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"windows":[{"days":[1],"start":"09:60","end":"17:00"}]}}`) == "invalid_value");
    string fifteen = `[`;
    foreach (i; 0 .. 15) fifteen ~= (i ? "," : "") ~ `{"days":[1],"start":"09:00","end":"10:00"}`;
    assert(patchError(`{"quiet":{"windows":` ~ fifteen ~ `]}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"breakthrough":{"repeatSec":60}}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"breakthrough":{"vip":["  "]}}}`) == "invalid_value");
    assert(patchError(`{"quiet":{"breakthrough":{"boss":true}}}`) == "unknown_field");
    assert(patchError(`{"highlight":{"words":[{"w":""}]}}`) == "invalid_value");
    assert(patchError(`{"highlight":{"words":["outage"]}}`) == "invalid_value");
    assert(patchError(`{"highlight":{"words":[{"w":"outage","loud":true}]}}`) == "unknown_field");
    assert(patchError(`{"highlight":{"words":[{"w":"outage","urgent":true}],"wholeWord":false}}`) == "");
    assert(patchError(`{"presentation":{"preview":"blurry"}}`) == "invalid_value");
    assert(patchError(`{"presentation":{"coalesceSec":60}}`) == "invalid_value");
    assert(patchError(`{"presentation":{"autoDismiss":false}}`) == "unknown_field");
    assert(patchField(`{"presentation":{"autoDismiss":false}}`) == "presentation.autoDismiss");
    assert(patchError(`{"email":{"mode":"weekly"}}`) == "invalid_value");
    assert(patchError(`{"email":{"dailyHour":24}}`) == "invalid_value");
    assert(patchError(`{"networks":{"n1":"loud"}}`) == "invalid_value");
    assert(patchError(`{"networks":{"n1":null,"n2":"muted"}}`) == "");
    assert(patchError(`{"bannerDismissed":"yes"}`) == "invalid_value");

    auto p = defaultPolicy();
    p.quiet.enabled = true;
    string field;
    assert(checkPolicy(p, field) == "invalid_timezone" && field == "quiet.tz");
    p.quiet.tz = "UTC";
    assert(checkPolicy(p, field) == "");
}

@("applyPatch: merge-patch semantics; arrays replace; applyPreset keeps email")
unittest {
    auto p = defaultPolicy();
    p.matrix[NotifyClass.dm].email = true;
    p.networks["n1"] = "muted";
    auto before = p;   // shares the networks AA: applyPatch must not touch it
    applyPatch(p, parseJsonString(`{"applyPreset":"everything"}`));
    assert(matchPreset(p) == "everything" && p.matrix[NotifyClass.dm].email, "a preset leaves email alone");
    applyPatch(p, parseJsonString(`{"matrix":{"all":{"sound":false}},"networks":{"n1":null,"n2":"all"},
        "quiet":{"enabled":true,"tz":"Europe/Berlin","windows":[{"days":[5,6],"start":"00:00","end":"24:00"}],
        "breakthrough":{"vip":["Bob","bob"," alice "]}},
        "highlight":{"words":[{"w":" Outage ","urgent":true},{"w":"outage"},{"w":"deploy"}],"caseSensitive":true},
        "presentation":{"coalesceSec":0},"email":{"mode":"daily","dailyHour":7},"bannerDismissed":true,"snoozeUntil":99}`));
    assert(matchPreset(p) == "custom" && !p.matrix[NotifyClass.all].sound && p.matrix[NotifyClass.all].mobile);
    assert(p.networks == ["n2": "all"] && before.networks == ["n1": "muted"]);
    assert(p.quiet.enabled && p.quiet.tz == "Europe/Berlin" && p.quiet.tzMode == "account");
    assert(p.quiet.windows == [QuietWindow([5, 6], 0, 1440)]);
    assert(p.quiet.breakthrough.vip == ["Bob", "alice"] && p.quiet.breakthrough.repeatSec == 180);
    assert(p.highlight.words == [HighlightWord("Outage", true), HighlightWord("deploy", false)]);
    assert(p.highlight.caseSensitive && p.highlight.wholeWord);
    assert(p.presentation == Presentation("full", 0));
    assert(p.email == EmailSettings("daily", 7) && p.bannerDismissed && p.snoozeUntil == 99);
    assert(p.rev == 1, "applyPatch does not bump rev");
    applyPatch(p, parseJsonString(`{"applyPreset":"quiet"}`));
    assert(matchPreset(p) == "quiet" && p.matrix[NotifyClass.dm].email);
}

@("client patches: ownership per target, null deletes, an empty entry is removed")
unittest {
    assert(clientError(CLIENT_WEB, `[]`) == "bad_request");
    assert(clientError(CLIENT_WEB, `{}`) == "bad_request");
    assert(clientError(TARGET_ACCOUNT, `{"snoozeUntil":-1}`) == "client_not_found");
    assert(clientError("ABCDEF", `{"snoozeUntil":-1}`) == "client_not_found");
    assert(clientError(CLIENT_WEB, `{"cells":{"dm.mobile":false}}`) == "override_not_owned");
    assert(clientError(CLIENT_WEB, `{"cells":{"dm.email":false}}`) == "override_not_owned");
    assert(clientError(DEV, `{"cells":{"dm.desktop":false}}`) == "override_not_owned");
    assert(clientError(DEV, `{"cells":{"dm.email":true}}`) == "override_not_owned");
    assert(clientError(DEV, `{"cells":{"dm":false}}`) == "invalid_value");
    assert(clientError(DEV, `{"cells":{"dm.mobile":"no"}}`) == "invalid_value");
    assert(clientError(DEV, `{"snoozeUntil":-5}`) == "invalid_value");
    assert(clientError(DEV, `{"volume":3}`) == "unknown_field");
    assert(clientError(CLIENT_WEB, `{"cells":{"dm.desktop":false,"dm.sound":null},"snoozeUntil":null}`) == "");
    assert(clientError(DEV, `{"cells":{"all.mobile":true,"all.sound":true},"snoozeUntil":0}`) == "");

    auto p = defaultPolicy();
    applyClientPatch(p, DEV, parseJsonString(`{"cells":{"all.mobile":true},"snoozeUntil":0}`));
    assert(resolveCell(p, DEV, NotifyClass.all, Transport.mobile) && !resolveCell(p, CLIENT_WEB, NotifyClass.all, Transport.mobile));
    p.snoozeUntil = -1;
    assert(snoozeOf(p, DEV) == 0 && !snoozeActive(snoozeOf(p, DEV), 5), "a client 0 beats the account snooze");
    assert(snoozeOf(p, CLIENT_WEB) == -1 && snoozeActive(snoozeOf(p, CLIENT_WEB), 5));
    applyClientPatch(p, DEV, parseJsonString(`{"snoozeUntil":null}`));
    assert(snoozeOf(p, DEV) == -1 && DEV in p.clients);
    applyClientPatch(p, DEV, parseJsonString(`{"cells":{"all.mobile":null}}`));
    assert(DEV !in p.clients, "an entry left empty is removed");
    assert(!removeClient(p, DEV));
    applyClientPatch(p, CLIENT_WEB, parseJsonString(`{"snoozeUntil":-1}`));
    assert(removeClient(p, CLIENT_WEB) && !p.clients.length);
}

@("matchPreset, presetsJson and quietTemplatesJson")
unittest {
    auto p = defaultPolicy();
    foreach (ref pr; PRESETS) {
        p.matrix = pr.cells;
        assert(matchPreset(p) == pr.name);
        p.matrix[NotifyClass.mention].email = true;
        assert(matchPreset(p) == pr.name, "email never counts");
    }
    p.matrix[NotifyClass.wallops].sound = !p.matrix[NotifyClass.wallops].sound;
    assert(matchPreset(p) == "custom");
    const pj = presetsJson();
    assert(pj["everything"]["wallops"]["sound"].get!bool == false && "email" !in pj["focused"]["dm"]);
    const qj = quietTemplatesJson();
    assert(qj["nights"].length == 1 && qj["nightsWeekends"].length == 3 && qj["offHours"].length == 3);
    assert(qj["offHours"][0]["start"].get!string == "18:00" && qj["offHours"][0]["end"].get!string == "09:00");
    assert(qj["nightsWeekends"][2]["days"] == parseJsonString(`[5,6]`) && qj["nightsWeekends"][2]["end"].get!string == "24:00");
}

@("v1 projections: account and device views")
unittest {
    auto p = defaultPolicy();
    assert(projDesktop(p) && projSound(p, "") && !projMuteAll(p, "", 10));
    assert(projSound(p, DEV), "dm pushes with sound by default");
    foreach (i; 0 .. 6) p.matrix[i].desktop = false;
    assert(!projDesktop(p));
    applyClientPatch(p, CLIENT_WEB, parseJsonString(`{"cells":{"invite.desktop":true}}`));
    assert(projDesktop(p), "a web override counts");
    applyClientPatch(p, DEV, parseJsonString(`{"cells":{"dm.sound":false,"mention.sound":false}}`));
    assert(!projSound(p, DEV) && projSound(p, ""), "the device pushes dm/mention/invite silently");
    p.snoozeUntil = 20;
    assert(projMuteAll(p, "", 10) && !projMuteAll(p, "", 20) && projMuteAll(p, DEV, 10));
    applyClientPatch(p, DEV, parseJsonString(`{"snoozeUntil":0}`));
    assert(!projMuteAll(p, DEV, 10) && projMuteAll(p, "", 10));
    p.highlight.words = [HighlightWord("a", true), HighlightWord("b", false)];
    assert(projHighlightWords(p) == ["a", "b"]);
}

@("migrateFromV1: matrix, snooze, presentation, words, server levels and device overrides")
unittest {
    auto raw = parseJsonString(`{"desktopNotifications":false,"notificationSound":true,"autoDismissNotifs":false,
        "muteAll":true,"highlightWords":["Deploy","deploy"," prod "],
        "devices":{"` ~ DEV ~ `":{"muteAll":false,"notificationSound":false},
                   "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee":{"muteAll":true,"notificationSound":true}}}`);
    Json[string] bp;
    bp["n1:_server"] = parseJsonString(`{"notifyAll":true,"showJoinPart":false}`);
    bp["n2:_server"] = parseJsonString(`{"mute":true,"notifyAll":true}`);
    bp["n1:#chan"] = parseJsonString(`{"mute":true}`);
    auto p = migrateFromV1(raw, 42, bp);
    foreach (i; 0 .. 6) {
        const pushes = i != NotifyClass.notice && i != NotifyClass.wallops;
        assert(p.matrix[i] == Cells(false, true, pushes, false));
    }
    assert(p.snoozeUntil == -1 && p.presentation == Presentation("full", 0) && p.migratedAt == 42);
    assert(p.highlight.words == [HighlightWord("Deploy", false), HighlightWord("prod", false)]);
    assert(p.networks == ["n1": "all", "n2": "muted"]);
    assert(bp.length == 2 && bp["n1:_server"] == parseJsonString(`{"showJoinPart":false}`) && "n2:_server" !in bp);
    assert(bp["n1:#chan"] == parseJsonString(`{"mute":true}`), "channel entries are untouched");
    assert(p.clients[DEV].hasSnooze && p.clients[DEV].snoozeUntil == 0, "unmuted under an account mute");
    foreach (i; 0 .. 6) assert(p.clients[DEV].cells[cellKey(cast(NotifyClass) i, Transport.sound)] == false);
    const other = p.clients["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"];
    assert(other.hasSnooze && other.snoozeUntil == -1 && !other.cells.length);

    // Absent flat keys: D, S default on, M off; a device without overrides gets no entry.
    Json[string] none;
    auto q = migrateFromV1(parseJsonString(`{"devices":{"` ~ DEV ~ `":{"muteAll":false,"notificationSound":true}}}`), 1, none);
    assert(q.matrix[NotifyClass.dm] == Cells(true, true, true, false) && q.snoozeUntil == 0);
    assert(!q.clients.length && !q.networks.length);
}

@("format helpers: isTzName, parseHhmm/formatHhmm, cell keys, ownership")
unittest {
    assert(isTzName("America/Los_Angeles") && isTzName("Etc/GMT+5") && isTzName("UTC"));
    assert(!isTzName("") && !isTzName("Europe/Berlin ") && !isTzName("../etc/passwd;") );
    string long_;
    foreach (i; 0 .. 65) long_ ~= "a";
    assert(!isTzName(long_) && isTzName(long_[0 .. 64]));
    ushort m;
    assert(parseHhmm("00:00", false, m) && m == 0);
    assert(parseHhmm("23:59", false, m) && m == 1439);
    assert(!parseHhmm("24:00", false, m) && parseHhmm("24:00", true, m) && m == 1440);
    assert(!parseHhmm("24:01", true, m) && !parseHhmm("7:00", false, m) && !parseHhmm("07-00", false, m));
    assert(formatHhmm(0) == "00:00" && formatHhmm(1439) == "23:59" && formatHhmm(1440) == "24:00");
    NotifyClass c;
    Transport t;
    assert(parseCellKey("wallops.email", c, t) && c == NotifyClass.wallops && t == Transport.email);
    assert(!parseCellKey("wallops", c, t) && !parseCellKey("dm.fax", c, t));
    assert(cellKey(NotifyClass.mention, Transport.sound) == "mention.sound");
    assert(ownsColumn(CLIENT_WEB, Transport.desktop) && ownsColumn(CLIENT_WEB, Transport.sound) && !ownsColumn(CLIENT_WEB, Transport.mobile));
    assert(ownsColumn(DEV, Transport.mobile) && !ownsColumn(DEV, Transport.desktop) && !ownsColumn(DEV, Transport.email));
    assert(!ownsColumn(TARGET_ACCOUNT, Transport.email));
    assert(deliveryColumn(CLIENT_WEB) == Transport.desktop && deliveryColumn(TARGET_ACCOUNT) == Transport.email
        && deliveryColumn(DEV) == Transport.mobile);
    assert(emailOffered(NotifyClass.dm) && emailOffered(NotifyClass.mention) && !emailOffered(NotifyClass.all));
}
