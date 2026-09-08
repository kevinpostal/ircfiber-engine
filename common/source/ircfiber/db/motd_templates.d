/**
 * MOTD templates for the IRC Fiber network.
 *
 * InspIRCd serves one static MOTD file per rehash, so "a different MOTD on
 * every connect" is done in the engine: the gateway keeps the admin-edited
 * templates in Mongo (`motd_templates`), mirrors the enabled ones into
 * Redis (`RedisKeys.motdTemplates`, see `publishMotdTemplates`) and the
 * engine picks one at random per registration to irc.ircfiber.com in place
 * of the ircd's 372 lines. The gateway additionally renders a random one
 * into the ircd's MOTD file and rehashes (rotation for native clients);
 * that lives in the gateway (`web/admin/motd.d`), not here.
 */
module ircfiber.db.motd_templates;

import std.algorithm : map, filter, sort;
import std.array : array, split;
import std.datetime : Clock;
import std.string : strip, stripRight;
import std.conv : to;
import std.utf : count;
import std.uuid : randomUUID;
import vibe.db.mongo.mongo;
import vibe.data.bson;
import vibe.data.json;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// Longest line accepted in a template body, in characters. Coloured
/// TheDraw art spends up to 6 characters per colour run on top of its 72
/// cells, and box-drawing cells are 3 bytes each, so the byte cap below is
/// what keeps a 372 line (`:server 372 <32-char nick> :- ` + text) inside
/// IRC's 512-byte limit.
immutable size_t MOTD_MAX_LINE_LENGTH = 400;
/// Byte cap per line (see `MOTD_MAX_LINE_LENGTH`).
immutable size_t MOTD_MAX_LINE_BYTES = 450;
/// Most lines one template may have.
immutable size_t MOTD_MAX_LINES = 120;

private string bsonStr(Bson b, string key) @trusted {
    auto v = b[key];
    return v.type == Bson.Type.string ? v.get!string : "";
}

private long bsonLong(Bson b, string key) @trusted {
    auto v = b[key];
    return (v.type == Bson.Type.long_ || v.type == Bson.Type.int_) ? v.to!long : 0;
}

private bool bsonBool(Bson b, string key) @trusted {
    auto v = b[key];
    return v.type == Bson.Type.bool_ ? v.get!bool : false;
}

/// One MOTD template; collection `motd_templates`.
struct MotdTemplateRecord {
    /// Template identifier (UUID string, `_id`).
    string id;
    /// Admin-facing label ("ANSI Shadow · boxed").
    string name;
    /// Full MOTD text, `\n`-separated lines (Bson field "body").
    string body_;
    /// Disabled templates stay editable but are never served.
    bool enabled;
    /// Admin ordering in the list (ascending).
    long sortOrder;
    /// Builder recipe (JSON) the body was generated from; "" for hand-
    /// written templates. Opaque to the server; the admin SPA owns the schema.
    string recipe;
    /// Variant group: templates generated together from one recipe share a
    /// group and are replaced together on regeneration; "" = standalone.
    string group;
    /// Creation timestamp (unix ms).
    long createdAt;
    /// Last change timestamp (unix ms).
    long updatedAt;

    /// Body split into lines with trailing whitespace removed; a trailing
    /// newline does not produce an empty last line.
    string[] lines() const @safe {
        auto ls = body_.stripRight("\n\r").split("\n").map!(l => l.stripRight).array;
        return ls;
    }

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(id), "name": Bson(name), "body": Bson(body_),
            "enabled": Bson(enabled), "sortOrder": Bson(sortOrder),
            "recipe": Bson(recipe), "group": Bson(group),
            "createdAt": Bson(createdAt), "updatedAt": Bson(updatedAt),
        ]);
    }

    /// Deserializes from Bson; missing fields keep their init value.
    static MotdTemplateRecord fromBson(Bson b) @trusted {
        MotdTemplateRecord r;
        r.id = bsonStr(b, "_id");
        r.name = bsonStr(b, "name");
        r.body_ = bsonStr(b, "body");
        r.enabled = bsonBool(b, "enabled");
        r.sortOrder = bsonLong(b, "sortOrder");
        r.recipe = bsonStr(b, "recipe");
        r.group = bsonStr(b, "group");
        r.createdAt = bsonLong(b, "createdAt");
        r.updatedAt = bsonLong(b, "updatedAt");
        return r;
    }

    /// Wire shape shared by the admin API and the Redis mirror.
    Json toJson() const @trusted {
        Json j = Json.emptyObject;
        j["id"] = id;
        j["name"] = name;
        j["body"] = body_;
        j["enabled"] = enabled;
        j["sortOrder"] = sortOrder;
        j["recipe"] = recipe;
        j["group"] = group;
        j["createdAt"] = createdAt;
        j["updatedAt"] = updatedAt;
        return j;
    }

    /// Inverse of `toJson`; tolerates missing fields.
    static MotdTemplateRecord fromJson(Json j) @trusted {
        MotdTemplateRecord r;
        if (j.type != Json.Type.object) return r;
        r.id = j["id"].type == Json.Type.string ? j["id"].get!string : "";
        r.name = j["name"].type == Json.Type.string ? j["name"].get!string : "";
        r.body_ = j["body"].type == Json.Type.string ? j["body"].get!string : "";
        r.enabled = j["enabled"].type == Json.Type.bool_ ? j["enabled"].get!bool : false;
        r.sortOrder = j["sortOrder"].type == Json.Type.int_ ? j["sortOrder"].get!long : 0;
        r.recipe = j["recipe"].type == Json.Type.string ? j["recipe"].get!string : "";
        r.group = j["group"].type == Json.Type.string ? j["group"].get!string : "";
        r.createdAt = j["createdAt"].type == Json.Type.int_ ? j["createdAt"].get!long : 0;
        r.updatedAt = j["updatedAt"].type == Json.Type.int_ ? j["updatedAt"].get!long : 0;
        return r;
    }
}

/// Validates a template body for the wire and the ircd file. Returns ""
/// when acceptable, else a human-readable reason.
string validateMotdBody(string body_) @safe {
    auto text = body_.stripRight("\n\r");
    if (text.strip.length == 0) return "MOTD body is empty";
    auto ls = text.split("\n");
    if (ls.length > MOTD_MAX_LINES) return "MOTD has more than " ~ MOTD_MAX_LINES.to!string ~ " lines";
    foreach (i, l; ls) {
        if (l.count > MOTD_MAX_LINE_LENGTH) return "line " ~ (i + 1).to!string ~ " is longer than " ~ MOTD_MAX_LINE_LENGTH.to!string ~ " characters";
        if (l.length > MOTD_MAX_LINE_BYTES) return "line " ~ (i + 1).to!string ~ " is longer than " ~ MOTD_MAX_LINE_BYTES.to!string ~ " bytes";
        foreach (ch; l) if (ch == '\r' || ch == '\0') return "line " ~ (i + 1).to!string ~ " contains a control character";
    }
    return "";
}

/// Persistence for MOTD templates; collection `motd_templates`.
final class MotdTemplateRepository {
    private MongoCollection collection;

    /// Constructs a repository bound to the motd_templates collection.
    this() {
        auto db = AppMongoConnection.getDb();
        collection = db["motd_templates"];
        try {
            collection.createIndex(Bson(["sortOrder": Bson(1), "createdAt": Bson(1)]));
        } catch (Exception e) {
            logWarn("Failed to create motd_templates index: %s", e.msg);
        }
    }

    /// Every template, admin order.
    MotdTemplateRecord[] all() @trusted {
        FindOptions opts;
        opts.sort = Bson(["sortOrder": Bson(1), "createdAt": Bson(1)]);
        MotdTemplateRecord[] result;
        foreach (doc; collection.find(Bson.emptyObject, opts)) result ~= MotdTemplateRecord.fromBson(doc);
        return result;
    }

    /// Enabled templates only, admin order.
    MotdTemplateRecord[] enabled() @trusted {
        return all().filter!(t => t.enabled).array;
    }

    /// Template by id, or init when absent.
    MotdTemplateRecord getById(string id) @trusted {
        auto doc = collection.findOne(Bson(["_id": Bson(id)]));
        if (doc.isNull) return MotdTemplateRecord.init;
        return MotdTemplateRecord.fromBson(doc);
    }

    /// Number of templates.
    long count() @trusted {
        return collection.countDocuments(Bson.emptyObject);
    }

    /// Inserts a new template (id/timestamps filled in when missing) and
    /// returns it.
    MotdTemplateRecord insert(MotdTemplateRecord r) @trusted {
        auto now = Clock.currTime.toUnixTime!long * 1000;
        if (r.id.length == 0) r.id = randomUUID().toString();
        if (r.createdAt == 0) r.createdAt = now;
        r.updatedAt = now;
        collection.insertOne(r.toBson());
        return r;
    }

    /// Replaces the editable fields. Returns false when the id is unknown.
    bool update(string id, string name, string body_, bool enabled, long sortOrder,
                string recipe, string group) @trusted {
        auto now = Clock.currTime.toUnixTime!long * 1000;
        auto res = collection.updateOne(
            Bson(["_id": Bson(id)]),
            Bson(["$set": Bson([
                "name": Bson(name), "body": Bson(body_), "enabled": Bson(enabled),
                "sortOrder": Bson(sortOrder), "recipe": Bson(recipe), "group": Bson(group),
                "updatedAt": Bson(now),
            ])]));
        return res.matchedCount > 0;
    }

    /// Deletes every template in `group`. Returns the number removed.
    long removeGroup(string group) @trusted {
        if (group.length == 0) return 0;
        auto res = collection.deleteMany(Bson(["group": Bson(group)]));
        return res.deletedCount;
    }

    /// Deletes a template. Returns false when it did not exist.
    bool remove(string id) @trusted {
        auto res = collection.deleteOne(Bson(["_id": Bson(id)]));
        return res.deletedCount > 0;
    }
}

/// Serializes the enabled templates for the Redis mirror.
string motdTemplatesToJson(const MotdTemplateRecord[] templates) @trusted {
    Json arr = Json.emptyArray;
    foreach (t; templates) if (t.enabled) arr ~= t.toJson();
    return arr.toString();
}

/// Parses the Redis mirror. Malformed or empty input yields an empty list
/// (callers then pass the ircd MOTD through).
MotdTemplateRecord[] motdTemplatesFromJson(string json) @trusted {
    if (json.length == 0) return null;
    try {
        auto arr = parseJsonString(json);
        if (arr.type != Json.Type.array) return null;
        MotdTemplateRecord[] result;
        foreach (item; arr) {
            auto t = MotdTemplateRecord.fromJson(item);
            if (t.body_.strip.length) result ~= t;
        }
        return result;
    } catch (Exception e) {
        logWarn("motd templates mirror is not valid JSON: %s", e.msg);
        return null;
    }
}

/// The templates seeded into an empty collection: the four comps chosen
/// for launch plus one that exercises the ircd's per-user `{placeholders}`
/// (motdpool module: built-ins such as {nick}/{ip}/{users} and the
/// motd.d/profiles fields such as {geo_city}/{connects}). Returned in
/// admin order.
MotdTemplateRecord[] defaultMotdTemplates() @safe {
    MotdTemplateRecord mk(string name, string body_, long order) {
        MotdTemplateRecord r;
        r.name = name;
        r.body_ = body_;
        r.enabled = true;
        r.sortOrder = order;
        return r;
    }
    return [
        mk("ANSI Shadow · boxed", MOTD_SEED_ANSI_SHADOW, 10),
        mk("Slant · classic", MOTD_SEED_SLANT, 20),
        mk("Calvin S · compact", MOTD_SEED_CALVIN, 30),
        mk("Banner3 · solid caps", MOTD_SEED_BANNER3, 40),
        mk("Personal · placeholders", MOTD_SEED_PERSONAL, 50),
    ];
}

/// Inserts the defaults when the collection is empty. Returns the number
/// inserted (0 when the collection already had templates).
size_t seedDefaultMotdTemplates(MotdTemplateRepository repo) @trusted {
    if (repo.count() > 0) return 0;
    size_t n;
    foreach (t; defaultMotdTemplates()) { repo.insert(t); n++; }
    logInfo("Seeded %s default MOTD templates", n);
    return n;
}

private immutable string MOTD_SEED_ANSI_SHADOW = `┌──────────────────────────────────────────────────────────────────────┐
│      ██╗██████╗  ██████╗    ███████╗██╗██████╗ ███████╗██████╗       │
│      ██║██╔══██╗██╔════╝    ██╔════╝██║██╔══██╗██╔════╝██╔══██╗      │
│      ██║██████╔╝██║         █████╗  ██║██████╔╝█████╗  ██████╔╝      │
│      ██║██╔══██╗██║         ██╔══╝  ██║██╔══██╗██╔══╝  ██╔══██╗      │
│      ██║██║  ██║╚██████╗    ██║     ██║██████╔╝███████╗██║  ██║      │
│      ╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝      │
│                                                                      │
│                         Welcome to IRC Fiber                         │
├──────────────────────────────────────────────────────────────────────┤
│ irc.ircfiber.com  ·  InspIRCd 4 + Anope services  ·  TLS on 6697     │
│ Web client: https://ircfiber.com   Support: admin@ircfiber.com       │
│                                                                      │
│ Register your nick ......  /msg NickServ REGISTER <password> [email] │
│ Register a channel ......  /msg ChanServ REGISTER #channel           │
│ Join a channel ..........  /join #channelname                        │
│ Get help ................  /msg NickServ HELP   ·   /join #support   │
│                                                                      │
│ Rules                                                                │
│   1. Be respectful to other users.                                   │
│   2. No spam, flooding, or abuse.                                    │
│   3. Follow the network operator instructions.                       │
└──────────────────────────────────────────────────────────────────────┘
`;

private immutable string MOTD_SEED_SLANT = `    ________  ______   _______ __
   /  _/ __ \/ ____/  / ____(_) /_  ___  _____
   / // /_/ / /      / /_  / / __ \/ _ \/ ___/
 _/ // _, _/ /___   / __/ / / /_/ /  __/ /
/___/_/ |_|\____/  /_/   /_/_.___/\___/_/
========================================================================
Welcome to IRC Fiber!
irc.ircfiber.com  ·  InspIRCd 4 + Anope services  ·  TLS on 6697
Web client: https://ircfiber.com   Support: admin@ircfiber.com

Register your nick ......  /msg NickServ REGISTER <password> [email]
Register a channel ......  /msg ChanServ REGISTER #channel
Join a channel ..........  /join #channelname
Get help ................  /msg NickServ HELP   ·   /join #support

Rules:
  1. Be respectful to other users.
  2. No spam, flooding, or abuse.
  3. Follow the network operator instructions.
========================================================================
`;

private immutable string MOTD_SEED_CALVIN = `╦╦═╗╔═╗  ╔═╗┬┌┐ ┌─┐┬─┐
║╠╦╝║    ╠╣ │├┴┐├┤ ├┬┘
╩╩╚═╚═╝  ╚  ┴└─┘└─┘┴└─
──────────────────────
irc.ircfiber.com · InspIRCd 4 + Anope · TLS 6697 · https://ircfiber.com

/msg NickServ REGISTER <password> [email]     register your nick
/msg ChanServ REGISTER #channel               register a channel
/join #support                                get help

Be respectful · no spam or flooding · follow operator instructions
`;

private immutable string MOTD_SEED_BANNER3 = `#### ########   ######     ######## #### ########  ######## ########
 ##  ##     ## ##    ##    ##        ##  ##     ## ##       ##     ##
 ##  ##     ## ##          ##        ##  ##     ## ##       ##     ##
 ##  ########  ##          ######    ##  ########  ######   ########
 ##  ##   ##   ##          ##        ##  ##     ## ##       ##   ##
 ##  ##    ##  ##    ##    ##        ##  ##     ## ##       ##    ##
#### ##     ##  ######     ##       #### ########  ######## ##     ##

Welcome to IRC Fiber — enterprise-grade IRC for the IRC Fiber community.
irc.ircfiber.com  ·  InspIRCd 4 + Anope services  ·  TLS on 6697
Web client: https://ircfiber.com   Support: admin@ircfiber.com

Register your nick ......  /msg NickServ REGISTER <password> [email]
Register a channel ......  /msg ChanServ REGISTER #channel
Join a channel ..........  /join #channelname
Get help ................  /msg NickServ HELP   ·   /join #support

Rules
  1. Be respectful to other users.
  2. No spam, flooding, or abuse.
  3. Follow the network operator instructions.
`;

private immutable string MOTD_SEED_PERSONAL = `You are {nick}!{user}@{host} — connecting from {ip}
Location: {geo_city}, {geo_country} · {geo_org}
Visits: {connects} since {first_seen} · last nick {last_nick}
Strikes: {strikes} · banned: {banned} · {users} users online
`;

@("MotdTemplateRecord round-trips through Bson and Json")
unittest {
    MotdTemplateRecord r;
    r.id = "t1"; r.name = "n"; r.body_ = "a\nb \n"; r.enabled = true; r.sortOrder = 5;
    r.recipe = `{"blocks":[]}`; r.group = "g1";
    r.createdAt = 1; r.updatedAt = 2;
    auto b = MotdTemplateRecord.fromBson(r.toBson());
    assert(b == r);
    auto j = MotdTemplateRecord.fromJson(r.toJson());
    assert(j == r);
    assert(r.lines() == ["a", "b"]);
}

@("motd templates mirror keeps only enabled, non-empty templates")
unittest {
    MotdTemplateRecord a, b, c;
    a.id = "a"; a.body_ = "x"; a.enabled = true;
    b.id = "b"; b.body_ = "y"; b.enabled = false;
    c.id = "c"; c.body_ = "  \n"; c.enabled = true;
    auto back = motdTemplatesFromJson(motdTemplatesToJson([a, b, c]));
    assert(back.length == 1 && back[0].id == "a");
    assert(motdTemplatesFromJson("").length == 0);
    assert(motdTemplatesFromJson("not json").length == 0);
    assert(motdTemplatesFromJson(`{"id":"x"}`).length == 0);
}

@("validateMotdBody rejects empty and overlong bodies")
unittest {
    import std.range : repeat;
    import std.array : join;
    assert(validateMotdBody("") != "");
    assert(validateMotdBody("\n\n") != "");
    assert(validateMotdBody("hello\n") == "");
    assert(validateMotdBody("x".repeat(401).join) != "");
    // 72 box-drawing cells (3 bytes each) plus 30 colour runs fit; the
    // builder warns past this so a 372 line stays inside 512 bytes.
    assert(validateMotdBody("\x0301,01█".repeat(30).join ~ "█".repeat(42).join) == "");
    assert(validateMotdBody("l\n".repeat(121).join) != "");
}

@("default templates are enabled, non-empty and fit in 80 columns")
unittest {
    auto defs = defaultMotdTemplates();
    assert(defs.length == 5);
    foreach (t; defs) {
        assert(t.enabled);
        assert(validateMotdBody(t.body_) == "");
        foreach (l; t.lines()) assert(l.count <= 80, t.name ~ ": " ~ l);
    }
}
