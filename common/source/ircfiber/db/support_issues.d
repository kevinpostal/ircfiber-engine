module ircfiber.db.support_issues;

import std.algorithm : canFind, map;
import std.array : array;
import std.uuid : randomUUID;
import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// Wire values of `SupportIssueRecord.kind`.
immutable string[] supportKinds = ["bug", "feature", "question", "other", "task"];
/// Wire values of `SupportIssueRecord.status`.
immutable string[] supportStatuses = ["open", "in_progress", "resolved", "closed"];
/// Wire values of `SupportIssueRecord.priority`.
immutable string[] supportPriorities = ["low", "normal", "high", "urgent"];

/// Returns the string field `key` of `b`, or "" when absent / not a string.
private string bsonStr(Bson b, string key) @trusted {
    auto v = b[key];
    return v.type == Bson.Type.string ? v.get!string : "";
}

/// Returns the numeric field `key` of `b` as long, or 0 when absent.
private long bsonLong(Bson b, string key) @trusted {
    auto v = b[key];
    return (v.type == Bson.Type.long_ || v.type == Bson.Type.int_) ? v.to!long : 0;
}

/// Returns the boolean field `key` of `b`, or false when absent.
private bool bsonBool(Bson b, string key) @trusted {
    auto v = b[key];
    return v.type == Bson.Type.bool_ ? v.get!bool : false;
}

/// One reply on a support issue; written by the reporter or an admin.
struct SupportComment {
    /// Comment identifier (UUID string).
    string id;
    /// Author user id.
    string authorId;
    /// Author username at write time.
    string authorName;
    /// Written from the admin pane.
    bool fromAdmin;
    /// Admin-only note; never serialized for the reporter, never announced.
    bool internal;
    /// Comment text (Bson field "body").
    string body_;
    /// Creation timestamp (unix ms).
    long createdAt;

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        return Bson([
            "id": Bson(id), "authorId": Bson(authorId), "authorName": Bson(authorName),
            "fromAdmin": Bson(fromAdmin), "internal": Bson(internal),
            "body": Bson(body_), "createdAt": Bson(createdAt),
        ]);
    }

    /// Deserializes from Bson; missing fields keep their init value.
    static SupportComment fromBson(Bson b) @trusted {
        SupportComment c;
        c.id = bsonStr(b, "id");
        c.authorId = bsonStr(b, "authorId");
        c.authorName = bsonStr(b, "authorName");
        c.fromAdmin = bsonBool(b, "fromAdmin");
        c.internal = bsonBool(b, "internal");
        c.body_ = bsonStr(b, "body");
        c.createdAt = bsonLong(b, "createdAt");
        return c;
    }
}

/// Diagnostics captured by the client when the report was filed
/// (Bson sub-document "context"). Every field is optional.
struct SupportIssueContext {
    string appVersion;
    string userAgent;
    string url;
    string networkId;
    string bufferName;
    string viewport;

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        return Bson([
            "appVersion": Bson(appVersion), "userAgent": Bson(userAgent), "url": Bson(url),
            "networkId": Bson(networkId), "bufferName": Bson(bufferName), "viewport": Bson(viewport),
        ]);
    }

    /// Deserializes from Bson; missing fields stay empty.
    static SupportIssueContext fromBson(Bson b) @trusted {
        SupportIssueContext c;
        if (b.type != Bson.Type.object) return c;
        c.appVersion = bsonStr(b, "appVersion");
        c.userAgent = bsonStr(b, "userAgent");
        c.url = bsonStr(b, "url");
        c.networkId = bsonStr(b, "networkId");
        c.bufferName = bsonStr(b, "bufferName");
        c.viewport = bsonStr(b, "viewport");
        return c;
    }
}

/// One Help & Feedback report; collection `support_issues`.
struct SupportIssueRecord {
    /// Issue identifier (UUID string, `_id`).
    string id;
    /// Human sequence number (#12), unique.
    long number;
    /// Reporting user id.
    string userId;
    /// Reporter username at creation time.
    string reporterUsername;
    /// One of `supportKinds`.
    string kind;
    /// Short summary.
    string title;
    /// Report text (Bson field "body").
    string body_;
    /// One of `supportStatuses`.
    string status;
    /// One of `supportPriorities`.
    string priority;
    /// Assigned admin user id ("" = unassigned).
    string assigneeId;
    /// Assigned admin username ("" = unassigned).
    string assigneeUsername;
    /// Upload URLs (screenshots), at most 3.
    string[] attachments;
    /// Client diagnostics.
    SupportIssueContext context;
    /// Conversation, chronological.
    SupportComment[] comments;
    /// Creation timestamp (unix ms).
    long createdAt;
    /// Last change timestamp (unix ms).
    long updatedAt;
    /// When the issue became resolved/closed (unix ms); 0 = none.
    long resolvedAt;

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(id), "number": Bson(number),
            "userId": Bson(userId), "reporterUsername": Bson(reporterUsername),
            "kind": Bson(kind), "title": Bson(title), "body": Bson(body_),
            "status": Bson(status), "priority": Bson(priority),
            "assigneeId": Bson(assigneeId), "assigneeUsername": Bson(assigneeUsername),
            "attachments": Bson(attachments.map!(a => Bson(a)).array),
            "context": context.toBson(),
            "comments": Bson(comments.map!(c => c.toBson()).array),
            "createdAt": Bson(createdAt), "updatedAt": Bson(updatedAt), "resolvedAt": Bson(resolvedAt),
        ]);
    }

    /// Deserializes from Bson. Tolerates missing fields (admin edits `$set`
    /// partial documents): arrays default empty, strings "", numbers 0.
    static SupportIssueRecord fromBson(Bson b) @trusted {
        SupportIssueRecord r;
        r.id = bsonStr(b, "_id");
        r.number = bsonLong(b, "number");
        r.userId = bsonStr(b, "userId");
        r.reporterUsername = bsonStr(b, "reporterUsername");
        r.kind = bsonStr(b, "kind");
        r.title = bsonStr(b, "title");
        r.body_ = bsonStr(b, "body");
        r.status = bsonStr(b, "status");
        r.priority = bsonStr(b, "priority");
        r.assigneeId = bsonStr(b, "assigneeId");
        r.assigneeUsername = bsonStr(b, "assigneeUsername");
        auto att = b["attachments"];
        if (att.type == Bson.Type.array)
            foreach (item; att.byValue)
                if (item.type == Bson.Type.string) r.attachments ~= item.get!string;
        r.context = SupportIssueContext.fromBson(b["context"]);
        auto com = b["comments"];
        if (com.type == Bson.Type.array)
            foreach (item; com.byValue)
                if (item.type == Bson.Type.object) r.comments ~= SupportComment.fromBson(item);
        r.createdAt = bsonLong(b, "createdAt");
        r.updatedAt = bsonLong(b, "updatedAt");
        r.resolvedAt = bsonLong(b, "resolvedAt");
        return r;
    }
}

/// Admin list filter; empty members mean "no constraint".
struct SupportAdminFilter {
    /// Status whitelist (`$in`); empty = every status.
    string[] statuses;
    /// Exact kind.
    string kind;
    /// Case-insensitive substring of title or reporter username.
    string q;
    /// Exact assignee user id.
    string assigneeId;
}

/// Backslash-escapes every regex metacharacter so user text can be used
/// as a literal `$regex` pattern.
string escapeRegex(string s) pure @safe {
    string out_;
    out_.reserve(s.length);
    foreach (dchar ch; s) {
        switch (ch) {
            case '\\': case '^': case '$': case '.': case '|': case '?': case '*':
            case '+': case '(': case ')': case '[': case ']': case '{': case '}':
                out_ ~= '\\';
                break;
            default:
                break;
        }
        out_ ~= ch;
    }
    return out_;
}

/// Persistence for Help & Feedback reports; collection `support_issues`
/// plus the `counters` document `{_id: "support_issues", seq}` that hands
/// out the human-facing issue number.
final class SupportIssueRepository {
    private MongoCollection collection;
    private MongoCollection counters;

    /// Constructs a repository bound to the support_issues collection.
    this() {
        auto db = AppMongoConnection.getDb();
        collection = db["support_issues"];
        counters = db["counters"];
        ensureIndexes();
    }

    private void ensureIndexes() @trusted {
        try {
            collection.createIndex(Bson(["userId": Bson(1), "createdAt": Bson(-1)]));
        } catch (Exception e) {
            logWarn("Failed to create support_issues userId index: %s", e.msg);
        }
        try {
            collection.createIndex(Bson(["status": Bson(1), "createdAt": Bson(-1)]));
        } catch (Exception e) {
            logWarn("Failed to create support_issues status index: %s", e.msg);
        }
        try {
            IndexOptions o;
            o.unique = true;
            collection.createIndex(Bson(["number": Bson(1)]), o);
        } catch (Exception e) {
            logWarn("Failed to create support_issues number index: %s", e.msg);
        }
    }

    /// Atomically allocates the next issue number.
    long nextNumber() @trusted {
        auto doc = counters.findAndModifyExt(
            Bson(["_id": Bson("support_issues")]),
            Bson(["$inc": Bson(["seq": Bson(1L)])]),
            Bson(["new": Bson(true), "upsert": Bson(true)]));
        return doc["seq"].to!long;
    }

    /// Inserts a new issue.
    void insert(SupportIssueRecord r) @trusted {
        collection.insertOne(r.toBson());
    }

    /// Issue by id regardless of owner, or init when absent.
    SupportIssueRecord getById(string id) @trusted {
        auto doc = collection.findOne(Bson(["_id": Bson(id)]));
        if (doc.isNull) return SupportIssueRecord.init;
        return SupportIssueRecord.fromBson(doc);
    }

    /// Issue by human number, or init when absent.
    SupportIssueRecord getByNumber(long n) @trusted {
        auto doc = collection.findOne(Bson(["number": Bson(n)]));
        if (doc.isNull) return SupportIssueRecord.init;
        return SupportIssueRecord.fromBson(doc);
    }

    /// One of the user's own issues, or init when absent / not theirs.
    SupportIssueRecord getByIdForUser(string userId, string id) @trusted {
        auto doc = collection.findOne(Bson(["_id": Bson(id), "userId": Bson(userId)]));
        if (doc.isNull) return SupportIssueRecord.init;
        return SupportIssueRecord.fromBson(doc);
    }

    /// Offset-paginated page of a user's issues, newest first.
    SupportIssueRecord[] pageByUser(string userId, int offset, int limit) @trusted {
        return fetchPage(Bson(["userId": Bson(userId)]), offset, limit);
    }

    /// Count of a user's issues.
    long countByUser(string userId) @trusted {
        return collection.countDocuments(Bson(["userId": Bson(userId)]));
    }

    /// Count of a user's issues created at or after `sinceMs` (rate limit).
    long countByUserSince(string userId, long sinceMs) @trusted {
        return collection.countDocuments(Bson([
            "userId": Bson(userId), "createdAt": Bson(["$gte": Bson(sinceMs)]),
        ]));
    }

    /// Offset-paginated admin listing, newest first.
    SupportIssueRecord[] pageAdmin(SupportAdminFilter f, int offset, int limit) @trusted {
        return fetchPage(buildAdminQuery(f), offset, limit);
    }

    /// Total matching the admin filter.
    long countAdmin(SupportAdminFilter f) @trusted {
        return collection.countDocuments(buildAdminQuery(f));
    }

    /// Issue count per status, keyed by wire value; every status is present.
    long[string] countByStatus() @trusted {
        long[string] counts;
        foreach (s; supportStatuses)
            counts[s] = collection.countDocuments(Bson(["status": Bson(s)]));
        return counts;
    }

    /// Newest issues whose status is in `statuses` (empty = any), for the bot.
    SupportIssueRecord[] recent(string[] statuses, int limit) @trusted {
        Bson query = Bson.emptyObject;
        if (statuses.length)
            query["status"] = Bson(["$in": Bson(statuses.map!(s => Bson(s)).array)]);
        return fetchPage(query, 0, limit);
    }

    /// Sets triage fields. Returns false when the issue does not exist.
    bool updateTriage(string id, string status, string priority, string assigneeId,
                      string assigneeUsername, long updatedAt, long resolvedAt) @trusted {
        auto res = collection.updateOne(
            Bson(["_id": Bson(id)]),
            Bson(["$set": Bson([
                "status": Bson(status), "priority": Bson(priority),
                "assigneeId": Bson(assigneeId), "assigneeUsername": Bson(assigneeUsername),
                "updatedAt": Bson(updatedAt), "resolvedAt": Bson(resolvedAt),
            ])]));
        return res.matchedCount > 0;
    }

    /// Appends a comment and bumps `updatedAt`; when `newStatus` is non-empty
    /// the status and `resolvedAt` are set too (reporter reopen). Returns
    /// false when the issue does not exist.
    bool appendComment(string id, SupportComment c, long updatedAt, string newStatus, long resolvedAt) @trusted {
        Bson setDoc = Bson.emptyObject;
        setDoc["updatedAt"] = Bson(updatedAt);
        if (newStatus.length) {
            setDoc["status"] = Bson(newStatus);
            setDoc["resolvedAt"] = Bson(resolvedAt);
        }
        auto res = collection.updateOne(
            Bson(["_id": Bson(id)]),
            Bson(["$push": Bson(["comments": c.toBson()]), "$set": setDoc]));
        return res.matchedCount > 0;
    }

    /// Permanently deletes an issue. Returns false when it did not exist.
    bool hardDelete(string id) @trusted {
        auto res = collection.deleteOne(Bson(["_id": Bson(id)]));
        return res.deletedCount > 0;
    }

    private SupportIssueRecord[] fetchPage(Bson query, int offset, int limit) @trusted {
        FindOptions opts;
        opts.sort = Bson(["createdAt": Bson(-1)]);
        opts.skip = offset;
        opts.limit = limit;
        SupportIssueRecord[] result;
        foreach (doc; collection.find(query, opts)) result ~= SupportIssueRecord.fromBson(doc);
        return result;
    }

    private static Bson buildAdminQuery(SupportAdminFilter f) @trusted {
        Bson query = Bson.emptyObject;
        if (f.statuses.length)
            query["status"] = Bson(["$in": Bson(f.statuses.map!(s => Bson(s)).array)]);
        if (f.kind.length) query["kind"] = Bson(f.kind);
        if (f.assigneeId.length) query["assigneeId"] = Bson(f.assigneeId);
        if (f.q.length) {
            auto rx = Bson(["$regex": Bson(escapeRegex(f.q)), "$options": Bson("i")]);
            query["$or"] = Bson([Bson(["title": rx]), Bson(["reporterUsername": rx])]);
        }
        return query;
    }
}

@("SupportIssueRecord round-trips through Bson")
unittest {
    SupportIssueRecord r;
    r.id = randomUUID().toString();
    r.number = 12;
    r.userId = randomUUID().toString();
    r.reporterUsername = "zodiac";
    r.kind = "bug";
    r.title = "Upload dialog freezes";
    r.body_ = "Dropping a PNG onto the composer freezes the tab.\nSteps: …";
    r.status = "in_progress";
    r.priority = "high";
    r.assigneeId = randomUUID().toString();
    r.assigneeUsername = "kevin";
    r.attachments = ["https://ircfiber.com/uploads/a.png", "https://ircfiber.com/uploads/b.png"];
    r.context = SupportIssueContext("v1.2.3", "Mozilla/5.0", "https://ircfiber.com/irc/x", "net1", "#chan", "1440x900");
    r.comments = [
        SupportComment("c1", r.userId, "zodiac", false, false, "Still happening", 1_765_000_000_500),
        SupportComment("c2", r.assigneeId, "kevin", true, true, "Repro'd on staging", 1_765_000_000_900),
    ];
    r.createdAt = 1_765_000_000_000;
    r.updatedAt = 1_765_000_000_900;
    r.resolvedAt = 0;
    auto b = r.toBson();
    const back = SupportIssueRecord.fromBson(b);
    assert(back == r);
    assert(b["body"].get!string == r.body_);
    assert(b["comments"][1]["internal"].get!bool == true);
}

@("fromBson tolerates missing optional fields")
unittest {
    auto b = Bson([
        "_id": Bson("abc"), "number": Bson(3L), "userId": Bson("u1"),
        "title": Bson("t"), "body": Bson("b"), "status": Bson("open"),
    ]);
    const r = SupportIssueRecord.fromBson(b);
    assert(r.id == "abc");
    assert(r.number == 3);
    assert(r.status == "open");
    assert(r.attachments.length == 0);
    assert(r.comments.length == 0);
    assert(r.assigneeId == "");
    assert(r.assigneeUsername == "");
    assert(r.resolvedAt == 0);
    assert(r.context == SupportIssueContext.init);
}

@("escapeRegex neutralises every metacharacter")
unittest {
    assert(escapeRegex("a.b*c") == "a\\.b\\*c");
    assert(escapeRegex("(x)[y]{z}|^$?+\\") == "\\(x\\)\\[y\\]\\{z\\}\\|\\^\\$\\?\\+\\\\");
    assert(escapeRegex("plain") == "plain");
}
