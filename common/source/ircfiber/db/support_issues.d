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

/// One hour in unix ms.
enum long SUPPORT_HOUR_MS = 3_600_000;
/// A trashed issue is purged by Mongo this long after it was trashed (TTL
/// index on the `purgeAt` date).
enum long SUPPORT_TRASH_RETENTION_MS = 30 * 24 * SUPPORT_HOUR_MS;

/// How long a waiting reporter may wait for a public staff reply at
/// `priority` before the issue counts as overdue.
long supportResponseSlaMs(string priority) pure nothrow @safe {
    switch (priority) {
        case "urgent": return 4 * SUPPORT_HOUR_MS;
        case "high": return 8 * SUPPORT_HOUR_MS;
        case "low": return 72 * SUPPORT_HOUR_MS;
        default: return 24 * SUPPORT_HOUR_MS;
    }
}

/// True for the statuses that end the conversation (`resolved`, `closed`).
bool isFinishedStatus(string status) pure nothrow @safe @nogc {
    return status == "resolved" || status == "closed";
}

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

/// One triage change on an issue (Bson array `history`, chronological).
/// `kind` is "created" (`to`: "web" | "admin" | "irc"), "status",
/// "priority", "assignee" (usernames; "" = unassigned), "trashed" or
/// "restored". Comments are not repeated here: they are the conversation.
struct SupportHistoryEntry {
    /// When (unix ms).
    long at;
    /// Admin username, the oper's nick for bot commands, or the reporter.
    string actor;
    /// See the struct doc.
    string kind;
    /// Value before the change ("" when not applicable).
    string from;
    /// Value after the change.
    string to;

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        return Bson([
            "at": Bson(at), "actor": Bson(actor), "kind": Bson(kind),
            "from": Bson(from), "to": Bson(to),
        ]);
    }

    /// Deserializes from Bson; missing fields keep their init value.
    static SupportHistoryEntry fromBson(Bson b) @trusted {
        SupportHistoryEntry h;
        h.at = bsonLong(b, "at");
        h.actor = bsonStr(b, "actor");
        h.kind = bsonStr(b, "kind");
        h.from = bsonStr(b, "from");
        h.to = bsonStr(b, "to");
        return h;
    }
}

/// Response-time and read-state bookkeeping, recomputed on every write
/// (`deskFieldsAfter`) and stored as flat fields on the issue document.
struct SupportDeskFields {
    /// Since when the reporter has been waiting for a public staff reply
    /// (unix ms); 0 = staff had the last word or the issue is finished.
    long awaitingStaffSince;
    /// `awaitingStaffSince` + the priority's response SLA; 0 = nothing owed.
    long slaDueAt;
    /// First public staff reply (unix ms); 0 = none yet.
    long firstResponseAt;
    /// Last change the reporter should notice — a public staff reply, a
    /// status change or staff filing the report for them (unix ms).
    long staffUpdatedAt;
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
    /// Response-time / read-state bookkeeping (flat Bson fields).
    SupportDeskFields desk;
    /// Last time the reporter opened the issue in Help & Feedback (unix
    /// ms); staff activity after it makes the issue unread for them.
    long reporterSeenAt;
    /// Triage changes, chronological.
    SupportHistoryEntry[] history;
    /// Moved to the trash (unix ms); 0 = live. Mongo purges a trashed issue
    /// `SUPPORT_TRASH_RETENTION_MS` later (TTL on `purgeAt`, which only the
    /// trash / restore updates write).
    long deletedAt;
    /// Admin who trashed it.
    string deletedBy;

    /// The reporter has not seen the latest staff activity.
    bool unreadByReporter() const pure nothrow @safe @nogc {
        return desk.staffUpdatedAt > reporterSeenAt;
    }

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
            "awaitingStaffSince": Bson(desk.awaitingStaffSince), "slaDueAt": Bson(desk.slaDueAt),
            "firstResponseAt": Bson(desk.firstResponseAt), "staffUpdatedAt": Bson(desk.staffUpdatedAt),
            "reporterSeenAt": Bson(reporterSeenAt),
            "history": Bson(history.map!(h => h.toBson()).array),
            "deletedAt": Bson(deletedAt), "deletedBy": Bson(deletedBy),
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
        r.desk.awaitingStaffSince = bsonLong(b, "awaitingStaffSince");
        r.desk.slaDueAt = bsonLong(b, "slaDueAt");
        r.desk.firstResponseAt = bsonLong(b, "firstResponseAt");
        r.desk.staffUpdatedAt = bsonLong(b, "staffUpdatedAt");
        r.reporterSeenAt = bsonLong(b, "reporterSeenAt");
        auto hist = b["history"];
        if (hist.type == Bson.Type.array)
            foreach (item; hist.byValue)
                if (item.type == Bson.Type.object) r.history ~= SupportHistoryEntry.fromBson(item);
        r.deletedAt = bsonLong(b, "deletedAt");
        r.deletedBy = bsonStr(b, "deletedBy");
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
    /// Exact priority.
    string priority;
    /// Only issues nobody is assigned to (wins over `assigneeId`).
    bool unassigned;
    /// Only issues whose response deadline passed before `nowMs`.
    bool overdue;
    /// Reference time for `overdue` (unix ms).
    long nowMs;
    /// The trash instead of live issues.
    bool trashed;
    /// "newest" (default) | "oldest" | "updated" | "due" (issues someone is
    /// waiting on only, earliest deadline first).
    string sort;
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

/// Desk fields after one write to an issue. `before` / `beforeStatus`:
/// the issue's values before it; `staff`: the actor works the desk (admin
/// pane or a bot oper command); `publicComment`: the write adds a reply the
/// reporter can read; `status` / `priority`: the values after it.
///
/// A public staff reply ends the reporter's wait and stamps the first
/// response; a reporter reply starts a wait (an older one keeps running);
/// a finished issue owes nothing; a public staff reply or a staff status
/// change is news for the reporter (`staffUpdatedAt`).
SupportDeskFields deskFieldsAfter(const SupportDeskFields before, string beforeStatus, bool staff,
        bool publicComment, string status, string priority, long now) pure nothrow @safe {
    SupportDeskFields d = before;
    if (publicComment) {
        if (staff) {
            d.awaitingStaffSince = 0;
            if (d.firstResponseAt == 0) d.firstResponseAt = now;
        } else if (d.awaitingStaffSince == 0) {
            d.awaitingStaffSince = now;
        }
    }
    if (isFinishedStatus(status)) d.awaitingStaffSince = 0;
    if (staff && (publicComment || status != beforeStatus)) d.staffUpdatedAt = now;
    d.slaDueAt = d.awaitingStaffSince ? d.awaitingStaffSince + supportResponseSlaMs(priority) : 0;
    return d;
}

/// Desk fields and read marker of a new issue `r` (its `priority` must be
/// set). `reporterWaits`: someone outside the staff asked — Help &
/// Feedback, or staff filing on a user's behalf; an oper's own `!new` /
/// `!bug` owes nobody a reply. `staffFiled`: the reporter did not file it
/// themselves, so it starts unread for them.
void initDesk(ref SupportIssueRecord r, bool reporterWaits, bool staffFiled, long now) pure nothrow @safe {
    r.desk = SupportDeskFields.init;
    if (reporterWaits) {
        r.desk.awaitingStaffSince = now;
        r.desk.slaDueAt = now + supportResponseSlaMs(r.priority);
    }
    r.desk.staffUpdatedAt = staffFiled ? now : 0;
    r.reporterSeenAt = staffFiled ? 0 : now;
}

/// Desk fields rebuilt from the conversation, for issues written before
/// the fields existed (one-time migration in `SupportIssueRepository`).
/// Status changes were not recorded then; `resolvedAt` stands in for the
/// last one.
SupportDeskFields deskFieldsReplayed(const SupportIssueRecord r) pure nothrow @safe {
    SupportDeskFields d;
    long awaiting = r.createdAt;
    foreach (const ref c; r.comments) {
        if (c.internal) continue;
        if (c.fromAdmin) {
            awaiting = 0;
            if (d.firstResponseAt == 0) d.firstResponseAt = c.createdAt;
            if (c.createdAt > d.staffUpdatedAt) d.staffUpdatedAt = c.createdAt;
        } else if (awaiting == 0) {
            awaiting = c.createdAt;
        }
    }
    if (isFinishedStatus(r.status)) {
        awaiting = 0;
        if (r.resolvedAt > d.staffUpdatedAt) d.staffUpdatedAt = r.resolvedAt;
    }
    d.awaitingStaffSince = awaiting;
    d.slaDueAt = awaiting ? awaiting + supportResponseSlaMs(r.priority) : 0;
    return d;
}

/// The reporter's read marker rebuilt for the same migration: they saw the
/// issue when they filed it and every time they replied.
long reporterSeenReplayed(const SupportIssueRecord r) pure nothrow @safe {
    long seen = r.createdAt;
    foreach (const ref c; r.comments)
        if (!c.fromAdmin && !c.internal && c.createdAt > seen) seen = c.createdAt;
    return seen;
}

/// History lines for one triage write — one per field that changes.
SupportHistoryEntry[] triageHistory(const SupportIssueRecord before, string status, string priority,
        string assigneeId, string assigneeUsername, string actor, long now) pure @safe {
    SupportHistoryEntry[] h;
    if (status != before.status) h ~= SupportHistoryEntry(now, actor, "status", before.status, status);
    if (priority != before.priority) h ~= SupportHistoryEntry(now, actor, "priority", before.priority, priority);
    if (assigneeId != before.assigneeId)
        h ~= SupportHistoryEntry(now, actor, "assignee", before.assigneeUsername, assigneeUsername);
    return h;
}

/// One write to an issue, built by `supportPatch` so every path keeps
/// `resolvedAt`, the history and the desk fields in step.
/// `SupportIssueRepository.apply` `$set`s the scalars and `$push`es
/// `comments` / `history`.
struct SupportIssuePatch {
    string status;
    string priority;
    string assigneeId;
    string assigneeUsername;
    long resolvedAt;
    long updatedAt;
    SupportDeskFields desk;
    /// Reporter read marker; 0 = leave unchanged.
    long reporterSeenAt;
    SupportComment[] comments;
    SupportHistoryEntry[] history;
}

/// The write for one action on `before` by `actor` (`staff`: works the
/// desk). Triage values are the ones after the action — pass `before`'s to
/// keep one. `resolvedAt` is stamped on the first resolve/close and
/// cleared on reopen; every changed triage field gets a history line; the
/// desk fields follow `deskFieldsAfter`.
SupportIssuePatch supportPatch(const SupportIssueRecord before, string actor, bool staff, long now,
        string status, string priority, string assigneeId, string assigneeUsername,
        SupportComment[] comments = null) pure @safe {
    SupportIssuePatch p;
    p.status = status;
    p.priority = priority;
    p.assigneeId = assigneeId;
    p.assigneeUsername = assigneeUsername;
    p.updatedAt = now;
    p.resolvedAt = isFinishedStatus(status) ? (before.resolvedAt ? before.resolvedAt : now) : 0;
    p.comments = comments;
    bool publicComment = false;
    foreach (const ref c; comments) if (!c.internal) publicComment = true;
    p.history = triageHistory(before, status, priority, assigneeId, assigneeUsername, actor, now);
    p.desk = deskFieldsAfter(before.desk, before.status, staff, publicComment, status, priority, now);
    return p;
}

/// Set once per process by the desk-field migration.
private __gshared bool supportDeskMigrated;

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
        migrateDeskFields();
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
        try {
            // Trash purge: Mongo deletes an issue once its `purgeAt` date —
            // written only while the issue is trashed — has passed.
            IndexOptions ttl;
            ttl.expireAfterSeconds = 0;
            collection.createIndex(Bson(["purgeAt": Bson(1)]), ttl);
        } catch (Exception e) {
            logWarn("Failed to create support_issues purgeAt TTL index: %s", e.msg);
        }
    }

    /// Fills the desk fields on issues written before they existed (see
    /// `deskFieldsReplayed`). Once per process; idempotent, so two first
    /// requests racing each other write the same values.
    private void migrateDeskFields() @trusted {
        if (supportDeskMigrated) return;
        supportDeskMigrated = true;
        try {
            SupportIssueRecord[] todo;
            foreach (doc; collection.find(Bson(["slaDueAt": Bson(["$exists": Bson(false)])])))
                todo ~= SupportIssueRecord.fromBson(doc);
            foreach (ref r; todo) {
                const d = deskFieldsReplayed(r);
                collection.updateOne(Bson(["_id": Bson(r.id)]), Bson(["$set": Bson([
                    "awaitingStaffSince": Bson(d.awaitingStaffSince), "slaDueAt": Bson(d.slaDueAt),
                    "firstResponseAt": Bson(d.firstResponseAt), "staffUpdatedAt": Bson(d.staffUpdatedAt),
                    "reporterSeenAt": Bson(reporterSeenReplayed(r)),
                    "deletedAt": Bson(0L), "deletedBy": Bson(""),
                ])]));
            }
            if (todo.length) logInfo("support_issues: filled desk fields on %d issue(s)", todo.length);
        } catch (Exception e) {
            supportDeskMigrated = false;
            logWarn("support_issues: desk field migration failed: %s", e.msg);
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

    /// Live issue by human number, or init when absent or trashed.
    SupportIssueRecord getByNumber(long n) @trusted {
        auto doc = collection.findOne(Bson(["number": Bson(n), "deletedAt": liveMatch()]));
        if (doc.isNull) return SupportIssueRecord.init;
        return SupportIssueRecord.fromBson(doc);
    }

    /// One of the user's own live issues, or init when absent / not theirs / trashed.
    SupportIssueRecord getByIdForUser(string userId, string id) @trusted {
        auto doc = collection.findOne(Bson(["_id": Bson(id), "userId": Bson(userId), "deletedAt": liveMatch()]));
        if (doc.isNull) return SupportIssueRecord.init;
        return SupportIssueRecord.fromBson(doc);
    }

    /// Offset-paginated page of a user's live issues, newest first.
    SupportIssueRecord[] pageByUser(string userId, int offset, int limit) @trusted {
        return fetchPage(Bson(["userId": Bson(userId), "deletedAt": liveMatch()]), offset, limit, sortSpec(""));
    }

    /// Count of a user's live issues.
    long countByUser(string userId) @trusted {
        return collection.countDocuments(Bson(["userId": Bson(userId), "deletedAt": liveMatch()]));
    }

    /// Count of a user's issues created at or after `sinceMs` (rate limit).
    long countByUserSince(string userId, long sinceMs) @trusted {
        return collection.countDocuments(Bson([
            "userId": Bson(userId), "createdAt": Bson(["$gte": Bson(sinceMs)]),
        ]));
    }

    /// Offset-paginated admin listing in `f.sort` order.
    SupportIssueRecord[] pageAdmin(SupportAdminFilter f, int offset, int limit) @trusted {
        return fetchPage(buildAdminQuery(f), offset, limit, sortSpec(f.sort));
    }

    /// Total matching the admin filter.
    long countAdmin(SupportAdminFilter f) @trusted {
        return collection.countDocuments(buildAdminQuery(f));
    }

    /// Live issue count per status, keyed by wire value; every status is present.
    long[string] countByStatus() @trusted {
        long[string] counts;
        foreach (s; supportStatuses)
            counts[s] = collection.countDocuments(Bson(["status": Bson(s), "deletedAt": liveMatch()]));
        return counts;
    }

    /// Live issues whose response deadline passed before `nowMs`.
    long countOverdue(long nowMs) @trusted {
        return collection.countDocuments(Bson([
            "deletedAt": liveMatch(), "slaDueAt": Bson(["$gt": Bson(0L), "$lt": Bson(nowMs)]),
        ]));
    }

    /// Issues in the trash.
    long countTrashed() @trusted {
        return collection.countDocuments(Bson(["deletedAt": Bson(["$gt": Bson(0L)])]));
    }

    /// Newest live issues whose status is in `statuses` (empty = any), for the bot.
    SupportIssueRecord[] recent(string[] statuses, int limit) @trusted {
        Bson query = Bson(["deletedAt": liveMatch()]);
        if (statuses.length)
            query["status"] = Bson(["$in": Bson(statuses.map!(s => Bson(s)).array)]);
        return fetchPage(query, 0, limit, sortSpec(""));
    }

    /// Writes `p` (see `supportPatch`) to a live issue. Returns false when
    /// the issue does not exist or is in the trash.
    bool apply(string id, const ref SupportIssuePatch p) @trusted {
        Bson set = Bson([
            "status": Bson(p.status), "priority": Bson(p.priority),
            "assigneeId": Bson(p.assigneeId), "assigneeUsername": Bson(p.assigneeUsername),
            "resolvedAt": Bson(p.resolvedAt), "updatedAt": Bson(p.updatedAt),
            "awaitingStaffSince": Bson(p.desk.awaitingStaffSince), "slaDueAt": Bson(p.desk.slaDueAt),
            "firstResponseAt": Bson(p.desk.firstResponseAt), "staffUpdatedAt": Bson(p.desk.staffUpdatedAt),
        ]);
        if (p.reporterSeenAt) set["reporterSeenAt"] = Bson(p.reporterSeenAt);
        Bson update = Bson(["$set": set]);
        if (p.comments.length || p.history.length) {
            Bson push = Bson.emptyObject;
            if (p.comments.length)
                push["comments"] = Bson(["$each": Bson(p.comments.map!(c => c.toBson()).array)]);
            if (p.history.length)
                push["history"] = Bson(["$each": Bson(p.history.map!(h => h.toBson()).array)]);
            update["$push"] = push;
        }
        auto res = collection.updateOne(Bson(["_id": Bson(id), "deletedAt": liveMatch()]), update);
        return res.matchedCount > 0;
    }

    /// Records that the reporter looked at their issue. Returns false when
    /// it is absent, not theirs or trashed.
    bool markSeen(string userId, string id, long now) @trusted {
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "userId": Bson(userId), "deletedAt": liveMatch()]),
            Bson(["$set": Bson(["reporterSeenAt": Bson(now)])]));
        return res.matchedCount > 0;
    }

    /// The user's live issues with staff activity they have not seen yet.
    long countUnreadForUser(string userId) @trusted {
        return collection.countDocuments(Bson([
            "userId": Bson(userId), "deletedAt": liveMatch(),
            "$expr": Bson(["$gt": Bson([Bson("$staffUpdatedAt"), Bson("$reporterSeenAt")])]),
        ]));
    }

    /// Moves a live issue to the trash; Mongo purges it
    /// `SUPPORT_TRASH_RETENTION_MS` later. Returns false when absent or
    /// already trashed.
    bool trash(string id, string actor, long now) @trusted {
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "deletedAt": liveMatch()]),
            Bson([
                "$set": Bson([
                    "deletedAt": Bson(now), "deletedBy": Bson(actor), "updatedAt": Bson(now),
                    "purgeAt": Bson(BsonDate(now + SUPPORT_TRASH_RETENTION_MS)),
                ]),
                "$push": Bson(["history": SupportHistoryEntry(now, actor, "trashed", "", "").toBson()]),
            ]));
        return res.matchedCount > 0;
    }

    /// Takes an issue back out of the trash. Returns false when absent or not trashed.
    bool restore(string id, string actor, long now) @trusted {
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "deletedAt": Bson(["$gt": Bson(0L)])]),
            Bson([
                "$set": Bson(["deletedAt": Bson(0L), "deletedBy": Bson(""), "updatedAt": Bson(now)]),
                "$unset": Bson(["purgeAt": Bson("")]),
                "$push": Bson(["history": SupportHistoryEntry(now, actor, "restored", "", "").toBson()]),
            ]));
        return res.matchedCount > 0;
    }

    /// Deletes a trashed issue now instead of at its purge date. Returns
    /// false when absent or not trashed — a live issue is never deleted.
    bool purge(string id) @trusted {
        auto res = collection.deleteOne(Bson(["_id": Bson(id), "deletedAt": Bson(["$gt": Bson(0L)])]));
        return res.deletedCount > 0;
    }

    private SupportIssueRecord[] fetchPage(Bson query, int offset, int limit, Bson sort) @trusted {
        FindOptions opts;
        opts.sort = sort;
        opts.skip = offset;
        opts.limit = limit;
        SupportIssueRecord[] result;
        foreach (doc; collection.find(query, opts)) result ~= SupportIssueRecord.fromBson(doc);
        return result;
    }

    /// Single-key sort for an admin `sort` value (an AA literal with several
    /// keys has no defined key order).
    private static Bson sortSpec(string sort) @trusted {
        switch (sort) {
            case "oldest": return Bson(["createdAt": Bson(1)]);
            case "updated": return Bson(["updatedAt": Bson(-1)]);
            case "due": return Bson(["slaDueAt": Bson(1)]);
            default: return Bson(["createdAt": Bson(-1)]);
        }
    }

    /// Matches live issues. `deletedAt` is absent on issues written before
    /// the trash existed, so "not > 0" rather than "== 0".
    private static Bson liveMatch() @trusted {
        return Bson(["$not": Bson(["$gt": Bson(0L)])]);
    }

    private static Bson buildAdminQuery(SupportAdminFilter f) @trusted {
        Bson query = Bson.emptyObject;
        query["deletedAt"] = f.trashed ? Bson(["$gt": Bson(0L)]) : liveMatch();
        if (f.statuses.length)
            query["status"] = Bson(["$in": Bson(f.statuses.map!(s => Bson(s)).array)]);
        if (f.kind.length) query["kind"] = Bson(f.kind);
        if (f.priority.length) query["priority"] = Bson(f.priority);
        if (f.unassigned) query["assigneeId"] = Bson("");
        else if (f.assigneeId.length) query["assigneeId"] = Bson(f.assigneeId);
        if (f.overdue) query["slaDueAt"] = Bson(["$gt": Bson(0L), "$lt": Bson(f.nowMs)]);
        else if (f.sort == "due") query["slaDueAt"] = Bson(["$gt": Bson(0L)]);
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
    r.desk = SupportDeskFields(1_765_000_000_100, 1_765_086_400_100, 1_765_000_000_900, 1_765_000_000_900);
    r.reporterSeenAt = 1_765_000_000_500;
    r.history = [SupportHistoryEntry(1_765_000_000_900, "kevin", "status", "open", "in_progress")];
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
    assert(r.desk == SupportDeskFields.init);
    assert(r.history.length == 0);
    assert(r.deletedAt == 0 && !r.unreadByReporter());
}

@("escapeRegex neutralises every metacharacter")
unittest {
    assert(escapeRegex("a.b*c") == "a\\.b\\*c");
    assert(escapeRegex("(x)[y]{z}|^$?+\\") == "\\(x\\)\\[y\\]\\{z\\}\\|\\^\\$\\?\\+\\\\");
    assert(escapeRegex("plain") == "plain");
}

@("supportResponseSlaMs: tighter deadlines for higher priority")
unittest {
    assert(supportResponseSlaMs("urgent") == 4 * SUPPORT_HOUR_MS);
    assert(supportResponseSlaMs("high") == 8 * SUPPORT_HOUR_MS);
    assert(supportResponseSlaMs("normal") == 24 * SUPPORT_HOUR_MS);
    assert(supportResponseSlaMs("low") == 72 * SUPPORT_HOUR_MS);
    assert(supportResponseSlaMs("") == 24 * SUPPORT_HOUR_MS, "unknown priority uses the normal SLA");
}

@("deskFieldsAfter: replies, notes and status changes move the wait the way staff expect")
unittest {
    enum t0 = 1_765_000_000_000L, t1 = t0 + 60_000, t2 = t0 + 120_000;
    SupportDeskFields waiting;
    waiting.awaitingStaffSince = t0;
    waiting.slaDueAt = t0 + supportResponseSlaMs("normal");

    // A public staff reply settles the wait, stamps the first response and is news for the reporter.
    auto r1 = deskFieldsAfter(waiting, "open", true, true, "open", "normal", t1);
    assert(r1.awaitingStaffSince == 0 && r1.slaDueAt == 0);
    assert(r1.firstResponseAt == t1 && r1.staffUpdatedAt == t1);

    // A later reply keeps the first-response time.
    auto r2 = deskFieldsAfter(r1, "open", true, true, "open", "normal", t2);
    assert(r2.firstResponseAt == t1 && r2.staffUpdatedAt == t2);

    // The reporter answers: a new wait starts with the current priority's deadline.
    auto r3 = deskFieldsAfter(r1, "open", false, true, "open", "high", t2);
    assert(r3.awaitingStaffSince == t2 && r3.slaDueAt == t2 + supportResponseSlaMs("high"));
    assert(r3.staffUpdatedAt == t1, "the reporter's own reply is not news to them");

    // A reporter follow-up while already waiting keeps the original start.
    assert(deskFieldsAfter(waiting, "open", false, true, "open", "normal", t2).awaitingStaffSince == t0);

    // An internal note changes nothing.
    assert(deskFieldsAfter(waiting, "open", true, false, "open", "normal", t1) == waiting);

    // Resolving without a reply ends the wait and is news; a priority change re-derives the deadline only.
    auto r6 = deskFieldsAfter(waiting, "open", true, false, "resolved", "normal", t1);
    assert(r6.awaitingStaffSince == 0 && r6.slaDueAt == 0 && r6.staffUpdatedAt == t1);
    auto r7 = deskFieldsAfter(waiting, "open", true, false, "open", "urgent", t1);
    assert(r7.slaDueAt == t0 + supportResponseSlaMs("urgent") && r7.staffUpdatedAt == 0);
}

@("supportPatch: resolvedAt, history lines and comments follow the action")
unittest {
    enum t0 = 1_765_000_000_000L, t1 = t0 + 60_000;
    SupportIssueRecord r;
    r.status = "open";
    r.priority = "normal";
    r.createdAt = t0;
    r.desk.awaitingStaffSince = t0;
    r.desk.slaDueAt = t0 + supportResponseSlaMs("normal");

    auto done = supportPatch(r, "kevin", true, t1, "resolved", "high", "a1", "alice");
    assert(done.resolvedAt == t1);
    assert(done.history == [
        SupportHistoryEntry(t1, "kevin", "status", "open", "resolved"),
        SupportHistoryEntry(t1, "kevin", "priority", "normal", "high"),
        SupportHistoryEntry(t1, "kevin", "assignee", "", "alice"),
    ]);
    assert(done.desk.awaitingStaffSince == 0 && done.desk.staffUpdatedAt == t1);

    // Already resolved: the first resolve time is kept; a reporter reopen clears it and starts a wait.
    r.status = "resolved";
    r.resolvedAt = t0;
    r.desk = SupportDeskFields.init;
    assert(supportPatch(r, "kevin", true, t1, "closed", r.priority, "", "").resolvedAt == t0);
    auto c = SupportComment("c1", "u1", "rep", false, false, "still broken", t1);
    auto reopen = supportPatch(r, "rep", false, t1, "open", r.priority, "", "", [c]);
    assert(reopen.resolvedAt == 0 && reopen.comments == [c]);
    assert(reopen.history == [SupportHistoryEntry(t1, "rep", "status", "resolved", "open")]);
    assert(reopen.desk.awaitingStaffSince == t1);

    // An internal note keeps the triage and records no history.
    r.status = "open";
    r.resolvedAt = 0;
    r.desk.awaitingStaffSince = t0;
    r.desk.slaDueAt = t0 + supportResponseSlaMs("normal");
    auto note = SupportComment("n1", "a1", "alice", true, true, "repro'd", t1);
    auto noted = supportPatch(r, "alice", true, t1, r.status, r.priority, r.assigneeId, r.assigneeUsername, [note]);
    assert(noted.history.length == 0 && noted.desk == r.desk);
}

@("initDesk: who waits and who has news on a new issue")
unittest {
    enum t0 = 1_765_000_000_000L;
    SupportIssueRecord web;
    web.priority = "normal";
    initDesk(web, true, false, t0);
    assert(web.desk.awaitingStaffSince == t0 && web.desk.slaDueAt == t0 + supportResponseSlaMs("normal"));
    assert(!web.unreadByReporter(), "the reporter has seen what they filed");

    SupportIssueRecord forUser;
    forUser.priority = "urgent";
    initDesk(forUser, true, true, t0);
    assert(forUser.unreadByReporter(), "a report staff filed for a user starts unread for them");

    SupportIssueRecord operTask;
    operTask.priority = "normal";
    initDesk(operTask, false, false, t0);
    assert(operTask.desk.awaitingStaffSince == 0 && operTask.desk.slaDueAt == 0,
        "an oper's own task owes nobody a reply");
}

@("deskFieldsReplayed: the migration rebuilds waits and read state from the conversation")
unittest {
    enum t0 = 1_765_000_000_000L;
    SupportIssueRecord r;
    r.status = "open";
    r.priority = "normal";
    r.createdAt = t0;
    r.comments = [
        SupportComment("c1", "a1", "alice", true, true, "internal", t0 + 1),
        SupportComment("c2", "a1", "alice", true, false, "try X", t0 + 2),
        SupportComment("c3", "u1", "rep", false, false, "X failed", t0 + 3),
        SupportComment("c4", "u1", "rep", false, false, "any news?", t0 + 4),
    ];
    auto d = deskFieldsReplayed(r);
    assert(d.firstResponseAt == t0 + 2 && d.staffUpdatedAt == t0 + 2);
    assert(d.awaitingStaffSince == t0 + 3, "waiting since the first unanswered reporter message");
    assert(reporterSeenReplayed(r) == t0 + 4);

    r.status = "resolved";
    r.resolvedAt = t0 + 10;
    auto f = deskFieldsReplayed(r);
    assert(f.awaitingStaffSince == 0 && f.slaDueAt == 0 && f.staffUpdatedAt == t0 + 10);

    SupportIssueRecord fresh;
    fresh.status = "open";
    fresh.priority = "high";
    fresh.createdAt = t0;
    assert(deskFieldsReplayed(fresh).awaitingStaffSince == t0, "an unanswered report waits since filing");
}
