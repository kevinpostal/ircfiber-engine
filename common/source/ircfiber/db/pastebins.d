module ircfiber.db.pastebins;

import std.algorithm : count;
import std.uuid : randomUUID;
import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// One text snippet (pastebin); the body is stored inline in Mongo.
struct PasteRecord {
    /// Paste identifier (UUID string).
    string id;               // _id (UUID string)
    /// Owning user id.
    string userId;
    /// Network the paste belongs to.
    string networkId;
    /// Buffer (channel) the paste belongs to.
    string buffer;
    /// User-edited display name (may be empty).
    string name;             // user-edited display name (may be empty)
    /// Ace mode value, e.g. "text", "python".
    string syntax;           // ace mode value, e.g. "text", "python"
    /// Paste body text.
    string content;
    /// Display line count.
    long lines;
    /// Creation timestamp (unix ms).
    long createdAt;          // unix ms
    /// Soft-delete flag.
    bool deleted;

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(id), "userId": Bson(userId), "networkId": Bson(networkId),
            "buffer": Bson(buffer), "name": Bson(name), "syntax": Bson(syntax),
            "content": Bson(content), "lines": Bson(lines),
            "createdAt": Bson(createdAt), "deleted": Bson(deleted),
        ]);
    }

    /// Deserializes from Bson.
    static PasteRecord fromBson(Bson b) @trusted {
        PasteRecord r;
        r.id = b["_id"].get!string;
        r.userId = b["userId"].get!string;
        r.networkId = b["networkId"].get!string;
        r.buffer = b["buffer"].get!string;
        r.name = b["name"].get!string;
        r.syntax = b["syntax"].get!string;
        r.content = b["content"].get!string;
        r.lines = b["lines"].get!long;
        r.createdAt = b["createdAt"].get!long;
        r.deleted = b["deleted"].get!bool;
        return r;
    }
}

/// Counts display lines the way pastebin viewers do: newlines + 1.
long countLines(string content) {
    if (content.length == 0) return 1;
    return content.count('\n') + 1;
}

/// Persistence for text snippets; collection `pastebins`.
final class PastebinRepository {
    private MongoCollection collection;

    /// Constructs a repository bound to the pastebins collection.
    this() {
        collection = AppMongoConnection.getDb()["pastebins"];
        ensureIndexes();
    }

    private void ensureIndexes() @trusted {
        try {
            collection.createIndex(Bson(["userId": Bson(1), "createdAt": Bson(-1)]));
        } catch (Exception e) {
            logWarn("Failed to create pastebins index: %s", e.msg);
        }
    }

    /// Inserts a paste record.
    void insert(PasteRecord r) @trusted {
        collection.insertOne(r.toBson());
    }

    /// Offset-paginated page of a user's non-deleted snippets, newest first.
    PasteRecord[] pageByUser(string userId, int offset, int limit) @trusted {
        auto query = Bson(["userId": Bson(userId), "deleted": Bson(false)]);
        FindOptions opts;
        opts.sort = Bson(["createdAt": Bson(-1)]);
        opts.skip = offset;
        opts.limit = limit;
        PasteRecord[] result;
        foreach (doc; collection.find(query, opts)) result ~= PasteRecord.fromBson(doc);
        return result;
    }

    /// Count of a user's non-deleted snippets (for pagination).
    long countByUser(string userId) @trusted {
        auto query = Bson(["userId": Bson(userId), "deleted": Bson(false)]);
        return collection.countDocuments(query);
    }

    /// One of the user's non-deleted snippets, or PasteRecord.init if absent.
    PasteRecord getById(string userId, string id) @trusted {
        auto doc = collection.findOne(Bson([
            "_id": Bson(id), "userId": Bson(userId), "deleted": Bson(false),
        ]));
        if (doc.isNull) return PasteRecord.init;
        return PasteRecord.fromBson(doc);
    }

    /// Public fetch by id regardless of owner (for shared viewer). Returns init if deleted/not found.
    PasteRecord getByIdPublic(string id) @trusted {
        auto doc = collection.findOne(Bson([
            "_id": Bson(id), "deleted": Bson(false),
        ]));
        if (doc.isNull) return PasteRecord.init;
        return PasteRecord.fromBson(doc);
    }

    /// Updates name and syntax of the user's snippet. Returns false if not found/not theirs.
    bool updateMeta(string userId, string id, string name, string syntax) @trusted {
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "userId": Bson(userId), "deleted": Bson(false)]),
            Bson(["$set": Bson(["name": Bson(name), "syntax": Bson(syntax)])]));
        return res.matchedCount > 0;
    }

    /// Updates name, syntax, body and lines. Returns false if not found/not theirs.
    bool updateFull(string userId, string id, string name, string syntax, string content) @trusted {
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "userId": Bson(userId), "deleted": Bson(false)]),
            Bson(["$set": Bson(["name": Bson(name), "syntax": Bson(syntax), "content": Bson(content), "lines": Bson(countLines(content))])]));
        return res.matchedCount > 0;
    }

    /// Soft-deletes one of the user's snippets. Returns false if not found/not theirs.
    bool softDelete(string userId, string id) @trusted {
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "userId": Bson(userId)]),
            Bson(["$set": Bson(["deleted": Bson(true)])]));
        return res.modifiedCount > 0;
    }
}

@("PasteRecord round-trips through Bson")
unittest {
    PasteRecord r;
    r.id = randomUUID().toString();
    r.userId = randomUUID().toString();
    r.networkId = "net1";
    r.buffer = "#chan";
    r.name = "snippet.py";
    r.syntax = "python";
    r.content = "print('hi')\nprint('bye')";
    r.lines = 2;
    r.createdAt = 1_765_000_000_000;
    auto b = r.toBson();
    const back = PasteRecord.fromBson(b);
    assert(back == r);
    assert(b["deleted"].get!bool == false);
}

@("countLines counts newline-separated lines")
unittest {
    assert(countLines("") == 1);
    assert(countLines("one") == 1);
    assert(countLines("one\ntwo") == 2);
    assert(countLines("one\ntwo\n") == 3);
}
