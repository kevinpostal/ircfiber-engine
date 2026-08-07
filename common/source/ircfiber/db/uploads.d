module ircfiber.db.uploads;

import std.datetime : Clock;
import std.uuid : randomUUID;
import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// One uploaded file reference (the bytes live on postimages.org).
struct UploadRecord {
    string id;               // _id (UUID string)
    string userId;
    string networkId;
    string buffer;
    string filename;         // user-edited display name
    string originalFilename;
    string mimeType;
    long size;
    long width;
    long height;
    string pageUrl;
    string directUrl;
    string thumbUrl;
    long createdAt;          // unix ms
    bool deleted;

    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(id), "userId": Bson(userId), "networkId": Bson(networkId),
            "buffer": Bson(buffer), "filename": Bson(filename),
            "originalFilename": Bson(originalFilename), "mimeType": Bson(mimeType),
            "size": Bson(size), "width": Bson(width), "height": Bson(height),
            "pageUrl": Bson(pageUrl), "directUrl": Bson(directUrl),
            "thumbUrl": Bson(thumbUrl), "createdAt": Bson(createdAt),
            "deleted": Bson(deleted),
        ]);
    }

    static UploadRecord fromBson(Bson b) @trusted {
        UploadRecord r;
        r.id = b["_id"].get!string;
        r.userId = b["userId"].get!string;
        r.networkId = b["networkId"].get!string;
        r.buffer = b["buffer"].get!string;
        r.filename = b["filename"].get!string;
        r.originalFilename = b["originalFilename"].get!string;
        r.mimeType = b["mimeType"].get!string;
        r.size = b["size"].get!long;
        r.width = b["width"].get!long;
        r.height = b["height"].get!long;
        r.pageUrl = b["pageUrl"].get!string;
        r.directUrl = b["directUrl"].get!string;
        r.thumbUrl = b["thumbUrl"].get!string;
        r.createdAt = b["createdAt"].get!long;
        r.deleted = b["deleted"].get!bool;
        return r;
    }
}

/// Persistence for upload references; collection `uploads`.
final class UploadRepository {
    private MongoCollection collection;

    this() {
        collection = AppMongoConnection.getDb()["uploads"];
        ensureIndexes();
    }

    private void ensureIndexes() @trusted {
        try {
            collection.createIndex(Bson(["userId": Bson(1), "createdAt": Bson(-1)]));
        } catch (Exception e) {
            logWarn("Failed to create uploads index: %s", e.msg);
        }
    }

    void insert(UploadRecord r) @trusted {
        collection.insertOne(r.toBson());
    }

    /// Newest-first page of a user's non-deleted uploads.
    UploadRecord[] listByUser(string userId, long beforeMs, int limit) @trusted {
        auto query = Bson([
            "userId": Bson(userId),
            "deleted": Bson(false),
            "createdAt": Bson(["$lt": Bson(beforeMs)]),
        ]);
        FindOptions opts;
        opts.sort = Bson(["createdAt": Bson(-1)]);
        opts.limit = limit;
        UploadRecord[] result;
        foreach (doc; collection.find(query, opts)) result ~= UploadRecord.fromBson(doc);
        return result;
    }

    /// Offset-paginated page of a user's non-deleted uploads.
    UploadRecord[] pageByUser(string userId, int offset, int limit) @trusted {
        auto query = Bson(["userId": Bson(userId), "deleted": Bson(false)]);
        FindOptions opts;
        opts.sort = Bson(["createdAt": Bson(-1)]);
        opts.skip = offset;
        opts.limit = limit;
        UploadRecord[] result;
        foreach (doc; collection.find(query, opts)) result ~= UploadRecord.fromBson(doc);
        return result;
    }

    /// Count of a user's non-deleted uploads (for pagination).
    long countByUser(string userId) @trusted {
        auto query = Bson(["userId": Bson(userId), "deleted": Bson(false)]);
        return collection.countDocuments(query);
    }

    /// Fetches a single upload record by id, scoped to userId.
    /// Returns UploadRecord.init if not found or not owned by the user.
    /// Includes deleted records so callers can inspect URLs before hard-deleting.
    UploadRecord getById(string userId, string id) @trusted {
        auto doc = collection.findOne(Bson(["_id": Bson(id), "userId": Bson(userId)]));
        if (doc.isNull) return UploadRecord.init;
        return UploadRecord.fromBson(doc);
    }

    /// Count of ALL user uploads (including soft-deleted), for admin cleanup.
    long countAllByUser(string userId) @trusted {
        return collection.countDocuments(Bson(["userId": Bson(userId)]));
    }

    /// Returns ALL uploads for a user regardless of deleted status (admin use).
    UploadRecord[] listAllByUser(string userId) @trusted {
        auto query = Bson(["userId": Bson(userId)]);
        FindOptions opts;
        opts.sort = Bson(["createdAt": Bson(-1)]);
        UploadRecord[] result;
        foreach (doc; collection.find(query, opts)) result ~= UploadRecord.fromBson(doc);
        return result;
    }

    /// Paginated list of ALL uploads across all users (admin use).
    UploadRecord[] listAll(int offset, int limit) @trusted {
        FindOptions opts;
        opts.sort = Bson(["createdAt": Bson(-1)]);
        opts.skip = offset;
        opts.limit = limit;
        UploadRecord[] result;
        foreach (doc; collection.find(Bson.emptyObject, opts)) result ~= UploadRecord.fromBson(doc);
        return result;
    }

    /// Count all uploads across all users (admin use).
    long countAll() @trusted {
        return collection.countDocuments(Bson.emptyObject);
    }

    /// Permanently removes the upload document from MongoDB.
    /// Returns false if the document wasn't found or didn't belong to the user.
    /// Note: callers should remove the local file BEFORE calling this.
    bool hardDelete(string userId, string id) @trusted {
        auto res = collection.deleteOne(
            Bson(["_id": Bson(id), "userId": Bson(userId)]));
        return res.deletedCount > 0;
    }


}

@("UploadRecord round-trips through Bson")
unittest {
    UploadRecord r;
    r.id = randomUUID().toString();
    r.userId = randomUUID().toString();
    r.networkId = "net1";
    r.buffer = "#chan";
    r.filename = "cat.png";
    r.originalFilename = "IMG_001.png";
    r.mimeType = "image/png";
    r.size = 12345;
    r.pageUrl = "https://postimg.cc/A";
    r.directUrl = "https://i.postimg.cc/A/cat.png";
    r.createdAt = 1765000000000;
    auto b = r.toBson();
    auto back = UploadRecord.fromBson(b);
    assert(back == r);
    assert(b["deleted"].get!bool == false);
}
