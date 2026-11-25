module ircfiber.db.uploads;

import std.datetime : Clock;
import std.uuid : randomUUID;
import std.typecons : Nullable;
import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.upload_category : uploadOriginalNameExpression;

/// One uploaded file reference; bytes may be managed locally or legacy remote.
struct UploadRecord {
    /// Upload identifier (UUID string).
    string id;               // _id (UUID string)
    /// Owning user id.
    string userId;
    /// Network the upload belongs to.
    string networkId;
    /// Buffer (channel) the upload belongs to.
    string buffer;
    /// User-edited display name.
    string filename;         // user-edited display name
    /// Original client filename.
    string originalFilename;
    /// MIME type.
    string mimeType;
    /// File size in bytes.
    long size;
    /// Image width (0 when not an image).
    long width;
    /// Image height (0 when not an image).
    long height;
    /// Postimages page URL.
    string pageUrl;
    /// Direct image URL.
    string directUrl;
    /// Thumbnail URL.
    string thumbUrl;
    /// Creation timestamp (unix ms).
    long createdAt;          // unix ms
    /// Soft-delete flag.
    bool deleted;
    private Nullable!bool localProvenance;

    /// Explicit provenance; an absent legacy field must not become false on save.
    @property bool local() const { return localProvenance.get(false); }
    @property void local(bool value) { localProvenance = value; }
    @property bool hasLocalProvenance() const { return !localProvenance.isNull; }

    /// Serializes to Bson.
    Bson toBson() const @trusted {
        auto doc = Bson([
            "_id": Bson(id), "userId": Bson(userId), "networkId": Bson(networkId),
            "buffer": Bson(buffer), "filename": Bson(filename),
            "originalFilename": Bson(originalFilename), "mimeType": Bson(mimeType),
            "size": Bson(size), "width": Bson(width), "height": Bson(height),
            "pageUrl": Bson(pageUrl), "directUrl": Bson(directUrl),
            "thumbUrl": Bson(thumbUrl), "createdAt": Bson(createdAt),
            "deleted": Bson(deleted),
        ]);
        if (!localProvenance.isNull) doc["local"] = Bson(local);
        return doc;
    }

    /// Deserializes from Bson.
    static UploadRecord fromBson(Bson b) @trusted {
        UploadRecord r;
        r.id = b["_id"].get!string;
        r.userId = b["userId"].get!string;
        r.networkId = b["networkId"].get!string;
        r.buffer = b["buffer"].get!string;
        r.filename = b["filename"].get!string;
        r.originalFilename = b["originalFilename"].type == Bson.Type.string ? b["originalFilename"].get!string : "";
        r.mimeType = b["mimeType"].type == Bson.Type.string ? b["mimeType"].get!string : "";
        r.size = b["size"].get!long;
        r.width = b["width"].get!long;
        r.height = b["height"].get!long;
        r.pageUrl = b["pageUrl"].get!string;
        r.directUrl = b["directUrl"].get!string;
        r.thumbUrl = b["thumbUrl"].get!string;
        r.createdAt = b["createdAt"].get!long;
        r.deleted = b["deleted"].get!bool;
        if (b["local"].type != Bson.Type.undefined)
            r.local = b["local"].type == Bson.Type.bool_ && b["local"].get!bool;
        return r;
    }
}

/// Persistence for upload references; collection `uploads`.
final class UploadRepository {
    private MongoCollection collection;

    /// Constructs a repository bound to the uploads collection.
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

    /// Inserts an upload record.
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

    /// Live owner-scoped lookup for all library operations.
    UploadRecord getLiveById(string userId, string id) @trusted {
        auto doc = collection.findOne(liveFilter(userId, id));
        return doc.isNull ? UploadRecord.init : UploadRecord.fromBson(doc);
    }

    private Bson liveFilter(string userId, string id) @trusted {
        return Bson(["_id": Bson(id), "userId": Bson(userId), "deleted": Bson(false)]);
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

    /// Library deletion, unlike administrative hardDelete, excludes tombstones.
    bool hardDeleteLive(string userId, string id) @trusted {
        return collection.deleteOne(liveFilter(userId, id)).deletedCount > 0;
    }

    /// Metadata-only rename; freeze the legacy original-name fallback atomically.
    /// Matched rather than modified count makes an unchanged name successful.
    bool rename(string userId, string id, string filename) @trusted {
        auto fields = Bson([
            "filename": Bson(["$literal": Bson(filename)]),
            "originalFilename": uploadOriginalNameExpression(),
        ]);
        return collection.updateOne(liveFilter(userId, id),
            Bson([Bson(["$set": fields])])).matchedCount > 0;
    }

    /// Caller coordinates bytes under the shared filesystem lock; content never
    /// enters Mongo. Equal-size and unchanged updates still match successfully.
    bool updateContent(string userId, string id, string newFilename, long newSize) @trusted {
        auto fields = Bson([
            "filename": Bson(["$literal": Bson(newFilename)]),
            "size": Bson(newSize),
            "originalFilename": uploadOriginalNameExpression(),
        ]);
        return collection.updateOne(liveFilter(userId, id),
            Bson([Bson(["$set": fields])])).matchedCount > 0;
    }


}

@("UploadRepository.updateContent updates file content")
unittest {
    import ircfiber.testing.isolated_db : connectIsolatedTestMongo;
    if (!connectIsolatedTestMongo("UploadRepository.updateContent")) return;
    auto repo = new UploadRepository();
    UploadRecord r;
    r.id = randomUUID().toString();
    r.userId = randomUUID().toString();
    r.filename = "test.py";
    r.mimeType = "text/x-python";
    r.size = 10;
    r.directUrl = "http://localhost:8090/uploads/abc.py";
    r.createdAt = Clock.currTime.toUnixTime * 1000;
    repo.insert(r);
    scope(exit) repo.hardDelete(r.userId, r.id);
    bool ok = repo.updateContent(r.userId, r.id, "new.py", 11);
    assert(ok);
    auto fetched = repo.getById(r.userId, r.id);
    assert(fetched.filename == "new.py");
    assert(fetched.size == 11);
    assert(fetched.originalFilename == "test.py"); // final legacy fallback frozen
    assert(repo.updateContent(r.userId, r.id, "new.py", 11)); // true no-op
    assert(repo.updateContent(r.userId, r.id, "same.py", 11)); // equal-byte edit
    assert(repo.rename(r.userId, r.id, "$literal.py"));
    assert(repo.rename(r.userId, r.id, "$literal.py"));
    auto renamed = repo.getLiveById(r.userId, r.id);
    assert(renamed.filename == "$literal.py");
    assert(renamed.originalFilename == "test.py");
    assert(renamed.directUrl == r.directUrl && renamed.mimeType == r.mimeType);
    assert(!repo.rename(randomUUID().toString(), r.id, "other.py"));
    assert(!repo.hardDeleteLive(randomUUID().toString(), r.id));
    // Verify ownership check: wrong user should not update
    bool wrong = repo.updateContent(randomUUID().toString(), r.id, "x.py", 1);
    assert(!wrong);
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
    r.size = 12_345;
    r.pageUrl = "https://postimg.cc/A";
    r.directUrl = "https://i.postimg.cc/A/cat.png";
    r.createdAt = 1_765_000_000_000;
    auto b = r.toBson();
    const back = UploadRecord.fromBson(b);
    assert(back == r);
    assert(b["deleted"].get!bool == false);
    assert(b["local"].type == Bson.Type.undefined);
    assert(!back.hasLocalProvenance);
    r.local = true;
    auto managed = UploadRecord.fromBson(r.toBson());
    assert(managed.local && managed.hasLocalProvenance);
    r.local = false;
    auto remote = UploadRecord.fromBson(r.toBson());
    assert(!remote.local && remote.hasLocalProvenance);
    assert(remote.toBson()["local"].type == Bson.Type.bool_);
}

@("UploadRepository library mutations reject deleted records")
unittest {
    import ircfiber.testing.isolated_db : connectIsolatedTestMongo;
    if (!connectIsolatedTestMongo("UploadRepository.liveMutations")) return;
    auto repo = new UploadRepository();
    UploadRecord record;
    record.id = randomUUID().toString();
    record.userId = randomUUID().toString();
    record.filename = "deleted.txt";
    record.deleted = true;
    repo.insert(record);
    scope(exit) repo.hardDelete(record.userId, record.id);
    assert(repo.getLiveById(record.userId, record.id).id.length == 0);
    assert(!repo.updateContent(record.userId, record.id, "changed.txt", 0));
    assert(!repo.rename(record.userId, record.id, "changed.txt"));
    assert(!repo.hardDeleteLive(record.userId, record.id));
    assert(repo.getById(record.userId, record.id).filename == "deleted.txt");
}
