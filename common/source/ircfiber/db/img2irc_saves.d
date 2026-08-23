module ircfiber.db.img2irc_saves;

import std.datetime : Clock;
import std.uuid : randomUUID;
import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import vibe.data.bson;
import vibe.data.json : Json, parseJsonString, serializeToJson;
import vibe.core.log;
import ircfiber.db.mongo : AppMongoConnection;

/// One saved IRC art conversion.
struct Img2IrcSaveRecord {
    string id;               // _id UUID
    string userId;
    string networkId;
    string buffer;
    string name;             // user-editable title
    string originalFilename;
    string originalMime;
    long   originalSize;
    string originalUrl;      // /uploads/img2irc/<uuid>.<ext>
    string thumbnailUrl;     // /uploads/img2irc/thumbs/<uuid>.png
    string art;              // full IRC art text with \x03/\x04 codes
    Json   params;           // serialized Img2IrcOptions
    long   createdAt;        // unix ms
    long   updatedAt;        // unix ms
    bool   deleted;

    Bson toBson() const @trusted {
        return Bson([
            "_id": Bson(id), "userId": Bson(userId), "networkId": Bson(networkId),
            "buffer": Bson(buffer), "name": Bson(name),
            "originalFilename": Bson(originalFilename), "originalMime": Bson(originalMime),
            "originalSize": Bson(originalSize), "originalUrl": Bson(originalUrl),
            "thumbnailUrl": Bson(thumbnailUrl), "art": Bson(art),
            "params": Bson(params.toString()),
            "createdAt": Bson(createdAt), "updatedAt": Bson(updatedAt),
            "deleted": Bson(deleted),
        ]);
    }

    static Img2IrcSaveRecord fromBson(Bson b) @trusted {
        Img2IrcSaveRecord r;
        r.id = b["_id"].get!string;
        r.userId = b["userId"].get!string;
        r.networkId = b["networkId"].get!string;
        r.buffer = b["buffer"].get!string;
        r.name = b["name"].get!string;
        r.originalFilename = b["originalFilename"].get!string;
        r.originalMime = b["originalMime"].get!string;
        r.originalSize = b["originalSize"].get!long;
        r.originalUrl = b["originalUrl"].get!string;
        r.thumbnailUrl = b["thumbnailUrl"].get!string;
        r.art = b["art"].get!string;
        // params stored as JSON string
        auto pStr = b["params"].get!string;
        try {
            if (pStr.length > 0) r.params = parseJsonString(pStr);
            else r.params = Json.emptyObject;
        } catch (Exception) {
            r.params = Json.emptyObject;
        }
        r.createdAt = b["createdAt"].get!long;
        // updatedAt may be missing on legacy docs
        try { r.updatedAt = b["updatedAt"].get!long; } catch (Exception) { r.updatedAt = r.createdAt; }
        r.deleted = b["deleted"].get!bool;
        return r;
    }
}

/// Persistence for IRC art saves; collection `img2irc_saves`.
final class Img2IrcSaveRepository {
    private MongoCollection collection;

    this() {
        collection = AppMongoConnection.getDb()["img2irc_saves"];
        ensureIndexes();
    }

    private void ensureIndexes() @trusted {
        try {
            collection.createIndex(Bson(["userId": Bson(1), "createdAt": Bson(-1)]));
        } catch (Exception e) {
            logWarn("Failed to create img2irc_saves index: %s", e.msg);
        }
    }

    void insert(Img2IrcSaveRecord r) @trusted {
        collection.insertOne(r.toBson());
    }

    Img2IrcSaveRecord[] pageByUser(string userId, int offset, int limit) @trusted {
        auto query = Bson(["userId": Bson(userId), "deleted": Bson(false)]);
        FindOptions opts;
        opts.sort = Bson(["createdAt": Bson(-1)]);
        opts.skip = offset;
        opts.limit = limit;
        Img2IrcSaveRecord[] result;
        foreach (doc; collection.find(query, opts)) result ~= Img2IrcSaveRecord.fromBson(doc);
        return result;
    }

    long countByUser(string userId) @trusted {
        auto query = Bson(["userId": Bson(userId), "deleted": Bson(false)]);
        return collection.countDocuments(query);
    }

    Img2IrcSaveRecord getById(string userId, string id) @trusted {
        auto doc = collection.findOne(Bson(["_id": Bson(id), "userId": Bson(userId), "deleted": Bson(false)]));
        if (doc.isNull) return Img2IrcSaveRecord.init;
        return Img2IrcSaveRecord.fromBson(doc);
    }

    bool hardDelete(string userId, string id) @trusted {
        auto res = collection.deleteOne(Bson(["_id": Bson(id), "userId": Bson(userId)]));
        return res.deletedCount > 0;
    }

    bool update(string userId, string id, string name, string art, Json params, long updatedAt) @trusted {
        Bson setDoc;
        setDoc["name"] = Bson(name);
        setDoc["art"] = Bson(art);
        setDoc["params"] = Bson(params.toString());
        setDoc["updatedAt"] = Bson(updatedAt);
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "userId": Bson(userId), "deleted": Bson(false)]),
            Bson(["$set": setDoc]));
        return res.matchedCount > 0;
    }

    bool updateWithFiles(string userId, string id, string name, string art, Json params, string originalUrl, string thumbnailUrl, long updatedAt) @trusted {
        Bson setDoc;
        setDoc["name"] = Bson(name);
        setDoc["art"] = Bson(art);
        setDoc["params"] = Bson(params.toString());
        if (originalUrl.length > 0) setDoc["originalUrl"] = Bson(originalUrl);
        if (thumbnailUrl.length > 0) setDoc["thumbnailUrl"] = Bson(thumbnailUrl);
        setDoc["updatedAt"] = Bson(updatedAt);
        auto res = collection.updateOne(
            Bson(["_id": Bson(id), "userId": Bson(userId), "deleted": Bson(false)]),
            Bson(["$set": setDoc]));
        return res.matchedCount > 0;
    }
}

@("Img2IrcSaveRecord round-trips through Bson")
unittest {
    Img2IrcSaveRecord r;
    r.id = randomUUID().toString();
    r.userId = randomUUID().toString();
    r.networkId = "net1";
    r.buffer = "#chan";
    r.name = "My Art";
    r.originalFilename = "cat.png";
    r.originalMime = "image/png";
    r.originalSize = 12345;
    r.originalUrl = "/uploads/img2irc/abc.png";
    r.thumbnailUrl = "/uploads/img2irc/thumbs/abc.png";
    r.art = "\x0312hello\x0f world";
    r.params = parseJsonString(`{"width":60,"renderMode":"ansi"}`);
    r.createdAt = 1_765_000_000_000;
    r.updatedAt = 1_765_000_000_001;
    auto b = r.toBson();
    const back = Img2IrcSaveRecord.fromBson(b);
    assert(back.id == r.id);
    assert(back.userId == r.userId);
    assert(back.name == r.name);
    assert(back.art == r.art);
    assert(back.params["width"].get!long == 60);
    assert(back.createdAt == r.createdAt);
    assert(back.updatedAt == r.updatedAt);
    assert(back.deleted == false);
}
