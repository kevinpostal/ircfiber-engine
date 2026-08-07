module ircfiber.web.admin.uploads;

import std.uuid : parseUUID;
import std.string : strip, indexOf;
import std.conv : to;
import std.file : remove;
import std.path : buildPath;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse, render;
import vibe.data.bson : Bson;
import vibe.core.log : logInfo;

import ircfiber.db.uploads : UploadRepository, UploadRecord;
import ircfiber.db.user : UserRepository;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.upload.local : uploadDir;

/// Display row for the uploads list.
struct AdminUploadRow {
    string id;
    string userId;
    string username;
    string filename;
    string buffer;
    string mimeType;
    long size;
    string sizeLabel;
    string directUrl;
    long createdAt;
}

package void adminUploads(HTTPServerRequest req, HTTPServerResponse res) {
    auto uploadRepo = new UploadRepository();
    auto userRepo = new UserRepository();

    int page = 0;
    int limit = 50;
    if (auto p = "page" in req.query) page = (*p).to!int;
    if (auto l = "limit" in req.query) limit = (*l).to!int;
    if (limit > 200) limit = 200;

    auto offset = page * limit;
    auto raw = uploadRepo.listAll(offset, limit);
    auto total = uploadRepo.countAll();

    AdminUploadRow[] uploads;
    foreach (r; raw) {
        AdminUploadRow row;
        row.id = r.id;
        row.userId = r.userId;
        row.filename = r.filename;
        row.buffer = r.buffer;
        row.mimeType = r.mimeType;
        row.size = r.size;
        if (r.size >= 1048576)
            row.sizeLabel = (r.size / 1048576).to!string ~ " MB";
        else if (r.size >= 1024)
            row.sizeLabel = (r.size / 1024).to!string ~ " KB";
        else
            row.sizeLabel = r.size.to!string ~ " B";
        row.directUrl = r.directUrl;
        row.createdAt = r.createdAt;
        try {
            auto uid = parseUUID(r.userId);
            auto usr = userRepo.findById(uid);
            row.username = usr.username.length > 0 ? usr.username : "unknown";
        } catch (Exception) { row.username = "unknown"; }
        uploads ~= row;
    }

    string message;
    auto pm = "message" in req.query;
    if (pm) message = (*pm);

    res.render!("admin/uploads.dt", uploads, total, page, limit, message)();
}

package void adminUploadDelete(HTTPServerRequest req, HTTPServerResponse res) {
    auto id = req.params["id"];

    auto coll = AppMongoConnection.getDb()["uploads"];
    auto doc = coll.findOne(Bson(["_id": Bson(id)]));
    if (!doc.isNull) {
        auto rec = UploadRecord.fromBson(doc);

        auto url = rec.directUrl.strip;
        auto uploadPrefix = "/uploads/";
        auto prefixPos = url.indexOf(uploadPrefix);
        if (prefixPos != -1) {
            auto filename = url[prefixPos + uploadPrefix.length .. $];
            if (filename.length > 0) {
                auto filePath = buildPath(uploadDir(), filename);
                try { remove(filePath); } catch (Exception) {}
            }
        }

        coll.deleteOne(Bson(["_id": Bson(id)]));
        logInfo("Admin deleted upload %s", id);
    }

    res.redirect("/admin/uploads?message=Upload+deleted");
}