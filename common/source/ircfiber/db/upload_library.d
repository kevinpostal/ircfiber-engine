module ircfiber.db.upload_library;

import std.array : appender;
import std.exception : enforce;
import std.string : strip;
import vibe.data.bson;
import vibe.data.json : Json;
import vibe.db.mongo.mongo;
import vibe.db.mongo.cursor;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.upload_category : uploadCategoryExpression, uploadOriginalNameExpression, uploadLocalExpression;

/// One owner-scoped page across the existing uploads and pastebins stores.
/// `counts` covers the complete live library, while `total` and `entries`
/// apply both filters. Empty paste names stay empty for localized UI labels.
/// The caller must obtain owner from its authenticated session, never input.
/// `legacyLocal` is internal: REST must remove it after verifying the managed
/// pathname and local file for legacy uploads with no provenance field.
Json uploadLibraryPage(string owner, string type = "all", string q = "", int offset = 0, int limit = 25) @trusted {
    enforce(owner.length != 0, "An upload library owner is required");
    enforce(type == "all" || type == "video" || type == "image" || type == "text",
        "Invalid upload library type");
    enforce(offset >= 0, "Invalid upload library offset");
    enforce(limit >= 1 && limit <= 100, "Invalid upload library limit");

    AggregateOptions options;
    options.maxTimeMS = 10_000;
    auto result = emptyPage();
    auto uploads = AppMongoConnection.getDb()["uploads"];
    foreach (doc; uploads.aggregate!Bson(libraryPipeline(owner, type, q, offset, limit), options)) {
        foreach (counts; doc["counts"]) {
            foreach (key; ["all", "video", "image", "text"])
                result["counts"][key] = Json(readNumber(counts[key]));
        }
        foreach (total; doc["total"]) result["total"] = Json(readNumber(total["value"]));
        auto entries = new Json[doc["entries"].length];
        size_t index;
        foreach (entry; doc["entries"]) entries[index++] = summaryJson(entry);
        result["entries"] = Json(entries);
    }
    return result;
}

private Json emptyPage() {
    auto result = Json.emptyObject;
    result["entries"] = Json.emptyArray;
    result["total"] = Json(0L);
    auto counts = Json.emptyObject;
    foreach (key; ["all", "video", "image", "text"]) counts[key] = Json(0L);
    result["counts"] = counts;
    return result;
}

/// Drop bodies and unrelated private fields before the union/facet. No facet
/// branch accumulates all records: only counters and the bounded result page.
private Bson[] libraryPipeline(string owner, string type, string q, int offset, int limit) @trusted {
    auto owned = Bson(["userId": Bson(owner), "deleted": Bson(false)]);
    auto pasteName = ifNull("$name", Bson(""));
    auto pasteContent = ifNull("$content", Bson(""));
    Bson[] pasteStages = [
        Bson(["$match": owned]),
        Bson(["$project": Bson([
            "_id": Bson(1), "kind": Bson("paste"), "category": Bson("text"),
            "name": pasteName, "originalName": pasteName,
            "createdAt": ifNull("$createdAt", Bson(0L)),
            "size": Bson(["$strLenBytes": pasteContent]), "mimeType": Bson("text/plain"),
            "syntax": ifNull("$syntax", Bson("text")), "lines": ifNull("$lines", Bson(1L)),
            "excerpt": Bson(["$substrCP": Bson([pasteContent, Bson(0), Bson(1500)])]),
            "local": Bson(["$literal": Bson(false)]),
        ])]),
    ];
    Bson[] pipeline = [
        Bson(["$match": owned]),
        Bson(["$project": Bson([
            "_id": Bson(1), "kind": Bson("upload"), "category": uploadCategoryExpression(),
            "name": ifNull("$filename", Bson("")), "originalName": uploadOriginalNameExpression(),
            "createdAt": ifNull("$createdAt", Bson(0L)), "size": ifNull("$size", Bson(0L)),
            "mimeType": ifNull("$mimeType", Bson("")), "url": ifNull("$directUrl", Bson("")),
            "thumbUrl": ifNull("$thumbUrl", Bson("")), "local": uploadLocalExpression(),
            "legacyLocal": Bson(["$eq": Bson([Bson(["$type": Bson("$local")]), Bson("missing")])]),
        ])]),
        Bson(["$unionWith": Bson(["coll": Bson("pastebins"), "pipeline": Bson(pasteStages)])]),
    ];

    auto filter = Bson.emptyObject;
    if (type != "all") filter["category"] = Bson(type);
    const search = q.strip;
    if (search.length)
        filter["name"] = Bson(["$regex": Bson(literalNamePattern(search)), "$options": Bson("i")]);

    // Bson associative arrays do not preserve sort priority; insert in order.
    auto sort = Bson.emptyObject;
    sort["createdAt"] = Bson(-1);
    sort["kind"] = Bson(1);
    sort["_id"] = Bson(1);
    Bson[] entries = [Bson(["$match": filter]), Bson(["$sort": sort])];
    if (offset > 0) entries ~= Bson(["$skip": Bson(offset)]);
    entries ~= Bson(["$limit": Bson(limit)]);

    auto counts = Bson.emptyObject;
    counts["_id"] = Bson(null);
    counts["all"] = Bson(["$sum": Bson(1)]);
    foreach (category; ["video", "image", "text"])
        counts[category] = Bson(["$sum": Bson(["$cond": Bson([
            Bson(["$eq": Bson([Bson("$category"), Bson(category)])]), Bson(1), Bson(0),
        ])])]);
    pipeline ~= Bson(["$facet": Bson([
        "counts": Bson([Bson(["$group": counts])]),
        "total": Bson([Bson(["$match": filter]), Bson(["$count": Bson("value")])]),
        "entries": Bson(entries),
    ])]);
    return pipeline;
}

private Bson ifNull(string field, Bson fallback) @trusted {
    return Bson(["$ifNull": Bson([Bson(field), fallback])]);
}

/// Escape regex syntax, not filenames: a search for `[` must match a literal
/// bracket and never become an invalid pattern or an arbitrary regex query.
private string literalNamePattern(string name) {
    auto pattern = appender!string();
    pattern.reserve(name.length);
    foreach (char c; name) {
        switch (c) {
            case '\\': case '^': case '$': case '.': case '|': case '?':
            case '*': case '+': case '(': case ')': case '[': case ']':
            case '{': case '}': pattern.put('\\'); break;
            default: break;
        }
        pattern.put(c);
    }
    return pattern.data;
}

private long readNumber(const Bson value) @trusted {
    switch (value.type) with (Bson.Type) {
        case int_: return value.get!int;
        case long_: return value.get!long;
        case double_: return cast(long) value.get!double;
        default: return 0;
    }
}

private Json summaryJson(Bson entry) @trusted {
    auto result = Json.emptyObject;
    result["id"] = Json(entry["_id"].get!string);
    foreach (key; ["kind", "category", "name", "mimeType", "originalName"])
        result[key] = Json(entry[key].get!string);
    result["createdAt"] = Json(readNumber(entry["createdAt"]));
    result["size"] = Json(readNumber(entry["size"]));
    result["local"] = Json(entry["local"].get!bool);
    if (entry["kind"].get!string == "paste") {
        result["syntax"] = Json(entry["syntax"].get!string);
        result["lines"] = Json(readNumber(entry["lines"]));
        result["excerpt"] = Json(entry["excerpt"].get!string);
    } else {
        result["url"] = Json(entry["url"].get!string);
        result["thumbUrl"] = Json(entry["thumbUrl"].get!string);
        result["legacyLocal"] = Json(entry["legacyLocal"].get!bool);
    }
    return result;
}

@("Upload library searches escape every regex metacharacter")
unittest {
    assert(literalNamePattern(`a[b].*+(x)?|^${y}\`) == `a\[b\]\.\*\+\(x\)\?\|\^\$\{y\}\\`);
    assert(literalNamePattern("résumé.py") == "résumé\\.py");
}

@("Upload library rejects invalid query values before database access")
unittest {
    import std.exception : assertThrown;
    assertThrown(uploadLibraryPage("", "all"));
    assertThrown(uploadLibraryPage("owner", "pdf"));
    assertThrown(uploadLibraryPage("owner", "all", "", -1));
    assertThrown(uploadLibraryPage("owner", "all", "", 0, 0));
    assertThrown(uploadLibraryPage("owner", "all", "", 0, 101));
}

@("Upload library unions owner stores before filtering, counting and deterministic pagination")
unittest {
    import ircfiber.testing.isolated_db : connectIsolatedTestMongo;
    import std.format : format;
    import std.uuid : randomUUID;
    if (!connectIsolatedTestMongo("uploadLibraryPage")) return;
    auto uploads = AppMongoConnection.getDb()["uploads"];
    auto pastes = AppMongoConnection.getDb()["pastebins"];
    const owner = randomUUID().toString();
    const otherOwner = randomUUID().toString();
    scope (exit) {
        uploads.deleteMany(Bson(["userId": Bson(owner)]));
        uploads.deleteMany(Bson(["userId": Bson(otherOwner)]));
        pastes.deleteMany(Bson(["userId": Bson(owner)]));
        pastes.deleteMany(Bson(["userId": Bson(otherOwner)]));
    }
    // All text records tie on time: kind and id must decide every page.
    foreach (i; 0 .. 30) {
        auto upload = Bson([
            "_id": Bson(owner ~ format("-%02d", i)), "userId": Bson(owner), "deleted": Bson(false),
            "filename": Bson(i == 29 ? "late[match].py" : format("code-%02d.py", i)),
            "originalFilename": Bson("stable.PY"), "mimeType": Bson("application/octet-stream"),
            "size": Bson(10L), "createdAt": Bson(1000L),
            "directUrl": Bson("https://example.test/uploads/0123456789abcdef0123456789abcdef.py"),
        ]);
        if (i == 0) upload["local"] = Bson(true);
        uploads.insertOne(upload);
    }
    foreach (i, mime; ["image/svg+xml", "video/webm", "application/pdf"]) {
        uploads.insertOne(Bson([
            "_id": Bson(owner ~ format("-media-%d", i)), "userId": Bson(owner), "deleted": Bson(false),
            "filename": Bson("misleading.py"), "originalFilename": Bson("misleading.py"),
            "mimeType": Bson(mime), "size": Bson(100L), "createdAt": Bson(2000L + i),
            "directUrl": Bson("https://example.test/file"),
        ]));
    }
    string largeBody;
    foreach (_; 0 .. 1502) largeBody ~= "猫";
    const sharedId = owner ~ "-00";
    foreach (i, content; ["é\n🐈", largeBody, "third"]) {
        pastes.insertOne(Bson([
            "_id": Bson(i == 0 ? sharedId : owner ~ format("-paste-%d", i)),
            "userId": Bson(owner), "deleted": Bson(false), "name": Bson(i == 0 ? "" : "snippet"),
            "syntax": Bson("html"), "content": Bson(content), "lines": Bson(i == 0 ? 2L : 1L),
            "createdAt": Bson(1000L),
        ]));
    }
    foreach (collection; [uploads, pastes]) {
        // Incomplete decoys would fail projection if either branch forgot its
        // owner/live match; neither may contribute to counts or the page.
        collection.insertOne(Bson([
            "_id": Bson(randomUUID().toString()), "userId": Bson(otherOwner), "deleted": Bson(false),
        ]));
        collection.insertOne(Bson([
            "_id": Bson(randomUUID().toString()), "userId": Bson(owner), "deleted": Bson(true),
        ]));
    }

    const first = uploadLibraryPage(owner);
    assert(first["total"].get!long == 36);
    assert(first["counts"]["all"].get!long == 36);
    assert(first["counts"]["text"].get!long == 33);
    assert(first["counts"]["image"].get!long == 1);
    assert(first["counts"]["video"].get!long == 1);
    assert(first["entries"].length == 25);
    assert(first["entries"][0]["category"].get!string == "other");
    assert(first["entries"][1]["category"].get!string == "video");
    assert(first["entries"][2]["category"].get!string == "image");
    assert(first["entries"][3]["kind"].get!string == "paste");
    assert(first["entries"][3]["id"].get!string == sharedId);
    assert(first["entries"][3]["name"].get!string == "");
    assert(first["entries"][3]["size"].get!long == 7);
    assert(first["entries"][3]["lines"].get!long == 2);
    assert(first["entries"][3]["syntax"].get!string == "html");
    assert(!first["entries"][3]["local"].get!bool);
    assert(first["entries"][4]["excerpt"].get!string.length == 4500);
    assert(first["entries"][6]["id"].get!string == sharedId);
    assert(first["entries"][6]["kind"].get!string == "upload");
    assert(first["entries"][6]["local"].get!bool);
    assert(!first["entries"][6]["legacyLocal"].get!bool);
    assert(first["entries"][7]["legacyLocal"].get!bool);
    assert(!first["entries"][7]["local"].get!bool);
    assert(first["entries"][6]["url"].get!string ==
        "https://example.test/uploads/0123456789abcdef0123456789abcdef.py");

    const second = uploadLibraryPage(owner, "all", "", 25);
    assert(second["entries"].length == 11);
    foreach (i; 0 .. 11)
        assert(second["entries"][i]["id"].get!string == owner ~ format("-%02d", i + 19));
    const search = uploadLibraryPage(owner, "text", " [MATCH] ");
    assert(search["total"].get!long == 1);
    assert(search["entries"][0]["name"].get!string == "late[match].py");
    assert(search["counts"]["all"].get!long == 36);
    assert(uploadLibraryPage(owner, "video", "[match]")["total"].get!long == 0);
    const none = uploadLibraryPage(owner, "all", "not-present");
    assert(none["total"].get!long == 0 && none["entries"].length == 0);
    assert(none["counts"]["all"].get!long == 36);
    const empty = uploadLibraryPage(randomUUID().toString());
    assert(empty["total"].get!long == 0 && empty["entries"].length == 0);
    foreach (category; ["all", "video", "image", "text"])
        assert(empty["counts"][category].get!long == 0);
}
