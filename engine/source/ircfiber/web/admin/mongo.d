module ircfiber.web.admin.mongo;

import std.string : strip, toLower;
import std.algorithm : canFind;
import std.typecons : Nullable;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse;
import vibe.core.log : logWarn;
import vibe.data.json : Json;
import vibe.data.bson : Bson;

import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.web.admin.helpers : jsonOk, jsonError, readJsonBody;

/// GET /api/admin/mongo/status — connection + dbStats + serverStatus subset.
package void apiMongoStatus(HTTPServerRequest req, HTTPServerResponse res) {
    Json data = Json.emptyObject;
    data["connected"] = Json(AppMongoConnection.isConnected());
    data["dbName"] = Json(AppMongoConnection.name());

    if (!AppMongoConnection.isConnected()) {
        jsonOk(res, data);
        return;
    }

    try {
        auto stats = AppMongoConnection.dbStats();
        data["dbStats"] = stats.toJson();
    } catch (Exception e) {
        data["dbStatsError"] = Json(e.msg);
    }

    try {
        auto ss = AppMongoConnection.serverStatusSubset();
        data["serverStatus"] = ss.toJson();
    } catch (Exception e) {
        data["serverStatusError"] = Json(e.msg);
    }

    jsonOk(res, data);
}

/// GET /api/admin/mongo/collections — list with counts and sizes.
package void apiMongoCollections(HTTPServerRequest req, HTTPServerResponse res) {
    Json data = Json.emptyObject;
    if (!AppMongoConnection.isConnected()) {
        data["connected"] = Json(false);
        jsonOk(res, data);
        return;
    }
    data["connected"] = Json(true);

    try {
        auto colls = AppMongoConnection.listCollectionsWithCounts();
        Json[] arr;
        foreach (c; colls) arr ~= c.toJson();
        data["collections"] = Json(arr);
    } catch (Exception e) {
        data["error"] = Json(e.msg);
    }
    jsonOk(res, data);
}

/// GET /api/admin/mongo/collections/:name — collStats + indexes.
package void apiMongoCollectionDetail(HTTPServerRequest req, HTTPServerResponse res) {
    auto collName = req.params["name"];
    Json data = Json.emptyObject;
    data["name"] = Json(collName);

    if (!AppMongoConnection.isConnected()) {
        data["connected"] = Json(false);
        jsonOk(res, data);
        return;
    }
    data["connected"] = Json(true);

    auto stats = AppMongoConnection.collectionStats(collName);
    if (stats.isNull) {
        data["error"] = Json("Collection not found or stats unavailable");
        jsonError(res, 404, "Collection not found");
        return;
    }
    data["stats"] = stats.get.toJson();

    auto indexes = AppMongoConnection.listIndexes(collName);
    Json[] idxArr;
    foreach (i; indexes) idxArr ~= i.toJson();
    data["indexes"] = Json(idxArr);

    jsonOk(res, data);
}

/// Disallowed MongoDB operators in user-supplied filters.
/// These can run JavaScript on the server, bypass indexes, or write data.
private static const string[] BLOCKED_OPERATORS = [
    "$where", "$function", "$accumulator", "$expr",
    "$out", "$merge", "$lookup", "$graphLookup",
];

/// Recursively reject any blocked operator key in a filter Bson.
private static bool filterIsSafe(const Bson filter) {
    if (filter.type == Bson.Type.object) {
        foreach (string k, const Bson v; filter.byKeyValue) {
            if (BLOCKED_OPERATORS.canFind(k)) return false;
            if (!filterIsSafe(v)) return false;
        }
    } else if (filter.type == Bson.Type.array) {
        foreach (size_t _, const Bson v; filter.byIndexValue) {
            if (!filterIsSafe(v)) return false;
        }
    }
    return true;
}

/// Convert a Bson array to a Json array.
private static Json bsonArrayToJson(const Bson b) {
    Json arr = Json.emptyArray;
    if (b.type != Bson.Type.array) return arr;
    foreach (size_t _, const Bson v; b.byIndexValue) arr ~= v.toJson();
    return arr;
}

/// POST /api/admin/mongo/query — sandboxed find().
/// Body: `{collection: string, filter: object, projection?: object, sort?: object, limit?: number, maxTimeMs?: number}`
/// Hard limits: limit ≤ 100, maxTimeMs ≤ 10000, no JS operators.
package void apiMongoQuery(HTTPServerRequest req, HTTPServerResponse res) {
    if (!AppMongoConnection.isConnected()) {
        jsonError(res, 503, "MongoDB not connected");
        return;
    }
    auto body = readJsonBody(req);
    string collName;
    Bson filter = Bson.emptyObject;
    Bson projection = Bson.emptyObject;
    Bson sort = Bson.emptyObject;
    int limit = 20;
    int maxTimeMs = 2000;

    try {
        collName = body["collection"].get!string;
        if ("filter" in body) filter = Bson(body["filter"]);
        if ("projection" in body) projection = Bson(body["projection"]);
        if ("sort" in body) sort = Bson(body["sort"]);
        if ("limit" in body) limit = body["limit"].get!int;
        if ("maxTimeMs" in body) maxTimeMs = body["maxTimeMs"].get!int;
    } catch (Exception e) {
        jsonError(res, 400, "Invalid request body: " ~ e.msg);
        return;
    }

    if (collName.length == 0) { jsonError(res, 400, "collection is required"); return; }
    if (!filterIsSafe(filter)) { jsonError(res, 400, "Filter contains a blocked operator ($where/$function/$lookup/etc.)"); return; }

    // Final clamping (safeFind re-clamps but we want to honor what the client asked within bounds)
    if (limit < 1) limit = 1;
    if (limit > 100) limit = 100;
    if (maxTimeMs < 1) maxTimeMs = 2000;
    if (maxTimeMs > 10000) maxTimeMs = 10000;

    auto docs = AppMongoConnection.safeFind(collName, filter, projection, sort, limit, maxTimeMs);
    Json[] arr;
    if (docs !is null) foreach (d; docs) arr ~= d.toJson();
    Json data = Json.emptyObject;
    data["collection"] = Json(collName);
    data["count"] = Json(cast(long) arr.length);
    data["limit"] = Json(limit);
    data["maxTimeMs"] = Json(maxTimeMs);
    data["results"] = Json(arr);
    jsonOk(res, data);
}