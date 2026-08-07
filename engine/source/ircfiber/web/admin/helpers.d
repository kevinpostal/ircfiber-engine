module ircfiber.web.admin.helpers;

import std.string : strip;
import std.conv : to;
import std.datetime : Clock;
import vibe.http.server : HTTPServerRequest, HTTPServerResponse;
import vibe.data.json : Json;
import ircfiber.web.common : getClientIp;

/// Vibe's session storage JSON-encodes every value, so plain strings get
/// wrapped in literal `"` characters before being written to the Redis hash.
/// Strip a single layer of JSON quoting when reading back, gracefully
/// leaving the value unchanged if it isn't quoted (so the helper is safe
/// to call on raw, non-JSON data such as the numeric timestamp we now store).
package string stripJsonStr(string raw) {
    if (raw.length >= 2 && raw[0] == '"' && raw[$-1] == '"')
        return raw[1 .. $-1];
    return raw;
}

/// Parse a numeric field that may be stored either as a plain decimal
/// string ("1782093504000") or as a JSON-quoted string because of legacy
/// write paths. Returns 0 if the field is empty or unparseable — never throws.
package long parseLongField(string raw) {
    auto s = stripJsonStr(raw);
    if (s.length == 0) return 0;
    try return s.to!long;
    catch (Exception) return 0;
}

/// True if the caller marked this as an XHR (fetch from the Svelte SPA
/// or the in-place remove button). Used to pick JSON vs redirect responses.
package bool isAjax(HTTPServerRequest req) {
    return req.headers.get("X-Requested-With", "") == "fetch";
}

/// Writes a JSON envelope `{ok:true,data:...}` with 200 status.
package void jsonOk(HTTPServerResponse res, Json data) {
    import std.string : replace;
    res.headers["Content-Type"] = "application/json; charset=utf-8";
    auto payload = Json.emptyObject;
    payload["ok"] = Json(true);
    payload["data"] = data;
    res.writeBody(payload.toString());
}

/// Writes a JSON envelope `{ok:false,error:"..."}` and the given status code.
package void jsonError(HTTPServerResponse res, int status, string error) {
    import std.string : replace;
    res.headers["Content-Type"] = "application/json; charset=utf-8";
    res.statusCode = status;
    auto payload = Json.emptyObject;
    payload["ok"] = Json(false);
    payload["error"] = Json(error);
    res.writeBody(payload.toString());
}

/// Reads a request body as JSON, returning Json.init on parse failure.
package Json readJsonBody(HTTPServerRequest req) {
    import vibe.data.json : parseJsonString;
    import vibe.stream.operations : readAll;
    try {
        auto raw = cast(string) req.bodyReader.readAll();
        if (raw.length == 0) return Json.init;
        return parseJsonString(raw);
    } catch (Exception) {
        return Json.init;
    }
}

/// Trim + null-coalesce a form value.
package string formString(HTTPServerRequest req, string key, string fallback = "") {
    return req.form.get(key, fallback).strip();
}

/// Captures client IP + User-Agent and stores them on the session as flat
/// string keys (`clientIp`, `userAgent`, `createdAt`, `lastAccess`) so the
/// admin Sessions page can render them without parsing JSON for every row.
/// Safe to call on any request that already has a session attached.
package void captureSessionMeta(HTTPServerRequest req) {
    if (!req.session) return;
    auto ms = Clock.currTime.toUnixTime() * 1000L;
    if (!req.session.isKeySet("createdAt")) {
        req.session.set("createdAt", ms);
    }
    req.session.set("lastAccess", ms);
    req.session.set("clientIp",   getClientIp(req));
    req.session.set("userAgent",  req.headers.get("User-Agent", ""));
}

/// Cheap refresh — only updates `lastAccess`. Used on every authenticated
/// admin page so the Sessions view reflects the user's actual activity
/// without re-writing the static fields.
package void touchSessionAccess(HTTPServerRequest req) {
    if (!req.session) return;
    if (!req.session.isKeySet("createdAt")) {
        captureSessionMeta(req);
        return;
    }
    auto ms = Clock.currTime.toUnixTime() * 1000L;
    req.session.set("lastAccess", ms);
}

/// Convert a string[] to a Json array. Used everywhere the old code had
/// `Json(stringArray)` — that constructor doesn't exist on vibe's Json.
package Json jsonArray(string[] items) {
    Json a = Json.emptyArray;
    foreach (item; items) a ~= Json(item);
    return a;
}