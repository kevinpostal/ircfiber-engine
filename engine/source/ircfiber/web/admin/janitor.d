module ircfiber.web.admin.janitor;

import std.conv : to;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse;
import vibe.core.log : logWarn;
import vibe.data.json : Json;

import ircfiber.irc.engine_janitor : EngineJanitor;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.web.admin.helpers : jsonOk, jsonError;

/// GET /api/admin/janitor/status — lock holder + cycle counters.
package void apiJanitorStatus(HTTPServerRequest req, HTTPServerResponse res,
                              EngineJanitor janitor) {
    try {
        jsonOk(res, janitor.getStatus());
    } catch (Exception e) {
        logWarn("apiJanitorStatus failed: %s", e.msg);
        jsonError(res, 500, e.msg);
    }
}

/// GET /api/admin/janitor/events?limit=100 — audit log (most-recent-first).
package void apiJanitorEvents(HTTPServerRequest req, HTTPServerResponse res,
                              EngineJanitor janitor) {
    int limit = 100;
    if (auto l = "limit" in req.query) {
        try {
            auto v = (*l).to!int;
            if (v > 0 && v <= 1000) limit = v;
        } catch (Exception) {}
    }
    try {
        auto events = janitor.getRecentEvents(limit);
        Json arr = Json.emptyArray;
        foreach (e; events) arr ~= e;
        Json data = Json.emptyObject;
        data["events"] = arr;
        data["count"] = Json(cast(long) events.length);
        data["limit"] = Json(limit);
        jsonOk(res, data);
    } catch (Exception e) {
        logWarn("apiJanitorEvents failed: %s", e.msg);
        jsonError(res, 500, e.msg);
    }
}

/// POST /api/admin/janitor/reap/:serverId — manual reap (bypasses global lock).
package void apiJanitorReap(HTTPServerRequest req, HTTPServerResponse res,
                            EngineJanitor janitor) {
    auto serverId = req.params["serverId"];
    if (serverId.length == 0) {
        jsonError(res, 400, "serverId required");
        return;
    }
    try {
        auto deleted = janitor.manualReap(serverId);
        Json data = Json.emptyObject;
        data["serverId"] = Json(serverId);
        data["keysDeleted"] = Json(deleted);
        data["ok"] = Json(true);
        jsonOk(res, data);
    } catch (Exception e) {
        logWarn("apiJanitorReap failed for %s: %s", serverId, e.msg);
        jsonError(res, 500, e.msg);
    }
}

/// POST /api/admin/janitor/cycle — run one janitor cycle synchronously.
package void apiJanitorCycle(HTTPServerRequest req, HTTPServerResponse res,
                             EngineJanitor janitor) {
    try {
        auto reaped = janitor.runOnce();
        Json data = Json.emptyObject;
        data["reaped"] = Json(reaped);
        data["ok"] = Json(true);
        jsonOk(res, data);
    } catch (Exception e) {
        logWarn("apiJanitorCycle failed: %s", e.msg);
        jsonError(res, 500, e.msg);
    }
}
