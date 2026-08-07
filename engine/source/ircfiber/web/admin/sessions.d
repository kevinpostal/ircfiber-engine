module ircfiber.web.admin.sessions;

import std.uuid : parseUUID;
import std.string : strip;
import std.algorithm : canFind, sort;
import std.array : array, join;
import std.uni : toLower;
import std.conv : to;
import std.datetime : Clock;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse, render;
import vibe.core.log : logInfo, logWarn;

import ircfiber.db.user : UserRepository;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.session : RedisSessionStore, SESSION_KEY_PREFIX;
import ircfiber.web.admin.helpers : stripJsonStr, parseLongField;

/// Row data for the Sessions admin page.
struct SessionInfo {
    string sessionKey;     // full Redis key, e.g. "session:abc..."
    string sessionId;      // bare id without prefix
    string userId;
    string username;
    string clientIp;
    string userAgent;
    long   createdAt;
    long   lastAccess;
    long   ttlSeconds;
    bool   isCurrent;
    bool   isAdmin;
    string roles;
}

package void adminSessions(HTTPServerRequest req, HTTPServerResponse res,
                            RedisStorage redis) {
    SessionInfo[] sessions;
    long nowMs = Clock.currTime.toUnixTime() * 1000L;
    string currentSid;
    if (req.session) currentSid = req.session.id;
    auto store = new RedisSessionStore(redis);
    auto userRepo = new UserRepository();

    try {
        foreach (sid; store.listAllSessionIds()) {
            auto fields = store.getSessionFields(sid);
            if (fields is null) continue;
            auto uidPtr = "sessionUserId" in fields;
            if (!uidPtr || (*uidPtr).length == 0) continue;

            SessionInfo si;
            si.sessionKey = SESSION_KEY_PREFIX ~ sid;
            si.sessionId  = sid;
            si.userId = stripJsonStr(*uidPtr);

            try {
                auto u = userRepo.findById(parseUUID(*uidPtr));
                si.username = u.username.length > 0 ? u.username : "unknown";
                si.isAdmin  = u.roles.canFind("admin");
                si.roles    = u.roles.join(",");
            } catch (Exception) {
                si.username = "unknown";
                si.roles    = "";
            }

            auto ipPtr = "clientIp" in fields;
            if (ipPtr && (*ipPtr).length > 0) si.clientIp = stripJsonStr(*ipPtr);
            auto uaPtr = "userAgent" in fields;
            if (uaPtr && (*uaPtr).length > 0) si.userAgent = stripJsonStr(*uaPtr);
            auto caPtr = "createdAt" in fields;
            if (caPtr && (*caPtr).length > 0) si.createdAt = parseLongField(*caPtr);
            auto laPtr = "lastAccess" in fields;
            if (laPtr && (*laPtr).length > 0) si.lastAccess = parseLongField(*laPtr);

            si.ttlSeconds = store.sessionTtl(sid);
            si.isCurrent = currentSid.length > 0 && si.sessionId == currentSid;
            sessions ~= si;
        }
    } catch (Exception e) {
        logWarn("adminSessions read error: %s", e.msg);
    }

    // Sort: current session first, then by lastAccess desc.
    sort!((a, b) {
        if (a.isCurrent != b.isCurrent) return a.isCurrent;
        if (a.lastAccess != b.lastAccess) return a.lastAccess > b.lastAccess;
        return a.username < b.username;
    })(sessions);

    int total          = cast(int) sessions.length;
    int yourSessions   = 0;
    int adminsOnline   = 0;
    int idleCount      = 0;
    bool[string] seenUsers;
    int uniqueUsers    = 0;
    long idleThreshold = 60L * 60L * 1000L;
    foreach (s; sessions) {
        if (s.isCurrent) yourSessions++;
        if (s.isAdmin)   adminsOnline++;
        if (!(s.userId in seenUsers)) {
            seenUsers[s.userId] = true;
            uniqueUsers++;
        }
        if (s.lastAccess > 0 && (nowMs - s.lastAccess) > idleThreshold) {
            idleCount++;
        }
    }

    string q;
    auto pq = "q" in req.query;
    if (pq) q = (*pq).strip();
    SessionInfo[] filtered;
    if (q.length > 0) {
        foreach (s; sessions) {
            if (s.username.toLower().canFind(q.toLower())
                || s.userId.toLower().canFind(q.toLower())
                || s.clientIp.toLower().canFind(q.toLower())) {
                filtered ~= s;
            }
        }
    } else {
        filtered = sessions;
    }

    auto message = req.query.get("message", "");
    res.render!("admin/sessions.dt",
        sessions, filtered, q,
        total, uniqueUsers, yourSessions, adminsOnline, idleCount,
        message)();
}

package void adminSessionsClear(HTTPServerRequest req, HTTPServerResponse res,
                                 RedisStorage redis) {
    auto currentUid = req.session.get("sessionUserId", "");
    int cleared;
    auto store = new RedisSessionStore(redis);
    try {
        foreach (sid; store.listAllSessionIds()) {
            auto fields = store.getSessionFields(sid);
            if (fields is null) continue;
            auto uidPtr = "sessionUserId" in fields;
            if (uidPtr && stripJsonStr(*uidPtr) == currentUid) continue;
            store.destroy(sid);
            cleared++;
        }
    } catch (Exception e) {
        logWarn("Session clear error: %s", e.msg);
    }
    logInfo("Admin cleared %d stale sessions", cleared);
    res.redirect("/admin/sessions?message=Cleared+" ~ cleared.to!string ~ "+sessions");
}

package void adminSessionsClearUser(HTTPServerRequest req, HTTPServerResponse res,
                                     RedisStorage redis) {
    auto targetUid = req.params["uid"];
    int cleared;
    auto store = new RedisSessionStore(redis);
    try {
        foreach (sid; store.listAllSessionIds()) {
            auto fields = store.getSessionFields(sid);
            if (fields is null) continue;
            auto uidPtr = "sessionUserId" in fields;
            if (uidPtr && stripJsonStr(*uidPtr) == targetUid) {
                store.destroy(sid);
                cleared++;
            }
        }
    } catch (Exception e) {
        logWarn("Session clear error for user %s: %s", targetUid, e.msg);
    }
    logInfo("Admin cleared %d sessions for user %s", cleared, targetUid);
    res.redirect("/admin/sessions?message=Cleared+" ~ cleared.to!string ~ "+sessions+for+user+" ~ targetUid);
}