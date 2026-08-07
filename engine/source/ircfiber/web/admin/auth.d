module ircfiber.web.admin.auth;

import std.uuid : UUID, parseUUID;
import std.string : strip;
import std.algorithm : canFind;
import std.datetime : Clock;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse, render;
import vibe.core.log : logInfo, logWarn, logError;

import ircfiber.auth : verifyPassword, hashPassword, isAdmin, requireAuth;
import ircfiber.db.user : UserRepository;
import ircfiber.models.user : User;
import ircfiber.web.common : getClientIp;
import ircfiber.web.admin.helpers : captureSessionMeta, stripJsonStr;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.session : limitUserSessions;

package void adminLoginPage(HTTPServerRequest req, HTTPServerResponse res) {
    string authError;
    auto redirect = req.query.get("redirect", "");
    res.render!("admin/login.dt", authError, redirect)();
}

package void adminLoginPost(HTTPServerRequest req, HTTPServerResponse res, RedisStorage redis) {
    string authError;
    try {
        auto repo = new UserRepository();
        auto username = req.form.get("username", "").strip();
        auto password = req.form.get("password", "").strip();

        if (username.length == 0 || password.length == 0) {
            authError = "Username and password required";
            auto redirect = req.form.get("redirect", "");
            res.render!("admin/login.dt", authError, redirect)();
            return;
        }

        auto user = repo.findByUsername(username);
        if (user.username.length > 0 && verifyPassword(password, user.passwordHash)) {
            if (!isAdmin(user)) {
                authError = "Not an admin account";
                auto redirect = req.form.get("redirect", "");
                res.render!("admin/login.dt", authError, redirect)();
                return;
            }

            // Record the real client IP, timestamp, and IP history.
            // Resolved via getClientIp which checks CF-Connecting-IP,
            // X-Forwarded-For, X-Real-IP, then falls back to the raw
            // TCP peer address.
            auto ip = getClientIp(req);
            user.lastLoginIp = ip;
            user.lastLoginAt = Clock.currTime;
            // Append to IP history (de-duplicated, never removes old entries)
            if (!user.loginIps.canFind(ip)) {
                user.loginIps ~= ip;
            }
            repo.update(user);

            if (!req.session) req.session = res.startSession();
            req.session.set("sessionUserId", user.id.toString());
            captureSessionMeta(req);
            limitUserSessions(redis, user.id.toString(), req.session.id);
            auto redirect = req.form.get("redirect", "");
            if (redirect.length > 0) res.redirect("/admin" ~ redirect);
            else res.redirect("/admin");
        } else {
            authError = "Invalid credentials";
            auto redirect = req.form.get("redirect", "");
            res.render!("admin/login.dt", authError, redirect)();
        }
    } catch (Exception e) {
        logError("Admin login failed with exception: %s", e.msg);
        logError("Admin login stack trace: %s", e.toString());
        authError = "An unexpected error occurred. Please try again.";
        res.statusCode = 500;
        try {
            auto redirect = req.form.get("redirect", "");
            res.render!("admin/login.dt", authError, redirect)();
        } catch (Exception) {
            res.writeBody("An unexpected error occurred.", "text/plain; charset=utf-8");
        }
    }
}

package void adminLogout(HTTPServerRequest req, HTTPServerResponse res) {
    // Clear impersonation state if present — prevents session-hijack
    // back to admin after logout via a stale originalSessionUserId.
    try req.session.remove("originalSessionUserId");
    catch (Exception) {}
    req.session.destroy();
    res.redirect("/admin/login");
}

/// Start impersonating another user. Admin-only (requireAuth + isAdmin
/// are checked by the caller before invoking this).
package void adminImpersonate(HTTPServerRequest req, HTTPServerResponse res) {
    auto repo = new UserRepository();
    auto id = parseUUID(req.params["id"]);
    auto user = repo.findById(id);

    if (user.username.length > 0) {
        auto adminUser = req.context["user"].get!User;
        req.session.set("originalSessionUserId", adminUser.id.toString());
        logInfo("Admin %s started impersonating user %s", adminUser.username, user.username);

        req.session.set("sessionUserId", user.id.toString());
        captureSessionMeta(req);
        res.redirect("/");
    } else {
        res.redirect("/admin/users");
    }
}

/// Stop impersonating — does NOT use adminWrap because the session is the
/// impersonated (non-admin) user at this point. The handler performs its
/// own admin-role re-verification on the original user.
package void adminStopImpersonating(HTTPServerRequest req, HTTPServerResponse res) {
    requireAuth(req, res);
    if (res.headerWritten) return;

    auto originalId = req.session.get("originalSessionUserId", "");
    if (originalId.length == 0) {
        res.redirect("/");
        return;
    }

    auto repo = new UserRepository();
    try {
        auto uid = parseUUID(originalId);
        auto originalUser = repo.findById(uid);

        if (originalUser.username.length == 0 || !isAdmin(originalUser)) {
            logWarn("Stop-impersonating blocked: original user %s not found or no longer admin", originalId);
            req.session.remove("originalSessionUserId");
            res.redirect("/");
            return;
        }

        auto impersonatedUser = req.context["user"].get!User;
        logInfo("Admin %s stopped impersonating user %s", originalUser.username, impersonatedUser.username);

        req.session.set("sessionUserId", originalUser.id.toString());
        req.session.remove("originalSessionUserId");
        captureSessionMeta(req);

        auto redirectTo = req.query.get("redirect", "/");
        res.redirect(redirectTo);

    } catch (Exception e) {
        logWarn("Stop-impersonating failed for originalId %s: %s", originalId, e.msg);
        req.session.remove("originalSessionUserId");
        res.redirect("/");
    }
}