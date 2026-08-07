module ircfiber.web;

import std.file : readText, exists, isFile, read;
import std.path : buildPath;
import std.uuid : randomUUID;
import std.string : strip;
import std.algorithm : startsWith, canFind, endsWith;
import std.string : indexOf;
import std.regex : regex, replaceAll;
import std.datetime : Clock;
import std.conv : to;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse, render;
import vibe.http.router : URLRouter;
import vibe.core.log;
import vibe.data.json : Json, parseJsonString;

import ircfiber.auth : verifyPassword, hashPassword, requireAuth;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.storage.buffer : sanitizeUtf8;
import ircfiber.db.user : UserRepository;
import ircfiber.db.network : NetworkRepository;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.default_network : ensureDefaultFiberNetwork;
import ircfiber.models.user : User;
import ircfiber.web.common : getClientIp;

    // Captures client IP, User-Agent, createdAt, and lastAccess on
    // the active session. Mirrors the helper in AdminController so
    // non-admin sessions also show full provenance on the admin
    // Sessions page. Timestamps are stored as `long` (unboxed JSON
    // number) because Vibe's JSON-storage variant can't store
    // reference types like Json directly.
    private void captureSessionMeta(HTTPServerRequest req) {
        if (!req.session) return;
        import std.datetime : Clock;
        auto ms = Clock.currTime.toUnixTime() * 1000L;
        if (!req.session.isKeySet("createdAt")) {
            req.session.set("createdAt", ms);
        }
        req.session.set("lastAccess", ms);
        req.session.set("clientIp",   getClientIp(req));
        req.session.set("userAgent",  req.headers.get("User-Agent", ""));
    }

import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.session : limitUserSessions;

/// Web controller for pages and static assets.
final class WebController {
    private RedisStorage redis;

    /// Creates a new web controller.
    this(RedisStorage redis) @safe {
        this.redis = redis;
    }

    /// Registers web routes on the given router.
    void registerRoutes(URLRouter router) {
        router.get("/", &index);
        router.get("/irc/*", &index);
        router.get("/login", &loginPage);
        router.post("/login", &loginPost);
        router.get("/register", &registerPage);
        router.post("/register", &registerPost);
        router.get("/logout", &logout);
        router.get("/public/landing.html", &serveLanding);
        router.get("/app-screenshot.png", &serveAppScreenshot);
        router.get("/public/dist/*", &serveDist);
        // Vite 5+ outputs the Svelte bundle under public/dist/assets/
        // and the generated index.html references it as `/assets/*`
        // (root-relative). Serve the same files at that path so the
        // HTML's <script src="/assets/index-*.js"> resolves without
        // going through a rewrite. The handler is the same serveDist
        // but rooted at the assets/ subdirectory.
        router.get("/assets/*", &serveAssets);
        // User-uploaded images are saved to /app/uploads/ and served
        // at /uploads/<uuid>.<ext>. Only common image MIME types are
        // returned; attempting to serve non-image files is refused.
        router.get("/uploads/*", &serveUpload);
        router.get("/api/events", &serveEvents);
    }

    private void index(HTTPServerRequest req, HTTPServerResponse res) {
        auto path = req.requestPath.toString();

        // Save the intended IRC path BEFORE the auth check so that
        // unauthenticated visitors who then log in get redirected back
        // to the correct route, not dumped at the root (/).
        // Without this, a bookmark or direct URL like /irc/IRC%20Fiber
        // silently drops the route after login because the cookie is
        // only set for authenticated requests (which never runs).
        if (path.startsWith("/irc/")) {
            res.setCookie("lastVisited", path, "/");
        }

        // If not authenticated, serve the static marketing landing page.
        // Logged-in users get the SPA, which detects auth state via /api/me.
        auto sid = req.session ? req.session.get("sessionUserId", "") : "";
        if (sid.length == 0) {
            serveLanding(req, res);
            return;
        }
        // If visiting root and we have a last visited location, redirect there.
        // Skip the redirect for client-side routes (e.g. /?/shortcuts, /?/settings)
        // so the SPA router can handle them on initial page load.
        else if (path == "/" && !req.queryString.startsWith("/")) {
            if (auto last = "lastVisited" in req.cookies) {
                res.redirect(*last);
                return;
            }
        }

        res.render!("index.dt")();
    }

    private void loginPage(HTTPServerRequest, HTTPServerResponse res) {
        string authError;
        res.render!("login.dt", authError)();
    }

    private void loginPost(HTTPServerRequest req, HTTPServerResponse res) {
        string authError;
        try {
            auto repo = new UserRepository();
            auto username = req.form.get("username", "").strip();
            auto password = req.form.get("password", "").strip();

            if (username.length == 0 || password.length == 0) {
                authError = "Please enter both your username and password.";
                res.statusCode = 400;
                res.render!("login.dt", authError)();
                return;
            }

            auto user = repo.findByUsername(username);
            if (user.username.length > 0 && verifyPassword(password, user.passwordHash)) {
                // Record login IP and timestamp on the user record
                auto ip = getClientIp(req);
                user.lastLoginIp = ip;
                user.lastLoginAt = Clock.currTime;
                if (!user.loginIps.canFind(ip)) {
                    user.loginIps ~= ip;
                }
                repo.update(user);

                // Lazy migration: ensure the default IRC Fiber network exists
                // for every logging-in user. Idempotent — skips if they
                // already have one. Failures here don't block login.
                try {
                    ensureDefaultFiberNetwork(user, new NetworkRepository(), redis, new ServerRegistry(redis));
                } catch (Exception e) {
                    logWarn("Failed to ensure default network for %s on login: %s", user.username, e.msg);
                }

                if (!req.session) req.session = res.startSession();
                req.session.set("sessionUserId", user.id.toString());
                captureSessionMeta(req);
                limitUserSessions(redis, user.id.toString(), req.session.id);
                res.redirect("/");
            } else {
                authError = "Incorrect username or password. Please try again.";
                res.statusCode = 401;
                res.render!("login.dt", authError)();
            }
        } catch (Exception e) {
            logError("Login failed with exception: %s", e.msg);
            logError("Login stack trace: %s", e.toString());
            authError = "An unexpected error occurred. Please try again.";
            res.statusCode = 500;
            try res.render!("login.dt", authError)();
            catch (Exception) {
                res.writeBody("An unexpected error occurred.", "text/plain; charset=utf-8");
            }
        }
    }

    private void registerPage(HTTPServerRequest, HTTPServerResponse res) {
        string authError;
        res.render!("register.dt", authError)();
    }

    private void registerPost(HTTPServerRequest req, HTTPServerResponse res) {
        auto repo = new UserRepository();
        auto username = req.form.get("username", "").strip();
        auto email = req.form.get("email", "").strip();
        auto password = req.form.get("password", "").strip();

        string authError;

        // Landing page sign-up sends email + password only.
        if (username.length == 0 && email.length > 0) {
            auto at = email.indexOf("@");
            username = at > 0 ? email[0..at].idup : email;
            // Strip non-alphanumeric to keep usernames IRC-friendly.
            username = replaceAll(username, regex(r"[^a-zA-Z0-9_\-]"), "");
            if (username.length == 0) username = "user";
        }

        if (username.length == 0 || email.length == 0 || password.length == 0) {
            authError = "Username, email and password are all required.";
            res.statusCode = 400;
            res.render!("register.dt", authError)();
            return;
        }

        if (!email.canFind('@') || !email.canFind('.')) {
            authError = "That doesn't look like a valid email address.";
            res.statusCode = 400;
            res.render!("register.dt", authError)();
            return;
        }

        if (password.length < 8) {
            authError = "Password must be at least 8 characters.";
            res.statusCode = 400;
            res.render!("register.dt", authError)();
            return;
        }

        if (repo.findByUsername(username).username.length > 0) {
            authError = "That username is already taken. Please choose another.";
            res.statusCode = 409;
            res.render!("register.dt", authError)();
            return;
        }

        User u;
        u.id = randomUUID();
        u.username = username;
        u.email = email;
        u.passwordHash = hashPassword(password);
        u.signupIp = getClientIp(req);
        u.createdAt = Clock.currTime;
        repo.create(u);

        // Provision the default IRC Fiber network (irc.ircfiber.com:6697).
        // Idempotent — existing-user migration runs the same helper on login.
        // We swallow exceptions here so a Mongo/Redis hiccup doesn't lose
        // the user record; the lazy login hook will catch up next session.
        try {
            ensureDefaultFiberNetwork(u, new NetworkRepository(), redis, new ServerRegistry(redis));
        } catch (Exception e) {
            logWarn("Failed to provision default network for new user %s: %s", u.username, e.msg);
        }

        if (!req.session) req.session = res.startSession();
        req.session.set("sessionUserId", u.id.toString());
        captureSessionMeta(req);
        limitUserSessions(redis, u.id.toString(), req.session.id);
        res.redirect("/");
    }

    private void logout(HTTPServerRequest req, HTTPServerResponse res) {
        req.session.destroy();
        res.redirect("/login");
    }

    private void serveLanding(HTTPServerRequest, HTTPServerResponse res) {
        try {
            res.headers["Cache-Control"] = "public, max-age=3600";
            res.writeBody(readText("public/landing.html"), "text/html; charset=utf-8");
        } catch (Exception e) {
            logWarn("Failed to serve landing page: %s", e.msg);
            res.statusCode = 500;
        }
    }

    private void serveAppScreenshot(HTTPServerRequest, HTTPServerResponse res) {
        try {
            res.headers["Cache-Control"] = "public, max-age=86400";
            res.writeBody(cast(const(ubyte)[])read("public/app-screenshot.png"), "image/png");
        } catch (Exception e) {
            logWarn("Failed to serve app screenshot: %s", e.msg);
            res.statusCode = 500;
        }
    }

    private void serveHyperFrames(HTTPServerRequest, HTTPServerResponse res) {
        try {
            res.headers["Cache-Control"] = "public, max-age=86400";
            res.writeBody(readText("public/hyperframes-launch.html"), "text/html; charset=utf-8");
        } catch (Exception e) {
            logWarn("Failed to serve HyperFrames source: %s", e.msg);
            res.statusCode = 500;
        }
    }

    private void serveDist(HTTPServerRequest req, HTTPServerResponse res) {
        try {
            auto pathStr = req.requestPath.toString();
            // Strip the "/public/dist/" prefix
            auto rel = pathStr[("/public/dist/".length)..$];
            // Strip any query string the framework may have left in
            auto qIdx = rel.indexOf('?');
            if (qIdx >= 0) rel = rel[0..qIdx];
            if (rel.length == 0 || rel.canFind("..")) {
                res.statusCode = 400;
                return;
            }

            auto fsPath = buildPath("public/dist", rel);
            if (!exists(fsPath) || !isFile(fsPath)) {
                res.statusCode = 404;
                return;
            }

            string mime = "application/octet-stream";
            if (endsWith(rel, ".js"))      mime = "application/javascript";
            else if (endsWith(rel, ".css")) mime = "text/css";
            else if (endsWith(rel, ".html")) mime = "text/html";
            else if (endsWith(rel, ".json")) mime = "application/json";
            else if (endsWith(rel, ".svg"))  mime = "image/svg+xml";
            else if (endsWith(rel, ".png"))  mime = "image/png";

            res.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            res.headers["Pragma"] = "no-cache";
            res.headers["Expires"] = "0";
            res.writeBody(cast(const(ubyte)[])read(fsPath), mime);
        } catch (Exception e) {
            logWarn("Failed to serve dist asset: %s", e.msg);
            res.statusCode = 500;
        }
    }

    // Same logic as serveDist but rooted at public/dist/assets/. The
    // Svelte bundle lives there under Vite 5+ (output: `assets/index-*.js`)
    // and the generated index.html references it as `/assets/index-*.js`.
    private void serveAssets(HTTPServerRequest req, HTTPServerResponse res) {
        try {
            auto pathStr = req.requestPath.toString();
            // Strip the "/assets/" prefix
            auto rel = pathStr[("/assets/".length)..$];
            auto qIdx = rel.indexOf('?');
            if (qIdx >= 0) rel = rel[0..qIdx];
            if (rel.length == 0 || rel.canFind("..")) {
                res.statusCode = 400;
                return;
            }

            auto fsPath = buildPath("public/dist/assets", rel);
            if (!exists(fsPath) || !isFile(fsPath)) {
                res.statusCode = 404;
                return;
            }

            string mime = "application/octet-stream";
            if (endsWith(rel, ".js"))      mime = "application/javascript";
            else if (endsWith(rel, ".css")) mime = "text/css";
            else if (endsWith(rel, ".html")) mime = "text/html";
            else if (endsWith(rel, ".json")) mime = "application/json";
            else if (endsWith(rel, ".svg"))  mime = "image/svg+xml";
            else if (endsWith(rel, ".png"))  mime = "image/png";

            res.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            res.headers["Pragma"] = "no-cache";
            res.headers["Expires"] = "0";
            res.writeBody(cast(const(ubyte)[])read(fsPath), mime);
        } catch (Exception e) {
            logWarn("Failed to serve /assets/ asset: %s", e.msg);
            res.statusCode = 500;
        }
    }

    /// GET /api/events — XHR fallback for event streaming.
    /// Returns events since the given ?since=<eid> (or empty array).
    /// Reads from the user's Redis event stream (irc:stream:<userId>),
    /// the same store used by the WebSocket's replayMissedEvents().
    private void serveEvents(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        long sinceEid = 0;
        if (auto p = "since" in req.query) {
            if ((*p).length > 0) {
                try {
                    sinceEid = to!long(*p);
                } catch (Exception) {}
            }
        }
        auto streamKey = RedisKeys.userStream(user.id.toString());
        Json[] result;
        try {
            auto db = redis.getDb();
            auto raw = db.lrange!(ubyte[])(streamKey, 0, -1);
            foreach (entry; raw) {
                string s;
                try { s = () @trusted { return cast(string)entry.idup; } (); }
                catch (Exception) { continue; }
                s = sanitizeUtf8(s);
                if (s.length == 0) continue;
                try {
                    auto json = parseJsonString(s);
                    if (auto e = "eid" in json) {
                        if (e.type == Json.Type.int_ && e.get!long > sinceEid) {
                            result ~= json;
                        }
                    }
                } catch (Exception) {}
            }
        } catch (Exception e) {
            logWarn("serveEvents: failed to read stream for user %s: %s", user.id, e.msg);
        }
        import std.algorithm : reverse;
        reverse(result);
        res.writeJsonBody(Json(result));
    }

    /// Serves uploaded files from /app/uploads/.
    /// Only allows common image MIME types to prevent misuse.
    private void serveUpload(HTTPServerRequest req, HTTPServerResponse res) {
        import ircfiber.upload.local : uploadDir;
        try {
            auto pathStr = req.requestPath.toString();
            // Strip the "/uploads/" prefix
            auto rel = pathStr[("/uploads/".length)..$];
            auto qIdx = rel.indexOf('?');
            if (qIdx >= 0) rel = rel[0..qIdx];
            if (rel.length == 0 || rel.canFind("..") || rel.canFind("/")) {
                res.statusCode = 400;
                return;
            }

            auto fsPath = buildPath(uploadDir(), rel);
            if (!exists(fsPath) || !isFile(fsPath)) {
                res.statusCode = 404;
                return;
            }

            // Only serve known image types
            string mime = "application/octet-stream";
            if (endsWith(rel, ".png"))       mime = "image/png";
            else if (endsWith(rel, ".jpg")
                  || endsWith(rel, ".jpeg")) mime = "image/jpeg";
            else if (endsWith(rel, ".gif"))  mime = "image/gif";
            else if (endsWith(rel, ".webp")) mime = "image/webp";
            else if (endsWith(rel, ".svg"))  mime = "image/svg+xml";
            else if (endsWith(rel, ".avif")) mime = "image/avif";
            else {
                // Non-image file — refuse to serve
                res.statusCode = 403;
                return;
            }

            res.headers["Cache-Control"] = "public, max-age=86400";
            res.writeBody(cast(const(ubyte)[])read(fsPath), mime);
        } catch (Exception e) {
            logWarn("Failed to serve upload: %s", e.msg);
            res.statusCode = 500;
        }
    }
}
