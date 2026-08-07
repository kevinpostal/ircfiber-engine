module ircfiber.web.admin;

import std.string : strip;
import std.uuid : parseUUID;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse, render, staticTemplate;
import vibe.http.router : URLRouter;
import vibe.core.log : logInfo, logWarn;

import ircfiber.auth : authenticateRequest, requireAuth, requireAdmin, isAdmin;
import ircfiber.db.user : UserRepository;
import ircfiber.irc.engine_janitor : EngineJanitor;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.storage.redis : RedisStorage;

import ircfiber.web.admin.helpers : captureSessionMeta, touchSessionAccess;
import ircfiber.web.admin.auth : adminLoginPage, adminLoginPost, adminLogout,
    adminImpersonate, adminStopImpersonating;

import ircfiber.web.admin.api : apiMe, apiDashboard,
    apiServers, apiServerHost, apiReassignServer, apiReassignAssignment,
    apiRemoveAssignment, apiEngineConfig, apiHostDisconnect, apiHostReconnect,
    apiHostDeleteNetwork, apiAssignmentDelete, apiRouting,
    apiUsersList, apiUserCreate, apiUserDetail, apiUserUpdate, apiUserDelete,
    apiResetPassword,
    apiSessions, apiSessionsClear, apiSessionsClearUser, apiSessionsClearOne,
    apiUploadsList, apiUploadDelete;

import ircfiber.web.admin.janitor : apiJanitorStatus, apiJanitorEvents,
    apiJanitorReap, apiJanitorCycle;

import ircfiber.web.admin.mongo : apiMongoStatus, apiMongoCollections,
    apiMongoCollectionDetail, apiMongoQuery;
import ircfiber.web.admin.redis : apiRedisInfo, apiRedisSummary, apiRedisKeys,
    apiRedisKeyDetail, apiRedisSlowlog, apiRedisPubsub, apiRedisClients;

/// Admin controller — orchestrates the admin submodules.
/// All routes are gated by `adminWrap` (requireAuth + requireAdmin + touch).
/// Diet templates are kept as a no-JS fallback until each page is ported
/// to the Svelte SPA in `frontend/src/admin/`.
final class AdminController {
    private RedisStorage redis;
    private ServerRegistry serverRegistry;
    private EngineJanitor janitor;

    this(RedisStorage redis) {
        this.redis = redis;
        this.serverRegistry = new ServerRegistry(redis);
    }

    /// Lazy accessor for the shared EngineJanitor. Created on first admin
    /// request so the gateway's own janitor task (constructed in app.d)
    /// and `/api/admin/janitor/cycle` route share the same instance —
    /// no risk of two janitors racing on the same Redis state.
    private EngineJanitor getJanitor() {
        if (janitor is null) janitor = new EngineJanitor(redis);
        return janitor;
    }

    /// Registers every admin route on the given router. Mixes diet-template
    /// routes (under /admin/*) with the new JSON API (under /api/admin/*).
    void registerRoutes(URLRouter router) {
        // ── Public (no auth) ──────────────────────────────────────
        router.get("/admin/login",  &adminLoginPage);
        router.post("/admin/login", &adminLoginPostRoute);
        router.get("/admin/logout", &adminLogout);

        // ── SPA shell - serves admin.html; /admin and /admin/ both
        //    must route here. The wildcard /admin/* below handles
        //    deeper paths.
        router.get("/admin",  &adminWrap!adminSpaShell);
        router.get("/admin/", &adminWrap!adminSpaShell);

        // ── Impersonation (must still serve from /admin/* for cookie
        //    scope) ───────────────────────────────────────────────
        router.get("/admin/users/:id/impersonate", &adminWrap!adminImpersonate);
        router.get("/admin/stop-impersonating", &adminStopImpersonating);

        // ── SPA shell — serves admin.html for any /admin/* that
        //    isn't matched above. This must be registered LAST so
        //    the specific routes above take precedence. ───────────
        router.get("/admin/*", &adminWrap!adminSpaShell);

        // ── JSON API for the Svelte SPA ──────────────────────────
        router.get("/api/admin/me", &adminWrap!apiMeRoute);
        router.get("/api/admin/dashboard", &adminWrap!apiDashboardRoute);

        router.get("/api/admin/servers", &adminWrap!apiServersRoute);
        router.get("/api/admin/servers/host/:host", &adminWrap!apiServerHostRoute);
        router.post("/api/admin/servers/:id/reassign", &adminWrap!apiReassignServerRoute);
        router.post("/api/admin/servers/assignments/:networkId/reassign", &adminWrap!apiReassignAssignmentRoute);
        router.post("/api/admin/servers/assignments/:networkId/remove", &adminWrap!apiRemoveAssignmentRoute);
        router.post("/api/admin/servers/assignments/:networkId/delete", &adminWrap!apiAssignmentDeleteRoute);
        router.post("/api/admin/servers/:id/config", &adminWrap!apiEngineConfigRoute);
        router.post("/api/admin/servers/host/:host/disconnect/:networkId", &adminWrap!apiHostDisconnectRoute);
        router.post("/api/admin/servers/host/:host/reconnect/:networkId", &adminWrap!apiHostReconnectRoute);
        router.post("/api/admin/servers/host/:host/delete-network/:networkId", &adminWrap!apiHostDeleteNetworkRoute);
        router.post("/api/admin/routing", &adminWrap!apiRoutingRoute);

        router.get("/api/admin/users", &adminWrap!apiUsersListRoute);
        router.post("/api/admin/users", &adminWrap!apiUserCreateRoute);
        router.get("/api/admin/users/:id", &adminWrap!apiUserDetailRoute);
        router.post("/api/admin/users/:id", &adminWrap!apiUserUpdateRoute);
        router.post("/api/admin/users/:id/delete", &adminWrap!apiUserDeleteRoute);
        router.post("/api/admin/users/:id/reset-password", &adminWrap!apiResetPasswordRoute);

        router.get("/api/admin/sessions", &adminWrap!apiSessionsRoute);
        router.post("/api/admin/sessions/clear", &adminWrap!apiSessionsClearRoute);
        router.post("/api/admin/sessions/clear/:uid", &adminWrap!apiSessionsClearUserRoute);
        router.post("/api/admin/sessions/clear-one/:sid", &adminWrap!apiSessionsClearOneRoute);

        router.get("/api/admin/uploads", &adminWrap!apiUploadsListRoute);
        router.post("/api/admin/uploads/:id/delete", &adminWrap!apiUploadDeleteRoute);

        // Mongo monitor
        router.get("/api/admin/mongo/status", &adminWrap!apiMongoStatusRoute);
        router.get("/api/admin/mongo/collections", &adminWrap!apiMongoCollectionsRoute);
        router.get("/api/admin/mongo/collections/:name", &adminWrap!apiMongoCollectionDetailRoute);
        router.post("/api/admin/mongo/query", &adminWrap!apiMongoQueryRoute);

        // Redis monitor
        router.get("/api/admin/redis/info", &adminWrap!apiRedisInfoRoute);
        router.get("/api/admin/redis/summary", &adminWrap!apiRedisSummaryRoute);
        router.get("/api/admin/redis/keys", &adminWrap!apiRedisKeysRoute);
        router.get("/api/admin/redis/keys/:key", &adminWrap!apiRedisKeyDetailRoute);
        router.get("/api/admin/redis/slowlog", &adminWrap!apiRedisSlowlogRoute);
        router.get("/api/admin/redis/pubsub", &adminWrap!apiRedisPubsubRoute);
        router.get("/api/admin/redis/clients", &adminWrap!apiRedisClientsRoute);

        // Engine janitor control plane
        router.get("/api/admin/janitor/status", &adminWrap!apiJanitorStatusRoute);
        router.get("/api/admin/janitor/events", &adminWrap!apiJanitorEventsRoute);
        router.post("/api/admin/janitor/reap/:serverId", &adminWrap!apiJanitorReapRoute);
        router.post("/api/admin/janitor/cycle", &adminWrap!apiJanitorCycleRoute);
    }

private:
    // ────────────────────────────────────────────────────────────
    // Wrapper — auth, admin role, session touch, then handler
    // ────────────────────────────────────────────────────────────
    template adminWrap(alias handler) {
        void adminWrap(scope HTTPServerRequest req, scope HTTPServerResponse res) {
            requireAuth(req, res);
            if (res.headerWritten) return;
            requireAdmin(req, res);
            if (res.headerWritten) return;
            touchSessionAccess(req);
            handler(req, res);
        }
    }

    // Login route — passes redis to adminLoginPost for session culling
    void adminLoginPostRoute(HTTPServerRequest req, HTTPServerResponse res) {
        adminLoginPost(req, res, redis);
    }

    // Diet-template handlers — bind `redis` + `serverRegistry` to the
    // existing free functions in `admin/*.d`.
    // (Diet template routes removed in Phase 3 — all pages now use the
    //  Svelte SPA. The handler functions in users.d / servers.d / sessions.d
    //  / uploads.d are kept as they export shared types and helpers used by
    //  api.d / mongo.d / redis.d; their diet-rendering functions are now
    //  dead code pending future cleanup.)

    // JSON API handlers — bind storage objects to free functions
    void apiMeRoute(HTTPServerRequest req, HTTPServerResponse res) { apiMe(req, res); }
    void apiDashboardRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiDashboard(req, res, redis, serverRegistry);
    }
    void apiServersRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiServers(req, res, redis, serverRegistry);
    }
    void apiServerHostRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiServerHost(req, res, redis, serverRegistry);
    }
    void apiReassignServerRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiReassignServer(req, res, serverRegistry);
    }
    void apiReassignAssignmentRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiReassignAssignment(req, res, serverRegistry);
    }
    void apiRemoveAssignmentRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiRemoveAssignment(req, res, redis, serverRegistry);
    }
    void apiAssignmentDeleteRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiAssignmentDelete(req, res, redis, serverRegistry);
    }
    void apiEngineConfigRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiEngineConfig(req, res, serverRegistry);
    }
    void apiHostDisconnectRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiHostDisconnect(req, res, redis, serverRegistry);
    }
    void apiHostReconnectRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiHostReconnect(req, res, redis, serverRegistry);
    }
    void apiHostDeleteNetworkRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiHostDeleteNetwork(req, res, redis, serverRegistry);
    }
    void apiRoutingRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiRouting(req, res, serverRegistry);
    }
    void apiUsersListRoute(HTTPServerRequest req, HTTPServerResponse res) { apiUsersList(req, res); }
    void apiUserCreateRoute(HTTPServerRequest req, HTTPServerResponse res) { apiUserCreate(req, res); }
    void apiUserDetailRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiUserDetail(req, res, redis);
    }
    void apiUserUpdateRoute(HTTPServerRequest req, HTTPServerResponse res) { apiUserUpdate(req, res); }
    void apiUserDeleteRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiUserDelete(req, res, redis, serverRegistry);
    }
    void apiResetPasswordRoute(HTTPServerRequest req, HTTPServerResponse res) { apiResetPassword(req, res); }
    void apiSessionsRoute(HTTPServerRequest req, HTTPServerResponse res) { apiSessions(req, res, redis); }
    void apiSessionsClearRoute(HTTPServerRequest req, HTTPServerResponse res) { apiSessionsClear(req, res, redis); }
    void apiSessionsClearUserRoute(HTTPServerRequest req, HTTPServerResponse res) { apiSessionsClearUser(req, res, redis); }
    void apiSessionsClearOneRoute(HTTPServerRequest req, HTTPServerResponse res) { apiSessionsClearOne(req, res, redis); }
    void apiUploadsListRoute(HTTPServerRequest req, HTTPServerResponse res) { apiUploadsList(req, res); }
    void apiUploadDeleteRoute(HTTPServerRequest req, HTTPServerResponse res) { apiUploadDelete(req, res); }

    // Mongo
    void apiMongoStatusRoute(HTTPServerRequest req, HTTPServerResponse res) { apiMongoStatus(req, res); }
    void apiMongoCollectionsRoute(HTTPServerRequest req, HTTPServerResponse res) { apiMongoCollections(req, res); }
    void apiMongoCollectionDetailRoute(HTTPServerRequest req, HTTPServerResponse res) { apiMongoCollectionDetail(req, res); }
    void apiMongoQueryRoute(HTTPServerRequest req, HTTPServerResponse res) { apiMongoQuery(req, res); }

    // Redis
    void apiRedisInfoRoute(HTTPServerRequest req, HTTPServerResponse res) { apiRedisInfo(req, res, redis); }
    void apiRedisSummaryRoute(HTTPServerRequest req, HTTPServerResponse res) { apiRedisSummary(req, res, redis); }
    void apiRedisKeysRoute(HTTPServerRequest req, HTTPServerResponse res) { apiRedisKeys(req, res, redis); }
    void apiRedisKeyDetailRoute(HTTPServerRequest req, HTTPServerResponse res) { apiRedisKeyDetail(req, res, redis); }
    void apiRedisSlowlogRoute(HTTPServerRequest req, HTTPServerResponse res) { apiRedisSlowlog(req, res, redis); }
    void apiRedisPubsubRoute(HTTPServerRequest req, HTTPServerResponse res) { apiRedisPubsub(req, res, redis); }
    void apiRedisClientsRoute(HTTPServerRequest req, HTTPServerResponse res) { apiRedisClients(req, res, redis); }

    // Janitor
    void apiJanitorStatusRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiJanitorStatus(req, res, getJanitor());
    }
    void apiJanitorEventsRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiJanitorEvents(req, res, getJanitor());
    }
    void apiJanitorReapRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiJanitorReap(req, res, getJanitor());
    }
    void apiJanitorCycleRoute(HTTPServerRequest req, HTTPServerResponse res) {
        apiJanitorCycle(req, res, getJanitor());
    }

    /// Serves the built Svelte admin SPA shell (`public/dist/admin.html`)
    /// for any authenticated admin request that didn't match a specific
    /// route above. The SPA handles client-side routing from there.
    void adminSpaShell(HTTPServerRequest req, HTTPServerResponse res) {
        import std.file : read, exists, isFile;
        import std.path : buildPath;
        try {
            auto path = buildPath("public", "dist", "admin.html");
            if (!exists(path) || !isFile(path)) {
                res.statusCode = 503;
                res.headers["Content-Type"] = "text/html; charset=utf-8";
                res.writeBody(
                    "<!doctype html><meta charset=utf-8><title>Admin not built</title>" ~
                    "<body style=\"background:#0a0e14;color:#c8d2dd;font-family:system-ui;padding:48px\">" ~
                    "<h1>Admin SPA not built yet</h1>" ~
                    "<p>Run <code>cd frontend &amp;&amp; npm run build</code> to generate <code>public/dist/admin.html</code>.</p>" ~
                    "<p>The diet-template admin pages are still available at:</p>" ~
                    "<ul><li><a href=\"/admin/servers\" style=\"color:#67e8f9\">/admin/servers</a></li>" ~
                    "<li><a href=\"/admin/sessions\" style=\"color:#67e8f9\">/admin/sessions</a></li>" ~
                    "<li><a href=\"/admin/users\" style=\"color:#67e8f9\">/admin/users</a></li>" ~
                    "<li><a href=\"/admin/uploads\" style=\"color:#67e8f9\">/admin/uploads</a></li></ul>" ~
                    "</body>");
                return;
            }
            res.headers["Content-Type"] = "text/html; charset=utf-8";
            res.headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
            res.writeBody(cast(const(ubyte)[]) read(path), "text/html; charset=utf-8");
        } catch (Exception e) {
            logWarn("adminSpaShell failed: %s", e.msg);
            res.statusCode = 500;
            res.writeBody("Failed to serve admin shell");
        }
    }
}