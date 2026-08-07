module app;

import std.process : environment;
import std.string;
import std.algorithm : canFind;
import std.conv : to;
import std.uuid : randomUUID;
import std.datetime : Clock;
import vibe.core.core : runApplication, runTask, sleep;
import vibe.core.task : TaskSettings;
import core.time : seconds, minutes, Duration;
import vibe.core.log;
import vibe.http.server : HTTPServerSettings, listenHTTP, HTTPServerRequest, HTTPServerResponse;
import vibe.http.router : URLRouter;
import vibe.http.websockets : handleWebSockets;

import ircfiber.api.session : SessionManager;
import ircfiber.api.websocket : WebSocketGateway;
import ircfiber.api.rest : RESTAPI;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.irc.engine_janitor : EngineJanitor;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.session : RedisSessionStore;
import ircfiber.resource : resourceId;
import ircfiber.web : WebController;
import ircfiber.web.admin : AdminController;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.user : UserRepository;
import ircfiber.logging : logException;
import ircfiber.models.user : User;
import ircfiber.auth : hashPassword;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.async : startFiberWatchdog;
import ircfiber.tracing : configureTracing, flushAndSendSpans, withSpan, Span, resetFiberCtx,
    isTracingEnabled, isEnvEnabled, setTracingEnabled;
import ircfiber.observability : configureMetrics;
import ircfiber.threadpool : initThreadPools, shutdownThreadPools,
    g_httpPool, g_ircPool, g_bgPool, g_stgPool;
import ircfiber.db.redis_pool : initRedisPool, shutdownRedisPool;
/// Global WebSocket gateway instance.
__gshared WebSocketGateway g_wsGateway;

void main() {
    logInfo("Starting IRC Fiber Gateway...");

    // Initialize dedicated thread pools for task isolation.
    initThreadPools();
    logInfo("Thread pools initialized (http=%d, irc=%d, bg=%d, stg=%d)",
        g_httpPool.threadCount, g_ircPool.threadCount,
        g_bgPool.threadCount, g_stgPool.threadCount);

    // Initialize shared Redis connection pool (avoids per-thread connections)
    initRedisPool();

    auto mongoUrl = environment.get("IRCFIBER_MONGO_URL", "mongodb://127.0.0.1:27017/ircfiber");
    auto mongoDbName = "ircfiber";
    auto mongoSlash = mongoUrl.lastIndexOf("/");
    if (mongoSlash > "mongodb://".length) {
        mongoDbName = mongoUrl[mongoSlash + 1 .. $];
    }
    foreach (attempt; 0 .. 30) {
        try {
            AppMongoConnection.connect(mongoUrl, mongoDbName);
            break;
        } catch (Exception e) {
            if (attempt == 29) {
                throw new Exception("MongoDB connection failed after 30 attempts: " ~ e.msg);
            } else {
                logInfo("MongoDB connection attempt %d failed (%s), retrying in 1s...", attempt + 1, e.msg);
                sleep(1.seconds);
            }
        }
    }

    try {
        auto userRepo = new UserRepository();
        const adminUser = userRepo.findByUsername("admin");
        if (adminUser.username.length == 0) {
            User u;
            u.id = randomUUID();
            u.username = "admin";
            u.email = "admin@localhost";
            u.passwordHash = hashPassword("REDACTED");
            u.roles = ["admin"];
            // Set explicit timestamps so toUnixTime() returns seconds (not SysTime.init)
            u.createdAt = Clock.currTime;
            u.lastLoginAt = Clock.currTime;
            u.signupIp = "system";
            userRepo.create(u);
            logInfo("Created default admin user: admin");
        }
    } catch (Exception e) {
        logWarn("Failed to seed admin user: %s", e.msg);
    }

    auto redisUrl = environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");
    auto redis = new RedisStorage();
    foreach (attempt; 0 .. 30) {
        try {
            redis.connectFromUrl(redisUrl);
            redis.getDb().exists("test");
            break;
        } catch (Exception e) {
            if (attempt == 29) {
                throw new Exception("Redis connection failed after 30 attempts: " ~ e.msg);
            } else {
                logInfo("Redis connection attempt %d failed, retrying in 1s...", attempt + 1);
                sleep(1.seconds);
            }
        }
    }

    NetworkRepository.initRedis(redis);

    // Dedicated Redis connection for session store — isolated from admin
    // monitoring operations (INFO, SCAN, SLOWLOG, etc.) that share the
    // main `redis` instance. Prevents heavy admin queries from starving
    // session reads/writes that would log the user out.
    auto sessionRedis = new RedisStorage();
    sessionRedis.connectFromUrl(redisUrl);

    auto bufferManager = new BufferManager(redis);

    auto sessionManager = new SessionManager();
    sessionManager.setRedis(redis); // Enable Redis-backed session persistence for cold restore
    g_wsGateway = new WebSocketGateway(sessionManager, bufferManager, redis);
    // Link the IRC pool dispatch to the gateway so pool threads can
    // deliver Redis events to user sessions through the gateway's
    // thread-safe SessionManager methods.
    import ircfiber.api.websocket : g_gwForIrcPool;
    g_gwForIrcPool = g_wsGateway;

    auto settings = new HTTPServerSettings;
    // Port overridable via env for parallel dev instances (default 8090).
    settings.port = cast(ushort) environment.get("IRCFIBER_HTTP_PORT", "8090").to!int;
    settings.bindAddresses = ["0.0.0.0", "::1"];
    settings.serverString = "IRC-Fiber-Gateway/0.3";
    settings.maxRequestSize = 210 * 1024 * 1024; // allow 200MB uploads + multipart overhead
    settings.sessionStore = new RedisSessionStore(sessionRedis);
    // Force Secure flag on session cookies. The gateway receives
    // plain HTTP from Caddy, but the browser connects via HTTPS
    // (Cloudflare terminates TLS). Without this, vibe.d sets
    // Secure=false on the cookie, which modern browsers may
    // reject or handle inconsistently over HTTPS connections.
    import vibe.http.server : SessionOption;
    settings.sessionOptions = SessionOption.httpOnly | SessionOption.secure;

    auto router = new URLRouter;

    auto webController = new WebController(redis);
    webController.registerRoutes(router);

    auto restApi = new RESTAPI(bufferManager, redis, sessionManager);
    restApi.registerRoutes(router);

    auto adminController = new AdminController(redis);
    adminController.registerRoutes(router);
    router.get("/ws", handleWebSockets((scope socket) nothrow {
        try { g_wsGateway.handleWebSocket(socket); } catch (Exception e) {}
    }));

    // ── OTel toggle (env-gated) ────────────────────────────────────
    // IRCFIBER_OTEL_ENABLED=1|true|yes|on → export traces+metrics.
    // Default disabled (safe for prod — 3.5 GB SigNoz footprint).
    // When enabled, IRCFIBER_OTEL_ENDPOINT is the OTLP base URL
    // (e.g. http://signoz:4318 or http://ircfiber-otel-collector:4318).
    // Empty endpoint → disabled even if flag is on (fail-safe).
    bool otelEnabled = isEnvEnabled("IRCFIBER_OTEL_ENABLED");
    string otelEpRaw = environment.get("IRCFIBER_OTEL_ENDPOINT", "");
    // Support both bare host and full /v1/traces path.
    string otelTracesEp;
    string otelMetricsEp;
    if (otelEnabled && otelEpRaw.length > 0) {
        // Normalize base: strip trailing slash.
        string base = otelEpRaw;
        if (base.length > 0 && base[$-1] == '/')
            base = base[0 .. $-1];
        if (base.canFind("/v1/traces")) {
            otelTracesEp = base;
        } else if (base.canFind("/v1/metrics")) {
            // User gave metrics endpoint, derive traces from it.
            otelTracesEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/traces";
        } else {
            otelTracesEp = base ~ "/v1/traces";
        }
        if (base.canFind("/v1/metrics")) {
            otelMetricsEp = base;
        } else if (base.canFind("/v1/traces")) {
            otelMetricsEp = base[0 .. base.lastIndexOf("/v1/")] ~ "/v1/metrics";
        } else {
            otelMetricsEp = base ~ "/v1/metrics";
        }
        configureTracing(otelTracesEp, "ircfiber-gateway", "0.3.0");
        configureMetrics(otelMetricsEp, "ircfiber-gateway", "0.3.0");
        // Ensure flags are set (configure* sets them, but be explicit).
        setTracingEnabled(true);
        import ircfiber.observability : setMetricsEnabled;
        setMetricsEnabled(true);
        logInfo("OTel enabled: traces=%s metrics=%s", otelTracesEp, otelMetricsEp);
    } else {
        setTracingEnabled(false);
        import ircfiber.observability : setMetricsEnabled;
        setMetricsEnabled(false);
        logInfo("OTel disabled (IRCFIBER_OTEL_ENABLED=%s, endpoint='%s')",
            otelEnabled ? "1 (empty endpoint)" : "0", otelEpRaw);
    }

    // Wrap the router with an OTel tracing span for every HTTP request.
    // This creates traces for ALL gateway endpoints with method, path,
    // status code, and duration automatically. Rare events (5xx, 4xx)
    // are tagged as errors in the span. The span is cheap (just timing
    // + 4-5 attributes) and the flush is batched every 10 s.
    //
    // resetFiberCtx() at the entry point handles a subtle race: vibe.d
    // reuses the SAME fiber for multiple sequential HTTP requests on
    // one TCP keep-alive connection. If the previous request's
    // withSpan scope(exit) didn't fire (e.g. socket reset mid-handler,
    // exception during cleanup), the next request would inherit the
    // previous request's traceId as its parent — producing traces
    // that look "parented" to a span from a different request, which
    // SigNoz surfaces as "missing spans". Wiping at the entry point
    // makes each request self-contained.
    // When OTel is disabled, withSpan is a pass-through and we use a
    // lightweight wrapper that only attaches resourceId.
    auto tracedRouter = delegate(HTTPServerRequest req, HTTPServerResponse res) {
        resetFiberCtx();
        req.context["resourceId"] = resourceId();
        if (!isTracingEnabled()) {
            router.handleRequest(req, res);
            return;
        }
        // Skip tracing for health check endpoints — they fire every 30s
        // from Docker, load balancers, and orchestrators, and would
        // produce thousands of pointless spans in SigNoz with no
        // debugging value.
        auto path = req.requestPath.toString();
        if (path == "/health" || path == "/api/health" || path.startsWith("/health/")) {
            router.handleRequest(req, res);
            return;
        }
        withSpan("http.request", [
            "http.method": to!string(req.method),
            "url.path": path
        ], (ref Span s) {
            if (req.session) {
                auto uid = req.session.get("sessionUserId", "");
                if (uid.length > 0)
                    s.attr("user", uid);
            }
            try {
                router.handleRequest(req, res);
                auto sc = res.statusCode;
                s.attr("http.status_code", to!string(sc));
                if (sc >= 500)
                    s.setStatusError("server error");
                else if (sc >= 400)
                    s.setStatusError("client error");
                else
                    s.setStatusOk();
            } catch (Exception e) {
                import std.stdio : stderr;
                stderr.writeln("otel: router error: ", e.msg);
            }
        });
    };

    listenHTTP(settings, tracedRouter);
    logInfo("IRC Fiber Gateway listening on http://localhost:8090");
    startFiberWatchdog();
    logInfo("Fiber watchdog started");

    auto registry = new ServerRegistry(redis);
    // Run engine health monitor on g_bgPool with its own Redis connection
    // so it never contends with HTTP handlers.
    g_bgPool.runTask(&bgEngineHealthTask);
    // Run shutdown listener on g_bgPool with its own Redis subscriber.
    g_bgPool.runTask(&bgShutdownListenerTask);

    // Distributed engine janitor — runs in the gateway so even if all
    // engines are dead, the gateway can reap orphan namespaces. Safe in
    // every process (SET NX EX global lock elects a single winner per
    // cycle). No-op on a healthy keyspace.
    auto janitor = new EngineJanitor(redis);
    janitor.start();
    logInfo("EngineJanitor: started in gateway");

    // Initialize resource/instance ID from env var, with hostname fallback.
    // Attached to every HTTP request context for operational identification.
    resourceId();

    // Start resource heartbeat (writes `irc:resource:<id>` to Redis every 10s).
    // Runs on g_bgPool (uses shared Redis pool).
    g_bgPool.runTask(&bgHeartbeatLoop);

    // Periodic OTel span flush — runs every 10s on g_bgPool to drain
    // the span queue without competing with HTTP fibers.
    // Only start when OTel is enabled; otherwise flush is a no-op and
    // we avoid waking a fiber every 10 s for nothing.
    if (otelEnabled && otelTracesEp.length > 0)
        g_bgPool.runTask(&bgOtelFlushTask);

    runApplication();
    logInfo("IRC Fiber Gateway shutdown — stopping thread pools and Redis pool...");
    shutdownRedisPool();
    shutdownThreadPools();
    logInfo("IRC Fiber Gateway shutdown complete");
}

// ---------------------------------------------------------------------------
// Background pool tasks (run on g_bgPool worker threads)
// ---------------------------------------------------------------------------

/// Resource heartbeat — writes `irc:resource:<id>` to Redis every 10s.
private void bgHeartbeatLoop() nothrow {
    import ircfiber.db.redis_pool : poolRedis;
    import ircfiber.storage.redis : RedisStorage;
    import vibe.data.json : Json;
    string id;
    try {
        id = environment.get("IRCFIBER_RESOURCE_ID", "");
        if (id.length == 0) {
            import core.sys.posix.unistd : gethostname;
            char[256] buf;
            if (gethostname(buf.ptr, buf.length) == 0)
                id = buf.ptr[0 .. buf.length].idup;
            else
                id = "unknown";
        }
    } catch (Exception) { id = "unknown"; }

    RedisStorage redis;
    try { redis = new RedisStorage(); redis.connectFromUrl(
        environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379")); }
    catch (Exception) { return; }

    while (true) {
        try {
            redis.setJson("irc:resource:" ~ id, Json(true), 30);
        } catch (Exception e) {
            logWarn("bgHeartbeat: %s", e.msg);
        }
        try { sleep(10.seconds); } catch (Exception) { return; }
    }
}

/// OTel span flush — runs every 10s on the bg pool.
private void bgOtelFlushTask() nothrow {
    while (true) {
        try { sleep(10.seconds); flushAndSendSpans(); }
        catch (Exception) { return; }
    }
}

/// Engine health monitor — runs every 10s on the bg pool.
/// Creates its own Redis connection (isolated from the gateway).
private void bgEngineHealthTask() nothrow {
    import ircfiber.storage.redis : RedisStorage;

    RedisStorage redis;
    try { redis = new RedisStorage(); redis.connectFromUrl(
        environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379")); }
    catch (Exception e) { logError("bgPool: health redis: %s", e.msg); return; }

    ServerRegistry registry;
    try { registry = new ServerRegistry(redis); }
    catch (Exception e) { logError("bgPool: health registry: %s", e.msg); return; }
    bool previouslyHealthy = true;
    bool firstCheck = true;
    int consecutiveFailures = 0;

    while (true) {
        try {
            registry.healthCheckAll();
            consecutiveFailures = 0;

            auto healthy = registry.getHealthyServers();
            if (healthy.length == 0) {
                if (firstCheck || previouslyHealthy) {
                    logWarn("===========================================================");
                    logWarn("  NO IRC ENGINE REGISTERED");
                    logWarn("  The gateway is running but no irc-fiber-engine process");
                    logWarn("  is healthy. Client messages will be queued in Redis but");
                    logWarn("  NEVER delivered to IRC until an engine starts.");
                    logWarn("===========================================================");
                } else {
                    logWarn("Still no healthy IRC engine registered (gateway is queueing commands only).");
                }
                previouslyHealthy = false;
            } else {
                if (!previouslyHealthy)
                    logInfo("IRC engine is back online (%d healthy engine(s) registered).", healthy.length);
                else if (firstCheck)
                    logInfo("Engine health check: %d healthy IRC engine(s) registered.", healthy.length);
                previouslyHealthy = true;
            }
            firstCheck = false;
        } catch (Exception e) {
            consecutiveFailures++;
            logError("Engine health monitor error (%d/%d): %s", consecutiveFailures, 10, e.msg);
            if (consecutiveFailures >= 10) {
                logWarn("Engine health monitor: %d consecutive failures, pausing for 5 minutes", consecutiveFailures);
                try { sleep(5.minutes); } catch (Exception) { return; }
                consecutiveFailures = 0;
                continue;
            }
        }
        try { sleep(10.seconds); } catch (Exception) { return; }
    }
}

/// Shutdown listener — subscribes to engine shutdown announcements
/// on the bg pool with its own Redis subscriber.
private void bgShutdownListenerTask() nothrow {
    import ircfiber.storage.redis : RedisStorage;

    RedisStorage redis;
    try { redis = new RedisStorage(); redis.connectFromUrl(
        environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379")); }
    catch (Exception e) { logError("bgPool: shutdown redis: %s", e.msg); return; }

    while (true) {
        try {
            auto client = redis.getClient();
            if (client is null) {
                sleep(5.seconds);
                continue;
            }
            auto subscriber = client.createSubscriber();
            subscriber.subscribe(RedisKeys.shutdownChannel());
            logInfo("bgPool: subscribed to shutdown channel: %s", RedisKeys.shutdownChannel());

            // Create registry once, then capture for the listener delegate.
            auto shutdownRegistry = new ServerRegistry(redis);

            subscriber.listen((string channel, string message) @safe nothrow {
                if (message.length == 0) return;
                try {
                    () @trusted {
                        logWarn("bgPool: shutdown from engine %s — reassigning networks", message);
                        shutdownRegistry.reassignServerNetworks(message);
                    }();
                } catch (Exception e) {
                    logError("bgPool: shutdown reassignment failed: %s", e.msg);
                }
            }, Duration.zero);
        } catch (Exception e) {
            logError("bgPool: shutdown listener error: %s — restarting in 5s", e.msg);
        }
        try { sleep(5.seconds); } catch (Exception) { return; }
    }
}
