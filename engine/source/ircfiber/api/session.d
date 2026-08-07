module ircfiber.api.session;

import std.array : join;
import std.conv : to;
import std.datetime : Clock, SysTime;
import std.uuid : UUID, randomUUID, parseUUID;
import std.base64 : Base64;
import std.digest.sha : SHA256;
import std.digest.hmac : HMAC;
import std.process : environment;
import std.string : indexOf, replace, split;

import core.sync.mutex : Mutex;

import vibe.core.log;
import vibe.core.sync : createSharedManualEvent, ManualEvent;
import vibe.http.websockets : WebSocket;
import vibe.data.json : Json, parseJsonString;
import vibe.container.ringbuffer : RingBuffer;
import ircfiber.storage.buffer : sanitizeUtf8;
import ircfiber.storage.redis : RedisStorage;

import ircfiber.models.user : User;
import ircfiber.models.network : Network;

package enum WS_SESSION_KEY_PREFIX = "ws_session:";
package enum JWT_TTL_SECONDS = 14 * 24 * 60 * 60; // 14 days
private enum WS_SESSION_TTL_SECONDS = 14 * 24 * 60 * 60;
private __gshared string _jwtHeaderB64;
private string jwtHeaderB64() {
    if (_jwtHeaderB64.length == 0) {
        auto h = Json.emptyObject;
        h["alg"] = Json("HS256");
        h["typ"] = Json("JWT");
        _jwtHeaderB64 = base64UrlEncode(cast(ubyte[])h.toString());
    }
    return _jwtHeaderB64;
}

/// Returns a GC-allocated `shared(ManualEvent)*`. The pointer
/// indirection keeps `UserSession` trivially copyable while letting
/// the g_ircPool thread emit and the main event loop wait on the
/// same cross-thread event.
public shared(ManualEvent)* allocSharedEvent() @trusted {
    import core.memory : GC;
    auto mem = cast(shared(ManualEvent)*) GC.malloc(ManualEvent.sizeof, GC.BlkAttr.NO_MOVE);
    // `initialize` is `private shared nothrow` on the struct; D's UFCS
    // can't see private members on a pointer type, so we go through
    // the public factory `createSharedManualEvent` and write the
    // initialized value back through the pointer.
    *mem = createSharedManualEvent();
    return mem;
}

/// Returns the JWT HMAC secret from env or a dev fallback.
/// Production MUST set IRCFIBER_JWT_SECRET.
private string jwtSecret() {
    auto secret = environment.get("IRCFIBER_JWT_SECRET", "");
    if (secret.length > 0) return secret;

    logWarn("IRCFIBER_JWT_SECRET not set; using dev fallback. Set it in production.");
    return "ircfiber-dev-jwt-secret-do-not-use-in-prod";
}

/// HMAC-SHA256 helper.
private ubyte[32] hmacSha256(const(ubyte)[] key, const(ubyte)[] data) {
    auto h = HMAC!SHA256(key);
    h.put(data);
    return h.finish();
}

/// Base64URL encode (RFC 4648 §5): standard base64 with +→-, /→_, no padding.
private string base64UrlEncode(const(ubyte)[] data) {
    auto b64 = Base64.encode(data).idup;
    b64 = b64.replace("+", "-").replace("/", "_");
    // Strip padding
    auto pad = b64.indexOf('=');
    if (pad >= 0) b64 = b64[0 .. pad];
    return b64;
}

/// Base64URL decode (RFC 4648 §5): inverse of base64UrlEncode.
private ubyte[] base64UrlDecode(string data) {
    auto b64 = data.replace("-", "+").replace("_", "/");
    // Restore padding
    switch (b64.length % 4) {
        case 2: b64 ~= "=="; break;
        case 3: b64 ~= "=";  break;
        default: break;
    }
    return Base64.decode(b64);
}

/// Creates a JWT string for the given session claims.
/// The token embeds sessionId, userId, nick, networks, and exp.
string createSessionJWT(UUID sessionId, UUID userId, string nick,
                        string[] networks, long ttlSeconds = JWT_TTL_SECONDS) {
    auto payload = Json.emptyObject;
    payload["sessionId"] = Json(sessionId.toString());
    payload["userId"] = Json(userId.toString());
    payload["nick"] = Json(nick);
    auto nets = Json.emptyArray;
    foreach (n; networks) nets ~= Json(n);
    payload["networks"] = nets;
    payload["exp"] = Json(Clock.currTime.toUnixTime() * 1000 + ttlSeconds * 1000);

    auto payloadB64 = base64UrlEncode(cast(ubyte[])payload.toString());
    auto signingInput = jwtHeaderB64() ~ "." ~ payloadB64;
    auto sig = hmacSha256(cast(ubyte[])jwtSecret(), cast(ubyte[])signingInput);
    auto sigB64 = base64UrlEncode(sig[]);

    return signingInput ~ "." ~ sigB64;
}

/// Verifies a JWT token and returns the payload Json on success, null on failure.
/// Checks HMAC signature and expiration.
Json verifySessionJWT(string token) {
    try {
        auto parts = token.split(".");
        if (parts.length != 3) return Json(null);

        // Verify header matches
        if (parts[0] != jwtHeaderB64()) return Json(null);

        // Verify signature
        auto signingInput = parts[0] ~ "." ~ parts[1];
        auto sig = hmacSha256(cast(ubyte[])jwtSecret(), cast(ubyte[])signingInput);
        auto expectedSigB64 = base64UrlEncode(sig[]);
        if (parts[2] != expectedSigB64) return Json(null);

        // Decode payload
        auto payloadJson = parseJsonString(cast(string)base64UrlDecode(parts[1]));
        if (payloadJson.type == Json.Type.null_) return Json(null);

        // Check expiration
        if (auto exp = "exp" in payloadJson) {
            if (exp.type == Json.Type.int_) {
                auto nowMs = Clock.currTime.toUnixTime() * 1000L;
                if (nowMs > exp.get!long) return Json(null); // expired
            }
        }

        return payloadJson;
    } catch (Exception e) {
        logDebug("verifySessionJWT failed: %s", e.msg);
        return Json(null);
    }
}

/// Serialize a UserSession (minus ephemeral WebSocket + outbound queue)
/// to a Json object for Redis persistence.
private Json serializeSessionForRedis(ref UserSession session) {
    auto j = Json.emptyObject;
    j["id"] = Json(session.id.toString());
    j["userId"] = Json(session.user.id.toString());
    j["username"] = Json(session.user.username);
    auto nets = Json.emptyArray;
    foreach (ref n; session.visibleNetworks) {
        auto netObj = Json.emptyObject;
        netObj["id"] = Json(n.config.id.toString());
        netObj["name"] = Json(n.config.name);
        nets ~= netObj;
    }
    j["networks"] = nets;
    j["connectedAt"] = Json(session.connectedAt.toUnixTime() * 1000L);
    j["lastSequence"] = Json(session.lastSequence);
    j["activeNetworkId"] = Json(session.activeNetworkId);
    j["activeChannel"] = Json(session.activeChannel);
    j["sinceEid"] = Json(session.sinceEid);
    j["lastDeliveredEid"] = Json(session.lastDeliveredEid);
    j["lastEnqueuedEid"] = Json(session.lastEnqueuedEid);
    return j;
}

/// Deserialize a minimal UserSession from Redis JSON.
/// The WebSocket and outbound queue are NOT restored — caller must set them.
private UserSession deserializeSessionFromRedis(Json j) {
    import std.datetime : SysTime;
    User u;
    u.id = parseUUID(j["userId"].get!string);
    u.username = j["username"].get!string;

    Network[] nets;
    foreach (netJson; j["networks"]) {
        import ircfiber.models.network : NetworkConfig;
        NetworkConfig cfg;
        cfg.id = parseUUID(netJson["id"].get!string);
        cfg.name = netJson["name"].get!string;
        Network n;
        n.config = cfg;
        nets ~= n;
    }

    auto connectedAt = SysTime.init;
    if (auto ca = "connectedAt" in j) {
        if (ca.type == Json.Type.int_) {
            connectedAt = Clock.currTime; // approximate on restore
        }
    }

    UserSession s;
    s.id = parseUUID(j["id"].get!string);
    s.user = u;
    s.visibleNetworks = nets;
    s.connectedAt = connectedAt;
    s.lastSequence = j["lastSequence"].get!long;
    s.isActive = true;
    if (auto v = "activeNetworkId" in j) s.activeNetworkId = v.get!string;
    if (auto v = "activeChannel" in j) s.activeChannel = v.get!string;
    if (auto v = "sinceEid" in j) s.sinceEid = v.get!long;
    if (auto v = "lastDeliveredEid" in j) s.lastDeliveredEid = v.get!long;
    if (auto v = "lastEnqueuedEid" in j) s.lastEnqueuedEid = v.get!long;
    s.outbound = RingBuffer!string(65536);
    s.outboundNotify = allocSharedEvent();
    return s;
}

/// Redis key for a WebSocket session blob.
private string wsSessionKey(UUID sessionId) {
    return WS_SESSION_KEY_PREFIX ~ sessionId.toString();
}



/// Aggregate outbound-queue stats across all sessions, for ops/monitoring.
struct SessionStats {
    /// Number of currently registered sessions.
    size_t total;
    /// Deepest current outbound depth across all sessions.
    size_t maxDepth;
    /// Highest eid the server has put into any session's outbound queue
    /// (largest lastEnqueuedEid). Useful for "is the server keeping up
    /// with the engine?" — if this lags the engine's global eid, the
    /// drain is behind. If the engine's global eid equals this, the
    /// server is fully caught up.
    long lastEnqueuedEid;
    /// Highest eid the client has acknowledged via the `ack` command
    /// (largest lastDeliveredEid). When this equals lastEnqueuedEid, the
    /// session is fully caught up. When it lags, the client has unprocessed
    /// frames in its queue. On disconnect, the gap is what would have been
    /// lost without scrollback persistence.
    long lastDeliveredEid;
    /// 2026-07-08: number of sessions with outbound queue > 32768
    /// (backpressured). These sessions have a slow consumer and may
    /// be dropping events. Zero means all sessions are keeping up.
    size_t backpressured;
    /// 2026-07-08: number of sessions with isActive=false (disconnected
    /// but not yet cleaned up). These are "ghost" sessions from a
    /// WS close that raced with the cleanup path. Zero means no ghosts.
    size_t ghosts;
}

/// Active WebSocket session for a user.
struct UserSession {
    /// Session unique identifier.
    UUID id;
    /// Associated user.
    User user;
    /// Networks visible to this session.
    Network[] visibleNetworks;
    /// Underlying WebSocket.
    WebSocket socket;
    /// Connection timestamp.
    SysTime connectedAt;
    /// Last event sequence number.
    long lastSequence;
    /// Whether the session is still active.
    bool isActive;
    /// Currently selected network ID.
    string activeNetworkId;
    /// Currently selected channel name.
    string activeChannel;
    /// Cross-thread notification fired by `sendToSession` after each
    /// `outbound.put()`. The drainer pump in
    /// `ircfiber.api.websocket.drainOutboundBatch` waits on this
    /// instead of polling with `sleep(5.msecs)`, so live events
    /// reach the WebSocket in microseconds rather than with a
    /// 5 ms per-event latency floor. `shared` so the g_ircPool
    /// thread can emit and the main event loop can wait.
    /// Pointer (not value) so `UserSession` stays trivially copyable —
    /// `shared ManualEvent` is a struct with non-copyable internals.
    shared(ManualEvent*) outboundNotify;
    /// IRCCloud-style stream resume: skip replayed events with eid <= this
    /// value. Set from the `?since=` query param on connect. The frontend
    /// sends maxEid so the server can replay missed events from the
    /// per-user Redis stream before live subscription starts. Used only
    /// during the initial replay; live event filtering uses
    /// `lastDeliveredEid` (updated by the `ack` client command).
    long sinceEid;
    /// Highest eid the client has acknowledged via the `ack` command.
    /// The Redis event listener filters live events with `eid <= this`,
    /// so the client never receives the same event twice over WS once
    /// it has ACKed it. Reset to 0 on reconnect so a fresh replay
    /// starts clean (the `?since=` query param handles the
    /// catch-up-from-disconnect case).
    long lastDeliveredEid;
    /// Highest eid put into this session's outbound queue. Used for
    /// "is the server keeping up?" monitoring. Does not need persistence
    /// (reconnects reset to 0 + the engine's global eid is the source
    /// of truth) but we persist for the /api/health snapshot.
    long lastEnqueuedEid;
    /// Outbound queue of JSON frames destined for the client.
    ///
    /// Decouples the producer (Redis event listener, REST handlers) from
    /// the WebSocket write fiber: `drainOutboundBatch()` in
    /// `ircfiber.api.websocket` is the sole writer to the socket.
    ///
    /// Capacity is 65536. We DO NOT drop on overflow. If the queue
    /// somehow fills, `sendToSession` logs a warning and skips the frame
    /// (the client will pick it up via the next replay or `/api/oob`).
    /// The previous "drop oldest" behavior was the root cause of the
    /// 2026-07-07 "connection logs don't show in real-time" bug.
    RingBuffer!string outbound;
}

/// Manages active WebSocket sessions. Thread-safe via an internal Mutex
/// on session-modifying methods. This enables the IRC event listener to
/// run on a dedicated thread pool (`g_ircPool`) while the main event
/// loop handles HTTP/WS I/O.
///
/// Sessions are stored in an in-memory hash map (hot path) and optionally
/// persisted to Redis (cold path / reconnect). The in-memory map is always
/// the primary lookup — `getSession()` never falls back to Redis automatically.
/// Callers explicitly invoke `restoreFromRedis()` on the reconnect cold path.
final class SessionManager {
    private {
        UserSession[UUID] sessions;
        RedisStorage redis; // null when Redis persistence is not configured
        Mutex m_mutex;
    }

    /// Creates a new session manager with optional Redis persistence.
    this() {
        m_mutex = new Mutex();
    }

    /// Configures Redis persistence for sessions.
    /// Safe to call once at boot; no-op if Redis already set.
    void setRedis(RedisStorage redisStorage) {
        if (redis is null) {
            this.redis = redisStorage;
            logInfo("SessionManager: Redis persistence enabled");
        }
    }

    /// True when Redis persistence is configured.
    @property bool hasRedis() { return redis !is null; }

    /// Creates a new session for a user.
    /// If Redis is configured, the session is also persisted to Redis with TTL.
    UserSession createSession(User user, WebSocket ws) {
        auto session = UserSession(
            id: randomUUID(),
            user: user,
            socket: ws,
            connectedAt: Clock.currTime,
            lastSequence: 0,
            isActive: true,
            lastDeliveredEid: 0,
            lastEnqueuedEid: 0,
            outbound: RingBuffer!string(65536),
            outboundNotify: allocSharedEvent()
        );

        synchronized (m_mutex) {
            sessions[session.id] = session;
        }

        // Persist to Redis if configured
        persistToRedis(session);

        return session;
    }

    /// Creates a session from an existing Redis record (restored session).
    /// The restored session gets a fresh outbound queue and no socket —
    /// the caller must attach the WebSocket.
    UserSession restoreSession(UUID sessionId, User user, WebSocket ws) {
        UserSession session;
        synchronized (m_mutex) {
            if (auto existing = sessionId in sessions) {
                // Already in memory — update socket and return
                existing.socket = ws;
                existing.isActive = true;
                return *existing;
            }
        }

        // Try Redis cold-load first
        if (redis !is null) {
            auto restored = loadFromRedis(sessionId);
            if (restored.id != UUID.init) {
                restored.socket = ws;
                restored.isActive = true;
                restored.outbound = RingBuffer!string(65536);
                restored.outboundNotify = allocSharedEvent();
                restored.lastDeliveredEid = 0;  // reset — fresh cursor for this WS
                restored.lastEnqueuedEid = 0;
                synchronized (m_mutex) {
                    sessions[restored.id] = restored;
                }
                return restored;
            }
        }

        // Fall back to a fresh session record if nothing in Redis
        return createSession(user, ws);
    }

    /// Destroys a session by ID.
    /// If Redis is configured, also removes the Redis record.
    void destroySession(UUID sessionId) {
        synchronized (m_mutex) {
            if (auto p = sessionId in sessions) {
                p.isActive = false;
                sessions.remove(sessionId);
            }
        }
        // Remove from Redis regardless of in-memory state
        removeFromRedis(sessionId);
    }

    UserSession* getSession(UUID id) {
        synchronized (m_mutex) {
            return id in sessions;
        }
    }

    /// Restores a session from Redis into the in-memory map.
    /// Returns null if the session is not in Redis or Redis is not configured.
    /// The restored session has no WebSocket or outbound data — these
    /// are ephemeral and must be re-established by the caller.
    UserSession* restoreFromRedis(UUID sessionId) {
        if (redis is null) return null;
        synchronized (m_mutex) {
            if (auto existing = sessionId in sessions) return existing; // already cached
        }

        auto restored = loadFromRedis(sessionId);
        if (restored.id == UUID.init) return null;

        synchronized (m_mutex) {
            sessions[restored.id] = restored;
            return restored.id in sessions;
        }
    }

    /// Persist a session record to Redis with TTL.
    private void persistToRedis(ref UserSession session) {
        if (redis is null) return;
        try {
            auto j = serializeSessionForRedis(session);
            redis.setJson(wsSessionKey(session.id), j, WS_SESSION_TTL_SECONDS);
        } catch (Exception e) {
            logWarn("SessionManager: failed to persist session %s: %s", session.id, e.msg);
        }
    }

    /// Remove a session record from Redis.
    private void removeFromRedis(UUID sessionId) {
        if (redis is null) return;
        try {
            redis.del(wsSessionKey(sessionId));
        } catch (Exception e) {
            logDebug("SessionManager: failed to remove session %s from Redis: %s", sessionId, e.msg);
        }
    }

    /// Load a session record from Redis. Returns UserSession.init on failure.
    private UserSession loadFromRedis(UUID sessionId) {
        try {
            auto j = redis.getJson(wsSessionKey(sessionId));
            if (j.type == Json.Type.null_) return UserSession.init;
            return deserializeSessionFromRedis(j);
        } catch (Exception e) {
            logDebug("SessionManager: failed to load session %s from Redis: %s", sessionId, e.msg);
            return UserSession.init;
        }
    }

    /// Broadcasts a message to all sessions of a user.
    void broadcastToUser(UUID userId, string message) {
        // Collect session IDs under lock, then send unlocked to
        // avoid holding the mutex across sendToSession (which also
        // acquires it, so we'd deadlock if we held it here).
        UUID[] targets;
        synchronized (m_mutex) {
            foreach (ref session; sessions) {
                if (session.user.id == userId)
                    targets ~= session.id;
            }
        }
        foreach (sid; targets)
            sendToSession(sid, message);
    }

    /// Enqueue a message into the session's outbound buffer.
    ///
    /// Returns immediately. The actual TCP write happens on the
    /// dedicated drain fiber (`drainOutboundBatch` in
    /// `ircfiber.api.websocket`). This decouples the producer (the Redis
    /// event listener on `g_ircPool`) from the WebSocket write path so a
    /// chat flood never starves either side.
    ///
    /// **We do not drop on overflow.** The previous "drop-oldest" policy
    /// was the root cause of the 2026-07-07 bug where the user had to
    /// refresh the page to see IRC connection phase events. If the queue
    /// ever fills (capacity 65536, ~2500x the previous 500), the cause is
    /// almost certainly a wedged WebSocket — `drainOutboundBatch` would
    /// stop calling `socket.send`, the queue fills, the producer logs and
    /// skips. The skipped events are still durable in scrollback (Redis
    /// + MongoDB) and the next replay/OOB fetch will recover them.
    ///
    /// Silently no-ops for unknown session IDs or disconnected sessions.
    void sendToSession(UUID sessionId, string message) {
        synchronized (m_mutex) {
            if (auto s = sessionId in sessions) {
                if (!s.isActive) return;          // already disconnected

                // Track the highest eid we're trying to send. Lets the
                // operator tell "is the server keeping up with the engine?"
                // by comparing this to the engine's global_eid in Redis.
                long eid = 0;
                try {
                    auto json = parseJsonString(message);
                    if (auto e = "eid" in json) {
                        if (e.type == Json.Type.int_) eid = e.get!long;
                    }
                } catch (Exception) {}

                if (eid > s.lastEnqueuedEid) s.lastEnqueuedEid = eid;

                if (s.outbound.full) {
                    // Should never happen with a healthy drain. Log loudly
                    // so an operator sees the WS is wedged — the session
                    // will be torn down by the next heartbeat miss.
                    logWarn("sendToSession: outbound queue full for session %s (cap=%d, eid=%d); skipping frame, client will recover via replay/oob",
                        s.id, 65536, eid);
                    return;
                }
                s.outbound.put(sanitizeUtf8(message));
                // Wake the drainer pump (ircfiber.api.websocket.drainOutboundLoop)
                // so the frame goes out in microseconds rather than after
                // the next 5ms poll tick. Multiple emits coalesce — the
                // pump will drain the entire queue before waiting again.
                s.outboundNotify.emit();
            }
        }
    }

    /// Snapshot of a session's outbound state for the WS drainer loop.
    ///
    /// The drainer MUST consume via this method (or equivalent locking)
    /// rather than holding its own `UserSession` struct copy: `UserSession`
    /// is a struct and `RingBuffer` has deep-copy semantics, so a copy's
    /// `outbound` is a private buffer whose `m_fill` never sees the puts
    /// `sendToSession` makes on the map-owned instance. That divergence is
    /// what broke live delivery after the 2026-07-08 outbound-queue change
    /// (symptom: "have to refresh the page to see connection events").
    struct OutboundPeek {
        /// Session still registered, active, and socket connected.
        bool alive;
        /// Frames popped from the map-owned queue (up to `maxBatch`).
        string[] batch;
        /// Shared event fired by `sendToSession` — wait on it when
        /// `batch` is empty. Null when the session is gone.
        shared(ManualEvent)* notify;
        /// Live WebSocket to send `batch` to (valid when `alive`).
        WebSocket socket;
        /// Remaining queue depth after the pop (backpressure signal).
        size_t depth;
    }

    /// Pop up to `maxBatch` frames from the map-owned session queue under
    /// the same mutex `sendToSession` uses. Returns `alive=false` when the
    /// session is gone, inactive, or its socket disconnected — the drainer
    /// should exit.
    OutboundPeek drainOutbound(UUID sessionId, size_t maxBatch) {
        OutboundPeek r;
        synchronized (m_mutex) {
            if (auto s = sessionId in sessions) {
                r.socket = s.socket;
                r.notify = s.outboundNotify;
                if (!s.isActive || s.socket is null || !s.socket.connected) {
                    r.alive = false;
                    return r;
                }
                r.alive = true;
                r.batch.reserve(maxBatch);
                while (r.batch.length < maxBatch && !s.outbound.empty) {
                    r.batch ~= s.outbound.front();
                    s.outbound.removeFront();
                }
                r.depth = s.outbound.length;
            }
        }
        return r;
    }

    /// Final-teardown snapshot: read the map-owned ack cursors and mark
    /// the session inactive. The gateway's WS `finally` block must use
    /// this instead of reading a local `UserSession` copy — the copy's
    /// `lastEnqueuedEid`/`lastDeliveredEid` never see the map updates,
    /// so the unacked-gap diagnostics and the persisted ack cursor would
    /// silently report zero. Returns zeros when the session is gone.
    struct SessionTeardown {
        long lastEnqueuedEid;
        long lastDeliveredEid;
    }

    SessionTeardown deactivateAndSnapshot(UUID sessionId) {
        SessionTeardown r;
        synchronized (m_mutex) {
            if (auto s = sessionId in sessions) {
                r = SessionTeardown(s.lastEnqueuedEid, s.lastDeliveredEid);
                s.isActive = false;
            }
        }
        return r;
    }

    /// Aggregate outbound-queue stats across all live sessions.
    /// Used by the `/api/health` endpoint for ops dashboards.
    SessionStats broadcastStats() {
        SessionStats stats;
        synchronized (m_mutex) {
            stats.total = sessions.length;
            foreach (ref s; sessions) {
                auto depth = s.outbound.length;
                if (depth > stats.maxDepth) stats.maxDepth = depth;
                if (s.lastEnqueuedEid > stats.lastEnqueuedEid)
                    stats.lastEnqueuedEid = s.lastEnqueuedEid;
                if (s.lastDeliveredEid > stats.lastDeliveredEid)
                    stats.lastDeliveredEid = s.lastDeliveredEid;
                // 2026-07-08: backpressure detection — queue > 32k
                if (depth > 32768) stats.backpressured++;
                // 2026-07-08: ghost detection — deactivated sessions
                if (!s.isActive) stats.ghosts++;
            }
        }
        return stats;
    }

    /// Update the highest-eid ACKed by the client. Called from the
    /// `ack` command handler in `ircfiber.api.websocket`. The Redis
    /// event listener reads this value (under the session mutex) to
    /// filter live events with `eid <= lastDeliveredEid`, so the
    /// client never sees the same event twice over the WS once it
    /// has acknowledged it.
    void acknowledgeEid(UUID sessionId, long eid) {
        synchronized (m_mutex) {
            if (auto s = sessionId in sessions) {
                if (eid > s.lastDeliveredEid) s.lastDeliveredEid = eid;
            }
        }
    }

    @property ref UserSession[UUID] getSessions() {
        synchronized (m_mutex) {
            return sessions;
        }
    }
}
