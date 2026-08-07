module ircfiber.api.websocket;

import std.uuid : UUID, parseUUID, randomUUID;
import std.conv : to;
import std.algorithm : canFind;
import std.array : join;
import std.range : walkLength;
import core.time : msecs, Duration, seconds;
import std.datetime : Clock;
import std.string : startsWith, indexOf;
import std.uni : toLower, icmp;

import vibe.core.core : runTask, sleep, yield;
import vibe.core.task : TaskSettings;
import vibe.core.log;
import vibe.http.websockets : WebSocket;
import vibe.data.json : Json, parseJsonString;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : Network, NetworkConfig;
import ircfiber.api.session : SessionManager, UserSession,
    createSessionJWT, verifySessionJWT;
import ircfiber.storage.buffer : BufferManager, sanitizeUtf8;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.auth : authenticateRequest;
import ircfiber.db.user : UserRepository;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.preferences : PreferencesRepository, UserPreferences;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.redis.protocol : RedisKeys, IRCCommand, NetworkStateSnapshot;
import ircfiber.async : watchedRunTask;
import ircfiber.observability : recordCounter;
import ircfiber.threadpool : g_ircPool;

/// Counter for yield() invocations across all three hot loops.
/// Incremented atomically (synchronized inside recordCounter) so no
/// thread-safety concerns.  Read by `drainMetrics()` in the heartbeat
/// loop and exported as OTel counter `ws_yields_total`.
private __gshared ulong g_subscriberCalls;

/// Gateway reference for IRC pool dispatch. Set from app.d once
/// at boot, before any WebSocket connections are accepted. Read
/// by pool threads delivering Redis events to user sessions.
__gshared WebSocketGateway g_gwForIrcPool;

/**
 * Decentralized WebSocket Gateway
 *
 * Routes client commands to the correct connection server based on
 * network assignments. State snapshots are loaded from server-aware keys.
 *
 * Stream sync protocol (the 2026-07-07 "real-time event delivery" redesign):
 *
 *   1. On WS open, gateway sends a `header` message with streamid +
 *      server time + idle interval. The client stores streamid for the
 *      next reconnect and uses the idle interval to detect a dead stream
 *      (matches IRCCloud's BackendController.header).
 *
 *   2. After the header, the gateway replays any events the client missed
 *      while disconnected (eid > ?since=) from the per-user Redis stream
 *      (replayMissedEvents). The client's `maxEidTracker` is the source
 *      of truth for what it has.
 *
 *   3. While connected, the client sends `ack {eid}` periodically (every
 *      5s, plus on close). The gateway stores the highest ACKed eid in
 *      `session.lastDeliveredEid` and uses it to filter live events in
 *      `ircPoolDispatch`. The client never sees an event twice over WS
 *      once it has ACKed it.
 *
 *   4. If the client detects a hole (eid gap on the live stream) it can
 *      call `/api/oob?since=<maxEid>` to fill the gap from MongoDB
 *      without reconnecting. This is the recovery path when the WS
 *      silently drops a frame.
 */
final class WebSocketGateway {
    private {
        SessionManager sessionManager;
        BufferManager bufferManager;
        RedisStorage redis;
        ServerRegistry serverRegistry;  // NEW: for server-aware routing
        string streamId;                 // IRCCloud-style stream id, set at boot
        long idleIntervalMs = 60_000;    // tell client when to expect idle
    }

    /// Creates a new WebSocket gateway.
    this(SessionManager sm, BufferManager bm, RedisStorage redis) {
        this.sessionManager = sm;
        this.bufferManager = bm;
        this.redis = redis;
        this.serverRegistry = new ServerRegistry(redis);  // NEW
        // Stream id: a single id for this gateway instance. Pinned into
        // the WS query string on every reconnect (IRCCloud-style), so the
        // bouncer can detect a client that's fallen behind and re-send
        // the header.
        this.streamId = randomUUID().toString();
    }

    /// Handles an incoming WebSocket connection.
    /// Supports stateless reconnect: if the vibe.d session carries a valid
    /// JWT (from a prior connection), the session is restored from Redis
    /// instead of created fresh. This lets the WebSocket resume the same
    /// session identity after a gateway restart or in-memory eviction.
    void handleWebSocket(WebSocket socket) {
        auto repo = new UserRepository();
        auto user = authenticateRequest(socket.request, repo);

        if (user.username.length == 0) {
            socket.close(1008, "Invalid token");
            return;
        }

        UserSession session;

        // Try JWT-based session restore (cold path from Redis).
        // Originally designed for the gateway-restart reconnect path — the
        // in-memory session map is empty after a restart, so we load the
        // session from Redis by ID.
        //
        // 2026-07-15 fix: the JWT is stored in the browser cookie, which is
        // shared across all tabs of the same origin. When a user opens a
        // SECOND tab, both tabs would re-use the FIRST tab's session: same
        // outbound queue, same socket (overwritten by the latest WS), same
        // `lastDeliveredEid` cursor. Result: messages sent in tab A never
        // appear in tab B in real-time, and only the most-recently-attached
        // socket receives events. Only restore from Redis when the session
        // is NOT in memory (true reconnect). If it IS in memory, this is a
        // new tab — fall through to the fresh-session path so the new tab
        // gets its own outbound queue, socket, and ack cursor.
        auto req = socket.request;
        if (req.session) {
            auto jwtToken = req.session.get("ws_session_jwt", "");
            if (jwtToken.length > 0) {
                auto claims = verifySessionJWT(jwtToken);
                if (claims.type != Json.Type.null_) {
                    auto sessionIdStr = claims["sessionId"].get!string;
                    try {
                        auto sessionId = parseUUID(sessionIdStr);
                        if (sessionManager.getSession(sessionId) is null) {
                            // Cold path: session is only in Redis (gateway
                            // was restarted since the last WS connected).
                            // Restore from Redis so the client resumes
                            // from its last `lastDeliveredEid` cursor.
                            auto restored = sessionManager.restoreFromRedis(sessionId);
                            if (restored !is null) {
                                // Re-attach the live WebSocket to the restored session
                                restored.socket = socket;
                                restored.isActive = true;
                                session = *restored;
                                logInfo("WebSocket session %s restored from Redis for user %s",
                                    session.id, user.username);
                            }
                        } else {
                            // Hot path: another live WS already owns this
                            // session (most likely a second tab sharing the
                            // JWT cookie). Don't reuse — create a fresh
                            // session so each tab gets independent state.
                            logInfo("WebSocket session %s already live for user %s; new tab — creating fresh session",
                                sessionId, user.username);
                        }
                    } catch (Exception e) {
                        logDebug("JWT restore failed for %s: %s", user.username, e.msg);
                    }
                }
            }
        }

        // If no restore happened, create a fresh session (hot path).
        if (session.id == UUID.init) {
            session = sessionManager.createSession(user, socket);
            logInfo("WebSocket session %s created for user %s", session.id, user.username);

            // Generate JWT for this session and store in the vibe.d session.
            // The JWT enables stateless reconnect: on next connect, the
            // middleware reads the JWT from connect.sid, verifies it, and
            // restores the in-memory session from Redis.
            if (req.session) {
                try {
                    // Collect network IDs for the JWT claims
                    string[] networkIds;
                    auto configs = (new NetworkRepository()).findByUserId(session.user.id);
                    foreach (ref cfg; configs) {
                        networkIds ~= cfg.id.toString();
                    }
                    auto jwt = createSessionJWT(session.id, session.user.id,
                        session.user.username, networkIds);
                    req.session.set("ws_session_jwt", jwt);
                } catch (Exception e) {
                    logDebug("Failed to store JWT for session %s: %s", session.id, e.msg);
                }
            }
        }

    // IRCCloud-style stream resume: parse `since` query param.
    // The frontend sends maxEid so the server can replay missed
    // events before subscribing to live updates.
    session.sinceEid = 0;
    try {
        auto sinceParam = socket.request.query.get("since", "");
        if (sinceParam.length > 0) session.sinceEid = sinceParam.to!long;
    } catch (Exception) {}
    if (session.sinceEid > 0) {
        logInfo("WebSocket session %s resumed from eid %d (streamid=%s)",
            session.id, session.sinceEid, streamId);
    }
    // 2026-07-08: restore lastDeliveredEid from Redis so a WS
    // reconnect picks up where the previous session left off.
    // The cursor survives gateway restarts and cross-device
    // sessions (different browser, same user).
    try {
        auto persistedKey = "irc:session:" ~ session.id.toString() ~ ":ack";
        auto persisted = redis.getDb().get(persistedKey);
        if (persisted.length > 0) {
            auto restored = persisted.to!long;
            if (restored > session.lastDeliveredEid) {
                session.lastDeliveredEid = restored;
                logInfo("WebSocket session %s restored lastDeliveredEid=%d from Redis",
                    session.id, restored);
            }
        }
    } catch (Exception e) {
        logDebug("Failed to restore lastDeliveredEid for session %s: %s", session.id, e.msg);
    }

        try {
            // IRCCloud-style: send the `header` first so the client has the
            // streamid + server time + idle interval before any data flows.
            // The frontend bakes streamid into the next reconnect URL.
            sendHeader(session, socket);

            // IRCCloud-style: push stat_user + networks as the first
            // WebSocket messages so the frontend can render user info and
            // the sidebar immediately — no separate REST /api/me needed.
            // The full state dump with buffers/users/topics follows.
            // Single MongoDB find + single Redis prefs load reused across
            // all three functions (was loading prefs TWICE before).
            auto bootConfigs = (new NetworkRepository()).findByUserId(session.user.id);
            auto bootPrefs = (new PreferencesRepository(redis)).load(session.user.id);
            sendStatUser(session, socket, bootPrefs);
            sendNetworkList(session, socket, bootConfigs);
            performStateDump(session, socket, bootConfigs, bootPrefs);
            // IRCCloud-style: replay events missed while disconnected.
            // Events are stored in a per-user Redis stream by the engine.
            // Always run, even on first load (sinceEid == 0), so the
            // frontend's _server buffer gets phase events (queued,
            // tcp_open, tls, registering, welcome) that were published
            // before this WebSocket subscribed to the live stream.
            // The replay caps at 200 newest events, so the first load
            // is bounded even for a long-lived session with thousands
            // of events. After replay, advance sinceEid so the live
            // pub/sub listener doesn't re-send the same events.
            auto beforeReplay = session.sinceEid;
            replayMissedEvents(session, socket);
            if (session.sinceEid > beforeReplay) {
                logInfo("Advanced sinceEid from %d to %d after replaying missed events",
                    beforeReplay, session.sinceEid);
            }
            // Only the outer setup task (subscribe + 500ms poll loop) is demoted.
            // The subscriber.listen callback runs on an internal fiber created by
            // vibe.d's Redis driver — its priority is not controllable externally.
            // Run on g_ircPool for OS-thread isolation from HTTP handlers.
            startIrcEventListenerOnPool(user.id.toString(), session.id);
            // Tier 1 wave 1 (t1-w1-t1-outbound-queue): dedicated write fiber
            // pulls outbound frames from `session.outbound` and writes them
            // to the WebSocket in batches. Groups up to 100 events or a 10ms
            // window into a single WS frame, reducing frame count by up to
            // 100x under load. Single events are sent as-is (no batch overhead).
            // See drainOutboundBatch below for the contract.
            runTask({ try { drainOutboundLoop(session.id); } catch (Exception e) {
                logDebug("drainOutboundLoop unhandled: %s", e.msg);
            } });
            enterUpdateLoop(session, socket);
        } catch (Exception e) {
            logError("WebSocket error: %s", e.msg);
        } finally {
            // Surface final delivery lag BEFORE tearing the session down.
            // Non-zero `unacked` means the client fell behind — useful for
            // diagnosing "channel stuck / messages missing" reports without
            // needing the queue gauge in /api/health. The unacked gap is
            // the number of events the gateway tried to send but the client
            // never ACKed; those events are still durable in scrollback
            // (Redis + MongoDB) so a reconnect with `?since=<maxEid>` will
            // re-replay them.
            // Read the ack cursors from the MAP-OWNED session and mark it
            // inactive under the same lock sendToSession uses. Reading a
            // local `UserSession` copy here would report zero — the copy's
            // lastEnqueuedEid/lastDeliveredEid never see sendToSession's
            // updates on the map instance (UserSession is a struct).
            auto teardown = sessionManager.deactivateAndSnapshot(session.id);
            if (teardown.lastEnqueuedEid > teardown.lastDeliveredEid) {
                logInfo("Session %s disconnected with unacked gap: lastEnqueuedEid=%d lastDeliveredEid=%d (gap=%d)",
                    session.id, teardown.lastEnqueuedEid, teardown.lastDeliveredEid,
                    teardown.lastEnqueuedEid - teardown.lastDeliveredEid);
            }
            // 2026-07-08: persist the final ack cursor to Redis so a new WS
            // for the same session (or a new session for the same user) can
            // resume from where it left off. TTL of 1 day means the key is
            // cleaned up automatically if the user is gone.
            // 2026-07-08: persist the final ack cursor to Redis so a new WS
            // for the same session (or a new session for the same user) can
            // resume from where it left off. Do NOT wrap in try-catch — D's
            // `finally` blocks disallow nested catch. Redis ops that fail
            // here are best-effort; the next WS will restore from the
            // existing stream replay path (since the ack cursor in Redis
            // is a perf optimization, not a correctness requirement).
            if (teardown.lastDeliveredEid > 0 && redis !is null) {
                string persistedKey = "irc:session:" ~ session.id.toString() ~ ":ack";
                auto db = redis.getDb();
                db.set(persistedKey, teardown.lastDeliveredEid.to!string);
                db.expire(persistedKey, 86400);
            }
            // The session is now inactive (deactivateAndSnapshot set the
            // map entry's flag), so any in-flight sendToSession() producer
            // returns early (the `!s.isActive` guard). Remove the map
            // entry to stop the redis listener; the drainer sees
            // alive=false on its next drainOutbound call and exits.
            sessionManager.destroySession(session.id);
            logInfo("WebSocket session %s destroyed", session.id);
        }
    }

    // IRCCloud-style: send the stream header first (equivalent to
    // IRCCloud's `header` stream event). The client bakes streamid into
    // the next reconnect URL; `time` is for clock-skew correction;
    // `idle_interval` tells the client when to consider the stream dead
    // and trigger a reconnect.
    //
    // Sent directly to the socket (not via sendToSession) because it
    // must be the very first frame the client sees, before any replay
    // or live data flows.
    private void sendHeader(UserSession session, WebSocket socket) {
        import std.base64 : Base64;
        auto msg = Json.emptyObject;
        msg["type"] = Json("header");
        msg["streamid"] = Json(streamId);
        msg["serverId"] = Json("ovh");  // gateway's server id; client uses for diagnostics
        msg["time"] = Json(Clock.currTime.toUnixTime!long * 1000L);
        msg["idle_interval"] = Json(idleIntervalMs);
        msg["sinceEid"] = Json(session.sinceEid);  // echo back for client sanity check
        try {
            socket.send(sanitizeUtf8(msg.toString()));
        } catch (Exception e) {
            logWarn("sendHeader: failed to send header to session %s: %s", session.id, e.msg);
        }
    }

    // IRCCloud-style: push user identity + preferences as the first
    // WebSocket message (equivalent to IRCCloud's stat_user stream event).
    // Lets the frontend render the user info immediately without waiting
    // for a REST API round-trip.  Accepts pre-loaded prefs to avoid a
    // duplicate Redis call (performStateDump also receives them).
    private void sendStatUser(UserSession session, WebSocket socket, UserPreferences prefs) {
        auto msg = Json.emptyObject;
        msg["type"] = Json("stat_user");
        msg["t"] = Json(Clock.currTime.toUnixTime!long * 1000);
        msg["username"] = Json(session.user.username);
        msg["email"] = Json(session.user.email);

        auto pinned = Json.emptyArray;
        foreach (ch; prefs.pinnedChannels) pinned ~= Json(ch);
        msg["pinnedChannels"] = pinned;

        auto archived = Json.emptyArray;
        foreach (ch; prefs.archivedChannels) archived ~= Json(ch);
        msg["archivedChannels"] = archived;

        auto slc = Json.emptyObject;
        foreach (k, v; prefs.serverlogCollapsed) slc[k] = Json(v);
        msg["serverlogCollapsed"] = slc;

        auto mc = Json.emptyObject;
        foreach (k, v; prefs.membersCollapsed) mc[k] = Json(v);
        msg["membersCollapsed"] = mc;

        auto col = Json.emptyObject;
        foreach (k, v; prefs.collapsed) col[k] = Json(v);
        msg["collapsed"] = col;

        auto ic = Json.emptyObject;
        foreach (k, v; prefs.inactiveCollapsed) ic[k] = Json(v);
        msg["inactiveCollapsed"] = ic;

        auto cc = Json.emptyObject;
        foreach (k, v; prefs.conversationsCollapsed) cc[k] = Json(v);
        msg["conversationsCollapsed"] = cc;

        auto no = Json.emptyArray;
        foreach (id; prefs.networkOrder) no ~= Json(id);
        msg["networkOrder"] = no;

        auto bp = Json.emptyObject;
        foreach (k, v; prefs.bufferPrefs) bp[k] = v;
        msg["bufferPrefs"] = bp;

        // Monotonic counter incremented by every prefsRepo.save(). The
        // frontend's mergePreferences() uses this as a last-write-wins
        // tiebreaker against its own local cache — see docs/PREF_VERSION.md.
        msg["prefVersion"] = Json(prefs.prefVersion);

        socket.send(sanitizeUtf8(msg.toString()));
    }

    // IRCCloud-style: push a lightweight network list (just names + IDs)
    // before the full state dump.  This is a fast MongoDB find with zero
    // Redis reads, so the frontend can render the sidebar with real network
    // names while the state snapshots (topics, users, buffers) are still
    // being loaded by performStateDump.
    // Accepts pre-fetched configs so we don't hit MongoDB twice on boot.
    private void sendNetworkList(UserSession session, WebSocket socket, NetworkConfig[] configs) {
        auto msg = Json.emptyObject;
        msg["type"] = Json("networks");
        msg["t"] = Json(Clock.currTime.toUnixTime!long * 1000);
        auto items = Json.emptyArray;

        foreach (ref cfg; configs) {
            auto item = Json.emptyObject;
            item["networkId"] = Json(cfg.id.toString());
            item["name"] = Json(cfg.name);
            items ~= item;
        }

        msg["items"] = items;
        socket.send(sanitizeUtf8(msg.toString()));
    }

    private void performStateDump(UserSession session, WebSocket socket, NetworkConfig[] configs, UserPreferences prefs) {
        // Server-side phase timestamps for boot profiling — included in
        // the sync message as "phases" so the frontend can correlate
        // server processing time with client-side timing marks.
        auto bootStart = Clock.currTime.toUnixTime!long * 1000;
        auto phases = Json.emptyObject;
        phases["start"] = Json(bootStart);

        auto state = Json.emptyObject;
        state["type"] = "sync";
        state["t"] = Json(Clock.currTime.toUnixTime!long * 1000);
        state["sequence"] = 0;
        state["networks"] = Json.emptyArray;
        state["phases"] = phases;

        phases["prefs"] = Json(Clock.currTime.toUnixTime!long * 1000);

        // W1-T06: pre-compute buffersToDelete during resume (sinceEid > 0).
        // Collect string[] of "networkId:bufferName" pairs for channels that
        // no longer exist server-side (ghost channels). Computed per-network
        // from the snapshot before the buffer list is populated.
        string[] buffersToDelete;
        bool isResume = session.sinceEid > 0;

        foreach (ref cfg; configs) {
            auto netObj = cfg.toJson();
            netObj["buffers"] = Json.emptyArray;

            // W1-T06: track snapshot buffer names for ghost detection
            bool[string] snapBufNames;

            // NEW: Load server-aware snapshot
            auto snap = loadStateSnapshot(cfg.id.toString());
            if (snap.config.type != Json.Type.undefined) {
                netObj["connected"] = Json(snap.connected);
                netObj["status"] = Json(snap.status);
                netObj["currentNick"] = Json(snap.currentNick);
                netObj["isAway"] = Json(snap.isAway);
                if (snap.awayMessage.length) netObj["awayMessage"] = Json(snap.awayMessage);
                // NEW: Include server attribution
                netObj["serverId"] = Json(snap.serverId);
                // Network-wide realname cache (nick → realname) so the
                // frontend can look up realnames for nicks seen in any
                // context (PM, sidebar, etc.) without depending on the
                // buffer-scoped subset.
                if (snap.realnames.type != Json.Type.undefined) {
                    auto rnObj = Json.emptyObject;
                    foreach (string k, ref v; snap.realnames) rnObj[k] = Json(v.get!string);
                    netObj["realnames"] = rnObj;
                } else {
                    netObj["realnames"] = Json.emptyObject;
                }
                // Network-wide account cache (nick → account)
                if (snap.accounts.type != Json.Type.undefined) {
                    auto acctObj = Json.emptyObject;
                    foreach (string k, ref v; snap.accounts) acctObj[k] = Json(v.get!string);
                    netObj["accounts"] = acctObj;
                } else {
                    netObj["accounts"] = Json.emptyObject;
                }
                // Network-wide ident cache (nick → ident)
                if (snap.idents.type != Json.Type.undefined) {
                    auto identObj = Json.emptyObject;
                    foreach (string k, ref v; snap.idents) identObj[k] = Json(v.get!string);
                    netObj["idents"] = identObj;
                } else {
                    netObj["idents"] = Json.emptyObject;
                }
                // Full ISUPPORT inventory the server advertised in
                // its 005 reply stream. The frontend renders this into
                // Full ISUPPORT inventory the server advertised in
                // its 005 reply stream. The frontend renders this into
                // the categorised "Server features" panel using its
                // 80-entry knowledge base (see src/lib/isupportCatalog.ts)
                // so we don't ship the catalog lookup server-side — the
                // raw values are enough for the panel to categorise.
                auto isupportObj = Json.emptyObject;
                foreach (string k, ref v; snap.isupport)
                    isupportObj[k] = Json(v);
                netObj["isupport"] = isupportObj;

                // W1-T01-rev1: structured retry status from the engine's
                // reconnect loop. Mirrors the `CONNECTION_RETRY_STATUS`
                // event payload's field names exactly so the frontend
                // can read both via the same accessor (applyRetryStatus
                // on the event side, net.retryStatus on the sync side).
                //
                // Only ship when `hasRetryStatus` is true — the engine
                // intentionally omits retryStatus on healthy / freshly
                // reset networks (persisted via the Nullable!RetryStatus
                // getter; see state.d and protocol.d). Shipping a
                // zero-valued `{attemptCount: 0, nextRetryAtMs: 0,
                // delayMs: 0}` would mask the active-retry
                // `delayMs > 0` claim (the previous Wave 1 commit's
                // zero-valued getRetryStatus() always serialized as
                // 0L for delayMs, breaking the closed-port smoke
                // assertion — see review-wave1 HIGH 1).
                if (snap.hasRetryStatus) {
                    netObj["retryStatus"] = snap.retryStatus.toJson();
                }

                // W1-T01: structured failInfo from the engine's
                // disconnect path. ONLY shipped when populated —
                // shipping an empty `{type: "", reason: ""}` would
                // make the frontend's truthy checks ambiguous
                // (network.isupport's "empty string" overlap). The
                // protocol layer's toJson() omits the field when
                // both type_ and reason are empty.
                if (snap.failInfo.type_.length > 0 || snap.failInfo.reason.length > 0) {
                    netObj["failInfo"] = snap.failInfo.toJson();
                }
            } else {
                netObj["connected"] = Json(false);
                netObj["status"] = Json("unknown");
                netObj["currentNick"] = Json(cfg.nick);
                netObj["serverId"] = Json("");
            }

            string[string] topics;
            string[][string] users;
            string[string] realnames;
            string[string] accounts;
            string[string] idents;
            if (snap.topics.type != Json.Type.undefined) {
                foreach (string k, v; snap.topics) topics[k] = v.get!string;
            }
            if (snap.users.type != Json.Type.undefined) {
                foreach (string k, v; snap.users) {
                    string[] arr;
                    foreach (item; v) arr ~= item.get!string;
                    users[k] = arr;
                }
            }
            if (snap.realnames.type != Json.Type.undefined) {
                foreach (string k, v; snap.realnames) realnames[k] = v.get!string;
            }
            if (snap.accounts.type != Json.Type.undefined) {
                foreach (string k, v; snap.accounts) accounts[k] = v.get!string;
            }
            if (snap.idents.type != Json.Type.undefined) {
                foreach (string k, v; snap.idents) idents[k] = v.get!string;
            }

            auto buffers = snap.buffers;
            if (buffers.type == Json.Type.undefined || buffers.length == 0) {
                buffers = Json.emptyArray;
                auto serverBuf = Json.emptyObject;
                serverBuf["name"] = Json("_server");
                serverBuf["type"] = Json("server");
                serverBuf["isJoined"] = Json(true);
                serverBuf["unreadCount"] = Json(0);
                serverBuf["highlight"] = Json(false);
                serverBuf["topic"] = Json("");
                serverBuf["users"] = Json.emptyArray;
                buffers ~= serverBuf;

                foreach (ch; cfg.autoJoinChannels) {
                    auto chan = Json.emptyObject;
                    chan["name"] = Json(ch);
                    chan["type"] = Json("channel");
                    chan["isJoined"] = Json(false);
                    chan["unreadCount"] = Json(0);
                    chan["highlight"] = Json(false);
                    chan["topic"] = Json("");
                    chan["users"] = Json.emptyArray;
                    buffers ~= chan;
                }
                foreach (ch; cfg.partedChannels) {
                    if (!cfg.autoJoinChannels.canFind(ch)) {
                        auto chan = Json.emptyObject;
                        chan["name"] = Json(ch);
                        chan["type"] = Json("channel");
                        chan["isJoined"] = Json(false);
                        chan["unreadCount"] = Json(0);
                        chan["highlight"] = Json(false);
                        chan["topic"] = Json("");
                        chan["users"] = Json.emptyArray;
                        buffers ~= chan;
                    }
                }
            }

            // W1-T06: collect snapshot buffer names for ghost detection
            if (snap.config.type != Json.Type.undefined) {
                foreach (ref b; buffers) {
                    auto bName = b["name"].get!string;
                    if (bName.length > 0 && bName != "_server") {
                        snapBufNames[bName.toLower()] = true;
                    }
                }
            }

            // Yield every 50 buffers during state dump so a user with
            // dozens of networks / hundreds of buffers does not starve
            // HTTP/other fibers on boot or sync.
            uint bufferCount = 0;
            foreach (ref buf; buffers) {
                auto chan = Json.emptyObject;
                chan["name"] = buf["name"];
                chan["type"] = buf["type"];
                chan["isJoined"] = buf["isJoined"];
                chan["unreadCount"] = Json(0);
                chan["highlight"] = Json(false);

                auto name = buf["name"].get!string;
                if (buf["type"].get!string == "channel") {
                    chan["topic"] = Json(topics.get(name, ""));
                    auto userArr = Json.emptyArray;
                    if (auto u = name in users) {
                        foreach (nick; *u) userArr ~= Json(nick);
                    }
                    chan["users"] = userArr;
                    // Buffer-scoped subset of the network's realname cache
                    // (only nicks present in this channel's user list). The
                    // frontend uses this to render the
                    // <span class="author-realname"> next to each nick
                    // (IRCCloud parity).
                    // NOTE: `nick` here is the raw entry from `channelUsers`
                    // which may carry a mode prefix (`@`, `+`, etc.) and a
                    // trailing `!user@host` (userhost-in-names). The
                    // network-wide cache is keyed by BARE nick, so we must
                    // strip the decorations before lookup; otherwise the
                    // subset is always empty and the member list never
                    // shows a real name.
                    auto realArr = Json.emptyObject;
                    if (auto u = name in users) {
                        foreach (nick; *u) {
                            string bare = nick;
                            while (bare.length > 0 && (bare[0] == '~' || bare[0] == '&' || bare[0] == '@' || bare[0] == '%' || bare[0] == '+'))
                                bare = bare[1 .. $];
                            auto bang = bare.indexOf('!');
                            if (bang >= 0) bare = bare[0 .. bang];
                            if (auto rn = bare in realnames)
                                realArr[nick] = Json(*rn);
                            else if (auto rn2 = nick in realnames)
                                realArr[nick] = Json(*rn2);
                        }
                    }
                    chan["realnames"] = realArr;
                    // extended-join accounts per-buffer (subset of network-wide cache)
                    auto acctArr = Json.emptyObject;
                    if (auto u = name in users) {
                        foreach (nick; *u) {
                            string bare = nick;
                            while (bare.length > 0 && (bare[0] == '~' || bare[0] == '&' || bare[0] == '@' || bare[0] == '%' || bare[0] == '+'))
                                bare = bare[1 .. $];
                            auto bang = bare.indexOf('!');
                            if (bang >= 0) bare = bare[0 .. bang];
                            if (auto acct = bare in accounts)
                                acctArr[nick] = Json(*acct);
                            else if (auto acct2 = nick in accounts)
                                acctArr[nick] = Json(*acct2);
                        }
                    }
                    chan["accounts"] = acctArr;
                    // Idents per-buffer (subset of network-wide cache)
                    auto identArr = Json.emptyObject;
                    if (auto u = name in users) {
                        foreach (nick; *u) {
                            string bare = nick;
                            while (bare.length > 0 && (bare[0] == '~' || bare[0] == '&' || bare[0] == '@' || bare[0] == '%' || bare[0] == '+'))
                                bare = bare[1 .. $];
                            auto bang = bare.indexOf('!');
                            if (bang >= 0) bare = bare[0 .. bang];
                            if (auto id = bare in idents)
                                identArr[nick] = Json(*id);
                            else if (auto id2 = nick in idents)
                                identArr[nick] = Json(*id2);
                        }
                    }
                    chan["idents"] = identArr;
                } else {
                    chan["topic"] = Json("");
                    chan["users"] = Json.emptyArray;
                    chan["realnames"] = Json.emptyObject;
                    chan["accounts"] = Json.emptyObject;
                    chan["idents"] = Json.emptyObject;
                }
                auto networkIdStr = cfg.id.toString();
                string pinName = name;
                if (buf["type"].get!string == "channel" && pinName.startsWith("#")) {
                    pinName = pinName.toLower();
                }
                chan["isPinned"] = Json(prefs.pinnedChannels.canFind(networkIdStr ~ ":" ~ pinName));

                // Include the last 200 _server messages from Redis scrollback
                // _server messages (connection logs, MOTD, welcome) are
                // loaded by the frontend via a REST call after the sync
                // arrives (App.svelte:loadBufferHistory).  Skipping them
                // here keeps the sync payload small and fast — Redis LRANGE
                // per network was the single largest contributor to
                // performStateDump latency (~5-50ms per network).
                // Non-server buffers still include their recent messages
                // so the channel sidebar shows previews immediately.

                netObj["buffers"] ~= chan;

                bufferCount++;
                if (bufferCount % 50 == 0) {
                    recordCounter("ws_yields_total", 1, ["loop": "performStateDump"]);
                    yield();
                    sleep(1.msecs);
                }
            }

            foreach (chanName; cfg.autoJoinChannels) {
                bool found = false;
                foreach (ref buf; netObj["buffers"]) {
                    if (icmp(buf["name"].get!string, chanName) == 0) { found = true; break; }
                }
                if (!found) {
                    auto chan = Json.emptyObject;
                    chan["name"] = Json(chanName);
                    chan["type"] = Json("channel");
                    chan["isJoined"] = Json(false);
                    chan["unreadCount"] = Json(0);
                    chan["highlight"] = Json(false);
                    chan["topic"] = Json("");
                    chan["users"] = Json.emptyArray;
                    netObj["buffers"] ~= chan;
                }
            }

            // Ensure parted channels are included (from config, snapshot, or both)
            string[] allParted = cfg.partedChannels;
            foreach (ch; snap.partedChannels) {
                bool dup = false;
                foreach (existing; allParted) {
                    if (icmp(existing, ch) == 0) { dup = true; break; }
                }
                if (!dup) allParted ~= ch;
            }
            foreach (chanName; allParted) {
                bool found = false;
                foreach (ref buf; netObj["buffers"]) {
                    if (icmp(buf["name"].get!string, chanName) == 0) { found = true; break; }
                }
                if (!found) {
                    auto chan = Json.emptyObject;
                    chan["name"] = Json(chanName);
                    chan["type"] = Json("channel");
                    chan["isJoined"] = Json(false);
                    chan["unreadCount"] = Json(0);
                    chan["highlight"] = Json(false);
                    chan["topic"] = Json("");
                    chan["users"] = Json.emptyArray;
                    netObj["buffers"] ~= chan;
                }
            }

            // Include last active buffer for this network
            auto cfgIdStr = cfg.id.toString();
            if (auto lastBuf = cfgIdStr in prefs.lastActiveBuffers)
                netObj["lastActiveBuffer"] = Json(*lastBuf);

            // Defense-in-depth C (frontend fallback): expose the
            // network-level channelUsers map (channel name →
            // nicks list) at the top level of the network object so
            // the frontend can synthesise buffer entries for channels
            // the engine's `channelState` lost track of. Without this
            // field, the frontend only sees channels present in
            // `snap.buffers` (which iterates `channelState.keys`); a
            // drifted channel that still has a populated `users` map
            // would render as "Inactive" with an empty member list
            // even though NAMES just arrived for it. See
            // source/ircfiber/irc/connection.d case "353" for the
            // matching engine-side self-heal.
            {
                auto chanUsersObj = Json.emptyObject;
                foreach (string k, v; users) {
                    auto arr = Json.emptyArray;
                    foreach (n; v) arr ~= Json(n);
                    chanUsersObj[k] = arr;
                }
                netObj["channelUsersMap"] = chanUsersObj;
            }

            state["networks"] ~= netObj;

            // W1-T06: detect ghost channels during resume.
            // Channels in partedChannels that are NOT in the snapshot's
            // buffer set AND NOT in autoJoinChannels → they no longer
            // exist server-side. The frontend will guard against deleting
            // pinned/archived/hidden/activeJoin channels.
            if (isResume && snap.config.type != Json.Type.undefined) {
                foreach (ch; cfg.partedChannels) {
                    if (ch.length == 0 || ch == "_server") continue;
                    bool isAuto = false;
                    foreach (aj; cfg.autoJoinChannels) {
                        if (icmp(aj, ch) == 0) { isAuto = true; break; }
                    }
                    if (isAuto) continue;
                    if (ch.toLower() !in snapBufNames) {
                        buffersToDelete ~= cfgIdStr ~ ":" ~ ch.toLower();
                    }
                }
            }
        }
        phases["networks"] = Json(Clock.currTime.toUnixTime!long * 1000);

        socket.send(sanitizeUtf8(state.toString()));
        phases["sent"] = Json(Clock.currTime.toUnixTime!long * 1000);

        // W1-T06: emit buffersToDelete after sync on resume
        if (isResume && buffersToDelete.length > 0) {
            auto btd = Json.emptyObject;
            btd["type"] = Json("buffersToDelete");
            auto bidArr = Json.emptyArray;
            foreach (bid; buffersToDelete) bidArr ~= Json(bid);
            btd["bid"] = bidArr;
            socket.send(sanitizeUtf8(btd.toString()));
        }
    }

    private NetworkStateSnapshot loadStateSnapshot(string networkId) {
        // Server-aware key first — skip legacy lookup entirely if we got data.
        // Previously this always queried the legacy key even when the
        // server-aware key succeeded, doubling Redis round trips per network.
        auto serverId = serverRegistry.getServerForNetwork(networkId);

        if (serverId.length > 0) {
            auto fields = redis.hgetAll(RedisKeys.state(serverId, networkId));
            if ("data" in fields) {
                try { return NetworkStateSnapshot.fromJson(parseJsonString(fields["data"])); }
                catch (Exception e) { logWarn("Failed to parse server-aware snapshot for %s", networkId); }
            }
        }

        // Legacy fallback only when no server assignment or server key empty.
        auto fields = redis.hgetAll(RedisKeys.state_legacy(networkId));
        if ("data" in fields) {
            try { return NetworkStateSnapshot.fromJson(parseJsonString(fields["data"])); }
            catch (Exception e) { logWarn("Failed to parse legacy snapshot for %s", networkId); }
        }
        return NetworkStateSnapshot.init;
    }

    /**
     * IRCCloud-style stream resume: replay events the user missed while
     * disconnected. Reads the per-user Redis stream (LPUSHed by the engine),
     * filters events with eid > sinceEid, sends the newest 200, and trims
     * the list. After replay, the live pub/sub listener takes over.
     */
    private void replayMissedEvents(UserSession session, WebSocket socket) {
        try {
            import std.string : indexOf;
            auto db = redis.getDb();
            auto streamKey = RedisKeys.userStream(session.user.id.toString());
            // Read ALL entries from the per-user stream (oldest → newest).
            // lrange returns oldest-first, but we need newest-first to send
            // chronologically. The stream is trimmed to 1000 entries by the
            // processor, so reading 0 to -1 (all) covers the full window.
            // Previously read only 500, which could drop phase events when
            // there were 500+ newer chat messages in the stream.
            auto raw = db.lrange!(ubyte[])(streamKey, 0, -1);
            if (raw.walkLength == 0) return;

            // Collect events with eid > sinceEid. Track the highest
            // eid seen so we can advance session.sinceEid after replay,
            // preventing the live pub/sub listener from re-sending them.
            string[] toSend;
            long maxEid = session.sinceEid;
            foreach (entry; raw) {
                string s;
                try { s = () @trusted { return cast(string)entry.idup; } (); }
                catch (Exception) { continue; }
                try { s = sanitizeUtf8(s); }
                catch (Exception) { continue; }
                if (s.length == 0) continue;
                try {
                    auto json = parseJsonString(s);
                    long eid;
                    if (auto e = "eid" in json) {
                        if (e.type == Json.Type.int_) eid = e.get!long;
                    }
                    if (eid > session.sinceEid) {
                        toSend ~= s;
                        if (eid > maxEid) maxEid = eid;
                    }
                } catch (Exception) {}
            }
            if (toSend.length == 0) return;

            logInfo("Replaying %d missed events for session %s (sinceEid=%d, maxEid=%d)",
                cast(int)toSend.length, session.id, session.sinceEid, maxEid);

            // Advance sinceEid so the live pub/sub listener skips
            // events we just replayed. Without this, the same events
            // could be delivered twice when sinceEid started at 0
            // (first load) — the pub/sub listener at line 580 checks
            // `eid <= session.sinceEid` to filter, but sinceEid was
            // never updated after replay.
            if (maxEid > session.sinceEid) {
                session.sinceEid = maxEid;
            }

            // Send events in chronological order (oldest first). The LPUSH
            // stream returns newest-first (head = most recent), so we must
            // reverse before sending. Without this, the frontend's
            // groupServerLog receives events out of order and can't
            // correctly group connection phases, MOTD, and welcome
            // banner into the right attempt card.
            import std.algorithm : reverse;
            toSend.reverse();

            // Send each event directly to the WebSocket. sessionManager
            // sanitizes UTF-8 on the way out (single source of truth).
            // Yield every 50 iterations so the WS read fiber does not
            // starve HTTP/other fibers during a flood of missed events.
            foreach (i, msg; toSend) {
                sessionManager.sendToSession(session.id, msg);
                if ((i + 1) % 50 == 0) {
                    recordCounter("ws_yields_total", 1, ["loop": "replayMissedEvents"]);
                    yield();
                    sleep(1.msecs);
                }
            }
        } catch (Exception e) {
            logWarn("Failed to replay missed events for session %s: %s", session.id, e.msg);
        }
    }

    private void redisEventListener(string userId, UUID sessionId) {
        if (!redis.getClient) return;
        auto subscriber = redis.getClient.createSubscriber();
        auto channel = RedisKeys.events(userId);
        subscriber.subscribe(channel);

        auto task = subscriber.listen((string ch, string msg) @safe nothrow {
            try {
                // IRCCloud-style: do NOT log every event on the hot path.
                // Logging even at INFO level was adding 1-10ms per message
                // on the listener thread, which serialized all 50 messages
                // of a paste into a slow trickle instead of a single batch.
                // The sinceEid filter and dispatch below run at full speed.
                // IRCCloud-style sinceEid filter: skip events the client
                // already processed. Only forward events with eid > sinceEid.
                bool shouldSkip = false;
                () @trusted {
                    if (auto session = sessionManager.getSession(sessionId)) {
                        if (session.sinceEid > 0) {
                            try {
                                auto json = parseJsonString(msg);
                                long eid;
                                if (auto e = "eid" in json) {
                                    if (e.type == Json.Type.int_) eid = e.get!long;
                                }
                                if (eid > 0 && eid <= session.sinceEid) {
                                    shouldSkip = true;
                                }
                            } catch (Exception) {}
                        }
                    }
                }();
                if (shouldSkip) return;
                // sessionManager.sendToSession sanitizes UTF-8 internally.
                () @trusted { sessionManager.sendToSession(sessionId, msg); }();

                // Yield every 100 subscriber callbacks so the Redis event
                // listener does not starve HTTP/other fibers during a flood.
                () @trusted {
                    g_subscriberCalls++;
                    if (g_subscriberCalls % 100 == 0) {
                        recordCounter("ws_yields_total", 1, ["loop": "subscriber"]);
                        yield();
                        sleep(1.msecs);
                    }
                }();
            } catch (Exception e) {
                logWarn("redisEventListener error: %s", e.msg);
            }
        }, Duration.zero);

        logInfo("Subscribed to Redis events for user %s session %s", userId, sessionId);

        while (sessionManager.getSession(sessionId) !is null) {
            sleep(500.msecs);
        }

        try { subscriber.bstop(); } catch (Exception e) {}
        try { task.join(); } catch (Exception e) {}
        logInfo("Unsubscribed from Redis events for user %s session %s", userId, sessionId);
    }

    /**
     * Dedicated write fiber for a single WS session.
     *
     * Pulls framed JSON strings from the session's map-owned `outbound`
     * queue (via `SessionManager.drainOutbound`, which pops under the
     * same mutex `sendToSession` uses) and writes them to the WebSocket.
     * Blocks on the outbound notify event when the queue is empty so the
     * fiber is cheap while idle but wakes quickly under load.
     *
     * The session is addressed by ID, never by struct copy: `UserSession`
     * is a struct and `RingBuffer` deep-copies on assignment, so any
     * drainer holding its own copy would read a queue that never fills —
     * the 2026-07-08 regression this replaces ("have to refresh the page
     * to see connection events").
     *
     * Termination conditions (any one is enough to exit):
     *   - `drainOutbound` reports the session gone/inactive (set by
     *     `handleWebSocket`'s `finally` block at disconnect time).
     *   - `socket.send()` throws (peer disconnected mid-write); caught
     *     and the loop breaks gracefully. Any frames still buffered are
     *     abandoned — the session is going away anyway.
     */
    private void drainOutboundLoop(UUID sessionId) {
        while (true) {
            auto peek = sessionManager.drainOutbound(sessionId, 100);
            if (!peek.alive) return; // session gone / inactive / disconnected

            if (peek.batch.length == 0) {
                // Block on the cross-thread event fired by sendToSession
                // so live frames go out in microseconds instead of after
                // a 5ms polling tick. The 5-second timeout is a safety
                // net in case a notify is ever lost (e.g. session
                // destroyed mid-wait); the loop's `alive` check on the
                // next drainOutbound call catches the destruction.
                if (peek.notify !is null)
                    peek.notify.waitUninterruptible(5.seconds, peek.notify.emitCount);
                continue;
            }

            // Build the WS frame
            string frame;
            if (peek.batch.length == 1) {
                // Single event — send as-is (same as current behavior)
                frame = peek.batch[0];
            } else {
                // Multi-event batch: wrap in JSON array envelope
                // Format: {"batch":[{e1},{e2},...],"batchSize":N}
                frame = "{\"batch\":[" ~ peek.batch.join(",") ~ "],\"batchSize\":" ~ to!string(peek.batch.length) ~ "}";
            }

            try {
                peek.socket.send(sanitizeUtf8(frame));
            } catch (Exception e) {
                logDebug("drainOutboundLoop send error: %s", e.msg);
                return;
            }

            // 2026-07-08: backpressure signal — when the outbound queue
            // exceeds 32k entries, log a metric so the engine can detect
            // a slow consumer and yield to let the WS catch up. The
            // metric fires once per flood-check interval, not every
            // iteration, to avoid log spam.
            auto depth = peek.depth;
            if (depth > 32768 && depth % 1000 < 100) {
                recordCounter("ws_backpressure", 1,
                    ["sessionId": sessionId.to!string, "depth": depth.to!string]);
                logWarn("Backpressure: session %s outbound queue at %d entries (cap 65536) — consumer may be slow",
                    sessionId, depth);
            }
        }
    }

    private void enterUpdateLoop(UserSession session, WebSocket socket) {
        while (socket.connected) {
            try {
                auto msg = socket.receiveText();
                if (msg.length > 0) {
                    handleClientMessage(session, msg);
                }
            } catch (Exception) {
                break;
            }
            yield();
        }
    }

    private void handleClientMessage(UserSession session, string text) {
        try {
            auto json = parseJsonString(text);
            if (json["cmd"].type == Json.Type.undefined) {
                logDebug("Received WebSocket message without 'cmd' field");
                return;
            }
            auto cmd = json["cmd"].get!string;

            // Handle ack first - it's the smallest, highest-priority message
            // and feeds the live-event filter. Sent every ~5s by the
            // client (plus on close) to keep lastDeliveredEid current.
            // No eid parameter is treated as "I have nothing yet" (a noop).
            if (cmd == "ack") {
                if (auto e = "eid" in json) {
                    if (e.type == Json.Type.int_) {
                        sessionManager.acknowledgeEid(session.id, e.get!long);
                    }
                }
                return;
            }

            // Handle sync first - it doesn't need a network
            if (cmd == "sync") {
                if (session.socket.connected) {
                    try {
                        // Periodic sync: configs and prefs aren't cached, re-fetch.
                        auto configs = (new NetworkRepository()).findByUserId(session.user.id);
                        auto prefs = (new PreferencesRepository(redis)).load(session.user.id);
                        performStateDump(session, session.socket, configs, prefs);
                    } catch (Exception e) {
                        logWarn("Failed to send sync dump: %s", e.msg);
                    }
                }
                return;
            }

            if (json["network"].type == Json.Type.undefined) {
                logWarn("Received '%s' command without 'network' field", cmd);
                return;
            }
            auto networkId = json["network"].get!string;

            // NEW: Get assigned server for routing
            auto serverId = serverRegistry.getServerForNetwork(networkId);

            // Buffer-switch is local to the gateway; no engine needed.
            if (cmd == "buffer") {
                session.activeNetworkId = networkId;
                session.activeChannel = json["channel"].get!string;
                // Persist last active buffer per network
                auto prefsRepo = new PreferencesRepository(redis);
                auto prefs = prefsRepo.load(session.user.id);
                prefs.lastActiveBuffers[networkId] = session.activeChannel;
                prefsRepo.save(session.user.id, prefs);
                return;
            }

            // For any command that needs an engine, verify one is healthy and
            // surface a visible error to the user when it isn't.
            if (!ensureEngineHealthy(session, networkId, serverId, cmd)) {
                return;
            }

            switch (cmd) {
                case "msg":
                    auto target = json["target"].get!string;
                    auto textMsg = json["text"].get!string;
                    auto c = IRCCommand("msg", target, textMsg);
                    c.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                    if (json["label"].type != Json.Type.undefined) {
                        c.label = json["label"].get!string;
                    }
                    routeCommand(networkId, serverId, c);
                    break;
                case "editmsg":
                    auto editTarget = json["target"].get!string;
                    auto editText = json["text"].get!string;
                    auto ec = IRCCommand("editmsg", editTarget, editText);
                    ec.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                    if (json["label"].type != Json.Type.undefined) {
                        ec.label = json["label"].get!string;
                    }
                    routeCommand(networkId, serverId, ec);
                    break;
                case "join":
                    auto channel = json["channel"].get!string;
                    auto c = IRCCommand("join", channel, "");
                    c.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                    routeCommand(networkId, serverId, c);
                    break;
                case "part":
                    auto channel = json["channel"].get!string;
                    auto c = IRCCommand("part", channel, "");
                    c.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                    routeCommand(networkId, serverId, c);
                    break;
                case "raw":
                    auto textMsg = json["text"].get!string;
                    auto c = IRCCommand("raw", "", textMsg);
                    c.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                    routeCommand(networkId, serverId, c);
                    break;
                default:
                    logWarn("Unknown client command: %s", cmd);
            }
        } catch (Exception e) {
            logError("Failed to handle client message: %s", e.msg);
        }
    }

    /**
     * Verify a healthy IRC engine is available to handle the command.
     *
     * If no engine is registered, or the assigned engine is unhealthy/missing,
     * push a system ERROR event to the client's chat and log a warning. The
     * caller should skip enqueueing the command in that case.
     *
     * Returns: true when an engine can take the command, false otherwise.
     */
    private bool ensureEngineHealthy(UserSession session, string networkId, string serverId, string cmd) {
        bool assigned = serverId.length > 0;
        bool healthy = assigned && serverRegistry.isServerHealthy(serverId);
        if (healthy) return true;

        auto healthyServers = serverRegistry.getHealthyServers();
        string reason;
        if (healthyServers.length == 0) {
            reason = "No IRC engine is running. Start one with `make up` (or run ./irc-fiber-engine). " ~
                     "The message has not been sent.";
        } else if (!assigned) {
            reason = "This network is not assigned to any engine yet. " ~
                     "Try reconnecting the network from the Edit dialog.";
        } else {
            reason = "The IRC engine handling this network (" ~ serverId ~
                     ") is offline. The message has not been sent. " ~
                     "Start the engine or reassign the network.";
        }

        logWarn("Engine unavailable: cmd=%s network=%s assignedServer=%s healthyEngines=%d reason=%s",
            cmd, networkId, serverId, healthyServers.length, reason);

        try {
            string networkName = lookupNetworkName(networkId);
            auto evt = Json.emptyObject;
            evt["type"] = Json("irc_event");
            evt["command"] = Json("ERROR");
            evt["network"] = Json(networkName);
            evt["channel"] = Json("_server");
            evt["text"] = Json(reason);
            evt["timestamp"] = Json(Clock.currTime.toISOExtString());
            evt["t"] = Json(Clock.currTime.toUnixTime!long * 1000);
            if (session.socket.connected) {
                session.socket.send(evt.toString());
            }
        } catch (Exception e) {
            logWarn("Failed to deliver engine-down notice to session %s: %s", session.id, e.msg);
        }
        return false;
    }

    private string lookupNetworkName(string networkId) {
        try {
            auto cfg = (new NetworkRepository()).findById(parseUUID(networkId));
            if (cfg.name.length > 0) return cfg.name;
        } catch (Exception) {}
        return networkId;
    }
    
    /// Expose the session manager for cross-pool dispatch.
    /// The IRC event listener (running on g_ircPool) needs this to
    /// deliver Redis pub/sub messages to the correct user session.
    /// Thread-safe — all public SessionManager methods are mutex-protected.
    public ref SessionManager getSessionManager() {
        return this.sessionManager;
    }

    /// Forwarding method for delivering messages to a session from
    /// a pool thread. Thread-safe via SessionManager's internal Mutex.
    public void sendToSession(UUID sessionId, string message) {
        this.sessionManager.sendToSession(sessionId, message);
    }

    // NEW: Route command to correct server or legacy queue
    private void routeCommand(string networkId, string serverId, IRCCommand cmd) {
        if (serverId.length > 0) {
            redis.lpush(RedisKeys.cmd(serverId, networkId), cmd.toJson().toString());
        } else {
            // Legacy fallback
            redis.lpush(RedisKeys.cmd_legacy(networkId), cmd.toJson().toString());
        }
    }
}

// ---------------------------------------------------------------------------
// IRC pool dispatch
// ---------------------------------------------------------------------------

/// Starts the Redis event listener for a user session on g_ircPool.
///
/// Creates a fresh Redis subscriber on the pool thread (isolated from the
/// gateway's main-thread Redis connection) and delivers events to the user
/// session via g_gwForIrcPool. The pool thread is dedicated to IRC event
/// processing so a chat flood never starves HTTP handlers.
///
/// The listener exits when the session is destroyed.
void startIrcEventListenerOnPool(string userId, UUID sessionId) {
    // Copy to heap so the slice survives the thread boundary.
    auto uid = userId.idup;

    g_ircPool.runTask(&ircPoolDispatch, uid, sessionId);
}

/// Module-level function pointer for TaskPool.runTask.
/// Runs on a g_ircPool worker thread. Creates its own Redis connection,
/// subscribes to the user's event channel, and forwards messages to the
/// session via g_gwForIrcPool.
private void ircPoolDispatch(string userId, UUID sessionId) nothrow @trusted {
    import std.process : environment;
    import ircfiber.storage.redis : RedisStorage;

    try {
        // Create a fresh Redis connection on this pool thread.
        auto redis = new RedisStorage();
        redis.connectFromUrl(environment.get("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379"));

        auto subscriber = redis.getClient.createSubscriber();
        auto channel = RedisKeys.events(userId);
        subscriber.subscribe(channel);

        logInfo("ircPool: subscribed to events for user %s session %s", userId, sessionId);

        subscriber.listen((string ch, string msg) @safe nothrow {
            try {
                auto gw = () @trusted { return g_gwForIrcPool; } ();
                if (gw is null) return;

                // Cursor-based filter: drop events the client already has.
                // Two cursors, in priority order:
                //   1. `lastDeliveredEid` (updated by client `ack` command) —
                //      primary filter for the live stream. Tells us the
                //      highest eid the client has actually received and
                //      processed, so any event <= this would be a duplicate.
                //   2. `sinceEid` (set from `?since=` on connect) — fallback
                //      used during the brief window between WS open and
                //      the first `ack` arriving. Once `lastDeliveredEid`
                //      catches up, `sinceEid` is dead weight.
                bool shouldSkip = false;
                auto sm = () @trusted { return gw.getSessionManager(); } ();
                if (sm !is null) {
                    if (auto session = () @trusted { return sm.getSession(sessionId); } ()) {
                        try {
                            auto json = parseJsonString(msg);
                            long eid;
                            if (auto e = "eid" in json) {
                                if (e.type == Json.Type.int_) eid = e.get!long;
                            }
                            // Filter on the higher of the two cursors.
                            // This handles both: the first connect before
                            // any ack has arrived (filter on sinceEid), and
                            // the steady state where the client is acking
                            // every 5s (filter on lastDeliveredEid).
                            long cursor = session.lastDeliveredEid;
                            if (session.sinceEid > cursor) cursor = session.sinceEid;
                            if (eid > 0 && eid <= cursor) shouldSkip = true;
                        } catch (Exception) {}
                    }
                }
                if (shouldSkip) return;

                // Wrapping in @trusted: the Mutex inside sendToSession
                // provides thread safety; the @system annotation is a false
                // positive from the aggregate nature of the method call.
                () @trusted { gw.sendToSession(sessionId, msg); } ();

                // Yield every 100 subscriber callbacks so the Redis event
                // listener does not starve HTTP/other fibers during a flood.
                () @trusted {
                    g_subscriberCalls++;
                    if (g_subscriberCalls % 100 == 0) {
                        recordCounter("ws_yields_total", 1, ["loop": "subscriber"]);
                        yield();
                        sleep(1.msecs);
                    }
                }();
            } catch (Exception e) {
                logWarn("redisEventListener error: %s", e.msg);
            }
        }, Duration.zero);

        // Poll until the session is destroyed.
        while (true) {
            auto gw = () @trusted { return g_gwForIrcPool; } ();
            if (gw is null) break;
            auto sm = () @trusted { return gw.getSessionManager(); } ();
            if (sm is null || () @trusted { return sm.getSession(sessionId); } () is null) break;
            sleep(500.msecs);
        }

        try subscriber.bstop(); catch (Exception) {}
        logInfo("ircPool: unsubscribed from events for user %s session %s", userId, sessionId);
    } catch (Exception e) {
        logError("ircPool: listener failed for session %s: %s", sessionId, e.msg);
    }
}
