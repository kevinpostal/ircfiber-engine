module ircfiber.api.rest;

import std.uuid : UUID, parseUUID, randomUUID;
import std.conv : to;
import std.datetime : Clock;
import std.algorithm : canFind, filter;
import std.array : array;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse;
import vibe.http.router : URLRouter;
import vibe.data.json : Json, deserializeJson, parseJson, parseJsonString, serializeToJson;
import vibe.data.bson : Bson;
import vibe.core.log;

import ircfiber.models.user : User;
import ircfiber.models.network : NetworkConfig, TLSMode, SASLMechanism, dedupChannels;
import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.messages : MessageRepository;
import ircfiber.db.preferences : PreferencesRepository, UserPreferences;
import ircfiber.db.uploads : UploadRepository, UploadRecord;
import ircfiber.db.pastebins : PastebinRepository, PasteRecord, countLines;
import ircfiber.upload.local : LocalUploadResult, LocalUploadException, saveUpload, uploadDir;
import std.file : remove;
import std.path : buildPath;
import std.string : strip, indexOf;
import ircfiber.auth : requireAuth;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.irc.server : ConnectionServer;
import ircfiber.redis.protocol : RedisKeys, ControlMessage, NetworkStateSnapshot, IRCCommand;
import ircfiber.api.session : SessionManager, SessionStats;

/**
 * Decentralized REST API
 * 
 * Routes commands to the correct connection server based on network
 * assignments stored in the ServerRegistry. Each command is pushed to
 * the server-specific queue rather than the global queue.
 */
final class RESTAPI {
    private {
        BufferManager bufferManager;
        NetworkRepository networkRepo;
        PreferencesRepository prefsRepo;
        UploadRepository uploadRepo;
        PastebinRepository pastebinRepo;
        RedisStorage redis;
        ServerRegistry serverRegistry;  // NEW: decentralized routing
        SessionManager sessionManager;  // T1-W3: gateway contention metrics
    }

    /// Creates a new REST API handler.
    this(BufferManager bm, RedisStorage redis, SessionManager sm = null) {
        this.bufferManager = bm;
        this.redis = redis;
        this.sessionManager = sm;
        this.networkRepo = new NetworkRepository();
        this.prefsRepo = new PreferencesRepository(redis);
        this.uploadRepo = new UploadRepository();
        this.pastebinRepo = new PastebinRepository();
        this.serverRegistry = new ServerRegistry(redis);  // NEW
    }

    /// Registers REST routes on the given router.
    void registerRoutes(URLRouter router) {
        router.get("/api/networks", &getNetworks);
        router.post("/api/networks", &createNetwork);
        router.put("/api/networks/:id", &updateNetwork);
        router.patch("/api/networks/:id", &updateNetwork);
        router.delete_("/api/networks/:id", &deleteNetwork);
        router.get("/api/channels/:network/:channel/messages", &getMessages);
        router.post("/api/networks/:network/join", &joinChannel);
        router.post("/api/networks/:network/part", &partChannel);
        router.post("/api/networks/:id/disconnect", &disconnectNetwork);
        router.post("/api/networks/:id/reconnect", &reconnectNetwork);
        router.post("/api/networks/:id/buffers/clear", &clearNetworkBuffer);
        router.get("/api/me", &getMe);
        router.post("/api/me/pins", &pinChannel);
        router.delete_("/api/me/pins/:network/:channel", &unpinChannel);
        router.post("/api/me/archives", &archiveChannel);
        router.delete_("/api/me/archives/:network/:channel", &unarchiveChannel);
        router.post("/api/me/members-collapsed", &updateMembersCollapsed);
        router.post("/api/me/conversations-collapsed", &updateConversationsCollapsed);
        router.post("/api/me/serverlog-collapsed", &updateServerlogCollapsed);
        router.post("/api/me/buffer-prefs", &updateBufferPrefs);
        router.post("/api/me/collapsed", &updateCollapsed);
        router.post("/api/me/inactive-collapsed", &updateInactiveCollapsed);
        router.post("/api/me/network-order", &updateNetworkOrder);
        router.get("/api/ping", &ping);
        router.get("/api/health", &healthCheck);
        router.get("/health", &healthCheck);
        // 2026-07-07 redesign: OOB (out-of-band) event fetch for hole
        // filling. The client calls this when it detects a gap in the
        // eid stream from the WS (e.g. WS silently dropped a frame).
        // Returns events with eid > `since`, across all channels of
        // the requested network, so the client can route them by channel.
        router.get("/api/oob", &getOOBEvents);
        // NEW: Decentralized endpoints
        router.get("/api/servers", &getServers);  // List connection servers
        router.get("/api/servers/:id", &getServer);  // Server health/status
        // Handoff / hot-reload admin endpoint
        router.get("/api/admin/handoff/status", &getHandoffStatus);
        // Manual draining recovery: clear a stuck draining flag
        router.post("/api/admin/servers/:id/clear-draining", &clearServerDraining);
        // Upload endpoints
        router.post("/api/upload", &uploadFile);
        router.get("/api/uploads", &getUploads);
        router.delete_("/api/uploads/:id", &deleteUpload);
        // Pastebin (text snippet) endpoints
        router.get("/api/pastebins", &getPastebins);
        router.post("/api/pastebins", &createPastebin);
        router.put("/api/pastebins/:id", &updatePastebin);
        router.delete_("/api/pastebins/:id", &deletePastebin);
        router.get("/api/pastebins/:id/raw", &getPastebinRaw);
        // W3-T01a: Bulk archive-names endpoint (cached, 5-min TTL)
        router.get("/api/buffers/archive-names", &getArchiveNames);
    }

    private void getNetworks(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto configs = networkRepo.findByUserId(user.id);
        Json[] arr;
        foreach (ref cfg; configs) {
            auto j = cfg.toJson();
            auto snap = loadSnapshot(cfg.id.toString());
            j["connected"] = Json(snap.connected);
            j["status"] = Json(snap.status);
            j["currentNick"] = Json(snap.currentNick.length ? snap.currentNick : cfg.nick);
            j["isAway"] = Json(snap.isAway);
            if (snap.awayMessage.length) j["awayMessage"] = Json(snap.awayMessage);
            // NEW: Include server assignment
            j["serverId"] = Json(serverRegistry.getServerForNetwork(cfg.id.toString()));
            if (snap.caps.length) {
                auto capsArr = Json.emptyArray;
                foreach (c; snap.caps) capsArr ~= Json(c);
                j["caps"] = capsArr;
            }
            arr ~= j;
        }
        res.writeJsonBody(Json(arr));
    }

    private void createNetwork(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;

        NetworkConfig cfg;
        cfg.id = randomUUID();
        cfg.name = bodyJson["name"].get!string;
        cfg.host = bodyJson["host"].get!string;
        cfg.port = cast(ushort) bodyJson["port"].get!int;
        cfg.tls = bodyJson["tls"].get!string.to!TLSMode;
        cfg.nick = bodyJson["nick"].get!string;

        if (bodyJson["realName"].type != Json.Type.undefined) {
            cfg.realName = bodyJson["realName"].get!string;
            if (cfg.realName.length == 0) cfg.realName = cfg.nick;
        } else {
            cfg.realName = cfg.nick;
        }

        cfg.autoJoinChannels = dedupChannels(deserializeJson!(string[])(bodyJson["autoJoinChannels"]));
        if (bodyJson["partedChannels"].type != Json.Type.undefined)
            cfg.partedChannels = dedupChannels(deserializeJson!(string[])(bodyJson["partedChannels"]));

        // SASL authentication fields
        if (bodyJson["sasl"].type != Json.Type.undefined)
            cfg.sasl = bodyJson["sasl"].get!string.to!SASLMechanism;
        if (bodyJson["saslUsername"].type != Json.Type.undefined)
            cfg.saslUsername = bodyJson["saslUsername"].get!string;
        if (bodyJson["saslPassword"].type != Json.Type.undefined)
            cfg.saslPassword = bodyJson["saslPassword"].get!string;

        // NickServ password, connect commands, and server password
        if (bodyJson["nspass"].type != Json.Type.undefined)
            cfg.nspass = bodyJson["nspass"].get!string;
        if (bodyJson["commands"].type != Json.Type.undefined)
            cfg.commands = bodyJson["commands"].get!string;
        if (bodyJson["serverPass"].type != Json.Type.undefined)
            cfg.serverPass = bodyJson["serverPass"].get!string;

        // Auto-join delay (seconds after connect before JOINs are sent).
        // 0 = join immediately after registration (legacy behavior).
        if (bodyJson["autoJoinDelaySeconds"].type != Json.Type.undefined) {
            auto v = bodyJson["autoJoinDelaySeconds"].get!int;
            cfg.autoJoinDelaySeconds = v > 0 ? cast(uint) v : 0;
        }

        networkRepo.save(cfg, user.id);
        redis.del(RedisKeys.userNetworks(user.id.toString()));

        // NEW: Assign to a healthy server and route to server-specific queue
        string serverId = serverRegistry.assignNetwork(cfg.id.toString());
        if (serverId.length == 0) {
            logError("Failed to assign network to server — no healthy connection servers");
            res.statusCode = 503;
            res.writeJsonBody(Json(["error": Json("No healthy connection servers available")]));
            return;
        }

        auto msg = ControlMessage("addNetwork", cfg.id.toString(), user.id.toString(), cfg.toJson());
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());

        res.writeJsonBody(cfg.toJson());
    }

    private void updateNetwork(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto id = parseUUID(req.params["id"]);
        auto bodyJson = req.json;
        auto cfg = networkRepo.findById(id);

        if (bodyJson["name"].type != Json.Type.undefined) cfg.name = bodyJson["name"].get!string;
        if (bodyJson["host"].type != Json.Type.undefined) cfg.host = bodyJson["host"].get!string;
        if (bodyJson["port"].type != Json.Type.undefined) cfg.port = cast(ushort) bodyJson["port"].get!int;
        if (bodyJson["tls"].type != Json.Type.undefined) cfg.tls = bodyJson["tls"].get!string.to!TLSMode;
        if (bodyJson["nick"].type != Json.Type.undefined) cfg.nick = bodyJson["nick"].get!string;

        if (bodyJson["realName"].type != Json.Type.undefined) {
            cfg.realName = bodyJson["realName"].get!string;
            if (cfg.realName.length == 0) cfg.realName = cfg.nick;
        }

        if (bodyJson["autoJoinChannels"].type != Json.Type.undefined)
        if (bodyJson["autoJoinChannels"].type != Json.Type.undefined)
            cfg.autoJoinChannels = dedupChannels(deserializeJson!(string[])(bodyJson["autoJoinChannels"]));
        if (bodyJson["partedChannels"].type != Json.Type.undefined)
            cfg.partedChannels = dedupChannels(deserializeJson!(string[])(bodyJson["partedChannels"]));

        // SASL authentication fields
        if (bodyJson["sasl"].type != Json.Type.undefined)
            cfg.sasl = bodyJson["sasl"].get!string.to!SASLMechanism;
        if (bodyJson["saslUsername"].type != Json.Type.undefined)
            cfg.saslUsername = bodyJson["saslUsername"].get!string;
        if (bodyJson["saslPassword"].type != Json.Type.undefined)
            cfg.saslPassword = bodyJson["saslPassword"].get!string;

        // NickServ password, connect commands, and server password
        if (bodyJson["nspass"].type != Json.Type.undefined)
            cfg.nspass = bodyJson["nspass"].get!string;
        if (bodyJson["commands"].type != Json.Type.undefined)
            cfg.commands = bodyJson["commands"].get!string;
        if (bodyJson["serverPass"].type != Json.Type.undefined)
            cfg.serverPass = bodyJson["serverPass"].get!string;

        // Auto-join delay (seconds after connect before JOINs are sent).
        // 0 = join immediately after registration (legacy behavior).
        if (bodyJson["autoJoinDelaySeconds"].type != Json.Type.undefined) {
            auto v = bodyJson["autoJoinDelaySeconds"].get!int;
            cfg.autoJoinDelaySeconds = v > 0 ? cast(uint) v : 0;
        }

        auto user = req.context["user"].get!User;
        networkRepo.save(cfg, user.id);
        redis.del(RedisKeys.userNetworks(user.id.toString()));

        // NEW: Route to assigned server
        auto serverId = serverRegistry.getServerForNetwork(cfg.id.toString());
        if (serverId.length == 0) {
            serverId = serverRegistry.assignNetwork(cfg.id.toString());
        }
        if (serverId.length == 0) {
            logError("Cannot update network %s — no healthy connection servers", cfg.id);
            res.statusCode = 503;
            res.writeJsonBody(Json(["error": Json("No healthy connection servers available")]));
            return;
        }

        auto msg = ControlMessage("updateConfig", cfg.id.toString(), "", cfg.toJson());
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());

        res.writeJsonBody(cfg.toJson());
    }

    private void deleteNetwork(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto id = parseUUID(req.params["id"]);

        // Refuse to delete platform-provisioned networks. Admins can
        // still remove them via the admin tools which bypass this API.
        auto existing = networkRepo.findById(id);
        if (existing.id != UUID.init && existing.systemManaged) {
            res.statusCode = 403;
            res.writeJsonBody(Json([
                "error": Json("This network is provisioned by IRC Fiber and cannot be removed"),
                "systemManaged": Json(true)
            ]));
            return;
        }

        // Capture owner userId before deleting, for cache invalidation.
        auto ownerId = networkRepo.findByIdWithUser(id).userId;

        // NEW: Route to assigned server
        auto serverId = serverRegistry.getServerForNetwork(id.toString());
        if (serverId.length == 0) {
            logWarn("Delete network %s: no assigned server found, using legacy routing", id.toString());
        }
        
        auto msg = ControlMessage("removeNetwork", id.toString());
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        
        if (serverId.length > 0) {
            redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
        } else {
            // Legacy fallback
            redis.lpush(RedisKeys.control_legacy(), msg.toJson().toString());
        }

        networkRepo.deleteById(id);
        if (ownerId != UUID.init)
            redis.del(RedisKeys.userNetworks(ownerId.toString()));

        // Clear scrollback buffers so a new network with the same name
        // doesn't inherit old server logs / messages.
        if (serverId.length > 0) {
            bufferManager.clearNetworkBuffers(serverId, id.toString());
        } else {
            bufferManager.clearNetworkBuffers(id.toString());
        }

        res.writeJsonBody(Json(["status": Json("deleted")]));
    }

    private void disconnectNetwork(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto id = parseUUID(req.params["id"]);
        auto user = req.context["user"].get!User;

        // Optional QUIT reason in the JSON body. Empty by default — IRCCloud
        // uses an empty quit message so the server response reads "(Quit: )".
        string quitReason = "";
        try {
            auto body = req.json;
            if (body.type == Json.Type.object && body["reason"].type == Json.Type.string) {
                quitReason = body["reason"].get!string;
            }
        } catch (Exception) {
            // No body / not JSON — that's fine, default to empty reason.
        }

        // Route to the engine that owns this network, if one is alive.
        auto serverId = serverRegistry.getServerForNetwork(id.toString());
        const bool engineHealthy = serverId.length > 0 && serverRegistry.isServerHealthy(serverId);

        // Mark the network as disabled in MongoDB so the engine's bootstrap
        // loop skips it on restart (matching admin disconnect behavior).
        // Without this, any engine restart (deploy, handoff, crash) reloads
        // the network from MongoDB and auto-reconnects it, undoing the user's
        // explicit disconnect.  The reconnect REST API clears this flag.
        networkRepo.setDisabled(id, true);

        // Always update the Redis state snapshot immediately so the
        // frontend's next sync sees disconnected — otherwise the stale
        // 'connecting' snapshot survives until the engine processes the
        // control message, which can take seconds (Redis BLPOP latency +
        // backoff sleep), during which the frontend re-overwrites the
        // local disconnected state back to 'connecting'.
        //
        // Only publish a synthetic DISCONNECT event when there is NO live
        // engine to handle it. When an engine IS alive, it will emit its
        // own "You disconnected" event through the normal connection loop
        // exit path. Publishing both creates a duplicate in the frontend's
        // _server buffer — two identical "You disconnected" timeline items
        // with different eids that the eid-based dedup can't catch.
        if (engineHealthy) {
            updateDisconnectSnapshot(id, serverId);
        } else {
            markNetworkDisconnected(id, user.id, serverId);
        }

        // Always send the control message — even if the engine's heartbeat
        // is temporarily stale (e.g. draining handoff or transient lag), the
        // consumer loop still processes the queue asynchronously and will
        // pick up the disconnect.  Without this, the snapshot says
        // disconnected but the engine overwrites it back to connected=true
        // on the next heartbeat cycle.
        if (serverId.length > 0) {
            auto msg = ControlMessage("disconnectNetwork", id.toString());
            msg.reason = quitReason;
            msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
            redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
        }

        res.writeJsonBody(Json(["status": Json("disconnected")]));
    }

    /**
     * POST /api/networks/:id/buffers/clear
     *
     * Body: { "buffer": "<buffer name>" } (e.g. "_server" or "#channel").
     *
     * Hard-deletes the scrollback list and its paired dedup SET for that
     * buffer on the engine that owns the network. Powers the user-facing
     * "Clear backlog" context-menu action — the frontend's localStorage
     * `clearedAt` flag only hides old messages client-side (and is
     * reversible via "Load more backlog…"); this endpoint actually
     * scrubs the Redis scrollback.
     *
     * If the network isn't currently assigned to a server (cold / not
     * yet bootstrapped) the legacy non-namespaced key is scrubbed
     * instead. Idempotent: missing keys are a no-op.
     */
    private void clearNetworkBuffer(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto id = parseUUID(req.params["id"]);
        auto cfg = networkRepo.findById(id);
        if (cfg.name.length == 0) {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("Network not found")]));
            return;
        }

        // Owner check — must match the calling user. A compromised
        // cookie should not be able to wipe another user's scrollback
        // via id guessing, so the destructive endpoint is gated on the
        // owning userId looked up separately (NetworkConfig itself
        // doesn't carry userId).
        auto user = req.context["user"].get!User;
        auto ownerInfo = networkRepo.findByIdWithUser(id);
        if (ownerInfo.userId != UUID.init && ownerInfo.userId != user.id) {
            res.statusCode = 403;
            res.writeJsonBody(Json(["error": Json("Not your network")]));
            return;
        }

        // Extract the buffer name from the JSON body ({"buffer":"_server"}).
        // Missing / malformed body → 400.
        string buffer = "";
        try {
            auto body = req.json;
            if (body.type == Json.Type.object && "buffer" in body
                && body["buffer"].type == Json.Type.string) {
                buffer = body["buffer"].get!string;
            }
        } catch (Exception) {
            // No body — fall through to 400 below.
        }
        if (buffer.length == 0) {
            res.statusCode = 400;
            res.writeJsonBody(Json(["error": Json("Missing `buffer` field")]));
            return;
        }

        // Look up the assigned engine so we scrub the right key namespace.
        // If none is assigned (cold network / single-server legacy mode)
        // the legacy overload handles it.
        auto serverId = serverRegistry.getServerForNetwork(id.toString());
        try {
            if (serverId.length > 0) {
                bufferManager.clearBuffer(serverId, id.toString(), buffer);
            } else {
                bufferManager.clearBuffer(id.toString(), buffer);
            }
        } catch (Exception e) {
            logError("clearNetworkBuffer: DEL failed for %s/%s: %s",
                id.toString(), buffer, e.msg);
            res.statusCode = 500;
            res.writeJsonBody(Json(["error": Json("Internal error clearing buffer")]));
            return;
        }

        // Also purge the MongoDB permanent store so the two-tier fallback
        // in getMessages doesn't re-surface deleted messages on page refresh.
        // If MongoDB delete fails, return 500 so the frontend keeps its
        // `clearedAt` filter active and the user has to retry. Previously
        // this was a silent swallow, which caused the bug where refreshing
        // and clicking "Load More Backlog..." re-surfaced old messages
        // from MongoDB even though Redis was cleared.
        if (serverId.length > 0) {
            try {
                auto mongoRepo = new MessageRepository();
                mongoRepo.deleteByChannel(serverId, id.toString(), buffer);
            } catch (Exception e) {
                logError("clearNetworkBuffer: MongoDB purge failed for %s/%s: %s — returning 500 so frontend keeps clearedAt active",
                    id.toString(), buffer, e.msg);
                res.statusCode = 500;
                res.writeJsonBody(Json(["error": Json("MongoDB purge failed — buffer not fully cleared")]));
                return;
            }
        }
        // Legacy (single-server): serverId is empty so there is no
        // namespaced MongoDB data to delete — the old Redis-only
        // scrollback path never wrote to Mongo.

        logInfo("User %s cleared buffer %s on network %s (server=%s)",
            user.username, buffer, id.toString(),
            serverId.length ? serverId : "<legacy>");

        res.writeJsonBody(Json([
            "status": Json("cleared"),
            "buffer": Json(buffer),
            "serverId": Json(serverId)
        ]));
    }

    /// Mark a network as disconnected when no live engine can do it for us.
    /// Publishes a synthetic "You disconnected" event to the frontend.
    private void markNetworkDisconnected(UUID networkId, UUID userId, string assignedServerId) {
        auto cfg = networkRepo.findById(networkId);
        if (cfg.name.length == 0) return;
        auto nick = updateDisconnectSnapshot(networkId, assignedServerId, cfg);

        // Push a DISCONNECT event onto the user's pub/sub channel so any open
        // WebSocket immediately flips the UI from Disconnect -> Connect.
        auto evt = IRCRawEvent(cfg.name, "DISCONNECT");
        evt.networkId = networkId.toString();
        evt.channel = "_server";
        evt.nick = nick;
        evt.text = "You disconnected";

        auto json = evt.toCompactJson();
        json["y"] = "irc_event";
        if (assignedServerId.length > 0) json["serverId"] = assignedServerId;
        redis.publish(RedisKeys.events(userId.toString()), json.toString());

        logInfo("Disconnected network %s without engine (assigned=%s, nick=%s)",
            networkId.toString(), assignedServerId.length ? assignedServerId : "<none>", nick);
    }

    /// Update the Redis state snapshots to mark the network as disconnected.
    /// Does NOT publish a DISCONNECT event — use when a live engine will
    /// emit its own disconnect event through the normal connection loop.
    /// Returns the most recent currentNick seen in any snapshot.
    private string updateDisconnectSnapshot(UUID networkId, string assignedServerId,
        NetworkConfig cfg = NetworkConfig.init) {
        if (cfg.name.length == 0) {
            cfg = networkRepo.findById(networkId);
            if (cfg.name.length == 0) return "";
        }

        string[] candidateKeys;
        if (assignedServerId.length > 0)
            candidateKeys ~= RedisKeys.state(assignedServerId, networkId.toString());
        candidateKeys ~= RedisKeys.state_legacy(networkId.toString());

        string currentNick = cfg.nick;
        long mostRecentSnapshot = 0;

        foreach (key; candidateKeys) {
            auto fields = redis.hgetAll(key);
            auto data = "data" in fields;
            if (data is null) continue;
            try {
                auto snap = NetworkStateSnapshot.fromJson(parseJsonString(*data));
                if (snap.currentNick.length > 0 && snap.updatedAt >= mostRecentSnapshot) {
                    currentNick = snap.currentNick;
                    mostRecentSnapshot = snap.updatedAt;
                }
                snap.connected = false;
                snap.status = "disconnected";
                snap.updatedAt = Clock.currTime.toUnixTime!long * 1000;
                redis.hset(key, "data", snap.toJson().toString());
            } catch (Exception e) {
                logWarn("Failed to update disconnect snapshot at %s: %s", key, e.msg);
            }
        }

        return currentNick;
    }

    private void reconnectNetwork(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto id = parseUUID(req.params["id"]);
        auto user = req.context["user"].get!User;
        auto cfg = networkRepo.findById(id);

        if (cfg.name.length == 0) {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("Network not found")]));
            return;
        }

        // Clear any admin-disabled flag so this network will load on
        // future engine restarts. This lets a user re-enable a network
        // an admin had disconnected.
        if (cfg.disabled) {
            networkRepo.setDisabled(id, false);
            cfg.disabled = false;
            logInfo("Cleared disabled flag on network %s via user reconnect", id.toString());
        }

        // Route to assigned server (or reassign if server is unhealthy)
        auto serverId = serverRegistry.getServerForNetwork(id.toString());
        if (serverId.length == 0 || !serverRegistry.isServerHealthy(serverId)) {
            serverId = serverRegistry.reassignNetwork(id.toString());
            if (serverId.length == 0) {
                logError("Failed to reassign network %s — no healthy connection servers", id.toString());
                res.statusCode = 503;
                res.writeJsonBody(Json(["error": Json("No healthy servers available for reconnect")]));
                return;
            }
        }

        auto msg = ControlMessage("reconnectNetwork", id.toString(), user.id.toString(), cfg.toJson());
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());

        res.writeJsonBody(Json(["status": Json("reconnecting")]));
    }

    private void getMessages(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto networkId = parseUUID(req.params["network"]);
        auto channel = req.params["channel"];
        auto count = req.query.get("count", "50").to!long;
        long before = 0;
        long after = 0;
        if (auto b = "before" in req.query) {
            try { before = (*b).to!long; } catch (Exception e) {}
        }
        if (auto a = "after" in req.query) {
            try { after = (*a).to!long; } catch (Exception e) {}
        }

        string beforeMsgid = "";
        string afterMsgid = "";
        if (auto bm = "before_msgid" in req.query) {
            beforeMsgid = *bm;
        }
        if (auto am = "after_msgid" in req.query) {
            afterMsgid = *am;
        }

        // IRCCloud-style "beforeid" cursor: the eid of the oldest rendered
        // message. For infinite scrollback, this is always an eid (long),
        // never a string. Legacy msgid cursors are still accepted via
        // before_msgid for backward compatibility.
        long beforeEid = 0;
        if (auto bid = "beforeid" in req.query) {
            try { beforeEid = (*bid).to!long; } catch (Exception e) {}
        }

        // If beforeid didn't parse as a number, try as msgid string
        // (legacy path for messages without eid)
        if (beforeEid == 0 && ("beforeid" in req.query)) {
            beforeMsgid = req.query["beforeid"];
        }

        // Force a CHATHISTORY fetch on this call. Set by the frontend
        // after a /join or /reconnect so the first message load always
        // sees the upstream backfill. The gateway pushes a "chathistory"
        // command to the engine which issues LATEST/BEFORE on the wire.
        bool triggerFetch = ("fetch" in req.query) && req.query["fetch"] == "1";
        // The frontend may also pass a ref msgid for explicit
        // pagination against the upstream, falling back to whatever's
        // already in the local buffer when not provided.
        string fetchCommand = "LATEST";
        string fetchRef = "";
        if (auto fc = "fetch_command" in req.query) {
            import std.uni : toUpper;
            fetchCommand = toUpper(*fc);
        }
        if (auto fr = "fetch_ref" in req.query) fetchRef = *fr;

        const cfg = networkRepo.findById(networkId);
        if (cfg.name.length == 0) {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("Network not found")]));
            return;
        }

        // Get serverId for namespaced buffer lookup
        auto serverId = serverRegistry.getServerForNetwork(networkId.toString());

        // Fire the CHATHISTORY request to the engine before reading the
        // buffer. The engine handles it asynchronously — the BATCH
        // responses land in the same buffer we're about to read, so the
        // first read may see the freshly backfilled messages. If the
        // engine is slow or the cap isn't negotiated, we just return
        // whatever is in the local scrollback.
        if (triggerFetch && serverId.length > 0 && serverRegistry.isServerHealthy(serverId)) {
            try {
                // Build the chathistory command payload. The colon
                // delimiter lets us pack channel, command, ref msgid,
                // and limit into a single text field without extending
                // the protocol struct. See consumer.d's chathistory case.
                string payload = channel ~ ":" ~ fetchCommand ~ ":" ~ fetchRef ~ ":" ~ count.to!string;
                auto chCmd = IRCCommand("chathistory", "", payload);
                chCmd.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                redis.lpush(RedisKeys.cmd(serverId, networkId.toString()), chCmd.toJson().toString());
            } catch (Exception e) {
                logWarn("Failed to enqueue chathistory command: %s", e.msg);
            }
        }

        // ── Two-tier lookup: Redis hot cache → MongoDB cold store ─────
        // IRCCloud keeps a small in-memory buffer and fetches older
        // history from the server. We do the same: Redis for the
        // recent cache, MongoDB for anything older. This is what makes
        // infinite scrollback possible.
        Json[] messages;
        if (serverId.length > 0) {
            // Decentralized: use server-namespaced buffer
            messages = bufferManager.getRecent(serverId, networkId.toString(), channel, count, before, after, beforeMsgid, afterMsgid);
        } else {
            // Legacy: non-namespaced buffer
            messages = bufferManager.getRecent(networkId.toString(), channel, count, before, after, beforeMsgid, afterMsgid);
        }

        // Fall through to MongoDB if Redis returned fewer than `count`
        // messages. This covers two cases:
        //   1. Cursor-based (beforeMsgid/before): Redis cache exhausted
        //   2. First load (no cursor): Redis is empty (e.g. engine
        //      never ran, or cold start), so read from the permanent
        //      store directly. This makes the scrollback work even
        //      when the engine isn't running.
        if (messages.length < count) {
            try {
                auto mongoRepo = new MessageRepository();
                Json[] older;
                if (beforeEid > 0) {
                    older = mongoRepo.getBeforeEid(serverId, networkId.toString(), channel, beforeEid, before, cast(int)(count - messages.length));
                } else if (beforeMsgid.length > 0) {
                    older = mongoRepo.getBeforeMsgid(serverId, networkId.toString(), channel, beforeMsgid, before, cast(int)(count - messages.length));
                } else if (before > 0) {
                    older = mongoRepo.getBeforeTimestamp(serverId, networkId.toString(), channel, before, cast(int)(count - messages.length));
                } else if (messages.length > 0) {
                    // Redis has SOME messages but fewer than `count`. The
                    // engine writes each event to BOTH Redis and MongoDB, so
                    // an unfiltered "newest N from Mongo" call would return
                    // every Redis message again — the user's #zod would show
                    // their own messages duplicated twice on refresh.
                    //
                    // Use the OLDEST Redis message's timestamp as the cursor
                    // so MongoDB returns strictly older messages only. The
                    // `$lt` filter handles the rare edge case where MongoDB
                    // has a message with the exact same timestamp.
                    long oldestTs = 0;
                    if (auto t = "t" in messages[0])
                        if (t.type == Json.Type.int_) oldestTs = t.get!long;
                    if (oldestTs > 0) {
                        older = mongoRepo.getBeforeTimestamp(serverId, networkId.toString(), channel, oldestTs, cast(int)(count - messages.length));
                    } else {
                        // Redis messages lack timestamps (legacy). Fall back to
                        // an unfiltered newest-N — then dedup against Redis by
                        // msgid so we don't return the same message twice.
                        older = mongoRepo.getBeforeTimestamp(serverId, networkId.toString(), channel, 0, cast(int)count);
                    }
                } else {
                    // Cold start: Redis is empty, fetch newest N from Mongo.
                    older = mongoRepo.getBeforeTimestamp(serverId, networkId.toString(), channel, 0, cast(int)count);
                }
                if (older.length > 0) {
                    // Defensive dedup: even with the cursor above, MongoDB
                    // could contain messages with the same msgid that the
                    // Redis cursor missed (e.g. a write happened mid-fetch).
                    // Drop any MongoDB message whose msgid is already in
                    // Redis's set so the frontend never renders duplicates.
                    auto dedupedOlder = RESTAPI.dedupMessages(messages, older);
                    if (dedupedOlder.length > 0) {
                        // Prepend older messages (newest at end of `older`)
                        messages = dedupedOlder ~ messages;
                    }
                }
            } catch (Exception e) {
                logWarn("MongoDB fall-through failed: %s", e.msg);
            }
        }

        // Wildcard fallback for decentralized history
        if (messages.length < count) {
            try {
                auto mongoRepoAny = new MessageRepository();
                Json[] olderAny = mongoRepoAny.getBeforeTimestamp("", networkId.toString(), channel, 0, cast(int)(count - messages.length));
                if (olderAny.length > 0) {
                    auto dedupedAny = RESTAPI.dedupMessages(messages, olderAny);
                    if (dedupedAny.length > 0) messages = dedupedAny ~ messages;
                }
            } catch (Exception e) {
                logWarn("MongoDB wildcard fall-through failed: %s", e.msg);
            }
        }

        // Surface total backlog size so the frontend can show "X total
        // messages" and decide when the user has reached the very
        // beginning. This is IRCCloud's `backlog_size` field.
        long backlogSize = 0;
        try {
            auto mongoRepo = new MessageRepository();
            backlogSize = mongoRepo.count(serverId, networkId.toString(), channel);
        } catch (Exception e) {
            logDebug("MongoDB count failed: %s", e.msg);
        }

        res.headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
        // Wrap the response in an envelope so we can include metadata
        // alongside the messages. The frontend reads `messages` for the
        // list and `backlog_size` / `earliest_msgid` for pagination.
        Json[] msgsArr;
        foreach (m; messages) msgsArr ~= m;

        // Find the OLDEST message's identifiers in the returned set —
        // this becomes the cursor for the next "load more" request.
        // msgsArr is ordered OLDEST-FIRST (oldest at index 0, newest
        // at the end). The cursor for the NEXT page is the OLDEST
        // message in this page, so the next request returns messages
        // even older than this page's boundary.
        // eid is the primary cursor (IRCCloud-style); msgid and ts
        // are fallbacks for legacy messages without eid.
        string earliestMsgid = "";
        long earliestTs = 0;
        long earliestEid = 0;
        if (msgsArr.length > 0) {
            auto first = msgsArr[0];
            if (auto e = "eid" in first) {
                if (e.type == Json.Type.int_) earliestEid = e.get!long;
            }
            if (auto m = "m" in first) {
                if (m.type == Json.Type.string) earliestMsgid = m.get!string;
            }
            if (auto t = "t" in first) {
                if (t.type == Json.Type.int_) {
                    earliestTs = t.get!long;
                }
            }
        }

        Json envelope = Json([
            "messages": Json(msgsArr),
            "backlog_size": Json(backlogSize),
            "earliest_msgid": Json(earliestMsgid),
            "earliest_ts": Json(earliestTs),
            "earliest_eid": Json(earliestEid),
            "cache_size": Json(cast(long)msgsArr.length)
        ]);
        res.writeJsonBody(envelope);
    }

    private void joinChannel(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto nid = parseUUID(req.params["network"]);
        auto bodyJson = req.json;
        auto c = IRCCommand("join", bodyJson["channel"].get!string, "");
        c.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        
        // NEW: Route to assigned server
        auto serverId = serverRegistry.getServerForNetwork(nid.toString());
        if (serverId.length > 0) {
            redis.lpush(RedisKeys.cmd(serverId, nid.toString()), c.toJson().toString());
        } else {
            redis.lpush(RedisKeys.cmd_legacy(nid.toString()), c.toJson().toString());
        }
        
        res.writeJsonBody(Json(["status": Json("ok")]));
    }

    /**
     * GET /api/oob?network=<id>&since=<eid>&count=<n>
     *
     * Out-of-band event fetch. The frontend calls this when it
     * detects a hole in the live eid stream (e.g. the WS silently
     * dropped a frame, or the page was hidden while events flowed).
     * Returns up to `count` events with eid > `since` across all
     * channels of the network, oldest first.
     *
     * This is the recovery path that makes the WS "best-effort
     * delivery" — the MongoDB scrollback is the source of truth, and
     * /api/oob lets the client fetch from it without a full
     * reconnect/replay.
     */
    private void getOOBEvents(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;

        // network: required (the network the client was on when it
        // detected the gap — we fetch across all its channels)
        auto networkIdStr = req.query.get("network", "");
        if (networkIdStr.length == 0) {
            res.statusCode = 400;
            res.writeJsonBody(Json(["error": Json("missing 'network' query param")]));
            return;
        }
        auto networkId = parseUUID(networkIdStr);

        // since: required (the highest eid the client has)
        long since = 0;
        if (auto s = "since" in req.query) {
            try { since = (*s).to!long; }
            catch (Exception e) {
                res.statusCode = 400;
                res.writeJsonBody(Json(["error": Json("invalid 'since' param")]));
                return;
            }
        }

        // count: default 100, cap at 1000
        int count = 100;
        if (auto c = "count" in req.query) {
            try {
                count = cast(int)(*c).to!long;
                if (count <= 0) count = 100;
                if (count > 1000) count = 1000;
            } catch (Exception) {}
        }

        // Look up the network config to validate ownership + get the
        // assigned serverId. (Required for the namespaced Mongo query.)
        auto found = networkRepo.findByIdWithUser(networkId);
        if (found.config.name.length == 0) {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("network not found")]));
            return;
        }
        if (found.userId != user.id) {
            res.statusCode = 403;
            res.writeJsonBody(Json(["error": Json("not your network")]));
            return;
        }

        auto serverId = serverRegistry.getServerForNetwork(networkIdStr);
        if (serverId.length == 0) {
            // Network isn't currently assigned to any engine — try the
            // legacy namespacing. The legacy lookup uses networkId as
            // serverId; messages written before the server-aware
            // refactor are stored there.
            serverId = networkIdStr;
        }

        try {
            auto mongoRepo = new MessageRepository();
            auto events = mongoRepo.getAfterEidForNetwork(
                serverId, networkIdStr, since, count);
            res.headers["Cache-Control"] = "no-store, no-cache, must-revalidate";
            res.writeJsonBody(Json([
                "events": Json(events),
                "count": Json(cast(int)events.length),
                "since": Json(since)
            ]));
        } catch (Exception e) {
            logError("getOOBEvents: %s", e.msg);
            res.statusCode = 500;
            res.writeJsonBody(Json(["error": Json("OOB fetch failed"), "detail": Json(e.msg)]));
        }
    }

    private void partChannel(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto nid = parseUUID(req.params["network"]);
        auto bodyJson = req.json;
        auto c = IRCCommand("part", bodyJson["channel"].get!string, "");
        c.timestampMs = Clock.currTime.toUnixTime!long * 1000;

        // NEW: Route to assigned server
        auto serverId = serverRegistry.getServerForNetwork(nid.toString());
        if (serverId.length > 0) {
            redis.lpush(RedisKeys.cmd(serverId, nid.toString()), c.toJson().toString());
        } else {
            redis.lpush(RedisKeys.cmd_legacy(nid.toString()), c.toJson().toString());
        }
        
        res.writeJsonBody(Json(["status": Json("ok")]));
    }

    private void getMe(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto prefs = prefsRepo.load(user.id);
        auto mc = Json.emptyObject;
        foreach (k, v; prefs.membersCollapsed)
            mc[k] = Json(v);
        auto col = Json.emptyObject;
        foreach (k, v; prefs.collapsed)
            col[k] = Json(v);
        auto ic = Json.emptyObject;
        foreach (k, v; prefs.inactiveCollapsed)
            ic[k] = Json(v);
        auto bp = Json.emptyObject;
        foreach (k, v; prefs.bufferPrefs)
            bp[k] = v;
        res.writeJsonBody(Json([
            "id": Json(user.id.toString()),
            "username": Json(user.username),
            "email": Json(user.email),
            "pinnedChannels": serializeToJson(prefs.pinnedChannels),
            "archivedChannels": serializeToJson(prefs.archivedChannels),
            "membersCollapsed": mc,
            "collapsed": col,
            "inactiveCollapsed": ic,
            "networkOrder": serializeToJson(prefs.networkOrder),
            "bufferPrefs": bp,
            // Monotonic counter incremented by every prefsRepo.save().
            // Lets the frontend decide whether to trust this stat_user
            // payload or skip the merge in favour of its locally-tracked
            // state. See docs/PREF_VERSION.md.
            "prefVersion": Json(prefs.prefVersion)
        ]));
    }

    private void pinChannel(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;
        const network = bodyJson["network"].get!string;
        const channel = bodyJson["channel"].get!string;
        const pinId = network ~ ":" ~ channel;

        auto prefs = prefsRepo.load(user.id);
        long newVersion = 0;
        if (!prefs.pinnedChannels.canFind(pinId)) {
            prefs.pinnedChannels ~= pinId;
            newVersion = prefsRepo.save(user.id, prefs);
        } else {
            // No mutation this request — surface the current prefVersion
            // so other tabs see a consistent counter in the broadcast.
            newVersion = prefs.prefVersion;
        }
        // Broadcast pref update to all connected WebSocket clients for this user
        broadcastPrefUpdate(user.id.toString(), "pinned", serializeToJson(prefs.pinnedChannels), newVersion);
        res.statusCode = 204;
        res.writeVoidBody();
    }

    private void unpinChannel(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        const network = req.params["network"];
        const channel = req.params["channel"];
        const pinId = network ~ ":" ~ channel;

        auto prefs = prefsRepo.load(user.id);
        prefs.pinnedChannels = prefs.pinnedChannels.filter!(p => p != pinId).array;
        auto newVersion = prefsRepo.save(user.id, prefs);

        // Broadcast pref update to all connected WebSocket clients for this user
        broadcastPrefUpdate(user.id.toString(), "pinned", serializeToJson(prefs.pinnedChannels), newVersion);
        res.statusCode = 204;
        res.writeVoidBody();
    }

    private void archiveChannel(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;
        const network = bodyJson["network"].get!string;
        const channel = bodyJson["channel"].get!string;
        const archiveId = network ~ ":" ~ channel;

        auto prefs = prefsRepo.load(user.id);
        long newVersion = 0;
        if (!prefs.archivedChannels.canFind(archiveId)) {
            prefs.archivedChannels ~= archiveId;
            newVersion = prefsRepo.save(user.id, prefs);
        } else {
            newVersion = prefs.prefVersion;
        }
        // Broadcast pref update to all connected WebSocket clients for this user
        broadcastPrefUpdate(user.id.toString(), "archived", serializeToJson(prefs.archivedChannels), newVersion);
        // Invalidate archive-names cache so subsequent fetches see the change
        redis.del(RedisKeys.archiveNames(user.id.toString()));
        res.statusCode = 204;
        res.writeVoidBody();
    }

    private void unarchiveChannel(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        const network = req.params["network"];
        const channel = req.params["channel"];
        const archiveId = network ~ ":" ~ channel;

        auto prefs = prefsRepo.load(user.id);
        prefs.archivedChannels = prefs.archivedChannels.filter!(a => a != archiveId).array;
        auto newVersion = prefsRepo.save(user.id, prefs);

        // Broadcast pref update to all connected WebSocket clients for this user
        broadcastPrefUpdate(user.id.toString(), "archived", serializeToJson(prefs.archivedChannels), newVersion);
        // Invalidate archive-names cache so subsequent fetches see the change
        redis.del(RedisKeys.archiveNames(user.id.toString()));
        res.statusCode = 204;
        res.writeVoidBody();
    }

    private void updateMembersCollapsed(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;
        const network = bodyJson["network"].get!string;
        const channel = bodyJson["channel"].get!string;
        const collapsed = bodyJson["collapsed"].get!bool;
        const key = network ~ ":" ~ channel;

        auto prefs = prefsRepo.load(user.id);
        if (collapsed) {
            prefs.membersCollapsed[key] = true;
        } else {
            prefs.membersCollapsed.remove(key);
        }
        auto newVersion = prefsRepo.save(user.id, prefs);

        // Broadcast to all connected sessions for this user
        auto json = Json.emptyObject;
        json["type"] = Json("pref_update");
        json["key"] = Json("membersCollapsed");
        json["prefVersion"] = Json(newVersion);
        auto mc = Json.emptyObject;
        foreach (k, v; prefs.membersCollapsed)
            mc[k] = Json(v);
        json["value"] = mc;
        redis.publish(RedisKeys.events(user.id.toString()), json.toString());

        res.statusCode = 204;
        res.writeVoidBody();
    }

    /// Conversations-header collapse persistence. Same pattern as
    /// membersCollapsed — keyed by networkId so collapses survive
    /// reconnection cycles deterministically. Broadcast via pref_update
    /// to all connected sessions in real time.
    private void updateConversationsCollapsed(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;
        const network = bodyJson["network"].get!string;
        const collapsed = bodyJson["collapsed"].get!bool;

        auto prefs = prefsRepo.load(user.id);
        if (collapsed) {
            prefs.conversationsCollapsed[network] = true;
        } else {
            prefs.conversationsCollapsed.remove(network);
        }
        auto newVersion = prefsRepo.save(user.id, prefs);

        // Broadcast to all connected sessions for this user
        auto json = Json.emptyObject;
        json["type"] = Json("pref_update");
        json["key"] = Json("conversationsCollapsed");
        json["prefVersion"] = Json(newVersion);
        auto cc = Json.emptyObject;
        foreach (k, v; prefs.conversationsCollapsed)
            cc[k] = Json(v);
        json["value"] = cc;
        redis.publish(RedisKeys.events(user.id.toString()), json.toString());

        res.statusCode = 204;
        res.writeVoidBody();
    }

    /// Enterprise-grade server-log collapse persistence. Same pattern as
    /// membersCollapsed — keyed by networkId:eid so collapses survive
    /// reconnection cycles deterministically. Broadcast via pref_update
    /// to all connected sessions in real time.
    private void updateServerlogCollapsed(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;

        // Support both eid (preferred) and msgid (legacy fallback) so
        // connection attempts without an eid still get persisted collapse.
        string key;
        if (auto e = "eid" in bodyJson) {
            key = bodyJson["network"].get!string ~ ":" ~ bodyJson["eid"].get!string;
        } else if (auto m = "msgid" in bodyJson) {
            key = bodyJson["network"].get!string ~ ":msgid:" ~ bodyJson["msgid"].get!string;
        } else {
            res.statusCode = 400;
            res.writeJsonBody(Json(["error": Json("eid or msgid required")]));
            return;
        }
        const collapsed = bodyJson["collapsed"].get!bool;

        auto prefs = prefsRepo.load(user.id);
        if (collapsed) {
            prefs.serverlogCollapsed[key] = true;
        } else {
            prefs.serverlogCollapsed.remove(key);
        }
        auto newVersion = prefsRepo.save(user.id, prefs);

        auto slc = Json.emptyObject;
        foreach (k, v; prefs.serverlogCollapsed)
            slc[k] = Json(v);
        broadcastPrefUpdate(user.id.toString(), "serverlogCollapsed", slc, newVersion);

        res.statusCode = 204;
        res.writeVoidBody();
    }

    private void updateBufferPrefs(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;
        const network = bodyJson["network"].get!string;
        const channel = bodyJson["channel"].get!string;
        const key = network ~ ":" ~ channel;
        auto prefs = prefsRepo.load(user.id);

        // Merge the incoming prefs object into the buffer's existing prefs
        Json bufferPref;
        if (key in prefs.bufferPrefs) {
            bufferPref = prefs.bufferPrefs[key];
        } else {
            bufferPref = Json.emptyObject;
        }

        if (auto bp = "prefs" in bodyJson) {
            if (bp.type == Json.Type.object) {
                foreach (string k, v; *bp)
                    bufferPref[k] = v;
            }
        }

        // Remove key if prefs object is empty
        if (bufferPref.type == Json.Type.object) {
            string[] keys;
            foreach (string k, _; bufferPref) keys ~= k;
            if (keys.length == 0) {
                prefs.bufferPrefs.remove(key);
            } else {
                prefs.bufferPrefs[key] = bufferPref;
            }
        } else {
            prefs.bufferPrefs[key] = bufferPref;
        }

        auto newVersion = prefsRepo.save(user.id, prefs);

        // Broadcast full bufferPrefs map to all connected sessions
        auto json = Json.emptyObject;
        json["type"] = Json("pref_update");
        json["key"] = Json("bufferPrefs");
        json["prefVersion"] = Json(newVersion);
        auto bpMap = Json.emptyObject;
        foreach (k, v; prefs.bufferPrefs)
            bpMap[k] = v;
        json["value"] = bpMap;
        redis.publish(RedisKeys.events(user.id.toString()), json.toString());

        res.statusCode = 204;
        res.writeVoidBody();
    }

    private void updateCollapsed(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;
        const network = bodyJson["network"].get!string;
        const collapsed = bodyJson["collapsed"].get!bool;

        auto prefs = prefsRepo.load(user.id);
        if (collapsed) {
            prefs.collapsed[network] = true;
        } else {
            prefs.collapsed.remove(network);
        }
        auto newVersion = prefsRepo.save(user.id, prefs);

        auto col = Json.emptyObject;
        foreach (k, v; prefs.collapsed)
            col[k] = Json(v);
        broadcastPrefUpdate(user.id.toString(), "collapsed", col, newVersion);

        res.statusCode = 204;
        res.writeVoidBody();
    }

    private void updateInactiveCollapsed(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;
        const network = bodyJson["network"].get!string;
        const collapsed = bodyJson["collapsed"].get!bool;

        auto prefs = prefsRepo.load(user.id);
        if (collapsed) {
            prefs.inactiveCollapsed[network] = true;
        } else {
            prefs.inactiveCollapsed.remove(network);
        }
        auto newVersion = prefsRepo.save(user.id, prefs);

        auto ic = Json.emptyObject;
        foreach (k, v; prefs.inactiveCollapsed)
            ic[k] = Json(v);
        broadcastPrefUpdate(user.id.toString(), "inactiveCollapsed", ic, newVersion);

        res.statusCode = 204;
        res.writeVoidBody();
    }

    /// Replaces the user's sidebar network order with `order` (array of
    /// networkIds, top-to-bottom). Mirrors IRCCloud's `reorder-connections`
    /// stream message body — the full ordered list is sent on every change
    /// rather than a (from, to) delta, which is simpler and matches the
    /// jQuery UI Sortable's `update` callback semantics.
    private void updateNetworkOrder(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto bodyJson = req.json;

        string[] order;
        if (auto o = "order" in bodyJson) {
            if (o.type == Json.Type.array) {
                foreach (entry; *o) {
                    if (entry.type == Json.Type.string) {
                        const id = entry.get!string;
                        if (id.length > 0 && !order.canFind(id))
                            order ~= id;
                    }
                }
            }
        }

        auto prefs = prefsRepo.load(user.id);
        prefs.networkOrder = order;
        auto newVersion = prefsRepo.save(user.id, prefs);

        broadcastPrefUpdate(user.id.toString(), "networkOrder", serializeToJson(prefs.networkOrder), newVersion);

        res.statusCode = 204;
        res.writeVoidBody();
    }

    /// Broadcasts a `pref_update` event so every connected tab/device for
    /// this user can sync its local state in real time. The `prefVersion`
    /// argument is the monotonic counter returned by the most recent
    /// `prefsRepo.save()`; the receiving frontend uses it for
    /// last-write-wins against its own copy. See docs/PREF_VERSION.md.
    private void broadcastPrefUpdate(string userId, string prefKey, Json value, long prefVersion) {
        try {
            auto json = Json.emptyObject;
            json["type"] = Json("pref_update");
            json["key"] = Json(prefKey);
            json["value"] = value;
            json["prefVersion"] = Json(prefVersion);
            redis.publish(RedisKeys.events(userId), json.toString());
        } catch (Exception e) {
            logWarn("Failed to broadcast pref update: %s", e.msg);
        }
    }

    /// W3-T01a: Returns archived buffer names for ALL user networks grouped
    /// by networkId. Cached in Redis with 5-minute TTL.
    private void getArchiveNames(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto user = req.context["user"].get!User;
        auto cacheKey = RedisKeys.archiveNames(user.id.toString());

        // Check Redis cache first
        auto cached = redis.getJson(cacheKey);
        if (cached.type != Json.Type.null_ && cached.type != Json.Type.undefined) {
            res.writeJsonBody(cached);
            return;
        }

        // Load user preferences and group archived channels by networkId
        auto prefs = prefsRepo.load(user.id);
        string[][string] grouped;
        foreach (const archiveId; prefs.archivedChannels) {
            auto colonIdx = archiveId.indexOf(":");
            if (colonIdx < 0) continue;
            auto networkId = archiveId[0 .. colonIdx];
            auto channelName = archiveId[colonIdx + 1 .. $];
            grouped[networkId] ~= channelName;
        }

        // Build JSON response
        auto archives = Json.emptyObject;
        foreach (nid, chans; grouped) {
            auto arr = Json.emptyArray;
            foreach (c; chans) arr ~= Json("" ~ c);
            archives[nid] = arr;
        }
        auto response = Json(["archives": archives]);

        // Cache in Redis with 5-minute TTL
        redis.setJson(cacheKey, response, 300);

        res.writeJsonBody(response);
    }

    // NEW: Get all connection servers (admin/health endpoint)
    private void getServers(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto servers = serverRegistry.getAllServers();
        Json[] arr;
        foreach (s; servers) {
            arr ~= s.toJson();
        }
        res.writeJsonBody(Json([
            "servers": Json(arr),
            "healthyCount": Json(serverRegistry.getHealthyServers().length)
        ]));
    }

    // NEW: Get single server details
    private void getServer(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto serverId = req.params["id"];
        auto server = serverRegistry.getServer(serverId);
        
        if (server.serverId.length == 0) {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("Server not found")]));
            return;
        }
        
        auto j = server.toJson();
        j["isHealthy"] = Json(serverRegistry.isServerHealthy(serverId));
        j["networkCount"] = Json(server.assignedNetworks.length);
        res.writeJsonBody(j);
    }

    /// Admin: handoff / hot-reload status. Reads metrics stored in
    /// Redis by the engine after each successful handoff.
    /// Returns the last handoff result + per-server draining state.
    private void getHandoffStatus(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        try {
            auto db = redis.getDb();
            auto fieldInfo = db.hget("ircfiber:handoff:last", "info");
            auto fieldSid = db.hget("ircfiber:handoff:last", "serverId");
            auto fieldTs  = db.hget("ircfiber:handoff:last", "timestamp");

            Json lastHandoff;
            if (fieldInfo.length > 0) {
                try {
                    lastHandoff = parseJsonString(cast(string) fieldInfo);
                } catch (Exception) {
                    lastHandoff = Json.emptyObject;
                }
            } else {
                lastHandoff = Json.emptyObject;
            }

            // Gather draining state from all registered servers
            auto servers = serverRegistry.getAllServers();
            Json[] drainingList;
            foreach (s; servers) {
                try {
                    auto data = db.hget(RedisKeys.server(s.serverId), "data");
                    if (data.length > 0) {
                        auto j = parseJsonString(cast(string) data);
                        if (j.type == Json.Type.object) {
                            bool draining = false;
                            if ("draining" in j) {
                                auto dv = j["draining"];
                                draining = dv.get!bool;
                            }
                            if (draining)
                                drainingList ~= Json(["serverId": Json(s.serverId), "draining": Json(true)]);
                        }
                    }
                } catch (Exception) {}
            }

            auto output = Json.emptyObject;
            output["lastHandoff"] = lastHandoff;
            output["lastHandoffServerId"] = Json(fieldSid.length > 0 ? cast(string) fieldSid : "");
            output["lastHandoffTimestamp"] = Json(fieldTs.length > 0 ? cast(string) fieldTs : "");
            output["drainingServers"] = Json(drainingList);
            res.writeJsonBody(output);
        } catch (Exception e) {
            res.statusCode = 500;
            res.writeJsonBody(Json(["error": Json("Failed to read handoff status: " ~ e.msg)]));
        }
    }

    /// Admin: manually clear a stuck draining flag for a specific server.
    /// This is the emergency recovery button for the admin dashboard.
    /// POST /api/admin/servers/:id/clear-draining
    private void clearServerDraining(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;

        auto serverId = req.params["id"];
        auto server = serverRegistry.getServer(serverId);

        if (server.serverId.length == 0) {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("Server not found")]));
            return;
        }

        try {
            serverRegistry.clearDraining(serverId);
            logInfo("Admin: manually cleared draining for server %s", serverId);
            res.writeJsonBody(Json([
                "status": Json("ok"),
                "serverId": Json(serverId),
                "message": Json("Draining state cleared")
            ]));
        } catch (Exception e) {
            res.statusCode = 500;
            res.writeJsonBody(Json(["error": Json("Failed to clear draining: " ~ e.msg)]));
        }
    }

    /// Max accepted upload size: 200MB.
    enum MAX_UPLOAD_BYTES = 200L * 1024 * 1024;

    /// Returns null if acceptable, else a user-presentable rejection reason.
    package static string validateUpload(string mime, long size) @safe {
        import std.algorithm.searching : startsWith;
        if (!mime.startsWith("image/")) return "Only images are supported";
        if (size <= 0) return "Empty file";
        if (size > MAX_UPLOAD_BYTES) return "File too large (max 200 MB)";
        return null;
    }

    /// Dedup `older` against `existing` by msgid (preferred) and eid
    /// (fallback). The engine writes every event to BOTH Redis and
    /// MongoDB, so when Redis returns fewer than the requested count
    /// and the REST handler falls through to a MongoDB `getBeforeTimestamp`
    /// call, MongoDB will return the same messages we already have.
    /// Without this filter the frontend renders each one twice.
    /// Public so `source/dedup_test.d` can exercise it without booting
    /// Redis/MongoDB (which the full `unittest` build is currently
    /// broken on macOS — see dub.sdl `unittest` config).
    public static Json[] dedupMessages(Json[] existing, Json[] older) @safe {
        bool[string] seenMsgids;
        bool[string] seenEids;
        foreach (m; existing) {
            if (auto mid = "m" in m)
                if (mid.type == Json.Type.string) seenMsgids[mid.get!string] = true;
            if (auto e = "eid" in m)
                if (e.type == Json.Type.int_) {
                    auto eidStr = e.get!long.to!string;
                    seenEids[eidStr] = true;
                }
        }
        Json[] deduped;
        foreach (m; older) {
            bool dup = false;
            if (auto mid = "m" in m)
                if (mid.type == Json.Type.string && (mid.get!string) in seenMsgids) dup = true;
            if (!dup)
                if (auto e = "eid" in m)
                    if (e.type == Json.Type.int_) {
                        if ((e.get!long.to!string) in seenEids) dup = true;
                    }
            if (!dup) deduped ~= m;
        }
        return deduped;
    }

    private void uploadFile(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;

        auto pf = "file" in req.files;
        if (pf is null) {
            res.statusCode = 400;
            res.writeJsonBody(Json(["error": Json("missing file field")]));
            return;
        }
        import vibe.core.file : readFile;
        auto data = cast(const(ubyte)[])readFile(pf.tempPath);
        auto mime = pf.headers.get("Content-Type", "");
        auto filename = req.form.get("filename", pf.filename.name);

        if (auto err = validateUpload(mime, cast(long)data.length)) {
            res.statusCode = 400;
            res.writeJsonBody(Json(["error": Json(err)]));
            return;
        }

        // Construct base URL from the incoming Host header (set by Caddy).
        // Fall back to a reasonable default for local dev.
        auto host = req.headers["Host"];
        if (host.length == 0) host = "localhost:8090";
        auto baseUrl = "https://" ~ host;

        LocalUploadResult uploaded;
        try {
            uploaded = saveUpload(filename, mime, data, baseUrl);
        } catch (LocalUploadException e) {
            logWarn("local upload failed: %s", e.msg);
            res.statusCode = 502;
            res.writeJsonBody(Json(["error": Json(e.msg)]));
            return;
        }

        UploadRecord rec;
        rec.id = randomUUID().toString();
        rec.userId = user.id.toString();
        rec.networkId = req.form.get("networkId", "");
        rec.buffer = req.form.get("buffer", "");
        rec.filename = filename;
        rec.originalFilename = pf.filename.name;
        rec.mimeType = mime;
        rec.size = cast(long)data.length;
    rec.pageUrl = uploaded.url;
    rec.directUrl = uploaded.url;
        rec.createdAt = Clock.currTime.toUnixTime!long * 1000;
        try { uploadRepo.insert(rec); }
        catch (Exception e) { logError("Failed to record upload: %s", e.msg); }

        res.writeJsonBody(Json([
            "id": Json(rec.id), "url": Json(rec.directUrl), "pageUrl": Json(rec.pageUrl),
            "name": Json(rec.filename), "size": Json(rec.size),
        ]));
    }

    private void getUploads(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        int limit = 25;
        if (auto p = "limit" in req.query) limit = (*p).to!int;
        UploadRecord[] records;
        if (auto p = "offset" in req.query) {
            records = uploadRepo.pageByUser(user.id.toString(), (*p).to!int, limit);
        } else {
            long before = long.max;
            if (auto p = "before" in req.query) before = (*p).to!long;
            records = uploadRepo.listByUser(user.id.toString(), before, limit);
        }
        long total = uploadRepo.countByUser(user.id.toString());
        auto arr = Json.emptyArray;
        foreach (r; records) {
            arr ~= Json([
                "id": Json(r.id), "url": Json(r.directUrl), "name": Json(r.filename),
                "mimeType": Json(r.mimeType), "size": Json(r.size),
                "createdAt": Json(r.createdAt), "buffer": Json(r.buffer),
                "networkId": Json(r.networkId),
            ]);
        }
        res.writeJsonBody(Json(["uploads": arr, "total": Json(total)]));
    }

    private void deleteUpload(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        auto id = req.params["id"];
        auto userId = user.id.toString();

        // 1. Fetch the record first so we know the URL/file path
        auto rec = uploadRepo.getById(userId, id);
        if (rec is UploadRecord.init) {
            // If we found nothing (or it's not theirs), maybe another request
            // already deleted it — double-check with the old soft-delete
            // semantics for idempotency.
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("not found")]));
            return;
        }

        // 2. Remove the local file from disk.
        //    Local upload URLs are always "<baseUrl>/uploads/<uuid.ext>".
        //    We extract the filename and look it up under the upload directory.
        auto url = rec.directUrl.strip;
        auto uploadDir_ = uploadDir();
        auto uploadPrefix = "/uploads/";
        auto prefixPos = url.indexOf(uploadPrefix);
        if (prefixPos != -1) {
            auto filename = url[prefixPos + uploadPrefix.length .. $];
            if (filename.length > 0) {
                auto filePath = buildPath(uploadDir_, filename);
                try {
                    remove(filePath);
                    logInfo("Deleted local file for upload %s: %s", id, filePath);
                } catch (Exception e) {
                    // File may already be gone (concurrent delete, prior cleanup, etc.)
                    logWarn("Could not remove local file for upload %s at %s: %s",
                        id, filePath, e.msg);
                }
            }
        } else {
            // Non-local URL (legacy / external upload). We still remove the DB
            // record below but can't delete the remote file.
            logInfo("Upload %s has remote URL %s — skipping file deletion", id, url);
        }

        // 3. Hard-delete the MongoDB document
        if (uploadRepo.hardDelete(userId, id)) {
            logInfo("Hard-deleted upload document %s for user %s", id, userId);
            res.statusCode = 204;
            res.writeVoidBody();
        } else {
            // The document was found by getById but disappeared by hardDelete.
            // Concurrent delete — rare but possible. Return 204 (idempotent).
            logWarn("Upload %s vanished between getById and hardDelete (concurrent delete?)", id);
            res.statusCode = 204;
            res.writeVoidBody();
        }
    }

    private Json pasteToJson(const ref PasteRecord r) {
        return Json([
            "id": Json(r.id), "name": Json(r.name), "syntax": Json(r.syntax),
            "lines": Json(r.lines), "body": Json(r.content),
            "createdAt": Json(r.createdAt), "buffer": Json(r.buffer),
            "networkId": Json(r.networkId),
        ]);
    }

    private void getPastebins(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        int limit = 25;
        if (auto p = "limit" in req.query) limit = (*p).to!int;
        int offset = 0;
        if (auto p = "offset" in req.query) offset = (*p).to!int;
        auto records = pastebinRepo.pageByUser(user.id.toString(), offset, limit);
        long total = pastebinRepo.countByUser(user.id.toString());
        auto arr = Json.emptyArray;
        foreach (r; records) arr ~= pasteToJson(r);
        res.writeJsonBody(Json(["pastebins": arr, "total": Json(total)]));
    }

    private void createPastebin(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        auto j = req.json;
        PasteRecord rec;
        rec.id = randomUUID().toString();
        rec.userId = user.id.toString();
        if ("networkId" in j) rec.networkId = j["networkId"].get!string;
        if ("buffer" in j) rec.buffer = j["buffer"].get!string;
        if ("name" in j) rec.name = j["name"].get!string;
        rec.syntax = ("syntax" in j) ? j["syntax"].get!string : "text";
        rec.content = ("body" in j) ? j["body"].get!string : "";
        if (rec.content.length == 0) {
            res.statusCode = 400;
            res.writeJsonBody(Json(["error": Json("empty body")]));
            return;
        }
        rec.lines = countLines(rec.content);
        rec.createdAt = Clock.currTime.toUnixTime!long * 1000;
        pastebinRepo.insert(rec);
        res.writeJsonBody(pasteToJson(rec));
    }

    private void updatePastebin(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        auto existing = pastebinRepo.getById(user.id.toString(), req.params["id"]);
        if (existing.id.length == 0) {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("not found")]));
            return;
        }
        auto j = req.json;
        string name = ("name" in j) ? j["name"].get!string : existing.name;
        string syntax = ("syntax" in j) ? j["syntax"].get!string : existing.syntax;
        pastebinRepo.updateMeta(user.id.toString(), existing.id, name, syntax);
        existing.name = name;
        existing.syntax = syntax;
        res.writeJsonBody(pasteToJson(existing));
    }

    private void deletePastebin(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        if (pastebinRepo.softDelete(user.id.toString(), req.params["id"])) {
            res.statusCode = 204;
            res.writeVoidBody();
        } else {
            res.statusCode = 404;
            res.writeJsonBody(Json(["error": Json("not found")]));
        }
    }

    private void getPastebinRaw(HTTPServerRequest req, HTTPServerResponse res) {
        requireAuth(req, res);
        if (res.headerWritten) return;
        auto user = req.context["user"].get!User;
        auto rec = pastebinRepo.getById(user.id.toString(), req.params["id"]);
        if (rec.id.length == 0) {
            res.statusCode = 404;
            res.writeBody("not found", "text/plain; charset=utf-8");
            return;
        }
        res.writeBody(rec.content, "text/plain; charset=utf-8");
    }

    /// HEAD /api/ping — lightweight connectivity check.  Unauthenticated
    /// so the frontend OnlineChecker can probe before login.
    /// Vibe.d automatically strips the body for HEAD requests on GET routes.
    private void ping(HTTPServerRequest, HTTPServerResponse res) {
        res.writeJsonBody(Json(["ping": Json("pong")]));
    }

    private void healthCheck(HTTPServerRequest, HTTPServerResponse res) {
        auto services = Json.emptyObject;
        bool allOk = true;

        // Check MongoDB
        try {
            auto db = AppMongoConnection.getDb();
            const _ = db["networks"].findOne(Bson.emptyObject);
            services["mongo"] = Json(["ok": Json(true)]);
        } catch (Exception e) {
            services["mongo"] = Json(["ok": Json(false), "error": Json(e.msg)]);
            allOk = false;
        }

        // Check Redis
        try {
            redis.getDb().exists("health_check_test");
            services["redis"] = Json(["ok": Json(true)]);
        } catch (Exception e) {
            services["redis"] = Json(["ok": Json(false), "error": Json(e.msg)]);
            allOk = false;
        }

        // NEW: Check connection servers
        auto healthyServers = serverRegistry.getHealthyServers();
        services["connectionServers"] = Json([
            "ok": Json(healthyServers.length > 0),
            "total": Json(serverRegistry.getAllServers().length),
            "healthy": Json(healthyServers.length)
        ]);
        if (healthyServers.length == 0) allOk = false;

        // T1-W3: gateway contention metrics — session queue depth / drops
        if (sessionManager !is null) {
            try {
                auto stats = sessionManager.broadcastStats();
                services["sessions"] = Json([
                    "ok": Json(true),
                    "total": Json(stats.total),
                    "maxDepth": Json(stats.maxDepth),
                    "lastEnqueuedEid": Json(stats.lastEnqueuedEid),
                    "lastDeliveredEid": Json(stats.lastDeliveredEid),
                    "backpressured": Json(stats.backpressured),
                    "ghosts": Json(stats.ghosts)
                ]);
            } catch (Exception e) {
                services["sessions"] = Json(["ok": Json(false), "error": Json(e.msg)]);
            }
        }

        res.writeJsonBody(Json([
            "status": Json(allOk ? "healthy" : "degraded"),
            "service": Json("irc-fiber-gateway"),
            "services": services
        ]));
    }

    private NetworkStateSnapshot loadSnapshot(string networkId) {
        // NEW: Try server-aware key first, then legacy
        auto serverId = serverRegistry.getServerForNetwork(networkId);
        
        if (serverId.length > 0) {
            auto fields = redis.hgetAll(RedisKeys.state(serverId, networkId));
            if ("data" in fields) {
                try { return NetworkStateSnapshot.fromJson(parseJson(fields["data"])); }
                catch (Exception e) {}
            }
        }
        
        // Legacy fallback
        auto fields = redis.hgetAll(RedisKeys.state_legacy(networkId));
        if ("data" in fields) {
            try { return NetworkStateSnapshot.fromJson(parseJson(fields["data"])); }
            catch (Exception e) {}
        }
        return NetworkStateSnapshot.init;
    }
}

@("validateUpload accepts images under the size cap")
unittest {
    assert(RESTAPI.validateUpload("image/png", 1024) is null);
    assert(RESTAPI.validateUpload("image/jpeg", 32 * 1024 * 1024) is null);
}

@("validateUpload rejects non-images and oversize files")
unittest {
    assert(RESTAPI.validateUpload("application/pdf", 10) !is null);
    assert(RESTAPI.validateUpload("video/mp4", 10) !is null);
    assert(RESTAPI.validateUpload("", 10) !is null);
    assert(RESTAPI.validateUpload("image/png", 201 * 1024 * 1024) !is null);
}

// Regression: refresh on a low-volume channel like /irc/SuperNets/channel/zod
// surfaced each Redis message twice because the engine writes every event to
// BOTH Redis and MongoDB, so when Redis returned 9/16 messages and the REST
// handler fell through to MongoDB's "newest N", MongoDB returned those same
// 9/16 again. The frontend's setMessages then rendered each one twice.
// Fix: RESTAPI.dedupMessages drops MongoDB-side messages whose msgid/eid is
// already in the Redis set.
@("dedupMessages drops MongoDB entries whose msgid matches Redis")
unittest {
    auto existing = [
        Json(["m": Json("msg-a"), "eid": Json(100)]),
        Json(["m": Json("msg-b"), "eid": Json(101)]),
    ];
    auto older = [
        Json(["m": Json("msg-a"), "eid": Json(100)]),  // dup
        Json(["m": Json("msg-c"), "eid": Json(102)]),  // new
        Json(["m": Json("msg-b"), "eid": Json(101)]),  // dup
    ];
    auto deduped = RESTAPI.dedupMessages(existing, older);
    assert(deduped.length == 1);
    assert(deduped[0]["m"].get!string == "msg-c");
}

@("dedupMessages falls back to eid match when msgid is absent")
unittest {
    // Legacy MongoDB entries may lack msgid (only eid). Make sure eid dedup
    // catches them too — otherwise a 200-row page would still dup those.
    auto existing = [
        Json(["eid": Json(42), "x": Json("hello")]),
    ];
    auto older = [
        Json(["eid": Json(42), "x": Json("hello")]),  // dup by eid
        Json(["eid": Json(43), "x": Json("world")]),  // new
    ];
    auto deduped = RESTAPI.dedupMessages(existing, older);
    assert(deduped.length == 1);
    assert(deduped[0]["eid"].get!long == 43);
}

@("dedupMessages returns the input unchanged when no overlap")
unittest {
    auto existing = [
        Json(["m": Json("a"), "eid": Json(1)]),
    ];
    auto older = [
        Json(["m": Json("b"), "eid": Json(2)]),
        Json(["m": Json("c"), "eid": Json(3)]),
    ];
    auto deduped = RESTAPI.dedupMessages(existing, older);
    assert(deduped.length == 2);
}
