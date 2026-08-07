module ircfiber.web.admin.api;

import std.uuid : UUID, parseUUID, randomUUID;
import std.string : strip, split, join, indexOf;
import std.algorithm : canFind, filter, map;
import std.array : array;
import std.conv : to;
import std.datetime : Clock;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse;
import vibe.core.log : logInfo, logWarn;
import vibe.data.json : Json;

import ircfiber.auth : hashPassword;
import ircfiber.web.common : getClientIp;
import ircfiber.db.user : UserRepository;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.uploads : UploadRepository;
import ircfiber.models.network : NetworkConfig;
import ircfiber.models.user : User;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.storage.session : RedisSessionStore;
import ircfiber.web.admin.helpers : jsonOk, jsonError, readJsonBody, formString, jsonArray, stripJsonStr;
import ircfiber.web.admin.servers : AssignmentRow, loadNetworkSnapshot;
import ircfiber.redis.protocol : NetworkStateSnapshot, RedisKeys, ControlMessage;

/// GET /api/admin/me — current admin user (id, username, email, roles).
package void apiMe(HTTPServerRequest req, HTTPServerResponse res) {
    try {
        auto user = req.context["user"].get!User;
        if (user.username.length == 0) {
            jsonError(res, 401, "Not authenticated");
            return;
        }
        Json data = Json.emptyObject;
        data["id"] = Json(user.id.toString());
        data["username"] = Json(user.username);
        data["email"] = Json(user.email);
        data["roles"] = jsonArray(user.roles);
        data["isAdmin"] = Json(user.roles.canFind("admin"));
        jsonOk(res, data);
    } catch (Exception e) {
        import std.string : replace;
        logWarn("apiMe failed: %s", e.msg);
        jsonError(res, 500, e.msg);
    }
}

/// GET /api/admin/dashboard — KPIs + host summary + recent activity.
package void apiDashboard(HTTPServerRequest req, HTTPServerResponse res,
                          RedisStorage redis, ServerRegistry serverRegistry) {
    auto repo = new UserRepository();
    auto userCount = repo.count();
    auto recentUsers = repo.findAll(10, 0);

    // Active sessions
    long activeSessions;
    try {
        auto db = redis.getDb();
        auto keys = db.keys("session:*");
        foreach (_; keys) activeSessions++;
    } catch (Exception) { activeSessions = -1; }

    // Uploads
    long uploadCount;
    try {
        auto uploadRepo = new UploadRepository();
        uploadCount = uploadRepo.countAll();
    } catch (Exception) { uploadCount = -1; }

    // Engines + networks
    auto allServers = serverRegistry.getAllServers();
    auto healthyServers = serverRegistry.getHealthyServers();
    int totalNetworks;
    foreach (s; allServers) totalNetworks += cast(int) s.assignedNetworks.length;
    int engineCount = cast(int) allServers.length;
    int healthyCount = cast(int) healthyServers.length;
    auto hostSummary = serverRegistry.getHostConnectionSummary();
    auto maxConns = serverRegistry.getMaxConnsPerHost();

    Json data = Json.emptyObject;
    data["userCount"] = Json(userCount);
    data["activeSessions"] = Json(activeSessions);
    data["totalNetworks"] = Json(totalNetworks);
    data["uploadCount"] = Json(uploadCount);
    data["engineCount"] = Json(engineCount);
    data["healthyCount"] = Json(healthyCount);
    data["maxConnsPerHost"] = Json(maxConns);

    // Engines detail
    Json[] engArr;
    foreach (s; allServers) {
        auto cfg = serverRegistry.getEngineConfig(s.serverId);
        Json e = Json.emptyObject;
        e["serverId"] = Json(s.serverId);
        e["bindAddress"] = Json(s.bindAddress);
        e["port"] = Json(s.port);
        e["priority"] = Json(cfg.priority != 0 ? cfg.priority : s.priority);
        e["maxConnections"] = Json(cfg.maxConnections != 0 ? cfg.maxConnections : s.maxConnections);
        e["fallbackOnly"] = Json(cfg.fallbackOnly);
        e["assignedNetworkCount"] = Json(cast(long) s.assignedNetworks.length);
        bool healthy = false;
        foreach (h; healthyServers) if (h.serverId == s.serverId) { healthy = true; break; }
        e["healthy"] = Json(healthy);
        long nowMs = Clock.currTime.toUnixTime!long * 1000L;
        e["lastHeartbeat"] = Json(s.lastHeartbeat);
        e["ageSeconds"] = Json((nowMs - s.lastHeartbeat) / 1000);
        engArr ~= e;
    }
    data["engines"] = Json(engArr);

    // Host summary
    Json[] hostArr;
    foreach (hcs; hostSummary) {
        Json h = Json.emptyObject;
        h["host"] = Json(hcs.host);
        h["totalConns"] = Json(hcs.totalConns);
        h["serverIds"] = jsonArray(hcs.serverIds);
        long cap = cast(long) maxConns * cast(long) hcs.serverIds.length;
        h["capacity"] = Json(cap);
        if (cap > 0 && hcs.totalConns >= cap) h["status"] = Json("full");
        else if (cap > 0 && hcs.totalConns >= cap * 2 / 3) h["status"] = Json("warn");
        else h["status"] = Json("safe");
        hostArr ~= h;
    }
    data["hosts"] = Json(hostArr);

    // Recent users (light)
    Json[] usersArr;
    foreach (u; recentUsers) {
        Json u2 = Json.emptyObject;
        u2["id"] = Json(u.id.toString());
        u2["username"] = Json(u.username);
        u2["email"] = Json(u.email);
        u2["roles"] = jsonArray(u.roles);
        usersArr ~= u2;
    }
    data["recentUsers"] = Json(usersArr);

    jsonOk(res, data);
}

// ────────────────────────────────────────────────────────────
// Servers API
// ────────────────────────────────────────────────────────────

/// GET /api/admin/servers — engines + assignments + host routing.
package void apiServers(HTTPServerRequest req, HTTPServerResponse res,
                        RedisStorage redis, ServerRegistry serverRegistry) {
    auto allServers = serverRegistry.getAllServers();
    auto healthyServers = serverRegistry.getHealthyServers();
    auto hostSummary = serverRegistry.getHostConnectionSummary();
    auto maxConns = serverRegistry.getMaxConnsPerHost();
    auto rawAssignments = serverRegistry.getAllAssignments();

    // Apply saved config overrides to the displayed engines
    foreach (ref s; allServers) {
        auto cfg = serverRegistry.getEngineConfig(s.serverId);
        if (cfg.priority != 0) s.priority = cfg.priority;
        if (cfg.maxConnections != 0) s.maxConnections = cfg.maxConnections;
        s.fallbackOnly = cfg.fallbackOnly;
    }

    AssignmentRow[] assignments;
    NetworkRepository netRepo;
    UserRepository userRepo;
    try netRepo = new NetworkRepository();
    catch (Exception e) { logWarn("Could not open NetworkRepository: %s", e.msg); }
    try userRepo = new UserRepository();
    catch (Exception e) { logWarn("Could not open UserRepository: %s", e.msg); }

    foreach (a; rawAssignments) {
        AssignmentRow row;
        row.networkId = a.networkId;
        row.serverId = a.serverId;
        if (netRepo) {
            try {
                auto netId = parseUUID(a.networkId);
                auto nw = netRepo.findByIdWithUser(netId);
                if (nw.config.id != UUID.init) {
                    row.networkName = nw.config.name.length > 0 ? nw.config.name : nw.config.host;
                    row.networkHost = nw.config.host;
                    if (userRepo && nw.userId != UUID.init) {
                        try {
                            auto u = userRepo.findById(nw.userId);
                            if (u.username.length > 0) {
                                row.userId = nw.userId.toString();
                                row.username = u.username;
                            }
                        } catch (Exception) {}
                    }
                }
            } catch (Exception) {}
        }
        // Pull the live nick from the engine's last state snapshot so
        // admins can see which IRC identity is in use on this server.
        // Falls back to the configured nick when the engine hasn't
        // reported yet, and stays empty when the network is offline.
        try {
            auto snap = loadNetworkSnapshot(redis, a.networkId);
            if (snap.currentNick.length > 0) {
                row.nick = snap.currentNick;
            } else if (netRepo) {
                try {
                    auto netId = parseUUID(a.networkId);
                    auto nw = netRepo.findByIdWithUser(netId);
                    if (nw.config.id != UUID.init && nw.config.nick.length > 0) {
                        row.nick = nw.config.nick;
                    }
                } catch (Exception) {}
            }
        } catch (Exception) {}
        assignments ~= row;
    }

    Json data = Json.emptyObject;
    Json[] engArr;
    foreach (s; allServers) {
        bool healthy = false;
        foreach (h; healthyServers) if (h.serverId == s.serverId) { healthy = true; break; }
        Json e = Json.emptyObject;
        e["serverId"] = Json(s.serverId);
        e["bindAddress"] = Json(s.bindAddress);
        e["port"] = Json(s.port);
        e["priority"] = Json(s.priority);
        e["maxConnections"] = Json(s.maxConnections);
        e["fallbackOnly"] = Json(s.fallbackOnly);
        e["assignedNetworks"] = jsonArray(s.assignedNetworks);
        e["healthy"] = Json(healthy);
        e["lastHeartbeat"] = Json(s.lastHeartbeat);
        long nowMs = Clock.currTime.toUnixTime!long * 1000L;
        e["ageSeconds"] = Json((nowMs - s.lastHeartbeat) / 1000);
        engArr ~= e;
    }
    data["engines"] = Json(engArr);
    data["maxConnsPerHost"] = Json(maxConns);

    Json[] hostArr;
    foreach (hcs; hostSummary) {
        Json h = Json.emptyObject;
        h["host"] = Json(hcs.host);
        h["totalConns"] = Json(hcs.totalConns);
        h["serverIds"] = jsonArray(hcs.serverIds);
        hostArr ~= h;
    }
    data["hosts"] = Json(hostArr);

    Json[] assignArr;
    foreach (a; assignments) {
        Json j = Json.emptyObject;
        j["networkId"] = Json(a.networkId);
        j["serverId"] = Json(a.serverId);
        j["networkName"] = Json(a.networkName);
        j["networkHost"] = Json(a.networkHost);
        j["userId"] = Json(a.userId);
        j["username"] = Json(a.username);
        j["nick"] = Json(a.nick);
        assignArr ~= j;
    }
    data["assignments"] = Json(assignArr);

    jsonOk(res, data);
}



/// GET /api/admin/servers/host/:host — host detail.
package void apiServerHost(HTTPServerRequest req, HTTPServerResponse res,
                          RedisStorage redis, ServerRegistry serverRegistry) {
    import std.uni : toLower;
    auto host = req.params["host"];
    auto netRepo = new NetworkRepository();
    auto allNetworks = netRepo.findAll();
    auto hostLower = host.toLower();
    auto userRepo = new UserRepository();

    Json[] connArr;
    int[string] serverCounts;
    int liveCount;
    foreach (nw; allNetworks) {
        if (nw.config.host.toLower() != hostLower) continue;
        auto netId = nw.config.id.toString();
        auto user = userRepo.findById(nw.userId);
        auto directSid = serverRegistry.getServerForNetwork(netId);
        auto snapshot = loadNetworkSnapshot(redis, netId);
        bool isBanned = false;
        try isBanned = redis.getDb().exists(RedisKeys.bannedNetwork(netId));
        catch (Exception) {}

        Json c = Json.emptyObject;
        c["networkId"] = Json(netId);
        c["networkName"] = Json(nw.config.name);
        c["host"] = Json(nw.config.host);
        c["userId"] = Json(nw.userId.toString());
        c["username"] = Json(user.username.length > 0 ? user.username : "unknown");
        c["serverId"] = Json(directSid.length > 0 ? directSid : "unassigned");
        c["connected"] = Json(snapshot.connected);
        c["status"] = Json(snapshot.status.length > 0 ? snapshot.status : (snapshot.connected ? "connected" : "offline"));
        c["nick"] = Json(snapshot.currentNick.length > 0 ? snapshot.currentNick : nw.config.nick);
        c["isBanned"] = Json(isBanned);
        c["disabled"] = Json(nw.config.disabled);
        connArr ~= c;

        auto sc = directSid in serverCounts;
        if (sc) (*sc)++;
        else serverCounts[directSid] = 1;
        if (snapshot.connected) liveCount++;
    }

    Json data = Json.emptyObject;
    data["host"] = Json(host);
    data["connections"] = Json(connArr);
    data["liveCount"] = Json(liveCount);
    Json counts = Json.emptyObject;
    foreach (sid, count; serverCounts) counts[sid] = Json(count);
    data["serverCounts"] = counts;
    jsonOk(res, data);
}

/// POST /api/admin/servers/:id/reassign — reassign all networks on engine.
package void apiReassignServer(HTTPServerRequest req, HTTPServerResponse res,
                              ServerRegistry serverRegistry) {
    auto serverId = req.params["id"];
    auto networks = serverRegistry.getNetworksForServer(serverId);
    int reassigned;
    foreach (netId; networks) {
        try {
            serverRegistry.reassignNetwork(netId);
            reassigned++;
        } catch (Exception e) {
            logWarn("Failed to reassign network %s: %s", netId, e.msg);
        }
    }
    Json data = Json.emptyObject;
    data["reassigned"] = Json(reassigned);
    data["total"] = Json(cast(long) networks.length);
    data["serverId"] = Json(serverId);
    jsonOk(res, data);
}

/// POST /api/admin/servers/assignments/:networkId/reassign — move one network.
package void apiReassignAssignment(HTTPServerRequest req, HTTPServerResponse res,
                                   ServerRegistry serverRegistry) {
    auto networkId = req.params["networkId"];
    try {
        auto newSid = serverRegistry.reassignNetwork(networkId);
        Json data = Json.emptyObject;
        data["networkId"] = Json(networkId);
        data["newServerId"] = Json(newSid);
        jsonOk(res, data);
    } catch (Exception e) {
        jsonError(res, 500, e.msg);
    }
}

/// POST /api/admin/servers/assignments/:networkId/remove — clear assignment.
package void apiRemoveAssignment(HTTPServerRequest req, HTTPServerResponse res,
                                RedisStorage redis, ServerRegistry serverRegistry) {
    import std.algorithm : filter;
    auto networkId = req.params["networkId"];
    auto oldServerId = serverRegistry.getServerForNetwork(networkId);
    if (oldServerId.length > 0) {
        try {
            auto srv = serverRegistry.getServer(oldServerId);
            srv.assignedNetworks = srv.assignedNetworks
                .filter!(n => n != networkId)
                .array;
            redis.hset(RedisKeys.server(oldServerId), "data", srv.toJson().toString());
        } catch (Exception e) {
            logWarn("Remove-assignment: could not update server %s: %s", oldServerId, e.msg);
        }
    }
    auto db = redis.getDb();
    db.hdel(RedisKeys.networkAssignments(), networkId);
    db.del(RedisKeys.networkFail(networkId));
    db.del(RedisKeys.lease(networkId));
    Json data = Json.emptyObject;
    data["networkId"] = Json(networkId);
    data["wasOn"] = Json(oldServerId);
    jsonOk(res, data);
}

/// POST /api/admin/servers/:id/config — set engine priority/cap/fallback.
package void apiEngineConfig(HTTPServerRequest req, HTTPServerResponse res,
                            ServerRegistry serverRegistry) {
    import std.conv : to;
    auto serverId = req.params["id"];
    auto body = readJsonBody(req);
    try {
        auto priority = body["priority"].get!int;
        auto maxConns = body["maxConnections"].get!int;
        auto fallback = body["fallbackOnly"].get!bool;
        serverRegistry.setEngineConfig(serverId, priority, maxConns, fallback);
        Json data = Json.emptyObject;
        data["serverId"] = Json(serverId);
        data["priority"] = Json(priority);
        data["maxConnections"] = Json(maxConns);
        data["fallbackOnly"] = Json(fallback);
        jsonOk(res, data);
    } catch (Exception e) {
        jsonError(res, 400, e.msg);
    }
}

/// POST /api/admin/servers/host/:host/disconnect/:networkId
package void apiHostDisconnect(HTTPServerRequest req, HTTPServerResponse res,
                              RedisStorage redis, ServerRegistry serverRegistry) {
    import std.uuid : parseUUID, UUID;
    auto networkId = req.params["networkId"];
    auto netRepo = new NetworkRepository();
    auto netId = parseUUID(networkId);
    auto owner = netRepo.findByIdWithUser(netId);
    netRepo.setDisabled(netId, true);
    if (owner.userId != UUID.init)
        redis.del(RedisKeys.userNetworks(owner.userId.toString()));
    auto serverId = serverRegistry.getServerForNetwork(networkId);
    bool engineHealthy = serverId.length > 0 && serverRegistry.isServerHealthy(serverId);
    if (engineHealthy) {
        auto msg = ControlMessage("disconnectNetwork", networkId);
        msg.reason = "Disconnected by admin";
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
    }
    Json data = Json.emptyObject;
    data["networkId"] = Json(networkId);
    data["engineHealthy"] = Json(engineHealthy);
    jsonOk(res, data);
}

/// POST /api/admin/servers/host/:host/reconnect/:networkId
package void apiHostReconnect(HTTPServerRequest req, HTTPServerResponse res,
                             RedisStorage redis, ServerRegistry serverRegistry) {
    import std.uuid : parseUUID, UUID;
    auto host = req.params["host"];
    auto networkIdStr = req.params["networkId"];
    auto networkId = parseUUID(networkIdStr);
    auto netRepo = new NetworkRepository();
    auto owner = netRepo.findByIdWithUser(networkId);
    netRepo.setDisabled(networkId, false);
    if (owner.userId != UUID.init)
        redis.del(RedisKeys.userNetworks(owner.userId.toString()));
    auto cfg = netRepo.findById(networkId);
    if (cfg.name.length == 0) { jsonError(res, 404, "Network not found"); return; }

    auto allNetworks = netRepo.findAll();
    string ownerId;
    foreach (nw; allNetworks) {
        if (nw.config.id == networkId) { ownerId = nw.userId.toString(); break; }
    }
    auto serverId = serverRegistry.getServerForNetwork(networkIdStr);
    if (serverId.length == 0 || !serverRegistry.isServerHealthy(serverId)) {
        serverId = serverRegistry.reassignNetwork(networkIdStr);
    }
    if (serverId.length > 0) {
        auto msg = ControlMessage("reconnectNetwork", networkIdStr, ownerId, cfg.toJson());
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
    }
    Json data = Json.emptyObject;
    data["networkId"] = Json(networkIdStr);
    data["serverId"] = Json(serverId);
    jsonOk(res, data);
}

/// Core network deletion — stops the engine client, scrubs Redis state,
/// drops the Mongo record, and clears the per-server assignedNetworks
/// array. Host-agnostic so both the form-based host-detail path
/// (`apiHostDeleteNetwork`) and the SPA's assignment-table path
/// (`apiAssignmentDelete`) share one code path. Validates the networkId
/// is a UUID unless `allowEmpty` is set, which is used by the SPA's
/// "Delete" button to scrub the orphan-empty-string entry from the
/// server record (no Mongo row to delete, no UUID to parse).
private void deleteNetworkCore(HTTPServerRequest req, HTTPServerResponse res,
                                RedisStorage redis, ServerRegistry serverRegistry,
                                string networkIdStr, bool allowEmpty) {
    import std.uuid : parseUUID, UUID;
    bool isEmptyOrInvalid = networkIdStr.length == 0;
    UUID networkId = UUID.init;
    if (!isEmptyOrInvalid) {
        try networkId = parseUUID(networkIdStr);
        catch (Exception e) {
            if (!allowEmpty) { jsonError(res, 400, "Invalid network id: " ~ e.msg); return; }
            isEmptyOrInvalid = true;
        }
        if (networkId == UUID.init) isEmptyOrInvalid = true;
    }
    if (isEmptyOrInvalid && !allowEmpty) {
        jsonError(res, 400, "networkId is required");
        return;
    }

    auto db = redis.getDb();
    auto netRepo = new NetworkRepository();
    NetworkConfig cfg;
    if (!isEmptyOrInvalid) cfg = netRepo.findById(networkId);

    string serverId = serverRegistry.getServerForNetwork(networkIdStr);

    // Tell the engine to stop the client. Skip when the networkId is
    // empty or invalid — there's no client to stop, only a stale
    // entry to scrub from the server record + per-engine mirror.
    if (!isEmptyOrInvalid) {
        auto msg = ControlMessage("removeNetwork", networkIdStr);
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        if (serverId.length > 0) redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
        else redis.lpush(RedisKeys.control_legacy(), msg.toJson().toString());
    }

    // Persisted cleanup — only meaningful for real networkIds.
    if (!isEmptyOrInvalid && cfg.name.length > 0) {
        // Capture owner userId before deleting, for cache invalidation.
        auto owner = netRepo.findByIdWithUser(networkId);
        netRepo.deleteById(networkId);
        if (owner.userId != UUID.init)
            redis.del(RedisKeys.userNetworks(owner.userId.toString()));
        if (serverId.length > 0) db.del(RedisKeys.state(serverId, networkIdStr));
        db.del(RedisKeys.state_legacy(networkIdStr));
        db.del(RedisKeys.networkFail(networkIdStr));
        db.del(RedisKeys.bannedNetwork(networkIdStr));
    }

    // Always-on Redis cleanup, even for empty networkIds.
    db.hdel(RedisKeys.networkAssignments(), networkIdStr);
    if (serverId.length > 0) {
        // Strip the id from the server record AND the per-engine mirror.
        // Both must be updated because the engine's heartbeat reads from
        // the mirror and the gateway's per-server query reads from the
        // server record. A "Remove" call without these two updates is
        // what produced the original orphan — the engine kept re-asserting
        // the empty entry every heartbeat because the mirror still held it.
        try {
            auto srv = serverRegistry.getServer(serverId);
            auto before = srv.assignedNetworks.length;
            srv.assignedNetworks = srv.assignedNetworks
                .filter!(n => n != networkIdStr)
                .array;
            if (srv.assignedNetworks.length != before) {
                db.hset(RedisKeys.server(serverId), "data", srv.toJson().toString());
                db.hdel(RedisKeys.serverAssignments(serverId), networkIdStr);
            }
        } catch (Exception e) {
            logWarn("deleteNetworkCore: scrub server %s assignedNetworks failed for %s: %s",
                serverId, networkIdStr, e.msg);
        }
    } else if (isEmptyOrInvalid) {
        // No canonical assignment — the orphan lives only in the engine's
        // server record. Best-effort: walk every healthy server and strip
        // matching ids from both the record and the mirror.
        foreach (sid; serverRegistry.getAllServers().map!(s => s.serverId)) {
            try {
                auto srv = serverRegistry.getServer(sid);
                auto before = srv.assignedNetworks.length;
                srv.assignedNetworks = srv.assignedNetworks
                    .filter!(n => n != networkIdStr)
                    .array;
                if (srv.assignedNetworks.length != before) {
                    db.hset(RedisKeys.server(sid), "data", srv.toJson().toString());
                    db.hdel(RedisKeys.serverAssignments(sid), networkIdStr);
                }
            } catch (Exception e) {
                logWarn("deleteNetworkCore: orphan-scrub on %s failed: %s", sid, e.msg);
            }
        }
    }

    Json data = Json.emptyObject;
    data["networkId"] = Json(networkIdStr);
    data["serverId"] = Json(serverId);
    data["scrubbed"] = Json(true);
    jsonOk(res, data);
}

/// POST /api/admin/servers/host/:host/delete-network/:networkId
package void apiHostDeleteNetwork(HTTPServerRequest req, HTTPServerResponse res,
                                  RedisStorage redis, ServerRegistry serverRegistry) {
    deleteNetworkCore(req, res, redis, serverRegistry, req.params["networkId"], false);
}

/// POST /api/admin/servers/assignments/:networkId/delete
/// Full delete (Mongo + Redis + engine stop + buffer scrub) reachable
/// directly from the main #/servers assignment table — no host detail
/// navigation required. Also handles the empty/invalid-id case so an
/// operator can clear a stale "ghost" row that lingers in the engine's
/// assignedNetworks array without a corresponding Mongo record.
package void apiAssignmentDelete(HTTPServerRequest req, HTTPServerResponse res,
                                 RedisStorage redis, ServerRegistry serverRegistry) {
    deleteNetworkCore(req, res, redis, serverRegistry, req.params["networkId"], true);
}

/// POST /api/admin/routing — set global maxConnsPerHost.
package void apiRouting(HTTPServerRequest req, HTTPServerResponse res,
                       ServerRegistry serverRegistry) {
    import std.conv : to;
    auto body = readJsonBody(req);
    try {
        auto maxConns = body["maxConnsPerHost"].get!int;
        serverRegistry.setMaxConnsPerHost(maxConns);
        Json data = Json.emptyObject;
        data["maxConnsPerHost"] = Json(maxConns);
        jsonOk(res, data);
    } catch (Exception e) {
        jsonError(res, 400, e.msg);
    }
}

// ────────────────────────────────────────────────────────────
// Users API
// ────────────────────────────────────────────────────────────

/// GET /api/admin/users?q=&role=
package void apiUsersList(HTTPServerRequest req, HTTPServerResponse res) {
    auto repo = new UserRepository();
    auto q = formString(req, "q");
    User[] users;
    if (q.length > 0) users = repo.search(q, 200);
    else users = repo.findAll(200, 0);
    Json[] arr;
    foreach (u; users) {
        Json u2 = Json.emptyObject;
        u2["id"] = Json(u.id.toString());
        u2["username"] = Json(u.username);
        u2["email"] = Json(u.email);
        u2["roles"] = jsonArray(u.roles);
        u2["createdAt"] = Json(u.createdAt.toUnixTime());
        u2["signupIp"] = Json(u.signupIp);
        arr ~= u2;
    }
    Json data = Json.emptyObject;
    data["users"] = Json(arr);
    data["count"] = Json(cast(long) users.length);
    jsonOk(res, data);
}

/// POST /api/admin/users — create user.
package void apiUserCreate(HTTPServerRequest req, HTTPServerResponse res) {
    auto body = readJsonBody(req);
    try {
        auto username = body["username"].get!string.strip();
        auto email = body["email"].get!string.strip();
        auto password = body["password"].get!string.strip();
        if (username.length == 0 || email.length == 0 || password.length == 0)
            throw new Exception("All fields are required");

        auto repo = new UserRepository();
        auto existing = repo.findByUsername(username);
        if (existing.username.length > 0) throw new Exception("Username already taken");

        User u;
        u.id = randomUUID();
        u.username = username;
        u.email = email;
        u.passwordHash = hashPassword(password);
        u.roles = ["user"];
        u.signupIp = getClientIp(req);
        u.createdAt = Clock.currTime;
        repo.create(u);
        Json data = Json.emptyObject;
        data["id"] = Json(u.id.toString());
        data["username"] = Json(u.username);
        jsonOk(res, data);
    } catch (Exception e) {
        jsonError(res, 400, e.msg);
    }
}

/// GET /api/admin/users/:id
package void apiUserDetail(HTTPServerRequest req, HTTPServerResponse res,
                          RedisStorage redis) {
    import std.uuid : parseUUID;
    auto id = parseUUID(req.params["id"]);
    auto repo = new UserRepository();
    auto user = repo.findById(id);
    if (user.username.length == 0) { jsonError(res, 404, "User not found"); return; }

    auto netRepo = new NetworkRepository();
    auto networks = netRepo.findByUserId(user.id);
    auto uploadRepo = new UploadRepository();
    auto uploads = uploadRepo.listAllByUser(user.id.toString());
    auto uploadCount = uploadRepo.countAllByUser(user.id.toString());

    Json data = Json.emptyObject;
    data["id"] = Json(user.id.toString());
    data["username"] = Json(user.username);
    data["email"] = Json(user.email);
    data["roles"] = jsonArray(user.roles);
    data["signupIp"] = Json(user.signupIp);
    data["lastLoginIp"] = Json(user.lastLoginIp);
    data["loginIps"] = jsonArray(user.loginIps);
    data["createdAt"] = Json(user.createdAt.toUnixTime());
    data["uploadCount"] = Json(uploadCount);

    Json[] netArr;
    foreach (net; networks) {
        Json n = Json.emptyObject;
        n["id"] = Json(net.id.toString());
        n["name"] = Json(net.name);
        n["host"] = Json(net.host);
        n["port"] = Json(net.port);
        n["disabled"] = Json(net.disabled);
        n["nick"] = Json(net.nick);
        n["autoJoinChannels"] = jsonArray(net.autoJoinChannels);
        n["tls"] = Json(net.tls.to!string);
        n["sasl"] = Json(net.sasl.to!string);
        auto snap = loadNetworkSnapshot(redis, net.id.toString());
        n["connected"] = Json(snap.connected);
        n["currentNick"] = Json(snap.currentNick);
        netArr ~= n;
    }
    data["networks"] = Json(netArr);

    Json[] upArr;
    foreach (upload; uploads) {
        Json u2 = Json.emptyObject;
        u2["id"] = Json(upload.id);
        u2["filename"] = Json(upload.filename);
        u2["buffer"] = Json(upload.buffer);
        u2["mimeType"] = Json(upload.mimeType);
        u2["size"] = Json(upload.size);
        u2["directUrl"] = Json(upload.directUrl);
        u2["createdAt"] = Json(upload.createdAt);
        upArr ~= u2;
    }
    data["uploads"] = Json(upArr);

    jsonOk(res, data);
}

/// POST /api/admin/users/:id — update email + roles.
package void apiUserUpdate(HTTPServerRequest req, HTTPServerResponse res) {
    import std.uuid : parseUUID;
    auto id = parseUUID(req.params["id"]);
    auto repo = new UserRepository();
    auto user = repo.findById(id);
    if (user.username.length == 0) { jsonError(res, 404, "User not found"); return; }

    auto body = readJsonBody(req);
    try {
        user.email = body["email"].get!string.strip();
        user.roles = [];
        if (auto rolesArrPtr = "roles" in body) {
            auto rolesArr = *rolesArrPtr;
            if (rolesArr.type == Json.Type.array) {
                foreach (r; rolesArr) user.roles ~= r.get!string.strip();
            }
        }
        if (user.roles.length == 0) user.roles ~= "user";
        repo.update(user);
        Json data = Json.emptyObject;
        data["id"] = Json(user.id.toString());
        data["username"] = Json(user.username);
        data["email"] = Json(user.email);
        data["roles"] = jsonArray(user.roles);
        jsonOk(res, data);
    } catch (Exception e) {
        jsonError(res, 400, e.msg);
    }
}

/// POST /api/admin/users/:id/delete
package void apiUserDelete(HTTPServerRequest req, HTTPServerResponse res,
                          RedisStorage redis, ServerRegistry serverRegistry) {
    import std.uuid : parseUUID;
    import std.file : remove;
    import std.path : buildPath;
    import ircfiber.upload.local : uploadDir;
    import ircfiber.storage.buffer : BufferManager;

    auto id = parseUUID(req.params["id"]);
    auto userRepo = new UserRepository();
    auto user = userRepo.findById(id);
    if (user.username.length == 0) { jsonError(res, 404, "User not found"); return; }
    logWarn("Admin deleting user via API: %s", user.username);

    auto db = redis.getDb();
    auto netRepo = new NetworkRepository();
    auto bufferManager = new BufferManager(redis);

    auto networks = netRepo.findByUserId(id);
    foreach (net; networks) {
        auto netId = net.id.toString();
        auto serverId = serverRegistry.getServerForNetwork(netId);
        auto msg = ControlMessage("removeNetwork", netId);
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        if (serverId.length > 0) {
            redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
            try { bufferManager.clearNetworkBuffers(serverId, netId); } catch (Exception) {}
        } else {
            redis.lpush(RedisKeys.control_legacy(), msg.toJson().toString());
            try { bufferManager.clearNetworkBuffers(netId); } catch (Exception) {}
        }
        netRepo.deleteById(net.id);
        if (serverId.length > 0) db.del(RedisKeys.state(serverId, netId));
        db.del(RedisKeys.state_legacy(netId));
        db.hdel(RedisKeys.networkAssignments(), netId);
        db.del(RedisKeys.networkFail(netId));
    }
    // Clear sessions via store (uses vibed session APIs)
    try {
        auto store = new RedisSessionStore(redis);
        auto targetUid = id.toString();
        foreach (sid; store.listAllSessionIds()) {
            auto fields = store.getSessionFields(sid);
            if (fields is null) continue;
            auto uidPtr = "sessionUserId" in fields;
            if (uidPtr) {
                import ircfiber.web.admin.helpers : stripJsonStr;
                if (stripJsonStr(*uidPtr) == targetUid) store.destroy(sid);
            }
        }
    } catch (Exception) {}
    try { db.del("prefs:" ~ id.toString()); } catch (Exception) {}
    // Hard-delete uploads
    try {
        auto uploadRepo = new UploadRepository();
        auto uploads = uploadRepo.listAllByUser(id.toString());
        foreach (upload; uploads) {
            auto url = upload.directUrl.strip;
            auto prefixPos = url.indexOf("/uploads/");
            if (prefixPos != -1) {
                auto filename = url[prefixPos + "/uploads/".length .. $];
                if (filename.length > 0) {
                    try remove(buildPath(uploadDir(), filename));
                    catch (Exception) {}
                }
            }
            try uploadRepo.hardDelete(id.toString(), upload.id);
            catch (Exception) {}
        }
    } catch (Exception) {}

    userRepo.deleteById(id);
    Json data = Json.emptyObject;
    data["deletedUserId"] = Json(id.toString());
    jsonOk(res, data);
}

/// POST /api/admin/users/:id/reset-password
package void apiResetPassword(HTTPServerRequest req, HTTPServerResponse res) {
    import std.uuid : parseUUID;
    auto id = parseUUID(req.params["id"]);
    auto body = readJsonBody(req);
    auto repo = new UserRepository();
    auto user = repo.findById(id);
    if (user.username.length == 0) { jsonError(res, 404, "User not found"); return; }
    string newPass = "changeme123";
    try if ("password" in body) newPass = body["password"].get!string.strip();
    catch (Exception) {}
    if (newPass.length == 0) newPass = "changeme123";
    user.passwordHash = hashPassword(newPass);
    repo.update(user);
    Json data = Json.emptyObject;
    data["id"] = Json(user.id.toString());
    data["passwordReset"] = Json(true);
    jsonOk(res, data);
}

// ────────────────────────────────────────────────────────────
// Sessions API
// ────────────────────────────────────────────────────────────

package void apiSessions(HTTPServerRequest req, HTTPServerResponse res, RedisStorage redis) {
    import ircfiber.web.admin.sessions : SessionInfo;
    SessionInfo[] sessions;
    long nowMs = Clock.currTime.toUnixTime!long * 1000L;
    string currentSid;
    if (req.session) currentSid = req.session.id;
    auto userRepo = new UserRepository();
    auto store = new RedisSessionStore(redis);

    try {
        auto sessionIds = store.listAllSessionIds();
        foreach (sid; sessionIds) {
            auto fields = store.getSessionFields(sid);
            if (fields is null) continue;
            auto uidPtr = "sessionUserId" in fields;
            if (!uidPtr || (*uidPtr).length == 0) continue;
            import ircfiber.web.admin.helpers : stripJsonStr, parseLongField;
            auto uid = stripJsonStr(*uidPtr);
            SessionInfo si;
            si.sessionId = sid;
            si.userId = uid;
            try {
                auto u = userRepo.findById(parseUUID(uid));
                si.username = u.username.length > 0 ? u.username : "unknown";
                si.isAdmin = u.roles.canFind("admin");
                si.roles = u.roles.join(",");
            } catch (Exception) { si.username = "unknown"; si.roles = ""; }

            auto ipPtr = "clientIp" in fields;
            if (ipPtr) si.clientIp = stripJsonStr(*ipPtr);
            auto uaPtr = "userAgent" in fields;
            if (uaPtr) si.userAgent = stripJsonStr(*uaPtr);
            auto caPtr = "createdAt" in fields;
            if (caPtr) si.createdAt = parseLongField(*caPtr);
            auto laPtr = "lastAccess" in fields;
            if (laPtr) si.lastAccess = parseLongField(*laPtr);
            si.ttlSeconds = store.sessionTtl(sid);
            si.isCurrent = currentSid.length > 0 && si.sessionId == currentSid;
            sessions ~= si;
        }
    } catch (Exception e) {
        logWarn("apiSessions read error: %s", e.msg);
    }

    int yourSessions, adminsOnline, idleCount;
    bool[string] seenUsers;
    foreach (s; sessions) {
        if (s.isCurrent) yourSessions++;
        if (s.isAdmin) adminsOnline++;
        if (!(s.userId in seenUsers)) seenUsers[s.userId] = true;
        if (s.lastAccess > 0 && (nowMs - s.lastAccess) > 3600_000L) idleCount++;
    }

    Json data = Json.emptyObject;
    data["total"] = Json(cast(long) sessions.length);
    data["uniqueUsers"] = Json(cast(long) seenUsers.length);
    data["yourSessions"] = Json(yourSessions);
    data["adminsOnline"] = Json(adminsOnline);
    data["idleCount"] = Json(idleCount);
    Json[] arr;
    foreach (s; sessions) {
        Json sj = Json.emptyObject;
        sj["sessionId"] = Json(s.sessionId);
        sj["userId"] = Json(s.userId);
        sj["username"] = Json(s.username);
        sj["clientIp"] = Json(s.clientIp);
        sj["userAgent"] = Json(s.userAgent);
        sj["createdAt"] = Json(s.createdAt);
        sj["lastAccess"] = Json(s.lastAccess);
        sj["ttlSeconds"] = Json(s.ttlSeconds);
        sj["isCurrent"] = Json(s.isCurrent);
        sj["isAdmin"] = Json(s.isAdmin);
        sj["roles"] = Json(s.roles);
        arr ~= sj;
    }
    data["sessions"] = Json(arr);
    jsonOk(res, data);
}

package void apiSessionsClear(HTTPServerRequest req, HTTPServerResponse res, RedisStorage redis) {
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
        logWarn("apiSessionsClear error: %s", e.msg);
    }
    Json data = Json.emptyObject;
    data["cleared"] = Json(cleared);
    jsonOk(res, data);
}

package void apiSessionsClearUser(HTTPServerRequest req, HTTPServerResponse res, RedisStorage redis) {
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
        logWarn("apiSessionsClearUser error: %s", e.msg);
    }
    Json data = Json.emptyObject;
    data["cleared"] = Json(cleared);
    data["targetUid"] = Json(targetUid);
    jsonOk(res, data);
}

/// POST /api/admin/sessions/clear-one/:sid
/// Delete a single session by id (one device, leaves the user's other
/// devices logged in). Refuses if the target is the current session —
/// use the explicit logout flow for that instead.
package void apiSessionsClearOne(HTTPServerRequest req, HTTPServerResponse res, RedisStorage redis) {
    auto targetSid = req.params["sid"];
    if (targetSid.length == 0 || targetSid.length > 128) {
        jsonError(res, 400, "Invalid session id");
        return;
    }
    string currentSid;
    if (req.session) currentSid = req.session.id;

    if (currentSid.length > 0 && targetSid == currentSid) {
        jsonError(res, 409, "Refusing to clear the current session — use Sign Out");
        return;
    }

    auto store = new RedisSessionStore(redis);
    try {
        auto fields = store.getSessionFields(targetSid);
        if (fields is null || fields.length == 0) {
            jsonError(res, 404, "Session not found or already expired");
            return;
        }
        store.destroy(targetSid);
        logInfo("Admin cleared single session %s", targetSid);
    } catch (Exception e) {
        logWarn("apiSessionsClearOne error for %s: %s", targetSid, e.msg);
        jsonError(res, 500, "Internal error clearing session");
        return;
    }
    Json data = Json.emptyObject;
    data["cleared"] = Json(1);
    data["sessionId"] = Json(targetSid);
    jsonOk(res, data);
}

// ────────────────────────────────────────────────────────────
// Uploads API
// ────────────────────────────────────────────────────────────

package void apiUploadsList(HTTPServerRequest req, HTTPServerResponse res) {
    import std.conv : to;
    int page = 0;
    int limit = 50;
    if (auto p = "page" in req.query) page = (*p).to!int;
    if (auto l = "limit" in req.query) limit = (*l).to!int;
    if (limit > 200) limit = 200;

    auto uploadRepo = new UploadRepository();
    auto userRepo = new UserRepository();
    auto raw = uploadRepo.listAll(page * limit, limit);
    auto total = uploadRepo.countAll();

    Json[] arr;
    foreach (r; raw) {
        Json u = Json.emptyObject;
        u["id"] = Json(r.id);
        u["userId"] = Json(r.userId);
        u["filename"] = Json(r.filename);
        u["buffer"] = Json(r.buffer);
        u["mimeType"] = Json(r.mimeType);
        u["size"] = Json(r.size);
        u["directUrl"] = Json(r.directUrl);
        u["createdAt"] = Json(r.createdAt);
        try {
            auto uid = parseUUID(r.userId);
            auto usr = userRepo.findById(uid);
            u["username"] = Json(usr.username.length > 0 ? usr.username : "unknown");
        } catch (Exception) { u["username"] = Json("unknown"); }
        arr ~= u;
    }
    Json data = Json.emptyObject;
    data["uploads"] = Json(arr);
    data["total"] = Json(total);
    data["page"] = Json(page);
    data["limit"] = Json(limit);
    jsonOk(res, data);
}

package void apiUploadDelete(HTTPServerRequest req, HTTPServerResponse res) {
    import ircfiber.db.mongo : AppMongoConnection;
    import ircfiber.db.uploads : UploadRecord;
    import std.file : remove;
    import std.path : buildPath;
    import ircfiber.upload.local : uploadDir;
    import vibe.data.bson : Bson;

    auto id = req.params["id"];
    auto coll = AppMongoConnection.getDb()["uploads"];
    auto doc = coll.findOne(Bson(["_id": Bson(id)]));
    if (!doc.isNull) {
        auto rec = UploadRecord.fromBson(doc);
        auto url = rec.directUrl.strip;
        auto prefixPos = url.indexOf("/uploads/");
        if (prefixPos != -1) {
            auto filename = url[prefixPos + "/uploads/".length .. $];
            if (filename.length > 0) {
                try remove(buildPath(uploadDir(), filename));
                catch (Exception) {}
            }
        }
        coll.deleteOne(Bson(["_id": Bson(id)]));
        logInfo("Admin deleted upload %s", id);
    }
    Json data = Json.emptyObject;
    data["deletedId"] = Json(id);
    jsonOk(res, data);
}