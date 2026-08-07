module ircfiber.web.admin.servers;

import std.uuid : UUID, parseUUID;
import std.string : strip, split, replace;
import std.conv : to;
import std.uni : toLower;
import std.algorithm : canFind, filter;
import std.array : array;
import std.datetime : Clock;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse, render;
import vibe.core.log : logInfo, logWarn;
import vibe.data.json : Json, parseJson;

import ircfiber.irc.registry : ServerRegistry;
import ircfiber.irc.server : ConnectionServer;
import ircfiber.irc.manager : ConnectionManager;
import ircfiber.models.network : NetworkConfig;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.uploads : UploadRepository;
import ircfiber.db.user : UserRepository;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : NetworkStateSnapshot, RedisKeys, ControlMessage;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.web.admin.helpers : isAjax, jsonOk, jsonError;
import ircfiber.engine.bootstrap : EngineContext;

/// Detail data for a single host's connections
struct HostNetworkInfo {
    string username;
    string userId;
    string networkName;
    string networkId;
    string nick;
    bool connected;
    string status;
    string serverId;
    string host;
    bool isBanned;
    bool disabled;
}

/// Enriched assignment record shown in the Network Assignments table.
struct AssignmentRow {
    string networkId;     // UUID as string
    string serverId;      // assigned engine
    string networkName;   // user-facing label (config.name || host || id)
    string networkHost;   // IRC host (irc.libera.chat etc.)
    string userId;        // owning user (UUID as string); "" if unknown
    string username;      // owning user's display name; "" if unknown
    string nick;          // current IRC nick as reported by the engine; "" if disconnected / unknown
}

/// Network state helper — reads the latest engine snapshot from Redis for
/// a given network ID. Falls back from the server-aware key to the legacy key.
NetworkStateSnapshot loadNetworkSnapshot(RedisStorage redis, string networkId) {
    try {
        auto assignments = redis.hgetAll(RedisKeys.networkAssignments());
        auto srv = networkId in assignments;
        auto serverId = srv ? *srv : "";

        if (serverId.length > 0) {
            auto fields = redis.hgetAll(RedisKeys.state(serverId, networkId));
            if ("data" in fields) {
                return NetworkStateSnapshot.fromJson(parseJson(fields["data"]));
            }
        }

        auto fields = redis.hgetAll(RedisKeys.state_legacy(networkId));
        if ("data" in fields) {
            return NetworkStateSnapshot.fromJson(parseJson(fields["data"]));
        }
    } catch (Exception) {}

    return NetworkStateSnapshot.init;
}

/// Dashboard page — KPIs + summaries.
package void adminDashboard(HTTPServerRequest req, HTTPServerResponse res,
                            RedisStorage redis, ServerRegistry serverRegistry) {
    auto repo = new UserRepository();
    auto userCount = repo.count();
    auto recentUsers = repo.findAll(10, 0);

    // Active sessions count
    int activeSessions;
    try {
        auto db = redis.getDb();
        auto keys = db.keys("session:*");
        foreach (_; keys) activeSessions++;
    } catch (Exception) {
        activeSessions = -1;
    }

    // Upload stats
    long uploadCount;
    try {
        auto uploadRepo = new UploadRepository();
        uploadCount = uploadRepo.countAll();
    } catch (Exception) {
        uploadCount = -1;
    }

    // Server/engine stats
    auto allServers = serverRegistry.getAllServers();
    auto healthyServers = serverRegistry.getHealthyServers();
    int totalNetworks;
    foreach (s; allServers) {
        totalNetworks += s.assignedNetworks.length;
    }
    auto engineCount = cast(int) allServers.length;
    auto healthyCount = cast(int) healthyServers.length;

    // Host connection summary
    auto hostSummary = serverRegistry.getHostConnectionSummary();
    auto maxConns = serverRegistry.getMaxConnsPerHost();

    res.render!("admin/dashboard.dt",
        userCount, recentUsers,
        activeSessions, totalNetworks,
        engineCount, healthyCount,
        hostSummary, maxConns, uploadCount)();
}

/// Servers & Routing page — engines + assignments + host routing.
package void adminServers(HTTPServerRequest req, HTTPServerResponse res,
                          RedisStorage redis, ServerRegistry serverRegistry) {
    auto allServers = serverRegistry.getAllServers();
    auto healthyServers = serverRegistry.getHealthyServers();
    auto hostSummary = serverRegistry.getHostConnectionSummary();
    auto maxConns = serverRegistry.getMaxConnsPerHost();
    auto rawAssignments = serverRegistry.getAllAssignments();

    bool[string] healthyMap;
    foreach (s; healthyServers) healthyMap[s.serverId] = true;

    // Merge saved engine config overrides into server display data.
    foreach (ref s; allServers) {
        auto cfg = serverRegistry.getEngineConfig(s.serverId);
        if (cfg.priority != 0 || cfg.maxConnections != 0 || cfg.fallbackOnly) {
            if (cfg.priority != 0) s.priority = cfg.priority;
            if (cfg.maxConnections != 0) s.maxConnections = cfg.maxConnections;
            s.fallbackOnly = cfg.fallbackOnly;
        }
    }

    // Enrich raw assignments with network metadata + owner
    AssignmentRow[] assignments;
    NetworkRepository netRepo;
    UserRepository userRepo;
    try netRepo = new NetworkRepository();
    catch (Exception e) { logWarn("Could not open NetworkRepository for assignments: %s", e.msg); }
    try userRepo = new UserRepository();
    catch (Exception e) { logWarn("Could not open UserRepository for assignments: %s", e.msg); }

    foreach (a; rawAssignments) {
        AssignmentRow row;
        row.networkId = a.networkId;
        row.serverId  = a.serverId;
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
        assignments ~= row;
    }

    string message;
    auto pm = "message" in req.query;
    if (pm) message = (*pm);

    res.render!("admin/servers.dt",
        allServers, healthyMap, hostSummary,
        maxConns, assignments, message)();
}

/// Per-host detail page.
package void adminHostDetail(HTTPServerRequest req, HTTPServerResponse res,
                             RedisStorage redis, ServerRegistry serverRegistry) {
    auto host = req.params["host"];
    string message;
    auto pm = "message" in req.query;
    if (pm) message = (*pm);

    auto netRepo = new NetworkRepository();
    auto allNetworks = netRepo.findAll();

    auto hostLower = host.toLower();
    auto userRepo = new UserRepository();

    HostNetworkInfo[] connections;
    foreach (nw; allNetworks) {
        if (nw.config.host.toLower() != hostLower) continue;

        HostNetworkInfo info;
        info.networkName = nw.config.name;
        info.networkId = nw.config.id.toString();
        info.host = nw.config.host;

        auto user = userRepo.findById(nw.userId);
        info.username = user.username.length > 0 ? user.username : "unknown";
        info.userId = nw.userId.toString();

        auto netId = nw.config.id.toString();
        auto directSid = serverRegistry.getServerForNetwork(netId);
        info.serverId = directSid.length > 0 ? directSid : "unassigned";

        auto snapshot = loadNetworkSnapshot(redis, netId);
        info.connected = snapshot.connected;
        info.status = snapshot.status.length > 0 ? snapshot.status : (snapshot.connected ? "connected" : "offline");
        info.nick = snapshot.currentNick.length > 0 ? snapshot.currentNick : nw.config.nick;

        try {
            info.isBanned = redis.getDb().exists(RedisKeys.bannedNetwork(netId));
        } catch (Exception) {}

        info.disabled = nw.config.disabled;
        connections ~= info;
    }

    int[string] serverCounts;
    int liveCount;
    foreach (c; connections) {
        auto sc = c.serverId in serverCounts;
        if (sc) (*sc)++;
        else serverCounts[c.serverId] = 1;
        if (c.connected) liveCount++;
    }

    auto allServers = serverRegistry.getAllServers();
    auto maxConns = serverRegistry.getMaxConnsPerHost();

    res.render!("admin/host_detail.dt",
        host, connections, allServers, maxConns, serverCounts, liveCount, message)();
}

// ────────────────────────────────────────────────────────────
// POST handlers — engine and network assignment mutations
// ────────────────────────────────────────────────────────────

/// Disconnect a network from its engine (sets disabled flag, sends control msg).
package void adminHostDisconnectPost(HTTPServerRequest req, HTTPServerResponse res,
                                     RedisStorage redis, ServerRegistry serverRegistry) {
    auto host = req.params["host"];
    auto networkId = req.params["networkId"];

    auto netRepo = new NetworkRepository();
    auto netId = parseUUID(networkId);
    auto owner = netRepo.findByIdWithUser(netId);
    netRepo.setDisabled(netId, true);
    if (owner.userId != UUID.init)
        redis.del(RedisKeys.userNetworks(owner.userId.toString()));
    logInfo("Admin disabled network %s (persisted across redeploys)", networkId);

    auto serverId = serverRegistry.getServerForNetwork(networkId);
    const bool engineHealthy = serverId.length > 0 && serverRegistry.isServerHealthy(serverId);

    if (engineHealthy) {
        auto msg = ControlMessage("disconnectNetwork", networkId);
        msg.reason = "Disconnected by admin";
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
        logInfo("Admin disconnected network %s on server %s (host: %s)", networkId, serverId, host);
    } else {
        logWarn("Admin disconnect skipped: network %s has no healthy engine (host: %s)", networkId, host);
    }

    res.redirect("/admin/servers/host/" ~ host ~ "?message=Disconnect+requested+for+" ~ networkId);
}

/// Re-enable a disabled network.
package void adminHostReconnectPost(HTTPServerRequest req, HTTPServerResponse res,
                                    RedisStorage redis, ServerRegistry serverRegistry) {
    auto host = req.params["host"];
    auto networkIdStr = req.params["networkId"];
    auto networkId = parseUUID(networkIdStr);

    auto netRepo = new NetworkRepository();
    auto owner = netRepo.findByIdWithUser(networkId);
    netRepo.setDisabled(networkId, false);
    if (owner.userId != UUID.init)
        redis.del(RedisKeys.userNetworks(owner.userId.toString()));

    auto cfg = netRepo.findById(networkId);
    if (cfg.name.length == 0) {
        res.redirect("/admin/servers/host/" ~ host ~ "?message=Network+not+found");
        return;
    }

    auto allNetworks = netRepo.findAll();
    string ownerId;
    foreach (nw; allNetworks) {
        if (nw.config.id == networkId) {
            ownerId = nw.userId.toString();
            break;
        }
    }

    auto serverId = serverRegistry.getServerForNetwork(networkIdStr);
    if (serverId.length == 0 || !serverRegistry.isServerHealthy(serverId)) {
        serverId = serverRegistry.reassignNetwork(networkIdStr);
    }

    if (serverId.length > 0) {
        auto msg = ControlMessage("reconnectNetwork", networkIdStr, ownerId, cfg.toJson());
        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
        logInfo("Admin re-enabled network %s on server %s (host: %s)", networkIdStr, serverId, host);
    } else {
        logWarn("Admin reconnect skipped: no healthy engine for network %s (host: %s)", networkIdStr, host);
    }

    res.redirect("/admin/servers/host/" ~ host ~ "?message=Reconnect+requested+for+" ~ networkIdStr);
}

/// Permanently delete a network.
package void adminHostDeleteNetworkPost(HTTPServerRequest req, HTTPServerResponse res,
                                        RedisStorage redis, ServerRegistry serverRegistry) {
    auto host = req.params["host"];
    auto networkIdStr = req.params["networkId"];
    auto networkId = parseUUID(networkIdStr);

    auto netRepo = new NetworkRepository();
    auto cfg = netRepo.findById(networkId);
    if (cfg.name.length == 0) {
        res.redirect("/admin/servers/host/" ~ host ~ "?message=Network+not+found");
        return;
    }

    // Capture owner userId before deleting, for cache invalidation.
    auto owner = netRepo.findByIdWithUser(networkId);

    auto db = redis.getDb();
    auto bufferManager = new BufferManager(redis);

    auto serverId = serverRegistry.getServerForNetwork(networkIdStr);
    auto msg = ControlMessage("removeNetwork", networkIdStr);
    msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;

    if (serverId.length > 0) {
        redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
        try { bufferManager.clearNetworkBuffers(serverId, networkIdStr); } catch (Exception) {}
    } else {
        redis.lpush(RedisKeys.control_legacy(), msg.toJson().toString());
        try { bufferManager.clearNetworkBuffers(networkIdStr); } catch (Exception) {}
    }

    netRepo.deleteById(networkId);
    if (owner.userId != UUID.init)
        redis.del(RedisKeys.userNetworks(owner.userId.toString()));

    if (serverId.length > 0) db.del(RedisKeys.state(serverId, networkIdStr));
    db.del(RedisKeys.state_legacy(networkIdStr));
    db.hdel(RedisKeys.networkAssignments(), networkIdStr);
    db.del(RedisKeys.networkFail(networkIdStr));
    db.del(RedisKeys.bannedNetwork(networkIdStr));

    logWarn("Admin deleted network %s (%s) from host %s", cfg.name, networkIdStr, host);
    res.redirect("/admin/servers/host/" ~ host ~ "?message=Deleted+network+" ~ networkIdStr);
}

/// Reassign all networks off a given engine.
package void adminReassignServerPost(HTTPServerRequest req, HTTPServerResponse res,
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
    logInfo("Admin reassigned %d/%d networks from server %s", reassigned, networks.length, serverId);
    res.redirect("/admin/servers?message=Reassigned " ~ reassigned.to!string ~ "/" ~ networks.length.to!string ~ " networks from " ~ serverId);
}

/// Reassign one network to the best available engine.
package void adminReassignAssignmentPost(HTTPServerRequest req, HTTPServerResponse res,
                                        ServerRegistry serverRegistry) {
    auto networkId = req.params["networkId"];
    try {
        auto newSid = serverRegistry.reassignNetwork(networkId);
        if (newSid.length == 0) {
            res.redirect("/admin/servers?message=No+healthy+engine+available+for+" ~ networkId);
        } else {
            logInfo("Admin reassigned network %s to %s", networkId, newSid);
            res.redirect("/admin/servers?message=Reassigned+" ~ networkId ~ "+to+" ~ newSid);
        }
    } catch (Exception e) {
        logWarn("Admin reassign of %s failed: %s", networkId, e.msg);
        res.redirect("/admin/servers?message=Reassign+failed:+%s".replace("%s", e.msg));
    }
}

/// Clear a single assignment from Redis. JSON response for AJAX, redirect for forms.
package void adminRemoveAssignmentPost(HTTPServerRequest req, HTTPServerResponse res,
                                       RedisStorage redis, ServerRegistry serverRegistry) {
    auto networkId = req.params["networkId"];
    bool ajax = isAjax(req);

    auto oldServerId = serverRegistry.getServerForNetwork(networkId);
    if (oldServerId.length > 0) {
        try {
            auto srv = serverRegistry.getServer(oldServerId);
            srv.assignedNetworks = srv.assignedNetworks
                .filter!(n => n != networkId)
                .array;
            redis.hset(RedisKeys.server(oldServerId), "data", srv.toJson().toString());
        } catch (Exception e) {
            logWarn("Could not update server %s assignedNetworks while removing %s: %s",
                oldServerId, networkId, e.msg);
        }
    }

    auto db = redis.getDb();
    db.hdel(RedisKeys.networkAssignments(), networkId);
    db.del(RedisKeys.networkFail(networkId));
    db.del(RedisKeys.lease(networkId));

    logInfo("Admin removed assignment for network %s (was on %s)", networkId, oldServerId);

    if (ajax) {
        auto payload = Json.emptyObject;
        payload["ok"] = Json(true);
        payload["networkId"] = Json(networkId);
        payload["wasOn"] = Json(oldServerId);
        jsonOk(res, payload);
    } else {
        res.redirect("/admin/servers?message=Removed+assignment+for+" ~ networkId);
    }
}

/// Update engine priority/cap/fallback override.
package void adminEngineConfigPost(HTTPServerRequest req, HTTPServerResponse res,
                                   ServerRegistry serverRegistry) {
    auto serverId = req.params["id"];
    try {
        auto priority = req.form.get("priority", "0").strip().to!int;
        auto maxConns = req.form.get("maxConns", "0").strip().to!int;
        auto fallbackOnly = req.form.get("fallbackOnly", "false").strip() == "true";
        serverRegistry.setEngineConfig(serverId, priority, maxConns, fallbackOnly);
        res.redirect("/admin/servers?message=Updated+" ~ serverId ~ "+config");
    } catch (Exception e) {
        res.redirect("/admin/servers?message=Failed+to+update+" ~ serverId ~ ":+" ~ e.msg);
    }
}

/// Update global max-connections-per-host cap.
package void adminRoutingConfigPost(HTTPServerRequest req, HTTPServerResponse res,
                                    ServerRegistry serverRegistry) {
    auto maxConnsStr = req.form.get("maxConnsPerHost", "").strip();
    if (maxConnsStr.length > 0) {
        try {
            auto maxConns = maxConnsStr.to!int;
            serverRegistry.setMaxConnsPerHost(maxConns);
            res.redirect("/admin/servers?message=Max+connections+per+host+set+to+" ~ maxConnsStr);
            return;
        } catch (Exception) {}
    }
    res.redirect("/admin/servers?message=Invalid+value");
}