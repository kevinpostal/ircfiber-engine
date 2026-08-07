module ircfiber.web.admin.users;

import std.uuid : UUID, parseUUID, randomUUID;
import std.string : strip, split, join, indexOf;
import std.algorithm : canFind;
import std.array : array;
import std.file : remove;
import std.path : buildPath;
import std.datetime : Clock;

import vibe.http.server : HTTPServerRequest, HTTPServerResponse, render;
import vibe.core.log : logInfo, logWarn;

import ircfiber.auth : hashPassword;
import ircfiber.web.common : getClientIp;
import ircfiber.db.user : UserRepository;
import ircfiber.db.network : NetworkRepository;
import ircfiber.db.uploads : UploadRepository;
import ircfiber.models.user : User;
import ircfiber.models.network : NetworkConfig;
import ircfiber.redis.protocol : NetworkStateSnapshot, RedisKeys, ControlMessage;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.storage.buffer : BufferManager;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.upload.local : uploadDir;
import ircfiber.web.admin.helpers : captureSessionMeta;
import ircfiber.web.admin.servers : loadNetworkSnapshot;

/// User list — renders the diet list page.
package void adminUserList(HTTPServerRequest req, HTTPServerResponse res) {
    auto repo = new UserRepository();
    string q;
    auto pq = "q" in req.query;
    auto pf = "q" in req.form;
    if (pf) q = (*pf).strip();
    else if (pq) q = (*pq).strip();

    User[] users;
    if (q.length > 0) {
        users = repo.search(q, 200);
    } else {
        users = repo.findAll(200, 0);
    }

    res.render!("admin/users.dt", users, q)();
}

/// New user form (GET).
package void adminUserNew(HTTPServerRequest req, HTTPServerResponse res) {
    string message;
    res.render!("admin/user_new.dt", message)();
}

/// New user create (POST).
package void adminUserCreate(HTTPServerRequest req, HTTPServerResponse res) {
    auto repo = new UserRepository();
    auto username = req.form.get("username", "").strip();
    auto email = req.form.get("email", "").strip();
    auto password = req.form.get("password", "").strip();

    string message;

    if (username.length == 0 || email.length == 0 || password.length == 0) {
        message = "All fields are required";
        res.render!("admin/user_new.dt", message)();
        return;
    }

    auto existing = repo.findByUsername(username);
    if (existing.username.length > 0) {
        message = "Username already taken";
        res.render!("admin/user_new.dt", message)();
        return;
    }

    User u;
    u.id = randomUUID();
    u.username = username;
    u.email = email;
    u.passwordHash = hashPassword(password);
    u.roles = ["user"];
    u.signupIp = getClientIp(req);
    u.createdAt = Clock.currTime;

    repo.create(u);
    logInfo("Admin created new user: %s", username);
    res.redirect("/admin/users");
}

/// User detail — loads networks + uploads + live state for the side panels.
package void adminUserDetail(HTTPServerRequest req, HTTPServerResponse res,
                             RedisStorage redis, ServerRegistry serverRegistry) {
    auto repo = new UserRepository();
    auto id = parseUUID(req.params["id"]);

    auto user = repo.findById(id);
    if (user.username.length == 0) {
        res.statusCode = 404;
        res.writeBody("User not found");
        return;
    }

    auto currentUser = req.context["user"].get!User;
    auto canEdit = !(currentUser.id == user.id);
    string message;
    string rolesStr = join(user.roles, ", ");

    // Load the user's networks and their live connection state
    auto netRepo = new NetworkRepository();
    auto networks = netRepo.findByUserId(user.id);
    NetworkStateSnapshot[] snapshots;
    foreach (net; networks) {
        snapshots ~= loadNetworkSnapshot(redis, net.id.toString());
    }

    // Load the user's uploads
    auto uploadRepo = new UploadRepository();
    auto uploads = uploadRepo.listAllByUser(user.id.toString());
    auto uploadCount = uploadRepo.countAllByUser(user.id.toString());

    res.render!("admin/user_detail.dt", user, canEdit, message, rolesStr, networks, snapshots, uploads, uploadCount)();
}

/// User update (POST).
package void adminUserUpdate(HTTPServerRequest req, HTTPServerResponse res,
                             RedisStorage redis, ServerRegistry serverRegistry) {
    auto repo = new UserRepository();
    auto id = parseUUID(req.params["id"]);

    auto user = repo.findById(id);
    if (user.username.length == 0) {
        res.statusCode = 404;
        res.writeBody("User not found");
        return;
    }

    auto email = req.form.get("email", user.email).strip();
    auto rolesInput = req.form.get("roles", "").strip();

    user.email = email;
    user.roles = [];
    foreach (r; rolesInput.split(",")) {
        auto cleaned = r.strip();
        if (cleaned.length > 0) user.roles ~= cleaned;
    }
    if (user.roles.length == 0) user.roles ~= ["user"];

    auto currentUser = req.context["user"].get!User;
    auto canEdit = !(currentUser.id == user.id);

    repo.update(user);
    logInfo("Admin updated user: %s (roles: %s)", user.username, user.roles);

    string message = "User updated successfully";
    string rolesStr = join(user.roles, ", ");

    auto netRepo = new NetworkRepository();
    auto networks = netRepo.findByUserId(user.id);
    NetworkStateSnapshot[] snapshots;
    foreach (net; networks) {
        snapshots ~= loadNetworkSnapshot(redis, net.id.toString());
    }

    auto uploadRepo = new UploadRepository();
    auto uploads = uploadRepo.listAllByUser(user.id.toString());
    auto uploadCount = uploadRepo.countAllByUser(user.id.toString());

    res.render!("admin/user_detail.dt", user, canEdit, message, rolesStr, networks, snapshots, uploads, uploadCount)();
}

/// User delete — tears down networks, sessions, prefs, uploads, then the user.
package void adminUserDelete(HTTPServerRequest req, HTTPServerResponse res,
                             RedisStorage redis, ServerRegistry serverRegistry) {
    auto userRepo = new UserRepository();
    auto id = parseUUID(req.params["id"]);
    auto user = userRepo.findById(id);
    logWarn("Admin deleting user: %s (id=%s)", user.username, id);

    auto db = redis.getDb();
    auto netRepo = new NetworkRepository();
    auto bufferManager = new BufferManager(redis);

    // 1. Stop all IRC connections + delete all networks for this user
    auto networks = netRepo.findByUserId(id);
    foreach (net; networks) {
        auto netId = net.id.toString();
        auto serverId = serverRegistry.getServerForNetwork(netId);

        // Send removeNetwork control message to the engine
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

        logInfo("Cleaned up network %s (%s) for deleted user %s", net.name, netId, user.username);
    }

    // 2. Delete all Redis sessions for this user
    try {
        auto keys = db.keys("session:*");
        int cleared;
        foreach (k; keys) {
            auto key = () @trusted { return cast(string) k.idup; } ();
            auto fields = redis.hgetAll(key);
            auto uidPtr = "sessionUserId" in fields;
            if (uidPtr && *uidPtr == id.toString()) {
                db.del(key);
                cleared++;
            }
        }
        if (cleared > 0) logInfo("Cleared %d sessions for deleted user %s", cleared, user.username);
    } catch (Exception e) {
        logWarn("Session cleanup error for deleted user %s: %s", user.username, e.msg);
    }

    // 3. Delete user preferences from Redis
    try {
        db.del("prefs:" ~ id.toString());
        logInfo("Cleared preferences for deleted user %s", user.username);
    } catch (Exception e) {
        logWarn("Preferences cleanup error for deleted user %s: %s", user.username, e.msg);
    }

    // 4. Hard-delete all uploaded files and their MongoDB records
    {
        auto uploadRepo = new UploadRepository();
        auto uploads = uploadRepo.listAllByUser(id.toString());
        int fileDeleted;
        int dbDeleted;
        foreach (upload; uploads) {
            auto url = upload.directUrl.strip;
            auto uploadPrefix = "/uploads/";
            auto prefixPos = url.indexOf(uploadPrefix);
            if (prefixPos != -1) {
                auto filename = url[prefixPos + uploadPrefix.length .. $];
                if (filename.length > 0) {
                    auto filePath = buildPath(uploadDir(), filename);
                    try {
                        remove(filePath);
                        fileDeleted++;
                    } catch (Exception e) {
                        logWarn("Could not remove upload file %s for deleted user %s: %s",
                            filePath, user.username, e.msg);
                    }
                }
            } else {
                logInfo("Upload %s has remote URL %s — skipping file deletion for deleted user %s",
                    upload.id, url, user.username);
            }

            try {
                if (uploadRepo.hardDelete(id.toString(), upload.id)) dbDeleted++;
            } catch (Exception e) {
                logWarn("Failed to delete upload document %s for deleted user %s: %s",
                    upload.id, user.username, e.msg);
            }
        }
        if (uploads.length > 0) {
            logInfo("Cleaned up %d uploads for deleted user %s (files=%d, db=%d)",
                uploads.length, user.username, fileDeleted, dbDeleted);
        }
    }

    userRepo.deleteById(id);
    logWarn("User %s fully deleted (networks=%d, sessions=cleaned, prefs=cleaned)",
        user.username, networks.length);

    res.redirect("/admin/users");
}

/// Reset a user's password (defaults to "changeme123" if blank).
package void adminResetPassword(HTTPServerRequest req, HTTPServerResponse res,
                                RedisStorage redis, ServerRegistry serverRegistry) {
    auto repo = new UserRepository();
    auto id = parseUUID(req.params["id"]);
    auto user = repo.findById(id);

    auto newPass = req.form.get("password", "").strip();
    if (newPass.length == 0) newPass = "changeme123";

    user.passwordHash = hashPassword(newPass);
    repo.update(user);
    logInfo("Admin reset password for user: %s", user.username);

    auto currentUser = req.context["user"].get!User;
    auto canEdit = !(currentUser.id == user.id);

    string message = "Password reset successfully";
    string rolesStr = join(user.roles, ", ");

    auto netRepo = new NetworkRepository();
    auto networks = netRepo.findByUserId(user.id);
    NetworkStateSnapshot[] snapshots;
    foreach (net; networks) {
        snapshots ~= loadNetworkSnapshot(redis, net.id.toString());
    }

    auto uploadRepo = new UploadRepository();
    auto uploads = uploadRepo.listAllByUser(user.id.toString());
    auto uploadCount = uploadRepo.countAllByUser(user.id.toString());

    res.render!("admin/user_detail.dt", user, canEdit, message, rolesStr, networks, snapshots, uploads, uploadCount)();
}