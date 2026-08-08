/**
 * DEPRECATED — Handoff removed 2026-08-08. Hard restart only.
 * See AGENTS.md Engine Lifecycle.
 */
module ircfiber.engine.exec_reload;
import std.json : JSONValue, JSONType;
import std.string : toUpper;
import std.conv : to;
import std.uuid : UUID, parseUUID;
import std.file : exists, write, readText, mkdirRecurse;
import std.path : buildPath;
import core.sys.posix.fcntl : fcntl, F_GETFD, F_SETFD, FD_CLOEXEC;
import core.sys.posix.unistd : execve, getpid;
import core.stdc.string : strlen;
import core.stdc.errno : errno;

import vibe.core.log;

import ircfiber.engine.handoff : HandoffState;

/// Marker file written by the OLD engine before calling execve(2).
/// The new engine (after exec) looks for this to know it's a post-exec
/// restart and where to find the checkpoint file.
string execReloadMarkerPath(string serverId) {
    return "/tmp/ircfiber-exec-reload-" ~ serverId ~ ".marker";
}

/// Checkpoint file path. Contains the JSON-serialized snapshot of every
/// IRC connection's state, including the FD numbers that survived the exec.
string execReloadCheckpointPath(string serverId) {
    return "/var/lib/ircfiber/reload-" ~ serverId ~ ".json";
}

/// Snapshot of the IRC state that needs to survive exec(2). One per
/// network, plus a list of FD numbers that should NOT be closed by
/// the new engine's startup code.
struct ExecReloadSnapshot {
    /// Per-network connection snapshots.
    ExecReloadRecord[] records;
    /// ISO timestamp of when the snapshot was captured.
    string capturedAt;
    /// PID of the engine that captured the snapshot.
    int capturedPid;
    /// Server ID this snapshot belongs to.
    string serverId;
    /// Path to the new binary the process was replaced with.
    string newBinaryPath;
}

/// One IRC connection's snapshot for exec-reload.
struct ExecReloadRecord {
    /// Handoff state of the connection.
    HandoffState state;
    /// Surviving file descriptor number.
    int fd;
    /// Whether the connection was TLS.
    bool wasTls;
}

/// Helper: get a string from a JSONValue object map, with a default.
private string jsonString(JSONValue[string] obj, string key, string defaultVal = "") {
    if (auto p = key in obj) {
        if (p.type == JSONType.string) return p.str;
    }
    return defaultVal;
}

/// Helper: get an integer from a JSONValue object map, with a default.
private long jsonInt(JSONValue[string] obj, string key, long defaultVal = 0) {
    if (auto p = key in obj) {
        if (p.type == JSONType.integer) return p.integer;
        if (p.type == JSONType.uinteger) return p.uinteger;
    }
    return defaultVal;
}

/// Helper: get a bool from a JSONValue object map, with a default.
private bool jsonBool(JSONValue[string] obj, string key, bool defaultVal = false) {
    if (auto p = key in obj) {
        if (p.type == JSONType.true_) return true;
        if (p.type == JSONType.false_) return false;
    }
    return defaultVal;
}

/// Serialize a snapshot to JSON.
JSONValue snapshotToJson(ref ExecReloadSnapshot snap) {
    auto root = JSONValue.emptyObject;
    root.object["serverId"] = JSONValue(snap.serverId);
    root.object["capturedAt"] = JSONValue(snap.capturedAt);
    root.object["capturedPid"] = JSONValue(snap.capturedPid);
    root.object["newBinaryPath"] = JSONValue(snap.newBinaryPath);
    auto recs = JSONValue.emptyArray;
    foreach (ref rec; snap.records) {
        auto r = JSONValue.emptyObject;
        r.object["fd"] = JSONValue(rec.fd);
        r.object["wasTls"] = JSONValue(rec.wasTls);
        r.object["networkId"] = JSONValue(rec.state.config.id.toString());
        r.object["networkName"] = JSONValue(rec.state.config.name);
        r.object["currentNick"] = JSONValue(rec.state.sessionNick);
        r.object["userId"] = JSONValue(rec.state.userId);
        r.object["isAway"] = JSONValue(rec.state.isAway);
        r.object["awayMessage"] = JSONValue(rec.state.awayMessage);
        auto caps = JSONValue.emptyArray;
        foreach (c; rec.state.ackedCaps) caps.array ~= JSONValue(c);
        r.object["ackedCaps"] = caps;
        auto queries = JSONValue.emptyArray;
        foreach (q; rec.state.queryBuffers) queries.array ~= JSONValue(q);
        r.object["queryBuffers"] = queries;
        auto channels = JSONValue.emptyObject;
        foreach (k, v; rec.state.channelState) channels.object[k] = JSONValue(v);
        r.object["channelState"] = channels;
        auto topics = JSONValue.emptyObject;
        foreach (k, v; rec.state.channelTopics) topics.object[k] = JSONValue(v);
        r.object["channelTopics"] = topics;
        auto users = JSONValue.emptyObject;
        foreach (k, arr; rec.state.channelUsers) {
            auto a = JSONValue.emptyArray;
            foreach (u; arr) a.array ~= JSONValue(u);
            users.object[k] = a;
        }
        r.object["channelUsers"] = users;
        auto rnames = JSONValue.emptyObject;
        foreach (k, v; rec.state.realnames) rnames.object[k] = JSONValue(v);
        r.object["realnames"] = rnames;
        auto parted = JSONValue.emptyArray;
        foreach (c; rec.state.config.partedChannels) parted.array ~= JSONValue(c);
        r.object["partedChannels"] = parted;
        auto sf = JSONValue.emptyObject;
        sf.object["network"] = JSONValue(rec.state.serverFeatures.network);
        sf.object["prefix"] = JSONValue(rec.state.serverFeatures.prefix);
        sf.object["chanModes"] = JSONValue(rec.state.serverFeatures.chanModes);
        sf.object["maxChannels"] = JSONValue(rec.state.serverFeatures.maxChannels);
        sf.object["maxNickLen"] = JSONValue(rec.state.serverFeatures.maxNickLen);
        sf.object["topicLen"] = JSONValue(rec.state.serverFeatures.topicLen);
        r.object["serverFeatures"] = sf;
        // Full ISUPPORT inventory (mirror of the per-network
        // handoff record). Old snapshots without this field are
        // accepted transparently — the new connection rebuilds it
        // on its first 005 reply stream, so the panel is empty
        // (not broken) for the brief window between exec and the
        // first welcome.
        if (rec.state.isupportMap.length > 0) {
            auto iso = JSONValue.emptyObject;
            foreach (k, v; rec.state.isupportMap) iso.object[k] = JSONValue(v);
            r.object["isupport"] = iso;
        }
        recs.array ~= r;
    }
    root.object["records"] = recs;
    return root;
}

/// Parse a JSON snapshot back into ExecReloadSnapshot.
ExecReloadSnapshot snapshotFromJson(JSONValue root) {
    ExecReloadSnapshot snap;
    snap.serverId = jsonString(root.object, "serverId");
    snap.capturedAt = jsonString(root.object, "capturedAt");
    snap.capturedPid = cast(int) jsonInt(root.object, "capturedPid");
    snap.newBinaryPath = jsonString(root.object, "newBinaryPath");
    if (auto recsP = "records" in root.object) {
        foreach (r; recsP.array) {
            ExecReloadRecord rec;
            rec.fd = cast(int) jsonInt(r.object, "fd", -1);
            rec.wasTls = jsonBool(r.object, "wasTls");
            rec.state.userId = jsonString(r.object, "userId");
            rec.state.sessionNick = jsonString(r.object, "currentNick");
            rec.state.isAway = jsonBool(r.object, "isAway");
            rec.state.awayMessage = jsonString(r.object, "awayMessage");
            rec.state.config.name = jsonString(r.object, "networkName");
            if (auto p = "networkId" in r.object) {
                try rec.state.config.id = parseUUID(p.str);
                catch (Exception) {}
            }
            if (auto p = "ackedCaps" in r.object)
                foreach (c; p.array) rec.state.ackedCaps ~= c.str;
            if (auto p = "queryBuffers" in r.object)
                foreach (q; p.array) rec.state.queryBuffers ~= q.str;
            if (auto p = "channelState" in r.object)
                foreach (k, v; p.object) rec.state.channelState[k] = v.str;
            if (auto p = "channelTopics" in r.object)
                foreach (k, v; p.object) rec.state.channelTopics[k] = v.str;
            if (auto p = "channelUsers" in r.object)
                foreach (k, v; p.object) {
                    string[] arr;
                    foreach (u; v.array) arr ~= u.str;
                    rec.state.channelUsers[k] = arr;
                }
            if (auto p = "realnames" in r.object)
                foreach (k, v; p.object) rec.state.realnames[k] = v.str;
            if (auto p = "partedChannels" in r.object)
                foreach (c; p.array) rec.state.config.partedChannels ~= c.str;
            if (auto p = "serverFeatures" in r.object) {
                rec.state.serverFeatures.network = jsonString(p.object, "network");
                rec.state.serverFeatures.prefix = jsonString(p.object, "prefix", "@+");
                rec.state.serverFeatures.chanModes = jsonString(p.object, "chanModes");
                rec.state.serverFeatures.maxChannels = cast(int) jsonInt(p.object, "maxChannels");
                rec.state.serverFeatures.maxNickLen = cast(int) jsonInt(p.object, "maxNickLen", 30);
                rec.state.serverFeatures.topicLen = cast(int) jsonInt(p.object, "topicLen");
            }
        // Full ISUPPORT inventory (mirror of the per-network
        // handoff record). Old snapshots without this field are
        // accepted transparently — the new connection rebuilds it
        // on its first 005 reply stream, so the panel is empty
        // (not broken) for the brief window between exec and the
        // first welcome.
        if (auto p = "isupport" in r.object) {
            auto obj = p.object;
            foreach (k, v; obj) rec.state.isupportMap[toUpper(k)] = v.str;
        }
            snap.records ~= rec;
        }
    }
    return snap;
}

/// Clear the O_CLOEXEC flag on the given FD so it survives exec(2).
/// By convention, all FDs that are NOT explicitly cleared are closed
/// by the kernel during exec.
void preserveFdAcrossExec(int fd) {
    const flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) return;
    fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
}

/// Call execve(2) to replace the current process image with `binary`.
/// Never returns on success.
void execReload(string binaryPath, string[] argv, string[] envp) {
    import std.string : toStringz;
    immutable(char)* binPtr = cast(immutable(char)*) binaryPath.toStringz();
    immutable(char)*[] argvArr = new immutable(char)*[argv.length + 1];
    foreach (i, a; argv) argvArr[i] = cast(immutable(char)*) a.toStringz();
    argvArr[argv.length] = null;
    immutable(char)*[] envpArr = new immutable(char)*[envp.length + 1];
    foreach (i, e; envp) envpArr[i] = cast(immutable(char)*) e.toStringz();
    envpArr[envp.length] = null;
    cast(void) execve(binPtr, cast(char**) argvArr.ptr, cast(char**) envpArr.ptr);
    import std.conv : to;
    throw new Exception("execve failed: errno=" ~ errno.to!string);
}