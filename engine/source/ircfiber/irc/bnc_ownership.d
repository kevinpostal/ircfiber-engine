module ircfiber.irc.bnc_ownership;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.redis.protocol : IRCCommand, RedisKeys;
import ircfiber.storage.redis : RedisStorage;
import vibe.data.json : Json, parseJsonString;
import vibe.core.core : yield;
import std.uuid : randomUUID, parseUUID;
import std.string : split, join, indexOf, startsWith;
import std.algorithm : sort;
import std.conv : to;

/// UUID routing, never a downstream label. The deadline is fixed at acceptance.
struct BncCommandOwner {
    string session, binding, request;
    long deadlineMs;
}

/// Admitted but not emitted paced traffic, retained only with its original socket.
struct BncPendingWrite {
    string line;
    BncCommandOwner owner;
    string epoch;
    string wireLabel;
}

struct MonitorStatus {
    string nick, onlineMask;
    bool online;
    string epoch;
}

/// All callbacks execute on the owning connection's serialized command fiber.
struct BncEngineHooks {
    string delegate() epoch;
    bool delegate() connected;
    bool delegate() labeled;
    bool delegate() monitorSupported;
    size_t delegate() monitorLimit;
    string delegate() ownNick;
    string delegate(string) fold;
    string[] delegate() webNicks;
    string[] delegate(string, const string[], size_t) monitorLines;
    void delegate(string) write;
    void delegate(IRCRawEvent) emit;
    void delegate(string) warning;
}

private struct Operation {
    BncCommandOwner owner;
    string id, epoch, root;
    long seq;
    bool terminal;
    Json result;
    string[] waiting;
    string group;
    string dispatchEpoch;
}
private struct OwnedBatch { string parent, operation; bool quarantined; }
private struct OwnedGroup {
    Operation response;
    string[] children;
    bool[string] dispatched;
    size_t remaining;
}
private struct MonitorLease {
    string binding;
    long revision, expiresAtMs, seq;
    string[] nicks;
}

/// Socket response ownership and the authoritative, per-network MONITOR union.
/// No fibers are spawned here: a Redis commit precedes the corresponding wire diff.
final class BncEngineState {
    private RedisStorage redis;
    private BncEngineHooks h;
    private string network, nid, uid, serverId;
    private Operation[string] operations;
    private OwnedGroup[string] groups;
    private string[string] childGroups;
    private OwnedBatch[string] batches;
    private MonitorLease[string] leases;
    private MonitorStatus[string] statuses;
    private string[string] activeUnion;
    private bool[string] unconfirmed;
    private bool restoredLeases;
    private bool busy;
    private string[] reportedWebRejection;
    private BncPendingWrite[string] retainedWrites;

    this(RedisStorage redis, string network, string nid, string uid,
            string serverId, BncEngineHooks hooks) {
        this.redis = redis; this.network = network; this.nid = nid;
        this.uid = uid; this.serverId = serverId; h = hooks;
    }

    static BncCommandOwner ownerOf(IRCCommand c) {
        return BncCommandOwner(c.bncSession, c.bncBinding, c.bncRequest, c.deadlineMs);
    }
    private static bool uuid(string s) {
        if (s.length != 36) return false;
        try { parseUUID(s); return true; } catch (Exception) { return false; }
    }
    private static bool validOwner(BncCommandOwner o) {
        return uuid(o.session) && uuid(o.binding) && uuid(o.request) && o.deadlineMs > 0;
    }
    private Json envelope(ref Operation op, string kind) {
        auto j = Json.emptyObject;
        j["nid"] = nid; j["sid"] = op.owner.session;
        j["binding"] = op.owner.binding; j["request"] = op.owner.request;
        j["operation"] = op.id; j["epoch"] = op.epoch;
        j["seq"] = ++op.seq; j["kind"] = kind;
        return j;
    }
    private void publish(Json j) {
        auto e = IRCRawEvent(network, "BNC_RESPONSE");
        e.networkId = nid; e.bncResponsePayload = j.toString(); h.emit(e);
    }
    private static Json publicTags(string encoded) {
        auto tags = parseJsonString(encoded);
        auto clean = Json.emptyObject;
        if (tags.type == Json.Type.object)
            foreach (string k, Json v; tags) if (k != "label") clean[k] = v;
        return clean;
    }
    private void line(ref Operation op, ref IRCRawEvent e) {
        if (op.terminal) return;
        if (op.group.length) {
            if (auto g = op.group in groups)
                if (e.command != "ACK") line(g.response, e);
            return;
        }
        auto j = envelope(op, "line"); auto l = Json.emptyObject;
        if (e.prefix.length) l["prefix"] = e.prefix;
        l["command"] = e.command;
        l["params"] = parseJsonString(e.paramsJson);
        l["tags"] = publicTags(e.tagsJson); j["line"] = l; publish(j);
    }
    private void complete(ref Operation op) {
        if (op.terminal) return;
        if (op.group.length) {
            op.terminal = true;
            if (auto g = op.group in groups) {
                if (g.remaining) --g.remaining;
                if (!g.remaining) complete(g.response);
            }
            return;
        }
        auto j = envelope(op, "complete");
        j["result"] = op.result.type == Json.Type.object ? op.result : Json.emptyObject;
        op.terminal = true; publish(j);
    }
    private void fail(ref Operation op, string code, string text) {
        if (op.terminal) return;
        if (op.group.length) {
            op.terminal = true;
            if (auto g = op.group in groups) fail(g.response, code, text);
            return;
        }
        auto j = envelope(op, "error"); j["code"] = code; j["text"] = text;
        if (op.result.type == Json.Type.object) j["result"] = op.result;
        op.terminal = true; publish(j);
    }
    void reject(BncCommandOwner owner, string code, string text, string operation = "", string expectedEpoch = "") {
        if (!validOwner(owner)) return;
        if (auto existing = operation in operations) {
            if (existing.owner == owner) fail(*existing, code, text);
            return;
        }
        if (auto existing = operation in groups) {
            if (existing.response.owner == owner) fail(existing.response, code, text);
            return;
        }
        if (auto parent = operation in childGroups) {
            if (auto g = *parent in groups) {
                if (g.response.owner != owner) return;
                g.dispatched[operation] = true;
                fail(g.response, code, text);
            }
            return;
        }
        Operation op; op.owner = owner;
        op.id = operation.length ? operation : "bnc-" ~ owner.request;
        op.epoch = expectedEpoch.length ? expectedEpoch : h.epoch();
        fail(op, code, text);
    }

    /// Preflight a split logical response without emitting a label or wire data.
    /// Child wire labels become active only at each child's actual writeOwned.
    bool prepareOwnedGroup(BncCommandOwner owner, string parentLabel,
            const string[] childLabels, string expectedEpoch, long nowMs) {
        if (!validOwner(owner)) return false;
        if (!parentLabel.startsWith("bnc-") || !uuid(parentLabel[4 .. $])
                || !childLabels.length || childLabels.length > 2_000) {
            reject(owner, "INVALID_COMMAND", "Invalid private operation group", parentLabel, expectedEpoch);
            return false;
        }
        if (parentLabel in groups) return false;
        bool[string] seen;
        foreach (label; childLabels) {
            if (!label.startsWith("bnc-") || !uuid(label[4 .. $]) || label == parentLabel
                    || label in seen || label in operations || label in childGroups) {
                reject(owner, "INVALID_COMMAND", "Invalid private operation group", parentLabel, expectedEpoch);
                return false;
            }
            seen[label] = true;
        }
        string code, text;
        if (expectedEpoch.length && expectedEpoch != h.epoch()) {
            code = "STALE_EPOCH"; text = "Upstream connection changed";
        } else if (owner.deadlineMs <= nowMs) {
            code = "RESPONSE_TIMEOUT"; text = "Upstream response timed out";
        } else if (!h.connected() || !h.epoch().length) {
            code = "UPSTREAM_UNAVAILABLE"; text = "No connected upstream";
        } else if (!h.labeled()) {
            code = "LABELED_RESPONSE_UNAVAILABLE"; text = "Upstream does not support labeled responses";
        }
        size_t count;
        foreach (ref op; operations)
            if (!op.terminal && !op.group.length && op.owner.session == owner.session
                    && op.owner.binding == owner.binding) ++count;
        foreach (ref g; groups)
            if (!g.response.terminal && g.response.owner.session == owner.session
                    && g.response.owner.binding == owner.binding) ++count;
        if (!code.length && count >= 256) {
            code = "TOO_MANY_PENDING"; text = "Too many outstanding labeled requests";
        }
        if (code.length) { reject(owner, code, text, parentLabel, expectedEpoch); return false; }
        OwnedGroup g; g.response.owner = owner; g.response.id = parentLabel;
        g.response.epoch = expectedEpoch.length ? expectedEpoch : h.epoch();
        g.response.dispatchEpoch = h.epoch();
        g.children = childLabels.dup; g.remaining = childLabels.length;
        groups[parentLabel] = g;
        foreach (label; childLabels) childGroups[label] = parentLabel;
        return true;
    }

    /// Trusted retained-socket adoption only: authorize exactly one captured
    /// queued write, never an arbitrary command carrying an older epoch.
    void restorePendingWrite(BncPendingWrite write) {
        if (write.owner == BncCommandOwner.init) return;
        if (!validOwner(write.owner) || !write.epoch.length || !write.line.length
                || !write.wireLabel.startsWith("bnc-") || !uuid(write.wireLabel[4 .. $]))
            throw new Exception("Invalid retained BNC write");
        retainedWrites[write.wireLabel] = write;
    }

    /// Called only at actual wire emission AFTER raw command recognition/security.
    /// Returns the private label, or empty without writing on rejection.
    string writeOwned(string wire, BncCommandOwner owner, long nowMs,
            string expectedEpoch = "", string wireLabel = "") {
        if (!validOwner(owner)) return "";
        if (wireLabel in operations) return "";
        bool retained;
        if (auto saved = wireLabel in retainedWrites) {
            retained = saved.line == wire && saved.owner == owner && saved.epoch == expectedEpoch;
            if (retained) retainedWrites.remove(wireLabel);
        }
        string group;
        if (auto parent = wireLabel in childGroups) {
            group = *parent;
            auto g = group in groups;
            if (g is null || g.response.owner != owner || wireLabel in g.dispatched) return "";
            g.dispatched[wireLabel] = true;
            if (g.response.terminal) return "";
        }
        const operation = wireLabel.length ? wireLabel : "bnc-" ~ owner.request;
        if (wireLabel.length && (!wireLabel.startsWith("bnc-") || !uuid(wireLabel[4 .. $]))) {
            reject(owner, "INVALID_COMMAND", "Invalid private operation label", operation, expectedEpoch); return "";
        }
        if (expectedEpoch.length && expectedEpoch != h.epoch() && !retained) {
            reject(owner, "STALE_EPOCH", "Upstream connection changed", operation, expectedEpoch); return "";
        }
        if (owner.deadlineMs <= nowMs) {
            reject(owner, "RESPONSE_TIMEOUT", "Upstream response timed out", operation, expectedEpoch); return "";
        }
        if (!h.connected() || !h.epoch().length) {
            reject(owner, "UPSTREAM_UNAVAILABLE", "No connected upstream", operation, expectedEpoch); return "";
        }
        if (!h.labeled()) {
            reject(owner, "LABELED_RESPONSE_UNAVAILABLE", "Upstream does not support labeled responses", operation, expectedEpoch); return "";
        }
        size_t count;
        foreach (ref op; operations) if (!op.terminal) {
            if (!op.group.length && op.owner.session == owner.session && op.owner.binding == owner.binding) ++count;
            if (!group.length && op.owner.session == owner.session && op.owner.request == owner.request)
                return ""; // Never re-execute a transferred/duplicated queue item.
        }
        foreach (ref g; groups) if (!g.response.terminal
                && g.response.owner.session == owner.session && g.response.owner.binding == owner.binding) ++count;
        if (!group.length && count >= 256) {
            reject(owner, "TOO_MANY_PENDING", "Too many outstanding labeled requests", operation, expectedEpoch); return "";
        }
        const label = wireLabel.length ? wireLabel : "bnc-" ~ randomUUID().toString();
        Operation op; op.owner = owner; op.id = label;
        op.epoch = expectedEpoch.length ? expectedEpoch : h.epoch();
        op.dispatchEpoch = h.epoch();
        op.group = group;
        operations[label] = op;
        // Existing client tags stay intact. No caller-controlled label reaches here.
        string tagged;
        if (wire.startsWith("@")) {
            const space = wire.indexOf(' ');
            if (space < 0) { fail(operations[label], "INVALID_COMMAND", "Invalid upstream command"); return ""; }
            tagged = "@label=" ~ label ~ ";" ~ wire[1 .. $];
        } else tagged = "@label=" ~ label ~ " " ~ wire;
        try h.write(tagged);
        catch (Exception) {
            fail(operations[label], "UPSTREAM_UNAVAILABLE", "No connected upstream");
            return "";
        }
        return label;
    }

    /// Observe BEFORE semantic early returns, AFTER sensitive services interception.
    /// true means private query/control output: do not fold or broadcast it.
    bool observeResponse(ref IRCRawEvent e, bool historical = false) {
        string id = e.getTag("label");
        if (id.startsWith("bnc-")) e.tagsJson = publicTags(e.tagsJson).toString();
        const parent = e.getTag("batch");
        auto bp = parent in batches;
        const params = e.getParams();
        bool ownedHistorical = bp !is null && !bp.quarantined && bp.operation.startsWith("bnc-");
        if (historical && e.command == "BATCH" && params.length && params[0].startsWith("-")) {
            if (auto closed = params[0][1 .. $] in batches)
                ownedHistorical = !closed.quarantined && closed.operation.startsWith("bnc-");
        }
        // Historical descendants of a LIVE-established owned root are still
        // part of that response. A historical standalone label cannot acquire
        // ownership or settle a current operation.
        if (historical && !ownedHistorical) return false;
        if (bp !is null && bp.operation.length && id.length && bp.operation != id) {
            bp.quarantined = true;
            return true;
        }
        if (!id.length && bp !is null) id = bp.operation;
        auto p = id in operations;
        bool closing;
        string ref_;
        if (e.command == "BATCH" && params.length && params[0].length > 1) {
            ref_ = params[0][1 .. $]; closing = params[0][0] == '-';
            if (closing) {
                if (auto b = ref_ in batches) { id = b.operation; p = id in operations; }
            } else {
                const bad = (ref_ in batches) !is null || batches.length >= 256
                    || (parent.length && bp is null) || (bp !is null && bp.quarantined);
                size_t depth; string walk = parent;
                while (walk.length && depth <= 16) {
                    auto ancestor = walk in batches;
                    if (ancestor is null) break;
                    walk = ancestor.parent; ++depth;
                }
                if (bad || depth >= 16) {
                    if (p !is null) fail(*p, "INVALID_RESPONSE", "Malformed upstream response batch");
                    if (batches.length < 256) batches[ref_] = OwnedBatch(parent, id, true);
                    return true;
                }
                batches[ref_] = OwnedBatch(parent, id, false);
                if (p !is null && !p.root.length) p.root = ref_;
            }
        }
        if (p is null) {
            const hidden = id.startsWith("bnc-") || (bp !is null && bp.quarantined);
            if (closing) {
                foreach (ref b; batches) if (b.parent == ref_) b.quarantined = true;
                batches.remove(ref_);
            }
            return hidden;
        }
        const privateOnly = e.command == "BATCH" || e.command == "ACK"
            || e.command == "FAIL" || e.command == "WARN" || e.command == "NOTE"
            || (e.command.length == 3 && e.command[0] >= '0' && e.command[0] <= '9');
        if (closing) {
            bool unclosedChild;
            foreach (ref b; batches) if (b.parent == ref_) {
                b.quarantined = true; unclosedChild = true;
            }
            if (unclosedChild) {
                fail(*p, "INVALID_RESPONSE", "Malformed upstream response batch");
                batches.remove(ref_);
                return true;
            }
        }
        if (!p.terminal && p.dispatchEpoch == h.epoch()) {
            line(*p, e);
            e.bncSession = p.owner.session; e.bncBinding = p.owner.binding; e.bncRequest = p.owner.request;
            // Remove the private label from the ordinary semantic copy.
            e.tagsJson = publicTags(e.tagsJson).toString();
            if (closing && ref_ == p.root) complete(*p);
            else if (!p.root.length && e.command != "BATCH") complete(*p);
        }
        if (closing) {
            foreach (ref b; batches) if (b.parent == ref_) b.quarantined = true;
            batches.remove(ref_);
        }
        return privateOnly;
    }

    void expireOperations(long nowMs) {
        foreach (ref g; groups) if (!g.response.terminal) {
            if (g.response.owner.deadlineMs <= nowMs)
                fail(g.response, "RESPONSE_TIMEOUT", "Upstream response timed out");
            else if (!h.connected() || g.response.dispatchEpoch != h.epoch())
                fail(g.response, "UPSTREAM_UNAVAILABLE", "No connected upstream");
            else if (!h.labeled())
                fail(g.response, "LABELED_RESPONSE_UNAVAILABLE", "Upstream does not support labeled responses");
        }
        foreach (ref op; operations) {
            if (op.terminal) continue;
            if (op.owner.deadlineMs <= nowMs) fail(op, "RESPONSE_TIMEOUT", "Upstream response timed out");
            else if (op.id == "monitor" && op.waiting.length
                    && (!h.connected() || op.dispatchEpoch != h.epoch()))
                fail(op, "UPSTREAM_UNAVAILABLE", "Monitor status is unavailable");
            else if (op.id != "monitor" && (!h.connected() || op.dispatchEpoch != h.epoch()))
                fail(op, "UPSTREAM_UNAVAILABLE", "No connected upstream");
            else if (op.id != "monitor" && !h.labeled())
                fail(op, "LABELED_RESPONSE_UNAVAILABLE", "Upstream does not support labeled responses");
        }
        // Late private labels are recognized by namespace even after their
        // completed record is released. Open ancestry stays until its close.
        foreach (key; operations.keys) if (operations[key].terminal) operations.remove(key);
        foreach (key; groups.keys) {
            auto g = &groups[key];
            if (!g.response.terminal || g.dispatched.length != g.children.length) continue;
            foreach (child; g.children) { childGroups.remove(child); operations.remove(child); }
            groups.remove(key);
        }
    }

    void tick(long nowMs) {
        expireOperations(nowMs);
        expireBncMonitorSessions(nowMs);
    }
    void newSocket(long nowMs) {
        foreach (ref g; groups) if (!g.response.terminal)
            fail(g.response, "UPSTREAM_UNAVAILABLE", "No connected upstream");
        foreach (ref op; operations) if (!op.terminal)
            fail(op, "UPSTREAM_UNAVAILABLE", "No connected upstream");
        operations = null; batches = null; statuses = null;
        groups = null; childGroups = null;
        retainedWrites = null;
        activeUnion = null; unconfirmed = null;
        expireBncMonitorSessions(nowMs);
    }

    private Json leaseJson(MonitorLease lease) {
        auto j = Json.emptyObject; j["binding"] = lease.binding;
        j["revision"] = lease.revision; j["expiresAtMs"] = lease.expiresAtMs;
        j["nicks"] = strings(lease.nicks); return j;
    }
    private static Json strings(const string[] values) {
        auto a = Json.emptyArray; foreach (v; values) a ~= Json(v); return a;
    }
    private static string[] stringArray(Json a) {
        string[] values;
        if (a.type != Json.Type.array) throw new Exception("invalid array");
        foreach (v; a) { if (v.type != Json.Type.string) throw new Exception("invalid nick"); values ~= v.get!string; }
        return values;
    }
    private MonitorLease decodeLease(string raw) {
        auto j = parseJsonString(raw); MonitorLease l;
        l.binding = j["binding"].get!string; l.revision = j["revision"].get!long;
        l.expiresAtMs = j["expiresAtMs"].get!long; l.nicks = stringArray(j["nicks"]);
        if (!uuid(l.binding) || l.revision < 0 || l.nicks.length > 100) throw new Exception("invalid lease");
        return l;
    }
    /// Owner+assignment fenced CAS. Redis I/O may yield; no in-memory state changes before success.
    private bool commit(string sid, string previous, string next) {
        auto r = redis.getDb().eval!string(
            "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 then return '0' end "
            ~ "if (redis.call('HGET',KEYS[3],ARGV[3]) or '') ~= ARGV[4] then return '0' end "
            ~ "if ARGV[5] == '' then redis.call('HDEL',KEYS[3],ARGV[3]) else redis.call('HSET',KEYS[3],ARGV[3],ARGV[5]) end return '1'",
            [RedisKeys.networkAssignments(), RedisKeys.routingMove(nid), RedisKeys.bncMonitorSessions(nid)],
            [nid, serverId, sid, previous, next]);
        return !r.empty && r.front == "1";
    }
    private bool presenceValid(string sid, long nowMs) {
        string[] ids;
        foreach (v; redis.getDb().smembers(RedisKeys.bncClients())) ids ~= v.idup;
        foreach (id; ids) {
            const raw = redis.getDb().get(RedisKeys.bncClient(id));
            if (!raw.length) continue;
            try {
                auto j = parseJsonString(raw);
                if (j["holderSessionId"].type != Json.Type.string || j["holderSessionId"].get!string != sid) continue;
                const stamp = j["updatedAtMs"].get!long;
                return j["userId"].get!string == uid && j["networkId"].get!string == nid
                    && stamp <= nowMs + 5_000 && nowMs - stamp <= 60_000;
            } catch (Exception) {}
        }
        return false;
    }
    private void restoreLeases(long nowMs) {
        if (restoredLeases) return;
        if (redis is null) { restoredLeases = true; return; }
        string[] fields;
        MonitorLease[string] loaded;
        foreach (v; redis.getDb().hkeys(RedisKeys.bncMonitorSessions(nid))) fields ~= v.idup;
        foreach (sid; fields) {
            const raw = redis.getDb().hget(RedisKeys.bncMonitorSessions(nid), sid);
            try {
                auto l = decodeLease(raw);
                if (uuid(sid) && l.expiresAtMs > nowMs) {
                    if (auto old = sid in leases)
                        if (old.binding == l.binding) l.seq = old.seq;
                    loaded[sid] = l;
                }
                else commit(sid, raw, "");
            } catch (Exception) { commit(sid, raw, ""); }
        }
        leases = loaded;
        restoredLeases = true;
    }
    private bool validNick(string n) {
        if (!n.length || n.length > 128 || n[0] == ':' || n[0] == '#') return false;
        foreach (ubyte c; cast(const(ubyte)[])n)
            if (c <= 32 || c == 127 || c == ',' || c == '!' || c == '@') return false;
        return true;
    }
    private string[] unique(const string[] nicks) {
        bool[string] seen; string[] result;
        foreach (n; nicks) if (validNick(n) && h.fold(n) !in seen) { seen[h.fold(n)] = true; result ~= n; }
        return result;
    }
    private void pruneLeases(long nowMs) {
        foreach (sid; leases.keys) if (leases[sid].expiresAtMs <= nowMs) {
            const raw = redis.getDb().hget(RedisKeys.bncMonitorSessions(nid), sid);
            if (commit(sid, raw, "")) leases.remove(sid);
        }
    }

    private void notifyLeaseChange(string sid, MonitorLease l, string[] rejected) {
        bool pendingOwner;
        bool[string] removed;
        foreach (n; rejected) removed[h.fold(n)] = true;
        foreach (ref pending; operations) {
            if (pending.id != "monitor" || pending.terminal
                    || pending.owner.session != sid || pending.owner.binding != l.binding) continue;
            pendingOwner = true;
            string[] allRejected;
            if (pending.result.type == Json.Type.object && pending.result["rejected"].type == Json.Type.array)
                allRejected = stringArray(pending.result["rejected"]);
            allRejected ~= rejected;
            pending.result = result(l, unique(allRejected));
            full(pending, rejected);
            string[] waiting;
            foreach (n; pending.waiting) if (n !in removed) waiting ~= n;
            pending.waiting = waiting;
            if (!waiting.length) complete(pending);
        }
        if (pendingOwner) return;
        Operation op; op.id = "monitor_update"; op.epoch = h.epoch();
        op.owner = BncCommandOwner(sid, l.binding, "", 0); op.seq = l.revision - 1;
        op.result = result(l, rejected); complete(op);
    }

    private Json result(MonitorLease l, string[] rejected = null) {
        auto j = Json.emptyObject; j["revision"] = l.revision;
        j["nicks"] = strings(l.nicks); j["rejected"] = strings(rejected); return j;
    }
    private void numeric(ref Operation op, string code, string[] params) {
        auto e = IRCRawEvent(network, code);
        e.setParams(params); line(op, e);
    }
    private void full(ref Operation op, string[] rejected) {
        if (rejected.length) numeric(op, "734", [h.ownNick(), to!string(h.monitorLimit() ? h.monitorLimit() : 100), rejected.join(","), "Monitor list is full."]);
    }
    private bool statusLine(ref Operation op, string nick) {
        auto p = h.fold(nick) in statuses;
        if (p is null || p.epoch != h.epoch() || !h.connected()) return false;
        numeric(op, p.online ? "730" : "731", [h.ownNick(), p.online ? p.onlineMask : p.nick]); return true;
    }
    private string monitorKey(BncCommandOwner o) { return "monitor:" ~ o.session ~ ":" ~ o.request; }

    void handleBncMonitor(IRCCommand c, long nowMs) {
        auto owner = ownerOf(c);
        if (!validOwner(owner)) return;
        if (redis is null) {
            reject(owner, "MONITOR_UNAVAILABLE", "Monitor state is unavailable", "monitor");
            return;
        }
        while (busy) yield();
        busy = true; scope(exit) busy = false;
        Operation op; op.id = "monitor"; op.owner = owner; op.epoch = h.epoch();
        op.dispatchEpoch = h.epoch();
        try {
            auto payload = parseJsonString(c.bncPayload);
            if (payload["epoch"].type == Json.Type.string && payload["epoch"].get!string.length)
                op.epoch = payload["epoch"].get!string;
            if (c.userId != uid) { fail(op, "STALE_BINDING", "Monitor binding is no longer active"); return; }
            if (owner.deadlineMs <= nowMs) { fail(op, "RESPONSE_TIMEOUT", "Upstream response timed out"); return; }
            restoreLeases(nowMs);
            pruneLeases(nowMs);
            const key = RedisKeys.bncMonitorSessions(nid);
            const raw = redis.getDb().hget(key, owner.session);
            MonitorLease old; bool exists;
            if (raw.length) { old = decodeLease(raw); exists = old.expiresAtMs > nowMs; }
            const verb = payload["verb"].get!string;
            const revision = payload["revision"].get!long;
            auto requested = unique(stringArray(payload["nicks"]));
            if (verb != "+" && verb != "-" && verb != "C" && verb != "L" && verb != "S"
                    && verb != "replace" && verb != "detach" && verb != "refresh") {
                fail(op, "INVALID_COMMAND", "Invalid monitor command"); return;
            }
            const creating = verb == "replace" && revision == 0;
            if (creating) {
                if ((exists && old.binding != owner.binding) || !presenceValid(owner.session, nowMs)) {
                    fail(op, "STALE_BINDING", "Monitor binding is no longer active"); return;
                }
                // Replaying initial admission is idempotent, never reset an existing list.
                if (exists && old.binding == owner.binding) { op.result = result(old); complete(op); return; }
            } else if (!exists || old.binding != owner.binding) {
                fail(op, "STALE_BINDING", "Monitor binding is no longer active"); return;
            }
            const mutation = verb == "+" || verb == "-" || verb == "C" || verb == "replace";
            if (!creating && verb != "detach" && revision != old.revision + (mutation ? 1 : 0)) {
                fail(op, "STALE_REVISION", "Monitor revision is no longer current"); return;
            }
            if (payload["epoch"].type == Json.Type.string && payload["epoch"].get!string.length
                    && payload["epoch"].get!string != h.epoch()) {
                fail(op, "STALE_EPOCH", "Upstream connection changed"); return;
            }
            if (verb == "detach") {
                if (!commit(owner.session, raw, "")) { fail(op, "STALE_BINDING", "Monitor binding is no longer active"); return; }
                leases.remove(owner.session); old.nicks = null; op.result = result(old); complete(op); reconcileMonitorUnionImpl(); return;
            }
            auto next = old; next.binding = owner.binding; next.expiresAtMs = nowMs + 60_000;
            string[] rejected, accepted;
            if ((verb == "+" || verb == "S" || (verb == "replace" && requested.length))
                    && (!h.connected() || !h.monitorSupported())) {
                fail(op, !h.monitorSupported() ? "MONITOR_UNAVAILABLE" : "UPSTREAM_UNAVAILABLE", "Monitor status is unavailable"); return;
            }
            if (verb == "replace") next.nicks = null;
            if (verb == "C") next.nicks = null;
            if (verb == "-") {
                bool[string] remove; foreach (n; requested) remove[h.fold(n)] = true;
                next.nicks = null; foreach (n; old.nicks) if (h.fold(n) !in remove) next.nicks ~= n;
            }
            if (verb == "+" || verb == "replace") {
                bool[string] union_; foreach (n; h.webNicks()) union_[h.fold(n)] = true;
                foreach (sid, l; leases) if (sid != owner.session && l.expiresAtMs > nowMs)
                    foreach (n; l.nicks) union_[h.fold(n)] = true;
                foreach (n; next.nicks) union_[h.fold(n)] = true;
                bool[string] own; foreach (n; next.nicks) own[h.fold(n)] = true;
                foreach (n; requested) {
                    const folded = h.fold(n);
                    if (folded in own) { accepted ~= n; continue; }
                    if (!h.monitorSupported() || next.nicks.length >= 100
                            || (h.monitorLimit() && folded !in union_ && union_.length >= h.monitorLimit())) { rejected ~= n; continue; }
                    if (!h.connected() && folded !in statuses) { fail(op, "UPSTREAM_UNAVAILABLE", "No connected upstream"); return; }
                    next.nicks ~= n; accepted ~= n; own[folded] = true; union_[folded] = true;
                }
            }
            if ((verb == "+" || verb == "S") && (!h.connected() || !h.monitorSupported())) {
                fail(op, !h.monitorSupported() ? "MONITOR_UNAVAILABLE" : "UPSTREAM_UNAVAILABLE", "Monitor status is unavailable"); return;
            }
            if (mutation) next.revision = revision;
            if (!commit(owner.session, raw, leaseJson(next).toString())) {
                fail(op, "STALE_BINDING", "Monitor binding is no longer active"); return;
            }
            leases[owner.session] = next; op.result = result(next, rejected);
            // Install waiter BEFORE MONITOR + can synchronously deliver initial state.
            if (verb == "+" || verb == "S" || (verb == "replace" && accepted.length)) {
                auto targets = verb == "S" ? next.nicks : accepted;
                foreach (n; targets) if (!statusLine(op, n)) op.waiting ~= h.fold(n);
            }
            if (verb == "L") {
                if (next.nicks.length) numeric(op, "732", [h.ownNick(), next.nicks.join(",")]);
                numeric(op, "733", [h.ownNick(), "End of MONITOR list"]);
            }
            full(op, rejected);
            const operationKey = monitorKey(owner);
            operations[operationKey] = op;
            reconcileMonitorUnionImpl();
            auto pending = operationKey in operations;
            if (pending !is null && !pending.terminal) {
                if (!pending.waiting.length) complete(*pending);
                else h.write("MONITOR S");
            }
        } catch (Exception) {
            if (auto pending = monitorKey(owner) in operations)
                fail(*pending, "UPSTREAM_UNAVAILABLE", "Monitor state is unavailable");
            else fail(op, "UPSTREAM_UNAVAILABLE", "Monitor state is unavailable");
        }
    }

    void expireBncMonitorSessions(long nowMs) {
        if (redis is null) return;
        if (busy) return;
        busy = true; scope(exit) busy = false;
        restoreLeases(nowMs);
        pruneLeases(nowMs);
        reconcileMonitorUnionImpl();
    }

    /// Web interests first, then stable holder UUID/list order. The persisted web
    /// desired list is never truncated when the upstream capacity shrinks.
    void reconcileMonitorUnion() {
        if (redis is null) return;
        if (busy) return;
        busy = true; scope(exit) busy = false;
        reconcileMonitorUnionImpl();
    }

    private void reconcileMonitorUnionImpl() {
        string[string] desired;
        const limit = h.monitorLimit();
        string[] rejectedWeb;
        foreach (n; h.webNicks()) {
            const key = h.fold(n);
            if (key in desired) continue;
            if (limit && desired.length >= limit) rejectedWeb ~= n;
            else desired[key] = n;
        }
        if (rejectedWeb != reportedWebRejection) {
            reportedWebRejection = rejectedWeb.dup;
            if (rejectedWeb.length && h.warning !is null)
                h.warning("MONITOR capacity rejected web targets: " ~ rejectedWeb.join(","));
        }
        auto sids = leases.keys; sort(sids);
        foreach (sid; sids) {
            auto l = leases[sid]; string[] kept, rejected;
            foreach (n; l.nicks) {
                const key = h.fold(n);
                if (key !in desired && limit && desired.length >= limit) rejected ~= n;
                else { desired[key] = n; kept ~= n; }
            }
            if (rejected.length) {
                const previous = redis.getDb().hget(RedisKeys.bncMonitorSessions(nid), sid);
                l.nicks = kept; ++l.revision;
                if (!commit(sid, previous, leaseJson(l).toString())) continue;
                leases[sid] = l;
                notifyLeaseChange(sid, l, rejected);
            }
        }
        if (!h.connected() || !h.monitorSupported()) return;
        string[] removed, added;
        foreach (k, n; activeUnion) if (k !in desired) removed ~= n;
        foreach (k, n; desired) if (k !in activeUnion) { added ~= n; unconfirmed[k] = true; }
        foreach (wire; h.monitorLines("-", removed, limit)) h.write(wire);
        foreach (wire; h.monitorLines("+", added, limit)) h.write(wire);
        activeUnion = desired;
    }

    /// Returns true for union-only numerics that MUST NOT reach generic fanout.
    /// 730/731 ordinary copies contain only web-persisted interests.
    bool observeMonitorNumeric(ref IRCRawEvent e) {
        while (busy) yield();
        busy = true; scope(exit) busy = false;
        const p = e.getParams();
        if (e.command == "732" || e.command == "733") return true;
        if (e.command == "734") {
            if (p.length >= 3) foreach (mask; p[2].split(",")) {
                const k = h.fold(mask);
                if (k !in unconfirmed) continue;
                unconfirmed.remove(k); activeUnion.remove(k);
                foreach (sid; leases.keys) {
                    auto l = leases[sid]; string[] kept, rejected;
                    foreach (n; l.nicks) { if (h.fold(n) == k) rejected ~= n; else kept ~= n; }
                    if (!rejected.length) continue;
                    const raw = redis.getDb().hget(RedisKeys.bncMonitorSessions(nid), sid);
                    l.nicks = kept; ++l.revision;
                    if (commit(sid, raw, leaseJson(l).toString())) {
                        leases[sid] = l;
                        notifyLeaseChange(sid, l, rejected);
                    }
                }
            }
            return true;
        }
        if (e.command != "730" && e.command != "731") return false;
        if (p.length < 2) return false;
        bool[string] web;
        foreach (nick; h.webNicks()) web[h.fold(nick)] = true;
        string[] webMasks;
        foreach (mask; p[1].split(",")) {
            const bang = mask.indexOf('!'); const nick = bang < 0 ? mask : mask[0 .. bang];
            const key = h.fold(nick); if (!key.length) continue;
            if (key in web) webMasks ~= mask;
            MonitorStatus value = MonitorStatus(nick, e.command == "730" ? mask : "", e.command == "730", h.epoch());
            auto old = key in statuses;
            const changed = old is null || old.epoch != value.epoch || old.online != value.online || old.onlineMask != value.onlineMask;
            statuses[key] = value; unconfirmed.remove(key);
            bool[string] initialOwners;
            foreach (ref op; operations) if (op.id == "monitor" && !op.terminal) {
                string[] remaining; bool answered;
                foreach (waiting; op.waiting) { if (waiting == key) answered = true; else remaining ~= waiting; }
                if (!answered) continue;
                initialOwners[op.owner.session] = true; statusLine(op, nick); op.waiting = remaining;
                if (!remaining.length) complete(op);
            }
            if (!changed) continue;
            foreach (sid; leases.keys) {
                auto l = &leases[sid]; bool interested;
                foreach (n; l.nicks) if (h.fold(n) == key) { interested = true; break; }
                if (!interested || sid in initialOwners) continue;
                Operation op; op.id = "monitor_presence"; op.epoch = h.epoch();
                op.owner = BncCommandOwner(sid, l.binding, "", 0); op.seq = l.seq;
                numeric(op, e.command, [h.ownNick(), value.online ? value.onlineMask : value.nick]); l.seq = op.seq;
            }
        }
        if (!webMasks.length) return true;
        auto webParams = p.dup;
        webParams[1] = webMasks.join(",");
        e.setParams(webParams);
        if (p.length == 2) e.text = webParams[1];
        return false;
    }

    /// Call once per live AWAY/ACCOUNT/CHGHOST/SETNAME before roster mutation.
    void publishPresence(ref IRCRawEvent e, string[] sharedChannels, bool historical) {
        if (historical || (e.command != "AWAY" && e.command != "ACCOUNT"
                && e.command != "CHGHOST" && e.command != "SETNAME")) return;
        auto j = Json.emptyObject; j["nid"] = nid;
        auto v = Json.emptyObject; v["c"] = e.command; v["n"] = e.nick;
        v["px"] = e.prefix; v["p"] = parseJsonString(e.paramsJson);
        j["event"] = v; j["sharedChannels"] = strings(sharedChannels);
        auto out_ = IRCRawEvent(network, "BNC_PRESENCE"); out_.networkId = nid;
        out_.bncPresencePayload = j.toString(); h.emit(out_);
    }

    /// Complete semantic handoff, including terminal quarantine and all ancestors.
    string snapshot() {
        auto j = Json.emptyObject; j["version"] = 1;
        auto ops = Json.emptyObject;
        foreach (key, op; operations) {
            auto v = Json.emptyObject;
            v["sid"] = op.owner.session; v["binding"] = op.owner.binding;
            v["request"] = op.owner.request; v["deadlineMs"] = op.owner.deadlineMs;
            v["id"] = op.id; v["epoch"] = op.epoch; v["root"] = op.root;
            v["seq"] = op.seq; v["terminal"] = op.terminal;
            v["result"] = op.result.type == Json.Type.object ? op.result : Json.emptyObject;
            v["group"] = op.group;
            v["waiting"] = strings(op.waiting); ops[key] = v;
        }
        j["operations"] = ops;
        auto gs = Json.emptyObject;
        foreach (key, g; groups) {
            auto v = Json.emptyObject; auto op = g.response;
            v["sid"] = op.owner.session; v["binding"] = op.owner.binding;
            v["request"] = op.owner.request; v["deadlineMs"] = op.owner.deadlineMs;
            v["epoch"] = op.epoch; v["seq"] = op.seq; v["terminal"] = op.terminal;
            v["children"] = strings(g.children); v["dispatched"] = strings(g.dispatched.keys);
            v["remaining"] = cast(long)g.remaining; gs[key] = v;
        }
        j["groups"] = gs;
        auto bs = Json.emptyObject;
        foreach (key, b; batches) {
            auto v = Json.emptyObject; v["parent"] = b.parent;
            v["operation"] = b.operation; v["quarantined"] = b.quarantined; bs[key] = v;
        }
        j["batches"] = bs;
        auto ls = Json.emptyObject;
        foreach (sid, l; leases) { auto v = leaseJson(l); v["seq"] = l.seq; ls[sid] = v; }
        j["leases"] = ls;
        auto ss = Json.emptyObject;
        foreach (key, s; statuses) {
            auto v = Json.emptyObject; v["nick"] = s.nick; v["onlineMask"] = s.onlineMask;
            v["online"] = s.online; v["epoch"] = s.epoch; ss[key] = v;
        }
        j["statuses"] = ss;
        auto union_ = Json.emptyObject; foreach (k, n; activeUnion) union_[k] = n;
        j["activeUnion"] = union_; j["unconfirmed"] = strings(unconfirmed.keys);
        return j.toString();
    }
    /// Restore only for the retained socket, before reading attach backlog.
    /// Malformed state fails closed; caller must abort retained-socket adoption.
    void restore(string payload) {
        if (!payload.length) return;
        auto j = parseJsonString(payload);
        if (j["version"].get!int != 1) throw new Exception("incompatible BNC engine ownership");
        Operation[string] nextOps; OwnedBatch[string] nextBatches;
        foreach (string key, Json v; j["operations"]) {
            Operation op; op.owner = BncCommandOwner(v["sid"].get!string, v["binding"].get!string,
                v["request"].get!string, v["deadlineMs"].get!long);
            if (!validOwner(op.owner)) throw new Exception("invalid BNC operation owner");
            op.id = v["id"].get!string; op.epoch = v["epoch"].get!string;
            op.dispatchEpoch = h.epoch();
            op.root = v["root"].get!string; op.seq = v["seq"].get!long;
            op.terminal = v["terminal"].get!bool; op.result = v["result"];
            op.waiting = stringArray(v["waiting"]); nextOps[key] = op;
            if (v["group"].type == Json.Type.string) nextOps[key].group = v["group"].get!string;
        }
        OwnedGroup[string] nextGroups;
        string[string] nextChildren;
        if (j["groups"].type != Json.Type.undefined) foreach (string key, Json v; j["groups"]) {
            OwnedGroup g;
            g.response.owner = BncCommandOwner(v["sid"].get!string, v["binding"].get!string,
                v["request"].get!string, v["deadlineMs"].get!long);
            if (!validOwner(g.response.owner)) throw new Exception("Invalid BNC group owner");
            g.response.id = key; g.response.epoch = v["epoch"].get!string;
            g.response.dispatchEpoch = h.epoch();
            g.response.seq = v["seq"].get!long; g.response.terminal = v["terminal"].get!bool;
            g.children = stringArray(v["children"]);
            const remaining = v["remaining"].get!long;
            if (remaining < 0 || remaining > g.children.length || !g.children.length || g.children.length > 2_000)
                throw new Exception("Invalid BNC group progress");
            g.remaining = cast(size_t)remaining;
            foreach (child; g.children) {
                if (child in nextChildren || !child.startsWith("bnc-") || !uuid(child[4 .. $]))
                    throw new Exception("Invalid BNC child operation");
                nextChildren[child] = key;
            }
            foreach (child; stringArray(v["dispatched"])) {
                if (nextChildren.get(child, "") != key) throw new Exception("Invalid BNC child progress");
                g.dispatched[child] = true;
            }
            nextGroups[key] = g;
        }
        foreach (key, op; nextOps) if (op.group.length) {
            if (op.group !in nextGroups || nextChildren.get(key, "") != op.group)
                throw new Exception("Missing BNC operation group");
        }
        foreach (string key, Json v; j["batches"]) {
            if (nextBatches.length >= 256) throw new Exception("too many BNC batches");
            nextBatches[key] = OwnedBatch(v["parent"].get!string, v["operation"].get!string, v["quarantined"].get!bool);
        }
        foreach (key, b; nextBatches) {
            string walk = b.parent; size_t depth;
            bool[string] seen;
            while (walk.length) {
                if (walk == key || walk in seen || ++depth > 16)
                    throw new Exception("Invalid BNC batch ancestry");
                seen[walk] = true;
                auto ancestor = walk in nextBatches;
                if (ancestor is null) {
                    if (!b.quarantined) throw new Exception("Missing BNC batch parent");
                    break;
                }
                walk = ancestor.parent;
            }
        }
        foreach (string sid, Json v; j["leases"]) {
            auto l = decodeLease(v.toString()); l.seq = v["seq"].get!long; leases[sid] = l;
        }
        foreach (string key, Json v; j["statuses"])
            statuses[key] = MonitorStatus(v["nick"].get!string, v["onlineMask"].get!string,
                v["online"].get!bool, h.epoch());
        foreach (string key, Json v; j["activeUnion"]) activeUnion[key] = v.get!string;
        foreach (key; stringArray(j["unconfirmed"])) unconfirmed[key] = true;
        operations = nextOps; batches = nextBatches;
        groups = nextGroups; childGroups = nextChildren;
        // Redis remains authoritative; restoreLeases checks lease expiry on first tick.
        restoredLeases = false;
    }
}

/// Callable from the standalone connection protocol registry; performs no I/O.
void runBncOwnershipProtocolChecks() {
    import std.uni : toLower;
    string[] writes;
    Json[] replies;
    Json[] presences;
    string epoch = "socket-1";
    BncEngineHooks hooks;
    hooks.epoch = () => epoch;
    hooks.connected = () => true;
    hooks.labeled = () => true;
    hooks.write = (string s) { writes ~= s; };
    hooks.emit = (IRCRawEvent e) {
        if (e.bncResponsePayload.length) replies ~= parseJsonString(e.bncResponsePayload);
        else if (e.bncPresencePayload.length) presences ~= parseJsonString(e.bncPresencePayload);
    };
    hooks.fold = (string s) => s.toLower();
    auto state = new BncEngineState(null, "test", "network", "owner", "engine", hooks);
    auto owner = BncCommandOwner("11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333", 30_000);
    auto label = state.writeOwned("WHO #test", owner, 1, epoch);
    assert(label.startsWith("bnc-") && writes.length == 1);
    assert(writes[0] == "@label=" ~ label ~ " WHO #test");
    IRCRawEvent event(string command, string[] params, string label_ = "", string batch = "") {
        auto e = IRCRawEvent("test", command); e.setParams(params);
        if (label_.length) e.addTag("label", label_);
        if (batch.length) e.addTag("batch", batch);
        return e;
    }
    auto open = event("BATCH", ["+outer", "labeled-response"], label);
    assert(state.observeResponse(open));
    auto inner = event("BATCH", ["+inner", "chathistory", "#test"], "", "outer");
    assert(state.observeResponse(inner, true));
    // Preserve arbitrary ancestry through retained-socket adoption.
    auto adopted = new BncEngineState(null, "test", "network", "owner", "engine", hooks);
    epoch = "socket-2";
    adopted.restore(state.snapshot());
    const beforeHistoricalLabel = replies.length;
    auto forged = event("315", ["me", "#test", "Historical end"], label);
    assert(!adopted.observeResponse(forged, true));
    assert(replies.length == beforeHistoricalLabel);
    auto member = event("FAIL", ["WHO", "TRY_AGAIN", "Safe failure"], "", "inner");
    assert(adopted.observeResponse(member, true));
    assert(replies[$ - 1]["kind"].get!string == "line");
    auto innerClose = event("BATCH", ["-inner"]);
    assert(adopted.observeResponse(innerClose, true));
    assert(replies[$ - 1]["kind"].get!string == "line");
    auto outerClose = event("BATCH", ["-outer"]);
    assert(adopted.observeResponse(outerClose));
    assert(replies[$ - 1]["kind"].get!string == "complete");
    foreach (i, reply; replies) assert(reply["seq"].get!long == i + 1);
    assert(replies[$ - 1]["epoch"].get!string == "socket-1",
        "retained adoption must preserve the accepted response epoch");
    const completed = replies.length;
    adopted.expireOperations(30_001);
    auto late = event("315", ["me", "#test", "End"], label);
    assert(adopted.observeResponse(late) && replies.length == completed);
    owner.request = "44444444-4444-4444-8444-444444444444";
    adopted.writeOwned("WHO #other", owner, 1, epoch);
    adopted.expireOperations(30_001);
    assert(replies[$ - 1]["kind"].get!string == "error");
    assert(replies[$ - 1]["code"].get!string == "RESPONSE_TIMEOUT");

    owner.request = "55555555-5555-4555-8555-555555555555";
    auto groupState = new BncEngineState(null, "test", "network", "owner", "engine", hooks);
    const parentLabel = "bnc-" ~ randomUUID().toString();
    const children = ["bnc-" ~ randomUUID().toString(), "bnc-" ~ randomUUID().toString()];
    const beforePrepare = writes.length;
    assert(groupState.prepareOwnedGroup(owner, parentLabel, children, epoch, 1));
    assert(writes.length == beforePrepare, "group preparation must not write");
    assert(groupState.writeOwned("PRIVMSG nick :one", owner, 1, epoch, children[0]) == children[0]);
    const groupReplies = replies.length;
    auto ack = event("ACK", [], children[0]);
    assert(groupState.observeResponse(ack));
    assert(replies.length == groupReplies, "child-only ACK must not finish the parent");
    const acceptedEpoch = epoch;
    const capturedGroup = groupState.snapshot();
    epoch = "socket-3";
    auto transferred = new BncEngineState(null, "test", "network", "owner", "engine", hooks);
    transferred.restore(capturedGroup);
    auto pendingWrite = BncPendingWrite("PRIVMSG nick :two", owner, acceptedEpoch, children[1]);
    transferred.restorePendingWrite(pendingWrite);
    assert(transferred.writeOwned(pendingWrite.line, owner, 1, acceptedEpoch, children[1]) == children[1]);
    auto echo = event("PRIVMSG", ["nick", "two"], children[1]);
    assert(!transferred.observeResponse(echo));
    assert(replies.length == groupReplies + 2);
    assert(replies[$ - 2]["kind"].get!string == "line");
    assert(replies[$ - 1]["kind"].get!string == "complete");
    foreach (r; replies[groupReplies .. $]) {
        assert(r["operation"].get!string == parentLabel);
        assert(r["epoch"].get!string == acceptedEpoch);
    }
    assert(replies[$ - 2]["seq"].get!long == 1 && replies[$ - 1]["seq"].get!long == 2);
    owner.request = "66666666-6666-4666-8666-666666666666";
    transferred.writeOwned("WHO #unrelated", owner, 1, acceptedEpoch, "bnc-" ~ randomUUID().toString());
    assert(replies[$ - 1]["code"].get!string == "STALE_EPOCH",
        "retained admission must not authorize an unrelated old-epoch command");
    auto away = event("AWAY", ["Gone"]);
    away.nick = "watched"; away.prefix = "watched!user@host";
    transferred.publishPresence(away, [], true);
    assert(presences.length == 0);
    transferred.publishPresence(away, [], false);
    assert(presences.length == 1 && presences[0]["sharedChannels"].toString() == "[]");
    assert(presences[0]["event"]["c"].get!string == "AWAY");
    owner.request = randomUUID().toString();
    const failedLabel = "bnc-" ~ randomUUID().toString();
    hooks.write = (string line) { throw new Exception("fixture write failure"); };
    auto failed = new BncEngineState(null, "test", "network", "owner", "engine", hooks);
    assert(failed.writeOwned("WHO #broken", owner, 1, epoch, failedLabel) == "");
    const failedReplies = replies.length;
    failed.reject(owner, "UPSTREAM_UNAVAILABLE", "No connected upstream", failedLabel, epoch);
    assert(replies.length == failedReplies, "existing operation rejection must be exactly once");
    failed.newSocket(2); // A no-MONITOR-backend protocol harness is valid.
}

/// Real Redis lease/union regression hook for the isolated fixture, not production.
/// The caller supplies its fixture Redis and engine identity; all created keys
/// have fresh UUIDs and are removed on exit. This hook is not run at module load.
void runBncMonitorProtocolChecks(RedisStorage redis, string engineId) {
    import std.uni : toLower;
    const nid = randomUUID().toString(), uid = randomUUID().toString();
    const sid = randomUUID().toString(), sid2 = randomUUID().toString();
    const binding = randomUUID().toString(), binding2 = randomUUID().toString();
    const long start = 1_800_000_000_000;
    bool connected = true;
    size_t capacity = 3;
    string[] writes;
    Json[] replies;
    BncEngineHooks hooks;
    hooks.epoch = () => connected ? "monitor-socket" : "";
    hooks.connected = () => connected;
    hooks.labeled = () => true;
    hooks.monitorSupported = () => true;
    hooks.monitorLimit = () => capacity;
    hooks.ownNick = () => "me";
    hooks.fold = (string s) => s.toLower();
    hooks.webNicks = () => ["web"];
    hooks.monitorLines = (string verb, const string[] nicks, size_t limit) {
        string[] result;
        if (nicks.length) result ~= "MONITOR " ~ verb ~ " " ~ nicks.join(",");
        return result;
    };
    hooks.write = (string s) { writes ~= s; };
    hooks.emit = (IRCRawEvent e) { replies ~= parseJsonString(e.bncResponsePayload); };
    auto state = new BncEngineState(redis, "fixture", nid, uid, engineId, hooks);
    auto db = redis.getDb();
    db.hset(RedisKeys.networkAssignments(), nid, engineId);
    scope(exit) {
        db.hdel(RedisKeys.networkAssignments(), nid);
        db.del(RedisKeys.bncMonitorSessions(nid));
        foreach (s; [sid, sid2]) {
            db.srem(RedisKeys.bncClients(), s);
            db.del(RedisKeys.bncClient(s));
        }
    }
    foreach (s; [sid, sid2]) {
        auto p = Json.emptyObject;
        p["holderSessionId"] = s; p["networkId"] = nid; p["userId"] = uid;
        p["updatedAtMs"] = start;
        redis.setJson(RedisKeys.bncClient(s), p, 60);
        db.sadd(RedisKeys.bncClients(), s);
    }
    void submit(string s, string b, string verb, long revision, string[] nicks, long now) {
        IRCCommand c; c.cmd = "bnc_monitor"; c.userId = uid;
        c.bncSession = s; c.bncBinding = b; c.bncRequest = randomUUID().toString();
        c.deadlineMs = now + 30_000;
        auto p = Json.emptyObject; p["verb"] = verb; p["revision"] = revision;
        auto a = Json.emptyArray; foreach (n; nicks) a ~= Json(n);
        p["nicks"] = a; c.bncPayload = p.toString();
        state.handleBncMonitor(c, now);
    }
    submit(sid, binding, "replace", 0, [], start);
    assert(replies[$ - 1]["kind"].get!string == "complete");
    submit(sid, binding, "+", 1, ["Alice", "Bob", "Carol"], start);
    assert(state.leases[sid].nicks == ["Alice", "Bob"]);
    assert(state.activeUnion.length == 3);
    auto online = IRCRawEvent("fixture", "730"); online.setParams(["me", "Alice!user@host"]);
    assert(state.observeMonitorNumeric(online),
        "BNC-only interests must not escape onto the web numeric path");
    auto offline = IRCRawEvent("fixture", "731"); offline.setParams(["me", "Bob"]);
    state.observeMonitorNumeric(offline);
    assert(replies[$ - 1]["kind"].get!string == "complete");
    assert(replies[$ - 1]["result"]["revision"].get!long == 1);
    assert(replies[$ - 1]["result"]["rejected"][0].get!string == "Carol");
    foreach (r; replies) assert(r["operation"].get!string != "monitor_presence",
        "initial statuses must not be duplicated as transitions");
    submit(sid2, binding2, "replace", 0, [], start + 5_000);
    submit(sid2, binding2, "+", 1, ["ALICE"], start + 5_000);
    assert(state.leases[sid2].nicks == ["ALICE"] && state.activeUnion.length == 3);
    submit(sid2, binding2, "+", 1, ["Bob"], start + 5_000);
    assert(replies[$ - 1]["code"].get!string == "STALE_REVISION");
    submit(sid, binding, "-", 2, ["Bob"], start + 5_000);
    submit(sid, binding, "+", 3, ["Dave"], start + 5_000);
    auto upstreamFull = IRCRawEvent("fixture", "734");
    upstreamFull.setParams(["me", "3", "Dave", "Monitor list is full."]);
    assert(state.observeMonitorNumeric(upstreamFull));
    assert(state.leases[sid].revision == 4 && state.leases[sid].nicks == ["Alice"]);
    assert(replies[$ - 1]["kind"].get!string == "complete");
    assert(replies[$ - 1]["result"]["rejected"][0].get!string == "Dave");
    connected = false;
    submit(sid2, binding2, "L", 1, [], start + 5_000);
    assert(replies[$ - 2]["line"]["command"].get!string == "733");
    assert(replies[$ - 1]["result"]["nicks"][0].get!string == "ALICE");
    submit(sid2, binding2, "C", 2, [], start + 5_000);
    assert(state.leases[sid2].nicks.length == 0 && state.leases[sid].nicks.length == 1);
    connected = true; capacity = 1;
    state.reconcileMonitorUnion();
    assert(state.leases[sid].nicks.length == 0 && state.activeUnion.length == 1);
    assert(replies[$ - 1]["operation"].get!string == "monitor_update");
    assert(replies[$ - 1]["result"]["rejected"][0].get!string == "Alice");
    submit(sid2, binding2, "refresh", 2, [], start + 10_000);
    state.expireBncMonitorSessions(start + 65_001);
    assert(sid !in state.leases && sid2 in state.leases);
    submit(sid, binding, "refresh", 4, [], start + 65_001);
    assert(replies[$ - 1]["code"].get!string == "STALE_BINDING");
}
