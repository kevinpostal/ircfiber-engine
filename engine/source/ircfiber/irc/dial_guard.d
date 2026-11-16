module ircfiber.irc.dial_guard;

import core.sync.mutex : Mutex;
import std.conv : to;
import std.datetime : Clock;
import std.range : empty, front;
import std.string : startsWith;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.holder_client : HolderClient, DialRequest, DialResult, DialProgress,
    DialFailedException, HolderErrorException, HolderUnavailableException;

private string dialKey(string serverId, string networkId) {
    return "irc:routing:dials:" ~ serverId ~ ":" ~ networkId;
}

/// Fresh physical incarnation evidence, never a cached engine assignment.
string holderDialIncarnation(HolderClient holder) {
    auto status = holder.status();
    if (status.instance.length) return status.instance;
    if (status.pid <= 0)
        throw new HolderUnavailableException("holder incarnation unavailable for dial ownership");
    return "legacy-pid:" ~ status.pid.to!string;
}

/// Upper bound on how long one holder DIAL can still be running after the
/// engine sent it: connect 10 s + TLS 10 s + STARTTLS 15 s + SOCKS 15 s is
/// ~50 s, and the engine's IPC read timeout is 60 s. A marker for the same
/// holder incarnation that is older than this, and not owned by a dial that is
/// still running in this process, belongs to an engine that died or lost the
/// IPC reply. Its DIAL has necessarily finished: it either left an open holder
/// entry (visible to `holder.scan()`, which every dial checks) or nothing.
enum long orphanedDialProofMs = 180_000;

private long unixMsNow() {
    return (Clock.currStdTime - 621_355_968_000_000_000L) / 10_000;
}

// Tokens of dials that are executing in this process right now, per dial key.
// A live dial may legitimately wait a long time in registration admission, so
// age alone must never retire its marker.
private __gshared bool[string][string] liveDials;
private __gshared Mutex liveDialsMutex;
shared static this() { liveDialsMutex = new Mutex; }

private string[] liveDialTokens(string key) {
    synchronized (liveDialsMutex) {
        if (auto tokens = key in liveDials) return (*tokens).keys;
    }
    return null;
}

/// Registers `token` as a dial executing in this process for the dial key of
/// (`serverId`, `networkId`). Pair with `endLocalDial`.
void beginLocalDial(string serverId, string networkId, string token) {
    synchronized (liveDialsMutex) liveDials[dialKey(serverId, networkId)][token] = true;
}

void endLocalDial(string serverId, string networkId, string token) {
    const key = dialKey(serverId, networkId);
    synchronized (liveDialsMutex) {
        if (auto tokens = key in liveDials) {
            (*tokens).remove(token);
            if ((*tokens).length == 0) liveDials.remove(key);
        }
    }
}

/// Marker value: `holder_v1:<incarnation>@<unix ms the marker was written>`.
private string markerValue(string incarnation, long atMs) {
    return "holder_v1:" ~ incarnation ~ "@" ~ atMs.to!string;
}

/// Retires DIAL markers whose completion is proven:
///  - written for another holder incarnation (a UUID incarnation proves that
///    process, and every DIAL it ran, is gone; a pid-only incarnation cannot);
///  - same incarnation, not live in this process, and at least
///    `orphanedDialProofMs` old. A marker without a timestamp (written by an
///    older engine) is stamped on first sight and ages from there, which only
///    lengthens the wait.
/// Legacy unversioned '1' markers are never touched.
void retireOrphanedDials(RedisStorage redis, string serverId, string networkId,
        string incarnation, long nowMs) {
    const key = dialKey(serverId, networkId);
    const trustIncarnationChange = !incarnation.startsWith("legacy-pid:");
    string[] args = [incarnation, nowMs.to!string, orphanedDialProofMs.to!string,
        trustIncarnationChange ? "1" : "0"];
    args ~= liveDialTokens(key);
    redis.getDb().eval!string(
        "local rows=redis.call('HGETALL',KEYS[1]); local live={}; " ~
        "for i=5,#ARGV do live[ARGV[i]]=true end; " ~
        "local now=tonumber(ARGV[2]); local proof=tonumber(ARGV[3]); " ~
        "for i=1,#rows,2 do local f=rows[i]; local v=rows[i+1]; " ~
        "if string.sub(v,1,10)=='holder_v1:' then " ~
        "local body=string.sub(v,11); local at=string.find(body,'@',1,true); " ~
        "local inc=body; if at then inc=string.sub(body,1,at-1) end; " ~
        "if inc~=ARGV[1] then " ~
        "if ARGV[4]=='1' then redis.call('HDEL',KEYS[1],f) end " ~
        "elseif not live[f] then " ~
        "local ts=at and tonumber(string.sub(body,at+1)) or nil; " ~
        "if ts==nil then redis.call('HSET',KEYS[1],f,'holder_v1:'..inc..'@'..ARGV[2]) " ~
        "elseif now-ts>=proof then redis.call('HDEL',KEYS[1],f) end " ~
        "end end end; return '1'",
        [key], args);
}

/// The marker hash has no TTL: a crashed process/ambiguous IPC failure must not
/// turn an unobserved, possibly still running holder DIAL into closure proof.
/// Markers leave only by their own terminal HDEL or `retireOrphanedDials`
/// proof (holder replaced, or older than `orphanedDialProofMs` and not live here).
bool networkDialsQuiescent(RedisStorage redis, string serverId, string networkId, HolderClient holder) {
    if (redis is null || !serverId.length) return false;
    auto reply = redis.getDb().eval!string(
        "if redis.call('HLEN',KEYS[1]) == 0 then return '1' else return '0' end",
        [dialKey(serverId, networkId)]);
    if (!reply.empty && reply.front == "1") return true;
    if (holder is null) return false;
    retireOrphanedDials(redis, serverId, networkId, holderDialIncarnation(holder), unixMsNow());
    auto after = redis.getDb().eval!string(
        "if redis.call('HLEN',KEYS[1]) == 0 then return '1' else return '0' end",
        [dialKey(serverId, networkId)]);
    return !after.empty && after.front == "1";
}

bool ownsNetworkForDial(RedisStorage redis, string serverId, string networkId) {
    if (redis is null || !serverId.length) return false;
    auto reply = redis.getDb().eval!string(
        "if redis.call('HGET',KEYS[1],ARGV[1]) == ARGV[2] and redis.call('EXISTS',KEYS[2]) == 0 then return '1' else return '0' end",
        [RedisKeys.networkAssignments(), RedisKeys.routingMove(networkId)], [networkId, serverId]);
    return !reply.empty && reply.front == "1";
}

DialResult dialWithOwnership(HolderClient holder, DialRequest req, DialProgress progress,
    RedisStorage redis, string serverId, scope bool delegate() stopping,
    scope void delegate() validatePolicy, scope void delegate(string) admitRegistration,
    scope void delegate() onResponse, out bool sent) {
    import deimos.openssl.rand : RAND_bytes;
    if (redis is null || stopping()) throw new HolderUnavailableException("connection stopped before dial");
    const incarnation = holderDialIncarnation(holder);
    retireOrphanedDials(redis, serverId, req.tag.networkId, incarnation, unixMsNow());
    ubyte[16] random;
    if (RAND_bytes(random.ptr, cast(int) random.length) != 1)
        throw new HolderUnavailableException("unable to reserve dial ownership token");
    char[32] hex;
    foreach (i, value; random) {
        hex[i * 2] = "0123456789abcdef"[value >> 4];
        hex[i * 2 + 1] = "0123456789abcdef"[value & 15];
    }
    const token = hex[].idup;
    const key = dialKey(serverId, req.tag.networkId);
    beginLocalDial(serverId, req.tag.networkId, token);
    scope(exit) endLocalDial(serverId, req.tag.networkId, token);
    auto db = redis.getDb();
    auto reply = db.eval!string(
        "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 or redis.call('HLEN',KEYS[3]) ~= 0 then return '0' end redis.call('HSET',KEYS[3],ARGV[3],ARGV[4]); return '1'",
        [RedisKeys.networkAssignments(), RedisKeys.routingMove(req.tag.networkId), key],
        [req.tag.networkId, serverId, token, markerValue(incarnation, unixMsNow())]);
    if (reply.empty || reply.front != "1")
        throw new HolderUnavailableException("canonical owner changed, routing move fenced, or an earlier holder DIAL has unproven completion (inspect " ~ key ~ ")");
    bool terminal = true;
    scope(exit) if (terminal) db.hdel(key, token);
    // Redis and progress callbacks yield; stop intent always wins before IPC.
    if (stopping()) {
        terminal = true;
        throw new HolderUnavailableException("connection stopped before holder dial");
    }
    // A removed generation may have left an open entry even after its own
    // transport looked dead. Never create another upstream beside it.
    foreach (entry; holder.scan())
        if (entry.tag.networkId == req.tag.networkId && entry.state == "open")
            throw new HolderUnavailableException("existing holder entry must close or be adopted before dialing");
    if (stopping())
        throw new HolderUnavailableException("connection stopped before holder dial");
    validatePolicy();
    if (stopping() || !ownsNetworkForDial(redis, serverId, req.tag.networkId))
        throw new HolderUnavailableException("connection stopped or fenced before holder dial");
    try {
        auto result = holder.dial(req, progress, {
            const actualIncarnation = holderDialIncarnation(holder);
            validatePolicy();
            if (stopping() || !ownsNetworkForDial(redis, serverId, req.tag.networkId))
                throw new HolderUnavailableException("connection stopped or fenced during dial admission");
            auto committed = db.eval!string(
                "if redis.call('HEXISTS',KEYS[1],ARGV[1]) == 0 or redis.call('HGET',KEYS[2],ARGV[2]) ~= ARGV[3] or redis.call('EXISTS',KEYS[3]) ~= 0 then return '0' end redis.call('HSET',KEYS[1],ARGV[1],ARGV[4]); return '1'",
                [key, RedisKeys.networkAssignments(), RedisKeys.routingMove(req.tag.networkId)],
                [token, req.tag.networkId, serverId, markerValue(actualIncarnation, unixMsNow())]);
            if (committed.empty || committed.front != "1")
                throw new HolderUnavailableException("dial ownership lost before registration admission");
            admitRegistration(actualIncarnation);
            // Admission may wait arbitrarily. Ownership and durable concrete
            // exit/trial admission must be fresh after that wait, not before.
            if (stopping() || !ownsNetworkForDial(redis, serverId, req.tag.networkId))
                throw new HolderUnavailableException("connection stopped or fenced after registration admission");
            validatePolicy();
            if (stopping()) throw new HolderUnavailableException("connection stopped before DIAL");
            terminal = false;
            sent = true;
        }, onResponse);
        terminal = true;
        return result;
    } catch (HolderErrorException e) {
        terminal = true; // authenticated holder rejected this request
        throw e;
    } catch (DialFailedException e) {
        // 'holder' includes a timed-out/malformed IPC stream, not an observed
        // terminal holder response. Retain that operation's uncertainty.
        terminal = terminal || e.phase != "holder";
        throw e;
    }
}
