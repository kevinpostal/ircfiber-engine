module ircfiber.irc.dial_guard;

import std.conv : to;
import std.range : empty, front;
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

private void retireLostIncarnationDials(RedisStorage redis, string serverId, string networkId,
        string incarnation) {
    import std.string : startsWith;
    // Only a UUID-bearing incarnation proves earlier process-owned DIALs
    // gone. Legacy unversioned '1' markers remain deliberately unproven.
    if (incarnation.startsWith("legacy-pid:")) return;
    redis.getDb().eval!string(
        "local rows=redis.call('HGETALL',KEYS[1]); for i=1,#rows,2 do local v=rows[i+1]; if string.sub(v,1,10)=='holder_v1:' and v~=ARGV[1] then redis.call('HDEL',KEYS[1],rows[i]) end end; return '1'",
        [dialKey(serverId, networkId)], ["holder_v1:" ~ incarnation]);
}

/// Deliberately has no TTL: a crashed process/ambiguous IPC failure must not
/// turn an unobserved, possibly still running holder DIAL into closure proof.
bool networkDialsQuiescent(RedisStorage redis, string serverId, string networkId, HolderClient holder) {
    if (redis is null || !serverId.length) return false;
    auto reply = redis.getDb().eval!string(
        "if redis.call('HLEN',KEYS[1]) == 0 then return '1' else return '0' end",
        [dialKey(serverId, networkId)]);
    if (!reply.empty && reply.front == "1") return true;
    if (holder is null) return false;
    retireLostIncarnationDials(redis, serverId, networkId, holderDialIncarnation(holder));
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
    retireLostIncarnationDials(redis, serverId, req.tag.networkId, incarnation);
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
    auto db = redis.getDb();
    auto reply = db.eval!string(
        "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 or redis.call('HLEN',KEYS[3]) ~= 0 then return '0' end redis.call('HSET',KEYS[3],ARGV[3],ARGV[4]); return '1'",
        [RedisKeys.networkAssignments(), RedisKeys.routingMove(req.tag.networkId), key],
        [req.tag.networkId, serverId, token, "holder_v1:" ~ incarnation]);
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
                [token, req.tag.networkId, serverId, "holder_v1:" ~ actualIncarnation]);
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
