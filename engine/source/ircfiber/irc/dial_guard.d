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

/// Deliberately has no TTL: a crashed process/ambiguous IPC failure must not
/// turn an unobserved, possibly still running holder DIAL into closure proof.
bool networkDialsQuiescent(RedisStorage redis, string serverId, string networkId) {
    if (redis is null || !serverId.length) return false;
    auto reply = redis.getDb().eval!string(
        "if redis.call('HLEN',KEYS[1]) == 0 then return '1' else return '0' end",
        [dialKey(serverId, networkId)]);
    return !reply.empty && reply.front == "1";
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
    scope void delegate() validatePolicy) {
    import deimos.openssl.rand : RAND_bytes;
    if (redis is null || stopping()) throw new HolderUnavailableException("connection stopped before dial");
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
        "if redis.call('HGET',KEYS[1],ARGV[1]) ~= ARGV[2] or redis.call('EXISTS',KEYS[2]) ~= 0 or redis.call('HLEN',KEYS[3]) ~= 0 then return '0' end redis.call('HSET',KEYS[3],ARGV[3],'1'); return '1'",
        [RedisKeys.networkAssignments(), RedisKeys.routingMove(req.tag.networkId), key],
        [req.tag.networkId, serverId, token]);
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
    foreach (entry; holder.list())
        if (entry.tag.networkId == req.tag.networkId && entry.state == "open")
            throw new HolderUnavailableException("existing holder entry must close or be adopted before dialing");
    if (stopping())
        throw new HolderUnavailableException("connection stopped before holder dial");
    validatePolicy();
    if (stopping() || !ownsNetworkForDial(redis, serverId, req.tag.networkId))
        throw new HolderUnavailableException("connection stopped or fenced before holder dial");
    terminal = false;
    try {
        auto result = holder.dial(req, progress);
        terminal = true;
        return result;
    } catch (HolderErrorException e) {
        terminal = true; // authenticated holder rejected this request
        throw e;
    } catch (DialFailedException e) {
        // 'holder' includes a timed-out/malformed IPC stream, not an observed
        // terminal holder response. Retain that operation's uncertainty.
        terminal = e.phase != "holder";
        throw e;
    }
}
