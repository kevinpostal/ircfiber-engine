/// Admission for physical sessions on IRC Fiber's dedicated Nord subscription.
/// The only creator of this ledger is the fenced cold-activation command.
module ircfiber.irc.nord_capacity;

import ircfiber.redis.protocol : RedisKeys;
import vibe.db.redis.redis : RedisDatabase;

enum NordVerdict { unavailable, full, acquired }

struct NordPermit {
    NordVerdict verdict;
    string generation, token;

    @property string reason() const {
        final switch (verdict) {
            case NordVerdict.acquired: return "";
            case NordVerdict.full: return "nord_capacity_full";
            case NordVerdict.unavailable: return "nord_capacity_unavailable";
        }
    }
}

struct NordReservation { string generation, token, kind, incarnation, owner; }

// INFO and the mutation must run in one invocation on the same primary: a
// persisted activation from before a Redis restart must not authorize a dial.
// Validate even on release. Neither corruption nor an ambiguous transport
// reply grants authority to repair, retry an acquire, or infer closure.
private enum ledger = `
local k = KEYS[1]
local function uuid(s)
    if not s or #s ~= 36 then return false end
    local a,b,c,d,e = s:match('^([0-9a-f]+)%-([0-9a-f]+)%-([0-9a-f]+)%-([0-9a-f]+)%-([0-9a-f]+)$')
    return a and #a == 8 and #b == 4 and #c == 4 and #d == 4 and #e == 12
end
local function token(s)
    return uuid(s) or (s and #s == 32 and s:match('^[0-9a-f]+$'))
end
local function owner(kind,inc,id)
    return (kind == 'holder' or kind == 'probe' or kind == 'image') and uuid(inc)
       and id and #id <= 128 and id:match('^[A-Za-z0-9_%.%-]+$')
end
if redis.call('TYPE', k).ok ~= 'hash' or redis.call('PTTL', k) ~= -1 then return 'unavailable' end
local n = redis.call('HLEN', k)
if n < 1 or n > 11 then return 'unavailable' end
local active = redis.call('HGET', k, 'active')
if not active then return 'unavailable' end
local run,gen = active:match('^([0-9a-f]+):(.+)$')
if not run or #run ~= 40 or not uuid(gen) then return 'unavailable' end
if redis.call('INFO', 'server'):match('\nrun_id:([0-9a-f]+)\r\n') ~= run or
   redis.call('INFO', 'replication'):match('\nrole:([^\r]+)\r\n') ~= 'master' then return 'unavailable' end
local rows = redis.call('HGETALL', k)
for i=1,#rows,2 do
    if rows[i] ~= 'active' then
        local kind,inc,id = rows[i+1]:match('^([^|]+)|([^|]+)|([^|]+)$')
        if not token(rows[i]) or not owner(kind,inc,id) then return 'unavailable' end
    end
end
`;

private enum acquire = ledger ~ `
local t,kind,inc,id = unpack(ARGV)
if not token(t) or not owner(kind,inc,id) or redis.call('HEXISTS',k,t) == 1 then return 'unavailable' end
if n == 11 then return 'full' end
redis.call('HSET', k, t, kind..'|'..inc..'|'..id)
return active
`;

private enum release = ledger ~ `
if not token(ARGV[2]) or ARGV[1] ~= active then return 'unavailable' end
redis.call('HDEL', k, ARGV[2])
return 'ok'
`;

private enum list = ledger ~ `
local out = {active}
for i=1,#rows,2 do
    if rows[i] ~= 'active' then out[#out+1] = rows[i]..'|'..rows[i+1] end
end
return table.concat(out, '\n')
`;

private string invoke(RedisDatabase db, string script, string[] args = null) {
    if (db.client is null || db.index != 0)
        throw new Exception("nord_capacity_unavailable");
    auto reply = db.eval!string(script, [RedisKeys.nordCapacity()], args);
    if (reply.empty) throw new Exception("empty Nord capacity reply");
    return reply.front.idup;
}

/// A lost acquire response leaves the slot occupied; only acquired may dial.
NordPermit tryAcquireNordCapacity(RedisDatabase db, string kind, string incarnation,
                                  string owner, string token) {
    try {
        auto result = invoke(db, acquire, [token, kind, incarnation, owner]);
        if (result == "full") return NordPermit(NordVerdict.full);
        if (result.length == 77 && result[40] == ':')
            return NordPermit(NordVerdict.acquired, result, token);
    } catch (Exception) { }
    return NordPermit.init;
}

/// True also for an absent token *in this intact generation*: permits safe
/// holder terminal-evidence acknowledgement after a release/ack crash.
bool releaseNordCapacity(RedisDatabase db, string generation, string token) {
    try { return invoke(db, release, [generation, token]) == "ok"; }
    catch (Exception) { return false; }
}

/// A bounded, atomic snapshot for reconciliation. Failure is NOT an empty list.
NordReservation[] nordReservations(RedisDatabase db) {
    import std.array : split;
    auto lines = invoke(db, list).split("\n");
    if (!lines.length || lines[0].length != 77 || lines[0][40] != ':' || lines.length > 11)
        throw new Exception("nord_capacity_unavailable");
    auto records = new NordReservation[lines.length - 1];
    foreach (i, line; lines[1 .. $]) {
        auto parts = line.split("|");
        if (parts.length != 4) throw new Exception("nord_capacity_unavailable");
        records[i] = NordReservation(lines[0], parts[0], parts[1], parts[2], parts[3]);
    }
    return records;
}
