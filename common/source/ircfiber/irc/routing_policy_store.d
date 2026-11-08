/** Durable routing policy and rolling-upgrade fences. Reads never default or
 * keep a stale permissive cache; writes never reconnect established sessions.
 */
module ircfiber.irc.routing_policy_store;

import std.conv : to;
import vibe.data.json : Json, parseJsonString;
import vibe.db.redis.redis : RedisDatabase;
import ircfiber.irc.routing_policy;
import ircfiber.redis.protocol : RedisKeys;

class RoutingPolicyUnavailableException : Exception {
    this(string message = "Routing policy unavailable") { super(message); }
}

class RoutingPolicyConflictException : Exception {
    long currentRevision;
    this(long revision) {
        super("Routing policy revision conflict");
        currentRevision = revision;
    }
}

class RoutingUpgradeException : Exception {
    string code = "routing_upgrade_in_progress";
    this() { super("Routing upgrade in progress"); }
}

private RoutingPolicyDocument readPolicy(RedisDatabase db, out string raw) {
    try {
        raw = db.get(RedisKeys.egressRoutingPolicy());
        if (!raw.length) throw new RoutingPolicyUnavailableException();
        return routingPolicyFromJson(parseJsonString(raw));
    } catch (RoutingPolicyUnavailableException e) { throw e; }
    catch (Exception) { throw new RoutingPolicyUnavailableException(); }
}

RoutingPolicyDocument loadRoutingPolicy(RedisDatabase db) {
    string raw;
    return readPolicy(db, raw);
}

EffectiveRoutingPolicy loadEffectiveRoutingPolicy(RedisDatabase db, string host,
                                                   const RoutingPreferences preferences) {
    try return resolveRoutingPolicy(loadRoutingPolicy(db), host, preferences);
    catch (Exception) {
        EffectiveRoutingPolicy blocked;
        blocked.available = false;
        blocked.errorCode = "routing_policy_unavailable";
        return blocked;
    }
}

bool hasAdministrativeBlocks(const RoutingPolicyDocument doc) pure @safe nothrow @nogc {
    if (doc.global.blockedRoutes.length) return true;
    foreach (rule; doc.hosts) if (rule.policy.blockedRoutes.length) return true;
    return false;
}

/// Fresh gate check, not an assertion that a registered engine is healthy or
/// supports any particular route. Placement performs those separate checks.
void requireRoutingUpgrade(RedisDatabase db, string serverId = "") {
    try {
        if (db.get(RedisKeys.routingSchemaVersion()) != "1") throw new RoutingUpgradeException();
        if (serverId.length) {
            const raw = db.hget(RedisKeys.server(serverId), "data");
            auto metadata = parseJsonString(raw);
            if (metadata.type != Json.Type.object
                    || metadata["routingPolicyVersion"].type != Json.Type.int_
                    || metadata["routingPolicyVersion"].get!long != 1)
                throw new RoutingUpgradeException();
        }
    } catch (RoutingUpgradeException e) { throw e; }
    catch (Exception) { throw new RoutingUpgradeException(); }
}

/// Includes orphaned/stale/hot-swap hashes, not just the currently healthy set.
bool routingEnginesPolicyAware(RedisDatabase db) {
    try {
        auto reply = db.eval!string(ENGINE_GATE_SCRIPT,
            [RedisKeys.serverList()], [RedisKeys.server("")]);
        return !reply.empty && reply.front == "1";
    } catch (Exception) { return false; }
}

/// The policy must already be explicitly seeded by the controlled migration.
/// Revision and rollback activation are committed together, with no TTL.
RoutingPolicyDocument saveRoutingPolicy(RedisDatabase db, long expectedRevision,
                                        const RoutingPolicyDocument proposed) {
    auto validated = routingPolicyFromJson(proposed.toJson());
    if (expectedRevision < 0 || expectedRevision >= MAX_ROUTING_POLICY_REVISION
            || validated.revision != expectedRevision)
        throw new RoutingValidationException("expectedRevision must match policy.revision and permit an exact increment");
    requireRoutingUpgrade(db);
    string raw;
    auto current = readPolicy(db, raw);
    if (current.revision != expectedRevision) throw new RoutingPolicyConflictException(current.revision);
    // A string placeholder avoids Redis cjson's limited numeric output precision.
    // Lua performs the increment and emits an exact integer, not a rounded JSON number.
    auto next = validated.toJson();
    next["revision"] = Json("__ircfiber_revision__");
    try {
        auto reply = db.eval!string(SAVE_SCRIPT,
            [RedisKeys.egressRoutingPolicy(), RedisKeys.routingHardBlocksActivated(),
             RedisKeys.routingSchemaVersion(), RedisKeys.serverList()],
            [raw, expectedRevision.to!string, next.toString(), hasAdministrativeBlocks(validated) ? "1" : "0",
             RedisKeys.server("")]);
        if (reply.empty) throw new RoutingPolicyUnavailableException();
        auto result = parseJsonString(reply.front.idup);
        if (result["state"].type != Json.Type.string) throw new RoutingPolicyUnavailableException();
        switch (result["state"].get!string) {
            case "ok":
                return routingPolicyFromJson(parseJsonString(result["raw"].get!string));
            case "changed": {
                RoutingPolicyDocument newer;
                try newer = routingPolicyFromJson(parseJsonString(result["raw"].get!string));
                catch (Exception) { throw new RoutingPolicyUnavailableException(); }
                throw new RoutingPolicyConflictException(newer.revision);
            }
            case "upgrade": throw new RoutingUpgradeException();
            default: throw new RoutingPolicyUnavailableException();
        }
    } catch (RoutingPolicyConflictException e) { throw e; }
    catch (RoutingUpgradeException e) { throw e; }
    catch (RoutingPolicyUnavailableException e) { throw e; }
    catch (Exception) { throw new RoutingPolicyUnavailableException(); }
}

private enum ENGINE_GATE_FUNCTION = q"LUA
local function enginesAware(setKey, prefix)
  local ids = {}
  for _, id in ipairs(redis.call('SMEMBERS', setKey)) do ids[id] = true end
  local cursor = '0'
  repeat
    local batch = redis.call('SCAN', cursor, 'MATCH', prefix .. '*', 'COUNT', 100)
    cursor = batch[1]
    for _, key in ipairs(batch[2]) do ids[string.sub(key, #prefix + 1)] = true end
  until cursor == '0'
  for id, _ in pairs(ids) do
    local raw = redis.call('HGET', prefix .. id, 'data')
    if not raw then return false end
    local ok, metadata = pcall(cjson.decode, raw)
    if not ok or type(metadata) ~= 'table' or metadata.routingPolicyVersion ~= 1 then return false end
  end
  return true
end
LUA";

private enum ENGINE_GATE_SCRIPT = ENGINE_GATE_FUNCTION ~ q"LUA
if enginesAware(KEYS[1], ARGV[1]) then return '1' else return '0' end
LUA";

private enum SAVE_SCRIPT = ENGINE_GATE_FUNCTION ~ q"LUA
if redis.call('GET', KEYS[3]) ~= '1' then return cjson.encode({state='upgrade'}) end
local current = redis.call('GET', KEYS[1])
if not current then return cjson.encode({state='unavailable'}) end
if current ~= ARGV[1] then return cjson.encode({state='changed', raw=current}) end
if (ARGV[4] == '1' or redis.call('EXISTS', KEYS[2]) == 1) and not enginesAware(KEYS[4], ARGV[5]) then
  return cjson.encode({state='upgrade'})
end
local revision = tonumber(ARGV[2]) + 1
local encoded, count = string.gsub(ARGV[3], '"revision":"__ircfiber_revision__"',
  '"revision":' .. string.format('%.0f', revision), 1)
if count ~= 1 then return cjson.encode({state='unavailable'}) end
redis.call('SET', KEYS[1], encoded)
if ARGV[4] == '1' then redis.call('SET', KEYS[2], '1') end
return cjson.encode({state='ok', raw=encoded})
LUA";
