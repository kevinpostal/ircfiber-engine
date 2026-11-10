/** Redis ownership handoff protocol. A fence never authorizes a destination
 * connection: only a matching, positively acknowledged source close can commit.
 */
module ircfiber.irc.routing_moves;

import std.conv : to;
import std.datetime : Clock;
import std.uuid : UUID, parseUUID;
import std.ascii : isWhite;
import std.string : strip, lineSplitter, icmp;
import vibe.data.json : Json, parseJsonString;
import vibe.db.redis.redis : RedisDatabase;
import ircfiber.irc.server : ConnectionServer;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.network_write_gate : NetworkWriteUnavailableException, NetworkWriter,
    runNetworkWrite, runNetworkRedisMutation;

public enum NETWORK_ROUTING_LEASE_TTL_SECONDS = 90;
private enum MOVE_FENCE_SECONDS = 120;
private enum MOVE_RESULT_SECONDS = 86_400;

class RoutingMoveConflictException : Exception {
    this(string message = "Routing move conflicts with current placement") { super(message); }
}
class RoutingMoveUnavailableException : Exception {
    this(string message = "Routing move coordination unavailable") { super(message); }
}

struct RoutingMove {
    string moveId, networkId, fromServerId, targetServerId, state, error;
    bool sourceClosed;
    string ackServerId;
    long createdAtMs;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["moveId"] = Json(moveId);
        j["networkId"] = Json(networkId);
        j["fromServerId"] = Json(fromServerId);
        j["targetServerId"] = Json(targetServerId);
        j["state"] = Json(state);
        j["error"] = Json(error);
        j["sourceClosed"] = Json(sourceClosed);
        j["ackServerId"] = Json(ackServerId);
        j["createdAtMs"] = Json(createdAtMs);
        return j;
    }
}

package(ircfiber) bool isRoutingMoveId(string value) pure @safe nothrow @nogc {
    if (value.length != 32) return false;
    foreach (c; value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
private bool validServerId(string value) pure @safe nothrow @nogc {
    if (!value.length || value.length > 128) return false;
    foreach (c; value) if (c <= ' ' || c == 127) return false;
    return true;
}
private bool validNetworkId(string value) {
    try { return value.length == 36 && parseUUID(value[]) != UUID.init; }
    catch (Exception) { return false; }
}
private string operationToken() @trusted {
    import deimos.openssl.rand : RAND_bytes;
    ubyte[16] bytes;
    if (RAND_bytes(bytes.ptr, cast(int)bytes.length) != 1)
        throw new RoutingMoveUnavailableException("Routing move entropy unavailable");
    enum digits = "0123456789abcdef";
    char[32] result;
    foreach (i, b; bytes) { result[i * 2] = digits[b >> 4]; result[i * 2 + 1] = digits[b & 15]; }
    return result[].idup;
}
private RoutingMove decodeMove(string raw) {
    if (!raw.length) return RoutingMove.init;
    auto j = parseJsonString(raw);
    if (j.type != Json.Type.object || j.get!(Json[string]).length != 9)
        throw new RoutingMoveUnavailableException("Malformed routing move status");
    RoutingMove m;
    foreach (name; ["moveId", "networkId", "fromServerId", "targetServerId", "state", "error", "ackServerId"])
        if (j[name].type != Json.Type.string) throw new RoutingMoveUnavailableException("Malformed routing move status");
    if (j["sourceClosed"].type != Json.Type.bool_ || j["createdAtMs"].type != Json.Type.int_)
        throw new RoutingMoveUnavailableException("Malformed routing move status");
    m.moveId = j["moveId"].get!string;
    m.networkId = j["networkId"].get!string;
    m.fromServerId = j["fromServerId"].get!string;
    m.targetServerId = j["targetServerId"].get!string;
    m.state = j["state"].get!string;
    m.error = j["error"].get!string;
    m.sourceClosed = j["sourceClosed"].get!bool;
    m.ackServerId = j["ackServerId"].get!string;
    m.createdAtMs = j["createdAtMs"].get!long;
    if (!isRoutingMoveId(m.moveId) || !validNetworkId(m.networkId)
            || !validServerId(m.fromServerId) || !validServerId(m.targetServerId)
            || m.fromServerId == m.targetServerId || m.createdAtMs <= 0
            || (m.state != "queued" && m.state != "processing" && m.state != "completed"
                && m.state != "failed" && m.state != "expired")
            || (m.sourceClosed ? m.ackServerId != m.fromServerId : m.ackServerId.length != 0)
            || (m.state == "queued" && m.sourceClosed) || (m.state == "completed" && !m.sourceClosed))
        throw new RoutingMoveUnavailableException("Malformed routing move status");
    return m;
}

RoutingMove loadRoutingMove(RedisDatabase db, string moveId) {
    if (!isRoutingMoveId(moveId)) throw new RoutingMoveConflictException("Invalid routing move ID");
    return runNetworkWrite!RoutingMove(db, (ref NetworkWriter writer) {
        return loadRoutingMove(db, moveId, writer);
    });
}

RoutingMove loadRoutingMove(RedisDatabase db, string moveId, ref NetworkWriter writer) {
    if (!isRoutingMoveId(moveId)) throw new RoutingMoveConflictException("Invalid routing move ID");
    try {
        const raw = runNetworkRedisMutation!string(writer, (RedisDatabase actualDb) {
            auto reply = actualDb.eval!string(LOAD_SCRIPT, [RedisKeys.routingMoveStatus(moveId)],
                [moveId, RedisKeys.routingMove(""), MOVE_RESULT_SECONDS.to!string]);
            if (reply.empty) throw new RoutingMoveUnavailableException();
            return reply.front.idup;
        });
        auto move = decodeMove(raw);
        if (move.moveId.length && move.moveId != moveId) throw new RoutingMoveUnavailableException();
        return move;
    } catch (NetworkWriteUnavailableException e) { throw e; }
    catch (RoutingMoveUnavailableException e) { throw e; }
    catch (Exception) { throw new RoutingMoveUnavailableException(); }
}

bool networkMoveFenced(RedisDatabase db, string networkId) {
    if (!validNetworkId(networkId)) throw new RoutingMoveConflictException("Invalid network ID");
    try { return db.exists(RedisKeys.routingMove(networkId)); }
    catch (Exception) { throw new RoutingMoveUnavailableException(); }
}

/// Route a command against canonical ownership in the same Redis operation as
/// enqueueing it. Moves retain fenced commands on the source queue until the
/// atomic commit transfers them; no legacy queue guesses an unknown owner.
bool enqueueRoutingCommand(RedisDatabase db, string networkId, string commandJson) {
    if (!validNetworkId(networkId)) throw new RoutingMoveConflictException("Invalid network ID");
    const connectionEffect = routingCommandChangesConnection(commandJson);
    if (connectionEffect)
        return runNetworkWrite!bool(db, (ref NetworkWriter writer) {
            return enqueueRoutingCommand(db, networkId, commandJson, writer);
        });
    return enqueueRoutingCommandUnchecked(db, networkId, commandJson, false);
}

bool enqueueRoutingCommand(RedisDatabase db, string networkId, string commandJson,
        ref NetworkWriter writer) {
    if (!validNetworkId(networkId)) throw new RoutingMoveConflictException("Invalid network ID");
    const connectionEffect = routingCommandChangesConnection(commandJson);
    return runNetworkRedisMutation!bool(writer, (RedisDatabase actualDb) {
        return enqueueRoutingCommandUnchecked(actualDb, networkId, commandJson, connectionEffect);
    });
}

// Message/PONG/history/channel traffic is runtime, not connection ownership.
// Raw QUIT (including a later line) is different: it can close the socket.
private bool routingCommandChangesConnection(string commandJson) {
    const command = parseJsonString(commandJson);
    const kind = command["cmd"].get!string;
    if (kind == "connect" || kind == "disconnect" || kind == "reconnect") return true;
    if (kind != "raw") return false;
    foreach (line; command["text"].get!string.lineSplitter) {
        auto text = line.strip;
        // IRCv3 tags and an optional prefix precede, not replace, the verb.
        foreach (prefix; ['@', ':']) {
            if (!text.length || text[0] != prefix) continue;
            size_t end;
            while (end < text.length && !isWhite(text[end])) ++end;
            text = text[end .. $].strip;
        }
        size_t end;
        while (end < text.length && !isWhite(text[end])) ++end;
        const verb = text[0 .. end];
        foreach (effect; ["QUIT", "CONNECT", "RECONNECT", "KILL", "SQUIT", "DIE", "RESTART"])
            if (icmp(verb, effect) == 0) return true;
    }
    return false;
}

private bool enqueueRoutingCommandUnchecked(RedisDatabase db, string networkId,
        string commandJson, bool connectionEffect) {
    try {
        auto reply = db.eval!string(q"LUA
if ARGV[4] == '1' and redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return 'maintenance' end
local owner = redis.call('HGET', KEYS[1], ARGV[1])
if not owner or owner == '' then return '0' end
redis.call('RPUSH', ARGV[2] .. owner .. ':' .. ARGV[1], ARGV[3])
return '1'
LUA", [RedisKeys.networkAssignments()], [networkId, "irc:cmd:", commandJson, connectionEffect ? "1" : "0"]);
        if (reply.empty) throw new RoutingMoveUnavailableException();
        if (reply.front == "maintenance") throw new NetworkWriteUnavailableException();
        return reply.front == "1";
    } catch (NetworkWriteUnavailableException e) { throw e; }
    catch (RoutingMoveUnavailableException e) { throw e; }
    catch (Exception) { throw new RoutingMoveUnavailableException(); }
}

RoutingMove requestNetworkMove(RedisDatabase db, string networkId, string targetServerId) {
    if (!validNetworkId(networkId) || !validServerId(targetServerId))
        throw new RoutingMoveConflictException("Invalid routing move placement");
    RoutingMoveConflictException conflict;
    auto move = runNetworkWrite!RoutingMove(db, (ref NetworkWriter writer) {
        try return requestNetworkMove(db, networkId, targetServerId, writer);
        catch (RoutingMoveConflictException e) { conflict = e; return RoutingMove.init; }
    });
    if (conflict !is null) throw conflict;
    return move;
}

RoutingMove requestNetworkMove(RedisDatabase db, string networkId, string targetServerId,
        ref NetworkWriter writer) {
    if (!validNetworkId(networkId) || !validServerId(targetServerId))
        throw new RoutingMoveConflictException("Invalid routing move placement");
    try {
        // Return the existing operation even if its requested target has since
        // disappeared. The create script repeats this check against races.
        const existing = db.get(RedisKeys.routingMove(networkId));
        if (existing.length) {
            auto move = loadRoutingMove(db, existing, writer);
            if (!move.moveId.length || move.networkId != networkId)
                throw new RoutingMoveUnavailableException("Malformed routing move fence");
            return move;
        }
        const targetRaw = db.hget(RedisKeys.server(targetServerId), "data");
        ConnectionServer target;
        try { target = ConnectionServer.fromJson(parseJsonString(targetRaw)); }
        catch (Exception) { throw new RoutingMoveConflictException("Target placement unavailable"); }
        if (target.serverId != targetServerId || target.routingPolicyVersion != 1 || !target.supportedRoutes.length)
            throw new RoutingMoveConflictException("Target has no routing capabilities");
        const token = operationToken();
        const now = Clock.currTime.toUnixTime!long * 1000;
        const result = runNetworkRedisMutation!string(writer, (RedisDatabase actualDb) {
            auto reply = actualDb.eval!string(CREATE_SCRIPT,
                [RedisKeys.routingMove(networkId), RedisKeys.routingMoveStatus(token), RedisKeys.routingMoves(),
                 RedisKeys.networkAssignments(), RedisKeys.server(targetServerId), RedisKeys.draining(targetServerId),
                 RedisKeys.routingSchemaVersion()],
                [token, networkId, targetServerId, now.to!string, targetRaw,
                 MOVE_FENCE_SECONDS.to!string, MOVE_RESULT_SECONDS.to!string]);
            if (reply.empty) throw new RoutingMoveUnavailableException();
            return reply.front.idup;
        });
        if (result == "conflict") throw new RoutingMoveConflictException();
        if (result == "maintenance") throw new NetworkWriteUnavailableException();
        if (!isRoutingMoveId(result)) throw new RoutingMoveUnavailableException();
        auto move = loadRoutingMove(db, result, writer);
        if (!move.moveId.length || move.networkId != networkId) throw new RoutingMoveUnavailableException();
        return move;
    } catch (NetworkWriteUnavailableException e) { throw e;
    } catch (RoutingMoveConflictException e) { throw e; }
    catch (RoutingMoveUnavailableException e) { throw e; }
    catch (Exception) { throw new RoutingMoveUnavailableException(); }
}

private bool transition(RedisDatabase db, const RoutingMove move, string script, string[] extra = []) {
    if (!isRoutingMoveId(move.moveId) || !validNetworkId(move.networkId)
            || !validServerId(move.fromServerId) || !validServerId(move.targetServerId)
            || move.fromServerId == move.targetServerId)
        throw new RoutingMoveConflictException("Invalid routing move identity");
    return runNetworkWrite!bool(db, (ref NetworkWriter writer) {
        return transition(db, move, script, extra, writer);
    });
}

private bool transition(RedisDatabase db, const RoutingMove move, string script,
        string[] extra, ref NetworkWriter writer) {
    if (!isRoutingMoveId(move.moveId) || !validNetworkId(move.networkId)
            || !validServerId(move.fromServerId) || !validServerId(move.targetServerId)
            || move.fromServerId == move.targetServerId)
        throw new RoutingMoveConflictException("Invalid routing move identity");
    try {
        return runNetworkRedisMutation!bool(writer, (RedisDatabase actualDb) {
        auto reply = actualDb.eval!string(script,
            [RedisKeys.routingMove(move.networkId), RedisKeys.routingMoveStatus(move.moveId),
             RedisKeys.networkAssignments()],
            [move.moveId, move.networkId, move.fromServerId, move.targetServerId,
             MOVE_RESULT_SECONDS.to!string] ~ extra);
        if (reply.empty) throw new RoutingMoveUnavailableException();
        return reply.front == "1";
        });
    } catch (NetworkWriteUnavailableException e) { throw e; }
    catch (RoutingMoveUnavailableException e) { throw e; }
    catch (Exception) { throw new RoutingMoveUnavailableException(); }
}

bool beginRoutingMove(RedisDatabase db, const RoutingMove move) {
    return transition(db, move, BEGIN_SCRIPT);
}
bool beginRoutingMove(RedisDatabase db, const RoutingMove move, ref NetworkWriter writer) {
    return transition(db, move, BEGIN_SCRIPT, [], writer);
}
bool acknowledgeNetworkMoveClosed(RedisDatabase db, const RoutingMove move) {
    return transition(db, move, ACK_SCRIPT);
}
bool acknowledgeNetworkMoveClosed(RedisDatabase db, const RoutingMove move, ref NetworkWriter writer) {
    return transition(db, move, ACK_SCRIPT, [], writer);
}
bool failRoutingMove(RedisDatabase db, const RoutingMove move, string reason, string state = "failed") {
    if (state != "failed" && state != "expired") throw new RoutingMoveConflictException("Invalid failure state");
    return transition(db, move, FAIL_SCRIPT, [reason, state]);
}
bool failRoutingMove(RedisDatabase db, const RoutingMove move, string reason,
        ref NetworkWriter writer, string state = "failed") {
    if (state != "failed" && state != "expired") throw new RoutingMoveConflictException("Invalid failure state");
    return transition(db, move, FAIL_SCRIPT, [reason, state], writer);
}
bool commitRoutingMove(RedisDatabase db, const RoutingMove move,
    string destinationControlJson, string expectedPolicyRaw, string expectedTargetData,
    const string[string] expectedAssignments) {
    auto args = prepareRoutingCommit(move, destinationControlJson, expectedPolicyRaw,
        expectedTargetData, expectedAssignments);
    return runNetworkWrite!bool(db, (ref NetworkWriter writer) {
        return commitPreparedRoutingMove(move, args, writer);
    });
}

bool commitRoutingMove(RedisDatabase db, const RoutingMove move,
        string destinationControlJson, string expectedPolicyRaw, string expectedTargetData,
        const string[string] expectedAssignments, ref NetworkWriter writer) {
    auto args = prepareRoutingCommit(move, destinationControlJson, expectedPolicyRaw,
        expectedTargetData, expectedAssignments);
    return commitPreparedRoutingMove(move, args, writer);
}

private string[] prepareRoutingCommit(const RoutingMove move, string destinationControlJson,
        string expectedPolicyRaw, string expectedTargetData, const string[string] expectedAssignments) {
    if (!isRoutingMoveId(move.moveId) || !validNetworkId(move.networkId)
            || !validServerId(move.fromServerId) || !validServerId(move.targetServerId)
            || move.fromServerId == move.targetServerId)
        throw new RoutingMoveConflictException("Invalid routing move identity");
    // A malformed caller cannot turn the atomic commit into a different action.
    try {
        auto control = parseJsonString(destinationControlJson);
        if (control["action"].type != Json.Type.string || control["action"].get!string != "addNetwork"
                || control["networkId"].type != Json.Type.string || control["networkId"].get!string != move.networkId
                || !expectedPolicyRaw.length || !expectedTargetData.length)
            throw new RoutingMoveConflictException("Invalid destination control");
        // Reuse exactly the assignment snapshot used for capacity validation.
        // An unrelated claim/move may conservatively invalidate this commit.
        string[9] fixedArgs = [move.moveId, move.networkId, move.fromServerId,
            move.targetServerId, MOVE_RESULT_SECONDS.to!string, destinationControlJson,
            expectedPolicyRaw, expectedTargetData, NETWORK_ROUTING_LEASE_TTL_SECONDS.to!string];
        auto args = new string[fixedArgs.length + 2 * expectedAssignments.length];
        args[0 .. fixedArgs.length] = fixedArgs[];
        size_t next = fixedArgs.length;
        foreach (id, owner; expectedAssignments) {
            args[next++] = id;
            args[next++] = owner;
        }
        return args;
    } catch (RoutingMoveConflictException e) { throw e; }
    catch (Exception) { throw new RoutingMoveUnavailableException(); }
}

private bool commitPreparedRoutingMove(const RoutingMove move, string[] args, ref NetworkWriter writer) {
    try {
        return runNetworkRedisMutation!bool(writer, (RedisDatabase actualDb) {
                auto reply = actualDb.eval!string(COMMIT_SCRIPT,
                    [RedisKeys.routingMove(move.networkId), RedisKeys.routingMoveStatus(move.moveId),
                     RedisKeys.networkAssignments(), RedisKeys.lease(move.networkId), RedisKeys.control(move.targetServerId),
                     RedisKeys.egressRoutingPolicy(), RedisKeys.server(move.targetServerId), RedisKeys.draining(move.targetServerId),
                     RedisKeys.routingSchemaVersion(), RedisKeys.serverAssignments(move.fromServerId),
                     RedisKeys.cmd(move.fromServerId, move.networkId), RedisKeys.cmd(move.targetServerId, move.networkId)],
                    args);
                if (reply.empty) throw new RoutingMoveUnavailableException();
                return reply.front == "1";
            });
    } catch (NetworkWriteUnavailableException e) { throw e; }
    catch (RoutingMoveConflictException e) { throw e; }
    catch (RoutingMoveUnavailableException e) { throw e; }
    catch (Exception) { throw new RoutingMoveUnavailableException(); }
}

// All mutation scripts validate the complete stored identity before touching
// it. Missing/expired fences never get recreated by an old queued operation.
private enum STATUS_FUNCTIONS = q"LUA
local function validNetwork(id)
  if #id ~= 36 or string.sub(id, 9, 9) ~= '-' or string.sub(id, 14, 14) ~= '-'
      or string.sub(id, 19, 19) ~= '-' or string.sub(id, 24, 24) ~= '-' then return false end
  local hex = string.gsub(id, '-', '')
  return #hex == 32 and hex ~= string.rep('0', 32) and not string.find(hex, '[^0-9a-fA-F]')
end
local function validServer(id)
  return #id > 0 and #id <= 128 and not string.find(id, '[%z%s%c]')
end
local fields = {'moveId','networkId','fromServerId','targetServerId','state','error','sourceClosed','ackServerId','createdAtMs'}
local function readStatus(key)
  if redis.call('EXISTS', key) == 0 then return nil end
  if redis.call('HLEN', key) ~= #fields then error('malformed routing move status') end
  local values = redis.call('HMGET', key, unpack(fields))
  local s = {}
  for i, name in ipairs(fields) do
    if not values[i] then error('malformed routing move status') end
    s[name] = values[i]
  end
  if #s.moveId ~= 32 or string.find(s.moveId, '[^0-9a-f]') or not validNetwork(s.networkId)
      or not validServer(s.fromServerId) or not validServer(s.targetServerId) or s.fromServerId == s.targetServerId
      or not string.match(s.createdAtMs, '^[1-9]%d*$') or #s.createdAtMs > 16
      or tonumber(s.createdAtMs) > 9007199254740991
      or (s.sourceClosed ~= '0' and s.sourceClosed ~= '1')
      or (s.sourceClosed == '1' and s.ackServerId ~= s.fromServerId)
      or (s.sourceClosed == '0' and s.ackServerId ~= '')
      or (s.state ~= 'queued' and s.state ~= 'processing' and s.state ~= 'completed' and s.state ~= 'failed' and s.state ~= 'expired')
      or (s.state == 'queued' and s.sourceClosed ~= '0')
      or (s.state == 'completed' and s.sourceClosed ~= '1') then error('malformed routing move status') end
  return s
end
local function unfinished(s) return s and (s.state == 'queued' or s.state == 'processing') end
local function matching(s)
  return s and s.moveId == ARGV[1] and s.networkId == ARGV[2]
    and s.fromServerId == ARGV[3] and s.targetServerId == ARGV[4]
end
local function owns(s)
  return redis.call('GET', KEYS[1]) == s.moveId
    and redis.call('HGET', KEYS[3], s.networkId) == s.fromServerId
end
local function targetLive(key, drainingKey, raw)
  if redis.call('HGET', key, 'data') ~= raw or redis.call('EXISTS', drainingKey) ~= 0
      or redis.call('HGET', key, 'draining') == 'true' then return false end
  local ok, t = pcall(cjson.decode, raw)
  if not ok or type(t) ~= 'table' or t.routingPolicyVersion ~= 1 or t.draining == true then return false end
  local health = redis.call('HGET', key, 'isHealthy')
  if health then
    if health ~= 'true' then return false end
  elseif t.isHealthy ~= true then return false end
  local heartbeat = tonumber(redis.call('HGET', key, 'lastHeartbeat') or t.lastHeartbeat)
  local time = redis.call('TIME')
  local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
  return heartbeat and heartbeat > 0 and heartbeat <= now + 1000 and now - heartbeat < 60000
end
LUA";

private enum CREATE_SCRIPT = STATUS_FUNCTIONS ~ q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return 'maintenance' end
local existing = redis.call('GET', KEYS[1])
if existing then return existing end
if redis.call('GET', KEYS[7]) ~= '1' or not targetLive(KEYS[5], KEYS[6], ARGV[5]) then return 'conflict' end
local owner = redis.call('HGET', KEYS[4], ARGV[2])
if not owner or not validServer(owner) or owner == ARGV[3] then return 'conflict' end
if redis.call('EXISTS', KEYS[2]) ~= 0 then error('routing move token collision') end
local queueType = redis.call('TYPE', KEYS[3]).ok
if queueType ~= 'none' and queueType ~= 'list' then error('invalid routing move queue') end
local s = {moveId=ARGV[1],networkId=ARGV[2],fromServerId=owner,targetServerId=ARGV[3],state='queued',error='',sourceClosed=false,ackServerId='',createdAtMs=tonumber(ARGV[4])}
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[6])
redis.call('HSET', KEYS[2], 'moveId', s.moveId, 'networkId', s.networkId, 'fromServerId', s.fromServerId,
  'targetServerId', s.targetServerId, 'state', s.state, 'error', '', 'sourceClosed', '0', 'ackServerId', '', 'createdAtMs', ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[7])
redis.call('RPUSH', KEYS[3], cjson.encode(s))
return s.moveId
LUA";

private enum LOAD_SCRIPT = STATUS_FUNCTIONS ~ q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then error('network maintenance') end
local s = readStatus(KEYS[1])
if not s then return '' end
if s.moveId ~= ARGV[1] then error('routing move status identity mismatch') end
if unfinished(s) and redis.call('GET', ARGV[2] .. s.networkId) ~= s.moveId
    and redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') == 0 then
  s.state = 'expired'
  s.error = 'Routing move fence expired'
  redis.call('HSET', KEYS[1], 'state', s.state, 'error', s.error)
  redis.call('EXPIRE', KEYS[1], ARGV[3])
end
s.sourceClosed = s.sourceClosed == '1'
s.createdAtMs = tonumber(s.createdAtMs)
return cjson.encode(s)
LUA";

private enum BEGIN_SCRIPT = STATUS_FUNCTIONS ~ q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return '0' end
local s = readStatus(KEYS[2])
if not matching(s) or s.state ~= 'queued' or not owns(s) then return '0' end
redis.call('HSET', KEYS[2], 'state', 'processing')
redis.call('EXPIRE', KEYS[2], ARGV[5])
return '1'
LUA";

private enum ACK_SCRIPT = STATUS_FUNCTIONS ~ q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return '0' end
local s = readStatus(KEYS[2])
if not matching(s) or s.state ~= 'processing' or not owns(s) then return '0' end
redis.call('HSET', KEYS[2], 'sourceClosed', '1', 'ackServerId', s.fromServerId)
redis.call('EXPIRE', KEYS[2], ARGV[5])
return '1'
LUA";

private enum FAIL_SCRIPT = STATUS_FUNCTIONS ~ q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return '0' end
local s = readStatus(KEYS[2])
if not matching(s) or not unfinished(s) then return '0' end
local fence = redis.call('GET', KEYS[1])
local state = ARGV[7]
if fence ~= s.moveId then state = 'expired' end
redis.call('HSET', KEYS[2], 'state', state, 'error', ARGV[6])
redis.call('EXPIRE', KEYS[2], ARGV[5])
if fence == s.moveId then redis.call('DEL', KEYS[1]) end
return '1'
LUA";

private enum COMMIT_SCRIPT = STATUS_FUNCTIONS ~ q"LUA
if redis.call('EXISTS', 'irc:holder:maintenance:write-exclusion') ~= 0 then return '0' end
local s = readStatus(KEYS[2])
if not matching(s) or s.state ~= 'processing' or not owns(s)
    or s.sourceClosed ~= '1' or s.ackServerId ~= s.fromServerId then return '0' end
if redis.call('GET', KEYS[9]) ~= '1' or redis.call('GET', KEYS[6]) ~= ARGV[7]
    or not targetLive(KEYS[7], KEYS[8], ARGV[8]) then return '0' end
-- Capacity was validated against these exact canonical assignments. Neither
-- another claim nor another move may consume its slot before this commit.
if redis.call('HLEN', KEYS[3]) ~= (#ARGV - 9) / 2 then return '0' end
for i = 10, #ARGV, 2 do
  if redis.call('HGET', KEYS[3], ARGV[i]) ~= ARGV[i + 1] then return '0' end
end
local queueType = redis.call('TYPE', KEYS[5]).ok
local mirrorType = redis.call('TYPE', KEYS[10]).ok
local sourceCommandsType = redis.call('TYPE', KEYS[11]).ok
local targetCommandsType = redis.call('TYPE', KEYS[12]).ok
if (sourceCommandsType ~= 'none' and sourceCommandsType ~= 'list')
    or (targetCommandsType ~= 'none' and targetCommandsType ~= 'list') then
  error('invalid routing move command storage')
end
if (queueType ~= 'none' and queueType ~= 'list') or (mirrorType ~= 'none' and mirrorType ~= 'hash') then
  error('invalid routing move destination storage')
end
redis.call('HSET', KEYS[3], s.networkId, s.targetServerId)
redis.call('SET', KEYS[4], s.targetServerId, 'EX', ARGV[9])
-- RPUSH producers / BLPOP consumers dispatch accepted commands FIFO.
-- Moving from the old tail to the new head preserves source dispatch order
-- before any pre-existing target backlog.
local pending = redis.call('LLEN', KEYS[11])
for i = 1, pending do redis.call('RPOPLPUSH', KEYS[11], KEYS[12]) end
redis.call('DEL', KEYS[11])
redis.call('LPUSH', KEYS[5], ARGV[6])
-- The source close is now proven; its reverse mirror must not resurrect it
-- after eviction of the canonical assignment hash.
redis.call('HDEL', KEYS[10], s.networkId)
redis.call('HSET', KEYS[2], 'state', 'completed', 'error', '')
redis.call('EXPIRE', KEYS[2], ARGV[5])
redis.call('DEL', KEYS[1])
return '1'
LUA";
