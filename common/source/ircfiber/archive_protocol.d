module ircfiber.archive_protocol;

import std.uuid : UUID, parseUUID;
import vibe.data.json : Json;

/// Engines advertise this only after durable spool/control initialization.
enum int archiveProtocolVersion = 1;
enum long archiveProjectionTtlSeconds = 90;
enum long archiveRetentionSeconds = 7 * 24 * 60 * 60;
enum long archiveProjectionMaxAgeMs = archiveProjectionTtlSeconds * 1_000;
enum long archiveOwnerMaxAgeMs = archiveRetentionSeconds * 1_000;

/// Persistent provenance is bounded by distinct engines, not migration count.
/// Pending groups never expire; terminal routing has journal-status retention.
enum size_t archiveMaxHistoricalServers = 64;
enum size_t archiveClearGroupMaxBytes = 16_384;

string archiveClearGroupKey(string operationId) {
    return "irc:archive:clear:" ~ operationId;
}

string archiveLookupKey(string serverId, string operationId) {
    return "irc:archive:lookup:" ~ serverId ~ ":" ~ operationId;
}

/// Archive retries cannot grow an unreachable engine's control queue forever.
enum string archiveDispatchControlLua = q"LUA
local kind = redis.call('TYPE', KEYS[1]).ok
if kind ~= 'none' and kind ~= 'list' then return 'unknown' end
if redis.call('LLEN', KEYS[1]) >= 1024 then return 'full' end
-- FIFO wakeups cannot let newer retries continually displace older intents.
redis.call('RPUSH', KEYS[1], ARGV[1]); return '1'
LUA";

/// Validate the retained projection without mistaking malformed data for an
/// empty catalog. The original single-server format is imported losslessly.
Json archiveOwnerServers(Json owner, string network) {
    if (owner.type != Json.Type.object || owner["version"].type != Json.Type.int_
        || owner["version"].get!int != archiveProtocolVersion
        || owner["networkId"].type != Json.Type.string || owner["networkId"].get!string != network
        || owner["serverId"].type != Json.Type.string || !owner["serverId"].get!string.length
        || owner["serverId"].get!string.length > 128) return Json(null);
    auto servers = owner["servers"].type == Json.Type.undefined ? Json([owner["serverId"]]) : owner["servers"];
    if (servers.type != Json.Type.array || !servers.length || servers.length > archiveMaxHistoricalServers)
        return Json(null);
    bool original;
    foreach (i, server; servers.get!(Json[])) {
        if (server.type != Json.Type.string || !server.get!string.length || server.get!string.length > 128)
            return Json(null);
        foreach (j; 0 .. i) if (servers[j].get!string == server.get!string) return Json(null);
        if (server.get!string == owner["serverId"].get!string) original = true;
    }
    return original ? servers : Json(null);
}


/// Install a freshly majority-read catalog, unioning (never replacing) prior
/// provenance. Only callers with durable canonical scope evidence use this.
/// KEYS: owner. ARGV: network, scopes JSON, time.
enum string archiveInstallCatalogLua = q"LUA
local ok, scopes = pcall(cjson.decode, ARGV[2])
if not ok or type(scopes) ~= 'table' or #scopes < 1 or #scopes > 64 then return 'unknown' end
local seen = {}
for _,id in ipairs(scopes) do
    if type(id) ~= 'string' or #id == 0 or #id > 128 or seen[id] then return 'unknown' end
    seen[id] = true
end
local original = scopes[1]
local raw = redis.call('GET', KEYS[1])
if raw then
    local valid,old = pcall(cjson.decode, raw)
    if not valid or old.version ~= 1 or old.networkId ~= ARGV[1]
        or type(old.serverId) ~= 'string' or #old.serverId == 0 or #old.serverId > 128 then return 'unknown' end
    local prior = old.servers or {old.serverId}
    if type(prior) ~= 'table' or #prior < 1 or #prior > 64 then return 'unknown' end
    local priorSeen = {}
    for _,id in ipairs(prior) do
        if type(id) ~= 'string' or #id == 0 or #id > 128 or priorSeen[id] then return 'unknown' end
        priorSeen[id] = true
        if not seen[id] then
            if #scopes == 64 then return 'full' end
            table.insert(scopes,id); seen[id] = true
        end
    end
    if not priorSeen[old.serverId] then return 'unknown' end
    original = old.serverId
end
redis.call('SET', KEYS[1], cjson.encode({version=1,networkId=ARGV[1],serverId=original,
    servers=scopes,sampledAtMs=tonumber(ARGV[3])}), 'EX', 604800)
return '1'
LUA";

/// KEYS: group, owner. ARGV: id,user,network,buffer,time,statusOnly,coordinator,lookupToken.
/// Reserve bounded routing metadata, NOT completion or a cutoff. The processor
/// barrier freezes both historical scopes and cutoff together below.
enum string archiveCaptureClearGroupLua = q"LUA
local raw = redis.call('GET', KEYS[1])
if raw then
    local ok,g = pcall(cjson.decode, raw)
    if not ok or g.version ~= 1 or type(g.servers) ~= 'table' then return 'unknown' end
    if g.operationId ~= ARGV[1] or g.userId ~= ARGV[2] or g.networkId ~= ARGV[3]
        or (ARGV[4] ~= '' and g.buffer ~= '' and g.buffer ~= ARGV[4]) then return 'conflict' end
    if g.unrecoverable then return raw end
    if ARGV[6] ~= '1' and g.queryOnly then
        g.queryOnly, g.absent, g.state = false, nil, 'requested'
        if g.buffer == '' then g.buffer = ARGV[4] end
        raw = cjson.encode(g); redis.call('SET', KEYS[1],raw)
    end
    return raw
end
if ARGV[6] == '1' then return 'unknown' end
local ownerRaw = redis.call('GET', KEYS[2])
if not ownerRaw then return 'unknown' end
local ok,owner = pcall(cjson.decode, ownerRaw)
if not ok or owner.version ~= 1 or owner.networkId ~= ARGV[3] then return 'unknown' end
local servers = owner.servers or {owner.serverId}
if type(servers) ~= 'table' or #servers < 1 or #servers > 64 then return 'unknown' end
local seen = {}
for _,id in ipairs(servers) do
    if type(id) ~= 'string' or #id == 0 or #id > 128 or seen[id] then return 'unknown' end
    seen[id] = true
end
if not seen[owner.serverId] then return 'unknown' end
if ARGV[7] ~= '' and not seen[ARGV[7]] then
    if #ARGV[7] > 128 or #servers == 64 then return 'full' end
    table.insert(servers,ARGV[7]); seen[ARGV[7]] = true
end
local pending = 'irc:archive:clear-pending:' .. owner.serverId
local kind = redis.call('TYPE', pending).ok
if kind ~= 'none' and kind ~= 'set' then return 'unknown' end
if redis.call('SCARD', pending) >= 128 then return 'full' end
local networkPending = 'irc:archive:clear-network-pending:' .. ARGV[3]
local nkind = redis.call('TYPE', networkPending).ok
if nkind ~= 'none' and nkind ~= 'set' then return 'unknown' end
if redis.call('SCARD', networkPending) >= 128 then return 'full' end
local coordinator = seen[ARGV[7]] and ARGV[7] or owner.serverId
local g = {version=1,operationId=ARGV[1],userId=ARGV[2],networkId=ARGV[3],
    buffer=ARGV[4],serverId=owner.serverId,coordinator=coordinator,servers=servers,cutoffEid=0,
    legacyTimestampCutoffMs=0,createdAtMs=tonumber(ARGV[5]),updatedAtMs=tonumber(ARGV[5]),
    queryOnly=ARGV[6]=='1',lookupToken=ARGV[8],state='requested'}
local encoded = cjson.encode(g)
redis.call('SET', KEYS[1], encoded)
redis.call('SADD', pending, ARGV[1])
redis.call('SADD', networkPending, ARGV[1])
return encoded
LUA";

/// Called only by the elected engine at ARCHIVE_CONTROL FIFO consumption.
/// Scope registration and this snapshot serialize in Redis, so a destination
/// can never archive a pre-cutoff row without being included in the clear.
/// KEYS: group, owner, global eid, assignments. ARGV: id,user,network,buffer,server,time.
enum string archiveFreezeClearGroupLua = q"LUA
local raw = redis.call('GET', KEYS[1])
if not raw then return 'unknown' end
local ok,g = pcall(cjson.decode, raw)
if not ok or g.version ~= 1 or g.operationId ~= ARGV[1] or g.userId ~= ARGV[2]
    or g.networkId ~= ARGV[3] or (ARGV[4] ~= '' and g.buffer ~= '' and g.buffer ~= ARGV[4]) then return 'conflict' end
if g.unrecoverable then return raw end
if type(g.cutoffEid) ~= 'number' then return 'unknown' end
if g.cutoffEid > 0 then return raw end
if g.coordinator ~= ARGV[5] then return 'wait' end
local ownerRaw = redis.call('GET', KEYS[2])
if not ownerRaw then return 'unknown' end
local valid,owner = pcall(cjson.decode, ownerRaw)
if not valid or owner.version ~= 1 or owner.networkId ~= ARGV[3] then return 'unknown' end
local servers = owner.servers or {owner.serverId}
if type(servers) ~= 'table' or #servers < 1 or #servers > 64 then return 'unknown' end
local seen = {}
for _,id in ipairs(servers) do
    if type(id) ~= 'string' or #id == 0 or #id > 128 or seen[id] then return 'unknown' end
    seen[id] = true
end
local assigned = redis.call('HGET', KEYS[4], ARGV[3])
if assigned then
    if #assigned == 0 or #assigned > 128 then return 'unknown' end
    if not seen[assigned] then
        if #servers == 64 then return 'full' end
        table.insert(servers,assigned); seen[assigned] = true
    end
end
if assigned and assigned ~= g.coordinator then
    g.coordinator, g.servers = assigned, servers
    redis.call('SET', KEYS[1], cjson.encode(g)); return 'wait'
end
if not seen[g.serverId] or not seen[g.coordinator] then return 'unknown' end
-- Resolve retained IDs in EVERY scope before allocating any cutoff. A lost
-- coordinated fence with retained local evidence is unknown, never rebuilt.
local cutoff, timestamp
for _,server in ipairs(servers) do
    local key = 'irc:archive:lookup:' .. server .. ':' .. g.operationId
    if redis.call('STRLEN', key) > 8192 then return 'unknown' end
    local observation = redis.call('GET', key)
    if not observation then
        g.servers = servers; redis.call('SET', KEYS[1], cjson.encode(g)); return 'wait'
    end
    local good,s = pcall(cjson.decode, observation)
    if not good or s.version ~= 1 or s.operationId ~= g.operationId or s.userId ~= g.userId
        or s.networkId ~= g.networkId or s.serverId ~= server then return 'conflict' end
    if s.lookupToken ~= g.lookupToken then
        g.servers = servers; redis.call('SET', KEYS[1], cjson.encode(g)); return 'wait'
    end
    if type(s.hasLiveProducer) ~= 'boolean' then return 'unknown' end
    if s.hasLiveProducer and (not assigned or server ~= assigned) then return 'unknown' end
    if s.state ~= 'not_found' then
        if type(s.buffer) ~= 'string' or #s.buffer == 0 or #s.buffer > 512 then return 'unknown' end
        if g.buffer == '' then g.buffer = s.buffer
        elseif s.buffer ~= g.buffer then return 'conflict' end
        if s.state ~= 'requested' and s.state ~= 'admitted' and s.state ~= 'completed'
            and s.state ~= 'failed' and s.state ~= 'unknown' then return 'unknown' end
        if type(s.cutoffEid) ~= 'number' or s.cutoffEid <= 0
            or type(s.legacyTimestampCutoffMs) ~= 'number' or s.legacyTimestampCutoffMs <= 0 then return 'unknown' end
        if cutoff and (cutoff ~= s.cutoffEid or timestamp ~= s.legacyTimestampCutoffMs) then return 'conflict' end
        cutoff, timestamp = s.cutoffEid, s.legacyTimestampCutoffMs
    end
end
if cutoff then
    -- The durable local ID survived but the coordinated incarnation set did
    -- not. Reconstructing it from current reusable names could clear later
    -- content. Retain an explicit unknown tombstone; NEVER invent a new cut.
    g.servers, g.unrecoverable, g.queryOnly, g.state = servers, true, true, 'unknown'
    local unknown = cjson.encode(g); redis.call('SET', KEYS[1], unknown); return unknown
end
-- Pin ALL physical incarnations in the same atomic barrier. An original
-- server may return as live owner before its purge is delivered; capturing
-- its then-current reusable name would be too late.
local keys, tokens = {}, {}
for i,server in ipairs(servers) do
    keys[i] = 'scrollback:' .. server .. ':' .. g.networkId .. ':' .. g.buffer
end
keys[#keys+1] = 'scrollback:' .. g.networkId .. ':' .. g.buffer
for i,key in ipairs(keys) do
    local kind = redis.call('TYPE', key).ok
    if kind ~= 'none' and kind ~= 'list' then return 'unknown' end
    lineageReconcile(key)
    if redis.call('EXISTS', key) == 0 then lineageRetire(key); tokens[i] = ''
    else
        tokens[i] = lineageEnsure(key)
        local refs = tonumber(redis.call('HGET', lineageLocator(tokens[i]), 'refs'))
        if not refs or refs >= 128 then return 'full' end
    end
end
for i,token in ipairs(tokens) do
    if token ~= '' then
        redis.call('HINCRBY', lineageLocator(token), 'refs', 1)
        redis.call('PERSIST', lineageLocator(token))
        redis.call('PERSIST', lineageCompanion(keys[i]))
    end
end
local legacyToken = tokens[#tokens]; tokens[#tokens] = nil
g.scopedLineageIds, g.legacyLineageId, g.legacyCaptured = tokens, legacyToken, true
g.queryOnly, g.absent, g.state = false, nil, 'requested'
g.servers, g.cutoffEid, g.legacyTimestampCutoffMs = servers, redis.call('INCR', KEYS[3]), tonumber(ARGV[6])
g.updatedAtMs = tonumber(ARGV[6])
local encoded = cjson.encode(g)
redis.call('SET', KEYS[1], encoded)
return encoded
LUA";

/// KEYS: group. ARGV: time,id. Background completion housekeeping, never an
/// independent proof for the HTTP response. All journals must acknowledge.
enum string archiveCompleteGroupLua = q"LUA
if redis.call('STRLEN', KEYS[1]) > 16384 then return 'unknown' end
local raw = redis.call('GET', KEYS[1])
if not raw then return 'pending' end
local ok,g = pcall(cjson.decode, raw)
if not ok or g.version ~= 1 or g.operationId ~= ARGV[2]
    or type(g.serverId) ~= 'string' or #g.serverId == 0 or #g.serverId > 128
    or type(g.servers) ~= 'table' or #g.servers < 1 or #g.servers > 64
    or type(g.cutoffEid) ~= 'number' or g.cutoffEid <= 0 then return 'pending' end
if g.state == 'completed' then return '1' end
for _,server in ipairs(g.servers) do
    if type(server) ~= 'string' or #server == 0 or #server > 128 then return 'unknown' end
    local key = 'irc:archive:operation:' .. server .. ':' .. g.operationId
    if redis.call('STRLEN', key) > 8192 then return 'unknown' end
    local operationRaw = redis.call('GET', key)
    if not operationRaw then return 'pending' end
    local valid,s = pcall(cjson.decode, operationRaw)
    if not valid or s.version ~= 1 or s.operationId ~= g.operationId or s.userId ~= g.userId
        or s.networkId ~= g.networkId or s.serverId ~= server or s.buffer ~= g.buffer
        or s.cutoffEid ~= g.cutoffEid or s.legacyTimestampCutoffMs ~= g.legacyTimestampCutoffMs
        or s.state ~= 'completed' or s.durable ~= true or s.redisApplied ~= true
        or type(s.sequence) ~= 'number' or s.sequence <= 0
        or type(s.updatedAtMs) ~= 'number' or s.updatedAtMs <= 0
        or s.updatedAtMs > tonumber(ARGV[1])+5000
        or tonumber(ARGV[1])-s.updatedAtMs > 604800000 then return 'pending' end
end
local completed = 'irc:archive:clear-completed:' .. g.serverId
local pending = 'irc:archive:clear-pending:' .. g.serverId
local networkPending = 'irc:archive:clear-network-pending:' .. g.networkId
local kind = redis.call('TYPE', completed).ok
if kind ~= 'none' and kind ~= 'zset' then return 'unknown' end
if redis.call('ZCARD', completed) > 1024 then return 'unknown' end
for _,key in ipairs({pending,networkPending}) do
    local t = redis.call('TYPE', key).ok
    if t ~= 'none' and t ~= 'set' then return 'unknown' end
end
g.state, g.updatedAtMs = 'completed', tonumber(ARGV[1])
redis.call('SET', KEYS[1], cjson.encode(g), 'EX', 604800)
redis.call('SREM', pending, g.operationId)
redis.call('SREM', networkPending, g.operationId)
redis.call('ZADD', completed, ARGV[1], g.operationId)
for _,id in ipairs(redis.call('ZRANGEBYSCORE', completed, '-inf', tonumber(ARGV[1])-604800000, 'LIMIT', 0, 1024)) do
    redis.call('DEL', 'irc:archive:clear:' .. id); redis.call('ZREM', completed, id)
end
local excess = redis.call('ZCARD', completed)-1024
if excess > 0 then
    for _,id in ipairs(redis.call('ZRANGE', completed, 0, excess-1)) do
        redis.call('DEL', 'irc:archive:clear:' .. id); redis.call('ZREM', completed, id)
    end
end
redis.call('EXPIRE', completed, 604800)
return '1'
LUA";

bool validArchiveClearGroup(Json group, string id, string user, string network, string buffer = "") {
    if (group.type != Json.Type.object
        || group["version"].type != Json.Type.int_
        || group["version"].get!int != archiveProtocolVersion) return false;
    if (group["queryOnly"].type != Json.Type.bool_) return false;
    if (group["lookupToken"].type != Json.Type.string
        || !isCanonicalArchiveOperationId(group["lookupToken"].get!string)) return false;
    foreach (field; ["operationId", "userId", "networkId", "buffer", "serverId", "coordinator"])
        if (group[field].type != Json.Type.string) return false;
    if (group["operationId"].get!string != id || group["userId"].get!string != user
        || group["networkId"].get!string != network
        || (buffer.length && group["buffer"].get!string != buffer)
        || (group["buffer"].get!string.length == 0 && !group["queryOnly"].get!bool)
        || group["buffer"].get!string.length > 512
        || group["cutoffEid"].type != Json.Type.int_ || group["cutoffEid"].get!long < 0
        || (group["cutoffEid"].get!long > 0 && group["queryOnly"].get!bool)
        || group["legacyTimestampCutoffMs"].type != Json.Type.int_
        || group["legacyTimestampCutoffMs"].get!long < 0
        || ((group["cutoffEid"].get!long == 0) != (group["legacyTimestampCutoffMs"].get!long == 0))
        || group["createdAtMs"].type != Json.Type.int_ || group["createdAtMs"].get!long <= 0
        || group["state"].type != Json.Type.string
        || (group["state"].get!string != "requested" && group["state"].get!string != "completed"
            && !(group["state"].get!string == "unknown" && group["queryOnly"].get!bool))
        || group["servers"].type != Json.Type.array || group["servers"].length == 0
        || group["servers"].length > archiveMaxHistoricalServers) return false;
    if (group["cutoffEid"].get!long > 0) {
        if (group["legacyLineageId"].type != Json.Type.string
            || (group["legacyLineageId"].get!string.length
                && !isCanonicalArchiveOperationId(group["legacyLineageId"].get!string))
            || group["legacyCaptured"].type != Json.Type.bool_) return false;
        if (group["scopedLineageIds"].type != Json.Type.array
            || group["scopedLineageIds"].length != group["servers"].length) return false;
        foreach (token; group["scopedLineageIds"])
            if (token.type != Json.Type.string || (token.get!string.length
                && !isCanonicalArchiveOperationId(token.get!string))) return false;
    } else if (group["state"].get!string == "completed") return false;
    bool original, coordinator;
    foreach (i, server; group["servers"].get!(Json[])) {
        if (server.type != Json.Type.string || !server.get!string.length || server.get!string.length > 128)
            return false;
        foreach (j; 0 .. i)
            if (group["servers"][j].get!string == server.get!string) return false;
        if (server.get!string == group["serverId"].get!string) original = true;
        if (server.get!string == group["coordinator"].get!string) coordinator = true;
    }
    return original && coordinator;
}

bool archiveClearGroupIncludes(Json group, string server) {
    foreach (scopeId; group["servers"])
        if (scopeId.get!string == server) return true;
    return false;
}

string archiveOwnerKey(string networkId) {
    return "irc:archive:owner:" ~ networkId;
}

string archiveProjectionKey(string serverId, string networkId) {
    return "irc:archive:status:" ~ serverId ~ ":" ~ networkId;
}

string archiveOperationKey(string serverId, string operationId) {
    return "irc:archive:operation:" ~ serverId ~ ":" ~ operationId;
}

/// Reject alternate spellings so one user action has exactly one journal ID.
bool isCanonicalArchiveOperationId(string value) {
    if (value.length != 36) return false;
    try {
        auto cursor = value;
        const id = parseUUID(cursor);
        return cursor.length == 0 && id != UUID.init && id.toString() == value;
    } catch (Exception) {
        return false;
    }
}

/// Missing, future-dated or expired observations never imply completeness.
bool archiveSampleFresh(long sampledAtMs, long nowMs, long maxAgeMs) {
    return sampledAtMs > 0 && sampledAtMs <= nowMs + 5_000
        && nowMs - sampledAtMs <= maxAgeMs;
}
