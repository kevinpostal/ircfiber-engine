module ircfiber.irc.dial_guard;

import core.sync.mutex : Mutex;
import std.conv : to;
import std.datetime : Clock;
import std.range : empty, front;
import std.string : startsWith;
import std.algorithm : canFind;
import vibe.db.redis.redis : RedisDatabase;
import ircfiber.irc.nord_capacity : NordPermit, NordVerdict, tryAcquireNordCapacity,
    releaseNordCapacity, nordReservations;
import ircfiber.irc.registration_admission : registrationAdmission;
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

/// Capacity refusals are coordinator outcomes, never observations of an exit.
class NordCapacityException : HolderUnavailableException {
    string reason;
    this(string reason) {
        this.reason = reason;
        super(reason);
    }
}

/// Carries only nonsecret proof coordinates, not a client or relay reference.
class NordDialUnprovenException : DialFailedException {
    string generation, token, incarnation;
    this(string generation, string token, string incarnation) {
        this.generation = generation;
        this.token = token;
        this.incarnation = incarnation;
        super("holder", "Nord holder DIAL completion unproven");
    }
}

/// Only the exact holder's retained terminal evidence proves physical closure.
/// A new instance/PID, missing inventory entry, or an old heartbeat proves
/// nothing about a reservation. Such claims require fenced operator recovery.
/// Enumerating terminal evidence also repairs a release-before-ACK crash: the
/// original generation remains in the holder even when its hash field is gone.
void reconcileNordCapacity(HolderClient holder, RedisStorage redis, string serverId) {
    if (holder is null || redis is null || !serverId.length) return;
    auto status = holder.status();
    if (!status.instance.length || !status.capabilities.canFind("nord-capacity-v1")) return;
    auto terminal = holder.nordTerminalTokens(status.instance);
    if (!terminal.length) return;
    auto db = redis.getDb();
    const reservations = nordReservations(db);
    foreach (evidence; terminal) {
        bool eligible = true;
        foreach (reservation; reservations) if (reservation.token == evidence.token) {
            eligible = reservation.kind == "holder" && reservation.owner == serverId
                && reservation.incarnation == status.instance
                && reservation.generation == evidence.generation;
            break;
        }
        if (!eligible) continue;
        if (registrationAdmission !is null)
            registrationAdmission.resolveNordTerminal(evidence.generation, evidence.token);
        if (releaseNordCapacity(db, evidence.generation, evidence.token))
            holder.ackNordToken(status.instance, evidence.token, evidence.generation);
    }
}

/// Recovery is best effort outside admission. Never interrupt a healthy socket
/// because Redis or the holder control stream is unavailable.
void reconcileNordCapacityQuietly(HolderClient holder, RedisStorage redis, string serverId) nothrow {
    try reconcileNordCapacity(holder, redis, serverId);
    catch (Exception) {}
}

private void deleteDialMarkerQuietly(RedisDatabase db, string key, string token) nothrow {
    try db.hdel(key, token);
    catch (Exception) {}
}

private void releaseUnsentNordCapacityQuietly(RedisDatabase db, string generation, string token) nothrow {
    try releaseNordCapacity(db, generation, token);
    catch (Exception) {}
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
    const nord = req.hasProxy && req.proxy.provider == "nordvpn";
    if (nord) {
        auto status = holder.status();
        if (status.instance != incarnation || !status.capabilities.canFind("nord-capacity-v1"))
            throw new NordCapacityException("nord_capacity_unavailable");
        req.holderInstance = incarnation;
        req.nordCapacityToken = token;
    }
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
    scope(exit) if (terminal) {
        // Failed cleanup retains the marker, without replacing a typed
        // capacity refusal with an unrelated Redis/exit failure.
        deleteDialMarkerQuietly(db, key, token);
    }
    NordPermit capacity;
    scope(exit) if (nord) {
        if (capacity.verdict == NordVerdict.acquired && !sent) {
            // No physical dial occurred (local cancellation or definitive
            // never-admitted response). Unavailable release retains the claim.
            releaseUnsentNordCapacityQuietly(db, capacity.generation, capacity.token);
        }
        // An uncertain failure first transfers its registration proof
        // coordinates to the observer; do not ACK its evidence before that.
        if (sent && terminal) reconcileNordCapacityQuietly(holder, redis, serverId);
        if ((!sent || terminal) && registrationAdmission !is null)
            registrationAdmission.forgetNordAttempt(capacity.generation, token);
    }
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
            if (nord) {
                // The serialized request is bound to this exact incarnation;
                // registration admission may have waited across a reconnect.
                auto status = holder.status();
                if (actualIncarnation != incarnation || status.instance != incarnation
                        || !status.capabilities.canFind("nord-capacity-v1"))
                    throw new NordCapacityException("nord_capacity_unavailable");
                try reconcileNordCapacity(holder, redis, serverId);
                catch (Exception) { throw new NordCapacityException("nord_capacity_unavailable"); }
                capacity = tryAcquireNordCapacity(db, "holder", incarnation, serverId, token);
                if (capacity.verdict != NordVerdict.acquired)
                    throw new NordCapacityException(capacity.reason);
                req.nordCapacityGeneration = capacity.generation;
                if (registrationAdmission !is null)
                    registrationAdmission.trackNordAttempt(capacity.generation, token);
                // Acquisition yields. Refresh all existing fences before the
                // holder may open a proxy socket; failed checks release above.
                validatePolicy();
                if (stopping() || !ownsNetworkForDial(redis, serverId, req.tag.networkId))
                    throw new HolderUnavailableException("connection stopped or fenced after Nord admission");
            }
            if (stopping()) throw new HolderUnavailableException("connection stopped before DIAL");
        }, onResponse, {
            // The client has finished all local validation/serialization.
            // Any failure from this boundary onward is an ambiguous write
            // until the exact holder supplies terminal token evidence.
            terminal = false;
            sent = true;
        });
        terminal = true;
        return result;
    } catch (HolderErrorException e) {
        if (nord && sent && e.code == "nord_not_admitted") {
            // This code is issued only for a validated, previously unseen
            // token that the holder positively refused before any dial.
            sent = false;
            terminal = true;
            throw new NordCapacityException("nord_capacity_unavailable");
        }
        if (nord && sent) {
            // ERR busy can describe a duplicate while its original attempt
            // is pending/open. Only this generation's terminal proof permits
            // retiring the operation or the full-registration claim.
            try terminal = holder.nordTokenStatus(incarnation, token, capacity.generation) == "terminal";
            catch (Exception) { terminal = false; }
            if (!terminal)
                throw new NordDialUnprovenException(capacity.generation, token, incarnation);
        } else terminal = true;
        throw e;
    } catch (DialFailedException e) {
        if (nord && sent) {
            try terminal = holder.nordTokenStatus(incarnation, token, capacity.generation) == "terminal";
            catch (Exception) { terminal = false; }
            if (!terminal)
                throw new NordDialUnprovenException(capacity.generation, token, incarnation);
        } else {
            // A timed-out/malformed IPC stream is not a terminal response.
            terminal = terminal || e.phase != "holder";
        }
        throw e;
    } catch (Exception e) {
        if (nord && sent)
            throw new NordDialUnprovenException(capacity.generation, token, incarnation);
        throw e;
    }
}
