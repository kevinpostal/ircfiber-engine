module ircfiber.network_write_gate;

import std.uuid : randomUUID;
import vibe.data.bson : Bson;
import vibe.db.redis.redis : RedisDatabase;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.storage.redis : RedisStorage;

/// Shared with the offline collector. Uncertain writers have no lease: only
/// a positively acknowledged completion permits removal of their token.
enum NETWORK_WRITE_EXCLUSION_KEY = "irc:holder:maintenance:write-exclusion";
enum NETWORK_WRITERS_KEY = "irc:holder:maintenance:writers";
enum NETWORK_WRITER_LIMIT = 256;

enum NETWORK_WRITER_BEGIN_SCRIPT = q"LUA
if redis.call('EXISTS', KEYS[1]) ~= 0 then return {'maintenance'} end
if redis.call('SCARD', KEYS[2]) >= 256 then return {'saturated'} end
if redis.call('SADD', KEYS[2], ARGV[1]) ~= 1 then return {'collision'} end
return {'admitted'}
LUA";

/// A typed, consumer-visible refusal, never a routing-policy failure.
final class NetworkWriteUnavailableException : Exception {
    immutable string code;
    this(string code = "network_maintenance") {
        super(code == "network_maintenance"
            ? "Network changes are temporarily excluded for holder maintenance"
            : "Network write coordination is unavailable; no change was dispatched");
        this.code = code;
    }
}

/// Preserve the server acknowledgement for typed storage consumers without
/// exposing command contents in the public exception message.
final class NetworkMutationException : Exception {
    Bson reply;
    this(string message, Bson reply) {
        super(message);
        this.reply = reply;
    }
}

/// One stack-owned logical write, including its Mongo, Redis and queue effects.
/// Only the scoped runner can confirm completion; uncertain steps remain sticky
/// even when a caller catches their exception and continues.
struct NetworkWriter {
    private RedisDatabase db;
    private string token;
    private bool confirmed;
    private size_t unconfirmed;
    @disable this(this);

    private this(RedisDatabase db) {
        this.db = db;
        token = randomUUID().toString();
        try {
            auto result = db.eval!string(NETWORK_WRITER_BEGIN_SCRIPT,
                [NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY], token);
            if (result.empty) throw new NetworkWriteUnavailableException("network_write_unavailable");
            const state = result.front.idup;
            if (state == "maintenance") throw new NetworkWriteUnavailableException();
            if (state != "admitted") throw new NetworkWriteUnavailableException("network_write_unavailable");
        } catch (NetworkWriteUnavailableException e) { throw e; }
        catch (Exception) {
            // Admission may have committed before its reply was lost. Do not
            // SREM here, even though Mongo has not yet been dispatched.
            throw new NetworkWriteUnavailableException("network_write_unavailable");
        }
    }

    private void beginStep() {
        if (token.length == 0)
            throw new NetworkWriteUnavailableException("network_write_unavailable");
        ++unconfirmed;
    }

    ~this() {
        if (!confirmed) return;
        // Failed/ambiguous removal conservatively retains evidence. Never mask
        // an acknowledged Mongo write with an unrelated Redis/cache failure.
        try db.srem(NETWORK_WRITERS_KEY, token);
        catch (Exception) {}
    }
}

/// Admit before the first effect and retain ownership across every fiber yield.
/// The collector atomically requires an empty writer set before exclusion, so
/// it cannot close the gate between this operation's acknowledged steps.
/// Canonical effects must use the tracked mutation helpers and must not escape
/// into a detached task. Validate consumer inputs before entering this scope.
T runNetworkWrite(T)(RedisStorage redis, scope T delegate(ref NetworkWriter) body) {
    if (redis is null || redis.getClient() is null)
        throw new NetworkWriteUnavailableException("network_write_unavailable");
    static if (is(T == void)) {
        runNetworkWrite!T(redis.getDb(), body);
    } else {
        return runNetworkWrite!T(redis.getDb(), body);
    }
}

/// Reuse an already connected database without allocating another connection.
T runNetworkWrite(T)(RedisDatabase db, scope T delegate(ref NetworkWriter) body) {
    auto writer = NetworkWriter(db);
    version (RoutingPolicyTest) {
        if (networkMutationAdmittedForTest !is null) networkMutationAdmittedForTest(writer.token);
    }
    static if (is(T == void)) {
        body(writer);
        writer.confirmed = writer.unconfirmed == 0;
    } else {
        auto result = body(writer);
        writer.confirmed = writer.unconfirmed == 0;
        return result;
    }
}

/// Track one synchronous, non-swallowing Redis command or Lua acknowledgement.
/// Use RedisDatabase, not RedisStorage's best-effort convenience methods. An
/// exception leaves this step outstanding even if the outer operation catches.
T runNetworkRedisMutation(T)(ref NetworkWriter writer, scope T delegate(RedisDatabase) body) {
    writer.beginStep();
    static if (is(T == void)) {
        body(writer.db);
        confirmRedisStep(writer);
    } else {
        auto result = body(writer.db);
        confirmRedisStep(writer);
        return result;
    }
}

private void confirmRedisStep(ref NetworkWriter writer) {
    version (RoutingPolicyTest) {
        if (networkRedisMutationRepliedForTest !is null) networkRedisMutationRepliedForTest();
    }
    --writer.unconfirmed;
}

/// An external effect with an unproven outcome may only retain evidence.
/// There is deliberately no public success/confirmation operation.
void retainNetworkWriteUncertainty(ref NetworkWriter writer) {
    writer.beginStep();
}

private enum MutationKind { update, delete_, reserve }

private MutationKind mutationKind(Bson command) {
    const updating = command["update"].type == Bson.Type.string && command["update"].get!string == "networks";
    const deleting = command["delete"].type == Bson.Type.string && command["delete"].get!string == "networks";
    const reserving = command["findAndModify"].type == Bson.Type.string && command["findAndModify"].get!string == "networks";
    if (cast(int)updating + cast(int)deleting + cast(int)reserving != 1)
        throw new Exception("Invalid canonical network mutation command");
    return updating ? MutationKind.update : deleting ? MutationKind.delete_ : MutationKind.reserve;
}

/// A standalone canonical mutation validates its command before admission.
Bson runNetworkMutation(RedisStorage redis, Bson command) {
    const kind = mutationKind(command);
    return runNetworkWrite!Bson(redis, (ref NetworkWriter writer) {
        return runAdmittedNetworkMutation(writer, command, kind);
    });
}

/// Reuse the existing logical owner; never readmit halfway through its effects.
Bson runNetworkMutation(ref NetworkWriter writer, Bson command) {
    return runAdmittedNetworkMutation(writer, command, mutationKind(command));
}

private Bson runAdmittedNetworkMutation(ref NetworkWriter writer, Bson command, MutationKind kind) {
    command["writeConcern"] = Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
    writer.beginStep();
    auto reply = AppMongoConnection.getDb().runCommandUnchecked(command);
    version (RoutingPolicyTest) {
        if (networkMutationRepliedForTest !is null) networkMutationRepliedForTest();
        if (networkMutationReplyObservedForTest !is null) networkMutationReplyObservedForTest(reply);
    }
    bool cleanErrors = reply.type == Bson.Type.object;
    if (cleanErrors) foreach (key, value; reply.byKeyValue) {
        // Presence is uncertainty, including malformed/null concern errors.
        if (key == "writeConcernError"
                || (key == "writeErrors" && (value.type != Bson.Type.array || value.length != 0)))
            cleanErrors = false;
    }
    // A typed duplicate-key rejection is authoritative command completion:
    // no operation remains in flight. Preserve the allocator's retry protocol.
    if (kind == MutationKind.reserve && cleanErrors
            && numeric(reply["ok"]) && reply["ok"].get!double == 0
            && numeric(reply["code"]) && reply["code"].get!double == 11000) {
        --writer.unconfirmed;
        return reply;
    }
    if (!cleanErrors || !numeric(reply["ok"]) || reply["ok"].get!double != 1.0)
        throw new NetworkMutationException("Network mutation did not receive a confirmed Mongo acknowledgement", reply);
    if ((kind == MutationKind.update && (!nonnegativeCount(reply["n"]) || !nonnegativeCount(reply["nModified"])))
            || (kind == MutationKind.delete_ && !nonnegativeCount(reply["n"]))
            || (kind == MutationKind.reserve && reply["value"].type == Bson.Type.undefined))
        throw new NetworkMutationException("Malformed network mutation completion acknowledgement", reply);
    --writer.unconfirmed;
    return reply;
}

private bool numeric(Bson value) {
    return value.type == Bson.Type.int_ || value.type == Bson.Type.long_ || value.type == Bson.Type.double_;
}

private bool nonnegativeCount(Bson value) {
    switch (value.type) {
        case Bson.Type.int_: return value.get!int >= 0;
        case Bson.Type.long_: return value.get!long >= 0;
        case Bson.Type.double_:
            const count = value.get!double;
            return count >= 0 && count <= 9_007_199_254_740_991.0
                && count == cast(double)cast(long)count;
        default: return false;
    }
}

version (RoutingPolicyTest) {
    /// Deterministic fiber barrier after real Redis admission, before dispatch.
    void delegate(string token) networkMutationAdmittedForTest;
    void delegate() networkMutationRepliedForTest;
    void delegate(ref Bson reply) networkMutationReplyObservedForTest;
    void delegate() networkRedisMutationRepliedForTest;
}
