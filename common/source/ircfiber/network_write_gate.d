module ircfiber.network_write_gate;

import std.uuid : randomUUID;
import vibe.data.bson : Bson;
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
            : code == "network_write_incomplete"
                ? "Network change acknowledgment is uncertain; do not assume it completed"
                : "Network write coordination is unavailable; a dispatched change may be incomplete");
        this.code = code;
    }
}

/// Stack ownership survives fiber yields. An admitted scope is released only
/// after its coordination-critical work has positively completed.
private struct NetworkWriter {
    private RedisStorage redis;
    private string token;
    private bool confirmed;
    @disable this(this);

    this(RedisStorage redis) {
        if (redis is null || redis.getClient() is null)
            throw new NetworkWriteUnavailableException("network_write_unavailable");
        this.redis = redis;
        token = randomUUID().toString();
        try {
            auto result = redis.getDb().eval!string(NETWORK_WRITER_BEGIN_SCRIPT,
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

    ~this() {
        if (!confirmed) return;
        // Failed/ambiguous removal conservatively retains evidence. Never mask
        // an acknowledged Mongo write with an unrelated Redis/cache failure.
        try redis.getDb().srem(NETWORK_WRITERS_KEY, token);
        catch (Exception) {}
    }
}

/// Holds exclusion through an entire lifecycle operation, including gaps
/// between Mongo writes. Mark unfenced critical dispatch before I/O and
/// confirm its reply; known validation/read failures do not retain a token.
struct NetworkWriteOperation {
    private NetworkWriter writer;
    @disable this();
    @disable this(this);

    this(RedisStorage redis) {
        writer = NetworkWriter(redis);
        writer.confirmed = true;
        version (RoutingPolicyTest) {
            if (networkOperationAdmittedForTest !is null)
                networkOperationAdmittedForTest(writer.token);
        }
    }

    void beginDispatch() @safe nothrow {
        writer.confirmed = false;
    }

    void confirmCompletion() {
        version (RoutingPolicyTest) {
            if (networkOperationRepliedForTest !is null) {
                writer.confirmed = false;
                networkOperationRepliedForTest(writer.token);
            }
        }
        writer.confirmed = true;
    }
}

/// Execute one canonical mutation. The command must be completely constructed
/// before admission. Every exception after dispatch retains the writer token,
/// including a malformed acknowledgement or write-concern uncertainty.
Bson runNetworkMutation(RedisStorage redis, Bson command) {
    const updating = command["update"].type == Bson.Type.string && command["update"].get!string == "networks";
    const deleting = command["delete"].type == Bson.Type.string && command["delete"].get!string == "networks";
    const reserving = command["findAndModify"].type == Bson.Type.string && command["findAndModify"].get!string == "networks";
    if (cast(int)updating + cast(int)deleting + cast(int)reserving != 1)
        throw new Exception("Invalid canonical network mutation command");
    command["writeConcern"] = Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
    auto writer = NetworkWriter(redis);
    version (RoutingPolicyTest) {
        if (networkMutationAdmittedForTest !is null) networkMutationAdmittedForTest(writer.token);
    }
    try {
        auto reply = AppMongoConnection.getDb().runCommandUnchecked(command);
        version (RoutingPolicyTest) {
            if (networkMutationRepliedForTest !is null) networkMutationRepliedForTest();
        }
        // A duplicate-key rejection is authoritative command completion:
        // no operation remains in flight. Preserve the allocator's retry protocol.
        if (command["findAndModify"].type == Bson.Type.string
                && numericEquals(reply["ok"], 0)
                && numericEquals(reply["code"], 11000)
                && (reply["writeConcernError"].isNull || reply["writeConcernError"].type == Bson.Type.undefined)) {
            writer.confirmed = true;
            return reply;
        }
        if (!numericEquals(reply["ok"], 1)
                || (!reply["writeErrors"].isNull && reply["writeErrors"].type != Bson.Type.undefined
                    && (reply["writeErrors"].type != Bson.Type.array || reply["writeErrors"].get!(Bson[]).length))
                || (!reply["writeConcernError"].isNull && reply["writeConcernError"].type != Bson.Type.undefined))
            throw new NetworkWriteUnavailableException("network_write_incomplete");
        if ((updating && (!numeric(reply["n"]) || !numeric(reply["nModified"])))
                || (deleting && !numeric(reply["n"]))
                || (reserving && reply["value"].type == Bson.Type.undefined))
            throw new NetworkWriteUnavailableException("network_write_incomplete");
        writer.confirmed = true;
        return reply;
    } catch (NetworkWriteUnavailableException e) { throw e; }
    catch (Exception) {
        throw new NetworkWriteUnavailableException("network_write_incomplete");
    }
}

private bool numeric(Bson value) {
    return value.type == Bson.Type.int_ || value.type == Bson.Type.long_ || value.type == Bson.Type.double_;
}

private bool numericEquals(Bson value, long expected) {
    switch (value.type) {
        case Bson.Type.int_: return value.get!int == expected;
        case Bson.Type.long_: return value.get!long == expected;
        case Bson.Type.double_: return value.get!double == expected;
        default: return false;
    }
}

version (RoutingPolicyTest) {
    /// Deterministic fiber barrier after real Redis admission, before dispatch.
    void delegate(string token) networkMutationAdmittedForTest;
    void delegate() networkMutationRepliedForTest;
    void delegate(string token) networkOperationAdmittedForTest;
    void delegate(string token) networkOperationRepliedForTest;
}
