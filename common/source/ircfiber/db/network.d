module ircfiber.db.network;

import std.uuid;
import std.conv;
import std.algorithm;
import std.array;
import vibe.db.mongo.mongo;
import vibe.data.bson;
import vibe.data.json;
import vibe.core.log;
import ircfiber.models.network;
import ircfiber.db.mongo;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : RedisKeys;

/// Repository for network configurations.
final class NetworkRepository {
    private MongoCollection collection;

    /// Global Redis instance, set at boot from app.d / bootstrap.d.
    __gshared RedisStorage g_redis;

    /// Initializes the global Redis reference for cache operations.
    /// Must be called once at boot after Redis is connected.
    static void initRedis(RedisStorage redis) {
        g_redis = redis;
    }

    /// Creates a new network repository.
    this() {
        collection = AppMongoConnection.getDb()["networks"];
    }

    /// Network config paired with its owner user ID.
    struct NetworkWithUser {
        /// Network configuration.
        NetworkConfig config;
        /// Owning user ID.
        UUID userId;
    }

    /// Finds all networks for a user, using Redis cache when available.
    NetworkConfig[] findByUserId(UUID userId) {
        // Try Redis cache first
        if (g_redis !is null) {
            auto key = RedisKeys.userNetworks(userId.toString());
            auto cached = g_redis.getJson(key);
            if (cached.type != Json.Type.null_) {
                return deserializeNetworkConfigs(cached);
            }
        }

        import ircfiber.db.circuit_breaker : mongoAllowRequest, mongoRecordSuccess, mongoRecordFailure;
        if (!mongoAllowRequest()) {
            logWarn("NetworkRepository.findByUserId: circuit breaker open, returning empty");
            return [];
        }
        try {
            NetworkConfig[] result;
            foreach (doc; collection.find(["userId": userId.toString()])) {
                result ~= docToConfig(doc);
            }
            mongoRecordSuccess();

            // Cache in Redis (60s TTL) so frequent reads don't hammer Mongo.
            // The cache is invalidated on every create/update/delete of a network.
            if (g_redis !is null) {
                g_redis.setJson(RedisKeys.userNetworks(userId.toString()), serializeNetworkConfigs(result), 60);
            }

            return result;
        } catch (Exception e) {
            mongoRecordFailure();
            throw e;
        }
    }

    /// Finds all networks with their owners.
    NetworkWithUser[] findAll() {
        NetworkWithUser[] result;
        foreach (doc; collection.find()) {
            result ~= NetworkWithUser(docToConfig(doc), parseUUID(doc["userId"].get!string));
        }
        return result;
    }

    /// Finds a network by its ID.
    NetworkConfig findById(UUID id) {
        auto doc = collection.findOne(["id": id.toString()]);
        if (doc.isNull) return NetworkConfig.init;
        return docToConfig(doc);
    }

    /// Finds a network with its owning userId. Returns a config with
    /// `id == UUID.init` if not found, and a `userId` of
    /// `UUID.init` if the record exists but has no userId field.
    NetworkWithUser findByIdWithUser(UUID id) {
        auto doc = collection.findOne(["id": id.toString()]);
        if (doc.isNull) return NetworkWithUser(NetworkConfig.init, UUID.init);
        UUID uid;
        try uid = parseUUID(doc["userId"].get!string);
        catch (Exception) uid = UUID.init;
        return NetworkWithUser(docToConfig(doc), uid);
    }

    /// Saves or updates a network configuration.
    void save(NetworkConfig config, UUID userId) {
        auto selector = Bson(["id": Bson(config.id.toString())]);
        auto update = Bson([
            "$set": Bson([
                "id": Bson(config.id.toString()),
                "userId": Bson(userId.toString()),
                "name": Bson(config.name),
                "host": Bson(config.host),
                "port": Bson(config.port),
                "tls": Bson(config.tls.to!string),
                "sasl": Bson(config.sasl.to!string),
                "saslUsername": Bson(config.saslUsername),
                "saslPassword": Bson(config.saslPassword),
                "autoJoinChannels": Bson(config.autoJoinChannels.map!(c => Bson(c)).array),
                "partedChannels": Bson(config.partedChannels.map!(c => Bson(c)).array),
                "nick": Bson(config.nick),
                "realName": Bson(config.realName),
                "disabled": Bson(config.disabled),
                "systemManaged": Bson(config.systemManaged),
                "autoJoinDelaySeconds": Bson(config.autoJoinDelaySeconds)
            ])
        ]);
        UpdateOptions options;
        options.upsert = true;
        collection.updateOne(selector, update, options);
    }

    /// Sets the disabled flag on a network without rewriting the full record.
    /// Used by admin disconnect/reconnect to persist the disabled state.
    void setDisabled(UUID id, bool disabled) {
        auto selector = Bson(["id": Bson(id.toString())]);
        auto update = Bson(["$set": Bson(["disabled": Bson(disabled)])]);
        collection.updateOne(selector, update);
    }

    /// Deletes a network by its ID.
    void deleteById(UUID id) {
        collection.deleteOne(["id": id.toString()]);
    }

    /// Serializes a NetworkConfig array to a JSON array.
    /// Each element is produced by NetworkConfig.toJson().
    private static Json serializeNetworkConfigs(NetworkConfig[] configs) {
        auto arr = Json.emptyArray;
        foreach (cfg; configs) {
            arr ~= cfg.toJson();
        }
        return arr;
    }

    /// Deserializes a JSON array back to a NetworkConfig array.
    /// Mirrors the field layout of NetworkConfig.toJson().
    private static NetworkConfig[] deserializeNetworkConfigs(Json json) {
        import std.algorithm.iteration : map;
        NetworkConfig[] result;
        foreach (elem; json) {
            NetworkConfig cfg;
            cfg.id = parseUUID(elem["id"].get!string);
            cfg.name = elem["name"].get!string;
            cfg.host = elem["host"].get!string;
            cfg.port = cast(ushort)elem["port"].get!int;
            cfg.tls = elem["tls"].get!string.to!TLSMode;
            cfg.sasl = elem["sasl"].get!string.to!SASLMechanism;
            cfg.saslUsername = elem["saslUsername"].get!string;
            cfg.saslPassword = elem["saslPassword"].get!string;
            cfg.autoJoinChannels = deserializeJson!(string[])(elem["autoJoinChannels"]);
            if (elem["partedChannels"].type != Json.Type.undefined)
                cfg.partedChannels = deserializeJson!(string[])(elem["partedChannels"]);
            cfg.nick = elem["nick"].get!string;
            cfg.realName = elem["realName"].get!string;
            try { cfg.disabled = elem["disabled"].get!bool; } catch (Exception) {}
            try { cfg.nspass = elem["nspass"].get!string; } catch (Exception) {}
            try { cfg.commands = elem["commands"].get!string; } catch (Exception) {}
            try { cfg.serverPass = elem["serverPass"].get!string; } catch (Exception) {}
            // systemManaged is optional in cached records (added July 2026).
            try { cfg.systemManaged = elem["systemManaged"].get!bool; } catch (Exception) {}
            // autoJoinDelaySeconds optional — 0 (join immediately) when absent.
            try {
                const v = elem["autoJoinDelaySeconds"].get!int;
                if (v > 0) cfg.autoJoinDelaySeconds = cast(uint) v;
            } catch (Exception) {}
            result ~= cfg;
        }
        return result;
    }

    private NetworkConfig docToConfig(const(Bson) doc) {
        NetworkConfig cfg;
        cfg.id = parseUUID(doc["id"].get!string);
        cfg.name = doc["name"].get!string;
        cfg.host = doc["host"].get!string;
        cfg.port = cast(ushort)doc["port"].get!int;
        cfg.tls = doc["tls"].get!string.to!TLSMode;
        cfg.sasl = doc["sasl"].get!string.to!SASLMechanism;
        cfg.saslUsername = doc["saslUsername"].get!string;
        cfg.saslPassword = doc["saslPassword"].get!string;
        cfg.autoJoinChannels = deserializeBson!(string[])(doc["autoJoinChannels"]);
        if (doc["partedChannels"].type == Bson.Type.array)
            cfg.partedChannels = deserializeBson!(string[])(doc["partedChannels"]);
        cfg.nick = doc["nick"].get!string;
        cfg.realName = doc["realName"].get!string;
        try { cfg.disabled = doc["disabled"].get!bool; } catch (Exception) {}
        // systemManaged is optional in older records (added July 2026).
        // Default to false for backwards compatibility with existing networks.
        try { cfg.systemManaged = doc["systemManaged"].get!bool; } catch (Exception) {}
        // autoJoinDelaySeconds optional — 0 (join immediately) when absent.
        try {
            const v = doc["autoJoinDelaySeconds"].get!int;
            if (v > 0) cfg.autoJoinDelaySeconds = cast(uint) v;
        } catch (Exception) {}
        return cfg;
    }
}
