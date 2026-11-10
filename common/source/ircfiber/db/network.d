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
import ircfiber.services.config : decodeStoredServicesConfig, ServicesConfig;
import ircfiber.irc.routing_policy : RoutingPreferences, routingPreferencesFromJson;
import ircfiber.irc.ipv6 : generateIpv6Iid, validIpv6Iid;
import ircfiber.db.mongo;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.db.user : idInFilters;
import ircfiber.network_write_gate : NetworkWriter, runNetworkWrite, runNetworkMutation,
    retainNetworkWriteUncertainty, NetworkWriteUnavailableException;

version (RoutingPolicyTest) {
    /// Called by the guarded real-Mongo/Redis runner with its explicit URI.
    /// Constructor cleanup is collection-wide, so never run it in the runner's
    /// populated namespace (or in any ambient application database).
    void networkRepositoryWriterGateCases(RedisStorage redis, string mongoUri) {
        import std.exception : enforce;
        import std.string : endsWith, replace;
        import ircfiber.network_write_gate : NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY,
            networkMutationAdmittedForTest, networkMutationRepliedForTest;
        enforce(mongoUri.length && AppMongoConnection.name().endsWith("_test"),
            "Repository proof requires an explicitly admitted test Mongo URI");
        const originalDatabase = AppMongoConnection.name();
        const database = "repository_gate_" ~ randomUUID().toString().replace("-", "") ~ "_test";
        AppMongoConnection.connect(mongoUri, database);
        scope (exit) AppMongoConnection.connect(mongoUri, originalDatabase);
        auto collection = AppMongoConnection.getDb()["networks"];
        enforce(collection.findOne(Bson.emptyObject).isNull, "Random migration namespace must be empty");
        auto db = redis.getDb();
        enforce(!db.exists(NETWORK_WRITE_EXCLUSION_KEY) && db.scard(NETWORK_WRITERS_KEY) == 0,
            "Repository proof requires dedicated quiescent Redis");
        const operation = randomUUID().toString();
        string[] tokens;
        UUID[] ids;
        scope (exit) {
            networkMutationAdmittedForTest = null;
            networkMutationRepliedForTest = null;
            db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
                [NETWORK_WRITE_EXCLUSION_KEY], operation);
            // Only this test's captured tokens, after synchronous DB completion.
            foreach (token; tokens) db.srem(NETWORK_WRITERS_KEY, token);
            foreach (id; ids) collection.deleteOne(Bson(["id": Bson(id.toString())]));
        }
        long collect() {
            auto reply = db.eval!long(
                "if redis.call('EXISTS',KEYS[1]) ~= 0 or redis.call('SCARD',KEYS[2]) ~= 0 then return 0 end redis.call('SET',KEYS[1],ARGV[1]); return 1",
                [NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY], operation);
            enforce(!reply.empty, "Collector oracle returned no result");
            return reply.front;
        }
        void unlock() {
            db.eval!long("if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
                [NETWORK_WRITE_EXCLUSION_KEY], operation);
        }
        bool hasIndex(string name) {
            foreach (index; collection.listIndexes()) if (index["name"].get!string == name) return true;
            return false;
        }
        const id = randomUUID();
        ids ~= id;
        collection.insertOne(Bson(["id": Bson(id.toString()), "bncToken": Bson("legacy-fixture")]));
        collection.createIndex(Bson(["bncToken": Bson(1)]));
        enforce(collect() == 1, "Closed fixture gate could not be acquired");
        auto repository = new NetworkRepository(redis);
        enforce(collection.findOne(["id": id.toString()])["bncToken"].get!string == "legacy-fixture"
            && hasIndex("bncToken_1"), "Closed constructor dispatched purge or legacy DDL");
        bool refused;
        try repository.ensureIpv6Iid(id);
        catch (NetworkWriteUnavailableException) { refused = true; }
        enforce(refused && !hasIndex("ipv6Iid_unique_v1")
            && collection.findOne(["id": id.toString()]).tryIndex("ipv6Iid").isNull,
            "Closed allocator dispatched index creation or reservation");
        unlock();
        size_t admissions;
        networkMutationAdmittedForTest = (string token) { tokens ~= token; ++admissions; };
        runNetworkWrite!void(redis, (ref NetworkWriter writer) {
            auto admitted = new NetworkRepository(redis, writer);
            enforce(collect() == 0 && admissions == 1, "Constructor readmitted or lost outer ownership");
            enforce(collection.findOne(["id": id.toString()]).tryIndex("bncToken").isNull
                && !hasIndex("bncToken_1"), "Open constructor did not perform real migration");
            admitted.beforeIpv6IidWriteForTest = (UUID row, string iid) {
                enforce(hasIndex("ipv6Iid_unique_v1") && collect() == 0
                    && admissions == 1 && db.scard(NETWORK_WRITERS_KEY) == 1,
                    "Collector closed between real index creation and reservation");
            };
            enforce(validIpv6Iid(admitted.ensureIpv6Iid(id, writer)), "Open allocator did not persist an IID");
            admitted.setDisabled(id, true, writer);
            enforce(admissions == 1 && collect() == 0, "Trailing overload readmitted or released outer owner");
        });
        enforce(db.scard(NETWORK_WRITERS_KEY) == 0 && collect() == 1,
            "Confirmed outer operation did not release its sole writer");
        unlock();
        bool refusedBeforeEffect;
        try runNetworkWrite!void(redis, (ref NetworkWriter writer) {
            throw new Exception("Known domain refusal before dispatch");
        });
        catch (Exception) { refusedBeforeEffect = true; }
        enforce(refusedBeforeEffect && db.scard(NETWORK_WRITERS_KEY) == 0 && collect() == 1,
            "A domain refusal without dispatched work must release its admitted scope");
        unlock();
        bool refusedAfterAcknowledgement;
        try runNetworkWrite!void(redis, (ref NetworkWriter writer) {
            repository.setDisabled(id, false, writer);
            throw new Exception("Known domain refusal after acknowledged mutation");
        });
        catch (Exception) { refusedAfterAcknowledgement = true; }
        enforce(refusedAfterAcknowledgement
                && !collection.findOne(["id": id.toString()])["disabled"].get!bool
                && db.scard(NETWORK_WRITERS_KEY) == 0 && collect() == 1,
            "A later domain refusal cannot make a confirmed mutation appear in flight");
        unlock();
        // Constructor swallows migration failures for compatibility, but it
        // cannot clear a real Mongo command's lost completion acknowledgement.
        networkMutationRepliedForTest = { throw new Exception("Lost migration acknowledgement"); };
        runNetworkWrite!void(redis, (ref NetworkWriter writer) {
            auto ignored = new NetworkRepository(redis, writer);
        });
        networkMutationRepliedForTest = null;
        enforce(db.scard(NETWORK_WRITERS_KEY) == 1 && collect() == 0
            && db.ttl(NETWORK_WRITERS_KEY) == -1, "Swallowed migration lost-ack cleared writer evidence");
        foreach (token; tokens) db.srem(NETWORK_WRITERS_KEY, token);
        const second = randomUUID();
        ids ~= second;
        collection.insertOne(Bson(["id": Bson(second.toString())]));
        networkMutationRepliedForTest = { throw new Exception("Lost reservation acknowledgement"); };
        runNetworkWrite!void(redis, (ref NetworkWriter writer) {
            try repository.ensureIpv6Iid(second, writer);
            catch (Exception) {}
        });
        networkMutationRepliedForTest = null;
        enforce(validIpv6Iid(collection.findOne(["id": second.toString()])["ipv6Iid"].get!string)
            && db.scard(NETWORK_WRITERS_KEY) == 1 && collect() == 0,
            "Committed reservation with swallowed lost-ack did not retain exclusion evidence");
        foreach (token; tokens) db.srem(NETWORK_WRITERS_KEY, token);
        // Real createIndexes failure after dispatch must also stay sticky when
        // an admitted consumer catches the synchronous DDL exception.
        collection.dropIndex("ipv6Iid_unique_v1");
        const duplicate = randomUUID();
        ids ~= duplicate;
        collection.insertOne(Bson(["id": Bson(duplicate.toString()),
            "ipv6Iid": collection.findOne(["id": id.toString()])["ipv6Iid"]]));
        collection.updateOne(Bson(["id": Bson(second.toString())]),
            Bson(["$unset": Bson(["ipv6Iid": Bson("")])]));
        auto failedDdl = new NetworkRepository(redis);
        runNetworkWrite!void(redis, (ref NetworkWriter writer) {
            try failedDdl.ensureIpv6Iid(second, writer);
            catch (Exception) {}
        });
        enforce(db.scard(NETWORK_WRITERS_KEY) == 1 && collect() == 0
            && collection.findOne(["id": second.toString()]).tryIndex("ipv6Iid").isNull,
            "Caught real uniqueness-index failure released its writer or dispatched a reservation");
    }
}

/// Repository for network configurations.
final class NetworkRepository {
    private MongoCollection collection;
    private bool ipv6IidIndexReady;
    /// Cache connections are thread-affine; background workers supply theirs.
    private RedisStorage cache;

    version (RoutingPolicyTest) {
        bool delegate(out string) ipv6IidGeneratorForTest;
        void delegate(UUID, string) beforeIpv6IidWriteForTest;
    }

    /// Default for this thread only: Redis sockets belong to its event loop.
    private static RedisStorage defaultRedis;

    /// Initializes the current thread's fallback after its Redis is connected.
    static void initRedis(RedisStorage redis) {
        defaultRedis = redis;
    }

    /// Creates a repository with the caller's connection, or this thread's default.
    this(RedisStorage cacheRedis = null) {
        cache = cacheRedis is null ? defaultRedis : cacheRedis;
        collection = AppMongoConnection.getDb()["networks"];
        // Boot migration stays best-effort, but refusal never dispatches DDL
        // or a document mutation.
        try runNetworkWrite!void(cache, (ref NetworkWriter writer) {
            purgeLegacyBncTokens(writer);
        });
        catch (Exception e) logWarn("networks legacy cleanup unavailable: %s", e.msg);
    }

    /// Reuse a logical operation's already admitted owner.
    this(RedisStorage cacheRedis, ref NetworkWriter writer) {
        cache = cacheRedis;
        collection = AppMongoConnection.getDb()["networks"];
        purgeLegacyBncTokens(writer);
    }

    /// Bouncer passwords moved from networks to users; drop the old index
    /// and strip stale tokens. Idempotent and best-effort within one owner.
    private void purgeLegacyBncTokens(ref NetworkWriter writer) @trusted {
        try {
            bool present;
            foreach (idx; collection.listIndexes())
                if (idx["name"].get!string == "bncToken_1") present = true;
            if (present) {
                try collection.dropIndex("bncToken_1");
                catch (Exception e) {
                    retainNetworkWriteUncertainty(writer);
                    throw e;
                }
            }
        } catch (Exception e) logWarn("networks bncToken_1 index drop: %s", e.msg);
        auto command = Bson.emptyObject;
        command["update"] = Bson("networks");
        command["updates"] = Bson([Bson([
            "q": Bson(["bncToken": Bson(["$exists": Bson(true)])]),
            "u": Bson(["$unset": Bson(["bncToken": Bson("")])]),
            "multi": Bson(true), "upsert": Bson(false)])]);
        try runNetworkMutation(writer, command);
        catch (Exception e) logWarn("networks bncToken purge: %s", e.msg);
    }

    /// Network config paired with its owner user ID.
    struct NetworkWithUser {
        /// Network configuration.
        NetworkConfig config;
        /// Owning user ID.
        UUID userId;

        /// True when the network exists and belongs to `user`. A document
        /// without a `userId` belongs to nobody — never to whoever asks.
        bool isOwnedBy(UUID user) const @safe pure nothrow @nogc {
            return config.id != UUID.init && userId != UUID.init && userId == user;
        }
    }

    /// Finds all networks for a user, using Redis cache when available.
    NetworkConfig[] findByUserId(UUID userId) {
        // Try Redis cache first
        if (cache !is null) {
            auto key = RedisKeys.userNetworks(userId.toString());
            auto cached = cache.getJson(key);
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
                try { result ~= docToConfig(doc); }
                catch (Ipv6IdentityException e) { throw e; }
                catch (Exception e) { logWarn("NetworkRepository.findByUserId: skipping broken doc %s: %s", doc["id"].toString(), e.msg); }
            }

            // Cache in Redis (60s TTL) so frequent reads don't hammer Mongo.
            // The cache is invalidated on every create/update/delete of a network.
            if (cache !is null) {
                cache.setJson(RedisKeys.userNetworks(userId.toString()), serializeNetworkConfigs(result), 60);
            }

            return result;
        } catch (Exception e) {
            mongoRecordFailure();
            throw e;
        }
    }

    /// Finds all networks for a user, straight from Mongo: no Redis cache,
    /// and no silent empty on an open circuit breaker (which also returns
    /// [] and is indistinguishable from "has no networks").
    ///
    /// Destructive callers (account purge) MUST use this: purging on an
    /// empty answer deletes the user while leaving every network, engine
    /// connection and NickServ account behind — the orphan pattern seen on
    /// prod (networks outliving their users). Throwing here fails the
    /// deletion loudly while the account still exists, so it can be
    /// retried; returning [] would fail it silently and permanently.
    NetworkConfig[] findByUserIdDirect(UUID userId) {
        import ircfiber.db.circuit_breaker : mongoAllowRequest, mongoRecordFailure;
        if (!mongoAllowRequest())
            throw new Exception(
                "Mongo circuit breaker open while enumerating networks for purge");
        try {
            NetworkConfig[] result;
            foreach (doc; collection.find(["userId": userId.toString()])) {
                try { result ~= docToConfig(doc); }
                catch (Ipv6IdentityException e) { throw e; }
                catch (Exception e) { logWarn("NetworkRepository.findByUserIdDirect: skipping broken doc %s: %s", doc["id"].toString(), e.msg); }
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
            try {
                result ~= NetworkWithUser(docToConfig(doc), parseUUID(doc["userId"].get!string));
            } catch (Exception e) {
                logWarn("NetworkRepository.findAll: skipping broken doc %s: %s", doc["id"].toString(), e.msg);
            }
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

    /// Networks whose IDs are in `ids`, each with its owner (`UUID.init`
    /// when the record has no userId, which `isOwnedBy` refuses). Unordered;
    /// unknown IDs are absent and duplicates are queried once. Bounded `$in`
    /// queries (`idInFilters`); empty input does no I/O. Mongo errors
    /// propagate; an undecodable record is skipped like a missing network.
    NetworkWithUser[] findByIdsWithUsers(UUID[] ids) {
        NetworkWithUser[] result;
        foreach (filter; idInFilters(ids)) {
            foreach (doc; collection.find(filter)) {
                UUID uid;
                try uid = parseUUID(doc["userId"].get!string);
                catch (Exception) uid = UUID.init;
                try result ~= NetworkWithUser(docToConfig(doc), uid);
                catch (Exception e) logWarn("NetworkRepository.findByIdsWithUsers: skipping broken doc: %s", e.msg);
            }
        }
        return result;
    }

    /// Every network on `host` that carries a NickServ credential, with its
    /// owner. Backs the admin NickServ section: it annotates the Anope
    /// account inventory with the IRC Fiber user that owns each account.
    NetworkWithUser[] listWithSaslAccount(string host) {
        NetworkWithUser[] result;
        auto filter = Bson([
            "host": Bson(host),
            "saslUsername": Bson(["$exists": Bson(true), "$ne": Bson("")])
        ]);
        foreach (doc; collection.find(filter)) {
            UUID uid;
            try uid = parseUUID(doc["userId"].get!string);
            catch (Exception) uid = UUID.init;
            result ~= NetworkWithUser(docToConfig(doc), uid);
        }
        return result;
    }

    /// Reserve only an absent identity. A corrupt or existing identity is
    /// never overwritten, including by stale ordinary saves.
    string ensureIpv6Iid(UUID networkId) {
        try {
            auto current = collection.findOne(["id": networkId.toString()]);
            if (current.isNull) throw new Ipv6IdentityException("Network does not exist");
            const existing = storedIpv6Iid(current);
            if (existing.length) {
                invalidateIpv6OwnerCache(current);
                return existing;
            }
            return runNetworkWrite!string(cache, (ref NetworkWriter writer) {
                return ensureIpv6Iid(networkId, writer);
            });
        }
        catch (NetworkWriteUnavailableException e) throw e;
        catch (Ipv6IdentityException e) throw e;
        catch (Exception e)
            throw new Ipv6IdentityException("IPv6 identity reservation unavailable: " ~ e.msg);
    }

    string ensureIpv6Iid(UUID networkId, ref NetworkWriter writer) {
        try return reserveIpv6Iid(networkId, writer);
        catch (NetworkWriteUnavailableException e) throw e;
        catch (Ipv6IdentityException e) throw e;
        catch (Exception e)
            throw new Ipv6IdentityException("IPv6 identity reservation unavailable: " ~ e.msg);
    }

    /// Canonical config for assignment/control, never the caller's stale copy.
    NetworkConfig findByIdWithIpv6Iid(UUID networkId) {
        const iid = ensureIpv6Iid(networkId);
        return reloadWithIpv6Iid(networkId, iid);
    }

    NetworkConfig findByIdWithIpv6Iid(UUID networkId, ref NetworkWriter writer) {
        const iid = ensureIpv6Iid(networkId, writer);
        return reloadWithIpv6Iid(networkId, iid);
    }

    private NetworkConfig reloadWithIpv6Iid(UUID networkId, string iid) {
        try {
            auto cfg = findById(networkId);
            if (cfg.id == UUID.init || cfg.ipv6Iid != iid)
                throw new Ipv6IdentityException("IPv6 identity changed during canonical reload");
            return cfg;
        } catch (Ipv6IdentityException e) { throw e; }
        catch (Exception e) {
            throw new Ipv6IdentityException("IPv6 canonical reload unavailable: " ~ e.msg);
        }
    }

    private string reserveIpv6Iid(UUID networkId, ref NetworkWriter writer) {
        foreach (attempt; 0 .. 8) {
            auto current = collection.findOne(["id": networkId.toString()]);
            if (current.isNull) throw new Ipv6IdentityException("Network does not exist");
            const existing = storedIpv6Iid(current);
            if (existing.length) {
                invalidateIpv6OwnerCache(current);
                return existing;
            }
            ensureIpv6IidIndex(writer);

            string candidate;
            bool generated;
            version (RoutingPolicyTest) {
                generated = ipv6IidGeneratorForTest !is null
                    ? ipv6IidGeneratorForTest(candidate) : generateIpv6Iid(candidate);
            } else {
                generated = generateIpv6Iid(candidate);
            }
            if (!generated || !validIpv6Iid(candidate))
                throw new Ipv6IdentityException("IPv6 identity entropy unavailable");
            version (RoutingPolicyTest) {
                if (beforeIpv6IidWriteForTest !is null)
                    beforeIpv6IidWriteForTest(networkId, candidate);
            }
            // The checked findAndModify helper discards Mongo's numeric error
            // code. Inspect the raw reply instead of classifying message text.
            auto command = Bson.emptyObject;
            command["findAndModify"] = Bson("networks");
            command["query"] = Bson(["id": Bson(networkId.toString()),
                "ipv6Iid": Bson(["$exists": Bson(false)])]);
            command["update"] = Bson(["$set": Bson(["ipv6Iid": Bson(candidate)])]);
            command["new"] = Bson(true);
            const reply = runNetworkMutation(writer, command);
            if (reply["ok"].get!double != 1.0) {
                if (reply["code"].type == Bson.Type.undefined || reply["code"].get!int != 11000)
                    throw new Ipv6IdentityException("Mongo rejected IPv6 identity reservation");
            } else {
                auto reserved = reply["value"];
                if (!reserved.isNull) {
                    const iid = storedIpv6Iid(reserved);
                    if (!iid.length) throw new Ipv6IdentityException("IPv6 reservation returned no identity");
                    invalidateIpv6OwnerCache(reserved);
                    return iid;
                }
            }
            auto winner = collection.findOne(["id": networkId.toString()]);
            if (winner.isNull) throw new Ipv6IdentityException("Network disappeared during IPv6 reservation");
            const iid = storedIpv6Iid(winner);
            if (iid.length) {
                invalidateIpv6OwnerCache(winner);
                return iid;
            }
        }
        throw new Ipv6IdentityException("IPv6 identity collision retries exhausted");
    }

    private void ensureIpv6IidIndex(ref NetworkWriter writer) {
        if (ipv6IidIndexReady) return;
        // Mongo commands require the verb to be the first BSON field. An
        // associative-array constructor can reorder it and is not safe here.
        auto command = Bson.emptyObject;
        command["createIndexes"] = Bson("networks");
        command["indexes"] = Bson([Bson([
            "key": Bson(["ipv6Iid": Bson(1)]),
            "name": Bson("ipv6Iid_unique_v1"),
            "unique": Bson(true),
            "partialFilterExpression": Bson(["ipv6Iid": Bson(["$type": Bson("string")])])
        ])]);
        // Failure is fatal: reservations without this index are not unique.
        try AppMongoConnection.getDb().runCommandChecked(command);
        catch (Exception e) {
            retainNetworkWriteUncertainty(writer);
            throw e;
        }
        ipv6IidIndexReady = true;
    }

    private static string storedIpv6Iid(const(Bson) doc) {
        const field = doc.tryIndex("ipv6Iid");
        if (field.isNull) return "";
        const value = field.get;
        if (value.type != Bson.Type.string || !validIpv6Iid(value.get!string))
            throw new Ipv6IdentityException("Stored IPv6 identity is corrupt");
        return value.get!string.idup;
    }

    private void invalidateIpv6OwnerCache(const(Bson) doc) {
        if (cache !is null && doc["userId"].type == Bson.Type.string)
            cache.del(RedisKeys.userNetworks(doc["userId"].get!string));
    }

    /// Saves or updates a network configuration.
    void save(NetworkConfig config, UUID userId) {
        auto update = saveUpdate(config, userId);
        auto selector = Bson(["id": Bson(config.id.toString())]);
        runNetworkWrite!void(cache, (ref NetworkWriter writer) {
            savePrepared(selector, update, userId, writer);
        });
    }

    void save(NetworkConfig config, UUID userId, ref NetworkWriter writer) {
        savePrepared(Bson(["id": Bson(config.id.toString())]),
            saveUpdate(config, userId), userId, writer);
    }

    private static Bson saveUpdate(NetworkConfig config, UUID userId) {
        return Bson([
            "$set": persistedFields(config, userId),
            "$setOnInsert": Bson([
                "servicesProvisioningPending": Bson(config.servicesProvisioningPending)
            ])
        ]);
    }

    private void savePrepared(Bson selector, Bson update, UUID userId, ref NetworkWriter writer) {
        updateConfig(selector, update, writer, true);
        // Invalidate per-user cache so findByUserId doesn't return stale [] for 60s
        // after a new network is provisioned (e.g. ensureDefaultFiberNetwork on register).
        if (cache !is null) {
            try cache.del(RedisKeys.userNetworks(userId.toString()));
            catch (Exception) {}
        }
    }

    /// All document changes use a strict acknowledged command under the
    /// shared writer registration. Construct/validate BSON before admission.
    private Bson updateConfig(Bson selector, Bson update, ref NetworkWriter writer, bool upsert = false) {
        auto command = Bson.emptyObject;
        command["update"] = Bson("networks");
        command["updates"] = Bson([Bson(["q": selector, "u": update,
            "multi": Bson(false), "upsert": Bson(upsert)])]);
        return runNetworkMutation(writer, command);
    }

    /// The `$set` document `save` writes: every user/admin-editable field.
    /// `servicesProvisioningPending` is insert-only (see `save`).
    /// The immutable `ipv6Iid` is deliberately never written by this path.
    private static Bson persistedFields(ref NetworkConfig config, UUID userId) {
        return Bson([
            "id": Bson(config.id.toString()),
            "userId": Bson(userId.toString()),
            "name": Bson(config.name),
            "host": Bson(config.host),
            "port": Bson(config.port),
            "tls": Bson(config.tls.to!string),
            "sasl": Bson(config.sasl.to!string),
            "saslUsername": Bson(config.saslUsername),
            "saslPassword": Bson(config.saslPassword),
            "operUsername": Bson(config.operUsername),
            "operPassword": Bson(config.operPassword),
            "nspass": Bson(config.nspass),
            "serverPass": Bson(config.serverPass),
            "commands": Bson(config.commands),
            "autoJoinChannels": Bson(config.autoJoinChannels.map!(c => Bson(c)).array),
            "partedChannels": Bson(config.partedChannels.map!(c => Bson(c)).array),
            "nick": Bson(config.nick),
            "realName": Bson(config.realName),
            "ident": Bson(config.ident),
            "disabled": Bson(config.disabled),
            "systemManaged": Bson(config.systemManaged),
            "autoJoinDelaySeconds": Bson(config.autoJoinDelaySeconds),
            "routing": config.routing.valid ? Bson.fromJson(config.routing.toJson()) : Bson(null),
            "avatarUrl": Bson(config.avatarUrl),
            "defaultAvatarUrl": Bson(config.defaultAvatarUrl),
            "profileMetadata": serializeToBson(config.profileMetadata),
            "monitoredNicks": Bson(config.monitoredNicks.map!(n => Bson(n)).array),
            "services": Bson.fromJson(config.services.toJson())
        ]);
    }

    /// Decodes a stored `services` value; absent (legacy) or malformed
    /// values give the no-trust default, malformed ones are logged.
    private static ServicesConfig storedServices(Json j, string networkId) {
        string error;
        auto services = decodeStoredServicesConfig(j, error);
        if (error.length)
            logWarn("NetworkRepository: network %s has an invalid services config (%s); using defaults",
                networkId, error);
        return services;
    }

    /// Missing or malformed saved routing must never become automatic routing.
    private static RoutingPreferences storedRouting(Json value, string networkId) {
        try return routingPreferencesFromJson(value);
        catch (Exception e) {
            logWarn("NetworkRepository: network %s has invalid routing (%s); new dials blocked",
                networkId, e.msg);
            RoutingPreferences invalid;
            invalid.valid = false;
            return invalid;
        }
    }

    /// Complete an initial signup exactly once; never create or re-arm a row.
    /// A verified credential is committed in the same atomic transition.
    bool completeSignupProvisioning(UUID id, UUID ownerId, string account = "", string password = "") {
        return runNetworkWrite!bool(cache, (ref NetworkWriter writer) {
            return completeSignupProvisioning(id, ownerId, account, password, writer);
        });
    }

    bool completeSignupProvisioning(UUID id, UUID ownerId, string account, string password,
            ref NetworkWriter writer) {
        auto fields = Bson(["servicesProvisioningPending": Bson(false)]);
        if (account.length) {
            fields["sasl"] = Bson(SASLMechanism.plain.to!string);
            fields["saslUsername"] = Bson(account);
            fields["saslPassword"] = Bson(password);
            fields["nick"] = Bson(account);
            fields["realName"] = Bson(account);
        }
        auto result = updateConfig(
            Bson([
                "id": Bson(id.toString()),
                "userId": Bson(ownerId.toString()),
                "servicesProvisioningPending": Bson(true)
            ]),
            Bson(["$set": fields]), writer);
        if (result["nModified"].get!long != 1) return false;
        if (cache !is null) {
            try cache.del(RedisKeys.userNetworks(ownerId.toString()));
            catch (Exception) {}
        }
        return true;
    }

    /// Updates only saved route preferences. Runtime policy filtering is separate.
    void setRouting(UUID id, RoutingPreferences routing) {
        auto validated = routingPreferencesFromJson(routing.toJson());
        auto selector = Bson(["id": Bson(id.toString())]);
        auto update = Bson(["$set": Bson(["routing": Bson.fromJson(validated.toJson())])]);
        runNetworkWrite!void(cache, (ref NetworkWriter writer) {
            updateConfig(selector, update, writer);
        });
    }

    void setRouting(UUID id, RoutingPreferences routing, ref NetworkWriter writer) {
        auto validated = routingPreferencesFromJson(routing.toJson());
        updateConfig(Bson(["id": Bson(id.toString())]),
            Bson(["$set": Bson(["routing": Bson.fromJson(validated.toJson())])]), writer);
    }


    /// Sets the disabled flag on a network without rewriting the full record.
    /// Used by admin disconnect/reconnect to persist the disabled state.
    void setDisabled(UUID id, bool disabled) {
        runNetworkWrite!void(cache, (ref NetworkWriter writer) {
            setDisabled(id, disabled, writer);
        });
    }

    void setDisabled(UUID id, bool disabled, ref NetworkWriter writer) {
        auto selector = Bson(["id": Bson(id.toString())]);
        auto update = Bson(["$set": Bson(["disabled": Bson(disabled)])]);
        updateConfig(selector, update, writer);
    }

    /// Deletes a network by its ID.
    void deleteById(UUID id) {
        runNetworkWrite!void(cache, (ref NetworkWriter writer) {
            deleteById(id, writer);
        });
    }

    void deleteById(UUID id, ref NetworkWriter writer) {
        auto command = Bson.emptyObject;
        command["delete"] = Bson("networks");
        command["deletes"] = Bson([Bson(["q": Bson(["id": Bson(id.toString())]), "limit": Bson(1)])]);
        runNetworkMutation(writer, command);
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
            auto iid = elem["ipv6Iid"];
            if (iid.type != Json.Type.undefined) {
                if (iid.type != Json.Type.string
                        || (iid.get!string.length && !validIpv6Iid(iid.get!string)))
                    throw new Ipv6IdentityException("Cached IPv6 identity is corrupt");
                cfg.ipv6Iid = iid.get!string;
            }
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
            try { cfg.ident = elem["ident"].get!string; } catch (Exception) {}
            try { cfg.disabled = elem["disabled"].get!bool; } catch (Exception) {}
            try { cfg.servicesProvisioningPending = elem["servicesProvisioningPending"].get!bool; } catch (Exception) {}
            try { cfg.nspass = elem["nspass"].get!string; } catch (Exception) {}
            try { cfg.commands = elem["commands"].get!string; } catch (Exception) {}
            try { cfg.serverPass = elem["serverPass"].get!string; } catch (Exception) {}
            try { cfg.operUsername = elem["operUsername"].get!string; } catch (Exception) {}
            try { cfg.operPassword = elem["operPassword"].get!string; } catch (Exception) {}
            // systemManaged is optional in cached records (added July 2026).
            try { cfg.systemManaged = elem["systemManaged"].get!bool; } catch (Exception) {}
            // autoJoinDelaySeconds optional — 0 (join immediately) when absent.
            try {
                const v = elem["autoJoinDelaySeconds"].get!int;
                if (v > 0) cfg.autoJoinDelaySeconds = cast(uint) v;
            } catch (Exception) {}
            cfg.routing = storedRouting(elem["routing"], cfg.id.toString());
            try { cfg.avatarUrl = elem["avatarUrl"].get!string; } catch (Exception) {}
            try { cfg.defaultAvatarUrl = elem["defaultAvatarUrl"].get!string; } catch (Exception) {}
            try { cfg.profileMetadata = deserializeJson!(string[string])(elem["profileMetadata"]); } catch (Exception) {}
            try { cfg.monitoredNicks = deserializeJson!(string[])(elem["monitoredNicks"]); } catch (Exception) {}
            cfg.services = storedServices(elem["services"], cfg.id.toString());
            result ~= cfg;
        }
        return result;
    }

    private static NetworkConfig docToConfig(const(Bson) doc) {
        NetworkConfig cfg;
        try { cfg.id = parseUUID(doc["id"].get!string); } catch (Exception) {}
        cfg.ipv6Iid = storedIpv6Iid(doc);
        try { cfg.name = doc["name"].get!string; } catch (Exception) {}
        try { cfg.host = doc["host"].get!string; } catch (Exception) {}
        try { cfg.port = cast(ushort)doc["port"].get!int; } catch (Exception) {}
        try { cfg.tls = doc["tls"].get!string.to!TLSMode; } catch (Exception) {}
        try { cfg.sasl = doc["sasl"].get!string.to!SASLMechanism; } catch (Exception) {}
        try { cfg.saslUsername = doc["saslUsername"].get!string; } catch (Exception) {}
        try { cfg.saslPassword = doc["saslPassword"].get!string; } catch (Exception) {}
        try { cfg.autoJoinChannels = deserializeBson!(string[])(doc["autoJoinChannels"]); } catch (Exception) {}
        if (doc["partedChannels"].type == Bson.Type.array)
            try { cfg.partedChannels = deserializeBson!(string[])(doc["partedChannels"]); } catch (Exception) {}
        try { cfg.nick = doc["nick"].get!string; } catch (Exception) {}
        try { cfg.realName = doc["realName"].get!string; } catch (Exception) {}
        try { cfg.ident = doc["ident"].get!string; } catch (Exception) {}
        try { cfg.disabled = doc["disabled"].get!bool; } catch (Exception) {}
        try { cfg.servicesProvisioningPending = doc["servicesProvisioningPending"].get!bool; } catch (Exception) {}
        try { cfg.systemManaged = doc["systemManaged"].get!bool; } catch (Exception) {}
        try {
            const v = doc["autoJoinDelaySeconds"].get!int;
            if (v > 0) cfg.autoJoinDelaySeconds = cast(uint) v;
        } catch (Exception) {}
        cfg.routing.valid = false;
        try { cfg.routing = storedRouting(doc["routing"].toJson(), cfg.id.toString()); }
        catch (Exception e) {
            logWarn("NetworkRepository: network %s routing cannot be decoded (%s); new dials blocked",
                cfg.id, e.msg);
        }
        try { cfg.avatarUrl = doc["avatarUrl"].get!string; } catch (Exception) {}
        try { cfg.defaultAvatarUrl = doc["defaultAvatarUrl"].get!string; } catch (Exception) {}
        try { cfg.profileMetadata = deserializeBson!(string[string])(doc["profileMetadata"]); } catch (Exception) {}
        try { cfg.monitoredNicks = deserializeBson!(string[])(doc["monitoredNicks"]); } catch (Exception) {}
        try { cfg.nspass = doc["nspass"].get!string; } catch (Exception) {}
        try { cfg.commands = doc["commands"].get!string; } catch (Exception) {}
        try { cfg.serverPass = doc["serverPass"].get!string; } catch (Exception) {}
        try { cfg.operUsername = doc["operUsername"].get!string; } catch (Exception) {}
        try { cfg.operPassword = doc["operPassword"].get!string; } catch (Exception) {}
        cfg.services = storedServices(doc["services"].toJson(), cfg.id.toString());
        return cfg;
    }
}

/// Allocation/corruption failures must not dispatch an upstream connection.
class Ipv6IdentityException : Exception {
    this(string message) { super(message); }
}

@("NetworkWithUser.isOwnedBy fails closed")
unittest {
    const owner = parseUUID("11111111-1111-1111-1111-111111111111");
    const other = parseUUID("22222222-2222-2222-2222-222222222222");
    NetworkRepository.NetworkWithUser owned;
    owned.config.id = parseUUID("33333333-3333-3333-3333-333333333333");
    owned.userId = owner;
    assert(owned.isOwnedBy(owner));
    assert(!owned.isOwnedBy(other));
    auto ownerless = owned;
    ownerless.userId = UUID.init;
    assert(!ownerless.isOwnedBy(other));
    assert(!ownerless.isOwnedBy(UUID.init));
    NetworkRepository.NetworkWithUser missing;
    assert(!missing.isOwnedBy(owner));
    assert(!missing.isOwnedBy(UUID.init));
}

@("NetworkConfig services pins survive the Mongo document and Redis cache paths")
unittest {
    import ircfiber.services.config : ServiceId, ServicePin, ServicesProvider;
    NetworkConfig cfg;
    cfg.id = parseUUID("44444444-4444-4444-4444-444444444444");
    cfg.name = "External";
    cfg.host = "irc.example.net";
    cfg.nick = "me";
    cfg.realName = "me";
    cfg.services.provider = ServicesProvider.anope;
    cfg.services.server = "services.example.net";
    cfg.services.pins[ServiceId.nickServ] = ServicePin("NS", "services", "services.example.net");
    cfg.services.pins[ServiceId.operServ] = ServicePin("OS", "", "");
    const owner = parseUUID("55555555-5555-5555-5555-555555555555");

    // Mongo: the `$set` document read back through docToConfig.
    auto doc = NetworkRepository.persistedFields(cfg, owner);
    auto fromDoc = NetworkRepository.docToConfig(doc);
    assert(fromDoc.services == cfg.services);
    assert(fromDoc.host == cfg.host);

    // Redis cache: serialize/deserialize the per-user array.
    auto cached = NetworkRepository.deserializeNetworkConfigs(
        parseJsonString(NetworkRepository.serializeNetworkConfigs([cfg]).toString()));
    assert(cached.length == 1 && cached[0].services == cfg.services);

    // Legacy rows/cache entries without `services`: default, nothing trusted.
    auto legacyDoc = Bson.emptyObject;
    legacyDoc["id"] = Bson(cfg.id.toString());
    legacyDoc["host"] = Bson(cfg.host);
    assert(NetworkRepository.docToConfig(legacyDoc).services.isDefault);
    auto legacyCache = NetworkConfig.init;
    legacyCache.id = cfg.id;
    auto legacyJson = legacyCache.toJson();
    legacyJson.remove("services");
    auto arr = Json.emptyArray;
    arr ~= legacyJson;
    assert(NetworkRepository.deserializeNetworkConfigs(arr)[0].services.isDefault);

    // A corrupted stored value fails closed to the default.
    doc["services"] = Bson.fromJson(parseJsonString(`{"provider":"anope","managed":true}`));
    assert(NetworkRepository.docToConfig(doc).services.isDefault);
}

@("Saved routing round-trips Mongo and Redis without widening the route order")
unittest {
    import ircfiber.irc.routing_policy : RouteKind;
    NetworkConfig cfg;
    cfg.id = parseUUID("66666666-6666-6666-6666-666666666666");
    cfg.name = "VPN only";
    cfg.host = "irc.example.net";
    cfg.nick = "alice";
    cfg.realName = "Alice";
    cfg.saslUsername = "account";
    cfg.saslPassword = "secret";
    cfg.autoJoinChannels = ["#saved"];
    cfg.routing.inherit = false;
    cfg.routing.order = [RouteKind.nordvpn, RouteKind.mullvad];
    cfg.routing.preferredExit = "unavailable-exit";
    const owner = parseUUID("77777777-7777-7777-7777-777777777777");
    foreach (inherit; [false, true]) {
        cfg.routing.inherit = inherit;
        foreach (empty; [false, true]) {
            cfg.routing.order = empty ? [] : [RouteKind.nordvpn, RouteKind.mullvad];
            auto fromDoc = NetworkRepository.docToConfig(NetworkRepository.persistedFields(cfg, owner));
            auto cached = NetworkRepository.deserializeNetworkConfigs(
                parseJsonString(NetworkRepository.serializeNetworkConfigs([fromDoc]).toString()));
            assert(cached.length == 1);
            foreach (saved; [fromDoc, cached[0]]) {
                assert(saved.routing.valid);
                assert(saved.routing.inherit == inherit);
                assert(saved.routing.order == (inherit ? [] : cfg.routing.order));
                assert(saved.routing.preferredExit == cfg.routing.preferredExit);
                assert(saved.saslPassword == "secret" && saved.saslUsername == "account");
                assert(saved.autoJoinChannels == ["#saved"]);
                assert(saved.id == cfg.id);
            }
        }
    }
}

@("Missing and malformed saved routing stay blocked through Mongo and Redis")
unittest {
    NetworkConfig cfg;
    cfg.id = parseUUID("88888888-8888-8888-8888-888888888888");
    cfg.name = "Blocked";
    cfg.host = "irc.example.net";
    const owner = parseUUID("99999999-9999-9999-9999-999999999999");
    auto doc = Bson.emptyObject;
    doc["id"] = Bson(cfg.id.toString());
    doc["host"] = Bson(cfg.host);
    auto cacheRow = cfg.toJson();
    cacheRow.remove("routing");
    assert(!NetworkRepository.docToConfig(doc).routing.valid);
    assert(!NetworkRepository.deserializeNetworkConfigs(Json([cacheRow]))[0].routing.valid);
    foreach (raw; [
        `null`,
        `{}`,
        `{"order":null}`,
        `{"order":["unknown"],"preferredExit":""}`,
        `{"order":["direct","direct"],"preferredExit":""}`,
        `{"order":[],"preferredExit":"direct"}`,
        `{"order":[],"preferredExit":"","extra":true}`
    ]) {
        const bad = parseJsonString(raw);
        doc["routing"] = Bson.fromJson(bad);
        cacheRow["routing"] = bad;
        auto fromDoc = NetworkRepository.docToConfig(doc);
        auto fromCache = NetworkRepository.deserializeNetworkConfigs(Json([cacheRow]))[0];
        foreach (saved; [fromDoc, fromCache]) {
            assert(!saved.routing.valid);
            assert(saved.toJson()["routing"].type == Json.Type.null_);
            auto rewritten = NetworkRepository.docToConfig(NetworkRepository.persistedFields(saved, owner));
            assert(!rewritten.routing.valid);
        }
    }
}
