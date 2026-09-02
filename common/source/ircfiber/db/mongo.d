module ircfiber.db.mongo;

import vibe.db.mongo.mongo;
import vibe.core.log;
import vibe.data.bson : Bson;
import std.algorithm : min;
import std.conv : to;
import std.typecons : Nullable;
import core.time : seconds, Duration;
import ircfiber.db.circuit_breaker : initMongoCircuitBreaker;

/// Cap on simultaneous open MongoDB connections per process.
///
/// vibe.d's `ConnectionPool` defaults to `uint.max` (effectively unlimited)
/// and only shrinks via `cleanupConnections()`. The pool is therefore kept
/// bounded by this cap and is never evicted (see `cleanupConnections`).
private enum uint MAX_MONGO_CONNECTIONS = 50;

/// MongoDB connection manager.
final class AppMongoConnection {
    private static MongoClient client;
    private static MongoDatabase db;
    private static bool connected;
    private static string dbName;

    /// Connects to MongoDB.
    static void connect(string uri = "mongodb://127.0.0.1:27017", string name = "ircfiber") @trusted {
        dbName = name;
        // Inject replicaSet/authSource if not already present. vibe-d's
        // driver does not implement readPreference (settings.d: "Unknown
        // MongoDB option") — every process start logged that warning and
        // the option never had any effect, so it is not injected.
        // URI may be single host or multi-host: mongodb://user:pass@host1,host2/db?opts
        string effectiveUri = uri;
        bool hasReplicaSet = false;
        bool hasAuthSource = false;
        // Simple substring check — sufficient for our injection needs.
        import std.string : indexOf;
        if (effectiveUri.indexOf("replicaSet=") != -1) hasReplicaSet = true;
        if (effectiveUri.indexOf("authSource=") != -1) hasAuthSource = true;
        // The plan's K8s IRCFIBER_MONGO_URL already contains ?replicaSet=rs0, so
        // injection is a no-op there. For the OVH single-host URI the driver
        // simply uses a single-node replica set.
        if (!hasReplicaSet || !hasAuthSource) {
            string sep = effectiveUri.indexOf("?") != -1 ? "&" : "?";
            string inject = "";
            if (!hasReplicaSet) {
                inject ~= sep ~ "replicaSet=rs0";
                sep = "&";
            }
            if (!hasAuthSource && effectiveUri.indexOf("/ircfiber") != -1) {
                // authSource defaults to admin, but our app user is in ircfiber DB
                inject ~= sep ~ "authSource=ircfiber";
            }
            effectiveUri ~= inject;
            if (inject.length > 0) {
                logInfo("MongoDB URI augmented for replica set: %s -> %s", uri, effectiveUri);
            }
        }
        MongoClientSettings settings;
        if (!parseMongoDBUrl(settings, effectiveUri)) {
            throw new Exception("Unable to parse MongoDB URL: " ~ effectiveUri);
        }
        settings.maxConnections = min(settings.maxConnections, MAX_MONGO_CONNECTIONS);
        logInfo("MongoDB connection pool size capped at %d", settings.maxConnections);
        client = connectMongoDB(settings);
        db = client.getDatabase(dbName);
        connected = true;
        initMongoCircuitBreaker();
        logInfo("Connected to MongoDB database %s (uri: %s)", dbName, effectiveUri);
    }
    /// Returns the MongoDB database.
    static MongoDatabase getDb() { return db; }
    /// Whether MongoDB is connected.
    static bool isConnected() { return connected; }
    /// Returns the database name.
    static string name() { return dbName; }

    /// Closes all currently unused connections in the pool.
    ///
    /// NOT called periodically any more — with vibe-d 0.10.3 every evicted
    /// `MongoConnection` leaks its socket: `disconnect()` only drops the
    /// `m_stream` copy of the `TCPConnection` while `m_outRange` keeps a
    /// third reference, so the refcounted fd is shut down but never
    /// `close()`d, and `ConnectionPool.removeUnused` leaves the object in
    /// `m_lockCount`, so the GC never finalizes it either. The prod engine
    /// leaked ~100 fds/h this way (strace 2026-09-02: 12 Mongo connects,
    /// 0 closes, `shutdown()` exactly every 60 s) and hit the 1024 soft
    /// limit after ~8 h, losing DNS/Redis/IRC until the monitor restarted
    /// it. A warm, capped pool is safe: a pooled connection that dies is
    /// reconnected lazily by `MongoConnection.send`, which replaces the old
    /// stream references and thereby closes the old socket.
    static void cleanupConnections() @trusted {
        if (client) client.cleanupConnections();
    }

    /// Runs an admin command and returns the result as a Bson document.
    /// Wraps `runCommandChecked` so callers can use a typed `Bson`.
    /// Throws on connection failure.
    static Bson runCommand(Bson cmd) @trusted {
        if (!connected) throw new Exception("MongoDB not connected");
        return db.runCommandChecked(cmd);
    }

    /// Returns the subset of `serverStatus` we surface in the admin dashboard.
    /// Calls Mongo's `serverStatus` admin command and pulls out the keys we
    /// care about (host, version, uptime, connections, opcounters, mem).
    /// Throws on failure — callers should catch and surface a degraded state.
    static Bson serverStatusSubset() @trusted {
        if (!connected) throw new Exception("MongoDB not connected");
        static struct Cmd { int serverStatus = 1; }
        auto result = db.runCommandChecked(Cmd());
        return projectServerStatus(result);
    }

    /// Runs `dbStats` and returns the document as-is.
    static Bson dbStats() @trusted {
        if (!connected) throw new Exception("MongoDB not connected");
        static struct Cmd { int dbStats = 1; int scale = 1; }
        return db.runCommandChecked(Cmd());
    }

    /// Returns a lightweight summary for the collections dashboard tab.
    /// Each entry has: name, count (estimatedDocumentCount), size, indexes.
    /// Uses the `listCollections` admin command to enumerate.
    static Bson[] listCollectionsWithCounts() @trusted {
        Bson[] out_;
        if (!connected) return out_;
        static struct ListCmd { int listCollections = 1; }
        try {
            foreach (entry; db.runListCommand!Bson(ListCmd())) {
                if (bsonHas(entry, "name")) {
                    auto collName = entry["name"].get!string;
                    long count = 0;
                    try {
                        auto coll = db[collName];
                        count = cast(long) coll.estimatedDocumentCount();
                    } catch (Exception) {}
                    long size = 0, avgObjSize = 0, storageSize = 0, totalIndexSize = 0;
                    long nindexes = 0;
                    try {
                        static struct StatsCmd { string collStats; int scale = 1; }
                        StatsCmd sc;
                        sc.collStats = collName;
                        auto stats = db.runCommandChecked(sc);
                        if (bsonHas(stats, "size")) size = stats["size"].get!long;
                        if (bsonHas(stats, "avgObjSize")) avgObjSize = stats["avgObjSize"].get!long;
                        if (bsonHas(stats, "storageSize")) storageSize = stats["storageSize"].get!long;
                        if (bsonHas(stats, "totalIndexSize")) totalIndexSize = stats["totalIndexSize"].get!long;
                        if (bsonHas(stats, "nindexes")) nindexes = stats["nindexes"].get!long;
                    } catch (Exception) {}
                    static struct Doc {
                        string name;
                        long count;
                        long size;
                        long avgObjSize;
                        long storageSize;
                        long totalIndexSize;
                        long nindexes;
                        Bson toBson() const {
                            Bson b = Bson.emptyObject;
                            b["name"] = Bson(name);
                            b["count"] = Bson(count);
                            b["size"] = Bson(size);
                            b["avgObjSize"] = Bson(avgObjSize);
                            b["storageSize"] = Bson(storageSize);
                            b["totalIndexSize"] = Bson(totalIndexSize);
                            b["nindexes"] = Bson(nindexes);
                            return b;
                        }
                    }
                    Doc d;
                    d.name = collName;
                    d.count = count;
                    d.size = size;
                    d.avgObjSize = avgObjSize;
                    d.storageSize = storageSize;
                    d.totalIndexSize = totalIndexSize;
                    d.nindexes = nindexes;
                    out_ ~= d.toBson();
                }
            }
        } catch (Exception e) {
            logDiagnostic("listCollectionsWithCounts failed: %s", e.msg);
        }
        return out_;
    }

    /// Returns collStats for a single collection, or Nullable.init if missing.
    static Nullable!Bson collectionStats(string collName) @trusted {
        if (!connected) return Nullable!Bson();
        try {
            static struct Cmd { string collStats; int scale = 1; }
            Cmd c;
            c.collStats = collName;
            auto stats = db.runCommandChecked(c);
            return Nullable!Bson(stats);
        } catch (Exception) {
            return Nullable!Bson();
        }
    }

    /// Returns the list of indexes for a collection as Bson docs.
    static Bson[] listIndexes(string collName) @trusted {
        Bson[] out_;
        if (!connected) return out_;
        try {
            auto coll = db[collName];
            foreach (idx; coll.listIndexes!Bson()) {
                out_ ~= idx;
            }
        } catch (Exception) {}
        return out_;
    }

    /// Safely run a find query with hard limits. Returns an empty array on failure.
    /// - `limit` is capped to 100
    /// - `maxTimeMs` is enforced via `FindOptions.maxTimeMS`
    /// Caller is responsible for ensuring the filter is safe (no $where/$function).
    static Bson[] safeFind(string collName, Bson filter, Bson projection,
                           Bson sort, int limit, int maxTimeMs) @trusted {
        Bson[] empty;
        if (!connected) return empty;
        if (limit < 1) limit = 1;
        if (limit > 100) limit = 100;
        if (maxTimeMs < 1) maxTimeMs = 2000;
        if (maxTimeMs > 10_000) maxTimeMs = 10_000;
        try {
            import vibe.db.mongo.impl.crud : FindOptions;
            FindOptions opts;
            opts.limit = Nullable!long(limit);
            opts.maxTimeMS = Nullable!long(maxTimeMs);
            if (sort.type != Bson.Type.undefined) opts.sort = Nullable!Bson(sort);
            auto coll = db[collName];
            Bson[] out_;
            foreach (doc; coll.find!Bson(filter, projection, opts)) out_ ~= doc;
            return out_;
        } catch (Exception) {
            return null;
        }
    }

    /// Returns true if a Bson document has the given key. Bson doesn't
    /// implement `in` directly, so we iterate byKeyValue.
    private static bool bsonHas(const Bson b, const string key) {
        if (b.type != Bson.Type.object) return false;
        foreach (k, v; b.byKeyValue) {
            if (k == key) return true;
        }
        return false;
    }

    /// Builds the slim serverStatus document we expose to the admin SPA.
    /// Uses a serializable struct so we sidestep Bson's limited opAssign surface.
    private static Bson projectServerStatus(const Bson result) @trusted {
        static struct S {
            string host;
            string redisVersion;
            string process;
            string pid;
            string uptime;
            string connCurrent;
            string connAvailable;
            string connTotalCreated;
            string connActive;
            string memResident;
            string memVirtual;
            string memMapped;
            Bson opcounters;

            Bson toBson() const {
                Bson b = Bson.emptyObject;
                if (host.length) b["host"] = Bson(host);
                if (redisVersion.length) b["version"] = Bson(redisVersion);
                if (process.length) b["process"] = Bson(process);
                if (pid.length) b["pid"] = Bson(pid);
                if (uptime.length) b["uptime"] = Bson(uptime);
                // Build sub-objects locally first — Bson is a value type
                // so chained assignment (b["x"]["y"] = ...) silently no-ops.
                if (connCurrent.length || connAvailable.length ||
                    connTotalCreated.length || connActive.length) {
                    Bson conn = Bson.emptyObject;
                    if (connCurrent.length) conn["current"] = Bson(connCurrent);
                    if (connAvailable.length) conn["available"] = Bson(connAvailable);
                    if (connTotalCreated.length) conn["totalCreated"] = Bson(connTotalCreated);
                    if (connActive.length) conn["active"] = Bson(connActive);
                    b["connections"] = conn;
                }
                if (memResident.length || memVirtual.length || memMapped.length) {
                    Bson m = Bson.emptyObject;
                    if (memResident.length) m["resident"] = Bson(memResident);
                    if (memVirtual.length) m["virtual"] = Bson(memVirtual);
                    if (memMapped.length) m["mapped"] = Bson(memMapped);
                    b["mem"] = m;
                }
                if (opcounters.type != Bson.Type.undefined && opcounters.type != Bson.Type.null_)
                    b["opcounters"] = opcounters;
                return b;
            }
        }
        S s;
        void pickStr(string k, ref string field) {
            if (bsonHas(result, k)) {
                try field = result[k].get!string;
                catch (Exception) {
                    // numeric — serialize as string for the wire
                    try field = result[k].toString();
                    catch (Exception) {}
                }
            }
        }
        void pickNum(string k, ref string field) {
            if (bsonHas(result, k)) {
                try field = result[k].toString();
                catch (Exception) {}
            }
        }
        pickStr("host", s.host);
        pickStr("version", s.redisVersion);
        pickStr("process", s.process);
        pickNum("pid", s.pid);
        pickNum("uptime", s.uptime);
        if (bsonHas(result, "connections") && result["connections"].type == Bson.Type.object) {
            auto c = result["connections"];
            if (bsonHas(c, "current")) s.connCurrent = c["current"].toString();
            if (bsonHas(c, "available")) s.connAvailable = c["available"].toString();
            if (bsonHas(c, "totalCreated")) s.connTotalCreated = c["totalCreated"].toString();
            if (bsonHas(c, "active")) s.connActive = c["active"].toString();
        }
        if (bsonHas(result, "mem") && result["mem"].type == Bson.Type.object) {
            auto m = result["mem"];
            if (bsonHas(m, "resident")) s.memResident = m["resident"].toString();
            if (bsonHas(m, "virtual")) s.memVirtual = m["virtual"].toString();
            if (bsonHas(m, "mapped")) s.memMapped = m["mapped"].toString();
        }
        if (bsonHas(result, "opcounters")) s.opcounters = result["opcounters"];
        return s.toBson();
    }
}