module archive_storage_test;

import std.algorithm : canFind, map;
import std.array : array;
import std.conv : to;
import std.datetime : Clock;
import std.process : environment;
import std.regex : matchFirst, regex;
import std.stdio : stderr;
import std.string : replace;
import std.uuid : randomUUID;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.core.log : setLogLevel, LogLevel;
import vibe.data.bson : Bson, BsonDate;
import vibe.data.json : Json, parseJsonString;
import vibe.db.mongo.mongo : MongoClientSettings, MongoDatabase, connectMongoDB, parseMongoDBUrl;

import ircfiber.db.messages : MessageRepository, ArchiveWriteResult,
    ArchiveWriteException, ArchiveWriteFailure;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.network_write_gate : NETWORK_WRITE_EXCLUSION_KEY, NETWORK_WRITERS_KEY;

// This executable never reads application Mongo environment variables. The
// explicit opt-in grants failpoint control of a disposable Mongo 7 fixture;
// its failCommand slot must be idle and enableTestCommands must be enabled.
// URL: mongodb://127.0.0.1:<port>/?replicaSet=rs0 (localhost / [::1] also work).
// No credentials, remote hosts, implicit ports or default database are allowed.
private enum URL_VARIABLE = "IRCFIBER_ARCHIVE_TEST_MONGO_URL";
private enum ISOLATION_VARIABLE = "IRCFIBER_ARCHIVE_TEST_ISOLATED";
private enum SERVER = "archive-storage-owned";
private enum OTHER_SERVER = "archive-storage-other";
private enum long CONCERN_CODE = 64;
private size_t passed, failed;

private final class FixtureAssertion : Exception {
    this(string message) { super(message); }
}

private void require(bool condition, string message) {
    if (!condition) throw new FixtureAssertion(message);
}

private long integer(Bson value) {
    switch (value.type) {
        case Bson.Type.int_: return value.get!int;
        case Bson.Type.long_: return value.get!long;
        case Bson.Type.double_:
            const number = value.get!double;
            require(number >= -9_007_199_254_740_991.0
                && number <= 9_007_199_254_740_991.0, "numeric reply is not a bounded integer");
            const result = cast(long) number;
            require(cast(double) result == number, "numeric reply is not integral");
            return result;
        default: throw new FixtureAssertion("missing or nonnumeric Mongo reply field");
    }
}

private bool hasField(Bson value, string field) {
    require(value.type == Bson.Type.object, "oracle expected a BSON object");
    foreach (key, ignored; value.byKeyValue) if (key == field) return true;
    return false;
}

private void expectFailure(void delegate() operation, ArchiveWriteFailure expected,
        long expectedCode = -1) {
    bool rejected;
    try operation();
    catch (ArchiveWriteException error) {
        require(error.failure == expected, "operation threw the wrong archival failure");
        if (expectedCode >= 0)
            require(error.mongoCode == expectedCode, "operation lost the failpoint error code");
        rejected = true;
    }
    require(rejected, "operation returned an archival acknowledgment instead of rejecting");
}

private void recordCase(string name, void delegate() body) {
    try {
        body();
        ++passed;
        stderr.writeln("  PASS ", name);
    } catch (Throwable error) {
        ++failed;
        stderr.writeln("  FAIL ", name);
        // Never dump arbitrary driver exceptions, connection settings or rows.
        if (auto assertion = cast(FixtureAssertion) error)
            stderr.writeln("    ", assertion.msg);
        else stderr.writeln("    exception type: ", error.classinfo.name);
    }
}

private string admittedUrl() {
    require(environment.get(ISOLATION_VARIABLE, "") == "1",
        "IRCFIBER_ARCHIVE_TEST_ISOLATED=1 is required for a disposable failpoint-capable Mongo");
    const uri = environment.get(URL_VARIABLE, "");
    require(uri.length > 0 && uri.length <= 512,
        "explicit IRCFIBER_ARCHIVE_TEST_MONGO_URL is required");
    // A replica-set option prevents AppMongoConnection injecting/logging a
    // different URL. A URI path is required by the installed vibe driver.
    auto matched = uri.matchFirst(regex(
        `^mongodb://(127\.0\.0\.1|localhost|\[::1\]):([0-9]+)/(?:[A-Za-z0-9_-]+)?\?replicaSet=[A-Za-z0-9_-]+$`));
    require(!matched.empty, "fixture URL must be credential-free single-loopback with explicit port and replicaSet");
    const port = matched.captures[2].to!uint;
    require(port > 0 && port <= ushort.max, "fixture port is invalid");
    return uri;
}

private ushort admittedRedisPort() {
    require(environment.get(ISOLATION_VARIABLE, "") == "1", "isolated Redis opt-in is required");
    const endpoint = environment.get("IRCFIBER_ARCHIVE_TEST_REDIS", "");
    auto matched = endpoint.matchFirst(regex(`^127\.0\.0\.1:([0-9]+)$`));
    require(!matched.empty, "IRCFIBER_ARCHIVE_TEST_REDIS requires explicit disposable 127.0.0.1:port");
    const port = matched.captures[1].to!uint;
    require(port > 0 && port <= ushort.max, "fixture Redis port is invalid");
    return cast(ushort) port;
}

private struct CutoffFixture {
    string network;
    string otherNetwork;
    Bson[] before;
    string[] selected;
}

private final class StorageFixture {
    private MongoDatabase admin;
    private MessageRepository repository;
    private RedisStorage redis;
    private string[] ownedNetworks;
    private string[] ownedMessageIds;
    private bool failpointOwned;
    private long failpointCount;
    private long timestamp;
    private string databaseName;
    private Bson causalReadTimestamp;
    private bool causalReads;

    this(string uri, ushort redisPort) {
        redis = new RedisStorage("127.0.0.1", redisPort);
        redis.connect();
        require(!redis.getDb().exists(NETWORK_WRITE_EXCLUSION_KEY)
            && redis.getDb().scard(NETWORK_WRITERS_KEY) == 0,
            "fixture Redis must be dedicated and have no exclusion or unresolved writers");
        databaseName = "ircfiber_archive_test_" ~ randomUUID().toString().replace("-", "");
        timestamp = Clock.currTime().toUnixTime!long * 1000;
        MongoClientSettings settings;
        require(parseMongoDBUrl(settings, uri), "fixture URL rejected by Mongo driver");
        settings.maxConnections = 2;
        auto client = connectMongoDB(settings);
        admin = client.getDatabase("admin");
        AppMongoConnection.connect(uri, databaseName);
        require(countRows("messages", Bson.emptyObject) == 0
            && countRows("networks", Bson.emptyObject) == 0,
            "new random fixture namespace was not empty");
        verifyIdleFailpoint();
        repository = new MessageRepository();
    }

    private Bson checked(MongoDatabase database, Bson command) {
        auto reply = database.runCommandUnchecked(command);
        require(reply.type == Bson.Type.object && integer(reply["ok"]) == 1,
            "raw Mongo oracle command failed");
        require(!hasField(reply, "writeConcernError"), "raw oracle write concern failed");
        if (hasField(reply, "writeErrors"))
            require(reply["writeErrors"].type == Bson.Type.array
                && reply["writeErrors"].length == 0, "raw oracle write failed");
        return reply;
    }

    private Bson checked(Bson command) {
        return checked(AppMongoConnection.getDb(), command);
    }

    private Bson writeConcern() {
        return Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(5000)]);
    }

    private Bson readConcern() {
        auto concern = Bson(["level": Bson("majority")]);
        if (causalReads) concern["afterClusterTime"] = causalReadTimestamp;
        return concern;
    }

    private long countRows(string collection, Bson filter) {
        auto command = Bson.emptyObject;
        command["count"] = Bson(collection);
        command["query"] = filter;
        command["maxTimeMS"] = Bson(5000);
        command["readConcern"] = readConcern();
        return integer(checked(command)["n"]);
    }

    private Bson[] rows(string collection, Bson filter, int limit = 128) {
        auto command = Bson.emptyObject;
        command["find"] = Bson(collection);
        command["filter"] = filter;
        command["limit"] = Bson(limit);
        command["singleBatch"] = Bson(true);
        command["maxTimeMS"] = Bson(5000);
        command["readConcern"] = readConcern();
        auto cursor = checked(command)["cursor"];
        require(cursor.type == Bson.Type.object && integer(cursor["id"]) == 0,
            "bounded oracle unexpectedly retained a cursor");
        auto batch = cursor["firstBatch"];
        require(batch.type == Bson.Type.array && batch.length <= limit,
            "bounded oracle returned an invalid batch");
        Bson[] result;
        foreach (row; batch.byValue) result ~= row;
        return result;
    }

    private Bson rowById(string collection, string id) {
        auto result = rows(collection, Bson(["_id": Bson(id)]), 2);
        require(result.length == 1, "expected exactly one persisted row");
        return result[0];
    }

    private string newNetwork(bool catalog = false) {
        const id = randomUUID().toString();
        ownedNetworks ~= id;
        if (catalog) insertRaw("networks", Bson(["_id": Bson(id), "id": Bson(id)]));
        return id;
    }

    private string payload(long eid, long time, string text = "fixture") {
        // Deliberate whitespace and field order distinguish verbatim replay
        // from parsing and reserializing an allegedly identical compact event.
        return `{ "eid": ` ~ eid.to!string ~ `, "t": ` ~ time.to!string
            ~ `, "m": "owned-message", "text": ` ~ Json(text).toString() ~ ` }`;
    }

    private string append(string network, string channel, long eid, long time,
            string server = SERVER) {
        require(repository.appendArchivedCompactMessage(server, network, channel,
            payload(eid, time)) == ArchiveWriteResult.inserted, "seed append did not insert");
        auto found = rows("messages", Bson(["serverId": Bson(server), "networkId": Bson(network),
            "eid": Bson(eid), "channel": Bson(channel)]), 2);
        require(found.length == 1, "seed append was not observable in majority history");
        const id = found[0]["_id"].get!string;
        ownedMessageIds ~= id;
        return id;
    }

    private void insertRaw(string collection, Bson document) {
        auto command = Bson.emptyObject;
        command["insert"] = Bson(collection);
        command["documents"] = Bson([document]);
        command["ordered"] = Bson(true);
        command["writeConcern"] = writeConcern();
        require(integer(checked(command)["n"]) == 1, "raw fixture insert did not persist");
    }

    private long setRaw(string collection, string id, Bson changes) {
        auto command = Bson.emptyObject;
        command["update"] = Bson(collection);
        command["updates"] = Bson([Bson(["q": Bson(["_id": Bson(id)]),
            "u": Bson(["$set": changes]), "multi": Bson(false), "upsert": Bson(false)])]);
        command["writeConcern"] = writeConcern();
        return integer(checked(command)["n"]);
    }

    private string legacy(string network, string channel, long time,
            string server = SERVER, bool zeroEid = false) {
        const id = "legacy-" ~ randomUUID().toString();
        auto document = Bson(["_id": Bson(id), "networkId": Bson(network),
            "serverId": Bson(server), "channel": Bson(channel), "t": Bson(time),
            "payload": Bson(`{"legacy":"owned fixture"}`), "tsAt": Bson(BsonDate(time))]);
        if (zeroEid) document["eid"] = Bson(0L);
        insertRaw("messages", document);
        return id;
    }

    private void verifyIdleFailpoint() {
        auto command = Bson.emptyObject;
        command["getParameter"] = Bson(1);
        command["failpoint.failCommand"] = Bson(1);
        auto state = checked(admin, command)["failpoint.failCommand"];
        require(state.type == Bson.Type.object && integer(state["mode"]) == 0,
            "fixture failCommand must be available and idle; enableTestCommands is required");
    }

    private void armConcernError(string verb, string collection) {
        require(!failpointOwned, "fixture already owns a failpoint");
        verifyIdleFailpoint();
        auto command = Bson.emptyObject;
        command["configureFailPoint"] = Bson("failCommand");
        command["mode"] = Bson(["times": Bson(1)]);
        command["data"] = Bson(["failCommands": Bson([Bson(verb)]),
            "namespace": Bson(databaseName ~ "." ~ collection),
            "writeConcernError": Bson(["code": Bson(cast(int) CONCERN_CODE),
                "errmsg": Bson("owned archive fixture uncertain write")])]);
        // Even an ambiguous configure response must trigger fixture cleanup.
        failpointOwned = true;
        failpointCount = integer(checked(admin, command)["count"]);
    }

    private void disarmConcernError(bool requireHit) {
        if (!failpointOwned) return;
        auto command = Bson.emptyObject;
        command["configureFailPoint"] = Bson("failCommand");
        command["mode"] = Bson("off");
        const count = integer(checked(admin, command)["count"]);
        failpointOwned = false;
        if (requireHit)
            require(count == failpointCount + 1, "real Mongo failCommand did not fire exactly once");
    }

    private void uncertainWrite(string verb, void delegate() operation, string collection = "messages") {
        armConcernError(verb, collection);
        scope(exit) disarmConcernError(false);
        expectFailure(operation, ArchiveWriteFailure.rejected, CONCERN_CODE);
        disarmConcernError(true);
        // Injected concern failure skips the server's replication wait. A
        // noncausal majority read can still select the pre-write snapshot.
        // Require majority visibility of the primary's actual applied optime.
        auto state = checked(admin, Bson(["replSetGetStatus": Bson(1)]));
        auto applied = state["optimes"]["appliedOpTime"];
        require(applied.type == Bson.Type.object && hasField(applied, "ts"),
            "replica-set applied optime is unavailable");
        causalReadTimestamp = applied["ts"];
        causalReads = true;
    }

    private void verifyUnchanged(Bson before, Bson after, string channel) {
        foreach (field; ["_id", "serverId", "networkId", "eid", "t", "payload", "tsAt"]) {
            require(hasField(before, field) == hasField(after, field),
                "mutation changed immutable field presence");
            if (hasField(before, field))
                require(before[field].toString() == after[field].toString(),
                    "mutation changed an immutable stored field");
        }
        require(after["channel"].get!string == channel, "mutation affected the wrong channel scope");
    }

    private CutoffFixture cutoffData() {
        CutoffFixture data;
        data.network = newNetwork();
        data.otherNetwork = newNetwork();
        // Event order is authoritative even when timestamps disagree.
        data.selected ~= append(data.network, "#source", 9, timestamp + 1000);
        data.selected ~= append(data.network, "#source", 10, timestamp + 1000);
        append(data.network, "#source", 11, timestamp - 1000);
        data.selected ~= legacy(data.network, "#source", timestamp - 1);
        data.selected ~= legacy(data.network, "#source", timestamp);
        legacy(data.network, "#source", timestamp + 1);
        legacy(data.network, "#source", timestamp - 1, SERVER, true);
        append(data.network, "#source", 5, timestamp - 1, OTHER_SERVER);
        append(data.otherNetwork, "#source", 5, timestamp - 1);
        append(data.network, "#other", 5, timestamp - 1);
        append(data.network, "#destination", 3, timestamp - 1);
        data.before = rows("messages", Bson(["networkId": Bson(["$in":
            Bson([Bson(data.network), Bson(data.otherNetwork)])])]));
        require(data.before.length == 11 && data.selected.length == 4,
            "cutoff fixture did not create every isolation boundary");
        return data;
    }

    void runCases() {
        recordCase("compact insert preserves original bytes and exact retry is alreadyPersisted", {
            const network = newNetwork();
            const compact = payload(101, timestamp, "verbatim");
            require(repository.appendArchivedCompactMessage(SERVER, network, "#SOURCE", compact)
                == ArchiveWriteResult.inserted, "compact append did not acknowledge insert");
            auto found = rows("messages", Bson(["networkId": Bson(network)]));
            require(found.length == 1, "compact append did not create one row");
            auto row = found[0];
            require(row["serverId"].get!string == SERVER && row["networkId"].get!string == network
                && row["channel"].get!string == "#source" && integer(row["eid"]) == 101
                && integer(row["t"]) == timestamp && row["payload"].get!string == compact
                && hasField(row, "tsAt"), "compact append changed original attribution or payload");
            require(repository.appendArchivedCompactMessage(SERVER, network, "#source", compact)
                == ArchiveWriteResult.alreadyPersisted, "identical bytes were not idempotent");
            require(countRows("messages", Bson(["networkId": Bson(network)])) == 1,
                "duplicate replay created another row");
            verifyUnchanged(row, rowById("messages", row["_id"].get!string), "#source");
        });

        recordCase("conflicting payload, timestamp and semantically equal different bytes reject", {
            const network = newNetwork();
            const original = payload(103, timestamp, "original");
            require(repository.appendArchivedCompactMessage(SERVER, network, "#conflict", original)
                == ArchiveWriteResult.inserted, "conflict seed did not insert");
            auto before = rows("messages", Bson(["networkId": Bson(network)]))[0];
            expectFailure({ repository.appendArchivedCompactMessage(SERVER, network,
                "#conflict", payload(103, timestamp, "different")); }, ArchiveWriteFailure.identityMismatch);
            expectFailure({ repository.appendArchivedCompactMessage(SERVER, network,
                "#conflict", payload(103, timestamp + 1, "original")); }, ArchiveWriteFailure.identityMismatch);
            auto reserialized = parseJsonString(original).toString();
            require(reserialized != original, "verbatim-byte conflict fixture did not differ");
            expectFailure({ repository.appendArchivedCompactMessage(SERVER, network,
                "#conflict", reserialized); }, ArchiveWriteFailure.identityMismatch);
            require(countRows("messages", Bson(["networkId": Bson(network)])) == 1,
                "conflicting identity added rows");
            verifyUnchanged(before, rowById("messages", before["_id"].get!string), "#conflict");
        });

        recordCase("duplicate verification rejects stored eid and attribution conflicts", {
            foreach (field; ["eid", "serverId", "networkId"]) {
                const network = newNetwork();
                const id = append(network, "#identity", 104, timestamp);
                auto changes = Bson.emptyObject;
                changes[field] = field == "eid" ? Bson(105L) : Bson("conflicting-" ~ field);
                require(setRaw("messages", id, changes) == 1, "identity conflict was not injected");
                auto conflicting = rowById("messages", id);
                expectFailure({ repository.appendArchivedCompactMessage(SERVER, network,
                    "#identity", payload(104, timestamp)); }, ArchiveWriteFailure.identityMismatch);
                verifyUnchanged(conflicting, rowById("messages", id), "#identity");
            }
        });

        recordCase("channel-renamed original append remains idempotent", {
            const network = newNetwork();
            const id = append(network, "#before", 106, timestamp);
            auto before = rowById("messages", id);
            require(repository.renameArchivedChannel(SERVER, network, "#BEFORE", "#AFTER",
                106, timestamp) == 1, "ordered rename did not move original row");
            require(repository.appendArchivedCompactMessage(SERVER, network, "#before",
                payload(106, timestamp)) == ArchiveWriteResult.alreadyPersisted,
                "renamed duplicate compared the mutable channel");
            verifyUnchanged(before, rowById("messages", id), "#after");
            require(countRows("messages", Bson(["networkId": Bson(network)])) == 1,
                "renamed retry resurrected the old buffer");
        });

        recordCase("cutoff rename and retry preserve newer eids, legacy timestamps and all scopes", {
            auto data = cutoffData();
            require(repository.renameArchivedChannel(SERVER, data.network, "#SOURCE", "#DESTINATION",
                10, timestamp) == 4, "rename did not acknowledge the exact frozen prefix");
            foreach (before; data.before) {
                const id = before["_id"].get!string;
                verifyUnchanged(before, rowById("messages", id), data.selected.canFind(id)
                    ? "#destination" : before["channel"].get!string);
            }
            const late = append(data.network, "#source", 12, timestamp - 1000);
            require(repository.renameArchivedChannel(SERVER, data.network, "#source", "#destination",
                10, timestamp) == 0, "rename retry modified newer reused-buffer content");
            require(rowById("messages", late)["channel"].get!string == "#source",
                "rename retry moved a post-cutoff eid");
            foreach (before; data.before) {
                const id = before["_id"].get!string;
                verifyUnchanged(before, rowById("messages", id), data.selected.canFind(id)
                    ? "#destination" : before["channel"].get!string);
            }
            require(countRows("messages", Bson(["networkId": Bson(["$in":
                Bson([Bson(data.network), Bson(data.otherNetwork)])])])) == 12,
                "rename lost or duplicated rows");
        });

        recordCase("cutoff purge and retry preserve newer eids, legacy timestamps and all scopes", {
            auto data = cutoffData();
            require(repository.deleteArchivedChannel(SERVER, data.network, "#SOURCE", 10, timestamp) == 4,
                "purge did not acknowledge the exact frozen prefix");
            foreach (before; data.before) {
                const id = before["_id"].get!string;
                if (data.selected.canFind(id))
                    require(countRows("messages", Bson(["_id": Bson(id)])) == 0,
                        "purge left a pre-cutoff row");
                else verifyUnchanged(before, rowById("messages", id), before["channel"].get!string);
            }
            const late = append(data.network, "#source", 12, timestamp - 1000);
            require(repository.deleteArchivedChannel(SERVER, data.network, "#source", 10, timestamp) == 0,
                "purge retry removed newer reused-buffer content");
            require(integer(rowById("messages", late)["eid"]) == 12, "purge lost post-cutoff append");
            foreach (before; data.before) {
                const id = before["_id"].get!string;
                if (!data.selected.canFind(id))
                    verifyUnchanged(before, rowById("messages", id), before["channel"].get!string);
            }
            require(countRows("messages", Bson(["networkId": Bson(["$in":
                Bson([Bson(data.network), Bson(data.otherNetwork)])])])) == 8,
                "purge removed a row outside its frozen scope");
        });

        recordCase("invalid append identities and cutoff scopes never create or mutate rows", {
            const network = newNetwork();
            const id = append(network, "#valid", 110, timestamp);
            auto before = rowById("messages", id);
            foreach (invalid; ["not-json", "[]", payload(0, timestamp),
                    payload(-1, timestamp), payload(111, 0)])
                expectFailure({ repository.appendArchivedCompactMessage(SERVER, network,
                    "#valid", invalid); }, ArchiveWriteFailure.invalidInput);
            expectFailure({ repository.appendArchivedMessage(SERVER, network, "#valid", Json(null)); },
                ArchiveWriteFailure.invalidInput);
            expectFailure({ repository.appendArchivedCompactMessage("", network, "#valid",
                payload(111, timestamp)); }, ArchiveWriteFailure.invalidInput);
            expectFailure({ repository.appendArchivedCompactMessage(SERVER, network, "",
                payload(111, timestamp)); }, ArchiveWriteFailure.invalidInput);
            expectFailure({ repository.renameArchivedChannel(SERVER, network, "#valid", "#new",
                0, timestamp); }, ArchiveWriteFailure.invalidInput);
            expectFailure({ repository.renameArchivedChannel(SERVER, network, "#valid", "",
                110, timestamp); }, ArchiveWriteFailure.invalidInput);
            expectFailure({ repository.deleteArchivedChannel(SERVER, network, "#valid",
                110, 0); }, ArchiveWriteFailure.invalidInput);
            expectFailure({ repository.deleteArchivedChannel("", network, "#valid",
                110, timestamp); }, ArchiveWriteFailure.invalidInput);
            require(countRows("messages", Bson(["networkId": Bson(network)])) == 1,
                "invalid archival inputs changed persisted row count");
            verifyUnchanged(before, rowById("messages", id), "#valid");
        });

        recordCase("real insert writeConcernError rejects after side effect; same identity retries once", {
            const network = newNetwork();
            const compact = payload(120, timestamp, "uncertain-insert");
            uncertainWrite("insert", { repository.appendArchivedCompactMessage(SERVER, network,
                "#uncertain", compact); });
            auto found = rows("messages", Bson(["networkId": Bson(network)]));
            require(found.length == 1 && found[0]["payload"].get!string == compact,
                "writeConcernError fixture did not execute the uncertain insert");
            require(repository.appendArchivedCompactMessage(SERVER, network, "#uncertain", compact)
                == ArchiveWriteResult.alreadyPersisted, "uncertain insert retry did not verify durable identity");
            require(countRows("messages", Bson(["networkId": Bson(network)])) == 1,
                "uncertain insert retry created duplicate history");
        });

        recordCase("real duplicate writeConcernError is not mistaken for alreadyPersisted", {
            const network = newNetwork();
            const id = append(network, "#duplicate-concern", 122, timestamp);
            auto before = rowById("messages", id);
            uncertainWrite("insert", { repository.appendArchivedCompactMessage(SERVER, network,
                "#duplicate-concern", payload(122, timestamp)); });
            require(repository.appendArchivedCompactMessage(SERVER, network, "#duplicate-concern",
                payload(122, timestamp)) == ArchiveWriteResult.alreadyPersisted,
                "verified duplicate did not recover after concern failure");
            verifyUnchanged(before, rowById("messages", id), "#duplicate-concern");
        });

        recordCase("real rename writeConcernError rejects after mutation and frozen retry preserves new rows", {
            const network = newNetwork();
            const id = append(network, "#uncertain-old", 130, timestamp);
            const newer = append(network, "#uncertain-old", 131, timestamp - 1);
            auto before = rowById("messages", id);
            uncertainWrite("update", { repository.renameArchivedChannel(SERVER, network,
                "#uncertain-old", "#uncertain-new", 130, timestamp); });
            verifyUnchanged(before, rowById("messages", id), "#uncertain-new");
            require(repository.renameArchivedChannel(SERVER, network, "#uncertain-old",
                "#uncertain-new", 130, timestamp) == 0, "uncertain rename retry was not idempotent");
            require(rowById("messages", newer)["channel"].get!string == "#uncertain-old",
                "uncertain rename retry moved a newer eid");
            require(countRows("messages", Bson(["networkId": Bson(network)])) == 2,
                "uncertain rename changed row cardinality");
        });

        recordCase("real purge writeConcernError rejects after deletion and frozen retry preserves new rows", {
            const network = newNetwork();
            const id = append(network, "#uncertain-purge", 140, timestamp);
            const newer = append(network, "#uncertain-purge", 141, timestamp - 1);
            uncertainWrite("delete", { repository.deleteArchivedChannel(SERVER, network,
                "#uncertain-purge", 140, timestamp); });
            require(countRows("messages", Bson(["_id": Bson(id)])) == 0,
                "writeConcernError fixture did not execute the uncertain delete");
            require(repository.deleteArchivedChannel(SERVER, network, "#uncertain-purge",
                140, timestamp) == 0, "uncertain purge retry was not idempotent");
            require(integer(rowById("messages", newer)["eid"]) == 141
                && countRows("messages", Bson(["networkId": Bson(network)])) == 1,
                "uncertain purge retry deleted newer history");
        });

        recordCase("durable archive catalog discovers prejournal servers and survives projection loss", {
            const network = newNetwork(true);
            legacy(network, "#history", timestamp, "legacy-engine-a");
            legacy(network, "#history", timestamp, "legacy-engine-b");
            auto scopes = repository.registerArchiveScopes(redis, network, [SERVER]);
            require(scopes.length == 3 && scopes[0] == SERVER && scopes.canFind("legacy-engine-a")
                && scopes.canFind("legacy-engine-b"), "first registration omitted a legacy server scope");
            auto doc = rowById("networks", network);
            require(integer(doc["archiveScopeVersion"]) == 1 && doc["archiveServers"].length == 3,
                "scope registration was not durable in canonical network metadata");
            legacy(network, "#history", timestamp, "later-legacy-engine");
            scopes = repository.archivedServerScopes(redis, network); // No Redis retained projection supplied.
            require(scopes.length == 4 && scopes[0] == SERVER && scopes.canFind("later-legacy-engine")
                && scopes.canFind("legacy-engine-a") && scopes.canFind("legacy-engine-b"),
                "Redis projection loss or later legacy discovery lost original attribution");
            doc = rowById("networks", network);
            require(doc["archiveServers"].length == 4, "legacy discovery was not durably cataloged");
            require(repository.registerArchiveScopes(redis, network, [SERVER, "legacy-engine-a"]).length == 4,
                "duplicate catalog registration added another scope");
        });

        recordCase("producer preparation validates majority owner and rejects uncertain catalog acknowledgments", {
            const network = newNetwork();
            const owner = randomUUID().toString();
            insertRaw("networks", Bson(["_id": Bson(network), "id": Bson(network), "userId": Bson(owner)]));
            expectFailure({ repository.registerArchiveScopes(redis, network, [SERVER], randomUUID().toString()); },
                ArchiveWriteFailure.identityMismatch);
            require(!hasField(rowById("networks", network), "archiveScopeVersion"),
                "owner mismatch installed archival provenance");
            require(repository.registerArchiveScopes(redis, network, [SERVER], owner) == [SERVER],
                "matching majority owner did not register the producer");
            uncertainWrite("update", {
                repository.registerArchiveScopes(redis, network, [OTHER_SERVER], owner);
            }, "networks");
            require(rowById("networks", network)["archiveServers"].length == 2,
                "uncertain scope write did not exercise a committed catalog update");
            const retried = repository.registerArchiveScopes(redis, network, [OTHER_SERVER], owner);
            require(retried.length == 2 && retried[0] == SERVER && retried.canFind(OTHER_SERVER),
                "positive majority retry lost original provenance or duplicated its target");
        });

        recordCase("archive catalog admits 64 scopes and rejects a 65th without partial metadata", {
            const network = newNetwork(true);
            string[] scopes;
            foreach (i; 0 .. 64) scopes ~= "bounded-engine-" ~ i.to!string;
            auto registered = repository.registerArchiveScopes(redis, network, scopes);
            require(registered.length == 64 && registered[0] == scopes[0], "64-scope catalog did not fit");
            auto before = rowById("networks", network)["archiveServers"].toString();
            expectFailure({ repository.registerArchiveScopes(redis, network, ["overflow-engine"]); },
                ArchiveWriteFailure.unavailable);
            require(rowById("networks", network)["archiveServers"].toString() == before,
                "65th scope partially mutated durable metadata");
            require(repository.archivedServerScopes(redis, network).length == 64,
                "bounded archive discovery truncated an accepted catalog");
        });

        recordCase("65 prejournal servers fail closed without cataloging a truncated subset", {
            const network = newNetwork(true);
            foreach (i; 0 .. 65) legacy(network, "#history", timestamp, "legacy-overflow-" ~ i.to!string);
            expectFailure({ repository.archivedServerScopes(redis, network); }, ArchiveWriteFailure.unavailable);
            auto doc = rowById("networks", network);
            require(!hasField(doc, "archiveScopeVersion") && !hasField(doc, "archiveServers"),
                "overflow legacy discovery persisted an incomplete server catalog");
            require(countRows("messages", Bson(["networkId": Bson(network)])) == 65,
                "legacy discovery modified or discarded history");
        });

        recordCase("deleted network cannot silently gain a new archival scope", {
            const missing = newNetwork();
            require(repository.registerArchiveScopes(redis, missing, [SERVER]).length == 0,
                "register recreated explicitly absent network metadata");
            expectFailure({ repository.archivedServerScopes(redis, missing); }, ArchiveWriteFailure.unavailable);
            require(countRows("networks", Bson(["id": Bson(missing)])) == 0,
                "archival discovery recreated deleted network metadata");
        });
    }

    void cleanup() {
        scope (exit) redis.close();
        // Lost-ack writer evidence is deliberately not cleared: this executable
        // requires disposable Redis, and cannot attest away an uncertain owner.
        // Never drop a database/collection and never disable somebody else's
        // failpoint. Every delete is restricted to UUIDs created by this run.
        disarmConcernError(false);
        if (!ownedNetworks.length) return;
        foreach (collection; ["messages", "networks"]) {
            const scopeField = collection == "messages" ? "networkId" : "id";
            auto filter = Bson([scopeField: Bson(["$in": Bson(ownedNetworks.map!(id => Bson(id)).array)])]);
            // A conflict test deliberately corrupts networkId; its original
            // row identity remains owned even if that test exits early.
            if (collection == "messages" && ownedMessageIds.length) {
                auto identityFilter = Bson(["_id":
                    Bson(["$in": Bson(ownedMessageIds.map!(id => Bson(id)).array)])]);
                filter = Bson(["$or": Bson([filter, identityFilter])]);
            }
            auto command = Bson.emptyObject;
            command["delete"] = Bson(collection);
            command["deletes"] = Bson([Bson(["q": filter, "limit": Bson(0)])]);
            command["writeConcern"] = writeConcern();
            checked(command);
            require(countRows(collection, filter) == 0, "owned fixture cleanup left documents");
        }
    }
}

int main() {
    setLogLevel(LogLevel.warn);
    string uri;
    ushort redisPort;
    try {
        uri = admittedUrl();
        redisPort = admittedRedisPort();
    }
    catch (Throwable error) {
        ++failed;
        stderr.writeln("  FAIL explicit isolated fixture admission");
        if (auto assertion = cast(FixtureAssertion) error) stderr.writeln("    ", assertion.msg);
        stderr.writeln("Result: cases=1 passed=0 failed=1");
        return 1;
    }
    runTask(() nothrow {
        StorageFixture fixture;
        try {
            fixture = new StorageFixture(uri, redisPort);
            fixture.runCases();
        } catch (Throwable error) {
            ++failed;
            try {
                stderr.writeln("  FAIL Mongo fixture setup/execution");
                if (auto assertion = cast(FixtureAssertion) error) stderr.writeln("    ", assertion.msg);
                else stderr.writeln("    exception type: ", error.classinfo.name);
            } catch (Throwable) {}
        }
        try {
            if (fixture !is null)
                recordCase("cleanup deletes only run-owned fixture documents", { fixture.cleanup(); });
        } catch (Throwable) {
            ++failed;
        }
        try stderr.writeln("Result: cases=", passed + failed, " passed=", passed, " failed=", failed);
        catch (Throwable) {}
        exitEventLoop();
    });
    runEventLoop();
    return failed ? 1 : 0;
}
