module ircfiber.testing.isolated_db;

import std.conv : to;
import std.exception : enforce;
import std.process : environment;
import std.regex : matchFirst, regex;
import std.stdio : writeln;

import ircfiber.storage.redis : RedisStorage;
import ircfiber.db.mongo : AppMongoConnection;
import vibe.data.bson : Bson;

private struct FixtureEndpoint {
    string host;
    ushort port;
}

private FixtureEndpoint fixtureEndpoint(string uri, string scheme) {
    enforce(uri.length <= 2048, "Isolated database test URI is too long");
    foreach (c; uri)
        enforce(c > ' ' && c != 127, "Invalid isolated database test URI");
    const suffix = scheme == "redis" ? `(?:/0?)?$` : `(?:/[A-Za-z0-9_-]*)?(?:\?[^#]*)?$`;
    auto matched = uri.matchFirst(regex("^" ~ scheme
        ~ `://(127\.0\.0\.1|localhost|\[::1\]):([0-9]+)` ~ suffix));
    enforce(!matched.empty, "Isolated database tests require a single loopback URI with an explicit port");
    const port = matched.captures[2].to!uint;
    enforce(port > 0 && port <= ushort.max, "Invalid isolated database test port");
    const host = matched.captures[1];
    return FixtureEndpoint(host == "[::1]" ? "::1" : host, cast(ushort) port);
}

/// Absent fixture admission skips without opening any database connection.
/// An explicitly supplied but invalid/unavailable fixture fails the test.
RedisStorage isolatedTestRedis(string testName) {
    enum variable = "IRCFIBER_HISTORY_TEST_REDIS_URL";
    const uri = environment.get(variable, "");
    if (!uri.length) {
        writeln("SKIP ", testName, ": ", variable, " is absent; no Redis connection attempted");
        return null;
    }
    const endpoint = fixtureEndpoint(uri, "redis");
    // RedisStorage's URL parser fixes the database at zero and retains
    // brackets in IPv6 hostnames; validate /0 and pass a bare IPv6 host.
    auto redis = new RedisStorage(endpoint.host, endpoint.port);
    if (endpoint.host == "::1") redis.connect();
    else redis.connectFromUrl(uri);
    redis.ping();
    return redis;
}

bool connectIsolatedTestMongo(string testName) {
    enum variable = "IRCFIBER_HISTORY_TEST_MONGO_URL";
    const uri = environment.get(variable, "");
    if (!uri.length) {
        writeln("SKIP ", testName, ": ", variable, " is absent; no MongoDB connection attempted");
        return false;
    }
    fixtureEndpoint(uri, "mongodb");
    // Never inherit the production/default database or an earlier global
    // connection. These module regressions own only their test database.
    AppMongoConnection.connect(uri, "ircfiber_common_test");
    AppMongoConnection.getDb()["uploads"].countDocuments(Bson.emptyObject);
    return true;
}

@("Database module tests admit only explicit loopback fixture endpoints")
unittest {
    assert(fixtureEndpoint("redis://127.0.0.1:32123/0", "redis").port == 32123);
    assert(fixtureEndpoint("redis://[::1]:32123/0", "redis").host == "::1");
    assert(fixtureEndpoint("mongodb://127.0.0.1:32124/?replicaSet=rs0", "mongodb").port == 32124);
    assert(fixtureEndpoint("mongodb://localhost:32124/test?replicaSet=rs0", "mongodb").port == 32124);
    foreach (uri; ["redis://example.com:6379/0", "redis://127.0.0.1:0/0",
            "redis://127.0.0.1:65536/0", "redis://127.0.0.1:6379/1",
            "redis://127.0.0.1:6379@remote:6379/0", "redis://127.0.0.1/0"]) {
        bool rejected;
        try fixtureEndpoint(uri, "redis"); catch (Exception) rejected = true;
        assert(rejected, "Unsafe fixture Redis URI must be rejected before connection");
    }
    foreach (uri; ["mongodb://example.com:27017/test", "mongodb+srv://localhost/test",
            "mongodb://localhost:27017,remote:27017/test", "mongodb://localhost:0/test",
            "mongodb://localhost:27017/test#remote", "mongodb://user@remote:27017/test"]) {
        bool rejected;
        try fixtureEndpoint(uri, "mongodb"); catch (Exception) rejected = true;
        assert(rejected, "Unsafe fixture MongoDB URI must be rejected before connection");
    }
}
