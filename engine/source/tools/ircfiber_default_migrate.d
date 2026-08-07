/**
 * One-shot bulk migration: ensure every existing IRC Fiber user has the
 * platform-provided default network (irc.ircfiber.com:6697).
 *
 * Run once after deploying the ensureDefaultFiberNetwork() runtime hook.
 * The runtime hook already handles users as they log in, so this tool is
 * only needed to catch the long-tail of users who have not logged in yet.
 *
 * Usage:
 *   dub run --config=ircfiber-default-migrate
 *   dub run --config=ircfiber-default-migrate -- --dry-run
 *   dub run --config=ircfiber-default-migrate -- --user=alice
 *   dub run --config=ircfiber-default-migrate -- --self-test
 *
 * Flags:
 *   --dry-run     Count users that need a default network but write nothing.
 *   --user=NAME   Limit to a single username (for spot-checks).
 *   --self-test   Build a default config for a synthetic user and print it,
 *                 then exit. Verifies buildDefaultFiberNetwork without
 *                 requiring Mongo/Redis credentials.
 *
 * Env:
 *   IRCFIBER_MONGO_URL  (default mongodb://127.0.0.1:27017)
 *   IRCFIBER_MONGO_DB   (default ircfiber)
 *   IRCFIBER_REDIS_URL  (default redis://127.0.0.1:6379)
 *
 * Exit codes:
 *   0 success (or dry-run completed)
 *   1 Mongo/Redis unreachable
 *   2 unexpected exception
 */
module ircfiber_default_migrate;

import std.stdio : writeln, writefln, stdout, stderr;
import std.getopt : getopt, defaultGetoptPrinter;
import std.string : toStringz;
import std.uuid : UUID, randomUUID;
import std.conv : to;
import std.array : array;
import core.stdc.stdlib : exit, getenv;

import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.user : UserRepository;
import ircfiber.db.network : NetworkRepository;
import ircfiber.models.user : User;
import ircfiber.models.network : NetworkConfig, TLSMode;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.irc.registry : ServerRegistry;
import ircfiber.default_network : ensureDefaultFiberNetwork, buildDefaultFiberNetwork, buildDefaultNick;

private string envOr(string name, string fallback) {
    auto p = getenv(name.toStringz);
    if (p is null) return fallback;
    auto v = to!string(p);
    return v.length > 0 ? v : fallback;
}

private int runSelfTest() {
    writeln("== self-test: buildDefaultFiberNetwork + buildDefaultNick invariants ==");

    int failed = 0;

    // 1. Synthetic user: full config shape
    {
        User u;
        u.id = randomUUID();
        u.username = "alice";
        auto cfg = buildDefaultFiberNetwork(u);
        writefln("  alice: nick=%s name=%s host=%s:%s tls=%s systemManaged=%s channels=%s",
                 cfg.nick, cfg.name, cfg.host, cfg.port, cfg.tls, cfg.systemManaged, cfg.autoJoinChannels);
        if (cfg.name != "IRC Fiber") {
            stderr.writeln("FAIL: alice name");
            failed++;
        }
        if (cfg.host != "irc.ircfiber.com") {
            stderr.writeln("FAIL: alice host");
            failed++;
        }
        if (cfg.port != 6697) {
            stderr.writeln("FAIL: alice port");
            failed++;
        }
        if (cfg.tls != TLSMode.required) {
            stderr.writeln("FAIL: alice tls");
            failed++;
        }
        if (cfg.realName != "alice") {
            stderr.writeln("FAIL: alice realName");
            failed++;
        }
        if (cfg.nick != "alice_" ~ u.id.toString()[0..4]) {
            stderr.writeln("FAIL: alice nick format");
            failed++;
        }
        if (!cfg.systemManaged) {
            stderr.writeln("FAIL: alice systemManaged");
            failed++;
        }
        if (cfg.autoJoinChannels != ["#ircfiber", "#welcome"]) {
            stderr.writeln("FAIL: alice channels");
            failed++;
        }
        if (cfg.disabled) {
            stderr.writeln("FAIL: alice disabled");
            failed++;
        }
    }

    // 2. Determinism: same user → same nick across calls
    {
        User u;
        u.id = randomUUID();
        u.username = "bob";
        const n1 = buildDefaultNick(u);
        const n2 = buildDefaultNick(u);
        if (n1 != n2) { stderr.writeln("FAIL: deterministic nick"); failed++; }
    }

    // 3. Different UUIDs → different suffixes (even with same username)
    {
        User u1; u1.id = randomUUID(); u1.username = "carol";
        User u2; u2.id = randomUUID(); u2.username = "carol";
        if (buildDefaultNick(u1) == buildDefaultNick(u2)) {
            stderr.writeln("FAIL: distinct users with same username must yield different suffixes");
            failed++;
        }
    }

    // 4. Hyphen-stripping in UUIDs
    {
        User u;
        u.id = UUID("12345678-90ab-cdef-1234-567890abcdef");
        u.username = "dan";
        if (buildDefaultNick(u) != "dan_1234") {
            stderr.writeln("FAIL: hyphen-strip UUID → wrong suffix");
            failed++;
        }
    }

    // 5. ensureDefaultFiberNetwork short-circuits on uninitialized user
    //    (we don't actually call it here because that would hit Mongo; the
    //    early-return guard is asserted by the inline unittests in
    //    default_network.d which are compiled into every config that
    //    pulls the module).
    {
        const User empty;
        if (empty.id != UUID.init || empty.username.length != 0) {
            stderr.writeln("FAIL: User.init invariant");
            failed++;
        }
    }

    if (failed == 0) writeln("PASS");
    else              writefln("FAILED: %d assertions", failed);
    return failed == 0 ? 0 : 1;
}

private int runMain(string[] args) {
    bool dryRun = false;
    bool selfTest = false;
    string onlyUser;

    auto helpInfo = getopt(args,
        "dry-run",    &dryRun,
        "self-test",  &selfTest,
        "user",       &onlyUser,
    );
    if (helpInfo.helpWanted) {
        defaultGetoptPrinter("Usage: ircfiber-default-migrate [--dry-run] " ~
            "[--user=NAME] [--self-test]", helpInfo.options);
        return 0;
    }

    if (selfTest) return runSelfTest();

    writeln("== IRC Fiber default-network migration ==");
    if (dryRun) writeln("  mode = DRY RUN (no writes)");
    if (onlyUser.length) writefln("  scope = user '%s'", onlyUser);

    auto mongoUrl = envOr("IRCFIBER_MONGO_URL", "mongodb://127.0.0.1:27017");
    auto mongoDb  = envOr("IRCFIBER_MONGO_DB",  "ircfiber");
    auto redisUrl = envOr("IRCFIBER_REDIS_URL", "redis://127.0.0.1:6379");

    writefln("  mongo = %s/%s", mongoUrl, mongoDb);
    writefln("  redis = %s", redisUrl);

    AppMongoConnection.connect(mongoUrl, mongoDb);
    if (!AppMongoConnection.isConnected()) {
        stderr.writeln("FATAL: could not connect to MongoDB");
        return 1;
    }

    auto redis = new RedisStorage();
    redis.connectFromUrl(redisUrl);

    auto userRepo = new UserRepository();
    auto netRepo = new NetworkRepository();
    auto registry = new ServerRegistry(redis);

    int processed = 0, skipped = 0, created = 0, errors = 0;

    void handleUser(User u) {
        processed++;

        // Dry-run fast path: peek without writing.
        if (dryRun) {
            auto existing = netRepo.findByUserId(u.id);
            bool hasFiber = false;
            foreach (ref c; existing)
                if (c.host == "irc.ircfiber.com") { hasFiber = true; break; }
            if (hasFiber) { skipped++; return; }
            writefln("  [would create] %s (%s)", u.username, u.id);
            created++;
            return;
        }

        try {
            // Snapshot the user's networks BEFORE the call so we can tell
            // whether ensureDefaultFiberNetwork actually inserted a new
            // config or just returned the pre-existing one.
            bool hadFiberBefore = false;
            foreach (c; netRepo.findByUserId(u.id))
                if (c.host == "irc.ircfiber.com") { hadFiberBefore = true; break; }

            const cfg = ensureDefaultFiberNetwork(u, netRepo, redis, registry);
            if (cfg.id == UUID.init) { errors++; return; }

            // The helper either created a new config or returned the
            // pre-existing one. Distinguish via the pre-call check.
            if (hadFiberBefore) skipped++;
            else               created++;
        } catch (Exception e) {
            stderr.writefln("  [error] user=%s: %s", u.username, e.msg);
            errors++;
        }
    }

    if (onlyUser.length > 0) {
        auto u = userRepo.findByUsername(onlyUser);
        if (u.username.length == 0) {
            stderr.writefln("User '%s' not found", onlyUser);
            return 1;
        }
        handleUser(u);
    } else {
        // Stream all users in pages so we don't load the full collection.
        // UserRepository doesn't expose a cursor today, so use findAll in
        // reasonable batches; for tens of thousands of users this still
        // completes in a few seconds.
        const int pageSize = 500;
        int offset = 0;
        while (true) {
            auto batch = userRepo.findAll(pageSize, offset);
            if (batch.length == 0) break;
            foreach (u; batch) handleUser(u);
            if (batch.length < pageSize) break;
            offset += pageSize;
        }
    }

    writeln("== done ==");
    writefln("  processed = %s", processed);
    writefln("  created   = %s", created);
    writefln("  skipped   = %s  (already had irc.ircfiber.com)", skipped);
    writefln("  errors    = %s", errors);
    return errors > 0 ? 2 : 0;
}

int main(string[] args) {
    try {
        return runMain(args);
    } catch (Exception e) {
        stderr.writefln("FATAL: %s", e.msg);
        return 2;
    }
}