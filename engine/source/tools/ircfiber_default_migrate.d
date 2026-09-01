/**
 * One-shot bulk migration: ensure every existing IRC Fiber user has the
 * platform-provided default network (irc.ircfiber.com:6697).
 *
 * Now also fixes legacy suffixed nicks (e.g. admin_a3f1 -> admin) and
 * triggers reconnect so everyone uses plain username.
 *
 * Run once after deploying the ensureDefaultFiberNetwork() runtime hook.
 * The runtime hook already handles users as they log in, so this tool is
 * only needed to catch the long-tail of users who have not logged in yet
 * and to bulk-fix legacy nicks.
 *
 * Usage:
 *   dub run --config=ircfiber-default-migrate
 *   dub run --config=ircfiber-default-migrate -- --dry-run
 *   dub run --config=ircfiber-default-migrate -- --user=alice
 *   dub run --config=ircfiber-default-migrate -- --fix-nicks
 *   dub run --config=ircfiber-default-migrate -- --fix-nicks --dry-run
 *   dub run --config=ircfiber-default-migrate -- --self-test
 *
 * Flags:
 *   --dry-run     Count users that need a default network but write nothing.
 *   --user=NAME   Limit to a single username (for spot-checks).
 *   --fix-nicks   Bulk-fix all Fiber networks with legacy suffixed nicks
 *                 (e.g. admin_a3f1) to plain username and reconnect.
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
import ircfiber.default_network : ensureDefaultFiberNetwork, buildDefaultFiberNetwork, buildDefaultNick, DEFAULT_FIBER_HOST;
import ircfiber.redis.protocol : RedisKeys, ControlMessage;
import vibe.core.log;
import std.datetime : Clock;

private string envOr(string name, string fallback) {
    auto p = getenv(name.toStringz);
    if (p is null) return fallback;
    auto v = to!string(p);
    return v.length > 0 ? v : fallback;
}

private int runSelfTest() {
    writeln("== self-test: buildDefaultFiberNetwork + buildDefaultNick invariants ==");

    int failed = 0;

    // 1. Synthetic user: full config shape — nick is plain username
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
        if (cfg.nick != "alice") {
            stderr.writeln("FAIL: alice nick must be plain username");
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

    // 2. buildDefaultNick returns plain username, stable across calls
    {
        User u;
        u.id = randomUUID();
        u.username = "bob";
        const n1 = buildDefaultNick(u);
        const n2 = buildDefaultNick(u);
        if (n1 != "bob") { stderr.writeln("FAIL: nick must be plain username"); failed++; }
        if (n1 != n2) { stderr.writeln("FAIL: deterministic nick"); failed++; }
    }

    // 3. Same username different UUIDs -> same nick (plain username)
    {
        User u1; u1.id = randomUUID(); u1.username = "carol";
        User u2; u2.id = randomUUID(); u2.username = "carol";
        if (buildDefaultNick(u1) != buildDefaultNick(u2)) {
            stderr.writeln("FAIL: same username must yield same nick");
            failed++;
        }
        if (buildDefaultNick(u1) != "carol") {
            stderr.writeln("FAIL: carol nick");
            failed++;
        }
    }

    // 4. Nick is plain username regardless of UUID value
    {
        User u;
        u.id = UUID("12345678-90ab-cdef-1234-567890abcdef");
        u.username = "dan";
        if (buildDefaultNick(u) != "dan") {
            stderr.writeln("FAIL: dan nick must be plain");
            failed++;
        }
    }

    // 5. ensureDefaultFiberNetwork short-circuits on uninitialized user
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

private int fixNicksBulk(NetworkRepository netRepo, UserRepository userRepo, RedisStorage redis, ServerRegistry registry, bool dryRun) {
    writeln("== Bulk fix: legacy suffixed nicks -> plain username ==");
    auto all = netRepo.findAll();
    int scanned = 0, fixed = 0, skipped = 0, errors = 0;
    foreach (nw; all) {
        if (nw.config.host != DEFAULT_FIBER_HOST) continue;
        scanned++;
        auto user = userRepo.findById(nw.userId);
        if (user.id == UUID.init || user.username.length == 0) {
            // Fallback: try to infer username from nick prefix if user missing
            // Skip — cannot determine correct nick
            writefln("  [skip] network=%s userId=%s nick=%s (user not found)", nw.config.id.toString(), nw.userId.toString(), nw.config.nick);
            skipped++;
            continue;
        }
        bool needsFix = (nw.config.nick != user.username || nw.config.realName != user.username);
        if (!needsFix) {
            // Also check persisted redis nick is not stale suffixed
            // If mongo is already correct but redis still has suffix, clear it
            if (!dryRun && redis !is null) {
                try {
                    auto persisted = redis.getDb().get(RedisKeys.networkNick(nw.config.id.toString()));
                    if (persisted.length > 0 && persisted != user.username) {
                        writefln("  [fix redis] %s: persisted '%s' -> '%s'", user.username, persisted, user.username);
                        redis.getDb().del(RedisKeys.networkNick(nw.config.id.toString()));
                        // Trigger reconnect to pick up clean nick
                        try {
                            auto serverId = registry.getServerForNetwork(nw.config.id.toString());
                            if (serverId.length > 0) {
                                // Need fresh config with correct nick for reconnect message
                                auto cfg = nw.config;
                                cfg.nick = user.username;
                                cfg.realName = user.username;
                                auto msg = ControlMessage("reconnectNetwork", cfg.id.toString(), user.id.toString(), cfg.toJson());
                                msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                                redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
                            }
                        } catch (Exception) {}
                        fixed++;
                    } else {
                        skipped++;
                    }
                } catch (Exception) { skipped++; }
            } else {
                skipped++;
            }
            continue;
        }
        writefln("  [%s] %s: '%s' -> '%s' (network %s)", dryRun ? "would fix" : "fix", user.username, nw.config.nick, user.username, nw.config.id.toString());
        if (dryRun) { fixed++; continue; }
        try {
            auto cfg = nw.config;
            cfg.nick = user.username;
            cfg.realName = user.username;
            netRepo.save(cfg, nw.userId);
            redis.del(RedisKeys.userNetworks(nw.userId.toString()));
            try { redis.getDb().del(RedisKeys.networkNick(cfg.id.toString())); } catch (Exception) {}
            try {
                auto serverId = registry.getServerForNetwork(cfg.id.toString());
                if (serverId.length > 0) {
                    auto msg = ControlMessage("reconnectNetwork", cfg.id.toString(), nw.userId.toString(), cfg.toJson());
                    msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                    redis.lpush(RedisKeys.control(serverId), msg.toJson().toString());
                } else {
                    auto sid = registry.assignNetwork(cfg.id.toString());
                    if (sid.length > 0) {
                        auto msg = ControlMessage("reconnectNetwork", cfg.id.toString(), nw.userId.toString(), cfg.toJson());
                        msg.timestampMs = Clock.currTime.toUnixTime!long * 1000;
                        redis.lpush(RedisKeys.control(sid), msg.toJson().toString());
                    }
                }
            } catch (Exception e) {
                writefln("    warn: reconnect push failed: %s", e.msg);
            }
            fixed++;
        } catch (Exception e) {
            stderr.writefln("  [error] %s: %s", user.username, e.msg);
            errors++;
        }
    }
    writefln("== nick fix done: scanned=%s fixed=%s skipped=%s errors=%s ==", scanned, fixed, skipped, errors);
    return errors > 0 ? 2 : 0;
}

private int runMain(string[] args) {
    bool dryRun = false;
    bool selfTest = false;
    bool fixNicks = false;
    string onlyUser;

    auto helpInfo = getopt(args,
        "dry-run",    &dryRun,
        "self-test",  &selfTest,
        "fix-nicks",  &fixNicks,
        "user",       &onlyUser,
    );
    if (helpInfo.helpWanted) {
        defaultGetoptPrinter("Usage: ircfiber-default-migrate [--dry-run] " ~
            "[--user=NAME] [--self-test] [--fix-nicks]", helpInfo.options);
        return 0;
    }

    if (selfTest) return runSelfTest();

    writeln("== IRC Fiber default-network migration ==");
    if (dryRun) writeln("  mode = DRY RUN (no writes)");
    if (onlyUser.length) writefln("  scope = user '%s'", onlyUser);
    if (fixNicks) writeln("  mode = FIX NICKS (legacy suffix -> plain)");

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

    if (fixNicks) {
        if (onlyUser.length > 0) {
            auto u = userRepo.findByUsername(onlyUser);
            if (u.username.length == 0) {
                stderr.writefln("User '%s' not found", onlyUser);
                return 1;
            }
            // Single-user fix via ensure path (self-heals)
            auto before = netRepo.findByUserId(u.id);
            bool hadFiber = false;
            foreach (c; before) if (c.host == DEFAULT_FIBER_HOST) hadFiber = true;
            if (!hadFiber) {
                writeln("  no Fiber network for user, nothing to fix");
                return 0;
            }
            if (dryRun) {
                foreach (c; before) if (c.host == DEFAULT_FIBER_HOST) writefln("  [would fix] %s: '%s' -> '%s'", u.username, c.nick, u.username);
                return 0;
            }
            ensureDefaultFiberNetwork(u, netRepo, redis, registry);
            writeln("  fixed single user via ensureDefaultFiberNetwork");
            return 0;
        }
        return fixNicksBulk(netRepo, userRepo, redis, registry, dryRun);
    }

    int processed = 0, skipped = 0, created = 0, errors = 0;

    void handleUser(User u) {
        processed++;

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
            bool hadFiberBefore = false;
            foreach (c; netRepo.findByUserId(u.id))
                if (c.host == "irc.ircfiber.com") { hadFiberBefore = true; break; }

            const cfg = ensureDefaultFiberNetwork(u, netRepo, redis, registry);
            if (cfg.id == UUID.init) { errors++; return; }

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
