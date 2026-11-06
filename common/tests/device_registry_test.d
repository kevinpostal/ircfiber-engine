/**
 * Device fleet repository behavior against a real MongoDB: live-owner join,
 * 90-day status boundary, explicit test-account and emulator classification,
 * deterministic pagination with consistent totals, and orphan repair.
 *
 * Uses its own `device_registry_test` database (refuses any other name).
 * Skipped when Mongo is unreachable unless `--require-services`.
 * Compiled only with `versions "DeviceRegistryTest"`, so the library's
 * unittest configuration (which includes tests/) never sees this `main`.
 */
module device_registry_test;

version (DeviceRegistryTest):

import std.algorithm : canFind, map, sort;
import std.array : array;
import std.process : environment;
import std.stdio : writeln, writefln;
import std.string : endsWith;
import std.uuid : UUID, randomUUID;
import vibe.data.bson : Bson;

import ircfiber.db.device_registry;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.user : UserRepository;
import ircfiber.models.user : User;

private enum string TEST_DB = "device_registry_test";
private enum long NOW = 1_800_000_000_000;
private enum long DAY = 24L * 60 * 60 * 1000;

private int failures;
private void check(bool condition, string description, string file = __FILE__, size_t line = __LINE__) {
    if (condition) return;
    failures++;
    writefln("FAIL %s:%s — %s", file, line, description);
}

private void clearCollections() {
    auto db = AppMongoConnection.getDb();
    db["device_registry"].deleteMany(Bson.emptyObject);
    db["users"].deleteMany(Bson.emptyObject);
}

private User makeUser(UserRepository users, string username) {
    User u;
    u.id = randomUUID();
    u.username = username;
    u.email = username ~ "@example.test";
    u.passwordHash = "x";
    u.roles = ["user"];
    users.create(u);
    return u;
}

private void addDevice(DeviceRegistryRepository repo, string deviceId, string userId, long lastSeenAt,
        string model = "iPhone17,1") {
    DeviceRegistryEntry e;
    e.deviceId = deviceId;
    e.userId = userId;
    e.username = "stored-name";
    e.model = model;
    e.lastSeenAt = lastSeenAt;
    e.createdAt = 1;
    repo.upsert(e);
}

private string[] ids(DeviceRegistryEntry[] rows) {
    return rows.map!(r => r.deviceId).array;
}

private string[] pageThrough(DeviceRegistryRepository repo, DeviceFleetStatus status, bool includeTests,
        int limit, out long total) {
    string[] seen;
    for (int offset = 0;; offset += limit) {
        auto page = repo.fleet(offset, limit, status, includeTests, NOW);
        total = page.total;
        seen ~= ids(page.devices);
        if (page.devices.length < limit) break;
    }
    return seen;
}

private void fleetCases() {
    clearCollections();
    auto users = new UserRepository();
    auto repo = new DeviceRegistryRepository();
    auto alice = makeUser(users, "alice");
    auto tester = makeUser(users, "tester");
    users.setTestAccount(tester.id, true);
    const aliceId = alice.id.toString();

    addDevice(repo, "a-recent", aliceId, NOW - DAY);
    addDevice(repo, "a-edge-active", aliceId, NOW - DEVICE_INACTIVE_MS + 1);
    addDevice(repo, "a-edge-inactive", aliceId, NOW - DEVICE_INACTIVE_MS);
    addDevice(repo, "a-never", aliceId, 0);
    addDevice(repo, "a-emulator", aliceId, NOW - DAY, "Google_sdk_gphone64_arm64");
    addDevice(repo, "a-sim", aliceId, NOW - DAY, "iPhone17,1 (Simulator)");
    addDevice(repo, "a-tie-b", aliceId, NOW - 2 * DAY);
    addDevice(repo, "a-tie-a", aliceId, NOW - 2 * DAY);
    addDevice(repo, "t-phone", tester.id.toString(), NOW - DAY);
    addDevice(repo, "orphan", randomUUID().toString(), NOW - DAY);

    auto def = repo.fleet(0, 50, DeviceFleetStatus.active, false, NOW);
    check(ids(def.devices) == ["a-recent", "a-tie-a", "a-tie-b", "a-edge-active"],
        "default fleet: active non-test live-owner devices, newest first, _id tiebreak");
    check(def.total == 4, "default total counts the filtered set");
    check(def.summary.total == 9 && def.summary.active == 7 && def.summary.inactive == 2,
        "summary counts the whole live-owner fleet regardless of filters");
    check(def.summary.test == 3, "summary.test counts test devices, hidden or not");
    foreach (d; def.devices) {
        check(d.status == "active" && !d.isTest, "default rows are active production devices");
        check(d.username == "alice", "username comes from the live owner");
    }

    auto inactive = repo.fleet(0, 50, DeviceFleetStatus.inactive, false, NOW);
    check(ids(inactive.devices).sort.array == ["a-edge-inactive", "a-never"],
        "exactly 90 days and never-seen devices are inactive");
    check(inactive.total == 2 && inactive.summary == def.summary, "inactive total is filtered; summary is not");

    auto all = repo.fleet(0, 50, DeviceFleetStatus.all, true, NOW);
    check(all.total == 9 && all.devices.length == 9, "all + tests: every live-owner device, no orphan");
    check(!ids(all.devices).canFind("orphan"), "orphan hidden before repair");
    check(all.summary == def.summary, "summary is independent of status and includeTests");
    foreach (d; all.devices) {
        if (d.deviceId == "a-emulator") check(d.isEmulator && d.isTest && !d.isTestAccount, "emulator model classified");
        if (d.deviceId == "a-sim") check(d.isEmulator && d.isTest, "iOS Simulator suffix classified");
        if (d.deviceId == "a-recent") check(!d.isEmulator && !d.isTest, "real device on the same account stays production");
        if (d.deviceId == "t-phone") check(d.isTestAccount && d.isTest && !d.isEmulator, "test account classified");
    }

    foreach (limit; [1, 3]) {
        long total;
        auto paged = pageThrough(repo, DeviceFleetStatus.all, true, limit, total);
        check(paged == ids(all.devices), "pagination is deterministic and complete");
        check(total == all.total, "page total is stable across pages");
    }

    check(repo.findFleetById("orphan", NOW).deviceId.length == 0, "orphan detail is hidden");
    check(repo.findFleetById("missing", NOW).deviceId.length == 0, "missing device is absent");
    auto t = repo.findFleetById("t-phone", NOW);
    check(t.deviceId == "t-phone" && t.isTestAccount && t.status == "active", "detail returns test devices");
    check(repo.findFleetById("a-edge-inactive", NOW).status == "inactive", "detail uses the same boundary");

    // A stale User copy must not clear the admin flag; the flag applies to
    // every device of the account on the next read.
    auto staleTester = users.findById(tester.id);
    users.setTestAccount(tester.id, false);
    staleTester.isTestAccount = true;
    staleTester.lastLoginIp = "198.51.100.1";
    users.update(staleTester);
    check(!users.findById(tester.id).isTestAccount, "generic update leaves isTestAccount alone");
    check(ids(repo.fleet(0, 50, DeviceFleetStatus.active, false, NOW).devices).canFind("t-phone"),
        "clearing the flag shows the account's devices immediately");
    check(users.setTestAccount(alice.id, true), "setTestAccount matches an existing user");
    check(repo.fleet(0, 50, DeviceFleetStatus.active, false, NOW).devices.length == 1,
        "flagging an account hides all of its devices at once");
    check(!users.setTestAccount(randomUUID(), true), "setTestAccount reports a missing user");

    // Heartbeats only raise lastSeenAt of an existing owned row; a delayed
    // check-in updates metadata without moving lastSeenAt backwards.
    check(repo.touch("a-edge-inactive", aliceId, NOW), "touch matches an owned row");
    check(repo.findFleetById("a-edge-inactive", NOW).status == "active", "touch revives an inactive device");
    check(!repo.touch("t-phone", aliceId, NOW), "touch refuses another owner's row");
    check(!repo.touch("never-registered", aliceId, NOW), "touch never creates a row");
    check(repo.findFleetById("never-registered", NOW).deviceId.length == 0, "no row appeared");
    check(repo.touch("a-recent", aliceId, NOW - 10 * DAY), "an older touch still matches");
    check(repo.findFleetById("a-recent", NOW).lastSeenAt == NOW - DAY, "an older touch never lowers lastSeenAt");
    DeviceRegistryEntry late;
    late.deviceId = "a-edge-inactive";
    late.userId = aliceId;
    late.username = "alice";
    late.model = "iPhone17,1";
    late.osVersion = "18.2";
    late.lastSeenAt = NOW - 200 * DAY;
    repo.upsert(late);
    auto afterLate = repo.findFleetById("a-edge-inactive", NOW);
    check(afterLate.lastSeenAt == NOW && afterLate.osVersion == "18.2",
        "delayed upsert updates metadata but keeps the newer lastSeenAt");

    // Scoped removal never touches another owner's row.
    check(!repo.remove("t-phone", aliceId), "scoped remove refuses another owner's device");
    check(repo.findFleetById("t-phone", NOW).deviceId == "t-phone", "other owner's device survives");
    check(repo.remove("a-recent", aliceId), "scoped remove deletes the owner's device");
}

private void reconcileCases() {
    clearCollections();
    auto users = new UserRepository();
    auto repo = new DeviceRegistryRepository();
    auto alice = makeUser(users, "alice");
    addDevice(repo, "d1", alice.id.toString(), NOW - DAY);
    addDevice(repo, "d2", randomUUID().toString(), NOW - DAY);
    addDevice(repo, "d3", alice.id.toString(), 0);
    addDevice(repo, "d4", randomUUID().toString(), 0);
    addDevice(repo, "d5", alice.id.toString(), NOW - 400 * DAY);
    AppMongoConnection.getDb()["device_registry"].insertOne(Bson(["_id": Bson("d6"), "lastSeenAt": Bson(5L)]));

    string after;
    size_t scanned, deleted, pages;
    for (;;) {
        auto b = repo.reconcileOrphans(after, 2);
        scanned += b.scanned;
        deleted += b.deleted;
        pages++;
        check(b.nextId >= after, "keyset never moves backwards");
        after = b.nextId;
        if (b.done) break;
        check(pages < 10, "reconcile terminates");
    }
    check(scanned == 6 && deleted == 3, "every row scanned once; only orphans deleted");
    auto remaining = AppMongoConnection.getDb()["device_registry"].find(Bson.emptyObject);
    string[] left;
    foreach (doc; remaining) left ~= doc["_id"].get!string;
    check(left.sort.array == ["d1", "d3", "d5"], "valid devices survive regardless of age");

    auto again = repo.reconcileOrphans("", 100);
    check(again.done && again.scanned == 3 && again.deleted == 0, "repair is idempotent");

    // An empty users collection means a wrong database, not orphans.
    AppMongoConnection.getDb()["users"].deleteMany(Bson.emptyObject);
    bool threw;
    try repo.reconcileOrphans("", 100);
    catch (Exception) threw = true;
    check(threw, "reconcile fails closed when users is empty");
    check(AppMongoConnection.getDb()["device_registry"].countDocuments(Bson.emptyObject) == 3,
        "nothing deleted when failing closed");

    bool badBatch;
    try repo.reconcileOrphans("", 0);
    catch (Exception) badBatch = true;
    check(badBatch, "invalid batch size is rejected");
}

int main(string[] args) {
    bool required;
    foreach (a; args[1 .. $]) if (a == "--require-services") required = true;
    const mongoUrl = environment.get("IRCFIBER_DEVICE_REGISTRY_TEST_MONGO_URL",
        "mongodb://127.0.0.1:27018/" ~ TEST_DB ~ "?replicaSet=rs0");
    try {
        AppMongoConnection.connect(mongoUrl, TEST_DB);
        AppMongoConnection.getDb()["users"].countDocuments(Bson.emptyObject);
    } catch (Exception e) {
        writefln("device registry tests: %s (%s)", required ? "FAILED" : "SKIPPED", e.msg);
        return required ? 1 : 0;
    }
    if (!AppMongoConnection.name().endsWith("_test")) {
        writeln("device registry tests: refusing to run against a non-test database");
        return 1;
    }
    scope (exit) clearCollections();

    fleetCases();
    reconcileCases();

    if (failures) {
        writefln("device registry tests: %s failure(s)", failures);
        return 1;
    }
    writeln("device registry tests: PASS");
    return 0;
}
