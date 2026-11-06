/**
 * Real-Redis proof of the egress admission state machine
 * (ircfiber.irc.egress_admission). Needs a disposable Redis:
 *
 *   EGRESS_ADMISSION_REDIS_URL=redis://127.0.0.1:26080 \
 *     EGRESS_ADMISSION_ALLOW_CONFIG_TEST=1 \
 *     dub run --root=site/common --config=egress-admission-redis-test
 *
 * Use a dedicated disposable server, never a shared or production Redis:
 * the write-failure case temporarily changes min-replicas-to-write.
 * Its data keys are `irc:egress:admission:admtest-<pid>-*`, deleted before
 * and after each case. Time is passed explicitly, so cooldowns and lock
 * expiries are exercised without sleeping. Compiled only with
 * `versions "EgressAdmissionRedisTest"`, so the library's unittest
 * configuration (which includes tests/) never sees this `main`.
 */
module egress_admission_redis_test;

version (EgressAdmissionRedisTest):
import core.sys.posix.unistd : getpid;
import std.algorithm : canFind;
import std.conv : to;
import std.process : environment;
import std.stdio : writeln;

import vibe.core.core : runTask;
import vibe.core.task : Task;
import vibe.db.redis.redis : RedisDatabase;

import ircfiber.irc.egress_admission;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.storage.redis : RedisStorage;

enum HOST = "socks-se8.nordvpn.com";
enum ushort PORT = 1080;
enum long T0 = 1_800_000_000_000;
enum long MIN = 60_000;

string url;
string prefix;

RedisStorage client() {
    auto r = new RedisStorage();
    r.connectFromUrl(url);
    return r;
}

string label(string name) { return prefix ~ name; }

void reset(RedisDatabase db, string l) { db.del(RedisKeys.egressAdmission(l)); }

void check(bool ok, string what) {
    if (!ok) throw new Exception("FAIL: " ~ what);
}

void expectState(EgressAdmission a, string state, string what) {
    check(a.state == state, what ~ ": expected " ~ state ~ ", got " ~ a.state ~ " (" ~ a.reason ~ ")");
}

/// Opens the circuit at `at` and returns the claimed trial token after the
/// cooldown ends.
string quarantineThenClaim(RedisDatabase db, string l, long at) {
    auto q = quarantineEgress(db, l, HOST, PORT, "correlated loss", at);
    check(q.opened, "quarantine opens the circuit");
    auto claim = admitEgressDial(db, l, HOST, PORT, true, 180_000, q.retryAtMs);
    check(claim.allowed && claim.trialToken.length > 0, "trial claimable once the cooldown ended");
    return claim.trialToken;
}

void noRecordIsHealthy(RedisDatabase db) {
    auto l = label("fresh");
    reset(db, l);
    expectState(readEgressAdmission(db, l, HOST, PORT, T0), "healthy", "no record");
    auto a = admitEgressDial(db, l, HOST, PORT, false, 180_000, T0);
    check(a.allowed && a.trialToken.length == 0, "no record admits a plain dial");
    check(!db.exists(RedisKeys.egressAdmission(l)), "a plain admit writes nothing");
}

void drainSurvivesClientsAndResumeKeepsCircuit(RedisDatabase db) {
    auto l = label("drain");
    reset(db, l);
    auto d = setEgressDraining(db, l, HOST, PORT, true, "provider maintenance", T0);
    expectState(d, "draining", "drain");
    check(d.draining && d.reason == "provider maintenance", "drain reason stored");
    // A brand-new connection (another engine, a restarted gateway) sees it.
    auto other = client();
    scope(exit) other.close();
    auto seen = readEgressAdmission(other.getDb(), l, HOST, PORT, T0 + 365L * 24 * 60 * MIN);
    expectState(seen, "draining", "drain survives client recreation, indefinitely");
    auto refused = admitEgressDial(other.getDb(), l, HOST, PORT, true, 180_000, T0 + MIN);
    check(!refused.allowed && refused.blockedState == "draining", "drain refuses even a trial claim");
    // Resume a healthy exit: healthy again.
    expectState(setEgressDraining(db, l, HOST, PORT, false, "", T0 + MIN), "healthy", "resume healthy");

    // Resume never clears an open circuit.
    auto q = quarantineEgress(db, l, HOST, PORT, "correlated loss", T0 + 2 * MIN);
    check(q.opened && q.retryAtMs == T0 + 2 * MIN + 5 * MIN, "first quarantine: 5 min");
    expectState(setEgressDraining(db, l, HOST, PORT, true, "", T0 + 3 * MIN), "draining", "drain over quarantine");
    auto resumed = setEgressDraining(db, l, HOST, PORT, false, "", T0 + 3 * MIN);
    expectState(resumed, "quarantined", "resume keeps quarantine");
    check(resumed.retryAtMs == q.retryAtMs && resumed.failures == 1, "resume keeps cooldown and failures");
    expectState(readEgressAdmission(db, l, HOST, PORT, q.retryAtMs), "recovering", "cooldown elapsed");
    // A second correlated loss does not extend an open circuit.
    auto again = quarantineEgress(db, l, HOST, PORT, "correlated loss", T0 + 4 * MIN);
    check(!again.opened && again.already && again.retryAtMs == q.retryAtMs, "open circuit unchanged");
    reset(db, l);
}

void singleTrialAcrossContenders(RedisDatabase db) {
    auto l = label("contend");
    reset(db, l);
    auto q = quarantineEgress(db, l, HOST, PORT, "correlated loss", T0);
    const at = q.retryAtMs;
    check(!admitEgressDial(db, l, HOST, PORT, true, 180_000, at - 1).allowed, "no trial during cooldown");
    // A non-recovery-tier dial never claims the trial.
    auto plain = admitEgressDial(db, l, HOST, PORT, false, 180_000, at);
    check(!plain.allowed && plain.blockedState == "recovering", "plain dial refused while recovering");
    enum N = 12;
    string[N] tokens;
    string[N] blocked;
    RedisStorage[N] clients;
    foreach (i; 0 .. N) clients[i] = client();
    scope(exit) foreach (c; clients) c.close();
    Task[N] tasks;
    foreach (i; 0 .. N) {
        tasks[i] = runTask((size_t idx) nothrow {
            try {
                auto r = admitEgressDial(clients[idx].getDb(), l, HOST, PORT, true, 180_000, at + idx);
                tokens[idx] = r.trialToken;
                blocked[idx] = r.blockedState;
            } catch (Exception e) {
                blocked[idx] = "error:" ~ e.msg;
            }
        }, i);
    }
    foreach (t; tasks) t.join();
    size_t claims;
    foreach (i; 0 .. N) {
        if (tokens[i].length) claims++;
        else check(blocked[i] == "trial", "contender " ~ i.to!string ~ " refused as trial-in-progress, got " ~ blocked[i]);
    }
    check(claims == 1, "exactly one trial claimed across " ~ N.to!string ~ " contenders, got " ~ claims.to!string);
    auto view = readEgressAdmission(db, l, HOST, PORT, at + N);
    expectState(view, "recovering", "trial in flight");
    check(view.trialUntilMs > at, "trial lock published");
    reset(db, l);
}

void fencedSustainedSuccess(RedisDatabase db) {
    auto l = label("fence");
    reset(db, l);
    const token = quarantineThenClaim(db, l, T0);
    const start = T0 + 5 * MIN;
    // Success needs registration first, then a full sustain window.
    check(settleEgressTrial(db, l, HOST, PORT, token, EgressTrialOutcome.success, "", start + 2 * MIN) == "early",
        "unregistered trial cannot succeed");
    check(!renewEgressTrial(db, l, HOST, PORT, token ~ "x", start + 5 * MIN, start + 10_000), "wrong token renew");
    check(renewEgressTrial(db, l, HOST, PORT, token, start + 10_000 + 2 * MIN, start + 10_000), "renew at registration");
    check(settleEgressTrial(db, l, HOST, PORT, token, EgressTrialOutcome.success, "", start + 10_000 + MIN - 1) == "early",
        "59.999 s registered is not enough");
    check(settleEgressTrial(db, l, HOST, PORT, token ~ "x", EgressTrialOutcome.success, "", start + 10_000 + MIN) == "stale",
        "a foreign token is fenced");
    check(settleEgressTrial(db, l, HOST, PORT, token, EgressTrialOutcome.success, "", start + 10_000 + MIN) == "ok",
        "sustained trial closes the circuit");
    auto healed = readEgressAdmission(db, l, HOST, PORT, start + 2 * MIN);
    expectState(healed, "healthy", "after success");
    check(healed.failures == 0, "success resets failures");
    // The same (now stale) owner can neither reopen nor re-close it.
    check(settleEgressTrial(db, l, HOST, PORT, token, EgressTrialOutcome.failure, "late", start + 3 * MIN) == "stale",
        "stale failure fenced");
    expectState(readEgressAdmission(db, l, HOST, PORT, start + 3 * MIN), "healthy", "stale callback ignored");

    // A drain cancels a running trial; its success cannot override the drain.
    const t2 = quarantineThenClaim(db, l, T0 + 60 * MIN);
    const s2 = T0 + 65 * MIN;
    check(renewEgressTrial(db, l, HOST, PORT, t2, s2 + 2 * MIN, s2), "renew second trial");
    expectState(setEgressDraining(db, l, HOST, PORT, true, "operator", s2 + 10_000), "draining", "drain mid-trial");
    check(settleEgressTrial(db, l, HOST, PORT, t2, EgressTrialOutcome.success, "", s2 + 2 * MIN) == "stale",
        "drain fenced the trial");
    auto after = setEgressDraining(db, l, HOST, PORT, false, "", s2 + 2 * MIN);
    expectState(after, "recovering", "resume after a cancelled trial waits for a new trial");
    reset(db, l);
}

void freshLossDuringTrialFailsIt(RedisDatabase db) {
    auto l = label("losstrial");
    reset(db, l);
    const token = quarantineThenClaim(db, l, T0);
    const s = T0 + 5 * MIN;
    check(renewEgressTrial(db, l, HOST, PORT, token, s + 2 * MIN, s), "trial registered");
    // New correlated losses while the trial runs: the trial fails, fenced.
    auto q = quarantineEgress(db, l, HOST, PORT, "correlated loss", s + 30_000);
    check(q.opened && q.retryAtMs == s + 30_000 + 10 * MIN, "fresh loss during a trial restarts the next cooldown");
    check(settleEgressTrial(db, l, HOST, PORT, token, EgressTrialOutcome.success, "", s + 2 * MIN) == "stale",
        "the interrupted trial can no longer heal the exit");
    auto v = readEgressAdmission(db, l, HOST, PORT, s + 2 * MIN);
    expectState(v, "quarantined", "after a loss during the trial");
    check(v.failures == 2 && v.trialUntilMs == 0, "trial counted as failed and released");
    // Duplicate notices inside the open window never extend the cooldown,
    // nor does a loss while recovering with no trial running.
    auto dup = quarantineEgress(db, l, HOST, PORT, "correlated loss", s + 3 * MIN);
    check(!dup.opened && dup.already && dup.retryAtMs == q.retryAtMs, "duplicate loss leaves the cooldown");
    auto idle = quarantineEgress(db, l, HOST, PORT, "correlated loss", q.retryAtMs + 1);
    check(!idle.opened && idle.already && idle.retryAtMs == q.retryAtMs, "no trial running: unchanged");
    reset(db, l);
}

void progressiveCappedCooldown(RedisDatabase db) {
    auto l = label("cooldown");
    reset(db, l);
    long now = T0;
    auto q = quarantineEgress(db, l, HOST, PORT, "correlated loss", now);
    check(q.retryAtMs - now == 5 * MIN, "failure 1: 5 min");
    const long[] expected = [10 * MIN, 20 * MIN, 40 * MIN, 60 * MIN, 60 * MIN, 60 * MIN];
    long retryAt = q.retryAtMs;
    foreach (i, want; expected) {
        now = retryAt;
        auto claim = admitEgressDial(db, l, HOST, PORT, true, 180_000, now);
        check(claim.trialToken.length > 0, "claim " ~ i.to!string);
        now += 1_000;
        check(settleEgressTrial(db, l, HOST, PORT, claim.trialToken, EgressTrialOutcome.failure, "dial failed", now) == "ok",
            "failure settled");
        auto v = readEgressAdmission(db, l, HOST, PORT, now);
        expectState(v, "quarantined", "after failed trial");
        check(v.retryAtMs - now == want, "failure " ~ (i + 2).to!string ~ ": expected " ~ (want / MIN).to!string
            ~ " min, got " ~ ((v.retryAtMs - now) / MIN).to!string);
        check(v.failures == cast(int) i + 2, "failure count");
        retryAt = v.retryAtMs;
    }
    // Abort releases without penalty.
    auto claim = admitEgressDial(db, l, HOST, PORT, true, 180_000, retryAt);
    check(settleEgressTrial(db, l, HOST, PORT, claim.trialToken, EgressTrialOutcome.abort, "", retryAt + 1) == "ok", "abort");
    auto v = readEgressAdmission(db, l, HOST, PORT, retryAt + 2);
    expectState(v, "recovering", "abort returns to recovering");
    check(v.failures == cast(int) expected.length + 1, "abort adds no failure");
    // At the ceiling the count saturates and the record stays decodable.
    db.set(RedisKeys.egressAdmission(l), `{"v":1,"endpoint":"socks-se8.nordvpn.com:1080","draining":false,`
        ~ `"drainReason":"","open":true,"retryAtMs":0,"failures":1000000,"circuitReason":"",`
        ~ `"trialToken":"","trialUntilMs":0,"trialRegisteredAtMs":0,"gen":0,"updatedAtMs":0}`);
    auto top = admitEgressDial(db, l, HOST, PORT, true, 180_000, T0);
    check(top.trialToken.length > 0, "claim at the ceiling");
    check(settleEgressTrial(db, l, HOST, PORT, top.trialToken, EgressTrialOutcome.failure, "x", T0 + 1) == "ok", "fail at ceiling");
    auto sat = readEgressAdmission(db, l, HOST, PORT, T0 + 2);
    expectState(sat, "quarantined", "saturated record still decodes");
    check(sat.failures == 1_000_000 && sat.retryAtMs == T0 + 1 + 60 * MIN, "saturated count, capped cooldown");
    reset(db, l);
}

void expiredTrialCountsAsFailure(RedisDatabase db) {
    auto l = label("expiry");
    reset(db, l);
    const token = quarantineThenClaim(db, l, T0);
    const claimedAt = T0 + 5 * MIN;
    const lockEnd = claimedAt + 180_000;
    expectState(readEgressAdmission(db, l, HOST, PORT, lockEnd - 1), "recovering", "lock still held");
    // Read-only view after expiry: failed, next cooldown measured from expiry.
    auto viewed = readEgressAdmission(db, l, HOST, PORT, lockEnd + 1);
    expectState(viewed, "quarantined", "expired trial is a failure, never healthy or stuck recovering");
    check(viewed.failures == 2 && viewed.retryAtMs == lockEnd + 10 * MIN, "expiry backoff");
    // A write at the same instant persists exactly what the read reported.
    auto refused = admitEgressDial(db, l, HOST, PORT, true, 180_000, lockEnd + 1);
    check(!refused.allowed && refused.blockedState == "quarantined", "no trial during the new cooldown");
    auto persisted = readEgressAdmission(db, l, HOST, PORT, lockEnd + 1);
    check(persisted.failures == viewed.failures && persisted.retryAtMs == viewed.retryAtMs
        && persisted.state == viewed.state, "read and admit agree on the settled expiry");
    // The late owner is fenced.
    check(settleEgressTrial(db, l, HOST, PORT, token, EgressTrialOutcome.success, "", lockEnd + 2) == "stale",
        "expired owner fenced");
    check(!renewEgressTrial(db, l, HOST, PORT, token, lockEnd + 5 * MIN, lockEnd + 2), "expired owner cannot renew");
    reset(db, l);
}

void malformedAndEndpointMismatch(RedisDatabase db) {
    auto l = label("bad");
    auto key = RedisKeys.egressAdmission(l);
    const string[] malformed = [
        "not json",
        `{"v":2}`,
        `{"v":1,"endpoint":"socks-se8.nordvpn.com:1080","draining":false,"drainReason":"","open":false,`
            ~ `"retryAtMs":1.5,"failures":0,"circuitReason":"","trialToken":"","trialUntilMs":0,`
            ~ `"trialRegisteredAtMs":0,"gen":0,"updatedAtMs":0}`,
        `{"v":1,"endpoint":"socks-se8.nordvpn.com:1080","draining":false,"drainReason":"","open":false,`
            ~ `"retryAtMs":-1,"failures":0,"circuitReason":"","trialToken":"","trialUntilMs":0,`
            ~ `"trialRegisteredAtMs":0,"gen":0,"updatedAtMs":0}`,
        `{"v":1,"endpoint":"socks-se8.nordvpn.com:1080","draining":false,"drainReason":"","open":false,`
            ~ `"retryAtMs":1e300,"failures":0,"circuitReason":"","trialToken":"","trialUntilMs":0,`
            ~ `"trialRegisteredAtMs":0,"gen":0,"updatedAtMs":0}`,
        `{"v":1,"endpoint":"socks-se8.nordvpn.com:1080","draining":null,"drainReason":"","open":false,`
            ~ `"retryAtMs":0,"failures":0,"circuitReason":"","trialToken":"","trialUntilMs":0,`
            ~ `"trialRegisteredAtMs":0,"gen":0,"updatedAtMs":0}`,
        // Counter beyond the decodable bound / a D int: never cast to healthy.
        `{"v":1,"endpoint":"socks-se8.nordvpn.com:1080","draining":false,"drainReason":"","open":true,`
            ~ `"retryAtMs":0,"failures":1000001,"circuitReason":"","trialToken":"","trialUntilMs":0,`
            ~ `"trialRegisteredAtMs":0,"gen":0,"updatedAtMs":0}`,
        `{"v":1,"endpoint":"socks-se8.nordvpn.com:1080","draining":false,"drainReason":"","open":false,`
            ~ `"retryAtMs":0,"failures":2147483648,"circuitReason":"","trialToken":"","trialUntilMs":0,`
            ~ `"trialRegisteredAtMs":0,"gen":0,"updatedAtMs":0}`,
    ];
    foreach (raw; malformed) {
        db.set(key, raw);
        expectState(readEgressAdmission(db, l, HOST, PORT, T0), "unavailable", "malformed: " ~ raw[0 .. raw.length < 24 ? raw.length : 24]);
        auto a = admitEgressDial(db, l, HOST, PORT, true, 180_000, T0);
        check(!a.allowed && a.blockedState == "unavailable", "malformed refuses dials");
        check(quarantineEgress(db, l, HOST, PORT, "loss", T0).unavailable, "quarantine leaves malformed alone");
        check(db.get(key) == raw, "nothing erased the malformed record");
    }
    // The operator's resume acknowledges the current endpoint: recovery, not healthy.
    auto ack = setEgressDraining(db, l, HOST, PORT, false, "", T0);
    expectState(ack, "recovering", "resume over malformed");
    check(ack.reason.canFind("malformed"), "reason explains the replacement");

    // Endpoint mismatch: bound to the old host, read for the new one.
    reset(db, l);
    quarantineEgress(db, l, "old-exit.example", PORT, "loss", T0);
    auto mismatch = readEgressAdmission(db, l, HOST, PORT, T0 + 120 * MIN);
    expectState(mismatch, "unavailable", "endpoint mismatch");
    check(mismatch.reason.canFind("old-exit.example:1080"), "mismatch reason names the bound endpoint");
    check(!admitEgressDial(db, l, HOST, PORT, true, 180_000, T0 + 120 * MIN).allowed, "mismatch refuses dials");
    check(quarantineEgress(db, l, HOST, PORT, "loss", T0).unavailable, "mismatch quarantine is a no-op");
    auto rebound = setEgressDraining(db, l, HOST, PORT, false, "", T0 + 121 * MIN);
    expectState(rebound, "recovering", "acknowledged endpoint enters recovery");
    expectState(readEgressAdmission(db, l, "old-exit.example", PORT, T0 + 121 * MIN), "unavailable",
        "the old endpoint is no longer the bound one");
    // Uppercase / whitespace host forms are the same canonical endpoint.
    expectState(readEgressAdmission(db, l, " SOCKS-SE8.NordVPN.com", PORT, T0 + 121 * MIN), "recovering", "canonical host");
    reset(db, l);
}

/// Writes refused while reads work (NOREPLICAS via a temporary
/// `min-replicas-to-write 1`, restored afterwards): every write throws, so
/// no caller can report a quarantine or drain that was not stored, while a
/// read still answers from the old record — the case the engine covers by
/// holding the quarantine in-process until it is persisted.
void writesRefusedReadsWork(RedisDatabase db) {
    import vibe.db.redis.redis : RedisReply;
    auto l = label("noreplicas");
    reset(db, l);
    string prior;
    try {
        auto rep = db.request!(RedisReply!string)("CONFIG", "GET", "min-replicas-to-write");
        rep.popFront();
        prior = rep.front.idup;
    } catch (Exception e) {
        throw new Exception("disposable Redis with CONFIG access is required for the write-failure case", e);
    }
    db.request("CONFIG", "SET", "min-replicas-to-write", "1");
    scope(exit) db.request("CONFIG", "SET", "min-replicas-to-write", prior);
    bool threw;
    try quarantineEgress(db, l, HOST, PORT, "correlated loss", T0); catch (Exception) threw = true;
    check(threw, "a refused quarantine write throws");
    threw = false;
    try setEgressDraining(db, l, HOST, PORT, true, "x", T0); catch (Exception) threw = true;
    check(threw, "a refused drain write throws");
    expectState(readEgressAdmission(db, l, HOST, PORT, T0), "healthy",
        "reads still work and know nothing of the refused write");
}

void storageFailuresFailClosed(RedisDatabase db) {
    // A key of the wrong type makes every script fail: read reports
    // unavailable, writes throw (no false success).
    auto l = label("wrongtype");
    auto key = RedisKeys.egressAdmission(l);
    reset(db, l);
    db.hset(key, "x", "y");
    expectState(readEgressAdmission(db, l, HOST, PORT, T0), "unavailable", "read error");
    bool threw;
    try setEgressDraining(db, l, HOST, PORT, true, "x", T0); catch (Exception) threw = true;
    check(threw, "drain write failure throws");
    threw = false;
    try admitEgressDial(db, l, HOST, PORT, false, 180_000, T0); catch (Exception) threw = true;
    check(threw, "admit failure throws (engine refuses the dial)");
    reset(db, l);
    // An unreachable Redis: unavailable, writes throw.
    auto dead = new RedisStorage("127.0.0.1", 1);
    dead.connect();
    expectState(readEgressAdmission(dead.getDb(), l, HOST, PORT, T0), "unavailable", "unreachable store");
    threw = false;
    try setEgressDraining(dead.getDb(), l, HOST, PORT, true, "x", T0); catch (Exception) threw = true;
    check(threw, "unreachable store write throws");
}

void main() {
    url = environment.get("EGRESS_ADMISSION_REDIS_URL", "");
    if (url.length == 0) throw new Exception("set EGRESS_ADMISSION_REDIS_URL to a disposable Redis (redis://host:port)");
    if (environment.get("EGRESS_ADMISSION_ALLOW_CONFIG_TEST", "") != "1")
        throw new Exception("set EGRESS_ADMISSION_ALLOW_CONFIG_TEST=1 only for a dedicated disposable Redis; the test temporarily changes server-wide write policy");
    prefix = "admtest-" ~ getpid().to!string ~ "-";
    auto r = client();
    scope(exit) r.close();
    r.ping();
    auto db = r.getDb();
    noRecordIsHealthy(db);
    drainSurvivesClientsAndResumeKeepsCircuit(db);
    singleTrialAcrossContenders(db);
    fencedSustainedSuccess(db);
    progressiveCappedCooldown(db);
    expiredTrialCountsAsFailure(db);
    freshLossDuringTrialFailsIt(db);
    malformedAndEndpointMismatch(db);
    storageFailuresFailClosed(db);
    writesRefusedReadsWork(db);
    writeln("egress admission Redis test: PASS (10 cases)");
}
