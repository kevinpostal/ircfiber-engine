/**
 * Durable admission control for VPN egress exits (Mullvad slots and static
 * NordVPN-style exits), shared by every engine and the gateway.
 *
 * One Redis record per exit label (`RedisKeys.egressAdmission`) holds the
 * operator drain and the automatic circuit (quarantine → recovery). Every
 * transition runs as one Lua script, so concurrent engines see a single
 * order of compare/update/claim steps; no process keeps a private verdict.
 *
 * Model:
 *  - No record: healthy (initial rollout).
 *  - Each record is bound to the exit's canonical `host:port`. A label whose
 *    endpoint changed is `unavailable` until an operator drain/resume
 *    acknowledges the current endpoint, which never yields a positive
 *    verdict: the acknowledged endpoint enters recovery.
 *  - A malformed record, or any Redis read failure, is `unavailable` and
 *    blocks new VPN dials. Nothing here erases or ignores it silently.
 *  - Drain blocks every new dial indefinitely and cancels an unsettled
 *    recovery trial; resume clears only the drain, never the circuit.
 *  - An open circuit is `quarantined` until `retryAtMs`, then `recovering`:
 *    exactly one atomically claimed trial dial at a time. The trial closes
 *    the circuit only after its IRC session stayed registered for
 *    `EGRESS_TRIAL_SUSTAIN_MS`, enforced here, not only by the caller. A
 *    failed or abandoned (lock-expired) trial reopens the circuit with a
 *    progressive cooldown (5 min doubling, capped at 1 h).
 *  - Trial outcomes are fenced by the owner token (which embeds the record
 *    generation): a stale callback can neither close nor reopen a circuit,
 *    nor undo a drain.
 *
 * `readEgressAdmission`, `setEgressDraining` and `EgressAdmission.toJson`
 * are the gateway contract; the remaining functions are the engine's.
 */
module ircfiber.irc.egress_admission;

import std.conv : to;
import std.string : strip, toLower, indexOf, startsWith;
import vibe.data.json : Json, parseJsonString;
import vibe.db.redis.redis : RedisDatabase;

import ircfiber.redis.protocol : RedisKeys;

/// First automatic cooldown after a quarantine or failed trial.
enum long EGRESS_ADMISSION_BASE_COOLDOWN_MS = 5 * 60_000L;
/// Cooldown cap for repeated failures.
enum long EGRESS_ADMISSION_MAX_COOLDOWN_MS = 60 * 60_000L;
/// A trial succeeds only after its session stayed registered this long.
enum long EGRESS_TRIAL_SUSTAIN_MS = 60_000L;
/// Longest operator reason stored, in code points.
enum size_t EGRESS_ADMISSION_REASON_MAX = 200;

/// Admission verdict for one exit at one instant. No credentials or tokens.
struct EgressAdmission {
    string state = "healthy"; // healthy | quarantined | recovering | draining | unavailable
    bool draining;
    long retryAtMs;
    long trialUntilMs;
    int failures;
    string reason;
    long updatedAtMs;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["state"] = Json(state);
        j["draining"] = Json(draining);
        j["retryAtMs"] = Json(retryAtMs);
        j["trialUntilMs"] = Json(trialUntilMs);
        j["failures"] = Json(cast(long) failures);
        j["reason"] = Json(reason);
        j["updatedAtMs"] = Json(updatedAtMs);
        return j;
    }

    /// New VPN dials may use this exit without a trial.
    @property bool admitsDials() const { return state == "healthy"; }
}

/// One exit as the engine's pool configures it.
struct EgressEndpointRef {
    string label;
    string host;
    ushort port;
}

/// Canonical endpoint a record is bound to: lower-case host, bracketed when
/// it is an IPv6 literal, plus the port.
string egressAdmissionEndpoint(string host, ushort port) {
    auto h = host.strip().toLower();
    if (h.indexOf(':') >= 0 && !h.startsWith("[")) h = "[" ~ h ~ "]";
    return h ~ ":" ~ port.to!string;
}

/// Operator reason, trimmed, control characters blanked, at most
/// `EGRESS_ADMISSION_REASON_MAX` code points. Throws on invalid UTF-8.
string boundAdmissionReason(string reason) {
    import std.array : appender;
    import std.uni : isControl;
    import std.utf : validate;
    validate(reason);
    auto app = appender!string;
    size_t n;
    foreach (dchar c; reason.strip()) {
        if (n >= EGRESS_ADMISSION_REASON_MAX) break;
        app.put(isControl(c) ? ' ' : c);
        n++;
    }
    return app.data.strip();
}

/// Reads one exit's admission. Never throws: a Redis failure or malformed
/// reply is `unavailable` (fail closed), never healthy.
EgressAdmission readEgressAdmission(RedisDatabase db, string label, string host, ushort port, long nowMs) {
    return readEgressAdmissions(db, [EgressEndpointRef(label, host, port)], nowMs)[0];
}

/// Batch read, one script for all exits, results aligned with `exits`.
/// Never throws: on any failure every entry is `unavailable`.
EgressAdmission[] readEgressAdmissions(RedisDatabase db, const(EgressEndpointRef)[] exits, long nowMs) nothrow {
    auto result = new EgressAdmission[exits.length];
    if (exits.length == 0) return result;
    try {
        string[] keys, args = commonArgs(nowMs);
        foreach (e; exits) {
            keys ~= RedisKeys.egressAdmission(e.label);
            args ~= egressAdmissionEndpoint(e.host, e.port);
        }
        auto reply = db.eval!string(READ_SCRIPT, keys, args);
        if (reply.empty) throw new Exception("empty admission reply");
        auto arr = parseJsonString(reply.front.idup);
        if (arr.type != Json.Type.array || arr.length != exits.length)
            throw new Exception("admission reply shape mismatch");
        foreach (i; 0 .. exits.length) result[i] = viewFromJson(arr[i]);
    } catch (Exception e) {
        string msg;
        try msg = e.msg; catch (Exception) {}
        foreach (ref a; result) a = unavailableAdmission(msg);
    }
    return result;
}

/// Sets or clears the operator drain and returns the resulting admission.
/// Resume never closes the circuit. On a malformed record or an endpoint
/// mismatch this is the explicit acknowledgement of the current endpoint:
/// the record is rebound with an open circuit due for one recovery trial.
/// Draining cancels an unsettled trial. Throws on Redis failure or invalid
/// reason, so a caller cannot report a write that did not happen.
EgressAdmission setEgressDraining(RedisDatabase db, string label, string host, ushort port,
                                  bool draining, string reason, long nowMs) {
    if (label.length == 0) throw new Exception("egress label required");
    auto args = commonArgs(nowMs) ~ [egressAdmissionEndpoint(host, port), draining ? "1" : "0",
                                     boundAdmissionReason(reason)];
    auto reply = db.eval!string(DRAIN_SCRIPT, [RedisKeys.egressAdmission(label)], args);
    if (reply.empty) throw new Exception("empty admission reply");
    return viewFromJson(parseJsonString(reply.front.idup));
}

/// Pre-dial admission decision.
struct EgressDialAdmit {
    /// The dial may proceed.
    bool allowed;
    /// Non-empty when this dial is the exit's single recovery trial; the
    /// caller owns its outcome (renew/settle with this token).
    string trialToken;
    /// Why the dial was refused: draining | quarantined | recovering |
    /// trial | unavailable.
    string blockedState;
}

/// Atomically re-checks admission right before a dial and, for a candidate
/// placed in the recovery tier (`allowTrial`), claims the exit's single
/// trial for `claimMs`. Throws on Redis failure (callers fail closed).
EgressDialAdmit admitEgressDial(RedisDatabase db, string label, string host, ushort port,
                                bool allowTrial, long claimMs, long nowMs) {
    // Entropy only when this call may claim the trial.
    string nonce;
    if (allowTrial) {
        import std.uuid : randomUUID;
        nonce = randomUUID().toString();
    }
    auto args = commonArgs(nowMs) ~ [egressAdmissionEndpoint(host, port), allowTrial ? "1" : "0",
                                     nonce, claimMs.to!string];
    auto reply = db.eval!string(ADMIT_SCRIPT, [RedisKeys.egressAdmission(label)], args);
    if (reply.empty) throw new Exception("empty admission reply");
    const raw = reply.front.idup;
    const bar = raw.indexOf('|');
    if (bar < 0) throw new Exception("malformed admission reply");
    EgressDialAdmit a;
    switch (raw[0 .. bar]) {
        case "ok": a.allowed = true; break;
        case "trial": a.allowed = true; a.trialToken = raw[bar + 1 .. $]; break;
        case "blocked": a.blockedState = raw[bar + 1 .. $]; break;
        default: throw new Exception("malformed admission reply");
    }
    if (raw[0 .. bar] == "trial" && a.trialToken.length == 0)
        throw new Exception("trial claim without token");
    return a;
}

/// Marks the trial's IRC session registered (first call only) and extends
/// its lock to `untilMs`. False when the token is stale or the lock already
/// expired (the expiry is then settled as a failure).
bool renewEgressTrial(RedisDatabase db, string label, string host, ushort port,
                      string token, long untilMs, long nowMs) {
    if (token.length == 0) return false;
    auto args = commonArgs(nowMs) ~ [egressAdmissionEndpoint(host, port), token, untilMs.to!string];
    auto reply = db.eval!string(RENEW_SCRIPT, [RedisKeys.egressAdmission(label)], args);
    if (reply.empty) throw new Exception("empty admission reply");
    return reply.front == "ok";
}

enum EgressTrialOutcome { success, failure, abort }

/// Settles a trial: `success` closes the circuit (refused as "early" unless
/// the session stayed registered `EGRESS_TRIAL_SUSTAIN_MS`), `failure`
/// reopens it with the next cooldown, `abort` releases the claim without
/// penalty (the exit was never exercised). Returns "ok" | "stale" | "early".
string settleEgressTrial(RedisDatabase db, string label, string host, ushort port, string token,
                         EgressTrialOutcome outcome, string reason, long nowMs) {
    if (token.length == 0) return "stale";
    auto args = commonArgs(nowMs) ~ [egressAdmissionEndpoint(host, port), token, outcome.to!string,
                                     EGRESS_TRIAL_SUSTAIN_MS.to!string, boundAdmissionReason(reason)];
    auto reply = db.eval!string(SETTLE_SCRIPT, [RedisKeys.egressAdmission(label)], args);
    if (reply.empty) throw new Exception("empty admission reply");
    return reply.front.idup;
}

/// Result of an automatic quarantine request.
struct EgressQuarantine {
    /// This call opened the circuit, or failed a running recovery trial and
    /// restarted the cooldown (announce once).
    bool opened;
    /// Circuit was already open (or became open by an expired trial).
    bool already;
    /// Record is malformed or bound to another endpoint: left untouched,
    /// dials stay blocked.
    bool unavailable;
    long retryAtMs;
}

/// Opens the circuit after correlated established-session losses. A trial
/// in progress is failed and fenced off (its success can no longer close
/// the circuit) with the next progressive cooldown; any other open circuit
/// keeps its cooldown unchanged. Throws on Redis failure.
EgressQuarantine quarantineEgress(RedisDatabase db, string label, string host, ushort port,
                                  string reason, long nowMs) {
    auto args = commonArgs(nowMs) ~ [egressAdmissionEndpoint(host, port), boundAdmissionReason(reason)];
    auto reply = db.eval!string(QUARANTINE_SCRIPT, [RedisKeys.egressAdmission(label)], args);
    if (reply.empty) throw new Exception("empty admission reply");
    const raw = reply.front.idup;
    const bar = raw.indexOf('|');
    if (bar < 0) throw new Exception("malformed admission reply");
    EgressQuarantine q;
    q.retryAtMs = raw[bar + 1 .. $].to!long;
    switch (raw[0 .. bar]) {
        case "opened": q.opened = true; break;
        case "already": q.already = true; break;
        case "unavailable": q.unavailable = true; break;
        default: throw new Exception("malformed admission reply");
    }
    return q;
}

/// `unavailable` with a bounded diagnosis (never echoes a whole reply).
/// Truncates on a code-point boundary; invalid UTF-8 is dropped entirely.
EgressAdmission unavailableAdmission(string detail) nothrow {
    import std.utf : stride, validate;
    EgressAdmission a;
    a.state = "unavailable";
    string d;
    try {
        validate(detail);
        size_t end;
        while (end < detail.length && end < 120) end += stride(detail, end);
        d = detail[0 .. end];
    } catch (Exception) {
        d = "";
    }
    a.reason = "admission store unavailable" ~ (d.length ? ": " ~ d : "") ~ "; new dials blocked";
    return a;
}

private string[] commonArgs(long nowMs) {
    return [nowMs.to!string, EGRESS_ADMISSION_BASE_COOLDOWN_MS.to!string,
            EGRESS_ADMISSION_MAX_COOLDOWN_MS.to!string];
}

private long jsonLong(Json j, string key) {
    auto v = j[key];
    if (v.type == Json.Type.int_) return v.get!long;
    throw new Exception("admission field " ~ key ~ " is not an integer");
}

private EgressAdmission viewFromJson(Json j) {
    if (j.type != Json.Type.object) throw new Exception("admission view is not an object");
    EgressAdmission a;
    a.state = j["state"].get!string;
    switch (a.state) {
        case "healthy", "quarantined", "recovering", "draining", "unavailable": break;
        default: throw new Exception("unknown admission state");
    }
    a.draining = j["draining"].get!bool;
    a.retryAtMs = jsonLong(j, "retryAtMs");
    a.trialUntilMs = jsonLong(j, "trialUntilMs");
    const failures = jsonLong(j, "failures");
    if (failures < 0 || failures > int.max) throw new Exception("admission failure count out of range");
    a.failures = cast(int) failures;
    a.reason = j["reason"].get!string;
    a.updatedAtMs = jsonLong(j, "updatedAtMs");
    return a;
}

// ── Lua state machine ─────────────────────────────────────────────────────
// ARGV[1..3] = now, base cooldown, max cooldown in every script. Records:
// {v=1, endpoint, draining, drainReason, open, retryAtMs, failures,
//  circuitReason, trialToken, trialUntilMs, trialRegisteredAtMs, gen,
//  updatedAtMs}.

private enum PRELUDE = q"LUA
local now, base, cap = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
-- Consecutive-failure ceiling (fits a D int; the cooldown caps long before).
local MAX_FAILURES = 1000000
local function decode(raw)
  if not raw then return nil, false end
  local ok, r = pcall(cjson.decode, raw)
  if not ok or type(r) ~= 'table' or r.v ~= 1 then return nil, true end
  for _, k in ipairs({'endpoint', 'drainReason', 'circuitReason', 'trialToken'}) do
    if type(r[k]) ~= 'string' then return nil, true end
  end
  for _, k in ipairs({'draining', 'open'}) do
    if type(r[k]) ~= 'boolean' then return nil, true end
  end
  -- Integers only, finite, non-negative and below 1e14 so cjson's 14-digit
  -- encoding round-trips them exactly; failure counts stay small.
  for _, k in ipairs({'retryAtMs', 'failures', 'trialUntilMs', 'trialRegisteredAtMs', 'gen', 'updatedAtMs'}) do
    local n = r[k]
    if type(n) ~= 'number' or n ~= n or n < 0 or n > 99999999999999 or math.floor(n) ~= n then
      return nil, true
    end
  end
  if r.failures > MAX_FAILURES then return nil, true end
  if r.trialToken ~= '' and not r.open then return nil, true end
  return r, false
end
local function fresh(endpoint)
  return {v = 1, endpoint = endpoint, draining = false, drainReason = '', open = false,
          retryAtMs = 0, failures = 0, circuitReason = '', trialToken = '', trialUntilMs = 0,
          trialRegisteredAtMs = 0, gen = 0, updatedAtMs = 0}
end
-- Saturating: the stored count never exceeds what decode() accepts.
local function bump(r)
  if r.failures < MAX_FAILURES then r.failures = r.failures + 1 end
end
local function cool(f)
  local ms, i = base, 1
  while i < f and ms < cap do ms = ms * 2; i = i + 1 end
  if ms > cap then ms = cap end
  return ms
end
local function clearTrial(r)
  r.trialToken = ''; r.trialUntilMs = 0; r.trialRegisteredAtMs = 0
end
local function settleExpired(r)
  if r.trialToken ~= '' and r.trialUntilMs <= now then
    bump(r)
    r.open = true
    r.retryAtMs = r.trialUntilMs + cool(r.failures)
    r.circuitReason = 'recovery trial expired without a sustained registered session'
    clearTrial(r)
    r.gen = r.gen + 1
    return true
  end
  return false
end
local function save(key, r)
  r.updatedAtMs = now
  redis.call('SET', key, cjson.encode(r))
end
local function view(r, bad, endpoint)
  local v = {state = 'healthy', draining = false, retryAtMs = 0, trialUntilMs = 0, failures = 0,
             reason = '', updatedAtMs = 0}
  if bad then
    v.state = 'unavailable'
    v.reason = 'admission record is malformed; new dials blocked until an operator drains or resumes this exit'
    return v
  end
  if not r then return v end
  v.updatedAtMs = r.updatedAtMs
  v.draining = r.draining
  if r.endpoint ~= endpoint then
    v.state = 'unavailable'
    v.reason = 'exit endpoint changed from ' .. r.endpoint .. ' to ' .. endpoint
      .. '; new dials blocked until an operator drains or resumes this exit'
    return v
  end
  settleExpired(r)
  v.failures = r.failures
  if r.open then v.retryAtMs = r.retryAtMs end
  v.trialUntilMs = r.trialUntilMs
  if r.draining then
    v.state = 'draining'
    v.reason = r.drainReason ~= '' and r.drainReason or 'drained by an operator'
  elseif r.open and now < r.retryAtMs then
    v.state = 'quarantined'
    v.reason = r.circuitReason
  elseif r.open then
    v.state = 'recovering'
    if r.trialToken ~= '' then
      v.reason = 'one recovery trial session in progress'
    elseif r.circuitReason ~= '' then
      v.reason = r.circuitReason .. '; waiting for one recovery trial'
    else
      v.reason = 'waiting for one recovery trial'
    end
  end
  return v
end
LUA";

// KEYS = records; ARGV[4..] = endpoint per key. Read-only.
private enum READ_SCRIPT = PRELUDE ~ q"LUA
local out = {}
for i, key in ipairs(KEYS) do
  local r, bad = decode(redis.call('GET', key))
  out[i] = view(r, bad, ARGV[3 + i])
end
return cjson.encode(out)
LUA";

// ARGV[4] endpoint, [5] '1' drain / '0' resume, [6] reason.
private enum DRAIN_SCRIPT = PRELUDE ~ q"LUA
local endpoint, drain, reason = ARGV[4], ARGV[5] == '1', ARGV[6]
local r, bad = decode(redis.call('GET', KEYS[1]))
if bad or (r and r.endpoint ~= endpoint) then
  local n = fresh(endpoint)
  n.open = true
  n.retryAtMs = now
  if bad then
    n.circuitReason = 'malformed admission record replaced by an operator; one recovery trial must prove this exit'
  else
    n.failures = r.failures
    n.gen = r.gen
    n.circuitReason = 'exit endpoint changed from ' .. r.endpoint .. '; one recovery trial must prove ' .. endpoint
  end
  r = n
elseif not r then
  if not drain then return cjson.encode(view(nil, false, endpoint)) end
  r = fresh(endpoint)
else
  settleExpired(r)
end
r.draining = drain
if drain then r.drainReason = reason else r.drainReason = '' end
if drain then clearTrial(r) end
r.gen = r.gen + 1
save(KEYS[1], r)
return cjson.encode(view(r, false, endpoint))
LUA";

// ARGV[4] endpoint, [5] allowTrial, [6] token nonce, [7] claim ms.
private enum ADMIT_SCRIPT = PRELUDE ~ q"LUA
local endpoint = ARGV[4]
local r, bad = decode(redis.call('GET', KEYS[1]))
if bad then return 'blocked|unavailable' end
if not r then return 'ok|' end
if r.endpoint ~= endpoint then return 'blocked|unavailable' end
local changed = settleExpired(r)
local result
if r.draining then result = 'blocked|draining'
elseif not r.open then result = 'ok|'
elseif now < r.retryAtMs then result = 'blocked|quarantined'
elseif r.trialToken ~= '' then result = 'blocked|trial'
elseif ARGV[5] ~= '1' then result = 'blocked|recovering'
else
  r.gen = r.gen + 1
  r.trialToken = ARGV[6] .. ':' .. string.format('%d', r.gen)
  r.trialUntilMs = now + tonumber(ARGV[7])
  r.trialRegisteredAtMs = 0
  changed = true
  result = 'trial|' .. r.trialToken
end
if changed then save(KEYS[1], r) end
return result
LUA";

// ARGV[4] endpoint, [5] token, [6] lock until ms.
private enum RENEW_SCRIPT = PRELUDE ~ q"LUA
local endpoint, token = ARGV[4], ARGV[5]
local r, bad = decode(redis.call('GET', KEYS[1]))
if token == '' or bad or not r or r.endpoint ~= endpoint or r.trialToken ~= token then return 'stale' end
if settleExpired(r) then save(KEYS[1], r); return 'stale' end
if r.trialRegisteredAtMs == 0 then r.trialRegisteredAtMs = now end
local untilMs = tonumber(ARGV[6])
if untilMs > r.trialUntilMs then r.trialUntilMs = untilMs end
save(KEYS[1], r)
return 'ok'
LUA";

// ARGV[4] endpoint, [5] token, [6] outcome, [7] sustain ms, [8] reason.
private enum SETTLE_SCRIPT = PRELUDE ~ q"LUA
local endpoint, token, outcome = ARGV[4], ARGV[5], ARGV[6]
local r, bad = decode(redis.call('GET', KEYS[1]))
if token == '' or bad or not r or r.endpoint ~= endpoint or r.trialToken ~= token then return 'stale' end
if settleExpired(r) then save(KEYS[1], r); return 'stale' end
if outcome == 'success' then
  if r.trialRegisteredAtMs == 0 or now - r.trialRegisteredAtMs < tonumber(ARGV[7]) then return 'early' end
  r.open = false
  r.failures = 0
  r.retryAtMs = 0
  r.circuitReason = ''
elseif outcome == 'failure' then
  bump(r)
  r.open = true
  r.retryAtMs = now + cool(r.failures)
  r.circuitReason = ARGV[8]
elseif outcome ~= 'abort' then
  return redis.error_reply('unknown trial outcome')
end
clearTrial(r)
r.gen = r.gen + 1
save(KEYS[1], r)
return 'ok'
LUA";

// ARGV[4] endpoint, [5] reason. A fresh correlated loss while a trial is
// running fails that trial (its token is fenced off) and restarts the next
// cooldown; any other open circuit is left exactly as it is.
private enum QUARANTINE_SCRIPT = PRELUDE ~ q"LUA
local endpoint = ARGV[4]
local r, bad = decode(redis.call('GET', KEYS[1]))
if bad or (r and r.endpoint ~= endpoint) then return 'unavailable|0' end
if not r then r = fresh(endpoint) end
local changed = settleExpired(r)
if r.open and r.trialToken == '' then
  if changed then save(KEYS[1], r) end
  return 'already|' .. string.format('%d', r.retryAtMs)
end
clearTrial(r)
r.open = true
bump(r)
r.retryAtMs = now + cool(r.failures)
r.circuitReason = ARGV[5]
r.gen = r.gen + 1
save(KEYS[1], r)
return 'opened|' .. string.format('%d', r.retryAtMs)
LUA";

@("egress admission: endpoint canonicalisation and bounded reasons")
unittest {
    assert(egressAdmissionEndpoint(" Socks-SE8.NordVPN.com ", 1080) == "socks-se8.nordvpn.com:1080");
    assert(egressAdmissionEndpoint("2001:db8::1", 1080) == "[2001:db8::1]:1080");
    assert(egressAdmissionEndpoint("[2001:db8::1]", 1080) == "[2001:db8::1]:1080");
    import std.array : replicate;
    assert(boundAdmissionReason("  maintenance\n window ") == "maintenance  window");
    assert(boundAdmissionReason("é".replicate(300)).length == 2 * EGRESS_ADMISSION_REASON_MAX);
    bool threw;
    try boundAdmissionReason("\xff"); catch (Exception) threw = true;
    assert(threw);
    // A store error is reported without splitting a multi-byte character.
    import std.utf : validate;
    auto u = unavailableAdmission("é".replicate(100));
    validate(u.reason);
    assert(u.state == "unavailable" && !u.admitsDials);
    assert(unavailableAdmission("\xff").reason == "admission store unavailable; new dials blocked");
}
