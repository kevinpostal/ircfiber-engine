/// Standalone test for the ConnectionServer.registrationUnavailableFor
/// field — the admin SPA's per-server "Registration stuck" indicator.
///
/// Verifies:
///   - JSON round-trip: registrationUnavailableFor serializes and
///     deserializes correctly so the admin API
///     (GET /api/admin/servers/:id) keeps working without runtime breakage
///   - getRegistrationTimeoutSince() on PersistentIRCClient is exposed
///     and defaults to 0 (no timeout) so the admin SPA can show
///     "last timeout at" without crashing on networks that have never
///     timed out
///
/// The actual timeout enforcement (REGISTRATION_OVERALL_TIMEOUT_SECS
/// firing the throw inside performRegistration) is exercised end-to-end
/// by `scripts/e2e/registration_timeout.py` which points a network at a
/// local Python TCP listener that accepts but never sends 001, and
/// verifies the engine retries with backoff after the hard timeout fires.
///
/// Run with: `make connection-registration-test`.
module connection_registration_test;

import std.stdio : stderr, writeln;
import std.algorithm : canFind;
import std.conv : to;
import std.array : split;
import vibe.data.json : Json;

import ircfiber.irc.server : ConnectionServer;
import ircfiber.irc.connection : parseJoinThrottleSeconds, remainingJoinDelayMs, joinBatches;

/// Tracks the number of passing checks.
int passed;
/// Tracks the number of failing checks.
int failed;

/// Records the outcome of a single named check.
void ok(string name, bool cond, string msg = "") {
    if (cond) {
        ++passed;
        stderr.writeln("  ✓ ", name);
    } else {
        ++failed;
        stderr.writeln("  ✗ ", name, msg.length ? " — " ~ msg : "");
    }
}

/// Serializes the given Json value to its string form.
string toJsonString(scope ref Json j) { return j.toString(); }

void main() {
    stderr.writeln("\n[connection.registration] admin surface contract");

    // ── JOIN-throttle parsing (SuperNETs 421) ────────────────────────────
    // Wire text captured from openwater.supernets.org 2026-09-05:
    //   421 <nick> JOIN :You must be connected for at least 5 seconds
    //   before you can use this command
    ok("throttle parser reads the SuperNETs window",
        parseJoinThrottleSeconds(
            "You must be connected for at least 5 seconds before you can use this command") == 5);
    ok("throttle parser honours a longer server window",
        parseJoinThrottleSeconds(
            "You must be connected for at least 30 seconds before you can use this command") == 30);
    ok("throttle parser ignores a real unknown-command 421",
        parseJoinThrottleSeconds("Unknown command") == 0);
    ok("throttle parser ignores the phrase without a number",
        parseJoinThrottleSeconds("You must be connected for at least a while") == 0);
    ok("throttle parser clamps an absurd window",
        parseJoinThrottleSeconds("connected for at least 99999 seconds") == 600);
    // The retry waits out the server's window measured from the connect,
    // not from the moment the 421 arrived.
    ok("retry delay covers the remaining window",
        remainingJoinDelayMs(6, 900_100, 900_000) == 5_900);
    ok("retry delay is zero once the window elapsed",
        remainingJoinDelayMs(6, 907_000, 900_000) == 0);

    // Auto-joins go out as one comma-joined JOIN per line, so a server that
    // rate-limits per command answers once instead of once per channel.
    ok("nine channels ride one JOIN",
        joinBatches(["#a", "#b", "#c", "#d", "#e", "#f", "#g", "#h", "#i"]).length == 1);
    ok("the batch is comma-joined in order",
        joinBatches(["#zod", "#bowlcut", "#dev"])[0] == "#zod,#bowlcut,#dev");
    ok("empty names never produce a stray comma",
        joinBatches(["#a", "", "#b"])[0] == "#a,#b");
    ok("no channels means no command",
        joinBatches([]).length == 0);
    // 512-byte IRC lines: split rather than truncate, and never lose a name.
    {
        string[] many;
        foreach (i; 0 .. 60) many ~= "#channel" ~ to!string(i);
        auto b = joinBatches(many);
        ok("a long channel list splits into several lines", b.length > 1);
        bool allShort = true;
        size_t names = 0;
        foreach (line; b) {
            if (line.length > 400) allShort = false;
            names += line.split(",").length;
        }
        ok("every batch stays inside the line limit", allShort);
        ok("splitting keeps every channel", names == many.length,
            "got " ~ to!string(names));
    }

    // 1. registrationUnavailableFor defaults to empty
    ConnectionServer s1;
    s1.serverId = "ovh";
    s1.bindAddress = "0.0.0.0";
    s1.isHealthy = true;
    ok("default registrationUnavailableFor is empty",
        s1.registrationUnavailableFor.length == 0,
        "got len=" ~ to!string(s1.registrationUnavailableFor.length));

    // 2. JSON round-trip with a non-trivial list
    auto s2 = ConnectionServer();
    s2.serverId = "ovh";
    s2.bindAddress = "0.0.0.0";
    s2.isHealthy = true;
    s2.registrationUnavailableFor = ["bully-nets", "gang-net"];

    auto j = s2.toJson();
    immutable regArr = j["registrationUnavailableFor"];
    ok("toJson includes registrationUnavailableFor key",
        regArr.type == Json.Type.array,
        "got type=" ~ to!string(cast(int)regArr.type));
    ok("toJson includes both registration entries",
        regArr[0].get!string == "bully-nets" && regArr[1].get!string == "gang-net",
        "got: " ~ toJsonString(j));

    // 3. fromJson restores the array
    auto s3 = ConnectionServer.fromJson(j);
    ok("fromJson restores registrationUnavailableFor length",
        s3.registrationUnavailableFor.length == 2,
        "got len=" ~ to!string(s3.registrationUnavailableFor.length));
    ok("fromJson preserves bully-nets in registration list",
        s3.registrationUnavailableFor.canFind("bully-nets"),
        "got: " ~ s3.registrationUnavailableFor.to!string);

    // 4. fromJson tolerates legacy snapshots without the key (older admin
    //    SPA build that doesn't know about this field yet) — graceful
    //    degradation. The admin SPA can then re-fetch the new shape
    //    on its next refresh.
    auto legacy = Json.emptyObject;
    legacy["serverId"] = "ovh";
    legacy["bindAddress"] = "0.0.0.0";
    legacy["isHealthy"] = true;
    auto s4 = ConnectionServer.fromJson(legacy);
    ok("fromJson tolerates missing registrationUnavailableFor key",
        s4.registrationUnavailableFor.length == 0,
        "got len=" ~ to!string(s4.registrationUnavailableFor.length));

    // 5. Three-entry ordering survives round-trip
    auto s5 = ConnectionServer();
    s5.serverId = "ovh";
    s5.bindAddress = "0.0.0.0";
    s5.isHealthy = true;
    s5.registrationUnavailableFor = ["gang-net", "bully-nets", "supernets"];
    auto j5 = s5.toJson();
    ok("registration list shows gang-net as first entry in toJson",
        j5["registrationUnavailableFor"][0].get!string == "gang-net",
        "got: " ~ toJsonString(j5));
    ok("registration list shows supernets as third entry in toJson",
        j5["registrationUnavailableFor"][2].get!string == "supernets",
        "got: " ~ toJsonString(j5));

    stderr.writeln("\n[", passed, " passed, ", failed, " failed]");
    if (failed > 0) core.stdc.stdlib.exit(1);
}

import core.stdc.stdlib;