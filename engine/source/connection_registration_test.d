/// Connection lifecycle and protocol regressions, including JOIN throttling,
/// roster convergence, identity enrichment, services and history handoff.
/// Run with `dub run --config=connection-registration-test --compiler=ldc2`.
module connection_registration_test;

import std.stdio : stderr;
import std.conv : to;
import std.array : split;
import vibe.data.json : Json;

import ircfiber.irc.server : ConnectionServer;
import ircfiber.irc.connection : parseJoinThrottleSeconds, remainingJoinDelayMs, joinBatches,
    memberNeedsRealname, channelNeedsRealnameWho, MAX_WHO_ENRICH_ATTEMPTS,
    upsertRosterEntry, applyNamesBurst, isSaslRequiredRefusal, extractServerReason,
    saslMechanismOffered, fiberMlsBackstopChecks, fiberMlsWireChecks, servicesIdentityWireChecks,
    ircv3ProtocolChecks, silentTransportRouteChecks;
import ircfiber.engine.session_snapshot : historySnapshotRegressionChecks;
import ircfiber.engine.processor : historyCheckpointRegressionChecks;
import ircfiber.irc.bnc_ownership : runBncOwnershipProtocolChecks;
import std.string : indexOf;

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

    // ── Realname-probe termination (SuperNets WHO/WHOIS flood) ───────────
    // The engine used to ask SuperNets for realnames forever: a user whose
    // realname equals their nick is deliberately not stored in `realnames`
    // (the UI would double-print it), so `bare !in realnames` stayed true
    // and the 60 s sweep re-sent `WHO #chan` every minute for the life of
    // the connection. `realnameProbed` records that the server answered.
    stderr.writeln("\n[connection.realnames] probe termination");

    ok("a stored realname needs no probe",
        !memberNeedsRealname("nick", ["nick": "Real Name"], null));
    ok("an unprobed nick needs a probe",
        memberNeedsRealname("nick", null, null));
    // The regression: pre-fix there was no probed set, so this member kept
    // its channel "needing WHO" on every sweep, forever.
    ok("a realname identical to the nick stops asking once answered",
        !memberNeedsRealname("nick", null, ["nick": true]));
    ok("prefix + userhost-in-names forms fold to the same nick",
        !memberNeedsRealname("@nick!user@host", null, ["nick": true]));

    ok("a fully resolved roster needs no WHO",
        !channelNeedsRealnameWho(["@a!u@h", "b"], ["b": "Bee"], ["a": true], 0));
    ok("an unresolved member triggers a WHO",
        channelNeedsRealnameWho(["a"], null, null, 0));
    // A server that answers WHO but omits members (or never sends 315)
    // cannot keep the sweep alive past the cap.
    ok("the attempt cap stops the sweep",
        !channelNeedsRealnameWho(["a"], null, null, MAX_WHO_ENRICH_ATTEMPTS));
    ok("an empty channel needs no WHO",
        !channelNeedsRealnameWho([], null, null, 0));

    // ── Channel roster identity (#tclmafia showed two Zodiacs) ───────────
    // The member list carried `Zodiac` AND `Zodiac_` for one person. The
    // roster on the held connection held four entries for that member: the
    // bare nick from our JOIN echo, two hostmask forms straddling an ident
    // change (`~Zodiac` → `~Zodiac_`), and the nick from before a 433
    // fallback, six hours stale. 353 only ever appended, so nothing could
    // remove any of them.
    stderr.writeln("\n[connection.roster] one member, one entry");

    /// Whether `roster` names `nick` (entries here carry no mode prefix).
    bool names(string[] roster, string nick) {
        foreach (e; roster) {
            const bang = e.indexOf("!");
            if ((bang > 0 ? e[0 .. bang] : e) == nick) return true;
        }
        return false;
    }

    const cloak = "@m4rrk4b62eyterscuiypip5ub6.gangnet.ru";
    string[] folded;
    foreach (e; ["Zodiac_", "Zodiac_!~Zodiac" ~ cloak, "Zodiac_!~Zodiac_" ~ cloak])
        folded = upsertRosterEntry(folded, e, "rfc1459");
    ok("every spelling of one member folds to a single entry",
        folded == ["Zodiac_!~Zodiac_" ~ cloak], "got: " ~ folded.to!string);
    ok("a bare JOIN echo does not deop a member the server gave status",
        upsertRosterEntry(["@pyylmao"], "pyylmao", "rfc1459") == ["@pyylmao"]);
    ok("a newly stated prefix is adopted and the hostmask survives",
        upsertRosterEntry(["kernelstub!~k@host"], "@kernelstub", "rfc1459")
            == ["@kernelstub!~k@host"]);
    ok("casemapping decides what counts as one member",
        upsertRosterEntry(["a[b"], "a{b", "rfc1459").length == 1
        && upsertRosterEntry(["a[b"], "a{b", "ascii").length == 2);
    ok("a trailing underscore is a different member, not a duplicate",
        upsertRosterEntry(["Zodiac"], "Zodiac_", "rfc1459").length == 2);

    string[] held;
    foreach (e; ["root!~root@cd42.gangnet.ru",
                 "Zodiac!~Zodiac@q6hg.gangnet.ru",
                 "kernelstub",
                 "Zodiac_",
                 "Zodiac_!~Zodiac" ~ cloak])
        held = upsertRosterEntry(held, e, "rfc1459");
    ok("the stale nick and the live one are two members until a resync",
        held.length == 4 && names(held, "Zodiac") && names(held, "Zodiac_"),
        "got: " ~ held.to!string);

    string[] burst;
    foreach (e; ["root!~root@cd42.gangnet.ru",
                 "kernelstub!~kernelstub@gt3t.gangnet.ru",
                 "Zodiac_!~Zodiac_" ~ cloak])
        burst = upsertRosterEntry(burst, e, "rfc1459");
    auto rebased = applyNamesBurst(held, burst);
    ok("a completed NAMES drops the member the server no longer names",
        !names(rebased, "Zodiac"), "got: " ~ rebased.to!string);
    ok("the members the server did name survive the re-baseline",
        rebased.length == 3 && names(rebased, "Zodiac_")
        && names(rebased, "root") && names(rebased, "kernelstub"),
        "got: " ~ rebased.to!string);
    ok("an empty burst never wipes a roster",
        applyNamesBurst(held, []) == held);

    // ── SASL-required refusals (irc.libera.chat, 2026-10-26) ─────────────
    // Wire text captured through the prod egresses. The engine retried the
    // gate for 11 h because it read as neither a ban nor a throttle; the
    // account-exempt K-line read as a ban and host-banned the exit for
    // every network, including ones that log in.
    stderr.writeln("\n[connection.sasl-gate] refusal classification");
    const liberaGate = "Closing Link: 2a02:6ea0:d406:3::e012 (SASL authentication to a NickServ "
        ~ "account with a verified email address is required to connect from your current network. "
        ~ "Please see https://libera.chat/guides/sasl for configuration assistance.)";
    const liberaSaslKline = "You are banned from this server- SASL authentication to a verified "
        ~ "NickServ account is required. Refer to https://libera.chat/guides/sasl and email "
        ~ "bans@libera.chat when resolved. (2026/10/26 17.02)";
    const liberaBotKline = "You are banned from this server- Your bot is not permitted to connect to "
        ~ "Libera Chat. Please email bans@libera.chat if you think this network ban was set in error. "
        ~ "(2026/10/26 17.03)";
    ok("Libera's per-network gate demands SASL", isSaslRequiredRefusal(liberaGate));
    ok("Libera's account-exempt K-line demands SASL", isSaslRequiredRefusal(liberaSaslKline));
    ok("a K-line that SASL cannot lift is not a SASL demand", !isSaslRequiredRefusal(liberaBotKline));
    ok("UnrealIRCd's require-authentication wording demands SASL",
        isSaslRequiredRefusal("You need to authenticate via SASL to use this server"));
    ok("a failed SASL login is not a SASL demand",
        !isSaslRequiredRefusal("SASL authentication failed"));
    ok("empty text is not a SASL demand", !isSaslRequiredRefusal(""));

    stderr.writeln("\n[connection.reason] server reason extraction");
    ok("a Solanum Closing Link yields its parenthesised reason",
        extractServerReason(liberaGate).length > 0
        && extractServerReason(liberaGate)[0 .. 4] == "SASL"
        && extractServerReason(liberaGate)[$ - 1] == '.',
        "got: " ~ extractServerReason(liberaGate));
    ok("a 465 ban text yields no reason, not its trailing timestamp",
        extractServerReason(liberaSaslKline) == "", "got: " ~ extractServerReason(liberaSaslKline));
    ok("an InspIRCd Closing link yields the bracketed reason, not the hostmask",
        extractServerReason("Closing link: (~u@1.2.3.4) [Registration timeout]") == "Registration timeout");
    ok("an InspIRCd quit drops the Quit: prefix",
        extractServerReason("Closing link: (~u@1.2.3.4) [Quit: bye]") == "bye");
    ok("an UnrealIRCd bracketed address keeps the parenthesised reason",
        extractServerReason("Closing Link: [1.2.3.4] (Too many unknown connections from your IP)")
            == "Too many unknown connections from your IP");
    ok("a quit reason is unwrapped", extractServerReason("Closing Link: 1.2.3.4 (Quit: bye)") == "bye");
    ok("a reason with its own parentheses stays whole",
        extractServerReason("Closing Link: host (Banned (spam))") == "Banned (spam)");

    stderr.writeln("\n[connection.sasl-mechs] offered mechanism check");
    const liberaMechs = "ECDSA-NIST256P-CHALLENGE,EXTERNAL,PLAIN,SCRAM-SHA-512";
    ok("Libera offers PLAIN", saslMechanismOffered(liberaMechs, "PLAIN"));
    ok("Libera does not offer SCRAM-SHA-256", !saslMechanismOffered(liberaMechs, "SCRAM-SHA-256"));
    ok("a prefix of an offered mechanism is not offered", !saslMechanismOffered(liberaMechs, "SCRAM-SHA"));
    ok("mechanism names compare case-insensitively", saslMechanismOffered("plain,external", "PLAIN"));
    ok("an unstated list means try it", saslMechanismOffered("", "SCRAM-SHA-256"));

    // ── FIBERMLS outbound discovery backstop (CTCP probe spam) ───────────
    // Old tabs, native clients and the msg path share one validated,
    // per-recipient queue. The wire half runs a real localhost fake ircd
    // and prints every line the client wrote to it.
    stderr.writeln("\n[connection.fibermls] outbound discovery backstop");
    foreach (check; fiberMlsBackstopChecks()) ok(check.name, check.passed);
    string[] wire;
    foreach (check; fiberMlsWireChecks(wire)) ok(check.name, check.passed);
    import std.array : replace;
    foreach (line; wire) stderr.writeln("    wire> ", line.replace("\x01", "^A"));

    // ── Engine-observed services identity (Anope UI step 1) ──────────────
    // A localhost fake ircd: the observed account comes only from server
    // statements, every socket and every attach gets a fresh epoch.
    stderr.writeln("\n[connection.services] observed account and connection epoch");
    string[] servicesWire;
    foreach (check; servicesIdentityWireChecks(servicesWire)) ok(check.name, check.passed);
    foreach (line; servicesWire) stderr.writeln("    wire> ", line);
    stderr.writeln("\n[connection.ircv3] protocol behavior");
    string[] ircv3Wire;
    foreach (check; ircv3ProtocolChecks(ircv3Wire)) ok(check.name, check.passed);
    foreach (line; ircv3Wire) stderr.writeln("    wire> ", line);
    foreach (check; silentTransportRouteChecks()) ok(check.name, check.passed);
    historySnapshotRegressionChecks();
    historyCheckpointRegressionChecks();
    runBncOwnershipProtocolChecks();
    stderr.writeln("\n[", passed, " passed, ", failed, " failed]");
    if (failed > 0) core.stdc.stdlib.exit(1);
}

import core.stdc.stdlib;