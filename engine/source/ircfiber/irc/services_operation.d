/**
 * Shared helpers for the actual-user services operation adapters (unit 3):
 * frame completeness, review revisions, fresh target identity checks,
 * capability JSON, validated parameters, and HELP metadata reads.
 *
 * HELP (`modules/help.cpp`, both releases) is live-session metadata about a
 * COMMAND, never channel authorization: `allowed` means services offered
 * this session the command's help without a denial — the command exists, is
 * not hidden from it (`hideprivilegedcommands`), and any opertype permission
 * it needs is held by the live user (`HasCommand`, which includes
 * `require_oper`). It says nothing about channel access, `HasPriv`
 * privileges or OperServ `opersonly`; operations combine it with their own
 * authoritative read.
 */
module ircfiber.irc.services_operation;

import std.algorithm : sort;
import std.array : appender, Appender;
import std.conv : to;
import std.digest : toHexString, LetterCase;
import std.digest.sha : SHA256;
import std.exception : enforce;

import vibe.data.json : Json;

import ircfiber.irc.services : ServicesTransaction, ServiceFrame, ServiceFrameSpec, ServiceFrameKind,
    ServiceFrameOutcome, ServicesEndpoint, ServicesActor, ServicesActorState, ServicesWhois, ServiceReplyLine,
    stripIrcFormatting;
import ircfiber.irc.services_grammar : AnopeGrammar, normalizeServiceText;
import ircfiber.services.config : ServiceId, SERVICE_KEYS;
import ircfiber.services.protocol : ServiceAction, ServiceStatus;

// ── HELP ───────────────────────────────────────────────────────────────────

/// What a framed `HELP <command>` proved for this live session.
struct HelpEvidence {
    /// allowed | denied | unknown | unsupported
    string state;
    string reasonCode;
    /// Opertype permission HELP named (`Access to this command requires the
    /// permission ...`), "" when the command needs none or HELP did not say.
    string permission;
}

/// HELP replies (both releases; `help.cpp`, `command.cpp`, `language.h`).
private enum HELP_SYNTAX = "Syntax";
private enum HELP_PERMISSION = "Access to this command requires the permission \x02%s\x02 to be present in your opertype.";
private enum HELP_IDENTIFY = "You need to be identified to use this command.";
private enum NICK_IDENTIFY_REQUIRED = "You must be logged into an account to use that command.";
private enum HELP_CANNOT_USE = "You cannot use this command.";
private enum HELP_NONE = "No help available for \x02%s\x02.";
private enum ACCESS_DENIED = "Access denied.";
/// Unknown HELP (help module absent): 2.1 then 2.0 forms.
private immutable string[] UNKNOWN_COMMAND = [
    "Unknown command \x02%s\x02. Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02? Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02?",
    "Unknown command \x02%s\x02.",
    "Unknown command \x02%s\x02. \"%s%s HELP\" for help.",
];

/// `HELP <command>` to the transaction's primary service.
void readServicesHelp(ServicesTransaction txn, string command, void delegate(HelpEvidence) done) {
    helpFrame(txn, txn.endpoint.service, false, command, done);
}

/// `HELP <command>` to an allowed peer service (HostServ → NickServ,
/// BotServ → ChanServ), same services server and release as the primary.
void readServicesHelpOn(ServicesTransaction txn, ServiceId peer, string command, void delegate(HelpEvidence) done) {
    helpFrame(txn, peer, peer != txn.endpoint.service, command, done);
}

private void helpFrame(ServicesTransaction txn, ServiceId service, bool peer, string command,
        void delegate(HelpEvidence) done) {
    enforce(helpCommandValid(command), "Invalid HELP command");
    // Every pseudoclient of the verified services server runs one release.
    auto grammar = new AnopeGrammar(txn.endpoint.version_);
    if (!grammar.supported) {
        done(HelpEvidence("unsupported", "unsupported_version"));
        return;
    }
    ServiceFrameSpec spec;
    spec.bodies = ["HELP " ~ command];
    spec.kind = ServiceFrameKind.ordinary;
    spec.mutating = false;
    auto handler = (ServiceFrame f) { done(classifyServicesHelp(grammar, command, f)); };
    if (peer) txn.frameOn(service, spec, handler);
    else txn.frame(spec, handler);
}

/// Command words only: `ACCESS`, `SET KEEPTOPIC`, `QUEUE` (1-4 tokens).
bool helpCommandValid(string command) @safe pure nothrow @nogc {
    if (!command.length || command.length > 64) return false;
    size_t words;
    bool inWord;
    foreach (char c; command) {
        if (c == ' ') {
            if (!inWord) return false; // leading or double space
            inWord = false;
            continue;
        }
        const ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return false;
        if (!inWord) ++words;
        inWord = true;
    }
    return inWord && words <= 4;
}

/**
 * Reads a finished HELP frame. Denials outrank help text (help.cpp prints
 * them after the command's help); only an exact `Syntax: <COMMAND>` line or
 * the opertype-permission line proves the help belongs to the command.
 */
HelpEvidence classifyServicesHelp(AnopeGrammar g, string command, const ref ServiceFrame frame) {
    if (g is null || !g.supported) return HelpEvidence("unsupported", "unsupported_version");
    if (!frameComplete(frame)) {
        if (frame.outcome == ServiceFrameOutcome.deadline) return HelpEvidence("unknown", "help_timeout");
        if (frame.outcome == ServiceFrameOutcome.unavailable && frame.reason.length)
            return HelpEvidence("unknown", frame.reason);
        return HelpEvidence("unknown", frame.truncated ? "help_truncated" : "help_incomplete");
    }
    const lines = servicePlainLines(frame);
    if (!lines.length) return HelpEvidence("unknown", "help_no_reply");

    // OperServ `opersonly` (and other OnBotPrivmsg gates) answer anything,
    // HELP included, with ACCESS_DENIED.
    if (g.has(ACCESS_DENIED, frame)) return HelpEvidence("denied", "access_denied");
    if (g.hasAny([HELP_IDENTIFY, NICK_IDENTIFY_REQUIRED], frame))
        return HelpEvidence("denied", "identification_required");
    string[] caps;
    string permission;
    if (g.matches(HELP_PERMISSION, frame, caps)) permission = caps[0];
    if (g.has(HELP_CANNOT_USE, frame)) return HelpEvidence("denied", "permission_denied", permission);
    if (g.matches(HELP_NONE, frame, caps))
        // hideprivilegedcommands hides a command the session may not use, and
        // an absent module looks the same: neither proves anything.
        return HelpEvidence("unknown", sameAsciiFold(caps[0], firstWord(command)) ? "help_unavailable" : "help_unrecognized");
    if (g.hasAny(UNKNOWN_COMMAND, frame)) return HelpEvidence("unknown", "help_unavailable");

    if (syntaxLine(g, command, lines) || permission.length) return HelpEvidence("allowed", "", permission);
    return HelpEvidence("unknown", "help_unrecognized");
}

/// `Syntax: <COMMAND>[ args]` (`Command::SendSyntax`, translated label,
/// 2.1 no-break spaces in the command name already normalised).
private bool syntaxLine(AnopeGrammar g, string command, const string[] lines) {
    foreach (label; g.variants(HELP_SYNTAX)) {
        if (g.contested(HELP_SYNTAX, label)) continue;
        foreach (l; lines) {
            if (l.length < label.length + 1 || l[0 .. label.length] != label || l[label.length] != ':') continue;
            size_t i = label.length + 1;
            if (i >= l.length || l[i] != ' ') continue;
            while (i < l.length && l[i] == ' ') ++i;
            const rest = l[i .. $];
            if (rest.length < command.length || !sameAsciiFold(rest[0 .. command.length], command)) continue;
            if (rest.length == command.length || rest[command.length] == ' ') return true;
        }
    }
    return false;
}

private string firstWord(string s) @safe pure nothrow @nogc {
    foreach (i, char c; s) if (c == ' ') return s[0 .. i];
    return s;
}

private bool sameAsciiFold(string a, string b) @safe pure nothrow @nogc {
    if (a.length != b.length) return false;
    foreach (i; 0 .. a.length) {
        char x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z') x -= 32;
        if (y >= 'a' && y <= 'z') y -= 32;
        if (x != y) return false;
    }
    return true;
}

// ── Frames ─────────────────────────────────────────────────────────────────

/// Completed between both verified fences, nothing dropped.
bool frameComplete(const ref ServiceFrame frame) @safe pure nothrow @nogc {
    return frame.outcome == ServiceFrameOutcome.completed && !frame.truncated && frame.startFenced && frame.endFenced;
}

/// Formatting-free reply lines in arrival order.
string[] servicePlainLines(const ref ServiceFrame frame) {
    string[] r;
    r.reserve(frame.lines.length);
    foreach (ref l; frame.lines) r ~= l.plain.length || !l.text.length ? l.plain : normalizeServiceText(l.text);
    return r;
}

// ── Revisions ──────────────────────────────────────────────────────────────

/**
 * Opaque review revision: SHA-256 (hex) over the canonical relevant read
 * state (object keys sorted at every level, arrays in order, undefined
 * members omitted) bound to the verified endpoint pin, the observed actor
 * and the connection epoch. Pass only the stable state the reviewed
 * effect depends on (entries, masks, levels, absolute expiry), never
 * read-time text such as "last seen", relative ages or counters, or every
 * review goes stale. Live authority/target changes are guarded at
 * dispatch by the transport's capability generation, not by this value.
 */
string servicesRevision(ServicesTransaction txn, Json canonical) {
    return servicesRevisionFor(txn.endpoint, txn.actor, txn.epoch, canonical);
}

/// ditto, from explicit bindings.
string servicesRevisionFor(const ServicesEndpoint ep, const ServicesActor actor, string epoch, Json canonical) {
    SHA256 sha;
    sha.start();
    void field(string s) {
        sha.put(cast(const(ubyte)[]) (s.length.to!string ~ ":"));
        sha.put(cast(const(ubyte)[]) s);
    }
    field("ircfiber.services.revision.v1");
    field(SERVICE_KEYS[ep.service]);
    field(ep.nick);
    field(ep.ident);
    field(ep.host);
    field(ep.server);
    field(actor.state.to!string);
    field(actor.account);
    field(epoch);
    auto text = appender!string;
    canonicalJson(canonical, text);
    field(text.data);
    const digest = sha.finish();
    return toHexString!(LetterCase.lower)(digest).idup;
}

/// The request's `expectedRevision` equals `actual`. Otherwise the request
/// completes `stale`/`revision_changed` and the caller must stop.
bool requireServicesRevision(ServicesTransaction txn, string actual) {
    if (revisionMatches(txn.request.expectedRevision, actual)) return true;
    txn.complete(ServiceStatus.stale, "revision_changed");
    return false;
}

/// ditto, handing the fresh view back so the browser can re-review it.
bool requireServicesRevision(ServicesTransaction txn, string actual, Json freshData, Json capabilities) {
    if (revisionMatches(txn.request.expectedRevision, actual)) return true;
    txn.complete(ServiceStatus.stale, "revision_changed", freshData, actual, capabilities);
    return false;
}

/// Exact, non-empty equality.
bool revisionMatches(string expected, string actual) @safe pure nothrow @nogc {
    return expected.length != 0 && expected == actual;
}

private void canonicalJson(Json j, ref Appender!string o) {
    switch (j.type) {
        default: // undefined, null
            o.put("null");
            return;
        case Json.Type.bool_:
            o.put(j.get!bool ? "true" : "false");
            return;
        case Json.Type.int_:
            o.put(j.get!long.to!string);
            return;
        case Json.Type.bigInt:
        case Json.Type.float_:
            o.put(j.toString());
            return;
        case Json.Type.string:
            jsonString(j.get!string, o);
            return;
        case Json.Type.array:
            o.put('[');
            foreach (i; 0 .. j.length) {
                if (i) o.put(',');
                canonicalJson(j[i], o);
            }
            o.put(']');
            return;
        case Json.Type.object: {
            string[] keys;
            foreach (string k, Json v; j)
                if (v.type != Json.Type.undefined) keys ~= k;
            sort(keys);
            o.put('{');
            foreach (i, k; keys) {
                if (i) o.put(',');
                jsonString(k, o);
                o.put(':');
                canonicalJson(j[k], o);
            }
            o.put('}');
            return;
        }
    }
}

private void jsonString(string s, ref Appender!string o) {
    static immutable hex = "0123456789abcdef";
    o.put('"');
    foreach (char c; s) {
        if (c == '"' || c == '\\') {
            o.put('\\');
            o.put(c);
        } else if (cast(ubyte) c < 0x20) {
            o.put("\\u00");
            o.put(hex[(c >> 4) & 0xF]);
            o.put(hex[c & 0xF]);
        } else o.put(c);
    }
    o.put('"');
}

// ── Target identity ────────────────────────────────────────────────────────

/**
 * Fresh WHOIS of `targetNick` immediately before a mutation reviewed
 * against it: the nick must be online under exactly `account` (330,
 * casemapped). Empty `targetNick` (an offline/account-addressed entry)
 * passes. A changed, absent or logged-out target completes the request
 * `stale`/`target_changed`; a WHOIS that never completed completes it
 * `unavailable`/`target_unverified`. `done(false)` then means: stop.
 */
void verifyServicesTarget(ServicesTransaction txn, string account, string targetNick, void delegate(bool) done) {
    if (!targetNick.length) {
        done(true);
        return;
    }
    if (!account.length) {
        txn.complete(ServiceStatus.stale, "target_changed");
        done(false);
        return;
    }
    txn.whois(targetNick, (ServicesWhois w) {
        if (!w.complete) {
            txn.complete(ServiceStatus.unavailable, "target_unverified");
            done(false);
            return;
        }
        if (!w.present || !w.nick.length || !txn.sameNick(w.nick, targetNick) || !w.account.length
                || !txn.sameNick(w.account, account)) {
            txn.complete(ServiceStatus.stale, "target_changed");
            done(false);
            return;
        }
        done(true);
    });
}

// ── Capabilities and parameters ────────────────────────────────────────────

/// `{state, reasonCode?}`; state is allowed | denied | unknown | unsupported.
Json serviceCapability(string state, string reasonCode = "") {
    enforce(state == "allowed" || state == "denied" || state == "unknown" || state == "unsupported",
        "Invalid services capability state");
    auto j = Json.emptyObject;
    j["state"] = state;
    if (reasonCode.length) j["reasonCode"] = reasonCode;
    return j;
}

/// Sets `capabilities[action]` (creating the object).
void putServiceCapability(ref Json capabilities, ServiceAction action, string state, string reasonCode = "") {
    if (capabilities.type != Json.Type.object) capabilities = Json.emptyObject;
    capabilities[action.to!string] = serviceCapability(state, reasonCode);
}

/// A validated request parameter as text: strings as sent, booleans
/// `true`/`false`, numbers in decimal; "" when absent.
string serviceParam(ServicesTransaction txn, string key) {
    const params = txn.request.params;
    if (params.type != Json.Type.object) return "";
    const found = key in params;
    if (found is null) return "";
    const v = *found;
    switch (v.type) {
        case Json.Type.string: return v.get!string;
        case Json.Type.bool_: return v.get!bool ? "true" : "false";
        case Json.Type.int_: return v.get!long.to!string;
        default: return "";
    }
}

// ── Regression checks (services-test) ──────────────────────────────────────

version (ServicesWireHarness) {
    /// HELP classification, frame completeness, revision and capability
    /// boundaries. `ok(name, cond)` records one named check.
    void servicesOperationChecks(scope void delegate(string, bool) ok) {
        enum V21 = "Anope-2.1.27-git build #1 -- inspircd -- enc_bcrypt";
        enum V20 = "VERSION Anope-2.0.20 services.test :inspircd3 - (enc_sha256) -- build #1";
        auto g21 = new AnopeGrammar(V21);
        auto g20 = new AnopeGrammar(V20);

        ServiceFrame frame(string[] texts...) {
            ServiceFrame f;
            f.outcome = ServiceFrameOutcome.completed;
            f.startFenced = true;
            f.endFenced = true;
            foreach (t; texts) {
                ServiceReplyLine l;
                l.command = "NOTICE";
                l.text = t;
                l.plain = stripIrcFormatting(t);
                f.lines ~= l;
            }
            return f;
        }

        auto usable = frame("Syntax: \x02ACCESS \x1Fchannel\x1F ADD \x1Fmask\x1F \x1Flevel\x1F [\x1Fdescription\x1F]\x02",
            " ", "Maintains the access list for a channel.");
        auto h = classifyServicesHelp(g21, "ACCESS", usable);
        ok("help: syntax for the command is allowed (command usable only)", h.state == "allowed" && !h.permission.length);
        h = classifyServicesHelp(g21, "access", usable);
        ok("help: command name compares case-insensitively", h.state == "allowed");
        h = classifyServicesHelp(g21, "ACC", usable);
        ok("help: another command's syntax proves nothing", h.state == "unknown" && h.reasonCode == "help_unrecognized");

        auto twoWords = frame("Syntax: \x02SET\x1BKEEPTOPIC \x1Fchannel\x1F {ON | OFF}\x02");
        ok("help: 2.1 no-break command names", classifyServicesHelp(g21, "SET KEEPTOPIC", twoWords).state == "allowed");

        auto translated = frame("Syntaxe: \x02ACCESS \x1Fcanal\x1F ADD \x1Fmasque\x1F \x1Fniveau\x1F\x02", " ", "Gère la liste d'accès.");
        ok("help: translated syntax label", classifyServicesHelp(g21, "ACCESS", translated).state == "allowed"
            && classifyServicesHelp(g20, "ACCESS", translated).state == "allowed");

        auto staff = frame("Syntax: \x02AKILL ADD [+\x1Fexpiry\x1F] \x1Fmask\x1F \x1Freason\x1F\x02", " ", "Manipulates the AKILL list.",
            " ", "Access to this command requires the permission \x02operserv/akill\x02 to be present in your opertype.");
        h = classifyServicesHelp(g21, "AKILL", staff);
        ok("help: opertype permission held is allowed with its name", h.state == "allowed" && h.permission == "operserv/akill");

        auto cannot = frame("Syntax: \x02AKILL ADD \x1Fmask\x1F \x1Freason\x1F\x02", " ",
            "Access to this command requires the permission \x02operserv/akill\x02 to be present in your opertype.",
            "You cannot use this command.");
        h = classifyServicesHelp(g20, "AKILL", cannot);
        ok("help: permission not held is denied", h.state == "denied" && h.reasonCode == "permission_denied"
            && h.permission == "operserv/akill");

        auto ident = frame("Syntax: \x02REGISTER \x1Fchannel\x1F\x02", " ", "You need to be identified to use this command.");
        h = classifyServicesHelp(g21, "REGISTER", ident);
        ok("help: unidentified session is denied", h.state == "denied" && h.reasonCode == "identification_required");
        auto identFr = frame("Vous devez être identifié(e) pour utiliser cette commande.");
        ok("help: translated identification denial (shared wording) is denied",
            classifyServicesHelp(g21, "REGISTER", identFr).reasonCode == "identification_required");

        auto hidden = frame("No help available for \x02AKILL\x02.");
        h = classifyServicesHelp(g21, "AKILL", hidden);
        ok("help: hidden privileged command is unknown, not unsupported",
            h.state == "unknown" && h.reasonCode == "help_unavailable");

        auto operOnly = frame("Access denied.");
        ok("help: opersonly ACCESS_DENIED is denied", classifyServicesHelp(g21, "STATS", operOnly).reasonCode == "access_denied");

        auto empty = frame();
        ok("help: no reply between fences is unknown", classifyServicesHelp(g21, "ACCESS", empty).reasonCode == "help_no_reply");
        auto late = usable;
        late.endFenced = false;
        late.outcome = ServiceFrameOutcome.deadline;
        ok("help: unfenced/deadline frame is unknown even with syntax text",
            classifyServicesHelp(g21, "ACCESS", late).state == "unknown");
        auto cut = usable;
        cut.truncated = true;
        ok("help: truncated frame is unknown", classifyServicesHelp(g21, "ACCESS", cut).state == "unknown");
        auto unknownText = frame("Help is temporarily unavailable, try later.");
        ok("help: unrecognised text is unknown", classifyServicesHelp(g21, "ACCESS", unknownText).state == "unknown");
        ok("help: unsupported release is unsupported",
            classifyServicesHelp(new AnopeGrammar("Anope-2.2.0"), "ACCESS", usable).state == "unsupported");
        ok("help: command words validated", helpCommandValid("SET KEEPTOPIC") && !helpCommandValid("ACCESS\r\nQUIT")
            && !helpCommandValid("") && !helpCommandValid(" ACCESS") && !helpCommandValid("A  B"));

        ok("frame: complete needs both fences, completion and no truncation",
            frameComplete(usable) && !frameComplete(late) && !frameComplete(cut));

        ServicesEndpoint ep;
        ep.service = ServiceId.chanServ;
        ep.nick = "ChanServ";
        ep.ident = "services";
        ep.host = "services.test";
        ep.server = "services.test";
        const actor = ServicesActor(ServicesActorState.account, "alice");
        enum EPOCH = "11111111-1111-4111-8111-111111111111";
        auto a = Json.emptyObject;
        a["kind"] = "channelAccess";
        a["channel"] = "#c";
        a["entries"] = Json([Json("x"), Json("y")]);
        a["note"] = Json.undefined;
        auto b = Json.emptyObject;
        b["entries"] = Json([Json("x"), Json("y")]);
        b["channel"] = "#c";
        b["kind"] = "channelAccess";
        const ra = servicesRevisionFor(ep, actor, EPOCH, a);
        ok("revision: key order and undefined members do not matter", ra == servicesRevisionFor(ep, actor, EPOCH, b));
        ok("revision: 64 lowercase hex", ra.length == 64 && revisionTokenSafe(ra));
        auto c = Json.emptyObject;
        c["kind"] = "channelAccess";
        c["channel"] = "#c";
        c["entries"] = Json([Json("y"), Json("x")]);
        ok("revision: array order matters", ra != servicesRevisionFor(ep, actor, EPOCH, c));
        ok("revision: bound to epoch", ra != servicesRevisionFor(ep, actor, "22222222-2222-4222-8222-222222222222", a));
        ok("revision: bound to actor",
            ra != servicesRevisionFor(ep, ServicesActor(ServicesActorState.account, "bob"), EPOCH, a));
        auto moved = ep;
        moved.host = "elsewhere.test";
        ok("revision: bound to endpoint pin", ra != servicesRevisionFor(moved, actor, EPOCH, a));
        ok("revision: only exact non-empty match passes",
            revisionMatches(ra, ra) && !revisionMatches("", "")
            && !revisionMatches(ra, ra[0 .. 63] ~ (ra[63] == '0' ? "1" : "0")));

        auto cap = serviceCapability("denied", "access_denied");
        bool threw;
        try serviceCapability("maybe");
        catch (Exception) threw = true;
        Json caps;
        putServiceCapability(caps, ServiceAction.channelAccessSet, "unknown", "help_unrecognized");
        ok("capability: shape and validation", cap["state"].get!string == "denied"
            && cap["reasonCode"].get!string == "access_denied" && threw
            && caps["channelAccessSet"]["state"].get!string == "unknown");
    }

    private bool revisionTokenSafe(string s) @safe pure nothrow @nogc {
        foreach (char c; s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }
}
