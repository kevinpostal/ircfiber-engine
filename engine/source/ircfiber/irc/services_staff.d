/**
 * Staff service adapters: OperServ STATS and AKILL, the HostServ request
 * queue (WAITING / ACTIVATE / REJECT) and Global (QUEUE LIST, GLOBAL).
 *
 * Every command runs as the actor's own live IRC user through
 * `ServicesTransaction`; nothing here borrows the gateway's administrative
 * RPC identity. Anope decides authority for that live user:
 *
 *  - Command permissions (`operserv/akill`, `operserv/stats`,
 *    `hostserv/set` on WAITING/ACTIVATE/REJECT, `global/global`,
 *    `global/queue`) are enforced by `Command::Run` through
 *    `CommandSource::HasCommand`, which is false unless
 *    `User::IsServicesOper()`: an `oper{}` block, plus IRC umode +o when
 *    that block has `require_oper` (default true), plus any certfp/host
 *    restriction. A website admin, a plain IRC operator without an `oper{}`
 *    block, or a successful STATS read is therefore never treated as a
 *    staff privilege for another command.
 *  - OperServ `opersonly` (operserv.cpp `OnBotPrivmsg`) refuses every
 *    OperServ line, HELP included, from a user without umode +o, even for an
 *    `oper{}` block with `require_oper = no`. Such an account can still use
 *    HostServ and Global. The gate is only visible as `Access denied.`, so
 *    OperServ capabilities need a recognised HELP *and* a recognised read.
 *  - HELP is live-session metadata (help.cpp): `allowed` only says the
 *    command is usable now; it is rechecked immediately before every
 *    mutation, and the paced write repeats the capability-generation check.
 *
 * Results are decoded with the source grammar of the two supported
 * baselines (upstream 2.0.20 and the managed 2.1 fork) and every shipped
 * translation through `AnopeGrammar`. Candidate builds additionally need
 * command-specific HELP syntax before a control can be requested. Tables
 * follow `ListFormatter`
 * (FIXED, 2.1 FLEXIBLE templates, 2.1 MONOSPACE prefix, column breaks) and
 * 2.1 `LineWrapper` continuation lines. Anything else is unrecognised and
 * answered `unconfirmed` with sanitised details, never as success.
 *
 * GLOBAL has no reply on success in either version. It is confirmed only by
 * observing, inside the frame, the verified Global pseudoclient's `$server`
 * NOTICE/PRIVMSG whose text is exactly `[<our nick>] <message>`
 * (global.cpp `SendSingle` / 2.0 `SendGlobal`). On 2.1 the actor's queue
 * must first read as recognisably empty: a non-empty or unreadable queue is
 * a conflict, and this module never sends QUEUE ADD/DEL/CLEAR or a bare
 * GLOBAL (which would send the existing queue). No command is ever retried.
 */
module ircfiber.irc.services_staff;

import std.algorithm : all, any, canFind, count, startsWith;
import std.ascii : isDigit, isUpper;
import std.conv : to;
import std.string : indexOf, replace, strip, toLower;

import vibe.data.json : Json;

import ircfiber.irc.services : ServicesOperation, ServicesTransaction, ServicesEndpoint, ServiceFrame,
    ServiceFrameSpec, ServiceFrameKind, ServiceFrameOutcome, ServiceFrameTerminal, ServiceEffect,
    registerServicesOperation;
import ircfiber.irc.services_grammar : AnopeGrammar, AnopeRelease, anopeRelease, candidateAnopeGrammar;
import ircfiber.irc.services_operation : HelpEvidence, readServicesActionHelp, frameComplete, servicesRevision,
    putServiceCapability, serviceParam;
import ircfiber.services.protocol : ServiceAction, ServiceStatus;

/// Installs the staff adapters (operStats, akill*, hostWaiting/Activate/
/// Reject, globalQueue/Send).
void registerStaffServicesOperations() {
    foreach (a; STAFF_ACTIONS) registerServicesOperation(a, new StaffOperation(a));
}

private immutable ServiceAction[] STAFF_ACTIONS = [
    ServiceAction.operStats, ServiceAction.akillList, ServiceAction.akillView, ServiceAction.akillAdd,
    ServiceAction.akillRemove, ServiceAction.hostWaiting, ServiceAction.hostActivate,
    ServiceAction.hostReject, ServiceAction.globalQueue, ServiceAction.globalSend
];

private immutable ServiceAction[] AKILL_ACTIONS = [
    ServiceAction.akillList, ServiceAction.akillView, ServiceAction.akillAdd, ServiceAction.akillRemove
];

// ── Source facts ───────────────────────────────────────────────────────────

/// 2.1 `options:linelength` default (misc.cpp `LineWrapper`).
private enum size_t ANOPE21_LINELENGTH = 100;
/// Relay budget for the Global broadcast (`:Global!u@h NOTICE $server :…`).
private enum size_t BROADCAST_LINE_LIMIT = 512;
/// Longest server name the `$server` broadcast target can carry.
private enum size_t SERVER_NAME_MAX = 63;
/// 2.1 FIXED tables pad to the English column title; the translated title
/// can be longer, leaving some widths ambiguous. Bound the search.
private enum size_t MAX_WIDTH_COMBINATIONS = 512;

// Shared replies (include/language.h, src/command.cpp).
private enum ACCESS_DENIED = "Access denied.";
private enum NICK_IDENTIFY_REQUIRED = "You must be logged into an account to use that command.";
private enum READ_ONLY_21 = "Services are temporarily in read-only mode.";
private enum READ_ONLY_20 = "Services are in read-only mode!";
private enum TRY_AGAIN_LATER_21 = "The \x02%s\x02 command is temporarily unavailable. Please try again later.";
private immutable string[] UNKNOWN_COMMAND_21 = [
    "Unknown command \x02%s\x02. Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02? Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02?",
    "Unknown command \x02%s\x02.",
];
private immutable string[] UNKNOWN_COMMAND_20 = [
    "Unknown command \x02%s\x02. \"%s%s HELP\" for help.",
    "Unknown command \x02%s\x02.",
];
/// gl_global.cpp (2.0) replies untranslated when the Global service is gone.
private enum NO_GLOBAL_20 = "No global reference, is global loaded?";

// os_akill.cpp, xline.cpp `CanAdd`, language.h.
private enum AKILL_EMPTY = "AKILL list is empty.";
private enum AKILL_NO_MATCH = "No matching entries on the AKILL list.";
private enum AKILL_LIST_START = "Current AKILL list:";
private enum AKILL_LIST_END = "End of AKILL list.";
private enum AKILL_ADDED = "\x02%s\x02 added to the AKILL list.";
private enum AKILL_DELETED = "\x02%s\x02 deleted from the AKILL list.";
private enum AKILL_NOT_FOUND = "\x02%s\x02 not found on the AKILL list.";
private enum BAD_EXPIRY_TIME = "Invalid expiry time.";
private enum BAD_USERHOST_MASK = "Mask must be in the form \x1Fuser\x1F@\x1Fhost\x1F.";
private enum USERHOST_MASK_TOO_WIDE = "%s coverage is too wide; Please use a more specific mask.";
private enum XLINE_EXISTS = "%s already exists.";
private enum XLINE_COVERED = "%s is already covered by %s.";
private enum XLINE_REMOVING = "Removing %s because %s covers it.";
private immutable string[] XLINE_UPDATED = [
    "Reason for %s updated.", "Expiry and reason updated for %s.", "Expiry for %s updated.",
];
private enum AKILL_VIEW_FLEX_ID_21 =
    "{number}: [{id}] \x02{mask}\x02 -- created by {creator} on {created}; {expires} ({reason})";
private enum AKILL_VIEW_FLEX_21 =
    "{number}: \x02{mask}\x02 -- created by {creator} on {created}; {expires} ({reason})";
private enum NO_EXPIRE = "does not expire";
private enum EXPIRES_MOMENTARILY = "expires momentarily";
private immutable string[] EXPIRES_21 = [NO_EXPIRE, EXPIRES_MOMENTARILY, "expires in %s"];
private immutable string[] EXPIRES_20 = [
    NO_EXPIRE, EXPIRES_MOMENTARILY, "expires in %d day", "expires in %d days", "expires in %d minute",
    "expires in %d minutes", "expires in %d hour, %d minute", "expires in %d hour, %d minutes",
    "expires in %d hours, %d minute", "expires in %d hours, %d minutes",
];

// os_stats.cpp.
private enum STATS_USERS_21 = "Current users: \x02%zu\x02 (\x02%zu\x02 ops)";
private enum STATS_MAX_21 = "Maximum users: \x02%zu\x02 (%s)";
private enum STATS_USERS_20 = "Current users: \x02%d\x02 (\x02%d\x02 ops)";
private enum STATS_MAX_20 = "Maximum users: \x02%d\x02 (%s)";
private enum STATS_UPTIME = "Services up %s.";
private enum STATS_XLINE_COUNT_21 = "Current number of %ss: \x02%zu\x02";
private enum STATS_XLINE_EXPIRY_21 = "Default %s expiry time: \x02%s\x02";
private enum STATS_XLINE_NEVER_21 = "Default %s expiry time: \x02No expiration\x02";
private immutable string[] XLINE_TYPES = ["AKILL", "SNLINE", "SQLINE"];

// hs_request.cpp, hostserv.cpp.
private enum HS_DISPLAYED = "Displayed \x02%d\x02 records (\x02%d\x02 total).";
private enum HS_ACTIVATED_21 = "VHost for %s has been activated.";
private enum HS_ACTIVATED_20 = "vHost for %s has been activated.";
private enum HS_REJECTED_21 = "VHost for %s has been rejected.";
private enum HS_REJECTED_20 = "vHost for %s has been rejected.";
private enum HS_NO_REQUEST = "No request for nick %s found.";
private enum HS_WAITING_FLEX_21 = "{number}: \x02{nick}\x02 = {vhost} -- created by {creator} at {created}";
/// Sent to the activated user itself (activate_on_set), so seen when staff
/// activate their own request.
private immutable string[] HS_OWN_ACTIVATED_21 = ["Your vhost of \x02%s\x02 is now activated."];
private immutable string[] HS_OWN_ACTIVATED_20 = [
    "Your vhost of \x02%s\x02@\x02%s\x02 is now activated.", "Your vhost of \x02%s\x02 is now activated.",
];

// gl_queue.cpp, modules/global/service.h (2.1 only).
private enum QUEUE_EMPTY = "You have no messages queued.";
private enum QUEUE_FLEX = "{number}: {message}";
private enum GLOBAL_QUEUE_CONFLICT = "You can not send a single message while you have messages queued.";
private enum GLOBAL_NO_MESSAGE = "You do not have any messages queued and did not specify a message to send.";

// ── Registration ───────────────────────────────────────────────────────────

private AnopeGrammar[string] grammarCache;

/// Candidate decoder only; each command still needs independent evidence.
private AnopeGrammar grammarFor(string versionText) {
    if (auto g = versionText in grammarCache) return *g;
    AnopeGrammar g;
    try g = candidateAnopeGrammar(versionText);
    catch (Exception) g = null;
    if (grammarCache.length >= 8) grammarCache = null;
    grammarCache[versionText] = g;
    return g;
}

private final class StaffOperation : ServicesOperation {
    private ServiceAction action;

    this(ServiceAction a) { action = a; }

    bool supports(const ref ServicesEndpoint endpoint) {
        auto g = grammarFor(endpoint.version_);
        return g !is null && g.supported;
    }

    void run(ServicesTransaction txn) {
        auto g = grammarFor(txn.endpoint.version_);
        if (g is null || !g.supported) {
            txn.complete(ServiceStatus.unavailable, "unsupported_version");
            return;
        }
        auto s = new Staff(txn, action, g);
        switch (action) {
            case ServiceAction.operStats: s.operStats(); break;
            case ServiceAction.akillList: s.akillRead(false); break;
            case ServiceAction.akillView: s.akillRead(true); break;
            case ServiceAction.akillAdd: s.akillAdd(); break;
            case ServiceAction.akillRemove: s.akillRemove(); break;
            case ServiceAction.hostWaiting: s.hostWaiting(); break;
            case ServiceAction.hostActivate: s.hostDecide(true); break;
            case ServiceAction.hostReject: s.hostDecide(false); break;
            case ServiceAction.globalQueue: s.globalQueue(); break;
            case ServiceAction.globalSend: s.globalSend(); break;
            default: txn.complete(ServiceStatus.unavailable, "adapter_unavailable"); break;
        }
    }
}

// ── Parsed views ───────────────────────────────────────────────────────────

/// How a read frame ended.
private enum ReadKind {
    /// Recognised, complete data.
    ok,
    /// A recognised refusal (`reason` says which).
    refused,
    /// The service answered with text this grammar does not cover.
    unrecognized,
    /// The frame did not complete between verified fences.
    incomplete
}

private struct ReadResult {
    ReadKind kind;
    string reason;
}

private struct AkillEntry {
    string number;
    string id;
    string mask;
    string creator;
    string created;
    string expires;
    string reason;
}

private struct HostRequest {
    string number;
    string nick;
    string host;
    string created;
}

private struct StatField {
    string name;
    string value;
}

// ── One staff request ──────────────────────────────────────────────────────

private final class Staff {
    private ServicesTransaction txn;
    private ServiceAction action;
    private AnopeGrammar g;
    private bool v21;
    private bool candidate;
    /// Capability generation when the request started. Every mutation is
    /// guarded by it at the paced write: an OPER/deOPER, login change, pin
    /// or epoch change after our HELP revalidation stops the command.
    private ulong reviewedGeneration;
    private Json caps;

    this(ServicesTransaction t, ServiceAction a, AnopeGrammar grammar) {
        txn = t;
        action = a;
        g = grammar;
        v21 = grammar.v21;
        candidate = anopeRelease(t.endpoint.version_) == AnopeRelease.unknown;
        reviewedGeneration = t.capabilityGeneration();
        caps = Json.emptyObject;
    }

    // ── completion ────────────────────────────────────────────────────

    private void finish(ServiceStatus status, string reason, Json data = Json.undefined,
            string revision = "", string[] details = null) {
        txn.complete(status, reason, data, revision, caps, details);
    }

    private void cap(ServiceAction a, string state, string reason = "") {
        putServiceCapability(caps, a, state, reason);
    }

    /// A read frame that did not produce data.
    private void finishRead(ReadResult r, const ref ServiceFrame f, bool withDetails = true) {
        final switch (r.kind) {
            case ReadKind.ok:
                assert(0, "finishRead on success");
            case ReadKind.refused:
                finish(refusalStatus(r.reason), r.reason, Json.undefined, "",
                    withDetails ? txn.details(f.lines) : null);
                return;
            case ReadKind.unrecognized:
                finish(ServiceStatus.unconfirmed, "unrecognized_reply", Json.undefined, "",
                    withDetails ? txn.details(f.lines) : null);
                return;
            case ReadKind.incomplete:
                finish(f.outcome == ServiceFrameOutcome.unavailable && !txn.dispatched
                    ? ServiceStatus.unavailable : ServiceStatus.unconfirmed,
                    f.reason.length ? f.reason : "frame_incomplete");
                return;
        }
    }

    // ── frames ────────────────────────────────────────────────────────

    /// False (and the request answered) once the transaction can no longer
    /// run frames: already answered, or the connection epoch is gone.
    private bool usable() {
        if (txn.live()) return true;
        finish(ServiceStatus.unavailable, "connection_lost");
        return false;
    }

    private void help(ServiceAction a, void delegate(HelpEvidence) next) {
        if (!usable()) return;
        readServicesActionHelp(txn, txn.endpoint.service, a, next);
    }

    private struct AkillHelp {
        HelpEvidence view;
        HelpEvidence add;
        HelpEvidence remove;
    }

    /// One complete AKILL HELP frame, independently classified for each
    /// form. Exact baselines keep their single generic HELP request.
    private void akillHelp(void delegate(AkillHelp) next) {
        help(ServiceAction.akillView, (HelpEvidence view) {
            if (!candidate || view.state == "unknown" || view.state == "denied") {
                next(AkillHelp(view, view, view));
                return;
            }
            help(ServiceAction.akillAdd, (HelpEvidence add) {
                help(ServiceAction.akillRemove, (HelpEvidence remove) {
                    next(AkillHelp(view, add, remove));
                });
            });
        });
    }

    private void akillCapabilities(AkillHelp h, ReadResult r) {
        cap(ServiceAction.akillList, combine(h.view, r), capReason(h.view, r));
        cap(ServiceAction.akillView, combine(h.view, r), capReason(h.view, r));
        cap(ServiceAction.akillAdd, combine(h.add, r), capReason(h.add, r));
        cap(ServiceAction.akillRemove, combine(h.remove, r), capReason(h.remove, r));
    }

    private void read(string[] bodies, void delegate(ServiceFrame) next) {
        if (!usable()) return;
        foreach (b; bodies)
            if (!txn.fits(b)) {
                finish(ServiceStatus.unavailable, "invalid_command");
                return;
            }
        ServiceFrameSpec spec;
        spec.bodies = bodies;
        spec.kind = ServiceFrameKind.ordinary;
        txn.frame(spec, next);
    }

    /// The single state-changing line. The transport rechecks the frame's
    /// generation and actor at the paced write; `preflight` adds that the
    /// generation is still the one our fresh HELP and read were taken at.
    private void mutate(string body_, ServiceFrameKind kind, ServiceFrameTerminal terminal,
            void delegate(ServiceFrame) next) {
        if (!usable()) return;
        if (txn.capabilityGeneration() != reviewedGeneration) {
            finish(ServiceStatus.stale, "capabilities_changed");
            return;
        }
        ServiceFrameSpec spec;
        spec.bodies = [body_];
        spec.kind = kind;
        spec.terminal = terminal;
        spec.mutating = true;
        auto t = txn;
        const reviewed = reviewedGeneration;
        spec.preflight = () => t.live() && t.capabilityGeneration() == reviewed;
        txn.frame(spec, next);
    }

    /// Mutations need fresh HELP evidence that the command is usable now;
    /// otherwise the reviewed capability no longer holds and nothing is sent.
    private bool requireUsable(HelpEvidence h, ServiceAction a) {
        if (h.state == "allowed") return true;
        if (!candidate && (a == ServiceAction.akillAdd || a == ServiceAction.akillRemove)) {
            // Preserve the certified baseline's command-wide refusal.
            foreach (related; AKILL_ACTIONS) cap(related, h.state, h.reasonCode);
        } else cap(a, h.state, h.reasonCode);
        finish(ServiceStatus.stale, "capabilities_changed");
        return false;
    }

    /// The exact reviewed revision, or a stale answer carrying the fresh view.
    private bool requireRevision(Json view, Json data) {
        const revision = servicesRevision(txn, view);
        if (txn.request.expectedRevision.length && txn.request.expectedRevision == revision) return true;
        finish(ServiceStatus.stale, "revision_changed", data, revision);
        return false;
    }

    // ── grammar ───────────────────────────────────────────────────────

    private bool match(string msgid, string line, out string[] captures) {
        return g.matches(msgid, line, captures);
    }

    private bool match(string msgid, string line) {
        string[] ignored;
        return g.matches(msgid, line, ignored);
    }

    private bool matchAny(const string[] msgids, string line, out string[] captures) {
        foreach (m; msgids)
            if (g.matches(m, line, captures)) return true;
        captures = null;
        return false;
    }

    private bool matchAny(const string[] msgids, string line) {
        string[] ignored;
        return matchAny(msgids, line, ignored);
    }

    /// A recognised refusal reply, as a reason code ("" when not one).
    private string refusal(string line) {
        if (match(ACCESS_DENIED, line)) return "permission_denied";
        if (match(NICK_IDENTIFY_REQUIRED, line)) return "identify_required";
        if (match(v21 ? READ_ONLY_21 : READ_ONLY_20, line)) return "read_only";
        if (matchAny(v21 ? UNKNOWN_COMMAND_21 : UNKNOWN_COMMAND_20, line)) return "command_unavailable";
        if (v21 && match(TRY_AGAIN_LATER_21, line)) return "service_unavailable";
        if (!v21 && line == NO_GLOBAL_20) return "service_unavailable";
        return "";
    }

    /// Every line of a frame is the same refusal.
    private ReadResult refusedFrame(const string[] lines) {
        if (!lines.length) return ReadResult(ReadKind.unrecognized, "no_reply");
        const first = refusal(lines[0]);
        if (!first.length) return ReadResult(ReadKind.unrecognized, "");
        foreach (l; lines[1 .. $])
            if (refusal(l) != first) return ReadResult(ReadKind.unrecognized, "");
        return ReadResult(ReadKind.refused, first);
    }

    /// Reply lines with 2.1 `LineWrapper` continuations rejoined. A line is
    /// a continuation only when the wrapper could have produced the split
    /// and it does not itself start a recognised unit: a known reply, the
    /// table header, or (for `table` frames) a numbered row — padded to the
    /// header's Number width in FIXED layout, `N:` in FLEXIBLE layout.
    private string[] logical(const ref ServiceFrame f, const string[] units, bool table, out bool lossy) {
        string[] phys;
        foreach (ref l; f.lines) phys ~= l.plain;
        lossy = false;
        // A line longer than the default proves another linelength: no
        // continuation can be inferred, the parsers validate structure.
        if (!v21 || phys.any!(p => p.length > ANOPE21_LINELENGTH)) return phys;
        string[] numberTitles;
        size_t numberWidth;
        if (table) {
            foreach (v; g.variants("Number")) if (v.length) numberTitles ~= v;
            foreach (p; phys)
                foreach (v; numberTitles) {
                    if (!p.startsWith(v)) continue;
                    size_t s;
                    while (v.length + s < p.length && p[v.length + s] == ' ') ++s;
                    // 2.1 pads to max(English title, values): exact unless
                    // a longer translated title is followed by two spaces.
                    if (s > 2) numberWidth = v.length + s - 2;
                    else if (s == 2 && v.length == "Number".length) numberWidth = v.length;
                }
        }
        bool starts(string b) {
            if (table && rowStart(b, numberWidth)) return true;
            foreach (u; units) if (match(u, b)) return true;
            foreach (v; numberTitles) if (b.startsWith(v)) return true;
            return false;
        }
        string[] out_;
        foreach (i, p; phys) {
            if (i > 0 && wrapContinues(phys[i - 1], p) && !starts(p)) {
                out_[$ - 1] ~= " " ~ p;
                continue;
            }
            // Exactly linelength with no space: the wrapper cut a word and
            // dropped one byte; the original cannot be rebuilt.
            if (i > 0 && phys[i - 1].length == ANOPE21_LINELENGTH && !starts(p)) lossy = true;
            out_ ~= p;
        }
        return out_;
    }

    // ── table parsing (misc.cpp ListFormatter) ───────────────────────

    /// FIXED layout first, then (2.1) every FLEXIBLE template.
    private bool parseTable(const string[] lines, const Column[] cols, const string[] flexTemplates,
            bool delegate(const string[]) rowValid, out string[][] rows) {
        if (parseFixed(g, v21, lines, cols, rowValid, rows)) return true;
        if (v21 && flexTemplates.length && parseFlexible(g, lines, cols, flexTemplates, rowValid, rows))
            return true;
        rows = null;
        return false;
    }

    // ── OperServ STATS ────────────────────────────────────────────────

    void operStats() {
        help(ServiceAction.operStats, (HelpEvidence h) {
            read(["STATS", "STATS AKILL"], (ServiceFrame f) {
                StatField[] fields;
                const r = parseStats(f, fields);
                cap(ServiceAction.operStats, combine(h, r), capReason(h, r));
                if (r.kind != ReadKind.ok) return finishRead(r, f);
                auto list = Json.emptyArray;
                foreach (fd; fields) list ~= Json(["name": Json(fd.name), "value": Json(fd.value)]);
                finish(ServiceStatus.confirmed, "", Json(["kind": Json("operStats"), "fields": list]));
            });
        });
    }

    private ReadResult parseStats(const ref ServiceFrame f, out StatField[] fields) {
        if (!frameComplete(f)) return ReadResult(ReadKind.incomplete, f.reason);
        bool lossy;
        auto lines = logical(f, null, false, lossy);
        if (lossy) return ReadResult(ReadKind.unrecognized, "");
        bool uptime;
        foreach (l; lines) {
            string[] c;
            if (match(v21 ? STATS_USERS_21 : STATS_USERS_20, l, c) && c.length == 2) {
                fields ~= StatField("currentUsers", c[0]);
                fields ~= StatField("currentOperators", c[1]);
                uptime = true;
            } else if (match(v21 ? STATS_MAX_21 : STATS_MAX_20, l, c) && c.length == 2) {
                fields ~= StatField("maximumUsers", c[0]);
                fields ~= StatField("maximumUsersAt", c[1]);
            } else if (match(STATS_UPTIME, l, c) && c.length == 1) {
                fields ~= StatField("uptime", c[0]);
            } else if (!xlineStat(l, fields)) {
                fields = null;
                return refusedFrame(lines);
            }
        }
        if (!uptime) {
            fields = null;
            return ReadResult(ReadKind.unrecognized, "");
        }
        return ReadResult(ReadKind.ok, "");
    }

    /// `STATS AKILL` lines (AKILL, SNLINE, SQLINE managers).
    private bool xlineStat(string l, ref StatField[] fields) {
        string[] c;
        if (v21) {
            if (match(STATS_XLINE_COUNT_21, l, c) && c.length == 2 && XLINE_TYPES.canFind(c[0])) {
                fields ~= StatField(c[0].toLower ~ "Count", c[1]);
                return true;
            }
            if (match(STATS_XLINE_NEVER_21, l, c) && c.length == 1 && XLINE_TYPES.canFind(c[0])) {
                fields ~= StatField(c[0].toLower ~ "DefaultExpiry", "never");
                return true;
            }
            if (match(STATS_XLINE_EXPIRY_21, l, c) && c.length == 2 && XLINE_TYPES.canFind(c[0])) {
                fields ~= StatField(c[0].toLower ~ "DefaultExpiry", c[1]);
                return true;
            }
            return false;
        }
        foreach (t; XLINE_TYPES) {
            const name = t.toLower;
            if (match("Current number of " ~ t ~ "s: \x02%d\x02", l, c) && c.length == 1) {
                fields ~= StatField(name ~ "Count", c[0]);
                return true;
            }
            const prefix = "Default " ~ t ~ " expiry time: \x02";
            if (match(prefix ~ "No expiration\x02", l)) {
                fields ~= StatField(name ~ "DefaultExpiry", "never");
                return true;
            }
            static immutable units = [["%d days", "d"], ["1 day", "1d"], ["%d hours", "h"], ["1 hour", "1h"],
                ["%d minutes", "m"], ["1 minute", "1m"]];
            foreach (u; units)
                if (match(prefix ~ u[0] ~ "\x02", l, c)) {
                    fields ~= StatField(name ~ "DefaultExpiry", c.length ? c[0] ~ u[1] : u[1]);
                    return true;
                }
        }
        return false;
    }

    // ── OperServ AKILL ────────────────────────────────────────────────

    /// akillList (`AKILL VIEW`) / akillView (`AKILL VIEW <entry>`).
    void akillRead(bool filtered) {
        const filter = filtered ? serviceParam(txn, "entry") : "";
        if (filtered && !akillSelectorValid(filter)) return finish(ServiceStatus.rejected, "invalid_entry");
        akillHelp((AkillHelp h) {
            read([filter.length ? "AKILL VIEW " ~ filter : "AKILL VIEW"], (ServiceFrame f) {
                AkillEntry[] entries;
                const r = parseAkillView(f, filtered, entries);
                akillCapabilities(h, r);
                if (r.kind != ReadKind.ok) return finishRead(r, f);
                finish(ServiceStatus.confirmed, "", akillData(entries, filter),
                    servicesRevision(txn, akillRevisionView(entries, filter)));
            });
        });
    }

    /// Review: akillList (unfiltered) revision.
    void akillAdd() {
        const mask = serviceParam(txn, "mask");
        const reason = serviceParam(txn, "reason");
        const p = txn.request.params;
        const expiry = p["expirySeconds"].get!long;
        const broadConfirmed = p["broadMaskConfirmed"].get!bool;
        const problem = akillMaskProblem(mask);
        if (problem.length) return finish(ServiceStatus.rejected, problem);
        if (expiry < 60 || expiry > int.max) return finish(ServiceStatus.rejected, "invalid_expiry");
        if (!reason.strip.length) return finish(ServiceStatus.rejected, "reason_required");
        if (broadAkillMask(mask) && !broadConfirmed) return finish(ServiceStatus.rejected, "broad_mask_unconfirmed");
        // Explicit seconds unit before the mask: a bare number means days
        // (os_akill.cpp DoAdd); DoTime accepts `+<n>s` in both versions.
        const body_ = "AKILL ADD +" ~ expiry.to!string ~ "s " ~ mask ~ " " ~ reason;
        if (!txn.fits(body_)) return finish(ServiceStatus.rejected, "too_long");

        akillHelp((AkillHelp h) {
            if (!requireUsable(h.add, ServiceAction.akillAdd)) return;
            read(["AKILL VIEW"], (ServiceFrame pre) {
                AkillEntry[] before;
                const r = parseAkillView(pre, false, before);
                akillCapabilities(h, r);
                if (r.kind != ReadKind.ok) return finishRead(r, pre);
                if (!requireRevision(akillRevisionView(before, ""), akillData(before, ""))) return;
                // Adding an existing mask would update its reason/expiry
                // (xline.cpp CanAdd): not the reviewed operation.
                if (before.any!(e => asciiEqual(e.mask, mask)))
                    return finish(ServiceStatus.rejected, "already_exists", akillData(before, ""),
                        servicesRevision(txn, akillRevisionView(before, "")));
                mutate(body_, ServiceFrameKind.ordinary, null, (ServiceFrame f) {
                    const outcome = akillAddVerdict(f, mask);
                    // Every covered entry the service says it removed must be
                    // gone too: the add may be partially destructive.
                    const removed = outcome.removed;
                    akillReadback(outcome.status, outcome.reason, f, (const AkillEntry[] after) =>
                        after.any!(e => asciiEqual(e.mask, mask))
                        && !after.any!(e => removed.any!(m => asciiEqual(e.mask, m))),
                        outcome.removed.dup, before, outcome.refusal);
                });
            });
        });
    }

    /// Review: akillList (unfiltered) revision; `entry` is an entry's id.
    void akillRemove() {
        const entry = serviceParam(txn, "entry");
        if (!akillSelectorValid(entry)) return finish(ServiceStatus.rejected, "invalid_entry");
        akillHelp((AkillHelp h) {
            if (!requireUsable(h.remove, ServiceAction.akillRemove)) return;
            read(["AKILL VIEW"], (ServiceFrame pre) {
                AkillEntry[] before;
                const r = parseAkillView(pre, false, before);
                akillCapabilities(h, r);
                if (r.kind != ReadKind.ok) return finishRead(r, pre);
                if (!requireRevision(akillRevisionView(before, ""), akillData(before, ""))) return;
                AkillEntry target;
                size_t found;
                foreach (e; before)
                    if (e.id == entry || asciiEqual(e.mask, entry)) {
                        target = e;
                        ++found;
                    }
                auto view = akillData(before, "");
                const rev = servicesRevision(txn, akillRevisionView(before, ""));
                if (!found) return finish(ServiceStatus.stale, "target_changed", view, rev);
                // DEL by mask removes every exact (case-insensitive) match;
                // without a unique ID the reviewed single entry is ambiguous.
                const byId = target.id.length && target.id != target.mask && !allDigits(target.id);
                const sameMask = before.count!(e => asciiEqual(e.mask, target.mask));
                if (found != 1 || (!byId && sameMask != 1))
                    return finish(ServiceStatus.rejected, "ambiguous_entry", view, rev);
                const body_ = "AKILL DEL " ~ (byId ? target.id : target.mask);
                if (!txn.fits(body_)) return finish(ServiceStatus.rejected, "too_long");
                mutate(body_, ServiceFrameKind.ordinary, null, (ServiceFrame f) {
                    string outcome;
                    const verdict = akillDelVerdict(f, target.mask, outcome);
                    akillReadback(verdict, outcome, f, (const AkillEntry[] after) =>
                        !after.any!(e => byId ? e.id == target.id : asciiEqual(e.mask, target.mask)));
                });
            });
        });
    }

    /// After an AKILL mutation: always a fresh `AKILL VIEW`, never a resend.
    /// An acknowledged change is confirmed only when the read-back shows
    /// `effect`; a refusal keeps its status and still returns fresh data.
    private void akillReadback(ServiceStatus verdict, string outcome, ServiceFrame mutation,
            bool delegate(const AkillEntry[]) effect, string[] removed = null, const AkillEntry[] before = null,
            string addRefusal = "") {
        // Nothing reached services (stale preflight, queue refusal).
        if (!txn.dispatched && mutation.outcome == ServiceFrameOutcome.unavailable)
            return finish(ServiceStatus.unavailable, mutation.reason.length ? mutation.reason : "not_sent");
        auto mutationDetails = txn.details(mutation.lines);
        read(["AKILL VIEW"], (ServiceFrame post) {
            AkillEntry[] after;
            const r = parseAkillView(post, false, after);
            const readOk = r.kind == ReadKind.ok;
            ServiceStatus status = verdict;
            string reason = outcome;
            if (verdict == ServiceStatus.confirmed && !readOk) {
                status = ServiceStatus.unconfirmed;
                reason = "readback_unavailable";
            } else if (verdict == ServiceStatus.confirmed && !effect(after)) {
                status = ServiceStatus.unconfirmed;
                reason = "readback_mismatch";
            }
            // Removal lines are part of the receipt even on success: a
            // covered ban disappearing is never a hidden side effect.
            string[] details = status == ServiceStatus.confirmed && !removed.length ? null : mutationDetails;
            Json data = readOk ? akillData(after, "") : Json(["kind": Json("akillRemovals")]);
            if (removed.length) data["removedEntries"] = removedEntries(removed, before);
            if (addRefusal.length) data["addRefusal"] = Json(addRefusal);
            if (!readOk && !removed.length) data = Json.undefined;
            finish(status, reason, data, readOk ? servicesRevision(txn, akillRevisionView(after, "")) : "",
                details);
        });
    }

    /// The reviewed entries a covering add removed (the pre-read's data when
    /// the mask was listed there, otherwise the mask the service named).
    private static Json removedEntries(const string[] masks, const AkillEntry[] before) {
        auto list = Json.emptyArray;
        foreach (m; masks) {
            bool known;
            foreach (e; before)
                if (asciiEqual(e.mask, m)) {
                    list ~= akillData([e], "")["entries"][0];
                    known = true;
                }
            if (!known) list ~= Json(["mask": Json(m)]);
        }
        return list;
    }

    private struct AddOutcome {
        ServiceStatus status;
        string reason;
        /// Masks the service removed because the new mask covers them.
        string[] removed;
        /// The service's refusal when it removed entries and then refused.
        string refusal;
    }

    /// `AKILL ADD` reply (os_akill.cpp DoAdd, xline.cpp CanAdd). CanAdd
    /// walks the list: each existing mask the new one covers with an expiry
    /// no later than the new one is deleted (`Removing X because <mask>
    /// covers it.`) before a later entry may still refuse the add, and a
    /// module may veto after the deletions. Then the add acknowledgement for
    /// exactly our mask, optionally the read-only notice. Recognised removal
    /// lines are reported in every outcome.
    private AddOutcome akillAddVerdict(const ref ServiceFrame f, string mask) {
        AddOutcome o;
        bool lossy;
        auto lines = logical(f, [AKILL_ADDED, XLINE_REMOVING, XLINE_EXISTS, XLINE_COVERED,
            v21 ? READ_ONLY_21 : READ_ONLY_20], false, lossy);
        bool added, readOnly, unknown;
        string refused;
        ServiceStatus refusedStatus;
        foreach (i, l; lines) {
            string[] c;
            if (!added && !refused.length && match(XLINE_REMOVING, l, c) && c.length == 2 && asciiEqual(c[1], mask))
                o.removed ~= c[0];
            else if (!added && !refused.length && match(AKILL_ADDED, l, c) && c.length == 1 && asciiEqual(c[0], mask))
                added = true;
            else if (added && !readOnly && match(v21 ? READ_ONLY_21 : READ_ONLY_20, l)) readOnly = true;
            else if (!added && !refused.length && i + 1 == lines.length) {
                refusedStatus = akillAddRefusal(l, mask, refused);
                if (refusedStatus != ServiceStatus.rejected && refused != "existing_entry_updated") unknown = true;
            } else unknown = true;
        }
        if (!frameComplete(f)) {
            o.status = ServiceStatus.unconfirmed;
            o.reason = f.reason.length ? f.reason : "frame_incomplete";
        } else if (lossy || unknown) {
            o.status = ServiceStatus.unconfirmed;
            o.reason = "unrecognized_reply";
        } else if (!lines.length) {
            o.status = ServiceStatus.unconfirmed;
            o.reason = "no_reply";
        } else if (added) {
            o.status = ServiceStatus.confirmed;
            o.reason = readOnly ? "services_read_only" : "";
        } else if (refused.length && o.removed.length) {
            // Covered entries are gone but the add was refused: partial.
            o.status = ServiceStatus.unconfirmed;
            o.reason = "covered_entries_removed_add_refused";
            o.refusal = refused;
        } else if (refused.length) {
            o.status = refusedStatus;
            o.reason = refused;
        } else {
            // Removals, then neither acknowledgement nor refusal (a module
            // vetoed the add after CanAdd deleted the covered entries).
            o.status = ServiceStatus.unconfirmed;
            o.reason = "covered_entries_removed_add_unacknowledged";
        }
        return o;
    }

    private ServiceStatus akillAddRefusal(string l, string mask, out string reason) {
        string[] c;
        if (match(XLINE_EXISTS, l, c) && c.length == 1 && asciiEqual(c[0], mask)) reason = "already_exists";
        else if (match(XLINE_COVERED, l, c) && c.length == 2 && asciiEqual(c[0], mask)) reason = "already_covered";
        else if (match(BAD_EXPIRY_TIME, l)) reason = "invalid_expiry";
        else if (match(BAD_USERHOST_MASK, l)) reason = "invalid_mask";
        else if (match(USERHOST_MASK_TOO_WIDE, l, c)) reason = "mask_too_wide";
        else if (matchAny(XLINE_UPDATED, l, c) && c.length == 1 && asciiEqual(c[0], mask)) {
            // An existing entry was changed instead of a new one added.
            reason = "existing_entry_updated";
            return ServiceStatus.unconfirmed;
        } else reason = refusal(l);
        if (!reason.length) {
            reason = "unrecognized_reply";
            return ServiceStatus.unconfirmed;
        }
        return ServiceStatus.rejected;
    }

    /// `AKILL DEL <id|mask>`: one deletion acknowledgement naming the
    /// reviewed entry's mask (os_akill.cpp DoDel), optionally the read-only
    /// notice.
    private ServiceStatus akillDelVerdict(const ref ServiceFrame f, string mask, out string reason) {
        if (!frameComplete(f)) {
            reason = f.reason.length ? f.reason : "frame_incomplete";
            return ServiceStatus.unconfirmed;
        }
        bool lossy;
        auto lines = logical(f, [AKILL_DELETED, AKILL_NOT_FOUND, AKILL_EMPTY,
            v21 ? READ_ONLY_21 : READ_ONLY_20], false, lossy);
        if (lossy || !lines.length) {
            reason = lines.length ? "unrecognized_reply" : "no_reply";
            return ServiceStatus.unconfirmed;
        }
        string[] c;
        if (lines.length == 1 && (match(AKILL_NOT_FOUND, lines[0]) || match(AKILL_EMPTY, lines[0]))) {
            reason = "not_found";
            return ServiceStatus.rejected;
        }
        if (match(AKILL_DELETED, lines[0], c) && c.length == 1 && asciiEqual(c[0], mask)) {
            if (lines.length == 1) {
                reason = "";
                return ServiceStatus.confirmed;
            }
            if (lines.length == 2 && match(v21 ? READ_ONLY_21 : READ_ONLY_20, lines[1])) {
                reason = "services_read_only";
                return ServiceStatus.confirmed;
            }
            reason = "unrecognized_reply";
            return ServiceStatus.unconfirmed;
        }
        if (lines.length == 1) {
            reason = refusal(lines[0]);
            if (reason.length) return ServiceStatus.rejected;
        }
        reason = "unrecognized_reply";
        return ServiceStatus.unconfirmed;
    }

    /// `AKILL VIEW [selector]` (os_akill.cpp DoView / ProcessList).
    private ReadResult parseAkillView(const ref ServiceFrame f, bool filtered, out AkillEntry[] entries) {
        if (!frameComplete(f)) return ReadResult(ReadKind.incomplete, f.reason);
        bool lossy;
        auto lines = logical(f, [AKILL_EMPTY, AKILL_NO_MATCH, AKILL_LIST_START, AKILL_LIST_END],
            true, lossy);
        if (lossy) return ReadResult(ReadKind.unrecognized, "");
        if (lines.length == 1 && (match(AKILL_EMPTY, lines[0]) || match(AKILL_NO_MATCH, lines[0])))
            return ReadResult(ReadKind.ok, "");
        if (lines.length < 3 || !match(AKILL_LIST_START, lines[0]) || !match(AKILL_LIST_END, lines[$ - 1]))
            return refusedFrame(lines);
        const table = lines[1 .. $ - 1];
        const expiresGrammar = v21 ? EXPIRES_21 : EXPIRES_20;
        bool validRow(const string[] v, bool withId) {
            // Number, Mask, Creator, Created, Expires, [ID], Reason
            if (!allDigits(v[0])) return false;
            if (v[1].canFind(' ') && !v[1].canFind('#')) return false;
            if (v[3].canFind(';') || v[4].canFind('(')) return false;
            if (!matchAny(expiresGrammar, v[4])) return false;
            if (withId && !v[5].all!(ch => isUpper(ch) || isDigit(ch))) return false;
            return true;
        }
        string[][] rows;
        bool withId = true;
        if (!parseTable(table, AKILL_VIEW_ID_COLUMNS, [AKILL_VIEW_FLEX_ID_21], v => validRow(v, true), rows)) {
            withId = false;
            if (!parseTable(table, AKILL_VIEW_COLUMNS, [AKILL_VIEW_FLEX_21], v => validRow(v, false), rows))
                return ReadResult(ReadKind.unrecognized, "");
        }
        if (!numbered(rows, !filtered)) return ReadResult(ReadKind.unrecognized, "");
        foreach (v; rows) {
            AkillEntry e;
            e.number = v[0];
            e.mask = v[1];
            e.creator = v[2];
            e.created = v[3];
            e.expires = v[4];
            e.reason = withId ? v[6] : v[5];
            const id = withId ? v[5] : "";
            e.id = id.length ? id : e.mask;
            entries ~= e;
        }
        return ReadResult(ReadKind.ok, "");
    }

    // ── HostServ request queue ────────────────────────────────────────

    void hostWaiting() {
        help(ServiceAction.hostWaiting, (HelpEvidence hw) {
            help(ServiceAction.hostActivate, (HelpEvidence ha) {
                help(ServiceAction.hostReject, (HelpEvidence hr) {
                    read(["WAITING"], (ServiceFrame f) {
                        HostRequest[] entries;
                        uint total;
                        const r = parseWaiting(f, entries, total);
                        cap(ServiceAction.hostWaiting, combine(hw, r), capReason(hw, r));
                        cap(ServiceAction.hostActivate, combine(ha, r), capReason(ha, r));
                        cap(ServiceAction.hostReject, combine(hr, r), capReason(hr, r));
                        if (r.kind != ReadKind.ok) return finishRead(r, f);
                        finish(ServiceStatus.confirmed, "", waitingData(entries, total),
                            servicesRevision(txn, waitingData(entries, total)));
                    });
                });
            });
        });
    }

    /// Review: hostWaiting revision. Approval is not activation: the
    /// acknowledgement only says the request was approved (or rejected);
    /// whether the user's live host changed is that user's own evidence.
    void hostDecide(bool activate) {
        const nick = serviceParam(txn, "nick");
        const why = activate ? "" : serviceParam(txn, "reason").strip;
        const command = activate ? "ACTIVATE" : "REJECT";
        const body_ = command ~ " " ~ nick ~ (why.length ? " " ~ why : "");
        if (!txn.fits(body_)) return finish(ServiceStatus.rejected, "too_long");
        const decisionAction = activate ? ServiceAction.hostActivate : ServiceAction.hostReject;
        help(decisionAction, (HelpEvidence h) {
            if (!requireUsable(h, decisionAction)) return;
            read(["WAITING"], (ServiceFrame pre) {
                HostRequest[] before;
                uint total;
                const r = parseWaiting(pre, before, total);
                cap(decisionAction, combine(h, r), capReason(h, r));
                if (r.kind != ReadKind.ok) return finishRead(r, pre);
                if (!requireRevision(waitingData(before, total), waitingData(before, total))) return;
                if (!before.any!(e => txn.sameNick(e.nick, nick)))
                    return finish(ServiceStatus.stale, "target_changed", waitingData(before, total),
                        servicesRevision(txn, waitingData(before, total)));
                mutate(body_, ServiceFrameKind.ordinary, null, (ServiceFrame f) {
                    string outcome;
                    const verdict = hostDecisionVerdict(f, nick, activate, outcome);
                    if (!txn.dispatched && f.outcome == ServiceFrameOutcome.unavailable)
                        return finish(ServiceStatus.unavailable, f.reason.length ? f.reason : "not_sent");
                    auto mutationDetails = txn.details(f.lines);
                    read(["WAITING"], (ServiceFrame post) {
                        HostRequest[] after;
                        uint afterTotal;
                        const pr = parseWaiting(post, after, afterTotal);
                        const readOk = pr.kind == ReadKind.ok;
                        ServiceStatus status = verdict;
                        string reason = outcome;
                        if (verdict == ServiceStatus.confirmed && !readOk) {
                            status = ServiceStatus.unconfirmed;
                            reason = "readback_unavailable";
                        } else if (verdict == ServiceStatus.confirmed && after.any!(e => txn.sameNick(e.nick, nick))) {
                            status = ServiceStatus.unconfirmed;
                            reason = "readback_mismatch";
                        }
                        string[] details = status == ServiceStatus.confirmed ? null : mutationDetails;
                        if (!readOk) return finish(status, reason, Json.undefined, "", details);
                        finish(status, reason, waitingData(after, afterTotal),
                            servicesRevision(txn, waitingData(after, afterTotal)), details);
                    });
                });
            });
        });
    }

    private ServiceStatus hostDecisionVerdict(const ref ServiceFrame f, string nick, bool activate,
            out string reason) {
        if (!frameComplete(f)) {
            reason = f.reason.length ? f.reason : "frame_incomplete";
            return ServiceStatus.unconfirmed;
        }
        const ack = activate ? (v21 ? HS_ACTIVATED_21 : HS_ACTIVATED_20) : (v21 ? HS_REJECTED_21 : HS_REJECTED_20);
        const own = v21 ? HS_OWN_ACTIVATED_21 : HS_OWN_ACTIVATED_20;
        bool lossy;
        auto lines = logical(f, [ack, HS_NO_REQUEST] ~ own, false, lossy);
        if (lossy || !lines.length) {
            reason = lines.length ? "unrecognized_reply" : "no_reply";
            return ServiceStatus.unconfirmed;
        }
        bool acked;
        foreach (l; lines) {
            string[] c;
            if (!acked && match(ack, l, c) && c.length == 1 && txn.sameNick(c[0], nick)) acked = true;
            else if (activate && txn.sameNick(nick, txn.ownNick()) && matchAny(own, l)) {}
            else if (lines.length == 1 && match(HS_NO_REQUEST, l, c)) {
                reason = "no_request";
                return ServiceStatus.rejected;
            } else if (lines.length == 1 && refusal(l).length) {
                reason = refusal(l);
                return ServiceStatus.rejected;
            } else {
                reason = "unrecognized_reply";
                return ServiceStatus.unconfirmed;
            }
        }
        reason = acked ? "" : "unrecognized_reply";
        return acked ? ServiceStatus.confirmed : ServiceStatus.unconfirmed;
    }

    /// `WAITING` (hs_request.cpp CommandHSWaiting): table, then the
    /// displayed/total line (listmax can hide entries).
    private ReadResult parseWaiting(const ref ServiceFrame f, out HostRequest[] entries, out uint total) {
        if (!frameComplete(f)) return ReadResult(ReadKind.incomplete, f.reason);
        bool lossy;
        auto lines = logical(f, [HS_DISPLAYED], true, lossy);
        if (lossy) return ReadResult(ReadKind.unrecognized, "");
        string[] c;
        if (!lines.length || !match(HS_DISPLAYED, lines[$ - 1], c) || c.length != 2) return refusedFrame(lines);
        uint displayed;
        try {
            displayed = c[0].to!uint;
            total = c[1].to!uint;
        } catch (Exception) return ReadResult(ReadKind.unrecognized, "");
        if (displayed > total) return ReadResult(ReadKind.unrecognized, "");
        const table = lines[0 .. $ - 1];
        string[][] rows;
        bool validRow(const string[] v) {
            // Number, Nick, VHost, Created [, flexible-only creator]
            return allDigits(v[0]) && !v[1].canFind(' ') && !v[2].canFind(' ')
                && (v.length < 5 || !v[4].length);
        }
        if (table.length || displayed) {
            const cols = v21 ? WAITING_COLUMNS_21 : WAITING_COLUMNS_20;
            if (!parseTable(table, cols, [HS_WAITING_FLEX_21], &validRow, rows))
                return ReadResult(ReadKind.unrecognized, "");
        }
        if (rows.length != displayed || !numbered(rows, true)) return ReadResult(ReadKind.unrecognized, "");
        foreach (v; rows) entries ~= HostRequest(v[0], v[1], v[2], v[3]);
        return ReadResult(ReadKind.ok, "");
    }

    // ── Global ────────────────────────────────────────────────────────

    void globalQueue() {
        help(ServiceAction.globalSend, (HelpEvidence hg) {
            if (!v21) {
                // 2.0.20 gl_global sends immediately; there is no queue.
                cap(ServiceAction.globalQueue, "unsupported", "no_queue_in_version");
                cap(ServiceAction.globalSend, hg.state, hg.reasonCode);
                auto view = queueData(null, true, false);
                return finish(ServiceStatus.confirmed, "", view, servicesRevision(txn, view));
            }
            help(ServiceAction.globalQueue, (HelpEvidence hq) {
                read(["QUEUE LIST"], (ServiceFrame f) {
                    string[] messages;
                    const r = parseQueue(f, messages);
                    cap(ServiceAction.globalQueue, combine(hq, r), capReason(hq, r));
                    putSendCapability(hg, r, messages, hq);
                    // Queue text is private: never echoed into details.
                    if (r.kind != ReadKind.ok) return finishRead(r, f, false);
                    auto view = queueData(messages, !messages.length, true);
                    finish(ServiceStatus.confirmed, "", view, servicesRevision(txn, view));
                });
            });
        });
    }

    private void putSendCapability(HelpEvidence hg, ReadResult queue, const string[] messages,
            HelpEvidence hq = HelpEvidence.init) {
        if (hg.state != "allowed") cap(ServiceAction.globalSend, hg.state, hg.reasonCode);
        else if (candidate && hq.state != "allowed") cap(ServiceAction.globalSend, hq.state, hq.reasonCode);
        else if (queue.kind != ReadKind.ok) cap(ServiceAction.globalSend, "unknown", "queue_unverified");
        else if (messages.length) cap(ServiceAction.globalSend, "denied", "global_queue_nonempty");
        else cap(ServiceAction.globalSend, "allowed");
    }

    /// Review: globalQueue revision (2.1: the queue recognised empty).
    void globalSend() {
        const text = serviceParam(txn, "text");
        if (!text.strip.length) return finish(ServiceStatus.rejected, "invalid_message");
        // Anope tokenises the command line on spaces, so leading, trailing or
        // repeated spaces would not survive into the broadcast we must match
        // exactly. Refuse instead of silently rewriting the reviewed text.
        if (text.strip != text || text.canFind("  ")) return finish(ServiceStatus.rejected, "noncanonical_spacing");
        const body_ = "GLOBAL " ~ text;
        const ep = txn.endpoint;
        const nick = txn.ownNick();
        // The broadcast must reach us whole to be matched exactly.
        const broadcastBytes = 1 + ep.nick.length + 1 + ep.ident.length + 1 + ep.host.length
            + " NOTICE $".length + SERVER_NAME_MAX + " :[".length + nick.length + "] ".length + text.length + 2;
        if (!txn.fits(body_) || broadcastBytes > BROADCAST_LINE_LIMIT)
            return finish(ServiceStatus.rejected, "message_too_long");

        help(ServiceAction.globalSend, (HelpEvidence hg) {
            if (!requireUsable(hg, ServiceAction.globalSend)) return;
            if (!v21) {
                auto view = queueData(null, true, false);
                if (!requireRevision(view, view)) return;
                return sendGlobal(text);
            }
            if (candidate) {
                help(ServiceAction.globalQueue, (HelpEvidence hq) {
                    readQueueForSend(text, hg, hq);
                });
            } else readQueueForSend(text, hg, HelpEvidence.init);
        });
    }

    private void readQueueForSend(string text, HelpEvidence hg, HelpEvidence hq) {
        read(["QUEUE LIST"], (ServiceFrame f) {
            string[] messages;
            const r = parseQueue(f, messages);
            if (candidate) cap(ServiceAction.globalQueue, combine(hq, r), capReason(hq, r));
            else cap(ServiceAction.globalQueue, r.kind == ReadKind.ok ? "allowed"
                : r.kind == ReadKind.refused ? refusalState(r.reason) : "unknown", r.reason);
            putSendCapability(hg, r, messages, hq);
            if (r.kind != ReadKind.ok)
                return finish(ServiceStatus.stale, "queue_unverified");
            if (candidate && !requireUsable(hq, ServiceAction.globalSend)) return;
            auto view = queueData(messages, !messages.length, true);
            if (!requireRevision(view, view)) return;
            // Never clear or send another queue; a single message is
            // only sent over a queue we just saw empty.
            if (messages.length)
                return finish(ServiceStatus.rejected, "queue_conflict", view, servicesRevision(txn, view));
            sendGlobal(text);
        });
    }

    private void sendGlobal(string text) {
        const nick = txn.ownNick();
        auto t = txn;
        bool exact(const ref ServiceEffect e) {
            return (e.command == "NOTICE" || e.command == "PRIVMSG") && e.params.length == 2
                && e.params[0].length > 1 && e.params[0][0] == '$'
                && broadcastFrom(e.params[1], nick, text, (a, b) => t.sameNick(a, b));
        }
        bool anonymous(const ref ServiceEffect e) {
            return (e.command == "NOTICE" || e.command == "PRIVMSG") && e.params.length == 2
                && e.params[0].length > 1 && e.params[0][0] == '$' && e.params[1] == text;
        }
        ServiceFrameTerminal terminal = delegate bool(const ref ServiceFrame fr) {
            if (fr.lines.length) return true;
            foreach (ref e; fr.effects) if (exact(e)) return true;
            return false;
        };
        mutate("GLOBAL " ~ text, ServiceFrameKind.observe, terminal, (ServiceFrame f) {
            auto details = privateDetails(f, text);
            if (!txn.dispatched && f.outcome == ServiceFrameOutcome.unavailable)
                return finish(ServiceStatus.unavailable, f.reason.length ? f.reason : "not_sent");
            foreach (ref e; f.effects)
                if (exact(e)) {
                    if (f.lines.length)
                        return finish(ServiceStatus.unconfirmed, "unrecognized_reply", sentData(true), "", details);
                    return finish(ServiceStatus.confirmed, "", sentData(true));
                }
            bool lossy;
            auto lines = logical(f, [GLOBAL_QUEUE_CONFLICT, GLOBAL_NO_MESSAGE], false, lossy);
            if (!lossy && lines.length == 1) {
                string reason;
                if (match(GLOBAL_QUEUE_CONFLICT, lines[0])) reason = "queue_conflict";
                else if (match(GLOBAL_NO_MESSAGE, lines[0])) reason = "invalid_message";
                else reason = refusal(lines[0]);
                if (reason.length) return finish(ServiceStatus.rejected, reason, sentData(false), "", details);
            }
            if (f.effects.any!(e => anonymous(e)))
                return finish(ServiceStatus.unconfirmed, "broadcast_actor_unverified", Json.undefined, "", details);
            finish(ServiceStatus.unconfirmed, lines.length ? "unrecognized_reply"
                : f.outcome == ServiceFrameOutcome.completed ? "broadcast_not_observed"
                : f.reason.length ? f.reason : "frame_incomplete", Json.undefined, "", details);
        });
    }

    /// Details for frames that may echo private text (the unknown-command
    /// reply repeats the whole input): lines containing it are withheld.
    private string[] privateDetails(const ref ServiceFrame f, string text) {
        import ircfiber.irc.services : stripIrcFormatting;
        const plainText = stripIrcFormatting(text);
        string[] out_;
        foreach (ref l; f.lines) {
            if ((text.length && l.text.canFind(text)) || (plainText.length && l.plain.canFind(plainText))) {
                out_ ~= "[message withheld]";
                continue;
            }
            out_ ~= txn.details([l]);
        }
        return out_;
    }

    /// `QUEUE LIST` (gl_queue.cpp DoList).
    private ReadResult parseQueue(const ref ServiceFrame f, out string[] messages) {
        if (!frameComplete(f)) return ReadResult(ReadKind.incomplete, f.reason);
        bool lossy;
        auto lines = logical(f, [QUEUE_EMPTY], true, lossy);
        if (lossy) return ReadResult(ReadKind.unrecognized, "");
        if (lines.length == 1 && match(QUEUE_EMPTY, lines[0])) return ReadResult(ReadKind.ok, "");
        auto refused = refusedFrame(lines);
        if (refused.kind == ReadKind.refused) return refused;
        string[][] rows;
        if (!parseTable(lines, QUEUE_COLUMNS, [QUEUE_FLEX], (const string[] v) => allDigits(v[0]), rows)
                || !rows.length || !numbered(rows, true))
            return ReadResult(ReadKind.unrecognized, "");
        foreach (v; rows) messages ~= v[1];
        return ReadResult(ReadKind.ok, "");
    }
}

// ── Canonical views ────────────────────────────────────────────────────────

private Json akillData(const AkillEntry[] entries, string filter) {
    auto list = Json.emptyArray;
    foreach (e; entries) {
        auto j = Json(["id": Json(e.id), "mask": Json(e.mask), "number": Json(e.number)]);
        if (e.creator.length) j["creator"] = Json(e.creator);
        if (e.created.length) j["createdAt"] = Json(e.created);
        if (e.expires.length) j["expires"] = Json(e.expires);
        if (e.reason.length) j["reason"] = Json(e.reason);
        list ~= j;
    }
    auto data = Json(["kind": Json("akills"), "entries": list]);
    if (filter.length) data["filter"] = Json(filter);
    return data;
}

/// Revision input: stable fields only. `expires` is a relative duration
/// that changes as time passes and positions shift with the list.
private Json akillRevisionView(const AkillEntry[] entries, string filter) {
    auto list = Json.emptyArray;
    foreach (e; entries)
        list ~= Json(["id": Json(e.id), "mask": Json(e.mask), "creator": Json(e.creator),
            "created": Json(e.created), "reason": Json(e.reason)]);
    return Json(["kind": Json("akills"), "filter": Json(filter), "entries": list]);
}

private Json waitingData(const HostRequest[] entries, uint total) {
    auto list = Json.emptyArray;
    foreach (e; entries) {
        auto j = Json(["nick": Json(e.nick), "host": Json(e.host), "number": Json(e.number)]);
        if (e.created.length) j["requestedAt"] = Json(e.created);
        list ~= j;
    }
    return Json(["kind": Json("hostRequests"), "entries": list, "total": Json(cast(long) total),
        "complete": Json(entries.length == total)]);
}

/// Private view only (queue text is never put in details or receipts).
private Json queueData(const string[] messages, bool empty, bool queueSupported) {
    auto list = Json.emptyArray;
    foreach (m; messages) list ~= Json(m);
    return Json(["kind": Json("globalQueue"), "messages": list, "empty": Json(empty),
        "queueSupported": Json(queueSupported)]);
}

/// No message text: receipts must not quote the broadcast.
private Json sentData(bool sent) {
    return Json(["kind": Json("announcement"), "sent": Json(sent)]);
}

// ── Capability evidence ────────────────────────────────────────────────────

/// HELP evidence plus the actual read: allowed only when both are; any
/// recognised denial wins; a missing command is unsupported.
private string combine(HelpEvidence h, ReadResult r) {
    const readState = r.kind == ReadKind.ok ? "allowed"
        : r.kind == ReadKind.refused ? refusalState(r.reason) : "unknown";
    if (h.state == "denied" || readState == "denied") return "denied";
    if (h.state == "unsupported" || readState == "unsupported") return "unsupported";
    if (h.state == "allowed" && readState == "allowed") return "allowed";
    return "unknown";
}

private string capReason(HelpEvidence h, ReadResult r) {
    if (r.kind == ReadKind.refused) return r.reason;
    if (h.state != "allowed" && h.reasonCode.length) return h.reasonCode;
    if (r.kind == ReadKind.unrecognized) return "unrecognized_reply";
    if (r.kind == ReadKind.incomplete) return "read_incomplete";
    return h.state == "allowed" ? "" : h.reasonCode;
}

private string refusalState(string reason) {
    switch (reason) {
        case "permission_denied": case "identify_required": return "denied";
        case "command_unavailable": return "unsupported";
        default: return "unknown";
    }
}

private ServiceStatus refusalStatus(string reason) {
    switch (reason) {
        case "permission_denied": case "identify_required": return ServiceStatus.rejected;
        default: return ServiceStatus.unavailable;
    }
}

// ── Pure helpers ───────────────────────────────────────────────────────────

/// Exactly `[<nick>] <text>` (global.cpp SendSingle; 2.0 SendGlobal).
private bool broadcastFrom(string line, string nick, string text, bool delegate(string, string) sameNick) {
    if (line.length < 4 || line[0] != '[') return false;
    const close = line.indexOf("] ");
    if (close <= 1) return false;
    return sameNick(line[1 .. close], nick) && line[close + 2 .. $] == text;
}

/// Whether `b` can be the rest of a 2.1 reply the `LineWrapper` split after
/// `a`: it breaks at the last space within `linelength` printable bytes and
/// drops that space, so `a` is shorter than the limit, the original was
/// longer, and `b` has no space before the limit.
package bool wrapContinues(string a, string b) @safe pure nothrow {
    enum M = ANOPE21_LINELENGTH;
    if (!a.length || a.length >= M) return false;
    if (b.length < M - a.length) return false;
    foreach (c; b[0 .. M - 1 - a.length])
        if (c == ' ') return false;
    return true;
}

/// A numbered table row: FIXED `N` padded to the Number column width when
/// the header gave it, otherwise FLEXIBLE `N: …` (never a `14:00` time) or
/// at least two spaces after the number.
private bool rowStart(string s, size_t width) @safe pure nothrow {
    size_t i;
    while (i < s.length && s[i] >= '0' && s[i] <= '9') ++i;
    if (!i || i + 1 >= s.length) return false;
    if (!width) return (s[i] == ':' || s[i] == ' ') && s[i + 1] == ' ';
    if (i > width || s.length <= width + 2) return false;
    foreach (c; s[i .. width + 2]) if (c != ' ') return false;
    return s[width + 2] != ' ';
}

private bool allDigits(string s) @safe pure nothrow {
    if (!s.length) return false;
    foreach (c; s) if (c < '0' || c > '9') return false;
    return true;
}

private bool asciiEqual(string a, string b) @safe pure nothrow {
    if (a.length != b.length) return false;
    foreach (i; 0 .. a.length) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return false;
    }
    return true;
}

/// Row numbers strictly increase; a complete list is exactly 1..n.
private bool numbered(const string[][] rows, bool consecutive) {
    ulong prev;
    foreach (i, v; rows) {
        ulong n;
        try n = v[0].to!ulong;
        catch (Exception) return false;
        if (consecutive ? n != i + 1 : n <= prev) return false;
        prev = n;
    }
    return true;
}

/// AKILL VIEW / DEL selector: an ID, an exact `user@host` mask or (VIEW
/// only, validated by the protocol) a number list. Realname masks are not
/// offered.
private bool akillSelectorValid(string s) @safe pure nothrow {
    if (!s.length || s.length > 255 || s[0] == '+' || s[0] == '/' || s[0] == ':') return false;
    foreach (c; s) if (c <= ' ' || c == 0x7f || c == '#' || c == ',') return false;
    return true;
}

/// Local AKILL ADD mask checks (os_akill.cpp DoAdd): `user@host` only; a
/// `#` switches Anope to realname parsing and a nick is resolved to a host,
/// neither of which this review shows.
package string akillMaskProblem(string mask) @safe pure nothrow {
    if (!mask.length || mask.length > 255) return "invalid_mask";
    if (mask[0] == '+' || mask[0] == '/' || mask[0] == ':') return "invalid_mask";
    ptrdiff_t at = -1;
    foreach (i, c; mask) {
        if (c <= ' ' || c == 0x7f || c == '#' || c == '!' || c == ',') return "invalid_mask";
        if (c == '@') {
            if (at >= 0) return "invalid_mask";
            at = cast(ptrdiff_t) i;
        }
    }
    if (at <= 0 || at + 1 >= cast(ptrdiff_t) mask.length) return "invalid_mask";
    bool onlyWild = true;
    foreach (c; mask)
        if (c != '/' && c != '~' && c != '@' && c != '.' && c != '*' && c != '?') onlyWild = false;
    return onlyWild ? "mask_too_wide" : "";
}

/// Masks that need an additional typed confirmation in review: a host part
/// with wildcards and fewer than two literal labels, or a short CIDR.
package bool broadAkillMask(string mask) {
    const at = mask.indexOf('@');
    if (at < 0) return true;
    const host = mask[at + 1 .. $];
    const slash = host.indexOf('/');
    if (slash >= 0) {
        int bits;
        try bits = host[slash + 1 .. $].to!int;
        catch (Exception) return true;
        return host.canFind(':') ? bits < 48 : bits < 24;
    }
    if (!host.canFind('*') && !host.canFind('?')) return false;
    size_t literal;
    size_t start;
    foreach (i; 0 .. host.length + 1) {
        if (i < host.length && host[i] != '.' && host[i] != ':') continue;
        const label = host[start .. i];
        if (label.length && !label.canFind('*') && !label.canFind('?')) ++literal;
        start = i + 1;
    }
    return literal < 2;
}

// ── Table grammar (misc.cpp ListFormatter) ────────────────────────────────

private struct Column {
    /// English source title (catalog msgid).
    string title;
    /// The value may contain spaces.
    bool spaced;
    /// The value may be empty.
    bool optional;
}

private immutable Column[] AKILL_VIEW_ID_COLUMNS = [
    Column("Number"), Column("Mask", true), Column("Creator", false, true), Column("Created", true, true),
    Column("Expires", true), Column("ID", false, true), Column("Reason", true, true),
];
private immutable Column[] AKILL_VIEW_COLUMNS = [
    Column("Number"), Column("Mask", true), Column("Creator", false, true), Column("Created", true, true),
    Column("Expires", true), Column("Reason", true, true),
];
private immutable Column[] WAITING_COLUMNS_21 = [
    Column("Number"), Column("Nick"), Column("VHost"), Column("Created", true, true),
];
private immutable Column[] WAITING_COLUMNS_20 = [
    Column("Number"), Column("Nick"), Column("Vhost"), Column("Created", true, true),
];
private immutable Column[] QUEUE_COLUMNS = [Column("Number"), Column("Message", true, true)];

private struct HeaderColumn {
    /// Header line (segment) the title is on.
    size_t seg;
    /// Translated title length in bytes.
    size_t tlen;
    /// Spaces after the title on the same line; -1 when it ends the line.
    long gap;
}

/// FIXED layout. The header gives column order, segment breaks (continued
/// lines begin with two spaces) and widths: 2.0 pads each column to
/// max(translated title, values); 2.1 to max(English title, values) and pads
/// the translated title only when shorter, so a title followed by exactly
/// two spaces leaves the width between the English and translated length.
/// Every width assignment consistent with all rows is tried; the parse must
/// be unique.
private bool parseFixed(AnopeGrammar g, bool v21, const string[] given, const Column[] cols,
        bool delegate(const string[]) rowValid, out string[][] rows) {
    // When the first column itself is a break column the formatter emits an
    // empty reply first (not sent, or a bare MONOSPACE byte in 2.1) and every
    // segment, including the first, starts with two spaces.
    string[] lines;
    foreach (l; given) if (l.length) lines ~= l;
    if (!lines.length || cols.length < 2) return false;
    size_t lead;
    string[][] variants;
    foreach (c; cols) {
        string[] vs;
        foreach (v; g.variants(c.title)) if (v.length && !vs.canFind(v)) vs ~= v;
        variants ~= vs;
    }
    HeaderColumn[][] headers;
    auto cur = new HeaderColumn[cols.length];
    void dfs(size_t col, size_t li, size_t pos) {
        if (headers.length > 8 || li >= lines.length) return;
        const line = lines[li];
        if (pos > line.length) return;
        foreach (v; variants[col]) {
            if (!line[pos .. $].startsWith(v)) continue;
            const end = pos + v.length;
            size_t s;
            while (end + s < line.length && line[end + s] == ' ') ++s;
            const eol = end + s == line.length;
            cur[col] = HeaderColumn(li, v.length, eol ? -1 : cast(long) s);
            if (col + 1 == cols.length) {
                if (eol) headers ~= cur.dup;
            } else if (eol) {
                if (li + 1 < lines.length && lines[li + 1].startsWith("  ")) dfs(col + 1, li + 1, 2);
            } else if (s >= 2) dfs(col + 1, li, end + s);
        }
    }
    dfs(0, 0, 0);
    if (!headers.length && lines[0].startsWith("  ")) {
        lead = 2;
        dfs(0, 0, 2);
    }
    if (!headers.length) return false;
    foreach (h; headers[1 .. $]) if (h != headers[0]) return false;
    const h = headers[0];
    const segs = h[$ - 1].seg + 1;
    const body_ = lines[segs .. $];
    if (body_.length % segs) return false;

    size_t[] lo, hi;
    foreach (j, c; h) {
        if (c.gap < 0) {
            lo ~= 0;
            hi ~= 0;
            continue;
        }
        const exact = c.tlen + cast(size_t) c.gap - 2;
        if (!v21 || c.gap > 2) {
            lo ~= exact;
            hi ~= exact;
            continue;
        }
        const english = cols[j].title.length;
        if (english > c.tlen) return false;
        lo ~= english;
        hi ~= c.tlen;
    }
    size_t combos = 1;
    foreach (j; 0 .. cols.length) {
        combos *= hi[j] - lo[j] + 1;
        if (combos > MAX_WIDTH_COMBINATIONS) return false;
    }
    string[][] found;
    bool haveFound;
    auto widths = lo.dup;
    foreach (n; 0 .. combos) {
        size_t rest = n;
        foreach (j; 0 .. cols.length) {
            const span = hi[j] - lo[j] + 1;
            widths[j] = lo[j] + rest % span;
            rest /= span;
        }
        string[][] parsed;
        if (!fixedRows(body_, h, cols, widths, segs, lead, rowValid, parsed)) continue;
        if (haveFound && parsed != found) return false;
        found = parsed;
        haveFound = true;
    }
    if (!haveFound) return false;
    rows = found;
    return true;
}

private bool fixedRows(const string[] body_, const HeaderColumn[] h, const Column[] cols, const size_t[] widths,
        size_t segs, size_t lead, bool delegate(const string[]) rowValid, out string[][] rows) {
    for (size_t r = 0; r < body_.length; r += segs) {
        auto vals = new string[cols.length];
        foreach (k; 0 .. segs) {
            const line = body_[r + k];
            size_t pos = k > 0 ? 2 : lead;
            if (pos && !line.startsWith("  ")) return false;
            if (k == 0 && (line.length <= pos || line[pos] == ' ')) return false;
            foreach (j; 0 .. cols.length) {
                if (h[j].seg != k) continue;
                string v;
                if (h[j].gap < 0) {
                    v = pos < line.length ? line[pos .. $] : "";
                } else {
                    const end = pos + widths[j];
                    const cut = end < line.length ? end : line.length;
                    v = pos < cut ? line[pos .. cut] : "";
                    if (end + 2 <= line.length) {
                        if (line[end .. end + 2] != "  ") return false;
                    } else if (end < line.length && line[end .. $].any!(ch => ch != ' ')) return false;
                    pos = end + 2;
                }
                v = trimSpaces(v);
                if (v.length && v[0] == ' ') return false;
                if (!cols[j].spaced && v.canFind(' ')) return false;
                if (!cols[j].optional && !v.length) return false;
                if (!utf8(v)) return false;
                vals[j] = v;
            }
        }
        if (!rowValid(vals)) return false;
        rows ~= vals;
    }
    return true;
}

/// 2.1 FLEXIBLE rows: each line is one translated template with `{key}`
/// placeholders (`Anope::Template`: lower-cased column title, spaces as
/// underscores; `{}` escapes `{`; an unknown key expands to nothing). A
/// row must have exactly one valid reading. Values for keys that are not
/// columns are appended after the columns, in template order.
private bool parseFlexible(AnopeGrammar g, const string[] lines, const Column[] cols,
        const string[] templates, bool delegate(const string[]) rowValid, out string[][] rows) {
    if (!lines.length) return false;
    string[] keys;
    foreach (c; cols) keys ~= c.title.toLower.replace(" ", "_");
    Tok[][] forms;
    foreach (t; templates)
        foreach (v; g.variants(t)) {
            auto toks = templateTokens(v);
            if (toks.length && !forms.canFind(toks)) forms ~= toks;
        }
    foreach (line; lines) {
        string[][] readings;
        foreach (toks; forms) {
            string[string][] sols;
            string[string] cur;
            templateMatch(toks, 0, line, 0, cur, sols);
            foreach (sol; sols) {
                auto vals = new string[cols.length];
                foreach (j, k; keys) {
                    if (auto p = k in sol) vals[j] = *p;
                }
                foreach (t; toks)
                    if (t.key && !keys.canFind(t.text)) vals ~= sol[t.text];
                bool ok = true;
                foreach (j; 0 .. cols.length) {
                    const v = vals[j];
                    if ((!cols[j].spaced && v.canFind(' ')) || (!cols[j].optional && !v.length) || !utf8(v)) ok = false;
                }
                if (ok && rowValid(vals) && !readings.canFind(vals)) readings ~= vals;
            }
        }
        if (readings.length != 1) return false;
        rows ~= readings[0];
    }
    return true;
}

private struct Tok {
    bool key;
    string text;
}

private Tok[] templateTokens(string t) {
    Tok[] out_;
    string lit;
    for (size_t i = 0; i < t.length; ++i) {
        if (t[i] != '{') {
            lit ~= t[i];
            continue;
        }
        const close = t[i + 1 .. $].indexOf('}');
        if (close < 0) continue;
        if (close == 0) {
            lit ~= '{';
            i += 1;
            continue;
        }
        if (lit.length) out_ ~= Tok(false, lit);
        lit = null;
        out_ ~= Tok(true, t[i + 1 .. i + 1 + close].strip);
        i += close + 1;
    }
    if (lit.length) out_ ~= Tok(false, lit);
    return out_;
}

private void templateMatch(const Tok[] toks, size_t ti, string line, size_t pos, ref string[string] cur,
        ref string[string][] sols) {
    if (sols.length >= 4) return;
    if (ti == toks.length) {
        if (pos == line.length) sols ~= cur.dup;
        return;
    }
    const t = toks[ti];
    if (!t.key) {
        if (line[pos .. $].startsWith(t.text)) templateMatch(toks, ti + 1, line, pos + t.text.length, cur, sols);
        return;
    }
    void take(size_t end) {
        const v = line[pos .. end];
        auto prev = t.text in cur;
        if (prev !is null && *prev != v) return;
        const had = prev !is null;
        cur[t.text] = v;
        templateMatch(toks, ti + 1, line, end, cur, sols);
        if (!had) cur.remove(t.text);
    }
    if (ti + 1 == toks.length) return take(line.length);
    const next = toks[ti + 1];
    if (!next.key) {
        for (size_t q = pos; q + next.text.length <= line.length; ++q)
            if (line[q .. q + next.text.length] == next.text) take(q);
    } else {
        for (size_t q = pos; q <= line.length; ++q) take(q);
    }
}

private string trimSpaces(string s) @safe pure nothrow {
    while (s.length && s[$ - 1] == ' ') s = s[0 .. $ - 1];
    return s;
}

private bool utf8(string s) {
    import std.utf : validate;
    try validate(s);
    catch (Exception) return false;
    return true;
}

// ── Module behaviour regression checks (services-test runner) ──────────────

version (ServicesWireHarness) {
    import std.algorithm : sort;
    import std.uni : icmp;
    import std.uuid : randomUUID;
    import vibe.data.json : parseJsonString;
    import ircfiber.irc.parser : parseIRCLineNamed;
    import ircfiber.irc.services : ServicesTransport, ServicesHost, ServicesActor, ServicesActorState,
        clearServicesOperations;
    import ircfiber.services.config : ServicesConfig, managedServicesConfig;
    import ircfiber.services.protocol : ServicesRequest, ServicesResult;

    private enum STAFF_NET = "33333333-3333-4333-8333-333333333333";
    /// CTCP VERSION bodies as each baseline formats them (bots.cpp 2.1,
    /// messages.cpp 2.0.20), after the `VERSION ` keyword.
    private enum STAFF_V21 = "Anope-2.1.27-git f6e46425 -- inspircd -- enc_bcrypt";
    private enum STAFF_V20 = "Anope-2.0.20 services.test :inspircd3 - (enc_bcrypt) -- build #1";

    private final class StaffHost : ServicesHost {
        long now = 1_700_000_000_000;
        string epoch = "44444444-4444-4444-8444-444444444444";
        string nick = "me";
        ServicesActor who = ServicesActor(ServicesActorState.account, "staff");
        ServicesConfig cfg;
        string[] written;
        ServicesTransport t;

        long nowMs() { return now; }
        string liveEpoch() { return epoch; }
        bool hasCapability(string) { return false; }
        string capabilityValue(string) { return ""; }
        string socketIdentity() { return "staff-socket"; }
        string ownNick() { return nick; }
        bool isOwnNick(string n) { return icmp(n, nick) == 0; }
        bool sameNick(string a, string b) { return icmp(a, b) == 0; }
        ServicesActor actor() { return who; }
        ServicesConfig servicesConfig() { return cfg; }
        string isupport(string) { return ""; }
        size_t lineLimit() { return 512; }
        size_t ownPrefixBytes() { return 30; }
        bool manualLinePending(string) { return false; }
        void wake() {
            for (;;) {
                auto l = t.nextWrite();
                if (!l.length) break;
                t.popWrite();
                written ~= l;
            }
        }
        void markerChanged() {}
        void adoptOwnAccount(string a) { who = ServicesActor(ServicesActorState.account, a); }
        bool ownChannelStatus(string, out string p) { p = ""; return false; }
    }

    /// A scripted Anope: answers WHOIS/VERSION pins, echoes CTCP PING
    /// fences, and replies to each command body from a per-body queue (the
    /// last entry repeats). Lines starting with ':' are fed raw (broadcasts,
    /// MODE changes); others come from the addressed pseudoclient.
    private final class FakeAnope {
        StaffHost host;
        string versionText;
        bool privmsg;
        string[][][string] replies;
        string[] bodies;
        size_t seen;

        void reply(string body_, string[][] queue...) { replies[body_] = queue.dup; }

        void feed(string raw) {
            auto ev = parseIRCLineNamed(raw, "net", STAFF_NET);
            host.t.intercept(ev, false);
        }

        void pump() {
            while (seen < host.written.length) handle(host.written[seen++]);
        }

        private void handle(string line) {
            if (line.startsWith("WHOIS ")) {
                const n = line[6 .. $];
                feed(":s 311 me " ~ n ~ " services services.test * :Services");
                feed(":s 312 me " ~ n ~ " services.test :Anope");
                feed(":s 318 me " ~ n ~ " :End of /WHOIS list.");
                feed(":" ~ n ~ "!services@services.test NOTICE me :\x01VERSION " ~ versionText ~ "\x01");
                return;
            }
            if (!line.startsWith("PRIVMSG ")) return;
            const sp = line.indexOf(" :");
            if (sp < 0) return;
            const target = line[8 .. sp];
            const at = target.indexOf('@');
            const svc = at > 0 ? target[0 .. at] : target;
            const text = line[sp + 2 .. $];
            const from = ":" ~ svc ~ "!services@services.test ";
            if (text.startsWith("\x01PING ")) {
                feed(from ~ "NOTICE me :" ~ text);
                return;
            }
            if (text.startsWith("\x01")) return;
            bodies ~= text;
            if (auto q = text in replies) {
                if (!(*q).length) return;
                auto lines = (*q)[0];
                if ((*q).length > 1) *q = (*q)[1 .. $];
                foreach (l; lines)
                    feed(l.startsWith(":") ? l : from ~ (privmsg ? "PRIVMSG" : "NOTICE") ~ " me :" ~ l);
            }
        }
    }

    private struct StaffRig {
        StaffHost host;
        FakeAnope anope;
        ServicesResult[] results;

        static StaffRig make(string versionText) {
            StaffRig r;
            r.host = new StaffHost;
            r.host.cfg = managedServicesConfig("services.test");
            r.host.t = new ServicesTransport(r.host);
            r.anope = new FakeAnope;
            r.anope.host = r.host;
            r.anope.versionText = versionText;
            return r;
        }

        ServicesResult run(ServiceAction action, string params, string revision = "") {
            auto j = parseJsonString(`{"params":` ~ params ~ `}`);
            j["requestId"] = randomUUID().toString();
            j["action"] = action.to!string;
            j["expectedConnectionEpoch"] = host.epoch;
            j["expectedActorAccount"] = host.who.account;
            if (revision.length) j["expectedRevision"] = revision;
            auto req = ServicesRequest.fromJson(j);
            const before = results.length;
            auto self = &this;
            host.t.execute(req, (ServicesResult r) { self.results ~= r; });
            anope.pump();
            if (results.length == before) return ServicesResult.init;
            return results[$ - 1];
        }

        /// Let a lingering frame reach its deadline.
        ServicesResult expire(long ms) {
            host.now += ms;
            host.t.tick();
            anope.pump();
            return results.length ? results[$ - 1] : ServicesResult.init;
        }
    }

    private string capState(const ServicesResult r, string action) {
        if (r.capabilities.type != Json.Type.object) return "";
        auto c = r.capabilities[action];
        if (c.type != Json.Type.object) return "";
        return c["state"].get!string;
    }

    private bool answered(const ServicesResult r, ServiceStatus status, string reason = null) {
        return r.requestId.length && r.status == status && (reason is null || r.reasonCode == reason);
    }

    private string[] helpOk(string syntax, string permission) {
        return ["Syntax: \x02" ~ syntax ~ "\x02", " ", "Staff command.", " ",
            "Access to this command requires the permission \x02" ~ permission
            ~ "\x02 to be present in your opertype."];
    }

    private string[] helpCannot(string syntax, string permission) {
        return helpOk(syntax, permission) ~ ["You cannot use this command."];
    }

    private string[] helpHidden(string command) {
        return ["No help available for \x02" ~ command ~ "\x02."];
    }

    /// FIXED rendering as ListFormatter does it: 2.1 pads to the English
    /// title and breaks after more than 100 cumulative bytes (2.0: the
    /// translated title, 80), columns visited in sorted English order; 2.1
    /// then wraps every reply longer than 100 bytes at its last space.
    private string[] renderFixed(bool v21, string[] english, string[] titles, string[][] rows) {
        size_t[string] lengths;
        foreach (i, e; english) lengths[e] = v21 ? e.length : titles[i].length;
        foreach (r; rows) foreach (i, e; english) if (r[i].length > lengths[e]) lengths[e] = r[i].length;
        auto keys = english.dup;
        keys.sort();
        bool[string] breaks;
        size_t total;
        foreach (k; keys) {
            if (total > (v21 ? 100 : 80)) {
                breaks[k] = true;
                total = 0;
            } else total += lengths[k];
        }
        string[] out_;
        void emit(string[] cells) {
            string s;
            foreach (i, e; english) {
                if (e in breaks) {
                    if (s.length) out_ ~= s; // Reply("") sends nothing
                    s = "  ";
                } else if (s.length) s ~= "  ";
                s ~= cells[i];
                if (i + 1 != english.length)
                    foreach (_; cells[i].length .. lengths[e]) s ~= ' ';
            }
            out_ ~= s;
        }
        emit(titles);
        foreach (r; rows) emit(r);
        return v21 ? wrap21(out_) : out_;
    }

    private string[] wrap21(string[] lines) {
        string[] out_;
        foreach (l; lines) {
            string t = l;
            while (t.length > 100) {
                ptrdiff_t sp = -1;
                foreach (i; 0 .. 100) if (t[i] == ' ') sp = i;
                if (sp <= 0) {
                    out_ ~= t[0 .. 100];
                    t = t[101 .. $];
                    continue;
                }
                out_ ~= t[0 .. sp];
                t = t[sp + 1 .. $];
            }
            out_ ~= t;
        }
        return out_;
    }

    private immutable string[] VIEW_ID_TITLES = ["Number", "Mask", "Creator", "Created", "Expires", "ID", "Reason"];

    private string[] akillView21(string[][] rows) {
        return ["Current AKILL list:"] ~ renderFixed(true, VIEW_ID_TITLES.dup, VIEW_ID_TITLES.dup, rows)
            ~ ["End of AKILL list."];
    }

    private string[][] twoAkills() {
        return [
            ["1", "*@203.0.113.7", "me", "Thu Nov  6 14:00:00 2026", "expires in 29 days, 23 hours", "AB12CD34EF",
                "[me] spam bot"],
            ["2", "baduser@*.bad.example", "oper2", "Thu Nov  6 15:30:00 2026", "does not expire", "Z9Y8X7W6V5",
                "[oper2] repeated flooding of #help over several hours (see ticket 41)"],
        ];
    }

    /// Runs every staff adapter scenario; `ok(name, passed)` records each.
    void staffServicesChecks(void delegate(string, bool) ok) {
        clearServicesOperations();
        registerStaffServicesOperations();
        scope (exit) clearServicesOperations();

        // ── pure source rules ─────────────────────────────────────────
        ok("staff: AKILL masks are user@host only, never realname/nick/regex/expiry-looking",
            akillMaskProblem("*@203.0.113.7") == "" && akillMaskProblem("*@* #real name") == "invalid_mask"
            && akillMaskProblem("nick!*@host") == "invalid_mask" && akillMaskProblem("+1d@host") == "invalid_mask"
            && akillMaskProblem("/re/") == "invalid_mask" && akillMaskProblem("*@*") == "mask_too_wide");
        ok("staff: broad masks need typed confirmation, specific ones do not",
            broadAkillMask("*@*.com") && broadAkillMask("*@10.0.0.0/8") && !broadAkillMask("*@*.bad.example")
            && !broadAkillMask("bob@203.0.113.7") && !broadAkillMask("*@203.0.113.0/24"));
        ok("staff: 2.1 LineWrapper continuation is recognised only where the wrapper could split",
            wrapContinues("a".replicateStr(95), "bcdef rest") && !wrapContinues("a".replicateStr(95), "bc def")
            && !wrapContinues("short line", "next line"));

        // Candidate compatibility is intersected per command, never per
        // shared permission or HELP query. These exercise real adapters.
        enum candidate21 = "Anope-2.1.27-git (1947276) build #1, compiled Mon Sep 28 2026 08:19:33 UTC, flags DG -- InspIRCd 4+ -- enc_sha2";
        {
            auto r = StaffRig.make(candidate21);
            r.anope.reply("HELP AKILL",
                helpOk("AKILL ADD [+expiry] mask reason", "operserv/akill")
                    ~ ["Syntax: AKILL VIEW [mask | list | id]"]);
            r.anope.reply("AKILL VIEW", ["AKILL list is empty."]);
            auto list = r.run(ServiceAction.akillList, `{}`);
            ok("staff: candidate AKILL ADD and VIEW do not prove DEL from the same HELP frame",
                answered(list, ServiceStatus.confirmed) && list.data["entries"].length == 0
                && capState(list, "akillList") == "allowed" && capState(list, "akillView") == "allowed"
                && capState(list, "akillAdd") == "allowed" && capState(list, "akillRemove") == "unsupported"
                && r.anope.bodies.count!(b => b == "HELP AKILL") == 1);
            auto del = r.run(ServiceAction.akillRemove, `{"entry":"AB12CD34EF"}`, list.revision);
            ok("staff: a candidate direct DEL cannot borrow compatible ADD permission or syntax",
                answered(del, ServiceStatus.stale, "capabilities_changed")
                && !r.anope.bodies.any!(b => b.startsWith("AKILL DEL")));
            auto added = akillView21([["1", "*@198.51.100.9", "me", "Thu Nov  6 16:00:00 2026",
                "expires in 59 minutes", "QW12ER34TY", "[me] drone"]]);
            r.anope.reply("AKILL VIEW", ["AKILL list is empty."], added);
            r.anope.reply("AKILL ADD +3600s *@198.51.100.9 drone", ["\x02*@198.51.100.9\x02 added to the AKILL list."]);
            auto add = r.run(ServiceAction.akillAdd,
                `{"mask":"*@198.51.100.9","expirySeconds":3600,"reason":"drone","broadMaskConfirmed":false}`,
                list.revision);
            ok("staff: candidate exact ADD syntax permits one reviewed write with acknowledgement and read-back",
                answered(add, ServiceStatus.confirmed) && add.data["entries"].length == 1
                && r.anope.bodies.count!(b => b == "AKILL ADD +3600s *@198.51.100.9 drone") == 1
                && capState(add, "akillRemove") == "unsupported"
                && r.anope.bodies.count!(b => b == "HELP AKILL") == 3);
        }
        {
            auto r = StaffRig.make(candidate21);
            r.anope.reply("HELP WAITING", helpOk("WAITING", "hostserv/set"));
            r.anope.reply("HELP ACTIVATE", helpOk("ACTIVATE [nick]", "hostserv/set"));
            r.anope.reply("HELP REJECT", helpOk("REJECT nick [reason]", "hostserv/set"));
            r.anope.reply("WAITING", ["Displayed \x020\x02 records (\x020\x02 total)."]);
            auto w = r.run(ServiceAction.hostWaiting, `{}`);
            ok("staff: candidate WAITING and REJECT syntax do not prove incompatible ACTIVATE arguments",
                answered(w, ServiceStatus.confirmed) && capState(w, "hostWaiting") == "allowed"
                && capState(w, "hostReject") == "allowed" && capState(w, "hostActivate") == "unsupported");
            auto a = r.run(ServiceAction.hostActivate, `{"nick":"alice"}`, w.revision);
            ok("staff: a candidate direct ACTIVATE needs its exact nick syntax before any write",
                answered(a, ServiceStatus.stale, "capabilities_changed")
                && !r.anope.bodies.canFind("ACTIVATE alice"));
        }
        {
            auto r = StaffRig.make(candidate21);
            r.anope.reply("HELP GLOBAL", helpOk("GLOBAL [message]", "global/global"));
            r.anope.reply("HELP QUEUE", helpOk("QUEUE LIST [message]", "global/queue"));
            r.anope.reply("QUEUE LIST", ["You have no messages queued."]);
            auto q = r.run(ServiceAction.globalQueue, `{}`);
            ok("staff: candidate GLOBAL syntax alone cannot authorize sending over an incompatible QUEUE",
                answered(q, ServiceStatus.confirmed) && q.data["empty"].get!bool
                && capState(q, "globalQueue") == "unsupported" && capState(q, "globalSend") == "unsupported");
            auto blocked = r.run(ServiceAction.globalSend, `{"text":"Never broadcast this"}`, q.revision);
            ok("staff: a candidate direct GLOBAL with incompatible QUEUE HELP never broadcasts or changes the queue",
                answered(blocked, ServiceStatus.stale, "capabilities_changed")
                && !r.anope.bodies.any!(b => b.startsWith("GLOBAL ") || b == "GLOBAL"
                    || b.startsWith("QUEUE ADD") || b.startsWith("QUEUE DEL") || b.startsWith("QUEUE CLEAR")));
            r.anope.reply("HELP QUEUE", helpOk("QUEUE LIST", "global/queue"));
            auto compatible = r.run(ServiceAction.globalQueue, `{}`);
            ok("staff: candidate separate compatible GLOBAL and QUEUE syntax plus empty state enables sending",
                answered(compatible, ServiceStatus.confirmed)
                && capState(compatible, "globalQueue") == "allowed" && capState(compatible, "globalSend") == "allowed");
            r.anope.reply("HELP GLOBAL", helpOk("GLOBAL message", "global/global"));
            auto wrongGlobal = r.run(ServiceAction.globalQueue, `{}`);
            ok("staff: candidate compatible QUEUE does not prove the wrong GLOBAL argument form",
                answered(wrongGlobal, ServiceStatus.confirmed)
                && capState(wrongGlobal, "globalQueue") == "allowed" && capState(wrongGlobal, "globalSend") == "unsupported");
        }
        {
            auto r = StaffRig.make("Anope-2.0.21 services.test :inspircd3 - (enc_bcrypt) -- build #2");
            r.anope.reply("HELP GLOBAL", helpOk("GLOBAL message", "global/global"));
            auto q = r.run(ServiceAction.globalQueue, `{}`);
            ok("staff: candidate 2.0 keeps the immediate-send model without any QUEUE probe",
                answered(q, ServiceStatus.confirmed) && !q.data["queueSupported"].get!bool
                && capState(q, "globalSend") == "allowed" && capState(q, "globalQueue") == "unsupported"
                && !r.anope.bodies.any!(b => b.startsWith("HELP QUEUE") || b.startsWith("QUEUE")));
            r.anope.reply("GLOBAL Hello all", [":Global!services@services.test PRIVMSG $*.test :[me] Hello all"]);
            auto sent = r.run(ServiceAction.globalSend, `{"text":"Hello all"}`, q.revision);
            ok("staff: compatible candidate 2.0 sends exactly the reviewed announcement once",
                answered(sent, ServiceStatus.confirmed)
                && r.anope.bodies.count!(b => b == "GLOBAL Hello all") == 1);
        }

        // ── OperServ STATS, require_oper staff with +o (2.1) ──────────
        {
            auto r = StaffRig.make(STAFF_V21);
            r.anope.reply("HELP STATS", helpOk("STATS [AKILL | HASH | PASSWORD | UPLINK | UPTIME | ALL | RESET]",
                "operserv/stats"));
            r.anope.reply("STATS", ["Current users: \x0212\x02 (\x022\x02 ops)",
                "Maximum users: \x0240\x02 (Thu Nov  6 10:00:00 2026)", "Services up 3 days, 2 hours."]);
            r.anope.reply("STATS AKILL", ["Current number of AKILLs: \x022\x02",
                "Default AKILL expiry time: \x0230 days\x02", "Current number of SNLINEs: \x020\x02",
                "Default SNLINE expiry time: \x02No expiration\x02"]);
            auto res = r.run(ServiceAction.operStats, `{}`);
            bool field(string name, string value) {
                if (res.data.type != Json.Type.object) return false;
                foreach (f; res.data["fields"]) if (f["name"].get!string == name) return f["value"].get!string == value;
                return false;
            }
            ok("staff: STATS is read over OperServ@server as the live user and parsed from source grammar",
                answered(res, ServiceStatus.confirmed) && field("currentUsers", "12") && field("currentOperators", "2")
                && field("akillCount", "2") && field("snlineDefaultExpiry", "never")
                && capState(res, "operStats") == "allowed");
            ok("staff: a STATS success grants no other staff capability",
                capState(res, "akillAdd") == "" && capState(res, "globalSend") == "");
        }

        // ── require_oper = no staff without +o: opersonly blocks OperServ,
        //    HostServ still works (both by Anope's own answers) ─────────
        {
            auto r = StaffRig.make(STAFF_V21);
            foreach (b; ["HELP STATS", "STATS", "STATS AKILL"]) r.anope.reply(b, ["Access denied."]);
            auto res = r.run(ServiceAction.operStats, `{}`);
            ok("staff: OperServ opersonly Access denied is a native denial, capability denied",
                answered(res, ServiceStatus.rejected, "permission_denied") && capState(res, "operStats") == "denied");
            r.anope.reply("HELP WAITING", helpOk("WAITING", "hostserv/set"));
            r.anope.reply("HELP ACTIVATE", helpOk("ACTIVATE nick", "hostserv/set"));
            r.anope.reply("HELP REJECT", helpOk("REJECT nick [reason]", "hostserv/set"));
            r.anope.reply("WAITING", renderFixed(true, ["Number", "Nick", "VHost", "Created"],
                ["Number", "Nick", "VHost", "Created"], [["1", "alice", "alice.users.example", "Thu Nov  6 09:00:00 2026"]])
                ~ ["Displayed \x021\x02 records (\x021\x02 total)."]);
            auto w = r.run(ServiceAction.hostWaiting, `{}`);
            ok("staff: the same require_oper=no account reads the HostServ queue",
                answered(w, ServiceStatus.confirmed) && w.data["entries"].length == 1
                && w.data["entries"][0]["nick"].get!string == "alice"
                && w.data["entries"][0]["host"].get!string == "alice.users.example"
                && capState(w, "hostActivate") == "allowed" && capState(w, "hostReject") == "allowed");
        }

        // ── require_oper = yes staff without +o on HostServ ───────────
        {
            auto r = StaffRig.make(STAFF_V21);
            r.anope.reply("HELP WAITING", helpCannot("WAITING", "hostserv/set"));
            r.anope.reply("HELP ACTIVATE", helpCannot("ACTIVATE nick", "hostserv/set"));
            r.anope.reply("HELP REJECT", helpCannot("REJECT nick [reason]", "hostserv/set"));
            r.anope.reply("WAITING", ["Access denied."]);
            auto w = r.run(ServiceAction.hostWaiting, `{}`);
            ok("staff: require_oper=yes without +o is denied by HELP and by the read",
                answered(w, ServiceStatus.rejected, "permission_denied") && capState(w, "hostWaiting") == "denied"
                && capState(w, "hostActivate") == "denied");
            auto a = r.run(ServiceAction.hostActivate, `{"nick":"alice"}`, "rev");
            ok("staff: a crafted ACTIVATE without usable HELP never reaches HostServ",
                answered(a, ServiceStatus.stale, "capabilities_changed") && !r.anope.bodies.canFind("ACTIVATE alice"));
        }

        // ── ordinary IRC operator without an oper{} block ─────────────
        {
            auto r = StaffRig.make(STAFF_V21);
            r.anope.reply("HELP AKILL", helpHidden("AKILL"));
            r.anope.reply("AKILL VIEW", ["Access denied."]);
            auto res = r.run(ServiceAction.akillList, `{}`);
            ok("staff: +o alone is not services authority (hidden HELP, Access denied)",
                answered(res, ServiceStatus.rejected, "permission_denied") && capState(res, "akillAdd") == "denied"
                && capState(res, "akillRemove") == "denied");
            auto add = r.run(ServiceAction.akillAdd,
                `{"mask":"*@198.51.100.9","expirySeconds":3600,"reason":"drone","broadMaskConfirmed":false}`, "rev");
            ok("staff: a crafted AKILL ADD from an ordinary oper sends no ADD",
                answered(add, ServiceStatus.stale, "capabilities_changed")
                && !r.anope.bodies.any!(b => b.startsWith("AKILL ADD")));
        }

        // ── AKILL list/add/remove (2.1, FIXED, wrapped rows) ──────────
        {
            auto r = StaffRig.make(STAFF_V21);
            auto before = akillView21(twoAkills());
            ok("staff: the 2.1 fixture really wraps AKILL rows", before.length > 5);
            r.anope.reply("HELP AKILL", helpOk("ADD [+expiry] mask reason", "operserv/akill"));
            r.anope.reply("AKILL VIEW", before.dup);
            auto list = r.run(ServiceAction.akillList, `{}`);
            ok("staff: AKILL VIEW rows are rebuilt across LineWrapper splits",
                answered(list, ServiceStatus.confirmed) && list.data["entries"].length == 2
                && list.data["entries"][0]["id"].get!string == "AB12CD34EF"
                && list.data["entries"][1]["mask"].get!string == "baduser@*.bad.example"
                && list.data["entries"][1]["reason"].get!string
                    == "[oper2] repeated flooding of #help over several hours (see ticket 41)"
                && list.data["entries"][0]["createdAt"].get!string == "Thu Nov  6 14:00:00 2026"
                && capState(list, "akillAdd") == "allowed" && list.revision.length);

            auto rows = twoAkills() ~ [["3", "*@198.51.100.9", "me", "Thu Nov  6 16:00:00 2026", "expires in 59 minutes",
                "QW12ER34TY", "[me] drone"]];
            // The relative expiry phrase changed between reads: still the same review.
            auto later = twoAkills();
            later[0][4] = "expires in 29 days, 22 hours";
            r.anope.reply("AKILL VIEW", akillView21(later), akillView21(rows));
            r.anope.reply("AKILL ADD +3600s *@198.51.100.9 drone", ["\x02*@198.51.100.9\x02 added to the AKILL list."]);
            auto add = r.run(ServiceAction.akillAdd,
                `{"mask":"*@198.51.100.9","expirySeconds":3600,"reason":"drone","broadMaskConfirmed":false}`,
                list.revision);
            ok("staff: AKILL ADD puts an explicit +<seconds>s expiry before the mask, then reads back",
                answered(add, ServiceStatus.confirmed) && add.data["entries"].length == 3
                && r.anope.bodies.count!(b => b == "AKILL ADD +3600s *@198.51.100.9 drone") == 1);

            const sent = r.anope.bodies.length;
            auto broad = r.run(ServiceAction.akillAdd,
                `{"mask":"*@*.example","expirySeconds":600,"reason":"x","broadMaskConfirmed":false}`, list.revision);
            ok("staff: a broad mask without typed confirmation is refused before any command",
                answered(broad, ServiceStatus.rejected, "broad_mask_unconfirmed") && r.anope.bodies.length == sent);
            auto realname = r.run(ServiceAction.akillAdd,
                `{"mask":"*@host#real","expirySeconds":600,"reason":"x","broadMaskConfirmed":true}`, list.revision);
            ok("staff: a realname (#) mask is refused locally", answered(realname, ServiceStatus.rejected, "invalid_mask"));

            r.anope.reply("AKILL VIEW", akillView21(rows));
            auto dup = r.run(ServiceAction.akillAdd,
                `{"mask":"*@198.51.100.9","expirySeconds":600,"reason":"x","broadMaskConfirmed":false}`, add.revision);
            ok("staff: adding an existing mask is not sent (it would update the entry)",
                answered(dup, ServiceStatus.rejected, "already_exists")
                && r.anope.bodies.count!(b => b.startsWith("AKILL ADD")) == 1);
            auto stale = r.run(ServiceAction.akillAdd,
                `{"mask":"*@192.0.2.1","expirySeconds":600,"reason":"x","broadMaskConfirmed":false}`, list.revision);
            ok("staff: a review of an older AKILL list is stale and sends nothing",
                answered(stale, ServiceStatus.stale, "revision_changed")
                && r.anope.bodies.count!(b => b.startsWith("AKILL ADD")) == 1);

            r.anope.reply("AKILL VIEW", akillView21(rows), akillView21(twoAkills()));
            r.anope.reply("AKILL DEL QW12ER34TY", ["\x02*@198.51.100.9\x02 deleted from the AKILL list."]);
            auto del = r.run(ServiceAction.akillRemove, `{"entry":"QW12ER34TY"}`, add.revision);
            ok("staff: AKILL DEL uses the entry ID and confirms only after the read-back lacks it",
                answered(del, ServiceStatus.confirmed) && del.data["entries"].length == 2
                && r.anope.bodies.canFind("AKILL DEL QW12ER34TY"));

            r.anope.reply("AKILL VIEW", akillView21(twoAkills()));
            r.anope.reply("AKILL DEL AB12CD34EF", ["\x02*@203.0.113.7\x02 deleted from the AKILL list."]);
            auto ghost = r.run(ServiceAction.akillRemove, `{"entry":"AB12CD34EF"}`, del.revision);
            ok("staff: an acknowledged DEL whose entry is still listed is unconfirmed, not success",
                answered(ghost, ServiceStatus.unconfirmed, "readback_mismatch")
                && r.anope.bodies.count!(b => b == "AKILL DEL AB12CD34EF") == 1);

            // xline.cpp CanAdd: a covering mask with a later expiry deletes
            // the covered entry before the add; the receipt must show it.
            auto afterCover = [
                ["1", "baduser@*.bad.example", "oper2", "Thu Nov  6 15:30:00 2026", "does not expire", "Z9Y8X7W6V5",
                    "[oper2] repeated flooding of #help over several hours (see ticket 41)"],
                ["2", "*@203.0.113.*", "me", "Thu Nov  6 16:10:00 2026", "expires in 29 days, 23 hours", "PO98IU76YT",
                    "[me] subnet"]];
            r.anope.reply("AKILL VIEW", akillView21(twoAkills()), akillView21(afterCover));
            r.anope.reply("AKILL ADD +2592000s *@203.0.113.* subnet", [
                "Removing *@203.0.113.7 because *@203.0.113.* covers it.",
                "\x02*@203.0.113.*\x02 added to the AKILL list."]);
            auto cover = r.run(ServiceAction.akillAdd,
                `{"mask":"*@203.0.113.*","expirySeconds":2592000,"reason":"subnet","broadMaskConfirmed":false}`,
                ghost.revision);
            ok("staff: a covering AKILL ADD reports the removed entry and confirms new mask + removal by read-back",
                answered(cover, ServiceStatus.confirmed) && cover.data["removedEntries"].length == 1
                && cover.data["removedEntries"][0]["mask"].get!string == "*@203.0.113.7"
                && cover.data["removedEntries"][0]["id"].get!string == "AB12CD34EF"
                && cover.details.any!(d => d.canFind("Removing *@203.0.113.7"))
                && cover.data["entries"].length == 2);

            auto afterPartial = [["1", "*@203.0.113.*", "me", "Thu Nov  6 16:10:00 2026", "expires in 29 days, 23 hours",
                "PO98IU76YT", "[me] subnet"]];
            r.anope.reply("AKILL VIEW", akillView21(afterCover), akillView21(afterPartial));
            r.anope.reply("AKILL ADD +600s *@*.bad.example wide", [
                "Removing baduser@*.bad.example because *@*.bad.example covers it.",
                "*@*.bad.example is already covered by *@*.example."]);
            auto partial = r.run(ServiceAction.akillAdd,
                `{"mask":"*@*.bad.example","expirySeconds":600,"reason":"wide","broadMaskConfirmed":false}`,
                cover.revision);
            ok("staff: removals followed by a refusal are a visible partial result, not a plain rejection",
                answered(partial, ServiceStatus.unconfirmed, "covered_entries_removed_add_refused")
                && partial.data["addRefusal"].get!string == "already_covered"
                && partial.data["removedEntries"][0]["id"].get!string == "Z9Y8X7W6V5"
                && r.anope.bodies.count!(b => b == "AKILL ADD +600s *@*.bad.example wide") == 1);
        }

        // ── AKILL FLEXIBLE (2.1) and a translated FIXED table ─────────
        {
            auto r = StaffRig.make(STAFF_V21);
            r.anope.reply("HELP AKILL", helpOk("ADD [+expiry] mask reason", "operserv/akill"));
            r.anope.reply("AKILL VIEW", ["Current AKILL list:"] ~ wrap21([
                "1: [AB12CD34EF] *@203.0.113.7 -- created by me on Thu Nov  6 14:00:00 2026; "
                    ~ "expires in 29 days, 23 hours ([me] spam (bot) from 14:00 onwards)"]) ~ ["End of AKILL list."]);
            auto res = r.run(ServiceAction.akillList, `{}`);
            ok("staff: 2.1 FLEXIBLE AKILL rows parse with parentheses inside the reason",
                answered(res, ServiceStatus.confirmed) && res.data["entries"].length == 1
                && res.data["entries"][0]["reason"].get!string == "[me] spam (bot) from 14:00 onwards");

            auto de = StaffRig.make(STAFF_V21);
            de.anope.reply("HELP AKILL", helpOk("ADD [+expiry] mask reason", "operserv/akill"));
            // de_DE: Created → Erstellt, Expires → Läuft ab, Reason → Grund;
            // fuzzy/empty titles stay English; expiry text translated too.
            de.anope.reply("AKILL VIEW", ["Current AKILL list:"] ~ renderFixed(true, VIEW_ID_TITLES.dup,
                ["Number", "Mask", "Creator", "Erstellt", "Läuft ab", "ID", "Grund"],
                [["1", "*@203.0.113.7", "me", "Do 06 Nov 2026 14:00:00", "wird nicht verfallen", "AB12CD34EF", "[me] Spam"]])
                ~ ["End of AKILL list."]);
            auto g = de.run(ServiceAction.akillList, `{}`);
            ok("staff: a German FIXED AKILL table parses through shipped translations",
                answered(g, ServiceStatus.confirmed) && g.data["entries"].length == 1
                && g.data["entries"][0]["expires"].get!string == "wird nicht verfallen");
            de.anope.reply("AKILL VIEW", ["Zugriff verweigert."]);
            auto d = de.run(ServiceAction.akillList, `{}`);
            ok("staff: a translated Access denied is the same native denial",
                answered(d, ServiceStatus.rejected, "permission_denied"));
        }

        // ── AKILL on 2.0.20: no wrapping, 80-byte column breaks, PRIVMSG ─
        {
            auto r = StaffRig.make(STAFF_V20);
            r.anope.privmsg = true;
            r.anope.reply("HELP AKILL", helpOk("ADD [+expiry] mask reason", "operserv/akill"));
            // A long creator and 2.0 expiry phrase push the cumulative width
            // past 80 before Mask, so every row continues on a second line.
            auto table = renderFixed(false, VIEW_ID_TITLES.dup, VIEW_ID_TITLES.dup, [
                ["1", "*@203.0.113.7", "services-administrator", "Thu Nov  6 14:00:00 2026",
                    "expires in 23 hours, 59 minutes", "AB12CD34EF", "[services-administrator] spam bot"],
                ["2", "baduser@*.bad.example", "oper2", "Thu Nov  6 15:30:00 2026", "does not expire", "Z9Y8X7W6V5",
                    "[oper2] flooding"]]);
            r.anope.reply("AKILL VIEW", ["Current AKILL list:"] ~ table ~ ["End of AKILL list."]);
            auto res = r.run(ServiceAction.akillList, `{}`);
            ok("staff: the 2.0.20 fixture really has column-break continuation lines", table.length == 6);
            ok("staff: 2.0.20 AKILL VIEW over PRIVMSG with column breaks parses",
                answered(res, ServiceStatus.confirmed) && res.data["entries"].length == 2
                && res.data["entries"][1]["id"].get!string == "Z9Y8X7W6V5");
        }

        // ── HostServ ACTIVATE / REJECT (2.1) ──────────────────────────
        {
            auto r = StaffRig.make(STAFF_V21);
            const cols = ["Number", "Nick", "VHost", "Created"];
            string[] waiting(string[][] rows) {
                return renderFixed(true, cols.dup, cols.dup, rows)
                    ~ ["Displayed \x02" ~ rows.length.to!string ~ "\x02 records (\x02" ~ rows.length.to!string
                        ~ "\x02 total)."];
            }
            auto both = [["1", "alice", "alice.users.example", "Thu Nov  6 09:00:00 2026"],
                ["2", "bob", "bob.users.example", "Thu Nov  6 09:05:00 2026"]];
            foreach (c; ["WAITING", "ACTIVATE", "REJECT"]) r.anope.reply("HELP " ~ c, helpOk(c, "hostserv/set"));
            r.anope.reply("WAITING", waiting(both));
            auto w = r.run(ServiceAction.hostWaiting, `{}`);
            r.anope.reply("WAITING", waiting(both), waiting([["1", "bob", "bob.users.example", "Thu Nov  6 09:05:00 2026"]]));
            r.anope.reply("ACTIVATE alice", ["VHost for alice has been activated."]);
            auto a = r.run(ServiceAction.hostActivate, `{"nick":"alice"}`, w.revision);
            ok("staff: ACTIVATE is acknowledged then the queue is read again without the request",
                answered(a, ServiceStatus.confirmed) && a.data["entries"].length == 1
                && a.data["entries"][0]["nick"].get!string == "bob");
            r.anope.reply("WAITING", waiting([["1", "bob", "bob.users.example", "Thu Nov  6 09:05:00 2026"]]));
            r.anope.reply("REJECT bob not a valid host", ["No request for nick bob found."]);
            auto rj = r.run(ServiceAction.hostReject, `{"nick":"bob","reason":"not a valid host"}`, a.revision);
            ok("staff: a REJECT the service answers with no request is rejected, never success",
                answered(rj, ServiceStatus.rejected, "no_request") && r.anope.bodies.canFind("REJECT bob not a valid host"));

            // An own deOPER after the review changes live authority: the
            // paced write is refused before ACTIVATE reaches the socket.
            r.anope.reply("WAITING", waiting([["1", "bob", "bob.users.example", "Thu Nov  6 09:05:00 2026"]])
                ~ [":me!~m@host MODE me :-o"]);
            auto bobRev = rj.revision;
            auto o = r.run(ServiceAction.hostActivate, `{"nick":"bob"}`, bobRev);
            ok("staff: deOPER between review and dispatch stops the mutation as stale",
                answered(o, ServiceStatus.stale) && !r.anope.bodies.canFind("ACTIVATE bob"));
        }

        // ── Global on 2.1: queue gate, exact broadcast evidence ───────
        {
            auto r = StaffRig.make(STAFF_V21);
            r.anope.reply("HELP GLOBAL", helpOk("[message]", "global/global"));
            r.anope.reply("HELP QUEUE", helpOk("LIST", "global/queue"));
            r.anope.reply("QUEUE LIST", ["You have no messages queued."]);
            auto q = r.run(ServiceAction.globalQueue, `{}`);
            ok("staff: an empty 2.1 queue is recognised and enables a single GLOBAL",
                answered(q, ServiceStatus.confirmed) && q.data["empty"].get!bool && capState(q, "globalSend") == "allowed");

            r.anope.reply("GLOBAL Network maintenance tonight",
                [":Global!services@services.test NOTICE $irc.services.test :[me] Network maintenance tonight"]);
            auto s = r.run(ServiceAction.globalSend, `{"text":"Network maintenance tonight"}`, q.revision);
            ok("staff: GLOBAL is confirmed only by our exact [nick] broadcast from the verified Global",
                answered(s, ServiceStatus.confirmed) && s.data["sent"].get!bool
                && !s.toJson().toString().canFind("maintenance"));

            r.anope.reply("GLOBAL Second notice", ["You can not send a single message while you have messages queued."]);
            auto c = r.run(ServiceAction.globalSend, `{"text":"Second notice"}`, q.revision);
            ok("staff: the service's queue conflict is a rejection, nothing else is sent",
                answered(c, ServiceStatus.rejected, "queue_conflict")
                && !r.anope.bodies.any!(b => b == "GLOBAL" || b.startsWith("QUEUE ADD") || b.startsWith("QUEUE CLEAR")));

            r.anope.reply("GLOBAL Lost one", cast(string[]) null);
            r.run(ServiceAction.globalSend, `{"text":"Lost one"}`, q.revision);
            auto lost = r.expire(SERVICES_LINGER_TEST_MS);
            ok("staff: no reply and no broadcast is unconfirmed, sent once, never retried",
                answered(lost, ServiceStatus.unconfirmed) && r.anope.bodies.count!(b => b == "GLOBAL Lost one") == 1);

            r.anope.reply("QUEUE LIST", renderFixed(true, ["Number", "Message"], ["Number", "Message"],
                [["1", "queued private draft"]]));
            auto busy = r.run(ServiceAction.globalQueue, `{}`);
            ok("staff: a non-empty queue blocks GLOBAL and its text stays out of details",
                answered(busy, ServiceStatus.confirmed) && !busy.data["empty"].get!bool
                && busy.data["messages"][0].get!string == "queued private draft"
                && capState(busy, "globalSend") == "denied" && !busy.details.any!(d => d.canFind("draft")));
            auto blocked = r.run(ServiceAction.globalSend, `{"text":"Third"}`, q.revision);
            ok("staff: a queue that changed since review is never sent over",
                answered(blocked, ServiceStatus.stale, "revision_changed") && !r.anope.bodies.canFind("GLOBAL Third"));
            auto spaced = r.run(ServiceAction.globalSend, `{"text":"Two  spaces"}`, q.revision);
            ok("staff: GLOBAL text Anope would respace is refused before dispatch",
                answered(spaced, ServiceStatus.rejected, "noncanonical_spacing")
                && !r.anope.bodies.any!(b => b.canFind("Two")));
        }

        // ── Global on 2.0.20: immediate, no queue ─────────────────────
        {
            auto r = StaffRig.make(STAFF_V20);
            r.anope.reply("HELP GLOBAL", helpOk("message", "global/global"));
            auto q = r.run(ServiceAction.globalQueue, `{}`);
            ok("staff: 2.0.20 has no queue; GLOBAL capability comes from live HELP",
                answered(q, ServiceStatus.confirmed) && !q.data["queueSupported"].get!bool
                && capState(q, "globalQueue") == "unsupported" && capState(q, "globalSend") == "allowed"
                && !r.anope.bodies.canFind("QUEUE LIST"));
            r.anope.reply("GLOBAL Hello all", [":Global!services@services.test PRIVMSG $*.test :[me] Hello all"]);
            auto s = r.run(ServiceAction.globalSend, `{"text":"Hello all"}`, q.revision);
            ok("staff: a 2.0.20 PRIVMSG broadcast with our nick confirms GLOBAL", answered(s, ServiceStatus.confirmed));
            r.anope.reply("GLOBAL Anonymous", [":Global!services@services.test NOTICE $*.test :Anonymous"]);
            auto anon = r.run(ServiceAction.globalSend, `{"text":"Anonymous"}`, q.revision);
            auto settled = anon.requestId.length ? anon : r.expire(SERVICES_LINGER_TEST_MS);
            ok("staff: an anonymousglobal broadcast cannot attribute the actor and stays unconfirmed",
                answered(settled, ServiceStatus.unconfirmed, "broadcast_actor_unverified"));
        }
    }

    /// Long enough for an observe frame's 15 s linger to expire.
    private enum long SERVICES_LINGER_TEST_MS = 16_000;

    private string replicateStr(string s, size_t n) {
        string out_;
        foreach (_; 0 .. n) out_ ~= s;
        return out_;
    }
}
