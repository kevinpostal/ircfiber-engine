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
import ircfiber.irc.services_grammar : AnopeGrammar, AnopeRelease, anopeRelease,
    anopeCandidateRelease, candidateAnopeGrammar, normalizeServiceText;
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

/// A HELP query and the complete argument grammar it must advertise.
enum ServiceSyntaxKind { catalog, literal, argumentless }
struct ServiceSyntaxSpec {
    string command;
    string suffix;
    ServiceSyntaxKind kind;
}

/// Read forms not represented by an individual mutation action.
enum ServiceReadSyntax {
    nickInfo, botInfo, memoList, groups, botList, stats, waiting,
    akillView, queueList, accessList, xopList, flagsModify
}

private ServiceSyntaxSpec syntax(string command, string suffix = "",
        ServiceSyntaxKind kind = ServiceSyntaxKind.catalog) {
    return ServiceSyntaxSpec(command, suffix, suffix.length ? kind : ServiceSyntaxKind.argumentless);
}

/// Alternatives are OR. Provider names and tier names come from the existing
/// provider parser / semantic XOP proof, never an outgoing command body.
ServiceSyntaxSpec[] servicesSyntax(ServiceAction action, bool v21, string provider = "", string tier = "") {
    final switch (action) {
        case ServiceAction.accountInfo: return servicesReadSyntax(ServiceReadSyntax.nickInfo, v21);
        case ServiceAction.accountIdentify: return [syntax("IDENTIFY", "[account] password")];
        case ServiceAction.accountRegister: return [syntax("REGISTER", "password email"), syntax("REGISTER", "password [email]")];
        case ServiceAction.accountConfirm: return [syntax(v21 ? "CONFIRM REGISTER" : "CONFIRM", v21 ? "code" : "passcode")];
        case ServiceAction.accountGroups: return servicesReadSyntax(ServiceReadSyntax.groups, v21);
        case ServiceAction.accountGroup: return [syntax("GROUP", "[target] [password]")];
        case ServiceAction.accountRecover: return [syntax("RECOVER", "nickname [password]")];
        case ServiceAction.accountPrivacy:
            return [syntax("SET HIDE", v21 ? "{EMAIL | STATUS | MASK | QUIT} {ON | OFF}"
                : "{EMAIL | STATUS | USERMASK | QUIT} {ON | OFF}", ServiceSyntaxKind.literal)];
        case ServiceAction.channelRegister: return [syntax("REGISTER", "channel [description]")];
        case ServiceAction.channelAccessSet:
        case ServiceAction.channelAccessRemove:
        case ServiceAction.channelAccessList: {
            const set = action == ServiceAction.channelAccessSet;
            const list = action == ServiceAction.channelAccessList;
            if (provider == "flags") return servicesReadSyntax(ServiceReadSyntax.flagsModify, v21);
            if (provider == "xop") {
                if (!helpCommandValid(tier) || firstWord(tier) != tier) return null;
                return [syntax(tier, list ? "channel LIST [mask | list]"
                    : set ? (v21 ? "channel ADD mask [description]" : "channel ADD mask")
                    : "channel DEL {mask | entry-num | list}")];
            }
            if (provider.length && provider != "access") return null;
            return [syntax("ACCESS", list ? (v21 ? "channel LIST [mask | list] [ALL]" : "channel LIST [mask | list]")
                : set ? (v21 ? "channel ADD mask level [description]" : "channel ADD mask level")
                : "channel DEL {mask | entry-num | list}")];
        }
        case ServiceAction.channelTopicSet: return [syntax("TOPIC", "channel [SET] [topic]")];
        case ServiceAction.channelTopicLock: return [syntax("TOPIC", "channel [UNLOCK|LOCK]")];
        case ServiceAction.channelKeepTopic: return [syntax("SET KEEPTOPIC", "channel {ON | OFF}")];
        case ServiceAction.channelModeLockList:
        case ServiceAction.channelModeLockChange: return [syntax("MODE", "channel LOCK {ADD|DEL|SET|LIST} [what]")];
        case ServiceAction.channelAkickAdd: return [syntax("AKICK", "channel ADD {nick | mask} [reason]")];
        case ServiceAction.channelAkickRemove: return [syntax("AKICK", "channel DEL {nick | mask | entry-num | list}")];
        case ServiceAction.botList: return servicesReadSyntax(ServiceReadSyntax.botList, v21);
        case ServiceAction.botInfo: return servicesReadSyntax(ServiceReadSyntax.botInfo, v21);
        case ServiceAction.botAssign: return [syntax("ASSIGN", "channel nick")];
        case ServiceAction.botUnassign: return [syntax("UNASSIGN", "channel")];
        case ServiceAction.botGreet: return [syntax("SET GREET", "channel {ON|OFF}")];
        case ServiceAction.botFantasy: return [syntax("SET FANTASY", "channel {ON|OFF}")];
        case ServiceAction.hostRequest: return [syntax("REQUEST", "vhost")];
        case ServiceAction.hostOn: return [syntax("ON")];
        case ServiceAction.hostOff: return [syntax("OFF")];
        case ServiceAction.hostWaiting: return servicesReadSyntax(ServiceReadSyntax.waiting, v21);
        case ServiceAction.hostActivate: return [syntax("ACTIVATE", "nick")];
        case ServiceAction.hostReject: return [syntax("REJECT", "nick [reason]")];
        case ServiceAction.memoList: return servicesReadSyntax(ServiceReadSyntax.memoList, v21);
        case ServiceAction.memoRead: return [syntax("READ", "[channel] {num | list | LAST | NEW | ALL}")];
        case ServiceAction.memoSend: return [syntax("SEND", "{nick | channel} memo-text")];
        case ServiceAction.memoDelete: return [syntax("DEL", "[channel] {num | list | LAST | ALL}")];
        case ServiceAction.operStats: return servicesReadSyntax(ServiceReadSyntax.stats, v21);
        case ServiceAction.akillList:
        case ServiceAction.akillView: return servicesReadSyntax(ServiceReadSyntax.akillView, v21);
        case ServiceAction.akillAdd: return [syntax("AKILL", "ADD [+expiry] mask reason")];
        case ServiceAction.akillRemove: return [syntax("AKILL", "DEL {mask | entry-num | list | id}")];
        case ServiceAction.globalQueue: return servicesReadSyntax(ServiceReadSyntax.queueList, v21);
        case ServiceAction.globalSend: return [syntax("GLOBAL", v21 ? "[message]" : "message")];
        // These fixed state reads establish their own compatibility and do
        // not have an additional command HELP gate.
        case ServiceAction.discover:
        case ServiceAction.channelInfo:
        case ServiceAction.channelAkickList:
        case ServiceAction.hostInfo: return null;
    }
}

ServiceSyntaxSpec[] servicesReadSyntax(ServiceReadSyntax read, bool v21, string tier = "") {
    final switch (read) {
        case ServiceReadSyntax.nickInfo: return [syntax("INFO", "[nickname]")];
        case ServiceReadSyntax.botInfo: return [syntax("INFO", "{channel | nickname}")];
        case ServiceReadSyntax.memoList: return [syntax("LIST", "[channel] [list | NEW]")];
        case ServiceReadSyntax.groups: return v21 ? [syntax("GLIST"), syntax("GLIST", "[nickname]")] : [syntax("GLIST")];
        case ServiceReadSyntax.botList: return [syntax("BOTLIST", v21 ? "[OPERONLY] [UNUSED] [VANITY]" : "", ServiceSyntaxKind.literal)];
        case ServiceReadSyntax.stats: return [syntax("STATS", v21
            ? "[AKILL | HASH | PASSWORD | UPLINK | UPTIME | ALL | RESET]"
            : "[AKILL | HASH | UPLINK | UPTIME | ALL | RESET]", ServiceSyntaxKind.literal)];
        case ServiceReadSyntax.waiting: return [syntax("WAITING")];
        case ServiceReadSyntax.akillView: return [syntax("AKILL", "VIEW [mask | list | id]")];
        case ServiceReadSyntax.queueList: return v21 ? [syntax("QUEUE", "LIST", ServiceSyntaxKind.literal)] : null;
        case ServiceReadSyntax.accessList: return servicesSyntax(ServiceAction.channelAccessList, v21);
        case ServiceReadSyntax.xopList: return servicesSyntax(ServiceAction.channelAccessList, v21, "xop", tier);
        case ServiceReadSyntax.flagsModify: return [syntax("FLAGS", v21
            ? "channel [MODIFY] mask changes [description]" : "channel [MODIFY] mask changes")];
    }
}

/// `HELP <command>` availability, with strict read-form evidence for candidates.
void readServicesHelp(ServicesTransaction txn, string command, void delegate(HelpEvidence) done) {
    readServicesHelpOn(txn, txn.endpoint.service, command, done);
}

void readServicesHelpOn(ServicesTransaction txn, ServiceId service, string command, void delegate(HelpEvidence) done) {
    fetchServicesHelp(txn, service, command, (ServicesEndpoint ep, AnopeGrammar g, ServiceFrame f) {
        if (anopeRelease(ep.version_) != AnopeRelease.unknown) {
            done(classifyServicesHelp(g, command, f));
            return;
        }
        ServiceSyntaxSpec[] specs;
        if (service == ServiceId.nickServ && sameAsciiFold(command, "INFO")) specs = servicesReadSyntax(ServiceReadSyntax.nickInfo, g.v21);
        else if (service == ServiceId.nickServ && sameAsciiFold(command, "GLIST")) specs = servicesReadSyntax(ServiceReadSyntax.groups, g.v21);
        else if (service == ServiceId.botServ && sameAsciiFold(command, "INFO")) specs = servicesReadSyntax(ServiceReadSyntax.botInfo, g.v21);
        else if (sameAsciiFold(command, "BOTLIST")) specs = servicesReadSyntax(ServiceReadSyntax.botList, g.v21);
        else if (service == ServiceId.memoServ && sameAsciiFold(command, "LIST")) specs = servicesReadSyntax(ServiceReadSyntax.memoList, g.v21);
        else if (sameAsciiFold(command, "STATS")) specs = servicesReadSyntax(ServiceReadSyntax.stats, g.v21);
        else if (sameAsciiFold(command, "WAITING")) specs = servicesReadSyntax(ServiceReadSyntax.waiting, g.v21);
        else if (sameAsciiFold(command, "QUEUE")) specs = servicesReadSyntax(ServiceReadSyntax.queueList, g.v21);
        done(classifyHelpAlternatives(g, specs, command, f));
    });
}

/// Exact releases retain generic HELP behavior; candidates require full syntax.
void readServicesCommandHelp(ServicesTransaction txn, ServiceId service, ServiceSyntaxSpec spec,
        void delegate(HelpEvidence) done) {
    readHelpAlternatives(txn, service, [spec], done);
}

void readServicesActionHelp(ServicesTransaction txn, ServiceId service, ServiceAction action,
        void delegate(HelpEvidence) done, string provider = "", string tier = "") {
    txn.resolveService(service, (bool valid, string reason, ServicesEndpoint ep) {
        if (!valid) { done(HelpEvidence("unknown", reason)); return; }
        readHelpAlternatives(txn, service, servicesSyntax(action,
            anopeCandidateRelease(ep.version_) == AnopeRelease.v2_1_pinned, provider, tier), done);
    });
}

void readServicesReadHelp(ServicesTransaction txn, ServiceId service, ServiceReadSyntax read,
        void delegate(HelpEvidence) done, string tier = "") {
    txn.resolveService(service, (bool valid, string reason, ServicesEndpoint ep) {
        if (!valid) { done(HelpEvidence("unknown", reason)); return; }
        readHelpAlternatives(txn, service, servicesReadSyntax(read,
            anopeCandidateRelease(ep.version_) == AnopeRelease.v2_1_pinned, tier), done);
    });
}

private void readHelpAlternatives(ServicesTransaction txn, ServiceId service, ServiceSyntaxSpec[] specs,
        void delegate(HelpEvidence) done) {
    if (!specs.length) { done(HelpEvidence("unsupported", "adapter_unavailable")); return; }
    // Inventory alternatives always share one HELP query. Do not fetch one
    // response per suffix (REGISTER and GLIST each have two forms).
    const command = specs[0].command;
    foreach (s; specs) enforce(s.command == command, "HELP alternatives must share one command");
    fetchServicesHelp(txn, service, command, (ServicesEndpoint ep, AnopeGrammar g, ServiceFrame f) {
        done(anopeRelease(ep.version_) != AnopeRelease.unknown
            ? classifyServicesHelp(g, command, f) : classifyHelpAlternatives(g, specs, command, f));
    });
}

private void fetchServicesHelp(ServicesTransaction txn, ServiceId service, string command,
        void delegate(ServicesEndpoint, AnopeGrammar, ServiceFrame) done) {
    enforce(helpCommandValid(command), "Invalid HELP command");
    const generation = txn.capabilityGeneration();
    txn.resolveService(service, (bool valid, string reason, ServicesEndpoint ep) {
        auto grammar = candidateAnopeGrammar(ep.version_);
        ServiceFrame failed;
        failed.outcome = ServiceFrameOutcome.unavailable;
        if (txn.capabilityGeneration() != generation) {
            failed.reason = "capabilities_changed";
            done(ep, grammar, failed);
            return;
        }
        if (!valid) {
            failed.reason = reason;
            // Preserve resolution failure rather than misclassifying its
            // missing VERSION as an unsupported release.
            done(ep, candidateAnopeGrammar(txn.endpoint.version_), failed);
            return;
        }
        if (service != txn.endpoint.service
                && (anopeCandidateRelease(ep.version_) == AnopeRelease.unknown
                    || anopeCandidateRelease(ep.version_) != anopeCandidateRelease(txn.endpoint.version_))) {
            failed.reason = "adapter_unavailable";
            done(ep, grammar, failed);
            return;
        }
        ServiceFrame cached;
        if (txn.cachedServicesHelp(ep, command, cached)) {
            done(ep, grammar, cached);
            return;
        }
        if (!grammar.supported) {
            done(ep, grammar, failed);
            return;
        }
        ServiceFrameSpec frameSpec;
        frameSpec.bodies = ["HELP " ~ command];
        frameSpec.kind = ServiceFrameKind.ordinary;
        frameSpec.mutating = false;
        auto handler = (ServiceFrame f) {
            if (txn.capabilityGeneration() != generation) {
                failed.reason = "capabilities_changed";
                done(ep, grammar, failed);
                return;
            }
            txn.resolveService(service, (bool stillValid, string currentReason, ServicesEndpoint current) {
                if (!stillValid || current != ep || txn.capabilityGeneration() != generation) {
                    failed.reason = stillValid ? "capabilities_changed" : currentReason;
                    done(ep, grammar, failed);
                    return;
                }
                txn.cacheServicesHelp(ep, command, f);
                done(ep, grammar, f);
            });
        };
        if (service == txn.endpoint.service) txn.frame(frameSpec, handler);
        else txn.frameOn(service, frameSpec, handler);
    });
}

// GLIST in 2.0 bypasses SendSyntax and sends one complete translated message.
// The printf slot is the command name, not an arbitrary argument grammar.
private immutable string[] GLIST20_HELP = [
    "Syntax: %s\n \nLists all nicks in your group.",
    "Syntax: %s [nickname]\n \nWithout a parameter, lists all nicknames that are in\n"
        ~ "your group.\n \nWith a parameter, lists all nicknames that are in the\n"
        ~ "group of the given nick.\nSpecifying a nick is limited to Services Operators.",
];

/// Full command syntax, not just command availability or opertype permission.
/// Braces and alternation are compared as literal documentation, never passed
/// through the reply grammar's table-template capture machinery.
HelpEvidence classifyServicesCommandHelp(AnopeGrammar g, const ref ServiceSyntaxSpec spec,
        const ref ServiceFrame frame) {
    auto available = classifyServicesHelp(g, spec.command, frame);
    if (available.state == "denied" || available.state == "unsupported"
            || !frameComplete(frame) || (available.state == "unknown"
                && available.reasonCode != "help_unrecognized")) return available;
    if (!g.v21 && sameAsciiFold(spec.command, "GLIST")) {
        string[] caps;
        size_t which;
        if (g.matchesAny(GLIST20_HELP, frame, caps, which)
                && caps.length == 1 && sameAsciiFold(caps[0], "GLIST"))
            return HelpEvidence("allowed", "", available.permission);
        if (available.state == "allowed" || hasSyntaxBlock(g, servicePlainLines(frame)))
            return HelpEvidence("unsupported", "adapter_unavailable", available.permission);
        return available;
    }
    string[] suffixes;
    final switch (spec.kind) {
        case ServiceSyntaxKind.argumentless:
            if (!spec.suffix.length) suffixes = [""];
            break;
        case ServiceSyntaxKind.literal:
            if (spec.suffix.length) suffixes = [normalizeServiceText(spec.suffix)];
            break;
        case ServiceSyntaxKind.catalog:
            if (spec.suffix.length && g.knows(spec.suffix)) {
                foreach (variant; g.variants(spec.suffix))
                    if (!g.contested(spec.suffix, variant)) suffixes ~= variant;
            }
            break;
    }
    foreach (suffix; suffixes)
        if (fullSyntaxLine(g, spec.command, suffix, frame))
            return HelpEvidence("allowed", "", available.permission);
    // Unknown prose is still unknown. A recognized syntax block for a
    // different command, or a permission-only reply, cannot prove this form.
    if (available.state == "allowed" || hasSyntaxBlock(g, servicePlainLines(frame)))
        return HelpEvidence("unsupported", "adapter_unavailable", available.permission);
    return available;
}

private HelpEvidence classifyHelpAlternatives(AnopeGrammar g, const ServiceSyntaxSpec[] specs,
        string command, const ref ServiceFrame frame) {
    auto result = classifyServicesHelp(g, command, frame);
    if (!specs.length) {
        if (result.state == "allowed") return HelpEvidence("unsupported", "adapter_unavailable", result.permission);
        return result;
    }
    foreach (ref spec; specs) {
        auto h = classifyServicesCommandHelp(g, spec, frame);
        if (h.state == "allowed" || h.state == "denied") return h;
        result = h;
    }
    return result;
}

private bool syntaxStart(string label, string line, out size_t at) {
    at = label.length + 1;
    if (line.length <= at || line[0 .. label.length] != label
            || line[label.length] != ':' || line[at] != ' ') return false;
    while (at < line.length && line[at] == ' ') ++at;
    return at < line.length;
}

private bool hasSyntaxBlock(AnopeGrammar g, const string[] lines) {
    foreach (label; g.variants(HELP_SYNTAX)) {
        if (g.contested(HELP_SYNTAX, label)) continue;
        foreach (line; lines) {
            size_t at;
            if (syntaxStart(label, line, at)) return true;
        }
    }
    return false;
}

private size_t syntaxPadding(string label) {
    // SendSyntax pads by UTF-8 character count, not byte count.
    size_t n = 2;
    foreach (char c; label) if ((cast(ubyte) c & 0xC0) != 0x80) ++n;
    return n;
}

private bool syntaxPrefix(string text, string expected, size_t commandLength) {
    if (text.length > expected.length) return false;
    const n = text.length < commandLength ? text.length : commandLength;
    if (!sameAsciiFold(text[0 .. n], expected[0 .. n])) return false;
    return text.length <= commandLength || text[commandLength .. $] == expected[commandLength .. text.length];
}

private bool fullSyntaxLine(AnopeGrammar g, string command, string suffix, const ref ServiceFrame frame) {
    const expected = suffix.length ? command ~ " " ~ suffix : command;
    const lines = servicePlainLines(frame);
    foreach (label; g.variants(HELP_SYNTAX)) {
        if (g.contested(HELP_SYNTAX, label)) continue;
        const padding = syntaxPadding(label);
        bool inBlock;
        foreach (i, line; lines) {
            size_t at;
            if (syntaxStart(label, line, at)) {
                inBlock = true;
            } else {
                size_t spaces;
                while (spaces < line.length && line[spaces] == ' ') ++spaces;
                if (spaces == line.length) { inBlock = false; continue; }
                // Only exactly padded rows within a recognized syntax block
                // can introduce another alternative. Unindented HELP prose
                // is never searched for command-shaped substrings.
                if (!inBlock) continue;
                if (spaces != padding) { inBlock = false; continue; }
                at = spaces;
            }
            auto text = line[at .. $];
            if (!syntaxPrefix(text, expected, command.length)) continue;
            if (text.length == expected.length) return true;
            if (!g.v21) continue;
            // 2.1 wraps at spaces. Join only prefixes of this exact full row,
            // with the original reply attribution and command preserved.
            for (size_t j = i + 1; j < lines.length && j < i + 16; ++j) {
                if (frame.lines[j].command != frame.lines[i].command
                        || frame.lines[j].replyTo != frame.lines[i].replyTo
                        || !lines[j].length || text.length >= expected.length
                        || expected[text.length] != ' ') break;
                text ~= " " ~ lines[j];
                if (!syntaxPrefix(text, expected, command.length)) break;
                if (text.length == expected.length) return true;
            }
        }
    }
    return false;
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
    // Resolution/authority failures have no usable endpoint grammar. Keep
    // their specific transport reason instead of inventing a version refusal.
    if (frame.outcome == ServiceFrameOutcome.unavailable && frame.reason.length)
        return HelpEvidence("unknown", frame.reason);
    if (g is null || !g.supported) return HelpEvidence("unsupported", "unsupported_version");
    if (!frameComplete(frame)) {
        if (frame.outcome == ServiceFrameOutcome.deadline) return HelpEvidence("unknown", "help_timeout");
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
    if (!g.v21 && sameAsciiFold(command, "GLIST")) {
        size_t which;
        if (g.matchesAny(GLIST20_HELP, frame, caps, which)
                && caps.length == 1 && sameAsciiFold(caps[0], "GLIST"))
            return HelpEvidence("allowed", "", permission);
    }

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
    return frame.outcome == ServiceFrameOutcome.completed && !frame.truncated && !frame.ambiguous
        && frame.startFenced && frame.endFenced;
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
    field("ircfiber.services.revision.v2");
    field(SERVICE_KEYS[ep.service]);
    field(ep.nick);
    field(ep.ident);
    field(ep.host);
    field(ep.server);
    field(ep.version_);
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

/// `{state, reasonCode?}`; state is allowed | service_checked | denied |
/// unknown | unsupported. Only allowed and service_checked are requestable;
/// service_checked means the service itself authorizes at execution.
Json serviceCapability(string state, string reasonCode = "") {
    enforce(state == "allowed" || state == "service_checked" || state == "denied"
        || state == "unknown" || state == "unsupported",
        "Invalid services capability state");
    auto j = Json.emptyObject;
    j["state"] = state;
    if (reasonCode.length) j["reasonCode"] = reasonCode;
    return j;
}

/// Channel (ChanServ) and BotServ operations: the only actions whose
/// capability may be service_checked. Identity, operator and staff actions
/// keep strictly proven permissions.
bool serviceCheckedAction(ServiceAction action) {
    import std.algorithm.searching : startsWith;
    const name = action.to!string;
    return name.startsWith("channel") || name.startsWith("bot");
}

/// Sets `capabilities[action]` (creating the object).
void putServiceCapability(ref Json capabilities, ServiceAction action, string state, string reasonCode = "") {
    enforce(state != "service_checked" || serviceCheckedAction(action),
        "service_checked is only valid for channel and BotServ actions");
    if (capabilities.type != Json.Type.object) capabilities = Json.emptyObject;
    capabilities[action.to!string] = serviceCapability(state, reasonCode);
    if (action == ServiceAction.accountRegister || action == ServiceAction.accountConfirm)
        capabilities[action.to!string]["registration"] = Json(["protocol": Json("nickserv"),
            "beforeConnect": Json(false), "customAccountName": Json(false), "emailRequired": Json(false)]);
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

        enum NETCRAVE = "Anope-2.1.27-git (1947276) build #1, compiled Mon Sep 28 2026 08:19:33 UTC, flags DG -- InspIRCd 4+ -- enc_sha2";
        auto candidate = candidateAnopeGrammar(NETCRAVE);
        HelpEvidence actionHelp(ServiceAction action, ServiceFrame f, bool v21 = true,
                string provider = "", string tier = "") {
            auto specs = servicesSyntax(action, v21, provider, tier);
            return classifyHelpAlternatives(v21 ? candidate : g20, specs,
                specs.length ? specs[0].command : "", f);
        }
        auto multi = frame("Syntax: ACCESS channel ADD mask level [description]",
            "        ACCESS channel DEL {mask | entry-num | list}",
            "        ACCESS channel LIST [mask | list] [ALL]", " ", "Maintains channel access.");
        ok("syntax: actual candidate ACCESS ADD does not imply DEL",
            actionHelp(ServiceAction.channelAccessSet, usable).state == "allowed"
            && actionHelp(ServiceAction.channelAccessRemove, usable).state == "unsupported");
        ok("syntax: fixed layout later DEL and full ALL LIST are independently proved",
            actionHelp(ServiceAction.channelAccessRemove, multi).state == "allowed"
            && actionHelp(ServiceAction.channelAccessList, multi).state == "allowed");
        auto flexible = frame("Syntax: ACCESS channel ADD mask level [description]",
            "Syntax: ACCESS channel DEL {mask | entry-num | list}",
            "Syntax: ACCESS channel LIST [mask | list] [ALL]");
        ok("syntax: flexible repeated labels prove later rows",
            actionHelp(ServiceAction.channelAccessRemove, flexible).state == "allowed"
            && actionHelp(ServiceAction.channelAccessList, flexible).state == "allowed");
        auto wrappedSyntax = frame("Syntax: ACCESS channel LIST [mask |", "list] [ALL]");
        ok("syntax: 2.1 wrapping proves full ALL rather than just a prefix",
            actionHelp(ServiceAction.channelAccessList, wrappedSyntax).state == "allowed"
            && actionHelp(ServiceAction.channelAccessList,
                frame("Syntax: ACCESS channel LIST [mask | list]")).state == "unsupported");
        auto wrongAttribution = wrappedSyntax;
        wrongAttribution.lines = wrappedSyntax.lines.dup;
        wrongAttribution.lines[1].replyTo = "someone-else";
        ok("syntax: wrapping does not cross reply attribution",
            actionHelp(ServiceAction.channelAccessList, wrongAttribution).state != "allowed");
        auto frenchSyntax = frame("Syntaxe: ACCESS canal ADD masque niveau [description]",
            "         ACCESS canal DEL {masque | numéro-entrée | liste}");
        ok("syntax: translated label and catalog suffix prove the same ADD and DEL",
            actionHelp(ServiceAction.channelAccessSet, frenchSyntax).state == "allowed"
            && actionHelp(ServiceAction.channelAccessRemove, frenchSyntax).state == "allowed");
        ok("syntax: wrong arguments and wrong command cannot prove a mutation",
            actionHelp(ServiceAction.channelAccessSet,
                frame("Syntax: ACCESS channel ADD mask")).state == "unsupported"
            && actionHelp(ServiceAction.channelAccessSet,
                frame("Syntax: FLAGS channel ADD mask level [description]")).state == "unsupported");
        ok("syntax: permission-only availability does not prove mutation syntax",
            actionHelp(ServiceAction.akillAdd,
                frame("Access to this command requires the permission \x02operserv/akill\x02 to be present in your opertype.")).state == "unsupported");
        ok("syntax: denial wins even when the full requested syntax is present",
            actionHelp(ServiceAction.channelAccessSet,
                frame("Syntax: ACCESS channel ADD mask level [description]", "Access denied.")).state == "denied");
        auto ambiguousSyntax = usable;
        ambiguousSyntax.ambiguous = true;
        ok("syntax: truncation ambiguity and deadlines retain unknown evidence",
            actionHelp(ServiceAction.channelAccessSet, cut).state == "unknown"
            && actionHelp(ServiceAction.channelAccessSet, ambiguousSyntax).state == "unknown"
            && actionHelp(ServiceAction.channelAccessSet, late).reasonCode == "help_timeout");
        ok("syntax: help absence remains unknown rather than module absence",
            actionHelp(ServiceAction.channelAccessSet, frame("No help available for ACCESS.")).state == "unknown");
        ok("syntax: unlabelled prose and stray padded command text prove nothing",
            actionHelp(ServiceAction.channelAccessRemove,
                frame("Use ACCESS channel DEL {mask | entry-num | list} to remove access.")).state != "allowed"
            && actionHelp(ServiceAction.channelAccessRemove,
                frame("        ACCESS channel DEL {mask | entry-num | list}")).state != "allowed"
            && actionHelp(ServiceAction.channelAccessRemove,
                frame("Syntax: ACCESS channel ADD mask level [description]", " ",
                    "        ACCESS channel DEL {mask | entry-num | list}")).state != "allowed"
            && actionHelp(ServiceAction.channelAccessRemove,
                frame("Syntax: ACCESS channel ADD mask level [description]", "This is prose.",
                    "        ACCESS channel DEL {mask | entry-num | list}")).state != "allowed");
        ok("syntax: ADD does not imply another provider's MODIFY",
            actionHelp(ServiceAction.channelAccessSet, usable, true, "flags").state == "unsupported");
        auto mask21 = frame("Syntax: SET\x1BHIDE {EMAIL | STATUS | MASK | QUIT} {ON | OFF}");
        auto mask20 = frame("Syntax: SET HIDE {EMAIL | STATUS | USERMASK | QUIT} {ON | OFF}");
        ok("syntax: self-service MASK and USERMASK signatures stay profile-specific",
            actionHelp(ServiceAction.accountPrivacy, mask21).state == "allowed"
            && actionHelp(ServiceAction.accountPrivacy, mask20).state == "unsupported"
            && actionHelp(ServiceAction.accountPrivacy, mask20, false).state == "allowed"
            && actionHelp(ServiceAction.accountPrivacy, mask21, false).state == "unsupported");
        ok("syntax: administrative nickname SET HIDE is not self-service evidence",
            actionHelp(ServiceAction.accountPrivacy,
                frame("Syntax: SET HIDE nickname {EMAIL | STATUS | MASK | QUIT} {ON | OFF}")).state == "unsupported");
        auto confirm21 = frame("Syntax: CONFIRM\x1BREGISTER code");
        auto confirm20 = frame("Syntax: CONFIRM passcode");
        ok("syntax: CONFIRM REGISTER and legacy CONFIRM cannot prove each other",
            actionHelp(ServiceAction.accountConfirm, confirm21).state == "allowed"
            && actionHelp(ServiceAction.accountConfirm, confirm20).state == "unsupported"
            && actionHelp(ServiceAction.accountConfirm, confirm20, false).state == "allowed"
            && actionHelp(ServiceAction.accountConfirm, confirm21, false).state == "unsupported");
        ok("syntax: REGISTER alternatives are OR with the complete signature",
            actionHelp(ServiceAction.accountRegister, frame("Syntax: REGISTER password email")).state == "allowed"
            && actionHelp(ServiceAction.accountRegister, frame("Syntax: REGISTER password [email]")).state == "allowed"
            && actionHelp(ServiceAction.accountRegister, frame("Syntax: REGISTER password")).state == "unsupported");
        ok("syntax: argumentless forms reject invented parameters",
            actionHelp(ServiceAction.hostOn, frame("Syntax: ON")).state == "allowed"
            && actionHelp(ServiceAction.hostOn, frame("Syntax: ON nickname")).state == "unsupported");
        ok("syntax: reviewed literals do not require catalog membership",
            actionHelp(ServiceAction.globalQueue, frame("Syntax: QUEUE LIST")).state == "allowed"
            && actionHelp(ServiceAction.botList,
                frame("Syntax: BOTLIST [OPERONLY] [UNUSED] [VANITY]")).state == "allowed");
        auto invented = ServiceSyntaxSpec("ACCESS", "invented arguments", ServiceSyntaxKind.catalog);
        auto inventedHelp = frame("Syntax: ACCESS invented arguments");
        ok("syntax: unknown catalog keys cannot prove matching invented documentation",
            classifyServicesCommandHelp(candidate, invented, inventedHelp).state == "unsupported");
        auto glist20 = frame("Syntax: GLIST", " ", "Lists all nicks in your group.");
        ok("syntax: GLIST20 requires its complete source formatter message",
            actionHelp(ServiceAction.accountGroups, glist20, false).state == "allowed"
            && actionHelp(ServiceAction.accountGroups, frame("Syntax: GLIST"), false).state == "unsupported"
            && actionHelp(ServiceAction.accountGroups,
                frame("Syntax: OTHER", " ", "Lists all nicks in your group."), false).state != "allowed");
        auto glist20Oper = frame("Syntax: GLIST [nickname]", " ",
            "Without a parameter, lists all nicknames that are in", "your group.", " ",
            "With a parameter, lists all nicknames that are in the", "group of the given nick.",
            "Specifying a nick is limited to Services Operators.");
        ok("syntax: GLIST20 operator formatter requires its complete multiline body",
            actionHelp(ServiceAction.accountGroups, glist20Oper, false).state == "allowed"
            && actionHelp(ServiceAction.accountGroups,
                frame("Syntax: GLIST [nickname]", " ", "Lists all nicks in your group."), false).state == "unsupported");
        ok("syntax: explicit memo READ has a mutation signature, not LIST evidence",
            actionHelp(ServiceAction.memoRead, frame("Syntax: LIST [channel] [list | NEW]")).state == "unsupported"
            && actionHelp(ServiceAction.memoRead,
                frame("Syntax: READ [channel] {num | list | LAST | NEW | ALL}")).state == "allowed");

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
        auto upgraded = ep;
        upgraded.version_ = NETCRAVE;
        ok("revision: raw observed VERSION changes the opaque review token",
            ra != servicesRevisionFor(upgraded, actor, EPOCH, a));
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
        putServiceCapability(caps, ServiceAction.channelAccessSet, "service_checked", "service_authorization_required");
        putServiceCapability(caps, ServiceAction.botAssign, "service_checked", "service_authorization_required");
        bool staffThrew, identityThrew;
        try putServiceCapability(caps, ServiceAction.akillAdd, "service_checked");
        catch (Exception) staffThrew = true;
        try putServiceCapability(caps, ServiceAction.accountPrivacy, "service_checked");
        catch (Exception) identityThrew = true;
        ok("capability: service_checked only for channel and BotServ actions",
            caps["channelAccessSet"]["state"].get!string == "service_checked"
            && caps["channelAccessSet"]["reasonCode"].get!string == "service_authorization_required"
            && caps["botAssign"]["state"].get!string == "service_checked"
            && staffThrew && identityThrew
            && caps["akillAdd"].type == Json.Type.undefined
            && caps["accountPrivacy"].type == Json.Type.undefined);
    }

    private bool revisionTokenSafe(string s) @safe pure nothrow @nogc {
        foreach (char c; s) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        return true;
    }
}
