/**
 * ChanServ and BotServ operation adapters (actual-user services, unit 3).
 *
 * Every action runs over the actor's own live IRC connection through
 * `ServicesTransaction`; nothing here talks to Anope's RPC interface.
 *
 * Grammar authority: the command sources and shipped catalogs of Anope
 * 2.1 (`f6e46425…`, `modules/chanserv/*`, `modules/botserv/*`,
 * `modules/{greet,fantasy}.cpp`, `include/language.h`, `src/misc.cpp`
 * ListFormatter/InfoFormatter) and upstream 2.0.20 (`12f1ebee…`,
 * `modules/commands/{cs,bs}_*.cpp`, `greet.cpp`, `fantasy.cpp`). The
 * English msgids below are the exact source strings (IRC formatting kept);
 * `AnopeGrammar` expands them to every shipped non-fuzzy translation and
 * strips formatting before matching. Anope is GPL-2.0; no implementation
 * code is copied — only the reply/command grammar the services print.
 *
 * What the adapters guarantee:
 *  - reads combine non-sensitive bodies in one fenced frame and split the
 *    replies per body by `+reply` groups, or else by each body's anchored,
 *    source-defined opener lines; anything unrecognised makes the read
 *    unconfirmed instead of guessed;
 *  - permissions come from the actual session: founder/super-admin from
 *    INFO/STATUS, numeric access entries against the channel's real
 *    LEVELS, XOP tiers against `HELP <tier>`, FLAGS letters against
 *    `HELP FLAGS` + `HELP LEVELS DESC`, and service denials of the gated
 *    reads. Live `@`/`%` never grants persisted access and there is no
 *    built-in XOP ladder. Positive entry/HELP evidence that the channel's
 *    LEVELS (or a non-founder's rank) cannot confirm is `service_checked`:
 *    the reviewed write may be sent and ChanServ/BotServ authorizes it;
 *    without positive evidence it stays `unknown` and disables the write;
 *  - every write re-reads state, re-checks the browser's revision, the
 *    capability and (for nick-menu targets) a fresh WHOIS account, sends
 *    exactly one mutating body, then reads back. Success requires the
 *    service's acknowledgement plus matching read-back state (TOPIC SET,
 *    which has no acknowledgement, requires the exact observed TOPIC
 *    effect). Partial outcomes are reported as observed; nothing is ever
 *    retried or compensated.
 */
module ircfiber.irc.services_channel;

import std.algorithm : all, any, canFind, countUntil, endsWith, sort, startsWith;
import std.array : array, join, split;
import std.ascii : isAlpha, isDigit;
import std.conv : to;
import std.string : indexOf, strip, stripLeft, toUpper;
import std.uni : icmp, sicmp;

import vibe.data.json : Json;

import ircfiber.irc.services;
import ircfiber.irc.services_grammar : AnopeGrammar;
import ircfiber.irc.services_operation;
import ircfiber.services.config : ServiceId;
import ircfiber.services.protocol : ServiceAction, ServiceStatus, AccessProvider, LockChange;

// ── Source grammar (exact English msgids) ─────────────────────────────────

// include/language.h (both versions unless suffixed)
private enum string M_ACCESS_DENIED = "Access denied.";
private enum string M_READ_ONLY_21 = "Services are temporarily in read-only mode.";
private enum string M_READ_ONLY_20 = "Services are in read-only mode!";
private enum string M_CHAN_NOT_REGISTERED = "Channel \x02%s\x02 isn't registered.";
private enum string M_CHAN_NOT_IN_USE = "Channel \x02%s\x02 doesn't exist.";
private enum string M_CHAN_SUSPENDED = "Channel %s is currently suspended.";
private enum string M_NICK_NOT_REGISTERED = "Nick \x02%s\x02 isn't registered.";
private enum string M_NICK_NOT_IN_USE = "Nick \x02%s\x02 isn't currently in use.";
private enum string M_IDENTIFY_REQUIRED = "You must be logged into an account to use that command.";
private enum string M_CHAN_INFO_HEADER_21 = "Information about channel \x02%s\x02:";
private enum string M_CHAN_INFO_HEADER_20 = "Information for channel \x02%s\x02:";
private enum string M_ACCESS_LIMIT_21 = "You can only have %u access entry on a channel.";
private enum string M_ACCESS_LIMIT_DEEP_21 =
    "You can only have %u access entry on a channel, including access entries from other channels.";
private enum string M_ACCESS_LIMIT_20 =
    "Sorry, you can only have %d access entries on a channel, including access entries from other channels.";
private enum string M_ACCESS_LEVEL_RANGE = "Access level must be between %d and %d inclusive.";
private enum string M_ACCESS_MALFORMED_21 =
    "You cannot add a malformed mask to an access list. Did you mean to add %s instead?";
private enum string M_ACCESS_FOREIGN_21 =
    "%u access entry from other access systems not shown; use \x02%s\x1BALL\x02 to view all access entries.";
private enum string M_CHAN_EXCEPTED =
    "\x02%s\x02 matches an except on %s and cannot be banned until the except has been removed.";
private enum string M_BOT_DOES_NOT_EXIST = "Bot \x02%s\x02 does not exist.";
private enum string M_BOT_NOT_ASSIGNED = "You must assign a bot to the channel before using this command.";

// src/command.cpp unknown-command replies
private immutable string[] M_UNKNOWN_21 = [
    "Unknown command \x02%s\x02. Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02? Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02?",
    "Unknown command \x02%s\x02.",
];
private immutable string[] M_UNKNOWN_20 = [
    "Unknown command \x02%s\x02. \"%s%s HELP\" for help.",
    "Unknown command \x02%s\x02.",
];

// 2.0 per-module "temporarily disabled" (read-only) replies
private immutable string[] M_DISABLED_20 = [
    "Sorry, channel %s list modification is temporarily disabled.",
    "Sorry, channel access list modification is temporarily disabled.",
    "Sorry, channel autokick list modification is temporarily disabled.",
    "Sorry, channel registration is temporarily disabled.",
    "Sorry, bot assignment is temporarily disabled.",
    "Sorry, bot option setting is temporarily disabled.",
    "Sorry, changing bot options is temporarily disabled.",
];

// cs_info.cpp / cs_topic.cpp / cs_mode.cpp InfoFormatter keys and options
private enum string K_FOUNDER = "Founder";
private enum string K_DESCRIPTION = "Description";
private enum string K_LAST_TOPIC = "Last topic";
private enum string K_OPTIONS = "Options";
private enum string K_MODE_LOCK = "Mode lock";
private enum string O_TOPIC_RETENTION = "Topic retention";
private enum string O_TOPIC_LOCK = "Topic lock";

// cs_status.cpp
private enum string M_STATUS_SUPER = "\x02%s\x02 is a super administrator.";
private enum string M_STATUS_FOUNDER = "\x02%s\x02 is the founder of \x02%s\x02.";
private enum string M_STATUS_NONE = "\x02%s\x02 has no access on \x02%s\x02.";
private enum string M_STATUS_HEADER = "Access for \x02%s\x02 on \x02%s\x02:";
private enum string M_STATUS_MATCH = "\x02%s\x02 matches access entry %s, which has privilege %s.";
private enum string M_STATUS_MATCH_FROM =
    "\x02%s\x02 matches access entry %s (from entry %s), which has privilege %s.";
private enum string M_STATUS_AKICK_NC = "\x02%s\x02 is on the auto kick list of \x02%s\x02 (%s).";
private enum string M_STATUS_AKICK_MASK = "\x02%s\x02 matches auto kick entry %s on \x02%s\x02 (%s).";

// cs_access.cpp (ACCESS, LEVELS)
private enum string M_ACCESS_HEADER = "Access list for %s:";
private enum string M_ACCESS_END = "End of access list";
private enum string M_ACCESS_EMPTY = "%s access list is empty.";
private enum string M_ACCESS_NO_MATCH = "No matching entries on %s access list.";
private enum string M_ACCESS_ADDED_LEVEL = "\x02%s\x02 added to %s access list at level \x02%d\x02.";
private enum string M_ACCESS_ADDED_PRIV = "\x02%s\x02 added to %s access list at privilege %s (level %d)";
private enum string M_ACCESS_DELETED = "\x02%s\x02 deleted from %s access list.";
private enum string M_ACCESS_NOT_FOUND = "\x02%s\x02 not found on %s access list.";
private enum string M_ACCESS_NONZERO = "Access level must be non-zero.";
private enum string F_ACCESS_ROW = "{number}: \x02{mask}\x02 = {level}";
private enum string F_ACCESS_ROW_DESC = "{number}: \x02{mask}\x02 = {level} ({description})";
private enum string M_LEVELS_HEADER = "Access level settings for channel %s:";
private enum string M_LEVEL_DISABLED = "(disabled)";
private enum string M_LEVEL_FOUNDER = "(founder only)";
private enum string F_LEVELS_ROW = "\x02{name}\x02 = {level}";
private enum string M_LEVELS_DESC_HEADER = "The following feature/function names are available:";
private enum string F_LEVELS_DESC_ROW = "\x02{name}\x02: defaults to {default} ({description})";

// shared by cs_xop.cpp / cs_access.cpp / cs_flags.cpp ADD paths
private enum string M_NEVEROP_21 = "\x02%s\x02 does not wish to be added to channel access lists.";
private enum string M_MASKS_FORBIDDEN = "Masks and unregistered users may not be on access lists.";
private enum string M_CHANNELS_FORBIDDEN = "Channels may not be on access lists.";

// cs_xop.cpp
private enum string M_XOP_ADDED = "\x02%s\x02 added to %s %s list.";
private enum string M_XOP_DELETED = "\x02%s\x02 deleted from %s %s list.";
private enum string M_XOP_NOT_FOUND = "\x02%s\x02 not found on %s %s list.";
private enum string M_XOP_EMPTY = "%s %s list is empty.";
private enum string M_XOP_HEADER = "%s list for %s";
private enum string M_XOP_HELP_21 =
    "Maintains the \x02%s list\x02 for a channel. Users who match an access entry "
    ~ "on the %s list receive the following privileges:";
private enum string M_XOP_HELP_20 =
    "Maintains the \x02%s list\x02 for a channel. Users who match an access entry\n"
    ~ "on the %s list receive the following privileges:\n ";
private enum string F_XOP_ROW = "{number}: \x02{mask}\x02";
private enum string F_XOP_ROW_DESC = "{number}: \x02{mask}\x02 ({description})";

// cs_flags.cpp
private enum string M_FLAGS_SET = "Flags for \x02%s\x02 on %s set to +\x02%s\x02";
private enum string M_FLAGS_REMOVED = "\x02%s\x02 removed from the %s access list.";
private enum string M_FLAGS_CANNOT = "You cannot set the \x02%c\x02 flag.";
private enum string M_FLAGS_HEADER = "Flags list for %s";
private enum string M_FLAGS_END = "End of access list.";
private enum string M_FLAGS_END_PARTIAL = "End of access list - %d/%d entries shown.";
private enum string M_FLAGS_HELP_AVAILABLE = "The available flags are:";
private enum string F_FLAGS_ROW =
    "{number}: \x02{mask}\x02 = {flags} -- added by {creator} at {created}";
private enum string F_FLAGS_ROW_DESC =
    "{number}: \x02{mask}\x02 = {flags} -- added by {creator} at {created} ({description})";

// cs_register.cpp
private enum string M_REGISTERED = "Channel \x02%s\x02 registered under your account: %s";
private enum string M_ALREADY_REGISTERED = "Channel \x02%s\x02 is already registered!";
private enum string M_REGISTER_NOT_OP = "You must be a channel operator to register the channel.";
private enum string M_REGISTER_UNCONFIRMED = "You must confirm your account before you can register a channel.";
private enum string M_REGISTER_LOCAL = "Local channels cannot be registered.";

// cs_topic.cpp
private enum string M_KEEPTOPIC_ON = "Topic retention option for %s is now \x02on\x02.";
private enum string M_KEEPTOPIC_OFF = "Topic retention option for %s is now \x02off\x02.";
private enum string M_TOPICLOCK_ON = "Topic lock option for %s is now \x02on\x02.";
private enum string M_TOPICLOCK_OFF = "Topic lock option for %s is now \x02off\x02.";

// cs_mode.cpp (MODE LOCK)
private enum string M_MLOCK_HEADER = "Mode locks for %s:";
private enum string M_MLOCK_NONE = "Channel %s has no mode locks.";
private enum string F_MLOCK_ROW = "{mode} -- created by {creator} on {created}";
private enum string F_MLOCK_ROW_PARAM = "{mode} {param} -- created by {creator} on {created}";
private enum string M_NOTHING_TO_DO = "Nothing to do.";
// 2.1 aggregated replies
private enum string M_MLOCK_LOCKED_21 = "%s has been locked on %s.";
private enum string M_MLOCK_UNLOCKED_21 = "%s has been unlocked from %s.";
private enum string M_MLOCK_NOT_LOCKED_21 = "%s is not locked on %s.";
private enum string M_MLOCK_UNKNOWN_21 = "Unknown modes %s ignored.";
private enum string M_MLOCK_MISSING_21 = "Missing parameter for modes %s.";
private enum string M_MLOCK_CANNOT_SET_21 = "You may not (un)lock modes %s from %s.";
private enum string M_MLOCK_LIST_FULL_21 = "List for modes %s is full.";
private enum string M_MLOCK_LOCKLIST_FULL_21 = "The mode lock list of \x02%s\x02 is full, unable to lock %s.";
private enum string M_MLOCK_CANNOT_LOCK_21 = "%s can not be locked on %s.";
// 2.0 per-mode replies
private enum string M_MLOCK_LOCKED_20 = "%s locked on %s.";
private enum string M_MLOCK_UNLOCKED_20 = "%c%c%s has been unlocked from %s.";
private enum string M_MLOCK_NOT_LOCKED_20 = "%c%c is not locked on %s.";
private enum string M_MLOCK_UNKNOWN_20 = "Unknown mode character %c ignored.";
private enum string M_MLOCK_MAY_NOT_20 = "You may not (un)lock mode %c.";
private enum string M_MLOCK_MISSING_20 = "Missing parameter for mode %c.";
private enum string M_MLOCK_LIST_FULL_20 = "List for mode %c is full.";
private enum string M_MLOCK_LOCKLIST_FULL_20 = "The mode lock list of \x02%s\x02 is full.";

// cs_akick.cpp
private enum string M_AKICK_HEADER = "Autokick list for %s:";
private enum string M_AKICK_END = "End of autokick list";
private enum string M_AKICK_EMPTY = "%s autokick list is empty.";
private enum string M_AKICK_NO_MATCH = "No matching entries on %s autokick list.";
private enum string M_AKICK_ADDED = "\x02%s\x02 added to %s autokick list.";
private enum string M_AKICK_EXISTS = "\x02%s\x02 already exists on %s autokick list.";
private enum string M_AKICK_DELETED = "\x02%s\x02 deleted from %s autokick list.";
private enum string M_AKICK_NOT_FOUND = "\x02%s\x02 not found on %s autokick list.";
private enum string M_AKICK_ENFORCED = "AKICK ENFORCE for \x02%s\x02 complete; \x02%d\x02 users were affected.";
private enum string M_AKICK_LIMIT_21 = "You can only have %d autokick masks on a channel.";
private enum string M_AKICK_LIMIT_20 = "Sorry, you can only have %d autokick masks on a channel.";
private enum string F_AKICK_ROW = "{number}: \x02{mask}\x02";
private enum string F_AKICK_ROW_REASON = "{number}: \x02{mask}\x02 ({reason})";

// botserv: bs_botlist.cpp / bs_info.cpp / bs_assign.cpp / greet.cpp / fantasy.cpp
private enum string M_BOTLIST_HEADER = "Bot list:";
private enum string M_BOTLIST_COUNT = "%d bots available.";
private enum string M_BOTLIST_NONE_21 =
    "There are no bots available at this time. Ask a Services Operator to create one!";
private enum string M_BOTLIST_NONE_20 =
    "There are no bots available at this time.\nAsk a Services Operator to create one!";
private enum string F_BOTLIST_ROW = "\x02{nick}\x02 ({mask}) [{real_name}]";
private enum string M_BS_NOT_VALID = "\x02%s\x02 is not a valid bot or registered channel.";
private enum string K_BOT_NICK = "Bot nick";
private enum string M_BOT_NOT_ASSIGNED_YET = "not assigned yet";
private enum string O_GREET = "Greet";
private enum string O_FANTASY = "Fantasy";
private enum string M_BOT_ASSIGNED = "Bot \x02%s\x02 has been assigned to %s.";
private enum string M_BOT_ALREADY = "Bot \x02%s\x02 is already assigned to channel \x02%s\x02.";
private enum string M_BOT_UNASSIGNED = "There is no bot assigned to %s anymore.";
private enum string M_BOT_PERSIST = "You cannot unassign bots while persist is set on the channel.";
private enum string M_GREET_ON = "Greet mode is now \x02on\x02 on channel %s.";
private enum string M_GREET_OFF = "Greet mode is now \x02off\x02 on channel %s.";
private enum string M_FANTASY_ON = "Fantasy mode is now \x02on\x02 on channel %s.";
private enum string M_FANTASY_OFF = "Fantasy mode is now \x02off\x02 on channel %s.";

/// XOP command names queried for provider resolution and availability.
/// Read-only discovery: the actual configured tiers are those that do not
/// answer "Unknown command". No rank order is derived from this list.
private immutable string[] XOP_QUERY = ["QOP", "SOP", "AOP", "HOP", "VOP"];
/// Tiers the browser may grant (protocol validation).
private immutable string[] XOP_WRITABLE = ["SOP", "AOP", "HOP", "VOP"];

// ── Grammar cache ─────────────────────────────────────────────────────────

private AnopeGrammar[string] gGrammars;

private AnopeGrammar grammarFor(string versionText) {
    if (auto g = versionText in gGrammars) return *g;
    auto g = new AnopeGrammar(versionText);
    gGrammars[versionText] = g;
    return g;
}

// ── Line matching ─────────────────────────────────────────────────────────

/// Anchored match of `msgid` at line `i`. On 2.1 a reply longer than
/// options:linelength is split by LineWrapper at its last breaking space,
/// which is dropped (misc.cpp GetLine), so up to three physical lines are
/// rejoined with one space. 2.0 has no LineWrapper (only `\n` in the msgid
/// itself), so it never joins. A following line that is itself a complete
/// occurrence of `msgid` is a separate message, never a continuation — this
/// keeps e.g. an INFO row + "nick is the founder of #c." from reading as one
/// founder line with a garbage nick. `used` = lines consumed.
private bool matchAt(AnopeGrammar g, string msgid, const string[] lines, size_t i,
        out string[] caps, out size_t used) {
    if (i >= lines.length) return false;
    if (g.matches(msgid, lines[i], caps)) { used = 1; return true; }
    if (!g.v21) return false;
    string joined = lines[i];
    foreach (k; 1 .. 3) {
        if (i + k >= lines.length) break;
        string[] alone;
        if (g.matches(msgid, lines[i + k], alone)) break;
        joined ~= " " ~ lines[i + k];
        if (g.matches(msgid, joined, caps)) { used = k + 1; return true; }
    }
    caps = null;
    return false;
}

private bool lineIs(AnopeGrammar g, string msgid, const string[] lines, size_t i) {
    string[] caps;
    size_t used;
    return matchAt(g, msgid, lines, i, caps, used);
}

private bool lineIs(AnopeGrammar g, string msgid, string line, out string[] caps) {
    return g.matches(msgid, line, caps);
}

private bool lineIs(AnopeGrammar g, string msgid, string line) {
    string[] caps;
    return g.matches(msgid, line, caps);
}

private bool lineIsAny(AnopeGrammar g, const string[] ids, const string[] lines, size_t i) {
    foreach (id; ids) if (lineIs(g, id, lines, i)) return true;
    return false;
}

private bool isUnknownCommand(AnopeGrammar g, string line) {
    foreach (id; g.v21 ? M_UNKNOWN_21 : M_UNKNOWN_20) if (lineIs(g, id, line)) return true;
    return false;
}

private bool isReadOnly(AnopeGrammar g, string line) {
    if (lineIs(g, g.v21 ? M_READ_ONLY_21 : M_READ_ONLY_20, line)) return true;
    if (!g.v21) foreach (id; M_DISABLED_20) if (lineIs(g, id, line)) return true;
    return false;
}

/// `value` is exactly one uncontested translation of the short catalog
/// string `msgid` (option names, column headers, level words).
private bool isVariant(AnopeGrammar g, string msgid, string value) {
    return g.isVariant(msgid, value.strip);
}

/// Replies every channel command may give instead of its own output.
private string commonFailure(AnopeGrammar g, const string[] lines, size_t i) {
    if (i >= lines.length) return "";
    if (lineIs(g, M_ACCESS_DENIED, lines, i)) return "denied";
    if (lineIs(g, M_CHAN_NOT_REGISTERED, lines, i)) return "channel_unregistered";
    if (lineIs(g, M_IDENTIFY_REQUIRED, lines, i)) return "not_identified";
    if (lineIs(g, M_CHAN_SUSPENDED, lines, i)) return "channel_suspended";
    if (isReadOnly(g, lines[i])) return "read_only";
    if (isUnknownCommand(g, lines[i])) return "unsupported";
    return "";
}

// ── Body segmentation ─────────────────────────────────────────────────────

/// Recognises the first reply line of one body.
private alias Opener = bool delegate(const string[] lines, size_t i);

private Opener openerOf(AnopeGrammar g, string[] ids) {
    return (const string[] lines, size_t i) {
        if (commonFailure(g, lines, i).length) return true;
        foreach (id; ids) if (lineIs(g, id, lines, i)) return true;
        return false;
    };
}

/// Splits the frame's reply lines among its bodies. With `+reply`
/// correlation on every line the groups are taken from the tags (and each
/// must still open with that body's grammar); otherwise each body's output
/// starts at the first line recognised by its opener, in body order. A
/// body whose opener is never seen makes the split fail (ambiguous).
private bool splitBodies(const ref ServiceFrame frame, const string[] plain, Opener[] openers,
        out string[][] segments) {
    segments = null;
    const n = openers.length;
    if (!n) return false;
    bool tagged = frame.lines.length == plain.length && plain.length
        && frame.lines.all!(l => l.replyTo.length > 0);
    if (tagged) {
        string[][] groups;
        string last;
        foreach (i, l; frame.lines) {
            string text = plain[i];
            if (!groups.length || l.replyTo != last) { groups ~= [text]; last = l.replyTo; }
            else groups[$ - 1] ~= text;
        }
        if (groups.length == n) {
            bool ok = true;
            foreach (k; 0 .. n) if (!openers[k](groups[k], 0)) { ok = false; break; }
            if (ok) { segments = groups; return true; }
        }
    }
    size_t pos = 0;
    foreach (k; 0 .. n) {
        if (pos >= plain.length || !openers[k](plain, pos)) return false;
        size_t end = plain.length;
        if (k + 1 < n) {
            end = size_t.max;
            foreach (j; pos + 1 .. plain.length)
                if (openers[k + 1](plain, j)) { end = j; break; }
            if (end == size_t.max) return false;
        }
        segments ~= plain[pos .. end].dup;
        pos = end;
    }
    return true;
}

// ── Small helpers ─────────────────────────────────────────────────────────

private ServiceFrameSpec readSpec(string[] bodies) {
    ServiceFrameSpec s;
    s.bodies = bodies;
    s.kind = ServiceFrameKind.ordinary;
    return s;
}

private ServiceFrameSpec writeSpec(ServicesTransaction txn, string body, ServiceFrameKind kind,
        ServiceFrameTerminal terminal = null) {
    ServiceFrameSpec s;
    s.bodies = [body];
    s.kind = kind;
    s.terminal = terminal;
    s.mutating = true;
    s.preflight = () => txn.live();
    return s;
}

private bool isNumber(string s) {
    if (!s.length) return false;
    size_t i = s[0] == '-' ? 1 : 0;
    if (i >= s.length) return false;
    foreach (c; s[i .. $]) if (!isDigit(c)) return false;
    return true;
}

private bool isLetters(string s) {
    return s.length && s.all!(c => isAlpha(c));
}

/// Mask column value is an account name (not a hostmask/channel/extban).
private bool isAccountMask(string mask) {
    if (!mask.length || "#&+!".canFind(mask[0])) return false;
    foreach (c; mask) if ("!@*?:$".canFind(c)) return false;
    return true;
}

private Json jsonStrings(const string[] values) {
    auto a = Json.emptyArray;
    foreach (v; values) a ~= Json(v);
    return a;
}

private string[] safeDetails(ServicesTransaction txn, const ServiceReplyLine[] lines, const string[] hidden) {
    string[] result;
    foreach (d; txn.details(lines)) {
        bool drop;
        foreach (h; hidden) if (h.length && d.canFind(h)) { drop = true; break; }
        if (!drop) result ~= d;
    }
    return result;
}

private bool sameChannel(ServicesTransaction txn, string a, string b) {
    return txn.sameNick(a, b);
}

/// Completes a transaction whose frame did not complete between fences.
private void completeIncomplete(ServicesTransaction txn, const ref ServiceFrame frame, string[] hidden = null) {
    if (frame.outcome == ServiceFrameOutcome.unavailable) {
        txn.complete(txn.dispatched ? ServiceStatus.unconfirmed : ServiceStatus.unavailable,
            frame.reason.length ? frame.reason : "frame_unavailable", Json.undefined, "", Json.undefined,
            safeDetails(txn, frame.lines, hidden));
        return;
    }
    txn.complete(ServiceStatus.unconfirmed, frame.reason.length ? frame.reason : "frame_incomplete",
        Json.undefined, "", Json.undefined, safeDetails(txn, frame.lines, hidden));
}

// ── Channel snapshot (one fenced read frame) ──────────────────────────────

private struct AccessRow {
    uint number;
    /// `ChanAccess::Mask()`: account display name or a mask.
    string mask;
    /// `AccessSerialize()`: level, XOP tier or flag letters.
    string value;
    /// "xop", "access", "flags"; "" when the provider could not be proven.
    string provider;
}

private struct ModeLockRow {
    bool adding;
    char mode;
    string param;
}

private struct AkickRow {
    uint number;
    string mask;
    string reason;
}

/// Which ChanServ bodies one snapshot frame carries.
private enum Part : uint {
    info = 1,
    status = 2,
    levels = 4,
    /// ACCESS LIST + FLAGS LIST + every XOP tier LIST.
    access = 8,
    modeLocks = 16,
    akick = 32,
}

private enum uint AUTHORITY_PARTS = Part.info | Part.status | Part.levels | Part.access;

private struct ChannelSnapshot {
    string channel;
    uint parts;
    // INFO
    bool infoRead;
    bool registered;
    string founder;
    string description;
    bool topicKnown;
    string topic;
    bool optionsRead;
    bool keepTopic;
    bool topicLock;
    string modeLockInfo;
    // STATUS
    bool statusRead;
    bool statusDenied;
    bool statusFounder;
    bool statusSuper;
    bool statusNone;
    string[2][] statusEntries;
    // LEVELS
    bool levelsRead;
    bool levelsDenied;
    string[] levelNames;
    string[string] levels;
    // ACCESS / FLAGS / XOP
    bool accessRead;
    bool accessDenied;
    bool accessAvailable;
    AccessRow[] entries;
    bool flagsRead;
    bool flagsAvailable;
    bool[uint] flagsNumbers;
    /// FLAGS LIST "Flags" column per entry number. 2.0 lists every provider
    /// through DetermineFlags (an XOP entry whose tier is not configured
    /// reads "(none)"); 2.1 without ALL lists flags entries only.
    string[uint] flagsValue;
    bool tiersRead;
    bool[string] tierAvailable;
    string[uint] tierOf;
    // MODE LOCK
    bool locksRead;
    bool locksDenied;
    ModeLockRow[] locks;
    // AKICK
    bool akicksRead;
    bool akicksDenied;
    AkickRow[] akicks;
    /// Machine reasons for anything not recognised.
    string[] problems;
    /// Bodies answered "Unknown command" (module not loaded): body kind name.
    bool[string] unsupported;

    bool accessComplete() const {
        if (!accessRead || !tiersRead) return false;
        foreach (e; entries) if (!e.provider.length) return false;
        return true;
    }
}

private enum BodyKind { info, status, levels, access, flags, xop, modeLocks, akick }

private struct SnapshotBody {
    BodyKind kind;
    string text;
    string tier;
}

/// `tiers`: XOP command names proven by their own HELP to be XOP tiers
/// (only those are ever invoked with `<tier> #c LIST`).
private SnapshotBody[] snapshotBodies(AnopeGrammar g, string channel, uint parts, const string[] tiers) {
    SnapshotBody[] b;
    if (parts & Part.info) b ~= SnapshotBody(BodyKind.info, "INFO " ~ channel);
    if (parts & Part.status) b ~= SnapshotBody(BodyKind.status, "STATUS " ~ channel);
    if (parts & Part.levels) b ~= SnapshotBody(BodyKind.levels, "LEVELS " ~ channel ~ " LIST");
    if (parts & Part.access) {
        // 2.1 hides other providers' entries without ALL (cs_access.cpp
        // ProcessList); 2.0 lists every provider and has no ALL.
        b ~= SnapshotBody(BodyKind.access, g.v21 ? "ACCESS " ~ channel ~ " LIST * ALL" : "ACCESS " ~ channel ~ " LIST");
        b ~= SnapshotBody(BodyKind.flags, "FLAGS " ~ channel ~ " LIST");
        foreach (t; tiers) b ~= SnapshotBody(BodyKind.xop, t ~ " " ~ channel ~ " LIST", t);
    }
    if (parts & Part.modeLocks) b ~= SnapshotBody(BodyKind.modeLocks, "MODE " ~ channel ~ " LOCK LIST");
    if (parts & Part.akick) b ~= SnapshotBody(BodyKind.akick, "AKICK " ~ channel ~ " LIST");
    return b;
}

/// Opener template with the capture that must name this body's channel
/// (and XOP tier), so user-controlled row text cannot forge a boundary.
private struct OpenerSpec {
    string id;
    int channelCapture = -1;
    int tierCapture = -1;
}

private Opener bodyOpener(AnopeGrammar g, ServicesTransaction txn, string channel, SnapshotBody b) {
    OpenerSpec[] specs;
    final switch (b.kind) {
        case BodyKind.info:
            specs = [OpenerSpec(g.v21 ? M_CHAN_INFO_HEADER_21 : M_CHAN_INFO_HEADER_20, 0)];
            break;
        case BodyKind.status:
            specs = [OpenerSpec(M_STATUS_SUPER), OpenerSpec(M_STATUS_FOUNDER, 1), OpenerSpec(M_STATUS_NONE, 1),
                OpenerSpec(M_STATUS_HEADER, 1)];
            break;
        case BodyKind.levels:
            specs = [OpenerSpec(M_LEVELS_HEADER, 0)];
            break;
        case BodyKind.access:
            specs = [OpenerSpec(M_ACCESS_HEADER, 0), OpenerSpec(M_ACCESS_EMPTY, 0), OpenerSpec(M_ACCESS_NO_MATCH, 0)];
            break;
        case BodyKind.flags:
            specs = [OpenerSpec(M_FLAGS_HEADER, 0), OpenerSpec(M_ACCESS_EMPTY, 0), OpenerSpec(M_ACCESS_NO_MATCH, 0)];
            break;
        case BodyKind.xop:
            specs = [OpenerSpec(M_XOP_HEADER, 1, 0), OpenerSpec(M_XOP_EMPTY, 0, 1), OpenerSpec(M_ACCESS_NO_MATCH, 0)];
            break;
        case BodyKind.modeLocks:
            specs = [OpenerSpec(M_MLOCK_HEADER, 0), OpenerSpec(M_MLOCK_NONE, 0)];
            break;
        case BodyKind.akick:
            specs = [OpenerSpec(M_AKICK_HEADER, 0), OpenerSpec(M_AKICK_EMPTY, 0), OpenerSpec(M_AKICK_NO_MATCH, 0)];
            break;
    }
    return (const string[] lines, size_t i) {
        if (i >= lines.length) return false;
        if (lineIs(g, M_ACCESS_DENIED, lines[i]) || isReadOnly(g, lines[i]) || isUnknownCommand(g, lines[i])
                || lineIs(g, M_IDENTIFY_REQUIRED, lines[i]))
            return true;
        string[] caps;
        if (lineIs(g, M_CHAN_NOT_REGISTERED, lines[i], caps) || lineIs(g, M_CHAN_SUSPENDED, lines[i], caps))
            return caps.length && sameChannel(txn, caps[0].strip, channel);
        foreach (s; specs) {
            size_t used;
            if (!matchAt(g, s.id, lines, i, caps, used)) continue;
            const cc = cast(size_t) s.channelCapture;
            const tc = cast(size_t) s.tierCapture;
            if (s.channelCapture >= 0 && (caps.length <= cc || !sameChannel(txn, caps[cc].strip, channel)))
                continue;
            if (s.tierCapture >= 0 && (caps.length <= tc || icmp(caps[tc].strip, b.tier) != 0))
                continue;
            return true;
        }
        return false;
    };
}

// ── Table rows ────────────────────────────────────────────────────────────

/// Whitespace-separated tokens of a fixed-layout row (formatting already
/// removed; the 2.1 MONOSPACE prefix leaves leading spaces).
private string[] tokens(string line) {
    string[] t;
    foreach (p; line.split(' ')) if (p.length) t ~= p;
    return t;
}

/// Text after the first `n` tokens (column values may contain spaces).
private string restAfter(string line, size_t n) {
    size_t i = 0;
    foreach (k; 0 .. n) {
        while (i < line.length && line[i] == ' ') ++i;
        while (i < line.length && line[i] != ' ') ++i;
    }
    return i < line.length ? line[i .. $].strip : "";
}

private bool parseUint(string s, out uint value) {
    s = s.strip;
    if (!s.length || s.length > 9 || !s.all!(c => isDigit(c))) return false;
    value = s.to!uint;
    return true;
}

/// Matches one 2.1 FLEXIBLE row template; `caps` follow the template's
/// `{key}` order of first appearance.
private bool flexibleRow(AnopeGrammar g, string tmpl, string line, out string[] caps) {
    return g.v21 && g.matches(tmpl, line, caps);
}

/// First token of a fixed table's header row is the translated first column.
private bool isHeaderRow(AnopeGrammar g, string firstColumn, string line) {
    auto t = tokens(line);
    return t.length && isVariant(g, firstColumn, t[0]);
}

// ── Body parsers ──────────────────────────────────────────────────────────

/// What a body's first line says when it is a shared failure.
private string segmentFailure(AnopeGrammar g, const string[] seg) {
    if (!seg.length) return "no_reply";
    return commonFailure(g, seg, 0);
}

private void parseInfo(AnopeGrammar g, ServicesTransaction txn, const string[] seg, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "channel_unregistered") {
        if (seg.length == 1) { s.infoRead = true; s.registered = false; }
        else s.problems ~= "info_unexpected_lines";
        return;
    }
    if (fail.length) { s.problems ~= "info_" ~ fail; return; }
    string[] caps;
    if (!lineIs(g, g.v21 ? M_CHAN_INFO_HEADER_21 : M_CHAN_INFO_HEADER_20, seg[0], caps)) {
        s.problems ~= "info_unrecognised";
        return;
    }
    auto rest = seg[1 .. $];
    bool found;
    s.registered = true;
    auto founder = g.infoValueIn(K_FOUNDER, rest, found);
    if (found) s.founder = founder.strip;
    auto desc = g.infoValueIn(K_DESCRIPTION, rest, found);
    if (found) s.description = desc;
    auto topic = g.infoValueIn(K_LAST_TOPIC, rest, found);
    if (found) { s.topicKnown = true; s.topic = topic; }
    auto mlock = g.infoValueIn(K_MODE_LOCK, rest, found);
    if (found) s.modeLockInfo = mlock;
    auto options = g.infoValueIn(K_OPTIONS, rest, found);
    // InfoFormatter prints Options only when at least one option is set
    // (misc.cpp); cs_topic adds "Topic retention"/"Topic lock" when set.
    s.optionsRead = true;
    if (found) {
        foreach (o; options.split(',')) {
            if (isVariant(g, O_TOPIC_RETENTION, o)) s.keepTopic = true;
            if (isVariant(g, O_TOPIC_LOCK, o)) s.topicLock = true;
        }
    }
    s.infoRead = true;
}

private void parseStatus(AnopeGrammar g, const string[] seg, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "denied" && seg.length == 1) { s.statusRead = true; s.statusDenied = true; return; }
    if (fail == "channel_unregistered" && seg.length == 1) { s.statusRead = true; return; }
    if (fail == "unsupported" && seg.length == 1) { s.unsupported["status"] = true; return; }
    if (fail.length) { s.problems ~= "status_" ~ fail; return; }
    size_t i = 0;
    string[] caps;
    if (lineIs(g, M_STATUS_SUPER, seg[0], caps)) s.statusSuper = true;
    else if (lineIs(g, M_STATUS_FOUNDER, seg[0], caps)) s.statusFounder = true;
    else if (lineIs(g, M_STATUS_NONE, seg[0], caps)) s.statusNone = true;
    else if (lineIs(g, M_STATUS_HEADER, seg[0], caps)) {
        // 2.1 LineWrapper splits replies longer than options:linelength at
        // the last space (dropping it), so long masks wrap these lines.
        size_t used;
        while (i + 1 < seg.length) {
            if (matchAt(g, M_STATUS_MATCH, seg, i + 1, caps, used) && caps.length == 3) {
                s.statusEntries ~= [caps[1].strip, caps[2].strip];
                i += used;
            } else if (matchAt(g, M_STATUS_MATCH_FROM, seg, i + 1, caps, used)) {
                // Chained channel access: the privilege belongs to another
                // channel's provider/levels; not evidence for this channel.
                i += used;
            } else break;
        }
    } else { s.problems ~= "status_unrecognised"; return; }
    for (size_t k = i + 1; k < seg.length;) {
        size_t used;
        if (matchAt(g, M_STATUS_AKICK_NC, seg, k, caps, used) || matchAt(g, M_STATUS_AKICK_MASK, seg, k, caps, used)) {
            k += used;
            continue;
        }
        s.problems ~= "status_unexpected_lines";
        return;
    }
    s.statusRead = true;
}

private void parseLevels(AnopeGrammar g, const string[] seg, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "denied" && seg.length == 1) { s.levelsDenied = true; return; }
    if (fail == "unsupported" && seg.length == 1) { s.unsupported["levels"] = true; return; }
    if (fail.length) { s.problems ~= "levels_" ~ fail; return; }
    string[] caps;
    if (!lineIs(g, M_LEVELS_HEADER, seg[0], caps)) { s.problems ~= "levels_unrecognised"; return; }
    foreach (idx, l; seg[1 .. $]) {
        string name, level;
        if (flexibleRow(g, F_LEVELS_ROW, l, caps) && caps.length == 2) {
            name = caps[0].strip;
            level = caps[1].strip;
        } else {
            if (idx == 0 && isHeaderRow(g, "Name", l)) continue;
            auto t = tokens(l);
            if (t.length < 2) { s.problems ~= "levels_unparsed_row"; return; }
            name = t[0];
            level = restAfter(l, 1);
        }
        string normalised;
        if (isNumber(level)) normalised = level;
        else if (isVariant(g, M_LEVEL_DISABLED, level)) normalised = "disabled";
        else if (isVariant(g, M_LEVEL_FOUNDER, level)) normalised = "founder";
        else { s.problems ~= "levels_unparsed_level"; return; }
        if (!(name in s.levels)) s.levelNames ~= name;
        s.levels[name] = normalised;
    }
    s.levelsRead = true;
}

/// "End of access list" (cs_access) and "End of access list." (cs_flags)
/// share translations (de_DE: "Ende der Zugangsliste."), so a single-msgid
/// match sees them as contested; both end the same listing.
private bool isAccessListEnd(AnopeGrammar g, string line) {
    string[] caps;
    size_t which;
    return g.matchesAny([M_ACCESS_END, M_FLAGS_END], line, caps, which);
}

/// ACCESS LIST rows → `entries`.
private void parseAccess(AnopeGrammar g, const string[] seg, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "unsupported" && seg.length == 1) { s.accessAvailable = false; s.unsupported["access"] = true; return; }
    s.accessAvailable = true;
    if (fail == "denied" && seg.length == 1) { s.accessDenied = true; return; }
    if (fail.length) { s.problems ~= "access_" ~ fail; return; }
    string[] caps;
    size_t i = 0;
    if (lineIs(g, M_ACCESS_EMPTY, seg[0], caps) || lineIs(g, M_ACCESS_NO_MATCH, seg[0], caps)) {
        i = 1;
    } else if (lineIs(g, M_ACCESS_HEADER, seg[0], caps)) {
        bool ended;
        for (i = 1; i < seg.length; ++i) {
            auto l = seg[i];
            if (isAccessListEnd(g, l)) { ended = true; ++i; break; }
            AccessRow r;
            if ((flexibleRow(g, F_ACCESS_ROW_DESC, l, caps) && caps.length == 4)
                    || (flexibleRow(g, F_ACCESS_ROW, l, caps) && caps.length == 3)) {
                if (!parseUint(caps[0], r.number)) { s.problems ~= "access_unparsed_row"; return; }
                r.mask = caps[1].strip;
                r.value = caps[2].strip;
            } else {
                if (i == 1 && isHeaderRow(g, "Number", l)) continue;
                auto t = tokens(l);
                // cs_access.cpp columns: Number, Level, Mask[, Description]
                if (t.length < 3 || !parseUint(t[0], r.number)) { s.problems ~= "access_unparsed_row"; return; }
                r.value = t[1];
                r.mask = t[2];
            }
            s.entries ~= r;
        }
        if (!ended) { s.problems ~= "access_unterminated"; return; }
    } else { s.problems ~= "access_unrecognised"; return; }
    // With ALL (2.1) nothing is foreign; a foreign-count line means the
    // listing is not the whole list.
    for (; i < seg.length; ++i) {
        s.problems ~= g.v21 && lineIs(g, M_ACCESS_FOREIGN_21, seg[i]) ? "access_foreign_hidden" : "access_unexpected_lines";
        return;
    }
    s.accessRead = true;
}

/// FLAGS LIST without ALL: exact flags-provider entry numbers on 2.1;
/// on 2.0 (every provider, effective flags) only proves availability.
private void parseFlags(AnopeGrammar g, const string[] seg, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "unsupported") { s.flagsAvailable = false; s.flagsRead = true; return; }
    s.flagsAvailable = true;
    if (fail == "denied" && seg.length == 1) return;
    if (fail.length) { s.problems ~= "flags_" ~ fail; return; }
    string[] caps;
    size_t i = 0;
    if (lineIs(g, M_ACCESS_EMPTY, seg[0], caps) || lineIs(g, M_ACCESS_NO_MATCH, seg[0], caps)) {
        i = 1;
    } else if (lineIs(g, M_FLAGS_HEADER, seg[0], caps)) {
        bool ended;
        for (i = 1; i < seg.length; ++i) {
            auto l = seg[i];
            if (isAccessListEnd(g, l) || lineIs(g, M_FLAGS_END_PARTIAL, l, caps)) { ended = true; ++i; break; }
            uint number;
            string flags;
            if ((flexibleRow(g, F_FLAGS_ROW_DESC, l, caps) && caps.length == 6)
                    || (flexibleRow(g, F_FLAGS_ROW, l, caps) && caps.length == 5)) {
                if (!parseUint(caps[0], number)) { s.problems ~= "flags_unparsed_row"; return; }
                flags = caps[2].strip;
            } else {
                if (i == 1 && isHeaderRow(g, "Number", l)) continue;
                auto t = tokens(l);
                if (t.length < 3 || !parseUint(t[0], number)) { s.problems ~= "flags_unparsed_row"; return; }
                flags = t[2];
            }
            s.flagsNumbers[number] = true;
            s.flagsValue[number] = flags;
        }
        if (!ended) { s.problems ~= "flags_unterminated"; return; }
    } else { s.problems ~= "flags_unrecognised"; return; }
    // CHAN_ACCESS_FOREIGN ("N access entries from other access systems not
    // shown; use FLAGS #c LIST * ALL to view all access entries.") follows
    // whenever XOP/ACCESS entries exist; with a real channel name it is
    // longer than the default 100-byte linelength and arrives wrapped.
    while (i < seg.length) {
        string[] fc;
        size_t used;
        if (g.v21 && matchAt(g, M_ACCESS_FOREIGN_21, seg, i, fc, used)) {
            i += used;
            continue;
        }
        s.problems ~= "flags_unexpected_lines";
        return;
    }
    s.flagsRead = true;
}

/// `<tier> #channel LIST`: XOP entry numbers of that tier (no end line).
private bool parseXop(AnopeGrammar g, const string[] seg, string tier, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "unsupported" && seg.length == 1) { s.tierAvailable[tier] = false; return true; }
    s.tierAvailable[tier] = true;
    if (fail.length) { s.problems ~= "xop_" ~ fail; return false; }
    string[] caps;
    if (lineIs(g, M_XOP_EMPTY, seg[0], caps) || lineIs(g, M_ACCESS_NO_MATCH, seg[0], caps)) {
        if (seg.length == 1) return true;
        s.problems ~= "xop_unexpected_lines";
        return false;
    }
    if (!lineIs(g, M_XOP_HEADER, seg[0], caps)) { s.problems ~= "xop_unrecognised"; return false; }
    foreach (idx, l; seg[1 .. $]) {
        uint number;
        if ((flexibleRow(g, F_XOP_ROW_DESC, l, caps) && caps.length == 3)
                || (flexibleRow(g, F_XOP_ROW, l, caps) && caps.length == 2)) {
            if (!parseUint(caps[0], number)) { s.problems ~= "xop_unparsed_row"; return false; }
        } else {
            if (idx == 0 && isHeaderRow(g, "Number", l)) continue;
            auto t = tokens(l);
            if (t.length < 2 || !parseUint(t[0], number)) { s.problems ~= "xop_unparsed_row"; return false; }
        }
        s.tierOf[number] = tier;
    }
    return true;
}

/// `MODE #channel LOCK LIST` (cs_mode.cpp): Mode, Param, Creator, Created.
private void parseModeLocks(AnopeGrammar g, const string[] seg, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "denied" && seg.length == 1) { s.locksDenied = true; return; }
    if (fail == "unsupported" && seg.length == 1) { s.unsupported["modeLocks"] = true; return; }
    if (fail.length) { s.problems ~= "modelock_" ~ fail; return; }
    string[] caps;
    if (lineIs(g, M_MLOCK_NONE, seg[0], caps)) {
        if (seg.length == 1) s.locksRead = true;
        else s.problems ~= "modelock_unexpected_lines";
        return;
    }
    if (!lineIs(g, M_MLOCK_HEADER, seg[0], caps)) { s.problems ~= "modelock_unrecognised"; return; }
    // Param column offset in FIXED layout: 2.1 pads "Mode" to its ENGLISH
    // width (SendFixed), 2.0 to the TRANSLATED header width (Process).
    size_t paramOffset = g.v21 ? 6 : 0;
    foreach (idx, raw; seg[1 .. $]) {
        auto l = raw.stripLeft;
        ModeLockRow r;
        string mode;
        if (flexibleRow(g, F_MLOCK_ROW_PARAM, l, caps) && caps.length == 4 && caps[0].strip.length == 2) {
            mode = caps[0].strip;
            r.param = caps[1].strip;
        } else if (flexibleRow(g, F_MLOCK_ROW, l, caps) && caps.length == 3 && caps[0].strip.length == 2) {
            mode = caps[0].strip;
        } else {
            if (idx == 0 && isHeaderRow(g, "Mode", l)) {
                if (!g.v21) {
                    auto first = tokens(l)[0];
                    paramOffset = (first.length > 2 ? first.length : 2) + 2;
                }
                continue;
            }
            if (!paramOffset || l.length < 2) { s.problems ~= "modelock_unparsed_row"; return; }
            mode = l[0 .. 2];
            if (l.length > paramOffset && l[paramOffset] != ' ' && l[paramOffset - 1] == ' ')
                r.param = tokens(l[paramOffset .. $])[0];
        }
        if (mode.length != 2 || (mode[0] != '+' && mode[0] != '-') || !isAlpha(mode[1])) {
            s.problems ~= "modelock_unparsed_row";
            return;
        }
        r.adding = mode[0] == '+';
        r.mode = mode[1];
        s.locks ~= r;
    }
    s.locksRead = true;
}

/// `AKICK #channel LIST` (cs_akick.cpp): Number, Mask, Reason.
private void parseAkicks(AnopeGrammar g, const string[] seg, ref ChannelSnapshot s) {
    auto fail = segmentFailure(g, seg);
    if (fail == "denied" && seg.length == 1) { s.akicksDenied = true; return; }
    if (fail == "unsupported" && seg.length == 1) { s.unsupported["akick"] = true; return; }
    if (fail.length) { s.problems ~= "akick_" ~ fail; return; }
    string[] caps;
    if (lineIs(g, M_AKICK_EMPTY, seg[0], caps) || lineIs(g, M_AKICK_NO_MATCH, seg[0], caps)) {
        if (seg.length == 1) s.akicksRead = true;
        else s.problems ~= "akick_unexpected_lines";
        return;
    }
    if (!lineIs(g, M_AKICK_HEADER, seg[0], caps)) { s.problems ~= "akick_unrecognised"; return; }
    bool ended;
    size_t i;
    for (i = 1; i < seg.length; ++i) {
        auto l = seg[i];
        if (lineIs(g, M_AKICK_END, l)) { ended = true; ++i; break; }
        AkickRow r;
        if (flexibleRow(g, F_AKICK_ROW_REASON, l, caps) && caps.length == 3) {
            if (!parseUint(caps[0], r.number)) { s.problems ~= "akick_unparsed_row"; return; }
            r.mask = caps[1].strip;
            r.reason = caps[2].strip;
        } else if (flexibleRow(g, F_AKICK_ROW, l, caps) && caps.length == 2) {
            if (!parseUint(caps[0], r.number)) { s.problems ~= "akick_unparsed_row"; return; }
            r.mask = caps[1].strip;
        } else {
            if (i == 1 && isHeaderRow(g, "Number", l)) continue;
            auto t = tokens(l);
            if (t.length < 2 || !parseUint(t[0], r.number)) { s.problems ~= "akick_unparsed_row"; return; }
            r.mask = t[1];
            r.reason = restAfter(l, 2);
        }
        s.akicks ~= r;
    }
    if (!ended || i != seg.length) { s.problems ~= "akick_unterminated"; return; }
    s.akicksRead = true;
}

/// Provider of every ACCESS LIST entry, only from proof:
///  - XOP: the entry number is in that tier's own LIST (cs_xop lists only
///    `access/xop` entries of exactly that type) — built-in and probed
///    custom tiers alike;
///  - FLAGS on 2.1: the number is in `FLAGS LIST` without ALL, which lists
///    only `access/flags` entries;
///  - ACCESS: numeric `AccessSerialize()` (only AccessChanAccess prints one
///    among the core providers);
///  - FLAGS on 2.0 (FLAGS LIST covers every provider): the ACCESS value V
///    is a sorted duplicate-free letter set (FlagsChanAccess serialises a
///    std::set<char>), the FLAGS LIST value of the same number is exactly V
///    (FlagsChanAccess::DetermineFlags returns AccessSerialize; an XOP entry
///    of an unconfigured type has no privileges and reads "(none)"), every
///    invoked tier list was read, and V cannot be an XOP type holding the
///    entry: V contains a lower-case letter (cs_xop stores
///    `source.command.upper()`, AccessSerialize returns it), or V names a
///    HELP-proven tier whose complete listing omitted the entry.
/// Anything else (third-party providers included) stays unproven: it is
/// shown nowhere as an editable entry and disables writes.
private void resolveProviders(AnopeGrammar g, ref ChannelSnapshot s) {
    foreach (ref e; s.entries) {
        if (auto t = e.number in s.tierOf) {
            e.provider = icmp(*t, e.value) == 0 ? "xop" : "";
            e.value = *t;
        } else if (g.v21 && s.flagsRead && (e.number in s.flagsNumbers)) e.provider = "flags";
        else if (isNumber(e.value)) e.provider = "access";
        else if (!g.v21 && s.tiersRead && s.flagsRead && isFlagSet(e.value)
                && s.flagsValue.get(e.number, "") == e.value && tierExcludes(s, e.value))
            e.provider = "flags";
        else e.provider = "";
    }
}

/// `value` cannot be the XOP type of an entry its tier listing omitted.
private bool tierExcludes(const ref ChannelSnapshot s, string value) {
    if (value.any!(c => c >= 'a' && c <= 'z')) return true;
    foreach (k, available; s.tierAvailable) if (icmp(k, value) == 0) return available;
    return false;
}

private bool isFlagSet(string value) {
    if (!isLetters(value)) return false;
    foreach (i; 1 .. value.length) if (value[i - 1] >= value[i]) return false;
    return true;
}

private void parseSnapshot(AnopeGrammar g, ServicesTransaction txn, const ref ServiceFrame frame,
        SnapshotBody[] bodies, ref ChannelSnapshot s) {
    auto plain = servicePlainLines(frame);
    Opener[] openers;
    foreach (b; bodies) openers ~= bodyOpener(g, txn, s.channel, b);
    string[][] segs;
    if (!splitBodies(frame, plain, openers, segs)) { s.problems ~= "unattributable_reply"; return; }
    bool tiersOk = true;
    foreach (k, b; bodies) {
        // An unregistered channel answers every body with the same line.
        if (b.kind != BodyKind.info && s.infoRead && !s.registered) {
            if (segmentFailure(g, segs[k]) != "channel_unregistered" || segs[k].length != 1)
                s.problems ~= "unexpected_reply_unregistered";
            continue;
        }
        final switch (b.kind) {
            case BodyKind.info: parseInfo(g, txn, segs[k], s); break;
            case BodyKind.status: parseStatus(g, segs[k], s); break;
            case BodyKind.levels: parseLevels(g, segs[k], s); break;
            case BodyKind.access: parseAccess(g, segs[k], s); break;
            case BodyKind.flags: parseFlags(g, segs[k], s); break;
            case BodyKind.xop: if (!parseXop(g, segs[k], b.tier, s)) tiersOk = false; break;
            case BodyKind.modeLocks: parseModeLocks(g, segs[k], s); break;
            case BodyKind.akick: parseAkicks(g, segs[k], s); break;
        }
    }
    if (s.parts & Part.access) {
        s.tiersRead = tiersOk;
        resolveProviders(g, s);
    }
}

// ── Actor authority on one channel ────────────────────────────────────────

/// Evidence for the actor's channel privileges. `allowed` holds only
/// positively established privileges; anything else is unknown unless a
/// gated read was denied by the service.
private struct Authority {
    bool identified;
    bool founder;
    bool superAdmin;
    bool[string] allowed;
    bool[string] denied;
    bool[string] disabled;
    /// Providers of the actor's own entries ("?" = unproven).
    string[] actorProviders;
    string[] actorTiers;
    string actorFlags;
    /// Flag letter → privilege (HELP FLAGS description ↔ HELP LEVELS DESC).
    string[char] flagPrivilege;
    bool flagsMapped;
    /// LEVELS LIST was read: `enabled` holds every privilege it shows that
    /// is not "(disabled)" (AccessGroup::HasPriv is false for disabled ones).
    bool levelsKnown;
    bool[string] enabled;
}

private struct Cap {
    string state;
    string reason;
    /// FLAGS write whose changed letters must each map to a requestable
    /// actor privilege (cs_flags.cpp DoModify) before anything is sent.
    bool flagsSubset;
}

/// Only allowed and service_checked capabilities may reach a native send;
/// unknown, denied and unsupported never do.
private bool channelCapRequestable(Cap cap) {
    return cap.state == "allowed" || cap.state == "service_checked";
}

private Authority deriveAuthority(ServicesTransaction txn, const ref ChannelSnapshot s) {
    Authority a;
    auto actor = txn.actor;
    a.identified = actor.state == ServicesActorState.account && actor.account.length > 0;
    if (!a.identified || !s.registered) return a;
    a.founder = s.statusFounder || (s.founder.length > 0 && txn.sameNick(s.founder, actor.account));
    a.superAdmin = s.statusSuper;
    a.levelsKnown = s.levelsRead;
    foreach (name, lvl; s.levels) {
        if (lvl == "disabled") a.disabled[name] = true;
        else a.enabled[name] = true;
    }
    // Gated reads the service refused (cs_status / cs_access / cs_mode /
    // cs_akick): the actor lacks that privilege (and the override privs).
    if (s.statusDenied) a.denied["ACCESS_CHANGE"] = true;
    if (s.accessDenied) a.denied["ACCESS_LIST"] = true;
    if (s.locksDenied) a.denied["MODE"] = true;
    if (s.akicksDenied) a.denied["AKICK"] = true;
    if (s.levelsDenied) a.denied["FOUNDER"] = true;

    // The actor's own entries: STATUS names every entry the live user
    // matches (masks included); without it only account entries count.
    AccessRow[] mine;
    if (s.statusRead && s.statusEntries.length) {
        foreach (se; s.statusEntries) {
            AccessRow r;
            r.mask = se[0];
            r.value = se[1];
            foreach (e; s.entries) if (icmp(e.mask, se[0]) == 0) { r = e; break; }
            if (!r.provider.length && isNumber(r.value)) r.provider = "access";
            mine ~= r;
        }
    } else {
        foreach (e; s.entries) if (isAccountMask(e.mask) && txn.sameNick(e.mask, actor.account)) mine ~= e;
    }
    foreach (e; mine) {
        auto provider = e.provider.length ? e.provider : "?";
        if (!a.actorProviders.canFind(provider)) a.actorProviders ~= provider;
        if (e.provider == "access" && s.levelsRead && isNumber(e.value)) {
            // AccessChanAccess::HasPriv: level >= channel level, not disabled.
            auto level = e.value.to!long;
            foreach (name, lvl; s.levels) if (isNumber(lvl) && level >= lvl.to!long) a.allowed[name] = true;
        } else if (e.provider == "xop") {
            if (!a.actorTiers.canFind(e.value)) a.actorTiers ~= e.value;
        } else if (e.provider == "flags") {
            foreach (c; e.value) if (!a.actorFlags.canFind(c)) a.actorFlags ~= c;
        }
    }
    return a;
}

private Cap privState(const ref Authority a, string priv) {
    if (!a.identified) return Cap("denied", "not_identified");
    if (a.superAdmin) return Cap("allowed", "");
    // AccessGroup::HasPriv: founders hold every privilege not disabled.
    if (a.founder) return (priv in a.disabled) ? Cap("denied", "privilege_disabled") : Cap("allowed", "");
    // Actual denials and disabled levels outrank derived evidence.
    if (priv in a.disabled) return Cap("denied", "privilege_disabled");
    if (priv in a.denied) return Cap("denied", "service_denied");
    // Entry-derived privileges (HELP tier lists, flag letters, numeric
    // levels) are proven only while the channel's real LEVELS show the
    // privilege enabled. Non-founders usually cannot read LEVELS: positive
    // evidence then lets the reviewed command reach ChanServ, which checks
    // it itself. Without positive evidence the privilege stays unknown.
    if (priv in a.allowed) {
        if (!a.levelsKnown) return Cap("service_checked", "service_authorization_required");
        return (priv in a.enabled) ? Cap("allowed", "") : Cap("unknown", "levels_unverified");
    }
    return Cap("unknown", "privilege_unverified");
}

/// Privileges the actor positively holds (founder: every listed level).
private string[] actorPrivileges(const ref Authority a, const ref ChannelSnapshot levelsSource) {
    string[] result;
    if (!a.identified) return result;
    if (a.founder || a.superAdmin) {
        foreach (name; levelsSource.levelNames) if (!(name in a.disabled)) result ~= name;
        if (a.founder && !result.canFind("FOUNDER")) result ~= "FOUNDER";
    } else {
        foreach (name, _; a.allowed) if (privState(a, name).state == "allowed") result ~= name;
    }
    sort(result);
    return result;
}

// ── HELP evidence (non-founder XOP/FLAGS actors) ──────────────────────────

/// `HELP <tier>` (cs_xop.cpp OnHelp): the tier's own privileges, printed
/// as indented comma lists. Inherited lower-tier privileges are not
/// printed; they remain unknown.
private string[] parseTierHelp(AnopeGrammar g, const ref ServiceFrame frame, string tier) {
    string[] caps;
    if (!g.matches(g.v21 ? M_XOP_HELP_21 : M_XOP_HELP_20, frame, caps) || !caps.length
            || icmp(caps[0].strip, tier) != 0)
        return null;
    string[] privs;
    foreach (l; servicePlainLines(frame)) {
        if (l.length < 3 || l[0 .. 2] != "  " || l[2] == ' ') continue;
        auto list = l.strip;
        if (list.endsWith(",")) list = list[0 .. $ - 1];
        string[] names;
        bool ok = true;
        foreach (p; list.split(", ")) {
            auto n = p.strip;
            if (!n.length || !(n[0] >= 'A' && n[0] <= 'Z')
                    || !n.all!(c => (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
                ok = false;
                break;
            }
            names ~= n;
        }
        if (ok) privs ~= names;
    }
    return privs;
}

/// `HELP FLAGS`: "  <flag> - <translated privilege description>".
private string[char] parseFlagsHelp(AnopeGrammar g, const ref ServiceFrame frame) {
    string[char] result;
    auto lines = servicePlainLines(frame);
    size_t i = 0;
    while (i < lines.length && !lineIs(g, M_FLAGS_HELP_AVAILABLE, lines[i])) ++i;
    for (++i; i < lines.length; ++i) {
        auto l = lines[i];
        if (l.length < 6 || l[0 .. 2] != "  " || l[2] == ' ' || l[3 .. 6] != " - ") break;
        result[l[2]] = l[6 .. $].strip;
    }
    return result;
}

/// `HELP LEVELS DESC`: privilege name → row text (fixed) or description
/// (flexible), matched by the same translated description as HELP FLAGS.
private string[2][] parseLevelsDesc(AnopeGrammar g, const ref ServiceFrame frame) {
    string[2][] rows;
    auto lines = servicePlainLines(frame);
    size_t i = 0;
    while (i < lines.length && !lineIs(g, M_LEVELS_DESC_HEADER, lines[i])) ++i;
    string[] caps;
    for (++i; i < lines.length; ++i) {
        auto l = lines[i];
        if (!l.strip.length) break;
        if (flexibleRow(g, F_LEVELS_DESC_ROW, l, caps) && caps.length == 3) {
            rows ~= [caps[0].strip, caps[2].strip];
            continue;
        }
        if (isHeaderRow(g, "Name", l)) continue;
        auto t = tokens(l);
        if (!t.length) break;
        rows ~= [t[0], l.strip];
    }
    return rows;
}

private void chanFrame(ServicesTransaction txn, bool viaPeer, ServiceFrameSpec spec, ServiceFrameDone done) {
    if (viaPeer) txn.frameOn(ServiceId.chanServ, spec, done);
    else txn.frame(spec, done);
}

private void runHelpSteps(ServicesTransaction txn, AnopeGrammar g, bool viaPeer, Authority a, string[] steps,
        size_t i, string[char] flagDesc, void delegate(Authority) done) {
    if (i >= steps.length) {
        done(a);
        return;
    }
    auto step = steps[i];
    string body = step.startsWith("tier:") ? "HELP " ~ step[5 .. $] : step == "flags" ? "HELP FLAGS" : "HELP LEVELS DESC";
    chanFrame(txn, viaPeer, readSpec([body]), (ServiceFrame f) {
        if (frameComplete(f)) {
            if (step.startsWith("tier:")) {
                foreach (p; parseTierHelp(g, f, step[5 .. $])) a.allowed[p] = true;
            } else if (step == "flags") {
                flagDesc = parseFlagsHelp(g, f);
            } else if (flagDesc.length) {
                auto rows = parseLevelsDesc(g, f);
                bool mapped = true;
                foreach (c, desc; flagDesc) {
                    string found;
                    size_t hits;
                    foreach (r; rows) {
                        if (r[1] == desc || r[1].endsWith(" " ~ desc)) { found = r[0]; ++hits; }
                    }
                    if (hits == 1) a.flagPrivilege[c] = found;
                    else mapped = false;
                }
                a.flagsMapped = mapped;
                foreach (c; a.actorFlags)
                    if (auto p = c in a.flagPrivilege) a.allowed[*p] = true;
            }
        }
        runHelpSteps(txn, g, viaPeer, a, steps, i + 1, flagDesc, done);
    });
}

/// Adds HELP-derived evidence for actors whose privileges depend on
/// network configuration (XOP tiers, flag letters).
private void helpPhase(ServicesTransaction txn, AnopeGrammar g, bool viaPeer, Authority a,
        void delegate(Authority) done) {
    if (!a.identified || a.founder || a.superAdmin) {
        done(a);
        return;
    }
    string[] steps;
    foreach (t; a.actorTiers) if (steps.length < 2) steps ~= "tier:" ~ t;
    if (a.actorFlags.length) steps ~= ["flags", "levels"];
    runHelpSteps(txn, g, viaPeer, a, steps, 0, null, done);
}

// ── Readers ───────────────────────────────────────────────────────────────

/// `HELP <name>` proofs remembered only inside ONE request (its snapshot and
/// read-back) and only while nothing it depends on changed: the key binds
/// the request id, connection epoch, verified primary endpoint (nick, ident,
/// host, server, version), peer/primary route, observed actor and the
/// transaction's capability generation (own authority, pins, config, epoch
/// and channel state). No other request ever reads an entry; the map only
/// holds booleans and is cleared when it grows past its bound.
private bool[string] gTierProof;

private string tierProofKey(ServicesTransaction txn, bool viaPeer, string name) {
    auto ep = txn.endpoint;
    auto actor = txn.actor;
    return txn.request.requestId ~ "|" ~ txn.epoch ~ "|" ~ ep.nick ~ "!" ~ ep.ident ~ "@" ~ ep.host ~ "/" ~ ep.server
        ~ "/" ~ ep.version_ ~ "|" ~ (viaPeer ? "peer" : "primary") ~ "|" ~ actor.state.to!string ~ ":"
        ~ actor.account ~ "|" ~ txn.capabilityGeneration().to!string ~ "|" ~ name.toUpper;
}

/// Proves (or recalls) whether `name` is an XOP tier by its own HELP. A
/// name is only ever sent as `<name> #c LIST` after this proof: an
/// unproven name may be a renamed or custom command that changes state.
private void proveTierHelp(ServicesTransaction txn, AnopeGrammar g, bool viaPeer, string name,
        void delegate(bool proven) done) {
    const key = tierProofKey(txn, viaPeer, name);
    if (auto known = key in gTierProof) {
        done(*known);
        return;
    }
    chanFrame(txn, viaPeer, readSpec(["HELP " ~ name]), (ServiceFrame hf) {
        if (!frameComplete(hf)) { done(false); return; }
        string[] caps;
        bool proven = g.matches(g.v21 ? M_XOP_HELP_21 : M_XOP_HELP_20, hf, caps) && caps.length
            && icmp(caps[0].strip, name) == 0;
        // A proof whose context moved meanwhile (actor, pins, config,
        // generation) is neither used nor remembered.
        if (tierProofKey(txn, viaPeer, name) != key) {
            done(false);
            return;
        }
        if (gTierProof.length >= 256) gTierProof = null;
        gTierProof[key] = proven;
        done(proven);
    });
}

private void proveStandardTiers(ServicesTransaction txn, AnopeGrammar g, bool viaPeer, size_t i, string[] proven,
        void delegate(string[]) done) {
    if (i >= XOP_QUERY.length) {
        done(proven);
        return;
    }
    auto name = XOP_QUERY[i];
    proveTierHelp(txn, g, viaPeer, name, (bool ok) {
        proveStandardTiers(txn, g, viaPeer, i + 1, ok ? proven ~ name : proven, done);
    });
}

private void readSnapshot(ServicesTransaction txn, AnopeGrammar g, string channel, uint parts, bool viaPeer,
        void delegate(ChannelSnapshot s, ServiceFrame f) done) {
    if (!(parts & Part.access)) {
        readSnapshotWith(txn, g, channel, parts, viaPeer, null, done);
        return;
    }
    proveStandardTiers(txn, g, viaPeer, 0, null, (string[] tiers) {
        readSnapshotWith(txn, g, channel, parts, viaPeer, tiers, done);
    });
}

private void readSnapshotWith(ServicesTransaction txn, AnopeGrammar g, string channel, uint parts, bool viaPeer,
        string[] tiers, void delegate(ChannelSnapshot s, ServiceFrame f) done) {
    auto bodies = snapshotBodies(g, channel, parts, tiers);
    string[] texts;
    foreach (b; bodies) texts ~= b.text;
    chanFrame(txn, viaPeer, readSpec(texts), (ServiceFrame f) {
        ChannelSnapshot s;
        s.channel = channel;
        s.parts = parts;
        if (frameComplete(f)) parseSnapshot(g, txn, f, bodies, s);
        else s.problems ~= f.reason.length ? f.reason : "frame_incomplete";
        if (!(parts & Part.access) || s.problems.length || !s.registered && s.infoRead) {
            done(s, f);
            return;
        }
        auto candidates = tierCandidates(s);
        if (!candidates.length) {
            done(s, f);
            return;
        }
        proveTiers(txn, g, viaPeer, s, candidates, 0, (ChannelSnapshot proven) {
            resolveProviders(g, proven);
            done(proven, f);
        });
    });
}

/// Upper-case letter values nothing else explained: they may be configured
/// custom XOP tiers (cs_xop stores `source.command.upper()`, so a value with
/// a lower-case letter is never an XOP type). At most four are examined.
private string[] tierCandidates(const ref ChannelSnapshot s) {
    string[] values;
    foreach (e; s.entries) {
        if (e.provider.length || !isLetters(e.value) || e.value.any!(c => c >= 'a' && c <= 'z')) continue;
        bool known;
        foreach (k, _; s.tierAvailable) if (icmp(k, e.value) == 0) { known = true; break; }
        if (known || values.canFind!(v => icmp(v, e.value) == 0)) continue;
        if (values.length == 4) return values;
        values ~= e.value;
    }
    return values;
}

/// A candidate becomes a tier only on positive proof: its own `HELP` prints
/// the XOP header for exactly that name, after which `<name> #c LIST` is
/// safe and gives the tier's entry numbers. No help, other help, a partial
/// listing or any failure leaves it unproven (read-only); an unproven name
/// is never invoked.
private void proveTiers(ServicesTransaction txn, AnopeGrammar g, bool viaPeer, ChannelSnapshot s,
        string[] values, size_t i, void delegate(ChannelSnapshot) done) {
    if (i >= values.length) {
        done(s);
        return;
    }
    auto value = values[i];
    void next() { proveTiers(txn, g, viaPeer, s, values, i + 1, done); }
    proveTierHelp(txn, g, viaPeer, value, (bool isTier) {
        auto body = value ~ " " ~ s.channel ~ " LIST";
        if (!isTier || !txn.fits(body)) { next(); return; }
        chanFrame(txn, viaPeer, readSpec([body]), (ServiceFrame lf) {
            if (frameComplete(lf)) {
                auto lines = servicePlainLines(lf);
                ChannelSnapshot probe;
                probe.channel = s.channel;
                if (!segmentFailure(g, lines).length
                        && bodyOpener(g, txn, s.channel, SnapshotBody(BodyKind.xop, body, value))(lines, 0)
                        && parseXop(g, lines, value, probe) && !probe.problems.length) {
                    s.tierAvailable[value] = true;
                    foreach (n, t; probe.tierOf) s.tierOf[n] = t;
                }
            }
            next();
        });
    });
}

/// Snapshot plus the actor's authority (identified actors only).
private void readAuthorized(ServicesTransaction txn, AnopeGrammar g, string channel, uint extraParts, bool viaPeer,
        void delegate(ChannelSnapshot s, Authority a, ServiceFrame f) done) {
    auto actor = txn.actor;
    bool identified = actor.state == ServicesActorState.account && actor.account.length > 0;
    uint parts = identified ? (AUTHORITY_PARTS | extraParts) : (Part.info | extraParts);
    readSnapshot(txn, g, channel, parts, viaPeer, (ChannelSnapshot s, ServiceFrame f) {
        auto a = deriveAuthority(txn, s);
        if (!frameComplete(f) || !s.infoRead || !s.registered) {
            done(s, a, f);
            return;
        }
        helpPhase(txn, g, viaPeer, a, (Authority full) { done(s, full, f); });
    });
}

private bool channelFits(ServicesTransaction txn, string channel) {
    // Longest read body this module sends for a channel.
    return txn.fits("ACCESS " ~ channel ~ " LIST * ALL") && txn.fits("MODE " ~ channel ~ " LOCK LIST");
}

// ── Canonical views ───────────────────────────────────────────────────────

private Json channelInfoView(const ref ChannelSnapshot s) {
    auto j = Json.emptyObject;
    j["kind"] = Json("channel");
    j["channel"] = Json(s.channel);
    j["registered"] = Json(s.registered);
    if (s.registered) {
        if (s.founder.length) j["founder"] = Json(s.founder);
        if (s.description.length) j["description"] = Json(s.description);
        if (s.topicKnown) j["topic"] = Json(s.topic);
        if (s.optionsRead) {
            j["keepTopic"] = Json(s.keepTopic);
            j["topicLocked"] = Json(s.topicLock);
        }
    }
    return j;
}

private Json accessEntries(const ref ChannelSnapshot s) {
    auto entries = Json.emptyArray;
    foreach (e; s.entries) {
        if (!e.provider.length) continue;
        auto j = Json.emptyObject;
        j["id"] = Json(e.number.to!string);
        if (isAccountMask(e.mask)) j["account"] = Json(e.mask);
        else j["mask"] = Json(e.mask);
        j["provider"] = Json(e.provider);
        j["value"] = Json(e.value);
        entries ~= j;
    }
    return entries;
}

private string[] providersOf(const ref ChannelSnapshot s) {
    string[] p;
    foreach (t; XOP_WRITABLE) if (s.tierAvailable.get(t, false)) { p ~= "xop"; break; }
    if (s.accessAvailable) p ~= "access";
    if (s.flagsAvailable) p ~= "flags";
    return p;
}

/// Persisted access state the review depends on (revision basis).
private Json accessBasis(const ref ChannelSnapshot s) {
    auto j = Json.emptyObject;
    j["kind"] = Json("channelAccess");
    j["channel"] = Json(s.channel);
    j["registered"] = Json(s.registered);
    if (s.founder.length) j["founder"] = Json(s.founder);
    j["entries"] = accessEntries(s);
    j["complete"] = Json(s.accessComplete());
    return j;
}

private Json accessView(const ref ChannelSnapshot s, const ref Authority a, const ref ChannelSnapshot levelsSource) {
    auto j = accessBasis(s);
    j["providers"] = jsonStrings(providersOf(s));
    string[] tiers;
    foreach (t; XOP_WRITABLE) if (s.tierAvailable.get(t, false)) tiers ~= t;
    j["xopTiers"] = jsonStrings(tiers);
    auto levels = Json.emptyArray;
    if (levelsSource.levelsRead) {
        foreach (name; levelsSource.levelNames) {
            auto l = Json.emptyObject;
            l["privilege"] = Json(name);
            l["level"] = Json(levelsSource.levels[name]);
            levels ~= l;
        }
    }
    j["levels"] = levels;
    j["actorPrivileges"] = jsonStrings(actorPrivileges(a, levelsSource));
    if (a.founder) j["actorIsFounder"] = Json(true);
    return j;
}

private Json modeLocksView(const ref ChannelSnapshot s) {
    auto j = Json.emptyObject;
    j["kind"] = Json("modeLocks");
    j["channel"] = Json(s.channel);
    auto locks = Json.emptyArray;
    foreach (l; s.locks) {
        auto o = Json.emptyObject;
        o["mode"] = Json([l.mode].idup);
        o["adding"] = Json(l.adding);
        if (l.param.length) o["parameter"] = Json(l.param);
        o["sensitive"] = Json(l.mode == 'k');
        locks ~= o;
    }
    j["locks"] = locks;
    return j;
}

private Json akickView(const ref ChannelSnapshot s) {
    auto j = Json.emptyObject;
    j["kind"] = Json("channelAkicks");
    j["channel"] = Json(s.channel);
    auto entries = Json.emptyArray;
    foreach (r; s.akicks) {
        auto o = Json.emptyObject;
        o["id"] = Json(r.number.to!string);
        o["mask"] = Json(r.mask);
        if (r.reason.length) o["reason"] = Json(r.reason);
        entries ~= o;
    }
    j["entries"] = entries;
    return j;
}

/// Channel-key lock parameters: never in generic details.
private string[] lockSecrets(const ref ChannelSnapshot s) {
    string[] hidden;
    foreach (l; s.locks) if (l.mode == 'k' && l.param.length) hidden ~= l.param;
    if (s.modeLockInfo.length) hidden ~= s.modeLockInfo;
    return hidden;
}

// ── Capabilities ──────────────────────────────────────────────────────────

private Cap registeredPriv(const ref ChannelSnapshot s, const ref Authority a, string priv) {
    if (!a.identified) return Cap("denied", "not_identified");
    if (!s.registered) return Cap("unsupported", "channel_unregistered");
    return privState(a, priv);
}

/// Prefix character of channel operator status (`PREFIX=(qaohv)~&@%+`).
private char opPrefix(ServicesTransaction txn) {
    auto p = txn.isupport("PREFIX");
    auto close = p.indexOf(')');
    if (p.length > 2 && p[0] == '(' && close > 0) {
        auto modes = p[1 .. close];
        auto chars = p[close + 1 .. $];
        auto at = modes.indexOf('o');
        if (at >= 0 && at < chars.length) return chars[at];
    }
    return '@';
}

private Cap registerCap(ServicesTransaction txn, const ref ChannelSnapshot s, const ref Authority a) {
    if (!a.identified) return Cap("denied", "not_identified");
    if (!s.infoRead) return Cap("unknown", "channel_state_unknown");
    if (s.registered) return Cap("unsupported", "already_registered");
    string prefixes;
    if (!txn.ownChannelStatus(s.channel, prefixes)) return Cap("denied", "not_in_channel");
    // cs_register.cpp: c->HasUserStatus(u, "OP") — the op mode itself.
    if (!prefixes.canFind(opPrefix(txn))) return Cap("denied", "not_channel_operator");
    return Cap("allowed", "");
}

private Cap accessWriteCap(const ref ChannelSnapshot s, const ref Authority a, string provider) {
    if (!a.identified) return Cap("denied", "not_identified");
    if (!s.registered) return Cap("unsupported", "channel_unregistered");
    if (provider == "xop" && !XOP_WRITABLE.any!(t => s.tierAvailable.get(t, false)))
        return Cap("unsupported", "provider_unavailable");
    if (provider == "access" && !s.accessAvailable) return Cap("unsupported", "provider_unavailable");
    if (provider == "flags" && !s.flagsAvailable) return Cap("unsupported", "provider_unavailable");
    if (!s.accessComplete()) return Cap("unknown", "access_list_incomplete");
    // Founders bypass the XOP/ACCESS rank checks and every flag check.
    if (a.founder || a.superAdmin) return Cap("allowed", "");
    auto change = privState(a, "ACCESS_CHANGE");
    if (change.state == "denied") return change;
    const requestable = channelCapRequestable(change);
    if (provider == "flags") {
        // FLAGS skips the rank comparison when the actor's own highest entry
        // is a flags entry and checks each changed flag against the actor's
        // own privileges (cs_flags.cpp DoModify): flagChangeCap decides.
        if (requestable && a.flagsMapped && a.actorProviders.length
                && a.actorProviders.all!(p => p == "flags"))
            return change.state == "allowed" ? Cap("allowed", "flags_subset", true)
                : Cap("service_checked", "service_authorization_required", true);
        return Cap("unknown", "rank_unverifiable");
    }
    // XOP/ACCESS compare the target with the actor's highest entry by the
    // configured privilege ranks/tier order, which a user cannot read. With
    // ACCESS_CHANGE evidence and a resolved own entry of this provider,
    // ChanServ's own rank/target checks decide the reviewed ADD/DEL.
    if (requestable && a.actorProviders.canFind(provider))
        return Cap("service_checked", "service_authorization_required");
    return Cap("unknown", "rank_unverifiable");
}

private Json capJson(Cap c) {
    return serviceCapability(c.state, c.reason);
}

private void putCap(ref Json caps, ServiceAction action, Cap c) {
    putServiceCapability(caps, action, c.state, c.reason);
}

private Json accessCapabilities(const ref ChannelSnapshot s, const ref Authority a) {
    auto caps = Json.emptyObject;
    putCap(caps, ServiceAction.channelAccessList, s.accessDenied ? Cap("denied", "service_denied")
        : s.accessRead ? Cap("allowed", "") : Cap("unknown", "access_list_unavailable"));
    // Prefer a proven provider, then a service-checked one, then the
    // non-requestable states.
    Cap best = Cap("unknown", "rank_unverifiable");
    foreach (p; ["xop", "access", "flags"]) {
        auto c = accessWriteCap(s, a, p);
        if (c.state == "allowed") { best = c; break; }
        if (best.state == "service_checked") continue;
        if (c.state == "service_checked" || c.state == "denied" || c.state == "unsupported") best = c;
    }
    putCap(caps, ServiceAction.channelAccessSet, best);
    putCap(caps, ServiceAction.channelAccessRemove, best);
    return caps;
}

private Json providerCapabilities(const ref ChannelSnapshot s, const ref Authority a) {
    auto j = Json.emptyObject;
    foreach (p; ["xop", "access", "flags"]) j[p] = capJson(accessWriteCap(s, a, p));
    return j;
}

private Json infoCapabilities(ServicesTransaction txn, const ref ChannelSnapshot s, const ref Authority a) {
    auto caps = Json.emptyObject;
    putCap(caps, ServiceAction.channelInfo, Cap("allowed", ""));
    putCap(caps, ServiceAction.channelRegister, registerCap(txn, s, a));
    putCap(caps, ServiceAction.channelTopicSet, registeredPriv(s, a, "TOPIC"));
    putCap(caps, ServiceAction.channelTopicLock, registeredPriv(s, a, "TOPIC"));
    putCap(caps, ServiceAction.channelKeepTopic, registeredPriv(s, a, "SET"));
    return caps;
}

private Cap modeLockCap(const ref ChannelSnapshot s, const ref Authority a) {
    if (s.unsupported.get("modeLocks", false)) return Cap("unsupported", "module_unavailable");
    return registeredPriv(s, a, "MODE");
}

private Cap akickCap(const ref ChannelSnapshot s, const ref Authority a) {
    if (s.unsupported.get("akick", false)) return Cap("unsupported", "module_unavailable");
    return registeredPriv(s, a, "AKICK");
}

/// Capability failure before anything is sent.
private void completeCap(ServicesTransaction txn, Cap c) {
    txn.complete(c.state == "denied" ? ServiceStatus.rejected : ServiceStatus.unavailable,
        c.reason.length ? c.reason : "permission_" ~ c.state);
}

// ── Acknowledgement classification ────────────────────────────────────────

private enum AckKind { accepted, rejected, info }

private struct AckRule {
    string id;
    AckKind kind;
    string reason;
}

private struct Ack {
    /// "accepted", "rejected", "partial", "unknown" (unrecognised text) or
    /// "none" (no reply between the fences).
    string state;
    string reason;
    /// Captures of every accepted line, in order.
    string[][] accepted;
    string[] rejections;
}

private AckRule[] commonRules(AnopeGrammar g) {
    AckRule[] r = [
        AckRule(M_ACCESS_DENIED, AckKind.rejected, "denied"),
        AckRule(M_CHAN_NOT_REGISTERED, AckKind.rejected, "channel_unregistered"),
        AckRule(M_CHAN_SUSPENDED, AckKind.rejected, "channel_suspended"),
        AckRule(M_IDENTIFY_REQUIRED, AckKind.rejected, "not_identified"),
        AckRule(g.v21 ? M_READ_ONLY_21 : M_READ_ONLY_20, AckKind.rejected, "read_only"),
    ];
    foreach (id; g.v21 ? M_UNKNOWN_21 : M_UNKNOWN_20) r ~= AckRule(id, AckKind.rejected, "unsupported");
    if (!g.v21) foreach (id; M_DISABLED_20) r ~= AckRule(id, AckKind.rejected, "read_only");
    return r;
}

private Ack classify(AnopeGrammar g, const string[] lines, AckRule[] rules) {
    Ack ack;
    rules ~= commonRules(g);
    bool unknown;
    size_t i = 0;
    while (i < lines.length) {
        if (!lines[i].strip.length) { ++i; continue; }
        bool matched;
        foreach (r; rules) {
            string[] caps;
            size_t used;
            if (!matchAt(g, r.id, lines, i, caps, used)) continue;
            matched = true;
            if (r.kind == AckKind.accepted) ack.accepted ~= caps;
            else if (r.kind == AckKind.rejected) ack.rejections ~= r.reason;
            i += used;
            break;
        }
        if (!matched) { unknown = true; ++i; }
    }
    if (ack.accepted.length && ack.rejections.length) ack.state = "partial";
    else if (ack.accepted.length) ack.state = "accepted";
    else if (ack.rejections.length) ack.state = "rejected";
    else ack.state = lines.any!(l => l.strip.length > 0) ? "unknown" : "none";
    if (ack.rejections.length) ack.reason = ack.rejections[0];
    else if (unknown) ack.reason = "unrecognised_reply";
    return ack;
}

/// Readback evaluation shared by every persisted write.
private void completeWrite(ServicesTransaction txn, Ack ack, bool readbackOk, bool expected, bool changed,
        Json data, string revision, Json caps, string[] details) {
    ServiceStatus status;
    string reason;
    if (!readbackOk) {
        status = ack.state == "rejected" ? ServiceStatus.rejected : ServiceStatus.unconfirmed;
        reason = ack.state == "rejected" ? ack.reason : ack.state == "accepted" ? "readback_unavailable" : "no_recognized_reply";
        txn.complete(status, reason, Json.undefined, "", Json.undefined, details);
        return;
    }
    switch (ack.state) {
        case "accepted":
            status = expected ? ServiceStatus.confirmed : ServiceStatus.unconfirmed;
            reason = expected ? "" : "readback_mismatch";
            break;
        case "rejected":
            status = ServiceStatus.rejected;
            reason = changed ? "partial" : ack.reason;
            break;
        case "partial":
            status = ServiceStatus.rejected;
            reason = "partial";
            break;
        default:
            // State observed without a recognised acknowledgement never
            // becomes this request's success.
            status = ServiceStatus.unconfirmed;
            reason = expected ? "observed_without_ack" : "no_recognized_reply";
            break;
    }
    txn.complete(status, reason, data, revision, caps, details);
}

// ── Operation plumbing ────────────────────────────────────────────────────

private abstract class ChannelOperation : ServicesOperation {
    bool supports(const ref ServicesEndpoint endpoint) {
        return grammarFor(endpoint.version_).supported;
    }
}

private bool prologue(ServicesTransaction txn, out AnopeGrammar g, out string channel) {
    g = grammarFor(txn.endpoint.version_);
    channel = serviceParam(txn, "channel");
    if (!channelFits(txn, channel)) {
        txn.complete(ServiceStatus.rejected, "line_too_long");
        return false;
    }
    return true;
}

private bool boolParam(ServicesTransaction txn, string key) {
    return serviceParam(txn, key) == "true";
}

/// IRC formatting removed (for comparing a requested topic with INFO).
private string plainText(string s) {
    string r;
    for (size_t i = 0; i < s.length; ++i) {
        auto c = s[i];
        if (c == '\x03') {
            size_t k = 0;
            while (k < 2 && i + 1 < s.length && isDigit(s[i + 1])) { ++i; ++k; }
            if (k && i + 2 < s.length && s[i + 1] == ',' && isDigit(s[i + 2])) {
                ++i;
                k = 0;
                while (k < 2 && i + 1 < s.length && isDigit(s[i + 1])) { ++i; ++k; }
            }
            continue;
        }
        if (c == '\x02' || c == '\x1D' || c == '\x1F' || c == '\x16' || c == '\x0F' || c == '\x11' || c == '\x1E')
            continue;
        r ~= c == '\x1B' ? ' ' : c;
    }
    return r;
}

/// `prefix` is the verified pseudoclient (or the services server itself).
private bool isServicePrefix(ServicesTransaction txn, string prefix, ServicesEndpoint ep) {
    auto bang = prefix.indexOf('!');
    auto at = prefix.indexOf('@');
    if (bang > 0 && at > bang)
        return txn.sameNick(prefix[0 .. bang], ep.nick) && prefix[bang + 1 .. at] == ep.ident
            && icmp(prefix[at + 1 .. $], ep.host) == 0;
    return icmp(prefix, ep.server) == 0;
}

/// cs_topic Set → Channel::ChangeTopic sends from `ci->WhoSends()`: the
/// assigned BotServ bot when there is one, else ChanServ (2.1
/// regchannel.cpp WhoSends; 2.0 the same, inspircd3 SVSTOPIC). True when
/// the frame holds the exact TOPIC from the verified ChanServ pin (no bot
/// assigned, `botPrefix` empty) or from exactly the WHOIS-verified assigned
/// bot `botPrefix` (nick!ident@host).
private bool topicObserved(ServicesTransaction txn, const ref ServiceFrame f, string channel, string topic,
        string botPrefix) {
    foreach (e; f.effects) {
        if (e.command != "TOPIC" || !e.params.length || !sameChannel(txn, e.params[0], channel)) continue;
        auto text = e.params.length >= 2 ? e.params[1] : "";
        if (text != topic) continue;
        if (!botPrefix.length ? isServicePrefix(txn, e.prefix, txn.endpoint) : samePrefix(txn, e.prefix, botPrefix))
            return true;
    }
    return false;
}

/// nick!ident@host equality (casemapped nick, exact ident, host ASCII-fold).
private bool samePrefix(ServicesTransaction txn, string a, string b) {
    auto ab = a.indexOf('!'), aa = a.indexOf('@'), bb = b.indexOf('!'), ba = b.indexOf('@');
    if (ab <= 0 || aa <= ab || bb <= 0 || ba <= bb) return false;
    return txn.sameNick(a[0 .. ab], b[0 .. bb]) && a[ab + 1 .. aa] == b[bb + 1 .. ba]
        && icmp(a[aa + 1 .. $], b[ba + 1 .. $]) == 0;
}

/// Topic text Anope would re-join differently: its command parser splits on
/// spaces and joins parameters with one space (command.cpp), so leading,
/// trailing or doubled spaces could never be observed verbatim.
private bool canonicalSpacing(string text) {
    return !text.length || (text[0] != ' ' && text[$ - 1] != ' ' && !text.canFind("  "));
}

private bool findAccount(ServicesTransaction txn, const ref ChannelSnapshot s, string account, out AccessRow row) {
    foreach (e; s.entries) {
        if (e.provider.length && isAccountMask(e.mask) && txn.sameNick(e.mask, account)) {
            row = e;
            return true;
        }
    }
    return false;
}

private bool sameFlagSet(string a, string b) {
    auto x = a.dup;
    auto y = b.dup;
    sort(cast(ubyte[]) x);
    sort(cast(ubyte[]) y);
    return x == y;
}

/// Raw lines of a snapshot frame may be attached as details only when it
/// carried neither INFO (2.1 show_all prints `Mode lock: <string incl. key>`,
/// possibly wrapped) nor MODE LOCK LIST (key parameters): failures of those
/// reads cannot prove which lines hold a key, so they report structured
/// reasons only.
private bool exposesRawDetails(uint parts) {
    return !(parts & (Part.info | Part.modeLocks));
}

private void readFailed(ServicesTransaction txn, const ref ChannelSnapshot s, const ref ServiceFrame f) {
    string reason = !frameComplete(f) ? (f.reason.length ? f.reason : "frame_incomplete")
        : s.problems.length ? s.problems[0] : "unrecognised_reply";
    auto status = !frameComplete(f) && f.outcome == ServiceFrameOutcome.unavailable && !txn.dispatched
        ? ServiceStatus.unavailable : ServiceStatus.unconfirmed;
    txn.complete(status, reason, Json.undefined, "", Json.undefined,
        exposesRawDetails(s.parts) ? safeDetails(txn, f.lines, lockSecrets(s)) : null);
}

// ── ChanServ: INFO / REGISTER / topic options ─────────────────────────────

private final class ChannelInfoOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            auto view = channelInfoView(s);
            txn.complete(ServiceStatus.confirmed, "", view, servicesRevision(txn, view), infoCapabilities(txn, s, a));
        });
    }
}

private final class ChannelRegisterOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            if (!requireServicesRevision(txn, servicesRevision(txn, channelInfoView(s)))) return;
            auto cap = registerCap(txn, s, a);
            if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
            auto desc = serviceParam(txn, "description");
            auto body = "REGISTER " ~ channel ~ (desc.length ? " " ~ desc : "");
            if (!txn.fits(body)) { txn.complete(ServiceStatus.rejected, "line_too_long"); return; }
            txn.frame(writeSpec(txn, body, ServiceFrameKind.ordinary), (ServiceFrame w) {
                if (!frameComplete(w)) { completeIncomplete(txn, w); return; }
                auto ack = classify(g, servicePlainLines(w), [
                    AckRule(M_REGISTERED, AckKind.accepted, ""),
                    AckRule(M_ALREADY_REGISTERED, AckKind.rejected, "already_registered"),
                    AckRule(M_REGISTER_NOT_OP, AckKind.rejected, "not_channel_operator"),
                    AckRule(M_REGISTER_UNCONFIRMED, AckKind.rejected, "account_unconfirmed"),
                    AckRule(M_REGISTER_LOCAL, AckKind.rejected, "local_channel"),
                    AckRule(M_CHAN_NOT_IN_USE, AckKind.rejected, "channel_not_in_use"),
                ]);
                auto details = safeDetails(txn, w.lines, null);
                readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot rb, Authority ra, ServiceFrame rf) {
                    bool ok = frameComplete(rf) && rb.infoRead;
                    bool expected = ok && rb.registered && rb.founder.length
                        && txn.sameNick(rb.founder, txn.actor.account);
                    auto view = channelInfoView(rb);
                    completeWrite(txn, ack, ok, expected, false, view, servicesRevision(txn, view),
                        infoCapabilities(txn, rb, ra), details);
                });
            });
        });
    }
}

/// TOPIC <#c> LOCK|UNLOCK and SET KEEPTOPIC <#c> ON|OFF: acknowledged
/// option toggles with INFO Options read-back.
private final class ChannelOptionOperation : ChannelOperation {
    private bool topicLock;

    this(bool topicLock) { this.topicLock = topicLock; }

    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        auto enabled = boolParam(txn, "enabled");
        readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            if (!requireServicesRevision(txn, servicesRevision(txn, channelInfoView(s)))) return;
            auto cap = registeredPriv(s, a, topicLock ? "TOPIC" : "SET");
            if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
            auto current = topicLock ? s.topicLock : s.keepTopic;
            if (s.optionsRead && current == enabled) { txn.complete(ServiceStatus.rejected, "unchanged"); return; }
            auto body = topicLock ? "TOPIC " ~ channel ~ (enabled ? " LOCK" : " UNLOCK")
                : "SET KEEPTOPIC " ~ channel ~ (enabled ? " ON" : " OFF");
            string okId = topicLock ? (enabled ? M_TOPICLOCK_ON : M_TOPICLOCK_OFF)
                : (enabled ? M_KEEPTOPIC_ON : M_KEEPTOPIC_OFF);
            txn.frame(writeSpec(txn, body, ServiceFrameKind.ordinary), (ServiceFrame w) {
                if (!frameComplete(w)) { completeIncomplete(txn, w); return; }
                auto ack = classify(g, servicePlainLines(w), [AckRule(okId, AckKind.accepted, "")]);
                auto details = safeDetails(txn, w.lines, null);
                readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot rb, Authority ra, ServiceFrame rf) {
                    bool ok = frameComplete(rf) && rb.infoRead && rb.optionsRead;
                    auto after = topicLock ? rb.topicLock : rb.keepTopic;
                    auto view = channelInfoView(rb);
                    completeWrite(txn, ack, ok, ok && after == enabled, ok && after != current, view,
                        servicesRevision(txn, view), infoCapabilities(txn, rb, ra), details);
                });
            });
        });
    }
}

/// TOPIC <#c> SET [topic]: Anope sends no reply on success, so the proof
/// is the exact TOPIC from the client that `ChannelInfo::WhoSends()` uses:
/// the assigned bot (BotServ INFO, then WHOIS on the verified services
/// server, both BEFORE the write) or, with none assigned, the ChanServ pin.
private final class ChannelTopicSetOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        auto topic = serviceParam(txn, "topic");
        auto topicLen = txn.isupport("TOPICLEN");
        if (isNumber(topicLen) && topic.length > topicLen.to!long) {
            txn.complete(ServiceStatus.rejected, "topic_too_long");
            return;
        }
        if (!canonicalSpacing(topic)) {
            txn.complete(ServiceStatus.rejected, "noncanonical_spacing");
            return;
        }
        readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            if (!requireServicesRevision(txn, servicesRevision(txn, channelInfoView(s)))) return;
            auto cap = registeredPriv(s, a, "TOPIC");
            if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
            if (s.topicKnown && s.topic == topic && plainText(topic) == topic) {
                // An identical topic produces no observable TOPIC.
                txn.complete(ServiceStatus.rejected, "unchanged");
                return;
            }
            auto body = "TOPIC " ~ channel ~ " SET" ~ (topic.length ? " " ~ topic : "");
            if (!txn.fits(body)) { txn.complete(ServiceStatus.rejected, "line_too_long"); return; }
            auto rules = [AckRule(M_CHAN_NOT_IN_USE, AckKind.rejected, "channel_not_in_use")];

            void write(string botPrefix) {
                ServiceFrameTerminal terminal = (const ref ServiceFrame fr) {
                    return topicObserved(txn, fr, channel, topic, botPrefix)
                        || classify(g, servicePlainLines(fr), rules.dup).state == "rejected";
                };
                txn.frame(writeSpec(txn, body, ServiceFrameKind.observe, terminal), (ServiceFrame w) {
                    if (!frameComplete(w)) {
                        txn.complete(ServiceStatus.unconfirmed,
                            w.outcome == ServiceFrameOutcome.deadline && txn.dispatched ? "no_effect_observed"
                                : (w.reason.length ? w.reason : "frame_incomplete"),
                            Json.undefined, "", Json.undefined, safeDetails(txn, w.lines, null));
                        return;
                    }
                    auto ack = classify(g, servicePlainLines(w), rules.dup);
                    if (ack.state != "rejected" && topicObserved(txn, w, channel, topic, botPrefix)) {
                        ack.state = "accepted";
                        ack.reason = "";
                    }
                    auto details = safeDetails(txn, w.lines, null);
                    readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot rb, Authority ra, ServiceFrame rf) {
                        bool ok = frameComplete(rf) && rb.infoRead;
                        // INFO hides Last topic on secret channels without INFO.
                        bool expected = ok && (!rb.topicKnown || rb.topic == plainText(topic));
                        auto view = channelInfoView(rb);
                        completeWrite(txn, ack, ok, expected, false, view, servicesRevision(txn, view),
                            infoCapabilities(txn, rb, ra), details);
                    });
                });
            }

            // Which client will send the TOPIC: BotServ INFO #c (CS→BS peer
            // read). No BotServ at all ⇒ no bot can be assigned ⇒ ChanServ.
            txn.frameOn(ServiceId.botServ, readSpec(["INFO " ~ channel]), (ServiceFrame bf) {
                if (bf.outcome == ServiceFrameOutcome.unavailable && bf.reason == "service_absent") {
                    write("");
                    return;
                }
                if (!frameComplete(bf)) {
                    txn.complete(ServiceStatus.unavailable, "bot_assignment_unknown");
                    return;
                }
                auto b = parseBotInfo(g, txn, channel, servicePlainLines(bf));
                if (!b.read || !b.registered) {
                    // Denied BotServ INFO (no INFO privilege) or unrecognised
                    // text: the sender cannot be proven, so nothing is sent.
                    txn.complete(ServiceStatus.unavailable, b.denied ? "bot_assignment_denied" : "bot_assignment_unknown");
                    return;
                }
                if (!b.assigned.length) {
                    write("");
                    return;
                }
                txn.whois(b.assigned, (ServicesWhois who) {
                    if (!who.complete || !who.present || !txn.sameNick(who.nick.length ? who.nick : b.assigned, b.assigned)
                            || icmp(who.server, txn.endpoint.server) != 0 || !who.ident.length || !who.host.length) {
                        txn.complete(ServiceStatus.unavailable, "assigned_bot_unverified");
                        return;
                    }
                    write(b.assigned ~ "!" ~ who.ident ~ "@" ~ who.host);
                });
            });
        });
    }
}

// ── ChanServ: people & access ─────────────────────────────────────────────

private AckRule[] accessAddRules(string provider) {
    AckRule[] r = [
        AckRule(M_NEVEROP_21, AckKind.rejected, "target_refuses_access"),
        AckRule(M_MASKS_FORBIDDEN, AckKind.rejected, "masks_forbidden"),
        AckRule(M_CHANNELS_FORBIDDEN, AckKind.rejected, "channels_forbidden"),
        AckRule(M_NICK_NOT_REGISTERED, AckKind.rejected, "target_unregistered"),
        AckRule(M_NICK_NOT_IN_USE, AckKind.rejected, "target_not_online"),
        AckRule(M_ACCESS_LIMIT_21, AckKind.rejected, "access_limit"),
        AckRule(M_ACCESS_LIMIT_DEEP_21, AckKind.rejected, "access_limit"),
        AckRule(M_ACCESS_LIMIT_20, AckKind.rejected, "access_limit"),
        AckRule(M_ACCESS_MALFORMED_21, AckKind.rejected, "malformed_mask"),
    ];
    switch (provider) {
        case "xop":
            r ~= AckRule(M_XOP_ADDED, AckKind.accepted, "");
            break;
        case "access":
            r ~= [AckRule(M_ACCESS_ADDED_LEVEL, AckKind.accepted, ""), AckRule(M_ACCESS_ADDED_PRIV, AckKind.accepted, ""),
                AckRule(M_ACCESS_NONZERO, AckKind.rejected, "invalid_level"),
                AckRule(M_ACCESS_LEVEL_RANGE, AckKind.rejected, "invalid_level")];
            break;
        default:
            r ~= [AckRule(M_FLAGS_SET, AckKind.accepted, ""), AckRule(M_FLAGS_REMOVED, AckKind.accepted, ""),
                AckRule(M_FLAGS_CANNOT, AckKind.rejected, "flag_not_permitted"),
                AckRule(M_ACCESS_NOT_FOUND, AckKind.rejected, "not_found")];
            break;
    }
    return r;
}

private AckRule[] accessDelRules(string provider) {
    switch (provider) {
        case "xop":
            return [AckRule(M_XOP_DELETED, AckKind.accepted, ""), AckRule(M_XOP_NOT_FOUND, AckKind.rejected, "not_found"),
                AckRule(M_XOP_EMPTY, AckKind.rejected, "not_found")];
        case "access":
            return [AckRule(M_ACCESS_DELETED, AckKind.accepted, ""),
                AckRule(M_ACCESS_NOT_FOUND, AckKind.rejected, "not_found"),
                AckRule(M_ACCESS_EMPTY, AckKind.rejected, "not_found")];
        default:
            // `-*` leaves flags the actor may not remove: still an entry.
            return [AckRule(M_FLAGS_REMOVED, AckKind.accepted, ""),
                AckRule(M_FLAGS_SET, AckKind.rejected, "partially_removed"),
                AckRule(M_FLAGS_CANNOT, AckKind.rejected, "flag_not_permitted"),
                AckRule(M_ACCESS_NOT_FOUND, AckKind.rejected, "not_found")];
    }
}

/// The flag letters a FLAGS change string touches.
private string flagLetters(string changes) {
    string r;
    foreach (c; changes) if (c != '+' && c != '-' && !r.canFind(c)) r ~= c;
    return r;
}

/// Every changed letter must map to a privilege the actor holds
/// (allowed) or positively evidences (service_checked); service_checked in
/// `base` or any letter makes the whole change service_checked.
private Cap flagChangeCap(const ref Authority a, string letters, Cap base) {
    bool checked = base.state == "service_checked";
    foreach (c; letters) {
        auto p = c in a.flagPrivilege;
        if (p is null) return Cap("unknown", "flag_privilege_unverified");
        const st = privState(a, *p).state;
        if (st == "service_checked") checked = true;
        else if (st != "allowed") return Cap("unknown", "flag_privilege_unverified");
    }
    return checked ? Cap("service_checked", "service_authorization_required") : Cap("allowed", "");
}

private final class ChannelAccessListOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            auto view = accessView(s, a, s);
            view["providerCapabilities"] = providerCapabilities(s, a);
            bool complete = !s.registered || (s.accessRead && s.problems.length == 0);
            void finish() {
                txn.complete(complete ? ServiceStatus.confirmed : ServiceStatus.unconfirmed,
                    complete ? "" : (s.accessDenied ? "denied" : s.problems.length ? s.problems[0] : "access_list_unavailable"),
                    view, servicesRevision(txn, accessBasis(s)), accessCapabilities(s, a),
                    null);
            }
            if (!s.registered || !s.flagsAvailable) { finish(); return; }
            // The flag letters this network actually configures, for the
            // native FLAGS editor (cs_flags.cpp OnHelp, translated texts).
            txn.frame(readSpec(["HELP FLAGS"]), (ServiceFrame hf) {
                auto defs = Json.emptyArray;
                if (frameComplete(hf)) {
                    auto parsed = parseFlagsHelp(g, hf);
                    auto letters = parsed.keys;
                    sort(cast(ubyte[]) letters);
                    foreach (c; letters) {
                        auto d = Json.emptyObject;
                        d["flag"] = Json([c].idup);
                        d["description"] = Json(parsed[c]);
                        defs ~= d;
                    }
                }
                view["flagDefinitions"] = defs;
                finish();
            });
        });
    }
}

private final class ChannelAccessSetOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        auto account = serviceParam(txn, "account");
        auto targetNick = serviceParam(txn, "targetNick");
        auto provider = serviceParam(txn, "provider");
        auto value = serviceParam(txn, "value");
        readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            if (!requireServicesRevision(txn, servicesRevision(txn, accessBasis(s)), accessView(s, a, s),
                    accessCapabilities(s, a)))
                return;
            auto cap = accessWriteCap(s, a, provider);
            if (channelCapRequestable(cap) && provider == "xop" && !s.tierAvailable.get(value, false))
                cap = Cap("unsupported", "tier_unavailable");
            if (channelCapRequestable(cap) && cap.flagsSubset) cap = flagChangeCap(a, flagLetters(value), cap);
            if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
            AccessRow before;
            bool had = findAccount(txn, s, account, before);
            // Without a verified live nick the only safe subject is the
            // account's existing entry (offline management from the table):
            // Anope resolves a bare name as a nick (possibly another
            // account's grouped nick or a live user), so a new grant needs
            // the fresh WHOIS of `targetNick`.
            if (!targetNick.length && !had) { txn.complete(ServiceStatus.rejected, "target_unverified"); return; }
            if (had && provider == "xop" && before.provider == "xop" && icmp(before.value, value) == 0) {
                txn.complete(ServiceStatus.rejected, "unchanged");
                return;
            }
            auto subject = had ? before.mask : account;
            FlagChange[] changes;
            if (provider == "flags" && !parseFlagChanges(value, changes)) {
                txn.complete(ServiceStatus.rejected, "invalid_flags");
                return;
            }
            void send(string body) {
                if (!txn.fits(body)) { txn.complete(ServiceStatus.rejected, "line_too_long"); return; }
                verifyServicesTarget(txn, account, targetNick, (bool targetOk) {
                    if (!targetOk) return;
                    txn.frame(writeSpec(txn, body, ServiceFrameKind.ordinary), (ServiceFrame w) {
                        if (!frameComplete(w)) { completeIncomplete(txn, w); return; }
                        auto ack = classify(g, servicePlainLines(w), accessAddRules(provider));
                        auto details = safeDetails(txn, w.lines, null);
                        readSnapshot(txn, g, channel, Part.info | Part.access, false, (ChannelSnapshot rb, ServiceFrame rf) {
                            bool ok = frameComplete(rf) && rb.infoRead && rb.accessComplete();
                            AccessRow after;
                            bool has = findAccount(txn, rb, account, after);
                            bool expected;
                            switch (provider) {
                                case "xop":
                                    expected = has && after.provider == "xop" && icmp(after.value, value) == 0;
                                    break;
                                case "access":
                                    expected = has && after.provider == "access" && isNumber(after.value)
                                        && after.value.to!long == value.to!long;
                                    break;
                                default:
                                    // Every requested letter's final state, not
                                    // the acknowledged set (cs_flags skips
                                    // letters it cannot apply silently).
                                    expected = flagChangesHold(changes, has && after.provider == "flags",
                                        has ? after.value : "");
                                    break;
                            }
                            bool changed = had != has || (has && (after.provider != before.provider || after.value != before.value));
                            auto view = accessView(rb, a, s);
                            completeWrite(txn, ack, ok, expected, changed, view, servicesRevision(txn, accessBasis(rb)),
                                accessCapabilities(rb, a), details);
                        });
                    });
                });
            }
            switch (provider) {
                case "xop": send(value ~ " " ~ channel ~ " ADD " ~ subject); break;
                case "access": send("ACCESS " ~ channel ~ " ADD " ~ subject ~ " " ~ value.to!int.to!string); break;
                default:
                    // Every letter must be one this network actually defines
                    // (HELP FLAGS) — founders included, since cs_flags
                    // ignores unknown letters yet still acknowledges.
                    txn.frame(readSpec(["HELP FLAGS"]), (ServiceFrame hf) {
                        if (!frameComplete(hf)) {
                            txn.complete(ServiceStatus.unavailable, "flag_definitions_unavailable");
                            return;
                        }
                        auto defs = parseFlagsHelp(g, hf);
                        foreach (c; changes) if (!(c.letter in defs)) {
                            txn.complete(ServiceStatus.rejected, "unknown_flag");
                            return;
                        }
                        send("FLAGS " ~ channel ~ " MODIFY " ~ subject ~ " " ~ flagsWire(changes));
                    });
                    break;
            }
        });
    }
}

private struct FlagChange {
    bool add;
    char letter;
}

/// `+AO-v` → explicit per-letter changes (protocol already limits the
/// value to letters and signs).
private bool parseFlagChanges(string value, out FlagChange[] changes) {
    bool add = true;
    bool signed;
    foreach (c; value) {
        if (c == '+' || c == '-') { add = c == '+'; signed = true; continue; }
        if (!isAlpha(c)) return false;
        changes ~= FlagChange(add, c);
    }
    return signed && changes.length > 0;
}

/// Wire form with a sign before every letter and a trailing sign:
/// cs_flags DoModify tries `FindPrivilege(flags.substr(i))` at each letter,
/// so no suffix of this string can ever be a privilege name.
private string flagsWire(const FlagChange[] changes) {
    string w;
    foreach (c; changes) {
        w ~= c.add ? '+' : '-';
        w ~= c.letter;
    }
    return w ~ (changes.length && changes[$ - 1].add ? "+" : "-");
}

/// Final state of every requested letter holds in the read-back flag set
/// (an absent entry has no flags). The last change of a letter wins.
private bool flagChangesHold(const FlagChange[] changes, bool isFlagsEntry, string flags) {
    bool[char] want;
    foreach (c; changes) want[c.letter] = c.add;
    foreach (letter, add; want) {
        if (add && !(isFlagsEntry && flags.canFind(letter))) return false;
        if (!add && isFlagsEntry && flags.canFind(letter)) return false;
    }
    return true;
}

private final class ChannelAccessRemoveOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        auto account = serviceParam(txn, "account");
        auto targetNick = serviceParam(txn, "targetNick");
        auto provider = serviceParam(txn, "provider");
        auto tier = serviceParam(txn, "value");
        readAuthorized(txn, g, channel, 0, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            if (!requireServicesRevision(txn, servicesRevision(txn, accessBasis(s)), accessView(s, a, s),
                    accessCapabilities(s, a)))
                return;
            AccessRow before;
            if (!findAccount(txn, s, account, before)) { txn.complete(ServiceStatus.stale, "entry_absent"); return; }
            if (before.provider != provider || (tier.length && icmp(before.value, tier) != 0)) {
                txn.complete(ServiceStatus.stale, "entry_changed");
                return;
            }
            Cap cap;
            // Removing one's own XOP/ACCESS entry needs no privilege
            // (cs_xop DoDel, cs_access Execute/DoDel).
            if (provider != "flags" && txn.sameNick(account, txn.actor.account) && s.accessComplete())
                cap = Cap("allowed", "");
            else cap = accessWriteCap(s, a, provider);
            if (channelCapRequestable(cap) && cap.flagsSubset) cap = flagChangeCap(a, before.value, cap);
            if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
            string body;
            switch (provider) {
                case "xop": body = before.value ~ " " ~ channel ~ " DEL " ~ before.mask; break;
                case "access": body = "ACCESS " ~ channel ~ " DEL " ~ before.mask; break;
                default: body = "FLAGS " ~ channel ~ " MODIFY " ~ before.mask ~ " -*"; break;
            }
            if (!txn.fits(body)) { txn.complete(ServiceStatus.rejected, "line_too_long"); return; }
            verifyServicesTarget(txn, account, targetNick, (bool targetOk) {
                if (!targetOk) return;
                txn.frame(writeSpec(txn, body, ServiceFrameKind.ordinary), (ServiceFrame w) {
                    if (!frameComplete(w)) { completeIncomplete(txn, w); return; }
                    auto ack = classify(g, servicePlainLines(w), accessDelRules(provider));
                    auto details = safeDetails(txn, w.lines, null);
                    readSnapshot(txn, g, channel, Part.info | Part.access, false, (ChannelSnapshot rb, ServiceFrame rf) {
                        bool ok = frameComplete(rf) && rb.infoRead && rb.accessComplete();
                        AccessRow after;
                        bool has = findAccount(txn, rb, account, after);
                        bool changed = !has || after.provider != before.provider || after.value != before.value;
                        auto view = accessView(rb, a, s);
                        completeWrite(txn, ack, ok, !has, changed, view, servicesRevision(txn, accessBasis(rb)),
                            accessCapabilities(rb, a), details);
                    });
                });
            });
        });
    }
}

// ── ChanServ: mode locks ──────────────────────────────────────────────────

private struct LockRequest {
    bool adding;
    char mode;
    string param;
    char type;
}

/// ISUPPORT CHANMODES class of `mode` ('A'..'D'), 0 when unknown.
private char chanModeType(ServicesTransaction txn, char mode) {
    auto groups = txn.isupport("CHANMODES").split(',');
    if (groups.length < 4) return 0;
    foreach (i, grp; groups[0 .. 4]) if (grp.canFind(mode)) return cast(char)('A' + i);
    return 0;
}

private bool isStatusMode(ServicesTransaction txn, char mode) {
    auto p = txn.isupport("PREFIX");
    auto close = p.indexOf(')');
    return p.length > 2 && p[0] == '(' && close > 0 && p[1 .. close].canFind(mode);
}

/// Validates a browser lock change against ISUPPORT and the fresh lock
/// list, and builds the exact `MODE #c LOCK` argument. Removal parameters
/// of key/limit-style modes come from the current list (2.1 NeedsParam:
/// list and always-parameter modes; 2.0: every non-regular mode), so the
/// browser never has to send a channel key back.
private bool planLocks(ServicesTransaction txn, AnopeGrammar g, string change, string modes,
        const ref ChannelSnapshot s, out LockRequest[] reqs, out string wire, out string reason, out bool stale) {
    if (txn.isupport("CHANMODES").split(',').length < 4) { reason = "chanmodes_unknown"; return false; }
    auto t = tokens(modes);
    if (!t.length) { reason = "empty_change"; return false; }
    auto params = t[1 .. $];
    size_t pi = 0;
    bool adding = true;
    foreach (c; t[0]) {
        if (c == '+') { adding = true; continue; }
        if (c == '-') { adding = false; continue; }
        if (!isAlpha(c)) { reason = "invalid_mode"; return false; }
        if (isStatusMode(txn, c)) { reason = "status_mode_unsupported"; return false; }
        auto type = chanModeType(txn, c);
        if (!type) { reason = "unknown_mode"; return false; }
        auto r = LockRequest(adding, c, "", type);
        if (change == "remove") {
            if (type == 'A') {
                if (pi >= params.length) { reason = "missing_parameter"; return false; }
                r.param = params[pi++];
            }
            bool found;
            string stored;
            foreach (l; s.locks) {
                if (l.adding != adding || l.mode != c || (type == 'A' && l.param != r.param)) continue;
                found = true;
                stored = l.param;
                break;
            }
            if (!found) { reason = "lock_absent"; stale = true; return false; }
            bool needs = type == 'B' || (type == 'C' && !g.v21);
            if (type != 'A' && needs) {
                if (!stored.length) { reason = "lock_parameter_unknown"; return false; }
                r.param = stored;
            }
        } else {
            if (!adding && type != 'D') { reason = "negative_parameter_lock_unsupported"; return false; }
            if (adding && type != 'D') {
                if (pi >= params.length) { reason = "missing_parameter"; return false; }
                r.param = params[pi++];
            }
        }
        reqs ~= r;
    }
    if (pi != params.length) { reason = "unexpected_parameter"; return false; }
    if (!reqs.length) { reason = "empty_change"; return false; }
    string letters, args;
    int sign = -1;
    foreach (r; reqs) {
        if (sign != (r.adding ? 1 : 0)) {
            letters ~= r.adding ? '+' : '-';
            sign = r.adding ? 1 : 0;
        }
        letters ~= r.mode;
        if (r.param.length) args ~= " " ~ r.param;
    }
    wire = letters ~ args;
    return true;
}

private AckRule[] lockRules(AnopeGrammar g) {
    if (g.v21)
        return [
            AckRule(M_MLOCK_LOCKED_21, AckKind.accepted, ""), AckRule(M_MLOCK_UNLOCKED_21, AckKind.accepted, ""),
            AckRule(M_MLOCK_UNKNOWN_21, AckKind.rejected, "unknown_mode"),
            AckRule(M_MLOCK_MISSING_21, AckKind.rejected, "missing_parameter"),
            AckRule(M_MLOCK_CANNOT_SET_21, AckKind.rejected, "mode_not_permitted"),
            AckRule(M_MLOCK_LIST_FULL_21, AckKind.rejected, "list_full"),
            AckRule(M_MLOCK_LOCKLIST_FULL_21, AckKind.rejected, "mode_lock_list_full"),
            AckRule(M_MLOCK_CANNOT_LOCK_21, AckKind.rejected, "cannot_lock"),
            AckRule(M_MLOCK_NOT_LOCKED_21, AckKind.rejected, "not_locked"),
            AckRule(M_NOTHING_TO_DO, AckKind.rejected, "nothing_to_do"),
        ];
    return [
        AckRule(M_MLOCK_LOCKED_20, AckKind.accepted, ""), AckRule(M_MLOCK_UNLOCKED_20, AckKind.accepted, ""),
        AckRule(M_MLOCK_UNKNOWN_20, AckKind.rejected, "unknown_mode"),
        AckRule(M_MLOCK_MAY_NOT_20, AckKind.rejected, "mode_not_permitted"),
        AckRule(M_MLOCK_MISSING_20, AckKind.rejected, "missing_parameter"),
        AckRule(M_MLOCK_LIST_FULL_20, AckKind.rejected, "list_full"),
        AckRule(M_MLOCK_LOCKLIST_FULL_20, AckKind.rejected, "mode_lock_list_full"),
        AckRule(M_MLOCK_NOT_LOCKED_20, AckKind.rejected, "not_locked"),
        AckRule(M_NOTHING_TO_DO, AckKind.rejected, "nothing_to_do"),
    ];
}

private bool hasLock(const ref ChannelSnapshot s, LockRequest r) {
    foreach (l; s.locks)
        if (l.adding == r.adding && l.mode == r.mode && (!r.param.length || l.param == r.param)) return true;
    return false;
}

private Json modeLockCapabilities(const ref ChannelSnapshot s, const ref Authority a) {
    auto caps = Json.emptyObject;
    putCap(caps, ServiceAction.channelModeLockList, s.locksDenied ? Cap("denied", "service_denied")
        : s.unsupported.get("modeLocks", false) ? Cap("unsupported", "module_unavailable") : Cap("allowed", ""));
    putCap(caps, ServiceAction.channelModeLockChange, modeLockCap(s, a));
    return caps;
}

private Json registeredView(Json view, bool registered) {
    view["registered"] = Json(registered);
    return view;
}

private final class ChannelModeLockListOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        readAuthorized(txn, g, channel, Part.modeLocks, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            if (s.registered && s.unsupported.get("modeLocks", false)) {
                txn.complete(ServiceStatus.unavailable, "module_unavailable");
                return;
            }
            if (s.registered && s.locksDenied) {
                txn.complete(ServiceStatus.rejected, "denied", Json.undefined, "", modeLockCapabilities(s, a));
                return;
            }
            if (s.registered && !s.locksRead) { readFailed(txn, s, f); return; }
            auto view = registeredView(modeLocksView(s), s.registered);
            // Private, session-only view: the key parameter is present but
            // marked sensitive; details are never attached.
            txn.complete(ServiceStatus.confirmed, "", view, servicesRevision(txn, view), modeLockCapabilities(s, a));
        });
    }
}

private final class ChannelModeLockChangeOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        auto change = serviceParam(txn, "change");
        auto modes = serviceParam(txn, "modes");
        readAuthorized(txn, g, channel, Part.modeLocks, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead || (s.registered && !s.locksRead && !s.locksDenied)) {
                readFailed(txn, s, f);
                return;
            }
            if (!requireServicesRevision(txn, servicesRevision(txn, registeredView(modeLocksView(s), s.registered)))) return;
            auto cap = modeLockCap(s, a);
            if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
            LockRequest[] reqs;
            string wire, reason;
            bool stale;
            if (!planLocks(txn, g, change, modes, s, reqs, wire, reason, stale)) {
                txn.complete(stale ? ServiceStatus.stale : ServiceStatus.rejected, reason);
                return;
            }
            auto verb = change == "add" ? "ADD" : change == "remove" ? "DEL" : "SET";
            auto body = "MODE " ~ channel ~ " LOCK " ~ verb ~ " " ~ wire;
            if (!txn.fits(body)) { txn.complete(ServiceStatus.rejected, "line_too_long"); return; }
            // MODE LOCK replies echo lock parameters (keys), possibly wrapped
            // by 2.1 LineWrapper: no raw details at all, structured view only.
            txn.frame(writeSpec(txn, body, ServiceFrameKind.ordinary), (ServiceFrame w) {
                if (!frameComplete(w)) {
                    txn.complete(w.outcome == ServiceFrameOutcome.unavailable && !txn.dispatched
                        ? ServiceStatus.unavailable : ServiceStatus.unconfirmed,
                        w.reason.length ? w.reason : "frame_incomplete");
                    return;
                }
                auto ack = classify(g, servicePlainLines(w), lockRules(g));
                readSnapshot(txn, g, channel, Part.modeLocks, false, (ChannelSnapshot rb, ServiceFrame rf) {
                    string[] details;
                    bool ok = frameComplete(rf) && rb.locksRead;
                    bool expected = ok;
                    foreach (r; reqs) {
                        bool present = hasLock(rb, r);
                        if (change == "remove" ? present : !present) { expected = false; break; }
                    }
                    bool changed = rb.locks.length != s.locks.length;
                    if (!changed)
                        foreach (i, l; rb.locks)
                            if (l != s.locks[i]) { changed = true; break; }
                    rb.registered = true;
                    auto view = registeredView(modeLocksView(rb), true);
                    completeWrite(txn, ack, ok, expected, changed, view, servicesRevision(txn, view),
                        modeLockCapabilities(rb, a), details);
                });
            });
        });
    }
}

// ── ChanServ: AKICK ───────────────────────────────────────────────────────

private Json akickCapabilities(const ref ChannelSnapshot s, const ref Authority a) {
    auto caps = Json.emptyObject;
    putCap(caps, ServiceAction.channelAkickList, s.akicksDenied ? Cap("denied", "service_denied")
        : s.unsupported.get("akick", false) ? Cap("unsupported", "module_unavailable") : Cap("allowed", ""));
    auto write = akickCap(s, a);
    putCap(caps, ServiceAction.channelAkickAdd, write);
    putCap(caps, ServiceAction.channelAkickRemove, write);
    return caps;
}

private final class ChannelAkickListOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        readAuthorized(txn, g, channel, Part.akick, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead) { readFailed(txn, s, f); return; }
            if (s.registered && s.unsupported.get("akick", false)) {
                txn.complete(ServiceStatus.unavailable, "module_unavailable");
                return;
            }
            if (s.registered && s.akicksDenied) {
                txn.complete(ServiceStatus.rejected, "denied", Json.undefined, "", akickCapabilities(s, a));
                return;
            }
            if (s.registered && !s.akicksRead) { readFailed(txn, s, f); return; }
            auto view = registeredView(akickView(s), s.registered);
            txn.complete(ServiceStatus.confirmed, "", view, servicesRevision(txn, view), akickCapabilities(s, a));
        });
    }
}

private final class ChannelAkickChangeOperation : ChannelOperation {
    private bool adding;

    this(bool adding) { this.adding = adding; }

    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        auto mask = adding ? serviceParam(txn, "mask") : "";
        auto reason = adding ? serviceParam(txn, "reason") : "";
        auto entry = adding ? "" : serviceParam(txn, "entry");
        // cs_akick DoAdd: a '#' in a non-account mask switches to realname
        // parsing that consumes the reason — not offered by this UI.
        if (adding && mask.canFind('#')) { txn.complete(ServiceStatus.rejected, "realname_mask_unsupported"); return; }
        readAuthorized(txn, g, channel, Part.akick, false, (ChannelSnapshot s, Authority a, ServiceFrame f) {
            if (!frameComplete(f) || !s.infoRead || (s.registered && !s.akicksRead && !s.akicksDenied)) {
                readFailed(txn, s, f);
                return;
            }
            if (!requireServicesRevision(txn, servicesRevision(txn, registeredView(akickView(s), s.registered)))) return;
            auto cap = akickCap(s, a);
            if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
            string target = mask;
            if (!adding) {
                uint number;
                bool numeric = parseUint(entry, number);
                foreach (r; s.akicks)
                    if (numeric ? r.number == number : icmp(r.mask, entry) == 0) { target = r.mask; break; }
                if (!target.length) { txn.complete(ServiceStatus.stale, "entry_absent"); return; }
            } else {
                foreach (r; s.akicks)
                    if (icmp(r.mask, mask) == 0) { txn.complete(ServiceStatus.rejected, "already_exists"); return; }
            }
            auto body = "AKICK " ~ channel ~ (adding ? " ADD " ~ mask ~ " " ~ reason : " DEL " ~ target);
            if (!txn.fits(body)) { txn.complete(ServiceStatus.rejected, "line_too_long"); return; }
            auto rules = adding
                ? [AckRule(M_AKICK_ADDED, AckKind.accepted, ""), AckRule(M_AKICK_ENFORCED, AckKind.info, ""),
                    AckRule(M_AKICK_EXISTS, AckKind.rejected, "already_exists"),
                    AckRule(M_AKICK_LIMIT_21, AckKind.rejected, "akick_limit"),
                    AckRule(M_AKICK_LIMIT_20, AckKind.rejected, "akick_limit"),
                    AckRule(M_CHAN_EXCEPTED, AckKind.rejected, "excepted")]
                : [AckRule(M_AKICK_DELETED, AckKind.accepted, ""),
                    AckRule(M_AKICK_NOT_FOUND, AckKind.rejected, "not_found"),
                    AckRule(M_AKICK_EMPTY, AckKind.rejected, "not_found")];
            txn.frame(writeSpec(txn, body, ServiceFrameKind.ordinary), (ServiceFrame w) {
                if (!frameComplete(w)) { completeIncomplete(txn, w); return; }
                auto ack = classify(g, servicePlainLines(w), rules);
                auto details = safeDetails(txn, w.lines, null);
                // The acknowledgement names the stored (cleaned) mask.
                auto stored = adding && ack.accepted.length && ack.accepted[0].length ? ack.accepted[0][0].strip : target;
                readSnapshot(txn, g, channel, Part.akick, false, (ChannelSnapshot rb, ServiceFrame rf) {
                    bool ok = frameComplete(rf) && rb.akicksRead;
                    bool present;
                    foreach (r; rb.akicks) if (icmp(r.mask, stored) == 0) { present = true; break; }
                    rb.registered = true;
                    auto view = registeredView(akickView(rb), true);
                    completeWrite(txn, ack, ok, adding ? present : !present, rb.akicks.length != s.akicks.length,
                        view, servicesRevision(txn, view), akickCapabilities(rb, a), details);
                });
            });
        });
    }
}

// ── BotServ ───────────────────────────────────────────────────────────────

private struct BotState {
    bool read;
    bool denied;
    bool registered;
    /// "" = no bot assigned (only meaningful when `read && registered`).
    string assigned;
    bool optionsRead;
    bool greet;
    bool fantasy;
    string problem;
}

private struct BotEntry {
    string nick;
    string realName;
}

/// A catalog message containing `\n` (2.0 splits it into one line each).
private bool multiLineAt(AnopeGrammar g, string msgid, const string[] lines, size_t i, out size_t used) {
    string[] caps;
    if (i < lines.length && g.matches(msgid, lines[i], caps)) { used = 1; return true; }
    foreach (v; g.variants(msgid)) {
        auto parts = v.split('\n');
        if (i + parts.length > lines.length) continue;
        bool ok = true;
        foreach (k, p; parts) if (lines[i + k].strip != p.strip) { ok = false; break; }
        if (ok) { used = parts.length; return true; }
    }
    return false;
}

private bool isBotListNone(AnopeGrammar g, const string[] lines, size_t i, out size_t used) {
    return multiLineAt(g, g.v21 ? M_BOTLIST_NONE_21 : M_BOTLIST_NONE_20, lines, i, used);
}

/// bs_info.cpp channel form: CHAN_INFO_HEADER, "Bot nick", Options with
/// the translated "Greet"/"Fantasy" option names (greet.cpp/fantasy.cpp).
private BotState parseBotInfo(AnopeGrammar g, ServicesTransaction txn, string channel, const string[] seg) {
    BotState b;
    if (!seg.length) { b.problem = "no_reply"; return b; }
    string[] caps;
    if (lineIs(g, M_BS_NOT_VALID, seg[0], caps) && caps.length && sameChannel(txn, caps[0].strip, channel)) {
        if (seg.length == 1) { b.read = true; b.registered = false; }
        else b.problem = "botinfo_unexpected_lines";
        return b;
    }
    if (lineIs(g, M_ACCESS_DENIED, seg[0])) {
        if (seg.length == 1) b.denied = true;
        else b.problem = "botinfo_unexpected_lines";
        return b;
    }
    auto fail = commonFailure(g, seg, 0);
    if (fail.length) { b.problem = "botinfo_" ~ fail; return b; }
    if (!lineIs(g, g.v21 ? M_CHAN_INFO_HEADER_21 : M_CHAN_INFO_HEADER_20, seg[0], caps)
            || !caps.length || !sameChannel(txn, caps[0].strip, channel)) {
        b.problem = "botinfo_unrecognised";
        return b;
    }
    auto rest = seg[1 .. $];
    bool found;
    auto bot = g.infoValueIn(K_BOT_NICK, rest, found);
    if (!found) { b.problem = "botinfo_unrecognised"; return b; }
    b.registered = true;
    b.assigned = isVariant(g, M_BOT_NOT_ASSIGNED_YET, bot) ? "" : bot.strip;
    auto options = g.infoValueIn(K_OPTIONS, rest, found);
    b.optionsRead = true;
    if (found) {
        foreach (o; options.split(',')) {
            if (isVariant(g, O_GREET, o)) b.greet = true;
            if (isVariant(g, O_FANTASY, o)) b.fantasy = true;
        }
    }
    b.read = true;
    return b;
}

/// bs_botlist.cpp: "Bot list:", rows (2.1 Nick/Mask/Real name or FLEXIBLE;
/// 2.0 Nick/Mask with "* " for operator-only bots), "%d bots available."
private bool parseBotList(AnopeGrammar g, const string[] seg, out BotEntry[] bots) {
    size_t used;
    if (isBotListNone(g, seg, 0, used)) return used == seg.length;
    if (!seg.length || !lineIs(g, M_BOTLIST_HEADER, seg[0])) return false;
    string[] caps;
    foreach (i; 1 .. seg.length) {
        auto l = seg[i];
        if (lineIs(g, M_BOTLIST_COUNT, l, caps)) {
            uint n;
            return i + 1 == seg.length && caps.length && parseUint(caps[0], n) && n == bots.length;
        }
        BotEntry e;
        if (flexibleRow(g, F_BOTLIST_ROW, l, caps) && caps.length == 3) {
            e.nick = caps[0].strip;
            e.realName = caps[2].strip;
        } else {
            if (i == 1 && isHeaderRow(g, "Nick", l)) continue;
            auto t = tokens(l);
            if (!g.v21 && t.length && t[0] == "*") t = t[1 .. $];
            if (t.length < 2) return false;
            e.nick = t[0];
            if (g.v21) e.realName = restAfter(l, 2);
        }
        bots ~= e;
    }
    return false;
}

private Opener botInfoOpener(AnopeGrammar g, ServicesTransaction txn, string channel) {
    return (const string[] lines, size_t i) {
        if (i >= lines.length) return false;
        string[] caps;
        if (lineIs(g, M_ACCESS_DENIED, lines[i]) || isReadOnly(g, lines[i]) || isUnknownCommand(g, lines[i]))
            return true;
        if ((lineIs(g, M_BS_NOT_VALID, lines[i], caps) || lineIs(g, g.v21 ? M_CHAN_INFO_HEADER_21
                : M_CHAN_INFO_HEADER_20, lines[i], caps)) && caps.length)
            return sameChannel(txn, caps[0].strip, channel);
        return false;
    };
}

private Opener botListOpener(AnopeGrammar g) {
    return (const string[] lines, size_t i) {
        size_t used;
        return i < lines.length && (lineIs(g, M_BOTLIST_HEADER, lines[i]) || isBotListNone(g, lines, i, used));
    };
}

/// One BotServ frame: `INFO #c` and optionally `BOTLIST`.
private void readBot(ServicesTransaction txn, AnopeGrammar g, string channel, bool withList,
        void delegate(BotState b, BotEntry[] bots, bool listOk, ServiceFrame f) done) {
    string[] bodies = ["INFO " ~ channel];
    Opener[] openers = [botInfoOpener(g, txn, channel)];
    if (withList) {
        bodies ~= "BOTLIST";
        openers ~= botListOpener(g);
    }
    txn.frame(readSpec(bodies), (ServiceFrame f) {
        BotState b;
        BotEntry[] bots;
        bool listOk;
        if (!frameComplete(f)) {
            b.problem = f.reason.length ? f.reason : "frame_incomplete";
            done(b, bots, false, f);
            return;
        }
        string[][] segs;
        if (!splitBodies(f, servicePlainLines(f), openers, segs)) {
            b.problem = "unattributable_reply";
            done(b, bots, false, f);
            return;
        }
        b = parseBotInfo(g, txn, channel, segs[0]);
        if (withList) listOk = parseBotList(g, segs[1], bots);
        done(b, bots, listOk, f);
    });
}

private Json botView(string channel, const ref BotState b) {
    auto j = Json.emptyObject;
    j["kind"] = Json("channelBot");
    j["channel"] = Json(channel);
    j["registered"] = Json(b.registered);
    if (b.registered) {
        j["assignedBot"] = b.assigned.length ? Json(b.assigned) : Json(null);
        if (b.optionsRead) {
            j["greet"] = Json(b.greet);
            j["fantasy"] = Json(b.fantasy);
        }
    }
    return j;
}

/// ChanServ privilege evidence for a BotServ action (bs_assign.cpp ASSIGN,
/// greet.cpp/fantasy.cpp SET, bs_info.cpp INFO).
private Cap botPriv(const ref ChannelSnapshot s, const ref Authority a, const ref BotState b, string priv) {
    if (b.read && !b.registered) return Cap("unsupported", "channel_unregistered");
    if (!s.infoRead) return Cap("unknown", "authority_unavailable");
    return registeredPriv(s, a, priv);
}

private Json botCapabilities(const ref ChannelSnapshot s, const ref Authority a, const ref BotState b) {
    auto caps = Json.emptyObject;
    putCap(caps, ServiceAction.botInfo, b.denied ? Cap("denied", "service_denied") : Cap("allowed", ""));
    auto assign = botPriv(s, a, b, "ASSIGN");
    putCap(caps, ServiceAction.botAssign, assign);
    putCap(caps, ServiceAction.botUnassign, b.read && b.registered && !b.assigned.length
        ? Cap("unsupported", "no_bot_assigned") : assign);
    auto set = botPriv(s, a, b, "SET");
    putCap(caps, ServiceAction.botGreet, set);
    putCap(caps, ServiceAction.botFantasy, set);
    return caps;
}

private final class BotListOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        auto g = grammarFor(txn.endpoint.version_);
        txn.frame(readSpec(["BOTLIST"]), (ServiceFrame f) {
            if (!frameComplete(f)) { completeIncomplete(txn, f); return; }
            BotEntry[] bots;
            if (!parseBotList(g, servicePlainLines(f), bots)) {
                txn.complete(ServiceStatus.unconfirmed, "unrecognised_reply", Json.undefined, "", Json.undefined,
                    safeDetails(txn, f.lines, null));
                return;
            }
            auto entries = Json.emptyArray;
            foreach (b; bots) {
                auto e = Json.emptyObject;
                e["nick"] = Json(b.nick);
                if (b.realName.length) e["description"] = Json(b.realName);
                entries ~= e;
            }
            auto view = Json.emptyObject;
            view["kind"] = Json("bots");
            view["entries"] = entries;
            auto caps = Json.emptyObject;
            putCap(caps, ServiceAction.botList, Cap("allowed", ""));
            txn.complete(ServiceStatus.confirmed, "", view, servicesRevision(txn, view), caps);
        });
    }
}

private final class BotInfoOperation : ChannelOperation {
    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        // ChanServ policy first (peer read lock), then BotServ's own view.
        readAuthorized(txn, g, channel, 0, true, (ChannelSnapshot s, Authority a, ServiceFrame cf) {
            readBot(txn, g, channel, false, (BotState b, BotEntry[] bots, bool listOk, ServiceFrame f) {
                if (!frameComplete(f)) { completeIncomplete(txn, f); return; }
                if (b.denied) {
                    txn.complete(ServiceStatus.rejected, "denied", Json.undefined, "", botCapabilities(s, a, b));
                    return;
                }
                if (!b.read) {
                    txn.complete(ServiceStatus.unconfirmed, b.problem.length ? b.problem : "unrecognised_reply",
                        Json.undefined, "", Json.undefined, safeDetails(txn, f.lines, null));
                    return;
                }
                auto view = botView(channel, b);
                txn.complete(ServiceStatus.confirmed, "", view, servicesRevision(txn, view), botCapabilities(s, a, b));
            });
        });
    }
}

private enum BotChange { assign, unassign, greet, fantasy }

private final class BotChangeOperation : ChannelOperation {
    private BotChange change;

    this(BotChange change) { this.change = change; }

    void run(ServicesTransaction txn) {
        AnopeGrammar g;
        string channel;
        if (!prologue(txn, g, channel)) return;
        auto bot = change == BotChange.assign ? serviceParam(txn, "bot") : "";
        auto enabled = (change == BotChange.greet || change == BotChange.fantasy) && boolParam(txn, "enabled");
        readAuthorized(txn, g, channel, 0, true, (ChannelSnapshot s, Authority a, ServiceFrame cf) {
            if (!frameComplete(cf) || !s.infoRead) { readFailed(txn, s, cf); return; }
            readBot(txn, g, channel, change == BotChange.assign, (BotState b, BotEntry[] bots, bool listOk, ServiceFrame f) {
                if (!frameComplete(f)) { completeIncomplete(txn, f); return; }
                if (b.denied) {
                    // Without BotServ INFO there is no reviewable state and
                    // no read-back path for the change.
                    txn.complete(ServiceStatus.unavailable, "bot_state_unreadable");
                    return;
                }
                if (!b.read) {
                    txn.complete(ServiceStatus.unconfirmed, b.problem.length ? b.problem : "unrecognised_reply",
                        Json.undefined, "", Json.undefined, safeDetails(txn, f.lines, null));
                    return;
                }
                if (!requireServicesRevision(txn, servicesRevision(txn, botView(channel, b)))) return;
                auto cap = botPriv(s, a, b, change == BotChange.assign || change == BotChange.unassign ? "ASSIGN" : "SET");
                if (!channelCapRequestable(cap)) { completeCap(txn, cap); return; }
                string body;
                AckRule[] rules;
                final switch (change) {
                    case BotChange.assign: {
                        if (!listOk) { txn.complete(ServiceStatus.unavailable, "bot_inventory_unavailable"); return; }
                        bool known;
                        foreach (e; bots) if (txn.sameNick(e.nick, bot)) { known = true; break; }
                        if (!known) { txn.complete(ServiceStatus.rejected, "bot_unknown"); return; }
                        if (b.assigned.length && txn.sameNick(b.assigned, bot)) {
                            txn.complete(ServiceStatus.rejected, "already_assigned");
                            return;
                        }
                        body = "ASSIGN " ~ channel ~ " " ~ bot;
                        rules = [AckRule(M_BOT_ASSIGNED, AckKind.accepted, ""),
                            AckRule(M_BOT_ALREADY, AckKind.rejected, "already_assigned"),
                            AckRule(M_BOT_DOES_NOT_EXIST, AckKind.rejected, "bot_unknown")];
                        break;
                    }
                    case BotChange.unassign:
                        if (!b.assigned.length) { txn.complete(ServiceStatus.rejected, "not_assigned"); return; }
                        body = "UNASSIGN " ~ channel;
                        rules = [AckRule(M_BOT_UNASSIGNED, AckKind.accepted, ""),
                            AckRule(M_BOT_NOT_ASSIGNED, AckKind.rejected, "not_assigned"),
                            AckRule(M_BOT_PERSIST, AckKind.rejected, "persist_set")];
                        break;
                    case BotChange.greet:
                    case BotChange.fantasy: {
                        bool greet = change == BotChange.greet;
                        if (b.optionsRead && (greet ? b.greet : b.fantasy) == enabled) {
                            txn.complete(ServiceStatus.rejected, "unchanged");
                            return;
                        }
                        body = "SET " ~ (greet ? "GREET " : "FANTASY ") ~ channel ~ (enabled ? " ON" : " OFF");
                        rules = [AckRule(greet ? (enabled ? M_GREET_ON : M_GREET_OFF) : (enabled ? M_FANTASY_ON : M_FANTASY_OFF),
                            AckKind.accepted, "")];
                        break;
                    }
                }
                if (!txn.fits(body)) { txn.complete(ServiceStatus.rejected, "line_too_long"); return; }
                txn.frame(writeSpec(txn, body, ServiceFrameKind.ordinary), (ServiceFrame w) {
                    if (!frameComplete(w)) { completeIncomplete(txn, w); return; }
                    auto ack = classify(g, servicePlainLines(w), rules);
                    auto details = safeDetails(txn, w.lines, null);
                    // Assignment results are only what BotServ INFO shows
                    // afterwards: BotInfo::Assign unassigns the previous bot
                    // first and a module may veto either step while the
                    // command still acknowledges (src/bots.cpp).
                    readBot(txn, g, channel, false, (BotState rb, BotEntry[] none, bool unused, ServiceFrame rf) {
                        bool ok = frameComplete(rf) && rb.read && rb.registered;
                        bool expected;
                        bool changed;
                        final switch (change) {
                            case BotChange.assign:
                                expected = rb.assigned.length && txn.sameNick(rb.assigned, bot);
                                changed = rb.assigned != b.assigned;
                                if (ok && ack.state == "accepted" && !expected && b.assigned.length && !rb.assigned.length) {
                                    // The old bot left but the new one never arrived.
                                    ack.state = "partial";
                                }
                                break;
                            case BotChange.unassign:
                                expected = !rb.assigned.length;
                                changed = rb.assigned != b.assigned;
                                break;
                            case BotChange.greet:
                                expected = rb.optionsRead && rb.greet == enabled;
                                changed = rb.optionsRead && rb.greet != b.greet;
                                break;
                            case BotChange.fantasy:
                                expected = rb.optionsRead && rb.fantasy == enabled;
                                changed = rb.optionsRead && rb.fantasy != b.fantasy;
                                break;
                        }
                        auto view = botView(channel, rb);
                        completeWrite(txn, ack, ok, ok && expected, changed, view, servicesRevision(txn, view),
                            botCapabilities(s, a, rb), details);
                    });
                });
            });
        });
    }
}

// ── Registration ──────────────────────────────────────────────────────────

/// Installs every channel* and bot* adapter.
void registerChannelServicesOperations() {
    registerServicesOperation(ServiceAction.channelInfo, new ChannelInfoOperation);
    registerServicesOperation(ServiceAction.channelRegister, new ChannelRegisterOperation);
    registerServicesOperation(ServiceAction.channelAccessList, new ChannelAccessListOperation);
    registerServicesOperation(ServiceAction.channelAccessSet, new ChannelAccessSetOperation);
    registerServicesOperation(ServiceAction.channelAccessRemove, new ChannelAccessRemoveOperation);
    registerServicesOperation(ServiceAction.channelTopicSet, new ChannelTopicSetOperation);
    registerServicesOperation(ServiceAction.channelTopicLock, new ChannelOptionOperation(true));
    registerServicesOperation(ServiceAction.channelKeepTopic, new ChannelOptionOperation(false));
    registerServicesOperation(ServiceAction.channelModeLockList, new ChannelModeLockListOperation);
    registerServicesOperation(ServiceAction.channelModeLockChange, new ChannelModeLockChangeOperation);
    registerServicesOperation(ServiceAction.channelAkickList, new ChannelAkickListOperation);
    registerServicesOperation(ServiceAction.channelAkickAdd, new ChannelAkickChangeOperation(true));
    registerServicesOperation(ServiceAction.channelAkickRemove, new ChannelAkickChangeOperation(false));
    registerServicesOperation(ServiceAction.botList, new BotListOperation);
    registerServicesOperation(ServiceAction.botInfo, new BotInfoOperation);
    registerServicesOperation(ServiceAction.botAssign, new BotChangeOperation(BotChange.assign));
    registerServicesOperation(ServiceAction.botUnassign, new BotChangeOperation(BotChange.unassign));
    registerServicesOperation(ServiceAction.botGreet, new BotChangeOperation(BotChange.greet));
    registerServicesOperation(ServiceAction.botFantasy, new BotChangeOperation(BotChange.fantasy));
}

// ── Source-backed parser/transition checks ────────────────────────────────

/// Version strings as the transport records them from CTCP VERSION
/// (bots.cpp: 2.1 `Anope-<ver> <build> -- …`, 2.0 `VERSION Anope-<ver> …`).
enum string CHANNEL_CHECK_VERSION_21 = "Anope-2.1.27-git build #1, compiled Thu Nov 5 2026, flags R -- inspircd -- enc_bcrypt";
enum string CHANNEL_CHECK_VERSION_20 = "VERSION Anope-2.0.20 services.test :inspircd3 - (enc_bcrypt) -- build #1";

/// Entry `i` of a parsed snapshot, or a sentinel so a failed parse reports
/// as a failed check instead of a range error.
private AccessRow entryAt(const ref ChannelSnapshot s, size_t i) {
    if (i < s.entries.length) return s.entries[i];
    AccessRow missing;
    missing.provider = "<missing>";
    missing.value = "<missing>";
    return missing;
}

/// Consumer-visible parser and outcome checks over the exact source reply
/// grammar of both certified versions. Wire into the services-test runner:
/// `channelServicesChecks((name, cond) => ok(name, cond));`
void channelServicesChecks(void delegate(string name, bool cond) ok) {
    auto g21 = grammarFor(CHANNEL_CHECK_VERSION_21);
    auto g20 = grammarFor(CHANNEL_CHECK_VERSION_20);
    ok("channel grammar: 2.1 and 2.0.20 supported", g21.supported && g21.v21 && g20.supported && !g20.v21);

    // 2.1 ACCESS LIST * ALL (fixed layout), FLAGS LIST, XOP tier lists.
    {
        ChannelSnapshot s;
        s.channel = "#c";
        s.parts = Part.access;
        parseAccess(g21, ["Access list for #c:", "Number  Level  Mask   Description",
            "1       SOP    alice", "2       10     bob    helper", "3       AOP    carol",
            "4       HOP    dave", "End of access list"], s);
        parseFlags(g21, ["Flags list for #c", "Number  Mask   Flags  Creator  Created",
            "3       carol  AOP    me       Nov 06 2026 10:00:00 UTC", "End of access list - 1/4 entries shown.",
            "3 access entries from other access systems not shown; use FLAGS #c LIST * ALL to view all access entries."], s);
        bool tiers = parseXop(g21, ["Unknown command QOP. Type /msg ChanServ HELP for help."], "QOP", s)
            && parseXop(g21, ["SOP list for #c", "Number  Mask   Description", "1       alice"], "SOP", s)
            && parseXop(g21, ["#c AOP list is empty."], "AOP", s)
            && parseXop(g21, ["HOP list for #c", "4: dave"], "HOP", s)
            && parseXop(g21, ["No matching entries on #c access list."], "VOP", s);
        s.tiersRead = tiers;
        resolveProviders(g21, s);
        ok("2.1 access: every provider proven from its own listing", s.accessRead && s.flagsRead && s.accessComplete());
        ok("2.1 access: flags entry serialised 'AOP' is not the AOP tier",
            s.entries.length == 4 && s.entries[2].provider == "flags" && s.entries[2].value == "AOP");
        ok("2.1 access: XOP/numeric entries keep their native values",
            entryAt(s, 0).provider == "xop" && entryAt(s, 0).value == "SOP" && entryAt(s, 1).provider == "access"
            && entryAt(s, 1).value == "10" && entryAt(s, 3).provider == "xop" && entryAt(s, 3).value == "HOP");
        ok("2.1 access: unconfigured tier is unavailable, not empty",
            !s.tierAvailable.get("QOP", true) && s.tierAvailable.get("SOP", false)
            && providersOf(s) == ["xop", "access", "flags"]);
        auto basis = accessBasis(s);
        ok("access basis: account entries, no list-time fields",
            basis["entries"].length == 4 && basis["entries"][1]["account"].get!string == "bob"
            && basis["entries"][1]["value"].get!string == "10");
    }

    // Real 2.1 FLAGS LIST without ALL on a channel holding only XOP/ACCESS
    // entries: CHAN_ACCESS_FOREIGN with the actual channel name exceeds the
    // 100-byte LineWrapper width ("FLAGS\x1B#c\x1BLIST\x1B*\x1BALL" cannot
    // break) and splits at the last breaking space before "view".
    {
        ChannelSnapshot s;
        s.channel = "#fixture-services";
        parseFlags(g21, ["No matching entries on #fixture-services access list.",
            "4 access entries from other access systems not shown; use FLAGS #fixture-services LIST * ALL to",
            "view all access entries."], s);
        ok("2.1 flags: wrapped foreign-entry footer is one recognised message",
            s.flagsRead && s.flagsAvailable && !s.flagsNumbers.length && !s.problems.length);
        ChannelSnapshot t;
        t.channel = "#fixture-services";
        parseFlags(g21, ["No matching entries on #fixture-services access list.",
            "4 access entries from other access systems not shown; use FLAGS #fixture-services LIST * ALL to",
            "view all access entries.", "something else"], t);
        ok("2.1 flags: an unknown line after the footer still fails closed", !t.flagsRead && t.problems.length);
        ChannelSnapshot st;
        parseStatus(g21, ["Access for me on #fixture-services:",
            "me matches access entry averyveryverylongaccountname-on-fixture, which has privilege",
            "SOP."], st);
        ok("2.1 status: wrapped match line is parsed", st.statusRead && st.statusEntries.length == 1
            && st.statusEntries[0][1] == "SOP");
    }

    // Translated (de_DE) header/end lines and FLEXIBLE rows.
    {
        ChannelSnapshot s;
        s.channel = "#c";
        parseAccess(g21, ["Zugriffs-Liste von #c:", "1: alice = 5 (friend)", "Ende der Zugangsliste."], s);
        ok("2.1 access: German catalog header/end and flexible row",
            s.accessRead && s.entries.length == 1 && s.entries[0].mask == "alice" && s.entries[0].value == "5");
    }

    // A truncated listing (no end line) never becomes a complete list.
    {
        ChannelSnapshot s;
        s.channel = "#c";
        parseAccess(g21, ["Access list for #c:", "1  10  bob"], s);
        ok("access: missing end line is incomplete", !s.accessRead && !s.accessComplete());
    }

    // 2.0: ACCESS LIST and FLAGS LIST both show every provider; FLAGS needs
    // proof (tier listing / no such tier + DetermineFlags equal to value).
    {
        ChannelSnapshot s;
        s.channel = "#c";
        parseAccess(g20, ["Access list for #c:", "Number  Level  Mask", "1       SOP    alice",
            "2       AOP    carol", "3       Afo    erin", "4       QOP    zed", "5       Fo     old",
            "6       BO     bea", "End of access list"], s);
        parseFlags(g20, ["Flags list for #c", "Number  Mask   Flags   Creator  Created",
            "1       alice  AOft    me       Nov 06 2026", "2       carol  AOP     me       Nov 06 2026",
            "3       erin   Afo     me       Nov 06 2026", "4       zed    (none)  me       Nov 06 2026",
            "5       old    (none)  me       Nov 06 2026", "6       bea    BO      me       Nov 06 2026",
            "End of access list."], s);
        // Only HELP-proven tiers are listed (QOP had no XOP help here).
        bool tiers = parseXop(g20, ["SOP list for #c", "Number  Mask", "1       alice"], "SOP", s)
            && parseXop(g20, ["#c AOP list is empty."], "AOP", s)
            && parseXop(g20, ["#c HOP list is empty."], "HOP", s)
            && parseXop(g20, ["#c VOP list is empty."], "VOP", s);
        s.tiersRead = tiers;
        resolveProviders(g20, s);
        ok("2.0 access: proven AOP tier listing without the entry + equal DetermineFlags proves flags",
            entryAt(s, 1).provider == "flags");
        ok("2.0 access: lower-case letter (never an XOP type) + equal DetermineFlags proves flags",
            entryAt(s, 2).provider == "flags");
        ok("2.0 access: XOP entry of an unconfigured tier reads (none) and stays unproven",
            entryAt(s, 4).provider == "");
        ok("2.0 access: upper-case value without a HELP-proven tier stays unproven, list incomplete",
            entryAt(s, 5).provider == "" && entryAt(s, 3).provider == "" && !s.accessComplete());
        ok("2.0 access: only upper-case unexplained values are tier candidates", tierCandidates(s) == ["QOP", "BO"]);
        ChannelSnapshot noFlags = s;
        noFlags.flagsRead = false;
        noFlags.entries = s.entries.dup;
        resolveProviders(g20, noFlags);
        ok("2.0 access: without FLAGS LIST evidence nothing is labelled flags",
            entryAt(noFlags, 1).provider == "" && entryAt(noFlags, 2).provider == "");
    }

    // LEVELS LIST, STATUS.
    {
        ChannelSnapshot s;
        s.channel = "#c";
        parseLevels(g21, ["Access level settings for channel #c:", "Name           Level",
            "ACCESS_CHANGE  10", "AUTOOP         (disabled)", "FOUNDER        (founder only)"], s);
        ok("levels: numeric, disabled and founder-only levels", s.levelsRead
            && s.levels.get("ACCESS_CHANGE", "") == "10" && s.levels.get("AUTOOP", "") == "disabled"
            && s.levels.get("FOUNDER", "") == "founder");
        parseStatus(g21, ["me is the founder of #c."], s);
        ok("status: founder line", s.statusRead && s.statusFounder);
        ChannelSnapshot d;
        parseStatus(g20, ["Access denied."], d);
        ok("status: denial is ACCESS_CHANGE evidence", d.statusRead && d.statusDenied);
        ChannelSnapshot m;
        parseStatus(g21, ["Access for me on #c:", "me matches access entry me, which has privilege 10.",
            "me matches auto kick entry *!*@bad on #c (spam)."], m);
        ok("status: matched entries kept, akick lines ignored",
            m.statusRead && m.statusEntries.length == 1 && m.statusEntries[0][1] == "10");
    }

    // HELP <tier> privilege lines (cs_xop.cpp OnHelp) are positive evidence only.
    {
        ServiceFrame f;
        f.outcome = ServiceFrameOutcome.completed;
        foreach (t; ["Syntax: SOP channel ADD mask [description]", " ",
                "Maintains the SOP list for a channel. Users who match an access entry on the SOP list "
                ~ "receive the following privileges:", " ", "  AKICK, ASSIGN, AUTOOP, MODE, TOPIC", " "]) {
            ServiceReplyLine l;
            l.text = t;
            l.plain = t;
            f.lines ~= l;
        }
        auto privs = parseTierHelp(g21, f, "SOP");
        ok("help: tier privileges parsed", privs == ["AKICK", "ASSIGN", "AUTOOP", "MODE", "TOPIC"]);
        ok("help: other tier's help is not evidence", parseTierHelp(g21, f, "AOP") is null);
    }

    // MODE LOCK LIST fixed rows: key parameter column vs empty parameter.
    {
        ChannelSnapshot s;
        parseModeLocks(g21, ["Mode locks for #c:", "Mode  Param   Creator  Created",
            "+k    hunter  bob      Nov 06 2026", "+n            bob      Nov 06 2026",
            "-s            bob      Nov 06 2026"], s);
        ok("mode locks: parameter only where the Param column has one", s.locksRead && s.locks.length == 3
            && s.locks[0].mode == 'k' && s.locks[0].param == "hunter" && s.locks[1].param == ""
            && !s.locks[2].adding && s.locks[2].mode == 's');
        ok("mode locks: key marked sensitive and hidden from details", s.locks.length == 3
            && modeLocksView(s)["locks"][0]["sensitive"].get!bool
            && lockSecrets(s) == ["hunter"]);
        ChannelSnapshot n;
        parseModeLocks(g20, ["Channel #c has no mode locks."], n);
        ok("mode locks: none", n.locksRead && !n.locks.length);
    }

    // AKICK LIST.
    {
        ChannelSnapshot s;
        parseAkicks(g21, ["Autokick list for #c:", "Number  Mask     Reason", "1       *!*@bad  spam and abuse",
            "2       troll", "End of autokick list"], s);
        ok("akick: rows with and without reason", s.akicksRead && s.akicks.length == 2
            && s.akicks[0].reason == "spam and abuse" && s.akicks[1].mask == "troll" && !s.akicks[1].reason.length);
    }

    // Acknowledgement classification.
    {
        auto replaced = classify(g21, ["You can only have 2 access entries on a channel."], accessAddRules("xop"));
        ok("ack: XOP limit after replacement is a rejection", replaced.state == "rejected"
            && replaced.reason == "access_limit");
        auto added = classify(g20, ["bob added to #c access list at level 10."], accessAddRules("access"));
        ok("ack: ACCESS ADD acknowledgement", added.state == "accepted");
        auto partial = classify(g21, ["+nt has been locked on #c.", "Unknown modes +Z ignored."], lockRules(g21));
        ok("ack: aggregated MODE LOCK partial success", partial.state == "partial");
        auto per20 = classify(g20, ["+n locked on #c.", "Missing parameter for mode k."], lockRules(g20));
        ok("ack: 2.0 per-mode MODE LOCK partial success", per20.state == "partial");
        auto none = classify(g21, [], [AckRule(M_TOPICLOCK_ON, AckKind.accepted, "")]);
        ok("ack: fence without reply is not success", none.state == "none");
        auto odd = classify(g21, ["Something translated we do not know."], [AckRule(M_TOPICLOCK_ON, AckKind.accepted, "")]);
        ok("ack: unknown text is not success", odd.state == "unknown");
        auto flags = classify(g21, ["You cannot set the v flag.", "Flags for bob on #c set to +AO"], accessAddRules("flags"));
        ok("ack: FLAGS with a refused flag is partial", flags.state == "partial");
        auto akick = classify(g21, ["*!*@bad added to #c autokick list.",
            "AKICK ENFORCE for #c complete; 1 users were affected."], [AckRule(M_AKICK_ADDED, AckKind.accepted, ""),
            AckRule(M_AKICK_ENFORCED, AckKind.info, "")]);
        ok("ack: AKICK add with enforcement", akick.state == "accepted" && akick.accepted.length
            && akick.accepted[0].length && akick.accepted[0][0] == "*!*@bad");
    }

    // BotServ BOTLIST (2.0 operator-only marker, two-line empty reply).
    {
        BotEntry[] bots;
        ok("botlist: 2.0 rows and count", parseBotList(g20, ["Bot list:", "Nick      Mask",
            "* OperBot  oper@services.test", "Helper    helper@services.test", "2 bots available."], bots)
            && bots.length == 2 && bots[0].nick == "OperBot");
        BotEntry[] none;
        ok("botlist: 2.0 empty reply split over two lines", parseBotList(g20, ["There are no bots available at this time.",
            "Ask a Services Operator to create one!"], none) && !none.length);
        BotEntry[] wrong;
        ok("botlist: count mismatch is not a complete inventory", !parseBotList(g21, ["Bot list:",
            "Nick  Mask  Real name", "Helper  h@s  Helper", "2 bots available."], wrong));
    }

    // 2.0 (no +reply, no LineWrapper): INFO's last row must not join the
    // following STATUS founder line into one "%s is the founder of %s."
    // whose nick capture swallows the INFO row.
    {
        string[] text = ["Information for channel #extnet-services:", "        Founder: extfounder",
            "     Registered: Nov 06 2026 10:00:00 UTC", "        Options: Peace, Topic retention",
            "extfounder is the founder of #extnet-services."];
        ServiceFrame f;
        f.outcome = ServiceFrameOutcome.completed;
        foreach (t; text) {
            ServiceReplyLine l;
            l.text = t;
            l.plain = t;
            f.lines ~= l;
        }
        string[][] segs;
        auto split = splitBodies(f, text, [openerOf(g20, [M_CHAN_INFO_HEADER_20]), openerOf(g20, [M_STATUS_FOUNDER])], segs);
        ChannelSnapshot s;
        if (split && segs.length == 2) parseStatus(g20, segs[1], s);
        ok("2.0 segmentation: INFO rows stay INFO, STATUS founder line parses",
            split && segs.length == 2 && segs[0].length == 4 && s.statusRead && s.statusFounder);
        string[] caps;
        size_t used;
        ok("wrap join: a complete following message is never a continuation",
            !matchAt(g21, M_STATUS_FOUNDER, ["Options: Peace", "x is the founder of #c."], 0, caps, used)
            && !matchAt(g20, M_STATUS_FOUNDER, ["Options: Peace x is", "the founder of #c."], 0, caps, used));
    }

    // Body segmentation without +reply: a description cannot forge the next
    // body's opener because openers are anchored whole-line source text.
    {
        ServiceFrame f;
        f.outcome = ServiceFrameOutcome.completed;
        string[] text = ["Access list for #c:", "1  10  bob  Access denied.", "End of access list", "Access denied."];
        foreach (t; text) {
            ServiceReplyLine l;
            l.text = t;
            l.plain = t;
            f.lines ~= l;
        }
        string[][] segs;
        auto split = splitBodies(f, text, [openerOf(g21, [M_ACCESS_HEADER]), openerOf(g21, [M_MLOCK_HEADER])], segs);
        ok("segmentation: row text does not end a body early", split && segs.length == 2 && segs[0].length == 3
            && segs[1] == ["Access denied."]);
    }

    ok("flag sets: only sorted unique letters", isFlagSet("AOv") && !isFlagSet("SOP") && !isFlagSet("AAO"));
    ok("topic compare strips formatting", plainText("\x02hi\x02 \x0304,01there") == "hi there");

    // Key privacy: reads carrying INFO or MODE LOCK LIST never expose raw
    // lines, whatever way they fail (deadline, truncation, split, parse).
    ok("details: INFO / MODE LOCK reads never expose raw lines",
        !exposesRawDetails(AUTHORITY_PARTS) && !exposesRawDetails(Part.modeLocks)
        && !exposesRawDetails(Part.info | Part.access) && exposesRawDetails(Part.akick));
    {
        // A 2.1-wrapped lock row splits the key onto a continuation line the
        // parser rejects: the key is then unknown to lockSecrets, and only
        // the parts gate keeps the raw lines out of details.
        ChannelSnapshot s;
        s.parts = Part.modeLocks;
        parseModeLocks(g21, ["Mode locks for #c:", "Mode  Param", "+k    CANARY", "KEY bob Nov 06 2026"], s);
        ok("details: wrapped key canary is unparsed and raw details stay suppressed",
            !s.locksRead && !lockSecrets(s).canFind("CANARYKEY") && !exposesRawDetails(s.parts));
    }

    // FLAGS: explicit per-letter wire, every requested letter checked.
    {
        FlagChange[] changes;
        ok("flags: delta parsed per letter", parseFlagChanges("+AO-v", changes) && changes.length == 3
            && changes[0].add && changes[1].letter == 'O' && !changes[2].add);
        ok("flags: no suffix can be a privilege name", flagsWire(changes) == "+A+O-v-"
            && flagsWire([FlagChange(true, 'O'), FlagChange(true, 'P')]) == "+O+P+");
        FlagChange[] x;
        parseFlagChanges("+x", x);
        ok("flags: skipped letter is not confirmed by the unchanged set", !flagChangesHold(x, true, "o"));
        ok("flags: applied add and removal hold", flagChangesHold(changes, true, "AOt")
            && !flagChangesHold(changes, true, "AOv"));
        FlagChange[] remove;
        parseFlagChanges("-v", remove);
        ok("flags: removing the last letter removes the entry", flagChangesHold(remove, false, ""));
        FlagChange[] none;
        ok("flags: unsigned or empty values are refused", !parseFlagChanges("AO", none) && !parseFlagChanges("+", none));
    }

    // Non-founder derived privileges: enabled LEVELS prove them; positive
    // evidence the LEVELS cannot confirm is service_checked; denials win.
    {
        Authority none;
        none.identified = true;
        ok("authority: no positive evidence stays unknown",
            privState(none, "TOPIC") == Cap("unknown", "privilege_unverified"));
        Authority a;
        a.identified = true;
        a.allowed["TOPIC"] = true;
        ok("authority: positive evidence without readable LEVELS is service_checked",
            privState(a, "TOPIC") == Cap("service_checked", "service_authorization_required"));
        a.levelsKnown = true;
        ok("authority: readable LEVELS not listing the privilege stay unknown",
            privState(a, "TOPIC") == Cap("unknown", "levels_unverified"));
        a.enabled["TOPIC"] = true;
        ok("authority: derived privilege with enabled LEVELS is allowed", privState(a, "TOPIC").state == "allowed");
        a.denied["TOPIC"] = true;
        ok("authority: actual service denial outranks derived evidence", privState(a, "TOPIC").state == "denied");
        Authority refused;
        refused.identified = true;
        refused.allowed["MODE"] = true;
        refused.denied["MODE"] = true;
        ok("authority: service denial outranks evidence while LEVELS are unreadable",
            privState(refused, "MODE") == Cap("denied", "service_denied"));
        Authority d;
        d.identified = true;
        d.allowed["SET"] = true;
        d.levelsKnown = true;
        d.disabled["SET"] = true;
        ok("authority: disabled level denies", privState(d, "SET").state == "denied");
        Authority anon;
        anon.allowed["TOPIC"] = true;
        ok("authority: unidentified evidence is denied", privState(anon, "TOPIC").state == "denied");
        Authority f;
        f.identified = true;
        f.founder = true;
        f.disabled["TOPIC"] = true;
        ok("authority: founder holds enabled privileges only", privState(f, "MODE").state == "allowed"
            && privState(f, "TOPIC").state == "denied");
        ok("authority: only allowed and service_checked are requestable",
            channelCapRequestable(Cap("allowed", "")) && channelCapRequestable(Cap("service_checked", ""))
            && !channelCapRequestable(Cap("unknown", "")) && !channelCapRequestable(Cap("denied", ""))
            && !channelCapRequestable(Cap("unsupported", "")) && !channelCapRequestable(Cap("", "")));

        // Channel/BotServ privileges carried through the serialised caps.
        ChannelSnapshot reg;
        reg.registered = true;
        reg.infoRead = true;
        Authority sop;
        sop.identified = true;
        sop.allowed["MODE"] = true;
        sop.allowed["AKICK"] = true;
        sop.allowed["ASSIGN"] = true;
        BotState bot;
        Json caps;
        putCap(caps, ServiceAction.channelModeLockChange, modeLockCap(reg, sop));
        putCap(caps, ServiceAction.channelAkickAdd, akickCap(reg, sop));
        putCap(caps, ServiceAction.botAssign, botPriv(reg, sop, bot, "ASSIGN"));
        putCap(caps, ServiceAction.botGreet, botPriv(reg, sop, bot, "SET"));
        ok("authority: service_checked serialises for ChanServ and BotServ actions",
            caps["channelModeLockChange"]["state"].get!string == "service_checked"
            && caps["channelModeLockChange"]["reasonCode"].get!string == "service_authorization_required"
            && caps["channelAkickAdd"]["state"].get!string == "service_checked"
            && caps["botAssign"]["state"].get!string == "service_checked"
            && caps["botGreet"]["state"].get!string == "unknown");
        auto unregistered = reg;
        unregistered.registered = false;
        ok("authority: evidence never makes an unregistered channel writable",
            modeLockCap(unregistered, sop).state == "unsupported");
    }

    // Access writes: founders bypass; same-provider positive evidence is
    // service_checked where ranks cannot be read; FLAGS keeps its subset rule.
    {
        ChannelSnapshot s;
        s.registered = true;
        s.infoRead = true;
        s.accessRead = true;
        s.tiersRead = true;
        s.accessAvailable = true;
        s.flagsAvailable = true;
        s.tierAvailable["SOP"] = true;
        s.tierAvailable["AOP"] = true;
        s.tierAvailable["HOP"] = true;

        Authority founder;
        founder.identified = true;
        founder.founder = true;
        ok("access: founder keeps the proven bypass",
            accessWriteCap(s, founder, "xop") == Cap("allowed", "")
            && accessWriteCap(s, founder, "flags") == Cap("allowed", ""));

        // An SOP whose HELP SOP lists ACCESS_CHANGE; LEVELS unreadable.
        Authority sop;
        sop.identified = true;
        sop.actorProviders = ["xop"];
        sop.actorTiers = ["SOP"];
        sop.allowed["ACCESS_CHANGE"] = true;
        ok("access: SOP with ACCESS_CHANGE evidence may request XOP changes",
            accessWriteCap(s, sop, "xop") == Cap("service_checked", "service_authorization_required"));
        ok("access: other providers stay rank-unverifiable without an own entry there",
            accessWriteCap(s, sop, "access") == Cap("unknown", "rank_unverifiable")
            && accessWriteCap(s, sop, "flags") == Cap("unknown", "rank_unverifiable"));
        auto caps = accessCapabilities(s, sop);
        ok("access: published set/remove capability is service_checked",
            caps["channelAccessSet"]["state"].get!string == "service_checked"
            && caps["channelAccessSet"]["reasonCode"].get!string == "service_authorization_required"
            && caps["channelAccessRemove"]["state"].get!string == "service_checked");
        auto noFlags = s;
        noFlags.flagsAvailable = false;
        ok("access: service_checked outranks a later unsupported provider",
            accessCapabilities(noFlags, sop)["channelAccessSet"]["state"].get!string == "service_checked");

        Authority aop;
        aop.identified = true;
        aop.actorProviders = ["xop"];
        aop.actorTiers = ["AOP"];
        aop.allowed["TOPIC"] = true;
        ok("access: no ACCESS_CHANGE evidence stays unknown",
            accessWriteCap(s, aop, "xop") == Cap("unknown", "rank_unverifiable")
            && accessCapabilities(s, aop)["channelAccessSet"]["state"].get!string == "unknown");
        Authority unresolved;
        unresolved.identified = true;
        unresolved.actorProviders = ["?"];
        unresolved.allowed["ACCESS_CHANGE"] = true;
        ok("access: an unresolved own entry is not same-provider evidence",
            accessWriteCap(s, unresolved, "xop").state == "unknown");

        auto refused = sop;
        refused.denied["ACCESS_CHANGE"] = true;
        ok("access: a service denial wins over SOP evidence",
            accessWriteCap(s, refused, "xop") == Cap("denied", "service_denied")
            && accessCapabilities(s, refused)["channelAccessSet"]["state"].get!string == "denied");
        auto disabled = sop;
        disabled.levelsKnown = true;
        disabled.disabled["ACCESS_CHANGE"] = true;
        ok("access: a disabled ACCESS_CHANGE level wins over SOP evidence",
            accessWriteCap(s, disabled, "xop") == Cap("denied", "privilege_disabled"));
        auto incomplete = s;
        incomplete.tiersRead = false;
        ok("access: an incomplete list is never requestable",
            accessWriteCap(incomplete, sop, "xop") == Cap("unknown", "access_list_incomplete"));
        auto noTiers = s;
        noTiers.tierAvailable = null;
        ok("access: no writable tier is unsupported",
            accessWriteCap(noTiers, sop, "xop") == Cap("unsupported", "provider_unavailable"));

        // Numeric ACCESS actor with readable LEVELS: proven ACCESS_CHANGE,
        // rank still decided by ChanServ.
        Authority numeric;
        numeric.identified = true;
        numeric.actorProviders = ["access"];
        numeric.allowed["ACCESS_CHANGE"] = true;
        numeric.levelsKnown = true;
        numeric.enabled["ACCESS_CHANGE"] = true;
        ok("access: proven ACCESS_CHANGE with unreadable rank is service_checked",
            accessWriteCap(s, numeric, "access") == Cap("service_checked", "service_authorization_required")
            && accessWriteCap(s, numeric, "xop").state == "unknown");

        // FLAGS: flags-only actor, complete letter mapping.
        Authority fl;
        fl.identified = true;
        fl.actorProviders = ["flags"];
        fl.actorFlags = "ft";
        fl.flagsMapped = true;
        fl.flagPrivilege['f'] = "ACCESS_CHANGE";
        fl.flagPrivilege['t'] = "TOPIC";
        fl.flagPrivilege['s'] = "SET";
        fl.allowed["ACCESS_CHANGE"] = true;
        fl.allowed["TOPIC"] = true;
        auto flagsCap = accessWriteCap(s, fl, "flags");
        ok("flags access: evidenced ACCESS_CHANGE is a service_checked subset write",
            flagsCap.state == "service_checked" && flagsCap.flagsSubset);
        ok("flags access: evidenced letters stay service_checked",
            flagChangeCap(fl, "t", flagsCap) == Cap("service_checked", "service_authorization_required"));
        ok("flags access: a letter without positive evidence is blocked",
            flagChangeCap(fl, "ts", flagsCap) == Cap("unknown", "flag_privilege_unverified"));
        ok("flags access: an unmapped letter is blocked",
            flagChangeCap(fl, "z", flagsCap) == Cap("unknown", "flag_privilege_unverified"));
        auto flDenied = fl;
        flDenied.denied["TOPIC"] = true;
        ok("flags access: a denied letter is blocked",
            flagChangeCap(flDenied, "t", accessWriteCap(s, flDenied, "flags")).state == "unknown");
        auto mixed = fl;
        mixed.actorProviders = ["flags", "xop"];
        ok("flags access: a non-flags own entry keeps the rank check",
            accessWriteCap(s, mixed, "flags") == Cap("unknown", "rank_unverifiable"));
        auto unmapped = fl;
        unmapped.flagsMapped = false;
        ok("flags access: an incomplete letter mapping is not requestable",
            accessWriteCap(s, unmapped, "flags").state == "unknown");

        auto proven = fl;
        proven.levelsKnown = true;
        proven.enabled["ACCESS_CHANGE"] = true;
        proven.enabled["TOPIC"] = true;
        auto provenCap = accessWriteCap(s, proven, "flags");
        ok("flags access: proven privileges keep the allowed subset path",
            provenCap == Cap("allowed", "flags_subset", true)
            && flagChangeCap(proven, "t", provenCap) == Cap("allowed", ""));
        auto partly = fl;
        partly.levelsKnown = true;
        partly.enabled["ACCESS_CHANGE"] = true;
        ok("flags access: a readable-LEVELS letter not enabled is blocked",
            flagChangeCap(partly, "t", accessWriteCap(s, partly, "flags")).state == "unknown");
        ok("flags access: the base state carries through an empty letter set",
            flagChangeCap(proven, "", provenCap).state == "allowed"
            && flagChangeCap(fl, "", flagsCap).state == "service_checked");
    }

    ok("topic: Anope-normalised spacing refused before sending",
        canonicalSpacing("a b") && canonicalSpacing("") && !canonicalSpacing("a  b") && !canonicalSpacing(" a")
        && !canonicalSpacing("a "));
}

unittest {
    channelServicesChecks((string name, bool cond) { assert(cond, name); });
}
