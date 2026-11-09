/**
 * Actual-user NickServ, personal HostServ and MemoServ operation adapters.
 *
 * Every action runs as the network owner's live IRC user through
 * `ServicesTransaction` frames (no privileged RPC). Command syntax,
 * acknowledgements and failure texts come from the exact Anope sources the
 * integration certifies: managed 2.1 (`f6e46425b674`) and upstream 2.0.20
 * (`12f1ebee1c03`). Replies are matched through `AnopeGrammar`, which carries
 * every shipped non-fuzzy translation, so a user's NickServ LANGUAGE is never
 * changed and NOTICE/PRIVMSG delivery does not matter.
 *
 * Outcome rules implemented here:
 *  - a verdict needs a recognised service text; quiet frames, fences and
 *    unknown text are `unconfirmed`, never success;
 *  - IDENTIFY/REGISTER/CONFIRM/GROUP report a login only from a
 *    server-stated account change (900/ACCOUNT), never from the ack text;
 *  - SET HIDE is `unconfirmed`/`privacy_unverified` even when accepted: the
 *    owner's INFO always shows hidden fields and never the HIDE flags, so
 *    no read the actor can perform verifies the public view;
 *  - HostServ REQUEST reports pending only in its own acknowledged result
 *    (no requester-side read exists, so `hostInfo` never claims pending);
 *    approval is the assigned vhost in own INFO, distinct from activation;
 *    ON/OFF need the server-observed own host, not the approval reply;
 *  - MemoServ READ reads exactly one number, treats everything after the
 *    header as the (attacker-controlled) body, and reports the read state
 *    only from a fresh LIST; SEND is never re-sent and its receipt never
 *    carries the text.
 *
 * Generic `details` omit own/private INFO, memo bodies and lists, generated
 * confirmation codes, decrypted password echoes and vhost DNS tokens.
 */
module ircfiber.irc.services_identity;

import std.algorithm : canFind, endsWith, sort, startsWith;
import std.array : join, split;
import std.ascii : isDigit;
import std.conv : to;
import std.string : indexOf, lastIndexOf, strip, stripLeft, toLower;
import std.uni : icmp;

import vibe.data.json : Json;

import ircfiber.irc.services;
import ircfiber.irc.services_grammar : AnopeGrammar, candidateAnopeGrammar, ANOPE_20_VERSION, ANOPE_21_VERSION, normalizeServiceText;
import ircfiber.irc.services_operation : HelpEvidence, readServicesActionHelp, servicesRevision,
    requireServicesRevision, verifyServicesTarget, putServiceCapability, serviceParam;
static import ircfiber.irc.services_operation;
import ircfiber.services.config : ServiceId;
import ircfiber.services.protocol : ServiceAction, ServiceStatus;

// ── Registration ───────────────────────────────────────────────────────────

/// Installs every account*, personal host* and memo* adapter.
void registerIdentityServicesOperations() {
    setLegacyAuthTerminalClassifier(&legacyAuthTerminal);
    reg(ServiceAction.accountInfo, &runAccountInfo);
    reg(ServiceAction.accountIdentify, &runAccountIdentify);
    reg(ServiceAction.accountRegister, &runAccountRegister);
    reg(ServiceAction.accountConfirm, &runAccountConfirm);
    reg(ServiceAction.accountGroups, &runAccountGroups);
    reg(ServiceAction.accountGroup, &runAccountGroup);
    reg(ServiceAction.accountRecover, &runAccountRecover);
    reg(ServiceAction.accountPrivacy, &runAccountPrivacy);
    reg(ServiceAction.hostInfo, &runHostInfo);
    reg(ServiceAction.hostRequest, &runHostRequest);
    reg(ServiceAction.hostOn, &runHostOn);
    reg(ServiceAction.hostOff, &runHostOff);
    reg(ServiceAction.memoList, &runMemoList);
    reg(ServiceAction.memoRead, &runMemoRead);
    reg(ServiceAction.memoSend, &runMemoSend);
    reg(ServiceAction.memoDelete, &runMemoDelete);
}

private alias Runner = void function(ServicesTransaction, AnopeGrammar);

private void reg(ServiceAction action, Runner runner) {
    registerServicesOperation(action, new IdentityOperation(runner));
}

private final class IdentityOperation : ServicesOperation {
    private Runner runner;

    this(Runner runner_) {
        runner = runner_;
    }

    /// A candidate family supplies only a decoder. Complete parsed replies
    /// and endpoint-bound command HELP establish usable capabilities.
    bool supports(const ref ServicesEndpoint endpoint) {
        return grammarFor(endpoint.version_).supported;
    }

    void run(ServicesTransaction txn) {
        runner(txn, grammarFor(txn.endpoint.version_));
    }
}

private AnopeGrammar[string] gGrammars;

private AnopeGrammar grammarFor(string versionText) {
    if (auto g = versionText in gGrammars) return *g;
    if (gGrammars.length >= 16) gGrammars = null;
    auto g = candidateAnopeGrammar(versionText);
    gGrammars[versionText] = g;
    return g;
}

// ── Source messages (exact msgids; \x02 bold, \x1F underline, \x1B nobreak) ─

// Common (include/language.h, src/command.cpp).
private enum M_ACCESS_DENIED = "Access denied.";
private enum M_IDENTIFY_REQUIRED = "You must be logged into an account to use that command.";
private enum M_READ_ONLY_21 = "Services are temporarily in read-only mode.";
private enum M_READ_ONLY_20 = "Services are in read-only mode!";
private enum M_TRY_AGAIN_21 = "The \x02%s\x02 command is temporarily unavailable. Please try again later.";
private enum M_NOT_REGISTERED = "Nick \x02%s\x02 isn't registered.";
private enum M_SUSPENDED = "Nick %s is currently suspended.";
private enum M_PASSWORD_INCORRECT = "Password incorrect.";
private enum M_CANNOT_REGISTER = "Nickname \x02%s\x02 may not be registered.";
private enum M_SYNTAX = "Syntax";

private static immutable string[] UNKNOWN_COMMAND = [
    "Unknown command \x02%s\x02. Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02? Type \x02%s\x02 for help.",
    "Unknown command \x02%s\x02. Did you mean \x02%s\x02?",
    "Unknown command \x02%s\x02.",
    "Unknown command \x02%s\x02. \"%s%s HELP\" for help.",
];

// NickServ INFO (ns_info.cpp, nickserv.cpp, ns_suspend.cpp, greet.cpp).
private enum M_INFO_HEADER_21 = "Information about nick \x02%s\x02:";
private enum M_INFO_HEADER_20 = "%s is %s";
private enum M_INFO_SERVICE = "Nick \x02%s\x02 is part of this Network's Services.";
private enum M_INFO_UNCONFIRMED = "%s is an unconfirmed nickname.";
private enum M_INFO_OPER = "%s is a Services Operator of type %s.";
private enum M_INFO_ONLINE = "%s is currently online.";
private enum M_INFO_ACCOUNT_ID = "%s (ID: %zu)";
private enum K_ACCOUNT = "Account";
private enum K_VHOST = "VHost";
private static immutable string[] INFO_KEYS_21 = ["Account", "Account registered", "Nick registered",
    "Online from", "Last seen", "Last seen mask", "Last quit message", "Email address", "VHost", "Expires",
    "Options", "Greet", "Suspended", "Suspended by", "Suspend reason", "Suspended on", "Suspension expires"];
private static immutable string[] INFO_KEYS_20 = ["Account", "Online from", "Last seen address", "Registered",
    "Last seen", "Last quit message", "Email address", "VHost", "Expires", "Options", "Greet", "Suspended",
    "Suspended by", "Suspend reason", "Suspended on", "Suspension expires"];

// IDENTIFY (ns_identify.cpp).
private enum M_IDENTIFY_OK = "Password accepted - you are now recognized.";
private enum M_ALREADY_IDENTIFIED = "You are already identified.";
private enum M_MAX_LOGINS = "Account \x02%s\x02 has already reached the maximum number of simultaneous logins (%u).";

// REGISTER / CONFIRM (ns_register.cpp, nickserv.cpp).
private enum M_REGISTERED = "Nickname \x02%s\x02 registered.";
private enum M_REGISTERED_MASK_20 = "Nickname \x02%s\x02 registered under your user@host-mask: %s";
private enum M_PASSWORD_ECHO_20 = "Your password is \x02%s\x02 - remember this for later use.";
private enum M_CONFIRM_ADMIN_21 = "All new accounts must be confirmed by an administrator. Please wait for your registration to be confirmed.";
private enum M_CONFIRM_CODE_21 = "All new accounts must be confirmed. To confirm your account, type \x02%s\x02.";
private enum M_CONFIRM_MAIL_21 = "All new accounts must be confirmed. To confirm your account, follow the instructions that were emailed to you.";
private enum M_CONFIRM_ADMIN_20 = "All new accounts must be validated by an administrator. Please wait for your registration to be confirmed.";
private enum M_CONFIRM_MAIL_20 = "Your email address is not confirmed. To confirm it, follow the instructions that were emailed to you.";
private enum M_CONFIRMED = "Nick \x02%s\x02 has been confirmed.";
private enum M_EMAIL_CONFIRMED_20 = "Your email address of \x02%s\x02 has been confirmed.";

// GROUP / GLIST (ns_group.cpp).
private enum M_GROUPED_21 = "Your nickname now belongs to the account \x02%s\x02.";
private enum M_GROUPED_20 = "You are now in the group of \x02%s\x02.";
private enum M_GLIST_HEADER_21 = "List of nicknames belonging to your account:";
private enum M_GLIST_HEADER_20 = "List of nicknames in your group:";
private enum M_GLIST_COUNT_21_ONE = "%zu nickname in the account.";
private enum M_GLIST_COUNT_21_MANY = "%zu nicknames in the account.";
private enum M_GLIST_COUNT_20 = "%d nickname(s) in the group.";
private enum M_GLIST_ROW_21 = "\x02{nick}\x02: registered on {registered}";
private enum M_GLIST_ROW_EXPIRES_21 = "\x02{nick}\x02: registered on {registered}; expires in {expires}";

// RECOVER (ns_recover.cpp).
private enum M_RECOVER_HOLD = "Services' hold on \x02%s\x02 has been released.";
private enum M_RECOVER_NONE = "No one is using your nick, and services are not holding it.";
private enum M_RECOVER_GHOST = "Ghost with your nick has been killed.";
private enum M_RECOVER_REGAINED = "You have regained control of \x02%s\x02.";
private enum M_RECOVER_REMOVED_21 = "The user with your nick has been removed. Use this command again to release services's hold on your nick.";
private enum M_RECOVER_REMOVED_20 = "The user with your nick has been removed. Use this command again\nto release services's hold on your nick.";
private enum M_RECOVER_LOGGED_IN = "You have been logged in as \x02%s\x02.";
private enum M_RECOVER_SELF = "You can't %s yourself!";

// SET HIDE (ns_info.cpp CommandNSSetHide): [field][version 0=2.1,1=2.0][0=on,1=off].
private static immutable string[2][2][4] HIDE_ACKS = [
    [["The email address of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The email address of \x02%s\x02 will now be shown in %s INFO displays."],
     ["The E-mail address of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The E-mail address of \x02%s\x02 will now be shown in %s INFO displays."]],
    [["The services access status of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The services access status of \x02%s\x02 will now be shown in %s INFO displays."],
     ["The services access status of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The services access status of \x02%s\x02 will now be shown in %s INFO displays."]],
    [["The last seen user@host mask of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The last seen user@host mask of \x02%s\x02 will now be shown in %s INFO displays."],
     ["The last seen user@host mask of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The last seen user@host mask of \x02%s\x02 will now be shown in %s INFO displays."]],
    [["The last quit message of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The last quit message of \x02%s\x02 will now be shown in %s INFO displays."],
     ["The last quit message of \x02%s\x02 will now be hidden from %s INFO displays.",
      "The last quit message of \x02%s\x02 will now be shown in %s INFO displays."]],
];
private static immutable string[4] PRIVACY_FIELDS = ["email", "status", "mask", "quit"];

// HostServ (hs_request.cpp, hs_on.cpp, hs_off.cpp, language.h).
private enum M_HOST_REQUESTED_21 = "Your vhost \x02%s\x02 has been requested.";
private enum M_HOST_REQUESTED_DNS_21 = "Your vhost \x02%s\x02 has been requested. If the requested vhost is for a valid DNS name you can add a TXT record for %s with the value %s and automatically approve your vhost using \x02%s\x02.";
private enum M_HOST_REQUESTED_20 = "Your vHost has been requested.";
private enum M_HOST_ON = "Your vhost of \x02%s\x02 is now activated.";
private enum M_HOST_ON_IDENT_20 = "Your vhost of \x02%s\x02@\x02%s\x02 is now activated.";
private enum M_HOST_OFF = "Your vhost was removed and the normal cloaking restored.";
private enum M_HOST_NOT_ASSIGNED_21 = "Please contact an Operator to get a vhost assigned to this nick.";
private enum M_HOST_NOT_ASSIGNED_20 = "Please contact an Operator to get a vHost assigned to this nick.";

// MemoServ (ms_list.cpp, ms_read.cpp, ms_send.cpp, ms_del.cpp, language.h).
private enum M_MEMO_NONE = "You have no memos.";
private enum M_MEMO_LIST_HEADER = "Memos for %s:";
private enum M_MEMO_LIST_ROW_21 = "{number}: sent by \x02{sender}\x02 at {date/time}";
private enum M_MEMO_READ_HEADER = "Memo %d from %s (%s).";
private enum M_MEMO_READ_HINT_21 = "To delete, type: \x02%s %d\x02";
private enum M_MEMO_READ_HINT_20 = "To delete, type: \x02%s%s %s %d\x02";
private enum M_MEMO_NOT_FOUND = "No memos to display.";
private enum M_MEMO_SENT = "Memo sent to \x02%s\x02.";
private enum M_MEMO_DELETED = "Memo %d has been deleted.";
private enum M_MEMO_ARRIVED_21 = "You have a new memo from %s. Type \x02%s\x1B%zu\x02 to read it.";
private enum M_MEMO_X_ARRIVED_21 = "There is a new memo on channel %s. Type \x02%s\x1B%s\x1B%zu\x02 to read it.";
private enum M_MEMO_ARRIVED_20 = "You have a new memo from %s.\nType \x02%s%s READ %d\x02 to read it.";
private enum M_MEMO_X_ARRIVED_20 = "There is a new memo on channel %s.\nType \x02%s%s READ %s %d\x02 to read it.";
/// Unsolicited MemoServ arrival notices (no `+reply`), both releases.
private static immutable string[] MEMO_ARRIVALS = [M_MEMO_ARRIVED_21, M_MEMO_X_ARRIVED_21, M_MEMO_ARRIVED_20,
    M_MEMO_X_ARRIVED_20];

/// Failure texts shared by every NickServ/HostServ/MemoServ command used here.
private static immutable string[3][] COMMON_REFUSALS = [
    [M_ACCESS_DENIED, "r", "access_denied"],
    [M_IDENTIFY_REQUIRED, "r", "identify_required"],
    [M_READ_ONLY_21, "u", "read_only"],
    [M_READ_ONLY_20, "u", "read_only"],
    [M_TRY_AGAIN_21, "u", "temporarily_unavailable"],
    [M_SUSPENDED, "r", "suspended"],
];

private static immutable string[3][] IDENTIFY_REFUSALS = [
    [M_PASSWORD_INCORRECT, "r", "password_incorrect"],
    [M_NOT_REGISTERED, "r", "not_registered"],
    [M_ALREADY_IDENTIFIED, "r", "already_identified"],
    [M_MAX_LOGINS, "r", "max_logins"],
];

private static immutable string[3][] REGISTER_REFUSALS = [
    ["Registration is currently disabled.", "u", "registration_disabled"],
    ["Sorry, nickname registration is temporarily disabled.", "u", "temporarily_unavailable"],
    ["You must wait %s before registering your nick.", "r", "too_soon"],
    ["You must have been using this nick for at least %d seconds to register.", "r", "too_soon"],
    [M_CANNOT_REGISTER, "r", "nick_not_allowed"],
    ["Please wait %s before using the REGISTER command again.", "r", "rate_limited"],
    ["Please wait %d seconds before using the REGISTER command again.", "r", "rate_limited"],
    ["Nickname \x02%s\x02 is already registered!", "r", "already_registered"],
    ["\x02%s\x02 is not a valid email address.", "r", "invalid_email"],
    ["\x02%s\x02 is not a valid e-mail address.", "r", "invalid_email"],
    ["Please try again with a more obscure password. Passwords should not be something that could be easily guessed (e.g. your real name or your nick) and cannot contain a space character.", "r", "weak_password"],
    ["Please try again with a more obscure password. Passwords should be at least\nfive characters long, should not be something easily guessed\n(e.g. your real name or your nick), and cannot contain the space or tab characters.", "r", "weak_password"],
    ["Your password is too short. It must be longer than %zu characters.", "r", "password_too_short"],
    ["Your password is too long. It must be shorter than %zu characters.", "r", "password_too_long"],
    ["Your password is too long. It must not exceed %u characters.", "r", "password_too_long"],
];

private static immutable string[3][] CONFIRM_REFUSALS = [
    ["There is no registration confirmation pending for %s.", "r", "not_pending"],
    ["The registration confirmation code you specified for %s is incorrect.", "r", "code_incorrect"],
    ["The registration of %s can only be confirmed by an administrator.", "r", "admin_confirmation_required"],
    ["Invalid passcode.", "r", "code_incorrect"],
    ["Invalid passcode has been entered, please check the e-mail again, and retry.", "r", "code_incorrect"],
    ["Nick \x02%s\x02 is already confirmed.", "r", "not_pending"],
    [M_NOT_REGISTERED, "r", "not_registered"],
];

private static immutable string[3][] GROUP_REFUSALS = [
    [M_PASSWORD_INCORRECT, "r", "password_incorrect"],
    [M_NOT_REGISTERED, "r", "not_registered"],
    ["Please wait %s before using the GROUP command again.", "r", "rate_limited"],
    ["Please wait %d seconds before using the GROUP command again.", "r", "rate_limited"],
    ["Your nick is already registered.", "r", "nick_registered"],
    ["You are already a member of the account of \x02%s\x02.", "r", "already_member"],
    ["You are already a member of the group of \x02%s\x02.", "r", "already_member"],
    ["There are too many nicks in your account.", "r", "too_many_nicks"],
    ["There are too many nicks in your group.", "r", "too_many_nicks"],
    [M_CANNOT_REGISTER, "r", "nick_not_allowed"],
    ["Sorry, nickname grouping is temporarily disabled.", "u", "temporarily_unavailable"],
];

private static immutable string[3][] GLIST_REFUSALS = [
    [M_NOT_REGISTERED, "r", "not_registered"],
];

private static immutable string[3][] RECOVER_REFUSALS = [
    [M_RECOVER_SELF, "r", "self_target"],
    [M_NOT_REGISTERED, "r", "not_registered"],
];

private static immutable string[3][] PRIVACY_REFUSALS = [
    [M_NOT_REGISTERED, "r", "not_registered"],
];

private static immutable string[3][] HOST_REQUEST_REFUSALS = [
    ["You must confirm your account before you may request a vhost.", "r", "unconfirmed_account"],
    ["Your IRCd does not support vidents. If this is incorrect please report this as a possible bug.", "r", "vident_unsupported"],
    ["Your IRCd does not support vIdent's, if this is incorrect, please report this as a possible bug", "r", "vident_unsupported"],
    ["A vhost must be in the format of a valid hostname.", "r", "invalid_vhost"],
    ["A vident must be in the format of a valid ident.", "r", "invalid_vhost"],
    ["Error! The vhost is too long, please use a hostname shorter than %zu characters.", "r", "invalid_vhost"],
    ["Error! The vident is too long, please use an ident shorter than %zu characters.", "r", "invalid_vhost"],
    ["A vHost must be in the format of a valid hostname.", "r", "invalid_vhost"],
    ["A vHost ident must be in the format of a valid ident.", "r", "invalid_vhost"],
    ["Error! The vHost is too long, please use a hostname shorter than %d characters.", "r", "invalid_vhost"],
    ["Error! The vHost ident is too long, please use an ident shorter than %d characters.", "r", "invalid_vhost"],
    ["Please wait %s before requesting a new vhost.", "r", "rate_limited"],
    ["Please wait %d seconds before requesting a new vHost.", "r", "rate_limited"],
];

private static immutable string[3][] HOST_TOGGLE_REFUSALS = [
    [M_HOST_NOT_ASSIGNED_21, "r", "vhost_not_assigned"],
    [M_HOST_NOT_ASSIGNED_20, "r", "vhost_not_assigned"],
];

private static immutable string[3][] MEMO_REFUSALS = [
    [M_MEMO_NONE, "r", "memo_not_found"],
    [M_MEMO_NOT_FOUND, "r", "memo_not_found"],
    ["Sorry, memo sending is temporarily disabled.", "u", "temporarily_unavailable"],
];

private static immutable string[3][] MEMO_SEND_REFUSALS = [
    ["You must confirm your account before you may send a memo.", "r", "unconfirmed_account"],
    ["\x02%s\x02 is not a registered unforbidden nick or channel.", "r", "recipient_not_registered"],
    ["Please wait %s before using the %s command again.", "r", "rate_limited"],
    ["Please wait %d seconds before using the %s command again.", "r", "rate_limited"],
    ["%s currently has too many memos and cannot receive more.", "r", "recipient_full"],
    ["Sorry, %s currently has too many memos and cannot receive more.", "r", "recipient_full"],
    ["Sorry, memo sending is temporarily disabled.", "u", "temporarily_unavailable"],
];

// ── Shared evaluation helpers ──────────────────────────────────────────────

alias NickEq = bool delegate(string a, string b);

private bool asciiSame(string a, string b) { return a.length == b.length && icmp(a, b) == 0; }

/// A recognised refusal: the specific list first, then common texts,
/// unknown-command (module absent) and syntax replies.
private bool findRefusal(AnopeGrammar g, const ref ServiceFrame f, const string[3][] specific,
        out ServiceStatus status, out string reason) {
    foreach (ref r; specific)
        if (g.has(r[0], f)) {
            status = r[1] == "u" ? ServiceStatus.unavailable : ServiceStatus.rejected;
            reason = r[2];
            return true;
        }
    foreach (ref r; COMMON_REFUSALS)
        if (g.has(r[0], f)) {
            status = r[1] == "u" ? ServiceStatus.unavailable : ServiceStatus.rejected;
            reason = r[2];
            return true;
        }
    foreach (m; UNKNOWN_COMMAND)
        if (g.has(m, f)) {
            status = ServiceStatus.unavailable;
            reason = "command_unavailable";
            return true;
        }
    if (syntaxReply(g, f)) {
        status = ServiceStatus.rejected;
        reason = "syntax_error";
        return true;
    }
    return false;
}

/// A refusal that is the whole answer (first line; at most a following
/// MORE_INFO line). Used where later lines may be attacker-controlled text.
private bool firstLineRefusal(AnopeGrammar g, const ref ServiceFrame f, const string[3][] specific,
        out ServiceStatus status, out string reason) {
    if (!f.lines.length || f.lines.length > 2) return false;
    const first = f.lines[0].plain;
    string[] c;
    foreach (list; [specific, COMMON_REFUSALS])
        foreach (ref r; list)
            if (g.matches(r[0], first, c)) {
                status = r[1] == "u" ? ServiceStatus.unavailable : ServiceStatus.rejected;
                reason = r[2];
                return true;
            }
    foreach (m; UNKNOWN_COMMAND)
        if (g.matches(m, first, c)) {
            status = ServiceStatus.unavailable;
            reason = "command_unavailable";
            return true;
        }
    foreach (v; g.variants(M_SYNTAX))
        if (v.length && first.stripLeft.startsWith(v ~ ":")) {
            status = ServiceStatus.rejected;
            reason = "syntax_error";
            return true;
        }
    return false;
}

/// `Syntax: COMMAND …` (Command::SendSyntax), translated label.
private bool syntaxReply(AnopeGrammar g, const ref ServiceFrame f) {
    auto labels = g.variants(M_SYNTAX);
    foreach (ref l; f.lines) {
        const p = l.plain.stripLeft;
        foreach (v; labels)
            if (v.length && p.startsWith(v ~ ":")) return true;
    }
    return false;
}

/// Last own login the server stated while the frame was open.
private ServicesActor lastAccountChange(const ref ServiceFrame f, out bool seen) {
    seen = f.accountChanges.length > 0;
    return seen ? f.accountChanges[$ - 1] : ServicesActor.init;
}

/// Row text with the 2.1 MONOSPACE marker's extra indent removed.
private string rowText(const ref ServiceReplyLine l) {
    if (l.text.length && l.text[0] == '\x11' && l.plain.startsWith("  ")) return l.plain[2 .. $];
    return l.plain;
}

/// Anope::Template rows (`{name}` placeholders) in a translated variant.
private bool braceMatch(string tmpl, string line, ref string[string] vars) {
    size_t ti, li;
    while (ti < tmpl.length) {
        if (tmpl[ti] == '{') {
            const close = tmpl.indexOf('}', ti);
            if (close < 0) return false;
            const name = tmpl[ti + 1 .. close];
            ti = close + 1;
            const next = tmpl.indexOf('{', ti);
            const lit = next < 0 ? tmpl[ti .. $] : tmpl[ti .. next];
            if (!lit.length) {
                if (next >= 0) return false;
                vars[name] = line[li .. $];
                return true;
            }
            const pos = line.indexOf(lit, li);
            if (pos < 0) return false;
            vars[name] = line[li .. pos];
            li = pos;
        } else {
            const next = tmpl.indexOf('{', ti);
            const lit = next < 0 ? tmpl[ti .. $] : tmpl[ti .. next];
            if (!line[li .. $].startsWith(lit)) return false;
            li += lit.length;
            ti += lit.length;
        }
    }
    return li == line.length;
}

private bool templateRow(AnopeGrammar g, string englishTemplate, string line, ref string[string] vars) {
    foreach (v; g.variants(englishTemplate)) {
        string[string] attempt;
        if (braceMatch(v, line, attempt)) {
            vars = attempt;
            return true;
        }
    }
    return false;
}

/// The frame carries text that must never become a generic detail line.
private bool hasPrivateText(AnopeGrammar g, const ref ServiceFrame f) {
    return g.has(M_CONFIRM_CODE_21, f) || g.has(M_PASSWORD_ECHO_20, f) || g.has(M_HOST_REQUESTED_DNS_21, f);
}

/// Detail lines limited to recognised (non-private) service texts.
private string[] recognizedDetails(ServicesTransaction txn, AnopeGrammar g, const ref ServiceFrame f,
        const string[] msgids) {
    ServiceReplyLine[] keep;
    foreach (ref l; f.lines) {
        foreach (m; msgids) {
            string[] c;
            if (g.matches(m, l.plain, c)) {
                keep ~= l;
                break;
            }
        }
    }
    return txn.details(keep);
}

private string[] refusalMsgids(const string[3][] specific) {
    string[] out_;
    foreach (ref r; specific) out_ ~= r[0];
    foreach (ref r; COMMON_REFUSALS) out_ ~= r[0];
    return out_;
}

/// Whole, fenced and unambiguous: a `+reply` line the transport could not
/// place (kept private, absent from `lines`) may have been this request's
/// answer, so such a frame is treated like a truncated one.
private bool frameComplete(const ref ServiceFrame f) {
    return ircfiber.irc.services_operation.frameComplete(f) && !f.ambiguous;
}

private string incompleteReason(const ref ServiceFrame f) {
    if (f.reason.length) return f.reason;
    if (f.outcome == ServiceFrameOutcome.deadline) return "deadline";
    if (f.truncated) return "truncated";
    if (f.ambiguous) return "ambiguous_reply";
    return "frame_incomplete";
}

/// A write frame with an unplaceable `+reply` builds no verdict, data or
/// details: the unplaced line may be its real answer.
private bool ambiguousWrite(ServicesTransaction txn, const ref ServiceFrame f) {
    if (!f.ambiguous) return false;
    txn.complete(ServiceStatus.unconfirmed, "ambiguous_reply");
    return true;
}

/// A read frame that cannot be parsed as a whole answers the request.
private bool readFailed(ServicesTransaction txn, const ref ServiceFrame f) {
    if (f.outcome == ServiceFrameOutcome.completed && frameComplete(f)) return false;
    txn.complete(ServiceStatus.unavailable, incompleteReason(f));
    return true;
}

private ServiceFrameSpec readSpec(string body_, ServiceLineRelease release = null) {
    ServiceFrameSpec s;
    s.bodies = [body_];
    s.kind = ServiceFrameKind.ordinary;
    s.release = release;
    return s;
}

/// One state-changing body. The transport rechecks its own generation and
/// the actor at dispatch; the preflight also pins the generation the
/// adapter's fresh read/revision check observed.
private ServiceFrameSpec writeSpec(ServicesTransaction txn, string body_, ServiceFrameKind kind,
        ServiceFrameTerminal terminal = null, ServiceLineRelease release = null) {
    ServiceFrameSpec s;
    s.bodies = [body_];
    s.kind = kind;
    s.terminal = terminal;
    s.release = release;
    s.mutating = true;
    const generation = txn.capabilityGeneration();
    s.preflight = () => txn.capabilityGeneration() == generation;
    return s;
}

/// An acknowledgement and a refusal in one frame cannot both be this
/// request's answer (a manual command's reply may have been attributed):
/// no verdict, no data.
private void completeConflict(ServicesTransaction txn, string[] details) {
    txn.complete(ServiceStatus.unconfirmed, "conflicting_replies", Json.undefined, "", Json.undefined, details);
}

private bool fitsOrReject(ServicesTransaction txn, string body_) {
    if (txn.fits(body_)) return true;
    txn.complete(ServiceStatus.rejected, "line_too_long");
    return false;
}

private ServiceStatus helpStatus(string state) {
    return state == "denied" ? ServiceStatus.rejected : ServiceStatus.unavailable;
}

private string helpReason(HelpEvidence h) {
    if (h.reasonCode.length) return h.reasonCode;
    if (h.state == "denied") return "permission_denied";
    if (h.state == "unsupported") return "unsupported";
    return "capability_unknown";
}

/// Fresh capability for a write: the actual session's HELP for the exact
/// command. Anything but `allowed` answers without sending the write.
private void requireHelp(ServicesTransaction txn, ServiceAction action, void delegate() proceed) {
    readServicesActionHelp(txn, txn.endpoint.service, action, (HelpEvidence h) {
        if (h.state == "allowed") {
            proceed();
            return;
        }
        auto caps = Json.emptyObject;
        putServiceCapability(caps, action, h.state, h.reasonCode);
        txn.complete(helpStatus(h.state), helpReason(h), Json.undefined, "", caps);
    });
}

/// Sequential HELP reads (one command per frame) into a capability map.
private void readCapabilities(ServicesTransaction txn, ServiceAction[] reads, void delegate(Json) done) {
    auto caps = Json.emptyObject;
    void step(size_t i) {
        if (i >= reads.length) {
            done(caps);
            return;
        }
        const read = reads[i];
        readServicesActionHelp(txn, txn.endpoint.service, read, (HelpEvidence h) {
            putServiceCapability(caps, read, h.state, h.reasonCode);
            step(i + 1);
        });
    }
    step(0);
}

private string capState(ref Json caps, ServiceAction action) {
    auto p = action.to!string in caps;
    if (p is null || p.type != Json.Type.object) return "unknown";
    auto s = (*p)["state"];
    return s.type == Json.Type.string ? s.get!string : "unknown";
}

/// Narrows an `allowed` HELP verdict by real state evidence.
private void narrowCapability(ref Json caps, ServiceAction action, string state, string reason) {
    if (capState(caps, action) == "allowed") putServiceCapability(caps, action, state, reason);
}


private string paramString(ServicesTransaction txn, string key) { return serviceParam(txn, key); }

private bool paramBool(ServicesTransaction txn, string key) {
    auto v = txn.request.params[key];
    return v.type == Json.Type.bool_ && v.get!bool;
}

private long paramLong(ServicesTransaction txn, string key) {
    auto v = txn.request.params[key];
    return v.type == Json.Type.int_ ? v.get!long : 0;
}

// ── Legacy (untagged) authentication terminal classifier ───────────────────

/// Final replies of IDENTIFY, REGISTER, CONFIRM, GROUP and RECOVER (acks,
/// effects and every refusal those commands send). A syntax error's
/// terminal is its `Syntax:` line; the MORE_INFO line that follows it when a
/// HELP command exists is deliberately not terminal, so every verdict yields
/// exactly one terminal line.
private string[] authTerminalMsgids() {
    string[] ids = [M_IDENTIFY_OK, M_REGISTERED, M_REGISTERED_MASK_20, M_CONFIRMED, M_EMAIL_CONFIRMED_20,
        M_GROUPED_21, M_GROUPED_20, M_RECOVER_HOLD, M_RECOVER_NONE, M_RECOVER_GHOST, M_RECOVER_REGAINED,
        M_RECOVER_REMOVED_21, M_RECOVER_REMOVED_20];
    foreach (list; [COMMON_REFUSALS, IDENTIFY_REFUSALS, REGISTER_REFUSALS, CONFIRM_REFUSALS, GROUP_REFUSALS,
            RECOVER_REFUSALS])
        foreach (ref r; list) ids ~= r[0];
    foreach (m; UNKNOWN_COMMAND) ids ~= m;
    return ids;
}

/// printf-style wildcard match over one normalized template segment:
/// `%s` any text, `%d`/`%u`/`%zu`/`%i` digits, `%N$…` positional, `%%`.
bool printfSegmentMatch(string tmpl, string line) {
    if (!tmpl.length) return !line.length;
    if (tmpl[0] != '%') return line.length && line[0] == tmpl[0] && printfSegmentMatch(tmpl[1 .. $], line[1 .. $]);
    size_t i = 1;
    if (i < tmpl.length && tmpl[i] == '%')
        return line.length && line[0] == '%' && printfSegmentMatch(tmpl[2 .. $], line[1 .. $]);
    size_t j = i;
    while (j < tmpl.length && isDigit(tmpl[j])) ++j;
    if (j < tmpl.length && tmpl[j] == '$') i = j + 1;
    while (i < tmpl.length && (tmpl[i] == 'z' || tmpl[i] == 'l' || tmpl[i] == 'h')) ++i;
    if (i >= tmpl.length) return false;
    const conv = tmpl[i];
    const rest = tmpl[i + 1 .. $];
    const digits = conv == 'd' || conv == 'u' || conv == 'i';
    foreach (k; (digits ? 1 : 0) .. line.length + 1) {
        if (digits && !isDigit(line[k - 1])) break;
        if (printfSegmentMatch(rest, line[k .. $])) return true;
    }
    return false;
}

private size_t literalLength(string tmpl) {
    size_t n;
    for (size_t i = 0; i < tmpl.length; ++i) {
        if (tmpl[i] != '%') {
            ++n;
            continue;
        }
        ++i;
        while (i < tmpl.length && !"sdui%".canFind(tmpl[i])) ++i;
    }
    return n;
}

private bool authTerminalFor(AnopeGrammar g, string line) {
    if (!g.supported || !line.length) return false;
    foreach (v; g.variants(M_SYNTAX))
        if (v.length && line.stripLeft.startsWith(v ~ ":")) return true;
    foreach (id; authTerminalMsgids()) {
        if (g.has(id, line)) return true;
        foreach (v; g.variants(id)) {
            // 2.0 `\n` messages end with their last part; 2.1 `LineWrapper`
            // wraps long replies at spaces, so the last physical line is a
            // space-aligned tail (long enough not to match stray text).
            const nl = v.lastIndexOf('\n');
            const last = nl < 0 ? v : v[nl + 1 .. $];
            if (nl >= 0 && printfSegmentMatch(last, line)) return true;
            foreach (k, ch; last)
                if (ch == ' ' && k + 1 < last.length) {
                    const tail = last[k + 1 .. $];
                    if (literalLength(tail) >= 20 && printfSegmentMatch(tail, line)) return true;
                }
        }
    }
    return false;
}

/// Transport classifier for untagged (legacy) authentication resolution:
/// true iff `plainLine` is the terminal reply of IDENTIFY, REGISTER,
/// CONFIRM, GROUP or RECOVER (any alias of them) in English or any shipped
/// locale of the endpoint's release; both releases when it is unknown.
/// Unsolicited notices (memo arrival, nick protection, vhost activation,
/// confirmation prompts) and unknown text are false.
bool legacyAuthTerminal(string versionText, string plainLine) {
    const line = normalizeServiceText(plainLine);
    auto g = grammarFor(versionText);
    if (g.supported) return authTerminalFor(g, line);
    return authTerminalFor(grammarFor(ANOPE_21_VERSION), line) || authTerminalFor(grammarFor(ANOPE_20_VERSION), line);
}

// ── NickServ INFO ──────────────────────────────────────────────────────────

/// One parsed NickServ INFO answer (ns_info.cpp; both versions).
struct NickInfo {
    /// The answer had a recognised first line.
    bool recognized;
    bool registered;
    /// The name is a services pseudoclient.
    bool service;
    string nick;
    /// Account (display) with the 2.1 account ID removed; "" if unknown.
    string account;
    bool unconfirmed;
    bool online;
    string operType;
    string[2][] fields;
    bool vhostFound;
    string vhost;

    void addField(string name, string value) {
        string[2] pair = [name, value];
        fields ~= pair;
    }
}

/// 2.0 header `%s is %s` (nick, last realname). The realname is free text
/// that may itself contain the separator, so the nick — which has no
/// spaces — is split at the separator's first occurrence.
private bool infoHeader20(AnopeGrammar g, string line, out string nick, out string realname) {
    string[] c;
    if (g.matches(M_INFO_HEADER_20, line, c) && c.length >= 2) {
        nick = c[0];
        realname = c[1];
        return !nick.canFind(' ');
    }
    foreach (v; g.variants(M_INFO_HEADER_20)) {
        if (v.length < 5 || !v.startsWith("%s") || !v.endsWith("%s")) continue;
        const sep = v[2 .. $ - 2];
        if (!sep.length || sep.canFind('%')) continue;
        const at = line.indexOf(sep);
        if (at <= 0 || line[0 .. at].canFind(' ')) continue;
        nick = line[0 .. at];
        realname = line[at + sep.length .. $];
        return true;
    }
    return false;
}

NickInfo parseNickInfo(AnopeGrammar g, const ref ServiceFrame f) {
    NickInfo r;
    if (!f.lines.length) return r;
    string[] c;
    const first = f.lines[0].plain;
    if (g.matches(M_NOT_REGISTERED, first, c)) {
        r.recognized = true;
        r.nick = c.length ? c[0] : "";
        return r;
    }
    if (g.matches(M_INFO_SERVICE, first, c)) {
        r.recognized = r.service = true;
        r.nick = c.length ? c[0] : "";
        return r;
    }
    if (g.v21) {
        if (!g.matches(M_INFO_HEADER_21, first, c) || c.length < 1) return r;
        r.nick = c[0];
    } else {
        string realname;
        if (!infoHeader20(g, first, r.nick, realname)) return r;
        r.addField("Real name", realname);
    }
    r.recognized = r.registered = true;
    // Status lines precede the key/value block (ns_info.cpp Execute order).
    foreach (i; 1 .. f.lines.length < 5 ? f.lines.length : 5) {
        const line = f.lines[i].plain;
        if (g.matches(M_INFO_UNCONFIRMED, line, c) && c.length && asciiSame(c[0], r.nick)) r.unconfirmed = true;
        else if (g.matches(M_INFO_OPER, line, c) && c.length > 1 && asciiSame(c[0], r.nick)) {
            r.operType = c[1];
            r.addField("Services Operator", c[1]);
        } else if (g.matches(M_INFO_ONLINE, line, c) && c.length && asciiSame(c[0], r.nick)) r.online = true;
    }
    foreach (key; g.v21 ? INFO_KEYS_21 : INFO_KEYS_20) {
        bool found;
        auto value = g.infoValue(key, f, found);
        if (!found) continue;
        if (key == K_ACCOUNT) {
            if (g.v21) {
                string[] idc;
                if (!g.matches(M_INFO_ACCOUNT_ID, value, idc) || !idc.length) continue;
                value = idc[0];
            }
            if (!value.length || value.canFind(' ')) continue;
            r.account = value;
        } else if (key == K_VHOST) {
            r.vhostFound = true;
            r.vhost = value;
        } else if (key == "Online from") r.online = true;
        r.addField(key, value);
    }
    return r;
}

private Json nickInfoJson(const ref NickInfo i) {
    auto j = Json(["kind": Json("account"), "nick": Json(i.nick), "registered": Json(i.registered)]);
    if (i.account.length) j["account"] = Json(i.account);
    if (i.registered) j["confirmed"] = Json(!i.unconfirmed);
    if (i.service) j["service"] = Json(true);
    if (i.online) j["online"] = Json(true);
    Json[] fields;
    foreach (ref fv; i.fields) fields ~= Json(["name": Json(fv[0]), "value": Json(fv[1])]);
    j["fields"] = Json(fields);
    return j;
}

/// Identity revision: account, registration and confirmation only, never
/// volatile seen/online values.
private Json accountCanonical(string account, bool registered, bool confirmed) {
    return Json(["kind": Json("account"), "account": Json(account.toLower), "registered": Json(registered),
        "confirmed": Json(confirmed)]);
}

/// INFO answered with the owner's (show_hidden) view: the requested name is
/// the actor's account, or INFO shows that any requested alias belongs to it.
bool privateInfoView(const ServicesActor actor, const ref NickInfo info, string requested, NickEq same) {
    if (actor.state != ServicesActorState.account) return false;
    return same(actor.account, requested) || (info.registered && same(info.account, actor.account));
}

/// Read-only nick → account resolution for `accountInfo {targetNick}` without
/// a reviewed account: only a fresh WHOIS 330 names the account (a grouped
/// nick's account differs from the nick); never the nick itself.
struct TargetAccount {
    bool ok;
    string account;
    ServiceStatus status;
    string reason;
}

TargetAccount resolveTargetAccount(const ServicesWhois w, string targetNick, NickEq same) {
    TargetAccount r;
    if (!w.complete) {
        r.status = ServiceStatus.unavailable;
        r.reason = "target_unverified";
    } else if (!w.present || !w.nick.length || !same(w.nick, targetNick)) {
        r.status = ServiceStatus.unavailable;
        r.reason = "target_absent";
    } else if (!w.account.length) {
        r.status = ServiceStatus.unconfirmed;
        r.reason = "target_unidentified";
    } else {
        r.ok = true;
        r.account = w.account;
    }
    return r;
}

private void runAccountInfo(ServicesTransaction txn, AnopeGrammar g) {
    const reviewedAccount = paramString(txn, "account");
    const targetNick = paramString(txn, "targetNick");
    const actor = txn.actor;

    /// `resolved`: the account came from this request's fresh WHOIS.
    void query(string account, bool resolved) {
        const identified = actor.state == ServicesActorState.account;
        const ownNickUnidentified = !resolved && !identified && txn.sameNick(account, txn.ownNick());
        const body_ = "INFO " ~ account;
        // Raw INFO lines never become details: the owner of any grouped alias
        // (show_hidden) and nickserv/auspex holders receive hidden fields,
        // and HELP cannot prove which view a session got.
        if (!fitsOrReject(txn, body_)) return;
        txn.frame(readSpec(body_), (ServiceFrame f) {
            if (readFailed(txn, f)) return;
            auto info = parseNickInfo(g, f);
            ServiceStatus st;
            string reason;
            if (!info.recognized) {
                if (findRefusal(g, f, null, st, reason)) txn.complete(st, reason);
                else txn.complete(ServiceStatus.unconfirmed, f.lines.length ? "unrecognized_reply" : "no_reply");
                return;
            }
            // Own view = INFO of any alias of the actor's account (ns_info
            // show_hidden is `na->nc == source.GetAccount()`), decided from
            // the parsed account, not the requested name.
            const ownView = privateInfoView(actor, info, account, &txn.sameNick);
            string[] details = null;
            auto data = nickInfoJson(info);
            if (targetNick.length) {
                // Evidence: this nick was logged into `account` at request time.
                data["targetNick"] = Json(targetNick);
                data["targetAccount"] = Json(account);
            }
            if (resolved && (!info.registered || !info.account.length || !txn.sameNick(info.account, account))) {
                // The WHOIS account must be the account INFO describes.
                txn.complete(ServiceStatus.unconfirmed, "account_mismatch", data, "", Json.undefined, details);
                return;
            }
            if (ownView) {
                data["ownAccount"] = Json(true);
                if (!info.registered || !txn.sameNick(info.account, actor.account)) {
                    txn.complete(ServiceStatus.unconfirmed, "account_mismatch");
                    return;
                }
                const revision = servicesRevision(txn, accountCanonical(info.account, true, !info.unconfirmed));
                readCapabilities(txn, [
                    ServiceAction.accountPrivacy,
                    ServiceAction.accountRecover,
                    ServiceAction.accountGroups,
                    ServiceAction.accountGroup,
                ], (Json caps) {
                    txn.complete(ServiceStatus.confirmed, "", data, revision, caps);
                });
                return;
            }
            if (ownNickUnidentified) {
                readCapabilities(txn, [
                    ServiceAction.accountIdentify,
                    ServiceAction.accountRegister,
                    ServiceAction.accountConfirm,
                    ServiceAction.accountGroup,
                    ServiceAction.accountRecover,
                ], (Json caps) {
                    // ns_register: an existing alias answers "already registered".
                    if (info.registered || info.service)
                        narrowCapability(caps, ServiceAction.accountRegister, "denied", "nick_registered");
                    txn.complete(ServiceStatus.confirmed, "", data, "", caps, details);
                });
                return;
            }
            txn.complete(ServiceStatus.confirmed, "", data, "", Json.undefined, details);
        });
    }

    if (!reviewedAccount.length) {
        if (!targetNick.length) {
            txn.complete(ServiceStatus.rejected, "target_required");
            return;
        }
        // Read-only: resolve the nick's account from a fresh WHOIS 330.
        txn.whois(targetNick, (ServicesWhois w) {
            auto t = resolveTargetAccount(w, targetNick, &txn.sameNick);
            if (!t.ok) {
                auto data = Json(["kind": Json("account"), "nick": Json(targetNick), "targetNick": Json(targetNick)]);
                txn.complete(t.status, t.reason, t.reason == "target_unidentified" ? data : Json.undefined);
                return;
            }
            query(t.account, true);
        });
        return;
    }
    // A reviewed account: the nick must still be logged into it (stale otherwise).
    verifyServicesTarget(txn, reviewedAccount, targetNick, (bool ok) {
        if (ok) query(reviewedAccount, false);
    });
}

// ── IDENTIFY ───────────────────────────────────────────────────────────────

/// Confirmation prompt state (ns_register.cpp OnNickIdentify / REGISTER).
string awaitingState(AnopeGrammar g, const ref ServiceFrame f, out string code) {
    string[] c;
    if (g.matches(M_CONFIRM_CODE_21, f, c)) {
        // `/msg NickServ CONFIRM REGISTER <code>`: the code is the last token.
        if (c.length) {
            auto parts = c[0].strip.split(' ');
            code = parts.length ? parts[$ - 1] : "";
        }
        return "awaiting_code";
    }
    if (g.has(M_CONFIRM_ADMIN_21, f) || g.has(M_CONFIRM_ADMIN_20, f)) return "awaiting_admin";
    if (g.has(M_CONFIRM_MAIL_21, f) || g.has(M_CONFIRM_MAIL_20, f)) return "awaiting_email";
    return "";
}

/// Evidence an IDENTIFY frame collected.
struct IdentifyEval {
    bool ack;
    bool refused;
    ServiceStatus refusalStatus;
    string refusal;
    /// Server-stated login ("" none observed).
    string observed;
    /// Awaiting-confirmation prompt (no 900 for unconfirmed accounts).
    string awaiting;
    string code;

    /// Ack and a refusal in one frame (e.g. a foreign manual reply): neither wins.
    bool conflicting() const { return ack && refused; }
}

IdentifyEval evaluateIdentify(AnopeGrammar g, const ref ServiceFrame f) {
    IdentifyEval e;
    e.refused = findRefusal(g, f, IDENTIFY_REFUSALS, e.refusalStatus, e.refusal);
    e.ack = g.has(M_IDENTIFY_OK, f);
    bool seen;
    const change = lastAccountChange(f, seen);
    if (seen && change.state == ServicesActorState.account) e.observed = change.account;
    e.awaiting = awaitingState(g, f, e.code);
    return e;
}

private void runAccountIdentify(ServicesTransaction txn, AnopeGrammar g) {
    const account = paramString(txn, "account");
    const password = paramString(txn, "password");
    const body_ = "IDENTIFY " ~ account ~ " " ~ password;
    if (!fitsOrReject(txn, body_)) return;
    ServiceFrameTerminal terminal = (ref const ServiceFrame f) {
        auto e = evaluateIdentify(g, f);
        // Never close as a success while a refusal is also present.
        return e.refused || (e.ack && (e.observed.length || e.awaiting.length));
    };
    requireHelp(txn, ServiceAction.accountIdentify, () {
        txn.frame(writeSpec(txn, body_, ServiceFrameKind.asyncAuth, terminal), (ServiceFrame f) {
            if (ambiguousWrite(txn, f)) return;
            auto e = evaluateIdentify(g, f);
            auto details = hasPrivateText(g, f) ? null : txn.details(f.lines);
            if (e.conflicting) return completeConflict(txn, details);
            if (e.refused) {
                txn.complete(e.refusalStatus, e.refusal, Json.undefined, "", Json.undefined, details);
                return;
            }
            if (e.ack && e.observed.length) {
                auto data = Json(["kind": Json("identity"), "account": Json(e.observed)]);
                if (txn.sameNick(e.observed, account)) {
                    txn.complete(ServiceStatus.confirmed, "", data, "", Json.undefined, details);
                    return;
                }
                // A grouped nick logs into its account's display name: prove
                // membership with the now-identified session's GLIST.
                txn.frame(readSpec("GLIST"), (ServiceFrame gl) {
                    auto groups = parseGroupList(g, gl);
                    if (gl.outcome == ServiceFrameOutcome.completed && frameComplete(gl) && groups.ok
                            && groups.nicks.canFind!((n) => txn.sameNick(n, account)))
                        txn.complete(ServiceStatus.confirmed, "", data, "", Json.undefined, details);
                    else
                        txn.complete(ServiceStatus.unconfirmed, "account_unverified", Json.undefined, "",
                            Json.undefined, details);
                });
                return;
            }
            if (e.ack && e.awaiting.length) {
                // Identified to an unconfirmed account: InspIRCd SendLogin sends
                // no account, so this is not a login.
                auto data = Json(["kind": Json("registration"), "nick": Json(account), "state": Json(e.awaiting)]);
                if (e.code.length) data["code"] = Json(e.code);
                txn.complete(ServiceStatus.unconfirmed, "awaiting_confirmation", data, "", Json.undefined, null);
                return;
            }
            if (e.ack) {
                txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                    ? "login_not_observed" : incompleteReason(f), Json.undefined, "", Json.undefined, details);
                return;
            }
            if (e.observed.length) {
                // Observed state without a reliable acknowledgement.
                auto data = txn.sameNick(e.observed, account)
                    ? Json(["kind": Json("identity"), "account": Json(e.observed)]) : Json.undefined;
                txn.complete(ServiceStatus.unconfirmed, "observed_without_ack", data, "", Json.undefined, details);
                return;
            }
            txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                Json.undefined, "", Json.undefined, details);
        });
    });
}

// ── REGISTER / CONFIRM ─────────────────────────────────────────────────────

/// Evidence a REGISTER or CONFIRM frame collected.
struct RegistrationEval {
    bool ack;
    string ackNick;
    bool refused;
    ServiceStatus refusalStatus;
    string refusal;
    string observed;
    string awaiting;
    string code;

    bool conflicting() const { return ack && refused; }
}

RegistrationEval evaluateRegister(AnopeGrammar g, const ref ServiceFrame f) {
    RegistrationEval e;
    string[] c;
    if (g.matches(M_REGISTERED, f, c) || g.matches(M_REGISTERED_MASK_20, f, c)) {
        e.ack = true;
        e.ackNick = c.length ? c[0] : "";
    }
    e.refused = findRefusal(g, f, REGISTER_REFUSALS, e.refusalStatus, e.refusal);
    bool seen;
    const change = lastAccountChange(f, seen);
    if (seen && change.state == ServicesActorState.account) e.observed = change.account;
    e.awaiting = awaitingState(g, f, e.code);
    return e;
}

/// registration view state: never `identified` without a server login.
string registrationState(const ref RegistrationEval e, string nick, NickEq same) {
    if (e.observed.length && same(e.observed, nick)) return "identified";
    if (e.awaiting.length) return e.awaiting;
    return "registered_unconfirmed";
}

private void runAccountRegister(ServicesTransaction txn, AnopeGrammar g) {
    const password = paramString(txn, "password");
    const email = paramString(txn, "email");
    const nick = txn.ownNick();
    import ircfiber.services.protocol : token;
    try { token(password); }
    catch (Exception) { return txn.complete(ServiceStatus.rejected, "legacy_token_required"); }
    const requested = paramString(txn, "account");
    if (requested.length && !txn.sameNick(requested, nick))
        return txn.complete(ServiceStatus.rejected, "custom_account_name_unsupported");
    const body_ = "REGISTER " ~ password ~ (email.length ? " " ~ email : "");
    if (!fitsOrReject(txn, body_)) return;
    requireHelp(txn, ServiceAction.accountRegister, () {
        // REGISTER is synchronous (no IdentifyRequest); its login and
        // confirmation prompts precede the end fence.
        txn.frame(writeSpec(txn, body_, ServiceFrameKind.ordinary), (ServiceFrame f) {
            if (ambiguousWrite(txn, f)) return;
            auto e = evaluateRegister(g, f);
            auto details = hasPrivateText(g, f) ? null : txn.details(f.lines);
            if (e.conflicting) return completeConflict(txn, details);
            if (!e.ack) {
                if (e.refused) txn.complete(e.refusalStatus, e.refusal, Json.undefined, "", Json.undefined, details);
                else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                    ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                    Json.undefined, "", Json.undefined, details);
                return;
            }
            const registered = e.ackNick.length ? e.ackNick : nick;
            const state = registrationState(e, registered, &txn.sameNick);
            auto data = Json(["kind": Json("registration"), "nick": Json(registered), "state": Json(state)]);
            if (state == "identified") data["account"] = Json(e.observed);
            // The generated code is shown to its owner only, in the private view.
            if (state == "awaiting_code" && e.code.length) data["code"] = Json(e.code);
            if (state == "registered_unconfirmed") {
                txn.complete(ServiceStatus.unconfirmed, "login_not_observed", data, "", Json.undefined, details);
                return;
            }
            if (state != "awaiting_code") {
                txn.complete(ServiceStatus.confirmed, "", data, "", Json.undefined, details);
                return;
            }
            readCapabilities(txn, [ServiceAction.accountConfirm], (Json caps) {
                txn.complete(ServiceStatus.confirmed, "", data, "", caps, details);
            });
        });
    });
}

RegistrationEval evaluateConfirm(AnopeGrammar g, const ref ServiceFrame f) {
    RegistrationEval e;
    string[] c;
    if (g.matches(M_CONFIRMED, f, c)) {
        e.ack = true;
        e.ackNick = c.length ? c[0] : "";
    } else if (g.has(M_EMAIL_CONFIRMED_20, f)) {
        e.ack = true; // captures the email address, not a nick
    }
    e.refused = findRefusal(g, f, CONFIRM_REFUSALS, e.refusalStatus, e.refusal);
    bool seen;
    const change = lastAccountChange(f, seen);
    if (seen && change.state == ServicesActorState.account) e.observed = change.account;
    return e;
}

private void runAccountConfirm(ServicesTransaction txn, AnopeGrammar g) {
    const code = paramString(txn, "code");
    const nick = txn.ownNick();
    import ircfiber.services.protocol : token;
    try { token(code); }
    catch (Exception) { return txn.complete(ServiceStatus.rejected, "legacy_token_required"); }
    const requested = paramString(txn, "account");
    if (requested.length && !txn.sameNick(requested, nick))
        return txn.complete(ServiceStatus.rejected, "custom_account_name_unsupported");
    const body_ = (g.v21 ? "CONFIRM REGISTER " : "CONFIRM ") ~ code;
    if (!fitsOrReject(txn, body_)) return;
    requireHelp(txn, ServiceAction.accountConfirm, () {
        txn.frame(writeSpec(txn, body_, ServiceFrameKind.ordinary), (ServiceFrame f) {
            if (ambiguousWrite(txn, f)) return;
            auto e = evaluateConfirm(g, f);
            auto details = hasPrivateText(g, f) ? null : txn.details(f.lines);
            if (e.conflicting) return completeConflict(txn, details);
            if (!e.ack) {
                if (e.refused) txn.complete(e.refusalStatus, e.refusal, Json.undefined, "", Json.undefined, details);
                else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                    ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                    Json.undefined, "", Json.undefined, details);
                return;
            }
            const confirmedNick = e.ackNick.length ? e.ackNick : nick;
            // CONFIRM logs every session in (SendLogin): only that proves identified.
            const identified = e.observed.length > 0;
            auto data = Json(["kind": Json("registration"), "nick": Json(confirmedNick),
                "state": Json(identified ? "identified" : "registered_unconfirmed")]);
            if (identified) data["account"] = Json(e.observed);
            txn.complete(identified ? ServiceStatus.confirmed : ServiceStatus.unconfirmed,
                identified ? "" : "login_not_observed", data, "", Json.undefined, details);
        });
    });
}

// ── GLIST / GROUP ──────────────────────────────────────────────────────────

/// Anope 2.1 `LineWrapper` (src/misc.cpp, used by every User::SendMessage)
/// splits a reply longer than `options:linelength` (default 100, kept by
/// the managed config) at the last space before the limit, so one list row
/// can continue on the next line (e.g. a GLIST row's `(90 days from now)`).
/// Anope 2.0 never wraps.
private enum size_t ANOPE21_LINE_LENGTH = 100;

/// `cur` can be the wrapped continuation of `prev`: the word that starts it
/// would not have fitted on `prev` (LineWrapper breaks once the printable
/// length reaches the limit, at the last space).
bool wrapContinuation(string prevPlain, string curPlain) {
    if (!curPlain.length) return false;
    const sp = curPlain.indexOf(' ');
    const word = sp < 0 ? curPlain.length : cast(size_t) sp;
    return prevPlain.length + 1 + word >= ANOPE21_LINE_LENGTH;
}

/// Own-account GLIST (ns_group.cpp CommandNSGList): FIXED/MONOSPACE table,
/// or 2.1 FLEXIBLE rows, framed by the header and the count footer.
struct GroupList {
    bool ok;
    string[] nicks;
}

/// Fixed-table row: the nick, then column padding plus the two-space
/// separator (ListFormatter), then the next column.
private bool glistRow(string text, out string nick) {
    if (!text.length || text[0] == ' ') return false;
    const sp = text.indexOf(' ');
    if (sp <= 0 || !text[sp .. $].startsWith("  ")) return false;
    const rest = text[sp .. $].stripLeft;
    if (!rest.length) return false;
    nick = text[0 .. sp];
    return true;
}

private bool glistFlexibleRow(AnopeGrammar g, string line, out string nick) {
    string[string] v;
    if (!templateRow(g, M_GLIST_ROW_EXPIRES_21, line, v) && !templateRow(g, M_GLIST_ROW_21, line, v)) return false;
    nick = v.get("nick", "").strip;
    return nick.length && !nick.canFind(' ');
}

GroupList parseGroupList(AnopeGrammar g, const ref ServiceFrame f) {
    GroupList r;
    string[] c;
    ptrdiff_t header = -1, footer = -1;
    size_t count;
    foreach (i, ref l; f.lines) {
        if (header < 0) {
            if (g.matches(g.v21 ? M_GLIST_HEADER_21 : M_GLIST_HEADER_20, l.plain, c)) header = i;
            continue;
        }
        const footerMatch = g.v21
            ? (g.matches(M_GLIST_COUNT_21_ONE, l.plain, c) || g.matches(M_GLIST_COUNT_21_MANY, l.plain, c))
            : g.matches(M_GLIST_COUNT_20, l.plain, c);
        if (footerMatch && c.length && c[0].length && c[0].canFind!(ch => !isDigit(ch)) == false) {
            footer = i;
            count = c[0].to!size_t;
            break;
        }
    }
    if (header < 0 || footer < 0 || footer <= header + 1 || count == 0) return r;
    auto rows = f.lines[header + 1 .. footer];

    // 2.1 FLEXIBLE: each row a translated template; a wrapped row's tail
    // (a line that is no row itself) joins it with the space it was split at.
    string[] flexible;
    bool flexOk = g.v21;
    for (size_t i = 0; flexOk && i < rows.length;) {
        string logical = rows[i].plain;
        size_t j = i + 1;
        string nick;
        while (j < rows.length && !glistFlexibleRow(g, rows[j].plain, nick)
                && wrapContinuation(rows[j - 1].plain, rows[j].plain)) {
            logical ~= " " ~ rows[j].plain;
            ++j;
        }
        if (!glistFlexibleRow(g, logical, nick)) flexOk = false;
        else flexible ~= nick;
        i = j;
    }
    if (flexOk && flexible.length == count) {
        r.nicks = flexible;
        r.ok = true;
        return r;
    }

    // FIXED/MONOSPACE: rows[0] is the translated column header. A line
    // starting with "  " is ListFormatter's own column break; on 2.1 a line
    // that is no row but continues the previous one is a LineWrapper tail.
    string prev = rows[0].plain;
    foreach (ref l; rows[1 .. $]) {
        const text = rowText(l);
        string nick;
        if (glistRow(text, nick)) r.nicks ~= nick;
        else if (text.startsWith(" ")) {
        } else if (!g.v21 || !r.nicks.length || !wrapContinuation(prev, l.plain)) {
            r.nicks = null;
            return r;
        }
        prev = l.plain;
    }
    r.ok = r.nicks.length == count;
    return r;
}

private Json groupsJson(string account, const string[] nicks) {
    Json[] list;
    foreach (n; nicks) list ~= Json(n);
    return Json(["kind": Json("groups"), "account": Json(account), "nicks": Json(list)]);
}

private Json groupsCanonical(string account, const string[] nicks) {
    string[] lower;
    foreach (n; nicks) lower ~= n.toLower;
    lower.sort();
    Json[] list;
    foreach (n; lower) list ~= Json(n);
    return Json(["kind": Json("groups"), "account": Json(account.toLower), "nicks": Json(list)]);
}

private void runAccountGroups(ServicesTransaction txn, AnopeGrammar g) {
    const account = txn.actor.account;
    txn.frame(readSpec("GLIST"), (ServiceFrame f) {
        ServiceStatus st;
        string reason;
        if (findRefusal(g, f, GLIST_REFUSALS, st, reason)) {
            txn.complete(st, reason);
            return;
        }
        if (readFailed(txn, f)) return;
        auto groups = parseGroupList(g, f);
        if (!groups.ok) {
            txn.complete(ServiceStatus.unconfirmed, f.lines.length ? "unrecognized_reply" : "no_reply");
            return;
        }
        const revision = servicesRevision(txn, groupsCanonical(account, groups.nicks));
        readCapabilities(txn, [ServiceAction.accountGroup], (Json caps) {
            txn.complete(ServiceStatus.confirmed, "", groupsJson(account, groups.nicks), revision, caps);
        });
    });
}

/// GROUP evidence: ack, recognised refusal.
struct GroupEval {
    bool ack;
    bool refused;
    ServiceStatus refusalStatus;
    string refusal;
    string observed;

    bool conflicting() const { return ack && refused; }
}

GroupEval evaluateGroup(AnopeGrammar g, const ref ServiceFrame f) {
    GroupEval e;
    e.ack = g.has(M_GROUPED_21, f) || g.has(M_GROUPED_20, f);
    e.refused = findRefusal(g, f, GROUP_REFUSALS, e.refusalStatus, e.refusal);
    bool seen;
    const change = lastAccountChange(f, seen);
    if (seen && change.state == ServicesActorState.account) e.observed = change.account;
    return e;
}

private void runAccountGroup(ServicesTransaction txn, AnopeGrammar g) {
    const target = paramString(txn, "account");
    const password = paramString(txn, "password");
    const body_ = "GROUP " ~ target ~ (password.length ? " " ~ password : "");
    if (!fitsOrReject(txn, body_)) return;
    const startActor = txn.actor;
    ServiceFrameTerminal terminal = (ref const ServiceFrame f) {
        auto e = evaluateGroup(g, f);
        return e.ack || e.refused;
    };
    requireHelp(txn, ServiceAction.accountGroup, () {
        txn.frame(writeSpec(txn, body_, ServiceFrameKind.asyncAuth, terminal), (ServiceFrame f) {
            if (ambiguousWrite(txn, f)) return;
            auto e = evaluateGroup(g, f);
            auto details = txn.details(f.lines);
            if (e.conflicting) return completeConflict(txn, details);
            if (!e.ack) {
                if (e.refused) txn.complete(e.refusalStatus, e.refusal, Json.undefined, "", Json.undefined, details);
                else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                    ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                    Json.undefined, "", Json.undefined, details);
                return;
            }
            // The account this session is now in, as the server stated it.
            const account = e.observed.length ? e.observed
                : startActor.state == ServicesActorState.account ? startActor.account : "";
            if (!account.length) {
                txn.complete(ServiceStatus.unconfirmed, "login_not_observed", Json.undefined, "",
                    Json.undefined, details);
                return;
            }
            const own = txn.ownNick();
            txn.frame(readSpec("GLIST"), (ServiceFrame gl) {
                auto groups = parseGroupList(g, gl);
                if (gl.outcome != ServiceFrameOutcome.completed || !frameComplete(gl) || !groups.ok) {
                    txn.complete(ServiceStatus.unconfirmed, "readback_unavailable", Json.undefined, "",
                        Json.undefined, details);
                    return;
                }
                auto data = groupsJson(account, groups.nicks);
                const revision = servicesRevision(txn, groupsCanonical(account, groups.nicks));
                if (groups.nicks.canFind!((n) => txn.sameNick(n, own)))
                    txn.complete(ServiceStatus.confirmed, "", data, revision, Json.undefined, details);
                else
                    txn.complete(ServiceStatus.unconfirmed, "readback_mismatch", data, revision,
                        Json.undefined, details);
            });
        });
    });
}

// ── RECOVER ────────────────────────────────────────────────────────────────

/// RECOVER effect, by the exact source text that reported it.
struct RecoverEval {
    string effect;
    bool refused;
    ServiceStatus refusalStatus;
    string refusal;
    string observed;
    bool loginClaimed;

    bool conflicting() const { return effect.length && refused; }
}

RecoverEval evaluateRecover(AnopeGrammar g, const ref ServiceFrame f) {
    RecoverEval e;
    if (g.has(M_RECOVER_HOLD, f)) e.effect = "holdReleased";
    else if (g.has(M_RECOVER_NONE, f)) e.effect = "noHolder";
    else if (g.has(M_RECOVER_GHOST, f)) e.effect = "ghostRemoved";
    else if (g.has(M_RECOVER_REGAINED, f)) e.effect = "nicknameRecovered";
    else if (g.has(M_RECOVER_REMOVED_21, f) || g.has(M_RECOVER_REMOVED_20, f)) e.effect = "removedNeedsRelease";
    e.refused = findRefusal(g, f, RECOVER_REFUSALS, e.refusalStatus, e.refusal);
    e.loginClaimed = g.has(M_RECOVER_LOGGED_IN, f);
    bool seen;
    const change = lastAccountChange(f, seen);
    if (seen && change.state == ServicesActorState.account) e.observed = change.account;
    return e;
}

private void runAccountRecover(ServicesTransaction txn, AnopeGrammar g) {
    const nick = paramString(txn, "nick");
    const password = paramString(txn, "password");
    const body_ = "RECOVER " ~ nick ~ (password.length ? " " ~ password : "");
    if (!fitsOrReject(txn, body_)) return;
    ServiceFrameTerminal terminal = (ref const ServiceFrame f) {
        auto e = evaluateRecover(g, f);
        return e.effect.length || e.refused;
    };
    requireHelp(txn, ServiceAction.accountRecover, () {
        txn.frame(writeSpec(txn, body_, ServiceFrameKind.asyncAuth, terminal), (ServiceFrame f) {
            if (ambiguousWrite(txn, f)) return;
            auto e = evaluateRecover(g, f);
            auto details = txn.details(f.lines);
            if (e.conflicting) return completeConflict(txn, details);
            if (!e.effect.length) {
                if (e.refused) {
                    // ns_recover answers a wrong password with ACCESS_DENIED.
                    const reason = e.refusal == "access_denied" && password.length ? "password_incorrect" : e.refusal;
                    txn.complete(e.refusalStatus, reason, Json.undefined, "", Json.undefined, details);
                } else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                    ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                    Json.undefined, "", Json.undefined, details);
                return;
            }
            auto data = Json(["kind": Json("recovery"), "nick": Json(nick), "effect": Json(e.effect)]);
            // A login is reported only from the server, never from the text.
            if (e.observed.length) data["account"] = Json(e.observed);
            const current = txn.ownNick();
            data["currentNick"] = Json(current);
            data["nickHeld"] = Json(txn.sameNick(current, nick));
            txn.complete(ServiceStatus.confirmed, "", data, "", Json.undefined, details);
        });
    });
}

// ── SET HIDE ───────────────────────────────────────────────────────────────

/// Field index into HIDE_ACKS, or -1.
private ptrdiff_t privacyIndex(string field) {
    foreach (i, f; PRIVACY_FIELDS)
        if (f == field) return cast(ptrdiff_t) i;
    return -1;
}

string privacyWire(string field, bool v21) {
    switch (field) {
        case "email": return "EMAIL";
        case "status": return "STATUS";
        case "mask": return v21 ? "MASK" : "USERMASK";
        case "quit": return "QUIT";
        default: return "";
    }
}

/// SET HIDE ack for exactly this field/direction, naming `account` and the
/// verified service nick.
bool privacyAccepted(AnopeGrammar g, const ref ServiceFrame f, string field, bool enabled, string account,
        string serviceNick, NickEq same) {
    const i = privacyIndex(field);
    if (i < 0) return false;
    string[] c;
    if (!g.matches(HIDE_ACKS[i][g.v21 ? 0 : 1][enabled ? 0 : 1], f, c) || c.length < 2) return false;
    return same(c[0], account) && same(c[1], serviceNick);
}

/// The privacy outcome is never `confirmed`: own INFO always shows hidden
/// fields and never exposes HIDE flags, so the public view is unverifiable
/// from the actor's session. No current-setting value is reported.
void privacyVerdict(bool accepted, bool readbackOk, string field, bool enabled, out ServiceStatus status,
        out string reason, out Json data) {
    if (!accepted) {
        status = ServiceStatus.unconfirmed;
        reason = "no_ack";
        data = Json.undefined;
        return;
    }
    status = ServiceStatus.unconfirmed;
    reason = "privacy_unverified";
    data = Json(["kind": Json("privacy"), "field": Json(field), "requestedEnabled": Json(enabled),
        "verification": Json("acceptedOnly"), "readback": Json(readbackOk ? "completed" : "unavailable")]);
}

private void runAccountPrivacy(ServicesTransaction txn, AnopeGrammar g) {
    const field = txn.request.params["field"].type == Json.Type.string ? txn.request.params["field"].get!string : "";
    const enabled = paramBool(txn, "enabled");
    const account = txn.actor.account;
    const wire = privacyWire(field, g.v21);
    if (!wire.length) {
        txn.complete(ServiceStatus.rejected, "invalid_field");
        return;
    }
    const body_ = "SET HIDE " ~ wire ~ (enabled ? " ON" : " OFF");
    const info = "INFO " ~ account;
    if (!fitsOrReject(txn, body_) || !fitsOrReject(txn, info)) return;
    requireHelp(txn, ServiceAction.accountPrivacy, () {
        txn.frame(readSpec(info), (ServiceFrame pre) {
            if (readFailed(txn, pre)) return;
            auto before = parseNickInfo(g, pre);
            if (!before.registered || !txn.sameNick(before.account, account)) {
                txn.complete(ServiceStatus.stale, "account_changed");
                return;
            }
            if (!requireServicesRevision(txn, servicesRevision(txn,
                    accountCanonical(before.account, true, !before.unconfirmed)), nickInfoJson(before),
                    Json.undefined)) return;
            txn.frame(writeSpec(txn, body_, ServiceFrameKind.ordinary), (ServiceFrame f) {
                if (ambiguousWrite(txn, f)) return;
                const accepted = privacyAccepted(g, f, field, enabled, account, txn.endpoint.nick, &txn.sameNick);
                auto details = txn.details(f.lines);
                if (!accepted) {
                    ServiceStatus st;
                    string reason;
                    if (findRefusal(g, f, PRIVACY_REFUSALS, st, reason))
                        txn.complete(st, reason, Json.undefined, "", Json.undefined, details);
                    else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                        ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                        Json.undefined, "", Json.undefined, details);
                    return;
                }
                // Read back own INFO (account still ours, current revision);
                // it cannot show the public view.
                txn.frame(readSpec(info), (ServiceFrame after) {
                    auto back = parseNickInfo(g, after);
                    const ok = after.outcome == ServiceFrameOutcome.completed && frameComplete(after)
                        && back.registered && txn.sameNick(back.account, account);
                    ServiceStatus st;
                    string reason;
                    Json data;
                    privacyVerdict(true, ok, field, enabled, st, reason, data);
                    const revision = ok
                        ? servicesRevision(txn, accountCanonical(back.account, true, !back.unconfirmed)) : "";
                    txn.complete(st, reason, data, revision, Json.undefined, details);
                });
            });
        });
    });
}

// ── HostServ (personal) ────────────────────────────────────────────────────

/// Host state from own NickServ INFO (assigned vhost) and WHOIS (current).
private struct HostState {
    /// The vhost HostServ ON would use is known (present or absent).
    bool assignedKnown;
    string assigned;
    /// The current nick's alias was read.
    bool nickKnown;
    /// The current nick is an alias of the actor's account (hs_request gate).
    bool nickInAccount;
    bool currentKnown;
    string currentHost;
    string currentIdent;
    /// NickServ peer read refused (busy/untrusted/absent).
    string peerReason;
}

/// `[ident@]host` equality: host case-insensitively, ident when both name one.
bool vhostMatches(string observed, string mask) {
    if (!observed.length || !mask.length) return false;
    const oa = observed.indexOf('@'), ma = mask.indexOf('@');
    const oh = oa < 0 ? observed : observed[oa + 1 .. $];
    const mh = ma < 0 ? mask : mask[ma + 1 .. $];
    if (!asciiSame(oh, mh)) return false;
    if (oa >= 0 && ma >= 0) return observed[0 .. oa] == mask[0 .. ma];
    return true;
}

/// Own displayed host from IRC effects seen while the frame was open:
/// RPL_VISIBLEHOST (396) or CHGHOST for our nick. "" when none.
string ownHostEffect(const ServiceEffect[] effects, string ownNick, NickEq same) {
    string host;
    foreach (ref e; effects) {
        if (e.command == "396" && e.params.length >= 2 && same(e.params[0], ownNick)) host = e.params[1];
        else if (e.command == "CHGHOST" && e.params.length >= 2) {
            const bang = e.prefix.indexOf('!');
            const nick = bang < 0 ? e.prefix : e.prefix[0 .. bang];
            if (same(nick, ownNick)) host = e.params[0] ~ "@" ~ e.params[1];
        }
    }
    return host;
}

private void readHostState(ServicesTransaction txn, AnopeGrammar g, void delegate(HostState) done) {
    HostState s;
    const own = txn.ownNick();
    const account = txn.actor.account;

    void whoisOwn() {
        txn.whois(own, (ServicesWhois w) {
            if (w.complete && w.present && w.host.length) {
                s.currentKnown = true;
                s.currentHost = w.host;
                s.currentIdent = w.ident;
            }
            done(s);
        });
    }

    void accountAlias() {
        txn.frameOn(ServiceId.nickServ, readSpec("INFO " ~ account), (ServiceFrame f) {
            if (f.outcome == ServiceFrameOutcome.unavailable) s.peerReason = incompleteReason(f);
            else if (f.outcome == ServiceFrameOutcome.completed && frameComplete(f)) {
                auto i = parseNickInfo(g, f);
                if (i.registered && txn.sameNick(i.account, account)) {
                    s.assignedKnown = true;
                    s.assigned = i.vhostFound ? i.vhost : "";
                }
            }
            whoisOwn();
        });
    }

    if (!fitsOrReject(txn, "INFO " ~ own) || !fitsOrReject(txn, "INFO " ~ account)) return;
    // hs_on/hs_off: the current nick's alias vhost when it is ours and has
    // one, else the account's own alias (AccountNick / display).
    txn.frameOn(ServiceId.nickServ, readSpec("INFO " ~ own), (ServiceFrame f) {
        if (f.outcome == ServiceFrameOutcome.unavailable) {
            s.peerReason = incompleteReason(f);
            whoisOwn();
            return;
        }
        if (f.outcome == ServiceFrameOutcome.completed && frameComplete(f)) {
            auto i = parseNickInfo(g, f);
            if (i.recognized) {
                s.nickKnown = true;
                s.nickInAccount = i.registered && txn.sameNick(i.account, account);
                if (s.nickInAccount && (i.vhostFound || txn.sameNick(own, account))) {
                    s.assignedKnown = true;
                    s.assigned = i.vhostFound ? i.vhost : "";
                    whoisOwn();
                    return;
                }
            }
        }
        accountAlias();
    });
}

private Json hostCanonical(const ref HostState s) {
    auto j = Json(["kind": Json("hostname")]);
    if (s.currentKnown) j["currentHost"] = Json(s.currentHost.toLower);
    if (s.assignedKnown) j["assignedVhost"] = s.assigned.length ? Json(s.assigned.toLower) : Json(null);
    return j;
}

/// Server-observable host state only: current host (WHOIS/396/CHGHOST) and
/// the assigned (approved) vhost from own INFO. Nothing about a pending
/// request, which the requester cannot read back.
private Json hostView(const ref HostState s) {
    auto j = Json(["kind": Json("hostname")]);
    if (s.currentKnown) j["currentHost"] = Json(s.currentHost);
    if (s.assignedKnown) {
        j["vhostAssigned"] = Json(s.assigned.length > 0);
        if (s.assigned.length) j["assignedVhost"] = Json(s.assigned);
    }
    return j;
}

private void hostCapabilities(ServicesTransaction txn, const HostState s, void delegate(Json) done) {
    readCapabilities(txn, [
        ServiceAction.hostRequest,
        ServiceAction.hostOn,
        ServiceAction.hostOff,
    ], (Json caps) {
        if (s.nickKnown && !s.nickInAccount)
            narrowCapability(caps, ServiceAction.hostRequest, "denied", "nick_not_in_account");
        else if (!s.nickKnown)
            narrowCapability(caps, ServiceAction.hostRequest, "unknown", s.peerReason.length ? s.peerReason : "state_unknown");
        foreach (a; [ServiceAction.hostOn, ServiceAction.hostOff]) {
            if (!s.assignedKnown)
                narrowCapability(caps, a, "unknown", s.peerReason.length ? s.peerReason : "state_unknown");
            else if (!s.assigned.length) narrowCapability(caps, a, "denied", "vhost_not_assigned");
            else if (!s.currentKnown) narrowCapability(caps, a, "unknown", "current_host_unknown");
        }
        done(caps);
    });
}

private void runHostInfo(ServicesTransaction txn, AnopeGrammar g) {
    // `supports` already required a certified grammar.
    readHostState(txn, g, (HostState s) {
        auto data = hostView(s);
        const revision = servicesRevision(txn, hostCanonical(s));
        hostCapabilities(txn, s, (Json caps) {
            const complete_ = s.assignedKnown && s.currentKnown;
            txn.complete(complete_ ? ServiceStatus.confirmed : ServiceStatus.unconfirmed,
                complete_ ? "" : (s.peerReason.length ? s.peerReason : "state_incomplete"), data, revision, caps);
        });
    });
}

/// Fresh host state, revision check, then `proceed`.
private void hostPrecheck(ServicesTransaction txn, AnopeGrammar g, void delegate(HostState) proceed) {
    readHostState(txn, g, (HostState s) {
        if (!requireServicesRevision(txn, servicesRevision(txn, hostCanonical(s)), hostView(s),
                Json.undefined)) return;
        proceed(s);
    });
}

/// REQUEST ack mask ("" for 2.0, which names none); false when absent.
bool hostRequestAccepted(AnopeGrammar g, const ref ServiceFrame f, out string mask) {
    string[] c;
    if (g.matches(M_HOST_REQUESTED_DNS_21, f, c) || g.matches(M_HOST_REQUESTED_21, f, c)) {
        mask = c.length ? c[0] : "";
        return true;
    }
    return g.has(M_HOST_REQUESTED_20, f);
}

private void runHostRequest(ServicesTransaction txn, AnopeGrammar g) {
    const host = paramString(txn, "host");
    const body_ = "REQUEST " ~ host;
    if (!fitsOrReject(txn, body_)) return;
    requireHelp(txn, ServiceAction.hostRequest, () {
        hostPrecheck(txn, g, (HostState s) {
            if (s.nickKnown && !s.nickInAccount) {
                txn.complete(ServiceStatus.rejected, "nick_not_in_account");
                return;
            }
            txn.frame(writeSpec(txn, body_, ServiceFrameKind.ordinary), (ServiceFrame f) {
                if (ambiguousWrite(txn, f)) return;
                string mask;
                const accepted = hostRequestAccepted(g, f, mask);
                // The DNS variant carries a validation token: recognised
                // non-private lines only.
                auto details = recognizedDetails(txn, g, f,
                    [M_HOST_REQUESTED_21, M_HOST_REQUESTED_20] ~ refusalMsgids(HOST_REQUEST_REFUSALS));
                if (!accepted || (mask.length && !vhostMatches(mask, host))) {
                    ServiceStatus st;
                    string reason;
                    if (!accepted && findRefusal(g, f, HOST_REQUEST_REFUSALS, st, reason))
                        txn.complete(st, reason == "access_denied" ? "nick_not_in_account" : reason,
                            Json.undefined, "", Json.undefined, details);
                    else txn.complete(ServiceStatus.unconfirmed, accepted ? "ack_mismatch"
                        : f.outcome == ServiceFrameOutcome.completed
                            ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                        Json.undefined, "", Json.undefined, details);
                    return;
                }
                // Anope has no requester-side read of a pending request: the
                // pending state exists only in this acknowledged result.
                auto data = hostView(s);
                data["requestedVhost"] = Json(mask.length ? mask : host);
                data["pending"] = Json(true);
                txn.complete(ServiceStatus.confirmed, "", data, servicesRevision(txn, hostCanonical(s)),
                    Json.undefined, details);
            });
        });
    });
}

/// HostServ ON evidence: ack mask (ident@host on 2.0's ident form).
bool hostOnAccepted(AnopeGrammar g, const ref ServiceFrame f, out string mask) {
    string[] c;
    if (!g.v21 && g.matches(M_HOST_ON_IDENT_20, f, c) && c.length >= 2) {
        mask = c[0] ~ "@" ~ c[1];
        return true;
    }
    if (g.matches(M_HOST_ON, f, c) && c.length) {
        mask = c[0];
        return true;
    }
    return false;
}

private void runHostOn(ServicesTransaction txn, AnopeGrammar g) {
    requireHelp(txn, ServiceAction.hostOn, () {
        hostPrecheck(txn, g, (HostState s) {
            txn.frame(writeSpec(txn, "ON", ServiceFrameKind.ordinary), (ServiceFrame f) {
                if (ambiguousWrite(txn, f)) return;
                string mask;
                const accepted = hostOnAccepted(g, f, mask);
                auto details = txn.details(f.lines);
                if (!accepted) {
                    ServiceStatus st;
                    string reason;
                    if (findRefusal(g, f, HOST_TOGGLE_REFUSALS, st, reason))
                        txn.complete(st, reason, Json.undefined, "", Json.undefined, details);
                    else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                        ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                        Json.undefined, "", Json.undefined, details);
                    return;
                }
                const own = txn.ownNick();
                HostState after = s;
                after.assignedKnown = true;
                after.assigned = mask;
                void finish(string observed) {
                    if (observed.length) {
                        const at = observed.indexOf('@');
                        after.currentKnown = true;
                        after.currentHost = at < 0 ? observed : observed[at + 1 .. $];
                    }
                    const active = observed.length && vhostMatches(observed, mask);
                    auto data = hostView(after);
                    const revision = servicesRevision(txn, hostCanonical(after));
                    txn.complete(active ? ServiceStatus.confirmed : ServiceStatus.unconfirmed,
                        active ? "" : "host_not_observed", data, revision, Json.undefined, details);
                }
                const effect = ownHostEffect(f.effects, own, &txn.sameNick);
                if (effect.length && vhostMatches(effect, mask)) return finish(effect);
                // No host change seen (already active, or not yet): the
                // server's WHOIS is the observation, the ack alone is not.
                txn.whois(own, (ServicesWhois w) {
                    finish(w.complete && w.present && w.host.length
                        ? (w.ident.length ? w.ident ~ "@" ~ w.host : w.host) : "");
                });
            });
        });
    });
}

private void runHostOff(ServicesTransaction txn, AnopeGrammar g) {
    requireHelp(txn, ServiceAction.hostOff, () {
        hostPrecheck(txn, g, (HostState s) {
            txn.frame(writeSpec(txn, "OFF", ServiceFrameKind.ordinary), (ServiceFrame f) {
                if (ambiguousWrite(txn, f)) return;
                const accepted = g.has(M_HOST_OFF, f);
                auto details = txn.details(f.lines);
                if (!accepted) {
                    ServiceStatus st;
                    string reason;
                    if (findRefusal(g, f, HOST_TOGGLE_REFUSALS, st, reason))
                        txn.complete(st, reason, Json.undefined, "", Json.undefined, details);
                    else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                        ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                        Json.undefined, "", Json.undefined, details);
                    return;
                }
                const own = txn.ownNick();
                void finish(string observedHost) {
                    HostState after = s;
                    after.currentKnown = observedHost.length > 0;
                    after.currentHost = observedHost;
                    // Removed = the observed host is no longer the vhost (or,
                    // when the vhost is unknown, it changed).
                    const removed = observedHost.length && (s.assignedKnown && s.assigned.length
                        ? !vhostMatches(observedHost, s.assigned)
                        : s.currentKnown && !asciiSame(observedHost, s.currentHost));
                    auto data = hostView(after);
                    const revision = servicesRevision(txn, hostCanonical(after));
                    txn.complete(removed ? ServiceStatus.confirmed : ServiceStatus.unconfirmed,
                        removed ? "" : "host_not_observed", data, revision, Json.undefined, details);
                }
                const effect = ownHostEffect(f.effects, own, &txn.sameNick);
                if (effect.length) {
                    const at = effect.indexOf('@');
                    return finish(at < 0 ? effect : effect[at + 1 .. $]);
                }
                txn.whois(own, (ServicesWhois w) {
                    finish(w.complete && w.present ? w.host : "");
                });
            });
        });
    });
}

// ── MemoServ ───────────────────────────────────────────────────────────────

struct MemoEntry {
    uint number;
    string sender;
    string sentAt;
    bool unread;
}

/// Personal `LIST` (ms_list.cpp): "Memos for <nick>:" then a FIXED table
/// (translated header row) or 2.1 FLEXIBLE rows, numbered 1..n, `* ` unread.
struct MemoInbox {
    bool ok;
    MemoEntry[] entries;
}

/// MemoServ's own unsolicited arrival notice (2.1 single line).
private bool memoArrival(AnopeGrammar g, string line) {
    string[] c;
    return g.v21 && (g.matches(M_MEMO_ARRIVED_21, line, c) || g.matches(M_MEMO_X_ARRIVED_21, line, c));
}

/// Releases MemoServ arrival notices to ordinary traffic. Never used for
/// READ frames, whose body lines are attacker-controlled.
private ServiceLineRelease memoArrivalRelease(AnopeGrammar g) {
    if (!g.v21) return null;
    return (ref const ServiceReplyLine l) => !l.replyTo.length && memoArrival(g, l.plain);
}

private bool parseMemoRow(string line, out MemoEntry e) {
    if (line.startsWith("* ")) e.unread = true;
    else if (!line.startsWith("  ")) return false;
    auto rest = line[2 .. $];
    size_t i;
    while (i < rest.length && isDigit(rest[i])) ++i;
    if (!i || i > 9) return false;
    e.number = rest[0 .. i].to!uint;
    rest = rest[i .. $];
    if (!rest.startsWith("  ")) return false;
    rest = rest.stripLeft;
    const sp = rest.indexOf(' ');
    if (sp <= 0) return false;
    e.sender = rest[0 .. sp];
    rest = rest[sp .. $];
    if (!rest.startsWith("  ")) return false;
    e.sentAt = rest.strip;
    return e.sentAt.length > 0;
}

private bool parseFlexibleMemoRow(AnopeGrammar g, string line, out MemoEntry e) {
    string[string] v;
    if (!templateRow(g, M_MEMO_LIST_ROW_21, line, v)) return false;
    const number = v.get("number", "");
    if (number.startsWith("* ")) e.unread = true;
    else if (!number.startsWith("  ")) return false;
    const digits = number[2 .. $];
    if (!digits.length || digits.length > 9) return false;
    foreach (ch; digits)
        if (!isDigit(ch)) return false;
    e.number = digits.to!uint;
    e.sender = v.get("sender", "");
    e.sentAt = v.get("date/time", "").strip;
    return e.sender.length && !e.sender.canFind(' ');
}

MemoInbox parseMemoList(AnopeGrammar g, const ref ServiceFrame f) {
    MemoInbox r;
    const(ServiceReplyLine)[] lines;
    foreach (ref l; f.lines)
        if (!memoArrival(g, l.plain)) lines ~= l;
    if (!lines.length) return r;
    string[] c;
    if (lines.length == 1 && g.matches(M_MEMO_NONE, lines[0].plain, c)) {
        r.ok = true;
        return r;
    }
    if (!g.matches(M_MEMO_LIST_HEADER, lines[0].plain, c) || lines.length < 2) return r;
    auto rows = lines[1 .. $];
    MemoEntry probe;
    // A header row never matches the flexible template.
    const flexible = g.v21 && parseFlexibleMemoRow(g, rows[0].plain, probe);
    string prev = rows[0].plain;
    foreach (ref l; flexible ? rows : rows[1 .. $]) {
        MemoEntry entry;
        if (flexible ? parseFlexibleMemoRow(g, l.plain, entry) : parseMemoRow(rowText(l), entry)) {
            // A full LIST is positional: 1..n with no gaps.
            if (entry.number != r.entries.length + 1) {
                r.entries = null;
                return r;
            }
            r.entries ~= entry;
        } else if (g.v21 && r.entries.length && wrapContinuation(prev, l.plain)) {
            // LineWrapper tail of the previous row: its last column (date).
            r.entries[$ - 1].sentAt ~= " " ~ l.plain.strip;
        } else {
            r.entries = null;
            return r;
        }
        prev = l.plain;
    }
    r.ok = r.entries.length > 0;
    return r;
}

private size_t unreadCount(const MemoEntry[] entries) {
    size_t n;
    foreach (ref e; entries) if (e.unread) ++n;
    return n;
}

private Json inboxJson(string account, const MemoEntry[] entries) {
    Json[] list;
    foreach (ref e; entries)
        list ~= Json(["number": Json(e.number), "sender": Json(e.sender), "sentAt": Json(e.sentAt),
            "unread": Json(e.unread)]);
    return Json(["kind": Json("memoInbox"), "account": Json(account), "entries": Json(list),
        "unreadCount": Json(cast(long) unreadCount(entries))]);
}

/// `Anope::strftime` appends a translated relative age (`(%s ago)`,
/// `(%s from now)`, `(now)`) that changes with the clock; the revision keeps
/// only the absolute timestamp before it.
string absoluteServiceTime(string text) {
    const t = text.strip;
    if (!t.endsWith(")")) return t;
    const open = t.lastIndexOf(" (");
    return open > 0 ? t[0 .. open] : t;
}

private Json inboxCanonical(string account, const MemoEntry[] entries) {
    Json[] list;
    foreach (ref e; entries)
        list ~= Json(["number": Json(e.number), "sender": Json(e.sender.toLower),
            "sentAt": Json(absoluteServiceTime(e.sentAt)), "unread": Json(e.unread)]);
    return Json(["kind": Json("memoInbox"), "account": Json(account.toLower), "entries": Json(list)]);
}

@("services identity: memo revision ignores the relative age suffix")
unittest {
    assert(absoluteServiceTime("Nov 06 12:00:00 2026 UTC (5 seconds ago)") == "Nov 06 12:00:00 2026 UTC");
    assert(absoluteServiceTime("Thu Nov  6 12:00:00 2026 (now)") == "Thu Nov  6 12:00:00 2026");
    assert(absoluteServiceTime("Thu Nov  6 12:00:00 2026") == "Thu Nov  6 12:00:00 2026");
    MemoEntry a = MemoEntry(1, "bob", "Nov 06 2026 (5 seconds ago)", true);
    MemoEntry b = MemoEntry(1, "Bob", "Nov 06 2026 (9 seconds ago)", true);
    assert(inboxCanonical("alice", [a]) == inboxCanonical("Alice", [b]));
}

/// Fresh LIST, parsed; answers the request itself on failure.
private void readInbox(ServicesTransaction txn, AnopeGrammar g, void delegate(MemoInbox) done) {
    txn.frame(readSpec("LIST", memoArrivalRelease(g)), (ServiceFrame f) {
        ServiceStatus st;
        string reason;
        if (readFailed(txn, f)) return;
        auto inbox = parseMemoList(g, f);
        if (!inbox.ok) {
            if (findRefusal(g, f, null, st, reason)) txn.complete(st, reason);
            else txn.complete(ServiceStatus.unconfirmed, f.lines.length ? "unrecognized_reply" : "no_reply");
            return;
        }
        done(inbox);
    });
}

private void runMemoList(ServicesTransaction txn, AnopeGrammar g) {
    const account = txn.actor.account;
    readInbox(txn, g, (MemoInbox inbox) {
        const revision = servicesRevision(txn, inboxCanonical(account, inbox.entries));
        auto data = inboxJson(account, inbox.entries);
        readCapabilities(txn, [
            ServiceAction.memoRead,
            ServiceAction.memoDelete,
            ServiceAction.memoSend,
        ], (Json caps) {
            if (!inbox.entries.length) {
                narrowCapability(caps, ServiceAction.memoRead, "denied", "no_memos");
                narrowCapability(caps, ServiceAction.memoDelete, "denied", "no_memos");
            }
            txn.complete(ServiceStatus.confirmed, "", data, revision, caps);
        });
    });
}

/// Anchored printf capture over one normalized template, in argument order
/// (`%N$` reordering honoured). `%d`/`%u`/`%i`/`%zu` take digits; arguments
/// flagged in `noSpace` are non-empty and space-free (nicks). The shortest
/// reading of every free `%s` that lets the rest match is taken, so a final
/// free-text argument (a date) runs up to the template's closing literal.
bool printfCapture(string tmpl, string line, const bool[] noSpace, out string[] caps) {
    string[size_t] found;
    bool rec(string t, string l, size_t nextArg) {
        if (!t.length) return !l.length;
        if (t[0] != '%') return l.length && l[0] == t[0] && rec(t[1 .. $], l[1 .. $], nextArg);
        if (t.length > 1 && t[1] == '%') return l.length && l[0] == '%' && rec(t[2 .. $], l[1 .. $], nextArg);
        size_t i = 1, j = 1;
        while (j < t.length && isDigit(t[j])) ++j;
        size_t arg = nextArg, next = nextArg + 1;
        if (j > 1 && j < t.length && t[j] == '$') {
            arg = t[1 .. j].to!size_t - 1;
            next = nextArg;
            i = j + 1;
        }
        while (i < t.length && (t[i] == 'z' || t[i] == 'l' || t[i] == 'h')) ++i;
        if (i >= t.length) return false;
        const conv = t[i];
        const rest = t[i + 1 .. $];
        const digits = conv == 'd' || conv == 'u' || conv == 'i';
        const tight = arg < noSpace.length && noSpace[arg];
        foreach (k; (digits || tight ? 1 : 0) .. l.length + 1) {
            if (k > 0) {
                const ch = l[k - 1];
                if ((digits && !isDigit(ch)) || (tight && ch == ' ')) break;
            }
            const v = l[0 .. k];
            if (auto p = arg in found) {
                if (*p == v && rec(rest, l[k .. $], next)) return true;
                continue;
            }
            found[arg] = v;
            if (rec(rest, l[k .. $], next)) return true;
            found.remove(arg);
        }
        return false;
    }
    if (!rec(tmpl, line, 0)) return false;
    foreach (a; 0 .. found.length) {
        auto p = a in found;
        if (p is null) return false;
        caps ~= *p;
    }
    return true;
}

/// `Memo %d from %s (%s).` — the date comes from `Anope::strftime`, which
/// appends a translated `(%s ago)` / `(%s from now)` / `(now)`, so the
/// generic matcher finds the sender/date split ambiguous. The sender is a
/// nick (no spaces) and the date runs to the closing `).`.
private bool memoReadHeader(AnopeGrammar g, string line, out string[] caps) {
    if (g.matches(M_MEMO_READ_HEADER, line, caps) && caps.length >= 3) return true;
    foreach (v; g.variants(M_MEMO_READ_HEADER))
        if (printfCapture(v, line, [false, true, false], caps) && caps.length >= 3) return true;
    caps = null;
    return false;
}

/// The optional delete hint naming exactly this memo number.
private bool memoReadHint(AnopeGrammar g, string line, uint expected) {
    const want = expected.to!string;
    foreach (m; [M_MEMO_READ_HINT_21, M_MEMO_READ_HINT_20]) {
        string[] h;
        if (g.matches(m, line, h) && h.length && h[$ - 1] == want) return true;
        foreach (v; g.variants(m))
            if (printfCapture(v, line, null, h) && h.length && h[$ - 1] == want) return true;
    }
    return false;
}

/// One memo READ (ms_read.cpp DoRead): header, optional delete hint, then
/// body. The body is attacker-controlled and may imitate a header, so only
/// the first line can be the header and everything after it is body. A
/// partial frame (deadline, truncation) never yields text. Anope 2.1 tags
/// CommandSource replies with `+reply` (users.cpp): on a correlated frame
/// only lines answering our READ count (MemoServ's untagged arrival notices
/// are not body). Anope 2.0 never tags replies, so even a frame whose own
/// msgid was learned from an echo collects them untagged; there (and on any
/// uncorrelated frame) an arrival notice in the window makes the body
/// ambiguous and nothing is returned.
struct MemoReadView {
    bool ok;
    uint number;
    string sender;
    string sentAt;
    string text;
}

MemoReadView parseMemoRead(AnopeGrammar g, const ref ServiceFrame f, uint expected) {
    MemoReadView r;
    if (!frameComplete(f)) return r;
    const(ServiceReplyLine)[] lines;
    if (g.v21 && f.replyCorrelated) {
        foreach (ref l; f.lines)
            if (l.attribution == ServiceReplyAttribution.reply) lines ~= l;
    } else {
        if (g.hasAny(MEMO_ARRIVALS, f)) return r;
        lines = f.lines;
    }
    if (lines.length < 2) return r;
    // The header may be wrapped by 2.1's LineWrapper (long nick/locale
    // date): it is the first line, or the first two joined by one space.
    string[] c;
    size_t start;
    if (memoReadHeader(g, lines[0].plain, c)) start = 1;
    else if (lines.length >= 3 && memoReadHeader(g, lines[0].plain ~ " " ~ lines[1].plain, c)) start = 2;
    else return r;
    if (c[0] != expected.to!string) return r;
    r.number = expected;
    r.sender = c[1];
    r.sentAt = c[2];
    if (start < lines.length && memoReadHint(g, lines[start].plain, expected)) ++start;
    if (start >= lines.length) return r;
    string[] body_;
    foreach (ref l; lines[start .. $]) body_ ~= l.plain;
    r.text = body_.join("\n");
    r.ok = true;
    return r;
}

/// Resolves `selection` to one memo number from a fresh LIST: a single
/// number or LAST. Multi-memo READ is ambiguous (bodies imitate headers).
private uint memoSelection(string selection, const MemoEntry[] entries, out string reason) {
    if (selection == "LAST") {
        if (!entries.length) reason = "memo_not_found";
        return cast(uint) entries.length;
    }
    if (!selection.length || selection.length > 9) {
        reason = "single_memo_only";
        return 0;
    }
    foreach (ch; selection)
        if (!isDigit(ch)) {
            reason = "single_memo_only";
            return 0;
        }
    const n = selection.to!uint;
    if (!n || n > entries.length) {
        reason = "memo_not_found";
        return 0;
    }
    return n;
}

private void runMemoRead(ServicesTransaction txn, AnopeGrammar g) {
    const selection = paramString(txn, "selection");
    const account = txn.actor.account;
    requireHelp(txn, ServiceAction.memoRead, () {
        readInbox(txn, g, (MemoInbox before) {
            if (!requireServicesRevision(txn, servicesRevision(txn, inboxCanonical(account, before.entries)),
                    inboxJson(account, before.entries), Json.undefined)) return;
            string reason;
            const number = memoSelection(selection, before.entries, reason);
            if (!number) {
                txn.complete(reason == "single_memo_only" ? ServiceStatus.unavailable : ServiceStatus.rejected, reason);
                return;
            }
            // READ marks the memo read: a mutation with one number only.
            txn.frame(writeSpec(txn, "READ " ~ number.to!string, ServiceFrameKind.ordinary), (ServiceFrame f) {
                if (ambiguousWrite(txn, f)) return;
                auto memo = parseMemoRead(g, f, number);
                if (!memo.ok) {
                    ServiceStatus st;
                    string why;
                    // Memo text never becomes details, and a body line is
                    // never read as an ack or denial: only a short answer
                    // whose first line is the refusal counts.
                    if (firstLineRefusal(g, f, MEMO_REFUSALS, st, why)) txn.complete(st, why);
                    else if (!frameComplete(f)) txn.complete(ServiceStatus.unconfirmed, incompleteReason(f));
                    else if (!(g.v21 && f.replyCorrelated) && g.hasAny(MEMO_ARRIVALS, f))
                        txn.complete(ServiceStatus.unconfirmed, "ambiguous_reply");
                    else txn.complete(ServiceStatus.unconfirmed, f.lines.length ? "unrecognized_reply" : "no_reply");
                    return;
                }
                auto data = Json(["kind": Json("memo"), "account": Json(account), "number": Json(number),
                    "sender": Json(memo.sender), "sentAt": Json(memo.sentAt), "text": Json(memo.text)]);
                // The read state comes from a fresh LIST, not the READ reply.
                txn.frame(readSpec("LIST", memoArrivalRelease(g)), (ServiceFrame lf) {
                    auto after = parseMemoList(g, lf);
                    if (lf.outcome != ServiceFrameOutcome.completed || !frameComplete(lf) || !after.ok) {
                        txn.complete(ServiceStatus.unconfirmed, "readback_unavailable", data);
                        return;
                    }
                    data["inbox"] = inboxJson(account, after.entries);
                    const revision = servicesRevision(txn, inboxCanonical(account, after.entries));
                    const marked = number <= after.entries.length && !after.entries[number - 1].unread;
                    txn.complete(marked ? ServiceStatus.confirmed : ServiceStatus.unconfirmed,
                        marked ? "" : "readback_mismatch", data, revision);
                });
            });
        });
    });
}

/// SEND ack naming exactly the recipient.
bool memoSent(AnopeGrammar g, const ref ServiceFrame f, string recipient, NickEq same) {
    string[] c;
    return g.matches(M_MEMO_SENT, f, c) && c.length && same(c[0], recipient);
}

private void runMemoSend(ServicesTransaction txn, AnopeGrammar g) {
    const recipient = paramString(txn, "recipient");
    const targetNick = paramString(txn, "targetNick");
    const text = paramString(txn, "text");
    const body_ = "SEND " ~ recipient ~ " " ~ text;
    if (!fitsOrReject(txn, body_)) return;
    requireHelp(txn, ServiceAction.memoSend, () {
        // A nick shortcut must still be logged into the reviewed account.
        verifyServicesTarget(txn, recipient.startsWith("#") ? "" : recipient,
                recipient.startsWith("#") ? "" : targetNick, (bool ok) {
            if (!ok) return;
            txn.frame(writeSpec(txn, body_, ServiceFrameKind.ordinary), (ServiceFrame f) {
                if (ambiguousWrite(txn, f)) return;
                // Only recognised texts: an unknown-command echo would carry the memo.
                auto details = recognizedDetails(txn, g, f, [M_MEMO_SENT] ~ refusalMsgids(MEMO_SEND_REFUSALS));
                if (memoSent(g, f, recipient, &txn.sameNick)) {
                    // Sent is not delivered (an ignoring recipient still gets
                    // MEMO_SUCCESS); no read-back and never a re-send.
                    txn.complete(ServiceStatus.confirmed, "",
                        Json(["kind": Json("memoSent"), "recipient": Json(recipient)]), "", Json.undefined, details);
                    return;
                }
                ServiceStatus st;
                string reason;
                if (findRefusal(g, f, MEMO_SEND_REFUSALS, st, reason))
                    txn.complete(st, reason, Json.undefined, "", Json.undefined, details);
                else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                    ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                    Json.undefined, "", Json.undefined, details);
            });
        });
    });
}

/// DEL ack for exactly `number`.
bool memoDeleted(AnopeGrammar g, const ref ServiceFrame f, uint number) {
    string[] c;
    return g.matches(M_MEMO_DELETED, f, c) && c.length && c[0] == number.to!string;
}

private void runMemoDelete(ServicesTransaction txn, AnopeGrammar g) {
    const number = paramLong(txn, "number");
    const account = txn.actor.account;
    if (number <= 0 || number > uint.max) {
        txn.complete(ServiceStatus.rejected, "memo_not_found");
        return;
    }
    const n = cast(uint) number;
    requireHelp(txn, ServiceAction.memoDelete, () {
        readInbox(txn, g, (MemoInbox before) {
            if (!requireServicesRevision(txn, servicesRevision(txn, inboxCanonical(account, before.entries)),
                    inboxJson(account, before.entries), Json.undefined)) return;
            if (n > before.entries.length) {
                txn.complete(ServiceStatus.rejected, "memo_not_found");
                return;
            }
            txn.frame(writeSpec(txn, "DEL " ~ n.to!string, ServiceFrameKind.ordinary, null, memoArrivalRelease(g)),
                    (ServiceFrame f) {
                if (ambiguousWrite(txn, f)) return;
                auto details = recognizedDetails(txn, g, f, [M_MEMO_DELETED] ~ refusalMsgids(MEMO_REFUSALS));
                if (!memoDeleted(g, f, n)) {
                    ServiceStatus st;
                    string reason;
                    if (findRefusal(g, f, MEMO_REFUSALS, st, reason))
                        txn.complete(st, reason, Json.undefined, "", Json.undefined, details);
                    else txn.complete(ServiceStatus.unconfirmed, f.outcome == ServiceFrameOutcome.completed
                        ? (f.lines.length ? "unrecognized_reply" : "no_reply") : incompleteReason(f),
                        Json.undefined, "", Json.undefined, details);
                    return;
                }
                txn.frame(readSpec("LIST", memoArrivalRelease(g)), (ServiceFrame lf) {
                    auto after = parseMemoList(g, lf);
                    if (lf.outcome != ServiceFrameOutcome.completed || !frameComplete(lf) || !after.ok) {
                        txn.complete(ServiceStatus.unconfirmed, "readback_unavailable", Json.undefined, "",
                            Json.undefined, details);
                        return;
                    }
                    txn.complete(ServiceStatus.confirmed, "", inboxJson(account, after.entries),
                        servicesRevision(txn, inboxCanonical(account, after.entries)), Json.undefined, details);
                });
            });
        });
    });
}

// ── Parser / transition boundary tests ─────────────────────────────────────

version (unittest) {
    private enum TEST_V21 = "Anope-2.1.27-git services.test -- inspircd -- enc_bcrypt";
    private enum TEST_V20 = "VERSION Anope-2.0.20 services.test :inspircd3 - (enc_bcrypt) -- Build #1";

    private bool testSame(string a, string b) { return asciiSame(a, b); }

    private ServiceFrame testFrame(string[] texts, string command = "NOTICE") {
        ServiceFrame f;
        f.outcome = ServiceFrameOutcome.completed;
        f.startFenced = f.endFenced = true;
        foreach (t; texts) {
            ServiceReplyLine l;
            l.command = command;
            l.text = t;
            l.plain = stripIrcFormatting(t);
            l.claimed = true;
            l.attribution = ServiceReplyAttribution.window;
            f.lines ~= l;
        }
        return f;
    }
}

@("services identity: translated PRIVMSG IDENTIFY needs the server-stated account")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    // de_DE "Password accepted - you are now recognized." over PRIVMSG (SET MESSAGE).
    auto f = testFrame(["Passwort akzeptiert - Du bist jetzt angemeldet."], "PRIVMSG");
    auto e = evaluateIdentify(g, f);
    assert(e.ack && !e.refused && !e.observed.length, "ack alone is not a login");
    f.accountChanges ~= ServicesActor(ServicesActorState.account, "alice");
    e = evaluateIdentify(g, f);
    assert(e.ack && e.observed == "alice");
    auto bad = testFrame(["Password incorrect."], "PRIVMSG");
    e = evaluateIdentify(g, bad);
    assert(!e.ack && e.refused && e.refusal == "password_incorrect" && e.refusalStatus == ServiceStatus.rejected);
}

@("services identity: REGISTER without login is registered-unconfirmed, prompts are awaiting states")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    NickEq same = (string a, string b) => testSame(a, b);
    auto plain = testFrame(["Nickname \x02alice\x02 registered."]);
    auto e = evaluateRegister(g, plain);
    assert(e.ack && e.ackNick == "alice");
    assert(registrationState(e, "alice", same) == "registered_unconfirmed");
    auto coded = testFrame(["Nickname \x02alice\x02 registered.",
        "All new accounts must be confirmed. To confirm your account, type \x02/msg NickServ CONFIRM\x1BREGISTER\x1Bq7Zk2p\x02.",
        "Your account will expire, if not confirmed, in 1 day."]);
    e = evaluateRegister(g, coded);
    assert(registrationState(e, "alice", same) == "awaiting_code" && e.code == "q7Zk2p");
    assert(hasPrivateText(g, coded), "generated code must keep the frame out of details");
    auto admin = testFrame(["Nickname \x02alice\x02 registered.",
        "All new accounts must be confirmed by an administrator. Please wait for your registration to be confirmed."]);
    e = evaluateRegister(g, admin);
    assert(registrationState(e, "alice", same) == "awaiting_admin");
    admin.accountChanges ~= ServicesActor(ServicesActorState.account, "alice");
    e = evaluateRegister(g, admin);
    assert(registrationState(e, "alice", same) == "identified");
    // 2.0 mail prompt and an unconfirmed INFO in German.
    auto g20 = new AnopeGrammar(TEST_V20);
    auto mail = testFrame(["Nickname \x02bob\x02 registered.",
        "Your email address is not confirmed. To confirm it, follow the instructions that were emailed to you."]);
    e = evaluateRegister(g20, mail);
    assert(registrationState(e, "bob", same) == "awaiting_email");
    auto info = testFrame(["Information about nick \x02alice\x02:", "alice ist ein noch nicht bestätigter Nickname.",
        "Account: alice (ID: 42)"]);
    auto ni = parseNickInfo(g, info);
    assert(ni.registered && ni.unconfirmed && ni.account == "alice");
}

@("services identity: memo READ body that imitates a header stays body")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    auto f = testFrame(["Memo 2 from bob (Nov 06 2026 12:00:00 UTC).",
        "To delete, type: \x02/msg MemoServ DEL\x1B2\x02",
        "Memo 3 from mallory (Nov 06 2026 12:01:00 UTC).",
        "To delete, type: /msg MemoServ DEL 3",
        "the real text"]);
    auto r = parseMemoRead(g, f, 2);
    assert(r.ok && r.sender == "bob" && r.number == 2);
    assert(r.text == "Memo 3 from mallory (Nov 06 2026 12:01:00 UTC).\nTo delete, type: /msg MemoServ DEL 3\nthe real text");
    assert(!parseMemoRead(g, f, 3).ok, "a different header number is not this memo");
    // fr_FR header over PRIVMSG.
    auto fr = testFrame(["Mémo 1 par carol (6 nov. 2026).", "bonjour"], "PRIVMSG");
    auto rf = parseMemoRead(g, fr, 1);
    assert(rf.ok && rf.sender == "carol" && rf.text == "bonjour");
    // LIST: fixed and monospace tables, positional numbering.
    auto list = testFrame(["Memos for alice:", "Number  Sender  Date/Time",
        "* 1     bob     Nov 06 2026", "  2     carol   Nov 06 2026"]);
    auto inbox = parseMemoList(g, list);
    assert(inbox.ok && inbox.entries.length == 2 && inbox.entries[0].unread && !inbox.entries[1].unread);
    auto mono = testFrame(["Memos for alice:", "\x11  Number  Sender  Date/Time",
        "\x11  * 1     bob     Nov 06 2026", "\x11    2     carol   Nov 06 2026"]);
    auto monoInbox = parseMemoList(g, mono);
    assert(monoInbox.ok && monoInbox.entries.length == 2 && !monoInbox.entries[1].unread);
    auto gap = testFrame(["Memos for alice:", "Number  Sender  Date/Time", "* 2     bob     Nov 06 2026"]);
    assert(!parseMemoList(g, gap).ok);
}

@("services identity: an accepted SET HIDE stays accepted-unverified")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    NickEq same = (string a, string b) => testSame(a, b);
    auto f = testFrame(["The last seen user@host mask of \x02alice\x02 will now be hidden from NickServ INFO displays."]);
    assert(privacyAccepted(g, f, "mask", true, "alice", "NickServ", same));
    assert(!privacyAccepted(g, f, "mask", false, "alice", "NickServ", same), "direction must match");
    assert(!privacyAccepted(g, f, "email", true, "alice", "NickServ", same), "field must match");
    assert(!privacyAccepted(g, f, "mask", true, "mallory", "NickServ", same), "account must match");
    ServiceStatus st;
    string reason;
    Json data;
    privacyVerdict(true, true, "mask", true, st, reason, data);
    assert(st == ServiceStatus.unconfirmed && reason == "privacy_unverified");
    assert(data["verification"].get!string == "acceptedOnly" && data["requestedEnabled"].get!bool);
    assert(data["enabled"].type == Json.Type.undefined && data["hidden"].type == Json.Type.undefined);
    assert(privacyWire("mask", true) == "MASK" && privacyWire("mask", false) == "USERMASK");
    auto g20 = new AnopeGrammar(TEST_V20);
    auto e20 = testFrame(["The E-mail address of \x02alice\x02 will now be shown in NickServ INFO displays."]);
    assert(privacyAccepted(g20, e20, "email", false, "alice", "NickServ", same));
}

@("services identity: vhost activation needs the observed host, not the approval")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    NickEq same = (string a, string b) => testSame(a, b);
    // de_DE "Your vhost of %s is now activated." over PRIVMSG.
    auto f = testFrame(["Dein vHost \x02cool.example\x02 ist jetzt aktiv."], "PRIVMSG");
    string mask;
    assert(hostOnAccepted(g, f, mask) && mask == "cool.example");
    assert(!ownHostEffect(f.effects, "alice", same).length, "an ack alone observes no host");
    ServiceEffect e396;
    e396.command = "396";
    e396.params = ["alice", "cool.example", "is now your displayed host"];
    f.effects ~= e396;
    const seen = ownHostEffect(f.effects, "alice", same);
    assert(vhostMatches(seen, mask));
    ServiceEffect other;
    other.command = "CHGHOST";
    other.prefix = "bob!b@old.host";
    other.params = ["b", "cool.example"];
    assert(!ownHostEffect([other], "alice", same).length, "another user's host change is not ours");
    ServiceEffect chg;
    chg.command = "CHGHOST";
    chg.prefix = "alice!a@cloak.example";
    chg.params = ["vid", "cool.example"];
    assert(ownHostEffect([chg], "alice", same) == "vid@cool.example");
    assert(!vhostMatches("other@cool.example", "vid@cool.example"));
    auto refused = testFrame(["Please contact an Operator to get a vhost assigned to this nick."]);
    assert(!hostOnAccepted(g, refused, mask));
    ServiceStatus st;
    string reason;
    assert(findRefusal(g, refused, HOST_TOGGLE_REFUSALS, st, reason) && reason == "vhost_not_assigned");
    auto g20 = new AnopeGrammar(TEST_V20);
    auto ident = testFrame(["Your vhost of \x02vid\x02@\x02cool.example\x02 is now activated."]);
    assert(hostOnAccepted(g20, ident, mask) && mask == "vid@cool.example");
}

@("services identity: GLIST fixed, flexible and recover effects")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    auto fixed = testFrame(["List of nicknames belonging to your account:", "Nick    Registered   Expires",
        "alice   Nov 06 2026  does not expire", "alice_  Nov 06 2026  Nov 06 2027", "2 nicknames in the account."]);
    auto r = parseGroupList(g, fixed);
    assert(r.ok && r.nicks == ["alice", "alice_"]);
    auto flex = testFrame(["List of nicknames belonging to your account:",
        "\x02alice\x02: registered on Nov 06 2026", "1 nickname in the account."]);
    r = parseGroupList(g, flex);
    assert(r.ok && r.nicks == ["alice"]);
    auto wrongCount = testFrame(["List of nicknames belonging to your account:", "Nick    Registered   Expires",
        "alice   Nov 06 2026  never", "3 nicknames in the account."]);
    assert(!parseGroupList(g, wrongCount).ok);
    auto g20 = new AnopeGrammar(TEST_V20);
    auto removed = testFrame(["The user with your nick has been removed. Use this command again",
        "to release services's hold on your nick."]);
    assert(evaluateRecover(g20, removed).effect == "removedNeedsRelease");
    auto ghost = testFrame(["Ghost with your nick has been killed.", "You have been logged in as \x02alice\x02."]);
    auto rg = evaluateRecover(g, ghost);
    assert(rg.effect == "ghostRemoved" && rg.loginClaimed && !rg.observed.length);
}

@("services identity: nick popup resolves a grouped nick's account only from WHOIS 330")
unittest {
    NickEq same = (string a, string b) => testSame(a, b);
    // Grouped nick: the WHOIS account differs from the nick and is used as is.
    auto grouped = ServicesWhois(true, true, "Alice_Away", "a", "cloak.example", "irc.test", "alice", false);
    auto r = resolveTargetAccount(grouped, "alice_away", same);
    assert(r.ok && r.account == "alice");
    // Logged out: no 330, so no account is invented from the nick.
    auto loggedOut = ServicesWhois(true, true, "bob", "b", "cloak.example", "irc.test", "", false);
    r = resolveTargetAccount(loggedOut, "bob", same);
    assert(!r.ok && !r.account.length && r.status == ServiceStatus.unconfirmed && r.reason == "target_unidentified");
    // Gone or answered for someone else: not this nick's account.
    auto absent = ServicesWhois(true, false, "", "", "", "", "", false);
    r = resolveTargetAccount(absent, "carol", same);
    assert(!r.ok && r.reason == "target_absent");
    auto incomplete = ServicesWhois(false, true, "carol", "c", "h", "s", "carol", false);
    r = resolveTargetAccount(incomplete, "carol", same);
    assert(!r.ok && r.reason == "target_unverified");
}

@("services identity: an ack mixed with a refusal is never a success")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    // A manual IDENTIFY's foreign ack + 900 attributed beside our own refusal.
    auto f = testFrame(["Password accepted - you are now recognized.", "Password incorrect."]);
    f.accountChanges ~= ServicesActor(ServicesActorState.account, "acct");
    auto e = evaluateIdentify(g, f);
    assert(e.ack && e.refused && e.conflicting, "mixed identify replies must conflict");
    auto grp = testFrame(["Your nickname now belongs to the account \x02acct\x02.", "Password incorrect."]);
    assert(evaluateGroup(g, grp).conflicting);
    auto rec = testFrame(["Ghost with your nick has been killed.", "Access denied."]);
    assert(evaluateRecover(g, rec).conflicting);
    auto reg = testFrame(["Nickname \x02acct\x02 registered.", "Nickname \x02acct\x02 is already registered!"]);
    assert(evaluateRegister(g, reg).conflicting);
    auto ok = testFrame(["Password accepted - you are now recognized."]);
    assert(!evaluateIdentify(g, ok).conflicting);
}

@("services identity: INFO of an own grouped alias is the private view")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    NickEq same = (string a, string b) => testSame(a, b);
    const actor = ServicesActor(ServicesActorState.account, "alice");
    auto alias_ = testFrame(["Information about nick \x02alice_\x02:", "Account: alice (ID: 7)",
        "Email address: alice@example.org", "VHost: alice.example"]);
    auto info = parseNickInfo(g, alias_);
    assert(info.registered && info.account == "alice" && info.vhostFound);
    assert(privateInfoView(actor, info, "alice_", same), "grouped alias of the actor shows hidden fields");
    auto other = testFrame(["Information about nick \x02bob\x02:", "Account: bob (ID: 8)"]);
    auto bob = parseNickInfo(g, other);
    assert(!privateInfoView(actor, bob, "bob", same));
    assert(!privateInfoView(ServicesActor(ServicesActorState.none, ""), info, "alice_", same));
}

@("services identity: memo READ never returns partial, foreign or ambiguous text")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    string[] lines = ["Memo 1 from bob (Nov 06 2026).", "first half"];
    auto partial = testFrame(lines);
    partial.outcome = ServiceFrameOutcome.deadline;
    partial.endFenced = false;
    assert(!parseMemoRead(g, partial, 1).ok, "deadline frame must not yield a memo");
    auto truncated = testFrame(lines);
    truncated.truncated = true;
    assert(!parseMemoRead(g, truncated, 1).ok, "truncated frame must not yield a memo");
    auto unplaced = testFrame(lines);
    unplaced.ambiguous = true;
    assert(!parseMemoRead(g, unplaced, 1).ok, "an unplaceable +reply makes the frame unusable");
    assert(incompleteReason(unplaced) == "ambiguous_reply");
    // Correlated: the untagged arrival notice is not READ output.
    auto correlated = testFrame(["Memo 1 from bob (Nov 06 2026).",
        "You have a new memo from mallory. Type \x02/msg MemoServ READ\x1B2\x02 to read it.", "hello"]);
    correlated.replyCorrelated = true;
    correlated.lines[0].attribution = ServiceReplyAttribution.reply;
    correlated.lines[2].attribution = ServiceReplyAttribution.reply;
    auto r = parseMemoRead(g, correlated, 1);
    assert(r.ok && r.text == "hello");
    // Uncorrelated: the same notice makes the body ambiguous.
    auto plain = testFrame(["Memo 1 from bob (Nov 06 2026).",
        "You have a new memo from mallory. Type \x02/msg MemoServ READ\x1B2\x02 to read it.", "hello"]);
    assert(!parseMemoRead(g, plain, 1).ok);
}

@("services identity: legacy auth terminal classifier")
unittest {
    // Acks and refusals, English and translated, any release.
    assert(legacyAuthTerminal(TEST_V21, "Password accepted - you are now recognized."));
    assert(legacyAuthTerminal(TEST_V21, "Passwort akzeptiert - Du bist jetzt angemeldet."));
    assert(legacyAuthTerminal(TEST_V20, "Password incorrect."));
    assert(legacyAuthTerminal(TEST_V20, "Please wait 30 seconds before using the GROUP command again."));
    assert(legacyAuthTerminal(TEST_V21, "Unknown command \x02ID\x02. Type \x02/msg NickServ HELP\x02 for help."));
    // 2.0 two-line RECOVER removal: its last part ends the reply.
    assert(legacyAuthTerminal(TEST_V20, "to release services's hold on your nick."));
    // Unknown release: union of both.
    assert(legacyAuthTerminal("", "You are now in the group of \x02alice\x02."));
    assert(legacyAuthTerminal("", "Your nickname now belongs to the account \x02alice\x02."));
    // Unsolicited notices and unknown text are not terminal.
    assert(!legacyAuthTerminal(TEST_V21, "You have a new memo from bob. Type \x02/msg MemoServ READ\x1B3\x02 to read it."));
    assert(!legacyAuthTerminal(TEST_V21, "Your vhost of \x02cool.example\x02 is now activated."));
    assert(!legacyAuthTerminal(TEST_V21, "All new accounts must be confirmed by an administrator. Please wait for your registration to be confirmed."));
    assert(!legacyAuthTerminal(TEST_V21, "hello world"));
    assert(printfSegmentMatch("Please wait %d seconds.", "Please wait 12 seconds."));
    assert(!printfSegmentMatch("Please wait %d seconds.", "Please wait x seconds."));
    // A syntax error yields exactly one terminal: `Syntax:`, not MORE_INFO.
    assert(legacyAuthTerminal(TEST_V21, "Syntax: \x02REGISTER \x1Fpassword\x1F \x1F[email]\x1F\x02"));
    assert(!legacyAuthTerminal(TEST_V21, "Type \x02/msg NickServ HELP REGISTER\x02 for more information."));
    assert(!legacyAuthTerminal(TEST_V20, "\x02/msg NickServ HELP REGISTER\x02 for more information."));
}

@("services identity: memo READ header with Anope::strftime's relative age")
unittest {
    auto g = new AnopeGrammar(TEST_V21);
    // ms_read.cpp: `Memo %d from %s (%s).` with strftime "<%c> (<n> ago)".
    auto f = testFrame(["Memo 1 from bob (Thu Nov  6 12:00:00 2026 (5 seconds ago)).",
        "To delete, type: \x02/msg MemoServ DEL\x1B1\x02", "hello there"]);
    auto r = parseMemoRead(g, f, 1);
    assert(r.ok && r.sender == "bob" && r.sentAt == "Thu Nov  6 12:00:00 2026 (5 seconds ago)");
    assert(r.text == "hello there", "the delete hint is not body");
    auto now = testFrame(["Memo 2 from carol (Thu Nov  6 12:00:00 2026 (now)).", "hi"]);
    auto rn = parseMemoRead(g, now, 2);
    assert(rn.ok && rn.sender == "carol" && rn.text == "hi");
    // LineWrapper split of a long header: first two lines joined.
    auto wrapped = testFrame(["Memo 3 from averyveryverylongnicknameindeed (Thursday 6 November 2026",
        "12:00:00 (5 seconds ago)).", "body"]);
    auto rw = parseMemoRead(g, wrapped, 3);
    assert(rw.ok && rw.sender == "averyveryverylongnicknameindeed" && rw.text == "body");
    // A body line imitating a dated header stays body.
    auto fake = testFrame(["Memo 4 from bob (Thu Nov  6 2026 (now)).",
        "Memo 5 from mallory (Thu Nov  6 2026 (now)).", "x"]);
    auto rf = parseMemoRead(g, fake, 4);
    assert(rf.ok && rf.sender == "bob" && rf.text == "Memo 5 from mallory (Thu Nov  6 2026 (now)).\nx");
    string[] caps;
    assert(printfCapture("%2$s hat %1$s (%3$s).", "bob hat 7 (a (b)).", [false, true, false], caps)
        && caps == ["7", "bob", "a (b)"]);
}

@("services identity: Anope 2.0 memo READ (untagged, echo-correlated frame)")
unittest {
    auto g = new AnopeGrammar(TEST_V20);
    // 2.0 ms_read.cpp DoRead: header with Anope::strftime "%b %d %H:%M:%S %Y %Z (%s ago)",
    // hint `To delete, type: \002%s%s %s %d\002` (StrictPrivmsg "/msg ", nick, DEL), body.
    string[] lines = ["Memo 1 from bob (Nov 06 12:00:00 2026 UTC (5 seconds ago)).",
        "To delete, type: \x02/msg MemoServ DEL 1\x02", "hello from 2.0"];
    auto f = testFrame(lines);
    // Own msgid learned from echo-message, but 2.0 sends no +reply: lines are window.
    f.replyCorrelated = true;
    auto r = parseMemoRead(g, f, 1);
    assert(r.ok && r.sender == "bob" && r.sentAt == "Nov 06 12:00:00 2026 UTC (5 seconds ago)");
    assert(r.text == "hello from 2.0", "the 2.0 delete hint is not body");
    auto strict = testFrame(["Memo 2 from carol (Nov 06 12:00:00 2026 UTC (now)).",
        "To delete, type: \x02/MemoServ DEL 2\x02", "hi"]);
    auto rs = parseMemoRead(g, strict, 2);
    assert(rs.ok && rs.sender == "carol" && rs.text == "hi");
    // The 2.0 two-line arrival notice in the window makes the body ambiguous.
    auto arrival = testFrame(["Memo 1 from bob (Nov 06 12:00:00 2026 UTC (5 seconds ago)).",
        "You have a new memo from mallory.", "Type \x02/msg MemoServ READ 2\x02 to read it.", "hello"]);
    arrival.replyCorrelated = true;
    assert(!parseMemoRead(g, arrival, 1).ok);
    // 2.1 keeps strict +reply attribution: untagged window lines are not READ output.
    auto g21 = new AnopeGrammar(TEST_V21);
    auto untagged = testFrame(["Memo 1 from bob (Thu Nov  6 12:00:00 2026 (now)).", "x"]);
    untagged.replyCorrelated = true;
    assert(!parseMemoRead(g21, untagged, 1).ok);
}

@("services identity: GLIST exactly as the live fixtures send it (2.1 LineWrapper, 2.0 fixed)")
unittest {
    // Managed 2.1 fixture, verbatim: the row exceeds linelength 100 and
    // LineWrapper moves `(90 days from now)` onto its own line.
    auto g = new AnopeGrammar(TEST_V21);
    auto managed = testFrame(["List of nicknames belonging to your account:",
        "Nick        Registered                                            Expires",
        "fixoffline  Sat Nov  7 01:08:31 2026 (5 minutes, 54 seconds ago)  Fri 05 Feb 2027 01:08:31 AM UTC",
        "(90 days from now)",
        "1 nickname in the account."]);
    auto r = parseGroupList(g, managed);
    assert(r.ok && r.nicks == ["fixoffline"]);
    // Two grouped nicks, the first row wrapped, the second not.
    auto two = testFrame(["List of nicknames belonging to your account:",
        "Nick          Registered                                            Expires",
        "fixoffline    Sat Nov  7 01:08:31 2026 (5 minutes, 54 seconds ago)  Fri 05 Feb 2027 01:08:31 AM UTC",
        "(90 days from now)",
        "fixoffline_2  Sat Nov  7 01:10:00 2026 (4 minutes ago)  does not expire",
        "2 nicknames in the account."]);
    r = parseGroupList(g, two);
    assert(r.ok && r.nicks == ["fixoffline", "fixoffline_2"]);
    // A short stray line after a short row is no wrap: the reply is not understood.
    auto stray = testFrame(["List of nicknames belonging to your account:", "Nick   Registered  Expires",
        "alice  Nov 7 2026  never", "(stray)", "1 nickname in the account."]);
    assert(!parseGroupList(g, stray).ok);
    // Flexible 2.1 row wrapped after its registered date.
    auto flex = testFrame(["List of nicknames belonging to your account:",
        "\x02fixoffline\x02: registered on Sat Nov  7 01:08:31 2026 (5 minutes, 54 seconds ago); expires in Fri 05",
        "Feb 2027 01:08:31 AM UTC (90 days from now)", "1 nickname in the account."]);
    r = parseGroupList(g, flex);
    assert(r.ok && r.nicks == ["fixoffline"]);
    // External 2.0.20 fixture, verbatim (no wrapping in 2.0).
    auto g20 = new AnopeGrammar(TEST_V20);
    auto external = testFrame(["List of nicknames in your group:", "Nick       Expires",
        "extmember  Nov 28 01:09:27 2026 UTC (20 days, 23 hours, 54 minutes from now)",
        "1 nickname(s) in the group."]);
    r = parseGroupList(g20, external);
    assert(r.ok && r.nicks == ["extmember"]);
    // A memo LIST row wrapped the same way keeps its whole date.
    auto memos = testFrame(["Memos for fixoffline:", "Number  Sender                          Date/Time",
        "* 1     averyveryverylongsendernickname  Sat Nov  7 01:08:31 2026 (5 minutes, 54 seconds ago) and",
        "more", "  2     bob                             Sat Nov  7 01:09:00 2026 (now)"]);
    auto inbox = parseMemoList(g, memos);
    assert(inbox.ok && inbox.entries.length == 2
        && inbox.entries[0].sentAt == "Sat Nov  7 01:08:31 2026 (5 minutes, 54 seconds ago) and more");
}
