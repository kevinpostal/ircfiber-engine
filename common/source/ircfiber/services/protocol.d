module ircfiber.services.protocol;

import vibe.data.json;
import std.algorithm : canFind;
import std.conv : to;
import std.exception : enforce;
import std.traits : FieldNameTuple;
import std.utf : validate;
import std.uuid : UUID;
import ircfiber.services.config : ServiceId;

/// User-facing operations use the live IRC actor, never administrative RPC.
enum ServiceAction {
    discover,
    channelInfo, channelRegister, channelAccessList, channelAccessSet, channelAccessRemove,
    channelTopicSet, channelTopicLock, channelKeepTopic, channelModeLockList, channelModeLockChange,
    channelAkickList, channelAkickAdd, channelAkickRemove,
    botList, botInfo, botAssign, botUnassign, botGreet, botFantasy,
    accountInfo, accountIdentify, accountRegister, accountConfirm, accountGroups, accountGroup,
    accountRecover, accountPrivacy,
    hostInfo, hostRequest, hostOn, hostOff,
    memoList, memoRead, memoSend, memoDelete,
    operStats, akillList, akillView, akillAdd, akillRemove,
    hostWaiting, hostActivate, hostReject, globalQueue, globalSend
}

enum ServiceStatus { confirmed, rejected, unconfirmed, unavailable, stale }
enum ServicePermission { allowed, denied, unknown, unsupported }
enum AccessProvider { xop, access, flags }
enum LockChange { add, remove, set }
enum PrivacyField { email, status, mask, quit }

struct EmptyParams {}
struct ChannelParams { string channel; }
struct AccountParams { string account; string targetNick; }
struct ChannelRegisterParams { string channel; string description; }
struct AccessParams { string channel; string account; string targetNick; AccessProvider provider; string value; }
struct TopicParams { string channel; string topic; }
struct ChannelToggleParams { string channel; bool enabled; }
struct ModeLockParams { string channel; LockChange change; string modes; }
struct AkickAddParams { string channel; string mask; string reason; }
struct AkickRemoveParams { string channel; string entry; }
struct BotAssignParams { string channel; string bot; }
struct IdentifyParams { string account; string password; }
struct RegisterParams { string password; string email; }
struct ConfirmParams { string code; }
struct GroupParams { string account; string password; }
struct RecoverParams { string nick; string password; }
struct PrivacyParams { PrivacyField field; bool enabled; }
struct HostRequestParams { string host; }
struct MemoReadParams { string selection; }
struct MemoSendParams { string recipient; string targetNick; string text; }
struct MemoDeleteParams { uint number; }
struct AkillViewParams { string entry; }
struct AkillAddParams { string mask; uint expirySeconds; string reason; bool broadMaskConfirmed; }
struct AkillRemoveParams { string entry; }
struct HostActivateParams { string nick; }
struct HostRejectParams { string nick; string reason; }
struct GlobalSendParams { string text; }

/// Only this envelope enters the expiring single-use payload store. Never log it.
struct ServicesRequest {
    string requestId;
    ServiceAction action;
    Json params;
    string expectedConnectionEpoch;
    string expectedActorAccount;
    string expectedRevision;

    static ServicesRequest fromJson(Json j) {
        requireObject(j);
        foreach (string key, Json ignored; j)
            enforce(["cmd", "network", "requestId", "action", "params", "expectedConnectionEpoch",
                "expectedActorAccount", "expectedRevision"].canFind(key), "Unknown services request field");
        ServicesRequest request;
        request.requestId = requiredString(j, "requestId");
        requireUUID(request.requestId);
        request.action = requiredString(j, "action").to!ServiceAction;
        request.expectedConnectionEpoch = requiredString(j, "expectedConnectionEpoch");
        requireUUID(request.expectedConnectionEpoch);
        request.expectedActorAccount = requiredString(j, "expectedActorAccount");
        accountIdentifier(request.expectedActorAccount, true);
        request.expectedRevision = optionalString(j, "expectedRevision");
        if (request.expectedRevision.length) {
            enforce(request.expectedRevision.length <= 128, "Invalid services revision");
            token(request.expectedRevision);
        }
        enforce(request.expectedActorAccount.length || permitsUnauthenticated(request.action),
            "This service operation requires an observed account");
        request.params = validateParams(request.action, j["params"]);
        return request;
    }

    Json toJson() const {
        return Json(["requestId": Json(requestId), "action": Json(action.to!string),
            "params": params, "expectedConnectionEpoch": Json(expectedConnectionEpoch),
            "expectedActorAccount": Json(expectedActorAccount), "expectedRevision": Json(expectedRevision)]);
    }
}

/// Replies are ephemeral and delivered only to the originating browser session.
struct ServicesResult {
    string network;
    string requestId;
    string connectionEpoch;
    ServiceAction action;
    ServiceStatus status;
    Json data;
    Json capabilities;
    string revision;
    string reasonCode;
    string[] details;

    Json toJson() const {
        auto result = Json([
            "type": Json("services_result"), "network": Json(network),
            "requestId": Json(requestId), "connectionEpoch": Json(connectionEpoch),
            "action": Json(action.to!string), "status": Json(status.to!string)
        ]);
        if (data.type != Json.Type.undefined) result["data"] = data;
        if (capabilities.type != Json.Type.undefined) result["capabilities"] = capabilities;
        if (revision.length) result["revision"] = Json(revision);
        if (reasonCode.length) result["reasonCode"] = Json(reasonCode);
        if (details.length) result["details"] = serializeToJson(details);
        return result;
    }
}

/// Routing metadata only. No password, memo, account-private INFO or broadcast text.
struct ServicesPayloadReference {
    string requestId;
    string payloadKey;

    Json toJson() const {
        requireUUID(requestId);
        enforce(payloadKey.length && !containsControl(payloadKey), "Invalid services payload reference");
        return Json(["requestId": Json(requestId), "payloadKey": Json(payloadKey)]);
    }

    static ServicesPayloadReference fromJson(Json j, string owner, string network) {
        requireObject(j);
        foreach (string key, Json ignored; j)
            enforce(key == "requestId" || key == "payloadKey", "Invalid services routing field");
        auto request = requiredString(j, "requestId");
        requireUUID(request);
        auto key = requiredString(j, "payloadKey");
        enforce(key == ServicesKeys.payload(owner, network, request), "Invalid services payload scope");
        return ServicesPayloadReference(request, key);
    }
}

/// A manual service-directed `msg`/`raw` line the privacy classifier marked
/// sensitive (IDENTIFY, MemoServ SEND, ...). The gateway stores it in the same
/// single-use expiring payload slot as typed requests and enqueues only a
/// `services_manual` routing reference, so the secret never enters the
/// ordinary command list. The engine keeps manual behavior (no typed result)
/// but refuses it on another connection epoch. Never log it.
struct ServicesManualPayload {
    enum maxTextBytes = 8192;

    string requestId;
    /// `msg` (PRIVMSG target :text) or `raw` (one complete IRC line).
    string command;
    /// Message target; empty for `raw`.
    string target;
    /// Message body, or the whole raw line.
    string text;
    /// Browser labeled-response label for `msg`; optional.
    string label;
    /// Gateway-observed live connection the line was accepted for.
    string expectedConnectionEpoch;

    Json toJson() const {
        validated();
        auto j = Json(["requestId": Json(requestId), "command": Json(command), "text": Json(text),
            "expectedConnectionEpoch": Json(expectedConnectionEpoch)]);
        if (target.length) j["target"] = Json(target);
        if (label.length) j["label"] = Json(label);
        return j;
    }

    static ServicesManualPayload fromJson(Json j) {
        requireObject(j);
        foreach (string key, Json ignored; j)
            enforce(["requestId", "command", "target", "text", "label", "expectedConnectionEpoch"].canFind(key),
                "Unknown manual services field");
        ServicesManualPayload p;
        p.requestId = requiredString(j, "requestId");
        p.command = requiredString(j, "command");
        p.target = optionalString(j, "target");
        p.text = requiredString(j, "text");
        p.label = optionalString(j, "label");
        p.expectedConnectionEpoch = requiredString(j, "expectedConnectionEpoch");
        p.validated();
        return p;
    }

    private void validated() const {
        requireUUID(requestId);
        requireUUID(expectedConnectionEpoch);
        enforce(command == "msg" || command == "raw", "Invalid manual services command");
        validate(text);
        enforce(text.length && text.length <= maxTextBytes, "Invalid manual services text");
        foreach (c; text) enforce(c != '\r' && c != '\n' && c != '\0', "Invalid manual services text");
        if (command == "msg") token(target);
        else enforce(!target.length, "Raw manual services line has no target");
        if (label.length) {
            token(label);
            enforce(label.length <= 64, "Invalid manual services label");
        }
    }
}

/// Request/session scoping is derived by the gateway, never from browser parameters.
struct ServicesKeys {
    enum payloadTTLSeconds = 15;
    enum replyTTLSeconds = 60;
    enum dedupTTLSeconds = 300;
    enum maxActivePerOwner = 8;
    enum maxActivePerConnection = 7;
    enum maxReplyBytes = 256 * 1024;
    enum maxPayloadBytes = 16384;

    static string payload(string owner, string network, string request) {
        return scoped("payload", owner, network, request);
    }
    static string reply(string owner, string network, string request) {
        return scoped("reply", owner, network, request);
    }
    private static string scoped(string kind, string owner, string network, string request) {
        requireUUID(owner); requireUUID(network); requireUUID(request);
        return "irc:services:" ~ kind ~ ":" ~ owner ~ ":" ~ network ~ ":" ~ request;
    }
}

ServiceId serviceFor(ServiceAction action) pure nothrow {
    final switch (action) {
        case ServiceAction.discover: return ServiceId.nickServ;
        case ServiceAction.channelInfo: case ServiceAction.channelRegister:
        case ServiceAction.channelAccessList: case ServiceAction.channelAccessSet:
        case ServiceAction.channelAccessRemove: case ServiceAction.channelTopicSet:
        case ServiceAction.channelTopicLock: case ServiceAction.channelKeepTopic:
        case ServiceAction.channelModeLockList: case ServiceAction.channelModeLockChange:
        case ServiceAction.channelAkickList: case ServiceAction.channelAkickAdd:
        case ServiceAction.channelAkickRemove: return ServiceId.chanServ;
        case ServiceAction.botList: case ServiceAction.botInfo: case ServiceAction.botAssign:
        case ServiceAction.botUnassign: case ServiceAction.botGreet: case ServiceAction.botFantasy:
            return ServiceId.botServ;
        case ServiceAction.accountInfo: case ServiceAction.accountIdentify: case ServiceAction.accountRegister:
        case ServiceAction.accountConfirm: case ServiceAction.accountGroups: case ServiceAction.accountGroup:
        case ServiceAction.accountRecover: case ServiceAction.accountPrivacy: return ServiceId.nickServ;
        case ServiceAction.hostInfo: case ServiceAction.hostRequest: case ServiceAction.hostOn:
        case ServiceAction.hostOff: case ServiceAction.hostWaiting: case ServiceAction.hostActivate:
        case ServiceAction.hostReject: return ServiceId.hostServ;
        case ServiceAction.memoList: case ServiceAction.memoRead: case ServiceAction.memoSend:
        case ServiceAction.memoDelete: return ServiceId.memoServ;
        case ServiceAction.operStats: case ServiceAction.akillList: case ServiceAction.akillView:
        case ServiceAction.akillAdd: case ServiceAction.akillRemove: return ServiceId.operServ;
        case ServiceAction.globalQueue: case ServiceAction.globalSend: return ServiceId.global;
    }
}

bool isMutation(ServiceAction action) pure nothrow {
    switch (action) {
        case ServiceAction.discover: case ServiceAction.channelInfo: case ServiceAction.channelAccessList:
        case ServiceAction.channelModeLockList: case ServiceAction.channelAkickList:
        case ServiceAction.botList: case ServiceAction.botInfo: case ServiceAction.accountInfo:
        case ServiceAction.accountGroups: case ServiceAction.hostInfo: case ServiceAction.memoList:
        case ServiceAction.operStats: case ServiceAction.akillList: case ServiceAction.akillView:
        case ServiceAction.hostWaiting: case ServiceAction.globalQueue: return false;
        default: return true; // READ marks a memo read; it is deliberately a mutation.
    }
}

bool permitsUnauthenticated(ServiceAction action) pure nothrow {
    switch (action) {
        case ServiceAction.discover: case ServiceAction.channelInfo: case ServiceAction.accountInfo:
        case ServiceAction.accountIdentify: case ServiceAction.accountRegister: case ServiceAction.accountConfirm:
        case ServiceAction.accountGroup: case ServiceAction.accountRecover: return true;
        default: return false;
    }
}

bool isAuthentication(ServiceAction action) pure nothrow {
    return action == ServiceAction.accountIdentify || action == ServiceAction.accountRegister
        || action == ServiceAction.accountConfirm || action == ServiceAction.accountGroup
        || action == ServiceAction.accountRecover;
}

/// Anope tokenizes command parameters; reject text it would silently normalize.
bool canonicalServicesSpacing(string text) @safe pure nothrow @nogc {
    if (!text.length) return true;
    if (text[0] == ' ' || text[$ - 1] == ' ') return false;
    foreach (i; 1 .. text.length)
        if (text[i] == ' ' && text[i - 1] == ' ') return false;
    return true;
}

string servicesNativeParamRejection(const ref ServicesRequest request) {
    string key;
    if (request.action == ServiceAction.channelTopicSet) key = "topic";
    else if (request.action == ServiceAction.globalSend) key = "text";
    else return "";
    return canonicalServicesSpacing(request.params[key].get!string) ? "" : "noncanonical_spacing";
}

/// Validate exact parameter shapes before any value reaches an IRC builder.
Json validateParams(ServiceAction action, Json j) {
    requireObject(j);
    final switch (action) {
        case ServiceAction.discover: case ServiceAction.botList: case ServiceAction.accountGroups:
        case ServiceAction.hostInfo: case ServiceAction.hostOn: case ServiceAction.hostOff:
        case ServiceAction.memoList: case ServiceAction.operStats: case ServiceAction.akillList:
        case ServiceAction.hostWaiting: case ServiceAction.globalQueue: return decode!EmptyParams(j);
        case ServiceAction.channelInfo: case ServiceAction.channelAccessList:
        case ServiceAction.channelModeLockList: case ServiceAction.channelAkickList:
        case ServiceAction.botInfo: case ServiceAction.botUnassign: return decode!ChannelParams(j);
        case ServiceAction.accountInfo: {
            auto result = decode!AccountParams(j, ["account", "targetNick"]);
            enforce(result["account"].get!string.length || result["targetNick"].get!string.length,
                "Account information requires an account or live nickname");
            return result;
        }
        case ServiceAction.channelRegister: return decode!ChannelRegisterParams(j, ["description"]);
        case ServiceAction.channelAccessSet: case ServiceAction.channelAccessRemove: {
            auto result = decode!AccessParams(j, ["targetNick", "value"]);
            auto provider = requiredString(result, "provider").to!AccessProvider;
            auto value = requiredString(result, "value");
            if (action == ServiceAction.channelAccessSet) {
                enforce(value.length, "Access value required");
                if (provider == AccessProvider.xop)
                    enforce(["SOP", "AOP", "HOP", "VOP"].canFind(value), "Invalid XOP tier");
                else if (provider == AccessProvider.access) {
                    enforce(value.length <= 6, "Invalid access level");
                    auto level = value.to!int;
                    enforce(level >= -9999 && level <= 10000, "Invalid access level");
                } else {
                    foreach (c; value) enforce((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                        || c == '+' || c == '-', "Invalid access flags");
                }
            } else enforce(!value.length || provider == AccessProvider.xop
                && ["SOP", "AOP", "HOP", "VOP"].canFind(value), "Invalid access removal");
            return result;
        }
        case ServiceAction.channelTopicSet: return decode!TopicParams(j, ["topic"]);
        case ServiceAction.channelTopicLock: case ServiceAction.channelKeepTopic:
        case ServiceAction.botGreet: case ServiceAction.botFantasy: return decode!ChannelToggleParams(j);
        case ServiceAction.channelModeLockChange: return decode!ModeLockParams(j, ["modes"]);
        case ServiceAction.channelAkickAdd: return decode!AkickAddParams(j);
        case ServiceAction.channelAkickRemove: return decode!AkickRemoveParams(j);
        case ServiceAction.botAssign: return decode!BotAssignParams(j);
        case ServiceAction.accountIdentify: return decode!IdentifyParams(j);
        case ServiceAction.accountRegister: return decode!RegisterParams(j, ["email"]);
        case ServiceAction.accountConfirm: return decode!ConfirmParams(j);
        case ServiceAction.accountGroup: return decode!GroupParams(j, ["password"]);
        case ServiceAction.accountRecover: return decode!RecoverParams(j, ["password"]);
        case ServiceAction.accountPrivacy: return decode!PrivacyParams(j);
        case ServiceAction.hostRequest: return decode!HostRequestParams(j);
        case ServiceAction.memoRead: {
            auto result = decode!MemoReadParams(j);
            auto selection = requiredString(result, "selection");
            if (!["LAST", "NEW", "ALL"].canFind(selection)) {
                enforce(selection.length <= 100, "Invalid memo selection");
                foreach (c; selection) enforce(c >= '0' && c <= '9' || c == ',' || c == '-', "Invalid memo selection");
                enforce(selection[0] >= '1' && selection[0] <= '9', "Invalid memo selection");
            }
            return result;
        }
        case ServiceAction.memoSend: return decode!MemoSendParams(j, ["targetNick"]);
        case ServiceAction.memoDelete: {
            auto result = decode!MemoDeleteParams(j);
            enforce(result["number"].get!uint > 0, "Invalid memo number");
            return result;
        }
        case ServiceAction.akillView: return decode!AkillViewParams(j);
        case ServiceAction.akillAdd: {
            auto result = decode!AkillAddParams(j);
            enforce(result["expirySeconds"].get!uint >= 60, "AKILL expiry must be at least 60 seconds");
            return result;
        }
        case ServiceAction.akillRemove: return decode!AkillRemoveParams(j);
        case ServiceAction.hostActivate: return decode!HostActivateParams(j);
        case ServiceAction.hostReject: return decode!HostRejectParams(j, ["reason"]);
        case ServiceAction.globalSend: return decode!GlobalSendParams(j);
    }
}

private Json decode(T)(Json j, string[] optional = []) {
    foreach (string key, Json value; j) {
        bool known;
        static foreach (field; FieldNameTuple!T)
            if (key == field) known = true;
        enforce(known, "Unknown service parameter");
    }
    auto result = Json.emptyObject;
    static foreach (field; FieldNameTuple!T) {{
        alias F = typeof(__traits(getMember, T.init, field));
        auto value = j[field];
        static if (is(F == string)) {
            enforce(value.type == Json.Type.string || optional.canFind(field)
                && value.type == Json.Type.undefined, "Invalid service parameter type");
            string text = value.type == Json.Type.string ? value.get!string : "";
            validate(text);
            enforce(!containsLineTerminator(text) && text.length <= 8192, "Invalid service parameter");
            enforce(text.length || optional.canFind(field), "Missing service parameter");
            static if (field == "channel") channelIdentifier(text);
            else static if (field == "account") accountIdentifier(text, optional.canFind(field));
            else static if (field == "targetNick" || field == "nick" || field == "bot")
                nickIdentifier(text, optional.canFind(field));
            else static if (field == "recipient") {
                if (text.length && text[0] == '#') channelIdentifier(text); else accountIdentifier(text);
            } else static if (field == "mask" || field == "entry" || field == "host" || field == "email"
                    || field == "code" || field == "password")
                if (text.length || !optional.canFind(field)) token(text);
            result[field] = Json(text);
        } else static if (is(F == bool)) {
            enforce(value.type == Json.Type.bool_, "Invalid service boolean");
            result[field] = value;
        } else static if (is(F == uint)) {
            enforce(value.type == Json.Type.int_ && value.get!long >= 0
                && value.get!long <= uint.max, "Invalid service number");
            result[field] = value;
        } else {
            enforce(value.type == Json.Type.string, "Invalid service enumeration");
            auto parsed = value.get!string.to!F;
            result[field] = Json(parsed.to!string);
        }
    }}
    return result;
}

void requireUUID(string value) {
    enforce(value.length == 36, "Invalid services identifier");
    auto id = UUID(value);
    enforce(id != UUID.init && id.toString() == value, "Invalid services identifier");
}

bool containsControl(string value) @safe pure nothrow {
    foreach (ubyte c; cast(const(ubyte)[]) value)
        if (c < 32 || c == 127) return true;
    return false;
}

bool containsLineTerminator(string value) @safe pure nothrow {
    foreach (c; value) if (c == '\0' || c == '\r' || c == '\n') return true;
    return false;
}

void accountIdentifier(string value, bool allowEmpty = false) {
    if (!value.length && allowEmpty) return;
    token(value);
    enforce(value.length <= 128 && !"#&+!".canFind(value[0]), "Invalid service account");
    foreach (c; value) enforce(!"@!*,?:".canFind(c), "Invalid service account");
}

void nickIdentifier(string value, bool allowEmpty = false) {
    if (!value.length && allowEmpty) return;
    accountIdentifier(value);
    enforce(!"0123456789-".canFind(value[0]), "Invalid service nickname");
}

void channelIdentifier(string value) {
    token(value);
    enforce(value.length > 1 && value.length <= 200 && "#&+!".canFind(value[0]), "Invalid service channel");
    enforce(!value.canFind(',') && !value.canFind(':'), "Invalid service channel");
}

void token(string value) {
    validate(value);
    enforce(value.length && !containsControl(value) && !value.canFind(' ')
        && value[0] != ':' && value.length <= 512, "Invalid service token");
}

/// Includes CRLF, optional tags and the server-added actor prefix. No splitting.
void enforceServiceWireLimit(string recipient, string body, size_t limit, size_t prefixBytes,
        size_t tagBytes = 0) {
    token(recipient);
    enforce(!containsLineTerminator(body), "Invalid service command");
    enforce(limit >= 64 && limit <= 65536 && prefixBytes <= limit && tagBytes <= limit,
        "Invalid IRC line budget");
    enforce(8 + recipient.length + 2 + body.length + 2 + prefixBytes + tagBytes <= limit,
        "Service command exceeds the IRC byte limit");
}

private void requireObject(Json j) { enforce(j.type == Json.Type.object, "Expected services object"); }
private string requiredString(Json j, string key) {
    enforce(j[key].type == Json.Type.string, "Missing services string");
    return j[key].get!string;
}
private string optionalString(Json j, string key) {
    if (j[key].type == Json.Type.undefined) return "";
    return requiredString(j, key);
}

@("services reject injected fields and control bytes before dispatch") unittest {
    import std.exception : assertThrown;
    foreach (text; ["hello\r\nOPER root password", "hello\0world"])
        assertThrown(validateParams(ServiceAction.memoSend,
            Json(["recipient": Json("alice"), "text": Json(text)])));
    assertThrown(validateParams(ServiceAction.accountIdentify,
        Json(["account": Json("alice"), "password": Json("secret"), "owner": Json("victim")])));
    assertThrown(validateParams(ServiceAction.channelInfo, Json(["channel": Json("#foo JOIN #bar")])));
    assertThrown(validateParams(ServiceAction.memoDelete, Json(["number": Json(0)])));
}

@("native ACCESS boundaries exclude reserved founder and disabled levels") unittest {
    import std.exception : assertThrown;
    Json input(string level) {
        return Json(["channel": Json("#c"), "account": Json("alice"),
            "provider": Json("access"), "value": Json(level)]);
    }
    foreach (level; ["-9999", "10000"])
        assert(validateParams(ServiceAction.channelAccessSet, input(level))["value"].get!string == level);
    foreach (level; ["-10000", "10001"])
        assertThrown(validateParams(ServiceAction.channelAccessSet, input(level)));
}

@("only readonly account lookup permits an unresolved live nickname") unittest {
    import std.exception : assertThrown;
    auto result = validateParams(ServiceAction.accountInfo, Json(["targetNick": Json("groupedNick")]));
    assert(result["account"].get!string == "" && result["targetNick"].get!string == "groupedNick");
    assertThrown(validateParams(ServiceAction.accountInfo, Json.emptyObject));
    assertThrown(validateParams(ServiceAction.channelAccessSet, Json(["channel": Json("#c"),
        "account": Json(""), "targetNick": Json("groupedNick"), "provider": Json("xop"), "value": Json("HOP")])));
}

@("services line limit counts UTF8 and transport overhead without splitting") unittest {
    import std.exception : assertThrown;
    import std.array : replicate;
    enforceServiceWireLimit("MemoServ@services.test", "SEND alice " ~ "a".replicate(100), 512, 80);
    assertThrown(enforceServiceWireLimit("MemoServ@services.test", "SEND alice " ~ "a".replicate(400), 512, 80));
    assertThrown(enforceServiceWireLimit("Global@services.test", "GLOBAL " ~ "é".replicate(200), 512, 80));
}

@("memo READ is a mutation and owner scopes cannot collide") unittest {
    import std.uuid : randomUUID;
    assert(isMutation(ServiceAction.memoRead));
    assert(!isMutation(ServiceAction.memoList));
    auto network = randomUUID().toString, request = randomUUID().toString;
    assert(ServicesKeys.payload(randomUUID().toString, network, request)
        != ServicesKeys.payload(randomUUID().toString, network, request));
}

@("manual sensitive payload is strict and cannot smuggle a second line") unittest {
    import std.exception : assertThrown;
    import std.uuid : randomUUID;
    auto p = ServicesManualPayload(randomUUID().toString, "msg", "NickServ", "IDENTIFY alice pw", "",
        randomUUID().toString);
    auto back = ServicesManualPayload.fromJson(p.toJson());
    assert(back == p);
    auto j = p.toJson();
    j["text"] = Json("IDENTIFY pw\r\nPRIVMSG #x :leak");
    assertThrown(ServicesManualPayload.fromJson(j));
    j = p.toJson();
    j["owner"] = Json(randomUUID().toString);
    assertThrown(ServicesManualPayload.fromJson(j));
    assertThrown(ServicesManualPayload(p.requestId, "raw", "NickServ", "x", "", p.expectedConnectionEpoch).toJson());
}
