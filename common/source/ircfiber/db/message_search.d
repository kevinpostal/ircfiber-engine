module ircfiber.db.message_search;

import std.algorithm : canFind;
import std.array : appender;
import std.string : startsWith;
import std.uni : toLower;
import vibe.data.bson : Bson, serializeToBson;
import vibe.data.json : Json, parseJsonString;
import ircfiber.models.network : normalizeChannelName;

/// Bump whenever classification, aliases, formatting or folding changes.
enum uint MESSAGE_SEARCH_VERSION = 1;

enum SearchKind { skip, message, edit, redact }

struct SearchClassification {
    SearchKind kind;
    string[] aliases;
    string target;
    string nick;
    string text;
    string command;
    string hostmask;
    /// False on an encrypted/diagnostic edit: applying it removes old plaintext.
    bool displayable;
    /// The live msgid identity (m, falling back to i), excluding label aliases.
    string msgid;
}

/// Identity and ordering come from the mutable archive envelope, never its _id
/// syntax or immutable payload's historical channel/server assignment.
struct SearchRow {
    string rowId;
    string networkId;
    string channel;
    long t;
    long eid;
    bool hasEid;
    SearchClassification classification;
}

struct SearchResolution {
    bool visible;
    bool ambiguous;
    bool redacted;
    SearchRow original;
    string text;
    string bodyFold;
    string senderFold;
}

bool isSearchChannel(string channel) @safe {
    if (channel.length < 2 || !canFind("#&+!", channel[0])) return false;
    foreach (char c; channel)
        if (c <= 0x20 || c == ',' || c == ':' || c == 0x7f) return false;
    return true;
}

/// Unicode lowercase, not IRC casemapping: nick and literal body comparisons
/// use the same locale-independent mapping. No normalization or word parsing.
string searchFold(string value) @safe {
    return toLower(value);
}

private bool decimal(char c) @safe pure nothrow @nogc {
    return c >= '0' && c <= '9';
}

private bool hex(char c) @safe pure nothrow @nogc {
    return decimal(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/// Byte-for-byte equivalent of frontend stripIrcFormatting's control patterns.
/// Return the original string when there is nothing to remove.
string stripSearchFormatting(string value) @safe {
    auto out_ = appender!string();
    size_t copied;
    bool changed;
    for (size_t i; i < value.length;) {
        const start = i;
        const c = value[i++];
        switch (c) {
            case '\x02': case '\x1d': case '\x1f': case '\x16':
            case '\x11': case '\x1e': case '\x0f':
                break;
            case '\x03':
                if (i < value.length && decimal(value[i])) {
                    i++;
                    if (i < value.length && decimal(value[i])) i++;
                    if (i + 1 < value.length && value[i] == ',' && decimal(value[i + 1])) {
                        i += 2;
                        if (i < value.length && decimal(value[i])) i++;
                    }
                }
                break;
            case '\x04':
                bool sixHex(size_t pos) {
                    if (value.length - pos < 6) return false;
                    foreach (k; pos .. pos + 6) if (!hex(value[k])) return false;
                    return true;
                }
                if (sixHex(i)) {
                    i += 6;
                    if (i < value.length && value[i] == ',' && sixHex(i + 1)) i += 7;
                }
                break;
            case '\x1b':
                if (i < value.length && value[i] == '[') {
                    i++;
                    while (i < value.length && (decimal(value[i]) || canFind(";:?", value[i]))) i++;
                    while (i < value.length && value[i] >= ' ' && value[i] <= '/') i++;
                    if (i < value.length && value[i] >= '@' && value[i] <= '~') i++;
                }
                break;
            default:
                continue;
        }
        if (!changed) {
            out_.reserve(value.length);
            changed = true;
        }
        out_.put(value[copied .. start]);
        copied = i;
    }
    if (!changed) return value;
    out_.put(value[copied .. $]);
    return out_.data;
}

private string stringField(const Json value, string key) @trusted {
    if (value.type != Json.Type.object) return "";
    const field = value[key];
    return field.type == Json.Type.string ? field.get!string : "";
}

private string firstString(const Json payload, string compact, string full) @trusted {
    const value = stringField(payload, compact);
    return value.length ? value : stringField(payload, full);
}

private bool validAlias(string value) @safe {
    if (!value.length) return false;
    foreach (char c; value) if (c <= 0x20 || c == 0x7f) return false;
    return true;
}

private bool encrypted(string value) @safe {
    return value.startsWith("!MLS1:") || value.startsWith("!PGP1:");
}

private bool visibleBody(string command, ref string text, string diagnostic, bool materialize) @safe {
    if (command != "PRIVMSG" && command != "NOTICE") return false;
    if (diagnostic.length || encrypted(text)) return false;
    if (text.length && text[0] == '\x01') {
        // Exactly one valid ACTION frame; all other CTCP is protocol data.
        if (command != "PRIVMSG" || !text.startsWith("\x01ACTION ") ||
                text.length < 9 || text[$ - 1] != '\x01') return false;
        text = text[8 .. $ - 1];
        if (canFind(text, '\x01') || encrypted(text)) return false;
    }
    if (canFind(text, '\x01')) return false;
    if (materialize) text = stripSearchFormatting(text);
    else if (text.length && canFind("\x02\x03\x04\x1d\x1f\x16\x11\x1e\x0f\x1b", text[0]))
        return !encrypted(stripSearchFormatting(text));
    // Formatting must not disguise an envelope or diagnostics as plaintext.
    return !encrypted(text);
}

/// Classify already parsed compact JSON. `channel` is the current authoritative
/// Mongo channel; historical ch/p are compared only to each other, for renames.
SearchClassification classifySearchMessage(const Json payload, string channel) @trusted {
    return classify(payload, channel, true);
}

private bool wellTypedPayload(const Json payload) @trusted {
    static immutable string[] stringKeys = [
        "c", "command", "n", "nick", "x", "text", "ch", "channel", "m",
        "msgid", "i", "id", "l", "label", "le", "eo", "ct", "ctcp", "hm", "hostmask"];
    foreach (key; stringKeys) {
        const field = payload[key];
        if (field.type != Json.Type.undefined && field.type != Json.Type.string) return false;
    }
    const tags = payload["tags"];
    if (tags.type != Json.Type.undefined && tags.type != Json.Type.object) return false;
    foreach (key; ["edit_of", "ctcp"]) {
        if (tags.type != Json.Type.object) break;
        const field = tags[key];
        if (field.type != Json.Type.undefined && field.type != Json.Type.string) return false;
    }
    const compactTarget = stringField(payload, "eo");
    const taggedTarget = stringField(tags, "edit_of");
    return !compactTarget.length || !taggedTarget.length || compactTarget == taggedTarget;
}

private SearchClassification classify(const Json payload, string channel, bool materialize) @trusted {
    SearchClassification result;
    if (payload.type != Json.Type.object || !isSearchChannel(channel)) return result;
    if (!wellTypedPayload(payload)) return result;
    result.command = firstString(payload, "c", "command");
    const payloadChannel = firstString(payload, "ch", "channel");
    const compactParams = payload["p"];
    const params = compactParams.type == Json.Type.undefined ? payload["params"] : compactParams;
    if (params.type != Json.Type.undefined && params.type != Json.Type.array) return SearchClassification.init;
    string wireTarget;
    if (params.type == Json.Type.array && params.length) {
        if (params[0].type != Json.Type.string) return SearchClassification.init;
        wireTarget = params[0].get!string;
    }
    if ((payloadChannel.length && !isSearchChannel(payloadChannel)) ||
            (wireTarget.length && !isSearchChannel(wireTarget))) return SearchClassification.init;
    if (payloadChannel.length && wireTarget.length &&
            normalizeChannelName(payloadChannel) != normalizeChannelName(wireTarget))
        return SearchClassification.init;

    result.nick = firstString(payload, "n", "nick");
    result.hostmask = firstString(payload, "hm", "hostmask");
    result.text = firstString(payload, "x", "text");
    const tags = payload["tags"];
    auto diagnostic = firstString(payload, "ct", "ctcp");
    if (!diagnostic.length) diagnostic = stringField(tags, "ctcp");
    result.target = stringField(payload, "eo");
    if (!result.target.length) result.target = stringField(tags, "edit_of");
    if (result.target.length) {
        if (!validAlias(result.target)) return SearchClassification.init;
        result.kind = SearchKind.edit;
        result.displayable = visibleBody(result.command, result.text,
            diagnostic, materialize) && validAlias(result.nick);
        if (!result.displayable) result.text = "";
        return result;
    }
    if (result.command == "REDACT") {
        if (params.type != Json.Type.array || params.length < 2 ||
                params[1].type != Json.Type.string) return SearchClassification.init;
        result.target = params[1].get!string;
        if (!validAlias(result.target)) return SearchClassification.init;
        result.kind = SearchKind.redact;
        result.text = ""; // Never return a deletion reason or ciphertext.
        return result;
    }
    if (!validAlias(result.nick) || !visibleBody(result.command, result.text,
            diagnostic, materialize)) return SearchClassification.init;

    // The live client uses i only when m is absent. Labels are edit-only aliases.
    result.msgid = firstString(payload, "m", "msgid");
    if (!result.msgid.length) result.msgid = firstString(payload, "i", "id");
    if (result.msgid.length) {
        if (!validAlias(result.msgid)) return SearchClassification.init;
        result.aliases ~= result.msgid;
    }
    auto label = firstString(payload, "l", "label");
    if (!label.length) label = stringField(payload, "le");
    if (label.length) {
        if (!validAlias(label)) return SearchClassification.init;
        if (!canFind(result.aliases, label)) result.aliases ~= label;
    }
    result.kind = SearchKind.message;
    result.displayable = true;
    return result;
}

private SearchClassification classifyArchive(Bson doc, const Json payload, bool materialize) @trusted {
    const channel = doc["channel"].type == Bson.Type.string ? doc["channel"].get!string : "";
    auto result = classify(payload, channel, materialize);
    if (result.kind != SearchKind.message) return result;
    const alias_ = doc["msgid"];
    if (alias_.isNull) return result;
    if (alias_.type != Bson.Type.string || !validAlias(alias_.get!string))
        return SearchClassification.init;
    const storageMsgid = alias_.get!string;
    if (result.msgid.length && result.msgid != storageMsgid) return SearchClassification.init;
    if (!result.msgid.length) {
        result.msgid = storageMsgid;
        if (!canFind(result.aliases, storageMsgid)) result.aliases ~= storageMsgid;
    }
    return result;
}

/// Attach only projection metadata; the original payload and archive ID stay
/// unchanged. Clearing stale fields also makes bootstrap reclassification safe.
void searchMetadata(ref Bson doc, const Json payload) @trusted {
    SearchClassification classification;
    // Metadata is not a second projection/body write. Invalid legacy fields must
    // never turn a successful archive insertion into a delivery failure.
    try classification = classifyArchive(doc, payload, false);
    catch (Exception) classification = SearchClassification.init;
    doc["searchVersion"] = Bson(cast(int) MESSAGE_SEARCH_VERSION);
    final switch (classification.kind) {
        case SearchKind.skip: doc["searchKind"] = Bson("skip"); break;
        case SearchKind.message: doc["searchKind"] = Bson("message"); break;
        case SearchKind.edit: doc["searchKind"] = Bson("edit"); break;
        case SearchKind.redact: doc["searchKind"] = Bson("redact"); break;
    }
    doc.remove("searchAliases");
    doc.remove("searchTarget");
    doc.remove("searchPending");
    if (classification.kind == SearchKind.message)
        doc["searchAliases"] = serializeToBson(classification.aliases);
    if (classification.kind == SearchKind.edit || classification.kind == SearchKind.redact)
        doc["searchTarget"] = Bson(classification.target);
    if (classification.kind != SearchKind.skip) doc["searchPending"] = Bson(true);
}

private bool bsonInteger(Bson value) @safe {
    return value.type == Bson.Type.int_ || value.type == Bson.Type.long_;
}

private long bsonLong(Bson value) @trusted {
    return value.type == Bson.Type.int_ ? cast(long) value.get!int : value.get!long;
}

/// Reclassification is intentional: readers never trust lagging index metadata.
/// An empty rowId means malformed authoritative identity or payload.
SearchRow searchRow(Bson doc) @trusted {
    SearchRow row;
    if (doc.type != Bson.Type.object || doc["_id"].type != Bson.Type.string ||
            doc["networkId"].type != Bson.Type.string || doc["channel"].type != Bson.Type.string ||
            !bsonInteger(doc["t"]) || doc["payload"].type != Bson.Type.string) return row;
    row.rowId = doc["_id"].get!string;
    row.networkId = doc["networkId"].get!string;
    try row.channel = normalizeChannelName(doc["channel"].get!string);
    catch (Exception) return SearchRow.init;
    if (!row.rowId.length || !row.networkId.length || !isSearchChannel(row.channel)) return SearchRow.init;
    row.t = bsonLong(doc["t"]);
    const eid = doc["eid"];
    if (!eid.isNull) {
        if (!bsonInteger(eid)) return SearchRow.init;
        row.hasEid = true;
        row.eid = bsonLong(eid);
    }
    try row.classification = classifyArchive(doc, parseJsonString(doc["payload"].get!string), true);
    catch (Exception) return SearchRow.init;
    return row;
}

/// Strict archive order, ascending. Presence distinguishes legacy missing eid
/// from an explicit zero. Storage row ID is the final tie breaker.
int compareSearchRows(SearchRow a, SearchRow b) @safe {
    if (a.t != b.t) return a.t < b.t ? -1 : 1;
    if (a.hasEid != b.hasEid) return a.hasEid ? 1 : -1;
    if (a.hasEid && a.eid != b.eid) return a.eid < b.eid ? -1 : 1;
    return a.rowId < b.rowId ? -1 : a.rowId > b.rowId ? 1 : 0;
}

private bool sameScope(SearchRow a, SearchRow b) @safe {
    return a.networkId == b.networkId && a.channel == b.channel;
}

/// `relatedRows` must contain all scoped controls naming a base alias and every
/// competing base owning those aliases. The repository batches those lookups.
/// Never infer equivalence from timestamps/eids or the old server assignment.
SearchResolution resolveSearchMessage(SearchRow base, SearchRow[] relatedRows) @safe {
    SearchResolution result;
    result.original = base;
    if (!base.rowId.length || !base.networkId.length || !isSearchChannel(base.channel) ||
            base.classification.kind != SearchKind.message || !base.classification.displayable) return result;
    SearchRow latest;
    bool edited;
    foreach (row; relatedRows) {
        if (!row.rowId.length || !sameScope(base, row)) continue;
        const classified = row.classification;
        if (classified.kind == SearchKind.message) {
            if (row.rowId == base.rowId) continue;
            foreach (alias_; classified.aliases) {
                if (!canFind(base.classification.aliases, alias_)) continue;
                // An ambiguous identity is not safe even without a known control:
                // either original could later be the target of a REDACT.
                result.ambiguous = true;
                return result;
            }
            continue;
        }
        if ((classified.kind != SearchKind.edit && classified.kind != SearchKind.redact) ||
                !canFind(base.classification.aliases, classified.target)) continue;
        if (classified.kind == SearchKind.redact) {
            if (classified.target != base.classification.msgid) continue;
            result.redacted = true;
            continue;
        }
        if (!edited || compareSearchRows(latest, row) < 0) {
            latest = row;
            edited = true;
        }
    }
    if (result.redacted || (edited && !latest.classification.displayable)) return result;
    result.text = edited ? latest.classification.text : base.classification.text;
    result.bodyFold = searchFold(result.text);
    result.senderFold = searchFold(base.classification.nick);
    result.visible = true;
    return result;
}

/// Deterministic pure regression cases, also invoked by history-boundary-test.
void runMessageSearchClassifierTests() @trusted {
    Json chat(string body, string alias_ = "original") {
        return Json(["c": Json("PRIVMSG"), "ch": Json("#ROOM"), "n": Json("Mira"),
            "m": Json(alias_), "l": Json("label-1"), "x": Json(body),
            "p": Json([Json("#room"), Json(body)])]);
    }
    auto message = chat("release freeze");
    auto classified = classifySearchMessage(message, "#room");
    assert(classified.kind == SearchKind.message && classified.displayable);
    assert(classified.aliases == ["original", "label-1"]);
    auto identified = chat("identity");
    identified["i"] = Json("overridden-id");
    assert(classifySearchMessage(identified, "#room").aliases == ["original", "label-1"]);
    identified["m"] = Json("");
    assert(classifySearchMessage(identified, "#room").msgid == "overridden-id");
    assert(classifySearchMessage(chat("\x01ACTION waves\x01"), "#room").text == "waves");
    assert(classifySearchMessage(chat("\x01VERSION\x01"), "#room").kind == SearchKind.skip);
    assert(classifySearchMessage(chat("\x01ACTION broken"), "#room").kind == SearchKind.skip);
    assert(classifySearchMessage(chat("!MLS1:id:1/2:cipher"), "#room").kind == SearchKind.skip);
    assert(classifySearchMessage(chat("!PGP1:cipher"), "#room").kind == SearchKind.skip);
    assert(classifySearchMessage(message, "mira").kind == SearchKind.skip);
    assert(classifySearchMessage(message, "_server").kind == SearchKind.skip);
    assert(isSearchChannel("&room") && isSearchChannel("+room") && isSearchChannel("!room"));
    assert(!isSearchChannel("#") && !isSearchChannel("#two rooms"));
    assert(stripSearchFormatting("\x02bold\x02 \x0312,04red\x0f \x04ff00aa,000000hex\x1b[31m!") ==
        "bold red hex!");
    assert(stripSearchFormatting("\x03,12 \x04fff \x1b[?25htext\x1b") == ",12 fff text");
    assert(searchFold("MÜNCHEN İ") == "münchen i\u0307");
    auto diagnostic = chat("release freeze");
    diagnostic["ct"] = Json("PING");
    assert(classifySearchMessage(diagnostic, "#room").kind == SearchKind.skip);
    diagnostic = chat("tagged diagnostic");
    diagnostic["tags"] = Json(["ctcp": Json("PING")]);
    assert(classifySearchMessage(diagnostic, "#room").kind == SearchKind.skip);
    auto malformed = chat("invalid edit");
    malformed["eo"] = Json(123);
    assert(classifySearchMessage(malformed, "#room").kind == SearchKind.skip);
    malformed = chat("wrong channel edit");
    malformed["eo"] = Json("original");
    malformed["p"] = Json([Json("#foreign"), Json("replacement")]);
    assert(classifySearchMessage(malformed, "#room").kind == SearchKind.skip);
    malformed = chat("ambiguous edit");
    malformed["eo"] = Json("original");
    malformed["tags"] = Json(["edit_of": Json("another-target")]);
    assert(classifySearchMessage(malformed, "#room").kind == SearchKind.skip);
    auto notice = chat("chat notice");
    notice["c"] = Json("NOTICE");
    assert(classifySearchMessage(notice, "#room").kind == SearchKind.message);
    notice["c"] = Json("JOIN");
    assert(classifySearchMessage(notice, "#room").kind == SearchKind.skip);

    SearchRow base = SearchRow("base", "net", "#room", 100, 0, false, classified);
    auto editPayload = chat("new body");
    editPayload["eo"] = Json("label-1");
    auto edit = SearchRow("edit", "net", "#room", 50, 0, false,
        classifySearchMessage(editPayload, "#room"));
    auto resolved = resolveSearchMessage(base, [edit]);
    assert(resolved.visible && resolved.text == "new body" && resolved.original.t == 100);
    assert(resolved.original.classification.nick == "Mira");
    auto newer = edit;
    newer.rowId = "edit-zero";
    newer.hasEid = true;
    newer.classification.text = "latest";
    assert(compareSearchRows(edit, newer) < 0);
    assert(resolveSearchMessage(base, [newer, edit]).text == "latest");
    auto foreign = newer;
    foreign.channel = "#elsewhere";
    assert(resolveSearchMessage(base, [foreign]).text == "release freeze");
    foreign.channel = "#room";
    foreign.networkId = "other";
    assert(resolveSearchMessage(base, [foreign]).text == "release freeze");
    auto redactPayload = Json(["c": Json("REDACT"), "p": Json([Json("#room"), Json("original")])]);
    auto redact = SearchRow("redact", "net", "#room", 1, 0, false,
        classifySearchMessage(redactPayload, "#room"));
    resolved = resolveSearchMessage(base, [newer, redact, edit]);
    assert(!resolved.visible && resolved.redacted && resolved.text == "");
    auto labelRedact = redact;
    labelRedact.classification.target = "label-1";
    assert(resolveSearchMessage(base, [labelRedact]).visible);
    auto wrongIdEdit = edit;
    wrongIdEdit.classification.target = "overridden-id";
    assert(resolveSearchMessage(base, [wrongIdEdit]).text == "release freeze");
    editPayload["x"] = Json("!MLS1:chunk:1/2:cipher");
    edit.classification = classifySearchMessage(editPayload, "#room");
    assert(edit.classification.kind == SearchKind.edit && !edit.classification.displayable);
    assert(!resolveSearchMessage(base, [edit]).visible);
    auto duplicate = base;
    duplicate.rowId = "other-base";
    assert(resolveSearchMessage(base, [duplicate]).ambiguous);
    duplicate.classification = classifySearchMessage(chat("other body", "other-msgid"), "#room");
    duplicate.classification.aliases = ["other-msgid"];
    assert(resolveSearchMessage(base, [duplicate]).visible);

    auto doc = Bson(["_id": Bson("old-server:opaque"), "networkId": Bson("net"),
        "channel": Bson("#renamed"), "t": Bson(100L), "payload": Bson(message.toString())]);
    const originalPayload = doc["payload"].get!string;
    searchMetadata(doc, message);
    assert(doc["searchVersion"].get!int == MESSAGE_SEARCH_VERSION && doc["searchPending"].get!bool);
    assert(doc["searchKind"].get!string == "message" && doc["searchAliases"].length == 2);
    assert(doc["payload"].get!string == originalPayload && doc["_id"].get!string == "old-server:opaque");
    assert(searchRow(doc).channel == "#renamed");
    doc["t"] = Bson(100);
    doc["eid"] = Bson(0);
    const intWidthRow = searchRow(doc);
    assert(intWidthRow.t == 100 && intWidthRow.hasEid && intWidthRow.eid == 0);
    searchMetadata(doc, redactPayload);
    assert(doc["searchKind"].get!string == "redact" && doc["searchTarget"].get!string == "original");
    assert(doc["searchAliases"].isNull);
    searchMetadata(doc, chat("!PGP1:cipher"));
    assert(doc["searchKind"].get!string == "skip" && doc["searchPending"].isNull && doc["searchTarget"].isNull);
    foreach (cipher; ["\x02!MLS1:cipher", "\x1b[31m!PGP1:chunk:1/2:cipher"]) {
        const obscured = chat(cipher);
        searchMetadata(doc, obscured);
        assert(doc["searchKind"].get!string == "skip");
        assert(classifySearchMessage(obscured, "#renamed").kind == SearchKind.skip);
    }
    searchMetadata(doc, malformed);
    assert(doc["searchKind"].get!string == "skip");
}
