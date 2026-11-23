module ircfiber.db.history_suppression;

import core.time : MonoTime, msecs, seconds;
import std.algorithm : canFind, min, max;
import std.conv : to;
import std.digest : LetterCase, toHexString;
import std.digest.sha : sha256Of;
import vibe.data.bson;
import vibe.data.json : Json, parseJsonString;
import vibe.core.core : yield;
import vibe.db.mongo.mongo : MongoDatabase;
import ircfiber.db.message_search;
import ircfiber.models.network : normalizeChannelName;

/// No message bodies, nicknames, edit text, or redaction reasons belong here.
/// Alias marks retain only ranges of witness coordinates per original engine.
/// Ranges may over-suppress gaps, but must never reconstruct a previous body.
final class HistorySuppressionRepository {
    private MongoDatabase database;
    private MonoTime deadline;
    private bool sourceIndexesEnsured;
    private enum collection = "history_search_suppressions";
    private enum pageSize = 256;
    private enum maxKeys = 10_000;
    private enum maxScopes = 256;
    private enum maxBytes = 32 * 1024 * 1024;

    this(MongoDatabase db) { database = db; }

    /// Called BEFORE deleting the exact source IDs. Controls always leave a
    /// mark. Bases leave none without a witnessed competitor/control. Legacy
    /// metadata is repaired in bounded CAS pages before trusting alias indexes;
    /// neither deletion nor privacy depends on the optional search worker.
    void preserveBeforeDelete(Bson[] documents, bool clearingScope = false) {
        deadline = MonoTime.currTime + 45.seconds;
        require(documents.length <= pageSize);
        SearchRow[] rows;
        Bson[] owners;
        Bson[] controls;
        foreach (doc; documents) {
            auto channel = text(doc, "channel");
            if (!isSearchChannel(channel)) continue;
            auto row = searchRow(doc);
            require(row.rowId.length != 0 && text(doc, "serverId").length != 0);
            validateSource(doc, row);
            // Truly unclassified protocol noise cannot own or target an alias.
            // Do not mutate it (or unrelated survivors) just to clear history.
            if (row.classification.kind == SearchKind.skip
                    || (row.classification.kind == SearchKind.message
                        && !row.classification.aliases.length)) continue;
            rows ~= row;
            if (row.classification.kind == SearchKind.message && row.classification.aliases.length) {
                auto scope_ = Bson(["networkId": Bson(row.networkId), "channel": Bson(row.channel)]);
                auto owner = scope_;
                owner["searchAliases"] = Bson(["$in": serializeToBson(row.classification.aliases),
                    "$exists": Bson(true)]);
                owners ~= owner;
                auto control = scope_;
                control["searchTarget"] = Bson(["$in": serializeToBson(row.classification.aliases),
                    "$exists": Bson(true)]);
                controls ~= control;
            } else if (row.classification.kind == SearchKind.edit || row.classification.kind == SearchKind.redact) {
                owners ~= Bson(["networkId": Bson(row.networkId), "channel": Bson(row.channel),
                    "searchAliases": Bson(["$in": serializeToBson([row.classification.target]),
                        "$exists": Bson(true)])]);
            }
        }
        if (!rows.length) return;
        ensureSourceIndexes();
        size_t classificationBudget = pageSize;
        string[] classifiedScopes;
        SearchRow[] scopeRows;
        foreach (row; rows) {
            const key = scopeKey(row.networkId, row.channel);
            if (classifiedScopes.canFind(key)) continue;
            classifyLegacyScope(row.networkId, row.channel, classificationBudget);
            classifiedScopes ~= key;
            scopeRows ~= row;
        }
        SearchRow[] related;
        size_t bytes;
        string[string] relatedServers;
        foreach (index, query; [owners, controls]) {
            if (!query.length) continue;
            foreach (doc; find("messages", Bson(["$or": Bson(query)]), maxKeys,
                    index == 0 ? "message_search_alias" : "message_search_target")) {
                account(bytes, doc);
                auto row = searchRow(doc);
                require(row.rowId.length != 0);
                validateClassification(doc, row);
                related ~= row;
                relatedServers[row.rowId] = text(doc, "serverId");
                require(related.length <= maxKeys);
            }
        }
        // A mixed old writer or a racing rename is not proof of absence.
        foreach (row; scopeRows) requireClassifiedScope(row.networkId, row.channel);
        string[] scopeIds;
        foreach (row; rows) {
            const id = scopeKey(row.networkId, row.channel);
            if (!scopeIds.canFind(id)) scopeIds ~= id;
        }
        Bson[string] scopeStates;
        foreach (doc; readIds(scopeIds, 2_000)) {
            account(bytes, doc);
            validateScope(doc, text(doc, "networkId"), text(doc, "channel"));
            scopeStates[text(doc, "_id")] = doc;
        }
        Bson[] updates;
        foreach (row; rows) {
            string server;
            foreach (doc; documents)
                if (text(doc, "_id") == row.rowId) { server = text(doc, "serverId"); break; }
            require(server.length != 0);
            auto names = row.classification.aliases;
            if (row.classification.kind == SearchKind.edit || row.classification.kind == SearchKind.redact)
                names = [row.classification.target];
            else if (row.classification.kind == SearchKind.message) {
                string[] dependent;
                foreach (name; names) {
                    bool keep;
                    foreach (other; related) {
                        if (row.networkId != other.networkId || row.channel != other.channel) continue;
                        bool competing = other.classification.kind == SearchKind.message
                            && other.rowId != row.rowId && other.classification.aliases.canFind(name);
                        bool targeted = (other.classification.kind == SearchKind.edit
                            || other.classification.kind == SearchKind.redact) && other.classification.target == name;
                        if (competing || targeted) { keep = true; break; }
                    }
                    // A rename can move competitors between our source capture
                    // and indexed lookup. Its published barrier makes only
                    // aliases in that particular prefix uncertain.
                    if (auto state = scopeKey(row.networkId, row.channel) in scopeStates)
                        foreach (edge; entries(*state, "retired"))
                            if (text(edge, "serverId") == server && !after(row, edge)) keep = true;
                    if (keep) dependent ~= name;
                }
                names = dependent;
            } else continue;
            foreach (name; names) {
                Pin[] pins;
                foreach (other; related) {
                    if (other.classification.kind != SearchKind.message
                            || other.networkId != row.networkId || other.channel != row.channel
                            || !other.classification.aliases.canFind(name)) continue;
                    bool reused;
                    if (!clearingScope && relatedServers[other.rowId] == server)
                        if (auto state = scopeKey(row.networkId, row.channel) in scopeStates)
                            foreach (field; ["clears", "retired"])
                                foreach (edge; entries(*state, field))
                                    if (text(edge, "serverId") == server && !after(row, edge)
                                            && after(other, edge)) reused = true;
                    if (!reused) pins ~= Pin(other.rowId, relatedServers[other.rowId],
                        other.t, other.eid, other.hasEid);
                }
                updates ~= markUpdate(row, server, name, pins);
            }
        }
        writeUpdates(updates);
    }

    /// Publish both directions before changing source channels. Incoming edges
    /// carry the immutable ordered rename barrier. The outgoing barrier stops
    /// the old channel's reuse inheriting marks from its renamed prefix.
    void beforeRename(string server, string network, string oldChannel, string newChannel,
            long cutoffEid, long legacyTimestampCutoffMs) {
        deadline = MonoTime.currTime + 45.seconds;
        oldChannel = normalizeChannelName(oldChannel);
        newChannel = normalizeChannelName(newChannel);
        if (!isSearchChannel(oldChannel) || !isSearchChannel(newChannel) || oldChannel == newChannel) return;
        require(server.length && network.length && cutoffEid >= 0 && legacyTimestampCutoffMs >= 0);
        auto edge = Bson(["serverId": Bson(server), "channel": Bson(oldChannel),
            "eid": Bson(cutoffEid), "t": Bson(legacyTimestampCutoffMs)]);
        const name = digest(server ~ "\0" ~ oldChannel ~ "\0" ~ newChannel ~ "\0"
            ~ to!string(cutoffEid) ~ ":" ~ to!string(legacyTimestampCutoffMs));
        writeUpdates([scopeUpdate(network, newChannel, "incoming." ~ name, edge),
            scopeUpdate(network, oldChannel, "retired." ~ name, edge)]);
    }

    /// A frozen channel clear retires only this engine's acknowledged prefix.
    /// Late pre-clear controls can recreate marks, but cannot poison new reuse.
    /// Cross-engine witnesses are deliberately not erased by a local clear.
    void beforeClear(string server, string network, string channel,
            long cutoffEid, long legacyTimestampCutoffMs) {
        deadline = MonoTime.currTime + 45.seconds;
        channel = normalizeChannelName(channel);
        if (!isSearchChannel(channel)) return;
        require(server.length && network.length && cutoffEid >= 0 && legacyTimestampCutoffMs >= 0);
        const stem = "clears." ~ digest(server) ~ ".";
        auto fields = scopeIdentity(network, channel);
        auto set = Bson([stem ~ "serverId": Bson(server)]);
        auto upper = Bson([stem ~ "eid": Bson(cutoffEid), stem ~ "t": Bson(legacyTimestampCutoffMs)]);
        writeUpdates([update(scopeKey(network, channel), Bson(["$setOnInsert": fields,
            "$set": set, "$max": upper]))]);
    }

    /// Source evidence is read first by both callers; marks are read afterwards.
    /// Therefore an acknowledged preserve-before-delete cannot disappear in the
    /// gap between those reads. All lookups are bounded _id batches.
    bool[string] suppressedRows(SearchRow[] bases, string[string] servers, long maxTimeMs = 2_000) {
        require(bases.length <= maxKeys && maxTimeMs > 0);
        deadline = MonoTime.currTime + maxTimeMs.msecs;
        Scope[string] scopes;
        string[] pending;
        foreach (base; bases) {
            const key = scopeKey(base.networkId, base.channel);
            if (key !in scopes) {
                scopes[key] = Scope(base.networkId, base.channel);
                pending ~= key;
            }
        }
        size_t bytes;
        while (pending.length) {
            string[] next;
            foreach (doc; readIds(pending, maxTimeMs)) {
                account(bytes, doc);
                const key = text(doc, "_id");
                auto scope_ = key in scopes;
                require(scope_ !is null);
                validateScope(doc, scope_.network, scope_.channel);
                const network = scope_.network;
                scope_.document = doc;
                foreach (edge; entries(doc, "incoming")) {
                    validateEdge(edge);
                    const channel = text(edge, "channel");
                    const ancestor = scopeKey(network, channel);
                    if (ancestor in scopes) continue;
                    require(scopes.length < maxScopes);
                    scopes[ancestor] = Scope(network, channel);
                    next ~= ancestor;
                }
            }
            pending = next;
        }
        bool[string] wanted;
        foreach (base; bases) foreach (key, scope_; scopes) {
            if (scope_.network != base.networkId) continue;
            foreach (name; base.classification.aliases)
                wanted[markKey(scope_.network, scope_.channel, name)] = true;
        }
        require(wanted.length <= maxKeys);
        string[] keys;
        foreach (key; wanted.keys) keys ~= key;
        Bson[string] marks;
        foreach (doc; readIds(keys, maxTimeMs)) {
            account(bytes, doc);
            validateMark(doc);
            marks[text(doc, "_id")] = doc;
        }
        bool[string] result;
        foreach (base; bases) {
            auto server = base.rowId in servers;
            require(server !is null && server.length != 0);
            auto start = scopeKey(base.networkId, base.channel);
            Path[] paths = [Path(start)];
            bool[Path] seen;
            size_t visited;
            while (paths.length && base.rowId !in result) {
                auto path = paths[$ - 1];
                paths.length--;
                if (path in seen) continue;
                seen[path] = true;
                require(++visited <= maxScopes);
                auto scope_ = path.key in scopes;
                require(scope_ !is null);
                // Clears apply along the whole lineage. A newer base on the
                // same engine is a new identity generation, not a late base.
                foreach (edge; entries(scope_.document, "clears")) {
                    validateEdge(edge, false);
                    if (path.key == start && text(edge, "serverId") == *server && !after(base, edge))
                        result[base.rowId] = true;
                    if (text(edge, "serverId") == *server && after(base, edge)) {
                        path.lowEid = max(path.lowEid, integer(edge, "eid"));
                        path.lowT = max(path.lowT, integer(edge, "t"));
                    }
                }
                if (path.key == start) foreach (edge; entries(scope_.document, "retired")) {
                    validateEdge(edge);
                    if (text(edge, "serverId") == *server && !after(base, edge))
                        result[base.rowId] = true;
                    if (text(edge, "serverId") == *server && after(base, edge)) {
                        path.lowEid = max(path.lowEid, integer(edge, "eid"));
                        path.lowT = max(path.lowT, integer(edge, "t"));
                    }
                }
                foreach (name; base.classification.aliases) {
                    auto mark = markKey(base.networkId, scope_.channel, name) in marks;
                    if (!mark) continue;
                    require(text(*mark, "networkId") == base.networkId
                        && text(*mark, "channel") == scope_.channel && text(*mark, "alias") == name);
                    const pinned = (*mark)["pinned"];
                    if (pinned.type == Bson.Type.object) {
                        const value = pinned[digest(base.rowId)];
                        if (value.type == Bson.Type.object && text(value, "serverId") == *server
                                && integer(value, "t") == base.t && integer(value, "eid") == base.eid
                                && value["hasEid"].get!bool == base.hasEid) {
                            result[base.rowId] = true;
                            break;
                        }
                    }
                    foreach (witness; entries(*mark, "witnesses")) {
                        const witnessServer = text(witness, "serverId");
                        if (path.server.length && witnessServer != path.server) continue;
                        const lowerEid = witnessServer == *server ? path.lowEid : -1;
                        const lowerT = witnessServer == *server ? path.lowT : -1;
                        const loEid = integer(witness, "loEid"), hiEid = integer(witness, "hiEid");
                        const loT = integer(witness, "loT"), hiT = integer(witness, "hiT");
                        if ((hiEid >= 0 && loEid <= path.highEid && hiEid > lowerEid)
                                || (hiT >= 0 && loT <= path.highT && hiT > lowerT)) {
                            result[base.rowId] = true;
                            break;
                        }
                    }
                }
                foreach (edge; entries(scope_.document, "incoming")) {
                    const edgeServer = text(edge, "serverId");
                    if (path.server.length && path.server != edgeServer) continue;
                    auto next = path;
                    next.key = scopeKey(base.networkId, text(edge, "channel"));
                    next.server = edgeServer;
                    next.highEid = min(path.highEid, integer(edge, "eid"));
                    next.highT = min(path.highT, integer(edge, "t"));
                    paths ~= next;
                }
            }
        }
        return result;
    }

    /// Only a positively observed durable network fence authorizes removing
    /// suppression and lineage. Keep the content-free fence forever. Repeated
    /// sweeps collect marks racing an already admitted expired replay.
    size_t deleteFencedNetworkPage(string network) {
        deadline = MonoTime.currTime + 45.seconds;
        auto fences = find("history_network_fences", Bson(["_id": Bson(network)]), 1);
        require(fences.length == 1 && text(fences[0], "_id") == network && text(fences[0], "ownerId").length);
        const prefix = digest(network) ~ ":";
        auto docs = find(collection, Bson(["_id": Bson(["$gte": Bson(prefix),
            "$lt": Bson(prefix ~ "~")])]), pageSize, "_id_", true);
        if (!docs.length) return 0;
        string[] ids;
        foreach (doc; docs) {
            require(text(doc, "networkId") == network);
            ids ~= text(doc, "_id");
        }
        auto command = Bson.emptyObject;
        command["delete"] = Bson(collection);
        command["deletes"] = Bson([Bson(["q": Bson(["_id": Bson(["$in": serializeToBson(ids)])]), "limit": Bson(0)])]);
        command["writeConcern"] = concern();
        auto reply = run(command);
        require(integer(reply, "n") >= 0 && integer(reply, "n") <= ids.length);
        return cast(size_t) integer(reply, "n");
    }

    private struct Scope { string network; string channel; Bson document; }
    private struct Pin { string rowId; string server; long t; long eid; bool hasEid; }
    private struct Path {
        string key; string server;
        long lowEid = -1, lowT = -1;
        long highEid = long.max, highT = long.max;
    }

    private static string digest(string value) { return toHexString!(LetterCase.lower)(sha256Of(value)).idup; }
    private static string scopeKey(string network, string channel) { return digest(network) ~ ":s:" ~ digest(channel); }
    private static string markKey(string network, string channel, string alias_) {
        return digest(network) ~ ":m:" ~ digest(channel) ~ ":" ~ digest(alias_);
    }
    private static Bson scopeIdentity(string network, string channel) {
        return Bson(["v": Bson(1), "kind": Bson("scope"), "networkId": Bson(network), "channel": Bson(channel)]);
    }
    private static Bson update(string id, Bson fields) {
        return Bson(["q": Bson(["_id": Bson(id)]), "u": fields, "upsert": Bson(true), "multi": Bson(false)]);
    }
    private static Bson scopeUpdate(string network, string channel, string field, Bson value) {
        return update(scopeKey(network, channel), Bson(["$setOnInsert": scopeIdentity(network, channel),
            "$set": Bson([field: value])]));
    }
    private static Bson markUpdate(SearchRow row, string server, string name, Pin[] pins) {
        require(name.length != 0);
        auto identity = Bson(["v": Bson(1), "kind": Bson("mark"), "networkId": Bson(row.networkId),
            "channel": Bson(row.channel), "alias": Bson(name)]);
        const stem = "witnesses." ~ digest(server) ~ ".";
        const eid = row.hasEid && row.eid > 0 ? row.eid : -1;
        const timestamp = eid < 0 ? row.t : -1;
        auto fixed = Bson([stem ~ "serverId": Bson(server)]);
        foreach (pin; pins) fixed["pinned." ~ digest(pin.rowId)] = Bson([
            "serverId": Bson(pin.server), "t": Bson(pin.t), "eid": Bson(pin.eid), "hasEid": Bson(pin.hasEid)]);
        return update(markKey(row.networkId, row.channel, name), Bson(["$setOnInsert": identity,
            "$set": fixed,
            "$min": Bson([stem ~ "loEid": Bson(eid < 0 ? long.max : eid),
                stem ~ "loT": Bson(timestamp < 0 ? long.max : timestamp)]),
            "$max": Bson([stem ~ "hiEid": Bson(eid), stem ~ "hiT": Bson(timestamp)])]));
    }
    private static bool after(SearchRow row, Bson edge) {
        return row.hasEid && row.eid > 0 ? row.eid > integer(edge, "eid") : row.t > integer(edge, "t");
    }
    private static Bson concern() { return Bson(["w": Bson("majority"), "j": Bson(true), "wtimeout": Bson(15_000)]); }

    private void writeUpdates(Bson[] updates) {
        foreach (offset; 0 .. (updates.length + pageSize - 1) / pageSize) {
            auto batch = updates[offset * pageSize .. min(updates.length, (offset + 1) * pageSize)];
            auto command = Bson.emptyObject;
            command["update"] = Bson(collection);
            command["updates"] = Bson(batch);
            command["ordered"] = Bson(true);
            command["writeConcern"] = concern();
            auto reply = run(command);
            require(integer(reply, "n") == batch.length);
        }
    }
    private Bson[] readIds(string[] ids, long timeMs) {
        require(ids.length <= maxKeys);
        Bson[] result;
        for (size_t offset; offset < ids.length; offset += pageSize)
            result ~= find(collection, Bson(["_id": Bson(["$in": serializeToBson(ids[offset .. min(ids.length, offset + pageSize)])])]),
                pageSize, "_id_", false, timeMs);
        return result;
    }
    /// These are the existing shared search index definitions, not a second
    /// classifier/index format. Preparation normally builds them; legacy-mode
    /// explicit clears must also work when search has never been enabled.
    private void ensureSourceIndexes() {
        if (sourceIndexesEnsured) return;
        Bson[] indexes;
        void add(string name, string[] fields, string partial = "") {
            auto key = Bson.emptyObject;
            foreach (field; fields) key[field] = Bson(1);
            auto definition = Bson(["name": Bson(name), "key": key]);
            if (partial.length) definition["partialFilterExpression"] =
                Bson([partial: Bson(["$exists": Bson(true)])]);
            indexes ~= definition;
        }
        add("message_search_alias", ["networkId", "channel", "searchAliases"], "searchAliases");
        add("message_search_target", ["networkId", "channel", "searchTarget", "t", "eid", "_id"], "searchTarget");
        add("message_search_version", ["networkId", "channel", "searchVersion"]);
        auto command = Bson.emptyObject;
        command["createIndexes"] = Bson("messages");
        command["indexes"] = Bson(indexes);
        command["writeConcern"] = concern();
        run(command);
        sourceIndexesEnsured = true;
    }

    private static Bson legacyFilter(string network, string channel) {
        return Bson(["networkId": Bson(network), "channel": Bson(channel),
            "searchVersion": Bson(["$ne": Bson(cast(int) MESSAGE_SEARCH_VERSION)])]);
    }

    private void requireClassifiedScope(string network, string channel) {
        require(!find("messages", legacyFilter(network, channel), 1,
            "message_search_version", true).length);
    }

    /// Removing each acknowledged row from the indexed unclassified set is the
    /// durable cursor. A retry never starts a whole-archive scan. Exhaustion,
    /// source CAS conflict or uncertain acknowledgement leaves deletion blocked;
    /// the next maintenance turn resumes with the remaining rows.
    private void classifyLegacyScope(string network, string channel, ref size_t budget) {
        if (!budget) { requireClassifiedScope(network, channel); return; }
        auto docs = find("messages", legacyFilter(network, channel), budget,
            "message_search_version", true);
        budget -= docs.length;
        foreach (doc; docs) {
            auto row = searchRow(doc);
            require(row.rowId.length != 0 && whollyUnclassified(doc));
            validateSource(doc, row);
            // Only the tiny classifier envelope is mutable. Never copy or
            // persist the payload in a suppression record or a second archive.
            auto metadata = Bson(["channel": doc["channel"]]);
            if (has(doc, "msgid")) metadata["msgid"] = doc["msgid"];
            searchMetadata(metadata, parseJsonString(text(doc, "payload")));
            validateClassification(metadata, row);
            auto set = Bson.emptyObject;
            foreach (field; ["searchVersion", "searchKind", "searchAliases", "searchTarget", "searchPending"])
                if (has(metadata, field)) set[field] = metadata[field];
            auto filter = Bson.emptyObject;
            foreach (field; ["_id", "networkId", "serverId", "channel", "payload", "t", "eid", "msgid",
                    "historyOwnerId", "historyBytes", "searchVersion", "searchKind", "searchAliases",
                    "searchTarget", "searchPending", "searchClaimGeneration", "searchClaimToken"]) {
                filter[field] = has(doc, field)
                    ? Bson(["$eq": doc[field], "$exists": Bson(true)])
                    : Bson(["$exists": Bson(false)]);
            }
            auto command = Bson.emptyObject;
            command["update"] = Bson("messages");
            command["updates"] = Bson([Bson(["q": filter, "u": Bson(["$set": set]),
                "multi": Bson(false), "upsert": Bson(false)])]);
            command["writeConcern"] = concern();
            require(command.data.length <= 16 * 1024 * 1024 - 16 * 1024);
            require(integer(run(command), "n") == 1);
            yield();
        }
        requireClassifiedScope(network, channel);
    }

    private Bson[] find(string name, Bson filter, size_t limit, string hint = "", bool page = false,
            long timeMs = 2_000) {
        auto command = Bson.emptyObject;
        command["find"] = Bson(name);
        command["filter"] = filter;
        if (hint != "message_search_alias" && hint != "message_search_target"
                && hint != "message_search_version")
            command["sort"] = Bson(["_id": Bson(1)]);
        command["limit"] = Bson(cast(long) (page ? limit : limit + 1));
        command["batchSize"] = Bson(cast(long) min(pageSize, page ? limit : limit + 1));
        command["maxTimeMS"] = Bson(timeMs);
        command["readConcern"] = Bson(["level": Bson("majority")]);
        if (hint.length) command["hint"] = Bson(hint);
        Bson[] result;
        size_t bytes;
        long cursorId;
        scope(exit) if (cursorId) {
            auto kill = Bson.emptyObject;
            kill["killCursors"] = Bson(name);
            kill["cursors"] = Bson([Bson(cursorId)]);
            closeCursor(kill);
        }
        string batchName = "firstBatch";
        while (true) {
            auto reply = run(command);
            auto cursor = reply["cursor"];
            require(cursor.type == Bson.Type.object
                && text(cursor, "ns") == database.name ~ "." ~ name
                && cursor[batchName].type == Bson.Type.array);
            cursorId = integer(cursor, "id");
            foreach (doc; cursor[batchName]) {
                require(doc.type == Bson.Type.object && text(doc, "_id").length != 0);
                account(bytes, doc);
                result ~= doc;
                require(result.length <= limit);
            }
            if (!cursorId) return result;
            command = Bson.emptyObject;
            command["getMore"] = Bson(cursorId);
            command["collection"] = Bson(name);
            command["batchSize"] = Bson(cast(long) pageSize);
            batchName = "nextBatch";
        }
    }
    private Bson run(Bson command) {
        if (deadline != MonoTime.init) {
            const remaining = (deadline - MonoTime.currTime).total!"msecs";
            require(remaining > 0);
            if (!has(command, "getMore")) {
                const cap = has(command, "maxTimeMS") ? integer(command, "maxTimeMS") : 15_000L;
                command["maxTimeMS"] = Bson(min(remaining, cap));
            }
        }
        Bson reply;
        try reply = database.runCommandUnchecked(command);
        catch (Exception) { throw new Exception("History suppression unavailable"); }
        const ok = reply["ok"];
        require(reply.type == Bson.Type.object &&
            ((ok.type == Bson.Type.double_ && ok.get!double == 1)
            || (ok.type == Bson.Type.int_ && ok.get!int == 1) || (ok.type == Bson.Type.long_ && ok.get!long == 1))
            && !has(reply, "writeConcernError") && !has(reply, "writeConcernErrors")
            && (!has(reply, "writeErrors") || (reply["writeErrors"].type == Bson.Type.array && reply["writeErrors"].length == 0)));
        return reply;
    }
    private void closeCursor(Bson command) {
        try database.runCommandUnchecked(command);
        catch (Exception) {}
    }
    private static Bson[] entries(Bson doc, string field) {
        if (doc.type == Bson.Type.undefined || doc.type == Bson.Type.null_) return null;
        require(doc.type == Bson.Type.object);
        if (!has(doc, field)) return null;
        require(doc[field].type == Bson.Type.object);
        Bson[] result;
        foreach (key, value; doc[field].byKeyValue) { require(value.type == Bson.Type.object); result ~= value; }
        require(result.length <= maxScopes);
        return result;
    }
    private static void validateScope(Bson doc, string network, string channel) {
        require(integer(doc, "v") == 1 && text(doc, "kind") == "scope"
            && text(doc, "networkId") == network && text(doc, "channel") == channel
            && text(doc, "_id") == scopeKey(network, channel));
        foreach (field; ["incoming", "retired"]) foreach (edge; entries(doc, field)) validateEdge(edge);
        foreach (edge; entries(doc, "clears")) validateEdge(edge, false);
    }
    private static void validateEdge(Bson edge, bool channel = true) {
        require(text(edge, "serverId").length && integer(edge, "eid") >= 0 && integer(edge, "t") >= 0);
        if (channel) require(isSearchChannel(text(edge, "channel")));
    }
    private static void validateMark(Bson doc) {
        const network = text(doc, "networkId"), channel = text(doc, "channel"), alias_ = text(doc, "alias");
        require(integer(doc, "v") == 1 && text(doc, "kind") == "mark" && network.length
            && isSearchChannel(channel) && alias_.length && text(doc, "_id") == markKey(network, channel, alias_));
        auto witnesses = entries(doc, "witnesses");
        require(witnesses.length != 0 && witnesses.length <= 64);
        foreach (witness; witnesses) {
            const loEid = integer(witness, "loEid"), hiEid = integer(witness, "hiEid");
            const loT = integer(witness, "loT"), hiT = integer(witness, "hiT");
            require(text(witness, "serverId").length && hiEid >= -1 && hiT >= -1
                && (hiEid == -1 ? loEid == long.max : loEid > 0 && loEid <= hiEid)
                && (hiT == -1 ? loT == long.max : loT > 0 && loT <= hiT)
                && (hiEid >= 0 || hiT >= 0));
        }
        if (has(doc, "pinned")) {
            require(doc["pinned"].type == Bson.Type.object);
            foreach (key, value; doc["pinned"].byKeyValue) {
                require(key.length == 64 && value.type == Bson.Type.object && text(value, "serverId").length
                    && integer(value, "t") > 0 && integer(value, "eid") >= 0
                    && value["hasEid"].type == Bson.Type.bool_);
            }
        }
    }
    private static bool whollyUnclassified(Bson doc) {
        foreach (field; ["searchVersion", "searchKind", "searchAliases", "searchTarget",
                "searchPending", "searchClaimGeneration", "searchClaimToken"])
            if (has(doc, field)) return false;
        return true;
    }

    private static void validateSource(Bson doc, SearchRow row) {
        if (!whollyUnclassified(doc)) { validateClassification(doc, row); return; }
        // searchRow rejects malformed JSON/identity. Also reject malformed
        // protocol shapes that the tolerant classifier deliberately maps to
        // skip: they are not affirmative evidence of harmless legacy noise.
        auto payload = parseJsonString(text(doc, "payload"));
        require(payload.type == Json.Type.object);
        foreach (field; ["c", "command", "n", "nick", "x", "text", "ch", "channel", "m",
                "msgid", "i", "id", "l", "label", "le", "eo", "ct", "ctcp", "hm", "hostmask"])
            require(payload[field].type == Json.Type.undefined || payload[field].type == Json.Type.string);
        foreach (field; ["p", "params"]) {
            const params = payload[field];
            require(params.type == Json.Type.undefined || params.type == Json.Type.array);
            if (params.type == Json.Type.array)
                foreach (value; params) require(value.type == Json.Type.string);
        }
        const tags = payload["tags"];
        require(tags.type == Json.Type.undefined || tags.type == Json.Type.object);
        if (tags.type == Json.Type.object) foreach (field; ["edit_of", "ctcp"])
            require(tags[field].type == Json.Type.undefined || tags[field].type == Json.Type.string);
        if (has(doc, "msgid")) require(doc["msgid"].type == Bson.Type.string);
        if (row.classification.kind == SearchKind.skip) {
            const command = payload["c"].type == Json.Type.string ? payload["c"] : payload["command"];
            require(command.type != Json.Type.string || command.get!string != "REDACT");
            require(payload["eo"].type != Json.Type.string || !payload["eo"].get!string.length);
            if (tags.type == Json.Type.object)
                require(tags["edit_of"].type != Json.Type.string || !tags["edit_of"].get!string.length);
        }
    }

    private static void validateClassification(Bson doc, SearchRow row) {
        require(integer(doc, "searchVersion") == MESSAGE_SEARCH_VERSION);
        const kind = row.classification.kind;
        const expected = kind == SearchKind.message ? "message" : kind == SearchKind.edit ? "edit"
            : kind == SearchKind.redact ? "redact" : "skip";
        require(text(doc, "searchKind") == expected);
        if (kind == SearchKind.message) {
            require(doc["searchAliases"].type == Bson.Type.array);
            size_t index;
            foreach (value; doc["searchAliases"]) {
                require(index < row.classification.aliases.length && value.type == Bson.Type.string
                    && value.get!string == row.classification.aliases[index]);
                index++;
            }
            require(index == row.classification.aliases.length);
        } else if (kind == SearchKind.edit || kind == SearchKind.redact)
            require(text(doc, "searchTarget") == row.classification.target);
        require(kind == SearchKind.message || !has(doc, "searchAliases"));
        require(kind == SearchKind.edit || kind == SearchKind.redact || !has(doc, "searchTarget"));
    }
    private static bool has(Bson doc, string field) {
        if (doc.type != Bson.Type.object) return false;
        foreach (key, value; doc.byKeyValue) if (key == field) return true;
        return false;
    }
    private static string text(Bson doc, string key) { return doc[key].type == Bson.Type.string ? doc[key].get!string : ""; }
    private static long integer(Bson doc, string key) {
        const value = doc[key];
        require(value.type == Bson.Type.long_ || value.type == Bson.Type.int_);
        return value.type == Bson.Type.long_ ? value.get!long : value.get!int;
    }
    private static void account(ref size_t bytes, Bson doc) {
        require(doc.data.length <= maxBytes - bytes); bytes += doc.data.length;
    }
    private static void require(bool condition) {
        if (!condition) throw new Exception("History suppression unavailable");
    }
}
