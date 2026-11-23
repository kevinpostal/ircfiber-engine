module ircfiber.db.message_search_repository;

import core.time : MonoTime, seconds;
import std.algorithm : canFind, min, max, reverse;
import vibe.data.bson;
import vibe.db.mongo.mongo : MongoCollection;
import vibe.db.mongo.cursor : FindOptions;
import ircfiber.db.mongo : AppMongoConnection;
import ircfiber.db.messages : HistoryBoundary, MessageRepository, messageRetentionDays;
import ircfiber.db.message_search;
import ircfiber.models.network : normalizeChannelName;
import std.datetime : Clock;

/// Empty channel means all eligible channel buffers in this network, never DMs.
/// Callers must derive/authorize networks before constructing these scopes.
struct MessageSearchScope {
    string networkId;
    string channel;
}

enum MessageSearchEvidenceFailure { invalidScope, unclassified, limitExceeded }

/// Contains no source identifiers, nicknames, message text or storage errors.
final class MessageSearchEvidenceException : Exception {
    immutable MessageSearchEvidenceFailure reason;
    this(MessageSearchEvidenceFailure reason) {
        super("Message search evidence unavailable");
        this.reason = reason;
    }
}

struct MessageSearchContext {
    bool found;
    SearchResolution[] rows;
}

private struct EvidenceBudget {
    MonoTime deadline;
    size_t evidenceBytes;
    // Per-operation server time limit. Interactive reads stay at two seconds;
    // the background worker raises it for cold production archives.
    long opCapMs = 2_000;
    // Cumulative raw source bytes, including worker hints and repeated reads.
    // Row limits alone do not bound JSON payload/evidence memory.
    private enum size_t maxEvidenceBytes = 32 * 1024 * 1024;
    static EvidenceBudget start() {
        return EvidenceBudget(MonoTime.currTime + 5.seconds);
    }
    static EvidenceBudget startWorker() {
        return EvidenceBudget(MonoTime.currTime + 45.seconds, 0, 20_000);
    }
    long remainingMs() {
        const remaining = (deadline - MonoTime.currTime).total!"msecs";
        if (remaining <= 0)
            throw new MessageSearchEvidenceException(MessageSearchEvidenceFailure.limitExceeded);
        return min(remaining, opCapMs);
    }
    void account(Bson doc) {
        const bytes = doc.data.length;
        if (bytes > maxEvidenceBytes - evidenceBytes)
            throw new MessageSearchEvidenceException(MessageSearchEvidenceFailure.limitExceeded);
        evidenceBytes += bytes;
    }
}

/// Authoritative retained-history evidence, independent of the external index.
/// Queries never restrict serverId: an engine move does not change IRC identity.
final class MessageSearchRepository {
    private MongoCollection collection;
    private MongoCollection networks;
    private Bson sourceProjection;
    private enum size_t maxBatch = 250;
    private enum size_t maxWorkerBatch = 1_000;
    private enum size_t maxEvidence = 10_000;
    private enum size_t maxContextScan = 10_000;

    this() {
        collection = AppMongoConnection.getDb()["messages"];
        networks = AppMongoConnection.getDb()["networks"];
        sourceProjection = Bson.emptyObject;
        foreach (field; ["_id", "networkId", "channel", "t", "eid", "payload", "msgid",
                "searchVersion", "searchKind", "searchAliases", "searchTarget"])
            sourceProjection[field] = Bson(1);
    }

    /// Results align with requested IDs, including invisible entries for absent,
    /// expired, moved, ambiguous or deleted sources. Never trust index content.
    SearchResolution[] resolveByIds(string[] rowIds, MessageSearchScope[] scopes) @trusted {
        auto budget = EvidenceBudget.start();
        scopes = normalizedScopes(scopes);
        if (rowIds.length > maxBatch) fail(MessageSearchEvidenceFailure.limitExceeded);
        requireClassified(scopes, budget);
        auto docs = readIds(rowIds, scopes, budget);
        auto resolved = resolveDocuments(docs, scopes, budget);
        SearchResolution[string] byId;
        foreach (row; resolved) byId[row.original.rowId] = row;
        SearchResolution[] result;
        result.length = rowIds.length;
        foreach (i, id; rowIds) {
            if (auto value = id in byId) result[i] = *value;
            else result[i].original.rowId = id;
        }
        requireClassified(scopes, budget);
        return result;
    }

    /// Changed rows are hints, not trusted content. Re-read current source and
    /// resolve bases for old AND current targets/aliases, so rename/reclassification
    /// and an out-of-order mutation can repair previously materialized documents.
    /// Output is deduplicated by base storage ID; mutations are never hits.
    SearchResolution[] resolveChangedRows(Bson[] changedRows, MessageSearchScope[] scopes) @trusted {
        auto budget = EvidenceBudget.start();
        scopes = normalizedScopes(scopes);
        if (changedRows.length > maxBatch) fail(MessageSearchEvidenceFailure.limitExceeded);
        requireClassified(scopes, budget);
        string[] ids;
        foreach (doc; changedRows) {
            const id = stringField(doc, "_id");
            if (id.length && !ids.canFind(id)) ids ~= id;
        }
        auto current = readIds(ids, scopes, budget);
        string[][MessageSearchScope] aliases;
        string[] baseIds;
        Bson[][2] sources = [changedRows, current];
        foreach (source; sources) foreach (doc; source) {
            auto row = searchRow(doc);
            if (!allowed(row, scopes)) continue;
            if (row.classification.kind == SearchKind.message) {
                if (!baseIds.canFind(row.rowId)) baseIds ~= row.rowId;
                addAliases(aliases, row);
            } else if (row.classification.kind == SearchKind.edit
                    || row.classification.kind == SearchKind.redact) {
                addAlias(aliases, MessageSearchScope(row.networkId, row.channel), row.classification.target);
            }
        }
        auto owners = readRelated(aliases, false, budget);
        foreach (doc; owners) {
            const id = stringField(doc, "_id");
            if (id.length && !baseIds.canFind(id)) baseIds ~= id;
        }
        // The potentially large owner set is fetched in one batched query rather
        // than resolveByIds per owner. Preserve missing originals as delete hints.
        auto docs = readIds(baseIds, scopes, budget);
        auto result = resolveDocuments(docs, scopes, budget);
        bool[string] present;
        foreach (row; result) present[row.original.rowId] = true;
        foreach (id; baseIds) {
            if (id in present) continue;
            SearchResolution absent;
            absent.original.rowId = id;
            result ~= absent;
        }
        requireClassified(scopes, budget);
        return result;
    }

    /// Worker hints have a separate cap; public ID/context requests stay at 250.
    /// Only fresh Mongo rows become bases or evidence. The first owner lookup
    /// already supplies canonical sources and complete ownership for its aliases;
    /// query again only for aliases introduced by those owners.
    /// A supplied monotonic deadline is shared across caller-side partitions;
    /// it can shorten, but never extend, this invocation's five-second budget.
    SearchResolution[] resolveChangedRowsWorker(Bson[] changedRows,
            MessageSearchScope[] scopes, MonoTime deadline = MonoTime.init) @trusted {
        auto budget = EvidenceBudget.startWorker();
        if (deadline != MonoTime.init) budget.deadline = min(budget.deadline, deadline);
        budget.remainingMs();
        scopes = normalizedScopes(scopes);
        if (changedRows.length > maxWorkerBatch) fail(MessageSearchEvidenceFailure.limitExceeded);
        requireClassified(scopes, budget, true);
        string[] ids;
        bool[string] seenIds;
        foreach (doc; changedRows) {
            budget.account(doc);
            const id = stringField(doc, "_id");
            if (id.length && id !in seenIds) {
                seenIds[id] = true;
                ids ~= id;
            }
        }
        auto current = readIds(ids, scopes, budget);
        string[] baseIds;
        bool[string] seenBases;
        string[][MessageSearchScope] aliases;
        bool[ScopedAlias] seenAliases;
        SearchRow[string] canonical;
        void discover(SearchRow row) {
            if (!allowed(row, scopes)) return;
            const scope_ = MessageSearchScope(row.networkId, row.channel);
            if (row.classification.kind == SearchKind.message) {
                if (row.rowId !in seenBases) {
                    seenBases[row.rowId] = true;
                    baseIds ~= row.rowId;
                }
                foreach (name; row.classification.aliases)
                    addWorkerAlias(aliases, seenAliases, scope_, name);
            } else if (row.classification.kind == SearchKind.edit
                    || row.classification.kind == SearchKind.redact) {
                addWorkerAlias(aliases, seenAliases, scope_, row.classification.target);
            }
        }
        foreach (doc; changedRows) discover(searchRow(doc));
        foreach (doc; current) {
            // Validate every fresh source, including controls, before its
            // payload-derived aliases or target can select indexed evidence.
            auto row = checkedRow(doc);
            discover(row);
            const id = stringField(doc, "_id");
            canonical[id] = row;
        }
        SearchRow[string] evidence;
        foreach (doc; readWorkerAliases(aliases, false, budget)) {
            auto row = checkedRow(doc);
            if (row.classification.kind != SearchKind.message)
                fail(MessageSearchEvidenceFailure.unclassified);
            const id = stringField(doc, "_id");
            canonical[id] = row;
            evidence[id] = row;
            if (id !in seenBases) {
                seenBases[id] = true;
                baseIds ~= id;
            }
        }
        if (baseIds.length > maxEvidence) fail(MessageSearchEvidenceFailure.limitExceeded);
        SearchRow[] bases;
        bases.reserve(baseIds.length);
        string[][MessageSearchScope] baseAliases;
        bool[ScopedAlias] seenBaseAliases;
        string[][MessageSearchScope] missingAliases;
        string[] missingIds;
        foreach (id; baseIds) {
            auto row = id in canonical;
            if (!row) {
                missingIds ~= id;
                continue;
            }
            if (!allowed(*row, scopes)) {
                missingIds ~= id;
                continue;
            }
            bases ~= *row;
            if (row.classification.kind != SearchKind.message) continue;
            const scope_ = MessageSearchScope(row.networkId, row.channel);
            foreach (name; row.classification.aliases) {
                const key = ScopedAlias(scope_, name);
                if (key in seenBaseAliases) continue;
                addWorkerAlias(baseAliases, seenBaseAliases, scope_, name);
                if (key !in seenAliases) missingAliases[scope_] ~= name;
            }
        }
        foreach (doc; readWorkerAliases(missingAliases, false, budget)) {
            auto row = checkedRow(doc);
            if (row.classification.kind != SearchKind.message)
                fail(MessageSearchEvidenceFailure.unclassified);
            evidence[stringField(doc, "_id")] = row;
            if (evidence.length > maxEvidence) fail(MessageSearchEvidenceFailure.limitExceeded);
        }
        foreach (doc; readWorkerAliases(baseAliases, true, budget)) {
            auto row = checkedRow(doc);
            if (row.classification.kind != SearchKind.edit
                    && row.classification.kind != SearchKind.redact)
                fail(MessageSearchEvidenceFailure.unclassified);
            evidence[stringField(doc, "_id")] = row;
            if (evidence.length > maxEvidence) fail(MessageSearchEvidenceFailure.limitExceeded);
        }
        auto result = resolveWorkerBases(bases, evidence, seenBaseAliases, budget);
        foreach (id; missingIds) {
            SearchResolution absent;
            absent.original.rowId = id;
            result ~= absent;
        }
        requireClassified(scopes, budget, true);
        return result;
    }

    /// Each branch fixes the leading network/channel index keys and implies the
    /// existing partial index predicate. Never hint the mixed owner/control OR:
    /// a single partial index would silently omit the other kind of evidence.
    private Bson[] readWorkerAliases(string[][MessageSearchScope] aliases, bool mutations,
            ref EvidenceBudget budget) {
        Bson[] clauses;
        foreach (scope_, names; aliases) {
            if (!names.length) continue;
            auto filter = exactScopeFilter(scope_);
            filter[mutations ? "searchTarget" : "searchAliases"] =
                Bson(["$in": serializeToBson(names), "$exists": Bson(true)]);
            clauses ~= filter;
        }
        if (!clauses.length) return null;
        return read(Bson(["$or": Bson(clauses)]), maxEvidence, budget, Bson.init,
            mutations ? "message_search_target" : "message_search_alias");
    }

    /// Index evidence by exact scoped alias, not the whole channel. A reusable
    /// scratch slice and generation marks avoid allocating/deduplicating a new
    /// related-row array for every base, while preserving the pure resolver.
    private SearchResolution[] resolveWorkerBases(SearchRow[] bases,
            SearchRow[string] evidence, bool[ScopedAlias] wantedAliases,
            ref EvidenceBudget budget) {
        SearchRow[] rows;
        rows.reserve(evidence.length);
        size_t[][ScopedAlias] byAlias;
        foreach (row; evidence) {
            const index = rows.length;
            rows ~= row;
            const scope_ = MessageSearchScope(row.networkId, row.channel);
            if (row.classification.kind == SearchKind.message) {
                foreach (name; row.classification.aliases) {
                    const key = ScopedAlias(scope_, name);
                    if (key in wantedAliases) byAlias[key] ~= index;
                }
            } else if (row.classification.kind == SearchKind.edit
                    || row.classification.kind == SearchKind.redact) {
                const key = ScopedAlias(scope_, row.classification.target);
                if (key in wantedAliases) byAlias[key] ~= index;
            }
        }
        auto scratch = new SearchRow[rows.length];
        auto marks = new size_t[rows.length];
        SearchResolution[] result;
        result.reserve(bases.length);
        const oldest = Clock.currTime().toUnixTime!long * 1000
            - cast(long) messageRetentionDays() * 86_400_000;
        foreach (i, base; bases) {
            budget.remainingMs();
            size_t count;
            const scope_ = MessageSearchScope(base.networkId, base.channel);
            foreach (name; base.classification.aliases) {
                auto related = ScopedAlias(scope_, name) in byAlias;
                if (!related) continue;
                foreach (index; *related) {
                    if (marks[index] == i + 1) continue;
                    marks[index] = i + 1;
                    scratch[count++] = rows[index];
                }
            }
            auto resolved = resolveSearchMessage(base, scratch[0 .. count]);
            if (base.t <= oldest) resolved.visible = false;
            result ~= resolved;
        }
        return result;
    }

    /// Exact storage reference, not msgid/time inference. Fills each side after
    /// folding all scoped controls, including mutations outside the raw window.
    /// Exhausting the bounded evidence budget throws, never pretends an edge.
    MessageSearchContext getContext(string networkId, string channel, string rowId,
            int neighbors = 10) @trusted {
        if (neighbors < 0 || neighbors > 10 || !rowId.length || !channel.length)
            fail(MessageSearchEvidenceFailure.invalidScope);
        auto budget = EvidenceBudget.start();
        auto scopes = normalizedScopes([MessageSearchScope(networkId, channel)]);
        requireClassified(scopes, budget);
        auto docs = readIds([rowId], scopes, budget);
        auto centers = resolveDocuments(docs, scopes, budget);
        MessageSearchContext context;
        if (centers.length != 1 || !centers[0].visible) return context;
        auto center = centers[0];
        auto before = contextSide(center.original, scopes, neighbors, true, budget);
        auto after = contextSide(center.original, scopes, neighbors, false, budget);
        requireClassified(scopes, budget);
        context.found = true;
        context.rows = before;
        context.rows.reserve(before.length + 1 + after.length);
        context.rows ~= center;
        context.rows ~= after;
        return context;
    }

    /// Scope-wide mixed-writer gate. A single unclassified legacy REDACT must
    /// prevent any result, even when it is not among the index's candidate IDs.
    void requireClassified(MessageSearchScope[] scopes) @trusted {
        auto budget = EvidenceBudget.start();
        requireClassified(normalizedScopes(scopes), budget);
    }

    private void requireClassified(MessageSearchScope[] scopes, ref EvidenceBudget budget,
            bool worker = false) {
        auto filter = scopeFilter(scopes);
        filter["searchVersion"] = Bson(["$ne": Bson(cast(int) MESSAGE_SEARCH_VERSION)]);
        FindOptions mixedOptions;
        mixedOptions.limit = 1;
        mixedOptions.maxTimeMS = budget.remainingMs();
        mixedOptions.projection = Bson(["_id": Bson(1)]);
        if (worker) mixedOptions.hint = Bson("message_search_version");
        foreach (doc; collection.find(filter, mixedOptions))
            fail(MessageSearchEvidenceFailure.unclassified);
        // Orphaned network content is never searchable, even during rebuilding.
        string[] requested;
        foreach (scope_; scopes)
            if (!requested.canFind(scope_.networkId)) requested ~= scope_.networkId;
        FindOptions options;
        options.limit = cast(long) requested.length;
        options.maxTimeMS = budget.remainingMs();
        options.projection = Bson(["_id": Bson(0), "id": Bson(1)]);
        // Worker setup provisions this index; a missing hint must fail closed,
        // never fall back to scanning the networks collection.
        if (worker) options.hint = Bson("message_search_network_owner");
        bool[string] existing;
        foreach (doc; networks.find(Bson(["id": Bson(["$in": serializeToBson(requested)])]), options)) {
            const id = stringField(doc, "id");
            if (id.length) existing[id] = true;
        }
        foreach (id; requested)
            if (id !in existing) fail(MessageSearchEvidenceFailure.invalidScope);
    }

    private SearchResolution[] resolveDocuments(Bson[] docs, MessageSearchScope[] scopes,
            ref EvidenceBudget budget) {
        SearchRow[] bases;
        string[][MessageSearchScope] aliases;
        foreach (doc; docs) {
            auto row = checkedRow(doc);
            if (!allowed(row, scopes)) continue;
            bases ~= row;
            if (row.classification.kind == SearchKind.message) addAliases(aliases, row);
        }
        auto evidenceDocs = readRelated(aliases, true, budget);
        SearchRow[][MessageSearchScope] evidence;
        foreach (doc; evidenceDocs) {
            auto row = checkedRow(doc);
            if (row.rowId.length)
                evidence[MessageSearchScope(row.networkId, row.channel)] ~= row;
        }
        SearchResolution[] result;
        result.reserve(bases.length);
        const oldest = Clock.currTime().toUnixTime!long * 1000
            - cast(long) messageRetentionDays() * 86_400_000;
        foreach (base; bases) {
            budget.remainingMs();
            auto related = MessageSearchScope(base.networkId, base.channel) in evidence;
            auto resolved = resolveSearchMessage(base, related ? *related : null);
            // Mongo's TTL monitor is asynchronous; expired rows are already
            // unreadable even if their original document has not been removed.
            if (base.t <= oldest) resolved.visible = false;
            result ~= resolved;
        }
        return result;
    }

    private SearchResolution[] contextSide(SearchRow center, MessageSearchScope[] scopes,
            int wanted, bool older, ref EvidenceBudget budget) {
        SearchResolution[] rows;
        if (!wanted) return rows;
        auto edge = boundary(center);
        size_t scanned;
        while (rows.length < wanted) {
            auto filter = scopeFilter(scopes);
            filter["searchKind"] = Bson("message");
            filter["$and"] = Bson([MessageRepository.boundaryFilter(edge, !older)]);
            auto order = Bson.emptyObject;
            foreach (key; ["t", "eid", "_id"]) order[key] = Bson(older ? -1 : 1);
            auto docs = read(filter, maxBatch, budget, order);
            if (!docs.length) break;
            scanned += docs.length;
            if (scanned > maxContextScan) fail(MessageSearchEvidenceFailure.limitExceeded);
            auto candidates = resolveDocuments(docs, scopes, budget);
            foreach (candidate; candidates) {
                if (!candidate.visible) continue;
                rows ~= candidate;
                if (rows.length == wanted) break;
            }
            // Walk raw tuples, not the last displayable message: an invisible
            // stretch must not repeat forever or hide later eligible neighbors.
            auto last = searchRow(docs[$ - 1]);
            if (!last.rowId.length) fail(MessageSearchEvidenceFailure.unclassified);
            edge = boundary(last);
            if (docs.length < maxBatch) break;
        }
        if (older) rows.reverse;
        return rows;
    }

    private Bson[] readIds(string[] ids, MessageSearchScope[] scopes, ref EvidenceBudget budget) {
        if (!ids.length) return null;
        if (ids.length > maxEvidence) fail(MessageSearchEvidenceFailure.limitExceeded);
        auto filter = scopeFilter(scopes);
        filter["_id"] = Bson(["$in": serializeToBson(ids)]);
        return read(filter, maxEvidence, budget, Bson.init, "_id_");
    }

    /// One query for all scoped alias owners and mutations, not one per hit.
    private Bson[] readRelated(string[][MessageSearchScope] aliases, bool mutations,
            ref EvidenceBudget budget) {
        Bson[] clauses;
        foreach (scope_, names; aliases) {
            if (!names.length) continue;
            auto filter = exactScopeFilter(scope_);
            auto owners = Bson(["searchKind": Bson("message"),
                "searchAliases": Bson(["$in": serializeToBson(names)])]);
            if (mutations) {
                filter["$or"] = Bson([owners, Bson([
                    "searchKind": Bson(["$in": serializeToBson(["edit", "redact"])]),
                    "searchTarget": Bson(["$in": serializeToBson(names)])
                ])]);
            } else filter["$and"] = Bson([owners]);
            clauses ~= filter;
        }
        if (!clauses.length) return null;
        return read(Bson(["$or": Bson(clauses)]), maxEvidence, budget);
    }

    private Bson[] read(Bson filter, size_t limit, ref EvidenceBudget budget,
            Bson order = Bson.init, string hint = "") {
        FindOptions options;
        // Fetch one extra so bounded lookup cannot silently omit a tombstone.
        options.limit = cast(long) limit + 1;
        options.maxTimeMS = budget.remainingMs();
        options.projection = sourceProjection;
        if (hint.length) options.hint = Bson(hint);
        if (order.type != Bson.Type.undefined) options.sort = order;
        Bson[] result;
        foreach (doc; collection.find(filter, options)) {
            if (result.length == limit) {
                // Context pages deliberately continue with a strict tuple edge.
                if (limit == maxBatch && order.type != Bson.Type.undefined) break;
                fail(MessageSearchEvidenceFailure.limitExceeded);
            }
            budget.account(doc);
            result ~= doc;
        }
        return result;
    }
}

private MessageSearchScope[] normalizedScopes(MessageSearchScope[] scopes) {
    if (!scopes.length || scopes.length > 250) fail(MessageSearchEvidenceFailure.invalidScope);
    MessageSearchScope[] result;
    foreach (scope_; scopes) {
        if (!scope_.networkId.length) fail(MessageSearchEvidenceFailure.invalidScope);
        scope_.channel = normalizeChannelName(scope_.channel);
        if (scope_.channel.length && !isSearchChannel(scope_.channel))
            fail(MessageSearchEvidenceFailure.invalidScope);
        if (!result.canFind(scope_)) result ~= scope_;
    }
    return result;
}

private Bson exactScopeFilter(MessageSearchScope scope_) {
    return Bson(["networkId": Bson(scope_.networkId), "channel": Bson(scope_.channel)]);
}

private Bson scopeFilter(MessageSearchScope[] scopes) {
    Bson[] clauses;
    foreach (scope_; scopes) {
        auto clause = Bson(["networkId": Bson(scope_.networkId)]);
        clause["channel"] = scope_.channel.length ? Bson(scope_.channel)
            : Bson(["$regex": Bson(`^[#&+!]`)]);
        clauses ~= clause;
    }
    return Bson(["$or": Bson(clauses)]);
}

private bool allowed(SearchRow row, MessageSearchScope[] scopes) {
    if (!row.rowId.length || !isSearchChannel(row.channel)) return false;
    foreach (scope_; scopes)
        if (row.networkId == scope_.networkId && (!scope_.channel.length || row.channel == scope_.channel))
            return true;
    return false;
}

private struct ScopedAlias {
    MessageSearchScope scope_;
    string name;
}

private void addWorkerAlias(ref string[][MessageSearchScope] aliases,
        ref bool[ScopedAlias] seen, MessageSearchScope scope_, string name) {
    if (!name.length) return;
    const key = ScopedAlias(scope_, name);
    if (key in seen) return;
    seen[key] = true;
    aliases[scope_] ~= name;
}

private void addAlias(ref string[][MessageSearchScope] aliases, MessageSearchScope scope_, string alias_) {
    if (!alias_.length) return;
    auto existing = scope_ in aliases;
    if (!existing) aliases[scope_] = [alias_];
    else if (!(*existing).canFind(alias_)) *existing ~= alias_;
}

private void addAliases(ref string[][MessageSearchScope] aliases, SearchRow row) {
    foreach (alias_; row.classification.aliases)
        addAlias(aliases, MessageSearchScope(row.networkId, row.channel), alias_);
}

private SearchRow checkedRow(Bson doc) {
    auto row = searchRow(doc);
    checkMetadata(doc, row);
    return row;
}

private void checkMetadata(Bson doc, SearchRow row) {
    if (!row.rowId.length) {
        if (stringField(doc, "searchKind") != "skip")
            fail(MessageSearchEvidenceFailure.unclassified);
        return;
    }
    // Metadata selects batched evidence; any mismatch invalidates the request
    // rather than risking attachment to an unrelated event or missed deletion.
    if (number(doc["searchVersion"]) != MESSAGE_SEARCH_VERSION
            || stringField(doc, "searchKind") != kindName(row.classification.kind))
        fail(MessageSearchEvidenceFailure.unclassified);
    if (row.classification.kind == SearchKind.message) {
        if (doc["searchAliases"].type != Bson.Type.array)
            fail(MessageSearchEvidenceFailure.unclassified);
        const stored = doc["searchAliases"];
        size_t index;
        foreach (value; stored) {
            if (index >= row.classification.aliases.length || value.type != Bson.Type.string
                    || value.get!string != row.classification.aliases[index])
                fail(MessageSearchEvidenceFailure.unclassified);
            ++index;
        }
        if (index != row.classification.aliases.length)
            fail(MessageSearchEvidenceFailure.unclassified);
    } else if (row.classification.kind == SearchKind.edit || row.classification.kind == SearchKind.redact) {
        if (stringField(doc, "searchTarget") != row.classification.target)
            fail(MessageSearchEvidenceFailure.unclassified);
    }
}

private string kindName(SearchKind kind) {
    final switch (kind) {
        case SearchKind.message: return "message";
        case SearchKind.edit: return "edit";
        case SearchKind.redact: return "redact";
        case SearchKind.skip: return "skip";
    }
}

private HistoryBoundary boundary(SearchRow row) {
    return HistoryBoundary(row.t, row.eid, row.rowId, "", true, row.hasEid);
}

private string stringField(Bson doc, string key) {
    return doc[key].type == Bson.Type.string ? doc[key].get!string : "";
}

private long number(Bson value) {
    if (value.type == Bson.Type.long_) return value.get!long;
    if (value.type == Bson.Type.int_) return value.get!int;
    return -1;
}

private void fail(MessageSearchEvidenceFailure reason) {
    throw new MessageSearchEvidenceException(reason);
}
