module ircfiber.irc.history_recovery;


/// Admission, not a claim that the server has supplied a complete page.
enum HistoryRequestResult { sent, queued, unsupported, invalid }


/// Socket state lives in the connection; transfer records live in session_snapshot.
/// The template keeps the protocol state machine beside its batch/recovery invariants.
mixin template HistoryRecoveryMixin() {
    import std.algorithm : canFind, min, max, map, remove;
    import std.array : appender, array;
    import std.conv : to;
    import std.datetime : Clock;
    import std.string : split, startsWith, toUpper;
    import std.uuid : randomUUID;
    import vibe.data.json : Json, parseJsonString;
    import vibe.core.log : logWarn;
    import ircfiber.models.irc_event : IRCRawEvent;
    import ircfiber.redis.protocol : RedisKeys;
    import ircfiber.engine.session_snapshot;
    import ircfiber.irc.chathistory : buildChathistoryLine, isoTimestampMs, parseIsoTimestampMs;
    import ircfiber.irc.parser : parseBatchOpen, parseBatchClose;

    private struct ReplayContext {
        bool historical;
        string historyBatchRef;
        string target;
        string label;
        bool contextMessage;
    }
    private struct OpenBatch {
        string type, target, label, parent, historyBatchRef, requestId;
        bool historical, contextMessage, quarantined;
        long openedAtMs, bufferedBytes, payloadBytes;
        int segments;
        string cmd;
        IRCRawEvent first;
        string[] lines;
        bool[] concat;
    }
    private OpenBatch[string] openBatches;
    private bool batchAncestryCompromised;
    private long bufferedMultilineBytes;
    private HistoryRecovery[string] historyRecovery;
    private HistoryPageSnapshot[string] historyPages;
    private PendingHistoryRequest[] historyManualQueue, historyAutomaticQueue;
    private bool historyLastAutomatic;
    private bool[string] historyDirty;
    private string[] historyDiscoverySeen;
    private bool historyDiscoveryOverlap;
    private long[string] historyRetryAt;
    private bool historyRestoreFailed;

    private long historyNowMs() { return Clock.currTime.toUnixTime!long * 1000; }
    private string historyKey(string target) { return target.length == 0 || target == "*targets" ? "*targets" : historyFold(target); }

    private void mergeCommittedHistoryCoverage(string key, HistoryRecovery recovery) {
        if (historyKey(recovery.target) != key) throw new Exception("History target mismatch");
        if (auto pending = key in historyRecovery) {
            // META carries gap intent, while Redis owns accepted page cursors.
            // A failed first page can leave only the pre-gap complete seed in
            // Redis after the closed request has disappeared from META.
            if ((pending.state == "recovering" || pending.state == "stalled")
                && (recovery.state == "complete" || recovery.state == "retention_exhausted")) {
                recovery.state = pending.state;
                recovery.reasonCode = pending.reasonCode;
            }
        }
        historyRecovery[key] = recovery;
    }

    private void restoreHistoryCoverage() {
        if (redis is null) return;
        try {
            auto values = redis.getDb().hgetAll!string(RedisKeys.historyRecovery(config.id.toString()));
            string key;
            bool field = true;
            foreach (value; values) {
                if (field) key = value;
                else {
                    auto recovery = historyRecoveryFromJSON(parseJsonString(value));
                    mergeCommittedHistoryCoverage(key, recovery);
                }
                field = !field;
            }
            if (!field) throw new Exception("Incomplete history hash");
            historyRestoreFailed = false;
        } catch (Exception) {
            historyRestoreFailed = true;
            logWarn("History coverage unavailable; recovery suspended for %s", config.name);
        }
    }

    public void flushHistoryCoverage() {
        if (redis is null || historyRestoreFailed) return;
        string[] saved;
        foreach (key, dirty; historyDirty) {
            if (!dirty) continue;
            if (auto recovery = key in historyRecovery) {
                try {
                    redis.getDb().hset(RedisKeys.historyRecovery(config.id.toString()), key,
                        historyRecoveryToJSON(*recovery).toString());
                    saved ~= key;
                } catch (Exception) { break; }
            }
        }
        foreach (key; saved) historyDirty.remove(key);
    }

    private void stallHistory(string requestId, string reason) {
        if (auto page = requestId in historyPages) {
            page.malformed = true;
            page.quarantined = true;
            auto recovery = historyRecovery.get(historyKey(page.request.target), HistoryRecovery.init);
            recovery.target = page.request.target.length ? page.request.target : "*targets";
            recovery.state = "stalled";
            recovery.reasonCode = reason;
            historyRecovery[historyKey(recovery.target)] = recovery;
            historyDirty[historyKey(recovery.target)] = true;
            historyRetryAt[historyKey(recovery.target)] = historyNowMs() + 60_000;
        }
    }

    private void quarantineBatch(string reference, string reason) {
        if (auto batch = reference in openBatches) {
            batch.quarantined = true;
            stallHistory(batch.requestId, reason);
        }
        // Propagate now: closing/removing the invalid ancestor cannot turn a child live.
        foreach (_; 0 .. 16) {
            bool changed;
            foreach (ref batch; openBatches) {
                if (batch.quarantined || batch.parent.length == 0) continue;
                if (auto parent = batch.parent in openBatches) {
                    if (parent.quarantined) {
                        batch.quarantined = true;
                        stallHistory(batch.requestId, reason);
                        changed = true;
                    }
                }
            }
            if (!changed) break;
        }
    }

    private ReplayContext replayContext(ref const IRCRawEvent event) {
        ReplayContext result;
        result.contextMessage = event.hasTag("draft/chathistory-context");
        result.label = event.getTag("label");
        string reference = event.getTag("batch");
        string[16] visited;
        size_t depth;
        while (reference.length) {
            if (depth == visited.length || visited[0 .. depth].canFind(reference)) {
                quarantineBatch(event.getTag("batch"), "batch_ancestry");
                result.historical = true;
                return result;
            }
            visited[depth++] = reference;
            auto batch = reference in openBatches;
            if (batch is null) {
                if (openBatches.length < 256) {
                    OpenBatch tombstone;
                    tombstone.quarantined = true;
                    tombstone.openedAtMs = historyNowMs();
                    openBatches[reference] = tombstone;
                } else batchAncestryCompromised = true;
                quarantineBatch(event.getTag("batch"), "batch_parent_missing");
                result.historical = true;
                return result;
            }
            if (batch.quarantined || batchAncestryCompromised) {
                result.historical = true;
                return result;
            }
            result.contextMessage = result.contextMessage || batch.contextMessage;
            if (!result.label.length) result.label = batch.label;
            if (batch.historical) {
                result.historical = true;
                result.historyBatchRef = batch.historyBatchRef;
                result.target = batch.target;
            }
            reference = batch.parent;
        }
        return result;
    }

    private bool replayQuarantined(ref const IRCRawEvent event) {
        const reference = event.getTag("batch");
        if (!reference.length) return false;
        if (batchAncestryCompromised) return true;
        if (auto batch = reference in openBatches) return batch.quarantined;
        return true;
    }

    private string historyRequestForLabel(string label) {
        if (!label.length) return "";
        foreach (id, ref page; historyPages)
            if (page.label == label && page.request.connectionEpoch == connectionEpoch) return id;
        return "";
    }

    private string matchHistoryBatch(string target, string label) {
        if (label.length) return historyRequestForLabel(label);
        string result;
        foreach (id, ref page; historyPages) {
            if (page.label.length || page.awaitingCommit || page.request.batchRef.length) continue;
            if (historyKey(page.request.target) != historyKey(target)) continue;
            if (result.length) return "";
            result = id;
        }
        return result;
    }

    private bool handleReplayBatch(IRCRawEvent event, ReplayContext inherited) {
        if (event.command != "BATCH") return false;
        string reference, type, target;
        const params = event.getParams();
        if (parseBatchOpen(params, reference, type, target)) {
            if (reference in openBatches) { quarantineBatch(reference, "batch_duplicate"); return true; }
            if (openBatches.length >= 256) { batchAncestryCompromised = true; return true; }
            OpenBatch batch;
            batch.type = type;
            batch.parent = event.getTag("batch");
            batch.target = inherited.target.length ? inherited.target : target;
            batch.label = inherited.label;
            batch.historical = inherited.historical || type == "chathistory" || type == "draft/chathistory-targets";
            batch.historyBatchRef = inherited.historyBatchRef.length ? inherited.historyBatchRef : (batch.historical ? reference : "");
            batch.contextMessage = inherited.contextMessage;
            batch.quarantined = replayQuarantined(event) || batchAncestryCompromised;
            batch.openedAtMs = historyNowMs();
            if (auto parent = batch.parent in openBatches) batch.requestId = parent.requestId;
            if (!batch.requestId.length) batch.requestId = historyRequestForLabel(batch.label);
            if (batch.historical && !batch.requestId.length) batch.requestId = matchHistoryBatch(target, batch.label);
            if (batch.historical && batch.quarantined && !batch.requestId.length) {
                // Broken ancestry cannot prove that a concurrent empty root is
                // complete. Keep its target's coverage at the committed bound.
                foreach (id, ref page; historyPages)
                    if (historyKey(page.request.target) == historyKey(batch.target))
                        stallHistory(id, "batch_ancestry");
            }
            openBatches[reference] = batch;
            if (auto page = batch.requestId in historyPages) {
                page.request.lastActivityMs = historyNowMs();
                if (!page.request.batchRef.length) page.request.batchRef = reference;
                if (type == "chathistory" || type == "draft/chathistory-targets") page.historySeen = true;
                if (event.hasTag("draft/chathistory-end")) page.endReceived = true;
                if (batch.quarantined) stallHistory(batch.requestId, "batch_ancestry");
            }
        } else if (parseBatchClose(params, reference)) {
            auto found = reference in openBatches;
            if (found is null) return true;
            auto batch = *found;
            // Resolve the complete inherited context while every ancestor still exists.
            auto member = event;
            member.addTag("batch", reference);
            auto context = replayContext(member);
            bool hasChildren;
            foreach (childRef, ref child; openBatches) {
                if (child.parent == reference) {
                    hasChildren = true;
                    quarantineBatch(childRef, "batch_parent_closed");
                }
            }
            if (hasChildren) { quarantineBatch(reference, "batch_parent_closed"); batch.quarantined = true; }
            bufferedMultilineBytes -= batch.bufferedBytes;
            openBatches.remove(reference);
            if (event.hasTag("draft/chathistory-end"))
                if (auto page = batch.requestId in historyPages) page.endReceived = true;
            if (!batch.quarantined && batch.type == "draft/multiline" && batch.lines.length) {
                auto output = appender!string();
                output.reserve(cast(size_t) batch.bufferedBytes);
                foreach (i, line; batch.lines) {
                    if (i && !batch.concat[i]) output.put('\n');
                    output.put(line);
                }
                auto merged = batch.first;
                auto mp = merged.getParams();
                if (mp.length) mp[$ - 1] = output.data;
                merged.paramsJson = Json(mp.map!(p => Json(p)).array).toString();
                merged.text = output.data;
                merged.addTag("batch", batch.parent);
                if (context.label.length) merged.addTag("label", context.label);
                if (!accumulateReplayMultiline(merged, batch.segments, batch.payloadBytes)) {
                    const previousMerge = inMultilineMerge;
                    inMultilineMerge = true;
                    scope (exit) inMultilineMerge = previousMerge;
                    if (context.historical) processHistoricalEvent(merged, context);
                    else processEvent(merged);
                }
            }
            if (batch.type == "labeled-response" && batch.label.length) clearPendingLabel(batch.label);
            if (auto page = batch.requestId in historyPages) {
                page.request.lastActivityMs = historyNowMs();
                if (page.request.batchRef == reference) finishHistoryPage(batch.requestId);
            }
        }
        return true;
    }

    private bool accumulateReplayMultiline(IRCRawEvent event, int segments = 1, long payloadBytes = -1) {
        if (event.command != "PRIVMSG" && event.command != "NOTICE") return false;
        auto batch = event.getTag("batch") in openBatches;
        if (batch is null || batch.type != "draft/multiline") return false;
        if (batch.quarantined) return true;
        auto limits = multilineLimits();
        const bytes = cast(long) event.text.length;
        const newLines = batch.segments + segments;
        const newBytes = batch.payloadBytes + (payloadBytes < 0 ? bytes : payloadBytes);
        if (bufferedMultilineBytes + bytes + 1 > 1_048_576
            || (limits.maxLines > 0 && newLines > limits.maxLines)
            || (limits.maxBytes > 0 && newBytes > limits.maxBytes)) {
            quarantineBatch(event.getTag("batch"), "multiline_limit");
            return true;
        }
        if (event.getParams().length < 2) {
            quarantineBatch(event.getTag("batch"), "multiline_target");
            return true;
        }
        if (batch.lines.length == 0) { batch.first = event; batch.cmd = event.command; }
        else if (batch.cmd != event.command || batch.first.prefix != event.prefix
            || batch.first.getParams()[0] != event.getParams()[0]) {
            quarantineBatch(event.getTag("batch"), "multiline_identity");
            return true;
        }
        batch.lines ~= event.text;
        batch.concat ~= event.hasTag("draft/multiline-concat");
        batch.segments = newLines;
        batch.payloadBytes = newBytes;
        batch.bufferedBytes += bytes + 1;
        bufferedMultilineBytes += bytes + 1;
        if (auto page = batch.requestId in historyPages) page.request.lastActivityMs = historyNowMs();
        return true;
    }

    private HistoryCursor historyCursor(ref const IRCRawEvent event) {
        HistoryCursor cursor;
        cursor.msgid = event.getTag("msgid");
        const serverTime = parseIsoTimestampMs(event.getTag("time"));
        cursor.hasServerTime = serverTime > 0;
        if (cursor.hasServerTime) cursor.timestampMs = serverTime;
        return cursor;
    }

    private void processHistoricalEvent(IRCRawEvent event, ReplayContext replay) {
        // Control/privacy interception also runs before the live path invokes this method.
        if (observeHistoryTargets(event, replay)) return;
        if (interceptFiberMls(event)) return;
        if (services.interceptNative(event, true, lineFromBacklog)) return;
        if (services.intercept(event, true)) return;
        if (!replay.target.length || replayQuarantined(event)) return;
        if (event.command == "TAGMSG" && (event.hasTag("+typing") || event.hasTag("+draft/typing"))) return;
        if ((event.command == "PRIVMSG" || event.command == "NOTICE")
            && event.text.length && event.text[0] == '\x01'
            && !(event.text.startsWith("\x01ACTION ") && event.text[$ - 1] == '\x01')) return;
        event.channel = replay.target;
        if (event.command == "NOTICE") resolveConversation(event);
        event.addTag("batch", "chathistory");
        if (replay.contextMessage) event.addTag("draft/chathistory-context", "");
        if (replay.label.startsWith("hist-") || replay.label.startsWith("bnc-")) event.addTag("label", "");
        else if (replay.label.length) event.addTag("label", replay.label);
        const edit = event.getTag("+draft/edit");
        if (edit.length) event.addTag("edit_of", edit);
        string requestId;
        if (auto batch = replay.historyBatchRef in openBatches) requestId = batch.requestId;
        if (auto page = requestId in historyPages) {
            page.request.lastActivityMs = historyNowMs();
            event.addTag("history_request", requestId);
            event.addTag("history_epoch", page.request.connectionEpoch);
            if (!replay.contextMessage) {
                const cursor = historyCursor(event);
                if (page.ordinaryCount == 0) {
                    page.first = cursor;
                    page.proposed.boundaryOverlapMs = 0;
                } else if (cursor.hasServerTime && page.first.hasServerTime
                    && cursor.timestampMs > page.first.timestampMs
                    && (!page.proposed.boundaryOverlapMs || cursor.timestampMs < page.proposed.boundaryOverlapMs))
                    page.proposed.boundaryOverlapMs = cursor.timestampMs;
                page.last = cursor;
                if (cursor.msgid.length && cursor.msgid == page.proposed.lowerBound.msgid)
                    page.lowerBoundSeen = true;
                ++page.ordinaryCount;
                if (!cursor.msgid.length && !cursor.hasServerTime) stallHistory(requestId, "missing_reference");
            }
        }
        if ((event.command == "PRIVMSG" || event.command == "NOTICE") && event.getTag("msgid").length)
            recordChannelMsgid(event.channel, event.getTag("msgid"), event.timestampMs);
        eventChannel.put(event);
    }

    private int historyLimit(int requested) {
        int limit = requested > 0 ? min(requested, 1000) : 100;
        if (auto maximum = "CHATHISTORY" in isupportMap) {
            try { const n = (*maximum).to!int; if (n > 0) limit = min(limit, n); }
            catch (Exception) {}
        }
        return limit;
    }

    private bool historyMsgids() {
        if (auto types = "MSGREFTYPES" in isupportMap) return (*types).split(",").canFind("msgid");
        return true;
    }

    private string historyBeforeSelector(ref const HistoryRecovery recovery) {
        const cursor = recovery.nextBefore;
        if (cursor.msgid.length && historyMsgids() && !recovery.timestampFallback)
            return "msgid=" ~ cursor.msgid;
        if (!cursor.hasServerTime || cursor.timestampMs <= 0) return "";
        // BEFORE is exclusive: overlap toward NEWER rows, never skip older rows.
        const upper = recovery.boundaryOverlapMs > cursor.timestampMs
            ? recovery.boundaryOverlapMs : cursor.timestampMs + 10_000;
        return "timestamp=" ~ isoTimestampMs(upper);
    }

    private string historyTargetsSelector(ref const HistoryRecovery recovery) {
        const lower = recovery.nextBefore.hasServerTime
            ? (recovery.boundaryOverlapMs > 0 && recovery.boundaryOverlapMs < recovery.nextBefore.timestampMs
                ? recovery.boundaryOverlapMs : max(1, recovery.nextBefore.timestampMs - 10_000))
            : max(1, recovery.lowerBound.timestampMs - 10_000);
        return "timestamp=" ~ isoTimestampMs(lower)
            ~ ",timestamp=" ~ isoTimestampMs(recovery.discoveryUpperBoundMs);
    }

    public HistoryRequestResult requestChathistory(string target, string command, string selector, int limit) {
        command = command.toUpper;
        if (!["LATEST", "BEFORE", "AFTER", "AROUND", "BETWEEN", "TARGETS"].canFind(command))
            return HistoryRequestResult.invalid;
        foreach (character; target)
            if (character <= ' ' || character == '\x7f') return HistoryRequestResult.invalid;
        foreach (character; selector)
            if (character <= ' ' || character == '\x7f') return HistoryRequestResult.invalid;
        if (target.startsWith(":")) return HistoryRequestResult.invalid;
        limit = historyLimit(limit);
        if (!historyMsgids()) selector = msgidRefAsTimestamp(historyKey(target), selector);
        if (buildChathistoryLine(command, target, selector, limit) is null) return HistoryRequestResult.invalid;
        if (!hasChathistoryCap()) return HistoryRequestResult.unsupported;
        PendingHistoryRequest request;
        request.requestId = randomUUID().toString();
        request.target = target;
        request.command = command;
        request.selector = selector;
        request.effectiveLimit = limit;
        historyManualQueue ~= request;
        drainHistoryQueue();
        return request.requestId in historyPages ? HistoryRequestResult.sent : HistoryRequestResult.queued;
    }

    public bool isChathistoryInFlight(string target) {
        foreach (ref page; historyPages)
            if (!page.quarantined && historyKey(page.request.target) == historyKey(target)) return true;
        return false;
    }

    private void queueAutomaticHistory(string target, string command, string selector) {
        foreach (ref request; historyAutomaticQueue)
            if (historyKey(request.target) == historyKey(target)) return;
        foreach (ref page; historyPages)
            if (page.request.automaticRecovery && historyKey(page.request.target) == historyKey(target)) return;
        PendingHistoryRequest request;
        request.requestId = randomUUID().toString();
        request.target = target == "*targets" ? "" : target;
        request.command = command;
        request.selector = selector;
        request.effectiveLimit = historyLimit(100);
        request.automaticRecovery = true;
        historyAutomaticQueue ~= request;
    }

    private void drainHistoryQueue() {
        if (!hasChathistoryCap() || historyRestoreFailed || !connectionEpoch.length) return;
        // A single outstanding response is deliberately conservative on unlabelled servers.
        if (historyPages.length || (!historyManualQueue.length && !historyAutomaticQueue.length)) return;
        const automatic = historyAutomaticQueue.length && (!historyManualQueue.length || !historyLastAutomatic);
        auto request = automatic ? historyAutomaticQueue[0] : historyManualQueue[0];
        if (automatic) historyAutomaticQueue = historyAutomaticQueue[1 .. $];
        else historyManualQueue = historyManualQueue[1 .. $];
        historyLastAutomatic = automatic;
        request.connectionEpoch = connectionEpoch;
        request.sentAtMs = request.lastActivityMs = historyNowMs();
        HistoryPageSnapshot page;
        page.request = request;
        page.proposed = historyRecovery.get(historyKey(request.target), HistoryRecovery.init);
        page.proposed.target = request.target.length ? request.target : "*targets";
        string line = buildChathistoryLine(request.command, request.target, request.selector, request.effectiveLimit);
        if (hasCap("labeled-response") && hasCap("batch")) {
            page.label = "hist-" ~ request.requestId;
            line = "@label=" ~ page.label ~ " " ~ line;
        }
        historyPages[request.requestId] = page;
        sendRaw(line);
    }

    private void beginTargetRecovery(string target) {
        if (!target.length || target == "*targets") return;
        const key = historyKey(target);
        auto recovery = historyRecovery.get(key, HistoryRecovery.init);
        if (recovery.state == "recovering" || recovery.state == "stalled" || recovery.state == "unavailable") return;
        recovery.target = target;
        // Freeze completed coverage before any newly accepted live row may advance it.
        recovery.nextBefore = HistoryCursor.init;
        recovery.state = "recovering";
        recovery.reasonCode = "";
        historyRecovery[key] = recovery;
        historyDirty[key] = true;
        if (!channelTypes().canFind(target[0])) {
            bool exists;
            foreach (query; queryBuffers) if (historyKey(query) == key) { exists = true; break; }
            if (!exists) { queryBuffers ~= target; metaDirty = true; }
        }
        queueAutomaticHistory(target, "LATEST", "");
    }

    private void startHistoryRecovery() {
        if (!hasChathistoryCap() || historyRestoreFailed) return;
        foreach (key, ref recovery; historyRecovery) {
            if (key == "*targets" || recovery.state == "unavailable") continue;
            recovery.state = "recovering";
            recovery.reasonCode = "";
            recovery.nextBefore = HistoryCursor.init;
            queueAutomaticHistory(recovery.target, "LATEST", "");
        }
        foreach (query; queryBuffers) beginTargetRecovery(query);
        foreach (channel; config.autoJoinChannels) beginTargetRecovery(channel);
        const now = historyNowMs();
        auto discovery = historyRecovery.get("*targets", HistoryRecovery.init);
        discovery.target = "*targets";
        discovery.state = "recovering";
        discovery.reasonCode = "";
        discovery.nextBefore = HistoryCursor.init;
        discovery.discoveryUpperBoundMs = now + 10_000;
        historyRecovery["*targets"] = discovery;
        historyDiscoverySeen = null;
        historyDiscoveryOverlap = false;
        queueAutomaticHistory("", "TARGETS",
            "timestamp=" ~ isoTimestampMs(max(1, discovery.lowerBound.timestampMs - 10_000))
            ~ ",timestamp=" ~ isoTimestampMs(discovery.discoveryUpperBoundMs));
        drainHistoryQueue();
    }

    private bool observeHistoryTargets(IRCRawEvent event, ReplayContext replay) {
        if (event.command != "CHATHISTORY") return false;
        auto params = event.getParams();
        if (params.length != 3 || params[0] != "TARGETS") return false;
        auto batch = replay.historyBatchRef in openBatches;
        if (batch is null) return true;
        auto page = batch.requestId in historyPages;
        if (page is null || page.request.command != "TARGETS" || page.quarantined) return true;
        const stamp = parseIsoTimestampMs(params[2]);
        if (!stamp || !params[1].length) { stallHistory(batch.requestId, "targets_reference"); return true; }
        HistoryCursor cursor;
        cursor.timestampMs = stamp;
        cursor.hasServerTime = true;
        if (!page.ordinaryCount) {
            page.first = cursor;
            page.proposed.boundaryOverlapMs = 0;
        } else if (stamp > page.last.timestampMs)
            page.proposed.boundaryOverlapMs = page.last.timestampMs;
        page.last = cursor;
        ++page.ordinaryCount;
        page.request.lastActivityMs = historyNowMs();
        const key = historyKey(params[1]);
        if (!historyDiscoverySeen.canFind(key)) {
            historyDiscoverySeen ~= key;
            beginTargetRecovery(params[1]);
        }
        return true;
    }

    private void finishHistoryPage(string requestId) {
        auto page = requestId in historyPages;
        if (page is null || page.awaitingCommit) return;
        if (page.malformed || page.quarantined || !page.historySeen) {
            stallHistory(requestId, page.historySeen ? "malformed_page" : "missing_history_batch");
            // A correlated close drains the ambiguous response; a timed-out open response does not.
            historyPages.remove(requestId);
            drainHistoryQueue();
            return;
        }
        auto proposed = page.proposed;
        proposed.target = page.request.target.length ? page.request.target : "*targets";
        if (!page.request.automaticRecovery) {
            // A manual page must be persisted before releasing another request, but cannot
            // replace an automatic coverage cursor with an unrelated user-selected window.
            proposed = historyRecovery.get(historyKey(proposed.target), proposed);
            if (!proposed.state.length) proposed.state = "complete";
        } else if (page.request.command == "TARGETS") {
            const exhausted = page.endReceived || page.ordinaryCount == 0;
            if (exhausted) {
                proposed.state = "complete";
                proposed.nextBefore = HistoryCursor.init;
            } else {
                if (proposed.nextBefore.hasServerTime && page.last.timestampMs <= proposed.nextBefore.timestampMs) {
                    stallHistory(requestId, "timestamp_boundary");
                    historyPages.remove(requestId);
                    drainHistoryQueue();
                    return;
                }
                proposed.nextBefore = page.last;
                proposed.state = "recovering";
            }
        } else {
            if (page.request.command == "LATEST" && page.ordinaryCount) proposed.upperBound = page.last;
            const fresh = !proposed.lowerBound.msgid.length && !proposed.lowerBound.hasServerTime;
            const crossed = page.first.hasServerTime && proposed.lowerBound.hasServerTime
                && page.first.timestampMs <= proposed.lowerBound.timestampMs - 10_000;
            const exactCrossed = !proposed.lowerBound.hasServerTime && page.lowerBoundSeen;
            if (fresh || crossed || exactCrossed || page.endReceived || page.ordinaryCount == 0) {
                proposed.state = !fresh && !crossed && !exactCrossed && (page.endReceived || page.ordinaryCount == 0)
                    ? "retention_exhausted" : "complete";
                // The latest page established the high-water mark; BEFORE pages must not lower it.
                if (proposed.upperBound.msgid.length || proposed.upperBound.hasServerTime)
                    proposed.lowerBound = proposed.upperBound;
                proposed.nextBefore = HistoryCursor.init;
            } else {
                if ((!historyMsgids() || !page.first.msgid.length) && page.first.hasServerTime
                    && page.first.timestampMs == page.last.timestampMs
                    && page.ordinaryCount >= page.request.effectiveLimit) {
                    stallHistory(requestId, "timestamp_boundary");
                    logWarn("History recovery stalled at an unsplittable timestamp boundary for %s", config.name);
                    historyPages.remove(requestId);
                    drainHistoryQueue();
                    return;
                }
                if ((!historyMsgids() || proposed.timestampFallback || !page.first.msgid.length) && (!page.first.hasServerTime
                    || (proposed.nextBefore.hasServerTime && page.first.timestampMs >= proposed.nextBefore.timestampMs))) {
                    stallHistory(requestId, "timestamp_boundary");
                    historyPages.remove(requestId);
                    drainHistoryQueue();
                    return;
                }
                if (page.request.command == "LATEST") proposed.discoveryUpperBoundMs = page.last.timestampMs;
                proposed.nextBefore = page.first;
                proposed.state = "recovering";
            }
        }
        proposed.reasonCode = "";
        page.proposed = proposed;
        page.awaitingCommit = true;
        Json envelope = Json.emptyObject;
        envelope["requestId"] = requestId;
        envelope["connectionEpoch"] = page.request.connectionEpoch;
        envelope["target"] = proposed.target;
        envelope["recovery"] = historyRecoveryToJSON(proposed);
        IRCRawEvent checkpoint;
        checkpoint.network = config.name;
        checkpoint.networkId = config.id.toString();
        checkpoint.command = "HISTORY_CHECKPOINT";
        checkpoint.text = envelope.toString();
        eventChannel.put(checkpoint);
    }

    public bool ownsHistoryRequest(string requestId, string epoch) {
        auto page = requestId in historyPages;
        return page !is null && page.request.connectionEpoch == epoch && epoch == connectionEpoch;
    }

    public void failHistoryStorage(string requestId, string epoch) {
        if (ownsHistoryRequest(requestId, epoch)) stallHistory(requestId, "storage_failure");
    }

    // Runs on the single event-processor fiber. It must only mutate history
    // state: sending the next page can publish pacing logs into the bounded
    // channel this fiber is draining. The reader loop's tick dispatches queued work.
    public void confirmHistoryPage(string requestId, bool committed) {
        auto found = requestId in historyPages;
        if (found is null) return;
        auto page = *found;
        if (!committed || page.malformed || page.quarantined) {
            stallHistory(requestId, "storage_failure");
            historyPages.remove(requestId);
            return;
        }
        const key = historyKey(page.proposed.target);
        historyRecovery[key] = page.proposed;
        historyDirty.remove(key); // Processor has durably committed the dedicated hash.
        historyPages.remove(requestId);
        if (page.request.automaticRecovery) {
            if (page.request.command == "TARGETS") {
                if (page.proposed.state == "recovering") {
                    queueAutomaticHistory("", "TARGETS", historyTargetsSelector(page.proposed));
                } else if (!historyDiscoveryOverlap) {
                    historyDiscoveryOverlap = true;
                    auto discovery = page.proposed;
                    discovery.state = "recovering";
                    discovery.discoveryUpperBoundMs = historyNowMs() + 10_000;
                    discovery.nextBefore = HistoryCursor.init;
                    historyRecovery[key] = discovery;
                    queueAutomaticHistory("", "TARGETS",
                        "timestamp=" ~ isoTimestampMs(max(1, page.proposed.discoveryUpperBoundMs - 20_000))
                        ~ ",timestamp=" ~ isoTimestampMs(discovery.discoveryUpperBoundMs));
                } else {
                    historyRecovery[key].lowerBound.timestampMs = page.proposed.discoveryUpperBoundMs - 10_000;
                    historyRecovery[key].lowerBound.hasServerTime = true;
                    historyDirty[key] = true;
                }
            } else if (page.proposed.state == "recovering") {
                const selector = historyBeforeSelector(page.proposed);
                if (selector.length) queueAutomaticHistory(page.request.target, "BEFORE", selector);
                else {
                    historyRecovery[key].state = "stalled";
                    historyRecovery[key].reasonCode = "missing_reference";
                    historyDirty[key] = true;
                }
            }
        }
    }

    public void noteAcceptedLiveHistory(ref const IRCRawEvent event) {
        if (event.getTag("batch") == "chathistory" || !event.channel.length) return;
        if (event.command != "PRIVMSG" && event.command != "NOTICE") return;
        const cursor = historyCursor(event);
        if (!cursor.msgid.length && !cursor.hasServerTime) return;
        const key = historyKey(event.channel);
        auto recovery = historyRecovery.get(key, HistoryRecovery.init);
        if (recovery.state == "recovering" || recovery.state == "stalled") return;
        if (cursor.hasServerTime && recovery.lowerBound.hasServerTime
            && cursor.timestampMs < recovery.lowerBound.timestampMs) return;
        recovery.target = event.channel;
        recovery.state = "complete";
        recovery.reasonCode = "";
        recovery.lowerBound = cursor;
        historyRecovery[key] = recovery;
        historyDirty[key] = true;
    }

    private bool handleHistoryFailure(ref IRCRawEvent event) {
        if (event.command != "FAIL") return false;
        const params = event.getParams();
        if (params.length < 2 || params[0] != "CHATHISTORY") return false;
        string requestId = historyRequestForLabel(event.getTag("label"));
        if (!requestId.length) {
            foreach (id, ref page; historyPages) {
                if (page.label.length) continue;
                if (page.request.command == "TARGETS" && params[2 .. $].canFind("TARGETS")) requestId = id;
                foreach (param; params[2 .. $])
                    if (historyKey(param) == historyKey(page.request.target)) requestId = id;
            }
        }
        auto page = requestId in historyPages;
        if (page is null) return false;
        const key = historyKey(page.request.target);
        if (page.request.automaticRecovery && page.request.selector.startsWith("msgid=")
            && (params[1] == "INVALID_PARAMS" || params[1] == "INVALID_MSGID"
                || params[1] == "MSGID_EXPIRED")) {
            auto recovery = historyRecovery.get(key, HistoryRecovery.init);
            if (recovery.nextBefore.hasServerTime) {
                recovery.timestampFallback = true;
                historyRecovery[key] = recovery;
                historyDirty[key] = true;
                const target = page.request.target;
                historyPages.remove(requestId);
                queueAutomaticHistory(target, "BEFORE", historyBeforeSelector(recovery));
                drainHistoryQueue();
                return true;
            }
        }
        stallHistory(requestId, params[1] == "INVALID_TARGET" ? "invalid_target" : "server_failure");
        if (params[1] == "INVALID_TARGET") historyRecovery[key].state = "unavailable";
        historyPages.remove(requestId);
        drainHistoryQueue();
        return true;
    }

    private void tickHistoryRecovery() {
        const now = historyNowMs();
        string[] expiredLabeled;
        foreach (id, ref page; historyPages) {
            if (!page.awaitingCommit && !page.quarantined
                && (now - page.request.lastActivityMs >= 30_000 || now - page.request.sentAtMs >= 120_000))
                stallHistory(id, "response_timeout");
            if (page.quarantined && !page.awaitingCommit && page.label.length) expiredLabeled ~= id;
        }
        foreach (id; expiredLabeled) historyPages.remove(id);
        string[] retries;
        foreach (key, at; historyRetryAt) {
            if (now < at) continue;
            bool outstanding;
            foreach (ref page; historyPages)
                if (historyKey(page.request.target) == key) { outstanding = true; break; }
            if (outstanding || !hasChathistoryCap()) continue;
            if (auto recovery = key in historyRecovery) {
                if (recovery.state != "unavailable") {
                    recovery.state = "recovering";
                    recovery.reasonCode = "";
                    if (key == "*targets") {
                        if (recovery.discoveryUpperBoundMs <= 0) recovery.discoveryUpperBoundMs = now + 10_000;
                        queueAutomaticHistory("", "TARGETS", historyTargetsSelector(*recovery));
                    } else {
                        const selector = historyBeforeSelector(*recovery);
                        queueAutomaticHistory(recovery.target, selector.length ? "BEFORE" : "LATEST", selector);
                    }
                }
            }
            retries ~= key;
        }
        foreach (key; retries) historyRetryAt.remove(key);
        drainHistoryQueue();
    }

    private string historyFirstEventJson(ref IRCRawEvent event) {
        Json value = Json.emptyObject;
        value["command"] = event.command;
        value["prefix"] = event.prefix;
        value["nick"] = event.nick;
        value["hostmask"] = event.hostmask;
        value["paramsJson"] = event.paramsJson;
        value["tagsJson"] = event.tagsJson;
        value["timestampMs"] = event.timestampMs;
        value["text"] = event.text;
        value["id"] = event.id;
        return value.toString();
    }

    private IRCRawEvent historyFirstEvent(string encoded) {
        IRCRawEvent event;
        if (!encoded.length) return event;
        const value = parseJsonString(encoded);
        event.command = value["command"].get!string;
        event.prefix = value["prefix"].get!string;
        event.nick = value["nick"].get!string;
        event.hostmask = value["hostmask"].get!string;
        event.paramsJson = value["paramsJson"].get!string;
        event.tagsJson = value["tagsJson"].get!string;
        event.timestampMs = value["timestampMs"].get!long;
        event.text = value["text"].get!string;
        event.id = value["id"].get!string;
        event.network = config.name;
        event.networkId = config.id.toString();
        return event;
    }

    private void captureHistoryState(ref SessionSnapshot snapshot) {
        snapshot.historyRecovery = historyRecovery.dup;
        foreach (ref page; historyPages) snapshot.historyPages ~= page;
        snapshot.historyManualQueue = historyManualQueue.dup;
        snapshot.historyAutomaticQueue = historyAutomaticQueue.dup;
        snapshot.historyLastAutomatic = historyLastAutomatic;
        snapshot.historyDiscoverySeen = historyDiscoverySeen.dup;
        snapshot.historyDiscoveryOverlap = historyDiscoveryOverlap;
        foreach (reference, ref batch; openBatches) {
            OpenBatchSnapshot saved;
            saved.reference = reference;
            saved.type = batch.type;
            saved.target = batch.target;
            saved.label = batch.label;
            saved.parent = batch.parent;
            saved.historyBatchRef = batch.historyBatchRef;
            saved.requestId = batch.requestId;
            saved.historical = batch.historical;
            saved.contextMessage = batch.contextMessage;
            saved.quarantined = batch.quarantined;
            saved.openedAtMs = batch.openedAtMs;
            saved.bufferedBytes = batch.bufferedBytes;
            saved.payloadBytes = batch.payloadBytes;
            saved.segments = batch.segments;
            saved.command = batch.cmd;
            saved.firstEventJson = batch.lines.length ? historyFirstEventJson(batch.first) : "";
            saved.lines = batch.lines.dup;
            saved.concat = batch.concat.dup;
            snapshot.openBatches ~= saved;
        }
    }

    private void restoreHistoryState(ref SessionSnapshot snapshot) {
        historyRecovery = snapshot.historyRecovery.dup;
        // The ordered processor may have committed after META was captured.
        restoreHistoryCoverage();
        historyManualQueue = snapshot.historyManualQueue.dup;
        historyAutomaticQueue = snapshot.historyAutomaticQueue.dup;
        historyLastAutomatic = snapshot.historyLastAutomatic;
        historyDiscoverySeen = snapshot.historyDiscoverySeen.dup;
        historyDiscoveryOverlap = snapshot.historyDiscoveryOverlap;
        historyPages = null;
        foreach (saved; snapshot.historyPages) {
            auto page = saved;
            page.request.connectionEpoch = connectionEpoch;
            // Old queued rows have no verifiable storage verdict in this engine.
            // Drain retained ancestry/partial messages, then repeat from committed coverage.
            page.malformed = true;
            page.quarantined = true;
            page.awaitingCommit = false;
            historyPages[page.request.requestId] = page;
            if (!page.request.automaticRecovery) {
                auto retry = page.request;
                retry.requestId = randomUUID().toString();
                retry.batchRef = "";
                historyManualQueue ~= retry;
            }
        }
        openBatches = null;
        bufferedMultilineBytes = 0;
        batchAncestryCompromised = false;
        foreach (saved; snapshot.openBatches) {
            if (openBatches.length >= 256 || saved.lines.length != saved.concat.length) {
                batchAncestryCompromised = true;
                break;
            }
            OpenBatch batch;
            batch.type = saved.type;
            batch.target = saved.target;
            batch.label = saved.label;
            batch.parent = saved.parent;
            batch.historyBatchRef = saved.historyBatchRef;
            batch.requestId = saved.requestId;
            batch.historical = saved.historical;
            batch.contextMessage = saved.contextMessage;
            batch.quarantined = saved.quarantined;
            batch.openedAtMs = saved.openedAtMs;
            batch.bufferedBytes = saved.bufferedBytes;
            batch.payloadBytes = saved.payloadBytes;
            batch.segments = saved.segments;
            batch.cmd = saved.command;
            try batch.first = historyFirstEvent(saved.firstEventJson);
            catch (Exception) { batch.quarantined = true; }
            batch.lines = saved.lines.dup;
            batch.concat = saved.concat.dup;
            if (saved.reference in openBatches) batch.quarantined = true;
            openBatches[saved.reference] = batch;
            bufferedMultilineBytes += batch.bufferedBytes;
        }
        if (bufferedMultilineBytes > 1_048_576) batchAncestryCompromised = true;
        string[] alreadyClosed;
        foreach (id, ref page; historyPages) {
            if (!page.request.batchRef.length || page.request.batchRef !in openBatches) alreadyClosed ~= id;
            historyRetryAt[historyKey(page.request.target)] = historyNowMs();
        }
        foreach (id; alreadyClosed) historyPages.remove(id);
        foreach (key, ref recovery; historyRecovery) {
            if (key in historyRetryAt) continue;
            if (recovery.state == "stalled") historyRetryAt[key] = historyNowMs() + 60_000;
            else if (recovery.state == "recovering") historyRetryAt[key] = historyNowMs();
        }
    }

    private void resetHistorySocket() {
        foreach (ref page; historyPages) {
            if (!page.request.automaticRecovery) {
                auto request = page.request;
                request.requestId = randomUUID().toString();
                request.batchRef = "";
                historyManualQueue ~= request;
            }
        }
        historyPages = null;
        historyAutomaticQueue = null;
        openBatches = null;
        bufferedMultilineBytes = 0;
        batchAncestryCompromised = false;
    }
}
