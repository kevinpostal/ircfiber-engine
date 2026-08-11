module ircfiber.models.irc_event;

import std.datetime;
import vibe.data.json;

/// Raw IRC event
struct IRCRawEvent {
    /// The network name
    string network;
    /// The network ID
    string networkId;
    /// The timestamp in milliseconds
    long timestampMs;
    /// The IRC command
    string command;
    /// Serialized params array
    string paramsJson;
    /// The message prefix
    string prefix;
    /// Serialized tag data
    string tagsJson;
    /// The event ID
    string id;
    /// The channel name
    string channel;
    /// The message text
    string text;
    /// The sender nick
    string nick;
    /// The sender user@host (hostmask, without the nick!)
    string hostmask;
    /// Global sequential event ID (IRCCloud-style). Assigned by the
    /// engine via Redis INCR before processing. Every event has one —
    /// no phantom messages, no missing identifiers.
    long eid;
    
    /// Construct a new IRCRawEvent
    this(string network, string command) {
        this.network = network;
        this.command = command;
        this.timestampMs = Clock.currTime.toUnixTime!long * 1000;
        import std.uuid;
        this.id = randomUUID().toString();
        this.paramsJson = "[]";
        this.tagsJson = "{}";
    }
    
    /// Serialize to JSON
    Json toJson() const {
        return Json([
            "network": Json(network),
            "timestamp": Json(SysTime.fromUnixTime(timestampMs / 1000).toISOExtString()),
            "command": Json(command),
            "params": parseJsonString(paramsJson),
            "prefix": Json(prefix),
            "tags": parseJsonString(tagsJson),
            "id": Json(id),
            "channel": Json(channel),
            "text": Json(text),
            "nick": Json(nick)
        ]);
    }
    
    /// W1-T01: structured retry-status payload for the synthetic
    /// CONNECTION_RETRY_STATUS event. Populated by
    /// `makeConnectionRetryStatus` (as a JSON-encoded string) and
    /// serialised by `toCompactJson` as the top-level `rs` object
    /// (frontend reads it via `data.rs` in `messageHandler.ts`).
    /// Empty when this is not a CONNECTION_RETRY_STATUS event.
    ///
    /// Stored as `string` (not `Json`) because `vibe.core.channel.Channel`
    /// requires its payload type to satisfy `isWeaklyIsolated`, and
    /// `vibe.data.json.Json` contains internal pointers that fail that
    /// trait. Encoding at construction + decoding at toCompactJson
    /// time mirrors the existing `paramsJson` / `tagsJson` pattern.
    string retryStatusPayload;
    /// W1-T01: structured fail-info payload for the synthetic
    /// CONNECTION_FAIL event. Populated by `makeConnectionFail`
    /// (as a JSON-encoded string) and serialised by `toCompactJson`
    /// as the top-level `fi` object (frontend reads it via
    /// `data.fi`). Empty when this is not a CONNECTION_FAIL event.
    /// See `retryStatusPayload` for the string-vs-Json rationale.
    string failInfoPayload;

    /// Serialize to compact JSON
    Json toCompactJson() const {
        auto j = Json.emptyObject;
        j["network"] = network;
        j["nid"] = networkId;
        j["i"] = id;
        j["t"] = timestampMs;
        j["c"] = command;
        j["eid"] = eid;
        if (nick.length) j["n"] = nick;
        if (hostmask.length) j["hm"] = hostmask;
        if (text.length) j["x"] = text;
        if (channel.length) j["ch"] = channel;
        if (prefix.length) j["px"] = prefix;
        auto params = getParams();
        if (params.length) {
            auto arr = Json.emptyArray;
            foreach (p; params) arr ~= Json(p);
            j["p"] = arr;
        }
        auto msgid = getTag("msgid");
        j["m"] = Json(msgid.length > 0 ? msgid : id);
        auto label = getTag("label");
        if (label.length) j["l"] = Json(label);
        auto batch = getTag("batch");
        if (batch.length) j["batch"] = Json(batch);
        auto phase = getTag("phase");
        if (phase.length) j["phase"] = Json(phase);
        auto selfEcho = getTag("self_echo");
        if (selfEcho.length) j["se"] = Json(selfEcho);
        // IRCv3 typing indicator (message-tags ext): TAGMSG events carry
        // +typing=active|done. Ship the value so the frontend can clear
        // the indicator on `done` instead of treating every TAGMSG as
        // fresh activity (which kept "X is typing" alive for another
        // 6.5s after the other client stopped). The long-form `toJson`
        // already carries the full tag map; this covers the realtime
        // compact path only. Tag name keeps its `+` prefix verbatim
        // from the wire (see parser.d tag loop).
        auto typingTag = getTag("+typing");
        if (typingTag.length) j["typing"] = Json(typingTag);
        // W1-T08: temp_unavailable event carries countdown_ms + serverTs
        if (command == "temp_unavailable") {
            auto cd = getTag("countdown_ms");
            if (cd.length) j["cd"] = Json(cd);
            auto st = getTag("serverTs");
            if (st.length) j["st"] = Json(st);
        }
        // W1-T08: idle event carries since_ms
        if (command == "idle") {
            auto sm = getTag("since_ms");
            if (sm.length) j["s"] = Json(sm);
        }
        // W1-T01: structured retry / fail info payloads ride alongside
        // the base envelope as `rs` / `fi`. The frontend (Wave 2
        // messageHandler.ts) dispatches on the command name and reads
        // these nested objects directly. We store the payloads as
        // JSON-encoded strings (see retryStatusPayload / failInfoPayload
        // field docs) so the event is safe to pass across fibers via
        // vibe.core.channel.Channel — decoding here is a one-shot cost
        // and isolated to the compact-JSON serialisation path.
        if (command == "CONNECTION_RETRY_STATUS"
            && retryStatusPayload.length > 0) {
            j["rs"] = parseJsonString(retryStatusPayload);
        }
        if (command == "CONNECTION_FAIL"
            && failInfoPayload.length > 0) {
            j["fi"] = parseJsonString(failInfoPayload);
        }
        return j;
    }
    
    /// Set the params array
    void setParams(string[] p) {
        paramsJson = serializeToJson(p).toString();
    }
    
    /// Get the params array
    string[] getParams() const @safe {
        try {
            return deserializeJson!(string[])(parseJsonString(paramsJson));
        } catch (Exception e) {
            return [];
        }
    }

    /// Add a tag
    void addTag(string key, string value) {
        auto tags = parseJsonString(tagsJson);
        tags[key] = Json(value);
        tagsJson = tags.toString();
    }

    /// Get a tag value by key. Returns "" if not found.
    string getTag(string key) const @safe {
        try {
            auto tags = parseJsonString(tagsJson);
            if (tags.type == Json.Type.object && key in tags) {
                return tags[key].get!string;
            }
        } catch (Exception) {}
        return "";
    }

    /// Get the label tag (for labeled-response).
    string getLabel() const @safe {
        return getTag("label");
    }

    /// Get the msgid tag (for chathistory/msgid).
    string getMsgid() const @safe {
        return getTag("msgid");
    }

    /// Build a synthetic CONNECTED event (used by handoff adoption to
    /// signal the new engine that the connection is live).
    static IRCRawEvent makeConnected(string network, string networkId) {
        auto e = IRCRawEvent(network, "CONNECTED");
        e.networkId = networkId;
        e.text = "Connection adopted from previous engine";
        return e;
    }

    /// Build a synthetic DISCONNECTED event (used by handoff to
    /// surface failure of an adopted connection).
    static IRCRawEvent makeDisconnected(string network, string networkId, string reason) {
        auto e = IRCRawEvent(network, "DISCONNECTED");
        e.networkId = networkId;
        e.text = reason;
        return e;
    }

    /// Build a server-log progress entry that surfaces in the `_server`
    /// buffer. These are NOTICE-shaped events (no `nick`, `text` populated)
    /// tagged with a `phase` so the frontend can render them as part of
    /// the connection lifecycle timeline instead of as chat.
    ///
    /// Phase taxonomy used by the engine (matches what MessageRow.svelte
    /// renders as a "phase chip" next to the message body):
    ///
    ///   queued       — request accepted, waiting for the engine fiber
    ///   resolving    — DNS lookup in progress
    ///   connecting   — TCP connect attempt
    ///   tcp_open     — TCP socket open
    ///   tls          — TLS handshake in progress
    ///   tls_done     — TLS handshake complete
    ///   registering  — sending CAP LS / NICK / USER
    ///   caps         — IRCv3 capability negotiation
    ///   sasl         — SASL authentication
    ///   welcome      — RPL_WELCOME received, fully connected
    ///   info         — neutral notice (MOTD, etc.)
    ///   warn         — non-fatal anomaly (TLS fallback, etc.)
    ///   error        — fatal failure
    ///
    /// The frontend also uses `phase=warn|error` to tint the row.
    static IRCRawEvent makeServerLog(string network, string networkId, string phase, string text) {
        auto e = IRCRawEvent(network, "NOTICE");
        e.networkId = networkId;
        e.text = text;
        e.addTag("phase", phase);
        return e;
    }

    /// Build a synthetic ISUPPORT state event. Sent by the engine
    /// after the 005 reply stream completes so the frontend can render
    /// the categorised "Server features" panel from structured data
    /// rather than re-parsing raw 005 message text.
    ///
    /// The full feature map is serialised into the `text` field as
    /// JSON (`{"KEY":"VALUE", ...}` or empty `{}` for bare flags).
    /// The `command` is `"ISUPPORT"` so the frontend can dispatch
    /// on it without confusing the message with chat.
    static IRCRawEvent makeIsupport(
        string network,
        string networkId,
        const ref string[string] map,
    ) {
        import std.json : JSONValue, JSONOptions;
        auto e = IRCRawEvent(network, "ISUPPORT");
        e.networkId = networkId;
        auto j = Json.emptyObject;
        foreach (k, v; map) j[k] = Json(v);
        e.text = j.toString();
        return e;
    }

    /// Build a synthetic CONNECTION_RETRY_STATUS event. Emitted by the
    /// engine at every reconnect-loop cycle (connection.d around line 1595)
    /// AND at every `backoff.reset()` site with all-zero arguments so the
    /// frontend's `applyRetryStatus(networkId, null)` clears both
    /// `net.retryStatus` AND `net.failInfo` per plan W1-T01 B3.
    ///
    /// Wire shape (per plan contracts block):
    ///   `{c: "CONNECTION_RETRY_STATUS", rs: {attemptCount, nextRetryAtMs, delayMs}}`
    ///
    /// The frontend renders the ordinal "Nth attempt" label from
    /// `attemptCount` and the 1s countdown from `nextRetryAtMs`.
    /// All three fields are zero when emitted from a `backoff.reset()` site
    /// to signal "retry cleared" (the frontend nulls both `retryStatus`
    /// AND `failInfo` on receipt of zero values).
    static IRCRawEvent makeConnectionRetryStatus(
        string network,
        string networkId,
        int attemptCount,
        long nextRetryAtMs,
        long delayMs,
    ) {
        auto e = IRCRawEvent(network, "CONNECTION_RETRY_STATUS");
        e.networkId = networkId;
        auto rs = Json.emptyObject;
        rs["attemptCount"] = Json(attemptCount);
        rs["nextRetryAtMs"] = Json(nextRetryAtMs);
        rs["delayMs"] = Json(delayMs);
        // Encode to string immediately so the event stays safe to
        // pass across fibers (vibe.core.channel.Channel requires
        // isWeaklyIsolated payloads). toCompactJson decodes back to
        // a Json object at serialisation time.
        e.retryStatusPayload = rs.toString();
        return e;
    }

    /// Build a synthetic CONNECTION_FAIL event. Emitted by the engine's
    /// disconnect path (connection.d around line 1422-1431) so the
    /// frontend can render IRCCloud-style structured failure messages
    /// (renderReasons.ts in Wave 2) instead of the free-text
    /// `disconnectReason` legacy string.
    ///
    /// Wire shape (per plan contracts block, plan section C):
    ///   `{c: "CONNECTION_FAIL",
    ///     fi: {type, reason, killedReason, sslVerifyError: {type, error}}}`
    ///
    /// `sslVerifyError` MUST be a nested Json object when populated
    /// (NOT a flat pair) so the engine's FailInfo and the frontend's
    /// TS interface match byte-for-byte — see plan B2. Pass
    /// `Json.undefined` (the default) for non-SSL failures so the
    /// serialiser omits the field entirely and the TS `sslVerifyError?:`
    /// is undefined rather than null.
    static IRCRawEvent makeConnectionFail(
        string network,
        string networkId,
        string type_,
        string reason,
        string killedReason,
        Json sslVerifyError,
    ) {
        auto e = IRCRawEvent(network, "CONNECTION_FAIL");
        e.networkId = networkId;
        auto fi = Json.emptyObject;
        fi["type"] = Json(type_);
        fi["reason"] = Json(reason);
        // killedReason is only meaningful when type=="killed"; still
        // always serialise the field so the TS interface's optional
        // `killedReason?: string` always decodes (empty string for
        // non-kill failures is the same as "not present" on the JS
        // side because falsy checks collapse).
        fi["killedReason"] = Json(killedReason);
        if (sslVerifyError.type != Json.Type.undefined) {
            // Caller built the nested {type, error} object via
            // parseReasonToFailInfo → setSSLVerify. Ship it as-is.
            fi["sslVerifyError"] = sslVerifyError;
        }
        // Encode to string for the same thread-safety reason as
        // makeConnectionRetryStatus above.
        e.failInfoPayload = fi.toString();
        return e;
    }
}

@("IRCRawEvent setParams and getParams roundtrip")
unittest {
    auto event = IRCRawEvent("libera", "PRIVMSG");
    event.setParams(["#channel", "hello world"]);
    auto params = event.getParams();
    assert(params.length == 2);
    assert(params[0] == "#channel");
    assert(params[1] == "hello world");
}

@("IRCRawEvent toCompactJson includes network")
unittest {
    auto event = IRCRawEvent("libera", "PRIVMSG");
    event.nick = "alice";
    event.text = "hello";
    event.channel = "#d";
    event.setParams(["#d", "hello"]);
    auto json = event.toCompactJson();
    assert(json["network"].get!string == "libera");
    assert(json["c"].get!string == "PRIVMSG");
    assert(json["n"].get!string == "alice");
    assert(json["x"].get!string == "hello");
    assert(json["ch"].get!string == "#d");
    assert(json["p"].length == 2);
}

@("IRCRawEvent addTag stores tag data")
unittest {
    auto event = IRCRawEvent("libera", "PRIVMSG");
    event.addTag("msgid", "abc123");

    auto json = event.toJson();
    assert(json["tags"]["msgid"].get!string == "abc123");
}

@("IRCRawEvent toCompactJson includes msgid when present")
unittest {
    auto event = IRCRawEvent("libera", "PRIVMSG");
    event.nick = "alice";
    event.text = "hello";
    event.channel = "#d";
    event.addTag("msgid", "abc123");
    auto json = event.toCompactJson();
    assert(json["m"].get!string == "abc123");
}

@("makeServerLog produces a NOTICE-shaped event with phase tag")
unittest {
    auto e = IRCRawEvent.makeServerLog("libera", "nid-123", "connecting",
        "Connecting to irc.libera.chat:6697...");
    assert(e.command == "NOTICE", "command should be NOTICE so it lands in _server");
    assert(e.network == "libera");
    assert(e.networkId == "nid-123");
    assert(e.text == "Connecting to irc.libera.chat:6697...");
    assert(e.getTag("phase") == "connecting", "phase tag must round-trip via getTag");
    assert(e.nick == "", "server log entries are system notices and must not have a nick");
}

@("makeServerLog phase round-trips through toCompactJson tags")
unittest {
    import std.array : array;

    auto e = IRCRawEvent.makeServerLog("libera", "nid-1", "welcome", "Connection registered");
    auto j = e.toCompactJson();
    // The phase tag is now inlined as `phase` so the frontend's
    // hot path reads it without deserializing the full tags object.
    assert(j["c"].get!string == "NOTICE");
    assert(j["x"].get!string == "Connection registered");
    assert(j["network"].get!string == "libera");
    assert(j["phase"].get!string == "welcome", "phase tag must round-trip through toCompactJson");
}

@("makeServerLog distinguishes every phase")
unittest {
    // Every documented phase must produce a distinct tag so the frontend
    // can map phase → icon / color without ambiguity.
    string[] phases = [
        "queued", "resolving", "connecting", "tcp_open",
        "tls", "tls_done", "registering", "caps",
        "sasl", "welcome", "info", "warn", "error"
    ];
    foreach (p; phases) {
        auto e = IRCRawEvent.makeServerLog("libera", "nid", p, "msg");
        assert(e.getTag("phase") == p, "phase tag mismatch for " ~ p);
    }
}

@("makeConnected / makeDisconnected keep their network attribution")
unittest {
    const c = IRCRawEvent.makeConnected("libera", "nid-1");
    assert(c.network == "libera");
    assert(c.networkId == "nid-1");
    assert(c.command == "CONNECTED");

    const d = IRCRawEvent.makeDisconnected("libera", "nid-1", "lost");
    assert(d.network == "libera");
    assert(d.networkId == "nid-1");
    assert(d.command == "DISCONNECTED");
    assert(d.text == "lost");
}

@("makeConnectionRetryStatus emits rs payload with attemptCount/nextRetryAtMs/delayMs")
unittest {
    // The frontend reads data.rs.{attemptCount,nextRetryAtMs,delayMs}
    // — pin the exact wire shape so the Wave 2 messageHandler
    // dispatch doesn't have to guess about field names.
    auto e = IRCRawEvent.makeConnectionRetryStatus("libera", "nid-1", 3, 1_700_000_005_000L, 5000L);
    assert(e.command == "CONNECTION_RETRY_STATUS");
    assert(e.network == "libera");
    assert(e.networkId == "nid-1");

    auto j = e.toCompactJson();
    assert(j["c"].get!string == "CONNECTION_RETRY_STATUS");
    assert(j["rs"].type == Json.Type.object);
    assert(j["rs"]["attemptCount"].get!int == 3);
    assert(j["rs"]["nextRetryAtMs"].get!long == 1_700_000_005_000L);
    assert(j["rs"]["delayMs"].get!long == 5000L);
}

@("makeConnectionRetryStatus zero-valued emit clears the retry on the frontend")
unittest {
    // Per plan W1-T01 B3: every backoff.reset() site emits a
    // zero-valued retry status so applyRetryStatus(networkId, null)
    // fires and clears net.failInfo. Pin that the all-zero case is
    // also well-formed wire-wise.
    auto e = IRCRawEvent.makeConnectionRetryStatus("libera", "nid-1", 0, 0L, 0L);
    auto j = e.toCompactJson();
    assert(j["rs"]["attemptCount"].get!int == 0);
    assert(j["rs"]["nextRetryAtMs"].get!long == 0);
    assert(j["rs"]["delayMs"].get!long == 0);
}

@("makeConnectionFail emits fi payload with type/reason/killedReason")
unittest {
    // The frontend reads data.fi.{type,reason,killedReason,sslVerifyError}
    // — pin the wire shape with no SSL detail first.
    auto e = IRCRawEvent.makeConnectionFail("libera", "nid-1",
        "connecting_failed", "econnrefused", "", Json.undefined);
    assert(e.command == "CONNECTION_FAIL");

    auto j = e.toCompactJson();
    assert(j["c"].get!string == "CONNECTION_FAIL");
    assert(j["fi"].type == Json.Type.object);
    assert(j["fi"]["type"].get!string == "connecting_failed");
    assert(j["fi"]["reason"].get!string == "econnrefused");
    assert(j["fi"]["killedReason"].get!string == "");
    // sslVerifyError is omitted when undefined so the TS interface's
    // optional `sslVerifyError?: {...}` decodes as undefined (not null).
    assert(j["fi"]["sslVerifyError"].type == Json.Type.undefined,
        "sslVerifyError must be omitted from the wire when not set");
}

@("makeConnectionFail emits nested sslVerifyError object (NOT flat pair)")
unittest {
    // Per plan W1-T01 B2: sslVerifyError must be a NESTED object
    // {type, error} on the wire so the engine's FailInfo and the
    // frontend's TS interface match byte-for-byte. messageHandler.ts
    // does no shape conversion.
    auto ssl = Json.emptyObject;
    ssl["type"]  = Json("bad_cert");
    ssl["error"] = Json("cert_expired");

    auto e = IRCRawEvent.makeConnectionFail("libera", "nid-1",
        "connecting_failed", "ssl_certificate_error", "", ssl);

    auto j = e.toCompactJson();
    assert(j["fi"]["sslVerifyError"].type == Json.Type.object);
    assert(j["fi"]["sslVerifyError"]["type"].get!string == "bad_cert");
    assert(j["fi"]["sslVerifyError"]["error"].get!string == "cert_expired");
}

@("makeConnectionFail killedReason carries the kill description")
unittest {
    // For type=="killed" failures (supernets.org ghost protection,
    // ERR_NICKNAMEINUSE rapid disconnects, etc.), killedReason
    // carries the parenthesised description that the frontend renders
    // as "Disconnected - Killed: {killedReason}" per Wave 3 banner
    // branch.
    auto e = IRCRawEvent.makeConnectionFail("libera", "nid-1",
        "killed", "killed", "(Ghost)", Json.undefined);
    auto j = e.toCompactJson();
    assert(j["fi"]["type"].get!string == "killed");
    assert(j["fi"]["killedReason"].get!string == "(Ghost)");
}

@("non-retry/non-fail events do NOT include rs/fi keys")
unittest {
    // A normal PRIVMSG / NOTICE / CONNECTED event must NOT carry
    // rs/fi fields even if the payload struct is at its default
    // undefined value. This protects against accidental wire-shape
    // pollution if a future maintainer reuses the payload fields.
    auto e = IRCRawEvent("libera", "PRIVMSG");
    e.networkId = "nid-1";
    e.nick = "alice";
    e.text = "hi";
    e.channel = "#d";
    e.setParams(["#d", "hi"]);
    auto j = e.toCompactJson();
    assert(j["c"].get!string == "PRIVMSG");
    assert(j["rs"].type == Json.Type.undefined, "rs must be absent for non-retry events");
    assert(j["fi"].type == Json.Type.undefined, "fi must be absent for non-fail events");
}
