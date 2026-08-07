module ircfiber.redis.protocol;

import vibe.data.json;
import std.uuid : UUID;
import std.string : toUpper;

/**
 * Redis Key Namespace for Decentralized Architecture
 *
 * All keys are prefixed with server ID to prevent collision:
 * - irc:server:<serverId>           — Server metadata
 * - irc:servers                      — Set of registered server IDs
 * - irc:assignments                  — Network-to-server mapping (canonical)
 * - irc:server-assignments:<serverId>— Per-engine mirror of assignments
 * - irc:state:<serverId>:<networkId> — Per-server state snapshots
 * - irc:buffer:<serverId>:<networkId>:<channel> — Namespaced message buffers
 * - irc:events:<userId>              — User event streams (unchanged)
 * - irc:cmd:<serverId>:<networkId>   — Per-server command queues
 * - irc:control:<serverId>          — Server-specific control queue
 * - irc:global_eid                   — Global sequential event ID counter
 *
 * This prevents the IRCCloud 2020 vulnerability where buffer IDs
 * from different servers collided in shared storage.
 *
 * The `irc:server-assignments:<serverId>` mirrors are written by each
 * engine on every heartbeat and exist as a recovery source if Redis
 * `allkeys-lru` evicts the rarely-touched `irc:servers` set or
 * `irc:assignments` hash. See ServerRegistry.getAllServers() and
 * getAllAssignments() for the recovery paths.
 */
struct RedisKeys {
    /// Server metadata key
    static string server(string serverId) { return "irc:server:" ~ serverId; }
    /// Registered server list key
    static string serverList() { return "irc:servers"; }
    /// Network-to-server assignment key
    static string networkAssignments() { return "irc:assignments"; }
    
    /// State snapshot key (namespaced by server)
    static string state(string serverId, string networkId) { 
        return "irc:state:" ~ serverId ~ ":" ~ networkId; 
    }
    
    /// User event stream key
    static string events(string userId) { return "irc:events:" ~ userId; }
    
    /// Command queue key (per-server)
    static string cmd(string serverId, string networkId) { 
        return "irc:cmd:" ~ serverId ~ ":" ~ networkId; 
    }
    
    /// Control queue key (per-server)
    static string control(string serverId) { return "irc:control:" ~ serverId; }
    
    /// Legacy state key (non-namespaced)
    static string state_legacy(string networkId) { return "irc:state:" ~ networkId; }
    /// Legacy command key (non-namespaced)
    static string cmd_legacy(string networkId) { return "irc:cmd:" ~ networkId; }
    /// Legacy control queue key (non-namespaced)
    static string control_legacy() { return "irc:control"; }

    /// Global sequential event ID counter (IRCCloud-style).
    /// Atomic INCR on this key produces monotonically-increasing
    /// eids that serve as the primary key for every event.
    static string globalEid() { return "irc:global_eid"; }

    /// Per-user event stream (IRCCloud-style). Every event published
    /// to the user's pub/sub channel is also LPUSHed here. On reconnect,
    /// the gateway replays events with eid > sinceEid from this list.
    /// LTRIM keeps the list bounded for memory safety.
    static string userStream(string userId) { return "irc:stream:" ~ userId; }

    /// Routing config key (per-host max connections, etc.)
    static string routingConfig() { return "irc:routing:config"; }

    /// Engine config override key (admin settings per engine)
    static string engineConfig(string serverId) { return "irc:engine:config:" ~ serverId; }

    /// Banned network flag key (admin Z-Line)
    static string bannedNetwork(string networkId) { return "irc:banned:" ~ networkId; }

    /// Per-network connection failure tracking key.
    /// Hash with fields: serverId, error, count, lastFailure.
    /// Used by smart routing to detect failing connections that need reassignment.
    static string networkFail(string networkId) { return "irc:network-fail:" ~ networkId; }

    /// Per-engine mirror of the canonical network-to-server mapping.
    /// The engine writes its current connections here on every heartbeat
    /// so `getAllAssignments()` can recover if `irc:assignments` is
    /// evicted by Redis `allkeys-lru`. Hash fields are network IDs;
    /// values are the server ID. Deleted by `unregisterServer()`.
    static string serverAssignments(string serverId) {
        return "irc:server-assignments:" ~ serverId;
    }

    /// SCAN pattern that matches every per-engine assignments mirror.
    /// Used by `getAllAssignments()` to rebuild the canonical hash when
    /// `irc:assignments` is missing.
    static string serverAssignmentsPattern() {
        return "irc:server-assignments:*";
    }

    /// Lease key for a network assignment (TTL auto-expires if engine dies).
    /// Used by the engine's heartbeat loop to renew, and the gateway's
    /// health check to detect orphaned assignments.
    static string lease(string networkId) { return "irc:lease:" ~ networkId; }

    /// Pub/sub channel for engine shutdown announcements.
    /// Engine publishes its serverId before graceful exit; gateway
    /// receives and reassigns networks instantly.
    static string shutdownChannel() { return "irc:shutdown"; }

    /// Redis keyspace notification pattern for server keys.
    /// Subscribing to this pattern catches server key deletions
    /// (crashes, manual cleanup) for instant reassignment.
    /// Requires Redis config: notify-keyspace-events K$
    static string serverKeyspacePattern() { return "__keyspace@0__:irc:server:*"; }

    /// TTL-backed draining flag key.
    /// Set by markDraining() with a 60s TTL during graceful handoff.
    /// Cleared by the engine's heartbeat on every cycle.
    /// If the engine crashes, the key auto-expires — no manual cleanup.
    static string draining(string serverId) { return "irc:draining:" ~ serverId; }

    /// Cache key for archive-names endpoint (5-minute TTL).
    /// Stores per-user archives grouped by networkId.
    static string archiveNames(string userId) { return "irc:archive-names:" ~ userId; }

    /// Cache key for NetworkRepository.findByUserId results.
    /// Stores a JSON array of serialized NetworkConfig objects per user.
    /// TTL is set at write time (60s). Invalidated on create/update/delete.
    static string userNetworks(string userId) { return "irc:user-networks:" ~ userId; }

    /// Last-negotiated nick for a network (IRCCloud-style persistence).
    /// On connect the engine uses this instead of config.nick to avoid
    /// unnecessary 433 collision → rename → reconnect races. Written
    /// on every successful registration and confirmed NICK change. No
    /// TTL — persists across restarts until the user explicitly changes
    /// their configured nick or the admin clears the key.
    static string networkNick(string networkId) { return "irc:nick:" ~ networkId; }

    /// Distributed janitor lock key. Exactly one process holds the lock
    /// at a time (SET NX EX). Held by the elected janitor for the lock
    /// TTL; lost lock auto-expires if the holder dies mid-cycle so the
    /// next janitor cycle re-elects.
    static string janitorLock() { return "irc:janitor:lock"; }

    /// Audit log of janitor activity (LPUSH/LTRIM 1000). Read by the
    /// admin endpoint at GET /api/admin/janitor/events.
    static string janitorEvents() { return "irc:janitor:events"; }

    /// SCAN pattern that matches every Redis key namespaced by a given
    /// serverId. Used by the janitor when reaping an orphan engine and
    /// by the bootstrap-time namespace purge.
    /// Convention: every key that holds per-engine state contains the
    /// literal substring `:<serverId>:`. New namespaced keys MUST follow
    /// this pattern or the janitor will miss them.
    static string serverNamespacePattern(string serverId) {
        return "*:" ~ serverId ~ ":*";
    }
}

/**
 * TTL governance constants for engine-scoped state.
 *
 * All per-server keys MUST expire within STATE_TTL_SECONDS so a dead
 * engine self-evicts its state without requiring a janitor run.
 * Engine heartbeat bumps the TTL each cycle (every 10s); the constant
 * is a 60× safety margin above the heartbeat interval.
 *
 * Override per-deployment via env vars (validated at startup):
 *   IRCFIBER_STATE_TTL, IRCFIBER_JANITOR_INTERVAL, IRCFIBER_JANITOR_LOCK_TTL
 */
struct StateTTL {
    /// Default TTL for `irc:state:<server>:<network>` keys. Engine
    /// heartbeat bumps every 10s; 600s = 60 cycles of slack.
    /// Overridden by IRCFIBER_STATE_TTL env var.
    enum DEFAULT = 600;

    /// Janitor run interval (seconds). The gateway runs janitor at
    /// this cadence. Overridden by IRCFIBER_JANITOR_INTERVAL.
    enum JANITOR_INTERVAL_DEFAULT = 60;

    /// Janitor distributed-lock TTL (seconds). Held by the elected
    /// janitor. Auto-expires if the holder crashes mid-cycle.
    enum JANITOR_LOCK_DEFAULT = 30;

    /// TTL for `irc:network-fail:<network>` failure counters. Auto-expires
    /// so chronic failures don't accumulate forever.
    enum NETWORK_FAIL_TTL = 24 * 3600;

    /// TTL for `irc:control:<server>` control queue. Bumped every
    /// heartbeat; if engine dies, queue evicts within this TTL.
    enum CONTROL_QUEUE_TTL = 300;
}

/// IRC command message
struct IRCCommand {
    /// The command text
    string cmd;
    /// The target recipient
    string target;
    /// The message text
    string text;
    /// The channel name
    string channel;
    /// The user identifier
    string userId;
    /// The timestamp in milliseconds
    long timestampMs;
    /// The label for IRCv3 labeled-response
    string label;

    /// Converts to JSON
    Json toJson() const {
        auto j = Json.emptyObject;
        j["cmd"] = Json(cmd);
        if (target.length) j["target"] = Json(target);
        if (text.length) j["text"] = Json(text);
        if (channel.length) j["channel"] = Json(channel);
        if (userId.length) j["userId"] = Json(userId);
        j["timestampMs"] = Json(timestampMs);
        if (label.length) j["label"] = Json(label);
        return j;
    }

    /// Creates from JSON
    static IRCCommand fromJson(Json j) {
        IRCCommand c;
        if (j["cmd"].type != Json.Type.undefined) c.cmd = j["cmd"].get!string;
        if (j["target"].type != Json.Type.undefined) c.target = j["target"].get!string;
        if (j["text"].type != Json.Type.undefined) c.text = j["text"].get!string;
        if (j["channel"].type != Json.Type.undefined) c.channel = j["channel"].get!string;
        if (j["userId"].type != Json.Type.undefined) c.userId = j["userId"].get!string;
        if (j["timestampMs"].type != Json.Type.undefined) c.timestampMs = j["timestampMs"].get!long;
        if (j["label"].type != Json.Type.undefined) c.label = j["label"].get!string;
        return c;
    }
}

/// Control message for server management
struct ControlMessage {
    /// The action type
    string action;
    /// The network identifier
    string networkId;
    /// The user identifier
    string userId;
    /// The configuration data
    Json config;
    /// The channel name
    string channel;
    /// The reason text
    string reason;
    /// The timestamp in milliseconds
    long timestampMs;

    /// Converts to JSON
    Json toJson() const {
        auto j = Json.emptyObject;
        j["action"] = Json(action);
        if (networkId.length) j["networkId"] = Json(networkId);
        if (userId.length) j["userId"] = Json(userId);
        if (config.type != Json.Type.undefined) j["config"] = config;
        if (channel.length) j["channel"] = Json(channel);
        if (reason.length) j["reason"] = Json(reason);
        j["timestampMs"] = Json(timestampMs);
        return j;
    }

    /// Creates from JSON
    static ControlMessage fromJson(Json j) {
        ControlMessage m;
        if (j["action"].type != Json.Type.undefined) m.action = j["action"].get!string;
        if (j["networkId"].type != Json.Type.undefined) m.networkId = j["networkId"].get!string;
        if (j["userId"].type != Json.Type.undefined) m.userId = j["userId"].get!string;
        if (j["config"].type != Json.Type.undefined) m.config = j["config"];
        if (j["channel"].type != Json.Type.undefined) m.channel = j["channel"].get!string;
        if (j["reason"].type != Json.Type.undefined) m.reason = j["reason"].get!string;
        if (j["timestampMs"].type != Json.Type.undefined) m.timestampMs = j["timestampMs"].get!long;
        return m;
    }
}

/// W1-T01: structured retry state surfaced from the engine's
/// reconnect loop. Mirrors `ircfiber.irc.connection.RetryStatus` —
/// kept as a separate type so the snapshot wire format doesn't
/// leak engine-side dependencies into the protocol layer.
struct RetryStatus {
    /// 1-based reconnect attempt number. 0 when no retry is pending.
    int  attemptCount;
    /// Unix-ms of the scheduled next reconnect attempt. 0 when no
    /// retry is pending.
    long nextRetryAtMs;
    /// Scheduled delay in milliseconds (informational; the live
    /// countdown is derived from `nextRetryAtMs - now`).
    long delayMs;

    /// Converts to JSON. Mirrors the field naming used by the
    /// `CONNECTION_RETRY_STATUS` event's `rs` payload so the frontend
    /// reads both via the same field names.
    Json toJson() const {
        auto j = Json.emptyObject;
        j["attemptCount"] = Json(attemptCount);
        j["nextRetryAtMs"] = Json(nextRetryAtMs);
        j["delayMs"]      = Json(delayMs);
        return j;
    }
}

/// W1-T01: structured disconnect information mirrored into the
/// snapshot for the WS sync payload. Mirrors the engine's
/// `FailInfo` (in `ircfiber.irc.connection`) but kept on the
/// protocol layer so the wire shape is owned by the snapshot.
///
/// Schema mirrors the `CONNECTION_FAIL` event's `fi` payload
/// byte-for-byte:
///   `{type, reason, killedReason, sslVerifyError?: {type, error}}`
struct FailInfoSnapshot {
    /// "connecting_failed" | "killed" | "socket_closed" |
    /// "ssl_verify_error" | "connecting_restricted" |
    /// "connection_blocked"
    string type_;
    /// Raw reason key (matches IRCCloud's RENDER_REASONS table).
    string reason;
    /// Kill description for type=="killed"; empty otherwise.
    string killedReason;
    /// Nested {type, error} object for SSL failures; absent otherwise.
    /// Stored as Json so the wire shape matches the event payload
    /// exactly (per plan B2 — MUST be nested, not flat).
    Json sslVerifyError;

    /// Converts to JSON. Mirrors the field naming used by the
    /// `CONNECTION_FAIL` event's `fi` payload.
    Json toJson() const {
        auto j = Json.emptyObject;
        j["type"]         = Json(type_);
        j["reason"]       = Json(reason);
        j["killedReason"] = Json(killedReason);
        if (sslVerifyError.type != Json.Type.undefined) {
            j["sslVerifyError"] = sslVerifyError;
        }
        return j;
    }
}

/// Network state snapshot for persistence
struct NetworkStateSnapshot {
    /// The network configuration
    Json config;
    /// Connection status flag
    bool connected;
    /// Connection status text
    string status;
    /// Current IRC nickname
    string currentNick;
    /// Channel buffer list
    Json buffers;
    /// Channel topics
    Json topics;
    /// Channel users
    Json users;
    /// IRCCloud-style realname cache: nick → realname
    Json realnames;
    /// extended-join account cache: nick → account name
    Json accounts;
    /// Ident cache from userhost-in-names: nick → ident
    Json idents;
    /// The owner user identifier
    string ownerId;
    /// The managing server identifier
    string serverId;
    /// Away status
    bool isAway = false;
    /// Away message
    string awayMessage;
    /// Last update timestamp
    long updatedAt;
    /// Negotiated IRCv3 capabilities
    string[] caps;
    /// Full ISUPPORT inventory the connected server advertised in its
    /// 005 reply stream. Used by the WS sync payload to ship the
    /// categorised "Server features" panel state to the frontend
    /// without requiring it to re-parse the raw 005 message stream.
    /// Schema is identical to `Network.isupport` on the frontend:
    /// every key=value or bare flag the server sent, keyed upper-case.
    string[string] isupport;
    /// Channels the user has parted (for inactive sidebar)
    string[] partedChannels;
    /// W1-T01-rev1: structured retry state surfaced from the engine's
    /// reconnect loop (see `ircfiber.irc.connection.RetryStatus`).
    /// The frontend uses this to render the ordinal "Nth attempt"
    /// label, the 1s countdown via setInterval, and the
    /// "Reconnecting..." state badge in ConnectionStatus.
    ///
    /// Now genuinely nullable on the wire: `hasRetryStatus` flags
    /// whether the field should be serialised. When false (network is
    /// healthy / freshly reset), `toJson()` omits `retryStatus`
    /// entirely so the frontend can distinguish "no retry pending"
    /// from a missing field on legacy snapshots (where `hasRetryStatus`
    /// also stays false after `fromJson()`). When true, `toJson()`
    /// emits the full `{attemptCount, nextRetryAtMs, delayMs}` object
    /// with the engine's real active delay — closed-port smoke
    /// assertions (plan W1-T01 section G scenario 1) require
    /// `delayMs > 0` during the active backoff.
    bool   hasRetryStatus;
    RetryStatus retryStatus;
    /// W1-T01: structured disconnect reason from the engine's
    /// `parseReasonToFailInfo` parser. Shipped on disconnect and
    /// cleared when the engine emits a zero-valued
    /// `CONNECTION_RETRY_STATUS` (per plan B3 — every
    /// `backoff.reset()` site clears both). Nullable — absent
    /// when the network is healthy.
    FailInfoSnapshot failInfo;

    /// Converts to JSON
    Json toJson() const {
        auto j = Json.emptyObject;
        if (config.type != Json.Type.undefined) j["config"] = config;
        j["connected"] = Json(connected);
        j["status"] = Json(status);
        j["currentNick"] = Json(currentNick);
        if (buffers.type != Json.Type.undefined) j["buffers"] = buffers;
        if (topics.type != Json.Type.undefined) j["topics"] = topics;
        if (users.type != Json.Type.undefined) j["users"] = users;
        if (realnames.type != Json.Type.undefined) j["realnames"] = realnames;
        if (accounts.type != Json.Type.undefined) j["accounts"] = accounts;
        if (idents.type != Json.Type.undefined) j["idents"] = idents;
        if (ownerId.length) j["ownerId"] = Json(ownerId);
        if (serverId.length) j["serverId"] = Json(serverId);
        j["isAway"] = Json(isAway);
        if (awayMessage.length) j["awayMessage"] = Json(awayMessage);
        j["updatedAt"] = Json(updatedAt);
        if (caps.length) {
            auto arr = Json.emptyArray;
            foreach (c; caps) arr ~= Json(c);
            j["caps"] = arr;
        }
        if (isupport.length) {
            // Always serialise (even when empty) so the frontend sees
            // an explicit "isupport" key and can distinguish a real
            // empty map from a missing field (older snapshot format).
            auto obj = Json.emptyObject;
            foreach (k, v; isupport) obj[k] = Json(v);
            j["isupport"] = obj;
        } else {
            j["isupport"] = Json.emptyObject;
        }
        if (partedChannels.length) {
            auto arr = Json.emptyArray;
            foreach (c; partedChannels) arr ~= Json(c);
            j["partedChannels"] = arr;
        }
        // W1-T01-rev1: structured retry / fail info payload. The
        // retry status is omitted from the wire entirely when
        // `hasRetryStatus` is false so the frontend sees an absent
        // field for "no retry scheduled" rather than a zero-valued
        // `{0, 0, 0}` (which previously masked the active retry's
        // `delayMs > 0` claim — see review-wave1 HIGH 1). failInfo
        // is only shipped when populated per the existing semantics
        // (plan R2 dual-emit — empty `{type: "", reason: ""}` would
        // make the frontend's truthy checks ambiguous).
        if (hasRetryStatus) {
            j["retryStatus"] = retryStatus.toJson();
        }
        if (failInfo.type_.length > 0 || failInfo.reason.length > 0) {
            // Only ship failInfo when populated — failInfo is
            // absent on healthy networks, and shipping an empty
            // `{type: "", reason: ""}` would make the frontend's
            // truthy checks ambiguous.
            j["failInfo"] = failInfo.toJson();
        }
        return j;
    }

    /// Creates from JSON
    static NetworkStateSnapshot fromJson(Json j) {
        NetworkStateSnapshot s;
        if (j["config"].type != Json.Type.undefined) s.config = j["config"];
        if (j["connected"].type != Json.Type.undefined) s.connected = j["connected"].get!bool;
        if (j["status"].type != Json.Type.undefined) s.status = j["status"].get!string;
        if (j["currentNick"].type != Json.Type.undefined) s.currentNick = j["currentNick"].get!string;
        if (j["buffers"].type != Json.Type.undefined) s.buffers = j["buffers"];
        if (j["topics"].type != Json.Type.undefined) s.topics = j["topics"];
        if (j["users"].type != Json.Type.undefined) s.users = j["users"];
        if (j["realnames"].type != Json.Type.undefined) s.realnames = j["realnames"];
        if (j["accounts"].type != Json.Type.undefined) s.accounts = j["accounts"];
        if (j["idents"].type != Json.Type.undefined) s.idents = j["idents"];
        if (j["ownerId"].type != Json.Type.undefined) s.ownerId = j["ownerId"].get!string;
        if (j["serverId"].type != Json.Type.undefined) s.serverId = j["serverId"].get!string;
        if (j["isAway"].type != Json.Type.undefined) s.isAway = j["isAway"].get!bool;
        if (j["awayMessage"].type != Json.Type.undefined) s.awayMessage = j["awayMessage"].get!string;
        if (j["updatedAt"].type != Json.Type.undefined) s.updatedAt = j["updatedAt"].get!long;
        if (j["caps"].type == Json.Type.array) {
            foreach (c; j["caps"]) {
                if (c.type == Json.Type.string) s.caps ~= c.get!string;
            }
        }
        // Restore the full ISUPPORT map keyed upper-case. Older
        // snapshots without this field deserialise as empty — the
        // frontend will fall back to its own parsing in that case
        // (and the engine will repopulate on the next 005 stream).
        if (j["isupport"].type == Json.Type.object) {
            auto obj = j["isupport"].get!(Json[string]);
            foreach (k, v; obj) {
                if (v.type == Json.Type.string) s.isupport[toUpper(k)] = v.get!string;
            }
        }
        if (j["partedChannels"].type == Json.Type.array) {
            foreach (c; j["partedChannels"]) {
                if (c.type == Json.Type.string) s.partedChannels ~= c.get!string;
            }
        }
        // W1-T01-rev1: structured retry status. Default to "absent"
        // (hasRetryStatus = false) so legacy snapshots without this
        // field still deserialise cleanly — the frontend treats a
        // missing field as "no retry scheduled", exactly like the
        // previous zero-valued payload. When the field is present,
        // flip the flag so toJson() re-emits it on the next
        // round-trip.
        if (j["retryStatus"].type == Json.Type.object) {
            auto rs = j["retryStatus"];
            if (auto a = "attemptCount" in rs)
                if (a.type == Json.Type.int_) s.retryStatus.attemptCount = a.get!int;
            if (auto n = "nextRetryAtMs" in rs)
                if (n.type == Json.Type.int_) s.retryStatus.nextRetryAtMs = n.get!long;
            if (auto d = "delayMs" in rs)
                if (d.type == Json.Type.int_) s.retryStatus.delayMs = d.get!long;
            s.hasRetryStatus = true;
        }
        // W1-T01: structured fail info. Optional — only deserialise
        // when present so legacy snapshots stay valid (plan compatibility
        // constraint: schema changes must be backward-compatible).
        if (j["failInfo"].type == Json.Type.object) {
            auto fi = j["failInfo"];
            if (auto t = "type" in fi)
                if (t.type == Json.Type.string) s.failInfo.type_ = t.get!string;
            if (auto r = "reason" in fi)
                if (r.type == Json.Type.string) s.failInfo.reason = r.get!string;
            if (auto k = "killedReason" in fi)
                if (k.type == Json.Type.string) s.failInfo.killedReason = k.get!string;
            // Rebuild the nested sslVerifyError Json object from its
            // children (vibe.data.json.Json's opAssign has subtle
            // aliasing rules that make a direct copy fragile, so we
            // rebuild it field-by-field instead).
            if (auto svePtr = "sslVerifyError" in fi) {
                auto sve = *svePtr;
                if (sve.type == Json.Type.object) {
                    auto nested = Json.emptyObject;
                    auto t = sve["type"];
                    if (t.type == Json.Type.string) nested["type"] = t;
                    auto e = sve["error"];
                    if (e.type == Json.Type.string) nested["error"] = e;
                    s.failInfo.sslVerifyError = nested;
                }
            }
        }
        return s;
    }
}
