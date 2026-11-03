module ircfiber.redis.protocol;

import vibe.data.json;
import std.uuid : UUID;
import std.string : toUpper, toLower;

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

    /// Per-user last-seen hash: field `<networkId>:<bufferKey>` → message `t` (ms).
    static string lastSeen(string userId) { return "irc:lastseen:" ~ userId; }
    
    /// Command queue key (per-server)
    static string cmd(string serverId, string networkId) { 
        return "irc:cmd:" ~ serverId ~ ":" ~ networkId; 
    }
    
    /// Control queue key (per-server)
    static string control(string serverId) { return "irc:control:" ~ serverId; }

    /// Per-server Mullvad egress slot registry: hash `label` → slot JSON
    /// `{label,host,port,locationId,hostname,country,countryCode,city,
    ///   controllable,state,activeConns,heldUntilMs,error}`.
    /// Written by the engine's state snapshotter, read by the gateway's
    /// `GET /api/egress`. Refreshed every snapshot tick with EXPIRE 60 so a
    /// dead engine's slots vanish instead of lingering as phantom exits.
    static string egressSlots(string serverId) { return "irc:egress:slots:" ~ serverId; }

    /// Per-server Mullvad location catalog: JSON array of
    /// `{id,country,countryCode,city,cityCode,relays}`, one entry per
    /// pickable exit city as the slot's own tailscaled reports it.
    /// EXPIRE 1800 — the catalog changes rarely and must survive a few
    /// missed refreshes so the picker never goes blank.
    static string egressCatalog(string serverId) { return "irc:egress:catalog:" ~ serverId; }

    /// Shared NordVPN SOCKS5 credential pair (admin-settable, like the OAuth
    /// provider overrides in ircfiber.oauth): `{"username":…, "password":…}`.
    /// Read by the gateway (ircfiber.nordvpn_creds) and the engine
    /// (loadNordvpnPoolUnlocked) to fill any pool entry that specifies no
    /// credentials of its own.
    static string nordvpnCreds() { return "irc:egress:nordvpn:creds"; }

    /// Cached SOCKS5 reachability + exit-IP/ASN probe for one egress pool
    /// entry (label): `{healthy,error,checkedAt,ipinfo:{...}}`. Written by
    /// the gateway's background refresher (ircfiber.web.admin.egress_probe)
    /// every 20s instead of on every admin page poll — apiMullvadStatus
    /// reads this and falls back to a live probe only on a miss. EXPIRE 90
    /// — a few missed refresh cycles still serve the last-known answer; a
    /// genuinely stopped refresher eventually goes stale rather than
    /// lying forever. Not per-server: the pool itself is gateway-global.
    static string egressProbe(string label) { return "irc:egress:probe:" ~ label; }

    /// Latest reachability result for one proxy label against every host the
    /// daily sweep (ircfiber.web.admin.egress_reachability) has tested it
    /// against: hash field `<host>:<port>` (host lowercased) -> JSON
    /// `{reachable,reachedIrcd,registered,banned,throttled,error,ms,checkedAt}`.
    /// No TTL — staleness is visible per field via `checkedAt`; this hash is
    /// the source the admin matrix reads and the source
    /// egressReachabilityBanned() below is derived from.
    static string egressReachability(string label) { return "irc:egress:reach:" ~ label; }

    /// Sparse snapshot of currently-banned (host, egress-ban-key) pairs from
    /// the daily sweep: JSON array of `{host,banKey}` (banKey matches the
    /// engine's own slotBanKey() shape: a Mullvad slot's current locationId,
    /// or "slot:<label>" for a static/NordVPN entry or a Mullvad slot with no
    /// known location). Written by the gateway sweep, read every ~10 min by
    /// the engine's startDailyReachabilityRefresh (connection.d) into its
    /// in-process dailyReachabilityBanned table. EXPIRE 93600 (26h) — survives
    /// a slightly-delayed next daily run; a genuinely stopped sweep still
    /// clears itself out within a day instead of lying forever.
    static string egressReachabilityBanned() { return "irc:egress:reach:banned"; }

    /// Daily-sweep job status: JSON `{running,lastRunStartedAt,lastRunFinishedAt,
    /// hostsChecked,probesRun,lastError}`. Written by the sweep, read by
    /// `GET /api/admin/egress-reachability/status`.
    static string egressReachabilityStatus() { return "irc:egress:reach:status"; }

    /// Single-flight lock for the daily sweep (`SET token NX EX`), so two
    /// gateway replicas (or an admin-triggered run-now overlapping the
    /// scheduled one) never run it concurrently.
    static string egressReachabilityLock() { return "irc:egress:reach:lock"; }

    /// Kill switch: missing key (the default) means enabled, matching
    /// isNickservSyncEnabled's fail-open convention
    /// (services/nickserv_sync.d:99-104). Set to anything to pause the sweep
    /// without a redeploy.
    static string egressReachabilitySweepEnabled() { return "irc:config:egressReachabilitySweep"; }
    
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
    /// LTRIM keeps the list bounded for memory safety; EXPIRE
    /// `StateTTL.USER_STREAM_TTL` is re-set on every append.
    static string userStream(string userId) { return "irc:stream:" ~ userId; }

    /// Per-network hash: field = bouncer clientid, value = last eid delivered to it.
    static string bncSeen(string networkId) { return "irc:bnc:seen:" ~ networkId; }

    /// Presence record of one attached bouncer client (JSON, short TTL
    /// refreshed by the client's keepalive loop). Written by the bnc
    /// process, read by the admin API in the gateway process.
    static string bncClient(string sessionId) { return "irc:bnc:client:" ~ sessionId; }
    /// Set of session ids that have a `bncClient` record. An explicit index
    /// rather than SCAN: vibe.d's RedisReply wedges on SCAN replies whose
    /// nested key array is empty, and SMEMBERS is O(clients) anyway. Stale
    /// members (record expired) are pruned by the reader.
    static string bncClients() { return "irc:bnc:clients"; }

    /// Per-user bouncer event trail (LPUSH, capped 50, 90-day TTL).
    static string bncAudit(string userId) { return "irc:bnc:audit:" ~ userId; }

    /// Per-user, per-network set of bouncer devices already announced in the
    /// network's server log (`id:<clientid>`, or `ip:<addr>` for clients
    /// without one). 90-day TTL refreshed on every attach.
    static string bncKnownDevices(string userId, string networkId) {
        return "irc:bnc:known:" ~ userId ~ ":" ~ networkId;
    }

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

    /// FIFO outbox of support-issue announcements (RPUSH by the gateway,
    /// BLPOP by the #support bot, LTRIM -1000 -1 keeps it bounded).
    static string supportOutbox() { return "irc:support:outbox"; }

    /// Presence/heartbeat of the #support services bot (JSON, 60 s TTL
    /// refreshed every ~5 s by the bot process). Read by the admin IRCD page
    /// through GET /api/admin/support/bot; absent = bot process down.
    static string supportBot() { return "irc:support:bot"; }

    /// Control commands for the #support bot (RPUSH by the admin API, BLPOP
    /// by the bot): `{"cmd":"reconnect"|"rejoin","by":"<admin>","ts":<ms>}`.
    /// Commands older than 60 s are dropped by the consumer.
    static string supportBotControl() { return "irc:support:bot:control"; }

    /// Reporter follow-ups per user in the current hour: INCR + 1 h EXPIRE,
    /// checked by POST /api/support/issues/:id/comments (every follow-up
    /// fans out to #support and staff mail, so it is capped like reports).
    static string supportCommentRate(string userId) { return "irc:support:ratelimit:comments:" ~ userId; }

    /// Run records published by the k3s `ircfiber-redis-backup` CronJob
    /// (LPUSH + LTRIM 0 59). Read by GET /api/admin/backups; the Mongo job
    /// writes its own records to the `backup_runs` collection instead,
    /// because `mongo:7` carries no redis-cli.
    static string backupRuns() { return "irc:backup:runs"; }

    /// Id of the admin-pinned MOTD template, or absent. While set the
    /// gateway writes the ircd pool with only that block, which is what
    /// keeps "pinned" meaning "everyone sees this one".
    static string motdPinned() { return "irc:config:motdPinned"; }
    /// Last browser IP seen for this user's web session, written by the
    /// gateway on every websocket handshake (30 day TTL). Read by the engine
    /// to forward the user's real address to irc.ircfiber.com via WEBIRC.
    static string webircIp(string userId) { return "irc:webirc:ip:" ~ userId; }

    /// Protocol version key. Written by engine heartbeat (see
    /// `ircfiber.engine.state.writeStateSnapshots`). Gateways and
    /// future Python implementations read this at startup to assert
    /// compatibility. Not yet enforced — version 1 is the initial
    /// frozen contract.
    static string protocolVersion() { return "irc:protocol:version"; }

    /// Public avatar registry fallback for networks without IRCv3
    /// draft/metadata-2: hash `<lowercased services account>` → avatar URL,
    /// keyed per network host. Written by the engine on services login
    /// (900/901), read by GET /api/avatars for users on bare IRC servers.
    static string publicAvatars(string host) { return "irc:avatar:pub:" ~ host.toLower; }

    /// MLS account-owner registry: hash `<lowercased services account>` →
    /// ircfiber site user UUID, keyed per network host. Generalizes
    /// `publicAvatars` to identity resolution so the MLS backend's
    /// `resolveAccount` can bind a NickServ account on ANY network (not
    /// just irc.ircfiber.com) to the ircfiber account whose connection
    /// observed that login. Written by the engine on services login
    /// (900/901), read by `resolveAccount`.
    static string mlsAccountOwners(string host) { return "irc:mls:acct:" ~ host.toLower; }

    /// Avatar upload rate limit: INCR + 1h EXPIRE, per user.
    static string avatarUploadRate(string userId) { return "irc:avatar:ratelimit:" ~ userId; }

    // ── Notifications (Notification Policy v2, `ircfiber.notify.*`) ──

    /// Claims one message for one user across gateway replicas: string, `SET NX EX 86400`.
    /// Replaces `irc:push:sent:<uid>:<m>`.
    static string notifyClaim(string userId, string msgid) { return "irc:notify:claim:" ~ userId ~ ":" ~ msgid; }

    /// Per-user app badge counter (reset by the app); 30-day expiry.
    static string pushBadge(string userId) { return "irc:push:badge:" ~ userId; }

    /// "Why was I notified?" index: ZSET msgid → event t, last 200, 24 h.
    static string notifyTraceIndex(string userId) { return "irc:notify:traces:" ~ userId; }

    /// Evaluation traces: HASH msgid → trace JSON, trimmed with `notifyTraceIndex`.
    static string notifyTrace(string userId) { return "irc:notify:trace:" ~ userId; }

    /// Delivery outcomes: HASH msgid → JSON array of outcomes, trimmed with `notifyTraceIndex`.
    static string notifyOutcome(string userId) { return "irc:notify:outcome:" ~ userId; }

    /// Items held by quiet hours: ZSET score t, member `<m>|<nid>|<buffer>|<cls>`; 8 days.
    static string notifyHeld(string userId) { return "irc:notify:held:" ~ userId; }

    /// Quiet-hours summary schedule: ZSET uid → window end (unix ms).
    static string notifySummaryDue() { return "irc:notify:summary:due"; }

    /// Repeated-DM tracking per sender: ZSET msgid → t; 1 h. `senderLower` is the lower-cased nick.
    static string notifyDmTimes(string userId, string networkId, string senderLower) {
        return "irc:notify:dm:" ~ userId ~ ":" ~ networkId ~ ":" ~ senderLower;
    }

    /// Burst grouping window for one thread: string holding the window start (ms), PX = window.
    static string notifyCoalesce(string userId, string threadHash) { return "irc:notify:co:" ~ userId ~ ":" ~ threadHash; }

    /// Messages coalesced into the current `notifyCoalesce` window (INCR).
    static string notifyCoalesceCount(string userId, string threadHash) {
        return "irc:notify:co:" ~ userId ~ ":" ~ threadHash ~ ":n";
    }

    /// Notification email schedule: ZSET uid → due (unix ms).
    static string notifyEmailDue() { return "irc:notify:email:due"; }

    /// Queued notification email items: LIST of JSON, at most 200, 3 days.
    static string notifyEmailItems(string userId) { return "irc:notify:email:items:" ~ userId; }

    /// When the last notification email went out (unix ms).
    static string notifyEmailLast(string userId) { return "irc:notify:email:last:" ~ userId; }

    /// Notification email unsubscribe token → uid; 30 days.
    static string notifyUnsub(string token) { return "notify:unsub:" ~ token; }

    /// SET of uids the server must evaluate without a push registration
    /// (an email cell on, or quiet hours with the summary on).
    static string notifyServerUsers() { return "irc:notify:server-users"; }

    /// Browser presence for Web Push: HASH sessionRef → expiry ms; key EXPIRE 120 s.
    static string notifyLive(string userId) { return "irc:notify:live:" ~ userId; }

    /// Delivery health: HASH `<target>:lastOkAt` / `<target>:lastErrAt` / `<target>:lastErr`.
    static string notifyHealth(string userId) { return "irc:notify:health:" ~ userId; }

    /// Notification endpoint rate limit (`kind` = `patch`, `test`, …): INCR + EXPIRE.
    static string notifyRate(string kind, string userId) { return "irc:notify:rl:" ~ kind ~ ":" ~ userId; }

    /// Kill switch for notification email: missing = enabled, `"0"` disables.
    static string notifyEmailSwitch() { return "irc:config:notifyEmail"; }

    /// Kill switch for Web Push: missing = enabled, `"0"` disables.
    static string notifyWebPushSwitch() { return "irc:config:notifyWebPush"; }

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

/// Inter-service protocol version. Increment when the Redis wire
/// format (keys, JSON shapes, command envelopes) changes
/// incompatibly. Stored as string value of `irc:protocol:version`.
/// Gateways SHOULD assert at startup that the stored version equals
/// this constant; mismatch MUST be surfaced as healthcheck failure.
enum PROTOCOL_VERSION = 1;

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

    /// TTL for `irc:stream:<user>` replay lists. Re-set on every append;
    /// matches the 30-day scrollback retention (storage/buffer.d TTL_DAYS).
    enum USER_STREAM_TTL = 30 * 86_400;
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
    /// Client-only message tags to send with a `msg` (`+reply`, for
    /// example), unescaped; the connection escapes them for the wire.
    string[string] tags;

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
        if (tags.length) {
            auto t = Json.emptyObject;
            foreach (k, v; tags) t[k] = Json(v);
            j["tags"] = t;
        }
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
        if (j["tags"].type == Json.Type.object) {
            foreach (string k, Json v; j["tags"]) {
                if (v.type == Json.Type.string) c.tags[k] = v.get!string;
            }
        }
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

/// Negotiated TLS session details captured by the engine right after
/// the handshake. Surfaced verbatim in the WS sync payload under
/// `tlsInfo` so the frontend can render the server-log header line.
struct TlsInfo {
    /// Protocol version as reported by OpenSSL (e.g. "TLSv1.3").
    string version_;
    /// Negotiated cipher suite name (e.g. "TLS_AES_256_GCM_SHA384").
    string cipher;
    /// Peer certificate subject commonName.
    string certCn;
    /// Peer certificate issuer commonName.
    string certIssuer;
    /// Peer certificate notAfter as unix ms (0 = unknown).
    long certNotAfterMs;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["version"] = Json(version_);
        j["cipher"] = Json(cipher);
        j["certCn"] = Json(certCn);
        j["certIssuer"] = Json(certIssuer);
        j["certNotAfterMs"] = Json(certNotAfterMs);
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
    /// IRCv3 draft/metadata-2 user cache: nick → {key: value}
    Json userMetadata;
    /// IRCv3 draft/metadata-2 channel cache: lowercased channel → {key: value}
    Json channelMetadata;
    /// Away cache: nick → away message (`""` = away with no text)
    Json away;
    /// Bot-mode cache: array of nicks
    Json bots;
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
    /// Active Mullvad egress actually used for this network's live TCP
    /// connection. "" = direct, else label like "de"/"se".
    string activeEgressLabel;
    /// SOCKS proxy host that won (e.g. "tailscale-mullvad-de:1055").
    string activeEgressHost;
    /// Resolved Tailnet IP of active SOCKS proxy (e.g. "100.117.47.8").
    string activeEgressIp;
    /// Human-readable location of the active egress, e.g. "Berlin, Germany".
    /// Empty when the connection is direct or the slot's location is unknown.
    /// Slot labels are internal names now, so this is what the UI shows.
    string activeEgressLocation;
    /// Remote IP of the live IRC socket (AAAA or A winner). "" when
    /// disconnected. Its family is the authoritative IPv6-vs-IPv4 signal.
    string peerIp;
    /// Local source IP of the live IRC socket (per-user IPv6 bind, shared
    /// host address, or SOCKS sidecar hop). "" when disconnected.
    string localIp;
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
    /// Structured connection retry state (attempt count, next retry time, delay).
    RetryStatus retryStatus;
    /// W1-T01: structured disconnect reason from the engine's
    /// `parseReasonToFailInfo` parser. Shipped on disconnect and
    /// cleared when the engine emits a zero-valued
    /// `CONNECTION_RETRY_STATUS` (per plan B3 — every
    /// `backoff.reset()` site clears both). Nullable — absent
    /// when the network is healthy.
    FailInfoSnapshot failInfo;
    /// Round-trip latency of the engine's last `PING :LAG<ms>` probe
    /// (unix ms). -1 = unknown (no PONG measured yet this connection).
    long lagMs = -1;
    /// Unix ms of RPL_WELCOME for the live connection. 0 = not connected.
    long connectedAtMs = 0;
    /// Seconds since the last inbound byte on the live connection. 0 =
    /// unknown / not connected. Shipped on every snapshot so the UI can
    /// show a stale hint before the PONG-timeout reaper fires.
    long dataAgeSecs = 0;
    /// Seconds since the last PONG on the live connection. 0 = unknown.
    long pongAgeSecs = 0;
    /// Whether `tlsInfo` is populated; false for plain connections or
    /// when the engine could not read the session details.
    bool hasTlsInfo;
    /// Negotiated TLS session details (only serialised when `hasTlsInfo`).
    TlsInfo tlsInfo;

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
        if (userMetadata.type != Json.Type.undefined) j["userMetadata"] = userMetadata;
        if (channelMetadata.type != Json.Type.undefined) j["channelMetadata"] = channelMetadata;
        if (away.type != Json.Type.undefined) j["away"] = away;
        if (bots.type != Json.Type.undefined) j["bots"] = bots;
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
        if (activeEgressLabel.length) j["activeEgressLabel"] = Json(activeEgressLabel);
        if (activeEgressHost.length) j["activeEgressHost"] = Json(activeEgressHost);
        if (activeEgressIp.length) j["activeEgressIp"] = Json(activeEgressIp);
        if (activeEgressLocation.length) j["activeEgressLocation"] = Json(activeEgressLocation);
        if (peerIp.length) j["peerIp"] = Json(peerIp);
        if (localIp.length) j["localIp"] = Json(localIp);
        j["lagMs"] = Json(lagMs);
        j["connectedAtMs"] = Json(connectedAtMs);
        j["dataAgeSecs"] = Json(dataAgeSecs);
        j["pongAgeSecs"] = Json(pongAgeSecs);
        if (hasTlsInfo) j["tlsInfo"] = tlsInfo.toJson();
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
        if (j["userMetadata"].type != Json.Type.undefined) s.userMetadata = j["userMetadata"];
        if (j["channelMetadata"].type != Json.Type.undefined) s.channelMetadata = j["channelMetadata"];
        if (j["away"].type != Json.Type.undefined) s.away = j["away"];
        if (j["bots"].type != Json.Type.undefined) s.bots = j["bots"];
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
        if (j["activeEgressLabel"].type == Json.Type.string) s.activeEgressLabel = j["activeEgressLabel"].get!string;
        if (j["activeEgressHost"].type == Json.Type.string) s.activeEgressHost = j["activeEgressHost"].get!string;
        if (j["activeEgressIp"].type == Json.Type.string) s.activeEgressIp = j["activeEgressIp"].get!string;
        if (j["activeEgressLocation"].type == Json.Type.string) s.activeEgressLocation = j["activeEgressLocation"].get!string;
        if (j["peerIp"].type == Json.Type.string) s.peerIp = j["peerIp"].get!string;
        if (j["localIp"].type == Json.Type.string) s.localIp = j["localIp"].get!string;
        if (j["lagMs"].type == Json.Type.int_) s.lagMs = j["lagMs"].get!long;
        if (j["connectedAtMs"].type == Json.Type.int_) s.connectedAtMs = j["connectedAtMs"].get!long;
        if (j["dataAgeSecs"].type == Json.Type.int_) s.dataAgeSecs = j["dataAgeSecs"].get!long;
        if (j["pongAgeSecs"].type == Json.Type.int_) s.pongAgeSecs = j["pongAgeSecs"].get!long;
        if (j["tlsInfo"].type == Json.Type.object) {
            const ti = j["tlsInfo"];
            if (auto v = "version" in ti)
                if (v.type == Json.Type.string) s.tlsInfo.version_ = v.get!string;
            if (auto c = "cipher" in ti)
                if (c.type == Json.Type.string) s.tlsInfo.cipher = c.get!string;
            if (auto cn = "certCn" in ti)
                if (cn.type == Json.Type.string) s.tlsInfo.certCn = cn.get!string;
            if (auto iss = "certIssuer" in ti)
                if (iss.type == Json.Type.string) s.tlsInfo.certIssuer = iss.get!string;
            if (auto na = "certNotAfterMs" in ti)
                if (na.type == Json.Type.int_) s.tlsInfo.certNotAfterMs = na.get!long;
            s.hasTlsInfo = true;
        }
        // W1-T01-rev1: structured retry status. Default to "absent"
        // field still deserialise cleanly — the frontend treats a
        // missing field as "no retry scheduled", exactly like the
        // previous zero-valued payload. When the field is present,
        // flip the flag so toJson() re-emits it on the next
        // round-trip.
        if (j["retryStatus"].type == Json.Type.object) {
            const rs = j["retryStatus"];
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
            const fi = j["failInfo"];
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
                    const t = sve["type"];
                    if (t.type == Json.Type.string) nested["type"] = t;
                    const e = sve["error"];
                    if (e.type == Json.Type.string) nested["error"] = e;
                    s.failInfo.sslVerifyError = nested;
                }
            }
        }
        return s;
    }
}

@("NetworkStateSnapshot lag/connectedAt/tlsInfo round-trip through JSON")
unittest {
    NetworkStateSnapshot s;
    s.lagMs = 42;
    s.connectedAtMs = 1_700_000_000_000;
    s.hasTlsInfo = true;
    s.tlsInfo = TlsInfo("TLSv1.3", "TLS_AES_256_GCM_SHA384", "irc.example.org", "R11", 1_800_000_000_000);
    auto j = s.toJson();
    assert(j["lagMs"].get!long == 42);
    assert(j["connectedAtMs"].get!long == 1_700_000_000_000);
    assert(j["tlsInfo"]["version"].get!string == "TLSv1.3");
    assert(j["tlsInfo"]["cipher"].get!string == "TLS_AES_256_GCM_SHA384");
    assert(j["tlsInfo"]["certCn"].get!string == "irc.example.org");
    assert(j["tlsInfo"]["certIssuer"].get!string == "R11");
    assert(j["tlsInfo"]["certNotAfterMs"].get!long == 1_800_000_000_000);
    auto back = NetworkStateSnapshot.fromJson(j);
    assert(back.lagMs == 42);
    assert(back.connectedAtMs == 1_700_000_000_000);
    assert(back.hasTlsInfo);
    assert(back.tlsInfo == s.tlsInfo);
}

@("NetworkStateSnapshot omits tlsInfo when unset and defaults lag/connectedAt on legacy JSON")
unittest {
    NetworkStateSnapshot s;
    auto j = s.toJson();
    assert(j["tlsInfo"].type == Json.Type.undefined);
    assert(j["lagMs"].get!long == -1);
    assert(j["connectedAtMs"].get!long == 0);
    auto legacy = Json.emptyObject;
    legacy["connected"] = Json(true);
    auto back = NetworkStateSnapshot.fromJson(legacy);
    assert(back.lagMs == -1);
    assert(back.connectedAtMs == 0);
    assert(!back.hasTlsInfo);
    assert(back.tlsInfo == TlsInfo.init);
}

@("NetworkStateSnapshot dataAgeSecs/pongAgeSecs round-trip; legacy JSON defaults to 0")
unittest {
    NetworkStateSnapshot s;
    s.dataAgeSecs = 95;
    s.pongAgeSecs = 61;
    auto j = s.toJson();
    assert(j["dataAgeSecs"].get!long == 95);
    assert(j["pongAgeSecs"].get!long == 61);
    auto back = NetworkStateSnapshot.fromJson(j);
    assert(back.dataAgeSecs == 95);
    assert(back.pongAgeSecs == 61);
    // Pre-change snapshot without the fields: no throw, ages read 0.
    auto legacy = Json.emptyObject;
    legacy["connected"] = Json(true);
    auto legacyBack = NetworkStateSnapshot.fromJson(legacy);
    assert(legacyBack.dataAgeSecs == 0);
    assert(legacyBack.pongAgeSecs == 0);
}

@("RedisKeys notification helpers build the contract key names")
unittest {
    assert(RedisKeys.notifyClaim("u1", "m1") == "irc:notify:claim:u1:m1");
    assert(RedisKeys.pushBadge("u1") == "irc:push:badge:u1");
    assert(RedisKeys.notifyTraceIndex("u1") == "irc:notify:traces:u1");
    assert(RedisKeys.notifyTrace("u1") == "irc:notify:trace:u1");
    assert(RedisKeys.notifyOutcome("u1") == "irc:notify:outcome:u1");
    assert(RedisKeys.notifyHeld("u1") == "irc:notify:held:u1");
    assert(RedisKeys.notifySummaryDue() == "irc:notify:summary:due");
    assert(RedisKeys.notifyDmTimes("u1", "n1", "bob") == "irc:notify:dm:u1:n1:bob");
    assert(RedisKeys.notifyCoalesce("u1", "h") == "irc:notify:co:u1:h");
    assert(RedisKeys.notifyCoalesceCount("u1", "h") == "irc:notify:co:u1:h:n");
    assert(RedisKeys.notifyEmailDue() == "irc:notify:email:due");
    assert(RedisKeys.notifyEmailItems("u1") == "irc:notify:email:items:u1");
    assert(RedisKeys.notifyEmailLast("u1") == "irc:notify:email:last:u1");
    assert(RedisKeys.notifyUnsub("tok") == "notify:unsub:tok");
    assert(RedisKeys.notifyServerUsers() == "irc:notify:server-users");
    assert(RedisKeys.notifyLive("u1") == "irc:notify:live:u1");
    assert(RedisKeys.notifyHealth("u1") == "irc:notify:health:u1");
    assert(RedisKeys.notifyRate("patch", "u1") == "irc:notify:rl:patch:u1");
    assert(RedisKeys.notifyEmailSwitch() == "irc:config:notifyEmail");
    assert(RedisKeys.notifyWebPushSwitch() == "irc:config:notifyWebPush");
}
