module ircfiber.irc.manager;

import std.uuid : UUID;
import std.conv : to;
import std.string : toStringz;

import vibe.core.channel : Channel;
import vibe.core.log;

import ircfiber.models.irc_event : IRCRawEvent;
import ircfiber.models.network : Network, NetworkConfig;
import ircfiber.irc.connection : PersistentIRCClient;
import ircfiber.storage.redis : RedisStorage;
import ircfiber.engine.handoff : HandoffState;
import ircfiber.redis.protocol : RedisKeys;
import ircfiber.logging : logJsonMap;
import std.uuid : parseUUID;
import vibe.data.json : Json;
import std.datetime : Clock;

/// Per-host circuit breaker state. Tracks consecutive failures to the
/// same host so we don't hammer unresponsive servers (getting us banned).
private struct HostCircuitBreaker {
    /// Number of consecutive failures since last success.
    int failCount;
    /// Unix-ms timestamp when the circuit was last tripped (opened).
    /// 0 = circuit is closed (normal operation).
    long openedAt;
    /// Unix-ms of the most recent attempt.
    long lastAttemptAt;
}

/// Manages IRC network connections for users.
final class ConnectionManager {
    private {
        PersistentIRCClient[string] clients;
        Channel!IRCRawEvent mainEventChannel;
        UUID[string] networkOwners;
        RedisStorage redis;
        string serverId;
        /// Per-host circuit breakers for smart rate limiting.
        /// Keyed by host:port string (e.g. "irc.supernets.org:6697").
        HostCircuitBreaker[string] hostBreakers;
        // TLS handoff records received during the handoff protocol.
        // We defer the soft-reconnect until after the protocol's DONE
        // marker, so the OLD engine can synchronously QUIT its live
        // TLS socket before we attempt NICK (otherwise we collide and
        // get a `_` suffix on every hot reload — bug Jul 4 2026).
        HandoffRecord[] pendingHandoffRecords;
    }

    /// Creates a new connection manager with the given event channel.
    this(Channel!IRCRawEvent eventChannel, RedisStorage redisStore = null, string sid = "") nothrow @safe {
        this.mainEventChannel = eventChannel;
        this.redis = redisStore;
        this.serverId = sid;
    }

    /// Networks whose IRC registration timed out (REGISTRATION_OVERALL_TIMEOUT_SECS
    /// elapsed without 001 being received from the server). Returns
    /// networkIds whose client.getRegistrationTimeoutSince() > 0.
    /// Surfaced to the admin SPA via the per-server health snapshot so
    /// operators can distinguish "this network is stuck in registration"
    /// from "this network has a slow DNS" — two different root causes
    /// with two different fixes.
    string[] networksAwaitingRegistration() const {
        string[] result;
        foreach (key, client; clients) {
            if (client.getRegistrationTimeoutSince > 0)
                result ~= key;
        }
        return result;
    }

    /// Adds a network for a user and starts its IRC client.
    void addNetwork(NetworkConfig config, UUID userId) {
        auto key = config.id.toString();
        if (key in clients) {
            logWarn("Network %s already managed", config.name);
            return;
        }

        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId);
        clients[key] = client;
        networkOwners[key] = userId;
        // Defer start() to avoid runTask() inside the bootstrap loop.
        // The caller must call startDeferredClients() after all networks
        // are loaded.
    }

    /// Adds a network and starts its IRC client immediately.
    /// Used when a single network needs to start outside the bootstrap loop
    /// (e.g. reconnectNetwork control message).
    void addAndStartNetwork(NetworkConfig config, UUID userId) {
        auto key = config.id.toString();
        if (key in clients) {
            logWarn("Network %s already managed", config.name);
            return;
        }

        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId);
        clients[key] = client;
        networkOwners[key] = userId;
        client.start();
    }

    /// Starts IRC clients for all networks that were added via addNetwork.
    void startDeferredClients() {
        foreach (key, client; clients) {
            client.start();
            logInfo("Started IRC client for %s", client.getConfig.name);
        }
    }

    /// Removes a network and stops its IRC client.
    void removeNetwork(UUID networkId) {
        auto key = networkId.toString();
        if (auto p = key in clients) {
            (*p).stop();
            // Mirror MongoDB's disabled flag into the in-memory config
            // so the connection loop's top-of-iteration `config.disabled`
            // check sees the admin's intent without waiting for a
            // process restart to reload from MongoDB.
            (*p).getConfig().disabled = true;
            clients.remove(key);
            networkOwners.remove(key);
        }
    }

    /// Disconnects a network without removing it. If `quitReason` is set
    /// the engine will send `QUIT :<reason>` before closing the socket so
    /// the IRC server emits a final ERROR back to the client.
    void disconnectNetwork(UUID networkId, string quitReason = "") {
        const key = networkId.toString();
        if (auto p = key in clients) {
            (*p).stop(quitReason);
        }
    }

    /// Drops the transport of every network currently egressing through the
    /// named Mullvad slot, so each one's own reconnect loop re-dials and
    /// re-runs egress selection — landing on the slot's new exit.
    ///
    /// Used after an operator force-swaps a slot that was carrying
    /// connections. Without it those sockets keep pointing at a relay the
    /// sidecar no longer routes through: nothing errors, the connection just
    /// goes quiet until the server's ping timeout minutes later. A deliberate
    /// close turns that into a ~5 s reconnect.
    int bounceNetworksOnEgress(string egressLabel) {
        if (egressLabel.length == 0) return 0;
        int bounced = 0;
        foreach (id, client; clients) {
            if (client is null) continue;
            if (client.getActiveEgressLabel != egressLabel) continue;
            if (!client.getConnected) continue;
            logInfo("Egress swap: bouncing %s so it re-dials through the new exit",
                client.getConfig.name);
            client.transportClose();
            bounced++;
        }
        return bounced;
    }

    PersistentIRCClient getClient(UUID networkId) {
        const key = networkId.toString();
        if (auto p = key in clients) {
            return *p;
        }
        return null;
    }

    Network[] getNetworks() {
        Network[] result;
        foreach (client; clients) {
            Network net;
            net.config = client.getConfig;
            net.isConnected = client.getConnected;
            net.status = client.getState.to!string;
            net.currentNick = client.getCurrentNick;
            result ~= net;
        }
        return result;
    }

    Network[] getNetworksForUser(UUID userId) {
        Network[] result;
        foreach (id, client; clients) {
            if (networkOwners.get(id, UUID.init) == userId) {
                Network net;
                net.config = client.getConfig;
                net.isConnected = client.getConnected;
                net.status = client.getState.to!string;
                net.currentNick = client.getCurrentNick;
                result ~= net;
            }
        }
        return result;
    }

    string[] getJoinedChannels(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getJoinedChannels;
        }
        return [];
    }

    /// Record a connection failure to a host. After FAIL_THRESHOLD consecutive
    /// failures within the window, the circuit opens for COOLDOWN_MS.
    void recordHostFailure(string host, int port) {
        auto key = host ~ ":" ~ port.to!string;
        auto now = Clock.currTime.toUnixTime!long * 1000;
        auto breaker = key in hostBreakers;
        if (breaker !is null) {
            // Reset window if too much time passed since last attempt
            if (now - breaker.lastAttemptAt > HOST_CIRCUIT_WINDOW_MS) {
                breaker.failCount = 0;
                breaker.openedAt = 0;
            }
            breaker.failCount++;
            breaker.lastAttemptAt = now;
            if (breaker.failCount >= HOST_FAIL_THRESHOLD && breaker.openedAt == 0) {
                breaker.openedAt = now;
                logWarn("Host circuit breaker OPENED for %s after %d failures (cooling down %d ms)",
                    key, breaker.failCount, HOST_COOLDOWN_MS);
            }
        } else {
            hostBreakers[key] = HostCircuitBreaker(1, 0, now);
        }
    }

    /// Record a successful connection — resets the breaker for this host.
    void recordHostSuccess(string host, int port) {
        auto key = host ~ ":" ~ port.to!string;
        if (auto breaker = key in hostBreakers) {
            if (breaker.openedAt > 0) {
                logInfo("Host circuit breaker CLOSED for %s (connection succeeded)", key);
            }
            hostBreakers.remove(key);
        }
    }

    /// Check if the circuit breaker allows a new connection attempt.
    /// Returns true if the connection is allowed, false if cooling down.
    bool canConnectToHost(string host, int port) {
        auto key = host ~ ":" ~ port.to!string;
        if (auto breaker = key in hostBreakers) {
            if (breaker.openedAt > 0) {
                const now = Clock.currTime.toUnixTime!long * 1000;
                if (now - breaker.openedAt < HOST_COOLDOWN_MS) {
                    return false;
                }
                // Cooldown expired — close the circuit (reset for next cycle)
                hostBreakers.remove(key);
                logInfo("Host circuit breaker CLOSED for %s (cooldown expired)", key);
            }
        }
        return true;
    }

    /// Time window for counting failures (rolling 30 minutes).
    private static immutable HOST_CIRCUIT_WINDOW_MS = 30 * 60 * 1000;
    /// Consecutive failures before opening the circuit.
    private static immutable HOST_FAIL_THRESHOLD = 5;
    /// Cooldown duration when circuit is open (30 minutes).
    private static immutable HOST_COOLDOWN_MS = 30 * 60 * 1000;

    string[string] getChannelTopics(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getChannelTopics;
        }
        return null;
    }

    string[][string] getChannelUsers(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getChannelUsers;
        }
        return null;
    }

    /// Returns the realname cache (nick → realname) for a network.
    /// IRCCloud parity: populated from extended-join (JOIN params[2]) and
    /// RPL_WHOISUSER (311). Used by the frontend to render
    /// <span class="author-realname"> next to the nick.
    string[string] getRealnames(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getRealnames;
        }
        return null;
    }

    string[string] getAccounts(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getAccounts;
        }
        return null;
    }

    string[string] getIdents(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getIdents;
        }
        return null;
    }

    /// Checks if a given IRCv3 capability is negotiated for a network.
    bool hasCap(UUID networkId, string cap) {
        if (auto client = getClient(networkId)) {
            return client.hasCap(cap);
        }
        return false;
    }

    /// Returns all negotiated capabilities for a network.
    string[] getAckedCaps(UUID networkId) {
        if (auto client = getClient(networkId)) {
            return client.getAckedCaps();
        }
        return [];
    }

    /// Sends a message to a target on a network.
    void sendMessage(UUID networkId, string target, string text) {
        if (auto client = getClient(networkId)) {
            client.sendMessage(target, text);
        }
    }

    /// Sends a labeled message to a target on a network.
    void sendLabeledMessage(UUID networkId, string target, string text, string label) {
        if (auto client = getClient(networkId)) {
            client.sendLabeledMessage(target, text, label);
        }
    }

    /// Sends an edit message using the draft/edit-message IRCv3 cap.
    void sendEditMessage(UUID networkId, string target, string originalLabel, string newBody) {
        if (auto client = getClient(networkId)) {
            client.sendEditMessage(target, originalLabel, newBody);
        }
    }

    /// Joins a channel on a network.
    void joinChannel(UUID networkId, string channel) {
        if (auto client = getClient(networkId)) {
            client.joinChannel(channel);
        }
    }

    /// Parts a channel on a network.
    void partChannel(UUID networkId, string channel, string reason = "") {
        if (auto client = getClient(networkId)) {
            client.partChannel(channel, reason);
        }
    }

    /// Sends a raw IRC line to a network.
    void sendRaw(UUID networkId, string line) {
        if (auto client = getClient(networkId)) {
            client.sendRaw(line);
        }
    }

    /// Issues a CHATHISTORY request on the named network. Silently no-ops
    /// if the network isn't connected, the client doesn't have the
    /// chathistory cap, or another request is in flight for the channel.
    void requestChathistory(UUID networkId, string channel, string command,
                            string refMsgid, int limit) {
        if (auto client = getClient(networkId)) {
            client.requestChathistory(channel, command, refMsgid, limit);
        }
    }

    /// Returns the latest msgid observed for the channel on the given network.
    string getLatestMsgid(UUID networkId, string channel) {
        if (auto client = getClient(networkId)) {
            return client.getLatestMsgid(channel);
        }
        return "";
    }

    /// Returns the earliest msgid observed for the channel on the given network.
    string getEarliestMsgid(UUID networkId, string channel) {
        if (auto client = getClient(networkId)) {
            return client.getEarliestMsgid(channel);
        }
        return "";
    }

    /// Information about a buffer (channel or query).
    struct BufferInfo {
        /// Buffer name.
        string name;
        /// Buffer type (channel, query, server).
        string type;
        /// Whether the buffer is currently joined.
        bool isJoined;
    }

    BufferInfo[] getBuffersForNetwork(UUID networkId) {
        BufferInfo[] result;
        result ~= BufferInfo("_server", "server", true);
        if (auto client = getClient(networkId)) {
            foreach (ch; client.getJoinedChannels) {
                result ~= BufferInfo(ch, "channel", true);
            }
            foreach (q; client.getQueryBuffers) {
                result ~= BufferInfo(q, "query", true);
            }
        }
        return result;
    }

    /// Clears unread count for a channel (frontend hook).
    void clearUnread(string _networkIdStr, string _channel) {
        cast(void)_networkIdStr;
        cast(void)_channel;
        // Unread tracking is handled entirely in the frontend
        // (see public/ircfiber.js incrementUnread / setActiveBuffer).
        // This method exists as a hook if engine-side tracking is ever needed.
    }

    /// Updates configuration for an existing network.
    void updateConfig(NetworkConfig config) {
        const key = config.id.toString();
        if (auto p = key in clients) {
            (*p).updateConfig(config);
        }
    }

    string getOwnerId(UUID networkId) {
        const key = networkId.toString();
        if (auto p = key in networkOwners) {
            return p.toString();
        }
        return "";
    }

    /// Checks if a network is managed by UUID.
    bool hasNetwork(UUID networkId) {
        return (networkId.toString() in clients) !is null;
    }

    /// Checks if a network is managed by string ID.
    bool hasNetwork(string networkIdStr) {
        return (networkIdStr in clients) !is null;
    }

    /// Shuts down all connections and clears state.
    void shutdown() {
        foreach (client; clients) {
            client.stop();
        }
        clients = null;
        networkOwners = null;
    }

    // ── Handoff API (engine reload) ──────────────────────────────────────────

    /// Pause every connected client's event loop so a handoff can
    /// capture a consistent snapshot of per-connection state. After
    /// this call returns, no client will be performing I/O on its
    /// socket. Caller MUST eventually call `resumeAllAfterHandoff()`
    /// (or the engine will hang). Returns the list of clients paused
    /// so the caller can iterate them in the same order.
    PersistentIRCClient[] pauseAllForHandoff() {
        PersistentIRCClient[] paused;
        foreach (key, client; clients) {
            client.pauseForHandoff();
            paused ~= client;
        }
        // Give every event loop a chance to observe the pause. The
        // loops check the counter at the next yield checkpoint; with
        // PROCESS_READ_TIMEOUT_MS = 50ms worst case we wait a bit
        // longer than that to be safe.
        foreach (client; paused) {
            client.waitForHandoffPause();
        }
        return paused;
    }

    /// Release every client previously paused by
    /// `pauseAllForHandoff()`. The clients resume I/O on the same
    /// sockets — except those that have been adopted by a new engine,
    /// which must be removed from the manager (via `removeNetwork`)
    /// *before* this call to avoid double-using the FD.
    void resumeAllAfterHandoff() {
        foreach (key, client; clients) {
            client.resumeAfterHandoff();
        }
    }

    /// Build a (state, rawFd) pair for every connected client that
    /// can be transferred (i.e. plain TCP, not TLS). TLS clients are
    /// skipped — the new engine will soft-reconnect them.
    HandoffRecord[] snapshotAllForHandoff() {
        HandoffRecord[] out_;
        foreach (key, client; clients) {
            auto state = client.snapshotForHandoff();
            // Override userId from the connection manager's authoritative
            // map. The client doesn't know its owner — only the manager
            // does via `networkOwners`. Without this fix, every handoff
            // silently corrupts event routing by setting `networkOwners`
            // to networkId→networkId instead of networkId→realUserUUID,
            // causing `getOwnerId()` to return the wrong UUID and events
            // to be published to the wrong Redis channel.
            if (auto p = key in networkOwners) {
                state.userId = (*p).toString();
            }
            int fd = -1;
            if (state.transportWasPlain) {
                fd = client.rawSocketFd();
                if (fd < 0) {
                    // Plain but not currently connected (e.g. mid-
                    // reconnect). Tell the new engine to soft-reconnect.
                    state.transportWasPlain = true;
                    state.wasConnected = false;
                }
            }
            out_ ~= HandoffRecord(state, fd);
        }
        return out_;
    }

    /// Mark every successfully handed-off client to QUIT and close
    /// after the handoff pause is released. Called by the OLD engine's
    /// `serveReload` after each record is ACK'd by the new engine.
    ///
    /// Without this, the OLD engine keeps its connection alive:
    ///   - Plain TCP: the FD was transferred via SCM_RIGHTS, so the
    ///     kernel-side socket is already gone in this process; the
    ///     loop would spin reading a dead FD.
    ///   - TLS: the FD was NOT transferred (TLS session state lives
    ///     in userspace), so the new engine soft-reconnects with the
    ///     same nick. The OLD engine's live TLS socket keeps the IRC
    ///     server's nick registration alive → next connect gets a
    ///     collision suffix (e.g. "Zod_").
    ///
    /// The flag is observed in `PersistentIRCClient.processEvents()`
    /// after `handoffPauseCount` drops to zero, so the QUIT goes out
    /// on the same socket before it closes — cleanly, no zombies.
    void notifyHandoffComplete(HandoffRecord[] records) {
        import std.datetime : Clock;
        auto now = Clock.currTime.toUnixTime!long * 1000;
        foreach (rec; records) {
            const key = rec.state.config.id.toString();
            if (auto p = key in clients) {
                // For TLS handoffs the FD was NOT transferred — the OLD
                // engine's live TLS socket still holds the IRC server's
                // nick registration. Synchronously write QUIT now so the
                // IRC server frees the nick BEFORE the new engine's
                // soft-reconnect claims it. Without this the new engine
                // races the OLD engine and falls back to a `_` suffix
                // (`Zodiac` → `Zodiac_` → `Zodiac__`).
                //
                // Plain-TCP records already transferred the FD via
                // SCM_RIGHTS; the OLD engine's socket is gone, so we
                // just schedule the post-pause cleanup flag.
                if (rec.fd < 0) {
                    (*p).forcePostHandoffQuit(now);
                    logInfo("Handoff: forced QUIT for TLS %s (live socket, fd not transferred)",
                        rec.state.config.name);
                } else {
                    (*p).schedulePostHandoffQuit(now);
                    logInfo("Handoff: scheduled QUIT for %s after handoff pause releases",
                        rec.state.config.name);
                }
                logJsonMap("info", "handoff",
                    "Post-handoff QUIT " ~ (rec.fd < 0 ? "forced" : "scheduled") ~
                        " for " ~ rec.state.config.name,
                    ["network": rec.state.config.name,
                     "sessionNick": rec.state.sessionNick,
                     "tls": (rec.fd < 0).to!string]);
            }
        }
    }

    /// Adopt a batch of handed-off connections. Each record contains
    /// a serialised `HandoffState` and (optionally) a raw fd; TLS
    /// records have fd == -1 and trigger a fresh `addNetwork` so
    /// the new engine does a normal registration dance for them.
    void adoptFromHandoff(HandoffRecord[] records) {
        foreach (rec; records) {
            HandoffState s = rec.state;
            if (rec.fd < 0) {
                // TLS / non-plain: queue the record so the soft-reconnect
                // starts AFTER the handoff protocol completes. This is
                // critical — if we soft-reconnect per-record, our NICK
                // races the OLD engine's still-live TLS socket on the
                // IRC server, hits 433, and falls back to a `_` suffix.
                // The OLD engine's `notifyHandoffComplete` (called after
                // the last ACK) now synchronously sends QUIT on its live
                // TLS socket; `startPendingHandoffReconnects()` (called
                // after we receive DONE) drains this queue.
                logInfo("Handoff: TLS network %s queued for reconnect after handoff DONE (was nick=%s)",
                    s.config.name, s.sessionNick);
                pendingHandoffRecords ~= rec;
                // Publish a synthetic DISCONNECTED event so the UI shows
                // the brief transition before reconnecting.
                try mainEventChannel.put(IRCRawEvent.makeDisconnected(
                    s.config.name, s.config.id.toString(),
                    "TLS connection requires soft-reconnect during engine hot-reload"));
                catch (Exception) {}
                continue;
            }
            // Plain: build a fresh client wrapping the adopted fd.
            auto key = s.config.id.toString();
            auto client = new PersistentIRCClient(s.config, mainEventChannel, redis, serverId);
            clients[key] = client;
            networkOwners[key] = parseUUID(s.userId.length ? s.userId : s.config.id.toString());
            client.adoptAndStart(rec.fd, s);
        }
    }

    /// Drain TLS handoff records queued by `adoptFromHandoff`. Called
    /// from `adoptFromOldEngine` after the protocol's DONE marker is
    /// received — by then the OLD engine has synchronously sent QUIT
    /// on its live TLS sockets (via `notifyHandoffComplete`), so the
    /// IRC server has freed the nicks. Safe to start our soft-reconnects
    /// now without colliding.
    void startPendingHandoffReconnects() {
        if (pendingHandoffRecords.length == 0) {
            logInfo("Handoff: no pending TLS reconnects to drain");
            return;
        }
        logInfo("Handoff: draining %d pending TLS reconnect(s)", pendingHandoffRecords.length);
        foreach (rec; pendingHandoffRecords) {
            HandoffState s = rec.state;
            // Mirror the original TLS soft-reconnect logic from
            // adoptFromHandoff. Keep them in lock-step so any future
            // change to the TLS soft-reconnect path applies to both
            // code paths (cold-start via handoff and any future
            // re-drain paths).
            auto cfg = s.config;
            // NOTE: we deliberately do NOT overwrite `cfg.nick` with
            // `s.sessionNick` here. That would propagate a 433 collision
            // fallback (e.g. `Zodiac__`) back into the in-memory config,
            // and on the next cold reconnect the engine would use the
            // fallback as its starting nick — locking the user out of
            // their intended nick once it frees up. The new client will
            // start from `cfg.nick` (the user's configured value) and
            // re-derive `requestedNick` from it; if a 433 fallback occurs
            // the new connection.d logic detects it via `requestedNick`
            // and clears the persisted nick instead of locking it in.
            try {
                auto db = redis.getDb();
                db.del(RedisKeys.networkNick(cfg.id.toString()));
            } catch (Exception) {}
            const uid = parseUUID(s.userId.length ? s.userId : s.config.id.toString());
            // Schedule the soft-reconnect on a separate fiber so we can
            // apply a brief settling delay. The OLD engine's QUIT
            // (synchronously written by `notifyHandoffComplete`) is
            // on the wire before we reach this point, but the IRC
            // server's processing latency plus our TCP+TLS handshake
            // time mean a back-to-back NICK could still hit 433 on a
            // busy network. 500ms gives the server ample time to
            // release the nick registration and propagate the QUIT
            // ERROR + socket close back to the OLD engine (which is
            // also exiting via the postHandoffQuitAtMs early-check
            // in `processEvents`).
            import vibe.core.core : runTask, sleep;
            import core.time : msecs;
            string netName = cfg.name;
            string netNick = cfg.nick;
            UUID netUserId = uid;
            NetworkConfig netCfg = cfg;
            void scheduleReconnect() nothrow {
                try {
                    try sleep(500.msecs); catch (Exception) {}
                    logInfo("Handoff: TLS network %s soft-reconnecting via new engine (nick=%s)",
                        netName, netNick);
                    addAndStartNetwork(netCfg, netUserId);
                } catch (Exception e) {
                    logWarn("Handoff: failed to soft-reconnect %s: %s", netName, e.msg);
                }
            }
            try runTask(&scheduleReconnect);
            catch (Exception e) logWarn("Handoff: failed to schedule reconnect for %s: %s", netName, e.msg);
        }
        pendingHandoffRecords = [];
    }
}

/// A single handoff record the manager consumes (state + optional
/// raw FD). Differs from the wire-format `HandoffRecord` in
/// `ircfiber.engine.handoff` — that one carries raw JSON + raw FDs;
/// this one carries parsed state ready for `adoptFromHandoff()`.
struct HandoffRecord {
    /// Parsed handoff state consumed by `adoptFromHandoff()`.
    HandoffState state;
    /// Raw file descriptor, or -1 for TLS / soft-reconnect records.
    int fd;
}
