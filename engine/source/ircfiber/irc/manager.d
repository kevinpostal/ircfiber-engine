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
import ircfiber.engine.holder_client : HolderClient, HolderEntry, AttachResult;
import ircfiber.engine.session_snapshot : SessionSnapshot;
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
        /// Client of this engine's connection holder (null only in tests).
        HolderClient holder;
        /// Networks removed on this engine, `networkId` → unix ms.
        ///
        /// Stopping a client emits its farewell events (the QUIT echo and
        /// the server's `ERROR :Quit:`) into the shared event channel, and
        /// the processor persists whatever it drains — AFTER the delete path
        /// has cleared that network's scrollback. The result was a deleted
        /// network keeping a `_server` and `#channel` buffer, which is how
        /// its rooms stayed renderable at /irc/<name>/channel/%23chan long
        /// after the sidebar dropped it. The processor consults this map and
        /// drops those events instead.
        long[string] removedAtMs;
    }

    /// Creates a new connection manager with the given event channel.
    this(Channel!IRCRawEvent eventChannel, RedisStorage redisStore = null, string sid = "",
         HolderClient holderClient = null) nothrow @safe {
        this.mainEventChannel = eventChannel;
        this.redis = redisStore;
        this.serverId = sid;
        this.holder = holderClient;
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

        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId, holder);
        clients[key] = client;
        networkOwners[key] = userId;
        removedAtMs.remove(key);
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

        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId, holder);
        clients[key] = client;
        networkOwners[key] = userId;
        client.start();
        // Re-adding clears the removal marker (reconnectNetwork removes and
        // immediately re-adds), or every event of the new client would be
        // dropped as belonging to a deleted network.
        removedAtMs.remove(key);
    }

    /// Starts IRC clients for all networks that were added via addNetwork.
    /// Clients attached to a held connection are already running.
    void startDeferredClients() {
        foreach (key, client; clients) {
            if (client.getConnected) continue;
            client.start();
            logInfo("Started IRC client for %s", client.getConfig.name);
        }
    }

    /// Removes a network and stops its IRC client.
    void removeNetwork(UUID networkId) {
        auto key = networkId.toString();
        // Marked before `stop()`: stopping is what emits the QUIT/ERROR
        // farewell into the shared event channel, and those must already be
        // droppable by the time the processor drains them.
        removedAtMs[key] = Clock.currTime.toUnixTime!long * 1000;
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

    /// How long a removal is remembered. Long enough to outlive the event
    /// pipeline draining a stopped client's farewell, short enough that an
    /// id re-added later (a network recreated with the same UUID by a
    /// restore) is not silenced. `addNetwork`/`addAndStartNetwork` clear the
    /// marker explicitly, so this is only a backstop.
    private enum long REMOVED_MEMORY_MS = 60_000;

    /// True when this network was removed here and its trailing events must
    /// not be persisted or published. Prunes stale entries as it goes.
    bool isRemoved(string networkId) {
        if (networkId.length == 0) return false;
        const now = Clock.currTime.toUnixTime!long * 1000;
        auto at = networkId in removedAtMs;
        if (at is null) return false;
        if (now - *at > REMOVED_MEMORY_MS) {
            removedAtMs.remove(networkId);
            return false;
        }
        return true;
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
            client.transportClose("egress retargeted");
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

    /// Decommission: QUIT every network, wait briefly for the servers to
    /// close (so the holder sees upstream EOF and the UI gets the final
    /// `ERROR :Closing Link`), then close whatever is still open through
    /// the holder explicitly. Must run inside the event loop (the signal
    /// watcher task drives it): the upstream sockets live in the holder
    /// process, so nothing closes them "on exit" any more.
    void shutdown() {
        import vibe.core.core : sleep;
        import core.time : msecs;
        foreach (client; clients) {
            client.stop();
        }
        foreach (_; 0 .. 30) {
            bool anyAlive;
            foreach (client; clients) if (client.transportAlive) { anyAlive = true; break; }
            if (!anyAlive) break;
            sleep(100.msecs);
        }
        foreach (client; clients) {
            try client.transportClose();
            catch (Exception e) logWarn("shutdown: closing %s failed: %s", client.getConfig.name, e.msg);
        }
        clients = null;
        networkOwners = null;
    }

    // ── Hot-swap API (engine SIGTERM) ────────────────────────────────────────

    /// Pause every client's event loop so the detach can publish an exact
    /// snapshot of per-connection state. After this returns, no client is
    /// performing I/O on its relay stream. Returns the clients paused so
    /// the caller can iterate them in the same order.
    PersistentIRCClient[] pauseAllForDetach() {
        PersistentIRCClient[] paused;
        foreach (key, client; clients) {
            client.pauseForDetach();
            paused ~= client;
        }
        // Give every event loop a chance to observe the pause. The loops
        // check the counter at the next yield checkpoint; with
        // PROCESS_READ_TIMEOUT_MS = 50ms worst case we wait a bit longer
        // than that to be safe.
        foreach (client; paused) {
            client.waitForDetachPause();
        }
        return paused;
    }

    /// Hot-swap detach of every client: publish META, close the relay
    /// streams, leave every upstream socket with the holder. No QUIT, no
    /// DISCONNECTED events. Bounded (each META write has a 10 s holder
    /// timeout; the process exits right after this returns).
    void detachAllForHotSwap() {
        auto paused = pauseAllForDetach();
        size_t live;
        foreach (client; paused) {
            try {
                if (client.getConnected) live++;
                client.detachForHotSwap();
            } catch (Exception e) {
                logWarn("detachForHotSwap failed for %s: %s", client.getConfig.name, e.msg);
            }
        }
        logJsonMap("info", "connection",
            "Detached all networks for hot swap",
            ["clients": paused.length.to!string,
             "live": live.to!string,
             "event": "detach_all"]);
    }

    /// Attach a network to a connection the holder kept across the engine
    /// restart (planned hot swap or crash). Creates the client exactly like
    /// `addNetwork`, attaches, and restores `snapshot`. `ERR busy` means
    /// another engine process still holds the relay (a slow shutdown of
    /// the previous engine): the client stays `disconnected` and retries
    /// the attach every 5 s — it never dials fresh while an open entry
    /// exists for the network, that would double-socket the server. Any
    /// other attach error falls back to a fresh dial.
    void attachNetwork(NetworkConfig config, UUID userId, HolderEntry entry, SessionSnapshot snapshot) {
        import ircfiber.engine.holder_client : HolderErrorException, HolderUnavailableException;
        import vibe.core.core : runTask, sleep;
        import core.time : seconds;
        auto key = config.id.toString();
        if (key in clients) {
            logWarn("Network %s already managed", config.name);
            return;
        }
        auto client = new PersistentIRCClient(config, mainEventChannel, redis, serverId, userId, holder);
        clients[key] = client;
        networkOwners[key] = userId;
        removedAtMs.remove(key);

        bool tryAttach() {
            AttachResult r;
            try {
                r = holder.attach(entry.id);
            } catch (HolderErrorException e) {
                if (e.code == "busy") {
                    logJsonMap("error", "connection", "Another engine holds this connection — not dialing",
                        ["network": config.name, "holderId": entry.id, "event": "attach_busy"]);
                    client.emitLog("error", "Another engine holds this connection — not dialing");
                    return false;
                }
                logJsonMap("warn", "connection", "Attach failed — dialing fresh",
                    ["network": config.name, "holderId": entry.id, "code": e.code, "err": e.msg,
                     "event": "attach_fail"]);
                client.start();
                return true;
            } catch (Exception e) {
                logJsonMap("warn", "connection", "Attach failed — dialing fresh",
                    ["network": config.name, "holderId": entry.id, "err": e.msg, "event": "attach_fail"]);
                client.start();
                return true;
            }
            client.attachHeld(r, snapshot, snapshot.graceful);
            return true;
        }

        if (tryAttach()) return;
        runTask(() nothrow {
            while (true) {
                try sleep(5.seconds); catch (Exception) {}
                if (key !in clients || clients[key] !is client) return;
                bool done;
                try done = tryAttach();
                catch (Exception e) {
                    string m; try { m = e.msg; } catch (Exception) { m = "unknown"; }
                    try logWarn("attach retry for %s failed: %s", config.name, m); catch (Exception) {}
                }
                if (done) return;
            }
        });
    }
}
