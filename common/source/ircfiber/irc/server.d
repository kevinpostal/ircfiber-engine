module ircfiber.irc.server;

import std.uuid : UUID;
import std.conv : to;
import std.datetime : Clock;
import std.array : split, join;
import vibe.data.json : Json, serializeToJson;
/**
 * Decentralized Connection Server Model
 * 
 * Following IRCCloud's architecture, each connection server has:
 * - A unique server ID for namespacing
 * - A dedicated outbound IP address (for IRC network whitelisting)
 * - Local buffer storage (prevents cross-server ID collisions)
 * - Independent health status
 * 
 * Invariant: serverId is non-empty and unique across the cluster.
 * Invariant: bindAddress is a valid IPv4/IPv6 address.
 * Invariant: bufferOffset >= 0, incremented atomically per server.
 * 
 * Reference: IRCCloud blog post on decentralization (2020)
 */
struct ConnectionServer {
    /// Unique server identifier.
    string serverId;           // Unique identifier (e.g., "hathersage", "stonehaven")
    /// Outbound IP address for IRC connections.
    string bindAddress;        // Outbound IP for IRC connections
    /// Local admin port.
    ushort port;               // Optional: local admin port
    /// Current health status.
    bool isHealthy;            // Current health status
    /// Unix timestamp of last heartbeat (ms).
    long lastHeartbeat;        // Unix timestamp ms
    /// Monotonic buffer ID counter.
    long bufferOffset;         // Monotonic buffer ID counter (prevents collision)
    /// Network IDs assigned to this server.
    string[] assignedNetworks; // Network IDs assigned to this server

    /// Admin routing priority (higher = preferred for new assignments).
    int priority;
    /// Admin max connections per IRC host on this engine (0 = unlimited).
    int maxConnections;
    /// Admin flag: only assign networks when no other healthy server exists.
    bool fallbackOnly;
    /// Whether the engine is in draining state (handoff in progress, about to exit).
    /// Set by markDraining() during graceful handoff; cleared by the next heartbeat.
    bool draining;

    /// Network IDs whose IRC registration timed out
    /// (REGISTRATION_OVERALL_TIMEOUT_SECS exceeded without 001). Surface so
    /// the admin SPA can distinguish "stuck in registration" from
    /// "still resolving DNS" — two root causes with two fixes.
    /// Populated by the heartbeat loop from
    /// `ConnectionManager.networksAwaitingRegistration()`.
    string[] registrationUnavailableFor;

    /// Git commit hash of the code this server is running (40 hex).
    string gitHash;
    /// Short git hash (7-12 hex).
    string gitShort;
    /// Git describe (e.g. 5b35f90-dirty, v0.3.0-12-gd8b3d21).
    string gitDescribe;
    /// Git branch.
    string gitBranch;
    /// Build time ISO8601 UTC.
    string buildTime;
    /// Version string (e.g. 0.3.0).
    string version_;
    /// Serializes to JSON.
    Json toJson() const {
        auto j = Json.emptyObject;
        j["serverId"] = Json(serverId);
        j["bindAddress"] = Json(bindAddress);
        j["port"] = Json(port);
        j["isHealthy"] = Json(isHealthy);
        j["lastHeartbeat"] = Json(lastHeartbeat);
        j["bufferOffset"] = Json(bufferOffset);
        j["assignedNetworks"] = serializeToJson(assignedNetworks);
        j["priority"] = Json(priority);
        j["maxConnections"] = Json(maxConnections);
        j["fallbackOnly"] = Json(fallbackOnly);
        j["draining"] = Json(draining);
        j["registrationUnavailableFor"] = serializeToJson(registrationUnavailableFor);
        if (gitHash.length) j["gitHash"] = Json(gitHash);
        if (gitShort.length) j["gitShort"] = Json(gitShort);
        if (gitDescribe.length) j["gitDescribe"] = Json(gitDescribe);
        if (gitBranch.length) j["gitBranch"] = Json(gitBranch);
        if (buildTime.length) j["buildTime"] = Json(buildTime);
        if (version_.length) j["version"] = Json(version_);
        return j;
    }

    /// Deserializes from JSON.
    static ConnectionServer fromJson(Json j) {
        ConnectionServer s;
        if (j["serverId"].type != Json.Type.undefined) s.serverId = j["serverId"].get!string;
        if (j["bindAddress"].type != Json.Type.undefined) s.bindAddress = j["bindAddress"].get!string;
        if (j["port"].type != Json.Type.undefined) s.port = cast(ushort) j["port"].get!int;
        if (j["isHealthy"].type != Json.Type.undefined) s.isHealthy = j["isHealthy"].get!bool;
        if (j["lastHeartbeat"].type != Json.Type.undefined) {
            try {
                if (j["lastHeartbeat"].type == Json.Type.string)
                    s.lastHeartbeat = j["lastHeartbeat"].get!string.to!long;
                else s.lastHeartbeat = j["lastHeartbeat"].get!long;
            } catch (Exception) {}
        }
        if (j["bufferOffset"].type != Json.Type.undefined) s.bufferOffset = j["bufferOffset"].get!long;
        if (j["assignedNetworks"].type != Json.Type.undefined) {
            foreach (item; j["assignedNetworks"]) s.assignedNetworks ~= item.get!string;
        }
        if (j["priority"].type != Json.Type.undefined) s.priority = j["priority"].get!int;
        if (j["maxConnections"].type != Json.Type.undefined) s.maxConnections = j["maxConnections"].get!int;
        if (j["fallbackOnly"].type != Json.Type.undefined) s.fallbackOnly = j["fallbackOnly"].get!bool;
        if (j["draining"].type != Json.Type.undefined) s.draining = j["draining"].get!bool;
        if (j["registrationUnavailableFor"].type != Json.Type.undefined) {
            foreach (item; j["registrationUnavailableFor"]) s.registrationUnavailableFor ~= item.get!string;
        }
        if (j["gitHash"].type != Json.Type.undefined) s.gitHash = j["gitHash"].get!string;
        if (j["gitShort"].type != Json.Type.undefined) s.gitShort = j["gitShort"].get!string;
        if (j["gitDescribe"].type != Json.Type.undefined) s.gitDescribe = j["gitDescribe"].get!string;
        if (j["gitBranch"].type != Json.Type.undefined) s.gitBranch = j["gitBranch"].get!string;
        if (j["buildTime"].type != Json.Type.undefined) s.buildTime = j["buildTime"].get!string;
        if (j["version"].type != Json.Type.undefined) s.version_ = j["version"].get!string;
        else if (j["version_"].type != Json.Type.undefined) s.version_ = j["version_"].get!string;
        return s;
    }
}

/**
 * Server ID with namespace for buffer isolation.
 * 
 * Format: "<serverId>:<networkId>:<bufferName>"
 * Example: "hathersage:550e8400-e29b-41d4-a716-446655440000:#general"
 * 
 * This prevents the IRCCloud 2020 data leak scenario where buffer IDs
 * from different servers collided in shared storage.
 */
struct NamespacedBufferId {
    /// Server identifier.
    string serverId;
    /// Network identifier.
    string networkId;
    /// Buffer name.
    string bufferName;
    
    string toString() const {
        return serverId ~ ":" ~ networkId ~ ":" ~ bufferName;
    }
    
    /// Parses a namespaced buffer ID string.
    static NamespacedBufferId parse(string id) {
        auto parts = id.split(":");
        if (parts.length < 3) {
            throw new Exception("Invalid namespaced buffer ID: " ~ id);
        }
        return NamespacedBufferId(parts[0], parts[1], parts[2 .. $].join(":"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Draining field serialisation tests
// ═══════════════════════════════════════════════════════════════════════════
unittest {
    // Test 1: default draining is false
    auto s = ConnectionServer.init;
    assert(s.draining == false, "default draining should be false");

    // Test 2: toJson includes draining field
    s.serverId = "test-server";
    s.draining = true;
    auto j = s.toJson();
    assert("draining" in j, "toJson should include draining field");
    assert(j["draining"].get!bool == true, "draining should be true in JSON");

    // Test 3: fromJson restores draining field
    auto restored = ConnectionServer.fromJson(j);
    assert(restored.draining == true, "fromJson should restore draining=true");
    assert(restored.serverId == "test-server", "serverId should survive round-trip");

    // Test 4: draining=false round-trip
    s.draining = false;
    j = s.toJson();
    assert(j["draining"].get!bool == false, "draining should be false in JSON");
    restored = ConnectionServer.fromJson(j);
    assert(restored.draining == false, "fromJson should restore draining=false");

    // Test 5: JSON without draining field defaults to false (backward compat)
    import vibe.data.json : parseJsonString;
    auto oldJson = parseJsonString(`{"serverId":"old-server","isHealthy":true}`);
    const oldServer = ConnectionServer.fromJson(oldJson);
    assert(oldServer.draining == false, "missing draining field should default to false");

    // Test 6: full round-trip preserves all fields
    s = ConnectionServer(
        "full-test",     // serverId
        "10.0.0.1",      // bindAddress
        8091,            // port
        true,            // isHealthy
        1_000_000,       // lastHeartbeat
        42,              // bufferOffset
        ["net1", "net2"], // assignedNetworks
        10,              // priority
        100,             // maxConnections
        false,           // fallbackOnly
        true             // draining
    );
    j = s.toJson();
    restored = ConnectionServer.fromJson(j);
    assert(restored.serverId == "full-test");
    assert(restored.bindAddress == "10.0.0.1");
    assert(restored.port == 8091);
    assert(restored.isHealthy == true);
    assert(restored.lastHeartbeat == 1_000_000);
    assert(restored.bufferOffset == 42);
    assert(restored.assignedNetworks.length == 2);
    assert(restored.assignedNetworks[0] == "net1");
    assert(restored.assignedNetworks[1] == "net2");
    assert(restored.priority == 10);
    assert(restored.maxConnections == 100);
    assert(restored.fallbackOnly == false);
    assert(restored.draining == true);
}

/**
 * Network-to-Server assignment mapping.
 * 
 * Stored in Redis for gateway routing decisions.
 * Gateway reads this to route commands to the correct connection server.
 */
struct NetworkAssignment {
    /// Network identifier.
    string networkId;
    /// Server identifier.
    string serverId;
    /// Unix timestamp of assignment (ms).
    long assignedAt;
    
    /// Serializes to JSON.
    Json toJson() const {
        auto j = Json.emptyObject;
        j["networkId"] = Json(networkId);
        j["serverId"] = Json(serverId);
        j["assignedAt"] = Json(assignedAt);
        return j;
    }
}
