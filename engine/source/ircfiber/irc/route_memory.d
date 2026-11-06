/// Bounded per-endpoint memory of which egress route last completed — or
/// failed — a full holder dial (TCP plus the configured TLS/STARTTLS).
///
/// Automatic egress orders exits by global policy (Mullvad tier rotation,
/// then static exits, then direct). That ranking knows nothing about a
/// particular IRC endpoint: a server can reject every connection from one
/// provider's address ranges while another exit, or the direct path, works.
/// This table records the outcome per endpoint (normalized host, port, TLS
/// mode) and per concrete route identity, so the next Automatic connect to
/// the same endpoint tries a route that recently proved itself first and a
/// route that recently failed last — never excluded, only deprioritized.
///
/// Pure and I/O-free; the caller owns locking (connection.d keeps the one
/// table under gMullvadLock with the rest of the egress state).
module ircfiber.irc.route_memory;

import std.algorithm : sort;

/// A completed dial keeps its route preferred for this long.
enum ROUTE_SUCCESS_TTL_MS = 30 * 60_000L;
/// A failed dial keeps its route at the back of the order for this long.
enum ROUTE_FAILURE_COOLDOWN_MS = 5 * 60_000L;
/// Hard caps: memory never grows past endpoints × routes entries.
enum ROUTE_MAX_ENDPOINTS = 512;
enum ROUTE_MAX_ROUTES_PER_ENDPOINT = 32;

/// Order class of one candidate route for one endpoint. Declaration order
/// is sort order.
enum RouteStanding : ubyte {
    /// Completed a full dial within ROUTE_SUCCESS_TTL_MS, no newer failure.
    preferred,
    /// No unexpired evidence either way.
    neutral,
    /// Failed within ROUTE_FAILURE_COOLDOWN_MS, no newer success.
    cooling,
}

/// Endpoint key: one IRC listener as the engine dials it. Port and TLS mode
/// are part of the key because a host can serve TLS on one port and reject
/// it on another, and STARTTLS and implicit TLS fail independently.
string routeEndpointKey(string hostLower, ushort port, string tlsMode) @safe pure {
    import std.conv : to;
    return hostLower ~ "|" ~ port.to!string ~ "|" ~ tlsMode;
}

/// One table instance. Not thread-safe: callers serialize every access.
struct RouteMemory {
    private struct Memo {
        /// Per-host ban key of the route (location id, `slot:<label>` or
        /// `direct`), so a ban can drop the memo it supersedes.
        string banKey;
        long atMs;
        bool ok;
    }
    private struct Endpoint {
        string hostLower;
        Memo[string] routes;
        /// Unix ms of the newest record; every memo's atMs is ≤ this.
        long touchedMs;
    }
    private Endpoint[string] endpoints;
    private long lastSweepMs;

    size_t endpointCount() const @safe pure nothrow @nogc { return endpoints.length; }

    size_t routeCount(string endpointKey) const @safe pure nothrow {
        if (auto ep = endpointKey in endpoints) return ep.routes.length;
        return 0;
    }

    /// Standing of `routeKey` for `endpointKey` at `nowMs`; `okAtMs` is the
    /// success time when preferred, else 0. Read-only: expiry is computed,
    /// cleanup happens on `record`. A timestamp from the future (clock step)
    /// is no evidence.
    RouteStanding standing(string endpointKey, string routeKey, long nowMs, out long okAtMs) const @safe pure nothrow {
        okAtMs = 0;
        auto ep = endpointKey in endpoints;
        if (ep is null) return RouteStanding.neutral;
        auto m = routeKey in ep.routes;
        if (m is null) return RouteStanding.neutral;
        return classify(*m, nowMs, okAtMs);
    }

    private static RouteStanding classify(const Memo m, long nowMs, out long okAtMs) @safe pure nothrow @nogc {
        okAtMs = 0;
        if (m.atMs > nowMs || expired(m, nowMs)) return RouteStanding.neutral;
        if (!m.ok) return RouteStanding.cooling;
        okAtMs = m.atMs;
        return RouteStanding.preferred;
    }

    private static bool expired(const Memo m, long nowMs) @safe pure nothrow @nogc {
        return nowMs - m.atMs >= (m.ok ? ROUTE_SUCCESS_TTL_MS : ROUTE_FAILURE_COOLDOWN_MS);
    }

    /// Records the outcome of one full dial. The newest outcome replaces the
    /// previous one for the same route. Enforces both caps and sweeps
    /// expired endpoints at most once per cooldown period.
    void record(string endpointKey, string hostLower, string routeKey, string banKey,
                bool ok, long nowMs) @safe pure nothrow {
        if (endpointKey.length == 0 || routeKey.length == 0) return;
        if (nowMs - lastSweepMs >= ROUTE_FAILURE_COOLDOWN_MS || lastSweepMs > nowMs) {
            lastSweepMs = nowMs;
            dropIdleEndpoints(nowMs);
        }
        auto ep = endpointKey in endpoints;
        if (ep is null) {
            if (endpoints.length >= ROUTE_MAX_ENDPOINTS) {
                dropIdleEndpoints(nowMs);
                if (endpoints.length >= ROUTE_MAX_ENDPOINTS) evictOldestEndpoint();
            }
            endpoints[endpointKey] = Endpoint(hostLower);
            ep = endpointKey in endpoints;
        }
        if (nowMs > ep.touchedMs) ep.touchedMs = nowMs;
        dropExpiredRoutes(*ep, nowMs);
        if (routeKey !in ep.routes && ep.routes.length >= ROUTE_MAX_ROUTES_PER_ENDPOINT)
            evictOldestRoute(*ep);
        ep.routes[routeKey] = Memo(banKey, nowMs, ok);
    }

    /// Forgets every memo of `hostLower` (all ports and TLS modes) whose
    /// route carries `banKey`: a host ban supersedes the dial evidence, and
    /// a success recorded before the ban must not promote the route once
    /// the ban expires.
    void forget(string hostLower, string banKey) @safe pure nothrow {
        if (hostLower.length == 0 || banKey.length == 0) return;
        string[] emptied;
        foreach (key; endpoints.byKey) {
            auto ep = key in endpoints;
            if (ep.hostLower != hostLower) continue;
            string[] dead;
            foreach (pair; ep.routes.byKeyValue) if (pair.value.banKey == banKey) dead ~= pair.key;
            foreach (route; dead) ep.routes.remove(route);
            if (ep.routes.length == 0) emptied ~= key;
        }
        foreach (key; emptied) endpoints.remove(key);
    }

    private static void dropExpiredRoutes(ref Endpoint ep, long nowMs) @safe pure nothrow {
        string[] dead;
        foreach (pair; ep.routes.byKeyValue)
            if (pair.value.atMs <= nowMs && expired(pair.value, nowMs)) dead ~= pair.key;
        foreach (route; dead) ep.routes.remove(route);
    }

    private static void evictOldestRoute(ref Endpoint ep) @safe pure nothrow {
        string oldest;
        long oldestAt = long.max;
        foreach (pair; ep.routes.byKeyValue)
            if (pair.value.atMs < oldestAt) { oldestAt = pair.value.atMs; oldest = pair.key; }
        if (oldest.length) ep.routes.remove(oldest);
    }

    /// An endpoint whose newest record is older than the longest TTL holds
    /// only expired memos.
    private void dropIdleEndpoints(long nowMs) @safe pure nothrow {
        string[] idle;
        foreach (pair; endpoints.byKeyValue)
            if (pair.value.touchedMs <= nowMs && nowMs - pair.value.touchedMs >= ROUTE_SUCCESS_TTL_MS)
                idle ~= pair.key;
        foreach (key; idle) endpoints.remove(key);
    }

    private void evictOldestEndpoint() @safe pure nothrow {
        string oldest;
        long oldestAt = long.max;
        foreach (pair; endpoints.byKeyValue)
            if (pair.value.touchedMs < oldestAt) { oldestAt = pair.value.touchedMs; oldest = pair.key; }
        if (oldest.length) endpoints.remove(oldest);
    }
}

/// Stable reorder of `items` and the aligned `routeKeys` by their standing
/// for `endpointKey`: preferred (newest success first), then neutral, then
/// cooling, each class keeping its incoming order. `promotable(i)` false
/// caps item i at neutral (the caller's avoided exit is never promoted, but
/// a recent failure still demotes it). One allocation per call when the
/// endpoint has memos; none otherwise. Every item stays in the result.
void rankByRouteMemory(T)(ref const RouteMemory memory, string endpointKey, T[] items,
                          string[] routeKeys, long nowMs, scope bool delegate(size_t) promotable) {
    assert(items.length == routeKeys.length);
    if (items.length < 2 || memory.routeCount(endpointKey) == 0) return;
    static struct Ranked {
        T item;
        string key;
        RouteStanding standing;
        long okAtMs;
        size_t order;
    }
    auto ranked = new Ranked[items.length];
    bool moved = false;
    foreach (i, item; items) {
        long okAt;
        auto s = memory.standing(endpointKey, routeKeys[i], nowMs, okAt);
        if (s == RouteStanding.preferred && promotable !is null && !promotable(i)) {
            s = RouteStanding.neutral;
            okAt = 0;
        }
        if (s != RouteStanding.neutral) moved = true;
        ranked[i] = Ranked(item, routeKeys[i], s, okAt, i);
    }
    if (!moved) return;
    ranked.sort!((a, b) =>
        a.standing != b.standing ? a.standing < b.standing :
        a.okAtMs != b.okAtMs ? a.okAtMs > b.okAtMs :
        a.order < b.order);
    foreach (i, r; ranked) {
        items[i] = r.item;
        routeKeys[i] = r.key;
    }
}

@("route memory: success preferred, failure cools, both expire")
unittest {
    RouteMemory m;
    const ep = routeEndpointKey("irc.example.org", 6697, "implicit");
    long at;
    m.record(ep, "irc.example.org", "vpn|a", "slot:a", true, 1_000);
    m.record(ep, "irc.example.org", "direct|", "direct", false, 1_000);
    assert(m.standing(ep, "vpn|a", 2_000, at) == RouteStanding.preferred && at == 1_000);
    assert(m.standing(ep, "direct|", 2_000, at) == RouteStanding.cooling && at == 0);
    assert(m.standing(ep, "vpn|b", 2_000, at) == RouteStanding.neutral);
    // Expiry recovers each route independently.
    assert(m.standing(ep, "direct|", 1_000 + ROUTE_FAILURE_COOLDOWN_MS, at) == RouteStanding.neutral);
    assert(m.standing(ep, "vpn|a", 1_000 + ROUTE_FAILURE_COOLDOWN_MS, at) == RouteStanding.preferred);
    assert(m.standing(ep, "vpn|a", 1_000 + ROUTE_SUCCESS_TTL_MS, at) == RouteStanding.neutral);
    // Newest evidence wins in both directions.
    m.record(ep, "irc.example.org", "vpn|a", "slot:a", false, 3_000);
    assert(m.standing(ep, "vpn|a", 3_001, at) == RouteStanding.cooling);
    m.record(ep, "irc.example.org", "vpn|a", "slot:a", true, 4_000);
    assert(m.standing(ep, "vpn|a", 4_001, at) == RouteStanding.preferred);
    // A record stamped in the future (clock stepped back) is no evidence.
    assert(m.standing(ep, "vpn|a", 3_999, at) == RouteStanding.neutral);
}

@("route memory: host, port and TLS mode are separate endpoints")
unittest {
    RouteMemory m;
    long at;
    m.record(routeEndpointKey("irc.example.org", 6697, "implicit"), "irc.example.org", "vpn|a", "slot:a", true, 1_000);
    assert(m.standing(routeEndpointKey("irc.example.org", 6697, "implicit"), "vpn|a", 1_001, at) == RouteStanding.preferred);
    assert(m.standing(routeEndpointKey("irc.example.org", 6667, "implicit"), "vpn|a", 1_001, at) == RouteStanding.neutral);
    assert(m.standing(routeEndpointKey("irc.example.org", 6697, "starttls"), "vpn|a", 1_001, at) == RouteStanding.neutral);
    assert(m.standing(routeEndpointKey("irc.example.net", 6697, "implicit"), "vpn|a", 1_001, at) == RouteStanding.neutral);
}

@("route memory: forget drops only the banned route on that host")
unittest {
    RouteMemory m;
    long at;
    const a = routeEndpointKey("irc.example.org", 6697, "implicit");
    const b = routeEndpointKey("irc.example.org", 6667, "none");
    const other = routeEndpointKey("irc.example.net", 6697, "implicit");
    m.record(a, "irc.example.org", "vpn|de", "de-ber", true, 1_000);
    m.record(a, "irc.example.org", "direct|", "direct", true, 1_000);
    m.record(b, "irc.example.org", "vpn|de", "de-ber", true, 1_000);
    m.record(other, "irc.example.net", "vpn|de", "de-ber", true, 1_000);
    m.forget("irc.example.org", "de-ber");
    assert(m.standing(a, "vpn|de", 1_001, at) == RouteStanding.neutral);
    assert(m.standing(b, "vpn|de", 1_001, at) == RouteStanding.neutral);
    assert(m.routeCount(b) == 0 && m.endpointCount() == 2, "an emptied endpoint is removed");
    assert(m.standing(a, "direct|", 1_001, at) == RouteStanding.preferred);
    assert(m.standing(other, "vpn|de", 1_001, at) == RouteStanding.preferred);
}

@("route memory: both caps hold and idle endpoints are swept")
unittest {
    import std.conv : to;
    RouteMemory m;
    long at;
    const ep = routeEndpointKey("irc.example.org", 6697, "implicit");
    foreach (i; 0 .. ROUTE_MAX_ROUTES_PER_ENDPOINT + 5)
        m.record(ep, "irc.example.org", "vpn|" ~ i.to!string, "slot:" ~ i.to!string, true, 1_000 + i);
    assert(m.routeCount(ep) == ROUTE_MAX_ROUTES_PER_ENDPOINT);
    assert(m.standing(ep, "vpn|0", 2_000, at) == RouteStanding.neutral, "oldest route evicted");
    assert(m.standing(ep, "vpn|" ~ (ROUTE_MAX_ROUTES_PER_ENDPOINT + 4).to!string, 2_000, at)
        == RouteStanding.preferred);

    RouteMemory n;
    foreach (i; 0 .. ROUTE_MAX_ENDPOINTS + 5)
        n.record(routeEndpointKey("h" ~ i.to!string, 6697, "implicit"), "h" ~ i.to!string,
            "direct|", "direct", true, 1_000 + i);
    assert(n.endpointCount() == ROUTE_MAX_ENDPOINTS);
    assert(n.routeCount(routeEndpointKey("h0", 6697, "implicit")) == 0, "least recently touched endpoint evicted");
    // Once every memo is past the longest TTL, the next record sweeps them.
    n.record(routeEndpointKey("fresh", 6697, "implicit"), "fresh", "direct|", "direct", true,
        1_000 + ROUTE_MAX_ENDPOINTS + 5 + ROUTE_SUCCESS_TTL_MS);
    assert(n.endpointCount() == 1);
}

@("rankByRouteMemory: preferred first, cooling last, nothing dropped, avoid not promoted")
unittest {
    RouteMemory m;
    const ep = routeEndpointKey("irc.example.org", 6697, "implicit");
    m.record(ep, "irc.example.org", "c", "c", true, 1_000);
    m.record(ep, "irc.example.org", "d", "d", true, 1_500);
    m.record(ep, "irc.example.org", "a", "a", false, 1_200);
    string[] items = ["a", "b", "c", "d", "e"];
    string[] keys = items.dup;
    rankByRouteMemory(m, ep, items, keys, 2_000, null);
    assert(items == ["d", "c", "b", "e", "a"]);
    assert(keys == items, "keys stay aligned with their items");

    // An avoided candidate keeps its neutral position even with a success.
    items = ["a", "b", "c", "d", "e"];
    keys = items.dup;
    rankByRouteMemory(m, ep, items, keys, 2_000, (size_t i) => items[i] != "d");
    assert(items == ["c", "b", "d", "e", "a"]);

    // No memos for the endpoint: order untouched.
    items = ["a", "b"];
    keys = items.dup;
    rankByRouteMemory(m, routeEndpointKey("irc.example.org", 6667, "none"), items, keys, 2_000, null);
    assert(items == ["a", "b"]);
}
