/** Ordered connection routing preferences and administrative hard limits.
 * No storage, DNS, provider health or fallback decisions belong in this model.
 */
module ircfiber.irc.routing_policy;

import std.algorithm : canFind;
import std.string : strip, toLower, split;
import vibe.data.json : Json;
import ircfiber.netaddr : canonicalHost, isIpLiteral;

/// JSON/Lua/browser revisions must remain exact integers.
enum long MAX_ROUTING_POLICY_REVISION = 9_007_199_254_740_991L;

enum RouteKind { ipv6, mullvad, nordvpn, direct }

class RoutingValidationException : Exception {
    string[] errors;
    this(string message) { super(message); errors = [message]; }
}

string routeToken(RouteKind route) pure @safe nothrow {
    final switch (route) {
        case RouteKind.ipv6: return "ipv6";
        case RouteKind.mullvad: return "mullvad";
        case RouteKind.nordvpn: return "nordvpn";
        case RouteKind.direct: return "direct";
    }
}

RouteKind routeKindFromToken(string token) {
    switch (token) {
        case "ipv6": return RouteKind.ipv6;
        case "mullvad": return RouteKind.mullvad;
        case "nordvpn": return RouteKind.nordvpn;
        case "direct": return RouteKind.direct;
        default: throw new RoutingValidationException("unknown route token: " ~ token);
    }
}

/// A null order inherits; an explicit empty order intentionally forbids dialing.
struct RoutingPreferences {
    bool inherit = true;
    RouteKind[] order;
    string preferredExit;
    /// False only when a stored configuration is absent or malformed.
    bool valid = true;

    Json toJson() const {
        if (!valid) return Json(null);
        auto j = Json.emptyObject;
        j["order"] = inherit ? Json(null) : routesToJson(order);
        j["preferredExit"] = Json(preferredExit);
        return j;
    }
}

struct RoutingPolicyScope {
    bool inherit;
    RouteKind[] order;
    RouteKind[] blockedRoutes;
}

struct RoutingHostPolicy {
    string host;
    RoutingPolicyScope policy;
}

struct RoutingPolicyDocument {
    uint schema = 1;
    long revision;
    RoutingPolicyScope global;
    RoutingHostPolicy[] hosts;

    Json toJson() const {
        auto j = Json.emptyObject;
        j["schema"] = Json(schema);
        j["revision"] = Json(revision);
        j["global"] = scopeToJson(global, false);
        auto rows = Json.emptyArray;
        foreach (h; hosts) {
            auto row = scopeToJson(h.policy, true);
            row["host"] = Json(h.host);
            rows ~= row;
        }
        j["hosts"] = rows;
        return j;
    }
}

struct EffectiveRoutingPolicy {
    RouteKind[] order;
    RouteKind[] blockedRoutes;
    string preferredExit;
    long revision;
    bool available = true;
    string errorCode;
}

RoutingPolicyDocument defaultRoutingPolicy() {
    RoutingPolicyDocument doc;
    doc.global.order = [RouteKind.mullvad, RouteKind.nordvpn, RouteKind.direct];
    return doc;
}

string normalizePreferredExit(string raw) pure @safe {
    return raw.strip.toLower;
}

/// Location or configured static-slot label, never a provider/direct selector.
bool validPreferredExit(string selector) pure @safe nothrow {
    if (selector.length == 0) return true;
    if (selector.length > 128 || selector == "direct" || selector == "nordvpn"
        || selector == "mullvad" || selector == "ipv6" || selector == "auto"
        || selector == "random") return false;
    bool separator = true;
    foreach (char c; selector) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) separator = false;
        else if ((c == '-' || c == '_') && !separator) separator = true;
        else return false;
    }
    return !separator;
}

RoutingPreferences routingPreferencesFromJson(Json j) {
    requireKeys(j, ["order", "preferredExit"], "routing");
    RoutingPreferences preferences;
    preferences.inherit = j["order"].type == Json.Type.null_;
    if (!preferences.inherit) preferences.order = routesFromJson(j["order"], "routing.order");
    if (j["preferredExit"].type != Json.Type.string)
        throw new RoutingValidationException("routing.preferredExit must be a string");
    preferences.preferredExit = normalizePreferredExit(j["preferredExit"].get!string);
    if (!validPreferredExit(preferences.preferredExit))
        throw new RoutingValidationException("routing.preferredExit is not a valid VPN exit selector");
    return preferences;
}

RoutingPolicyDocument routingPolicyFromJson(Json j) {
    requireKeys(j, ["schema", "revision", "global", "hosts"], "policy");
    if (j["schema"].type != Json.Type.int_ || j["schema"].get!long != 1)
        throw new RoutingValidationException("policy.schema must be 1");
    if (j["revision"].type != Json.Type.int_ || j["revision"].get!long < 0
            || j["revision"].get!long > MAX_ROUTING_POLICY_REVISION)
        throw new RoutingValidationException("policy.revision must be a nonnegative exact JSON integer");
    RoutingPolicyDocument doc;
    doc.revision = j["revision"].get!long;
    doc.global = scopeFromJson(j["global"], false, "policy.global");
    if (j["hosts"].type != Json.Type.array)
        throw new RoutingValidationException("policy.hosts must be an array");
    bool[string] seenHosts;
    foreach (row; j["hosts"]) {
        requireKeys(row, ["host", "order", "blockedRoutes"], "policy.hosts entry");
        if (row["host"].type != Json.Type.string)
            throw new RoutingValidationException("policy host must be a string");
        const raw = row["host"].get!string;
        if (!validRoutingHost(raw)) throw new RoutingValidationException("invalid policy host: " ~ raw);
        const host = canonicalHost(raw);
        if (host in seenHosts) throw new RoutingValidationException("duplicate canonical policy host: " ~ host);
        seenHosts[host] = true;
        doc.hosts ~= RoutingHostPolicy(host, scopeFromJson(row, true, "policy.hosts entry"));
    }
    return doc;
}

/// Administrative order supplies defaults; blocks are hard limits on every saved order.
pure EffectiveRoutingPolicy resolveRoutingPolicy(const RoutingPolicyDocument doc,
                                                   string host, const RoutingPreferences preferences) {
    EffectiveRoutingPolicy effective;
    effective.revision = doc.revision;
    if (doc.schema != 1 || doc.global.inherit || !preferences.valid) {
        effective.available = false;
        effective.errorCode = preferences.valid ? "routing_policy_unavailable" : "invalid_stored_routing";
        return effective;
    }
    effective.preferredExit = preferences.preferredExit;
    effective.blockedRoutes = doc.global.blockedRoutes.dup;
    const(RouteKind)[] defaults = doc.global.order;
    const canonical = canonicalHost(host);
    foreach (rule; doc.hosts) {
        if (canonicalHost(rule.host) != canonical) continue;
        if (!rule.policy.inherit) defaults = rule.policy.order;
        foreach (route; rule.policy.blockedRoutes)
            if (!effective.blockedRoutes.canFind(route)) effective.blockedRoutes ~= route;
        break;
    }
    import ircfiber.default_network : DEFAULT_FIBER_HOST;
    const firstParty = canonical == canonicalHost(DEFAULT_FIBER_HOST);
    const(RouteKind)[] chosen = firstParty && preferences.inherit
        ? [RouteKind.direct] : preferences.inherit ? defaults : preferences.order;
    foreach (route; chosen)
        if ((!firstParty || route == RouteKind.direct) && !effective.blockedRoutes.canFind(route))
            effective.order ~= route;
    return effective;
}

bool routingContainsBlocked(const RoutingPreferences preferences,
                            const EffectiveRoutingPolicy effective) pure @safe {
    if (preferences.inherit) return false;
    foreach (route; preferences.order)
        if (effective.blockedRoutes.canFind(route)) return true;
    return false;
}

private Json routesToJson(const RouteKind[] routes) {
    auto j = Json.emptyArray;
    foreach (route; routes) j ~= Json(routeToken(route));
    return j;
}

private RouteKind[] routesFromJson(Json j, string where) {
    if (j.type != Json.Type.array || j.length > 4)
        throw new RoutingValidationException(where ~ " must be an array of at most four route tokens");
    RouteKind[] routes;
    foreach (value; j) {
        if (value.type != Json.Type.string)
            throw new RoutingValidationException(where ~ " contains a non-string route");
        const route = routeKindFromToken(value.get!string);
        if (routes.canFind(route)) throw new RoutingValidationException(where ~ " contains a duplicate route");
        routes ~= route;
    }
    return routes;
}

private void requireKeys(Json j, const string[] keys, string where) {
    if (j.type != Json.Type.object) throw new RoutingValidationException(where ~ " must be an object");
    foreach (string key, value; j)
        if (!keys.canFind(key)) throw new RoutingValidationException(where ~ " contains unknown key: " ~ key);
    foreach (key; keys)
        if (j[key].type == Json.Type.undefined) throw new RoutingValidationException(where ~ "." ~ key ~ " is required");
}

private RoutingPolicyScope scopeFromJson(Json j, bool hostRule, string where) {
    requireKeys(j, hostRule ? ["host", "order", "blockedRoutes"] : ["order", "blockedRoutes"], where);
    RoutingPolicyScope parsed;
    parsed.inherit = hostRule && j["order"].type == Json.Type.null_;
    if (!parsed.inherit) parsed.order = routesFromJson(j["order"], where ~ ".order");
    parsed.blockedRoutes = routesFromJson(j["blockedRoutes"], where ~ ".blockedRoutes");
    return parsed;
}

private Json scopeToJson(const RoutingPolicyScope settings, bool hostRule) {
    auto j = Json.emptyObject;
    j["order"] = hostRule && settings.inherit ? Json(null) : routesToJson(settings.order);
    j["blockedRoutes"] = routesToJson(settings.blockedRoutes);
    return j;
}

private bool validRoutingHost(string raw) {
    if (raw.length == 0 || raw != raw.strip || raw.length > 254) return false;
    if (isIpLiteral(raw)) return true;
    auto host = raw;
    if (host[$ - 1] == '.') host = host[0 .. $ - 1];
    if (host.length == 0 || host.length > 253) return false;
    foreach (label; host.split('.')) {
        if (label.length == 0 || label.length > 63 || label[0] == '-' || label[$ - 1] == '-') return false;
        foreach (char c; label)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return true;
}

unittest {
    import vibe.data.json : parseJsonString;
    auto doc = routingPolicyFromJson(parseJsonString(`{"schema":1,"revision":2,"global":{"order":["mullvad","nordvpn","direct"],"blockedRoutes":["direct"]},"hosts":[{"host":"IRC.Supernets.ORG.","order":["ipv6","nordvpn"],"blockedRoutes":["mullvad"]}]}`));
    RoutingPreferences inherited;
    assert(resolveRoutingPolicy(doc, "irc.supernets.org", inherited).order == [RouteKind.ipv6, RouteKind.nordvpn]);
    auto explicitVpn = routingPreferencesFromJson(parseJsonString(`{"order":["nordvpn","direct"],"preferredExit":"socks-us39"}`));
    assert(resolveRoutingPolicy(doc, "irc.supernets.org.", explicitVpn).order == [RouteKind.nordvpn]);
    assert(routingContainsBlocked(explicitVpn, resolveRoutingPolicy(doc, "irc.supernets.org", explicitVpn)));
    auto empty = routingPreferencesFromJson(parseJsonString(`{"order":[],"preferredExit":""}`));
    assert(resolveRoutingPolicy(doc, "irc.supernets.org", empty).order.length == 0);
    assert(resolveRoutingPolicy(doc, "alias.supernets.org", inherited).order == [RouteKind.mullvad, RouteKind.nordvpn]);
    RoutingPreferences invalid;
    invalid.valid = false;
    auto blocked = resolveRoutingPolicy(doc, "irc.supernets.org", invalid);
    assert(!blocked.available && blocked.order.length == 0);
    assert(routingPolicyFromJson(doc.toJson()).toJson() == doc.toJson());
    assert(routingPreferencesFromJson(explicitVpn.toJson()).toJson() == explicitVpn.toJson());
    foreach (bad; [`{"order":["nordvpn","nordvpn"],"preferredExit":""}`, `{"order":["DIRECT"],"preferredExit":""}`, `{"order":null}`, `{"order":false,"preferredExit":""}`, `{"order":[],"preferredExit":"../evil"}`, `{"order":[],"preferredExit":"","egress":"direct"}`]) {
        bool rejected;
        try routingPreferencesFromJson(parseJsonString(bad));
        catch (RoutingValidationException) rejected = true;
        assert(rejected, bad);
    }
    foreach (host; ["", "irc..example", "irc.example..", "*.example", "irc.example:6697", " x.example", "x_irc.example"])
        assert(!validRoutingHost(host), host);
    auto duplicate = doc.toJson();
    duplicate["hosts"] ~= duplicate["hosts"][0];
    bool rejected;
    try routingPolicyFromJson(duplicate);
    catch (RoutingValidationException) rejected = true;
    assert(rejected);
}
