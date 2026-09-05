/// Mullvad exit-location catalog: pure parsing and matching helpers.
///
/// The engine drives its SOCKS egress slots through each sidecar's own
/// tailscaled LocalAPI socket (`tailscale --socket=… status --json`). This
/// module owns everything about that payload that can be reasoned about
/// without a tailnet: which peers are pickable exits, what location id each
/// one has, how a user's pin matches a slot, and which concrete relay a pin
/// should be retargeted to.
///
/// Deliberately I/O-free and vibe-free (uses `std.json`, not
/// `vibe.data.json`) so it compiles into a standalone test binary:
///   dub build --config=egress-catalog-test --compiler=ldc2 && ./egress-catalog-test
module ircfiber.irc.egress_catalog;

import std.algorithm : sort;
import std.json : JSONException, JSONType, JSONValue, parseJSON;

/// One Mullvad exit relay as tailscaled reports it.
struct ExitRelay {
    /// Tailnet host name, e.g. "de-ber-wg-003".
    string hostname;
    /// Tailnet IP used as the `--exit-node=` argument.
    string ip;
    /// `<countryCode>-<cityCode>`, lower-case, e.g. "de-ber".
    string locationId;
    /// Display country, e.g. "Germany".
    string country;
    /// ISO country code, lower-case.
    string countryCode;
    /// Display city, e.g. "Berlin".
    string city;
    /// Mullvad city code, lower-case, e.g. "ber".
    string cityCode;
    /// Mullvad's own relay preference within the city (higher = better).
    long priority;
    /// Whether tailscaled currently sees the relay.
    bool online;
}

/// One pickable location (city), deduped from the relay list.
struct ExitLocation {
    /// `<countryCode>-<cityCode>`, the value a city pin carries.
    string id;
    string country;
    string countryCode;
    string city;
    string cityCode;
    /// How many online relays back this city.
    int relays;
}

private JSONValue* jsub(JSONValue* o, string key) {
    if (o is null || o.type != JSONType.object) return null;
    if (auto p = key in o.object)
        if (p.type == JSONType.object) return p;
    return null;
}

private string jstr(JSONValue* o, string key) {
    if (o is null || o.type != JSONType.object) return "";
    if (auto p = key in o.object)
        if (p.type == JSONType.string) return p.str;
    return "";
}

private bool jbool(JSONValue* o, string key) {
    if (o is null || o.type != JSONType.object) return false;
    if (auto p = key in o.object) {
        if (p.type == JSONType.true_) return true;
        if (p.type == JSONType.false_) return false;
    }
    return false;
}

private long jlong(JSONValue* o, string key) {
    if (o is null || o.type != JSONType.object) return 0;
    if (auto p = key in o.object) {
        if (p.type == JSONType.integer) return p.integer;
        if (p.type == JSONType.uinteger) return cast(long) p.uinteger;
        if (p.type == JSONType.float_) return cast(long) p.floating;
    }
    return 0;
}

/// ASCII lower-case. Hand-rolled so the pure/nothrow matchers below cannot
/// throw on malformed UTF-8 the way `std.string.toLower` can.
private string asciiLower(string s) pure nothrow {
    bool needs = false;
    foreach (c; s) if (c >= 'A' && c <= 'Z') { needs = true; break; }
    if (!needs) return s;
    auto buf = new char[s.length];
    foreach (i, c; s) buf[i] = (c >= 'A' && c <= 'Z') ? cast(char)(c + 32) : c;
    return cast(string) buf;
}

/// Reads one `Peer` entry. `requireLocation` off keeps the hostname of a
/// non-Mullvad exit (used to confirm a retarget landed).
private ExitRelay relayFromPeer(JSONValue* peer, bool requireLocation) {
    ExitRelay r;
    if (peer is null || peer.type != JSONType.object) return r;
    r.hostname = jstr(peer, "HostName");
    r.online = jbool(peer, "Online");
    if (auto ips = "TailscaleIPs" in peer.object) {
        if (ips.type == JSONType.array) {
            foreach (ref ip; ips.array) {
                if (ip.type != JSONType.string) continue;
                auto s = ip.str;
                if (r.ip.length == 0) r.ip = s;
                // Prefer the IPv4 tailnet address for `--exit-node=`.
                bool v4 = false;
                foreach (c; s) if (c == '.') { v4 = true; break; }
                if (v4) { r.ip = s; break; }
            }
        }
    }
    auto loc = jsub(peer, "Location");
    if (loc !is null) {
        r.countryCode = asciiLower(jstr(loc, "CountryCode"));
        r.cityCode = asciiLower(jstr(loc, "CityCode"));
        r.country = jstr(loc, "Country");
        r.city = jstr(loc, "City");
        r.priority = jlong(loc, "Priority");
        if (r.countryCode.length && r.cityCode.length)
            r.locationId = r.countryCode ~ "-" ~ r.cityCode;
    }
    if (requireLocation && r.locationId.length == 0) return ExitRelay.init;
    return r;
}

/// Parses `tailscale status --json`. Keeps peers with `ExitNodeOption == true`,
/// a `Location` object and a non-empty CountryCode+CityCode. Never throws:
/// a malformed or empty payload yields an empty list.
ExitRelay[] parseExitRelays(string statusJson) nothrow {
    ExitRelay[] relays;
    try {
        auto doc = parseJSON(statusJson);
        auto peers = jsub(&doc, "Peer");
        if (peers is null) return relays;
        foreach (_, ref peer; peers.object) {
            if (!jbool(&peer, "ExitNodeOption")) continue;
            auto r = relayFromPeer(&peer, true);
            if (r.locationId.length) relays ~= r;
        }
    } catch (JSONException) {
        return null;
    } catch (Exception) {
        return null;
    }
    return relays;
}

/// The relay currently selected as this node's exit (the peer with
/// `ExitNode == true`), or `ExitRelay.init` when none is selected.
ExitRelay parseSelectedExit(string statusJson) nothrow {
    try {
        auto doc = parseJSON(statusJson);
        auto peers = jsub(&doc, "Peer");
        if (peers is null) return ExitRelay.init;
        foreach (_, ref peer; peers.object) {
            if (!jbool(&peer, "ExitNode")) continue;
            return relayFromPeer(&peer, false);
        }
    } catch (Exception) {
        return ExitRelay.init;
    }
    return ExitRelay.init;
}

/// True when `Status.ExitNodeStatus.Online` is true — i.e. the selected exit
/// is actually usable, not merely configured.
bool parseExitOnline(string statusJson) nothrow {
    try {
        auto doc = parseJSON(statusJson);
        auto st = jsub(&doc, "ExitNodeStatus");
        if (st is null) return false;
        return jbool(st, "Online");
    } catch (Exception) {
        return false;
    }
}

/// Dedupes relays to one entry per `locationId`, counting the relays behind
/// each city. Sorted by country then city so the picker's optgroups are
/// stable without the frontend sorting anything.
ExitLocation[] locationsFromRelays(ExitRelay[] relays) {
    ExitLocation[] out_;
    size_t[string] seen;
    foreach (r; relays) {
        if (r.locationId.length == 0) continue;
        if (auto idx = r.locationId in seen) {
            out_[*idx].relays++;
            continue;
        }
        seen[r.locationId] = out_.length;
        out_ ~= ExitLocation(r.locationId, r.country, r.countryCode, r.city, r.cityCode, 1);
    }
    out_.sort!((a, b) => a.country == b.country ? a.city < b.city : a.country < b.country);
    return out_;
}

/// Pin matching. A city pin (`de-ber`) matches only that exact location; a
/// country pin (`de`) matches every city in the country. Both arguments must
/// already be lower-case (`ExitRelay.locationId` and the normalised pin are).
/// An empty pin means "automatic" and matches nothing here.
bool locationMatches(string slotLocationId, string pin) pure nothrow {
    if (slotLocationId.length == 0 || pin.length == 0) return false;
    if (slotLocationId == pin) return true;
    if (pin.length != 2) return false;
    return slotLocationId.length > 3
        && slotLocationId[0 .. 2] == pin
        && slotLocationId[2] == '-';
}

/// The relay a pin should be retargeted to: online only, highest
/// `Location.Priority`, ties broken by hostname ascending for determinism.
/// `ExitRelay.init` when the pin matches no online relay.
ExitRelay pickRelayForPin(ExitRelay[] relays, string pin) {
    ExitRelay best;
    bool found = false;
    foreach (r; relays) {
        if (!r.online) continue;
        if (!locationMatches(r.locationId, pin)) continue;
        if (!found || r.priority > best.priority
            || (r.priority == best.priority && r.hostname < best.hostname)) {
            best = r;
            found = true;
        }
    }
    return found ? best : ExitRelay.init;
}
