/// Standalone fast test for ircfiber.irc.egress_catalog.
///
/// Pure code — no tailnet, Mullvad license, Redis or Mongo needed:
///   dub build --config=egress-catalog-test --compiler=ldc2 && ./egress-catalog-test
module egress_catalog_test;

import std.stdio : writeln, writefln;

import ircfiber.irc.egress_catalog : ExitLocation, ExitRelay, locationMatches,
    locationsFromRelays, parseExitOnline, parseExitRelays, parseSelectedExit,
    pickRelayForPin;

private int failures;

private void check(bool cond, string what, string file = __FILE__, size_t line = __LINE__) {
    if (cond) return;
    failures++;
    writefln("FAIL %s:%d — %s", file, line, what);
}

/// Two Mullvad exits (Berlin, Stockholm) plus a plain non-exit peer with no
/// `Location` block at all — the shape a real tailnet returns.
private enum THREE_PEERS = `{
  "ExitNodeStatus": { "Online": true },
  "Peer": {
    "nodekey:aaa": {
      "HostName": "de-ber-wg-003",
      "TailscaleIPs": ["100.64.0.11", "fd7a::11"],
      "Online": true, "ExitNode": true, "ExitNodeOption": true,
      "Location": { "Country": "Germany", "CountryCode": "DE", "City": "Berlin", "CityCode": "BER", "Priority": 100 }
    },
    "nodekey:bbb": {
      "HostName": "se-sto-wg-201",
      "TailscaleIPs": ["100.64.0.12"],
      "Online": true, "ExitNode": false, "ExitNodeOption": true,
      "Location": { "Country": "Sweden", "CountryCode": "SE", "City": "Stockholm", "CityCode": "STO", "Priority": 100 }
    },
    "nodekey:ccc": {
      "HostName": "laptop",
      "TailscaleIPs": ["100.99.1.1"],
      "Online": true, "ExitNode": false, "ExitNodeOption": false
    }
  }
}`;

private void testParseExitRelays() {
    auto relays = parseExitRelays(THREE_PEERS);
    check(relays.length == 2, "only the two exit-option peers are relays");
    bool ber, sto;
    foreach (r; relays) {
        if (r.locationId == "de-ber") {
            ber = true;
            check(r.hostname == "de-ber-wg-003", "berlin hostname");
            check(r.ip == "100.64.0.11", "prefers the IPv4 tailnet address");
            check(r.country == "Germany" && r.city == "Berlin", "berlin display names");
            check(r.countryCode == "de" && r.cityCode == "ber", "codes lower-cased");
            check(r.priority == 100 && r.online, "priority + online");
        } else if (r.locationId == "se-sto") {
            sto = true;
            check(r.ip == "100.64.0.12", "stockholm ip");
        }
    }
    check(ber && sto, "ids de-ber and se-sto present");
}

private void testLocationsFromRelays() {
    ExitRelay[] relays = [
        ExitRelay("se-sto-wg-201", "100.64.0.12", "se-sto", "Sweden", "se", "Stockholm", "sto", 100, true),
        ExitRelay("de-ber-wg-003", "100.64.0.11", "de-ber", "Germany", "de", "Berlin", "ber", 100, true),
        ExitRelay("de-ber-wg-004", "100.64.0.13", "de-ber", "Germany", "de", "Berlin", "ber", 40, true),
    ];
    auto locs = locationsFromRelays(relays);
    check(locs.length == 2, "two cities after dedupe");
    check(locs[0].country == "Germany" && locs[0].id == "de-ber", "sorted by country: Germany first");
    check(locs[0].relays == 2, "de-ber counts both relays");
    check(locs[1].id == "se-sto" && locs[1].relays == 1, "se-sto single relay");
    check(locationsFromRelays(null).length == 0, "no relays → no locations");
}

private void testLocationMatches() {
    check(locationMatches("de-ber", "de"), "country pin matches city in country");
    check(locationMatches("de-ber", "de-ber"), "exact city pin matches");
    check(!locationMatches("de-ber", "de-fra"), "different city does not match");
    check(!locationMatches("de-ber", ""), "empty pin (automatic) matches nothing");
    check(!locationMatches("", "de"), "unknown slot location matches nothing");
    check(!locationMatches("dk-cph", "de"), "country prefix must be exact");
}

private void testPickRelayForPin() {
    ExitRelay[] relays = [
        ExitRelay("se-sto-wg-100", "100.64.0.20", "se-sto", "Sweden", "se", "Stockholm", "sto", 40, true),
        ExitRelay("se-sto-wg-201", "100.64.0.21", "se-sto", "Sweden", "se", "Stockholm", "sto", 100, true),
        ExitRelay("se-got-wg-001", "100.64.0.22", "se-got", "Sweden", "se", "Gothenburg", "got", 100, false),
        ExitRelay("de-ber-wg-003", "100.64.0.11", "de-ber", "Germany", "de", "Berlin", "ber", 100, true),
    ];
    check(pickRelayForPin(relays, "se-sto").hostname == "se-sto-wg-201", "highest priority wins");
    check(pickRelayForPin(relays, "se-got").hostname.length == 0, "offline relay is skipped");
    check(pickRelayForPin(relays, "se").hostname == "se-sto-wg-201", "country pin picks best online in country");
    check(pickRelayForPin(relays, "fr").hostname.length == 0, "unknown country → none");

    ExitRelay[] tie = [
        ExitRelay("se-sto-wg-900", "100.64.0.30", "se-sto", "Sweden", "se", "Stockholm", "sto", 100, true),
        ExitRelay("se-sto-wg-100", "100.64.0.31", "se-sto", "Sweden", "se", "Stockholm", "sto", 100, true),
    ];
    check(pickRelayForPin(tie, "se-sto").hostname == "se-sto-wg-100", "priority tie broken by hostname asc");
}

private void testSelectedExitAndOnline() {
    check(parseSelectedExit(THREE_PEERS).hostname == "de-ber-wg-003", "selected exit is the ExitNode peer");
    check(parseExitOnline(THREE_PEERS), "ExitNodeStatus.Online true");
    check(!parseExitOnline(`{"ExitNodeStatus":{"Online":false},"Peer":{}}`), "explicit offline");
    check(!parseExitOnline(`{"Peer":{}}`), "absent ExitNodeStatus → offline");
    check(parseSelectedExit(`{"Peer":{"k":{"HostName":"x","ExitNodeOption":true}}}`).hostname.length == 0,
        "no ExitNode peer → no selection");
}

private void testMalformedInput() {
    check(parseExitRelays("").length == 0, "empty payload → no relays, no throw");
    check(parseExitRelays("{oops").length == 0, "malformed json → no relays, no throw");
    check(parseExitRelays(`{"Peer":[]}`).length == 0, "Peer wrong type → no relays");
    check(parseSelectedExit("{oops").hostname.length == 0, "malformed json → no selection");
    check(!parseExitOnline("{oops"), "malformed json → offline");
}

void main() {
    testParseExitRelays();
    testLocationsFromRelays();
    testLocationMatches();
    testPickRelayForPin();
    testSelectedExitAndOnline();
    testMalformedInput();
    if (failures) {
        writefln("egress catalog tests: %d FAILED", failures);
        import core.stdc.stdlib : exit;
        exit(1);
    }
    writeln("egress catalog tests: PASS");
}
