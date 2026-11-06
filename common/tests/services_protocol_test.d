/**
 * Real services protocol smoke test: request serialization round-trip
 * and payload reference redaction verification.
 *
 *   dub run --root=site/common --config=services-protocol-test
 *
 * Exercises the services request/payload envelope contract:
 * - memoSend browser JSON round-trips through ServicesRequest
 * - Action and text are preserved after re-serialization
 * - ServicesPayloadReference routing excludes sensitive data
 */
module services_protocol_test;

version (ServicesProtocolTest):
import std.stdio : writeln;
import std.algorithm : canFind;
import std.uuid : randomUUID;
import vibe.data.json;

import ircfiber.services.protocol;

void check(bool ok, string what) {
    if (!ok) throw new Exception("FAIL: " ~ what);
}

void main() {
    // Construct memoSend browser JSON with random UUIDs.
    auto requestId = randomUUID().toString;
    auto epochId = randomUUID().toString;
    auto memoJson = Json([
        "requestId": Json(requestId),
        "action": Json("memoSend"),
        "expectedConnectionEpoch": Json(epochId),
        "expectedActorAccount": Json("alice"),
        "expectedRevision": Json(""),
        "params": Json([
            "recipient": Json("bob"),
            "targetNick": Json("bob"),
            "text": Json("unique-private-memo-canary")
        ])
    ]);

    // Parse ServicesRequest.fromJson.
    auto request = ServicesRequest.fromJson(memoJson);
    check(request.requestId == requestId, "requestId preserved");
    check(request.action == ServiceAction.memoSend, "action is memoSend");
    check(request.expectedActorAccount == "alice", "actor account is alice");
    check(request.params["text"].get!string == "unique-private-memo-canary", "params text preserved");

    // Serialize to JSON and parse again.
    auto serialized = request.toJson();
    auto requestRoundtrip = ServicesRequest.fromJson(serialized);
    check(requestRoundtrip.action == ServiceAction.memoSend, "action preserved after round-trip");
    check(requestRoundtrip.params["text"].get!string == "unique-private-memo-canary",
        "text preserved after round-trip");

    // Build ServicesPayloadReference with ServicesKeys.payload.
    auto owner = randomUUID().toString;
    auto network = randomUUID().toString;
    auto payloadKey = ServicesKeys.payload(owner, network, requestId);
    auto payloadRef = ServicesPayloadReference(requestId, payloadKey);

    // Serialize routing JSON and verify sensitive data is excluded.
    auto routingJson = payloadRef.toJson();
    auto routingStr = routingJson.toString();

    // Assert the memo canary text is NOT in routing JSON.
    check(!routingStr.canFind("unique-private-memo-canary"),
        "memo text not in routing JSON");

    // Assert the recipient value is NOT in routing JSON.
    check(!routingStr.canFind("bob"),
        "recipient not in routing JSON");

    writeln("services protocol smoke test: PASS (request round-trip + payload redaction)");
}

