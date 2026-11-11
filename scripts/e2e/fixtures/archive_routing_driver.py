#!/usr/bin/env python3
"""Candidate-only HTTP/Redis/Mongo/two-journal qualification, not a mock oracle.

The --journal reader runs inside the labelled endpoint with read-only archive
mounts. It validates the real double-slot state and every still-retained frame;
Redis operation projections are never used as proof of journal completion.
"""
import json
import os
from pathlib import Path
import struct
import sys
import time
import zlib


def read_journal(directory):
    directory = Path(directory)
    candidates = []
    assert (directory / "state").stat().st_size == 8_388_608, "invalid reserved state file size"
    with (directory / "state").open("rb") as stream:
        for slot in range(2):
            stream.seek(slot * 4_194_304)
            header = stream.read(24)
            if len(header) != 24 or header[:8] != b"IFASv001":
                continue
            generation, length, checksum = struct.unpack("<QII", header[8:])
            if not generation or not 0 < length <= 4_194_304 - 24:
                continue
            payload = stream.read(length)
            if len(payload) == length and zlib.crc32(struct.pack("<Q", generation) + payload) == checksum:
                candidates.append((generation, json.loads(payload)))
    assert candidates, "missing valid real archive state slots: " + str(directory)
    generation, state = max(candidates, key=lambda item: item[0])
    assert not state["failed"], (directory.name, "sticky journal failure")
    assert len(state["operations"]) <= 1152 and len(state["gaps"]) <= 256
    files = sorted(directory.iterdir())
    assert len(files) <= 160, (directory.name, "journal file cap", len(files))
    frame_bytes = 0
    frames = []
    allocated = sum(item.stat().st_blocks * 512 for item in files if item.is_file())
    assert allocated <= 536_870_912, (directory.name, "journal allocation cap", allocated)
    previous = 0
    for path in files:
        if not path.name.startswith("segment-") or not path.name.endswith(".log"):
            continue
        # Snapshot the current length: the sole disk writer can append while
        # this read-only observer runs. An incomplete active suffix is retried.
        size = path.stat().st_size
        assert size <= 4_194_304, (path.name, size)
        with path.open("rb") as stream:
            assert stream.read(8) == b"IFARv001", path.name
            position = 8
            while position < size:
                header = stream.read(16)
                if len(header) != 16:
                    break
                length, checksum, sequence = struct.unpack("<IIQ", header)
                assert 0 < length <= 1_048_576 and sequence > previous, path.name
                if position + 16 + length > size:
                    break
                payload = stream.read(length)
                assert len(payload) == length
                assert zlib.crc32(struct.pack("<Q", sequence) + payload) == checksum, path.name
                assert len(frames) < 8192, "fixture frame evidence limit exceeded"
                previous = sequence
                frame_bytes += length
                assert frame_bytes <= 524_288, "fixture frame byte evidence limit exceeded"
                frames.append({"sequence": sequence, "record": json.loads(payload)})
                position += 16 + length
    return {"generation": generation, "state": state, "frames": frames,
            "files": len(files), "allocatedBytes": allocated}


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--journal":
    assert sys.argv[2] in ("/archive/native", "/archive/old")
    for attempt in range(3):
        try:
            snapshot = read_journal(sys.argv[2])
            break
        except FileNotFoundError:
            if attempt == 2:
                raise
            time.sleep(0.02)  # concurrent checkpoint may reclaim a segment
    print(json.dumps(snapshot, separators=(",", ":")))
    sys.exit(0)

# Import only in driver mode; journal inspection needs no gateway/host helpers.
import contextlib
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid
import routed_policy_driver as routed

ENGINES = {"fixture-old": "old-engine", "fixture-native": "native-engine"}
ARCHIVES = {"fixture-old": "/archive/old", "fixture-native": "/archive/native"}
BUFFERS = ("#proof", "#renamed", "#offline", "#unsupported", "#rename-source", "#rename-target", "_server")
INITIAL_ARCHIVE_GAPS = {}
RECOVERY_ARCHIVE_GAPS = {}
MONGO_FAULTS = set()
COMPOSE = sys.argv[1]
PAUSED = set()
STARTED = {}
CASE = "startup"
EVIDENCE = []
QUALIFICATION_SECONDS = 1800
DEADLINE = time.monotonic() + QUALIFICATION_SECONDS


def command(args, seconds=40):
    assert time.monotonic() < DEADLINE, f"whole qualification exceeded {QUALIFICATION_SECONDS} seconds"
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        result = subprocess.run(args, stdout=out, stderr=err,
                                timeout=min(seconds, max(1, DEADLINE - time.monotonic())))
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(1_048_577), err.read(65_537)
    assert len(stdout) <= 1_048_576 and len(stderr) <= 65_536, "bounded command output exceeded"
    assert result.returncode == 0, (args[:6], result.returncode, stderr.decode(errors="replace"))
    return stdout.decode().strip()


def containers():
    ids = command([*routed.DOCKER, "ps", "-aq", "--filter",
                   "label=com.docker.compose.project=" + routed.PROJECT]).splitlines()
    assert len(ids) <= 16, "unexpected fixture resource count"
    if not ids:
        return []
    rows = json.loads(command([*routed.DOCKER, "inspect", *ids]))
    for row in rows:
        labels = row["Config"]["Labels"]
        assert labels.get("ircfiber.fixture.run") == routed.PROJECT, "refusing foreign container"
        assert labels.get("com.docker.compose.project") == routed.PROJECT
    return rows


def dc(*args, capture=True):
    # All mutations are project-scoped and refuse unlabelled/lookalike resources.
    if args and args[0] in ("pause", "unpause", "kill", "stop", "start", "up", "exec"):
        containers()
    result = command([*routed.DOCKER, "compose", "--project-name", routed.PROJECT,
                      "-f", COMPOSE, *args], seconds=120 if args[0] == "up" else 40)
    if not capture and result:
        print(result, flush=True)
    return result


routed.dc = dc


def health():
    for row in containers():
        service = row["Config"]["Labels"]["com.docker.compose.service"]
        state = row["State"]
        assert not state.get("OOMKilled") and row["RestartCount"] == 0, (service, "OOM/restart", state)
        if service in STARTED:
            assert (row["Id"], state["StartedAt"]) == STARTED[service], (service, "unexpected generation change")
            assert state["Running"], (service, "exited during qualification", state)


def baseline():
    STARTED.clear()
    for row in containers():
        service = row["Config"]["Labels"]["com.docker.compose.service"]
        STARTED[service] = (row["Id"], row["State"]["StartedAt"])
    health()


def wait(label, predicate, seconds=90):
    stop = min(DEADLINE, time.monotonic() + seconds)
    last = None
    while time.monotonic() < stop:
        health()
        try:
            result = predicate()
            if result:
                return result
        except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError, FileNotFoundError) as error:
            last = str(error)
        time.sleep(0.5)
    raise AssertionError((CASE, "timeout", label, last))


def case(name, **evidence):
    global CASE
    health()
    CASE = name
    EVIDENCE.append({"case": name, "phase": "entered", "socketCounts": routed.counts(), **evidence})
    print(json.dumps(EVIDENCE[-1], sort_keys=True), flush=True)


def http(method, path, body=None):
    request = urllib.request.Request(routed.BASE + path, method=method,
              data=None if body is None else json.dumps(body).encode(),
              headers={"Content-Type": "application/json"})
    try:
        response = routed.http.open(request, timeout=12)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        payload = response.read(65_537)
        assert len(payload) <= 65_536, "oversized HTTP evidence"
        value = json.loads(payload) if payload else {}
        return response.status, value.get("data", value)


def clear(ident, operation, buffer="#proof"):
    return http("POST", f"/api/networks/{ident}/buffers/clear",
                {"operationId": operation, "buffer": buffer})


def status(ident, operation, buffer="#proof"):
    import urllib.parse
    return http("GET", f"/api/networks/{ident}/buffers/clear/{operation}?buffer=" + urllib.parse.quote(buffer))


def not_cleared(reply, status_query=False):
    code, result = reply
    assert result.get("status") != "cleared" and result.get("state") != "completed", reply
    states = ("not_accepted", "pending", "unknown") + (("requested", "admitted") if status_query else ())
    assert ((code == 503 and result.get("state") in states)
            or (status_query and code == 404 and result.get("state") == "unknown")), reply
    return result


def raw_journal(server):
    return json.loads(routed.ex("endpoint", "python3", "/fixture/archive_routing_driver.py",
                                "--journal", ARCHIVES[server]))


def journal(server):
    snapshot = raw_journal(server)
    assert server in INITIAL_ARCHIVE_GAPS, "startup archival evidence was not frozen"
    expected_gaps = RECOVERY_ARCHIVE_GAPS.get(server, INITIAL_ARCHIVE_GAPS[server])
    assert snapshot["state"]["gaps"] == expected_gaps, \
        (server, "new archival loss/uncertainty outside frozen proof", snapshot["state"]["gaps"])
    return snapshot


def operation(server, ident):
    snapshot = journal(server)
    matches = [item for item in snapshot["state"]["operations"] if item["operationId"] == ident]
    assert len(matches) <= 1
    return (snapshot, matches[0]) if matches else None


def drained(server):
    snapshot = journal(server)
    checkpoint = snapshot["state"]["checkpoint"]
    return (all(frame["sequence"] <= checkpoint for frame in snapshot["frames"])
            and all(op["state"] != 1 for op in snapshot["state"]["operations"]))


def group(ident):
    raw = routed.redis("get", "irc:archive:clear:" + ident)
    return json.loads(raw) if raw else {}


def rows(network):
    script = "print(JSON.stringify(db.messages.find({networkId:" + json.dumps(network) + \
             "},{_id:1,serverId:1,channel:1,eid:1,t:1,payload:1}).limit(1001).toArray().map(d=>{" \
             "for(const k of ['eid','t'])if(k in d){d[k]=Number(d[k]);" \
             "if(!Number.isSafeInteger(d[k]))throw new Error('unsafe fixture integer '+k);}return d;})))"
    result = json.loads(routed.mongo(script))
    assert len(result) <= 1000, "fixture Mongo evidence limit exceeded; refusing truncated proof"
    return result


def marker_rows(network, marker):
    return [row for row in rows(network) if marker in row["payload"]]


def live_entries(network, marker=""):
    result = []
    # Include the real pre-namespace legacy lists, not only engine-scoped data.
    for server in (*ENGINES, None):
        for buffer in BUFFERS:
            key = f"scrollback:{server}:{network}:{buffer}" if server else f"scrollback:{network}:{buffer}"
            raw = routed.redis("lrange", key, "0", "-1")
            entries = raw.splitlines()
            assert len(entries) <= 1000 and len(raw.encode()) <= 524_288, "Redis evidence limit exceeded"
            result.extend((key, json.loads(line)) for line in entries if marker in line)
    return result


def live_rows(network, marker):
    return [row for _, row in live_entries(network, marker)]


def seed_legacy(network, buffer, prefix):
    # Deliberately straddle the forthcoming timestamp cutoff. These are actual
    # eid-less pre-journal documents/lists, not journal-admission test doubles.
    old_time = int(time.time() * 1000) - 60_000
    new_time = int((time.time() + max(1, DEADLINE - time.monotonic()) + 60) * 1000)
    events = []
    documents = []
    for suffix, timestamp in (("old", old_time), ("new", new_time)):
        marker = prefix + "-" + suffix
        event = {"network": "fixture", "nid": network, "i": str(uuid.uuid4()),
                 "t": timestamp, "c": "PRIVMSG", "n": "legacy", "ch": buffer,
                 "x": marker, "p": [buffer, marker]}
        encoded = json.dumps(event, separators=(",", ":"))
        events.append(encoded)
        for server in ENGINES:
            documents.append({"_id": f"{server}:{network}:{buffer}:{event['i']}",
                              "serverId": server, "networkId": network, "channel": buffer,
                              "t": timestamp, "payload": encoded})
    result = json.loads(routed.mongo("print(JSON.stringify(db.messages.insertMany(" +
                                    json.dumps(documents) + ",{writeConcern:{w:'majority',j:true}})))"))
    assert result["acknowledged"] and len(result["insertedIds"]) == 4, result
    assert routed.redis("rpush", f"scrollback:{network}:{buffer}", *events).isdigit()
    for suffix in ("old", "new"):
        stored, live = marker_rows(network, prefix + "-" + suffix), live_rows(network, prefix + "-" + suffix)
        assert len(stored) == 2 and len(live) == 1
        assert all("eid" not in row for row in (*stored, *live)), "seed is not genuinely legacy"
    return old_time, new_time


def legacy_result(network, prefix, timestamps, frozen):
    assert timestamps[0] <= frozen["legacyTimestampCutoffMs"] < timestamps[1], frozen
    assert not marker_rows(network, prefix + "-old") and not live_rows(network, prefix + "-old")
    assert len(marker_rows(network, prefix + "-new")) == 2
    assert len(live_rows(network, prefix + "-new")) == 1


def backend_snapshot(network):
    return {"mongo": sorted(rows(network), key=lambda row: row["_id"]),
            "redis": sorted((key, json.dumps(row, sort_keys=True)) for key, row in live_entries(network))}


def deliver(nick, lines):
    routed.endpoint(body={"deliver": {"nick": nick, "lines": lines}})


def message(network, nick, marker, channel="#proof", persisted=True):
    deliver(nick, [f":sender!ident@fixture PRIVMSG {channel} :{marker}"])
    live = wait("actual wire message accepted into Redis: " + marker,
                lambda: live_rows(network, marker))
    assert len(live) == 1 and live[0]["eid"] > 0, live
    if persisted:
        stored = wait("strict Mongo replay: " + marker, lambda: marker_rows(network, marker))
        assert len(stored) == 1 and stored[0]["eid"] == live[0]["eid"] and stored[0]["t"] == live[0]["t"], stored
        assert stored[0]["serverId"] == routed.owner(network), stored
    return live[0]


def mongo_fault(name, enabled):
    # Real server-side failures: append and delete gates remain independent,
    # while reads/catalog updates/ordered renames continue to execute in Mongo.
    assert name in ("insert", "delete")
    if enabled:
        MONGO_FAULTS.add(name)
    else:
        MONGO_FAULTS.discard(name)
    result = json.loads(routed.mongo("print(JSON.stringify(db.getSiblingDB('admin').runCommand(" +
        json.dumps({"configureFailPoint": "failCommand", "mode": "alwaysOn" if MONGO_FAULTS else "off",
                    "data": {"failCommands": sorted(MONGO_FAULTS), "errorCode": 91}}) + ")))"))
    assert result.get("ok") == 1, ("Mongo enableTestCommands/failCommand prerequisite", result)


def insert_fault(enabled):
    mongo_fault("insert", enabled)


@contextlib.contextmanager
def pause(service):
    assert service in ENGINES.values(), "only run-owned engine reachability faults are allowed"
    dc("pause", service)
    PAUSED.add(service)
    try:
        yield
    finally:
        dc("unpause", service)
        PAUSED.discard(service)


def socket_identity(network, nick):
    upstream = routed.single_upstream(network, nick)
    held = routed.held(network)
    assert len(upstream) == len(held) == 1, (upstream, held)
    physical = upstream[0]
    assert physical["remotePort"] > 0 and physical["inode"] > 0, physical
    return (physical["id"], physical["peer"], physical["remotePort"], physical["inode"],
            held[0][0], held[0][1]["id"], held[0][1]["connectedAtMs"])


def move(network, nick, target, allowed=True):
    source = routed.owner(network)
    before = socket_identity(network, nick)
    with pause(ENGINES[source]):
        request = routed.api("POST", f"/api/admin/networks/{network}/move",
                             {"serverId": target}, expect=(202,))
        routed.endpoint(body={"moveWitness": {"moveId": request["moveId"], "fromServerId": source}})
    def terminal():
        health()
        routed.single_upstream(network, nick)
        result = routed.api("GET", "/api/admin/routing-moves/" + request["moveId"])
        return result if result["state"] in ("completed", "failed", "expired") else None
    result = wait("real MOVE terminal acknowledgment", terminal, 110)
    if allowed:
        assert result["state"] == "completed" and result.get("sourceClosed") is True, result
        assert result["ackServerId"] == source and routed.owner(network) == target, result
        wait("actual destination numeric 001", lambda: routed.single_upstream(network, nick))
        proof = routed.single_upstream(network, nick)[0]["moveProof"]
        assert proof["moveId"] == request["moveId"] and proof["sourceClosed"], proof
        assert socket_identity(network, nick) != before
    else:
        assert result["state"] == "failed" and "archive_pending" in json.dumps(result), result
        assert not result.get("sourceClosed") and routed.owner(network) == source, result
        assert socket_identity(network, nick) == before, "pending archive MOVE closed source socket"
    routed.endpoint(body={"moveWitness": None})
    routed.command_ping(network, nick)
    return result


def completed(network, ident, cutoff, buffer="#proof"):
    code, result = status(network, ident, buffer)
    if result.get("status") != "cleared":
        return None
    assert code == 200 and result["state"] == "completed", result
    evidence = {}
    for server in ENGINES:
        found = operation(server, ident)
        assert found, ("HTTP reported completed but the journal operation is missing", server, ident)
        snap, retained = found
        assert retained["state"] == 2, ("HTTP reported completed before the journal operation completed",
                                         server, retained)
        assert retained["cutoffEid"] == cutoff and retained["redisApplied"], retained
        assert retained["sequence"] > 0 and snap["state"]["checkpoint"] >= retained["sequence"], retained
        frozen = group(ident)
        assert retained["legacyCutoffMs"] == frozen["legacyTimestampCutoffMs"], retained
        assert retained["serverId"] == server and retained["networkId"] == network and retained["channel"] == buffer
        projected = json.loads(routed.redis("get", f"irc:archive:operation:{server}:{ident}"))
        assert projected["state"] == "completed" and projected["durable"] and projected["redisApplied"], projected
        assert projected["sequence"] == retained["sequence"] and projected["cutoffEid"] == cutoff, projected
        evidence[server] = {"sequence": retained["sequence"], "checkpoint": snap["state"]["checkpoint"],
                            "cutoffEid": retained["cutoffEid"], "files": snap["files"],
                            "allocatedBytes": snap["allocatedBytes"]}
    assert set(group(ident)["servers"]) == set(ENGINES), group(ident)
    return evidence


def admitted_everywhere(ident):
    evidence = {}
    for server in ENGINES:
        found = operation(server, ident)
        if not found or found[1]["state"] != 1:
            return None
        snapshot, retained = found
        assert retained["sequence"] > snapshot["state"]["checkpoint"], retained
        assert any(frame["sequence"] == retained["sequence"] and
                   frame["record"].get("operationId") == ident for frame in snapshot["frames"]), retained
        lookup = json.loads(routed.redis("get", f"irc:archive:lookup:{server}:{ident}"))
        assert lookup["lookupToken"] == group(ident)["lookupToken"], "admission used stale historical lookup"
        assert lookup["serverId"] == server and lookup["operationId"] == ident, lookup
        evidence[server] = retained["sequence"]
    return evidence


def redis_applied_everywhere(ident):
    evidence = admitted_everywhere(ident)
    if not evidence:
        return None
    for server in ENGINES:
        found = operation(server, ident)
        assert found and found[1]["redisApplied"], (server, "Redis purge not durably applied", found)
    return evidence


def rename_before_purge(network, nick):
    case("actual-Mongo-RENAME-before-delayed-purge")
    before = socket_identity(network, nick)
    original = message(network, nick, "rename-before-purge", "#rename-source")
    original_document = marker_rows(network, "rename-before-purge")[0]
    deliver(nick, [":fixture RENAME #rename-source #rename-target :qualification"])
    def moved():
        stored, live = marker_rows(network, "rename-before-purge"), live_entries(network, "rename-before-purge")
        if len(stored) != 1 or stored[0]["channel"] != "#rename-target":
            return None
        if len(live) != 1 or not live[0][0].endswith(":#rename-target"):
            return None
        assert stored[0]["_id"] == original_document["_id"]
        assert stored[0]["payload"] == original_document["payload"]
        assert stored[0]["eid"] == original["eid"] and stored[0]["t"] == original["t"]
        return stored[0]
    moved_document = wait("pre-cutoff record physically renamed in Redis AND Mongo", moved)
    wait("rename checkpointed before purge", lambda: drained("fixture-old"))
    mongo_fault("delete", True)
    ident = str(uuid.uuid4())
    not_cleared(clear(network, ident, "#rename-target"))
    frozen = wait("renamed buffer frozen", lambda: group(ident) if group(ident).get("cutoffEid", 0) > 0 else None)
    wait("both real purge records blocked on Mongo delete", lambda: admitted_everywhere(ident))
    assert original["eid"] < frozen["cutoffEid"]
    assert marker_rows(network, "rename-before-purge") == [moved_document], "delete fault did not preserve renamed Mongo evidence"
    # The sole FIFO Mongo replayer is blocked by the injected delete failure.
    # Prove the append reached the durable journal, then verify strict replay after unblocking it.
    reused = message(network, nick, "rename-source-reused-after-cutoff", "#rename-source", persisted=False)
    assert reused["eid"] > frozen["cutoffEid"]
    owner = routed.owner(network)
    def reused_journaled():
        snapshot = raw_journal(owner)
        return next((frame for frame in snapshot["frames"]
                     if frame["record"].get("kind") == "append"
                     and "rename-source-reused-after-cutoff" in frame["record"].get("payload", "")), None)
    wait("post-cutoff append durably journaled behind blocked purge", reused_journaled)
    not_cleared(status(network, ident, "#rename-target"), status_query=True)
    mongo_fault("delete", False)
    reused_document = wait("strict Mongo replay: rename-source-reused-after-cutoff",
                           lambda: marker_rows(network, "rename-source-reused-after-cutoff"))
    assert len(reused_document) == 1 and reused_document[0]["eid"] == reused["eid"], reused_document
    proof = wait("renamed clear completes in both journals",
                 lambda: completed(network, ident, frozen["cutoffEid"], "#rename-target"), 120)
    assert not marker_rows(network, "rename-before-purge") and not live_rows(network, "rename-before-purge")
    survived = marker_rows(network, "rename-source-reused-after-cutoff")
    assert len(survived) == 1 and survived[0]["channel"] == "#rename-source" and survived[0]["eid"] == reused["eid"]
    assert len(live_rows(network, "rename-source-reused-after-cutoff")) == 1
    assert socket_identity(network, nick) == before, "rename/clear changed exact physical socket"
    case("rename-before-purge-evidence", operationId=ident, cutoffEid=frozen["cutoffEid"],
         renamedEid=original["eid"], reusedEid=reused["eid"], journals=proof, physicalSocket=before)


def start():
    dc("up", "-d", "--no-build", "redis", "mongo", "native-net", "endpoint", "nord", "mull")
    wait("Redis", lambda: routed.redis("ping") == "PONG")
    def mongo_ready():
        try:
            return routed.mongo("print(db.runCommand({ping:1}).ok)") == "1"
        except AssertionError as error:
            # The compose exec may beat mongod's first bind; retry only that
            # expected startup race, never a different fixture command failure.
            if (len(error.args) == 3 and error.args[1] == 1
                    and "MongoNetworkError: connect ECONNREFUSED 127.0.0.1:27017" in error.args[2]):
                return False
            raise
    wait("Mongo", mongo_ready)
    wait("routed endpoint", lambda: routed.endpoint())
    routed.redis("set", "irc:config:fiberEnabled", "0")
    routed.redis("set", "irc:config:routingSchemaVersion", "1")
    routed.redis("set", routed.POLICY_KEY, json.dumps({"schema": 1, "revision": 0,
        "global": {"order": ["nordvpn", "direct"], "blockedRoutes": []}, "hosts": []}))
    wait("native namespace fixture readiness", lambda:
         routed.ex("native-net", "test", "-f", "/tmp/namespace-ready") == "")
    dc("up", "-d", "--no-build", "native-holder", "old-holder", "gateway", "old-engine", "native-engine")


def run():
    wait("gateway health", lambda: urllib.request.urlopen(routed.BASE + "/health", timeout=2).status == 200)
    routed.login("/register")
    routed.mongo('db.users.updateOne({username:"routedfixture"},{$addToSet:{roles:"admin"}})')
    routed.login("/login")
    wait("fixture admin", lambda: routed.api("GET", "/api/admin/me")["isAdmin"])
    wait("both real engines registered", lambda: all(routed.redis("sismember", "irc:servers", s) == "1" for s in ENGINES))
    routed.priority("fixture-old", 200)
    routed.priority("fixture-native", 10)
    images = {row["Config"]["Labels"]["com.docker.compose.service"]: row["Image"] for row in containers()}
    assert images["old-engine"] == os.environ["ARCHIVE_ENGINE_OLD_IMAGE"]
    assert images["native-engine"] == os.environ["ARCHIVE_ENGINE_IMAGE"]
    assert images["gateway"] == os.environ["ARCHIVE_GATEWAY_IMAGE"]
    assert images["old-holder"] == images["native-holder"] == os.environ["ARCHIVE_HOLDER_IMAGE"]
    baseline()
    case("gateway-B-before-engine-B", images=images)
    nick = "archiveroute"
    network, _ = routed.create(["nordvpn"], nick)
    wait("old unsupported engine actual registration", lambda:
         routed.owner(network) == "fixture-old" and routed.single_upstream(network, nick))
    old_registration = json.loads(routed.redis("hget", "irc:server:fixture-old", "data"))
    assert old_registration.get("archiveVersion", 0) != 1, "old image must actually lack archive capability"
    original = message(network, nick, "unsupported-must-remain", "#unsupported")
    unsupported_id = str(uuid.uuid4())
    code, unavailable = clear(network, unsupported_id, "#unsupported")
    assert code == 503 and unavailable.get("state") in ("not_accepted", "pending", "unknown"), (code, unavailable)
    assert len(marker_rows(network, "unsupported-must-remain")) == 1, "unsupported engine caused direct Mongo purge"
    case("unsupported-clear-evidence", network=network, operationId=unsupported_id,
         httpStatus=code, state=unavailable["state"], originalEid=original["eid"],
         capability=old_registration.get("archiveVersion", 0), mongoRowsPreserved=1)
    before = socket_identity(network, nick)
    os.environ["ROUTED_OLD_ENGINE_IMAGE"] = os.environ["ARCHIVE_ENGINE_IMAGE"]
    # Intentional engine-only replacement; the two holder processes are never
    # stopped, killed, recreated or used as an archival failure injection.
    STARTED.pop("old-engine")
    dc("up", "-d", "--no-build", "--no-deps", "old-engine")
    wait("B journal capability ready on old owner", lambda:
         json.loads(routed.redis("hget", "irc:server:fixture-old", "data")).get("archiveVersion") == 1)
    wait("B reattached same physical upstream", lambda: socket_identity(network, nick) == before)
    assert next(row["Image"] for row in containers() if row["Config"]["Labels"]["com.docker.compose.service"] == "old-engine") == os.environ["ARCHIVE_ENGINE_IMAGE"]
    health()
    baseline()
    wait("second independent B journal ready", lambda:
         json.loads(routed.redis("hget", "irc:server:fixture-native", "data")).get("archiveVersion") == 1)
    # A's replacement can deliver pre-catalog startup events while B correctly
    # reports archival admission unavailable. Retain, never erase or relabel
    # that explicit uncertainty; the routing proof must introduce no new gap.
    for server in ENGINES:
        startup = raw_journal(server)["state"]["gaps"]
        assert all(gap["reason"] == "admission_rejected" and
                   0 < gap["from"] <= gap["through"] <= int(time.time() * 1000)
                   for gap in startup), (server, startup)
        INITIAL_ARCHIVE_GAPS[server] = startup
    case("startup-archive-uncertainty", gaps=INITIAL_ARCHIVE_GAPS,
         gapFreeArchiveClaim=False)
    assert journal("fixture-old")["state"]["spoolId"] != journal("fixture-native")["state"]["spoolId"]
    case("pending-journal-refuses-before-CLOSE", network=network, originalEid=original["eid"])
    source_before = message(network, nick, "A-before-move")
    message(network, nick, "A-offline", "#offline")
    insert_fault(True)
    pending = message(network, nick, "A-pending-before-move", persisted=False)
    wait("real pending append frame", lambda: any("A-pending-before-move" in json.dumps(frame["record"])
         for frame in journal("fixture-old")["frames"]))
    assert not marker_rows(network, "A-pending-before-move")
    move(network, nick, "fixture-native", allowed=False)
    insert_fault(False)
    persisted_pending = wait("pending append drains to original Mongo scope", lambda: marker_rows(network, "A-pending-before-move"))
    assert len(persisted_pending) == 1 and persisted_pending[0]["serverId"] == "fixture-old"
    assert persisted_pending[0]["eid"] == pending["eid"] and persisted_pending[0]["t"] == pending["t"]
    wait("source journal fully checkpointed", lambda: drained("fixture-old"))
    case("quiescent-A-to-B-to-A")
    move(network, nick, "fixture-native")
    target_before = message(network, nick, "B-before-return")
    message(network, nick, "B-offline", "#offline")
    wait("B journal drained", lambda: drained("fixture-native"))
    move(network, nick, "fixture-old")
    message(network, nick, "A-after-return")
    for token, server in (("A-before-move", "fixture-old"), ("B-before-return", "fixture-native"),
                          ("A-after-return", "fixture-old")):
        assert [row["serverId"] for row in marker_rows(network, token)] == [server], token
    for token, original_event in (("A-before-move", source_before), ("B-before-return", target_before)):
        preserved = marker_rows(network, token)[0]
        assert preserved["eid"] == original_event["eid"] and preserved["t"] == original_event["t"]
    rename_before_purge(network, nick)
    case("all-scopes-one-freeze-rename-reuse-delayed-append")
    archive_socket = socket_identity(network, nick)
    legacy_times = seed_legacy(network, "#proof", "legacy-global")
    insert_fault(True)
    delayed = message(network, nick, "delayed-accepted-append", persisted=False)
    wait("delayed append durably present", lambda: any("delayed-accepted-append" in json.dumps(frame["record"])
         for frame in journal("fixture-old")["frames"]))
    operation_id = str(uuid.uuid4())
    # Freeze needs a fresh lookupToken response from EVERY historical engine.
    # Keep both readers alive through fsynced admission; actual Mongo delete
    # failures, not a paused lookup participant, prevent premature completion.
    mongo_fault("delete", True)
    not_cleared(clear(network, operation_id))
    frozen = wait("coordinator frozen cutoff", lambda: group(operation_id) if group(operation_id).get("cutoffEid", 0) > 0 else None)
    cutoff = frozen["cutoffEid"]
    assert set(frozen["servers"]) == set(ENGINES), frozen
    assert pending["eid"] < cutoff and delayed["eid"] < cutoff
    admitted = wait("every historical journal durably admitted before reachability fault",
                    lambda: admitted_everywhere(operation_id))
    assert len(marker_rows(network, "B-before-return")) == 1, "Mongo delete fault did not retain historical scope"
    with pause("native-engine"):
        code, conflict = clear(network, operation_id, "#different")
        assert code == 409, (code, conflict)
        not_cleared(clear(network, operation_id))
        assert group(operation_id)["cutoffEid"] == cutoff, "retry allocated a new cutoff"
        deliver(nick, [":fixture RENAME #proof #renamed :qualification"])
        renamed = message(network, nick, "post-cutoff-renamed", "#renamed", persisted=False)
        reused = message(network, nick, "post-cutoff-reused-name", persisted=False)
        assert min(renamed["eid"], reused["eid"]) > cutoff
        insert_fault(False)
        # The FIFO append can now persist, but neither scope's purge may claim
        # Mongo completion while the separate real delete failure is active.
        wait("delayed append reaches its original Mongo identity", lambda: marker_rows(network, "delayed-accepted-append"))
        not_cleared(status(network, operation_id), status_query=True)
        assert len(marker_rows(network, "A-before-move")) == 1
        assert len(marker_rows(network, "B-before-return")) == 1
        mongo_fault("delete", False)
        wait("local journal completed while historical engine unreachable", lambda:
             operation("fixture-old", operation_id) and operation("fixture-old", operation_id)[1]["state"] == 2)
        not_cleared(status(network, operation_id), status_query=True)
        not_cleared(clear(network, operation_id))
        assert socket_identity(network, nick) == archive_socket, "archival delay changed physical socket"
    proof = wait("all real journals and strict stores completed", lambda: completed(network, operation_id, cutoff), 120)
    for token in ("A-before-move", "A-pending-before-move", "B-before-return", "A-after-return", "delayed-accepted-append"):
        assert not marker_rows(network, token) and not live_rows(network, token), ("pre-cutoff resurrection", token)
    for token, channel in (("post-cutoff-renamed", "#renamed"), ("post-cutoff-reused-name", "#proof")):
        stored = wait("preserved new incarnation " + token, lambda: marker_rows(network, token))
        assert len(stored) == 1 and stored[0]["channel"] == channel and stored[0]["eid"] > cutoff, stored
        assert len(live_rows(network, token)) == 1
    legacy_result(network, "legacy-global", legacy_times, frozen)
    code, retry = clear(network, operation_id)
    assert code == 200 and retry.get("status") == "cleared" and retry["cutoffEid"] == cutoff, (code, retry)
    def beyond_cut(row):
        return row["eid"] > cutoff if "eid" in row else row["t"] > frozen["legacyTimestampCutoffMs"]
    assert all(beyond_cut(row) for row in rows(network)
               if row["channel"] in ("#proof", "#renamed")), "pre-cutoff Mongo rows survived"
    assert all(beyond_cut(row) for key, row in live_entries(network)
               if key.endswith((":#proof", ":#renamed"))), "pre-cutoff Redis/legacy rows survived"
    case("durable-clear-evidence", network=network, operationId=operation_id, cutoffEid=cutoff, journals=proof,
         preCutoffRemoved=5, postCutoffPreserved=2, legacyOldRemoved=3, legacyNewPreserved=3,
         legacyTimestampCutoffMs=frozen["legacyTimestampCutoffMs"], admittedSequences=admitted, physicalSocket=archive_socket)
    case("lost-coordination-retained-ID-is-unknown")
    retained = {server: operation(server, operation_id)[1] for server in ENGINES}
    with pause("native-engine"), pause("old-engine"):
        keys = ["irc:archive:clear:" + operation_id]
        keys += [f"irc:archive:{kind}:{server}:{operation_id}" for server in ENGINES for kind in ("operation", "lookup")]
        routed.redis("del", *keys)
        not_cleared(status(network, operation_id), status_query=True)
        not_cleared(clear(network, operation_id))
    def unknown_retry():
        reply = clear(network, operation_id)
        value = not_cleared(reply)
        return value if value.get("state") == "unknown" else None
    wait("journals refuse refreezing after coordination loss", unknown_retry, 45)
    for server in ENGINES:
        current = operation(server, operation_id)[1]
        assert current["sequence"] == retained[server]["sequence"] and current["cutoffEid"] == cutoff
    assert group(operation_id).get("cutoffEid", 0) in (0, cutoff), "new cutoff after lost coordination"
    assert len(marker_rows(network, "post-cutoff-reused-name")) == 1
    assert socket_identity(network, nick) == archive_socket, "coordination loss changed physical socket"
    case("status-GET-cannot-admit-requested-clear")
    status_id = str(uuid.uuid4())
    marker = "status-get-must-preserve-new-message"
    queued = message(network, nick, marker)
    with pause("native-engine"), pause("old-engine"):
        code, requested = clear(network, status_id)
        not_cleared((code, requested))
        initial_group = group(status_id)
        assert initial_group.get("state") == "requested" and initial_group.get("cutoffEid", 0) == 0, initial_group
        before_backends = backend_snapshot(network)
        before_journals = {server: journal(server) for server in ENGINES}
        code, response = status(network, status_id)
        not_cleared((code, response), status_query=True)
        after_group = group(status_id)
        assert after_group == initial_group, (initial_group, after_group)
        assert backend_snapshot(network) == before_backends, "status GET admitted and applied a purge"
        for server in ENGINES:
            after = journal(server)
            before = before_journals[server]
            assert not operation(server, status_id), "status GET admitted a purge journal operation"
            assert after["state"]["checkpoint"] == before["state"]["checkpoint"]
            assert after["state"]["operations"] == before["state"]["operations"] and after["frames"] == before["frames"]
    code, accepted = clear(network, status_id)
    assert code in (200, 503), (code, accepted)
    if code == 200:
        assert accepted.get("status") == "cleared" and accepted.get("state") == "completed", accepted
    else:
        not_cleared((code, accepted))
    frozen = wait("explicit POST freezes status-polled operation", lambda:
                  group(status_id) if group(status_id).get("cutoffEid", 0) > 0 else None)
    assert queued["eid"] < frozen["cutoffEid"], (queued, frozen)
    proof = wait("explicit POST completes both status-polled journals",
                 lambda: completed(network, status_id, frozen["cutoffEid"]), 120)
    assert not marker_rows(network, marker) and not live_rows(network, marker), "explicit POST did not clear the queued message"
    case("status-GET-lookup-only-evidence", operationId=status_id, messageEid=queued["eid"],
         cutoffEid=frozen["cutoffEid"], journals=proof, postOnlyInitiatedClear=True)
    case("purge-replay-after-engine-SIGKILL-before-Mongo-ack")
    crash_id = str(uuid.uuid4())
    crash_marker = "purge-replay-after-engine-crash"
    crash_message = message(network, nick, crash_marker, "#proof")
    mongo_fault("delete", True)
    not_cleared(clear(network, crash_id))
    crash_group = wait("crash-test cutoff frozen", lambda:
                       group(crash_id) if group(crash_id).get("cutoffEid", 0) > 0 else None)
    assert crash_message["eid"] < crash_group["cutoffEid"], (crash_message, crash_group)
    crash_admission = wait("purge Redis-applied on both durable journals",
                           lambda: redis_applied_everywhere(crash_id), 90)
    crash_socket = socket_identity(network, nick)
    old_row = next(row for row in containers()
                   if row["Config"]["Labels"]["com.docker.compose.service"] == "old-engine")
    old_generation = (old_row["Id"], old_row["State"]["StartedAt"])
    STARTED.pop("old-engine")
    dc("kill", "old-engine")
    wait("old engine process exited for SIGKILL recovery",
         lambda: next(row for row in containers()
                      if row["Config"]["Labels"]["com.docker.compose.service"] == "old-engine")["State"]["Status"]
         == "exited", 30)
    dc("start", "old-engine")
    wait("restarted old engine archive capability",
         lambda: json.loads(routed.redis("hget", "irc:server:fixture-old", "data")).get("archiveVersion") == 1,
         90)
    restarted = next(row for row in containers()
                     if row["Config"]["Labels"]["com.docker.compose.service"] == "old-engine")
    assert restarted["Id"] == old_generation[0] and restarted["State"]["StartedAt"] != old_generation[1], restarted
    STARTED["old-engine"] = (restarted["Id"], restarted["State"]["StartedAt"])
    wait("holder-owned physical socket survived engine SIGKILL", lambda: socket_identity(network, nick) == crash_socket, 60)
    # SIGKILL necessarily leaves the unclean marker; preserve its conservative
    # uncertainty and the one startup admission gap instead of claiming completeness.
    recovered = raw_journal("fixture-old")["state"]["gaps"]
    initial = INITIAL_ARCHIVE_GAPS["fixture-old"]
    assert recovered[:len(initial)] == initial, ("crash recovery rewrote prior gap evidence", recovered)
    new_recovery_gaps = recovered[len(initial):]
    assert len(new_recovery_gaps) == 2 and sorted(gap["reason"] for gap in new_recovery_gaps) == [
        "admission_rejected", "unclean_ram_admission_uncertainty"], new_recovery_gaps
    assert all(0 < gap["from"] <= gap["through"] for gap in new_recovery_gaps), new_recovery_gaps
    assert next(gap for gap in new_recovery_gaps
                if gap["reason"] == "unclean_ram_admission_uncertainty")["from"] == min(
                    gap["from"] for gap in initial), new_recovery_gaps
    RECOVERY_ARCHIVE_GAPS["fixture-old"] = recovered
    assert routed.owner(network) == "fixture-old", "engine SIGKILL changed archive producer ownership"
    routed.command_ping(network, nick)
    assert operation("fixture-old", crash_id)[1]["state"] == 1
    assert operation("fixture-old", crash_id)[1]["redisApplied"]
    mongo_fault("delete", False)
    crash_proof = wait("recovered purge reaches strict Mongo/checkpoint completion",
                       lambda: completed(network, crash_id, crash_group["cutoffEid"]), 120)
    assert not marker_rows(network, crash_marker) and not live_rows(network, crash_marker)
    assert socket_identity(network, nick) == crash_socket
    routed.command_ping(network, nick)
    baseline()
    case("purge-recovery-evidence", operationId=crash_id, cutoffEid=crash_group["cutoffEid"],
         admittedSequences=crash_admission, journals=crash_proof, mongoRowsRemoved=True,
         holderSocketPreserved=True, crashRecoveryGaps=recovered)
    case("offline-unreachable-and-uncatalogued-legacy-Mongo-discovery")
    routed.api("POST", f"/api/networks/{network}/disconnect", {})
    wait("explicit offline network has no upstream", lambda: not routed.held(network) and not routed.physical_registered(nick))
    wait("offline source journal drained", lambda: drained("fixture-old"))
    offline_times = seed_legacy(network, "#offline", "legacy-offline")
    owner_key = "irc:archive:owner:" + network
    # Simulate a genuine pre-catalog database: historical rows remain in both
    # real Mongo server scopes, but neither catalog nor Redis owner can supply
    # those scopes. No synthetic scope is installed as an oracle.
    with pause("native-engine"):
        with pause("old-engine"):
            changed = json.loads(routed.mongo("print(JSON.stringify(db.networks.updateOne({id:" +
                json.dumps(network) + "},{$unset:{archiveScopeVersion:'',archiveServers:''}})))"))
            assert changed["matchedCount"] == 1 and changed["modifiedCount"] == 1, changed
            uncatalogued = json.loads(routed.mongo("print(JSON.stringify(db.networks.findOne({id:" +
                json.dumps(network) + "},{_id:0,archiveScopeVersion:1,archiveServers:1})))"))
            assert uncatalogued == {}, uncatalogued
            routed.redis("del", owner_key, *(f"irc:archive:status:{server}:{network}" for server in ENGINES))
            assert not routed.redis("get", owner_key)
        def offline_backends():
            tokens = ("A-offline", "B-offline", "legacy-offline-old", "legacy-offline-new")
            return {token: {"mongo": sorted(marker_rows(network, token), key=lambda row: row["_id"]),
                            "redis": sorted((key, json.dumps(row, sort_keys=True))
                                            for key, row in live_entries(network, token))}
                    for token in tokens}
        preserved = offline_backends()
        assert all(value["mongo"] and value["redis"] for value in preserved.values()), preserved
        offline_id = str(uuid.uuid4())
        code, unavailable = clear(network, offline_id, "#offline")
        not_cleared((code, unavailable))
        assert code == 503, (code, unavailable)
        unavailable_group = group(offline_id)
        assert unavailable_group.get("cutoffEid", 0) == 0, "unreachable historical engine allowed a fresh cutoff"
        assert set(unavailable_group["servers"]) == set(ENGINES), unavailable_group
        catalog = json.loads(routed.mongo("print(JSON.stringify(db.networks.findOne({id:" +
            json.dumps(network) + "},{_id:0,archiveScopeVersion:1,archiveServers:1})))"))
        assert catalog["archiveScopeVersion"] == 1 and set(catalog["archiveServers"]) == set(ENGINES), catalog
        assert offline_backends() == preserved, "offline unavailable clear mutated backend history"
        assert all(not operation(server, offline_id) for server in ENGINES), "unfrozen offline intent reached a journal"
        not_cleared(status(network, offline_id, "#offline"), status_query=True)
        case("offline-unreachable-evidence", network=network, operationId=offline_id,
             httpStatus=code, state=unavailable["state"], cutoffEid=0, backendRowsPreserved=True,
             discoveredMongoScopes=catalog["archiveServers"])
    # Retry the exact UUID only after the unreachable original engine returns.
    clear(network, offline_id, "#offline")
    offline_group = wait("recovered historical scopes freeze once", lambda:
                         group(offline_id) if group(offline_id).get("cutoffEid", 0) > 0 else None)
    assert set(offline_group["servers"]) == set(ENGINES), offline_group
    offline_proof = wait("offline real journals complete",
                         lambda: completed(network, offline_id, offline_group["cutoffEid"], "#offline"), 120)
    assert not marker_rows(network, "A-offline") and not marker_rows(network, "B-offline")
    assert not live_rows(network, "A-offline") and not live_rows(network, "B-offline")
    legacy_result(network, "legacy-offline", offline_times, offline_group)
    rebuilt = json.loads(routed.redis("get", owner_key))
    assert set(rebuilt["servers"]) == set(ENGINES), rebuilt
    case("offline-clear-evidence", network=network, operationId=offline_id,
         cutoffEid=offline_group["cutoffEid"], journals=offline_proof, preCutoffRemoved=2,
         legacyOldRemoved=3, legacyNewPreserved=3)
    case("fresh-unknown-GET-has-no-side-effects")
    wait("both idle journals drained", lambda: all(drained(server) for server in ENGINES))
    unknown_id = str(uuid.uuid4())
    before_backends = backend_snapshot(network)
    before_journals = {server: journal(server) for server in ENGINES}
    before_eid = routed.redis("get", "irc:global_eid")
    assert before_eid.isdigit(), "missing actual global eid counter"
    code, unknown = status(network, unknown_id)
    assert code == 404 and unknown.get("state") == "unknown", (code, unknown)
    not_cleared((code, unknown), status_query=True)
    assert not group(unknown_id), "GET created coordination group"
    assert backend_snapshot(network) == before_backends, "GET mutated real Mongo/Redis history"
    assert routed.redis("get", "irc:global_eid") == before_eid, "GET allocated a new cutoff"
    for server in ENGINES:
        after = journal(server)
        before = before_journals[server]
        assert after["state"]["checkpoint"] == before["state"]["checkpoint"]
        assert after["state"]["operations"] == before["state"]["operations"] and after["frames"] == before["frames"], "GET mutated real journal"
        for kind in ("operation", "lookup", "pin", "redis-applied"):
            assert not routed.redis("get", f"irc:archive:{kind}:{server}:{unknown_id}"), "GET created operation evidence"
        assert routed.redis("sismember", "irc:archive:clear-pending:" + server, unknown_id) == "0"
    assert routed.redis("sismember", "irc:archive:clear-network-pending:" + network, unknown_id) == "0"
    assert not routed.held(network) and not routed.physical_registered(nick), "offline clear/GET registered a socket"
    case("fresh-unknown-GET-evidence", operationId=unknown_id, httpStatus=code,
         groupCreated=False, journalMutation=False, backendMutation=False, cutoffAllocated=False)
    health()
    final_images = {row["Config"]["Labels"]["com.docker.compose.service"]: row["Image"] for row in containers()}
    print(json.dumps({"result": "PASS", "qualified": False, "scope": "two-engine-archive-routing",
                      "run": routed.PROJECT, "initialImages": images,
                      "images": final_images, "cases": EVIDENCE, "network": network}, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        start()
        with routed.gateway_access():
            run()
    except BaseException as error:
        requested_images = {key: os.environ.get(key, "unavailable") for key in
                            ("ARCHIVE_ENGINE_OLD_IMAGE", "ARCHIVE_ENGINE_IMAGE",
                             "ARCHIVE_GATEWAY_IMAGE", "ARCHIVE_HOLDER_IMAGE")}
        scope = next((item["network"] for item in reversed(EVIDENCE) if "network" in item), None)
        print(json.dumps({"result": "FAIL", "run": routed.PROJECT, "case": CASE,
                          "network": scope, "requestedImages": requested_images,
                          "reason": str(error), "evidence": EVIDENCE}, sort_keys=True), file=sys.stderr, flush=True)
        raise
    finally:
        DEADLINE = time.monotonic() + 90  # bounded fault release even after qualification timeout
        for service in tuple(PAUSED):
            try:
                dc("unpause", service)
            except Exception as error:
                print("fixture unpause failed: " + str(error), file=sys.stderr)
        # Shell owns labelled resource cleanup, including this disposable Mongo.
