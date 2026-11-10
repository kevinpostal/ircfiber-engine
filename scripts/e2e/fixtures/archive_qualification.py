#!/usr/bin/env python3
"""Real isolated archival-B qualification; imports A's physical/load oracle unchanged.

ARCHIVE_CASE=full is the only load production gate: 250+ sessions (125+ TLS),
1800s warm-up, 1800s measurement, actual >=900s owned-Mongo pause and live drain.
ARCHIVE_CASE=smoke permits ARCHIVE_SMOKE_SECONDS=30..300; always qualified=false.
All cases retain 250+ sessions including 125+ TLS; ARCHIVE_SESSIONS<250 is unsupported.
ARCHIVE_CASE=quota uses a separate fresh 32-MiB spool; sticky gaps are mandatory
and qualified=false. Run full and quota separately, never reuse their volumes.
No application builds, production endpoints, Docker cleanup or lifecycle policy
changes occur here. The existing labelled launcher owns all fixture resources.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zlib

from memory_qualification import Qualification as MemoryQualification, require, wait, number, OLD_HOLDER
from memory_fixture import Fixture, encode, resp

MIB = 1024**2
MARKERS = ("rename-before", "rename-after", "rename-reuse", "clear-before", "clear-after")


class InventoryFixture(Fixture):
    """Memory wire fixture with bounded, metadata-free new-holder observations."""
    def __init__(self):
        super().__init__()
        self.inventory_networks = {}
        self.holder_instance = None

    async def holder_request(self, verb, payload):
        reader, writer = await asyncio.open_unix_connection("/run/ircfiber/holder.sock", limit=9 * MIB)
        try:
            writer.write(b'HELLO {"proto":1,"serverId":"fixture-regression","engine":"qualified-holder-observer"}\n')
            await writer.drain()
            require((await asyncio.wait_for(reader.readline(), 20)).startswith(b"OK "), "qualified holder HELLO rejected")
            writer.write((verb + " " + json.dumps(payload) + "\n").encode())
            await writer.drain()
            reply = await asyncio.wait_for(reader.readline(), 20)
            require(reply.startswith(b"OK "), "qualified holder observation rejected")
            require(len(reply) <= (65536 if verb == "INVENTORY" else 8 * MIB + 65536), "holder response outside byte cap")
            return json.loads(reply[3:])
        finally:
            writer.close()

    async def holder(self, verb):
        if verb != "LIST":
            return await super().holder(verb)
        # Only the first observation of an ID needs one INFO to associate its
        # original tag; subsequent scans retain metadata-free inventory only.
        result, cursor = [], {}
        for _ in range(8):
            page = await self.holder_request("INVENTORY", cursor)
            require(len(page["connections"]) <= 128, "holder inventory page exceeds 128")
            if self.holder_instance is None:
                self.holder_instance = page["instance"]
            require(page["instance"] == self.holder_instance, "holder incarnation changed")
            for row in page["connections"]:
                identifier = row["id"]
                if identifier not in self.inventory_networks:
                    require(len(self.inventory_networks) < 512, "held identity association exceeds bound")
                    detail = await self.holder_request("INFO", {"id": identifier})
                    self.inventory_networks[identifier] = detail["tag"]["networkId"]
                    del detail
                require(row.get("droppedLines") == 0 and not row.get("deliveryAmbiguous"),
                        "holder relay lost/ambiguously delivered bytes under representative load")
                result.append(dict(id=identifier, networkId=self.inventory_networks[identifier],
                                   state=row["state"], connectedAtMs=row["connectedAtMs"],
                                   attached=row["attached"], bufferedBytes=row["bufferedBytes"]))
                require(len(result) <= 512, "held inventory exceeds session cap")
            if not page["more"]:
                return result
            cursor = {key: page[key] for key in ("instance", "through")}
            cursor["after"] = page["nextAfter"]
        raise RuntimeError("holder inventory pagination exceeds bound")


class ArchiveFixture(InventoryFixture):
    """Only bounded real-wire injection and original live-identity observations."""
    def __init__(self):
        super().__init__()
        self.archive_live = {}

    async def archive_subscriber(self):
        reader, writer = await asyncio.open_connection("192.0.2.2", 6379)
        writer.write(encode("PSUBSCRIBE", "irc:events:*"))
        await writer.drain()
        require((await resp(reader))[0] == b"psubscribe", "archive subscriber not acknowledged")
        try:
            while True:
                message = await resp(reader)
                if message[0] != b"pmessage":
                    continue
                event = json.loads(message[3])
                token = event.get("x", "")
                if event.get("c") != "PRIVMSG" or not token.startswith("AQ:"):
                    continue
                require(token.removeprefix("AQ:") in MARKERS, "unexpected archive marker")
                require(token not in self.archive_live, "duplicate live archive marker")
                require(len(self.archive_live) < len(MARKERS), "archive marker bound exceeded")
                self.archive_live[token] = {k: event[k] for k in ("eid", "t", "nid", "c", "x")}
        finally:
            writer.close()

    async def run(self):
        self.task(self.archive_subscriber())
        await super().run()

    async def control(self, command):
        action = command["action"]
        if action == "archiveLive":
            return self.archive_live
        if action == "archiveInject":
            nick = command["nick"]
            session = self.by_nick[nick]
            require(nick in self.networks.values() and not session.closed, "injection target is not owned/live")
            phase = command["phase"]
            lines = {
                "before": [f":{nick}!u@mock JOIN #archive-old", f":{nick}!u@mock JOIN #archive-clear",
                           ":m000!u@mock PRIVMSG #archive-old :AQ:rename-before",
                           ":m000!u@mock PRIVMSG #archive-clear :AQ:clear-before"],
                "rename": [":mock RENAME #archive-old #archive-new :qualification rename",
                           ":m000!u@mock PRIVMSG #archive-new :AQ:rename-after",
                           f":{nick}!u@mock JOIN #archive-old",
                           ":m000!u@mock PRIVMSG #archive-old :AQ:rename-reuse"],
                "after": [":m000!u@mock PRIVMSG #archive-clear :AQ:clear-after"],
            }
            require(phase in lines, "invalid bounded injection phase")
            await session.send(lines[phase])
            return {"sent": phase}
        return await super().control(command)


def journal_snapshot(cutoff, after=None):
    """CRC-check only the synced prefix; page identities with fixed memory/output."""
    root = Path("/var/lib/ircfiber/archive")
    files = list(root.iterdir())
    require(len(files) <= 160, "archive file bound exceeded")
    probes, controls, per_network = [], [], {}
    numbered, numbered_bytes, more = [], 0, False
    allocated = 0
    previous = 0
    frames, first_sequence = 0, 0
    for path in sorted(files):
        stat = path.stat()
        allocated += stat.st_blocks * 512
        if not path.name.startswith("segment-"):
            require(path.name in ("lock", "state"), "unexpected spool evidence file")
            continue
        require(stat.st_size <= 4 * MIB, "archive segment exceeds 4 MiB")
        with path.open("rb") as stream:
            require(stream.read(8) == b"IFARv001", "invalid journal magic")
            while True:
                header = stream.read(16)
                if not header:
                    break
                # Concurrent active-tail writes may be incomplete; these bytes
                # are not used as durable evidence. Any complete frame is CRC checked.
                if len(header) < 16:
                    break
                length, checksum, sequence = struct.unpack("<IIQ", header)
                require(0 < length <= MIB, "journal record outside byte bound")
                if sequence > cutoff:
                    break
                payload = stream.read(length)
                require(len(payload) == length, "durable journal frame is truncated")
                require(zlib.crc32(struct.pack("<Q", sequence) + payload) == checksum,
                        "durable journal frame CRC mismatch")
                require(sequence > previous and (not previous or sequence == previous + 1),
                        "durable journal sequence has a hole/reordering")
                previous = sequence
                if not frames:
                    first_sequence = sequence
                frames += 1
                record = json.loads(payload)
                record["sequence"] = sequence
                if record["kind"] != "append" and after is None:
                    require(len(controls) < 128, "control evidence bound exceeded")
                    controls.append(record)
                    continue
                if record["kind"] != "append":
                    continue
                event = json.loads(record["payload"])
                text = event.get("x", "")
                network = record["networkId"]
                count = per_network.get(network, 0)
                if after is not None:
                    if text.startswith("MR:") and sequence > after:
                        encoded_bytes = len(json.dumps(record, separators=(",", ":")).encode())
                        if len(numbered) == 256 or numbered_bytes + encoded_bytes > 512 * 1024:
                            more = True
                        elif not more:
                            numbered.append(record)
                            numbered_bytes += encoded_bytes
                    continue
                if text.startswith("AQ:") or (text.startswith("MR:") and count < 2):
                    require(len(probes) < 1030, "journal probe bound exceeded")
                    probes.append(record)
                    if text.startswith("MR:"):
                        per_network[network] = count + 1
    return dict(files=len(files), allocatedBytes=allocated, frames=frames,
                firstSequence=first_sequence, throughSequence=previous, requestedDurableSequence=cutoff, probes=probes, controls=controls,
                numbered=numbered, more=more, nextAfter=numbered[-1]["sequence"] if numbered else after)


class ArchiveQualification(MemoryQualification):
    def __init__(self):
        super().__init__(expected_holder_image=os.environ["ROUTING_REGRESSION_HOLDER_IMAGE"],
                         qualification_scope="archival B candidate load proof")
        self.overlay = os.environ["ARCHIVE_COMPOSE_FILE"]
        self.case = os.environ.get("ARCHIVE_CASE", "full")
        require(self.case in ("full", "smoke", "quota"), "invalid archive case")
        self.short_seconds = int(os.environ.get("ARCHIVE_SMOKE_SECONDS", "60"))
        require(30 <= self.short_seconds <= 300, "directed smoke must be 30..300 seconds")
        require(self.gateway == "http://127.0.0.1:" + os.environ["ROUTING_REGRESSION_PORT"],
                "refusing nonfixture gateway")
        require(os.environ["ROUTING_REGRESSION_HOLDER_IMAGE"] != OLD_HOLDER, "B requires new qualified holder")
        self.max_spool = int(os.environ["ROUTING_REGRESSION_ARCHIVE_MAX_BYTES"])
        require(self.max_spool == (32 * MIB if self.case == "quota" else 512 * MIB), "wrong isolated spool quota")
        self.paused_mongo = False
        self.probes = {}
        self.last_gap_count = 0
        self.max_gap_count = 0
        self.archive_checkpoints = 0

    def dc(self, *args, **kwargs):
        return self.command("compose", "--project-name", self.project, "-f", self.compose,
                            "-f", self.overlay, *args, **kwargs)

    def save(self, name, data):
        if name == "manifest.json":
            data = dict(data, scope="archival B candidate; full and quota are separate owned runs",
                        case=self.case, qualified=False, originalServerId="fixture-regression",
                        spoolMaxBytes=self.max_spool, mongoOutageSeconds=900 if self.case == "full" else self.short_seconds,
                        acceptance=dict(sessions=self.sessions, minimumTlsSessions=125,
                                        warmupSeconds=1800, measuredSeconds=1800, messagesPerSecond=100),
                        shortened=self.case != "full")
        super().save(name, data)

    def check_sample(self, sample):
        super().check_sample(sample)
        archive = sample.get("archive")
        if isinstance(archive, str):
            archive = sample["archive"] = json.loads(archive)
        require(isinstance(archive, dict), "missing actual archive counters")
        for key, cap in (("ingressCommands", 1024), ("ingressBytes", 8 * MIB), ("pendingOperations", 128)):
            value = archive.get(key)
            if value is None and not archive.get("ready"):
                continue
            require(0 <= number(value) <= cap, "archive bound exceeded: " + key)
        require(number(archive.get("maxBytes")) == self.max_spool, "runtime spool quota differs from fixture")
        require(number(archive.get("maxIngressCommands")) == 1024
                and number(archive.get("maxIngressBytes")) == 8 * MIB
                and number(archive.get("maxReplayBytes")) == MIB, "unexpected archive ingress/replay limits")
        if archive.get("ready"):
            require(not archive.get("failed"), "archive worker failed")
            require(0 <= number(archive.get("diskBytes")) <= self.max_spool, "allocated spool exceeds budget")
            require(isinstance(archive.get("replayInFlight"), bool), "missing one-record replay diagnostic")
            require(number(archive.get("consumerFibers")) == 1 and number(archive.get("diskThreads")) == 1,
                    "archive consumer-fiber/native-disk-thread lifecycle is not single-owner")
            require(number(archive.get("minFreeBytes")) == 2 * 1024**3
                    and number(archive.get("freeBytes")) >= 0, "archive filesystem reserve/availability missing")
            gap_count = number(archive.get("gapCount"))
            require(self.last_gap_count == 0 or gap_count > 0, "sticky archive gaps disappeared")
            self.last_gap_count = gap_count
            self.max_gap_count = max(self.max_gap_count, gap_count)
        return sample

    def archive(self):
        sample = self.latest()
        archive = sample["archive"]
        require(archive["ready"] and not archive["failed"] and not archive["stopping"], "archive is not ready")
        require(time.time() * 1000 - number(archive["diskSampledAtMs"]) < 75000,
                "spool allocation evidence stale/unavailable")
        return archive

    def history(self, network, channel="#memory0", before_eid=None):
        encoded = urllib.parse.quote(channel, safe="")
        query = "?count=20" + ("" if before_eid is None else "&beforeid=" + str(before_eid))
        return self.api("GET", f"/api/channels/{network}/{encoded}/messages" + query)

    def projection(self, network):
        archive = self.history(network).get("archive")
        require(isinstance(archive, dict) and archive.get("version") == 1, "missing HTTP archive projection")
        require(archive.get("state") in ("healthy", "pending", "gap"), "HTTP archive projection unavailable")
        require(abs(time.time() * 1000 - number(archive.get("sampledAtMs"))) < 90000, "HTTP archive projection stale")
        gaps = archive.get("gaps", []) + archive.get("uncertainty", [])
        require(isinstance(gaps, list) and len(gaps) <= 512 * 64, "unbounded/invalid HTTP gaps")
        require((archive["state"] == "gap") == bool(gaps), "HTTP gap/healthy state contradicts sticky intervals")
        return archive

    def http_result(self, method, path, body=None):
        request = urllib.request.Request(self.gateway + path, method=method,
                                        data=None if body is None else json.dumps(body).encode(),
                                        headers={"Content-Type": "application/json"})
        try:
            response = self.http.open(request, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            require(len(raw) <= 65536, "clear response exceeds byte bound")
            return response.code, json.loads(raw)

    def mongo(self, javascript, timeout=90):
        require(not self.paused_mongo, "do not issue Mongo queries while owned Mongo is paused")
        self.owned("mongo")
        return json.loads(self.command("exec", "-i", self.ids["mongo"], "mongosh", "--quiet",
                                      "mongodb://127.0.0.1/ircfiber_regression_fixture", "--file", "/dev/stdin",
                                      data=javascript, timeout=timeout, max_bytes=2 * MIB))

    def mongo_count(self):
        return self.mongo('print(JSON.stringify({count:db.messages.countDocuments({payload:{$regex:"MR:"}})}))')["count"]

    def pause_mongo(self):
        info = self.owned("mongo")
        require(self.identity(info) == self.protected["mongo"] and info["State"]["Running"]
                and not info["State"]["Paused"], "Mongo pause target generation changed")
        self.command("pause", info["Id"])
        self.paused_mongo = True
        require(self.owned("mongo")["State"]["Paused"], "actual Mongo pause was not observed")
        self.pause_started = time.monotonic()

    def resume_mongo(self):
        if not self.paused_mongo:
            return
        info = self.owned("mongo")
        require(self.identity(info) == self.protected["mongo"], "refusing unpause of changed/foreign Mongo")
        self.command("unpause", info["Id"])
        self.paused_mongo = False
        require(not self.owned("mongo")["State"]["Paused"], "Mongo remains paused")

    def journal(self, name):
        archive = self.archive()
        result = json.loads(self.command("exec", "-i", self.ids["mock-irc"], "python3",
                            "/fixture/archive_qualification.py", "journal", str(int(archive["durableSequence"])),
                            timeout=90, max_bytes=2 * MIB))
        require(result["files"] <= 160 and result["allocatedBytes"] <= self.max_spool, "physical spool allocation bound exceeded")
        for record in result["probes"]:
            token = json.loads(record["payload"])["x"]
            prior = self.probes.get(token)
            require(prior is None or prior == record, "journal identity changed between observations")
            self.probes[token] = record
        require(len(self.probes) <= 2060, "retained journal evidence outside fixed bound")
        self.save(name, result)
        return result

    def settled_archive(self):
        # Live receipt follows processor admission, but does not imply fsync.
        # A fresh disk-owner sample with empty ingress proves every admission
        # before this fence has either synced or been explicitly rejected.
        started = time.time() * 1000
        return wait(lambda: (lambda a: a if number(a["diskSampledAtMs"]) >= started
                             and a["ingressCommands"] == 0 else False)(self.archive()),
                    "fresh disk-owner empty-ingress fence", 90)

    def numbered_journal(self, cutoff, checkpoint):
        after = 0
        for _ in range(2048):
            page = json.loads(self.command("exec", "-i", self.ids["mock-irc"], "python3",
                              "/fixture/archive_qualification.py", "journal", str(cutoff), str(after),
                              timeout=90, max_bytes=1024 * 1024))
            require(page["files"] <= 160 and page["allocatedBytes"] <= self.max_spool,
                    "physical spool allocation bound exceeded")
            require(page["firstSequence"] <= checkpoint + 1 and page["throughSequence"] == cutoff,
                    "synced journal prefix missing between checkpoint and durable watermark")
            for record in page["numbered"]:
                yield record
            if not page["more"]:
                return
            require(page["nextAfter"] > after, "journal evidence page made no progress")
            after = page["nextAfter"]
        raise RuntimeError("numbered journal evidence exceeds fixed page bound")

    def remember_admission(self, record):
        event = json.loads(record["payload"])
        network = record["networkId"]
        require(network in self.networks and record["serverId"] == "fixture-regression"
                and record["channel"] == "#memory0", "foreign durable numbered admission")
        serial = int(event["x"].split(":")[2])
        state = self.admitted[network]
        require(serial > state["last"], "duplicate/out-of-order durable admission identity")
        identity = [record["serverId"], network, str(record["eid"]), str(record["timestampMs"]), record["payload"]]
        encoded = (json.dumps(identity, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        self.admission_bytes += len(encoded)
        require(self.admission_bytes <= 128 * MIB, "durable identity evidence exceeds 128 MiB")
        self.admission_stream.write(encoded)
        state["hash"].update(encoded)
        state["last"] = serial
        state["count"] += 1

    def quota_baseline(self):
        # Freeze a fully drained, strictly contiguous baseline before the real
        # outage. Checkpointed warm-up segments may already have been reclaimed.
        wire = self.catch_up()
        self.drain(stopped=True)
        self.cold_oracle(wire, baseline=True)
        self.admitted = {nid: dict(count=0, last=0, hash=hashlib.sha256()) for nid in self.networks}
        self.admission_bytes = 0
        self.admission_stream = (self.output / "quota-durable-identities.jsonl").open("xb")
        for network in self.networks:
            after = 0
            for _ in range(2048):
                script = '''const rows=db.messages.find({networkId:NETWORK,eid:{$gt:Long(AFTER)},
payload:{$regex:'MR:'}}).sort({eid:1}).limit(256).toArray();
print(JSON.stringify(rows.map(d=>({serverId:d.serverId,networkId:d.networkId,channel:d.channel,
eid:d.eid.toString(),timestampMs:Number(d.t),payload:d.payload}))));'''
                rows = self.mongo(script.replace("NETWORK", json.dumps(network)).replace("AFTER", json.dumps(str(after))))
                for row in rows:
                    self.remember_admission(row)
                    after = int(row["eid"])
                if len(rows) < 256:
                    break
            else:
                raise RuntimeError("baseline identity evidence exceeds fixed page bound")
            expected = next(s for s in wire["sessions"] if s["nick"] == self.networks[network])
            require(self.admitted[network]["count"] == expected["sent"],
                    "quota baseline does not cover every original warm-up row")
        self.admission_stream.flush()
        os.fsync(self.admission_stream.fileno())
        self.quota_prefix = {n: s["last"] for n, s in self.admitted.items()}

    def quota_durable_fence(self):
        self.catch_up()
        archive = self.settled_archive()
        for record in self.numbered_journal(int(archive["durableSequence"]), int(archive["checkpoint"])):
            serial = int(json.loads(record["payload"])["x"].split(":")[2])
            if serial > self.admitted[record["networkId"]]["last"]:
                self.remember_admission(record)
            else:
                # Only the fully verified pre-outage prefix can overlap.
                require(serial <= self.quota_prefix[record["networkId"]],
                        "duplicate numbered journal admission")
        self.admission_stream.flush()
        os.fsync(self.admission_stream.fileno())
        self.admission_stream.close()
        self.save("quota-durable-admissions.json", dict(durableSequence=archive["durableSequence"],
                  identityBytes=self.admission_bytes, networks={n: dict(count=s["count"], last=s["last"],
                  hash=s["hash"].hexdigest()) for n, s in self.admitted.items()}))

    def record_archive(self, phase, wire):
        archive = self.archive()
        require(self.archive_checkpoints < 800, "archive checkpoint bound exceeded")
        self.archive_checkpoints += 1
        with (self.output / "archive-samples.jsonl").open("a") as stream:
            stream.write(json.dumps(dict(at=time.time(), phase=phase, archive=archive,
                                        sent=sum(s["sent"] for s in wire["sessions"]),
                                        received=sum(s["received"] for s in wire["sessions"])), separators=(",", ":")) + "\n")
        return archive

    def run_load(self, duration, phase):
        deadline = time.monotonic() + duration
        self.rpc("load", enabled=True)
        first = self.wire()
        while time.monotonic() < deadline:
            status = self.wire()
            self.record_archive(phase, status)
            self.assert_protected()
            info = self.owned("ircfiber-engine")
            require(info["State"]["Running"] and self.identity(info) == self.stationary_engine,
                    "engine restarted/OOM; restart is not boundedness")
            self.checkpoint(phase, status)
            time.sleep(min(30, max(0, deadline - time.monotonic())))
        final = self.wire()
        sent = sum(s["sent"] for s in final["sessions"]) - sum(s["sent"] for s in first["sessions"])
        received = sum(s["received"] for s in final["sessions"]) - sum(s["received"] for s in first["sessions"])
        require(sent >= duration * 99 and received >= duration * 98, "actual wire/Redis rate below representative load")
        return final

    def mutation_start(self):
        self.mutation_network = next(iter(self.networks))
        nick = self.networks[self.mutation_network]
        self.rpc("archiveInject", nick=nick, phase="before")
        wait(lambda: len(self.rpc("archiveLive")) >= 2, "original pre-mutation live events")
        self.rpc("archiveInject", nick=nick, phase="rename")
        wait(lambda: len(self.rpc("archiveLive")) >= 4, "ordered rename and reused-buffer live events")
        self.operation = str(uuid.uuid4())
        path = f"/api/networks/{self.mutation_network}/buffers/clear"
        body = dict(operationId=self.operation, buffer="#archive-clear")
        code, response = self.http_result("POST", path, body)
        require(code == 503 and response.get("state") in ("pending", "unknown")
                and response.get("operationId") == self.operation and response.get("status") != "cleared",
                "Mongo outage clear falsely completed/rejected or lost its stable operation ID")
        def frozen():
            raw = self.command("exec", self.ids["redis"], "redis-cli", "--raw", "GET", "irc:archive:clear:" + self.operation).strip()
            if not raw:
                return False
            group = json.loads(raw)
            return group if number(group.get("cutoffEid")) > 0 else False
        group = wait(frozen, "single coordinated clear cutoff", 90)
        self.frozen_cutoff = group["cutoffEid"]
        self.rpc("archiveInject", nick=nick, phase="after")
        wait(lambda: len(self.rpc("archiveLive")) == len(MARKERS), "post-cutoff live marker")
        live = self.rpc("archiveLive")
        require(live["AQ:clear-after"]["eid"] > self.frozen_cutoff >= live["AQ:clear-before"]["eid"],
                "clear did not straddle real processor cutoff")
        code2, retry = self.http_result("POST", path, body)
        require(code2 == 503 and retry.get("status") != "cleared", "retry cleared while Mongo paused")
        again = frozen()
        require(again["cutoffEid"] == self.frozen_cutoff, "stable clear ID acquired a replacement cutoff")
        conflict, _ = self.http_result("POST", path, dict(operationId=self.operation, buffer="#archive-old"))
        require(conflict == 409, "operation-ID scope conflict was not rejected")
        self.save("clear-pending.json", dict(operationId=self.operation, first=response, retry=retry,
                                             cutoffEid=self.frozen_cutoff, originalLive=live))

    def mutation_complete(self):
        path = f"/api/networks/{self.mutation_network}/buffers/clear/{self.operation}"
        def completed():
            code, body = self.http_result("GET", path)
            require(code in (200, 503), "clear status returned unexpected HTTP status")
            if body.get("state") == "completed":
                require(code == 200 and body.get("status") == "cleared" and body.get("operationId") == self.operation
                        and body.get("cutoffEid") == self.frozen_cutoff, "invalid coordinated completed clear")
                return body
            require(body.get("status") != "cleared", "uncompleted clear claims cleared")
            return False
        result = wait(completed, "durable Mongo/Redis/checkpoint clear completion", 900)
        self.save("clear-completed.json", result)
        code, retry = self.http_result("POST", f"/api/networks/{self.mutation_network}/buffers/clear",
                                      dict(operationId=self.operation, buffer="#archive-clear"))
        require(code == 200 and retry.get("status") == "cleared" and retry.get("cutoffEid") == self.frozen_cutoff,
                "terminal same-ID retry did not preserve original cutoff")

    def crash_proof(self):
        # Persist original framed identities while Mongo cannot acknowledge, then
        # kill only the engine. This really replays uncheckpointed durable rows.
        before = {s["nick"]: s["sent"] for s in self.catch_up()["sessions"]}
        self.pause_mongo()
        try:
            for tls in (False, True):
                nick = next(s["nick"] for s in self.wire()["sessions"] if s["tls"] == tls)
                self.rpc("burst", nick=nick)
            final = self.catch_up()
            target = {nid: (nick, before[nick], next(s["sent"] for s in final["sessions"] if s["nick"] == nick))
                      for nid, nick in self.networks.items()}
            fence_started = time.time() * 1000
            def synced_bursts():
                archive = self.archive()
                cutoff = int(archive["durableSequence"])
                if number(archive["diskSampledAtMs"]) < fence_started:
                    return False
                if cutoff <= int(archive["checkpoint"]):
                    return False
                counts = {n: 0 for n in target}
                hashes = {n: hashlib.sha256() for n in target}
                for record in self.numbered_journal(cutoff, int(archive["checkpoint"])):
                    event = json.loads(record["payload"])
                    network = record["networkId"]
                    require(network in target, "foreign numbered crash admission")
                    nick, low, high = target[network]
                    serial = int(event["x"].split(":")[2])
                    if serial <= low:
                        continue
                    require(serial <= high and serial == low + counts[network] + 1,
                            "durable crash burst missing/reordered/duplicated")
                    digest = hashlib.sha256((nick + "/" + str(serial)).encode()).hexdigest()
                    require(event["x"] == f"MR:{nick}:{serial}:{digest}", "corrupt durable crash burst")
                    counts[network] += 1
                    hashes[network].update((event["x"] + "\n").encode())
                if any(counts[n] != high - low for n, (_, low, high) in target.items()):
                    return False
                return dict(durableSequence=cutoff, networks={n: dict(count=counts[n],
                            hash=hashes[n].hexdigest(), first=low + 1, last=high)
                            for n, (_, low, high) in target.items() if high > low})
            # durableSequence is published by the real disk owner only after
            # file+directory fsync. Every one of the 10,000 numbered burst rows
            # must exist, CRC-valid and contiguous, below that synced watermark.
            fence = wait(synced_bursts, "every numbered burst record fsynced before SIGKILL", 90)
            require(sum(n["count"] for n in fence["networks"].values()) == 10000,
                    "crash proof requires both original 5,000-line bursts")
            self.save("crash-durable-fence.json", fence)
            snapshot = self.journal("crash-journal.json")
            require(len(snapshot["probes"]) >= 4, "no original durable crash-replay probes")
            self.assert_protected()
            self.command("kill", "--signal", "SIGKILL", self.ids["ircfiber-engine"])
            require(not self.inspect(self.ids["ircfiber-engine"])["State"]["Running"], "SIGKILL did not stop engine")
            self.stop_logs()
            probe = self.rpc("probe")
            require(probe["errorCount"] == 0, "detached PONG failed after SIGKILL")
            self.command("start", self.ids["ircfiber-engine"])
            self.start_logs()
            wait(lambda: self.all_attached(), "all original holder sockets reattached after crash", 180)
            wait(lambda: self.latest()["archive"].get("ready"), "native spool crash recovery", 120)
            require(self.held() == self.held_baseline, "holder socket identity changed across SIGKILL")
            self.assert_protected()
            self.save("sigkill.json", dict(held=self.held(), detachedProbe=probe, originalProbeCount=len(snapshot["probes"])))
            self.faults.append("SIGKILL_uncheckpointed_durable_replay")
        finally:
            self.resume_mongo()
        self.stationary_engine = self.identity(self.owned("ircfiber-engine"))
        self.drain(stopped=True)
        self.cold_oracle(self.catch_up(), partial=True)
        self.crash_intervals = {nid: self.projection(nid).get("uncertainty", [])
                                for nid in self.networks}
        require(self.archive()["gapCount"] > 0 and all(self.crash_intervals.values()),
                "SIGKILL RAM-admission uncertainty was not durably exposed")
        self.save("crash-uncertainty.json", self.crash_intervals)

    def drain(self, stopped=False, gaps_allowed=False):
        if stopped:
            self.rpc("load", enabled=False)
        else:
            self.rpc("load", enabled=True)
        if stopped:
            start = time.monotonic()
            first_count = self.mongo_count()
            first_wire = self.wire()
            backlog = self.archive()["pendingBytes"]
        else:
            start = self.outage_resumed_at
            # All numbered sends observed just after the pause are a strict
            # upper bound on rows Mongo could have persisted before suspension.
            # Using this bound never credits already-drained rows as throughput.
            first_count = self.outage_cold_upper_bound
            first_wire = self.outage_final_wire
            backlog = self.outage_pending_bytes
        best_rate = 0.0
        previous_count, previous_at = first_count, start
        while time.monotonic() - start < 1200:
            time.sleep(10)
            status = self.wire()
            archive = self.record_archive("cold-drain", status)
            self.assert_protected()
            require(self.identity(self.owned("ircfiber-engine")) == self.stationary_engine, "engine restarted during drain")
            count = self.mongo_count()
            now = time.monotonic()
            rate = (count - previous_count) / (now - previous_at)
            best_rate = max(best_rate, rate)
            previous_count, previous_at = count, now
            outstanding = sum(s["received"] for s in status["sessions"]) - count
            if (archive["pendingBytes"] == 0 and archive["ingressCommands"] == 0
                    and (gaps_allowed or outstanding <= (0 if stopped else 1000))):
                if not stopped:
                    elapsed = now - start
                    arrivals = sum(s["received"] for s in status["sessions"]) - sum(s["received"] for s in first_wire["sessions"])
                    rate_all = (count - first_count) / elapsed
                    require(backlog > 0 and rate_all > 100 and count - first_count > arrivals,
                            "cold Mongo backlog did not drain faster than continuing 100/s arrivals")
                result = dict(seconds=now - start, initialPendingBytes=backlog,
                              initialColdRowsUpperBound=first_count, finalColdRows=count,
                              provenMinimumRowsPerSecond=(count - first_count) / (now - start),
                              bestObservedRowsPerSecond=best_rate, liveContinued=not stopped)
                self.save("drain-stopped.json" if stopped else "drain-live.json", result)
                return result
        raise RuntimeError("cold Mongo backlog did not drain within twenty minutes")

    def cold_oracle(self, wire, partial=False, gaps_allowed=False, baseline=False):
        expected = {nid: dict(nick=nick, sent=next(s["sent"] for s in wire["sessions"] if s["nick"] == nick),
                              sentHash=next(s["sentHash"] for s in wire["sessions"] if s["nick"] == nick))
                    for nid, nick in self.networks.items()}
        if gaps_allowed:
            for network, state in self.admitted.items():
                expected[network].update(admittedCount=state["count"], admittedHash=state["hash"].hexdigest())
        # Mongo cursor streams all numbered records in real eid order. O(networks)
        # state detects duplicates, holes, corruption, attribution and reordering.
        javascript = r'''
const crypto=require('crypto'); const expected=EXPECTED; const gapsAllowed=GAPS;
const state={}; for(const [n,e] of Object.entries(expected)) state[n]={count:0,last:0,hash:crypto.createHash('sha256'),identityHash:crypto.createHash('sha256')};
let total=0; const errors=[]; const fail=x=>{if(errors.length<16)errors.push(x)};
const cursor=db.messages.find({payload:{$regex:'MR:'}}).sort({networkId:1,eid:1}).allowDiskUse().batchSize(256);
while(cursor.hasNext()) {const d=cursor.next(); const p=JSON.parse(d.payload);if(p.c!=='PRIVMSG'||!p.x?.startsWith('MR:'))continue;
 const e=expected[d.networkId],s=state[d.networkId];if(!e||!s){fail('foreign network');continue;}
 const parts=p.x.split(':'), serial=Number(parts[2]);const digest=crypto.createHash('sha256').update(e.nick+'/'+serial).digest('hex');
 if(parts.length!==4||parts[1]!==e.nick||parts[3]!==digest||serial<=s.last||(!gapsAllowed&&serial!==s.last+1))fail('numbered payload order/content '+d.networkId);
 if(d.serverId!=='fixture-regression'||d.channel!=='#memory0'||Number(d.eid)<=0||Number(d.eid)!==p.eid||Number(d.t)!==p.t||p.nid!==d.networkId)fail('original attribution/eid/t mismatch');
 s.last=serial;s.count++;s.hash.update(p.x+'\n');total++;
 s.identityHash.update(JSON.stringify([d.serverId,d.networkId,d.eid.toString(),d.t.toString(),d.payload])+'\n');
}
const rows={};for(const [n,e]of Object.entries(expected)){const s=state[n],h=s.hash.digest('hex');
 if(!gapsAllowed&&(s.count!==e.sent||h!==e.sentHash))fail('cold count/hash mismatch '+n);
 if(gapsAllowed&&(s.count!==e.admittedCount||s.identityHash.digest('hex')!==e.admittedHash))fail('lost/changed/extra durable admission '+n);
 if(s.last>e.sent||s.count>e.sent)fail('extra/duplicate cold numbered row '+n);
 rows[n]={count:s.count,last:s.last,hash:h,expected:e.sent};}
print(JSON.stringify({total,networks:rows,errors}));
'''.replace("EXPECTED", json.dumps(expected)).replace("GAPS", "true" if gaps_allowed else "false")
        result = self.mongo(javascript, timeout=180)
        require(not result["errors"], "cold Mongo oracle failure: " + str(result["errors"]))
        if baseline:
            self.save("quota-baseline-oracle.json", result)
            return result
        # Separately compare exact journal compact bytes and immutable identities.
        probes = list(self.probes.values())
        self.save("original-journal-probes.json", probes)
        script = '''const probes=PROBES;let verified=0;const errors=[];
for(const p of probes){const e=JSON.parse(p.payload);if(e.x==='AQ:clear-before')continue;
 const rows=db.messages.find({serverId:p.serverId,networkId:p.networkId,eid:Long(p.eid.toString())}).limit(2).toArray();
 if(rows.length!==1||rows[0].payload!==p.payload||Number(rows[0].t)!==p.timestampMs){if(errors.length<16)errors.push({eid:p.eid,network:p.networkId});}else verified++;}
print(JSON.stringify({verified,errors}));'''.replace("PROBES", json.dumps(probes))
        identities = self.mongo(script)
        require(not identities["errors"] and identities["verified"] > 0, "original journal identity/bytes not recovered once")
        result["originalJournalIdentities"] = identities
        self.save("cold-crash-oracle.json" if partial else "cold-row-oracle.json", result)
        return result

    def mutation_oracle(self):
        network = self.mutation_network
        rows = self.mongo('''const rows=[];for(const d of db.messages.find({networkId:NETWORK,payload:{$regex:'AQ:'}}).limit(16)){
const p=JSON.parse(d.payload);rows.push({channel:d.channel,eid:Number(d.eid),t:Number(d.t),serverId:d.serverId,token:p.x,payload:d.payload});}
print(JSON.stringify(rows));'''.replace("NETWORK", json.dumps(network)))
        expected = {"AQ:rename-before": "#archive-new", "AQ:rename-after": "#archive-new",
                    "AQ:rename-reuse": "#archive-old", "AQ:clear-after": "#archive-clear"}
        require(len(rows) == len(expected) and {r["token"] for r in rows} == set(expected),
                "cold rename/clear resurrected, lost or duplicated markers")
        live = self.rpc("archiveLive")
        for row in rows:
            original = live[row["token"]]
            require(row["channel"] == expected[row["token"]] and row["serverId"] == "fixture-regression"
                    and row["eid"] == original["eid"] and row["t"] == original["t"],
                    "mutation changed original identity or incorrect FIFO channel")
        for channel in ("#archive-new", "#archive-old", "#archive-clear"):
            page = self.history(network, channel)
            tokens = {m.get("x", m.get("text", "")) for m in page["messages"]}
            wanted = {token for token, dest in expected.items() if dest == channel}
            require(wanted <= tokens and "AQ:clear-before" not in tokens, "HTTP mutation history disagrees with cold oracle")
        self.save("mutation-cold-oracle.json", dict(rows=rows, originalLive=live, operationId=self.operation,
                                                    cutoffEid=self.frozen_cutoff))

    def write_failpoint(self, enabled):
        command = dict(configureFailPoint="failCommand", mode="alwaysOn" if enabled else "off")
        if enabled:
            command["data"] = dict(failCommands=["insert", "update", "delete"], errorCode=91)
        reply = self.mongo("print(JSON.stringify(db.adminCommand(" + json.dumps(command) + ")))")
        require(reply.get("ok") == 1, "owned Mongo write-failure injection was not acknowledged")
        self.write_fault = enabled

    def outage(self, duration, mutate=True):
        self.rpc("load", enabled=True)
        if mutate:
            # Ownership/history require Mongo reads. Fail real archive writes
            # while keeping reads live for the HTTP barrier proof, then perform
            # the independent full-process pause for the required 15 minutes.
            self.write_failpoint(True)
            self.mutation_start()
            pending_http = self.projection(self.mutation_network)
            require(pending_http["state"] in ("pending", "gap"), "write outage falsely reports healthy over HTTP")
            self.save("http-write-outage.json", pending_http)
        self.pause_mongo()
        before = self.wire()
        self.outage_cold_upper_bound = sum(s["sent"] for s in before["sessions"])
        try:
            self.run_load(duration, "mongo-paused")
            require(self.owned("mongo")["State"]["Paused"], "Mongo outage did not remain physically paused")
            elapsed = time.monotonic() - self.pause_started
            require(elapsed >= duration, "Mongo outage shortened")
            after = self.wire()
            require(sum(s["received"] for s in after["sessions"]) - sum(s["received"] for s in before["sessions"]) >= duration * 98,
                    "Redis/live delivery stalled during actual Mongo outage")
            archive = self.archive()
            require(archive["pendingBytes"] > 0, "Mongo outage has no measured backlog")
            network = next(iter(self.networks))
            raw = self.command("exec", self.ids["redis"], "redis-cli", "--raw", "GET",
                               "irc:archive:status:fixture-regression:" + network).strip()
            projection = json.loads(raw)
            require(projection.get("state") in ("pending", "gap")
                    and abs(time.time() * 1000 - number(projection.get("sampledAtMs"))) < 90000,
                    "paused Mongo archive projection falsely healthy/stale")
            snapshot = self.journal("outage-journal.json")
            if mutate:
                controls = snapshot["controls"]
                renames = [r for r in controls if r["kind"] == "rename" and r["channel"] == "#archive-old"]
                purges = [r for r in controls if r["kind"] == "purge" and r["operationId"] == self.operation]
                require(len(renames) == len(purges) == 1 and renames[0]["sequence"] < purges[0]["sequence"],
                        "real durable FIFO rename/purge evidence missing")
            self.outage_pending_bytes = archive["pendingBytes"]
            self.outage_final_wire = after
            self.save("mongo-outage.json", dict(pausedSeconds=elapsed, before=before, after=after,
                                                archive=archive, redisProjection=projection,
                                                httpDuringPause="unavailable: authenticated ownership requires Mongo reads"))
            if self.case == "quota":
                # Capture every remaining synced numbered identity while Mongo
                # is still paused: none can disappear through reclamation.
                self.quota_durable_fence()
        finally:
            self.resume_mongo()
            self.outage_resumed_at = time.monotonic()
            if getattr(self, "write_fault", False):
                self.write_failpoint(False)

    def setup(self):
        super().setup()
        wait(lambda: self.archive(), "archive B native journal ready", 120)
        require(sum(s["tls"] for s in self.wire()["sessions"]) >= 125, "require at least 125 physical TLS sessions")
        mounts = self.owned("ircfiber-engine")["Mounts"]
        volumes = [m for m in mounts if m["Destination"] == "/var/lib/ircfiber/archive" and m["Type"] == "volume" and m["RW"]]
        require(len(volumes) == 1, "engine archive is not one durable writable named volume")
        volume = json.loads(self.command("volume", "inspect", volumes[0]["Name"]))[0]
        require(volume["Labels"].get("ircfiber.fixture.run") == self.run_id, "archive volume is not run-owned")
        self.save("archive-volume.json", dict(name=volumes[0]["Name"], labels=volume["Labels"], maxBytes=self.max_spool))

    def run(self):
        self.setup()
        if self.case == "quota":
            self.stationary_engine = self.identity(self.owned("ircfiber-engine"))
            # Allow two writable segments beyond state/control/lock reserves so
            # normal rotation works before the independent pressure exercise.
            self.run_load(300, "quota-warmup")
            self.quota_baseline()
            memory_before = self.latest()
            self.outage(900, mutate=False)
            memory_after = self.latest()
            increase = (number(memory_after["cgroupBytes"]) + number(memory_after["cgroupSwapBytes"])
                        - number(memory_before["cgroupBytes"]) - number(memory_before["cgroupSwapBytes"]))
            require(increase <= 32 * MIB, "quota pressure grew resident+swap by more than 32 MiB")
            self.save("quota-memory.json", dict(before=memory_before, after=memory_after,
                                               cgroupPlusSwapIncreaseBytes=increase))
            require(self.archive()["gapCount"] > 0, "small quota did not produce an explicit sticky archive gap")
            self.catch_up()
            self.drain(stopped=True, gaps_allowed=True)
            status = self.catch_up()
            oracle = self.cold_oracle(status, gaps_allowed=True)
            require(oracle["total"] < sum(s["sent"] for s in status["sessions"]), "quota did not reject real archival records")
            projection = self.projection(next(iter(self.networks)))
            require(projection["state"] == "gap" and self.archive()["gapCount"] > 0, "drain erased sticky quota gap")
            require(self.held() == self.held_baseline, "quota pressure lost holder sockets")
            self.assert_protected()
            require(self.identity(self.owned("ircfiber-engine")) == self.stationary_engine
                    and self.all_attached(), "quota run ended with changed engine generation or detached relays")
            self.save("final.json", dict(wire=status, held=self.held(), archive=self.archive(),
                                         projection=projection))
            return dict(state="passed", qualified=False, scope="independent quota/gap proof only", httpProjection=projection,
                        missingColdNumberedRows=sum(s["sent"] for s in status["sessions"]) - oracle["total"])
        self.crash_proof()
        self.rpc("load", enabled=True)
        self.run_load(self.warmup if self.case == "full" else self.short_seconds, "warmup")
        start = time.time()
        self.run_load(self.soak if self.case == "full" else self.short_seconds, "measured")
        end = time.time()
        evaluation = self.evaluate(start, end) if self.case == "full" else {"shortened": True}
        self.outage(900 if self.case == "full" else self.short_seconds)
        drain = self.drain()
        self.mutation_complete()
        final = self.catch_up()
        self.drain(stopped=True)
        oracle = self.cold_oracle(final)
        self.mutation_oracle()
        original = next(p for p in self.probes.values() if json.loads(p["payload"])["x"].startswith("MR:")
                        and json.loads(p["payload"])["x"].split(":")[2] == "1")
        page = self.history(original["networkId"], before_eid=int(original["eid"]) + 1)
        token = json.loads(original["payload"])["x"]
        historical = [m for m in page["messages"] if m.get("x", m.get("text")) == token]
        require(len(historical) == 1 and historical[0].get("eid") == original["eid"]
                and historical[0].get("t") == original["timestampMs"],
                "authenticated historical HTTP lost/duplicated or reassigned original cold row")
        self.save("historical-http-oracle.json", dict(original=original, page=page,
                                                    independentColdMongoVerified=True))
        projections = {nid: self.projection(nid) for nid in self.networks}
        gap_count = self.archive()["gapCount"]
        for nid, projection in projections.items():
            require(projection.get("uncertainty", []) == self.crash_intervals[nid],
                    "new archival loss/uncertainty appeared after the deliberate crash")
            if projection.get("gaps") or projection.get("uncertainty"):
                require(projection["state"] == "gap", "drained historical gap hidden as healthy")
            else:
                require(projection["state"] == "healthy" and projection.get("pendingBytes") == 0,
                        "fully drained gap-free network is not healthy")
        require(self.held() == self.held_baseline, "final holder socket identity changed")
        self.assert_protected()
        require(self.all_attached(), "final qualified holder is not fully attached")
        require(self.identity(self.owned("ircfiber-engine")) == self.stationary_engine, "final engine generation changed")
        require(all(s["churn"] > 0 for s in final["sessions"]), "unique churn did not reach every held session")
        self.save("final.json", dict(wire=final, held=self.held(), archive=self.archive(), projections=projections))
        return dict(state="passed", qualified=self.case == "full", scope="archival B load proof" if self.case == "full" else "directed smoke only",
                    case=self.case, faults=self.faults, stickyGapCount=gap_count, archiveHealthy=gap_count == 0,
                    coldRows=oracle["total"], drain=drain, memory=evaluation)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        asyncio.run(ArchiveFixture().run())
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "journal":
        print(json.dumps(journal_snapshot(int(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else None),
                         separators=(",", ":")))
        return 0
    qualification = None
    try:
        qualification = ArchiveQualification()
        result = qualification.run()
    except BaseException as error:
        result = dict(state="failed", qualified=False,
                      reason=(type(error).__name__ + ": " + str(error))[:2000], scope="archival B")
    finally:
        if qualification:
            for cleanup in (qualification.resume_mongo, qualification.stop_logs):
                try:
                    cleanup()
                except BaseException as error:
                    result = dict(state="failed", qualified=False, scope="archival B",
                                  reason=("qualification cleanup failed: " + str(error))[:2000])
    result.update(case=os.environ.get("ARCHIVE_CASE"), run=os.environ.get("ROUTING_REGRESSION_RUN"),
                  inputImages={component: os.environ.get("ROUTING_REGRESSION_" + component.upper() + "_IMAGE")
                               for component in ("engine", "holder", "gateway")},
                  sessionsRequested=qualification.sessions if qualification else None,
                  networksObserved=len(qualification.networks) if qualification else None)
    path = os.environ.get("ARCHIVE_EVIDENCE_DIR")
    if path and Path(path).is_dir():
        (Path(path) / "result.json").write_text(json.dumps(result) + "\n")
    print(json.dumps(result), flush=True)
    return 0 if result["state"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
