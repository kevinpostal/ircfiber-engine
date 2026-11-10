#!/usr/bin/env python3
"""Separate full corrected-holder working-set/engine comparison, never A or B.

Uses MemoryQualification's unshrunk 250-session / 1800+1800-second physical,
PONG, SIGTERM/SIGKILL, roster/churn, live hash and engine-memory gates. Adds
actual holder GC/cgroup/owner/queue samples, not a synthetic holder pass.
Only the existing internal fixture listeners are used. No Mongo faults or
archive volume/overlay is enabled; the original old-holder A gate is unchanged.
"""
import asyncio
from collections import defaultdict, deque
import hashlib
from itertools import islice
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.request

from archive_qualification import InventoryFixture
from memory_qualification import Qualification as MemoryQualification, OLD_HOLDER, require, number, slope

MIB = 1024**2
SCOPE = "Corrected-holder working-set and engine comparison only; not Rollout A or archival B"
QUEUE_CAPS = {"relay": (64 * MIB, 4 * MIB), "outbound": (8 * MIB, 65536), "pong": (4 * MIB, 65536)}


class HolderMemoryQualification(MemoryQualification):
    def __init__(self):
        image = os.environ["ROUTING_REGRESSION_HOLDER_IMAGE"]
        require(image != OLD_HOLDER, "corrected-holder comparison cannot use the old A holder")
        super().__init__(expected_holder_image=image, qualification_scope=SCOPE)
        self.holder_samples = []
        self.holder_lock = threading.Lock()
        self.holder_process = self.holder_thread = None
        self.holder_error = None
        self.http_trace = deque(maxlen=16)
        self.http_auth_captured = False
        class ObserveCookieHeaders(urllib.request.BaseHandler):
            # HTTPCookieProcessor runs at 500. Observe its actual outgoing
            # result without adding/removing any header or changing auth.
            handler_order = 501
            def http_request(observer, request):
                if self.http_trace:
                    hops = self.http_trace[-1].setdefault("outgoing", [])
                    if len(hops) < 4:
                        header = request.get_header("Cookie", "")
                        hops.append(dict(cookieHeaderPresent=bool(header),
                                         cookieHeaderFingerprint=hashlib.sha256(header.encode()).hexdigest()))
                return request
        self.http.add_handler(ObserveCookieHeaders())

    def cookie_metadata(self):
        return dict(count=len(self.cookie), cookies=[
            dict(name=c.name, domain=c.domain, path=c.path, secure=c.secure,
                 expires=c.expires, discard=c.discard,
                 valueFingerprint=hashlib.sha256(c.value.encode()).hexdigest())
            for c in islice(self.cookie, 16)])

    def api(self, method, path, body=None, form=False):
        record = dict(at=time.time(), method=method, path=path, cookiesBefore=self.cookie_metadata())
        self.http_trace.append(record)
        try:
            response = super().api(method, path, body=body, form=form)
            record["outcome"] = "success"
            return response
        except Exception as error:
            record["outcome"] = "failed"
            record["error"] = (type(error).__name__ + ": " + str(error))[:1500]
            # Preserve unauthorized-response context before a roster wait
            # replaces it with later requests. Never log cookie values.
            if "HTTP 401:" in str(error) and not self.http_auth_captured:
                self.http_auth_captured = True
                try:
                    self.save("failure-http-auth.json", dict(observedAt=time.time(),
                              requests=list(self.http_trace), cookiesAfter=self.cookie_metadata()))
                except Exception as evidence_error:
                    record["evidenceError"] = str(evidence_error)[:500]
            raise
        finally:
            record["durationSeconds"] = time.time() - record["at"]
            record["cookiesAfter"] = self.cookie_metadata()

    def capture_failure_evidence(self, result):
        """Capture independent bounded fixtures even if another capture fails."""
        errors = {}
        def capture(name, collect):
            try:
                self.save(name, collect())
            except Exception as error:
                errors[name] = (type(error).__name__ + ": " + str(error))[:500]
        capture("failure-wire.json", lambda: self.rpc("status"))
        def generations():
            values = {}
            for service, cid in self.ids.items():
                try:
                    info = self.inspect(cid)
                    values[service] = dict(self.identity(info), running=info["State"]["Running"],
                                           exitCode=info["State"]["ExitCode"], error=info["State"].get("Error", "")[:500])
                except Exception as error:
                    values[service] = dict(unavailable=str(error)[:500])
            return values
        capture("failure-generations.json", generations)
        capture("failure-engine-registry.json", lambda: json.loads(self.command(
            "exec", self.ids["redis"], "redis-cli", "--json", "HGETALL", "irc:server:fixture-regression")))
        for service in ("ircfiber-engine", "ircfiber-gateway", "ircfiber-holder", "redis", "mongo"):
            def logs(service=service):
                info = self.owned(service)
                require(info["Id"] == self.ids[service], "diagnostic target generation changed")
                return self.command("logs", "--tail", "80", info["Id"], include_stderr=True, max_bytes=1024**2)
            capture("failure-" + service + "-logs.json", logs)
        def auth():
            redis = self.owned("redis")
            require(redis["Id"] == self.ids["redis"], "session diagnostic Redis generation changed")
            sessions = []
            for cookie in islice(self.cookie, 16):
                state = json.loads(self.command("exec", redis["Id"], "redis-cli", "--raw", "EVAL",
                    "local t=redis.call('TYPE',KEYS[1]).ok; local r={type=t,exists=redis.call('EXISTS',KEYS[1]),pttl=redis.call('PTTL',KEYS[1])}; "
                    "if t=='hash' then r.expiresAt=redis.call('HGET',KEYS[1],'_expiresAt') or cjson.null; "
                    "r.userIdPresent=redis.call('HEXISTS',KEYS[1],'sessionUserId') end; return cjson.encode(r)",
                    "1", "session:" + cookie.value, timeout=15, max_bytes=4096))
                sessions.append(dict(cookieName=cookie.name,
                                     valueFingerprint=hashlib.sha256(cookie.value.encode()).hexdigest(), redis=state))
            return dict(observedAt=time.time(), cookies=self.cookie_metadata(), sessionStates=sessions,
                        requests=list(self.http_trace), redaction="no cookie values, session IDs or user IDs")
        capture("failure-http-auth-final.json", auth)
        if errors:
            result["evidenceErrors"] = errors

    def check_holder_sample(self, sample):
        for field in ("gcUsedBytes", "gcCollections", "cgroupBytes", "cgroupSwapBytes",
                      "cgroupMaxEvents", "cgroupOomEvents", "cgroupOomKillEvents"):
            number(sample.get(field))
        for field in ("cgroupMaxEvents", "cgroupOomEvents", "cgroupOomKillEvents"):
            require(number(sample[field]) == 0, "corrected holder hit cgroup pressure/OOM: " + field)
        for key in ("holderOwners", "holderQueues"):
            if isinstance(sample.get(key), str):
                sample[key] = json.loads(sample[key])
            require(isinstance(sample.get(key), dict), "missing actual holder diagnostic: " + key)
        owners = sample["holderOwners"]
        require(0 <= number(owners.get("metaBytes")) <= 128 * MIB, "holder META aggregate exceeds 128 MiB")
        require(0 <= number(owners.get("tombstones")) <= 4096, "holder tombstones exceed fixed bound")
        require(number(owners.get("droppedLines")) == 0 and number(owners.get("droppedBytes")) == 0
                and number(owners.get("gapEntries")) == 0, "holder lost wire data below pressure limits")
        for name, (aggregate, session) in QUEUE_CAPS.items():
            queue = sample["holderQueues"].get(name)
            require(isinstance(queue, dict), "missing holder queue lane: " + name)
            require(number(queue.get("maxBytes")) == aggregate and number(queue.get("sessionMaxBytes")) == session,
                    "unexpected holder queue cap: " + name)
            reserved = number(queue.get("reservedBytes"))
            require(0 <= reserved <= aggregate, "holder reservation exceeds aggregate cap: " + name)
            require(0 <= number(queue.get("queuedReservedBytes")) + number(queue.get("inFlightReservedBytes")) <= reserved,
                    "holder queued/in-flight ownership exceeds reservations: " + name)
        return sample

    def start_logs(self):
        super().start_logs()
        if self.holder_process is not None:
            return
        self.holder_process = subprocess.Popen(
            ["docker", "--context", self.context, "logs", "--follow", "--since",
             self.inspect(self.ids["ircfiber-holder"])["State"]["StartedAt"], self.ids["ircfiber-holder"]],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        process = self.holder_process
        def collect():
            try:
                while True:
                    line = process.stdout.readline(32769)
                    if not line:
                        return
                    require(len(line) <= 32768, "holder diagnostic line exceeds bound")
                    try:
                        sample = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if isinstance(sample.get("fields"), dict):
                        sample = sample["fields"]
                    if sample.get("event") != "memory_sample":
                        continue
                    sample["fixtureObservedAt"] = time.time()
                    self.check_holder_sample(sample)
                    with self.holder_lock:
                        require(len(self.holder_samples) < 1100, "holder sample ring bound exceeded")
                        self.holder_samples.append(sample)
                        with (self.output / "holder-memory-samples.jsonl").open("a") as stream:
                            stream.write(json.dumps(sample, separators=(",", ":")) + "\n")
            except Exception as error:
                self.holder_error = str(error)
        self.holder_thread = threading.Thread(target=collect, daemon=True)
        self.holder_thread.start()

    def latest_holder(self):
        require(self.holder_error is None, "holder collector failed: " + str(self.holder_error))
        with self.holder_lock:
            require(self.holder_samples, "no actual holder memory samples")
            sample = self.holder_samples[-1]
        require(time.time() - sample["fixtureObservedAt"] <= 75, "holder memory diagnostic stale")
        return self.check_holder_sample(sample)

    def wire(self, caught_up=False):
        status = super().wire(caught_up=caught_up)
        self.latest_holder()
        return status

    def setup(self):
        super().setup()
        holder = self.owned("ircfiber-holder")
        values = holder["Config"]["Env"]
        require("IRCFIBER_HOLDER_DETACH_MAX_SECS=0" in values, "corrected-holder fixture did not disable detach expiry")
        require(sum(s["tls"] for s in self.wire()["sessions"]) >= 125, "working set requires 125+ actual TLS sessions")
        status = self.rpc("holderStatus")
        require({"inventory_v1", "gap_ack_v1", "bounded_meta_v1", "independent_pong_v1"}
                <= set(status.get("capabilities", [])), "corrected holder capabilities unavailable")
        self.save("holder-baseline.json", dict(identity=self.identity(holder), status=status,
                                               memory=self.latest_holder(), scope=SCOPE))

    def evaluate(self, start, end):
        engine = super().evaluate(start, end)
        self.latest_holder()
        with self.holder_lock:
            samples = [s for s in self.holder_samples if start <= s["fixtureObservedAt"] <= end]
        require(len(samples) >= self.soak // 30 - 3, "missing holder samples in measured window")
        require(samples[0]["fixtureObservedAt"] - start <= 60 and end - samples[-1]["fixtureObservedAt"] <= 60,
                "missing holder measurement endpoints")
        require(all(b["fixtureObservedAt"] - a["fixtureObservedAt"] <= 75 for a, b in zip(samples, samples[1:])),
                "holder measurement gap")
        for sample in samples:
            self.check_holder_sample(sample)
            owners = sample["holderOwners"]
            require(number(owners.get("liveEntries")) == self.sessions, "holder live population shrank/grew")
            require(number(owners.get("timerTasks")) == 0, "unlimited-detach holder retained expiry timers")
            for key in ("readerTasks", "upstreamWriterTasks", "attachmentWriterTasks", "pumpTasks"):
                require(0 <= number(owners.get(key)) <= self.sessions, "holder task ownership grew: " + key)
        combined = lambda s: number(s["cgroupBytes"]) + number(s["cgroupSwapBytes"])
        last15 = [s for s in samples if s["fixtureObservedAt"] >= end - 900]
        require(len(last15) >= 28, "missing holder final fifteen-minute window")
        increase = combined(last15[-1]) - combined(last15[0])
        require(increase <= 32 * MIB, "holder resident+swap increased more than 32 MiB in final fifteen minutes")
        values = sorted(combined(s) for s in samples)
        p99 = values[math.ceil(len(values) * 0.99) - 1]
        require(p99 < 0.85 * 2 * 1024**3, "holder p99 working set lacks 15% headroom under unchanged 2-GiB cap")
        groups, previous = defaultdict(list), None
        for sample in samples:
            count = number(sample["gcCollections"])
            if previous is not None:
                require(count >= previous, "holder GC counter rolled back")
                if count > previous:
                    owners = sample["holderOwners"]
                    signature = tuple(number(owners.get(k)) for k in ("liveEntries", "metaMembersKnown", "openMembersKnown"))
                    groups[signature].append((sample["fixtureObservedAt"], number(sample["gcUsedBytes"])))
            previous = count
        require(groups, "no actual holder post-collection observations")
        comparable = max(groups.values(), key=len)
        require(len(comparable) >= 3 and comparable[-1][0] - comparable[0][0] >= 900,
                "insufficient holder post-collection samples at identical logical owner/member counts")
        growth = slope(comparable)
        require(growth <= 0, "holder collection-updated GC estimate trends upward")
        holder = dict(samples=len(samples), p99CgroupPlusSwapBytes=p99,
                      target512MiBP99Met=p99 <= 512 * MIB,
                      last15MinuteCgroupPlusSwapIncreaseBytes=increase,
                      postCollectionComparableSamples=len(comparable), gcUsedSlopeBytesPerSecond=growth,
                      first=samples[0], last=samples[-1],
                      gcAccounting="collection_updated_estimate; not exact live-object census")
        self.save("holder-memory-evaluation.json", holder)
        return dict(engine=engine, holder=holder)

    def stop_holder_logs(self):
        if self.holder_process is not None:
            self.holder_process.terminate()
            self.holder_process.wait(timeout=10)
            self.holder_thread.join(timeout=10)
            self.holder_process = None


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        asyncio.run(InventoryFixture().run())
        return 0
    qualification = None
    try:
        qualification = HolderMemoryQualification()
        result = qualification.run()
        result["holderWorkingSetQualified"] = True
    except BaseException as error:
        result = dict(state="failed", reason=(type(error).__name__ + ": " + str(error))[:2000],
                      holderWorkingSetQualified=False)
    finally:
        if qualification:
            if result["state"] != "passed":
                qualification.capture_failure_evidence(result)
            for cleanup in (qualification.stop_logs, qualification.stop_holder_logs):
                try:
                    cleanup()
                except BaseException as error:
                    result["state"] = "failed"
                    result["holderWorkingSetQualified"] = False
                    result.setdefault("cleanupErrors", []).append(str(error)[:500])
    result.update(scope=SCOPE, qualified=False, rolloutAQualified=False, archiveBQualified=False,
                  inputImages={k: os.environ.get("ROUTING_REGRESSION_" + k.upper() + "_IMAGE")
                               for k in ("engine", "holder", "gateway")},
                  run=os.environ.get("ROUTING_REGRESSION_RUN"),
                  sessions=qualification.sessions if qualification else None)
    path = os.environ.get("MEMORY_EVIDENCE_DIR")
    if path and Path(path).is_dir():
        (Path(path) / "result.json").write_text(json.dumps(result) + "\n")
    print(json.dumps(result), flush=True)
    return 0 if result["state"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
