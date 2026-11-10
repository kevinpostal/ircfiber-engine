#!/usr/bin/env python3
"""Rollout-A qualification. Missing data is failure, never a zero/pass.

Evidence: manifest/result JSON, memory-samples JSONL, checkpoints JSONL and
full before/after/final wire oracle JSON. No raw chat or growing traffic log.
A is intentionally not the later holder saturation or durable-archive proof.
"""
from collections import defaultdict
from fixture_http import LoopbackFixtureCookies
import json
import os
from pathlib import Path
import statistics
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import urllib.error

CHANNELS = [f"#memory{i}" for i in range(10)]
STABLE = {f"m{i:03x}" for i in range(2000)}
OLD_HOLDER = "sha256:8e7447fa51f9b2fa88fb4b88de8687af6483d8e078c147181469125bc0d82f09"
FULL_MEMORY_PROFILE = "full_memory"
LEGACY_CONTINUITY_PROFILE = "legacy_holder_continuity"
QUEUE_LIMITS = {"metrics": (4096, 4 * 1024**2), "tracing": (1024, 4 * 1024**2),
                "logging": (8192, 8 * 1024**2)}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def wait(predicate, reason, seconds=120):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception as error:
            last = str(error)
        time.sleep(0.5)
    raise RuntimeError(f"timeout: {reason}; last error: {last}")


def number(value):
    if isinstance(value, str):
        value = json.loads(value)
    require(isinstance(value, (int, float)) and not isinstance(value, bool), "unavailable numeric diagnostic")
    return value


def slope(points):
    mean_x = statistics.mean(x for x, _ in points)
    mean_y = statistics.mean(y for _, y in points)
    denominator = sum((x - mean_x)**2 for x, _ in points)
    require(denominator > 0, "insufficient distinct regression timestamps")
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator


class Qualification:
    def __init__(self, expected_holder_image=OLD_HOLDER, qualification_scope=None, *,
                 _profile=FULL_MEMORY_PROFILE):
        """Full memory gates stay mandatory except for the explicit legacy wire-only profile."""
        require(_profile in (FULL_MEMORY_PROFILE, LEGACY_CONTINUITY_PROFILE), "unknown qualification profile")
        self.profile = _profile
        require(isinstance(expected_holder_image, str) and expected_holder_image.startswith("sha256:")
                and len(expected_holder_image) == 71
                and all(c in "0123456789abcdef" for c in expected_holder_image[7:]),
                "expected holder must be an explicit immutable image ID")
        self.expected_holder_image = expected_holder_image
        self.qualification_scope = qualification_scope if qualification_scope is not None else (
            "Rollout A only" if expected_holder_image == OLD_HOLDER else "Candidate holder working-set only")
        require(isinstance(self.qualification_scope, str) and self.qualification_scope.strip()
                and len(self.qualification_scope) <= 256, "qualification scope must be a bounded nonempty label")
        self.context = os.environ["DOCKER_CONTEXT"]
        self.project = os.environ["COMPOSE_PROJECT_NAME"]
        self.compose = os.environ["COMPOSE_FILE"]
        self.run_id = os.environ["ROUTING_REGRESSION_RUN"]
        self.gateway = os.environ["GATEWAY_URL"]
        self.output = Path(os.environ["MEMORY_EVIDENCE_DIR"])
        if self.profile == LEGACY_CONTINUITY_PROFILE:
            require(expected_holder_image == OLD_HOLDER and qualification_scope is not None,
                    "legacy continuity requires the exact old holder and an explicit bounded scope label")
            self.sessions = int(os.environ.get("LEGACY_CONTINUITY_SESSIONS", "12"))
            self.warmup = self.soak = 0
            require(4 <= self.sessions <= 64, "legacy continuity requires 4..64 sessions (default 12)")
        else:
            self.sessions = int(os.environ.get("MEMORY_SESSIONS", "250"))
            self.warmup = int(os.environ.get("MEMORY_WARMUP_SECONDS", "1800"))
            self.soak = int(os.environ.get("MEMORY_SOAK_SECONDS", "1800"))
            require(250 <= self.sessions <= 500, "qualification cannot shrink the 250-session set")
            require(1800 <= self.warmup <= 7200 and 1800 <= self.soak <= 7200,
                    "require 30-minute warm-up plus at least 30-minute measured soak (each at most two hours)")
        require(self.gateway.startswith("http://127.0.0.1:"), "fixture gateway must be loopback")
        require(os.environ["ROUTING_REGRESSION_HOLDER_IMAGE"] == self.expected_holder_image,
                "A requires exact old holder" if self.expected_holder_image == OLD_HOLDER
                else "candidate holder differs from explicit expected immutable image")
        self.cookie = LoopbackFixtureCookies(self.gateway)
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie))
        self.samples = []
        self.sample_lock = threading.Lock()
        self.log_error = None
        self.log_process = None
        self.log_thread = None
        self.engine_epoch = 0
        self.networks = {}
        self.names = {}
        self.ids = {}
        self.protected = {}
        self.baseline = None
        self.load_started = None
        self.faults = []

    def command(self, *args, data=None, timeout=90, max_bytes=2 * 1024**2, include_stderr=False):
        process = subprocess.Popen(["docker", "--context", self.context, *args], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # All commands have fixture-bounded output (not docker logs/LIST dumps).
        try:
            stdout, stderr = process.communicate(None if data is None else data.encode(), timeout=timeout)
        except BaseException:
            process.kill()
            process.communicate()
            raise
        require(len(stdout) <= max_bytes and len(stderr) <= max_bytes, "Docker result outside fixture byte bound")
        require(process.returncode == 0, f"Docker {args[0]} failed: {stderr.decode(errors='replace')[:500]}")
        return stdout.decode() + (stderr.decode(errors="replace") if include_stderr else "")

    def dc(self, *args, **kwargs):
        return self.command("compose", "--project-name", self.project, "-f", self.compose, *args, **kwargs)

    def inspect(self, identifier):
        return json.loads(self.command("inspect", identifier))[0]

    def owned(self, service):
        cid = self.dc("ps", "-aq", service).strip()
        require(cid and "\n" not in cid, "missing/ambiguous fixture " + service)
        info = self.inspect(cid)
        labels = info["Config"]["Labels"]
        for key, expected in {"ircfiber.fixture": "routing-regression", "ircfiber.fixture.run": self.run_id,
                              "com.docker.compose.project": self.project, "com.docker.compose.service": service}.items():
            require(labels.get(key) == expected, "refusing foreign fixture " + service)
        require(info["HostConfig"]["RestartPolicy"]["Name"] == "no", "fixture must not auto-restart")
        return info

    def identity(self, info):
        return {key: info["State"][key] for key in ("Pid", "StartedAt", "Restarting", "OOMKilled")} | {
            "id": info["Id"], "image": info["Image"], "restartCount": info["RestartCount"]}

    def assert_protected(self):
        for service, expected in self.protected.items():
            info = self.owned(service)
            require(info["State"]["Running"] and self.identity(info) == expected,
                    "protected fixture generation changed: " + service)

    def api(self, method, path, body=None, form=False):
        data = None
        headers = {}
        if body is not None:
            data = urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
        request = urllib.request.Request(self.gateway + path, data=data, method=method, headers=headers)
        try:
            response = self.http.open(request, timeout=60)
        except urllib.error.HTTPError as error:
            body = error.read(4096).decode(errors="replace")
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {body}") from error
        with response:
            raw = response.read(4 * 1024**2)
            if "application/json" in response.headers.get("Content-Type", ""):
                return json.loads(raw)
            return raw.decode()

    def rpc(self, action, **kwargs):
        return json.loads(self.command("exec", "-i", self.ids["mock-irc"], "python3", "/fixture/memory_fixture.py", "rpc",
                                       data=json.dumps(dict(action=action, **kwargs)), timeout=100))

    def save(self, name, data):
        with (self.output / name).open("w") as file:
            json.dump(data, file, separators=(",", ":"), sort_keys=True)
            file.write("\n")

    def capture_failure_evidence(self, result):
        """Attempt each bounded capture independently, before owned-stack cleanup."""
        errors = {}
        def capture(name, collect):
            try:
                self.save(name, collect())
            except Exception as error:
                errors[name] = (type(error).__name__ + ": " + str(error))[:500]
        def target(service):
            info = self.owned(service)
            require(info["Id"] == self.ids[service], "diagnostic target generation changed: " + service)
            return info
        def wire():
            target("mock-irc")
            return self.rpc("status")
        capture("failure-wire.json", wire)
        for service in self.ids:
            def generation(service=service):
                info = target(service)
                return dict(self.identity(info), running=info["State"]["Running"],
                            exitCode=info["State"]["ExitCode"], error=info["State"].get("Error", "")[:500])
            capture("failure-" + service + "-generation.json", generation)
            capture("failure-" + service + "-logs.json", lambda service=service: self.command(
                "logs", "--tail", "80", target(service)["Id"], timeout=15,
                max_bytes=1024**2, include_stderr=True))
        capture("failure-engine-registry.json", lambda: json.loads(self.command(
            "exec", target("redis")["Id"], "redis-cli", "--json", "HGETALL",
            "irc:server:fixture-regression", timeout=15)))
        if errors:
            result["evidenceErrors"] = errors

    def checkpoint(self, phase, status):
        with (self.output / "checkpoints.jsonl").open("a") as file:
            file.write(json.dumps(dict(at=time.time(), phase=phase, sessions=len(status["sessions"]),
                                       sent=sum(s["sent"] for s in status["sessions"]),
                                       received=sum(s["received"] for s in status["sessions"]),
                                       churn=sum(s["churn"] for s in status["sessions"]),
                                       metaRequests=status["metaRequests"], metaDelayed=status["metaDelayed"],
                                       maxPongSeconds=max(s["maxPongSeconds"] for s in status["sessions"]))) + "\n")

    def start_logs(self):
        self.engine_epoch += 1
        epoch = self.engine_epoch
        self.log_process = subprocess.Popen(["docker", "--context", self.context, "logs", "--follow", "--since",
                                             self.inspect(self.ids["ircfiber-engine"])["State"]["StartedAt"],
                                             self.ids["ircfiber-engine"]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        def read_logs():
            try:
                while True:
                    line = self.log_process.stdout.readline(32769)
                    if not line:
                        return
                    require(len(line) <= 32768, "oversized engine diagnostic line")
                    try:
                        record = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if record.get("event") != "memory_sample":
                        continue
                    # Earlier structured loggers encoded values as JSON strings.
                    for key in ("owners", "telemetry", "availability"):
                        if isinstance(record.get(key), str):
                            record[key] = json.loads(record[key])
                    record["fixtureEpoch"] = epoch
                    record["fixtureObservedAt"] = time.time()
                    with self.sample_lock:
                        require(len(self.samples) < 1100, "sample ring bound exceeded")
                        self.samples.append(record)
                        with (self.output / "memory-samples.jsonl").open("a") as file:
                            file.write(json.dumps(record, separators=(",", ":")) + "\n")
                    self.check_sample(record)
            except Exception as error:
                self.log_error = str(error)
        self.log_thread = threading.Thread(target=read_logs, daemon=True)
        self.log_thread.start()

    def stop_logs(self):
        if self.log_process:
            self.log_process.terminate()
            self.log_process.wait(timeout=10)
            self.log_thread.join(timeout=10)
            self.log_process = None

    def latest(self):
        require(self.log_error is None, "sample collector failed: " + str(self.log_error))
        with self.sample_lock:
            samples = [s for s in self.samples if s["fixtureEpoch"] == self.engine_epoch]
        require(samples, "no actual engine memory diagnostic")
        sample = samples[-1]
        require(time.time() - sample["fixtureObservedAt"] <= 75, "stale engine memory diagnostic")
        self.check_sample(sample)
        return sample

    def check_sample(self, sample):
        for field in ("gcUsedBytes", "gcCollections", "cgroupBytes", "cgroupSwapBytes", "cgroupMaxEvents",
                      "cgroupOomEvents", "cgroupOomKillEvents"):
            number(sample.get(field))
        for field in ("cgroupMaxEvents", "cgroupOomEvents", "cgroupOomKillEvents"):
            require(number(sample[field]) == 0, "fresh fixture cgroup pressure: " + field)
        owners = sample.get("owners")
        require(isinstance(owners, dict), "missing owner diagnostics")
        total = number(owners.get("activeGenerations")) + number(owners.get("retiredGenerations"))
        require(number(owners.get("metaBuilds")) <= 1, "more than one retained META payload")
        require(number(owners.get("ordinaryMetaPublishers")) <= total, "more than one ordinary publisher/client")
        require(number(owners.get("pendingMetaFlags")) <= total, "unbounded META dirty state")
        capacity = number(owners.get("eventBufferCapacity"))
        require(capacity > 0 and 0 <= number(owners.get("eventBufferFill")) <= capacity,
                "event channel exceeds its directly reported capacity")
        for key, limits in QUEUE_LIMITS.items():
            queue = sample.get("telemetry", {}).get(key)
            require(isinstance(queue, dict), "missing direct telemetry queue counters: " + key)
            require((number(queue.get("maxCount")), number(queue.get("maxBytes"))) == limits,
                    "unexpected configured telemetry bounds: " + key)
            require(0 <= number(queue.get("count")) <= limits[0] and 0 <= number(queue.get("bytes")) <= limits[1],
                    "direct telemetry queue bound exceeded: " + key)
        return sample

    def wire(self, caught_up=False):
        status = self.rpc("status")
        require(status["subscribed"], "live-delivery oracle subscriber unavailable")
        require(status["errorCount"] == 0, "wire oracle failure: " + str(status["errors"]))
        require(len(status["sessions"]) == self.sessions, "physical session set changed; cannot shrink acceptance")
        require(len(status["acceptedPhysical"]) == self.sessions and len({tuple(p) for p in status["acceptedPhysical"]}) == self.sessions,
                "extra/missing physical accept, including pre-TLS accepts")
        actual = {s["nick"] for s in status["sessions"]}
        require(actual == set(self.networks.values()), "physical network/nick set differs")
        for session in status["sessions"]:
            require(session["welcomed"] and not session["closed"] and session["physical"][1] > 0,
                    "missing physical TCP/001 evidence")
            require(session["nickCommands"] == session["userCommands"] == 1 and session["quitCommands"] == 0,
                    "extra registration or upstream QUIT")
            require(set(CHANNELS) <= set(session["channels"]), "missing representative channel set")
            require(session["maxPongSeconds"] <= 5, "PONG deadline exceeded")
            if self.baseline:
                require(session["physical"] == self.baseline[session["nick"]], "physical TCP identity changed")
            if caught_up:
                require(session["sent"] == session["received"] and session["sentHash"] == session["receivedHash"],
                        "numbered live messages missing/reordered/duplicated: " + session["nick"])
        return status

    def held(self):
        rows = self.rpc("held")
        require(len(rows) == self.sessions, "held identity set differs from complete physical set")
        require({r["networkId"] for r in rows} == set(self.networks), "missing held network identities")
        require(all(r["state"] == "open" and r["connectedAtMs"] > 0 for r in rows), "closed/unavailable holder socket")
        return {r["networkId"]: (r["id"], r["connectedAtMs"]) for r in rows}

    def all_attached(self):
        status = self.rpc("holderStatus")
        return status.get("open") == status.get("attached") == self.sessions and status.get("detached") == 0

    def roster_ready(self, network):
        members = self.api("GET", f"/api/networks/{network}/channels/%23memory9/members")["members"]
        names = {m["nick"] if isinstance(m, dict) else m for m in members}
        return names == STABLE | {self.networks[network]}

    def setup(self):
        for service in ("redis", "mongo", "ircfiber-gateway", "ircfiber-holder", "mock-irc", "egress-a", "ircfiber-engine"):
            info = self.owned(service)
            self.ids[service] = info["Id"]
            if service != "ircfiber-engine":
                self.protected[service] = self.identity(info)
        for component in ("engine", "holder", "gateway"):
            info = self.inspect(self.ids["ircfiber-" + component])
            expected = os.environ["ROUTING_REGRESSION_" + component.upper() + "_IMAGE"]
            require(info["Image"] == expected, "running fixture image differs from immutable input")
            image = json.loads(self.command("image", "inspect", expected))[0]
            require(image["Architecture"] == "amd64" and image["Os"] == "linux", "fixture image not Linux/amd64")
            if component in ("engine", "holder"):
                require(info["HostConfig"]["Memory"] == 2 * 1024**3
                        and info["HostConfig"]["MemorySwap"] == 3 * 1024**3,
                        "A fixture must retain the 2-GiB cgroup and 3-GiB combined ceilings")
        self.start_logs()
        wait(lambda: self.api("GET", "/health"), "gateway health")
        wait(lambda: self.rpc("status")["subscribed"], "live event subscriber")
        username = "memory" + str(int(time.time()))
        credentials = dict(username=username, password="fixtureMemory123", email=username + "@fixture.invalid")
        self.api("POST", "/register", credentials, form=True)
        self.api("POST", "/login", credentials, form=True)
        defaults = self.api("GET", "/api/networks")
        require(isinstance(defaults, list) and len(defaults) < self.sessions, "signup network list unavailable")
        for network in defaults:
            nid = network.get("id") or network.get("networkId")
            require(nid and network.get("nick"), "default network/nick identity unavailable")
            self.networks[nid] = network["nick"]
            self.names[nid] = network["name"]
            wait(lambda nid=nid: any((n.get("id") or n.get("networkId")) == nid and n.get("connected")
                                    for n in self.api("GET", "/api/networks")), "default actually connected", 180)
            for channel in CHANNELS:
                self.api("POST", f"/api/networks/{nid}/join", dict(channel=channel))
            wait(lambda nid=nid: self.roster_ready(nid),
                 "default authoritative initial roster", 180)
        tls_count = self.sessions // 2
        for index in range(self.sessions - len(defaults)):
            tls = index < tls_count
            nick = f"memory{index:03d}"
            name = f"Memory_{index:03d}_{self.run_id}"
            result = self.api("POST", "/api/networks", dict(name=name, host="mock-irc", port=16669 if tls else 16668,
                              tls="enabled" if tls else "disabled", nick=nick, realName="Memory qualification",
                              routing=dict(order=["direct"], preferredExit=""), autoJoinChannels=CHANNELS))
            nid = result.get("id") or result.get("networkId")
            require(nid, "create network returned no ID")
            self.networks[nid] = nick
            self.names[nid] = name
            # Setup is not a 250-registration burst test. Admit the next
            # network only after the current full roster reaches Redis;
            # every one of the 250 remains active for all measured load.
            wait(lambda nid=nid: self.roster_ready(nid),
                 "new network authoritative initial roster", 180)
        self.rpc("configure", networks=self.networks, profile=self.profile, scope=self.qualification_scope)
        wait(lambda: self.all_attached(), "all representative sessions attached", 600)
        for nid in self.networks:
            wait(lambda nid=nid: self.roster_ready(nid), "authoritative last roster " + nid, 180)
        status = self.wire()
        require(sum(s["tls"] for s in status["sessions"]) == tls_count, "mixed plain/TLS physical set incomplete")
        self.baseline = {s["nick"]: s["physical"] for s in status["sessions"]}
        self.held_baseline = self.held()
        self.save("before.json", dict(wire=status, held=self.held_baseline, protected=self.protected))
        self.save("manifest.json", dict(run=self.run_id, images={k: os.environ["ROUTING_REGRESSION_" + k.upper() + "_IMAGE"]
                                                               for k in ("engine", "holder", "gateway")},
                                        sessions=self.sessions, tlsSessions=tls_count, channels=CHANNELS, stableMembers=2000,
                                        stableNicknameFormat="m%03x", stableRealname="Stable",
                                        messagesPerSecond=100, burstLinesPerProtocol=5000, warmupSeconds=self.warmup,
                                        measuredSeconds=self.soak, networks=self.networks,
                                        profile=self.profile,
                                        expectedHolderImage=self.expected_holder_image,
                                        scope=("Rollout A; old holder; no unbounded-backpressure or archival guarantee"
                                               if self.expected_holder_image == OLD_HOLDER and self.qualification_scope == "Rollout A only"
                                               else self.qualification_scope + "; no unbounded-backpressure or archival guarantee")))
        wait(lambda: self.latest(), "first actual GC/cgroup/owner diagnostic", 90)

    def catch_up(self):
        self.rpc("load", enabled=False)
        return wait(lambda: self.wire(caught_up=True), "complete ordered/hash-matched live oracle", 90)

    def swap(self, signal):
        self.catch_up()
        self.assert_protected()
        before = self.wire(caught_up=True)
        if signal == "SIGTERM":
            self.command("stop", "--time", "35", self.ids["ircfiber-engine"], timeout=50)
        else:
            self.command("kill", "--signal", "SIGKILL", self.ids["ircfiber-engine"])
        require(not self.inspect(self.ids["ircfiber-engine"])["State"]["Running"], "engine-down proof unavailable")
        self.stop_logs()
        burst_targets = []
        for tls in (False, True):
            target = next(s["nick"] for s in before["sessions"] if s["tls"] == tls)
            burst_targets.append(target)
            burst = self.rpc("burst", nick=target)
            original = next(s for s in before["sessions"] if s["nick"] == target)
            sent = next(s for s in burst["sessions"] if s["nick"] == target)
            require(sent["sent"] - original["sent"] == 5000, "transport burst was not exactly 5,000 lines")
        detached_probe = self.rpc("probe")
        require(not self.inspect(self.ids["ircfiber-engine"])["State"]["Running"],
                "engine was not stopped throughout the detached PONG probe")
        require(detached_probe["errorCount"] == 0, "detached PONG probe failed")
        require(all(s["pongs"] > next(old["pongs"] for old in before["sessions"] if old["nick"] == s["nick"])
                    for s in detached_probe["sessions"]), "missing stopped-engine per-socket PONG")
        def backlog():
            rows = self.rpc("held")
            require({r["networkId"]: (r["id"], r["connectedAtMs"]) for r in rows} == self.held_baseline,
                    "detached held identity changed")
            by_nick = {self.networks[r["networkId"]]: r for r in rows}
            return rows if all(number(by_nick[nick]["bufferedBytes"]) > 0 for nick in burst_targets) else False
        detached_backlog = wait(backlog, "TCP and TLS burst backlog held while engine stopped", 30)
        self.rpc("delayMeta", seconds=4, count=12)
        previous = self.rpc("status")
        self.command("start", self.ids["ircfiber-engine"])
        self.start_logs()
        self.rpc("load", enabled=True)
        wait(lambda: self.rpc("status")["metaWaiting"] > 0, "real delayed META acknowledgment", 90)
        gate_started = time.time()
        # While a real META acknowledgment is withheld, readers must deliver.
        def draining():
            current = self.wire()
            return current if current["metaWaiting"] > 0 and sum(s["received"] for s in current["sessions"]) > sum(s["received"] for s in previous["sessions"]) else False
        during = wait(draining, "reader drains independently of META ACK", 30)
        def gated_sample():
            sample = self.latest()
            status = self.rpc("status")
            return sample if (sample["fixtureObservedAt"] >= gate_started and status["metaWaiting"] > 0
                              and number(sample["owners"]["metaBuilds"]) == 1) else False
        retained_payload_sample = wait(gated_sample, "direct retained-payload counter during real delayed META ACK", 55)
        wait(lambda: self.all_attached(), "reattach every original held socket", 180)
        wait(lambda: (lambda s: s["metaWaiting"] == 0 and s["metaDelayRemaining"] == 0)(self.rpc("status")),
             "all real META ACK gates released", 90)
        status = self.catch_up()
        require(self.held() == self.held_baseline, "held IDs/connectedAtMs changed across engine-only fault")
        self.assert_protected()
        require(status["metaDelayed"] - previous["metaDelayed"] == 12, "all twelve four-second META gates must execute")
        require(status["metaMaxWaiting"] <= 1, "control lock admitted multiple publication payloads")
        require(all(s["pongs"] > 0 for s in status["sessions"]), "missing per-socket PONG evidence")
        self.faults.append(signal)
        evidence = dict(before=before, engineStoppedPongProbe=detached_probe, detachedBacklog=detached_backlog,
                        burstTargets=burst_targets, burstLinesPerTransport=5000, metaGateSeconds=4, metaGateCount=12,
                        duringMetaDelay=during, retainedPayloadSample=retained_payload_sample,
                        after=status, held=self.held_baseline)
        self.save(signal.lower() + ".json", evidence)
        wait(lambda: self.latest(), "post-swap actual diagnostic", 90)
        self.rpc("load", enabled=True)
        return evidence

    def run_load(self, duration, phase):
        deadline = time.monotonic() + duration
        engine = self.stationary_engine
        self.rpc("load", enabled=True)
        while time.monotonic() < deadline:
            status = self.wire()
            self.latest()
            self.assert_protected()
            current = self.inspect(self.ids["ircfiber-engine"])
            require(current["State"]["Running"] and self.identity(current) == engine, "engine restarted/OOM under representative load")
            self.checkpoint(phase, status)
            time.sleep(min(30, max(0, deadline - time.monotonic())))

    def evaluate(self, start, end):
        require(self.profile == FULL_MEMORY_PROFILE, "continuity profile cannot evaluate stationary memory qualification")
        with self.sample_lock:
            samples = [s for s in self.samples if s["fixtureEpoch"] == self.engine_epoch
                       and start <= s["fixtureObservedAt"] <= end]
        require(len(samples) >= self.soak // 30 - 3, "missing diagnostic samples during measured soak")
        require(samples[0]["fixtureObservedAt"] - start <= 60 and end - samples[-1]["fixtureObservedAt"] <= 60,
                "missing measurement endpoints")
        require(all(b["fixtureObservedAt"] - a["fixtureObservedAt"] <= 75 for a, b in zip(samples, samples[1:])), "diagnostic sampling gap")
        for sample in samples:
            self.check_sample(sample)
            owners = sample["owners"]
            require(number(owners["activeGenerations"]) == self.sessions and number(owners["completedRetiredGenerations"]) == 0,
                    "active/completed-retired generation invariant failed")
            require(number(owners["members"]) >= self.sessions * 10 * 2001, "representative member workload disappeared")
        for field in ("cgroupMaxEvents", "cgroupOomEvents", "cgroupOomKillEvents"):
            values = [number(s[field]) for s in samples]
            require(values[-1] == values[0], "new cgroup pressure event: " + field)
        last15 = [s for s in samples if s["fixtureObservedAt"] >= end - 900]
        require(len(last15) >= 28, "missing last fifteen-minute memory window")
        combined = lambda s: number(s["cgroupBytes"]) + number(s["cgroupSwapBytes"])
        increase = combined(last15[-1]) - combined(last15[0])
        require(increase <= 32 * 1024**2, f"resident cgroup+swap increased {increase} bytes in last fifteen minutes")
        # Only actual new collection counts identify collection-updated estimates.
        # Compare identical live-owner state, not a smaller/substituted workload.
        groups = defaultdict(list)
        previous_collection = None
        for sample in samples:
            count = number(sample["gcCollections"])
            if previous_collection is not None:
                require(count >= previous_collection, "GC collection counter rolled back")
            if previous_collection is not None and count > previous_collection:
                owners = sample["owners"]
                signature = tuple(number(owners[key]) for key in ("activeGenerations", "retiredGenerations", "members", "namesMembers",
                                    "realnames", "realnameProbed", "idents", "accounts", "away", "bots", "userMetadata"))
                groups[signature].append((sample["fixtureObservedAt"], number(sample["gcUsedBytes"])))
            previous_collection = count
        require(groups, "no actual post-collection samples (GC is never forced by production hooks)")
        comparable = max(groups.values(), key=len)
        require(len(comparable) >= 3 and comparable[-1][0] - comparable[0][0] >= 900,
                "insufficient post-collection samples with identical logical live state over fifteen minutes")
        growth = slope(comparable)
        require(growth <= 0, f"collection-updated GC used estimate trends upward: {growth} bytes/second")
        return dict(samples=len(samples), postCollectionComparableSamples=len(comparable), gcUsedSlopeBytesPerSecond=growth,
                    last15MinuteCgroupPlusSwapIncreaseBytes=increase,
                    gcAccounting="collection_updated_estimate; not exact live-object census")

    def run(self):
        require(self.profile == FULL_MEMORY_PROFILE, "continuity profile requires its separate wire-only runner")
        self.setup()
        self.rpc("load", enabled=True)
        time.sleep(6)
        self.swap("SIGTERM")
        self.swap("SIGKILL")
        self.stationary_engine = self.identity(self.inspect(self.ids["ircfiber-engine"]))
        # Faults finish before warm-up: the entire measured window is stationary
        # with unchanged logical state and engine/holder generations.
        self.run_load(self.warmup, "warmup")
        start = time.time()
        first = self.wire()
        self.run_load(self.soak, "measured")
        end = time.time()
        final = self.catch_up()
        require(sum(s["sent"] for s in final["sessions"]) - sum(s["sent"] for s in first["sessions"]) >= self.soak * 99,
                "measured actual arrival rate below 99 messages/second")
        require(all(s["churn"] > 0 for s in final["sessions"]), "unique-nick churn did not reach every session")
        require(self.held() == self.held_baseline, "final held identity mismatch")
        self.assert_protected()
        self.save("final.json", dict(wire=final, held=self.held_baseline, protected=self.protected))
        engine = self.owned("ircfiber-engine")
        require(engine["State"]["Running"] and self.identity(engine) == self.stationary_engine,
                "engine generation changed at measurement completion")
        evaluation = self.evaluate(start, end)
        return dict(state="passed", scope=self.qualification_scope, faults=self.faults, **evaluation)


def main():
    qualification = None
    result = dict(state="failed")
    try:
        qualification = Qualification()
        result = qualification.run()
    except BaseException as error:
        result["reason"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        if qualification:
            if result["state"] != "passed":
                qualification.capture_failure_evidence(result)
            qualification.stop_logs()
            qualification.save("result.json", result)
        else:
            path = os.environ.get("MEMORY_EVIDENCE_DIR")
            if path and Path(path).is_dir():
                (Path(path) / "result.json").write_text(json.dumps(result) + "\n")
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
