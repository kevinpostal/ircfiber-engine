#!/usr/bin/env python3
"""Local-only Nord physical-session boundary and recovery qualification.

All admissions come from the real engine/gateway. The oracle counts one SOCKS
client, never both relay ends. Faults interrupt real sockets/processes; no
application state or successful protocol response is synthesized.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from fixture_http import LoopbackFixtureCookies
from memory_qualification import Qualification, require

LEDGER = "irc:egress:nordvpn:capacity:v1"


def until(predicate, description, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = predicate()
        except (urllib.error.URLError, ConnectionError):
            result = False
        if result:
            return result
        time.sleep(.2)
    raise AssertionError("timed out: " + description)


class Capacity(Qualification):
    def __init__(self):
        self.context = os.environ["DOCKER_CONTEXT"]
        self.project = os.environ["COMPOSE_PROJECT_NAME"]
        self.run_id = os.environ["ROUTING_REGRESSION_RUN"]
        self.compose = os.environ["COMPOSE_FILE"]
        self.gateway = os.environ["GATEWAY_URL"]
        require(os.environ.get("ROUTING_REGRESSION_READY") == "1", "use owned routing wrapper")
        require(self.project == self.run_id and self.project.startswith("regression-"), "non-fixture project")
        require(self.gateway.startswith("http://127.0.0.1:"), "non-loopback gateway")
        self.output = Path(os.environ["NORD_CAPACITY_EVIDENCE_DIR"])
        require(self.output.is_dir() and not any(self.output.iterdir()), "fresh evidence directory required")
        self.cookie = LoopbackFixtureCookies(self.gateway)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(self.cookie))
        self.ids, self.networks, self.nicks, self.cases = {}, {}, {}, []
        self.phase = "setup"

    def request(self, method, path, body=None, form=False, expected=(200, 201, 302)):
        data = None if body is None else (urllib.parse.urlencode(body).encode() if form else json.dumps(body).encode())
        headers = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json"}
        req = urllib.request.Request(self.gateway + path, data=data, method=method, headers=headers)
        try:
            response = self.http.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(2 * 1024**2 + 1)
            require(len(raw) <= 2 * 1024**2, "HTTP evidence exceeds bound")
            require(response.status in expected, f"{method} {path}: {response.status}: {raw[:500]!r}")
            value = json.loads(raw) if "application/json" in response.headers.get("Content-Type", "") else raw
            return response.status, value

    def data(self, value):
        return value.get("data", value) if isinstance(value, dict) else value

    def rpc(self, action, **kwargs):
        return json.loads(self.command("exec", "-i", self.ids["mock-irc"], "python3",
                                       "/fixture/holder_engine_qualification.py", "rpc",
                                       data=json.dumps(dict(action=action, **kwargs)), timeout=120,
                                       max_bytes=12 * 1024**2))

    def redis(self, *args):
        return self.command("exec", self.ids["redis"], "redis-cli", "--raw", *args).strip()

    def ledger(self):
        fields = self.redis("HGETALL", LEDGER).splitlines()
        require(len(fields) % 2 == 0, "malformed ledger response")
        return dict(zip(fields[::2], fields[1::2]))

    def permits(self):
        return {key: value for key, value in self.ledger().items() if key != "active"}

    def metrics(self, operation="metrics", target="nord"):
        return self.rpc("metrics", operation=operation, target=target)

    def held(self):
        return [row for row in self.rpc("held") if row["state"] == "open"]

    def nord_held(self):
        return [row for row in self.held() if row["tag"].get("egressLabel") in ("north", "south")]

    def registered(self, nid):
        return any(row["tag"]["networkId"] == nid for row in self.held()) and any(
            row["nick"] == self.nicks[nid] and row["welcomed"] and not row["closed"]
            for row in self.rpc("status")["sessions"])

    def create(self, label="north", tls=False, host="alpha.example.org"):
        nick = "nc" + secrets.token_hex(5)
        route = "direct" if label == "direct" else "mullvad" if label == "fixture-mullvad" else "nordvpn"
        _, value = self.request("POST", "/api/networks", dict(name=nick, host=host,
            port=16669 if tls else 16668, tls="enabled" if tls else "disabled", nick=nick,
            realName="Isolated Nord boundary", autoJoinChannels=[],
            routing=dict(order=[route], preferredExit="" if route == "direct" else label)))
        value = self.data(value)
        nid = value.get("id") or value.get("networkId")
        require(nid, "network identity absent")
        self.networks[nid], self.nicks[nid] = route, nick
        return nid

    def remove(self, nid):
        self.request("DELETE", "/api/networks/" + nid, expected=(200, 204))
        self.networks.pop(nid, None)

    def snapshot(self):
        # Admission and ban evidence must not change because the capacity pool is
        # full. Catalog counters and probe TCP timestamps are deliberately not
        # confused with failed credentials/reachability.
        result = {}
        for pattern in ("irc:egress:admission:*", "irc:egress:reach:*", "irc:ban:*"):
            for key in self.redis("--scan", "--pattern", pattern).splitlines():
                # DUMP is binary, including when redis-cli requests JSON.
                result[key] = self.redis("EVAL", "local v=redis.call('DUMP',KEYS[1]); "
                                         "return v and redis.sha1hex(v) or false", "1", key)
        return result

    def record(self, case, **evidence):
        metrics = self.metrics()
        require(metrics["peak"] <= 10, "physical Nord peak exceeded ten")
        require(metrics["current"] >= 0 and metrics["started"] - metrics["closed"] == metrics["current"],
                "physical session accounting drift")
        self.cases.append(dict(case=case, metrics=metrics, **evidence))
        self.save("coverage.json", self.cases)

    def activation(self, recover=False, success=False):
        args = [sys.executable, os.environ["NORD_CAPACITY_HELPER"], "fixture-activate",
                "--docker-socket", os.environ["NORD_CAPACITY_DOCKER_SOCKET"], "--project", self.project,
                "--redis-service", "redis", "--redis-db", "0"]
        if recover:
            args.append("--recover")
        result = subprocess.run(args, capture_output=True, text=True, timeout=30)
        require((result.returncode == 0) == success, "cold fence activation unexpectedly accepted/refused: " + result.stderr[:500])
        return result.stdout + result.stderr

    def setup(self):
        for service in ("redis", "mongo", "mock-irc", "egress-a", "egress-b", "ircfiber-holder",
                        "ircfiber-gateway", "ircfiber-engine"):
            self.ids[service] = self.owned(service)["Id"]
        status = self.rpc("holderStatus")
        require("nord-capacity-v1" in status["capabilities"], "guarded holder capability absent")
        self.instance = status["instance"]
        require("password" not in json.dumps(status).lower() and "redis://" not in json.dumps(status).lower(),
                "holder status disclosed coordinator or credential material")
        require("active" in self.ledger(), "fixture activation absent")
        self.generation = self.ledger()["active"]
        self.activation(recover=True)  # Actual live producer inventory must fail.
        # Default signup network is direct; only explicitly created Nord rows
        # participate in this test's account-wide budget.
        policy = {"schema": 1, "revision": 1,
                  "global": {"order": ["direct", "nordvpn", "mullvad"], "blockedRoutes": []}, "hosts": []}
        self.redis("SET", "irc:config:egressRoutingPolicy", json.dumps(policy))
        self.user = "capacity" + secrets.token_hex(4)
        self.credentials = dict(username=self.user, password=secrets.token_urlsafe(24), email=self.user + "@fixture.invalid")
        self.request("POST", "/register", self.credentials, form=True)
        self.request("POST", "/login", self.credentials, form=True)
        script = 'db.users.updateOne({username:' + json.dumps(self.user) + '},{$set:{roles:["user","admin"]}})'
        self.command("exec", self.ids["mongo"], "mongosh", "--quiet", "ircfiber_regression_fixture", "--eval", script)
        self.request("POST", "/admin/login", self.credentials, form=True)
        until(lambda: self.data(self.request("GET", "/api/admin/mullvad/status")[1]), "admin status")
        until(lambda: self.metrics()["current"] == 0 and not self.permits(), "startup probes close")
        self.record("cold_activation_and_live_producer_fence", generation=self.generation)

    def boundary(self):
        self.phase = "nine IRC plus blocked probe"
        for index in range(9):
            nid = self.create("south" if index % 2 else "north")
            until(lambda: self.registered(nid), "registered Nord network")
        until(lambda: len(self.permits()) == 9 and self.metrics()["current"] == 9, "nine physical Nord sessions")
        self.metrics("block")
        with ThreadPoolExecutor(max_workers=2) as workers:
            probe = workers.submit(self.request, "POST", "/api/admin/mullvad/north/test", {}, False, (200, 503))
            until(lambda: self.metrics()["current"] == 10, "blocked authenticated tenth probe", 5)
            started = self.metrics()["started"]
            nid = self.create("south")
            status, denied = self.request("POST", "/api/admin/mullvad/south/test", {}, expected=(503,))
            require(self.data(denied)["capacityError"] == "nord_capacity_full", "eleventh did not report capacity")
            require(self.metrics()["started"] == started, "eleventh reached proxy authentication")
            self.record("nine_irc_plus_blocked_probe_deny_eleventh", denied=denied)
            self.metrics("unblock")
            probe.result(timeout=30)
        until(lambda: self.registered(nid) and len(self.permits()) == 10, "one slot reused after probe closes")
        require(len(self.nord_held()) == 10, "ten actual held upstreams absent")
        require(self.metrics()["started"] == started + 1, "one closed probe did not admit exactly one new transport")
        self.record("probe_close_admits_exactly_one_waiting_irc")

    def full_paths(self):
        self.phase = "all gateway paths at full"
        baseline = self.snapshot()
        started = self.metrics()["started"]
        _, single = self.request("POST", "/api/admin/mullvad/north/test", {}, expected=(503,))
        require(self.data(single)["capacityError"] == "nord_capacity_full", "manual HTTPS missing retryable capacity")
        _, bulk = self.request("POST", "/api/admin/mullvad/test-all", {})
        rows = self.data(bulk)["results"]
        for label in ("north", "south"):
            row = next(row for row in rows if row["label"] == label)
            require(row["skipped"] and row["retryable"] and row["capacityError"] == "nord_capacity_full",
                    "bulk test did not individually skip Nord label")
        require(next(row for row in rows if row["label"] == "fixture-mullvad")["healthy"], "Mullvad blocked by Nord full")
        _, irc = self.request("POST", "/api/admin/mullvad/north/irc-test", {"host": "alpha.example.org", "port": 16668}, expected=(503,))
        require(self.data(irc)["capacityError"] == "nord_capacity_full", "raw IRC did not preserve capacity result")
        _, image = self.request("GET", "/api/image-proxy?" + urllib.parse.urlencode({"url": "https://image.regression.test/image?full=1"}), expected=(503,))
        require("nord_capacity_full" in json.dumps(image), "image Nord endpoint bypassed capacity")
        direct, mullvad = self.create("direct"), self.create("fixture-mullvad")
        until(lambda: self.registered(direct) and self.registered(mullvad), "direct and Mullvad at Nord saturation")
        # The cache-miss fan-out and normal refresher are actual gateway jobs.
        # No test entrypoint invokes a private fetch helper or fabricates its result.
        self.redis("DEL", "irc:egress:probe:north")
        # Age the two fetch clocks, keeping the real prior observation intact.
        # With fresh IP info the scheduler only tests TCP, which needs no slot.
        south_key = "irc:egress:probe:south"
        previous = json.loads(self.redis("GET", south_key))
        previous["ipinfoCheckedAt"] = previous["ipinfoAttemptedAt"] = "2000-01-01T00:00:00Z"
        south = json.dumps(previous)
        require(self.redis("SET", south_key, south, "XX", "KEEPTTL") == "OK", "south observation expired")
        with ThreadPoolExecutor(max_workers=4) as workers:
            list(workers.map(lambda _: self.request("GET", "/api/admin/mullvad/status"), range(4)))
        self.request("POST", "/api/admin/egress-reachability/run-now", {})
        deadline = time.monotonic() + 21
        while time.monotonic() < deadline:
            require(self.metrics()["started"] == started, "full gateway job authenticated a new Nord session")
            time.sleep(.5)
        require(not self.redis("GET", "irc:egress:probe:north"), "skipped cache miss was written as an observation")
        require(self.redis("GET", "irc:egress:probe:south") == south, "scheduled capacity skip advanced observation")
        # Reachability snapshots include Mullvad's successful observation; only
        # compare the two Nord exit records for no failure/ban mutation.
        after = self.snapshot()
        nord_keys = {key for key in baseline | after if key.endswith(":north") or key.endswith(":south") or key.startswith("irc:ban:")}
        require(all(baseline.get(key) == after.get(key) for key in nord_keys), "capacity mutated Nord health or ban state")
        self.record("manual_single_bulk_raw_irc_image_cache_fanout_scheduled_skip", single=single, bulk=bulk)

    def adoption(self):
        self.phase = "hot swap full pool"
        before = {row["id"]: row["connectedAtMs"] for row in self.nord_held()}
        permits = self.permits()
        started = self.metrics()["started"]
        self.command("restart", "--time", "35", self.ids["ircfiber-engine"])
        until(lambda: len(self.nord_held()) == 10 and all(row["attached"] for row in self.nord_held()), "full holder adoption")
        until(lambda: self.rpc("probe")["probed"] >= 10, "PONG after engine hot swap")
        require({row["id"]: row["connectedAtMs"] for row in self.nord_held()} == before, "adoption replaced physical sockets")
        require(self.permits() == permits and self.metrics()["started"] == started, "adoption freed or double charged capacity")
        self.record("ten_socket_engine_hot_swap_reuses_permits", holderIds=before)

    def image_attribution(self):
        self.phase = "image endpoint attribution"
        for endpoint, expected in (("socks5://test:test@192.0.2.30:1082", 503),
                                   ("socks5://192.0.2.31:1080", 200)):
            os.environ["ROUTING_REGRESSION_IMAGE_SOCKS"] = endpoint
            self.dc("up", "-d", "--no-deps", "--no-build", "--force-recreate", "ircfiber-gateway")
            self.ids["ircfiber-gateway"] = self.owned("ircfiber-gateway")["Id"]
            until(lambda: self.request("GET", "/health", expected=(200, 503))[0] == 200, "recreated gateway health")
            _, image = self.request("GET", "/api/image-proxy?" + urllib.parse.urlencode({"url": "https://image.regression.test/image?" + secrets.token_hex(4)}), expected=(expected,))
            if expected == 503:
                require("nord_capacity_full" in json.dumps(image), "unattributed image endpoint was unmetered")
            else:
                require(isinstance(image, bytes) and image.startswith(b"\x89PNG"), "Mullvad image path failed at Nord full")
        os.environ["ROUTING_REGRESSION_IMAGE_SOCKS"] = "socks5://test:test@192.0.2.30:1080"
        self.record("unknown_image_endpoint_metered_and_mullvad_endpoint_exempt")

    def empty_nord(self):
        for nid, route in tuple(self.networks.items()):
            if route == "nordvpn":
                self.remove(nid)
        until(lambda: self.metrics()["current"] == 0 and not self.permits(), "all closed Nord attempts durably released")

    def fault_paths(self):
        self.phase = "terminal failures and cancellation"
        self.empty_nord()
        for operation, undo, tls in (("fail-auth", "allow-auth", False), ("bad-tls", "allow-tls", True)):
            self.metrics(operation)
            started = self.metrics()["started"]
            # Failed transports legitimately cool down this destination. Keep
            # the subsequent lost-reply test on an independent healthy host.
            nid = self.create(tls=tls, host="beta.example.net")
            until(lambda: self.metrics()["started"] > started, operation + " reached real proxy")
            self.remove(nid)
            until(lambda: not self.permits() and self.metrics()["current"] == 0, operation + " terminal release")
            self.metrics(undo)
            self.record(operation + "_physical_close_releases")
        self.metrics("stall-auth")
        nid = self.create(host="beta.example.net")
        until(lambda: self.metrics()["current"] == 1 and len(self.permits()) == 1, "pending auth consumes one slot")
        self.remove(nid)
        physical = self.metrics()["current"]
        require(len(self.permits()) >= physical, "cancellation released before physical pending socket closed")
        self.metrics("unblock")
        until(lambda: not self.permits() and self.metrics()["current"] == 0, "cancelled pending attempt terminal")
        self.record("stalled_auth_and_preconnect_cancel_do_not_undercount")
        self.rpc("loseNextDial")
        nid = self.create()
        lost = until(lambda: self.rpc("lost"), "actual DIAL response loss")[-1]
        token = lost["token"]
        require(token in self.permits(), "lost DIAL response prematurely released token")
        require(self.metrics()["current"] == 1, "lost response did not leave actual upstream")
        status = self.rpc("holderRpc", verb="NORD_STATUS", payload={"instance": self.instance, "tokens": [token],
                          "nordCapacityGeneration": self.generation})
        require(status["tokens"][0]["state"] in ("pending", "open"), "lost response not positively unresolved")
        duplicate = self.rpc("duplicateDial")["reply"]
        require(duplicate.startswith("ERR "), "holder reused a live/unresolved attempt token")
        started = self.metrics()["started"]
        for mutation in ("missingProvider", "wrongInstance", "missingGeneration"):
            require(self.rpc("invalidDial", mutation=mutation)["reply"].startswith("ERR "),
                    "holder accepted invalid Nord attribution: " + mutation)
        require(self.metrics()["started"] == started, "invalid attributed DIAL reached proxy authentication")
        self.record("lost_dial_response_retains_slot_duplicate_token_rejected")
        self.remove(nid)
        self.rpc("holderRpc", verb="CLOSE", payload={"id": lost["id"]})
        until(lambda: token not in self.permits() and self.metrics()["current"] == 0, "lost attempt proven closed and released")
        # Startup reconciliation is repeated across the release/ACK crash window;
        # unrelated reservations may not be removed by duplicate cleanup.
        survivor = self.create()
        until(lambda: self.registered(survivor), "survivor for duplicate reconciliation")
        permits = self.permits()
        for _ in range(2):
            self.command("restart", "--time", "35", self.ids["ircfiber-engine"])
            until(lambda: self.registered(survivor), "survivor adopted after duplicate cleanup")
            require(self.permits() == permits, "duplicate release consumed unrelated reservation")
        self.record("terminal_release_and_idempotent_startup_cleanup")
        self.rpc("closeNick", nick=self.nicks[survivor])
        self.remove(survivor)
        until(lambda: not self.permits() and self.metrics()["current"] == 0, "upstream EOF releases exactly one")
        self.record("upstream_eof_positive_terminal_release")
        # Kill an actual guarded curl while authenticated and blocked. The
        # execute owner must reap it before making the slot available again.
        self.metrics("block")
        with ThreadPoolExecutor(max_workers=1) as workers:
            probe = workers.submit(self.request, "POST", "/api/admin/mullvad/north/test", {}, False, (200, 503))
            until(lambda: self.metrics()["current"] == 1, "curl child actual authenticated socket", 5)
            self.command("exec", self.ids["ircfiber-gateway"], "sh", "-c",
                'for p in /proc/[0-9]*; do read -r comm < "$p/comm" 2>/dev/null || continue; [ "$comm" != curl ] || kill -KILL "${p##*/}"; done')
            self.metrics("unblock")
            probe.result(timeout=30)
        until(lambda: not self.permits() and self.metrics()["current"] == 0, "aborted curl close and reap release")
        self.record("aborted_curl_child_closed_and_reaped")

    def release_ack_crash(self):
        self.phase = "durable release before holder acknowledgement crash"
        survivor = self.create()
        until(lambda: self.registered(survivor), "ACK-window survivor registration")
        protected = self.permits()
        victim = self.create("south")
        until(lambda: self.registered(victim), "ACK-window victim registration")
        victim_tokens = set(self.permits()) - set(protected)
        require(len(victim_tokens) == 1, "victim reservation not uniquely identified")
        token = victim_tokens.pop()
        self.rpc("blockNextAck")
        self.remove(victim)
        ack = until(lambda: self.rpc("blockedAck"), "real ACK withheld after durable release")
        require(ack["nordCapacityToken"] == token and token not in self.permits(),
                "ACK injection was not in the durable release/ACK crash window")
        status = self.rpc("holderRpc", verb="NORD_STATUS", payload={"instance": self.instance,
                          "tokens": [token], "nordCapacityGeneration": self.generation})
        require(status["tokens"][0]["state"] == "terminal", "unacknowledged terminal evidence absent")
        self.command("kill", "--signal", "KILL", self.ids["ircfiber-engine"])
        self.rpc("releaseAck")
        self.command("start", self.ids["ircfiber-engine"])
        def acknowledged():
            response = self.rpc("holderRpc", verb="NORD_STATUS", payload={"instance": self.instance,
                "tokens": [token], "nordCapacityGeneration": self.generation})
            return response["tokens"][0]["state"] == "unknown"
        until(acknowledged, "restart cleans exact absent reservation and ACKs terminal evidence")
        require(self.permits() == protected, "release/ACK crash cleanup removed another live permit")
        self.record("release_ack_crash_window_and_exact_absent_token_cleanup")
        self.remove(survivor)
        until(lambda: not self.permits() and self.metrics()["current"] == 0, "ACK-window survivor closed")

    def issuer_crash(self):
        self.phase = "probe issuer process death"
        self.metrics("block")
        def interrupted_probe():
            try:
                return self.request("POST", "/api/admin/mullvad/north/test", {}, expected=(200, 503))
            except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
                return {"interrupted": type(error).__name__}
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(interrupted_probe)
            until(lambda: self.metrics()["current"] == 1 and len(self.permits()) == 1,
                  "guarded probe occupies actual transport before issuer death", 5)
            occupied = self.permits()
            self.command("kill", "--signal", "KILL", self.ids["ircfiber-gateway"])
            self.metrics("unblock")
            pending.result(timeout=35)
        until(lambda: self.metrics()["current"] == 0, "dead container child sockets physically close")
        require(self.permits() == occupied, "issuer death silently released uncertain child reservation")
        self.command("start", self.ids["ircfiber-gateway"])
        until(lambda: self.request("GET", "/health", expected=(200, 503))[0] == 200, "new gateway process")
        require(all(self.permits().get(token) == value for token, value in occupied.items()),
                "new process incarnation reclaimed an old issuer reservation")
        self.record("dead_probe_issuer_slot_retained_until_full_fence")

    def coordinator_loss(self):
        self.phase = "coordinator loss with live socket"
        nid = self.create()
        until(lambda: self.registered(nid), "live upstream before coordinator loss")
        before = {row["id"]: row["connectedAtMs"] for row in self.nord_held()}
        # Explicitly persist the disposable server's old run-bound ledger so a
        # later restart exercises stale-incarnation denial, not just absence.
        self.redis("SAVE")
        self.redis("DEL", LEDGER)
        require(not self.ledger(), "ledger deletion failed")
        _, denied = self.request("POST", "/api/admin/mullvad/north/test", {}, expected=(503,))
        require(self.data(denied)["capacityError"] == "nord_capacity_unavailable", "missing coordinator not fail-closed")
        require(not self.ledger(), "admission lazily recreated empty budget")
        require({row["id"]: row["connectedAtMs"] for row in self.nord_held()} == before, "ledger loss disconnected healthy socket")
        self.activation(recover=True)
        self.command("restart", self.ids["redis"])
        until(lambda: self.inspect(self.ids["redis"])["State"]["Health"]["Status"] == "healthy",
              "restarted fixture Redis answers its PING health check")
        require(self.ledger().get("active") == self.generation, "fixture did not restore the old Redis generation")
        self.request("POST", "/login", self.credentials, form=True)
        self.request("POST", "/admin/login", self.credentials, form=True)
        _, denied = self.request("POST", "/api/admin/mullvad/north/test", {}, expected=(503,))
        require(self.data(denied)["capacityError"] == "nord_capacity_unavailable", "Redis restart not fail-closed")
        require({row["id"]: row["connectedAtMs"] for row in self.nord_held()} == before, "Redis restart dropped live socket")
        self.record("missing_and_restarted_redis_deny_without_disconnect_or_lazy_activation")
        # Recovery is deliberately last: prove every fixture producer and every
        # proxy process stopped, not merely that one endpoint or PID changed.
        self.dc("stop", "--timeout", "10", "ircfiber-engine", "ircfiber-gateway", "ircfiber-holder", "egress-a", "egress-b", "mock-irc", "mongo")
        self.activation(recover=True, success=True)
        generation = self.ledger()["active"]
        require(generation != self.generation and len(self.ledger()) == 1, "fenced recovery did not create empty fresh generation")
        self.cases.append(dict(case="fully_fenced_cold_recovery", generation=generation))
        self.save("coverage.json", self.cases)

    def run(self):
        self.setup()
        self.boundary()
        self.full_paths()
        self.adoption()
        self.image_attribution()
        self.fault_paths()
        self.release_ack_crash()
        self.issuer_crash()
        self.coordinator_loss()
        return {"state": "passed", "scope": "isolated Nord physical connection capacity", "cases": [row["case"] for row in self.cases]}


if __name__ == "__main__":
    proof = Capacity()
    try:
        result = proof.run()
    except BaseException as error:
        result = dict(state="failed", phase=proof.phase, reason=str(error))
        try:
            proof.save("failure-ledger.json", proof.ledger())
            proof.save("failure-metrics.json", proof.metrics())
        except Exception as diagnostic:
            result["diagnosticError"] = str(diagnostic)
    proof.save("result.json", result)
    print(json.dumps(result, separators=(",", ":")))
    raise SystemExit(0 if result["state"] == "passed" else 1)
