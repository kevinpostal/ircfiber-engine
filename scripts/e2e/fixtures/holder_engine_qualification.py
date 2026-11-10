#!/usr/bin/env python3
"""Step-8 candidate proof using actual gateway, engine, holder and TCP/TLS.

serve runs only inside the owned upstream fixture. qualify runs on the launcher
host. Controls interrupt real IPC streams; they never synthesize holder replies,
registrations, observed 001s or physical socket identities. Evidence is bounded;
unavailable evidence is an exception, never an implicit passing default.
"""
import asyncio
from collections import Counter
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
import threading
import uuid

from fixture_http import LoopbackFixtureCookies
from memory_fixture import Fixture, Session, CERTS, encode, resp
from memory_qualification import Qualification, require, wait, number

MAX_EVENTS = 24000
CAPABILITIES = {"inventory_v1", "gap_ack_v1", "bounded_meta_v1", "independent_pong_v1"}


def certificates():
    CERTS.mkdir(exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=mock-irc", "-addext",
                    "subjectAltName=DNS:mock-irc,DNS:default.regression.test,DNS:alpha.example.org,DNS:beta.example.net",
                    "-keyout", str(CERTS / "key.pem"), "-out", str(CERTS / "ca-certificates.crt")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


class EngineSession(Session):
    def __init__(self, fixture, physical, reader, writer, tls):
        super().__init__(fixture, physical, reader, writer, tls)
        self.names_count = self.history_count = self.auth_count = self.cap_count = 0
        self.sasl_done = False
        self.sent001_at = None
        self.accept_at = time.monotonic()
        self.cap_done = False
        self.welcome_task = None

    async def names(self, channel, nick):
        self.names_count += 1
        await super().names(channel, nick)

    async def gate(self, phase):
        while phase in self.fixture.gates:
            await asyncio.sleep(0.02)

    async def welcome(self):
        await self.gate("001")
        while self.nick in self.fixture.silent_nicks:
            await asyncio.sleep(0.02)
        if self.welcomed or not self.nick or not self.user:
            return
        if self.nick in self.fixture.refused_nicks:
            self.fixture.audit("465", nick=self.nick, physical=self.physical)
            await self.send([f":mock.irc 465 {self.nick} :Owned fixture external refusal"])
            self.writer.close()
            return
        await self.send([f":mock.irc 001 {self.nick} :Welcome {self.nick}!u@mock",
                         f":mock.irc 005 {self.nick} CASEMAPPING=rfc1459 CHANTYPES=# :supported",
                         f":mock.irc 376 {self.nick} :End of MOTD"])
        self.welcomed = True
        self.sent001_at = time.monotonic()
        self.fixture.audit("001", nick=self.nick, physical=self.physical, tls=self.tls)

    async def run(self):
        try:
            while line := await self.reader.readline():
                if len(line) > 65536:
                    raise ValueError("oversized engine command")
                text = line.decode().rstrip("\r\n")
                parts = text.split()
                if not parts:
                    continue
                command = parts[0].upper()
                if command == "CAP":
                    self.cap_count += 1
                    sub = parts[1].upper()
                    if sub == "LS":
                        await self.gate("CAP")
                        await self.send(["CAP * LS :message-tags server-time batch draft/chathistory sasl"])
                    elif sub == "REQ":
                        await self.send(["CAP * ACK :" + text.split(":", 1)[-1]])
                    elif sub == "END":
                        self.cap_done = True
                elif command == "AUTHENTICATE":
                    self.auth_count += 1
                    await self.gate("SASL")
                    if parts[1] == "PLAIN":
                        await self.send(["AUTHENTICATE +"])
                    else:
                        self.sasl_done = True
                        await self.send([f":mock.irc 900 {self.nick or '*'} {self.nick or '*'}!u@mock fixture :Logged in",
                                         f":mock.irc 903 {self.nick or '*'} :SASL success"])
                elif command == "NICK":
                    self.nicks += 1
                    self.nick = parts[1].lstrip(":")
                    previous = self.fixture.by_nick.get(self.nick)
                    if previous and not previous.closed:
                        self.fixture.error("duplicate active physical registration: " + self.nick)
                    self.fixture.by_nick[self.nick] = self
                    self.fixture.audit("NICK", nick=self.nick, physical=self.physical)
                elif command == "USER":
                    self.users += 1
                    self.user = True
                    self.fixture.audit("USER", nick=self.nick, physical=self.physical)
                elif command == "QUIT":
                    self.quits += 1
                    self.fixture.audit("QUIT", nick=self.nick, physical=self.physical)
                elif command == "PING":
                    await self.send(["PONG :" + parts[-1].lstrip(":")])
                elif command == "PONG":
                    token = parts[-1].lstrip(":")
                    if self.pending_ping is None or token != self.pending_ping[0]:
                        self.fixture.error("duplicate/unexpected PONG: " + str(self.nick))
                    else:
                        elapsed = time.monotonic() - self.pending_ping[1]
                        self.max_pong_seconds = max(self.max_pong_seconds, elapsed)
                        if elapsed > 5:
                            self.fixture.error("PONG exceeded five seconds")
                        self.pongs += 1
                        self.pending_ping = None
                elif command in ("JOIN", "NAMES") and len(parts) > 1:
                    for channel in parts[1].lstrip(":").split(","):
                        await self.names(channel, self.nick)
                    self.fixture.audit("NAMES", nick=self.nick, physical=self.physical)
                elif command == "CHATHISTORY":
                    self.history_count += 1
                    self.fixture.audit("CHATHISTORY", nick=self.nick, physical=self.physical)
                    # A real supported empty history batch is honest: it cannot
                    # prove lost live messages recovered.
                    batch = "he" + str(self.history_count)
                    target = parts[2] if len(parts) > 2 else "#memory0"
                    await self.send([f":mock.irc BATCH +{batch} chathistory {target}",
                                     f":mock.irc BATCH -{batch}"])
                elif command == "WHO" and len(parts) > 1:
                    await self.send([f":mock.irc 315 {self.nick} {parts[1]} :End of WHO"])
                elif command == "MODE" and len(parts) > 1 and parts[1].startswith("#"):
                    await self.send([f":mock.irc 324 {self.nick} {parts[1]} +nt"])
                if self.nick and self.user and self.cap_done and self.welcome_task is None:
                    self.welcome_task = asyncio.create_task(self.welcome())
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            pass
        except Exception as error:
            self.fixture.error("upstream: " + str(error))
        finally:
            if self.welcome_task:
                self.welcome_task.cancel()
                await asyncio.gather(self.welcome_task, return_exceptions=True)
            self.closed = True
            self.writer.close()
            self.fixture.audit("physicalClosed", nick=self.nick, physical=self.physical)

    def summary(self):
        return super().summary() | dict(namesRequests=self.names_count, historyRequests=self.history_count,
                                        authCommands=self.auth_count, capCommands=self.cap_count,
                                        saslDone=self.sasl_done, observed001At=self.sent001_at)


class EngineFixture(Fixture):
    def __init__(self):
        super().__init__()
        self.events = []
        self.relays = {}
        self.controls = set()
        self.gates = set()
        self.control_until = 0
        self.pause_ids = set()
        self.blocked_writes = Counter()
        self.observed = []
        self.event_count = 0
        self.accepted_records = []
        self.command_count = Counter()
        self.current_relay_readers = Counter()
        self.max_relay_readers = Counter()
        self.silent_nicks = set()
        self.refused_nicks = set()

    def audit(self, event, at=None, **fields):
        if len(self.events) >= MAX_EVENTS:
            raise ValueError("fixture event storage full; refusing incomplete evidence")
        self.event_count += 1
        self.events.append(dict(sequence=self.event_count, at=time.monotonic() if at is None else at, event=event, **fields))


    async def wait_gate(self, phase):
        while phase in self.gates:
            await asyncio.sleep(0.02)

    async def accept(self, listener, tls):
        context = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(CERTS / "ca-certificates.crt", CERTS / "key.pem")
        loop = asyncio.get_running_loop()
        while True:
            raw, addr = await loop.sock_accept(listener)
            physical = [addr[1], os.fstat(raw.fileno()).st_ino]
            if len(self.accepted_physical) >= 512:
                raw.close()
                raise ValueError("physical accepts exceed bound")
            self.accepted_physical.append(physical)
            self.audit("accept", physical=physical, tls=tls, source=addr[0])
            self.task(self.wrap(raw, physical, context, tls))

    async def wrap(self, raw, physical, context, tls):
        self.accepted_records.append(dict(physical=physical, tls=tls, at=time.monotonic()))
        await self.wait_gate("TLS" if tls else "TCP")
        reader = asyncio.StreamReader(limit=65536)
        protocol = asyncio.StreamReaderProtocol(reader)
        try:
            transport, _ = await asyncio.get_running_loop().connect_accepted_socket(
                lambda: protocol, raw, ssl=context, ssl_handshake_timeout=20 if context else None)
        except (ssl.SSLError, ConnectionError, asyncio.TimeoutError):
            raw.close()
            self.audit("handshakeFailed", physical=physical, tls=tls)
            return
        writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_running_loop())
        session = EngineSession(self, physical, reader, writer, tls)
        self.sessions.append(session)
        await session.run()

    async def subscriber(self):
        reader, writer = await asyncio.open_connection("192.0.2.2", 6379)
        writer.write(encode("PSUBSCRIBE", "irc:events:*"))
        await writer.drain()
        reply = await resp(reader)
        if reply[0] != b"psubscribe":
            raise ValueError("event subscription not acknowledged")
        self.subscribed = True
        try:
            while True:
                reply = await resp(reader)
                event = json.loads(reply[3])
                # Store only recovery diagnostics, never entire chat/history.
                text = str(event.get("x", ""))
                if any(word in text.lower() for word in ("gap", "uncertain", "lost", "resync")):
                    if len(self.observed) >= 512:
                        raise ValueError("recovery diagnostic bound exceeded")
                    self.observed.append(dict(at=time.monotonic(), networkId=event.get("nid"),
                                              command=event.get("c"), text=text[:1024]))
        finally:
            self.subscribed = False
            writer.close()

    async def holder_request(self, verb, payload=None):
        reader, writer = await asyncio.open_unix_connection("/run/ircfiber/holder.sock", limit=9 * 1024**2)
        try:
            writer.write(b'HELLO {"proto":1,"serverId":"fixture-regression","engine":"holder-engine-observer"}\n')
            await writer.drain()
            hello = await reader.readline()
            if not hello.startswith(b"OK "):
                raise ValueError("observer HELLO rejected")
            writer.write((verb + (" " + json.dumps(payload) if payload is not None else "") + "\n").encode())
            await writer.drain()
            reply = await asyncio.wait_for(reader.readline(), 20)
            if not reply.startswith(b"OK "):
                raise ValueError("holder request rejected: " + reply[:300].decode())
            return json.loads(reply[3:])
        finally:
            writer.close()

    async def inventory(self):
        result, cursor = [], {}
        for _ in range(16):
            page = await self.holder_request("INVENTORY", cursor)
            if len(page["connections"]) > 128 or len(json.dumps(page).encode()) > 65536:
                raise ValueError("inventory page cap exceeded")
            for row in page["connections"]:
                detail = await self.holder_request("INFO", {"id": row["id"]})
                detail.pop("meta", None)
                result.append(detail)
            if not page["more"]:
                return result
            cursor = {key: page[key] for key in ("instance", "through")}
            cursor["after"] = page["nextAfter"]
        raise ValueError("inventory pagination bound exceeded")

    async def relay_out(self, reader, writer, held_id):
        self.current_relay_readers[held_id] += 1
        self.max_relay_readers[held_id] = max(self.max_relay_readers[held_id], self.current_relay_readers[held_id])
        try:
            while True:
                if held_id in self.pause_ids:
                    self.blocked_writes[held_id] += 1
                    await asyncio.sleep(0.02)
                    continue
                data = await reader.read(65536)
                if not data:
                    return
                writer.write(data)
                await writer.drain()
        finally:
            self.current_relay_readers[held_id] -= 1

    async def proxy(self, reader, writer):
        upstream = None
        held_id = None
        tasks = []
        try:
            # Match the real holder: admission can wait before the first DIAL
            # byte. The enclosing qualification bounds and owns these streams.
            first = await reader.readline()
            verb, _, raw = first.partition(b" ")
            payload = json.loads(raw) if raw.strip() else {}
            if verb == b"HELLO" and time.monotonic() < self.control_until:
                return
            upstream_reader, upstream = await asyncio.open_unix_connection("/run/ircfiber/holder.sock", limit=9 * 1024**2)
            forwarded_at = time.monotonic()
            upstream.write(first)
            await upstream.drain()
            if verb == b"HELLO":
                self.controls.add(writer)
                writer.write(await upstream_reader.readline())
                await writer.drain()
                while command := await reader.readline():
                    command_verb, _, raw = command.partition(b" ")
                    args = json.loads(raw) if raw.strip() else {}
                    command_name = command_verb.decode()
                    self.command_count[command_name] += 1
                    if command_verb in (b"CLOSE", b"GAP_ACK"):
                        self.audit(command_name, id=args.get("id"), generation=args.get("generation"))
                    upstream.write(command)
                    await upstream.drain()
                    reply = await upstream_reader.readline()
                    if not reply:
                        return
                    if command_verb == b"INFO" and reply.startswith(b"OK "):
                        observed = json.loads(reply[3:])
                        self.audit("INFO_GAP", id=args.get("id"), gapGeneration=observed.get("gapGeneration"))
                    elif command_verb == b"INVENTORY" and reply.startswith(b"OK "):
                        observed = json.loads(reply[3:])
                        for entry in observed.get("connections", []):
                            self.audit("INVENTORY_GAP", id=entry.get("id"),
                                       gapGeneration=entry.get("gapGeneration"))
                    writer.write(reply)
                    await writer.drain()
                return
            if verb == b"DIAL":
                tag, proxy = payload["tag"], payload.get("proxy") or {}
                # Never retain fixture credentials in evidence.
                self.audit("DIAL", at=forwarded_at, networkId=tag["networkId"], host=payload["host"].lower(),
                           port=payload["port"], tls=payload["tls"],
                           route=dict(provider="nordvpn" if proxy else "direct", slot=tag.get("egressLabel", ""),
                                      exitId=proxy.get("host", ""), nativeIpv6=payload.get("bindIp6") or ""))
            while True:
                reply = await upstream_reader.readline()
                if not reply:
                    return
                writer.write(reply)
                await writer.drain()
                kind, _, raw = reply.partition(b" ")
                parsed = json.loads(raw) if raw.strip() else {}
                if kind in (b"ERR", b"FAILED"):
                    self.audit("relayRejected", operation=verb.decode(), id=payload.get("id"), code=parsed.get("code"),
                               reason=parsed.get("reason") or parsed.get("msg"))
                    if verb == b"ATTACH" and parsed.get("code") == "busy":
                        owner = self.relays.get(payload.get("id"))
                        if owner and owner["keepBusy"]:
                            owner["busyReleased"].set()
                    return
                if (verb == b"DIAL" and kind == b"CONNECTED") or (verb == b"ATTACH" and kind == b"OK"):
                    held_id = parsed.get("id", payload.get("id"))
                    self.audit(verb.decode() + "_OK", id=held_id, instance=parsed.get("instance"),
                               connectedAtMs=parsed.get("connectedAtMs"), replayBytes=parsed.get("bufferedBytes"),
                               gapGeneration=parsed.get("gapGeneration"))
                    break
            if held_id in self.relays:
                raise ValueError("two active IPC relay owners: " + held_id)
            self.relays[held_id] = dict(engine=writer, holder=upstream, keepBusy=False,
                                       busyReleased=asyncio.Event())
            tasks = [asyncio.create_task(self.tunnel(reader, upstream)),
                     asyncio.create_task(self.relay_out(upstream_reader, writer, held_id))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            entry = self.relays.get(held_id)
            if entry and entry["keepBusy"]:
                # Keep the real old attachment until the real holder rejects
                # a retry. A fixed sleep can expire before an idle actor sees EOF.
                await asyncio.wait_for(entry["busyReleased"].wait(), 90)
        except (ConnectionError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            self.controls.discard(writer)
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if held_id:
                self.relays.pop(held_id, None)
            writer.close()
            if upstream:
                upstream.close()

    async def control(self, command):
        action = command["action"]
        if action == "status":
            return dict(subscribed=self.subscribed, errorCount=self.error_count, errors=self.errors,
                        sessions=[s.summary() for s in self.sessions], acceptedPhysical=self.accepted_physical,
                        accepts=self.accepted_records, events=self.events, diagnostics=self.observed,
                        blockedReads=dict(self.blocked_writes), maxRelayReaders=dict(self.max_relay_readers),
                        commandCounts=dict(self.command_count), gates=sorted(self.gates), relayIds=list(self.relays))
        if action == "targetRules":
            self.silent_nicks = set(command["silent"])
            self.refused_nicks = set(command["refused"])
        elif action == "gates":
            gates = set(command["phases"])
            if not gates <= {"CAP", "SASL", "001", "TLS", "TCP"}:
                raise ValueError("unknown registration gate")
            self.gates = gates
        elif action == "controlUnavailable":
            self.control_until = time.monotonic() + min(20, max(1, command["seconds"]))
            for writer in tuple(self.controls):
                writer.close()
            self.audit("controlUnavailable", until=self.control_until)
        elif action == "relayLoss":
            entry = self.relays[command["id"]]
            entry["keepBusy"] = bool(command.get("busy"))
            entry["busyReleased"] = asyncio.Event()
            entry["engine"].close()
            if not entry["keepBusy"]:
                entry["holder"].close()
            self.audit("relayLoss", id=command["id"], busy=entry["keepBusy"])
        elif action == "pressure":
            held_id = command["id"]
            if command["enabled"]:
                self.pause_ids.add(held_id)
            else:
                self.pause_ids.discard(held_id)
        elif action == "burst":
            target = self.by_nick[command["nick"]]
            count = int(command["count"])
            if not 1 <= count <= 20000:
                raise ValueError("burst bound exceeded")
            # >4 MiB of complete lines; no unbounded burst concatenation.
            for index in range(count):
                await target.send([f":m000!u@mock PRIVMSG #memory0 :HE:{index}:" + "x" * 900])
        elif action == "held":
            return await self.inventory()
        elif action == "holderStatus":
            return await self.holder_request("STATUS")
        elif action == "probe":
            targets = [s for s in self.sessions if s.welcomed and not s.closed]
            for session in targets:
                token = "he-probe-" + secrets.token_hex(8)
                session.pending_ping = (token, time.monotonic())
                session.pings += 1
                await session.send(["PING :" + token])
            deadline = time.monotonic() + 5
            while any(s.pending_ping for s in targets):
                if time.monotonic() >= deadline:
                    raise ValueError("live/detached real PONG probe exceeded five seconds")
                await asyncio.sleep(0.01)
            return {"probed": len(targets), "maxPongSeconds": max(s.max_pong_seconds for s in targets)}
        else:
            raise ValueError("unknown engine fixture action")
        return {"ok": True}

    async def run(self):
        for port, tls in ((16668, False), (16669, True)):
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", port))
            listener.listen(512)
            listener.setblocking(False)
            self.task(self.accept(listener, tls))
        await asyncio.start_server(self.proxy, "0.0.0.0", 7690, limit=9 * 1024**2)
        await asyncio.start_server(self.http, "127.0.0.1", 8099, limit=128 * 1024)
        self.task(self.subscriber())
        await asyncio.Future()


class EngineQualification(Qualification):
    def __init__(self):
        # Do not call A's constructor: its exact-old-holder and 250-session soak
        # gates are intentionally separate, not weakened or repurposed here.
        self.context = os.environ["DOCKER_CONTEXT"]
        self.project = os.environ["COMPOSE_PROJECT_NAME"]
        self.compose = os.environ["COMPOSE_FILE"]
        self.run_id = os.environ["ROUTING_REGRESSION_RUN"]
        self.gateway = os.environ["GATEWAY_URL"]
        require(self.gateway.startswith("http://127.0.0.1:"), "gateway must use owned loopback forward")
        self.output = Path(os.environ["HOLDER_ENGINE_EVIDENCE_DIR"])
        require(self.output.is_dir() and not any(self.output.iterdir()), "fresh evidence directory required")
        self.cookie = LoopbackFixtureCookies(self.gateway)
        self.http = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie))
        self.ids, self.protected, self.networks, self.names = {}, {}, {}, {}
        self.coverage = []
        self.phase = "prerequisites"
        self.helper = os.environ["HOLDER_MAINTENANCE_HELPER"]
        require(Path(self.helper).is_file(), "guarded maintenance helper absent")
        self.diagnostics = []
        self.diagnostic_error = None
        self.log_process = None
        self.log_thread = None

    def start_diagnostics(self):
        self.log_process = subprocess.Popen(["docker", "--context", self.context, "logs", "--follow", "--since",
                                             self.inspect(self.ids["ircfiber-engine"])["State"]["StartedAt"],
                                             self.ids["ircfiber-engine"]], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        process = self.log_process
        def consume():
            try:
                while line := process.stdout.readline(32769):
                    require(len(line) <= 32768, "engine diagnostic line exceeds bound")
                    try:
                        value = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if value.get("event") not in {"holder_rebound", "holder_delivery_gap", "holder_rebind_wait",
                                                   "registration_admitted", "registration_released", "egress_retarget",
                                                   "maintenance_affinity_blocked"}:
                        continue
                    require(len(self.diagnostics) < 12000, "engine diagnostic evidence exceeds bound")
                    self.diagnostics.append(value)
            except Exception as error:
                self.diagnostic_error = str(error)
        self.log_thread = threading.Thread(target=consume, daemon=True)
        self.log_thread.start()

    def stop_diagnostics(self):
        if self.log_process:
            self.log_process.terminate()
            self.log_process.wait(timeout=10)
            self.log_thread.join(timeout=10)
            self.log_process = None

    def diagnostics_for(self, event, network=None):
        require(self.diagnostic_error is None, "diagnostic collector failed: " + str(self.diagnostic_error))
        return [d for d in self.diagnostics if d["event"] == event and
                (network is None or d.get("networkId") == network)]

    def rpc(self, action, **kwargs):
        return json.loads(self.command("exec", "-i", self.ids["mock-irc"], "python3",
                                       "/fixture/holder_engine_qualification.py", "rpc",
                                       data=json.dumps(dict(action=action, **kwargs)), timeout=120, max_bytes=12 * 1024**2))

    def record(self, case, **evidence):
        self.assert_protected()
        self.coverage.append(dict(case=case, at=time.time(), **evidence))
        self.save("coverage.json", self.coverage)

    def redis(self, *args):
        return self.command("exec", self.ids["redis"], "redis-cli", "--raw", *args).strip()

    def setup(self):
        for service in ("redis", "mongo", "ircfiber-gateway", "ircfiber-holder", "mock-irc", "egress-a", "egress-b", "ircfiber-engine"):
            info = self.owned(service)
            self.ids[service] = info["Id"]
            if service not in ("ircfiber-engine", "ircfiber-holder"):
                self.protected[service] = self.identity(info)
        for component in ("engine", "holder", "gateway"):
            info = self.inspect(self.ids["ircfiber-" + component])
            expected = os.environ["ROUTING_REGRESSION_" + component.upper() + "_IMAGE"]
            require(expected.startswith("sha256:") and info["Image"] == expected, "immutable candidate identity mismatch")
        holder_env = self.inspect(self.ids["ircfiber-holder"])["Config"]["Env"]
        require("IRCFIBER_HOLDER_DETACH_MAX_SECS=0" in holder_env, "candidate fixture must use unlimited detach")
        status = wait(lambda: self.rpc("holderStatus"), "candidate holder status")
        caps = status.get("capabilities")
        require(isinstance(caps, list) and CAPABILITIES <= set(caps), "candidate holder capabilities unavailable")
        require(status.get("instance"), "candidate holder UUID absent")
        self.initial_instance = status["instance"]
        self.start_diagnostics()
        wait(lambda: self.rpc("status")["subscribed"], "actual live event subscriber")
        user = "holder" + secrets.token_hex(6)
        credentials = dict(username=user, password=secrets.token_urlsafe(24), email=user + "@fixture.invalid")
        self.api("POST", "/register", credentials, form=True)
        self.api("POST", "/login", credentials, form=True)
        for row in self.api("GET", "/api/networks"):
            nid = row.get("id") or row.get("networkId")
            require(nid and row.get("nick"), "signup default network identity absent")
            self.networks[nid] = row["nick"]
        wait(lambda: self.registered(), "signup actual registration")
        self.save("manifest.json", dict(run=self.run_id, project=self.project, context=self.context,
                                         images={k: os.environ["ROUTING_REGRESSION_" + k.upper() + "_IMAGE"]
                                                 for k in ("engine", "holder", "gateway")},
                                         protected=self.protected, initialHolder=self.identity(self.owned("ircfiber-holder")),
                                         nativeIpv6="not configured; no native IPv6 claim"))

    def create(self, index, route="direct", tls=False, host="mock-irc", sasl=False, fallback=False):
        nick = "he" + secrets.token_hex(5)
        body = dict(name=f"HE_{index}_{self.run_id}", host=host, port=16669 if tls else 16668,
                    tls="enabled" if tls else "disabled", nick=nick, realName="Owned holder qualification",
                    routing=dict(order=["nordvpn"] if route != "direct" else ["direct"],
                                 preferredExit=route if route != "direct" else ""), autoJoinChannels=["#memory0"])
        if sasl:
            body.update(sasl="plain", saslUsername="fixture", saslPassword="fixture-only")
        if fallback:
            body["routing"]["order"] = ["nordvpn", "direct"]
        result = self.api("POST", "/api/networks", body)
        nid = result.get("id") or result.get("networkId")
        require(nid, "network create lacked identity")
        self.networks[nid] = nick
        return nid

    def registered(self):
        status = self.rpc("status")
        require(status["errorCount"] == 0, "upstream oracle errors: " + str(status["errors"]))
        live = {s["nick"]: s for s in status["sessions"] if not s["closed"] and s["welcomed"]}
        return bool(self.networks) and set(live) == set(self.networks.values()) and all(
            s["nickCommands"] == s["userCommands"] == 1 and s["observed001At"] is not None for s in live.values())

    def held(self):
        rows = [r for r in self.rpc("held") if r["state"] == "open"]
        require({r["tag"]["networkId"] for r in rows} == set(self.networks), "complete open holder/network set differs")
        return {r["tag"]["networkId"]: r for r in rows}

    def physical(self):
        status = self.rpc("status")
        require(status["errorCount"] == 0, "wire oracle errors: " + str(status["errors"]))
        live = {s["nick"]: s for s in status["sessions"] if not s["closed"]}
        require(set(live) == set(self.networks.values()), "physical network set cannot be narrowed")
        for session in live.values():
            require(session["nickCommands"] == session["userCommands"] == 1 and session["quitCommands"] == 0,
                    "duplicate NICK/USER or QUIT")
            require(session["welcomed"] and number(session["physical"][1]) > 0, "actual 001/inode missing")
        routes = self.held()
        accepts = {tuple(e["physical"]): e for e in status["events"] if e["event"] == "accept"}
        for nid, nick in self.networks.items():
            slot = routes[nid]["tag"].get("egressLabel")
            source = accepts[tuple(live[nick]["physical"])]["source"]
            if slot:
                require(slot in ("north", "south") and source == {"north": "192.0.2.30", "south": "192.0.2.31"}[slot],
                        "advertised concrete route differs from physical accepted source")
        return {nid: dict(physical=live[nick]["physical"], tls=live[nick]["tls"],
                          observed001At=live[nick]["observed001At"]) for nid, nick in self.networks.items()}

    def same(self, before_held, before_physical):
        current = self.held()
        require(set(current) == set(before_held), "holder set changed")
        for nid, row in current.items():
            require((row["id"], row["connectedAtMs"], row["instance"]) ==
                    tuple(before_held[nid][k] for k in ("id", "connectedAtMs", "instance")),
                    "same-instance rebind changed holder/socket identity")
        require(self.physical() == before_physical, "physical remote port/inode changed")
        require(all(v <= 1 for v in self.rpc("status")["maxRelayReaders"].values()), "duplicate IPC relay reader")
        self.assert_protected()

    def recovery(self):
        self.phase = "relay-recovery"
        self.create("plain", "north", sasl=True)
        self.create("tls", "south", tls=True, sasl=True)
        wait(self.registered, "mixed plain/TLS through real gateway")
        before_held, physical = self.held(), self.physical()
        self.save("pre-recovery.json", dict(held=before_held, physical=physical))
        for busy, outage in ((False, False), (True, False), (False, True)):
            for tls in (False, True):
                nid = next(n for n, p in physical.items() if p["tls"] == tls and before_held[n]["tag"].get("egressLabel"))
                row = before_held[nid]
                previous = self.rpc("status")
                if outage:
                    self.rpc("controlUnavailable", seconds=12)
                self.rpc("relayLoss", id=row["id"], busy=busy)
                wait(lambda: any(e["event"] == "ATTACH_OK" and e["id"] == row["id"]
                                 for e in self.rpc("status")["events"][len(previous["events"]):]),
                     "real same-ID actor rebind after IPC fault", 90)
                after = self.rpc("status")
                events = after["events"][len(previous["events"]):]
                require(not any(e["event"] in ("CLOSE", "DIAL", "NICK", "USER") for e in events),
                        "transient relay failure attempted CLOSE/DIAL/registration")
                if busy:
                    require(any(e["event"] == "relayRejected" and e.get("code") == "busy" for e in events),
                            "real holder busy response was not exercised")
                self.same(before_held, physical)
                diagnostic = wait(lambda: next((d for d in reversed(self.diagnostics_for("holder_rebound", nid))
                                                if d.get("holderId") == row["id"]), None),
                                  "actual actor/egress ownership diagnostic", 15)
                require(number(diagnostic.get("readerActors")) == 1, "rebind reader actor count unavailable/not one")
                expected_hold = 1 if row["tag"].get("egressLabel") else 0
                require(number(diagnostic.get("egressHold")) == expected_hold, "rebind changed concrete egress hold")
                slot = row["tag"].get("egressLabel")
                expected_slot_holds = sum(1 for r in before_held.values() if r["tag"].get("egressLabel") == slot)
                require(number(diagnostic.get("routeSlotHolds")) == expected_slot_holds,
                        "rebind leaked or duplicated concrete route pool holds")
                self.record("actor-rebind", tls=tls, realBusy=busy, controlOutage=outage,
                            holderId=row["id"], evidence=events)
        self.rpc("probe")

    def gaps(self):
        self.phase = "gap-recovery"
        for tls in (False, True):
            held, physical = self.held(), self.physical()
            nid = next(n for n, p in physical.items() if p["tls"] == tls and held[n]["tag"].get("egressLabel"))
            row = held[nid]
            before = self.rpc("status")
            session = next(s for s in before["sessions"] if s["nick"] == self.networks[nid] and not s["closed"])
            generation = number(row.get("gapGeneration"))
            prior_auth = json.loads(self.redis("HGET", "irc:state:fixture-regression:" + nid, "data"))
            require(prior_auth.get("servicesAccountState") == "account" and prior_auth.get("servicesAccount"),
                    "gap test requires actually observed known upstream account before invalidation")
            self.rpc("pressure", id=row["id"], enabled=True)
            try:
                self.rpc("burst", nick=self.networks[nid], count=12000)
                lost = wait(lambda: next((r for r in self.rpc("held") if r["id"] == row["id"]
                                         and number(r.get("gapGeneration")) > generation
                                         and number(r.get("droppedBytes")) > 0), None), "actual relay capacity gap")
                require(number(self.rpc("status")["blockedReads"].get(row["id"])) > 0,
                        "real relay draining was not paused")
                require(number(lost["gapAckGeneration"]) <= number(lost["gapGeneration"]), "future gap already ACKed")
            finally:
                self.rpc("pressure", id=row["id"], enabled=False)
            if row["id"] in self.rpc("status")["relayIds"]:
                self.rpc("relayLoss", id=row["id"], busy=False)
            def recovered():
                status = self.rpc("status")
                live = next(s for s in status["sessions"] if s["nick"] == self.networks[nid] and not s["closed"])
                acks = [e for e in status["events"][len(before["events"]):] if e["event"] == "GAP_ACK" and e["id"] == row["id"]]
                visible = [d for d in status["diagnostics"] if d["networkId"] == nid]
                if not acks or not visible:
                    return False
                for ack in acks:
                    require(any(e["event"] in ("INFO_GAP", "ATTACH_OK", "INVENTORY_GAP") and e.get("id") == row["id"] and
                                e["sequence"] < ack["sequence"] and
                                number(e.get("gapGeneration")) == number(ack["generation"])
                                for e in status["events"]),
                            "GAP_ACK covered a generation not observed by this engine")
                require(any(number(a["generation"]) >= number(lost["gapGeneration"]) for a in acks),
                        "observed loss generation was not acknowledged")
                require(live["namesRequests"] > session["namesRequests"], "gap did not rebaseline membership")
                require(live["historyRequests"] > session["historyRequests"], "supported history was not requested")
                return dict(acks=acks, diagnostics=visible, wire=live)
            evidence = wait(recovered, "visible gap + NAMES + supported history + observed generation ACK", 120)
            # Auth is checked from the real engine state, not inferred from NAMES.
            def invalidated_auth():
                raw = self.redis("HGET", "irc:state:fixture-regression:" + nid, "data")
                if not raw:
                    return None
                state = json.loads(raw)
                return state if (state.get("servicesAccountState") == "unknown"
                                 and state.get("servicesAccount", "") == "") else None
            state = wait(invalidated_auth, "fresh gap-invalidated authentication snapshot", 15)
            self.same(held, physical)
            self.record("actual-pressure-gap", tls=tls, gap=lost, recovery=evidence,
                        lossless=False, servicesAccountState=state["servicesAccountState"])

    def registration(self):
        self.phase = "registration-admission"
        start = len(self.rpc("status")["events"])
        # Different aliases are concrete normalized host/port routes, not fake
        # IPv6 identities. Enough independent destinations can fill eight slots.
        hosts = ["mock-irc", "alpha.example.org", "beta.example.net"]
        for phase in ("TLS", "CAP", "SASL", "001"):
            self.rpc("gates", phases=[phase, "001"])
            created = []
            try:
                for index in range(20):
                    route = ("direct", "north", "south")[index % 3]
                    created.append(self.create(f"admission_{phase}_{index}", route,
                                               tls=phase == "TLS" or index % 2 == 0,
                                               host=hosts[index % len(hosts)], sasl=phase == "SASL"))
                wait(lambda: len([e for e in self.rpc("status")["events"][start:]
                                  if e["event"] == "DIAL"]) >= 8, "eight actual admission starts", 90)
                # The real holder's TLS DIAL deadline is ten seconds. Inspect
                # occupancy before that terminal timeout can release a permit.
                if phase != "TLS":
                    time.sleep(4)
                events = self.rpc("status")["events"][start:]
                starts = [e for e in events if e["event"] == "DIAL" and e["networkId"] in created]
                require(len(starts) == 8, "global permit not held through delayed " + phase + "/001")
                # Full fresh-registration admission must not block a same-ID
                # attach. This is an actual lost relay, not a synthetic permit.
                existing = next(r for r in self.rpc("held")
                                if r["tag"]["networkId"] not in created and r["state"] == "open")
                relay_start = len(self.rpc("status")["events"])
                self.rpc("relayLoss", id=existing["id"], busy=False)
                wait(lambda: any(e["event"] == "ATTACH_OK" and e["id"] == existing["id"]
                                 for e in self.rpc("status")["events"][relay_start:]),
                     "ATTACH exempt while all eight fresh registration permits occupied", 30)
                require(not any(e["event"] == "DIAL" for e in self.rpc("status")["events"][relay_start:]),
                        "ATTACH exemption introduced a fresh DIAL")
                if phase == "TLS":
                    # Cancellation below targets a positively owned socket.
                    # An unresolved DIAL must retain its admission claim until
                    # terminal evidence, not release merely on user shutdown.
                    self.rpc("gates", phases=["001"])
                    wait(lambda: len([r for r in self.rpc("held")
                                      if r["state"] == "open" and
                                      r["tag"].get("networkId") in created]) == 8,
                         "eight completed TLS transports still gated before 001", 8)
                    require(len([e for e in self.rpc("status")["events"][start:]
                                 if e["event"] == "DIAL" and e["networkId"] in created]) == 8,
                            "TLS completion released registration admission before 001")
                # Cancel one real pending registration and prove one, not two,
                # waiters starts. This also exercises permit release on shutdown.
                cancelled = starts[0]["networkId"]
                self.api("POST", f"/api/networks/{cancelled}/disconnect")
                self.networks.pop(cancelled)
                wait(lambda: len([e for e in self.rpc("status")["events"][start:]
                                  if e["event"] == "DIAL" and e["networkId"] in created]) == 9,
                     "cancelled permit releases exactly one waiter", 30)
                time.sleep(2)
                require(len([e for e in self.rpc("status")["events"][start:]
                             if e["event"] == "DIAL" and e["networkId"] in created]) == 9,
                        "cancelled global permit released twice")
                self.record("global-eight-through-" + phase, starts=starts, cancellation=cancelled)
            finally:
                self.rpc("gates", phases=[])
            wait(self.registered, "all uncancelled registrations actually observed 001", 240)
            start = len(self.rpc("status")["events"])
        self.validate_registration_events()
        self.fallback()
        self.route_waiters()

    def fallback(self):
        start = len(self.rpc("status")["events"])
        nid = self.create("fallback", "north", host="fallback.example.org", fallback=True)
        wait(self.registered, "real SOCKS refusal falls back to direct registration", 120)
        starts = [e for e in self.rpc("status")["events"][start:] if e["event"] == "DIAL" and e["networkId"] == nid]
        require(any(e["route"]["provider"] == "nordvpn" for e in starts) and
                any(e["route"]["provider"] == "direct" for e in starts), "actual owned fallback DIALs missing")
        self.validate_registration_events()
        self.record("actual-fallback-registration", starts=starts)

    def route_waiters(self):
        start = len(self.rpc("status")["events"])
        self.rpc("gates", phases=["001"])
        created, other = [], []
        try:
            for index in range(12):
                created.append(self.create("routewait" + str(index), host="beta.example.net"))
            for index, route in enumerate(("north", "south")):
                other.append(self.create("independent" + str(index), route, host="alpha.example.org"))
            wait(lambda: len([e for e in self.rpc("status")["events"][start:] if e["event"] == "DIAL"]) >= 8,
                 "route-waiter fairness fills eight real attempts", 30)
            starts = [e for e in self.rpc("status")["events"][start:] if e["event"] == "DIAL"]
            require(len(starts) == 8 and {e["networkId"] for e in starts} >= set(other),
                    "same-route waiters consumed global permits and starved independent routes")
            self.record("route-waiters-do-not-own-global-permits", starts=starts, independent=other)
        finally:
            self.rpc("gates", phases=[])
        wait(self.registered, "route waiter set completes actual 001", 120)
        self.validate_registration_events()

    def control(self, action, config):
        self.redis("LPUSH", "irc:control:fixture-regression",
                   json.dumps(dict(action=action, timestampMs=int(time.time() * 1000), config=config)))

    def projection(self, operation, deadline):
        self.control("holderMaintenance", dict(serverId="fixture-regression", operationId=operation,
                                               phase="status", deadlineMs=deadline))
        raw = self.redis("GET", "irc:holder:maintenance:fixture-regression:" + operation)
        return json.loads(raw) if raw else None

    def helper_command(self, action, operation, spec, lost=False, expected=0):
        command = [sys.executable, self.helper, action, "--operation-id", operation,
                   "--image", os.environ["ROUTING_REGRESSION_HOLDER_IMAGE"], "--fixture-spec", str(spec)]
        if lost:
            command.append("--fixture-lost-return")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=640)
        require(len(result.stdout) + len(result.stderr) <= 1024**2, "helper output exceeds bound")
        # A nonzero return is not necessarily the injected lost activation
        # reply: retain the real guard error before inspecting a fence.
        self.save("maintenance-helper-" + action + ".json",
                  dict(returncode=result.returncode, stdout=result.stdout.decode(errors="replace"),
                       stderr=result.stderr.decode(errors="replace")))
        if lost:
            require((self.output / "maintenance-private" / "fence.json").is_file()
                    and b"single activation attempt ambiguous/failed" in result.stderr,
                    "lost-return injection did not reach activation: " + result.stderr.decode(errors="replace")[:1000])
        require((result.returncode == 0) == (expected == 0), "guarded helper outcome differs: " +
                result.stderr.decode(errors="replace")[:1000] + result.stdout.decode(errors="replace")[:1000])
        return dict(returncode=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode())

    def maintenance(self):
        self.phase = "maintenance-freeze"
        before_held, before_physical = self.held(), self.physical()
        preferences = {n.get("id") or n.get("networkId"): n["routing"] for n in self.api("GET", "/api/networks")}
        old = self.owned("ircfiber-holder")
        root = self.output / "maintenance-private"
        root.mkdir(mode=0o700)
        context = json.loads(self.command("context", "inspect", self.context))[0]
        endpoint = context["Endpoints"]["docker"]["Host"]
        require(endpoint.startswith("unix:///"), "fixture helper requires local Unix Docker context")
        aliases = {"holder": "ircfiber-holder", "engine": "ircfiber-engine", "gateway": "ircfiber-gateway",
                   "redis": "redis", "mock-irc": "mock-irc", "egress-a": "egress-a", "egress-b": "egress-b"}
        spec = dict(serverId="fixture-regression", dockerSocket=endpoint[7:], project=self.project,
                    run=self.run_id, root=str(root.resolve()), sourceImageId=old["Image"],
                    candidateImageId=os.environ["ROUTING_REGRESSION_HOLDER_IMAGE"],
                    containers={key: dict(id=self.ids[service], name=self.inspect(self.ids[service])["Name"].lstrip("/"))
                                for key, service in aliases.items()})
        spec_path = root / "fixture-spec.json"
        fd = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(spec, stream)
        direct = [nid for nid, row in before_held.items() if not row["tag"].get("egressLabel")]
        require(len(direct) >= 2, "need two actually registered direct rows for refusal/unresolved classification")
        silent, refused = direct[:2]
        self.rpc("targetRules", silent=[self.networks[silent]], refused=[self.networks[refused]])
        admission_before = {slot: self.redis("GET", "irc:egress:admission:" + slot) for slot in ("north", "south")}
        now = int(time.time() * 1000)
        # These are real admission-store states read by the engine, not a mocked
        # route picker. Existing sockets remain open until the single replacement.
        injected = {}
        for slot, address in (("north", "192.0.2.30"), ("south", "192.0.2.31")):
            item = dict(v=1, endpoint=address + ":1080", draining=slot == "north", drainReason="owned maintenance proof",
                        open=slot == "south", retryAtMs=now + 600000, failures=1 if slot == "south" else 0,
                        circuitReason="owned quarantine proof" if slot == "south" else "", trialToken="",
                        trialUntilMs=0, trialRegisteredAtMs=0, gen=1, updatedAtMs=now)
            injected[slot] = item
            self.redis("SET", "irc:egress:admission:" + slot, json.dumps(item))
        operation = str(uuid.uuid4())
        fault_start = len(self.rpc("status")["events"])
        try:
            ambiguous = self.helper_command("activate", operation, spec_path, lost=True, expected=1)
            fence = json.loads((root / "fence.json").read_text())
            baseline = json.loads((root / "baseline.json").read_text())["manifest"]
            deadline = number(fence["deadlineMs"])
            require({r["networkId"] for r in baseline["rows"]} == set(self.networks),
                    "maintenance freeze omitted currently actual registered networks")
            for row in baseline["rows"]:
                original = before_held[row["networkId"]]
                require(row["oldHolderId"] == original["id"] and row["oldConnectedAtMs"] == original["connectedAtMs"],
                        "frozen physical holder provenance differs")
                require(row["userId"] == original["tag"]["userId"] and
                        row["host"].lower() == original["host"].lower() and row["port"] == original["port"] and
                        row["tls"] == ("implicit" if before_physical[row["networkId"]]["tls"] else "none"),
                        "frozen owner/destination/TLS differs from actual registered socket")
                require(row["route"]["slot"] == original["tag"].get("egressLabel", "") and
                        row["route"]["nativeIpv6"] == "",
                        "frozen concrete route changed or invented native IPv6")
                require(set(("provider", "slot", "exitId", "nativeIpv6")) <= row["route"].keys(),
                        "concrete route freeze lacks explicit values")
                require(number(row["registeredAtMs"]) > 0, "freeze lacks actual pre-maintenance 001")
            require({r["route"]["slot"] for r in baseline["rows"]} >= {"north", "south"},
                    "frozen complete set did not retain both concrete SOCKS routes")
            new = self.inspect(old["Name"].lstrip("/"))
            require(new["Id"] != old["Id"] and new["State"]["Running"], "helper did not perform physical holder replacement")
            self.ids["ircfiber-holder"] = new["Id"]
            new_identity = self.identity(new)
            require(self.rpc("holderStatus")["instance"] != self.initial_instance, "new holder incarnation not observed")
            self.control("retargetEgress", dict(label="north", locationId="fixture-forbidden-retarget", force=True))
            retarget = wait(lambda: next((d for d in self.diagnostics_for("egress_retarget")
                                         if d.get("reason") == "maintenance-frozen"), None),
                            "real forced retarget rejected by maintenance affinity", 30)
            require(number(retarget.get("bounced")) == 0, "freeze retarget bounced live networks")
            pending = wait(lambda: self.projection(operation, deadline), "complete pending recovery projection", 30)
            time.sleep(8)
            pending = self.projection(operation, deadline)
            rows = {r["networkId"]: r for r in pending["rows"]}
            require(rows[silent]["state"] in ("pending", "unresolved") and
                    not rows[silent].get("observed001AtMs"), "silent upstream was falsely recovered")
            wait(lambda: any(e["event"] == "465" and e.get("nick") == self.networks[refused]
                             for e in self.rpc("status")["events"][fault_start:]), "actual upstream 465 refusal", 30)
            pending = self.projection(operation, deadline)
            refused_row = next(r for r in pending["rows"] if r["networkId"] == refused)
            require(refused_row["state"] == "refused" and refused_row.get("reason") and
                    number(refused_row.get("classifiedAtMs")) > 0 and not refused_row.get("observed001AtMs"),
                    "external refusal classification unavailable or falsely recovered")
            blocked_nids = {r["networkId"] for r in baseline["rows"] if r["route"]["slot"] in ("north", "south")}
            post_fault = self.rpc("status")["events"][fault_start:]
            for slot, expected in injected.items():
                observed = json.loads(self.redis("GET", "irc:egress:admission:" + slot))
                require(number(observed.get("failures")) == number(expected["failures"]) and
                        observed.get("open") == expected["open"] and observed.get("draining") == expected["draining"],
                        "planned holder loss changed failure scoring or frozen-route admission")
            require(not any(e["event"] == "DIAL" and e["networkId"] in blocked_nids for e in post_fault),
                    "drain/quarantine frozen route rotated or dialed despite admission")
            require(number(pending.get("unresolvedCount")) > 0, "incomplete physical recovery claimed zero unresolved")
            self.save("unresolved-must-fail.json", dict(state="failed", reason="actual 001/affinity incomplete",
                                                       projection=pending, refusal=refused_row, retarget=retarget))
        finally:
            for slot, prior in admission_before.items():
                if prior:
                    self.redis("SET", "irc:egress:admission:" + slot, prior)
                else:
                    self.redis("DEL", "irc:egress:admission:" + slot)
            # Keep external refusal active; it is not a recovered row. Resolve
            # the intentionally silent row so the real classification can finish.
            self.rpc("targetRules", silent=[], refused=[self.networks[refused]])
        self.phase = "maintenance-classification"
        classification = self.helper_command("status", operation, spec_path)
        completed = self.projection(operation, deadline)
        require(number(completed.get("unresolvedCount")) == 0, "maintenance classification has unresolved rows")
        require(number(completed.get("refusedCount")) >= 1, "refusal case disappeared from complete classification")
        require({r["networkId"] for r in completed["rows"]} == set(self.networks), "classified manifest shrank")
        recovered_ids = set()
        status = self.rpc("status")
        live_sessions = {s["nick"]: s for s in status["sessions"] if not s["closed"] and s["welcomed"]}
        for row in completed["rows"]:
            nid = row["networkId"]
            if row["state"] == "refused":
                require(nid == refused and row.get("reason"), "unexplained external refusal")
                continue
            require(row["state"] == "recovered", "nonterminal classification")
            recovered_ids.add(nid)
            require(row["newHolderId"] != row["oldHolderId"] and
                    number(row["newConnectedAtMs"]) > number(row["oldConnectedAtMs"]) and
                    number(row.get("observed001AtMs")) > number(fence["activationMs"]) and
                    row["actualRoute"] == row["route"], "new generation/actual 001/concrete affinity not proved")
            physical = live_sessions[self.networks[nid]]
            require(physical["physical"] != before_physical[nid]["physical"] and physical["observed001At"] is not None,
                    "classification lacks corresponding new physical accepted socket")
            require(physical["nickCommands"] == physical["userCommands"] == 1,
                    "maintenance duplicated registration on recovered socket")
            new_registrations = [s for s in status["sessions"] if s["nick"] == self.networks[nid] and
                                 s["physical"] != before_physical[nid]["physical"]]
            require(len(new_registrations) == 1, "replacement caused extra physical registrations on recovered network")
            slot = row["route"]["slot"]
            if slot:
                accepted = next(e for e in status["events"] if e["event"] == "accept" and
                                e["physical"] == physical["physical"])
                require(accepted["source"] == {"north": "192.0.2.30", "south": "192.0.2.31"}[slot],
                        "recovered concrete route differs from physical source endpoint")
        require(not ({r["oldHolderId"] for r in completed["rows"]} &
                     {r["id"] for r in self.rpc("held")}), "new incarnation reused old opaque IDs")
        repeated = self.helper_command("activate", operation, spec_path)
        require(self.identity(self.inspect(new["Name"].lstrip("/"))) == new_identity, "ambiguous resume replaced twice")
        rejected = self.helper_command("activate", str(uuid.uuid4()), spec_path, expected=1)
        require(self.identity(self.inspect(new["Name"].lstrip("/"))) == new_identity, "second UUID replaced holder")
        current_preferences = {n.get("id") or n.get("networkId"): n["routing"] for n in self.api("GET", "/api/networks")}
        require(current_preferences == preferences, "maintenance rewrote saved routing preferences")
        for slot, prior in admission_before.items():
            actual = self.redis("GET", "irc:egress:admission:" + slot)
            if prior:
                before, after = json.loads(prior), json.loads(actual)
                require(after.get("failures") == before.get("failures") and after.get("open") == before.get("open"),
                        "planned holder loss changed egress failure scoring")
        self.record("single-fenced-holder-maintenance", operationId=operation, baseline=baseline,
                    classification=completed, helperStatus=classification, ambiguousReturn=ambiguous,
                    sameOperationReadOnlyResume=repeated, secondUUIDRejected=rejected)
        self.hot_swap_after_maintenance(recovered_ids, completed, new_identity)
        self.maintenance_counts = {key: number(completed.get(key)) for key in
                                   ("recoveredCount", "refusedCount", "unresolvedCount")}

    def hot_swap_after_maintenance(self, recovered_ids, classification, holder_identity):
        self.phase = "post-maintenance-engine-hot-swap"
        before = {r["tag"]["networkId"]: (r["id"], r["connectedAtMs"]) for r in self.rpc("held")
                  if r["state"] == "open" and r["tag"]["networkId"] in recovered_ids}
        physical = {s["nick"]: s["physical"] for s in self.rpc("status")["sessions"]
                    if not s["closed"] and s["welcomed"]}
        require(len(before) == len(recovered_ids), "missing recovered physical baseline before engine hot-swap")
        self.stop_diagnostics()
        self.command("stop", "--time", "35", self.ids["ircfiber-engine"], timeout=50)
        require(not self.inspect(self.ids["ircfiber-engine"])["State"]["Running"], "engine did not stop")
        self.rpc("probe")
        self.command("start", self.ids["ircfiber-engine"])
        self.start_diagnostics()
        def attached():
            rows = {r["tag"]["networkId"]: r for r in self.rpc("held") if r["state"] == "open"}
            return set(before) <= rows.keys() and all(rows[n].get("attached") and
                    (rows[n]["id"], rows[n]["connectedAtMs"]) == before[n] for n in before)
        wait(attached, "all new-generation sockets survive subsequent SIGTERM engine hot-swap", 120)
        after = {s["nick"]: s for s in self.rpc("status")["sessions"] if not s["closed"] and s["welcomed"]}
        require({nick: row["physical"] for nick, row in after.items()} == physical,
                "post-maintenance engine hot-swap changed physical sockets")
        require(all(s["nickCommands"] == s["userCommands"] == 1 and s["quitCommands"] == 0 for s in after.values()),
                "engine hot-swap registered or QUIT existing recovered socket")
        require(self.identity(self.owned("ircfiber-holder")) == holder_identity, "holder changed during engine hot-swap")
        self.record("post-maintenance-socket-preserving-SIGTERM", recoveredNetworks=sorted(recovered_ids),
                    externallyRefused=[r["networkId"] for r in classification["rows"] if r["state"] == "refused"],
                    held=before, physical=physical)

    def validate_registration_events(self):
        status = self.rpc("status")
        starts = [e for e in status["events"] if e["event"] == "DIAL"]
        require(starts, "no real DIAL starts")
        routes = {}
        for event in starts:
            route = event["route"]
            key = (event["host"], event["port"], route["provider"], route["slot"], route["exitId"], route["nativeIpv6"])
            if key in routes:
                require(event["at"] - routes[key] >= 0.999, "actual DIAL route spacing below one second")
            routes[key] = event["at"]
        require({e["route"]["slot"] for e in starts} >= {"north", "south"}, "multiple actual SOCKS routes unexercised")
        self.record("concrete-route-spacing", actualDialStarts=starts)

    def run(self):
        self.setup()
        self.recovery()
        self.gaps()
        self.registration()
        self.maintenance()
        admissions = self.diagnostics_for("registration_admitted")
        releases = self.diagnostics_for("registration_released")
        require(admissions and releases, "registration ownership counters unavailable")
        require(all(0 <= number(d.get("inFlight")) <= 8 for d in admissions + releases),
                "global registration counter outside zero/eight bound")
        self.save("engine-diagnostics.json", self.diagnostics)
        self.save("final-wire.json", self.rpc("status"))
        return dict(state="passed", scope="step8 physical engine/maintenance", coverage=self.coverage,
                    nativeIpv6="unavailable; no native IPv6 physical claim", noAutomaticHolderRollback=True,
                    maintenance=self.maintenance_counts)


async def socks_server():
    active = set()
    targets = {"mock-irc", "alpha.example.org", "beta.example.net", "fallback.example.org"}
    async def handle(reader, writer):
        upstream = None
        tasks = []
        if len(active) >= 256:
            writer.close()
            return
        active.add(writer)
        try:
            version, count = await reader.readexactly(2)
            methods = await reader.readexactly(count)
            require(version == 5 and 2 in methods, "SOCKS fixture requires username/password")
            writer.write(b"\x05\x02")
            await writer.drain()
            version, count = await reader.readexactly(2)
            username = await reader.readexactly(count)
            size = (await reader.readexactly(1))[0]
            password = await reader.readexactly(size)
            require(version == 1 and username == password == b"test", "fixture-only SOCKS credentials required")
            writer.write(b"\x01\x00")
            await writer.drain()
            version, command, reserved, kind = await reader.readexactly(4)
            require((version, command, reserved, kind) == (5, 1, 0, 3), "fixture SOCKS requires named CONNECT")
            size = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(size)).decode().lower()
            port = int.from_bytes(await reader.readexactly(2), "big")
            require(host in targets and port in (16668, 16669), "refusing nonfixture SOCKS destination")
            if host == "fallback.example.org":
                # Deliberate real proxy refusal exercises owned DIAL fallback.
                writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return
            upstream_reader, upstream = await asyncio.wait_for(asyncio.open_connection("mock-irc", port), 10)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            async def copy(source, target):
                while data := await source.read(65536):
                    target.write(data)
                    await target.drain()
            tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(upstream_reader, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, RuntimeError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            active.discard(writer)
            writer.close()
            if upstream:
                upstream.close()
    server = await asyncio.start_server(handle, "0.0.0.0", 1080)
    async with server:
        await server.serve_forever()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("serve", "socks", "rpc", "certificates", "qualify"):
        raise SystemExit("expected serve|socks|rpc|certificates|qualify")
    mode = sys.argv[1]
    if mode == "serve":
        asyncio.run(EngineFixture().run())
    elif mode == "socks":
        asyncio.run(socks_server())
    elif mode == "certificates":
        certificates()
    elif mode == "rpc":
        data = sys.stdin.buffer.read(128 * 1024 + 1)
        require(len(data) <= 128 * 1024, "RPC request too large")
        request = urllib.request.Request("http://127.0.0.1:8099", data=data,
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=110) as response:
            body = response.read(12 * 1024**2 + 1)
            require(len(body) <= 12 * 1024**2, "RPC evidence exceeds bound")
            sys.stdout.buffer.write(body)
    else:
        proof = None
        result = dict(state="failed", scope="step8 physical engine/maintenance")
        try:
            proof = EngineQualification()
            result = proof.run()
        except Exception as error:
            result.update(reason=str(error), phase=proof.phase if proof else "prerequisites")
            if proof:
                try:
                    proof.capture_failure_evidence(result)
                    proof.save("engine-diagnostics.json", proof.diagnostics)
                except Exception as observation_error:
                    result["observationError"] = str(observation_error)
        finally:
            if proof:
                try:
                    proof.stop_diagnostics()
                except Exception as error:
                    result.update(state="failed", diagnosticShutdownError=str(error))
            output = Path(os.environ["HOLDER_ENGINE_EVIDENCE_DIR"])
            output.mkdir(parents=True, exist_ok=True)
            (output / "result.json").write_text(json.dumps(result, separators=(",", ":")) + "\n")
        print(json.dumps(result, separators=(",", ":")))
        raise SystemExit(0 if result["state"] == "passed" else 1)


if __name__ == "__main__":
    main()
