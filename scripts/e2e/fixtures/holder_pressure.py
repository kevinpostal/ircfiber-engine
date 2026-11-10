#!/usr/bin/env python3
"""Real candidate-holder Unix IPC/TCP/TLS qualification, without engine traffic.

Run through holder_pressure.sh. The launcher owns stack creation and cleanup;
this driver never creates/restarts/removes Docker objects. All pressure, including
605 seconds detached, is physical and uses the unmodified candidate's limits.
Evidence is bounded: hashes/counters, not message contents or META snapshots.
"""
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

MIB = 1024 * 1024
SOCKET = os.environ.get("HOLDER_PRESSURE_SOCKET", "/run/ircfiber/holder.sock")
SERVER_ID = os.environ.get("HOLDER_PRESSURE_SERVER_ID", "fixture-regression")
TOKEN = ""
if os.environ.get("HOLDER_PRESSURE_TOKEN_FILE"):
    TOKEN = Path(os.environ["HOLDER_PRESSURE_TOKEN_FILE"]).read_text().strip()
CAPS = {"inventory_v1", "gap_ack_v1", "bounded_meta_v1", "independent_pong_v1"}
LIMITS = {"relayBytes": 64 * MIB, "outboundBytes": 8 * MIB,
          "pongBytes": 4 * MIB, "metaBytes": 128 * MIB}
SESSION_LIMITS = {"relayBytes": 4 * MIB, "outboundBytes": 64 * 1024,
                  "pongBytes": 64 * 1024}


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def number(obj, key):
    value = obj.get(key)
    require(isinstance(value, (int, float)) and not isinstance(value, bool)
            and value >= 0, "missing/invalid numeric " + key)
    return value


def compact(obj):
    return json.dumps(obj, separators=(",", ":"))


async def until(fn, predicate, seconds=15, message="condition did not become true"):
    deadline = time.monotonic() + seconds
    while True:
        value = await fn()
        if predicate(value):
            return value
        require(time.monotonic() < deadline, message)
        await asyncio.sleep(.05)


class Wire:
    """No eager read-ahead: a stopped Wire is an actually undrained IPC socket."""
    def __init__(self, sock):
        self.sock = sock

    @classmethod
    async def open(cls, path=SOCKET):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        sock.setblocking(False)
        await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, path), 10)
        return cls(sock)

    async def send(self, data):
        await asyncio.wait_for(asyncio.get_running_loop().sock_sendall(self.sock, data), 30)

    async def request(self, verb, obj):
        await self.send((verb + " " + compact(obj) + "\n").encode())
        return await self.reply()

    async def line(self, limit=9 * MIB):
        async with asyncio.timeout(30):
            return await self.read_line(limit)

    async def read_line(self, limit):
        # Peek then consume only through the delimiter: efficiently handle a
        # large INFO without stealing even one byte of the replay that follows.
        buf = bytearray()
        loop = asyncio.get_running_loop()
        while True:
            data = await asyncio.wait_for(loop.sock_recv(self.sock, 1), 30)
            if not data:
                raise EOFError("IPC EOF")
            buf += data
            if data != b"\n":
                try:
                    available = self.sock.recv(65536, socket.MSG_PEEK)
                except BlockingIOError:
                    available = b""
                if available:
                    end = available.find(b"\n")
                    wanted = len(available) if end < 0 else end + 1
                    extra = await loop.sock_recv(self.sock, wanted)
                    buf += extra
            require(len(buf) <= limit, "IPC response bound exceeded")
            if buf.endswith(b"\n"):
                return bytes(buf)

    async def reply(self):
        raw = await self.line()
        verb, data = raw.split(b" ", 1)
        return verb.decode(), json.loads(data), len(raw)

    def close(self):
        self.sock.close()


class AckGate:
    """Unix proxy holds an actual META reply before bytes reach its consumer."""
    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="holder-pressure-ack-")
        self.path = self.directory.name + "/control.sock"
        self.received = asyncio.Event()
        self.release = asyncio.Event()
        self.server = None
        self.tasks = set()
        self.error = None

    async def start(self):
        self.server = await asyncio.start_unix_server(self.accept, self.path, limit=9 * MIB)

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        upstream = None
        try:
            upstream = await Wire.open()
            while line := await reader.readline():
                require(len(line) <= 8 * MIB + 4096, "ACK proxy request overflow")
                await upstream.send(line)
                reply = await upstream.line()
                if line.startswith(b"META "):
                    require(reply.startswith(b"OK "), "real strict META ACK was not successful")
                    self.received.set()
                    await self.release.wait()
                writer.write(reply)
                await writer.drain()
        except Exception as exc:
            self.error = str(exc)
        finally:
            if upstream:
                upstream.close()
            writer.close()
            self.tasks.discard(task)

    async def stop(self):
        self.release.set()
        self.server.close()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 5)
        await asyncio.wait_for(self.server.wait_closed(), 5)
        self.directory.cleanup()


class Control:
    def __init__(self, wire):
        self.wire = wire
        self.lock = asyncio.Lock()

    @classmethod
    async def open(cls, path=SOCKET):
        wire = await Wire.open(path)
        verb, hello, _ = await wire.request("HELLO", {"proto": 1, "serverId": SERVER_ID,
                                                      "engine": "pressure-fixture", "token": TOKEN})
        require(verb == "OK" and CAPS <= set(hello.get("capabilities", [])), "candidate capabilities missing")
        require(isinstance(hello.get("instance"), str) and len(hello["instance"]) >= 32, "instance UUID absent")
        self = cls(wire)
        self.hello = hello
        return self

    async def raw(self, verb, obj=None):
        async with self.lock:
            return await self.wire.request(verb, obj or {})

    async def call(self, verb, obj=None):
        kind, result, _ = await self.raw(verb, obj)
        require(kind == "OK", verb + " failed: " + compact(result)[:256])
        return result

    async def info(self, ident):
        return await self.call("INFO", {"id": ident})

    async def status(self):
        result = await self.call("STATUS")
        for key, maximum in LIMITS.items():
            require(number(result, key) <= maximum, key + " aggregate bound exceeded")
        for key in ("readerTasks", "upstreamWriterTasks", "attachmentWriterTasks", "pumpTasks",
                    "timerTasks", "droppedBytes", "droppedLines", "relaySaturations",
                    "commandSaturations", "pongSaturations", "metaRejectedBytes", "open", "attached",
                    "detached", "closed", "liveEntries", "retiringEntries", "tombstones"):
            number(result, key)
        require(number(result, "upstreamWriterTasks") <= number(result, "liveEntries") + number(result, "retiringEntries"),
                "more than one upstream writer per live/retiring owner")
        return result

    def close(self):
        self.wire.close()


class Peer:
    def __init__(self, fixture, physical, reader, writer, tls):
        self.fixture, self.physical = fixture, physical
        self.reader, self.writer, self.tls = reader, writer, tls
        self.closed = False
        self.nick = None
        self.nicks = self.users = self.quits = self.commands = 0
        self.pings = self.pongs = 0
        self.pending = {}
        self.max_pong = 0
        self.send_lock = asyncio.Lock()
        self.pause = False
        self.read_paused = asyncio.Event()
        self.resume = asyncio.Event()
        self.resume.set()
        self.error = None
        self.ping_task = None

    async def send(self, data):
        async with self.send_lock:
            self.writer.write(data)
            await asyncio.wait_for(self.writer.drain(), 10)

    async def ping(self):
        self.pings += 1
        token = "HP-%s-%d" % (self.physical[1], self.pings)
        self.pending[token] = time.monotonic()
        await self.send(("PING :" + token + "\r\n").encode())

    async def ticker(self):
        while not self.closed:
            await self.ping()
            await asyncio.sleep(5)

    async def run(self):
        try:
            while True:
                if self.pause:
                    self.writer.transport.pause_reading()
                    self.read_paused.set()
                    await self.resume.wait()
                    self.writer.transport.resume_reading()
                    self.read_paused.clear()
                raw = await self.reader.readline()
                if not raw:
                    break
                require(len(raw) <= 65536 and raw.endswith(b"\r\n"), "interleaved/malformed upstream command")
                text = raw[:-2].decode("ascii")
                if text.startswith("NICK "):
                    self.nicks += 1
                    self.nick = text[5:]
                    require(self.nick not in self.fixture.by_nick, "duplicate registration")
                    self.fixture.by_nick[self.nick] = self
                elif text.startswith("USER "):
                    self.users += 1
                elif text.startswith("PONG "):
                    token = text.split()[-1].lstrip(":")
                    require(token in self.pending, "duplicate/unrequested PONG or interleaving")
                    elapsed = time.monotonic() - self.pending.pop(token)
                    self.max_pong = max(self.max_pong, elapsed)
                    self.pongs += 1
                elif text.startswith("PRIVMSG #pressure :CMD:"):
                    match = re.fullmatch(r"PRIVMSG #pressure :CMD:(\d+):([x]+)", text)
                    require(match is not None, "ordinary/PONG bytes interleaved")
                    require(int(match[1]) == self.commands, "ordinary commands reordered")
                    self.commands += 1
                elif text == "WAKE":
                    pass
                elif text.startswith("QUIT"):
                    self.quits += 1
                else:
                    raise AssertionError("unexpected/malformed upstream command")
        except Exception as exc:
            self.error = str(exc)
        finally:
            self.closed = True
            self.writer.close()
            if self.ping_task:
                self.ping_task.cancel()

    def summary(self):
        return {"physical": self.physical, "tls": self.tls, "closed": self.closed,
                "nicks": self.nicks, "users": self.users, "quits": self.quits,
                "commands": self.commands, "pings": self.pings, "pongs": self.pongs,
                "maxPongSeconds": self.max_pong, "pendingPings": len(self.pending),
                "error": self.error}


class Fixture:
    def __init__(self):
        self.peers = []
        self.by_nick = {}
        self.listeners = []
        self.tasks = set()

    async def start(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/fixture-certs/ca-certificates.crt", "/fixture-certs/key.pem")
        for port, tls in ((17668, False), (17669, True)):
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", port))
            listener.listen(512)
            listener.setblocking(False)
            self.listeners.append(listener)
            self.track(self.accept(listener, context if tls else None))

    def track(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    async def accept(self, listener, context):
        loop = asyncio.get_running_loop()
        while True:
            sock, addr = await loop.sock_accept(listener)
            # Capture the accepted TCP inode/remote port BEFORE TLS wrapping.
            physical = [addr[1], os.fstat(sock.fileno()).st_ino]
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            self.track(self.accepted(sock, physical, context))

    async def accepted(self, sock, physical, context):
        reader = asyncio.StreamReader(limit=65536)
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await asyncio.get_running_loop().connect_accepted_socket(
            lambda: protocol, sock, ssl=context, ssl_handshake_timeout=10 if context else None)
        writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_running_loop())
        peer = Peer(self, physical, reader, writer, bool(context))
        self.peers.append(peer)
        await peer.run()

    async def stop(self):
        for listener in self.listeners:
            listener.close()
        for peer in self.peers:
            peer.writer.close()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)


class Suite:
    def __init__(self):
        self.fixture = Fixture()
        self.control = None
        self.serial = 0
        self.owned = []
        self.cases = []
        self.counters = []
        self.started = time.monotonic()
        self.initial = None
        self.running = set()
        self.terminal_diagnostics = []

    def progress(self):
        summary = [{key: row[key] for key in ("name", "state", "seconds", "reason") if key in row}
                   for row in self.cases]
        data = compact({"running": sorted(self.running), "elapsed": time.monotonic() - self.started,
                        "cases": summary})
        require(len(data) <= 32768, "pressure progress evidence exceeds bound")
        path = Path("/tmp/holder-pressure-progress.json")
        temporary = path.with_suffix(".tmp")
        temporary.write_text(data)
        os.replace(temporary, path)

    async def sample(self):
        value = await self.control.status()
        require(value["instance"] == self.control.hello["instance"], "holder generation changed")
        if len(self.counters) < 160:
            self.counters.append({"elapsed": round(time.monotonic() - self.started, 3), "status": value})
        return value

    async def check_entry(self, ident):
        info = await self.control.info(ident)
        for key, maximum in SESSION_LIMITS.items():
            require(number(info, key) <= maximum, key + " session bound exceeded")
        for key in ("relayWriterFlightBytes", "relayWriteInFlightMs", "upstreamWriteInFlightMs",
                    "attachmentGeneration", "attachmentWriterCompletions", "gapGeneration",
                    "gapAckGeneration", "droppedBytes", "droppedLines", "gapStartedAtMs",
                    "connectedAtMs", "bufferedBytes"):
            number(info, key)
        require(isinstance(info.get("deliveryAmbiguous"), bool), "missing delivery ambiguity diagnostic")
        return info

    async def dial(self, tls=False):
        self.serial += 1
        nick = "hp%d" % self.serial
        wire = await Wire.open()
        request = {"token": TOKEN, "host": "mock-irc", "port": 17669 if tls else 17668,
                   "tls": "implicit" if tls else "none", "sni": "mock-irc",
                   "tag": {"networkId": nick, "userId": "holder-pressure-owned", "name": nick}}
        await wire.send(("DIAL " + compact(request) + "\n").encode())
        while True:
            kind, result, _ = await wire.reply()
            if kind != "EVENT":
                break
        require(kind == "CONNECTED", "actual DIAL failed: " + compact(result))
        ident = result["id"]
        self.owned.append(ident)
        await wire.send(("NICK %s\r\nUSER %s 0 * :holder pressure\r\n" % (nick, nick)).encode())
        async def find():
            return self.fixture.by_nick.get(nick)
        peer = await until(find, lambda p: p is not None and p.users == 1)
        baseline = {"id": ident, "connectedAtMs": result["connectedAtMs"], "physical": peer.physical[:]}
        return wire, peer, baseline

    async def same(self, peer, base):
        info = await self.check_entry(base["id"])
        require(info["state"] == "open" and info["connectedAtMs"] == base["connectedAtMs"], "held socket identity/time changed")
        require(not peer.closed and peer.physical == base["physical"], "physical socket closed/replaced")
        require(peer.nicks == peer.users == 1 and peer.quits == 0 and peer.error is None, "extra registration/QUIT/wire corruption")
        return info

    async def attach(self, ident):
        wire = await Wire.open()
        try:
            kind, value, _ = await wire.request("ATTACH", {"token": TOKEN, "id": ident})
        except (EOFError, ConnectionError):
            wire.close()
            return wire, "EOF", {}
        if kind != "OK":
            wire.close()
        return wire, kind, value

    async def reattach(self, ident):
        async def attempt():
            return await self.attach(ident)
        wire, kind, value = await until(attempt, lambda row: row[1] == "OK", message="same-ID reattach never succeeded")
        return wire, value

    async def drain(self, wire, byte_count):
        digest, received, tail, lines = hashlib.sha256(), 0, b"", 0
        while received < byte_count:
            data = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(wire.sock, min(65536, byte_count - received)), 20)
            require(bool(data), "relay closed before admitted FIFO drained")
            received += len(data)
            digest.update(data)
            tail += data
            while b"\n" in tail:
                line, tail = tail.split(b"\n", 1)
                require(line.startswith(b":mock PRIVMSG #pressure :HP:"), "PING leaked or unexpected replay bytes")
                parts = line.split(b":HP:", 1)[1].split(b":", 1)
                require(int(parts[0]) == lines, "numbered relay FIFO violation")
                lines += 1
        require(not tail, "relay ended inside a raw line")
        return {"bytes": received, "sha256": digest.hexdigest(), "lines": lines}

    async def burst(self, peer, size, seed=0):
        digest, total, count = hashlib.sha256(), 0, 0
        while total < size:
            data = b":mock PRIVMSG #pressure :HP:%d:" % (seed + count) + b"z" * 4040 + b"\r\n"
            await peer.send(data)
            digest.update(data)
            total += len(data)
            count += 1
        return {"bytes": total, "sha256": digest.hexdigest(), "lines": count}

    async def case(self, name, fn):
        require(not any(row["state"] == "failed" for row in self.cases),
                "earlier pressure case failed; candidate is not qualified")
        before = time.monotonic()
        self.running.add(name)
        self.progress()
        timeout = 720 if name.startswith("detached_605_seconds_") else 600 if name == "aggregate_relay_meta_inventory" else 180
        try:
            detail = await asyncio.wait_for(fn(), timeout)
            self.cases.append({"name": name, "state": "passed", "seconds": round(time.monotonic() - before, 3), "evidence": detail})
        except Exception as exc:
            self.cases.append({"name": name, "state": "failed", "seconds": round(time.monotonic() - before, 3),
                               "reason": (type(exc).__name__ + ": " + str(exc))[:1000]})
            raise
        finally:
            self.running.discard(name)
            self.progress()
        await self.sample()

    async def delayed_meta_fifo(self, tls):
        wire, peer, base = await self.dial(tls)
        wire.close()
        await until(lambda: self.same(peer, base), lambda row: not row["attached"])
        sent = await self.burst(peer, 2 * MIB)
        await until(lambda: self.same(peer, base), lambda row: number(row, "bufferedBytes") == sent["bytes"])
        proxy = AckGate()
        await proxy.start()
        gate = await Control.open(proxy.path)
        pending = asyncio.create_task(gate.call("META", {"id": base["id"], "meta": {"strict": "current"}}))
        try:
            await asyncio.wait_for(proxy.received.wait(), 10)
            peer.ping_task = self.fixture.track(peer.ticker())
            wire, attached = await self.reattach(base["id"])
            require(number(attached, "bufferedBytes") == sent["bytes"], "ATTACH raw replay fence does not match admitted wire bytes")
            require(number(attached, "gapGeneration") == 0, "below-limit detach created a gap")
            await until(lambda: self.check_entry(base["id"]),
                        lambda row: number(row, "relayWriteInFlightMs") >= 750 and number(row, "relayWriterFlightBytes") > 0,
                        message="no positive stalled attachment write observation")
            await asyncio.sleep(5.2)
            require(not pending.done(), "META ACK gate did not hold consumer")
            got = await self.drain(wire, sent["bytes"])
            require(got == sent, "below-limit relay hash/FIFO mismatch")
            await until(lambda: self.same(peer, base), lambda row: number(row, "relayWriterFlightBytes") == 0)
            require(peer.pongs >= 2 and not peer.pending and peer.max_pong <= 5, "writable-upstream PONG deadline failed during blocked IPC/META gate")
            proxy.release.set()
            await pending
            return {"baseline": base, "sent": sent, "received": got, "peer": peer.summary(),
                    "stallMinimumMs": 750, "ackHeldUntilAfterDrain": True, "attachReplayBoundary": attached["bufferedBytes"]}
        finally:
            proxy.release.set()
            await asyncio.gather(pending, return_exceptions=True)
            gate.close()
            await proxy.stop()
            wire.close()
            if peer.ping_task:
                peer.ping_task.cancel()

    async def overflow(self, tls):
        wire, peer, base = await self.dial(tls)
        peer.ping_task = self.fixture.track(peer.ticker())
        try:
            await self.burst(peer, 8 * MIB)
            info = await until(lambda: self.same(peer, base), lambda row: number(row, "gapGeneration") > 0 and not row["attached"])
            require(number(info, "droppedBytes") > 0 and number(info, "droppedLines") > 0, "pressure did not expose explicit loss")
            wire.close()
            wire, attached = await self.reattach(base["id"])
            require(attached["id"] == base["id"], "reattach switched socket")
            boundary = number(attached, "bufferedBytes")
            # Only the positively admitted prefix is exact. Bytes whose IPC
            # delivery was partial are explicitly not compared as exactly-once.
            require(boundary <= 4 * MIB, "raw replay boundary exceeds session cap")
            require(isinstance(info.get("deliveryAmbiguous"), bool), "gap ambiguity unavailable")
            old = number(info, "gapGeneration")
            ack = await self.control.call("GAP_ACK", {"id": base["id"], "generation": old})
            require(number(ack, "gapAckGeneration") == old, "gap ACK not recorded")
            await self.burst(peer, 8 * MIB, seed=5000)
            newer = await until(lambda: self.same(peer, base), lambda row: number(row, "gapGeneration") > old)
            require(number(newer, "gapAckGeneration") < number(newer, "gapGeneration"), "old ACK covered later loss")
            await self.sample()
            return {"baseline": base, "pressure": info, "reattach": attached, "laterGap": newer,
                    "exactlyOnceClaim": False, "peer": peer.summary()}
        finally:
            wire.close()
            if peer.ping_task:
                peer.ping_task.cancel()

    async def partial_stale(self, tls):
        wire, peer, base = await self.dial(tls)
        try:
            await self.burst(peer, 2 * MIB)
            stalled = await until(lambda: self.same(peer, base), lambda row: number(row, "relayWriteInFlightMs") >= 750)
            one = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(wire.sock, 1), 5)
            require(len(one) == 1, "forced partial IPC read missing")
            wire.close()
            wire, attached = await self.reattach(base["id"])
            generation = number(await self.same(peer, base), "attachmentGeneration")
            await asyncio.sleep(1)
            final = await self.same(peer, base)
            require(final["attached"] and number(final, "attachmentGeneration") == generation,
                    "stale attachment completion detached successor")
            require(final.get("deliveryAmbiguous") is True and number(final, "gapGeneration") > 0,
                    "partial IPC delivery falsely reported exact")
            require(number(final, "attachmentWriterCompletions") > number(stalled, "attachmentWriterCompletions"),
                    "no old attachment completion observed")
            return {"baseline": base, "partialReadBytes": 1, "old": stalled, "new": final, "attach": attached}
        finally:
            wire.close()

    async def busy_outage(self, tls):
        wire, peer, base = await self.dial(tls)
        try:
            other, kind, error = await self.attach(base["id"])
            other.close()
            require(kind == "ERR" and error.get("code") == "busy", "concurrent attach did not refuse busy")
            # Remove a real Unix control proxy and close both real streams.
            # This creates observable EOF/unavailability, without changing the
            # holder listener/process or faking a client exception.
            proxy = AckGate()
            await proxy.start()
            outage = await Control.open(proxy.path)
            await proxy.stop()
            unavailable = False
            try:
                await outage.call("STATUS")
            except (EOFError, OSError):
                unavailable = True
            finally:
                outage.close()
            require(unavailable, "control proxy removal did not produce actual EOF/unavailability")
            peer.ping_task = self.fixture.track(peer.ticker())
            await asyncio.sleep(5.3)
            restored = await Control.open()
            require(restored.hello["instance"] == self.control.hello["instance"], "control reconnect changed incarnation")
            restored.close()
            require(peer.pongs >= 2 and peer.max_pong <= 5, "control outage blocked independent PONG")
            check = await self.same(peer, base)
            return {"baseline": base, "busy": error, "controlProxyOutageSeconds": 5.3, "observedControlEOF": unavailable,
                    "entry": check, "peer": peer.summary()}
        finally:
            wire.close()
            if peer.ping_task:
                peer.ping_task.cancel()

    async def oversized(self, tls):
        wire, peer, base = await self.dial(tls)
        try:
            # PING substring inside an oversized unterminated application line
            # must never create a PONG; discard continues through its delimiter.
            await peer.send(b"x" * 65536 + b"PING :not-a-server-ping" + b"x" * 65536)
            await asyncio.sleep(.5)
            await peer.send(b"\r\n")
            await peer.ping()
            dropped = await until(lambda: self.same(peer, base),
                                  lambda row: number(row, "droppedBytes") >= 65536 and not row["attached"])
            wire.close()
            wire, rebound = await self.reattach(base["id"])
            require(rebound["id"] == base["id"], "framing gap replaced the physical socket")
            expected = await self.burst(peer, 4096)
            got = await self.drain(wire, expected["bytes"])
            await asyncio.sleep(.2)
            require(expected == got and peer.pongs == 1 and not peer.pending and peer.error is None,
                    "oversized framing/PING substring/next delimiter isolation failed")
            return {"baseline": base, "framingGap": dropped, "rebind": rebound,
                    "entry": await self.same(peer, base), "digest": got, "peer": peer.summary()}
        finally:
            wire.close()

    async def command_pressure(self, tls):
        wire, peer, base = await self.dial(tls)
        try:
            peer.pause = True
            peer.resume.clear()
            await wire.send(b"WAKE\r\n")
            await asyncio.wait_for(peer.read_paused.wait(), 10)
            async def pump():
                for seq in range(8192):
                    await wire.send(("PRIVMSG #pressure :CMD:%d:" % seq).encode() + b"x" * 16000 + b"\r\n")
                raise AssertionError("ordinary pump accepted 128 MiB with upstream undrained")
            pumping = asyncio.create_task(pump())
            try:
                blocked = await until(lambda: self.same(peer, base),
                                      lambda row: number(row, "upstreamWriteInFlightMs") >= 750 and number(row, "outboundBytes") >= 16000,
                                      seconds=30, message="ordinary upstream write never physically stalled")
                require(not pumping.done(), "full ordinary storage failed to backpressure IPC pump")
                before = number(await self.sample(), "pongSaturations")
                # Upstream isn't writable: no impossible deadline claim. Reader
                # still consumes PING, charging the independent reserved lane.
                for _ in range(8):
                    await peer.ping()
                await asyncio.sleep(.5)
                reserved = await self.same(peer, base)
                require(number(reserved, "pongBytes") > 0, "urgent reserved storage not observed under ordinary saturation")
                require(number(await self.sample(), "pongSaturations") == before, "eight PINGs exhausted urgent reserve")
            finally:
                pumping.cancel()
                await asyncio.gather(pumping, return_exceptions=True)
                # Cancel may leave a last partial command in the Unix stream.
                # EOF is the real boundary that tells the pump to discard it.
                wire.close()
                peer.pause = False
                peer.resume.set()
            await until(lambda: self.same(peer, base), lambda row: number(row, "outboundBytes") < 16000 and not peer.pending, seconds=30)
            require(peer.error is None and peer.commands > 0, "single upstream writer interleaving/order failed")
            return {"baseline": base, "blocked": blocked, "reserved": reserved, "peer": peer.summary(),
                    "pongDeadlineClaimWhileUpstreamBlocked": False}
        finally:
            peer.pause = False
            peer.resume.set()
            wire.close()

    async def detached_long(self, tls):
        wire, peer, base = await self.dial(tls)
        wire.close()
        await until(lambda: self.same(peer, base), lambda row: not row["attached"])
        peer.ping_task = self.fixture.track(peer.ticker())
        began = time.monotonic()
        try:
            while time.monotonic() - began < 605:
                await asyncio.sleep(5)
                await self.same(peer, base)
                await self.sample()
                require(peer.max_pong <= 5 and len(peer.pending) <= 1, "detached PONG deadline failed")
            elapsed = time.monotonic() - began
            wire, attached = await self.reattach(base["id"])
            require(elapsed > 600 and peer.pongs >= 120, "old detach timeout not physically exceeded")
            await self.same(peer, base)
            return {"baseline": base, "elapsedWallSeconds": elapsed, "attach": attached, "peer": peer.summary()}
        finally:
            wire.close()
            peer.ping_task.cancel()

    async def aggregate_inventory_meta(self):
        sessions = []
        try:
            # 140 actual upstreams force multiple inventory pages; no fabricated
            # registry fixtures and no LIST/META-heavy heartbeat.
            for index in range(140):
                sessions.append(await self.dial(index % 2 == 1))
            kind, first, encoded = await self.control.raw("INVENTORY")
            require(kind == "OK", "inventory failed")
            through = number(first, "through")
            extra = await self.dial()
            sessions.append(extra)
            rows, pages, after = [], [], 0
            page = first
            while True:
                require(encoded <= 65536 and len(page["connections"]) <= 128, "inventory encoded/row cap exceeded")
                require(page["instance"] == self.control.hello["instance"] and page["through"] == through and page["after"] == after,
                        "inventory instance/high-water/cursor mismatch")
                for row in page["connections"]:
                    require(set(row) <= {"ordinal", "id", "state", "attached", "connectedAtMs", "bufferedBytes", "gapGeneration",
                                         "gapAckGeneration", "droppedBytes", "droppedLines", "gapStartedAtMs", "deliveryAmbiguous"},
                            "inventory leaked META or extra fields")
                    require(after < number(row, "ordinal") <= through, "inventory ordinal outside frozen scan")
                rows.extend(row["id"] for row in page["connections"])
                pages.append({"encodedBytes": encoded, "rows": len(page["connections"]), "after": page["after"], "nextAfter": page["nextAfter"]})
                if not page["more"]:
                    break
                next_after = number(page, "nextAfter")
                require(next_after > after, "inventory stalled cursor")
                after = next_after
                kind, page, encoded = await self.control.raw("INVENTORY", {"instance": first["instance"], "after": after, "through": through})
                require(kind == "OK", "inventory continuation failed")
            require(len(pages) >= 2 and len(rows) == len(set(rows)) and extra[2]["id"] not in rows, "inventory frozen-page coverage failed")
            kind, error, _ = await self.control.raw("INVENTORY", {"instance": "00000000-0000-0000-0000-000000000000", "after": 0, "through": through})
            require(kind == "ERR", "inventory accepted another instance")
            # Fill aggregate META with real encoded JSON, keeping only one
            # payload string in the fixture at a time. Failed replacement must
            # leave the previously ACKed strict marker intact.
            payload = "m" * (7 * MIB)
            accepted = rejected = 0
            rejection = None
            for wire, peer, base in sessions[:22]:
                await self.control.call("META", {"id": base["id"], "meta": {"strict": base["id"]}})
                kind, response, _ = await self.control.raw("META", {"id": base["id"], "meta": {"blob": payload}})
                if kind == "OK":
                    accepted += 1
                    if accepted == 1:
                        actual = await self.control.info(base["id"])
                        require(hashlib.sha256(actual["meta"]["blob"].encode()).digest() == hashlib.sha256(payload.encode()).digest(),
                                "accepted META ACK did not preserve actual payload")
                else:
                    rejected += 1
                    require(response.get("code") == "too_large", "aggregate META rejected for wrong reason")
                    info = await self.control.info(base["id"])
                    require(info["meta"] == {"strict": base["id"]}, "rejected aggregate META overwrote strict marker")
                    rejection = {"id": base["id"], "error": response}
                await self.sample()
            require(accepted >= 16 and rejected >= 1, "aggregate META cap not actually reached")
            target = sessions[-1][2]["id"]
            await self.control.call("META", {"id": target, "meta": {"strict": "preserved"}})
            kind, error, _ = await self.control.raw("META", {"id": target, "meta": {"blob": "e" * (8 * MIB)}})
            require(kind == "ERR" and error.get("code") == "too_large", "entry META cap not enforced")
            require((await self.control.info(target))["meta"] == {"strict": "preserved"}, "oversized META destroyed accepted value")
            # Prove replacement releases the aggregate owner before testing a
            # different lane; do not repeatedly deserialize 7 MiB INFO trees.
            meta_peak = await self.sample()
            for _, _, base in sessions[:22]:
                await self.control.call("META", {"id": base["id"], "meta": {}})
            cleared = await self.sample()
            require(number(cleared, "metaBytes") < number(meta_peak, "metaBytes") - 100 * MIB,
                    "META replacement retained old aggregate ownership")
            # Populate >64 MiB aggregate relay through many individually bounded
            # sessions; totals are checked during admission, never from RSS.
            before = number(await self.sample(), "relaySaturations")
            for wire, peer, base in sessions[:40]:
                await self.burst(peer, 2 * MIB)
                await self.same(peer, base)
                await self.sample()
            state = await self.sample()
            require(number(state, "relaySaturations") > before and number(state, "droppedBytes") > 0,
                    "aggregate relay budget never actually saturated")
            gaps = 0
            for wire, peer, base in sessions[:40]:
                info = await self.same(peer, base)
                gaps += number(info, "gapGeneration") > 0
            require(gaps > 0, "aggregate overflow lacked explicit gaps")
            return {"sessions": len(sessions), "inventoryPages": pages, "inventoryFrozenThrough": through,
                    "inventoryRows": len(rows), "metaAccepted": accepted, "metaRejected": rejected,
                    "metaRejection": rejection, "metaPeak": meta_peak, "aggregate": state, "gapSessions": gaps}
        finally:
            for wire, peer, base in sessions:
                wire.close()
                with contextlib.suppress(Exception):
                    await self.control.call("CLOSE", {"id": base["id"]})

    async def terminal_race(self, tls):
        baselines = []
        for _ in range(8):
            wire, peer, base = await self.dial(tls)
            baselines.append(base)
            await self.control.call("META", {"id": base["id"], "meta": {"blob": "t" * 32768}})
            send = asyncio.create_task(self.burst(peer, 2 * MIB))
            write = asyncio.create_task(wire.send(b"PRIVMSG #pressure :CMD:0:" + b"x" * 32000 + b"\r\n"))
            await asyncio.sleep(.02)
            await self.control.call("CLOSE", {"id": base["id"]})
            wire.close()
            await asyncio.gather(send, write, return_exceptions=True)
            final = None
            async def terminal_state():
                nonlocal final
                final = await self.control.info(base["id"])
                return final
            try:
                final = await until(terminal_state,
                                    lambda row: row["state"] == "closed" and row.get("upstreamWriterDone") is True
                                    and row.get("tlsFinalized") is True
                                    and all(number(row, key) == 0 for key in SESSION_LIMITS)
                                    and number(row, "relayWriterFlightBytes") == 0, seconds=30,
                                    message="terminal I/O owners did not finalize TLS and release reservations")
            finally:
                self.terminal_diagnostics.append({
                    "tls": tls, "iteration": len(baselines), "id": base["id"],
                    "entry": {key: final.get(key) for key in (
                        "state", "upstreamWriterDone", "tlsFinalized", "closeReason",
                        "relayBytes", "outboundBytes", "pongBytes", "relayWriterFlightBytes",
                        "relayWriteInFlightMs", "upstreamWriteInFlightMs",
                        "attachmentGeneration", "attachmentWriterCompletions")} if final else None,
                    "status": await self.control.status()})
            for key in SESSION_LIMITS:
                require(number(final, key) == 0, "terminal close retained " + key)
            require(final.get("meta") in (None, {}), "terminal close retained META")
            await self.sample()
        return {"iterations": len(baselines), "tls": tls, "baselines": baselines,
                "final": final, "holderInstance": self.control.hello["instance"]}

    async def run(self):
        await self.fixture.start()
        self.control = await Control.open()
        initial = await self.sample()
        self.initial = initial
        # Long wall-clock cases overlap other independent physical checks, but
        # no case's required duration/coverage is skipped or shortened.
        long_cases = [asyncio.create_task(self.case("detached_605_seconds_" + name,
                      lambda tls=tls: self.detached_long(tls))) for name, tls in (("tcp", False), ("tls", True))]
        try:
            for name, tls in (("tcp", False), ("tls", True)):
                for label, fn in (("meta_ack_stalled_fifo", self.delayed_meta_fifo),
                                  ("session_overflow_gap_rebind", self.overflow),
                                  ("partial_ipc_stale_completion", self.partial_stale),
                                  ("control_outage_busy", self.busy_outage),
                                  ("oversized_line_framing", self.oversized),
                                  ("ordinary_backpressure_urgent_reserve", self.command_pressure),
                                  ("terminal_close_tls_handshake", self.terminal_race)):
                    await self.case(label + "_" + name, lambda fn=fn, tls=tls: fn(tls))
            await self.case("aggregate_relay_meta_inventory", self.aggregate_inventory_meta)
            await asyncio.gather(*long_cases)
            final = await self.sample()
            require(len(self.fixture.peers) == self.serial, "unexpected extra physical upstream accepted")
            result = {"state": "passed" if all(row["state"] == "passed" for row in self.cases) else "failed",
                      "version": 1, "holderInstance": self.control.hello["instance"], "holderPid": initial["pid"],
                      "seconds": time.monotonic() - self.started, "cases": self.cases,
                      "initial": initial, "final": final, "samples": self.counters,
                      "memoryTarget512MiBIsNotAcceptance": True,
                      "coverageLimits": ["No cross-process TCP migration claim", "No exactly-once claim for ambiguous partial IPC writes",
                                         "No PONG deadline claim while the upstream TCP/TLS writer is itself blocked"]}
            return result
        finally:
            for task in long_cases:
                if not task.done():
                    task.cancel()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(asyncio.gather(*long_cases, return_exceptions=True), 5)
            for ident in self.owned:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(self.control.call("CLOSE", {"id": ident}), 3)
            self.control.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.fixture.stop(), 5)


def host():
    context = os.environ.get("DOCKER_CONTEXT", "")
    run = os.environ.get("ROUTING_REGRESSION_RUN", "")
    project = os.environ.get("COMPOSE_PROJECT_NAME", "")
    require(os.environ.get("ROUTING_REGRESSION_READY") == "1" and run.startswith("regression-") and project == run,
            "must run in the existing owned routing fixture")
    require(context and not os.environ.get("DOCKER_HOST"), "explicit owned local Docker context required")
    evidence = Path(os.environ.get("HOLDER_PRESSURE_EVIDENCE_DIR", "/tmp/" + run + "-holder-pressure"))
    require(not evidence.exists(), "evidence directory already exists")
    evidence.mkdir(mode=0o700, parents=False)
    docker = ["docker", "--context", context]

    def invoke(args, maximum=2 * MIB, timeout=30):
        # Disk-bounded inspection output; no unbounded communicate() capture.
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(docker + args, stdout=output, stderr=output)
            began = time.monotonic()
            while process.poll() is None:
                if output.tell() > maximum or time.monotonic() - began > timeout:
                    process.kill()
                    process.wait()
                    raise AssertionError("bounded Docker command output/deadline exceeded")
                time.sleep(.05)
            output.seek(0)
            data = output.read(maximum + 1)
            require(len(data) <= maximum, "Docker output exceeded cap")
            require(process.returncode == 0, "owned Docker command failed: " + data[:512].decode(errors="replace"))
            return data

    def inspect(service):
        ids = invoke(["ps", "-aq", "--filter", "label=com.docker.compose.project=" + project,
                      "--filter", "label=com.docker.compose.service=" + service]).decode().split()
        require(len(ids) == 1, "expected one owned " + service)
        # Only IDs selected by both project/service labels are inspected.
        obj = json.loads(invoke(["inspect", ids[0]], maximum=MIB))[0]
        labels = obj["Config"]["Labels"]
        require(labels.get("ircfiber.fixture.run") == run and labels.get("com.docker.compose.project") == project
                and labels.get("com.docker.compose.service") == service, "foreign Docker object refused")
        return {"id": obj["Id"], "image": obj["Image"], "pid": obj["State"]["Pid"],
                "startedAt": obj["State"]["StartedAt"], "restarts": obj["RestartCount"],
                "running": obj["State"]["Running"]}

    def owned(service, args, **kwargs):
        current = inspect(service)
        require(current == baseline[service], "fixture container generation/state changed: " + service)
        return invoke([args[0], current["id"]] + args[1:], **kwargs)

    baseline = {name: inspect(name) for name in ("mock-irc", "ircfiber-holder")}
    manifest = {"version": 1, "run": run, "project": project, "context": context,
                "containers": baseline, "sessionLimits": SESSION_LIMITS, "aggregateLimits": LIMITS,
                "detachedWallSecondsMinimum": 605, "productionTouched": False}
    (evidence / "manifest.json").write_text(compact(manifest) + "\n")
    result = None
    try:
        # The script is already installed in the owned mock image. Docker exec
        # options precede the container; no lifecycle action is issued.
        current = inspect("mock-irc")
        require(current == baseline["mock-irc"], "mock generation changed")
        output = invoke(["exec", "-e", "HOLDER_PRESSURE_SOCKET=" + SOCKET,
                         "-e", "HOLDER_PRESSURE_SERVER_ID=" + SERVER_ID,
                         current["id"], "python3", "/fixture/holder_pressure.py", "inside"],
                        maximum=2 * MIB, timeout=2400)
        result = json.loads(output)
        (evidence / "result.json").write_text(compact(result) + "\n")
        # Independent cgroup and /proc observations belong to the exact holder
        # process ID returned by its real STATUS, not an assumed container PID.
        pid = number(result, "holderPid")
        require(int(pid) == pid and pid > 0, "invalid holder diagnostic PID")
        status = owned("ircfiber-holder", ["exec", "cat", "/proc/%d/status" % pid]).decode()
        cgroup = owned("ircfiber-holder", ["exec", "cat", "/proc/%d/cgroup" % pid]).decode()
        require("0::" in cgroup, "cgroup v2 membership missing")
        memory = {}
        mountinfo = owned("ircfiber-holder", ["exec", "cat", "/proc/%d/mountinfo" % pid]).decode()
        membership = next(line.split(":", 2)[2] for line in cgroup.splitlines() if line.startswith("0::"))
        root = None
        for line in mountinfo.splitlines():
            left, right = line.split(" - ", 1)
            if right.split()[0] == "cgroup2":
                fields = left.split()
                mounted_root, mountpoint = fields[3:5]
                if membership == mounted_root or membership.startswith(mounted_root.rstrip("/") + "/"):
                    suffix = membership[len(mounted_root):].lstrip("/")
                    root = mountpoint.rstrip("/") + ("/" + suffix if suffix else "")
                    break
        require(root is not None, "holder cgroup membership/mount could not be resolved")
        for field in ("memory.current", "memory.swap.current", "memory.max", "memory.events", "memory.stat"):
            memory[field] = owned("ircfiber-holder", ["exec", "cat", root + "/" + field]).decode()
        require(memory["memory.current"].strip().isdigit() and memory["memory.swap.current"].strip().isdigit(),
                "missing numeric cgroup resident/swap samples")
        proc = {}
        for key in ("VmRSS", "VmHWM", "VmSwap", "Threads"):
            match = re.search(r"^" + key + r":\s+(\d+)", status, re.M)
            require(match is not None, "missing /proc numeric " + key)
            proc[key] = int(match[1])
        logs = owned("ircfiber-holder", ["logs", "--tail", "180"], maximum=2 * MIB).decode()
        runtime = []
        for line in logs.splitlines():
            with contextlib.suppress(ValueError):
                row = json.loads(line)
                if row.get("event") == "memory_sample" or (isinstance(row.get("fields"), dict) and row["fields"].get("event") == "memory_sample"):
                    runtime.append(row)
        require(runtime, "actual holder runtime GC diagnostic not observed")
        latest = runtime[-1].get("fields", runtime[-1])
        for key in ("gcUsedBytes", "gcFreeBytes", "gcCollections", "rssBytes", "swapBytes", "cgroupBytes", "cgroupSwapBytes"):
            number(latest, key)
        require(isinstance(latest.get("holderOwners"), dict), "holder allocation-owner diagnostic missing")
        # Keep diagnostics numeric-only; no container environments, IRC payload,
        # certificates or META contents enter retained evidence.
        result["physicalMemory"] = {"proc": proc, "cgroupMembership": cgroup, "cgroup": memory,
                                     "runtime": runtime[-3:]}
        result["finalizerErrors"] = []
        for line in logs.splitlines():
            with contextlib.suppress(ValueError):
                row = json.loads(line)
                if row.get("event") == "holder_tls_finalize_failed":
                    result["finalizerErrors"].append({key: row.get(key) for key in
                        ("event", "exceptionType", "reason", "ts")})
        result["finalizerErrors"] = result["finalizerErrors"][-8:]
        result["containersUnchanged"] = {name: inspect(name) == before for name, before in baseline.items()}
        require(all(result["containersUnchanged"].values()), "physical holder/mock process identity changed")
        (evidence / "result.json").write_text(compact(result) + "\n")
        print(str(evidence))
        require(result["state"] == "passed", "holder pressure qualification failed; see bounded result.json")
    except Exception as exc:
        if result is None:
            result = {"state": "failed"}
        result["state"] = "failed"
        result["hostError"] = str(exc)[:2000]
        with contextlib.suppress(Exception):
            progress = owned("mock-irc", ["exec", "cat", "/tmp/holder-pressure-progress.json"],
                             maximum=32768, timeout=10)
            (evidence / "partial-cases.json").write_bytes(progress)
        (evidence / "result.json").write_text(compact(result) + "\n")
        raise


if __name__ == "__main__":
    if sys.argv[1:] == ["host"]:
        host()
    elif sys.argv[1:] == ["inside"]:
        suite = Suite()
        try:
            result = asyncio.run(suite.run())
        except Exception as exc:
            result = {"state": "failed", "reason": type(exc).__name__ + ": " + str(exc)[:2000],
                      "trace": traceback.format_exc()[-4000:], "cases": suite.cases,
                      "samples": suite.counters, "initial": suite.initial,
                      "holderPid": suite.initial.get("pid") if suite.initial else None,
                      "terminalDiagnostics": suite.terminal_diagnostics}
        print(compact(result))
    else:
        raise SystemExit("expected host or inside (use holder_pressure.sh)")
