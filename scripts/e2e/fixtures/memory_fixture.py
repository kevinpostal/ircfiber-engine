#!/usr/bin/env python3
"""Owned Rollout-A wire oracle, TLS endpoint and transparent META-ACK gate.

No production protocol additions. The proxy delays a real holder acknowledgment,
never fabricates one; relay streams continue independently. Oracle digests cover
all numbered messages in order, while storage stays O(sessions), not O(traffic).
"""
import asyncio
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.request

LIMIT = 512
LINE_LIMIT = 64 * 1024 * 1024
CHANNELS = [f"#memory{i}" for i in range(10)]
MEMBERS = [f"m{i:03x}" for i in range(2000)]
# Include the in-flight command in both limits; rosters are built only by its
# single worker. The byte budget covers encoded descriptor fields, not replies.
RESPONSE_REQUEST_LIMIT = 128
RESPONSE_BYTE_LIMIT = 128 * 1024
PING_TRACE_LIMIT = 2  # Keep aggregate 512-session status inside the 1-MiB RPC envelope.
CERTS = Path("/fixture-certs")


def certificates():
    CERTS.mkdir(exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-days", "2", "-subj", "/CN=mock-irc", "-addext",
                    "subjectAltName=DNS:mock-irc,DNS:default.regression.test",
                    "-keyout", str(CERTS / "key.pem"), "-out",
                    str(CERTS / "ca-certificates.crt")], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


async def resp(reader):
    line = await reader.readline()
    if not line:
        raise EOFError("Redis subscriber disconnected")
    kind, data = line[:1], line[1:-2]
    if kind == b"*":
        return [await resp(reader) for _ in range(int(data))]
    if kind == b"$":
        size = int(data)
        if size < 0:
            return None
        if size > 1024 * 1024:
            raise ValueError("oversized Redis event")
        return (await reader.readexactly(size + 2))[:-2]
    if kind == b"-":
        raise ValueError(data.decode())
    return data


def encode(*args):
    args = [str(x).encode() for x in args]
    return b"*%d\r\n" % len(args) + b"".join(b"$%d\r\n" % len(x) + x + b"\r\n" for x in args)


class Session:
    def __init__(self, fixture, physical, reader, writer, tls):
        self.fixture, self.physical = fixture, physical
        self.reader, self.writer, self.tls = reader, writer, tls
        self.nick = None
        self.user = False
        self.welcomed = False
        self.closed = False
        self.nicks = self.users = self.quits = 0
        self.channels = set()
        self.who_sent = False
        self.send_lock = asyncio.Lock()
        self.sent = self.received = self.churn = 0
        self.sent_hash, self.received_hash = hashlib.sha256(), hashlib.sha256()
        self.pending_ping = None
        self.pings = self.pongs = 0
        self.max_pong_seconds = 0.0
        self.ping_trace = deque(maxlen=PING_TRACE_LIMIT)
        self.pending_ping_trace = None
        self.responses = asyncio.Queue(maxsize=RESPONSE_REQUEST_LIMIT)
        self.response_task = None
        self.response_active = None
        self.response_requests = self.response_bytes = 0
        self.response_max_requests = self.response_max_bytes = 0
        self.response_enqueued = self.response_completed = 0
        self.response_cancelled = self.response_failed = self.response_rejected = 0
        self.response_overflow = False
        self.response_worker_starts = 0

    async def send(self, lines, ping=None):
        data = ("\r\n".join(lines) + "\r\n").encode()
        async with self.send_lock:
            self.writer.write(data)
            if ping is not None:
                ping["writtenMono"] = time.monotonic()
            await asyncio.wait_for(self.writer.drain(), 5)
            if ping is not None:
                ping["flushedMono"] = time.monotonic()

    async def send_ping(self, token):
        requested = time.monotonic()
        trace = dict(token=token, requestedMono=requested, writtenMono=None,
                     flushedMono=None, pongReadMono=None,
                     responseRequests=self.response_requests,
                     responseBytes=self.response_bytes)
        self.pending_ping = (token, requested)
        self.pending_ping_trace = trace
        self.ping_trace.append(trace)
        self.pings += 1
        try:
            await self.send(["PING :" + token], ping=trace)
        except BaseException as error:
            trace["sendError"] = type(error).__name__
            raise

    def observe_pong(self, token, read_at):
        if self.pending_ping is None or token != self.pending_ping[0]:
            self.fixture.error("duplicate/unexpected PONG: " + str(self.nick))
            return
        trace = self.pending_ping_trace
        trace["pongReadMono"] = read_at
        trace["responseRequestsAtPong"] = self.response_requests
        trace["responseBytesAtPong"] = self.response_bytes
        elapsed = read_at - self.pending_ping[1]
        self.max_pong_seconds = max(self.max_pong_seconds, elapsed)
        if elapsed > 5:
            self.fixture.error("PONG exceeded five seconds: " + str(self.nick))
        self.pongs += 1
        self.pending_ping = None
        self.pending_ping_trace = None

    def queue_response(self, command, argument=""):
        # Capture the nick at command admission: later NICK input must not
        # rewrite replies already waiting behind a blocked writer.
        nick = str(self.nick)
        size = sum(len(value.encode()) for value in (command, argument, nick))
        if (self.response_requests >= RESPONSE_REQUEST_LIMIT or
                self.response_bytes + size > RESPONSE_BYTE_LIMIT or
                self.response_task.done()):
            self.response_rejected += 1
            if not self.response_overflow:
                self.response_overflow = True
                self.fixture.error("response queue overflow/unavailable: " + str(self.nick))
            return
        self.responses.put_nowait((command, argument, nick, size))
        self.response_requests += 1
        self.response_bytes += size
        self.response_enqueued += 1
        self.response_max_requests = max(self.response_max_requests, self.response_requests)
        self.response_max_bytes = max(self.response_max_bytes, self.response_bytes)

    async def respond(self, command, argument, nick):
        if command == "CAP":
            await self.send(["CAP * LS :"])
        elif command == "PING":
            await self.send(["PONG :" + argument])
        elif command in ("JOIN", "NAMES"):
            for channel in argument.lstrip(":").split(","):
                if channel in CHANNELS:
                    await self.names(channel, nick)
                elif command == "JOIN":
                    self.channels.add(channel)
                    await self.send([f":{nick}!u@mock JOIN {channel}",
                                     f":mock.irc 353 {nick} = {channel} :{nick}",
                                     f":mock.irc 366 {nick} {channel} :End of NAMES"])
        elif command == "WHO":
            if not self.who_sent:
                self.who_sent = True
                for start in range(0, 2000, 25):
                    await self.send([f":mock.irc 352 {nick} {argument} ident mock mock.irc {member} H :0 Stable"
                                     for member in MEMBERS[start:start + 25]])
            await self.send([f":mock.irc 315 {nick} {argument} :End of WHO"])
        elif command == "MODE":
            await self.send([f":mock.irc 324 {nick} {argument} +nt"])
        elif command == "WELCOME":
            await self.send([f":mock.irc 001 {nick} :Welcome {nick}!u@mock",
                             f":mock.irc 005 {nick} CASEMAPPING=rfc1459 CHANTYPES=# :supported",
                             f":mock.irc 376 {nick} :End of MOTD"])

    async def response_worker(self):
        self.response_worker_starts += 1
        try:
            while True:
                command, argument, nick, size = await self.responses.get()
                self.response_active = command
                try:
                    await self.respond(command, argument, nick)
                    self.response_completed += 1
                except asyncio.CancelledError:
                    self.response_cancelled += 1
                    raise
                except Exception:
                    self.response_failed += 1
                    raise
                finally:
                    self.response_active = None
                    self.response_requests -= 1
                    self.response_bytes -= size
                    # Release descriptor references with their reservation,
                    # including while the worker waits for its next request.
                    command = argument = nick = None
        except Exception as error:
            self.fixture.error(f"upstream responder {self.nick}: {type(error).__name__}: {error}")
            self.writer.close()

    async def names(self, channel, nick):
        if channel not in self.channels:
            await self.send([f":{nick}!u@mock JOIN {channel}"])
        self.channels.add(channel)
        roster = [nick] + MEMBERS
        for offset in range(0, len(roster), 35):
            await self.send([f":mock.irc 353 {nick} = {channel} :" + " ".join(roster[offset:offset + 35])])
        await self.send([f":mock.irc 366 {nick} {channel} :End of NAMES"])

    async def numbered(self, churn=False):
        self.sent += 1
        token = f"MR:{self.nick}:{self.sent}:" + hashlib.sha256(f"{self.nick}/{self.sent}".encode()).hexdigest()
        self.sent_hash.update((token + "\n").encode())
        lines = [f":m000!u@mock PRIVMSG #memory0 :{token}"]
        if churn:
            self.churn += 1
            nick = f"churn{self.churn}"
            lines += [f":{nick}!ident@mock JOIN #memory0",
                      f":mock.irc 352 {self.nick} #memory0 ident mock mock.irc {nick} H :0 Real {self.churn}",
                      f":{nick}!ident@mock QUIT :completed churn"]
        await self.send(lines)

    async def run(self):
        self.response_task = asyncio.create_task(self.response_worker())
        try:
            while line := await self.reader.readline():
                read_at = time.monotonic()
                if len(line) > 65536:
                    raise ValueError("oversized engine command")
                text = line.decode().strip("\r\n")
                parts = text.split()
                if not parts:
                    continue
                command = parts[0].upper()
                if command == "CAP" and len(parts) > 1 and parts[1].upper() == "LS":
                    self.queue_response("CAP")
                elif command == "NICK":
                    self.nicks += 1
                    self.nick = parts[1].lstrip(":")
                    if self.nick in self.fixture.by_nick and self.fixture.by_nick[self.nick] is not self:
                        self.fixture.error("duplicate physical registration: " + self.nick)
                    self.fixture.by_nick[self.nick] = self
                elif command == "USER":
                    self.users += 1
                    self.user = True
                elif command == "QUIT":
                    self.quits += 1
                    self.fixture.error("upstream QUIT: " + str(self.nick))
                elif command == "PING":
                    self.queue_response("PING", text.split(":", 1)[-1])
                elif command == "PONG":
                    # No response production, lock acquisition or drain can
                    # delay timestamping an engine command already readable.
                    self.observe_pong(parts[-1].lstrip(":"), read_at)
                elif command in ("JOIN", "NAMES", "WHO") and len(parts) > 1:
                    self.queue_response(command, parts[1])
                elif command == "MODE" and len(parts) > 1 and parts[1].startswith("#"):
                    self.queue_response(command, parts[1])
                if self.nick and self.user and not self.welcomed:
                    self.welcomed = True
                    self.queue_response("WELCOME")
        except Exception as error:
            self.fixture.error(f"upstream reader {self.nick}: {type(error).__name__}: {error}")
        finally:
            self.closed = True
            self.response_task.cancel()
            await asyncio.gather(self.response_task, return_exceptions=True)
            while not self.responses.empty():
                _, _, _, size = self.responses.get_nowait()
                self.response_requests -= 1
                self.response_bytes -= size
                self.response_cancelled += 1
            self.writer.close()
            self.fixture.error("physical socket closed: " + str(self.nick))

    def summary(self):
        return dict(nick=self.nick, physical=self.physical, tls=self.tls, closed=self.closed,
                    nickCommands=self.nicks, userCommands=self.users, quitCommands=self.quits,
                    welcomed=self.welcomed, channels=sorted(self.channels), sent=self.sent,
                    received=self.received, sentHash=self.sent_hash.hexdigest(),
                    receivedHash=self.received_hash.hexdigest(), churn=self.churn,
                    pings=self.pings, pongs=self.pongs, maxPongSeconds=self.max_pong_seconds,
                    pingTrace=list(self.ping_trace),
                    responseQueueRequests=self.responses.qsize(),
                    responseRequests=self.response_requests, responseBytes=self.response_bytes,
                    responseMaxRequests=self.response_max_requests,
                    responseMaxBytes=self.response_max_bytes,
                    responseRequestLimit=RESPONSE_REQUEST_LIMIT,
                    responseByteLimit=RESPONSE_BYTE_LIMIT,
                    responseEnqueued=self.response_enqueued,
                    responseCompleted=self.response_completed,
                    responseCancelled=self.response_cancelled,
                    responseFailed=self.response_failed,
                    responseRejected=self.response_rejected,
                    responseOverflow=self.response_overflow,
                    responseWorkerStarts=self.response_worker_starts,
                    responseWorkerRunning=self.response_task is not None and not self.response_task.done(),
                    responseWorkerCommand=self.response_active)


class Fixture:
    def __init__(self):
        self.sessions = []
        self.accepted_physical = []
        self.by_nick = {}
        self.networks = {}
        self.errors = []
        self.error_count = 0
        self.subscribed = False
        self.loading = False
        self.pinging = False
        self.meta_delay = 0
        self.meta_delay_count = 0
        self.meta_delayed = 0
        self.meta_waiting = 0
        self.meta_max_waiting = 0
        self.meta_requests = 0
        self.list_requests = 0
        self.tasks = set()
        self.started = time.time()

    def error(self, message):
        self.error_count += 1
        if len(self.errors) < 32:
            self.errors.append(str(message)[:300])

    def task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def finished(result):
            self.tasks.discard(result)
            if not result.cancelled() and result.exception():
                self.error(str(result.exception()))
        task.add_done_callback(finished)

    async def accept(self, listener, tls):
        loop = asyncio.get_running_loop()
        context = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(CERTS / "ca-certificates.crt", CERTS / "key.pem")
        while True:
            raw, addr = await loop.sock_accept(listener)
            # Capture the physical TCP identity BEFORE OpenSSL owns/wraps the FD.
            physical = [addr[1], os.fstat(raw.fileno()).st_ino]
            if len(self.accepted_physical) >= LIMIT:
                self.error("physical socket bound exceeded")
                raw.close()
                continue
            self.accepted_physical.append(physical)
            self.task(self.accepted(raw, physical, context, tls))

    async def accepted(self, raw, physical, context, tls):
        reader = asyncio.StreamReader(limit=65536)
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await asyncio.get_running_loop().connect_accepted_socket(
            lambda: protocol, raw, ssl=context, ssl_handshake_timeout=10 if context else None)
        writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_running_loop())
        session = Session(self, physical, reader, writer, tls)
        self.sessions.append(session)
        await session.run()

    async def subscriber(self):
        reader, writer = await asyncio.open_connection("192.0.2.2", 6379)
        writer.write(encode("PSUBSCRIBE", "irc:events:*"))
        await writer.drain()
        response = await resp(reader)
        if response[0] != b"psubscribe":
            raise ValueError("Redis subscription not acknowledged")
        self.subscribed = True
        try:
            while True:
                message = await resp(reader)
                if message[0] != b"pmessage":
                    continue
                event = json.loads(message[3])
                token = event.get("x", "")
                if event.get("c") != "PRIVMSG" or not token.startswith("MR:"):
                    continue
                _, nick, serial, _ = token.split(":")
                session = self.by_nick.get(nick)
                if session is None or self.networks.get(event.get("nid")) != nick:
                    self.error("oracle event has unexpected network/nick")
                    continue
                if int(serial) != session.received + 1:
                    self.error(f"oracle sequence {nick}: expected {session.received + 1}, received {serial}")
                session.received += 1
                session.received_hash.update((token + "\n").encode())
        finally:
            self.subscribed = False
            writer.close()

    async def traffic(self):
        index = 0
        next_at = time.monotonic()
        while True:
            if not self.loading:
                next_at = time.monotonic()
                await asyncio.sleep(0.05)
                continue
            sessions = [s for s in self.sessions if s.nick in self.networks.values() and not s.closed]
            if not sessions:
                raise ValueError("load has no live sessions")
            session = sessions[index % len(sessions)]
            index += 1
            await session.numbered(churn=True)
            next_at += 0.01  # 100 actual numbered messages/second aggregate.
            await asyncio.sleep(max(0, next_at - time.monotonic()))
            if time.monotonic() - next_at > 5:
                raise ValueError("fixture could not sustain 100 messages/second")

    async def pings(self):
        serial = 0
        while True:
            await asyncio.sleep(5)
            if not self.pinging:
                continue
            serial += 1
            for session in self.sessions:
                if not session.welcomed or session.closed:
                    continue
                if session.pending_ping:
                    self.error("missing PONG at next five-second interval: " + session.nick)
                    continue
                token = f"memory-ping-{serial}-{session.nick}"
                await session.send_ping(token)

    async def tunnel(self, source, destination):
        while data := await source.read(65536):
            destination.write(data)
            await destination.drain()

    async def proxy(self, reader, writer):
        upstream = None
        try:
            upstream_reader, upstream = await asyncio.open_unix_connection("/run/ircfiber/holder.sock", limit=LINE_LIMIT)
            first = await reader.readline()
            upstream.write(first)
            await upstream.drain()
            if not first.startswith(b"HELLO "):
                # DIAL/ATTACH relay bytes are never paused by the META gate.
                tasks = [asyncio.create_task(self.tunnel(reader, upstream)),
                         asyncio.create_task(self.tunnel(upstream_reader, writer))]
                try:
                    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                return
            writer.write(await upstream_reader.readline())
            await writer.drain()
            while command := await reader.readline():
                meta = command.startswith(b"META ")
                if meta:
                    self.meta_requests += 1
                if command.startswith(b"LIST"):
                    self.list_requests += 1
                upstream.write(command)
                await upstream.drain()
                # Release the request tree before waiting on its real ACK.
                command = None
                reply = await upstream_reader.readline()
                if not reply:
                    return
                if meta and self.meta_delay_count:
                    self.meta_delay_count -= 1
                    self.meta_delayed += 1
                    self.meta_waiting += 1
                    self.meta_max_waiting = max(self.meta_max_waiting, self.meta_waiting)
                    try:
                        await asyncio.sleep(self.meta_delay)
                    finally:
                        self.meta_waiting -= 1
                writer.write(reply)
                await writer.drain()
        except (ConnectionError, BrokenPipeError, asyncio.IncompleteReadError):
            pass  # Expected at engine-only shutdown; upstream sockets are separate.
        finally:
            writer.close()
            if upstream:
                upstream.close()

    async def holder(self, verb):
        reader, writer = await asyncio.open_unix_connection("/run/ircfiber/holder.sock", limit=LINE_LIMIT)
        try:
            writer.write(b'HELLO {"proto":1,"serverId":"fixture-regression","engine":"memory-observer"}\n')
            await writer.drain()
            if not (await reader.readline()).startswith(b"OK "):
                raise ValueError("observer HELLO rejected")
            writer.write(verb.encode() + b"\n")
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), 30)
            if not line.startswith(b"OK "):
                raise ValueError("holder observation rejected")
            result = json.loads(line[3:])
            if verb == "LIST":
                return [dict(id=e["id"], networkId=e.get("tag", {}).get("networkId"),
                             state=e["state"], connectedAtMs=e["connectedAtMs"],
                             attached=e.get("attached"), bufferedBytes=e.get("bufferedBytes"))
                        for e in result["connections"]]
            return result
        finally:
            writer.close()

    async def control(self, command):
        action = command["action"]
        if action == "configure":
            networks = command["networks"]
            if not 250 <= len(networks) <= LIMIT or len(set(networks.values())) != len(networks):
                raise ValueError("require 250..512 unique network/nick identities")
            self.networks = networks
        elif action == "load":
            self.loading = bool(command["enabled"])
            self.pinging = True
        elif action == "delayMeta":
            self.meta_delay = min(4, max(0, float(command["seconds"])))
            self.meta_delay_count = min(12, max(0, int(command["count"])))
        elif action == "burst":
            if self.loading:
                raise ValueError("pause steady traffic before serialized numbered burst")
            targets = [s for s in self.sessions if s.nick == command["nick"]]
            if len(targets) != 1:
                raise ValueError("burst target must be unique")
            for _ in range(5000):
                await targets[0].numbered()
        elif action == "probe":
            was_pinging, self.pinging = self.pinging, False
            try:
                deadline = time.monotonic() + 5
                while any(s.pending_ping for s in self.sessions):
                    if time.monotonic() >= deadline:
                        raise ValueError("previous PONG did not complete before detached probe")
                    await asyncio.sleep(0.01)
                for session in self.sessions:
                    token = f"memory-probe-{session.pings + 1}-{session.nick}"
                    await session.send_ping(token)
                deadline = time.monotonic() + 5
                while any(s.pending_ping for s in self.sessions):
                    if time.monotonic() >= deadline:
                        raise ValueError("detached per-socket PONG probe timed out")
                    await asyncio.sleep(0.01)
            finally:
                self.pinging = was_pinging
        elif action == "held":
            return await self.holder("LIST")
        elif action == "holderStatus":
            return await self.holder("STATUS")
        elif action != "status":
            raise ValueError("unknown control action")
        return dict(startedAt=self.started, subscribed=self.subscribed, loading=self.loading,
                    errors=self.errors, errorCount=self.error_count,
                    metaRequests=self.meta_requests, metaDelayed=self.meta_delayed,
                    metaWaiting=self.meta_waiting, metaMaxWaiting=self.meta_max_waiting,
                    metaDelayRemaining=self.meta_delay_count, acceptedPhysical=self.accepted_physical,
                    listRequests=self.list_requests, tasks=len(self.tasks),
                    sessions=[s.summary() for s in self.sessions])

    async def http(self, reader, writer):
        try:
            headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            size = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                         if line.lower().startswith(b"content-length:")), 0)
            if not 0 < size <= 128 * 1024:
                raise ValueError("control body outside bound")
            request = json.loads(await reader.readexactly(size))
            result = await self.control(request)
            body = json.dumps(result, separators=(",", ":")).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            await writer.drain()
        except Exception as error:
            self.error("control: " + str(error))
            body = json.dumps(dict(error=str(error))).encode()
            writer.write(b"HTTP/1.1 500 Error\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
            await writer.drain()
        finally:
            writer.close()

    async def run(self):
        for port, tls in ((16668, False), (16669, True)):
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", port))
            listener.listen(512)
            listener.setblocking(False)
            self.task(self.accept(listener, tls))
        await asyncio.start_server(self.proxy, "0.0.0.0", 7690, limit=LINE_LIMIT)
        await asyncio.start_server(self.http, "127.0.0.1", 8099, limit=128 * 1024)
        self.task(self.subscriber())
        self.task(self.traffic())
        self.task(self.pings())
        await asyncio.Future()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "certificates":
        certificates()
    elif len(sys.argv) > 1 and sys.argv[1] == "rpc":
        request = urllib.request.Request("http://127.0.0.1:8099", data=sys.stdin.buffer.read(128 * 1024),
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=90) as response:
            payload = response.read(1024 * 1024 + 1)
            if len(payload) > 1024 * 1024:
                raise ValueError("fixture RPC response exceeds the one-MiB envelope")
            sys.stdout.buffer.write(payload)
    else:
        asyncio.run(Fixture().run())


if __name__ == "__main__":
    main()
