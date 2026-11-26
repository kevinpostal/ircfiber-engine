#!/usr/bin/env python3
"""Disposable physical transport oracle; never a production admission authority."""
import asyncio
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

from holder_engine_qualification import EngineFixture


class NordFixture(EngineFixture):
    def __init__(self):
        super().__init__()
        self.lose_next = False
        self.lost = []
        self.drop_ack = False
        self.blocked_ack = None
        self.ack_gate = asyncio.Event()
        self.ack_gate.set()

    async def proxy(self, reader, writer):
        # The ordinary fixture already forwards every real holder control frame.
        # Peek only the first line to inject loss of one actual CONNECTED reply.
        first = await reader.readline()
        if not first:
            writer.close()
            return
        if not (self.lose_next and first.startswith(b"DIAL ")):
            fixture = self
            class Prefix:
                def __init__(self, stream, line):
                    self.stream, self.line = stream, line
                async def readline(self):
                    if self.line is not None:
                        line, self.line = self.line, None
                        return line
                    line = await self.stream.readline()
                    if fixture.drop_ack and line.startswith(b"NORD_ACK "):
                        fixture.drop_ack = False
                        fixture.blocked_ack = json.loads(line.partition(b" ")[2])
                        await asyncio.wait_for(fixture.ack_gate.wait(), 60)
                        return b""
                    return line
                async def read(self, n=-1):
                    return await self.stream.read(n)
            await super().proxy(Prefix(reader, first), writer)
            return
        self.lose_next = False
        upstream_reader, upstream = await asyncio.open_unix_connection("/run/ircfiber/holder.sock")
        upstream.write(first)
        await upstream.drain()
        try:
            while reply := await asyncio.wait_for(upstream_reader.readline(), 30):
                if reply.startswith(b"CONNECTED "):
                    entry = json.loads(reply.partition(b" ")[2])
                    self.lost.append({"id": entry["id"], "request": json.loads(first.partition(b" ")[2]),
                                      "writer": upstream})
                    writer.close()
                    # Preserve the actual holder attachment until explicitly
                    # closed by the fault controller, not a fabricated outcome.
                    await upstream_reader.read()
                    return
                writer.write(reply)
                await writer.drain()
        finally:
            upstream.close()
            writer.close()

    async def control(self, command):
        action = command["action"]
        if action == "blockNextAck":
            self.drop_ack = True
            self.blocked_ack = None
            self.ack_gate.clear()
            return {"ok": True}
        if action == "blockedAck":
            return self.blocked_ack
        if action == "releaseAck":
            self.ack_gate.set()
            return {"ok": True}
        if action == "metrics":
            target = command.get("target", "nord")
            if target not in ("nord", "mullvad"):
                raise ValueError("unknown measured endpoint")
            operation = command.get("operation", "metrics")
            if operation not in {"metrics", "block", "unblock", "close", "stall-auth",
                                 "fail-auth", "allow-auth", "bad-tls", "allow-tls"}:
                raise ValueError("unknown proxy operation")
            url = "http://" + ("192.0.2.30" if target == "nord" else "192.0.2.31") + ":1081/" + operation
            def request():
                req = urllib.request.Request(url, method="GET" if operation == "metrics" else "POST")
                with urllib.request.urlopen(req, timeout=5) as response:
                    return json.load(response)
            return await asyncio.to_thread(request)
        if action == "holderRpc":
            return await self.holder_request(command["verb"], command.get("payload"))
        if action == "loseNextDial":
            self.lose_next = True
            return {"ok": True}
        if action == "lost":
            return [{"id": row["id"], "token": row["request"].get("nordCapacityToken")}
                    for row in self.lost]
        if action == "closeNick":
            target = self.by_nick[command["nick"]]
            target.writer.close()
            return {"ok": True}
        if action == "duplicateDial":
            row = self.lost[-1]
            reader, writer = await asyncio.open_unix_connection("/run/ircfiber/holder.sock")
            try:
                writer.write(("DIAL " + json.dumps(row["request"]) + "\n").encode())
                await writer.drain()
                return {"reply": (await asyncio.wait_for(reader.readline(), 10)).decode()}
            finally:
                writer.close()
        if action == "invalidDial":
            request = json.loads(json.dumps(self.lost[-1]["request"]))
            mutation = command["mutation"]
            if mutation == "missingProvider":
                request["proxy"].pop("provider", None)
            elif mutation == "wrongInstance":
                request["holderInstance"] = "00000000-0000-4000-8000-000000000000"
            elif mutation == "missingGeneration":
                request.pop("nordCapacityGeneration", None)
            else:
                raise ValueError("unknown invalid DIAL mutation")
            reader, writer = await asyncio.open_unix_connection("/run/ircfiber/holder.sock")
            try:
                writer.write(("DIAL " + json.dumps(request) + "\n").encode())
                await writer.drain()
                return {"reply": (await asyncio.wait_for(reader.readline(), 10)).decode()}
            finally:
                writer.close()
        return await super().control(command)


def certificates():
    root = Path("/fixture-certs")
    root.mkdir(exist_ok=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                    "-subj", "/CN=mock-irc", "-addext",
                    "subjectAltName=DNS:mock-irc,DNS:default.regression.test,DNS:alpha.example.org,DNS:beta.example.net,DNS:am.i.mullvad.net,DNS:ipinfo.io,DNS:image.regression.test,IP:93.184.216.34",
                    "-keyout", str(root / "key.pem"), "-out", str(root / "ca-certificates.crt")],
                   check=True, timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / "nord-server.crt").write_bytes((root / "ca-certificates.crt").read_bytes())
    (root / "nord-server.key").write_bytes((root / "key.pem").read_bytes())


if __name__ == "__main__":
    if sys.argv[1:] == ["certificates"]:
        certificates()
    elif sys.argv[1:] == ["serve"]:
        asyncio.run(NordFixture().run())
    else:
        raise SystemExit("expected serve|certificates")
