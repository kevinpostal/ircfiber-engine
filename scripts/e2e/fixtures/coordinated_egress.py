#!/usr/bin/env python3
"""Owned egress oracle: real SOCKS paths plus tailscaled-compatible Unix LocalAPI.

A is a direct socket from egress-a; B goes through egress-b, so selected control
state changes the actual source observed by the IRC listener. This is an explicit
provider emulator, not a real Mullvad/tailnet qualification or historical proof.
"""
import asyncio
import json
import os
from pathlib import Path

from holder_engine_qualification import socks_server


class Egress:
    selected = 'a'

    def status(self):
        return dict(BackendState='Running', Self=dict(Online=True, HostName='owned-dynamic-slot'),
                    ExitNodeStatus=dict(Online=True, ID='fixture-exit-' + self.selected),
                    Peer={key: dict(ID='fixture-exit-' + key, HostName='fixture-exit-' + key,
                                    PublicKey='nodekey:' + key * 64, Online=True, ExitNodeOption=True,
                                    ExitNode=key == self.selected, TailscaleIPs=['100.64.0.' + str(index + 10)],
                                    Location=dict(CountryCode='fixture', CityCode=key, Country='Fixture', City=key))
                          for index, key in enumerate(('a', 'b'))})

    async def api(self, reader, writer):
        try:
            while True:
                try:
                    header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 610)
                except asyncio.IncompleteReadError:
                    break
                lines = header.decode().split('\r\n')
                method, path, _ = lines[0].split(' ')
                fields = dict(line.split(':', 1) for line in lines[1:] if ':' in line)
                count = int(next((v.strip() for k, v in fields.items() if k.lower() == 'content-length'), '0'))
                if not 0 <= count <= 65536:
                    raise ValueError('bounded LocalAPI body required')
                body = await reader.readexactly(count)
                if method == 'GET' and path.startswith('/localapi/v0/status'):
                    result = self.status()
                elif method == 'GET' and path == '/localapi/v0/prefs':
                    result = dict(ExitNodeIP='100.64.0.' + ('10' if self.selected == 'a' else '11'), WantRunning=True)
                elif method == 'PATCH' and path == '/localapi/v0/prefs':
                    preferences = json.loads(body)
                    target = preferences.get('ExitNodeIP')
                    if target not in ('100.64.0.10', '100.64.0.11'):
                        raise ValueError('refusing nonfixture exit')
                    self.selected = 'a' if target.endswith('.10') else 'b'
                    result = dict(ExitNodeIP=target, WantRunning=True)
                else:
                    raise ValueError('unsupported LocalAPI request')
                encoded = json.dumps(result, separators=(',', ':')).encode()
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' +
                             str(len(encoded)).encode() + b'\r\nConnection: keep-alive\r\n\r\n' + encoded)
                await writer.drain()
        except (ValueError, ConnectionError, asyncio.TimeoutError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()

    async def dynamic(self, reader, writer):
        upstream = None
        tasks = []
        try:
            version, count = await reader.readexactly(2)
            methods = await reader.readexactly(count)
            if version != 5 or 0 not in methods:
                return
            writer.write(b'\x05\x00')
            await writer.drain()
            prefix = await reader.readexactly(4)
            if prefix != b'\x05\x01\x00\x03':
                return
            size = (await reader.readexactly(1))[0]
            name = await reader.readexactly(size)
            port_bytes = await reader.readexactly(2)
            port = int.from_bytes(port_bytes, 'big')
            if name.decode() not in ('mock-irc', 'alpha.example.org', 'beta.example.net') or port not in (16668, 16669):
                return
            if self.selected == 'a':
                remote, upstream = await asyncio.open_connection('mock-irc', port)
            else:
                remote, upstream = await asyncio.open_connection('egress-b', 1080)
                upstream.write(b'\x05\x01\x02')
                await upstream.drain()
                if await remote.readexactly(2) != b'\x05\x02':
                    return
                upstream.write(b'\x01\x04test\x04test')
                await upstream.drain()
                if await remote.readexactly(2) != b'\x01\x00':
                    return
                upstream.write(prefix + bytes([size]) + name + port_bytes)
                await upstream.drain()
                if await remote.readexactly(10) != b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00':
                    return
            writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            await writer.drain()
            async def copy(source, target):
                while data := await source.read(65536):
                    target.write(data)
                    await target.drain()
            tasks = [asyncio.create_task(copy(reader, upstream)), asyncio.create_task(copy(remote, writer))]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            writer.close()
            if upstream:
                upstream.close()

    async def run(self):
        path = Path('/control/dynamic/tailscaled.sock')
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        control = await asyncio.start_unix_server(self.api, str(path), limit=131072)
        os.chmod(path, 0o666)
        dynamic = await asyncio.start_server(self.dynamic, '0.0.0.0', 1081)
        async with control, dynamic:
            await asyncio.gather(socks_server(), control.serve_forever(), dynamic.serve_forever())


if __name__ == '__main__':
    asyncio.run(Egress().run())
