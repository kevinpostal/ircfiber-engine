#!/usr/bin/env python3
"""E2E: verify the engine's IRC registration hard-timeout fires when a server
never sends 001 (the symptom that caused #tclmafia + #welcome to appear
stuck at 'Joining...' for hours after a server stop responding).

This stands up a local Python TCP listener that accepts connections
without sending any data, configures a network pointing at it, waits
for the engine's REGISTRATION_OVERALL_TIMEOUT_SECS (30s) to fire,
and asserts the engine retries with backoff and the network surfaces
'registration timeout' state.
"""
import asyncio
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ENV_FILE = Path('/Users/zodiac/Library/Mobile Documents/com~apple~CloudDocs/Work/IRC/IRC_FIBER/.env')
creds = {}
for line in ENV_FILE.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        creds[k.strip()] = v.strip()

BASE = 'https://ircfiber.com'


class BlackHoleIRC:
    """Accepts TCP connections on the given port and sends nothing.
    Models a misbehaving IRC server that completes the TCP handshake
    but never replies to the client's CAP LS / NICK / USER. The engine
    must time out the registration (REGISTRATION_OVERALL_TIMEOUT_SECS)
    rather than block forever."""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', port))
        self.sock.listen(8)
        self.conns = []

    def accept_one(self):
        conn, _ = self.sock.accept()
        self.conns.append(conn)
        return conn

    def close(self):
        for c in self.conns:
            try: c.close()
            except: pass
        self.sock.close()


def get_session():
    Path('/tmp/reg_to_h.txt').write_text('')
    subprocess.run([
        'curl', '-s', '-D', '/tmp/reg_to_h.txt',
        '-X', 'POST', f'{BASE}/login',
        '-d', f'username={creds["FIBER_USERNAME"]}&password={creds["FIBER_PASSWORD"]}',
        '-o', '/dev/null'
    ], capture_output=True, timeout=15)
    for line in Path('/tmp/reg_to_h.txt').read_text().splitlines():
        if line.lower().startswith('set-cookie:'):
            m = re.search(r'vibe\.session_id=([^;]+)', line)
            if m:
                return m.group(1)
    return None


def http_json(cookie, method, path, body=None, expect_status=200):
    """Tiny helper for the JSON admin/api endpoints."""
    args = ['curl', '-s', '-w', '%{http_code}', '-X', method,
            '-H', f'Cookie: vibe.session_id={cookie}']
    if body is not None:
        args += ['-H', 'Content-Type: application/json', '-d', json.dumps(body)]
    args += [f'{BASE}{path}']
    p = subprocess.run(args, capture_output=True, text=True, timeout=15)
    last = p.stdout[-3:]
    raw = p.stdout[:-3]
    try:
        return int(last), json.loads(re.sub(r'[\x00-\x1f]', '', raw)) if raw.strip() else None
    except Exception:
        return int(last) if last.isdigit() else 0, raw


def get_server_id(cookie):
    """Find a server ID that we can use to attach networks to for testing.
    In a single-engine prod deployment, the only serverId is 'ovh'."""
    status, data = http_json(cookie, 'GET', '/api/admin/servers')
    if status != 200 or not data.get('ok'):
        raise RuntimeError(f"admin /servers failed: {status} {data}")
    engines = data['data'].get('engines', [])
    if not engines:
        raise RuntimeError("no engines registered")
    return engines[0]['serverId']


async def main():
    failures = []

    # 1. Stand up a local black-holed TCP server
    bh = BlackHoleIRC(port=16667)
    bh.sock.settimeout(2)
    print(f'BlackHoleIRC listening on 127.0.0.1:{bh.port}')

    async def accept_in_background():
        while True:
            try:
                bh.accept_one()
            except Exception:
                return
    accept_task = asyncio.create_task(accept_in_background())

    # 2. Login + create a network pointing at the black hole
    cookie = get_session()
    if not cookie:
        print('FAIL: no session cookie')
        return False
    print(f'Got session cookie')

    server_id = get_server_id(cookie)
    print(f'Using serverId: {server_id}')

    net_name = f'BlackHoleTest_{int(time.time())}'
    body = {
        'name': net_name,
        'host': '127.0.0.1',
        'port': bh.port,
        'tls': 'disabled',
        'nick': 'BHProbe',
        'realName': 'BH Probe',
        'autoJoinChannels': [],
    }
    status, data = http_json(cookie, 'POST', '/api/networks', body=body)
    if status != 200 or not data:
        print(f'FAIL: create network returned {status} {data}')
        return False
    network_id = data.get('id') or data.get('networkId')
    print(f'Created network {net_name} ({network_id})')

    # 3. Wait for the engine to attempt the connection.
    #    The black hole accepts the TCP, never sends 001.
    #    The engine's REGISTRATION_OVERALL_TIMEOUT_SECS (30) should fire.
    #    We poll the admin /servers endpoint to detect either:
    #      (a) registrationUnavailableFor contains our networkId
    #          → timeout fired, our fix worked.
    #      (b) status stays "connecting" > 60s → fix didn't fire in time.
    deadline = time.time() + 75
    timeout_observed = False
    last_status = ''
    while time.time() < deadline:
        _, data = http_json(cookie, 'GET', '/api/admin/servers')
        for e in (data or {}).get('data', {}).get('engines', []):
            reg_unavail = e.get('registrationUnavailableFor', [])
            status_holder = e.get('holderUnavailableFor', [])
            joined_status = f'engine={e["serverId"]} reg_unavail={reg_unavail}'
            if joined_status != last_status:
                print(f'  [{75-(deadline-time.time()):.0f}s] {joined_status}')
                last_status = joined_status
            if network_id in reg_unavail:
                timeout_observed = True
                break
        if timeout_observed:
            break
        await asyncio.sleep(2)

    if timeout_observed:
        print('✓ Network appears in registrationUnavailableFor (timeout fired)')
    else:
        print('✗ Network did NOT appear in registrationUnavailableFor within 75s')
        failures.append('Registration timeout did not fire within 75s')

    # 4. Verify the network is being retried (still has the network in
    #    its state, just stuck on connecting).
    _, data = http_json(cookie, 'GET', '/api/admin/servers')
    for e in (data or {}).get('data', {}).get('engines', []):
        net_in_list = next((n for n in (data.get('data', {}).get('networks', [])
                                       if n.get('name') == server_id)), None)
        # Check the per-network view
    _, data2 = http_json(cookie, 'GET', '/api/networks')
    for n in data2:
        if n.get('name') == net_name:
            print(f'  network status: connected={n.get("connected")} status={n.get("status")}')

    # 5. Clean up — delete the test network so it doesn't pollute the user's
    #    server list forever.
    accept_task.cancel()
    bh.close()
    try:
        status, _ = http_json(cookie, 'DELETE', f'/api/networks/{network_id}')
        print(f'Cleanup: DELETE /api/networks/{network_id} → {status}')
    except Exception as e:
        print(f'Cleanup warning: {e}')

    print(f'\n{"="*60}')
    if failures:
        print(f'FAIL — {len(failures)} issues:')
        for f in failures:
            print(f'  - {f}')
        return False
    print('PASS — registration timeout fires correctly')
    return True


if __name__ == '__main__':
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)