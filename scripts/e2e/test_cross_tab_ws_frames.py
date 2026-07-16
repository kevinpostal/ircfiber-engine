#!/usr/bin/env python3
"""Capture WS frames sent to Tab B."""
import asyncio
import subprocess
import sys
import time
from pathlib import Path
from playwright.async_api import async_playwright

ENV_FILE = Path('/Users/zodiac/Library/Mobile Documents/com~apple~CloudDocs/Work/IRC/IRC_FIBER/.env')
creds = {}
for line in ENV_FILE.read_text().splitlines():
    line = line.strip()
    if line and '=' in line and not line.startswith('#'):
        k, v = line.split('=', 1)
        creds[k.strip()] = v.strip()

BASE = 'https://ircfiber.com'
NETWORK = 'irc.supernets.org'
CHANNEL = 'zod'


async def main():
    subprocess.run(['curl', '-s', '-c', '/tmp/xtab_cookies.txt', '-X', 'POST', f'{BASE}/login',
        '-d', f'username={creds["FIBER_USERNAME"]}&password={creds["FIBER_PASSWORD"]}',
        '-o', '/dev/null'], timeout=15)
    cookie = ''
    for line in Path('/tmp/xtab_cookies.txt').read_text().splitlines():
        if 'vibe.session_id' in line:
            parts = line.split('\t')
            cookie = parts[-1].strip()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={'width': 1400, 'height': 900},
                                        ignore_https_errors=True)
        await ctx.add_cookies([{'name': 'vibe.session_id', 'value': cookie,
            'domain': 'ircfiber.com', 'path': '/', 'httpOnly': True, 'secure': True}])

        url = f'{BASE}/irc/{NETWORK}/channel/{CHANNEL}'

# Tab A
        tabA = await ctx.new_page()
        tabA_ws_frames = []
        def on_ws_a(ws):
            print(f'[TabA] WS opened: {ws.url}')
            ws.on('framereceived', lambda payload: tabA_ws_frames.append(payload[:300]))
        tabA.on('websocket', on_ws_a)
        await tabA.goto(url, wait_until='domcontentloaded', timeout=30000)
        await tabA.wait_for_timeout(5000)

        # Tab B
        tabB = await ctx.new_page()
        tabB_ws_frames = []
        def on_ws_b(ws):
            print(f'[TabB] WS opened: {ws.url}')
            ws.on('framereceived', lambda payload: tabB_ws_frames.append(payload[:300]))
        tabB.on('websocket', on_ws_b)
        await tabB.goto(url, wait_until='domcontentloaded', timeout=30000)
        await tabB.wait_for_timeout(5000)

        # Send marker from Tab A
        markerA = f'XTabTest-A-{int(time.time())}'
        print(f'\nSending: {markerA}')

        box = tabA.locator('textarea, input[type="text"]').first
        await box.click()
        await box.fill(markerA)
        await box.press('Enter')
        await tabA.wait_for_timeout(8000)

        # Find marker in Tab B's WS frames
        marker_in_b = any(markerA in f for f in tabB_ws_frames)
        print(f'\nTab A WS frames received: {len(tabA_ws_frames)}')
        print(f'Tab B WS frames received: {len(tabB_ws_frames)}')
        print(f'Tab B contains marker: {marker_in_b}')

        if tabB_ws_frames:
            print('\nLast 10 Tab B frames:')
            for f in tabB_ws_frames[-10:]:
                print(f'  {f[:200]}')

        await browser.close()
        return marker_in_b


if __name__ == '__main__':
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)