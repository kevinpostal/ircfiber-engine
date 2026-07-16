#!/usr/bin/env python3
"""E2E: Verify messages appear in real-time across two browser tabs.

With detailed debugging.
"""
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


async def type_marker(page, marker):
    """Type a unique marker into the chat input and submit it."""
    selectors = [
        'textarea[placeholder*="message"]',
        'textarea',
        'input[placeholder*="message"]',
        'input[type="text"]',
        '[contenteditable="true"]',
    ]
    box = None
    for sel in selectors:
        loc = page.locator(sel).first
        if await loc.count() > 0:
            box = loc
            break
    if box is None:
        raise RuntimeError('No chat input found on page')
    await box.click()
    await box.fill(marker)
    await box.press('Enter')


async def ws_state(page):
    """Get the WS state from window.__ws_state__ if available."""
    return await page.evaluate('() => window.__ws_state__ || "unknown"')


async def body_contains(page, text):
    body = await page.evaluate('() => document.body.innerText')
    return text in body


async def main():
    print('═══ Cross-Tab Sync Test (debug) ═══')
    subprocess.run(['curl', '-s', '-c', '/tmp/xtab_cookies.txt', '-X', 'POST', f'{BASE}/login',
        '-d', f'username={creds["FIBER_USERNAME"]}&password={creds["FIBER_PASSWORD"]}',
        '-o', '/dev/null'], timeout=15)
    cookie = ''
    for line in Path('/tmp/xtab_cookies.txt').read_text().splitlines():
        if 'vibe.session_id' in line:
            parts = line.split('\t')
            cookie = parts[-1].strip()

    if not cookie:
        print('❌ FAIL: No cookie from login')
        return False

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={'width': 1400, 'height': 900},
                                        ignore_https_errors=True)
        await ctx.add_cookies([{'name': 'vibe.session_id', 'value': cookie,
            'domain': 'ircfiber.com', 'path': '/', 'httpOnly': True, 'secure': True}])

        url = f'{BASE}/irc/{NETWORK}/channel/{CHANNEL}'

        # Tab A
        tabA = await ctx.new_page()
        async def on_a_console(msg):
            try:
                text = msg.text
                if 'WS' in text or 'ws' in text or msg.type == 'error':
                    print(f'[TabA console.{msg.type}]', text)
            except: pass
        tabA.on('console', lambda msg: asyncio.create_task(on_a_console(msg)))
        await tabA.goto(url, wait_until='domcontentloaded', timeout=30000)
        await tabA.wait_for_timeout(6000)  # let WS connect + sync state
        print(f'   Tab A WS state: {await ws_state(tabA)}')

        # Tab B
        tabB = await ctx.new_page()
        async def on_b_console(msg):
            try:
                text = msg.text
                if 'WS' in text or 'ws' in text or msg.type == 'error':
                    print(f'[TabB console.{msg.type}]', text)
            except: pass
        tabB.on('console', lambda msg: asyncio.create_task(on_b_console(msg)))
        await tabB.goto(url, wait_until='domcontentloaded', timeout=30000)
        await tabB.wait_for_timeout(6000)
        print(f'   Tab B WS state: {await ws_state(tabB)}')

        print('   Both tabs loaded and connected')

        # Check current state
        a_visible_text = await tabA.evaluate('() => document.body.innerText.substring(0, 500)')
        b_visible_text = await tabB.evaluate('() => document.body.innerText.substring(0, 500)')
        print(f'   Tab A preview: {a_visible_text[:200]!r}')
        print(f'   Tab B preview: {b_visible_text[:200]!r}')

        # Send marker from Tab A
        markerA = f'XTabTest-A-{int(time.time())}'
        print(f'\n   Tab A sends: {markerA}')
        # Verify input field exists
        input_count = await tabA.locator('textarea, input[type="text"]').count()
        print(f'   Input fields found in Tab A: {input_count}')
        await type_marker(tabA, markerA)
        # Verify input is empty after send
        input_val = await tabA.locator('textarea, input[type="text"]').first.input_value()
        print(f'   Tab A input after send: {input_val!r}')
        # Wait longer for the WS round-trip
        for i in range(8):
            await tabA.wait_for_timeout(1000)
            await tabB.wait_for_timeout(1000)
            a_has_a_now = await body_contains(tabA, markerA)
            b_has_a_now = await body_contains(tabB, markerA)
            print(f'   After {i+1}s: Tab A={a_has_a_now} Tab B={b_has_a_now}')
            if b_has_a_now:
                break

        a_has_a = await body_contains(tabA, markerA)
        b_has_a = await body_contains(tabB, markerA)
        print(f'   Final: Tab A sees markerA: {a_has_a}')
        print(f'   Final: Tab B sees markerA: {b_has_a}')

        # Take screenshots for inspection
        await tabA.screenshot(path='/tmp/xtab_a.png')
        await tabB.screenshot(path='/tmp/xtab_b.png')

        if not b_has_a:
            print('\n   FAIL: Tab B does not see markerA in real-time')
            # Get fresh body contents (no truncation)
            a_full = await tabA.evaluate('() => document.body.innerText')
            b_full = await tabB.evaluate('() => document.body.innerText')
            print(f'\n   Tab A body length: {len(a_full)}')
            print(f'   Tab B body length: {len(b_full)}')
            print(f'   Tab A contains "{markerA}": {markerA in a_full}')
            print(f'   Tab B contains "{markerA}": {markerA in b_full}')
            print('\n   --- Tab A body (full, search for XTabTest) ---')
            for line in a_full.split('\n'):
                if 'XTabTest' in line or markerA in line:
                    print(f'      {line!r}')
            print('\n   --- Tab B body (full, search for XTabTest) ---')
            for line in b_full.split('\n'):
                if 'XTabTest' in line or markerA in line:
                    print(f'      {line!r}')
            return False

        await browser.close()
        print('\n   ✅ PASS')
        return True


if __name__ == '__main__':
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)