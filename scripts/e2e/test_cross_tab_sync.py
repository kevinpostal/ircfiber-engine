#!/usr/bin/env python3
"""E2E: Verify messages appear in real-time across two browser tabs.

Regression for the 2026-07-15 multi-tab cross-sync bug. Before the fix,
the JWT-based session restore in `handleWebSocket` reused the in-memory
session for any new tab sharing the JWT cookie. Both tabs ended up
sharing one outbound queue + socket + cursor, so a message sent in tab A
never appeared in tab B until a refresh triggered a fresh state dump.

This test opens two browser contexts (sharing cookies) on the same
channel URL, types a unique marker in each tab, and asserts the marker
appears in BOTH tabs' chat view within a few seconds (real-time sync).

Pre-fix: assertions fail — each tab only sees its own optimistic
          message, never the other tab's message.
Post-fix: both tabs see both markers in real-time.
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
    # The input is the textarea/input at the bottom of the chat panel.
    # Try common selectors.
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


async def body_contains(page, text):
    """Return True iff `text` appears in the page body."""
    body = await page.evaluate('() => document.body.innerText')
    return text in body


async def main():
    print('═══ Cross-Tab Sync Test (2026-07-15 regression) ═══')
    # Login via curl to get the cookie
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

    print(f'   Logged in (cookie present)')

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # ONE browser context → cookies (including the JWT-backed ws_session_jwt
        # cookie set by the gateway after the first WS) are shared across
        # tabs. This is the exact user-visible scenario from the bug report.
        ctx = await browser.new_context(viewport={'width': 1400, 'height': 900},
                                        ignore_https_errors=True)
        await ctx.add_cookies([{'name': 'vibe.session_id', 'value': cookie,
            'domain': 'ircfiber.com', 'path': '/', 'httpOnly': True, 'secure': True}])

        url = f'{BASE}/irc/{NETWORK}/channel/{CHANNEL}'

        # Tab A opens first — establishes the shared WS session
        tabA = await ctx.new_page()
        await tabA.goto(url, wait_until='domcontentloaded', timeout=30000)
        await tabA.wait_for_timeout(4000)  # let WS connect + sync state

        # Tab B opens in the SAME context — shares cookies
        tabB = await ctx.new_page()
        await tabB.goto(url, wait_until='domcontentloaded', timeout=30000)
        await tabB.wait_for_timeout(4000)  # let WS connect

        print('   Both tabs loaded')

        # ── Test 1: Tab A sends a marker; both tabs should see it ──
        markerA = f'XTabTest-A-{int(time.time())}'
        print(f'   Tab A sends: {markerA}')
        await type_marker(tabA, markerA)
        # Give the WS round-trip + reactive render time
        await tabA.wait_for_timeout(2500)
        await tabB.wait_for_timeout(2500)

        a_has_a = await body_contains(tabA, markerA)
        b_has_a = await body_contains(tabB, markerA)
        print(f'   Tab A sees markerA: {a_has_a} (own optimistic = OK either way)')
        print(f'   Tab B sees markerA: {b_has_a} (REAL-TIME SYNC TEST)')

        if not b_has_a:
            print('   ❌ FAIL: Tab B did not receive Tab A\'s message in real-time')
            await tabA.screenshot(path='/tmp/xtab_tabA.png')
            await tabB.screenshot(path='/tmp/xtab_tabB.png')
            await browser.close()
            return False

        # ── Test 2: Tab B sends a marker; both tabs should see it ──
        markerB = f'XTabTest-B-{int(time.time())}'
        print(f'   Tab B sends: {markerB}')
        await type_marker(tabB, markerB)
        await tabA.wait_for_timeout(2500)
        await tabB.wait_for_timeout(2500)

        a_has_b = await body_contains(tabA, markerB)
        b_has_b = await body_contains(tabB, markerB)
        print(f'   Tab A sees markerB: {a_has_b} (REAL-TIME SYNC TEST)')
        print(f'   Tab B sees markerB: {b_has_b} (own optimistic = OK either way)')

        if not a_has_b:
            print('   ❌ FAIL: Tab A did not receive Tab B\'s message in real-time')
            await tabA.screenshot(path='/tmp/xtab_tabA.png')
            await tabB.screenshot(path='/tmp/xtab_tabB.png')
            await browser.close()
            return False

        await browser.close()
        print('\n   ✅ PASS: messages sync in real-time across two tabs')
        return True


if __name__ == '__main__':
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)