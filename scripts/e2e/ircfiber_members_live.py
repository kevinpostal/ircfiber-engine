#!/usr/bin/env python3
"""Comprehensive e2e test for IRC Fiber: join, see members, send messages.

Validates the full flow with TWO browser sessions to confirm the members
list updates when a real second user joins.
"""
import asyncio
import sys
import time
import urllib.parse
from pathlib import Path
from playwright.async_api import async_playwright

ENV_FILE = Path('/Users/zodiac/Library/Mobile Documents/com~apple~CloudDocs/Work/IRC/IRC_FIBER/.env')
creds = {}
for line in ENV_FILE.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        creds[k.strip()] = v.strip()

BASE = 'https://ircfiber.com'
NETWORK_NAME = 'IRC Fiber'
CHANNEL = 'welcome'
ts = int(time.time())
PROBE_NICK = f'e2e_probe_{ts}'

async def login_and_open(ctx, label):
    page = await ctx.new_page()
    logs = []
    page.on('console', lambda msg: logs.append(f'[{msg.type}] {msg.text[:200]}'))
    page.on('pageerror', lambda err: logs.append(f'[pageerror] {err.message[:200]}'))
    print(f'\n=== {label}: opening /login ===')
    await page.goto(f'{BASE}/login', wait_until='domcontentloaded', timeout=30000)
    await page.wait_for_timeout(1500)
    await page.locator('input[name="username"]').first.fill(creds['FIBER_USERNAME'])
    await page.locator('input[name="password"]').first.fill(creds['FIBER_PASSWORD'])
    await page.locator('form[action="/login"] button[type="submit"]').first.click()
    await page.wait_for_load_state('domcontentloaded', timeout=30000)
    await page.wait_for_timeout(2000)
    return page, logs

async def find_chat_input(page, timeout=15000):
    """Robustly find the chat input (textarea, contenteditable, etc)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for sel in ['textarea', 'input[placeholder*="message" i]', 'div[contenteditable="true"]']:
            loc = page.locator(sel).last
            if await loc.count() > 0:
                ph = (await loc.get_attribute('placeholder')) or ''
                if 'search' in ph.lower():
                    continue
                return loc
        await page.wait_for_timeout(500)
    return None

async def wait_for_member_nick(page, nick, timeout=30000):
    """Wait until the members panel shows the given bare nick."""
    print(f'  waiting for member "{nick}" in members list...')
    deadline = time.time() + timeout
    while time.time() < deadline:
        n = await page.locator(f'.member-nick:has-text("{nick}")').count()
        if n > 0:
            return True
        await page.wait_for_timeout(500)
    return False

async def wait_for_connection_stable(page, timeout=60000):
    """Wait for IRC engine to register (001/welcome) and the channel to join.
    Heuristic: the connecting-... overlay disappears AND the input area is visible
    AND no error pill is shown.
    """
    print('  waiting for IRC connection to stabilize...')
    deadline = time.time() + timeout
    last_status = None
    while time.time() < deadline:
        # Check for the connecting overlay (its text contains "Connecting")
        # The error pill says "Click to reconnect" or similar.
        body = (await page.locator('body').text_content() or '').lower()
        is_connecting = 'connecting' in body
        is_reconnect = 'reconnect' in body and 'click' in body
        chat_input = await find_chat_input(page, timeout=2)
        if chat_input is not None and not is_connecting and not is_reconnect:
            return True
        await page.wait_for_timeout(500)
    return False

async def run():
    failures = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        # ── Session 1: probe user joins #welcome and verifies own nick ──
        ctx1 = await browser.new_context(viewport={'width': 1400, 'height': 900},
                                        ignore_https_errors=True)
        page1, logs1 = await login_and_open(ctx1, 'Session 1 (probe)')

        # Navigate to the channel
        url = f'{BASE}/irc/{urllib.parse.quote(NETWORK_NAME)}/channel/{CHANNEL}'
        print(f'\n=== Session 1: navigating to {url} ===')
        await page1.goto(url, wait_until='domcontentloaded', timeout=30000)

        # Wait for IRC engine to be ready
        connected = await wait_for_connection_stable(page1, timeout=90000)
        if not connected:
            await page1.screenshot(path='/tmp/s1-stuck.png', full_page=True)
            print('   ✗ Session 1 did not reach stable IRC state')
            for l in logs1[-30:]:
                print(f'   {l}')
            failures.append('Session 1 did not reach stable IRC state')
        else:
            print('   ✓ Session 1 connected')

        # Set nick to PROBE_NICK
        chat_input = await find_chat_input(page1)
        if chat_input is None:
            await page1.screenshot(path='/tmp/s1-no-input.png', full_page=True)
            print('   ✗ No chat input found in session 1')
            failures.append('No chat input in session 1')
        else:
            print(f'\n=== Session 1: setting nick to {PROBE_NICK} ===')
            await chat_input.click()
            await chat_input.fill(f'/nick {PROBE_NICK}')
            await chat_input.press('Enter')
            await page1.wait_for_timeout(5000)

            # Verify session 1's own nick is in its members list
            own_nick_in_members = await wait_for_member_nick(page1, PROBE_NICK, timeout=30000)
            if own_nick_in_members:
                print(f'   ✓ Session 1: {PROBE_NICK} visible in own members list')
            else:
                await page1.screenshot(path='/tmp/s1-no-self-nick.png', full_page=True)
                print(f'   ✗ Session 1: {PROBE_NICK} NOT in own members list')
                # Dump the members list
                members = page1.locator('.member-nick')
                count = await members.count()
                print(f'     members panel has {count} entries:')
                for i in range(min(count, 30)):
                    txt = await members.nth(i).text_content()
                    print(f'       - {(txt or "").strip()[:60]}')
                failures.append(f'Session 1 missing own nick {PROBE_NICK}')

        # ── Session 2: admin joins the same channel, should see probe ──
        ctx2 = await browser.new_context(viewport={'width': 1400, 'height': 900},
                                        ignore_https_errors=True)
        page2, logs2 = await login_and_open(ctx2, 'Session 2 (admin)')
        print(f'\n=== Session 2: navigating to {url} ===')
        await page2.goto(url, wait_until='domcontentloaded', timeout=30000)
        connected2 = await wait_for_connection_stable(page2, timeout=90000)
        if not connected2:
            await page2.screenshot(path='/tmp/s2-stuck.png', full_page=True)
            print('   ✗ Session 2 did not reach stable IRC state')
            for l in logs2[-30:]:
                print(f'   {l}')
            failures.append('Session 2 did not reach stable IRC state')
        else:
            print('   ✓ Session 2 connected')

        # Admin sends a message
        chat_input2 = await find_chat_input(page2)
        if chat_input2 is None:
            await page2.screenshot(path='/tmp/s2-no-input.png', full_page=True)
            print('   ✗ No chat input in session 2')
            failures.append('No chat input in session 2')
        else:
            test_msg = f'probe-test-{ts}'
            print(f'\n=== Session 2: sending message "{test_msg}" ===')
            await chat_input2.click()
            await chat_input2.fill(test_msg)
            await chat_input2.press('Enter')
            await page2.wait_for_timeout(3000)

            # Verify the message appears in session 2's chat
            msg_visible_in_s2 = await page2.locator(f'text="{test_msg}"').count() > 0
            print(f'   Session 2 message visible: {msg_visible_in_s2}')
            if not msg_visible_in_s2:
                failures.append('Session 2 message not visible in own chat')

            # Wait for the message to propagate to session 1
            print('\n=== Session 1: waiting for admin message ===')
            deadline = time.time() + 30
            msg_visible_in_s1 = False
            while time.time() < deadline:
                if await page1.locator(f'text="{test_msg}"').count() > 0:
                    msg_visible_in_s1 = True
                    break
                await page1.wait_for_timeout(500)
            print(f'   Session 1 sees message: {msg_visible_in_s1}')
            if not msg_visible_in_s1:
                failures.append('Session 1 did not receive admin message')

        # Check that probe is visible in admin's members list
        if connected and connected2:
            print(f'\n=== Session 2: waiting for {PROBE_NICK} in members list ===')
            probe_in_admin = await wait_for_member_nick(page2, PROBE_NICK, timeout=30000)
            print(f'   Probe visible in admin members: {probe_in_admin}')
            if not probe_in_admin:
                await page2.screenshot(path='/tmp/s2-no-probe.png', full_page=True)
                members = page2.locator('.member-nick')
                count = await members.count()
                print(f'     admin members panel has {count} entries:')
                for i in range(min(count, 30)):
                    txt = await members.nth(i).text_content()
                    print(f'       - {(txt or "").strip()[:60]}')
                failures.append(f'Admin session missing probe {PROBE_NICK}')

            # Check that admin is visible in probe's members list
            admin_nick = f'{creds["FIBER_USERNAME"]}_b520'  # the underscore-suffix pattern
            print(f'\n=== Session 1: waiting for admin in members list ===')
            # The admin's actual nick depends on the server; check for the base name
            admin_in_probe = False
            deadline = time.time() + 30
            while time.time() < deadline:
                members = page1.locator('.member-nick')
                count = await members.count()
                for i in range(count):
                    txt = (await members.nth(i).text_content() or '').strip()
                    if creds['FIBER_USERNAME'].lower() in txt.lower():
                        admin_in_probe = True
                        break
                if admin_in_probe:
                    break
                await page1.wait_for_timeout(500)
            print(f'   Admin visible in probe members: {admin_in_probe}')
            if not admin_in_probe:
                await page1.screenshot(path='/tmp/s1-no-admin.png', full_page=True)
                failures.append('Probe session missing admin user')

        # ── Nick change test: probe renames itself, admin should see the new nick ──
        if connected and connected2 and chat_input:
            new_nick = f'{PROBE_NICK}_renamed'
            print(f'\n=== Session 1: changing nick to {new_nick} ===')
            await chat_input.click()
            await chat_input.fill(f'/nick {new_nick}')
            await chat_input.press('Enter')
            await page1.wait_for_timeout(8000)

            # Probe should see its own new nick
            new_in_probe = await page1.locator(f'.member-nick:has-text("{new_nick}")').count() > 0
            old_in_probe = await page1.locator(f'.member-nick:has-text("{PROBE_NICK}")').count() > 0
            print(f'   Probe sees new nick {new_nick}: {new_in_probe}')
            print(f'   Probe still sees old nick {PROBE_NICK}: {old_in_probe}')
            if not new_in_probe or old_in_probe:
                failures.append(f'Probe members list did not update to new nick')

            # Admin should see probe's new nick (not the old one)
            print(f'\n=== Session 2: waiting for {new_nick} in members list ===')
            new_in_admin = False
            old_in_admin = False
            deadline = time.time() + 30
            while time.time() < deadline:
                new_in_admin = await page2.locator(f'.member-nick:has-text("{new_nick}")').count() > 0
                old_in_admin = await page2.locator(f'.member-nick:has-text("{PROBE_NICK}")').count() > 0
                if new_in_admin:
                    break
                await page2.wait_for_timeout(500)
            print(f'   Admin sees new nick {new_nick}: {new_in_admin}')
            print(f'   Admin still sees old nick {PROBE_NICK}: {old_in_admin}')
            if not new_in_admin or old_in_admin:
                await page2.screenshot(path='/tmp/s2-old-nick.png', full_page=True)
                failures.append(f'Admin members list did not propagate nick change')

        await browser.close()

    print(f'\n{"="*60}')
    if failures:
        print(f'FAIL — {len(failures)} issues:')
        for f in failures:
            print(f'  - {f}')
        return False
    else:
        print('PASS — all checks succeeded')
        return True

if __name__ == '__main__':
    ok = asyncio.run(run())
    sys.exit(0 if ok else 1)