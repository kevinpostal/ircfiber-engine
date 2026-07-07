#!/usr/bin/env python3
"""E2E: verify MOTD, server-log grouping, and auto-rejoin on IRC Fiber."""
import asyncio
import json
import re
import subprocess
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
CHANNEL = 'ircfiber'

def get_session():
    Path('/tmp/c.txt').write_text('')
    subprocess.run([
        'curl', '-s', '-D', '/tmp/c.txt',
        '-X', 'POST', f'{BASE}/login',
        '-d', f'username={creds["FIBER_USERNAME"]}&password={creds["FIBER_PASSWORD"]}',
        '-o', '/dev/null'
    ], capture_output=True, timeout=15)
    for line in Path('/tmp/c.txt').read_text().splitlines():
        if line.lower().startswith('set-cookie:'):
            m = re.search(r'vibe\.session_id=([^;]+)', line)
            if m:
                return m.group(1)
    return None

async def main():
    failures = []
    passed = 0

    cookie = get_session()
    if not cookie:
        print('FAIL: no cookie')
        return False
    print(f'cookie: {cookie[:20]}...')

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=['--disable-blink-features=AutomationControlled'])
        ctx = await browser.new_context(
            viewport={'width': 1400, 'height': 900},
            ignore_https_errors=True,
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        )
        await ctx.add_cookies([{
            'name': 'vibe.session_id', 'value': cookie,
            'domain': 'ircfiber.com', 'path': '/',
            'httpOnly': True, 'secure': True,
        }])
        page = await ctx.new_page()
        logs = []
        page.on('console', lambda msg: logs.append(f'[{msg.type[:4]}] {msg.text[:200]}'))
        page.on('pageerror', lambda err: logs.append(f'[err] {err.message[:200]}'))

        # ── 1. Navigate to IRC Fiber server buffer ──────────────────────────
        url = f'{BASE}/irc/{urllib.parse.quote(NETWORK_NAME)}'
        print(f'\n─── Test 1: Navigate to server buffer ───')
        print(f'Navigating to {url}')
        await page.goto(url, wait_until='domcontentloaded', timeout=30000)
        await page.wait_for_timeout(3000)
        await page.screenshot(path='/tmp/irf_test_1_loaded.png', full_page=True)

        # ── 2. If disconnected, click Connect and wait ──────────────────────
        print(f'\n─── Test 2: Connect to server ───')

        # Check current connection state
        lock_icons = page.locator('.fa-lock')
        disconnect_btn = page.locator('button:has-text("Disconnect")')
        connect_btn = page.locator('button:has-text("Connect")').first
        reconnect_btn = page.locator('button:has-text("Reconnect"), button:has-text("Click to reconnect")').first

        if await disconnect_btn.count() > 0:
            print('✅ Network already connected (Disconnect button visible)')
        elif await reconnect_btn.count() > 0 and await reconnect_btn.is_visible():
            print('Network disconnected — clicking Reconnect...')
            await reconnect_btn.click()
        elif await connect_btn.count() > 0:
            # Check if this is actually a reconnect/connect button in the log (not a card)
            # The real Connect button has text "Connect" and is in the page header
            body_text = await page.locator('body').text_content() or ''
            if 'Click to reconnect' in body_text:
                reconnect_link = page.locator('text=Click to reconnect')
                if await reconnect_link.count() > 0:
                    await reconnect_link.click()
                    print('Clicked "Click to reconnect" link')
            else:
                print('Network appears connected (no reconnect prompt)')

        # Wait for connection to establish (up to 60s)
        print('Waiting for connection (up to 60s)...')
        connected = False
        for i in range(60):
            lock_icon = await page.locator('.fa-lock').count()
            connecting_text = await page.locator('text=/Connecting…/i').count()
            disconnected_text = await page.locator('text=/Disconnected/i').count()
            server_info = await page.locator('text=/Server info/i').count()
            motd = await page.locator('text=/MOTD/i').count()
            await page.wait_for_timeout(1000)
            status = f'  [{i}s] lock={lock_icon} connecting={connecting_text} disconnected={disconnected_text} server_info={server_info} motd={motd}'
            print(status)
            if lock_icon > 0 and (server_info > 0 or motd > 0):
                connected = True
                print('  ✅ Connected with server info/MOTD visible!')
                break
            if i % 10 == 9:
                await page.screenshot(path=f'/tmp/irf_test_2_connecting_{i}.png', full_page=True)

        if not connected:
            failures.append('Network did not connect within 60s')
        else:
            passed += 1

        await page.screenshot(path='/tmp/irf_test_2_connected.png', full_page=True)

        # ── 3. Verify MOTD and server log grouping ──────────────────────────
        print(f'\n─── Test 3: MOTD + server log grouping ───')

        # Check for MOTD content
        motd_found = False
        for phrase in ['Message of the Day', 'MOTD', 'irc.ircfiber.com', 'Welcome to IRC Fiber']:
            if await page.locator(f'text=/{re.escape(phrase)}/i').count() > 0:
                motd_found = True
                print(f'  ✅ MOTD content found: "{phrase}"')
                break
        if not motd_found:
            failures.append('MOTD content not visible')
        else:
            passed += 1

        # Check for connected card with collapse/expand
        # Cards have status classes: status-success (connected), status-pending (connecting), status-disconnected
        connected_cards = page.locator('.serverLogCard__status:has-text("Connected")')
        if await connected_cards.count() > 0:
            print(f'  ✅ Connected cards visible: {await connected_cards.count()}')
            passed += 1

            # Find the most recent connected card header and toggle it
            # Look for the last (most recent) card header within a connected card
            card_headers = page.locator('.serverLogCard.header, .serverLogCard__header')
            ch_count = await card_headers.count()
            if ch_count > 0:
                # Click the first one to collapse, then again to expand
                await card_headers.first.click()
                await page.wait_for_timeout(500)
                await card_headers.first.click()
                await page.wait_for_timeout(500)
                print(f'  ✅ Card expand/collapse toggled ({ch_count} headers)')
                passed += 1
            else:
                failures.append('Card header not found for toggle')
        else:
            failures.append('Connected card not found')
            # Broader check
            connected_text = page.locator('text=Connected').first
            if await connected_text.count() > 0:
                print('  ⚠ "Connected" text found in page content')

        # Check for connection steps toggle
        phases_toggle = page.locator('button:has-text("Connection steps")')
        if await phases_toggle.count() > 0:
            print(f'  ✅ Connection steps toggle found ({await phases_toggle.count()})')
            # Click to expand phases
            await phases_toggle.first.click()
            await page.wait_for_timeout(800)
            phases_visible = await page.locator('.serverLogTimeline__item').count()
            print(f'  📊 Phase items visible: {phases_visible}')
            passed += 1
        else:
            failures.append('Connection steps toggle not found')

        await page.screenshot(path='/tmp/irf_test_3_motd.png', full_page=True)

        # ── 4. Verify auto-rejoin by triggering disconnect/reconnect ─────────
        print(f'\n─── Test 4: Auto-rejoin channels (disconnect → reconnect) ───')

        # First: disconnect the network to reset state
        print('Disconnecting network...')
        disconnect_btn = page.locator('button:has-text("Disconnect")').first
        if await disconnect_btn.count() > 0:
            await disconnect_btn.click()
            await page.wait_for_timeout(2000)
            await page.screenshot(path='/tmp/irf_test_4_disconnected.png', full_page=True)

        # Verify disconnect card appeared
        if await page.locator('text=/Disconnected/i').count() > 0:
            print('  ✅ Disconnect card appeared')
            passed += 1
        else:
            failures.append('Disconnect card did not appear')

        # Now reconnect by clicking Connect/Reconnect
        print('Reconnecting...')
        for btn_text in ['Connect', 'Click to reconnect']:
            btn = page.locator(f'button:has-text("{btn_text}")').first
            if await btn.count() > 0 and await btn.is_visible():
                await btn.click()
                print(f'  Clicked "{btn_text}"')
                break

        # Wait for #ircfiber to appear in the Active list after reconnection
        active_found = False
        for i in range(45):
            await page.wait_for_timeout(1000)
            ircfiber_tabs = page.locator('[role="tab"]:has-text("ircfiber")')
            ircfiber_count = await ircfiber_tabs.count()
            inactive_header = page.locator('.inactive-header')
            lock_icons = await page.locator('.fa-lock').count()

            if ircfiber_count > 0:
                # Check if Inactive section has #ircfiber in it
                inactive_items = page.locator('.inactive-channels [role="tab"]')
                try:
                    inactive_texts = await inactive_items.all_text_contents()
                except:
                    inactive_texts = []
                inactive_ircfiber = any('ircfiber' in t.lower() for t in inactive_texts)

                if not inactive_ircfiber:
                    active_found = True
                    print(f'  ✅ #ircfiber is ACTIVE (not in Inactive) at {i}s (lock={lock_icons})')
                    break
                print(f'  [{i}s] #ircfiber in Inactive, waiting... lock={lock_icons}')
            else:
                print(f'  [{i}s] #ircfiber tab not found... lock={lock_icons}')

            if i % 10 == 9:
                await page.screenshot(path=f'/tmp/irf_test_4_waiting_{i}.png', full_page=True)

        if not active_found:
            failures.append('#ircfiber did not become active within 45s after reconnect')
            await page.screenshot(path='/tmp/irf_test_4_fail.png', full_page=True)
            sidebar_tabs = await page.locator('[role="tab"]').all_text_contents()
            print(f'  📊 Sidebar tabs: {[t.strip()[:40] for t in sidebar_tabs]}')
        else:
            passed += 1

        # ── 5. Navigate to #ircfiber channel and verify member list ──────────
        print(f'\n─── Test 5: Join #ircfiber via URL navigation ───')
        channel_url = f'{BASE}/irc/{urllib.parse.quote(NETWORK_NAME)}/channel/{CHANNEL}'
        await page.goto(channel_url, wait_until='domcontentloaded', timeout=30000)
        await page.wait_for_timeout(5000)

        # Wait for member list to appear (indicates isJoined=true)
        member_found = False
        for i in range(20):
            members = await page.locator('.member-nick, .member-entry, [role="tab"]:has-text("admin_b520")').count()
            join_status = await page.locator('text=/Joining/i').count()
            rejoin_btn = await page.locator('button:has-text("Rejoin")').count()
            await page.wait_for_timeout(1000)
            if members > 0 and join_status == 0:
                member_found = True
                print(f'  ✅ Member list visible ({members} members) at {i}s')
                break
            if rejoin_btn > 0:
                print(f'  [{i}s] Rejoin button visible — clicking...')
                await page.locator('button:has-text("Rejoin")').click()

            if i % 5 == 4:
                print(f'  [{i}s] members={members} joining={join_status} rejoin={rejoin_btn}')

        if not member_found:
            failures.append('Member list did not appear within 20s')
            await page.screenshot(path='/tmp/irf_test_5_fail.png', full_page=True)
        else:
            passed += 1

        await page.screenshot(path='/tmp/irf_test_5_members.png', full_page=True)

        # ── Summary ─────────────────────────────────────────────────────────
        print(f'\n{"═" * 50}')
        print(f'Results: {passed} passed, {len(failures)} failed')
        if failures:
            print(f'\nFailures:')
            for f in failures:
                print(f'  ❌ {f}')
        else:
            print('  ✅ All tests passed!')

        if logs:
            # Filter for relevant errors only (exclude Cloudflare beacon)
            our_errors = [l for l in logs if 'cloudflare' not in l.lower() and 'beacon' not in l.lower()]
            if our_errors:
                print(f'\nConsole errors ({len(our_errors)}):')
                for l in our_errors[-10:]:
                    print(f'  {l}')

        await browser.close()
        return len(failures) == 0

asyncio.run(main())
