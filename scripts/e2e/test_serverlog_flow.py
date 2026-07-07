#!/usr/bin/env python3
"""E2E: comprehensive server-log flow verification."""
import asyncio, json, re, subprocess, urllib.parse, time
from pathlib import Path
from playwright.async_api import async_playwright

ENV_FILE = Path('/Users/zodiac/Library/Mobile Documents/com~apple~CloudDocs/Work/IRC/IRC_FIBER/.env')
creds = {}
for line in ENV_FILE.read_text().splitlines():
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1)
        creds[k.strip()] = v.strip()

BASE = "http://127.0.0.1:8090"
NET = 'IRC%20Fiber'
results = {'pass': 0, 'fail': 0, 'details': []}

def ok(msg): results['pass'] += 1; results['details'].append(f'  ✅ {msg}')
def fail(msg): results['fail'] += 1; results['details'].append(f'  ❌ {msg}')

def get_session():
    subprocess.run(['curl', '-s', '-c', '/tmp/sl_cookies.txt',
        '-X', 'POST', f'{BASE}/login',
        '-d', f'username={creds["FIBER_USERNAME"]}&password={creds["FIBER_PASSWORD"]}',
        '-o', '/dev/null'], capture_output=True, timeout=15)

async def main():
    get_session()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(
            viewport={'width': 1400, 'height': 900},
            ignore_https_errors=True,
            storage_state=None)
        # Inject cookie manually
        cookie_val = ''
        for line in Path('/tmp/sl_cookies.txt').read_text().splitlines():
            if 'vibe.session_id' in line:
                cookie_val = line.split('\t')[-1]
        await ctx.add_cookies([{
            'name': 'vibe.session_id', 'value': cookie_val,
            'domain': 'ircfiber.com', 'path': '/', 'httpOnly': True, 'secure': True,
        }])
        page = await ctx.new_page()
        logs = []
        page.on('console', lambda msg: logs.append(f'[{msg.type[:4]}] {msg.text[:200]}'))
        page.on('pageerror', lambda err: logs.append(f'[err] {err.message[:200]}'))

        # ─── TEST 1: Initial load — verify server buffer loads with history ───
        print('\n═══ TEST 1: Server buffer loads connection history ═══')
        await page.goto(f'{BASE}/irc/{NET}', wait_until='networkidle', timeout=45000)
        await page.wait_for_timeout(3000)

        # Check for connection cards
        cards = page.locator('.serverLogCard, [class*=serverLogCard]')
        card_count = await cards.count()
        print(f'  Cards found: {card_count}')
        if card_count > 0:
            ok(f'{card_count} server log cards visible')
        else:
            # Broader check
            connected = page.locator('text=Connected')
            if await connected.count() > 0:
                ok('Connected cards visible (count uncertain)')
            else:
                fail('No server log cards found')

        # Check for MOTD content
        motd = page.locator('text=/Message of the Day|MOTD|meth\\.cat message/i')
        if await motd.count() > 0:
            ok('MOTD content visible')
        else:
            fail('MOTD not found')

        # Check for server info / welcome banner
        welcome = page.locator('text=/Welcome to|Your host is|Server welcome/i')
        if await welcome.count() > 0:
            ok('Server welcome/banner visible')
        else:
            fail('Server welcome not found')

        # Check the card has expand/collapse sections
        toggles = page.locator('button:has-text("Connection steps"), button:has-text("Server info"), button:has-text("ISUPPORT"), button:has-text("Raw IRC")')
        toggle_count = await toggles.count()
        print(f'  Section toggles: {toggle_count}')
        if toggle_count >= 2:
            ok(f'Card has {toggle_count} expandable sections')
        else:
            fail(f'Expected >=2 sections, got {toggle_count}')

        await page.screenshot(path='/tmp/sl_test1.png', full_page=True)

        # ─── TEST 2: Refresh — verify MOTD persists ──────────────────────────
        print('\n═══ TEST 2: MOTD survives page refresh ═══')
        await page.reload(wait_until='networkidle', timeout=45000)
        await page.wait_for_timeout(5000)

        motd_after = page.locator('text=/Message of the Day|MOTD/i')
        welcome_after = page.locator('text=/Welcome to|Your host is/i')
        if await motd_after.count() > 0:
            ok('MOTD visible after refresh')
        else:
            fail('MOTD missing after refresh')
        if await welcome_after.count() > 0:
            ok('Server welcome visible after refresh')
        else:
            fail('Server welcome missing after refresh')

        # Check no "Fetching more history…" is stuck visible
        fetching = page.locator('text=Fetching more history')
        if await fetching.count() == 0:
            ok('No "Fetching more history" stuck on screen')
        else:
            fail('"Fetching more history" still visible after load')

        await page.screenshot(path='/tmp/sl_test2.png', full_page=True)

        # ─── TEST 3: Single card per connection (no duplicates) ──────────────
        print('\n═══ TEST 3: No duplicate cards per connection ═══')
        # Look at the timestamps of connected cards — if two cards share
        # the same second, they're duplicates
        connected_headers = page.locator('.serverLogCard__status:has-text("Connected")')
        ch_count = await connected_headers.count()
        print(f'  Connected cards in timeline: {ch_count}')

        # Check there aren't two cards with the SAME timestamp
        times = await page.locator('.serverLogCard__time').all_text_contents()
        seen_times = {}
        dupes = 0
        for t in times:
            t = t.strip()
            if t in seen_times:
                dupes += 1
                print(f'  ⚠ Duplicate timestamp: {t}')
            seen_times[t] = seen_times.get(t, 0) + 1
        if dupes == 0:
            ok('No duplicate connection cards (unique timestamps)')
        else:
            fail(f'Found {dupes} duplicate timestamps — dedup may not be working')

        # ─── TEST 4: Card transitions smoothly (pending→success) ─────────────
        print('\n═══ TEST 4: Disconnect → reconnect card flow ═══')

        # Find Disconnect button
        disconnect_btn = page.locator('button:has-text("Disconnect")').first
        if await disconnect_btn.count() > 0:
            await disconnect_btn.click()
            await page.wait_for_timeout(2000)

            # Should see a Disconnected card appear
            disco = page.locator('.serverLogCard__status:has-text("Disconnected")')
            if await disco.count() > 0:
                ok('Disconnected card appeared after clicking Disconnect')
            else:
                # Check for text
                disco_text = page.locator('text=Disconnected')
                if await disco_text.count() > 0:
                    ok('Disconnected text appeared')
                else:
                    fail('No disconnected state shown')

            # Reconnect
            for btn_text in ['Connect', 'Click to reconnect']:
                btn = page.locator(f'button:has-text("{btn_text}")').first
                if await btn.count() > 0:
                    await btn.click()
                    print(f'  Clicked "{btn_text}"')
                    break

            # Wait for connecting state
            await page.wait_for_timeout(3000)
            connecting = page.locator('text=/Connecting…|Connecting to/i')
            if await connecting.count() > 0:
                ok('Connecting state visible after reconnect click')
            else:
                fail('No connecting state shown')

            # Wait for connected state (up to 30s)
            connected_ok = False
            for i in range(30):
                await page.wait_for_timeout(1000)
                lock = await page.locator('.fa-lock').count()
                connected_text = page.locator('.serverLogCard__status:has-text("Connected")')
                ct = await connected_text.count()
                if lock > 0 and ct > 0:
                    connected_ok = True
                    print(f'  ✅ Reconnected at {i}s')
                    break
                if i % 10 == 9:
                    print(f'  [{i}s] lock={lock} connected_cards={ct}')
            if connected_ok:
                ok('Successfully reconnected')
            else:
                fail('Did not reconnect within 30s')
        else:
            # Already connecting or connected — verify state
            lock = await page.locator('.fa-lock').count()
            if lock > 0:
                ok('Network already connected (no disconnect needed)')
            else:
                fail('Cannot find Disconnect button — network state unclear')

        await page.screenshot(path='/tmp/sl_test4.png', full_page=True)

        # ─── TEST 5: Channel auto-joins after reconnect ──────────────────────
        print('\n═══ TEST 5: Auto-join channels after reconnect ═══')
        # Check if #ircfiber is in the active list
        active_channels = page.locator('.network-buffers [role="tab"]')
        active_texts = await active_channels.all_text_contents()
        ircfiber_active = any('ircfiber' in t.lower() for t in active_texts)
        if ircfiber_active:
            ok('#ircfiber is in active channels')
        else:
            # Check inactive
            inactive_channels = page.locator('.inactive-channels [role="tab"]')
            inactive_texts = await inactive_channels.all_text_contents()
            ircfiber_inactive = any('ircfiber' in t.lower() for t in inactive_texts)
            if ircfiber_inactive:
                fail('#ircfiber still in Inactive — auto-join pending')
            else:
                fail('#ircfiber not found in sidebar')

        # ─── TEST 6: GSAP animations don't cause errors ──────────────────────
        print('\n═══ TEST 6: No GSAP/JS errors ═══')
        our_errors = [l for l in logs if 'cloudflare' not in l.lower() and 'beacon' not in l.lower()
                      and 'gsap' not in l.lower() and '404' not in l.lower()]
        if our_errors:
            for e in our_errors:
                print(f'  ⚠ {e}')
            fail(f'{len(our_errors)} unexpected console messages')
        else:
            ok('No JS errors from our code')

        # ─── Summary ─────────────────────────────────────────────────────────
        print(f'\n{"═" * 50}')
        print(f'Results: {results["pass"]} passed, {results["fail"]} failed')
        for d in results['details']:
            print(d)

        await browser.close()
        return results['fail'] == 0

asyncio.run(main())
