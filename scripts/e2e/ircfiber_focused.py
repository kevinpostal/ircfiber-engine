#!/usr/bin/env python3
"""Fast focused e2e test: join #welcome on IRC Fiber, send a message, see members.
Skips the login flow by reusing a saved session cookie.
"""
import asyncio
import sys
import time
import urllib.parse
import re
import json
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

def get_session_cookie():
    """Login via curl, capture vibe.session_id from the Set-Cookie header."""
    import subprocess
    Path('/tmp/e2e_headers.txt').write_text('')
    subprocess.run([
        'curl', '-s', '-D', '/tmp/e2e_headers.txt',
        '-X', 'POST', f'{BASE}/login',
        '-d', f'username={creds["FIBER_USERNAME"]}&password={creds["FIBER_PASSWORD"]}',
        '-o', '/dev/null'
    ], capture_output=True, text=True, timeout=15)
    headers = Path('/tmp/e2e_headers.txt').read_text()
    for line in headers.splitlines():
        if line.lower().startswith('set-cookie:'):
            m = re.search(r'vibe\.session_id=([^;]+)', line)
            if m:
                return m.group(1)
    return None

async def main():
    cookie = get_session_cookie()
    if not cookie:
        print('FAIL: could not get session cookie')
        return False
    print(f'Got session cookie: {cookie[:30]}...')

    failures = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=['--disable-blink-features=AutomationControlled'],
        )
        ctx = await browser.new_context(
            viewport={'width': 1400, 'height': 900},
            ignore_https_errors=True,
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        )
        await ctx.add_cookies([{
            'name': 'vibe.session_id',
            'value': cookie,
            'domain': 'ircfiber.com',
            'path': '/',
            'httpOnly': True,
            'secure': True,
        }])
        page = await ctx.new_page()
        logs = []
        page.on('console', lambda msg: logs.append(f'[{msg.type[:4]}] {msg.text[:200]}'))
        page.on('pageerror', lambda err: logs.append(f'[err] {err.message[:200]}'))

        # Navigate to the IRC Fiber channel page directly
        url = f'{BASE}/irc/{urllib.parse.quote(NETWORK_NAME)}/channel/{CHANNEL}'
        print(f'\nNavigating to {url}')
        await page.goto(url, wait_until='domcontentloaded', timeout=30000)
        await page.wait_for_timeout(3000)
        await page.screenshot(path='/tmp/e2e-1-loaded.png', full_page=True)

        # Wait for the connecting overlay to disappear
        print('Waiting for IRC engine to connect (up to 90s)...')
        deadline = time.time() + 90
        connected = False
        last_status = ''
        while time.time() < deadline:
            connecting_count = await page.locator('text=/connecting/i').count()
            reconnect_count = await page.locator('text=/reconnect/i').count()
            input_count = await page.locator('textarea[placeholder*="message" i]').count()
            member_count = await page.locator('.member-nick').count()
            status = f'connecting={connecting_count} reconnect={reconnect_count} inputs={input_count} members={member_count}'
            if status != last_status:
                print(f'  [{time.time()-deadline+90:.0f}s] {status}')
                last_status = status
            if connecting_count == 0 and reconnect_count == 0 and member_count > 0:
                connected = True
                break
            await page.wait_for_timeout(1000)
        if not connected:
            await page.screenshot(path='/tmp/e2e-stuck.png', full_page=True)
            print(f'  STUCK. {status}')
            for l in logs[-30:]:
                print(f'  {l}')
            failures.append('IRC engine did not reach connected state with members list visible')
        else:
            print(f'  ✓ IRC connected, members list visible ({member_count} entries)')

        # Find chat input
        chat_input = None
        for sel in ['textarea', 'input[placeholder*="message" i]']:
            loc = page.locator(sel).last
            if await loc.count() > 0:
                ph = (await loc.get_attribute('placeholder')) or ''
                if 'search' not in ph.lower():
                    chat_input = loc
                    print(f'  Found chat input: {sel} (placeholder="{ph}")')
                    break
        if not chat_input:
            failures.append('No chat input found')

        # Set nick
        if chat_input:
            print(f'\nSetting nick to {PROBE_NICK}...')
            await chat_input.click()
            await chat_input.fill(f'/nick {PROBE_NICK}')
            await chat_input.press('Enter')
            await page.wait_for_timeout(5000)

            own_visible = await page.locator(f'.member-nick:has-text("{PROBE_NICK}")').count() > 0
            print(f'  {PROBE_NICK} in own members list: {own_visible}')
            if not own_visible:
                await page.screenshot(path='/tmp/e2e-no-own-nick.png', full_page=True)
                members = page.locator('.member-nick')
                count = await members.count()
                print(f'  members panel has {count} entries:')
                for i in range(min(count, 30)):
                    txt = (await members.nth(i).text_content() or '').strip()
                    print(f'    - {txt[:60]}')
                failures.append(f'Own nick {PROBE_NICK} not in members list')

        # Send a test message
        if chat_input:
            test_msg = f'hello-from-e2e-{ts}'
            print(f'\nSending message: "{test_msg}"')
            await chat_input.click()
            await chat_input.fill(test_msg)
            await chat_input.press('Enter')
            await page.wait_for_timeout(3000)
            msg_visible = await page.locator(f'text="{test_msg}"').count() > 0
            print(f'  Message visible in own chat: {msg_visible}')
            if not msg_visible:
                failures.append('Sent message not visible in own chat')

        # Check for admin in the members list (the "admin" user)
        admin_count = await page.locator(f'.member-nick:has-text("admin")').count()
        print(f'\n"admin" in members list: {admin_count > 0}')
        if admin_count == 0:
            await page.screenshot(path='/tmp/e2e-no-admin.png', full_page=True)

        # Capture final state
        await page.screenshot(path='/tmp/e2e-final.png', full_page=True)

        # Final summary
        print(f'\n{"="*60}')
        if failures:
            print(f'FAIL — {len(failures)} issues:')
            for f in failures:
                print(f'  - {f}')
            return False
        print('PASS')
        await browser.close()
        return True

if __name__ == '__main__':
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)