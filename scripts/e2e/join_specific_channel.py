#!/usr/bin/env python3
"""E2E diagnostic: navigate to /irc/Gang Net/channel/tclmafia and capture what happens."""
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
NETWORK_NAME = 'Gang Net'
CHANNEL = 'tclmafia'
ts = int(__import__('time').time())
PROBE_NICK = f'e2e_tclmafia_{ts}'

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
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
        )
        await ctx.add_cookies([{
            'name': 'vibe.session_id', 'value': cookie,
            'domain': 'ircfiber.com', 'path': '/', 'httpOnly': True, 'secure': True,
        }])
        page = await ctx.new_page()
        logs = []
        page.on('console', lambda msg: logs.append(f'[{msg.type[:4]}] {msg.text[:200]}'))
        page.on('pageerror', lambda err: logs.append(f'[err] {err.message[:200]}'))

        url = f'{BASE}/irc/{urllib.parse.quote(NETWORK_NAME)}/channel/{CHANNEL}'
        print(f'\nNavigating to {url}')
        await page.goto(url, wait_until='domcontentloaded', timeout=30000)
        await page.wait_for_timeout(5000)
        await page.screenshot(path='/tmp/tclmafia-1-loaded.png', full_page=True)

        # Wait for IRC engine to be ready
        print('Waiting for IRC engine to connect (up to 60s)...')
        for i in range(60):
            connecting = await page.locator('text=/connecting/i').count()
            reconnect = await page.locator('text=/reconnect/i').count()
            chat_input = await page.locator('textarea[placeholder*="message" i]').count()
            members = await page.locator('.member-nick').count()
            if chat_input > 0:
                print(f'  [{i}s] chat_input={chat_input} members={members} connecting={connecting} reconnect={reconnect}')
                if members > 0:
                    break
            await page.wait_for_timeout(1000)

        await page.screenshot(path='/tmp/tclmafia-2-after-wait.png', full_page=True)

        # Try to set nick
        chat_input = page.locator('textarea[placeholder*="message" i]').last
        if await chat_input.count() > 0:
            print(f'\nSetting nick to {PROBE_NICK}...')
            await chat_input.click()
            await chat_input.fill(f'/nick {PROBE_NICK}')
            await chat_input.press('Enter')
            await page.wait_for_timeout(5000)

        # Capture state
        await page.screenshot(path='/tmp/tclmafia-3-final.png', full_page=True)

        # Dump member list and status
        members = page.locator('.member-nick')
        mcount = await members.count()
        print(f'\nMembers in list: {mcount}')
        for i in range(min(mcount, 30)):
            txt = (await members.nth(i).text_content() or '').strip()
            print(f'  - {txt[:60]}')

        # Look for status text
        body = await page.locator('body').text_content() or ''
        if 'Joining' in body or 'Reconnect' in body or 'Failed' in body or 'banned' in body.lower() or 'invite' in body.lower():
            for line in body.split('\n'):
                line = line.strip()
                if line and any(w in line for w in ['Join', 'Reconnect', 'Failed', 'banned', 'invite', 'err', 'key']):
                    print(f'  status: {line[:200]}')

        if logs:
            print(f'\nConsole logs (last 15):')
            for l in logs[-15:]:
                print(f'  {l}')

        await browser.close()
        return mcount > 0

asyncio.run(main())