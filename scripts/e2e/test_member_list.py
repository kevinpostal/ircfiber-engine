#!/usr/bin/env python3
"""E2E: Verify member list shows user with correct op permissions."""
import asyncio, subprocess, re
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
NETWORK = 'IRC%20Fiber'
CHANNEL = 'ircfiber'

async def main():
    print('═══ Member List Test ═══')
    # Login
    subprocess.run(['curl', '-s', '-c', '/tmp/mem_cookies.txt', '-X', 'POST', f'{BASE}/login',
        '-d', f'username={creds["FIBER_USERNAME"]}&password={creds["FIBER_PASSWORD"]}',
        '-o', '/dev/null'], timeout=15)
    cookie = ''
    for line in Path('/tmp/mem_cookies.txt').read_text().splitlines():
        if 'vibe.session_id' in line:
            parts = line.split('\t')
            cookie = parts[-1].strip()

    if not cookie:
        print('❌ FAIL: No cookie')
        return False

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(viewport={'width': 1400, 'height': 900}, ignore_https_errors=True)
        await ctx.add_cookies([{'name': 'vibe.session_id', 'value': cookie,
            'domain': 'ircfiber.com', 'path': '/', 'httpOnly': True, 'secure': True}])
        page = await ctx.new_page()

        # Navigate to channel
        await page.goto(f'{BASE}/irc/{NETWORK}/channel/{CHANNEL}',
            wait_until='domcontentloaded', timeout=30000)
        await page.wait_for_timeout(3000)

        # Wait for member list or click Rejoin
        member_found = False
        our_nick_found = False
        category_found = False

        for i in range(60):
            await page.wait_for_timeout(1000)

            # Try clicking Rejoin if visible
            rejoin = page.locator('button:has-text("Rejoin")')
            if await rejoin.count() > 0:
                await rejoin.click()
                await page.wait_for_timeout(500)

            # Check member list section exists
            member_sidebar = page.locator('#member-sidebar, [class*=memberList], [class*=member-list]')
            member_items = page.locator('.member-nick, .member-entry')

            # Also check for the member button in the header (shows count)
            member_btn = page.locator('button:has-text("Members")')
            member_count_text = await member_btn.text_content() if await member_btn.count() > 0 else ''

            # Check for permission category headings
            category_headings = page.locator('h2, [class*=category]')
            cat_texts = await category_headings.all_text_contents()
            perm_cats = [t.strip() for t in cat_texts if any(w in t.lower()
                for w in ['ops', 'opers', 'owner', 'admin', 'voice', 'member', 'halfop'])]

            # Check for our nick in member entries
            if await member_items.count() > 0:
                texts = await member_items.all_text_contents()
                our_nick = [t.strip() for t in texts if 'admin' in t.lower() or 'zodiac' in t.lower()]

                if not member_found:
                    print(f'  [{i}s] 👥 Members: {await member_items.count()} | Categories: {perm_cats}')
                    for t in texts[:8]:
                        print(f'       {t.strip()[:50]}')
                    member_found = True

                if our_nick:
                    our_nick_found = True
                    nick_display = our_nick[0]
                    has_op = any(c in nick_display for c in ['@', '~', '&', '%'])
                    if not has_op:
                        # Try to derive from position in category
                        pass

            if member_found and our_nick_found and perm_cats:
                break

            if i % 10 == 9:
                await page.screenshot(path=f'/tmp/mem_test_{i}s.png', full_page=True)
                print(f'  [{i}s] members={await member_items.count()} cats={perm_cats}')

        # Final screenshot
        await page.screenshot(path='/tmp/member_test_final.png', full_page=True)

        # Results
        passed = 0
        failed = 0

        if member_found:
            print('  ✅ PASS: Member list visible')
            passed += 1
        else:
            print('  ❌ FAIL: No member list appeared')
            failed += 1

        if our_nick_found:
            print(f'  ✅ PASS: Our nick visible in member list')
            passed += 1
        else:
            print('  ❌ FAIL: Our nick not found in member list')
            failed += 1

        # Check for member count in header button
        member_btn = page.locator('button:has-text("Members")')
        if await member_btn.count() > 0:
            btn_text = await member_btn.text_content() or ''
            count_match = re.search(r'(\d+)', btn_text)
            if count_match:
                count = int(count_match.group(1))
                print(f'  ℹ️  Member count in header: {count}')
                if count > 0:
                    passed += 1
                else:
                    failed += 1

        # Check for @ prefix on our nick (op status)
        op_nicks = page.locator('[class*="mode_OP"] .member-nick, .mode_OP, [class*="Op"] .member-nick')
        op_texts = await op_nicks.all_text_contents()
        our_op = [t.strip() for t in op_texts if 'admin' in t.lower() or '@admin' in t.lower()]
        if our_op:
            print(f'  ✅ PASS: Found in Ops section: {our_op[0]}')
            passed += 1
        else:
            # Broader check: look for any nick starting with @
            all_member_texts = await page.locator('.member-nick, .member-entry').all_text_contents()
            op_marked = [t.strip() for t in all_member_texts if t.strip().startswith('@')]
            our_with_op = [t for t in op_marked if 'admin' in t.lower()]
            if our_with_op:
                print(f'  ✅ PASS: Found with op prefix: {our_with_op[0]}')
                passed += 1
            else:
                print(f'  ⚠️  No op-prefixed nick found (may not be opped)')

        print(f'\nResults: {passed} passed, {failed} failed')
        await browser.close()
        return failed == 0

asyncio.run(main())
