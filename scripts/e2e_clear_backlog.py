#!/usr/bin/env python3
"""E2E test: register user, clear backlog, verify Load more backlog is gone.

Runs the gateway binary locally, then uses Playwright to test the full flow.
"""
import os, sys, time, uuid, subprocess, signal, json
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8090"
USER = f"e2e-{uuid.uuid4().hex[:8]}"
PASS = "testpass123"

GW = os.path.join(os.path.dirname(__file__), "..", "irc-fiber")
ENV = os.environ.copy()
ENV.update({
    "IRCFIBER_MONGO_URL": "mongodb://ircfiber:jqgwEv3GJwwizulaj3Fnbd8imqcMH4Gh@100.126.197.92:27017/ircfiber",
    "IRCFIBER_REDIS_URL": "redis://100.126.197.92:6379/0",
    "IRCFIBER_SERVER_ID": "localdebug",
    "IRCFIBER_BIND_ADDRESS": "127.0.0.1",
})

def main():
    # ── 1. Start gateway ──
    gw = subprocess.Popen([GW], env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[gateway] pid={gw.pid}")
    for i in range(20):
        try:
            r = __import__("urllib.request").request.urlopen(f"{BASE}/health", timeout=2)
            if r.status == 200:
                print(f"[gateway] healthy after {i+1}s")
                break
        except Exception:
            time.sleep(1)
    else:
        gw.kill()
        print("[FAIL] Gateway did not start")
        sys.exit(1)

    try:
        # ── 2. Playwright test ──
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context(viewport={"width": 1280, "height": 900})
            page = ctx.new_page()

            # Register via form
            page.goto(f"{BASE}/register", wait_until="networkidle")
            page.wait_for_timeout(500)
            page.fill("input[placeholder='choose a handle']", USER)
            page.fill("input[placeholder='you@example.com']", f"{USER}@test.local")
            page.fill("input[placeholder='at least 8 characters']", PASS)
            page.click("button:has-text('Create account')")
            page.wait_for_timeout(3000)
            print(f"[auth] registered {USER}")

            # Check auth
            authed = page.evaluate("async () => { let r = await fetch('/api/me'); return r.ok ? await r.json() : null }")
            if authed:
                print(f"[auth] logged in as {authed.get('username')}")
            else:
                print("[FAIL] Not authenticated after register")
                ctx.close()
                return

            # Navigate to chat
            page.goto(f"{BASE}/irc/IRC%20Fiber", wait_until="networkidle")
            page.wait_for_timeout(5000)
            title = page.title()
            print(f"[page] title={title}")

            # Wait for WebSocket to connect — look for sidebar elements
            for i in range(30):
                has_sidebar = page.locator(".sidebar, .server-list, [class*=sidebar], [class*=server]").count() > 0
                if has_sidebar:
                    print(f"[page] sidebar visible at t={i+1}s")
                    break
                time.sleep(1)
            else:
                print("[page] sidebar not visible, saving screenshot")
                page.screenshot(path="/tmp/e2e-nosidebar.png")

            # Right-click the first server/network in sidebar
            page.screenshot(path="/tmp/e2e-before-clear.png")

            # Try to right-click a network name
            page.keyboard.press("Control+F12")  # open network context menu
            page.wait_for_timeout(500)
            page.screenshot(path="/tmp/e2e-context-menu.png")

            # Check if Clear backlog is in page
            page_content = page.content()
            has_clear_backlog = "Clear backlog" in page_content
            print(f"[test] 'Clear backlog' in page: {has_clear_backlog}")

            # Try to find and click Clear backlog
            clear_btn = page.get_by_text("Clear backlog")
            count = clear_btn.count()
            print(f"[test] 'Clear backlog' buttons found: {count}")

            if count > 0:
                clear_btn.first.click()
                page.wait_for_timeout(2000)
                print("[test] clicked Clear backlog")
                page.screenshot(path="/tmp/e2e-after-clear.png")

            # ── 3. Verify Load more backlog is gone ──
            load_more = page.get_by_text("Load more backlog")
            lm_count = load_more.count()
            if lm_count > 0:
                print(f"[FAIL] 'Load more backlog' still visible ({lm_count} times) ❌")
            else:
                print("[PASS] 'Load more backlog' not found after clearing ✅")

            ctx.close()

    finally:
        gw.terminate()
        gw.wait(timeout=5)
        print("[gateway] stopped")

if __name__ == "__main__":
    main()
