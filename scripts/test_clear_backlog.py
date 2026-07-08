"""E2E test: clear backlog → "Load more backlog" button disappears.

Usage:
  python scripts/test_clear_backlog.py
"""
import os, time, uuid
from playwright.sync_api import sync_playwright

BASE = os.environ.get("TEST_URL", "http://127.0.0.1:8090")
USER = f"test-{uuid.uuid4().hex[:8]}"
PASS = "testpass123"

def test():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()

        # ── 1. Register directly
        page.goto(f"{BASE}/register", wait_until="networkidle")
        page.wait_for_timeout(500)
        page.get_by_label("Username").fill(USER)
        page.get_by_label("Email").fill(f"{USER}@test.local")
        page.get_by_label("Password").fill(PASS)
        page.get_by_role("button", name="Create account").click()
        page.wait_for_timeout(2000)
        print(f"[1] Registered user {USER}")

        # ── 2. Navigate to chat
        page.goto(f"{BASE}", wait_until="networkidle")
        page.wait_for_timeout(3000)
        print(f"[2] Chat page loaded")

        # ── 3. Find server name in sidebar and right-click
        page.screenshot(path="/tmp/clear-test-1.png")
        print("[3] Screenshot saved")

        # Right-click the server/network name
        server_el = page.get_by_text("IRC Fiber").first
        server_el.click(button="right")
        page.wait_for_timeout(1000)

        # ── 4. Click "Clear backlog" in context menu
        clear_btn = page.get_by_text("Clear backlog")
        if clear_btn.count() > 0:
            clear_btn.click()
            page.wait_for_timeout(2000)
            print("[4] Clicked Clear backlog")
        else:
            print("[4] Clear backlog not found in context menu — taking screenshot")
            page.screenshot(path="/tmp/clear-test-2-noclear.png")

        page.screenshot(path="/tmp/clear-test-3-after-clear.png")

        # ── 5. Verify "Load more backlog" is absent
        load_more = page.get_by_text("Load more backlog")
        count = load_more.count()
        if count > 0:
            print(f"[FAIL] ❌ 'Load more backlog' visible ({count} times)!")
        else:
            print("[PASS] ✅ No 'Load more backlog' button after clearing")

        browser.close()

if __name__ == "__main__":
    test()
