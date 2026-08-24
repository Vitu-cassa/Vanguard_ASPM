"""Captura vistas filtradas do dashboard (LGPD apenas, HIGH apenas)."""
from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:8765/"

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    ctx = browser.new_context(viewport={"width": 1440, "height": 1200}, device_scale_factor=2)
    page = ctx.new_page()

    # Vista 1: filtro "apenas LGPD"
    page.goto(URL, wait_until="networkidle")
    page.wait_for_selector("#rows tr", timeout=5000)
    page.check("#fLgpd")
    page.wait_for_timeout(400)
    page.screenshot(path="evidencias-reais/14-dashboard-lgpd-only.png", full_page=True)

    # Vista 2: filtro severidade HIGH
    page.uncheck("#fLgpd")
    page.select_option("#fSev", "HIGH")
    page.wait_for_timeout(400)
    page.screenshot(path="evidencias-reais/15-dashboard-high-only.png", full_page=True)

    browser.close()
    print("OK: 14-dashboard-lgpd-only.png")
    print("OK: 15-dashboard-high-only.png")
