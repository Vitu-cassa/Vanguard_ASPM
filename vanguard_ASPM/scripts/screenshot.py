"""
Captura screenshot do dashboard renderizado em Chromium headless.
Uso: python scripts/screenshot.py <url> <output.png>
"""
import sys
from playwright.sync_api import sync_playwright

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765/"
out = sys.argv[2] if len(sys.argv) > 2 else "evidencias-reais/13-dashboard-screenshot.png"

with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    ctx = browser.new_context(viewport={"width": 1440, "height": 1600}, device_scale_factor=2)
    page = ctx.new_page()
    page.goto(url, wait_until="networkidle")
    # dá tempo para o JS popular tabela/detalhe
    page.wait_for_selector("#rows tr", timeout=5000)
    page.screenshot(path=out, full_page=True)
    # também clica na linha do achado #1 e captura o painel de detalhe
    page.click("tr[data-id='1']")
    page.wait_for_selector("#detail:not(.hidden)", timeout=3000)
    detail_out = out.replace(".png", "-detail.png")
    page.screenshot(path=detail_out, full_page=True)
    browser.close()
    print(f"OK: {out}")
    print(f"OK: {detail_out}")
