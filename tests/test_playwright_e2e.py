import sys
import os
import json
import time
import asyncio
from typing import List, Dict, Any
from playwright.async_api import async_playwright, Page, Response, ConsoleMessage, Error

# Ensure UTF-8 output encoding for Windows console
if hasattr(sys.stdout, 'reconfigure'):
    getattr(sys.stdout, 'reconfigure')(encoding='utf-8')

STREAMLIT_URL = "http://localhost:8501"
FASTAPI_URL = "http://127.0.0.1:8000"
ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "playwright_reports")
os.makedirs(ARTIFACTS_DIR, exist_ok=True)

class PlaywrightAppTester:
    def __init__(self):
        self.console_errors: List[str] = []
        self.page_errors: List[str] = []
        self.failed_requests: List[Dict[str, Any]] = []
        self.issues_found: List[Dict[str, Any]] = []
        self.passed_checks: List[str] = []

    def log_issue(self, category: str, title: str, description: str, severity: str = "MEDIUM"):
        issue = {
            "category": category,
            "title": title,
            "description": description,
            "severity": severity,
            "timestamp": time.strftime("%H:%M:%S")
        }
        self.issues_found.append(issue)
        print(f"❌ [{severity}] {category}: {title} - {description}")

    def log_pass(self, title: str):
        self.passed_checks.append(title)
        print(f"✅ PASS: {title}")

    def setup_listeners(self, page: Page):
        def handle_console(msg: ConsoleMessage):
            if msg.type == "error":
                err_text = f"[Console Error] {msg.text} (Location: {msg.location})"
                self.console_errors.append(err_text)
                print(f"⚠️ {err_text}")

        def handle_page_error(error: Error):
            err_text = f"[Uncaught Page Error] {error.name}: {error.message}\n{error.stack}"
            self.page_errors.append(err_text)
            print(f"💥 {err_text}")

        def handle_response(response: Response):
            if response.status >= 400:
                req_info = {
                    "url": response.url,
                    "status": response.status,
                    "status_text": response.status_text,
                }
                self.failed_requests.append(req_info)
                print(f"⚠️ HTTP {response.status} from {response.url}")

        page.on("console", handle_console)
        page.on("pageerror", handle_page_error)
        page.on("response", handle_response)

    async def test_fastapi_backend(self, playwright):
        print("\n=========================================")
        print("🔍 Phase 1: Playwright API Testing (FastAPI Backend)")
        print("=========================================")
        request = playwright.request
        api_context = await request.new_context(base_url=FASTAPI_URL)

        # 1. Health Endpoint
        res = await api_context.get("/health")
        if res.status == 200:
            body = await res.json()
            if body.get("status") == "ok":
                self.log_pass(f"FastAPI Health Check (/health) -> {body}")
            else:
                self.log_issue("API", "Health Check Unexpected Payload", f"Received {body}", "HIGH")
        else:
            self.log_issue("API", "Health Check Failed", f"HTTP {res.status}", "CRITICAL")

        # 2. Swagger Docs Endpoint
        res_docs = await api_context.get("/docs")
        if res_docs.status == 200:
            self.log_pass("FastAPI OpenAPI Docs (/docs) accessible")
        else:
            self.log_issue("API", "Swagger UI Inaccessible", f"HTTP {res_docs.status}", "MEDIUM")

        # 3. Test /scan with valid URL
        scan_payload = {"url": "http://example.com"}
        res_scan = await api_context.post("/scan", data=json.dumps(scan_payload), headers={"Content-Type": "application/json"})
        if res_scan.status == 200:
            data = await res_scan.json()
            if "s_phish" in data and "s_lex" in data:
                self.log_pass(f"FastAPI Single Scan (/scan) -> s_phish: {data.get('s_phish')}, latency: {data.get('latency_ms')}ms")
            else:
                self.log_issue("API", "Scan Response Missing Fields", f"Payload: {data}", "HIGH")
        else:
            self.log_issue("API", "Single Scan API Failed", f"HTTP {res_scan.status}: {await res_scan.text()}", "HIGH")

        # 4. Test /scan with malformed URL (Edge case)
        res_bad = await api_context.post("/scan", data=json.dumps({"url": "invalid-url-string"}), headers={"Content-Type": "application/json"})
        if res_bad.status in [200, 400, 422]:
            self.log_pass(f"FastAPI Edge Case Malformed URL -> HTTP {res_bad.status}")
        else:
            self.log_issue("API", "Unexpected Status on Malformed URL", f"HTTP {res_bad.status}", "MEDIUM")

        # 5. Test /scan/batch
        batch_payload = {"urls": ["http://example.com", "https://google.com"], "max_concurrency": 2}
        res_batch = await api_context.post("/scan/batch", data=json.dumps(batch_payload), headers={"Content-Type": "application/json"})
        if res_batch.status == 200:
            bdata = await res_batch.json()
            if bdata.get("scanned_count") == 2:
                self.log_pass(f"FastAPI Batch Scan (/scan/batch) -> Scanned {bdata.get('scanned_count')} URLs successfully")
            else:
                self.log_issue("API", "Batch Scan Result Count Mismatch", f"Scanned: {bdata.get('scanned_count')}", "MEDIUM")
        else:
            self.log_issue("API", "Batch Scan API Failed", f"HTTP {res_batch.status}", "HIGH")

        # 6. Test Export Endpoints - execute real scan first to get a full ScanResult object
        real_scan_resp = await api_context.post("/scan", data=json.dumps({"url": "http://paypa1-security.tk"}), headers={"Content-Type": "application/json"})
        if real_scan_resp.status == 200:
            full_scan_result = await real_scan_resp.json()
        else:
            full_scan_result = {
                "url": "http://paypa1-security.tk",
                "matched_brand": "paypal",
                "s_phish": 0.95,
                "s_lex": 0.8,
                "s_dom": 0.9,
                "s_vis": 0.95,
                "shap_contributions": {"s_lex": 0.3, "s_dom": 0.3, "s_vis": 0.4},
                "confidence": "full",
                "latency_ms": 120.0
            }
        
        # Firewall Export
        res_fw = await api_context.post("/export/firewall", data=json.dumps({"scan_result": full_scan_result}), headers={"Content-Type": "application/json"})
        if res_fw.status == 200:
            fw_json = await res_fw.json()
            if "palo_alto_cli" in fw_json and "cloudflare_waf_json" in fw_json:
                self.log_pass("FastAPI Firewall Export (/export/firewall) -> Palo Alto & Cloudflare rules generated")
            else:
                self.log_issue("API", "Firewall Export Missing Formats", f"Keys: {list(fw_json.keys())}", "MEDIUM")
        else:
            self.log_issue("API", "Firewall Export Failed", f"HTTP {res_fw.status}", "HIGH")

        # STIX Export
        res_stix = await api_context.post("/export/stix", data=json.dumps({"scan_results": [full_scan_result]}), headers={"Content-Type": "application/json"})
        if res_stix.status == 200:
            stix_json = await res_stix.json()
            if stix_json.get("type") == "bundle":
                self.log_pass("FastAPI STIX 2.1 Export (/export/stix) -> Bundle generated successfully")
            else:
                self.log_issue("API", "STIX Export Invalid Type", f"Payload type: {stix_json.get('type')}", "MEDIUM")
        else:
            self.log_issue("API", "STIX Export Failed", f"HTTP {res_stix.status}: {await res_stix.text()}", "HIGH")

        # Takedown Notice Generation
        res_td = await api_context.post("/takedown/generate", data=json.dumps({"scan_result": full_scan_result}), headers={"Content-Type": "application/json"})
        if res_td.status == 200:
            td_json = await res_td.json()
            if "body_text" in td_json and "target_domain" in td_json:
                self.log_pass("FastAPI Takedown Notice Generator (/takedown/generate) -> Legal notice body created")
            else:
                self.log_issue("API", "Takedown Notice Missing Fields", f"Keys: {list(td_json.keys())}", "MEDIUM")
        else:
            self.log_issue("API", "Takedown Notice Generator Failed", f"HTTP {res_td.status}", "HIGH")

        await api_context.dispose()

    async def test_streamlit_frontend(self, playwright):
        print("\n=========================================")
        print("🖥️ Phase 2: Playwright UI Testing (Streamlit App)")
        print("=========================================")
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900},
            record_video_dir=ARTIFACTS_DIR
        )
        
        # Enable tracing for deep analysis
        await context.tracing.start(screenshots=True, snapshots=True, sources=True)

        page = await context.new_page()
        self.setup_listeners(page)

        try:
            # 1. Open Streamlit UI
            print(f"⏳ Navigating to {STREAMLIT_URL}...")
            response = await page.goto(STREAMLIT_URL, wait_until="networkidle", timeout=25000)
            if response and response.status == 200:
                self.log_pass("Streamlit UI main page loaded (HTTP 200)")
            else:
                self.log_issue("UI", "Main Page Load Failed", f"Response: {response}", "CRITICAL")
                return

            # Wait for Streamlit app iframe/components to hydrate
            await page.wait_for_selector('button[role="tab"], [data-testid="stTab"], [data-baseweb="tab"]', timeout=15000)
            await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "01_streamlit_home.png"), full_page=True)

            # 2. Check Branding & System Diagnostics
            page_text = await page.content()
            if "CloneCatcher AI" in page_text:
                self.log_pass("Found 'CloneCatcher AI' banner header")
            else:
                self.log_issue("UI", "Header Banner Missing", "Could not locate 'CloneCatcher AI' banner text", "HIGH")

            if "CONNECTED TO BACKEND" in page_text:
                self.log_pass("System Diagnostics shows 'CONNECTED TO BACKEND'")
            elif f"Offline at {FASTAPI_URL}" in page_text:
                self.log_issue("UI", "Backend Diagnostics Disconnected", "Streamlit UI claims backend is offline", "HIGH")

            # 3. Test Main Navigation Tabs using get_by_role("tab") or data-testid="stTab"
            tabs = page.get_by_role("tab")
            tab_count = await tabs.count()
            self.log_pass(f"Found {tab_count} total tabs on page (main + subtabs)")

            if tab_count == 0:
                # Fallback check
                tabs = page.locator('[data-testid="stTab"]')
                tab_count = await tabs.count()

            # Main tabs by text
            single_tab = page.get_by_role("tab", name="Single URL Deep Triage")
            batch_tab = page.get_by_role("tab", name="Multi-URL Batch Queue Scanner")
            lab_tab = page.get_by_role("tab", name="Model Performance & Data Lab")

            if await single_tab.count() > 0:
                self.log_pass("Found 'Single URL Deep Triage' main tab")
            else:
                self.log_issue("UI", "Single URL Tab Missing", "Could not locate Single URL tab", "HIGH")

            # Tab 1: Single URL Deep Triage
            if await single_tab.count() > 0:
                await single_tab.click()
                await page.wait_for_timeout(1000)
                self.log_pass("Switched to 'Single URL Deep Triage' tab")

            # Test URL Input and Submit
            input_box = page.get_by_placeholder("Enter target URL")
            if await input_box.count() == 0:
                input_box = page.locator('input[type="text"]').first

            if await input_box.count() > 0:
                self.log_pass("Found Target URL input text field")
                await input_box.fill("http://example.com")
                await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "02_input_filled.png"))

                # Click Submit Button
                run_btn = page.get_by_role("button", name="Run Live Scan")
                if await run_btn.count() > 0:
                    await run_btn.click()
                    print("⏳ Executing live scan on http://example.com...")
                    # Wait for results
                    await page.wait_for_timeout(10000)
                    await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "03_scan_results.png"), full_page=True)

                    res_text = await page.content()
                    if "Phishing Probability" in res_text or "VERIFIED SAFE" in res_text or "CRITICAL PHISHING" in res_text:
                        self.log_pass("Live Scan completed and verdict banner rendered successfully!")
                    else:
                        self.log_issue("UI", "Scan Result Banner Not Found", "Verdict banner did not render after clicking Run Live Scan", "HIGH")

                    # Click through forensic workspace subtabs
                    subtab_names = [
                        "Signal Attribution",
                        "Live Web Surface Render",
                        "TLS & Cryptographic Telemetry",
                        "DOM & Form Forensics",
                        "Threat Intel & SIEM Rules",
                        "Pipeline Data Flow & Architecture"
                    ]
                    
                    for sub_n in subtab_names:
                        try:
                            sub_elem = page.get_by_role("tab", name=sub_n)
                            if await sub_elem.count() > 0:
                                await sub_elem.click()
                                await page.wait_for_timeout(1000)
                                self.log_pass(f"Forensic Subtab clicked: '{sub_n}'")
                        except Exception as ex:
                            self.log_issue("UI", f"Subtab Click Error '{sub_n}'", str(ex), "MEDIUM")

                    # Test Threat Intel & SIEM Rules Subtab Buttons
                    siem_tab = page.get_by_role("tab", name="Threat Intel & SIEM Rules")
                    if await siem_tab.count() > 0:
                        await siem_tab.click()
                        await page.wait_for_timeout(1000)

                        # Test Webhook Dispatch button
                        wh_btn = page.get_by_role("button", name="Dispatch Real-Time SOC Alert")
                        if await wh_btn.count() > 0:
                            await wh_btn.click()
                            await page.wait_for_timeout(2000)
                            wh_text = await page.content()
                            if "dispatched successfully" in wh_text:
                                self.log_pass("Webhook Dispatch executed successfully!")
                            elif "failed" in wh_text or "error" in wh_text:
                                self.log_issue("UI", "Webhook Dispatch Failed", "UI displayed error notification", "MEDIUM")

                        # Test Abuse Takedown Package Button
                        td_btn = page.get_by_role("button", name="Generate Official Abuse Takedown Package")
                        if await td_btn.count() > 0:
                            await td_btn.click()
                            await page.wait_for_timeout(3000)
                            td_text = await page.content()
                            if "Takedown package generated" in td_text:
                                self.log_pass("1-Click Abuse Takedown Package generated successfully!")
                            else:
                                self.log_issue("UI", "Takedown Notice Generation Failed", "UI did not show success banner", "MEDIUM")
            else:
                self.log_issue("UI", "URL Input Box Missing", "Target URL text input element not found in DOM", "HIGH")

            # Tab 2: Multi-URL Batch Queue Scanner
            if await batch_tab.count() > 0:
                await batch_tab.click()
                await page.wait_for_timeout(1000)
                self.log_pass("Switched to 'Multi-URL Batch Queue Scanner' tab")
                await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "04_batch_tab.png"))

                batch_area = page.get_by_role("textbox", name="Paste URLs (one per line)")
                if await batch_area.count() == 0:
                    batch_area = page.locator('textarea[placeholder*="http://paypa1"]')

                if await batch_area.count() > 0:
                    await batch_area.fill("http://example.com\nhttps://google.com")
                    batch_btn = page.get_by_role("button", name="Start Batch Scan")
                    if await batch_btn.count() > 0:
                        await batch_btn.click()
                        print("⏳ Executing batch scan...")
                        await page.wait_for_timeout(8000)
                        await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "05_batch_results.png"), full_page=True)

                        b_text = await page.content()
                        if "Batch execution completed" in b_text or "Total Submitted" in b_text:
                            self.log_pass("Batch Queue Scan completed and displayed results table!")
                        else:
                            self.log_issue("UI", "Batch Results Missing", "Batch results table not rendered", "HIGH")

            # Tab 3: Model Performance & Data Lab
            if await lab_tab.count() > 0:
                await lab_tab.click()
                await page.wait_for_timeout(1000)
                self.log_pass("Switched to 'Model Performance & Data Lab' tab")
                await page.screenshot(path=os.path.join(ARTIFACTS_DIR, "06_data_lab_tab.png"))

                lab_text = await page.content()
                if "99.98%" in lab_text and "Model Accuracy" in lab_text:
                    self.log_pass("Model Data Lab metrics (99.98% Accuracy) rendered cleanly!")
                else:
                    self.log_issue("UI", "Data Lab Metrics Missing", "Model accuracy metrics missing", "MEDIUM")

        except Exception as e:
            self.log_issue("UI", "Unhandled Automation Exception", f"{type(e).__name__}: {str(e)}", "CRITICAL")

        finally:
            await context.tracing.stop(path=os.path.join(ARTIFACTS_DIR, "trace.zip"))
            await browser.close()
            print(f"\n🎥 Traces saved to {os.path.join(ARTIFACTS_DIR, 'trace.zip')}")
            print(f"📷 Screenshots saved to {ARTIFACTS_DIR}")

    def generate_report(self):
        print("\n=========================================")
        print("📊 PLAYWRIGHT COMPREHENSIVE TEST REPORT")
        print("=========================================")
        print(f"✅ Passed Checks: {len(self.passed_checks)}")
        print(f"❌ Issues Identified: {len(self.issues_found)}")
        print(f"⚠️ Console JS Errors: {len(self.console_errors)}")
        print(f"💥 Page Uncaught Exceptions: {len(self.page_errors)}")
        print(f"🌐 HTTP 4xx/5xx Failures: {len(self.failed_requests)}")

        report_path = os.path.join(ARTIFACTS_DIR, "test_summary.json")
        summary_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "passed_count": len(self.passed_checks),
            "passed_checks": self.passed_checks,
            "issues_count": len(self.issues_found),
            "issues": self.issues_found,
            "console_errors": self.console_errors,
            "page_errors": self.page_errors,
            "failed_requests": self.failed_requests
        }
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)

        print(f"\n📄 Saved test summary report to {report_path}")

async def main():
    tester = PlaywrightAppTester()
    async with async_playwright() as playwright:
        await tester.test_fastapi_backend(playwright)
        await tester.test_streamlit_frontend(playwright)
        tester.generate_report()

if __name__ == "__main__":
    asyncio.run(main())
