import asyncio
import logging
from typing import Tuple, Optional
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)

async def render_url(url: str, timeout_ms: int = 10000) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Renders candidate URL using headless Playwright browser per FR-DOM-01, FR-VIS-01, FR-DOM-04.
    Returns (screenshot_bytes, dom_html_string).
    On timeout or error, returns (None, None) gracefully without raising exceptions.
    """
    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "http://" + cleaned_url

    try:
        async with async_playwright() as p:
            # Launch chromium headless
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = await context.new_page()
            
            try:
                # Navigate with timeout (10s default per FR-DOM-04)
                await page.goto(cleaned_url, timeout=timeout_ms, wait_until="domcontentloaded")
                # Wait briefly for rendering/images
                await page.wait_for_timeout(1000)
            except Exception as e:
                logger.warning(f"Navigation warning for {url}: {e}")
                # If domcontentloaded fails or times out, try capturing whatever loaded
            
            try:
                screenshot_bytes = await page.screenshot(full_page=False, timeout=5000)
                dom_html = await page.content()
                await browser.close()
                return screenshot_bytes, dom_html
            except Exception as e:
                logger.error(f"Failed to capture screenshot/DOM for {url}: {e}")
                await browser.close()
                return None, None

    except PlaywrightTimeoutError:
        logger.warning(f"Playwright render timed out after {timeout_ms}ms for {url}")
        return None, None
    except Exception as e:
        logger.error(f"Playwright error rendering {url}: {e}")
        return None, None
