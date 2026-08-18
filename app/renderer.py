import asyncio
import logging
from typing import Tuple, Optional, List
from playwright.async_api import async_playwright, Playwright, Browser, TimeoutError as PlaywrightTimeoutError

logger = logging.getLogger(__name__)

class PlaywrightRenderer:
    """
    Manages a persistent Playwright browser instance with anti-sandbox stealth
    evasion and redirect chain tracing.
    """
    def __init__(self):
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._lock = asyncio.Lock()

    async def start(self):
        async with self._lock:
            if self._browser is None or not self._browser.is_connected():
                try:
                    self._playwright = await async_playwright().start()
                    self._browser = await self._playwright.chromium.launch(
                        headless=True,
                        args=[
                            "--no-sandbox",
                            "--disable-setuid-sandbox",
                            "--disable-gpu",
                            "--disable-dev-shm-usage",
                            "--disable-background-networking",
                            "--disable-default-apps",
                            "--disable-extensions",
                            "--disable-sync",
                            "--disable-translate",
                            "--mute-audio",
                            "--disable-blink-features=AutomationControlled"
                        ]
                    )
                    logger.info("Playwright persistent browser worker initialized successfully.")
                except Exception as e:
                    logger.error(f"Failed to start Playwright browser worker: {e}")
                    self._browser = None

    async def close(self):
        async with self._lock:
            if self._browser:
                try:
                    await self._browser.close()
                except Exception as e:
                    logger.warning(f"Error closing Playwright browser: {e}")
                self._browser = None
            if self._playwright:
                try:
                    await self._playwright.stop()
                except Exception as e:
                    logger.warning(f"Error stopping Playwright instance: {e}")
                self._playwright = None
            logger.info("Playwright browser worker shutdown complete.")

    async def render(self, url: str, timeout_ms: int = 10000) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Renders candidate URL with anti-bot stealth scripts.
        Returns (screenshot_bytes, dom_html_string).
        """
        cleaned_url = url.strip()
        if not cleaned_url.startswith(("http://", "https://")):
            cleaned_url = "http://" + cleaned_url

        if self._browser is None or not self._browser.is_connected():
            await self.start()

        if self._browser is None:
            logger.error("Playwright browser is unavailable. Cannot render URL.")
            return None, None

        context = None
        page = None
        try:
            context = await self._browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                locale="en-US",
                timezone_id="America/New_York",
                ignore_https_errors=True
            )

            # Stealth: Mask navigator.webdriver and automation artifacts
            await context.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                window.chrome = { runtime: {} };
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
                Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            """)

            # Route filter: Block heavy media and streaming websockets to accelerate page rendering
            await context.route(
                "**/*",
                lambda route: route.abort() if route.request.resource_type in ["media", "websocket"] else route.continue_()
            )

            page = await context.new_page()

            dom_html = None
            try:
                await page.goto(cleaned_url, timeout=timeout_ms, wait_until="domcontentloaded")
                await page.wait_for_timeout(500)
            except Exception as e:
                logger.warning(f"Navigation warning for {url}: {e}")

            # 1. Extract DOM with Deep Shadow DOM & Custom Web Component unrolling first
            try:
                dom_html = await page.evaluate("""
                    () => {
                        function unrollShadowRoots(root) {
                            if (!root) return;
                            const elements = root.querySelectorAll('*');
                            for (const el of elements) {
                                if (el.shadowRoot) {
                                    const shadowDiv = document.createElement('div');
                                    shadowDiv.setAttribute('data-shadow-root', 'true');
                                    shadowDiv.innerHTML = el.shadowRoot.innerHTML;
                                    el.appendChild(shadowDiv);
                                    unrollShadowRoots(el.shadowRoot);
                                }
                            }
                        }
                        try {
                            unrollShadowRoots(document.body || document.documentElement);
                        } catch(e) {}
                        return document.documentElement.outerHTML;
                    }
                """)
            except Exception:
                try:
                    dom_html = await page.content()
                except Exception:
                    dom_html = None

            # 2. Attempt viewport screenshot capture (non-blocking for DOM analysis)
            screenshot_bytes = None
            try:
                screenshot_bytes = await page.screenshot(
                    full_page=False, 
                    timeout=4000, 
                    animations="disabled"
                )
            except Exception as e:
                logger.warning(f"Headless screenshot capture warning for {url}: {e}")

            if screenshot_bytes or dom_html:
                return screenshot_bytes, dom_html

            # If both failed in browser, fallback to HTTP fetch
            return await self._fallback_http_fetch(cleaned_url)

        except PlaywrightTimeoutError:
            logger.warning(f"Playwright render timed out after {timeout_ms}ms for {url}. Attempting resilient HTTP fallback...")
            return await self._fallback_http_fetch(cleaned_url)
        except Exception as e:
            logger.warning(f"Playwright error rendering {url}: {e}. Attempting resilient HTTP fallback...")
            return await self._fallback_http_fetch(cleaned_url)
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    pass
            if context:
                try:
                    await context.close()
                except Exception:
                    pass

    async def _fallback_http_fetch(self, url: str) -> Tuple[Optional[bytes], Optional[str]]:
        """
        Fast resilient HTTP fallback to extract DOM HTML when headless browser is blocked or timed out.
        """
        try:
            import httpx
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            async with httpx.AsyncClient(timeout=6.0, follow_redirects=True, verify=False) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code < 500:
                    dom_html = resp.text
                    return None, dom_html
        except Exception as ex:
            logger.debug(f"HTTP fallback fetch failed for {url}: {ex}")
        return None, None

# Global renderer instance
_renderer = PlaywrightRenderer()

async def render_url(url: str, timeout_ms: int = 10000) -> Tuple[Optional[bytes], Optional[str]]:
    """Public helper function."""
    return await _renderer.render(url, timeout_ms=timeout_ms)

async def start_renderer():
    """Starts the global renderer instance on server startup."""
    await _renderer.start()

async def close_renderer():
    """Closes the global renderer instance on server shutdown."""
    await _renderer.close()


