#!/usr/bin/env python3
"""Browser Engine - Real browser with Cloudflare bypass for Bug Bounty"""
import asyncio
import json
import time
from typing import Dict, List, Optional

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class BrowserEngine:
    """
    Real headless browser that bypasses Cloudflare and JS challenges.
    Simulates real browser fingerprinting.
    """

    # Realistic user agents
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    ]

    def __init__(self, proxy: str = None):
        self.proxy = proxy
        self.browser = None
        self.context = None
        self.page = None
        self.cookies = {}
        self.headers = {}
        self.requests_log = []
        self.responses_log = []

    async def launch(self):
        """Launch stealth browser."""
        if not HAS_PLAYWRIGHT:
            print("[!] Playwright not installed. Install: pip install playwright && playwright install chromium")
            return False

        self.playwright = await async_playwright().start()

        args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-web-security",
            "--disable-features=IsolateOrigins,site-per-process",
            "--disable-site-isolation-trials",
            "--disable-dev-shm-usage",
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-gpu",
            "--disable-infobars",
            "--window-size=1920,1080",
            "--start-maximized",
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ]

        browser_options = {
            "headless": True,
            "args": args,
        }

        if self.proxy:
            browser_options["proxy"] = {"server": self.proxy}

        self.browser = await self.playwright.chromium.launch(**browser_options)

        self.context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent=self.USER_AGENTS[0],
            locale="en-US",
            timezone_id="America/New_York",
            geolocation={"latitude": 40.7128, "longitude": -74.0060},
            permissions=["geolocation"],
            color_scheme="light",
            java_script_enabled=True,
            bypass_csp=True,
            ignore_https_errors=True,
        )

        # Stealth: override navigator.webdriver
        await self.context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            window.chrome = { runtime: {} };
            delete navigator.__proto__.webdriver;
        """)

        self.page = await self.context.new_page()

        # Intercept requests/responses
        self.page.on("request", self._on_request)
        self.page.on("response", self._on_response)

        return True

    def _on_request(self, request):
        """Log all outgoing requests."""
        self.requests_log.append({
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "post_data": request.post_data,
        })

    def _on_response(self, response):
        """Log all responses."""
        asyncio.create_task(self._log_response(response))

    async def _log_response(self, response):
        try:
            body = await response.body()
            self.responses_log.append({
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers),
                "body_preview": body[:2000] if body else "",
            })
        except Exception:
            pass

    async def navigate(self, url: str, wait_for: str = "networkidle", timeout: int = 30) -> Dict:
        """Navigate to URL and bypass Cloudflare."""
        result = {
            "url": url,
            "status": 0,
            "title": "",
            "html": "",
            "cookies": [],
            "headers": {},
            "cloudflare_passed": False,
            "requests": [],
            "responses": [],
        }

        try:
            response = await self.page.goto(url, wait_until=wait_for, timeout=timeout * 1000)
            result["status"] = response.status if response else 0
            result["headers"] = dict(response.headers) if response else {}

            # Wait for Cloudflare challenge to complete
            await asyncio.sleep(2)

            # Check if we're past Cloudflare
            title = await self.page.title()
            result["title"] = title
            result["html"] = await self.page.content()

            if "Just a moment" in title or "Checking your browser" in title:
                # Wait longer for challenge
                await asyncio.sleep(5)
                result["html"] = await self.page.content()
                title = await self.page.title()
                result["title"] = title

            if "Just a moment" not in title and "Checking your browser" not in title:
                result["cloudflare_passed"] = True

            # Get cookies
            cookies = await self.context.cookies()
            result["cookies"] = cookies
            self.cookies = {c["name"]: c["value"] for c in cookies}

            # Get localStorage/sessionStorage
            local_storage = await self.page.evaluate("() => JSON.stringify(localStorage)")
            session_storage = await self.page.evaluate("() => JSON.stringify(sessionStorage)")
            result["local_storage"] = json.loads(local_storage) if local_storage else {}
            result["session_storage"] = json.loads(session_storage) if session_storage else {}

            result["requests"] = self.requests_log[-50:]  # Last 50
            result["responses"] = self.responses_log[-50:]

        except Exception as e:
            result["error"] = str(e)

        return result

    async def extract_api_calls(self) -> List[Dict]:
        """Extract all API calls made by the page."""
        api_calls = []
        for req in self.requests_log:
            url = req["url"]
            if any(x in url for x in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/auth/"]):
                api_calls.append(req)
        return api_calls

    async def extract_tokens(self) -> List[Dict]:
        """Extract tokens from page context."""
        tokens = []

        # Check localStorage for tokens
        for key, value in result.get("local_storage", {}).items():
            if any(x in key.lower() for x in ["token", "auth", "jwt", "api", "key", "secret"]):
                tokens.append({"source": f"localStorage.{key}", "value": str(value)[:50]})

        # Check cookies for tokens
        for cookie in result.get("cookies", []):
            if any(x in cookie["name"].lower() for x in ["token", "auth", "jwt", "session"]):
                tokens.append({"source": f"cookie.{cookie['name']}", "value": cookie["value"][:50]})

        return tokens

    async def close(self):
        """Close browser."""
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright'):
            await self.playwright.stop()


class CloudflareBypass:
    """Helper to bypass Cloudflare using browser engine."""

    @staticmethod
    async def fetch(url: str, proxy: str = None) -> Dict:
        """Fetch URL bypassing Cloudflare."""
        engine = BrowserEngine(proxy=proxy)
        try:
            launched = await engine.launch()
            if not launched:
                return {"error": "Playwright not available"}

            result = await engine.navigate(url, timeout=45)
            result["api_calls"] = await engine.extract_api_calls()
            result["tokens"] = await engine.extract_tokens()
            return result
        finally:
            await engine.close()
