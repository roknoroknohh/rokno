#!/usr/bin/env python3
"""Cookie Manager - Automatic cookie and session handling"""
import random
from typing import Dict, List


class CookieManager:
    """Manages cookies, user-agents, and session rotation."""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ]

    ACCEPT_HEADERS = [
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    ]

    def __init__(self):
        self.cookies: Dict[str, str] = {}
        self.session_tokens: Dict[str, str] = {}
        self.current_ua = random.choice(self.USER_AGENTS)

    def get_headers(self, extra: Dict = None) -> Dict:
        """Get realistic browser headers."""
        headers = {
            "User-Agent": self.current_ua,
            "Accept": random.choice(self.ACCEPT_HEADERS),
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        if self.cookies:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

        if extra:
            headers.update(extra)

        return headers

    def update_cookies(self, cookie_string: str):
        """Parse and update cookies from Set-Cookie header."""
        for part in cookie_string.split(","):
            if "=" in part:
                key, val = part.split("=", 1)
                key = key.strip()
                val = val.split(";")[0].strip()
                if key and val:
                    self.cookies[key] = val

    def rotate_ua(self):
        """Rotate user agent."""
        self.current_ua = random.choice(self.USER_AGENTS)

    def get_auth_headers(self, token: str = None) -> Dict:
        """Get headers with authentication."""
        headers = self.get_headers()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers
