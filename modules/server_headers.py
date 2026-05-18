#!/usr/bin/env python3
# server_headers.py - Fetch and analyze HTTP headers

import subprocess
import re

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

REAL_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class ServerHeaders:
    def __init__(self, target_url: str):
        self.target = target_url
        self.html = ""
        self.headers = {}

    def fetch(self) -> dict:
        """Fetch headers and HTML with multiple fallbacks."""
        # Try requests
        if HAS_REQUESTS:
            try:
                import requests
                r = requests.get(
                    self.target,
                    headers={"User-Agent": REAL_USER_AGENT},
                    timeout=15,
                    allow_redirects=True
                )
                self.html = r.text
                self.headers = dict(r.headers)
                self.headers["_status"] = r.status_code
                self.headers["_url"] = r.url
                return self.headers
            except Exception:
                pass

        # Fallback: curl
        try:
            result = subprocess.run(
                ["curl", "-sIL", "-A", REAL_USER_AGENT, "--max-time", "15", self.target],
                capture_output=True, text=True, timeout=20
            )
            self.headers = self._parse_curl_headers(result.stdout)

            # Get body
            body_result = subprocess.run(
                ["curl", "-sL", "-A", REAL_USER_AGENT, "--max-time", "15", self.target],
                capture_output=True, text=True, timeout=20
            )
            self.html = body_result.stdout
            return self.headers
        except Exception:
            pass

        return self.headers

    def _parse_curl_headers(self, raw: str) -> dict:
        headers = {}
        for line in raw.split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip()] = val.strip()
            elif line.startswith("HTTP/"):
                parts = line.split()
                if len(parts) >= 2:
                    headers["_status"] = int(parts[1])
        return headers
