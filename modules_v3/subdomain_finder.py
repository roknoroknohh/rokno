#!/usr/bin/env python3
# subdomain_finder.py - FIXED: Multi-source, no API keys needed

import subprocess
import json
import re
import urllib.parse

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


class SubdomainFinder:
    def __init__(self, domain: str):
        self.domain = domain
        self.subdomains = set()

    def find_all(self) -> list:
        """Find subdomains from multiple free sources, merge and deduplicate."""
        # 1. crt.sh (Certificate Transparency)
        self._crt_sh()
        # 2. HackerTarget
        self._hackertarget()
        # 3. Wayback Machine
        self._wayback()
        # 4. subfinder (if installed)
        self._subfinder()
        # 5. assetfinder (if installed)
        self._assetfinder()

        return sorted(list(self.subdomains))

    def _http_get(self, url: str, timeout: int = 20) -> str:
        if HAS_REQUESTS:
            try:
                r = requests.get(url, headers={"User-Agent": REAL_USER_AGENT}, timeout=timeout)
                return r.text if r.status_code == 200 else ""
            except Exception:
                pass
        try:
            result = subprocess.run(
                ["curl", "-sL", "-A", REAL_USER_AGENT, "--max-time", str(timeout), url],
                capture_output=True, text=True, timeout=timeout + 5
            )
            return result.stdout
        except Exception:
            return ""

    def _crt_sh(self):
        """Query crt.sh certificate transparency logs."""
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            text = self._http_get(url, timeout=25)
            if not text:
                return
            data = json.loads(text)
            for entry in data:
                name = entry.get("name_value", "").strip().lower()
                if name and self.domain in name:
                    for sub in name.split("\\n"):
                        sub = sub.strip()
                        if sub and "*" not in sub and sub != self.domain:
                            self.subdomains.add(sub)
        except Exception:
            pass

    def _hackertarget(self):
        """Query HackerTarget API (free, no key)."""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            text = self._http_get(url, timeout=20)
            for line in text.split("\\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub and self.domain in sub:
                        self.subdomains.add(sub)
        except Exception:
            pass

    def _wayback(self):
        """Query Wayback Machine for subdomains."""
        try:
            url = (
                f"https://web.archive.org/cdx/search/cdx?"
                f"url=*.{self.domain}&output=json&fl=original&collapse=urlkey"
            )
            text = self._http_get(url, timeout=30)
            if not text:
                return
            data = json.loads(text)
            for entry in data:
                if isinstance(entry, list) and len(entry) > 0:
                    url_str = entry[0]
                    parsed = urllib.parse.urlparse(url_str)
                    host = parsed.netloc.lower()
                    if host and self.domain in host and host != self.domain:
                        self.subdomains.add(host)
        except Exception:
            pass

    def _subfinder(self):
        """Run subfinder if available."""
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-silent"],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.strip().split("\\n"):
                line = line.strip().lower()
                if line and self.domain in line:
                    self.subdomains.add(line)
        except Exception:
            pass

    def _assetfinder(self):
        """Run assetfinder if available."""
        try:
            result = subprocess.run(
                ["assetfinder", "--subs-only", self.domain],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.strip().split("\\n"):
                line = line.strip().lower()
                if line and self.domain in line:
                    self.subdomains.add(line)
        except Exception:
            pass
