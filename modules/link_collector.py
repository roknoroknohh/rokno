#!/usr/bin/env python3
import asyncio
import re
import urllib.parse

REAL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

class LinkCollector:
    def __init__(self, domain: str, target_url: str):
        self.domain = domain
        self.target = target_url
        self.links = []
        self.js_links = []

    async def collect_all(self):
        results = await asyncio.gather(
            self._collect_gau(),
            self._collect_waybackurls(),
            self._fallback_links(),
        )
        urls = set()
        for r in results:
            urls.update(r)
        self.links = sorted(list(urls))
        await self._collect_js()
        return {"discovered_links": self.links, "js_links": self.js_links}

    async def _http_get(self, url: str, timeout: int = 10):
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sL", "-A", REAL_UA, "--max-time", str(timeout), url,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 3)
            return stdout.decode()
        except Exception:
            return ""

    async def _collect_gau(self):
        urls = set()
        try:
            proc = await asyncio.create_subprocess_exec(
                "gau", self.domain,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for u in stdout.decode().strip().split("\n"):
                if u.strip():
                    urls.add(u.strip())
        except Exception:
            pass
        return urls

    async def _collect_waybackurls(self):
        urls = set()
        try:
            proc = await asyncio.create_subprocess_exec(
                "waybackurls", self.domain,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for u in stdout.decode().strip().split("\n"):
                if u.strip():
                    urls.add(u.strip())
        except Exception:
            pass
        return urls

    async def _fallback_links(self):
        found = set()
        html = await self._http_get(self.target, timeout=10)
        if not html:
            return found
        quote = chr(34) + chr(39)
        hrefs = re.findall("href=[" + quote + "](.*?)[" + quote + "]", html, re.IGNORECASE)
        for h in hrefs:
            if h.startswith("http"):
                found.add(h)
            elif h.startswith("/"):
                found.add(urllib.parse.urljoin(self.target, h))
            elif not h.startswith(("#", "javascript:", "mailto:", "tel:")):
                found.add(urllib.parse.urljoin(self.target, h))
        srcs = re.findall("src=[" + quote + "](.*?)[" + quote + "]", html, re.IGNORECASE)
        for s in srcs:
            if s.startswith("http"):
                found.add(s)
            elif s.startswith("/"):
                found.add(urllib.parse.urljoin(self.target, s))
        robots_url = urllib.parse.urljoin(self.target, "/robots.txt")
        robots_text = await self._http_get(robots_url, timeout=8)
        for line in robots_text.split("\n"):
            line = line.strip().lower()
            if line.startswith("allow:") or line.startswith("disallow:"):
                path = line.split(":", 1)[-1].strip()
                if path:
                    found.add(urllib.parse.urljoin(self.target, path))
        sitemap_url = urllib.parse.urljoin(self.target, "/sitemap.xml")
        sm_text = await self._http_get(sitemap_url, timeout=8)
        locs = re.findall(r"<loc>(.*?)</loc>", sm_text)
        for loc in locs:
            found.add(loc.strip())
        return found

    async def _collect_js(self):
        js_urls = [u for u in self.links if u.endswith(".js")][:15]
        if not js_urls:
            js_urls = await self._find_js_from_homepage()
            js_urls = js_urls[:15]
        endpoints = set()
        for js_url in js_urls:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python3", "/opt/LinkFinder/linkfinder.py", "-i", js_url, "-o", "cli",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                for line in stdout.decode().split("\n"):
                    line = line.strip()
                    if line.startswith(("/", "http")) and len(line) > 2:
                        endpoints.add(line)
            except Exception:
                pass
        if not endpoints:
            for js_url in js_urls[:5]:
                try:
                    js_code = await self._http_get(js_url, timeout=8)
                    if not js_code:
                        continue
                    quote = chr(34) + chr(39)
                    apis = re.findall(r"[" + quote + r"]((?:/api/|/v\d+/|/graphql|/rest/)[^" + quote + r"]+)[" + quote + r"]", js_code)
                    endpoints.update(apis)
                    fetches = re.findall(r"fetch\s*\(\s*[" + quote + r"]([^" + quote + r"]+)[" + quote + r"]", js_code)
                    endpoints.update(fetches)
                    bases = re.findall(r"baseURL\s*:\s*[" + quote + r"]([^" + quote + r"]+)[" + quote + r"]", js_code)
                    endpoints.update(bases)
                    routes = re.findall(r"path\s*:\s*[" + quote + r"]([^" + quote + r"]+)[" + quote + r"]", js_code)
                    endpoints.update(routes)
                except Exception:
                    pass
        self.js_links = sorted(list(endpoints))

    async def _find_js_from_homepage(self):
        html = await self._http_get(self.target, timeout=10)
        if not html:
            return []
        js_urls = []
        quote = chr(34) + chr(39)
        srcs = re.findall(r"src=[" + quote + r"](.*?\.js[^" + quote + r"]*)[" + quote + r"]", html, re.IGNORECASE)
        for s in srcs:
            if s.startswith("http"):
                js_urls.append(s)
            elif s.startswith("/"):
                js_urls.append(urllib.parse.urljoin(self.target, s))
            else:
                js_urls.append(urllib.parse.urljoin(self.target, s))
        return js_urls
