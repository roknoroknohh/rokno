#!/usr/bin/env python3
import asyncio
import socket
import subprocess

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False


class DomainInfo:
    def __init__(self, target_url: str):
        self.target = target_url
        self.domain = self._extract_domain(target_url)
        self.root_domain = self._get_root_domain(self.domain)

    def _extract_domain(self, url: str) -> str:
        url = url.replace("https://", "").replace("http://", "")
        return url.split("/")[0].split(":")[0].strip()

    def _get_root_domain(self, domain: str) -> str:
        if HAS_TLDEXTRACT:
            extracted = tldextract.extract(domain)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

    async def gather(self) -> dict:
        ip, whois, dns = await asyncio.gather(
            self._resolve_ip(),
            self._whois_lookup(),
            self._dns_lookup(),
        )
        return {
            "target": self.target,
            "domain": self.domain,
            "root_domain": self.root_domain,
            "ip": ip,
            "whois": whois,
            "dns_records": dns,
        }

    async def _resolve_ip(self) -> str:
        try:
            return await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyname, self.domain
            )
        except Exception:
            return "N/A"

    async def _whois_lookup(self) -> dict:
        result = {"raw": "", "parsed": {}}
        try:
            proc = await asyncio.create_subprocess_exec(
                "whois", self.root_domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            raw = stdout.decode()
            result["raw"] = raw[:3000]
            result["parsed"] = self._parse_whois(raw)
        except Exception as e:
            result["raw"] = f"Error: {str(e)}"
        return result

    def _parse_whois(self, raw: str) -> dict:
        parsed = {}
        for line in raw.split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                val = val.strip()
                if key in ["registrar", "creation_date", "expiration_date", "name_server", "status"]:
                    parsed.setdefault(key, []).append(val)
        return parsed

    async def _dns_lookup(self) -> dict:
        records = {}
        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", self.domain, rtype,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                out = stdout.decode().strip()
                if out:
                    records[rtype] = [l.strip() for l in out.split("\n") if l.strip()]
            except Exception:
                pass
        return records
