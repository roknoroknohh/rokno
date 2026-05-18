#!/usr/bin/env python3
"""Deep JavaScript Analysis - Extract endpoints, secrets, APIs for Bug Bounty"""
import re
import urllib.parse
import asyncio
from typing import Dict, List, Set


class JSAnalyzer:
    """Analyzes JavaScript files to find hidden endpoints, secrets, and APIs."""

    # Regex patterns for different secrets
    SECRET_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"['\"]([A-Za-z0-9/+=]{40})['\"].*aws",
        "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
        "Firebase API Key": r"AIza[0-9A-Za-z_-]{35}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "Private Key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        "JWT Token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "Bearer Token": r"bearer\s+[a-zA-Z0-9_\-\.=]+",
        "Basic Auth": r"basic\s+[a-zA-Z0-9=]+",
        "API Key Generic": r"api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9_-]{16,}['\"]",
        "Secret Generic": r"secret\s*[:=]\s*['\"][a-zA-Z0-9_-]{8,}['\"]",
        "Auth Token": r"auth[_-]?token\s*[:=]\s*['\"][a-zA-Z0-9_-]{8,}['\"]",
        "Stripe Key": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "PayPal Token": r"access_token\$production\$[0-9a-z]{32}\$[0-9a-f]{32}",
        "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
        "Twilio SID": r"AC[a-zA-Z0-9_-]{32}",
        "Twilio Token": r"SK[a-zA-Z0-9_-]{32}",
        "SendGrid Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "Heroku API": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "S3 Bucket": r"s3\.amazonaws\.com/[a-z0-9_-]+|s3://[a-z0-9_-]+",
        "CloudFront Domain": r"[a-z0-9-]+\.cloudfront\.net",
        "Firebase URL": r"[a-z0-9-]+\.firebaseio\.com",
        "Algolia Key": r"[a-zA-Z0-9]{10}:[a-zA-Z0-9]{32}",
    }

    # Endpoint patterns
    ENDPOINT_PATTERNS = [
        r'["\']((?:/api/|/v\d+/|/graphql|/rest/|/internal/|/admin/|/dev/|/beta/|/staging/)[^"\']+)["\']',
        r'["\']((?:/auth/|/oauth/|/sso/|/login/|/register/|/password/|/reset/|/verify/)[^"\']+)["\']',
        r'["\']((?:/user/|/account/|/profile/|/settings/|/dashboard/|/panel/)[^"\']+)["\']',
        r'["\']((?:/upload/|/file/|/media/|/attachment/|/import/|/export/)[^"\']+)["\']',
        r'["\']((?:/payment/|/billing/|/invoice/|/subscription/|/plan/|/pricing/)[^"\']+)["\']',
        r'["\']((?:/search/|/filter/|/sort/|/query/|/find/)[^"\']+)["\']',
        r'["\']((?:/webhook/|/callback/|/hook/|/notify/|/event/)[^"\']+)["\']',
        r'["\']((?:/config/|/env/|/settings/|/setup/|/install/)[^"\']+)["\']',
        r'["\']((?:/health/|/status/|/ping/|/ready/|/alive/|/metrics/)[^"\']+)["\']',
        r'["\']((?:/debug/|/test/|/trace/|/profile/|/monitor/)[^"\']+)["\']',
        r'["\']((?:/backup/|/snapshot/|/restore/|/dump/)[^"\']+)["\']',
        r'["\']((?:/ws/|/socket/|/realtime/|/stream/|/live/)[^"\']+)["\']',
    ]

    # Parameter patterns in JS
    PARAM_PATTERNS = [
        r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\s*:\s*["\']([^"\']*)["\']',
        r'\?([a-zA-Z_][a-zA-Z0-9_]*)=',
        r'params\[["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\]',
        r'getParameter\(["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']\)',
    ]

    # API base URL patterns
    API_BASE_PATTERNS = [
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'base_url\s*[:=]\s*["\']([^"\']+)["\']',
        r'api_url\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\'](https?://[^"\']+)["\']',
        r'host\s*[:=]\s*["\'](https?://[^"\']+)["\']',
        r'origin\s*[:=]\s*["\'](https?://[^"\']+)["\']',
        r'BACKEND_URL\s*[:=]\s*["\']([^"\']+)["\']',
        r'API_BASE\s*[:=]\s*["\']([^"\']+)["\']',
        r'REACT_APP_API_URL\s*[:=]\s*["\']([^"\']+)["\']',
        r'NEXT_PUBLIC_API_URL\s*[:=]\s*["\']([^"\']+)["\']',
        r'VUE_APP_API_URL\s*[:=]\s*["\']([^"\']+)["\']',
    ]

    def __init__(self, js_urls: List[str], base_url: str = ""):
        self.js_urls = js_urls
        self.base_url = base_url
        self.results = {
            "endpoints": set(),
            "parameters": set(),
            "secrets": [],
            "api_bases": set(),
            "comments": [],
            "interesting_strings": [],
        }

    async def analyze_all(self) -> Dict:
        """Analyze all JS files concurrently."""
        tasks = [self._analyze_js(url) for url in self.js_urls[:20]]
        await asyncio.gather(*tasks)

        return {
            "total_files_analyzed": len(self.js_urls[:20]),
            "endpoints_found": sorted(list(self.results["endpoints"])),
            "parameters_found": sorted(list(self.results["parameters"])),
            "secrets_found": self.results["secrets"],
            "api_base_urls": sorted(list(self.results["api_bases"])),
            "developer_comments": self.results["comments"][:20],
            "interesting_strings": self.results["interesting_strings"][:20],
        }

    async def _analyze_js(self, js_url: str):
        """Analyze a single JS file."""
        try:
            js_code = await self._fetch_js(js_url)
            if not js_code:
                return

            # Extract endpoints
            self._extract_endpoints(js_code, js_url)

            # Extract parameters
            self._extract_parameters(js_code)

            # Extract secrets
            self._extract_secrets(js_code, js_url)

            # Extract API base URLs
            self._extract_api_bases(js_code)

            # Extract developer comments
            self._extract_comments(js_code, js_url)

            # Extract interesting strings
            self._extract_interesting(js_code, js_url)

        except Exception:
            pass

    async def _fetch_js(self, url: str) -> str:
        """Fetch JS file content."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sL", "--max-time", "10", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12)
            return stdout.decode('utf-8', errors='ignore')
        except Exception:
            return ""

    def _extract_endpoints(self, js_code: str, source_url: str):
        """Extract API endpoints from JS code."""
        for pattern in self.ENDPOINT_PATTERNS:
            matches = re.findall(pattern, js_code)
            for match in matches:
                if len(match) > 1 and not match.startswith("http"):
                    # Build full URL
                    full = urllib.parse.urljoin(self.base_url or source_url, match)
                    self.results["endpoints"].add(full)
                elif match.startswith("http"):
                    self.results["endpoints"].add(match)

        # Also look for fetch/axios patterns
        fetch_matches = re.findall(r'fetch\s*\(\s*["\']([^"\']+)["\']', js_code)
        self.results["endpoints"].update(fetch_matches)

        axios_matches = re.findall(r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', js_code)
        self.results["endpoints"].update(axios_matches)

        xhr_matches = re.findall(r'open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']', js_code)
        self.results["endpoints"].update(xhr_matches)

    def _extract_parameters(self, js_code: str):
        """Extract parameter names from JS code."""
        for pattern in self.PARAM_PATTERNS:
            matches = re.findall(pattern, js_code)
            if isinstance(matches, list) and matches:
                if isinstance(matches[0], tuple):
                    for m in matches:
                        self.results["parameters"].add(m[0] if isinstance(m, tuple) else m)
                else:
                    self.results["parameters"].update(matches)

    def _extract_secrets(self, js_code: str, source_url: str):
        """Extract leaked secrets/tokens from JS code."""
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, js_code)
            for match in matches:
                # Mask the secret
                masked = match[:4] + "****" + match[-4:] if len(match) > 12 else "****"
                self.results["secrets"].append({
                    "type": secret_type,
                    "masked_value": masked,
                    "source": source_url,
                    "severity": "Critical" if secret_type in ["AWS Access Key", "AWS Secret Key", "Private Key"] else "High",
                })

    def _extract_api_bases(self, js_code: str):
        """Extract API base URLs from JS code."""
        for pattern in self.API_BASE_PATTERNS:
            matches = re.findall(pattern, js_code)
            self.results["api_bases"].update(matches)

    def _extract_comments(self, js_code: str, source_url: str):
        """Extract developer comments that might contain sensitive info."""
        # Single line comments
        single = re.findall(r'//\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|WARNING|DEBUG|SECRET|KEY|TOKEN|PASSWORD|ADMIN)\s*:?\s*(.*)', js_code, re.IGNORECASE)
        for match in single:
            self.results["comments"].append({
                "type": match[0].upper(),
                "content": match[1].strip()[:100],
                "source": source_url,
            })

        # Multi-line comments
        multi = re.findall(r'/\*\s*(TODO|FIXME|HACK|BUG|XXX|NOTE|WARNING|DEBUG|SECRET|KEY|TOKEN|PASSWORD|ADMIN)\s*:?\s*([^*]*)', js_code, re.IGNORECASE)
        for match in multi:
            self.results["comments"].append({
                "type": match[0].upper(),
                "content": match[1].strip()[:100],
                "source": source_url,
            })

    def _extract_interesting(self, js_code: str, source_url: str):
        """Extract other interesting strings."""
        # GraphQL queries
        graphql = re.findall(r'(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)', js_code)
        for g in graphql:
            self.results["interesting_strings"].append({
                "type": "GraphQL",
                "value": g,
                "source": source_url,
            })

        # Internal IPs
        ips = re.findall(r'(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d+\.\d+', js_code)
        for ip in ips:
            self.results["interesting_strings"].append({
                "type": "Internal IP",
                "value": ip,
                "source": source_url,
            })

        # Email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', js_code)
        for email in emails:
            if not email.endswith((".png", ".jpg", ".gif", ".svg")):
                self.results["interesting_strings"].append({
                    "type": "Email",
                    "value": email,
                    "source": source_url,
                })
