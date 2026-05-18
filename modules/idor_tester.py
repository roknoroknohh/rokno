#!/usr/bin/env python3
"""IDOR Tester - Dynamic 3-case comparison without hardcoded names"""
import asyncio
import json
import re
import urllib.parse
from typing import Dict, List, Set
from difflib import SequenceMatcher


class IDORTester:
    """
    Dynamically tests endpoints for IDOR by:
    1. Detecting ID parameters automatically
    2. Comparing 3 scenarios with REAL response analysis
    3. No hardcoded names or tokens - everything is dynamic
    """

    ID_PATTERNS = [
    r"[?&](id|user_id|account_id|order_id|product_id|item_id|file_id|doc_id|post_id)=",
    r"[?&](uid|uuid|guid|pid|sid|tid|rid|cid|bid|aid)=",
    r"[?&](user|account|profile|member|customer|client|patient|student|teacher|admin)=",
    r"[?&](number|no|num|ref|reference|code|key|token|session)=",
        r"[?&](category|page|type|chapter|level|index|step|sort|filter)=",
]

    SENSITIVE_FIELDS = [
        "email", "phone", "mobile", "address", "ssn", "social",
        "credit", "card", "bank", "account", "password", "secret",
        "token", "api_key", "private", "personal", "dob", "birth",
        "salary", "income", "balance", "amount", "payment",
        "name", "first_name", "last_name", "full_name", "username",
        "location", "geo", "coordinates", "ip", "device",
    ]

    def __init__(self, endpoints: List[str], cookies: Dict = None):
        self.endpoints = endpoints
        self.cookies = cookies or {}
        self.findings = []

    async def test_all(self) -> Dict:
        """Run dynamic IDOR tests on all endpoints."""
        testable = self._find_id_endpoints()
        print(f"      {len(testable)} endpoints with ID parameters found")

        for ep in testable[:15]:  # Test top 15
            result = await self._test_endpoint_dynamic(ep)
            if result:
                self.findings.append(result)

        return {
            "total_tested": len(testable[:15]),
            "idor_found": len([f for f in self.findings if f.get("idor_detected")]),
            "missing_auth": len([f for f in self.findings if f.get("missing_auth")]),
            "broken_access": len([f for f in self.findings if f.get("broken_access")]),
            "findings": self.findings,
        }

    def _find_id_endpoints(self) -> List[str]:
        """Find endpoints containing ID-like parameters."""
        found = []
        for url in self.endpoints:
            parsed = urllib.parse.urlparse(url)
            if not parsed.query:
                # Check REST-style paths: /api/user/123/profile
                if re.search(r"/\d+(/|$)", url) or re.search(r"/[a-f0-9-]{8,}(/|$)", url):
                    found.append(url)
                continue

            # Check query parameters
            for pattern in self.ID_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    found.append(url)
                    break
        return list(set(found))

    async def _test_endpoint_dynamic(self, endpoint: str) -> Dict:
        """Test a single endpoint with 3 dynamic cases."""
        result = {
            "endpoint": endpoint,
            "method": "GET",
            "case_original": {},
            "case_modified_id": {},
            "case_no_auth": {},
            "idor_detected": False,
            "missing_auth": False,
            "broken_access": False,
            "severity": "Info",
            "evidence": "",
        }

        # Parse the endpoint
        parsed = urllib.parse.urlparse(endpoint)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Case 1: Original request (with any available cookies)
        result["case_original"] = await self._make_request(endpoint, use_cookies=True)

        # If original fails (404/500), skip
        if result["case_original"].get("status") not in [200, 201, 202]:
            return None

        # Case 2: Modified ID parameter
        modified_url = self._modify_id(endpoint)
        if modified_url != endpoint:
            result["case_modified_id"] = await self._make_request(modified_url, use_cookies=True)

        # Case 3: No authentication
        result["case_no_auth"] = await self._make_request(endpoint, use_cookies=False)

        # Dynamic analysis
        result["idor_detected"] = self._analyze_idor(
            result["case_original"],
            result["case_modified_id"]
        )
        result["missing_auth"] = self._analyze_missing_auth(
            result["case_original"],
            result["case_no_auth"]
        )
        result["broken_access"] = self._analyze_broken_access(
            result["case_original"],
            result["case_modified_id"]
        )

        # Set severity
        if result["missing_auth"] and result["idor_detected"]:
            result["severity"] = "Critical"
        elif result["missing_auth"] or result["idor_detected"]:
            result["severity"] = "High"
        elif result["broken_access"]:
            result["severity"] = "Medium"

        # Build evidence string dynamically
        evidence_parts = []
        if result["idor_detected"]:
            orig_len = result["case_original"].get("body_length", 0)
            mod_len = result["case_modified_id"].get("body_length", 0)
            similarity = self._calculate_similarity(
                result["case_original"].get("body_preview", ""),
                result["case_modified_id"].get("body_preview", "")
            )
            evidence_parts.append(
                f"IDOR: Modified ID returned similar data (similarity: {similarity:.0%}, "
                f"lengths: {orig_len}/{mod_len})"
            )

        if result["missing_auth"]:
            evidence_parts.append(
                f"Missing Auth: No-cookie request returned status {result['case_no_auth'].get('status')} "
                f"with {result['case_no_auth'].get('body_length', 0)} bytes"
            )

        result["evidence"] = " | ".join(evidence_parts)

        return result

    def _modify_id(self, url: str) -> str:
        """Modify ID parameter in URL to test access control."""
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        modified = False
        for param in list(query.keys()):
            param_lower = param.lower()
            if any(x in param_lower for x in ["id", "user", "account", "order", "product", "file"]):
                for i, val in enumerate(query[param]):
                    if val.isdigit():
                        # Change to adjacent ID
                        new_val = str(int(val) + 1)
                        query[param][i] = new_val
                        modified = True
                    elif len(val) > 8 and all(c in "0123456789abcdef-" for c in val.lower()):
                        # UUID - change last char
                        new_val = val[:-1] + ("0" if val[-1] != "0" else "1")
                        query[param][i] = new_val
                        modified = True

        if modified:
            new_query = urllib.parse.urlencode(query, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))

        # Try REST path modification: /api/user/123 → /api/user/124
        path = parsed.path
        match = re.search(r"/(\d+)(/|$)", path)
        if match:
            old_id = match.group(1)
            new_id = str(int(old_id) + 1)
            new_path = path[:match.start(1)] + new_id + path[match.end(1):]
            return urllib.parse.urlunparse(parsed._replace(path=new_path))

        return url

    async def _make_request(self, url: str, use_cookies: bool = True) -> Dict:
        """Make HTTP request."""
        try:
            cmd = ["curl", "-sL", "--max-time", "10", "-w", "\\n%{http_code}"]

            headers = [
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "-H", "Accept: application/json, text/plain, */*",
                "-H", "Accept-Language: en-US,en;q=0.5",
            ]
            cmd.extend(headers)

            if use_cookies and self.cookies:
                cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
                cmd.extend(["-H", f"Cookie: {cookie_str}"])

            cmd.append(url)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12)
            output = stdout.decode()

            lines = output.strip().split("\n")
            status = 0
            body = ""
            if lines:
                try:
                    status = int(lines[-1])
                    body = "\n".join(lines[:-1])
                except ValueError:
                    body = output

            # Extract sensitive fields
            body_lower = body.lower()
            sensitive_found = [f for f in self.SENSITIVE_FIELDS if f in body_lower]

            return {
                "status": status,
                "body_length": len(body),
                "body_preview": body[:800],
                "has_data": len(body) > 50 and status == 200,
                "sensitive_fields": sensitive_found,
                "has_sensitive": len(sensitive_found) > 0,
            }
        except Exception as e:
            return {"status": 0, "error": str(e), "body_length": 0, "has_data": False, "has_sensitive": False}

    def _analyze_idor(self, case_orig: Dict, case_mod: Dict) -> bool:
        """
        Detect IDOR dynamically:
        - Original request returns data
        - Modified ID request returns SIMILAR data (not 403/404)
        """
        if not case_orig.get("has_data") or not case_mod:
            return False

        orig_status = case_orig.get("status", 0)
        mod_status = case_mod.get("status", 0)

        # If modified ID returns 200 with data = potential IDOR
        if mod_status == 200 and case_mod.get("has_data"):
            # Calculate similarity
            similarity = self._calculate_similarity(
                case_orig.get("body_preview", ""),
                case_mod.get("body_preview", "")
            )

            # If responses are similar (>60%) and both have sensitive data
            if similarity > 0.6:
                # Check if both have sensitive fields
                orig_sensitive = case_orig.get("has_sensitive", False)
                mod_sensitive = case_mod.get("has_sensitive", False)
                if orig_sensitive or mod_sensitive:
                    return True

        return False

    def _analyze_missing_auth(self, case_orig: Dict, case_no_auth: Dict) -> bool:
        """
        Detect missing authentication:
        - Original request returns data with auth
        - No-auth request also returns data (not 401/403)
        """
        if not case_orig.get("has_data"):
            return False

        no_auth_status = case_no_auth.get("status", 0)
        no_auth_len = case_no_auth.get("body_length", 0)

        # If no-auth returns 200 with substantial data
        if no_auth_status == 200 and no_auth_len > 100:
            # Make sure it's not just an error page
            if case_no_auth.get("has_data"):
                return True

        # Sometimes APIs return 500 when auth is missing (bad error handling)
        if no_auth_status == 500 and no_auth_len > 50:
            return True

        return False

    def _analyze_broken_access(self, case_orig: Dict, case_mod: Dict) -> bool:
        """
        Detect broken access control:
        - Modified ID returns different status but still leaks info
        """
        if not case_orig.get("has_data") or not case_mod:
            return False

        orig_status = case_orig.get("status", 0)
        mod_status = case_mod.get("status", 0)

        # If modified ID returns 403 but body still contains data
        if mod_status in [403, 401] and case_mod.get("body_length", 0) > 100:
            return True

        # If modified ID returns 500 with error details
        if mod_status == 500 and case_mod.get("body_length", 0) > 200:
            return True

        return False

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts."""
        if not text1 or not text2:
            return 0.0
        return SequenceMatcher(None, text1, text2).ratio()
