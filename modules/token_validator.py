#!/usr/bin/env python3
"""Token Validator - Generic dynamic verification of any discovered secret"""
import asyncio
import json
import base64
import re
from typing import Dict, List
from datetime import datetime


class TokenValidator:
    """
    Dynamically validates ANY discovered secret/token/cookie.
    Auto-detects type, checks if fake/expired/valid.
    """

    FAKE_PATTERNS = [
        r"your_", r"YOUR_", r"example", r"EXAMPLE", r"test", r"TEST",
        r"dummy", r"DUMMY", r"placeholder", r"PLACEHOLDER", r"sample",
        r"xxxx", r"XXXX", r"0000", r"1111", r"aaaa", r"AAAA",
        r"changeme", r"CHANGE_ME", r"insert_", r"ENTER_", r"paste_",
        r"my_api_key", r"api_key_here", r"secret_here", r"token_here",
        r"sk_test_0000", r"pk_test_0000", r"AIza0000",
    ]

    def __init__(self):
        self.results = []

    async def validate_all(self, secrets: List[Dict]) -> List[Dict]:
        for secret in secrets:
            validated = await self._auto_validate(secret)
            self.results.append(validated)
        return self.results

    async def _auto_validate(self, secret: Dict) -> Dict:
        """Auto-detect type and validate accordingly."""
        result = {
            "original": secret,
            "status": "UNKNOWN",
            "confidence": "low",
            "details": "",
            "risk_level": "Info",
        }

        value = secret.get("masked_value", "")
        source = secret.get("source", "")

        # Step 1: Check fake
        if self._is_fake(value):
            result["status"] = "FAKE/DUMMY"
            result["confidence"] = "high"
            result["details"] = "Matches known placeholder/test patterns"
            return result

        # Step 2: Auto-detect type and validate
        detected_type = self._detect_type(value)

        if detected_type == "jwt":
            result.update(self._validate_jwt(value))
        elif detected_type == "api_key":
            result.update(await self._validate_api_key(secret))
        elif detected_type == "cookie":
            result.update(self._validate_cookie(secret))
        elif detected_type == "aws":
            result.update(await self._validate_aws(secret))
        else:
            result.update(await self._validate_generic(secret))

        return result

    def _is_fake(self, value: str) -> bool:
        for pattern in self.FAKE_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        clean = value.replace("****", "").replace("*", "")
        if len(set(clean)) <= 2 and len(clean) > 8:
            return True
        return False

    def _detect_type(self, value: str) -> str:
        """Auto-detect secret type from value."""
        if "." in value and len(value.split(".")) == 3 and len(value) > 50:
            return "jwt"
        if value.startswith("AKIA") or value.startswith("ASIA"):
            return "aws"
        if value.startswith("eyJ"):
            return "jwt"
        if "=" in value and ";" in value and len(value) < 500:
            return "cookie"
        if len(value) > 20 and any(x in value for x in ["_", "-"]):
            return "api_key"
        return "generic"

    def _validate_jwt(self, token: str) -> Dict:
        result = {"status": "UNKNOWN", "confidence": "medium", "details": "", "risk_level": "Medium"}
        try:
            parts = token.split(".")
            if len(parts) != 3:
                result["status"] = "INVALID_FORMAT"
                result["details"] = "Not valid JWT (expected 3 parts)"
                return result

            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
            details = [f"Algorithm: {json.loads(base64.urlsafe_b64decode(parts[0] + '==')).get('alg', 'unknown')}"]

            exp = payload.get("exp")
            if exp:
                exp_date = datetime.fromtimestamp(exp)
                now = datetime.now()
                if exp_date < now:
                    result["status"] = "EXPIRED"
                    result["confidence"] = "high"
                    details.append(f"Expired {(now - exp_date).days} days ago")
                    result["risk_level"] = "Low"
                else:
                    days = (exp_date - now).days
                    result["status"] = "REAL & ACTIVE"
                    result["confidence"] = "high"
                    details.append(f"Valid {days} days (expires {exp_date.date()})")
                    result["risk_level"] = "Critical"

            for k in ["iss", "aud", "sub", "role", "scope"]:
                if payload.get(k):
                    details.append(f"{k}: {payload[k]}")

            result["details"] = " | ".join(details)
        except Exception as e:
            result["status"] = "INVALID_FORMAT"
            result["details"] = f"JWT decode failed: {e}"
        return result

    async def _validate_api_key(self, secret: Dict) -> Dict:
        result = {"status": "UNKNOWN", "confidence": "low", "details": "", "risk_level": "High"}
        value = secret.get("masked_value", "").replace("****", "")
        source = secret.get("source", "")

        # Safe HEAD request to source domain to check if key is accepted
        try:
            domain = re.search(r"https?://([^/]+)", source)
            if domain:
                test_url = f"https://{domain.group(1)}/"
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sI", "--max-time", "5", "-H", f"Authorization: Bearer {value}", test_url,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=7)
                resp = stdout.decode()

                if "401" in resp:
                    result["status"] = "REAL BUT REJECTED"
                    result["confidence"] = "high"
                    result["details"] = "Key format accepted but rejected (401). Likely expired or wrong scope."
                    result["risk_level"] = "Medium"
                elif "403" in resp:
                    result["status"] = "REAL BUT RESTRICTED"
                    result["confidence"] = "high"
                    result["details"] = "Key valid but access restricted (403)."
                    result["risk_level"] = "High"

        except Exception:
            pass

        if result["status"] == "UNKNOWN":
            result["details"] = f"API key from {source}. Length {len(value)}. Manual verification needed."
        return result

    def _validate_cookie(self, secret: Dict) -> Dict:
        result = {"status": "UNKNOWN", "confidence": "low", "details": "", "risk_level": "Low"}
        value = secret.get("masked_value", "")

        # Parse cookie attributes
        attrs = {}
        for part in value.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                attrs[k.strip().lower()] = v.strip()

        details = []
        if "expires" in attrs:
            try:
                exp = datetime.strptime(attrs["expires"], "%a, %d %b %Y %H:%M:%S %Z")
                if exp < datetime.now():
                    result["status"] = "EXPIRED"
                    result["confidence"] = "high"
                    details.append(f"Cookie expired {exp.date()}")
                else:
                    details.append(f"Cookie expires {exp.date()}")
            except Exception:
                pass

        if "secure" in attrs:
            details.append("Secure flag set")
        if "httponly" in attrs:
            details.append("HttpOnly flag set")
        if "samesite" in attrs:
            details.append(f"SameSite={attrs['samesite']}")

        if result["status"] == "UNKNOWN" and details:
            result["status"] = "VALID_COOKIE"
            result["confidence"] = "medium"

        result["details"] = " | ".join(details) if details else "Cookie format valid"
        return result

    async def _validate_aws(self, secret: Dict) -> Dict:
        result = {"status": "UNKNOWN", "confidence": "low", "details": "", "risk_level": "High"}
        value = secret.get("masked_value", "")
        if "AKIA" in value:
            result["details"] = "AWS Access Key format. Manual verification via AWS CLI required."
            result["confidence"] = "medium"
        elif "ASIA" in value:
            result["details"] = "AWS Temporary Credentials. Session token likely required."
            result["confidence"] = "medium"
        return result

    async def _validate_generic(self, secret: Dict) -> Dict:
        result = {"status": "UNKNOWN", "confidence": "low", "details": "", "risk_level": "Medium"}
        value = secret.get("masked_value", "").replace("****", "").replace("*", "")
        source = secret.get("source", "")

        if len(value) < 10:
            result["status"] = "LIKELY_FAKE"
            result["confidence"] = "medium"
            result["details"] = f"Too short ({len(value)} chars). Likely placeholder."
            result["risk_level"] = "Info"
        else:
            result["details"] = f"Unknown type from {source}. Length: {len(value)}. Manual check needed."
        return result
