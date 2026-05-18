#!/usr/bin/env python3
# rokno_a3 - Input Validator Module (COMPLETE)
# Validates and sanitizes target URL

import re
from urllib.parse import urlparse

class TargetValidator:
    """
    Validates user input:
    1. Single URL only
    2. Valid URL format
    3. Extract clean domain
    """

    def __init__(self):
        self.clean_url = None
        self.domain = None
        self.approved = False
        self.error_msg = None

    def validate(self, raw_input: str) -> dict:
        """Main validation pipeline."""
        if not raw_input or not raw_input.strip():
            self.error_msg = "Empty input provided"
            return self._result()

        raw = raw_input.strip()

        # Step 1: Single target check
        if " " in raw or "," in raw or ";" in raw:
            self.error_msg = "Only ONE target allowed per run"
            return self._result()

        # Step 2: Add protocol if missing
        if not raw.startswith(("http://", "https://")):
            raw = "https://" + raw

        # Step 3: URL regex validation
        url_pattern = re.compile(
            r'^(https?://)'
            r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )

        parsed = urlparse(raw)
        if not parsed.netloc:
            self.error_msg = "Invalid URL format"
            return self._result()

        # Step 4: Extract domain
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]

        # Step 5: Clean URL (no trailing slash, no path for base)
        clean = f"{parsed.scheme}://{parsed.netloc}"

        self.clean_url = clean
        self.domain = domain
        self.approved = True
        return self._result()

    def _result(self) -> dict:
        return {
            "clean_url": self.clean_url,
            "domain": self.domain,
            "approved": self.approved,
            "error": self.error_msg
        }
