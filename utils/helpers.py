#!/usr/bin/env python3
# rokno_a3 - Helper Utilities

import os
import hashlib
from datetime import datetime

class OutputManager:
    """
    Manages output directory and file naming.
    """

    def __init__(self, domain: str):
        self.domain = domain
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = f"/tmp/rokno_a3/{domain}_{self.timestamp}"
        os.makedirs(self.session_dir, exist_ok=True)

    def save_json(self, data: dict, filename: str):
        """Save structured data as JSON."""
        # TODO: Implement JSON save
        pass

    def save_raw(self, content: str, filename: str):
        """Save raw text output."""
        # TODO: Implement raw text save
        pass

class DataCleaner:
    """
    Deduplication and data normalization.
    """

    @staticmethod
    def deduplicate(items: list) -> list:
        """Remove duplicates while preserving order."""
        seen = set()
        clean = []
        for item in items:
            if item not in seen:
                seen.add(item)
                clean.append(item)
        return clean

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL format."""
        # TODO: Add protocol, trailing slash handling
        return url.strip().lower()
