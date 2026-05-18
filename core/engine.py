#!/usr/bin/env python3
# rokno_a3 - Analysis Engine (FIXED)
# Orchestrates data collection with retry and fallback

import time
from typing import Dict, Callable

from modules.domain_info import DomainInfoCollector
from modules.tech_detect import TechDetector
from modules.server_headers import ServerHeaderCollector
from modules.link_collector import LinkCollector
from modules.subdomain_finder import SubdomainFinder
from modules.data_compressor import DataCompressor

class AnalysisEngine:
    TOTAL_STEPS = 6

    def __init__(self, target_url: str, domain: str):
        self.target = target_url
        self.domain = domain
        self.results = {
            "target": target_url,
            "domain": domain,
            "domain_info": {},
            "technologies": [],
            "server_headers": {},
            "discovered_links": [],
            "subdomains": [],
            "js_links": [],
        }
        self.start_time = time.time()
        self.step_times = {}

    def run_recon(self, ui_callback=None) -> dict:
        steps = [
            (0, "whois", self._run_whois),
            (1, "whatweb", self._run_whatweb),
            (2, "httpx", self._run_httpx),
            (3, "gau", self._run_gau),
            (4, "assetfinder", self._run_assetfinder),
            (5, "linkfinder", self._run_linkfinder),
        ]

        for idx, name, func in steps:
            if ui_callback:
                ui_callback(idx, name, "running")

            step_start = time.time()
            success = False

            try:
                func()
                success = True
            except Exception as e:
                # Store error but don't crash
                self.results[name] = {"error": str(e), "source": name}
                success = False

            self.step_times[name] = round(time.time() - step_start, 2)

            if ui_callback:
                ui_callback(idx, name, "done" if success else "warning")

            if not self.check_timeout():
                if ui_callback:
                    ui_callback(idx, name, "warning")
                break

        return self.results

    def _run_whois(self):
        collector = DomainInfoCollector(self.domain)
        self.results["domain_info"] = collector.collect()

    def _run_whatweb(self):
        detector = TechDetector(self.target)
        self.results["technologies"] = detector.detect()

    def _run_httpx(self):
        collector = ServerHeaderCollector(self.target)
        self.results["server_headers"] = collector.collect()

    def _run_gau(self):
        lc = LinkCollector(self.domain, self.target)
        lc.collect_all()
        self.results["discovered_links"] = lc.links
        self.results["js_links"] = lc.js_links

    def _run_assetfinder(self):
        finder = SubdomainFinder(self.domain)
        self.results["subdomains"] = finder.find()

    def _run_linkfinder(self):
        # Already handled in _run_gau (LinkCollector does both)
        pass

    def compress_for_ai(self) -> dict:
        compressor = DataCompressor(self.results)
        return compressor.compress()

    def check_timeout(self) -> bool:
        elapsed = time.time() - self.start_time
        return elapsed < 55

    def get_stats(self) -> dict:
        total = time.time() - self.start_time
        return {
            "total_seconds": round(total, 2),
            "step_times": self.step_times
        }
