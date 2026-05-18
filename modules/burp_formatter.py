#!/usr/bin/env python3
"""Burp Suite Formatter - Export findings in Burp-compatible formats"""
import json
import base64
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List


class BurpFormatter:
    """Formats scan results for Burp Suite import."""

    @staticmethod
    def to_burp_xml(findings: List[Dict], target: str) -> str:
        """Generate Burp Suite XML report (compatible with Burp import)."""
        root = ET.Element("issues", attrib={"burpVersion": "2024.1.1", "exportTime": datetime.now().isoformat()})

        for i, finding in enumerate(findings, 1):
            issue = ET.SubElement(root, "issue")

            ET.SubElement(issue, "serialNumber").text = str(i)
            ET.SubElement(issue, "type").text = finding.get("type", "134217728")
            ET.SubElement(issue, "name").text = finding.get("title", "Unknown Issue")
            ET.SubElement(issue, "host", attrib={"ip": finding.get("ip", "")}).text = finding.get("host", target)
            ET.SubElement(issue, "path").text = finding.get("path", "/")
            ET.SubElement(issue, "location").text = finding.get("location", "")
            ET.SubElement(issue, "severity").text = finding.get("severity", "Information")
            ET.SubElement(issue, "confidence").text = finding.get("confidence", "Certain")

            request = ET.SubElement(issue, "request", attrib={"base64": "false"})
            request.text = finding.get("request", "")

            response = ET.SubElement(issue, "response", attrib={"base64": "false"})
            response.text = finding.get("response", "")[:2000]

            ET.SubElement(issue, "issueBackground").text = finding.get("background", "")
            ET.SubElement(issue, "remediationBackground").text = finding.get("remediation", "")

        return ET.tostring(root, encoding="unicode")

    @staticmethod
    def to_burp_state(data: Dict) -> str:
        """Generate simplified Burp state JSON for Logger++ import."""
        entries = []

        for req in data.get("requests", []):
            entry = {
                "url": req.get("url", ""),
                "method": req.get("method", "GET"),
                "status": req.get("status", 0),
                "request_headers": req.get("headers", {}),
                "response_headers": req.get("response_headers", {}),
                "response_body": req.get("response_body", "")[:1000],
                "timestamp": datetime.now().isoformat(),
            }
            entries.append(entry)

        return json.dumps({"target": data.get("target", ""), "entries": entries}, indent=2)

    @staticmethod
    def to_autorize_format(endpoints: List[str]) -> str:
        """Generate Autorize-compatible endpoint list."""
        lines = ["# Autorize Target Endpoints", f"# Generated: {datetime.now().isoformat()}", ""]

        for ep in endpoints:
            lines.append(ep)

        return "\n".join(lines)

    @staticmethod
    def to_logger_filter(endpoints: List[str]) -> str:
        """Generate Logger++ filter rules."""
        lines = [
            "# Logger++ Filter Rules",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "# Highlight API endpoints",
        ]

        api_patterns = ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/auth/", "/user/", "/admin/"]
        for pattern in api_patterns:
            lines.append(f"RegexFilter: {pattern} -> Color: RED")

        lines.extend([
            "",
            "# Highlight interesting status codes",
            "StatusCodeFilter: 401 -> Color: ORANGE",
            "StatusCodeFilter: 403 -> Color: ORANGE",
            "StatusCodeFilter: 500 -> Color: RED",
            "",
            "# Highlight tokens in responses",
            "ResponseFilter: (token|api_key|secret|password) -> Color: YELLOW",
        ])

        return "\n".join(lines)

    @staticmethod
    def generate_burp_workflow_report(data: Dict) -> str:
        """Generate comprehensive Burp workflow report."""
        lines = []
        lines.append("=" * 70)
        lines.append("  BURP SUITE WORKFLOW REPORT")
        lines.append("=" * 70)
        lines.append(f"  Target: {data.get('target', 'N/A')}")
        lines.append(f"  Generated: {datetime.now().isoformat()}")
        lines.append("")

        # Logger++ targets
        lines.append("─" * 70)
        lines.append("  ① LOGGER++ FILTER TARGETS")
        lines.append("─" * 70)
        lines.append("  Add these to Logger++ Scope:")
        for pattern in ["/api/", "/graphql", "/auth/", "/user/", "/admin/", "/upload/", "/payment/"]:
            lines.append(f"    • {pattern}")
        lines.append("")
        lines.append("  Status codes to watch: 401, 403, 500")
        lines.append("  Save responses containing: token, api_key, secret")
        lines.append("")

        # Autorize setup
        lines.append("─" * 70)
        lines.append("  ② AUTORIZE SETUP")
        lines.append("─" * 70)
        lines.append("  1. Login with Account A (owner)")
        lines.append("  2. Copy Account A's cookies/token to Autorize")
        lines.append("  3. Login with Account B (attacker)")
        lines.append("  4. Browse the application normally")
        lines.append("  5. Watch for 'Bypassed!' in Autorize")
        lines.append("")
        lines.append("  High-value endpoints for Autorize:")
        for ep in data.get("idor_endpoints", [])[:10]:
            lines.append(f"    → {ep}")
        lines.append("")

        # Param Miner targets
        lines.append("─" * 70)
        lines.append("  ③ PARAM MINER TARGETS")
        lines.append("─" * 70)
        lines.append("  Run Param Miner (Passive only) on:")
        for ep in data.get("param_endpoints", [])[:10]:
            lines.append(f"    → {ep}")
        lines.append("")

        # Repeater checklist
        lines.append("─" * 70)
        lines.append("  ④ REPEATER MANUAL CHECKLIST")
        lines.append("─" * 70)
        for i, finding in enumerate(data.get("findings", [])[:15], 1):
            lines.append(f"  [{i}] {finding.get('severity', 'Info')} | {finding.get('type', 'Unknown')}")
            lines.append(f"      URL: {finding.get('url', '')}")
            lines.append(f"      Test: {finding.get('test_payload', '')}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)
