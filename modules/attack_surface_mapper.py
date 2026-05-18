#!/usr/bin/env python3
"""Attack Surface Mapper - Generate Bug Bounty ready report"""
from typing import Dict, List


class AttackSurfaceMapper:
    """Maps attack surface and generates ready-to-test report."""

    def __init__(self, target: str, data: Dict):
        self.target = target
        self.data = data

    def generate(self) -> str:
        """Generate attack_surface.txt in Bug Bounty format."""
        lines = []
        lines.append("=" * 70)
        lines.append("  ATTACK SURFACE MAP — BUG BOUNTY READY")
        lines.append("=" * 70)
        lines.append(f"  Target: {self.target}")
        lines.append(f"  Generated: {self.data.get('timestamp', 'N/A')}")
        lines.append("")

        # P1 - Critical
        lines.append("─" * 70)
        lines.append("  [P1] CRITICAL TARGETS — Test First")
        lines.append("─" * 70)
        p1_count = self._write_p1(lines)
        lines.append(f"\n  Total P1: {p1_count}")
        lines.append("")

        # P2 - High
        lines.append("─" * 70)
        lines.append("  [P2] HIGH VALUE TARGETS")
        lines.append("─" * 70)
        p2_count = self._write_p2(lines)
        lines.append(f"\n  Total P2: {p2_count}")
        lines.append("")

        # P3 - Medium
        lines.append("─" * 70)
        lines.append("  [P3] MEDIUM VALUE TARGETS")
        lines.append("─" * 70)
        p3_count = self._write_p3(lines)
        lines.append(f"\n  Total P3: {p3_count}")
        lines.append("")

        # P4 - Low
        lines.append("─" * 70)
        lines.append("  [P4] LOW VALUE / INFORMATIONAL")
        lines.append("─" * 70)
        p4_count = self._write_p4(lines)
        lines.append(f"\n  Total P4: {p4_count}")
        lines.append("")

        # Statistics
        lines.append("=" * 70)
        lines.append("  STATISTICS")
        lines.append("=" * 70)
        stats = self.data.get("stats", {})
        lines.append(f"  • Total Endpoints Found:     {stats.get('endpoints', 0)}")
        lines.append(f"  • Testable Parameters:       {stats.get('parameters', 0)}")
        lines.append(f"  • JS Files Analyzed:         {stats.get('js_files', 0)}")
        lines.append(f"  • Hidden APIs from JS:       {stats.get('js_endpoints', 0)}")
        lines.append(f"  • Subdomains Found:          {stats.get('subdomains', 0)}")
        lines.append(f"  • Potential Takeovers:       {stats.get('takeovers', 0)}")
        lines.append(f"  • Secrets Leaked in JS:      {stats.get('secrets', 0)}")
        lines.append(f"  • Injection Points:          {stats.get('injection_points', 0)}")
        lines.append("")

        # Subdomain Takeover
        takeovers = self.data.get("takeovers", [])
        if takeovers:
            lines.append("=" * 70)
            lines.append("  🚨 SUBDOMAIN TAKEOVER CANDIDATES")
            lines.append("=" * 70)
            for t in takeovers:
                lines.append(f"  [{t.get('risk', 'HIGH')}] {t['subdomain']}")
                lines.append(f"      Service: {t.get('service', 'Unknown')}")
                lines.append(f"      Issue: {t.get('issue', '')}")
                lines.append(f"      Note: {t.get('note', '')}")
                lines.append("")

        # Secrets
        secrets = self.data.get("secrets", [])
        if secrets:
            lines.append("=" * 70)
            lines.append("  🔑 SECRETS FOUND IN JS")
            lines.append("=" * 70)
            for s in secrets[:10]:
                lines.append(f"  [{s.get('severity', 'High')}] {s.get('type', s.get('original', {}).get('type', 'Unknown'))}")
                lines.append(f"      Value: {s.get('masked_value', '***')}")
                lines.append(f"      Source: {s.get('source', '')}")
                lines.append("")

        # Injection Points
        injections = self.data.get("injection_points", [])
        if injections:
            lines.append("=" * 70)
            lines.append("  💉 INJECTION POINTS")
            lines.append("=" * 70)
            for ip in injections[:20]:
                lines.append(f"  [{ip.get('type', 'Unknown')}] {ip['parameter']}")
                lines.append(f"      URL: {ip['url'][:80]}")
                lines.append(f"      Test: {', '.join(ip.get('test_payloads', [])[:3])}")
                lines.append("")

        lines.append("=" * 70)
        lines.append("  END OF REPORT — Happy Hunting!")
        lines.append("=" * 70)

        return "\n".join(lines)

    def _write_p1(self, lines: List[str]) -> int:
        """Write P1 critical targets."""
        count = 0
        endpoints = self.data.get("all_endpoints", [])

        # API endpoints
        api_patterns = ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/", "/swagger", "/openapi"]
        for url in endpoints:
            if any(p in url.lower() for p in api_patterns):
                lines.append(f"  [P1] {url}")
                count += 1

        # Admin panels
        admin_patterns = ["/admin", "/wp-admin", "/dashboard", "/panel", "/manage", "/backend", "/cpanel", "/phpmyadmin", "/console"]
        for url in endpoints:
            if any(p in url.lower() for p in admin_patterns):
                lines.append(f"  [P1] {url}")
                count += 1

        # Auth endpoints
        auth_patterns = ["/auth/", "/oauth/", "/sso/", "/token/", "/jwt/", "/bearer/", "/session/", "/api/auth"]
        for url in endpoints:
            if any(p in url.lower() for p in auth_patterns):
                lines.append(f"  [P1] {url}")
                count += 1

        # Password reset
        reset_patterns = ["/reset-password", "/forgot-password", "/password-reset", "/recover", "/reset"]
        for url in endpoints:
            if any(p in url.lower() for p in reset_patterns):
                lines.append(f"  [P1] {url}")
                count += 1

        # Payment endpoints
        payment_patterns = ["/payment", "/billing", "/checkout", "/subscribe", "/upgrade", "/purchase", "/pay/"]
        for url in endpoints:
            if any(p in url.lower() for p in payment_patterns):
                lines.append(f"  [P1] {url}")
                count += 1

        # Hidden APIs from JS
        js_endpoints = self.data.get("js_endpoints", [])
        for url in js_endpoints:
            if any(p in url.lower() for p in api_patterns + auth_patterns):
                lines.append(f"  [P1] {url}  (from JS)")
                count += 1

        if count == 0:
            lines.append("  No P1 targets found.")
        return count

    def _write_p2(self, lines: List[str]) -> int:
        """Write P2 high value targets."""
        count = 0
        endpoints = self.data.get("all_endpoints", [])

        # Upload endpoints
        upload_patterns = ["/upload", "/file/", "/media/", "/attachment/", "/import", "/export", "/bulk-upload"]
        for url in endpoints:
            if any(p in url.lower() for p in upload_patterns):
                lines.append(f"  [P2] {url}")
                count += 1

        # User/account endpoints
        user_patterns = ["/user/", "/account/", "/profile/", "/settings/", "/preferences/", "/me/"]
        for url in endpoints:
            if any(p in url.lower() for p in user_patterns):
                lines.append(f"  [P2] {url}")
                count += 1

        # Download endpoints
        for url in endpoints:
            if "/download" in url.lower() or url.lower().endswith((".csv", ".xlsx", ".pdf", ".zip", ".tar.gz")):
                lines.append(f"  [P2] {url}")
                count += 1

        # Webhook endpoints
        webhook_patterns = ["/webhook", "/callback", "/hook", "/notify", "/event/"]
        for url in endpoints:
            if any(p in url.lower() for p in webhook_patterns):
                lines.append(f"  [P2] {url}")
                count += 1

        # Login pages
        login_patterns = ["/login", "/signin", "/register", "/signup", "/join"]
        for url in endpoints:
            if any(p in url.lower() for p in login_patterns):
                lines.append(f"  [P2] {url}")
                count += 1

        if count == 0:
            lines.append("  No P2 targets found.")
        return count

    def _write_p3(self, lines: List[str]) -> int:
        """Write P3 medium value targets."""
        count = 0
        endpoints = self.data.get("all_endpoints", [])

        # Search endpoints
        search_patterns = ["/search", "/filter", "/sort", "/query", "/find", "?q=", "?search=", "?query="]
        for url in endpoints:
            if any(p in url.lower() for p in search_patterns):
                lines.append(f"  [P3] {url}")
                count += 1

        # Redirect parameters
        redirect_params = ["?redirect=", "?return=", "?next=", "?url=", "?dest=", "?callback="]
        for url in endpoints:
            if any(p in url.lower() for p in redirect_params):
                lines.append(f"  [P3] {url}")
                count += 1

        # Debug endpoints
        debug_patterns = ["/debug", "/test", "/trace", "/profile", "/monitor", "/health", "/status", "/metrics"]
        for url in endpoints:
            if any(p in url.lower() for p in debug_patterns):
                lines.append(f"  [P3] {url}")
                count += 1

        # Subdomains (non-critical)
        subdomains = self.data.get("subdomains", [])
        for sub in subdomains[:10]:
            if sub != self.target.replace("https://", "").replace("http://", "").split("/")[0]:
                lines.append(f"  [P3] https://{sub}")
                count += 1

        if count == 0:
            lines.append("  No P3 targets found.")
        return count

    def _write_p4(self, lines: List[str]) -> int:
        """Write P4 low value targets."""
        count = 0
        endpoints = self.data.get("all_endpoints", [])

        # Static assets
        static_patterns = ["/static/", "/cdn/", "/assets/", "/dist/", "/build/", "/public/", "/resources/"]
        static_exts = [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"]
        for url in endpoints:
            if any(p in url.lower() for p in static_patterns) or any(url.lower().endswith(e) for e in static_exts):
                lines.append(f"  [P4] {url}")
                count += 1

        # Fonts
        font_patterns = ["/fonts/", ".woff", ".woff2", ".ttf", ".eot", ".otf"]
        for url in endpoints:
            if any(p in url.lower() for p in font_patterns):
                lines.append(f"  [P4] {url}")
                count += 1

        # Documentation
        doc_patterns = ["/docs/", "/documentation/", "/help/", "/faq/", "/guide/", "/tutorial/"]
        for url in endpoints:
            if any(p in url.lower() for p in doc_patterns):
                lines.append(f"  [P4] {url}")
                count += 1

        if count == 0:
            lines.append("  No P4 targets found.")
        return count
