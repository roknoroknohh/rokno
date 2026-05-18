#!/usr/bin/env python3
# rokno_a3 - Report Builder Module (FIXED)
# Handles missing data gracefully - never shows empty/ugly N/A

import json
from datetime import datetime

class ReportBuilder:
    def __init__(self, recon_data: dict, ai_analysis: dict, target: str, domain: str):
        self.recon = recon_data
        self.ai = ai_analysis
        self.target = target
        self.domain = domain
        self.report = {}

    def _safe(self, val, default="غير متوفر"):
        """Return value or default if empty/N/A/error."""
        if val is None:
            return default
        if isinstance(val, str):
            v = val.strip()
            if not v or v.lower() in ("n/a", "na", "", "none", "null", "error", "unknown"):
                return default
            return v
        return val

    def _safe_list(self, val, default=None):
        """Return list or empty list with note."""
        if not val or not isinstance(val, list):
            return default if default is not None else ["لم يتم العثور على بيانات"]
        clean = [x for x in val if x and str(x).strip()]
        return clean if clean else ["لم يتم العثور على بيانات"]

    def build(self) -> dict:
        self.report = {
            "meta": {
                "tool": "rokno_a3",
                "version": "2.0",
                "target": self.target,
                "domain": self.domain,
                "timestamp": datetime.now().isoformat(),
                "mode": "passive_only"
            },
            "sections": {
                "1_site_summary": self._build_site_summary(),
                "2_technologies": self._build_technologies(),
                "3_server_info": self._build_server_info(),
                "4_important_links": self._build_links(),
                "5_subdomains": self._build_subdomains(),
                "6_ai_analysis": self._build_ai_analysis()
            },
            "critical_findings": self.ai.get("critical_findings", []) if self.ai else []
        }
        return self.report

    def _build_site_summary(self) -> dict:
        domain_info = self.recon.get("domain_info", {})
        return {
            "domain": self.domain,
            "target_url": self.target,
            "registrar": self._safe(domain_info.get("registrar")),
            "creation_date": self._safe(domain_info.get("creation_date")),
            "expiration_date": self._safe(domain_info.get("expiration_date")),
            "name_servers": self._safe_list(domain_info.get("name_servers", [])),
            "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M")
        }

    def _build_technologies(self) -> dict:
        techs = self.recon.get("technologies", [])
        # Filter out error entries
        clean_techs = []
        for t in techs:
            if isinstance(t, dict) and not t.get("error"):
                clean_techs.append(t)
            elif isinstance(t, str):
                clean_techs.append({"name": t, "version": ""})

        return {
            "detected_count": len(clean_techs),
            "technologies": clean_techs[:15] if clean_techs else [{"name": "لم يتم التعرف على تقنيات", "version": ""}],
            "categories": self._categorize_techs(clean_techs)
        }

    def _categorize_techs(self, techs: list) -> dict:
        cats = {"cms": [], "framework": [], "server": [], "analytics": [], "other": []}
        cms_kw = ["wordpress", "drupal", "joomla", "magento", "shopify"]
        fw_kw = ["react", "vue", "angular", "django", "flask", "laravel", "next.js", "nuxt"]
        srv_kw = ["apache", "nginx", "iis", "cloudflare", "cdn"]
        ana_kw = ["analytics", "gtag", "facebook", "pixel", "mixpanel"]

        for t in techs:
            name = str(t.get("name", t)).lower()
            if any(k in name for k in cms_kw):
                cats["cms"].append(t)
            elif any(k in name for k in fw_kw):
                cats["framework"].append(t)
            elif any(k in name for k in srv_kw):
                cats["server"].append(t)
            elif any(k in name for k in ana_kw):
                cats["analytics"].append(t)
            else:
                cats["other"].append(t)

        # Fill empty categories with note
        for k in cats:
            if not cats[k]:
                cats[k] = ["غير مكتشف"]
        return cats

    def _build_server_info(self) -> dict:
        headers_data = self.recon.get("server_headers", {})
        headers = headers_data.get("headers", {}) if isinstance(headers_data, dict) else {}

        security_headers = {}
        sec_list = ["strict-transport-security", "content-security-policy",
                    "x-frame-options", "x-content-type-options", "x-xss-protection",
                    "referrer-policy", "permissions-policy"]
        for h in sec_list:
            val = headers.get(h, headers.get(h.lower(), headers.get(h.title(), "NOT SET")))
            security_headers[h] = self._safe(val, "غير مفعل")

        status = headers_data.get("status_code", "N/A") if isinstance(headers_data, dict) else "N/A"

        return {
            "status_code": self._safe(status),
            "server_software": self._safe(headers.get("server", headers.get("Server", "غير معلن"))),
            "powered_by": self._safe(headers.get("x-powered-by", headers.get("X-Powered-By", "غير معلن"))),
            "content_type": self._safe(headers.get("content-type", headers.get("Content-Type", "غير معروف"))),
            "security_headers": security_headers,
            "security_score": self._calc_security_score(security_headers)
        }

    def _calc_security_score(self, sec_headers: dict) -> str:
        present = sum(1 for v in sec_headers.values() if v not in ("غير مفعل", "NOT SET", "غير متوفر", ""))
        total = len(sec_headers)
        ratio = present / total if total > 0 else 0
        if ratio >= 0.7:
            return "جيد ✅"
        elif ratio >= 0.4:
            return "متوسط ⚠️"
        return "ضعيف ❌"

    def _build_links(self) -> dict:
        links = self.recon.get("discovered_links", [])
        js_links = self.recon.get("js_links", [])

        interesting = self._find_interesting_paths(links + js_links)

        return {
            "total_discovered": len(links),
            "total_js_endpoints": len(js_links),
            "sample_links": self._safe_list(links[:10]),
            "sample_js_endpoints": self._safe_list(js_links[:10]),
            "interesting_paths": self._safe_list(interesting[:10], ["لم يتم العثور على مسارات مثيرة للاهتمام"])
        }

    def _find_interesting_paths(self, links: list) -> list:
        interesting = []
        keywords = ["admin", "api", "login", "config", "backup", "debug",
                    ".env", "swagger", "graphql", "wp-content", "phpmyadmin",
                    "/api/", "/admin/", "/panel/", "/manage/", "/dashboard/"]
        for link in links:
            low = str(link).lower()
            if any(k in low for k in keywords):
                interesting.append(link)
        return list(set(interesting))

    def _build_subdomains(self) -> dict:
        subs = self.recon.get("subdomains", [])
        return {
            "total_found": len(subs),
            "subdomains": self._safe_list(subs[:20]),
            "has_wildcard": any("*" in str(s) for s in subs)
        }

    def _build_ai_analysis(self) -> dict:
        if not self.ai:
            return {
                "initial_analysis": "التحليل الذكي غير متوفر",
                "refined_analysis": "الخدمة الخارجية غير متوفرة حالياً",
                "top_3_points": ["لا توجد نقاط متاحة"],
                "priority_ranking": ["لا يوجد ترتيب متاح"],
                "executive_summary": "التحليل الذكي غير متوفر. تم الاعتماد على البيانات المحلية فقط."
            }

        return {
            "initial_analysis": self._safe(self.ai.get("initial_analysis"), "تحليل أولي غير متوفر"),
            "refined_analysis": self._safe(self.ai.get("refined_analysis"), "تحليل محسن غير متوفر"),
            "top_3_points": self._safe_list(self.ai.get("top_3_points", [])),
            "priority_ranking": self._safe_list(self.ai.get("priority_ranking", [])),
            "executive_summary": self._extract_executive_summary()
        }

    def _extract_executive_summary(self) -> str:
        refined = self.ai.get("refined_analysis", "") if self.ai else ""
        lines = [l.strip() for l in refined.split("\n") if l.strip()]
        summary_lines = [l for l in lines if len(l) < 120][-2:]
        return "\n".join(summary_lines) if summary_lines else "التحليل الذكي غير متوفر حالياً."

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.report, ensure_ascii=False, indent=indent)

    def to_text(self) -> str:
        r = self.report
        s = r["sections"]
        C = self._color

        lines = [
            C("=" * 65, "cyan"),
            C("           ROKNO_A3 - FINAL INTELLIGENCE REPORT", "cyan+bold"),
            C("=" * 65, "cyan"),
            "",
            C(f"  Target: {self.target}", "yellow"),
            C(f"  Domain: {self.domain}", "yellow"),
            C(f"  Date:   {r['meta']['timestamp']}", "dim"),
            C("-" * 65, "dim"),
            "",
            C("  [1] SITE SUMMARY", "green+bold"),
            f"      Registrar: {s['1_site_summary']['registrar']}",
            f"      Created:   {s['1_site_summary']['creation_date']}",
            f"      Expires:   {s['1_site_summary']['expiration_date']}",
            "",
            C("  [2] TECHNOLOGIES", "green+bold"),
            f"      Detected: {s['2_technologies']['detected_count']}",
        ]

        for t in s['2_technologies']['technologies'][:8]:
            if isinstance(t, dict):
                name = t.get('name', 'unknown')
                ver = t.get('version', '')
                src = t.get('source', '')
                ver_str = f" v{ver}" if ver else ""
                src_str = f" [{src}]" if src else ""
                lines.append(f"      • {name}{ver_str}{src_str}")
            else:
                lines.append(f"      • {t}")

        lines.extend([
            "",
            C("  [3] SERVER INFO", "green+bold"),
            f"      Status: {s['3_server_info']['status_code']}",
            f"      Server: {s['3_server_info']['server_software']}",
            f"      Powered By: {s['3_server_info']['powered_by']}",
            f"      Security Score: {s['3_server_info']['security_score']}",
            "",
            C("  [4] LINKS & ENDPOINTS", "green+bold"),
            f"      Discovered URLs: {s['4_important_links']['total_discovered']}",
            f"      JS Endpoints: {s['4_important_links']['total_js_endpoints']}",
            f"      Interesting Paths: {len(s['4_important_links']['interesting_paths'])}",
        ])

        for p in s['4_important_links']['interesting_paths'][:5]:
            lines.append(f"      ! {p}")

        lines.extend([
            "",
            C("  [5] SUBDOMAINS", "green+bold"),
            f"      Found: {s['5_subdomains']['total_found']}",
        ])
        for sub in s['5_subdomains']['subdomains'][:5]:
            lines.append(f"      • {sub}")

        lines.extend([
            "",
            C("  [6] AI ANALYSIS", "magenta+bold"),
            C("      Top 3 Points:", "white+bold"),
        ])
        for p in s['6_ai_analysis']['top_3_points']:
            lines.append(f"      → {p}")

        lines.extend([
            "",
            C("      Executive Summary:", "white+bold"),
            f"      {s['6_ai_analysis']['executive_summary']}",
            "",
            C("=" * 65, "cyan"),
        ])

        if r['critical_findings']:
            lines.append(C("  ⚠️  CRITICAL FINDINGS:", "red+bold"))
            for cf in r['critical_findings']:
                lines.append(C(f"      ! {cf}", "yellow"))
            lines.append(C("=" * 65, "cyan"))

        return "\n".join(lines)

    def _color(self, text: str, style: str) -> str:
        """Apply ANSI color codes."""
        codes = {
            "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
            "blue": "\033[94m", "cyan": "\033[96m", "magenta": "\033[95m",
            "white": "\033[97m", "dim": "\033[2m", "bold": "\033[1m",
            "reset": "\033[0m"
        }
        parts = style.split("+")
        out = ""
        for p in parts:
            out += codes.get(p, "")
        return f"{out}{text}\033[0m"
