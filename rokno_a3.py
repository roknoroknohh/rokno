#!/usr/bin/env python3
import sys, os, json, asyncio, time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.domain_info import DomainInfo
from modules.subdomain_finder import SubdomainFinder
from modules.link_collector import LinkCollector
from modules.parameter_discovery import ParameterDiscovery
from modules.js_analyzer import JSAnalyzer
from modules.subdomain_takeover import SubdomainTakeover
from modules.attack_surface_mapper import AttackSurfaceMapper
from modules.server_headers import ServerHeaders
from modules.tech_detect import TechDetect
from modules.browser_engine import CloudflareBypass
from modules.idor_tester import IDORTester
from modules.token_validator import TokenValidator
from modules.burp_formatter import BurpFormatter
from modules.cookie_manager import CookieManager

R, G, Y, B = "\033[91m", "\033[92m", "\033[93m", "\033[94m"
M, C, D = "\033[95m", "\033[96m", "\033[90m"
BOLD, RESET = "\033[1m", "\033[0m"

def banner():
    print(f"""
{M}{BOLD}    ╔═══════════════════════════════════════════════════════════════╗{RESET}
{M}{BOLD}    ║   ██████╗  ██████╗ ██╗  ██╗███╗   ██╗ ██████╗               ║{RESET}
{M}{BOLD}    ║   ██╔══██╗██╔═══██╗██║ ██╔╝████╗  ██║██╔═══██╗              ║{RESET}
{M}{BOLD}    ║   ██████╔╝██║   ██║█████╔╝ ██╔██╗ ██║██║   ██║              ║{RESET}
{M}{BOLD}    ║   ██╔══██╗██║   ██║██╔═██╗ ██║╚██╗██║██║   ██║              ║{RESET}
{M}{BOLD}    ║   ██║  ██║╚██████╔╝██║  ██╗██║ ╚████║╚██████╔╝              ║{RESET}
{M}{BOLD}    ║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝               ║{RESET}
{C}{BOLD}    ║  BUG BOUNTY + BURP COMPANION v2.2                             ║{RESET}
{C}{BOLD}    ║  Dynamic IDOR | Token Validator | Cloudflare Bypass           ║{RESET}
{M}{BOLD}    ╚═══════════════════════════════════════════════════════════════╝{RESET}
    """)

async def safe_call(func, *args, **kwargs):
    result = func(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return await result
    return result

async def run_scan(target_url, use_browser=False):
    start_time = time.time()
    target_url = target_url.rstrip("/")
    domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    cookie_mgr = CookieManager()
    browser_cookies = {}

    print(f"\n{Y}[TARGET]{RESET} {BOLD}{target_url}{RESET}")
    print(f"{Y}[DOMAIN]{RESET} {domain}")
    print(f"{D}{'─' * 60}{RESET}")

    # Browser
    browser_data = None
    if use_browser:
        print(f"\n{C}[BROWSER]{RESET} {BOLD}Launching browser...{RESET}")
        try:
            browser_data = await CloudflareBypass.fetch(target_url)
            print(f"      {G}✓{RESET} Bypassed: {browser_data.get('cloudflare_passed', False)}")
            print(f"      {G}✓{RESET} API calls: {len(browser_data.get('api_calls', []))}")
            for c in browser_data.get("cookies", []):
                browser_cookies[c["name"]] = c["value"]
                cookie_mgr.cookies[c["name"]] = c["value"]
        except Exception as e:
            print(f"      {Y}⚠{RESET} {e}")

    # Domain Info
    print(f"\n{C}[1/7]{RESET} {BOLD}Domain reconnaissance...{RESET}")
    info = await safe_call(DomainInfo(target_url).gather)
    print(f"      {G}✓{RESET} IP: {info.get('ip', 'N/A')}")
    print(f"      {G}✓{RESET} Root: {info.get('root_domain', domain)}")

    # Recon
    print(f"\n{C}[2-5/7]{RESET} {BOLD}Running reconnaissance...{RESET}")
    subdomains = await safe_call(SubdomainFinder(domain).find_all)
    print(f"      {G}✓{RESET} Subdomains: {Y}{len(subdomains)}{RESET}")

    links_data = await safe_call(LinkCollector(domain, target_url).collect_all)
    all_links = links_data.get("discovered_links", [])
    js_urls = [u for u in all_links if u.endswith(".js")]
    js_endpoints = links_data.get("js_links", [])
    print(f"      {G}✓{RESET} Links: {Y}{len(all_links)}{RESET}")
    print(f"      {G}✓{RESET} JS Files: {Y}{len(js_urls)}{RESET}")

    headers_obj = ServerHeaders(target_url)
    headers = await safe_call(headers_obj.fetch)
    print(f"      {G}✓{RESET} Server: {headers.get('Server', 'Unknown')}")

    # Deep Analysis
    print(f"\n{C}[6/7]{RESET} {BOLD}Deep analysis...{RESET}")
    param_results = await safe_call(ParameterDiscovery(all_links).discover)
    js_results = await safe_call(JSAnalyzer(js_urls, target_url).analyze_all)
    takeover_results = await safe_call(SubdomainTakeover(subdomains).check_all)
    techs = TechDetect(target_url).detect(html=headers_obj.html or "", headers=headers)

    # IDOR Testing
    idor_endpoints = [ep["url"] for ep in param_results.get("injection_points", [])[:20]]
    idor_results = {"idor_found": 0, "missing_auth": 0}
    if idor_endpoints:
        print(f"      {C}→{RESET} Testing {len(idor_endpoints)} endpoints for IDOR...")
        idor_tester = IDORTester(idor_endpoints, cookies=browser_cookies)
        idor_results = await idor_tester.test_all()
        print(f"      {R if idor_results['idor_found'] > 0 else G}✓{RESET} IDOR: {idor_results['idor_found']}")
        print(f"      {R if idor_results['missing_auth'] > 0 else G}✓{RESET} Missing Auth: {idor_results['missing_auth']}")

    # TOKEN VALIDATION — NEW
    secrets = js_results.get("secrets_found", [])
    validated_secrets = []
    if secrets:
        print(f"      {C}→{RESET} Validating {len(secrets)} discovered secrets...")
        validator = TokenValidator()
        validated_secrets = await validator.validate_all(secrets)
        real_count = len([s for s in validated_secrets if s["status"] in ["REAL & ACTIVE", "LIVE KEY"]])
        fake_count = len([s for s in validated_secrets if s["status"] in ["FAKE/DUMMY", "LIKELY_FAKE"]])
        expired_count = len([s for s in validated_secrets if s["status"] == "EXPIRED"])
        print(f"      {R if real_count > 0 else G}✓{RESET} Real & Active: {real_count}")
        print(f"      {Y}✓{RESET} Fake/Placeholder: {fake_count}")
        print(f"      {Y}✓{RESET} Expired: {expired_count}")

    takeover_count = takeover_results.get('summary', {}).get('high_risk', 0)
    print(f"      {G}✓{RESET} Parameters: {Y}{param_results.get('total_injection_points', 0)}{RESET}")
    print(f"      {G}✓{RESET} Hidden APIs: {Y}{len(js_results.get('endpoints_found', []))}{RESET}")
    print(f"      {G}✓{RESET} Secrets: {Y}{len(secrets)}{RESET}")

    # Reports
    print(f"\n{C}[7/7]{RESET} {BOLD}Generating reports...{RESET}")
    out_dir = f"output/{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    os.makedirs(out_dir, exist_ok=True)

    all_endpoints = list(set(all_links + js_results.get("endpoints_found", []) + js_endpoints))

    attack_data = {
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "all_endpoints": all_endpoints,
        "subdomains": subdomains,
        "js_endpoints": js_results.get("endpoints_found", []),
        "secrets": validated_secrets,
        "takeovers": takeover_results.get("vulnerable", []),
        "injection_points": param_results.get("injection_points", []),
        "idor_findings": idor_results.get("findings", []),
        "stats": {
            "endpoints": len(all_endpoints),
            "parameters": param_results.get("total_injection_points", 0),
            "js_files": len(js_urls),
            "js_endpoints": len(js_results.get("endpoints_found", [])),
            "subdomains": len(subdomains),
            "takeovers": takeover_count,
            "secrets": len(secrets),
            "real_secrets": len([s for s in validated_secrets if s["status"] in ["REAL & ACTIVE", "LIVE KEY"]]),
            "fake_secrets": len([s for s in validated_secrets if s["status"] in ["FAKE/DUMMY", "LIKELY_FAKE"]]),
            "idor_found": idor_results.get("idor_found", 0),
            "missing_auth": idor_results.get("missing_auth", 0),
        },
    }

    with open(f"{out_dir}/attack_surface.txt", "w", encoding="utf-8") as f:
        f.write(AttackSurfaceMapper(target_url, attack_data).generate())

    burp_data = {"target": target_url, "idor_endpoints": idor_endpoints,
        "param_endpoints": [ep["url"] for ep in param_results.get("injection_points", [])[:20]],
        "findings": idor_results.get("findings", [])}
    with open(f"{out_dir}/burp_workflow.txt", "w", encoding="utf-8") as f:
        f.write(BurpFormatter.generate_burp_workflow_report(burp_data))

    # Secrets report
    if validated_secrets:
        with open(f"{out_dir}/validated_secrets.txt", "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("  VALIDATED SECRETS REPORT\n")
            f.write("=" * 60 + "\n\n")
            for s in validated_secrets:
                f.write(f"[{s['status']}] {s['original'].get('type', 'Unknown')}\n")
                f.write(f"  Source: {s['original'].get('source', '')}\n")
                f.write(f"  Value: {s['original'].get('masked_value', '')}\n")
                f.write(f"  Confidence: {s['confidence']}\n")
                f.write(f"  Details: {s['details']}\n")
                f.write(f"  Risk: {s['risk_level']}\n\n")

    burp_findings = []
    for finding in idor_results.get("findings", []):
        burp_findings.append({
            "title": f"IDOR: {finding.get('endpoint', '')}",
            "severity": finding.get("severity", "High"),
            "host": domain, "path": finding.get("endpoint", ""),
            "type": "134217728",
            "request": f"GET {finding.get('endpoint', '')} HTTP/1.1\nHost: {domain}",
            "response": str(finding.get("case_original", {}).get("body_preview", ""))[:500],
            "background": finding.get("evidence", ""),
            "remediation": "Implement proper authorization checks.",
        })
    with open(f"{out_dir}/burp_import.xml", "w", encoding="utf-8") as f:
        f.write(BurpFormatter.to_burp_xml(burp_findings, target_url))

    with open(f"{out_dir}/logger_filter.txt", "w", encoding="utf-8") as f:
        f.write(BurpFormatter.to_logger_filter(all_endpoints))

    with open(f"{out_dir}/autorize_targets.txt", "w", encoding="utf-8") as f:
        f.write(BurpFormatter.to_autorize_format(idor_endpoints))

    with open(f"{out_dir}/data.json", "w", encoding="utf-8") as f:
        json.dump({
            "scan_info": {"target": target_url, "domain": domain,
                "started_at": datetime.now().isoformat(),
                "duration_seconds": round(time.time() - start_time, 2),
                "browser_used": use_browser},
            "domain_info": info, "subdomains": subdomains, "links": all_links,
            "js_analysis": js_results, "parameters": param_results,
            "takeover": takeover_results, "technologies": techs, "headers": headers,
            "idor": idor_results, "validated_secrets": validated_secrets,
            "browser_data": browser_data,
        }, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - start_time
    print(f"\n{G}{BOLD}✅ Scan complete in {round(elapsed, 1)}s{RESET}")
    print(f"{B}📁 Reports:{RESET} {out_dir}/")
    print(f"   {D}• attack_surface.txt{RESET}")
    print(f"   {D}• validated_secrets.txt{RESET}")
    print(f"   {D}• burp_workflow.txt{RESET}")
    print(f"   {D}• burp_import.xml{RESET}")
    print(f"   {D}• logger_filter.txt{RESET}")
    print(f"   {D}• autorize_targets.txt{RESET}")
    print(f"   {D}• data.json{RESET}")

    print(f"\n{Y}{BOLD}📊 SUMMARY:{RESET}")
    print(f"   {G}✓{RESET} Endpoints:     {Y}{len(all_endpoints)}{RESET}")
    print(f"   {G}✓{RESET} Parameters:    {Y}{param_results.get('total_injection_points', 0)}{RESET}")
    print(f"   {G}✓{RESET} Hidden APIs:   {Y}{len(js_results.get('endpoints_found', []))}{RESET}")
    print(f"   {G}✓{RESET} Secrets Found: {Y}{len(secrets)}{RESET}")
    if validated_secrets:
        real = len([s for s in validated_secrets if s["status"] in ["REAL & ACTIVE", "LIVE KEY"]])
        fake = len([s for s in validated_secrets if s["status"] in ["FAKE/DUMMY", "LIKELY_FAKE"]])
        print(f"   {R if real > 0 else G}✓{RESET} Real Secrets:  {real}{RESET}")
        print(f"   {Y}✓{RESET} Fake Secrets:  {fake}{RESET}")
    print(f"   {G}✓{RESET} IDOR:          {R if idor_results.get('idor_found', 0) > 0 else Y} {idor_results.get('idor_found', 0)}{RESET}")
    print(f"   {G}✓{RESET} Missing Auth:  {R if idor_results.get('missing_auth', 0) > 0 else Y} {idor_results.get('missing_auth', 0)}{RESET}")

def main():
    banner()
    if len(sys.argv) < 2:
        print(f"{Y}[!] Usage:{RESET} python3 rokno_a3.py <URL> [--browser]")
        sys.exit(1)
    target = sys.argv[1]
    use_browser = "--browser" in sys.argv
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    try:
        asyncio.run(run_scan(target, use_browser))
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted.{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{R}[!] Error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
