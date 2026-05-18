#!/usr/bin/env python3
# Rokno AI — Bug Bounty Attack Surface Mapper v1.0
# Passive only | No API keys | ARM64 ready | <4GB RAM

import sys
import os
import json
import asyncio
import time
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

# ANSI Colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
M = "\033[95m"; C = "\033[96m"; D = "\033[90m"
BOLD = "\033[1m"; RESET = "\033[0m"


def banner():
    print(f"""
{M}{BOLD}    ╔═══════════════════════════════════════════════════════════════╗{RESET}
{M}{BOLD}    ║                                                               ║{RESET}
{M}{BOLD}    ║   ██████╗  ██████╗ ██╗  ██╗███╗   ██╗ ██████╗               ║{RESET}
{M}{BOLD}    ║   ██╔══██╗██╔═══██╗██║ ██╔╝████╗  ██║██╔═══██╗              ║{RESET}
{M}{BOLD}    ║   ██████╔╝██║   ██║█████╔╝ ██╔██╗ ██║██║   ██║              ║{RESET}
{M}{BOLD}    ║   ██╔══██╗██║   ██║██╔═██╗ ██║╚██╗██║██║   ██║              ║{RESET}
{M}{BOLD}    ║   ██║  ██║╚██████╔╝██║  ██╗██║ ╚████║╚██████╔╝              ║{RESET}
{M}{BOLD}    ║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝               ║{RESET}
{M}{BOLD}    ║                                                               ║{RESET}
{C}{BOLD}    ║     BUG BOUNTY ATTACK SURFACE MAPPER v1.0                     ║{RESET}
{C}{BOLD}    ║        Passive | No API Keys | ARM64 Ready                    ║{RESET}
{M}{BOLD}    ╚═══════════════════════════════════════════════════════════════╝{RESET}
    """)


async def run_scan(target_url: str):
    start_time = time.time()
    target_url = target_url.rstrip("/")
    domain = target_url.replace("https://", "").replace("http://", "").split("/")[0]

    print(f"\n{Y}[TARGET]{RESET} {BOLD}{target_url}{RESET}")
    print(f"{Y}[DOMAIN]{RESET} {domain}")
    print(f"{D}{'─' * 60}{RESET}")

    # ── Phase 1: Domain Info ──
    print(f"\n{C}[1/6]{RESET} {BOLD}Domain reconnaissance...{RESET}")
    domain_info = DomainInfo(target_url)
    info = await domain_info.gather()
    print(f"      {G}✓{RESET} IP: {info.get('ip', 'N/A')}")
    print(f"      {G}✓{RESET} Root Domain: {info.get('root_domain', domain)}")

    # ── Phase 2-4: Parallel recon ──
    print(f"\n{C}[2-4/6]{RESET} {BOLD}Running parallel reconnaissance...{RESET}")

    finder = SubdomainFinder(domain)
    collector = LinkCollector(domain, target_url)
    headers_obj = ServerHeaders(target_url)

    recon_tasks = [
        finder.find_all(),
        collector.collect_all(),
        headers_obj.fetch(),
    ]
    subdomains, links_data, headers = await asyncio.gather(*recon_tasks)

    all_links = links_data["discovered_links"]
    js_urls = [u for u in all_links if u.endswith(".js")]
    js_endpoints = links_data["js_links"]

    print(f"      {G}✓{RESET} Subdomains: {Y}{len(subdomains)}{RESET}")
    print(f"      {G}✓{RESET} Links: {Y}{len(all_links)}{RESET}")
    print(f"      {G}✓{RESET} JS Files: {Y}{len(js_urls)}{RESET}")
    print(f"      {G}✓{RESET} JS Endpoints: {Y}{len(js_endpoints)}{RESET}")

    # ── Phase 5: Deep Analysis (parallel) ──
    print(f"\n{C}[5/6]{RESET} {BOLD}Deep analysis (JS + Parameters + Takeover)...{RESET}")

    # Parameter discovery
    param_disc = ParameterDiscovery(all_links)
    param_results = param_disc.discover()

    # JS deep analysis
    js_analyzer = JSAnalyzer(js_urls, target_url)
    js_results = await js_analyzer.analyze_all()

    # Subdomain takeover check
    takeover_checker = SubdomainTakeover(subdomains)
    takeover_results = await takeover_checker.check_all()

    # Tech detection
    tech_obj = TechDetect(target_url)
    techs = tech_obj.detect(html=headers_obj.html or "", headers=headers)

    total_endpoints = len(all_links) + len(js_results.get("endpoints_found", []))

    print(f"      {G}✓{RESET} Parameters: {Y}{param_results['total_injection_points']}{RESET}")
    print(f"      {G}✓{RESET} Hidden APIs from JS: {Y}{len(js_results.get('endpoints_found', []))}{RESET}")
    print(f"      {G}✓{RESET} Secrets in JS: {Y}{len(js_results.get('secrets_found', []))}{RESET}")
    print(f"      {G}✓{RESET} Takeover candidates: {R if takeover_results['summary']['high_risk'] > 0 else Y}{takeover_results['summary']['high_risk']}{RESET}")
    print(f"      {G}✓{RESET} Technologies: {Y}{', '.join(techs) if techs else 'None'}{RESET}")

    # ── Phase 6: Generate Attack Surface Report ──
    print(f"\n{C}[6/6]{RESET} {BOLD}Generating attack surface report...{RESET}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = f"output/{domain}_{timestamp}"
    os.makedirs(out_dir, exist_ok=True)

    # Combine all endpoints
    all_endpoints = list(set(all_links + js_results.get("endpoints_found", []) + js_endpoints))

    attack_data = {
        "timestamp": datetime.now().isoformat(),
        "target": target_url,
        "all_endpoints": all_endpoints,
        "subdomains": subdomains,
        "js_endpoints": js_results.get("endpoints_found", []),
        "secrets": js_results.get("secrets_found", []),
        "takeovers": takeover_results.get("vulnerable", []),
        "injection_points": param_results.get("injection_points", []),
        "stats": {
            "endpoints": len(all_endpoints),
            "parameters": param_results["total_injection_points"],
            "js_files": len(js_urls),
            "js_endpoints": len(js_results.get("endpoints_found", [])),
            "subdomains": len(subdomains),
            "takeovers": takeover_results["summary"]["high_risk"],
            "secrets": len(js_results.get("secrets_found", [])),
            "injection_points": param_results["total_injection_points"],
        },
    }

    mapper = AttackSurfaceMapper(target_url, attack_data)
    attack_surface_report = mapper.generate()

    # Save attack_surface.txt
    attack_path = f"{out_dir}/attack_surface.txt"
    with open(attack_path, "w", encoding="utf-8") as f:
        f.write(attack_surface_report)

    # Save JSON
    json_path = f"{out_dir}/data.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "scan_info": {
                "target": target_url,
                "domain": domain,
                "started_at": datetime.now().isoformat(),
                "duration_seconds": round(time.time() - start_time, 2),
            },
            "domain_info": info,
            "subdomains": subdomains,
            "links": all_links,
            "js_analysis": js_results,
            "parameters": param_results,
            "takeover": takeover_results,
            "technologies": techs,
            "headers": headers,
        }, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - start_time
    print(f"\n{G}{BOLD}✅ Scan complete in {round(elapsed, 1)}s{RESET}")
    print(f"{B}📁 Reports saved to:{RESET} {out_dir}/")
    print(f"   {D}• attack_surface.txt  (main report){RESET}")
    print(f"   {D}• data.json           (raw data){RESET}")
    print(f"{D}{'─' * 60}{RESET}")

    # Print summary
    print(f"\n{Y}{BOLD}📊 SUMMARY:{RESET}")
    print(f"   {G}✓{RESET} Endpoints Found:     {Y}{len(all_endpoints)}{RESET}")
    print(f"   {G}✓{RESET} Testable Parameters: {Y}{param_results['total_injection_points']}{RESET}")
    print(f"   {G}✓{RESET} Hidden APIs in JS:   {Y}{len(js_results.get('endpoints_found', []))}{RESET}")
    print(f"   {G}✓{RESET} Abandoned Subdomains:{R if takeover_results['summary']['high_risk'] > 0 else Y} {takeover_results['summary']['high_risk']}{RESET}")
    print(f"   {G}✓{RESET} Secrets Leaked:      {R if len(js_results.get('secrets_found', [])) > 0 else Y} {len(js_results.get('secrets_found', []))}{RESET}")
    print("")

    # Print attack surface preview
    print(attack_surface_report[:3000])
    print(f"\n{D}... (full report in {attack_path}){RESET}")


def main():
    banner()
    if len(sys.argv) < 2:
        print(f"{Y}[!] Usage:{RESET} python3 rokno_a3.py <URL>")
        print(f"{Y}[!] Example:{RESET} python3 rokno_a3.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    try:
        asyncio.run(run_scan(target))
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Interrupted by user.{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{R}[!] Error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
