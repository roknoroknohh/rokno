#!/usr/bin/env python3
"""Subdomain Takeover Detection - Passive checks only"""
import asyncio
import socket
from typing import Dict, List


class SubdomainTakeover:
    """Checks subdomains for potential takeover vulnerabilities."""

    # Services vulnerable to takeover with their CNAME patterns
    TAKEOVER_SERVICES = {
        "AWS S3": ["s3.amazonaws.com", "s3-website"],
        "AWS CloudFront": ["cloudfront.net"],
        "GitHub Pages": ["github.io", "github.com"],
        "Heroku": ["herokuapp.com", "herokussl.com"],
        "Vercel": ["vercel.app", "vercel.com", "now.sh"],
        "Netlify": ["netlify.app", "netlify.com"],
        "Firebase": ["firebaseapp.com", "web.app"],
        "Shopify": ["myshopify.com"],
        "Fastly": ["fastly.net"],
        "Pantheon": ["pantheonsite.io"],
        "Tumblr": ["tumblr.com"],
        "WordPress.com": ["wordpress.com"],
        "Ghost.io": ["ghost.io"],
        "Surge.sh": ["surge.sh"],
        "Bitbucket": ["bitbucket.io"],
        "Azure": ["azurewebsites.net", "cloudapp.net", "blob.core.windows.net"],
        "Google Cloud": ["appspot.com", "googlehosted.com"],
        "Zendesk": ["zendesk.com"],
        "Help Scout": ["helpscoutdocs.com"],
        "Statuspage": ["statuspage.io"],
        "Unbounce": ["unbouncepages.com"],
        "Webflow": ["webflow.io"],
        "Squarespace": ["squarespace.com"],
        "Wix": ["wixsite.com"],
        "Strikingly": ["strikinglydns.com"],
        "Mashery": ["mashery.com"],
        "SendGrid": ["sendgrid.net"],
        "Mailgun": ["mailgun.org"],
        "GetResponse": ["gr8.com"],
        "Airee": ["airee.ru"],
        "Anima": ["animaapp.io"],
        "LaunchRock": ["launchrock.com"],
        "Readme.io": ["readme.io"],
        "Smartling": ["smartling.com"],
        "Worksites": ["worksites.net"],
    }

    def __init__(self, subdomains: List[str]):
        self.subdomains = subdomains
        self.vulnerable = []
        self.suspicious = []

    async def check_all(self) -> Dict:
        """Check all subdomains for takeover indicators."""
        tasks = [self._check_subdomain(sub) for sub in self.subdomains]
        await asyncio.gather(*tasks)

        return {
            "total_checked": len(self.subdomains),
            "vulnerable": self.vulnerable,
            "suspicious": self.suspicious,
            "summary": {
                "high_risk": len(self.vulnerable),
                "medium_risk": len(self.suspicious),
                "safe": len(self.subdomains) - len(self.vulnerable) - len(self.suspicious),
            },
        }

    async def _check_subdomain(self, subdomain: str):
        """Check a single subdomain for takeover indicators."""
        try:
            # Try DNS resolution
            try:
                ip = socket.gethostbyname(subdomain)
            except socket.gaierror:
                # NXDOMAIN - domain doesn't resolve
                # Check CNAME record
                cname = await self._get_cname(subdomain)
                if cname:
                    service = self._detect_service(cname)
                    if service:
                        self.vulnerable.append({
                            "subdomain": subdomain,
                            "issue": "NXDOMAIN with dangling CNAME",
                            "cname": cname,
                            "service": service,
                            "risk": "HIGH",
                            "note": f"Subdomain points to {service} but the resource no longer exists. Potential takeover!",
                        })
                    else:
                        self.suspicious.append({
                            "subdomain": subdomain,
                            "issue": "NXDOMAIN",
                            "cname": cname,
                            "service": "Unknown",
                            "risk": "MEDIUM",
                            "note": "Subdomain does not resolve. Check if CNAME is dangling.",
                        })
                return

            # If it resolves, check for known takeover fingerprints
            await self._check_http_fingerprints(subdomain)

        except Exception:
            pass

    async def _get_cname(self, subdomain: str) -> str:
        """Get CNAME record for subdomain."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "CNAME", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            cname = stdout.decode().strip()
            return cname.rstrip(".") if cname else ""
        except Exception:
            return ""

    def _detect_service(self, cname: str) -> str:
        """Detect which service a CNAME points to."""
        cname_lower = cname.lower()
        for service, patterns in self.TAKEOVER_SERVICES.items():
            for pattern in patterns:
                if pattern in cname_lower:
                    return service
        return ""

    async def _check_http_fingerprints(self, subdomain: str):
        """Check HTTP response for takeover fingerprints."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sI", "--max-time", "8", f"http://{subdomain}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            response = stdout.decode().lower()

            # Known takeover fingerprints
            fingerprints = {
                "github pages": ["there isn't a github pages site here", "404 not found"],
                "heroku": ["no such app", "there is no app configured at this hostname"],
                "aws s3": ["no such bucket", "the specified bucket does not exist"],
                "shopify": ["sorry, this shop is currently unavailable"],
                "fastly": ["fastly error: unknown domain"],
                "ghost": ["404 - page not found"],
                "pantheon": ["404 unknown site!"],
                "tumblr": ["not found"],
                "wordpress.com": ["do you want to register"],
                "azure": ["404 web site not found", "error 404 - web app not found"],
                "webflow": ["the page you are looking for doesn't exist"],
                "surge.sh": ["project not found"],
                "readme.io": ["project doesnt exist"],
                "netlify": ["not found - request id:"],
            }

            for service, indicators in fingerprints.items():
                for indicator in indicators:
                    if indicator in response:
                        self.vulnerable.append({
                            "subdomain": subdomain,
                            "issue": f"HTTP fingerprint: {service}",
                            "cname": "",
                            "service": service,
                            "risk": "HIGH",
                            "note": f"Response matches {service} takeover fingerprint.",
                        })
                        return

        except Exception:
            pass
