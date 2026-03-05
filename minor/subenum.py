#!/usr/bin/env python3
"""
Subdomain Enumerator
====================
WHAT THIS DOES:
    Discovers subdomains of a target domain using multiple techniques:
    1. DNS brute-force (tries common subdomain names)
    2. Certificate Transparency logs (public SSL cert records)
    3. DNS zone transfer attempt (misconfigured DNS servers leak everything)

WHY IT MATTERS:
    This is the #1 external recon technique. A company might lock down
    www.target.com but forget about dev.target.com, staging.target.com,
    or admin.target.com. Every subdomain is a potential entry point.

    Real operators use tools like Amass, Subfinder, and Sublist3r.
    We're building the core logic from scratch so you understand it.

HOW IT WORKS:
    DNS Brute Force:
        - Take a wordlist of common subdomain names (dev, staging, admin, etc.)
        - For each word, try to resolve {word}.target.com
        - If it resolves to an IP → subdomain exists

    Certificate Transparency:
        - SSL certificates are logged in public databases
        - Query crt.sh to find all certificates issued for *.target.com
        - Each cert reveals subdomains that exist (or existed)

    Zone Transfer:
        - DNS servers can be configured to share their full zone file
        - If misconfigured, we get EVERY subdomain in one request
        - Rare but devastating when it works

USAGE:
    python3 subenum.py example.com
    python3 subenum.py example.com -w /path/to/wordlist.txt
    python3 subenum.py example.com --ct-only    # just cert transparency
"""

import sys
import argparse
import socket
import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# Default wordlist — common subdomain names
# In real engagements you'd use SecLists:
# https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
DEFAULT_SUBDOMAINS = [
    # Dev/staging
    "dev", "development", "staging", "stage", "stg", "test", "testing",
    "qa", "uat", "sandbox", "demo", "beta", "alpha", "preview",
    "pre-prod", "preprod", "next",
    # Infrastructure
    "api", "api2", "api-v2", "api-dev", "api-staging", "api-test",
    "app", "application", "web", "www", "www2", "www3",
    "mail", "email", "smtp", "pop", "imap", "webmail", "mx",
    "ftp", "sftp", "ssh", "vpn", "remote", "gateway", "gw",
    "proxy", "cdn", "cache", "edge", "lb", "loadbalancer",
    "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    # Admin/management
    "admin", "administrator", "panel", "portal", "manage", "management",
    "dashboard", "console", "control", "cp", "cpanel", "whm",
    "cms", "backend", "backoffice", "internal", "intranet",
    # Services
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "elastic", "elasticsearch", "kibana", "grafana", "prometheus",
    "jenkins", "ci", "cd", "gitlab", "git", "bitbucket",
    "jira", "confluence", "wiki", "docs", "documentation",
    "sentry", "monitor", "monitoring", "status", "health",
    "log", "logs", "logging", "splunk", "datadog",
    # Storage/media
    "files", "file", "upload", "uploads", "media", "assets",
    "static", "images", "img", "storage", "s3", "backup", "backups",
    "archive",
    # Auth
    "auth", "login", "sso", "oauth", "identity", "id", "accounts",
    "signup", "register",
    # Communication
    "chat", "slack", "teams", "meet", "zoom", "video",
    "blog", "news", "forum", "community", "support", "help",
    "helpdesk", "ticket", "tickets",
    # Cloud/hosting
    "cloud", "aws", "azure", "gcp", "heroku", "docker",
    "k8s", "kubernetes", "cluster", "node", "worker",
    # Security
    "secure", "security", "waf", "firewall",
    # Misc
    "shop", "store", "pay", "payment", "billing", "checkout",
    "search", "analytics", "track", "tracking",
    "m", "mobile", "ios", "android",
    "old", "new", "legacy", "v1", "v2", "v3",
    "lab", "labs", "research", "data", "bi",
    "crm", "erp", "hr", "corp", "corporate",
    "exchange", "autodiscover", "owa",  # Microsoft
    "lyncdiscover", "sip",  # Skype/Teams
]


def dns_resolve(subdomain, domain):
    """Try to resolve a subdomain via DNS lookup."""
    fqdn = f"{subdomain}.{domain}"
    try:
        answers = socket.getaddrinfo(fqdn, None)
        ips = set()
        for answer in answers:
            ip = answer[4][0]
            ips.add(ip)
        return fqdn, list(ips)
    except (socket.gaierror, socket.herror):
        return fqdn, None


def brute_force_subdomains(domain, wordlist, threads=50):
    """
    DNS brute force — try every word in the list as a subdomain.

    This is "active" recon — you're directly querying the target's
    DNS infrastructure. It's detectable if they're monitoring DNS logs.
    """
    found = {}
    total = len(wordlist)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(dns_resolve, word, domain): word
            for word in wordlist
        }

        for i, future in enumerate(as_completed(futures), 1):
            fqdn, ips = future.result()
            if ips:
                found[fqdn] = ips
                print(f"  [+] {fqdn} → {', '.join(ips)}")

            if total > 20 and i % (total // 10) == 0:
                pct = (i / total) * 100
                sys.stdout.write(f"\r  [{pct:.0f}% complete]")
                sys.stdout.flush()

    if total > 20:
        print()

    return found


def cert_transparency_lookup(domain):
    """
    Query Certificate Transparency logs via crt.sh.

    CT logs are public databases of every SSL/TLS certificate ever issued.
    When a company gets an SSL cert for staging.target.com, it gets
    logged here. This is "passive" recon — the target has no idea
    you're looking.

    This is one of the most powerful recon techniques because:
    - It's completely passive (no direct contact with target)
    - It finds subdomains that might not be in any wordlist
    - It can reveal internal naming conventions
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read())

            for entry in data:
                name = entry.get("name_value", "")
                # CT entries can have multiple names separated by newlines
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        # Remove wildcard prefix
                        sub = sub.lstrip("*.")
                        if sub and sub != domain:
                            subdomains.add(sub)

    except urllib.error.URLError as e:
        print(f"  [!] CT lookup failed: {e}")
    except json.JSONDecodeError:
        print(f"  [!] CT lookup returned invalid data")
    except Exception as e:
        print(f"  [!] CT lookup error: {e}")

    return subdomains


def attempt_zone_transfer(domain):
    """
    Try a DNS zone transfer (AXFR).

    This is like asking a DNS server: "Give me EVERYTHING."
    Most servers won't allow it, but when they do, you get the
    complete list of all subdomains, mail servers, etc.

    This is a serious misconfiguration and an instant win in a pentest.
    """
    import subprocess

    subdomains = set()

    # First get the nameservers
    try:
        ns_records = socket.getaddrinfo(domain, None)
    except Exception:
        return subdomains

    # Try zone transfer against each nameserver
    try:
        result = subprocess.run(
            ["dig", "axfr", domain, f"@ns1.{domain}"],
            capture_output=True, text=True, timeout=10,
        )
        if "Transfer failed" not in result.stdout and result.stdout.strip():
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts and parts[0].endswith(f".{domain}."):
                    sub = parts[0].rstrip(".")
                    if sub != domain:
                        subdomains.add(sub)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return subdomains


def resolve_subdomains(subdomains, domain, threads=50):
    """Resolve a set of subdomain FQDNs to IP addresses."""
    resolved = {}

    def resolve_one(sub):
        try:
            answers = socket.getaddrinfo(sub, None)
            ips = list(set(a[4][0] for a in answers))
            return sub, ips
        except Exception:
            return sub, None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_one, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            sub, ips = future.result()
            if ips:
                resolved[sub] = ips

    return resolved


def enumerate_subdomains(domain, wordlist=None, threads=50, ct_only=False):
    """Run full subdomain enumeration."""
    all_subdomains = {}

    # Phase 1: Certificate Transparency (passive)
    print(f"\n[*] Phase 1: Certificate Transparency lookup")
    ct_subs = cert_transparency_lookup(domain)
    if ct_subs:
        print(f"  [+] Found {len(ct_subs)} subdomains in CT logs")
        resolved = resolve_subdomains(ct_subs, domain, threads)
        all_subdomains.update(resolved)
        for sub, ips in sorted(resolved.items()):
            print(f"  [+] {sub} → {', '.join(ips)}")
    else:
        print(f"  [-] No results from CT logs")

    if ct_only:
        return all_subdomains

    # Phase 2: Zone Transfer (opportunistic)
    print(f"\n[*] Phase 2: Zone transfer attempt")
    zt_subs = attempt_zone_transfer(domain)
    if zt_subs:
        print(f"  [+] ZONE TRANSFER SUCCESSFUL! Found {len(zt_subs)} records")
        resolved = resolve_subdomains(zt_subs, domain, threads)
        all_subdomains.update(resolved)
    else:
        print(f"  [-] Zone transfer not allowed (expected)")

    # Phase 3: DNS Brute Force (active)
    words = wordlist or DEFAULT_SUBDOMAINS
    print(f"\n[*] Phase 3: DNS brute force ({len(words)} words)")
    brute_results = brute_force_subdomains(domain, words, threads)
    all_subdomains.update(brute_results)

    return all_subdomains


def display_results(domain, subdomains):
    """Display final results."""
    print(f"\n{'='*60}")
    print(f"Subdomain Enumeration Report: {domain}")
    print(f"{'='*60}\n")

    if not subdomains:
        print("No subdomains found.")
        return

    # Group by IP to find shared hosting
    ip_to_subs = {}
    for sub, ips in sorted(subdomains.items()):
        for ip in ips:
            ip_to_subs.setdefault(ip, []).append(sub)

    print(f"{'Subdomain':<45} {'IP Address'}")
    print("-" * 60)
    for sub, ips in sorted(subdomains.items()):
        print(f"{sub:<45} {', '.join(ips)}")

    print(f"\n{len(subdomains)} unique subdomains found")
    print(f"{len(ip_to_subs)} unique IP addresses")

    # Show shared hosting
    shared = {ip: subs for ip, subs in ip_to_subs.items() if len(subs) > 1}
    if shared:
        print(f"\nShared hosting detected:")
        for ip, subs in shared.items():
            print(f"  {ip}: {', '.join(subs)}")


def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=50)
    parser.add_argument("--ct-only", action="store_true",
                        help="Only use Certificate Transparency (passive)")

    args = parser.parse_args()

    wordlist = None
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [line.strip() for line in f if line.strip()]

    subdomains = enumerate_subdomains(
        args.domain, wordlist=wordlist, threads=args.threads,
        ct_only=args.ct_only,
    )
    display_results(args.domain, subdomains)


if __name__ == "__main__":
    main()
