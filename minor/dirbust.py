#!/usr/bin/env python3
"""
Directory Brute-Forcer
======================
WHAT THIS DOES:
    Discovers hidden files and directories on a web server by trying
    common paths. Finds things like:
    - /admin, /dashboard — admin panels
    - /backup, /db — exposed backups/databases
    - /.git, /.env — leaked source code and secrets
    - /api/docs, /swagger — undocumented API endpoints

WHY IT MATTERS:
    Web servers often have pages/files that aren't linked from the
    main site but are still accessible. This is one of the most
    common findings in real pentests — forgotten admin panels,
    exposed config files, backup archives.

    Real operators use tools like Gobuster, Feroxbuster, and dirsearch.

HOW IT WORKS:
    1. Take a wordlist of common directory/file names
    2. Send HTTP requests to target.com/{word}
    3. Check the response code:
       - 200 = exists and accessible
       - 301/302 = redirect (probably exists)
       - 403 = forbidden (exists but blocked — interesting!)
       - 404 = doesn't exist
       - 500 = server error (might be exploitable)

USAGE:
    python3 dirbust.py http://target.com
    python3 dirbust.py http://target.com -w /path/to/wordlist.txt
    python3 dirbust.py http://target.com -x php,html,txt  # try extensions
    python3 dirbust.py http://target.com --codes 200,301,403
"""

import sys
import argparse
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Default wordlist — focused on high-value targets
# For real engagements, use SecLists:
# https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
DEFAULT_WORDLIST = [
    # Admin panels
    "admin", "administrator", "admin.php", "admin.html",
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    "administrator", "admin/login", "admin/dashboard",
    "panel", "cpanel", "dashboard", "manage", "management",
    "control", "controlpanel",
    # Login pages
    "login", "login.php", "login.html", "signin", "sign-in",
    "auth", "authenticate", "oauth", "sso",
    # API endpoints
    "api", "api/v1", "api/v2", "api/v3", "api/docs",
    "swagger", "swagger.json", "swagger.yaml",
    "swagger-ui", "swagger-ui.html",
    "openapi", "openapi.json",
    "graphql", "graphiql", "playground",
    "api-docs", "docs", "documentation",
    "health", "healthcheck", "health-check",
    "status", "info", "version",
    "metrics", "prometheus",
    # Source code / version control leaks
    ".git", ".git/config", ".git/HEAD",
    ".svn", ".svn/entries",
    ".hg", ".bzr",
    ".gitignore", ".gitattributes",
    # Config / secrets
    ".env", ".env.local", ".env.production", ".env.backup",
    "config", "config.php", "config.yml", "config.json",
    "configuration", "settings", "settings.php",
    "web.config", "web.xml",
    ".htaccess", ".htpasswd",
    "phpinfo.php", "info.php",
    "wp-config.php", "wp-config.php.bak",
    "database.yml", "database.php",
    # Backup files
    "backup", "backups", "backup.sql", "backup.zip",
    "backup.tar.gz", "db.sql", "database.sql",
    "dump.sql", "data.sql",
    "site.zip", "www.zip", "html.zip",
    "backup.tar", "archive.zip", "archive.tar.gz",
    # Common directories
    "uploads", "upload", "files", "documents",
    "images", "img", "media", "assets", "static",
    "css", "js", "javascript", "fonts",
    "includes", "include", "inc",
    "lib", "libs", "library",
    "vendor", "node_modules", "packages",
    "tmp", "temp", "cache", "logs", "log",
    # Server files
    "robots.txt", "sitemap.xml", "sitemap.txt",
    "crossdomain.xml", "security.txt", ".well-known/security.txt",
    "favicon.ico", "humans.txt",
    # Common apps
    "phpmyadmin", "pma", "mysql", "adminer", "adminer.php",
    "jenkins", "travis", "circleci",
    "kibana", "grafana", "prometheus",
    "nagios", "zabbix", "cacti",
    "tomcat", "jmx-console", "web-console",
    "manager", "manager/html",
    "console", "debug", "trace",
    # Testing / dev
    "test", "testing", "debug", "dev", "development",
    "staging", "stage", "demo", "sandbox",
    "phpunit", "tests", "spec",
    # Error pages (can leak info)
    "error", "errors", "404", "500",
    # User-related
    "user", "users", "account", "accounts", "profile",
    "register", "signup", "password", "reset",
    # E-commerce
    "cart", "checkout", "shop", "store", "products",
    "payment", "pay", "order", "orders",
    # CMS
    "wordpress", "joomla", "drupal", "magento",
    "wp-json", "wp-json/wp/v2/users",
    "xmlrpc.php", "readme.html",
    # Server info
    "server-status", "server-info",  # Apache
    "nginx-status",  # Nginx
    "elmah.axd",  # .NET error log
    "trace.axd",  # .NET tracing
]


def check_path(base_url, path, timeout=5):
    """
    Check if a path exists on the target web server.

    Returns (path, status_code, content_length, redirect_url)
    """
    url = f"{base_url.rstrip('/')}/{path}"

    try:
        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/120.0.0.0 Safari/537.36")

        response = urllib.request.urlopen(req, timeout=timeout)
        size = len(response.read(10000))  # Read up to 10KB
        return path, response.status, size, response.url

    except urllib.error.HTTPError as e:
        return path, e.code, 0, None

    except (urllib.error.URLError, TimeoutError, ConnectionError):
        return path, 0, 0, None

    except Exception:
        return path, 0, 0, None


def dirbust(base_url, wordlist=None, extensions=None, threads=20,
            show_codes=None, timeout=5):
    """
    Run directory brute force against a target URL.

    Args:
        base_url: Target URL (e.g., http://target.com)
        wordlist: List of paths to try
        extensions: File extensions to append (e.g., ["php", "html"])
        threads: Concurrent request threads
        show_codes: Only show these HTTP status codes
        timeout: Request timeout in seconds
    """
    words = wordlist or DEFAULT_WORDLIST

    # Build the full path list
    paths = list(words)
    if extensions:
        for word in words:
            for ext in extensions:
                paths.append(f"{word}.{ext}")

    paths = list(set(paths))  # Deduplicate
    total = len(paths)

    start_time = datetime.now()
    results = []
    checked = 0

    # Default to showing interesting status codes
    if show_codes is None:
        show_codes = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(check_path, base_url, path, timeout): path
            for path in paths
        }

        for future in as_completed(futures):
            checked += 1
            path, status, size, redirect = future.result()

            if status in show_codes:
                result = {
                    "path": path,
                    "status": status,
                    "size": size,
                    "redirect": redirect,
                }
                results.append(result)

                status_color = ""
                if status == 200:
                    status_color = "\033[92m"  # green
                elif status in (301, 302, 307, 308):
                    status_color = "\033[93m"  # yellow
                elif status == 403:
                    status_color = "\033[91m"  # red
                elif status in (401,):
                    status_color = "\033[91m"  # red
                elif status >= 500:
                    status_color = "\033[95m"  # magenta
                reset = "\033[0m"

                redirect_info = f" → {redirect}" if redirect and redirect != f"{base_url.rstrip('/')}/{path}" else ""
                print(f"  {status_color}[{status}]{reset} /{path:<40} {size:>6}B{redirect_info}")

            if total > 50 and checked % (total // 10) == 0:
                pct = (checked / total) * 100
                sys.stdout.write(f"\r  [{pct:.0f}% — {checked}/{total}]")
                sys.stdout.flush()

    if total > 50:
        print()

    duration = (datetime.now() - start_time).total_seconds()
    return results, duration


def display_results(base_url, results, duration):
    """Display results summary."""
    print(f"\n{'='*60}")
    print(f"Directory Brute-Force Report: {base_url}")
    print(f"{'='*60}")
    print(f"Duration: {duration:.1f}s")

    if not results:
        print("No interesting paths found.")
        return

    # Group by status code
    by_status = {}
    for r in results:
        by_status.setdefault(r["status"], []).append(r)

    for status in sorted(by_status.keys()):
        paths = by_status[status]
        status_label = {
            200: "OK (Accessible)",
            301: "Moved Permanently",
            302: "Found (Redirect)",
            307: "Temporary Redirect",
            401: "Unauthorized (Auth Required)",
            403: "Forbidden (Exists but Blocked)",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }.get(status, f"Status {status}")

        print(f"\n[{status}] {status_label}:")
        for r in sorted(paths, key=lambda x: x["path"]):
            print(f"  /{r['path']}")

    # Highlight critical findings
    critical = [r for r in results if any(
        keyword in r["path"].lower()
        for keyword in [".env", ".git", "backup", "config", "admin",
                        "phpinfo", "wp-config", "database", "dump"]
    ) and r["status"] in (200, 403)]

    if critical:
        print(f"\n⚠ CRITICAL FINDINGS:")
        for r in critical:
            print(f"  [{r['status']}] /{r['path']}")

    print(f"\n{len(results)} paths found")


def main():
    parser = argparse.ArgumentParser(description="Directory Brute-Forcer")
    parser.add_argument("url", help="Target URL (e.g., http://target.com)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
    parser.add_argument("-x", "--extensions", help="Extensions to try (e.g., php,html,txt)")
    parser.add_argument("-t", "--threads", type=int, default=20)
    parser.add_argument("--codes", help="Status codes to show (e.g., 200,301,403)")
    parser.add_argument("--timeout", type=float, default=5)

    args = parser.parse_args()

    wordlist = None
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [line.strip() for line in f if line.strip()]

    extensions = args.extensions.split(",") if args.extensions else None
    show_codes = set(int(c) for c in args.codes.split(",")) if args.codes else None

    print(f"[*] Target: {args.url}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Wordlist: {len(wordlist or DEFAULT_WORDLIST)} paths")
    if extensions:
        print(f"[*] Extensions: {', '.join(extensions)}")

    results, duration = dirbust(
        args.url,
        wordlist=wordlist,
        extensions=extensions,
        threads=args.threads,
        show_codes=show_codes,
        timeout=args.timeout,
    )
    display_results(args.url, results, duration)


if __name__ == "__main__":
    main()
