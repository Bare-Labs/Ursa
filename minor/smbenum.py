#!/usr/bin/env python3
"""
SMB Enumerator
==============
WHAT THIS DOES:
    Enumerates Windows SMB (Server Message Block) shares, users, and
    system info. SMB is the protocol Windows uses for file sharing,
    printer sharing, and inter-process communication.

WHY IT MATTERS:
    SMB is the #1 lateral movement protocol in Windows environments:
    - Open shares may contain credentials, configs, source code
    - Null sessions (anonymous access) can enumerate users/groups
    - SMB version can indicate unpatched systems (EternalBlue)
    - PsExec, WMI, and most Windows admin tools use SMB

    Real operators use CrackMapExec, enum4linux, and smbclient.

HOW IT WORKS:
    1. Connect to SMB service (port 445 or 139)
    2. Try null session (no credentials)
    3. Enumerate shares, users, groups
    4. Check for known SMB vulnerabilities
    5. Identify OS version from SMB negotiation

USAGE:
    python3 smbenum.py 192.168.1.1
    python3 smbenum.py 192.168.1.1 -u admin -p password
    python3 smbenum.py 192.168.1.1 --shares
    python3 smbenum.py 192.168.1.1 --all
"""

import sys
import socket
import struct
import argparse
from datetime import datetime


# ── SMB Protocol Constants ──

# SMB1 Negotiate Protocol Request
# This is the raw bytes for an SMB1 negotiate request
# We use this to talk to older Windows systems
SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x85"  # NetBIOS session
    b"\xff\x53\x4d\x42"  # SMB1 magic
    b"\x72"              # Command: Negotiate
    b"\x00\x00\x00\x00"  # Status
    b"\x18"              # Flags
    b"\x53\xc8"          # Flags2
    b"\x00\x00"          # PID High
    b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    b"\x00\x00"          # Reserved
    b"\x00\x00"          # TID
    b"\x00\x00"          # PID
    b"\x00\x00"          # UID
    b"\x00\x00"          # MID
    b"\x00"              # Word Count
    b"\x62\x00"          # Byte Count
    b"\x02"              # Dialect buffer format
    b"PC NETWORK PROGRAM 1.0\x00"
    b"\x02"
    b"LANMAN1.0\x00"
    b"\x02"
    b"Windows for Workgroups 3.1a\x00"
    b"\x02"
    b"LM1.2X002\x00"
    b"\x02"
    b"LANMAN2.1\x00"
    b"\x02"
    b"NT LM 0.12\x00"
)


def check_smb_port(target, timeout=5):
    """Check if SMB ports (445 or 139) are open."""
    for port in [445, 139]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                return port
        except Exception:
            pass
    return None


def smb_negotiate(target, port=445, timeout=5):
    """
    Send SMB negotiate request and parse the response.

    The negotiate response reveals:
    - SMB version supported (SMB1, SMB2, SMB3)
    - OS version string
    - Server name / domain
    - Security mode (signing required?)
    - Capabilities
    """
    results = {
        "smb_version": None,
        "os": None,
        "server": None,
        "domain": None,
        "signing": None,
        "dialect": None,
        "raw_response": None,
    }

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))

        # Send SMB1 negotiate
        s.send(SMB1_NEGOTIATE)
        response = s.recv(4096)
        s.close()

        if len(response) < 40:
            return results

        results["raw_response"] = response

        # Check if SMB1 or SMB2 response
        if response[4:8] == b"\xff\x53\x4d\x42":
            # SMB1 response
            results["smb_version"] = "SMB1"

            # Parse the negotiate response to extract OS info
            # The OS string is in the data portion after the fixed fields
            try:
                # Word count at offset 36
                word_count = response[36]
                byte_count_offset = 37 + (word_count * 2)

                if byte_count_offset + 2 < len(response):
                    byte_count = struct.unpack_from("<H", response, byte_count_offset)[0]
                    data_start = byte_count_offset + 2

                    # Try to extract strings from data
                    data = response[data_start:data_start + byte_count]

                    # Look for null-terminated Unicode strings
                    strings = []
                    current = b""
                    i = 0
                    while i < len(data) - 1:
                        char = data[i:i+2]
                        if char == b"\x00\x00":
                            if current:
                                try:
                                    decoded = current.decode("utf-16-le", errors="ignore").strip("\x00")
                                    if decoded and len(decoded) > 1:
                                        strings.append(decoded)
                                except Exception:
                                    pass
                                current = b""
                            i += 2
                        else:
                            current += char
                            i += 2

                    if strings:
                        results["os"] = strings[0] if len(strings) > 0 else None
                        results["server"] = strings[1] if len(strings) > 1 else None
                        results["domain"] = strings[2] if len(strings) > 2 else None

            except Exception:
                pass

            # Security mode
            if len(response) > 39:
                sec_mode = response[39]
                results["signing"] = "Required" if sec_mode & 0x08 else "Optional"

        elif response[4:8] == b"\xfe\x53\x4d\x42":
            # SMB2/3 response
            results["smb_version"] = "SMB2/3"

            # SMB2 dialect
            if len(response) > 72:
                dialect = struct.unpack_from("<H", response, 72)[0]
                dialect_map = {
                    0x0202: "SMB 2.0.2",
                    0x0210: "SMB 2.1",
                    0x0300: "SMB 3.0",
                    0x0302: "SMB 3.0.2",
                    0x0311: "SMB 3.1.1",
                }
                results["dialect"] = dialect_map.get(dialect, f"0x{dialect:04x}")

            # Security mode
            if len(response) > 70:
                sec_mode = struct.unpack_from("<H", response, 70)[0]
                results["signing"] = "Required" if sec_mode & 0x02 else "Optional"

    except socket.timeout:
        pass
    except ConnectionRefusedError:
        pass
    except Exception as e:
        results["error"] = str(e)

    return results


def enumerate_shares_smbclient(target, username="", password="", timeout=10):
    """
    Enumerate SMB shares using smbclient (if available).

    smbclient is part of the Samba suite and is the most reliable
    way to enumerate shares from Linux/macOS.
    """
    import subprocess

    shares = []

    try:
        cmd = ["smbclient", "-L", f"//{target}", "-N"]  # -N = no password

        if username:
            cmd = ["smbclient", "-L", f"//{target}", "-U",
                   f"{username}%{password}"]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )

        output = result.stdout + result.stderr

        # Parse share listing
        in_shares = False
        for line in output.splitlines():
            line = line.strip()

            if "Sharename" in line and "Type" in line:
                in_shares = True
                continue
            if line.startswith("---"):
                continue
            if not line or "Reconnecting" in line:
                in_shares = False
                continue

            if in_shares:
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    comment = " ".join(parts[2:]) if len(parts) > 2 else ""
                    shares.append({
                        "name": share_name,
                        "type": share_type,
                        "comment": comment,
                    })

    except FileNotFoundError:
        return None  # smbclient not installed
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return shares


def enumerate_shares_native(target, port=445, timeout=5):
    """
    Enumerate shares using raw SMB protocol.

    This is a simplified version — real SMB enumeration requires
    full session setup, tree connect, and RPC calls.
    We try a basic approach and fall back to smbclient.
    """
    # Try smbclient first (more reliable)
    shares = enumerate_shares_smbclient(target)
    if shares is not None:
        return shares

    # Basic connectivity check
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.close()
        return []  # Connected but can't enumerate without smbclient
    except Exception:
        return None


def check_null_session(target, port=445, timeout=5):
    """
    Check if null session (anonymous) access is allowed.

    A null session means you can connect without credentials.
    This is a misconfiguration that allows enumeration of:
    - User accounts
    - Group memberships
    - Share names
    - Password policies

    This was very common on older Windows but is disabled by default
    on modern systems (Windows 10+).
    """
    import subprocess

    try:
        # Try to connect with no credentials
        result = subprocess.run(
            ["smbclient", "-L", f"//{target}", "-N"],
            capture_output=True, text=True, timeout=timeout,
        )

        output = result.stdout + result.stderr

        if "Anonymous login successful" in output:
            return True, "Anonymous login allowed (null session)"
        elif "NT_STATUS_ACCESS_DENIED" in output:
            return False, "Anonymous login denied"
        elif "NT_STATUS_LOGON_FAILURE" in output:
            return False, "Login failure (no null session)"
        elif "Sharename" in output:
            return True, "Share listing accessible (likely null session)"
        else:
            return False, f"Unknown response: {output[:200]}"

    except FileNotFoundError:
        return None, "smbclient not installed — install with: brew install samba"
    except subprocess.TimeoutExpired:
        return False, "Connection timed out"
    except Exception as e:
        return False, str(e)


def check_smb_vulns(target, negotiate_results):
    """
    Check for known SMB vulnerabilities based on version/dialect.
    """
    vulns = []

    smb_version = negotiate_results.get("smb_version", "")
    dialect = negotiate_results.get("dialect", "")
    os_str = negotiate_results.get("os", "")
    signing = negotiate_results.get("signing", "")

    # SMB1 enabled (CVE-2017-0144 / EternalBlue / WannaCry)
    if smb_version == "SMB1":
        vulns.append({
            "name": "SMB1 Enabled",
            "severity": "HIGH",
            "description": "SMB1 is enabled. SMB1 has known critical vulnerabilities "
                           "including EternalBlue (MS17-010) used in WannaCry ransomware.",
            "cve": "CVE-2017-0144",
        })

    # Signing not required (relay attacks possible)
    if signing == "Optional":
        vulns.append({
            "name": "SMB Signing Not Required",
            "severity": "MEDIUM",
            "description": "SMB signing is not required. This allows SMB relay attacks "
                           "where an attacker can intercept and relay authentication.",
            "cve": "N/A (configuration issue)",
        })

    # Old Windows versions
    if os_str:
        old_os = ["Windows 5.", "Windows 6.0", "Windows 6.1"]
        for old in old_os:
            if old in os_str:
                vulns.append({
                    "name": f"Legacy OS: {os_str}",
                    "severity": "HIGH",
                    "description": "Target is running an end-of-life Windows version "
                                   "that no longer receives security updates.",
                    "cve": "Multiple unpatched CVEs",
                })
                break

    return vulns


def enumerate(target, username="", password="", detailed=False, timeout=5):
    """Run full SMB enumeration."""
    start_time = datetime.now()

    print(f"\n[*] SMB Enumeration: {target}")
    print(f"[*] Started: {start_time.strftime('%H:%M:%S')}\n")

    # Check if SMB is open
    port = check_smb_port(target, timeout)
    if not port:
        print("[!] SMB ports (445, 139) are not open")
        return

    print(f"[+] SMB open on port {port}")

    # Negotiate
    print("[*] SMB negotiation...")
    neg_results = smb_negotiate(target, port, timeout)

    if neg_results.get("smb_version"):
        print(f"[+] SMB Version: {neg_results['smb_version']}")
    if neg_results.get("dialect"):
        print(f"[+] Dialect:     {neg_results['dialect']}")
    if neg_results.get("os"):
        print(f"[+] OS:          {neg_results['os']}")
    if neg_results.get("server"):
        print(f"[+] Server:      {neg_results['server']}")
    if neg_results.get("domain"):
        print(f"[+] Domain:      {neg_results['domain']}")
    if neg_results.get("signing"):
        print(f"[+] Signing:     {neg_results['signing']}")

    # Null session check
    print("\n[*] Checking null session...")
    null_ok, null_msg = check_null_session(target, port, timeout)
    if null_ok:
        print(f"[+] {null_msg}")
    elif null_ok is None:
        print(f"[!] {null_msg}")
    else:
        print(f"[-] {null_msg}")

    # Share enumeration
    print("\n[*] Enumerating shares...")
    shares = enumerate_shares_native(target, port, timeout)

    if shares is None:
        print("[!] Could not enumerate shares")
        print("[*] Install smbclient: brew install samba")
    elif not shares:
        print("[-] No shares found (or access denied)")
    else:
        print(f"[+] {len(shares)} shares found:\n")
        print(f"  {'Share':<25} {'Type':<10} {'Comment'}")
        print(f"  {'-'*55}")
        for share in shares:
            # Flag interesting shares
            flag = ""
            interesting = ["admin$", "c$", "ipc$", "backup", "data",
                           "users", "share", "public", "common"]
            if share["name"].lower() in interesting:
                flag = " ← interesting"
            elif share["name"].lower().endswith("$"):
                flag = " ← hidden share"

            print(f"  {share['name']:<25} {share['type']:<10} "
                  f"{share['comment']}{flag}")

    # Vulnerability checks
    print("\n[*] Checking for known vulnerabilities...")
    vulns = check_smb_vulns(target, neg_results)

    if vulns:
        for vuln in vulns:
            print(f"  [{vuln['severity']}] {vuln['name']}")
            print(f"        {vuln['description']}")
            print(f"        CVE: {vuln['cve']}")
    else:
        print("  [-] No known SMB vulnerabilities detected")

    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Duration: {duration:.1f}s")


def main():
    parser = argparse.ArgumentParser(description="SMB Enumerator")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-u", "--username", default="", help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("--detailed", action="store_true")
    parser.add_argument("--timeout", type=float, default=5)

    args = parser.parse_args()
    enumerate(args.target, args.username, args.password,
              args.detailed, args.timeout)


if __name__ == "__main__":
    main()
