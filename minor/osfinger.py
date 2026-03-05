#!/usr/bin/env python3
"""
OS Fingerprinting
=================
WHAT THIS DOES:
    Identifies the operating system of a remote host by analyzing how
    its TCP/IP stack behaves. Every OS implements networking slightly
    differently — these differences are fingerprints.

WHY IT MATTERS:
    Knowing the OS tells you:
    - What exploits to try (Linux vs Windows vs macOS)
    - What post-exploitation tools to use
    - What shell commands work (bash vs powershell)
    - What privilege escalation paths exist

    This is what nmap -O does under the hood.

HOW IT WORKS:
    Passive fingerprinting (from packet analysis):
        - TTL: Linux=64, Windows=128, Cisco=255
        - TCP window size: differs by OS
        - TCP options and their order

    Active fingerprinting (we send crafted probes):
        - SYN with specific options → analyze SYN-ACK response
        - TCP timestamp behavior
        - IP ID sequence analysis
        - ICMP response analysis
        - FIN/NULL/XMAS scan responses (different OSes respond differently)

    Banner grabbing (service-level):
        - SSH banners reveal OS (OpenSSH_8.9p1 Ubuntu)
        - HTTP Server headers (Apache on Debian, IIS on Windows)
        - SMB negotiation reveals Windows version

USAGE:
    sudo python3 osfinger.py 192.168.1.1
    sudo python3 osfinger.py 192.168.1.1 --detailed
    python3 osfinger.py 192.168.1.1 --passive   # banner-only (no root needed)
"""

import sys
import socket
import struct
import argparse
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from scapy.all import (
    IP, TCP, ICMP, UDP, Raw, sr1, sr, conf,
)

conf.verb = 0


# ── Known OS Signatures ──

# TTL values by OS family
TTL_SIGNATURES = {
    (0, 64): "Linux/Unix/macOS",
    (65, 128): "Windows",
    (129, 255): "Cisco/Network Device",
}

# TCP window sizes (initial) by OS
WINDOW_SIGNATURES = {
    5840: "Linux 2.4/2.6",
    5720: "Google Linux",
    8192: "Windows XP/2003",
    16384: "OpenBSD/AIX",
    65535: "Windows 7/8/10/11 or macOS",
    64240: "Linux 4.x/5.x",
    29200: "Linux 3.x",
    14600: "Linux 3.x (alt)",
    28960: "Linux 5.x",
    32120: "Linux (alt)",
    32768: "Cisco IOS",
    4128: "Cisco IOS (alt)",
    61320: "Linux 5.x/6.x",
    65160: "Linux 6.x",
    26883: "macOS Sonoma+",
    131072: "macOS (large window)",
}

# SSH banner → OS mapping
SSH_OS_PATTERNS = [
    (r"Ubuntu", "Ubuntu Linux"),
    (r"Debian", "Debian Linux"),
    (r"FreeBSD", "FreeBSD"),
    (r"OpenBSD", "OpenBSD"),
    (r"CentOS", "CentOS Linux"),
    (r"Red Hat", "Red Hat Linux"),
    (r"Fedora", "Fedora Linux"),
    (r"SUSE", "SUSE Linux"),
    (r"Arch", "Arch Linux"),
    (r"Raspbian", "Raspbian (Raspberry Pi)"),
    (r"OpenSSH_(\d+\.\d+)p1 Ubuntu", "Ubuntu Linux (OpenSSH {})"),
    (r"OpenSSH_for_Windows", "Windows (OpenSSH)"),
    (r"dropbear", "Embedded Linux (Dropbear SSH)"),
    (r"libssh", "Embedded/IoT device"),
    (r"Cisco", "Cisco IOS"),
    (r"OpenSSH_(\d+\.\d+)", "Unix/Linux (OpenSSH {})"),
]

# HTTP Server header → OS mapping
HTTP_OS_PATTERNS = [
    (r"Microsoft-IIS/(\d+\.\d+)", "Windows Server (IIS {})"),
    (r"Microsoft-HTTPAPI", "Windows"),
    (r"Apache.*Ubuntu", "Ubuntu Linux"),
    (r"Apache.*Debian", "Debian Linux"),
    (r"Apache.*CentOS", "CentOS Linux"),
    (r"Apache.*Red Hat", "Red Hat Linux"),
    (r"Apache.*Fedora", "Fedora Linux"),
    (r"Apache.*Win32", "Windows (Apache)"),
    (r"Apache.*Win64", "Windows x64 (Apache)"),
    (r"nginx", "Linux (likely)"),
    (r"lighttpd", "Linux (likely)"),
    (r"openresty", "Linux (OpenResty/nginx)"),
    (r"Apache/(\d+\.\d+)", "Linux (Apache {})"),
    (r"cloudflare", "Cloudflare CDN (OS hidden)"),
]

# SMB/NetBIOS → Windows version mapping
SMB_OS_STRINGS = {
    "Windows 10.0": "Windows 10/11 or Server 2016+",
    "Windows 6.3": "Windows 8.1 or Server 2012 R2",
    "Windows 6.2": "Windows 8 or Server 2012",
    "Windows 6.1": "Windows 7 or Server 2008 R2",
    "Windows 6.0": "Windows Vista or Server 2008",
    "Windows 5.1": "Windows XP",
    "Windows 5.0": "Windows 2000",
}


def tcp_fingerprint(target, port=80, timeout=3):
    """
    Active TCP fingerprinting — send a SYN and analyze the SYN-ACK.

    Different OSes set different values in their SYN-ACK:
    - TTL (time to live)
    - Window size
    - TCP options and their order
    - Don't Fragment bit
    - IP ID behavior
    """
    results = {
        "ttl": None,
        "window": None,
        "df": None,
        "tcp_options": [],
        "ip_id": None,
        "os_guess_ttl": "Unknown",
        "os_guess_window": "Unknown",
    }

    # Send SYN with specific options to elicit a detailed response
    syn = IP(dst=target) / TCP(
        dport=port,
        flags="S",
        options=[
            ("MSS", 1460),
            ("SAckOK", b""),
            ("Timestamp", (12345, 0)),
            ("NOP", None),
            ("WScale", 7),
        ],
    )

    response = sr1(syn, timeout=timeout)
    if response is None:
        return results

    if response.haslayer(TCP):
        tcp = response[TCP]
        ip = response[IP]

        results["ttl"] = ip.ttl
        results["window"] = tcp.window
        results["df"] = bool(ip.flags.DF)
        results["ip_id"] = ip.id

        # Parse TCP options
        if tcp.options:
            results["tcp_options"] = [
                (opt[0] if isinstance(opt, tuple) else opt)
                for opt in tcp.options
            ]

        # TTL-based OS guess
        for (low, high), os_name in TTL_SIGNATURES.items():
            if low <= ip.ttl <= high:
                results["os_guess_ttl"] = os_name
                break

        # Window-based OS guess
        if tcp.window in WINDOW_SIGNATURES:
            results["os_guess_window"] = WINDOW_SIGNATURES[tcp.window]
        else:
            # Find closest match
            closest = min(WINDOW_SIGNATURES.keys(),
                          key=lambda w: abs(w - tcp.window))
            if abs(closest - tcp.window) < 1000:
                results["os_guess_window"] = f"{WINDOW_SIGNATURES[closest]} (approx)"

        # Send RST to clean up the half-open connection
        rst = IP(dst=target) / TCP(
            dport=port, sport=tcp.dport,
            flags="R", seq=tcp.ack,
        )
        sr1(rst, timeout=1)

    return results


def icmp_fingerprint(target, timeout=3):
    """
    ICMP fingerprinting — analyze ping response behavior.

    Different OSes respond to ICMP differently:
    - TTL in response
    - Whether they respond to timestamp/address mask requests
    - ICMP error message quoting behavior
    """
    results = {
        "responds_to_ping": False,
        "ping_ttl": None,
        "responds_to_timestamp": False,
    }

    # Standard ping
    ping = IP(dst=target) / ICMP(type=8, code=0) / Raw(load=b"A" * 32)
    reply = sr1(ping, timeout=timeout)

    if reply and reply.haslayer(ICMP):
        results["responds_to_ping"] = True
        results["ping_ttl"] = reply[IP].ttl

    # ICMP timestamp request (type 13)
    # Windows responds, many Linux configs don't
    ts_req = IP(dst=target) / ICMP(type=13, code=0)
    ts_reply = sr1(ts_req, timeout=timeout)

    if ts_reply and ts_reply.haslayer(ICMP):
        if ts_reply[ICMP].type == 14:  # Timestamp reply
            results["responds_to_timestamp"] = True

    return results


def banner_fingerprint(target, timeout=3):
    """
    Service banner fingerprinting — grab banners and extract OS info.

    This is "passive" fingerprinting from the application layer.
    Many services advertise the OS in their banners.
    """
    results = {
        "ssh": None,
        "http": None,
        "smb": None,
        "ftp": None,
        "smtp": None,
        "os_from_ssh": None,
        "os_from_http": None,
    }

    # SSH banner (port 22)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 22))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        results["ssh"] = banner

        for pattern, os_name in SSH_OS_PATTERNS:
            match = re.search(pattern, banner)
            if match:
                if "{}" in os_name:
                    results["os_from_ssh"] = os_name.format(match.group(1))
                else:
                    results["os_from_ssh"] = os_name
                break

    except Exception:
        pass

    # HTTP Server header (port 80 and 443)
    for port in [80, 443, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((target, port))

            proto = "https" if port == 443 else "http"
            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
            s.send(request.encode())
            response = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()

            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    results["http"] = server

                    for pattern, os_name in HTTP_OS_PATTERNS:
                        match = re.search(pattern, server, re.IGNORECASE)
                        if match:
                            if "{}" in os_name:
                                results["os_from_http"] = os_name.format(match.group(1))
                            else:
                                results["os_from_http"] = os_name
                            break
                    break

            if results["http"]:
                break

        except Exception:
            continue

    # FTP banner (port 21)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 21))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        results["ftp"] = banner
    except Exception:
        pass

    # SMTP banner (port 25)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, 25))
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        s.close()
        results["smtp"] = banner
    except Exception:
        pass

    return results


def scan_behavior(target, timeout=3):
    """
    Probe closed/filtered ports to see how the OS responds.

    - Linux sends RST to closed ports, nothing to filtered
    - Windows sends RST with non-zero window to closed ports
    - Some OSes respond to NULL/FIN/XMAS scans, others don't
    """
    results = {
        "closed_port_rst": False,
        "closed_port_rst_window": None,
        "responds_to_fin": False,
        "responds_to_null": False,
        "responds_to_xmas": False,
    }

    # Find a closed port (try high ephemeral ports)
    closed_port = 44444

    # RST behavior on closed port
    syn = IP(dst=target) / TCP(dport=closed_port, flags="S")
    reply = sr1(syn, timeout=timeout)
    if reply and reply.haslayer(TCP):
        if reply[TCP].flags & 0x04:  # RST flag
            results["closed_port_rst"] = True
            results["closed_port_rst_window"] = reply[TCP].window

    # FIN scan (should get no response from open port on Linux, RST from Windows)
    fin = IP(dst=target) / TCP(dport=closed_port, flags="F")
    reply = sr1(fin, timeout=timeout)
    if reply:
        results["responds_to_fin"] = True

    # NULL scan (no flags set)
    null = IP(dst=target) / TCP(dport=closed_port, flags="")
    reply = sr1(null, timeout=timeout)
    if reply:
        results["responds_to_null"] = True

    # XMAS scan (FIN + PSH + URG)
    xmas = IP(dst=target) / TCP(dport=closed_port, flags="FPU")
    reply = sr1(xmas, timeout=timeout)
    if reply:
        results["responds_to_xmas"] = True

    return results


def determine_os(tcp_results, icmp_results, banner_results, behavior_results):
    """
    Combine all fingerprinting results into a final OS determination.

    Weight different signals:
    1. Banner info is most reliable (application layer tells us directly)
    2. TCP stack behavior is very reliable
    3. ICMP adds supporting evidence
    4. Scan behavior helps differentiate
    """
    candidates = {}

    def add_vote(os_name, confidence, source):
        if os_name and os_name != "Unknown":
            candidates.setdefault(os_name, []).append({
                "confidence": confidence,
                "source": source,
            })

    # Banner votes (highest confidence)
    if banner_results.get("os_from_ssh"):
        add_vote(banner_results["os_from_ssh"], 90, "SSH banner")
    if banner_results.get("os_from_http"):
        add_vote(banner_results["os_from_http"], 80, "HTTP Server header")

    # TCP fingerprint votes
    if tcp_results.get("os_guess_ttl"):
        add_vote(tcp_results["os_guess_ttl"], 60, f"TTL={tcp_results['ttl']}")
    if tcp_results.get("os_guess_window"):
        add_vote(tcp_results["os_guess_window"], 70,
                 f"Window={tcp_results['window']}")

    # ICMP votes
    if icmp_results.get("responds_to_timestamp"):
        add_vote("Windows", 40, "Responds to ICMP timestamp")

    # Behavior votes
    if behavior_results.get("closed_port_rst_window") == 0:
        add_vote("Linux/Unix", 50, "RST window=0 on closed port")
    elif behavior_results.get("closed_port_rst_window") and \
         behavior_results["closed_port_rst_window"] > 0:
        add_vote("Windows", 50, f"RST window={behavior_results['closed_port_rst_window']}")

    # Score and rank
    scored = {}
    for os_name, votes in candidates.items():
        total = sum(v["confidence"] for v in votes)
        sources = [v["source"] for v in votes]
        scored[os_name] = {"score": total, "sources": sources}

    return dict(sorted(scored.items(), key=lambda x: -x[1]["score"]))


def fingerprint(target, detailed=False, passive_only=False, timeout=3):
    """Run full OS fingerprinting against a target."""
    start_time = datetime.now()

    print(f"\n[*] OS Fingerprinting: {target}")
    print(f"[*] Mode: {'Passive (banners only)' if passive_only else 'Active + Passive'}")
    print(f"[*] Started: {start_time.strftime('%H:%M:%S')}\n")

    # Always do banner grabbing
    print("[*] Banner grabbing...")
    banner_results = banner_fingerprint(target, timeout)

    tcp_results = {}
    icmp_results = {}
    behavior_results = {}

    if not passive_only:
        # TCP fingerprinting (needs root)
        print("[*] TCP stack fingerprinting...")
        # Try common open ports
        for port in [80, 443, 22, 8080, 21, 25, 3389]:
            tcp_results = tcp_fingerprint(target, port, timeout)
            if tcp_results.get("ttl"):
                break

        # ICMP fingerprinting
        print("[*] ICMP fingerprinting...")
        icmp_results = icmp_fingerprint(target, timeout)

        # Behavior analysis
        if detailed:
            print("[*] Scan behavior analysis...")
            behavior_results = scan_behavior(target, timeout)

    # Determine OS
    os_candidates = determine_os(
        tcp_results, icmp_results, banner_results, behavior_results
    )

    duration = (datetime.now() - start_time).total_seconds()

    # Display results
    print(f"\n{'='*60}")
    print(f"OS Fingerprint Report: {target}")
    print(f"{'='*60}")

    if os_candidates:
        print(f"\nOS Detection Results:")
        for os_name, info in os_candidates.items():
            bar = "█" * (info["score"] // 10)
            print(f"  {info['score']:>3}%  {bar:<10}  {os_name}")
            for source in info["sources"]:
                print(f"          └─ {source}")
        print()

        best = list(os_candidates.keys())[0]
        best_score = os_candidates[best]["score"]
        print(f"Best guess: {best} (confidence: {best_score}%)")
    else:
        print("\nCould not determine OS. Target may be firewalled.")

    # Raw data
    if detailed or True:
        print(f"\nRaw Fingerprint Data:")

        if tcp_results.get("ttl"):
            print(f"  TTL:          {tcp_results['ttl']}")
            print(f"  TCP Window:   {tcp_results['window']}")
            print(f"  DF bit:       {'Set' if tcp_results.get('df') else 'Not set'}")
            print(f"  IP ID:        {tcp_results.get('ip_id')}")
            print(f"  TCP Options:  {tcp_results.get('tcp_options', [])}")

        if icmp_results.get("responds_to_ping") is not None:
            print(f"  ICMP Ping:    {'Responds' if icmp_results.get('responds_to_ping') else 'No response'}")
            if icmp_results.get("ping_ttl"):
                print(f"  Ping TTL:     {icmp_results['ping_ttl']}")
            print(f"  ICMP TS:      {'Responds' if icmp_results.get('responds_to_timestamp') else 'No response'}")

        if banner_results.get("ssh"):
            print(f"  SSH Banner:   {banner_results['ssh']}")
        if banner_results.get("http"):
            print(f"  HTTP Server:  {banner_results['http']}")
        if banner_results.get("ftp"):
            print(f"  FTP Banner:   {banner_results['ftp']}")
        if banner_results.get("smtp"):
            print(f"  SMTP Banner:  {banner_results['smtp']}")

    print(f"\nDuration: {duration:.1f}s")
    return os_candidates


def main():
    parser = argparse.ArgumentParser(description="OS Fingerprinting")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("--detailed", action="store_true",
                        help="Include scan behavior analysis (slower)")
    parser.add_argument("--passive", action="store_true",
                        help="Passive mode — banner grabbing only (no root)")
    parser.add_argument("--timeout", type=float, default=3)

    args = parser.parse_args()
    fingerprint(args.target, detailed=args.detailed,
                passive_only=args.passive, timeout=args.timeout)


if __name__ == "__main__":
    main()
