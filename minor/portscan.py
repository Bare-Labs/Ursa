#!/usr/bin/env python3
"""
Port Scanner
============
WHAT THIS DOES:
    Checks which ports are open on a target device. An open port means
    a service is running and listening — a potential entry point.

WHY IT MATTERS:
    Every service on a port is an "attack surface." A web server on port 80,
    SSH on port 22, a database on port 3306 — each one could have
    vulnerabilities. Operators map out every open port before looking
    for exploits.

HOW IT WORKS:
    TCP Connect Scan (what we're doing):
        - Try to complete a TCP handshake (SYN → SYN-ACK → ACK)
        - If it completes → port is open
        - If refused → port is closed
        - If no response → port is filtered (firewall)

    SYN Scan (what pros use, aka "stealth scan"):
        - Send SYN, if you get SYN-ACK, send RST instead of ACK
        - Never completes the connection → harder to detect in logs
        - We build this too (requires root)

USAGE:
    python3 portscan.py 192.168.1.1                    # scan common ports
    python3 portscan.py 192.168.1.1 -p 1-1024          # scan range
    python3 portscan.py 192.168.1.1 -p 22,80,443       # scan specific ports
    sudo python3 portscan.py 192.168.1.1 --syn          # stealth SYN scan
    python3 portscan.py 192.168.1.1 --all               # scan all 65535 ports
"""

import sys
import socket
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from scapy.all import IP, TCP, sr1, conf

conf.verb = 0

# Well-known ports and what runs on them
# Knowing these is fundamental — you should memorize the common ones
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9090: "Web-Mgmt",
    27017: "MongoDB",
}

# Top 100 most commonly open ports (based on nmap's frequency data)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389,
    5432, 5900, 5901, 6379, 8080, 8443, 8888, 9090, 27017,
    49152, 49153, 49154, 49155, 49156, 49157,
    # Additional common ports
    25565, 6667, 6697, 1080, 1194, 1883, 2049, 2082, 2083,
    2086, 2087, 2096, 2222, 3000, 3128, 4443, 4444, 5000,
    5001, 5060, 5222, 5269, 5500, 5601, 5984, 6000, 6443,
    7000, 7001, 7070, 7443, 8000, 8008, 8081, 8082, 8083,
    8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8181,
    8222, 8333, 8444, 8880, 8983, 9000, 9001, 9042, 9043,
    9080, 9091, 9200, 9300, 9418, 9999, 10000, 10443, 11211,
]


def grab_banner(ip, port, timeout=2):
    """
    Try to grab the service banner from an open port.

    Many services announce themselves when you connect.
    This is "service enumeration" — figuring out WHAT is running
    and often WHAT VERSION. Version info is gold for finding exploits.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        # Some services send a banner immediately
        # Others need us to send something first
        try:
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            # Try sending a basic HTTP request for web servers
            if port in (80, 8080, 8000, 8888, 443, 8443):
                s.send(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                # Just grab the server header
                for line in banner.split("\r\n"):
                    if line.lower().startswith("server:"):
                        banner = line
                        break
            else:
                banner = ""

        s.close()
        return banner[:100] if banner else ""
    except Exception:
        return ""


def tcp_connect_scan(ip, port, timeout=1):
    """
    TCP Connect Scan — the basic approach.

    Tries to complete a full TCP handshake. If the connection succeeds,
    the port is open. Simple but "loud" — the target's logs will show
    the connection.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0  # 0 means connection succeeded
    except Exception:
        return False


def syn_scan(ip, port, timeout=2):
    """
    SYN Scan (Half-Open / Stealth Scan) — the professional approach.

    Instead of completing the TCP handshake:
    1. Send SYN (I want to connect)
    2. If we get SYN-ACK → port is OPEN (service wants to talk)
    3. If we get RST → port is CLOSED
    4. If nothing → port is FILTERED (firewall dropping packets)

    We never send the final ACK, so the connection is never "established"
    in the target's logs. This is why it's called "stealth."

    Requires root because we're crafting raw packets.
    """
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    response = sr1(pkt, timeout=timeout)

    if response is None:
        return "filtered"
    elif response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK
            return "open"
        elif response[TCP].flags == 0x14:  # RST-ACK
            return "closed"
    return "filtered"


def parse_ports(port_str):
    """Parse port specification string into a list of ports."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def scan_target(ip, ports, scan_type="connect", threads=100, timeout=1):
    """Scan all specified ports on target using thread pool."""
    open_ports = []
    total = len(ports)
    scanned = 0

    print(f"\n[*] Scanning {ip} — {total} ports — {scan_type} scan")
    print(f"[*] Started at {datetime.now().strftime('%H:%M:%S')}\n")

    def check_port(port):
        if scan_type == "syn":
            result = syn_scan(ip, port, timeout)
            return (port, result)
        else:
            is_open = tcp_connect_scan(ip, port, timeout)
            return (port, "open" if is_open else "closed")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_port, port): port for port in ports}

        for future in as_completed(futures):
            scanned += 1
            port, status = future.result()

            if status == "open":
                service = COMMON_PORTS.get(port, "unknown")
                banner = grab_banner(ip, port)
                open_ports.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "status": status,
                })
                print(f"  [+] {port:<6} OPEN    {service:<15} {banner}")
            elif status == "filtered" and scan_type == "syn":
                # Only show filtered in SYN scan mode (it's meaningful there)
                pass

            # Progress indicator every 10%
            if total > 100 and scanned % (total // 10) == 0:
                pct = (scanned / total) * 100
                sys.stdout.write(f"\r  [{pct:.0f}% complete — {scanned}/{total} ports]")
                sys.stdout.flush()

    if total > 100:
        print()  # newline after progress

    return open_ports


def display_results(ip, open_ports, scan_type, duration):
    """Display final scan results."""
    print(f"\n{'='*60}")
    print(f"Scan Report for {ip}")
    print(f"{'='*60}")
    print(f"Scan type: {scan_type}")
    print(f"Duration:  {duration:.1f}s")
    print()

    if not open_ports:
        print("No open ports found.")
        print("This could mean:")
        print("  - All ports are closed or filtered")
        print("  - Host is down")
        print("  - Firewall is blocking our probes")
        return

    open_ports.sort(key=lambda x: x["port"])

    print(f"{'Port':<8} {'State':<10} {'Service':<15} {'Banner'}")
    print("-" * 60)
    for p in open_ports:
        print(f"{p['port']:<8} {p['status']:<10} {p['service']:<15} {p['banner']}")

    print(f"\n{len(open_ports)} open ports found")


def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner — discover open services on a target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 portscan.py 192.168.1.1              Scan top ports
  python3 portscan.py 192.168.1.1 -p 1-1024    Scan port range
  python3 portscan.py 192.168.1.1 -p 22,80     Scan specific ports
  sudo python3 portscan.py 192.168.1.1 --syn    Stealth SYN scan
        """
    )

    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--ports", help="Port specification (e.g., 22,80,443 or 1-1024)")
    parser.add_argument("--all", action="store_true", help="Scan all 65535 ports")
    parser.add_argument("--syn", action="store_true", help="SYN scan (requires root)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Thread count (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout per port in seconds")

    args = parser.parse_args()

    # Determine which ports to scan
    if args.ports:
        ports = parse_ports(args.ports)
    elif args.all:
        ports = list(range(1, 65536))
    else:
        ports = TOP_PORTS

    # Check for root if SYN scan
    scan_type = "connect"
    if args.syn:
        if os.geteuid() != 0:
            print("[!] SYN scan requires root. Run with sudo.")
            sys.exit(1)
        scan_type = "syn"

    # Verify target is reachable
    print(f"[*] Target: {args.target}")

    start = datetime.now()
    open_ports = scan_target(
        args.target,
        ports,
        scan_type=scan_type,
        threads=args.threads,
        timeout=args.timeout,
    )
    duration = (datetime.now() - start).total_seconds()

    display_results(args.target, open_ports, scan_type, duration)


if __name__ == "__main__":
    main()
