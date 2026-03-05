#!/usr/bin/env python3
"""
Packet Sniffer
==============
WHAT THIS DOES:
    Captures and displays network packets flowing through your network
    interface in real-time. You can see what protocols are being used,
    who's talking to whom, and (for unencrypted traffic) what data is
    being sent.

WHY IT MATTERS:
    Packet analysis is how you understand what's really happening on a
    network. Operators use this to:
    - Map network communications ("who talks to whom")
    - Find unencrypted credentials (HTTP basic auth, FTP, telnet)
    - Detect suspicious traffic patterns
    - Understand protocols at a deep level

    Tools like Wireshark do this with a GUI. We're building the
    command-line version so you understand what's happening under the hood.

HOW IT WORKS:
    Your network card (NIC) normally only processes packets addressed to
    it. We put it in "promiscuous mode" — it captures ALL packets on the
    wire/wifi, even ones not meant for us. On a switched network you'll
    mainly see your own traffic + broadcasts, but on WiFi you can see
    more.

USAGE:
    sudo python3 sniff.py                       # sniff all traffic
    sudo python3 sniff.py -f "tcp port 80"      # only HTTP
    sudo python3 sniff.py -f "host 192.168.1.1" # traffic to/from host
    sudo python3 sniff.py -c 100                # capture 100 packets
    sudo python3 sniff.py --dns                 # show DNS queries only
    sudo python3 sniff.py --creds               # look for credentials
"""

import sys
import argparse
import re
from datetime import datetime

from scapy.all import (
    sniff as scapy_sniff,
    IP, TCP, UDP, DNS, DNSQR, DNSRR,
    ARP, ICMP, Raw,
    conf,
)

conf.verb = 0

# ANSI colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
GRAY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"


class PacketSniffer:
    """Network packet sniffer with protocol-aware display."""

    def __init__(self, dns_only=False, cred_mode=False, verbose=False):
        self.packet_count = 0
        self.dns_only = dns_only
        self.cred_mode = cred_mode
        self.verbose = verbose

        # Stats tracking
        self.stats = {
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "arp": 0,
            "dns": 0,
            "http": 0,
            "other": 0,
        }
        self.connections = set()
        self.dns_queries = []
        self.credentials_found = []

    def process_packet(self, packet):
        """Process each captured packet — this is the callback for scapy's sniff."""
        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # DNS packets
        if packet.haslayer(DNS):
            self.stats["dns"] += 1
            self.handle_dns(packet, timestamp)
            if self.dns_only:
                return

        # Skip non-IP/ARP if in DNS-only mode
        if self.dns_only:
            return

        # ARP packets
        if packet.haslayer(ARP):
            self.stats["arp"] += 1
            self.handle_arp(packet, timestamp)
            return

        if not packet.haslayer(IP):
            self.stats["other"] += 1
            return

        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        # TCP
        if packet.haslayer(TCP):
            self.stats["tcp"] += 1
            tcp = packet[TCP]
            sport = tcp.sport
            dport = tcp.dport

            self.connections.add((src, sport, dst, dport))

            # Check for HTTP traffic (potential credentials)
            if self.cred_mode and packet.haslayer(Raw):
                self.check_credentials(packet, src, dst, sport, dport, timestamp)
                return

            # Identify the service
            service = self.identify_service(sport, dport)
            flags = self.tcp_flags(tcp.flags)

            if not self.cred_mode:
                size = len(packet)
                print(
                    f"{GRAY}{timestamp}{RESET} "
                    f"{GREEN}TCP{RESET} "
                    f"{src}:{sport} → {dst}:{dport} "
                    f"[{CYAN}{flags}{RESET}] "
                    f"{YELLOW}{service}{RESET} "
                    f"{GRAY}{size}B{RESET}"
                )

                # Show HTTP requests/responses
                if packet.haslayer(Raw) and dport in (80, 8080, 8000):
                    payload = packet[Raw].load.decode("utf-8", errors="ignore")
                    if payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                        method_line = payload.split("\r\n")[0]
                        print(f"  {BLUE}→ {method_line}{RESET}")

        # UDP
        elif packet.haslayer(UDP):
            self.stats["udp"] += 1
            udp = packet[UDP]
            sport = udp.sport
            dport = udp.dport
            service = self.identify_service(sport, dport)

            if not self.cred_mode:
                print(
                    f"{GRAY}{timestamp}{RESET} "
                    f"{BLUE}UDP{RESET} "
                    f"{src}:{sport} → {dst}:{dport} "
                    f"{YELLOW}{service}{RESET}"
                )

        # ICMP (ping, traceroute, etc.)
        elif packet.haslayer(ICMP):
            self.stats["icmp"] += 1
            icmp = packet[ICMP]
            icmp_type = {0: "Echo Reply", 3: "Unreachable", 8: "Echo Request",
                         11: "TTL Exceeded"}.get(icmp.type, f"Type {icmp.type}")

            if not self.cred_mode:
                print(
                    f"{GRAY}{timestamp}{RESET} "
                    f"{RED}ICMP{RESET} "
                    f"{src} → {dst} "
                    f"{YELLOW}{icmp_type}{RESET}"
                )

    def handle_dns(self, packet, timestamp):
        """Parse and display DNS queries and responses."""
        dns = packet[DNS]

        if dns.qr == 0 and packet.haslayer(DNSQR):  # Query
            query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            qtype = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS",
                     12: "PTR", 6: "SOA", 16: "TXT", 33: "SRV"}.get(
                         packet[DNSQR].qtype, str(packet[DNSQR].qtype))

            self.dns_queries.append(query)
            print(
                f"{GRAY}{timestamp}{RESET} "
                f"{CYAN}DNS{RESET} "
                f"Query: {BOLD}{query}{RESET} "
                f"[{qtype}]"
            )

        elif dns.qr == 1 and packet.haslayer(DNSRR):  # Response
            query = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            answers = []
            for i in range(dns.ancount):
                try:
                    rr = dns.an[i]
                    if hasattr(rr, "rdata"):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="ignore")
                        answers.append(str(rdata))
                except Exception:
                    pass

            if answers:
                print(
                    f"{GRAY}{timestamp}{RESET} "
                    f"{CYAN}DNS{RESET} "
                    f"Response: {query} → {', '.join(answers)}"
                )

    def handle_arp(self, packet, timestamp):
        """Display ARP requests and replies."""
        arp = packet[ARP]
        if arp.op == 1:  # ARP request
            print(
                f"{GRAY}{timestamp}{RESET} "
                f"{YELLOW}ARP{RESET} "
                f"Who has {arp.pdst}? Tell {arp.psrc}"
            )
        elif arp.op == 2:  # ARP reply
            print(
                f"{GRAY}{timestamp}{RESET} "
                f"{YELLOW}ARP{RESET} "
                f"{arp.psrc} is at {arp.hwsrc}"
            )

    def check_credentials(self, packet, src, dst, sport, dport, timestamp):
        """
        Look for potential credentials in unencrypted traffic.

        This only catches plaintext credentials (HTTP basic auth, FTP, etc.)
        HTTPS traffic is encrypted and safe from this kind of sniffing.
        This is why HTTPS everywhere matters.
        """
        if not packet.haslayer(Raw):
            return

        payload = packet[Raw].load.decode("utf-8", errors="ignore")

        # HTTP Basic Auth (Base64 encoded but NOT encrypted)
        if "Authorization: Basic" in payload:
            match = re.search(r"Authorization: Basic (.+)", payload)
            if match:
                import base64
                try:
                    decoded = base64.b64decode(match.group(1).strip()).decode()
                    finding = f"HTTP Basic Auth: {decoded}"
                    self.credentials_found.append(finding)
                    print(f"{RED}{BOLD}[CREDENTIAL]{RESET} {timestamp} {src}→{dst}:{dport} {finding}")
                except Exception:
                    pass

        # FTP credentials (sent in plaintext!)
        if dport == 21 or sport == 21:
            if payload.startswith("USER ") or payload.startswith("PASS "):
                finding = f"FTP: {payload.strip()}"
                self.credentials_found.append(finding)
                print(f"{RED}{BOLD}[CREDENTIAL]{RESET} {timestamp} {src}→{dst} {finding}")

        # HTTP form data with common credential field names
        credential_patterns = [
            r"(?:user(?:name)?|login|email)=([^&\s]+)",
            r"(?:pass(?:word)?|pwd|secret)=([^&\s]+)",
        ]
        for pattern in credential_patterns:
            matches = re.findall(pattern, payload, re.IGNORECASE)
            if matches:
                finding = f"HTTP Form: {payload[:200]}"
                self.credentials_found.append(finding)
                print(f"{RED}{BOLD}[CREDENTIAL]{RESET} {timestamp} {src}→{dst}:{dport}")
                print(f"  {payload[:200]}")
                break

    def identify_service(self, sport, dport):
        """Identify the service based on port number."""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        return services.get(dport, services.get(sport, ""))

    def tcp_flags(self, flags):
        """Convert TCP flags integer to human-readable string."""
        flag_names = []
        flag_map = [
            (0x02, "SYN"),
            (0x10, "ACK"),
            (0x01, "FIN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x20, "URG"),
        ]
        for bit, name in flag_map:
            if flags & bit:
                flag_names.append(name)
        return ",".join(flag_names) if flag_names else str(flags)

    def print_stats(self):
        """Print capture statistics."""
        print(f"\n{'='*50}")
        print(f"Capture Statistics")
        print(f"{'='*50}")
        print(f"Total packets: {self.packet_count}")
        for proto, count in sorted(self.stats.items(), key=lambda x: -x[1]):
            if count > 0:
                bar = "█" * min(count, 40)
                print(f"  {proto:<8} {count:>6}  {bar}")

        if self.dns_queries:
            print(f"\nTop DNS Queries:")
            from collections import Counter
            for domain, count in Counter(self.dns_queries).most_common(10):
                print(f"  {count:>4}x  {domain}")

        unique_connections = len(self.connections)
        print(f"\nUnique connections: {unique_connections}")

        if self.credentials_found:
            print(f"\n{RED}Credentials Found: {len(self.credentials_found)}{RESET}")
            for cred in self.credentials_found:
                print(f"  {RED}• {cred}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="Packet Sniffer — watch network traffic in real-time",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 sniff.py                       Sniff all traffic
  sudo python3 sniff.py -f "tcp port 80"      Only HTTP traffic
  sudo python3 sniff.py --dns                  DNS queries only
  sudo python3 sniff.py --creds               Hunt for credentials
  sudo python3 sniff.py -c 50                 Capture 50 packets

BPF Filter Examples:
  "tcp port 80"          - HTTP traffic
  "host 192.168.1.1"     - Traffic to/from specific host
  "tcp port 443"         - HTTPS traffic
  "udp port 53"          - DNS traffic
  "not port 22"          - Exclude SSH
  "src 192.168.1.5"      - From specific source
        """
    )

    parser.add_argument("-f", "--filter", default=None, help="BPF filter expression")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0=infinite)")
    parser.add_argument("-i", "--interface", default=None, help="Network interface to sniff on")
    parser.add_argument("--dns", action="store_true", help="Show only DNS queries")
    parser.add_argument("--creds", action="store_true", help="Hunt for plaintext credentials")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.creds:
        print(f"{BOLD}[*] Credential sniffing mode{RESET}")
        print(f"[*] Looking for plaintext credentials in HTTP, FTP, Telnet...")
        print(f"[*] Note: HTTPS traffic is encrypted and won't show credentials")
        print(f"[*] This is why HTTPS everywhere is important!\n")

    sniffer = PacketSniffer(
        dns_only=args.dns,
        cred_mode=args.creds,
        verbose=args.verbose,
    )

    print(f"[*] Starting packet capture...")
    if args.filter:
        print(f"[*] Filter: {args.filter}")
    if args.count:
        print(f"[*] Capturing {args.count} packets")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        scapy_sniff(
            iface=args.interface,
            filter=args.filter,
            prn=sniffer.process_packet,
            count=args.count,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("[!] Permission denied. Run with sudo.")
        sys.exit(1)

    sniffer.print_stats()


if __name__ == "__main__":
    main()
