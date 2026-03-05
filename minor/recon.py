#!/usr/bin/env python3
"""
Recon — Full Network Reconnaissance Tool
==========================================
Ties everything together: discover hosts, scan their ports, identify services.

This is what a real engagement looks like:
    1. Discover all hosts on the network (ARP scan)
    2. Port scan each discovered host
    3. Banner grab open services
    4. Generate a report

USAGE:
    sudo python3 recon.py                     # full recon of local network
    sudo python3 recon.py 192.168.1.0/24      # recon specific network
    sudo python3 recon.py --quick             # fast scan (top 30 ports only)
"""

import sys
import argparse
from datetime import datetime

from discover import arp_scan, get_local_ip, get_netmask, calculate_cidr
from portscan import scan_target, TOP_PORTS


QUICK_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
               443, 445, 993, 995, 3306, 3389, 5432, 5900,
               6379, 8080, 8443, 8888, 9090, 27017, 5000,
               8000, 3000, 4443, 9200, 10000]


def run_recon(target_range, quick=False, threads=50):
    """Run full network reconnaissance."""
    start_time = datetime.now()

    print(f"""
╔══════════════════════════════════════════════╗
║         NETWORK RECONNAISSANCE               ║
╚══════════════════════════════════════════════╝
    """)

    local_ip = get_local_ip()
    print(f"[*] Your IP:  {local_ip}")
    print(f"[*] Target:   {target_range}")
    print(f"[*] Mode:     {'Quick' if quick else 'Standard'}")
    print(f"[*] Started:  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")

    # Phase 1: Host Discovery
    print(f"\n{'='*50}")
    print(f"PHASE 1: HOST DISCOVERY (ARP Scan)")
    print(f"{'='*50}")

    devices = arp_scan(target_range)

    if not devices:
        print("[!] No hosts discovered. Exiting.")
        return

    print(f"\n[+] Found {len(devices)} live hosts:\n")
    for d in sorted(devices, key=lambda x: [int(p) for p in x["ip"].split(".")]):
        label = ""
        if d["ip"] == local_ip:
            label = " (you)"
        elif d["ip"].endswith(".1"):
            label = " (gateway)"
        print(f"  {d['ip']:<18} {d['mac']:<20} {d['vendor']}{label}")

    # Phase 2: Port Scanning
    print(f"\n{'='*50}")
    print(f"PHASE 2: SERVICE DISCOVERY (Port Scan)")
    print(f"{'='*50}")

    ports = QUICK_PORTS if quick else TOP_PORTS
    all_results = {}

    for device in devices:
        ip = device["ip"]
        if ip == local_ip:
            continue  # Skip scanning ourselves

        open_ports = scan_target(ip, ports, scan_type="connect", threads=threads)
        all_results[ip] = {
            "mac": device["mac"],
            "vendor": device["vendor"],
            "open_ports": open_ports,
        }

    # Phase 3: Report
    duration = (datetime.now() - start_time).total_seconds()

    print(f"\n{'='*60}")
    print(f"RECONNAISSANCE REPORT")
    print(f"{'='*60}")
    print(f"Target:   {target_range}")
    print(f"Duration: {duration:.1f}s")
    print(f"Hosts:    {len(devices)} discovered")
    print()

    total_open = 0
    for ip, data in sorted(all_results.items()):
        open_ports = data["open_ports"]
        if not open_ports:
            continue

        total_open += len(open_ports)
        print(f"┌─ {ip} ({data['vendor']}) [{data['mac']}]")
        for p in sorted(open_ports, key=lambda x: x["port"]):
            banner_info = f" — {p['banner']}" if p.get("banner") else ""
            print(f"│  {p['port']:<6} {p['service']:<15}{banner_info}")
        print(f"└─ {len(open_ports)} open ports")
        print()

    print(f"Total: {len(devices)} hosts, {total_open} open ports")
    print(f"Completed in {duration:.1f}s")


def main():
    parser = argparse.ArgumentParser(description="Full network reconnaissance")
    parser.add_argument("target", nargs="?", help="Target network (CIDR notation)")
    parser.add_argument("--quick", action="store_true", help="Quick scan (top 30 ports)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Threads per host")

    args = parser.parse_args()

    if args.target:
        target = args.target
    else:
        local_ip = get_local_ip()
        netmask = get_netmask()
        target = calculate_cidr(local_ip, netmask)

    run_recon(target, quick=args.quick, threads=args.threads)


if __name__ == "__main__":
    main()
