#!/usr/bin/env python3
"""
Network Discovery Tool — ARP Scanner
=====================================
WHAT THIS DOES:
    Sends ARP (Address Resolution Protocol) requests to every IP on your
    local network. Every device MUST respond to ARP — it's how networking
    works. This means you can find every device on your WiFi, even ones
    trying to hide.

WHY IT MATTERS:
    This is "reconnaissance" — the first phase of any penetration test.
    You can't attack what you can't see. Real operators spend most of
    their time on recon before ever touching an exploit.

HOW IT WORKS:
    1. Figures out your network range (e.g., 192.168.1.0/24)
    2. Sends an ARP "who has this IP?" to every address
    3. Listens for replies — each reply = a live device
    4. Looks up the MAC vendor to identify device types

USAGE:
    sudo python3 discover.py              # scan your local network
    sudo python3 discover.py 192.168.1.0/24   # scan a specific range

NOTE: Requires sudo because raw network access needs root privileges.
      This is normal for any network tool (nmap, wireshark, etc.)
"""

import sys
import socket
import struct
import fcntl

from scapy.all import ARP, Ether, srp, conf

# Suppress scapy's noisy output
conf.verb = 0


# Common MAC address prefixes → manufacturer
# Real tools use a full database, but this gives you the idea
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "aa:bb:cc": "Example",
    "00:1a:2b": "Apple",
    "3c:22:fb": "Apple",
    "a4:83:e7": "Apple",
    "f8:ff:c2": "Apple",
    "ac:de:48": "Apple",
    "14:7d:da": "Apple",
    "88:e9:fe": "Apple",
    "00:1e:c2": "Apple",
    "98:01:a7": "Apple",
    "7c:d1:c3": "Apple",
    "d0:03:4b": "Apple",
    "a8:88:08": "Apple",
    "50:ed:3c": "Apple",
    "48:d7:05": "Apple",
    "8c:85:90": "Apple",
    "00:25:00": "Apple",
    "d8:30:62": "Apple",
    "34:36:3b": "Apple",
    "b0:34:95": "Apple",
    "70:56:81": "Apple",
    "d4:61:9d": "Apple",
    "18:af:61": "Apple",
    "8c:fe:57": "Apple",
    "54:26:96": "Apple",
    "cc:08:8d": "Apple",
    "28:cf:da": "Apple",
    "00:17:f2": "Apple",
    "d8:bb:2c": "Apple",
    "ac:87:a3": "Apple",
    "f0:18:98": "Apple",
    "70:3e:ac": "Apple",
    "30:35:ad": "Apple",
    "c8:69:cd": "Apple",
    "24:a0:74": "Apple",
    "80:e6:50": "Apple",
    "00:23:12": "Apple",
    "00:26:bb": "Apple",
    "d0:4f:7e": "Apple",
    "60:f8:1d": "Apple",
    "54:ae:27": "Apple",
    "34:c0:59": "Apple",
    "10:dd:b1": "Apple",
    "c8:b5:b7": "Apple",
    "00:11:24": "Apple",
    "38:f9:d3": "Apple",
    "c0:b6:58": "Apple",
    "5c:f7:e6": "Apple",
    "f4:5c:89": "Apple",
    "5c:8d:4e": "Apple",
    "00:22:41": "Apple",
    "00:16:cb": "Apple",
    "00:1f:5b": "Apple",
    "00:1f:f3": "Apple",
    "e0:b9:ba": "Apple",
    "58:55:ca": "Apple",
    "98:fe:94": "Apple",
    "8c:29:37": "Apple",
    "44:d8:84": "Apple",
    "c4:2c:03": "Apple",
    "a0:99:9b": "Apple",
    "d8:96:95": "Apple",
    "78:67:d7": "Apple",
    "00:03:93": "Apple",
    "fc:fc:48": "Apple",
    "80:ed:2c": "Apple",
    "84:38:35": "Apple",
    "40:b3:95": "Apple",
    "84:fc:fe": "Apple",
    "e8:06:88": "Apple",
    "90:72:40": "Samsung",
    "00:1a:8a": "Samsung",
    "ec:1f:72": "Samsung",
    "10:2a:b3": "Samsung",
    "00:26:37": "Samsung",
    "c4:73:1e": "Samsung",
    "ac:36:13": "Samsung",
    "00:07:ab": "Samsung",
    "f0:72:8c": "Samsung",
    "34:14:5f": "Samsung",
    "00:e0:64": "Samsung",
    "44:4e:1a": "Samsung",
    "68:27:37": "Samsung",
    "88:32:9b": "Samsung",
    "10:1d:c0": "Samsung",
    "5c:49:7d": "Samsung",
    "94:63:d1": "Samsung",
    "00:21:19": "Samsung",
    "00:24:54": "Samsung",
    "20:64:32": "Samsung",
    "bc:44:86": "Samsung",
    "a8:f2:74": "Samsung",
    "78:47:1d": "Samsung",
    "1c:62:b8": "Samsung",
    "38:01:97": "Samsung",
    "78:ab:bb": "Samsung",
    "10:d5:42": "Samsung",
    "b4:3a:28": "Samsung",
    "d0:87:e2": "Samsung",
    "c0:bd:d1": "Samsung",
    "f8:d0:bd": "Samsung",
    "d0:59:e4": "Samsung",
    "b4:79:a7": "Google",
    "f4:f5:d8": "Google",
    "54:60:09": "Google",
    "a4:77:33": "Google",
    "30:fd:38": "Google",
    "94:eb:2c": "Google",
    "00:1a:11": "Google",
    "3c:5a:b4": "Google",
    "58:cb:52": "Google",
    "f8:0f:f9": "Google",
    "44:07:0b": "Google",
    "e4:f0:42": "Google",
    "48:d6:d5": "Google",
    "20:df:b9": "Google",
    "00:1a:6b": "Intel",
    "68:05:ca": "Intel",
    "3c:97:0e": "Intel",
    "a0:36:9f": "Intel",
    "00:1b:21": "Intel",
    "00:1e:67": "Intel",
    "00:1f:3b": "Intel",
    "00:22:fa": "Intel",
    "00:24:d7": "Intel",
    "00:27:10": "Intel",
    "58:94:6b": "Intel",
    "68:17:29": "Intel",
    "7c:5c:f8": "Intel",
    "80:86:f2": "Intel",
    "8c:ec:4b": "Intel",
    "34:13:e8": "Intel",
    "b4:d5:bd": "Intel",
    "f8:94:c2": "Intel",
    "b4:ae:2b": "Intel",
    "4c:34:88": "Intel",
    "a4:4c:c8": "Intel",
    "ac:fd:ce": "Intel",
    "b0:a4:60": "Intel",
    "b8:08:cf": "Intel",
    "c8:5b:76": "Intel",
    "dc:53:60": "Intel",
    "e8:b1:fc": "Intel",
    "f4:8c:50": "Intel",
    "00:e0:4c": "Realtek",
    "52:54:00": "QEMU/KVM",
    "00:15:5d": "Hyper-V",
    "00:1c:42": "Parallels",
    "b0:be:76": "TP-Link",
    "50:c7:bf": "TP-Link",
    "ec:08:6b": "TP-Link",
    "14:cc:20": "TP-Link",
    "30:b5:c2": "TP-Link",
    "60:32:b1": "TP-Link",
    "a4:2b:b0": "TP-Link",
    "18:d6:c7": "TP-Link",
    "c0:06:c3": "TP-Link",
    "f4:f2:6d": "TP-Link",
    "74:da:38": "Edimax",
    "00:1e:58": "D-Link",
    "1c:7e:e5": "D-Link",
    "28:10:7b": "D-Link",
    "34:08:04": "D-Link",
    "1c:af:f7": "D-Link",
    "00:26:5a": "D-Link",
    "00:05:5d": "D-Link",
    "00:17:9a": "D-Link",
    "00:19:5b": "D-Link",
    "00:1b:11": "D-Link",
    "00:1c:f0": "D-Link",
    "00:21:91": "D-Link",
    "00:22:b0": "D-Link",
    "00:24:01": "D-Link",
    "c8:d3:a3": "D-Link",
    "14:d6:4d": "D-Link",
    "b8:a3:86": "D-Link",
    "00:50:fc": "Edimax",
    "a0:f3:c1": "TP-Link",
    "20:0d:b0": "Shenzhen",
    "c0:25:e9": "TP-Link",
    "24:a4:3c": "Ubiquiti",
    "78:8a:20": "Ubiquiti",
    "b4:fb:e4": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "04:18:d6": "Ubiquiti",
    "18:e8:29": "Ubiquiti",
    "44:d9:e7": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "74:83:c2": "Ubiquiti",
    "80:2a:a8": "Ubiquiti",
    "ac:8b:a9": "Ubiquiti",
    "dc:9f:db": "Ubiquiti",
    "e0:63:da": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti",
    "20:a6:cd": "Netgear",
    "c4:04:15": "Netgear",
    "00:14:6c": "Netgear",
    "00:1b:2f": "Netgear",
    "00:1e:2a": "Netgear",
    "00:1f:33": "Netgear",
    "00:22:3f": "Netgear",
    "00:24:b2": "Netgear",
    "00:26:f2": "Netgear",
    "2c:b0:5d": "Netgear",
    "30:46:9a": "Netgear",
    "44:94:fc": "Netgear",
    "6c:b0:ce": "Netgear",
    "84:1b:5e": "Netgear",
    "a0:04:60": "Netgear",
    "a0:21:b7": "Netgear",
    "a4:2b:8c": "Netgear",
    "b0:7f:b9": "Netgear",
    "c0:3f:0e": "Netgear",
    "e0:46:9a": "Netgear",
    "e0:91:f5": "Netgear",
    "e4:f4:c6": "Netgear",
    "08:36:c9": "Netgear",
    "28:c6:8e": "Netgear",
    "2c:30:33": "Netgear",
    "4c:60:de": "Netgear",
    "6c:b0:ce": "Netgear",
    "9c:3d:cf": "Netgear",
    "b0:39:56": "Netgear",
    "c4:3d:c7": "Netgear",
    "dc:ef:09": "Netgear",
    "e8:fc:af": "Netgear",
    "f8:73:94": "Netgear",
}


def get_local_ip():
    """Get this machine's IP on the local network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send anything — just figures out which
        # network interface would be used to reach the internet
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def get_netmask(ifname="en0"):
    """Get the subnet mask for a network interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # SIOCGIFNETMASK ioctl to get the netmask
        result = fcntl.ioctl(s.fileno(), 0xC0206919, struct.pack("256s", ifname.encode()))
        return socket.inet_ntoa(result[20:24])
    except Exception:
        # Default to /24 (most common home network)
        return "255.255.255.0"


def calculate_cidr(ip, netmask):
    """Convert IP + netmask to CIDR notation (e.g., 192.168.1.0/24)."""
    ip_parts = [int(x) for x in ip.split(".")]
    mask_parts = [int(x) for x in netmask.split(".")]

    # AND the IP with the mask to get the network address
    network = [ip_parts[i] & mask_parts[i] for i in range(4)]

    # Count the bits in the mask to get the prefix length
    mask_int = sum(mask_parts[i] << (24 - 8 * i) for i in range(4))
    prefix_len = bin(mask_int).count("1")

    return f"{'.'.join(map(str, network))}/{prefix_len}"


def lookup_vendor(mac):
    """Look up device manufacturer from MAC address prefix."""
    prefix = mac[:8].lower()
    return MAC_VENDORS.get(prefix, "Unknown")


def arp_scan(target_range, timeout=3):
    """
    Send ARP requests to discover all live hosts on the network.

    This is the same technique tools like nmap use with the -sn flag.
    ARP works at Layer 2 (data link layer), so it can find devices
    that block ping (ICMP) or have firewalls up.
    """
    print(f"\n[*] ARP scanning {target_range} ...")
    print(f"[*] Timeout: {timeout}s per batch\n")

    # Build the packet:
    # Ether(dst="ff:ff:ff:ff:ff:ff") = broadcast to everyone
    # ARP(pdst=target_range) = "who has this IP?"
    arp_request = ARP(pdst=target_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # Send and receive responses
    answered, unanswered = srp(packet, timeout=timeout, retry=1)

    devices = []
    for sent, received in answered:
        vendor = lookup_vendor(received.hwsrc)
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": vendor,
        })

    return devices


def display_results(devices, local_ip):
    """Pretty-print discovered devices."""
    if not devices:
        print("[!] No devices found. Are you on the right network?")
        print("[!] Make sure to run with sudo.")
        return

    # Sort by IP address
    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])

    print(f"{'IP Address':<18} {'MAC Address':<20} {'Vendor':<15} {'Notes'}")
    print("-" * 75)

    for device in devices:
        notes = ""
        if device["ip"] == local_ip:
            notes = "← YOU"
        elif device["ip"].endswith(".1"):
            notes = "← likely router/gateway"

        print(f"{device['ip']:<18} {device['mac']:<20} {device['vendor']:<15} {notes}")

    print(f"\n[*] {len(devices)} devices found on network")


def main():
    # Determine target range
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        local_ip = get_local_ip()
        netmask = get_netmask()
        target = calculate_cidr(local_ip, netmask)
        print(f"[*] Your IP: {local_ip}")
        print(f"[*] Netmask: {netmask}")
        print(f"[*] Auto-detected network: {target}")

    local_ip = get_local_ip()
    devices = arp_scan(target)
    display_results(devices, local_ip)


if __name__ == "__main__":
    main()
