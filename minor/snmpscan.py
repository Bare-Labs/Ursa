#!/usr/bin/env python3
"""
SNMP Scanner
============
WHAT THIS DOES:
    Queries devices using SNMP (Simple Network Management Protocol) to
    extract system information, network configs, routing tables, and more.
    Also brute-forces community strings (SNMP's "password").

WHY IT MATTERS:
    SNMP is one of the most overlooked attack surfaces:
    - Default community string "public" is left unchanged everywhere
    - Read access reveals: hostname, OS, interfaces, routing, ARP tables,
      running processes, installed software, user accounts
    - Write access ("private") can let you modify configs, change routes,
      or even upload firmware
    - Found on routers, switches, printers, UPS systems, HVAC, cameras

    It's like having read access to the device's entire brain.

HOW SNMP WORKS:
    SNMP uses OIDs (Object Identifiers) — numeric paths that identify
    specific pieces of data on a device. Think of it like a filesystem:

    .1.3.6.1.2.1.1.1.0 = sysDescr (system description)
    .1.3.6.1.2.1.1.5.0 = sysName (hostname)
    .1.3.6.1.2.1.4.20  = IP addresses table

    You send a "GET" request with an OID and the device responds with
    the value. The "community string" is the password (sent in plaintext!).

USAGE:
    python3 snmpscan.py 192.168.1.1                    # try default strings
    python3 snmpscan.py 192.168.1.1 -c public          # specific community
    python3 snmpscan.py 192.168.1.1 --brute             # brute-force strings
    python3 snmpscan.py 192.168.1.1 --walk              # full SNMP walk
    python3 snmpscan.py --sweep 192.168.1.0/24          # find SNMP devices
"""

import sys
import socket
import struct
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── SNMP Protocol Implementation ──

# We implement SNMPv1/v2c from scratch using raw sockets
# because it's educational and avoids dependencies.
# In real engagements you'd use snmpwalk, snmpget, or pysnmp.

# ASN.1 / BER encoding types used in SNMP
ASN1_SEQUENCE = 0x30
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OID = 0x06
ASN1_GET_REQUEST = 0xa0
ASN1_GET_NEXT_REQUEST = 0xa1
ASN1_GET_RESPONSE = 0xa2
ASN1_COUNTER32 = 0x41
ASN1_GAUGE32 = 0x42
ASN1_TIMETICKS = 0x43
ASN1_IP_ADDRESS = 0x40
ASN1_COUNTER64 = 0x46
ASN1_NO_SUCH_OBJECT = 0x80
ASN1_NO_SUCH_INSTANCE = 0x81
ASN1_END_OF_MIB = 0x82


# Common OIDs and what they reveal
IMPORTANT_OIDS = {
    "1.3.6.1.2.1.1.1.0": ("sysDescr", "System description — OS, version, hardware"),
    "1.3.6.1.2.1.1.2.0": ("sysObjectID", "Vendor OID"),
    "1.3.6.1.2.1.1.3.0": ("sysUpTime", "How long the device has been running"),
    "1.3.6.1.2.1.1.4.0": ("sysContact", "Admin contact info"),
    "1.3.6.1.2.1.1.5.0": ("sysName", "Hostname"),
    "1.3.6.1.2.1.1.6.0": ("sysLocation", "Physical location"),
    "1.3.6.1.2.1.1.7.0": ("sysServices", "Available services"),
}

# OID subtrees for walking
WALK_OIDS = {
    "1.3.6.1.2.1.2.2": "Network interfaces",
    "1.3.6.1.2.1.4.20": "IP addresses",
    "1.3.6.1.2.1.4.21": "IP routing table",
    "1.3.6.1.2.1.3.1": "ARP table",
    "1.3.6.1.2.1.25.4.2": "Running processes",
    "1.3.6.1.2.1.25.6.3": "Installed software",
    "1.3.6.1.2.1.6.13": "TCP connections",
    "1.3.6.1.2.1.25.1": "Host info (OS details)",
}

# Default community strings to try
DEFAULT_COMMUNITIES = [
    "public", "private", "community", "snmp",
    "monitor", "manager", "admin", "default",
    "read", "write", "secret", "cisco",
    "cable-docsis", "ILMI", "internal",
    "mngt", "system", "tivoli", "openview",
    "netman", "security", "all private",
    "test", "guest", "access", "network",
]


def encode_length(length):
    """BER-encode a length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])


def encode_integer(value):
    """BER-encode an integer."""
    if value == 0:
        data = b"\x00"
    else:
        data = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return bytes([ASN1_INTEGER]) + encode_length(len(data)) + data


def encode_string(value):
    """BER-encode an octet string."""
    data = value.encode() if isinstance(value, str) else value
    return bytes([ASN1_OCTET_STRING]) + encode_length(len(data)) + data


def encode_null():
    """BER-encode a NULL."""
    return bytes([ASN1_NULL, 0x00])


def encode_oid(oid_str):
    """BER-encode an OID from dotted string format."""
    parts = [int(x) for x in oid_str.split(".") if x]

    if len(parts) < 2:
        parts = [1, 3] + parts

    # First two components are combined
    encoded = bytes([parts[0] * 40 + parts[1]])

    for part in parts[2:]:
        if part < 128:
            encoded += bytes([part])
        else:
            # Multi-byte encoding for large values
            temp = []
            temp.append(part & 0x7f)
            part >>= 7
            while part:
                temp.append(0x80 | (part & 0x7f))
                part >>= 7
            encoded += bytes(reversed(temp))

    return bytes([ASN1_OID]) + encode_length(len(encoded)) + encoded


def encode_sequence(data):
    """BER-encode a SEQUENCE."""
    return bytes([ASN1_SEQUENCE]) + encode_length(len(data)) + data


def build_snmp_get(community, oid, request_id=1):
    """
    Build an SNMPv1 GET request packet.

    Structure:
    SEQUENCE {
        INTEGER version (0 = SNMPv1)
        OCTET STRING community
        GetRequest-PDU {
            INTEGER request-id
            INTEGER error-status
            INTEGER error-index
            SEQUENCE OF {
                SEQUENCE {
                    OID
                    NULL value
                }
            }
        }
    }
    """
    # Variable binding: OID + NULL
    varbind = encode_oid(oid) + encode_null()
    varbind_seq = encode_sequence(varbind)
    varbind_list = encode_sequence(varbind_seq)

    # PDU
    pdu_data = (
        encode_integer(request_id) +
        encode_integer(0) +  # error-status
        encode_integer(0) +  # error-index
        varbind_list
    )
    pdu = bytes([ASN1_GET_REQUEST]) + encode_length(len(pdu_data)) + pdu_data

    # Full message
    message = (
        encode_integer(0) +  # version: SNMPv1 = 0, SNMPv2c = 1
        encode_string(community) +
        pdu
    )

    return encode_sequence(message)


def build_snmp_getnext(community, oid, request_id=1):
    """Build an SNMP GETNEXT request (for walking)."""
    varbind = encode_oid(oid) + encode_null()
    varbind_seq = encode_sequence(varbind)
    varbind_list = encode_sequence(varbind_seq)

    pdu_data = (
        encode_integer(request_id) +
        encode_integer(0) +
        encode_integer(0) +
        varbind_list
    )
    pdu = bytes([ASN1_GET_NEXT_REQUEST]) + encode_length(len(pdu_data)) + pdu_data

    message = (
        encode_integer(1) +  # SNMPv2c
        encode_string(community) +
        pdu
    )

    return encode_sequence(message)


def decode_tlv(data, offset=0):
    """Decode a BER TLV (Type-Length-Value) at the given offset."""
    if offset >= len(data):
        return None, None, offset

    tag = data[offset]
    offset += 1

    # Decode length
    if data[offset] < 0x80:
        length = data[offset]
        offset += 1
    elif data[offset] == 0x81:
        length = data[offset + 1]
        offset += 2
    elif data[offset] == 0x82:
        length = (data[offset + 1] << 8) | data[offset + 2]
        offset += 3
    else:
        return tag, None, offset

    value = data[offset:offset + length]
    return tag, value, offset + length


def decode_oid(data):
    """Decode a BER-encoded OID to dotted string."""
    if not data:
        return ""

    parts = [str(data[0] // 40), str(data[0] % 40)]

    i = 1
    while i < len(data):
        value = 0
        while i < len(data):
            value = (value << 7) | (data[i] & 0x7f)
            if not (data[i] & 0x80):
                i += 1
                break
            i += 1
        parts.append(str(value))

    return ".".join(parts)


def decode_snmp_response(data):
    """
    Parse an SNMP response and extract the OID and value.

    Returns: (oid_string, value, value_type)
    """
    try:
        # Outer SEQUENCE
        tag, content, _ = decode_tlv(data)
        if tag != ASN1_SEQUENCE:
            return None, None, None

        offset = 0

        # Version
        tag, version_data, offset = decode_tlv(content, offset)

        # Community string
        tag, community, offset = decode_tlv(content, offset)

        # PDU
        tag, pdu_data, _ = decode_tlv(content, offset)
        if tag != ASN1_GET_RESPONSE:
            return None, None, None

        pdu_offset = 0

        # Request ID
        _, _, pdu_offset = decode_tlv(pdu_data, pdu_offset)
        # Error status
        tag, err_data, pdu_offset = decode_tlv(pdu_data, pdu_offset)
        error_status = int.from_bytes(err_data, "big") if err_data else 0
        # Error index
        _, _, pdu_offset = decode_tlv(pdu_data, pdu_offset)

        if error_status != 0:
            return None, None, None

        # Varbind list (SEQUENCE OF)
        _, varbind_list, _ = decode_tlv(pdu_data, pdu_offset)

        # First varbind (SEQUENCE)
        _, varbind, _ = decode_tlv(varbind_list)

        vb_offset = 0

        # OID
        tag, oid_data, vb_offset = decode_tlv(varbind, vb_offset)
        oid_str = decode_oid(oid_data) if tag == ASN1_OID else ""

        # Value
        tag, value_data, _ = decode_tlv(varbind, vb_offset)

        # Decode value based on type
        if tag == ASN1_OCTET_STRING:
            try:
                value = value_data.decode("utf-8", errors="replace")
            except Exception:
                value = value_data.hex()
        elif tag == ASN1_INTEGER:
            value = int.from_bytes(value_data, "big", signed=True)
        elif tag == ASN1_OID:
            value = decode_oid(value_data)
        elif tag == ASN1_TIMETICKS:
            ticks = int.from_bytes(value_data, "big")
            seconds = ticks // 100
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            minutes = (seconds % 3600) // 60
            value = f"{days}d {hours}h {minutes}m ({ticks} ticks)"
        elif tag == ASN1_IP_ADDRESS:
            value = ".".join(str(b) for b in value_data)
        elif tag == ASN1_COUNTER32 or tag == ASN1_GAUGE32:
            value = int.from_bytes(value_data, "big")
        elif tag == ASN1_COUNTER64:
            value = int.from_bytes(value_data, "big")
        elif tag in (ASN1_NO_SUCH_OBJECT, ASN1_NO_SUCH_INSTANCE, ASN1_END_OF_MIB):
            value = None
        elif tag == ASN1_NULL:
            value = None
        else:
            value = value_data.hex() if value_data else None

        return oid_str, value, tag

    except Exception as e:
        return None, None, None


def snmp_get(target, community, oid, timeout=3, port=161):
    """Send an SNMP GET request and return the value."""
    packet = build_snmp_get(community, oid)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (target, port))
        data, _ = sock.recvfrom(65535)
        sock.close()

        oid_str, value, _ = decode_snmp_response(data)
        return value

    except socket.timeout:
        return None
    except Exception:
        return None


def snmp_walk(target, community, base_oid, timeout=3, port=161, max_results=500):
    """
    SNMP walk — get all OIDs under a base OID.

    Sends repeated GETNEXT requests, each time using the OID from
    the previous response, until we leave the subtree.
    """
    results = []
    current_oid = base_oid
    request_id = 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        while len(results) < max_results:
            packet = build_snmp_getnext(community, current_oid, request_id)
            request_id += 1

            sock.sendto(packet, (target, port))
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                break

            oid_str, value, tag = decode_snmp_response(data)

            if oid_str is None or value is None:
                break

            # Check if we've left the subtree
            if not oid_str.startswith(base_oid):
                break

            # End of MIB
            if tag in (ASN1_END_OF_MIB, ASN1_NO_SUCH_OBJECT, ASN1_NO_SUCH_INSTANCE):
                break

            results.append((oid_str, value))
            current_oid = oid_str

    except Exception:
        pass
    finally:
        sock.close()

    return results


def brute_force_community(target, timeout=2, port=161, threads=10):
    """
    Brute-force SNMP community strings.

    Try a list of common community strings against the target.
    Most devices use "public" for read and "private" for write.
    """
    found = []

    def try_community(community):
        value = snmp_get(target, community, "1.3.6.1.2.1.1.1.0", timeout, port)
        if value is not None:
            return community, value
        return None, None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(try_community, c): c
            for c in DEFAULT_COMMUNITIES
        }

        for future in as_completed(futures):
            community, value = future.result()
            if community:
                found.append({"community": community, "sysDescr": value})
                print(f"  [+] Found: '{community}' — {str(value)[:80]}")

    return found


def sweep_network(target_range, timeout=2, port=161, threads=20):
    """
    Sweep a network range for SNMP-enabled devices.

    Tries "public" community string on every IP.
    """
    import ipaddress

    network = ipaddress.ip_network(target_range, strict=False)
    found = []

    def check_host(ip):
        value = snmp_get(str(ip), "public", "1.3.6.1.2.1.1.1.0", timeout, port)
        if value:
            return str(ip), value
        return None, None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in network.hosts()}

        for future in as_completed(futures):
            ip, value = future.result()
            if ip:
                found.append({"ip": ip, "sysDescr": value})
                print(f"  [+] {ip} — {str(value)[:80]}")

    return found


def full_scan(target, community="public", do_walk=False, timeout=3):
    """Run full SNMP enumeration against a target."""
    start_time = datetime.now()

    print(f"\n[*] SNMP Scan: {target}")
    print(f"[*] Community: {community}")
    print(f"[*] Started: {start_time.strftime('%H:%M:%S')}\n")

    # Get basic system info
    print("[*] System Information:")
    for oid, (name, description) in IMPORTANT_OIDS.items():
        value = snmp_get(target, community, oid, timeout)
        if value is not None:
            # Truncate long values
            val_str = str(value)[:100]
            print(f"  {name:<15} {val_str}")
        else:
            if name == "sysDescr":
                print(f"  [!] No response — wrong community string or SNMP disabled")
                return

    # Walk subtrees if requested
    if do_walk:
        print(f"\n[*] Walking SNMP tree...")

        for base_oid, description in WALK_OIDS.items():
            print(f"\n  [*] {description} ({base_oid}):")
            results = snmp_walk(target, community, base_oid, timeout)

            if results:
                for oid, value in results[:20]:  # Limit output
                    # Clean up OID for display
                    short_oid = oid[len(base_oid):]
                    val_str = str(value)[:80]
                    print(f"    {short_oid:<30} {val_str}")

                if len(results) > 20:
                    print(f"    ... and {len(results) - 20} more entries")
            else:
                print(f"    (no data)")

    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Duration: {duration:.1f}s")


def main():
    parser = argparse.ArgumentParser(
        description="SNMP Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 snmpscan.py 192.168.1.1                  Basic scan with "public"
  python3 snmpscan.py 192.168.1.1 -c private       Use specific community
  python3 snmpscan.py 192.168.1.1 --brute           Brute-force community strings
  python3 snmpscan.py 192.168.1.1 --walk            Full SNMP walk
  python3 snmpscan.py --sweep 192.168.1.0/24        Find all SNMP devices
        """
    )

    parser.add_argument("target", nargs="?", help="Target IP address")
    parser.add_argument("-c", "--community", default="public",
                        help="SNMP community string (default: public)")
    parser.add_argument("--brute", action="store_true",
                        help="Brute-force community strings")
    parser.add_argument("--walk", action="store_true",
                        help="Full SNMP walk (verbose)")
    parser.add_argument("--sweep", help="Sweep network range for SNMP devices")
    parser.add_argument("--timeout", type=float, default=3)

    args = parser.parse_args()

    if args.sweep:
        print(f"\n[*] SNMP Network Sweep: {args.sweep}")
        print(f"[*] Community: public\n")
        devices = sweep_network(args.sweep, args.timeout)
        print(f"\n[*] {len(devices)} SNMP-enabled devices found")
        return

    if not args.target:
        parser.error("Provide a target IP or use --sweep")

    if args.brute:
        print(f"\n[*] Brute-forcing SNMP community strings on {args.target}...")
        found = brute_force_community(args.target, args.timeout)
        if found:
            print(f"\n[+] {len(found)} community strings found")
            for f in found:
                print(f"  '{f['community']}' → {str(f['sysDescr'])[:80]}")
        else:
            print("\n[-] No valid community strings found")
        return

    full_scan(args.target, args.community, args.walk, args.timeout)


if __name__ == "__main__":
    main()
