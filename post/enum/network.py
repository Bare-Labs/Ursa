"""Network enumeration.

Collects: network interfaces and IPs, routing table, ARP cache,
listening services, active outbound connections, firewall rules,
and /etc/hosts entries.  Everything is read-only.

Platform: Linux, macOS (darwin).
"""

from __future__ import annotations

import re
import socket
import subprocess

from post.base import ModuleResult, PostModule
from post.loader import register


def _run(cmd: str, timeout: int = 10) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return (r.stdout + r.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return f"[error: {exc}]"


def _interfaces() -> dict:
    """Parse network interfaces from `ip addr` (Linux) or `ifconfig` (macOS)."""
    raw = _run("ip addr show 2>/dev/null || ifconfig 2>/dev/null")
    interfaces: dict[str, dict] = {}

    # Try `ip addr` format first
    current: str | None = None
    for line in raw.splitlines():
        m = re.match(r"^\d+:\s+(\S+):", line)
        if m:
            current = m.group(1).rstrip(":")
            interfaces[current] = {"ipv4": [], "ipv6": [], "mac": ""}
            continue
        if current is None:
            continue
        m_inet = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", line)
        if m_inet:
            interfaces[current]["ipv4"].append(m_inet.group(1))
        m_inet6 = re.search(r"inet6\s+([0-9a-f:]+/\d+)", line)
        if m_inet6:
            interfaces[current]["ipv6"].append(m_inet6.group(1))
        m_mac = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
        if m_mac:
            interfaces[current]["mac"] = m_mac.group(1)

    # Fall back to ifconfig format if ip addr produced nothing
    if not any(v["ipv4"] for v in interfaces.values()):
        current = None
        for line in raw.splitlines():
            iface_m = re.match(r"^(\S+)[\s:]", line)
            if iface_m and not line.startswith(" ") and not line.startswith("\t"):
                current = iface_m.group(1).rstrip(":")
                interfaces.setdefault(current, {"ipv4": [], "ipv6": [], "mac": ""})
            if current is None:
                continue
            m_inet = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m_inet:
                interfaces[current]["ipv4"].append(m_inet.group(1))
            m_mac = re.search(r"ether\s+([0-9a-f:]{17})", line)
            if m_mac:
                interfaces[current]["mac"] = m_mac.group(1)

    return interfaces


def _routes() -> str:
    """Routing table."""
    return _run("ip route show 2>/dev/null || netstat -rn 2>/dev/null")


def _arp_cache() -> str:
    """ARP cache — reveals other live hosts on the local segment."""
    return _run("arp -a 2>/dev/null || ip neigh show 2>/dev/null")


def _listening_ports() -> list[dict]:
    """Parse listening TCP/UDP sockets from ss or netstat."""
    # ss output: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    raw = _run("ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null || netstat -an 2>/dev/null")
    ports = []
    for line in raw.splitlines():
        # ss format
        m = re.search(r"(tcp|udp)\s+\S+\s+\d+\s+\d+\s+(\S+):(\d+)\s+\S+\s*(.*)", line, re.I)
        if m:
            ports.append({
                "proto": m.group(1).lower(),
                "local_addr": m.group(2),
                "port": int(m.group(3)),
                "process": m.group(4).strip(),
            })
    return ports


def _active_connections() -> str:
    """Active (ESTABLISHED) TCP connections."""
    return _run(
        "ss -tnp state established 2>/dev/null"
        " || netstat -tnp 2>/dev/null | grep ESTABLISHED"
    )


def _firewall_rules() -> dict:
    """Read firewall rules (read-only, may require root for full output)."""
    iptables = _run("iptables -L -n --line-numbers 2>/dev/null")
    ufw = _run("ufw status verbose 2>/dev/null")
    pf = _run("pfctl -sr 2>/dev/null")   # macOS
    return {
        "iptables": iptables,
        "ufw": ufw,
        "pf": pf,
    }


def _hosts_file() -> str:
    """Read /etc/hosts — may reveal internal hostnames."""
    try:
        with open("/etc/hosts") as f:
            return f.read()
    except OSError:
        return "[not readable]"


def _dns_config() -> str:
    """DNS resolver configuration."""
    resolv = _run("cat /etc/resolv.conf 2>/dev/null")
    dns_via_cmd = _run("resolvectl status 2>/dev/null | head -20")
    return resolv or dns_via_cmd


@register
class NetworkModule(PostModule):
    NAME = "enum/network"
    DESCRIPTION = "Network enumeration: interfaces, routes, ARP, listening ports, firewall, /etc/hosts"
    PLATFORM = ["linux", "darwin"]

    def run(self, args: dict | None = None) -> ModuleResult:  # noqa: ARG002
        data: dict = {}
        lines: list[str] = []

        data["hostname"] = socket.getfqdn()
        lines.append(f"Hostname: {data['hostname']}")

        data["interfaces"] = _interfaces()
        lines.append("Interfaces:")
        for iface, info in data["interfaces"].items():
            if info["ipv4"]:
                lines.append(f"  {iface}: {info['ipv4']}  mac={info['mac']}")

        data["routes"] = _routes()
        lines.append(f"Routes:\n{data['routes']}")

        data["arp_cache"] = _arp_cache()
        lines.append(f"ARP cache:\n{data['arp_cache']}")

        data["listening_ports"] = _listening_ports()
        lines.append("Listening ports:")
        for p in data["listening_ports"]:
            lines.append(f"  {p['proto']}:{p['port']}  {p['local_addr']}  {p['process']}")

        data["active_connections"] = _active_connections()
        lines.append(f"Active connections:\n{data['active_connections']}")

        data["firewall"] = _firewall_rules()

        data["hosts_file"] = _hosts_file()
        lines.append(f"/etc/hosts:\n{data['hosts_file']}")

        data["dns_config"] = _dns_config()

        # Highlight internal RFC-1918 ranges found in ARP / interfaces
        private_re = re.compile(
            r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b"
        )
        all_text = data["arp_cache"] + "\n" + data["routes"]
        internal_ips = sorted(set(private_re.findall(all_text)))
        data["internal_hosts_seen"] = [ip if isinstance(ip, str) else ip[0] for ip in internal_ips]
        if data["internal_hosts_seen"]:
            lines.append(f"Internal hosts in ARP/routes: {data['internal_hosts_seen']}")

        return ModuleResult(ok=True, output="\n".join(lines), data=data)
