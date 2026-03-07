# Ursa Major

Command and control server — the C2 component of [Ursa](../README.md).

Ursa Major is an HTTP-based C2 server that manages implant sessions, queues tasks, collects results, and handles file transfers. It provides both an API for direct use and an MCP server for AI agent integration.

## Architecture

```
Implant (beacon.py)          Ursa Major (server.py)           Operator
      │                            │                             │
      ├── POST /register ─────────►│  Create session + AES key   │
      │                            │                             │
      ├── POST /beacon ───────────►│  Return pending tasks       │
      │◄─── tasks (encrypted) ─────│                             │
      │                            │                             │
      │   [execute task locally]   │                             │
      │                            │       MCP / API             │
      ├── POST /result ───────────►│◄────────────────────────────┤
      │                            │  ursa_shell("whoami")       │
      ├── POST /upload ───────────►│                             │
      │   (file exfiltration)      │  ursa_task_result(id)       │
      │                            │────────────────────────────►│
      │◄── GET /download/<id> ─────│                             │
      │   (file delivery)          │                             │
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | New implant registers, receives session ID and encryption key |
| `POST` | `/beacon` | Implant check-in, returns pending tasks |
| `POST` | `/result` | Implant submits task results |
| `POST` | `/upload` | Implant uploads a file (exfiltration) |
| `GET` | `/download/<id>` | Implant downloads a file (delivery) |
| `GET` | `/stage` | Serve the stager payload for initial delivery |
| `GET` | `/health` | Health check |

## MCP Tools

When accessed via MCP (through the root `server.py`), operators get these tools:

**C2 Management:**
- `ursa_start_c2` — Start the C2 server daemon
- `ursa_stop_c2` — Stop the C2 server
- `ursa_c2_status` — Check if C2 is running, show stats
- `ursa_events` — View the C2 event log
- `ursa_policy_matrix` — View risk policy mapping for task types
- `ursa_governance_summary` — Pending approvals summary by risk/campaign (filterable)
- `ursa_set_campaign_policy` — Configure campaign approval-alert thresholds (including oldest pending age)
- `ursa_campaign_policies` — List campaign threshold policies
- `ursa_delete_campaign_policy` — Delete campaign threshold policy
- `ursa_campaign_alerts` — Show active campaign policy threshold alerts
- `ursa_policy_remediation_plan` — Suggested actions for active policy alerts
- `ursa_preview_policy_remediation` — Dry-run remediation impact by strategy
- `ursa_apply_policy_remediation` — Apply conservative campaign remediation strategy
- `ursa_governance_report` — Export governance snapshot report (JSON/CSV)
- `ursa_approvals` — List pending/approved/rejected step-up approvals (filterable)
- `ursa_approve` — Approve a pending request and queue its task
- `ursa_reject` — Reject a pending request
- `ursa_approve_campaign` — Bulk-approve pending requests for campaign/tag/risk
- `ursa_reject_campaign` — Bulk-reject pending requests for campaign/tag/risk
- `ursa_audit_integrity` — Verify immutable audit chain integrity

**Session Management:**
- `ursa_sessions` — List all sessions (active/stale/dead)
- `ursa_session_info` — Detailed info on a specific session
- `ursa_set_session_context` — Set campaign and tags for session grouping
- `ursa_campaigns` — Campaign summary (sessions/tasks/events)
- `ursa_campaign_report` — Export campaign report as JSON/CSV
- `ursa_campaign_info` — Detailed single-campaign operational context
- `ursa_campaign_timeline` — Unified timeline of events/tasks/approvals for a campaign
- `ursa_campaign_add_note` — Add campaign operator note
- `ursa_campaign_notes` — List recent campaign notes
- `ursa_campaign_delete_note` — Delete campaign note by ID
- `ursa_campaign_playbooks` — List checklist playbooks
- `ursa_campaign_save_playbook` — Create/update checklist playbook from JSON items
- `ursa_campaign_delete_playbook` — Delete checklist playbook
- `ursa_campaign_apply_playbook` — Apply a playbook to a campaign checklist
- `ursa_campaign_snapshot_playbook` — Snapshot campaign checklist into a reusable playbook
- `ursa_campaign_checklist` — List campaign checklist items
- `ursa_campaign_checklist_history` — List checklist history timeline entries
- `ursa_campaign_add_checklist_item` — Add a campaign checklist item
- `ursa_campaign_update_checklist_item` — Update checklist title/details/owner/due/status
- `ursa_campaign_delete_checklist_item` — Delete campaign checklist item by ID
- `ursa_campaign_bulk_update_checklist` — Bulk-update checklist status by filters
- `ursa_campaign_checklist_alerts` — Show overdue / near-due checklist items
- `ursa_campaign_checklist_from_alerts` — Generate checklist remediation items from active policy alerts
- `ursa_campaign_handoff` — Generate campaign handoff brief
- `ursa_campaign_handoff_report` — Export campaign handoff report (MD/JSON)
- `ursa_kill_session` — Terminate a session

**Tasking:**
- `ursa_shell` — Execute a shell command on a target
- `ursa_task` — Send any task type (shell, sysinfo, download, upload, sleep, kill, ps, pwd, cd, ls, whoami, env)
- `ursa_task_result` — Check the output of a task
- `ursa_tasks` — List tasks filtered by session or status

**File Operations:**
- `ursa_download` — Exfiltrate a file from a target
- `ursa_upload` — Deliver a file to a target
- `ursa_files` — List all transferred files

**Payload Generation:**
- `ursa_generate` — Generate a full beacon payload
- `ursa_stager` — Generate stager one-liners for different platforms

## Encryption

All implant communication (after registration) is encrypted with per-session AES-256-CTR + HMAC-SHA256. Keys are negotiated during the `/register` handshake. HTTP traffic is structured as normal JSON API responses to blend with regular web traffic.

## Database

Ursa Major uses SQLite (WAL mode) with these tables:

| Table | Purpose |
|-------|---------|
| `sessions` | Implant sessions — IP, hostname, OS, arch, status, encryption key |
| `tasks` | Task queue — type, args, status, results, timestamps |
| `files` | Transferred files — filename, direction, size, binary data |
| `listeners` | Listener configurations |
| `event_log` | Audit trail of all C2 operations |
| `approval_requests` | Step-up approvals for high-risk actions |
| `immutable_audit` | Hash-chained immutable governance/audit records |

The database is created automatically on first run. It is excluded from version control (`.gitignore`) since it contains operational data.

## Running

### Via MCP (recommended)

The MCP server manages the C2 lifecycle — Claude can start/stop it with `ursa_start_c2` and `ursa_stop_c2`.

### Standalone

```bash
python3 major/server.py                    # Default: 0.0.0.0:8443
python3 major/server.py --port 9000        # Custom port
python3 major/server.py --host 127.0.0.1   # Localhost only
```

## File Structure

```
major/
├── server.py     # HTTP C2 server
├── db.py         # SQLite database layer
├── crypto.py     # AES-256-CTR + HMAC-SHA256 encryption
└── __init__.py
```
