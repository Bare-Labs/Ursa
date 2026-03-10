# Ursa Major

Command and control server — the C2 component of [Ursa](../README.md).

Ursa Major is an HTTP-based C2 server that manages implant sessions, queues tasks, collects results, handles file transfers, and provides a web UI and MCP interface for operators.

## Architecture

```
Implant (beacon.py)          Ursa Major (major/server.py)         Operator
      │                               │                              │
      ├── POST /register ────────────►│  Create session + AES key    │
      │                               │                              │
      ├── POST /beacon ──────────────►│  Return pending tasks        │
      │◄─── tasks (encrypted) ────────│                              │
      │                               │                              │
      │   [execute task locally]      │      MCP (server.py)         │
      │                               │◄─────────────────────────────┤
      ├── POST /result ──────────────►│  ursa_shell("whoami")        │
      │                               │                              │
      ├── POST /upload ──────────────►│  ursa_task_result(id)        │
      │   (file exfiltration)         │─────────────────────────────►│
      │                               │                              │
      │◄── GET /download/<id> ────────│  Web UI (major/web/)         │
      │   (file delivery)             │◄─────────────────────────────┤
      │                               │  browser dashboard           │
```

## Running

### Via MCP (recommended)

The MCP server (`server.py` at project root) manages the C2 lifecycle — Claude can start/stop it with `ursa_start_c2` and `ursa_stop_c2`.

### Standalone

```bash
python3 major/server.py                    # Default: 0.0.0.0:8443
python3 major/server.py --port 9000        # Custom port
python3 major/server.py --host 127.0.0.1   # Localhost only
python3 major/server.py --tls              # Enable HTTPS (auto-generates cert)
```

### Web UI

```bash
python3 -m major.web                       # Default: http://0.0.0.0:8080
```

Default credentials (change before any non-local deployment):
- Username: `admin`  Password: `change-me-now`

Role-based access: `admin`, `reviewer`, `operator`.

### Configuration

Create a `ursa.yaml` at the project root to override defaults:

```yaml
major:
  port: 8443
  traffic_profile: jquery       # default | jquery | office365 | github-api
  tls:
    enabled: true
    hostname: c2.example.com    # SAN for the self-signed cert
  auto_recon:
    enabled: true
    modules:
      - enum/sysinfo
      - enum/users
      - enum/privesc
      - enum/network
      - enum/loot
  governance:
    require_step_up_approval: true
    step_up_risks: [high, critical]
  redirector:
    enabled: true
    listen_port: 80
    upstream_url: http://127.0.0.1:8443
    allowed_paths: [/jquery/]
    user_agent_filter: ""
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

Endpoint paths vary by traffic profile (e.g. the `jquery` profile remaps `/beacon` to `/jquery/3.7.1/jquery.min.js`).

## MCP Tools

When accessed via MCP (root `server.py`), operators get 60+ tools:

**Operator Situational Awareness:**
- `ursa_sitrep` — Morning briefing: active sessions, pending tasks, CRITICAL/HIGH findings, recon progress
- `ursa_session_recon` — Per-session findings viewer: loot findings grouped by severity

**C2 Management:**
- `ursa_start_c2` — Start the C2 server daemon
- `ursa_stop_c2` — Stop the C2 server
- `ursa_c2_status` — Check if C2 is running, show stats
- `ursa_events` — View the C2 event log
- `ursa_policy_matrix` — View risk policy mapping for task types
- `ursa_governance_summary` — Pending approvals summary by risk/campaign
- `ursa_set_campaign_policy` — Configure campaign approval-alert thresholds
- `ursa_campaign_policies` — List campaign threshold policies
- `ursa_delete_campaign_policy` — Delete campaign threshold policy
- `ursa_campaign_alerts` — Show active campaign policy threshold alerts
- `ursa_policy_remediation_plan` — Suggested actions for active policy alerts
- `ursa_preview_policy_remediation` — Dry-run remediation impact by strategy
- `ursa_apply_policy_remediation` — Apply conservative campaign remediation strategy
- `ursa_governance_report` — Export governance snapshot report (JSON/CSV)
- `ursa_approvals` — List pending/approved/rejected step-up approvals
- `ursa_approve` — Approve a pending request and queue its task
- `ursa_reject` — Reject a pending request
- `ursa_approve_campaign` — Bulk-approve pending requests for campaign/tag/risk
- `ursa_reject_campaign` — Bulk-reject pending requests for campaign/tag/risk
- `ursa_audit_integrity` — Verify immutable audit chain integrity

**Session Management:**
- `ursa_sessions` — List all sessions (active/stale/dead, filterable)
- `ursa_session_info` — Detailed info on a specific session
- `ursa_set_session_context` — Set campaign and tags for session grouping
- `ursa_kill_session` — Terminate a session
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
- `ursa_campaign_checklist_history` — Checklist history timeline entries
- `ursa_campaign_add_checklist_item` — Add a campaign checklist item
- `ursa_campaign_update_checklist_item` — Update checklist title/details/owner/due/status
- `ursa_campaign_delete_checklist_item` — Delete campaign checklist item by ID
- `ursa_campaign_bulk_update_checklist` — Bulk-update checklist status by filters
- `ursa_campaign_checklist_alerts` — Show overdue / near-due checklist items
- `ursa_campaign_checklist_from_alerts` — Generate checklist items from active policy alerts
- `ursa_campaign_handoff` — Generate campaign handoff brief
- `ursa_campaign_handoff_report` — Export campaign handoff report (MD/JSON)

**Tasking:**
- `ursa_shell` — Execute a shell command on a target
- `ursa_task` — Send any task type (shell, sysinfo, download, upload, sleep, kill, ps, pwd, cd, ls, whoami, env)
- `ursa_task_result` — Check the output of a task
- `ursa_tasks` — List tasks filtered by session/status/campaign/tag

**Post-Exploitation:**
- `ursa_post_list` — List all available post-exploitation modules
- `ursa_post_run` — Run a post-exploitation module (locally on C2 for enumeration)

**File Operations:**
- `ursa_download` — Exfiltrate a file from a target
- `ursa_upload` — Deliver a file to a target
- `ursa_files` — List all transferred files

**Payload Generation:**
- `ursa_generate` — Generate a full beacon payload (Python, Go, Zig, or any template)
- `ursa_stager` — Generate stager one-liners for bash, python, powershell

## Encryption

All implant communication (after registration) is encrypted with per-session AES-256-CTR + HMAC-SHA256. Keys are negotiated during the `/register` handshake.

## Traffic Profiles

Four built-in profiles change URL paths and response headers to blend with legitimate traffic:

| Profile | Beacon path | Server header |
|---------|-------------|---------------|
| `default` | `/beacon` | `nginx/1.24.0` |
| `jquery` | `/jquery/3.7.1/jquery.min.js` | `nginx/1.24.0` |
| `office365` | `/autodiscover/autodiscover.xml` | `Microsoft-IIS/10.0` |
| `github-api` | `/api/v3/repos` | `GitHub.com` |

Set with `traffic_profile` in `ursa.yaml` or `--profile` CLI flag. The builder automatically substitutes the correct URL paths into generated payloads.

## Auto-Recon

When `auto_recon.enabled: true`, Ursa Major queues a configurable set of post-exploitation modules on the first beacon check-in from a new session. Results surface automatically in `ursa_sitrep` and `ursa_session_recon`.

Completed `enum/sysinfo` results also trigger **session auto-tagging** — OS (linux/darwin/windows), architecture (x64/arm64), privilege level (root/admin), and cloud credentials (aws-creds/k8s) are applied as session tags automatically.

## Database

SQLite (WAL mode) at `major/ursa.db` (auto-created on first run, excluded from version control):

| Table | Purpose |
|-------|---------|
| `sessions` | Implant sessions — IP, hostname, OS, arch, status, encryption key |
| `tasks` | Task queue — type, args, status, results, timestamps |
| `files` | Transferred files — filename, direction, size, binary data |
| `event_log` | Audit trail of all C2 operations |
| `approval_requests` | Step-up approvals for high-risk actions |
| `immutable_audit` | HMAC-chained immutable governance/audit records |
| `settings` | Key-value runtime settings (auto-recon state, etc.) |

## File Structure

```
major/
├── server.py       # HTTP C2 server (registration, beacon, result, upload, download)
├── db.py           # SQLite database layer
├── crypto.py       # AES-256-CTR + HMAC-SHA256 encryption
├── governance.py   # Step-up approvals, immutable audit chain, policy matrix
├── profiles.py     # Traffic profiles (URL remapping, headers, UA filtering)
├── cert.py         # TLS certificate generation (self-signed X.509 with SAN)
├── redirector.py   # HTTP transparent forwarding proxy
├── config.py       # YAML config loader with dotted-path access and defaults
├── listeners/
│   ├── dns.py      # DNS listener (stub — not yet implemented)
│   └── smb.py      # SMB listener (stub — not yet implemented)
├── web/
│   ├── app.py      # FastAPI application
│   ├── auth.py     # Session auth and RBAC
│   ├── __main__.py # Web UI entry point
│   ├── routes/     # Route handlers: dashboard, sessions, tasks, events, files,
│   │               #   campaigns, governance, auth, SSE
│   ├── templates/  # Jinja2 HTML templates
│   └── static/     # CSS, htmx
└── __init__.py
```
