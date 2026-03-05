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

**Session Management:**
- `ursa_sessions` — List all sessions (active/stale/dead)
- `ursa_session_info` — Detailed info on a specific session
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
