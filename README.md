# Ursa

An AI-native red team penetration testing toolkit by [Bare Labs](https://github.com/BareLabs).

Ursa is built around two components — **Ursa Major** (command & control) and **Ursa Minor** (reconnaissance) — each exposing an [MCP](https://modelcontextprotocol.io/) server so AI agents like Claude can operate them conversationally alongside human operators.

```
                        ┌─────────────────────────────┐
                        │         AI Agent             │
                        │  (Claude Code / Desktop)     │
                        └──────────┬──────────────────┘
                                   │ MCP Protocol
                        ┌──────────┴──────────────────┐
                        │                              │
                ┌───────▼───────┐            ┌─────────▼──────┐
                │  Ursa Major   │            │  Ursa Minor    │
                │  C2 Server    │            │  Recon Toolkit │
                │  (server.py)  │            │  (minor/)      │
                └───────┬───────┘            └────────┬───────┘
                        │                             │
                ┌───────▼───────┐            ┌────────▼───────┐
                │   Web UI      │            │    Targets     │
                │  (major/web)  │            │  (scan/enum)   │
                └───────────────┘            └────────────────┘
                        │ HTTP
                ┌───────▼───────┐
                │   Implants    │
                │  (beacons)    │
                └───────────────┘
```

## Components

| Component | Description | Docs |
|-----------|-------------|------|
| **[Ursa Major](major/)** | C2 server — sessions, tasking, file transfer, encrypted comms, governance, web UI, traffic profiles, TLS, and 60+ MCP tools | [major/README.md](major/README.md) |
| **[Ursa Minor](minor/)** | Recon toolkit — 16 network reconnaissance and vulnerability scanning tools | [minor/README.md](minor/README.md) |
| **[Implants](implants/)** | HTTP beacons (Python + Go + Zig), stager, evasion, and payload builder | [implants/README.md](implants/README.md) |
| **[Post modules](post/)** | Post-exploitation: enumeration, credential harvesting, lateral movement, persistence | — |

## Quick Start

### Prerequisites

- Python 3.11+
- `sudo` access (required for raw network operations in Ursa Minor)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) or [Claude Desktop](https://claude.ai/download) (for MCP integration)

### Setup

```bash
git clone https://github.com/BareLabs/Ursa.git
cd Ursa

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install Ursa Minor as a package (optional, for CLI usage)
pip install ./minor
```

### Configuration (optional)

Copy and edit `ursa.yaml` to customize server settings, enable TLS, configure traffic profiles, set up the redirector, or tune auto-recon:

```bash
cp ursa.example.yaml ursa.yaml   # if present, otherwise create from scratch
```

Key settings:
```yaml
major:
  port: 8443
  traffic_profile: default        # default | jquery | office365 | github-api
  tls:
    enabled: false                # set true to enable HTTPS
  auto_recon:
    enabled: true                 # queue recon modules on first beacon check-in
  governance:
    require_step_up_approval: true
```

### MCP Configuration

To use Ursa with Claude, add both MCP servers to your configuration.

**Claude Code** (`~/.claude/settings.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "Ursa-Major": {
      "command": "/path/to/Ursa/venv/bin/python3",
      "args": ["/path/to/Ursa/server.py"]
    },
    "Ursa-Minor": {
      "command": "sudo",
      "args": ["/path/to/Ursa/venv/bin/python3", "/path/to/Ursa/minor/server.py"]
    }
  }
}
```

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "Ursa-Major": {
      "command": "/path/to/Ursa/venv/bin/python3",
      "args": ["/path/to/Ursa/server.py"]
    },
    "Ursa-Minor": {
      "command": "sudo",
      "args": ["/path/to/Ursa/venv/bin/python3", "/path/to/Ursa/minor/server.py"]
    }
  }
}
```

> Replace `/path/to/Ursa` with the actual path to your cloned repo.

> Ursa Minor requires `sudo` because tools like ARP scanning and packet sniffing need raw socket access.

### Web UI

Ursa Major includes a browser-based operator dashboard. Start it alongside the C2:

```bash
python3 -m major.web         # Default: http://0.0.0.0:8080
```

Default credentials (change before any non-local deployment):
- Username: `admin`  Password: `change-me-now`

### Standalone C2

```bash
python3 major/server.py                    # Default: 0.0.0.0:8443
python3 major/server.py --port 9000
python3 major/server.py --tls              # Enable HTTPS (auto-generates cert)
```

## What's Built

### Ursa Major — C2
- **Session management** — implant registration, check-in, status tracking (active/stale/dead)
- **Task queuing** — 13 task types: shell, sysinfo, ps, whoami, pwd, cd, ls, env, download, upload, sleep, kill, post
- **Encrypted comms** — per-session AES-256-CTR + HMAC-SHA256; keys negotiated at registration
- **File transfer** — exfiltration (upload from target) and delivery (download to target)
- **Traffic profiles** — 4 built-in malleable C2 profiles: `default`, `jquery`, `office365`, `github-api`
- **TLS/HTTPS** — optional; auto-generates self-signed cert with SAN, or supply your own
- **HTTP redirector** — transparent forwarding proxy with path/user-agent filtering and decoy responses
- **YAML configuration** — full config file system with profile overrides and sane defaults
- **Auto-recon** — configurable post-module queue on first beacon check-in
- **Operator situational awareness** — `ursa_sitrep` morning briefing, `ursa_session_recon` per-session findings view
- **Loot alerting** — automatic `CRITICAL`/`HIGH` finding events when loot modules complete
- **Session auto-tagging** — OS, arch, privilege, and cloud-cred tags applied from sysinfo results

### Governance & Audit
- **Step-up approvals** — high/critical-risk actions require explicit approval before queuing
- **Immutable audit chain** — HMAC-chained audit records with integrity verification
- **HMAC-signed decisions** — approval/rejection decisions are cryptographically signed
- **Policy matrix** — configurable risk tiers per task/action type
- **Campaign threshold alerts** — configurable limits on pending approval counts and age

### Campaign Management
- **Campaigns & tagging** — group sessions by operation; filter all tools by campaign/tag
- **Checklists & playbooks** — per-campaign operator checklists with due dates and owners; reusable playbook library
- **Timeline** — unified event/task/approval timeline per campaign
- **Notes** — operator notes attached to campaigns
- **Handoff reports** — briefing generator for shift/team handoffs (Markdown + JSON export)

### Web UI
- Session list, task history, file browser, event log
- Campaign dashboard, governance approvals, policy management
- Real-time updates via SSE
- Role-based access: `operator`, `reviewer`, `admin`

### Implants & Payloads
- **Python beacon** — full-featured, jitter sleep, UA rotation, sandbox/debugger detection, AMSI bypass
- **Go beacon** — compiled, cross-platform (linux/windows/darwin), no runtime dependencies
- **Zig template** — skeleton for Zig compilation target
- **Payload builder** — language-agnostic token substitution; post-build compile step for Go/Zig/C/etc.
- **Stager** — minimal first-stage dropper; downloads and executes beacon from `/stage`
- **Evasion** — sandbox/VM detection (14 checks), debugger detection, analysis tool detection, obfuscated sleep, process name spoofing

### Post-Exploitation (21 modules)
- **Enumeration** — sysinfo, users, privilege escalation checks, network config, loot
- **Credentials** — memory dumping, browser credentials, keychain/credential store harvesting, loot aggregation
- **Lateral movement** — WMI exec, SSH pivoting, pass-the-hash
- **Persistence** — registry run keys, cron jobs, launch agents/daemons

### Ursa Minor — Recon (16 tools)
- Network discovery, port scanning, packet capture, full recon
- Subdomain enumeration (CT logs + DNS brute-force)
- Web directory busting, vulnerability scanning (SQLi, XSS, CMDi, LFI, headers)
- Credential spraying (SSH, FTP, HTTP Basic Auth)
- OS fingerprinting, SMB enumeration, SNMP scanning
- Hash cracking/identification, reverse shell generation

### Infrastructure
- **842+ tests** — pytest suite covering all major components
- **GitHub Actions CI** — ruff lint, mypy type check, pytest on every push/PR

## Disclaimer

Ursa is intended for **authorized security testing, red team engagements, CTF competitions, and security research only**. Always obtain proper authorization before testing systems you do not own. Unauthorized access to computer systems is illegal.

## License

[MIT](LICENSE)
