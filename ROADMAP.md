# Ursa Roadmap

## Vision

Ursa is an AI-native red team toolkit where AI agents and human operators work side by side. The agent handles reconnaissance, automates repetitive tasks, and manages C2 operations through natural conversation, while the human provides judgment, authorization, and strategic direction.

The long-term goal is a complete offensive security platform:
- **Ursa Minor** handles all reconnaissance and scanning
- **Ursa Major** manages command and control with both a **web UI** (for humans) and an **MCP interface** (for agents)
- **Implants** cover multiple platforms and evasion techniques
- **Post-exploitation modules** handle privilege escalation, lateral movement, and persistence

## Current State

What works today:
- 16 recon/scanning tools in Ursa Minor (all MCP-accessible)
- Full C2 server with encrypted comms, session management, and task queuing
- HTTP beacon implant with 13 task types
- Stager generation for initial delivery
- MCP integration for both components

## Gaps

### Infrastructure
- **No tests** — needs a pytest suite covering both Major and Minor
- **No CI/CD** — needs GitHub Actions for linting (ruff), type checking (mypy), and testing
- **No unified package config** — Minor has a `pyproject.toml`, Major and root don't
- **No configuration system** — everything is CLI flags or hardcoded

### Ursa Major
- **No web UI** — the primary gap; needs a dashboard for human operators to manage sessions, view results, and issue tasks without the MCP/agent layer
- **No TLS** — C2 server runs plain HTTP (relies on external reverse proxy for HTTPS)
- **Single listener** — only HTTP; no DNS, SMB, or other covert channels
- **No session grouping/tagging** — flat session list, no campaign organization
- **No persistent config** — no config file, all runtime flags

### Ursa Minor
- **ARP spoof not MCP-exposed** — `arpspoof.py` exists but isn't available through MCP (intentional for safety, but should be reconsidered)
- **No output persistence** — scan results only returned to the agent, not saved to disk
- **No scan scheduling** — no recurring or timed scans
- **No report generation** — no export to HTML/PDF for deliverables

### Implants
- **Python-only** — no compiled payloads (Go, Rust, C) for stealth and portability
- **Empty templates directory** — no payload template/builder system
- **No persistence mechanisms** — beacon doesn't survive reboots
- **No evasion/obfuscation** — no process injection, AMSI bypass, or code obfuscation
- **No lateral movement** — can't spread to other hosts from a compromised system

### Cross-Cutting
- **No authentication on MCP servers** — anyone who can reach them can use them
- **Empty `payloads/` directory** — reserved but unused
- **Empty `post/` directory** — no post-exploitation modules exist yet

## Roadmap

### Phase 1: Testing & CI
- Add pytest suite for Ursa Major (server, database, crypto)
- Add pytest suite for Ursa Minor (tool output parsing, mock scanning)
- Set up GitHub Actions: ruff, mypy, pytest
- Add root `pyproject.toml` to unify the project

### Phase 2: Ursa Major Web UI
- FastAPI backend wrapping the existing C2 database/server
- Web dashboard: session list, task history, file browser, event log
- Real-time updates (WebSocket or SSE) for new sessions and task results
- Dark theme, responsive — usable on a second monitor during engagements

### Phase 3: Configuration & Polish
- YAML/TOML config file system for both Major and Minor
- Operator profiles (saved connection settings, preferences)
- Scan result persistence and export (JSON, CSV, HTML reports)
- Expose ARP spoof through MCP with appropriate safeguards

### Phase 4: Expanded Implants
- Go implant (compiled, cross-platform)
- Payload builder/template system
- Basic evasion (string obfuscation, sleep timers, sandbox detection)
- Persistence mechanisms (cron, registry, launch agents)

### Phase 5: Post-Exploitation
- Privilege escalation checkers
- Lateral movement modules (pass-the-hash, WMI, SSH pivoting)
- Credential harvesting (browser, keychain, memory)
- Populate `post/` directory with modules

### Phase 6: Advanced C2
- Multiple listener types (HTTPS, DNS tunneling, SMB pipes)
- Session grouping and campaign management
- Redirector/proxy chain support
- Traffic profiles (malleable C2 concept)
