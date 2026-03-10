# Ursa Roadmap

> **Note:** This file is internal and will be removed from the public repository. Feature documentation lives in [README.md](README.md) and the component READMEs.

## Vision

Ursa is an AI-native red team toolkit where AI agents and human operators work side by side. The agent handles reconnaissance, automates repetitive tasks, and manages C2 operations through natural conversation, while the human provides judgment, authorization, and strategic direction.

- **Ursa Minor** handles all reconnaissance and scanning
- **Ursa Major** manages command and control with both a **web UI** (for humans) and an **MCP interface** (for agents)
- **Implants** cover multiple platforms and evasion techniques
- **Post-exploitation modules** handle privilege escalation, lateral movement, and persistence

## Current State (as of March 2026)

All six roadmap phases are complete. See [README.md](README.md) for the full feature list.

### Phase 1: Testing & CI ✅
- pytest suite covering Major, Minor, builder, post-exploitation, evasion (842+ tests)
- GitHub Actions CI: ruff lint, mypy type check, pytest on push/PR

### Phase 2: Ursa Major Web UI ✅
- FastAPI web app (`major/web/`) with auth and role-based access (operator/reviewer/admin)
- Dashboard: session list, task history, file browser, event log, campaign management, governance
- Real-time updates via SSE
- Bootstrap admin account from config

### Phase 3: Configuration & Polish ✅
- YAML config system (`major/config.py`) with dotted-path access and profile overrides
- Traffic profiles: `default`, `jquery`, `office365`, `github-api` (malleable C2)
- HTTP redirector: transparent forwarding proxy with path/UA filtering
- TLS/HTTPS: auto-generated self-signed cert with SAN support, or bring your own

### Phase 4: Expanded Implants ✅
- Go beacon (`implants/templates/http_go.go`) — compiled, cross-platform, no runtime deps
- Zig template (`implants/templates/http_zig.zig`) — skeleton for Zig compilation target
- Payload builder (`implants/builder.py`) — language-agnostic token substitution + post-build compile step
- Evasion (`implants/evasion.py`) — sandbox/VM detection, debugger detection, AMSI bypass, obfuscated sleep, process spoofing
- Persistence mechanisms via post-exploitation modules

### Phase 5: Post-Exploitation ✅
- 21 modules across 4 categories: enumeration, credentials, lateral movement, persistence
- Structured findings format with CRITICAL/HIGH/MEDIUM/LOW severity levels
- Auto-recon: configurable module queue on first beacon check-in
- Loot alerting: automatic warning/info events for CRITICAL/HIGH findings
- Session auto-tagging: OS, arch, privilege, and cloud-cred tags from sysinfo results
- Operator tools: `ursa_sitrep` (morning briefing), `ursa_session_recon` (per-session findings)

### Phase 6: Advanced C2 ✅
- Traffic profiles with URL remapping, custom headers, and UA filtering
- HTTPS with cert auto-generation
- HTTP redirector/proxy chain support
- Campaign management, checklists, playbooks, handoffs, timelines
- Governance: step-up approvals, immutable audit chain, HMAC-signed decisions, policy matrix

## What's Genuinely Next

The core roadmap is complete. Honest remaining gaps:

- **DNS/SMB listeners** — `major/listeners/dns.py` and `smb.py` exist as stubs; neither is a functional listener yet
- **Zig beacon implementation** — `http_zig.zig` is a buildable skeleton; all task handlers need implementing
- **Web UI tests** — `major/web/` has no test coverage
- **CI improvements** — currently installs via `requirements.txt`; could migrate to poetry, add coverage reporting, matrix builds
- **Ursa Minor: scan result persistence** — results returned to agent only, not saved to disk
- **Ursa Minor: report generation** — no export to HTML/PDF for deliverables
