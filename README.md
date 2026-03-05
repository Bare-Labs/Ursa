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
                        │ HTTP                        │ Raw sockets
                ┌───────▼───────┐            ┌────────▼───────┐
                │   Implants    │            │    Targets     │
                │   (beacon)    │            │  (scan/enum)   │
                └───────────────┘            └────────────────┘
```

## Components

| Component | Description | Docs |
|-----------|-------------|------|
| **[Ursa Major](major/)** | C2 server — manages implant sessions, task queuing, file transfer, encrypted comms | [major/README.md](major/README.md) |
| **[Ursa Minor](minor/)** | Recon toolkit — 16 network reconnaissance and vulnerability scanning tools | [minor/README.md](minor/README.md) |
| **[Implants](implants/)** | HTTP beacon and stager that run on target systems | [implants/README.md](implants/README.md) |

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

### Standalone Usage

Ursa Minor tools can also be run directly without MCP:

```bash
# Network discovery
sudo python3 minor/discover.py

# Port scan
sudo python3 minor/portscan.py 192.168.1.1

# Full recon
sudo python3 minor/recon.py
```

The C2 server can be started directly:

```bash
python3 major/server.py --port 8443
```

## Project Status

**Working today:**
- Full C2 server with session management, tasking, and encrypted comms
- 16 recon/scanning tools (network discovery, port scanning, vulnerability scanning, credential testing, subdomain enumeration, and more)
- HTTP beacon implant with 13 task types
- MCP integration for both components — agent-operable out of the box

**Planned — see [ROADMAP.md](ROADMAP.md):**
- Web UI for Ursa Major
- Testing and CI/CD
- Compiled implants (Go/Rust)
- Post-exploitation modules

## Disclaimer

Ursa is intended for **authorized security testing, red team engagements, CTF competitions, and security research only**. Always obtain proper authorization before testing systems you do not own. Unauthorized access to computer systems is illegal.

## License

[MIT](LICENSE)
