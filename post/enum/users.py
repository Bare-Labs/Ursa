"""User and group enumeration.

Collects: current user identity, all local accounts, group memberships,
active sessions, recently logged-in users, and SSH authorised keys.

Platform: Linux, macOS (darwin).
"""

from __future__ import annotations

import grp
import os
import pwd
import subprocess

from post.base import ModuleResult, PostModule
from post.loader import register


def _run(cmd: str, timeout: int = 10) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return (r.stdout + r.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return f"[error: {exc}]"


def _current_user() -> dict:
    """Identity of the process owner."""
    uid = os.getuid()
    gid = os.getgid()
    try:
        entry = pwd.getpwuid(uid)
        username = entry.pw_name
        home = entry.pw_dir
        shell = entry.pw_shell
    except KeyError:
        username = str(uid)
        home = ""
        shell = ""

    groups = []
    for g in grp.getgrall():
        if username in g.gr_mem or g.gr_gid == gid:
            groups.append(g.gr_name)

    return {
        "uid": uid,
        "gid": gid,
        "username": username,
        "home": home,
        "shell": shell,
        "groups": groups,
        "is_root": uid == 0,
        "in_sudo_group": any(g in ("sudo", "wheel", "admin") for g in groups),
        "in_docker_group": "docker" in groups,
    }


def _all_local_users() -> list[dict]:
    """Parse /etc/passwd for all accounts with a valid shell."""
    users = []
    valid_shells = {"/bin/sh", "/bin/bash", "/bin/zsh", "/bin/fish",
                    "/bin/dash", "/usr/bin/bash", "/usr/bin/zsh"}
    try:
        for entry in pwd.getpwall():
            users.append({
                "username": entry.pw_name,
                "uid": entry.pw_uid,
                "gid": entry.pw_gid,
                "home": entry.pw_dir,
                "shell": entry.pw_shell,
                "has_login_shell": entry.pw_shell in valid_shells,
                "has_home": os.path.isdir(entry.pw_dir),
            })
    except Exception as exc:  # noqa: BLE001
        return [{"error": str(exc)}]
    return sorted(users, key=lambda u: u["uid"])


def _privileged_accounts(users: list[dict]) -> list[str]:
    """Return accounts that are root (uid 0) or have a login shell + home dir."""
    return [
        u["username"]
        for u in users
        if u.get("uid") == 0 or (u.get("has_login_shell") and u.get("has_home"))
    ]


def _active_sessions() -> str:
    """Currently logged-in users via `who`."""
    return _run("who 2>/dev/null || w 2>/dev/null | head -20")


def _recent_logins() -> str:
    """Recent login history via `last`."""
    return _run("last -n 20 2>/dev/null")


def _sudo_group_members() -> dict:
    """Members of the sudo/wheel/admin groups."""
    result = {}
    for gname in ("sudo", "wheel", "admin"):
        try:
            g = grp.getgrnam(gname)
            result[gname] = g.gr_mem
        except KeyError:
            pass
    return result


def _ssh_keys(users: list[dict]) -> list[dict]:
    """Discover SSH authorized_keys and private keys for each user."""
    found = []
    for u in users:
        home = u.get("home", "")
        if not home or not os.path.isdir(home):
            continue
        ssh_dir = os.path.join(home, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue

        entry: dict = {"username": u["username"], "files": []}
        for fname in ("authorized_keys", "id_rsa", "id_ecdsa", "id_ed25519",
                      "id_dsa", "known_hosts", "config"):
            fpath = os.path.join(ssh_dir, fname)
            if os.path.exists(fpath):
                readable = os.access(fpath, os.R_OK)
                entry["files"].append({
                    "path": fpath,
                    "readable": readable,
                    "is_private_key": fname.startswith("id_") and "pub" not in fname,
                })
        if entry["files"]:
            found.append(entry)
    return found


@register
class UsersModule(PostModule):
    NAME = "enum/users"
    DESCRIPTION = "User and group enumeration: identity, local accounts, sessions, SSH keys"
    PLATFORM = ["linux", "darwin"]

    def run(self, args: dict | None = None) -> ModuleResult:  # noqa: ARG002
        data: dict = {}
        lines: list[str] = []

        data["current_user"] = _current_user()
        u = data["current_user"]
        lines.append(
            f"Current user : {u['username']} (uid={u['uid']}, gid={u['gid']})"
        )
        lines.append(f"Groups       : {u['groups']}")
        if u["is_root"]:
            lines.append("[!] Running as root")
        if u["in_sudo_group"]:
            lines.append("[!] User is in sudo/wheel/admin group")
        if u["in_docker_group"]:
            lines.append("[!] User is in the docker group (root-equivalent)")

        data["all_users"] = _all_local_users()
        data["privileged_accounts"] = _privileged_accounts(data["all_users"])
        lines.append(
            f"Local accounts: {len(data['all_users'])} total, "
            f"privileged: {data['privileged_accounts']}"
        )

        data["sudo_groups"] = _sudo_group_members()
        if data["sudo_groups"]:
            lines.append(f"Sudo group members: {data['sudo_groups']}")

        data["active_sessions"] = _active_sessions()
        lines.append(f"Active sessions:\n{data['active_sessions']}")

        data["recent_logins"] = _recent_logins()

        data["ssh_keys"] = _ssh_keys(data["all_users"])
        readable_priv_keys = [
            f["path"]
            for entry in data["ssh_keys"]
            for f in entry["files"]
            if f["is_private_key"] and f["readable"]
        ]
        if readable_priv_keys:
            lines.append(f"[!] Readable private SSH keys: {readable_priv_keys}")

        return ModuleResult(ok=True, output="\n".join(lines), data=data)
