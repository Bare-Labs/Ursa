"""Ursa Major governance and policy enforcement helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from major.config import get_config
from major.db import append_immutable_audit_event, create_approval_request, create_task

RISK_MATRIX: dict[str, str] = {
    "sysinfo": "low",
    "pwd": "low",
    "whoami": "low",
    "env": "low",
    "ls": "medium",
    "ps": "medium",
    "cd": "medium",
    "download": "high",
    "upload": "high",
    "sleep": "medium",
    "shell": "high",
    "kill": "critical",
}

SHELL_HIGH_RISK_TOKENS = {
    "rm -rf",
    "chmod 777",
    "chown ",
    "net user",
    "reg add",
    "powershell -enc",
    "nc -e",
    "curl ",
    "wget ",
}

SHELL_CRITICAL_TOKENS = {
    "vssadmin delete shadows",
    "bcdedit ",
    "diskpart",
    "cipher /w",
}


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    risk_level: str
    policy_result: str
    reason: str
    policy_path: str = "bearclaw/local"


def _classify_shell_risk(command: str) -> str:
    cmd = command.lower().strip()
    if any(token in cmd for token in SHELL_CRITICAL_TOKENS):
        return "critical"
    if any(token in cmd for token in SHELL_HIGH_RISK_TOKENS):
        return "high"
    if len(cmd) > 140:
        return "high"
    return "medium"


def classify_task_risk(task_type: str, args: dict[str, Any] | None = None) -> str:
    task = (task_type or "").strip().lower()
    args = args or {}
    if task == "shell":
        return _classify_shell_risk(str(args.get("command", "")))
    return RISK_MATRIX.get(task, "high")


def enforce_bearclaw_policy(
    *,
    action: str,
    task_type: str,
    args: dict[str, Any] | None,
    actor: str,
    approval_id: str | None = None,
) -> PolicyDecision:
    """Policy decision point aligned to the BearClaw path."""
    cfg = get_config()
    governance = cfg.get("major.governance", {}) or {}
    risk_level = classify_task_risk(task_type, args)
    step_up_enabled = bool(governance.get("require_step_up_approval", False))
    step_up_risks = set(governance.get("step_up_risks", ["high", "critical"]))
    mode = governance.get("bearclaw_mode", "local")

    if mode == "disabled":
        return PolicyDecision(
            allowed=True,
            requires_approval=False,
            risk_level=risk_level,
            policy_result="allow",
            reason="BearClaw governance disabled by configuration.",
            policy_path="bearclaw/disabled",
        )

    if step_up_enabled and risk_level in step_up_risks and not approval_id:
        return PolicyDecision(
            allowed=False,
            requires_approval=True,
            risk_level=risk_level,
            policy_result="step_up_required",
            reason=f"Step-up approval is required for {risk_level}-risk action.",
        )

    return PolicyDecision(
        allowed=True,
        requires_approval=False,
        risk_level=risk_level,
        policy_result="allow",
        reason=f"Allowed by BearClaw local policy ({risk_level} risk).",
    )


def queue_task_with_policy(
    *,
    session_id: str,
    task_type: str,
    args: dict[str, Any] | None = None,
    actor: str = "operator",
    approval_id: str | None = None,
) -> dict[str, Any]:
    """Enqueue a task through governance controls and immutable auditing."""
    task_args = args or {}
    decision = enforce_bearclaw_policy(
        action="queue_task",
        task_type=task_type,
        args=task_args,
        actor=actor,
        approval_id=approval_id,
    )

    audit_details = {
        "task_type": task_type,
        "args": task_args,
        "reason": decision.reason,
        "policy_path": decision.policy_path,
    }

    if decision.requires_approval:
        approval_id = create_approval_request(
            action="queue_task",
            risk_level=decision.risk_level,
            session_id=session_id,
            task_type=task_type,
            args=task_args,
            requested_by=actor,
            reason=decision.reason,
        )
        append_immutable_audit_event(
            actor=actor,
            action="queue_task",
            session_id=session_id,
            approval_id=approval_id,
            risk_level=decision.risk_level,
            policy_result=decision.policy_result,
            details={
                **audit_details,
                "approval_id": approval_id,
                "status": "awaiting_approval",
            },
        )
        return {
            "status": "approval_required",
            "approval_id": approval_id,
            "risk_level": decision.risk_level,
            "message": decision.reason,
        }

    task_id = create_task(session_id, task_type, task_args)
    append_immutable_audit_event(
        actor=actor,
        action="queue_task",
        session_id=session_id,
        task_id=task_id,
        approval_id=approval_id,
        risk_level=decision.risk_level,
        policy_result=decision.policy_result,
        details={**audit_details, "task_id": task_id},
    )
    return {
        "status": "queued",
        "task_id": task_id,
        "risk_level": decision.risk_level,
        "message": decision.reason,
    }


def format_risk_matrix() -> str:
    """Text table of policy risk mapping for operator visibility."""
    rows = ["TASK TYPE      RISK", "-------------------"]
    for task_type in sorted(RISK_MATRIX):
        rows.append(f"{task_type:<13} {RISK_MATRIX[task_type]}")
    rows.append("shell         command-dependent (medium/high/critical)")
    return "\n".join(rows)


def normalize_args_string(args: str) -> dict[str, Any]:
    """Parse JSON args string from MCP tools."""
    try:
        parsed = json.loads(args) if isinstance(args, str) else args
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON args: {args}") from exc
    return parsed if isinstance(parsed, dict) else {}
