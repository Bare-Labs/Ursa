"""Tests for governance policy, approvals, and immutable audit events."""

from major.db import (
    get_immutable_audit,
    list_approval_requests,
    verify_immutable_audit_chain,
)
from major.governance import queue_task_with_policy


class _Cfg:
    def __init__(self, values):
        self._values = values

    def get(self, path, default=None):
        return self._values.get(path, default)


def test_queue_task_without_step_up(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": False,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )

    result = queue_task_with_policy(
        session_id=sample_session,
        task_type="whoami",
        args={},
        actor="test",
    )
    assert result["status"] == "queued"
    assert result["task_id"]

    audit_rows = get_immutable_audit(limit=10)
    assert audit_rows
    assert audit_rows[0]["policy_result"] == "allow"
    assert verify_immutable_audit_chain()["ok"] is True


def test_high_risk_requires_approval_when_enabled(tmp_db, sample_session, monkeypatch):
    monkeypatch.setattr(
        "major.governance.get_config",
        lambda: _Cfg(
            {
                "major.governance": {
                    "bearclaw_mode": "local",
                    "require_step_up_approval": True,
                    "step_up_risks": ["high", "critical"],
                }
            }
        ),
    )

    result = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/etc/shadow"},
        actor="test",
    )
    assert result["status"] == "approval_required"
    assert result["approval_id"]

    approvals = list_approval_requests(status="pending", limit=10)
    assert any(r["id"] == result["approval_id"] for r in approvals)
    assert verify_immutable_audit_chain()["ok"] is True
