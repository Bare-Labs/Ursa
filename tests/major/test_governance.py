"""Tests for governance policy, approvals, and immutable audit events."""

from major.db import (
    create_session,
    get_approval_request,
    get_immutable_audit,
    list_approval_requests,
    resolve_approval_request,
    verify_immutable_audit_chain,
)
from major.governance import (
    process_approval_decision,
    process_bulk_approval_decisions,
    queue_task_with_policy,
)


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


def test_approved_request_can_queue_task(tmp_db, sample_session, monkeypatch):
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
    pending = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/loot.txt"},
        actor="test",
    )
    assert pending["status"] == "approval_required"
    approval_id = pending["approval_id"]

    assert resolve_approval_request(approval_id, approved=True, decided_by="test") is True
    assert get_approval_request(approval_id)["status"] == "approved"

    queued = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/loot.txt"},
        actor="test",
        approval_id=approval_id,
    )
    assert queued["status"] == "queued"
    assert queued["task_id"]


def test_invalid_approval_id_is_denied(tmp_db, sample_session, monkeypatch):
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
        args={"path": "/tmp/loot.txt"},
        actor="test",
        approval_id="NOPE1234",
    )
    assert result["status"] == "denied"
    assert "not found" in result["message"]


def test_process_approval_decision_approve_queues_task(tmp_db, sample_session, monkeypatch):
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
    pending = queue_task_with_policy(
        session_id=sample_session,
        task_type="download",
        args={"path": "/tmp/loot.txt"},
        actor="test",
    )
    result = process_approval_decision(
        approval_id=pending["approval_id"],
        approved=True,
        actor="test-bulk",
        note="ok",
    )
    assert result["status"] == "approved"
    assert result["queue_result"] == "queued"
    assert result["task_id"]


def test_process_bulk_approvals_campaign_filter(tmp_db, sample_session, monkeypatch):
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
    sid_campaign = create_session("10.0.0.99", campaign="ALPHA", tags="prod")
    sid_other = create_session("10.0.0.100", campaign="BETA", tags="lab")

    a1 = queue_task_with_policy(
        session_id=sid_campaign,
        task_type="download",
        args={"path": "/tmp/a.txt"},
        actor="test",
    )
    a2 = queue_task_with_policy(
        session_id=sid_other,
        task_type="download",
        args={"path": "/tmp/b.txt"},
        actor="test",
    )
    assert a1["status"] == "approval_required"
    assert a2["status"] == "approval_required"

    summary = process_bulk_approval_decisions(
        approved=False,
        actor="test-bulk",
        campaign="ALPHA",
        tag=None,
        note="campaign reject",
    )
    assert summary["matched"] == 1
    assert summary["rejected"] == 1
