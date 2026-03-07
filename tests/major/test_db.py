"""Tests for the Ursa Major database layer."""

import json
import time

from major import db


class TestSessions:

    def test_create_returns_8char_id(self, tmp_db):
        sid = db.create_session("10.0.0.1", hostname="BOX1")
        assert isinstance(sid, str)
        assert len(sid) == 8

    def test_get_session_all_fields(self, tmp_db):
        sid = db.create_session(
            "10.0.0.1",
            hostname="BOX1",
            username="admin",
            os_info="Linux",
            arch="x64",
            pid=99,
            process_name="bash",
            encryption_key="abc123",
            beacon_interval=10,
            jitter=0.2,
        )
        s = db.get_session(sid)
        assert s["remote_ip"] == "10.0.0.1"
        assert s["hostname"] == "BOX1"
        assert s["username"] == "admin"
        assert s["os"] == "Linux"
        assert s["status"] == "active"
        assert s["beacon_interval"] == 10

    def test_get_nonexistent_returns_none(self, tmp_db):
        assert db.get_session("NOPE1234") is None

    def test_update_checkin_updates_last_seen(self, tmp_db, sample_session):
        before = db.get_session(sample_session)["last_seen"]
        time.sleep(0.05)
        db.update_session_checkin(sample_session)
        after = db.get_session(sample_session)["last_seen"]
        assert after > before

    def test_update_checkin_with_new_ip(self, tmp_db, sample_session):
        db.update_session_checkin(sample_session, remote_ip="10.0.0.99")
        assert db.get_session(sample_session)["remote_ip"] == "10.0.0.99"

    def test_list_sessions_all(self, tmp_db):
        db.create_session("10.0.0.1")
        db.create_session("10.0.0.2")
        assert len(db.list_sessions()) == 2

    def test_list_sessions_by_status(self, tmp_db, sample_session):
        db.kill_session(sample_session)
        assert len(db.list_sessions(status="dead")) == 1
        assert len(db.list_sessions(status="active")) == 0

    def test_list_sessions_by_campaign(self, tmp_db):
        s1 = db.create_session("10.0.0.1", campaign="ALPHA")
        _ = db.create_session("10.0.0.2", campaign="BETA")
        rows = db.list_sessions(campaign="ALPHA")
        assert len(rows) == 1
        assert rows[0]["id"] == s1

    def test_list_sessions_by_tag(self, tmp_db):
        s1 = db.create_session("10.0.0.1", tags="finance,dc1")
        _ = db.create_session("10.0.0.2", tags="eng,linux")
        rows = db.list_sessions(tag="finance")
        assert len(rows) == 1
        assert rows[0]["id"] == s1

    def test_kill_session(self, tmp_db, sample_session):
        db.kill_session(sample_session)
        assert db.get_session(sample_session)["status"] == "dead"

    def test_update_session_info(self, tmp_db, sample_session):
        db.update_session_info(
            sample_session,
            hostname="NEWBOX",
            status="stale",
            campaign="OP-SNOW",
            tags="corp,dc",
        )
        s = db.get_session(sample_session)
        assert s["hostname"] == "NEWBOX"
        assert s["status"] == "stale"
        assert s["campaign"] == "OP-SNOW"
        assert s["tags"] == "corp,dc"

    def test_update_session_info_filters_disallowed_fields(self, tmp_db, sample_session):
        db.update_session_info(sample_session, id="HIJACKED", remote_ip="evil")
        s = db.get_session(sample_session)
        assert s["id"] == sample_session
        assert s["remote_ip"] == "10.0.0.42"


class TestTasks:

    def test_create_task(self, tmp_db, sample_session):
        tid = db.create_task(sample_session, "shell", {"command": "whoami"})
        assert isinstance(tid, str)
        assert len(tid) == 8

    def test_get_task(self, tmp_db, sample_session):
        tid = db.create_task(sample_session, "shell", {"command": "id"})
        t = db.get_task(tid)
        assert t["task_type"] == "shell"
        assert t["status"] == "pending"
        assert json.loads(t["args"]) == {"command": "id"}

    def test_get_pending_marks_in_progress(self, tmp_db, sample_session):
        t1 = db.create_task(sample_session, "shell", {"command": "ls"})
        t2 = db.create_task(sample_session, "whoami")
        pending = db.get_pending_tasks(sample_session)
        assert len(pending) == 2
        # Should now be in_progress
        assert db.get_task(t1)["status"] == "in_progress"
        assert db.get_task(t2)["status"] == "in_progress"
        # Second call returns empty
        assert db.get_pending_tasks(sample_session) == []

    def test_complete_task_success(self, tmp_db, sample_session):
        tid = db.create_task(sample_session, "shell")
        db.complete_task(tid, result="root")
        t = db.get_task(tid)
        assert t["status"] == "completed"
        assert t["result"] == "root"
        assert t["completed_at"] is not None

    def test_complete_task_error(self, tmp_db, sample_session):
        tid = db.create_task(sample_session, "shell")
        db.complete_task(tid, error="command not found")
        t = db.get_task(tid)
        assert t["status"] == "error"
        assert t["error"] == "command not found"

    def test_list_tasks_filtered(self, tmp_db, sample_session):
        sid2 = db.create_session("10.0.0.2")
        db.create_task(sample_session, "shell")
        db.create_task(sid2, "whoami")
        assert len(db.list_tasks(session_id=sample_session)) == 1
        assert len(db.list_tasks()) == 2

    def test_list_tasks_by_campaign(self, tmp_db):
        sid1 = db.create_session("10.0.0.1", campaign="ALPHA")
        sid2 = db.create_session("10.0.0.2", campaign="BETA")
        db.create_task(sid1, "shell")
        db.create_task(sid2, "whoami")
        rows = db.list_tasks(campaign="ALPHA", limit=20)
        assert len(rows) == 1
        assert rows[0]["session_id"] == sid1

    def test_list_tasks_by_tag(self, tmp_db):
        sid1 = db.create_session("10.0.0.1", tags="finance,dc1")
        sid2 = db.create_session("10.0.0.2", tags="eng,linux")
        db.create_task(sid1, "shell")
        db.create_task(sid2, "whoami")
        rows = db.list_tasks(tag="finance", limit=20)
        assert len(rows) == 1
        assert rows[0]["session_id"] == sid1


class TestFiles:

    def test_store_and_retrieve(self, tmp_db, sample_session):
        data = b"secret file contents"
        fid = db.store_file(sample_session, "passwords.txt", data)
        f = db.get_file(fid)
        assert f["filename"] == "passwords.txt"
        assert f["data"] == data
        assert f["size"] == len(data)
        assert f["direction"] == "download"

    def test_list_files(self, tmp_db, sample_session):
        db.store_file(sample_session, "a.txt", b"aaa")
        db.store_file(sample_session, "b.txt", b"bbb", direction="upload")
        assert len(db.list_files(session_id=sample_session)) == 2

    def test_get_nonexistent_file(self, tmp_db):
        assert db.get_file("NOPE") is None


class TestListeners:

    def test_create_listener(self, tmp_db):
        lid = db.create_listener("http-main", 8443)
        listener = db.get_listener(listener_id=lid)
        assert listener["name"] == "http-main"
        assert listener["bind_port"] == 8443

    def test_get_listener_by_name(self, tmp_db):
        db.create_listener("https-alt", 9443)
        listener = db.get_listener(name="https-alt")
        assert listener is not None
        assert listener["bind_port"] == 9443

    def test_update_listener_status(self, tmp_db):
        lid = db.create_listener("test-listener", 7777)
        db.update_listener_status(lid, "running")
        assert db.get_listener(listener_id=lid)["status"] == "running"

    def test_list_listeners(self, tmp_db):
        db.create_listener("l1", 1111)
        db.create_listener("l2", 2222)
        assert len(db.list_listeners()) == 2


class TestEvents:

    def test_log_and_retrieve(self, tmp_db):
        db.log_event("warning", "test", "something happened", details={"key": "val"})
        events = db.get_events(limit=10)
        assert len(events) >= 1
        e = events[0]
        assert e["level"] == "warning"
        assert e["source"] == "test"
        assert "something happened" in e["message"]

    def test_filter_by_level(self, tmp_db):
        db.log_event("info", "a", "info msg")
        db.log_event("error", "b", "error msg")
        errors = db.get_events(level="error")
        assert all(e["level"] == "error" for e in errors)

    def test_filter_by_session(self, tmp_db, sample_session):
        db.log_event("info", "test", "session event", session_id=sample_session)
        events = db.get_events(session_id=sample_session)
        assert len(events) >= 1
        assert all(e["session_id"] == sample_session for e in events)

    def test_filter_events_by_campaign(self, tmp_db):
        sid1 = db.create_session("10.0.0.1", campaign="ALPHA")
        sid2 = db.create_session("10.0.0.2", campaign="BETA")
        db.log_event("info", "test", "alpha event", session_id=sid1)
        db.log_event("info", "test", "beta event", session_id=sid2)
        events = db.get_events(campaign="ALPHA", limit=20)
        assert any(e["session_id"] == sid1 and e["message"] == "alpha event" for e in events)
        assert all(e.get("campaign") == "ALPHA" for e in events)

    def test_filter_events_by_tag(self, tmp_db):
        sid1 = db.create_session("10.0.0.1", tags="prod,dc1")
        sid2 = db.create_session("10.0.0.2", tags="lab,dev")
        db.log_event("info", "test", "prod event", session_id=sid1)
        db.log_event("info", "test", "lab event", session_id=sid2)
        events = db.get_events(tag="prod", limit=20)
        assert any(e["session_id"] == sid1 and e["message"] == "prod event" for e in events)
        assert all("prod" in (e.get("session_tags") or "") for e in events)


class TestApprovals:

    def test_list_approvals_by_campaign(self, tmp_db):
        sid1 = db.create_session("10.0.0.1", campaign="ALPHA")
        sid2 = db.create_session("10.0.0.2", campaign="BETA")
        db.create_approval_request("queue_task", "high", session_id=sid1, task_type="download")
        db.create_approval_request("queue_task", "high", session_id=sid2, task_type="download")
        rows = db.list_approval_requests(status="pending", campaign="ALPHA", limit=20)
        assert len(rows) == 1
        assert rows[0]["session_id"] == sid1
        assert rows[0]["campaign"] == "ALPHA"

    def test_list_approvals_by_tag(self, tmp_db):
        sid1 = db.create_session("10.0.0.1", tags="prod,dc1")
        sid2 = db.create_session("10.0.0.2", tags="lab,dev")
        db.create_approval_request("queue_task", "high", session_id=sid1, task_type="download")
        db.create_approval_request("queue_task", "high", session_id=sid2, task_type="download")
        rows = db.list_approval_requests(status="pending", tag="prod", limit=20)
        assert len(rows) == 1
        assert rows[0]["session_id"] == sid1
        assert "prod" in (rows[0]["session_tags"] or "")

    def test_list_approvals_by_risk_level(self, tmp_db):
        sid = db.create_session("10.0.0.1", campaign="ALPHA")
        _ = db.create_approval_request("queue_task", "high", session_id=sid, task_type="download")
        _ = db.create_approval_request("queue_task", "critical", session_id=sid, task_type="kill")
        rows = db.list_approval_requests(status="pending", risk_level="critical", limit=20)
        assert len(rows) == 1
        assert rows[0]["risk_level"] == "critical"


class TestCampaignPolicies:

    def test_upsert_and_get_campaign_policy(self, tmp_db):
        p = db.upsert_campaign_policy(
            campaign="ALPHA",
            max_pending_total=5,
            max_pending_high=3,
            max_pending_critical=1,
            max_oldest_pending_minutes=15,
            updated_by="test",
            note="policy test",
        )
        assert p["campaign"] == "ALPHA"
        assert p["max_pending_total"] == 5
        assert p["max_oldest_pending_minutes"] == 15
        fetched = db.get_campaign_policy("ALPHA")
        assert fetched is not None
        assert fetched["max_pending_high"] == 3

    def test_evaluate_campaign_policy_alerts(self, tmp_db):
        sid = db.create_session("10.0.0.1", campaign="ALPHA")
        db.upsert_campaign_policy(
            campaign="ALPHA",
            max_pending_total=1,
            max_pending_high=0,
            max_pending_critical=0,
            updated_by="test",
        )
        db.create_approval_request("queue_task", "high", session_id=sid, task_type="download")
        db.create_approval_request("queue_task", "critical", session_id=sid, task_type="kill")
        alerts = db.evaluate_campaign_policy_alerts(campaign="ALPHA")
        assert len(alerts) >= 2
        assert any(a["metric"] == "total" for a in alerts)
        assert any(a["metric"] == "critical" for a in alerts)

    def test_evaluate_campaign_policy_alerts_oldest_age(self, tmp_db):
        sid = db.create_session("10.0.0.1", campaign="ALPHA")
        db.upsert_campaign_policy(
            campaign="ALPHA",
            max_pending_total=100,
            max_pending_high=100,
            max_pending_critical=100,
            max_oldest_pending_minutes=1,
            updated_by="test",
        )
        approval_id = db.create_approval_request("queue_task", "high", session_id=sid, task_type="download")
        conn = db.get_db()
        conn.execute(
            "UPDATE approval_requests SET created_at=? WHERE id=?",
            (time.time() - 180, approval_id),
        )
        conn.commit()
        conn.close()
        alerts = db.evaluate_campaign_policy_alerts(campaign="ALPHA")
        assert any(a["metric"] == "oldest_age_minutes" for a in alerts)

    def test_delete_campaign_policy(self, tmp_db):
        db.upsert_campaign_policy(campaign="ALPHA", updated_by="test")
        assert db.get_campaign_policy("ALPHA") is not None
        assert db.delete_campaign_policy("ALPHA") is True
        assert db.get_campaign_policy("ALPHA") is None


class TestCampaignTimeline:

    def test_get_campaign_timeline_includes_events_tasks_approvals(self, tmp_db):
        sid = db.create_session("10.0.0.1", campaign="ALPHA")
        task_id = db.create_task(sid, "whoami")
        approval_id = db.create_approval_request("queue_task", "high", session_id=sid, task_type="download")
        db.log_event("info", "test", "timeline event", session_id=sid)
        db.add_campaign_note("ALPHA", "timeline note", author="tester")

        rows = db.get_campaign_timeline("ALPHA", limit=50)
        kinds = {r["kind"] for r in rows}
        assert "task" in kinds
        assert "approval" in kinds
        assert "event" in kinds
        assert "note" in kinds
        assert any(r["ref_id"] == task_id for r in rows)
        assert any(r["ref_id"] == approval_id for r in rows)

    def test_get_campaign_timeline_includes_checklist_history(self, tmp_db):
        item_id = db.add_campaign_checklist_item("ALPHA", "prep infra", owner="ops")
        db.update_campaign_checklist_item(item_id, status="in_progress")
        rows = db.get_campaign_timeline("ALPHA", limit=50)
        assert any(r["kind"] == "checklist" for r in rows)
        assert any(r["kind"] == "checklist" and r["ref_id"] == str(item_id) for r in rows)


class TestCampaignNotes:

    def test_add_and_list_campaign_notes(self, tmp_db):
        db.add_campaign_note("ALPHA", "first note", author="tester")
        db.add_campaign_note("ALPHA", "second note", author="tester")
        notes = db.list_campaign_notes(campaign="ALPHA", limit=10)
        assert len(notes) == 2
        assert notes[0]["note"] == "second note"
        assert notes[1]["note"] == "first note"

    def test_delete_campaign_note(self, tmp_db):
        db.add_campaign_note("ALPHA", "delete me", author="tester")
        notes = db.list_campaign_notes(campaign="ALPHA", limit=10)
        note_id = notes[0]["id"]
        assert db.delete_campaign_note(note_id) is True
        notes_after = db.list_campaign_notes(campaign="ALPHA", limit=10)
        assert all(n["id"] != note_id for n in notes_after)


class TestCampaignChecklist:

    def test_add_and_list_checklist_items(self, tmp_db):
        db.add_campaign_checklist_item("ALPHA", "prep infra", details="terraform", owner="alice")
        db.add_campaign_checklist_item("ALPHA", "run validation", owner="bob")
        rows = db.list_campaign_checklist(campaign="ALPHA", limit=10)
        assert len(rows) == 2
        assert rows[0]["title"] == "run validation"
        assert rows[1]["title"] == "prep infra"
        assert rows[1]["details"] == "terraform"

    def test_filter_checklist_by_status(self, tmp_db):
        item_id = db.add_campaign_checklist_item("ALPHA", "stage payload")
        db.add_campaign_checklist_item("ALPHA", "schedule op")
        assert db.update_campaign_checklist_item(item_id, status="done") is True
        rows = db.list_campaign_checklist(campaign="ALPHA", status="done", limit=10)
        assert len(rows) == 1
        assert rows[0]["id"] == item_id

    def test_filter_checklist_by_owner_and_text(self, tmp_db):
        db.add_campaign_checklist_item("ALPHA", "prep phishing infra", details="sendgrid tenant", owner="alice")
        db.add_campaign_checklist_item("ALPHA", "credential staging", details="hashcat", owner="bob")
        rows = db.list_campaign_checklist(campaign="ALPHA", owner="alice", text="sendgrid", limit=10)
        assert len(rows) == 1
        assert rows[0]["owner"] == "alice"
        assert "sendgrid" in rows[0]["details"]

    def test_update_and_delete_checklist_item(self, tmp_db):
        item_id = db.add_campaign_checklist_item("ALPHA", "collect creds")
        assert db.update_campaign_checklist_item(
            item_id,
            title="collect credentials",
            owner="charlie",
            details="domain admin first",
            due_at=time.time() + 600,
            status="in_progress",
        )
        rows = db.list_campaign_checklist(campaign="ALPHA", limit=10)
        assert rows[0]["title"] == "collect credentials"
        assert rows[0]["owner"] == "charlie"
        assert rows[0]["status"] == "in_progress"
        assert db.delete_campaign_checklist_item(item_id) is True
        rows_after = db.list_campaign_checklist(campaign="ALPHA", limit=10)
        assert rows_after == []

    def test_checklist_history_records_changes_and_delete(self, tmp_db):
        item_id = db.add_campaign_checklist_item("ALPHA", "escalate privileges")
        db.update_campaign_checklist_item(item_id, status="done")
        db.delete_campaign_checklist_item(item_id)
        history = db.list_campaign_checklist_history("ALPHA", limit=10)
        actions = [row["action"] for row in history]
        assert "created" in actions
        assert "status_changed" in actions
        assert "deleted" in actions

    def test_checklist_history_can_filter_by_action(self, tmp_db):
        item_id = db.add_campaign_checklist_item("ALPHA", "validate creds")
        db.update_campaign_checklist_item(item_id, status="in_progress")
        status_events = db.list_campaign_checklist_history("ALPHA", action="status_changed", limit=10)
        assert any(e["action"] == "status_changed" for e in status_events)


class TestCampaignPlaybooks:

    def test_upsert_and_list_playbooks(self, tmp_db):
        row = db.upsert_campaign_playbook(
            "initial-access",
            items=["recon host", {"title": "collect creds", "details": "lsass dump", "due_offset_days": 1}],
            description="initial foothold flow",
        )
        assert row["name"] == "initial-access"
        assert len(row["items"]) == 2
        rows = db.list_campaign_playbooks(limit=10)
        names = {r["name"] for r in rows}
        assert "initial-access" in names

    def test_apply_playbook_creates_items_and_skips_existing(self, tmp_db):
        db.upsert_campaign_playbook(
            "lateral",
            items=[
                {"title": "enumerate trusts", "owner": "alice", "due_offset_days": 0},
                {"title": "pivot smb", "due_offset_days": 2},
            ],
            description="",
        )
        first = db.apply_campaign_playbook("ALPHA", "lateral", default_owner="team", due_base=time.time())
        assert first["created"] == 2
        second = db.apply_campaign_playbook("ALPHA", "lateral", default_owner="team", due_base=time.time())
        assert second["created"] == 0
        assert second["skipped"] == 2
        rows = db.list_campaign_checklist(campaign="ALPHA", limit=10)
        assert len(rows) == 2
        assert any(r["owner"] == "alice" for r in rows)
        assert any(r["owner"] == "team" for r in rows)

    def test_delete_playbook(self, tmp_db):
        db.upsert_campaign_playbook("cleanup", items=["remove artifacts"], description="")
        assert db.delete_campaign_playbook("cleanup") is True
        assert db.get_campaign_playbook("cleanup") is None

    def test_snapshot_campaign_checklist_to_playbook(self, tmp_db):
        db.add_campaign_checklist_item("ALPHA", "item one", details="a", owner="ops1")
        item_two = db.add_campaign_checklist_item("ALPHA", "item two", details="b", owner="ops2")
        db.update_campaign_checklist_item(item_two, status="done")
        row = db.snapshot_campaign_checklist_to_playbook(
            campaign="ALPHA",
            playbook_name="alpha-open-snapshot",
            only_open=True,
        )
        assert row["name"] == "alpha-open-snapshot"
        assert len(row["items"]) == 1
        assert row["items"][0]["title"] == "item one"


class TestUsers:

    def test_bootstrap_admin_exists(self, tmp_db):
        users = db.list_users(limit=20)
        assert any(u["username"] == "admin" and u["role"] == "admin" for u in users)

    def test_create_and_authenticate_user(self, tmp_db):
        created = db.create_user("alice", "s3cret!", role="reviewer")
        assert created is not None
        assert created["username"] == "alice"
        assert created["role"] == "reviewer"
        auth = db.authenticate_user("alice", "s3cret!")
        assert auth is not None
        assert auth["username"] == "alice"

    def test_password_reset_and_role_update(self, tmp_db):
        created = db.create_user("bob", "initial-pass", role="operator")
        user_id = created["id"]
        assert db.update_user_role_status(user_id, role="admin", is_active=False) is True
        assert db.authenticate_user("bob", "initial-pass") is None
        assert db.update_user_role_status(user_id, is_active=True) is True
        assert db.set_user_password(user_id, "new-pass") is True
        assert db.authenticate_user("bob", "initial-pass") is None
        assert db.authenticate_user("bob", "new-pass") is not None
