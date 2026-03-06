"""Tests for the Ursa Major database layer."""

import json
import time

import pytest
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

    def test_kill_session(self, tmp_db, sample_session):
        db.kill_session(sample_session)
        assert db.get_session(sample_session)["status"] == "dead"

    def test_update_session_info(self, tmp_db, sample_session):
        db.update_session_info(sample_session, hostname="NEWBOX", status="stale")
        s = db.get_session(sample_session)
        assert s["hostname"] == "NEWBOX"
        assert s["status"] == "stale"

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
