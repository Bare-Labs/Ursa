"""Tests for Ursa Minor scan result persistence and export."""

import json
import time

import pytest

import ursa_minor.results as results_mod
from ursa_minor.results import (
    delete_result,
    export_csv,
    export_engagement_report,
    export_html,
    export_json,
    get_result,
    list_results,
    save_result,
)


@pytest.fixture(autouse=True)
def results_dir(tmp_path, monkeypatch):
    """Redirect results to a temp directory for every test."""
    monkeypatch.setattr(results_mod, "DEFAULT_RESULTS_DIR", tmp_path)
    monkeypatch.setattr(results_mod, "_get_results_dir", lambda: tmp_path)
    return tmp_path


# ── save_result ──


class TestSaveResult:
    def test_basic_save(self, results_dir):
        result_id = save_result("scan_ports", "Port 22 open", {"target": "10.0.0.1"})
        assert result_id.startswith("scan_ports_")
        assert (results_dir / f"{result_id}.json").exists()

    def test_record_fields(self, results_dir):
        rid = save_result("discover_network", "found 3 devices", {"target_range": "10.0.0.0/24"})
        record = json.loads((results_dir / f"{rid}.json").read_text())
        assert record["tool"] == "discover_network"
        assert record["result"] == "found 3 devices"
        assert record["metadata"]["target_range"] == "10.0.0.0/24"
        assert "timestamp" in record
        assert "timestamp_str" in record

    def test_save_with_structured_data(self, results_dir):
        data = [{"port": 22, "service": "SSH", "banner": "OpenSSH_8.9"}]
        rid = save_result("scan_ports", "text output", {"target": "10.0.0.1"},
                          structured_data=data)
        record = json.loads((results_dir / f"{rid}.json").read_text())
        assert record["structured_data"] == data

    def test_save_without_structured_data_omits_key(self, results_dir):
        rid = save_result("test_tool", "output")
        record = json.loads((results_dir / f"{rid}.json").read_text())
        assert "structured_data" not in record

    def test_creates_directory(self, tmp_path, monkeypatch):
        new_dir = tmp_path / "nested" / "dir"

        def _custom_get_dir():
            new_dir.mkdir(parents=True, exist_ok=True)
            return new_dir

        monkeypatch.setattr(results_mod, "_get_results_dir", _custom_get_dir)
        save_result("test", "data")
        assert new_dir.exists()


# ── list_results ──


class TestListResults:
    def test_list_empty(self):
        assert list_results() == []

    def test_list_returns_all(self):
        save_result("scan_ports", "a")
        save_result("discover_network", "b")
        results = list_results()
        assert len(results) == 2

    def test_tool_filter(self):
        save_result("scan_ports", "a")
        save_result("discover_network", "b")
        results = list_results(tool_filter="scan_ports")
        assert len(results) == 1
        assert results[0]["tool"] == "scan_ports"

    def test_target_filter(self):
        save_result("scan_ports", "a", {"target": "10.0.0.1"})
        save_result("scan_ports_2", "b", {"target": "192.168.1.1"})
        results = list_results(target_filter="10.0.0.1")
        assert len(results) == 1

    def test_since_filter(self):
        save_result("old", "old data")
        cutoff = time.time() + 1  # 1 second in the future
        results = list_results(since=cutoff)
        assert len(results) == 0

    def test_limit(self):
        for i in range(10):
            save_result(f"tool_{i}", f"result {i}")
        results = list_results(limit=3)
        assert len(results) == 3

    def test_metadata_included(self):
        save_result("scan_ports", "text", {"target": "10.0.0.1"})
        results = list_results()
        assert results[0]["metadata"]["target"] == "10.0.0.1"


# ── get_result ──


class TestGetResult:
    def test_get_existing(self):
        rid = save_result("test", "hello world")
        record = get_result(rid)
        assert record is not None
        assert record["result"] == "hello world"

    def test_get_nonexistent(self):
        assert get_result("does_not_exist") is None

    def test_get_includes_structured_data(self):
        data = [{"port": 80}]
        rid = save_result("scan_ports", "text", structured_data=data)
        record = get_result(rid)
        assert record["structured_data"] == data


# ── delete_result ──


class TestDeleteResult:
    def test_delete_existing(self, results_dir):
        rid = save_result("test", "data")
        assert (results_dir / f"{rid}.json").exists()
        assert delete_result(rid) is True
        assert not (results_dir / f"{rid}.json").exists()

    def test_delete_nonexistent(self):
        assert delete_result("nonexistent") is False


# ── export_json ──


class TestExportJson:
    def test_basic_export(self):
        rid = save_result("test", "data")
        output = export_json(rid)
        parsed = json.loads(output)
        assert parsed["tool"] == "test"
        assert parsed["result"] == "data"

    def test_not_found(self):
        output = export_json("missing_id")
        assert "not found" in output.lower()


# ── export_csv ──


class TestExportCsv:
    def test_structured_csv(self):
        data = [{"port": 22, "service": "SSH"}, {"port": 80, "service": "HTTP"}]
        rid = save_result("scan_ports", "text", structured_data=data)
        output = export_csv(rid)
        assert "port" in output
        assert "22" in output
        assert "SSH" in output
        assert "80" in output
        assert "HTTP" in output

    def test_text_fallback_csv(self):
        rid = save_result("test", "line1\nline2")
        output = export_csv(rid)
        assert "line1" in output
        assert "line2" in output
        assert "tool" in output  # header row

    def test_not_found(self):
        output = export_csv("missing_id")
        assert "not found" in output.lower()


# ── export_html ──


class TestExportHtml:
    def test_contains_tool_name(self):
        rid = save_result("scan_ports", "Port 22 open")
        output = export_html(rid)
        assert "scan_ports" in output
        assert "<html" in output

    def test_contains_metadata(self):
        rid = save_result("scan_ports", "text", {"target": "10.0.0.1"})
        output = export_html(rid)
        assert "10.0.0.1" in output

    def test_structured_data_renders_table(self):
        data = [{"port": 22, "service": "SSH"}]
        rid = save_result("scan_ports", "text", structured_data=data)
        output = export_html(rid)
        assert "<table>" in output or "<table" in output
        assert "22" in output
        assert "SSH" in output

    def test_not_found(self):
        output = export_html("missing_id")
        assert "not found" in output.lower()


# ── export_engagement_report ──


class TestEngagementReport:
    def test_html_report(self):
        save_result("scan_ports", "port scan output", {"target": "10.0.0.1"},
                     structured_data=[{"port": 22}])
        save_result("discover_network", "network scan", {"target_range": "10.0.0.0/24"})
        output = export_engagement_report(format="html")
        assert "<html" in output
        assert "scan_ports" in output
        assert "discover_network" in output

    def test_json_report(self):
        save_result("test", "data")
        output = export_engagement_report(format="json")
        parsed = json.loads(output)
        assert parsed["result_count"] == 1
        assert len(parsed["results"]) == 1

    def test_csv_report(self):
        save_result("test", "data", {"target": "10.0.0.1"})
        output = export_engagement_report(format="csv")
        assert "result_id" in output
        assert "tool" in output

    def test_with_specific_ids(self):
        rid1 = save_result("tool_a", "a")
        rid2 = save_result("tool_b", "b")
        save_result("tool_c", "c")  # excluded
        output = export_engagement_report(result_ids=[rid1, rid2], format="json")
        parsed = json.loads(output)
        assert parsed["result_count"] == 2

    def test_with_tool_filter(self):
        save_result("scan_ports", "a")
        save_result("discover_network", "b")
        output = export_engagement_report(tool_filter="scan_ports", format="json")
        parsed = json.loads(output)
        assert parsed["result_count"] == 1

    def test_empty(self):
        output = export_engagement_report(tool_filter="nonexistent")
        assert "no results" in output.lower()
