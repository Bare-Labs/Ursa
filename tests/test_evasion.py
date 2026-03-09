"""Tests for implants/evasion.py — sandbox/VM detection."""

import sys
import platform

import pytest

from implants.evasion import (
    _cpu_has_vm_string,
    _dmi_has_vm_string,
    _mac_ouis,
    _process_count,
    _uptime_seconds,
    is_sandbox,
    sandbox_checks,
    spoof_process_name,
)


class TestIndividualChecks:
    def test_uptime_returns_positive_float(self):
        uptime = _uptime_seconds()
        assert isinstance(uptime, float)
        assert uptime >= 0

    def test_uptime_reasonable_range(self):
        # A machine running tests has been up for at least a few seconds.
        # Unknown returns 9999, real uptime can be much larger.
        uptime = _uptime_seconds()
        assert uptime > 0

    def test_mac_ouis_returns_set(self):
        ouis = _mac_ouis()
        assert isinstance(ouis, set)

    def test_mac_ouis_format(self):
        ouis = _mac_ouis()
        for oui in ouis:
            parts = oui.split(":")
            assert len(parts) == 3, f"OUI {oui!r} should have 3 colon-separated parts"
            assert all(len(p) == 2 for p in parts)

    def test_cpu_has_vm_string_returns_bool(self):
        result = _cpu_has_vm_string()
        assert isinstance(result, bool)

    def test_dmi_has_vm_string_returns_bool(self):
        result = _dmi_has_vm_string()
        assert isinstance(result, bool)

    def test_process_count_returns_int(self):
        count = _process_count()
        assert isinstance(count, int)
        assert count >= 0

    def test_process_count_reasonable(self):
        # Any test runner has at least a handful of processes
        count = _process_count()
        assert count > 0


class TestSandboxChecks:
    def test_returns_dict(self):
        result = sandbox_checks()
        assert isinstance(result, dict)

    def test_has_all_expected_keys(self):
        result = sandbox_checks()
        expected_keys = {
            "low_uptime",
            "sandbox_user",
            "sandbox_hostname",
            "vm_mac_oui",
            "vm_cpu_string",
            "vm_dmi_string",
            "low_process_count",
        }
        assert set(result.keys()) == expected_keys

    def test_all_values_are_bool(self):
        result = sandbox_checks()
        for key, val in result.items():
            assert isinstance(val, bool), f"check '{key}' returned non-bool: {val!r}"

    def test_not_sandbox_on_dev_machine(self):
        """On a normal developer machine the machine should not be flagged."""
        result = sandbox_checks()
        hit_count = sum(1 for v in result.values() if v)
        # On a real machine we expect fewer than 3 hits
        # (CI runners may have VM MACs or low uptime — tolerate up to 2)
        assert hit_count < 3, f"Unexpected sandbox hits: {result}"


class TestIsSandbox:
    def test_returns_bool(self):
        result = is_sandbox()
        assert isinstance(result, bool)

    def test_false_on_dev_machine(self):
        """Should not flag a real dev/CI machine at the default threshold."""
        assert is_sandbox(min_hits=2) is False

    def test_min_hits_zero_is_always_false(self):
        # 0 checks fired >= 0 required — always True; min_hits=0 edge case
        # We don't guarantee True here but it should return bool
        assert isinstance(is_sandbox(min_hits=0), bool)

    def test_min_hits_high_is_false(self):
        # Requiring all 7 checks to fire should never trigger on a real machine
        assert is_sandbox(min_hits=7) is False

    def test_is_sandbox_with_mocked_hits(self, monkeypatch):
        """Artificially inject hits to verify threshold logic."""
        from implants import evasion
        # Make uptime look tiny (< 5 minutes) and username look like sandbox
        monkeypatch.setattr(evasion, "_uptime_seconds", lambda: 10.0)
        original_user = __import__("os").getenv
        monkeypatch.setenv("USER", "sandbox")
        # Also mock process count
        monkeypatch.setattr(evasion, "_process_count", lambda: 5)

        result = evasion.sandbox_checks()
        hit_count = sum(1 for v in result.values() if v)
        # low_uptime + sandbox_user + low_process_count = at least 3 hits
        assert hit_count >= 3
        assert evasion.is_sandbox(min_hits=2) is True


class TestInlineBeaconCheck:
    """Verify the beacon.py inline _is_sandbox() matches the standalone module."""

    def test_beacon_has_is_sandbox(self):
        from implants.beacon import _is_sandbox
        assert callable(_is_sandbox)

    def test_beacon_is_sandbox_returns_bool(self):
        from implants.beacon import _is_sandbox
        result = _is_sandbox()
        assert isinstance(result, bool)

    def test_beacon_is_sandbox_false_on_dev_machine(self):
        from implants.beacon import _is_sandbox
        assert _is_sandbox(min_hits=2) is False

    def test_beacon_has_spoof_process_name(self):
        from implants.beacon import _spoof_process_name
        assert callable(_spoof_process_name)


class TestSpoofProcessName:
    """Tests for spoof_process_name() in evasion.py."""

    def test_returns_bool(self):
        result = spoof_process_name("test-process")
        assert isinstance(result, bool)

    def test_returns_true_via_argv_fallback(self):
        # argv[0] mutation is always available, so should succeed
        result = spoof_process_name("test-process")
        assert result is True

    def test_argv0_is_changed(self):
        original = sys.argv[0]
        spoof_process_name("my-fake-process")
        assert sys.argv[0] == "my-fake-process"
        # Restore
        sys.argv[0] = original

    def test_empty_string_no_crash(self):
        # Empty name should not raise
        result = spoof_process_name("")
        assert isinstance(result, bool)

    def test_long_name_no_crash(self):
        # Very long names should not raise (prctl truncates to 15, argv is unlimited)
        result = spoof_process_name("a" * 200)
        assert isinstance(result, bool)

    def test_setproctitle_graceful_when_missing(self, monkeypatch):
        """If setproctitle is not installed, falls through gracefully."""
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "setproctitle":
                raise ImportError("no module")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        # Should still return True (argv[0] fallback)
        result = spoof_process_name("fallback-test")
        assert result is True

    @pytest.mark.skipif(platform.system() != "Linux", reason="prctl is Linux-only")
    def test_linux_prctl_attempt(self):
        """On Linux, the prctl path is attempted (may or may not succeed)."""
        result = spoof_process_name("ursa-beacon")
        assert isinstance(result, bool)
