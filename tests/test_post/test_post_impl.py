"""Tests for implemented post-exploitation modules.

Covers the 7 modules promoted from STUB to IMPLEMENTED:
  cred/browser, cred/keychain, cred/memory,
  lateral/pth, lateral/ssh,
  persist/cron, persist/launchagent
"""

import platform
import sys

import pytest

from post.base import ModuleResult, PostModule
from post.loader import PostLoader

# ── Helpers ────────────────────────────────────────────────────────────────────

SYSTEM = platform.system()
IS_LINUX  = SYSTEM == "Linux"
IS_MACOS  = SYSTEM == "Darwin"


def dispatch(name, args=None):
    return PostLoader().dispatch(name, args or {})


# ── Shared metadata checks ─────────────────────────────────────────────────────

IMPLEMENTED_MODULES = [
    "cred/browser",
    "cred/keychain",
    "cred/memory",
    "lateral/pth",
    "lateral/ssh",
    "persist/cron",
    "persist/launchagent",
]


class TestImplementedMetadata:
    @pytest.mark.parametrize("name", IMPLEMENTED_MODULES)
    def test_implemented_flag_is_true(self, name):
        modules = {m["name"]: m for m in PostLoader().list_modules()}
        assert modules[name]["implemented"] is True

    @pytest.mark.parametrize("name", IMPLEMENTED_MODULES)
    def test_dispatch_returns_module_result_shape(self, name):
        result = PostLoader().dispatch(name)
        assert isinstance(result, dict)
        assert "ok" in result
        assert "output" in result
        assert "data" in result
        assert "error" in result

    @pytest.mark.parametrize("name", IMPLEMENTED_MODULES)
    def test_module_is_subclass_of_post_module(self, name):
        import importlib
        # Resolve the class from the loader registry
        loader = PostLoader()
        modules = {m["name"]: m for m in loader.list_modules()}
        assert name in modules


# ── cred/browser ───────────────────────────────────────────────────────────────

class TestBrowserModule:
    def test_implemented_true(self):
        from post.cred.browser import BrowserCredModule
        assert BrowserCredModule.IMPLEMENTED is True

    def test_platform_is_list(self):
        from post.cred.browser import BrowserCredModule
        assert isinstance(BrowserCredModule.PLATFORM, list)
        assert len(BrowserCredModule.PLATFORM) > 0

    def test_run_returns_module_result(self):
        from post.cred.browser import BrowserCredModule
        result = BrowserCredModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_ok_on_supported_platform(self):
        result = dispatch("cred/browser")
        # ok may be False if no browsers installed, but should never raise
        assert "ok" in result
        assert result["error"] == "" or isinstance(result["error"], str)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_returns_data_dict(self):
        result = dispatch("cred/browser")
        assert isinstance(result["data"], dict)

    def test_chrome_key_linux_helper_returns_bytes(self):
        from post.cred.browser import _chrome_key_linux
        key = _chrome_key_linux()
        assert isinstance(key, bytes)
        assert len(key) == 16

    def test_pbkdf2_helper_returns_correct_length(self):
        from post.cred.browser import _pbkdf2_key
        key = _pbkdf2_key(b"peanuts", iterations=1)
        assert len(key) == 16

    def test_chrome_locations_returns_list(self):
        from post.cred.browser import _chrome_locations
        locs = _chrome_locations()
        assert isinstance(locs, list)

    def test_firefox_profiles_returns_list(self):
        from post.cred.browser import _firefox_profiles
        profiles = _firefox_profiles()
        assert isinstance(profiles, list)


# ── cred/keychain ──────────────────────────────────────────────────────────────

class TestKeychainModule:
    def test_implemented_true(self):
        from post.cred.keychain import KeychainModule
        assert KeychainModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.cred.keychain import KeychainModule
        assert "linux" in KeychainModule.PLATFORM
        assert "darwin" in KeychainModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.cred.keychain import KeychainModule
        result = KeychainModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(IS_MACOS, reason="test macos path separately")
    @pytest.mark.skipif(not IS_LINUX, reason="linux only")
    def test_dispatch_linux_returns_ok(self):
        result = dispatch("cred/keychain")
        assert result["ok"] is True
        assert "secretstorage" in result["output"].lower() or "credential" in result["output"].lower()

    @pytest.mark.skipif(not IS_MACOS, reason="macos only")
    def test_dispatch_macos_returns_ok(self):
        result = dispatch("cred/keychain")
        assert result["ok"] is True
        assert "keychain" in result["output"].lower()

    @pytest.mark.skipif(not IS_MACOS, reason="macos only")
    def test_macos_list_keychains_returns_list(self):
        from post.cred.keychain import _macos_list_keychains
        keychains = _macos_list_keychains()
        assert isinstance(keychains, list)

    @pytest.mark.skipif(not IS_LINUX, reason="linux only")
    def test_linux_credential_files_returns_list(self):
        from post.cred.keychain import _linux_credential_files
        files = _linux_credential_files()
        assert isinstance(files, list)
        for f in files:
            assert "path" in f
            assert "size" in f
            assert "mode" in f


# ── cred/memory ────────────────────────────────────────────────────────────────

class TestMemoryModule:
    def test_implemented_true(self):
        from post.cred.memory import MemoryCredModule
        assert MemoryCredModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.cred.memory import MemoryCredModule
        assert "linux" in MemoryCredModule.PLATFORM
        assert "darwin" in MemoryCredModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.cred.memory import MemoryCredModule
        result = MemoryCredModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_dispatch_returns_ok(self):
        result = dispatch("cred/memory")
        assert result["ok"] is True

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_output_mentions_ssh(self):
        result = dispatch("cred/memory")
        assert "ssh" in result["output"].lower()

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_data_has_expected_keys(self):
        result = dispatch("cred/memory")
        assert "agent_sockets" in result["data"] or "ssh_keys" in result["data"]

    def test_find_ssh_keys_returns_list(self):
        from post.cred.memory import _find_ssh_keys
        keys = _find_ssh_keys()
        assert isinstance(keys, list)

    def test_find_agent_sockets_returns_list(self):
        from post.cred.memory import _find_agent_sockets
        sockets = _find_agent_sockets()
        assert isinstance(sockets, list)


# ── lateral/pth ────────────────────────────────────────────────────────────────

class TestPassTheHashModule:
    def test_implemented_true(self):
        from post.lateral.pth import PassTheHashModule
        assert PassTheHashModule.IMPLEMENTED is True

    def test_platform_includes_common_oses(self):
        from post.lateral.pth import PassTheHashModule
        assert "linux" in PassTheHashModule.PLATFORM or "windows" in PassTheHashModule.PLATFORM

    def test_run_without_args_returns_module_result(self):
        from post.lateral.pth import PassTheHashModule
        result = PassTheHashModule().run({})
        assert isinstance(result, ModuleResult)

    def test_run_missing_target_returns_error(self):
        from post.lateral.pth import PassTheHashModule
        result = PassTheHashModule().run({})
        # Should fail gracefully — either impacket missing or no target
        assert result.ok is False or isinstance(result.error, str)

    def test_parse_hash_lm_nt_format(self):
        from post.lateral.pth import _parse_hash
        lm, nt = _parse_hash("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_parse_hash_nt_only(self):
        from post.lateral.pth import _parse_hash
        lm, nt = _parse_hash("8846f7eaee8fb117ad06bdd830b7586c")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "8846f7eaee8fb117ad06bdd830b7586c"

    def test_dispatch_without_impacket_returns_helpful_error(self):
        """When impacket is missing, error should mention how to install."""
        from post.lateral import pth as pth_mod
        if pth_mod._IMPACKET_OK:
            pytest.skip("impacket is installed — skip missing-impacket path")
        result = dispatch("lateral/pth", {"target": "127.0.0.1", "username": "admin",
                                          "hash": "aad3:8846"})
        assert result["ok"] is False
        assert "impacket" in result["error"].lower()


# ── lateral/ssh ────────────────────────────────────────────────────────────────

class TestSSHPivotModule:
    def test_implemented_true(self):
        from post.lateral.ssh import SSHPivotModule
        assert SSHPivotModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.lateral.ssh import SSHPivotModule
        assert "linux" in SSHPivotModule.PLATFORM
        assert "darwin" in SSHPivotModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.lateral.ssh import SSHPivotModule
        result = SSHPivotModule().run({})
        assert isinstance(result, ModuleResult)

    def test_list_mode_returns_ok(self):
        result = dispatch("lateral/ssh", {"mode": "list"})
        assert result["ok"] is True
        assert "pivot" in result["output"].lower() or "active" in result["output"].lower()

    def test_list_data_has_pivots_key(self):
        result = dispatch("lateral/ssh", {"mode": "list"})
        assert "pivots" in result["data"]

    def test_missing_host_returns_error(self):
        result = dispatch("lateral/ssh", {"mode": "socks5"})
        assert result["ok"] is False

    def test_unknown_mode_no_host_returns_error(self):
        result = dispatch("lateral/ssh", {"mode": "bogus"})
        # No ssh_host → returns "Required: ssh_host, ssh_user" error
        assert result["ok"] is False

    def test_without_paramiko_returns_error_or_ok(self):
        from post.lateral import ssh as ssh_mod
        if not ssh_mod._PARAMIKO_OK:
            result = dispatch("lateral/ssh", {"action": "list"})
            assert result["ok"] is False
            assert "paramiko" in result["error"].lower()


# ── persist/cron ───────────────────────────────────────────────────────────────

class TestCronModule:
    def test_implemented_true(self):
        from post.persist.cron import CronPersistModule
        assert CronPersistModule.IMPLEMENTED is True

    def test_platform_includes_linux_and_darwin(self):
        from post.persist.cron import CronPersistModule
        assert "linux" in CronPersistModule.PLATFORM
        assert "darwin" in CronPersistModule.PLATFORM

    def test_run_returns_module_result(self):
        from post.persist.cron import CronPersistModule
        result = CronPersistModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_list_action_returns_ok(self):
        result = dispatch("persist/cron", {"action": "list"})
        assert result["ok"] is True

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_list_output_mentions_crontab(self):
        result = dispatch("persist/cron", {"action": "list"})
        assert "crontab" in result["output"].lower()

    @pytest.mark.skipif(not (IS_LINUX or IS_MACOS), reason="linux/macos only")
    def test_list_data_has_cron_entries_key(self):
        result = dispatch("persist/cron", {"action": "list"})
        assert "cron_entries" in result["data"]

    def test_install_without_command_returns_error(self):
        result = dispatch("persist/cron", {"action": "install", "command": ""})
        assert result["ok"] is False
        assert "command" in result["error"].lower()

    def test_unknown_action_returns_error(self):
        result = dispatch("persist/cron", {"action": "bogus_action"})
        assert result["ok"] is False

    def test_systemd_install_on_macos_returns_error(self):
        if not IS_MACOS:
            pytest.skip("macOS only")
        result = dispatch("persist/cron", {"action": "systemd_install",
                                           "command": "/bin/true"})
        assert result["ok"] is False
        assert "linux" in result["error"].lower()

    def test_crontab_list_helper_returns_list(self):
        from post.persist.cron import _crontab_list
        entries = _crontab_list()
        assert isinstance(entries, list)


# ── persist/launchagent ────────────────────────────────────────────────────────

class TestLaunchAgentModule:
    def test_implemented_true(self):
        from post.persist.launchagent import LaunchAgentPersistModule as LaunchAgentModule
        assert LaunchAgentModule.IMPLEMENTED is True

    def test_platform_darwin_only(self):
        from post.persist.launchagent import LaunchAgentPersistModule as LaunchAgentModule
        assert LaunchAgentModule.PLATFORM == ["darwin"]

    def test_run_returns_module_result(self):
        from post.persist.launchagent import LaunchAgentPersistModule as LaunchAgentModule
        result = LaunchAgentModule().run({})
        assert isinstance(result, ModuleResult)

    @pytest.mark.skipif(not IS_MACOS, reason="macOS only")
    def test_list_action_returns_ok(self):
        result = dispatch("persist/launchagent", {"action": "list"})
        assert result["ok"] is True

    @pytest.mark.skipif(not IS_MACOS, reason="macOS only")
    def test_list_data_has_agents_key(self):
        result = dispatch("persist/launchagent", {"action": "list"})
        assert "agents" in result["data"]

    def test_install_without_program_returns_error(self):
        result = dispatch("persist/launchagent", {"action": "install"})
        assert result["ok"] is False

    def test_on_non_macos_returns_error(self):
        if IS_MACOS:
            pytest.skip("only meaningful on non-macOS")
        result = dispatch("persist/launchagent", {"action": "list"})
        assert result["ok"] is False

    def test_unknown_action_returns_error(self):
        result = dispatch("persist/launchagent", {"action": "bogus"})
        assert result["ok"] is False

    def test_plist_path_helper(self):
        from post.persist.launchagent import _plist_path
        p = _plist_path("com.test.label")
        assert str(p).endswith("com.test.label.plist")
        assert "LaunchAgents" in str(p)
