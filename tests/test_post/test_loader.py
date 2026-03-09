"""Tests for the PostLoader module registry and dispatcher."""

from post.base import ModuleResult
from post.loader import PostLoader


class TestPostLoaderList:
    def test_list_returns_list(self):
        loader = PostLoader()
        modules = loader.list_modules()
        assert isinstance(modules, list)

    def test_list_contains_dicts(self):
        loader = PostLoader()
        for m in loader.list_modules():
            assert "name" in m
            assert "description" in m
            assert "platform" in m
            assert "implemented" in m

    def test_list_contains_known_modules(self):
        loader = PostLoader()
        names = [m["name"] for m in loader.list_modules()]
        for expected in (
            "enum/sysinfo", "enum/privesc", "enum/users", "enum/network",
            "cred/browser", "cred/keychain", "cred/memory",
            "lateral/pth", "lateral/ssh", "lateral/wmi",
            "persist/cron", "persist/registry", "persist/launchagent",
        ):
            assert expected in names, f"Missing module: {expected}"

    def test_list_sorted_alphabetically(self):
        loader = PostLoader()
        names = [m["name"] for m in loader.list_modules()]
        assert names == sorted(names)

    def test_implemented_flags_correct(self):
        loader = PostLoader()
        modules = {m["name"]: m for m in loader.list_modules()}
        # Enum modules are implemented
        assert modules["enum/sysinfo"]["implemented"] is True
        assert modules["enum/privesc"]["implemented"] is True
        assert modules["enum/users"]["implemented"] is True
        assert modules["enum/network"]["implemented"] is True
        # Post-exploitation modules are now implemented
        assert modules["cred/browser"]["implemented"] is True
        assert modules["cred/keychain"]["implemented"] is True
        assert modules["cred/memory"]["implemented"] is True
        assert modules["lateral/pth"]["implemented"] is True
        assert modules["lateral/ssh"]["implemented"] is True
        assert modules["persist/cron"]["implemented"] is True
        assert modules["persist/launchagent"]["implemented"] is True
        # Windows stubs remain not implemented
        assert modules["lateral/wmi"]["implemented"] is False
        assert modules["persist/registry"]["implemented"] is False


class TestPostLoaderDispatch:
    def test_dispatch_unknown_module_returns_error(self):
        result = PostLoader().dispatch("nonexistent/module")
        assert result["ok"] is False
        assert "not found" in result["error"].lower()

    def test_dispatch_windows_stubs_return_not_implemented(self):
        for stub in ("lateral/wmi", "persist/registry"):
            result = PostLoader().dispatch(stub)
            assert result["ok"] is False, f"{stub} should return ok=False"

    def test_dispatch_returns_dict(self):
        result = PostLoader().dispatch("nonexistent")
        assert isinstance(result, dict)
        assert set(result.keys()) >= {"ok", "output", "data", "error"}

    def test_dispatch_sysinfo_returns_ok(self):
        result = PostLoader().dispatch("enum/sysinfo")
        assert result["ok"] is True
        assert result["output"] != ""
        assert "hostname" in result["data"]
