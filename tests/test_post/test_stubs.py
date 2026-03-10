"""Tests for stub modules.

All post-exploitation modules have now been promoted to IMPLEMENTED = True.
This file is kept so that future stubs can be added to WINDOWS_STUBS and
automatically tested for the required stub contract.

Previously stubbed Windows modules (now implemented — see test_post_impl.py):
  lateral/wmi       → WMIExecModule
  persist/registry  → RegistryPersistModule
"""

import pytest

from post.base import PostModule
from post.lateral.wmi import WMIExecModule
from post.persist.registry import RegistryPersistModule

# Add any future stubs here.  An empty list means no parametrised tests run.
WINDOWS_STUBS: list[type[PostModule]] = []


class TestStubMetadata:
    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_has_name(self, cls):
        assert cls.NAME

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_name_has_category_prefix(self, cls):
        assert "/" in cls.NAME

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_has_description(self, cls):
        assert cls.DESCRIPTION

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_implemented_false(self, cls):
        assert cls.IMPLEMENTED is False

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_has_platform(self, cls):
        assert isinstance(cls.PLATFORM, list) and len(cls.PLATFORM) > 0

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_is_subclass_of_post_module(self, cls):
        assert issubclass(cls, PostModule)

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_module_has_implementation_guide(self, cls):
        import importlib
        mod = importlib.import_module(cls.__module__)
        assert mod.__doc__ and len(mod.__doc__) > 200

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_run_raises_not_implemented(self, cls):
        with pytest.raises(NotImplementedError):
            cls().run({})

    @pytest.mark.parametrize("cls", WINDOWS_STUBS)
    def test_loader_dispatch_returns_ok_false(self, cls):
        from post.loader import PostLoader
        result = PostLoader().dispatch(cls.NAME)
        assert result["ok"] is False


class TestPlatformTags:
    """Sanity-check platform tags on the formerly-stubbed Windows modules."""

    def test_registry_windows_only(self):
        assert RegistryPersistModule.PLATFORM == ["windows"]

    def test_wmi_windows_only(self):
        assert WMIExecModule.PLATFORM == ["windows"]

    def test_registry_now_implemented(self):
        assert RegistryPersistModule.IMPLEMENTED is True

    def test_wmi_now_implemented(self):
        assert WMIExecModule.IMPLEMENTED is True
