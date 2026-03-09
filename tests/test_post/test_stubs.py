"""Tests for stub modules (Windows-only, not implemented on this platform).

The remaining stubs are Windows-specific: WMI and Registry.
All other post-exploitation modules are now implemented — see test_post_impl.py.
"""

import pytest

from post.base import PostModule
from post.lateral.wmi import WMIExecModule
from post.persist.registry import RegistryPersistModule

WINDOWS_STUBS = [
    WMIExecModule,
    RegistryPersistModule,
]


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
    def test_registry_windows_only(self):
        assert RegistryPersistModule.PLATFORM == ["windows"]

    def test_wmi_windows_only(self):
        assert WMIExecModule.PLATFORM == ["windows"]
