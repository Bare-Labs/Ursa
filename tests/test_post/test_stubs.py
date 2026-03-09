"""Tests that all stub modules are properly structured and raise NotImplementedError."""

import pytest

from post.base import PostModule
from post.cred.browser import BrowserCredModule
from post.cred.keychain import KeychainModule
from post.cred.memory import MemoryCredModule
from post.lateral.pth import PassTheHashModule
from post.lateral.ssh import SSHPivotModule
from post.lateral.wmi import WMIExecModule
from post.persist.cron import CronPersistModule
from post.persist.launchagent import LaunchAgentPersistModule
from post.persist.registry import RegistryPersistModule

ALL_STUBS = [
    BrowserCredModule,
    KeychainModule,
    MemoryCredModule,
    PassTheHashModule,
    SSHPivotModule,
    WMIExecModule,
    CronPersistModule,
    LaunchAgentPersistModule,
    RegistryPersistModule,
]


class TestStubMetadata:
    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_has_name(self, cls):
        assert cls.NAME, f"{cls.__name__} must have a non-empty NAME"

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_name_has_category_prefix(self, cls):
        assert "/" in cls.NAME, f"{cls.__name__}.NAME should be 'category/name'"

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_has_description(self, cls):
        assert cls.DESCRIPTION, f"{cls.__name__} must have a DESCRIPTION"

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_description_contains_stub(self, cls):
        assert "STUB" in cls.DESCRIPTION.upper(), \
            f"{cls.__name__}.DESCRIPTION should contain 'STUB'"

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_implemented_false(self, cls):
        assert cls.IMPLEMENTED is False, \
            f"{cls.__name__}.IMPLEMENTED should be False for stubs"

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_has_platform(self, cls):
        assert isinstance(cls.PLATFORM, list)
        assert len(cls.PLATFORM) > 0

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_is_subclass_of_post_module(self, cls):
        assert issubclass(cls, PostModule)

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_module_has_implementation_guide(self, cls):
        """The module-level docstring is where the implementation guide lives."""
        import importlib
        mod = importlib.import_module(cls.__module__)
        assert mod.__doc__, f"Module {cls.__module__} has no docstring"
        assert len(mod.__doc__) > 200, \
            f"Module {cls.__module__} docstring too short to be an implementation guide"


class TestStubBehaviour:
    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_run_raises_not_implemented(self, cls):
        instance = cls()
        with pytest.raises(NotImplementedError):
            instance.run({})

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_run_not_implemented_message_is_helpful(self, cls):
        instance = cls()
        with pytest.raises(NotImplementedError) as exc_info:
            instance.run({})
        msg = str(exc_info.value)
        # Message should point to the docstring or give a concrete hint
        assert len(msg) > 10, f"{cls.__name__} NotImplementedError message too short"

    @pytest.mark.parametrize("cls", ALL_STUBS)
    def test_loader_dispatch_returns_ok_false(self, cls):
        from post.loader import PostLoader
        result = PostLoader().dispatch(cls.NAME)
        assert result["ok"] is False
        assert "implement" in result["error"].lower() or "not" in result["error"].lower()


class TestPlatformTags:
    def test_registry_windows_only(self):
        assert RegistryPersistModule.PLATFORM == ["windows"]

    def test_launchagent_darwin_only(self):
        assert LaunchAgentPersistModule.PLATFORM == ["darwin"]

    def test_cron_linux_darwin(self):
        assert "linux" in CronPersistModule.PLATFORM
        assert "darwin" in CronPersistModule.PLATFORM
