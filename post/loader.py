"""Module registry and dispatcher for the post/ package.

Registration
------------
Every PostModule subclass decorates itself with @register:

    from post.loader import register
    from post.base import PostModule, ModuleResult

    @register
    class MyModule(PostModule):
        NAME = "enum/mymodule"
        ...

Auto-discovery
--------------
PostLoader._discover() walks the post package on first use and imports every
submodule, which triggers all @register decorators.  Adding a new file to
post/enum/, post/cred/, etc. is sufficient — no central registration list.

Dispatch
--------
    loader = PostLoader()
    result = loader.dispatch("enum/privesc", args={})   # → dict
    modules = loader.list_modules()                     # → list[dict]
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import post

from post.base import ModuleResult, PostModule

# Global registry: NAME → module class
_REGISTRY: dict[str, type[PostModule]] = {}


def register(cls: type[PostModule]) -> type[PostModule]:
    """Class decorator that registers a PostModule subclass by its NAME."""
    if cls.NAME:
        _REGISTRY[cls.NAME] = cls
    return cls


class PostLoader:
    """Discovers and dispatches post-exploitation modules."""

    _discovered: bool = False

    @classmethod
    def _discover(cls) -> None:
        """Walk the post package once and import every submodule."""
        if cls._discovered:
            return
        import post  # noqa: PLC0415

        for _finder, name, _ispkg in pkgutil.walk_packages(
            path=post.__path__,
            prefix="post.",
            onerror=lambda _: None,
        ):
            try:
                importlib.import_module(name)
            except Exception:  # noqa: BLE001
                pass
        cls._discovered = True

    # ── Public API ────────────────────────────────────────────────────────────

    def list_modules(self) -> list[dict]:
        """Return metadata for every registered module, sorted by name."""
        self._discover()
        return sorted(
            [
                {
                    "name": m.NAME,
                    "description": m.DESCRIPTION,
                    "platform": m.PLATFORM,
                    "implemented": m.IMPLEMENTED,
                }
                for m in _REGISTRY.values()
            ],
            key=lambda d: d["name"],
        )

    def dispatch(self, name: str, args: dict | None = None) -> dict:
        """Load module by name and run it.  Returns a serialised ModuleResult.

        Returns ok=False with an error string if:
          - the module name is unknown
          - the module raises NotImplementedError (stub)
          - the module raises any other exception
        """
        self._discover()

        if name not in _REGISTRY:
            available = list(_REGISTRY.keys())
            return ModuleResult(
                ok=False,
                output="",
                error=(
                    f"Module '{name}' not found. "
                    f"Available: {available if available else ['(none)']}"
                ),
            ).to_dict()

        module = _REGISTRY[name]()

        try:
            result = module.run(args or {})
        except NotImplementedError as exc:
            hint = str(exc) or "see module docstring for implementation guide"
            return ModuleResult(
                ok=False,
                output="",
                error=f"Module '{name}' is not yet implemented. {hint}",
            ).to_dict()
        except Exception as exc:  # noqa: BLE001
            return ModuleResult(
                ok=False,
                output="",
                error=f"Module '{name}' raised an error: {exc}",
            ).to_dict()

        return result.to_dict()
