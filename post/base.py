"""Base class for all Ursa post-exploitation modules.

Every module (implemented or stub) subclasses PostModule and registers itself
with PostLoader via the @register decorator in loader.py.

Module lifecycle
----------------
1.  PostLoader.dispatch("enum/privesc", args={}) is called (e.g. from the MCP
    tool ursa_post_run, or directly from an operator script).
2.  The loader instantiates the module class and calls module.run(args).
3.  run() returns a ModuleResult; the loader serialises it with .to_dict().

Running against a live target
------------------------------
All enum modules in this package execute locally (on the machine running the
C2 or the operator's workstation) using subprocess.  To run them against a
remote implant session instead, send the module's shell commands as a "shell"
task via major.server and parse the raw output with the same helpers used in
each module.  A future "post" task type in the C2 will automate this flow.
"""

from __future__ import annotations

import platform
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ModuleResult:
    """Structured output returned by every PostModule.run() call."""

    ok: bool
    output: str              # human-readable text summary
    data: dict = field(default_factory=dict)   # machine-readable findings
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "output": self.output,
            "data": self.data,
            "error": self.error,
        }


class PostModule(ABC):
    """Abstract base for all post-exploitation modules."""

    # ── Class-level metadata (override in each subclass) ─────────────────────

    NAME: str = ""           # "enum/privesc"  — used as dispatch key
    DESCRIPTION: str = ""   # one-line summary shown in module listings
    AUTHOR: str = ""
    PLATFORM: list[str] = ["linux", "darwin", "windows"]

    # False for stubs; PostLoader surfaces this in ursa_post_list output.
    IMPLEMENTED: bool = True

    # ── Helpers ───────────────────────────────────────────────────────────────

    @classmethod
    def supported(cls) -> bool:
        """Return True if the module supports the current OS."""
        sys = platform.system().lower()
        return any(p in sys for p in cls.PLATFORM)

    # ── Interface ─────────────────────────────────────────────────────────────

    @abstractmethod
    def run(self, args: dict | None = None) -> ModuleResult:
        """Execute the module and return a ModuleResult.

        Implemented modules: run their logic and return ok=True on success.
        Stub modules: raise NotImplementedError with a short hint message.
            The loader catches this and returns ok=False with error text.
        """
