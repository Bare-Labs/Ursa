# Changelog

All notable changes to Ursa are documented here.

## [Unreleased]

### Fixed

- **Slow builds on Apple Silicon** — Rewrote the Dockerfile as a two-stage build. Stage 1 runs natively on the build machine (`$BUILDPLATFORM`) and uses `pip download` to fetch pre-built `manylinux2014_x86_64` wheels without any QEMU emulation. Stage 2 installs from those local wheels — no compilation, no network — so even the first build is fast. Also added `dist/`, `deploy/`, and `*.tgz` to `.dockerignore` to eliminate deploy artifact bloat from the build context.
- **Missing rollback pipeline** — Added `rollback_pipeline = ["stop", "start", "health_check"]` to the `ursa-major` deploy config. Previously a failed deploy had no automated recovery path.
- **Dockerfile layer caching** — Rewrote the Dockerfile to separate dependency installation from source copying. `pyproject.toml` is copied first; stubs are used to install all deps into a cached layer; real source is copied second and installed with `--no-deps`. This eliminates the redundant apt-then-pip double-install pattern and ensures dep layers are only rebuilt when `pyproject.toml` changes, not on every code edit.

### Changed

- `blink.toml`: added `tls_insecure = true` to the `ursa-major.verify.tests.c2-health` inline HTTP test. Blink Sprint D flipped the HTTP adapter to TLS-verify-by-default; the C2 listener on `:6708` still uses a self-signed cert, so the test needs an explicit opt-in. The planner now surfaces this as a warning in `blink validate` / `blink plan`, keeping the insecure posture visible.
- Standardized the repository documentation contract and moved active planning to the workspace root `ROADMAP.md`.
- Merged the Ursa operator MCP surface into the `major.web` control plane at `/mcp`, renamed the operator-facing service concept to the control plane, and updated the published homelab ports to `6707` for control plane and `6708` for C2.
- Fixed the Ursa Major deploy/build pipeline so Blink pushes the same registry image name that the remote start step pulls, and updated the production image to install the Python package dependencies required by the embedded MCP control plane.
- Ignored the repository-root `blink.toml` and `BLINK.md` and stopped tracking them so homelab-specific Blink targets and operator notes stay local-only.
