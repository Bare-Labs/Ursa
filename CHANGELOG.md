# Changelog

All notable changes to Ursa are documented here.

## [Unreleased]

### Changed

- Standardized the repository documentation contract and moved active planning to the workspace root `ROADMAP.md`.
- Merged the Ursa operator MCP surface into the `major.web` control plane at `/mcp`, renamed the operator-facing service concept to the control plane, and updated the published homelab ports to `6707` for control plane and `6708` for C2.
- Fixed the Ursa Major deploy/build pipeline so Blink pushes the same registry image name that the remote start step pulls, and updated the production image to install the Python package dependencies required by the embedded MCP control plane.
- Ignored the repository-root `blink.toml` and `BLINK.md` and stopped tracking them so homelab-specific Blink targets and operator notes stay local-only.
