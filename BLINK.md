# Ursa Blink Contract

This file documents the real behavior of [`blink.toml`](/Users/joecaruso/Projects/BareSystems/Ursa/blink.toml).

## Target

- `homelab`
- type: SSH
- host: `blink`
- user: `admin`
- runtime dir: `/home/admin/barelabs/runtime/ursa-major`

## Service

### `ursa-major`

- Build: local Docker build for `linux/amd64`, push image to the registry, and package the deploy directory as `dist/ursa-major-deploy.tgz`
- Deploy pipeline: `fetch_artifact`, `remote_script`, `stop`, `backup`, `install`, `start`, `health_check`, `verify`
- Rollback pipeline: `stop`, `rollback`, `start`, `health_check`, `verify`
- Runtime shape: Docker Compose on the homelab host for both `c2` and `cp`

## Verification

The manifest verifies:

- C2 HTTPS health
- C2 container running state
- C2 published port mapping
- control-plane health
- control-plane container running state
- control-plane published port mapping

## Operator Notes

- Ursa deploys both the C2 and BearClaw-facing control plane together.
- Published homelab ports are `6708` for C2 and `6707` for the control plane.
- The deploy bundle includes only the `deploy/` tree; the runtime pulls the actual image from the registry.
- Update this file whenever ports, compose behavior, packaging shape, or verification coverage changes.
