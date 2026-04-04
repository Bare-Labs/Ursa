#!/usr/bin/env bash
# Deploy Ursa Major to blink, then SSH-tunnel the web UI back to localhost:6707
# so Claude Preview can inspect it at http://localhost:6707
#
# A placeholder HTTP server holds port 6707 open immediately so the preview
# tool doesn't time out during the Docker build.

set -euo pipefail

PORT="${BLINK_URSA_WEB_PORT:-6707}"
SSH_HOST="${BLINK_SSH_HOST:-blink}"

cleanup() {
  [ -n "${PLACEHOLDER_PID:-}" ] && kill "$PLACEHOLDER_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Hold port open immediately so the preview tool doesn't time out
python3 -m http.server "$PORT" --directory /tmp &>/dev/null &
PLACEHOLDER_PID=$!
echo "==> Placeholder server holding port ${PORT} (PID: ${PLACEHOLDER_PID})"

echo "==> Deploying Ursa Major to ${SSH_HOST}..."
/usr/local/bin/blink deploy ursa --local

# Hand off: kill placeholder, open the SSH tunnel
kill "$PLACEHOLDER_PID" 2>/dev/null || true
PLACEHOLDER_PID=""

echo "==> Opening SSH tunnel: localhost:${PORT} -> ${SSH_HOST}:${PORT}"
echo "==> Ursa web UI available at http://localhost:${PORT}"
exec ssh -N -L "${PORT}:localhost:${PORT}" "${SSH_HOST}"
