"""Run the Ursa Major web UI.

Usage:
    python -m major.web [--port 8080] [--host 127.0.0.1] [--profile field]
"""

import argparse
import uvicorn

from major.config import get_config, reload_config


def main():
    parser = argparse.ArgumentParser(description="Ursa Major Web UI")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--reload", action="store_true", help="Auto-reload on changes")
    parser.add_argument("--profile", default=None, help="Config profile to use")
    parser.add_argument("--config", default=None, help="Path to config file")
    args = parser.parse_args()

    # Reload config with profile/path if specified
    if args.profile or args.config:
        cfg = reload_config(path=args.config, profile=args.profile)
    else:
        cfg = get_config()

    host = args.host or cfg.get("major.web.host", "0.0.0.0")
    port = args.port or cfg.get("major.web.port", 8080)

    print(f"  URSA MAJOR — Web UI")
    print(f"  http://{host}:{port}")
    print()

    uvicorn.run(
        "major.web.app:app",
        host=host,
        port=port,
        reload=args.reload,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
