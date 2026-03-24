#!/usr/bin/env python3
"""Standalone launcher for the packaged Ursa Minor MCP server."""

import os
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "src"))

from ursa_minor.server import mcp_server


if __name__ == "__main__":
    mcp_server.run()
