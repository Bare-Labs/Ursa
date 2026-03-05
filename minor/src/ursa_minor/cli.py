#!/usr/bin/env python3
"""Ursa Minor CLI — entry point for the recon toolkit."""

import click


@click.group()
def main():
    """Ursa Minor — Recon & Scanning Toolkit."""
    pass


@main.group()
def mcp():
    """MCP server commands."""
    pass


@mcp.command()
def serve():
    """Start the Ursa Minor MCP server."""
    from ursa_minor.server import mcp_server
    mcp_server.run()


if __name__ == "__main__":
    main()
