"""DOCKERAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from dockeraudit.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-dockeraudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-dockeraudit[mcp]'")
        return 1
    app = FastMCP("dockeraudit")

    @app.tool()
    def dockeraudit_scan(target: str) -> str:
        """Audit Dockerfiles + image configs for security smells. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
