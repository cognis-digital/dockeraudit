"""DOCKERAUDIT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

# Alias the public API names expected by MCP tool callers.
from dockeraudit.core import audit_path as scan  # noqa: F401
from dockeraudit.core import render_json as to_json  # noqa: F401


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-dockeraudit[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-dockeraudit[mcp]'")
        return 1
    app = FastMCP("dockeraudit")

    @app.tool()
    def dockeraudit_scan(target: str) -> str:
        """Audit Dockerfiles + image configs for security smells. Returns JSON findings."""
        if not target or not target.strip():
            return '{"error": "target path must not be empty"}'
        try:
            findings = scan(target)
        except FileNotFoundError:
            return '{"error": "file not found: ' + target.replace('"', '\\"') + '"}'
        except OSError as exc:
            return '{"error": "' + str(exc).replace('"', '\\"') + '"}'
        return to_json(target, findings)

    app.run()
    return 0
