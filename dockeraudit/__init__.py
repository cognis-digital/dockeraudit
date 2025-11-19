"""DOCKERAUDIT — Audit Dockerfiles + image configs for security smells."""
from dockeraudit.core import scan, TOOL_NAME, TOOL_VERSION
__all__ = ["scan", "TOOL_NAME", "TOOL_VERSION"]
