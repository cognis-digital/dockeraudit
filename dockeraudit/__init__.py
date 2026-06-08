"""DOCKERAUDIT - Audit Dockerfiles and image configs for security smells.

A zero-install, standard-library-only static analyzer in the spirit of
hadolint / dockle. Defensive use only: analyze artifacts you own.
"""
from .core import (
    Finding,
    Severity,
    audit_dockerfile_text,
    audit_path,
    summarize,
    RULES,
)

TOOL_NAME = "dockeraudit"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Severity",
    "audit_dockerfile_text",
    "audit_path",
    "summarize",
    "RULES",
    "TOOL_NAME",
    "TOOL_VERSION",
]
