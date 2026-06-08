"""Command-line interface for dockeraudit."""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    DEFAULT_FAIL_LEVEL,
    RULES,
    Severity,
    audit_path,
    render_html,
    render_json,
    render_table,
    worst_severity,
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Audit Dockerfiles for security smells and container hygiene.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    audit = sub.add_parser("audit", help="Audit a Dockerfile.")
    audit.add_argument("path", help="Path to the Dockerfile to audit.")
    audit.add_argument("--format", choices=["table", "json", "html"],
                       default="table", help="Output format (default: table).")
    audit.add_argument("-o", "--output", help="Write report to file instead of stdout.")
    audit.add_argument("--fail-level",
                       choices=[s.value for s in Severity], default=DEFAULT_FAIL_LEVEL.value,
                       help="Minimum severity that causes a non-zero exit "
                            f"(default: {DEFAULT_FAIL_LEVEL.value}).")

    sub.add_parser("rules", help="List the audit rules.")
    return p


def _cmd_rules() -> int:
    print(f"{TOOL_NAME} {TOOL_VERSION} - {len(RULES)} rules")
    print("-" * 60)
    for r in sorted(RULES, key=lambda x: x["rule"]):
        print(f"  {r['rule']:<7} {r['severity']:<9} {r['title']}")
    return 0


def _cmd_audit(args) -> int:
    try:
        findings = audit_path(args.path)
    except FileNotFoundError:
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: cannot read {args.path}: {e}", file=sys.stderr)
        return 2

    if args.format == "json":
        report = render_json(args.path, findings)
    elif args.format == "html":
        report = render_html(args.path, findings)
    else:
        report = render_table(args.path, findings)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
            print(f"wrote {args.format} report to {args.output}", file=sys.stderr)
        except OSError as e:
            print(f"error: cannot write {args.output}: {e}", file=sys.stderr)
            return 2
    else:
        print(report)

    fail_level = Severity(args.fail_level)
    worst = worst_severity(findings)
    if worst is not None and worst.rank >= fail_level.rank:
        return 1
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules":
        return _cmd_rules()
    if args.command == "audit":
        return _cmd_audit(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
