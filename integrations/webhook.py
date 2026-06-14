#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Post dockeraudit JSON findings to a webhook URL."
    )
    ap.add_argument("--url", required=True, help="Destination URL (https://…)")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra request header in 'Key: Value' form (repeatable)")
    args = ap.parse_args()

    # Validate URL scheme to catch obvious mistakes early.
    if not (args.url.startswith("http://") or args.url.startswith("https://")):
        print(f"error: --url must start with http:// or https://: {args.url!r}",
              file=sys.stderr)
        return 2

    # Validate headers before reading stdin so we fail fast.
    parsed_headers: list[tuple[str, str]] = []
    for h in args.header:
        if ":" not in h:
            print(f"error: --header must be in 'Key: Value' form, got: {h!r}",
                  file=sys.stderr)
            return 2
        k, _, v = h.partition(":")
        key, val = k.strip(), v.strip()
        if not key:
            print(f"error: empty header name in: {h!r}", file=sys.stderr)
            return 2
        parsed_headers.append((key, val))

    payload = sys.stdin.buffer.read()
    if not payload:
        print("warning: no input on stdin — posting empty body", file=sys.stderr)

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for key, val in parsed_headers:
        req.add_header(key, val)

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as e:
        print(f"webhook error: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"webhook error: {e.reason}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
