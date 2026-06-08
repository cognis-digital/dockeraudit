"""Smoke tests for dockeraudit. Standard library only, no network."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dockeraudit import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    audit_dockerfile_text,
    summarize,
)
from dockeraudit.cli import main  # noqa: E402
from dockeraudit.core import (  # noqa: E402
    Severity,
    parse_dockerfile,
    render_html,
    render_json,
    worst_severity,
)

DIRTY = """\
FROM python:latest
ENV API_KEY=sk_live_abcdef0123456789
RUN curl -fsSL https://x.test/i.sh | sudo bash
RUN chmod -R 777 /app
ADD ./req.txt /app/req.txt
COPY . /app
EXPOSE 22
CMD [\"python\", \"app.py\"]
"""

CLEAN = """\
FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
RUN apt-get update && apt-get install -y curl \\
 && rm -rf /var/lib/apt/lists/*
COPY app/ /app/
RUN useradd -u 10001 appuser
USER appuser
HEALTHCHECK CMD [\"true\"]
CMD [\"python\", \"/app/main.py\"]
"""


class TestMeta(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "dockeraudit")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestParser(unittest.TestCase):
    def test_continuation_join(self):
        instrs = parse_dockerfile("RUN a \\\n  && b\nUSER app\n")
        self.assertEqual(instrs[0].cmd, "RUN")
        self.assertIn("&& b", instrs[0].args)
        self.assertEqual(instrs[1].cmd, "USER")

    def test_comments_skipped(self):
        instrs = parse_dockerfile("# comment\n\nFROM scratch\n")
        self.assertEqual(len(instrs), 1)
        self.assertEqual(instrs[0].line, 3)


class TestRules(unittest.TestCase):
    def test_dirty_findings(self):
        f = audit_dockerfile_text(DIRTY)
        codes = {x.rule for x in f}
        for expected in ("DA001", "DA002", "DA003", "DA004",
                         "DA005", "DA006", "DA007", "DA008", "DA011"):
            self.assertIn(expected, codes, f"missing {expected}")

    def test_secret_is_critical(self):
        f = audit_dockerfile_text(DIRTY)
        sec = [x for x in f if x.rule == "DA003"]
        self.assertTrue(sec)
        self.assertEqual(sec[0].severity, Severity.CRITICAL)

    def test_clean_dockerfile(self):
        f = audit_dockerfile_text(CLEAN)
        codes = {x.rule for x in f}
        # Non-root user set, digest-pinned base, healthcheck present, scoped copy.
        for not_expected in ("DA001", "DA002", "DA010", "DA011"):
            self.assertNotIn(not_expected, codes, f"unexpected {not_expected}")

    def test_worst_and_summary(self):
        f = audit_dockerfile_text(DIRTY)
        self.assertEqual(worst_severity(f), Severity.CRITICAL)
        s = summarize(f)
        self.assertEqual(s["total"], len(f))
        self.assertGreaterEqual(s["by_severity"]["CRITICAL"], 1)


class TestRenderers(unittest.TestCase):
    def test_json_valid(self):
        f = audit_dockerfile_text(DIRTY)
        payload = json.loads(render_json("x", f))
        self.assertEqual(payload["tool"], "dockeraudit")
        self.assertEqual(len(payload["findings"]), len(f))

    def test_html_selfcontained(self):
        f = audit_dockerfile_text(DIRTY)
        out = render_html("x", f)
        self.assertIn("<!DOCTYPE html>", out)
        self.assertIn("DOCKERAUDIT", out)
        # no external assets referenced in the document head
        self.assertNotIn("http://", out.split("<style>")[0])


class TestCLI(unittest.TestCase):
    def _demo(self):
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "demos", "01-basic", "Dockerfile")

    def test_audit_exit_nonzero(self):
        rc = main(["audit", self._demo(), "--format", "json"])
        self.assertEqual(rc, 1)

    def test_rules_exit_zero(self):
        self.assertEqual(main(["rules"]), 0)

    def test_missing_file(self):
        self.assertEqual(main(["audit", "does_not_exist_42.Dockerfile"]), 2)

    def test_fail_level_gate(self):
        rc = main(["audit", self._demo(), "--fail-level", "CRITICAL"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
