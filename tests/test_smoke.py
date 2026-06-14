"""Smoke tests for dockeraudit. Standard library only, no network."""
import json
import os
import sys
import tempfile
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
    audit_path,
    parse_dockerfile,
    render_html,
    render_json,
    render_table,
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


class TestEdgeCases(unittest.TestCase):
    """Edge-case and error-path tests added during hardening."""

    # ------------------------------------------------------------------
    # Parser edge cases
    # ------------------------------------------------------------------

    def test_empty_dockerfile_no_crash(self):
        """An empty file must not raise; it has no instructions."""
        instrs = parse_dockerfile("")
        self.assertEqual(instrs, [])

    def test_only_comments_no_crash(self):
        """A file that is only comments must not raise."""
        findings = audit_dockerfile_text("# this is just a comment\n")
        # DA001 fires (no USER) but no other rule should crash.
        self.assertIsInstance(findings, list)

    def test_empty_findings_renderers(self):
        """All renderers must handle an empty findings list gracefully."""
        table = render_table("test.Dockerfile", [])
        self.assertIn("No findings", table)

        html_out = render_html("test.Dockerfile", [])
        self.assertIn("No findings", html_out)
        self.assertIn("<!DOCTYPE html>", html_out)

        payload = json.loads(render_json("test.Dockerfile", []))
        self.assertEqual(payload["summary"]["total"], 0)
        self.assertEqual(payload["findings"], [])

    def test_worst_severity_empty_list(self):
        """worst_severity of an empty list must return None (not crash)."""
        self.assertIsNone(worst_severity([]))

    # ------------------------------------------------------------------
    # audit_path error paths
    # ------------------------------------------------------------------

    def test_audit_path_missing_file_raises(self):
        """audit_path raises FileNotFoundError for a nonexistent path."""
        with self.assertRaises(FileNotFoundError):
            audit_path("__nonexistent_file_xyz__.Dockerfile")

    def test_audit_path_oversized_file_raises(self):
        """audit_path raises ValueError when the file exceeds the size limit."""
        from dockeraudit.core import _MAX_DOCKERFILE_BYTES
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".Dockerfile", delete=False
        ) as fh:
            fh.write(b"FROM scratch\n" * 100)
            # Write enough zeroes to exceed the limit.
            fh.write(b"\x00" * (_MAX_DOCKERFILE_BYTES + 1))
            tmp_path = fh.name
        try:
            with self.assertRaises(ValueError) as ctx:
                audit_path(tmp_path)
            self.assertIn("too large", str(ctx.exception))
        finally:
            os.unlink(tmp_path)

    # ------------------------------------------------------------------
    # CLI error paths
    # ------------------------------------------------------------------

    def test_cli_missing_file_exit2(self):
        """CLI returns exit code 2 for a missing file."""
        rc = main(["audit", "__no_such_file__.Dockerfile"])
        self.assertEqual(rc, 2)

    def test_cli_oversized_file_exit2(self):
        """CLI returns exit code 2 when the file is too large."""
        from dockeraudit.core import _MAX_DOCKERFILE_BYTES
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".Dockerfile", delete=False
        ) as fh:
            fh.write(b"\x00" * (_MAX_DOCKERFILE_BYTES + 1))
            tmp_path = fh.name
        try:
            rc = main(["audit", tmp_path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(tmp_path)

    def test_cli_no_subcommand_exits_zero(self):
        """Invoking without a subcommand prints help and returns 0."""
        rc = main([])
        self.assertEqual(rc, 0)

    # ------------------------------------------------------------------
    # mcp_server importability
    # ------------------------------------------------------------------

    def test_mcp_server_imports_without_error(self):
        """mcp_server must be importable (scan/to_json aliases must resolve)."""
        import importlib
        mod = importlib.import_module("dockeraudit.mcp_server")
        self.assertTrue(callable(mod.scan))
        self.assertTrue(callable(mod.to_json))


if __name__ == "__main__":
    unittest.main()
