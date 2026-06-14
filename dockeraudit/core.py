"""Core engine: parse Dockerfiles and emit security/hygiene findings.

Pure standard library. The parser handles line continuations, comments,
and per-stage context so rules can reason about FROM/USER/HEALTHCHECK state.
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Callable, Iterable, List, Optional


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


# Severities at or above this exit non-zero (override-able from CLI).
DEFAULT_FAIL_LEVEL = Severity.HIGH


@dataclass
class Finding:
    rule: str
    severity: Severity
    line: int
    message: str
    instruction: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class _Instruction:
    cmd: str          # e.g. "FROM", "RUN"
    args: str         # full argument text (continuations joined)
    line: int         # 1-based line of the instruction start
    raw: str = ""


@dataclass
class _State:
    """Mutable analysis context shared across rules within a Dockerfile."""
    instructions: List[_Instruction]
    final_user: Optional[str] = None
    has_healthcheck: bool = False
    stage_count: int = 0
    has_latest_base: bool = False


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

_CMD_RE = re.compile(r"^\s*([A-Za-z]+)\s*(.*)$")


def parse_dockerfile(text: str) -> List[_Instruction]:
    """Parse Dockerfile text into instructions, joining `\\` continuations."""
    instrs: List[_Instruction] = []
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        stripped = line.strip()
        i += 1
        if not stripped or stripped.startswith("#"):
            continue
        start_line = i  # 1-based of this instruction's first line
        # Join continuations.
        buf = line
        while buf.rstrip().endswith("\\") and i < n:
            buf = buf.rstrip()[:-1] + " " + lines[i]
            i += 1
        m = _CMD_RE.match(buf)
        if not m:
            continue
        cmd = m.group(1).upper()
        args = m.group(2).strip()
        instrs.append(_Instruction(cmd=cmd, args=args, line=start_line, raw=buf))
    return instrs


# --------------------------------------------------------------------------
# Rule helpers
# --------------------------------------------------------------------------

RuleFn = Callable[[_State], Iterable[Finding]]
RULES: List[dict] = []  # registry metadata for --list-rules / docs
_RULE_FNS: List[RuleFn] = []


def rule(code: str, severity: Severity, title: str):
    def deco(fn: RuleFn) -> RuleFn:
        RULES.append({"rule": code, "severity": severity.value, "title": title})
        _RULE_FNS.append(fn)
        return fn
    return deco


# Secret-ish patterns for ENV/ARG leakage.
_SECRET_KEY_RE = re.compile(
    r"(?i)(pass(word|wd)?|secret|api[_-]?key|access[_-]?key|token|"
    r"private[_-]?key|aws_secret|client[_-]?secret)"
)
_SECRET_VAL_RE = re.compile(r"(?i)(aws_secret_access_key|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
_CURL_PIPE_SH_RE = re.compile(r"(?i)(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash)\b")
_SUDO_RE = re.compile(r"(?:^|\s|&&|;|\|)\s*sudo\b")
_CHMOD_777_RE = re.compile(r"chmod\s+(-[A-Za-z]+\s+)*(0?777|a\+rwx|ugo\+rwx)\b")
_PKG_NO_CLEAN_RE = re.compile(r"(?i)apt(-get)?\s+install\b")
_APT_CLEAN_RE = re.compile(r"(?i)(rm\s+-rf\s+/var/lib/apt|apt-get\s+clean)")
_LATEST_RE = re.compile(r":latest$")
_HAS_TAG_RE = re.compile(r"^[^\s]+:[^\s]+$")
_HAS_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}", re.I)


def _split_from(args: str):
    """Return (image, stage_alias) from a FROM arg string."""
    parts = args.split()
    if not parts:
        return "", None
    image = parts[0]
    alias = None
    if len(parts) >= 3 and parts[1].upper() == "AS":
        alias = parts[2]
    return image, alias


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

@rule("DA001", Severity.HIGH, "Container runs as root (no non-root USER)")
def _r_no_user(st: _State) -> Iterable[Finding]:
    if st.final_user is None or st.final_user.lower() in ("root", "0"):
        # find last FROM line for anchoring
        last_from = next((ins for ins in reversed(st.instructions) if ins.cmd == "FROM"), None)
        ln = last_from.line if last_from else 1
        yield Finding(
            "DA001", Severity.HIGH, ln,
            "Image runs as root; no non-root USER set in final stage.",
            "USER",
            "Add a non-root user, e.g. `RUN useradd -u 10001 app` then `USER app`.",
        )


@rule("DA002", Severity.MEDIUM, "Base image uses :latest or untagged")
def _r_latest(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd != "FROM":
            continue
        image, _ = _split_from(ins.args)
        if not image or image.lower() == "scratch":
            continue
        if image.startswith("$"):  # build-arg driven, skip
            continue
        if _HAS_DIGEST_RE.search(image):
            continue
        if _LATEST_RE.search(image):
            yield Finding("DA002", Severity.MEDIUM, ins.line,
                          f"Base image '{image}' pinned to mutable :latest tag.",
                          "FROM", "Pin to a specific version and ideally a @sha256 digest.")
        elif not _HAS_TAG_RE.match(image):
            yield Finding("DA002", Severity.MEDIUM, ins.line,
                          f"Base image '{image}' is untagged (implies :latest).",
                          "FROM", "Pin an explicit version tag, e.g. python:3.12-slim.")


@rule("DA003", Severity.CRITICAL, "Hardcoded secret in ENV/ARG")
def _r_secret(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd not in ("ENV", "ARG"):
            continue
        # ENV KEY=VAL or ENV KEY VAL
        text = ins.args
        if _SECRET_VAL_RE.search(text):
            yield Finding("DA003", Severity.CRITICAL, ins.line,
                          "Likely embedded private key / AWS secret value.",
                          ins.cmd, "Use build secrets / runtime env, never bake secrets into layers.")
            continue
        # extract key
        kv = re.split(r"\s+", text, maxsplit=1)
        key = kv[0].split("=")[0]
        has_value = ("=" in text) or (len(kv) > 1 and kv[1].strip())
        if _SECRET_KEY_RE.search(key) and has_value:
            yield Finding("DA003", Severity.CRITICAL, ins.line,
                          f"Sensitive name '{key}' assigned a value in image layers.",
                          ins.cmd, "Inject secrets at runtime; layers are persisted and inspectable.")


@rule("DA004", Severity.HIGH, "Pipe-to-shell install (curl|sh)")
def _r_curl_pipe(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd == "RUN" and _CURL_PIPE_SH_RE.search(ins.args):
            yield Finding("DA004", Severity.HIGH, ins.line,
                          "Remote script piped directly into a shell (supply-chain risk).",
                          "RUN", "Download, verify a checksum/signature, then execute.")


@rule("DA005", Severity.LOW, "Use of sudo inside RUN")
def _r_sudo(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd == "RUN" and _SUDO_RE.search(ins.args):
            yield Finding("DA005", Severity.LOW, ins.line,
                          "`sudo` in RUN is unnecessary (build runs as root) and can mask intent.",
                          "RUN", "Drop sudo; switch users explicitly with USER.")


@rule("DA006", Severity.MEDIUM, "Overly permissive chmod (777)")
def _r_chmod(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd == "RUN" and _CHMOD_777_RE.search(ins.args):
            yield Finding("DA006", Severity.MEDIUM, ins.line,
                          "World-writable permissions (777) set on filesystem objects.",
                          "RUN", "Grant least privilege; avoid 0777 / a+rwx.")


@rule("DA007", Severity.LOW, "ADD used where COPY suffices")
def _r_add(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd != "ADD":
            continue
        src = ins.args.split()[0] if ins.args.split() else ""
        is_remote = src.startswith("http://") or src.startswith("https://")
        is_archive = re.search(r"\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz)\b", src or "")
        if not is_remote and not is_archive:
            yield Finding("DA007", Severity.LOW, ins.line,
                          "ADD used for a plain file; COPY is more predictable and auditable.",
                          "ADD", "Use COPY unless you need remote fetch or auto-extract.")
        elif is_remote:
            yield Finding("DA007", Severity.MEDIUM, ins.line,
                          "ADD fetches a remote URL (unverified download into image).",
                          "ADD", "Fetch via RUN with checksum verification, or COPY a vendored copy.")


@rule("DA008", Severity.MEDIUM, "Privileged port exposed / runs on 22")
def _r_ssh_port(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd != "EXPOSE":
            continue
        for tok in ins.args.split():
            port = tok.split("/")[0]
            if port == "22":
                yield Finding("DA008", Severity.MEDIUM, ins.line,
                              "Exposing SSH (port 22) inside a container is an anti-pattern.",
                              "EXPOSE", "Avoid running sshd in app containers; use exec/attach.")


@rule("DA009", Severity.LOW, "apt-get install without cache cleanup")
def _r_apt_clean(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd == "RUN" and _PKG_NO_CLEAN_RE.search(ins.args):
            if not _APT_CLEAN_RE.search(ins.args):
                yield Finding("DA009", Severity.LOW, ins.line,
                              "apt-get install without removing /var/lib/apt lists bloats the image.",
                              "RUN", "Append `&& rm -rf /var/lib/apt/lists/*` in the same RUN.")


@rule("DA010", Severity.LOW, "Missing HEALTHCHECK")
def _r_healthcheck(st: _State) -> Iterable[Finding]:
    has_service = any(ins.cmd in ("CMD", "ENTRYPOINT") for ins in st.instructions)
    if has_service and not st.has_healthcheck:
        last = st.instructions[-1].line if st.instructions else 1
        yield Finding("DA010", Severity.LOW, last,
                      "No HEALTHCHECK defined for a long-running service image.",
                      "HEALTHCHECK", "Add a HEALTHCHECK so orchestrators detect unhealthy containers.")


@rule("DA011", Severity.MEDIUM, "Wildcard COPY/ADD of build context")
def _r_wildcard_copy(st: _State) -> Iterable[Finding]:
    for ins in st.instructions:
        if ins.cmd in ("COPY", "ADD"):
            toks = [t for t in ins.args.split() if not t.startswith("--")]
            if toks and toks[0] in (".", "./", "*"):
                yield Finding("DA011", Severity.MEDIUM, ins.line,
                              f"`{ins.cmd} {toks[0]}` copies the whole build context "
                              "(risks leaking secrets / .git).",
                              ins.cmd, "Copy only needed paths and maintain a .dockerignore.")


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def _build_state(instrs: List[_Instruction]) -> _State:
    st = _State(instructions=instrs)
    for ins in instrs:
        if ins.cmd == "FROM":
            st.stage_count += 1
            # A new build stage resets the effective user.
            st.final_user = None
        elif ins.cmd == "USER":
            st.final_user = ins.args.split()[0] if ins.args.split() else None
        elif ins.cmd == "HEALTHCHECK":
            if ins.args.strip().upper() != "NONE":
                st.has_healthcheck = True
    return st


def audit_dockerfile_text(text: str, source: str = "<text>") -> List[Finding]:
    instrs = parse_dockerfile(text)
    st = _build_state(instrs)
    findings: List[Finding] = []
    for fn in _RULE_FNS:
        findings.extend(fn(st))
    findings.sort(key=lambda f: (-f.severity.rank, f.line, f.rule))
    return findings


_MAX_DOCKERFILE_BYTES = 1 * 1024 * 1024  # 1 MiB — Dockerfiles are never this large


def audit_path(path: str) -> List[Finding]:
    """Read *path* and return findings.

    Raises:
        FileNotFoundError: path does not exist.
        OSError: path is a directory, unreadable, or too large.
        ValueError: file exceeds the 1 MiB safety limit.
    """
    import os as _os
    try:
        size = _os.path.getsize(path)
    except OSError:
        # Let the open() below produce the canonical error.
        size = 0
    if size > _MAX_DOCKERFILE_BYTES:
        raise ValueError(
            f"{path!r} is {size:,} bytes — too large to be a Dockerfile "
            f"(limit {_MAX_DOCKERFILE_BYTES:,} bytes)"
        )
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return audit_dockerfile_text(fh.read(), source=path)


def summarize(findings: List[Finding]) -> dict:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return {"total": len(findings), "by_severity": counts}


def worst_severity(findings: List[Finding]) -> Optional[Severity]:
    if not findings:
        return None
    return max((f.severity for f in findings), key=lambda s: s.rank)


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

_SEV_COLOR = {
    "CRITICAL": "#7c1d1d", "HIGH": "#b42318", "MEDIUM": "#b54708",
    "LOW": "#175cd3", "INFO": "#475467",
}


def render_json(source: str, findings: List[Finding]) -> str:
    payload = {
        "tool": "dockeraudit",
        "source": source,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def render_table(source: str, findings: List[Finding]) -> str:
    s = summarize(findings)
    out = [f"DOCKERAUDIT report for: {source}"]
    bys = s["by_severity"]
    out.append("Summary: " + "  ".join(
        f"{k}={bys[k]}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")) +
        f"  (total={s['total']})")
    out.append("-" * 78)
    if not findings:
        out.append("No findings. Clean image hygiene.")
        return "\n".join(out)
    out.append(f"{'LINE':>4}  {'SEVERITY':<9} {'RULE':<7} MESSAGE")
    for f in findings:
        out.append(f"{f.line:>4}  {f.severity.value:<9} {f.rule:<7} {f.message}")
        if f.remediation:
            out.append(f"        -> {f.remediation}")
    return "\n".join(out)


def render_html(source: str, findings: List[Finding]) -> str:
    s = summarize(findings)
    esc = html.escape
    rows = []
    for f in findings:
        color = _SEV_COLOR[f.severity.value]
        rows.append(f"""    <tr>
      <td class=\"ln\">{f.line}</td>
      <td><span class=\"badge\" style=\"background:{color}\">{f.severity.value}</span></td>
      <td class=\"rule\">{esc(f.rule)}</td>
      <td>{esc(f.instruction)}</td>
      <td class=\"msg\">{esc(f.message)}<div class=\"rem\">{esc(f.remediation)}</div></td>
    </tr>""")
    body = "\n".join(rows) if rows else (
        '<tr><td colspan="5" class="clean">No findings. Clean image hygiene.</td></tr>')
    bys = s["by_severity"]
    chips = "".join(
        f'<span class="chip" style="border-color:{_SEV_COLOR[k]};color:{_SEV_COLOR[k]}">'
        f'{k}: <b>{bys[k]}</b></span>'
        for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))
    return f"""<!DOCTYPE html>
<html lang=\"en\"><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>DOCKERAUDIT report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #f5f6f8; color: #1d2939; }}
  header {{ background: #0f172a; color: #fff; padding: 20px 28px; }}
  header h1 {{ margin: 0; font-size: 20px; }}
  header .src {{ color: #94a3b8; font-size: 13px; margin-top: 4px; word-break: break-all; }}
  .wrap {{ max-width: 1000px; margin: 24px auto; padding: 0 16px; }}
  .chips {{ margin: 0 0 18px; }}
  .chip {{ display: inline-block; border: 1px solid; border-radius: 999px;
          padding: 4px 12px; margin: 4px 8px 4px 0; font-size: 13px; background:#fff; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(16,24,40,.1); }}
  th, td {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid #eaecf0;
          font-size: 14px; vertical-align: top; }}
  th {{ background: #f9fafb; color: #475467; font-size: 12px; text-transform: uppercase;
        letter-spacing: .04em; }}
  td.ln {{ color: #667085; font-variant-numeric: tabular-nums; width: 48px; }}
  td.rule {{ font-family: ui-monospace, Menlo, Consolas, monospace; color:#344054; }}
  .badge {{ color: #fff; padding: 2px 9px; border-radius: 6px; font-size: 12px;
           font-weight: 600; }}
  .msg .rem {{ color: #667085; font-size: 12.5px; margin-top: 3px; }}
  .clean {{ text-align: center; color: #027a48; padding: 28px; font-weight: 600; }}
  footer {{ text-align: center; color: #98a2b3; font-size: 12px; margin: 24px 0; }}
</style></head>
<body>
<header>
  <h1>DOCKERAUDIT &mdash; container hygiene report</h1>
  <div class=\"src\">{esc(source)} &nbsp;&middot;&nbsp; {s['total']} finding(s)</div>
</header>
<div class=\"wrap\">
  <div class=\"chips\">{chips}</div>
  <table>
    <thead><tr><th>Line</th><th>Severity</th><th>Rule</th><th>Instr</th><th>Finding</th></tr></thead>
    <tbody>
{body}
    </tbody>
  </table>
  <footer>Generated by dockeraudit &middot; defensive static analysis &middot; stdlib-only</footer>
</div>
</body></html>"""
