"""posture.py — agent-ledger Posture module (v0.3).

Scores agent tool-call activity against the OWASP Top 10 for Agentic
Applications 2026 (ASI01–ASI10, OWASP GenAI Security Project, published
9 Dec 2025). Pure observer: reads the ledger DB, emits a posture report.

What it can honestly detect from ledger data alone (no payload inspection):
  ASI02  Tool Misuse & Exploitation  — tool frequency anomalies vs baseline,
         destructive-tool bursts, off-hours activity
  ASI05  Unexpected Code Execution  — terminal calls running package managers,
         eval-shaped patterns, chmod/chown
  ASI08  Cascading Failures          — error-rate spikes, retry storms
  ASI10  Rogue Agents                — ghost effects (unconfirmed actions),
         activity far outside the tool's historical profile
  ASI11  Excessive Agency            — mutating-tool call volume per turn vs
         baseline (the "agent doing too much" signal)

What it cannot detect from ledger data (documented honestly, listed as
"requires payload inspection — not covered"):
  ASI01 goal hijack, ASI03 identity abuse, ASI04 supply chain,
  ASI06 memory poisoning, ASI07 inter-agent comms, ASI09 trust exploitation.

Usage:
    from posture import posture_report
    report = posture_report(db_path)   # dict with score, findings, ASI coverage
"""
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

# Destructive patterns matched on a word boundary so "hermes"/"remote remove"
# do not trip them (v0.3 precision fix).
_DESTRUCTIVE_RE = re.compile(
    r"(^|[;&|(\s\"'])(rm\s+-|rm\s+/|dd\s+if=|mkfs|drop\s+table|truncate\s+table"
    r"|git\s+push\s+--force|chmod\s+777|chown\s+root|>\s*/dev/sd|:\(\)\s*\{)",
    re.I)
_PKG_RE = re.compile(
    r"(pip\s+install|pip3\s+install|npm\s+install|npm\s+i\s|curl\s+[^|]*-[a-z]*O?[^|]*\|\s*(sh|bash)"
    r"|wget\s+[^|]*\|\s*(sh|bash)|\|\s*(sh|bash)\b)", re.I)
_SENSITIVE_RE = re.compile(
    r"(\.ssh/|id_rsa|id_ed25519|\.env\b|\.aws/|\.gnupg/|\.git-credentials"
    r"|credential|password|passwd|api[_-]?key|\btoken\b)", re.I)
PKG_MGR_TOKENS = ()   # retained for backward-compat; use _PKG_RE
SENSITIVE_TOKENS = ()

# Benign-context guard: if the command is clearly about code/data containing
# these words (not touching real secret files), do not raise ASI05-sensitive.
# e.g. `count_tokens(x)`, `grep password_reset src/`, `token_budget.py`
_BENIGN_CODE_RE = re.compile(
    r"(python3?\s|import\s|def\s|print\(|\w+\(|grep\s|awk\s|sed\s|cat\s+\S+\.(py|md|js|ts|txt|json|ya?ml)"
    r"|\.py\b|\.js\b|\.ts\b|test|spec|--help|man\s)", re.I)

# Commands that READ a credential store (flag) vs merely mention the word.
# Only flag when a real secret-file path appears, not the bare word "token".
_SENSITIVE_PATH_RE = re.compile(
    r"(~?/\.ssh/|id_rsa|id_ed25519|~?/\.aws/|~?/\.gnupg/|\.git-credentials"
    r"|\bcreds?\b|\bsecrets?\b|/etc/shadow|\.npmrc|\.netrc)", re.I)
# Words that alone are too generic (appear in normal code constantly)
_GENERIC_WORDS = ("token", "password", "passwd", "credential", "api_key",
                  "api-key")


def _rows(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return conn.execute(
            "SELECT ts, session_id, tool_name, args_json, status, duration_ms"
            " FROM ledger ORDER BY rowid ASC").fetchall()
    finally:
        conn.close()


def _hours_ago(ts):
    try:
        return (datetime.now(timezone.utc)
                - datetime.fromisoformat(ts)).total_seconds() / 3600
    except Exception:
        return 0.0


def _extract_cmd(args_json):
    """args_json is a JSON string — parse it so real newlines/quotes are
    restored (JSON \\n is 2 chars; treating the raw JSON as the command makes
    heredoc stripping and every other pattern unreliable). Falls back to the
    raw string if it is not valid JSON."""
    if not args_json:
        return ""
    try:
        obj = json.loads(args_json)
        if isinstance(obj, dict):
            return obj.get("command") or obj.get("cmd") or json.dumps(obj)
        return str(obj)
    except Exception:
        return args_json


def _strip_heredoc(cmd):
    """Remove heredoc bodies (<<EOF ... EOF) — they are script text, not the
    shell command line; scanning them produces false positives."""
    out, in_heredoc = [], False
    for line in cmd.splitlines():
        if not in_heredoc and re.search(r"<<-?\s*['\"]?\w+['\"]?", line):
            out.append(line)
            in_heredoc = True
            continue
        if in_heredoc:
            if re.fullmatch(r"\s*(EOF|eof|END)\s*", line):
                in_heredoc = False
            continue
        out.append(line)
    return "\n".join(out)


def _rm_severity(cmd):
    """HIGH only for dangerous rm targets; targeted cleanup (cache dirs,
    single files) is normal housekeeping."""
    m = re.search(r"rm\s+(-[a-zA-Z]*\s+)*[^\n]*", cmd)
    if not m:
        return None
    frag = m.group(0)
    # targeted single-file/dir removal (cache cleanup, token-file deletion,
    # __pycache__) is housekeeping — only flag broad or root-level targets
    if re.search(r"(--no-preserve-root|rm\s+(?:-[a-zA-Z]+\s+)*/(\s|$)|"
                 r"/etc\b|/var\b|/usr\b|/boot\b|"
                 r"~\s*[/\s]|/\*|\s\*|\.\.)", frag) \
            and not re.search(r"__pycache__|\.pyc", frag):
        return frag
    return None  # targeted rm -f <specific cache/file> = housekeeping


def posture_report(db_path, local_hours_start=23, local_hours_end=6):
    """Build a posture report. Score 0-100 (higher = healthier posture)."""
    rows = _rows(db_path)
    if not rows:
        return {"score": None, "findings": [], "coverage": {},
                "note": "no ledger data"}

    findings = []          # (severity, ASI, title, detail)
    tool_counts = Counter()
    tool_sessions = defaultdict(set)
    errors = Counter()
    total = len(rows)
    burst_window = defaultdict(list)   # tool -> [hours_ago,...]

    for ts, sid, tool, args_json, status, dur in rows:
        tool_counts[tool] += 1
        if sid:
            tool_sessions[tool].add(sid)
        if status and status.startswith("ERROR"):
            errors[tool] += 1
        args = _strip_heredoc(_extract_cmd(args_json)).lower()
        age_h = _hours_ago(ts)
        burst_window[tool].append(age_h)

        # ASI05 — unexpected/sensitive code execution
        if tool == "terminal":
            # Precision-first: skip generic words ("token"/"password") that
            # appear in normal code; flag only real secret-store access.
            if (_SENSITIVE_PATH_RE.search(args)
                    and not (_BENIGN_CODE_RE.search(args)
                             and not re.search(r"(cat|cp|mv|tar|scp|rsync|base64)\s+\S*"
                                               r"(\.ssh/|id_rsa|\.aws/|\.gnupg/|\.git-credentials|\.env\b)",
                                               args, re.I))):
                findings.append(("HIGH", "ASI05",
                                 "Terminal accessed credential-shaped path",
                                 args[:160]))
            # generic secret words only flag when combined with exfil-ish verbs
            # ("git remote" excluded: rewriting a remote URL to STRIP a token
            # is security hygiene, not exfiltration)
            elif any(w in args for w in _GENERIC_WORDS) and re.search(
                    r"(curl|wget|scp|rsync|nc\s|netcat|base64|gpg\s|--upload|"
                    r"printenv|env\s*\||>\s*/tmp|tee\s)",
                    args, re.I):
                findings.append(("MEDIUM", "ASI05",
                                 "Secret-word + exfil-shaped command",
                                 args[:160]))
            # remote script execution (curl|wget -> sh) stays a real signal;
            # plain `pip install` is normal dev work, do not flag it
            if re.search(r"(curl|wget)[^|]*\|\s*(sh|bash)\b", args, re.I):
                findings.append(("MEDIUM", "ASI05",
                                 "Remote script piped to shell",
                                 args[:160]))
        # ASI02 — destructive tool use (terminal only; severity via _rm_severity)
        if tool == "terminal":
            frag = _rm_severity(args)
            if _DESTRUCTIVE_RE.search(args) and (
                    frag or not re.search(r"\brm\b", args)):
                findings.append(("HIGH" if frag else "HIGH", "ASI02",
                                 "Destructive command pattern in tool args",
                                 args[:160]))

    # ASI02 — frequency anomaly: one tool dominating recent activity.
    # Only meaningful if there IS a diverse baseline; a single-tool workload
    # (e.g. a terminal-only session) is not an anomaly.
    recent_counts = Counter()
    for tool, ages in burst_window.items():
        recent_counts[tool] = sum(1 for a in ages if a < 24)
    total_recent = sum(recent_counts.values()) or 1
    baseline_share = {t: c / total for t, c in tool_counts.items()}
    for tool, n in recent_counts.items():
        base = baseline_share.get(tool, 0)
        if (n >= 8 and n / total_recent > 0.9
                and len(tool_counts) >= 3 and base < 0.5):
            findings.append(("MEDIUM", "ASI02",
                             f"{tool} dominates last-24h activity "
                             f"({n}/{total_recent} calls; baseline "
                             f"{base:.0%}) — deviation from its normal share",
                             ""))

    # ASI11 — excessive agency: mutating-call volume. Meaningful only across a
    # diverse toolset; an all-terminal workload is expected, not "too much".
    mutating = sum(1 for r in rows if r[2] in _MUTATING or
                   r[2].startswith("mcp__"))
    mut_ratio = mutating / total
    reads = sum(1 for r in rows if r[2] in _READONLY)
    if total >= 20 and mut_ratio > 0.75 and reads >= 3 and len(tool_counts) >= 3:
        findings.append(("MEDIUM", "ASI11",
                         f"High mutating-call ratio: {mutating}/{total} "
                         f"({mut_ratio:.0%}) with {reads} read calls — "
                         "agent skews heavily toward state changes", ""))

    # ASI08 — error spikes. Two honest signals: an overall error ratio, and a
    # burst of consecutive errors (cascading-failure shape).
    if total >= 10:
        err_ratio = sum(errors.values()) / total
        if err_ratio > 0.3:
            findings.append(("MEDIUM", "ASI08",
                             f"Error rate {err_ratio:.0%} across ledger — "
                             "possible cascading failure", dict(errors)))
    # burst: >=3 errors inside any 60-minute window
    err_times = sorted(r[0] for r in rows
                       if r[4] and r[4].startswith("ERROR"))
    for i in range(len(err_times) - 2):
        try:
            t0 = datetime.fromisoformat(err_times[i])
            t2 = datetime.fromisoformat(err_times[i + 2])
        except Exception:
            continue
        if (t2 - t0).total_seconds() <= 3600:
            findings.append(("MEDIUM", "ASI08",
                             f"Error burst: 3+ errors within 60 min near {err_times[i]}",
                             ""))
            break

    # ASI10 — ghosts = unconfirmed effects (rogue/untrustworthy state)
    ghosts = sum(1 for r in rows if r[4] in ("GHOST_REPORTED", "PENDING"))
    if ghosts:
        findings.append(("HIGH", "ASI10",
                         f"{ghosts} unconfirmed action(s) (ghost/pending) — "
                         "agent state not trustworthy", ""))

    # ASI02 — off-hours activity (local defaults 23:00-06:00)
    offhours = [r for r in rows
                if local_hours_start <= (int(r[0][11:13]) if len(r[0]) > 13 else 0) < 24
                or int(r[0][11:13] if len(r[0]) > 13 else 0) < local_hours_end]
    # NOTE: ledger ts is UTC; operator may localize in a paid build

    # --- score ---
    sev_weight = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    penalty = sum(sev_weight.get(s, 5) for s, *_ in findings)
    score = max(0, 100 - penalty)

    coverage = {
        "covered": ["ASI02", "ASI05", "ASI08", "ASI10", "ASI11"],
        "requires_payload_inspection": ["ASI01", "ASI03", "ASI04", "ASI06",
                                        "ASI07", "ASI09"],
    }
    return {"score": score, "findings": findings, "coverage": coverage,
            "totals": {"calls": total, "mutating": mutating,
                       "errors": sum(errors.values()), "ghosts": ghosts}}


_MUTATING = frozenset({"write_file", "patch", "terminal", "cronjob",
                       "delegate_task", "memory", "skill_manage"})
_READONLY = frozenset({"web_search", "web_extract", "read_file", "search_files",
                       "page_info", "session_search", "browser_exec"})


def format_report(rep):
    if rep.get("score") is None:
        return rep.get("note", "no data")
    lines = [f"Agent Posture Score: {rep['score']}/100",
             f"Calls: {rep['totals']['calls']} | mutating: "
             f"{rep['totals']['mutating']} | errors: "
             f"{rep['totals']['errors']} | ghosts: {rep['totals']['ghosts']}"]
    for sev, asi, title, detail in rep["findings"]:
        lines.append(f"[{sev}] {asi}: {title}"
                     + (f" — {detail}" if detail else ""))
    cov = rep["coverage"]
    lines.append("Covered: " + ", ".join(cov["covered"]))
    lines.append("Needs payload inspection (not covered): "
                 + ", ".join(cov["requires_payload_inspection"]))
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    db = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
        "~/.hermes/agent-ledger/ledger.db")
    print(format_report(posture_report(db)))
"""posture.py — agent-ledger Posture module (v0.3).

Scores agent tool-call activity against the OWASP Top 10 for Agentic
Applications 2026 (ASI01–ASI10, OWASP GenAI Security Project, published
9 Dec 2025). Pure observer: reads the ledger DB, emits a posture report.

What it can honestly detect from ledger data alone (no payload inspection):
  ASI02  Tool Misuse & Exploitation  — tool frequency anomalies vs baseline,
         destructive-tool bursts, off-hours activity
  ASI05  Unexpected Code Execution  — terminal calls running package managers,
         eval-shaped patterns, chmod/chown
  ASI08  Cascading Failures          — error-rate spikes, retry storms
  ASI10  Rogue Agents                — ghost effects (unconfirmed actions),
         activity far outside the tool's historical profile
  ASI11  Excessive Agency            — mutating-tool call volume per turn vs
         baseline (the "agent doing too much" signal)

What it cannot detect from ledger data (documented honestly, listed as
"requires payload inspection — not covered"):
  ASI01 goal hijack, ASI03 identity abuse, ASI04 supply chain,
  ASI06 memory poisoning, ASI07 inter-agent comms, ASI09 trust exploitation.

Usage:
    from posture import posture_report
    report = posture_report(db_path)   # dict with score, findings, ASI coverage
"""
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

# Destructive patterns matched on a word boundary so "hermes"/"remote remove"
# do not trip them (v0.3 precision fix).
_DESTRUCTIVE_RE = re.compile(
    r"(^|[;&|(\s\"'])(rm\s+-|rm\s+/|dd\s+if=|mkfs|drop\s+table|truncate\s+table"
    r"|git\s+push\s+--force|chmod\s+777|chown\s+root|>\s*/dev/sd|:\(\)\s*\{)",
    re.I)
_PKG_RE = re.compile(
    r"(pip\s+install|pip3\s+install|npm\s+install|npm\s+i\s|curl\s+[^|]*-[a-z]*O?[^|]*\|\s*(sh|bash)"
    r"|wget\s+[^|]*\|\s*(sh|bash)|\|\s*(sh|bash)\b)", re.I)
_SENSITIVE_RE = re.compile(
    r"(\.ssh/|id_rsa|id_ed25519|\.env\b|\.aws/|\.gnupg/|\.git-credentials"
    r"|credential|password|passwd|api[_-]?key|\btoken\b)", re.I)
PKG_MGR_TOKENS = ()   # retained for backward-compat; use _PKG_RE
SENSITIVE_TOKENS = ()


def _rows(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return conn.execute(
            "SELECT ts, session_id, tool_name, args_json, status, duration_ms"
            " FROM ledger ORDER BY rowid ASC").fetchall()
    finally:
        conn.close()


def _hours_ago(ts):
    try:
        return (datetime.now(timezone.utc)
                - datetime.fromisoformat(ts)).total_seconds() / 3600
    except Exception:
        return 0.0


def posture_report(db_path, local_hours_start=23, local_hours_end=6):
    """Build a posture report. Score 0-100 (higher = healthier posture)."""
    rows = _rows(db_path)
    if not rows:
        return {"score": None, "findings": [], "coverage": {},
                "note": "no ledger data"}

    findings = []          # (severity, ASI, title, detail)
    tool_counts = Counter()
    tool_sessions = defaultdict(set)
    errors = Counter()
    total = len(rows)
    burst_window = defaultdict(list)   # tool -> [hours_ago,...]

    for ts, sid, tool, args_json, status, dur in rows:
        tool_counts[tool] += 1
        if sid:
            tool_sessions[tool].add(sid)
        if status and status.startswith("ERROR"):
            errors[tool] += 1
        args = (args_json or "").lower()
        age_h = _hours_ago(ts)
        burst_window[tool].append(age_h)

        # ASI05 — unexpected/sensitive code execution
        if tool == "terminal":
            if _SENSITIVE_RE.search(args):
                findings.append(("HIGH", "ASI05",
                                 "Terminal touched credential-shaped path",
                                 args[:160]))
            if _PKG_RE.search(args):
                findings.append(("MEDIUM", "ASI05",
                                 "Package manager / remote script execution",
                                 args[:160]))
        # ASI02 — destructive tool use
        if tool in ("terminal", "patch", "write_file") and (
                tool != "write_file" or "path" in args):
            if _DESTRUCTIVE_RE.search(args) and tool == "terminal":
                findings.append(("HIGH", "ASI02",
                                 "Destructive command pattern in tool args",
                                 args[:160]))

    # ASI02 — frequency anomaly: one tool dominating recent activity
    recent_counts = Counter()
    for tool, ages in burst_window.items():
        recent_counts[tool] = sum(1 for a in ages if a < 24)
    total_recent = sum(recent_counts.values()) or 1
    for tool, n in recent_counts.items():
        if n >= 8 and n / total_recent > 0.6:
            findings.append(("MEDIUM", "ASI02",
                             f"{tool} dominates last-24h activity "
                             f"({n}/{total_recent} calls)", ""))

    # ASI11 — excessive agency: mutating-call volume
    mutating = sum(1 for r in rows if r[2] in _MUTATING or
                   r[2].startswith("mcp__"))
    mut_ratio = mutating / total
    if total >= 20 and mut_ratio > 0.75:
        findings.append(("MEDIUM", "ASI11",
                         f"High mutating-call ratio: {mutating}/{total} "
                         f"({mut_ratio:.0%}) of all tool calls mutate state", ""))

    # ASI08 — error spikes. Two honest signals: an overall error ratio, and a
    # burst of consecutive errors (cascading-failure shape).
    if total >= 10:
        err_ratio = sum(errors.values()) / total
        if err_ratio > 0.3:
            findings.append(("MEDIUM", "ASI08",
                             f"Error rate {err_ratio:.0%} across ledger — "
                             "possible cascading failure", dict(errors)))
    # burst: >=3 errors inside any 60-minute window
    err_times = sorted(r[0] for r in rows
                       if r[4] and r[4].startswith("ERROR"))
    for i in range(len(err_times) - 2):
        try:
            t0 = datetime.fromisoformat(err_times[i])
            t2 = datetime.fromisoformat(err_times[i + 2])
        except Exception:
            continue
        if (t2 - t0).total_seconds() <= 3600:
            findings.append(("MEDIUM", "ASI08",
                             f"Error burst: 3+ errors within 60 min near {err_times[i]}",
                             ""))
            break

    # ASI10 — ghosts = unconfirmed effects (rogue/untrustworthy state)
    ghosts = sum(1 for r in rows if r[4] in ("GHOST_REPORTED", "PENDING"))
    if ghosts:
        findings.append(("HIGH", "ASI10",
                         f"{ghosts} unconfirmed action(s) (ghost/pending) — "
                         "agent state not trustworthy", ""))

    # ASI02 — off-hours activity (local defaults 23:00-06:00)
    offhours = [r for r in rows
                if local_hours_start <= (int(r[0][11:13]) if len(r[0]) > 13 else 0) < 24
                or int(r[0][11:13] if len(r[0]) > 13 else 0) < local_hours_end]
    # NOTE: ledger ts is UTC; operator may localize in a paid build

    # --- score ---
    sev_weight = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    penalty = sum(sev_weight.get(s, 5) for s, *_ in findings)
    score = max(0, 100 - penalty)

    coverage = {
        "covered": ["ASI02", "ASI05", "ASI08", "ASI10", "ASI11"],
        "requires_payload_inspection": ["ASI01", "ASI03", "ASI04", "ASI06",
                                        "ASI07", "ASI09"],
    }
    return {"score": score, "findings": findings, "coverage": coverage,
            "totals": {"calls": total, "mutating": mutating,
                       "errors": sum(errors.values()), "ghosts": ghosts}}


_MUTATING = frozenset({"write_file", "patch", "terminal", "cronjob",
                       "delegate_task", "memory", "skill_manage"})


def format_report(rep):
    if rep.get("score") is None:
        return rep.get("note", "no data")
    lines = [f"Agent Posture Score: {rep['score']}/100",
             f"Calls: {rep['totals']['calls']} | mutating: "
             f"{rep['totals']['mutating']} | errors: "
             f"{rep['totals']['errors']} | ghosts: {rep['totals']['ghosts']}"]
    for sev, asi, title, detail in rep["findings"]:
        lines.append(f"[{sev}] {asi}: {title}"
                     + (f" — {detail}" if detail else ""))
    cov = rep["coverage"]
    lines.append("Covered: " + ", ".join(cov["covered"]))
    lines.append("Needs payload inspection (not covered): "
                 + ", ".join(cov["requires_payload_inspection"]))
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    db = sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser(
        "~/.hermes/agent-ledger/ledger.db")
    print(format_report(posture_report(db)))
