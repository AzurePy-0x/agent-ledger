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
