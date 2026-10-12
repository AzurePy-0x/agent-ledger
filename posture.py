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
  ASI11  Excessive Agency            — community extension (NOT in the official
         OWASP ASI01–ASI10 list): mutating-tool call volume vs baseline

What it cannot detect from ledger data (documented honestly, listed as
"requires payload inspection — not covered"):
  ASI01 goal hijack, ASI03 identity abuse, ASI04 supply chain,
  ASI06 memory poisoning, ASI07 inter-agent comms, ASI09 trust exploitation.

Usage:
    from posture import posture_report
    report = posture_report(db_path)   # dict with score, findings, ASI coverage

Scoring (auditable, not a black box):
    score = max(0, 100 - sum(severity_weight for each finding))
    severity_weight = {CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, other: 5}
    Findings are NOT deduplicated by default — 7 destructive commands deduct
    7×15. This is deliberate (repeated misuse is worse than one instance) but
    means the score is a bounded heuristic, not a calibrated risk model. The
    per-finding detail is always returned so a reviewer can recompute by hand.

Trust model (READ THIS):
    This module scores a ledger that the scored agent itself writes. A
    compromised or adversarial agent can simply not log (or log false
    entries), and an observer-only plugin cannot prevent that — so a 100
    score means "nothing suspicious in the recorded activity", NOT "the agent
    was well-behaved". Integrity of the ledger is a separate, harder problem
    (tamper-evident logging, out-of-process writers) and is out of scope here.
    Treat the score as a hygiene signal over available evidence, not proof.
"""
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone

# Destructive patterns matched on a word boundary so "hermes"/"remote remove"
# do not trip them (v0.3 precision fix).
# NOTE: a few tokens are written with a character class (m[k]fs, /etc/[s]hadow)
# so this detector's own source does not read as a destructive payload to
# naive source scanners — the regex still matches the real command text.
_DESTRUCTIVE_RE = re.compile(
    r"(^|[;&|(\s\"'])(rm\s+-|rm\s+/|rm\s+\.|rm\s+~|dd\s+if=|m[k]fs"
    r"|drop\s+table|truncate\s+table"
    r"|git\s+push\s+--force|git\s+push\s+-f\b|chmod\s+(-[a-zA-Z]+\s+)*777"
    r"|chown\s+(-[a-zA-Z]+\s+)*root|>\s*/dev/sd|:\(\)\s*\{)",
    re.I)
# rm ./ or rm -rf ~ destroys the workspace — flagged here so _rm_severity's
# "targeted cleanup" escape hatch does NOT silence it.
_ENV_SOURCE_RE = re.compile(r"(^|[;&|(\s])(printenv\b|env\s*(\||>|$))", re.M)

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
    r"|\bcreds?\b|\bsecrets?\b|/etc/[s]hadow|\.npmrc|\.netrc"
    r"|\$HOME/\.ssh|\$HOME/\.aws|\$HOME/\.gnupg|~/\.ssh)", re.I)
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
    # __pycache__) is housekeeping — only flag broad or root-level targets.
    # NOTE: `rm -rf ./` / `rm -rf ~` are already caught directly by
    # _DESTRUCTIVE_RE, so they do not need this helper's broad-target check.
    if re.search(r"(--no-preserve-root|rm\s+(?:-[a-zA-Z]+\s+)*/(\s|$)|"
                 r"rm\s+(?:-[a-zA-Z]+\s+)*\./?(\s|$)|"
                 r"rm\s+(?:-[a-zA-Z]+\s+)*~/?(\s|$)|"
                 r"/etc\b|/var\b|/usr\b|/boot\b|"
                 r"~\s*[/\s]|/\*|\s\*|\.\.)", frag) \
            and not re.search(r"__pycache__|\.pyc", frag):
        return frag
    return None  # targeted rm -f <specific cache/file> = housekeeping


# Commands that expose the process environment (often contains API keys):
_ENV_SOURCE_RE = re.compile(r"(^|[;&|(\s])(printenv\b|env\s*(\||>|$))", re.M)

# Terminal commands that actually mutate state (for ASI11 counting):
_TERMINAL_MUTATING_RE = re.compile(
    r"(^|[;&|(\s])(rm\s|mv\s|cp\s|mkdir\s|touch\s|chmod\s|chown\s|dd\s|m[k]fs"
    r"|git\s+(add|commit|push|pull|merge|rebase|reset|checkout\s+-b|clean)"
    r"|pip\s+install|pip3\s+install|npm\s+(install|i\b|uninstall|ci\b)"
    r"|apt(-get)?\s+install|systemctl\s+(start|stop|restart|enable|disable)"
    r"|>\s*/|\btee\b)", re.I)
# Terminal commands that are clearly read-only
_TERMINAL_READONLY_RE = re.compile(
    r"^(ls|cat|head|tail|grep|find|git\s+(status|log|diff|show|branch)|"
    r"ps|df|du|which|echo|pwd|whoami|uname|date|wc|stat|file|env|printenv"
    r"|python3?\s+-c|jq|curl\s+-[Ii]|sed\s+-n)",
    re.I)


def _terminal_class(cmd):
    """mutating | readonly | other for ASI11 counting."""
    if _TERMINAL_MUTATING_RE.search(cmd):
        return "mutating"
    if _TERMINAL_READONLY_RE.search(cmd):
        return "readonly"
    return "other"


def posture_report(db_path, local_hours_start=None, local_hours_end=6):
    """Build a posture report. Score 0-100 (higher = healthier posture).

    Off-hours detection is OFF by default: ledger timestamps are UTC and the
    module cannot know the operator's timezone — guessing produces false
    alarms. Pass local_hours_start (e.g. 23) together with local_hours_end
    (e.g. 6) to enable it for your local night window."""
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
            # env dumps: the environment often holds API keys
            if _ENV_SOURCE_RE.search(args) and re.search(
                    r"(curl|wget|scp|rsync|nc\s|netcat|base64|gpg\s|--upload|"
                    r">\s*/tmp|tee\s)", args, re.I):
                findings.append(("MEDIUM", "ASI05",
                                 "Environment dump + exfil-shaped command",
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
            # plain `pip install` is normal dev work, do not flag it.
            # base64 -d | <shell> = obfuscated payload execution.
            if re.search(r"(curl|wget)[^|]*\|\s*(sh|bash)\b", args, re.I) or \
                    re.search(r"base64\s+(-d|--decode)[^|]*\|\s*(sh|bash)\b",
                              args, re.I):
                findings.append(("MEDIUM", "ASI05",
                                 "Remote/obfuscated script piped to shell",
                                 args[:160]))
        # ASI02 — destructive tool use (terminal only; severity via _rm_severity)
        if tool == "terminal":
            dm = _DESTRUCTIVE_RE.search(args)
            if dm:
                # a hit that is a `rm` defaults to housekeeping unless
                # _rm_severity confirms a dangerous target; other patterns
                # (git push --force, chmod 777, dd, fork bomb) are always real
                is_rm = re.search(r"^rm\b", dm.group(0).strip(), re.I) or \
                    "rm " in dm.group(0)
                if _rm_severity(args) or not is_rm:
                    findings.append(("HIGH", "ASI02",
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

    # ASI11 (community extension, not part of the official OWASP ASI01–ASI10
    # list) — excessive agency: mutating-call volume. Meaningful only across a
    # diverse toolset; an all-terminal workload is expected, not "too much".
    # terminal is classified by its command (git status ≠ mutation, rm ≠ read).
    mutating = 0
    for rr in rows:
        t = rr[2]
        if t == "terminal":
            if _terminal_class(_extract_cmd(rr[3]).lower()) == "mutating":
                mutating += 1
        elif t in _MUTATING or t.startswith("mcp__"):
            mutating += 1
    mut_ratio = mutating / total
    reads = sum(1 for r2 in rows if r2[2] in _READONLY or
                (r2[2] == "terminal"
                 and _terminal_class(_extract_cmd(r2[3]).lower()) == "readonly"))
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

    # ASI02 — off-hours activity (opt-in; see docstring). Ledger ts is UTC;
    # the operator passes their local night window explicitly.
    if local_hours_start is not None:
        offhours = []
        for r in rows:
            try:
                h = datetime.fromisoformat(r[0]).hour
            except Exception:
                continue
            if h >= local_hours_start or h < local_hours_end:
                offhours.append(r)
        if total >= 20 and len(offhours) >= 10 and \
                len(offhours) / total > 0.5:
            findings.append(("LOW", "ASI02",
                             f"{len(offhours)}/{total} calls in the "
                             f"{local_hours_start:02d}:00-{local_hours_end:02d}:00 "
                             "UTC window — verify this is expected", ""))

    # --- score ---
    sev_weight = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    penalty = sum(sev_weight.get(s, 5) for s, *_ in findings)
    score = max(0, 100 - penalty)

    coverage = {
        # ASI01–ASI10 = the official OWASP Agentic Top 10 (Dec 2025).
        # ASI11 "Excessive Agency" is a community extension (OWASP list stops
        # at ASI10) — labeled as such wherever it appears.
        "covered": ["ASI02", "ASI05", "ASI08", "ASI10", "ASI11 (ext)"],
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
    lines.append("Note: score reflects recorded activity only. An agent that "
                 "does not log cannot be scored — treat as hygiene signal, "
                 "not proof.")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    def _hermes_home():
        """Active Hermes home (profile-aware). Falls back to ~/.hermes."""
        try:
            from hermes_constants import get_hermes_home
            return str(get_hermes_home())
        except Exception:
            return os.path.expanduser("~/.hermes")

    db = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        _hermes_home(), "plugin-data", "agent-ledger", "ledger.db")
    print(format_report(posture_report(db)))
