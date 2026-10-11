#!/usr/bin/env python3
"""posture_daily.py — scheduled Agent Posture audit → Telegram (v0.3.4).

Runs daily via cron. Reads the live ledger, scores posture, and sends a
compact report to Telegram. This is the free-tier seed of "posture pro"
(the paid build adds policy packs, per-session reports, dashboard).

Env:
  POSTURE_TELEGRAM_BOT_TOKEN   bot token (own env only - never Hermes .env)
  POSTURE_TELEGRAM_CHAT_ID     chat id (own env only)
  POSTURE_LEDGER_DB            ledger path (default <hermes_home>/plugin-data/agent-ledger/ledger.db)
  POSTURE_STATE_DIR            state dir (default <hermes_home>/plugin-data/agent-ledger)

State: ~/.hermes/agent-ledger/posture_state.json remembers the last score
so the report can show a delta (score going DOWN is the alert-worthy signal).

Exit codes: 0 sent/skipped-ok, 1 config error, 2 send failure.
"""
import json
import os
import sqlite3
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from posture import posture_report, format_report  # noqa: E402

def _hermes_home():
    """Active Hermes home (profile-aware). Falls back to ~/.hermes."""
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:
        return os.path.expanduser("~/.hermes")


STATE_DIR = os.environ.get(
    "POSTURE_STATE_DIR",
    os.path.join(_hermes_home(), "plugin-data", "agent-ledger"))
STATE_FILE = os.path.join(STATE_DIR, "posture_state.json")
LEDGER = os.environ.get(
    "POSTURE_LEDGER_DB",
    os.path.join(_hermes_home(), "plugin-data", "agent-ledger", "ledger.db"))



def send_telegram(token, chat_id, text):
    url = (f"https://api.telegram.org/bot{token}/sendMessage?"
           + urllib.parse.urlencode(
               {"chat_id": chat_id, "text": text,
                "parse_mode": "HTML", "disable_web_page_preview": "true"}))
    req = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())
        if not body.get("ok"):
            raise RuntimeError(f"telegram api: {body}")
        return body


def policy_hits(since_ts):
    """Count + sample POLICY_WOULD_BLOCK rows since last report."""
    try:
        conn = sqlite3.connect(f"file:{LEDGER}?mode=ro", uri=True)
        n = conn.execute(
            "SELECT COUNT(*) FROM ledger WHERE status='POLICY_WOULD_BLOCK'"
            " AND ts > ?", (since_ts,)).fetchone()[0]
        sample = conn.execute(
            "SELECT ts, tool_name, result_digest FROM ledger"
            " WHERE status='POLICY_WOULD_BLOCK' AND ts > ?"
            " ORDER BY id DESC LIMIT 5", (since_ts,)).fetchall()
        conn.close()
        return n, sample
    except Exception:
        return 0, []


def build_message(rep, prev_score, since_calls, since_ts=""):
    lines = []
    score = rep["score"]
    arrow = ""
    if prev_score is not None and score is not None:
        d = score - prev_score
        arrow = f" ({'+' if d >= 0 else ''}{d} vs kemarin)"
    lines.append(f"🛡 <b>Agent Posture harian</b>: {score}/100{arrow}")
    t = rep["totals"]
    lines.append(
        f"<i>{t['calls']} calls (+{since_calls} baru) | "
        f"mutating {t['mutating']} | errors {t['errors']} | "
        f"ghosts {t['ghosts']}</i>")
    findings = rep["findings"]
    if findings:
        lines.append("")
        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪️", "CRITICAL": "🚨"}
        # top 5 by severity, dedup by (asi, title)
        seen, shown = set(), 0
        for sev, asi, title, detail in findings:
            key = (asi, title)
            if key in seen or shown >= 5:
                continue
            seen.add(key)
            lines.append(f"{icon.get(sev, '•')} <b>{asi}</b> [{sev}] {title}")
            shown += 1
        extra = len(findings) - shown
        if extra > 0:
            lines.append(f"<i>…+{extra} more findings</i>")
    else:
        lines.append("✅ No findings. Posture is clean.")
    lines.append("")
    lines.append("Covered: " + ", ".join(rep["coverage"]["covered"]))

    # policy dry-run section
    n_hits, samples = policy_hits(since_ts)
    if n_hits:
        lines.append("")
        lines.append(f"🚧 <b>Policy (dry-run)</b>: {n_hits} call(s) WOULD be blocked:")
        for ts, tool, reason in samples:
            lines.append(f"• {tool}: {reason} <i>({ts})</i>")
    return "\n".join(lines)


def main():
    # Catalog rule 11: credentials only via the caller's own environment.
    # This script NEVER reads Hermes's .env or reuses Hermes's bot token -
    # give it POSTURE_TELEGRAM_BOT_TOKEN / POSTURE_TELEGRAM_CHAT_ID directly.
    token = os.environ.get("POSTURE_TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("POSTURE_TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        print("posture_daily: set POSTURE_TELEGRAM_BOT_TOKEN and "
              "POSTURE_TELEGRAM_CHAT_ID in the script's own environment "
              "(a dedicated bot is recommended)", file=sys.stderr)
        return 1
    if not os.path.exists(LEDGER):
        print(f"posture_daily: ledger not found: {LEDGER}", file=sys.stderr)
        return 1

    # calls since yesterday's run (delta stat)
    since_calls = 0
    prev = {}
    try:
        with open(STATE_FILE) as f:
            prev = json.load(f)
        conn = sqlite3.connect(f"file:{LEDGER}?mode=ro", uri=True)
        since_calls = conn.execute(
            "SELECT COUNT(*) FROM ledger WHERE ts > ?",
            (prev.get("last_ts", ""),)).fetchone()[0]
        last_ts = conn.execute(
            "SELECT MAX(ts) FROM ledger").fetchone()[0]
        conn.close()
    except Exception:
        last_ts = datetime.now(timezone.utc).isoformat()

    rep = posture_report(LEDGER)
    msg = build_message(rep, prev.get("score"), since_calls,
                        prev.get("last_ts", ""))

    # dry-run mode for testing
    if os.environ.get("POSTURE_DRY_RUN"):
        print(msg)
        return 0

    try:
        send_telegram(token, chat_id, msg)
    except Exception as e:
        print(f"posture_daily: send failed: {e}", file=sys.stderr)
        return 2

    os.makedirs(STATE_DIR, exist_ok=True)
    with open(STATE_FILE, "w") as f:
        json.dump({"score": rep["score"], "last_ts": last_ts,
                   "sent_at": datetime.now(timezone.utc).isoformat()}, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
