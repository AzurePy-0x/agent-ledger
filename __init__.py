"""agent-ledger — write-ahead ledger for Hermes agent side effects.

Every state-mutating tool call is written as PENDING before it executes and
updated to CONFIRMED after it returns. A reconciliation pass on session
boundaries flags PENDING entries that never confirmed: operations the agent
issued but whose effects were silently lost (e.g. turn torn down by context
compaction — NousResearch/hermes-agent issue #90985).

Observer-only: never blocks, never transforms. Writes are sub-10ms SQLite
inserts on a dedicated connection with WAL mode.
"""
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

# Tools whose success mutates persistent state. Everything else is read-only
# from the ledger's point of view. MCP calls (mcp__*) are covered by prefix match.
MUTATING_TOOLS = frozenset({
    "write_file", "patch", "terminal", "cronjob", "delegate_task",
    "kanban_create", "kanban_complete", "kanban_block", "kanban_unblock",
    "kanban_assign", "kanban_comment", "memory", "skill_manage",
})
_MUTATING_PREFIXES = ("mcp__",)

# Long-running tools whose PENDING window legitimately spans many minutes.
# Reconciliation only alerts on these past a grace period, not immediately.
GRACE_SECONDS = 120

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ledger.db")
_alert_fn = None  # set by register() from ctx, used for Telegram alerts


class _Ledger:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                session_id TEXT,
                tool_call_id TEXT,
                tool_name TEXT NOT NULL,
                args_json TEXT,
                status TEXT NOT NULL DEFAULT 'PENDING',
                result_digest TEXT,
                duration_ms INTEGER,
                confirmed_ts TEXT
            )""")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_status ON ledger(status)")
        self._conn.commit()

    def pending(self, tool_name, tool_call_id, args, session_id):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            args_json = json.dumps(args, default=str)[:4000]
        except Exception:
            args_json = str(args)[:4000]
        with self._lock:
            self._conn.execute(
                "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status)"
                " VALUES (?,?,?,?,?,'PENDING')",
                (now, session_id, tool_call_id, tool_name, args_json))
            self._conn.commit()

    def confirm(self, tool_name, tool_call_id, result, duration_ms, status):
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        digest = None
        if result is not None:
            digest = str(result)[:300]
        with self._lock:
            cur = None
            if tool_call_id:
                cur = self._conn.execute(
                    "UPDATE ledger SET status=?, result_digest=?, duration_ms=?, confirmed_ts=?"
                    " WHERE tool_call_id=? AND status='PENDING'",
                    (status, digest, duration_ms, now, tool_call_id))
            # fallback: match by tool+recency when no call id present or it missed
            if tool_call_id is None or (cur is not None and cur.rowcount == 0):
                self._conn.execute(
                    "UPDATE ledger SET status=?, result_digest=?, duration_ms=?, confirmed_ts=?"
                    " WHERE id = (SELECT id FROM ledger WHERE tool_name=? AND status='PENDING'"
                    " ORDER BY id DESC LIMIT 1)",
                    (status, digest, duration_ms, now, tool_name))
            self._conn.commit()

    def reconcile(self, session_id=None):
        """Return PENDING entries older than the grace period (ghost candidates)."""
        cutoff = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, session_id, tool_name, args_json FROM ledger"
                " WHERE status='PENDING' AND ts <= ?"
                " ORDER BY id DESC LIMIT 50", (cutoff,)).fetchall()
        ghosts = []
        for rid, ts, sid, tool, args_json in rows:
            try:
                age = (datetime.now(timezone.utc) -
                       datetime.fromisoformat(ts)).total_seconds()
            except Exception:
                age = 0
            if age >= GRACE_SECONDS:
                ghosts.append({"id": rid, "ts": ts, "session_id": sid,
                               "tool": tool, "args": args_json})
        return ghosts

    def mark_ghost_reported(self, rid):
        with self._lock:
            self._conn.execute(
                "UPDATE ledger SET status='GHOST_REPORTED' WHERE id=?", (rid,))
            self._conn.commit()


_LEDGER = None


def _get_ledger():
    global _LEDGER
    if _LEDGER is None:
        _LEDGER = _Ledger(DB_PATH)
    return _LEDGER


def _is_mutating(tool_name):
    return tool_name in MUTATING_TOOLS or tool_name.startswith(_MUTATING_PREFIXES)


def _alert(text):
    if _alert_fn:
        try:
            _alert_fn(text)
        except Exception:
            pass


# ---------------- hooks ----------------

def on_pre_tool_call(tool_name, args, task_id=None, tool_call_id=None,
                     session_id=None, **kwargs):
    if not _is_mutating(tool_name):
        return None
    try:
        _get_ledger().pending(tool_name, tool_call_id, args, session_id or task_id)
    except Exception:
        pass  # observer-only: never break the tool path
    return None


def on_post_tool_call(tool_name, args=None, result=None, task_id=None,
                      tool_call_id=None, duration_ms=0, status=None,
                      error_type=None, **kwargs):
    if not _is_mutating(tool_name):
        return None
    final = "CONFIRMED"
    if status is not None and status != "ok":
        final = f"ERROR:{status}"
    elif error_type:
        final = f"ERROR:{error_type}"
    try:
        _get_ledger().confirm(tool_name, tool_call_id, result, duration_ms, final)
    except Exception:
        pass
    return None


def reconcile_and_alert(session_id=None, **kwargs):
    ghosts = _get_ledger().reconcile()
    for g in ghosts:
        _alert(
            f"⚠️ agent-ledger GHOST EFFECT: {g['tool']} issued {g['ts']} "
            f"(session {g['session_id']}) never confirmed.\nargs: {g['args'][:300]}")
        _get_ledger().mark_ghost_reported(g["id"])
    if ghosts:
        # inject into the turn's context so the agent + user see it immediately
        lines = "\n".join(
            f"- {g['tool']} @ {g['ts']} (session {g['session_id']}): issued but NEVER confirmed"
            for g in ghosts)
        return {"context": (
            "⚠️ agent-ledger: the following agent actions were issued earlier but never "
            "confirmed completed (likely lost to a turn teardown / compaction). "
            "Verify whether their effects actually happened before trusting state:\n" + lines)}
    return None


def register(ctx):
    global _alert_fn, DB_PATH
    try:
        # prefer a DB under the active profile's hermes home
        home = getattr(ctx, "hermes_home", None) or os.path.expanduser("~/.hermes")
        data_dir = os.path.join(home, "agent-ledger")
        os.makedirs(data_dir, exist_ok=True)
        DB_PATH = os.path.join(data_dir, "ledger.db")
    except Exception:
        pass
    try:
        _alert_fn = None  # MVP: ghosts surface via pre_llm_call injection below
    except Exception:
        _alert_fn = None

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("pre_llm_call", reconcile_and_alert)
    ctx.register_hook("on_session_start", reconcile_and_alert)
