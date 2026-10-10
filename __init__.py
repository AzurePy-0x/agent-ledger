"""agent-ledger — write-ahead ledger for Hermes agent side effects.

Every state-mutating tool call is written as PENDING before it executes and
updated to CONFIRMED after it returns. A reconciliation pass on session
boundaries flags PENDING entries that never confirmed: operations the agent
issued but whose effects were silently lost (e.g. turn torn down by context
compaction — NousResearch/hermes-agent issue #90985).

Observer-first: never breaks the tool path. Writes are sub-10ms SQLite
inserts on a dedicated connection with WAL mode.

Policy engine (v0.4.0, free — enforcement included):
  If ~/.hermes/agent-ledger/policy.json exists, every mutating tool call is
  checked against it in on_pre_tool_call. Matching `block` rules return
  {"action": "block", "reason": ...} to the hook (the agent's call is
  refused before it runs). Matching `allow` rules exempt the call.
  POLICY_MODE controls behavior:
    "off"       → policy ignored entirely (default until you opt in)
    "dry_run"   → blocks are only LOGGED (ledger status POLICY_WOULD_BLOCK)
                  and surfaced as a context note; nothing is actually blocked
    "enforce"   → blocks are real
  This ordering lets you observe what WOULD be blocked for a few days
  before trusting the engine with enforcement. No license, no gate —
  the whole plugin is free (MIT).

Matching model (v0.2):
  pre_tool_call  inserts a PENDING row keyed by (tool_name, session_id) and,
                 when available, tool_call_id.
  post_tool_call confirms: exact tool_call_id match first; otherwise the
                 OLDEST still-PENDING row for the same (tool_name, session_id)
                 — FIFO, never LIFO. Hermes occasionally fires pre/post with an
                 empty tool_call_id on one side only, so by-id-only matching
                 strands rows; FIFO-per-session is the robust pairing.
  reconcile      a PENDING row is only a ghost if NO confirmed/error row for
                 the same (tool_name, session_id) exists at a later ts.
"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

# Tools whose success mutates persistent state. Everything else is read-only
# from the ledger's point of view. MCP calls (mcp__*) are covered by prefix match.
MUTATING_TOOLS = frozenset({
    "write_file", "patch", "terminal", "cronjob", "delegate_task",
    "kanban_create", "kanban_complete", "kanban_block", "kanban_unblock",
    "kanban_assign", "kanban_comment", "memory", "skill_manage",
})
_MUTATING_PREFIXES = ("mcp__",)

# A PENDING row younger than this is never reported: still legitimately in flight.
GRACE_SECONDS = 180

_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ledger.db")
_alert_fn = None

# Policy engine state (loaded once per process; refresh via reload_policy())
_policy_rules = None
_policy_mode = "off"  # off | dry_run | enforce
POLICY_MODE_ENV = "AGENT_LEDGER_POLICY_MODE"


def _policy_mode_setting():
    return os.environ.get(POLICY_MODE_ENV, _policy_mode)


def load_policy_for_hook():
    """Load rules + mode. Mode: env var > ~/.hermes/agent-ledger/policy_mode > off."""
    global _policy_rules, _policy_mode
    import policy as _policy
    _policy_rules = _policy.load_policy()
    mode_file = os.path.join(os.path.dirname(DB_PATH), "policy_mode")
    mode = "off"
    if os.path.isfile(mode_file):
        try:
            with open(mode_file) as f:
                mode = f.read().strip().lower()
        except Exception:
            pass
    mode = os.environ.get(POLICY_MODE_ENV, mode).strip().lower()
    _policy_mode = mode if mode in ("off", "dry_run", "enforce") else "off"
    return _policy_rules, _policy_mode


def reload_policy():
    """Re-read policy.json + mode (call after editing policy files)."""
    global _policy_rules
    _policy_rules = None
    return load_policy_for_hook()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ledger_sess_tool ON ledger(session_id, tool_name, status)")
        self._conn.commit()

    def pending(self, tool_name, tool_call_id, args, session_id):
        try:
            args_json = json.dumps(args, default=str)[:4000]
        except Exception:
            args_json = str(args)[:4000]
        with self._lock:
            self._conn.execute(
                "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status)"
                " VALUES (?,?,?,?,?,'PENDING')",
                (_now(), session_id or "", tool_call_id or "", tool_name, args_json))
            self._conn.commit()

    def confirm(self, tool_name, tool_call_id, session_id, result, duration_ms, status):
        digest = None if result is None else str(result)[:300]
        ts = _now()
        with self._lock:
            rowid = None
            if tool_call_id:
                row = self._conn.execute(
                    "SELECT id FROM ledger WHERE tool_call_id=? AND status='PENDING'"
                    " ORDER BY id ASC LIMIT 1", (tool_call_id,)).fetchone()
                rowid = row[0] if row else None
            if rowid is None:
                # FIFO: oldest still-PENDING row for this tool+session. Never LIFO —
                # with concurrent calls LIFO confirms the wrong row and strands the rest.
                row = self._conn.execute(
                    "SELECT id FROM ledger WHERE tool_name=? AND session_id=? AND status='PENDING'"
                    " ORDER BY id ASC LIMIT 1", (tool_name, session_id or "")).fetchone()
                if row is None:
                    row = self._conn.execute(
                        "SELECT id FROM ledger WHERE tool_name=? AND status='PENDING'"
                        " ORDER BY id ASC LIMIT 1", (tool_name,)).fetchone()
                rowid = row[0] if row else None
            if rowid is not None:
                self._conn.execute(
                    "UPDATE ledger SET status=?, result_digest=?, duration_ms=?,"
                    " confirmed_ts=?, tool_call_id=COALESCE(NULLIF(tool_call_id,''),?)"
                    " WHERE id=?",
                    (status, digest, duration_ms, ts, tool_call_id or "", rowid))
            else:
                # post without any pre (pre hook missed/suppressed) — record the fact.
                self._conn.execute(
                    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json,"
                    " status, result_digest, duration_ms, confirmed_ts)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (ts, session_id or "", tool_call_id or "", tool_name, None,
                     status, digest, duration_ms, ts))
            self._conn.commit()

    def reconcile(self):
        """Return genuine ghosts: PENDING past grace with no later confirmation
        for the same (tool, session)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, session_id, tool_name, args_json FROM ledger"
                " WHERE status='PENDING' ORDER BY id ASC LIMIT 200").fetchall()
            ghosts = []
            for rid, ts, sid, tool, args_json in rows:
                try:
                    age = (datetime.now(timezone.utc)
                           - datetime.fromisoformat(ts)).total_seconds()
                except Exception:
                    age = 0
                if age < GRACE_SECONDS:
                    continue
                # Any confirmed/error row for the same tool+session at a later ts
                # means the action did complete — the row was orphaned by an id
                # mismatch. Resolve it instead of crying wolf.
                later = self._conn.execute(
                    "SELECT 1 FROM ledger WHERE tool_name=? AND session_id=?"
                    " AND status NOT IN ('PENDING','GHOST_REPORTED') AND ts >= ?"
                    " LIMIT 1", (tool, sid, ts)).fetchone()
                if later:
                    self._conn.execute("UPDATE ledger SET status='RESOLVED' WHERE id=?", (rid,))
                    continue
                ghosts.append({"id": rid, "ts": ts, "session_id": sid,
                               "tool": tool, "args": args_json})
            self._conn.commit()
        return ghosts

    def mark_ghost_reported(self, rid):
        with self._lock:
            self._conn.execute(
                "UPDATE ledger SET status='GHOST_REPORTED' WHERE id=?", (rid,))
            self._conn.commit()

    def record_policy_hit(self, tool_name, tool_call_id, args, session_id, reason):
        """Dry-run record: a call that matched a block rule (not enforced)."""
        try:
            args_json = json.dumps(args, default=str)[:4000]
        except Exception:
            args_json = str(args)[:4000]
        with self._lock:
            self._conn.execute(
                "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name,"
                " args_json, status, result_digest)"
                " VALUES (?,?,?,?,?,'POLICY_WOULD_BLOCK',?)",
                (_now(), session_id or "", tool_call_id or "", tool_name,
                 args_json, reason[:300]))
            self._conn.commit()


_LEDGER = None
DB_PATH = _DB_PATH  # resolved at register() to the per-profile data dir


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

    # --- policy engine (pro preview) -------------------------------------
    # Never let a policy-engine bug break the tool path: everything wrapped.
    try:
        if _policy_rules is None:
            load_policy_for_hook()
        if _policy_rules and _policy_mode != "off":
            import policy as _policy
            verdict = _policy.check(_policy_rules, tool_name, args)
            if verdict.get("action") == "block":
                reason = verdict.get("reason", "blocked by policy")
                # v0.4.0: enforcement is free — no license gate.
                if _policy_mode == "enforce":
                    _policy_mode_local = "enforce"
                else:
                    _policy_mode_local = _policy_mode
                if _policy_mode_local == "enforce":
                    _alert(f"🚫 agent-ledger POLICY BLOCK: {tool_name} — {reason}")
                    return {"action": "block",
                            "reason": f"agent-ledger policy: {reason}"}
                # dry_run: record what WOULD have been blocked
                try:
                    _get_ledger().record_policy_hit(
                        tool_name, tool_call_id, args, session_id or task_id,
                        reason)
                except Exception:
                    pass
                _alert(f"⚠️ agent-ledger POLICY (dry-run would block): "
                       f"{tool_name} — {reason}")
                return {"context": (
                    f"⚠️ agent-ledger policy (dry-run): this {tool_name} call "
                    f"matches a block rule ({reason}). In enforce mode this "
                    f"call would be refused. Proceed only if this is intended.")}
    except Exception:
        pass  # fail-open: a broken policy must never wedge the agent

    # --- ledger (always) ---------------------------------------------------
    try:
        _get_ledger().pending(tool_name, tool_call_id, args, session_id or task_id)
    except Exception:
        pass  # observer-only: never break the tool path
    return None


def on_post_tool_call(tool_name, args=None, result=None, task_id=None,
                      tool_call_id=None, session_id=None, duration_ms=0,
                      status=None, error_type=None, **kwargs):
    if not _is_mutating(tool_name):
        return None
    final = "CONFIRMED"
    if status is not None and status != "ok":
        final = f"ERROR:{status}"
    elif error_type:
        final = f"ERROR:{error_type}"
    try:
        _get_ledger().confirm(tool_name, tool_call_id, session_id or task_id,
                              result, duration_ms, final)
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
        home = getattr(ctx, "hermes_home", None) or os.path.expanduser("~/.hermes")
        data_dir = os.path.join(home, "agent-ledger")
        os.makedirs(data_dir, exist_ok=True)
        DB_PATH = os.path.join(data_dir, "ledger.db")
    except Exception:
        pass
    _alert_fn = None  # ghosts surface via pre_llm_call context injection

    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("post_tool_call", on_post_tool_call)
    ctx.register_hook("pre_llm_call", reconcile_and_alert)
    ctx.register_hook("on_session_start", reconcile_and_alert)
