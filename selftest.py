"""Self-test for agent-ledger — run: python3 selftest.py"""
import os
import sys
import tempfile
import time

os.environ["AGENT_LEDGER_TEST"] = "1"

import importlib.util

spec = importlib.util.spec_from_file_location(
    "agent_ledger", os.path.join(os.path.dirname(__file__), "__init__.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# --- redirect DB to temp dir ---
tmp = tempfile.mkdtemp()
mod.DB_PATH = os.path.join(tmp, "ledger.db")
led = mod._Ledger(mod.DB_PATH)
mod._LEDGER = led

# 1. pending + confirm via tool_call_id
led.pending("cronjob", "call_1", {"action": "create", "schedule": "5m"}, "sess_a")
led.confirm("cronjob", "call_1", "created job abc", 40, "CONFIRMED")
rows = led._conn.execute("SELECT status FROM ledger").fetchall()
assert rows == [("CONFIRMED",)], rows
print("PASS: pending->confirmed via tool_call_id")

# 2. confirm fallback by tool name (no call id)
led.pending("write_file", None, {"path": "/tmp/x"}, "sess_a")
led.confirm("write_file", None, "ok", 5, "CONFIRMED")
rows = led._conn.execute("SELECT status FROM ledger WHERE tool_name='write_file'").fetchall()
assert rows == [("CONFIRMED",)], rows
print("PASS: fallback confirm by tool name")

# 3. ghost detection: old PENDING shows up in reconcile
led._conn.execute(
    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status)"
    " VALUES (?,?,?,?,?,'PENDING')",
    ("2020-01-01T00:00:00+00:00", "sess_old", "call_ghost", "cronjob",
     '{"action": "create", "schedule": "30m"}'))
led._conn.commit()
ghosts = led.reconcile()
assert any(g["tool_call_id"] if isinstance(g, dict) and "tool_call_id" in g else g["id"] for g in ghosts), ghosts
assert all(g["tool"] == "cronjob" for g in ghosts), ghosts
print(f"PASS: ghost detected ({len(ghosts)} old pending)")

# 4. reconcile_and_alert returns context injection and marks GHOST_REPORTED
ret = mod.reconcile_and_alert(session_id="sess_now")
assert ret and "context" in ret and "NEVER confirmed" in ret["context"], ret
statuses = led._conn.execute(
    "SELECT status FROM ledger WHERE status='GHOST_REPORTED'").fetchall()
assert statuses, "ghost not marked"
print("PASS: context injection + GHOST_REPORTED")

# 5. mutating filter
assert mod._is_mutating("write_file") and mod._is_mutating("mcp__calendar_add")
assert not mod._is_mutating("read_file") and not mod._is_mutating("web_search")
print("PASS: mutating-tool filter")

# 6. hook signatures survive real kwargs (post_tool_call passes extras)
try:
    mod.on_post_tool_call("cronjob", args={}, result="ok", task_id="t", tool_call_id="call_9",
                          duration_ms=12, status="ok", error_type=None,
                          middleware_trace=[], session_id="s")
    mod.on_pre_tool_call("terminal", {"command": "ls"}, task_id="t", tool_call_id="call_10",
                         session_id="s")
    print("PASS: hook signatures accept real fire-site kwargs")
except TypeError as e:
    print("FAIL: signature mismatch:", e)
    sys.exit(1)

print("\nALL TESTS PASSED")
