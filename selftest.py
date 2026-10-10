"""Self-test for agent-ledger v0.2 — run: python3 selftest.py"""
import importlib.util
import os
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location(
    "agent_ledger", os.path.join(os.path.dirname(os.path.abspath(__file__)), "__init__.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

tmp = tempfile.mkdtemp()
mod.DB_PATH = os.path.join(tmp, "ledger.db")
led = mod._Ledger(mod.DB_PATH)
mod._LEDGER = led

FAILS = []
def check(name, cond, detail=""):
    if cond:
        print(f"PASS: {name}")
    else:
        print(f"FAIL: {name} {detail}")
        FAILS.append(name)

# 1. pending -> confirm by tool_call_id (exact match)
led.pending("cronjob", "call_1", {"action": "create"}, "sess_a")
led.confirm("cronjob", "call_1", "sess_a", "created", 40, "CONFIRMED")
rows = led._conn.execute("SELECT status FROM ledger").fetchall()
check("exact id match confirm", rows == [("CONFIRMED",)], rows)

# 2. THE v0.1 BUG: pre fires with empty id, post fires with real id
led.pending("terminal", "", {"command": "git push"}, "sess_a")      # pre: empty id
led.confirm("terminal", "call_X", "sess_a", "ok", 5, "CONFIRMED")   # post: real id, no row has it
st = led._conn.execute("SELECT status FROM ledger WHERE tool_name='terminal'").fetchone()[0]
check("empty-id pre confirmed via FIFO fallback", st == "CONFIRMED", st)

# 3. FIFO not LIFO: two pendings, first post confirms the OLDER row
led.pending("write_file", "", {"path": "/a"}, "sess_b")  # older
time.sleep(0.01)
led.pending("write_file", "", {"path": "/b"}, "sess_b")  # newer
led.confirm("write_file", "call_Y", "sess_b", "ok", 1, "CONFIRMED")
older = led._conn.execute("SELECT status FROM ledger WHERE args_json LIKE '%/a%'").fetchone()[0]
newer = led._conn.execute("SELECT status FROM ledger WHERE args_json LIKE '%/b%'").fetchone()[0]
check("FIFO confirms older row first", older == "CONFIRMED" and newer == "PENDING",
      f"older={older} newer={newer}")
led.confirm("write_file", "call_Z", "sess_b", "ok", 1, "CONFIRMED")
newer = led._conn.execute("SELECT status FROM ledger WHERE args_json LIKE '%/b%'").fetchone()[0]
check("second confirm takes the next FIFO row", newer == "CONFIRMED", newer)

# 4. post without any pre -> recorded, no crash
n0 = led._conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
led.confirm("cronjob", "call_W", "sess_c", "ok", 1, "CONFIRMED")
n1 = led._conn.execute("SELECT COUNT(*) FROM ledger").fetchone()[0]
check("post-without-pre recorded", n1 == n0 + 1)

# 5. reconcile: young PENDING is not a ghost
led.pending("terminal", "call_young", {"command": "sleep"}, "sess_d")
check("young pending not ghost", led.reconcile() == [])

# 6. reconcile: old PENDING with NO later confirmation = ghost
old_ts = "2020-01-01T00:00:00+00:00"
led._conn.execute(
    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status)"
    " VALUES (?,?,?,?,?,'PENDING')", (old_ts, "sess_e", "call_ghost", "cronjob", '{"x":1}'))
led._conn.commit()
ghosts = led.reconcile()
check("old orphan pending = ghost", len(ghosts) == 1 and ghosts[0]["tool"] == "cronjob", ghosts)

# 7. v0.1 false-positive fix: old PENDING WITH later confirmation for same
#    tool+session = RESOLVED, not ghost
led._conn.execute(
    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status)"
    " VALUES (?,?,?,?,?,'PENDING')", (old_ts, "sess_f", "", "terminal", '{"command":"git push"}'))
led._conn.execute(
    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status, confirmed_ts)"
    " VALUES (?,?,?,?,?,'CONFIRMED',?)",
    ("2020-01-01T00:05:00+00:00", "sess_f", "call_later", "terminal", None,
     "2020-01-01T00:05:01+00:00"))
led._conn.commit()
ghosts = [g for g in led.reconcile() if g["session_id"] == "sess_f"]
resolved = led._conn.execute(
    "SELECT status FROM ledger WHERE session_id='sess_f' AND (tool_call_id='' IS NOT 1 OR tool_call_id='') "
    "AND args_json LIKE '%git push%'").fetchone()[0]
check("orphaned-but-completed row RESOLVED, not ghost", ghosts == [] and resolved == "RESOLVED",
      f"ghosts={ghosts} resolved={resolved}")

# 8. context injection on ghosts
led._conn.execute(
    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status)"
    " VALUES (?,?,?,?,?,'PENDING')", (old_ts, "sess_g", "call_g2", "write_file", '{"p":1}'))
led._conn.commit()
ret = mod.reconcile_and_alert()
check("ghost injects context", ret and "NEVER confirmed" in ret["context"])
st = led._conn.execute("SELECT status FROM ledger WHERE session_id='sess_g'").fetchone()[0]
check("ghost marked GHOST_REPORTED", st == "GHOST_REPORTED", st)

# 9. second reconcile does not re-report
ret2 = mod.reconcile_and_alert()
check("no repeat reporting", ret2 is None, ret2)

# 10. mutating filter
check("mutating filter", mod._is_mutating("write_file")
      and mod._is_mutating("mcp__cal_add")
      and not mod._is_mutating("read_file")
      and not mod._is_mutating("web_search"))

# 11. hook signatures accept real fire-site kwargs
try:
    mod.on_pre_tool_call("terminal", {"command": "ls"}, task_id="t", tool_call_id="c1",
                         session_id="s", turn_id="", api_request_id="", middleware_trace=[])
    mod.on_post_tool_call("terminal", args={}, result="ok", task_id="t", tool_call_id="c1",
                          session_id="s", duration_ms=9, status="ok", error_type=None,
                          error_message=None, middleware_trace=[])
    check("real fire-site kwargs accepted", True)
except TypeError as e:
    check("real fire-site kwargs accepted", False, str(e))

print()
if FAILS:
    print(f"{len(FAILS)} FAILED: {FAILS}")
    sys.exit(1)
print("ALL TESTS PASSED")
