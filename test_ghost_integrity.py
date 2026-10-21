"""test_ghost_integrity.py — ghost integrity, tool coverage, block directive.

Regressions for three defects found while integrating with Hermes 0.21.x:

1. enforce mode returned ``{"action": "block", "reason": ...}``. The host's
   ``pre_tool_call`` contract reads ``"message"`` and discards a block directive
   without one, so enforcement was a silent no-op — the tool call proceeded.
2. the mutating set missed names current Hermes registers (``cronjob_manage``,
   ``execute_code``, ``process_manage``, ``computer_use``, ``browser_click``/
   ``type``/``press``, the kanban attach/link/review calls), so those
   state-changing calls were never recorded at all.
3. ``confirm()``'s FIFO fallback let an unrelated later success of the same tool
   in the same session stamp a never-confirmed call CONFIRMED with the wrong
   result digest, and ``reconcile()`` then suppressed it — a real ghost, hidden.

Run: python3 test_ghost_integrity.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import __init__ as al  # noqa: E402

PASS = 0
FAIL = 0


def t(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"PASS: {name}")
    else:
        FAIL += 1
        print(f"FAIL: {name} {detail}")


# --- 1. tool coverage -------------------------------------------------------
for name in ("cronjob_manage", "execute_code", "process_manage", "computer_use",
             "browser_click", "browser_type", "browser_press", "kanban_attach",
             "kanban_attach_url", "kanban_link", "kanban_request_changes",
             "kanban_request_review"):
    t(f"tracks {name}", al._is_mutating(name))
t("still ignores read_file", not al._is_mutating("read_file"))
t("still ignores web_search", not al._is_mutating("web_search"))
t("execute_code grace clears the host's 300s call cap", al._grace_for("execute_code") > 300)
t("computer_use grace clears its nested loop", al._grace_for("computer_use") >= 900)

# --- 2. the block directive the host actually honours -----------------------
tmp = tempfile.mkdtemp()
al.DB_PATH = os.path.join(tmp, "ledger.db")
al._LEDGER = None
al._policy_rules = [{"block": "terminal", "match": "rm -rf /", "reason": "destructive"}]
al._policy_mode = "enforce"
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"}, session_id="s1", tool_call_id="c1")
t("enforce returns a block action", (r or {}).get("action") == "block", r)
t("block carries 'message' (the key the host reads)",
  bool((r or {}).get("message")) and "destructive" in r["message"], r)
t("block still carries 'reason' for existing consumers",
  "destructive" in (r or {}).get("reason", ""), r)

# --- 3. ghost integrity -----------------------------------------------------
al._policy_mode = "off"
al._policy_rules = []
al.DB_PATH = os.path.join(tmp, "ledger2.db")
al._LEDGER = None
led = al._Ledger(al.DB_PATH)
al._LEDGER = led
OLD = "2020-01-01T00:00:00+00:00"

# a call that was issued with an id and never confirmed
led.pending("execute_code", "ghost1", {"code": "open('/x','w').write('y')"}, "sessA")
# an unrelated, later, successful call of the same tool in the same session
led.confirm("execute_code", "other1", "sessA", "ok", 5, "CONFIRMED")
led._conn.execute("UPDATE ledger SET ts=? WHERE tool_call_id='ghost1'", (OLD,))
led._conn.commit()

st = led._conn.execute("SELECT status FROM ledger WHERE tool_call_id='ghost1'").fetchone()[0]
t("an unrelated success does not confirm another call's row", st == "PENDING", st)
n = led._conn.execute("SELECT COUNT(*) FROM ledger WHERE tool_call_id='other1'").fetchone()[0]
t("the unrelated success is recorded as its own row", n == 1, n)
ghosts = [g for g in led.reconcile() if g["session_id"] == "sessA"]
t("the genuine ghost is still reported",
  len(ghosts) == 1 and ghosts[0]["tool"] == "execute_code", str(ghosts))

# the documented no-id pairing must be preserved (pre fires with an empty id)
led.pending("write_file", "", {"path": "/no-id"}, "sessB")
led.confirm("write_file", "call_X", "sessB", "ok", 1, "CONFIRMED")
st2 = led._conn.execute(
    "SELECT status FROM ledger WHERE session_id='sessB' AND tool_name='write_file'").fetchone()[0]
t("id-less pre still paired by FIFO", st2 == "CONFIRMED", st2)

# and the documented RESOLVED path for a no-id row with a later confirmation
led._conn.execute(
    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status)"
    " VALUES (?,?,?,?,?,'PENDING')", (OLD, "sessC", "", "terminal", '{"command":"git push"}'))
led._conn.execute(
    "INSERT INTO ledger (ts, session_id, tool_call_id, tool_name, args_json, status, confirmed_ts)"
    " VALUES (?,?,?,?,?,'CONFIRMED',?)",
    ("2020-01-01T00:05:00+00:00", "sessC", "call_later", "terminal", None,
     "2020-01-01T00:05:01+00:00"))
led._conn.commit()
g = [x for x in led.reconcile() if x["session_id"] == "sessC"]
# by tool_call_id, not by (session, tool): idx_ledger_sess_tool sorts 'CONFIRMED'
# before 'PENDING', so a status-only lookup can read the wrong row.
st3 = led._conn.execute(
    "SELECT status FROM ledger WHERE session_id='sessC' AND tool_call_id=''").fetchone()[0]
t("no-id orphan with a later confirmation is still RESOLVED",
  g == [] and st3 == "RESOLVED", f"{g} {st3}")

print()
print(f"PASS {PASS} / FAIL {FAIL}")
sys.exit(0 if FAIL == 0 else 1)
