"""New regression tests for review fixes: session-scoped reconcile,
per-tool grace, GHOST_REPORTED revival, credential isolation."""
import importlib
import json
import os
import sqlite3
import sys
import tempfile

tmp = tempfile.mkdtemp()
os.environ["AGENT_LEDGER_DB"] = os.path.join(tmp, "ledger.db")
sys.path.insert(0, "/home/agentuser/agent-ledger-repo")
import __init__ as al  # noqa: E402

DB = os.environ["AGENT_LEDGER_DB"]
al.DB_PATH = DB
al._LEDGER = None

results = []


def check(name, cond):
    results.append((name, bool(cond)))


# --- FIX 3: session-scoped reconcile --------------------------------------
led = al._get_ledger()
led.pending("terminal", "id-A", {"cmd": "x"}, "sess-A")
led.pending("write_file", "id-B", {"path": "y"}, "sess-B")
import time as _t
# age both rows beyond grace by rewriting ts
conn = sqlite3.connect(DB)
old_ts = "2020-01-01T00:00:00+00:00"
conn.execute("UPDATE ledger SET ts=?", (old_ts,))
conn.commit()
conn.close()

ghosts_a = led.reconcile(session_id="sess-A")
check("session filter: sess-A sees only its ghost",
      len(ghosts_a) == 1 and ghosts_a[0]["session_id"] == "sess-A")
ghosts_none = led.reconcile(session_id=None)
check("no filter: sees both (back-compat)",
      len(ghosts_none) == 2)

# --- FIX 4a: per-tool grace ------------------------------------------------
led2 = al._get_ledger()
led2.pending("delegate_task", "id-D", {"goal": "long"}, "sess-C")
recent_ts = "2099-01-01T00:00:00+00:00"  # not needed; check helper directly
check("grace: delegate_task gets long window", al._grace_for("delegate_task") >= 1800)
check("grace: terminal gets long window", al._grace_for("terminal") >= 900)
check("grace: write_file keeps default", al._grace_for("write_file") == al.GRACE_SECONDS)
check("grace: mcp tool falls back to default", al._grace_for("mcp__custom") == al.GRACE_SECONDS)

# --- FIX 4b: GHOST_REPORTED revival ----------------------------------------
conn = sqlite3.connect(DB)
conn.execute("UPDATE ledger SET ts=? WHERE tool_call_id='id-A'", (old_ts,))
conn.commit()
conn.close()
# mark id-A ghost-reported (simulate reconcile_and_alert already alerted)
led.mark_ghost_reported(led.reconcile(session_id="sess-A")[0]["id"])
# late confirmation must UPDATE the same row, not insert a dup
led.confirm("terminal", "id-A", "sess-A", "done", 5, "CONFIRMED")
conn = sqlite3.connect(DB)
n = conn.execute("SELECT COUNT(*) FROM ledger WHERE tool_call_id='id-A'").fetchone()[0]
st = conn.execute("SELECT status FROM ledger WHERE tool_call_id='id-A'").fetchone()[0]
conn.close()
check("revival: late confirm updates ghost row (no dup)", n == 1 and st == "CONFIRMED")

# --- FIX 1: posture_daily has no .env fallback -----------------------------
src = open("/home/agentuser/agent-ledger-repo/posture_daily.py").read()
check("creds: no load_env_file left", "load_env_file" not in src)
check("creds: no TELEGRAM_BOT_TOKEN read", "TELEGRAM_BOT_TOKEN" not in src
      or "POSTURE_TELEGRAM_BOT_TOKEN" in src and '.hermes/.env' not in src)
check("creds: uses own env names",
      'os.environ.get("POSTURE_TELEGRAM_BOT_TOKEN", "")' in src)

# --- FIX 2: profile-aware home ----------------------------------------------
check("profile: register uses get_hermes_home", "get_hermes_home" in open(
    "/home/agentuser/agent-ledger-repo/__init__.py").read())
check("profile: plugin-data path", "plugin-data" in open(
    "/home/agentuser/agent-ledger-repo/__init__.py").read())

passed = sum(1 for _, ok in results if ok)
for name, ok in results:
    print(("PASS" if ok else "FAIL") + ": " + name)
print(f"\n{passed}/{len(results)} passed")
sys.exit(0 if passed == len(results) else 1)
