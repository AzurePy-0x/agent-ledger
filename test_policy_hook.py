"""test_policy_hook.py — integration: policy engine wired into on_pre_tool_call."""
import importlib
import json
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import __init__ as al  # noqa: E402

PASS = 0
FAIL = 0


def t(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


# --- Test 1: mode off (default) — no interference
al._policy_rules = []
al._policy_mode = "off"
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"}, session_id="s1")
t("mode off → plain ledger path (no dict return)", r is None)

# --- Test 2: dry_run — block rule matches → context note + recorded hit
al.DB_PATH = tempfile.mktemp(suffix=".db")
al._LEDGER = None  # force fresh ledger at new temp path
rules = [{"block": "terminal", "match": "rm -rf /", "reason": "destructive"}]
al._policy_rules = rules
al._policy_mode = "dry_run"
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"},
                        session_id="s1", tool_call_id="t1")
t("dry_run match → context note returned", bool(r) and "context" in r)
t("dry_run note mentions enforce mode", "enforce" in r["context"])

r2 = al.on_pre_tool_call("terminal", {"command": "ls -la"},
                         session_id="s1", tool_call_id="t2")
t("dry_run non-match → normal pending path", r2 is None)

conn = sqlite3.connect(al.DB_PATH)
rows = conn.execute(
    "SELECT tool_name, status, result_digest FROM ledger"
    " WHERE status='POLICY_WOULD_BLOCK'").fetchall()
conn.close()
t("POLICY_WOULD_BLOCK recorded in ledger",
   len(rows) == 1 and rows[0][0] == "terminal" and "destructive" in rows[0][2])

# --- Test 3: enforce WITHOUT license → degrades to dry-run (license gate)
al._policy_mode = "enforce"
import license as _L
_L.SECRET_PATH = os.path.join(tempfile.mkdtemp(), ".sec")
_L.LICENSE_PATH = os.path.join(tempfile.mkdtemp(), "license")
try:
    os.remove(_L.LICENSE_PATH)
except OSError:
    pass
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"},
                        session_id="s1", tool_call_id="t3")
t("enforce without license → dry-run context note",
  bool(r) and "context" in r and "action" not in r)

# --- Test 3b: enforce WITH valid license → real block
with open(_L.LICENSE_PATH, "w") as f:
    f.write(_L.generate_key("HookTest", "h@t.st", exp=None))
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"},
                        session_id="s1", tool_call_id="t3b")
t("enforce with license → action block", (r or {}).get("action") == "block")
t("block carries reason", "destructive" in (r or {}).get("reason", ""))

# --- Test 4: allow exemption beats block (first-match-wins)
al._policy_rules = [
    {"allow": "terminal", "match": r"git\s+status"},
    {"block": "terminal", "match": r"git\s+push\s+-f", "reason": "force push"},
]
al._policy_mode = "enforce"
r = al.on_pre_tool_call("terminal", {"command": "git status"}, session_id="s1")
t("allowed call falls through to normal path", r is None)
r = al.on_pre_tool_call("terminal", {"command": "git push -f"}, session_id="s1")
t("blocked call still fires after exemption rule (license present)", (r or {}).get("action") == "block")

# --- Test 5: broken policy json must fail open (never wedge the agent)
al._policy_rules = "THIS IS NOT A LIST"
r = al.on_pre_tool_call("terminal", {"command": "ls"}, session_id="s1")
t("corrupt rules fail-open (no crash, no block)", r is None or "action" not in (r or {}))

print(f"\n{'='*40}")
print(f"PASS {PASS} / FAIL {FAIL}")
print("RESULT:", "PASS ✅" if FAIL == 0 else "FAIL ❌")
sys.exit(0 if FAIL == 0 else 1)
