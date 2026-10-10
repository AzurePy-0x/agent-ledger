"""test_license_gate.py — enforce mode is license-gated; falls back to dry_run."""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import __init__ as al      # noqa: E402
import license as L        # noqa: E402

PASS = 0
FAIL = 0


def t(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
        print(f"  FAIL: {name}")


tmpdir = tempfile.mkdtemp()
L.SECRET_PATH = os.path.join(tmpdir, ".license_secret")
L.LICENSE_PATH = os.path.join(tmpdir, "license")

al.DB_PATH = tempfile.mktemp(suffix=".db")
al._LEDGER = None
rules = [{"block": "terminal", "match": "rm -rf /", "reason": "destructive"}]
al._policy_rules = rules

# --- enforce mode WITHOUT license → degrades to dry_run
al._policy_mode = "enforce"
try:
    os.remove(L.LICENSE_PATH)
except OSError:
    pass
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"},
                        session_id="s", tool_call_id="t1")
t("no license: enforce degrades to context note (dry-run)",
  bool(r) and "context" in r and "enforce" in r["context"])
conn = sqlite3.connect(al.DB_PATH)
n = conn.execute("SELECT COUNT(*) FROM ledger WHERE status='POLICY_WOULD_BLOCK'"
                 " AND result_digest LIKE 'LICENSE MISSING%'").fetchone()[0]
conn.close()
t("fallback recorded with LICENSE MISSING reason", n == 1)

# --- enforce mode WITH valid license → real block
with open(L.LICENSE_PATH, "w") as f:
    f.write(L.generate_key("Tester", "t@e.st", exp=None))
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"},
                        session_id="s", tool_call_id="t2")
t("valid license: real block fires", (r or {}).get("action") == "block")
t("block reason present", "destructive" in (r or {}).get("reason", ""))

# --- expired license → degrades again
exp_past = "2020-01-01T00:00:00+00:00"
with open(L.LICENSE_PATH, "w") as f:
    f.write(L.generate_key("Tester", "t@e.st", exp=exp_past))
r = al.on_pre_tool_call("terminal", {"command": "rm -rf /"},
                        session_id="s", tool_call_id="t3")
t("expired license: degrades to dry-run",
  bool(r) and "context" in r and "action" not in r)

# --- license check failure never crashes the hook (fail-open)
al._policy_rules = [{"block": "terminal", "match": "x", "reason": "r"}]
L.LICENSE_PATH = "/nonexistent/dir/license"
r = al.on_pre_tool_call("terminal", {"command": "x ls"}, session_id="s")
t("unreadable license: no crash", True)  # reaching here = no exception

print(f"\n{'='*40}")
print(f"PASS {PASS} / FAIL {FAIL}")
print("RESULT:", "PASS ✅" if FAIL == 0 else "FAIL ❌")
sys.exit(0 if FAIL == 0 else 1)
