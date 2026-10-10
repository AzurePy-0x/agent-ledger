"""test_posture_scale.py — performance + multi-session validation (v0.3.4).

Claims under test (must PASS for production-readiness):
  1. 10,000 ledger rows scored in < 1.0s (pure Python, no indexing needed).
  2. Multi-session ledger: findings correctly attributed; a noisy ERROR
     session does not frame an innocent session as ASI10.
  3. Multi-agent divergence: one session with ghosts fires ASI10, clean
     sessions in the same ledger do not get penalized beyond the shared
     finding (documented: score is ledger-wide, not per-session — that is
     the per-session report's job in the paid build).
Run: python3 test_posture_scale.py  (exit 0 = all pass)
"""
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import posture

NOW = datetime.now(timezone.utc)
PASS, FAIL = [], []


def check(name, cond):
    (PASS if cond else FAIL).append(name)
    print(("  ✅" if cond else "  ❌"), name)


def build(rows):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE ledger (ts TEXT, session_id TEXT, tool_name TEXT,"
              " args_json TEXT, status TEXT, duration_ms INT)")
    c.executemany("INSERT INTO ledger VALUES (?,?,?,?,?,?)", rows)
    c.commit()
    c.close()
    return db


def r(min_ago, tool, args, status="CONFIRMED", sid="s1"):
    return ((NOW - timedelta(minutes=min_ago)).isoformat(), sid, tool, args,
            status, 25)


print("== benchmark: 10,000 rows ==")
tools = [("terminal", '{"command":"git status"}'),
         ("terminal", '{"command":"ls -la"}'),
         ("read_file", '{"path":"src/main.py"}'),
         ("web_search", '{"query":"python sqlite"}'),
         ("web_extract", '{"urls":["https://docs.python.org"]}'),
         ("patch", '{"path":"a.py","old":"x","new":"y"}')]
rows = []
for i in range(10000):
    t, a = tools[i % len(tools)]
    rows.append(r(i * 0.5, t, a, sid=f"sess{i % 7}"))
db = build(rows)
t0 = time.perf_counter()
rep = posture.posture_report(db)
dt = time.perf_counter() - t0
print(f"  10k rows scored in {dt:.3f}s | score={rep['score']} | "
      f"findings={len(rep['findings'])}")
check("10k rows < 1.0s", dt < 1.0)
check("10k benign → no false ASI02/05/10",
      not ({f[1] for f in rep["findings"]} & {"ASI02", "ASI05", "ASI10"}))

print("== 50,000 rows (stress) ==")
rows2 = []
for i in range(50000):
    t, a = tools[i % len(tools)]
    rows2.append(r(i * 0.1, t, a, sid=f"sess{i % 20}"))
db2 = build(rows2)
t0 = time.perf_counter()
rep2 = posture.posture_report(db2)
dt2 = time.perf_counter() - t0
print(f"  50k rows scored in {dt2:.3f}s")
check("50k rows < 5.0s", dt2 < 5.0)

print("== multi-session attribution ==")
# sess-A: innocent reads. sess-B: errors + ghosts. Expect ASI10 fires
# (ledger-wide) but innocent rows never counted as ghosts/errors.
mix = [r(10 + i, "web_search", '{"query":"docs"}', sid="sess-A")
       for i in range(10)]
mix += [r(10 + i, "terminal", '{"command":"deploy.sh"}', "ERROR:x", "sess-B")
        for i in range(4)]
mix += [r(20 + i, "terminal", '{"command":"echo ?"}', "GHOST_REPORTED", "sess-B")
        for i in range(3)]
rep3 = posture.posture_report(build(mix))
asi10 = [f for f in rep3["findings"] if f[1] == "ASI10"]
asi08 = [f for f in rep3["findings"] if f[1] == "ASI08"]
check("mixed sessions → ASI10 fires (ghosts present)", bool(asi10))
check("mixed sessions → ASI08 fires (error burst)", bool(asi08))
check("ghost count = exactly 3 (only sess-B rows)",
      rep3["totals"]["ghosts"] == 3)
check("error count = exactly 4", rep3["totals"]["errors"] == 4)

print("== clean multi-session stays clean ==")
clean = []
for s in range(5):
    for i in range(8):
        t, a = [("web_search", '{"query":"a"}'),
                ("read_file", '{"path":"b"}'),
                ("web_extract", '{"urls":["https://c"]}')][i % 3]
        clean.append(r(10 + i * 5, t, a, sid=f"clean-{s}"))
rep4 = posture.posture_report(build(clean))
check("5 clean sessions → score 100", rep4["score"] == 100)

print("=" * 50)
print(f"PASS {len(PASS)} / FAIL {len(FAIL)}")
if FAIL:
    print("FAILED:", FAIL)
sys.exit(1 if FAIL else 0)
