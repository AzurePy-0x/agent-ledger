# agent-ledger: a security and audit plugin for Hermes Agent, scored against the OWASP Agentic Top 10

*Every tool call your agent makes, recorded locally before it runs — with a 0–100 posture score and an honest list of what it can't see.*

If you run an AI agent on your own machine, you already trust it with a lot. It edits files, restarts services, pushes to GitHub. agent-ledger answers two questions about that arrangement: **what did my agent actually do, and how risky is its behavior?**

It's a free, open-source (MIT) plugin for Hermes Agent, and it works in two layers.

## Layer 1: the ledger

The plugin hooks `pre_tool_call` and writes an entry to a local SQLite database **before** the tool executes. When the call completes, the entry is confirmed. Anything issued but never confirmed becomes a **ghost** — a tool call the agent believed it made, with no evidence it happened. Ghosts typically appear when a session is torn down mid-flight, for example during context compaction.

When a ghost is detected, the plugin injects a warning into the agent's next context, so the agent itself goes back and verifies reality instead of trusting its memory. That's the core loop: record first, act second, reconcile after.

Everything stays on your machine. The ledger is a plain SQLite file, there is no telemetry, no account, nothing leaves the box.

## Layer 2: the posture score

`posture.py` reads the ledger and scores your agent's recorded behavior from 100 to 0 against the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

What it detects from ledger metadata alone:

- **ASI02 — tool misuse:** destructive-tool bursts, credential-store access, unusual tool frequency versus your baseline.
- **ASI05 — unexpected code execution:** `curl ... | bash`, `wget | sh`, obfuscated payloads like `echo <base64> | base64 -d | bash`.
- **ASI08 — cascading failures:** error-rate spikes and bursts of consecutive failures.
- **ASI10 — rogue agents:** ghost entries and unconfirmed mutations.
- **ASI11 (ext) — excessive agency:** mutating-call volume relative to reads. Labeled `(ext)` because the official OWASP list stops at ASI10; this one is a community extension.

What it deliberately does **not** claim: categories that need payload or conversation inspection (ASI01, ASI03, ASI04, ASI06, ASI07, ASI09 — goal hijack, identity abuse, supply chain, memory poisoning, inter-agent trust, trust exploitation). Every report prints the not-covered list right next to the covered one. A score of 100 means "nothing suspicious in the recorded activity," not "the agent was well-behaved" — the ledger is written by the agent being scored, and the report says exactly that. No security tool should hide this, so agent-ledger doesn't.

The scoring itself is auditable, not a black box: `score = 100 − Σ{CRITICAL:25, HIGH:15, MEDIUM:8, LOW:3}` over all findings, no deduplication, and the full finding list always comes back so you can recompute it by hand.

## Using it

Install (once it's in the catalog, this becomes `hermes plugins install agent-ledger`):

```bash
git clone https://github.com/ZidoCode/agent-ledger ~/.hermes/plugins/agent-ledger
```

Restart your Hermes gateway and the ledger starts recording. To score your agent right now:

```bash
python3 ~/.hermes/plugins/agent-ledger/posture.py
```

Output looks like:

```
Agent Posture Score: 24/100
Calls: 216 | mutating: 120 | errors: 14 | ghosts: 1
[HIGH] ASI05: Terminal accessed credential-shaped path — ...
Covered: ASI02, ASI05, ASI08, ASI10, ASI11 (ext)
Requires payload inspection (not covered): ASI01, ASI03, ASI04, ASI06, ASI07, ASI09
Note: score reflects recorded activity only ...
```

For a scheduled report, `posture_daily.py` sends a daily digest to Telegram (score, delta versus yesterday, top findings by severity). Point it at your bot token via environment variables, add one cron line, done.

## Validation

The scorer ships with its full test suite, and you're encouraged to run it before trusting it:

| Suite | What it proves | Result |
|---|---|---|
| `test_posture.py` | benign ledger → 100 with zero findings; planted malicious ledger → all covered ASI families fire | PASS |
| `test_posture_unit.py` | per-ASI must-fire and must-not-fire cases, plus 7 known evasion patterns | 36/36 |
| `test_posture_scale.py` | 10k rows in 0.054s, 50k rows in 0.281s; correct multi-session attribution | PASS |
| `selftest.py` | ledger FIFO matching and ghost reconciliation | 13/13 |

The honest version of that table: the suite proves the scorer catches the seven evasion patterns we know about and none of the innocent look-alikes. It does not prove immunity to novel evasions — signature detection is always a step behind attacks nobody has written a rule for yet. The behavioral signals (rate spikes, error bursts, ghosts) are the mitigation for that, and they degrade the score even without a matching signature.

## Where it's going

On the roadmap: per-session posture reports, policy packs (block dangerous tool calls before they execute rather than reporting them after), a multi-agent dashboard, and tamper-evident logging.

Links:

- Repo: [github.com/ZidoCode/agent-ledger](https://github.com/ZidoCode/agent-ledger) (v0.3.5)
- Plugin catalog submission: [PR #135993](https://github.com/NousResearch/hermes-agent/pull/135993)

If you build with agents, try it on your own ledger and see what the score says. Feedback and issues are welcome.

---

*Building in public: agent security and reliability tooling. [github.com/ZidoCode](https://github.com/ZidoCode)*
