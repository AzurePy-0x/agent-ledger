# agent-ledger

**Your agent said it did the job. Did it actually happen?**

agent-ledger is a Hermes Agent plugin that keeps a write-ahead ledger of every state-mutating tool call — so actions that were *issued* but never *confirmed* (silently lost, e.g. when context compaction tears down an in-flight turn) get caught, reported, and injected back into the agent's context on the next turn.

Inspired by [NousResearch/hermes-agent#90985](https://github.com/NousResearch/hermes-agent/issues/90985): a `cronjob_create` tool call was issued, compaction tore the turn down before the result was persisted, and the job **never existed** — no error, no retry, no trace. The agent believed it never happened. So did the user.

## How it works

```
pre_tool_call   → ledger entry PENDING   (tool, args, ts, session_id)
post_tool_call  → entry → CONFIRMED / ERROR:*
pre_llm_call    → reconcile: PENDING older than grace period = GHOST
                  → injected into the turn's context as a warning
```

- **Observer-only** — never blocks, never transforms. Writes are sub-10ms SQLite inserts (WAL mode) on a dedicated thread-safe connection.
- **Ghost detection** — a PENDING entry older than the grace period (2 min) is a candidate ghost: the call was issued but its effect was never confirmed.
- **Context injection** — ghosts surface in the *next* turn's context, so the agent itself is told: "verify whether this actually happened before trusting state."
- **Mutating-tool filter** — only tracks tools that change state (`write_file`, `patch`, `terminal`, `cronjob`, `delegate_task`, kanban mutations, all MCP tools via `mcp__` prefix). Read-only tools cost zero overhead.

## Install

```bash
mkdir -p ~/.hermes/plugins/agent-ledger
cd ~/.hermes/plugins/agent-ledger
# drop plugin.yaml + __init__.py here, or:
git clone https://github.com/ZidoCode/agent-ledger.git .
hermes plugins list          # should show agent-ledger
hermes plugins enable agent-ledger
hermes gateway restart       # plugin loads on the next session
```

## Inspecting the ledger

```bash
sqlite3 ~/.hermes/agent-ledger/ledger.db "
  SELECT ts, tool_name, status, substr(args_json,1,60)
  FROM ledger ORDER BY id DESC LIMIT 20;"
```

Statuses: `PENDING` → `CONFIRMED` | `ERROR:<type>` | `GHOST_REPORTED` (flagged and surfaced to the agent).

## Self-test

```bash
python3 selftest.py
# PASS: pending->confirmed via tool_call_id
# PASS: fallback confirm by tool name
# PASS: ghost detected
# PASS: context injection + GHOST_REPORTED
# PASS: mutating-tool filter
# PASS: hook signatures accept real fire-site kwargs
```

## Design notes

- **Why pre_llm_call and not a background alert?** The hook can return `{"context": ...}` — injected into the current turn's user message without touching the (cache-sensitive) system prompt. The agent learns about the ghost *in the conversation where it can fix it*.
- **Why not block suspicious calls in pre_tool_call?** Hermes fails pre_tool_call hooks closed after a 30s timeout — a slow ledger would block legitimate tools. The ledger is a flight recorder, not a gate.
- **Why confirm-by-tool-name fallback?** Some fire paths don't carry `tool_call_id`; the fallback updates the most recent PENDING entry for that tool (safe under the write lock).
- Tested on Hermes Agent v0.21.3 (Linux VPS).

## Status

MVP, in daily use. Ghost-effect telemetry is being collected — real-world numbers will land in this README. Issues/PRs welcome.

## License

MIT
