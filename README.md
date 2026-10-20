# Alibi

![CI](https://github.com/Lucaszy1/Alibi/actions/workflows/tests.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

Alibi reads an AI coding agent's session transcript alongside the endpoint-security alerts it
triggered and decides whether each flagged action was the user's intent or an injected attack. It
follows untrusted data through the session, correlates the steps of one intrusion, proposes a
human-approved reversal, and can run inline as a hook that blocks a hijack before it happens. It is
provenance-aware, not signature-based: it asks where an instruction came from, so a novel technique
it has never seen is still caught when it traces to untrusted input.

## Why Alibi exists

Over the past year, AI coding agents have taken real, damaging actions their users never authorized.
[Replit's agent wiped a production database](https://www.eweek.com/news/replit-ai-coding-assistant-failure/)
during a code freeze. [A compromised Amazon Q ran file-wiping commands](https://www.bleepingcomputer.com/news/security/amazon-ai-coding-agent-hacked-to-inject-data-wiping-commands/).
[Injected content drove a Semantic Kernel agent to execute code on its host](https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/).
In every case, endpoint security could see the action but had no way to judge it against what the
user actually asked for.

I built Alibi to close that gap, so incidents like these become preventable instead of cautionary
tales. Plenty of tools can flag a dangerous command, but none of them ask the question that actually
matters for an agent: did the user request this, or did something injected into the session? Alibi
judges each flagged action by where its instruction came from, connecting what the endpoint sees to
what the user asked. That link, between an agent's action and the intent behind it, is what hasn't
been built before.

## The name

An alibi is proof that accounts for what you did. Alibi asks the same of every flagged agent action:
can it be accounted for by what the user actually requested? An action with no alibi is one worth
stopping.

## Verdicts

| Verdict       | Meaning                                                                 |
|---------------|-------------------------------------------------------------------------|
| `JUSTIFIED`   | The flagged action follows from the user's request.                     |
| `UNJUSTIFIED` | The user did not ask for it, with no sign of outside influence.         |
| `HIJACKED`    | The action was driven by injected or untrusted content, not the user.   |

## How it works

A session transcript becomes a timeline of user prompts, agent tool calls, and tool results (each
result marked TRUSTED or UNTRUSTED). Endpoint alerts are linked to the tool call that caused them,
then judged in tiers, cheapest first:

- Provenance: is the action's target traceable to the user's prompts, or only to untrusted content?
- Taint: follow untrusted data to the argument of a dangerous call, across calls, including a file
  the agent wrote from untrusted input and later executed. The flow path is the evidence.
- Policy: does the action fall in a sensitive category (exfiltration, destruction, credential and
  collection, command-and-control, persistence, defense impairment) the user never licensed?
- Bulk-rewrite: a burst of file rewrites the request never asked for (ransomware shaped).
- Anomaly: a high-severity action with no external target and no tie to the request is surfaced for
  review even when nothing else fires, the attack-agnostic catch for a genuinely novel technique.
- Model (optional): a local Ollama model adjudicates the UNKNOWN pile and can recover a paraphrased
  hijack, but it can never clear a deterministic flag.

A decoding pass runs before the tiers, so payloads hidden behind base64, PowerShell `-enc`, hex,
percent-encoding, string concatenation, or shell variables are judged on their real content. Text is also normalized before matching:
invisible and bidirectional-control characters stripped, homoglyphs folded, and leetspeak or
spaced-out phrasing collapsed, so disguised injection cues still match.
Flagged actions on one host within a window are correlated into a single incident. A user-controlled
allowlist can sanction known-good hosts, paths, or commands, and a YAML policy file (`--policy`) tunes
how strictly each category is treated (strict / escalate / off). Sessions from other agents can be
ingested through a neutral role/kind JSONL format.

## Usage

### scan (fast, deterministic)
```
alibi scan <hayabusa-results.csv> [transcript.jsonl]
alibi scan results.csv --json --all --min-confidence 0.7
alibi scan results.csv --model             # also adjudicate UNKNOWNs inline (local Ollama)
alibi scan results.csv --allow allow.txt   # sanction known-good hosts/paths/commands
alibi scan results.csv --policy policy.yaml # tune category severity + allowlist (see examples/)
```

### adjudicate (background model pass)
```
alibi adjudicate results.csv transcript.jsonl --model qwen2.5:7b --json
```

### remediate (propose, then optionally act)
```
alibi remediate results.csv transcript.jsonl   # list proposals, run nothing
alibi remediate results.csv --apply            # act, asking y/N before every action
```

### incidents (correlate an intrusion's steps)
```
alibi incidents results.csv transcript.jsonl --json --incident-window 120
```

### hook (real-time guardrail)
Run Alibi as a Claude Code PreToolUse hook that judges each proposed tool call before it executes:
a taint-derived call (a hijack in progress) is denied, an unrequested sensitive call is escalated to
you, and everything else passes silently so the normal permission flow is untouched. It fails open,
a hook error never blocks the agent.
```
alibi hook        # reads the hook JSON on stdin, prints a permission decision
```
Wire it in `.claude/settings.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [ { "type": "command", "command": "alibi hook" } ] }
    ]
  }
}
```

## Exit codes

| Code | Meaning                                                                        |
|------|--------------------------------------------------------------------------------|
| `0`  | nothing flagged (for `remediate`/`incidents`, nothing to propose or correlate) |
| `1`  | at least one HIJACKED or UNJUSTIFIED at or above `--min-confidence`             |
| `2`  | error (bad input, missing file)                                                |

## Security of Alibi itself

Alibi treats everything it ingests as hostile. A reversal with shell-unsafe or truncated target
characters is never auto-run; the judge model can never override a deterministic flag or be steered
by session text; oversized input is refused instead of exhausting memory; the parsers and hot
regexes are fuzzed against malformed and random input. Remediation can be forced shell-free
(`--apply --no-shell`), and the optional model host is loopback-only by default. The full trust model
is in `SECURITY.md`; `KNOWN_LIMITATIONS.md` lists the honest edges and how each is tracked.

## Layout
```
src/alibi/   package code
tests/       pytest suite and fixtures
examples/    a cold-start demo on real captured telemetry
```

## Development
```
python -m venv .venv
.venv\Scripts\activate        # Windows; use `source .venv/bin/activate` elsewhere
pip install -e ".[dev]"
pytest
```
The model tier needs a local Ollama server. Without it, every command runs fully on the
deterministic tiers.

## Modules

- `transcript.py`: sessions (Claude Code or neutral JSONL) into a timeline; TRUSTED/UNTRUSTED results.
- `alerts.py`: Hayabusa results CSV into alerts with process lineage and MITRE tags.
- `link.py`: link each alert to its tool call, the harness, or nothing.
- `decode.py`: reveal payloads hidden behind encodings, concatenation, and shell variables.
- `taint.py`: follow untrusted data into a later dangerous call, across dropped files.
- `judge.py` / `verdict.py`: provenance, taint, policy, bulk-rewrite, anomaly, and the model tier.
- `model_tier.py`: local Ollama adjudication, fenced and guarded so it cannot be steered.
- `incidents.py`: correlate flagged verdicts into same-host attack chains.
- `allowlist.py`: user-sanctioned hosts, paths, and commands that downgrade a flag.
- `inline.py`: real-time assessment of a proposed call (ALLOW / WARN / BLOCK).
- `remediate.py`: propose reversals and run them only behind a per-action approval gate.
- `policy.py`: a YAML policy that tunes category severity (strict / escalate / off) and the allowlist.
- `mcp_server.py`: a dependency-free MCP server exposing the guardrail to any agent.
- `bench.py`: the benchmark, ablations, baselines, and calibration.
- `redact.py` / `state.py`: report secret-redaction and durable run history.
- `cli.py`: scan / adjudicate / remediate / incidents / report / hook / undo / history / bench / mcp.

## Known limitations

Alibi is honest about its edges. `KNOWN_LIMITATIONS.md` lists every known limitation and deferred
item, each mapped to the milestone that will address it. Nothing there is a silent defect.
