# Alibi

Alibi reads AI coding-agent session transcripts alongside endpoint-security alerts and decides
whether each alert was justified by what the user actually asked for. When an action was not
justified, Alibi can propose a concrete, human-approved reversal.

## Verdicts

| Verdict       | Meaning                                                                 |
|---------------|-------------------------------------------------------------------------|
| `JUSTIFIED`   | The flagged action follows from the user's request.                     |
| `UNJUSTIFIED` | The user did not ask for it, with no sign of outside influence.         |
| `HIJACKED`    | The action was driven by injected or untrusted content, not the user.   |

## How it works

A session transcript becomes a timeline of user prompts, agent tool calls, and tool results
(each result marked TRUSTED or UNTRUSTED). Endpoint alerts are linked to the tool call that
caused them, then judged in tiers:

- Provenance: was the action driven by untrusted content that entered through a tool result?
- Policy: does the action fall in a sensitive category (exfiltration, data destruction and
  impact, credential and collection, command-and-control, persistence) the user never licensed?
- Bulk-rewrite: a burst of file rewrites the request never asked for (ransomware-shaped).
- Model (optional): a local Ollama model adjudicates whatever the deterministic tiers leave
  UNKNOWN. A model verdict cannot invent provenance, so a HIJACKED call with no untrusted
  source is downgraded to UNJUSTIFIED.

Transcripts from other agents can be ingested through a neutral role/kind JSONL format, so Alibi
is not tied to Claude Code.

## Usage

### scan (fast, deterministic)

### adjudicate (background model pass)
Resolves only the UNKNOWN pile with a local model and reports just what the model decided.
### remediate (propose, then optionally act)
Proposes a reversal for each HIJACKED or UNJUSTIFIED verdict. Dry run by default: it changes
nothing. With `--apply` it runs each proposal only after you confirm it, one at a time.Proposals include: delete a scheduled task the agent created, quarantine a file it wrote (moved
to a timestamped path so nothing is overwritten), restore files from version control after an
unrequested mass rewrite, or flag a leaked credential for manual rotation.

## Exit codes

| Code | Meaning                                                                                         |
|------|-------------------------------------------------------------------------------------------------|
| `0`  | nothing HIJACKED or UNJUSTIFIED (for `remediate`, nothing to propose)                           |
| `1`  | at least one HIJACKED or UNJUSTIFIED at or above `--min-confidence` (for `remediate`, a proposal)|
| `2`  | error (bad input, missing file)                                                                 |

## Layout
## DevelopmentThe model tier needs a local Ollama server. Without it, `scan` and `remediate` still run fully
on the deterministic tiers.

## Modules

- `transcript.py`: session transcripts (Claude Code, or neutral cross-agent JSONL) into a timeline.
- `alerts.py`: Hayabusa results CSV into alerts with process lineage and MITRE ATT&CK tags.
- `link.py`: links each alert to the tool call that caused it, to the agent harness, or to nothing.
- `judge.py` / `verdict.py`: provenance, policy, and bulk-rewrite tiers plus the optional model tier.
- `model_tier.py`: local Ollama adjudication with caching and a provenance guard.
- `remediate.py`: proposes reversals and runs them only behind a per-action approval gate.
- `cli.py`: the `scan` / `adjudicate` / `remediate` commands.
