# Alibi

Alibi reads an AI coding agent's session transcript alongside the endpoint-security alerts it
triggered and decides whether each flagged action was the user's intent or an injected attack. It
follows untrusted data through the session, correlates the steps of one intrusion, and proposes a
human-approved reversal. It is provenance-aware, not signature-based: it asks where an instruction
came from, so a novel technique it has never seen is still caught when it traces to untrusted input.

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
- Model (optional): a local Ollama model adjudicates the UNKNOWN pile and can recover a paraphrased
  hijack, but it can never clear a deterministic flag.

A decoding pass runs before the tiers, so payloads hidden behind base64, PowerShell `-enc`, hex,
percent-encoding, string concatenation, or shell variables are judged on their real content.
Flagged actions on one host within a window are correlated into a single incident. Sessions from
other agents can be ingested through a neutral role/kind JSONL format.

## Usage

### scan (fast, deterministic)
```
alibi scan <hayabusa-results.csv> [transcript.jsonl]
alibi scan results.csv --json
alibi scan results.csv --all --min-confidence 0.7
alibi scan results.csv --model          # also adjudicate UNKNOWNs inline (local Ollama)
```

### adjudicate (background model pass)
```
alibi adjudicate results.csv transcript.jsonl --model qwen2.5:7b --json
```

### remediate (propose, then optionally act)
```
alibi remediate results.csv transcript.jsonl   # list proposals, run nothing
alibi remediate results.csv --json             # machine-readable proposals
alibi remediate results.csv --apply            # act, asking y/N before every action
```

### incidents (correlate an intrusion's steps)
```
alibi incidents results.csv transcript.jsonl              # grouped attack chains
alibi incidents results.csv --json --incident-window 120
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
regexes are fuzzed against malformed and random input. See `KNOWN_LIMITATIONS.md` for the honest
edges and how each is tracked.

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
- `judge.py` / `verdict.py`: provenance, taint, policy, bulk-rewrite, and the optional model tier.
- `model_tier.py`: local Ollama adjudication, fenced and guarded so it cannot be steered.
- `incidents.py`: correlate flagged verdicts into same-host attack chains.
- `remediate.py`: propose reversals and run them only behind a per-action approval gate.
- `cli.py`: the scan / adjudicate / remediate / incidents commands.

## Known limitations

Alibi is honest about its edges. `KNOWN_LIMITATIONS.md` lists every known limitation and deferred
item, each mapped to the milestone that will address it. Nothing there is a silent defect.
