# Alibi

Alibi reads AI coding-agent session transcripts alongside endpoint-security alerts and decides
whether each alert was justified by what the user actually asked for.

## Verdicts

| Verdict       | Meaning                                                                 |
|---------------|-------------------------------------------------------------------------|
| `JUSTIFIED`   | The flagged action follows from the user's request.                     |
| `UNJUSTIFIED` | The user did not ask for it, with no sign of outside influence.         |
| `HIJACKED`    | The action was driven by injected or untrusted content, not the user.   |

## Layout

```
src/alibi/   package code
tests/       pytest suite
data/        sample transcripts and alert logs
```

## Development

```
python -m venv .venv
.venv\Scripts\activate        # Windows; use `source .venv/bin/activate` elsewhere
pip install -e ".[dev]"
pytest
```

## Status

Parsing, linking, and the deterministic judge tiers are in place; the model tier is not.

- `transcript.py`: Claude Code session transcripts into a timeline of prompts, tool calls,
  and tool results (each result marked TRUSTED or UNTRUSTED).
- `alerts.py`: Hayabusa results CSV into alerts with process lineage and MITRE ATT&CK tags.
- `link.py`: links each alert to the tool call that caused it, to Claude Code itself, or to
  nothing (not the agent).
- `judge.py` / `verdict.py`: turns a linked alert into a verdict (provenance and policy tiers),
  a harness disposition, or stands aside.
