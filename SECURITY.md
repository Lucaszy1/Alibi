# Security model

Alibi judges whether an AI coding agent's actions, flagged by endpoint security, were justified by
the user's request. It is an **analyzer and advisor**, not an autonomous agent. This document states
its trust boundary and the properties that keep the tool itself from becoming an attack vector.

## Trust boundary

Alibi runs on a **trusted analyst/operator machine** and reasons over inputs that may be
**attacker-influenced**:

- **Untrusted (assume hostile):** tool-result content in the transcript (file reads, web fetches,
  MCP/subagent output), the command text of flagged actions, and endpoint alert fields. Source
  classification is default-untrusted: anything not on a small allowlist of agent-side action tools
  is treated as attacker-controllable.
- **Trusted by assumption:** the user's own turns in the transcript (pasted/attached blocks excepted
  - those are excluded from justification), and the operator running the CLI. If the session record
  itself is forged, that is outside the boundary.

Alibi assumes the host it runs on is not already compromised; nothing can help if it is.

## Why reading hostile input cannot execute code

The analysis engine (judge, decode, taint, provenance, incidents, report) is **pure**: it parses
JSON/CSV/text and returns verdicts. It contains **no `eval`, `exec`, `subprocess`, or shell**. Parsing
is hardened: `yaml.safe_load` only, stdlib `json`/`csv`, hard input size caps, a bounded `reveal()`
(linear indicator regex, capped matches/tokens, size-limited gunzip, bounded recursion) so hostile
input cannot cause catastrophic backtracking or memory blow-up, and a fuzz suite over the loaders.

## Why Alibi cannot be turned into a weapon against its operator

- **Nothing runs without a human yes.** The only execution path is `remediate --apply`, which runs a
  reversal only after a per-action `y/N` prompt **and** with a real executor; no executor means a dry
  run. The inline hook and the MCP server only return allow / warn / block - they never execute.
- **Generated reversals are built from validated parts.** A target with unusual or unsafe characters,
  or a truncated quoted name, is withheld to manual review with no command at all.
- **Shell-free by preference, and optionally shell-free by force.** Single-process reversals carry an
  argv vector and run with `shell=False`; `remediate --apply --no-shell` refuses any reversal that
  needs a shell, so execution is structurally limited to validated argv.
- **The model tier is strictly non-exonerating.** It may escalate a verdict but can never clear one to
  JUSTIFIED, so a prompt injection in the untrusted content it reads cannot talk the judge into
  allowing an action. By default the model host must be loopback (`--allow-remote-model` to override).
- **Evasion is normalized away.** Zero-width, bidi-control, fullwidth, and common Cyrillic/Greek
  homoglyphs are canonicalized before matching.

## Fail-safe posture

Alibi fails toward caution: uncertainty becomes UNKNOWN (human review), never a silent allow; the
benchmark shows zero silent-allows and zero false-flags; the CLI exits non-zero on bad input rather
than reporting "clean". Real-time prevention is the inline guardrail returning BLOCK before a hijacked
tool call runs.

## Residual risks (honest)

- An operator who blindly approves every `--apply` prompt can run a safe-looking reversal; the human is
  the final gate.
- A model endpoint the operator points at is trusted to that extent (hence the loopback default).
- A compromised host, or a forged session transcript, is outside the trust boundary.
- Confusables folding is a curated subset; instruction-like heuristics are English-only (provenance and
  taint are language-independent).

## Reporting

Security issues: open a private report to the maintainer rather than a public issue.
