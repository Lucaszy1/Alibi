# Known limitations and deferred work

This file is the honest ledger for Alibi. Everything here is either an inherent limitation of the
approach or a deliberately sequenced milestone, not a silent defect. The shipped code is tested
(215 tests). Each item names how it will be addressed. These are tracked, not forgotten, and will
be repaired as the dependent milestone lands, when the paper's evaluation forces the question, or
immediately if one turns out to block real use.

## A. Inherent limitations in shipped code

Detection
- Paraphrase / semantic laundering: recovered only via the local model tier; without a model a
  paraphrased hijack is still flagged, but as UNJUSTIFIED rather than HIJACKED. Fix path: model
  tier (done, partial) plus the anomaly tier (M-An) for the no-source case.
- Taint and provenance are token-overlap based; values transformed in ways not modeled (encryption,
  compression, char-code math, multi-file splitting, unobserved channels) can break the link.
- Decoding is single-layer: base64, PowerShell -enc, hex, percent, string-concat, cross-call env
  vars. Not yet: nested encodings, base32, gzip, XOR, ROT13, .NET FromBase64 without -enc,
  certutil/bitsadmin decode-to-file. Fix path: extend decode.py.
- Policy tier keys off EDR MITRE tags, not command content, so an untagged technique is missed by
  policy (provenance/taint may still catch). Fix path: optional decoded-content policy scan.
- Target extraction uses a fixed TLD allowlist; unusual or newer TLDs may not extract.
- Alert-to-call linking is time-window heuristic; clock skew or background processes can mislink.

Remediation
- block_host blocks by hostname via the hosts file; a bare IP is not meaningfully blocked, and the
  command needs admin/sudo to run. Fix path: firewall-rule reversal for IPs (M13).
- Reversals execute via shell with validated or withheld targets; argv-style execution is a planned
  defense-in-depth hardening.
- Persistence reversals cover schtasks/systemd/launchd/cron. Windows Run-key, WMI, sc.exe services,
  and startup-folder persistence have no reversal yet. Fix path: M13.
- Quoted multi-word task or service names are safely withheld to manual review, not auto-parsed.

Model, confidence, performance
- Model tier needs local Ollama and its accuracy is not yet measured (M15).
- Confidence values are hand-tuned, not calibrated against data (M15).
- trace_taint is memoized per call but still O(events) per distinct call; very large sessions will
  be slow. Fix path: a precomputed per-session taint index.

Privacy
- Secret redaction in shared reports: DONE. redact.py masks credential values (keyed secrets, URL
  credentials, Authorization/Bearer headers, AWS/GitHub/Slack tokens, PEM private-key blocks) and
  report.py applies it through the _san sanitizer before truncation, so a secret can't be half-shown;
  attack indicators (hosts, URLs, commands) are preserved by design. Scope decision: redaction covers
  the report artifact (the output meant to be shared); scan/adjudicate stdout and --json are the
  operator's own local view of their own machine and are intentionally left unredacted.

## B. Deferred milestones (on the roadmap, not built)

- M10 broader ingestion: DONE for the neutral layer. A documented neutral JSON/JSONL alert feed is
  auto-detected and parsed (alerts.py), so any SIEM or EDR that can emit JSON feeds Alibi without a
  bespoke parser; source classification is default-untrusted, so web-fetch, MCP, and subagent
  results are already treated as attacker-controllable (locked by test_source_classification.py).
  DEFERRED: native binary/log parsers (EVTX, Windows Event Log, auditd, osquery, Elastic/Splunk
  native) are a convenience layer on top of that neutral contract, not a correctness gap. Fix path:
  per-format adapters that normalize into the neutral shape, added when a real feed needs one.
- M11 allowlists (false-positive controls).
- M-An unexplained-action anomaly tier (attack-agnostic catch for no-source novel attacks).
- M12 explainability: DONE (incident report artifact, Mermaid provenance graph, and secret
  redaction in reports are all shipped and tested).
- M13 remediation depth (rollback bundle, undo, containment, IP / registry / WMI reversals).
- M14 MCP server exposing assess to any agent (the Claude Code PreToolUse hook is shipped and
  tested; the MCP server is not yet built).
- M15 benchmark and evaluation (corpus, metrics, ablations, baselines, confidence calibration).
- M16 paper. M17 vision (policy DSL, PyPI, docs site, public benchmark).

## C. Process and housekeeping

- GitHub push, CI badge, and v1.0.0 tag deferred until a milestone worth showing.
- No LICENSE or CHANGELOG yet.
- CI runs the test suite but has no lint/type-check (ruff/mypy) or coverage gate yet.
- Verdicts and incidents are not persisted across runs (each run is independent).

## Commitment

These are not closed by ignoring them. Every item is tied to a milestone and will be revisited when
that milestone is built, when evaluation forces the question, or immediately if one blocks real use.
This ledger is updated as items are closed.
