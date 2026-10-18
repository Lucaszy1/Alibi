# Changelog

All notable changes to Alibi are documented here. The format is based on Keep a Changelog. This
project is pre-1.0 and has not yet been released or tagged; everything below is unreleased.

## [Unreleased]

### Added
- Provenance-based adjudicator: links endpoint-security (Hayabusa/Sysmon) alerts to an AI agent's
  tool calls and classifies each flagged action as JUSTIFIED, UNJUSTIFIED, or HIJACKED using TRUSTED
  vs UNTRUSTED tool-result provenance rather than signatures.
- Tiered deterministic judge: link, provenance (untrusted-target hits), taint (cross-call, decode-
  aware, via dropped files), policy (MITRE ATT&CK strict/escalate categories), plus an attack-agnostic
  anomaly catch for high-severity actions with no explanation.
- Decoding: base64, PowerShell -enc (UTF-16LE), hex, percent, string-concat, same-command env vars.
- Attack-chain correlation into incidents; Markdown incident report with a Mermaid provenance graph
  and secret redaction for shared output.
- Remediation behind a human-approval gate: firewall blocking for bare IPs (netsh/iptables/ip6tables);
  Windows Run-key / sc service / startup-folder persistence reversals (WMI flagged manual); a
  serializable rollback bundle with undo; argv-style shell-free execution.
- Ingestion: Hayabusa CSV plus a neutral JSON/JSONL alert adapter; default-untrusted classification
  for Read/Bash/WebFetch/Glob/subagent/MCP tool results.
- Inline guardrail with a Claude Code PreToolUse hook (allow / warn / block).
- Allowlist downgrade of flags via a trusted config file.
- Benchmark: labeled paired corpus (25 cases), confusion matrix with per-class precision/recall/F1,
  an operational detection view, tier ablations, and naive baselines, exposed through an `alibi bench`
  CLI that writes benchmark/REPORT.md. Deterministic judge: 0.96 accuracy, 0.947 macro-F1, zero
  silent-allows, zero false-flags; ablations show each tier earns its place.
- CLI subcommands: scan, adjudicate, remediate, incidents, report, hook, undo, bench.

### Known limitations
- Tracked in KNOWN_LIMITATIONS.md: deferred milestones (vendor binary parsers, MCP server, model-tier
  evaluation, confidence calibration, macOS pf adapter) and inherent limits, each with a repair path.
