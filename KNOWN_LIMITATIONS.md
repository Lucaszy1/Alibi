# Known limitations and deferred work

This file is the honest ledger for Alibi. Everything here is either an inherent limitation of the
approach or a deliberately sequenced milestone, not a silent defect. The shipped code is tested
(313 tests). Each item names how it will be addressed. These are tracked, not forgotten, and will
be repaired as the dependent milestone lands, when the paper's evaluation forces the question, or
immediately if one turns out to block real use.

## A. Inherent limitations in shipped code

Detection
- Paraphrase / semantic laundering: recovered only via the local model tier; without a model a
  paraphrased hijack is still flagged, but as UNJUSTIFIED rather than HIJACKED. Fix path: model
  tier (done, partial) plus the anomaly tier (M-An) for the no-source case.
- Taint and provenance are token-overlap based; values transformed in ways not modeled (encryption,
  compression, char-code math, multi-file splitting, unobserved channels) can break the link.
- Decoding covers base64, PowerShell -enc, hex, percent, string-concat, cross-call env vars,
  gzip-in-base64, base32, and ROT13 (noisy transforms gated on a real indicator). Intentionally
  omitted: brute-force single-byte XOR (a 256-key sweep over attacker-controlled blobs is a DoS
  vector for little gain) and certutil/bitsadmin decode-to-file (handled by taint's via-file path).
  Still open: nested multi-layer encodings and .NET FromBase64 without -enc. Fix path: extend decode.py.
- Policy tier keys off EDR MITRE tags, not command content, so an untagged technique is missed by
  policy (provenance/taint may still catch). Fix path: optional decoded-content policy scan.
- Target extraction uses a fixed TLD allowlist, so unusual or newer TLDs may not extract as bare
  hosts (URLs always extract their host). Local files whose extension is also a gTLD (.sh/.zip/
  .app) are no longer misread as hosts. Fix path for allowlist breadth: widen it as needed.
- Alert-to-call linking is time-window heuristic; clock skew or background processes can mislink.

Remediation
- Blocking needs admin/sudo to apply (inherent): hostnames route to 0.0.0.0 in the hosts file, bare
  IPs get a firewall rule (netsh on Windows, iptables/ip6tables on Linux, a pfctl anchor on macOS). DONE.
- Reversals carry an argv vector built from validated parts, so an executor can run them shell-free
  (shell=False); only genuinely shell-shaped reversals (hosts redirect, sc stop&delete chain) keep a
  shell command and are flagged needs_shell. DONE.
- Persistence reversals: schtasks/systemd/launchd and now Windows Run-key / sc.exe service /
  startup-folder are automatic; cron and WMI event-subscription are manual by design (no single safe
  command removes a WMI filter+consumer+binding together). DONE.
- Quoted multi-word task or service names are safely withheld to manual review, not auto-parsed.
- Undo: Alibi rolls back its own reversible containment (restore a quarantined file, remove a
  firewall rule) via a serializable bundle, and never auto-undoes a persistence deletion (that would
  reinstate the attacker's autostart). DONE, and surfaced through the CLI: `remediate --apply` writes
  a rollback bundle and `alibi undo <bundle> --apply` reverts it.

Model, confidence, performance
- The deterministic judge is now benchmarked (M15): 0.933 accuracy, 0.915 macro-F1 on the labeled
  corpus, zero silent-allows and zero false-flags, with ablations and baselines showing each tier
  earns its place (benchmark/REPORT.md). DONE.
- Model-tier accuracy is still unmeasured: the benchmark runs the deterministic judge only (no local
  Ollama in CI). Fix path: a model-tier eval pass once a model is pinned. Deferred.
- Confidence values are hand-tuned, not yet calibrated against corpus scores. Fix path: calibrate on
  an expanded corpus. Deferred.
- Taint uses a precomputed per-session TaintIndex (one pass, snapshot before each call), so a call's
  taint resolves in O(tokens in the call) and the session is O(events) overall, not O(events x calls). DONE.

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
- M11 allowlists: DONE. A trusted --allow file downgrades a flagged verdict to JUSTIFIED
  (judge._apply_allowlist), keeping the original finding in the reason; tested.
- M-An anomaly tier: DONE. A high-severity action with no external target and no tie to the
  request is surfaced as UNKNOWN / ELEVATED for review (judge._anomaly) — the attack-agnostic
  catch for a novel attack that leaves no other signal; tested.
- M12 explainability: DONE (incident report artifact, Mermaid provenance graph, and secret
  redaction in reports are all shipped and tested).
- M13 remediation depth: DONE (IP/firewall blocking, Windows Run-key / service / startup-folder /
  WMI handling, rollback bundle + undo, argv-style shell-free execution, and a macOS pfctl IP block).
- M14 MCP server: DONE. A dependency-free stdio JSON-RPC MCP server (alibi mcp) exposes the inline
  assess guardrail as an `assess` tool (allow / warn / block), alongside the shipped Claude Code hook.
- M15 benchmark and evaluation: DONE for the deterministic judge (labeled paired corpus, confusion
  matrix + precision/recall/F1, operational detection view, tier ablations, naive baselines, and an
  `alibi bench` CLI writing benchmark/REPORT.md). Remaining deferred: model-tier evaluation and
  confidence calibration; the corpus is synthetic-but-realistic and modest in size, to be expanded.
- M16 paper. M17 vision (policy DSL, PyPI, docs site, public benchmark).

## C. Process and housekeeping

- GitHub push, CI badge, and v1.0.0 tag deferred until a milestone worth showing.
- LICENSE (MIT) and CHANGELOG added. DONE.
- CI runs tests (Linux/macOS/Windows x py3.11/3.12) and a lint job (ruff + mypy), both enforced. DONE. Coverage gate still deferred.
- Runs append a JSON history record (--state FILE), readable via `alibi history`; the judge stays stateless. DONE. Full verdict round-trip and cross-run incident correlation remain future work.

## Commitment

These are not closed by ignoring them. Every item is tied to a milestone and will be revisited when
that milestone is built, when evaluation forces the question, or immediately if one blocks real use.
This ledger is updated as items are closed.
