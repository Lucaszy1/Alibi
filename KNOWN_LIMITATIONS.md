# Known limitations and deferred work

This file is the honest ledger for Alibi. Everything here is either an inherent limitation of the
approach, a deliberate scope decision, or a sequenced milestone -- not a silent defect. The shipped
code is tested (339 tests, ruff + mypy clean). Each item says how it is addressed or why it is left.

## A. Inherent limitations in shipped code

Detection
- Attribution of laundered hijacks: a hijack whose injected instruction carries no distinctive token
  (e.g. "create a scheduled task" with no host/path) cannot be proven by provenance, so it is still
  flagged but as UNJUSTIFIED rather than HIJACKED. It is never silently allowed. The model tier
  recovers it semantically when a local model is configured (and the model tier is strictly
  non-exonerating -- see Robustness). This is the one benchmark miss.
- Taint and provenance are token-overlap based; values transformed in ways not modeled (encryption,
  compression, char-code math, multi-file splitting, unobserved channels) can break the link.
- Decoding covers base64, PowerShell -enc, hex, percent, string-concat, cross-call env vars,
  gzip-in-base64, base32, ROT13, and nested multi-layer combinations (recursive, bounded depth/total);
  .NET FromBase64String is caught by the generic base64 scan. Intentionally omitted: brute-force
  single-byte XOR (a 256-key sweep over attacker-controlled blobs is a DoS vector for little gain) and
  certutil/bitsadmin decode-to-file (handled by taint's via-file path). Still open: keyed or stateful
  transforms (e.g. AES). Fix path: extend decode.py.
- Policy applies to both EDR MITRE tags and decoded command content: anchored command signatures
  (cmdkey, schtasks /create, reg ...Run, Set-MpPreference -Disable, vssadmin delete, Get-Clipboard,
  ...) catch an untagged sensitive action, and dual-use tokens (curl/wget) are deliberately excluded
  so justified work is not false-flagged. It is still keyword/signature based, so a novel tool name or
  an obfuscation the decoder does not model can evade the policy tier (provenance and taint may still
  catch it).
- Target extraction uses a TLD allowlist, widened with common ccTLDs and abused gTLDs; it stays an
  allowlist by design (ordinary dotted words and word-like TLDs .to/.in/.it excluded), URLs always
  extract their host regardless of TLD, and local files whose extension is also a gTLD (.sh/.zip/.app)
  are not misread as hosts. A bare host on a very obscure TLD may still be missed.
- Alert-to-call linking is a time-window heuristic; clock skew between the EDR and the transcript, or
  a flood of background events, can mis-link or break linking. The window is configurable
  (--window-seconds). Fix path: process-tree / PID-based linking where the EDR provides it.

Robustness against tampering (Alibi judging attacker-influenced input)
- Model tier is strictly non-exonerating: it may escalate an UNKNOWN to UNJUSTIFIED/HIJACKED or
  strengthen an UNJUSTIFIED to HIJACKED, but can never clear a verdict to JUSTIFIED. A prompt
  injection embedded in the untrusted content the model reads cannot talk the judge into allowing an
  action. DONE.
- Pasted / attached content inside a user message is excluded from justification matching, so an
  attacker whose payload the user pasted cannot self-justify an action by having its target appear
  "in the request". DONE.
- Normalization folds unicode (NFKC), strips zero-width and bidi-control characters, and folds a
  curated set of Cyrillic/Greek homoglyphs to Latin before matching, so invisible-character,
  fullwidth, and common look-alike-letter evasion is canonicalized away. LIMIT: the confusables set is
  a curated subset, not the full Unicode confusables database, and other scripts are not folded. Fix
  path: a fuller table if a feed needs it.
- Instruction-detection heuristics (the "instruction-like text" boost) are English-only, so a prompt
  injection written in another language is not boosted -- but provenance and taint do not depend on
  language, so such a hijack is still caught when it carries a distinctive target. Fix path:
  multilingual instruction cues.
- User turns in the transcript are trusted as the user's genuine intent (pasted blocks aside). An
  attacker who could forge a real user-role message could manufacture justification; that is outside
  the trust boundary (it would mean the session record itself is forged). Documented assumption.
- reveal() is bounded (linear indicator regex, capped matches/tokens, size-limited gunzip, bounded
  recursion) so hostile input cannot make the analyzer slow -- a ReDoS/DoS in Alibi would itself be a
  vulnerability. DONE.

Remediation
- Blocking needs admin/sudo to apply (inherent): hostnames route to 0.0.0.0 in the hosts file, bare
  IPs get a firewall rule (netsh on Windows, iptables/ip6tables on Linux, a pfctl anchor on macOS).
- Reversals carry an argv vector built from validated parts for shell-free execution; only genuinely
  shell-shaped reversals keep a shell command and are flagged needs_shell.
- Persistence reversals: schtasks/systemd/launchd and Windows Run-key / sc.exe service /
  startup-folder are automatic; cron and WMI event-subscription are manual by design.
- Quoted multi-word task/service names are withheld to manual review, not auto-parsed.
- Undo: Alibi rolls back its own reversible containment via a serializable bundle and never
  auto-undoes a persistence deletion; `remediate --apply` writes the bundle, `alibi undo` reverts it.
- Alibi never acts on its own: every reversal is behind a per-action human approval and a real
  executor (no executor = dry run); the inline hook / MCP guardrail only returns allow/warn/block.

Model, confidence, performance
- Deterministic judge benchmarked: 0.96 accuracy, 0.947 macro-F1 on the 25-case corpus, zero
  silent-allows, zero false-flags, with ablations and baselines (benchmark/REPORT.md).
- Model-tier evaluation harness in place (bench.model_tier_system); a mock backend shows it recovers
  the laundered case. Real numbers need a local Ollama model at run time (practical on GPU hardware;
  CPU-only runs are slow).
- Confidence is measured (alibi bench --calibration) and is not yet probability-calibrated. Re-tuning
  needs a larger corpus.
- Taint uses a precomputed per-session TaintIndex: O(tokens) per call, O(events) per session.

Privacy
- Secret redaction in shared reports (redact.py via report.py _san, before truncation) masks
  credential values and known token shapes while preserving attack indicators; scan/adjudicate stdout
  and --json are the operator's local view and are intentionally not redacted.

Evaluation methodology (important caveat)
- The 0.96 figure is on a 25-case corpus authored for this project that the judge was partly tuned
  against (e.g. the URL-coverage fix was found via a corpus miss). It demonstrates the mechanism and
  guards against regressions; it is NOT an estimate of real-world accuracy. The anti-tampering
  behaviors are covered by separate regression tests, not folded into the scored corpus, so they do
  not inflate it. Fix path: a larger, independently-sourced corpus and a model-tier run on real
  hardware before any performance claim in the paper.

## B. Milestones (status)

- M10 ingestion: DONE for the neutral + vendor-JSON layer (neutral JSON/JSONL auto-detected; Elastic
  ECS and Splunk field names normalized; default-untrusted source classification). DEFERRED: binary
  EVTX / Windows Event Log (needs a parser dependency), auditd text, osquery epoch feeds -- convenience
  layers, not correctness gaps.
- M11 allowlists: DONE. M-An anomaly tier: DONE. M12 explainability: DONE.
- M13 remediation depth: DONE (IP/firewall incl. macOS pf, Windows persistence, rollback+undo, argv).
- M14 MCP server: DONE (dependency-free stdio JSON-RPC exposing the assess guardrail).
- M15 benchmark: DONE for the deterministic judge (corpus, metrics, detection view, ablations,
  baselines, calibration, model-tier harness, alibi bench CLI). See the evaluation caveat above.
- M16 paper: not started (deliberately, until the tool is complete and a real-hardware eval is run).
- M17 vision: not started -- policy DSL, PyPI publish, docs site, public benchmark. Mostly
  publishing/packaging decisions rather than tool capability.

## C. Process and housekeeping

- GitHub push, CI badge, v1.0.0 tag: deferred pending the owner's decision on remote + visibility.
- LICENSE (MIT) and CHANGELOG: DONE.
- CI: tests on Linux/macOS/Windows x py3.11/3.12 plus an enforced ruff + mypy lint job. Coverage gate
  still deferred.
- Run history: runs append a JSON record (--state FILE), readable via `alibi history`; the judge is
  stateless. Full verdict round-trip and cross-run incident correlation remain future work.

## Commitment

These are not closed by ignoring them. Every item is either done, a documented scope decision, or tied
to a milestone, and is revisited when that milestone is built, when evaluation forces the question, or
immediately if one blocks real use. This ledger is updated as items change.
