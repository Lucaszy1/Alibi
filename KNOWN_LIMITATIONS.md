# Known limitations and scope

Alibi is an analyzer and advisor, not a complete defense. This file records, at a high level, the
honest limits of the approach and the areas held for future work. Specific detection signatures,
thresholds, and the exact patterns that make evasion harder are kept in internal notes rather than
published, so this document describes what kind of limitation exists, not a recipe for working around
it. The shipped code is tested (356 tests, ruff + mypy clean).

## Inherent to the approach

- Provenance and taint are the primary, signature-independent defenses and the strongest claims Alibi
  makes. They can still be defeated by data transformations the analysis does not model (for example
  strong encryption, or channels never observed in the session). Such cases are not silently allowed;
  they fall through to review.
- Detection vs attribution: some hijacks can be detected (flagged as not-the-user's-intent) without
  being provably attributed to an injected instruction. These are flagged for review, never cleared.
  The optional local model tier improves attribution and is strictly non-exonerating.
- The policy tier is signature-based and therefore inherently incomplete: novel tooling or unmodeled
  obfuscation can slip past it. It is a backstop to provenance and taint, not the main line of
  defense, and an anomaly tier flags consequential actions that match neither the request nor a
  known-benign pattern.
- Heuristic layers (content normalization, instruction-like cues) have finite coverage and serve as
  defense-in-depth. The core provenance and taint analysis does not depend on them.
- Alert-to-action linking is heuristic and can be affected by clock skew or event floods; the window
  is configurable, and process/PID-based linking is a future improvement.

## Self-protection

- The analysis core has no execution path (no eval / exec / subprocess / shell), so parsing hostile
  input cannot run code. SECURITY.md states the trust boundary and the full set of properties.
- All execution is human-gated remediation; the model tier is loopback-bound and non-exonerating.
- Parsing and decoding are resource-bounded so hostile input cannot cause a denial of service.

## Fail-safe posture

- Uncertainty resolves to review, never a silent allow. The benchmark shows zero silent-allows and
  zero false-flags.

## Remediation

- Alibi never acts on its own: every reversal is behind a per-action human approval, and the inline
  hook and MCP guardrail only return allow / warn / block. Applying network or host blocks needs
  admin/sudo. Reversible containment can be rolled back; destructive undo is never automatic.

## Evaluation methodology (important caveat)

- Reported accuracy is measured on a small corpus authored for this project that the judge was partly
  tuned against. It demonstrates the mechanism and guards against regressions; it is NOT an estimate
  of real-world accuracy. A larger, independently sourced corpus and a model-tier run on real hardware
  are required before any performance claim in a paper.

## No required third-party software (by design)

Alibi runs on Python with a minimal footprint and does not require its users to install extra parsers,
services, or agents. It consumes the JSON/CSV that endpoint tools and SIEMs already export, so there is
nothing extra to stand up in order to use it. Two consequences follow:

- Raw binary formats that would need a third-party parser (for example Windows EVTX) are intentionally
  out of scope. Export from your existing tooling instead. This is a deliberate choice to avoid
  imposing a dependency on every user, not a capability gap.
- The optional local model tier is the only component that talks to an external service, and it is off
  by default. Every deterministic tier works with no third-party software at all.

## Status and future work

- Shipped: ingestion (neutral and common vendor JSON), allowlists, anomaly tier, explainability,
  remediation depth with rollback, inline guardrail and MCP server, benchmark with ablations and
  calibration.
- Deferred (convenience, not correctness): some additional host-feed formats.
- Future: policy layer, packaging and docs, an independent public benchmark, and the paper.

## Commitment

Every item here is either inherent to the approach, a documented scope decision, or tied to future
work, and is revisited when that work is built or when evaluation forces the question.
