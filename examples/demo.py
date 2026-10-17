#!/usr/bin/env python
"""Cold-start demo for Alibi.

Runs three judgments against ONE real captured Hayabusa alert slice:
  1. a hijacked session (the agent obeyed a poisoned README and exfiltrated credentials),
  2. the same alerts with a defended session (the agent read the README and refused),
  3. the proposed remediation for the hijack (dry run, nothing is executed).

No install and no Ollama needed; this uses the deterministic tiers only.

    python examples/demo.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from alibi.cli import main  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
RESULTS = FIX / "hijacked_exfil.results.csv"
HIJACK = FIX / "hijacked_exfil.jsonl"
DEFENDED = FIX / "defended_readonly.jsonl"


def banner(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def run():
    banner("1. Hijacked session: agent followed a poisoned README and exfiltrated creds")
    main(["scan", str(RESULTS), str(HIJACK)])

    banner("2. Same alerts, defended session: agent read the README and refused to act")
    main(["scan", str(RESULTS), str(DEFENDED)])

    banner("3. Proposed remediation for the hijack (dry run, nothing is executed)")
    main(["remediate", str(RESULTS), str(HIJACK)])


if __name__ == "__main__":
    run()
