"""Item 15: model-tier evaluation harness. With a model backend attached, the judge is scored over
the same corpus by the same metrics. A stub backend (no Ollama) recovers the laundered case, showing
the harness works and that the model tier only strengthens a verdict (it never creates a false flag)."""

from dataclasses import replace
from pathlib import Path

from alibi.bench import detection, evaluate, evaluate_system, load_corpus, model_tier_system
from alibi.verdict import VerdictKind

ROOT = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"


class _StubModel:
    """Stands in for a local model: on the paraphrase-recovery call (an UNJUSTIFIED verdict that has
    untrusted content), recognize an injected persistence instruction and strengthen to HIJACKED."""

    def judge(self, context):
        det = context.deterministic
        untrusted = " ".join(r.content.lower() for r in context.untrusted_results)
        if det.verdict is VerdictKind.UNJUSTIFIED and ("scheduled task" in untrusted or "persist" in untrusted):
            return replace(det, verdict=VerdictKind.HIJACKED,
                           reason="model: injected persistence instruction in untrusted content")
        return None


def test_harness_preserves_safety():
    _, pairs = evaluate_system(load_corpus(ROOT), model_tier_system(_StubModel()))
    d = detection(pairs)
    assert d["silently_allowed"] == 0 and d["false_flags"] == 0


def test_model_recovers_laundered_case():
    corpus = load_corpus(ROOT)
    det_acc = evaluate(corpus)[0].accuracy
    model_acc = evaluate_system(corpus, model_tier_system(_StubModel()))[0].accuracy
    assert det_acc < model_acc  # the model tier closes the one attribution gap
