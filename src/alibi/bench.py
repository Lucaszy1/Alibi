"""Benchmark metrics for Alibi: a confusion matrix and per-class precision / recall / F1 over
(expected, predicted) verdict labels. Pure and deterministic. The adjudication classes are
JUSTIFIED / UNJUSTIFIED / HIJACKED; a prediction outside them (e.g. UNKNOWN) counts as a miss for
the true class and never as a true positive, so hedging cannot inflate the score."""

from __future__ import annotations

from dataclasses import dataclass

from alibi.verdict import VerdictKind

JUSTIFIED = "JUSTIFIED"
UNJUSTIFIED = "UNJUSTIFIED"
HIJACKED = "HIJACKED"
CLASSES = (JUSTIFIED, UNJUSTIFIED, HIJACKED)


def label_of(kind) -> str:
    """Canonical label string for a VerdictKind (or a plain string)."""
    return getattr(kind, "name", str(kind))


@dataclass(frozen=True)
class ClassMetrics:
    label: str
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass(frozen=True)
class Metrics:
    confusion: dict
    per_class: dict
    n: int

    @property
    def accuracy(self) -> float:
        correct = sum(self.confusion.get(c, {}).get(c, 0) for c in CLASSES)
        return correct / self.n if self.n else 0.0

    @property
    def macro_f1(self) -> float:
        return sum(c.f1 for c in self.per_class.values()) / len(self.per_class) if self.per_class else 0.0


def score(pairs) -> Metrics:
    """pairs: iterable of (expected_label, predicted_label) as strings."""
    pairs = [(label_of(e), label_of(p)) for e, p in pairs]
    confusion: dict = {c: {} for c in CLASSES}
    for exp, pred in pairs:
        row = confusion.setdefault(exp, {})
        row[pred] = row.get(pred, 0) + 1
    per_class = {}
    for lab in CLASSES:
        tp = confusion.get(lab, {}).get(lab, 0)
        fp = sum(confusion.get(t, {}).get(lab, 0) for t in confusion if t != lab)
        fn = sum(cnt for pred, cnt in confusion.get(lab, {}).items() if pred != lab)
        per_class[lab] = ClassMetrics(lab, tp, fp, fn)
    return Metrics(confusion, per_class, len(pairs))


assert VerdictKind  # labels align with the verdict enum names
