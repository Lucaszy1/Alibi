"""M15a: the benchmark metrics engine. Confusion matrix and per-class precision/recall/F1 must be
exact on a hand-computed example, a perfect run must score 1.0, and an out-of-class prediction
(UNKNOWN) must count as a miss, never a true positive."""

import math

from alibi.bench import CLASSES, HIJACKED, JUSTIFIED, UNJUSTIFIED, score


def _approx(a, b):
    return math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-9)


def test_perfect_run_scores_one():
    pairs = [(JUSTIFIED, JUSTIFIED), (UNJUSTIFIED, UNJUSTIFIED), (HIJACKED, HIJACKED)]
    m = score(pairs)
    assert _approx(m.accuracy, 1.0) and _approx(m.macro_f1, 1.0)
    for c in CLASSES:
        assert _approx(m.per_class[c].f1, 1.0)


def test_hand_computed_confusion():
    pairs = [(JUSTIFIED, JUSTIFIED), (JUSTIFIED, JUSTIFIED),
             (UNJUSTIFIED, UNJUSTIFIED), (HIJACKED, HIJACKED), (HIJACKED, UNJUSTIFIED)]
    m = score(pairs)
    assert _approx(m.accuracy, 0.8)
    j, u, h = m.per_class[JUSTIFIED], m.per_class[UNJUSTIFIED], m.per_class[HIJACKED]
    assert (j.tp, j.fp, j.fn) == (2, 0, 0) and _approx(j.f1, 1.0)
    assert (u.tp, u.fp, u.fn) == (1, 1, 0) and _approx(u.precision, 0.5) and _approx(u.recall, 1.0)
    assert (h.tp, h.fp, h.fn) == (1, 0, 1) and _approx(h.precision, 1.0) and _approx(h.recall, 0.5)
    assert _approx(m.macro_f1, (1.0 + 2 / 3 + 2 / 3) / 3)


def test_unknown_prediction_is_a_miss_not_a_tp():
    pairs = [(HIJACKED, "UNKNOWN"), (HIJACKED, HIJACKED)]
    m = score(pairs)
    h = m.per_class[HIJACKED]
    assert h.tp == 1 and h.fn == 1 and _approx(h.recall, 0.5)
    assert _approx(m.accuracy, 0.5)


def test_empty_corpus_does_not_crash():
    m = score([])
    assert m.n == 0 and _approx(m.accuracy, 0.0) and _approx(m.macro_f1, 0.0)
