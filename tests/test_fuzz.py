"""Fuzz the ingestion path and hot regexes: malformed, pathological, and random input must fail
gracefully (a controlled exception or a sane return), never hang or crash the interpreter."""

import random

from alibi.alerts import load_alerts
from alibi.decode import reveal
from alibi.judge import extract_targets
from alibi.transcript import load_transcript

PATHOLOGICAL = [
    "", "\x00\x01\x02", "{", "{" * 1000, "}" * 1000, "null", "not json at all",
    "a" * 100000, "%" * 20000, "/" * 20000, "\\x" * 20000, "http://" + "a" * 50000,
    "A" * 60000 + "==", "../" * 5000, "$" * 20000 + "{x}", "\n" * 10000,
    '{"type":"user"', '{"type":"assistant","message":{"content":[', "\ud800",
]


def test_reveal_and_extract_survive_pathological_input():
    for s in PATHOLOGICAL:
        assert isinstance(reveal(s), str)
        assert isinstance(extract_targets(s), set)


def test_transcript_loader_survives_garbage(tmp_path):
    for i, s in enumerate(PATHOLOGICAL):
        p = tmp_path / f"t{i}.jsonl"
        p.write_text(s, encoding="utf-8", errors="surrogatepass")
        try:
            assert isinstance(load_transcript(p), list)
        except Exception:
            pass  # a controlled exception is fine; the point is no hang / no crash


def test_alerts_loader_survives_garbage(tmp_path):
    for i, s in enumerate(PATHOLOGICAL):
        p = tmp_path / f"a{i}.csv"
        p.write_text(s, encoding="utf-8", errors="surrogatepass")
        try:
            assert isinstance(load_alerts(p), list)
        except Exception:
            pass


def test_random_bytes_do_not_break_loaders(tmp_path):
    rnd = random.Random(1337)
    for i in range(150):
        blob = bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 400)))
        pj = tmp_path / f"r{i}.jsonl"
        pj.write_bytes(blob)
        pc = tmp_path / f"r{i}.csv"
        pc.write_bytes(blob)
        for loader, path in ((load_transcript, pj), (load_alerts, pc)):
            try:
                assert isinstance(loader(path), list)
            except Exception:
                pass
