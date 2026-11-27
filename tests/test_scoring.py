import pytest

from app.models import SourceResult, Verdict
from app.services.scoring import aggregate, score_to_verdict


def src(name, score, weight=1.0, **details):
    return SourceResult(name=name, score=score, weight=weight, details=details)


def test_empty():
    score, verdict, expl = aggregate([])
    assert (score, verdict) == (0, Verdict.UNKNOWN)
    assert expl


def test_allowlist_wins():
    score, verdict, _ = aggregate([src("local-intel", 0, source="allowlist"), src("otx", 100)])
    assert (score, verdict) == (0, Verdict.CLEAN)


def test_weighted_max():
    score, verdict, expl = aggregate([src("otx", 100, 0.6), src("abuseipdb", 80, 0.9)])
    assert score == 72 + 5  # abuseipdb 80*0.9=72 strongest, otx >=50 corroborates
    assert verdict is Verdict.MALICIOUS
    assert "abuseipdb" in expl[0]


def test_bonus_capped():
    sources = [src("a", 100), src("b", 90), src("c", 90), src("d", 90)]
    score, verdict, _ = aggregate(sources)
    assert score == 100
    assert verdict is Verdict.MALICIOUS


def test_no_bonus_when_top_below_50():
    score, _, expl = aggregate([src("a", 40), src("b", 60, 0.5)])
    assert score == 40
    assert not any("corroborated" in e for e in expl)


def test_no_bonus_when_others_weak():
    score, _, _ = aggregate([src("a", 90), src("b", 49)])
    assert score == 90


@pytest.mark.parametrize(
    ("score", "has", "expected"),
    [
        (0, False, Verdict.UNKNOWN),
        (100, False, Verdict.UNKNOWN),
        (0, True, Verdict.CLEAN),
        (24, True, Verdict.CLEAN),
        (25, True, Verdict.SUSPICIOUS),
        (74, True, Verdict.SUSPICIOUS),
        (75, True, Verdict.MALICIOUS),
        (100, True, Verdict.MALICIOUS),
    ],
)
def test_thresholds(score, has, expected):
    assert score_to_verdict(score, has) is expected
