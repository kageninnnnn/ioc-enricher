"""Turn per-source scores into one explainable verdict.

Rules (deliberately simple so an analyst can reason about them):

1. Each source score is multiplied by the source's reliability weight.
2. The strongest weighted signal becomes the base score.
3. Corroboration bonus: +5 for every *additional* source that independently
   scores >= 50, capped at 100. Two feeds agreeing is worth more than one.
4. An explicit allowlist entry (local feed, score 0) wins: verdict "clean".
5. No source knew anything -> "unknown" (not "clean"!).
"""

from app.models import SourceResult, Verdict

MALICIOUS_THRESHOLD = 75
SUSPICIOUS_THRESHOLD = 25
CORROBORATION_MIN = 50
CORROBORATION_BONUS = 5


def score_to_verdict(score: int, has_sources: bool) -> Verdict:
    if not has_sources:
        return Verdict.UNKNOWN
    if score >= MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def aggregate(sources: list[SourceResult]) -> tuple[int, Verdict, list[str]]:
    if not sources:
        return 0, Verdict.UNKNOWN, ["no source has data on this indicator"]

    allow = next(
        (s for s in sources if s.name == "local-intel" and s.details.get("source") == "allowlist"),
        None,
    )
    if allow is not None:
        return 0, Verdict.CLEAN, ["indicator is on the local allowlist"]

    weighted = sorted(
        ((round(s.score * s.weight), s) for s in sources), key=lambda t: t[0], reverse=True
    )
    base, top = weighted[0]
    explanation = [f"strongest signal: {top.name} score {top.score} x weight {top.weight} = {base}"]

    agreeing = [s.name for _, s in weighted[1:] if s.score >= CORROBORATION_MIN]
    score = base
    if agreeing and top.score >= CORROBORATION_MIN:
        bonus = CORROBORATION_BONUS * len(agreeing)
        score = min(100, base + bonus)
        explanation.append(f"corroborated by {', '.join(agreeing)}: +{bonus}")

    verdict = score_to_verdict(score, True)
    explanation.append(f"final score {score} -> {verdict.value}")
    return score, verdict, explanation
