from app.config import Settings
from app.models import EnrichResponse, IndicatorType, SourceResult, Verdict
from app.services import abuseipdb, local_intel
from app.services.detector import detect_type, normalize


def score_to_verdict(score: int, has_sources: bool) -> Verdict:
    if not has_sources:
        return Verdict.UNKNOWN
    if score >= 75:
        return Verdict.MALICIOUS
    if score >= 25:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


async def enrich(indicator: str, settings: Settings) -> EnrichResponse:
    ioc_type = detect_type(indicator)
    value = normalize(indicator, ioc_type)
    sources: list[SourceResult] = []

    local = local_intel.lookup(value, settings.threat_intel_path)
    if local:
        sources.append(local)

    if ioc_type in {IndicatorType.IPV4, IndicatorType.IPV6}:
        remote = await abuseipdb.lookup_ip(value, settings)
        if remote:
            sources.append(remote)

    score = max((s.score for s in sources), default=0)
    return EnrichResponse(
        indicator=value,
        type=ioc_type,
        verdict=score_to_verdict(score, bool(sources)),
        score=score,
        sources=sources,
    )
