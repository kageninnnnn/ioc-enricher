import base64

import httpx

from app.config import Settings
from app.models import IndicatorType, SourceResult
from app.services.sources.base import Source, SourceContext, parse_json

_COLLECTION = {
    IndicatorType.IPV4: "ip_addresses",
    IndicatorType.IPV6: "ip_addresses",
    IndicatorType.DOMAIN: "domains",
    IndicatorType.MD5: "files",
    IndicatorType.SHA1: "files",
    IndicatorType.SHA256: "files",
    IndicatorType.URL: "urls",
}


def vt_object_id(value: str, ioc_type: IndicatorType) -> str:
    if ioc_type is IndicatorType.URL:
        # https://docs.virustotal.com/reference/url#url-identifiers
        return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return value


def score_from_stats(stats: dict) -> int:
    """Map engine verdict counts to 0-100.

    A handful of engines flagging an object is already a strong signal, so the
    curve is steep: 5+ malicious detections saturate at 100.
    """
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    return min(100, malicious * 20 + suspicious * 10)


class VirusTotal(Source):
    """https://docs.virustotal.com/reference/overview (API v3)"""

    name = "virustotal"
    weight = 0.95
    supported_types = frozenset(_COLLECTION)

    def enabled(self, settings: Settings) -> bool:
        return settings.virustotal_api_key is not None

    async def lookup(
        self, value: str, ioc_type: IndicatorType, ctx: SourceContext
    ) -> SourceResult | None:
        s = ctx.settings
        url = f"{s.virustotal_url}/{_COLLECTION[ioc_type]}/{vt_object_id(value, ioc_type)}"
        resp = await ctx.http.get(
            url, headers={"x-apikey": s.virustotal_api_key.get_secret_value()}
        )
        if resp.status_code == httpx.codes.NOT_FOUND:
            return None
        resp.raise_for_status()
        attrs = (parse_json(resp).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        return self.result(
            score_from_stats(stats),
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            reputation=attrs.get("reputation"),
            tags=attrs.get("tags") or None,
        )
