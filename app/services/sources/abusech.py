"""abuse.ch feeds: URLhaus (malware URLs) and ThreatFox (IOCs).

Both APIs require a free Auth-Key from https://auth.abuse.ch/.
"""

from app.config import Settings
from app.models import HASH_TYPES, IP_TYPES, IndicatorType, SourceResult
from app.services.sources.base import Source, SourceContext, SourceError, parse_json


def _headers(settings: Settings) -> dict[str, str]:
    return {"Auth-Key": settings.abusech_auth_key.get_secret_value()}


def _check_status(data: dict, ok: str = "ok") -> bool:
    status = data.get("query_status")
    if status == ok:
        return True
    if status in {"no_results", "no_result", "hash_not_found", "illegal_search_term"}:
        return False
    raise SourceError(f"abuse.ch query_status={status!r}")


class URLhaus(Source):
    name = "urlhaus"
    weight = 0.9
    supported_types = frozenset(
        {IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.MD5, IndicatorType.SHA256}
        | IP_TYPES
    )

    def enabled(self, settings: Settings) -> bool:
        return settings.abusech_auth_key is not None

    async def lookup(
        self, value: str, ioc_type: IndicatorType, ctx: SourceContext
    ) -> SourceResult | None:
        base = ctx.settings.urlhaus_url.rstrip("/")
        if ioc_type is IndicatorType.URL:
            endpoint, form = "url", {"url": value}
        elif ioc_type in HASH_TYPES:
            endpoint, form = "payload", {f"{ioc_type.value}_hash": value}
        else:
            endpoint, form = "host", {"host": value}
        resp = await ctx.http.post(f"{base}/{endpoint}/", data=form, headers=_headers(ctx.settings))
        resp.raise_for_status()
        data = parse_json(resp)
        if not _check_status(data):
            return None

        if endpoint == "url":
            online = data.get("url_status") == "online"
            return self.result(
                100 if online else 80,
                url_status=data.get("url_status"),
                threat=data.get("threat"),
                tags=data.get("tags") or None,
                date_added=data.get("date_added"),
            )
        if endpoint == "payload":
            return self.result(
                100,
                file_type=data.get("file_type"),
                signature=data.get("signature"),
                url_count=data.get("url_count"),
                first_seen=data.get("firstseen"),
            )
        urls = data.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        return self.result(
            90 if online else 70,
            url_count=len(urls),
            online_urls=online,
            blacklists=data.get("blacklists"),
        )


class ThreatFox(Source):
    name = "threatfox"
    weight = 0.9
    supported_types = frozenset(IndicatorType)

    def enabled(self, settings: Settings) -> bool:
        return settings.abusech_auth_key is not None

    async def lookup(
        self, value: str, ioc_type: IndicatorType, ctx: SourceContext
    ) -> SourceResult | None:
        if ioc_type in HASH_TYPES:
            body = {"query": "search_hash", "hash": value}
        else:
            body = {"query": "search_ioc", "search_term": value, "exact_match": True}
        resp = await ctx.http.post(
            ctx.settings.threatfox_url, json=body, headers=_headers(ctx.settings)
        )
        resp.raise_for_status()
        data = parse_json(resp)
        if not _check_status(data):
            return None
        iocs = data.get("data") or []
        if not isinstance(iocs, list) or not iocs:
            return None
        confidence = max(int(i.get("confidence_level") or 0) for i in iocs)
        return self.result(
            confidence,
            matches=len(iocs),
            malware=sorted({i["malware_printable"] for i in iocs if i.get("malware_printable")})
            or None,
            threat_types=sorted({i["threat_type"] for i in iocs if i.get("threat_type")}) or None,
            first_seen=min((i["first_seen"] for i in iocs if i.get("first_seen")), default=None),
        )
