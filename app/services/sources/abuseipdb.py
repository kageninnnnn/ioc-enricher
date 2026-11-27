from app.config import Settings
from app.models import IP_TYPES, IndicatorType, SourceResult
from app.services.sources.base import Source, SourceContext, parse_json


class AbuseIPDB(Source):
    """https://docs.abuseipdb.com/#check-endpoint"""

    name = "abuseipdb"
    weight = 0.9
    supported_types = IP_TYPES

    def enabled(self, settings: Settings) -> bool:
        return settings.abuseipdb_api_key is not None

    async def lookup(
        self, value: str, ioc_type: IndicatorType, ctx: SourceContext
    ) -> SourceResult | None:
        s = ctx.settings
        resp = await ctx.http.get(
            s.abuseipdb_url,
            headers={"Key": s.abuseipdb_api_key.get_secret_value(), "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": "90"},
        )
        resp.raise_for_status()
        data = parse_json(resp).get("data") or {}
        reports = int(data.get("totalReports") or 0)
        score = int(data.get("abuseConfidenceScore") or 0)
        return self.result(
            score,
            total_reports=reports,
            country=data.get("countryCode"),
            isp=data.get("isp"),
            usage_type=data.get("usageType"),
            is_tor=data.get("isTor"),
            last_reported_at=data.get("lastReportedAt"),
        )
