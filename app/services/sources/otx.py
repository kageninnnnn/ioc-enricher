import httpx

from app.config import Settings
from app.models import IndicatorType, SourceResult
from app.services.sources.base import Source, SourceContext, parse_json

_SECTION = {
    IndicatorType.IPV4: "IPv4",
    IndicatorType.IPV6: "IPv6",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.MD5: "file",
    IndicatorType.SHA1: "file",
    IndicatorType.SHA256: "file",
    IndicatorType.URL: "url",
}


class AlienVaultOTX(Source):
    """https://otx.alienvault.com/api - community pulses referencing the indicator."""

    name = "otx"
    # Pulses are community-curated and often include benign infrastructure,
    # so OTX alone should not push an indicator to "malicious".
    weight = 0.6
    supported_types = frozenset(_SECTION)

    def enabled(self, settings: Settings) -> bool:
        return settings.otx_api_key is not None

    async def lookup(
        self, value: str, ioc_type: IndicatorType, ctx: SourceContext
    ) -> SourceResult | None:
        s = ctx.settings
        url = f"{s.otx_url}/{_SECTION[ioc_type]}/{value}/general"
        resp = await ctx.http.get(url, headers={"X-OTX-API-KEY": s.otx_api_key.get_secret_value()})
        if resp.status_code == httpx.codes.NOT_FOUND:
            return None
        resp.raise_for_status()
        pulse_info = parse_json(resp).get("pulse_info") or {}
        count = int(pulse_info.get("count") or 0)
        if count == 0:
            return None
        pulses = pulse_info.get("pulses") or []
        malware = sorted(
            {
                fam.get("display_name")
                for p in pulses
                for fam in (p.get("malware_families") or [])
                if isinstance(fam, dict) and fam.get("display_name")
            }
        )
        return self.result(
            min(100, count * 15),
            pulse_count=count,
            pulses=[p.get("name") for p in pulses[:5]] or None,
            malware_families=malware or None,
        )
