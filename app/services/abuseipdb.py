import logging

import httpx

from app.config import Settings
from app.models import SourceResult

logger = logging.getLogger(__name__)


async def lookup_ip(ip: str, settings: Settings) -> SourceResult | None:
    """Query AbuseIPDB; returns None if disabled or on error."""
    if settings.abuseipdb_api_key is None:
        return None
    headers = {
        "Key": settings.abuseipdb_api_key.get_secret_value(),
        "Accept": "application/json",
    }
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        async with httpx.AsyncClient(timeout=settings.abuseipdb_timeout) as client:
            resp = await client.get(settings.abuseipdb_url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("AbuseIPDB lookup failed: %s", type(exc).__name__)
        return None
    return SourceResult(
        name="abuseipdb",
        score=max(0, min(100, int(data.get("abuseConfidenceScore", 0)))),
        details={
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
        },
    )
