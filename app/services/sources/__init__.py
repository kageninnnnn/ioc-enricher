from app.services.sources.abusech import ThreatFox, URLhaus
from app.services.sources.abuseipdb import AbuseIPDB
from app.services.sources.base import Source, SourceContext, SourceError
from app.services.sources.local_intel import LocalIntel
from app.services.sources.otx import AlienVaultOTX
from app.services.sources.virustotal import VirusTotal

ALL_SOURCES: tuple[Source, ...] = (
    LocalIntel(),
    AbuseIPDB(),
    VirusTotal(),
    AlienVaultOTX(),
    URLhaus(),
    ThreatFox(),
)

__all__ = ["ALL_SOURCES", "Source", "SourceContext", "SourceError"]
