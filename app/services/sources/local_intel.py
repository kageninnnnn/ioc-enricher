import json
from functools import lru_cache
from pathlib import Path

from app.config import Settings
from app.models import IndicatorType, SourceResult
from app.services.sources.base import Source, SourceContext

DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel.json"


@lru_cache
def load_dataset(path: str | None = None) -> dict[str, dict]:
    p = Path(path) if path else DEFAULT_PATH
    with p.open(encoding="utf-8") as fh:
        entries = json.load(fh)
    return {e["indicator"].lower(): e for e in entries}


class LocalIntel(Source):
    """Curated in-house feed / allowlist shipped with the image."""

    name = "local-intel"
    weight = 1.0
    supported_types = frozenset(IndicatorType)

    def enabled(self, settings: Settings) -> bool:
        return True

    async def lookup(
        self, value: str, ioc_type: IndicatorType, ctx: SourceContext
    ) -> SourceResult | None:
        entry = load_dataset(ctx.settings.threat_intel_path).get(value.lower())
        if entry is None:
            return None
        details = {k: v for k, v in entry.items() if k not in {"indicator", "score"}}
        return self.result(int(entry["score"]), **details)
