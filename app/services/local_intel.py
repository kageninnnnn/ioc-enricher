import json
from functools import lru_cache
from pathlib import Path

from app.models import SourceResult

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "data" / "threat_intel.json"


@lru_cache
def load_dataset(path: str | None = None) -> dict[str, dict]:
    p = Path(path) if path else DEFAULT_PATH
    with p.open(encoding="utf-8") as fh:
        entries = json.load(fh)
    return {e["indicator"].lower(): e for e in entries}


def lookup(indicator: str, path: str | None = None) -> SourceResult | None:
    entry = load_dataset(path).get(indicator.lower())
    if entry is None:
        return None
    return SourceResult(
        name="local-intel",
        score=int(entry["score"]),
        details={k: v for k, v in entry.items() if k not in {"indicator", "score"}},
    )
