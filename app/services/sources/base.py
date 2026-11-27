"""Common interface for threat-intel sources.

A source returns a ``SourceResult`` when it knows something about the indicator,
``None`` when it has no record (a *miss*), and raises on transport/parse errors.
The enricher turns those three outcomes into metrics and never lets one failing
provider break the whole response.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx

from app.config import Settings
from app.models import IndicatorType, SourceResult


@dataclass(frozen=True)
class SourceContext:
    settings: Settings
    http: httpx.AsyncClient


class SourceError(Exception):
    """Raised by a source when the provider answered with something unusable."""


class Source(ABC):
    name: str
    #: Reliability weight in [0, 1] used by the scoring engine.
    weight: float = 1.0
    supported_types: frozenset[IndicatorType]

    def supports(self, ioc_type: IndicatorType) -> bool:
        return ioc_type in self.supported_types

    def enabled(self, settings: Settings) -> bool:  # pragma: no cover - trivial default
        return True

    @abstractmethod
    async def lookup(
        self, value: str, ioc_type: IndicatorType, ctx: SourceContext
    ) -> SourceResult | None: ...

    def result(self, score: float, **details) -> SourceResult:
        return SourceResult(
            name=self.name,
            score=max(0, min(100, round(score))),
            weight=self.weight,
            details={k: v for k, v in details.items() if v is not None},
        )


def parse_json(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
    except ValueError as exc:
        raise SourceError("invalid JSON from provider") from exc
    if not isinstance(data, dict):
        raise SourceError("unexpected JSON shape from provider")
    return data
