import asyncio
import logging
import time

from pydantic import ValidationError

from app.config import Settings
from app.metrics import CACHE_EVENTS, ENRICH_REQUESTS, SOURCE_LATENCY, SOURCE_LOOKUPS
from app.models import EnrichResponse, SourceResult
from app.services.cache import Backend
from app.services.detector import detect_type, normalize
from app.services.scoring import aggregate
from app.services.sources import ALL_SOURCES, Source, SourceContext

logger = logging.getLogger(__name__)

CACHE_PREFIX = "ioc:v1:"


class Enricher:
    def __init__(
        self,
        settings: Settings,
        ctx: SourceContext,
        cache: Backend,
        sources: tuple[Source, ...] = ALL_SOURCES,
    ) -> None:
        self.settings = settings
        self.ctx = ctx
        self.cache = cache
        self.sources = sources

    async def _run_source(
        self, source: Source, value: str, ioc_type
    ) -> tuple[SourceResult | None, bool]:
        """Return (result, failed)."""
        if not source.supports(ioc_type) or not source.enabled(self.settings):
            SOURCE_LOOKUPS.labels(source.name, "skipped").inc()
            return None, False
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self.settings.timeout):
                result = await source.lookup(value, ioc_type, self.ctx)
        except Exception as exc:  # one broken provider must not break the response
            SOURCE_LOOKUPS.labels(source.name, "error").inc()
            # Log the exception class only: messages may echo URLs with secrets.
            logger.warning(
                "source lookup failed",
                extra={"source": source.name, "error": type(exc).__name__},
            )
            return None, True
        finally:
            SOURCE_LATENCY.labels(source.name).observe(time.perf_counter() - started)
        SOURCE_LOOKUPS.labels(source.name, "hit" if result else "miss").inc()
        return result, False

    async def _cache_get(self, key: str) -> EnrichResponse | None:
        if self.settings.cache_ttl_seconds == 0:
            return None
        try:
            raw = await self.cache.get(key)
        except Exception as exc:
            logger.warning("cache read failed", extra={"error": type(exc).__name__})
            return None
        if raw is None:
            CACHE_EVENTS.labels("miss").inc()
            return None
        try:
            cached = EnrichResponse.model_validate_json(raw)
        except ValidationError:
            CACHE_EVENTS.labels("miss").inc()
            return None
        CACHE_EVENTS.labels("hit").inc()
        return cached.model_copy(update={"cached": True})

    async def _cache_set(self, key: str, resp: EnrichResponse) -> None:
        if self.settings.cache_ttl_seconds == 0:
            return
        try:
            await self.cache.set(key, resp.model_dump_json(), self.settings.cache_ttl_seconds)
        except Exception as exc:
            logger.warning("cache write failed", extra={"error": type(exc).__name__})

    async def enrich(self, indicator: str) -> EnrichResponse:
        """Raises ValueError for an unrecognised indicator."""
        ioc_type = detect_type(indicator)
        value = normalize(indicator, ioc_type)
        key = f"{CACHE_PREFIX}{ioc_type.value}:{value}"

        if (hit := await self._cache_get(key)) is not None:
            ENRICH_REQUESTS.labels(ioc_type.value, hit.verdict.value).inc()
            return hit

        results = await asyncio.gather(
            *(self._run_source(s, value, ioc_type) for s in self.sources)
        )
        sources = [r for r, _ in results if r is not None]
        failed = [s.name for s, (_, err) in zip(self.sources, results, strict=True) if err]
        score, verdict, explanation = aggregate(sources)
        resp = EnrichResponse(
            indicator=value,
            type=ioc_type,
            verdict=verdict,
            score=score,
            sources=sources,
            explanation=explanation,
            failed_sources=failed,
        )
        # Don't pin a degraded answer in the cache: retry failed providers next time.
        if not failed:
            await self._cache_set(key, resp)
        ENRICH_REQUESTS.labels(ioc_type.value, verdict.value).inc()
        return resp
