import asyncio
import logging
from collections import Counter
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.config import Settings, get_settings
from app.models import (
    BatchEnrichRequest,
    BatchEnrichResponse,
    BatchError,
    EnrichRequest,
    EnrichResponse,
)
from app.security import Client, authenticate, enforce_rate_limit
from app.services.enricher import Enricher

router = APIRouter(tags=["enrich"])
audit = logging.getLogger("ioc_enricher.audit")

_ERRORS = {
    401: {"description": "Missing or invalid API key"},
    429: {"description": "Rate limit exceeded"},
}


def get_enricher(request: Request) -> Enricher:
    return request.app.state.enricher


@router.post("/enrich", response_model=EnrichResponse, responses=_ERRORS)
async def enrich_indicator(
    req: EnrichRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    client: Annotated[Client, Depends(authenticate)],
    enricher: Annotated[Enricher, Depends(get_enricher)],
) -> EnrichResponse:
    """Enrich one IOC (IP, domain, URL, MD5/SHA1/SHA256). Defanged input is accepted."""
    await enforce_rate_limit(request, client, 1, settings)
    try:
        resp = await enricher.enrich(req.indicator)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
    audit.info(
        "indicator enriched",
        extra={
            "client": client.id,
            "ioc_type": resp.type.value,
            "verdict": resp.verdict.value,
            "score": resp.score,
            "cached": resp.cached,
        },
    )
    return resp


@router.post("/enrich/batch", response_model=BatchEnrichResponse, responses=_ERRORS)
async def enrich_batch(
    req: BatchEnrichRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    client: Annotated[Client, Depends(authenticate)],
    enricher: Annotated[Enricher, Depends(get_enricher)],
) -> BatchEnrichResponse:
    """Enrich up to `BATCH_MAX_ITEMS` indicators. Duplicates are collapsed; invalid
    items are reported in `errors` instead of failing the whole batch."""
    items = list(dict.fromkeys(i.strip() for i in req.indicators if i.strip()))
    if not items:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "no indicators supplied")
    if len(items) > settings.batch_max_items:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"batch too large: {len(items)} > {settings.batch_max_items}",
        )
    await enforce_rate_limit(request, client, len(items), settings)

    sem = asyncio.Semaphore(10)  # bound fan-out towards upstream APIs

    async def one(ind: str) -> EnrichResponse | BatchError:
        async with sem:
            try:
                return await enricher.enrich(ind)
            except ValueError as exc:
                return BatchError(indicator=ind, error=str(exc))

    outcomes = await asyncio.gather(*(one(i) for i in items))
    results = [o for o in outcomes if isinstance(o, EnrichResponse)]
    errors = [o for o in outcomes if isinstance(o, BatchError)]
    summary = Counter(r.verdict.value for r in results)
    summary["invalid"] = len(errors)
    audit.info(
        "batch enriched",
        extra={
            "client": client.id,
            "items": len(items),
            **{f"n_{k}": v for k, v in summary.items()},
        },
    )
    return BatchEnrichResponse(results=results, errors=errors, summary=dict(summary))
