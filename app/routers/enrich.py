from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.config import Settings, get_settings
from app.models import EnrichRequest, EnrichResponse
from app.services.enricher import enrich

router = APIRouter(tags=["enrich"])


@router.post("/enrich", response_model=EnrichResponse)
async def enrich_indicator(
    req: EnrichRequest, settings: Annotated[Settings, Depends(get_settings)]
) -> EnrichResponse:
    try:
        return await enrich(req.indicator, settings)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc
