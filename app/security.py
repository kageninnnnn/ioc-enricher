"""API-key authentication and per-client rate limiting (FastAPI dependencies)."""

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.config import Settings, get_settings
from app.metrics import AUTH_FAILURES, RATE_LIMITED

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass(frozen=True)
class Client:
    id: str
    authenticated: bool


def _fingerprint(key: str) -> str:
    # Never keep raw keys in cache keys / logs.
    return "key:" + hashlib.sha256(key.encode()).hexdigest()[:16]


async def authenticate(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    api_key: Annotated[str | None, Security(api_key_header)] = None,
) -> Client:
    accepted = settings.accepted_api_keys
    if not accepted:  # auth disabled (local dev / demo)
        host = request.client.host if request.client else "unknown"
        return Client(id=f"ip:{host}", authenticated=False)
    if api_key and any(hmac.compare_digest(api_key, k) for k in accepted):
        return Client(id=_fingerprint(api_key), authenticated=True)
    AUTH_FAILURES.inc()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing or invalid API key",
        headers={"WWW-Authenticate": "ApiKey"},
    )


async def enforce_rate_limit(request: Request, client: Client, cost: int, settings: Settings):
    """Fixed one-minute window per client, shared via Redis when configured."""
    limit = settings.rate_limit_per_minute
    if limit == 0:
        return
    window = int(time.time() // 60)
    key = f"rl:{client.id}:{window}"
    cache = request.app.state.cache
    try:
        used = await cache.incr(key, ttl=65, amount=cost)
    except Exception:  # fail open: rate limiting must not take the API down
        return
    if used > limit:
        RATE_LIMITED.inc()
        retry_after = 60 - int(time.time()) % 60
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"rate limit of {limit} indicators/minute exceeded",
            headers={"Retry-After": str(retry_after)},
        )
