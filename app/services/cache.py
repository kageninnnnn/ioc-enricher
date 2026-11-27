"""Response cache and rate-limit counters.

Redis is used when ``REDIS_URL`` is set, so cache and rate limits are shared
across replicas. Otherwise an in-process TTL store is used (fine for a single
pod / local dev). Cache failures are logged and treated as misses: the cache
must never take the API down.
"""

import logging
import time
from typing import Protocol

logger = logging.getLogger(__name__)


class Backend(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl: int) -> None: ...
    async def incr(self, key: str, ttl: int, amount: int = 1) -> int: ...
    async def ping(self) -> bool: ...
    async def close(self) -> None: ...


class MemoryBackend:
    def __init__(self, max_items: int = 10_000) -> None:
        self._data: dict[str, tuple[float, str | int]] = {}
        self._max = max_items

    def _alive(self, key: str) -> tuple[float, str | int] | None:
        item = self._data.get(key)
        if item is None:
            return None
        if item[0] < time.monotonic():
            self._data.pop(key, None)
            return None
        return item

    def _evict(self) -> None:
        if len(self._data) < self._max:
            return
        now = time.monotonic()
        for k in [k for k, (exp, _) in self._data.items() if exp < now]:
            del self._data[k]
        while len(self._data) >= self._max:  # still full: drop oldest inserted
            self._data.pop(next(iter(self._data)))

    async def get(self, key: str) -> str | None:
        item = self._alive(key)
        return None if item is None else str(item[1])

    async def set(self, key: str, value: str, ttl: int) -> None:
        self._evict()
        self._data[key] = (time.monotonic() + ttl, value)

    async def incr(self, key: str, ttl: int, amount: int = 1) -> int:
        item = self._alive(key)
        if item is None:
            self._evict()
            self._data[key] = (time.monotonic() + ttl, amount)
            return amount
        count = int(item[1]) + amount
        self._data[key] = (item[0], count)
        return count

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        self._data.clear()


class RedisBackend:
    def __init__(self, client) -> None:  # redis.asyncio.Redis
        self._r = client

    @classmethod
    def from_url(cls, url: str) -> "RedisBackend":
        from redis.asyncio import Redis

        return cls(Redis.from_url(url, decode_responses=True, socket_timeout=1.0))

    async def get(self, key: str) -> str | None:
        return await self._r.get(key)

    async def set(self, key: str, value: str, ttl: int) -> None:
        await self._r.set(key, value, ex=ttl)

    async def incr(self, key: str, ttl: int, amount: int = 1) -> int:
        async with self._r.pipeline(transaction=True) as pipe:
            pipe.incrby(key, amount)
            pipe.expire(key, ttl, nx=True)
            count, _ = await pipe.execute()
        return int(count)

    async def ping(self) -> bool:
        return bool(await self._r.ping())

    async def close(self) -> None:
        await self._r.aclose()


def build_backend(redis_url: str | None) -> Backend:
    if redis_url:
        logger.info("cache backend: redis")
        return RedisBackend.from_url(redis_url)
    logger.info("cache backend: in-memory")
    return MemoryBackend()
