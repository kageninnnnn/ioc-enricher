import asyncio

import pytest
from fakeredis import aioredis

from app.services import cache as cache_mod
from app.services.cache import MemoryBackend, RedisBackend, build_backend
from tests.conftest import metric


def run(coro):
    return asyncio.run(coro)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(cache_mod.time, "monotonic", c)
    return c


def test_memory_get_set_ttl(clock):
    async def go():
        b = MemoryBackend()
        assert await b.get("k") is None
        await b.set("k", "v", ttl=10)
        assert await b.get("k") == "v"
        clock.t += 11
        assert await b.get("k") is None
        assert await b.ping() is True
        await b.set("x", "y", 10)
        await b.close()
        assert await b.get("x") is None

    run(go())


def test_memory_incr(clock):
    async def go():
        b = MemoryBackend()
        assert await b.incr("c", ttl=60) == 1
        assert await b.incr("c", ttl=60, amount=5) == 6
        clock.t += 61
        assert await b.incr("c", ttl=60, amount=3) == 3

    run(go())


def test_memory_eviction(clock):
    async def go():
        b = MemoryBackend(max_items=2)
        await b.set("a", "1", 5)
        await b.set("b", "2", 100)
        clock.t += 10  # "a" expired -> evicted first
        await b.set("c", "3", 100)
        assert await b.get("b") == "2"
        assert await b.get("c") == "3"
        # full, nothing expired: oldest inserted ("b") dropped
        await b.set("d", "4", 100)
        assert await b.get("b") is None
        assert await b.get("d") == "4"
        await b.incr("e", 100)
        assert await b.get("c") is None

    run(go())


def test_redis_backend():
    async def go():
        b = RedisBackend(aioredis.FakeRedis(decode_responses=True))
        assert await b.ping() is True
        assert await b.get("k") is None
        await b.set("k", "v", ttl=30)
        assert await b.get("k") == "v"
        assert await b.incr("c", ttl=60) == 1
        assert await b.incr("c", ttl=60, amount=4) == 5
        assert 0 < await b._r.ttl("c") <= 60
        await b.close()

    run(go())


def test_build_backend():
    assert isinstance(build_backend(None), MemoryBackend)
    b = build_backend("redis://localhost:6379/0")
    assert isinstance(b, RedisBackend)
    run(b.close())


def test_enrich_tolerates_cache_errors(client, monkeypatch):
    async def boom(*a, **kw):
        raise ConnectionError

    monkeypatch.setattr(client.app.state.cache, "get", boom)
    monkeypatch.setattr(client.app.state.cache, "set", boom)
    r = client.post("/enrich", json={"indicator": "185.220.101.1"})
    assert r.status_code == 200
    assert r.json()["verdict"] == "malicious"


def test_corrupted_cache_entry_is_miss(client):
    async def go():
        await client.app.state.cache.set("ioc:v1:ipv4:185.220.101.1", "{not json", 60)

    run(go())
    misses = metric("ioc_cache_events_total", event="miss")
    body = client.post("/enrich", json={"indicator": "185.220.101.1"}).json()
    assert body["cached"] is False
    assert body["score"] == 90
    assert metric("ioc_cache_events_total", event="miss") == misses + 1
