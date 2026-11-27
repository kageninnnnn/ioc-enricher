import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from app.config import Settings
from app.main import create_app


def make_settings(**overrides) -> Settings:
    base = {
        "abuseipdb_api_key": None,
        "virustotal_api_key": None,
        "otx_api_key": None,
        "abusech_auth_key": None,
        "api_keys": None,
        "redis_url": None,
        "rate_limit_per_minute": 0,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


@pytest.fixture
def make_client():
    """Factory: make_client(**settings_overrides) -> started TestClient."""
    clients = []

    def _make(**overrides) -> TestClient:
        c = TestClient(create_app(make_settings(**overrides)))
        c.__enter__()
        clients.append(c)
        return c

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture
def client(make_client):
    return make_client()


@pytest.fixture
def client_with_key(make_client):
    return make_client(abuseipdb_api_key="test-key")


def metric(name: str, **labels) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0
