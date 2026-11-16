import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import app


@pytest.fixture
def client():
    app.dependency_overrides[get_settings] = lambda: Settings(abuseipdb_api_key=None)
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def client_with_key():
    app.dependency_overrides[get_settings] = lambda: Settings(abuseipdb_api_key="test-key")
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
