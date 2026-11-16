import httpx
import pytest
import respx

from app.config import get_settings

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_metrics(client):
    client.get("/health")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "http_request" in r.text or "python_info" in r.text


@pytest.mark.parametrize(
    ("indicator", "type_", "verdict", "score"),
    [
        ("185.220.101.1", "ipv4", "malicious", 90),
        ("203.0.113.50", "ipv4", "suspicious", 40),
        ("8.8.8.8", "ipv4", "clean", 0),
        ("2001:DB8::BAD", "ipv6", "malicious", 80),
        ("Evil-Phish.example", "domain", "malicious", 95),
        ("44D88612FEA8A8F36DE82E1278ABB02F", "md5", "malicious", 100),
        ("http://evil-phish.example/login", "url", "malicious", 95),
        ("unknown-site.org", "domain", "unknown", 0),
        ("  1.1.1.1  ", "ipv4", "unknown", 0),
    ],
)
def test_enrich_local(client, indicator, type_, verdict, score):
    r = client.post("/enrich", json={"indicator": indicator})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == type_
    assert body["verdict"] == verdict
    assert body["score"] == score


@pytest.mark.parametrize(
    "payload", [{"indicator": ""}, {"indicator": "   "}, {}, {"indicator": "??"}]
)
def test_enrich_invalid(client, payload):
    assert client.post("/enrich", json=payload).status_code == 422


@respx.mock
def test_abuseipdb_success(client_with_key):
    route = respx.get(ABUSE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 100,
                    "totalReports": 7,
                    "countryCode": "NL",
                    "isp": "x",
                }
            },
        )
    )
    r = client_with_key.post("/enrich", json={"indicator": "1.1.1.1"})
    body = r.json()
    assert route.called
    assert route.calls.last.request.headers["Key"] == "test-key"
    assert body["verdict"] == "malicious"
    assert body["sources"][0]["name"] == "abuseipdb"
    assert body["sources"][0]["details"]["total_reports"] == 7


@respx.mock
def test_abuseipdb_combined_max(client_with_key):
    respx.get(ABUSE_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 10}})
    )
    body = client_with_key.post("/enrich", json={"indicator": "185.220.101.1"}).json()
    assert {s["name"] for s in body["sources"]} == {"local-intel", "abuseipdb"}
    assert body["score"] == 90


@respx.mock
@pytest.mark.parametrize(
    "response",
    [httpx.Response(500), httpx.Response(200, text="not-json")],
)
def test_abuseipdb_errors(client_with_key, response):
    respx.get(ABUSE_URL).mock(return_value=response)
    body = client_with_key.post("/enrich", json={"indicator": "1.1.1.1"}).json()
    assert body["verdict"] == "unknown"
    assert body["sources"] == []


@respx.mock
def test_abuseipdb_timeout(client_with_key):
    respx.get(ABUSE_URL).mock(side_effect=httpx.ConnectTimeout("boom"))
    body = client_with_key.post("/enrich", json={"indicator": "1.1.1.1"}).json()
    assert body["verdict"] == "unknown"


@respx.mock
def test_abuseipdb_not_called_for_domain(client_with_key):
    route = respx.get(ABUSE_URL)
    client_with_key.post("/enrich", json={"indicator": "example.com"})
    assert not route.called


def test_settings_from_env(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "env-key")
    s = get_settings()
    assert s.abuseipdb_api_key.get_secret_value() == "env-key"
    assert "env-key" not in repr(s)
    get_settings.cache_clear()
