import httpx
import pytest
import respx

from app.config import get_settings
from tests.conftest import metric

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_ready(client):
    r = client.get("/ready")
    assert r.status_code == 200
    assert r.json()["cache"] == "up"


def test_ready_cache_down(client, monkeypatch):
    async def boom():
        raise ConnectionError

    monkeypatch.setattr(client.app.state.cache, "ping", boom)
    assert client.get("/ready").status_code == 503


def test_metrics(client):
    client.post("/enrich", json={"indicator": "185.220.101.1"})
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "ioc_enrich_requests_total" in r.text
    assert "ioc_source_lookups_total" in r.text


def test_security_headers_and_request_id(client):
    r = client.get("/health", headers={"X-Request-ID": "abc-123"})
    assert r.headers["X-Request-ID"] == "abc-123"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    bad = client.get("/health", headers={"X-Request-ID": "<script>"})
    assert bad.headers["X-Request-ID"] != "<script>"


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
        ("hxxp://evil-phish[.]example/login", "url", "malicious", 95),
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
    assert body["explanation"]


@pytest.mark.parametrize(
    "payload", [{"indicator": ""}, {"indicator": "   "}, {}, {"indicator": "??"}]
)
def test_enrich_invalid(client, payload):
    assert client.post("/enrich", json=payload).status_code == 422


def test_cache_hit(client):
    first = client.post("/enrich", json={"indicator": "45.155.205.233"}).json()
    hits = metric("ioc_cache_events_total", event="hit")
    second = client.post("/enrich", json={"indicator": "45.155.205.233"}).json()
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["score"] == first["score"]
    assert metric("ioc_cache_events_total", event="hit") == hits + 1


def test_cache_disabled(make_client):
    c = make_client(cache_ttl_seconds=0)
    c.post("/enrich", json={"indicator": "45.155.205.233"})
    assert c.post("/enrich", json={"indicator": "45.155.205.233"}).json()["cached"] is False


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
    body = client_with_key.post("/enrich", json={"indicator": "1.1.1.1"}).json()
    assert route.called
    assert route.calls.last.request.headers["Key"] == "test-key"
    assert body["verdict"] == "malicious"
    assert body["score"] == 90  # 100 x weight 0.9
    assert body["sources"][0]["name"] == "abuseipdb"
    assert body["sources"][0]["details"]["total_reports"] == 7


@respx.mock
def test_corroboration_bonus(client_with_key):
    respx.get(ABUSE_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 80}})
    )
    body = client_with_key.post("/enrich", json={"indicator": "185.220.101.1"}).json()
    assert {s["name"] for s in body["sources"]} == {"local-intel", "abuseipdb"}
    assert body["score"] == 95  # local 90 + 5 for an agreeing source
    assert any("corroborated" in e for e in body["explanation"])


@respx.mock
def test_weak_second_source_no_bonus(client_with_key):
    respx.get(ABUSE_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 10}})
    )
    body = client_with_key.post("/enrich", json={"indicator": "185.220.101.1"}).json()
    assert body["score"] == 90


@respx.mock
@pytest.mark.parametrize(
    "response",
    [httpx.Response(500), httpx.Response(200, text="not-json"), httpx.Response(200, json=[1])],
)
def test_abuseipdb_errors(client_with_key, response):
    respx.get(ABUSE_URL).mock(return_value=response)
    body = client_with_key.post("/enrich", json={"indicator": "1.1.1.1"}).json()
    assert body["verdict"] == "unknown"
    assert body["sources"] == []
    assert body["failed_sources"] == ["abuseipdb"]


@respx.mock
def test_failed_results_not_cached(client_with_key):
    route = respx.get(ABUSE_URL)
    route.side_effect = [
        httpx.Response(503),
        httpx.Response(200, json={"data": {"abuseConfidenceScore": 100}}),
    ]
    first = client_with_key.post("/enrich", json={"indicator": "1.1.1.1"}).json()
    second = client_with_key.post("/enrich", json={"indicator": "1.1.1.1"}).json()
    assert first["verdict"] == "unknown"
    assert second["verdict"] == "malicious"
    assert second["cached"] is False


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


# ---------------- batch ----------------


def test_batch(client):
    r = client.post(
        "/enrich/batch",
        json={
            "indicators": [
                "185.220.101.1",
                "185.220.101.1",  # duplicate collapsed
                "8.8.8.8",
                "not an ioc",
                "unknown-site.org",
            ]
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["results"]) == 3
    assert body["errors"] == [{"indicator": "not an ioc", "error": "unrecognised indicator type"}]
    assert body["summary"] == {"malicious": 1, "clean": 1, "unknown": 1, "invalid": 1}


@pytest.mark.parametrize(
    "payload", [{"indicators": []}, {"indicators": ["  "]}, {"indicators": ["a" * 3000]}]
)
def test_batch_invalid(client, payload):
    assert client.post("/enrich/batch", json=payload).status_code == 422


def test_batch_too_large(make_client):
    c = make_client(batch_max_items=2)
    r = c.post("/enrich/batch", json={"indicators": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]})
    assert r.status_code == 422
    assert "too large" in r.json()["detail"]


# ---------------- auth & rate limit ----------------


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": "wrong"}])
def test_auth_required(make_client, headers):
    c = make_client(api_keys="k1,k2")
    r = c.post("/enrich", json={"indicator": "8.8.8.8"}, headers=headers)
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "ApiKey"


def test_auth_ok(make_client):
    c = make_client(api_keys="k1, k2")
    r = c.post("/enrich", json={"indicator": "8.8.8.8"}, headers={"X-API-Key": "k2"})
    assert r.status_code == 200


def test_health_needs_no_auth(make_client):
    assert make_client(api_keys="k1").get("/health").status_code == 200


def test_rate_limit(make_client):
    c = make_client(rate_limit_per_minute=3)
    codes = [c.post("/enrich", json={"indicator": "8.8.8.8"}).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    r = c.post("/enrich", json={"indicator": "8.8.8.8"})
    assert 1 <= int(r.headers["Retry-After"]) <= 60


def test_rate_limit_counts_batch_items(make_client):
    c = make_client(rate_limit_per_minute=3)
    r = c.post("/enrich/batch", json={"indicators": ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]})
    assert r.status_code == 429


def test_rate_limit_is_per_key(make_client):
    c = make_client(rate_limit_per_minute=1, api_keys="a,b")
    assert c.post("/enrich", json={"indicator": "8.8.8.8"}, headers={"X-API-Key": "a"}).is_success
    assert c.post("/enrich", json={"indicator": "8.8.8.8"}, headers={"X-API-Key": "b"}).is_success
    r = c.post("/enrich", json={"indicator": "8.8.8.8"}, headers={"X-API-Key": "a"})
    assert r.status_code == 429


def test_rate_limit_fails_open(make_client, monkeypatch):
    c = make_client(rate_limit_per_minute=1)

    async def boom(*a, **kw):
        raise ConnectionError

    monkeypatch.setattr(c.app.state.cache, "incr", boom)
    for _ in range(3):
        assert c.post("/enrich", json={"indicator": "8.8.8.8"}).status_code == 200


def test_settings_from_env(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "env-key")
    monkeypatch.setenv("API_KEYS", "one, two ,")
    s = get_settings()
    assert s.abuseipdb_api_key.get_secret_value() == "env-key"
    assert s.accepted_api_keys == ["one", "two"]
    assert "env-key" not in repr(s)
    get_settings.cache_clear()


def test_openapi_documents_endpoints(client):
    paths = client.get("/openapi.json").json()["paths"]
    assert {"/enrich", "/enrich/batch", "/health", "/ready"} <= set(paths)


def test_ui_served_with_csp(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "IOC Enricher" in r.text
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert client.get("/static/app.js").status_code == 200


def test_docs_not_blocked_by_csp(client):
    r = client.get("/docs")
    assert r.status_code == 200
    assert "Content-Security-Policy" not in r.headers
