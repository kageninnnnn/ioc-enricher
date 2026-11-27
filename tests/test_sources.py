import asyncio
import base64

import httpx
import pytest
import respx

from app.models import IndicatorType as T
from app.services.sources import ALL_SOURCES, SourceContext, SourceError
from app.services.sources.abusech import ThreatFox, URLhaus
from app.services.sources.abuseipdb import AbuseIPDB
from app.services.sources.otx import AlienVaultOTX
from app.services.sources.virustotal import VirusTotal, score_from_stats, vt_object_id
from tests.conftest import make_settings, metric

VT = "https://www.virustotal.com/api/v3"
OTX = "https://otx.alienvault.com/api/v1/indicators"
UH = "https://urlhaus-api.abuse.ch/v1"
TF = "https://threatfox-api.abuse.ch/api/v1/"

KEYS = {
    "abuseipdb_api_key": "ab",
    "virustotal_api_key": "vt",
    "otx_api_key": "otx",
    "abusech_auth_key": "ach",
}


def lookup(source, value, ioc_type, **settings):
    async def go():
        async with httpx.AsyncClient() as http:
            ctx = SourceContext(make_settings(**(KEYS | settings)), http)
            return await source.lookup(value, ioc_type, ctx)

    return asyncio.run(go())


# ---------------- enabled() ----------------


def test_enabled_requires_keys():
    bare = make_settings()
    keyed = make_settings(**KEYS)
    for s in ALL_SOURCES:
        if s.name == "local-intel":
            assert s.enabled(bare)
        else:
            assert not s.enabled(bare), s.name
        assert s.enabled(keyed), s.name


# ---------------- VirusTotal ----------------


@pytest.mark.parametrize(
    ("value", "type_", "path"),
    [
        ("1.2.3.4", T.IPV4, "ip_addresses/1.2.3.4"),
        ("2001:db8::1", T.IPV6, "ip_addresses/2001:db8::1"),
        ("evil.example", T.DOMAIN, "domains/evil.example"),
        ("a" * 64, T.SHA256, "files/" + "a" * 64),
    ],
)
@respx.mock
def test_vt_hit(value, type_, path):
    route = respx.get(f"{VT}/{path}").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 60},
                        "reputation": -20,
                        "tags": ["c2"],
                    }
                }
            },
        )
    )
    r = lookup(VirusTotal(), value, type_)
    assert route.calls.last.request.headers["x-apikey"] == "vt"
    assert r.score == 70
    assert r.weight == 0.95
    assert r.details["malicious"] == 3
    assert r.details["tags"] == ["c2"]


@respx.mock
def test_vt_url_id():
    url = "http://evil.example/a?b=1"
    vid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    assert "=" not in vid
    assert vt_object_id(url, T.URL) == vid
    route = respx.get(f"{VT}/urls/{vid}").mock(
        return_value=httpx.Response(200, json={"data": {"attributes": {}}})
    )
    r = lookup(VirusTotal(), url, T.URL)
    assert route.called
    assert r.score == 0


@respx.mock
def test_vt_404():
    respx.get(f"{VT}/domains/x.example").mock(return_value=httpx.Response(404))
    assert lookup(VirusTotal(), "x.example", T.DOMAIN) is None


@respx.mock
def test_vt_500_raises():
    respx.get(f"{VT}/domains/x.example").mock(return_value=httpx.Response(500))
    with pytest.raises(httpx.HTTPStatusError):
        lookup(VirusTotal(), "x.example", T.DOMAIN)


@pytest.mark.parametrize(
    ("stats", "expected"),
    [
        ({}, 0),
        ({"malicious": None}, 0),
        ({"suspicious": 1}, 10),
        ({"malicious": 4, "suspicious": 2}, 100),
        ({"malicious": 50}, 100),
    ],
)
def test_score_from_stats(stats, expected):
    assert score_from_stats(stats) == expected


# ---------------- OTX ----------------


@respx.mock
def test_otx_hit():
    route = respx.get(f"{OTX}/IPv4/1.2.3.4/general").mock(
        return_value=httpx.Response(
            200,
            json={
                "pulse_info": {
                    "count": 3,
                    "pulses": [
                        {"name": "p1", "malware_families": [{"display_name": "Emotet"}]},
                        {"name": "p2", "malware_families": [{"display_name": "AgentTesla"}, "x"]},
                        {"name": "p3"},
                    ],
                }
            },
        )
    )
    r = lookup(AlienVaultOTX(), "1.2.3.4", T.IPV4)
    assert route.calls.last.request.headers["X-OTX-API-KEY"] == "otx"
    assert r.score == 45
    assert r.weight == 0.6
    assert r.details["malware_families"] == ["AgentTesla", "Emotet"]
    assert r.details["pulses"] == ["p1", "p2", "p3"]


@respx.mock
def test_otx_hash_section_and_cap():
    respx.get(f"{OTX}/file/{'a' * 32}/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 50, "pulses": []}})
    )
    r = lookup(AlienVaultOTX(), "a" * 32, T.MD5)
    assert r.score == 100
    assert "pulses" not in r.details


@respx.mock
def test_otx_no_pulses():
    respx.get(f"{OTX}/domain/x.example/general").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 0}})
    )
    assert lookup(AlienVaultOTX(), "x.example", T.DOMAIN) is None


@respx.mock
def test_otx_404():
    respx.get(f"{OTX}/domain/x.example/general").mock(return_value=httpx.Response(404))
    assert lookup(AlienVaultOTX(), "x.example", T.DOMAIN) is None


# ---------------- URLhaus ----------------


@pytest.mark.parametrize(("status", "score"), [("online", 100), ("offline", 80)])
@respx.mock
def test_urlhaus_url(status, score):
    route = respx.post(f"{UH}/url/").mock(
        return_value=httpx.Response(
            200,
            json={"query_status": "ok", "url_status": status, "threat": "malware_download"},
        )
    )
    r = lookup(URLhaus(), "http://evil.example/x", T.URL)
    req = route.calls.last.request
    assert req.headers["Auth-Key"] == "ach"
    assert b"url=http" in req.content
    assert r.score == score
    assert r.details["threat"] == "malware_download"


@respx.mock
def test_urlhaus_host():
    route = respx.post(f"{UH}/host/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "urls": [{"url_status": "online"}, {"url_status": "offline"}],
                "blacklists": {"spamhaus_dbl": "not listed"},
            },
        )
    )
    r = lookup(URLhaus(), "evil.example", T.DOMAIN)
    assert b"host=evil.example" in route.calls.last.request.content
    assert r.score == 90
    assert r.details["url_count"] == 2
    assert r.details["online_urls"] == 1


@respx.mock
def test_urlhaus_host_all_offline():
    respx.post(f"{UH}/host/").mock(
        return_value=httpx.Response(
            200, json={"query_status": "ok", "urls": [{"url_status": "offline"}]}
        )
    )
    assert lookup(URLhaus(), "1.2.3.4", T.IPV4).score == 70


@pytest.mark.parametrize(("type_", "value"), [(T.MD5, "a" * 32), (T.SHA256, "b" * 64)])
@respx.mock
def test_urlhaus_payload(type_, value):
    route = respx.post(f"{UH}/payload/").mock(
        return_value=httpx.Response(
            200, json={"query_status": "ok", "file_type": "exe", "signature": "Emotet"}
        )
    )
    r = lookup(URLhaus(), value, type_)
    assert f"{type_.value}_hash={value}".encode() in route.calls.last.request.content
    assert r.score == 100
    assert r.details["signature"] == "Emotet"


def test_urlhaus_does_not_support_sha1():
    assert not URLhaus().supports(T.SHA1)


@pytest.mark.parametrize("status", ["no_results", "hash_not_found", "illegal_search_term"])
@respx.mock
def test_urlhaus_no_results(status):
    respx.post(f"{UH}/host/").mock(return_value=httpx.Response(200, json={"query_status": status}))
    assert lookup(URLhaus(), "evil.example", T.DOMAIN) is None


@respx.mock
def test_urlhaus_weird_status():
    respx.post(f"{UH}/host/").mock(
        return_value=httpx.Response(200, json={"query_status": "unknown_auth_key"})
    )
    with pytest.raises(SourceError):
        lookup(URLhaus(), "evil.example", T.DOMAIN)


# ---------------- ThreatFox ----------------


@respx.mock
def test_threatfox_ioc_hit():
    route = respx.post(TF).mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "confidence_level": 50,
                        "malware_printable": "Cobalt Strike",
                        "threat_type": "botnet_cc",
                        "first_seen": "2026-01-02 00:00:00 UTC",
                    },
                    {
                        "confidence_level": 100,
                        "malware_printable": "AsyncRAT",
                        "threat_type": "botnet_cc",
                        "first_seen": "2025-12-01 00:00:00 UTC",
                    },
                ],
            },
        )
    )
    r = lookup(ThreatFox(), "evil.example", T.DOMAIN)
    req = route.calls.last.request
    assert req.headers["Auth-Key"] == "ach"
    assert b'"search_ioc"' in req.content
    assert b'"exact_match":true' in req.content.replace(b" ", b"")
    assert r.score == 100
    assert r.details["malware"] == ["AsyncRAT", "Cobalt Strike"]
    assert r.details["threat_types"] == ["botnet_cc"]
    assert r.details["first_seen"].startswith("2025")
    assert r.details["matches"] == 2


@respx.mock
def test_threatfox_hash():
    route = respx.post(TF).mock(
        return_value=httpx.Response(200, json={"query_status": "ok", "data": [{}]})
    )
    r = lookup(ThreatFox(), "c" * 40, T.SHA1)
    assert b'"search_hash"' in route.calls.last.request.content
    assert r.score == 0
    assert "malware" not in r.details


@respx.mock
def test_threatfox_no_result():
    respx.post(TF).mock(return_value=httpx.Response(200, json={"query_status": "no_result"}))
    assert lookup(ThreatFox(), "evil.example", T.DOMAIN) is None


@pytest.mark.parametrize("data", [[], None, "nope"])
@respx.mock
def test_threatfox_empty_data(data):
    respx.post(TF).mock(return_value=httpx.Response(200, json={"query_status": "ok", "data": data}))
    assert lookup(ThreatFox(), "evil.example", T.DOMAIN) is None


# ---------------- AbuseIPDB ----------------


def test_abuseipdb_disabled_without_key():
    assert not AbuseIPDB().enabled(make_settings())
    assert not AbuseIPDB().supports(T.DOMAIN)


# ---------------- enricher-level ----------------


@respx.mock
def test_enricher_records_error_and_skipped(make_client):
    c = make_client(virustotal_api_key="vt")
    respx.get(f"{VT}/domains/evil-phish.example").mock(side_effect=httpx.ConnectError("x"))
    errors = metric("ioc_source_lookups_total", source="virustotal", outcome="error")
    skipped = metric("ioc_source_lookups_total", source="abuseipdb", outcome="skipped")
    body = c.post("/enrich", json={"indicator": "evil-phish.example"}).json()
    assert body["failed_sources"] == ["virustotal"]
    assert body["verdict"] == "malicious"  # local feed still answers
    assert metric("ioc_source_lookups_total", source="virustotal", outcome="error") == errors + 1
    assert metric("ioc_source_lookups_total", source="abuseipdb", outcome="skipped") == skipped + 1


@respx.mock
def test_enricher_hit_and_miss_metrics(make_client):
    c = make_client(virustotal_api_key="vt")
    respx.get(f"{VT}/domains/nothing.example").mock(return_value=httpx.Response(404))
    misses = metric("ioc_source_lookups_total", source="virustotal", outcome="miss")
    body = c.post("/enrich", json={"indicator": "nothing.example"}).json()
    assert body["verdict"] == "unknown"
    assert body["failed_sources"] == []
    assert metric("ioc_source_lookups_total", source="virustotal", outcome="miss") == misses + 1


@respx.mock
def test_enricher_source_timeout(make_client):
    c = make_client(otx_api_key="otx", source_timeout=0.05)

    async def slow(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={})

    respx.get(f"{OTX}/domain/slow.example/general").mock(side_effect=slow)
    body = c.post("/enrich", json={"indicator": "slow.example"}).json()
    assert body["failed_sources"] == ["otx"]


@respx.mock
def test_otx_url_indicator_is_path_escaped():
    url = "http://evil.example/a?b=1#frag"
    route = respx.get(url__startswith=f"{OTX}/url/").mock(
        return_value=httpx.Response(200, json={"pulse_info": {"count": 1, "pulses": []}})
    )
    r = lookup(AlienVaultOTX(), url, T.URL)
    sent = route.calls.last.request.url
    assert sent.raw_path.decode().endswith(
        "/url/http%3A%2F%2Fevil.example%2Fa%3Fb%3D1%23frag/general"
    )
    assert not sent.query
    assert r.score == 15
