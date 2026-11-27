from prometheus_client import Counter, Histogram

ENRICH_REQUESTS = Counter(
    "ioc_enrich_requests_total", "Enriched indicators by type and verdict", ["type", "verdict"]
)
SOURCE_LOOKUPS = Counter(
    "ioc_source_lookups_total",
    "Source lookups by outcome (hit|miss|error|skipped)",
    ["source", "outcome"],
)
SOURCE_LATENCY = Histogram(
    "ioc_source_latency_seconds",
    "Latency of upstream threat-intel lookups",
    ["source"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)
CACHE_EVENTS = Counter("ioc_cache_events_total", "Cache hits and misses", ["event"])
RATE_LIMITED = Counter("ioc_rate_limited_total", "Requests rejected by the rate limiter")
AUTH_FAILURES = Counter("ioc_auth_failures_total", "Requests rejected for a bad/missing API key")
