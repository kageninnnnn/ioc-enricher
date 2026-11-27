# Architecture

## Request flow

```mermaid
flowchart LR
  C[Client / SOAR / analyst] -->|POST /enrich<br/>POST /enrich/batch<br/>X-API-Key| AUTH[API key auth<br/>+ rate limit per key]
  AUTH --> DET[Detect + normalize<br/>ipv4/ipv6/domain/url/md5/sha1/sha256]
  DET --> CACHE{Cache<br/>Redis or in-memory TTL}
  CACHE -- hit --> RESP
  CACHE -- miss --> FAN[asyncio.gather<br/>per-source timeout]
  FAN --> S1[local-intel<br/>bundled feed]
  FAN --> S2[AbuseIPDB<br/>IP]
  FAN --> S3[VirusTotal<br/>IP / domain / URL / hash]
  FAN --> S4[AlienVault OTX<br/>all types]
  FAN --> S5[URLhaus<br/>URL / domain / hash]
  FAN --> S6[ThreatFox<br/>IOC search]
  S1 & S2 & S3 & S4 & S5 & S6 --> SCORE[Weighted scoring<br/>-> verdict + explanation]
  SCORE --> CACHE
  SCORE --> RESP[JSON response<br/>verdict, score, per-source details]
  FAN -. metrics .-> PROM[(/metrics)]
```

- A source without an API key, or that does not support the indicator type, is **skipped**;
  a source that times out or errors is reported as **error** and does not fail the request.
- Every lookup is counted in `ioc_source_lookups_total{source,outcome}` and timed in
  `ioc_source_latency_seconds{source}`; cache efficiency in `ioc_cache_events_total{event}`.
- Secrets (`*_API_KEY`, `API_KEYS`) are `SecretStr` in settings and never logged.

## Deployment view

```mermaid
flowchart TB
  subgraph GH[GitHub]
    CI[ci.yml: lint, test, SAST, SCA, DAST,<br/>build, sign, SBOM] --> GHCR[(ghcr.io image<br/>+ cosign signature + SBOM)]
    CDW[cd.yml]
  end
  subgraph K3S[k3s node - homelab]
    RUNNER[self-hosted runner<br/>namespace-scoped kubeconfig]
    subgraph KS[kube-system]
      TRAEFIK[Traefik ingress]
    end
    subgraph KY[kyverno]
      ADM[admission controller<br/>verifyImages + pod security]
    end
    subgraph NS[ioc-enricher namespace]
      POD[ioc-enricher pods<br/>non-root, read-only FS,<br/>NetworkPolicy, HPA]
      REDIS[(Redis cache)]
      SEC[[SealedSecret -> Secret<br/>API keys]]
    end
    subgraph MON[monitoring]
      PR[Prometheus<br/>ServiceMonitor] --> GF[Grafana dashboard]
    end
  end
  CDW --> RUNNER -->|helm upgrade| ADM --> POD
  GHCR -. pull .-> POD
  TRAEFIK --> POD
  POD --> REDIS
  SEC -. envFrom .-> POD
  PR -->|scrape /metrics| POD
  POD -->|HTTPS 443 only| EXT[(Threat-intel APIs)]
```

Local equivalent: `docker compose up --build` starts the API, Redis, Prometheus and Grafana
with the same dashboard (`deploy/grafana/dashboards/ioc-enricher.json`).
