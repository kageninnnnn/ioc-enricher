# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-27

### Added
- Six threat-intel sources queried in parallel with per-source timeouts: local feed and
  allowlist, AbuseIPDB, VirusTotal v3, AlienVault OTX, URLhaus and ThreatFox.
- Explainable weighted scoring: reliability weights, a corroboration bonus and an
  allowlist override. Every response includes an `explanation`.
- `POST /enrich/batch` with de-duplication, per-item errors and a verdict summary.
- Refanging of defanged IOCs (`hxxp://`, `[.]`, `(dot)`).
- API-key authentication and per-key rate limiting.
- Redis or in-memory TTL cache. Degraded answers are not cached.
- `/ready` readiness probe, JSON logs with request IDs, and custom Prometheus metrics.
- A dependency-free web UI with a strict Content-Security-Policy.
- CI: OWASP ZAP API scan (DAST) and a helm lint + kubeconform job, both gating publish.
- Kyverno policies: admit only cosign-signed images with an SBOM attestation, plus a pod
  security baseline.
- Helm: `envFrom` for all provider keys, `config.*` values, and optional ServiceMonitor and
  PodDisruptionBudget.
- `docker compose` stack with Redis, Prometheus and a provisioned Grafana dashboard.
- README, architecture docs and LICENSE.

### Changed
- An external source's score is now multiplied by its weight (for example, AbuseIPDB
  100 becomes 90).
- Helm: `existingSecretKey` was removed and the secret is mounted with `envFrom`. Key names
  must match the environment variable names.
- The CD job runs on `[self-hosted, k3s, deploy]`.

### Fixed
- Pinned `aquasecurity/trivy-action` to a commit SHA. The `0.28.0` tag no longer exists, so
  both trivy gates had been failing.
- CVE-2025-47273 (HIGH) in the runtime image. The fix removes pip and its vendored
  setuptools from the shipped virtualenv and the base image.
- `cosign sign` resolved the image against Docker Hub. The image is now signed by its
  GHCR registry digest.
- A ThreatFox `no_result` response was counted as an error, and URL indicators were not
  path-escaped for OTX.

### Security
- The image is signed with cosign keyless (GitHub OIDC) and has an SPDX SBOM attestation:
  `ghcr.io/kageninnnnn/ioc-enricher@sha256:1f7098e47fd68f5b4ef9295434799b920b80e7e6047cea1bb46012afe39362e9`

## [0.1.0]

- Initial FastAPI service with local feed and AbuseIPDB lookups, CI security gates,
  cosign signing, a hardened Helm chart and k3s deployment docs.

[0.2.0]: https://github.com/kageninnnnn/ioc-enricher/compare/936c73a...v0.2.0
