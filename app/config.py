from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, loaded from environment variables (12-factor)."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ioc-enricher"
    log_level: str = "INFO"

    # --- threat intel providers (all optional; a source without a key is skipped) ---
    abuseipdb_api_key: SecretStr | None = None
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    virustotal_api_key: SecretStr | None = None
    virustotal_url: str = "https://www.virustotal.com/api/v3"
    otx_api_key: SecretStr | None = None
    otx_url: str = "https://otx.alienvault.com/api/v1/indicators"
    abusech_auth_key: SecretStr | None = None
    urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1"
    threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    threat_intel_path: str | None = None

    source_timeout: float = Field(default=5.0, gt=0, le=30)
    # Backwards-compatible alias of the original setting name.
    abuseipdb_timeout: float | None = None

    # --- caching ---
    redis_url: str | None = None
    cache_ttl_seconds: int = Field(default=3600, ge=0)

    # --- API protection ---
    # Comma-separated list of accepted client keys. Empty => auth disabled (dev mode).
    api_keys: SecretStr | None = None
    rate_limit_per_minute: int = Field(default=60, ge=0)  # 0 disables rate limiting
    batch_max_items: int = Field(default=100, ge=1, le=1000)

    @property
    def timeout(self) -> float:
        return self.abuseipdb_timeout or self.source_timeout

    @property
    def accepted_api_keys(self) -> list[str]:
        if self.api_keys is None:
            return []
        return [k.strip() for k in self.api_keys.get_secret_value().split(",") if k.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
