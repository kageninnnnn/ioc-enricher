from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ioc-enricher"
    abuseipdb_api_key: SecretStr | None = None
    abuseipdb_url: str = "https://api.abuseipdb.com/api/v2/check"
    abuseipdb_timeout: float = 5.0
    threat_intel_path: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
