from enum import StrEnum

from pydantic import BaseModel, Field, field_validator


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    URL = "url"


HASH_TYPES = frozenset({IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256})
IP_TYPES = frozenset({IndicatorType.IPV4, IndicatorType.IPV6})


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


def _strip_indicator(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("indicator must not be empty")
    return v


class EnrichRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048, examples=["185.220.101.1"])

    @field_validator("indicator")
    @classmethod
    def strip(cls, v: str) -> str:
        return _strip_indicator(v)


class BatchEnrichRequest(BaseModel):
    indicators: list[str] = Field(
        ..., min_length=1, examples=[["185.220.101.1", "evil-phish.example"]]
    )

    @field_validator("indicators")
    @classmethod
    def validate_items(cls, v: list[str]) -> list[str]:
        for item in v:
            if len(item) > 2048:
                raise ValueError("indicator too long (max 2048 chars)")
        return v


class SourceResult(BaseModel):
    name: str
    score: int = Field(ge=0, le=100)
    weight: float = Field(default=1.0, ge=0, le=1)
    details: dict = Field(default_factory=dict)


class EnrichResponse(BaseModel):
    indicator: str
    type: IndicatorType
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    sources: list[SourceResult]
    explanation: list[str] = Field(default_factory=list)
    failed_sources: list[str] = Field(default_factory=list)
    cached: bool = False


class BatchError(BaseModel):
    indicator: str
    error: str


class BatchEnrichResponse(BaseModel):
    results: list[EnrichResponse]
    errors: list[BatchError]
    summary: dict[str, int]
