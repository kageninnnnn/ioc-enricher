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


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class EnrichRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048)

    @field_validator("indicator")
    @classmethod
    def strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("indicator must not be empty")
        return v


class SourceResult(BaseModel):
    name: str
    score: int = Field(ge=0, le=100)
    details: dict = Field(default_factory=dict)


class EnrichResponse(BaseModel):
    indicator: str
    type: IndicatorType
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    sources: list[SourceResult]
