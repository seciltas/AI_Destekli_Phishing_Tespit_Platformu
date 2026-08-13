from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def strip_url(cls, value: str) -> str:
        return value.strip()


class AnalysisResult(BaseModel):
    id: int | None = None
    url: str
    domain: str
    risk: int = Field(ge=0, le=100)
    status: Literal["safe", "suspicious", "dangerous"]
    reasons: list[str]
    domain_age_days: int | None = None
    ssl_valid: bool | None = None
    dns: dict[str, Any] = Field(default_factory=dict)
    whois: dict[str, Any] = Field(default_factory=dict)
    virustotal: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class HealthResponse(BaseModel):
    status: str
    database_configured: bool
    database_connected: bool
