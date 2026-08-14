from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)

    @field_validator("url")
    @classmethod
    def strip_url(cls, value: str) -> str:
        return value.strip()


class AnalysisResult(BaseModel):
    id: Optional[int] = None
    url: str
    domain: str
    risk: int = Field(ge=0, le=100)
    status: Literal["safe", "suspicious", "dangerous"]
    reasons: list[str]
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    dns: dict[str, Any] = Field(default_factory=dict)
    whois: dict[str, Any] = Field(default_factory=dict)
    virustotal: dict[str, Any] = Field(default_factory=dict)
    brand_similarity: dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None


class HealthResponse(BaseModel):
    status: str
    database_configured: bool
    database_connected: bool
    n8n_enabled: bool


class InternalAnalysisRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    domain: str = Field(min_length=3, max_length=253)
