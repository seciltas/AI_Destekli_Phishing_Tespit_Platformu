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
    ai_explanation: Optional[str] = None
    created_at: Optional[datetime] = None


class HealthResponse(BaseModel):
    status: str
    database_configured: bool
    database_connected: bool
    n8n_enabled: bool
    n8n_text_enabled: bool


class InternalAnalysisRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    domain: str = Field(min_length=3, max_length=253)


class TextUrlCheckRequest(BaseModel):
    text: str = Field(min_length=1, max_length=20_000)


class AIExplanationRequest(InternalAnalysisRequest):
    domain_age_days: Optional[int] = None
    ssl_valid: Optional[bool] = None
    dns: dict[str, Any] = Field(default_factory=dict)
    whois: dict[str, Any] = Field(default_factory=dict)
    virustotal: dict[str, Any] = Field(default_factory=dict)
    brand_similarity: dict[str, Any] = Field(default_factory=dict)


class TextAnalysisRequest(BaseModel):
    text: str = Field(min_length=3, max_length=20_000)

    @field_validator("text")
    @classmethod
    def strip_text(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 3:
            raise ValueError("Mesaj en az 3 karakter olmalı.")
        return value


class InternalTextAnalysisRequest(TextAnalysisRequest):
    url_checks: list[dict[str, Any]] = Field(default_factory=list, max_length=10)


class TextSignals(BaseModel):
    urgency: bool = False
    fear: bool = False
    reward: bool = False
    credential_request: bool = False
    suspicious_link: bool = False
    impersonation: bool = False
    payment_request: bool = False


class TextAnalysisResult(BaseModel):
    risk: int = Field(ge=0, le=100)
    status: Literal["safe", "suspicious", "dangerous"]
    reasons: list[str]
    signals: TextSignals
    risk_breakdown: dict[str, int] = Field(default_factory=dict)
    url_checks: list[dict[str, Any]] = Field(default_factory=list)
    ai_explanation: str
    ai_used: bool
    ai_error: Optional[str] = None
    workflow_warnings: list[str] = Field(default_factory=list)


class TelegramNotificationRequest(BaseModel):
    analysis_type: Literal["url", "text"]
    risk: int = Field(ge=0, le=100)
    reasons: list[str] = Field(default_factory=list, max_length=20)
    url: Optional[str] = Field(default=None, max_length=2048)
    domain: Optional[str] = Field(default=None, max_length=253)
