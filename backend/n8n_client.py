import os
from typing import Any

import httpx

from analyzer import CollectedSignals


class N8nConfigurationError(RuntimeError):
    pass


class N8nWorkflowError(RuntimeError):
    pass


def n8n_is_enabled() -> bool:
    return os.getenv("N8N_ENABLED", "false").strip().lower() in {"1", "true", "yes"}


def n8n_text_is_enabled() -> bool:
    return os.getenv("N8N_TEXT_ENABLED", "false").strip().lower() in {"1", "true", "yes"}


def collect_signals_via_n8n(url: str, domain: str) -> CollectedSignals:
    webhook_url = os.getenv("N8N_WEBHOOK_URL", "").strip()
    shared_secret = os.getenv("N8N_SHARED_SECRET", "").strip()
    if not webhook_url or not shared_secret:
        raise N8nConfigurationError(
            "N8N_WEBHOOK_URL ve N8N_SHARED_SECRET backend/.env içinde tanımlanmalı."
        )

    try:
        response = httpx.post(
            webhook_url,
            json={"url": url, "domain": domain},
            headers={"X-N8N-Secret": shared_secret},
            timeout=90,
        )
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return CollectedSignals(
            url=url,
            domain=domain,
            domain_age_days=data.get("domain_age_days"),
            ssl_valid=data.get("ssl_valid"),
            dns_data=data.get("dns", {}),
            whois_data=data.get("whois", {}),
            virustotal_data=data.get("virustotal", {}),
            brand_similarity_data=data.get("brand_similarity", {}),
            ai_explanation=data.get("ai_explanation"),
        )
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        raise N8nWorkflowError(f"n8n workflow çağrısı başarısız: {type(exc).__name__}") from exc


def analyze_text_via_n8n(text: str) -> dict[str, Any]:
    webhook_url = os.getenv("N8N_TEXT_WEBHOOK_URL", "").strip()
    shared_secret = os.getenv("N8N_SHARED_SECRET", "").strip()
    if not webhook_url or not shared_secret:
        raise N8nConfigurationError(
            "N8N_TEXT_WEBHOOK_URL ve N8N_SHARED_SECRET backend/.env içinde tanımlanmalı."
        )

    try:
        response = httpx.post(
            webhook_url,
            json={"text": text},
            headers={"X-N8N-Secret": shared_secret},
            timeout=120,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise TypeError("n8n metin analizi nesne döndürmedi")
        return data
    except (httpx.HTTPError, TypeError, ValueError) as exc:
        raise N8nWorkflowError(
            f"n8n metin workflow çağrısı başarısız: {type(exc).__name__}"
        ) from exc
