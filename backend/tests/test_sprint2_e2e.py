"""Live Sprint 2 contract test; no external service is mocked here."""

import os

import httpx
import pytest


@pytest.mark.e2e
def test_sprint2_text_analysis_through_running_stack():
    """Exercise frontend-facing FastAPI -> n8n -> FastAPI flow when configured."""
    base_url = os.getenv("SPRINT2_E2E_BASE_URL", "").rstrip("/")
    if not base_url:
        pytest.skip("SPRINT2_E2E_BASE_URL tanımlı değil; canlı Sprint 2 testi atlandı.")

    health_response = httpx.get(f"{base_url}/health", timeout=10)
    assert health_response.status_code == 200, health_response.text
    assert health_response.json()["n8n_text_enabled"] is True

    response = httpx.post(
        f"{base_url}/analyze-text",
        json={
            "text": (
                "Bankanız: Hesabınız kapatılacak. Hemen doğrulama kodunuzu "
                "https://example.com adresine girmeyin."
            )
        },
        timeout=190,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] in {"safe", "suspicious", "dangerous"}
    assert 0 <= payload["risk"] <= 100
    assert payload["reasons"]
    assert payload["ai_explanation"]
    assert "workflow_warnings" in payload
