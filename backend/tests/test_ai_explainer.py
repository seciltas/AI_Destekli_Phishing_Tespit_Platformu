import ai_explainer
import httpx


class FakeResponse:
    status_code = 200

    def raise_for_status(self):
        return None

    def json(self):
        return {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "Belirgin bir risk sinyali görülmedi. Yine de adresi kontrol edin.",
                        }
                    ],
                }
            ]
        }


def test_generate_ai_explanation_parses_responses_api(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    monkeypatch.setattr(ai_explainer.httpx, "post", lambda *args, **kwargs: FakeResponse())

    explanation = ai_explainer.generate_ai_explanation(
        {"domain": "example.com", "risk_score": 0, "reasons": []}
    )

    assert explanation.startswith("Belirgin bir risk")


def test_openai_configuration_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    try:
        ai_explainer.generate_ai_explanation({})
    except ai_explainer.AIConfigurationError:
        return
    raise AssertionError("AIConfigurationError bekleniyordu")


def test_insufficient_quota_is_reported_as_actionable_error(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def quota_response(*_args, **_kwargs):
        request = httpx.Request("POST", "https://api.openai.com/v1/responses")
        response = httpx.Response(
            429,
            request=request,
            json={"error": {"code": "insufficient_quota"}},
        )
        response.raise_for_status()

    monkeypatch.setattr(ai_explainer.httpx, "post", quota_response)

    try:
        ai_explainer.generate_ai_explanation({})
    except ai_explainer.AIQuotaError as exc:
        assert "faturalandırma" in str(exc)
        assert "yedek modda" in str(exc)
        return
    raise AssertionError("AIQuotaError bekleniyordu")


def test_fallback_explanation_keeps_url_analysis_usable():
    explanation = ai_explainer.fallback_ai_explanation(
        {"risk_status": "dangerous", "reasons": ["VirusTotal uyarısı"]}
    )

    assert "VirusTotal uyarısı" in explanation
    assert "tıklamayın" in explanation
