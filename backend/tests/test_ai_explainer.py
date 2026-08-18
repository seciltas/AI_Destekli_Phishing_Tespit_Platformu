import ai_explainer


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
