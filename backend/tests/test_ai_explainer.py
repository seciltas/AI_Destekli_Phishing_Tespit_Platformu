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
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    monkeypatch.setattr(ai_explainer.httpx, "post", lambda *args, **kwargs: FakeResponse())

    explanation = ai_explainer.generate_ai_explanation(
        {"domain": "example.com", "risk_score": 0, "reasons": []}
    )

    assert explanation.startswith("Belirgin bir risk")


def test_openai_configuration_requires_api_key(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    try:
        ai_explainer.generate_ai_explanation({})
    except ai_explainer.AIConfigurationError:
        return
    raise AssertionError("AIConfigurationError bekleniyordu")


def test_generate_ai_explanation_with_ollama(monkeypatch):
    class OllamaResponse(FakeResponse):
        def json(self):
            return {"message": {"content": "Bu mesaj dikkat gerektiriyor."}}

    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs["json"])
        return OllamaResponse()

    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:3b")
    monkeypatch.setattr(ai_explainer.httpx, "post", fake_post)

    explanation = ai_explainer.generate_ai_explanation({"risk_score": 80})

    assert explanation == "Bu mesaj dikkat gerektiriyor."
    assert captured["url"].endswith("/api/chat")
    assert captured["model"] == "qwen2.5:3b"
    assert captured["stream"] is False
