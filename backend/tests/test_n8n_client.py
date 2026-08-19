import n8n_client


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "domain_age_days": 1000,
            "ssl_valid": True,
            "dns": {"a": ["93.184.216.34"]},
            "whois": {"registrar": "Example"},
            "virustotal": {"configured": False},
            "brand_similarity": {"suspicious": False},
        }


class FakeTextResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "risk": 80,
            "status": "dangerous",
            "reasons": ["VirusTotal uyarısı"],
            "signals": {"suspicious_link": True},
            "risk_breakdown": {"suspicious_link": 20, "virustotal_malicious": 50},
            "url_checks": [],
            "ai_explanation": "Bu mesaj riskli bir bağlantı içeriyor.",
            "ai_used": True,
            "ai_error": None,
        }


def test_collect_signals_via_n8n(monkeypatch):
    monkeypatch.setenv("N8N_WEBHOOK_URL", "http://localhost:5678/webhook/test")
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")
    monkeypatch.setattr(n8n_client.httpx, "post", lambda *args, **kwargs: FakeResponse())

    signals = n8n_client.collect_signals_via_n8n(
        "https://example.com", "example.com"
    )

    assert signals.domain_age_days == 1000
    assert signals.ssl_valid is True
    assert signals.dns_data["a"] == ["93.184.216.34"]


def test_analyze_text_via_n8n(monkeypatch):
    captured = {}
    monkeypatch.setenv("N8N_TEXT_WEBHOOK_URL", "http://localhost:5678/webhook/text")
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return FakeTextResponse()

    monkeypatch.setattr(n8n_client.httpx, "post", fake_post)

    result = n8n_client.analyze_text_via_n8n("Acil mesaj")

    assert result["risk"] == 80
    assert captured["json"] == {"text": "Acil mesaj"}
    assert captured["headers"]["X-N8N-Secret"] == "test-secret"
    assert captured["timeout"] == 180


def test_text_n8n_requires_configuration(monkeypatch):
    monkeypatch.delenv("N8N_TEXT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("N8N_SHARED_SECRET", raising=False)

    try:
        n8n_client.analyze_text_via_n8n("Acil mesaj")
    except n8n_client.N8nConfigurationError:
        pass
    else:
        raise AssertionError("Eksik n8n metin ayarı kabul edilmemeliydi")


def test_text_n8n_reports_timeout_clearly(monkeypatch):
    monkeypatch.setenv("N8N_TEXT_WEBHOOK_URL", "http://localhost:5678/webhook/text")
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")
    monkeypatch.setattr(
        n8n_client.httpx,
        "post",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(n8n_client.httpx.ReadTimeout("slow")),
    )

    try:
        n8n_client.analyze_text_via_n8n("Acil mesaj")
    except n8n_client.N8nWorkflowError as exc:
        assert "zaman aşımı" in str(exc)
    else:
        raise AssertionError("n8n timeout hataya dönüşmeliydi")


def test_text_n8n_rejects_incomplete_response(monkeypatch):
    monkeypatch.setenv("N8N_TEXT_WEBHOOK_URL", "http://localhost:5678/webhook/text")
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")

    class IncompleteResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"status": "dangerous"}

    monkeypatch.setattr(n8n_client.httpx, "post", lambda *_args, **_kwargs: IncompleteResponse())

    try:
        n8n_client.analyze_text_via_n8n("Acil mesaj")
    except n8n_client.N8nWorkflowError as exc:
        assert "TypeError" in str(exc)
    else:
        raise AssertionError("Eksik workflow yanıtı kabul edilmemeliydi")


def test_prepare_qr_url_via_n8n(monkeypatch):
    captured = {}
    monkeypatch.setenv("N8N_QR_WEBHOOK_URL", "http://localhost:5678/webhook/qr")
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")

    class QrResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"url": "https://example.com/from-qr", "source": "qr"}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return QrResponse()

    monkeypatch.setattr(n8n_client.httpx, "post", fake_post)

    result = n8n_client.prepare_qr_url_via_n8n("https://example.com/from-qr")

    assert result == "https://example.com/from-qr"
    assert captured["json"]["source"] == "qr"
    assert captured["params"] == {"url": "https://example.com/from-qr"}
    assert captured["headers"]["X-N8N-Secret"] == "test-secret"
    assert captured["timeout"] == 30


def test_qr_n8n_rejects_invalid_response(monkeypatch):
    monkeypatch.setenv("N8N_QR_WEBHOOK_URL", "http://localhost:5678/webhook/qr")
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")

    class InvalidResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"source": "qr"}

    monkeypatch.setattr(n8n_client.httpx, "post", lambda *_args, **_kwargs: InvalidResponse())

    try:
        n8n_client.prepare_qr_url_via_n8n("https://example.com")
    except n8n_client.N8nWorkflowError as exc:
        assert "TypeError" in str(exc)
    else:
        raise AssertionError("Geçersiz QR workflow yanıtı kabul edilmemeliydi")
