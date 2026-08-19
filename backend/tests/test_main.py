from fastapi.testclient import TestClient

import main
from analyzer import CollectedSignals


client = TestClient(main.app)


def test_health_reports_missing_database_configuration(monkeypatch):
    def missing_database():
        raise main.DatabaseConfigurationError("missing")

    monkeypatch.setattr(main, "get_database_url", missing_database)
    monkeypatch.setattr(main, "n8n_is_enabled", lambda: False)
    monkeypatch.setattr(main, "n8n_text_is_enabled", lambda: False)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "degraded",
        "database_configured": False,
        "database_connected": False,
        "n8n_enabled": False,
        "n8n_text_enabled": False,
    }


def test_analyze_returns_saved_result(monkeypatch):
    monkeypatch.setattr(main, "n8n_is_enabled", lambda: False)
    signals = CollectedSignals(
        url="https://example.com",
        domain="example.com",
        domain_age_days=5000,
        ssl_valid=True,
        dns_data={"a": ["93.184.216.34"]},
        whois_data={},
        virustotal_data={"configured": False},
        brand_similarity_data={"suspicious": False},
    )
    monkeypatch.setattr(
        main,
        "analyze_url",
        lambda _: (signals, 0, "safe", ["Belirgin bir risk sinyali bulunamadı"]),
    )
    monkeypatch.setattr(main, "save_analysis", lambda **_: {"id": 7})

    response = client.post("/analyze", json={"url": "example.com"})
    assert response.status_code == 201
    assert response.json()["id"] == 7
    assert response.json()["status"] == "safe"


def test_analyze_rejects_invalid_url(monkeypatch):
    monkeypatch.setattr(main, "n8n_is_enabled", lambda: False)
    def invalid_url(_: str):
        raise main.InvalidUrlError("Geçersiz URL")

    monkeypatch.setattr(main, "analyze_url", invalid_url)
    response = client.post("/analyze", json={"url": "invalid"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Geçersiz URL"}


def test_analyze_sends_telegram_notification_above_80(monkeypatch):
    monkeypatch.setattr(main, "n8n_is_enabled", lambda: False)
    signals = CollectedSignals(
        url="https://bad.example",
        domain="bad.example",
        domain_age_days=1,
        ssl_valid=False,
        dns_data={"a": []},
        whois_data={},
        virustotal_data={"stats": {"malicious": 5}},
        brand_similarity_data={"suspicious": False},
    )
    monkeypatch.setattr(
        main,
        "analyze_url",
        lambda _: (signals, 81, "dangerous", ["VirusTotal uyarısı"]),
    )
    monkeypatch.setattr(main, "save_analysis", lambda **_: {"id": 8})
    notification = {}
    monkeypatch.setattr(
        main,
        "notify_high_risk_analysis",
        lambda **kwargs: notification.update(kwargs),
    )

    response = client.post("/analyze", json={"url": "https://bad.example"})

    assert response.status_code == 201
    assert notification["risk"] == 81
    assert notification["domain"] == "bad.example"


def test_analyze_does_not_duplicate_telegram_when_n8n_is_enabled(monkeypatch):
    monkeypatch.setattr(main, "n8n_is_enabled", lambda: True)
    monkeypatch.setattr(main, "normalize_url", lambda _: ("https://bad.example", "bad.example"))
    monkeypatch.setattr(main, "ensure_public_destination", lambda _: None)
    signals = CollectedSignals(
        url="https://bad.example",
        domain="bad.example",
        domain_age_days=1,
        ssl_valid=False,
        dns_data={},
        whois_data={},
        virustotal_data={"stats": {"malicious": 5}},
        brand_similarity_data={"suspicious": False},
    )
    monkeypatch.setattr(main, "collect_signals_via_n8n", lambda *_: signals)
    monkeypatch.setattr(main, "save_analysis", lambda **_: {"id": 9})
    monkeypatch.setattr(
        main,
        "notify_high_risk_analysis",
        lambda **_: (_ for _ in ()).throw(AssertionError("duplicate notification")),
    )

    response = client.post("/analyze", json={"url": "https://bad.example"})

    assert response.status_code == 201


def test_internal_endpoint_requires_n8n_secret():
    response = client.post(
        "/internal/signals/dns",
        json={"url": "https://example.com", "domain": "example.com"},
    )
    assert response.status_code == 401


def test_internal_text_url_checks_uses_virustotal_helper(monkeypatch):
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")
    monkeypatch.setattr(
        main,
        "analyze_text_urls",
        lambda text: [{"url": "https://bad.example", "virustotal": {"found": True}}],
    )

    response = client.post(
        "/internal/signals/text-urls",
        headers={"X-N8N-Secret": "test-secret"},
        json={"text": "https://bad.example"},
    )

    assert response.status_code == 200
    assert response.json()["urls"][0]["virustotal"]["found"] is True


def test_ai_failure_does_not_break_signal_workflow(monkeypatch):
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")
    monkeypatch.setattr(
        main,
        "validate_internal_target",
        lambda _: ("https://example.com", "example.com"),
    )
    monkeypatch.setattr(
        main,
        "generate_ai_explanation",
        lambda _: (_ for _ in ()).throw(main.AIServiceError("quota unavailable")),
    )

    response = client.post(
        "/internal/ai-explanation",
        headers={"X-N8N-Secret": "test-secret"},
        json={
            "url": "https://example.com",
            "domain": "example.com",
            "domain_age_days": 1000,
            "ssl_valid": True,
            "dns": {"a": ["93.184.216.34"]},
            "virustotal": {"stats": {"malicious": 0, "suspicious": 0}},
            "brand_similarity": {"suspicious": False},
        },
    )

    assert response.status_code == 200
    assert "Belirgin bir risk sinyali" in response.json()["ai_explanation"]
    assert response.json()["ai_error"] == "quota unavailable"


def test_analyze_text_returns_result(monkeypatch):
    from text_analyzer import TextAnalysis

    monkeypatch.setattr(main, "n8n_text_is_enabled", lambda: False)
    monkeypatch.setattr(main, "analyze_text_urls", lambda _: [])
    monkeypatch.setattr(
        main,
        "analyze_text_message",
        lambda *_args, **_kwargs: TextAnalysis(
            risk=70,
            status="dangerous",
            reasons=["Mesaj korku veya hesap kaybı tehdidi kullanıyor."],
            signals={
                "urgency": True,
                "fear": True,
                "reward": False,
                "credential_request": True,
                "suspicious_link": False,
                "impersonation": False,
                "payment_request": False,
            },
            risk_breakdown={"fear": 20, "credential_request": 30, "urgency": 10, "combination_bonus": 10},
            ai_explanation="Bu mesaj bilgi vermeniz için baskı kuruyor.",
            ai_used=True,
        ),
    )

    response = client.post("/analyze-text", json={"text": "Hesabınızı hemen doğrulayın."})

    assert response.status_code == 200
    assert response.json()["risk"] == 70
    assert response.json()["status"] == "dangerous"
    assert response.json()["signals"]["credential_request"] is True


def test_direct_text_analysis_sends_high_risk_fallback_notification(monkeypatch):
    from text_analyzer import TextAnalysis

    monkeypatch.setattr(main, "n8n_text_is_enabled", lambda: False)
    monkeypatch.setattr(main, "analyze_text_urls", lambda _: [])
    monkeypatch.setattr(
        main,
        "analyze_text_message",
        lambda *_args, **_kwargs: TextAnalysis(
            risk=90,
            status="dangerous",
            reasons=["Parola talebi"],
            signals={},
            risk_breakdown={"credential_request": 30},
            ai_explanation="Riskli mesaj.",
            ai_used=False,
        ),
    )
    notification = {}
    monkeypatch.setattr(
        main,
        "notify_high_risk_text_analysis",
        lambda **kwargs: notification.update(kwargs),
    )

    response = client.post("/analyze-text", json={"text": "Parolanızı hemen paylaşın."})

    assert response.status_code == 200
    assert notification == {"risk": 90, "reasons": ["Parola talebi"]}


def test_analyze_text_uses_n8n_workflow_when_enabled(monkeypatch):
    monkeypatch.setattr(main, "n8n_text_is_enabled", lambda: True)
    monkeypatch.setattr(
        main,
        "analyze_text_via_n8n",
        lambda text: {
            "risk": 65,
            "status": "dangerous",
            "reasons": ["VirusTotal uyarısı"],
            "signals": {
                "urgency": False,
                "fear": False,
                "reward": False,
                "credential_request": False,
                "suspicious_link": True,
                "impersonation": False,
                "payment_request": False,
            },
            "risk_breakdown": {"suspicious_link": 20, "virustotal_malicious": 45},
            "url_checks": [{"url": "https://bad.example", "virustotal": {}}],
            "ai_explanation": "Bağlantı riskli işaretler taşıyor.",
            "ai_used": True,
            "ai_error": None,
        },
    )

    response = client.post(
        "/analyze-text",
        json={"text": "Bu bağlantıyı kontrol edin: https://bad.example"},
    )

    assert response.status_code == 200
    assert response.json()["risk"] == 65
    assert response.json()["url_checks"][0]["url"] == "https://bad.example"


def test_internal_text_analysis_requires_n8n_secret():
    response = client.post(
        "/internal/text-analysis",
        json={"text": "Acil mesaj", "url_checks": []},
    )

    assert response.status_code == 401


def test_internal_telegram_notification_routes_text_without_content(monkeypatch):
    monkeypatch.setenv("N8N_SHARED_SECRET", "test-secret")
    captured = {}
    monkeypatch.setattr(
        main,
        "notify_high_risk_text_analysis",
        lambda **kwargs: captured.update(kwargs) or {"sent": True},
    )

    response = client.post(
        "/internal/notifications/telegram",
        headers={"X-N8N-Secret": "test-secret"},
        json={
            "analysis_type": "text",
            "risk": 95,
            "reasons": ["Parola talebi"],
        },
    )

    assert response.status_code == 200
    assert response.json() == {"sent": True}
    assert captured == {"risk": 95, "reasons": ["Parola talebi"]}


def test_analyze_text_rejects_blank_text():
    response = client.post("/analyze-text", json={"text": "   "})

    assert response.status_code == 422
