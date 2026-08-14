from fastapi.testclient import TestClient

import main
from analyzer import CollectedSignals


client = TestClient(main.app)


def test_health_reports_missing_database_configuration(monkeypatch):
    def missing_database():
        raise main.DatabaseConfigurationError("missing")

    monkeypatch.setattr(main, "get_database_url", missing_database)
    monkeypatch.setattr(main, "n8n_is_enabled", lambda: False)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "degraded",
        "database_configured": False,
        "database_connected": False,
        "n8n_enabled": False,
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


def test_internal_endpoint_requires_n8n_secret():
    response = client.post(
        "/internal/signals/dns",
        json={"url": "https://example.com", "domain": "example.com"},
    )
    assert response.status_code == 401
