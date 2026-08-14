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
