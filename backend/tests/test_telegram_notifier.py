import telegram_notifier


def test_does_not_notify_at_or_below_threshold(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")

    result = telegram_notifier.notify_high_risk_analysis(
        url="https://example.com", domain="example.com", risk=80, reasons=[]
    )

    assert result == {"sent": False, "reason": "risk_below_threshold"}


def test_notifies_high_risk_analysis(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")
    sent: dict = {}

    class Response:
        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        sent["url"] = url
        sent.update(kwargs)
        return Response()

    monkeypatch.setattr(telegram_notifier.httpx, "post", fake_post)
    result = telegram_notifier.notify_high_risk_analysis(
        url="https://bad.example", domain="bad.example", risk=81, reasons=["VT uyarısı"]
    )

    assert result == {"sent": True}
    assert sent["url"] == "https://api.telegram.org/bottoken/sendMessage"
    assert sent["json"]["chat_id"] == "123"
    assert "81/100" in sent["json"]["text"]


def test_telegram_failure_does_not_raise(monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "123")

    def fail(*_, **__):
        raise telegram_notifier.httpx.ConnectError("offline")

    monkeypatch.setattr(telegram_notifier.httpx, "post", fail)
    result = telegram_notifier.notify_high_risk_analysis(
        url="https://bad.example", domain="bad.example", risk=100, reasons=[]
    )

    assert result == {"sent": False, "reason": "ConnectError"}
