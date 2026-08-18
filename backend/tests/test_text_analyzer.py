import text_analyzer


def test_keyword_analysis_works_without_openai_key():
    result = text_analyzer.analyze_text_message(
        "ACİL! Hesabınız kapatılacak. ŞİFRENİZİ hemen doğrulayın: https://example.test",
        api_key="",
        model="gpt-5-mini",
    )

    assert result.risk == 90
    assert result.status == "dangerous"
    assert result.signals["urgency"] is True
    assert result.signals["fear"] is True
    assert result.signals["credential_request"] is True
    assert result.signals["suspicious_link"] is True
    assert result.ai_used is False
    assert result.ai_error


def test_ai_signals_are_combined_with_keyword_signals(monkeypatch):
    monkeypatch.setattr(
        text_analyzer,
        "_analyze_with_ai",
        lambda *_: {
            "urgency": False,
            "fear": False,
            "reward": True,
            "credential_request": False,
            "suspicious_link": False,
            "explanation": "Mesaj gerçekçi olmayan bir ödül vaadi içeriyor.",
        },
    )

    result = text_analyzer.analyze_text_message(
        "Tebrikler, size özel bir teklif var.",
        api_key="test-key",
        model="gpt-5-mini",
    )

    assert result.risk == 15
    assert result.status == "suspicious"
    assert result.signals["reward"] is True
    assert result.ai_used is True
    assert result.ai_error is None
    assert "ödül" in result.ai_explanation


def test_openai_failure_falls_back_to_keyword_analysis(monkeypatch):
    monkeypatch.setattr(
        text_analyzer,
        "_analyze_with_ai",
        lambda *_: (_ for _ in ()).throw(text_analyzer.AIServiceError("quota unavailable")),
    )

    result = text_analyzer.analyze_text_message(
        "Acil, doğrulama kodunuzu paylaşın.",
        api_key="test-key",
        model="gpt-5-mini",
    )

    assert result.status == "suspicious"
    assert result.ai_used is False
    assert result.ai_error == "quota unavailable"
    assert result.ai_explanation
