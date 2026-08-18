from analyzer import (
    CollectedSignals,
    InvalidUrlError,
    analyze_brand_similarity,
    analyze_text_urls,
    calculate_risk,
    levenshtein_distance,
    normalize_url,
)


def make_signals(**changes):
    values = {
        "url": "https://example.com",
        "domain": "example.com",
        "domain_age_days": 5000,
        "ssl_valid": True,
        "dns_data": {"a": ["93.184.216.34"]},
        "whois_data": {},
        "virustotal_data": {"configured": False},
        "brand_similarity_data": {"suspicious": False},
    }
    values.update(changes)
    return CollectedSignals(**values)


def test_normalize_url_adds_https():
    url, domain = normalize_url("Example.COM/path")
    assert url == "https://example.com/path"
    assert domain == "example.com"


def test_normalize_url_rejects_non_http_scheme():
    try:
        normalize_url("ftp://example.com/file")
    except InvalidUrlError:
        return
    raise AssertionError("InvalidUrlError bekleniyordu")


def test_low_risk_signals_are_safe():
    score, status, reasons = calculate_risk(make_signals())
    assert score == 0
    assert status == "safe"
    assert reasons == ["Belirgin bir risk sinyali bulunamadı"]


def test_multiple_risk_signals_are_dangerous():
    signals = make_signals(
        domain="verify-account-login-example.com",
        domain_age_days=3,
        ssl_valid=False,
        dns_data={"a": []},
        virustotal_data={"stats": {"malicious": 4, "suspicious": 1}},
    )
    score, status, reasons = calculate_risk(signals)
    assert score == 100
    assert status == "dangerous"
    assert len(reasons) >= 5


def test_levenshtein_distance_detects_one_character_change():
    assert levenshtein_distance("paypal", "paypa1") == 1


def test_brand_similarity_flags_typosquatting():
    result = analyze_brand_similarity("paypa1.com")
    assert result["matched_brand"] == "paypal"
    assert result["suspicious"] is True


def test_official_brand_domain_is_not_suspicious():
    result = analyze_brand_similarity("paypal.com")
    assert result["matched_brand"] == "paypal"
    assert result["suspicious"] is False


def test_analyze_text_urls_extracts_unique_urls_and_checks_virustotal(monkeypatch):
    monkeypatch.setattr(
        "analyzer.collect_virustotal", lambda url: {"checked": url}
    )

    result = analyze_text_urls(
        "Hemen https://example.com/a! ve https://example.com/a ile "
        "https://phishing.example/login adreslerini kontrol edin."
    )

    assert result == [
        {"url": "https://example.com/a", "virustotal": {"checked": "https://example.com/a"}},
        {"url": "https://phishing.example/login", "virustotal": {"checked": "https://phishing.example/login"}},
    ]
