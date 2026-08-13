from analyzer import CollectedSignals, InvalidUrlError, calculate_risk, normalize_url


def make_signals(**changes):
    values = {
        "url": "https://example.com",
        "domain": "example.com",
        "domain_age_days": 5000,
        "ssl_valid": True,
        "dns_data": {"a": ["93.184.216.34"]},
        "whois_data": {},
        "virustotal_data": {"configured": False},
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
