import base64
import ipaddress
import os
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from typing import Any, Optional, Tuple
from urllib.parse import urlparse

import dns.resolver
import httpx
import whois


SUSPICIOUS_WORDS = {
    "account",
    "confirm",
    "login",
    "secure",
    "signin",
    "update",
    "verify",
    "wallet",
}

PROTECTED_BRANDS = {
    "amazon": {"amazon.com", "amazon.com.tr"},
    "apple": {"apple.com"},
    "facebook": {"facebook.com"},
    "google": {"google.com"},
    "instagram": {"instagram.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "telegram": {"telegram.org"},
    "whatsapp": {"whatsapp.com"},
}


class InvalidUrlError(ValueError):
    pass


@dataclass
class CollectedSignals:
    url: str
    domain: str
    domain_age_days: Optional[int]
    ssl_valid: Optional[bool]
    dns_data: dict[str, Any]
    whois_data: dict[str, Any]
    virustotal_data: dict[str, Any]
    brand_similarity_data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_url(raw_url: str) -> tuple[str, str]:
    candidate = raw_url.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlparse(candidate)
    domain = (parsed.hostname or "").rstrip(".").lower()
    if parsed.scheme not in {"http", "https"} or not domain:
        raise InvalidUrlError("Geçerli bir HTTP/HTTPS URL girin.")

    if " " in domain or "." not in domain:
        raise InvalidUrlError("URL geçerli bir alan adı içermeli.")

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidUrlError("Alan adı dönüştürülemedi.") from exc

    return parsed._replace(netloc=parsed.netloc.lower()).geturl(), domain


def ensure_public_destination(domain: str) -> None:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(domain, None)}
    except socket.gaierror as exc:
        raise InvalidUrlError("Alan adı çözümlenemedi.") from exc

    if not addresses:
        raise InvalidUrlError("Alan adı için IP adresi bulunamadı.")

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise InvalidUrlError("Yerel veya özel ağ adresleri analiz edilemez.")


def _json_safe(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def levenshtein_distance(left: str, right: str) -> int:
    if len(left) < len(right):
        return levenshtein_distance(right, left)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for left_index, left_character in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_character in enumerate(right, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[right_index] + 1,
                    previous[right_index - 1] + (left_character != right_character),
                )
            )
        previous = current
    return previous[-1]


def analyze_brand_similarity(domain: str) -> dict[str, Any]:
    labels = domain.lower().split(".")
    candidate = labels[-2] if len(labels) >= 2 else labels[0]
    best: dict[str, Any] = {
        "candidate": candidate,
        "matched_brand": None,
        "distance": None,
        "similarity": 0.0,
        "suspicious": False,
    }

    for brand, official_domains in PROTECTED_BRANDS.items():
        distance = levenshtein_distance(candidate, brand)
        similarity = 1 - (distance / max(len(candidate), len(brand)))
        is_official = domain in official_domains or any(
            domain.endswith(f".{official}") for official in official_domains
        )
        suspicious = not is_official and similarity >= 0.72
        if similarity > best["similarity"]:
            best = {
                "candidate": candidate,
                "matched_brand": brand,
                "distance": distance,
                "similarity": round(similarity, 3),
                "suspicious": suspicious,
            }
    return best


def collect_dns(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {"a": [], "mx": [], "ns": [], "errors": []}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4

    for record_type, key in (("A", "a"), ("MX", "mx"), ("NS", "ns")):
        try:
            answers = resolver.resolve(domain, record_type)
            result[key] = [str(answer).rstrip(".") for answer in answers]
        except Exception as exc:
            result["errors"].append(f"{record_type}: {type(exc).__name__}")

    return result


def collect_ssl(domain: str) -> Tuple[Optional[bool], dict[str, Any]]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as secure_socket:
                certificate = secure_socket.getpeercert()
        return True, {
            "issuer": _json_safe(certificate.get("issuer")),
            "expires_at": certificate.get("notAfter"),
        }
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        return False, {"error": type(exc).__name__}


def collect_whois(domain: str) -> Tuple[Optional[int], dict[str, Any]]:
    try:
        record = whois.whois(domain)
        creation_date = record.creation_date
        if isinstance(creation_date, list):
            creation_date = next((item for item in creation_date if item), None)

        age_days = None
        if isinstance(creation_date, datetime):
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = max(0, (datetime.now(timezone.utc) - creation_date).days)
        elif isinstance(creation_date, date):
            age_days = max(0, (date.today() - creation_date).days)

        data = {
            "registrar": record.registrar,
            "creation_date": creation_date,
            "expiration_date": record.expiration_date,
            "name_servers": record.name_servers,
        }
        return age_days, _json_safe(data)
    except Exception as exc:
        return None, {"error": type(exc).__name__}


def collect_virustotal(url: str) -> dict[str, Any]:
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"configured": False}

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    try:
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        if response.status_code == 404:
            return {"configured": True, "found": False}
        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {"configured": True, "found": True, "stats": stats}
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
        return {"configured": True, "error": type(exc).__name__}


def calculate_risk(signals: CollectedSignals) -> tuple[int, str, list[str]]:
    score = 0
    reasons: list[str] = []

    if signals.domain_age_days is None:
        score += 10
        reasons.append("Alan adı yaşı doğrulanamadı")
    elif signals.domain_age_days < 30:
        score += 30
        reasons.append("Alan adı 30 günden daha yeni")
    elif signals.domain_age_days < 180:
        score += 15
        reasons.append("Alan adı 6 aydan daha yeni")

    if signals.ssl_valid is False:
        score += 25
        reasons.append("Geçerli SSL bağlantısı kurulamadı")

    if not signals.dns_data.get("a"):
        score += 20
        reasons.append("A tipi DNS kaydı bulunamadı")

    labels = signals.domain.split(".")
    domain_text = "-".join(labels[:-1])
    matched_words = sorted(word for word in SUSPICIOUS_WORDS if word in domain_text)
    if matched_words:
        score += min(20, 5 * len(matched_words))
        reasons.append(f"Şüpheli alan adı ifadeleri: {', '.join(matched_words)}")

    if "xn--" in signals.domain:
        score += 20
        reasons.append("Alan adı Punycode karakterleri içeriyor")
    if len(signals.domain) > 50:
        score += 10
        reasons.append("Alan adı olağandan uzun")
    if signals.domain.count("-") >= 3:
        score += 10
        reasons.append("Alan adında çok sayıda tire var")

    brand_data = signals.brand_similarity_data
    if brand_data.get("suspicious"):
        score += 25
        reasons.append(
            f"Alan adı {brand_data['matched_brand']} markasına benziyor "
            f"(%{round(brand_data['similarity'] * 100)})"
        )

    try:
        ipaddress.ip_address(signals.domain)
        score += 30
        reasons.append("Alan adı yerine doğrudan IP adresi kullanılmış")
    except ValueError:
        pass

    vt_stats = signals.virustotal_data.get("stats", {})
    malicious = int(vt_stats.get("malicious", 0) or 0)
    suspicious = int(vt_stats.get("suspicious", 0) or 0)
    if malicious:
        score += min(50, malicious * 10)
        reasons.append(f"VirusTotal: {malicious} motor zararlı olarak işaretledi")
    if suspicious:
        score += min(15, suspicious * 5)
        reasons.append(f"VirusTotal: {suspicious} motor şüpheli olarak işaretledi")

    score = min(100, score)
    status = "dangerous" if score >= 70 else "suspicious" if score >= 35 else "safe"
    if not reasons:
        reasons.append("Belirgin bir risk sinyali bulunamadı")
    return score, status, reasons


def analyze_url(raw_url: str) -> tuple[CollectedSignals, int, str, list[str]]:
    url, domain = normalize_url(raw_url)
    ensure_public_destination(domain)
    dns_data = collect_dns(domain)
    ssl_valid, ssl_data = collect_ssl(domain)
    domain_age_days, whois_data = collect_whois(domain)
    whois_data["ssl"] = ssl_data
    virustotal_data = collect_virustotal(url)
    brand_similarity_data = analyze_brand_similarity(domain)

    signals = CollectedSignals(
        url=url,
        domain=domain,
        domain_age_days=domain_age_days,
        ssl_valid=ssl_valid,
        dns_data=dns_data,
        whois_data=whois_data,
        virustotal_data=virustotal_data,
        brand_similarity_data=brand_similarity_data,
    )
    score, status, reasons = calculate_risk(signals)
    return signals, score, status, reasons
