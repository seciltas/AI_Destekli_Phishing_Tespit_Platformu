import os
from typing import Any

import httpx


HIGH_RISK_THRESHOLD = 80


def telegram_is_configured() -> bool:
    return bool(
        os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        and os.getenv("TELEGRAM_CHAT_ID", "").strip()
    )


def _send_high_risk_notification(
    *, risk: int, reasons: list[str], detail_lines: list[str]
) -> dict[str, Any]:
    if risk <= HIGH_RISK_THRESHOLD:
        return {"sent": False, "reason": "risk_below_threshold"}

    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return {"sent": False, "reason": "not_configured"}

    message = "\n".join(
        [
            "⚠️ Yüksek riskli phishing analizi",
            f"Risk skoru: {risk}/100",
            *detail_lines,
            "Nedenler: " + "; ".join(reasons[:3]),
        ]
    )
    try:
        response = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "disable_web_page_preview": True},
            timeout=10,
        )
        response.raise_for_status()
        return {"sent": True}
    except httpx.HTTPError as exc:
        return {"sent": False, "reason": type(exc).__name__}


def notify_high_risk_analysis(
    *, url: str, domain: str, risk: int, reasons: list[str]
) -> dict[str, Any]:
    """Yüksek riskli URL için Telegram bildirimi yollar."""
    return _send_high_risk_notification(
        risk=risk,
        reasons=reasons,
        detail_lines=[f"Tür: URL", f"Alan adı: {domain}", f"URL: {url}"],
    )


def notify_high_risk_text_analysis(*, risk: int, reasons: list[str]) -> dict[str, Any]:
    """Mesaj içeriğini paylaşmadan yüksek riskli metin bildirimi yollar."""
    return _send_high_risk_notification(
        risk=risk,
        reasons=reasons,
        detail_lines=["Tür: SMS/E-posta"],
    )
