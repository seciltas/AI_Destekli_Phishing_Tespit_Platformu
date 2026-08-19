import os
import secrets
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from analyzer import (
    CollectedSignals,
    InvalidUrlError,
    analyze_brand_similarity,
    analyze_text_urls,
    analyze_url,
    calculate_risk,
    collect_dns,
    collect_ssl,
    collect_virustotal,
    collect_whois,
    ensure_public_destination,
    normalize_url,
)
from ai_explainer import (
    AIConfigurationError,
    AIServiceError,
    fallback_ai_explanation,
    generate_ai_explanation,
)
from database import DatabaseConfigurationError, database_is_connected, get_database_url
from models import (
    AIExplanationRequest,
    AnalysisResult,
    AnalyzeRequest,
    HealthResponse,
    InternalTextAnalysisRequest,
    InternalAnalysisRequest,
    TelegramNotificationRequest,
    TextAnalysisRequest,
    TextAnalysisResult,
    TextUrlCheckRequest,
)
from n8n_client import (
    N8nConfigurationError,
    N8nWorkflowError,
    analyze_text_via_n8n,
    collect_signals_via_n8n,
    n8n_is_enabled,
    n8n_qr_is_enabled,
    n8n_text_is_enabled,
    prepare_qr_url_via_n8n,
)
from repository import list_analyses, save_analysis
from qr_analyzer import (
    ALLOWED_QR_CONTENT_TYPES,
    MAX_QR_IMAGE_BYTES,
    QRDecodeError,
    decode_qr_url,
)
from text_analyzer import analyze_text_message
from telegram_notifier import notify_high_risk_analysis, notify_high_risk_text_analysis


app = FastAPI(
    title="AI Destekli Phishing Tespit Platformu",
    version="0.2.0",
)

frontend_origins = {
    origin.strip()
    for origin in os.getenv("FRONTEND_ORIGIN", "http://localhost:5173").split(",")
    if origin.strip()
}
# Yerel geliştirmede tarayıcı localhost ve 127.0.0.1 adreslerini farklı origin sayar.
if "http://localhost:5173" in frontend_origins:
    frontend_origins.add("http://127.0.0.1:5173")
if "http://127.0.0.1:5173" in frontend_origins:
    frontend_origins.add("http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=sorted(frontend_origins),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(InvalidUrlError)
def invalid_url_handler(_, exc: InvalidUrlError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.get("/")
def home() -> dict[str, str]:
    return {"message": "AI Destekli Phishing Tespit Platformu"}


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    try:
        get_database_url()
        database_configured = True
    except DatabaseConfigurationError:
        database_configured = False
    database_connected = database_is_connected() if database_configured else False
    return HealthResponse(
        status="ok" if database_connected else "degraded",
        database_configured=database_configured,
        database_connected=database_connected,
        n8n_enabled=n8n_is_enabled(),
        n8n_text_enabled=n8n_text_is_enabled(),
        n8n_qr_enabled=n8n_qr_is_enabled(),
    )


def require_n8n_secret(
    x_n8n_secret: Optional[str] = Header(default=None, alias="X-N8N-Secret"),
) -> None:
    expected = os.getenv("N8N_SHARED_SECRET", "").strip()
    if not expected or not x_n8n_secret or not secrets.compare_digest(expected, x_n8n_secret):
        raise HTTPException(status_code=401, detail="Geçersiz n8n erişim anahtarı.")


def validate_internal_target(payload: InternalAnalysisRequest) -> tuple[str, str]:
    url, domain = normalize_url(payload.url)
    if domain != payload.domain.lower():
        raise InvalidUrlError("URL ve domain birbiriyle eşleşmiyor.")
    ensure_public_destination(domain)
    return url, domain


@app.post("/internal/signals/whois", dependencies=[Depends(require_n8n_secret)])
def internal_whois(payload: InternalAnalysisRequest) -> dict[str, Any]:
    _, domain = validate_internal_target(payload)
    domain_age_days, whois_data = collect_whois(domain)
    return {"domain_age_days": domain_age_days, "whois": whois_data}


@app.post("/internal/signals/dns", dependencies=[Depends(require_n8n_secret)])
def internal_dns(payload: InternalAnalysisRequest) -> dict[str, Any]:
    _, domain = validate_internal_target(payload)
    return {"dns": collect_dns(domain)}


@app.post("/internal/signals/ssl", dependencies=[Depends(require_n8n_secret)])
def internal_ssl(payload: InternalAnalysisRequest) -> dict[str, Any]:
    _, domain = validate_internal_target(payload)
    ssl_valid, ssl_data = collect_ssl(domain)
    return {"ssl_valid": ssl_valid, "ssl": ssl_data}


@app.post("/internal/signals/brand", dependencies=[Depends(require_n8n_secret)])
def internal_brand(payload: InternalAnalysisRequest) -> dict[str, Any]:
    _, domain = validate_internal_target(payload)
    return {"brand_similarity": analyze_brand_similarity(domain)}


@app.post("/internal/signals/virustotal", dependencies=[Depends(require_n8n_secret)])
def internal_virustotal(payload: InternalAnalysisRequest) -> dict[str, Any]:
    url, _ = validate_internal_target(payload)
    return {"virustotal": collect_virustotal(url)}


@app.post("/internal/signals/text-urls", dependencies=[Depends(require_n8n_secret)])
def internal_text_url_checks(payload: TextUrlCheckRequest) -> dict[str, Any]:
    return {"urls": analyze_text_urls(payload.text)}


@app.post(
    "/internal/text-analysis",
    response_model=TextAnalysisResult,
    dependencies=[Depends(require_n8n_secret)],
)
def internal_text_analysis(payload: InternalTextAnalysisRequest) -> TextAnalysisResult:
    result = analyze_text_message(
        payload.text,
        api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        model=os.getenv("OPENAI_MODEL", "gpt-5-mini").strip(),
        url_checks=payload.url_checks,
    )
    return TextAnalysisResult(**result.to_dict())


@app.post(
    "/internal/notifications/telegram",
    dependencies=[Depends(require_n8n_secret)],
)
def internal_telegram_notification(payload: TelegramNotificationRequest) -> dict[str, Any]:
    if payload.analysis_type == "text":
        return notify_high_risk_text_analysis(risk=payload.risk, reasons=payload.reasons)
    return notify_high_risk_analysis(
        url=payload.url or "-",
        domain=payload.domain or "-",
        risk=payload.risk,
        reasons=payload.reasons,
    )


@app.post("/internal/ai-explanation", dependencies=[Depends(require_n8n_secret)])
def internal_ai_explanation(payload: AIExplanationRequest) -> dict[str, Any]:
    url, domain = validate_internal_target(payload)
    signals = CollectedSignals(
        url=url,
        domain=domain,
        domain_age_days=payload.domain_age_days,
        ssl_valid=payload.ssl_valid,
        dns_data=payload.dns,
        whois_data=payload.whois,
        virustotal_data=payload.virustotal,
        brand_similarity_data=payload.brand_similarity,
    )
    score, risk_status, reasons = calculate_risk(signals)
    explanation_input = {
        "domain": domain,
        "risk_score": score,
        "risk_status": risk_status,
        "reasons": reasons,
        "domain_age_days": signals.domain_age_days,
        "ssl_valid": signals.ssl_valid,
        "virustotal_stats": signals.virustotal_data.get("stats", {}),
        "brand_similarity": signals.brand_similarity_data,
    }
    try:
        ai_explanation = generate_ai_explanation(explanation_input)
    except AIConfigurationError as exc:
        return {
            "risk": score,
            "status": risk_status,
            "reasons": reasons,
            "ai_explanation": fallback_ai_explanation(explanation_input),
            "ai_error": str(exc),
        }
    except AIServiceError as exc:
        return {
            "risk": score,
            "status": risk_status,
            "reasons": reasons,
            "ai_explanation": fallback_ai_explanation(explanation_input),
            "ai_error": str(exc),
        }

    return {
        "risk": score,
        "status": risk_status,
        "reasons": reasons,
        "ai_explanation": ai_explanation,
    }


@app.post(
    "/analyze",
    response_model=AnalysisResult,
    status_code=status.HTTP_201_CREATED,
)
def analyze(payload: AnalyzeRequest) -> AnalysisResult:
    use_n8n = n8n_is_enabled()
    try:
        if use_n8n:
            normalized_url, domain = normalize_url(payload.url)
            ensure_public_destination(domain)
            signals = collect_signals_via_n8n(normalized_url, domain)
            signals.whois_data["ssl"] = signals.whois_data.get("ssl", {})
            score, risk_status, reasons = calculate_risk(signals)
        else:
            signals, score, risk_status, reasons = analyze_url(payload.url)
        analysis_row = save_analysis(
            url=signals.url,
            domain=signals.domain,
            domain_age_days=signals.domain_age_days,
            ssl_valid=signals.ssl_valid,
            dns_data=signals.dns_data,
            whois_data=signals.whois_data,
            virustotal_data=signals.virustotal_data,
            brand_similarity_data=signals.brand_similarity_data,
            score=score,
            status=risk_status,
            reasons=reasons,
            ai_explanation=signals.ai_explanation,
        )
        if not use_n8n:
            # n8n kapalıyken bildirim doğrudan gönderilir; çift bildirim oluşmaz.
            notify_high_risk_analysis(
                url=signals.url,
                domain=signals.domain,
                risk=score,
                reasons=reasons,
            )
    except InvalidUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (DatabaseConfigurationError, N8nConfigurationError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except N8nWorkflowError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Analiz tamamlanamadı: {type(exc).__name__}",
        ) from exc

    return AnalysisResult(
        id=analysis_row["id"],
        url=signals.url,
        domain=signals.domain,
        risk=score,
        status=risk_status,
        reasons=reasons,
        domain_age_days=signals.domain_age_days,
        ssl_valid=signals.ssl_valid,
        dns=signals.dns_data,
        whois=signals.whois_data,
        virustotal=signals.virustotal_data,
        brand_similarity=signals.brand_similarity_data,
        ai_explanation=signals.ai_explanation,
        created_at=analysis_row.get("created_at"),
    )


@app.post(
    "/analyze-qr",
    response_model=AnalysisResult,
    status_code=status.HTTP_201_CREATED,
)
async def analyze_qr(file: UploadFile = File(...)) -> AnalysisResult:
    if file.content_type not in ALLOWED_QR_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Yalnızca PNG, JPEG veya WebP QR görselleri yüklenebilir.",
        )
    image_bytes = await file.read(MAX_QR_IMAGE_BYTES + 1)
    try:
        url = decode_qr_url(image_bytes)
    except QRDecodeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if n8n_qr_is_enabled():
        try:
            url = prepare_qr_url_via_n8n(url)
        except N8nConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except N8nWorkflowError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    return await run_in_threadpool(analyze, AnalyzeRequest(url=url))


@app.get("/analyses")
def analyses(limit: int = Query(default=50, ge=1, le=100)) -> list[dict[str, Any]]:
    try:
        return list_analyses(limit)
    except DatabaseConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Analiz geçmişi alınamadı: {type(exc).__name__}",
        ) from exc


@app.post("/analyze-text", response_model=TextAnalysisResult)
def analyze_text(payload: TextAnalysisRequest) -> TextAnalysisResult:
    if n8n_text_is_enabled():
        try:
            return TextAnalysisResult.model_validate(analyze_text_via_n8n(payload.text))
        except N8nConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except N8nWorkflowError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    url_checks = analyze_text_urls(payload.text)
    result = analyze_text_message(
        payload.text,
        api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        model=os.getenv("OPENAI_MODEL", "gpt-5-mini").strip(),
        url_checks=url_checks,
    )
    notify_high_risk_text_analysis(risk=result.risk, reasons=result.reasons)
    return TextAnalysisResult(**result.to_dict())
