import os
from typing import Any

from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from analyzer import InvalidUrlError, analyze_url
from database import DatabaseConfigurationError, database_is_connected, get_database_url
from models import AnalysisResult, AnalyzeRequest, HealthResponse
from repository import list_analyses, save_analysis


app = FastAPI(
    title="AI Destekli Phishing Tespit Platformu",
    version="0.2.0",
)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    )


@app.post(
    "/analyze",
    response_model=AnalysisResult,
    status_code=status.HTTP_201_CREATED,
)
def analyze(payload: AnalyzeRequest) -> AnalysisResult:
    try:
        signals, score, risk_status, reasons = analyze_url(payload.url)
        analysis_row = save_analysis(
            url=signals.url,
            domain=signals.domain,
            domain_age_days=signals.domain_age_days,
            ssl_valid=signals.ssl_valid,
            dns_data=signals.dns_data,
            whois_data=signals.whois_data,
            virustotal_data=signals.virustotal_data,
            score=score,
            status=risk_status,
            reasons=reasons,
        )
    except InvalidUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DatabaseConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
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
        created_at=analysis_row.get("created_at"),
    )


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
