import json
from typing import Any, Optional

from database import get_connection


def save_analysis(
    *,
    url: str,
    domain: str,
    domain_age_days: Optional[int],
    ssl_valid: Optional[bool],
    dns_data: dict[str, Any],
    whois_data: dict[str, Any],
    virustotal_data: dict[str, Any],
    brand_similarity_data: dict[str, Any],
    score: int,
    status: str,
    reasons: list[str],
) -> dict[str, Any]:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "insert into public.urls (url, domain) values (%s, %s) returning id",
                (url, domain),
            )
            url_id = cursor.fetchone()["id"]

            cursor.execute(
                """
                insert into public.analyses
                    (url_id, domain_age_days, ssl_valid, dns_data, whois_data,
                     virustotal_data, brand_similarity_data)
                values (%s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)
                returning id, created_at
                """,
                (
                    url_id,
                    domain_age_days,
                    ssl_valid,
                    json.dumps(dns_data),
                    json.dumps(whois_data),
                    json.dumps(virustotal_data),
                    json.dumps(brand_similarity_data),
                ),
            )
            analysis_row = cursor.fetchone()

            cursor.execute(
                """
                insert into public.risk_scores (analysis_id, score, status, reasons)
                values (%s, %s, %s, %s::jsonb)
                """,
                (analysis_row["id"], score, status, json.dumps(reasons)),
            )
            return analysis_row


def list_analyses(limit: int = 50) -> list[dict[str, Any]]:
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    a.id, a.created_at, a.domain_age_days, a.ssl_valid,
                    a.dns_data, a.whois_data, a.virustotal_data, a.brand_similarity_data,
                    u.url, u.domain,
                    r.score, r.status, r.reasons, r.ai_explanation
                from public.analyses a
                join public.urls u on u.id = a.url_id
                join public.risk_scores r on r.analysis_id = a.id
                order by a.created_at desc
                limit %s
                """,
                (limit,),
            )
            return list(cursor.fetchall())
