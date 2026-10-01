"""
API FastAPI do Vanguard. Serve também o dashboard estático (index.html).

Rotas:
    GET /                    -> dashboard (index.html)
    GET /api/stats           -> totais, por severidade/scanner, % triado, LGPD, score
    GET /api/summary         -> agregados para a aba "Resumos AI"
    GET /api/findings        -> lista com filtros severity, lgpd e scanner
    GET /api/findings/{id}   -> detalhe de um achado
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.db import get_conn, init_db



@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Garante que o schema existe, mesmo que o usuário rode a API sem scan.
    # (substitui @app.on_event("startup"), que o FastAPI marcou como deprecated)
    init_db()
    yield


app = FastAPI(title="Vanguard ASPM", version="0.2.0", lifespan=lifespan)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
INDEX_HTML = os.path.join(STATIC_DIR, "index.html")

# Serve os arquivos estáticos (logo etc.) em /static/*
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _row_to_dict(row: Any) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


def _security_score(by_sev: dict[str, int], lgpd: int) -> tuple[int, str]:
    """
    Score simples e explicável de 0 a 100.

    Não é o CVSS, não é padrão ISO — é um MVP acadêmico. A ideia é dar
    ao usuário uma leitura rápida do "quão ruim está" o repositório
    escaneado. Cada severidade e a flag LGPD viram penalidade.

    Ajuste os pesos com o grupo quando quiser (é uma boa 'MISSÃO C').
    """
    penalty = (
        by_sev.get("HIGH", 0) * 2.0
        + by_sev.get("MEDIUM", 0) * 0.5
        + by_sev.get("LOW", 0) * 0.1
        + lgpd * 1.0
    )
    raw = 100.0 - penalty
    score = max(0, min(100, round(raw)))
    if score >= 90:
        label = "Excelente"
    elif score >= 70:
        label = "Bom"
    elif score >= 40:
        label = "Atenção"
    else:
        label = "Crítico"
    return score, label


@app.get("/api/stats")
def stats() -> JSONResponse:
    with get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]
        by_sev_rows = conn.execute(
            "SELECT severity, COUNT(*) AS c FROM findings GROUP BY severity"
        ).fetchall()
        triados = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE ai_status = 'triado'"
        ).fetchone()["c"]
        lgpd = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE lgpd_flag = 1"
        ).fetchone()["c"]
        by_scanner_rows = conn.execute(
            "SELECT scanner, COUNT(*) AS c FROM findings GROUP BY scanner "
            "ORDER BY c DESC"
        ).fetchall()

    by_sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for r in by_sev_rows:
        by_sev[r["severity"]] = r["c"]
    by_scanner = {r["scanner"]: r["c"] for r in by_scanner_rows}

    pct_triado = round((triados / total) * 100, 1) if total else 0.0
    score, score_label = _security_score(by_sev, lgpd)
    return JSONResponse(
        {
            "total": total,
            "by_severity": by_sev,
            "by_scanner": by_scanner,
            "triados": triados,
            "pct_triado": pct_triado,
            "lgpd": lgpd,
            "security_score": score,
            "security_score_label": score_label,
        }
    )


@app.get("/api/summary")
def summary() -> JSONResponse:
    """
    Agregados usados pela aba 'Resumos AI'. Retorna:
      - top_rules: as 5 regras que mais aparecem
      - top_cwes:  os 5 CWEs mais frequentes (ignorando NULL)
      - by_triage: contagem de cada rótulo da IA
      - critical_examples: até 3 achados HIGH+LGPD já triados
    """
    with get_conn() as conn:
        top_rules = [dict(r) for r in conn.execute(
            "SELECT rule_id, COUNT(*) AS c FROM findings "
            "GROUP BY rule_id ORDER BY c DESC LIMIT 5"
        )]
        top_cwes = [dict(r) for r in conn.execute(
            "SELECT cwe, COUNT(*) AS c FROM findings "
            "WHERE cwe IS NOT NULL GROUP BY cwe ORDER BY c DESC LIMIT 5"
        )]
        by_triage_rows = conn.execute(
            "SELECT COALESCE(ai_triage, 'pendente') AS t, COUNT(*) AS c "
            "FROM findings GROUP BY t"
        ).fetchall()
        critical_examples = [dict(r) for r in conn.execute(
            "SELECT id, rule_id, file_path, line, severity, cwe, ai_explanation "
            "FROM findings WHERE severity='HIGH' AND lgpd_flag=1 "
            "  AND ai_status='triado' "
            "ORDER BY priority_score DESC LIMIT 3"
        )]

    by_triage = {r["t"]: r["c"] for r in by_triage_rows}
    return JSONResponse(
        {
            "top_rules": top_rules,
            "top_cwes": top_cwes,
            "by_triage": by_triage,
            "critical_examples": critical_examples,
        }
    )


@app.get("/api/findings")
def findings(
    severity: str | None = Query(default=None, description="HIGH | MEDIUM | LOW"),
    lgpd: bool | None = Query(default=None, description="filtra apenas LGPD"),
    scanner: str | None = Query(
        default=None, description="semgrep | sonarqube | owasp_zap"
    ),
) -> JSONResponse:
    query = (
        "SELECT id, scanner, rule_id, severity, file_path, line, message, "
        "cwe, lgpd_flag, priority_score, ai_status, ai_triage "
        "  FROM findings WHERE 1=1"
    )
    params: list[Any] = []
    if severity:
        query += " AND severity = ?"
        params.append(severity.upper())
    if lgpd:
        query += " AND lgpd_flag = 1"
    if scanner:
        query += " AND scanner = ?"
        params.append(scanner.lower())
    query += " ORDER BY priority_score DESC, id ASC"

    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
    return JSONResponse([_row_to_dict(r) for r in rows])


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: int) -> JSONResponse:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Achado não encontrado")
    return JSONResponse(_row_to_dict(row))


@app.get("/")
def root() -> FileResponse:
    return FileResponse(INDEX_HTML, media_type="text/html")
