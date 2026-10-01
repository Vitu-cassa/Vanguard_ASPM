"""
Normalização e gravação de achados — compartilhado pelos três sensores
(Semgrep, SonarQube e OWASP ZAP).

Cada sensor converte a saída do seu scanner para uma lista de dicts no
formato abaixo e chama `save_findings()`:

    {
        "rule_id":   "vanguard.sql-string-concat",
        "severity":  "HIGH" | "MEDIUM" | "LOW",
        "file_path": "routes/search.js"   (ou URL, no caso do ZAP),
        "line":      12                   (0 quando não se aplica),
        "message":   "texto do scanner",
        "cwe":       "CWE-89" | None,
    }

LGPD, prioridade e fingerprint são calculados aqui, para que os três
scanners usem exatamente a mesma régua.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

from app.db import get_conn, init_db

# Pontuação base por severidade. A ideia é dar peso maior a HIGH.
# Em produção isso vira uma matriz por (severidade x criticidade do ativo x
# exposição). Aqui, MVP: criticidade e exposição ficam fixas.
SEVERITY_BASE_SCORE = {
    "HIGH": 9.0,
    "MEDIUM": 7.0,
    "LOW": 4.0,
    "UNKNOWN": 1.0,
}

# CWEs que consideramos "sensíveis para LGPD" nesta versão. Cada uma
# tem relação com vazamento, exposição indevida ou controle de acesso
# a dados pessoais. Ideia futura: acrescentar CWE-311 (dados sensíveis
# sem criptografia) e CWE-359 (exposição de PII em log).
LGPD_CWES = {
    "CWE-89":  "SQL Injection (pode expor dados pessoais em massa)",
    "CWE-798": "Credenciais embutidas no código",
    "CWE-79":  "Cross-Site Scripting (roubo de sessão -> acesso a dados)",
    "CWE-327": "Uso de criptografia fraca em dados protegidos pela LGPD",
    "CWE-532": "Log com informação sensível",
    "CWE-22":  "Path Traversal (leitura arbitrária de arquivos)",
    "CWE-284": "Controle de acesso impróprio",
    "CWE-862": "Falta de autorização",
}

VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}

_CWE_RE = re.compile(r"(?i)^cwe[\s:_-]*(\d+)")


def normalize_cwe(raw: Any) -> str | None:
    """
    Aceita os formatos que os scanners usam e devolve 'CWE-89' ou None:
    'CWE-89: SQL Injection' (Semgrep), 'cwe-89' / 'cwe:89' (Sonar), 89 ou
    '89' (ZAP). Valores 0 e -1 (ZAP usa para "sem CWE") viram None.
    """
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
        return normalize_cwe(raw)
    text = str(raw).strip()
    if re.fullmatch(r"-?\d+", text):  # 89, "89", "-1"
        num = int(text)
    else:
        m = _CWE_RE.match(text)
        if not m:
            return None
        num = int(m.group(1))
    return f"CWE-{num}" if num > 0 else None


def is_lgpd(cwe: str | None) -> int:
    return 1 if cwe in LGPD_CWES else 0


def compute_priority(severity: str, lgpd_flag: int) -> float:
    """Nota simples e explicável para ordenar o dashboard."""
    base = SEVERITY_BASE_SCORE.get(severity, 1.0)
    # Bônus de LGPD faz achados sensíveis subirem no ranking.
    return base + (1.5 if lgpd_flag else 0.0)


def fingerprint(scanner: str, rule_id: str, file_path: str, line: int) -> str:
    """Identidade estável de um achado: mesmo scanner, regra e local."""
    raw = f"{scanner}|{rule_id}|{file_path}|{line}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def save_findings(scanner: str, findings: Iterable[dict[str, Any]]) -> tuple[int, int]:
    """
    Grava os achados. Devolve (inseridos, ignorados_por_ja_existirem).

    Rodar o mesmo scan duas vezes não duplica nada e preserva a triagem de
    IA já feita nos achados que continuam aparecendo.
    """
    init_db()
    inserted = skipped = 0
    with get_conn() as conn:
        cur = conn.cursor()
        for f in findings:
            severity = str(f.get("severity") or "UNKNOWN").upper()
            if severity not in VALID_SEVERITIES:
                severity = "UNKNOWN"
            cwe = normalize_cwe(f.get("cwe"))
            lgpd_flag = is_lgpd(cwe)
            rule_id = str(f.get("rule_id") or f"{scanner}-rule")
            file_path = str(f.get("file_path") or "")
            try:
                line = int(f.get("line") or 0)
            except (TypeError, ValueError):
                line = 0
            message = str(f.get("message") or "").strip()

            fp = fingerprint(scanner, rule_id, file_path, line)
            # Checa antes de inserir (em vez de só confiar no ON CONFLICT) para
            # não "gastar" ids do AUTOINCREMENT com linhas que já existem.
            if cur.execute(
                "SELECT 1 FROM findings WHERE fingerprint = ?", (fp,)
            ).fetchone():
                skipped += 1
                continue
            cur.execute(
                """
                INSERT INTO findings
                    (scanner, rule_id, severity, file_path, line, message,
                     cwe, lgpd_flag, priority_score, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO NOTHING
                """,
                (
                    scanner,
                    rule_id,
                    severity,
                    file_path,
                    line,
                    message,
                    cwe,
                    lgpd_flag,
                    compute_priority(severity, lgpd_flag),
                    fp,
                ),
            )
            if cur.rowcount == 1:
                inserted += 1
            else:
                skipped += 1
        conn.commit()
    return inserted, skipped


def print_db_summary(scanner: str | None = None) -> None:
    """Resumo no terminal após cada scan."""
    with get_conn() as conn:
        where, params = ("WHERE scanner = ?", (scanner,)) if scanner else ("", ())
        by_sev = {
            row["severity"]: row["c"]
            for row in conn.execute(
                f"SELECT severity, COUNT(*) AS c FROM findings {where} "
                "GROUP BY severity",
                params,
            )
        }
        lgpd = conn.execute(
            f"SELECT COUNT(*) AS c FROM findings {where} "
            f"{'AND' if where else 'WHERE'} lgpd_flag = 1",
            params,
        ).fetchone()["c"]
    label = f" ({scanner})" if scanner else ""
    print(f"Total no banco por severidade{label}: {by_sev}")
    print(f"Achados com flag LGPD{label}       : {lgpd}")
