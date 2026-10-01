"""
Roda o Semgrep no código de um alvo (por padrão, targets/juice-shop),
normaliza os achados e salva no vanguard.db.

Uso típico:
    python scripts/scan.py
    python scripts/scan.py --target targets/juice-shop --config auto

Requisitos:
- Semgrep instalado (já está no requirements.txt).
- Alvo clonado dentro de targets/ (veja o README).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any

# Deixa a pasta raiz do projeto no sys.path para importar `app.db`
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.db import get_conn, init_db  # noqa: E402

# Mapeamento severidade do Semgrep -> nosso vocabulário
SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}

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


def normalize_severity(raw: str | None) -> str:
    if not raw:
        return "UNKNOWN"
    return SEVERITY_MAP.get(raw.upper(), "UNKNOWN")


def extract_cwe(metadata: dict[str, Any] | None) -> str | None:
    """
    O Semgrep coloca CWE em metadata['cwe']. Pode vir string ou lista.
    Devolvemos algo tipo 'CWE-89' ou None se não achar.
    """
    if not metadata:
        return None
    raw = metadata.get("cwe")
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw or not isinstance(raw, str):
        return None
    # Formatos comuns: 'CWE-89: SQL Injection' ou apenas '89'
    token = raw.split(":", 1)[0].strip()
    if token.upper().startswith("CWE-"):
        return token.upper()
    if token.isdigit():
        return f"CWE-{token}"
    return None


def compute_priority(severity: str, lgpd_flag: int) -> float:
    """Nota simples e explicável para ordenar o dashboard."""
    base = SEVERITY_BASE_SCORE.get(severity, 1.0)
    # Bônus de LGPD faz achados sensíveis subirem no ranking.
    return base + (1.5 if lgpd_flag else 0.0)


def run_semgrep(target: str, configs: list[str]) -> dict[str, Any]:
    """Chama o binário do Semgrep e devolve o JSON parseado.

    Aceita 1..N rulesets (--config c1 --config c2 ...). Compatível com o
    formato antigo (uma string única) via `nargs='+'` no argparse.
    """
    cmd = ["semgrep"]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["--json", "--quiet", target]
    print(f"[scan] rodando: {' '.join(cmd)}")
    # Semgrep pode demorar. Sem timeout aqui, pois em Codespaces roda bem.
    result = subprocess.run(cmd, capture_output=True, text=True)
    if not result.stdout.strip():
        print("[scan] Semgrep não devolveu JSON. stderr abaixo:")
        print(result.stderr)
        sys.exit(1)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"[scan] Falha ao parsear JSON do Semgrep: {e}")
        # Salva bruto para depurar
        with open("semgrep_out.json", "w", encoding="utf-8") as fh:
            fh.write(result.stdout)
        print("[scan] Saída bruta salva em semgrep_out.json")
        sys.exit(1)


def insert_findings(semgrep_json: dict[str, Any], target: str) -> int:
    """Persiste os achados normalizados e devolve quantos foram salvos."""
    init_db()
    inserted = 0
    with get_conn() as conn:
        cur = conn.cursor()
        for r in semgrep_json.get("results", []):
            severity = normalize_severity(
                (r.get("extra") or {}).get("severity")
            )
            metadata = (r.get("extra") or {}).get("metadata") or {}
            cwe = extract_cwe(metadata)
            lgpd_flag = 1 if cwe in LGPD_CWES else 0
            priority = compute_priority(severity, lgpd_flag)

            # Path relativo ao target para facilitar leitura no dashboard.
            file_path = r.get("path") or ""
            try:
                file_path = os.path.relpath(file_path, target)
            except ValueError:
                pass  # em Windows caminhos de drives diferentes podem falhar

            cur.execute(
                """
                INSERT INTO findings
                    (scanner, rule_id, severity, file_path, line, message,
                     cwe, lgpd_flag, priority_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "semgrep",
                    r.get("check_id") or "",
                    severity,
                    file_path,
                    (r.get("start") or {}).get("line", 0),
                    ((r.get("extra") or {}).get("message") or "").strip(),
                    cwe,
                    lgpd_flag,
                    priority,
                ),
            )
            inserted += 1
        conn.commit()
    return inserted


def main() -> None:
    parser = argparse.ArgumentParser(description="Vanguard - scan Semgrep")
    parser.add_argument(
        "--target",
        default=os.path.join("targets", "juice-shop"),
        help="pasta a ser escaneada (padrão: targets/juice-shop)",
    )
    parser.add_argument(
        "--config",
        nargs="+",
        default=["auto"],
        help="regras do Semgrep (aceita múltiplos; padrão: auto)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"[scan] Alvo não encontrado: {args.target}")
        print("Clone o Juice Shop antes. Veja o README na seção 'Passo a passo'.")
        sys.exit(2)

    data = run_semgrep(args.target, args.config)
    total = insert_findings(data, args.target)

    # Resumo por severidade, para dar feedback visual no terminal.
    with get_conn() as conn:
        by_sev = dict(
            (row["severity"], row["c"])
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings GROUP BY severity"
            )
        )
        lgpd = conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE lgpd_flag = 1"
        ).fetchone()["c"]

    print("\n=== Vanguard - scan concluído ===")
    print(f"Novos achados inseridos: {total}")
    print(f"Total por severidade   : {by_sev}")
    print(f"Achados com flag LGPD  : {lgpd}")
    print("Próximo passo: rodar `python scripts/triage.py` (com chave)")
    print("           ou: rodar `python scripts/triage.py --fake` (sem chave)")


if __name__ == "__main__":
    main()
