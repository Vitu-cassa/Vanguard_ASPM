"""
Sensor SAST 1: Semgrep.

Roda o Semgrep no código de um alvo (por padrão, targets/mini-app),
normaliza os achados e salva no vanguard.db.

Uso típico:
    python scripts/scan.py --target targets/mini-app --config auto semgrep-rules/vanguard-custom.yml
    python scripts/scan.py --config semgrep-rules/vanguard-custom.yml   # offline

Requisitos:
- Semgrep instalado (já está no requirements.txt).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any

# Deixa a pasta raiz do projeto no sys.path para importar `app.*`
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# LGPD_CWES e compute_priority moraram aqui até a v0.1; continuam
# importáveis a partir deste módulo para não quebrar código antigo.
from app.ingest import (  # noqa: E402,F401
    LGPD_CWES,
    compute_priority,
    normalize_cwe,
    print_db_summary,
    save_findings,
)

# Mapeamento severidade do Semgrep -> nosso vocabulário.
# ERROR/WARNING/INFO é o formato clássico; versões recentes do Semgrep
# também aceitam CRITICAL/HIGH/MEDIUM/LOW nas regras, e elas aparecem assim
# no JSON — sem estas entradas, viravam UNKNOWN.
SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
    "CRITICAL": "HIGH",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
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
    return normalize_cwe(metadata.get("cwe"))


def run_semgrep(target: str, configs: list[str]) -> dict[str, Any]:
    """Chama o binário do Semgrep e devolve o JSON parseado.

    Aceita 1..N rulesets (--config c1 --config c2 ...).
    """
    cmd = ["semgrep"]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["--json", "--quiet", target]
    print(f"[scan] rodando: {' '.join(cmd)}")
    try:
        # Semgrep pode demorar. Sem timeout aqui, pois em Codespaces roda bem.
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    except FileNotFoundError:
        print("[scan] Comando 'semgrep' não encontrado. Ative o venv e rode "
              "`pip install -r requirements.txt`.")
        sys.exit(1)
    if not result.stdout.strip():
        print("[scan] Semgrep não devolveu JSON. stderr abaixo:")
        print(result.stderr)
        sys.exit(1)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"[scan] Falha ao parsear JSON do Semgrep: {e}")
        # Salva bruto para depurar
        with open("semgrep_out.json", "w", encoding="utf-8") as fh:
            fh.write(result.stdout)
        print("[scan] Saída bruta salva em semgrep_out.json")
        sys.exit(1)

    # Erros de parsing/regra não derrubam o Semgrep, mas escondem achados.
    errors = data.get("errors") or []
    if errors:
        print(f"[scan] AVISO: Semgrep reportou {len(errors)} erro(s):")
        for err in errors[:5]:
            print(f"        - {str(err.get('message') or err)[:200]}")
    return data


def normalize_results(semgrep_json: dict[str, Any], target: str) -> list[dict[str, Any]]:
    """Converte o JSON do Semgrep para o formato comum do app.ingest."""
    findings = []
    for r in semgrep_json.get("results", []):
        extra = r.get("extra") or {}
        # Path relativo ao target para facilitar leitura no dashboard.
        file_path = r.get("path") or ""
        try:
            file_path = os.path.relpath(file_path, target)
        except ValueError:
            pass  # em Windows caminhos de drives diferentes podem falhar
        findings.append(
            {
                "rule_id": r.get("check_id") or "",
                "severity": normalize_severity(extra.get("severity")),
                # Barra normal em qualquer SO: facilita comparar com o Sonar.
                "file_path": file_path.replace(os.sep, "/"),
                "line": (r.get("start") or {}).get("line", 0),
                "message": (extra.get("message") or "").strip(),
                "cwe": extract_cwe(extra.get("metadata")),
            }
        )
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Vanguard - scan Semgrep")
    parser.add_argument(
        "--target",
        default=os.path.join("targets", "mini-app"),
        help="pasta a ser escaneada (padrão: targets/mini-app)",
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
        print("Rode a partir da raiz do projeto (a pasta com o README.md).")
        sys.exit(2)

    data = run_semgrep(args.target, args.config)
    inserted, skipped = save_findings("semgrep", normalize_results(data, args.target))

    print("\n=== Vanguard - scan Semgrep concluído ===")
    print(f"Novos achados inseridos: {inserted}")
    if skipped:
        print(f"Já existentes (ignorados): {skipped}")
    print_db_summary("semgrep")
    print("Próximo passo: `python scripts/triage_claude.py --online` (com GEMINI_API_KEY)")
    print("           ou: `python scripts/triage_claude.py --dump-prompts` (sem chave)")


if __name__ == "__main__":
    main()
