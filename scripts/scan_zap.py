"""
Sensor DAST: OWASP ZAP
Executa o ZAP via Docker contra um alvo dinâmico, normaliza os achados
e persiste no banco vanguard.db.

Uso:
    python scripts/scan_zap.py
    python scripts/scan_zap.py --target http://host.docker.internal:3000
"""

import argparse
import json
import os
import subprocess
import sys

# Garante acesso aos módulos do Vanguard
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.db import get_conn, init_db
from scripts.scan import LGPD_CWES, compute_priority

# Mapeamento do riskcode do ZAP (0-3) para severidade do Vanguard
ZAP_SEVERITY_MAP = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "LOW"  # Info vira LOW no MVP para manter o padrão
}

def run_zap(target_url: str, report_path: str):
    print(f"[scan_zap] Iniciando ZAP Baseline Scan contra {target_url}...")
    
    # Cria o arquivo vazio para garantir permissões do Docker
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, 'w', encoding='utf-8') as f:
        pass

    report_dir = os.path.dirname(report_path)
    report_filename = os.path.basename(report_path)

    docker_command = [
        "docker", "run", "--rm",
        "--add-host", "host.docker.internal:host-gateway",
        "-v", f"{report_dir}:/zap/wrk/:rw",
        "-t", "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py",
        "-t", target_url,
        "-J", report_filename
    ]

    try:
        process = subprocess.Popen(
            docker_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in process.stdout:
            # Imprime os logs do ZAP em tempo real
            print(line, end="")
        process.wait()
        
        if process.returncode not in [0, 2]:
            print(f"\n[scan_zap] Atenção: ZAP encerrou com erro (código {process.returncode}).")
    except FileNotFoundError:
        print("\n[scan_zap] Erro: Comando 'docker' não encontrado.")
        sys.exit(1)

def load_and_insert_zap(report_path: str) -> int:
    init_db()
    if not os.path.exists(report_path):
        print(f"[scan_zap] Arquivo JSON não encontrado: {report_path}")
        return 0

    with open(report_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("[scan_zap] Falha ao ler o JSON do ZAP.")
            return 0

    inserted = 0
    with get_conn() as conn:
        cur = conn.cursor()
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                risk_code = str(alert.get("riskcode", "0"))
                severity = ZAP_SEVERITY_MAP.get(risk_code, "LOW")
                
                # O ZAP retorna o CWE ID numérico
                cwe_id = alert.get("cweid", "-1")
                cwe = f"CWE-{cwe_id}" if str(cwe_id).isdigit() and str(cwe_id) != "-1" else None
                
                # Usa a mesma lógica de prioridade do Semgrep
                lgpd_flag = 1 if cwe in LGPD_CWES else 0
                priority = compute_priority(severity, lgpd_flag)

                # Como é DAST, o arquivo é na verdade a URL (endpoint) vulnerável
                instances = alert.get("instances", [])
                endpoint = instances[0].get("uri", "N/A") if instances else "N/A"
                
                rule_id = alert.get("alert", "zap-rule")[:50]
                message = alert.get("description", "").strip()

                cur.execute(
                    """
                    INSERT INTO findings
                        (scanner, rule_id, severity, file_path, line, message, cwe, lgpd_flag, priority_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "owasp_zap",
                        rule_id,
                        severity,
                        endpoint,
                        1,  # ZAP não tem "linha de código", setamos 1 por padrão
                        message,
                        cwe,
                        lgpd_flag,
                        priority,
                    ),
                )
                inserted += 1
        conn.commit()
    return inserted

def main():
    parser = argparse.ArgumentParser(description="Vanguard - Sensor DAST OWASP ZAP")
    parser.add_argument(
        "--target",
        default="http://host.docker.internal:3000",
        help="URL do alvo a ser escaneado",
    )
    parser.add_argument(
        "--report",
        default=os.path.join(ROOT, "reference-run", "zap-report.json"),
        help="Caminho onde o relatório JSON do ZAP será salvo",
    )
    args = parser.parse_args()

    print(f"\n=== Vanguard - Iniciando Sensor ZAP ===")
    
    # Executa o scan e gera o arquivo em reference-run/
    run_zap(args.target, args.report)
    
    # Ingestão para o banco SQLite
    total = load_and_insert_zap(args.report)
    print(f"\n=== Vanguard - Scan ZAP Concluído ===")
    print(f"Novos achados inseridos (OWASP ZAP): {total}")

if __name__ == "__main__":
    main()