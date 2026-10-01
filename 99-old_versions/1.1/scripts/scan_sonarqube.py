"""
Sensor SAST Extra: SonarQube
Lê os achados do arquivo de referência do SonarQube, normaliza as vulnerabilidades
e persiste no banco vanguard.db.

Uso:
    python scripts/scan_sonarqube.py
    python scripts/scan_sonarqube.py --report reference-run/sonar-issues.json
"""

import argparse
import json
import os
import sys

# Garante acesso ao módulo app.db
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.db import get_conn, init_db
from scripts.scan import LGPD_CWES, compute_priority

SONAR_SEVERITY_MAP = {
    "BLOCKER": "HIGH",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "LOW",
}


def load_findings(report_path: str) -> list:
    """Carrega os achados a partir do relatório JSON de referência do SonarQube."""
    if os.path.exists(report_path):
        print(f"[scan_sonarqube] Lendo relatório do SonarQube: {report_path}")
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("issues", []) if isinstance(data, dict) else data
    return []


def parse_sonar_cwe(tags: list) -> str | None:
    """Extrai o padrão CWE das tags do SonarQube (ex: ['cwe-89', 'security'])."""
    for tag in tags or []:
        tag_str = str(tag).lower()
        if tag_str.startswith("cwe-"):
            return tag_str.upper()
    return None


def insert_sonar_findings(issues: list) -> int:
    """Insere os achados do SonarQube no SQLite vanguard.db."""
    init_db()
    inserted = 0
    with get_conn() as conn:
        cur = conn.cursor()
        for issue in issues:
            severity = SONAR_SEVERITY_MAP.get(
                issue.get("severity", "MAJOR").upper(), "MEDIUM"
            )
            tags = issue.get("tags", [])
            cwe = parse_sonar_cwe(tags)
            lgpd_flag = 1 if cwe in LGPD_CWES else 0
            priority = compute_priority(severity, lgpd_flag)

            component = issue.get("component", "")
            file_path = (
                component.split(":")[-1] if ":" in component else component
            )

            cur.execute(
                """
                INSERT INTO findings
                    (scanner, rule_id, severity, file_path, line, message, cwe, lgpd_flag, priority_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "sonarqube",
                    issue.get("rule", "sonar-rule"),
                    severity,
                    file_path,
                    issue.get("line", 1),
                    issue.get("message", "").strip(),
                    cwe,
                    lgpd_flag,
                    priority,
                ),
            )
            inserted += 1
        conn.commit()
    return inserted


def main():
    parser = argparse.ArgumentParser(description="Vanguard - Sensor SonarQube")
    parser.add_argument(
        "--report",
        default=os.path.join("reference-run", "sonar-issues.json"),
        help="Caminho do relatório JSON do SonarQube",
    )
    args = parser.parse_args()

    issues = load_findings(args.report)
    if not issues:
        print(
            f"[scan_sonarqube] Nenhum achado encontrado no relatório {args.report}."
        )
        sys.exit(1)

    total = insert_sonar_findings(issues)
    print(f"\n=== Vanguard - Scan SonarQube Concluído ===")
    print(f"Novos achados inseridos (SonarQube): {total}")


if __name__ == "__main__":
    main()