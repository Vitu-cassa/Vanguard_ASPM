"""
Conexão e schema do banco SQLite do Vanguard.

Mantemos tudo em um único arquivo para ficar fácil de ler. Sem ORM.
A única "migration" é a coluna `fingerprint` (usada para não duplicar
achados quando o mesmo scan roda de novo): `init_db()` adiciona a coluna
em bancos antigos automaticamente, sem precisar apagar o vanguard.db.
"""

import os
import sqlite3

# Caminho do banco fica na raiz do projeto, ao lado do requirements.txt
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vanguard.db")

# Em produção (Vercel), o filesystem é readonly. Abrimos o SQLite em modo ro.
READONLY = os.getenv("VANGUARD_READONLY") == "1"

# Schema da tabela `findings`. Cada linha é um achado de scanner.
SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner         TEXT    NOT NULL,   -- 'semgrep' | 'sonarqube' | 'owasp_zap'
    rule_id         TEXT    NOT NULL,   -- id da regra do scanner
    severity        TEXT    NOT NULL,   -- HIGH | MEDIUM | LOW
    file_path       TEXT    NOT NULL,   -- caminho relativo ao alvo (SAST) ou URL (DAST)
    line            INTEGER NOT NULL,   -- linha do achado (0 = não se aplica, ex.: DAST)
    message         TEXT    NOT NULL,   -- descrição do scanner
    cwe             TEXT,               -- ex.: 'CWE-89' (pode ser NULL)
    lgpd_flag       INTEGER NOT NULL DEFAULT 0,   -- 0/1
    priority_score  REAL    NOT NULL DEFAULT 0,   -- ranking do MVP
    ai_status       TEXT    NOT NULL DEFAULT 'pendente',  -- pendente | triado
    ai_triage       TEXT,               -- verdadeiro_positivo_provavel | ...
    ai_explanation  TEXT,               -- texto pt-BR gerado pela IA
    ai_fix          TEXT,               -- sugestão de correção
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    fingerprint     TEXT                -- hash scanner+regra+local; evita duplicatas
);
"""


def get_conn() -> sqlite3.Connection:
    """Devolve uma conexão com row_factory para acessar por nome de coluna."""
    if READONLY:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    else:
        conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Atualiza bancos criados por versões anteriores (sem `fingerprint`)."""
    cols = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
    if "fingerprint" not in cols:
        conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT")
    # Linhas antigas ficam com fingerprint NULL; o índice UNIQUE aceita
    # vários NULLs, então nada quebra.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint "
        "ON findings(fingerprint)"
    )


def init_db() -> None:
    """Cria a tabela se ainda não existir. Seguro para chamar várias vezes."""
    if READONLY:
        return  # em produção não escrevemos no banco
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()


if __name__ == "__main__":
    # Rodar `python app/db.py` inicializa o banco manualmente.
    init_db()
    print(f"Banco pronto em: {DB_PATH}")
