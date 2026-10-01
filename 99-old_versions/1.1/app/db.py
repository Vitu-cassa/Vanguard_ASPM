"""
Conexão e schema do banco SQLite do Vanguard.

Mantemos tudo em um único arquivo para ficar fácil de ler. Sem ORM,
sem migrations: quando você quiser um campo novo, apague o vanguard.db
e rode o scan de novo. Aqui é um MVP acadêmico, não produção.
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
    scanner         TEXT    NOT NULL,   -- ex.: 'semgrep'
    rule_id         TEXT    NOT NULL,   -- id da regra do scanner
    severity        TEXT    NOT NULL,   -- HIGH | MEDIUM | LOW
    file_path       TEXT    NOT NULL,   -- caminho relativo ao alvo
    line            INTEGER NOT NULL,   -- linha do achado
    message         TEXT    NOT NULL,   -- descrição do scanner
    cwe             TEXT,               -- ex.: 'CWE-89' (pode ser NULL)
    lgpd_flag       INTEGER NOT NULL DEFAULT 0,   -- 0/1
    priority_score  REAL    NOT NULL DEFAULT 0,   -- ranking do MVP
    ai_status       TEXT    NOT NULL DEFAULT 'pendente',  -- pendente | triado
    ai_triage       TEXT,               -- verdadeiro_positivo_provavel | ...
    ai_explanation  TEXT,               -- texto pt-BR gerado pela IA
    ai_fix          TEXT,               -- sugestão de correção
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
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


def init_db() -> None:
    """Cria a tabela se ainda não existir. Seguro para chamar várias vezes."""
    if READONLY:
        return  # em produção não escrevemos no banco
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        conn.commit()


if __name__ == "__main__":
    # Rodar `python app/db.py` inicializa o banco manualmente.
    init_db()
    print(f"Banco pronto em: {DB_PATH}")
