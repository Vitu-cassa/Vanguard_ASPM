"""
Triagem por IA dos achados (Semgrep, SonarQube e OWASP ZAP).

Três modos (escolha exatamente um):

  --online          chama a API do Google Gemini (precisa GEMINI_API_KEY no .env)
  --dump-prompts    fase offline 1 (sem chave)
  --load-responses  fase offline 2 (sem chave)

O fluxo offline, em duas fases, é auditável e não faz chamada de rede:

  1) dump-prompts  →  seleciona pendentes, monta o mesmo user prompt do
                      script original e grava cada lote em prompts/batch_NN.json
                      (com o SYSTEM_PROMPT junto). O modelo (Claude no loop
                      desta sessão) lê esses arquivos.

  2) load-responses → lê responses/batch_NN.json (o array JSON que a IA
                      devolveu, no mesmo shape que o script original espera)
                      e faz UPDATE nas linhas correspondentes.

Vantagens em ambiente de PoC:
- Sem chave, sem tráfego externo.
- Prompts e respostas ficam versionáveis como evidência.
- Mesmo shape de dados do script real → drop-in replacement pra swap futuro.

Uso:
    python scripts/triage_claude.py --dump-prompts --limit 30
    # (o operador — humano ou agente — produz responses/batch_NN.json)
    python scripts/triage_claude.py --load-responses
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any

import requests
from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

load_dotenv(os.path.join(ROOT, ".env"))

from app.db import get_conn, init_db  # noqa: E402

PROMPTS_DIR = os.path.join(ROOT, "prompts")
RESPONSES_DIR = os.path.join(ROOT, "responses")
BATCH_SIZE = 8
SLEEP_BETWEEN_BATCHES = 4

# A chave vai no header x-goog-api-key, NUNCA na URL: em erro de rede
# (timeout, DNS, proxy) o requests imprime a URL inteira no traceback, e a
# chave acabava no terminal e nos logs salvos como evidência.
GEMINI_URL_TMPL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
)
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

SYSTEM_PROMPT = (
    "Você é uma analista sênior de AppSec brasileira. "
    "Analisa achados de scanner e responde SEMPRE em português do Brasil. "
    "Os achados vêm de SAST (semgrep, sonarqube: file_path é arquivo e line "
    "é a linha) e de DAST (owasp_zap: file_path é a URL testada e line é 0). "
    "Sua resposta DEVE ser SOMENTE um array JSON válido, sem prosa antes "
    "ou depois, sem cercas de código. Cada item do array corresponde, na "
    "mesma ordem, a um achado enviado, com as chaves: "
    '"triage" (valor entre "verdadeiro_positivo_provavel", '
    '"falso_positivo_provavel" ou "revisar"), '
    '"explicacao" (2 a 3 frases claras, pensadas para um dev júnior, '
    "explicando o risco no contexto do achado) e "
    '"fix" (1 a 2 frases objetivas de como corrigir).'
)


def fetch_pending(limit: int) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, scanner, rule_id, severity, file_path, line,
                   message, cwe, lgpd_flag, priority_score
              FROM findings
             WHERE ai_status = 'pendente'
             ORDER BY priority_score DESC, id ASC
             LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def build_user_prompt(batch: list[dict[str, Any]]) -> str:
    header = (
        "Analise os achados abaixo (JSON). Responda com um array JSON "
        f"contendo exatamente {len(batch)} itens, na mesma ordem."
    )
    payload = [
        {
            "indice": i,
            "scanner": f["scanner"],
            "rule_id": f["rule_id"],
            "severity": f["severity"],
            "file_path": f["file_path"],
            "line": f["line"],
            "message": f["message"],
            "cwe": f["cwe"],
            "lgpd_flag": bool(f["lgpd_flag"]),
        }
        for i, f in enumerate(batch)
    ]
    return f"{header}\n\nACHADOS:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"


def dump_prompts(limit: int) -> int:
    """Fase 1: escreve os prompts em disco para consumo pelo modelo local."""
    os.makedirs(PROMPTS_DIR, exist_ok=True)
    pending = fetch_pending(limit)
    if not pending:
        print("[triage] Nenhum achado pendente. Rode o scan primeiro.")
        return 0

    n_batches = 0
    for start in range(0, len(pending), BATCH_SIZE):
        n_batches += 1
        batch = pending[start : start + BATCH_SIZE]
        ids = [f["id"] for f in batch]
        prompt_obj = {
            "batch_index": n_batches,
            "finding_ids": ids,
            "system": SYSTEM_PROMPT,
            "user": build_user_prompt(batch),
        }
        path = os.path.join(PROMPTS_DIR, f"batch_{n_batches:02d}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(prompt_obj, fh, ensure_ascii=False, indent=2)
        print(f"[triage] gravado {path}  (ids={ids})")

    print(
        f"\n[triage] {n_batches} lote(s) escritos em {PROMPTS_DIR}. "
        f"Total de achados: {len(pending)}."
    )
    print(
        "[triage] próximo passo: o modelo produz responses/batch_NN.json "
        "(array JSON puro, mesma ordem) e você roda:"
    )
    print("           python scripts/triage_claude.py --load-responses")
    return n_batches


def parse_ai_content(content: str, expected: int) -> list[dict[str, Any]]:
    if not content:
        return []
    stripped = re.sub(r"^```(?:json)?", "", content.strip())
    stripped = re.sub(r"```$", "", stripped).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        try:
            s = stripped.index("[")
            e = stripped.rindex("]")
            data = json.loads(stripped[s : e + 1])
        except (ValueError, json.JSONDecodeError):
            return []
    if not isinstance(data, list):
        return []
    return data[:expected]


VALID_TRIAGE = {"verdadeiro_positivo_provavel", "falso_positivo_provavel", "revisar"}


def save_triage(finding_id: int, triage: dict[str, Any]) -> None:
    # Se a IA inventar um rótulo fora do combinado, cai em "revisar".
    label = str(triage.get("triage", "revisar")).strip()
    if label not in VALID_TRIAGE:
        label = "revisar"
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE findings
               SET ai_status      = 'triado',
                   ai_triage      = ?,
                   ai_explanation = ?,
                   ai_fix         = ?
             WHERE id = ?
            """,
            (
                label,
                str(triage.get("explicacao", ""))[:2000],
                str(triage.get("fix", ""))[:2000],
                finding_id,
            ),
        )
        conn.commit()


def load_responses() -> int:
    """Fase 2: consome responses/batch_NN.json e atualiza o banco."""
    if not os.path.isdir(RESPONSES_DIR):
        print(f"[triage] Pasta {RESPONSES_DIR} não existe.")
        return 0

    files = sorted(f for f in os.listdir(RESPONSES_DIR) if f.startswith("batch_") and f.endswith(".json"))
    if not files:
        print(f"[triage] Nenhum response em {RESPONSES_DIR}.")
        return 0

    updated = 0
    for name in files:
        idx = int(re.search(r"batch_(\d+)", name).group(1))
        prompt_path = os.path.join(PROMPTS_DIR, f"batch_{idx:02d}.json")
        if not os.path.isfile(prompt_path):
            print(f"[triage] AVISO: sem prompt correspondente para {name}, pulando.")
            continue
        with open(prompt_path, "r", encoding="utf-8") as fh:
            prompt_obj = json.load(fh)
        ids = prompt_obj["finding_ids"]

        with open(os.path.join(RESPONSES_DIR, name), "r", encoding="utf-8") as fh:
            raw = fh.read()

        # Aceita tanto array JSON direto quanto {"content": "..."} (formato flexível).
        try:
            data = json.loads(raw)
            if isinstance(data, dict) and "content" in data:
                items = parse_ai_content(data["content"], expected=len(ids))
            elif isinstance(data, list):
                items = data
            else:
                items = []
        except json.JSONDecodeError:
            items = parse_ai_content(raw, expected=len(ids))

        for fid, item in zip(ids, items):
            save_triage(fid, item if isinstance(item, dict) else {})
            updated += 1
        # Se o modelo devolveu menos itens que o lote, marca o restante como revisar.
        for fid in ids[len(items):]:
            save_triage(
                fid,
                {
                    "triage": "revisar",
                    "explicacao": "Resposta ausente para este item.",
                    "fix": "Reveja manualmente.",
                },
            )
            updated += 1
        print(f"[triage] {name}: {len(items)} triagens aplicadas (esperado {len(ids)}).")

    print(f"\n[triage] concluído: {updated} achados atualizados.")
    return updated


def call_gemini(user_prompt: str, api_key: str, model: str) -> str:
    """Chama a API do Google (Generative Language) e devolve o texto bruto."""
    url = GEMINI_URL_TMPL.format(model=model)
    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }
    resp = requests.post(
        url, json=body, headers={"x-goog-api-key": api_key}, timeout=120
    )
    resp.raise_for_status()
    data = resp.json()
    return data["candidates"][0]["content"]["parts"][0]["text"]


def run_online_gemini(pending: list[dict[str, Any]], api_key: str, model: str) -> int:
    done = 0
    n_batches = (len(pending) + BATCH_SIZE - 1) // BATCH_SIZE
    for start in range(0, len(pending), BATCH_SIZE):
        batch = pending[start : start + BATCH_SIZE]
        idx = start // BATCH_SIZE + 1
        print(f"[triage] lote {idx}/{n_batches}: {len(batch)} achados → Gemini ({model})")
        try:
            content = call_gemini(build_user_prompt(batch), api_key, model)
        except requests.HTTPError as e:
            # Erro HTTP (401, 404, 429...): deixa o lote como 'pendente' para
            # que a próxima execução tente de novo, em vez de gravar 'revisar'
            # e dar a impressão de que a IA analisou.
            print(f"[triage] HTTP {e.response.status_code}: {e.response.text[:200]}")
            print("[triage] lote mantido como pendente; rode de novo depois.")
            time.sleep(SLEEP_BETWEEN_BATCHES)
            continue
        except requests.RequestException as e:
            # Timeout/DNS/proxy. Mostra só o tipo do erro (a mensagem completa
            # do requests pode conter a URL da requisição).
            print(f"[triage] falha de rede ({type(e).__name__}); lote mantido como pendente.")
            time.sleep(SLEEP_BETWEEN_BATCHES)
            continue
        except (KeyError, IndexError, ValueError):
            # Resposta sem 'candidates' (ex.: bloqueio de segurança do modelo).
            print("[triage] resposta inesperada do Gemini; lote mantido como pendente.")
            time.sleep(SLEEP_BETWEEN_BATCHES)
            continue

        parsed = parse_ai_content(content, expected=len(batch))
        for f, item in zip(batch, parsed):
            save_triage(f["id"], item if isinstance(item, dict) else {})
            done += 1
        # sobra do lote se a IA devolveu menos que o esperado
        for f in batch[len(parsed):]:
            save_triage(
                f["id"],
                {
                    "triage": "revisar",
                    "explicacao": "A IA não devolveu resposta para este item.",
                    "fix": "Rode a triagem novamente ou revise manualmente.",
                },
            )
            done += 1
        time.sleep(SLEEP_BETWEEN_BATCHES)
    return done


def count_pending() -> int:
    with get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) AS c FROM findings WHERE ai_status = 'pendente'"
        ).fetchone()["c"]


def reset_status() -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE findings SET ai_status='pendente', ai_triage=NULL, "
            "ai_explanation=NULL, ai_fix=NULL"
        )
        conn.commit()
        return cur.rowcount


def main() -> None:
    parser = argparse.ArgumentParser(description="Vanguard - triagem por IA")
    parser.add_argument("--dump-prompts", action="store_true",
                        help="Fase offline 1: grava prompts em prompts/")
    parser.add_argument("--load-responses", action="store_true",
                        help="Fase offline 2: consome responses/ e grava no banco")
    parser.add_argument("--online", action="store_true",
                        help="Chama Gemini API para triar os pendentes")
    parser.add_argument("--reset", action="store_true",
                        help="Antes de rodar, marca TODOS os achados como pendentes (perde triagem anterior)")
    parser.add_argument("--limit", type=int, default=100,
                        help="máximo de achados por execução (padrão 100)")
    parser.add_argument("--model", default=DEFAULT_GEMINI_MODEL,
                        help=f"modelo Gemini (default {DEFAULT_GEMINI_MODEL})")
    args = parser.parse_args()

    init_db()

    modes = [args.dump_prompts, args.load_responses, args.online]
    if sum(bool(m) for m in modes) != 1:
        print("Escolha exatamente um: --dump-prompts | --load-responses | --online")
        sys.exit(2)

    if args.reset:
        n = reset_status()
        print(f"[triage] reset: {n} achados marcados como 'pendente'.")

    if args.dump_prompts:
        dump_prompts(args.limit)
    elif args.load_responses:
        load_responses()
    else:
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            print("[triage] GEMINI_API_KEY ausente no .env.")
            sys.exit(1)
        pending = fetch_pending(args.limit)
        if not pending:
            print("[triage] Nenhum achado pendente. Rode o scan primeiro (ou use --reset).")
            return
        print(f"[triage] pendentes: {len(pending)} · modelo: {args.model}")
        done = run_online_gemini(pending, api_key=api_key, model=args.model)
        print(f"[triage] concluído: {done} achados triados por Gemini.")
        remaining = count_pending()
        if remaining:
            print(f"[triage] ainda pendentes: {remaining} (rode o comando de novo).")


if __name__ == "__main__":
    main()
