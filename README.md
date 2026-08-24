# Vanguard ASPM MVP — Pacote de Replicação

Kit completo pra rodar em **qualquer máquina** o pipeline `scan → triagem por IA
(Gemini) → dashboard`, com **~19 achados reais** de segurança contra um alvo
vulnerável semeado.

**Vem incluso:** código, alvo de teste, regras Semgrep custom, HTML do dashboard,
e uma pasta `reference-run/` com **como deve ficar** o output se tudo der certo
(logs, JSONs da API, screenshots do dashboard).

**Não vem incluso:** o `.env` com chave (você cria a sua) e o `.venv` (montado
localmente).

---

## 1. Pré-requisitos

| Ferramenta | Versão mínima | Como checar |
|---|---|---|
| Python | 3.10+ (3.12 recomendado) | `python3 --version` |
| pip | qualquer recente | `python3 -m pip --version` |
| git | qualquer | `git --version` |
| Conexão à internet | | (Semgrep baixa regras; Gemini é API) |
| macOS / Linux | | Windows funciona via WSL |
| **Chave Gemini** | grátis | https://aistudio.google.com/apikey |

Não precisa Docker, Node.js nem banco externo. SQLite é embutido.

---

## 2. Setup em 4 comandos

```bash
# 1) crie o venv e ative
python3 -m venv .venv && source .venv/bin/activate

# 2) instale dependências (~1 min)
pip install -r requirements.txt

# 3) configure sua chave Gemini
cp .env.example .env
$EDITOR .env    # troque SUA_CHAVE_AQUI pelo valor real

# 4) proteja a chave (opcional mas recomendado no macOS/Linux)
chmod 600 .env
```

Windows/PowerShell: `python -m venv .venv; .\.venv\Scripts\Activate.ps1`.

---

## 3. Rodar o pipeline

### 3.1. Scan do alvo (Semgrep + regras custom)

```bash
python scripts/scan.py --target targets/mini-app --config auto semgrep-rules/vanguard-custom.yml
```

Saída esperada (compare com `reference-run/stdout-logs/02-scan-real.txt`):

```
[scan] rodando: semgrep --config auto --config semgrep-rules/vanguard-custom.yml --json --quiet targets/mini-app

=== Vanguard - scan concluído ===
Novos achados inseridos: 19
Total por severidade   : {'HIGH': 10, 'MEDIUM': 9}
Achados com flag LGPD  : 11
```

**Se der 0 achados:** o Semgrep provavelmente falhou. Rode
`semgrep --config semgrep-rules/vanguard-custom.yml --validate` — deve dizer
"12 rule(s)".

### 3.2. Triagem por Gemini

```bash
python scripts/triage_claude.py --online
```

Saída esperada (compare com `reference-run/stdout-logs/16-triage-gemini.txt`):

```
[triage] pendentes: 19 · modelo: gemini-3.6-flash
[triage] lote 1/3: 8 achados → Gemini (gemini-3.6-flash)
[triage] lote 2/3: 8 achados → Gemini (gemini-3.6-flash)
[triage] lote 3/3: 3 achados → Gemini (gemini-3.6-flash)
[triage] concluído: 19 achados triados por Gemini.
```

**Se quiser re-triagar** (ex.: testar um modelo diferente):
```bash
python scripts/triage_claude.py --online --reset --model gemini-3.6-pro
```

**Se você não tem chave** — modo offline manual funciona:
```bash
python scripts/triage_claude.py --dump-prompts       # gera prompts/batch_NN.json
# preencha responses/batch_NN.json à mão ou usando ChatGPT/Claude/qualquer LLM
python scripts/triage_claude.py --load-responses
```

### 3.3. Dashboard

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Abra `http://127.0.0.1:8765/` no navegador. Deve mostrar:
- 5 stat cards: **Total 19 · HIGH 10 · MEDIUM 9 · LGPD 11 · Score 64 (Atenção)**
- Tabela com 19 achados, badges HIGH/MEDIUM/LGPD, coluna "Triagem IA"
- Clique em qualquer linha → painel de detalhe abre com explicação em PT-BR + fix

Para parar: `Ctrl+C` no terminal do uvicorn.

---

## 4. Sanity checks

Verificações agregadas via SQL — devem bater com `reference-run/12-sanity-checks.txt`:

```bash
sqlite3 vanguard.db "SELECT 'total:', COUNT(*) FROM findings"
# total:|19

sqlite3 vanguard.db "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
# HIGH|10
# MEDIUM|9

sqlite3 vanguard.db "SELECT ai_triage, COUNT(*) FROM findings GROUP BY ai_triage"
# 18 VP + 1 revisar (varia por modelo/temperatura)

sqlite3 vanguard.db "SELECT COUNT(*) FROM findings WHERE lgpd_flag=1"
# 11
```

Comparação HTTP:
```bash
curl -s http://127.0.0.1:8765/api/stats | python3 -m json.tool
# deve retornar o mesmo formato que reference-run/api-responses/18-api-stats-gemini.json
```

---

## 5. Screenshots opcionais do dashboard

Se quiser gerar PNGs igual ao que fiz em `reference-run/screenshots/`:

```bash
pip install playwright && playwright install chromium
python scripts/screenshot.py http://127.0.0.1:8765/ dashboard.png
python scripts/screenshot_views.py     # LGPD-only + HIGH-only
```

---

## 6. Estrutura do pacote

```
vanguard-poc-replicavel/
├── README.md                      ← este arquivo
├── requirements.txt
├── .env.example                   ← template; NÃO tem chave
├── .gitignore                     ← protege .env, .venv, *.db
│
├── app/                           ← FastAPI
│   ├── __init__.py
│   ├── db.py                      ← SQLite, schema, get_conn/init_db
│   ├── main.py                    ← endpoints /api/stats, /api/findings, ...
│   └── static/index.html          ← dashboard vanilla + Tailwind CDN
│
├── scripts/
│   ├── scan.py                    ← Semgrep → SQLite
│   ├── triage_claude.py           ← 3 modos: --dump-prompts | --load-responses | --online
│   ├── screenshot.py              ← Playwright: dashboard PNG
│   └── screenshot_views.py        ← filtros LGPD/HIGH
│
├── semgrep-rules/
│   └── vanguard-custom.yml        ← 12 regras próprias (MD5, SQLi, XSS, cmd inj, ...)
│
├── targets/mini-app/              ← alvo vulnerável semeado (10 arquivos)
│   ├── config/{default.yml,.env.example}
│   ├── lib/{crypto.js,eval.js}
│   └── routes/{admin.js,file.js,login.js,profile.js,search.js}
│
├── docs/
│   └── RELATORIO-EXECUCAO-REAL.md ← relatório detalhado da execução original
│
└── reference-run/                 ← "como deve ficar" após rodar
    ├── 11-vanguard-db-dump.sql    ← .dump completo do SQLite
    ├── 12-sanity-checks.txt       ← contagens agregadas
    ├── stdout-logs/               ← saídas de terminal esperadas
    ├── api-responses/             ← JSONs dos endpoints
    └── screenshots/               ← 6 PNGs do dashboard renderizado
```

---

## 7. O que o alvo `mini-app/` contém (semeado propositalmente)

10 arquivos JS/YAML com vulnerabilidades LGPD-relevantes plantadas:

| Arquivo | Padrão | CWE |
|---|---|---|
| `lib/crypto.js` | MD5 para hash de senha | 327 |
| `lib/eval.js` | `eval()` e `new Function()` com input do usuário | 94, 95 |
| `routes/admin.js` | `child_process.exec` + `Math.random` + SHA1 + token hardcoded | 78, 338, 330, 798 |
| `routes/file.js` | Path traversal via `path.join(req.params.file)` | 22 |
| `routes/login.js` | Password em `console.log`, JWT_SECRET hardcoded | 532, 798 |
| `routes/profile.js` | XSS por concat, open redirect | 79, 601 |
| `routes/search.js` | SQL injection por concat | 89 |
| `config/default.yml` | Chave API embutida em YAML | 798 |

Nenhum código é de produção. Serve pra exercitar 19 achados variados e gerar
dashboard visualmente completo.

---

## 8. Segurança operacional

1. **Nunca versione `.env`.** O `.gitignore` bloqueia, mas revise `git status`
   antes de qualquer `git add -A`.
2. **Rotacione a chave Gemini** se você suspeitar que vazou (em log, screenshot,
   chat, PR). O Google AI Studio permite revogar e gerar nova em segundos.
3. **`.env` com `chmod 600`** no macOS/Linux — só o dono lê.
4. **Não commite `vanguard.db`** — pode conter dados sensíveis se você trocar o
   alvo por código real (bruto do scan preserva mensagens/paths).

---

## 9. Troubleshooting

| Sintoma | Causa provável | Fix |
|---|---|---|
| `[scan] Alvo não encontrado` | rodou de fora da raiz do pacote | `cd` para a pasta com `README.md` |
| Scan retorna 0 achados | Semgrep sem rede pra baixar rules do Registry | `--config auto` requer internet; use apenas `--config semgrep-rules/vanguard-custom.yml` offline |
| `HTTP 401 UNAUTHENTICATED` no Gemini | chave inválida/rotacionada | gere nova em https://aistudio.google.com/apikey e atualize `.env` |
| `HTTP 404 model not found` | modelo aposentado | ajuste `GEMINI_MODEL` no `.env` |
| `[triage] Nenhum achado pendente` | já triou tudo | `python scripts/triage_claude.py --online --reset` |
| Dashboard em branco | `main.py` startup falhou | veja terminal do uvicorn; se faltar `app/static/`, o mount quebra |
| Rate limit 429 no Gemini | free tier atingido | `SLEEP_BETWEEN_BATCHES` em `triage_claude.py` sobe pra 8s |

---

## 10. Diferenças esperadas ao replicar

O output **não vai ser byte-idêntico** ao `reference-run/`:

- **IDs numéricos** podem variar se você rodar o scan múltiplas vezes (INSERT sequencial).
- **`ai_triage`, `ai_explanation`, `ai_fix`** vão diferir a cada chamada Gemini (LLM não é determinístico mesmo com `temperature=0.2`).
- **Contagens agregadas** (`total=19`, `HIGH=10`, `MEDIUM=9`, `lgpd=11`) devem
  bater. Se não baterem: o Semgrep Registry pode ter atualizado regras entre
  o meu run e o seu, gerando ±1-2 achados.
- **Distribuição da triagem** (18 VP + 1 revisar no meu run) vai variar por
  modelo. Um Gemini 3.6-pro tende a marcar mais duplicatas como `revisar`.

O que **deve** ser reprodutível:
- Pipeline não trava, os 3 comandos rodam.
- Dashboard responde 200 em todos os endpoints.
- Cada finding tem `ai_status='triado'` e explicação em PT-BR.

---

## 11. Créditos

- **Semgrep** — engine de scan (open source)
- **Google Gemini** — LLM de triagem
- **FastAPI + Uvicorn** — servidor web
- **Playwright** — captura de screenshot (opcional)
- **Vanguard** — grupo FIAP 2026 (Challenge Pride Security)

Livre pra estudar, adaptar, distribuir dentro do escopo do challenge.
