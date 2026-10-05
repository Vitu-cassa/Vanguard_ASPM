# Vanguard ASPM MVP — Pacote de Replicação

Kit completo pra rodar em localmente o pipeline:

```
 Semgrep (SAST) ─┐
 SonarQube (SAST)├─► vanguard.db ─► triagem por IA (Gemini) ─► dashboard
 OWASP ZAP (DAST)┘
```

contra um alvo vulnerável semeado (`targets/mini-app/`). Os três scanners
gravam no **mesmo formato** (severidade, CWE, flag LGPD, prioridade), então o
dashboard e a triagem tratam todos igual — e dá pra ver o SAST apontando a
linha do bug e o DAST confirmando que ele é explorável na aplicação rodando.

**Vem incluso:** código, alvo de teste (agora executável), regras Semgrep
custom, `docker-compose.yml` (SonarQube + mini-app), HTML do dashboard e a
pasta `reference-run/` da execução original.

**Não vem incluso:** o `.env` com chaves (você cria o seu a partir do
`.env.example`) e o `.venv` (montado localmente).

> O que mudou nesta versão (bugs corrigidos + integrações): veja
> [`docs/MUDANCAS-v0.2.md`](docs/MUDANCAS-v0.2.md).

---

## 1. Pré-requisitos

| Ferramenta | Versão mínima | Para quê | Como checar |
|---|---|---|---|
| Python | 3.10+ (3.12 recomendado) | tudo | `python3 --version` |
| pip | qualquer recente | dependências | `python3 -m pip --version` |
| Docker + Compose | Docker 20.10+ | SonarQube e ZAP (recomendado) | `docker compose version` |
| Node.js | 18+ | só se for rodar o mini-app sem Docker | `node --version` |
| Conexão à internet | | Semgrep Registry, imagens Docker, Gemini | |
| **Chave Gemini** | grátis | triagem online (opcional) | https://aistudio.google.com/apikey |

SQLite é embutido. macOS / Linux funcionam direto; Windows via WSL2 ou
Docker Desktop. RAM: o SonarQube sozinho pede ~2 GB livres.

---

## 2. Setup em 4 comandos

```bash
# 1) crie o venv e ative
python3 -m venv .venv && source .venv/bin/activate

# 2) instale dependências (~1 min)
pip install -r requirements.txt

# 3) configure suas chaves
cp .env.example .env
$EDITOR .env    # GEMINI_API_KEY (e SONAR_TOKEN, depois do passo 3.2)

# 4) proteja o arquivo (macOS/Linux)
chmod 600 .env
```

Windows/PowerShell: `python -m venv .venv; .\.venv\Scripts\Activate.ps1`.

---

## 3. Rodar o pipeline

Rode tudo **a partir da raiz do projeto** (a pasta deste README).
Cada scanner pode ser rodado de novo quantas vezes quiser: achados que já
existem são ignorados (não duplicam e mantêm a triagem de IA já feita).

### 3.1. SAST 1 — Semgrep (regras do Registry + 13 regras custom)

```bash
python scripts/scan.py --target targets/mini-app --config auto semgrep-rules/vanguard-custom.yml
```

Só com as regras custom (funciona offline) o resultado é exato e
reprodutível — **15 achados**, um por vulnerabilidade semeada:

```bash
python scripts/scan.py --config semgrep-rules/vanguard-custom.yml
# Novos achados inseridos: 15
# Total no banco por severidade (semgrep): {'HIGH': 10, 'MEDIUM': 5}
# Achados com flag LGPD (semgrep)       : 9
```

Com `--config auto` entram também as regras do Semgrep Registry, e o total
sobe (o número exato varia com a versão do Registry).

### 3.2. SAST 2 — SonarQube

**Primeira vez (uma vez só):**

```bash
docker compose up -d sonarqube     # leva 1-2 min pra ficar pronto
```

1. Abra http://localhost:9000, entre com `admin` / `admin` e troque a senha.
2. Vá em **My Account → Security → Generate Tokens**, tipo **User Token**
   (tokens de *análise* não conseguem ler a Web API).
3. Cole o token em `SONAR_TOKEN=` no `.env`.

**Scan:**

```bash
python scripts/scan_sonarqube.py
```

O script: roda o SonarScanner no `targets/mini-app` (usa o `sonar-scanner`
do PATH se existir; senão, o container `sonarsource/sonar-scanner-cli`),
espera o SonarQube processar a análise e baixa pela Web API as
**vulnerabilidades** e os **Security Hotspots**.

> **Por que hotspots?** Na edição Community, quase todas as regras de
> segurança de JavaScript (SQL por concatenação, hash fraco, `Math.random`,
> `exec`, `eval`, senha hardcoded...) são *Security Hotspots* — "código
> sensível que precisa de revisão". Eles **não** aparecem em
> `/api/issues/search`; sem buscá-los, o Sonar traria quase nada. No
> dashboard eles aparecem com a mensagem começando por `[Security Hotspot]`.

Outros modos:

```bash
python scripts/scan_sonarqube.py --skip-scan              # só baixa (projeto já analisado)
python scripts/scan_sonarqube.py --scanner docker         # força o scanner em container
python scripts/scan_sonarqube.py --report arquivo.json    # só importa um JSON salvo (offline)
python scripts/scan_sonarqube.py --no-hotspots            # só vulnerabilidades
```

A resposta bruta fica em `reports/sonarqube/sonar-findings.json` (pode ser
reimportada com `--report`). Compatível com SonarQube 9.9 LTS até 2025.x (o
script detecta a versão e usa os nomes de parâmetro certos da API).

### 3.3. DAST — OWASP ZAP

O ZAP ataca a aplicação **rodando**, então primeiro suba o mini-app:

```bash
docker compose up -d mini-app      # recomendado: isolado em container
# ou, sem Docker:  cd targets/mini-app && npm install && npm start
```

Confira em http://localhost:3000. Depois:

```bash
python scripts/scan_zap.py                 # baseline: spider + análise passiva (~2 min)
python scripts/scan_zap.py --active        # full scan: baseline + ATAQUES (mais lento)
```

- **Baseline** acha problemas de configuração: headers ausentes (CSP,
  anti-clickjacking, nosniff), `X-Powered-By` vazando versão, falta de token
  anti-CSRF.
- **`--active`** também acha o que o SAST apontou, agora *confirmado em
  execução*: SQL Injection em `/search`, XSS refletido em `/profile/render`,
  command injection em `/admin/exec`, open redirect em `/profile/redirect`.

Resultado da execução de referência (ZAP 2.16.1, `--active`): **12 achados**
— 6 HIGH, 4 MEDIUM, 2 LOW, 4 com flag LGPD. Pode variar ±1-2 com a versão das
regras do ZAP.

Outros modos:

```bash
# Usar um ZAP Desktop já aberto (sem Docker). A chave fica em
# Tools > Options > API; coloque em ZAP_API_KEY no .env.
python scripts/scan_zap.py --mode api --active

# Importar um relatório gerado antes (ZAP Desktop: Report > Generate Report >
# "Traditional JSON Report")
python scripts/scan_zap.py --report caminho/zap-report.json
```

Alertas informativos (risco 0) são descartados por padrão
(`--include-info` para gravar). Alertas de **ataque** viram um achado por
endpoint; alertas **passivos** (headers etc.) viram um achado por tipo,
listando as URLs afetadas — senão um header ausente em 50 páginas viraria
50 linhas no dashboard.

> ⚠️ **Só escaneie aplicações suas ou com autorização por escrito.** O scan
> ativo envia payloads reais. O mini-app executa comandos do sistema em
> `/admin/exec` — por isso ele escuta só em `127.0.0.1` e o recomendado é
> rodá-lo no container.

### 3.4. Triagem por IA (Gemini)

```bash
python scripts/triage_IA.py --online
```

```
[triage] pendentes: N · modelo: gemini-3.6-flash
[triage] lote 1/K: 8 achados → Gemini (gemini-3.6-flash)
...
[triage] concluído: N achados triados por Gemini.
```

A IA recebe os achados dos três scanners (e sabe que, no ZAP, `file_path` é
uma URL). Se uma chamada falhar (rede, 429, 401), o lote **continua
pendente** e é retentado na próxima execução.

**Se quiser re-triagar** (ex.: testar um modelo diferente):
```bash
python scripts/triage_IA.py --online --reset --model gemini-3.6-pro
```

**Se você não tem chave** — modo offline manual funciona:
```bash
python scripts/triage_IA.py --dump-prompts       # gera prompts/batch_NN.json
# preencha responses/batch_NN.json à mão ou usando ChatGPT/Claude/qualquer LLM
python scripts/triage_IA.py --load-responses
```

### 3.5. Dashboard

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8765
```

Abra `http://127.0.0.1:8765/`. Deve mostrar:
- 5 stat cards (Total com a divisão por scanner · HIGH · MEDIUM · LGPD · Score)
- Tabela com coluna **Scanner** e filtros por severidade, **scanner** e LGPD
- Clique em qualquer linha → painel de detalhe com explicação em PT-BR + fix

Para parar: `Ctrl+C` no terminal do uvicorn.

---

## 4. Sanity checks

```bash
sqlite3 vanguard.db "SELECT scanner, COUNT(*) FROM findings GROUP BY scanner"
# semgrep|15          (só regras custom; mais com --config auto)
# sonarqube|...       (depende da versão do SonarQube/SonarJS)
# owasp_zap|12        (com --active)

sqlite3 vanguard.db "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
sqlite3 vanguard.db "SELECT ai_triage, COUNT(*) FROM findings GROUP BY ai_triage"
sqlite3 vanguard.db "SELECT COUNT(*) FROM findings WHERE lgpd_flag=1"
```

Comparação HTTP:
```bash
curl -s http://127.0.0.1:8765/api/stats | python3 -m json.tool
curl -s "http://127.0.0.1:8765/api/findings?scanner=owasp_zap" | python3 -m json.tool
```

---

## 5. Screenshots opcionais do dashboard

```bash
pip install playwright && playwright install chromium
python scripts/screenshot.py http://127.0.0.1:8765/ dashboard.png
python scripts/screenshot_views.py     # LGPD-only + HIGH-only
```

---

## 6. Estrutura do pacote

```
Vanguard_ASPM/
├── README.md                      ← este arquivo
├── requirements.txt
├── .env.example                   ← template; NÃO tem chave
├── .gitignore                     ← protege .env, .venv, *.db, reports/
├── docker-compose.yml             ← SonarQube + mini-app (portas só em 127.0.0.1)
│
├── app/                           ← FastAPI
│   ├── db.py                      ← SQLite, schema, migração da coluna fingerprint
│   ├── ingest.py                  ← normalização comum: CWE, LGPD, prioridade, dedupe
│   ├── netutil.py                 ← "localhost" visto de dentro de um container
│   ├── main.py                    ← /api/stats, /api/findings (filtro scanner), ...
│   └── static/index.html          ← dashboard vanilla + Tailwind CDN
│
├── scripts/
│   ├── scan.py                    ← SAST 1: Semgrep → SQLite
│   ├── scan_sonarqube.py          ← SAST 2: SonarScanner + Web API → SQLite
│   ├── scan_zap.py                ← DAST: OWASP ZAP (docker | api | report) → SQLite
│   ├── triage_claude.py           ← IA: --online | --dump-prompts | --load-responses
│   ├── triage_IA.py               ← cópia idêntica do anterior
│   ├── screenshot.py              ← Playwright: dashboard PNG
│   └── screenshot_views.py        ← filtros LGPD/HIGH
│
├── semgrep-rules/
│   └── vanguard-custom.yml        ← 13 regras próprias (MD5, SQLi, XSS, cmd inj, ...)
│
├── targets/mini-app/              ← alvo vulnerável semeado
│   ├── server.js, package.json    ← servidor Express (para o DAST ter o que atacar)
│   ├── Dockerfile
│   ├── config/default.yml
│   ├── lib/{crypto.js,eval.js}
│   ├── routes/{admin.js,file.js,login.js,profile.js,search.js}
│   └── uploads/manual.txt
│
├── docs/
│   ├── MUDANCAS-v0.2.md           ← bugs corrigidos e integrações desta versão
│
├── reports/                       ← (gerado) saída bruta de Sonar e ZAP — no .gitignore
│
└── reference-run/                 ← execução ORIGINAL (v0.1, só Semgrep)
```

---

## 7. O que o alvo `mini-app/` contém (semeado propositalmente)

| Arquivo | Padrão | CWE | Semgrep (custom) | ZAP `--active` (execução de referência) |
|---|---|---|---|---|
| `lib/crypto.js` | MD5 para hash de senha | 327 | ✔ | — (não é visível de fora) |
| `lib/eval.js` | `eval()` e `new Function()` | 94, 95 | ✔ | — (não exposto em rota) |
| `routes/admin.js` | `child_process.exec` com input | 78 | ✔ | ✔ command injection (+ path traversal e XSS no mesmo endpoint) |
| `routes/admin.js` | `Math.random` p/ sessão, SHA1, token hardcoded | 338, 328, 798 | ✔ | — |
| `routes/file.js` | Path traversal via `path.join(req.params.file)` | 22 | ✔ | não detectado nesta rota |
| `routes/login.js` | Senha em `console.log`, JWT_SECRET hardcoded | 532, 798 | ✔ | — |
| `routes/profile.js` | XSS por concatenação, open redirect | 79, 601 | ✔ | ✔ XSS refletido, ✔ open redirect |
| `routes/search.js` | SQL injection por concatenação | 89 | ✔ | ✔ SQL injection (SQLite) |
| `config/default.yml` | Chave API embutida em YAML | 798 | ✔ (2 chaves) | — |

O SonarQube (Community) cobre boa parte desses pontos como Security
Hotspots (SQL, `exec`, `eval`, hash fraco, `Math.random`, credenciais); o
resultado exato depende da versão do SonarJS instalada no seu servidor.

`server.js` junta as rotas e serve uma página inicial com links e
formulários — é por ela que o spider do ZAP descobre os parâmetros. A tabela
`products` é criada **no fim** de `routes/search.js`, para não mudar as
linhas que o SAST aponta.

Nenhum código é de produção. Serve pra exercitar achados variados de SAST
e DAST e gerar um dashboard visualmente completo.

---

## 8. Segurança operacional

1. **Nunca versione `.env`.** O `.gitignore` bloqueia, mas revise `git status`
   antes de qualquer `git add -A`.
2. **Rotacione a chave Gemini / token do Sonar** se suspeitar que vazou (em
   log, screenshot, chat, PR). A chave Gemini agora vai no header
   `x-goog-api-key`, e não mais na URL — antes, qualquer erro de rede
   imprimia a chave inteira no traceback.
3. **`.env` com `chmod 600`** no macOS/Linux — só o dono lê.
4. **Não commite `vanguard.db` nem `reports/`** — podem conter trechos de
   código e URLs do alvo.
5. **O dashboard trata tudo do banco como não confiável** (mensagens de
   scanner, URLs, texto da IA): tudo é escapado antes de ir para a tela.

---

## 9. Troubleshooting

| Sintoma | Causa provável | Fix |
|---|---|---|
| `[scan] Alvo não encontrado` | rodou de fora da raiz do pacote | `cd` para a pasta com `README.md` |
| Semgrep retorna 0 achados | sem rede pro Registry | use só `--config semgrep-rules/vanguard-custom.yml` (dá 15) |
| `SonarQube não respondeu` | container ainda subindo | `docker compose logs -f sonarqube`; espere "SonarQube is operational" |
| `SonarQube respondeu 401` / `Token inválido` | token errado ou de análise | gere um **User Token** e atualize `SONAR_TOKEN` |
| SonarQube reinicia em loop (Linux) | limite do Elasticsearch | `sudo sysctl -w vm.max_map_count=262144` |
| Sonar: `vulnerabilidades: 0` | normal na Community | os achados vêm como hotspots (veja 3.2) |
| ZAP: `Relatório não encontrado ou vazio` | ZAP não alcançou o alvo | confira http://localhost:3000; veja o log do ZAP acima do erro |
| ZAP só acha headers (MEDIUM/LOW) | rodou baseline | use `--active` |
| `O ZAP recusou a conexão` (modo api) | chave da API errada | `ZAP_API_KEY` = valor em Tools > Options > API |
| `HTTP 401 UNAUTHENTICATED` no Gemini | chave inválida/rotacionada | gere nova e atualize `.env` |
| `HTTP 404 model not found` | modelo aposentado | ajuste `GEMINI_MODEL` no `.env` |
| `[triage] Nenhum achado pendente` | já triou tudo | `python scripts/triage_claude.py --online --reset` |
| Rate limit 429 no Gemini | free tier atingido | lote fica pendente; rode de novo depois ou suba `SLEEP_BETWEEN_BATCHES` |
| Dashboard em branco | `main.py` startup falhou | veja terminal do uvicorn |

---

## 10. Diferenças esperadas ao replicar

- **`reference-run/`** é da versão anterior (só Semgrep, com regras que
  tinham falso positivo). Serve de referência de **formato**, não de
  contagem.
- **`reference-run/sonar-issues.json` é um exemplo sintético**, não uma
  saída real do SonarQube: as linhas não batem com os arquivos (ex.:
  `config/default.yml:12`, mas o arquivo tem 11 linhas) e algumas regras não
  correspondem ao problema descrito (S5144 é SSRF, S5332 é protocolo em
  texto claro). Para apresentar, gere um relatório real com o passo 3.2.
- **IDs numéricos** mudam se você apagar o banco e rodar de novo.
- **`ai_triage`, `ai_explanation`, `ai_fix`** diferem a cada chamada (LLM não
  é determinístico mesmo com `temperature=0.2`).
- **SonarQube e ZAP** evoluem as regras a cada versão; espere ±1-2 achados.

O que **deve** ser reprodutível:
- Os três scanners rodam e gravam sem duplicar em reexecuções.
- Semgrep só com regras custom: exatamente 15 achados.
- Dashboard responde 200 em todos os endpoints.

---

## Desenvolvido por:
Victor Cassamassimo da Silva - 572852
Pedro Bezerra Cardoso - 567119
Nicolas Schultais Gouvea - 573863

---

## 11. Créditos

- **Semgrep** — SAST (open source)
- **SonarQube Community Build** — SAST (SonarSource)
- **OWASP ZAP** — DAST (open source)
- **Google Gemini** — LLM de triagem
- **FastAPI + Uvicorn** — servidor web
- **Playwright** — captura de screenshot (opcional)
- **Vanguard** — grupo FIAP 2026 (Challenge Pride Security)

Livre pra estudar, adaptar, distribuir dentro do escopo do challenge.
