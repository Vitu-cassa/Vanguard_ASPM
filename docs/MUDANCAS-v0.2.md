# Vanguard ASPM — mudanças da v0.2

Revisão de código da v0.1 + integração real de **SonarQube** (SAST) e
**OWASP ZAP** (DAST). Cada item diz o que estava errado, o efeito prático e
o que foi feito.

---

## 1. Bugs corrigidos

### Segurança (o ASPM tinha as próprias falhas)

| # | Onde | Problema | Efeito | Correção |
|---|---|---|---|---|
| 1 | `app/static/index.html` | Todo dado do banco ia para `innerHTML` sem escapar (mensagem do scanner, caminho, regra, texto da IA). | **XSS armazenado no dashboard.** O Semgrep interpola trechos do código escaneado nas mensagens, o ZAP reflete conteúdo do site atacado e a IA pode sofrer prompt injection — qualquer um deles vira script rodando no navegador de quem abre o dashboard. | Função `esc()` aplicada a todo valor. Testado com `<img src=x onerror=alert(1)>` no texto da IA: aparece como texto, nenhum `alert` dispara. |
| 2 | `scripts/triage_*.py` | Chave do Gemini ia na URL (`?key=...`). | Em qualquer erro de rede (timeout, DNS, proxy) o `requests` imprime a URL no traceback — **a chave aparecia inteira no terminal** (e nos logs salvos como evidência). Reproduzido: `url: /v1beta/models/...:generateContent?key=AIza...`. | Chave vai no header `x-goog-api-key`; erros de rede tratados sem imprimir a URL. |
| 3 | raiz | `.gitignore` e `.env.example` citados no README não existiam no pacote. | Nada impedia `git add -A` de versionar `.env` e `vanguard.db`. | Criados (incluindo `reports/`, `node_modules/`). |

### Regras Semgrep (`semgrep-rules/vanguard-custom.yml`)

Rodando só as regras custom contra o mini-app, a v0.1 dava 12 achados, dos
quais **4 eram falsos positivos/duplicatas** e **4 regras nunca disparavam**:

| Regra | Problema | Correção |
|---|---|---|
| `sql-string-concat` | `pattern-inside: $DB.$METHOD(...)` casa com `router.get(...)`, então pegava **qualquer** concatenação dentro de uma rota: marcava `exec("ls -la " + cmd)` e o HTML do perfil como SQL injection, e o SQL real 2×. | Só dispara se o literal começa com comando SQL (`metavariable-regex`). |
| `xss-html-concat` | `'"<...>" + $X'` não é sintaxe válida para "string com tag" — **nunca disparava**. | Captura o literal em `$HTML` e filtra por regex `<tag`. |
| `open-redirect` | Só casava `res.redirect(req.query.x)` direto; o código usa variável intermediária — **nunca disparava**. | Modo taint (segue `req.query/params/body` até o redirect). |
| `hardcoded-admin-token` | Regex em bloco `\|` do YAML termina com `\n`, mas a linha termina em `;` — **nunca disparava**. Também não cobria `JWT_SECRET`. | Regex em uma linha, cobrindo `*TOKEN*`, `*SECRET*`, `*API_KEY*`, `*PASSWORD*`. Renomeada para `hardcoded-secret`. |
| `hardcoded-api-key-in-yaml` | Mesmo problema do `\n` — **nunca disparava**. | Regex em uma linha. |
| `sha1-in-security-context` | CWE-330 (aleatoriedade fraca) não descreve SHA1. | CWE-328 (hash fraco). |
| (nova) `path-traversal` | O README listava path traversal em `file.js`, mas nenhuma regra custom cobria. | Regra taint `req.*` → `path.join`/`res.sendFile`. |

Resultado: **15 achados, 13 regras, um por vulnerabilidade semeada, zero
falso positivo.**

### Pipeline

| # | Onde | Problema | Correção |
|---|---|---|---|
| 4 | `scan.py` e demais | Rodar o scan de novo **duplicava todos os achados** (o próprio README avisava). Os números do dashboard inflavam a cada execução. | Coluna `fingerprint` (hash de scanner+regra+local) com índice único; reexecução ignora o que já existe e **preserva a triagem de IA**. Bancos antigos ganham a coluna automaticamente. |
| 5 | `scan.py` | Alvo padrão `targets/juice-shop` (não existe no pacote); mensagem final mandava rodar `scripts/triage.py --fake`, que não existe. | Padrão `targets/mini-app`; mensagens apontam para `triage_claude.py`. |
| 6 | `scan.py` | Semgrep recente pode emitir severidade `CRITICAL/HIGH/MEDIUM/LOW`; o mapa só conhecia `ERROR/WARNING/INFO` → tudo virava `UNKNOWN`. Erros de parsing do Semgrep eram ignorados em silêncio. | Mapa ampliado; erros do Semgrep são exibidos. |
| 7 | `triage_*.py` | Só `HTTPError` era tratado: timeout/DNS/resposta sem `candidates` derrubava o script no meio. Em erro HTTP, o lote era gravado como `revisar` com texto de falha (parecia triado). Rótulo da IA não era validado. Limite padrão de 30 deixava achados sem triagem sem avisar. | Todos os erros tratados; lote com falha continua `pendente` para a próxima execução; rótulo fora do combinado vira `revisar`; limite 100 e aviso de quantos faltam. |
| 8 | `app/main.py` | `@app.on_event("startup")` está deprecated no FastAPI. | `lifespan`. |
| 9 | `screenshot.py` | Clicava em `tr[data-id='1']`, que pode não existir. | Clica na primeira linha. |

`scripts/triage_IA.py` era cópia idêntica de `triage_claude.py`; recebeu as
mesmas correções. Vale apagar um dos dois.

---

## 2. Integração SonarQube (`scripts/scan_sonarqube.py`)

**Como estava:** lia `reference-run/sonar-issues.json`, que é um arquivo
escrito à mão (linhas inexistentes nos arquivos, regras que não
correspondem à descrição). A tentativa anterior (`.bak`, removido) usava
`sonar.scanner.dumpToFile`, que grava as *propriedades* do scanner, não os
achados — desde o SonarQube 7 não existe exportação local de issues — e
apontava para `localhost:9000` de dentro do container (que é o próprio
container).

**Como ficou:**
1. confere servidor (`/api/system/status`) e token (`/api/authentication/validate`);
2. roda o SonarScanner (binário local ou `sonarsource/sonar-scanner-cli`),
   com o token por variável de ambiente e o código montado só-leitura;
3. pega o id da análise no log e espera o Compute Engine (`/api/ce/task`);
4. baixa vulnerabilidades (`/api/issues/search`) **e Security Hotspots**
   (`/api/hotspots/search`), com paginação;
5. mapeia CWE por regra (tabela `RULE_CWE`), categoria do hotspot ou tag.

Detecta a versão do servidor: usa `components`/`project` no 10.2+ e
`componentKeys`/`projectKey` no 9.9 LTS. Salva a resposta bruta em
`reports/sonarqube/` e aceita `--report` para reimportar.

## 3. Integração OWASP ZAP (`scripts/scan_zap.py`)

**Como estava:** o alvo `mini-app` não tinha servidor (só módulos de rota),
então não havia o que o ZAP atacar. O parser lia `alert["description"]`,
mas o relatório do ZAP usa `desc` — **a mensagem de todo achado ficava
vazia**. Código de saída 1 (= "achou FAIL") era tratado como erro; `-v` com
caminho relativo quebra no Docker; alertas informativos entravam como LOW.

**Como ficou:**
- `targets/mini-app/server.js` + `package.json` + `Dockerfile`: o alvo roda
  de verdade (só em `127.0.0.1`), com página inicial para o spider.
- Três modos: `docker` (baseline ou full scan com `--active`), `api` (ZAP
  Desktop/daemon já aberto) e `--report` (importar JSON).
- `localhost` resolvido para dentro do container (`--network host` no Linux,
  `host.docker.internal` no Mac/Windows, com as URLs revertidas no banco).
- HTML removido das descrições; achado de ataque = 1 por endpoint, achado
  passivo = 1 por tipo com lista de URLs; parâmetro/ataque/evidência vão na
  mensagem (ajuda a triagem da IA).

## 4. Dashboard e API

- Coluna e filtro **Scanner**; card Total mostra a divisão por scanner.
- `/api/findings?scanner=...` e `by_scanner` em `/api/stats`.
- Local mostra URL para DAST (sem o `:0` de linha).

---

## 5. Como foi testado

| Parte | Teste |
|---|---|
| Regras Semgrep | Semgrep 1.178 contra o mini-app: 15 achados, 13 regras, sem FP. |
| Semgrep → banco | Rodado 2×: segunda execução insere 0. Banco no schema antigo migrado sem perda. |
| ZAP (modo api) | **ZAP 2.16.1 real**, scan ativo contra o mini-app rodando: 12 achados (SQLi, XSS, command injection, open redirect confirmados). Chave errada e ZAP desligado testados. |
| ZAP (modo report) | Relatório "Traditional JSON" gerado pelo próprio ZAP (mesmo formato do `-J` do Docker): mesmos 12 achados. |
| ZAP (modo docker) | Comando e volume validados com um `docker` simulado (sem daemon Docker no ambiente de teste). |
| SonarQube | Contra uma **API simulada** que segue a Web API oficial (9.9 e 10.7), com um `sonar-scanner` simulado: token, id da análise, espera do Compute Engine, nomes de parâmetro por versão, paginação, hotspots. Não foi possível subir um SonarQube real no ambiente de teste — **vale rodar uma vez contra o servidor do `docker compose`**. |
| Triagem | Modo offline completo; online sem rede não vaza a chave e mantém pendente. |
| Dashboard | Playwright: 200 em todos os endpoints, filtro por scanner, payload XSS exibido como texto. |
