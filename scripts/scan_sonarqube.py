"""
Sensor SAST 2: SonarQube.

Fluxo completo (padrão):
  1. roda o SonarScanner no código do alvo (binário local ou container);
  2. espera o SonarQube processar a análise (Compute Engine);
  3. baixa, pela Web API, as VULNERABILIDADES e os SECURITY HOTSPOTS;
  4. normaliza e grava no vanguard.db (sem duplicar em execuções repetidas).

Por que hotspots? Na Community Edition quase todas as regras de segurança
de JavaScript (SQL montado com concatenação, hash fraco, Math.random,
exec de comando, eval, senha hardcoded...) são "Security Hotspots", que
NÃO aparecem em /api/issues/search. Só buscar issues traria quase nada.

Uso:
    python scripts/scan_sonarqube.py                          # scan + coleta
    python scripts/scan_sonarqube.py --skip-scan              # só coleta (projeto já analisado)
    python scripts/scan_sonarqube.py --report arquivo.json    # só importa um JSON salvo

Configuração (.env):
    SONAR_HOST_URL=http://localhost:9000
    SONAR_TOKEN=squ_xxx          # token de USUÁRIO (My Account > Security)
    SONAR_PROJECT_KEY=vanguard-mini-app
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any

import requests
from dotenv import load_dotenv

# Garante acesso aos módulos do Vanguard
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

load_dotenv(os.path.join(ROOT, ".env"))

from app.ingest import normalize_cwe, print_db_summary, save_findings  # noqa: E402
from app.netutil import docker_reach_host  # noqa: E402

SCANNER = "sonarqube"
DEFAULT_HOST = os.getenv("SONAR_HOST_URL", "http://localhost:9000")
DEFAULT_PROJECT = os.getenv("SONAR_PROJECT_KEY", "vanguard-mini-app")
DEFAULT_OUT = os.path.join(ROOT, "reports", "sonarqube", "sonar-findings.json")
SCANNER_IMAGE = "sonarsource/sonar-scanner-cli"

# Severidade "clássica" (até 10.x e no modo Standard Experience)
SONAR_SEVERITY_MAP = {
    "BLOCKER": "HIGH",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "LOW",
}
# Severidade de "impacto" (10.2+ / modo MQR)
IMPACT_SEVERITY_MAP = {
    "BLOCKER": "HIGH",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
}
_SEV_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# A Web API do SonarQube não devolve o número do CWE em cada achado.
# Tabela das regras de segurança mais comuns (o número "Sxxxx" é o mesmo
# para JS/TS/Java/Python...). Fonte: páginas das regras em rules.sonarsource.com.
RULE_CWE = {
    "S2077": "CWE-89",   # SQL montado dinamicamente (hotspot)
    "S3649": "CWE-89",   # SQL injection (taint)
    "S5131": "CWE-79",   # XSS (taint)
    "S5696": "CWE-79",   # XSS via DOM
    "S5247": "CWE-79",   # auto-escape desligado
    "S2083": "CWE-22",   # path injection
    "S6096": "CWE-22",   # zip slip
    "S5146": "CWE-601",  # open redirect
    "S2076": "CWE-78",   # OS command injection (taint)
    "S4721": "CWE-78",   # execução de comando do SO (hotspot)
    "S1523": "CWE-95",   # eval / código dinâmico
    "S5334": "CWE-94",   # code injection
    "S4790": "CWE-327",  # hash fraco (MD5/SHA1)
    "S5547": "CWE-327",  # cifra fraca
    "S2245": "CWE-338",  # PRNG não criptográfico (Math.random)
    "S2068": "CWE-798",  # senha hardcoded
    "S6418": "CWE-798",  # segredo hardcoded
    "S6437": "CWE-798",  # credencial hardcoded
    "S5332": "CWE-319",  # protocolo em texto claro (http://)
    "S4423": "CWE-326",  # TLS fraco
    "S4426": "CWE-326",  # chave criptográfica curta
    "S4830": "CWE-295",  # validação de certificado desligada
    "S5144": "CWE-918",  # SSRF
    "S2755": "CWE-611",  # XXE
    "S5145": "CWE-117",  # log injection
    "S5147": "CWE-943",  # NoSQL injection
    "S4502": "CWE-352",  # CSRF desativado
    "S5122": "CWE-346",  # CORS permissivo
    "S2092": "CWE-614",  # cookie sem Secure
    "S3330": "CWE-1004", # cookie sem HttpOnly
    "S5689": "CWE-200",  # X-Powered-By expõe tecnologia
    "S4507": "CWE-489",  # debug ativo em produção
    "S5852": "CWE-1333", # regex vulnerável a ReDoS
}

# Fallback para hotspots: /api/hotspots/search devolve a categoria.
CATEGORY_CWE = {
    "sql-injection": "CWE-89",
    "command-injection": "CWE-78",
    "path-traversal-injection": "CWE-22",
    "ldap-injection": "CWE-90",
    "xpath-injection": "CWE-643",
    "rce": "CWE-94",
    "dos": "CWE-400",
    "ssrf": "CWE-918",
    "csrf": "CWE-352",
    "xss": "CWE-79",
    "log-injection": "CWE-117",
    "http-response-splitting": "CWE-113",
    "open-redirect": "CWE-601",
    "xxe": "CWE-611",
    "object-injection": "CWE-502",
    "weak-cryptography": "CWE-327",
    "auth": "CWE-287",
    "insecure-conf": "CWE-16",
    "file-manipulation": "CWE-73",
    "encrypt-data": "CWE-311",
    "traceability": "CWE-778",
    "permission": "CWE-732",
}


# --------------------------------------------------------------------------
# Conversa com o servidor
# --------------------------------------------------------------------------

class Sonar:
    def __init__(self, host: str, token: str | None):
        self.host = host.rstrip("/")
        self.session = requests.Session()
        if token:
            # Token como usuário e senha vazia: funciona do 9.9 ao 2025.x.
            self.session.auth = (token, "")

    def get(self, path: str, **params: Any) -> requests.Response:
        return self.session.get(f"{self.host}{path}", params=params, timeout=60)

    def get_json(self, path: str, **params: Any) -> dict[str, Any]:
        resp = self.get(path, **params)
        if resp.status_code == 401:
            fail("SonarQube respondeu 401: token ausente ou inválido. Gere um token "
                 "de USUÁRIO em My Account > Security e coloque em SONAR_TOKEN no .env.")
        if resp.status_code == 403:
            fail(f"SonarQube respondeu 403 em {path}: o token não tem permissão "
                 "'Browse' no projeto (tokens de análise não servem para a Web API).")
        resp.raise_for_status()
        return resp.json()

    def check(self) -> tuple[int, int]:
        """Confere se o servidor está de pé e o token vale. Devolve a versão."""
        try:
            status = self.get("/api/system/status").json().get("status")
        except requests.RequestException:
            fail(f"SonarQube não respondeu em {self.host}.\n"
                 "           Suba com `docker compose up -d sonarqube` e aguarde 1-2 min.")
        if status != "UP":
            fail(f"SonarQube ainda não está pronto (status: {status}). Aguarde e tente de novo.")
        version_txt = self.get("/api/server/version").text.strip()
        nums = [int(n) for n in re.findall(r"\d+", version_txt)[:2]] + [0, 0]
        if not self.get_json("/api/authentication/validate").get("valid"):
            fail("Token do SonarQube inválido. Confira SONAR_TOKEN no .env.")
        print(f"[scan_sonarqube] conectado ao SonarQube {version_txt} em {self.host}")
        return nums[0], nums[1]


def fail(msg: str) -> None:
    print(f"[scan_sonarqube] {msg}")
    sys.exit(1)


# --------------------------------------------------------------------------
# 1. Rodar o SonarScanner
# --------------------------------------------------------------------------

TASK_RE = re.compile(r"api/ce/task\?id=([\w-]+)")


def run_scanner(target: str, host: str, token: str, project_key: str,
                how: str) -> str:
    """Executa o scanner e devolve o id da tarefa no Compute Engine."""
    target_abs = os.path.abspath(target)
    local_bin = shutil.which("sonar-scanner")
    if how == "auto":
        how = "local" if local_bin else "docker"
    common = [
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.projectName={project_key}",
        "-Dsonar.sources=.",
        "-Dsonar.exclusions=**/node_modules/**,**/uploads/**",
        "-Dsonar.sourceEncoding=UTF-8",
    ]
    env = dict(os.environ, SONAR_TOKEN=token)  # token por env, não na linha de comando

    if how == "local":
        if not local_bin:
            fail("'sonar-scanner' não está no PATH. Instale o SonarScanner CLI ou use --scanner docker.")
        cmd = [local_bin, f"-Dsonar.host.url={host}",
               f"-Dsonar.projectBaseDir={target_abs}", *common]
    else:
        if not shutil.which("docker"):
            fail("Nem 'sonar-scanner' nem 'docker' foram encontrados. Instale um dos dois.")
        host_in_container, net_args, _ = docker_reach_host(host)
        cmd = [
            "docker", "run", "--rm", *net_args,
            "-e", "SONAR_TOKEN",
            # Código montado só para leitura; o scanner trabalha em /tmp.
            "-v", f"{target_abs}:/usr/src:ro",
            SCANNER_IMAGE,
            f"-Dsonar.host.url={host_in_container}",
            "-Dsonar.working.directory=/tmp/.scannerwork",
            *common,
        ]

    print(f"[scan_sonarqube] rodando SonarScanner ({how}) em {target}")
    print(f"[scan_sonarqube] {' '.join(cmd)}")
    task_id = None
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", env=env,
    )
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="")
        m = TASK_RE.search(line)
        if m:
            task_id = m.group(1)
    process.wait()
    if process.returncode != 0:
        fail(f"SonarScanner terminou com erro (código {process.returncode}). Veja o log acima.")

    if not task_id:
        # Plano B: o scanner local grava o id em .scannerwork/report-task.txt
        report_task = os.path.join(target_abs, ".scannerwork", "report-task.txt")
        if os.path.exists(report_task):
            with open(report_task, encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("ceTaskId="):
                        task_id = line.split("=", 1)[1].strip()
    if not task_id:
        fail("Não consegui descobrir o id da análise no log do scanner.")
    return task_id


def wait_for_task(sonar: Sonar, task_id: str, timeout_s: int) -> None:
    """O SonarQube processa a análise em segundo plano; espera terminar."""
    start = time.time()
    status = None
    while time.time() - start < timeout_s:
        task = sonar.get_json("/api/ce/task", id=task_id).get("task", {})
        if task.get("status") != status:
            status = task.get("status")
            print(f"[scan_sonarqube] processamento da análise: {status}")
        if status == "SUCCESS":
            return
        if status in ("FAILED", "CANCELED"):
            fail(f"O SonarQube não conseguiu processar a análise ({status}): "
                 f"{task.get('errorMessage', 'sem detalhes')}")
        time.sleep(2)
    fail(f"Tempo esgotado ({timeout_s}s) esperando o SonarQube processar a análise.")


# --------------------------------------------------------------------------
# 2. Coletar achados
# --------------------------------------------------------------------------

def _paginate(sonar: Sonar, path: str, key: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    page = 1
    while True:
        data = sonar.get_json(path, p=page, ps=500, **params)
        batch = data.get(key, [])
        items.extend(batch)
        total = (data.get("paging") or {}).get("total", data.get("total", 0))
        # A API limita a 10.000 resultados (p * ps).
        if not batch or len(items) >= total or page * 500 >= 10000:
            return items
        page += 1


def fetch_issues(sonar: Sonar, project_key: str, version: tuple[int, int]) -> list[dict[str, Any]]:
    # 10.2 renomeou componentKeys -> components (o nome antigo sai nas versões novas).
    comp_param = "components" if version >= (10, 2) else "componentKeys"
    params = {comp_param: project_key, "resolved": "false", "types": "VULNERABILITY"}
    try:
        issues = _paginate(sonar, "/api/issues/search", "issues", params)
    except requests.HTTPError:
        # Versões futuras podem remover "types" (substituído por impactos).
        params.pop("types")
        issues = _paginate(sonar, "/api/issues/search", "issues", params)
    return [i for i in issues if is_security_issue(i)]


def is_security_issue(issue: dict[str, Any]) -> bool:
    if issue.get("type") == "VULNERABILITY":
        return True
    return any(i.get("softwareQuality") == "SECURITY" for i in issue.get("impacts") or [])


def fetch_hotspots(sonar: Sonar, project_key: str, version: tuple[int, int]) -> list[dict[str, Any]]:
    # 10.2 renomeou projectKey -> project
    proj_param = "project" if version >= (10, 2) else "projectKey"
    return _paginate(
        sonar, "/api/hotspots/search", "hotspots",
        {proj_param: project_key, "status": "TO_REVIEW"},
    )


# --------------------------------------------------------------------------
# 3. Normalizar
# --------------------------------------------------------------------------

def rule_cwe(rule_key: str | None) -> str | None:
    if not rule_key:
        return None
    return RULE_CWE.get(rule_key.split(":")[-1].upper())


def tags_cwe(tags: list[str] | None) -> str | None:
    for tag in tags or []:
        cwe = normalize_cwe(tag) if str(tag).lower().startswith("cwe") else None
        if cwe:
            return cwe
    return None


def component_path(component: str, project_key: str | None) -> str:
    """'meu-projeto:routes/search.js' -> 'routes/search.js'."""
    if project_key and component.startswith(project_key + ":"):
        return component[len(project_key) + 1:]
    return component.split(":", 1)[-1] if ":" in component else component


def issue_severity(issue: dict[str, Any]) -> str:
    impacts = issue.get("impacts") or []
    relevant = [i for i in impacts if i.get("softwareQuality") == "SECURITY"] or impacts
    mapped = [IMPACT_SEVERITY_MAP.get(str(i.get("severity", "")).upper()) for i in relevant]
    mapped = [m for m in mapped if m]
    if mapped:
        return max(mapped, key=lambda s: _SEV_ORDER[s])
    return SONAR_SEVERITY_MAP.get(str(issue.get("severity") or "MAJOR").upper(), "MEDIUM")


def normalize_issue(issue: dict[str, Any], project_key: str | None) -> dict[str, Any]:
    rule = issue.get("rule") or "sonar-rule"
    return {
        "rule_id": rule,
        "severity": issue_severity(issue),
        "file_path": component_path(issue.get("component", ""), project_key or issue.get("project")),
        "line": issue.get("line") or (issue.get("textRange") or {}).get("startLine") or 0,
        "message": (issue.get("message") or "").strip(),
        "cwe": rule_cwe(rule) or tags_cwe(issue.get("tags")),
    }


def normalize_hotspot(h: dict[str, Any], project_key: str | None) -> dict[str, Any]:
    category = h.get("securityCategory") or "others"
    rule = h.get("ruleKey") or f"hotspot:{category}"
    prob = str(h.get("vulnerabilityProbability") or "MEDIUM").upper()
    return {
        "rule_id": rule,
        "severity": prob if prob in _SEV_ORDER else "MEDIUM",
        "file_path": component_path(h.get("component", ""), project_key or h.get("project")),
        "line": h.get("line") or (h.get("textRange") or {}).get("startLine") or 0,
        # Hotspot = "código sensível que precisa de revisão humana".
        "message": f"[Security Hotspot · {category}] {(h.get('message') or '').strip()}",
        "cwe": rule_cwe(rule) or CATEGORY_CWE.get(category),
    }


def normalize_all(issues: list[dict[str, Any]], hotspots: list[dict[str, Any]],
                  project_key: str | None) -> list[dict[str, Any]]:
    return ([normalize_issue(i, project_key) for i in issues]
            + [normalize_hotspot(h, project_key) for h in hotspots])


def load_report(path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Aceita a resposta de /api/issues/search, de /api/hotspots/search ou o
    arquivo que este script salva (com as duas chaves)."""
    if not os.path.exists(path):
        fail(f"Relatório não encontrado: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data, []
    return data.get("issues", []), data.get("hotspots", [])


def main() -> None:
    parser = argparse.ArgumentParser(description="Vanguard - Sensor SonarQube (SAST)")
    parser.add_argument("--target", default=os.path.join("targets", "mini-app"),
                        help="pasta com o código a analisar (padrão: targets/mini-app)")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"URL do SonarQube (padrão {DEFAULT_HOST})")
    parser.add_argument("--project-key", default=DEFAULT_PROJECT,
                        help=f"chave do projeto no SonarQube (padrão {DEFAULT_PROJECT})")
    parser.add_argument("--scanner", choices=["auto", "local", "docker"], default="auto",
                        help="auto: usa sonar-scanner do PATH se houver, senão Docker")
    parser.add_argument("--skip-scan", action="store_true",
                        help="não roda o scanner; só baixa os achados do projeto")
    parser.add_argument("--report", default=None,
                        help="só importa um JSON salvo (não fala com o servidor)")
    parser.add_argument("--no-hotspots", action="store_true",
                        help="ignora Security Hotspots (só vulnerabilidades)")
    parser.add_argument("--timeout", type=int, default=300,
                        help="segundos máximos esperando o SonarQube processar (padrão 300)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="onde salvar o JSON bruto coletado")
    args = parser.parse_args()

    print("\n=== Vanguard - Sensor SonarQube ===")
    if args.report:
        issues, hotspots = load_report(args.report)
        print(f"[scan_sonarqube] importando {args.report}")
        project_key = None  # usa o campo "project" de cada achado
    else:
        token = os.getenv("SONAR_TOKEN", "").strip()
        if not token:
            fail("SONAR_TOKEN ausente no .env (veja o README, seção SonarQube).")
        if not args.skip_scan and not os.path.isdir(args.target):
            fail(f"Alvo não encontrado: {args.target}")
        sonar = Sonar(args.host, token)
        version = sonar.check()
        if not args.skip_scan:
            task_id = run_scanner(args.target, args.host, token, args.project_key, args.scanner)
            wait_for_task(sonar, task_id, args.timeout)
        issues = fetch_issues(sonar, args.project_key, version)
        hotspots = [] if args.no_hotspots else fetch_hotspots(sonar, args.project_key, version)
        project_key = args.project_key

        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"issues": issues, "hotspots": hotspots}, fh, ensure_ascii=False, indent=2)
        print(f"[scan_sonarqube] resposta bruta salva em {args.out}")

    if args.no_hotspots:
        hotspots = []
    print(f"[scan_sonarqube] vulnerabilidades: {len(issues)} · security hotspots: {len(hotspots)}")
    inserted, skipped = save_findings(SCANNER, normalize_all(issues, hotspots, project_key))

    print("\n=== Vanguard - Scan SonarQube concluído ===")
    print(f"Novos achados inseridos (SonarQube): {inserted}")
    if skipped:
        print(f"Já existentes (ignorados)         : {skipped}")
    print_db_summary(SCANNER)


if __name__ == "__main__":
    main()
