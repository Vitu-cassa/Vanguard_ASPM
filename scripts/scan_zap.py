"""
Sensor DAST: OWASP ZAP.

Ataca a aplicação RODANDO (não o código) e grava os alertas no vanguard.db,
no mesmo formato dos achados de Semgrep e SonarQube.

Três jeitos de usar:

  1) docker (padrão) — sobe o ZAP num container descartável:
       python scripts/scan_zap.py --target http://localhost:3000
       python scripts/scan_zap.py --target http://localhost:3000 --active

     Sem --active roda o "baseline" (spider + análise passiva, ~2 min):
     acha headers ausentes, cookies inseguros, vazamento de versão etc.
     Com --active roda o "full scan" (baseline + ataques): acha SQL
     injection, XSS, path traversal, command injection... Demora mais.

  2) api — usa um ZAP que já está aberto (ZAP Desktop ou `zap.sh -daemon`):
       python scripts/scan_zap.py --mode api --target http://localhost:3000 --active

  3) só importar um relatório JSON do ZAP gerado antes
     (ZAP Desktop: Report > Generate Report > "Traditional JSON Report"):
       python scripts/scan_zap.py --report caminho/zap-report.json

Configuração opcional no .env: ZAP_TARGET, ZAP_API_URL, ZAP_API_KEY.

ATENÇÃO: só escaneie aplicações suas ou com autorização por escrito.
O scan ativo envia payloads de ataque de verdade.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests
from dotenv import load_dotenv

# Garante acesso aos módulos do Vanguard
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

load_dotenv(os.path.join(ROOT, ".env"))

from app.ingest import print_db_summary, save_findings  # noqa: E402
from app.netutil import docker_reach_host  # noqa: E402

SCANNER = "owasp_zap"
DEFAULT_TARGET = os.getenv("ZAP_TARGET", "http://localhost:3000")
DEFAULT_OUT = os.path.join(ROOT, "reports", "zap", "zap-report.json")
DEFAULT_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

# riskcode do ZAP (0-3) -> severidade do Vanguard
ZAP_SEVERITY_MAP = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW"}

# A API do ZAP devolve texto; o relatório JSON usa códigos numéricos.
RISK_TEXT_TO_CODE = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
CONF_TEXT_TO_CODE = {
    "False Positive": 0, "Low": 1, "Medium": 2, "High": 3, "Confirmed": 4,
}

# --------------------------------------------------------------------------
# Utilitários
# --------------------------------------------------------------------------

def strip_html(text: str | None) -> str:
    """O ZAP manda descrição/solução em HTML (<p>...</p>). Vira texto puro."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", str(text))
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:60] or "alerta"


def url_without_query(uri: str) -> str:
    parts = urlsplit(uri or "")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def site_root(uri: str) -> str:
    parts = urlsplit(uri or "")
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def replace_netloc(uri: str, old: str, new: str) -> str:
    parts = urlsplit(uri or "")
    if parts.netloc != old:
        return uri
    return urlunsplit((parts.scheme, new, parts.path, parts.query, parts.fragment))


# --------------------------------------------------------------------------
# Modo 1: Docker (zap-baseline.py / zap-full-scan.py)
# --------------------------------------------------------------------------

def run_zap_docker(target: str, out_path: str, active: bool, image: str,
                   spider_minutes: int) -> tuple[str, str] | None:
    """Roda o ZAP em container e deixa o relatório JSON em out_path."""
    if not shutil.which("docker"):
        print("[scan_zap] Comando 'docker' não encontrado. Instale o Docker ou use "
              "--mode api com o ZAP Desktop aberto.")
        sys.exit(1)

    out_dir = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(out_path):
        os.remove(out_path)  # evita importar um relatório velho se o ZAP falhar
    if os.name == "posix":
        # O container roda como usuário "zap" (uid 1000). Se o seu usuário
        # tiver outro uid, ele não conseguiria gravar o relatório aqui.
        os.chmod(out_dir, 0o777)

    scan_target, net_args, rewrite = docker_reach_host(target)
    if rewrite:
        print(f"[scan_zap] {rewrite[1]} -> {rewrite[0]} (acesso ao host a partir do container)")
    script = "zap-full-scan.py" if active else "zap-baseline.py"
    cmd = [
        "docker", "run", "--rm", *net_args,
        # -v precisa de caminho ABSOLUTO; com relativo o Docker cria um volume.
        "-v", f"{out_dir}:/zap/wrk/:rw",
        image, script,
        "-t", scan_target,
        "-J", os.path.basename(out_path),
        "-m", str(spider_minutes),  # minutos máximos de spider
        "-I",                        # não trata WARN como falha
    ]
    kind = "FULL SCAN (ativo)" if active else "BASELINE (passivo)"
    print(f"[scan_zap] {kind} contra {scan_target}")
    print(f"[scan_zap] rodando: {' '.join(cmd)}")

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    assert process.stdout is not None
    for line in process.stdout:
        print(line, end="")  # logs do ZAP em tempo real
    process.wait()

    # Códigos do zap-baseline/full-scan: 0 ok, 1 há FAIL, 2 há WARN, 3 erro.
    # 1 e 2 significam "achou coisas" — não são erro de execução.
    if process.returncode not in (0, 1, 2):
        print(f"\n[scan_zap] ZAP terminou com erro (código {process.returncode}).")
    return rewrite


# --------------------------------------------------------------------------
# Modo 2: API de um ZAP já aberto
# --------------------------------------------------------------------------

class ZapApi:
    def __init__(self, base_url: str, api_key: str | None):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        # O ZAP é local: não passa por proxy corporativo/variáveis de ambiente.
        self.session.trust_env = False
        if api_key:
            self.session.headers["X-ZAP-API-Key"] = api_key

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        try:
            resp = self.session.get(f"{self.base}{path}", params=params, timeout=60)
        except requests.ConnectionError as e:
            # Com chave errada/ausente o ZAP simplesmente derruba a conexão
            # (resposta vazia) em vez de devolver 401.
            if "aborted" in str(e).lower() or "RemoteDisconnected" in str(e):
                self._bad_key()
            raise
        if resp.status_code >= 400 and "api_key" in resp.text.lower():
            self._bad_key()
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _bad_key() -> None:
        print("[scan_zap] O ZAP recusou a conexão: chave da API ausente ou errada.")
        print("           Confira ZAP_API_KEY no .env (ZAP Desktop: Tools > Options > API).")
        sys.exit(1)

    def wait(self, label: str, status_fn, timeout_s: int, stop_fn=None) -> None:
        start = time.time()
        last = None
        while True:
            pct = int(status_fn())
            if pct != last:
                print(f"[scan_zap] {label}: {pct}%")
                last = pct
            if pct >= 100:
                return
            if time.time() - start > timeout_s:
                print(f"[scan_zap] {label}: tempo limite atingido; parando e seguindo com o que já foi achado.")
                if stop_fn:
                    stop_fn()
                return
            time.sleep(2)


def run_zap_api(target: str, zap_url: str, api_key: str | None, active: bool,
                timeout_min: int) -> dict[str, Any]:
    zap = ZapApi(zap_url, api_key)
    try:
        version = zap.get("/JSON/core/view/version/")["version"]
    except requests.ConnectionError:
        print(f"[scan_zap] Não encontrei o ZAP em {zap_url}.")
        print("           Abra o ZAP Desktop (a API sobe junto, porta 8080) ou rode:")
        print("           zap.sh -daemon -port 8080 -config api.key=SUA_CHAVE")
        sys.exit(1)
    print(f"[scan_zap] conectado ao ZAP {version} em {zap_url}")

    zap.get("/JSON/core/action/accessUrl/", url=target, followRedirects="true")

    spider_id = zap.get("/JSON/spider/action/scan/", url=target, recurse="true")["scan"]
    zap.wait(
        "spider",
        lambda: zap.get("/JSON/spider/view/status/", scanId=spider_id)["status"],
        timeout_s=5 * 60,
        stop_fn=lambda: zap.get("/JSON/spider/action/stop/", scanId=spider_id),
    )

    if active:
        ascan_id = zap.get(
            "/JSON/ascan/action/scan/", url=target, recurse="true", inScopeOnly="false"
        )["scan"]
        zap.wait(
            "scan ativo",
            lambda: zap.get("/JSON/ascan/view/status/", scanId=ascan_id)["status"],
            timeout_s=timeout_min * 60,
            stop_fn=lambda: zap.get("/JSON/ascan/action/stop/", scanId=ascan_id),
        )

    # Espera o scanner passivo terminar de analisar as respostas.
    start = time.time()
    while int(zap.get("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) > 0:
        if time.time() - start > 120:
            break
        time.sleep(1)

    alerts: list[dict[str, Any]] = []
    page = 500
    while True:
        chunk = zap.get(
            "/JSON/core/view/alerts/", baseurl=target, start=len(alerts), count=page
        )["alerts"]
        alerts.extend(chunk)
        if len(chunk) < page:
            break
    print(f"[scan_zap] {len(alerts)} ocorrência(s) de alerta recebidas da API.")
    return api_alerts_to_report(alerts, target)


def api_alerts_to_report(alerts: list[dict[str, Any]], target: str) -> dict[str, Any]:
    """
    A API devolve uma linha por OCORRÊNCIA. Agrupa no mesmo formato do
    relatório "Traditional JSON" (um alerta com várias instâncias), para
    que os três modos usem o mesmo normalizador.
    """
    grouped: dict[tuple, dict[str, Any]] = {}
    for a in alerts:
        risk = RISK_TEXT_TO_CODE.get(a.get("risk", ""), 0)
        conf = CONF_TEXT_TO_CODE.get(a.get("confidence", ""), 2)
        ref = a.get("alertRef") or a.get("pluginId") or a.get("alert")
        key = (ref, risk, conf)
        if key not in grouped:
            grouped[key] = {
                "pluginid": a.get("pluginId", ""),
                "alertRef": ref,
                "alert": a.get("alert") or a.get("name", ""),
                "name": a.get("name") or a.get("alert", ""),
                "riskcode": str(risk),
                "confidence": str(conf),
                "desc": a.get("description", ""),
                "solution": a.get("solution", ""),
                "reference": a.get("reference", ""),
                "cweid": str(a.get("cweid", "-1")),
                "wascid": str(a.get("wascid", "-1")),
                "sourceid": str(a.get("sourceid", "")),
                "instances": [],
            }
        grouped[key]["instances"].append(
            {
                "uri": a.get("url", ""),
                "method": a.get("method", ""),
                "param": a.get("param", ""),
                "attack": a.get("attack", ""),
                "evidence": a.get("evidence", ""),
                "otherinfo": a.get("other", ""),
            }
        )
    for g in grouped.values():
        g["count"] = str(len(g["instances"]))
    return {
        "@programName": "ZAP",
        "@generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "site": [{"@name": site_root(target), "alerts": list(grouped.values())}],
    }


# --------------------------------------------------------------------------
# Normalização: relatório Traditional JSON -> achados do Vanguard
# --------------------------------------------------------------------------

def _shorten(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _describe_instances(instances: list[dict[str, Any]], limit: int = 5) -> str:
    lines = []
    for inst in instances[:limit]:
        bits = [f"{inst.get('method') or 'GET'} {inst.get('uri', '')}"]
        if inst.get("param"):
            bits.append(f"parâmetro: {inst['param']}")
        if inst.get("attack"):
            bits.append(f"ataque: {str(inst['attack'])[:120]}")
        if inst.get("evidence"):
            bits.append(f"evidência: {str(inst['evidence'])[:120]}")
        lines.append("- " + " · ".join(bits))
    if len(instances) > limit:
        lines.append(f"- (+{len(instances) - limit} ocorrência(s))")
    return "\n".join(lines)


def normalize_report(report: dict[str, Any], include_info: bool = False,
                     rewrite: tuple[str, str] | None = None) -> tuple[list[dict[str, Any]], int]:
    """
    Converte o relatório do ZAP em achados. Regra de agrupamento:
      - alertas de ATAQUE (scan ativo: SQLi, XSS...) -> um achado por endpoint;
      - alertas PASSIVOS (headers, cookies...)      -> um achado por tipo de
        alerta no site, listando as URLs afetadas (senão um header ausente
        em 50 páginas viraria 50 linhas no dashboard).
    Devolve (achados, quantidade_ignorada_por_ser_informativa).
    """
    sites = report.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]

    findings: list[dict[str, Any]] = []
    skipped_info = 0
    for site in sites:
        site_name = site.get("@name", "")
        for alert in site.get("alerts") or []:
            try:
                riskcode = int(alert.get("riskcode", 0))
            except (TypeError, ValueError):
                riskcode = 0
            if str(alert.get("confidence", "")) == "0":
                continue  # marcado como falso positivo no próprio ZAP
            if riskcode == 0 and not include_info:
                skipped_info += 1
                continue

            name = alert.get("name") or alert.get("alert") or "Alerta ZAP"
            ref = alert.get("alertRef") or alert.get("pluginid") or slug(name)
            rule_id = f"zap-{ref}.{slug(name)}"
            desc = strip_html(alert.get("desc"))
            solution = strip_html(alert.get("solution"))

            instances = list(alert.get("instances") or [])
            if rewrite:
                for inst in instances:
                    inst["uri"] = replace_netloc(inst.get("uri", ""), *rewrite)
                site_name = replace_netloc(site_name, *rewrite)
            instances.sort(key=lambda i: (i.get("uri", ""), i.get("param", "")))

            if any(i.get("attack") for i in instances):
                groups: dict[str, list[dict[str, Any]]] = {}
                for inst in instances:
                    groups.setdefault(url_without_query(inst.get("uri", "")), []).append(inst)
            else:
                root = site_name or (site_root(instances[0].get("uri", "")) if instances else "")
                groups = {root: instances}

            for location, insts in groups.items():
                # O que importa para triagem vem primeiro (onde + como foi
                # explorado); a descrição genérica do ZAP é longa e vai cortada.
                parts = [f"{name}."]
                if insts:
                    parts.append(f"Ocorrências ({len(insts)}):\n{_describe_instances(insts)}\n")
                parts.append(_shorten(desc, 500))
                if solution:
                    parts.append(f"\nCorreção sugerida pelo ZAP: {_shorten(solution, 400)}")
                findings.append(
                    {
                        "rule_id": rule_id,
                        "severity": ZAP_SEVERITY_MAP.get(riskcode, "LOW"),
                        "file_path": location,
                        "line": 0,  # DAST não tem linha de código
                        "message": " ".join(p for p in parts if p)[:2000],
                        "cwe": alert.get("cweid"),
                    }
                )
    return findings, skipped_info


def load_report(path: str) -> dict[str, Any] | None:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        print(f"[scan_zap] Relatório não encontrado ou vazio: {path}")
        return None
    with open(path, "r", encoding="utf-8") as fh:
        try:
            return json.load(fh)
        except json.JSONDecodeError:
            print(f"[scan_zap] {path} não é um JSON válido (use o 'Traditional JSON Report').")
            return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Vanguard - Sensor DAST OWASP ZAP")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                        help=f"URL da aplicação rodando (padrão: {DEFAULT_TARGET})")
    parser.add_argument("--mode", choices=["docker", "api"], default="docker",
                        help="docker: sobe o ZAP em container | api: usa um ZAP já aberto")
    parser.add_argument("--active", action="store_true",
                        help="inclui scan ativo (ataques). Mais lento e intrusivo.")
    parser.add_argument("--report", default=None,
                        help="só importa um relatório JSON existente (não roda o ZAP)")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="onde salvar o relatório bruto do scan")
    parser.add_argument("--include-info", action="store_true",
                        help="grava também alertas informativos (risco 0)")
    parser.add_argument("--zap-url", default=os.getenv("ZAP_API_URL", "http://127.0.0.1:8080"),
                        help="(modo api) endereço da API do ZAP")
    parser.add_argument("--api-key", default=os.getenv("ZAP_API_KEY") or None,
                        help="(modo api) chave da API do ZAP")
    parser.add_argument("--timeout", type=int, default=15,
                        help="(modo api) minutos máximos de scan ativo (padrão 15)")
    parser.add_argument("--spider-minutes", type=int, default=2,
                        help="(modo docker) minutos máximos de spider (padrão 2)")
    parser.add_argument("--image", default=DEFAULT_IMAGE,
                        help=f"(modo docker) imagem do ZAP (padrão {DEFAULT_IMAGE})")
    args = parser.parse_args()

    print("\n=== Vanguard - Sensor OWASP ZAP ===")
    rewrite = None
    if args.report:
        report = load_report(args.report)
    elif args.mode == "docker":
        rewrite = run_zap_docker(args.target, args.out, args.active, args.image,
                                 args.spider_minutes)
        report = load_report(args.out)
    else:
        report = run_zap_api(args.target, args.zap_url, args.api_key, args.active,
                             args.timeout)
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"[scan_zap] relatório bruto salvo em {args.out}")

    if report is None:
        sys.exit(1)

    findings, skipped_info = normalize_report(report, args.include_info, rewrite)
    inserted, skipped = save_findings(SCANNER, findings)

    print("\n=== Vanguard - Scan ZAP concluído ===")
    print(f"Novos achados inseridos (OWASP ZAP): {inserted}")
    if skipped:
        print(f"Já existentes (ignorados)        : {skipped}")
    if skipped_info:
        print(f"Alertas informativos descartados : {skipped_info} (use --include-info para gravar)")
    print_db_summary(SCANNER)


if __name__ == "__main__":
    main()
