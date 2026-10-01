"""
Utilitário usado pelos sensores que rodam ferramentas em container
(SonarScanner e OWASP ZAP).

Problema que resolve: dentro de um container, "localhost" é o próprio
container — não a sua máquina. Então uma URL como http://localhost:9000
(SonarQube) ou http://localhost:3000 (mini-app) não funciona lá dentro.
"""

from __future__ import annotations

import platform
from urllib.parse import urlsplit, urlunsplit

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def docker_reach_host(url: str) -> tuple[str, list[str], tuple[str, str] | None]:
    """
    Ajusta uma URL do host para ser acessível de dentro de um container:
      - Linux: usa --network host (o container enxerga o localhost do host);
      - macOS/Windows (Docker Desktop): troca o host por host.docker.internal.

    Devolve (url_para_o_container, args_extras_do_docker, troca) onde
    `troca` é (netloc_no_container, netloc_original) ou None — útil para
    desfazer a troca nas URLs que voltam nos relatórios.
    """
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if host in LOCAL_HOSTS:
        if platform.system() == "Linux":
            return url, ["--network", "host"], None
        new_netloc = "host.docker.internal" + (f":{parts.port}" if parts.port else "")
        new_url = urlunsplit(
            (parts.scheme, new_netloc, parts.path, parts.query, parts.fragment)
        )
        return new_url, [], (new_netloc, parts.netloc)
    if host == "host.docker.internal":
        return url, ["--add-host", "host.docker.internal:host-gateway"], None
    return url, [], None
