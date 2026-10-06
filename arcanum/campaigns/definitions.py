"""Adaptive campaign catalog (Phase 2).

Each campaign is ``{key, icon, title, desc, steps}``. A step is::

    {
      "id":    short id,
      "title": plain-language label (what the operator sees),
      "why":   one-line rationale,
      "cmd":   command template using {host}/{base}/{url} placeholders,
      "when":  context predicate key (None => always run),  # adaptive gate
      "parse": parser key applied to stdout (None => no parsing),
      "intrusive": bool,   # needs approval on a non-auto engagement
    }

Placeholders (resolved by :meth:`CampaignRunner.render`):
  * ``{host}`` bare domain/host (no scheme, no port)  -> subfinder, nmap, wpscan host
  * ``{base}`` host[:port] (no scheme)                -> httpx target
  * ``{url}``  http(s)://host[:port]                  -> nuclei/katana/feroxbuster/...

Context keys set by parsers and consumed by ``when``:
  * ``has_web``      a live HTTP service answered
  * ``is_wordpress`` the stack fingerprinted as WordPress
  * ``has_graphql``  a /graphql endpoint was crawled

All tool flags verified against the Kali sandbox image (nuclei ``-jsonl``,
httpx-toolkit ``-j -td -sc``, katana ``-jc``, gowitness v3 ``scan single -u``).
"""
from __future__ import annotations


SMART_RECON = {
    "key": "smart_recon",
    "icon": "🗺️",
    "title": "Recon inteligente",
    "desc": "Descobre ativos, resolve hosts vivos e fingerprinta a stack. Só observa — base para decidir o resto.",
    "risk": "seguro",
    "steps": [
        {"id": "subs", "title": "Descobrir subdomínios", "why": "Amplia a superfície via OSINT, sem tocar no alvo.",
         "cmd": "subfinder -d {host} -silent"},
        {"id": "httpx", "title": "Achar web vivo + tecnologias", "why": "Quais hosts respondem e qual a stack (decide os próximos passos).",
         "cmd": "subfinder -d {host} -silent | dnsx -silent | httpx-toolkit -silent -td -sc -title -j", "parse": "httpx_json"},
        {"id": "shot", "title": "Screenshot do alvo", "why": "Triagem visual rápida.",
         "cmd": "gowitness scan single -u {url}", "when": "has_web"},
    ],
}

SMART_WEB = {
    "key": "smart_web",
    "icon": "🧠",
    "title": "Varredura inteligente (web)",
    "desc": "Faz recon, entende a stack e decide sozinho os próximos testes (WordPress→wpscan, GraphQL→graphqlmap) e cria findings das falhas achadas.",
    "risk": "intrusivo",
    "steps": [
        {"id": "httpx", "title": "Identificar web + tecnologias", "why": "Confirma web vivo e a stack para ramificar.",
         "cmd": "httpx-toolkit -u {base} -silent -td -sc -title -j", "parse": "httpx_json"},
        {"id": "nuclei", "title": "Falhas conhecidas (frutos fáceis)", "why": "CVEs, exposições e desconfigurações — viram findings automáticos.",
         "cmd": "nuclei -u {url} -jsonl -severity critical,high,medium,low -rl 50 -c 10 -tags cve,exposure,misconfiguration",
         "when": "has_web", "parse": "nuclei_jsonl"},
        {"id": "katana", "title": "Mapear endpoints", "why": "Descobre rotas/parâmetros e detecta GraphQL/API.",
         "cmd": "katana -u {url} -d 2 -jc -silent", "when": "has_web", "parse": "katana_urls"},
        {"id": "ferox", "title": "Rotas e arquivos ocultos", "why": "admin, backups e APIs escondidas.",
         "cmd": "feroxbuster -u {url} -w /opt/seclists/Discovery/Web-Content/common.txt -q", "when": "has_web"},
        {"id": "wpscan", "title": "WordPress a fundo", "why": "A stack é WordPress — enumera usuários/plugins/temas (ativo).",
         "cmd": "wpscan --url {url} --enumerate u,vp,vt --random-user-agent", "when": "is_wordpress", "intrusive": True},
        {"id": "graphql", "title": "Testar GraphQL", "why": "Endpoint GraphQL detectado — introspecção/abuso (ativo).",
         "cmd": "graphqlmap -u {url}/graphql", "when": "has_graphql", "intrusive": True},
    ],
}

CAMPAIGNS = [SMART_RECON, SMART_WEB]


def get_campaign(key: str) -> dict | None:
    for c in CAMPAIGNS:
        if c["key"] == key:
            return c
    return None
