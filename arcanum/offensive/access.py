"""F1 — initial access / structured red team (non-destructive base).

Three governed capabilities (roadmap §11 F1). None contains an exploit; they
orchestrate established tools in the sandbox and record real state:

* :func:`map_service_to_exploits` (ACTIVE) — ``nmap -sV`` → parse services → query
  the local CVE KB for candidate CVEs. Pure correlation, no attack.
* :func:`exploit_webapp` (EXPLOIT, dual approval) — **delegates** access confirmation
  to an operator-chosen established tool (a Metasploit module, a nuclei template, or
  a raw command); on a real session it registers a foothold + proof, on a confirmed
  vuln it records proof only. The exploit is the tool's; this is governance + proof.
* ``capture_proof`` lives in :mod:`.proof`.
"""
from __future__ import annotations

import re
import shlex

from .base import OffensiveContext
from .proof import build_proof, detect_access

# nmap -sV service line: "80/tcp open  http    Apache httpd 2.4.49 ((Unix))"
_SVC_RX = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$")
_VER_RX = re.compile(r"(\d+\.[\w.\-]+)")


def _parse_services(nmap_output: str) -> list[dict]:
    services: list[dict] = []
    for line in (nmap_output or "").splitlines():
        m = _SVC_RX.match(line.strip())
        if not m:
            continue
        port, proto, service, rest = m.groups()
        rest = (rest or "").strip()
        vm = _VER_RX.search(rest)
        services.append({
            "port": int(port), "proto": proto, "service": service,
            "product": rest, "version": vm.group(1) if vm else "",
        })
    return services


async def map_service_to_exploits(ctx: OffensiveContext, target: str,
                                  nmap_output: str | None = None, do_scan: bool = True,
                                  cve_limit: int = 5) -> dict:
    """Correlate services on ``target`` to candidate CVEs (ACTIVE — no attack).

    Runs ``nmap -sV`` in the sandbox (or uses supplied ``nmap_output``), parses the
    services, and queries the local CVE KB per service. Feeds the graph. The CVEs are
    hypotheses to validate — mapping is not exploitation.
    """
    if not target:
        return {"error": "Parâmetro 'target' obrigatório."}
    if nmap_output is None and do_scan:
        if not ctx.has_sandbox():
            return {"error": "Sandbox indisponível — forneça 'nmap_output' ou habilite o sandbox autorizado."}
        res = await ctx.delegate(f"nmap -sV -Pn -T4 {shlex.quote(target)}", timeout=300)
        nmap_output = res.get("stdout", "")

    services = _parse_services(nmap_output or "")
    cve_kb = ctx.cve_kb
    for svc in services:
        query = f"{svc['product']}".strip() or svc["service"]
        svc["cve_candidates"] = []
        if cve_kb and query:
            try:
                results = await cve_kb.search(query, limit=cve_limit)
                svc["cve_candidates"] = [
                    {"id": r.id, "cvss": getattr(r, "cvss_score", None),
                     "desc": (getattr(r, "description", "") or "")[:160]}
                    for r in results
                ]
            except Exception:
                pass

    if nmap_output and ctx.graph is not None:
        try:
            await ctx.graph.ingest_text(ctx.session_id, nmap_output)
        except Exception:
            pass

    return {
        "target": target,
        "services": services,
        "service_count": len(services),
        "note": ("Correlação recon→CVE (classe ACTIVE, nenhum ataque). Os CVEs são "
                 "candidatos a validar — mapear não é explorar."),
    }


def _build_delegation(method: str, target: str, command: str | None,
                      module: str | None, options: dict | None) -> tuple[str | None, str]:
    """Build the delegated command from an OPERATOR-supplied spec. No exploit/payload
    is synthesized here — the module/template/command is chosen by the operator and the
    technique lives entirely in the established tool."""
    method = (method or "command").lower()
    options = options or {}
    if method == "command":
        return (command or None, "operator-command")
    if method == "metasploit":
        if not module:
            return (None, "metasploit")
        lines = [f"use {module}"]
        if "RHOSTS" not in {str(k).upper() for k in options}:
            lines.append(f"set RHOSTS {target}")
        for k, v in options.items():
            lines.append(f"set {k} {v}")
        lines += ["set ExitOnSession true", "run -z", "exit"]
        script = "; ".join(lines)
        return (f"msfconsole -q -x {shlex.quote(script)}", "metasploit")
    if method == "nuclei":
        sel = ""
        if options.get("id"):
            sel = f"-id {shlex.quote(str(options['id']))}"
        elif options.get("template"):
            sel = f"-t {shlex.quote(str(options['template']))}"
        return (f"nuclei -u {shlex.quote(target)} {sel} -silent".strip(), "nuclei")
    return (None, method)


async def exploit_webapp(ctx: OffensiveContext, target: str, method: str = "command",
                         command: str | None = None, module: str | None = None,
                         options: dict | None = None,
                         teardown_recipe: list[str] | None = None) -> dict:
    """Confirm access against an authorized target by DELEGATING to an established
    tool (EXPLOIT — the engine already enforced ROE + dual approval before this runs).

    On a real session → register a foothold (+ teardown recipe) + proof + mark the
    host owned. On a confirmed vuln without a shell → proof only (honest: no foothold).
    Nothing runs without an authorized sandbox.
    """
    if not target:
        return {"error": "Parâmetro 'target' obrigatório (alvo do ROE).", "access_obtained": False}
    if not ctx.has_sandbox():
        return {"error": ("Sandbox indisponível — exploração real recusada por segurança. "
                          "Habilite o sandbox autorizado ('arcanum sandbox build')."),
                "access_obtained": False}

    cmd, tool = _build_delegation(method, target, command, module, options)
    if not cmd:
        return {"error": (f"method '{method}' exige os parâmetros adequados "
                          f"(command | module | nuclei id/template)."),
                "access_obtained": False}

    run = await ctx.delegate(cmd, timeout=600)
    output = ((run.get("stdout", "") or "") + "\n" + (run.get("stderr", "") or "")).strip()
    tag = f"ARCANUM-RT:{ctx.engagement_id or ctx.session_id or 'op'}:{target}"
    access = detect_access(output)

    if access is None:
        return {
            "access_obtained": False, "target": target, "tool": tool,
            "proof": build_proof("output", output, note="Sem sinal de acesso/vuln",
                                 deconfliction_tag=tag),
            "note": "A ferramenta delegada não confirmou acesso nem vulnerabilidade.",
        }

    if access["level"] == "session":
        foothold = await ctx.register_foothold(
            host=target, access_level="user", implant_type="shell",
            teardown_recipe=teardown_recipe,  # sessions have nothing persistent unless the operator says so
            metadata={"via": tool, "method": method, "signal": access["signal"],
                      "deconfliction_tag": tag})
        await ctx.mark_owned(target, owned="user",
                             foothold_id=(foothold or {}).get("id"))
        return {
            "access_obtained": True, "target": target, "tool": tool,
            "foothold": foothold, "access_signal": access,
            "proof": build_proof("shell", output,
                                 note=f"Acesso confirmado via {tool} ({access['signal']})",
                                 deconfliction_tag=tag),
            "note": "Foothold registrado com prova. Pós-exploração é F4 (gated).",
        }

    # vuln_confirmed — real evidence of exploitability, but NOT a shell ⇒ no foothold.
    return {
        "access_obtained": False, "vuln_confirmed": True, "target": target, "tool": tool,
        "access_signal": access,
        "proof": build_proof("vuln_confirmation", output,
                             note=f"Vulnerabilidade confirmada via {tool} ({access['signal']})",
                             deconfliction_tag=tag),
        "note": "Exploração confirmou a vulnerabilidade mas não resultou em sessão — sem foothold (honesto).",
    }
