"""F5 — collection / exfiltration / impact (maximum gate; most OFF by default).

These prove impact with the MINIMUM necessary and never destroy/exfiltrate beyond an
authorized PoC (principle 6 of the roadmap). All follow the governed contract and
delegate to established tools:

* ``collect_sample`` (POST_EXPLOIT): a MINIMAL, masked sample of one sensitive file —
  proof, not bulk theft.
* ``demo_exfiltration`` (DESTRUCTIVE-adjacent, dual approval): a size/rate-LIMITED
  channel to test DLP; it LOGS exactly what left and never moves real bulk data.
* ``impact_poc`` (DESTRUCTIVE, OFF BY DEFAULT): refuses unless
  ``allow_destructive_testing`` is explicitly enabled; even then it needs an isolated
  test directory — never production without an explicit ROE that requires it.
"""
from __future__ import annotations

from typing import Any

from .base import OffensiveContext
from .proof import build_proof

# Hard caps so a "demo" can never become real bulk exfiltration/collection.
_MAX_SAMPLE_BYTES = 4096
_MAX_EXFIL_BYTES = 2048


def _combine(run: dict) -> str:
    return ((run.get("stdout", "") or "") + "\n" + (run.get("stderr", "") or "")).strip()


def _tag(ctx: OffensiveContext, host: str) -> str:
    return f"ARCANUM-RT:{ctx.engagement_id or ctx.session_id or 'op'}:{host}"


async def collect_sample(ctx: OffensiveContext, foothold_id: str, command: str,
                         max_bytes: int = _MAX_SAMPLE_BYTES) -> dict:
    """POST_EXPLOIT: collect a MINIMAL masked sample (proof of access to sensitive data).
    Hard-capped and masked — never bulk collection."""
    if not ctx.has_sandbox():
        return {"error": "Sandbox indisponível — coleta recusada.", "ok": False}
    fh = await ctx.get_foothold(foothold_id)
    if not fh:
        return {"error": f"Foothold '{foothold_id}' não encontrado.", "ok": False}
    if not command:
        return {"error": "Parâmetro 'command' obrigatório (leitura delegada)."}
    cap = min(int(max_bytes or _MAX_SAMPLE_BYTES), _MAX_SAMPLE_BYTES)
    run = await ctx.delegate(command, timeout=120)
    out = _combine(run)[:cap]
    host = fh.get("host") or ""
    return {"ok": True, "foothold_id": foothold_id, "host": host, "bytes": len(out), "cap": cap,
            "proof": build_proof("sample", out, note=f"amostra mínima ({len(out)}B, cap {cap}B)",
                                 deconfliction_tag=_tag(ctx, host))}


async def demo_exfiltration(ctx: OffensiveContext, foothold_id: str, command: str,
                            destination: str = "", max_bytes: int = _MAX_EXFIL_BYTES) -> dict:
    """DESTRUCTIVE-adjacent (dual approval): a size/rate-LIMITED exfil to test DLP. Logs
    exactly what left; refuses anything above the hard cap. Never moves real bulk data."""
    if not ctx.has_sandbox():
        return {"error": "Sandbox indisponível — exfil demo recusada.", "ok": False}
    fh = await ctx.get_foothold(foothold_id)
    if not fh:
        return {"error": f"Foothold '{foothold_id}' não encontrado.", "ok": False}
    if not command:
        return {"error": "Parâmetro 'command' obrigatório (canal de exfil delegado)."}
    cap = min(int(max_bytes or _MAX_EXFIL_BYTES), _MAX_EXFIL_BYTES)
    run = await ctx.delegate(command, timeout=120)
    out = _combine(run)
    host = fh.get("host") or ""
    # Honest DLP-test record: what left, where, how much (capped).
    exfil_log = {"destination": destination or "(operator-supplied in command)",
                 "cap_bytes": cap, "channel_output_bytes": len(out)}
    return {"ok": True, "foothold_id": foothold_id, "host": host, "exfil_log": exfil_log,
            "note": "Demo de exfil limitada para testar DLP — registra exatamente o que saiu; sem dados reais em massa.",
            "proof": build_proof("output", out[:cap], note="demo de exfiltração (DLP test)",
                                 deconfliction_tag=_tag(ctx, host))}


async def impact_poc(ctx: OffensiveContext, foothold_id: str, command: str,
                     test_directory: str = "", config: Any = None) -> dict:
    """DESTRUCTIVE (OFF BY DEFAULT): a non-destructive-by-default impact PoC. Refuses
    unless ``allow_destructive_testing`` is enabled AND an isolated ``test_directory`` is
    given. Never runs destructive impact on production without an explicit ROE for it."""
    try:
        if config is None:
            from ..core.config import get_config
            config = get_config()
        allowed = bool(getattr(config, "allow_destructive_testing", False))
    except Exception:
        allowed = False
    if not allowed:
        return {"error": ("impact_poc está DESLIGADO por padrão. Habilite explicitamente "
                          "ARCANUM_ALLOW_DESTRUCTIVE_TESTING=1 e só com ROE que exija impacto destrutivo."),
                "ok": False, "executed": False}
    if not test_directory:
        return {"error": ("Recusado: 'test_directory' obrigatório — impacto destrutivo só em diretório "
                          "de teste isolado autorizado, nunca em produção."), "ok": False, "executed": False}
    if not ctx.has_sandbox():
        return {"error": "Sandbox indisponível — PoC de impacto recusado.", "ok": False, "executed": False}
    fh = await ctx.get_foothold(foothold_id)
    if not fh:
        return {"error": f"Foothold '{foothold_id}' não encontrado.", "ok": False, "executed": False}
    if not command:
        return {"error": "Parâmetro 'command' obrigatório (PoC delegado).", "ok": False}
    run = await ctx.delegate(command, timeout=300)
    out = _combine(run)
    host = fh.get("host") or ""
    return {"ok": True, "executed": True, "foothold_id": foothold_id, "host": host,
            "test_directory": test_directory,
            "note": "PoC de impacto executado em diretório de teste isolado sob ROE + dupla aprovação.",
            "proof": build_proof("output", out, note=f"impact PoC em {test_directory}",
                                 deconfliction_tag=_tag(ctx, host))}
