"""Purple campaign (F3): chain techniques, measure coverage, report gaps.

Runs an emulation plan (a list of ATT&CK techniques) through the closed loop,
measures end-to-end detection coverage, and produces a gap report. Optionally
auto-tunes (deploys detection rules) to close gaps and re-measures.
"""
from __future__ import annotations

import uuid
from typing import Any

from .loop import PurpleLoop
from .store import PurpleResultStore


class PurpleCampaign:
    def __init__(self, db: Any, config: Any = None, sandbox: Any = None,
                 session_id: str | None = None, engagement_id: str | None = None):
        self.db = db
        self.config = config
        self.loop = PurpleLoop(db, config=config, sandbox=sandbox,
                               session_id=session_id, engagement_id=engagement_id)
        self.store = PurpleResultStore(db)

    async def run(self, techniques: list, auto_tune: bool = True,
                  campaign_id: str | None = None) -> dict:
        """Run a campaign over ``techniques`` (list of ids, or dicts with
        {technique_id, tactic, command}). Returns coverage + per-technique results."""
        campaign_id = campaign_id or ("pc-" + uuid.uuid4().hex[:8])
        per_technique = []
        for t in techniques:
            if isinstance(t, str):
                tid, tactic, command = t, None, None
            else:
                tid = t.get("technique_id") or t.get("id")
                tactic = t.get("tactic")
                command = t.get("command")
            if not tid:
                continue
            res = await self.loop.close_gap(
                tid, campaign_id=campaign_id, tactic=tactic, command=command,
                auto_tune=auto_tune)
            after = res.get("after") or {}
            prev_before = res.get("before_prevention", {})
            per_technique.append({
                "technique_id": tid,
                "status": res.get("status"),
                "detected_before": res.get("before", {}).get("detected"),
                "detected_after": after.get("detected") if res.get("tuned") else None,
                "detection_simulated": after.get("simulated") if res.get("tuned") else res.get("before", {}).get("simulated"),
                "prevented": prev_before.get("prevented"),
                "prevention_source": prev_before.get("source"),
                "prevention_simulated": prev_before.get("simulated"),
                "tuned": res.get("tuned"),
            })

        coverage = await self.store.coverage(campaign_id)

        # Honest recommendation: distinguish real gaps from simulated-only coverage.
        sim_gaps = coverage.get("simulated_gaps", [])
        if coverage["gaps"]:
            rec = (f"{len(coverage['gaps'])} técnica(s) ainda sem detecção: "
                   f"{', '.join(coverage['gaps'])}. Gere e implante regras de detecção "
                   "(deploy_detection_rule) e re-meça.")
        elif sim_gaps:
            rec = (f"Cobertura SIMULADA para {len(sim_gaps)} técnica(s) ({', '.join(sim_gaps)}): "
                   "as regras foram implantadas em modo mock (sem credenciais de SIEM/WAF/EDR). "
                   "Configure um controle real e re-meça para cobertura REAL.")
        else:
            rec = "Cobertura REAL total — todas as técnicas executadas são detectadas por controles reais."

        return {
            "campaign_id": campaign_id,
            "auto_tune": auto_tune,
            "coverage": coverage,
            "results": per_technique,
            "gap_report": {
                "remaining_gaps": coverage["gaps"],
                "simulated_coverage_gaps": sim_gaps,
                "coverage_percent": coverage["coverage_percent"],
                "coverage_percent_real": coverage["coverage_percent_real"],
                "prevention_percent": coverage.get("prevention_percent", 0.0),
                "prevention_percent_real": coverage.get("prevention_percent_real", 0.0),
                "recommendation": rec,
            },
        }
