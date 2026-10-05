"""Closed Purple loop for a single technique (F3): detect → tune → re-measure.

Runs a technique, measures detection; on a MISS it generates and deploys a
detection rule (via the F2 SIEM deployer), then re-measures to confirm the gap is
closed. Every step is recorded in the measured-result store.

Honesty note: without SIEM credentials the F2 deploy is a MOCK, so the re-measure
reports SIMULATED coverage (``detection_simulated=True``), not real detection —
``status`` becomes ``tuned_simulated`` rather than ``tuned_detected``. Real
detection requires a rule deployed to a real control (or a real SIEM alert).
"""
from __future__ import annotations

import uuid
from typing import Any

from ..blue.registry import DeploymentRegistry
from ..blue.deployers.siem import SIEMDeployer
from .bas import BASRunner
from .verify import DetectionVerifier
from .store import PurpleResultStore


def build_detection_rule(technique_id: str, tactic: str | None = None) -> dict:
    """A minimal, real Sigma rule tagged with the technique (so verification can
    measure that a covering rule is deployed). Not a fabricated detection — an
    actual rule recorded in the deployment registry."""
    sigma = (
        f"title: Arcanum Purple Detection for {technique_id}\n"
        f"id: {uuid.uuid4()}\n"
        f"status: experimental\n"
        f"description: Auto-generated to close a detection gap for {technique_id}.\n"
        f"tags:\n  - attack.{(tactic or 'execution').lower().replace(' ', '_')}\n  - attack.{technique_id.lower()}\n"
        f"logsource:\n  category: process_creation\n"
        f"detection:\n  selection:\n    technique: '{technique_id}'\n  condition: selection\n"
        f"level: high\n"
    )
    return {"rule_type": "sigma", "name": f"purple-{technique_id}", "sigma": sigma, "body": sigma,
            "technique_id": technique_id, "tactic": tactic}


class PurpleLoop:
    def __init__(self, db: Any, config: Any = None, sandbox: Any = None,
                 session_id: str | None = None, engagement_id: str | None = None):
        self.db = db
        self.config = config
        self.session_id = session_id
        self.engagement_id = engagement_id
        self.store = PurpleResultStore(db)
        self.bas = BASRunner(sandbox=sandbox, session_id=session_id, engagement_id=engagement_id)
        self.verifier = DetectionVerifier(db, config=config)
        self.registry = DeploymentRegistry(db)

    async def close_gap(self, technique_id: str, campaign_id: str | None = None,
                        tactic: str | None = None, command: str | None = None,
                        auto_tune: bool = True, target_system: str = "siem") -> dict:
        campaign_id = campaign_id or ("pc-" + uuid.uuid4().hex[:8])

        run = await self.bas.run(technique_id, campaign_id, tactic=tactic, command=command)
        tag = run.get("deconfliction_tag")

        before = await self.verifier.was_detected(technique_id, tag=tag)
        await self.store.record(
            campaign_id=campaign_id, technique_id=technique_id, tactic=tactic,
            deconfliction_tag=tag, executed=run.get("executed", False),
            execution_status=run.get("execution_status", "simulated"),
            detected=before.get("detected"), detection_source=before.get("source"),
            detection_simulated=before.get("simulated", False),
            tuned=False, session_id=self.session_id, engagement_id=self.engagement_id)

        result = {"campaign_id": campaign_id, "technique_id": technique_id,
                  "execution": run, "before": before, "tuned": False}

        if before.get("detected"):
            result["status"] = "detected"
            return result

        if not auto_tune:
            result["status"] = "missed"
            return result

        # MISS → generate + deploy a covering detection rule, then re-measure.
        deployer = SIEMDeployer(config=self.config, registry=self.registry,
                                session_id=self.session_id, engagement_id=self.engagement_id)
        rule = build_detection_rule(technique_id, tactic)
        deployment = await deployer.deploy(rule)

        after = await self.verifier.was_detected(technique_id, tag=tag)
        await self.store.record(
            campaign_id=campaign_id, technique_id=technique_id, tactic=tactic,
            deconfliction_tag=tag, executed=run.get("executed", False),
            execution_status=run.get("execution_status", "simulated"),
            detected=after.get("detected"), detection_source=after.get("source"),
            detection_simulated=after.get("simulated", False),
            tuned=True, deployment_id=deployment.get("id"),
            session_id=self.session_id, engagement_id=self.engagement_id)

        if after.get("detected"):
            status = "tuned_simulated" if after.get("simulated") else "tuned_detected"
        else:
            status = "still_missed"
        result.update({
            "tuned": True,
            "deployment": deployment,
            "after": after,
            "status": status,
        })
        return result
