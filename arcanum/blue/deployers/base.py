"""Common deploy → verify → rollback contract for Blue Team adapters (F2).

Each adapter deploys a detection rule to a defensive control and records it in the
:class:`~arcanum.blue.registry.DeploymentRegistry`. When no credentials are
configured the adapter runs in **honest mock mode**: it records the deployment
as ``mock=True`` and NEVER claims a real external deploy happened (same contract
as ``integrations/jira.py``). ``verify`` and ``rollback`` operate on the registry
(and, for a real deploy, on the external system).
"""
from __future__ import annotations

from typing import Any


class BaseDeployer:
    target_system = "generic"

    def __init__(self, config: Any = None, registry: Any = None,
                 session_id: str | None = None, engagement_id: str | None = None):
        self.config = config
        self.registry = registry
        self.session_id = session_id
        self.engagement_id = engagement_id

    # -- credentials / mode -------------------------------------------------

    def configured(self) -> bool:
        """Whether real credentials are present. Subclasses override."""
        return False

    @property
    def mock_mode(self) -> bool:
        return not self.configured()

    # -- lifecycle ----------------------------------------------------------

    async def deploy(self, rule: dict) -> dict:
        """Deploy a rule. ``rule`` carries at least ``rule_type`` and the rule
        body (e.g. ``sigma``/``modsecurity``/``suricata`` text) plus a ``name``.
        Returns ``{id, status, mock, target_system, ...}``."""
        rule_type = rule.get("rule_type") or self._default_rule_type()
        name = rule.get("name") or f"{self.target_system}-rule"
        external_id = None
        status = "active"
        mock = self.mock_mode
        error = None

        if not mock:
            try:
                external_id = await self._deploy_real(rule)
                if not external_id:
                    status, error = "failed", "real deploy returned no id"
            except Exception as exc:  # honest failure — never fake success
                status, error = "failed", str(exc)

        rec = await self.registry.record(
            kind="detection_rule", target_system=self.target_system,
            rule_type=rule_type, name=name, status=status, mock=mock,
            payload={"rule": rule, "error": error},
            external_id=external_id,
            session_id=self.session_id, engagement_id=self.engagement_id,
        )
        out = {
            "id": rec["id"], "status": rec["status"], "mock": mock,
            "target_system": self.target_system, "rule_type": rule_type,
            "name": name, "external_id": external_id,
        }
        if error:
            out["error"] = error
        return out

    async def verify(self, deployment_id: str) -> dict:
        """Return whether the deployment is currently active."""
        rec = await self.registry.get(deployment_id)
        if not rec:
            return {"active": False, "status": "not_found", "deployment_id": deployment_id}
        active = rec["status"] == "active"
        if active and not rec["mock"]:
            # A real deployment is verified against the external control.
            try:
                active = await self._verify_real(rec)
            except Exception:
                active = False
            await self.registry.set_status(deployment_id, "active" if active else "failed")
        await self.registry.mark_verified(deployment_id, active)
        return {"active": active, "status": "active" if active else rec["status"],
                "mock": rec["mock"], "deployment_id": deployment_id,
                "target_system": rec["target_system"]}

    async def rollback(self, deployment_id: str) -> dict:
        rec = await self.registry.get(deployment_id)
        if not rec:
            return {"success": False, "status": "not_found", "deployment_id": deployment_id}
        if rec["status"] == "rolled_back":
            return {"success": True, "status": "rolled_back", "deployment_id": deployment_id,
                    "note": "already rolled back"}
        if not rec["mock"] and rec.get("external_id"):
            try:
                await self._rollback_real(rec)
            except Exception as exc:
                return {"success": False, "status": rec["status"], "error": str(exc),
                        "deployment_id": deployment_id}
        await self.registry.mark_rolled_back(deployment_id)
        return {"success": True, "status": "rolled_back", "mock": rec["mock"],
                "deployment_id": deployment_id, "target_system": rec["target_system"]}

    # -- real-system hooks (overridden by configured adapters) --------------

    def _default_rule_type(self) -> str:
        return "generic"

    async def _deploy_real(self, rule: dict) -> str | None:
        raise NotImplementedError

    async def _verify_real(self, rec: dict) -> bool:
        # Default: trust the registry status (adapters with a query API override).
        return rec["status"] == "active"

    async def _rollback_real(self, rec: dict) -> None:
        raise NotImplementedError
