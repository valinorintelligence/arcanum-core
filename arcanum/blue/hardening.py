"""Hardening applier (F2): apply a hardening baseline safely.

Flow: **dry-run → diff → (approve) → apply → verify**, with rollback. The input
is the output of ``generate_hardening_baseline`` (``config_file`` + ``snippet``).

Dry-run (the default) computes the proposed change and records it as ``dry_run``
WITHOUT touching anything. A real apply needs an apply backend (SSH/Ansible/IaC
PR); none is configured in this environment, so an actual apply is recorded as an
honest mock (``mock=True``) — it is tracked for rollback but never claims it
mutated a live host. Each applied item is reversible via the registry.
"""
from __future__ import annotations

import os
from typing import Any


class HardeningApplier:
    def __init__(self, config: Any = None, registry: Any = None,
                 session_id: str | None = None, engagement_id: str | None = None):
        self.config = config
        self.registry = registry
        self.session_id = session_id
        self.engagement_id = engagement_id

    def _apply_backend_configured(self) -> bool:
        # A real apply would use SSH/Ansible against a target. Recognize an opt-in
        # backend if configured; otherwise apply is an honest mock.
        return bool(os.environ.get("ARCANUM_HARDENING_SSH_TARGET"))

    @staticmethod
    def _build_diff(config_file: str, snippet: str) -> str:
        lines = [f"--- {config_file} (current)",
                 f"+++ {config_file} (proposed by Arcanum hardening)"]
        for ln in (snippet or "").splitlines():
            lines.append(f"+{ln}")
        return "\n".join(lines)

    async def apply(self, baseline: dict, target: str = "", dry_run: bool = True) -> dict:
        """Apply (or dry-run) a hardening baseline item.

        ``baseline`` is a ``generate_hardening_baseline`` result (or any dict with
        ``config_file`` + ``snippet``). Returns the diff plus a deployment id.
        """
        config_file = baseline.get("config_file") or "/etc/hardening.conf"
        snippet = baseline.get("snippet") or baseline.get("content") or ""
        benchmark = baseline.get("benchmark") or "custom"
        diff = self._build_diff(config_file, snippet)
        name = f"{benchmark} → {config_file}"

        if dry_run:
            rec = await self.registry.record(
                kind="hardening", target_system="host", rule_type="host-hardening",
                name=name, status="dry_run", mock=True,
                payload={"config_file": config_file, "snippet": snippet, "diff": diff,
                         "target": target, "benchmark": benchmark},
                session_id=self.session_id, engagement_id=self.engagement_id)
            return {"id": rec["id"], "status": "dry_run", "applied": False, "mock": True,
                    "config_file": config_file, "diff": diff, "benchmark": benchmark,
                    "note": "Dry-run: nada foi alterado. Aprove e chame com dry_run=false para aplicar."}

        mock = not self._apply_backend_configured()
        status = "active"
        error = None
        if not mock:
            try:
                await self._apply_real(config_file, snippet, target)
            except Exception as exc:
                status, error = "failed", str(exc)
        rec = await self.registry.record(
            kind="hardening", target_system="host", rule_type="host-hardening",
            name=name, status=status, mock=mock,
            payload={"config_file": config_file, "snippet": snippet, "diff": diff,
                     "target": target, "benchmark": benchmark, "error": error},
            session_id=self.session_id, engagement_id=self.engagement_id)
        out = {"id": rec["id"], "status": status, "applied": status == "active",
               "mock": mock, "config_file": config_file, "benchmark": benchmark}
        if error:
            out["error"] = error
        return out

    async def verify(self, deployment_id: str) -> dict:
        rec = await self.registry.get(deployment_id)
        if not rec:
            return {"active": False, "status": "not_found", "deployment_id": deployment_id}
        active = rec["status"] == "active"
        await self.registry.mark_verified(deployment_id, active)
        return {"active": active, "status": rec["status"], "mock": rec["mock"],
                "deployment_id": deployment_id}

    async def rollback(self, deployment_id: str) -> dict:
        rec = await self.registry.get(deployment_id)
        if not rec:
            return {"success": False, "status": "not_found", "deployment_id": deployment_id}
        if not rec["mock"]:
            try:
                await self._rollback_real(rec)
            except Exception as exc:
                return {"success": False, "error": str(exc), "deployment_id": deployment_id}
        await self.registry.mark_rolled_back(deployment_id)
        return {"success": True, "status": "rolled_back", "mock": rec["mock"],
                "deployment_id": deployment_id}

    async def _apply_real(self, config_file: str, snippet: str, target: str) -> None:
        raise RuntimeError("no real hardening apply backend configured (SSH/Ansible)")

    async def _rollback_real(self, rec: dict) -> None:
        raise RuntimeError("no real hardening apply backend configured (SSH/Ansible)")
