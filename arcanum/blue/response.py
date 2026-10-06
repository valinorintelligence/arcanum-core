"""Incident-response containment (F2): reversible IR actions.

Provides ``isolate_host``, ``disable_account`` and ``block_ip``. Each is a
*reversible* containment action recorded in the rollback registry so it can be
undone (and so the kill-switch can revert everything). A real action needs an
EDR/firewall/IdP API (opt-in via env/config); without it the action is an honest
mock (tracked, reversible, never claims a live containment happened).
"""
from __future__ import annotations

import os
from typing import Any

import httpx


class IncidentResponder:
    def __init__(self, config: Any = None, registry: Any = None,
                 session_id: str | None = None, engagement_id: str | None = None):
        self.config = config
        self.registry = registry
        self.session_id = session_id
        self.engagement_id = engagement_id

    def _edr(self) -> tuple[str, str]:
        url = (getattr(self.config, "edr_api_url", "") if self.config else "") or os.environ.get("ARCANUM_EDR_API_URL", "")
        token = (getattr(self.config, "edr_api_token", "") if self.config else "") or os.environ.get("ARCANUM_EDR_API_TOKEN", "")
        return url, token

    async def contain(self, action: str, target: str) -> dict:
        """Perform a containment ``action`` (isolate_host | disable_account |
        block_ip) against ``target``. Reversible."""
        action = (action or "").strip().lower()
        valid = {"isolate_host": "host", "disable_account": "account", "block_ip": "firewall"}
        if action not in valid:
            return {"success": False, "error": f"unknown IR action '{action}'. Valid: {sorted(valid)}"}

        url, token = self._edr()
        mock = not (url and token)
        status = "active"
        error = None
        external_id = None
        if not mock:
            try:
                external_id = await self._contain_real(action, target, url, token)
            except Exception as exc:
                status, error = "failed", str(exc)

        rec = await self.registry.record(
            kind="ir_action", target_system=valid[action], rule_type=action,
            name=f"{action}:{target}", status=status, mock=mock, reversible=True,
            payload={"action": action, "target": target, "error": error},
            external_id=external_id,
            session_id=self.session_id, engagement_id=self.engagement_id)
        out = {"id": rec["id"], "action": action, "target": target, "status": status,
               "mock": mock, "reversible": True}
        if error:
            out["error"] = error
        return out

    async def revert(self, deployment_id: str) -> dict:
        rec = await self.registry.get(deployment_id)
        if not rec:
            return {"success": False, "status": "not_found", "deployment_id": deployment_id}
        if not rec["mock"]:
            try:
                await self._revert_real(rec)
            except Exception as exc:
                return {"success": False, "error": str(exc), "deployment_id": deployment_id}
        await self.registry.mark_rolled_back(deployment_id)
        return {"success": True, "status": "reverted", "mock": rec["mock"],
                "deployment_id": deployment_id}

    async def _contain_real(self, action: str, target: str, url: str, token: str) -> str | None:
        endpoint = {"isolate_host": "isolate", "disable_account": "disable-account",
                    "block_ip": "block-ip"}[action]
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{url.rstrip('/')}/{endpoint}",
                                     json={"target": target}, headers=headers)
            if resp.status_code not in (200, 201, 202):
                raise RuntimeError(f"EDR API {resp.status_code}: {resp.text[:300]}")
            return (resp.json() or {}).get("id") or target

    async def _revert_real(self, rec: dict) -> None:
        url, token = self._edr()
        action = rec["payload"].get("action")
        endpoint = {"isolate_host": "unisolate", "disable_account": "enable-account",
                    "block_ip": "unblock-ip"}.get(action, "revert")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            await client.post(f"{url.rstrip('/')}/{endpoint}",
                              json={"target": rec["payload"].get("target")}, headers=headers)
