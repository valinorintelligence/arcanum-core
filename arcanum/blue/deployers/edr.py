"""EDR detection-rule deployer (F2).

Deploys a custom detection/IOC rule to an EDR. A real deploy needs an EDR
management endpoint (``ARCANUM_EDR_API_URL`` + ``ARCANUM_EDR_API_TOKEN``);
without it the deployer runs in honest mock mode.
"""
from __future__ import annotations

import os

import httpx

from .base import BaseDeployer


class EDRDeployer(BaseDeployer):
    target_system = "edr"

    def _api(self) -> tuple[str, str]:
        url = getattr(self.config, "edr_api_url", "") if self.config else ""
        token = getattr(self.config, "edr_api_token", "") if self.config else ""
        url = url or os.environ.get("ARCANUM_EDR_API_URL", "")
        token = token or os.environ.get("ARCANUM_EDR_API_TOKEN", "")
        return url, token

    def configured(self) -> bool:
        url, token = self._api()
        return bool(url and token)

    def _default_rule_type(self) -> str:
        return "ioc"

    async def _deploy_real(self, rule: dict) -> str | None:
        url, token = self._api()
        body = {
            "name": rule.get("name") or "arcanum-edr-rule",
            "indicator": rule.get("indicator") or rule.get("ioc") or rule.get("body") or "",
            "action": rule.get("action", "detect"),
        }
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{url.rstrip('/')}/detections", json=body, headers=headers)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"EDR API {resp.status_code}: {resp.text[:300]}")
            return (resp.json() or {}).get("id") or body["name"]

    async def _verify_real(self, rec: dict) -> bool:
        """Confirm the detection is still present on the live EDR (follow-up F2 (c)):
        GET it by external id instead of trusting the registry. No external id, a
        non-200, or a transport error ⇒ not active (honest)."""
        url, token = self._api()
        ext = rec.get("external_id")
        if not ext:
            return False
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{url.rstrip('/')}/detections/{ext}", headers=headers)
            return resp.status_code == 200

    async def _rollback_real(self, rec: dict) -> None:
        url, token = self._api()
        ext = rec.get("external_id")
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            await client.delete(f"{url.rstrip('/')}/detections/{ext}", headers=headers)
