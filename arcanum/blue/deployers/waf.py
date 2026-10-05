"""WAF detection-rule deployer (F2).

Deploys a ModSecurity/Coraza rule to a WAF. ModSecurity rules are files loaded by
the proxy, so a real deploy needs a management endpoint (``ARCANUM_WAF_ADMIN_URL``
+ ``ARCANUM_WAF_ADMIN_TOKEN``) that accepts a rule for a managed WAF; without it
the deployer runs in honest mock mode (records the rule for rollback, never
pretends it was pushed to a live WAF).
"""
from __future__ import annotations

import os

import httpx

from .base import BaseDeployer


class WAFDeployer(BaseDeployer):
    target_system = "waf"

    def _admin(self) -> tuple[str, str]:
        url = getattr(self.config, "waf_admin_url", "") if self.config else ""
        token = getattr(self.config, "waf_admin_token", "") if self.config else ""
        # These are optional/advanced settings, so also accept env directly.
        url = url or os.environ.get("ARCANUM_WAF_ADMIN_URL", "")
        token = token or os.environ.get("ARCANUM_WAF_ADMIN_TOKEN", "")
        return url, token

    def configured(self) -> bool:
        url, token = self._admin()
        return bool(url and token)

    def _default_rule_type(self) -> str:
        return "modsecurity"

    async def _deploy_real(self, rule: dict) -> str | None:
        url, token = self._admin()
        body = {
            "name": rule.get("name") or "arcanum-waf-rule",
            "rule": rule.get("modsecurity") or rule.get("body") or rule.get("rule") or "",
            "phase": rule.get("phase", 2),
        }
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{url.rstrip('/')}/rules", json=body, headers=headers)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"WAF admin API {resp.status_code}: {resp.text[:300]}")
            return (resp.json() or {}).get("id") or body["name"]

    async def _rollback_real(self, rec: dict) -> None:
        url, token = self._admin()
        ext = rec.get("external_id")
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            await client.delete(f"{url.rstrip('/')}/rules/{ext}", headers=headers)
