"""SIEM detection-rule deployer (F2).

Deploys a detection rule (Sigma, or an Elastic detection-engine rule) to a SIEM.
Real path implemented for Elastic (Kibana Detection Engine REST API); Splunk/
Datadog credentials are recognized but rule *creation* over HEC is not possible,
so those honestly report unsupported rather than faking a deploy. Without any
SIEM credentials the deployer runs in honest mock mode.
"""
from __future__ import annotations

from typing import Any

import httpx

from .base import BaseDeployer


class SIEMDeployer(BaseDeployer):
    target_system = "siem"

    def _cfg(self, name: str, default: str = "") -> str:
        return getattr(self.config, name, default) if self.config else default

    def configured(self) -> bool:
        return bool(
            (self._cfg("elastic_url") and self._cfg("elastic_api_key"))
            or (self._cfg("splunk_hec_url") and self._cfg("splunk_hec_token"))
            or self._cfg("datadog_api_key")
        )

    def _default_rule_type(self) -> str:
        return "sigma"

    async def _deploy_real(self, rule: dict) -> str | None:
        # Elastic Detection Engine is the one SIEM here that supports creating a
        # rule over a documented REST API. Splunk HEC / Datadog ingest events,
        # not saved searches, so creating a rule there is out of scope.
        elastic_url = self._cfg("elastic_url")
        elastic_key = self._cfg("elastic_api_key")
        if not (elastic_url and elastic_key):
            raise RuntimeError(
                "SIEM rule deploy is supported for Elastic only; configure "
                "ARCANUM_ELASTIC_URL + ARCANUM_ELASTIC_API_KEY (Splunk HEC/Datadog "
                "ingest events, not detection rules).")
        body = {
            "type": "query",
            "language": "kuery",
            "query": rule.get("query") or "*",
            "name": rule.get("name") or "Arcanum Detection Rule",
            "description": rule.get("description") or "Deployed by Arcanum Blue Team.",
            "severity": (rule.get("severity") or "high").lower(),
            "risk_score": int(rule.get("risk_score", 73)),
            "enabled": True,
            "tags": ["arcanum", "blue-team"],
        }
        headers = {"Authorization": f"ApiKey {elastic_key}",
                   "kbn-xsrf": "true", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{elastic_url.rstrip('/')}/api/detection_engine/rules",
                json=body, headers=headers)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"Elastic API {resp.status_code}: {resp.text[:300]}")
            return resp.json().get("id")

    async def _verify_real(self, rec: dict) -> bool:
        elastic_url = self._cfg("elastic_url")
        elastic_key = self._cfg("elastic_api_key")
        ext = rec.get("external_id")
        if not (elastic_url and elastic_key and ext):
            return rec["status"] == "active"
        headers = {"Authorization": f"ApiKey {elastic_key}", "kbn-xsrf": "true"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{elastic_url.rstrip('/')}/api/detection_engine/rules?id={ext}",
                headers=headers)
            return resp.status_code == 200 and bool(resp.json().get("enabled", False))

    async def _rollback_real(self, rec: dict) -> None:
        elastic_url = self._cfg("elastic_url")
        elastic_key = self._cfg("elastic_api_key")
        ext = rec.get("external_id")
        headers = {"Authorization": f"ApiKey {elastic_key}", "kbn-xsrf": "true"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            await client.delete(
                f"{elastic_url.rstrip('/')}/api/detection_engine/rules?id={ext}",
                headers=headers)
