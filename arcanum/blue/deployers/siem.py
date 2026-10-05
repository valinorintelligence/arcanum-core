"""SIEM detection-rule deployer (F2 — real deploy backends).

Deploys a detection rule to a real SIEM, with deploy → verify → rollback, choosing
the configured backend:

* **Elastic** — Kibana Detection Engine (`elastic_url` + `elastic_api_key`).
* **Splunk** — a scheduled saved/correlation search via the management REST API
  (`splunk_mgmt_url` :8089 + token or basic auth) (F2 b).
* **Microsoft Sentinel** — a scheduled analytics rule via the ARM REST API
  (`sentinel_resource_id` + `sentinel_token`) (F2 b).

Without credentials the deployer runs in **honest mock** mode (never fakes a real
deploy). Splunk HEC / Datadog ingest *events*, not rules, so they are not deploy
backends here. The external id is stored prefixed with the backend
(``elastic:`` / ``splunk:`` / ``sentinel:``) so verify/rollback route correctly.
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx

from .base import BaseDeployer

_ARM = "https://management.azure.com"


class SIEMDeployer(BaseDeployer):
    target_system = "siem"

    def _cfg(self, name: str, default: str = "") -> str:
        return getattr(self.config, name, default) if self.config else default

    # -- backend selection --------------------------------------------------

    def _backend(self) -> str:
        """The configured deploy backend (elastic > splunk > sentinel), or ''."""
        if self._cfg("elastic_url") and self._cfg("elastic_api_key"):
            return "elastic"
        if self._cfg("splunk_mgmt_url") and (
                self._cfg("splunk_mgmt_token")
                or (self._cfg("splunk_username") and self._cfg("splunk_password"))):
            return "splunk"
        if self._cfg("sentinel_resource_id") and self._cfg("sentinel_token"):
            return "sentinel"
        return ""

    def configured(self) -> bool:
        return bool(self._backend())

    def _default_rule_type(self) -> str:
        return "sigma"

    @staticmethod
    def _split_ext(external_id: str | None) -> tuple[str, str]:
        """Return (backend, identifier). Legacy unprefixed ids are treated as Elastic."""
        ext = external_id or ""
        if ":" in ext:
            backend, _, ident = ext.partition(":")
            if backend in ("elastic", "splunk", "sentinel"):
                return backend, ident
        return "elastic", ext

    # -- dispatch -----------------------------------------------------------

    async def _deploy_real(self, rule: dict) -> str | None:
        backend = self._backend()
        if backend == "elastic":
            return "elastic:" + (await self._deploy_elastic(rule) or "")
        if backend == "splunk":
            return "splunk:" + (await self._deploy_splunk(rule) or "")
        if backend == "sentinel":
            return "sentinel:" + (await self._deploy_sentinel(rule) or "")
        raise RuntimeError(
            "No supported SIEM deploy backend configured. Set Elastic "
            "(ARCANUM_ELASTIC_URL/API_KEY), Splunk mgmt (ARCANUM_SPLUNK_MGMT_URL + token), "
            "or Sentinel (ARCANUM_SENTINEL_RESOURCE_ID + token). Splunk HEC/Datadog ingest "
            "events, not detection rules.")

    async def _verify_real(self, rec: dict) -> bool:
        backend, ident = self._split_ext(rec.get("external_id"))
        if not ident:
            return rec["status"] == "active"
        try:
            if backend == "elastic":
                return await self._verify_elastic(ident)
            if backend == "splunk":
                return await self._verify_splunk(ident)
            if backend == "sentinel":
                return await self._verify_sentinel(ident)
        except Exception:
            return False
        return rec["status"] == "active"

    async def _rollback_real(self, rec: dict) -> None:
        backend, ident = self._split_ext(rec.get("external_id"))
        if not ident:
            return
        if backend == "elastic":
            await self._rollback_elastic(ident)
        elif backend == "splunk":
            await self._rollback_splunk(ident)
        elif backend == "sentinel":
            await self._rollback_sentinel(ident)

    # -- Elastic (Kibana Detection Engine) ----------------------------------

    async def _deploy_elastic(self, rule: dict) -> str | None:
        url = self._cfg("elastic_url").rstrip("/")
        key = self._cfg("elastic_api_key")
        body = {
            "type": "query", "language": "kuery",
            "query": rule.get("query") or "*",
            "name": rule.get("name") or "Arcanum Detection Rule",
            "description": rule.get("description") or "Deployed by Arcanum Blue Team.",
            "severity": (rule.get("severity") or "high").lower(),
            "risk_score": int(rule.get("risk_score", 73)),
            "enabled": True, "tags": ["arcanum", "blue-team"],
        }
        headers = {"Authorization": f"ApiKey {key}", "kbn-xsrf": "true",
                   "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(f"{url}/api/detection_engine/rules", json=body, headers=headers)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"Elastic API {resp.status_code}: {resp.text[:300]}")
            return resp.json().get("id")

    async def _verify_elastic(self, ident: str) -> bool:
        url = self._cfg("elastic_url").rstrip("/")
        key = self._cfg("elastic_api_key")
        headers = {"Authorization": f"ApiKey {key}", "kbn-xsrf": "true"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(f"{url}/api/detection_engine/rules?id={ident}", headers=headers)
            return resp.status_code == 200 and bool(resp.json().get("enabled", False))

    async def _rollback_elastic(self, ident: str) -> None:
        url = self._cfg("elastic_url").rstrip("/")
        key = self._cfg("elastic_api_key")
        headers = {"Authorization": f"ApiKey {key}", "kbn-xsrf": "true"}
        async with httpx.AsyncClient(timeout=15.0) as client:
            await client.delete(f"{url}/api/detection_engine/rules?id={ident}", headers=headers)

    # -- Splunk (saved/correlation search via mgmt REST :8089) --------------

    def _splunk_base(self) -> tuple[str, dict, Any]:
        url = self._cfg("splunk_mgmt_url").rstrip("/")
        app = self._cfg("splunk_app") or "search"
        token = self._cfg("splunk_mgmt_token")
        if token:
            headers, auth = {"Authorization": f"Bearer {token}"}, None
        else:
            headers, auth = {}, (self._cfg("splunk_username"), self._cfg("splunk_password"))
        base = f"{url}/servicesNS/nobody/{app}/saved/searches"
        return base, headers, auth

    async def _deploy_splunk(self, rule: dict) -> str | None:
        spl = rule.get("spl") or rule.get("search") or rule.get("query")
        if not spl:
            raise RuntimeError("Splunk saved-search deploy needs an SPL query "
                               "(rule['spl'] / rule['search'] / rule['query']).")
        name = rule.get("name") or f"Arcanum - {uuid.uuid4().hex[:8]}"
        base, headers, auth = self._splunk_base()
        data = {
            "name": name, "search": spl,
            "is_scheduled": "1", "cron_schedule": rule.get("cron", "*/10 * * * *"),
            "dispatch.earliest_time": "-15m", "dispatch.latest_time": "now",
            "alert_type": "number of events", "alert_comparator": "greater than",
            "alert_threshold": "0", "alert.severity": "4",
            "description": rule.get("description") or "Deployed by Arcanum Blue Team.",
            "output_mode": "json",
        }
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.post(base, data=data, headers=headers, auth=auth)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"Splunk mgmt API {resp.status_code}: {resp.text[:300]}")
            return name

    async def _verify_splunk(self, name: str) -> bool:
        base, headers, auth = self._splunk_base()
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.get(f"{base}/{name}?output_mode=json", headers=headers, auth=auth)
            return resp.status_code == 200

    async def _rollback_splunk(self, name: str) -> None:
        base, headers, auth = self._splunk_base()
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            await client.delete(f"{base}/{name}?output_mode=json", headers=headers, auth=auth)

    # -- Microsoft Sentinel (scheduled analytics rule via ARM) --------------

    def _sentinel_url(self, rule_id: str) -> str:
        scope = self._cfg("sentinel_resource_id").rstrip("/")
        ver = self._cfg("sentinel_api_version") or "2023-11-01"
        return f"{_ARM}{scope}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}?api-version={ver}"

    async def _deploy_sentinel(self, rule: dict) -> str | None:
        kql = rule.get("kql") or rule.get("query")
        if not kql:
            raise RuntimeError("Sentinel analytics rule deploy needs a KQL query "
                               "(rule['kql'] / rule['query']).")
        rule_id = rule.get("rule_id") or str(uuid.uuid4())
        token = self._cfg("sentinel_token")
        body = {
            "kind": "Scheduled",
            "properties": {
                "displayName": rule.get("name") or "Arcanum Detection Rule",
                "description": rule.get("description") or "Deployed by Arcanum Blue Team.",
                "severity": (rule.get("severity") or "High").capitalize(),
                "enabled": True, "query": kql,
                "queryFrequency": rule.get("query_frequency", "PT15M"),
                "queryPeriod": rule.get("query_period", "PT15M"),
                "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            },
        }
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.put(self._sentinel_url(rule_id), json=body, headers=headers)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"Sentinel ARM API {resp.status_code}: {resp.text[:300]}")
            return rule_id

    async def _verify_sentinel(self, rule_id: str) -> bool:
        token = self._cfg("sentinel_token")
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(self._sentinel_url(rule_id), headers=headers)
            if resp.status_code != 200:
                return False
            return bool(resp.json().get("properties", {}).get("enabled", False))

    async def _rollback_sentinel(self, rule_id: str) -> None:
        token = self._cfg("sentinel_token")
        headers = {"Authorization": f"Bearer {token}"}
        async with httpx.AsyncClient(timeout=20.0) as client:
            await client.delete(self._sentinel_url(rule_id), headers=headers)
