"""SIEM event forwarder (Splunk HEC, Datadog Logs, Elasticsearch, CEF Format)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
import httpx


class SIEMForwarder:
    """Dispatches normalized security events to enterprise SIEM platforms."""

    SEVERITY_NUMERIC = {
        "critical": 10,
        "high": 8,
        "medium": 5,
        "low": 2,
        "info": 0,
    }

    def __init__(
        self,
        splunk_hec_url: str = "",
        splunk_hec_token: str = "",
        datadog_api_key: str = "",
        datadog_site: str = "datadoghq.com",
        elastic_url: str = "",
        elastic_api_key: str = "",
        mock_mode: bool = False,
    ):
        self.splunk_hec_url = (splunk_hec_url or "").rstrip("/")
        self.splunk_hec_token = splunk_hec_token
        self.datadog_api_key = datadog_api_key
        self.datadog_site = datadog_site or "datadoghq.com"
        self.elastic_url = (elastic_url or "").rstrip("/")
        self.elastic_api_key = elastic_api_key
        self.mock_mode = mock_mode

    def format_cef(self, finding: dict[str, Any], session_name: str = "") -> str:
        """Formats the finding as a standard CEF (Common Event Format) string."""
        title = (finding.get("title") or "Unknown Vulnerability").replace("|", "\\|")
        ftype = (finding.get("type") or "security_finding").replace("|", "\\|")
        severity = (finding.get("severity") or "medium").lower()
        sev_num = self.SEVERITY_NUMERIC.get(severity, 5)
        cve_id = finding.get("cve_id") or "N/A"
        affected = finding.get("affected") or {}
        target = ""
        if isinstance(affected, dict):
            target = affected.get("url") or affected.get("host") or affected.get("target") or ""
        elif isinstance(affected, str):
            target = affected

        return (
            f"CEF:0|Arcanum|ArcanumCore|2.0|{ftype}|{title}|{sev_num}|"
            f"src={target} cs1Label=CVE cs1={cve_id} cs2Label=Session cs2={session_name} "
            f"cs3Label=Status cs3={finding.get('status', 'confirmed')}"
        )

    def format_ecs(self, finding: dict[str, Any], session_name: str = "") -> dict[str, Any]:
        """Formats the finding using Elastic Common Schema (ECS)."""
        severity = (finding.get("severity") or "medium").lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        affected = finding.get("affected") or {}
        host = ""
        if isinstance(affected, dict):
            host = affected.get("host") or affected.get("url") or ""
        elif isinstance(affected, str):
            host = affected

        return {
            "@timestamp": now_iso,
            "event": {
                "kind": "alert",
                "category": ["vulnerability", "threat"],
                "type": ["info"],
                "severity": self.SEVERITY_NUMERIC.get(severity, 5),
                "module": "arcanum.core",
                "dataset": "arcanum.findings",
            },
            "vulnerability": {
                "id": finding.get("cve_id") or finding.get("id"),
                "name": finding.get("title"),
                "severity": severity,
                "score": {
                    "base": finding.get("cvss_score"),
                },
                "explanation": finding.get("description"),
            },
            "host": {
                "name": host,
            },
            "arcanum": {
                "session_name": session_name,
                "finding_id": finding.get("id"),
                "status": finding.get("status", "confirmed"),
                "remediation": finding.get("remediation"),
            },
        }

    async def forward_to_splunk(self, finding: dict[str, Any], session_name: str = "") -> dict[str, Any]:
        """Forwards event to Splunk HTTP Event Collector (HEC)."""
        if not (self.splunk_hec_url and self.splunk_hec_token) or self.mock_mode:
            return {"destination": "splunk", "success": True, "mock": True}

        payload = {
            "time": datetime.now(timezone.utc).timestamp(),
            "sourcetype": "arcanum:security:finding",
            "source": "arcanum-core",
            "event": self.format_ecs(finding, session_name),
        }
        headers = {
            "Authorization": f"Splunk {self.splunk_hec_token}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self.splunk_hec_url}/services/collector/event",
                json=payload,
                headers=headers,
            )
            return {"destination": "splunk", "success": resp.status_code == 200, "status_code": resp.status_code}

    async def forward_to_datadog(self, finding: dict[str, Any], session_name: str = "") -> dict[str, Any]:
        """Forwards log event to Datadog Logs API."""
        if not self.datadog_api_key or self.mock_mode:
            return {"destination": "datadog", "success": True, "mock": True}

        severity = (finding.get("severity") or "medium").lower()
        ecs_event = self.format_ecs(finding, session_name)
        payload = [
            {
                "ddsource": "arcanum",
                "ddtags": f"env:production,session:{session_name},severity:{severity}",
                "hostname": "arcanum-engine",
                "service": "arcanum-core",
                "message": f"[{severity.upper()}] {finding.get('title')}",
                **ecs_event,
            }
        ]
        headers = {
            "DD-API-KEY": self.datadog_api_key,
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"https://http-intake.logs.{self.datadog_site}/api/v2/logs",
                json=payload,
                headers=headers,
            )
            return {"destination": "datadog", "success": resp.status_code in (200, 202), "status_code": resp.status_code}

    async def forward_finding(self, finding: dict[str, Any], session_name: str = "") -> dict[str, Any]:
        """Broadcasts finding to all configured SIEM destinations and returns CEF string."""
        results = []
        cef_string = self.format_cef(finding, session_name)

        if self.splunk_hec_url or self.mock_mode:
            res = await self.forward_to_splunk(finding, session_name)
            results.append(res)

        if self.datadog_api_key or self.mock_mode:
            res = await self.forward_to_datadog(finding, session_name)
            results.append(res)

        return {
            "success": True,
            "cef_payload": cef_string,
            "ecs_payload": self.format_ecs(finding, session_name),
            "dispatches": results,
        }
