"""ServiceNow Enterprise Incident Management Connector."""

from __future__ import annotations

import base64
import json
from typing import Any, Optional
import httpx


class ServiceNowConnector:
    """Connects Arcanum to ServiceNow Table API to open security incidents."""

    # Urgency & Impact mapping
    MAPPING = {
        "critical": {"urgency": "1", "impact": "1", "priority_label": "1 - Critical"},
        "high": {"urgency": "2", "impact": "2", "priority_label": "2 - High"},
        "medium": {"urgency": "2", "impact": "3", "priority_label": "3 - Moderate"},
        "low": {"urgency": "3", "impact": "3", "priority_label": "4 - Low"},
        "info": {"urgency": "3", "impact": "3", "priority_label": "5 - Planning"},
    }

    def __init__(
        self,
        instance: str = "",
        username: str = "",
        password: str = "",
        mock_mode: bool = False,
    ):
        self.instance = (instance or "").strip().rstrip("/")
        if self.instance and not self.instance.startswith("http"):
            self.instance = f"https://{self.instance}.service-now.com"
        self.username = username
        self.password = password
        self.mock_mode = mock_mode or not (self.instance and self.username and self.password)

    def _get_auth_headers(self) -> dict[str, str]:
        auth_str = f"{self.username}:{self.password}"
        encoded = base64.b64encode(auth_str.encode()).decode()
        return {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def create_security_incident(
        self,
        finding: dict[str, Any],
        session_name: str = "",
    ) -> dict[str, Any]:
        """Creates an incident ticket in ServiceNow for the finding."""
        title = finding.get("title") or "Security Incident Detected"
        severity = (finding.get("severity") or "medium").lower()
        cve_id = finding.get("cve_id") or "N/A"
        affected = finding.get("affected")
        remediation = finding.get("remediation") or ""

        map_info = self.MAPPING.get(severity, self.MAPPING["medium"])

        description = (
            f"Vulnerabilidade identificada de forma autônoma pelo Arcanum Core.\n\n"
            f"Operação: {session_name}\n"
            f"Severidade: {severity.upper()}\n"
            f"CVE: {cve_id}\n"
            f"Ativo Afetado: {affected}\n\n"
            f"Plano de Remediação:\n{remediation}\n"
        )

        payload = {
            "short_description": f"[Arcanum SOC] [{severity.upper()}] {title}",
            "description": description,
            "category": "Security",
            "subcategory": "Vulnerability",
            "contact_type": "Arcanum Engine",
            "urgency": map_info["urgency"],
            "impact": map_info["impact"],
            "comments": "Ticket gerado automaticamente pelo cérebro cognitivo Arcanum.",
        }

        if self.mock_mode:
            import hashlib
            inc_number = "INC" + hashlib.sha1(title.encode()).hexdigest()[:7].upper()
            return {
                "success": True,
                "mock": True,
                "incident_number": inc_number,
                "sys_id": f"mock_sys_{inc_number}",
                "priority": map_info["priority_label"],
                "short_description": payload["short_description"],
            }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self.instance}/api/now/table/incident",
                json=payload,
                headers=self._get_auth_headers(),
            )
            if resp.status_code not in (200, 201):
                return {
                    "success": False,
                    "error": f"ServiceNow API returned status {resp.status_code}: {resp.text}",
                }
            data = resp.json().get("result", {})
            return {
                "success": True,
                "mock": False,
                "incident_number": data.get("number"),
                "sys_id": data.get("sys_id"),
                "priority": data.get("priority"),
            }
