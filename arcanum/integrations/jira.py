"""Jira Software enterprise connector for vulnerability tracking and remediation."""

from __future__ import annotations

import base64
import json
from typing import Any, Optional
import httpx


class JiraConnector:
    """Connects Arcanum to Jira Software Cloud / Server to sync security findings."""

    SEVERITY_MAP = {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }

    def __init__(
        self,
        base_url: str = "",
        email: str = "",
        api_token: str = "",
        project_key: str = "SEC",
        issue_type: str = "Vulnerability",
        mock_mode: bool = False,
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
        self.issue_type = issue_type
        self.mock_mode = mock_mode or not (self.base_url and self.api_token)

    def _get_auth_headers(self) -> dict[str, str]:
        if self.email and self.api_token:
            auth_str = f"{self.email}:{self.api_token}"
            encoded = base64.b64encode(auth_str.encode()).decode()
            return {
                "Authorization": f"Basic {encoded}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        elif self.api_token:
            return {
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        return {"Content-Type": "application/json", "Accept": "application/json"}

    async def create_vulnerability_issue(
        self,
        finding: dict[str, Any],
        session_name: str = "",
        retest_callback_url: str = "",
    ) -> dict[str, Any]:
        """Creates a security issue in Jira for the given finding."""
        title = finding.get("title") or "Security Vulnerability"
        severity = (finding.get("severity") or "medium").lower()
        cve_id = finding.get("cve_id") or "N/A"
        cvss = finding.get("cvss_score") or "N/A"
        affected = finding.get("affected")
        remediation = finding.get("remediation") or "Aplicar patches de segurança e isolamento perimetral."
        evidence = finding.get("evidence") or finding.get("poc") or {}

        jira_priority = self.SEVERITY_MAP.get(severity, "Medium")

        description = (
            f"*Arcanum Autonomous Pentest Security Finding*\n\n"
            f"*Operação:* {session_name}\n"
            f"*Severidade:* {severity.upper()} (CVSS: {cvss})\n"
            f"*CVE ID:* {cve_id}\n"
            f"*Alvo Afetado:* {affected}\n\n"
            f"h3. Remediação Recomendada\n{remediation}\n\n"
            f"h3. Evidência Técnica (PoC)\n{{code:json}}\n{json.dumps(evidence, indent=2, default=str)[:1500]}\n{{code}}\n\n"
        )
        if retest_callback_url:
            description += f"*1-Click Retest Webhook:* {retest_callback_url}\n"

        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"[Arcanum] [{severity.upper()}] {title}",
                "description": description,
                "issuetype": {"name": self.issue_type},
                "priority": {"name": jira_priority},
                "labels": ["arcanum-security", f"severity-{severity}", "autonomous-finding"],
            }
        }

        if self.mock_mode:
            import hashlib
            issue_id = "SEC-" + hashlib.sha1(title.encode()).hexdigest()[:4].upper()
            return {
                "success": True,
                "mock": True,
                "issue_key": issue_id,
                "issue_url": f"https://mock-jira.atlassian.net/browse/{issue_id}",
                "project": self.project_key,
                "summary": payload["fields"]["summary"],
                "priority": jira_priority,
            }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self.base_url}/rest/api/2/issue",
                json=payload,
                headers=self._get_auth_headers(),
            )
            if resp.status_code not in (200, 201):
                return {
                    "success": False,
                    "error": f"Jira API returned status {resp.status_code}: {resp.text}",
                }
            data = resp.json()
            key = data.get("key")
            return {
                "success": True,
                "mock": False,
                "issue_key": key,
                "issue_url": f"{self.base_url}/browse/{key}",
                "id": data.get("id"),
            }
