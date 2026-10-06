"""Rich notification dispatcher for Slack, Microsoft Teams and Custom Webhooks."""

from __future__ import annotations

import hmac
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional
import httpx


class NotificationDispatcher:
    """Dispatches formatted security alert cards to communication channels."""

    COLORS = {
        "critical": "#dc2626",  # Red
        "high": "#ea580c",      # Orange
        "medium": "#eab308",    # Yellow
        "low": "#3b82f6",       # Blue
        "info": "#6b7280",      # Gray
    }

    def __init__(
        self,
        slack_webhook_url: str = "",
        teams_webhook_url: str = "",
        custom_webhook_url: str = "",
        webhook_secret: str = "",
        mock_mode: bool = False,
    ):
        self.slack_webhook_url = slack_webhook_url
        self.teams_webhook_url = teams_webhook_url
        self.custom_webhook_url = custom_webhook_url
        self.webhook_secret = webhook_secret
        self.mock_mode = mock_mode

    async def send_slack_alert(
        self,
        finding: dict[str, Any],
        session_name: str = "",
        retest_url: str = "",
    ) -> dict[str, Any]:
        """Sends a rich Block Kit formatted card to Slack."""
        title = finding.get("title") or "Alerta de Segurança"
        severity = (finding.get("severity") or "medium").lower()
        color = self.COLORS.get(severity, self.COLORS["medium"])
        cve = finding.get("cve_id") or "N/A"
        cvss = finding.get("cvss_score") or "N/A"
        affected = finding.get("affected") or "Alvo não especificado"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 [Arcanum SOC] Vulnerabilidade {severity.upper()} Detectada",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Operação:*\n`{session_name}`"},
                    {"type": "mrkdwn", "text": f"*Severidade:*\n*{severity.upper()}* (CVSS: {cvss})"},
                    {"type": "mrkdwn", "text": f"*CVE ID:*\n`{cve}`"},
                    {"type": "mrkdwn", "text": f"*Ativo Afetado:*\n`{affected}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Título:*\n*{title}*\n\n*Remediação:*\n{finding.get('remediation', 'Nenhuma remediação informada.')}",
                },
            },
        ]

        if retest_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🔄 Disparar 1-Click Retest"},
                        "style": "primary",
                        "url": retest_url,
                    }
                ],
            })

        payload = {"attachments": [{"color": color, "blocks": blocks}]}

        if not self.slack_webhook_url or self.mock_mode:
            return {"channel": "slack", "success": True, "mock": True, "payload": payload}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(self.slack_webhook_url, json=payload)
            return {"channel": "slack", "success": resp.status_code == 200, "status_code": resp.status_code}

    async def send_teams_alert(
        self,
        finding: dict[str, Any],
        session_name: str = "",
        retest_url: str = "",
    ) -> dict[str, Any]:
        """Sends an Adaptive Card / MessageCard to Microsoft Teams."""
        title = finding.get("title") or "Alerta de Segurança"
        severity = (finding.get("severity") or "medium").lower()
        color = self.COLORS.get(severity, self.COLORS["medium"]).replace("#", "")

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Arcanum Alerta: {title}",
            "sections": [
                {
                    "activityTitle": f"🚨 [Arcanum Core] Vulnerabilidade {severity.upper()} Detectada",
                    "activitySubtitle": f"Operação: {session_name} | {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M:%S UTC')}",
                    "facts": [
                        {"name": "Título:", "value": title},
                        {"name": "Severidade:", "value": severity.upper()},
                        {"name": "CVE:", "value": finding.get("cve_id") or "N/A"},
                        {"name": "Alvo Afetado:", "value": str(finding.get("affected") or "-")},
                        {"name": "Remediação:", "value": finding.get("remediation") or "Verifique as configurações do ativo."},
                    ],
                    "markdown": True,
                }
            ],
        }

        if retest_url:
            payload["potentialAction"] = [
                {
                    "@type": "OpenUri",
                    "name": "🔄 Disparar 1-Click Retest",
                    "targets": [{"os": "default", "uri": retest_url}],
                }
            ]

        if not self.teams_webhook_url or self.mock_mode:
            return {"channel": "teams", "success": True, "mock": True, "payload": payload}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(self.teams_webhook_url, json=payload)
            return {"channel": "teams", "success": resp.status_code == 200, "status_code": resp.status_code}

    async def send_custom_webhook(
        self,
        event_type: str,
        payload_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Dispatches payload to a custom webhook URL with optional HMAC signature."""
        body_bytes = json.dumps(payload_data, default=str).encode("utf-8")
        headers = {"Content-Type": "application/json", "X-Arcanum-Event": event_type}

        if self.webhook_secret:
            sig = hmac.new(self.webhook_secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
            headers["X-Arcanum-Signature"] = f"sha256={sig}"

        if not self.custom_webhook_url or self.mock_mode:
            return {"channel": "custom_webhook", "success": True, "mock": True, "event": event_type}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(self.custom_webhook_url, content=body_bytes, headers=headers)
            return {"channel": "custom_webhook", "success": resp.status_code in (200, 201, 202), "status_code": resp.status_code}
