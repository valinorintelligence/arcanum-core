"""Central Enterprise Integration Hub for Arcanum Core."""

from __future__ import annotations

import logging
from typing import Any, Optional

from .jira import JiraConnector
from .servicenow import ServiceNowConnector
from .siem import SIEMForwarder
from .notifications import NotificationDispatcher

logger = logging.getLogger("arcanum.integrations")


class EnterpriseHub:
    """Orchestrates all enterprise connectors (Jira, ServiceNow, SIEM, Slack, Teams)."""

    def __init__(
        self,
        config: Any = None,
        db: Any = None,
        mock_mode: bool = False,
    ):
        self.config = config
        self.db = db
        self.mock_mode = mock_mode

        # Initialize sub-connectors with config values or mock mode
        jira_url = getattr(config, "jira_url", "") if config else ""
        jira_email = getattr(config, "jira_email", "") if config else ""
        jira_token = getattr(config, "jira_api_token", "") if config else ""
        jira_project = getattr(config, "jira_project_key", "SEC") if config else "SEC"

        self.jira = JiraConnector(
            base_url=jira_url,
            email=jira_email,
            api_token=jira_token,
            project_key=jira_project,
            mock_mode=mock_mode or not (jira_url and jira_token),
        )

        snow_instance = getattr(config, "servicenow_instance", "") if config else ""
        snow_user = getattr(config, "servicenow_user", "") if config else ""
        snow_pass = getattr(config, "servicenow_password", "") if config else ""

        self.servicenow = ServiceNowConnector(
            instance=snow_instance,
            username=snow_user,
            password=snow_pass,
            mock_mode=mock_mode or not (snow_instance and snow_user),
        )

        splunk_url = getattr(config, "splunk_hec_url", "") if config else ""
        splunk_token = getattr(config, "splunk_hec_token", "") if config else ""
        dd_key = getattr(config, "datadog_api_key", "") if config else ""
        dd_site = getattr(config, "datadog_site", "datadoghq.com") if config else "datadoghq.com"

        self.siem = SIEMForwarder(
            splunk_hec_url=splunk_url,
            splunk_hec_token=splunk_token,
            datadog_api_key=dd_key,
            datadog_site=dd_site,
            mock_mode=mock_mode,
        )

        slack_url = getattr(config, "slack_webhook_url", "") if config else ""
        teams_url = getattr(config, "teams_webhook_url", "") if config else ""
        cust_url = getattr(config, "custom_webhook_url", "") if config else ""
        wh_secret = getattr(config, "webhook_secret", "") if config else ""

        self.notifications = NotificationDispatcher(
            slack_webhook_url=slack_url,
            teams_webhook_url=teams_url,
            custom_webhook_url=cust_url,
            webhook_secret=wh_secret,
            mock_mode=mock_mode,
        )

    async def broadcast_finding(
        self,
        finding: dict[str, Any],
        session_name: str = "",
        channels: list[str] | None = None,
        base_api_url: str = "http://127.0.0.1:8000",
    ) -> dict[str, Any]:
        """Broadcasts a finding across chosen enterprise channels."""
        target_channels = [c.lower() for c in (channels or ["siem", "slack"])]
        finding_id = finding.get("id") or "f-unknown"
        retest_url = f"{base_api_url}/api/findings/{finding_id}/retest"

        dispatches: dict[str, Any] = {}

        # 1. Jira
        if "jira" in target_channels:
            try:
                dispatches["jira"] = await self.jira.create_vulnerability_issue(
                    finding, session_name=session_name, retest_callback_url=retest_url
                )
            except Exception as e:
                dispatches["jira"] = {"success": False, "error": str(e)}

        # 2. ServiceNow
        if "servicenow" in target_channels:
            try:
                dispatches["servicenow"] = await self.servicenow.create_security_incident(
                    finding, session_name=session_name
                )
            except Exception as e:
                dispatches["servicenow"] = {"success": False, "error": str(e)}

        # 3. SIEM (Splunk / Datadog / CEF)
        if "siem" in target_channels:
            try:
                dispatches["siem"] = await self.siem.forward_finding(
                    finding, session_name=session_name
                )
            except Exception as e:
                dispatches["siem"] = {"success": False, "error": str(e)}

        # 4. Slack
        if "slack" in target_channels:
            try:
                dispatches["slack"] = await self.notifications.send_slack_alert(
                    finding, session_name=session_name, retest_url=retest_url
                )
            except Exception as e:
                dispatches["slack"] = {"success": False, "error": str(e)}

        # 5. Microsoft Teams
        if "teams" in target_channels:
            try:
                dispatches["teams"] = await self.notifications.send_teams_alert(
                    finding, session_name=session_name, retest_url=retest_url
                )
            except Exception as e:
                dispatches["teams"] = {"success": False, "error": str(e)}

        return {
            "finding_id": finding_id,
            "session_name": session_name,
            "channels_targeted": target_channels,
            "dispatches": dispatches,
        }

    async def handle_incoming_webhook(
        self,
        source: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Handles inbound webhooks from Jira or external platforms to trigger actions (e.g. 1-Click Retest)."""
        logger.info(f"Received inbound webhook from {source}: {payload}")
        source_norm = source.lower()

        finding_id = payload.get("finding_id")

        # Parse Jira webhook
        if source_norm == "jira":
            issue = payload.get("issue", {})
            fields = issue.get("fields", {})
            labels = fields.get("labels", [])
            # Search for finding_id in labels or description
            for label in labels:
                if label.startswith("finding-"):
                    finding_id = label[len("finding-"):]
                    break
                elif label.startswith("f-") or label.startswith("find-"):
                    finding_id = label
                    break

        if not finding_id:
            return {
                "success": False,
                "action": "none",
                "message": "Nenhum finding_id detectado no webhook.",
            }

        # Trigger re-test if DB is present
        retest_result = None
        if self.db:
            from arcanum.core.retest import RetestEngine
            retest_engine = RetestEngine(db=self.db)
            retest_result = await retest_engine.retest_finding(finding_id=finding_id)

        return {
            "success": True,
            "source": source_norm,
            "action": "retest_triggered",
            "finding_id": finding_id,
            "retest": retest_result,
        }
