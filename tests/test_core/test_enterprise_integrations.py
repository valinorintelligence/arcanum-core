"""Unit tests for Phase 3: Enterprise Integration Hub (Jira, ServiceNow, SIEM, Webhooks)."""

import pytest
import pytest_asyncio
import hmac
import hashlib
import json

from arcanum.core.database import Database
from arcanum.integrations.jira import JiraConnector
from arcanum.integrations.servicenow import ServiceNowConnector
from arcanum.integrations.siem import SIEMForwarder
from arcanum.integrations.notifications import NotificationDispatcher
from arcanum.integrations.hub import EnterpriseHub


@pytest.fixture
def sample_finding():
    return {
        "id": "find-sqli-01",
        "title": "SQL Injection in User Profile API",
        "severity": "critical",
        "type": "cve",
        "cve_id": "CVE-2024-9999",
        "cvss_score": 9.8,
        "affected": {"url": "https://api.corp.internal/v1/profile?id=1'"},
        "evidence": {"query": "SELECT * FROM users WHERE id = '1''", "vuln": True},
        "remediation": "Utilizar Prepared Statements e parametrizar queries SQL.",
        "status": "confirmed",
    }


@pytest.mark.asyncio
async def test_jira_connector_issue_creation(sample_finding):
    """Test Jira connector formats issue correctly with severity mapping and retest link."""
    jira = JiraConnector(mock_mode=True, project_key="CYBER", issue_type="Bug")

    res = await jira.create_vulnerability_issue(
        finding=sample_finding,
        session_name="q3-audit",
        retest_callback_url="http://127.0.0.1:8000/api/findings/find-sqli-01/retest",
    )

    assert res["success"] is True
    assert res["mock"] is True
    assert res["project"] == "CYBER"
    assert res["priority"] == "Highest"  # critical maps to Highest
    assert "SQL Injection" in res["summary"]
    assert "https://mock-jira.atlassian.net/browse/" in res["issue_url"]


@pytest.mark.asyncio
async def test_servicenow_connector_incident_creation(sample_finding):
    """Test ServiceNow connector maps urgency/impact and creates incident."""
    snow = ServiceNowConnector(mock_mode=True)

    res = await snow.create_security_incident(
        finding=sample_finding,
        session_name="soc-triage",
    )

    assert res["success"] is True
    assert res["mock"] is True
    assert res["priority"] == "1 - Critical"
    assert res["incident_number"].startswith("INC")


@pytest.mark.asyncio
async def test_siem_forwarder_cef_and_ecs(sample_finding):
    """Test SIEM forwarder produces valid CEF and Elastic Common Schema."""
    siem = SIEMForwarder(mock_mode=True)

    # 1. Test CEF format
    cef = siem.format_cef(sample_finding, session_name="red-team-op")
    assert cef.startswith("CEF:0|Arcanum|ArcanumCore|2.0|")
    assert "SQL Injection in User Profile API" in cef
    assert "src=https://api.corp.internal/v1/profile?id=1'" in cef
    assert "cs1Label=CVE cs1=CVE-2024-9999" in cef

    # 2. Test ECS format
    ecs = siem.format_ecs(sample_finding, session_name="red-team-op")
    assert ecs["event"]["category"] == ["vulnerability", "threat"]
    assert ecs["vulnerability"]["severity"] == "critical"
    assert ecs["vulnerability"]["score"]["base"] == 9.8
    assert ecs["arcanum"]["finding_id"] == "find-sqli-01"

    # 3. Test forward finding
    res = await siem.forward_finding(sample_finding, session_name="red-team-op")
    assert res["success"] is True
    assert "cef_payload" in res
    assert "ecs_payload" in res


@pytest.mark.asyncio
async def test_notification_dispatcher_slack_and_teams(sample_finding):
    """Test Slack Block Kit and Microsoft Teams Adaptive Cards format."""
    notif = NotificationDispatcher(mock_mode=True, webhook_secret="super-secret-key")

    # 1. Slack
    slack_res = await notif.send_slack_alert(
        finding=sample_finding,
        session_name="pentest-prod",
        retest_url="http://localhost:8000/api/findings/find-sqli-01/retest",
    )
    assert slack_res["success"] is True
    assert slack_res["channel"] == "slack"
    blocks = slack_res["payload"]["attachments"][0]["blocks"]
    assert any("CRITICAL" in json.dumps(b) for b in blocks)
    assert any("Disparar 1-Click Retest" in json.dumps(b) for b in blocks)

    # 2. Teams
    teams_res = await notif.send_teams_alert(
        finding=sample_finding,
        session_name="pentest-prod",
        retest_url="http://localhost:8000/api/findings/find-sqli-01/retest",
    )
    assert teams_res["success"] is True
    assert teams_res["channel"] == "teams"
    assert "MessageCard" in teams_res["payload"]["@type"]

    # 3. Custom Webhook with HMAC
    custom_res = await notif.send_custom_webhook("finding_alert", {"id": "123"})
    assert custom_res["success"] is True
    assert custom_res["channel"] == "custom_webhook"


@pytest_asyncio.fixture
async def test_db():
    db = Database(":memory:")
    await db.connect()
    await db.init_db()
    yield db
    await db.close()


@pytest.mark.asyncio
async def test_enterprise_hub_broadcast_and_inbound_webhook(test_db, sample_finding):
    """Test EnterpriseHub broadcasts finding and processes inbound webhook for 1-Click Retest."""
    db = test_db
    hub = EnterpriseHub(db=db, mock_mode=True)

    # Insert session and finding into database
    await db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        ("sess-integ", "sess-integ", "https://example.com"),
    )
    await db.execute(
        """INSERT INTO findings (id, session_id, title, severity, status, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            sample_finding["id"],
            "sess-integ",
            sample_finding["title"],
            sample_finding["severity"],
            "confirmed",
            "audit_security_headers",
            json.dumps({"url": "https://example.com"}),
        ),
    )

    # 1. Broadcast finding to Jira, SIEM, Slack
    broadcast = await hub.broadcast_finding(
        finding=sample_finding,
        session_name="sess-integ",
        channels=["jira", "siem", "slack"],
    )
    assert broadcast["finding_id"] == "find-sqli-01"
    assert "jira" in broadcast["dispatches"]
    assert broadcast["dispatches"]["jira"]["success"] is True
    assert "siem" in broadcast["dispatches"]
    assert "slack" in broadcast["dispatches"]

    # 2. Simulate inbound Jira webhook resolving ticket and triggering retest
    inbound_payload = {
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "SEC-100",
            "fields": {
                "labels": ["finding-find-sqli-01", "resolved"],
            },
        },
    }
    webhook_res = await hub.handle_incoming_webhook("jira", inbound_payload)
    assert webhook_res["success"] is True
    assert webhook_res["action"] == "retest_triggered"
    assert webhook_res["finding_id"] == "finding-find-sqli-01" or webhook_res["finding_id"] == "find-sqli-01"
