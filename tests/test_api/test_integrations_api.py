"""Integration tests for Enterprise Integration API routes (Jira, ServiceNow, SIEM, Webhooks)."""

import json
import pytest
import pytest_asyncio
import httpx

from arcanum.api.main import create_app
from arcanum.core.config import get_config


@pytest_asyncio.fixture
async def async_client(tmp_path, monkeypatch):
    """Provides an AsyncClient with an isolated database and test token."""
    monkeypatch.setenv("ARCANUM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ARCANUM_API_TOKEN", "test-secret-token")
    get_config.cache_clear()

    app = create_app()

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            client.app = app
            yield client


@pytest.fixture
def sample_finding():
    return {
        "id": "find-ap-01",
        "title": "Remote Code Execution via Insecure Deserialization",
        "severity": "critical",
        "type": "cve",
        "affected": "api-gateway:8443",
        "details": "Untrusted Java object deserialized leading to arbitrary command execution.",
        "remediation": "Upgrade Jackson Databind and enforce strict class whitelisting.",
    }


@pytest.mark.asyncio
async def test_jira_and_servicenow_api_endpoints(async_client, sample_finding):
    """Test Jira issue and ServiceNow incident creation endpoints."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. Jira Issue Creation
    jira_resp = await client.post(
        "/api/integrations/jira/create-issue",
        headers=headers,
        json={
            "finding": sample_finding,
            "session_name": "prod-audit",
            "retest_callback_url": "https://arcanum.corp.local/api/findings/find-ap-01/retest",
        },
    )
    assert jira_resp.status_code == 200
    jira_data = jira_resp.json()["jira"]
    assert jira_data["success"] is True
    assert "issue_key" in jira_data
    assert jira_data["issue_key"].startswith("SEC-")

    # 2. ServiceNow Incident Creation
    snow_resp = await client.post(
        "/api/integrations/servicenow/create-incident",
        headers=headers,
        json={
            "finding": sample_finding,
            "session_name": "prod-audit",
        },
    )
    assert snow_resp.status_code == 200
    snow_data = snow_resp.json()["servicenow"]
    assert snow_data["success"] is True
    assert "incident_number" in snow_data
    assert snow_data["incident_number"].startswith("INC")


@pytest.mark.asyncio
async def test_siem_forward_and_notify_api_endpoints(async_client, sample_finding):
    """Test SIEM forwarding and Slack/Teams notification endpoints."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. Forward to SIEM
    siem_resp = await client.post(
        "/api/integrations/siem/forward",
        headers=headers,
        json={
            "finding": sample_finding,
            "session_name": "prod-audit",
        },
    )
    assert siem_resp.status_code == 200
    siem_data = siem_resp.json()["siem"]
    assert "CEF:0|Arcanum|ArcanumCore|" in siem_data["cef_payload"]
    assert siem_data["ecs_payload"]["vulnerability"]["severity"] == "critical"

    # 2. Slack Notification
    slack_resp = await client.post(
        "/api/integrations/notify",
        headers=headers,
        json={
            "finding": sample_finding,
            "session_name": "prod-audit",
            "channel": "slack",
        },
    )
    assert slack_resp.status_code == 200
    assert slack_resp.json()["notification"]["channel"] == "slack"

    # 3. Teams Notification
    teams_resp = await client.post(
        "/api/integrations/notify",
        headers=headers,
        json={
            "finding": sample_finding,
            "session_name": "prod-audit",
            "channel": "teams",
        },
    )
    assert teams_resp.status_code == 200
    assert teams_resp.json()["notification"]["channel"] == "teams"


@pytest.mark.asyncio
async def test_broadcast_and_inbound_webhook_endpoints(async_client, sample_finding):
    """Test multichannel broadcast and inbound webhook triggering re-test."""
    client = async_client
    headers = {"Authorization": "Bearer test-secret-token"}
    db = client.app.state.db

    # Create session and finding in database
    await db.execute(
        "INSERT INTO sessions (id, name, target) VALUES (?, ?, ?)",
        ("sess-api-integ", "sess-api-integ", "https://api.corp.local"),
    )
    await db.execute(
        """INSERT INTO findings (id, session_id, title, severity, status, retest_tool, retest_arguments)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            sample_finding["id"],
            "sess-api-integ",
            sample_finding["title"],
            sample_finding["severity"],
            "confirmed",
            "audit_security_headers",
            json.dumps({"url": "https://api.corp.local"}),
        ),
    )

    # 1. Test Broadcast Endpoint
    bcast_resp = await client.post(
        "/api/integrations/broadcast",
        headers=headers,
        json={
            "finding": sample_finding,
            "session_name": "sess-api-integ",
            "channels": ["jira", "siem", "slack"],
        },
    )
    assert bcast_resp.status_code == 200
    bcast_data = bcast_resp.json()["broadcast"]
    assert bcast_data["finding_id"] == sample_finding["id"]
    assert "jira" in bcast_data["dispatches"]
    assert "siem" in bcast_data["dispatches"]
    assert "slack" in bcast_data["dispatches"]

    # 2. Test Inbound Webhook Endpoint
    inbound_payload = {
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "SEC-999",
            "fields": {
                "labels": [f"finding-{sample_finding['id']}", "resolved"],
            },
        },
    }
    hook_resp = await client.post(
        "/api/integrations/webhook/incoming",
        headers=headers,
        json={
            "source": "jira",
            "payload": inbound_payload,
        },
    )
    assert hook_resp.status_code == 200
    hook_data = hook_resp.json()["webhook"]
    assert hook_data["success"] is True
    assert hook_data["finding_id"] == sample_finding["id"]
    assert hook_data["action"] == "retest_triggered"
