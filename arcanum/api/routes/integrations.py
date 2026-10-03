"""Enterprise Integration API routes (Jira, ServiceNow, SIEM, Webhooks)."""

from __future__ import annotations

from typing import Any, Optional
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel

router = APIRouter()


class JiraIssueRequest(BaseModel):
    finding: dict[str, Any]
    session_name: str = ""
    retest_callback_url: str = ""


class ServiceNowIncidentRequest(BaseModel):
    finding: dict[str, Any]
    session_name: str = ""


class SIEMForwardRequest(BaseModel):
    finding: dict[str, Any]
    session_name: str = ""


class NotifyRequest(BaseModel):
    finding: dict[str, Any]
    session_name: str = ""
    channel: str = "slack"  # "slack" or "teams"
    retest_url: str = ""


class BroadcastRequest(BaseModel):
    finding: dict[str, Any]
    session_name: str = ""
    channels: list[str] = ["siem", "slack", "jira"]


class InboundWebhookRequest(BaseModel):
    source: str = "jira"
    payload: dict[str, Any]


@router.post("/jira/create-issue")
async def create_jira_issue(request: Request, body: JiraIssueRequest):
    hub = getattr(request.app.state, "enterprise_hub", None)
    if not hub:
        from arcanum.integrations.hub import EnterpriseHub
        hub = EnterpriseHub(db=request.app.state.db, mock_mode=True)

    result = await hub.jira.create_vulnerability_issue(
        finding=body.finding,
        session_name=body.session_name,
        retest_callback_url=body.retest_callback_url,
    )
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Failed to create Jira issue"))
    return {"jira": result}


@router.post("/servicenow/create-incident")
async def create_servicenow_incident(request: Request, body: ServiceNowIncidentRequest):
    hub = getattr(request.app.state, "enterprise_hub", None)
    if not hub:
        from arcanum.integrations.hub import EnterpriseHub
        hub = EnterpriseHub(db=request.app.state.db, mock_mode=True)

    result = await hub.servicenow.create_security_incident(
        finding=body.finding,
        session_name=body.session_name,
    )
    if not result.get("success"):
        raise HTTPException(502, result.get("error", "Failed to create ServiceNow incident"))
    return {"servicenow": result}


@router.post("/siem/forward")
async def forward_to_siem(request: Request, body: SIEMForwardRequest):
    hub = getattr(request.app.state, "enterprise_hub", None)
    if not hub:
        from arcanum.integrations.hub import EnterpriseHub
        hub = EnterpriseHub(db=request.app.state.db, mock_mode=True)

    result = await hub.siem.forward_finding(
        finding=body.finding,
        session_name=body.session_name,
    )
    return {"siem": result}


@router.post("/notify")
async def send_notification(request: Request, body: NotifyRequest):
    hub = getattr(request.app.state, "enterprise_hub", None)
    if not hub:
        from arcanum.integrations.hub import EnterpriseHub
        hub = EnterpriseHub(db=request.app.state.db, mock_mode=True)

    ch = body.channel.lower()
    if ch == "teams":
        result = await hub.notifications.send_teams_alert(
            finding=body.finding,
            session_name=body.session_name,
            retest_url=body.retest_url,
        )
    else:
        result = await hub.notifications.send_slack_alert(
            finding=body.finding,
            session_name=body.session_name,
            retest_url=body.retest_url,
        )
    return {"notification": result}


@router.post("/broadcast")
async def broadcast_finding(request: Request, body: BroadcastRequest):
    hub = getattr(request.app.state, "enterprise_hub", None)
    if not hub:
        from arcanum.integrations.hub import EnterpriseHub
        hub = EnterpriseHub(db=request.app.state.db, mock_mode=True)

    result = await hub.broadcast_finding(
        finding=body.finding,
        session_name=body.session_name,
        channels=body.channels,
    )
    return {"broadcast": result}


@router.post("/webhook/incoming")
async def incoming_webhook(request: Request, body: InboundWebhookRequest):
    hub = getattr(request.app.state, "enterprise_hub", None)
    if not hub:
        from arcanum.integrations.hub import EnterpriseHub
        hub = EnterpriseHub(db=request.app.state.db, mock_mode=True)

    result = await hub.handle_incoming_webhook(
        source=body.source,
        payload=body.payload,
    )
    return {"webhook": result}
