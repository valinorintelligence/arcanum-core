"""Integration tests for Retest and Exposure Drift API endpoints."""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient

from arcanum.api.main import create_app
from arcanum.core.config import get_config
from arcanum.core.database import Database
from arcanum.agent.session import SessionManager


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    """Provides a TestClient with an isolated database and test token."""
    monkeypatch.setenv("ARCANUM_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ARCANUM_API_TOKEN", "test-secret-token")
    get_config.cache_clear()
    
    app = create_app()

    with TestClient(app) as client:
        yield client


def test_retest_finding_api_endpoint(api_client):
    """Test POST /api/findings/{finding_id}/retest works via API."""
    client = api_client
    app = client.app
    headers = {"Authorization": "Bearer test-secret-token"}

    # Mock tool executor to simulate retest success (remediated)
    mock_tool_exec = MagicMock()
    mock_tool_exec.execute_tool = AsyncMock(return_value={"success": True, "output": {"findings": []}})
    app.state.tool_executor = mock_tool_exec

    # 1. Create session first
    create_sess_resp = client.post(
        "/api/sessions/",
        headers=headers,
        json={"name": "pentest-corp", "target": "192.168.1.100"},
    )
    assert create_sess_resp.status_code == 200
    session_id = create_sess_resp.json()["session"]["id"]

    # 2. Create finding
    finding_payload = {
        "session_id": session_id,
        "title": "Unauthenticated Redis Service",
        "severity": "high",
        "description": "Port 6379 accepts connections without AUTH",
        "status": "confirmed",
        "retest_tool": "nmap_scan",
        "retest_arguments": {"target": "192.168.1.100", "ports": "6379"},
    }
    create_finding_resp = client.post("/api/findings/", headers=headers, json=finding_payload)
    assert create_finding_resp.status_code == 200
    finding_id = create_finding_resp.json()["finding"]["id"]

    # 3. Trigger 1-Click Retest via API
    retest_resp = client.post(
        f"/api/findings/{finding_id}/retest",
        headers=headers,
        json={"tool": "nmap_scan", "arguments": {"target": "192.168.1.100", "ports": "6379"}},
    )
    assert retest_resp.status_code == 200
    retest_data = retest_resp.json()["retest"]
    assert retest_data["success"] is True
    # Security invariant: the probe ('nmap_scan' is not a registered tool, so it
    # errors) could NOT positively confirm the vulnerability was fixed, therefore
    # the finding MUST remain open. A retest must never mark a finding
    # 'remediated' without real confirmation (previously it silently did via a
    # mock fallback).
    assert retest_data["new_status"] == "confirmed"
    assert retest_data["verdict"] == "CONFIRMED"
    assert retest_data["finding_id"] == finding_id

    # 4. Verify finding status in GET endpoint
    get_resp = client.get(f"/api/findings/{finding_id}", headers=headers)
    assert get_resp.status_code == 200
    updated_finding = get_resp.json()["finding"]
    assert updated_finding["status"] == "confirmed"
    assert updated_finding["retest_proof"] is not None


def test_exposure_drift_api_endpoint(api_client):
    """Test GET /api/sessions/{name}/drift works via API."""
    client = api_client
    headers = {"Authorization": "Bearer test-secret-token"}

    # 1. Create baseline session
    s1_resp = client.post(
        "/api/sessions/",
        headers=headers,
        json={"name": "audit-v1", "target": "10.0.0.1"},
    )
    assert s1_resp.status_code == 200
    s1_id = s1_resp.json()["session"]["id"]

    # Add finding to audit-v1
    f1_resp = client.post(
        "/api/findings/",
        headers=headers,
        json={
            "session_id": s1_id,
            "title": "FTP Anonymous Login",
            "severity": "critical",
            "type": "cve",
            "affected": {"service": "vsftpd-2.3.4"},
            "status": "confirmed",
        },
    )
    assert f1_resp.status_code == 200

    # 2. Create second session
    s2_resp = client.post(
        "/api/sessions/",
        headers=headers,
        json={"name": "audit-v2", "target": "10.0.0.1"},
    )
    assert s2_resp.status_code == 200
    s2_id = s2_resp.json()["session"]["id"]

    # In session 2, old FTP is marked remediated, and new SSH weak cipher is discovered
    client.post(
        "/api/findings/",
        headers=headers,
        json={
            "session_id": s2_id,
            "title": "FTP Anonymous Login",
            "severity": "critical",
            "type": "cve",
            "affected": {"service": "vsftpd-2.3.4"},
            "status": "remediated",
        },
    )
    client.post(
        "/api/findings/",
        headers=headers,
        json={
            "session_id": s2_id,
            "title": "SSH Weak MACs Enabled",
            "severity": "low",
            "type": "config",
            "affected": {"service": "sshd"},
            "status": "confirmed",
        },
    )

    # 3. Query drift comparing audit-v2 to audit-v1
    drift_resp = client.get("/api/sessions/audit-v2/drift?compare_to=audit-v1", headers=headers)
    assert drift_resp.status_code == 200
    drift = drift_resp.json()["drift"]

    assert drift["remediated_count"] == 1
    assert drift["remediated_findings"][0]["title"] == "FTP Anonymous Login"
    assert drift["new_count"] == 1
    assert drift["new_findings"][0]["title"] == "SSH Weak MACs Enabled"
    assert drift["regressed_count"] == 0
    assert drift["posture_trend"] == "improving"
    assert drift["score_delta"] > 0  # +40 for critical remediated - 5 for low new = +35
